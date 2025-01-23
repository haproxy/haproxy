#include <inttypes.h>

#include <haproxy/compat.h>
#include <haproxy/quic_tx-t.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_cc_drs.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>
#include <haproxy/window_filter.h>


/* Bottleneck Bandwidth and Round-trip propagation time version 3 (BBRv3)
 * congestion algorithm implementation for QUIC.
 * https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/
 *
 * This algorithm builds a model of the network producing some delivery rate
 * sample from acknowledgement information to sequentially estimate the maximum
 * bandwidth and round-trip time.
 */


/* BBR constant definitions */

/* BBRStartupFullLossCnt(6):
 * the maximum number of accepted discontiguous sequence ranges lost in a round
 * trip during Startup.
 */
#define BBR_STARTUP_FULL_LOSS_COUNT    6

/* BBRStartupPacingGain(2.77):
 * a constant specifying the minimum gain value for calculating the pacing rate
 * that will allow the sending rate to double each round (4 * ln(2) ~= 2.77);
 * used in Startup mode for BBR.pacing_gain.
 */
#define BBR_STARTUP_PACING_GAIN_MULT 277 /* percents */

/* BBRDrainPacingGain(0.35)
 * a constant specifying the pacing gain value used in Drain mode, to attempt
 * to drain the estimated queue at the bottleneck link in one round-trip or less.
 */
#define BBR_DRAIN_PACING_GAIN_MULT    35 /* percents */

/* BBRDefaultCwndGain:
 * a constant specifying the minimum gain value that
 * allows the sending rate to double each round (2). Used by default in most
 * phases for BBR.cwnd_gain.
 */
#define BBR_DEFAULT_CWND_GAIN_MULT   200 /* percents */

/* BBRPacingMarginPercent(1%):
 * the static discount factor of 1% used to scale BBR.bw to produce
 * BBR.pacing_rate.
 */
#define BBR_PACING_MARGIN_PERCENT      1 /* percents */

/* BBRLossThresh(2%):
 * the maximum tolerated per-round-trip packet loss rate when probing for
 * bandwidth.
 */
#define BBR_LOSS_THRESH_MULT   2
#define BBR_LOSS_THRESH_DIVI 100

/* BBRBeta(0.7):
 * the default multiplicative decrease to make upon each round trip during
 * which the connection detects packet loss.
 */
#define BBR_BETA_MULT  7
#define BBR_BETA_DIVI 10

/* BBRHeadroom (0.15):
 * the multiplicative factor to apply to BBR.inflight_hi when calculating a
 * volume of free headroom to try to leave unused in the path (e.g. free space
 * in the bottleneck buffer or free time slots in the bottleneck link) that can
 * be used by cross traffic.
 */
#define BBR_HEADROOM_MULT  15
#define BBR_HEADROOM_DIVI 100

/* MaxBwFilterLen(2):
 * the length of the windowed filter length for BBR.MaxBwFilter */
#define BBR_MAX_BW_FILTERLEN       2

/* BBRExtraAckedFilterLen(10):
 * The window length of the BBR.ExtraACKedFilter max filter window in steady-state
 * in units of packet-timed round trips
 */
#define BBR_EXTRA_ACKED_FILTERLEN 10

/* MinRTTFilterLen(10s):
 * A constant specifying the length of the BBR.min_rtt min filter window.
 */
#define BBR_MIN_RTT_FILTERLEN      10000 /* ms */

/* BBRProbeRTTCwndGain(0.5):
 * A constant specifying the gain value for calculating the cwnd during ProbeRTT:
 * 0.5 (meaning that ProbeRTT attempts to reduce in-flight data to 50% of the
 * estimated BDP)
 */
#define BBR_PROBE_RTT_CWND_GAIN_MULT  50 /* percents */

/* ProbeRTTDuration(200ms):
 * A constant specifying the minimum duration for which ProbeRTT state holds
 * inflight to BBRMinPipeCwnd or fewer packets
 */
#define BBR_PROBE_RTT_DURATION       200 /* ms */

/* ProbeRTTInterval(5s)
 * A constant specifying the minimum time interval between ProbeRTT states
 */
#define BBR_PROBE_RTT_INTERVAL      5000 /* ms */

/* The divisor to apply to the gain multiplicandes above (BBR.*_GAIN_MULT)
 * whose the unit is the percent.
 */
#define BBR_GAIN_DIVI                100

/* 4.1.1: State Transition Diagram
 *
 *
 *             |
 *             V
 *    +---> Startup  ------------+
 *    |        |                 |
 *    |        V                 |
 *    |     Drain  --------------+
 *    |        |                 |
 *    |        V                 |
 *    +---> ProbeBW_DOWN  -------+
 *    | ^      |                 |
 *    | |      V                 |
 *    | |   ProbeBW_CRUISE ------+
 *    | |      |                 |
 *    | |      V                 |
 *    | |   ProbeBW_REFILL  -----+
 *    | |      |                 |
 *    | |      V                 |
 *    | |   ProbeBW_UP  ---------+
 *    | |      |                 |
 *    | +------+                 |
 *    |                          |
 *    +---- ProbeRTT <-----------+
 *
 */

/*
 *  4.1.2. State Machine Operation Overview
 *
 * When starting up, BBR probes to try to quickly build a model of the network
 * path; to adapt to later changes to the path or its traffic, BBR must
 * continue to probe to update its model. If the available bottleneck bandwidth
 * increases, BBR must send faster to discover this. Likewise, if the round-trip
 * propagation delay changes, this changes the BDP, and thus BBR must send slower
 * to get inflight below the new BDP in order to measure the new BBR.min_rtt.
 * Thus, BBR's state machine runs periodic, sequential experiments, sending faster
 * to check for BBR.bw increases or sending slower to yield bandwidth, drain the
 * queue, and check for BBR.min_rtt decreases. The frequency, magnitude, duration,
 * and structure of these experiments differ depending on what's already known
 * (startup or steady-state) and application sending behavior (intermittent or
 * continuous).
 * This state machine has several goals:
 *
 *  - Achieve high throughput by efficiently utilizing available bandwidth.
 *  - Achieve low latency and packet loss rates by keeping queues bounded and
 *    small.
 *  - Share bandwidth with other flows in an approximately fair manner.
 *  - Feed samples to the model estimators to refresh and update the model.
 */

/* BBR states */
enum bbr_state {
	BBR_ST_STARTUP,
	BBR_ST_DRAIN,
	BBR_ST_PROBE_BW_DOWN,
	BBR_ST_PROBE_BW_CRUISE,
	BBR_ST_PROBE_BW_REFILL,
	BBR_ST_PROBE_BW_UP,
	BBR_ST_PROBE_RTT,
};

struct bbr {
	/* Delivery rate sampling information. */
	struct quic_cc_drs drs;
	/* 2.4 Output Control Parameters */
	uint64_t pacing_rate;
	/* 2.5 Pacing State and Parameters */
	/* BBR.pacing_gain: The dynamic gain factor used to scale BBR.bw to
	 * produce BBR.pacing_rate.
	 */
	uint64_t pacing_gain; // percents
	/* 2.6. cwnd State and Parameters */
	/* BBR.cwnd_gain: The dynamic gain factor used to scale the estimated BDP
	 * to produce a congestion window (cwnd).
	 */
	uint64_t cwnd_gain; // percents
	/* 2.7 General Algorithm State */
	enum bbr_state state;
	uint64_t round_count;
	int round_start; /* boolean */
	uint64_t next_round_delivered;
	int idle_restart; /* boolean */
	/* 2.9.1 Data Rate Network Path Model Parameters */
	uint64_t max_bw;
	uint64_t bw_lo;
	uint64_t bw;
	uint64_t prior_cwnd;
	/* 2.9.2 Data Volume Network Path Model Parameters */
	uint32_t min_rtt;
	uint64_t extra_acked;
	uint64_t bytes_lost_in_round;
	uint64_t loss_events_in_round;
	uint64_t offload_budget;
	uint64_t probe_up_cnt;
	uint32_t cycle_stamp;
	unsigned int bw_probe_wait;
	int bw_probe_samples;
	int bw_probe_up_rounds;
	uint64_t bw_probe_up_acks;
	uint64_t max_inflight;
	uint64_t inflight_hi;
	uint64_t inflight_lo;
	/* 2.10 State for Responding to Congestion */
	int loss_round_start; /* boolean */
	uint64_t bw_latest;
	int loss_in_round; /* boolean */
	uint64_t loss_round_delivered;
	unsigned int rounds_since_bw_probe;
	uint64_t inflight_latest;
	/* 2.11 Estimating BBR.max_bw */
	struct wf max_bw_filter;
	uint64_t cycle_count;
	/* 2.12 Estimating BBR.extra_acked */
	uint32_t extra_acked_interval_start;
	uint64_t extra_acked_delivered;
	struct wf extra_acked_filter;
	/* 2.13 Startup Parameters and State */
	int full_bw_reached; /* boolean */
	int full_bw_now; /* boolean */
	uint64_t full_bw;
	int full_bw_count;
	/* 2.14 ProbeRTT and min_rtt Parameters and State */
	/* 2.14.1 Parameters for Estimating BBR.min_rtt */
	uint32_t min_rtt_stamp;
	/* 2.14.2  Parameters for Scheduling ProbeRTT */
	uint32_t probe_rtt_min_delay; /* ms */
	uint32_t probe_rtt_min_stamp; /* ms */
	uint32_t probe_rtt_done_stamp;
	int probe_rtt_round_done; /* boolean */
	int probe_rtt_expired; /* boolean */
	int packet_conservation; /* boolean */
	uint64_t round_count_at_recovery;
	int in_loss_recovery; /* boolean */
	uint32_t recovery_start_ts;
};

/* BBR functions definitions.
 * The camelcase naming convention is used by the BBR RFC for the function names
 * and constants. To helps in matching the code below with the RFC one, note
 * that all the function names have been translated this way. The uppercase
 * letters have been replaced by lowercase letters. The words have been seperated
 * by underscores as follows:
 *
 *     ex: BBRMinPipeCwnd() -> bbr_min_pipe_cwnd()
 */

/* BBRMinPipeCwnd:
 * Return the minimal cwnd value BBR targets, to allow pipelining with TCP
 * endpoints that follow an "ACK every other packet" delayed-ACK policy: 4 * SMSS.
 */
static inline uint64_t bbr_min_pipe_cwnd(struct quic_cc_path *p)
{
	return 4 * p->mtu;
}

static inline int is_inflight_too_high(struct quic_cc_rs *rs)
{
	return rs->lost * BBR_LOSS_THRESH_DIVI >
		rs->tx_in_flight * BBR_LOSS_THRESH_MULT;
}

static inline int bbr_is_in_a_probe_bw_state(struct bbr *bbr)
{
	switch (bbr->state) {
	case BBR_ST_PROBE_BW_DOWN:
	case BBR_ST_PROBE_BW_CRUISE:
	case BBR_ST_PROBE_BW_REFILL:
	case BBR_ST_PROBE_BW_UP:
		return 1;
	default:
		return 0;
	}
}

static void bbr_reset_congestion_signals(struct bbr *bbr)
{
	bbr->loss_in_round = 0;
	bbr->bw_latest = 0;
	bbr->inflight_latest = 0;
}

static void bbr_reset_lower_bounds(struct bbr *bbr)
{
	bbr->bw_lo = UINT64_MAX;
	bbr->inflight_lo = UINT64_MAX;
}

static void bbr_init_round_counting(struct bbr *bbr)
{
	bbr->next_round_delivered = 0;
	bbr->round_start = 0;
	bbr->round_count = 0;
}

static void bbr_reset_full_bw(struct bbr *bbr)
{
	bbr->full_bw = 0;
	bbr->full_bw_count = 0;
	bbr->full_bw_now = 0;
}

static void bbr_init_pacing_rate(struct quic_cc *cc, struct bbr *bbr)
{
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);
	unsigned int srtt = p->loss.srtt;

	bbr->pacing_rate = 1000 * p->initial_wnd * BBR_STARTUP_PACING_GAIN_MULT /
		BBR_GAIN_DIVI / (srtt ? srtt : 1);
}

/* 4.6.3. Send Quantum: BBR.send_quantum
 *
 * In order to amortize per-packet overheads involved in the sending process
 * (host CPU, NIC processing, and interrupt processing delays), high-performance
 * transport sender implementations (e.g., Linux TCP) often schedule an
 * aggregate containing multiple packets (multiple SMSS) worth of data as a
 * single quantum (using TSO, GSO, or other offload mechanisms). The BBR
 * congestion control algorithm makes this control decision explicitly,
 * dynamically calculating a quantum control parameter that specifies the
 * maximum size of these transmission aggregates. This decision is based on a
 * trade-off:
 *
 * A smaller quantum is preferred at lower data rates because it results in
 * shorter packet bursts, shorter queues, lower queueing delays, and lower rates
 * of packet loss.
 *
 * A bigger quantum can be required at higher data rates because it results in
 * lower CPU overheads at the sending and receiving hosts, who can ship larger
 * amounts of data with a single trip through the networking stack.
 */

/* Set ->send_quantum. Must be called on each ack receipt. */
static void bbr_set_send_quantum(struct bbr *bbr, struct quic_cc_path *p)
{
	p->send_quantum = bbr->pacing_rate / 1000;
	p->send_quantum = MIN(p->send_quantum, 64 * 1024);
	p->send_quantum = MAX(p->send_quantum, 2 * p->mtu);
}

/* 4.3.1. Startup
 *
 * 4.3.1.1. Startup Dynamics
 *
 * When a BBR flow starts up, it performs its first (and most rapid) sequential
 * probe/drain process in the Startup and Drain states. Network link bandwidths
 * currently span a range of at least 11 orders of magnitude, from a few bps to
 * hundreds of Gbps. To quickly learn BBR.max_bw, given this huge range to
 * explore, BBR's Startup state does an exponential search of the rate space,
 * doubling the sending rate each round. This finds BBR.max_bw in O(log_2(BDP))
 * round trips.
 * To achieve this rapid probing smoothly, in Startup BBR uses the minimum gain
 * values that will allow the sending rate to double each round: in Startup BBR
 * sets BBR.pacing_gain to BBRStartupPacingGain (2.77) [BBRStartupPacingGain]
 * and BBR.cwnd_gain to BBRDefaultCwndGain (2) [BBRStartupCwndGain].
 * As BBR grows its sending rate rapidly, it obtains higher delivery rate
 * samples, BBR.max_bw increases, and the pacing rate and cwnd both adapt by
 * smoothly growing in proportion. Once the pipe is full, a queue typically
 * forms, but the cwnd_gain bounds any queue to (cwnd_gain - 1) * estimated_BDP,
 * which is approximately (2 - 1) * estimated_BDP = estimated_BDP. The
 * immediately following Drain state is designed to quickly drain that queue.
 */
static void bbr_enter_startup(struct bbr *bbr)
{
	bbr->state = BBR_ST_STARTUP;
	bbr->pacing_gain = BBR_STARTUP_PACING_GAIN_MULT;
	bbr->cwnd_gain = BBR_DEFAULT_CWND_GAIN_MULT;
}

/* 4.3.2. Drain
 *
 * Upon exiting Startup, BBR enters its Drain state. In Drain, BBR aims to
 * quickly drain any queue at the bottleneck link that was created in Startup
 * by switching to a pacing_gain well below 1.0, until any estimated queue has
 * been drained. It uses a pacing_gain of BBRDrainPacingGain = 0.35, chosen via
 * analysis [BBRDrainPacingGain] and experimentation to try to drain the queue
 * in less than one round-trip.
 */
static void bbr_enter_drain(struct bbr *bbr)
{
    bbr->state = BBR_ST_DRAIN;
    bbr->pacing_gain = BBR_DRAIN_PACING_GAIN_MULT; /* pace slowly */
    bbr->cwnd_gain = BBR_DEFAULT_CWND_GAIN_MULT;
}

static void bbr_enter_probe_rtt(struct bbr *bbr)
{
	bbr->state = BBR_ST_PROBE_RTT;
	bbr->pacing_gain = 100;
	bbr->cwnd_gain = BBR_PROBE_RTT_CWND_GAIN_MULT;
}

static void bbr_save_cwnd(struct bbr *bbr, struct quic_cc_path *p)
{
	if (!bbr->in_loss_recovery && bbr->state != BBR_ST_PROBE_RTT) {
		bbr->prior_cwnd = p->cwnd;
	}
	else {
		bbr->prior_cwnd = MAX(bbr->prior_cwnd, p->cwnd);
	}
}

static void bbr_restore_cwnd(struct bbr *bbr, struct quic_cc_path *p)
{
	p->cwnd = MAX(p->cwnd, bbr->prior_cwnd);
}

/* <gain> must be provided in percents. */
static uint64_t bbr_bdp_multiple(struct bbr *bbr, struct quic_cc_path *p,
                                 uint64_t bw, uint64_t gain)
{
	uint64_t bdp;

	if (bbr->min_rtt == UINT32_MAX)
		return p->initial_wnd; /* no valid RTT samples yet */

	bdp = bw * bbr->min_rtt / 1000;

	/* Note that <gain> unit is the percent. */
	return gain * bdp / BBR_GAIN_DIVI;
}

static void bbr_update_offload_budget(struct bbr *bbr, struct quic_cc_path *p)
{
	bbr->offload_budget = 3 * p->send_quantum;
}

static uint64_t bbr_quantization_budget(struct bbr *bbr, struct quic_cc_path *p,
                                        uint64_t inflight)
{
	bbr_update_offload_budget(bbr, p);
	inflight = MAX(inflight, bbr->offload_budget);
	inflight = MAX(inflight, bbr_min_pipe_cwnd(p));
	if (bbr->state == BBR_ST_PROBE_BW_UP)
		inflight += 2 * p->mtu;

	return inflight;
}

static uint64_t bbr_inflight(struct bbr *bbr, struct quic_cc_path *p,
                             uint64_t bw, uint64_t gain)
{
	uint64_t inflight = bbr_bdp_multiple(bbr, p, bw, gain);
	return bbr_quantization_budget(bbr, p, inflight);
}

static void bbr_update_max_inflight(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t inflight;

	/* Not defined by RFC */
	//BBRUpdateAggregationBudget();
	inflight = bbr_bdp_multiple(bbr, p, bbr->bw, bbr->cwnd_gain);
	inflight += bbr->extra_acked;
	bbr->max_inflight = bbr_quantization_budget(bbr, p, inflight);
}

static void bbr_set_pacing_rate_with_gain(struct bbr *bbr,
                                          struct quic_cc_path *p,
                                          uint64_t pacing_gain)
{
	uint64_t rate;

	if (!bbr->bw)
		return;

	/* pacing_gain unit is percent */
	rate = pacing_gain * bbr->bw * (100 - BBR_PACING_MARGIN_PERCENT) /
		BBR_GAIN_DIVI / BBR_GAIN_DIVI;
	if (bbr->full_bw_reached || rate > bbr->pacing_rate)
		bbr->pacing_rate = rate;
}

static void bbr_set_pacing_rate(struct bbr *bbr, struct quic_cc_path *p)
{
	bbr_set_pacing_rate_with_gain(bbr, p, bbr->pacing_gain);
}

static uint64_t bbr_probe_rtt_cwnd(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t probe_rtt_cwnd =
		bbr_bdp_multiple(bbr, p, bbr->bw, BBR_PROBE_RTT_CWND_GAIN_MULT);

    return MAX(probe_rtt_cwnd, bbr_min_pipe_cwnd(p));
}

static void bbr_bound_cwnd_for_probe_rtt(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr->state == BBR_ST_PROBE_RTT)
		p->cwnd = MIN(p->cwnd, bbr_probe_rtt_cwnd(bbr, p));
}

/* Return a volume of data that tries to leave free headroom in the bottleneck
 * buffer or link for other flows, for fairness convergence and lower RTTs and
 * loss.
 */
static uint64_t bbr_inflight_with_headroom(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t headroom;

	if (bbr->inflight_hi == UINT64_MAX)
		return UINT64_MAX;

	headroom =
		MAX(p->mtu, bbr->inflight_hi * BBR_HEADROOM_MULT / BBR_HEADROOM_DIVI);
	return MAX(bbr->inflight_hi - headroom, bbr_min_pipe_cwnd(p));
}

static void bbr_bound_cwnd_for_model(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t cap = UINT64_MAX;

	if (bbr_is_in_a_probe_bw_state(bbr) && bbr->state != BBR_ST_PROBE_BW_CRUISE)
		cap = bbr->inflight_hi;
	else if (bbr->state == BBR_ST_PROBE_RTT || bbr->state == BBR_ST_PROBE_BW_CRUISE)
		cap = bbr_inflight_with_headroom(bbr, p);

	/* apply inflight_lo (possibly infinite): */
	cap = MIN(cap, bbr->inflight_lo);
	cap = MAX(cap, bbr_min_pipe_cwnd(p));
	p->cwnd = MIN(p->cwnd, cap);
}

static void bbr_set_cwnd(struct bbr *bbr, struct quic_cc_path *p, uint32_t acked)
{
	bbr_update_max_inflight(bbr, p);
	if (bbr->full_bw_reached) {
		p->cwnd += acked;
		p->cwnd = MIN(p->cwnd, bbr->max_inflight);
	}
	else if (p->cwnd < bbr->max_inflight || bbr->drs.delivered < p->initial_wnd) {
		p->cwnd += acked;
	}
	p->cwnd = MAX(p->cwnd, bbr_min_pipe_cwnd(p));
	bbr_bound_cwnd_for_probe_rtt(bbr, p);
	bbr_bound_cwnd_for_model(bbr, p);
	/* Limitation by configuration (not in BBR RFC). */
	p->cwnd = MIN(p->cwnd, p->max_cwnd);
}

static int bbr_init(struct quic_cc *cc)
{
	struct bbr *bbr = quic_cc_priv(cc);

	quic_cc_drs_init(&bbr->drs);
	wf_init(&bbr->max_bw_filter, BBR_MAX_BW_FILTERLEN, 0, ~0U);
	wf_init(&bbr->extra_acked_filter, BBR_EXTRA_ACKED_FILTERLEN, 0, ~0U);
	bbr->min_rtt = UINT32_MAX;
	bbr->min_rtt_stamp = now_ms;
	bbr->probe_rtt_done_stamp = TICK_ETERNITY;
	bbr->probe_rtt_round_done = 0;
	bbr->prior_cwnd = 0;
	bbr->idle_restart = 0;
	bbr->extra_acked_interval_start = now_ms;
	bbr->extra_acked_delivered = 0;
	bbr->full_bw_reached = 0;

	bbr_reset_congestion_signals(bbr);
	bbr_reset_lower_bounds(bbr);
	bbr_init_round_counting(bbr);
	bbr_reset_full_bw(bbr);
	bbr_init_pacing_rate(cc, bbr);
	bbr_enter_startup(bbr);

	/* Not in RFC */
	bbr->loss_round_start = 0;
	bbr->loss_round_delivered = UINT64_MAX;
	bbr->rounds_since_bw_probe = 0;
	bbr->max_bw = 0;
	bbr->bw = 0;
	bbr->extra_acked = 0;
	bbr->bytes_lost_in_round = 0;
	bbr->loss_events_in_round = 0;
	bbr->offload_budget = 0;
	bbr->probe_up_cnt = UINT64_MAX;
	bbr->cycle_stamp = TICK_ETERNITY;
	bbr->bw_probe_wait = 0;
	bbr->bw_probe_samples = 0;
	bbr->bw_probe_up_rounds = 0;
	bbr->bw_probe_up_acks = 0;
	bbr->max_inflight = 0;
	bbr->inflight_hi = UINT64_MAX;
	bbr->cycle_count = 0;
	bbr->probe_rtt_min_delay = UINT32_MAX;
	bbr->probe_rtt_min_stamp = now_ms;
	bbr->probe_rtt_expired = 0;
	bbr->in_loss_recovery = 0;
	bbr->packet_conservation = 0;
	bbr->recovery_start_ts = TICK_ETERNITY;
	bbr->round_count_at_recovery = UINT64_MAX;

	return 1;
}

/* 4.3.1.2. Exiting Acceleration Based on Bandwidth Plateau
 *
 * In phases where BBR is accelerating to probe the available bandwidth
 * - Startup and ProbeBW_UP - BBR runs a state machine to estimate whether an
 * accelerating sending rate has saturated the available per-flow bandwidth
 * ("filled the pipe") by looking for a plateau in the measured rs.delivery_rate.
 * BBR tracks the status of the current full-pipe estimation process in the
 * boolean BBR.full_bw_now, and uses BBR.full_bw_now to exit ProbeBW_UP. BBR
 * records in the boolean BBR.full_bw_reached whether BBR estimates that it has
 * ever fully utilized its available bandwidth (over the lifetime of the
 * connection), and uses BBR.full_bw_reached to decide when to exit Startup and
 * enter Drain.The full pipe estimator works as follows: if BBR counts several
 * (three) non-application-limited rounds where attempts to significantly increase
 * the delivery rate actually result in little increase (less than 25 percent),
 * then it estimates that it has fully utilized the per-flow available bandwidth,
 * and sets both BBR.full_bw_now and BBR.full_bw_reached to true.
 */
static void bbr_check_full_bw_reached(struct bbr *bbr, struct quic_cc_path *p)
{
	struct quic_cc_rs *rs = &bbr->drs.rs;

	if (bbr->full_bw_now || rs->is_app_limited)
		return; /* no need to check for a full pipe now */

	if (p->delivery_rate * 100 >= bbr->full_bw * 125) {
		bbr_reset_full_bw(bbr); /* bw is still growing, so reset */
		bbr->full_bw = p->delivery_rate; /* record new baseline bw */
		return;
	}

	if (!bbr->round_start)
		return;

	bbr->full_bw_count++;   /* another round w/o much growth */
	bbr->full_bw_now = bbr->full_bw_count >= 3;
	if (bbr->full_bw_now)
		bbr->full_bw_reached = 1;
}

/* 4.3.1.3. Exiting Startup Based on Packet Loss
 *
 * A second method BBR uses for estimating the bottleneck is full in Startup is
 * by looking at packet losses. Specifically, BBRCheckStartupHighLoss() checks
 * whether all of the following criteria are all met:
 *
 * The connection has been in fast recovery for at least one full packet-timed
 * round trip.
 *
 * The loss rate over the time scale of a single full round trip exceeds
 * BBRLossThresh (2%).
 *
 * There are at least BBRStartupFullLossCnt=6 discontiguous sequence ranges lost
 * in that round trip.
 *
 * If these criteria are all met, then BBRCheckStartupHighLoss() takes the
 * following steps. First, it sets BBR.full_bw_reached = true. Then it sets
 * BBR.inflight_hi to its estimate of a safe level of in-flight data suggested
 * by these losses, which is max(BBR.bdp, BBR.inflight_latest), where
 * BBR.inflight_latest is the max delivered volume of data (rs.delivered) over
 * the last round trip. Finally, it exits Startup and enters Drain.The algorithm
 * waits until all three criteria are met to filter out noise from burst losses,
 * and to try to ensure the bottleneck is fully utilized on a sustained basis,
 * and the full bottleneck bandwidth has been measured, before attempting to drain
 * the level of in-flight data to the estimated BDP.
 */
static void bbr_check_startup_high_loss(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr->full_bw_reached ||
	    bbr->loss_events_in_round < BBR_STARTUP_FULL_LOSS_COUNT ||
	    (bbr->in_loss_recovery &&
	     bbr->round_count <= bbr->round_count_at_recovery) ||
	    !is_inflight_too_high(&bbr->drs.rs)) {
		return;
	}

	bbr->full_bw_reached = 1;
	bbr->inflight_hi =
		MAX(bbr_bdp_multiple(bbr, p, bbr->bw, bbr->cwnd_gain), bbr->inflight_latest);
}

static void bbr_start_round(struct bbr *bbr)
{
	bbr->next_round_delivered = bbr->drs.delivered;
}

static void bbr_update_round(struct bbr *bbr, uint32_t delivered)
{
	if (delivered >= bbr->next_round_delivered) {
		bbr_start_round(bbr);
		bbr->round_count++;
		bbr->rounds_since_bw_probe++;
		bbr->round_start = 1;
		bbr->bytes_lost_in_round = 0;
		bbr->loss_events_in_round = 0;
		bbr->drs.is_cwnd_limited = 0;
	}
	else {
		bbr->round_start = 0;
	}
}

static void bbr_pick_probe_wait(struct bbr *bbr)
{
	uint32_t rand = ha_random32();

	bbr->rounds_since_bw_probe = rand & 0x1; /* 0 or 1 */
	/* Decide the random wall clock bound for wait: */
	bbr->bw_probe_wait = 2000 + (rand % 1000);
}

static void bbr_raise_inflight_hi_slope(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t growth_this_round = p->mtu << bbr->bw_probe_up_rounds;

	bbr->bw_probe_up_rounds = MIN(bbr->bw_probe_up_rounds + 1, 30);
	bbr->probe_up_cnt = MAX(p->cwnd / growth_this_round, 1) * p->mtu;
}

static inline void bbr_advance_max_bw_filter(struct bbr *bbr)
{
	bbr->cycle_count++;
}

/* 4.3.3. ProbeBW
 *
 * Long-lived BBR flows tend to spend the vast majority of their time in the
 * ProbeBW states. In the ProbeBW states, a BBR flow sequentially accelerates,
 * decelerates, and cruises, to measure the network path, improve its operating
 * point (increase throughput and reduce queue pressure), and converge toward a
 * more fair allocation of bottleneck bandwidth. To do this, the flow
 * sequentially cycles through all three tactics: trying to send faster than,
 * slower than, and at the same rate as the network delivery process. To achieve
 * this, a BBR flow in ProbeBW mode cycles through the four Probe bw states
 * (DOWN, CRUISE, REFILL, and UP).
 */

/* 4.3.3.1. ProbeBW_DOWN
 *
 * In the ProbeBW_DOWN phase of the cycle, a BBR flow pursues the deceleration
 * tactic, to try to send slower than the network is delivering data, to reduce
 * the amount of data in flight, with all of the standard motivations for the
 * deceleration tactic (discussed in "State Machine Tactics" in Section 4.1.3).
 * It does this by switching to a BBR.pacing_gain of 0.90, sending at 90% of
 * BBR.bw. The pacing_gain value of 0.90 is derived based on the ProbeBW_UP
 * pacing gain of 1.25, as the minimum pacing_gain value that allows
 * bandwidth-based convergence to approximate fairness, and validated through
 * experiments.
 */
static void bbr_start_probe_bw_down(struct bbr *bbr)
{
	bbr_reset_congestion_signals(bbr);
	bbr->probe_up_cnt = UINT64_MAX;
	bbr_pick_probe_wait(bbr);
	bbr->cycle_stamp = now_ms;
	bbr_start_round(bbr);
	bbr->state = BBR_ST_PROBE_BW_DOWN;
	bbr->pacing_gain = 90;
	bbr->cwnd_gain = BBR_DEFAULT_CWND_GAIN_MULT;
	if (!bbr->drs.rs.is_app_limited)
		bbr_advance_max_bw_filter(bbr);
}

/*  4.3.3.2. ProbeBW_CRUISE
 *
 * In the ProbeBW_CRUISE phase of the cycle, a BBR flow pursues the "cruising"
 * tactic (discussed in "State Machine Tactics" in Section 4.1.3), attempting
 * to send at the same rate the network is delivering data. It tries to match
 * the sending rate to the flow's current available bandwidth, to try to
 * achieve high utilization of the available bandwidth without increasing
 * queue pressure. It does this by switching to a pacing_gain of 1.0, sending
 * at 100% of BBR.bw. Notably, while in this state it responds to concrete
 * congestion signals (loss) by reducing BBR.bw_lo and BBR.inflight_lo,
 * because these signals suggest that the available bandwidth and deliverable
 * volume of in-flight data have likely reduced, and the flow needs to change
 * to adapt, slowing down to match the latest delivery process.
 */
static void bbr_start_probe_bw_cruise(struct bbr *bbr)
{
	bbr->state = BBR_ST_PROBE_BW_CRUISE;
	bbr->pacing_gain = 100;
	bbr->cwnd_gain = BBR_DEFAULT_CWND_GAIN_MULT;
}

static void bbr_start_probe_bw_refill(struct bbr *bbr)
{
	bbr_reset_lower_bounds(bbr);
	bbr->bw_probe_up_rounds = 0;
	bbr->bw_probe_up_acks = 0;
	bbr_start_round(bbr);
	bbr->state = BBR_ST_PROBE_BW_REFILL;
	bbr->pacing_gain = 100;
	bbr->cwnd_gain = BBR_DEFAULT_CWND_GAIN_MULT;
}

static void bbr_start_probe_bw_up(struct bbr *bbr, struct quic_cc_path *p)
{
	bbr_start_round(bbr);
	bbr_reset_full_bw(bbr);
	bbr->full_bw = p->delivery_rate;
	bbr->state = BBR_ST_PROBE_BW_UP;
	bbr->pacing_gain = 125;
	bbr->cwnd_gain = 225;
	bbr_raise_inflight_hi_slope(bbr, p);
}

/* 4.3.4.5. Exiting ProbeRTT
 *
 * When exiting ProbeRTT, BBR transitions to ProbeBW if it estimates the pipe
 * was filled already, or Startup otherwise.
 * When transitioning out of ProbeRTT, BBR calls BBRResetLowerBounds() to reset
 * the lower bounds, since any congestion encountered in ProbeRTT may have
 * pulled the short-term model far below the capacity of the path.But the
 * algorithm is cautious in timing the next bandwidth probe: raising inflight
 * after ProbeRTT may cause loss, so the algorithm resets the bandwidth-probing
 * clock by starting the cycle at ProbeBW_DOWN(). But then as an optimization,
 * since the connection is exiting ProbeRTT, we know that infligh is already
 * below the estimated BDP, so the connection can proceed immediately to ProbeBW_CRUISE.
 */
static void bbr_exit_probe_rtt(struct bbr *bbr)
{
	bbr_reset_lower_bounds(bbr);
	if (bbr->full_bw_reached) {
		bbr_start_probe_bw_down(bbr);
		bbr_start_probe_bw_cruise(bbr);
	} else {
		bbr_enter_startup(bbr);
	}
}

static uint64_t bbr_target_inflight(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t bdp = bbr_inflight(bbr, p, bbr->bw, 100);
	return MIN(bdp, p->cwnd);
}

static void bbr_handle_inflight_too_high(struct bbr *bbr,
                                         struct quic_cc_path *p,
                                         struct quic_cc_rs *rs)
{
	bbr->bw_probe_samples = 0;
	if (!rs->is_app_limited)
		bbr->inflight_hi =
			MAX(rs->tx_in_flight,
			    bbr_target_inflight(bbr, p) * BBR_BETA_MULT / BBR_BETA_DIVI);

	if (bbr->state == BBR_ST_PROBE_BW_UP)
		bbr_start_probe_bw_down(bbr);
}

/* 4.5.10.2. Probing for Bandwidth In ProbeBW
 * IsInflightTooHigh() implementation at BBR state level. This function
 * call is_inflight_too_high() at delivery rate sampling level.
 */
static int bbr_is_inflight_too_high(struct bbr *bbr, struct quic_cc_path *p)
{
	if (!is_inflight_too_high(&bbr->drs.rs))
		return 0;

	if (bbr->bw_probe_samples)
		bbr_handle_inflight_too_high(bbr, p, &bbr->drs.rs);

	return 1;
}

static void bbr_probe_inflight_hi_upward(struct bbr *bbr, struct quic_cc_path *p, uint32_t acked)
{
	if (!bbr->drs.is_cwnd_limited || p->cwnd < bbr->inflight_hi)
		return; /* not fully using inflight_hi, so don't grow it */

	bbr->bw_probe_up_acks += acked;
	if (bbr->bw_probe_up_acks >= bbr->probe_up_cnt) {
		uint64_t delta;

		delta = bbr->bw_probe_up_acks / bbr->probe_up_cnt;
		bbr->bw_probe_up_acks -= delta * bbr->probe_up_cnt;
		bbr->inflight_hi += delta * p->mtu;
	}

	if (bbr->round_start)
		bbr_raise_inflight_hi_slope(bbr, p);
}

/* Track ACK state and update BBR.max_bw window and
 * BBR.inflight_hi.
 */
static void bbr_adapt_upper_bounds(struct bbr *bbr, struct quic_cc_path *p,
                                   uint32_t acked)
{
	if (bbr_is_inflight_too_high(bbr, p))
		return;

	if (bbr->inflight_hi == UINT64_MAX)
		return;

	if (bbr->drs.rs.tx_in_flight > bbr->inflight_hi)
		bbr->inflight_hi = bbr->drs.rs.tx_in_flight;

	if (bbr->state == BBR_ST_PROBE_BW_UP)
		bbr_probe_inflight_hi_upward(bbr, p, acked);
}


static inline int bbr_has_elapsed_in_phase(struct bbr *bbr,
                                           uint32_t interval)
{
	return tick_is_lt(tick_add(bbr->cycle_stamp, interval), now_ms);
}

static int bbr_is_reno_coexistence_probe_time(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t reno_rounds;

	reno_rounds = bbr_target_inflight(bbr, p) / p->mtu;
	return bbr->rounds_since_bw_probe >= MIN(reno_rounds, 63);
}

/* Is it time to transition from DOWN or CRUISE to REFILL? */
static int bbr_is_time_to_probe_bw(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr_has_elapsed_in_phase(bbr, bbr->bw_probe_wait) ||
	    bbr_is_reno_coexistence_probe_time(bbr, p)) {
		bbr_start_probe_bw_refill(bbr);
		return 1;
	}

	return 0;
}

/* Called to exit from ProbeBW_DONW.
 *  4.3.3.1. ProbeBW_DOWN
 *
 * Exit conditions: The flow exits the ProbeBW_DOWN phase and enters CRUISE when
 * the flow estimates that both of the following conditions have been met:
 *
 * There is free headroom: If inflight_hi is set, then BBR remains in
 * ProbeBW_DOWN at least until the volume of in-flight data is less than or equal
 * to a target calculated based on (1 - BBRHeadroom)*BBR.inflight_hi. The goal of
 * this constraint is to ensure that in cases where loss signals suggest an upper
 * limit on the volume of in-flight data, then the flow attempts to leave some
 * free headroom in the path (e.g. free space in the bottleneck buffer or free
 * time slots in the bottleneck link) that can be used by cross traffic (both for
 * convergence of bandwidth shares and for burst tolerance).
 *
 * The volume of in-flight data is less than or equal to BBR.bdp, i.e. the flow
 * estimates that it has drained any queue at the bottleneck.
 */

/* Time to transition from DOWN to CRUISE? */
static int bbr_is_time_to_cruise(struct bbr *bbr, struct quic_cc_path *p)
{
	if (p->in_flight > bbr_inflight_with_headroom(bbr, p))
		return 0; /* not enough headroom */

	if (p->in_flight <= bbr_inflight(bbr, p, bbr->max_bw, 100))
		return 1; /* inflight <= estimated BDP */

	return 0;
}

/* Time to transition from UP to DOWN? */
static int bbr_is_time_to_go_down(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr->drs.is_cwnd_limited && p->cwnd >= bbr->inflight_hi) {
		bbr_reset_full_bw(bbr); /* bw is limited by inflight_hi */
		bbr->full_bw = p->delivery_rate;
	}
	else if (bbr->full_bw_now) {
		return 1;  /* we estimate we've fully used path bw */
	}

	return 0;
}

static void bbr_check_probe_rtt_done(struct bbr *bbr, struct quic_cc_path *p)
{
	if (tick_isset(bbr->probe_rtt_done_stamp) &&
	    tick_is_lt(bbr->probe_rtt_done_stamp, now_ms)) {
		/* schedule next ProbeRTT: */
		bbr->probe_rtt_min_stamp = now_ms;
		bbr_restore_cwnd(bbr, p);
		bbr_exit_probe_rtt(bbr);
	}
}

static void bbr_mark_connection_app_limited(struct bbr *bbr, struct quic_cc_path *p)
{
	uint64_t app_limited = bbr->drs.delivered + p->in_flight;

	bbr->drs.app_limited = app_limited ? app_limited : p->mtu;
}

static void bbr_update_max_bw(struct bbr *bbr, struct quic_cc_path *p,
                              uint32_t delivered)
{
	struct quic_cc_rs *rs = &bbr->drs.rs;

	bbr_update_round(bbr, delivered);
	if (p->delivery_rate >= bbr->max_bw || !rs->is_app_limited)
		bbr->max_bw = wf_max_update(&bbr->max_bw_filter,
		                            p->delivery_rate, bbr->cycle_count);
}

static void bbr_init_lower_bounds(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr->bw_lo == UINT64_MAX)
		bbr->bw_lo = bbr->max_bw;
	if (bbr->inflight_lo == UINT64_MAX)
		bbr->inflight_lo = p->cwnd;
}

static void bbr_loss_lower_bounds(struct bbr *bbr)
{
	bbr->bw_lo = MAX(bbr->bw_latest, bbr->bw_lo * BBR_BETA_MULT / BBR_BETA_DIVI);
	bbr->inflight_lo = MAX(bbr->inflight_latest,
	                       bbr->inflight_lo * BBR_BETA_MULT / BBR_BETA_DIVI);
}

static inline int bbr_is_probing_bw(struct bbr *bbr)
{
	return bbr->state == BBR_ST_STARTUP ||
		bbr->state == BBR_ST_PROBE_BW_REFILL ||
		bbr->state == BBR_ST_PROBE_BW_UP;
}

static void bbr_adapt_lower_bounds_from_congestion(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr_is_probing_bw(bbr))
		return;

	if (bbr->loss_in_round) {
		bbr_init_lower_bounds(bbr, p);
		bbr_loss_lower_bounds(bbr);
	}
}

static void bbr_update_latest_delivery_signals(struct bbr *bbr,
                                               struct quic_cc_path *p)
{
	struct quic_cc_drs *drs = &bbr->drs;

	bbr->loss_round_start = 0;
	bbr->bw_latest = MAX(bbr->bw_latest, p->delivery_rate);
	bbr->inflight_latest = MAX(bbr->inflight_latest, drs->rs.delivered);
	if (drs->rs.prior_delivered >= bbr->loss_round_delivered) {
		bbr->loss_round_delivered = drs->delivered;
		bbr->loss_round_start = 1;
	}
}

static void bbr_update_congestion_signals(struct bbr *bbr, struct quic_cc_path *p,
                                          uint64_t bytes_lost, uint64_t delivered)
{
	bbr_update_max_bw(bbr, p, delivered);
	if (bytes_lost) {
		bbr->bytes_lost_in_round += bytes_lost;
		++bbr->loss_events_in_round;

		if (!bbr->loss_in_round) {
			bbr->loss_in_round = 1;
			bbr->loss_round_delivered = bbr->drs.delivered;
		}
	}

	if (!bbr->loss_round_start)
		return;  /* wait until end of round trip */

	bbr_adapt_lower_bounds_from_congestion(bbr, p);  /* once per round, adapt */
	bbr->loss_in_round = 0;
}

static void bbr_update_ack_aggregation(struct bbr *bbr,
                                       struct quic_cc_path *p,
                                       uint32_t acked)
{
	uint32_t interval = now_ms - bbr->extra_acked_interval_start;
	uint64_t expected_delivered = bbr->bw * interval / 1000;
	uint64_t extra;

	if (bbr->extra_acked_delivered <= expected_delivered) {
		bbr->extra_acked_delivered = 0;
		bbr->extra_acked_interval_start = now_ms;
		expected_delivered = 0;
	}

	bbr->extra_acked_delivered += acked;
	extra = bbr->extra_acked_delivered - expected_delivered;
	extra = MIN(extra, p->cwnd);

	bbr->extra_acked = wf_max_update(&bbr->extra_acked_filter, extra, bbr->round_count);
}

/* 4.3.1. Startup
 *
 * During Startup, BBR estimates whether the pipe is full using two estimators.
 * The first looks for a plateau in the BBR.max_bw estimate. The second looks
 * for packet loss.
 */
static void bbr_check_startup_done(struct bbr *bbr, struct quic_cc_path *p)
{
	bbr_check_startup_high_loss(bbr, p);
	if (bbr->state == BBR_ST_STARTUP && bbr->full_bw_reached)
		bbr_enter_drain(bbr);
}

/* 4.3.2. Drain
 * In Drain, when the amount of data in flight is less than or equal to the
 * estimated BDP, meaning BBR estimates that the queue at the bottleneck link
 * has been fully drained, then BBR exits Drain and enters ProbeBW.
 */
static void bbr_check_drain_done(struct bbr *bbr,
                                 struct quic_cc_path *p)
{
	if (bbr->state == BBR_ST_DRAIN &&
	    p->in_flight <= bbr_inflight(bbr, p, bbr->bw, 100))
		bbr_start_probe_bw_down(bbr);
}

/* The core state machine logic for ProbeBW: */
static void bbr_update_probe_bw_cycle_phase(struct bbr *bbr, struct quic_cc_path *p,
                                            uint32_t acked)
{
	if (!bbr->full_bw_reached)
		return; /* only handling steady-state behavior here */

	bbr_adapt_upper_bounds(bbr, p, acked);
	if (!bbr_is_in_a_probe_bw_state(bbr))
		return; /* only handling ProbeBW states here: */

	switch (bbr->state) {
	case BBR_ST_PROBE_BW_DOWN:
		if (bbr_is_time_to_probe_bw(bbr, p))
			return;/* already decided state transition */

		if (bbr_is_time_to_cruise(bbr, p))
			bbr_start_probe_bw_cruise(bbr);
		break;

	case BBR_ST_PROBE_BW_CRUISE:
		if (bbr_is_time_to_probe_bw(bbr, p))
			return; /* already decided state transition */
		break;

	case BBR_ST_PROBE_BW_REFILL:
		/* After one round of REFILL, start UP */
		if (bbr->round_start) {
			bbr->bw_probe_samples = 1;
			bbr_start_probe_bw_up(bbr, p);
		}
		break;

	case BBR_ST_PROBE_BW_UP:
		if (bbr_is_time_to_go_down(bbr, p))
			bbr_start_probe_bw_down(bbr);
		break;

	default:
		break;
	}
}

/* 4.3.4.4. ProbeRTT Logic
 *
 * On every ACK BBR executes BBRUpdateMinRTT() to update its ProbeRTT scheduling
 * state (BBR.probe_rtt_min_delay and BBR.probe_rtt_min_stamp) and its
 * BBR.min_rtt estimate.
 * Here BBR.probe_rtt_expired is a boolean recording whether the
 * BBR.probe_rtt_min_delay has expired and is due for a refresh, via either an
 * application idle period or a transition into ProbeRTT state.
 */
static void bbr_update_min_rtt(struct bbr *bbr, uint32_t ack_rtt)
{
	int min_rtt_expired;

	bbr->probe_rtt_expired =
		tick_is_lt(tick_add(bbr->probe_rtt_min_stamp, BBR_PROBE_RTT_INTERVAL), now_ms);
	if (ack_rtt != UINT32_MAX && (ack_rtt < bbr->probe_rtt_min_delay ||
	                              bbr->probe_rtt_expired)) {
		bbr->probe_rtt_min_delay = ack_rtt;
		bbr->probe_rtt_min_stamp = now_ms;
	}

	min_rtt_expired =
		tick_is_lt(tick_add(bbr->min_rtt_stamp, BBR_MIN_RTT_FILTERLEN), now_ms);
	if (bbr->probe_rtt_min_delay < bbr->min_rtt || min_rtt_expired) {
		bbr->min_rtt       = bbr->probe_rtt_min_delay;
		bbr->min_rtt_stamp = bbr->probe_rtt_min_stamp;
	}
}

static void bbr_handle_probe_rtt(struct bbr *bbr, struct quic_cc_path *p)
{
	/* Ignore low rate samples during ProbeRTT: */
	bbr_mark_connection_app_limited(bbr, p);
	if (!tick_isset(bbr->probe_rtt_done_stamp) &&
		p->in_flight <= bbr_probe_rtt_cwnd(bbr, p)) {
		/* Wait for at least ProbeRTTDuration to elapse: */
		bbr->probe_rtt_done_stamp = tick_add(now_ms, BBR_PROBE_RTT_DURATION);
		/* Wait for at least one round to elapse: */
		bbr->probe_rtt_round_done = 0;
		bbr_start_round(bbr);
	}
	else if (tick_isset(bbr->probe_rtt_done_stamp)) {
		if (bbr->round_start)
			bbr->probe_rtt_round_done = 1;
		if (bbr->probe_rtt_round_done)
			bbr_check_probe_rtt_done(bbr, p);
	}
}

/* On every ACK BBR executes BBRCheckProbeRTT() to handle the steps related to
 * the ProbeRTT state.
 */
static inline void bbr_check_probe_rtt(struct bbr *bbr, struct quic_cc_path *p)
{
	if (bbr->state != BBR_ST_PROBE_RTT &&
	    bbr->probe_rtt_expired && !bbr->idle_restart) {
		bbr_enter_probe_rtt(bbr);
		bbr_save_cwnd(bbr, p);
		bbr->probe_rtt_done_stamp = TICK_ETERNITY;
		bbr_start_round(bbr);
	}

	if (bbr->state == BBR_ST_PROBE_RTT)
		bbr_handle_probe_rtt(bbr, p);
	if (bbr->drs.rs.delivered > 0)
		bbr->idle_restart = 0;
}

static inline void bbr_advance_latest_delivery_signals(struct bbr *bbr,
                                                       struct quic_cc_path *p)
{
	if (bbr->loss_round_start) {
		bbr->bw_latest = p->delivery_rate;
		bbr->inflight_latest = bbr->drs.rs.delivered;
	}
}

static inline void bbr_bound_bw_for_model(struct bbr *bbr)
{
	bbr->bw = MIN(bbr->max_bw, bbr->bw_lo);
}

static void bbr_update_model_and_state(struct bbr *bbr,
                                       struct quic_cc_path *p,
                                       uint32_t acked,
                                       uint32_t delivered,
                                       uint32_t ack_rtt,
                                       uint32_t bytes_lost)
{
	bbr_update_latest_delivery_signals(bbr, p);
	bbr_update_congestion_signals(bbr, p, bytes_lost, delivered);
	bbr_update_ack_aggregation(bbr, p, acked);
	bbr_check_full_bw_reached(bbr, p);
	bbr_check_startup_done(bbr, p);
	bbr_check_drain_done(bbr, p);
	bbr_update_probe_bw_cycle_phase(bbr, p, acked);
	bbr_update_min_rtt(bbr, ack_rtt);
	bbr_check_probe_rtt(bbr, p);
	bbr_advance_latest_delivery_signals(bbr, p);
	bbr_bound_bw_for_model(bbr);
}

static void bbr_update_control_parameters(struct bbr *bbr,
                                          struct quic_cc_path *p,
                                          uint32_t acked)
{
	bbr_set_pacing_rate(bbr, p);
	bbr_set_send_quantum(bbr, p);
	bbr_set_cwnd(bbr, p, acked);
}

static inline int in_recovery_period(struct quic_cc_path *p, uint32_t ts)
{
	return tick_isset(p->recovery_start_ts) &&
		tick_is_le(ts, p->recovery_start_ts);
}

static void bbr_handle_recovery(struct bbr *bbr, struct quic_cc_path *p,
                                unsigned int largest_pkt_sent_ts,
                                uint32_t acked)
{
	if (bbr->in_loss_recovery) {
		if (tick_isset(largest_pkt_sent_ts) &&
		    !in_recovery_period(p, largest_pkt_sent_ts)) {
			bbr->in_loss_recovery = 0;
			bbr->round_count_at_recovery = UINT64_MAX;
			bbr_restore_cwnd(bbr, p);
		}

		return;
	}

	if (!tick_isset(bbr->recovery_start_ts))
		return;

	bbr->in_loss_recovery = 1;
	bbr->round_count_at_recovery =
		bbr->round_start ? bbr->round_count : bbr->round_count + 1;
	bbr_save_cwnd(bbr, p);
	p->cwnd = p->in_flight + MAX(acked, p->mtu);
	p->recovery_start_ts = bbr->recovery_start_ts;
	bbr->recovery_start_ts = TICK_ETERNITY;
}

/* On every ACK, BBR updates its model, its state machine and its control
 * parameters.
 */
static void bbr_update_on_ack(struct quic_cc *cc,
                              uint32_t acked, uint32_t delivered, uint32_t rtt,
                              uint32_t bytes_lost, unsigned largest_pkt_sent_ts)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	bbr_handle_recovery(bbr, p, largest_pkt_sent_ts, acked);
	bbr_update_model_and_state(bbr, p, acked, delivered, rtt, bytes_lost);
	bbr_update_control_parameters(bbr, p, acked);
}

/* At what prefix of packet did losses exceed BBRLossThresh? */
static uint64_t bbr_inflight_hi_from_lost_packet(struct quic_cc_rs *rs,
                                                 struct quic_tx_packet *pkt)
{
	uint64_t inflight_prev, lost_prev, lost_prefix;
	uint64_t size = pkt->len;

	BUG_ON(rs->tx_in_flight < size);
	/* What was in flight before this packet? */
	inflight_prev = rs->tx_in_flight - size;
	BUG_ON(rs->lost < size);
	/* What was lost before this packet? */
	lost_prev = rs->lost - size;
	if (BBR_LOSS_THRESH_MULT * inflight_prev < lost_prev * BBR_LOSS_THRESH_DIVI)
		return inflight_prev;

	lost_prefix =
		(BBR_LOSS_THRESH_MULT * inflight_prev - lost_prev * BBR_LOSS_THRESH_DIVI) /
		(BBR_LOSS_THRESH_DIVI - BBR_LOSS_THRESH_MULT);
	/* At what inflight value did losses cross BBRLossThresh? */
	return inflight_prev + lost_prefix;
}

static void bbr_note_loss(struct bbr *bbr, uint64_t C_delivered)
{
	if (!bbr->loss_in_round)   /* first loss in this round trip? */
		bbr->loss_round_delivered = C_delivered;
	bbr->loss_in_round = 1;
}

static void bbr_handle_lost_packet(struct bbr *bbr, struct quic_cc_path *p,
                                   struct quic_tx_packet *pkt,
                                   uint32_t lost)
{
	struct quic_cc_rs rs;

	/* C.delivered = bbr->drs.delivered */
	bbr_note_loss(bbr, bbr->drs.delivered);
	if (!bbr->bw_probe_samples)
		return; /* not a packet sent while probing bandwidth */

	/* Only ->tx_in_fligth, ->lost and ->is_app_limited <rs> member
	 * initializations are needed.
	 */
	rs.tx_in_flight = pkt->rs.tx_in_flight; /* inflight at transmit */
	BUG_ON(bbr->drs.lost + pkt->len < lost);
	/* bbr->rst->lost is not yet incremented */
	rs.lost = bbr->drs.lost + pkt->len - lost; /* data lost since transmit */
	rs.is_app_limited = pkt->rs.is_app_limited;
	if (is_inflight_too_high(&rs)) {
		rs.tx_in_flight = bbr_inflight_hi_from_lost_packet(&rs, pkt);
		bbr_handle_inflight_too_high(bbr, p, &rs);
	}
}

/* 4.2.4. Per-Loss Steps
 *
 * On every packet loss event, where some sequence range "packet" is marked lost,
 * the BBR algorithm executes the following BBRUpdateOnLoss() steps in order to
 * update its network path model
 */
static void bbr_update_on_loss(struct quic_cc *cc, struct quic_tx_packet *pkt,
                               uint32_t lost)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	if (bbr->state == BBR_ST_STARTUP) {
		/* Not in RFC. That said, during Startup, the packet loss is handled by
		 * bbr_check_startup_high_loss().
		 */
		return;
	}

	bbr_handle_lost_packet(bbr, p, pkt, lost);
}

static void bbr_handle_restart_from_idle(struct bbr *bbr, struct quic_cc_path *p)
{
	if (p->in_flight != 0 || !bbr->drs.app_limited)
		return;

	bbr->idle_restart = 1;
	bbr->extra_acked_interval_start = now_ms;

	if (bbr_is_in_a_probe_bw_state(bbr))
		bbr_set_pacing_rate_with_gain(bbr, p, 100);
	else if (bbr->state == BBR_ST_PROBE_RTT)
		bbr_check_probe_rtt_done(bbr, p);
}

/* To be called upon packet transmissions. */
static void bbr_on_transmit(struct quic_cc *cc)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	bbr_handle_restart_from_idle(bbr, p);
}

/* Update the delivery rate sampling state upon <pkt> packet transmission */
static void bbr_drs_on_transmit(struct quic_cc *cc, struct quic_tx_packet *pkt)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	quic_cc_drs_on_pkt_sent(p, pkt, &bbr->drs);
}

/* Callback to be called on every congestion event detection. */
static void bbr_congestion_event(struct quic_cc *cc, uint32_t ts)
{
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);
	struct bbr *bbr = quic_cc_priv(&p->cc);

	if (bbr->in_loss_recovery ||
		tick_isset(bbr->recovery_start_ts) || in_recovery_period(p, ts))
		return;

	bbr->recovery_start_ts = now_ms;
}

/* Callback to return the delivery rate sample struct from <cc> */
struct quic_cc_drs *bbr_get_drs(struct quic_cc *cc)
{
	return &((struct bbr *)quic_cc_priv(cc))->drs;
}

/* Return the pacing delay between bursts of packets in nanoseconds. */
uint bbr_pacing_inter(const struct quic_cc *cc)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	return p->mtu * 1000000000 / bbr->pacing_rate;
}

/* Return the pacing burst size in datagrams */
uint bbr_pacing_burst(const struct quic_cc *cc)
{
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	return p->send_quantum / p->mtu;
}

/* Update the delivery rate sampling state about the application limitation. */
static void bbr_check_app_limited(const struct quic_cc *cc, int sent)
{
	struct bbr *bbr = quic_cc_priv(cc);
	struct quic_cc_drs *drs = &bbr->drs;
	struct quic_cc_path *p = container_of(cc, struct quic_cc_path, cc);

	if (p->in_flight >= p->cwnd) {
		drs->is_cwnd_limited = 1;
	}
	else if (!sent) {
		drs->app_limited = drs->delivered + p->in_flight;
		if (!drs->app_limited)
			drs->app_limited = p->mtu;
	}
}

static inline const char *bbr_state_str(struct bbr *bbr)
{
	switch (bbr->state) {
	case BBR_ST_STARTUP:
		return "s";
	case BBR_ST_DRAIN:
		return "d";
	case BBR_ST_PROBE_BW_DOWN:
		return "pbd";
	case BBR_ST_PROBE_BW_CRUISE:
		return "pbc";
	case BBR_ST_PROBE_BW_REFILL:
		return "pbf";
	case BBR_ST_PROBE_BW_UP:
		return "pbu";
	case BBR_ST_PROBE_RTT:
		return "pr";
	default:
		return "uk";
	}
}

/* Callback used to dump BBR specific information from "show quic" CLI command. */
static void bbr_state_cli(struct buffer *buf, const struct quic_cc_path *p)
{
	struct bbr *bbr = quic_cc_priv(&p->cc);

	chunk_appendf(buf, "  bbr: st=%s max_bw=%llu min_rtt=%llu bw=%llu"
	              " sq=%llu pacing_rate=%llu\n",
	              bbr_state_str(bbr), (ull)bbr->max_bw, (ull)bbr->min_rtt,
	              (ull)bbr->bw, (ull)p->send_quantum, (ull)bbr->pacing_rate);
}

struct quic_cc_algo quic_cc_algo_bbr = {
	.type        = QUIC_CC_ALGO_TP_BBR,
	.init        = bbr_init,
	.pacing_inter = bbr_pacing_inter,
	.pacing_burst = bbr_pacing_burst,
	.get_drs     = bbr_get_drs,
	.on_transmit = bbr_on_transmit,
	.drs_on_transmit = bbr_drs_on_transmit,
	.on_ack_rcvd = bbr_update_on_ack,
	.congestion_event = bbr_congestion_event,
	.on_pkt_lost = bbr_update_on_loss,
	.check_app_limited = bbr_check_app_limited,
	.state_cli   = bbr_state_cli,
};

void bbr_check(void)
{
	struct quic_cc *cc;
	BUG_ON(sizeof(struct bbr) > sizeof(cc->priv));
}

INITCALL0(STG_REGISTER, bbr_check);
