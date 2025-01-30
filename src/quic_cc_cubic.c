#include <haproxy/global-t.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_cc_hystart.h>
#include <haproxy/quic_trace.h>
#include <haproxy/ticks.h>
#include <haproxy/trace.h>

/* IMPORTANT NOTE about the units defined by the RFC 9438
 * (CUBIC for Fast and Long-Distance Networks):
 *
 * RFC 9438 4.1. Definitions:
 * The unit of all window sizes in this document is segments of the SMSS, and
 * the unit of all times is seconds. Implementations can use bytes to express
 * window sizes, which would require factoring in the SMSS wherever necessary
 * and replacing segments_acked (Figure 4) with the number of acknowledged
 * bytes.
 */

/* So, this is the reason why here in this implementation each time a number
 * of segments is used (typically a congestion window value), its value is
 * multiplied by the MTU value.
 */

/* This source file is highly inspired from Linux kernel source file
 * implementation for TCP Cubic. In fact, we have no choice if we do
 * not want to use any floating point operations to be fast!
 * (See net/ipv4/tcp_cubic.c)
 */

/* Constants definitions:
 * CUBIC_BETA_SCALED refers to the scaled value of RFC 9438 beta_cubic variable.
 * CUBIC_C_SCALED    refers to the scaled value of RFC 9438 C variable.
 */

/* The right shifting value to apply to scaled values to get its real value. */
#define CUBIC_SCALE_FACTOR_SHIFT     10

/* CUBIC multiplicative decrease factor as described in RFC 9438 section 4.6 */
#define CUBIC_BETA_SCALED           717  /* beta_cubic = 0.7 (constant) */

/* CUBIC C constant that determines the aggressiveness of CUBIC in competing
 * with other congestion control algorithms in high-BDP networks.
 */
#define CUBIC_C_SCALED              410  /* RFC 9438 C = 0.4 segment/seconds^3
                                          * or 410 mB/s^3 in this implementation.
                                          */

/* The scaled value of 1 */
#define CUBIC_ONE_SCALED  (1 << CUBIC_SCALE_FACTOR_SHIFT)

/* The maximum time value which may be cubed and multiplied by CUBIC_C_SCALED */
#define CUBIC_TIME_LIMIT    355535ULL  /* ms */

/* By connection CUBIC algorithm state. Note that the current congestion window
 * value is not stored in this structure.
 */
struct cubic {
	/* QUIC_CC_ST_* state values. */
	uint32_t state;
	/* Slow start threshold (in bytes) */
	uint32_t ssthresh;
	/* Remaining number of acknowledged bytes between two ACK for CUBIC congestion
	 * control window (in bytes).
	 */
	uint32_t remaining_inc;
	/* Start time of at which the current avoidance stage started (in ms). */
	uint32_t t_epoch;
	/* The window to reach for each recovery period during a concave region (in bytes). */
	uint32_t W_target;
	/* The time period to reach W_target during a concave region (in ms). */
	uint32_t K;
	/* The last window maximum reached (in bytes). */
	uint32_t last_w_max;
	/* Estimated value of the Reno congestion window in the TCP-friendly region (in bytes). */
	uint32_t W_est;
	/* Remaining number of acknowledged bytes between two ACKs for estimated
	 * TCP-Reno congestion control window (in bytes).
	 */
	uint32_t remaining_W_est_inc;
	/* Start time of recovery period (used to avoid re-entering this state, if already
	 * in recovery period) (in ms).
	 */
	uint32_t recovery_start_time;
	/* HyStart++ state. */
	struct quic_hystart hystart;
	/* Consecutive number of losses since last ACK */
	uint32_t consecutive_losses;
};

static void quic_cc_cubic_reset(struct quic_cc *cc)
{
	struct cubic *c = quic_cc_priv(cc);

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	c->state = QUIC_CC_ST_SS;
	c->ssthresh = QUIC_CC_INFINITE_SSTHESH;
	c->remaining_inc = 0;
	c->remaining_W_est_inc = 0;
	c->t_epoch = 0;
	c->W_target = 0;
	c->K = 0;
	c->last_w_max = 0;
	c->W_est = 0;
	c->recovery_start_time = 0;
	if (global.tune.options & GTUNE_QUIC_CC_HYSTART)
		quic_cc_hystart_reset(&c->hystart);
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc);
}

static int quic_cc_cubic_init(struct quic_cc *cc)
{
	struct cubic *c = quic_cc_priv(cc);

	quic_cc_cubic_reset(cc);
	c->consecutive_losses = 0;
	return 1;
}

/* Cubic root.
 * Highly inspired from Linux kernel sources.
 * See net/ipv4/tcp_cubic.c
 */
static uint32_t cubic_root(uint64_t val)
{
	uint32_t x, b, shift;

	static const uint8_t v[] = {
		  0,   54,   54,   54,  118,  118,  118,  118,
		123,  129,  134,  138,  143,  147,  151,  156,
		157,  161,  164,  168,  170,  173,  176,  179,
		181,  185,  187,  190,  192,  194,  197,  199,
		200,  202,  204,  206,  209,  211,  213,  215,
		217,  219,  221,  222,  224,  225,  227,  229,
		231,  232,  234,  236,  237,  239,  240,  242,
		244,  245,  246,  248,  250,  251,  252,  254,
	};

	if (!val || (b = my_flsl(val)) < 7) {
		/* val in [0..63] */
		return ((uint32_t)v[(uint32_t)val] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (val >> (b * 3));

	x = ((uint32_t)(((uint32_t)v[shift] + 10) << b)) >> 6;

	x = 2 * x + (uint32_t)(val / ((uint64_t)x * (uint64_t)(x - 1)));
	x = ((x * 341) >> 10);

	return x;
}

/*
 * RFC 9438 3.1. Principle 1 for the CUBIC Increase Function
 *
 * For better network utilization and stability, CUBIC [HRX08] uses a cubic
 * window increase function in terms of the elapsed time from the last
 * congestion event. While most congestion control algorithms that provide
 * alternatives to Reno increase the congestion window using convex functions,
 * CUBIC uses both the concave and convex profiles of a cubic function for
 * window growth.
 *
 * After a window reduction in response to a congestion event detected by
 * duplicate acknowledgments (ACKs), Explicit Congestion Notification-Echo
 * (ECN-Echo (ECE)) ACKs [RFC3168], RACK-TLP for TCP [RFC8985], or QUIC loss
 * detection [RFC9002], CUBIC remembers the congestion window size at which it
 * received the congestion event and performs a multiplicative decrease of the
 * congestion window. When CUBIC enters into congestion avoidance, it starts to
 * increase the congestion window using the concave profile of the cubic
 * function. The cubic function is set to have its plateau at the remembered
 * congestion window size, so that the concave window increase continues until
 * then. After that, the cubic function turns into a convex profile and the
 * convex window increase begins.
 *
 *  W_cubic(time) (bytes)
 *          ^                                            convex region
 *          |                                      <------------------------->
 *          |                                      .                         +
 *          |                                      .                         +
 *          |                                      .                         +
 *          |                                      .                        +
 *          |                                      .                      + ^
 *          |                                      .                   +    | W_cubic_t
 *          |                                      .               +        |
 *          |                                      .         +              |
 * W_target |-----------+--------------------------+------------------------+
 * (W_max)  |          +.                +         .                        t
 *          |         + .          +               .
 *          |       +   .      +                   .
 *          |    +      .   +                      .
 *          | +         . +                        .
 *          |           .+                         .
 *          |           +                          .
 *          |           +                          .
 *          |           +                          .
 *          |           .                          .
 *          |           .                          .
 *          |           .                          .
 *          +-----------+--------------------------+-+------------------------> time (s)
 *        0          t_epoch                 (t_epoch + K)
 *                      <-------------------------->
 *                      .      concave region
 *                      .
 *                  congestion
 *                    event
 *
 * RFC 9438 4.2. Window Increase Function:
 *
 *     W_cubic(t) = C*(t-K)^3 + W_max         (Figure 1)
 *     K = cubic_root((W_max - cwnd_epoch)/C) (Figure 2)
 *
 *     +--------------------------------------------------------------------+
 *     |     RFC 9438 definitions      |        Code variables              |
 *     +--------------------------------------------------------------------+
 *     |        C (segments/s^3)       |   CUBIC_C_SCALED (mB/s^3)          |
 *     +--------------------------------------------------------------------+
 *     |       W_max (segments)        | c->last_w_max - path->cwnd (bytes) |
 *     +--------------------------------------------------------------------+
 *     |           K (s)               |         c->K (ms)                  |
 *     +--------------------------------------------------------------------+
 *     |    beta_cubic (constant)      |   CUBIC_BETA_SCALED (constant)     |
 *     +--------------------------------------------------------------------+
 */
static inline void quic_cubic_update(struct quic_cc *cc, uint32_t acked)
{
	struct cubic *c = quic_cc_priv(cc);
	struct quic_cc_path *path = container_of(cc, struct quic_cc_path, cc);
	/* The elapsed time since the start of the congestion event. */
	uint32_t elapsed_time;
	/* Target value of the congestion window. */
	uint32_t target;
	/* The time at which the congestion window will be computed based
	 * on the cubic increase function.
	 */
	uint64_t t;
	/* The computed value of the congestion window at time t based on the cubic
	 * increase function.
	 */
	uint64_t W_cubic_t;
	uint32_t inc, inc_diff;

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	if (!c->t_epoch) {
		c->t_epoch = now_ms;
		if (c->last_w_max <= path->cwnd) {
			c->K = 0;
			c->W_target = path->cwnd;
		}
		else {
			uint64_t wnd_diff;

			/* K value computing (in seconds):
			 * K = cubic_root((W_max - cwnd_epoch)/C) (Figure 2)
			 * Note that K is stored in milliseconds and that
			 * 8000 * 125000 = 1000^3.
			 *
			 * Supporting 2^40 windows, shifted by 10, leaves ~13 bits of unused
			 * precision. We exploit this precision for our NS conversion by
			 * multiplying by 8000 without overflowing, then later by 125000
			 * after the divide so that we limit the precision loss to the minimum
			 * before the cubic_root() call."
			 */
			wnd_diff = (c->last_w_max - path->cwnd) << CUBIC_SCALE_FACTOR_SHIFT;
			wnd_diff *= 8000ULL;
			wnd_diff /= CUBIC_C_SCALED * path->mtu;
			wnd_diff *= 125000ULL;
			c->K = cubic_root(wnd_diff);
			c->W_target = c->last_w_max;
		}

		c->W_est = path->cwnd;
		c->remaining_inc = 0;
		c->remaining_W_est_inc = 0;
	}

	elapsed_time = now_ms + path->loss.rtt_min - c->t_epoch;
	if (elapsed_time < c->K) {
		t = c->K - elapsed_time;
	}
	else {
		t = elapsed_time - c->K;
	}

	if (t > CUBIC_TIME_LIMIT) {
		/* TODO : should not happen if we handle the case
		 * of very late acks receipt. This must be handled as a congestion
		 * control event: a very late ack should trigger a congestion
		 * control algorithm reset.
		 */
		quic_cc_cubic_reset(cc);
		goto leave;
	}

	/* Compute W_cubic_t at t time. */
	W_cubic_t = CUBIC_C_SCALED * path->mtu;
	W_cubic_t = (W_cubic_t * t) / 1000;
	W_cubic_t = (W_cubic_t * t) / 1000;
	W_cubic_t = (W_cubic_t * t) / 1000;
	W_cubic_t >>= CUBIC_SCALE_FACTOR_SHIFT;
	if (elapsed_time < c->K)
		target = c->W_target - W_cubic_t;
	else
		target = c->W_target + W_cubic_t;

	if (target > path->cwnd) {
		/* Concave region */

		/* RFC 9438 4.4. Concave Region
		 *
		 * When receiving a new ACK in congestion avoidance, if CUBIC is not in
		 * the Reno-friendly region and cwnd is less than Wmax, then CUBIC is
		 * in the concave region. In this region, cwnd MUST be incremented by
		 * (target - cwnd) / cwnd.
		 */
		inc_diff = c->remaining_inc + path->mtu * (target - path->cwnd);
		c->remaining_inc = inc_diff % path->cwnd;
		inc = inc_diff / path->cwnd;
	}
	else {
		/* Convex region: very small increment */

		/* RFC 9438  4.5. Convex Region
		 *
		 * When receiving a new ACK in congestion avoidance, if CUBIC is not in
		 * the Reno-friendly region and cwnd is larger than or equal to Wmax,
		 * then CUBIC is in the convex region.The convex region indicates that
		 * the network conditions might have changed since the last congestion
		 * event, possibly implying more available bandwidth after some flow
		 * departures. Since the Internet is highly asynchronous, some amount
		 * of perturbation is always possible without causing a major change in
		 * available bandwidth.Unless the cwnd is overridden by the AIMD window
		 * increase, CUBIC will behave cautiously when operating in this region.
		 * The convex profile aims to increase the window very slowly at the
		 * beginning when cwnd is around Wmax and then gradually increases its
		 * rate of increase. This region is also called the "maximum probing
		 * phase", since CUBIC is searching for a new Wmax.  In this region,
		 * cwnd MUST be incremented by (target - cwnd) / cwnd) for each received
		 * new ACK, where target is calculated as described in Section 4.2.
		 */
		inc_diff = c->remaining_inc + path->mtu;
		c->remaining_inc = inc_diff % (100 * path->cwnd);
		inc = inc_diff / (100 * path->cwnd);
	}

	inc_diff = c->remaining_W_est_inc + path->mtu * acked;
	c->W_est += inc_diff / path->cwnd;
	c->remaining_W_est_inc = inc_diff % path->cwnd;

	/* TCP friendliness :
	 * RFC 9438 4.3.  Reno-Friendly Region
	 *
	 * Reno performs well in certain types of networks -- for example, under
	 * short RTTs and small bandwidths (or small BDPs). In these networks,
	 * CUBIC remains in the Reno-friendly region to achieve at least the same
	 * throughput as Reno.
	 *
	 * When receiving a new ACK in congestion avoidance (where cwnd could be
	 * greater than or less than Wmax), CUBIC checks whether Wcubic(t) is less
	 * than West.  If so, CUBIC is in the Reno-friendly region and cwnd SHOULD
	 * be set to West at each reception of a new ACK.
	 *
	 * West is set equal to cwnd_epoch at the start of the congestion avoidance
	 * stage. After that, on every new ACK, West is updated using Figure 4.
	 * Note that this equation uses segments_acked and cwnd is measured in
	 * segments. An implementation that measures cwnd in bytes should adjust the
	 * equation accordingly using the number of acknowledged bytes and the SMSS.
	 * Also note that this equation works for connections with enabled or
	 * disabled delayed ACKs [RFC5681], as segments_acked will be different based
	 * on the segments actually acknowledged by a new ACK.
	 *
	 * Figure 4 : West = West + alpha_cubic * (segments_acked / cwnd)
	 *
	 * Once West has grown to reach the cwnd at the time of most recently
	 * setting ssthresh -- that is, West >= cwndprior -- the sender SHOULD set
	 * alpha_cubic to 1 to ensure that it can achieve the same congestion window
	 * increment rate as Reno, which uses AIMD(1, 0.5).
	 */
	if (c->W_est > path->cwnd) {
		uint32_t W_est_inc = path->mtu * (c->W_est - path->cwnd) / path->cwnd;
		if (W_est_inc > inc)
			inc = W_est_inc;
	}

	if (quic_cwnd_may_increase(path)) {
		path->cwnd += inc;
		path->cwnd = QUIC_MIN(path->max_cwnd, path->cwnd);
		path->mcwnd = QUIC_MAX(path->cwnd, path->mcwnd);
	}
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc);
}

static void quic_cc_cubic_slow_start(struct quic_cc *cc)
{
	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	quic_cc_cubic_reset(cc);
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc);
}

static void quic_enter_recovery(struct quic_cc *cc)
{
	struct quic_cc_path *path = container_of(cc, struct quic_cc_path, cc);
	struct cubic *c = quic_cc_priv(cc);
	/* Current cwnd as number of packets */

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	c->t_epoch = 0;
	c->recovery_start_time = now_ms;

	/* RFC 9438 4.7.  Fast Convergence
	 *
	 * To improve convergence speed, CUBIC uses a heuristic. When a new flow
	 * joins the network, existing flows need to give up some of their bandwidth
	 * to allow the new flow some room for growth if the existing flows have
	 * been using all the network bandwidth. To speed up this bandwidth release
	 * by existing flows, the following fast convergence mechanism SHOULD be
	 * implemented.With fast convergence, when a congestion event occurs, Wmax
	 * is updated as follows, before the window reduction described in Section
	 * 4.6.
	 *
	 *       if cwnd < Wmax and fast convergence enabled, further reduce Wax:
	 *              Wmax = cwnd * (1 + beta_cubic)
	 *       otherwise, remember cwn before reduction:
	 *              Wmax = cwnd
	 */
	if (path->cwnd < c->last_w_max) {
		/* (1 + beta_cubic) * path->cwnd / 2 */
		c->last_w_max = (path->cwnd * (CUBIC_ONE_SCALED + CUBIC_BETA_SCALED) / 2) >> CUBIC_SCALE_FACTOR_SHIFT;
	}
	else {
		c->last_w_max = path->cwnd;
	}

	c->ssthresh = (CUBIC_BETA_SCALED * path->cwnd) >> CUBIC_SCALE_FACTOR_SHIFT;
	path->cwnd =  QUIC_MAX(c->ssthresh, (uint32_t)path->min_cwnd);
	c->state = QUIC_CC_ST_RP;
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc, NULL, cc);
}

/* Congestion slow-start callback. */
static void quic_cc_cubic_ss_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	struct quic_cc_path *path = container_of(cc, struct quic_cc_path, cc);
	struct cubic *c = quic_cc_priv(cc);

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	TRACE_PROTO("CC cubic", QUIC_EV_CONN_CC, cc->qc, ev);
	switch (ev->type) {
	case QUIC_CC_EVT_ACK:
		if (global.tune.options & GTUNE_QUIC_CC_HYSTART) {
			struct quic_hystart *h = &c->hystart;
			unsigned int acked = QUIC_MIN(ev->ack.acked, (uint64_t)HYSTART_LIMIT * path->mtu);

			if (path->cwnd >= QUIC_CC_INFINITE_SSTHESH - acked)
				goto out;

			if (quic_cwnd_may_increase(path)) {
				path->cwnd += acked;
				path->mcwnd = QUIC_MAX(path->cwnd, path->mcwnd);
			}
			quic_cc_hystart_track_min_rtt(cc, h, path->loss.latest_rtt);
			if (ev->ack.pn >= h->wnd_end)
				h->wnd_end = UINT64_MAX;
			if (quic_cc_hystart_may_enter_cs(&c->hystart)) {
				/* Exit slow start and enter conservative slow start */
				c->state = QUIC_CC_ST_CS;
				goto out;
			}
		}
		else if (path->cwnd < QUIC_CC_INFINITE_SSTHESH - ev->ack.acked) {
			if (quic_cwnd_may_increase(path)) {
				path->cwnd += ev->ack.acked;
				path->cwnd = QUIC_MIN(path->max_cwnd, path->cwnd);
			}
		}
		/* Exit to congestion avoidance if slow start threshold is reached. */
		if (path->cwnd >= c->ssthresh)
			c->state = QUIC_CC_ST_CA;
		path->mcwnd = QUIC_MAX(path->cwnd, path->mcwnd);
		break;

	case QUIC_CC_EVT_LOSS:
		quic_enter_recovery(cc);
		break;

	case QUIC_CC_EVT_ECN_CE:
		/* TODO */
		break;
	}

 out:
	TRACE_PROTO("CC cubic", QUIC_EV_CONN_CC, cc->qc, NULL, cc);
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc);
}

/* Congestion avoidance callback. */
static void quic_cc_cubic_ca_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	struct cubic *c = quic_cc_priv(cc);

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	TRACE_PROTO("CC cubic", QUIC_EV_CONN_CC, cc->qc, ev);
	switch (ev->type) {
	case QUIC_CC_EVT_ACK:
		c->consecutive_losses = 0;
		quic_cubic_update(cc, ev->ack.acked);
		break;
	case QUIC_CC_EVT_LOSS:
		/* Principle: we may want to tolerate one or a few occasional
		 * losses that are *not* caused by congestion that we'd have
		 * any control on. Tests show that over long distances this
		 * significantly improves the transfer stability and
		 * performance, but can quickly result in a massive loss
		 * increase if set too high. This counter is reset upon ACKs.
		 * Maybe we could refine this to consider only certain ACKs
		 * though.
		 */
		c->consecutive_losses += ev->loss.count;
		if (c->consecutive_losses <= global.tune.quic_cubic_loss_tol)
			goto out;
		quic_enter_recovery(cc);
		break;
	case QUIC_CC_EVT_ECN_CE:
		/* TODO */
		break;
	}

 out:
	TRACE_PROTO("CC cubic", QUIC_EV_CONN_CC, cc->qc, NULL, cc);
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc);
}

/* Conservative slow start callback. */
static void quic_cc_cubic_cs_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	struct quic_cc_path *path = container_of(cc, struct quic_cc_path, cc);

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	TRACE_PROTO("CC cubic", QUIC_EV_CONN_CC, cc->qc, ev);

	switch (ev->type) {
	case QUIC_CC_EVT_ACK:
	{
		struct cubic *c = quic_cc_priv(cc);
		struct quic_hystart *h = &c->hystart;
		unsigned int acked =
			QUIC_MIN(ev->ack.acked, (uint64_t)HYSTART_LIMIT * path->mtu) / HYSTART_CSS_GROWTH_DIVISOR;

		if (path->cwnd >= QUIC_CC_INFINITE_SSTHESH - acked)
			goto out;

		if (quic_cwnd_may_increase(path)) {
			path->cwnd += acked;
			path->mcwnd = QUIC_MAX(path->cwnd, path->mcwnd);
		}
		quic_cc_hystart_track_min_rtt(cc, h, path->loss.latest_rtt);
		if (quic_cc_hystart_may_reenter_ss(h)) {
			/* Exit to slow start */
			c->state = QUIC_CC_ST_SS;
			goto out;
		}

		if (h->css_rnd_count >= HYSTART_CSS_ROUNDS) {
			/* Exit to congestion avoidance
			 *
			 * RFC 9438 4.10. Slow start
			 *
			 * When CUBIC uses HyStart++ [RFC9406], it may exit the first slow start
			 * without incurring any packet loss and thus _W_max_ is undefined. In
			 * this special case, CUBIC sets _cwnd_prior = cwnd_ and switches to
			 * congestion avoidance. It then increases its congestion window size
			 * using Figure 1, where _t_ is the elapsed time since the beginning of
			 * the current congestion avoidance stage, _K_ is set to 0, and _W_max_
			 * is set to the congestion window size at the beginning of the current
			 * congestion avoidance stage.
			 */
			c->last_w_max = path->cwnd;
			c->t_epoch = 0;
			c->state = QUIC_CC_ST_CA;
		}

		break;
	}

	case QUIC_CC_EVT_LOSS:
		quic_enter_recovery(cc);
		break;
	case QUIC_CC_EVT_ECN_CE:
		/* TODO */
		break;
	}

 out:
	TRACE_PROTO("CC cubic", QUIC_EV_CONN_CC, cc->qc, NULL, cc);
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc);
}

/* Recovery period callback */
static void quic_cc_cubic_rp_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	struct cubic *c = quic_cc_priv(cc);

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc, ev);
	TRACE_PROTO("CC cubic", QUIC_EV_CONN_CC, cc->qc, ev, cc);

	switch (ev->type) {
	case QUIC_CC_EVT_ACK:
		/* RFC 9002 7.3.2. Recovery
		 * A recovery period ends and the sender enters congestion avoidance when a
		 * packet sent during the recovery period is acknowledged.
		 */
		if (tick_is_le(ev->ack.time_sent, c->recovery_start_time)) {
			TRACE_PROTO("CC cubic (still in recov. period)", QUIC_EV_CONN_CC, cc->qc);
			goto leave;
		}

		c->state = QUIC_CC_ST_CA;
		c->recovery_start_time = TICK_ETERNITY;
		break;
	case QUIC_CC_EVT_LOSS:
		break;
	case QUIC_CC_EVT_ECN_CE:
		/* TODO */
		break;
	}

 leave:
	TRACE_PROTO("CC cubic", QUIC_EV_CONN_CC, cc->qc, NULL, cc);
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc, NULL, cc);
}

static void (*quic_cc_cubic_state_cbs[])(struct quic_cc *cc,
                                      struct quic_cc_event *ev) = {
	[QUIC_CC_ST_SS] = quic_cc_cubic_ss_cb,
	[QUIC_CC_ST_CS] = quic_cc_cubic_cs_cb,
	[QUIC_CC_ST_CA] = quic_cc_cubic_ca_cb,
	[QUIC_CC_ST_RP] = quic_cc_cubic_rp_cb,
};

static void quic_cc_cubic_event(struct quic_cc *cc, struct quic_cc_event *ev)
{
	struct cubic *c = quic_cc_priv(cc);

	return quic_cc_cubic_state_cbs[c->state](cc, ev);
}

static void quic_cc_cubic_hystart_start_round(struct quic_cc *cc, uint64_t pn)
{
	struct cubic *c = quic_cc_priv(cc);
	struct quic_hystart *h = &c->hystart;

	if (c->state != QUIC_CC_ST_SS && c->state != QUIC_CC_ST_CS)
		return;

	quic_cc_hystart_start_round(h, pn);
}

static void quic_cc_cubic_state_trace(struct buffer *buf, const struct quic_cc *cc)
{
	struct quic_cc_path *path;
	struct cubic *c = quic_cc_priv(cc);

	path = container_of(cc, struct quic_cc_path, cc);
	chunk_appendf(buf, " state=%s cwnd=%llu mcwnd=%llu ssthresh=%d rpst=%dms",
	              quic_cc_state_str(c->state),
	              (unsigned long long)path->cwnd,
	              (unsigned long long)path->mcwnd,
	              (int)c->ssthresh,
	              !tick_isset(c->recovery_start_time) ? -1 :
	              TICKS_TO_MS(tick_remain(c->recovery_start_time, now_ms)));
}

static void quic_cc_cubic_state_cli(struct buffer *buf, const struct quic_cc_path *path)
{
	struct cubic *c = quic_cc_priv(&path->cc);

	chunk_appendf(buf, "  cc: state=%s ssthresh=%u K=%u last_w_max=%u wdiff=%lld\n",
	              quic_cc_state_str(c->state), c->ssthresh, c->K, c->last_w_max,
	              (long long)(path->cwnd - c->last_w_max));
}

struct quic_cc_algo quic_cc_algo_cubic = {
	.type        = QUIC_CC_ALGO_TP_CUBIC,
	.flags       = QUIC_CC_ALGO_FL_OPT_PACING,
	.init        = quic_cc_cubic_init,
	.event       = quic_cc_cubic_event,
	.slow_start  = quic_cc_cubic_slow_start,
	.hystart_start_round = quic_cc_cubic_hystart_start_round,
	.pacing_inter = quic_cc_default_pacing_inter,
	.pacing_burst = NULL,
	.state_trace = quic_cc_cubic_state_trace,
	.state_cli   = quic_cc_cubic_state_cli,
};

void quic_cc_cubic_check(void)
{
	struct quic_cc *cc;
	BUG_ON_HOT(sizeof(struct cubic) > sizeof(cc->priv));
}

INITCALL0(STG_REGISTER, quic_cc_cubic_check);
