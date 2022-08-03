#include <haproxy/trace.h>
#include <haproxy/quic_cc.h>

/* This source file is highly inspired from Linux kernel source file
 * implementation for TCP Cubic. In fact, we have no choice if we do
 * not want to use any floating point operations to be fast!
 * (See net/ipv4/tcp_cubic.c)
 */
#define TRACE_SOURCE    &trace_quic

#define CUBIC_BETA_SCALE       1024
#define CUBIC_BETA_SCALE_SHIFT   10
/* beta = 0.7 ; C = 0.4 */
#define CUBIC_BETA   717 /*    CUBIC_BETA / CUBIC_BETA_SCALE = 0.7 */
#define CUBIC_C      410 /*       CUBIC_C / CUBIC_BETA_SCALE = 0.4 */

#define CUBIC_BETA_SCALE_FACTOR_SHIFT (3 * CUBIC_BETA_SCALE_SHIFT)
#define TIME_SCALE_FACTOR_SHIFT  10

/* The maximum value which may be cubed an multiplied by CUBIC_BETA */
#define CUBIC_DIFF_TIME_LIMIT    355535ULL  /* ms */

/* K cube factor: (1 - beta) / c */
struct cubic {
	uint32_t ssthresh;
	uint32_t remaining_inc;
	uint32_t remaining_tcp_inc;
	uint32_t epoch_start;
	uint32_t origin_point;
	uint32_t K;
	uint32_t last_w_max;
	uint32_t tcp_wnd;
	uint32_t recovery_start_time;
};

static void quic_cc_cubic_reset(struct quic_cc *cc)
{
	struct cubic *c = quic_cc_priv(cc);

	cc->algo->state = QUIC_CC_ST_SS;

	c->ssthresh = QUIC_CC_INFINITE_SSTHESH;
	c->remaining_inc = 0;
	c->remaining_tcp_inc = 0;
	c->epoch_start = 0;
	c->origin_point = 0;
	c->K = 0;
	c->last_w_max = 0;
	c->tcp_wnd = 0;
	c->recovery_start_time = 0;
}

static int quic_cc_cubic_init(struct quic_cc *cc)
{
	quic_cc_cubic_reset(cc);
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

static inline void quic_cubic_update(struct quic_cc *cc, uint32_t acked)
{
	struct cubic *c = quic_cc_priv(cc);
	struct quic_path *path = container_of(cc, struct quic_path, cc);
	/* Current cwnd as number of packets */
	uint32_t t, target, inc, inc_diff;
	uint64_t delta, diff;

	if (!c->epoch_start) {
		c->epoch_start = now_ms;
		if (c->last_w_max <= path->cwnd) {
			c->K = 0;
			c->origin_point = path->cwnd;
		}
		else {
			/* K = cubic_root((1 - beta) * W_max / C) */
			c->K = cubic_root((c->last_w_max - path->cwnd) *
			                  (CUBIC_BETA_SCALE - CUBIC_BETA) / CUBIC_C / path->mtu) << TIME_SCALE_FACTOR_SHIFT;
			c->origin_point = c->last_w_max;
		}

		c->tcp_wnd = path->cwnd;
		c->remaining_inc = 0;
		c->remaining_tcp_inc = 0;
	}

	t = now_ms + path->loss.rtt_min - c->epoch_start;
	if (t < c->K) {
		diff = c->K - t;
	}
	else {
		diff = t - c->K;
	}

	if (diff > CUBIC_DIFF_TIME_LIMIT) {
		/* TODO : should not happen if we handle the case
		 * of very late acks receipt. This must be handled as a congestion
		 * control event: a very late ack should trigger a congestion
		 * control algorithm reset.
		 */
		quic_cc_cubic_reset(cc);
		return;
	}

	delta = path->mtu * ((CUBIC_C * diff * diff * diff) >> (10 + 3 * TIME_SCALE_FACTOR_SHIFT));
	if (t < c->K)
		target = c->origin_point - delta;
	else
		target = c->origin_point + delta;

	if (target > path->cwnd) {
		inc_diff = c->remaining_inc + path->mtu * (target - path->cwnd);
		c->remaining_inc = inc_diff % path->cwnd;
		inc = inc_diff / path->cwnd;
	}
	else {
		/* small increment */
		inc_diff = c->remaining_inc + path->mtu;
		c->remaining_inc = inc_diff % (100 * path->cwnd);
		inc = inc_diff / (100 * path->cwnd);
	}

	inc_diff = c->remaining_tcp_inc + path->mtu * acked;
	c->tcp_wnd += inc_diff / path->cwnd;
	c->remaining_tcp_inc = inc_diff % path->cwnd;
	/* TCP friendliness */
	if (c->tcp_wnd > path->cwnd) {
		uint32_t tcp_inc = path->mtu * (c->tcp_wnd - path->cwnd) / path->cwnd;
		if (tcp_inc > inc)
			inc = tcp_inc;
	}

	path->cwnd += inc;
}

static void quic_cc_cubic_slow_start(struct quic_cc *cc)
{
	quic_cc_cubic_reset(cc);
}

static void quic_enter_recovery(struct quic_cc *cc)
{
	struct quic_path *path = container_of(cc, struct quic_path, cc);
	struct cubic *c = quic_cc_priv(cc);
	/* Current cwnd as number of packets */

	c->epoch_start = 0;
	c->recovery_start_time = now_ms;
	/* Fast convergence */
	if (path->cwnd < c->last_w_max) {
		/* (1 + beta) * path->cwnd / 2 */
		c->last_w_max = (path->cwnd * (CUBIC_BETA_SCALE + CUBIC_BETA) / 2) >> CUBIC_BETA_SCALE_SHIFT;
	}
	else {
		c->last_w_max = path->cwnd;
	}
	path->cwnd = (CUBIC_BETA * path->cwnd) >> CUBIC_BETA_SCALE_SHIFT;
	c->ssthresh =  QUIC_MAX(path->cwnd, path->min_cwnd);
}

/* Congestion slow-start callback. */
static void quic_cc_cubic_ss_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	struct quic_path *path = container_of(cc, struct quic_path, cc);
	struct cubic *c = quic_cc_priv(cc);

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc, ev);
	switch (ev->type) {
	case QUIC_CC_EVT_ACK:
		/* Do not increase the congestion window in recovery period. */
		if (ev->ack.time_sent <= c->recovery_start_time)
			goto out;

		path->cwnd += ev->ack.acked;
		/* Exit to congestion avoidance if slow start threshold is reached. */
		if (path->cwnd >= c->ssthresh)
			cc->algo->state = QUIC_CC_ST_CA;
		break;

	case QUIC_CC_EVT_LOSS:
		/* Do not decrease the congestion window when already in recovery period. */
		if (ev->loss.time_sent <= c->recovery_start_time)
			goto out;

		quic_enter_recovery(cc);
		/* Exit to congestion avoidance. */
		cc->algo->state = QUIC_CC_ST_CA;
		break;

	case QUIC_CC_EVT_ECN_CE:
		/* TODO */
		break;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc, NULL, cc);
}

/* Congestion avoidance callback. */
static void quic_cc_cubic_ca_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	struct cubic *c = quic_cc_priv(cc);

	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc, ev);
	switch (ev->type) {
	case QUIC_CC_EVT_ACK:
		/* Do not increase the congestion window when already in recovery period. */
		if (ev->ack.time_sent <= c->recovery_start_time)
			goto out;

		quic_cubic_update(cc, ev->ack.acked);
		break;
	case QUIC_CC_EVT_LOSS:
		/* Do not decrease the congestion window when already in recovery period. */
		if (ev->loss.time_sent <= c->recovery_start_time)
			goto out;

		quic_enter_recovery(cc);
		break;
	case QUIC_CC_EVT_ECN_CE:
		/* TODO */
		break;
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc, NULL, cc);
}

static void (*quic_cc_cubic_state_cbs[])(struct quic_cc *cc,
                                      struct quic_cc_event *ev) = {
	[QUIC_CC_ST_SS] = quic_cc_cubic_ss_cb,
	[QUIC_CC_ST_CA] = quic_cc_cubic_ca_cb,
};

static void quic_cc_cubic_event(struct quic_cc *cc, struct quic_cc_event *ev)
{
	return quic_cc_cubic_state_cbs[cc->algo->state](cc, ev);
}

static void quic_cc_cubic_state_trace(struct buffer *buf, const struct quic_cc *cc)
{
}

struct quic_cc_algo quic_cc_algo_cubic = {
	.type        = QUIC_CC_ALGO_TP_CUBIC,
	.init        = quic_cc_cubic_init,
	.event       = quic_cc_cubic_event,
	.slow_start  = quic_cc_cubic_slow_start,
	.state_trace = quic_cc_cubic_state_trace,
};
