/*
 * Fake congestion control algorithm which does nothing except initializing
 * the congestion control window to a fixed value.
 *
 */

#include <haproxy/api-t.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_trace.h>
#include <haproxy/trace.h>

static int quic_cc_nocc_init(struct quic_cc *cc)
{
	struct quic_cc_path *path;

	path = container_of(cc, struct quic_cc_path, cc);
	path->cwnd = path->max_cwnd;
	return 1;
}

static void quic_cc_nocc_slow_start(struct quic_cc *cc)
{
}

/* Slow start callback. */
static void quic_cc_nocc_ss_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	TRACE_PROTO("CC nocc", QUIC_EV_CONN_CC, cc->qc, ev, cc);
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc);
}

/* Congestion avoidance callback. */
static void quic_cc_nocc_ca_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	TRACE_PROTO("CC nocc", QUIC_EV_CONN_CC, cc->qc, ev, cc);
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc);
}

/*  Recovery period callback. */
static void quic_cc_nocc_rp_cb(struct quic_cc *cc, struct quic_cc_event *ev)
{
	TRACE_ENTER(QUIC_EV_CONN_CC, cc->qc);
	TRACE_PROTO("CC nocc", QUIC_EV_CONN_CC, cc->qc, ev, cc);
	TRACE_LEAVE(QUIC_EV_CONN_CC, cc->qc);
}

static void quic_cc_nocc_state_trace(struct buffer *buf, const struct quic_cc *cc)
{
	struct quic_cc_path *path;

	path = container_of(cc, struct quic_cc_path, cc);
	chunk_appendf(buf, " cwnd=%llu", (unsigned long long)path->cwnd);
}

static void (*quic_cc_nocc_state_cbs[])(struct quic_cc *cc,
                                      struct quic_cc_event *ev) = {
	[QUIC_CC_ST_SS] = quic_cc_nocc_ss_cb,
	[QUIC_CC_ST_CA] = quic_cc_nocc_ca_cb,
	[QUIC_CC_ST_RP] = quic_cc_nocc_rp_cb,
};

static void quic_cc_nocc_event(struct quic_cc *cc, struct quic_cc_event *ev)
{
	return quic_cc_nocc_state_cbs[QUIC_CC_ST_SS](cc, ev);
}

struct quic_cc_algo quic_cc_algo_nocc = {
	.type        = QUIC_CC_ALGO_TP_NOCC,
	.flags       = QUIC_CC_ALGO_FL_OPT_PACING,
	.init        = quic_cc_nocc_init,
	.event       = quic_cc_nocc_event,
	.pacing_inter = quic_cc_default_pacing_inter,
	.pacing_burst = NULL,
	.slow_start  = quic_cc_nocc_slow_start,
	.state_trace = quic_cc_nocc_state_trace,
};

