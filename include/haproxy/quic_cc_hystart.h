/* RFC 9406: HyStart++: Modified Slow Start for TCP. */

/* HyStart++ constants */
#define HYSTART_MIN_RTT_THRESH      4U /* ms */
#define HYSTART_MAX_RTT_THRESH     16U /* ms */
#define HYSTART_MIN_RTT_DIVISOR      8
#define HYSTART_N_RTT_SAMPLE         8
#define HYSTART_CSS_GROWTH_DIVISOR   4
#define HYSTART_CSS_ROUNDS           5
#define HYSTART_LIMIT                8 /* Must be infinite if paced */

#define QUIC_CLAMP(a, b, c) ({ \
    typeof(a) _a = (a);   \
    typeof(b) _b = (b);   \
    typeof(c) _c = (c);   \
    (void) (&_a == &_b);  \
    (void) (&_b == &_c);  \
    _b < _a ? _a : _b > _c ? _c : _b; })

struct quic_hystart {
	/* Current round minimum RTT. */
	uint32_t curr_rnd_min_rtt;
	/* Last round minimum RTT. */
	uint32_t last_rnd_min_rtt;
	/* Conservative Slow State baseline minimum RTT */
	uint32_t css_baseline_min_rtt;
	uint32_t rtt_sample_count;
	uint32_t css_rnd_count;
	uint64_t wnd_end;
};

/* Reset <h> Hystart++ algorithm state.
 * Never fail.
 */
static inline void quic_cc_hystart_reset(struct quic_hystart *h)
{
	h->curr_rnd_min_rtt = UINT32_MAX;
	h->last_rnd_min_rtt = UINT32_MAX;
	h->css_baseline_min_rtt = UINT32_MAX;
	h->rtt_sample_count = 0;
	h->css_rnd_count = 0;
	h->wnd_end = UINT64_MAX;
}

/* Track the minimum RTT. */
static inline void quic_cc_hystart_track_min_rtt(struct quic_cc *cc,
                                                 struct quic_hystart *h,
                                                 unsigned int latest_rtt)
{
	if (h->wnd_end == UINT64_MAX)
		return;

	h->curr_rnd_min_rtt = QUIC_MIN(h->curr_rnd_min_rtt, latest_rtt);
	h->rtt_sample_count++;
}

/* RFC 9406 4.2. Algorithm Details
 * At the start of each round during standard slow start [RFC5681] and CSS,
 * initialize the variables used to compute the last round's and current round's
 * minimum RTT.
 *
 * Never fail.
 */
static inline void quic_cc_hystart_start_round(struct quic_hystart *h, uint64_t pn)
{
	if (h->wnd_end != UINT64_MAX) {
		/* Round already started */
		return;
	}

	h->wnd_end = pn;
	h->last_rnd_min_rtt = h->curr_rnd_min_rtt;
	h->rtt_sample_count = 0;
}

/* RFC 9406 4.2. Algorithm Details
 * For rounds where at least N_RTT_SAMPLE RTT samples have been obtained and
 * currentRoundMinRTT and lastRoundMinRTT are valid, check to see if delay
 *increase triggers slow start exit.
 *
 * Depending on <h> HyStart++ algorithm state, returns 1 if the underlying
 * congestion control algorithm may enter the Conservative Slow Start (CSS)
 * state, 0 if not.
 */
static inline int quic_cc_hystart_may_enter_cs(struct quic_hystart *h)
{
	uint32_t rtt_thresh;

	if (h->rtt_sample_count < HYSTART_N_RTT_SAMPLE ||
	    h->curr_rnd_min_rtt == UINT32_MAX || h->last_rnd_min_rtt == UINT32_MAX)
		return 0;

	rtt_thresh = QUIC_CLAMP(HYSTART_MIN_RTT_THRESH,
	                        h->last_rnd_min_rtt / HYSTART_MIN_RTT_DIVISOR,
	                        HYSTART_MAX_RTT_THRESH);
	if (h->curr_rnd_min_rtt + rtt_thresh >= h->last_rnd_min_rtt) {
		h->css_baseline_min_rtt = h->curr_rnd_min_rtt;
		h->rtt_sample_count = 0;
		return 1;
	}

	return 0;
}


/* RFC 9406 4.2. Algorithm Details
 * For CSS rounds where at least N_RTT_SAMPLE RTT samples have been obtained,
 * check to see if the current round's minRTT drops below baseline (cssBaselineMinRtt)
 * indicating that slow start exit was spurious.
 *
 * Return 1 if slow start exit was spurious, 0 if not. If the slow start
 * exist was spurious, the caller must update the underlying congestion control
 * algorithm to make it re-enter slow start state.
 */
static inline int quic_cc_hystart_may_reenter_ss(struct quic_hystart *h)
{
	if (h->rtt_sample_count < HYSTART_N_RTT_SAMPLE)
		return 0;

	h->css_rnd_count++;
	h->rtt_sample_count = 0;

	if (h->curr_rnd_min_rtt >= h->css_baseline_min_rtt) {
		return 0;
	}

	h->css_baseline_min_rtt = UINT32_MAX;
	return 1;
}
