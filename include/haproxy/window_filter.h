#ifndef _HAPROXY_WINDOW_FILTER_H
#define _HAPROXY_WINDOW_FILTER_H

/* Kathleen Nichols' algorithm to track the maximum values of a data type during
 * a fixed time interval. This algorithm makes usage of three samples to track
 * the best, second best and third best values with 1st >= 2nd >= 3rd as
 * invariant.
 *
 * This code is used in Linux kernel in linux/win_minmax.c to track both
 * minimal and maximum values.
 *
 * Here the code has been adapted to track 64 bits values and only their
 * maximum.
 *
 * Note that these windowed filters are used by BBR to filter the maximum
 * estimated bandwidth with counters as time values. A length has been
 * added to simulate the fixed time interval with counter which are
 * monotonically increasing.
 */

/* Windowed filter sample */
struct wf_smp {
	uint64_t v;
	uint32_t t;
};

/* Windowed filter */
struct wf {
	size_t len;
	struct wf_smp smp[3];
};

/* Reset all the <wf> windowed filter samples with <v> and <t> as value and
 * time value respectively.
 */
static inline uint64_t wf_reset(struct wf *wf, uint64_t v, uint32_t t)
{
	struct wf_smp smp = { .v = v, .t = t };

	wf->smp[2] = wf->smp[1] = wf->smp[0] = smp;

	return wf->smp[0].v;
}

/* Initialize <wf> windowed filter to track maximum values, with <len> as
 * length and <v> and <t> as value and time value respectively.
 */
static inline void wf_init(struct wf *wf, size_t len, uint64_t v, uint32_t t)
{
	wf->len = len;
	wf_reset(wf, v, t);
}

/* Similar to minmax_running_max() Linux kernel function to update the best
 * estimation of <wf> windowed filted with <v> and <t> as value and time value
 * respectively
 */
static inline uint64_t wf_max_update(struct wf *wf, uint64_t v, uint32_t t)
{
	uint64_t delta_t;
	struct wf_smp smp = { .v = v, .t = t };

	/* Reset all estimates if they have not yet been initialized, if new
	   sample is a new best, or if the newest recorded estimate is too
	   old. */
	if (unlikely(v > wf->smp[0].v) || unlikely(t - wf->smp[2].t > wf->len))
		return wf_reset(wf, v, t);

	if (unlikely(v > wf->smp[1].v))
		wf->smp[2] = wf->smp[1] = smp;
	else if (unlikely(v > wf->smp[2].v))
		wf->smp[2] = smp;

	delta_t = t - wf->smp[0].t;
	/* From here, similar to minmax_subwin_update() from Linux kernel. */
	if (unlikely(delta_t > wf->len)) {
		wf->smp[0] = wf->smp[1];
		wf->smp[1] = wf->smp[2];
		wf->smp[2] = smp;

		if (unlikely(t - wf->smp[0].t > wf->len)) {
			wf->smp[0] = wf->smp[1];
			wf->smp[1] = wf->smp[2];
		}
	} else if (unlikely(wf->smp[1].t == wf->smp[0].t) && delta_t > wf->len / 4) {
		wf->smp[2] = smp;
		wf->smp[1] = wf->smp[2];
	} else if (unlikely(wf->smp[2].t == wf->smp[1].t) && delta_t > wf->len / 2) {
		wf->smp[2] = smp;
	}

	return wf->smp[0].v;
}

/* Return <wf> windowed filter best maximum estimation. */
static inline uint64_t wf_get_max(struct wf *wf)
{
	return wf->smp[0].v;
}

#endif /* _HAPROXY_WINDOW_FILTER_H */
