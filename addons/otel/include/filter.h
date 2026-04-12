/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_FILTER_H_
#define _OTEL_FILTER_H_

#define FLT_OTEL_FMT_NAME           "'" FLT_OTEL_OPT_NAME "' : "
#define FLT_OTEL_FMT_TYPE           "'filter' : "
#define FLT_OTEL_ALERT(f, ...)      ha_alert(FLT_OTEL_FMT_TYPE FLT_OTEL_FMT_NAME f "\n", ##__VA_ARGS__)

#define FLT_OTEL_CONDITION_IF       "if"
#define FLT_OTEL_CONDITION_UNLESS   "unless"

/* Return codes for OTel filter operations. */
enum FLT_OTEL_RET_enum {
	FLT_OTEL_RET_ERROR  = -1,
	FLT_OTEL_RET_WAIT   = 0,
	FLT_OTEL_RET_IGNORE = 0,
	FLT_OTEL_RET_OK     = 1,
};

/* Dump or iterate a named configuration list for debugging. */
#define FLT_OTEL_DBG_LIST(d,m,p,t,v,f)                               \
	do {                                                         \
		if (LIST_ISEMPTY(&((d)->m##s))) {                    \
			OTELC_DBG(DEBUG, p "- no " #m "s " t);       \
		} else {                                             \
			const struct flt_otel_conf_##m *v;           \
			                                             \
			OTELC_DBG(DEBUG, p "- " t " " #m "s: %s",    \
			          flt_otel_list_dump(&((d)->m##s))); \
			list_for_each_entry(v, &((d)->m##s), list)   \
				do { f; } while (0);                 \
		}                                                    \
	} while (0)


extern const char     *otel_flt_id;
extern struct flt_ops  flt_otel_ops;


/* Check whether the OTel filter is disabled for a stream. */
bool flt_otel_is_disabled(const struct filter *f FLT_OTEL_DBG_ARGS(, int event));

#endif /* _OTEL_FILTER_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
