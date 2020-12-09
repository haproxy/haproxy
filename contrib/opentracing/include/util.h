/***
 * Copyright 2020 HAProxy Technologies
 *
 * This file is part of the HAProxy OpenTracing filter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef _OPENTRACING_UTIL_H_
#define _OPENTRACING_UTIL_H_

#define HTTP_METH_STR_OPTIONS   "OPTIONS"
#define HTTP_METH_STR_GET       "GET"
#define HTTP_METH_STR_HEAD      "HEAD"
#define HTTP_METH_STR_POST      "POST"
#define HTTP_METH_STR_PUT       "PUT"
#define HTTP_METH_STR_DELETE    "DELETE"
#define HTTP_METH_STR_TRACE     "TRACE"
#define HTTP_METH_STR_CONNECT   "CONNECT"

/* Defined in include/haproxy/channel-t.h. */
#define FLT_OT_AN_DEFINES                     \
	FLT_OT_AN_DEF(AN_REQ_INSPECT_FE)      \
	FLT_OT_AN_DEF(AN_REQ_WAIT_HTTP)       \
	FLT_OT_AN_DEF(AN_REQ_HTTP_BODY)       \
	FLT_OT_AN_DEF(AN_REQ_HTTP_PROCESS_FE) \
	FLT_OT_AN_DEF(AN_REQ_SWITCHING_RULES) \
	FLT_OT_AN_DEF(AN_REQ_INSPECT_BE)      \
	FLT_OT_AN_DEF(AN_REQ_HTTP_PROCESS_BE) \
	FLT_OT_AN_DEF(AN_REQ_HTTP_TARPIT)     \
	FLT_OT_AN_DEF(AN_REQ_SRV_RULES)       \
	FLT_OT_AN_DEF(AN_REQ_HTTP_INNER)      \
	FLT_OT_AN_DEF(AN_REQ_PRST_RDP_COOKIE) \
	FLT_OT_AN_DEF(AN_REQ_STICKING_RULES)  \
	FLT_OT_AN_DEF(AN_REQ_HTTP_XFER_BODY)  \
	FLT_OT_AN_DEF(AN_REQ_WAIT_CLI)        \
	FLT_OT_AN_DEF(AN_RES_INSPECT)         \
	FLT_OT_AN_DEF(AN_RES_WAIT_HTTP)       \
	FLT_OT_AN_DEF(AN_RES_STORE_RULES)     \
	FLT_OT_AN_DEF(AN_RES_HTTP_PROCESS_BE) \
	FLT_OT_AN_DEF(AN_RES_HTTP_PROCESS_FE) \
	FLT_OT_AN_DEF(AN_RES_HTTP_XFER_BODY)  \
	FLT_OT_AN_DEF(AN_RES_WAIT_CLI)

#define FLT_OT_PROXIES_LIST_START()                                             \
	do {                                                                    \
		struct flt_conf *fconf;                                         \
		struct proxy    *px;                                            \
                                                                                \
		for (px = proxies_list; px != NULL; px = px->next)              \
			list_for_each_entry(fconf, &(px->filter_configs), list) \
				if (fconf->id == ot_flt_id) {                   \
					struct flt_ot_conf *conf = fconf->conf;
#define FLT_OT_PROXIES_LIST_END() \
				} \
	} while (0)

#ifdef DEBUG_OT
#  define FLT_OT_ARGS_DUMP()   do { if (flt_ot_debug.level & (1 << 2)) flt_ot_args_dump(args); } while (0)
#else
#  define FLT_OT_ARGS_DUMP()   while (0)
#endif


#ifndef DEBUG_OT
#  define flt_ot_filters_dump()   while (0)
#else
void        flt_ot_args_dump(char **args);
void        flt_ot_filters_dump(void);
const char *flt_ot_chn_label(const struct channel *chn);
const char *flt_ot_pr_mode(const struct stream *s);
const char *flt_ot_stream_pos(const struct stream *s);
const char *flt_ot_type(const struct filter *f);
const char *flt_ot_analyzer(uint an_bit);
const char *flt_ot_str_hex(const void *data, size_t size);
const char *flt_ot_str_ctrl(const void *data, size_t size);
const char *flt_ot_list_debug(const struct list *head);
#endif

ssize_t     flt_ot_chunk_add(struct buffer *chk, const void *src, size_t n, char **err);
int         flt_ot_args_count(char **args);
void        flt_ot_args_to_str(char **args, int idx, char **str);
double      flt_ot_strtod(const char *nptr, double limit_min, double limit_max, char **err);
int64_t     flt_ot_strtoll(const char *nptr, int64_t limit_min, int64_t limit_max, char **err);
int         flt_ot_sample_to_str(const struct sample_data *data, char *value, size_t size, char **err);
int         flt_ot_sample_to_value(const char *key, const struct sample_data *data, struct otc_value *value, char **err);
int         flt_ot_sample_add(struct stream *s, uint dir, struct flt_ot_conf_sample *sample, struct flt_ot_scope_data *data, int type, char **err);

#endif /* _OPENTRACING_UTIL_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
