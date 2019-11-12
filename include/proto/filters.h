/*
 * include/proto/filters.h
 * This file defines function prototypes for stream filters management.
 *
 * Copyright (C) 2015 Qualys Inc., Christopher Faulet <cfaulet@qualys.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef _PROTO_FILTERS_H
#define _PROTO_FILTERS_H

#include <types/channel.h>
#include <types/filters.h>
#include <types/http_ana.h>
#include <types/proxy.h>
#include <types/stream.h>

#include <proto/channel.h>

extern const char *trace_flt_id;
extern const char *http_comp_flt_id;
extern const char *cache_store_flt_id;
extern const char *spoe_filter_id;
extern const char *fcgi_flt_id;

#define FLT_ID(flt)   (flt)->config->id
#define FLT_CONF(flt) (flt)->config->conf
#define FLT_OPS(flt)  (flt)->config->ops

/* Useful macros to access per-channel values. It can be safely used inside
 * filters. */
#define CHN_IDX(chn)     (((chn)->flags & CF_ISRESP) == CF_ISRESP)
#define FLT_STRM_OFF(s, chn) (strm_flt(s)->offset[CHN_IDX(chn)])
#define FLT_OFF(flt, chn) ((flt)->offset[CHN_IDX(chn)])

#define HAS_FILTERS(strm)           ((strm)->strm_flt.flags & STRM_FLT_FL_HAS_FILTERS)

#define HAS_REQ_DATA_FILTERS(strm)  ((strm)->strm_flt.nb_req_data_filters != 0)
#define HAS_RSP_DATA_FILTERS(strm)  ((strm)->strm_flt.nb_rsp_data_filters != 0)
#define HAS_DATA_FILTERS(strm, chn) (((chn)->flags & CF_ISRESP) ? HAS_RSP_DATA_FILTERS(strm) : HAS_REQ_DATA_FILTERS(strm))

#define IS_REQ_DATA_FILTER(flt)  ((flt)->flags & FLT_FL_IS_REQ_DATA_FILTER)
#define IS_RSP_DATA_FILTER(flt)  ((flt)->flags & FLT_FL_IS_RSP_DATA_FILTER)
#define IS_DATA_FILTER(flt, chn) (((chn)->flags & CF_ISRESP) ? IS_RSP_DATA_FILTER(flt) : IS_REQ_DATA_FILTER(flt))

#define FLT_STRM_CB(strm, call)						\
	do {								\
		if (HAS_FILTERS(strm)) { call; }			\
	} while (0)

#define FLT_STRM_DATA_CB_IMPL_1(strm, chn, call, default_ret)	        \
	(HAS_DATA_FILTERS(strm, chn) ? call : default_ret)
#define FLT_STRM_DATA_CB_IMPL_2(strm, chn, call, default_ret, on_error)	\
	({								\
		int _ret;						\
		if (HAS_DATA_FILTERS(strm, chn)) {			\
			_ret = call;					\
			if (_ret < 0) { on_error; }			\
		}							\
		else							\
			_ret = default_ret;				\
		_ret;							\
	})
#define FLT_STRM_DATA_CB_IMPL_3(strm, chn, call, default_ret, on_error, on_wait) \
	({								\
		int _ret;						\
		if (HAS_DATA_FILTERS(strm, chn)) {			\
			_ret = call;					\
			if (_ret < 0) { on_error; }			\
			if (!_ret)    { on_wait;  }			\
		}							\
		else							\
			_ret = default_ret;				\
		_ret;							\
	})

#define FLT_STRM_DATA_CB_IMPL_X(strm, chn, call, A, B, C, DATA_CB_IMPL, ...) \
	DATA_CB_IMPL

#define FLT_STRM_DATA_CB(strm, chn, call, ...)				\
	FLT_STRM_DATA_CB_IMPL_X(strm, chn, call, ##__VA_ARGS__,		\
				FLT_STRM_DATA_CB_IMPL_3(strm, chn, call, ##__VA_ARGS__), \
				FLT_STRM_DATA_CB_IMPL_2(strm, chn, call, ##__VA_ARGS__), \
				FLT_STRM_DATA_CB_IMPL_1(strm, chn, call, ##__VA_ARGS__))

void flt_deinit(struct proxy *p);
int  flt_check(struct proxy *p);

int  flt_stream_start(struct stream *s);
void flt_stream_stop(struct stream *s);
int  flt_set_stream_backend(struct stream *s, struct proxy *be);
int  flt_stream_init(struct stream *s);
void flt_stream_release(struct stream *s, int only_backend);
void flt_stream_check_timeouts(struct stream *s);

int  flt_http_payload(struct stream *s, struct http_msg *msg, unsigned int len);
int  flt_http_end(struct stream *s, struct http_msg *msg);

void flt_http_reset(struct stream *s, struct http_msg *msg);
void flt_http_reply(struct stream *s, short status, const struct buffer *msg);

int  flt_start_analyze(struct stream *s, struct channel *chn, unsigned int an_bit);
int  flt_pre_analyze(struct stream *s, struct channel *chn, unsigned int an_bit);
int  flt_post_analyze(struct stream *s, struct channel *chn, unsigned int an_bit);
int  flt_analyze_http_headers(struct stream *s, struct channel *chn, unsigned int an_bit);
int  flt_end_analyze(struct stream *s, struct channel *chn, unsigned int an_bit);

int  flt_xfer_data(struct stream *s, struct channel *chn, unsigned int an_bit);

void           flt_register_keywords(struct flt_kw_list *kwl);
struct flt_kw *flt_find_kw(const char *kw);
void           flt_dump_kws(char **out);
void           list_filters(FILE *out);

/* Helper function that returns the "global" state of filters attached to a
 * stream. */
static inline struct strm_flt *
strm_flt(struct stream *s)
{
	return &s->strm_flt;
}

/* Registers a filter to a channel. If a filter was already registered, this
 * function do nothing. Once registered, the filter becomes a "data" filter for
 * this channel. */
static inline void
register_data_filter(struct stream *s, struct channel *chn, struct filter *filter)
{
	if (!IS_DATA_FILTER(filter, chn)) {
		if (chn->flags & CF_ISRESP) {
			filter->flags |= FLT_FL_IS_RSP_DATA_FILTER;
			strm_flt(s)->nb_rsp_data_filters++;
		}
		else  {
			filter->flags |= FLT_FL_IS_REQ_DATA_FILTER;
			strm_flt(s)->nb_req_data_filters++;
		}
	}
}

/* Unregisters a "data" filter from a channel. */
static inline void
unregister_data_filter(struct stream *s, struct channel *chn, struct filter *filter)
{
	if (IS_DATA_FILTER(filter, chn)) {
		if (chn->flags & CF_ISRESP) {
			filter->flags &= ~FLT_FL_IS_RSP_DATA_FILTER;
			strm_flt(s)->nb_rsp_data_filters--;

		}
		else  {
			filter->flags &= ~FLT_FL_IS_REQ_DATA_FILTER;
			strm_flt(s)->nb_req_data_filters--;
		}
	}
}

/* This function must be called when a filter alter payload data. It updates
 * offsets of all previous filters and the offset of the stream. Do not call
 * this function when a filter change the size of payload data leads to an
 * undefined behavior.
 *
 * This is the filter's responsiblitiy to update data itself..
 */
static inline void
flt_update_offsets(struct filter *filter, struct channel *chn, int len)
{
	struct stream *s = chn_strm(chn);
	struct filter *f;

	list_for_each_entry(f, &strm_flt(s)->filters, list) {
		if (f == filter)
			break;
		if (IS_DATA_FILTER(filter, chn))
			FLT_OFF(f, chn) += len;
	}
}


#endif /* _PROTO_FILTERS_H */
