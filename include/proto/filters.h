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
#include <types/proto_http.h>
#include <types/proxy.h>
#include <types/stream.h>

#include <proto/channel.h>

/* Useful macros to access per-channel values. It can be safely used inside
 * filters. */
#define CHN_IDX(chn)     (((chn)->flags & CF_ISRESP) == CF_ISRESP)
#define FLT_NXT(flt, chn) ((flt)->next[CHN_IDX(chn)])
#define FLT_FWD(flt, chn) ((flt)->fwd[CHN_IDX(chn)])

extern struct pool_head *pool2_filter;

int  flt_init(struct proxy *p);
void flt_deinit(struct proxy *p);
int  flt_check(struct proxy *p);

int  flt_stream_start(struct stream *s);
void flt_stream_stop(struct stream *s);

int  flt_http_headers(struct stream *s, struct http_msg *msg);
int  flt_http_start_chunk(struct stream *s, struct http_msg *msg);
int  flt_http_data(struct stream *s, struct http_msg *msg);
int  flt_http_last_chunk(struct stream *s, struct http_msg *msg);
int  flt_http_end_chunk(struct stream *s, struct http_msg *msg);
int  flt_http_chunk_trailers(struct stream *s, struct http_msg *msg);
int  flt_http_end(struct stream *s, struct http_msg *msg);
void flt_http_reset(struct stream *s, struct http_msg *msg);

void flt_http_reply(struct stream *s, short status, const struct chunk *msg);
int  flt_http_forward_data(struct stream *s, struct http_msg *msg, unsigned int len);

int  flt_start_analyze(struct stream *s, struct channel *chn, unsigned int an_bit);
int  flt_analyze(struct stream *s, struct channel *chn, unsigned int an_bit);
int  flt_end_analyze(struct stream *s, struct channel *chn, unsigned int an_bit);

int  flt_xfer_data(struct stream *s, struct channel *chn, unsigned int an_bit);

void           flt_register_keywords(struct flt_kw_list *kwl);
struct flt_kw *flt_find_kw(const char *kw);
void           flt_dump_kws(char **out);

static inline void
flt_set_forward_data(struct filter *filter, struct channel *chn)
{
	filter->flags[CHN_IDX(chn)] |= FILTER_FL_FORWARD_DATA;
}

static inline void
flt_reset_forward_data(struct filter *filter, struct channel *chn)
{
	filter->flags[CHN_IDX(chn)] &= ~FILTER_FL_FORWARD_DATA;
}

static inline int
flt_want_forward_data(struct filter *filter, const struct channel *chn)
{
	return filter->flags[CHN_IDX(chn)] & FILTER_FL_FORWARD_DATA;
}


/* This function must be called when a filter alter incoming data. It updates
 * next offset value of all filter's predecessors. Do not call this function
 * when a filter change the size of incomding data leads to an undefined
 * behavior.
 *
 * This is the filter's responsiblitiy to update data itself. For now, it is
 * unclear to know how to handle data updates, so we do the minimum here. For
 * example, if you filter an HTTP message, we must update msg->next and
 * msg->chunk_len values.
 */
static inline void
flt_change_next_size(struct filter *filter, struct channel *chn, int len)
{
	struct stream *s = chn_strm(chn);
	struct filter *f;

	list_for_each_entry(f, &s->strm_flt.filters, list) {
		if (f == filter)
			break;
		FLT_NXT(f, chn) += len;
	}
}

/* This function must be called when a filter alter forwarded data. It updates
 * offset values (next and forward) of all filters. Do not call this function
 * when a filter change the size of forwarded data leads to an undefined
 * behavior.
 *
 * This is the filter's responsiblitiy to update data itself. For now, it is
 * unclear to know how to handle data updates, so we do the minimum here. For
 * example, if you filter an HTTP message, we must update msg->next and
 * msg->chunk_len values.
 */
static inline void
flt_change_forward_size(struct filter *filter, struct channel *chn, int len)
{
	struct stream *s = chn_strm(chn);
	struct filter *f;
	int before = 1;

	list_for_each_entry(f, &s->strm_flt.filters, list) {
		if (f == filter)
			before = 0;
		if (before)
			FLT_FWD(f, chn) += len;
		FLT_NXT(f, chn) += len;
	}
}


#endif /* _PROTO_FILTERS_H */
