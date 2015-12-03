/*
 * include/types/filteers.h
 * This file defines everything related to stream filters.
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
#ifndef _TYPES_FILTERS_H
#define _TYPES_FILTERS_H

#include <common/config.h>
#include <common/mini-clist.h>

struct http_msg;
struct proxy;
struct stream;
struct channel;
struct filter;

/* Descriptor for a "filter" keyword. The ->parse() function returns 0 in case
 * of success, or a combination of ERR_* flags if an error is encountered. The
 * function pointer can be NULL if not implemented. The function also has an
 * access to the current "server" config line. The ->skip value tells the parser
 * how many words have to be skipped after the keyword. If the function needs to
 * parse more keywords, it needs to update cur_arg.
 */
struct flt_kw {
	const char *kw;
	int (*parse)(char **args, int *cur_arg, struct proxy *px,
		     struct filter *filter, char **err);
};

/*
 * A keyword list. It is a NULL-terminated array of keywords. It embeds a struct
 * list in order to be linked to other lists, allowing it to easily be declared
 * where it is needed, and linked without duplicating data nor allocating
 * memory. It is also possible to indicate a scope for the keywords.
 */
struct flt_kw_list {
	const char *scope;
	struct list list;
	struct flt_kw kw[VAR_ARRAY];
};

/*
 * Filter flags set for a specific filter on channel
 *
 *  - FILTER_FL_FORWARD_DATA : When this flag is set, the rest of the data is
 *                             directly forwarded. For chunk-encoded HTTP
 *                             messages, this flag is reseted between each
 *                             chunks.
 */
#define FILTER_FL_FORWARD_DATA 0x00000001


/*
 * Callbacks available on a filter:
 *
 *  - init                : Initializes the filter for a proxy. Returns a
 *                          negative value if an error occurs.
 *  - deinit              : Cleans up what the init function has done.
 *  - check               : Check the filter config for a proxy. Returns the
 *                          number of errors encountered.
 *
 *
 *  - stream_start        : Called when a stream is started. This callback will
 *                          only be called for filters defined on a proxy with
 *                          the frontend capability.
 *                          Returns a negative value if an error occurs, any
 *                          other value otherwise.
 *  - stream_stop         : Called when a stream is stopped. This callback will
 *                          only be called for filters defined on a proxy with
 *                          the frontend capability.
 *
 *
 *  - channel_start_analyze: Called when a filter starts to analyze a channel.
 *                          Returns a negative value if an error occurs, 0 if
 *                          it needs to wait, any other value otherwise.
 *  - channel_analyze     : Called before each analyzer attached to a channel,
 *                          expects analyzers responsible for data sending.
 *                          Returns a negative value if an error occurs, 0 if
 *                          it needs to wait, any other value otherwise.
 *  - channel_end_analyze : Called when all other analyzers have finished their
 *                          processing.
 *                          Returns a negative value if an error occurs, 0 if
 *                          it needs to wait, any other value otherwise.
 *
 *
 *  - http_data           : Called when unparsed body data are available.
 *                          Returns a negative value if an error occurs, else
 *                          the number of consumed bytes.
 *  - http_chunk_trailers : Called when part of trailer headers of a
 *                          chunk-encoded request/response are ready to be
 *                          processed.
 *                          Returns a negative value if an error occurs, any
 *                          other value otherwise.
 *  - http_end            : Called when all the request/response has been
 *                          processed and all body data has been forwarded.
 *                          Returns a negative value if an error occurs, 0 if
 *                          it needs to wait for some reason, any other value
 *                          otherwise.
 *  - http_reset          : Called when the HTTP message is reseted. It happens
 *                          when a 100-continue response is received.
 *                          Returns nothing.
 *  - http_reply          : Called when, at any time, HA proxy decides to stop
 *                          the HTTP message's processing and to send a message
 *                          to the client (mainly, when an error or a redirect
 *                          occur).
 *                          Returns nothing.
 *  - http_forward_data   : Called when some data can be consumed.
 *                          Returns a negative value if an error occurs, else
 *                          the number of forwarded bytes.
 *  - tcp_data            : Called when unparsed data are available.
 *                          Returns a negative value if an error occurs, else
 *                          the number of consumed bytes.
 *  - tcp_forward_data    : Called when some data can be consumed.
 *                          Returns a negative value if an error occurs, else
 *                          or the number of forwarded bytes.
 */
struct flt_ops {
	/*
	 * Callbacks to manage the filter lifecycle
	 */
	int  (*init)  (struct proxy *p, struct filter *f);
	void (*deinit)(struct proxy *p, struct filter *f);
	int  (*check) (struct proxy *p, struct filter *f);

	/*
	 * Stream callbacks
	 */
	int  (*stream_start)     (struct stream *s, struct filter *f);
	void (*stream_stop)      (struct stream *s, struct filter *f);

	/*
	 * Channel callbacks
	 */
	int  (*channel_start_analyze)(struct stream *s, struct filter *f, struct channel *chn);
	int  (*channel_analyze)      (struct stream *s, struct filter *f, struct channel *chn, unsigned int an_bit);
	int  (*channel_end_analyze)  (struct stream *s, struct filter *f, struct channel *chn);

	/*
	 * HTTP callbacks
	 */
	int  (*http_data)          (struct stream *s, struct filter *f, struct http_msg *msg);
	int  (*http_chunk_trailers)(struct stream *s, struct filter *f, struct http_msg *msg);
	int  (*http_end)           (struct stream *s, struct filter *f, struct http_msg *msg);
	int  (*http_forward_data)  (struct stream *s, struct filter *f, struct http_msg *msg,
				    unsigned int len);

	void (*http_reset)         (struct stream *s, struct filter *f, struct http_msg *msg);
	void (*http_reply)         (struct stream *s, struct filter *f, short status,
				    const struct chunk *msg);

	/*
	 * TCP callbacks
	 */
	int  (*tcp_data)        (struct stream *s, struct filter *f, struct channel *chn);
	int  (*tcp_forward_data)(struct stream *s, struct filter *f, struct channel *chn,
				 unsigned int len);
};

/*
 * Structure representing the state of a filter. When attached to a proxy, only
 * <ops> and <conf> field (and optionnaly <id>) are set. All other fields are
 * used when the filter is attached to a stream.
 *
 * 2D-Array fields are used to store info per channel. The first index stands
 * for the request channel, and the second one for the response channel.
 * Especially, <next> and <fwd> are offets representing amount of data that the
 * filter are, respectively, parsed and forwarded on a channel. Filters can
 * access these values using FLT_NXT and FLT_FWD macros.
 */
struct filter {
	const char     *id;                /* The filter id */
	struct flt_ops *ops;               /* The filter callbacks */
	void           *conf;              /* The filter configuration */
	void           *ctx;               /* The filter context (opaque) */
	int             is_backend_filter; /* Flag to specify if the filter is a "backend" filter */
	unsigned int    flags[2];          /* 0: request, 1: response */
	unsigned int    next[2];           /* Offset, relative to buf->p, to the next byte to parse for a specific channel
	                                    * 0: request channel, 1: response channel */
	unsigned int    fwd[2];            /* Offset, relative to buf->p, to the next byte to forward for a specific channel
	                                    * 0: request channel, 1: response channel */
	struct list     list;              /* Next filter for the same proxy/stream */
};

struct strm_flt {
	struct list    filters;
	struct filter *current[2]; // 0: request, 1: response
	int            has_filters;
};

#endif /* _TYPES_FILTERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
