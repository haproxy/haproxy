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
struct flt_conf;
struct filter;

/* Descriptor for a "filter" keyword. The ->parse() function returns 0 in case
 * of success, or a combination of ERR_* flags if an error is encountered. The
 * function pointer can be NULL if not implemented.
 */
struct flt_kw {
	const char *kw;
	int (*parse)(char **args, int *cur_arg, struct proxy *px,
		     struct flt_conf *fconf, char **err, void *private);
	void *private;
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
 * Callbacks available on a filter:
 *
 *  - init                : Initializes the filter for a proxy. Returns a
 *                          negative value if an error occurs.
 *  - deinit              : Cleans up what the init function has done.
 *  - check               : Check the filter config for a proxy. Returns the
 *                          number of errors encountered.
 * - init_per_thread      : Initializes the filter for a proxy for a specific
 *                          thread. Returns a negative value if an error
 *                          occurs.
 * - deinit_per_thread    : Cleans up what the init_per_thread funcion has
 *                          done.
 *
 *
 *  - attach              : Called after a filter instance creation, when it is
 *                          attached to a stream. This happens when the stream
 *                          is started for filters defined on the stream's
 *                          frontend and when the backend is set for filters
 *                          declared on the stream's backend.
 *                          Returns a negative value if an error occurs, 0 if
 *                          the filter must be ignored for the stream, any other
 *                          value otherwise.
 *  - stream_start        : Called when a stream is started. This callback will
 *                          only be called for filters defined on the stream's
 *                          frontend.
 *                          Returns a negative value if an error occurs, any
 *                          other value otherwise.
 *  - stream_set_backend  : Called when a backend is set for a stream. This
 *                          callbacks will be called for all filters attached
 *                          to a stream (frontend and backend).
 *                          Returns a negative value if an error occurs, any
 *                          other value otherwise.
 *  - stream_stop         : Called when a stream is stopped. This callback will
 *                          only be called for filters defined on the stream's
 *                          frontend.
 *  - detach              : Called when a filter instance is detached from a
 *                          stream, before its destruction. This happens when
 *                          the stream is stopped for filters defined on the
 *                          stream's frontend and when the analyze ends for
 *                          filters defined on the stream's backend.
 *  - check_timeouts      : Called when a a stream is woken up because of an
 *                          expired timer.
 *
 *
 *  - channel_start_analyze: Called when a filter starts to analyze a channel.
 *                          Returns a negative value if an error occurs, 0 if
 *                          it needs to wait, any other value otherwise.
 *  - channel_pre_analyze : Called before each analyzer attached to a channel,
 *                          expects analyzers responsible for data sending.
 *                          Returns a negative value if an error occurs, 0 if
 *                          it needs to wait, any other value otherwise.
 *  - channel_post_analyze: Called after each analyzer attached to a channel,
 *                          expects analyzers responsible for data sending.
 *                          Returns a negative value if an error occurs,
 *                          any other value otherwise.
 *  - channel_end_analyze : Called when all other analyzers have finished their
 *                          processing.
 *                          Returns a negative value if an error occurs, 0 if
 *                          it needs to wait, any other value otherwise.
 *
 *
 *  - http_headers        : Called before the body parsing, after all HTTP
 *                          headers was parsed and analyzed.
 *                          Returns a negative value if an error occurs, 0 if
 *                          it needs to wait, any other value otherwise.
 *  - http_payload        : Called when some data can be consumed.
 *                          Returns a negative value if an error occurs, else
 *                          the number of forwarded bytes.
 *  - http_end            : Called when all the request/response has been
 *                          processed and all body data has been forwarded.
 *                          Returns a negative value if an error occurs, 0 if
 *                          it needs to wait for some reason, any other value
 *                          otherwise.
 *  - http_reset          : Called when the HTTP message is reseted. It happens
 *                          either when a 100-continue response is received.
 *                          that can be detected if s->txn->status is 10X, or
 *                          if we're attempting a L7 retry.
 *                          Returns nothing.
 *  - http_reply          : Called when, at any time, HA proxy decides to stop
 *                          the HTTP message's processing and to send a message
 *                          to the client (mainly, when an error or a redirect
 *                          occur).
 *                          Returns nothing.
 *
 *
 *  - tcp_payload         : Called when some data can be consumed.
 *                          Returns a negative value if an error occurs, else
 *                          the number of forwarded bytes.
 */
struct flt_ops {
	/*
	 * Callbacks to manage the filter lifecycle
	 */
	int  (*init)             (struct proxy *p, struct flt_conf *fconf);
	void (*deinit)           (struct proxy *p, struct flt_conf *fconf);
	int  (*check)            (struct proxy *p, struct flt_conf *fconf);
	int  (*init_per_thread)  (struct proxy *p, struct flt_conf *fconf);
	void (*deinit_per_thread)(struct proxy *p, struct flt_conf *fconf);
	/*
	 * Stream callbacks
	 */
	int  (*attach)            (struct stream *s, struct filter *f);
	int  (*stream_start)      (struct stream *s, struct filter *f);
	int  (*stream_set_backend)(struct stream *s, struct filter *f, struct proxy *be);
	void (*stream_stop)       (struct stream *s, struct filter *f);
	void (*detach)            (struct stream *s, struct filter *f);
	void (*check_timeouts)    (struct stream *s, struct filter *f);
	/*
	 * Channel callbacks
	 */
	int  (*channel_start_analyze)(struct stream *s, struct filter *f, struct channel *chn);
	int  (*channel_pre_analyze)  (struct stream *s, struct filter *f, struct channel *chn, unsigned int an_bit);
	int  (*channel_post_analyze) (struct stream *s, struct filter *f, struct channel *chn, unsigned int an_bit);
	int  (*channel_end_analyze)  (struct stream *s, struct filter *f, struct channel *chn);

	/*
	 * HTTP callbacks
	 */
	int  (*http_headers)       (struct stream *s, struct filter *f, struct http_msg *msg);
	int  (*http_payload)       (struct stream *s, struct filter *f, struct http_msg *msg,
				    unsigned int offset, unsigned int len);
	int  (*http_end)           (struct stream *s, struct filter *f, struct http_msg *msg);

	void (*http_reset)         (struct stream *s, struct filter *f, struct http_msg *msg);
	void (*http_reply)         (struct stream *s, struct filter *f, short status,
				    const struct buffer *msg);

	/*
	 * TCP callbacks
	 */
	int  (*tcp_payload)       (struct stream *s, struct filter *f, struct channel *chn,
				    unsigned int offset, unsigned int len);
};

/* Flags set on a filter config */
#define FLT_CFG_FL_HTX    0x00000001  /* The filter can filter HTX streams */

/* Flags set on a filter instance */
#define FLT_FL_IS_BACKEND_FILTER  0x0001 /* The filter is a backend filter */
#define FLT_FL_IS_REQ_DATA_FILTER 0x0002 /* The filter will parse data on the request channel */
#define FLT_FL_IS_RSP_DATA_FILTER 0x0004 /* The filter will parse data on the response channel */

/* Flags set on the stream, common to all filters attached to its stream */
#define STRM_FLT_FL_HAS_FILTERS          0x0001 /* The stream has at least one filter */

/*
 * Structure representing the filter configuration, attached to a proxy and
 * accessible from a filter when instantiated in a stream
 */
struct flt_conf {
	const char     *id;   /* The filter id */
	struct flt_ops *ops;  /* The filter callbacks */
	void           *conf; /* The filter configuration */
	struct list     list; /* Next filter for the same proxy */
	unsigned int    flags; /* FLT_CFG_FL_* */
};

/*
 * Structure reprensenting a filter instance attached to a stream
 *
 * 2D-Array fields are used to store info per channel. The first index stands
 * for the request channel, and the second one for the response channel.
 * Especially, <next> and <fwd> are offets representing amount of data that the
 * filter are, respectively, parsed and forwarded on a channel. Filters can
 * access these values using FLT_NXT and FLT_FWD macros.
 */
struct filter {
	struct flt_conf *config;           /* the filter's configuration */
	void           *ctx;               /* The filter context (opaque) */
	unsigned short  flags;             /* FLT_FL_* */
	unsigned long long offset[2];      /* Offset of input data already filtered for a specific channel
	                                    * 0: request channel, 1: response channel */
	unsigned int    pre_analyzers;     /* bit field indicating analyzers to pre-process */
	unsigned int    post_analyzers;    /* bit field indicating analyzers to post-process */
	struct list     list;              /* Next filter for the same proxy/stream */
};

/*
 * Structure reprensenting the "global" state of filters attached to a stream.
 */
struct strm_flt {
	struct list    filters;               /* List of filters attached to a stream */
	struct filter *current[2];            /* From which filter resume processing, for a specific channel.
	                                       * This is used for resumable callbacks only,
	                                       * If NULL, we start from the first filter.
	                                       * 0: request channel, 1: response channel */
	unsigned short flags;                 /* STRM_FL_* */
	unsigned char  nb_req_data_filters;   /* Number of data filters registered on the request channel */
	unsigned char  nb_rsp_data_filters;   /* Number of data filters registered on the response channel */
	unsigned long long offset[2];
};

#endif /* _TYPES_FILTERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
