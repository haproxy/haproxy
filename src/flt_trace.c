/*
 * Stream filters related variables and functions.
 *
 * Copyright (C) 2015 Qualys Inc., Christopher Faulet <cfaulet@qualys.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/standard.h>
#include <common/time.h>
#include <common/tools.h>

#include <types/channel.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/proxy.h>
#include <types/stream.h>

#include <proto/filters.h>
#include <proto/log.h>
#include <proto/stream.h>

struct flt_ops trace_ops;

struct trace_config {
	struct proxy *proxy;
	char         *name;
	int           rand_parsing;
	int           rand_forwarding;
};

#define TRACE(conf, fmt, ...)						\
	fprintf(stderr, "%d.%06d [%-20s] " fmt "\n",			\
		(int)now.tv_sec, (int)now.tv_usec, (conf)->name,	\
		##__VA_ARGS__)

#define STRM_TRACE(conf, strm, fmt, ...)				\
	fprintf(stderr, "%d.%06d [%-20s] [strm %p(%x)] " fmt "\n",	\
		(int)now.tv_sec, (int)now.tv_usec, (conf)->name,	\
		strm, (strm ? ((struct stream *)strm)->uniq_id : ~0U),	\
		##__VA_ARGS__)


static const char *
channel_label(const struct channel *chn)
{
	return (chn->flags & CF_ISRESP) ? "RESPONSE" : "REQUEST";
}

static const char *
proxy_mode(const struct stream *s)
{
	struct proxy *px = (s->flags & SF_BE_ASSIGNED ? s->be : strm_fe(s));

	return (px->mode == PR_MODE_HTTP) ? "HTTP" : "TCP";
}

static const char *
stream_pos(const struct stream *s)
{
	return (s->flags & SF_BE_ASSIGNED) ? "backend" : "frontend";
}

/***************************************************************************
 * Hooks that manage the filter lifecycle (init/check/deinit)
 **************************************************************************/
/* Initialize the filter. Returns -1 on error, else 0. */
static int
trace_init(struct proxy *px, struct flt_conf *fconf)
{
	struct trace_config *conf = fconf->conf;

	if (conf->name)
		memprintf(&conf->name, "%s/%s", conf->name, px->id);
	else
		memprintf(&conf->name, "TRACE/%s", px->id);
	fconf->conf = conf;
	TRACE(conf, "filter initialized [read random=%s - fwd random=%s]",
	      (conf->rand_parsing ? "true" : "false"),
	      (conf->rand_forwarding ? "true" : "false"));
	return 0;
}

/* Free ressources allocated by the trace filter. */
static void
trace_deinit(struct proxy *px, struct flt_conf *fconf)
{
	struct trace_config *conf = fconf->conf;

	if (conf) {
		TRACE(conf, "filter deinitialized");
		free(conf->name);
		free(conf);
	}
	fconf->conf = NULL;
}

/* Check configuration of a trace filter for a specified proxy.
 * Return 1 on error, else 0. */
static int
trace_check(struct proxy *px, struct flt_conf *fconf)
{
	return 0;
}

/**************************************************************************
 * Hooks to handle start/stop of streams
 *************************************************************************/
/* Called when a stream is created */
static int
trace_stream_start(struct stream *s, struct filter *filter)
{
	struct trace_config *conf = FLT_CONF(filter);

	STRM_TRACE(conf, s, "%-25s",
		   __FUNCTION__);
	return 0;
}

/* Called when a stream is destroyed */
static void
trace_stream_stop(struct stream *s, struct filter *filter)
{
	struct trace_config *conf = FLT_CONF(filter);

	STRM_TRACE(conf, s, "%-25s",
		   __FUNCTION__);
}

/**************************************************************************
 * Hooks to handle channels activity
 *************************************************************************/
/* Called when analyze starts for a given channel */
static int
trace_chn_start_analyze(struct stream *s, struct filter *filter,
			struct channel *chn)
{
	struct trace_config *conf = FLT_CONF(filter);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__,
		   channel_label(chn), proxy_mode(s), stream_pos(s));
	register_data_filter(s, chn, filter);
	return 1;
}

/* Called before a processing happens on a given channel */
static int
trace_chn_analyze(struct stream *s, struct filter *filter,
		  struct channel *chn, unsigned an_bit)
{
	struct trace_config *conf = FLT_CONF(filter);
	char                *ana;

	switch (an_bit) {
		case AN_REQ_INSPECT_FE:
			ana = "AN_REQ_INSPECT_FE";
			break;
		case AN_REQ_WAIT_HTTP:
			ana = "AN_REQ_WAIT_HTTP";
			break;
		case AN_REQ_HTTP_BODY:
			ana = "AN_REQ_HTTP_BODY";
			break;
		case AN_REQ_HTTP_PROCESS_FE:
			ana = "AN_REQ_HTTP_PROCESS_FE";
			break;
		case AN_REQ_SWITCHING_RULES:
			ana = "AN_REQ_SWITCHING_RULES";
			break;
		case AN_REQ_INSPECT_BE:
			ana = "AN_REQ_INSPECT_BE";
			break;
		case AN_REQ_HTTP_PROCESS_BE:
			ana = "AN_REQ_HTTP_PROCESS_BE";
			break;
		case AN_REQ_SRV_RULES:
			ana = "AN_REQ_SRV_RULES";
			break;
		case AN_REQ_HTTP_INNER:
			ana = "AN_REQ_HTTP_INNER";
			break;
		case AN_REQ_HTTP_TARPIT:
			ana = "AN_REQ_HTTP_TARPIT";
			break;
		case AN_REQ_STICKING_RULES:
			ana = "AN_REQ_STICKING_RULES";
			break;
		case AN_REQ_PRST_RDP_COOKIE:
			ana = "AN_REQ_PRST_RDP_COOKIE";
			break;
		case AN_REQ_HTTP_XFER_BODY:
			ana = "AN_REQ_HTTP_XFER_BODY";
			break;
		case AN_REQ_ALL:
			ana = "AN_REQ_ALL";
			break;
		case AN_RES_INSPECT:
			ana = "AN_RES_INSPECT";
			break;
		case AN_RES_WAIT_HTTP:
			ana = "AN_RES_WAIT_HTTP";
			break;
		case AN_RES_HTTP_PROCESS_FE: // AN_RES_HTTP_PROCESS_BE
			ana = "AN_RES_HTTP_PROCESS_FE/BE";
			break;
		case AN_RES_STORE_RULES:
			ana = "AN_RES_STORE_RULES";
			break;
		case AN_FLT_HTTP_HDRS:
			ana = "AN_FLT_HTTP_HDRS";
			break;
		case AN_RES_HTTP_XFER_BODY:
			ana = "AN_RES_HTTP_XFER_BODY";
			break;
		case AN_FLT_XFER_DATA:
			ana = "AN_FLT_XFER_DATA";
			break;
		default:
			ana = "unknown";
	}

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s) - analyzer=%s",
		   __FUNCTION__,
		   channel_label(chn), proxy_mode(s), stream_pos(s),
		   ana);
	return 1;
}

/* Called when analyze ends for a given channel */
static int
trace_chn_end_analyze(struct stream *s, struct filter *filter,
		      struct channel *chn)
{
	struct trace_config *conf = FLT_CONF(filter);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__,
		   channel_label(chn), proxy_mode(s), stream_pos(s));
	return 1;
}

/**************************************************************************
 * Hooks to filter HTTP messages
 *************************************************************************/
static int
trace_http_data(struct stream *s, struct filter *filter,
		      struct http_msg *msg)
{
	struct trace_config *conf = FLT_CONF(filter);
	int avail = MIN(msg->chunk_len + msg->next, msg->chn->buf->i) - FLT_NXT(filter, msg->chn);
	int ret   = avail;

	if (ret && conf->rand_parsing)
		ret = random() % (ret+1);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s) - "
		   "chunk_len=%llu - next=%u - fwd=%u - avail=%d - consume=%d",
		   __FUNCTION__,
		   channel_label(msg->chn), proxy_mode(s), stream_pos(s),
		   msg->chunk_len, FLT_NXT(filter, msg->chn),
		   FLT_FWD(filter, msg->chn), avail, ret);
	if (ret != avail)
		task_wakeup(s->task, TASK_WOKEN_MSG);
	return ret;
}

static int
trace_http_chunk_trailers(struct stream *s, struct filter *filter,
			  struct http_msg *msg)
{
	struct trace_config *conf = FLT_CONF(filter);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__,
		   channel_label(msg->chn), proxy_mode(s), stream_pos(s));
	return 1;
}

static int
trace_http_end(struct stream *s, struct filter *filter,
	       struct http_msg *msg)
{
	struct trace_config *conf = FLT_CONF(filter);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__,
		   channel_label(msg->chn), proxy_mode(s), stream_pos(s));
	return 1;
}

static void
trace_http_reset(struct stream *s, struct filter *filter,
		 struct http_msg *msg)
{
	struct trace_config *conf = FLT_CONF(filter);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__,
		   channel_label(msg->chn), proxy_mode(s), stream_pos(s));
}

static void
trace_http_reply(struct stream *s, struct filter *filter, short status,
		 const struct chunk *msg)
{
	struct trace_config *conf = FLT_CONF(filter);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__, "-", proxy_mode(s), stream_pos(s));
}

static int
trace_http_forward_data(struct stream *s, struct filter *filter,
			struct http_msg *msg, unsigned int len)
{
	struct trace_config *conf = FLT_CONF(filter);
	int                  ret  = len;

	if (ret && conf->rand_forwarding)
		ret = random() % (ret+1);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s) - "
		   "len=%u - nxt=%u - fwd=%u - forward=%d",
		   __FUNCTION__,
		   channel_label(msg->chn), proxy_mode(s), stream_pos(s), len,
		   FLT_NXT(filter, msg->chn), FLT_FWD(filter, msg->chn), ret);

	if ((ret != len) ||
	    (FLT_NXT(filter, msg->chn) != FLT_FWD(filter, msg->chn) + ret))
		task_wakeup(s->task, TASK_WOKEN_MSG);
	return ret;
}

/**************************************************************************
 * Hooks to filter TCP data
 *************************************************************************/
static int
trace_tcp_data(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct trace_config *conf = FLT_CONF(filter);
	int                  avail = chn->buf->i - FLT_NXT(filter, chn);
	int                  ret  = avail;

	if (ret && conf->rand_parsing)
		ret = random() % (ret+1);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s) - next=%u - avail=%u - consume=%d",
		   __FUNCTION__,
		   channel_label(chn), proxy_mode(s), stream_pos(s),
		   FLT_NXT(filter, chn), avail, ret);

	if (ret != avail)
		task_wakeup(s->task, TASK_WOKEN_MSG);
	return ret;
}

static int
trace_tcp_forward_data(struct stream *s, struct filter *filter, struct channel *chn,
		 unsigned int len)
{
	struct trace_config *conf = FLT_CONF(filter);
	int                  ret  = len;

	if (ret && conf->rand_forwarding)
		ret = random() % (ret+1);

	STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s) - len=%u - fwd=%u - forward=%d",
		   __FUNCTION__,
		   channel_label(chn), proxy_mode(s), stream_pos(s), len,
		   FLT_FWD(filter, chn), ret);

	if (ret != len)
		task_wakeup(s->task, TASK_WOKEN_MSG);
	return ret;
}

/********************************************************************
 * Functions that manage the filter initialization
 ********************************************************************/
struct flt_ops trace_ops = {
	/* Manage trace filter, called for each filter declaration */
	.init   = trace_init,
	.deinit = trace_deinit,
	.check  = trace_check,

	/* Handle start/stop of streams */
	.stream_start = trace_stream_start,
	.stream_stop  = trace_stream_stop,

	/* Handle channels activity */
	.channel_start_analyze = trace_chn_start_analyze,
	.channel_analyze       = trace_chn_analyze,
	.channel_end_analyze   = trace_chn_end_analyze,

	/* Filter HTTP requests and responses */
	.http_data           = trace_http_data,
	.http_chunk_trailers = trace_http_chunk_trailers,
	.http_end            = trace_http_end,

	.http_reset          = trace_http_reset,
	.http_reply          = trace_http_reply,
	.http_forward_data   = trace_http_forward_data,

	/* Filter TCP data */
	.tcp_data         = trace_tcp_data,
	.tcp_forward_data = trace_tcp_forward_data,
};

/* Return -1 on error, else 0 */
static int
parse_trace_flt(char **args, int *cur_arg, struct proxy *px,
                struct flt_conf *fconf, char **err, void *private)
{
	struct trace_config *conf;
	int                  pos = *cur_arg;

	conf = calloc(1, sizeof(*conf));
	if (!conf) {
		memprintf(err, "%s: out of memory", args[*cur_arg]);
		return -1;
	}
	conf->proxy = px;

	if (!strcmp(args[pos], "trace")) {
		pos++;

		while (*args[pos]) {
			if (!strcmp(args[pos], "name")) {
				if (!*args[pos + 1]) {
					memprintf(err, "'%s' : '%s' option without value",
						  args[*cur_arg], args[pos]);
					goto error;
				}
				conf->name = strdup(args[pos + 1]);
				if (!conf->name) {
					memprintf(err, "%s: out of memory", args[*cur_arg]);
					goto error;
				}
				pos++;
			}
			else if (!strcmp(args[pos], "random-parsing"))
				conf->rand_parsing = 1;
			else if (!strcmp(args[pos], "random-forwarding"))
				conf->rand_forwarding = 1;
			else
				break;
			pos++;
		}
		*cur_arg = pos;
		fconf->ops  = &trace_ops;
	}

	fconf->conf = conf;
	return 0;

 error:
	if (conf->name)
		free(conf->name);
	free(conf);
	return -1;
}

/* Declare the filter parser for "trace" keyword */
static struct flt_kw_list flt_kws = { "TRACE", { }, {
		{ "trace", parse_trace_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

__attribute__((constructor))
static void
__flt_trace_init(void)
{
	flt_register_keywords(&flt_kws);
}
