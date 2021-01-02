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

#include <ctype.h>

#include <haproxy/api.h>
#include <haproxy/channel-t.h>
#include <haproxy/errors.h>
#include <haproxy/filters.h>
#include <haproxy/global.h>
#include <haproxy/http_ana-t.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/proxy-t.h>
#include <haproxy/stream.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

const char *trace_flt_id = "trace filter";

struct flt_ops trace_ops;

#define TRACE_F_QUIET       0x00000001
#define TRACE_F_RAND_FWD    0x00000002
#define TRACE_F_HEXDUMP     0x00000004

struct trace_config {
	struct proxy *proxy;
	char         *name;
	unsigned int  flags;
};

#define FLT_TRACE(conf, fmt, ...)						\
	do {									\
		if (!(conf->flags & TRACE_F_QUIET))				\
			fprintf(stderr, "%d.%06d [%-20s] " fmt "\n",		\
				(int)now.tv_sec, (int)now.tv_usec, (conf)->name,\
				##__VA_ARGS__);					\
	} while (0)

#define FLT_STRM_TRACE(conf, strm, fmt, ...)								\
	do {												\
		if (!(conf->flags & TRACE_F_QUIET))							\
			fprintf(stderr, "%d.%06d [%-20s] [strm %p(%x) 0x%08x 0x%08x] " fmt "\n",	\
				(int)now.tv_sec, (int)now.tv_usec, (conf)->name,			\
				strm, (strm ? ((struct stream *)strm)->uniq_id : ~0U),			\
				(strm ? strm->req.analysers : 0), (strm ? strm->res.analysers : 0),	\
				##__VA_ARGS__);								\
	} while (0)


static const char *
channel_label(const struct channel *chn)
{
	return (chn->flags & CF_ISRESP) ? "RESPONSE" : "REQUEST";
}

static const char *
proxy_mode(const struct stream *s)
{
	struct proxy *px = (s->flags & SF_BE_ASSIGNED ? s->be : strm_fe(s));

	return ((px->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
}

static const char *
stream_pos(const struct stream *s)
{
	return (s->flags & SF_BE_ASSIGNED) ? "backend" : "frontend";
}

static const char *
filter_type(const struct filter *f)
{
	return (f->flags & FLT_FL_IS_BACKEND_FILTER) ? "backend" : "frontend";
}

static void
trace_hexdump(struct ist ist)
{
	int i, j, padding;

	padding = ((ist.len % 16) ? (16 - ist.len % 16) : 0);
	for (i = 0; i < ist.len + padding; i++) {
                if (!(i % 16))
                        fprintf(stderr, "\t0x%06x: ", i);
		else if (!(i % 8))
                        fprintf(stderr, "  ");

                if (i < ist.len)
                        fprintf(stderr, "%02x ", (unsigned char)*(ist.ptr+i));
                else
                        fprintf(stderr, "   ");

                /* print ASCII dump */
                if (i % 16 == 15) {
                        fprintf(stderr, "  |");
                        for(j = i - 15; j <= i && j < ist.len; j++)
				fprintf(stderr, "%c", (isprint((unsigned char)*(ist.ptr+j)) ? *(ist.ptr+j) : '.'));
                        fprintf(stderr, "|\n");
                }
        }
}

static void
trace_raw_hexdump(struct buffer *buf, unsigned int offset, unsigned int len)
{
	unsigned char p[len];
	int block1, block2;

	block1 = len;
	if (block1 > b_contig_data(buf, offset))
		block1 = b_contig_data(buf, offset);
	block2 = len - block1;

	memcpy(p, b_peek(buf, offset), block1);
	memcpy(p+block1, b_orig(buf), block2);
	trace_hexdump(ist2(p, len));
}

static void
trace_htx_hexdump(struct htx *htx, unsigned int offset, unsigned int len)
{
	struct htx_blk *blk;

	for (blk = htx_get_first_blk(htx); blk && len; blk = htx_get_next_blk(htx, blk)) {
		enum htx_blk_type type = htx_get_blk_type(blk);
		uint32_t sz = htx_get_blksz(blk);
		struct ist v;

		if (offset >= sz) {
			offset -= sz;
			continue;
		}

		v = htx_get_blk_value(htx, blk);
		v.ptr += offset;
		v.len -= offset;
		offset = 0;

		if (v.len > len)
			v.len = len;
		len -= v.len;
		if (type == HTX_BLK_DATA)
			trace_hexdump(v);
	}
}

static unsigned int
trace_get_htx_datalen(struct htx *htx, unsigned int offset, unsigned int len)
{
	struct htx_blk *blk;
	struct htx_ret htxret = htx_find_offset(htx, offset);
	uint32_t data = 0;

	blk = htxret.blk;
	if (blk && htxret.ret && htx_get_blk_type(blk) == HTX_BLK_DATA) {
		data += htxret.ret;
		blk = htx_get_next_blk(htx, blk);
	}
	while (blk) {
		if (htx_get_blk_type(blk) == HTX_BLK_UNUSED)
			goto next;
		else if (htx_get_blk_type(blk) != HTX_BLK_DATA)
			break;
		data += htx_get_blksz(blk);
	  next:
		blk = htx_get_next_blk(htx, blk);
	}
	return data;
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

	fconf->flags |= FLT_CFG_FL_HTX;
	fconf->conf = conf;

	FLT_TRACE(conf, "filter initialized [quiet=%s - fwd random=%s - hexdump=%s]",
		  ((conf->flags & TRACE_F_QUIET) ? "true" : "false"),
		  ((conf->flags & TRACE_F_RAND_FWD) ? "true" : "false"),
		  ((conf->flags & TRACE_F_HEXDUMP) ? "true" : "false"));
	return 0;
}

/* Free resources allocated by the trace filter. */
static void
trace_deinit(struct proxy *px, struct flt_conf *fconf)
{
	struct trace_config *conf = fconf->conf;

	if (conf) {
		FLT_TRACE(conf, "filter deinitialized");
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

/* Initialize the filter for each thread. Return -1 on error, else 0. */
static int
trace_init_per_thread(struct proxy *px, struct flt_conf *fconf)
{
	struct trace_config *conf = fconf->conf;

	FLT_TRACE(conf, "filter initialized for thread tid %u", tid);
	return 0;
}

/* Free resources allocate by the trace filter for each thread. */
static void
trace_deinit_per_thread(struct proxy *px, struct flt_conf *fconf)
{
	struct trace_config *conf = fconf->conf;

	if (conf)
		FLT_TRACE(conf, "filter deinitialized for thread tid %u", tid);
}

/**************************************************************************
 * Hooks to handle start/stop of streams
 *************************************************************************/
/* Called when a filter instance is created and attach to a stream */
static int
trace_attach(struct stream *s, struct filter *filter)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s: filter-type=%s",
		   __FUNCTION__, filter_type(filter));

	return 1;
}

/* Called when a filter instance is detach from a stream, just before its
 * destruction */
static void
trace_detach(struct stream *s, struct filter *filter)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s: filter-type=%s",
		   __FUNCTION__, filter_type(filter));
}

/* Called when a stream is created */
static int
trace_stream_start(struct stream *s, struct filter *filter)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s",
		   __FUNCTION__);
	return 0;
}


/* Called when a backend is set for a stream */
static int
trace_stream_set_backend(struct stream *s, struct filter *filter,
			 struct proxy *be)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s: backend=%s",
		   __FUNCTION__, be->id);
	return 0;
}

/* Called when a stream is destroyed */
static void
trace_stream_stop(struct stream *s, struct filter *filter)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s",
		   __FUNCTION__);
}

/* Called when the stream is woken up because of an expired timer */
static void
trace_check_timeouts(struct stream *s, struct filter *filter)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s",
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

	FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__,
		   channel_label(chn), proxy_mode(s), stream_pos(s));
	filter->pre_analyzers  |= (AN_REQ_ALL | AN_RES_ALL);
	filter->post_analyzers |= (AN_REQ_ALL | AN_RES_ALL);
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
		case AN_RES_HTTP_XFER_BODY:
			ana = "AN_RES_HTTP_XFER_BODY";
			break;
		default:
			ana = "unknown";
	}

	FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s) - "
		   "analyzer=%s - step=%s",
		   __FUNCTION__,
		   channel_label(chn), proxy_mode(s), stream_pos(s),
		   ana, ((chn->analysers & an_bit) ? "PRE" : "POST"));
	return 1;
}

/* Called when analyze ends for a given channel */
static int
trace_chn_end_analyze(struct stream *s, struct filter *filter,
		      struct channel *chn)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__,
		   channel_label(chn), proxy_mode(s), stream_pos(s));
	return 1;
}

/**************************************************************************
 * Hooks to filter HTTP messages
 *************************************************************************/
static int
trace_http_headers(struct stream *s, struct filter *filter,
		   struct http_msg *msg)
{
	struct trace_config *conf = FLT_CONF(filter);
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct htx_sl *sl = http_get_stline(htx);
	int32_t pos;

	FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)\t%.*s %.*s %.*s",
		   __FUNCTION__,
		   channel_label(msg->chn), proxy_mode(s), stream_pos(s),
		   HTX_SL_P1_LEN(sl), HTX_SL_P1_PTR(sl),
		   HTX_SL_P2_LEN(sl), HTX_SL_P2_PTR(sl),
		   HTX_SL_P3_LEN(sl), HTX_SL_P3_PTR(sl));

	for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
		struct htx_blk *blk = htx_get_blk(htx, pos);
		enum htx_blk_type type = htx_get_blk_type(blk);
		struct ist n, v;

		if (type == HTX_BLK_EOH)
			break;
		if (type != HTX_BLK_HDR)
			continue;

		n = htx_get_blk_name(htx, blk);
		v = htx_get_blk_value(htx, blk);
		FLT_STRM_TRACE(conf, s, "\t%.*s: %.*s",
			   (int)n.len, n.ptr, (int)v.len, v.ptr);
	}
	return 1;
}

static int
trace_http_payload(struct stream *s, struct filter *filter, struct http_msg *msg,
		   unsigned int offset, unsigned int len)
{
	struct trace_config *conf = FLT_CONF(filter);
	int ret = len;

	if (ret && (conf->flags & TRACE_F_RAND_FWD)) {
		unsigned int data = trace_get_htx_datalen(htxbuf(&msg->chn->buf), offset, len);

		if (data) {
			ret = ha_random() % (ret+1);
			if (!ret || ret >= data)
				ret = len;
		}
	}

	FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s) - "
		   "offset=%u - len=%u - forward=%d",
		   __FUNCTION__,
		   channel_label(msg->chn), proxy_mode(s), stream_pos(s),
		   offset, len, ret);

	 if (conf->flags & TRACE_F_HEXDUMP)
		 trace_htx_hexdump(htxbuf(&msg->chn->buf), offset, ret);

	 if (ret != len)
		 task_wakeup(s->task, TASK_WOKEN_MSG);
	return ret;
}

static int
trace_http_end(struct stream *s, struct filter *filter,
	       struct http_msg *msg)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__,
		   channel_label(msg->chn), proxy_mode(s), stream_pos(s));
	return 1;
}

static void
trace_http_reset(struct stream *s, struct filter *filter,
		 struct http_msg *msg)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__,
		   channel_label(msg->chn), proxy_mode(s), stream_pos(s));
}

static void
trace_http_reply(struct stream *s, struct filter *filter, short status,
		 const struct buffer *msg)
{
	struct trace_config *conf = FLT_CONF(filter);

	FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s)",
		   __FUNCTION__, "-", proxy_mode(s), stream_pos(s));
}

/**************************************************************************
 * Hooks to filter TCP data
 *************************************************************************/
static int
trace_tcp_payload(struct stream *s, struct filter *filter, struct channel *chn,
		  unsigned int offset, unsigned int len)
{
	struct trace_config *conf = FLT_CONF(filter);
	int ret = len;

	if (s->flags & SF_HTX) {
		if (ret && (conf->flags & TRACE_F_RAND_FWD)) {
			unsigned int data = trace_get_htx_datalen(htxbuf(&chn->buf), offset, len);

			if (data) {
				ret = ha_random() % (ret+1);
				if (!ret || ret >= data)
					ret = len;
			}
		}

		FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s) - "
			       "offset=%u - len=%u - forward=%d",
			       __FUNCTION__,
			       channel_label(chn), proxy_mode(s), stream_pos(s),
			       offset, len, ret);

		if (conf->flags & TRACE_F_HEXDUMP)
			trace_htx_hexdump(htxbuf(&chn->buf), offset, ret);
	}
	else {

		if (ret && (conf->flags & TRACE_F_RAND_FWD))
			ret = ha_random() % (ret+1);

		FLT_STRM_TRACE(conf, s, "%-25s: channel=%-10s - mode=%-5s (%s) - "
			       "offset=%u - len=%u - forward=%d",
			       __FUNCTION__,
			       channel_label(chn), proxy_mode(s), stream_pos(s),
			       offset, len, ret);

		if (conf->flags & TRACE_F_HEXDUMP)
			trace_raw_hexdump(&chn->buf, offset, ret);
	}

	 if (ret != len)
		 task_wakeup(s->task, TASK_WOKEN_MSG);
	return ret;
}
/********************************************************************
 * Functions that manage the filter initialization
 ********************************************************************/
struct flt_ops trace_ops = {
	/* Manage trace filter, called for each filter declaration */
	.init              = trace_init,
	.deinit            = trace_deinit,
	.check             = trace_check,
	.init_per_thread   = trace_init_per_thread,
	.deinit_per_thread = trace_deinit_per_thread,

	/* Handle start/stop of streams */
	.attach             = trace_attach,
	.detach             = trace_detach,
	.stream_start       = trace_stream_start,
	.stream_set_backend = trace_stream_set_backend,
	.stream_stop        = trace_stream_stop,
	.check_timeouts     = trace_check_timeouts,

	/* Handle channels activity */
	.channel_start_analyze = trace_chn_start_analyze,
	.channel_pre_analyze   = trace_chn_analyze,
	.channel_post_analyze  = trace_chn_analyze,
	.channel_end_analyze   = trace_chn_end_analyze,

	/* Filter HTTP requests and responses */
	.http_headers        = trace_http_headers,
	.http_payload        = trace_http_payload,
	.http_end            = trace_http_end,
	.http_reset          = trace_http_reset,
	.http_reply          = trace_http_reply,

	/* Filter TCP data */
	.tcp_payload        = trace_tcp_payload,
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
	conf->flags = 0;
	if (strcmp(args[pos], "trace") == 0) {
		pos++;

		while (*args[pos]) {
			if (strcmp(args[pos], "name") == 0) {
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
			else if (strcmp(args[pos], "quiet") == 0)
				conf->flags |= TRACE_F_QUIET;
			else if (strcmp(args[pos], "random-parsing") == 0)
				continue; // ignore
			else if (strcmp(args[pos], "random-forwarding") == 0)
				conf->flags |= TRACE_F_RAND_FWD;
			else if (strcmp(args[pos], "hexdump") == 0)
				conf->flags |= TRACE_F_HEXDUMP;
			else
				break;
			pos++;
		}
		*cur_arg = pos;
		fconf->id   = trace_flt_id;
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

INITCALL1(STG_REGISTER, flt_register_keywords, &flt_kws);
