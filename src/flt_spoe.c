/*
 * Stream processing offload engine management.
 *
 * Copyright 2016 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <ctype.h>
#include <errno.h>

#include <haproxy/acl.h>
#include <haproxy/applet.h>
#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/cfgparse.h>
#include <haproxy/check.h>
#include <haproxy/filters.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/http_rules.h>
#include <haproxy/log.h>
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/session.h>
#include <haproxy/signal.h>
#include <haproxy/sink.h>
#include <haproxy/spoe.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>


/* Type of list of messages */
#define SPOE_MSGS_BY_EVENT 0x01
#define SPOE_MSGS_BY_GROUP 0x02

/* Flags set on the SPOE context */
#define SPOE_CTX_FL_CLI_CONNECTED 0x00000001 /* Set after that on-client-session event was processed */
#define SPOE_CTX_FL_SRV_CONNECTED 0x00000002 /* Set after that on-server-session event was processed */
#define SPOE_CTX_FL_REQ_PROCESS   0x00000004 /* Set when SPOE is processing the request */
#define SPOE_CTX_FL_RSP_PROCESS   0x00000008 /* Set when SPOE is processing the response */
/* unused 0x00000010 */

#define SPOE_CTX_FL_PROCESS (SPOE_CTX_FL_REQ_PROCESS|SPOE_CTX_FL_RSP_PROCESS)

/* All possible states for a SPOE context */
enum spoe_ctx_state {
	SPOE_CTX_ST_NONE = 0,
	SPOE_CTX_ST_READY,
	SPOE_CTX_ST_ENCODING_MSGS,
	SPOE_CTX_ST_SENDING_MSGS,
	SPOE_CTX_ST_WAITING_ACK,
	SPOE_CTX_ST_DONE,
	SPOE_CTX_ST_ERROR,
};

/* All possible states for a SPOE applet */
enum spoe_appctx_state {
	SPOE_APPCTX_ST_WAITING_ACK = 0,
	SPOE_APPCTX_ST_EXIT,
	SPOE_APPCTX_ST_END,
};

/* All supported SPOE events */
enum spoe_event {
	SPOE_EV_NONE = 0,

	/* Request events */
	SPOE_EV_ON_CLIENT_SESS = 1,
	SPOE_EV_ON_TCP_REQ_FE,
	SPOE_EV_ON_TCP_REQ_BE,
	SPOE_EV_ON_HTTP_REQ_FE,
	SPOE_EV_ON_HTTP_REQ_BE,

	/* Response events */
	SPOE_EV_ON_SERVER_SESS,
	SPOE_EV_ON_TCP_RSP,
	SPOE_EV_ON_HTTP_RSP,

	SPOE_EV_EVENTS
};

/* Errors triggered by streams */
enum spoe_context_error {
	SPOE_CTX_ERR_NONE = 0,
	SPOE_CTX_ERR_TOUT,
	SPOE_CTX_ERR_RES,
	SPOE_CTX_ERR_TOO_BIG,
	SPOE_CTX_ERR_INTERRUPT,
	SPOE_CTX_ERR_UNKNOWN = 255,
	SPOE_CTX_ERRS,
};

/* Describe an argument that will be linked to a message. It is a sample fetch,
 * with an optional name. */
struct spoe_arg {
	char               *name;     /* Name of the argument, may be NULL */
	unsigned int        name_len; /* The name length, 0 if NULL */
	struct sample_expr *expr;     /* Sample expression */
	struct list         list;     /* Used to chain SPOE args */
};

/* Used during the config parsing only because, when a SPOE agent section is
 * parsed, messages/groups can be undefined. */
struct spoe_placeholder {
	char       *id;    /* SPOE placeholder id */
	struct list list;  /* Use to chain SPOE placeholders */
};

/* Used during the config parsing, when SPOE agent section is parsed, to
 * register some variable names. */
struct spoe_var_placeholder {
	char        *name;  /* The variable name */
	struct list  list;  /* Use to chain SPOE var placeholders */
};

/* Describe a message that will be sent in a NOTIFY frame. A message has a name,
 * an argument list (see above) and it is linked to a specific event. */
struct spoe_message {
	char               *id;     /* SPOE message id */
	unsigned int        id_len; /* The message id length */
	struct spoe_agent  *agent;  /* SPOE agent owning this SPOE message */
	struct spoe_group  *group;  /* SPOE group owning this SPOE message (can be NULL) */
        struct {
                char       *file;   /* file where the SPOE message appears */
                int         line;   /* line where the SPOE message appears */
        } conf;                     /* config information */
	unsigned int        nargs;  /* # of arguments */
	struct list         args;   /* Arguments added when the SPOE messages is sent */
	struct list         list;   /* Used to chain SPOE messages */
	struct list         by_evt; /* By event list */
	struct list         by_grp; /* By group list */

	struct list         acls;   /* ACL declared on this message */
	struct acl_cond    *cond;   /* acl condition to meet */
	enum spoe_event     event;  /* SPOE_EV_* */
};

/* Describe a group of messages that will be sent in a NOTIFY frame. A group has
 * a name and a list of messages. It can be used by HAProxy, outside events
 * processing, mainly in (tcp|http) rules. */
struct spoe_group {
	char              *id;      /* SPOE group id */
	struct spoe_agent *agent;   /* SPOE agent owning this SPOE group */
        struct {
                char      *file;    /* file where the SPOE group appears */
                int        line;    /* line where the SPOE group appears */
        } conf;                     /* config information */

	struct list phs;      /* List of placeholders used during conf parsing */
	struct list messages; /* List of SPOE messages that will be sent by this
			       * group */

	struct list list;     /* Used to chain SPOE groups */
};


/* SPOE context attached to a stream. It is the main structure that handles the
 * processing offload */
struct spoe_context {
	struct filter      *filter;       /* The SPOE filter */
	struct stream      *strm;         /* The stream that should be offloaded */

	struct list        *events;       /* List of messages that will be sent during the stream processing */
	struct list        *groups;       /* List of available SPOE group */

	struct buffer       buffer;       /* Buffer used to store a encoded messages */
	struct buffer_wait  buffer_wait;  /* position in the list of resources waiting for a buffer */

	enum spoe_ctx_state state;        /* SPOE_CTX_ST_* */
	unsigned int        flags;        /* SPOE_CTX_FL_* */
	unsigned int        status_code;  /* SPOE_CTX_ERR_* */

	unsigned int        stream_id;    /* stream_id and frame_id are used */
	unsigned int        frame_id;     /* to map NOTIFY and ACK frames */
	unsigned int        process_exp;  /* expiration date to process an event */

	struct spoe_appctx *spoe_appctx; /* SPOE appctx sending the current frame */

	struct {
		ullong         start_ts;    /* start date of the current event/group */
		long           t_process;   /* processing time of the last event/group */
		unsigned long  t_total;     /* cumulative processing time */
	} stats; /* Stats for this stream */
};

/* SPOE context inside a appctx */
struct spoe_appctx {
	struct appctx      *owner;          /* the owner */
	struct spoe_agent  *agent;          /* agent on which the applet is attached */
	unsigned int        flags;          /* SPOE_APPCTX_FL_* */
	unsigned int        status_code;    /* SPOE_FRM_ERR_* */
	struct spoe_context *spoe_ctx;      /* The SPOE context to handle */
};

/* SPOE filter configuration */
struct spoe_config {
	char              *id;          /* The SPOE engine name. If undefined in HAProxy config,
					 * it will be set with the SPOE agent name */
	struct proxy      *proxy;       /* Proxy owning the filter */
	struct spoe_agent *agent;       /* Agent used by this filter */
};


/* Helper to get SPOE ctx inside an appctx */
#define SPOE_APPCTX(appctx) ((struct spoe_appctx *)((appctx)->svcctx))

/* SPOE filter id. Used to identify SPOE filters */
const char *spoe_filter_id = "SPOE filter";

/* The name of the SPOE engine, used during the parsing */
char *curengine = NULL;

/* SPOE agent used during the parsing */
/* SPOE agent/group/message used during the parsing */
struct spoe_agent   *curagent = NULL;
struct spoe_group   *curgrp   = NULL;
struct spoe_message *curmsg   = NULL;

/* list of SPOE messages and placeholders used during the parsing */
struct list curmsgs;
struct list curgrps;
struct list curmphs;
struct list curgphs;
struct list curvars;

/* list of log servers used during the parsing */
struct list curloggers;

/* agent's proxy flags (PR_O_* and PR_O2_*) used during parsing */
int curpxopts;
int curpxopts2;

/* Pools used to allocate SPOE structs */
DECLARE_STATIC_POOL(pool_head_spoe_ctx,    "spoe_ctx",    sizeof(struct spoe_context));
DECLARE_STATIC_POOL(pool_head_spoe_appctx, "spoe_appctx", sizeof(struct spoe_appctx));

struct flt_ops spoe_ops;

static int  spoe_acquire_buffer(struct buffer *buf, struct buffer_wait *buffer_wait);
static void spoe_release_buffer(struct buffer *buf, struct buffer_wait *buffer_wait);
static struct appctx *spoe_create_appctx(struct spoe_context *ctx);

/********************************************************************
 * helper functions/globals
 ********************************************************************/
static void spoe_release_placeholder(struct spoe_placeholder *ph)
{
	if (!ph)
		return;
	free(ph->id);
	free(ph);
}

static void spoe_release_message(struct spoe_message *msg)
{
	struct spoe_arg *arg, *argback;
	struct acl      *acl, *aclback;

	if (!msg)
		return;
	free(msg->id);
	free(msg->conf.file);
	list_for_each_entry_safe(arg, argback, &msg->args, list) {
		release_sample_expr(arg->expr);
		free(arg->name);
		LIST_DELETE(&arg->list);
		free(arg);
	}
	list_for_each_entry_safe(acl, aclback, &msg->acls, list) {
		LIST_DELETE(&acl->list);
		prune_acl(acl);
		free(acl);
	}
	free_acl_cond(msg->cond);
	free(msg);
}

static void spoe_release_group(struct spoe_group *grp)
{
	if (!grp)
		return;
	free(grp->id);
	free(grp->conf.file);
	free(grp);
}

static void spoe_release_agent(struct spoe_agent *agent)
{
	struct spoe_message *msg, *msgback;
	struct spoe_group   *grp, *grpback;

	if (!agent)
		return;
	free(agent->id);
	free(agent->conf.file);
	free(agent->var_pfx);
	free(agent->var_on_error);
	free(agent->var_t_process);
	free(agent->var_t_total);
	list_for_each_entry_safe(msg, msgback, &agent->messages, list) {
		LIST_DELETE(&msg->list);
		spoe_release_message(msg);
	}
	list_for_each_entry_safe(grp, grpback, &agent->groups, list) {
		LIST_DELETE(&grp->list);
		spoe_release_group(grp);
	}
	free(agent->events);
	free(agent->engine_id);
	free(agent);
}

static const char *spoe_event_str[SPOE_EV_EVENTS] = {
	[SPOE_EV_ON_CLIENT_SESS] = "on-client-session",
	[SPOE_EV_ON_TCP_REQ_FE]  = "on-frontend-tcp-request",
	[SPOE_EV_ON_TCP_REQ_BE]  = "on-backend-tcp-request",
	[SPOE_EV_ON_HTTP_REQ_FE] = "on-frontend-http-request",
	[SPOE_EV_ON_HTTP_REQ_BE] = "on-backend-http-request",

	[SPOE_EV_ON_SERVER_SESS] = "on-server-session",
	[SPOE_EV_ON_TCP_RSP]     = "on-tcp-response",
	[SPOE_EV_ON_HTTP_RSP]    = "on-http-response",
};


/* Used to generates a unique id for an engine. On success, it returns a
 * allocated string. So it is the caller's responsibility to release it. If the
 * allocation failed, it returns NULL. */
static char *generate_pseudo_uuid()
{
	ha_generate_uuid_v4(&trash);
	return my_strndup(trash.area, trash.data);
}

/* set/add to <t> the elapsed time since <since> and now */
static inline void spoe_update_stat_time(ullong *since, long *t)
{
	if (*t == -1)
		*t = ns_to_ms(now_ns - *since);
	else
		*t += ns_to_ms(now_ns - *since);
	*since = 0;
}

/********************************************************************
 * Functions that manage the SPOE applet
 ********************************************************************/
struct spoe_agent *spoe_appctx_agent(struct appctx *appctx)
{
	struct spoe_appctx  *spoe_appctx;

	if (!appctx)
		return NULL;

	spoe_appctx = SPOE_APPCTX(appctx);
	if (!spoe_appctx)
		return NULL;

	return spoe_appctx->agent;
}

static int spoe_init_appctx(struct appctx *appctx)
{
	struct spoe_appctx *spoe_appctx = SPOE_APPCTX(appctx);
	struct spoe_agent *agent = spoe_appctx->agent;
	struct stream *s;

	if (appctx_finalize_startup(appctx, &agent->fe, &spoe_appctx->spoe_ctx->buffer) == -1)
		goto error;

	spoe_appctx->owner = appctx;

	s = appctx_strm(appctx);
	stream_set_backend(s, agent->b.be);

	/* applet is waiting for data */
	applet_need_more_data(appctx);

	s->do_log = NULL;
	s->scb->flags |= SC_FL_RCV_ONCE;
	s->parent = spoe_appctx->spoe_ctx->strm;

	appctx->st0 = SPOE_APPCTX_ST_WAITING_ACK;
	appctx_wakeup(appctx);
	return 0;

  error:
	return -1;
}

static void spoe_shut_appctx(struct appctx *appctx, enum se_shut_mode mode, struct se_abort_info *reason)
{
	struct spoe_appctx  *spoe_appctx = SPOE_APPCTX(appctx);

	if (!reason || spoe_appctx->status_code != SPOP_ERR_NONE)
		return;

	if (((reason->info & SE_ABRT_SRC_MASK) >> SE_ABRT_SRC_SHIFT) == SE_ABRT_SRC_MUX_SPOP)
		spoe_appctx->status_code = reason->code;
}

/* Callback function that releases a SPOE applet. This happens when the
 * connection with the agent is closed. */
static void spoe_release_appctx(struct appctx *appctx)
{
	struct spoe_appctx  *spoe_appctx = SPOE_APPCTX(appctx);

	if (spoe_appctx == NULL)
		return;

 	appctx->svcctx = NULL;
	appctx_strm(appctx)->parent = NULL;

	/* Shutdown the server connection, if needed */
	if (appctx->st0 != SPOE_APPCTX_ST_END) {
		appctx->st0 = SPOE_APPCTX_ST_END;
		if (spoe_appctx->status_code == SPOP_ERR_NONE)
			spoe_appctx->status_code = SPOP_ERR_IO;
	}

	if (spoe_appctx->spoe_ctx)  {
		/* Report an error to stream */
		spoe_appctx->spoe_ctx->spoe_appctx = NULL;
		spoe_appctx->spoe_ctx->state = SPOE_CTX_ST_ERROR;
		spoe_appctx->spoe_ctx->status_code = (spoe_appctx->status_code + 0x100);
		task_wakeup(spoe_appctx->spoe_ctx->strm->task, TASK_WOKEN_MSG);
	}

  end:
	/* Release allocated memory */
	pool_free(pool_head_spoe_appctx, spoe_appctx);
}

static int spoe_handle_receiving_frame_appctx(struct appctx *appctx)
{
	struct spoe_appctx *spoe_appctx = SPOE_APPCTX(appctx);
	struct spoe_context *spoe_ctx = spoe_appctx->spoe_ctx;
	int ret = 0;

	BUG_ON(b_data(&spoe_ctx->buffer));

	if (!b_data(&appctx->inbuf)) {
		applet_need_more_data(appctx);
		goto end;
	}

	if (b_data(&appctx->inbuf) > spoe_appctx->agent->max_frame_size) {
		spoe_ctx->state = SPOE_CTX_ST_ERROR;
		spoe_ctx->status_code = (spoe_appctx->status_code + 0x100);
		spoe_appctx->status_code = SPOP_ERR_TOO_BIG;
		appctx->st0 = SPOE_APPCTX_ST_EXIT;
		task_wakeup(spoe_ctx->strm->task, TASK_WOKEN_MSG);
		ret = -1;
		goto end;
	}

	b_xfer(&spoe_ctx->buffer, &appctx->inbuf, b_data(&appctx->inbuf));
	spoe_ctx->state = SPOE_CTX_ST_DONE;
	appctx->st0 = SPOE_APPCTX_ST_EXIT;
	task_wakeup(spoe_ctx->strm->task, TASK_WOKEN_MSG);
	ret = 1;

  end:
	return ret;
}

/* I/O Handler processing messages exchanged with the agent */
static void spoe_handle_appctx(struct appctx *appctx)
{
	if (SPOE_APPCTX(appctx) == NULL)
		goto out;

	if (applet_fl_test(appctx, APPCTX_FL_INBLK_ALLOC))
		goto out;

	if (!appctx_get_buf(appctx, &appctx->inbuf))
		goto out;

	if (unlikely(se_fl_test(appctx->sedesc, (SE_FL_EOS|SE_FL_ERROR)))) {
		b_reset(&appctx->inbuf);
		applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);
		goto out;
	}

	if (!SPOE_APPCTX(appctx)->spoe_ctx)
		appctx->st0 =  SPOE_APPCTX_ST_EXIT;

  switchstate:
	switch (appctx->st0) {
		/* case SPOE_APPCTX_ST_PROCESSING: */
		case SPOE_APPCTX_ST_WAITING_ACK:
			if (!spoe_handle_receiving_frame_appctx(appctx))
				break;
			goto switchstate;

		case SPOE_APPCTX_ST_EXIT:
			appctx->st0 = SPOE_APPCTX_ST_END;
			se_fl_set(appctx->sedesc, SE_FL_EOS);
			if (SPOE_APPCTX(appctx)->status_code != SPOP_ERR_NONE)
				se_fl_set(appctx->sedesc, SE_FL_ERROR);
			else
				se_fl_set(appctx->sedesc, SE_FL_EOI);
			__fallthrough;

		case SPOE_APPCTX_ST_END:
			b_reset(&appctx->inbuf);
			applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);
			break;
	}

  out:
	applet_have_no_more_data(appctx);
	return;
}

struct applet spoe_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<SPOE>", /* used for logging */
	.fct = spoe_handle_appctx,
	.init = spoe_init_appctx,
	.shut = spoe_shut_appctx,
	.rcv_buf = appctx_raw_rcv_buf,
	.snd_buf = appctx_raw_snd_buf,
	.release = spoe_release_appctx,
};

/* Create a SPOE applet. On success, the created applet is returned, else
 * NULL. */
static struct appctx *spoe_create_appctx(struct spoe_context *ctx)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent *agent = conf->agent;
	struct spoe_appctx *spoe_appctx;
	struct appctx *appctx;

	spoe_appctx = pool_zalloc(pool_head_spoe_appctx);
	if (spoe_appctx == NULL)
		goto out_error;

	spoe_appctx->agent           = agent;
	spoe_appctx->flags           = 0;
	spoe_appctx->status_code     = SPOP_ERR_NONE;
	spoe_appctx->spoe_ctx        = ctx;
	ctx->spoe_appctx             = spoe_appctx;

	if ((appctx = appctx_new_here(&spoe_applet, NULL)) == NULL)
		goto out_free_spoe_appctx;

	appctx->svcctx = spoe_appctx;
	if (appctx_init(appctx) == -1)
		goto out_free_appctx;

	appctx_wakeup(appctx);
	return appctx;

	/* Error unrolling */
 out_free_appctx:
	appctx_free_on_early_error(appctx);
 out_free_spoe_appctx:
	pool_free(pool_head_spoe_appctx, spoe_appctx);
 out_error:
	send_log(&agent->fe, LOG_EMERG, "SPOE: [%s] failed to create SPOE applet\n", agent->id);
 out:

	return NULL;
}

/***************************************************************************
 * Functions that encode SPOE messages
 **************************************************************************/
/* Encode a SPOE message. If the next message can be processed, it returns 0. If
 * the message is too big, it returns -1.*/
static int spoe_encode_message(struct stream *s, struct spoe_context *ctx,
			       struct spoe_message *msg, int dir,
			       char **buf, char *end)
{
	struct sample   *smp;
	struct spoe_arg *arg;
	int ret;

	if (!acl_match_cond(msg->cond, s->be, s->sess, s, dir|SMP_OPT_FINAL))
		goto next;

	/* Check if there is enough space for the message name and the
	 * number of arguments. It implies <msg->id_len> is encoded on 2
	 * bytes, at most (< 2288). */
	if (*buf + 2 + msg->id_len + 1 > end)
		goto too_big;

	/* Encode the message name */
	if (spoe_encode_buffer(msg->id, msg->id_len, buf, end) == -1)
		goto too_big;

	/* Set the number of arguments for this message */
	**buf = msg->nargs;
	(*buf)++;

	/* Loop on arguments */
	list_for_each_entry(arg, &msg->args, list) {
		/* Encode the argument name as a string. It can by NULL */
		if (spoe_encode_buffer(arg->name, arg->name_len, buf, end) == -1)
			goto too_big;

		/* Fetch the argument value */
		smp = sample_process(s->be, s->sess, s, dir|SMP_OPT_FINAL, arg->expr, NULL);
		ret = spoe_encode_data(smp, buf, end);
		if (ret == -1)
			goto too_big;
	}

  next:
	return 0;

  too_big:
	return -1;
}

/* Encode list of SPOE messages. On success it returns 1. If an error occurred, -1
 * is returned. If nothing has been encoded, it returns 0. */
static int spoe_encode_messages(struct stream *s, struct spoe_context *ctx,
				struct list *messages, int dir, int type)
{
	struct spoe_config  *conf = FLT_CONF(ctx->filter);
	struct spoe_agent   *agent = conf->agent;
	struct spoe_message *msg;
	char   *p, *end;

	p   = b_head(&ctx->buffer);
	end =  p + agent->max_frame_size - SPOP_FRAME_HDR_SIZE;

	/* Set Frame type */
	*p++ = SPOP_FRM_T_HAPROXY_NOTIFY;

	if (type == SPOE_MSGS_BY_EVENT) { /* Loop on messages by event */
		list_for_each_entry(msg, messages, by_evt) {
			if (spoe_encode_message(s, ctx, msg, dir, &p, end) == -1)
				goto too_big;
		}
	}
	else if (type == SPOE_MSGS_BY_GROUP) { /* Loop on messages by group */
		list_for_each_entry(msg, messages, by_grp) {
		encode_grp_message:
			if (spoe_encode_message(s, ctx, msg, dir, &p, end) == -1)
				goto too_big;
		}
	}
	else
		goto skip;


	/* nothing has been encoded */
	if (p == b_head(&ctx->buffer))
		goto skip;

	b_set_data(&ctx->buffer, p - b_head(&ctx->buffer));
	return 1;

  too_big:
	/* Return an error if nothing has been encoded because its too big */
	ctx->status_code = SPOE_CTX_ERR_TOO_BIG;
	return -1;

  skip:
	return 0;
}


/***************************************************************************
 * Functions that handle SPOE actions
 **************************************************************************/
/* Helper function to set a variable */
static void spoe_set_var(struct spoe_context *ctx, char *scope, char *name, int len,
			 struct sample *smp)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent  *agent = conf->agent;
	char                varname[64];

	memset(varname, 0, sizeof(varname));
	len = snprintf(varname, sizeof(varname), "%s.%s.%.*s",
		       scope, agent->var_pfx, len, name);
	if (agent->flags & SPOE_FL_FORCE_SET_VAR)
		vars_set_by_name(varname, len, smp);
	else
		vars_set_by_name_ifexist(varname, len, smp);
}

/* Helper function to unset a variable */
static void spoe_unset_var(struct spoe_context *ctx, char *scope, char *name, int len,
			   struct sample *smp)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent  *agent = conf->agent;
	char                varname[64];

	memset(varname, 0, sizeof(varname));
	len = snprintf(varname, sizeof(varname), "%s.%s.%.*s",
		       scope, agent->var_pfx, len, name);
	vars_unset_by_name_ifexist(varname, len, smp);
}


static inline int spoe_decode_action_set_var(struct stream *s, struct spoe_context *ctx,
					     char **buf, char *end, int dir)
{
	char         *str, *scope, *p = *buf;
	struct sample smp;
	uint64_t      sz;
	int           ret;

	if (p + 2 >= end)
		goto skip;

	/* SET-VAR requires 3 arguments */
	if (*p++ != 3)
		goto skip;

	switch (*p++) {
		case SPOP_SCOPE_PROC: scope = "proc"; break;
		case SPOP_SCOPE_SESS: scope = "sess"; break;
		case SPOP_SCOPE_TXN : scope = "txn";  break;
		case SPOP_SCOPE_REQ : scope = "req";  break;
		case SPOP_SCOPE_RES : scope = "res";  break;
		default: goto skip;
	}

	if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
		goto skip;
	memset(&smp, 0, sizeof(smp));
	smp_set_owner(&smp, s->be, s->sess, s, dir|SMP_OPT_FINAL);

	if (spoe_decode_data(&p, end, &smp) == -1)
		goto skip;

	if (smp.data.type == SMP_T_ANY)
		spoe_unset_var(ctx, scope, str, sz, &smp);
	else
		spoe_set_var(ctx, scope, str, sz, &smp);

	ret  = (p - *buf);
	*buf = p;
	return ret;
  skip:
	return 0;
}

static inline int spoe_decode_action_unset_var(struct stream *s, struct spoe_context *ctx,
					       char **buf, char *end, int dir)
{
	char         *str, *scope, *p = *buf;
	struct sample smp;
	uint64_t      sz;
	int           ret;

	if (p + 2 >= end)
		goto skip;

	/* UNSET-VAR requires 2 arguments */
	if (*p++ != 2)
		goto skip;

	switch (*p++) {
		case SPOP_SCOPE_PROC: scope = "proc"; break;
		case SPOP_SCOPE_SESS: scope = "sess"; break;
		case SPOP_SCOPE_TXN : scope = "txn";  break;
		case SPOP_SCOPE_REQ : scope = "req";  break;
		case SPOP_SCOPE_RES : scope = "res";  break;
		default: goto skip;
	}

	if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
		goto skip;
	memset(&smp, 0, sizeof(smp));
	smp_set_owner(&smp, s->be, s->sess, s, dir|SMP_OPT_FINAL);

	spoe_unset_var(ctx, scope, str, sz, &smp);

	ret  = (p - *buf);
	*buf = p;
	return ret;
  skip:
	return 0;
}

/* Process SPOE actions for a specific event. It returns 1 on success. If an
 * error occurred, 0 is returned. */
static int spoe_process_actions(struct stream *s, struct spoe_context *ctx, int dir)
{
	char *p, *end;
	int   ret;

	p   = b_head(&ctx->buffer);
	end = p + b_data(&ctx->buffer);

	while (p < end)  {
		enum spoe_action_type type;

		type = *p++;
		switch (type) {
			case SPOP_ACT_T_SET_VAR:
				ret = spoe_decode_action_set_var(s, ctx, &p, end, dir);
				if (!ret)
					goto skip;
				break;

			case SPOP_ACT_T_UNSET_VAR:
				ret = spoe_decode_action_unset_var(s, ctx, &p, end, dir);
				if (!ret)
					goto skip;
				break;

			default:
				goto skip;
		}
	}

	return 1;
  skip:
	return 0;
}

/***************************************************************************
 * Functions that process SPOE events
 **************************************************************************/
static inline enum spop_error spoe_ctx_err_to_spop_err(enum spoe_context_error err)
{
	switch (err) {
	case SPOE_CTX_ERR_NONE:
		return SPOP_ERR_NONE;
	case SPOE_CTX_ERR_TOUT:
		return SPOP_ERR_TOUT;
	case SPOE_CTX_ERR_RES:
		return SPOP_ERR_RES;
	case SPOE_CTX_ERR_TOO_BIG:
		return SPOP_ERR_TOO_BIG;
	case SPOE_CTX_ERR_INTERRUPT:
		return SPOP_ERR_IO;
	default:
		return SPOP_ERR_UNKNOWN;
	}
}
static void spoe_update_stats(struct stream *s, struct spoe_agent *agent,
			      struct spoe_context *ctx, int dir)
{
	if (ctx->stats.start_ts != 0) {
		spoe_update_stat_time(&ctx->stats.start_ts, &ctx->stats.t_process);
		ctx->stats.t_total    += ctx->stats.t_process;
	}

	if (agent->var_t_process) {
		struct sample smp;

		memset(&smp, 0, sizeof(smp));
		smp_set_owner(&smp, s->be, s->sess, s, dir|SMP_OPT_FINAL);
		smp.data.u.sint = ctx->stats.t_process;
		smp.data.type   = SMP_T_SINT;

		spoe_set_var(ctx, "txn", agent->var_t_process,
			     strlen(agent->var_t_process), &smp);
	}

	if (agent->var_t_total) {
		struct sample smp;

		memset(&smp, 0, sizeof(smp));
		smp_set_owner(&smp, s->be, s->sess, s, dir|SMP_OPT_FINAL);
		smp.data.u.sint = ctx->stats.t_total;
		smp.data.type   = SMP_T_SINT;

		spoe_set_var(ctx, "txn", agent->var_t_total,
			     strlen(agent->var_t_total), &smp);
	}
}

static void spoe_handle_processing_error(struct stream *s, struct spoe_agent *agent,
					 struct spoe_context *ctx, int dir)
{
	if (agent->var_on_error) {
		struct sample smp;

		memset(&smp, 0, sizeof(smp));
		smp_set_owner(&smp, s->be, s->sess, s, dir|SMP_OPT_FINAL);
		smp.data.u.sint = ctx->status_code;
		smp.data.type   = SMP_T_BOOL;

		spoe_set_var(ctx, "txn", agent->var_on_error,
			     strlen(agent->var_on_error), &smp);
	}

	ctx->state = ((agent->flags & SPOE_FL_CONT_ON_ERR)
		      ? SPOE_CTX_ST_READY
		      : SPOE_CTX_ST_NONE);
}

static inline int spoe_start_processing(struct spoe_agent *agent, struct spoe_context *ctx, int dir)
{
	/* If a process is already started for this SPOE context, retry
	 * later. */
	if (ctx->flags & SPOE_CTX_FL_PROCESS)
		return 0;

	ctx->stats.start_ts   = now_ns;
	ctx->stats.t_process  = -1;

	ctx->status_code = 0;

	/* Set the right flag to prevent request and response processing
	 * in same time. */
	ctx->flags |= ((dir == SMP_OPT_DIR_REQ)
		       ? SPOE_CTX_FL_REQ_PROCESS
		       : SPOE_CTX_FL_RSP_PROCESS);
	return 1;
}

static inline void spoe_stop_processing(struct spoe_agent *agent, struct spoe_context *ctx)
{
	struct spoe_appctx *sa = ctx->spoe_appctx;

	if (!(ctx->flags & SPOE_CTX_FL_PROCESS))
		return;
	_HA_ATOMIC_INC(&agent->counters.nb_processed);
	if (sa) {
		if (sa->status_code == SPOP_ERR_NONE)
			sa->status_code = spoe_ctx_err_to_spop_err(ctx->status_code);
		sa->spoe_ctx = NULL;
		appctx_strm(sa->owner)->parent = NULL;
		appctx_wakeup(sa->owner);
	}

	/* Reset the flag to allow next processing */
	ctx->flags &= ~SPOE_CTX_FL_PROCESS;

	/* Reset processing timer */
	ctx->process_exp = TICK_ETERNITY;
	ctx->strm->req.analyse_exp = TICK_ETERNITY;
	ctx->strm->res.analyse_exp = TICK_ETERNITY;

	spoe_release_buffer(&ctx->buffer, &ctx->buffer_wait);

	ctx->spoe_appctx = NULL;
}

/* Process a list of SPOE messages. First, this functions will process messages
 *  and send them to an agent in a NOTIFY frame. Then, it will wait a ACK frame
 *  to process corresponding actions. During all the processing, it returns 0
 *  and it returns 1 when the processing is finished. If an error occurred, -1
 *  is returned. */
static int spoe_process_messages(struct stream *s, struct spoe_context *ctx,
				 struct list *messages, int dir, int type)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent  *agent = conf->agent;
	int                 ret = 1;

	if (ctx->state == SPOE_CTX_ST_ERROR)
		goto end;

	if (tick_is_expired(ctx->process_exp, now_ms) && ctx->state != SPOE_CTX_ST_DONE) {
		ctx->status_code = SPOE_CTX_ERR_TOUT;
		goto end;
	}

	if (ctx->state == SPOE_CTX_ST_READY) {
		if (!tick_isset(ctx->process_exp)) {
			ctx->process_exp = tick_add_ifset(now_ms, agent->timeout.processing);
			if (dir == SMP_OPT_DIR_REQ)
				s->req.analyse_exp = ctx->process_exp;
			else
				s->res.analyse_exp = ctx->process_exp;
		}
		ret = spoe_start_processing(agent, ctx, dir);
		if (!ret)
			goto out;

		ctx->state = SPOE_CTX_ST_ENCODING_MSGS;
		/* fall through */
	}

	if (ctx->state == SPOE_CTX_ST_ENCODING_MSGS) {
		struct appctx *appctx;

		if (!spoe_acquire_buffer(&ctx->buffer, &ctx->buffer_wait))
			goto out;
		ret = spoe_encode_messages(s, ctx, messages, dir, type);
		if (ret < 0)
			goto end;
		if (!ret)
			goto skip;
		appctx = spoe_create_appctx(ctx);
		if (!appctx) {
			ctx->status_code = SPOE_CTX_ERR_RES;
			goto end;
		}
		ctx->state = SPOE_CTX_ST_SENDING_MSGS;
	}

	if (ctx->state == SPOE_CTX_ST_SENDING_MSGS) {
		if (ctx->spoe_appctx)
			appctx_wakeup(ctx->spoe_appctx->owner);
		ret = 0;
		goto out;
	}

	if (ctx->state == SPOE_CTX_ST_WAITING_ACK) {
		ret = 0;
		goto out;
	}

	if (ctx->state == SPOE_CTX_ST_DONE) {
		spoe_process_actions(s, ctx, dir);
		ret = 1;
		ctx->frame_id++;
		ctx->state = SPOE_CTX_ST_READY;
		goto end;
	}

  out:
	return ret;

  skip:
	ctx->stats.start_ts = 0;
	ctx->state = SPOE_CTX_ST_READY;
	spoe_stop_processing(agent, ctx);
	return 1;

  end:
	spoe_update_stats(s, agent, ctx, dir);
	spoe_stop_processing(agent, ctx);
	if (ctx->status_code) {
		_HA_ATOMIC_INC(&agent->counters.nb_errors);
		spoe_handle_processing_error(s, agent, ctx, dir);
		ret = 1;
	}
	return ret;
}

/* Process a SPOE group, ie the list of messages attached to the group <grp>.
 * See spoe_process_message for details. */
static int spoe_process_group(struct stream *s, struct spoe_context *ctx,
			      struct spoe_group *group, int dir)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent  *agent = conf->agent;
	int ret;

	if (LIST_ISEMPTY(&group->messages))
		return 1;

	ret = spoe_process_messages(s, ctx, &group->messages, dir, SPOE_MSGS_BY_GROUP);
	if (ret && ctx->stats.t_process != -1) {
		if (ctx->status_code || !(agent->fe.options2 & PR_O2_NOLOGNORM))
			send_log(&agent->fe, (!ctx->status_code ? LOG_NOTICE : LOG_WARNING),
				 "SPOE: [%s] <GROUP:%s> sid=%u st=%u %ld %llu/%llu\n",
				 agent->id, group->id, s->uniq_id, ctx->status_code, ctx->stats.t_process,
				 agent->counters.nb_errors, agent->counters.nb_processed);
	}
	return ret;
}

/* Process a SPOE event, ie the list of messages attached to the event <ev>.
 * See spoe_process_message for details. */
static int spoe_process_event(struct stream *s, struct spoe_context *ctx,
			      enum spoe_event ev)
{
	struct spoe_config *conf = FLT_CONF(ctx->filter);
	struct spoe_agent  *agent = conf->agent;
	int dir, ret;

	dir = ((ev < SPOE_EV_ON_SERVER_SESS) ? SMP_OPT_DIR_REQ : SMP_OPT_DIR_RES);

	if (LIST_ISEMPTY(&(ctx->events[ev])))
		return 1;

	ret = spoe_process_messages(s, ctx, &(ctx->events[ev]), dir, SPOE_MSGS_BY_EVENT);
	if (ret && ctx->stats.t_process != -1) {
		if (ctx->status_code || !(agent->fe.options2 & PR_O2_NOLOGNORM))
			send_log(&agent->fe, (!ctx->status_code ? LOG_NOTICE : LOG_WARNING),
				 "SPOE: [%s] <EVENT:%s> sid=%u st=%u %ld %llu/%llu\n",
				 agent->id, spoe_event_str[ev], s->uniq_id, ctx->status_code, ctx->stats.t_process,
				 agent->counters.nb_errors, agent->counters.nb_processed);
	}
	return ret;
}

/***************************************************************************
 * Functions that create/destroy SPOE contexts
 **************************************************************************/
static int spoe_acquire_buffer(struct buffer *buf, struct buffer_wait *buffer_wait)
{
	if (buf->size)
		return 1;

	b_dequeue(buffer_wait);

	if (b_alloc(buf, DB_CHANNEL))
		return 1;

	b_requeue(DB_CHANNEL, buffer_wait);
	return 0;
}

static void spoe_release_buffer(struct buffer *buf, struct buffer_wait *buffer_wait)
{
	b_dequeue(buffer_wait);

	/* Release the buffer if needed */
	if (buf->size) {
		b_free(buf);
		offer_buffers(buffer_wait->target, 1);
	}
}

static int spoe_wakeup_context(struct spoe_context *ctx)
{
	task_wakeup(ctx->strm->task, TASK_WOKEN_MSG);
	return 1;
}

static struct spoe_context *spoe_create_context(struct stream *s, struct filter *filter)
{
	struct spoe_config  *conf = FLT_CONF(filter);
	struct spoe_context *ctx;

	ctx = pool_zalloc(pool_head_spoe_ctx);
	if (ctx == NULL) {
		return NULL;
	}
	ctx->filter      = filter;
	ctx->state       = SPOE_CTX_ST_NONE;
	ctx->status_code = SPOE_CTX_ERR_NONE;
	ctx->flags       = 0;
	ctx->events      = conf->agent->events;
	ctx->groups      = &conf->agent->groups;
	ctx->buffer      = BUF_NULL;
	LIST_INIT(&ctx->buffer_wait.list);
	ctx->buffer_wait.target = ctx;
	ctx->buffer_wait.wakeup_cb = (int (*)(void *))spoe_wakeup_context;

	ctx->stream_id   = 0;
	ctx->frame_id    = 1;
	ctx->process_exp = TICK_ETERNITY;

	ctx->stats.start_ts   =  0;
	ctx->stats.t_process  = -1;
	ctx->stats.t_total    =  0;

	ctx->strm   = s;
	ctx->state  = SPOE_CTX_ST_READY;
	filter->ctx = ctx;

	return ctx;
}

static void spoe_destroy_context(struct filter *filter)
{
	struct spoe_config  *conf = FLT_CONF(filter);
	struct spoe_context *ctx  = filter->ctx;

	if (!ctx)
		return;

	spoe_stop_processing(conf->agent, ctx);
	pool_free(pool_head_spoe_ctx, ctx);
	filter->ctx = NULL;
}

static void spoe_reset_context(struct spoe_context *ctx)
{
	ctx->state  = SPOE_CTX_ST_READY;
	ctx->flags &= ~SPOE_CTX_FL_PROCESS;

	ctx->stats.start_ts   =  0;
	ctx->stats.t_process  = -1;
	ctx->stats.t_total    =  0;
}


/***************************************************************************
 * Hooks that manage the filter lifecycle (init/check/deinit)
 **************************************************************************/
/* Initialize the SPOE filter. Returns -1 on error, else 0. */
static int spoe_init(struct proxy *px, struct flt_conf *fconf)
{
	struct spoe_config *conf = fconf->conf;

	/* conf->agent->fe was already initialized during the config
	 * parsing. Finish initialization. */
	conf->agent->fe.fe_counters.last_change = ns_to_sec(now_ns);
	conf->agent->fe.cap = PR_CAP_FE;
	conf->agent->fe.mode = PR_MODE_SPOP;
	conf->agent->fe.maxconn = 0;
	conf->agent->fe.options2 |= PR_O2_INDEPSTR;
	conf->agent->fe.conn_retries = CONN_RETRIES;
	conf->agent->fe.accept = frontend_accept;
	conf->agent->fe.srv = NULL;
	conf->agent->fe.timeout.client = TICK_ETERNITY;
	conf->agent->fe.fe_req_ana = AN_REQ_SWITCHING_RULES;

	proxy_init_per_thr(&conf->agent->fe);

	conf->agent->engine_id = generate_pseudo_uuid();
	if (conf->agent->engine_id == NULL)
		return -1;

	fconf->flags |= FLT_CFG_FL_HTX;
	return 0;
}

/* Free resources allocated by the SPOE filter. */
static void spoe_deinit(struct proxy *px, struct flt_conf *fconf)
{
	struct spoe_config *conf = fconf->conf;

	if (conf) {
		struct spoe_agent *agent = conf->agent;

		spoe_release_agent(agent);
		free(conf->id);
		free(conf);
	}
	fconf->conf = NULL;
}

/* Check configuration of a SPOE filter for a specified proxy.
 * Return 1 on error, else 0. */
static int spoe_check(struct proxy *px, struct flt_conf *fconf)
{
	struct flt_conf    *f;
	struct spoe_config *conf = fconf->conf;
	struct proxy       *target;

	/* Check all SPOE filters for proxy <px> to be sure all SPOE agent names
	 * are uniq */
	list_for_each_entry(f, &px->filter_configs, list) {
		struct spoe_config *c = f->conf;

		/* This is not an SPOE filter */
		if (f->id != spoe_filter_id)
			continue;
		/* This is the current SPOE filter */
		if (f == fconf)
			continue;

		/* Check engine Id. It should be uniq */
		if (strcmp(conf->id, c->id) == 0) {
			ha_alert("Proxy %s : duplicated name for SPOE engine '%s'.\n",
				 px->id, conf->id);
			return 1;
		}
	}

	target = proxy_be_by_name(conf->agent->b.name);
	if (target == NULL) {
		ha_alert("Proxy %s : unknown backend '%s' used by SPOE agent '%s'"
			 " declared at %s:%d.\n",
			 px->id, conf->agent->b.name, conf->agent->id,
			 conf->agent->conf.file, conf->agent->conf.line);
		return 1;
	}
	if (target->mode == PR_MODE_TCP) {
		/* Convert legacy SPOP backend by added the right mode */
		target->mode = PR_MODE_SPOP;
	}
	if (target->mode != PR_MODE_SPOP) {
		ha_alert("Proxy %s : backend '%s' used by SPOE agent '%s' declared"
			 " at %s:%d must use SPOP mode.\n",
			 px->id, target->id, conf->agent->id,
			 conf->agent->conf.file, conf->agent->conf.line);
		return 1;
	}

	if (postresolve_logger_list(NULL, &conf->agent->fe.loggers, "SPOE agent", conf->agent->id) & ERR_CODE)
		return 1;

	ha_free(&conf->agent->b.name);
	conf->agent->b.be = target;
	return 0;
}

/**************************************************************************
 * Hooks attached to a stream
 *************************************************************************/
/* Called when a filter instance is created and attach to a stream. It creates
 * the context that will be used to process this stream. */
static int spoe_start(struct stream *s, struct filter *filter)
{
	struct spoe_config  *conf  = FLT_CONF(filter);
	struct spoe_agent   *agent = conf->agent;
	struct spoe_context *ctx;

	if ((ctx = spoe_create_context(s, filter)) == NULL) {
		send_log(&agent->fe, LOG_EMERG,
			 "SPOE: [%s] failed to create SPOE context\n",
			 agent->id);
		return 0;
	}

	if (!LIST_ISEMPTY(&ctx->events[SPOE_EV_ON_TCP_REQ_FE]))
		filter->pre_analyzers |= AN_REQ_INSPECT_FE;

	if (!LIST_ISEMPTY(&ctx->events[SPOE_EV_ON_TCP_REQ_BE]))
		filter->pre_analyzers |= AN_REQ_INSPECT_BE;

	if (!LIST_ISEMPTY(&ctx->events[SPOE_EV_ON_TCP_RSP]))
		filter->pre_analyzers |= AN_RES_INSPECT;

	if (!LIST_ISEMPTY(&ctx->events[SPOE_EV_ON_HTTP_REQ_FE]))
		filter->pre_analyzers |= AN_REQ_HTTP_PROCESS_FE;

	if (!LIST_ISEMPTY(&ctx->events[SPOE_EV_ON_HTTP_REQ_BE]))
		filter->pre_analyzers |= AN_REQ_HTTP_PROCESS_BE;

	if (!LIST_ISEMPTY(&ctx->events[SPOE_EV_ON_HTTP_RSP]))
		filter->pre_analyzers |= AN_RES_HTTP_PROCESS_FE;

	return 1;
}

/* Called when a filter instance is detached from a stream. It release the
 * attached SPOE context. */
static void spoe_stop(struct stream *s, struct filter *filter)
{
	spoe_destroy_context(filter);
}


/*
 * Called when the stream is woken up because of expired timer.
 */
static void spoe_check_timeouts(struct stream *s, struct filter *filter)
{
	struct spoe_context *ctx = filter->ctx;

	if (tick_is_expired(ctx->process_exp, now_ms))
		s->pending_events |= STRM_EVT_MSG;
}

/* Called when we are ready to filter data on a channel */
static int spoe_start_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct spoe_context *ctx = filter->ctx;
	int                  ret = 1;

	if (ctx->state == SPOE_CTX_ST_NONE)
		goto out;

	if (!(chn->flags & CF_ISRESP)) {
		if (filter->pre_analyzers & AN_REQ_INSPECT_FE)
			chn->analysers |= AN_REQ_INSPECT_FE;
		if (filter->pre_analyzers & AN_REQ_INSPECT_BE)
			chn->analysers |= AN_REQ_INSPECT_BE;

		if (ctx->flags & SPOE_CTX_FL_CLI_CONNECTED)
			goto out;

		ctx->stream_id = s->uniq_id;
		ret = spoe_process_event(s, ctx, SPOE_EV_ON_CLIENT_SESS);
		if (!ret)
			goto out;
		ctx->flags |= SPOE_CTX_FL_CLI_CONNECTED;
	}
	else {
		if (filter->pre_analyzers & AN_RES_INSPECT)
			chn->analysers |= AN_RES_INSPECT;

		if (ctx->flags & SPOE_CTX_FL_SRV_CONNECTED)
			goto out;

		ret = spoe_process_event(s, ctx, SPOE_EV_ON_SERVER_SESS);
		if (!ret) {
			channel_dont_read(chn);
			channel_dont_close(chn);
			goto out;
		}
		ctx->flags |= SPOE_CTX_FL_SRV_CONNECTED;
	}

  out:
	return ret;
}

/* Called before a processing happens on a given channel */
static int spoe_chn_pre_analyze(struct stream *s, struct filter *filter,
				struct channel *chn, unsigned an_bit)
{
	struct spoe_context *ctx = filter->ctx;
	int                  ret = 1;

	if (ctx->state == SPOE_CTX_ST_NONE)
		goto out;

	switch (an_bit) {
		case AN_REQ_INSPECT_FE:
			ret = spoe_process_event(s, ctx, SPOE_EV_ON_TCP_REQ_FE);
			break;
		case AN_REQ_INSPECT_BE:
			ret = spoe_process_event(s, ctx, SPOE_EV_ON_TCP_REQ_BE);
			break;
		case AN_RES_INSPECT:
			ret = spoe_process_event(s, ctx, SPOE_EV_ON_TCP_RSP);
			break;
		case AN_REQ_HTTP_PROCESS_FE:
			ret = spoe_process_event(s, ctx, SPOE_EV_ON_HTTP_REQ_FE);
			break;
		case AN_REQ_HTTP_PROCESS_BE:
			ret = spoe_process_event(s, ctx, SPOE_EV_ON_HTTP_REQ_BE);
			break;
		case AN_RES_HTTP_PROCESS_FE:
			ret = spoe_process_event(s, ctx, SPOE_EV_ON_HTTP_RSP);
			break;
	}

  out:
	if (!ret && (chn->flags & CF_ISRESP)) {
                channel_dont_read(chn);
                channel_dont_close(chn);
	}
	return ret;
}

/* Called when the filtering on the channel ends. */
static int spoe_end_analyze(struct stream *s, struct filter *filter, struct channel *chn)
{
	struct spoe_context *ctx = filter->ctx;

	if (!(ctx->flags & SPOE_CTX_FL_PROCESS)) {
		spoe_reset_context(ctx);
	}

	return 1;
}

/********************************************************************
 * Functions that manage the filter initialization
 ********************************************************************/
struct flt_ops spoe_ops = {
	/* Manage SPOE filter, called for each filter declaration */
	.init   = spoe_init,
	.deinit = spoe_deinit,
	.check  = spoe_check,

	/* Handle start/stop of SPOE */
	.attach         = spoe_start,
	.detach         = spoe_stop,
	.check_timeouts = spoe_check_timeouts,

	/* Handle channels activity */
	.channel_start_analyze = spoe_start_analyze,
	.channel_pre_analyze   = spoe_chn_pre_analyze,
	.channel_end_analyze   = spoe_end_analyze,
};


static int cfg_parse_spoe_agent(const char *file, int linenum, char **args, int kwm)
{
	const char *err;
	int         i, err_code = 0;

	if ((cfg_scope == NULL && curengine != NULL) ||
	    (cfg_scope != NULL && curengine == NULL) ||
	    (curengine != NULL && cfg_scope != NULL && strcmp(curengine, cfg_scope) != 0))
		goto out;

	if (strcmp(args[0], "spoe-agent") == 0) { /* new spoe-agent section */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for spoe-agent section.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (curagent != NULL) {
			ha_alert("parsing [%s:%d] : another spoe-agent section previously defined.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if ((curagent = calloc(1, sizeof(*curagent))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curagent->id              = strdup(args[1]);

		curagent->conf.file       = strdup(file);
		curagent->conf.line       = linenum;

		curagent->timeout.processing = TICK_ETERNITY;

		curagent->var_pfx        = NULL;
		curagent->var_on_error   = NULL;
		curagent->var_t_process  = NULL;
		curagent->var_t_total    = NULL;
		curagent->flags          = SPOE_FL_PIPELINING;
		curagent->max_frame_size = SPOP_MAX_FRAME_SIZE;

		if ((curagent->events = calloc(SPOE_EV_EVENTS, sizeof(*curagent->events))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		for (i = 0; i < SPOE_EV_EVENTS; ++i)
			LIST_INIT(&curagent->events[i]);
		LIST_INIT(&curagent->groups);
		LIST_INIT(&curagent->messages);
	}
	else if (strcmp(args[0], "use-backend") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects a backend name.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		free(curagent->b.name);
		curagent->b.name = strdup(args[1]);
	}
	else if (strcmp(args[0], "messages") == 0) {
		int cur_arg = 1;
		while (*args[cur_arg]) {
			struct spoe_placeholder *ph = NULL;

			list_for_each_entry(ph, &curmphs, list) {
				if (strcmp(ph->id, args[cur_arg]) == 0) {
					ha_alert("parsing [%s:%d]: spoe-message '%s' already used.\n",
						 file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}

			if ((ph = calloc(1, sizeof(*ph))) == NULL) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
			ph->id = strdup(args[cur_arg]);
			LIST_APPEND(&curmphs, &ph->list);
			cur_arg++;
		}
	}
	else if (strcmp(args[0], "groups") == 0) {
		int cur_arg = 1;
		while (*args[cur_arg]) {
			struct spoe_placeholder *ph = NULL;

			list_for_each_entry(ph, &curgphs, list) {
				if (strcmp(ph->id, args[cur_arg]) == 0) {
					ha_alert("parsing [%s:%d]: spoe-group '%s' already used.\n",
						 file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}

			if ((ph = calloc(1, sizeof(*ph))) == NULL) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
			ph->id = strdup(args[cur_arg]);
			LIST_APPEND(&curgphs, &ph->list);
			cur_arg++;
		}
	}
	else if (strcmp(args[0], "timeout") == 0) {
		unsigned int *tv = NULL;
		const char   *res;
		unsigned      timeout;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : 'timeout' expects 'hello', 'idle' and 'processing'.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (alertif_too_many_args(2, file, linenum, args, &err_code))
			goto out;
		if (strcmp(args[1], "hello") == 0) {
			/* TODO: Add a warning or a diag ? Ignore it for now */
			goto out;
		}
		else if (strcmp(args[1], "idle") == 0) {
			/* TODO: Add a warning or a diag ? Ignore it for now */
			goto out;
		}
		else if (strcmp(args[1], "processing") == 0)
			tv = &curagent->timeout.processing;
		else {
			ha_alert("parsing [%s:%d] : 'timeout' supports 'processing' (got %s).\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (!*args[2]) {
			ha_alert("parsing [%s:%d] : 'timeout %s' expects an integer value (in milliseconds).\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		res = parse_time_err(args[2], &timeout, TIME_UNIT_MS);
		if (res == PARSE_TIME_OVER) {
			ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s %s>, maximum value is 2147483647 ms (~24.8 days).\n",
				 file, linenum, args[2], args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (res == PARSE_TIME_UNDER) {
			ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s %s>, minimum non-null value is 1 ms.\n",
				 file, linenum, args[2], args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (res) {
			ha_alert("parsing [%s:%d] : unexpected character '%c' in 'timeout %s'.\n",
				 file, linenum, *res, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		*tv = MS_TO_TICKS(timeout);
	}
	else if (strcmp(args[0], "option") == 0) {
		if (!*args[1]) {
                        ha_alert("parsing [%s:%d]: '%s' expects an option name.\n",
				 file, linenum, args[0]);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }

		if (strcmp(args[1], "pipelining") == 0) {
			if (alertif_too_many_args(1, file, linenum, args, &err_code))
				goto out;
			if (kwm == 1)
				curagent->flags &= ~SPOE_FL_PIPELINING;
			else
				curagent->flags |= SPOE_FL_PIPELINING;
			goto out;
		}
		else if (strcmp(args[1], "async") == 0) {
			if (alertif_too_many_args(1, file, linenum, args, &err_code))
				goto out;
			/* TODO: Add a warning or a diag ? Ignore it for now */
			goto out;
		}
		else if (strcmp(args[1], "send-frag-payload") == 0) {
			if (alertif_too_many_args(1, file, linenum, args, &err_code))
				goto out;
			/* TODO: Add a warning or a diag ? Ignore it for now */
			goto out;
		}
		else if (strcmp(args[1], "dontlog-normal") == 0) {
			if (alertif_too_many_args(1, file, linenum, args, &err_code))
				goto out;
			if (kwm == 1)
				curpxopts2 &= ~PR_O2_NOLOGNORM;
			else
				curpxopts2 |= PR_O2_NOLOGNORM;
			goto out;
		}

		/* Following options does not support negation */
		if (kwm == 1) {
			ha_alert("parsing [%s:%d]: negation is not supported for option '%s'.\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (strcmp(args[1], "var-prefix") == 0) {
			char *tmp;

			if (!*args[2]) {
				ha_alert("parsing [%s:%d]: '%s %s' expects a value.\n",
					 file, linenum, args[0],
					 args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (alertif_too_many_args(2, file, linenum, args, &err_code))
				goto out;
			tmp = args[2];
			while (*tmp) {
				if (!isalnum((unsigned char)*tmp) && *tmp != '_' && *tmp != '.') {
					ha_alert("parsing [%s:%d]: '%s %s' only supports [a-zA-Z0-9_.] chars.\n",
						 file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tmp++;
			}
			curagent->var_pfx = strdup(args[2]);
		}
		else if (strcmp(args[1], "force-set-var") == 0) {
			if (alertif_too_many_args(1, file, linenum, args, &err_code))
				goto out;
			curagent->flags |= SPOE_FL_FORCE_SET_VAR;
		}
		else if (strcmp(args[1], "continue-on-error") == 0) {
			if (alertif_too_many_args(1, file, linenum, args, &err_code))
				goto out;
			curagent->flags |= SPOE_FL_CONT_ON_ERR;
		}
		else if (strcmp(args[1], "set-on-error") == 0) {
			char *tmp;

			if (!*args[2]) {
				ha_alert("parsing [%s:%d]: '%s %s' expects a value.\n",
					 file, linenum, args[0],
					 args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (alertif_too_many_args(2, file, linenum, args, &err_code))
				goto out;
			tmp = args[2];
			while (*tmp) {
				if (!isalnum((unsigned char)*tmp) && *tmp != '_' && *tmp != '.') {
					ha_alert("parsing [%s:%d]: '%s %s' only supports [a-zA-Z0-9_.] chars.\n",
						 file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tmp++;
			}
			curagent->var_on_error = strdup(args[2]);
		}
		else if (strcmp(args[1], "set-process-time") == 0) {
			char *tmp;

			if (!*args[2]) {
				ha_alert("parsing [%s:%d]: '%s %s' expects a value.\n",
					 file, linenum, args[0],
					 args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (alertif_too_many_args(2, file, linenum, args, &err_code))
				goto out;
			tmp = args[2];
			while (*tmp) {
				if (!isalnum((unsigned char)*tmp) && *tmp != '_' && *tmp != '.') {
					ha_alert("parsing [%s:%d]: '%s %s' only supports [a-zA-Z0-9_.] chars.\n",
						 file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tmp++;
			}
			curagent->var_t_process = strdup(args[2]);
		}
		else if (strcmp(args[1], "set-total-time") == 0) {
			char *tmp;

			if (!*args[2]) {
				ha_alert("parsing [%s:%d]: '%s %s' expects a value.\n",
					 file, linenum, args[0],
					 args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (alertif_too_many_args(2, file, linenum, args, &err_code))
				goto out;
			tmp = args[2];
			while (*tmp) {
				if (!isalnum((unsigned char)*tmp) && *tmp != '_' && *tmp != '.') {
					ha_alert("parsing [%s:%d]: '%s %s' only supports [a-zA-Z0-9_.] chars.\n",
						 file, linenum, args[0], args[1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
				tmp++;
			}
			curagent->var_t_total = strdup(args[2]);
		}
		else {
			ha_alert("parsing [%s:%d]: option '%s' is not supported.\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "maxconnrate") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n",
				 file, linenum, args[0]);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }
		/* TODO: Add a warning or a diag ? Ignore it for now */
	}
	else if (strcmp(args[0], "maxerrrate") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n",
				 file, linenum, args[0]);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }
		/* TODO: Add a warning or a diag ? Ignore it for now */
	}
	else if (strcmp(args[0], "max-frame-size") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n",
				 file, linenum, args[0]);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		curagent->max_frame_size = atol(args[1]);
		if (curagent->max_frame_size < SPOP_MIN_FRAME_SIZE ||
		    curagent->max_frame_size > SPOP_MAX_FRAME_SIZE) {
			ha_alert("parsing [%s:%d] : '%s' expects a positive integer argument in the range [%d, %d].\n",
				 file, linenum, args[0], SPOP_MIN_FRAME_SIZE, SPOP_MAX_FRAME_SIZE);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "max-waiting-frames") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n",
				 file, linenum, args[0]);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }
		if (alertif_too_many_args(1, file, linenum, args, &err_code))
			goto out;
		/* TODO: Add a warning or a diag ? Ignore it for now */
	}
	else if (strcmp(args[0], "register-var-names") == 0) {
		int   cur_arg;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects one or more variable names.\n",
				 file, linenum, args[0]);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }
		cur_arg = 1;
		while (*args[cur_arg]) {
			struct spoe_var_placeholder *vph;

			if ((vph = calloc(1, sizeof(*vph))) == NULL) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
			if ((vph->name  = strdup(args[cur_arg])) == NULL) {
				free(vph);
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
			LIST_APPEND(&curvars, &vph->list);
			cur_arg++;
		}
	}
	else if (strcmp(args[0], "log") == 0) {
		char *errmsg = NULL;

		if (!parse_logger(args, &curloggers, (kwm == 1), file, linenum, &errmsg)) {
			ha_alert("parsing [%s:%d] : %s : %s\n", file, linenum, args[0], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (*args[0]) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in spoe-agent section.\n",
			 file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
 out:
	return err_code;
}
static int cfg_parse_spoe_group(const char *file, int linenum, char **args, int kwm)
{
	struct spoe_group *grp;
	const char        *err;
	int                err_code = 0;

	if ((cfg_scope == NULL && curengine != NULL) ||
	    (cfg_scope != NULL && curengine == NULL) ||
	    (curengine != NULL && cfg_scope != NULL && strcmp(curengine, cfg_scope) != 0))
		goto out;

	if (strcmp(args[0], "spoe-group") == 0) { /* new spoe-group section */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for spoe-group section.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		list_for_each_entry(grp, &curgrps, list) {
			if (strcmp(grp->id, args[1]) == 0) {
				ha_alert("parsing [%s:%d]: spoe-group section '%s' has the same"
					 " name as another one declared at %s:%d.\n",
					 file, linenum, args[1], grp->conf.file, grp->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		if ((curgrp = calloc(1, sizeof(*curgrp))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curgrp->id        = strdup(args[1]);
		curgrp->conf.file = strdup(file);
		curgrp->conf.line = linenum;
		LIST_INIT(&curgrp->phs);
		LIST_INIT(&curgrp->messages);
		LIST_APPEND(&curgrps, &curgrp->list);
	}
	else if (strcmp(args[0], "messages") == 0) {
		int cur_arg = 1;
		while (*args[cur_arg]) {
			struct spoe_placeholder *ph = NULL;

			list_for_each_entry(ph, &curgrp->phs, list) {
				if (strcmp(ph->id, args[cur_arg]) == 0) {
					ha_alert("parsing [%s:%d]: spoe-message '%s' already used.\n",
						 file, linenum, args[cur_arg]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}

			if ((ph = calloc(1, sizeof(*ph))) == NULL) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}
			ph->id = strdup(args[cur_arg]);
			LIST_APPEND(&curgrp->phs, &ph->list);
			cur_arg++;
		}
	}
	else if (*args[0]) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in spoe-group section.\n",
			 file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
 out:
	return err_code;
}

static int cfg_parse_spoe_message(const char *file, int linenum, char **args, int kwm)
{
	struct spoe_message *msg;
	struct spoe_arg     *arg;
	const char          *err;
	char                *errmsg   = NULL;
	int                  err_code = 0;

	if ((cfg_scope == NULL && curengine != NULL) ||
	    (cfg_scope != NULL && curengine == NULL) ||
	    (curengine != NULL && cfg_scope != NULL && strcmp(curengine, cfg_scope) != 0))
		goto out;

	if (strcmp(args[0], "spoe-message") == 0) { /* new spoe-message section */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for spoe-message section.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}
		if (alertif_too_many_args(1, file, linenum, args, &err_code)) {
			err_code |= ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		list_for_each_entry(msg, &curmsgs, list) {
			if (strcmp(msg->id, args[1]) == 0) {
				ha_alert("parsing [%s:%d]: spoe-message section '%s' has the same"
					 " name as another one declared at %s:%d.\n",
					 file, linenum, args[1], msg->conf.file, msg->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}

		if ((curmsg = calloc(1, sizeof(*curmsg))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		curmsg->id = strdup(args[1]);
		curmsg->id_len = strlen(curmsg->id);
		curmsg->event  = SPOE_EV_NONE;
		curmsg->conf.file = strdup(file);
		curmsg->conf.line = linenum;
		curmsg->nargs = 0;
		LIST_INIT(&curmsg->args);
		LIST_INIT(&curmsg->acls);
		LIST_INIT(&curmsg->by_evt);
		LIST_INIT(&curmsg->by_grp);
		LIST_APPEND(&curmsgs, &curmsg->list);
	}
	else if (strcmp(args[0], "args") == 0) {
		int cur_arg = 1;

		curproxy->conf.args.ctx  = ARGC_SPOE;
		curproxy->conf.args.file = file;
		curproxy->conf.args.line = linenum;
		while (*args[cur_arg]) {
			char *delim = strchr(args[cur_arg], '=');
			int   idx = 0;

			if ((arg = calloc(1, sizeof(*arg))) == NULL) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT | ERR_ABORT;
				goto out;
			}

			if (!delim) {
				arg->name = NULL;
				arg->name_len  = 0;
				delim = args[cur_arg];
			}
			else {
				arg->name = my_strndup(args[cur_arg], delim - args[cur_arg]);
				arg->name_len = delim - args[cur_arg];
				delim++;
			}
			arg->expr = sample_parse_expr((char*[]){delim, NULL},
						      &idx, file, linenum, &errmsg,
						      &curproxy->conf.args, NULL);
			if (arg->expr == NULL) {
				ha_alert("parsing [%s:%d] : '%s': %s.\n", file, linenum, args[0], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(arg->name);
				free(arg);
				goto out;
			}
			curmsg->nargs++;
			LIST_APPEND(&curmsg->args, &arg->list);
			cur_arg++;
		}
		curproxy->conf.args.file = NULL;
		curproxy->conf.args.line = 0;
	}
	else if (strcmp(args[0], "acl") == 0) {
		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in acl name '%s'.\n",
				 file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strcasecmp(args[1], "or") == 0) {
			ha_alert("parsing [%s:%d] : acl name '%s' will never match. 'or' is used to express a "
				   "logical disjunction within a condition.\n",
				   file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (parse_acl((const char **)args + 1, &curmsg->acls, &errmsg, &curproxy->conf.args, file, linenum) == NULL) {
			ha_alert("parsing [%s:%d] : error detected while parsing ACL '%s' : %s.\n",
				 file, linenum, args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (strcmp(args[0], "event") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing event name.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		/* if (alertif_too_many_args(1, file, linenum, args, &err_code)) */
		/* 	goto out; */

		if (strcmp(args[1], spoe_event_str[SPOE_EV_ON_CLIENT_SESS]) == 0)
			curmsg->event = SPOE_EV_ON_CLIENT_SESS;
		else if (strcmp(args[1], spoe_event_str[SPOE_EV_ON_SERVER_SESS]) == 0)
			curmsg->event = SPOE_EV_ON_SERVER_SESS;

		else if (strcmp(args[1], spoe_event_str[SPOE_EV_ON_TCP_REQ_FE]) == 0)
			curmsg->event = SPOE_EV_ON_TCP_REQ_FE;
		else if (strcmp(args[1], spoe_event_str[SPOE_EV_ON_TCP_REQ_BE]) == 0)
			curmsg->event = SPOE_EV_ON_TCP_REQ_BE;
		else if (strcmp(args[1], spoe_event_str[SPOE_EV_ON_TCP_RSP]) == 0)
			curmsg->event = SPOE_EV_ON_TCP_RSP;

		else if (strcmp(args[1], spoe_event_str[SPOE_EV_ON_HTTP_REQ_FE]) == 0)
			curmsg->event = SPOE_EV_ON_HTTP_REQ_FE;
		else if (strcmp(args[1], spoe_event_str[SPOE_EV_ON_HTTP_REQ_BE]) == 0)
			curmsg->event = SPOE_EV_ON_HTTP_REQ_BE;
		else if (strcmp(args[1], spoe_event_str[SPOE_EV_ON_HTTP_RSP]) == 0)
			curmsg->event = SPOE_EV_ON_HTTP_RSP;
		else {
			ha_alert("parsing [%s:%d] : unknown event '%s'.\n",
				 file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (strcmp(args[2], "if") == 0 || strcmp(args[2], "unless") == 0) {
			struct acl_cond *cond;

			cond = build_acl_cond(file, linenum, &curmsg->acls,
					      curproxy, (const char **)args+2,
					      &errmsg);
			if (cond == NULL) {
				ha_alert("parsing [%s:%d] : error detected while "
					 "parsing an 'event %s' condition : %s.\n",
					 file, linenum, args[1], errmsg);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			curmsg->cond = cond;
		}
		else if (*args[2]) {
			ha_alert("parsing [%s:%d]: 'event %s' expects either 'if' "
				 "or 'unless' followed by a condition but found '%s'.\n",
				 file, linenum, args[1], args[2]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (!*args[0]) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in spoe-message section.\n",
			 file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
 out:
	free(errmsg);
	return err_code;
}

/* Return -1 on error, else 0 */
static int parse_spoe_flt(char **args, int *cur_arg, struct proxy *px,
			  struct flt_conf *fconf, char **err, void *private)
{
	struct list backup_sections;
	struct spoe_config          *conf;
	struct spoe_message         *msg, *msgback;
	struct spoe_group           *grp, *grpback;
	struct spoe_placeholder     *ph, *phback;
	struct spoe_var_placeholder *vph, *vphback;
	struct cfgfile		    cfg_file = { };
	struct logger               *logger, *loggerback;
	char                        *file = NULL, *engine = NULL;
	int                          ret, pos = *cur_arg + 1;

	LIST_INIT(&curmsgs);
	LIST_INIT(&curgrps);
	LIST_INIT(&curmphs);
	LIST_INIT(&curgphs);
	LIST_INIT(&curvars);
	LIST_INIT(&curloggers);
	curpxopts  = 0;
	curpxopts2 = 0;

	conf = calloc(1, sizeof(*conf));
	if (conf == NULL) {
		memprintf(err, "%s: out of memory", args[*cur_arg]);
		goto error;
	}
	conf->proxy = px;

	while (*args[pos]) {
		if (strcmp(args[pos], "config") == 0) {
			if (!*args[pos+1]) {
				memprintf(err, "'%s' : '%s' option without value",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			file = args[pos+1];
			pos += 2;
		}
		else if (strcmp(args[pos], "engine") == 0) {
			if (!*args[pos+1]) {
				memprintf(err, "'%s' : '%s' option without value",
					  args[*cur_arg], args[pos]);
				goto error;
			}
			engine = args[pos+1];
			pos += 2;
		}
		else {
			memprintf(err, "unknown keyword '%s'", args[pos]);
			goto error;
		}
	}
	if (file == NULL) {
		memprintf(err, "'%s' : missing config file", args[*cur_arg]);
		goto error;
	}

	/* backup sections and register SPOE sections */
	LIST_INIT(&backup_sections);
	cfg_backup_sections(&backup_sections);
	cfg_register_section("spoe-agent",   cfg_parse_spoe_agent, NULL);
	cfg_register_section("spoe-group",   cfg_parse_spoe_group, NULL);
	cfg_register_section("spoe-message", cfg_parse_spoe_message, NULL);

	/* Parse SPOE filter configuration file */
	BUG_ON(px != curproxy);
	curengine = engine;
	curagent  = NULL;
	curmsg    = NULL;

	/* load the content of SPOE config file from cfg_file.filename into some
	 * area in .heap. readcfgfile() now parses the content of config files
	 * stored in RAM as separate chunks (see struct cfgfile in cfgparse.h),
	 * these chunks chained in cfg_cfgfiles global list.
	 */
	cfg_file.filename = file;
	cfg_file.size = load_cfg_in_mem(file, &cfg_file.content);
	if (cfg_file.size < 0) {
		goto error;
	}
	ret = parse_cfg(&cfg_file);
	ha_free(&cfg_file.content);

	/* unregister SPOE sections and restore previous sections */
	cfg_unregister_sections();
	cfg_restore_sections(&backup_sections);

	if (ret == -1) {
		memprintf(err, "Could not open configuration file %s : %s",
			  file, strerror(errno));
		goto error;
	}
	if (ret & (ERR_ABORT|ERR_FATAL)) {
		memprintf(err, "Error(s) found in configuration file %s", file);
		goto error;
	}

	/* Check SPOE agent */
	if (curagent == NULL) {
		memprintf(err, "No SPOE agent found in file %s", file);
		goto error;
	}
	if (curagent->b.name == NULL) {
		memprintf(err, "No backend declared for SPOE agent '%s' declared at %s:%d",
			  curagent->id, curagent->conf.file, curagent->conf.line);
		goto error;
	}
	if (curagent->timeout.processing == TICK_ETERNITY) {
		ha_warning("Proxy '%s': missing 'processing' timeout for SPOE agent '%s' declare at %s:%d.\n"
			   "   | While not properly invalid, you will certainly encounter various problems\n"
			   "   | with such a configuration. To fix this, please ensure it is set to a non-zero value.\n",
			   px->id, curagent->id, curagent->conf.file, curagent->conf.line);
	}
	if (curagent->var_pfx == NULL) {
		char *tmp = curagent->id;

		while (*tmp) {
			if (!isalnum((unsigned char)*tmp) && *tmp != '_' && *tmp != '.') {
				memprintf(err, "Invalid variable prefix '%s' for SPOE agent '%s' declared at %s:%d. "
					  "Use 'option var-prefix' to set it. Only [a-zA-Z0-9_.] chars are supported.\n",
					  curagent->id, curagent->id, curagent->conf.file, curagent->conf.line);
				goto error;
			}
			tmp++;
		}
		curagent->var_pfx = strdup(curagent->id);
	}

	if (curagent->var_on_error) {
		struct arg arg;

		trash.data = snprintf(trash.area, trash.size, "txn.%s.%s",
				     curagent->var_pfx, curagent->var_on_error);

		arg.type = ARGT_STR;
		arg.data.str.area = trash.area;
		arg.data.str.data = trash.data;
		arg.data.str.size = 0; /* Set it to 0 to not release it in vars_check_arg() */
		if (!vars_check_arg(&arg, err)) {
			memprintf(err, "SPOE agent '%s': failed to register variable %s.%s (%s)",
				  curagent->id, curagent->var_pfx, curagent->var_on_error, *err);
			goto error;
		}
	}

	if (curagent->var_t_process) {
		struct arg arg;

		trash.data = snprintf(trash.area, trash.size, "txn.%s.%s",
				     curagent->var_pfx, curagent->var_t_process);

		arg.type = ARGT_STR;
		arg.data.str.area = trash.area;
		arg.data.str.data = trash.data;
		arg.data.str.size = 0;  /* Set it to 0 to not release it in vars_check_arg() */
		if (!vars_check_arg(&arg, err)) {
			memprintf(err, "SPOE agent '%s': failed to register variable %s.%s (%s)",
				  curagent->id, curagent->var_pfx, curagent->var_t_process, *err);
			goto error;
		}
	}

	if (curagent->var_t_total) {
		struct arg arg;

		trash.data = snprintf(trash.area, trash.size, "txn.%s.%s",
				     curagent->var_pfx, curagent->var_t_total);

		arg.type = ARGT_STR;
		arg.data.str.area = trash.area;
		arg.data.str.data = trash.data;
		arg.data.str.size = 0;  /* Set it to 0 to not release it in vars_check_arg() */
		if (!vars_check_arg(&arg, err)) {
			memprintf(err, "SPOE agent '%s': failed to register variable %s.%s (%s)",
				  curagent->id, curagent->var_pfx, curagent->var_t_process, *err);
			goto error;
		}
	}

	if (LIST_ISEMPTY(&curmphs) && LIST_ISEMPTY(&curgphs)) {
		ha_warning("Proxy '%s': No message/group used by SPOE agent '%s' declared at %s:%d.\n",
			   px->id, curagent->id, curagent->conf.file, curagent->conf.line);
		goto finish;
	}

	/* Replace placeholders by the corresponding messages for the SPOE
	 * agent */
	list_for_each_entry(ph, &curmphs, list) {
		list_for_each_entry(msg, &curmsgs, list) {
			struct spoe_arg *arg;
			unsigned int     where;

			if (strcmp(msg->id, ph->id) == 0) {
				if ((px->cap & (PR_CAP_FE|PR_CAP_BE)) == (PR_CAP_FE|PR_CAP_BE)) {
					if (msg->event == SPOE_EV_ON_TCP_REQ_BE)
						msg->event = SPOE_EV_ON_TCP_REQ_FE;
					if (msg->event == SPOE_EV_ON_HTTP_REQ_BE)
						msg->event = SPOE_EV_ON_HTTP_REQ_FE;
				}
				if (!(px->cap & PR_CAP_FE) && (msg->event == SPOE_EV_ON_CLIENT_SESS ||
							       msg->event == SPOE_EV_ON_TCP_REQ_FE ||
							       msg->event == SPOE_EV_ON_HTTP_REQ_FE)) {
					ha_warning("Proxy '%s': frontend event used on a backend proxy at %s:%d.\n",
						   px->id, msg->conf.file, msg->conf.line);
					goto next_mph;
				}
				if (msg->event == SPOE_EV_NONE) {
					ha_warning("Proxy '%s': Ignore SPOE message '%s' without event at %s:%d.\n",
						   px->id, msg->id, msg->conf.file, msg->conf.line);
					goto next_mph;
				}

				where = 0;
				switch (msg->event) {
					case SPOE_EV_ON_CLIENT_SESS:
						where |= SMP_VAL_FE_CON_ACC;
						break;

					case SPOE_EV_ON_TCP_REQ_FE:
						where |= SMP_VAL_FE_REQ_CNT;
						break;

					case SPOE_EV_ON_HTTP_REQ_FE:
						where |= SMP_VAL_FE_HRQ_HDR;
						break;

					case SPOE_EV_ON_TCP_REQ_BE:
						if (px->cap & PR_CAP_FE)
							where |= SMP_VAL_FE_REQ_CNT;
						if (px->cap & PR_CAP_BE)
							where |= SMP_VAL_BE_REQ_CNT;
						break;

					case SPOE_EV_ON_HTTP_REQ_BE:
						if (px->cap & PR_CAP_FE)
							where |= SMP_VAL_FE_HRQ_HDR;
						if (px->cap & PR_CAP_BE)
							where |= SMP_VAL_BE_HRQ_HDR;
						break;

					case SPOE_EV_ON_SERVER_SESS:
						where |= SMP_VAL_BE_SRV_CON;
						break;

					case SPOE_EV_ON_TCP_RSP:
						if (px->cap & PR_CAP_FE)
							where |= SMP_VAL_FE_RES_CNT;
						if (px->cap & PR_CAP_BE)
							where |= SMP_VAL_BE_RES_CNT;
						break;

					case SPOE_EV_ON_HTTP_RSP:
						if (px->cap & PR_CAP_FE)
							where |= SMP_VAL_FE_HRS_HDR;
						if (px->cap & PR_CAP_BE)
							where |= SMP_VAL_BE_HRS_HDR;
						break;

					default:
						break;
				}

				list_for_each_entry(arg, &msg->args, list) {
					if (!(arg->expr->fetch->val & where)) {
						memprintf(err, "Ignore SPOE message '%s' at %s:%d: "
							"some args extract information from '%s', "
							"none of which is available here ('%s')",
							msg->id, msg->conf.file, msg->conf.line,
							sample_ckp_names(arg->expr->fetch->use),
							sample_ckp_names(where));
						goto error;
					}
				}

				msg->agent = curagent;
				LIST_APPEND(&curagent->events[msg->event], &msg->by_evt);
				goto next_mph;
			}
		}
		memprintf(err, "SPOE agent '%s' try to use undefined SPOE message '%s' at %s:%d",
			  curagent->id, ph->id, curagent->conf.file, curagent->conf.line);
		goto error;
	  next_mph:
		continue;
	}

	/* Replace placeholders by the corresponding groups for the SPOE
	 * agent */
	list_for_each_entry(ph, &curgphs, list) {
		list_for_each_entry_safe(grp, grpback, &curgrps, list) {
			if (strcmp(grp->id, ph->id) == 0) {
				grp->agent = curagent;
				LIST_DELETE(&grp->list);
				LIST_APPEND(&curagent->groups, &grp->list);
				goto next_aph;
			}
		}
		memprintf(err, "SPOE agent '%s' try to use undefined SPOE group '%s' at %s:%d",
			  curagent->id, ph->id, curagent->conf.file, curagent->conf.line);
		goto error;
	  next_aph:
		continue;
	}

	/* Replace placeholders by the corresponding message for each SPOE
	 * group of the SPOE agent */
	list_for_each_entry(grp, &curagent->groups, list) {
		list_for_each_entry_safe(ph, phback, &grp->phs, list) {
			list_for_each_entry(msg, &curmsgs, list) {
				if (strcmp(msg->id, ph->id) == 0) {
					if (msg->group != NULL) {
						memprintf(err, "SPOE message '%s' already belongs to "
							  "the SPOE group '%s' declare at %s:%d",
							  msg->id, msg->group->id,
							  msg->group->conf.file,
							  msg->group->conf.line);
						goto error;
					}

					/* Scope for arguments are not checked for now. We will check
					 * them only if a rule use the corresponding SPOE group. */
					msg->agent = curagent;
					msg->group = grp;
					LIST_DELETE(&ph->list);
					LIST_APPEND(&grp->messages, &msg->by_grp);
					goto next_mph_grp;
				}
			}
			memprintf(err, "SPOE group '%s' try to use undefined SPOE message '%s' at %s:%d",
				  grp->id, ph->id, curagent->conf.file, curagent->conf.line);
			goto error;
		  next_mph_grp:
			continue;
		}
	}

 finish:
	/* move curmsgs to the agent message list */
	curmsgs.n->p = &curagent->messages;
	curmsgs.p->n = &curagent->messages;
	curagent->messages = curmsgs;
	LIST_INIT(&curmsgs);

	conf->id    = strdup(engine ? engine : curagent->id);
	conf->agent = curagent;
	curagent->spoe_conf = conf;

	/* Start agent's proxy initialization here. It will be finished during
	 * the filter init. */
        memset(&conf->agent->fe, 0, sizeof(conf->agent->fe));
        init_new_proxy(&conf->agent->fe);
	conf->agent->fe.id        = conf->agent->id;
	conf->agent->fe.parent    = conf->agent;
	conf->agent->fe.options  |= curpxopts;
	conf->agent->fe.options2 |= curpxopts2;

	list_for_each_entry_safe(logger, loggerback, &curloggers, list) {
		LIST_DELETE(&logger->list);
		LIST_APPEND(&conf->agent->fe.loggers, &logger->list);
	}

	list_for_each_entry_safe(ph, phback, &curmphs, list) {
		LIST_DELETE(&ph->list);
		spoe_release_placeholder(ph);
	}
	list_for_each_entry_safe(ph, phback, &curgphs, list) {
		LIST_DELETE(&ph->list);
		spoe_release_placeholder(ph);
	}
	list_for_each_entry_safe(vph, vphback, &curvars, list) {
		struct arg arg;

		trash.data = snprintf(trash.area, trash.size, "proc.%s.%s",
				     curagent->var_pfx, vph->name);

		arg.type = ARGT_STR;
		arg.data.str.area = trash.area;
		arg.data.str.data = trash.data;
		arg.data.str.size = 0;  /* Set it to 0 to not release it in vars_check_arg() */
		if (!vars_check_arg(&arg, err)) {
			memprintf(err, "SPOE agent '%s': failed to register variable %s.%s (%s)",
				  curagent->id, curagent->var_pfx, vph->name, *err);
			goto error;
		}

		LIST_DELETE(&vph->list);
		free(vph->name);
		free(vph);
	}
	list_for_each_entry_safe(grp, grpback, &curgrps, list) {
		LIST_DELETE(&grp->list);
		spoe_release_group(grp);
	}
	*cur_arg    = pos;
	fconf->id   = spoe_filter_id;
	fconf->ops  = &spoe_ops;
	fconf->conf = conf;
	return 0;

 error:
	ha_free(&cfg_file.content);
	spoe_release_agent(curagent);
	list_for_each_entry_safe(ph, phback, &curmphs, list) {
		LIST_DELETE(&ph->list);
		spoe_release_placeholder(ph);
	}
	list_for_each_entry_safe(ph, phback, &curgphs, list) {
		LIST_DELETE(&ph->list);
		spoe_release_placeholder(ph);
	}
	list_for_each_entry_safe(vph, vphback, &curvars, list) {
		LIST_DELETE(&vph->list);
		free(vph->name);
		free(vph);
	}
	list_for_each_entry_safe(grp, grpback, &curgrps, list) {
		LIST_DELETE(&grp->list);
		spoe_release_group(grp);
	}
	list_for_each_entry_safe(msg, msgback, &curmsgs, list) {
		LIST_DELETE(&msg->list);
		spoe_release_message(msg);
	}
	list_for_each_entry_safe(logger, loggerback, &curloggers, list) {
		LIST_DELETE(&logger->list);
		free(logger);
	}
	free(conf);
	return -1;
}

/* Send message of a SPOE group. This is the action_ptr callback of a rule
 * associated to a "send-spoe-group" action.
 *
 * It returns ACT_RET_CONT if processing is finished (with error or not), it returns
 * ACT_RET_YIELD if the action is in progress. */
static enum act_return spoe_send_group(struct act_rule *rule, struct proxy *px,
				       struct session *sess, struct stream *s, int flags)
{
	struct filter      *filter;
	struct spoe_agent   *agent = NULL;
	struct spoe_group   *group = NULL;
	struct spoe_context *ctx   = NULL;
	int ret, dir;

	list_for_each_entry(filter, &s->strm_flt.filters, list) {
		if (filter->config == rule->arg.act.p[0]) {
			agent = rule->arg.act.p[2];
			group = rule->arg.act.p[3];
			ctx   = filter->ctx;
			break;
		}
	}
	if (agent == NULL || group == NULL || ctx == NULL)
		return ACT_RET_CONT;
	if (ctx->state == SPOE_CTX_ST_NONE)
		return ACT_RET_CONT;

	switch (rule->from) {
		case ACT_F_TCP_REQ_SES: dir = SMP_OPT_DIR_REQ; break;
		case ACT_F_TCP_REQ_CNT: dir = SMP_OPT_DIR_REQ; break;
		case ACT_F_TCP_RES_CNT: dir = SMP_OPT_DIR_RES; break;
		case ACT_F_HTTP_REQ:    dir = SMP_OPT_DIR_REQ; break;
		case ACT_F_HTTP_RES:    dir = SMP_OPT_DIR_RES; break;
		default:
			send_log(px, LOG_ERR, "SPOE: [%s] internal error while execute spoe-send-group\n",
				 agent->id);
			return ACT_RET_CONT;
	}

	ret = spoe_process_group(s, ctx, group, dir);
	if (ret == 1)
		return ACT_RET_CONT;
	else if (ret == 0) {
		if (flags & ACT_OPT_FINAL) {
			ctx->status_code = SPOE_CTX_ERR_INTERRUPT;
			spoe_stop_processing(agent, ctx);
			spoe_handle_processing_error(s, agent, ctx, dir);
			return ACT_RET_CONT;
		}
		return ACT_RET_YIELD;
	}
	else
		return ACT_RET_CONT;
}

/* Check an "send-spoe-group" action. Here, we'll try to find the real SPOE
 * group associated to <rule>. The format of an rule using 'send-spoe-group'
 * action should be:
 *
 *   (http|tcp)-(request|response) send-spoe-group <engine-id> <group-id>
 *
 * So, we'll loop on each configured SPOE filter for the proxy <px> to find the
 * SPOE engine matching <engine-id>. And then, we'll try to find the good group
 * matching <group-id>. Finally, we'll check all messages referenced by the SPOE
 * group.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
static int check_send_spoe_group(struct act_rule *rule, struct proxy *px, char **err)
{
	struct flt_conf     *fconf;
	struct spoe_config  *conf;
	struct spoe_agent   *agent = NULL;
	struct spoe_group   *group;
	struct spoe_message *msg;
	char                *engine_id = rule->arg.act.p[0];
	char                *group_id  = rule->arg.act.p[1];
	unsigned int         where = 0;

	switch (rule->from) {
		case ACT_F_TCP_REQ_SES: where = SMP_VAL_FE_SES_ACC; break;
		case ACT_F_TCP_REQ_CNT: where = SMP_VAL_FE_REQ_CNT; break;
		case ACT_F_TCP_RES_CNT: where = SMP_VAL_BE_RES_CNT; break;
		case ACT_F_HTTP_REQ:    where = SMP_VAL_FE_HRQ_HDR; break;
		case ACT_F_HTTP_RES:    where = SMP_VAL_BE_HRS_HDR; break;
		default:
			memprintf(err,
				  "internal error, unexpected rule->from=%d, please report this bug!",
				  rule->from);
			goto error;
	}

	/* Try to find the SPOE engine by checking all SPOE filters for proxy
	 * <px> */
	list_for_each_entry(fconf, &px->filter_configs, list) {
		conf = fconf->conf;

		/* This is not an SPOE filter */
		if (fconf->id != spoe_filter_id)
			continue;

		/* This is the good engine */
		if (strcmp(conf->id, engine_id) == 0) {
			agent = conf->agent;
			break;
		}
	}
	if (agent == NULL) {
		memprintf(err, "unable to find SPOE engine '%s' used by the send-spoe-group '%s'",
			  engine_id, group_id);
		goto error;
	}

	/* Try to find the right group */
	list_for_each_entry(group, &agent->groups, list) {
		/* This is the good group */
		if (strcmp(group->id, group_id) == 0)
			break;
	}
	if (&group->list == &agent->groups) {
		memprintf(err, "unable to find SPOE group '%s' into SPOE engine '%s' configuration",
			  group_id, engine_id);
		goto error;
	}

	/* Ok, we found the group, we need to check messages and their
	 * arguments */
	list_for_each_entry(msg, &group->messages, by_grp) {
		struct spoe_arg *arg;

		list_for_each_entry(arg, &msg->args, list) {
			if (!(arg->expr->fetch->val & where)) {
				memprintf(err, "Invalid SPOE message '%s' used by SPOE group '%s' at %s:%d: "
					  "some args extract information from '%s',"
					  "none of which is available here ('%s')",
					  msg->id, group->id, msg->conf.file, msg->conf.line,
					  sample_ckp_names(arg->expr->fetch->use),
					  sample_ckp_names(where));
				goto error;
			}
		}
	}

	free(engine_id);
	free(group_id);
	rule->arg.act.p[0] = fconf; /* Associate filter config with the rule */
	rule->arg.act.p[1] = conf;  /* Associate SPOE config with the rule */
	rule->arg.act.p[2] = agent; /* Associate SPOE agent with the rule */
	rule->arg.act.p[3] = group; /* Associate SPOE group with the rule */
	return 1;

  error:
	free(engine_id);
	free(group_id);
	return 0;
}

/* Parse 'send-spoe-group' action following the format:
 *
 *     ... send-spoe-group <engine-id> <group-id>
 *
 * It returns ACT_RET_PRS_ERR if fails and <err> is filled with an error
 * message. Otherwise, it returns ACT_RET_PRS_OK and parsing engine and group
 * ids are saved and used later, when the rule will be checked.
 */
static enum act_parse_ret parse_send_spoe_group(const char **args, int *orig_arg, struct proxy *px,
						struct act_rule *rule, char **err)
{
	if (!*args[*orig_arg] || !*args[*orig_arg+1] ||
	    (*args[*orig_arg+2] && strcmp(args[*orig_arg+2], "if") != 0 && strcmp(args[*orig_arg+2], "unless") != 0)) {
		memprintf(err, "expects 2 arguments: <engine-id> <group-id>");
		return ACT_RET_PRS_ERR;
	}
	rule->arg.act.p[0] = strdup(args[*orig_arg]);   /* Copy the SPOE engine id */
	rule->arg.act.p[1] = strdup(args[*orig_arg+1]); /* Cope the SPOE group id */

	(*orig_arg) += 2;

	rule->action     = ACT_CUSTOM;
	rule->action_ptr = spoe_send_group;
	rule->check_ptr  = check_send_spoe_group;
	return ACT_RET_PRS_OK;
}


/* returns the engine ID of the SPOE */
static int smp_fetch_spoe_engine_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct appctx *appctx;
	struct spoe_agent *agent;

        if (!smp->strm)
                return 0;

	appctx = sc_appctx(smp->strm->scf);
	if (!appctx || appctx->applet != &spoe_applet)
		return 0;

	agent = spoe_appctx_agent(appctx);
	if (!agent)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->data.u.str.area = agent->engine_id;
	smp->data.u.str.data = strlen(agent->engine_id);
	smp->flags = SMP_F_CONST;

	return 1;
}

static int spoe_postcheck_spop_proxy(struct proxy *px)
{
	struct server *srv;
	int err_code = ERR_NONE;

	if (!(px->cap & PR_CAP_BE) || px->mode != PR_MODE_SPOP)
		goto out;

	for (srv = px->srv; srv; srv = srv->next) {
		if (srv->pool_conn_name) {
			ha_free(&srv->pool_conn_name);
			release_sample_expr(srv->pool_conn_name_expr);
		}
		srv->pool_conn_name = strdup("spoe.engine-id");
		if (!srv->pool_conn_name) {
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		srv->pool_conn_name_expr = _parse_srv_expr(srv->pool_conn_name, &px->conf.args, NULL, 0, NULL);
		if (!srv->pool_conn_name_expr) {
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}

  out:
	return err_code;
}

REGISTER_POST_PROXY_CHECK(spoe_postcheck_spop_proxy);

/* Declare the filter parser for "spoe" keyword */
static struct flt_kw_list flt_kws = { "SPOE", { }, {
		{ "spoe", parse_spoe_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &flt_kws);

/* Delcate the action parser for "spoe-action" keyword */
static struct action_kw_list tcp_req_action_kws = { { }, {
		{ "send-spoe-group", parse_send_spoe_group },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_action_kws);

static struct action_kw_list tcp_res_action_kws = { { }, {
		{ "send-spoe-group", parse_send_spoe_group },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_action_kws);

static struct action_kw_list http_req_action_kws = { { }, {
		{ "send-spoe-group", parse_send_spoe_group },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_action_kws);

static struct action_kw_list http_res_action_kws = { { }, {
		{ "send-spoe-group", parse_send_spoe_group },
		{ /* END */ },
	}
};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_action_kws);


static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "spoe.engine-id",  smp_fetch_spoe_engine_id, 0, NULL, SMP_T_STR, SMP_USE_INTRN},
	{},
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_kws);
