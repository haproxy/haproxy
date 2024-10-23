/*
 * include/haproxy/applet-t.h
 * This file describes the applet struct and associated constants.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_APPLET_T_H
#define _HAPROXY_APPLET_T_H

#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/dynbuf-t.h>
#include <haproxy/freq_ctr-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/show_flags-t.h>
#include <haproxy/task-t.h>
#include <haproxy/xref-t.h>

/* flags for appctx->state */

/* Room for per-command context (mostly CLI commands but not only) */
#define APPLET_MAX_SVCCTX 256

/* Appctx Flags */
#define APPCTX_FL_INBLK_ALLOC    0x00000001
#define APPCTX_FL_INBLK_FULL     0x00000002
#define APPCTX_FL_OUTBLK_ALLOC   0x00000004
#define APPCTX_FL_OUTBLK_FULL    0x00000008
#define APPCTX_FL_EOI            0x00000010
#define APPCTX_FL_EOS            0x00000020
#define APPCTX_FL_ERR_PENDING    0x00000040
#define APPCTX_FL_ERROR          0x00000080
#define APPCTX_FL_SHUTDOWN       0x00000100  /* applet was shut down (->release() called if any). No more data exchange with SCs */
#define APPCTX_FL_WANT_DIE       0x00000200  /* applet was running and requested to die */
#define APPCTX_FL_INOUT_BUFS     0x00000400  /* applet uses its own buffers */
#define APPCTX_FL_FASTFWD        0x00000800  /* zero-copy forwarding is in-use, don't fill the outbuf */
#define APPCTX_FL_IN_MAYALLOC    0x00001000  /* applet may try again to allocate its inbuf */
#define APPCTX_FL_OUT_MAYALLOC   0x00002000  /* applet may try again to allocate its outbuf */

struct appctx;
struct proxy;
struct stconn;
struct sedesc;
struct se_abort_info;
struct session;

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *appctx_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(APPCTX_FL_INBLK_ALLOC, _(APPCTX_FL_INBLK_FULL,
	_(APPCTX_FL_OUTBLK_ALLOC, _(APPCTX_FL_OUTBLK_FULL,
	_(APPCTX_FL_EOI, _(APPCTX_FL_EOS,
	_(APPCTX_FL_ERR_PENDING, _(APPCTX_FL_ERROR,
	_(APPCTX_FL_SHUTDOWN, _(APPCTX_FL_WANT_DIE, _(APPCTX_FL_INOUT_BUFS,
	_(APPCTX_FL_FASTFWD, _(APPCTX_FL_IN_MAYALLOC, _(APPCTX_FL_OUT_MAYALLOC))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/* Applet descriptor */
struct applet {
	enum obj_type obj_type;            /* object type = OBJ_TYPE_APPLET */
	/* 3 unused bytes here */
	char *name;                        /* applet's name to report in logs */
	int (*init)(struct appctx *);      /* callback to init resources, may be NULL.
					      expect 0 if ok, -1 if an error occurs. */
	void (*fct)(struct appctx *);      /* internal I/O handler, may never be NULL */
	size_t (*rcv_buf)(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags); /* called from the upper layer to get data */
	size_t (*snd_buf)(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags); /* Called from the upper layet to put data */
	size_t (*fastfwd)(struct appctx *appctx, struct buffer *buf, size_t count, unsigned int flags); /* Callback to fast-forward data */
	void (*shut)(struct appctx *appctx, unsigned int mode, struct se_abort_info *reason); /* shutdown function */
	void (*release)(struct appctx *);  /* callback to release resources, may be NULL */
	unsigned int timeout;              /* execution timeout. */
};

/* Context of a running applet. */
struct appctx {
	enum obj_type obj_type;    /* OBJ_TYPE_APPCTX */
	/* 3 unused bytes here */
	unsigned int st0;          /* CLI state for stats, session state for peers */
	unsigned int st1;          /* prompt/payload (bitwise OR of APPCTX_CLI_ST1_*) for stats, session error for peers */

	unsigned int flags;        /* APPCTX_FL_* */
	struct buffer inbuf;
	struct buffer outbuf;
	size_t to_forward;

	struct buffer *chunk;       /* used to store unfinished commands */
	struct applet *applet;     /* applet this context refers to */
	struct session *sess;      /* session for frontend applets (NULL for backend applets) */
	struct sedesc *sedesc;     /* stream endpoint descriptor the applet is attached to */
	struct act_rule *rule;     /* rule associated with the applet. */
	int (*io_handler)(struct appctx *appctx);  /* used within the cli_io_handler when st0 = CLI_ST_CALLBACK */
	void (*io_release)(struct appctx *appctx);  /* used within the cli_io_handler when st0 = CLI_ST_CALLBACK,
	                                               if the command is terminated or the session released */
	int cli_severity_output;        /* used within the cli_io_handler to format severity output of informational feedback */
	int cli_level;              /* the level of CLI which can be lowered dynamically */
	char cli_payload_pat[8];        /* Payload pattern */
	uint32_t cli_anon_key;       /* the key to anonymise with the hash in cli */
	struct buffer_wait buffer_wait; /* position in the list of objects waiting for a buffer */
	struct task *t;                  /* task associated to the applet */
	struct freq_ctr call_rate;       /* appctx call rate */
	struct mt_list wait_entry;       /* entry in a list of waiters for an event (e.g. ring events) */

	/* The pointer seen by application code is appctx->svcctx. In 2.7 the
	 * anonymous union and the "ctx" struct disappeared, and the struct
	 * "svc" became svc_storage, which is never accessed directly by
	 * application code. Look at "show fd" for an example.
	 */

	/* here we have the service's context (CLI command, applet, etc) */
	void *svcctx;                            /* pointer to a context used by the command, e.g. <storage> below */
	struct {
		void *shadow;                    /* shadow of svcctx above, do not use! */
		char storage[APPLET_MAX_SVCCTX]; /* storage of svcctx above */
	} svc;                                   /* generic storage for most commands */
};

#endif /* _HAPROXY_APPLET_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
