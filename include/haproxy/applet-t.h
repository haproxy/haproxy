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
#include <haproxy/xref-t.h>

/* flags for appctx->state */
#define APPLET_WANT_DIE     0x01  /* applet was running and requested to die */

/* Room for per-command context (mostly CLI commands but not only) */
#define APPLET_MAX_SVCCTX 88

struct appctx;
struct proxy;
struct conn_stream;
struct cs_endpoint;

/* Applet descriptor */
struct applet {
	enum obj_type obj_type;            /* object type = OBJ_TYPE_APPLET */
	/* 3 unused bytes here */
	char *name;                        /* applet's name to report in logs */
	int (*init)(struct appctx *);   /* callback to init resources, may be NULL.
	                                     expect 1 if ok, 0 if an error occurs, -1 if miss data. */
	void (*fct)(struct appctx *);      /* internal I/O handler, may never be NULL */
	void (*release)(struct appctx *);  /* callback to release resources, may be NULL */
	unsigned int timeout;              /* execution timeout. */
};

/* Context of a running applet. */
struct appctx {
	enum obj_type obj_type;    /* OBJ_TYPE_APPCTX */
	/* 3 unused bytes here */
	unsigned short state;      /* Internal appctx state */
	unsigned int st0;          /* CLI state for stats, session state for peers */
	unsigned int st1;          /* prompt/payload (bitwise OR of APPCTX_CLI_ST1_*) for stats, session error for peers */
	struct buffer *chunk;       /* used to store unfinished commands */
	unsigned int st2;          /* output state for stats, unused by peers  */
	struct applet *applet;     /* applet this context refers to */
	struct conn_stream *owner;
	struct cs_endpoint *endp;
	struct act_rule *rule;     /* rule associated with the applet. */
	int (*io_handler)(struct appctx *appctx);  /* used within the cli_io_handler when st0 = CLI_ST_CALLBACK */
	void (*io_release)(struct appctx *appctx);  /* used within the cli_io_handler when st0 = CLI_ST_CALLBACK,
	                                               if the command is terminated or the session released */
	int cli_severity_output;        /* used within the cli_io_handler to format severity output of informational feedback */
	int cli_level;              /* the level of CLI which can be lowered dynamically */
	struct buffer_wait buffer_wait; /* position in the list of objects waiting for a buffer */
	struct task *t;                  /* task associated to the applet */
	struct freq_ctr call_rate;       /* appctx call rate */
	struct list wait_entry;          /* entry in a list of waiters for an event (e.g. ring events) */

	/* This anonymous union is temporary for 2.6 to avoid a new API change
	 * after 2.6 while keeping the compatibility with pre-2.7 code.
	 * The pointer seen by application code is appctx->svcctx. In 2.7 the
	 * anonymous union will disappear and the struct "svc" will become
	 * svc_storage, which is never accessed directly by application code.
	 * The compatibility with the old appctx->ctx.* is preserved for now
	 * and this union will disappear in 2.7
	 */
	union {
		/* here we have the service's context (CLI command, applet, etc) */
		void *svcctx;                  /* pointer to a context used by the command, e.g. <storage> below */
		struct {
			void *shadow;          /* shadow of svcctx above, do not use! */
			char storage[APPLET_MAX_SVCCTX]; /* storage of svcctx above */
		} svc;                         /* generic storage for most commands */
		union {
			struct {
				int connected;
				struct xref xref; /* cross reference with the Lua object owner. */
				struct list wake_on_read;
				struct list wake_on_write;
				int die;
			} hlua_cosocket;                /* used by the Lua cosockets */
			struct {
				struct hlua *hlua;
				int flags;
				struct task *task;
			} hlua_apptcp;                  /* used by the Lua TCP services */
			struct {
				struct hlua *hlua;
				int left_bytes;         /* The max amount of bytes that we can read. */
				int flags;
				int status;
				const char *reason;
				struct task *task;
			} hlua_apphttp;                 /* used by the Lua HTTP services */
			struct {
				void *ptr;              /* private pointer for SPOE filter */
			} spoe;                         /* used by SPOE filter */
			struct {
				const char *msg;        /* pointer to a persistent message to be returned in CLI_ST_PRINT state */
				int severity;           /* severity of the message to be returned according to (syslog) rfc5424 */
				char *err;              /* pointer to a 'must free' message to be returned in CLI_ST_PRINT_FREE state */
				void *p0, *p1, *p2;     /* ...registered commands, initialized to 0 by the CLI before first... */
				size_t o0, o1;          /* ...invocation of the keyword parser, except for the list element which... */
				int i0, i1;             /* ...is initialized with LIST_INIT(). */
			} cli;                          /* context used by the CLI */
			struct {
				struct cache_entry *entry;  /* Entry to be sent from cache. */
				unsigned int sent;          /* The number of bytes already sent for this cache entry. */
				unsigned int offset;        /* start offset of remaining data relative to beginning of the next block */
				unsigned int rem_data;      /* Remaining bytes for the last data block (HTX only, 0 means process next block) */
				unsigned int send_notmodified:1;   /* In case of conditional request, we might want to send a "304 Not Modified"
	                                                            * response instead of the stored data. */
				unsigned int unused:31;
				struct shared_block *next;  /* The next block of data to be sent for this cache entry. */
			} cache;
		} ctx;					/* context-specific variables used by any applet */
	}; /* end of anon union */
};

#endif /* _HAPROXY_APPLET_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
