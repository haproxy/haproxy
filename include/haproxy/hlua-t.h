/*
 * include/haproxy/hlua-t.h
 * Lua core types definitions
 *
 * Copyright (C) 2015-2016 Thierry Fournier <tfournier@arpalert.org>
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

#ifndef _HAPROXY_HLUA_T_H
#define _HAPROXY_HLUA_T_H

#ifdef USE_LUA

#include <lua.h>
#include <lauxlib.h>
#include <stdint.h>

#include <import/ebtree-t.h>

#include <haproxy/proxy-t.h>
#include <haproxy/regex-t.h>
#include <haproxy/server-t.h>
#include <haproxy/stick_table-t.h>
#include <haproxy/xref-t.h>
#include <haproxy/event_hdl-t.h>
#include <haproxy/pattern-t.h>

#define CLASS_CORE         "Core"
#define CLASS_TXN          "TXN"
#define CLASS_FETCHES      "Fetches"
#define CLASS_CONVERTERS   "Converters"
#define CLASS_SOCKET       "Socket"
#define CLASS_CHANNEL      "Channel"
#define CLASS_HTTP         "HTTP"
#define CLASS_HTTP_MSG     "HTTPMessage"
#define CLASS_HTTPCLIENT   "HTTPClient"
#define CLASS_MAP          "Map"
#define CLASS_APPLET_TCP   "AppletTCP"
#define CLASS_APPLET_HTTP  "AppletHTTP"
#define CLASS_PROXY        "Proxy"
#define CLASS_SERVER       "Server"
#define CLASS_LISTENER     "Listener"
#define CLASS_EVENT_SUB    "EventSub"
#define CLASS_PATREF       "Patref"
#define CLASS_REGEX        "Regex"
#define CLASS_STKTABLE     "StickTable"
#define CLASS_CERTCACHE    "CertCache"
#define CLASS_PROXY_LIST   "ProxyList"
#define CLASS_SERVER_LIST  "ServerList"

struct stream;

#define HLUA_RUN       0x00000001
#define HLUA_CTRLYIELD 0x00000002
#define HLUA_WAKERESWR 0x00000004
#define HLUA_WAKEREQWR 0x00000008
#define HLUA_EXIT      0x00000010
#define HLUA_NOYIELD   0x00000020
#define HLUA_BUSY      0x00000040

#define HLUA_F_AS_STRING    0x01
#define HLUA_F_MAY_USE_HTTP 0x02

/* HLUA TXN flags */
#define HLUA_TXN_NOTERM   0x00000001
/* 0x00000002 .. 0x00000008 unused */

/* The execution context (enum), bits values from 0x00000010 to
 * 0x00000030. These flags are mutually exclusives. Only one must be set at a
 * time.
 */
#define HLUA_TXN_SMP_NONE 0x00000000 /* No specific execution context */
#define HLUA_TXN_SMP_CTX  0x00000010 /* Executed from a sample fecth context */
#define HLUA_TXN_ACT_CTX  0x00000020 /* Executed from a action context */
#define HLUA_TXN_FLT_CTX  0x00000030 /* Executed from a filter context */
#define HLUA_TXN_CTX_MASK 0x00000030 /* Mask to get the execution context */


#define HLUA_CONCAT_BLOCSZ 2048

enum hlua_exec {
	HLUA_E_OK = 0,
	HLUA_E_AGAIN,  /* LUA yield, must resume the stack execution later, when
	                  the associatedtask is waked. */
	HLUA_E_ETMOUT, /* Execution timeout */
	HLUA_E_BTMOUT, /* Burst timeout */
	HLUA_E_NOMEM,  /* Out of memory error */
	HLUA_E_YIELD,  /* LUA code try to yield, and this is not allowed */
	HLUA_E_ERRMSG, /* LUA stack execution failed with a string error message
	                  in the top of stack. */
	HLUA_E_ERR,    /* LUA stack execution failed without error message. */
};

struct hlua_timer {
	uint32_t start;      /* cpu time in ms when the timer was started */
	uint32_t burst;      /* execution time for the current call in ms */
	uint32_t cumulative; /* cumulative execution time for the coroutine in ms */
	uint32_t max;        /* max (cumulative) execution time for the coroutine in ms */
};

struct hlua {
	lua_State *T; /* The LUA stack. */
	int state_id; /* contains the lua state id. 0 is common state, 1 to n are per-thread states.*/
	int Tref; /* The reference of the stack in coroutine case.
	             -1 for the main lua stack. */
	int Mref; /* The reference of the memory context in coroutine case.
	             -1 if the memory context is not used. */
	int nargs; /* The number of arguments in the stack at the start of execution. */
	unsigned int flags; /* The current execution flags. */
	int wake_time; /* The lua wants to be waked at this time, or before. (ticks) */
	struct hlua_timer timer; /* lua multipurpose timer */
	struct task *task; /* The task associated with the lua stack execution.
	                      We must wake this task to continue the task execution */
	struct list com; /* The list head of the signals attached to this task. */
	struct mt_list hc_list;  /* list of httpclient associated to this lua task */
	struct ebpt_node node;
	int gc_count;  /* number of items which need a GC */
};

/* This is a part of the list containing references to functions
 * called at the initialisation time.
 */
struct hlua_init_function {
	struct list l;
	int function_ref;
};

/* This struct contains the lua data used to bind
 * Lua function on HAProxy hook like sample-fetches
 * or actions.
 */
struct hlua_function {
	struct list l;
	char *name;
	int function_ref[MAX_THREADS + 1];
	int nargs;
};

/* This struct is used with the structs:
 *  - http_req_rule
 *  - http_res_rule
 *  - tcp_rule
 * It contains the lua execution configuration.
 */
struct hlua_rule {
	struct hlua_function *fcn;
	char **args;
};

/* This struct contains the pointer provided on the most
 * of internal HAProxy calls during the processing of
 * rules, converters and sample-fetches. This struct is
 * associated with the lua object called "TXN".
 */
struct hlua_txn {
	struct stream *s;
	struct proxy *p;
	int dir;                /* SMP_OPT_DIR_{REQ,RES} */
	int flags;
};

/* This struct contains the applet context. */
struct hlua_appctx {
	struct appctx *appctx;
	luaL_Buffer b; /* buffer used to prepare strings. */
	struct hlua_txn htxn;
};

/* This struct is used with sample fetches and sample converters. */
struct hlua_smp {
	struct stream *s;
	struct proxy *p;
	unsigned int flags;     /* LUA_F_OPT_* */
	int dir;                /* SMP_OPT_DIR_{REQ,RES} */
};

/* This struct contains data used with sleep functions. */
struct hlua_sleep {
	struct task *task; /* task associated with sleep. */
	struct list com; /* list of signal to wake at the end of sleep. */
	unsigned int wakeup_ms; /* hour to wakeup. */
};

/* This struct is used to create coprocess doing TCP or
 * SSL I/O. It uses a fake stream.
 */
struct hlua_socket {
	struct xref xref; /* cross reference with the stream used for socket I/O. */
	luaL_Buffer b; /* buffer used to prepare strings. */
	unsigned long tid; /* Store the thread id which creates the socket. */
};

struct hlua_concat {
	int size;
	int len;
};

/* This struct is used to store the httpclient */
struct hlua_httpclient {
	struct httpclient *hc; /* ptr to the httpclient instance */
	size_t sent; /* payload sent */
	luaL_Buffer b; /* buffer used to prepare strings. */
	struct mt_list by_hlua; /* linked in the current hlua task */
};

struct hlua_proxy_list {
	char capabilities;
};

struct hlua_proxy_list_iterator_context {
	struct proxy *next;
	char capabilities;
};

struct hlua_server_list {
	struct proxy *px;
};

struct hlua_server_list_iterator_context {
	struct watcher srv_watch; /* watcher to automatically update next pointer
	                           * on server deletion
	                           */
	struct server *next;      /* next server in list */
	struct proxy *px;         /* to retrieve first server */
};

#define HLUA_PATREF_FL_NONE    0x00
#define HLUA_PATREF_FL_GEN     0x01 /* patref update backed by specific subset, check curr_gen */

/* pat_ref struct wrapper for lua */
struct hlua_patref {
	/* no need for lock-protecting the struct, it is not meant to
	 * be used by parallel lua contexts
	 */
	struct pat_ref *ptr;
	uint16_t flags; /* HLUA_PATREF_FL_* */
	unsigned int curr_gen; /* relevant if HLUA_PATREF_FL_GEN is set */
};

struct hlua_patref_iterator_context {
	struct hlua_patref *ref;
	struct bref bref;       /* back-reference from the pat_ref_elt being accessed
	                         * during listing */
};

#else /* USE_LUA */
/************************ For use when Lua is disabled ********************/

/* Empty struct for compilation compatibility */
struct hlua { };
struct hlua_socket { };
struct hlua_rule { };

#endif /* USE_LUA */

#endif /* _HAPROXY_HLUA_T_H */
