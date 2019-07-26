#ifndef _TYPES_HLUA_H
#define _TYPES_HLUA_H

#ifdef USE_LUA

#include <lua.h>
#include <lauxlib.h>

#include <common/regex.h>
#include <common/xref.h>

#include <types/http_ana.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/stick_table.h>

#define CLASS_CORE         "Core"
#define CLASS_TXN          "TXN"
#define CLASS_FETCHES      "Fetches"
#define CLASS_CONVERTERS   "Converters"
#define CLASS_SOCKET       "Socket"
#define CLASS_CHANNEL      "Channel"
#define CLASS_HTTP         "HTTP"
#define CLASS_MAP          "Map"
#define CLASS_APPLET_TCP   "AppletTCP"
#define CLASS_APPLET_HTTP  "AppletHTTP"
#define CLASS_PROXY        "Proxy"
#define CLASS_SERVER       "Server"
#define CLASS_LISTENER     "Listener"
#define CLASS_REGEX        "Regex"
#define CLASS_STKTABLE     "StickTable"

struct stream;

#define HLUA_RUN       0x00000001
#define HLUA_CTRLYIELD 0x00000002
#define HLUA_WAKERESWR 0x00000004
#define HLUA_WAKEREQWR 0x00000008
#define HLUA_EXIT      0x00000010
#define HLUA_MUST_GC   0x00000020
#define HLUA_STOP      0x00000040

#define HLUA_F_AS_STRING    0x01
#define HLUA_F_MAY_USE_HTTP 0x02

#define HLUA_TXN_NOTERM   0x00000001
#define HLUA_TXN_HTTP_RDY 0x00000002 /* Set if the txn is HTTP ready for the defined direction */

#define HLUA_CONCAT_BLOCSZ 2048

enum hlua_exec {
	HLUA_E_OK = 0,
	HLUA_E_AGAIN,  /* LUA yield, must resume the stack execution later, when
	                  the associatedtask is waked. */
	HLUA_E_ETMOUT, /* Execution timeout */
	HLUA_E_NOMEM,  /* Out of memory error */
	HLUA_E_YIELD,  /* LUA code try to yield, and this is not allowed */
	HLUA_E_ERRMSG, /* LUA stack execution failed with a string error message
	                  in the top of stack. */
	HLUA_E_ERR,    /* LUA stack execution failed without error message. */
};

/* This struct is use for storing HAProxy parsers state
 * before executing some Lua code. The goal is we can
 * check and compare the parser state a the end of Lua
 * execution. If the state is changed by Lua towards
 * an unexpected state, we can abort the transaction.
 */
struct hlua_consistency {
	enum pr_mode mode;
	union {
		struct {
			int dir;
			enum h1_state state;
		} http;
	} data;
};

struct hlua {
	lua_State *T; /* The LUA stack. */
	int Tref; /* The reference of the stack in coroutine case.
	             -1 for the main lua stack. */
	int Mref; /* The reference of the memory context in coroutine case.
	             -1 if the memory context is not used. */
	int nargs; /* The number of arguments in the stack at the start of execution. */
	unsigned int flags; /* The current execution flags. */
	int wake_time; /* The lua wants to be waked at this time, or before. */
	unsigned int max_time; /* The max amount of execution time for an Lua process, in ms. */
	unsigned int start_time; /* The ms time when the Lua starts the last execution. */
	unsigned int run_time; /* Lua total execution time in ms. */
	struct task *task; /* The task associated with the lua stack execution.
	                      We must wake this task to continue the task execution */
	struct list com; /* The list head of the signals attached to this task. */
	struct ebpt_node node;
	struct hlua_consistency cons; /* Store data consistency check. */
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
	char *name;
	int function_ref;
	int nargs;
};

/* This struct is used with the structs:
 *  - http_req_rule
 *  - http_res_rule
 *  - tcp_rule
 * It contains the lua execution configuration.
 */
struct hlua_rule {
	struct hlua_function fcn;
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

/* This struc is used with sample fetches and sample converters. */
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

struct hlua_addr {
	union {
		struct {
			struct in_addr ip;
			struct in_addr mask;
		} v4;
		struct {
			struct in6_addr ip;
			struct in6_addr mask;
		} v6;
	} addr;
	int type;
};

#else /* USE_LUA */

/* Empty struct for compilation compatibility */
struct hlua { };
struct hlua_socket { };
struct hlua_rule { };

#endif /* USE_LUA */

#endif /* _TYPES_HLUA_H */
