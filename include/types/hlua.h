#ifndef _TYPES_HLUA_H
#define _TYPES_HLUA_H

#ifdef USE_LUA

#include <lua.h>
#include <lauxlib.h>

#include <types/proxy.h>
#include <types/server.h>

#define CLASS_CORE     "Core"
#define CLASS_TXN      "TXN"
#define CLASS_FETCHES  "Fetches"
#define CLASS_CONVERTERS "Converters"
#define CLASS_SOCKET   "Socket"
#define CLASS_CHANNEL  "Channel"
#define CLASS_HTTP     "HTTP"
#define CLASS_MAP      "Map"

struct stream;

#define HLUA_RUN       0x00000001
#define HLUA_CTRLYIELD 0x00000002
#define HLUA_WAKERESWR 0x00000004
#define HLUA_WAKEREQWR 0x00000008

enum hlua_exec {
	HLUA_E_OK = 0,
	HLUA_E_AGAIN,  /* LUA yield, must resume the stack execution later, when
	                  the associatedtask is waked. */
	HLUA_E_ERRMSG, /* LUA stack execution failed with a string error message
	                  in the top of stack. */
	HLUA_E_ERR,    /* LUA stack execution failed without error message. */
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
	int expire; /* Lua execution must be stopped over this time. */
	struct task *task; /* The task associated with the lua stack execution.
	                      We must wake this task to continue the task execution */
	struct list com; /* The list head of the signals attached to this task. */
	struct ebpt_node node;
};

struct hlua_com {
	struct list purge_me; /* Part of the list of signals to be purged in the
	                         case of the LUA execution stack crash. */
	struct list wake_me; /* Part of list of signals to be targeted if an
	                        event occurs. */
	struct task *task; /* The task to be wake if an event occurs. */
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
};

/* This struc is used with sample fetches and sample converters. */
struct hlua_smp {
	struct stream *s;
	struct proxy *p;
	int stringsafe;
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
	struct stream *s; /* Stream used for socket I/O. */
	luaL_Buffer b; /* buffer used to prepare strings. */
};

#else /* USE_LUA */

/* Empty struct for compilation compatibility */
struct hlua { };
struct hlua_socket { };

#endif /* USE_LUA */

#endif /* _TYPES_HLUA_H */
