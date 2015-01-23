#ifndef _TYPES_HLUA_H
#define _TYPES_HLUA_H

#include <lua.h>

enum hlua_state {
	HLUA_STOP = 0,
	HLUA_RUN,
};

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
	enum hlua_state state; /* The current execution state. */
	struct task *task; /* The task associated with the lua stack execution.
	                      We must wake this task to continue the task execution */
	struct ebpt_node node;
};

#endif /* _TYPES_HLUA_H */
