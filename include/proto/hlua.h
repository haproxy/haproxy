#ifndef _PROTO_HLUA_H
#define _PROTO_HLUA_H

#include <lua.h>

#include <types/hlua.h>

/* Lua HAProxy integration functions. */
int hlua_ctx_init(struct hlua *lua, struct task *task);
void hlua_ctx_destroy(struct hlua *lua);
void hlua_init();
int hlua_post_init();

#endif /* _PROTO_HLUA_H */
