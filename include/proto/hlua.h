#ifndef _PROTO_HLUA_H
#define _PROTO_HLUA_H

#ifdef USE_LUA

#include <lua.h>

#include <types/hlua.h>

#define HLUA_INIT(__hlua) do { (__hlua)->T = 0; } while(0)

/* Lua HAProxy integration functions. */
void hlua_ctx_destroy(struct hlua *lua);
void hlua_init();
int hlua_post_init();

#else /* USE_LUA */

#define HLUA_INIT(__hlua)

/* Empty function for compilation without Lua. */
static inline void hlua_init() { }
static inline int hlua_post_init() { return 1; }
static inline void hlua_ctx_destroy() { }

#endif /* USE_LUA */

#endif /* _PROTO_HLUA_H */
