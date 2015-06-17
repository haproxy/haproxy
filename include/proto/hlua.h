#ifndef _PROTO_HLUA_H
#define _PROTO_HLUA_H

#ifdef USE_LUA

#include <lua.h>

#include <types/hlua.h>

/* The following macros are used to set flags. */
#define HLUA_SET_RUN(__hlua)         do {(__hlua)->flags |= HLUA_RUN;} while(0)
#define HLUA_CLR_RUN(__hlua)         do {(__hlua)->flags &= ~HLUA_RUN;} while(0)
#define HLUA_IS_RUNNING(__hlua)      ((__hlua)->flags & HLUA_RUN)
#define HLUA_SET_CTRLYIELD(__hlua)   do {(__hlua)->flags |= HLUA_CTRLYIELD;} while(0)
#define HLUA_CLR_CTRLYIELD(__hlua)   do {(__hlua)->flags &= ~HLUA_CTRLYIELD;} while(0)
#define HLUA_IS_CTRLYIELDING(__hlua) ((__hlua)->flags & HLUA_CTRLYIELD)
#define HLUA_SET_WAKERESWR(__hlua)   do {(__hlua)->flags |= HLUA_WAKERESWR;} while(0)
#define HLUA_CLR_WAKERESWR(__hlua)   do {(__hlua)->flags &= ~HLUA_WAKERESWR;} while(0)
#define HLUA_IS_WAKERESWR(__hlua)    ((__hlua)->flags & HLUA_WAKERESWR)
#define HLUA_SET_WAKEREQWR(__hlua)   do {(__hlua)->flags |= HLUA_WAKEREQWR;} while(0)
#define HLUA_CLR_WAKEREQWR(__hlua)   do {(__hlua)->flags &= ~HLUA_WAKEREQWR;} while(0)
#define HLUA_IS_WAKEREQWR(__hlua)    ((__hlua)->flags & HLUA_WAKEREQWR)

#define HLUA_INIT(__hlua) do { (__hlua)->T = 0; } while(0)

/* Lua HAProxy integration functions. */
void hlua_ctx_destroy(struct hlua *lua);
void hlua_init();
int hlua_post_init();

#else /* USE_LUA */

#define HLUA_IS_RUNNING(__hlua) 0

#define HLUA_INIT(__hlua)

/* Empty function for compilation without Lua. */
static inline void hlua_init() { }
static inline int hlua_post_init() { return 1; }
static inline void hlua_ctx_destroy(struct hlua *lua) { }

#endif /* USE_LUA */

#endif /* _PROTO_HLUA_H */
