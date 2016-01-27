#ifndef _PROTO_HLUA_FCN_H
#define _PROTO_HLUA_FCN_H

void *hlua_checkudata(lua_State *L, int ud, int class_ref);
int hlua_fcn_reg_core_fcn(lua_State *L);

#endif /* _PROTO_HLUA_FCN_H */
