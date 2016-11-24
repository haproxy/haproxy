#ifndef _PROTO_HLUA_FCN_H
#define _PROTO_HLUA_FCN_H

int hlua_checkboolean(lua_State *L, int index);

void hlua_class_const_int(lua_State *L, const char *name, int value);
void hlua_class_const_str(lua_State *L, const char *name, const char *value);
void hlua_class_function(lua_State *L, const char *name, int (*function)(lua_State *L));
void *hlua_checkudata(lua_State *L, int ud, int class_ref);
int hlua_register_metatable(struct lua_State *L, char *name);
int hlua_fcn_post_init(lua_State *L);
int hlua_fcn_reg_core_fcn(lua_State *L);
int hlua_dump_object(lua_State *L);

#endif /* _PROTO_HLUA_FCN_H */
