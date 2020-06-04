/*
 * include/haproxy/hlua_fcn.h
 * Lua user-level management functions
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

#ifndef _HAPROXY_HLUA_FCN_H
#define _HAPROXY_HLUA_FCN_H

#include <lua.h>

int hlua_checkboolean(lua_State *L, int index);

void hlua_class_const_int(lua_State *L, const char *name, int value);
void hlua_class_const_str(lua_State *L, const char *name, const char *value);
void hlua_class_function(lua_State *L, const char *name, int (*function)(lua_State *L));
void *hlua_checkudata(lua_State *L, int ud, int class_ref);
int hlua_register_metatable(struct lua_State *L, char *name);
int hlua_fcn_post_init(lua_State *L);
int hlua_fcn_reg_core_fcn(lua_State *L);
int hlua_dump_object(lua_State *L);

#endif /* _HAPROXY_HLUA_FCN_H */
