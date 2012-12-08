/*
 * include/proto/obj_type.h
 * This file contains function prototypes to manipulate object types
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_OBJ_TYPE_H
#define _PROTO_OBJ_TYPE_H

#include <common/config.h>
#include <common/memory.h>
#include <types/listener.h>
#include <types/obj_type.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/stream_interface.h>

static inline enum obj_type obj_type(enum obj_type *t)
{
	if (!t || *t > OBJ_TYPE_APPLET)
		return OBJ_TYPE_NONE;
	return *t;
}

static inline const char *obj_type_name(enum obj_type *t)
{
	switch (obj_type(t)) {
	case OBJ_TYPE_LISTENER: return "LISTENER";
	case OBJ_TYPE_PROXY:    return "PROXY";
	case OBJ_TYPE_SERVER:   return "SERVER";
	case OBJ_TYPE_APPLET:   return "APPLET";
	default:                return "NONE";
	}
}

static inline struct listener *objt_listener(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_LISTENER)
		return NULL;
	return container_of(t, struct listener, obj_type);
}

static inline struct proxy *objt_proxy(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_PROXY)
		return NULL;
	return container_of(t, struct proxy, obj_type);
}

static inline struct server *objt_server(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_SERVER)
		return NULL;
	return container_of(t, struct server, obj_type);
}

static inline struct si_applet *objt_applet(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_APPLET)
		return NULL;
	return container_of(t, struct si_applet, obj_type);
}

static inline void *obj_base_ptr(enum obj_type *t)
{
	switch (obj_type(t)) {
	case OBJ_TYPE_LISTENER: return objt_listener(t);
	case OBJ_TYPE_PROXY:    return objt_proxy(t);
	case OBJ_TYPE_SERVER:   return objt_server(t);
	case OBJ_TYPE_APPLET:   return objt_applet(t);
	default:                return NULL;
	}
}

#endif /* _PROTO_OBJ_TYPE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
