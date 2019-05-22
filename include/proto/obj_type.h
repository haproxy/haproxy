/*
 * include/proto/obj_type.h
 * This file contains function prototypes to manipulate object types
 *
 * Copyright (C) 2000-2013 Willy Tarreau - w@1wt.eu
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
#include <types/applet.h>
#include <types/connection.h>
#include <types/listener.h>
#include <types/obj_type.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/stream.h>
#include <types/stream_interface.h>

static inline enum obj_type obj_type(const enum obj_type *t)
{
	if (!t || *t >= OBJ_TYPE_ENTRIES)
		return OBJ_TYPE_NONE;
	return *t;
}

static inline const char *obj_type_name(const enum obj_type *t)
{
	switch (obj_type(t)) {
	case OBJ_TYPE_NONE:     return "NONE";
	case OBJ_TYPE_LISTENER: return "LISTENER";
	case OBJ_TYPE_PROXY:    return "PROXY";
	case OBJ_TYPE_SERVER:   return "SERVER";
	case OBJ_TYPE_APPLET:   return "APPLET";
	case OBJ_TYPE_APPCTX:   return "APPCTX";
	case OBJ_TYPE_CONN:     return "CONN";
	case OBJ_TYPE_SRVRQ:    return "SRVRQ";
	case OBJ_TYPE_CS:       return "CS";
	case OBJ_TYPE_STREAM:   return "STREAM";
	default:                return "!INVAL!";
	}
}

/* Note: for convenience, we provide two versions of each function :
 *   - __objt_<type> : converts the pointer without any control of its
 *     value nor type.
 *   - objt_<type> : same as above except that if the pointer is NULL
 *     or points to a non-matching type, NULL is returned instead.
 */

static inline struct listener *__objt_listener(enum obj_type *t)
{
	return container_of(t, struct listener, obj_type);
}

static inline struct listener *objt_listener(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_LISTENER)
		return NULL;
	return __objt_listener(t);
}

static inline struct proxy *__objt_proxy(enum obj_type *t)
{
	return container_of(t, struct proxy, obj_type);
}

static inline struct proxy *objt_proxy(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_PROXY)
		return NULL;
	return __objt_proxy(t);
}

static inline struct server *__objt_server(enum obj_type *t)
{
	return container_of(t, struct server, obj_type);
}

static inline struct server *objt_server(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_SERVER)
		return NULL;
	return __objt_server(t);
}

static inline struct applet *__objt_applet(enum obj_type *t)
{
	return container_of(t, struct applet, obj_type);
}

static inline struct applet *objt_applet(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_APPLET)
		return NULL;
	return __objt_applet(t);
}

static inline struct appctx *__objt_appctx(enum obj_type *t)
{
	return container_of(t, struct appctx, obj_type);
}

static inline struct appctx *objt_appctx(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_APPCTX)
		return NULL;
	return __objt_appctx(t);
}

static inline struct conn_stream *__objt_cs(enum obj_type *t)
{
	return (container_of(t, struct conn_stream, obj_type));
}

static inline struct conn_stream *objt_cs(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_CS)
		return NULL;
	return __objt_cs(t);
}

static inline struct connection *__objt_conn(enum obj_type *t)
{
	return container_of(t, struct connection, obj_type);
}

static inline struct connection *objt_conn(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_CONN)
		return NULL;
	return __objt_conn(t);
}

static inline struct dns_srvrq *__objt_dns_srvrq(enum obj_type *t)
{
	return container_of(t, struct dns_srvrq, obj_type);
}

static inline struct dns_srvrq *objt_dns_srvrq(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_SRVRQ)
		return NULL;
	return __objt_dns_srvrq(t);
}

static inline struct stream *__objt_stream(enum obj_type *t)
{
	return container_of(t, struct stream, obj_type);
}

static inline struct stream *objt_stream(enum obj_type *t)
{
	if (!t || *t != OBJ_TYPE_STREAM)
		return NULL;
	return __objt_stream(t);
}

static inline void *obj_base_ptr(enum obj_type *t)
{
	switch (obj_type(t)) {
	case OBJ_TYPE_NONE:     return NULL;
	case OBJ_TYPE_LISTENER: return __objt_listener(t);
	case OBJ_TYPE_PROXY:    return __objt_proxy(t);
	case OBJ_TYPE_SERVER:   return __objt_server(t);
	case OBJ_TYPE_APPLET:   return __objt_applet(t);
	case OBJ_TYPE_APPCTX:   return __objt_appctx(t);
	case OBJ_TYPE_CONN:     return __objt_conn(t);
	case OBJ_TYPE_SRVRQ:    return __objt_dns_srvrq(t);
	case OBJ_TYPE_CS:       return __objt_cs(t);
	default:                return t; // exact pointer for invalid case
	}
}

#endif /* _PROTO_OBJ_TYPE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
