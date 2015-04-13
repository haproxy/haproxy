/*
 * include/types/obj_type.h
 * This file declares some object types for use in various structures.
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

#ifndef _TYPES_OBJ_TYPE_H
#define _TYPES_OBJ_TYPE_H

/* The principle is to be able to change the type of a pointer by pointing
 * it directly to an object type. The object type indicates the format of the
 * structure holing the type, and this is used to retrieve the pointer to the
 * beginning of the structure. Doing so saves us from having to maintain both
 * a pointer and a type for elements such as connections which can point to
 * various types of objects.
 */

/* object types : these ones take the same space as a char */
enum obj_type {
	OBJ_TYPE_NONE = 0,     /* pointer is NULL by definition */
	OBJ_TYPE_LISTENER,     /* object is a struct listener */
	OBJ_TYPE_PROXY,        /* object is a struct proxy */
	OBJ_TYPE_SERVER,       /* object is a struct server */
	OBJ_TYPE_APPLET,       /* object is a struct applet */
	OBJ_TYPE_APPCTX,       /* object is a struct appctx */
	OBJ_TYPE_CONN,         /* object is a struct connection */
	OBJ_TYPE_ENTRIES       /* last one : number of entries */
} __attribute__((packed)) ;

#endif /* _TYPES_OBJ_TYPE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
