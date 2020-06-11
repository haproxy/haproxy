/*
 * include/haproxy/vars-t.h
 * Macros and structures definitions for variables.
 *
 * Copyright (C) 2015 Thierry FOURNIER <tfournier@arpalert.org>
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

#ifndef _HAPROXY_VARS_T_H
#define _HAPROXY_VARS_T_H

#include <haproxy/sample_data-t.h>
#include <haproxy/thread-t.h>

enum vars_scope {
	SCOPE_SESS = 0,
	SCOPE_TXN,
	SCOPE_REQ,
	SCOPE_RES,
	SCOPE_PROC,
	SCOPE_CHECK,
};

struct vars {
	struct list head;
	enum vars_scope scope;
	unsigned int size;
	__decl_thread(HA_RWLOCK_T rwlock);
};

/* This struct describes a variable. */
struct var_desc {
	const char *name; /* Contains the normalized variable name. */
	enum vars_scope scope;
};

struct var {
	struct list l; /* Used for chaining vars. */
	const char *name; /* Contains the variable name. */
	struct sample_data data; /* data storage. */
};

#endif
