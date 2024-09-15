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
#include <import/cebtree.h>

/* flags used when setting/clearing variables */
#define VF_CREATEONLY       0x00000001   // do nothing if the variable already exists
#define VF_PERMANENT        0x00000002   // variables known to the config parser

#define VF_COND_IFEXISTS    0x00000004   // only set variable if it already exists
#define VF_COND_IFNOTEXISTS 0x00000008   // only set variable if it did not exist yet
#define VF_COND_IFEMPTY     0x00000010   // only set variable if sample is empty
#define VF_COND_IFNOTEMPTY  0x00000020   // only set variable if sample is not empty
#define VF_COND_IFSET       0x00000040   // only set variable if its type is not SMP_TYPE_ANY
#define VF_COND_IFNOTSET    0x00000080   // only set variable if its type is ANY
#define VF_COND_IFGT        0x00000100   // only set variable if its value is greater than the sample's
#define VF_COND_IFLT        0x00000200   // only set variable if its value is less than the sample's

enum vars_scope {
	SCOPE_SESS = 0,
	SCOPE_TXN,
	SCOPE_REQ,
	SCOPE_RES,
	SCOPE_PROC,
	SCOPE_CHECK,
};

#define VAR_NAME_ROOTS	4
struct vars {
	struct ceb_node *name_root[VAR_NAME_ROOTS];
	enum vars_scope scope;
	unsigned int size;
	__decl_thread(HA_RWLOCK_T rwlock);
};

#define VDF_PARENT_CTX       0x00000001   // Set if the variable is related to the parent stream

/* This struct describes a variable as found in an arg_data */
struct var_desc {
	uint64_t name_hash;
	enum vars_scope scope;
	uint flags; /*VDF_* */
};

struct var {
	struct ceb_node node; /* Used for chaining vars. */
	uint64_t name_hash;      /* XXH3() of the variable's name, must be just after node */
	uint flags;       // VF_*
	/* 32-bit hole here */
	struct sample_data data; /* data storage. */
};

#endif
