/*
 * include/types/stick_table.h
 * Macros, variables and structures for stick tables management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2010 Willy Tarreau <w@1wt.eu>
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

#ifndef _TYPES_STICK_TABLE_H
#define _TYPES_STICK_TABLE_H

#include <sys/socket.h>
#include <netinet/in.h>

#include <ebtree.h>
#include <ebmbtree.h>
#include <eb32tree.h>
#include <common/memory.h>

/* stick table key types */
enum {
	STKTABLE_TYPE_IP = 0,     /* table key is ipv4 */
	STKTABLE_TYPE_INTEGER,    /* table key is unsigned 32bit integer */
	STKTABLE_TYPE_STRING,     /* table key is a null terminated string */
	STKTABLE_TYPES            /* Number of types, must always be last */
};

/* The types of extra data we can store in a stick table */
enum {
	STKTABLE_DATA_TYPES       /* Number of data types, must always be last */
};

/* stick_table extra data. This is mainly used for casting or size computation */
union stktable_data {
};

#define stktable_data_size(type) (sizeof(((union stktable_data*)0)->type))
#define stktable_data_cast(ptr, type) ((union stktable_data*)(ptr))->type

/* known data types */
struct stktable_data_type {
	const char *name; /* name of the data type */
	int data_length;  /* length of this type, or 0 if variable (eg: string) */
};

/* stick table key type flags */
#define STK_F_CUSTOM_KEYSIZE      0x00000001   /* this table's key size is configurable */

/* stick table keyword type */
struct stktable_type {
	const char *kw;           /* keyword string */
	int flags;                /* type flags */
	size_t default_size;      /* default key size */
};

/* Sticky session.
 * Any additional data related to the stuck session is installed *before*
 * stksess (with negative offsets). This allows us to run variable-sized
 * keys and variable-sized data without making use of intermediate pointers.
 */
struct stksess {
	int sid;                  /* id of server to use for this session */
	unsigned int expire;      /* session expiration date */
	struct eb32_node exp;     /* ebtree node used to hold the session in expiration tree */
	struct ebmb_node key;     /* ebtree node used to hold the session in table */
	/* WARNING! do not put anything after <keys>, it's used by the key */
};

/* stick table */
struct stktable {
	struct eb_root keys;      /* head of sticky session tree */
	struct eb_root exps;      /* head of sticky session expiration tree */
	struct pool_head *pool;   /* pool used to allocate sticky sessions */
	struct task *exp_task;    /* expiration task */
	unsigned long type;       /* type of table (determines key format) */
	size_t key_size;          /* size of a key, maximum size in case of string */
	unsigned int size;        /* maximum number of sticky sessions in table */
	unsigned int current;     /* number of sticky sessions currently in table */
	int nopurge;              /* if non-zero, don't purge sticky sessions when full */
	int exp_next;             /* next expiration date (ticks) */
	int expire;               /* time to live for sticky sessions (milliseconds) */
	int data_size;            /* the size of the data that is prepended *before* stksess */
	int data_ofs[STKTABLE_DATA_TYPES]; /* negative offsets of present data types, or 0 if absent */
};

struct stktable_data_type stktable_data_types[STKTABLE_DATA_TYPES];

/* stick table key data */
union stktable_key_data {
	struct in_addr ip;        /* used to store an ip key */
	uint32_t integer;         /* used to store an integer key */
	char buf[BUFSIZE];        /* used to store a null terminated string key */
};

/* stick table key */
struct stktable_key {
	void *key;                      /* pointer on key buffer */
	size_t key_len;                 /* data len to read in buff in case of null terminated string */
	union stktable_key_data data;   /* data */
};

#endif /* _TYPES_STICK_TABLE_H */

