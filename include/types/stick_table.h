/*
 * include/types/stick_table.h
 * Macros, variables and structures for stick tables management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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
#define STKTABLE_TYPE_IP	0 /* table key is ipv4 */
#define STKTABLE_TYPE_INTEGER	1 /* table key is unsigned 32bit integer */
#define STKTABLE_TYPE_STRING	2 /* table key is a null terminated string */

#define STKTABLE_TYPES	3  /* Increase this value if you add a type */

/* stick table type flags */
#define STKTABLE_TYPEFLAG_CUSTOMKEYSIZE 0x00000001 /* this table type maxsize is configurable */

/* stick table keyword type */
struct stktable_type {
	const char *kw;       /* keyword string */
	int flags;            /* type flags */
	size_t default_size;  /* default key size */
};

/* stuck session */
struct stksess {
	int sid;                  /* id of server to use for session */
	unsigned int expire;      /* session expiration date */
	struct eb32_node exps;    /* ebtree node used to hold the session in expiration tree */
	struct ebmb_node keys;    /* ebtree node used to hold the session in table */
};


/* stick table */
struct stktable {
	struct eb_root keys;      /* head of stuck session tree */
	struct eb_root exps;      /* head of stuck session expiration tree */
	struct pool_head *pool;   /* pool used to allocate stuck sessions */
	struct task *exp_task;    /* expiration task */
	unsigned long type;       /* type of table (determine key format) */
	size_t key_size;          /* size of a key, maximum size in case of string */
	unsigned int size;        /* maximum stuck session in table */
	unsigned int current;     /* number of stuck session in table */
	int nopurge;              /* 1 never purge stuck sessions */
	int exp_next;             /* next epiration date */
	int expire;               /* duration before expiration of stuck session */
};

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

