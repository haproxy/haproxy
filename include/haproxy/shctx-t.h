/*
 * include/haproxy/shctx-t.h - shared context management functions for SSL
 *
 * Copyright (C) 2011-2012 EXCELIANCE
 *
 * Author: Emeric Brun - emeric@exceliance.fr
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef __HAPROXY_SHCTX_T_H
#define __HAPROXY_SHCTX_T_H

#if !defined (USE_PRIVATE_CACHE) && defined(USE_PTHREAD_PSHARED)
#include <pthread.h>
#endif
#include <haproxy/list.h>

#ifndef SHSESS_BLOCK_MIN_SIZE
#define SHSESS_BLOCK_MIN_SIZE 128
#endif

#ifndef SHSESS_MAX_DATA_LEN
#define SHSESS_MAX_DATA_LEN 4096
#endif

#ifndef SHCTX_APPNAME
#define SHCTX_APPNAME "haproxy"
#endif

#define SHCTX_E_ALLOC_CACHE -1
#define SHCTX_E_INIT_LOCK   -2

#define SHCTX_F_REMOVING 0x1      /* Removing flag, does not accept new */

/* generic shctx struct */
struct shared_block {
	struct list list;
	unsigned int len;          /* data length for the row */
	unsigned int block_count;  /* number of blocks */
	unsigned int refcount;
	struct shared_block *last_reserved;
	struct shared_block *last_append;
	unsigned char data[VAR_ARRAY];
};

struct shared_context {
#ifndef USE_PRIVATE_CACHE
#ifdef USE_PTHREAD_PSHARED
	pthread_mutex_t mutex;
#else
	unsigned int waiters;
#endif
#endif
	struct list avail;  /* list for active and free blocks */
	struct list hot;     /* list for locked blocks */
	unsigned int nbav;  /* number of available blocks */
	unsigned int max_obj_size;   /* maximum object size (in bytes). */
	void (*free_block)(struct shared_block *first, struct shared_block *block);
	short int block_size;
	unsigned char data[VAR_ARRAY];
};

#endif /* __HAPROXY_SHCTX_T_H */
