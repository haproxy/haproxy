/*
 * shctx.h - shared context management functions for SSL
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

#ifndef SHCTX_H
#define SHCTX_H
#include <openssl/ssl.h>
#include <stdint.h>

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

/* Allocate shared memory context.
 * <size> is the number of allocated blocks into cache (default 128 bytes)
 * A block is large enough to contain a classic session (without client cert)
 * If <size> is set less or equal to 0, ssl cache is disabled.
 * Set <use_shared_memory> to 1 to use a mapped shared memory instead
 * of private. (ignored if compiled with USE_PRIVATE_CACHE=1).
 * Returns: -1 on alloc failure, <size> if it performs context alloc,
 * and 0 if cache is already allocated.
 */
int shared_context_init(int size, int use_shared_memory);

/* Set shared cache callbacks on an ssl context.
 * Set session cache mode to server and disable openssl internal cache.
 * Shared context MUST be firstly initialized */
void shared_context_set_cache(SSL_CTX *ctx);

#endif /* SHCTX_H */

