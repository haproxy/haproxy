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

#ifndef SHSESS_MAX_FOOTER_LEN
#define SHSESS_MAX_FOOTER_LEN sizeof(uint32_t) \
				+ EVP_MAX_MD_SIZE
#endif

#ifndef SHSESS_MAX_DATA_LEN
#define SHSESS_MAX_DATA_LEN 512
#endif

#ifndef SHCTX_DEFAULT_SIZE
#define SHCTX_DEFAULT_SIZE 20000
#endif

#define SHSESS_MAX_ENCODED_LEN SSL_MAX_SSL_SESSION_ID_LENGTH \
				+ SHSESS_MAX_DATA_LEN \
				+ SHSESS_MAX_FOOTER_LEN



/* Callback called on a new session event:
 * session contains the sessionid zeros padded to SSL_MAX_SSL_SESSION_ID_LENGTH
 *                                               followed by ASN1 session encoding.
 * len is set to SSL_MAX_SSL_SESSION_ID_LENGTH + ASN1 session length
 * len is always less than SSL_MAX_SSL_SESSION_ID_LENGTH + SHSESS_MAX_DATA_LEN.
 * Remaining Bytes from len to SHSESS_MAX_ENCODED_LEN can be used to add a footer.
 * cdate is the creation date timestamp.
 */
void shsess_set_new_cbk(void (*func)(unsigned char *session, unsigned int len, long cdate));

/* Add a session into the cache,
 * session contains the sessionid zeros padded to SSL_MAX_SSL_SESSION_ID_LENGTH
 *                                             followed by ASN1 session encoding.
 * len is set to SSL_MAX_SSL_SESSION_ID_LENGTH + ASN1 data length.
 *            if len greater than SHSESS_MAX_ENCODED_LEN, session is not added.
 * if cdate not 0, on get events session creation date will be reset to cdate */
void shctx_sess_add(const unsigned char *session, unsigned int session_len, long cdate);

/* Allocate shared memory context.
 * size is maximum cached sessions.
 *      if set less or equal to 0, SHCTX_DEFAULT_SIZE is used.
 * Returns: -1 on alloc failure, size if it performs context alloc,
 * and 0 if cache is already allocated */
int shared_context_init(int size);

/* Set shared cache callbacks on an ssl context.
 * Set session cache mode to server and disable openssl internal cache.
 * Shared context MUST be firstly initialized */
void shared_context_set_cache(SSL_CTX *ctx);

#endif /* SHCTX_H */

