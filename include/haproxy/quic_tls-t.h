/*
 * include/types/quic_tls.h
 * This file provides definitions for QUIC-TLS.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _TYPES_QUIC_TLS_H
#define _TYPES_QUIC_TLS_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <openssl/evp.h>

/* It seems TLS 1.3 ciphersuites macros differ between openssl and boringssl */

#if defined(OPENSSL_IS_BORINGSSL)
#if !defined(TLS1_3_CK_AES_128_GCM_SHA256)
#define TLS1_3_CK_AES_128_GCM_SHA256       TLS1_CK_AES_128_GCM_SHA256
#endif
#if !defined(TLS1_3_CK_AES_256_GCM_SHA384)
#define TLS1_3_CK_AES_256_GCM_SHA384       TLS1_CK_AES_256_GCM_SHA384
#endif
#if !defined(TLS1_3_CK_CHACHA20_POLY1305_SHA256)
#define TLS1_3_CK_CHACHA20_POLY1305_SHA256 TLS1_CK_CHACHA20_POLY1305_SHA256
#endif
#if !defined(TLS1_3_CK_AES_128_CCM_SHA256)
/* Note that TLS1_CK_AES_128_CCM_SHA256 is not defined in boringssl */
#define TLS1_3_CK_AES_128_CCM_SHA256       0x03001304
#endif
#endif

/* The TLS extension (enum) for QUIC transport parameters */
#define TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS 0xffa5

/* QUIC handshake states for both clients and servers. */
enum quic_handshake_state {
	QUIC_HS_ST_CLIENT_INITIAL,
	QUIC_HS_ST_CLIENT_HANDSHAKE,
	QUIC_HS_ST_CLIENT_HANDSHAKE_FAILED,

	QUIC_HS_ST_SERVER_INITIAL,
	QUIC_HS_ST_SERVER_HANDSHAKE,
	QUIC_HS_ST_SERVER_HANDSHAKE_FAILED,

	/* Common to servers and clients */
	QUIC_HS_ST_COMPLETE,
	QUIC_HS_ST_CONFIRMED,
};

/* QUIC TLS level encryption */
enum quic_tls_enc_level {
	QUIC_TLS_ENC_LEVEL_NONE = -1,
	QUIC_TLS_ENC_LEVEL_INITIAL,
	QUIC_TLS_ENC_LEVEL_EARLY_DATA,
	QUIC_TLS_ENC_LEVEL_HANDSHAKE,
	QUIC_TLS_ENC_LEVEL_APP,
	/* Please do not insert any value after this following one */
	QUIC_TLS_ENC_LEVEL_MAX,
};

/* QUIC packet number spaces */
enum quic_tls_pktns {
	QUIC_TLS_PKTNS_INITIAL,
	QUIC_TLS_PKTNS_01RTT,
	QUIC_TLS_PKTNS_HANDSHAKE,
	/* Please do not insert any value after this following one */
	QUIC_TLS_PKTNS_MAX,
};

/* The ciphersuites for AEAD QUIC-TLS have 16-bytes authentication tag */
#define QUIC_TLS_TAG_LEN             16

extern unsigned char initial_salt[20];

/* Flag to be used when TLS secrets have been set. */
#define QUIC_FL_TLS_SECRETS_SET  (1 << 0)
/* Flag to be used when TLS secrets have been discarded. */
#define QUIC_FL_TLS_SECRETS_DCD  (1 << 1)

struct quic_tls_secrets {
	const EVP_CIPHER *aead;
	const EVP_MD *md;
	const EVP_CIPHER *hp;
	unsigned char key[32];
	unsigned char iv[12];
	/* Header protection key.
	* Note: the header protection is applied after packet protection.
	* As the header belong to the data, its protection must be removed before removing
	* the packet protection.
	*/
	unsigned char hp_key[32];
	char flags;
};

struct quic_tls_ctx {
	struct quic_tls_secrets rx;
	struct quic_tls_secrets tx;
};

#endif /* USE_QUIC */
#endif /* _TYPES_QUIC_TLS_H */

