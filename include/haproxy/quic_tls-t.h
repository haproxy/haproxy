/*
 * include/types/quic_tls.h
 * This file provides definitions for QUIC-TLS.
 *
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

/* AEAD iv and secrete key lengths */
#define QUIC_TLS_IV_LEN     12 /* bytes */
#define QUIC_TLS_KEY_LEN    32 /* bytes */
#define QUIC_TLS_SECRET_LEN 64 /* bytes */
/* The ciphersuites for AEAD QUIC-TLS have 16-bytes authentication tags */
#define QUIC_TLS_TAG_LEN    16 /* bytes */

/* The TLS extensions for QUIC transport parameters */
#define TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS       0x0039
#define TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS_DRAFT 0xffa5

extern struct pool_head *pool_head_quic_tls_secret;
extern struct pool_head *pool_head_quic_tls_iv;
extern struct pool_head *pool_head_quic_tls_key;

#define QUIC_HKDF_KEY_LABEL_V1 "quic key"
#define QUIC_HKDF_IV_LABEL_V1  "quic iv"
#define QUIC_HKDF_HP_LABEL_V1  "quic hp"
#define QUIC_HKDF_KU_LABEL_V1  "quic ku"

#define QUIC_HKDF_KEY_LABEL_V2 "quicv2 key"
#define QUIC_HKDF_IV_LABEL_V2  "quicv2 iv"
#define QUIC_HKDF_HP_LABEL_V2  "quicv2 hp"
#define QUIC_HKDF_KU_LABEL_V2  "quicv2 ku"

#define QUIC_TLS_RETRY_KEY_DRAFT \
	"\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1"
#define QUIC_TLS_RETRY_NONCE_DRAFT \
	"\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c"
#define QUIC_TLS_RETRY_KEY_V1 \
	"\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e"
#define QUIC_TLS_RETRY_NONCE_V1 \
	"\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb"
#define QUIC_TLS_RETRY_KEY_V2 \
	"\x8f\xb4\xb0\x1b\x56\xac\x48\xe2\x60\xfb\xcb\xce\xad\x7c\xcc\x92"
#define QUIC_TLS_RETRY_NONCE_V2 \
	"\xd8\x69\x69\xbc\x2d\x7c\x6d\x99\x90\xef\xb0\x4a"

/* QUIC handshake states for both clients and servers. */
enum quic_handshake_state {
	QUIC_HS_ST_CLIENT_HANDSHAKE_FAILED,
	QUIC_HS_ST_SERVER_HANDSHAKE_FAILED,

	QUIC_HS_ST_CLIENT_INITIAL,
	QUIC_HS_ST_CLIENT_HANDSHAKE,

	QUIC_HS_ST_SERVER_INITIAL,
	QUIC_HS_ST_SERVER_HANDSHAKE,

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
	QUIC_TLS_PKTNS_HANDSHAKE,
	QUIC_TLS_PKTNS_01RTT,
	/* Please do not insert any value after this following one */
	QUIC_TLS_PKTNS_MAX,
};

extern unsigned char initial_salt[20];
extern const unsigned char initial_salt_draft_29[20];
extern const unsigned char initial_salt_v1[20];
extern const unsigned char initial_salt_v2[20];

/* Key phase used for Key Update */
struct quic_tls_kp {
	EVP_CIPHER_CTX *ctx;
	unsigned char *secret;
	size_t secretlen;
	unsigned char *iv;
	size_t ivlen;
	unsigned char *key;
	size_t keylen;
	uint64_t count;
	int64_t pn;
	unsigned char flags;
};

/* Key update phase bit */
#define QUIC_FL_TLS_KP_BIT_SET   (1 << 0)
/* Flag to be used when TLS secrets have been discarded. */
#define QUIC_FL_TLS_SECRETS_DCD  (1 << 1)

struct quic_tls_secrets {
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *aead;
	const EVP_MD *md;
	EVP_CIPHER_CTX *hp_ctx;
	const EVP_CIPHER *hp;
	unsigned char *secret;
	size_t secretlen;
	/* Header protection key.
	* Note: the header protection is applied after packet protection.
	* As the header belong to the data, its protection must be removed before removing
	* the packet protection.
	*/
	unsigned char hp_key[32];
	unsigned char *iv;
	size_t ivlen;
	unsigned char *key;
	size_t keylen;
	int64_t pn;
};

struct quic_tls_ctx {
	struct quic_tls_secrets rx;
	struct quic_tls_secrets tx;
	unsigned char flags;
};

#endif /* USE_QUIC */
#endif /* _TYPES_QUIC_TLS_H */

