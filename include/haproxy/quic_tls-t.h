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

#include <haproxy/openssl-compat.h>
#if defined(OPENSSL_IS_AWSLC)
#include <openssl/chacha.h>
#endif
#include <openssl/evp.h>

#include <import/ebtree.h>

#include <haproxy/buf-t.h>
#include <haproxy/ncbuf-t.h>
#include <haproxy/quic_ack-t.h>

/* Use EVP_CIPHER or EVP_AEAD API depending on the library */
#if defined(OPENSSL_IS_AWSLC)

# define QUIC_AEAD_API

# define QUIC_AEAD            EVP_AEAD
# define QUIC_AEAD_CTX        EVP_AEAD_CTX

# define QUIC_AEAD_CTX_free   EVP_AEAD_CTX_free
# define QUIC_AEAD_key_length EVP_AEAD_key_length
# define QUIC_AEAD_iv_length  EVP_AEAD_nonce_length

# define EVP_CIPHER_CTX_CHACHA20 ((EVP_CIPHER_CTX *)EVP_aead_chacha20_poly1305())
# define EVP_CIPHER_CHACHA20     ((EVP_CIPHER*)EVP_aead_chacha20_poly1305())

#else

# define QUIC_AEAD            EVP_CIPHER
# define QUIC_AEAD_CTX        EVP_CIPHER_CTX

# define QUIC_AEAD_CTX_free   EVP_CIPHER_CTX_free
# define QUIC_AEAD_key_length EVP_CIPHER_key_length
# define QUIC_AEAD_iv_length  EVP_CIPHER_iv_length

#endif


/* It seems TLS 1.3 ciphersuites macros differ between openssl and boringssl */

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
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
#define QUIC_TLS_SECRET_LEN 48 /* bytes */
/* The ciphersuites for AEAD QUIC-TLS have 16-bytes authentication tags */
#define QUIC_TLS_TAG_LEN    16 /* bytes */

/* The TLS extensions for QUIC transport parameters */
#define TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS       0x0039
#define TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS_DRAFT 0xffa5

extern struct pool_head *pool_head_quic_pktns;
extern struct pool_head *pool_head_quic_enc_level;
extern struct pool_head *pool_head_quic_tls_ctx;
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

/* QUIC packet number space */
struct quic_pktns {
	struct list list;
	struct {
		/* List of frames to send. */
		struct list frms;
		/* Next packet number to use for transmissions. */
		int64_t next_pn;
		/* The packet which has been sent. */
		struct eb_root pkts;
		/* The time the most recent ack-eliciting packer was sent. */
		unsigned int time_of_last_eliciting;
		/* The time this packet number space has experienced packet loss. */
		unsigned int loss_time;
		/* Boolean to denote if we must send probe packet. */
		unsigned int pto_probe;
		/* In flight bytes for this packet number space. */
		size_t in_flight;
		/* The acknowledgement delay of the packet with the largest packet number */
		uint64_t ack_delay;
	} tx;
	struct {
		/* Largest packet number */
		int64_t largest_pn;
		/* Largest acked sent packet. */
		int64_t largest_acked_pn;
		struct quic_arngs arngs;
		unsigned int nb_aepkts_since_last_ack;
		/* The time the packet with the largest packet number was received */
		uint64_t largest_time_received;
	} rx;
	unsigned int flags;
};

/* Key phase used for Key Update */
struct quic_tls_kp {
	QUIC_AEAD_CTX *ctx;
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

struct quic_tls_secrets {
	QUIC_AEAD_CTX *ctx;
	const QUIC_AEAD *aead;
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
	/* Used only on the RX part to store the largest received packet number */
	int64_t pn;
};

struct quic_tls_ctx {
	struct quic_tls_secrets rx;
	struct quic_tls_secrets tx;
	unsigned char flags;
};

#define QUIC_CRYPTO_BUF_SHIFT  10
#define QUIC_CRYPTO_BUF_MASK   ((1UL << QUIC_CRYPTO_BUF_SHIFT) - 1)
/* The maximum allowed size of CRYPTO data buffer provided by the TLS stack. */
#define QUIC_CRYPTO_BUF_SZ    (1UL << QUIC_CRYPTO_BUF_SHIFT) /* 1 KB */

extern struct pool_head *pool_head_quic_crypto_buf;

/*
 * CRYPTO buffer struct.
 * Such buffers are used to send CRYPTO data.
 */
struct quic_crypto_buf {
	unsigned char data[QUIC_CRYPTO_BUF_SZ];
	size_t sz;
};

/* Crypto data stream (one by encryption level) */
struct quic_cstream {
	struct {
		uint64_t offset;       /* absolute current base offset of ncbuf */
		struct ncbuf ncbuf;    /* receive buffer - can handle out-of-order offset frames */
	} rx;
	struct {
		uint64_t offset;      /* last offset of data ready to be sent */
		uint64_t sent_offset; /* last offset sent by transport layer */
		struct buffer buf;    /* transmit buffer before sending via xprt */
	} tx;

	struct qc_stream_desc *desc;
};

struct quic_enc_level {
	struct list list;

	/* Attach point to register encryption level before sending. */
	struct list el_send;
	/* Pointer to the frames used by sending functions */
	struct list *send_frms;

	/* Encryption level, as defined by the TLS stack. */
	enum ssl_encryption_level_t level;
	/* TLS encryption context (AEAD only) */
	struct quic_tls_ctx tls_ctx;

	/* RX part */
	struct {
		/* The packets received by the listener I/O handler
		 * with header protection removed.
		 */
		struct eb_root pkts;
		/* List of QUIC packets with protected header. */
		struct list pqpkts;
	} rx;

	/* TX part */
	struct {
		struct {
			/* Array of CRYPTO data buffers */
			struct quic_crypto_buf **bufs;
			/* The number of element in use in the previous array. */
			size_t nb_buf;
			/* The total size of the CRYPTO data stored in the CRYPTO buffers. */
			size_t sz;
			/* The offset of the CRYPT0 data stream. */
			uint64_t offset;
		} crypto;
	} tx;

	/* Crypto data stream */
	struct quic_cstream *cstream;
	/* Packet number space */
	struct quic_pktns *pktns;
};

#endif /* USE_QUIC */
#endif /* _TYPES_QUIC_TLS_H */

