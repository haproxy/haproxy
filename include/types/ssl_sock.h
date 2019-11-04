/*
 * include/types/ssl_sock.h
 * SSL settings for listeners and servers
 *
 * Copyright (C) 2012 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#ifndef _TYPES_SSL_SOCK_H
#define _TYPES_SSL_SOCK_H
#ifdef USE_OPENSSL

#include <ebmbtree.h>

#include <common/hathreads.h>
#include <common/openssl-compat.h>

struct pkey_info {
	uint8_t sig;          /* TLSEXT_signature_[rsa,ecdsa,...] */
	uint16_t bits;        /* key size in bits */
};

struct sni_ctx {
	SSL_CTX *ctx;             /* context associated to the certificate */
	int order;                /* load order for the certificate */
	uint8_t neg:1;              /* reject if match */
	uint8_t wild:1;            /* wildcard sni */
	struct pkey_info kinfo;   /* pkey info */
	struct ssl_bind_conf *conf; /* ssl "bind" conf for the certificate */
	struct list by_ckch_inst; /* chained in ckch_inst's list of sni_ctx */
	struct ebmb_node name;    /* node holding the servername value */
};

struct tls_version_filter {
	uint16_t flags;     /* ssl options */
	uint8_t  min;      /* min TLS version */
	uint8_t  max;      /* max TLS version */
};

extern struct list tlskeys_reference;

struct tls_sess_key_128 {
	unsigned char name[16];
	unsigned char aes_key[16];
	unsigned char hmac_key[16];
} __attribute__((packed));

struct tls_sess_key_256 {
	unsigned char name[16];
	unsigned char aes_key[32];
	unsigned char hmac_key[32];
} __attribute__((packed));

union tls_sess_key{
	unsigned char name[16];
	struct tls_sess_key_128 key_128;
	struct tls_sess_key_256 key_256;
} __attribute__((packed));

struct tls_keys_ref {
	struct list list; /* Used to chain refs. */
	char *filename;
	int unique_id; /* Each pattern reference have unique id. */
	int refcount;  /* number of users of this tls_keys_ref. */
	union tls_sess_key *tlskeys;
	int tls_ticket_enc_index;
	int key_size_bits;
	__decl_hathreads(HA_RWLOCK_T lock); /* lock used to protect the ref */
};

/* shared ssl session */
struct sh_ssl_sess_hdr {
	struct ebmb_node key;
	unsigned char key_data[SSL_MAX_SSL_SESSION_ID_LENGTH];
};

/* This is used to preload the certifcate, private key
 * and Cert Chain of a file passed in via the crt
 * argument
 *
 * This way, we do not have to read the file multiple times
 */
struct cert_key_and_chain {
	X509 *cert;
	EVP_PKEY *key;
	STACK_OF(X509) *chain;
	DH *dh;
	struct buffer *sctl;
	struct buffer *ocsp_response;
	X509 *ocsp_issuer;
};

/*
 * this is used to store 1 to SSL_SOCK_NUM_KEYTYPES cert_key_and_chain and
 * metadata.
 */
struct ckch_store {
	struct cert_key_and_chain *ckch;
	int multi:1; /* is it a multi-cert bundle ? */
	int filters:1; /* one of the instances is using filters, TODO:remove this flag once filters are supported */
	struct list ckch_inst; /* list of ckch_inst which uses this ckch_node */
	struct ebmb_node node;
	char path[0];
};

/*
 * This structure describe a ckch instance. An instance is generated for each
 * bind_conf.  The instance contains a linked list of the sni ctx which uses
 * the ckch in this bind_conf.
 *
 * XXX: the instance may evolve to handle ssl_bind_conf instead of bind_conf.
 */
struct ckch_inst {
	struct bind_conf *bind_conf; /* pointer to the bind_conf that uses this ckch_inst */
	struct ssl_bind_conf *ssl_conf; /* pointer to the ssl_conf which is used by every sni_ctx of this inst */
	int is_default;      /* This instance is used as the default ctx for this bind_conf */
	struct list sni_ctx; /* list of sni_ctx using this ckch_inst */
	struct list by_ckchs; /* chained in ckch_store's list of ckch_inst */
};

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL

#define SSL_SOCK_POSSIBLE_KT_COMBOS (1<<(SSL_SOCK_NUM_KEYTYPES))

struct key_combo_ctx {
	SSL_CTX *ctx;
	int order;
};

/* Map used for processing multiple keypairs for a single purpose
 *
 * This maps CN/SNI name to certificate type
 */
struct sni_keytype {
	int keytypes;			  /* BITMASK for keytypes */
	struct ebmb_node name;    /* node holding the servername value */
};

#endif

#endif /* USE_OPENSSL */
#endif /* _TYPES_SSL_SOCK_H */
