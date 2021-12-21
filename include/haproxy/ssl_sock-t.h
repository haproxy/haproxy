/*
 * include/haproxy/ssl_sock-t.h
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

#ifndef _HAPROXY_SSL_SOCK_T_H
#define _HAPROXY_SSL_SOCK_T_H
#ifdef USE_OPENSSL

#include <import/ebtree-t.h>

#include <haproxy/buf-t.h>
#include <haproxy/connection-t.h> /* struct wait_event */
#include <haproxy/listener-t.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_ckch-t.h>
#include <haproxy/ssl_crtlist-t.h>
#include <haproxy/thread-t.h>

/* ***** READ THIS before adding code here! *****
 *
 * Due to API incompatibilities between multiple OpenSSL versions and their
 * derivatives, it's often tempting to add macros to (re-)define certain
 * symbols. Please do not do this here, and do it in common/openssl-compat.h
 * exclusively so that the whole code consistently uses the same macros.
 *
 * Whenever possible if a macro is missing in certain versions, it's better
 * to conditionally define it in openssl-compat.h than using lots of ifdefs.
 */

/* Warning, these are bits, not integers! */
#define SSL_SOCK_ST_FL_VERIFY_DONE  0x00000001
#define SSL_SOCK_ST_FL_16K_WBFSIZE  0x00000002
#define SSL_SOCK_SEND_UNLIMITED     0x00000004
#define SSL_SOCK_RECV_HEARTBEAT     0x00000008

/* bits 0xFFFF0000 are reserved to store verify errors */

/* Verify errors macros */
#define SSL_SOCK_CA_ERROR_TO_ST(e) (((e > 63) ? 63 : e) << (16))
#define SSL_SOCK_CAEDEPTH_TO_ST(d) (((d > 15) ? 15 : d) << (6+16))
#define SSL_SOCK_CRTERROR_TO_ST(e) (((e > 63) ? 63 : e) << (4+6+16))

#define SSL_SOCK_ST_TO_CA_ERROR(s) ((s >> (16)) & 63)
#define SSL_SOCK_ST_TO_CAEDEPTH(s) ((s >> (6+16)) & 15)
#define SSL_SOCK_ST_TO_CRTERROR(s) ((s >> (4+6+16)) & 63)

/* ssl_methods flags for ssl options */
#define MC_SSL_O_ALL            0x0000
#define MC_SSL_O_NO_SSLV3       0x0001	/* disable SSLv3 */
#define MC_SSL_O_NO_TLSV10      0x0002	/* disable TLSv10 */
#define MC_SSL_O_NO_TLSV11      0x0004	/* disable TLSv11 */
#define MC_SSL_O_NO_TLSV12      0x0008	/* disable TLSv12 */
#define MC_SSL_O_NO_TLSV13      0x0010	/* disable TLSv13 */

/* file to guess during file loading */
#define SSL_GF_NONE         0x00000000   /* Don't guess any file, only open the files specified in the configuration files */
#define SSL_GF_BUNDLE       0x00000001   /* try to open the bundles */
#define SSL_GF_SCTL         0x00000002   /* try to open the .sctl file */
#define SSL_GF_OCSP         0x00000004   /* try to open the .ocsp file */
#define SSL_GF_OCSP_ISSUER  0x00000008   /* try to open the .issuer file if an OCSP file was loaded */
#define SSL_GF_KEY          0x00000010   /* try to open the .key file to load a private key */

#define SSL_GF_ALL          (SSL_GF_BUNDLE|SSL_GF_SCTL|SSL_GF_OCSP|SSL_GF_OCSP_ISSUER|SSL_GF_KEY)

/* ssl_methods versions */
enum {
	CONF_TLSV_NONE = 0,
	CONF_TLSV_MIN  = 1,
	CONF_SSLV3     = 1,
	CONF_TLSV10    = 2,
	CONF_TLSV11    = 3,
	CONF_TLSV12    = 4,
	CONF_TLSV13    = 5,
	CONF_TLSV_MAX  = 5,
};

/* server and bind verify method, it uses a global value as default */
enum {
	SSL_SOCK_VERIFY_DEFAULT  = 0,
	SSL_SOCK_VERIFY_REQUIRED = 1,
	SSL_SOCK_VERIFY_OPTIONAL = 2,
	SSL_SOCK_VERIFY_NONE     = 3,
};

/* states of the CLI IO handler for 'set ssl cert' */
enum {
	SETCERT_ST_INIT = 0,
	SETCERT_ST_GEN,
	SETCERT_ST_INSERT,
	SETCERT_ST_FIN,
};

#if (HA_OPENSSL_VERSION_NUMBER < 0x1010000fL)
typedef enum { SET_CLIENT, SET_SERVER } set_context_func;
#else /* openssl >= 1.1.0 */
typedef enum { SET_MIN, SET_MAX } set_context_func;
#endif

struct methodVersions {
	int      option;
	uint16_t flag;
	void   (*ctx_set_version)(SSL_CTX *, set_context_func);
	void   (*ssl_set_version)(SSL *, set_context_func);
	const char *name;
};

struct pkey_info {
	uint8_t sig;          /* TLSEXT_signature_[rsa,ecdsa,...] */
	uint16_t bits;        /* key size in bits */
};

struct sni_ctx {
	SSL_CTX *ctx;             /* context associated to the certificate */
	int order;                /* load order for the certificate */
	unsigned int neg:1;       /* reject if match */
	unsigned int wild:1;      /* wildcard sni */
	struct pkey_info kinfo;   /* pkey info */
	struct ssl_bind_conf *conf; /* ptr to a crtlist's ssl_conf, must not be free from here */
	struct list by_ckch_inst; /* chained in ckch_inst's list of sni_ctx */
	struct ckch_inst *ckch_inst; /* instance used to create this sni_ctx */
	struct ebmb_node name;    /* node holding the servername value */
};

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
	__decl_thread(HA_RWLOCK_T lock); /* lock used to protect the ref */
};

/* shared ssl session */
struct sh_ssl_sess_hdr {
	struct ebmb_node key;
	unsigned char key_data[SSL_MAX_SSL_SESSION_ID_LENGTH];
};

/* issuer chain store with hash of Subject Key Identifier
   certificate/issuer matching is verify with X509_check_issued
*/
struct issuer_chain {
	struct eb64_node node;
	STACK_OF(X509) *chain;
	char *path;
};

struct connection;

typedef void (*ssl_sock_msg_callback_func)(struct connection *conn,
	int write_p, int version, int content_type,
	const void *buf, size_t len, SSL *ssl);

/* This structure contains a function pointer <func> that is called
 * when observing received or sent SSL/TLS protocol messages, such as
 * handshake messages or other events that can occur during processing.
 */
struct ssl_sock_msg_callback {
	ssl_sock_msg_callback_func func;
	struct list list;    /* list of registered callbacks */
};

/* This memory pool is used for capturing clienthello parameters. */
struct ssl_capture {
	ullong xxh64;
	ushort protocol_version;
	ushort ciphersuite_len;
	ushort extensions_len;
	ushort ec_len;
	uint ciphersuite_offset;
	uint extensions_offset;
	uint ec_offset;
	uint ec_formats_offset;
	uchar ec_formats_len;
	char data[VAR_ARRAY];
};

#ifdef HAVE_SSL_KEYLOG
#define SSL_KEYLOG_MAX_SECRET_SIZE 129

struct ssl_keylog {
	/*
	 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
	 */
	char *client_random;

	/* TLS 1.3 */
	char *client_early_traffic_secret;
	char *client_handshake_traffic_secret;
	char *server_handshake_traffic_secret;
	char *client_traffic_secret_0;
	char *server_traffic_secret_0;
	char *exporter_secret;
	char *early_exporter_secret;
};
#endif

struct ssl_sock_ctx {
	struct connection *conn;
	SSL *ssl;
	BIO *bio;
	const struct xprt_ops *xprt;
	void *xprt_ctx;
	struct wait_event wait_event;
	struct wait_event *subs;
	int xprt_st;                  /* transport layer state, initialized to zero */
	unsigned long error_code;     /* last error code of the error stack */
	struct buffer early_buf;      /* buffer to store the early data received */
	int sent_early_data;          /* Amount of early data we sent so far */

#ifdef USE_QUIC
	struct quic_conn *qc;
#endif
};

struct global_ssl {
	char *crt_base;             /* base directory path for certificates */
	char *ca_base;              /* base directory path for CAs and CRLs */
	char *issuers_chain_path;   /* from "issuers-chain-path" */
	int  skip_self_issued_ca;

	int  async;                 /* whether we use ssl async mode */

	char *listen_default_ciphers;
	char *connect_default_ciphers;
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	char *listen_default_ciphersuites;
	char *connect_default_ciphersuites;
#endif
#if defined(SSL_CTX_set1_curves_list)
	char *listen_default_curves;
#endif
	int listen_default_ssloptions;
	int connect_default_ssloptions;
	struct tls_version_filter listen_default_sslmethods;
	struct tls_version_filter connect_default_sslmethods;

	int private_cache; /* Force to use a private session cache even if nbproc > 1 */
	unsigned int life_time;   /* SSL session lifetime in seconds */
	unsigned int max_record; /* SSL max record size */
	unsigned int default_dh_param; /* SSL maximum DH parameter size */
	int ctx_cache; /* max number of entries in the ssl_ctx cache. */
	int capture_buffer_size; /* Size of the capture buffer. */
	int keylog; /* activate keylog  */
	int extra_files; /* which files not defined in the configuration file are we looking for */
	int extra_files_noext; /* whether we remove the extension when looking up a extra file */
};

/* The order here matters for picking a default context,
 * keep the most common keytype at the bottom of the list
 */
extern const char *SSL_SOCK_KEYTYPE_NAMES[];

#define SSL_SOCK_NUM_KEYTYPES 3

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_SOCK_T_H */
