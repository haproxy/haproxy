/*
 * include/haproxy/ssl_ckch-t.h
 * ckch structures
 *
 * Copyright (C) 2020 HAProxy Technologies, William Lallemand <wlallemand@haproxy.com>
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


/* The ckch (cert key and chain) structures are a group of structures used to
 * cache and manipulate the certificates files loaded from the configuration
 * file and the CLI Every certificate change made in a SSL_CTX should be done
 * in these structures before being applied to a SSL_CTX.
 *
 * The complete architecture is described in doc/internals/ssl_cert.dia
 */


#ifndef _HAPROXY_SSL_CKCH_T_H
#define _HAPROXY_SSL_CKCH_T_H
#ifdef USE_OPENSSL

#include <import/ebmbtree.h>
#include <haproxy/buf-t.h>
#include <haproxy/openssl-compat.h>

/* This is used to preload the certificate, private key
 * and Cert Chain of a file passed in via the crt
 * argument
 *
 * This way, we do not have to read the file multiple times
 *
 * This structure is the base one, in the case of a multi-cert bundle, we
 *  allocate 1 structure per type.
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
 *
 * XXX: Once we remove the multi-cert bundle support, we could merge this structure
 * with the cert_key_and_chain one.
 */
struct ckch_store {
	struct cert_key_and_chain *ckch;
	struct list ckch_inst; /* list of ckch_inst which uses this ckch_node */
	struct list crtlist_entry; /* list of entries which use this store */
	struct ebmb_node node;
	char path[VAR_ARRAY];
};

/* forward declarations for ckch_inst */
struct ssl_bind_conf;
struct crtlist_entry;


/* Used to keep a list of all the instances using a specific cafile_entry.
 * It enables to link instances regardless of how they are using the CA file
 * (either via the ca-file, ca-verify-file or crl-file option). */
struct ckch_inst_link {
       struct ckch_inst *ckch_inst;
       struct list list;
};

/* Used to keep in a ckch instance a list of all the ckch_inst_link which
 * reference it. This way, when deleting a ckch_inst, we can ensure that no
 * dangling reference on it will remain. */
struct ckch_inst_link_ref {
       struct ckch_inst_link *link;
       struct list list;
};

/*
 * This structure describe a ckch instance. An instance is generated for each
 * bind_conf.  The instance contains a linked list of the sni ctx which uses
 * the ckch in this bind_conf.
 */
struct ckch_inst {
	struct bind_conf *bind_conf; /* pointer to the bind_conf that uses this ckch_inst */
	struct ssl_bind_conf *ssl_conf; /* pointer to the ssl_conf which is used by every sni_ctx of this inst */
	struct ckch_store *ckch_store; /* pointer to the store used to generate this inst */
	struct crtlist_entry *crtlist_entry; /* pointer to the crtlist_entry used, or NULL */
	struct server *server; /* pointer to the server if is_server_instance is set, NULL otherwise */
	SSL_CTX *ctx; /* pointer to the SSL context used by this instance */
	unsigned int is_default:1;      /* This instance is used as the default ctx for this bind_conf */
	unsigned int is_server_instance:1; /* This instance is used by a backend server */
	/* space for more flag there */
	struct list sni_ctx; /* list of sni_ctx using this ckch_inst */
	struct list by_ckchs; /* chained in ckch_store's list of ckch_inst */
	struct list by_crtlist_entry; /* chained in crtlist_entry list of inst */
	struct list cafile_link_refs; /* list of ckch_inst_link pointing to this instance */
};


/*
 * deduplicate cafile (and crlfile)
 */
struct cafile_entry {
	X509_STORE *ca_store;
	STACK_OF(X509_NAME) *ca_list;
	struct list ckch_inst_link; /* list of ckch_inst which use this CA file entry */
	struct ebmb_node node;
	char path[0];
};

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_CKCH_T_H */
