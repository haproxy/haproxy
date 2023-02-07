/*
 * include/haproxy/ssl_ocsp-t.h
 * SSL structures related to OCSP
 *
 * Copyright (C) 2022 Remi Tricot-Le Breton - rlebreton@haproxy.com
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

#ifndef _HAPROXY_SSL_OCSP_T_H
#define _HAPROXY_SSL_OCSP_T_H
#ifdef USE_OPENSSL

#include <import/ebtree-t.h>

#include <haproxy/buf-t.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_sock-t.h>

#ifndef OPENSSL_NO_OCSP
extern int ocsp_ex_index;
#endif

#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
/*
 * struct alignment works here such that the key.key is the same as key_data
 * Do not change the placement of key_data
 */
struct certificate_ocsp {
	struct ebmb_node key;
	unsigned char key_data[OCSP_MAX_CERTID_ASN1_LENGTH];
	unsigned int key_length;
	struct buffer response;
	int refcount;
	long expire;
	X509 *issuer;
	STACK_OF(X509) *chain;
	struct eb64_node next_update;	/* Key of items inserted in ocsp_update_tree (sorted by absolute date) */
	struct buffer *uri;	/* First OCSP URI contained in the corresponding certificate */
};

struct ocsp_cbk_arg {
	int is_single;
	int single_kt;
	union {
		struct certificate_ocsp *s_ocsp;
		/*
		 * m_ocsp will have multiple entries dependent on key type
		 * Entry 0 - DSA
		 * Entry 1 - ECDSA
		 * Entry 2 - RSA
		 */
		struct certificate_ocsp *m_ocsp[SSL_SOCK_NUM_KEYTYPES];
	};
};

extern struct eb_root cert_ocsp_tree;
extern struct eb_root ocsp_update_tree;

__decl_thread(extern HA_SPINLOCK_T ocsp_tree_lock);

#endif /* (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) */

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_OCSP_T_H */
