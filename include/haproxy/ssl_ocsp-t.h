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

#define SSL_OCSP_UPDATE_DELAY_MAX 60*60 /* 1H */
#define SSL_OCSP_UPDATE_DELAY_MIN 5*60  /* 5 minutes */
#define SSL_OCSP_UPDATE_MARGIN 60   /* 1 minute */
#define SSL_OCSP_HTTP_ERR_REPLAY 60 /* 1 minute */

#if defined(HAVE_SSL_OCSP)
/*
 * struct alignment works here such that the key.key is the same as key_data
 * Do not change the placement of key_data
 */
struct certificate_ocsp {
	struct ebmb_node key;
	unsigned char key_data[OCSP_MAX_CERTID_ASN1_LENGTH];
	unsigned int key_length;
	int refcount_store;		/* Number of ckch_store that reference this certificate_ocsp */
	int refcount;			/* Number of actual references to this certificate_ocsp (SSL_CTXs mostly) */
	struct buffer response;
	long expire;
	X509 *issuer;
	STACK_OF(X509) *chain;
	struct eb64_node next_update;	/* Key of items inserted in ocsp_update_tree (sorted by absolute date) */
	struct buffer *uri;	/* First OCSP URI contained in the corresponding certificate */

	/* OCSP update stats */
	u64 last_update;		/* Time of last successful update */
	char *last_update_error;	/* Error message filled in case of update issue */
	unsigned int last_update_status;/* Status of the last OCSP update */
	unsigned int num_success;	/* Number of successful updates */
	unsigned int num_failure;	/* Number of failed updates */
	unsigned int fail_count:30;	/* Number of successive failures */
	unsigned int update_once:1;	/* Set if an entry should not be reinserted into te tree after update */
	unsigned int updating:1;	/* Set if an entry is already being updated */
	char path[VAR_ARRAY];
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
extern struct task *ocsp_update_task;

__decl_thread(extern HA_SPINLOCK_T ocsp_tree_lock);

#endif /*  HAVE_SSL_OCSP */

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_OCSP_T_H */
