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

#include <openssl/ssl.h>
#include <ebmbtree.h>

struct sni_ctx {
	SSL_CTX *ctx;             /* context associated to the certificate */
	int order;                /* load order for the certificate */
	int neg;                  /* reject if match */
	struct ebmb_node name;    /* node holding the servername value */
};

extern struct list tlskeys_reference;

struct tls_sess_key {
	unsigned char name[16];
	unsigned char aes_key[16];
	unsigned char hmac_key[16];
} __attribute__((packed));

struct tls_keys_ref {
	struct list list; /* Used to chain refs. */
	char *filename;
	int unique_id; /* Each pattern reference have unique id. */
	struct tls_sess_key *tlskeys;
	int tls_ticket_enc_index;
};

#endif /* _TYPES_SSL_SOCK_H */
