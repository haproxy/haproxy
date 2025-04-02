/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _ACME_T_H_
#define _ACME_T_H_

#include <haproxy/openssl-compat.h>

/* acme section configuration */
struct acme_cfg {
	char *filename;             /* config filename */
	int linenum;                /* config linenum */
	char *name;                 /* section name */
	char *uri;                  /* directory URL */
	struct {
		char *contact;      /* email associated to account */
		char *file;         /* account key filename */
		EVP_PKEY *pkey;     /* account PKEY */
		char *thumbprint;   /* account PKEY JWS thumbprint */
	} account;

	struct {
		int type;                   /* EVP_PKEY_EC or EVP_PKEY_RSA */
		int bits;                   /* bits for RSA */
		int curves;                 /* NID of curves */
	} key;
	char *challenge;            /* HTTP-01, DNS-01, etc */
	struct acme_cfg *next;
};

#endif
