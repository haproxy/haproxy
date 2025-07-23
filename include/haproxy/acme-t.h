/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _ACME_T_H_
#define _ACME_T_H_

#include <haproxy/istbuf.h>
#include <haproxy/openssl-compat.h>

#define ACME_RETRY 5

/* acme section configuration */
struct acme_cfg {
	char *filename;             /* config filename */
	int linenum;                /* config linenum */
	char *name;                 /* section name */
	char *directory;            /* directory URL */
	char *map;                  /* storage for tokens + thumbprint */
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

enum acme_st {
	ACME_RESOURCES = 0,
	ACME_NEWNONCE,
	ACME_CHKACCOUNT,
	ACME_NEWACCOUNT,
	ACME_NEWORDER,
	ACME_AUTH,
	ACME_CHALLENGE,
	ACME_CHKCHALLENGE,
	ACME_FINALIZE,
	ACME_CHKORDER,
	ACME_CERTIFICATE,
	ACME_END
};

enum http_st {
	ACME_HTTP_REQ,
	ACME_HTTP_RES,
};

struct acme_auth {
       struct ist auth;   /* auth URI */
       struct ist chall;  /* challenge URI */
       struct ist token;  /* token */
       void *next;
};

/* acme task context */
struct acme_ctx {
	enum acme_st state;
	enum http_st http_state;
	int retries;
	int retryafter;
	struct httpclient *hc;
	struct acme_cfg *cfg;
	struct ckch_store *store;
	struct {
		struct ist newNonce;
		struct ist newAccount;
		struct ist newOrder;
	} resources;
	struct ist nonce;
	struct ist kid;
	struct ist order;
	struct acme_auth *auths;
	struct acme_auth *next_auth;
	X509_REQ *req;
	struct ist finalize;
	struct ist certificate;
	struct mt_list el;
};
#endif
