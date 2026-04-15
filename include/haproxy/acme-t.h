/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _ACME_T_H_
#define _ACME_T_H_

#include <haproxy/acme_resolvers-t.h>
#include <haproxy/istbuf.h>
#include <haproxy/openssl-compat.h>

#if defined(HAVE_ACME)

#define ACME_RETRY 5

/* Readiness requirements for challenge */
#define ACME_RDY_NONE         0x00
#define ACME_RDY_CLI          0x01
#define ACME_RDY_DNS          0x02
#define ACME_RDY_DELAY        0x04
#define ACME_RDY_INITIAL_DNS  0x08

/* acme section configuration */
struct acme_cfg {
	char *filename;             /* config filename */
	int linenum;                /* config linenum */
	char *name;                 /* section name */
	int reuse_key;              /* do we need to renew the private key */
	int cond_ready;             /* ready condition */
	unsigned int dns_delay;     /* delay in seconds before re-triggering DNS resolution (default: 300) */
	unsigned int dns_timeout;   /* time after which the DNS check shouldn't be retried  (default: 600) */
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
	char *vars;                 /* variables put in the dpapi sink */
	char *provider;             /* DNS provider put in the dpapi sink */
	struct acme_cfg *next;
};

enum acme_st {
	ACME_RESOURCES = 0,
	ACME_NEWNONCE,
	ACME_CHKACCOUNT,
	ACME_NEWACCOUNT,
	ACME_NEWORDER,
	ACME_AUTH,
	ACME_INITIAL_RSLV_TRIGGER,   /* opportunistic DNS check avoid cond_ready steps */
	ACME_INITIAL_RSLV_READY,
	ACME_CLI_WAIT,               /* wait for the ACME_RDY_CLI */
	ACME_INITIAL_DELAY,
	ACME_RSLV_RETRY_DELAY,
	ACME_RSLV_TRIGGER,
	ACME_RSLV_READY,
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
       struct ist dns;    /* dns entry */
       struct ist auth;   /* auth URI */
       struct ist chall;  /* challenge URI */
       struct ist token;  /* token */
       int validated;     /* already validated */
       struct acme_rslv *rslv; /* acme dns-01 resolver */
       int ready;         /* is the challenge ready ? */
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
	unsigned int dnstasks;      /* number of DNS tasks running for this ctx */
	unsigned int dnsstarttime;  /* time at which we started the DNS checks */
	struct task *task;
	struct ebmb_node node;
	char name[VAR_ARRAY];
};

#define ACME_EV_SCHED              (1ULL <<  0)  /* scheduling wakeup */
#define ACME_EV_NEW                (1ULL <<  1)  /* new task */
#define ACME_EV_TASK               (1ULL <<  2)  /* Task handler */
#define ACME_EV_REQ                (1ULL <<  3)  /* HTTP Request */
#define ACME_EV_RES                (1ULL <<  4)  /* HTTP Response */

#define ACME_VERB_CLEAN    1
#define ACME_VERB_MINIMAL  2
#define ACME_VERB_SIMPLE   3
#define ACME_VERB_ADVANCED 4
#define ACME_VERB_COMPLETE 5

#endif /* ! HAVE_ACME */

#endif
