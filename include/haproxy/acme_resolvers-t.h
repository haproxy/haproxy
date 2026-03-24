/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _HAPROXY_ACME_RESOLVERS_T_H
#define _HAPROXY_ACME_RESOLVERS_T_H

#include <haproxy/obj_type-t.h>
#include <haproxy/resolvers-t.h>

struct dns_counters;

/* TXT records for dns-01 */

struct acme_rslv {
	enum obj_type obj_type;                   /* OBJ_TYPE_ACME_RSLV */
	unsigned int *dnstasks;                   /* number of running DNS resolution for the same acme_task */
	char *hostname_dn;
	int hostname_dn_len;
	struct resolvers *resolvers;
	struct resolv_requester *requester;
	int result;                               /* RSLV_STATUS_* — NONE until done */
	int error_code;                           /* RSLV_RESP_* from the error callback */
	struct task *acme_task;                    /* ACME task to wake on completion, or NULL */
	struct ist txt;                           /* first TXT record found */
	int (*success_cb)(struct resolv_requester *, struct dns_counters *);
	int (*error_cb)(struct resolv_requester *, int);
};

#endif /* _HAPROXY_ACME_RESOLVERS_T_H */
