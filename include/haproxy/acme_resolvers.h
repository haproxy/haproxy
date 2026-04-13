/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _HAPROXY_ACME_RESOLVERS_H
#define _HAPROXY_ACME_RESOLVERS_H

#include <haproxy/openssl-compat.h>

#if defined(HAVE_ACME)

#include <haproxy/acme_resolvers-t.h>
#include <haproxy/acme-t.h>
#include <haproxy/resolvers-t.h>

struct acme_rslv *acme_rslv_start(struct acme_auth *auth, unsigned int *dnstasks, const char *challenge_type, char **errmsg);
void acme_rslv_free(struct acme_rslv *rslv);

#endif

#endif /* _HAPROXY_ACME_RESOLVERS_H */
