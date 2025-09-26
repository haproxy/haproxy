/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _HAPROXY_ECH_H
# define _HAPROXY_ECH_H
#ifdef USE_ECH

#include <openssl/ech.h>

int load_echkeys(SSL_CTX *ctx, char *dirname, int *loaded);

# endif /* USE_ECH */
#endif /* _HAPROXY_ECH_H */
