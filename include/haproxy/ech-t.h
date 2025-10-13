/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _HAPROXY_ECH_T_H
# define _HAPROXY_ECH_T_H

#ifdef USE_ECH
#include <openssl/ssl.h>

struct show_ech_ctx {
	struct proxy * pp;
	int fd;
	SSL_CTX *specific_ctx;
	char *specific_name;
	enum {
		SHOW_ECH_FD = 0,
		SHOW_ECH_SPECIFIC,
	} state;                       /* phase of the current dump */
};
#endif

#endif
