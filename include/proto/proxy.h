/*
  include/proto/proxy.h
  This file defines function prototypes for proxy management.

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _PROTO_PROXY_H
#define _PROTO_PROXY_H

#include <common/config.h>
#include <common/time.h>
#include <types/proxy.h>

int start_proxies(int verbose);
void maintain_proxies(struct timeval *next);
void soft_stop(void);
void pause_proxy(struct proxy *p);
void pause_proxies(void);
void listen_proxies(void);

const char *proxy_cap_str(int cap);
const char *proxy_mode_str(int mode);
struct proxy *findproxy(const char *name, int mode, int cap);
int proxy_parse_timeout(const char **args, struct proxy *proxy,
			struct proxy *defpx, char *err, int errlen);

/*
 * This function returns a string containing the type of the proxy in a format
 * suitable for error messages, from its capabilities.
 */
static inline const char *proxy_type_str(struct proxy *proxy)
{
	return proxy_cap_str(proxy->cap);
}

#endif /* _PROTO_PROXY_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
