/*
  include/types/backend.h
  This file rassembles definitions for backends

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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

#ifndef _TYPES_BACKEND_H
#define _TYPES_BACKEND_H

#include <common/config.h>

/* bits for proxy->options */
#define PR_O_REDISP     0x00000001      /* allow reconnection to dispatch in case of errors */
#define PR_O_TRANSP     0x00000002      /* transparent mode : use original DEST as dispatch */
#define PR_O_COOK_RW    0x00000004      /* rewrite all direct cookies with the right serverid */
#define PR_O_COOK_IND   0x00000008      /* keep only indirect cookies */
#define PR_O_COOK_INS   0x00000010      /* insert cookies when not accessing a server directly */
#define PR_O_COOK_PFX   0x00000020      /* rewrite all cookies by prefixing the right serverid */
#define PR_O_COOK_ANY   (PR_O_COOK_RW | PR_O_COOK_IND | PR_O_COOK_INS | PR_O_COOK_PFX)
#define PR_O_BALANCE_RR 0x00000040      /* balance in round-robin mode */
#define	PR_O_KEEPALIVE  0x00000080      /* follow keep-alive sessions */
#define	PR_O_FWDFOR     0x00000100      /* insert x-forwarded-for with client address */
#define	PR_O_BIND_SRC   0x00000200      /* bind to a specific source address when connect()ing */
#define PR_O_NULLNOLOG  0x00000400      /* a connect without request will not be logged */
#define PR_O_COOK_NOC   0x00000800      /* add a 'Cache-control' header with the cookie */
#define PR_O_COOK_POST  0x00001000      /* don't insert cookies for requests other than a POST */
#define PR_O_HTTP_CHK   0x00002000      /* use HTTP 'OPTIONS' method to check server health */
#define PR_O_PERSIST    0x00004000      /* server persistence stays effective even when server is down */
#define PR_O_LOGASAP    0x00008000      /* log as soon as possible, without waiting for the session to complete */
#define PR_O_HTTP_CLOSE 0x00010000      /* force 'connection: close' in both directions */
#define PR_O_CHK_CACHE  0x00020000      /* require examination of cacheability of the 'set-cookie' field */
#define PR_O_TCP_CLI_KA 0x00040000      /* enable TCP keep-alive on client-side sessions */
#define PR_O_TCP_SRV_KA 0x00080000      /* enable TCP keep-alive on server-side sessions */
#define PR_O_USE_ALL_BK 0x00100000      /* load-balance between backup servers */
#define PR_O_FORCE_CLO  0x00200000      /* enforce the connection close immediately after server response */
#define PR_O_BALANCE_SH 0x00400000      /* balance on source IP hash */
#define PR_O_BALANCE    (PR_O_BALANCE_RR | PR_O_BALANCE_SH)
#define PR_O_ABRT_CLOSE 0x00800000      /* immediately abort request when client closes */
#define PR_O_SSL3_CHK   0x01000000      /* use SSLv3 CLIENT_HELLO packets for server health */

#define	PR_O_TPXY_ADDR  0x02000000	/* bind to this non-local address when connect()ing */
#define	PR_O_TPXY_CIP	0x04000000	/* bind to the client's IP address when connect()ing */
#define	PR_O_TPXY_CLI	0x06000000	/* bind to the client's IP+port when connect()ing */
#define	PR_O_TPXY_MASK	0x06000000	/* bind to a non-local address when connect()ing */
#define	PR_O_TCPSPLICE	0x08000000      /* delegate data transfer to linux kernel's tcp_splice */


#endif /* _TYPES_BACKEND_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
