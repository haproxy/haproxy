/*
  include/haproxy/defaults.h
  Miscellaneous default values.

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

#ifndef _HAPROXY_DEFAULTS_H
#define _HAPROXY_DEFAULTS_H


/* CONFIG_HAP_MEM_OPTIM
 * This enables use of memory pools instead of malloc()/free(). There
 * is no reason to disable it, except perhaps for rare debugging.
 */
#ifndef   CONFIG_HAP_NO_MEM_OPTIM
#  define CONFIG_HAP_MEM_OPTIM
#endif /* CONFIG_HAP_NO_MEM_OPTIM */

/*
 * BUFSIZE defines the size of a read and write buffer. It is the maximum
 * amount of bytes which can be stored by the proxy for each session. However,
 * when reading HTTP headers, the proxy needs some spare space to add or rewrite
 * headers if needed. The size of this spare is defined with MAXREWRITE. So it
 * is not possible to process headers longer than BUFSIZE-MAXREWRITE bytes. By
 * default, BUFSIZE=16384 bytes and MAXREWRITE=BUFSIZE/2, so the maximum length
 * of headers accepted is 8192 bytes, which is in line with Apache's limits.
 */
#ifndef BUFSIZE
#define BUFSIZE	        16384
#endif

// reserved buffer space for header rewriting
#ifndef MAXREWRITE
#define MAXREWRITE      (BUFSIZE / 2)
#endif

#define REQURI_LEN      1024
#define CAPTURE_LEN     64

// max # args on a configuration line
#define MAX_LINE_ARGS   40

// max # of added headers per request
#define MAX_NEWHDR      10

// max # of matches per regexp
#define	MAX_MATCH       10

// cookie delimitor in "prefix" mode. This character is inserted between the
// persistence cookie and the original value. The '~' is allowed by RFC2965,
// and should not be too common in server names.
#ifndef COOKIE_DELIM
#define COOKIE_DELIM    '~'
#endif

#define CONN_RETRIES    3

#define	CHK_CONNTIME    2000
#define	DEF_CHKINTR     2000
#define DEF_FALLTIME    3
#define DEF_RISETIME    2
#define DEF_CHECK_REQ   "OPTIONS / HTTP/1.0\r\n\r\n"

/* Default connections limit.
 *
 * A system limit can be enforced at build time in order to avoid using haproxy
 * beyond reasonable system limits. For this, just define SYSTEM_MAXCONN to the
 * absolute limit accepted by the system. If the configuration specifies a
 * higher value, it will be capped to SYSTEM_MAXCONN and a warning will be
 * emitted. The only way to override this limit will be to set it via the
 * command-line '-n' argument.
 */
#ifndef SYSTEM_MAXCONN
#define DEFAULT_MAXCONN 2000
#else
#define DEFAULT_MAXCONN SYSTEM_MAXCONN
#endif

#endif /* _HAPROXY_DEFAULTS_H */
