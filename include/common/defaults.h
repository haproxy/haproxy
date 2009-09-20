/*
  include/common/defaults.h
  Miscellaneous default values.

  Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu

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

#ifndef _COMMON_DEFAULTS_H
#define _COMMON_DEFAULTS_H

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

// maximum line size when parsing config
#ifndef LINESIZE
#define LINESIZE	2048
#endif

// max # of configuration files
#define MAX_CFG_FILES   10

// max # args on a configuration line
#define MAX_LINE_ARGS   64

// max # args on a stats socket
#define MAX_STATS_ARGS  16

// max # of added headers per request
#define MAX_NEWHDR      10

// max # of matches per regexp
#define	MAX_MATCH       10

// max # of headers in one HTTP request or response
// By default, about 100 headers per 8 kB.
#ifndef MAX_HTTP_HDR
#define MAX_HTTP_HDR    ((BUFSIZE+79)/80)
#endif

// max # of loops we can perform around a read() which succeeds.
// It's very frequent that the system returns a few TCP segments at a time.
#ifndef MAX_READ_POLL_LOOPS
#define MAX_READ_POLL_LOOPS 4
#endif

// minimum number of bytes read at once above which we don't try to read
// more, in order not to risk facing an EAGAIN. Most often, if we read
// at least 10 kB, we can consider that the system has tried to read a
// full buffer and got multiple segments (>1 MSS for jumbo frames, >7 MSS
// for normal frames) did not bother truncating the last segment.
#ifndef MIN_RECV_AT_ONCE_ENOUGH
#define MIN_RECV_AT_ONCE_ENOUGH (7*1448)
#endif

// same, but for writes. Generally, it's enough to write twice: one time for
// first half of the buffer, and a second time for the last half after a
// wrap-around.
#ifndef MAX_WRITE_POLL_LOOPS
#define MAX_WRITE_POLL_LOOPS 2
#endif

// the number of bytes returned by a read below which we will not try to
// poll the socket again. Generally, return values below the MSS are worthless
// to try again.
#ifndef MIN_RET_FOR_READ_LOOP
#define MIN_RET_FOR_READ_LOOP 1460
#endif

// the max number of events returned in one call to poll/epoll. Too small a
// value will cause lots of calls, and too high a value may cause high latency.
#ifndef MAX_POLL_EVENTS
#define MAX_POLL_EVENTS 200
#endif

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
#define DEF_SMTP_CHECK_REQ   "HELO localhost\r\n"

// X-Forwarded-For header default
#define DEF_XFORWARDFOR_HDR	"X-Forwarded-For"

// X-Original-To header default
#define DEF_XORIGINALTO_HDR	"X-Original-To"

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
#ifndef DEFAULT_MAXCONN
#define DEFAULT_MAXCONN 2000
#endif
#else
#undef  DEFAULT_MAXCONN
#define DEFAULT_MAXCONN SYSTEM_MAXCONN
#endif

/* Minimum check interval for spread health checks. Servers with intervals
 * greater than or equal to this value will have their checks spread apart
 * and will be considered when searching the minimal interval.
 * Others will be ignored for the minimal interval and will have their checks
 * scheduled on a different basis.
 */
#ifndef SRV_CHK_INTER_THRES
#define SRV_CHK_INTER_THRES 1000
#endif

/* Specifies the string used to report the version and release date on the
 * statistics page. May be defined to the empty string ("") to permanently
 * disable the feature.
 */
#ifndef STATS_VERSION_STRING
#define STATS_VERSION_STRING " version " HAPROXY_VERSION ", released " HAPROXY_DATE
#endif

/* Maximum signal queue size, and also number of different signals we can
 * handle.
 */
#ifndef MAX_SIGNAL
#define MAX_SIGNAL 256
#endif

/* Maximum host name length */
#ifndef MAX_HOSTNAME_LEN
#define MAX_HOSTNAME_LEN	32
#endif

#endif /* _COMMON_DEFAULTS_H */
