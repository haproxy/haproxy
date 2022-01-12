/*
 * include/haproxy/defaults.h
 * Miscellaneous default values.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_DEFAULTS_H
#define _HAPROXY_DEFAULTS_H

/* MAX_THREADS defines the highest limit for the global nbthread value. It
 * defaults to the number of bits in a long integer when threads are enabled
 * but may be lowered to save resources on embedded systems.
*/
#ifndef USE_THREAD
/* threads disabled, 1 thread max, 1 group max (note: group ids start at 1) */
#define MAX_THREADS 1
#define MAX_THREADS_MASK 1

#define MAX_TGROUPS 1
#define MAX_THREADS_PER_GROUP 1

#else
/* threads enabled, max_threads defaults to long bits */
#ifndef MAX_THREADS
#define MAX_THREADS LONGBITS
#endif
#define MAX_THREADS_MASK (~0UL >> (LONGBITS - MAX_THREADS))

/* still limited to 1 group for now by default (note: group ids start at 1) */
#ifndef MAX_TGROUPS
#define MAX_TGROUPS 1
#endif
#define MAX_THREADS_PER_GROUP LONGBITS
#endif

/*
 * BUFSIZE defines the size of a read and write buffer. It is the maximum
 * amount of bytes which can be stored by the proxy for each stream. However,
 * when reading HTTP headers, the proxy needs some spare space to add or rewrite
 * headers if needed. The size of this spare is defined with MAXREWRITE. So it
 * is not possible to process headers longer than BUFSIZE-MAXREWRITE bytes. By
 * default, BUFSIZE=16384 bytes and MAXREWRITE=min(1024,BUFSIZE/2), so the
 * maximum length of headers accepted is 15360 bytes.
 */
#ifndef BUFSIZE
#define BUFSIZE	        16384
#endif

/* certain buffers may only be allocated for responses in order to avoid
 * deadlocks caused by request queuing. 2 buffers is the absolute minimum
 * acceptable to ensure that a request gaining access to a server can get
 * a response buffer even if it doesn't completely flush the request buffer.
 * The worst case is an applet making use of a request buffer that cannot
 * completely be sent while the server starts to respond, and all unreserved
 * buffers are allocated by request buffers from pending connections in the
 * queue waiting for this one to flush. Both buffers reserved buffers may
 * thus be used at the same time.
 */
#ifndef RESERVED_BUFS
#define RESERVED_BUFS   2
#endif

// reserved buffer space for header rewriting
#ifndef MAXREWRITE
#define MAXREWRITE      1024
#endif

#ifndef REQURI_LEN
#define REQURI_LEN      1024
#endif

#ifndef CAPTURE_LEN
#define CAPTURE_LEN     64
#endif

#ifndef MAX_SYSLOG_LEN
#define MAX_SYSLOG_LEN          1024
#endif

/* 64kB to archive startup-logs seems way more than enough */
#ifndef STARTUP_LOG_SIZE
#define STARTUP_LOG_SIZE        65536
#endif

// maximum line size when parsing config
#ifndef LINESIZE
#define LINESIZE	2048
#endif

// max # args on a configuration line
#define MAX_LINE_ARGS   64

// maximum line size when parsing crt-bind-list config
#define CRT_LINESIZE    65536

// max # args on crt-bind-list configuration line
#define MAX_CRT_ARGS  2048

// max # args on a command issued on the CLI ("stats socket")
// This should cover at least 5 + twice the # of data_types
#define MAX_CLI_ARGS  64

// max recursion levels in config condition evaluations
// (note that binary operators add one recursion level, and
// that parenthesis may add two).
#define MAX_CFG_RECURSION 1024

// max # of matches per regexp
#define	MAX_MATCH       10

// max # of headers in one HTTP request or response
// By default, about 100 headers (+1 for the first line)
#ifndef MAX_HTTP_HDR
#define MAX_HTTP_HDR    101
#endif

// max # of headers in history when looking for header #-X
#ifndef MAX_HDR_HISTORY
#define MAX_HDR_HISTORY 10
#endif

// max # of stick counters per session (at least 3 for sc0..sc2)
#ifndef MAX_SESS_STKCTR
#define MAX_SESS_STKCTR 3
#endif

// max # of extra stick-table data types that can be registered at runtime
#ifndef STKTABLE_EXTRA_DATA_TYPES
#define STKTABLE_EXTRA_DATA_TYPES 0
#endif

// max # of stick-table filter entries that can be used during dump
#ifndef STKTABLE_FILTER_LEN
#define STKTABLE_FILTER_LEN 4
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

// The minimum number of bytes to be forwarded that is worth trying to splice.
// Below 4kB, it's not worth allocating pipes nor pretending to zero-copy.
#ifndef MIN_SPLICE_FORWARD
#define MIN_SPLICE_FORWARD 4096
#endif

// the max number of events returned in one call to poll/epoll. Too small a
// value will cause lots of calls, and too high a value may cause high latency.
#ifndef MAX_POLL_EVENTS
#define MAX_POLL_EVENTS 200
#endif

/* eternity when exprimed in timeval */
#ifndef TV_ETERNITY
#define TV_ETERNITY     (~0UL)
#endif

/* eternity when exprimed in ms */
#ifndef TV_ETERNITY_MS
#define TV_ETERNITY_MS  (-1)
#endif

/* we want to be able to detect time jumps. Fix the maximum wait time to a low
 * value so that we know the time has changed if we wait longer.
 */
#ifndef MAX_DELAY_MS
#define MAX_DELAY_MS    60000
#endif

// The maximum number of connections accepted at once by a thread for a single
// listener. It used to default to 64 divided by the number of processes but
// the tasklet-based model is much more scalable and benefits from smaller
// values. Experimentation has shown that 4 gives the highest accept rate for
// all thread values, and that 3 and 5 come very close, as shown below (HTTP/1
// connections forwarded per second at multi-accept 4 and 64):
//
// ac\thr|    1    2     4     8     16
// ------+------------------------------
//      4|   80k  106k  168k  270k  336k
//     64|   63k   89k  145k  230k  274k
//
#ifndef MAX_ACCEPT
#define MAX_ACCEPT 4
#endif

// The base max number of tasks to run at once to be used when not set by
// tune.runqueue-depth. It will automatically be divided by the square root
// of the number of threads for better fairness. As such, 64 threads will
// use 35 and a single thread will use 280.
#ifndef RUNQUEUE_DEPTH
#define RUNQUEUE_DEPTH 280
#endif

// cookie delimiter in "prefix" mode. This character is inserted between the
// persistence cookie and the original value. The '~' is allowed by RFC6265,
// and should not be too common in server names.
#ifndef COOKIE_DELIM
#define COOKIE_DELIM    '~'
#endif

// this delimiter is used between a server's name and a last visit date in
// cookies exchanged with the client.
#ifndef COOKIE_DELIM_DATE
#define COOKIE_DELIM_DATE       '|'
#endif

#define CONN_RETRIES    3

#define	CHK_CONNTIME    2000
#define	DEF_CHKINTR     2000
#define DEF_MAILALERTTIME 10000
#define DEF_FALLTIME    3
#define DEF_RISETIME    2
#define DEF_AGENT_FALLTIME    1
#define DEF_AGENT_RISETIME    1
#define DEF_CHECK_PATH  ""


#define DEF_HANA_ONERR		HANA_ONERR_FAILCHK
#define DEF_HANA_ERRLIMIT	10

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
 * command-line '-n' argument. If SYSTEM_MAXCONN is not set, a minimum value
 * of 100 will be used for DEFAULT_MAXCONN which almost guarantees that a
 * process will correctly start in any situation.
 */
#ifdef SYSTEM_MAXCONN
#undef  DEFAULT_MAXCONN
#define DEFAULT_MAXCONN SYSTEM_MAXCONN
#elif !defined(DEFAULT_MAXCONN)
#define DEFAULT_MAXCONN 100
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

/* This is the default statistics URI */
#ifdef CONFIG_STATS_DEFAULT_URI
#define STATS_DEFAULT_URI CONFIG_STATS_DEFAULT_URI
#else
#define STATS_DEFAULT_URI "/haproxy?stats"
#endif

/* This is the default statistics realm */
#ifdef CONFIG_STATS_DEFAULT_REALM
#define STATS_DEFAULT_REALM CONFIG_STATS_DEFAULT_REALM
#else
#define STATS_DEFAULT_REALM "HAProxy Statistics"
#endif

/* Maximum signal queue size, and also number of different signals we can
 * handle.
 */
#ifndef MAX_SIGNAL
#define MAX_SIGNAL 256
#endif

/* Maximum host name length */
#ifndef MAX_HOSTNAME_LEN
#ifdef MAXHOSTNAMELEN
#define MAX_HOSTNAME_LEN	MAXHOSTNAMELEN
#else
#define MAX_HOSTNAME_LEN	64
#endif // MAXHOSTNAMELEN
#endif // MAX_HOSTNAME_LEN

/* Maximum health check description length */
#ifndef HCHK_DESC_LEN
#define HCHK_DESC_LEN	128
#endif

/* ciphers used as defaults on connect */
#ifndef CONNECT_DEFAULT_CIPHERS
#define CONNECT_DEFAULT_CIPHERS NULL
#endif

/* ciphers used as defaults on TLS 1.3 connect */
#ifndef CONNECT_DEFAULT_CIPHERSUITES
#define CONNECT_DEFAULT_CIPHERSUITES NULL
#endif

/* ciphers used as defaults on listeners */
#ifndef LISTEN_DEFAULT_CIPHERS
#define LISTEN_DEFAULT_CIPHERS NULL
#endif

/* cipher suites used as defaults on TLS 1.3 listeners */
#ifndef LISTEN_DEFAULT_CIPHERSUITES
#define LISTEN_DEFAULT_CIPHERSUITES NULL
#endif

/* named curve used as defaults for ECDHE ciphers */
#ifndef ECDHE_DEFAULT_CURVE
#define ECDHE_DEFAULT_CURVE "prime256v1"
#endif

/* ssl cache size */
#ifndef SSLCACHESIZE
#define SSLCACHESIZE 20000
#endif

/* ssl max dh param size */
#ifndef SSL_DEFAULT_DH_PARAM
#define SSL_DEFAULT_DH_PARAM 0
#endif

/* max memory cost per SSL session */
#ifndef SSL_SESSION_MAX_COST
#define SSL_SESSION_MAX_COST (16*1024)    // measured
#endif

/* max memory cost per SSL handshake (on top of session) */
#ifndef SSL_HANDSHAKE_MAX_COST
#define SSL_HANDSHAKE_MAX_COST (76*1024)  // measured
#endif

#ifndef DEFAULT_SSL_CTX_CACHE
#define DEFAULT_SSL_CTX_CACHE 1000
#endif

/* approximate stream size (for maxconn estimate) */
#ifndef STREAM_MAX_COST
#define STREAM_MAX_COST (sizeof(struct stream) + \
                          2 * sizeof(struct channel) + \
                          2 * sizeof(struct connection) + \
                          global.tune.requri_len + \
                          2 * global.tune.cookie_len)
#endif

/* available memory estimate : count about 3% of overhead in various structures */
#ifndef MEM_USABLE_RATIO
#define MEM_USABLE_RATIO 0.97
#endif

/* Pools are always enabled unless explicitly disabled. When disabled, the
 * calls are directly passed to the underlying OS functions.
 */
#if !defined(DEBUG_NO_POOLS) && !defined(DEBUG_UAF)
#define CONFIG_HAP_POOLS
#endif

/* On modern architectures with many threads, a fast memory allocator, and
 * local pools, the global pools with their single list can be way slower than
 * the standard allocator which already has its own per-thread arenas. In this
 * case we disable global pools. The global pools may still be enforced
 * using CONFIG_HAP_GLOBAL_POOLS though.
 */
#if defined(USE_THREAD) && defined(HA_HAVE_FAST_MALLOC) && !defined(CONFIG_HAP_GLOBAL_POOLS)
#define CONFIG_HAP_NO_GLOBAL_POOLS
#endif

/* default per-thread pool cache size when enabled */
#ifndef CONFIG_HAP_POOL_CACHE_SIZE
#define CONFIG_HAP_POOL_CACHE_SIZE 524288
#endif

#ifndef CONFIG_HAP_POOL_CLUSTER_SIZE
#define CONFIG_HAP_POOL_CLUSTER_SIZE 8
#endif

/* Number of samples used to compute the times reported in stats. A power of
 * two is highly recommended, and this value multiplied by the largest response
 * time must not overflow and unsigned int. See freq_ctr.h for more information.
 * We consider that values are accurate to 95% with two batches of samples below,
 * so in order to advertise accurate times across 1k samples, we effectively
 * measure over 512.
 */
#ifndef TIME_STATS_SAMPLES
#define TIME_STATS_SAMPLES 512
#endif

/* max ocsp cert id asn1 encoded length */
#ifndef OCSP_MAX_CERTID_ASN1_LENGTH
#define OCSP_MAX_CERTID_ASN1_LENGTH 128
#endif

#ifndef OCSP_MAX_RESPONSE_TIME_SKEW
#define OCSP_MAX_RESPONSE_TIME_SKEW 300
#endif

/* Number of TLS tickets to check, used for rotation */
#ifndef TLS_TICKETS_NO
#define TLS_TICKETS_NO 3
#endif

/* pattern lookup default cache size, in number of entries :
 * 10k entries at 10k req/s mean 1% risk of a collision after 60 years, that's
 * already much less than the memory's reliability in most machines and more
 * durable than most admin's life expectancy. A collision will result in a
 * valid result to be returned for a different entry from the same list.
 */
#ifndef DEFAULT_PAT_LRU_SIZE
#define DEFAULT_PAT_LRU_SIZE 10000
#endif

/* maximum number of pollers that may be registered */
#ifndef MAX_POLLERS
#define MAX_POLLERS	10
#endif

/* system sysfs directory */
#define NUMA_DETECT_SYSTEM_SYSFS_PATH "/sys/devices/system"

#endif /* _HAPROXY_DEFAULTS_H */
