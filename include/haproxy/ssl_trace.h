/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _HAPROXY_SSL_TRACE_H
#define _HAPROXY_SSL_TRACE_H

#include <haproxy/trace-t.h>

extern struct trace_source trace_ssl;

#define SSL_EV_CONN_NEW            (1ULL <<  0)
#define SSL_EV_CONN_CLOSE          (1ULL <<  1)
#define SSL_EV_CONN_END            (1ULL <<  2)
#define SSL_EV_CONN_ERR            (1ULL <<  3)
#define SSL_EV_CONN_SEND           (1ULL <<  4)
#define SSL_EV_CONN_SEND_EARLY     (1ULL <<  5)
#define SSL_EV_CONN_RECV           (1ULL <<  6)
#define SSL_EV_CONN_RECV_EARLY     (1ULL <<  7)
#define SSL_EV_CONN_IO_CB          (1ULL <<  8)
#define SSL_EV_CONN_HNDSHK         (1ULL <<  9)
#define SSL_EV_CONN_VFY_CB         (1ULL << 10)
#define SSL_EV_CONN_STAPLING       (1ULL << 11)
#define SSL_EV_CONN_SWITCHCTX_CB   (1ULL << 12)
#define SSL_EV_CONN_CHOOSE_SNI_CTX (1ULL << 13)
#define SSL_EV_CONN_SIGALG_EXT     (1ULL << 14)
#define SSL_EV_CONN_CIPHERS_EXT    (1ULL << 15)
#define SSL_EV_CONN_CURVES_EXT     (1ULL << 16)


#define SSL_VERB_CLEAN    1
#define SSL_VERB_MINIMAL  2
#define SSL_VERB_SIMPLE   3
#define SSL_VERB_ADVANCED 4
#define SSL_VERB_COMPLETE 5

#define TRACE_SOURCE &trace_ssl

#endif /* _HAPROXY_SSL_TRACE_H */
