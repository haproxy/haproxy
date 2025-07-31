#ifndef _HAPROXY_QUIC_TUNE_H
#define _HAPROXY_QUIC_TUNE_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/quic_tune-t.h>

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/obj_type.h>
#include <haproxy/quic_conn-t.h>

extern struct quic_tune quic_tune;

#define QUIC_TUNE_FB_GET(opt, qc) \
	(!((qc)->flags & QUIC_FL_CONN_IS_BACK) ? quic_tune.fe. opt : quic_tune.be. opt)

static inline int quic_tune_test(int opt, const struct quic_conn *qc)
{
	return !(qc->flags & QUIC_FL_CONN_IS_BACK) ?
	  quic_tune.fe.fb_opts & opt : quic_tune.be.fb_opts & opt;
}

#define QUIC_TUNE_FB_CONN_GET(opt, conn) \
	(!(conn_is_back(conn)) ? quic_tune.fe. opt : quic_tune.be. opt)

static inline int quic_tune_conn_test(int opt, const struct connection *conn)
{
	return !(conn_is_back(conn)) ?
	  quic_tune.fe.fb_opts & opt : quic_tune.be.fb_opts & opt;
}

#endif /* USE_QUIC */

#endif /* _HAPROXY_QUIC_TUNE_H */
