/*
 * Frontend variables and functions.
 *
 * Copyright 2000-2013 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/channel.h>
#include <proto/fd.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/hdr_idx.h>
#include <proto/proto_tcp.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/session.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

/* Finish a session accept() for a proxy (TCP or HTTP). It returns a negative
 * value in case of a critical failure which must cause the listener to be
 * disabled, a positive value in case of success, or zero if it is a success
 * but the session must be closed ASAP (eg: monitoring). It only supports
 * sessions with a connection in si[0].
 */
int frontend_accept(struct session *s)
{
	struct connection *conn = __objt_conn(s->si[0].end);
	int cfd = conn->t.sock.fd;

	tv_zero(&s->logs.tv_request);
	s->logs.t_queue = -1;
	s->logs.t_connect = -1;
	s->logs.t_data = -1;
	s->logs.t_close = 0;
	s->logs.bytes_in = s->logs.bytes_out = 0;
	s->logs.prx_queue_size = 0;  /* we get the number of pending conns before us */
	s->logs.srv_queue_size = 0; /* we will get this number soon */

	/* FIXME: the logs are horribly complicated now, because they are
	 * defined in <p>, <p>, and later <be> and <be>.
	 */
	s->do_log = sess_log;

	/* default error reporting function, may be changed by analysers */
	s->srv_error = default_srv_error;

	/* Adjust some socket options */
	if (s->listener->addr.ss_family == AF_INET || s->listener->addr.ss_family == AF_INET6) {
		if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY,
			       (char *) &one, sizeof(one)) == -1)
			goto out_return;

		if (s->fe->options & PR_O_TCP_CLI_KA)
			setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE,
				   (char *) &one, sizeof(one));

		if (s->fe->options & PR_O_TCP_NOLING)
			fdtab[cfd].linger_risk = 1;

#if defined(TCP_MAXSEG)
		if (s->listener->maxseg < 0) {
			/* we just want to reduce the current MSS by that value */
			int mss;
			socklen_t mss_len = sizeof(mss);
			if (getsockopt(cfd, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_len) == 0) {
				mss += s->listener->maxseg; /* remember, it's < 0 */
				setsockopt(cfd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
			}
		}
#endif
	}

	if (global.tune.client_sndbuf)
		setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &global.tune.client_sndbuf, sizeof(global.tune.client_sndbuf));

	if (global.tune.client_rcvbuf)
		setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &global.tune.client_rcvbuf, sizeof(global.tune.client_rcvbuf));

	if (unlikely(s->fe->nb_req_cap > 0 && (s->txn.req.cap = pool_alloc2(s->fe->req_cap_pool)) == NULL))
		goto out_return;	/* no memory */

	if (unlikely(s->fe->nb_rsp_cap > 0 && (s->txn.rsp.cap = pool_alloc2(s->fe->rsp_cap_pool)) == NULL))
		goto out_free_reqcap;	/* no memory */

	if (s->fe->http_needed) {
		/* we have to allocate header indexes only if we know
		 * that we may make use of them. This of course includes
		 * (mode == PR_MODE_HTTP).
		 */
		s->txn.hdr_idx.size = global.tune.max_http_hdr;

		if (unlikely((s->txn.hdr_idx.v = pool_alloc2(pool2_hdr_idx)) == NULL))
			goto out_free_rspcap; /* no memory */

		/* and now initialize the HTTP transaction state */
		http_init_txn(s);
	}

	if ((s->fe->mode == PR_MODE_TCP || s->fe->mode == PR_MODE_HTTP)
	    && (!LIST_ISEMPTY(&s->fe->logsrvs))) {
		if (likely(!LIST_ISEMPTY(&s->fe->logformat))) {
			/* we have the client ip */
			if (s->logs.logwait & LW_CLIP)
				if (!(s->logs.logwait &= ~(LW_CLIP|LW_INIT)))
					s->do_log(s);
		}
		else {
			char pn[INET6_ADDRSTRLEN], sn[INET6_ADDRSTRLEN];

			conn_get_from_addr(conn);
			conn_get_to_addr(conn);

			switch (addr_to_str(&conn->addr.from, pn, sizeof(pn))) {
			case AF_INET:
			case AF_INET6:
				addr_to_str(&conn->addr.to, sn, sizeof(sn));
				send_log(s->fe, LOG_INFO, "Connect from %s:%d to %s:%d (%s/%s)\n",
					 pn, get_host_port(&conn->addr.from),
					 sn, get_host_port(&conn->addr.to),
					 s->fe->id, (s->fe->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
				break;
			case AF_UNIX:
				/* UNIX socket, only the destination is known */
				send_log(s->fe, LOG_INFO, "Connect to unix:%d (%s/%s)\n",
					 s->listener->luid,
					 s->fe->id, (s->fe->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
				break;
			}
		}
	}

	if (unlikely((global.mode & MODE_DEBUG) && (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		char pn[INET6_ADDRSTRLEN];

		conn_get_from_addr(conn);

		switch (addr_to_str(&conn->addr.from, pn, sizeof(pn))) {
		case AF_INET:
		case AF_INET6:
			chunk_printf(&trash, "%08x:%s.accept(%04x)=%04x from [%s:%d]\n",
			             s->uniq_id, s->fe->id, (unsigned short)s->listener->fd, (unsigned short)cfd,
			             pn, get_host_port(&conn->addr.from));
			break;
		case AF_UNIX:
			/* UNIX socket, only the destination is known */
			chunk_printf(&trash, "%08x:%s.accept(%04x)=%04x from [unix:%d]\n",
			             s->uniq_id, s->fe->id, (unsigned short)s->listener->fd, (unsigned short)cfd,
			             s->listener->luid);
			break;
		}

		shut_your_big_mouth_gcc(write(1, trash.str, trash.len));
	}

	if (s->fe->mode == PR_MODE_HTTP)
		s->req->flags |= CF_READ_DONTWAIT; /* one read is usually enough */

	/* note: this should not happen anymore since there's always at least the switching rules */
	if (!s->req->analysers) {
		channel_auto_connect(s->req);  /* don't wait to establish connection */
		channel_auto_close(s->req);    /* let the producer forward close requests */
	}

	s->req->rto = s->fe->timeout.client;
	s->rep->wto = s->fe->timeout.client;

	/* everything's OK, let's go on */
	return 1;

	/* Error unrolling */
 out_free_rspcap:
	pool_free2(s->fe->rsp_cap_pool, s->txn.rsp.cap);
 out_free_reqcap:
	pool_free2(s->fe->req_cap_pool, s->txn.req.cap);
 out_return:
	return -1;
}

/************************************************************************/
/*      All supported sample and ACL keywords must be declared here.    */
/************************************************************************/

/* set temp integer to the id of the frontend */
static int
smp_fetch_fe_id(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                const struct arg *args, struct sample *smp, const char *kw)
{
	smp->flags = SMP_F_VOL_SESS;
	smp->type = SMP_T_UINT;
	smp->data.uint = l4->fe->uuid;
	return 1;
}

/* set temp integer to the number of connections per second reaching the frontend.
 * Accepts exactly 1 argument. Argument is a frontend, other types will cause
 * an undefined behaviour.
 */
static int
smp_fetch_fe_sess_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp, const char *kw)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = read_freq_ctr(&args->data.prx->fe_sess_per_sec);
	return 1;
}

/* set temp integer to the number of concurrent connections on the frontend
 * Accepts exactly 1 argument. Argument is a frontend, other types will cause
 * an undefined behaviour.
 */
static int
smp_fetch_fe_conn(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                  const struct arg *args, struct sample *smp, const char *kw)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = args->data.prx->feconn;
	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "fe_conn",      smp_fetch_fe_conn,      ARG1(1,FE), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "fe_id",        smp_fetch_fe_id,        0,          NULL, SMP_T_UINT, SMP_USE_FTEND, },
	{ "fe_sess_rate", smp_fetch_fe_sess_rate, ARG1(1,FE), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ /* END */ },
}};


/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ /* END */ },
}};


__attribute__((constructor))
static void __frontend_init(void)
{
	sample_register_fetches(&smp_kws);
	acl_register_keywords(&acl_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
