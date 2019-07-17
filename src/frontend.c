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
#include <common/initcall.h>
#include <common/standard.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/channel.h>
#include <proto/fd.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/proto_tcp.h>
#include <proto/http_ana.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

/* Finish a stream accept() for a proxy (TCP or HTTP). It returns a negative
 * value in case of a critical failure which must cause the listener to be
 * disabled, a positive or null value in case of success.
 */
int frontend_accept(struct stream *s)
{
	struct session *sess = s->sess;
	struct connection *conn = objt_conn(sess->origin);
	struct listener *l = sess->listener;
	struct proxy *fe = sess->fe;

	if ((fe->mode == PR_MODE_TCP || fe->mode == PR_MODE_HTTP)
	    && (!LIST_ISEMPTY(&fe->logsrvs))) {
		if (likely(!LIST_ISEMPTY(&fe->logformat))) {
			/* we have the client ip */
			if (s->logs.logwait & LW_CLIP)
				if (!(s->logs.logwait &= ~(LW_CLIP|LW_INIT)))
					s->do_log(s);
		}
		else if (conn && !conn_get_src(conn)) {
			send_log(fe, LOG_INFO, "Connect from unknown source to listener %d (%s/%s)\n",
				 l->luid, fe->id, (fe->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
		}
		else if (conn) {
			char pn[INET6_ADDRSTRLEN], sn[INET6_ADDRSTRLEN];
			int port;

			switch (addr_to_str(conn->src, pn, sizeof(pn))) {
			case AF_INET:
			case AF_INET6:
				if (conn_get_dst(conn)) {
					addr_to_str(conn->dst, sn, sizeof(sn));
					port = get_host_port(conn->dst);
				} else {
					strcpy(sn, "undetermined address");
					port = 0;
				}
				send_log(fe, LOG_INFO, "Connect from %s:%d to %s:%d (%s/%s)\n",
					 pn, get_host_port(conn->src),
					 sn, port,
					 fe->id, (fe->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
				break;
			case AF_UNIX:
				/* UNIX socket, only the destination is known */
				send_log(fe, LOG_INFO, "Connect to unix:%d (%s/%s)\n",
					 l->luid,
					 fe->id, (fe->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");
				break;
			}
		}
	}

	if (unlikely((global.mode & MODE_DEBUG) && conn &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)))) {
		char pn[INET6_ADDRSTRLEN];
		char alpn[16] = "<none>";
		const char *alpn_str = NULL;
		int alpn_len;

		/* try to report the ALPN value when available (also works for NPN) */
		if (conn == cs_conn(objt_cs(s->si[0].end))) {
			if (conn_get_alpn(conn, &alpn_str, &alpn_len) && alpn_str) {
				int len = MIN(alpn_len, sizeof(alpn) - 1);
				memcpy(alpn, alpn_str, len);
				alpn[len] = 0;
			}
		}

		if (!conn_get_src(conn)) {
			chunk_printf(&trash, "%08x:%s.accept(%04x)=%04x from [listener:%d] ALPN=%s\n",
			             s->uniq_id, fe->id, (unsigned short)l->fd, (unsigned short)conn->handle.fd,
			             l->luid, alpn);
		}
		else switch (addr_to_str(conn->src, pn, sizeof(pn))) {
		case AF_INET:
		case AF_INET6:
			chunk_printf(&trash, "%08x:%s.accept(%04x)=%04x from [%s:%d] ALPN=%s\n",
			             s->uniq_id, fe->id, (unsigned short)l->fd, (unsigned short)conn->handle.fd,
			             pn, get_host_port(conn->src), alpn);
			break;
		case AF_UNIX:
			/* UNIX socket, only the destination is known */
			chunk_printf(&trash, "%08x:%s.accept(%04x)=%04x from [unix:%d] ALPN=%s\n",
			             s->uniq_id, fe->id, (unsigned short)l->fd, (unsigned short)conn->handle.fd,
			             l->luid, alpn);
			break;
		}

		shut_your_big_mouth_gcc(write(1, trash.area, trash.data));
	}

	if (fe->mode == PR_MODE_HTTP)
		s->req.flags |= CF_READ_DONTWAIT; /* one read is usually enough */

	if (unlikely(fe->nb_req_cap > 0)) {
		if ((s->req_cap = pool_alloc(fe->req_cap_pool)) == NULL)
			goto out_return;	/* no memory */
		memset(s->req_cap, 0, fe->nb_req_cap * sizeof(void *));
	}

	if (unlikely(fe->nb_rsp_cap > 0)) {
		if ((s->res_cap = pool_alloc(fe->rsp_cap_pool)) == NULL)
			goto out_free_reqcap;	/* no memory */
		memset(s->res_cap, 0, fe->nb_rsp_cap * sizeof(void *));
	}

	if (fe->http_needed) {
		/* we have to allocate header indexes only if we know
		 * that we may make use of them. This of course includes
		 * (mode == PR_MODE_HTTP).
		 */
		if (unlikely(!http_alloc_txn(s)))
			goto out_free_rspcap; /* no memory */

		/* and now initialize the HTTP transaction state */
		http_init_txn(s);
	}

	/* everything's OK, let's go on */
	return 1;

	/* Error unrolling */
 out_free_rspcap:
	pool_free(fe->rsp_cap_pool, s->res_cap);
 out_free_reqcap:
	pool_free(fe->req_cap_pool, s->req_cap);
 out_return:
	return -1;
}

/************************************************************************/
/*      All supported sample and ACL keywords must be declared here.    */
/************************************************************************/

/* set temp integer to the id of the frontend */
static int
smp_fetch_fe_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_SESS;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = smp->sess->fe->uuid;
	return 1;
}

/* set string to the name of the frontend */
static int
smp_fetch_fe_name(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.u.str.area = (char *)smp->sess->fe->id;
	if (!smp->data.u.str.area)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);
	return 1;
}

/* set string to the name of the default backend */
static int
smp_fetch_fe_defbe(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->sess->fe->defbe.be)
		return 0;
	smp->data.u.str.area = (char *)smp->sess->fe->defbe.be->id;
	if (!smp->data.u.str.area)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);
	return 1;
}

/* set temp integer to the number of HTTP requests per second reaching the frontend.
 * Accepts exactly 1 argument. Argument is a frontend, other types will cause
 * an undefined behaviour.
 */
static int
smp_fetch_fe_req_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = read_freq_ctr(&args->data.prx->fe_req_per_sec);
	return 1;
}

/* set temp integer to the number of connections per second reaching the frontend.
 * Accepts exactly 1 argument. Argument is a frontend, other types will cause
 * an undefined behaviour.
 */
static int
smp_fetch_fe_sess_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = read_freq_ctr(&args->data.prx->fe_sess_per_sec);
	return 1;
}

/* set temp integer to the number of concurrent connections on the frontend
 * Accepts exactly 1 argument. Argument is a frontend, other types will cause
 * an undefined behaviour.
 */
static int
smp_fetch_fe_conn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = args->data.prx->feconn;
	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "fe_conn",      smp_fetch_fe_conn,      ARG1(1,FE), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "fe_defbe",     smp_fetch_fe_defbe,     0,          NULL, SMP_T_STR,  SMP_USE_FTEND, },
	{ "fe_id",        smp_fetch_fe_id,        0,          NULL, SMP_T_SINT, SMP_USE_FTEND, },
	{ "fe_name",      smp_fetch_fe_name,      0,          NULL, SMP_T_STR,  SMP_USE_FTEND, },
	{ "fe_req_rate",  smp_fetch_fe_req_rate,  ARG1(1,FE), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "fe_sess_rate", smp_fetch_fe_sess_rate, ARG1(1,FE), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_kws);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, acl_register_keywords, &acl_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
