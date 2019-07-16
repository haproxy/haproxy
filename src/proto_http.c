/*
 * HTTP protocol analyzer
 *
 * Copyright 2000-2011 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/base64.h>
#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/h1.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/cli.h>
#include <types/filters.h>
#include <types/global.h>
#include <types/stats.h>

#include <proto/acl.h>
#include <proto/action.h>
#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/cli.h>
#include <proto/compression.h>
#include <proto/dns.h>
#include <proto/stats.h>
#include <proto/fd.h>
#include <proto/filters.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/hlua.h>
#include <proto/pattern.h>
#include <proto/proto_tcp.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/sample.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/pattern.h>
#include <proto/vars.h>

DECLARE_POOL(pool_head_http_txn, "http_txn", sizeof(struct http_txn));
DECLARE_POOL(pool_head_uniqueid, "uniqueid", UNIQUEID_LEN);

struct pool_head *pool_head_requri = NULL;
struct pool_head *pool_head_capture = NULL;


/* Allocate a new HTTP transaction for stream <s> unless there is one already.
 * In case of allocation failure, everything allocated is freed and NULL is
 * returned. Otherwise the new transaction is assigned to the stream and
 * returned.
 */
struct http_txn *http_alloc_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;

	if (txn)
		return txn;

	txn = pool_alloc(pool_head_http_txn);
	if (!txn)
		return txn;

	s->txn = txn;
	return txn;
}

void http_txn_reset_req(struct http_txn *txn)
{
	txn->req.flags = 0;
	txn->req.msg_state = HTTP_MSG_RQBEFORE; /* at the very beginning of the request */
}

void http_txn_reset_res(struct http_txn *txn)
{
	txn->rsp.flags = 0;
	txn->rsp.msg_state = HTTP_MSG_RPBEFORE; /* at the very beginning of the response */
}

/*
 * Initialize a new HTTP transaction for stream <s>. It is assumed that all
 * the required fields are properly allocated and that we only need to (re)init
 * them. This should be used before processing any new request.
 */
void http_init_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;
	struct conn_stream *cs = objt_cs(s->si[0].end);

	txn->flags = ((cs && cs->flags & CS_FL_NOT_FIRST)
		      ? (TX_NOT_FIRST|TX_WAIT_NEXT_RQ)
		      : 0);
	txn->status = -1;
	*(unsigned int *)txn->cache_hash = 0;

	txn->cookie_first_date = 0;
	txn->cookie_last_date = 0;

	txn->srv_cookie = NULL;
	txn->cli_cookie = NULL;
	txn->uri = NULL;

	http_txn_reset_req(txn);
	http_txn_reset_res(txn);

	txn->req.chn = &s->req;
	txn->rsp.chn = &s->res;

	txn->auth.method = HTTP_AUTH_UNKNOWN;

	vars_init(&s->vars_txn,    SCOPE_TXN);
	vars_init(&s->vars_reqres, SCOPE_REQ);
}

/* to be used at the end of a transaction */
void http_end_txn(struct stream *s)
{
	struct http_txn *txn = s->txn;
	struct proxy *fe = strm_fe(s);

	/* these ones will have been dynamically allocated */
	pool_free(pool_head_requri, txn->uri);
	pool_free(pool_head_capture, txn->cli_cookie);
	pool_free(pool_head_capture, txn->srv_cookie);
	pool_free(pool_head_uniqueid, s->unique_id);

	s->unique_id = NULL;
	txn->uri = NULL;
	txn->srv_cookie = NULL;
	txn->cli_cookie = NULL;

	if (s->req_cap) {
		struct cap_hdr *h;
		for (h = fe->req_cap; h; h = h->next)
			pool_free(h->pool, s->req_cap[h->index]);
		memset(s->req_cap, 0, fe->nb_req_cap * sizeof(void *));
	}

	if (s->res_cap) {
		struct cap_hdr *h;
		for (h = fe->rsp_cap; h; h = h->next)
			pool_free(h->pool, s->res_cap[h->index]);
		memset(s->res_cap, 0, fe->nb_rsp_cap * sizeof(void *));
	}

	if (!LIST_ISEMPTY(&s->vars_txn.head))
		vars_prune(&s->vars_txn, s->sess, s);
	if (!LIST_ISEMPTY(&s->vars_reqres.head))
		vars_prune(&s->vars_reqres, s->sess, s);
}

/* to be used at the end of a transaction to prepare a new one */
void http_reset_txn(struct stream *s)
{
	http_end_txn(s);
	http_init_txn(s);

	/* reinitialise the current rule list pointer to NULL. We are sure that
	 * any rulelist match the NULL pointer.
	 */
	s->current_rule_list = NULL;

	s->be = strm_fe(s);
	s->logs.logwait = strm_fe(s)->to_log;
	s->logs.level = 0;
	stream_del_srv_conn(s);
	s->target = NULL;
	/* re-init store persistence */
	s->store_count = 0;
	s->uniq_id = _HA_ATOMIC_XADD(&global.req_count, 1);

	s->req.flags |= CF_READ_DONTWAIT; /* one read is usually enough */

	/* We must trim any excess data from the response buffer, because we
	 * may have blocked an invalid response from a server that we don't
	 * want to accidently forward once we disable the analysers, nor do
	 * we want those data to come along with next response. A typical
	 * example of such data would be from a buggy server responding to
	 * a HEAD with some data, or sending more than the advertised
	 * content-length.
	 */
	if (unlikely(ci_data(&s->res)))
		b_set_data(&s->res.buf, co_data(&s->res));

	/* Now we can realign the response buffer */
	c_realign_if_empty(&s->res);

	s->req.rto = strm_fe(s)->timeout.client;
	s->req.wto = TICK_ETERNITY;

	s->res.rto = TICK_ETERNITY;
	s->res.wto = strm_fe(s)->timeout.client;

	s->req.rex = TICK_ETERNITY;
	s->req.wex = TICK_ETERNITY;
	s->req.analyse_exp = TICK_ETERNITY;
	s->res.rex = TICK_ETERNITY;
	s->res.wex = TICK_ETERNITY;
	s->res.analyse_exp = TICK_ETERNITY;
	s->si[1].hcto = TICK_ETERNITY;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
