/*
 * Backend variables and functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
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
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/backend.h>
#include <proto/client.h>
#include <proto/lb_chash.h>
#include <proto/lb_fwlc.h>
#include <proto/lb_fwrr.h>
#include <proto/lb_map.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/task.h>

/*
 * This function recounts the number of usable active and backup servers for
 * proxy <p>. These numbers are returned into the p->srv_act and p->srv_bck.
 * This function also recomputes the total active and backup weights. However,
 * it does not update tot_weight nor tot_used. Use update_backend_weight() for
 * this.
 */
void recount_servers(struct proxy *px)
{
	struct server *srv;

	px->srv_act = px->srv_bck = 0;
	px->lbprm.tot_wact = px->lbprm.tot_wbck = 0;
	px->lbprm.fbck = NULL;
	for (srv = px->srv; srv != NULL; srv = srv->next) {
		if (!srv_is_usable(srv->state, srv->eweight))
			continue;

		if (srv->state & SRV_BACKUP) {
			if (!px->srv_bck &&
			    !(px->options & PR_O_USE_ALL_BK))
				px->lbprm.fbck = srv;
			px->srv_bck++;
			px->lbprm.tot_wbck += srv->eweight;
		} else {
			px->srv_act++;
			px->lbprm.tot_wact += srv->eweight;
		}
	}
}

/* This function simply updates the backend's tot_weight and tot_used values
 * after servers weights have been updated. It is designed to be used after
 * recount_servers() or equivalent.
 */
void update_backend_weight(struct proxy *px)
{
	if (px->srv_act) {
		px->lbprm.tot_weight = px->lbprm.tot_wact;
		px->lbprm.tot_used   = px->srv_act;
	}
	else if (px->lbprm.fbck) {
		/* use only the first backup server */
		px->lbprm.tot_weight = px->lbprm.fbck->eweight;
		px->lbprm.tot_used = 1;
	}
	else {
		px->lbprm.tot_weight = px->lbprm.tot_wbck;
		px->lbprm.tot_used   = px->srv_bck;
	}
}

/*
 * This function tries to find a running server for the proxy <px> following
 * the source hash method. Depending on the number of active/backup servers,
 * it will either look for active servers, or for backup servers.
 * If any server is found, it will be returned. If no valid server is found,
 * NULL is returned.
 */
struct server *get_server_sh(struct proxy *px, const char *addr, int len)
{
	unsigned int h, l;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	l = h = 0;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	while ((l + sizeof (int)) <= len) {
		h ^= ntohl(*(unsigned int *)(&addr[l]));
		l += sizeof (int);
	}
 hash_done:
	if (px->lbprm.algo & BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, h);
	else
		return map_get_server_hash(px, h);
}

/*
 * This function tries to find a running server for the proxy <px> following
 * the URI hash method. In order to optimize cache hits, the hash computation
 * ends at the question mark. Depending on the number of active/backup servers,
 * it will either look for active servers, or for backup servers.
 * If any server is found, it will be returned. If no valid server is found,
 * NULL is returned.
 *
 * This code was contributed by Guillaume Dallaire, who also selected this hash
 * algorithm out of a tens because it gave him the best results.
 *
 */
struct server *get_server_uh(struct proxy *px, char *uri, int uri_len)
{
	unsigned long hash = 0;
	int c;
	int slashes = 0;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	if (px->uri_len_limit)
		uri_len = MIN(uri_len, px->uri_len_limit);

	while (uri_len--) {
		c = *uri++;
		if (c == '/') {
			slashes++;
			if (slashes == px->uri_dirs_depth1) /* depth+1 */
				break;
		}
		else if (c == '?')
			break;

		hash = c + (hash << 6) + (hash << 16) - hash;
	}
 hash_done:
	if (px->lbprm.algo & BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash);
	else
		return map_get_server_hash(px, hash);
}

/* 
 * This function tries to find a running server for the proxy <px> following
 * the URL parameter hash method. It looks for a specific parameter in the
 * URL and hashes it to compute the server ID. This is useful to optimize
 * performance by avoiding bounces between servers in contexts where sessions
 * are shared but cookies are not usable. If the parameter is not found, NULL
 * is returned. If any server is found, it will be returned. If no valid server
 * is found, NULL is returned.
 */
struct server *get_server_ph(struct proxy *px, const char *uri, int uri_len)
{
	unsigned long hash = 0;
	const char *p;
	const char *params;
	int plen;

	/* when tot_weight is 0 then so is srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

	if ((p = memchr(uri, '?', uri_len)) == NULL)
		return NULL;

	p++;

	uri_len -= (p - uri);
	plen = px->url_param_len;
	params = p;

	while (uri_len > plen) {
		/* Look for the parameter name followed by an equal symbol */
		if (params[plen] == '=') {
			if (memcmp(params, px->url_param_name, plen) == 0) {
				/* OK, we have the parameter here at <params>, and
				 * the value after the equal sign, at <p>
				 * skip the equal symbol
				 */
				p += plen + 1;
				uri_len -= plen + 1;

				while (uri_len && *p != '&') {
					hash = *p + (hash << 6) + (hash << 16) - hash;
					uri_len--;
					p++;
				}
				if (px->lbprm.algo & BE_LB_LKUP_CHTREE)
					return chash_get_server_hash(px, hash);
				else
					return map_get_server_hash(px, hash);
			}
		}
		/* skip to next parameter */
		p = memchr(params, '&', uri_len);
		if (!p)
			return NULL;
		p++;
		uri_len -= (p - params);
		params = p;
	}
	return NULL;
}

/*
 * this does the same as the previous server_ph, but check the body contents
 */
struct server *get_server_ph_post(struct session *s)
{
	unsigned long    hash = 0;
	struct http_txn *txn  = &s->txn;
	struct buffer   *req  = s->req;
	struct http_msg *msg  = &txn->req;
	struct proxy    *px   = s->be;
	unsigned int     plen = px->url_param_len;
	unsigned long body;
	unsigned long len;
	const char *params;
	struct hdr_ctx ctx;
	const char   *p;

	/* tot_weight appears to mean srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

        body = msg->sol[msg->eoh] == '\r' ? msg->eoh + 2 : msg->eoh + 1;
        len  = req->l - body;
        params = req->data + body;

	if ( len == 0 )
		return NULL;

	ctx.idx = 0;

	/* if the message is chunked, we skip the chunk size, but use the value as len */
	http_find_header2("Transfer-Encoding", 17, msg->sol, &txn->hdr_idx, &ctx);
	if (ctx.idx && ctx.vlen >= 7 && strncasecmp(ctx.line+ctx.val, "chunked", 7) == 0) {
		unsigned int chunk = 0;
		while ( params < (req->data+req->max_len) && !HTTP_IS_CRLF(*params)) {
			char c = *params;
			if (ishex(c)) {
				unsigned int hex = toupper(c) - '0';
				if ( hex > 9 )
					hex -= 'A' - '9' - 1;
				chunk = (chunk << 4) | hex;
			}
			else
				return NULL;
			params++;
			len--;
		}
		/* spec says we get CRLF */
		if (HTTP_IS_CRLF(*params) && HTTP_IS_CRLF(params[1]))
			params += 2;
		else
			return NULL;
		/* ok we have some encoded length, just inspect the first chunk */
		len = chunk;
	}

	p = params;

	while (len > plen) {
		/* Look for the parameter name followed by an equal symbol */
		if (params[plen] == '=') {
			if (memcmp(params, px->url_param_name, plen) == 0) {
				/* OK, we have the parameter here at <params>, and
				 * the value after the equal sign, at <p>
				 * skip the equal symbol
				 */
				p += plen + 1;
				len -= plen + 1;

				while (len && *p != '&') {
					if (unlikely(!HTTP_IS_TOKEN(*p))) {
					/* if in a POST, body must be URI encoded or its not a URI.
					 * Do not interprete any possible binary data as a parameter.
					 */
						if (likely(HTTP_IS_LWS(*p))) /* eol, uncertain uri len */
							break;
						return NULL;                 /* oh, no; this is not uri-encoded.
									      * This body does not contain parameters.
									      */
					}
					hash = *p + (hash << 6) + (hash << 16) - hash;
					len--;
					p++;
					/* should we break if vlen exceeds limit? */
				}
				if (px->lbprm.algo & BE_LB_LKUP_CHTREE)
					return chash_get_server_hash(px, hash);
				else
					return map_get_server_hash(px, hash);
			}
		}
		/* skip to next parameter */
		p = memchr(params, '&', len);
		if (!p)
			return NULL;
		p++;
		len -= (p - params);
		params = p;
	}
	return NULL;
}


/*
 * This function tries to find a running server for the proxy <px> following
 * the Header parameter hash method. It looks for a specific parameter in the
 * URL and hashes it to compute the server ID. This is useful to optimize
 * performance by avoiding bounces between servers in contexts where sessions
 * are shared but cookies are not usable. If the parameter is not found, NULL
 * is returned. If any server is found, it will be returned. If no valid server
 * is found, NULL is returned.
 */
struct server *get_server_hh(struct session *s)
{
	unsigned long    hash = 0;
	struct http_txn *txn  = &s->txn;
	struct http_msg *msg  = &txn->req;
	struct proxy    *px   = s->be;
	unsigned int     plen = px->hh_len;
	unsigned long    len;
	struct hdr_ctx   ctx;
	const char      *p;

	/* tot_weight appears to mean srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

	ctx.idx = 0;

	/* if the message is chunked, we skip the chunk size, but use the value as len */
	http_find_header2(px->hh_name, plen, msg->sol, &txn->hdr_idx, &ctx);

	/* if the header is not found or empty, let's fallback to round robin */
	if (!ctx.idx || !ctx.vlen)
		return NULL;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	/* Found a the hh_name in the headers.
	 * we will compute the hash based on this value ctx.val.
	 */
	len = ctx.vlen;
	p = (char *)ctx.line + ctx.val;
	if (!px->hh_match_domain) {
		while (len) {
			hash = *p + (hash << 6) + (hash << 16) - hash;
			len--;
			p++;
		}
	} else {
		int dohash = 0;
		p += len - 1;
		/* special computation, use only main domain name, not tld/host
		 * going back from the end of string, start hashing at first
		 * dot stop at next.
		 * This is designed to work with the 'Host' header, and requires
		 * a special option to activate this.
		 */
		while (len) {
			if (*p == '.') {
				if (!dohash)
					dohash = 1;
				else
					break;
			} else {
				if (dohash)
					hash = *p + (hash << 6) + (hash << 16) - hash;
			}
			len--;
			p--;
		}
	}
 hash_done:
	if (px->lbprm.algo & BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash);
	else
		return map_get_server_hash(px, hash);
}

struct server *get_server_rch(struct session *s)
{
	unsigned long    hash = 0;
	struct proxy    *px   = s->be;
	unsigned long    len;
	const char      *p;
	int              ret;
	struct acl_expr  expr;
	struct acl_test  test;

	/* tot_weight appears to mean srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

	memset(&expr, 0, sizeof(expr));
	memset(&test, 0, sizeof(test));

	expr.arg.str = px->hh_name;
	expr.arg_len = px->hh_len;

	ret = acl_fetch_rdp_cookie(px, s, NULL, ACL_DIR_REQ, &expr, &test);
	if (ret == 0 || (test.flags & ACL_TEST_F_MAY_CHANGE) || test.len == 0)
		return NULL;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	/* Found a the hh_name in the headers.
	 * we will compute the hash based on this value ctx.val.
	 */
	len = test.len;
	p = (char *)test.ptr;
	while (len) {
		hash = *p + (hash << 6) + (hash << 16) - hash;
		len--;
		p++;
	}
 hash_done:
	if (px->lbprm.algo & BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash);
	else
		return map_get_server_hash(px, hash);
}
 
/*
 * This function applies the load-balancing algorithm to the session, as
 * defined by the backend it is assigned to. The session is then marked as
 * 'assigned'.
 *
 * This function MAY NOT be called with SN_ASSIGNED already set. If the session
 * had a server previously assigned, it is rebalanced, trying to avoid the same
 * server.
 * The function tries to keep the original connection slot if it reconnects to
 * the same server, otherwise it releases it and tries to offer it.
 *
 * It is illegal to call this function with a session in a queue.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK. Session assigned to ->srv
 *   SRV_STATUS_NOSRV    if no server is available. Session is not ASSIGNED
 *   SRV_STATUS_FULL     if all servers are saturated. Session is not ASSIGNED
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the session flag SN_ASSIGNED is set to indicate that
 * it does not need to be called anymore. This means that s->srv can be trusted
 * in balance and direct modes.
 *
 */

int assign_server(struct session *s)
{

	struct server *conn_slot;
	int err;

#ifdef DEBUG_FULL
	fprintf(stderr,"assign_server : s=%p\n",s);
#endif

	err = SRV_STATUS_INTERNAL;
	if (unlikely(s->pend_pos || s->flags & SN_ASSIGNED))
		goto out_err;

	s->prev_srv = s->prev_srv;
	conn_slot = s->srv_conn;

	/* We have to release any connection slot before applying any LB algo,
	 * otherwise we may erroneously end up with no available slot.
	 */
	if (conn_slot)
		sess_change_server(s, NULL);

	/* We will now try to find the good server and store it into <s->srv>.
	 * Note that <s->srv> may be NULL in case of dispatch or proxy mode,
	 * as well as if no server is available (check error code).
	 */

	s->srv = NULL;
	if (s->be->lbprm.algo & BE_LB_KIND) {
		int len;
		/* we must check if we have at least one server available */
		if (!s->be->lbprm.tot_weight) {
			err = SRV_STATUS_NOSRV;
			goto out;
		}

		/* First check whether we need to fetch some data or simply call
		 * the LB lookup function. Only the hashing functions will need
		 * some input data in fact, and will support multiple algorithms.
		 */
		switch (s->be->lbprm.algo & BE_LB_LKUP) {
		case BE_LB_LKUP_RRTREE:
			s->srv = fwrr_get_next_server(s->be, s->prev_srv);
			break;

		case BE_LB_LKUP_LCTREE:
			s->srv = fwlc_get_next_server(s->be, s->prev_srv);
			break;

		case BE_LB_LKUP_CHTREE:
		case BE_LB_LKUP_MAP:
			if ((s->be->lbprm.algo & BE_LB_KIND) == BE_LB_KIND_RR) {
				if (s->be->lbprm.algo & BE_LB_LKUP_CHTREE)
					s->srv = chash_get_next_server(s->be, s->prev_srv);
				else
					s->srv = map_get_server_rr(s->be, s->prev_srv);
				break;
			}
			else if ((s->be->lbprm.algo & BE_LB_KIND) != BE_LB_KIND_HI) {
				/* unknown balancing algorithm */
				err = SRV_STATUS_INTERNAL;
				goto out;
			}

			switch (s->be->lbprm.algo & BE_LB_PARM) {
			case BE_LB_HASH_SRC:
				if (s->cli_addr.ss_family == AF_INET)
					len = 4;
				else if (s->cli_addr.ss_family == AF_INET6)
					len = 16;
				else {
					/* unknown IP family */
					err = SRV_STATUS_INTERNAL;
					goto out;
				}
		
				s->srv = get_server_sh(s->be,
						       (void *)&((struct sockaddr_in *)&s->cli_addr)->sin_addr,
						       len);
				break;

			case BE_LB_HASH_URI:
				/* URI hashing */
				s->srv = get_server_uh(s->be,
						       s->txn.req.sol + s->txn.req.sl.rq.u,
						       s->txn.req.sl.rq.u_l);
				break;

			case BE_LB_HASH_PRM:
				/* URL Parameter hashing */
				if (s->txn.meth == HTTP_METH_POST &&
				    memchr(s->txn.req.sol + s->txn.req.sl.rq.u, '&',
					   s->txn.req.sl.rq.u_l ) == NULL)
					s->srv = get_server_ph_post(s);
				else
					s->srv = get_server_ph(s->be,
							       s->txn.req.sol + s->txn.req.sl.rq.u,
							       s->txn.req.sl.rq.u_l);
				break;

			case BE_LB_HASH_HDR:
				/* Header Parameter hashing */
				s->srv = get_server_hh(s);
				break;

			case BE_LB_HASH_RDP:
				/* RDP Cookie hashing */
				s->srv = get_server_rch(s);
				break;

			default:
				/* unknown balancing algorithm */
				err = SRV_STATUS_INTERNAL;
				goto out;
			}

			/* If the hashing parameter was not found, let's fall
			 * back to round robin on the map.
			 */
			if (!s->srv) {
				if (s->be->lbprm.algo & BE_LB_LKUP_CHTREE)
					s->srv = chash_get_next_server(s->be, s->prev_srv);
				else
					s->srv = map_get_server_rr(s->be, s->prev_srv);
			}

			/* end of map-based LB */
			break;

		default:
			/* unknown balancing algorithm */
			err = SRV_STATUS_INTERNAL;
			goto out;
		}

		if (!s->srv) {
			err = SRV_STATUS_FULL;
			goto out;
		}
		else if (s->srv != s->prev_srv) {
			s->be->counters.cum_lbconn++;
			s->srv->counters.cum_lbconn++;
		}
	}
	else if (s->be->options & PR_O_HTTP_PROXY) {
		if (!s->srv_addr.sin_addr.s_addr) {
			err = SRV_STATUS_NOSRV;
			goto out;
		}
	}
	else if (!*(int *)&s->be->dispatch_addr.sin_addr &&
		 !(s->be->options & PR_O_TRANSP)) {
		err = SRV_STATUS_NOSRV;
		goto out;
	}

	s->flags |= SN_ASSIGNED;
	err = SRV_STATUS_OK;
 out:

	/* Either we take back our connection slot, or we offer it to someone
	 * else if we don't need it anymore.
	 */
	if (conn_slot) {
		if (conn_slot == s->srv) {
			sess_change_server(s, s->srv);
		} else {
			if (may_dequeue_tasks(conn_slot, s->be))
				process_srv_queue(conn_slot);
		}
	}

 out_err:
	return err;
}


/*
 * This function assigns a server address to a session, and sets SN_ADDR_SET.
 * The address is taken from the currently assigned server, or from the
 * dispatch or transparent address.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the session flag SN_ADDR_SET is set. This flag is
 * not cleared, so it's to the caller to clear it if required.
 *
 */
int assign_server_address(struct session *s)
{
#ifdef DEBUG_FULL
	fprintf(stderr,"assign_server_address : s=%p\n",s);
#endif

	if ((s->flags & SN_DIRECT) || (s->be->lbprm.algo & BE_LB_KIND)) {
		/* A server is necessarily known for this session */
		if (!(s->flags & SN_ASSIGNED))
			return SRV_STATUS_INTERNAL;

		s->srv_addr = s->srv->addr;

		/* if this server remaps proxied ports, we'll use
		 * the port the client connected to with an offset. */
		if (s->srv->state & SRV_MAPPORTS) {
			if (!(s->be->options & PR_O_TRANSP) && !(s->flags & SN_FRT_ADDR_SET))
				get_frt_addr(s);
			if (s->frt_addr.ss_family == AF_INET) {
				s->srv_addr.sin_port = htons(ntohs(s->srv_addr.sin_port) +
							     ntohs(((struct sockaddr_in *)&s->frt_addr)->sin_port));
			} else {
				s->srv_addr.sin_port = htons(ntohs(s->srv_addr.sin_port) +
							     ntohs(((struct sockaddr_in6 *)&s->frt_addr)->sin6_port));
			}
		}
	}
	else if (*(int *)&s->be->dispatch_addr.sin_addr) {
		/* connect to the defined dispatch addr */
		s->srv_addr = s->be->dispatch_addr;
	}
	else if (s->be->options & PR_O_TRANSP) {
		/* in transparent mode, use the original dest addr if no dispatch specified */
		if (!(s->flags & SN_FRT_ADDR_SET))
			get_frt_addr(s);

		memcpy(&s->srv_addr, &s->frt_addr, MIN(sizeof(s->srv_addr), sizeof(s->frt_addr)));
		/* when we support IPv6 on the backend, we may add other tests */
		//qfprintf(stderr, "Cannot get original server address.\n");
		//return SRV_STATUS_INTERNAL;
	}
	else if (s->be->options & PR_O_HTTP_PROXY) {
		/* If HTTP PROXY option is set, then server is already assigned
		 * during incoming client request parsing. */
	}
	else {
		/* no server and no LB algorithm ! */
		return SRV_STATUS_INTERNAL;
	}

	s->flags |= SN_ADDR_SET;
	return SRV_STATUS_OK;
}


/* This function assigns a server to session <s> if required, and can add the
 * connection to either the assigned server's queue or to the proxy's queue.
 * If ->srv_conn is set, the session is first released from the server.
 * It may also be called with SN_DIRECT and/or SN_ASSIGNED though. It will
 * be called before any connection and after any retry or redispatch occurs.
 *
 * It is not allowed to call this function with a session in a queue.
 *
 * Returns :
 *
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_NOSRV    if no server is available. s->srv = NULL.
 *   SRV_STATUS_QUEUED   if the connection has been queued.
 *   SRV_STATUS_FULL     if the server(s) is/are saturated and the
 *                       connection could not be queued in s->srv,
 *                       which may be NULL if we queue on the backend.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 */
int assign_server_and_queue(struct session *s)
{
	struct pendconn *p;
	int err;

	if (s->pend_pos)
		return SRV_STATUS_INTERNAL;

	err = SRV_STATUS_OK;
	if (!(s->flags & SN_ASSIGNED)) {
		err = assign_server(s);
		if (s->prev_srv) {
			/* This session was previously assigned to a server. We have to
			 * update the session's and the server's stats :
			 *  - if the server changed :
			 *    - set TX_CK_DOWN if txn.flags was TX_CK_VALID
			 *    - set SN_REDISP if it was successfully redispatched
			 *    - increment srv->redispatches and be->redispatches
			 *  - if the server remained the same : update retries.
			 */

			if (s->prev_srv != s->srv) {
				if ((s->txn.flags & TX_CK_MASK) == TX_CK_VALID) {
					s->txn.flags &= ~TX_CK_MASK;
					s->txn.flags |= TX_CK_DOWN;
				}
				s->flags |= SN_REDISP;
				s->prev_srv->counters.redispatches++;
				s->be->counters.redispatches++;
			} else {
				s->prev_srv->counters.retries++;
				s->be->counters.retries++;
			}
		}
	}

	switch (err) {
	case SRV_STATUS_OK:
		/* we have SN_ASSIGNED set */
		if (!s->srv)
			return SRV_STATUS_OK;   /* dispatch or proxy mode */

		/* If we already have a connection slot, no need to check any queue */
		if (s->srv_conn == s->srv)
			return SRV_STATUS_OK;

		/* OK, this session already has an assigned server, but no
		 * connection slot yet. Either it is a redispatch, or it was
		 * assigned from persistence information (direct mode).
		 */
		if ((s->flags & SN_REDIRECTABLE) && s->srv->rdr_len) {
			/* server scheduled for redirection, and already assigned. We
			 * don't want to go further nor check the queue.
			 */
			sess_change_server(s, s->srv); /* not really needed in fact */
			return SRV_STATUS_OK;
		}

		/* We might have to queue this session if the assigned server is full.
		 * We know we have to queue it into the server's queue, so if a maxqueue
		 * is set on the server, we must also check that the server's queue is
		 * not full, in which case we have to return FULL.
		 */
		if (s->srv->maxconn &&
		    (s->srv->nbpend || s->srv->served >= srv_dynamic_maxconn(s->srv))) {

			if (s->srv->maxqueue > 0 && s->srv->nbpend >= s->srv->maxqueue)
				return SRV_STATUS_FULL;

			p = pendconn_add(s);
			if (p)
				return SRV_STATUS_QUEUED;
			else
				return SRV_STATUS_INTERNAL;
		}

		/* OK, we can use this server. Let's reserve our place */
		sess_change_server(s, s->srv);
		return SRV_STATUS_OK;

	case SRV_STATUS_FULL:
		/* queue this session into the proxy's queue */
		p = pendconn_add(s);
		if (p)
			return SRV_STATUS_QUEUED;
		else
			return SRV_STATUS_INTERNAL;

	case SRV_STATUS_NOSRV:
		return err;

	case SRV_STATUS_INTERNAL:
		return err;

	default:
		return SRV_STATUS_INTERNAL;
	}
}

/*
 * This function initiates a connection to the server assigned to this session
 * (s->srv, s->srv_addr). It will assign a server if none is assigned yet.
 * It can return one of :
 *  - SN_ERR_NONE if everything's OK
 *  - SN_ERR_SRVTO if there are no more servers
 *  - SN_ERR_SRVCL if the connection was refused by the server
 *  - SN_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SN_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SN_ERR_INTERNAL for any other purely internal errors
 * Additionnally, in the case of SN_ERR_RESOURCE, an emergency log will be emitted.
 */
int connect_server(struct session *s)
{
	int err;

	if (!(s->flags & SN_ADDR_SET)) {
		err = assign_server_address(s);
		if (err != SRV_STATUS_OK)
			return SN_ERR_INTERNAL;
	}

	if (!s->req->cons->connect)
		return SN_ERR_INTERNAL;

	err = s->req->cons->connect(s->req->cons, s->be, s->srv,
				    (struct sockaddr *)&s->srv_addr,
				    (struct sockaddr *)&s->cli_addr);

	if (err != SN_ERR_NONE)
		return err;

	if (s->srv) {
		s->flags |= SN_CURR_SESS;
		s->srv->cur_sess++;
		if (s->srv->cur_sess > s->srv->counters.cur_sess_max)
			s->srv->counters.cur_sess_max = s->srv->cur_sess;
		if (s->be->lbprm.server_take_conn)
			s->be->lbprm.server_take_conn(s->srv);
	}

	return SN_ERR_NONE;  /* connection is OK */
}


/* This function performs the "redispatch" part of a connection attempt. It
 * will assign a server if required, queue the connection if required, and
 * handle errors that might arise at this level. It can change the server
 * state. It will return 1 if it encounters an error, switches the server
 * state, or has to queue a connection. Otherwise, it will return 0 indicating
 * that the connection is ready to use.
 */

int srv_redispatch_connect(struct session *t)
{
	int conn_err;

	/* We know that we don't have any connection pending, so we will
	 * try to get a new one, and wait in this state if it's queued
	 */
 redispatch:
	conn_err = assign_server_and_queue(t);
	switch (conn_err) {
	case SRV_STATUS_OK:
		break;

	case SRV_STATUS_FULL:
		/* The server has reached its maxqueue limit. Either PR_O_REDISP is set
		 * and we can redispatch to another server, or it is not and we return
		 * 503. This only makes sense in DIRECT mode however, because normal LB
		 * algorithms would never select such a server, and hash algorithms
		 * would bring us on the same server again. Note that t->srv is set in
		 * this case.
		 */
		if ((t->flags & SN_DIRECT) && (t->be->options & PR_O_REDISP)) {
			t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
			t->prev_srv = t->srv;
			goto redispatch;
		}

		if (!t->req->cons->err_type) {
			t->req->cons->err_type = SI_ET_QUEUE_ERR;
			t->req->cons->err_loc = t->srv;
		}

		t->srv->counters.failed_conns++;
		t->be->counters.failed_conns++;
		return 1;

	case SRV_STATUS_NOSRV:
		/* note: it is guaranteed that t->srv == NULL here */
		if (!t->req->cons->err_type) {
			t->req->cons->err_type = SI_ET_CONN_ERR;
			t->req->cons->err_loc = NULL;
		}

		t->be->counters.failed_conns++;
		return 1;

	case SRV_STATUS_QUEUED:
		t->req->cons->exp = tick_add_ifset(now_ms, t->be->timeout.queue);
		t->req->cons->state = SI_ST_QUE;
		/* do nothing else and do not wake any other session up */
		return 1;

	case SRV_STATUS_INTERNAL:
	default:
		if (!t->req->cons->err_type) {
			t->req->cons->err_type = SI_ET_CONN_OTHER;
			t->req->cons->err_loc = t->srv;
		}

		if (t->srv)
			srv_inc_sess_ctr(t->srv);
		if (t->srv)
			t->srv->counters.failed_conns++;
		t->be->counters.failed_conns++;

		/* release other sessions waiting for this server */
		if (may_dequeue_tasks(t->srv, t->be))
			process_srv_queue(t->srv);
		return 1;
	}
	/* if we get here, it's because we got SRV_STATUS_OK, which also
	 * means that the connection has not been queued.
	 */
	return 0;
}

int be_downtime(struct proxy *px) {
	if (px->lbprm.tot_weight && px->last_change < now.tv_sec)  // ignore negative time
		return px->down_time;

	return now.tv_sec - px->last_change + px->down_time;
}

/* This function parses a "balance" statement in a backend section describing
 * <curproxy>. It returns -1 if there is any error, otherwise zero. If it
 * returns -1, it may write an error message into ther <err> buffer, for at
 * most <errlen> bytes, trailing zero included. The trailing '\n' will not be
 * written. The function must be called with <args> pointing to the first word
 * after "balance".
 */
int backend_parse_balance(const char **args, char *err, int errlen, struct proxy *curproxy)
{
	if (!*(args[0])) {
		/* if no option is set, use round-robin by default */
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RR;
		return 0;
	}

	if (!strcmp(args[0], "roundrobin")) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RR;
	}
	else if (!strcmp(args[0], "static-rr")) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_SRR;
	}
	else if (!strcmp(args[0], "leastconn")) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_LC;
	}
	else if (!strcmp(args[0], "source")) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_SH;
	}
	else if (!strcmp(args[0], "uri")) {
		int arg = 1;

		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_UH;

		while (*args[arg]) {
			if (!strcmp(args[arg], "len")) {
				if (!*args[arg+1] || (atoi(args[arg+1]) <= 0)) {
					snprintf(err, errlen, "'balance uri len' expects a positive integer (got '%s').", args[arg+1]);
					return -1;
				}
				curproxy->uri_len_limit = atoi(args[arg+1]);
				arg += 2;
			}
			else if (!strcmp(args[arg], "depth")) {
				if (!*args[arg+1] || (atoi(args[arg+1]) <= 0)) {
					snprintf(err, errlen, "'balance uri depth' expects a positive integer (got '%s').", args[arg+1]);
					return -1;
				}
				/* hint: we store the position of the ending '/' (depth+1) so
				 * that we avoid a comparison while computing the hash.
				 */
				curproxy->uri_dirs_depth1 = atoi(args[arg+1]) + 1;
				arg += 2;
			}
			else {
				snprintf(err, errlen, "'balance uri' only accepts parameters 'len' and 'depth' (got '%s').", args[arg]);
				return -1;
			}
		}
	}
	else if (!strcmp(args[0], "url_param")) {
		if (!*args[1]) {
			snprintf(err, errlen, "'balance url_param' requires an URL parameter name.");
			return -1;
		}
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_PH;

		free(curproxy->url_param_name);
		curproxy->url_param_name = strdup(args[1]);
		curproxy->url_param_len  = strlen(args[1]);
		if (*args[2]) {
			if (strcmp(args[2], "check_post")) {
				snprintf(err, errlen, "'balance url_param' only accepts check_post modifier.");
				return -1;
			}
			if (*args[3]) {
				/* TODO: maybe issue a warning if there is no value, no digits or too long */
				curproxy->url_param_post_limit = str2ui(args[3]);
			}
			/* if no limit, or faul value in args[3], then default to a moderate wordlen */
			if (!curproxy->url_param_post_limit)
				curproxy->url_param_post_limit = 48;
			else if ( curproxy->url_param_post_limit < 3 )
				curproxy->url_param_post_limit = 3; /* minimum example: S=3 or \r\nS=6& */
		}
	}
	else if (!strncmp(args[0], "hdr(", 4)) {
		const char *beg, *end;

		beg = args[0] + 4;
		end = strchr(beg, ')');

		if (!end || end == beg) {
			snprintf(err, errlen, "'balance hdr(name)' requires an http header field name.");
			return -1;
		}

		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_HH;

		free(curproxy->hh_name);
		curproxy->hh_len  = end - beg;
		curproxy->hh_name = my_strndup(beg, end - beg);
		curproxy->hh_match_domain = 0;

		if (*args[1]) {
			if (strcmp(args[1], "use_domain_only")) {
				snprintf(err, errlen, "'balance hdr(name)' only accepts 'use_domain_only' modifier.");
				return -1;
			}
			curproxy->hh_match_domain = 1;
		}

	}
	else if (!strncmp(args[0], "rdp-cookie", 10)) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RCH;

		if ( *(args[0] + 10 ) == '(' ) { /* cookie name */
			const char *beg, *end;

			beg = args[0] + 11;
			end = strchr(beg, ')');

			if (!end || end == beg) {
				snprintf(err, errlen, "'balance rdp-cookie(name)' requires an rdp cookie name.");
				return -1;
			}

			free(curproxy->hh_name);
			curproxy->hh_name = my_strndup(beg, end - beg);
			curproxy->hh_len  = end - beg;
		}
		else if ( *(args[0] + 10 ) == '\0' ) { /* default cookie name 'mstshash' */
			free(curproxy->hh_name);
			curproxy->hh_name = strdup("mstshash");
			curproxy->hh_len  = strlen(curproxy->hh_name);
		}
		else { /* syntax */
			snprintf(err, errlen, "'balance rdp-cookie(name)' requires an rdp cookie name.");
			return -1;
		}
	}
	else {
		snprintf(err, errlen, "'balance' only supports 'roundrobin', 'static-rr', 'leastconn', 'source', 'uri', 'url_param', 'hdr(name)' and 'rdp-cookie(name)' options.");
		return -1;
	}
	return 0;
}


/************************************************************************/
/*             All supported keywords must be declared here.            */
/************************************************************************/

/* set test->i to the number of enabled servers on the proxy */
static int
acl_fetch_nbsrv(struct proxy *px, struct session *l4, void *l7, int dir,
                struct acl_expr *expr, struct acl_test *test)
{
	test->flags = ACL_TEST_F_VOL_TEST;
	if (expr->arg_len) {
		/* another proxy was designated, we must look for it */
		for (px = proxy; px; px = px->next)
			if ((px->cap & PR_CAP_BE) && !strcmp(px->id, expr->arg.str))
				break;
	}
	if (!px)
		return 0;

	if (px->srv_act)
		test->i = px->srv_act;
	else if (px->lbprm.fbck)
		test->i = 1;
	else
		test->i = px->srv_bck;

	return 1;
}

/* set test->i to the number of enabled servers on the proxy */
static int
acl_fetch_connslots(struct proxy *px, struct session *l4, void *l7, int dir,
		    struct acl_expr *expr, struct acl_test *test)
{
	struct server *iterator;
	test->flags = ACL_TEST_F_VOL_TEST;
	if (expr->arg_len) {
		/* another proxy was designated, we must look for it */
		for (px = proxy; px; px = px->next)
			if ((px->cap & PR_CAP_BE) && !strcmp(px->id, expr->arg.str))
				break;
	}
	if (!px)
		return 0;

	test->i = 0;
	iterator = px->srv;
	while (iterator) {
		if ((iterator->state & 1) == 0) {
			iterator = iterator->next;
			continue;
		}
		if (iterator->maxconn == 0 || iterator->maxqueue == 0) {
			test->i = -1;
			return 1;
		}

		test->i += (iterator->maxconn - iterator->cur_sess)
			+  (iterator->maxqueue - iterator->nbpend);
		iterator = iterator->next;
	}

	return 1;
}

/* set test->i to the number of connections per second reaching the frontend */
static int
acl_fetch_fe_sess_rate(struct proxy *px, struct session *l4, void *l7, int dir,
                       struct acl_expr *expr, struct acl_test *test)
{
	test->flags = ACL_TEST_F_VOL_TEST;
	if (expr->arg_len) {
		/* another proxy was designated, we must look for it */
		for (px = proxy; px; px = px->next)
			if ((px->cap & PR_CAP_FE) && !strcmp(px->id, expr->arg.str))
				break;
	}
	if (!px)
		return 0;

	test->i = read_freq_ctr(&px->fe_sess_per_sec);
	return 1;
}

/* set test->i to the number of connections per second reaching the backend */
static int
acl_fetch_be_sess_rate(struct proxy *px, struct session *l4, void *l7, int dir,
                       struct acl_expr *expr, struct acl_test *test)
{
	test->flags = ACL_TEST_F_VOL_TEST;
	if (expr->arg_len) {
		/* another proxy was designated, we must look for it */
		for (px = proxy; px; px = px->next)
			if ((px->cap & PR_CAP_BE) && !strcmp(px->id, expr->arg.str))
				break;
	}
	if (!px)
		return 0;

	test->i = read_freq_ctr(&px->be_sess_per_sec);
	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten */
static struct acl_kw_list acl_kws = {{ },{
	{ "nbsrv",    acl_parse_int,   acl_fetch_nbsrv,     acl_match_int, ACL_USE_NOTHING },
	{ "connslots", acl_parse_int,   acl_fetch_connslots, acl_match_int, ACL_USE_NOTHING },
	{ "fe_sess_rate", acl_parse_int, acl_fetch_fe_sess_rate, acl_match_int, ACL_USE_NOTHING },
	{ "be_sess_rate", acl_parse_int, acl_fetch_be_sess_rate, acl_match_int, ACL_USE_NOTHING },
	{ NULL, NULL, NULL, NULL },
}};


__attribute__((constructor))
static void __backend_init(void)
{
	acl_register_keywords(&acl_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
