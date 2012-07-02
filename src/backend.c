/*
 * Backend variables and functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
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
#include <proto/arg.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/frontend.h>
#include <proto/lb_chash.h>
#include <proto/lb_fas.h>
#include <proto/lb_fwlc.h>
#include <proto/lb_fwrr.h>
#include <proto/lb_map.h>
#include <proto/protocols.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/sock_raw.h>
#include <proto/stream_interface.h>
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
	if ((px->lbprm.algo & BE_LB_HASH_TYPE) != BE_LB_HASH_MAP)
		h = full_hash(h);
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
		else if (c == '?' && !px->uri_whole)
			break;

		hash = c + (hash << 6) + (hash << 16) - hash;
	}
	if ((px->lbprm.algo & BE_LB_HASH_TYPE) != BE_LB_HASH_MAP)
		hash = full_hash(hash);
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
				if ((px->lbprm.algo & BE_LB_HASH_TYPE) != BE_LB_HASH_MAP)
					hash = full_hash(hash);
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
	struct channel   *req = s->req;
	struct http_msg *msg  = &txn->req;
	struct proxy    *px   = s->be;
	unsigned int     plen = px->url_param_len;
	unsigned long    len  = msg->body_len;
	const char      *params = b_ptr(&req->buf, (int)(msg->sov - req->buf.o));
	const char      *p    = params;

	if (len > buffer_len(&req->buf) - msg->sov)
		len = buffer_len(&req->buf) - msg->sov;

	if (len == 0)
		return NULL;

	if (px->lbprm.tot_weight == 0)
		return NULL;

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
						/* if in a POST, body must be URI encoded or it's not a URI.
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
				if ((px->lbprm.algo & BE_LB_HASH_TYPE) != BE_LB_HASH_MAP)
					hash = full_hash(hash);
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
	http_find_header2(px->hh_name, plen, b_ptr(&s->req->buf, s->req->buf.o), &txn->hdr_idx, &ctx);

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
	if ((px->lbprm.algo & BE_LB_HASH_TYPE) != BE_LB_HASH_MAP)
		hash = full_hash(hash);
 hash_done:
	if (px->lbprm.algo & BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash);
	else
		return map_get_server_hash(px, hash);
}

/* RDP Cookie HASH.  */
struct server *get_server_rch(struct session *s)
{
	unsigned long    hash = 0;
	struct proxy    *px   = s->be;
	unsigned long    len;
	const char      *p;
	int              ret;
	struct sample    smp;
	struct arg       args[2];
	int rewind;

	/* tot_weight appears to mean srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

	memset(&smp, 0, sizeof(smp));

	args[0].type = ARGT_STR;
	args[0].data.str.str = px->hh_name;
	args[0].data.str.len = px->hh_len;
	args[1].type = ARGT_STOP;

	b_rew(s->req, rewind = s->req->buf.o);

	ret = smp_fetch_rdp_cookie(px, s, NULL, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, args, &smp);
	len = smp.data.str.len;

	b_adv(s->req, rewind);

	if (ret == 0 || (smp.flags & SMP_F_MAY_CHANGE) || len == 0)
		return NULL;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	/* Found a the hh_name in the headers.
	 * we will compute the hash based on this value ctx.val.
	 */
	p = smp.data.str.str;
	while (len) {
		hash = *p + (hash << 6) + (hash << 16) - hash;
		len--;
		p++;
	}
	if ((px->lbprm.algo & BE_LB_HASH_TYPE) != BE_LB_HASH_MAP)
		hash = full_hash(hash);
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
 * server, which should still be present in target_srv(&s->target) before the call.
 * The function tries to keep the original connection slot if it reconnects to
 * the same server, otherwise it releases it and tries to offer it.
 *
 * It is illegal to call this function with a session in a queue.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK. ->srv and ->target are assigned.
 *   SRV_STATUS_NOSRV    if no server is available. Session is not ASSIGNED
 *   SRV_STATUS_FULL     if all servers are saturated. Session is not ASSIGNED
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the session flag SN_ASSIGNED is set to indicate that
 * it does not need to be called anymore. This means that target_srv(&s->target)
 * can be trusted in balance and direct modes.
 *
 */

int assign_server(struct session *s)
{

	struct server *conn_slot;
	struct server *srv, *prev_srv;
	int err;

	DPRINTF(stderr,"assign_server : s=%p\n",s);

	err = SRV_STATUS_INTERNAL;
	if (unlikely(s->pend_pos || s->flags & SN_ASSIGNED))
		goto out_err;

	prev_srv  = target_srv(&s->target);
	conn_slot = s->srv_conn;

	/* We have to release any connection slot before applying any LB algo,
	 * otherwise we may erroneously end up with no available slot.
	 */
	if (conn_slot)
		sess_change_server(s, NULL);

	/* We will now try to find the good server and store it into <target_srv(&s->target)>.
	 * Note that <target_srv(&s->target)> may be NULL in case of dispatch or proxy mode,
	 * as well as if no server is available (check error code).
	 */

	srv = NULL;
	clear_target(&s->target);

	if (s->be->lbprm.algo & BE_LB_KIND) {
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
			srv = fwrr_get_next_server(s->be, prev_srv);
			break;

		case BE_LB_LKUP_FSTREE:
			srv = fas_get_next_server(s->be, prev_srv);
			break;

		case BE_LB_LKUP_LCTREE:
			srv = fwlc_get_next_server(s->be, prev_srv);
			break;

		case BE_LB_LKUP_CHTREE:
		case BE_LB_LKUP_MAP:
			if ((s->be->lbprm.algo & BE_LB_KIND) == BE_LB_KIND_RR) {
				if (s->be->lbprm.algo & BE_LB_LKUP_CHTREE)
					srv = chash_get_next_server(s->be, prev_srv);
				else
					srv = map_get_server_rr(s->be, prev_srv);
				break;
			}
			else if ((s->be->lbprm.algo & BE_LB_KIND) != BE_LB_KIND_HI) {
				/* unknown balancing algorithm */
				err = SRV_STATUS_INTERNAL;
				goto out;
			}

			switch (s->be->lbprm.algo & BE_LB_PARM) {
			case BE_LB_HASH_SRC:
				if (s->req->prod->addr.from.ss_family == AF_INET) {
					srv = get_server_sh(s->be,
							    (void *)&((struct sockaddr_in *)&s->req->prod->addr.from)->sin_addr,
							    4);
				}
				else if (s->req->prod->addr.from.ss_family == AF_INET6) {
					srv = get_server_sh(s->be,
							    (void *)&((struct sockaddr_in6 *)&s->req->prod->addr.from)->sin6_addr,
							    16);
				}
				else {
					/* unknown IP family */
					err = SRV_STATUS_INTERNAL;
					goto out;
				}
				break;

			case BE_LB_HASH_URI:
				/* URI hashing */
				if (s->txn.req.msg_state < HTTP_MSG_BODY)
					break;
				srv = get_server_uh(s->be,
						    b_ptr(&s->req->buf, (int)(s->txn.req.sl.rq.u - s->req->buf.o)),
						    s->txn.req.sl.rq.u_l);
				break;

			case BE_LB_HASH_PRM:
				/* URL Parameter hashing */
				if (s->txn.req.msg_state < HTTP_MSG_BODY)
					break;

				srv = get_server_ph(s->be,
						    b_ptr(&s->req->buf, (int)(s->txn.req.sl.rq.u - s->req->buf.o)),
						    s->txn.req.sl.rq.u_l);

				if (!srv && s->txn.meth == HTTP_METH_POST)
					srv = get_server_ph_post(s);
				break;

			case BE_LB_HASH_HDR:
				/* Header Parameter hashing */
				if (s->txn.req.msg_state < HTTP_MSG_BODY)
					break;
				srv = get_server_hh(s);
				break;

			case BE_LB_HASH_RDP:
				/* RDP Cookie hashing */
				srv = get_server_rch(s);
				break;

			default:
				/* unknown balancing algorithm */
				err = SRV_STATUS_INTERNAL;
				goto out;
			}

			/* If the hashing parameter was not found, let's fall
			 * back to round robin on the map.
			 */
			if (!srv) {
				if (s->be->lbprm.algo & BE_LB_LKUP_CHTREE)
					srv = chash_get_next_server(s->be, prev_srv);
				else
					srv = map_get_server_rr(s->be, prev_srv);
			}

			/* end of map-based LB */
			break;

		default:
			/* unknown balancing algorithm */
			err = SRV_STATUS_INTERNAL;
			goto out;
		}

		if (!srv) {
			err = SRV_STATUS_FULL;
			goto out;
		}
		else if (srv != prev_srv) {
			s->be->be_counters.cum_lbconn++;
			srv->counters.cum_lbconn++;
		}
		set_target_server(&s->target, srv);
	}
	else if (s->be->options & (PR_O_DISPATCH | PR_O_TRANSP)) {
		set_target_proxy(&s->target, s->be);
	}
	else if ((s->be->options & PR_O_HTTP_PROXY) &&
		 is_addr(&s->req->cons->addr.to)) {
		/* in proxy mode, we need a valid destination address */
		set_target_proxy(&s->target, s->be);
	}
	else {
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
		if (conn_slot == srv) {
			sess_change_server(s, srv);
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

		s->req->cons->addr.to = target_srv(&s->target)->addr;

		if (!is_addr(&s->req->cons->addr.to)) {
			/* if the server has no address, we use the same address
			 * the client asked, which is handy for remapping ports
			 * locally on multiple addresses at once.
			 */
			if (!(s->be->options & PR_O_TRANSP))
				si_get_to_addr(s->req->prod);

			if (s->req->prod->addr.to.ss_family == AF_INET) {
				((struct sockaddr_in *)&s->req->cons->addr.to)->sin_addr = ((struct sockaddr_in *)&s->req->prod->addr.to)->sin_addr;
			} else if (s->req->prod->addr.to.ss_family == AF_INET6) {
				((struct sockaddr_in6 *)&s->req->cons->addr.to)->sin6_addr = ((struct sockaddr_in6 *)&s->req->prod->addr.to)->sin6_addr;
			}
		}

		/* if this server remaps proxied ports, we'll use
		 * the port the client connected to with an offset. */
		if (target_srv(&s->target)->state & SRV_MAPPORTS) {
			int base_port;

			if (!(s->be->options & PR_O_TRANSP))
				si_get_to_addr(s->req->prod);

			/* First, retrieve the port from the incoming connection */
			base_port = get_host_port(&s->req->prod->addr.to);

			/* Second, assign the outgoing connection's port */
			base_port += get_host_port(&s->req->cons->addr.to);
			set_host_port(&s->req->cons->addr.to, base_port);
		}
	}
	else if (s->be->options & PR_O_DISPATCH) {
		/* connect to the defined dispatch addr */
		s->req->cons->addr.to = s->be->dispatch_addr;
	}
	else if (s->be->options & PR_O_TRANSP) {
		/* in transparent mode, use the original dest addr if no dispatch specified */
		si_get_to_addr(s->req->prod);

		if (s->req->prod->addr.to.ss_family == AF_INET || s->req->prod->addr.to.ss_family == AF_INET6) {
			memcpy(&s->req->cons->addr.to, &s->req->prod->addr.to, MIN(sizeof(s->req->cons->addr.to), sizeof(s->req->prod->addr.to)));
		}
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
 *   SRV_STATUS_NOSRV    if no server is available. target_srv(&s->target) = NULL.
 *   SRV_STATUS_QUEUED   if the connection has been queued.
 *   SRV_STATUS_FULL     if the server(s) is/are saturated and the
 *                       connection could not be queued at the server's,
 *                       which may be NULL if we queue on the backend.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 */
int assign_server_and_queue(struct session *s)
{
	struct pendconn *p;
	struct server *srv;
	int err;

	if (s->pend_pos)
		return SRV_STATUS_INTERNAL;

	err = SRV_STATUS_OK;
	if (!(s->flags & SN_ASSIGNED)) {
		struct server *prev_srv = target_srv(&s->target);

		err = assign_server(s);
		if (prev_srv) {
			/* This session was previously assigned to a server. We have to
			 * update the session's and the server's stats :
			 *  - if the server changed :
			 *    - set TX_CK_DOWN if txn.flags was TX_CK_VALID
			 *    - set SN_REDISP if it was successfully redispatched
			 *    - increment srv->redispatches and be->redispatches
			 *  - if the server remained the same : update retries.
			 */

			if (prev_srv != target_srv(&s->target)) {
				if ((s->txn.flags & TX_CK_MASK) == TX_CK_VALID) {
					s->txn.flags &= ~TX_CK_MASK;
					s->txn.flags |= TX_CK_DOWN;
				}
				s->flags |= SN_REDISP;
				prev_srv->counters.redispatches++;
				s->be->be_counters.redispatches++;
			} else {
				prev_srv->counters.retries++;
				s->be->be_counters.retries++;
			}
		}
	}

	switch (err) {
	case SRV_STATUS_OK:
		/* we have SN_ASSIGNED set */
		srv = target_srv(&s->target);
		if (!srv)
			return SRV_STATUS_OK;   /* dispatch or proxy mode */

		/* If we already have a connection slot, no need to check any queue */
		if (s->srv_conn == srv)
			return SRV_STATUS_OK;

		/* OK, this session already has an assigned server, but no
		 * connection slot yet. Either it is a redispatch, or it was
		 * assigned from persistence information (direct mode).
		 */
		if ((s->flags & SN_REDIRECTABLE) && srv->rdr_len) {
			/* server scheduled for redirection, and already assigned. We
			 * don't want to go further nor check the queue.
			 */
			sess_change_server(s, srv); /* not really needed in fact */
			return SRV_STATUS_OK;
		}

		/* We might have to queue this session if the assigned server is full.
		 * We know we have to queue it into the server's queue, so if a maxqueue
		 * is set on the server, we must also check that the server's queue is
		 * not full, in which case we have to return FULL.
		 */
		if (srv->maxconn &&
		    (srv->nbpend || srv->served >= srv_dynamic_maxconn(srv))) {

			if (srv->maxqueue > 0 && srv->nbpend >= srv->maxqueue)
				return SRV_STATUS_FULL;

			p = pendconn_add(s);
			if (p)
				return SRV_STATUS_QUEUED;
			else
				return SRV_STATUS_INTERNAL;
		}

		/* OK, we can use this server. Let's reserve our place */
		sess_change_server(s, srv);
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

/* If an explicit source binding is specified on the server and/or backend, and
 * this source makes use of the transparent proxy, then it is extracted now and
 * assigned to the session's req->cons->addr.from entry.
 */
static void assign_tproxy_address(struct session *s)
{
#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_LINUX_TPROXY)
	struct server *srv = target_srv(&s->target);

	if (srv && srv->state & SRV_BIND_SRC) {
		switch (srv->state & SRV_TPROXY_MASK) {
		case SRV_TPROXY_ADDR:
			s->req->cons->addr.from = srv->tproxy_addr;
			break;
		case SRV_TPROXY_CLI:
		case SRV_TPROXY_CIP:
			/* FIXME: what can we do if the client connects in IPv6 or unix socket ? */
			s->req->cons->addr.from = s->req->prod->addr.from;
			break;
		case SRV_TPROXY_DYN:
			if (srv->bind_hdr_occ) {
				char *vptr;
				int vlen;
				int rewind;

				/* bind to the IP in a header */
				((struct sockaddr_in *)&s->req->cons->addr.from)->sin_family = AF_INET;
				((struct sockaddr_in *)&s->req->cons->addr.from)->sin_port = 0;
				((struct sockaddr_in *)&s->req->cons->addr.from)->sin_addr.s_addr = 0;

				b_rew(s->req, rewind = s->req->buf.o);
				if (http_get_hdr(&s->txn.req, srv->bind_hdr_name, srv->bind_hdr_len,
						 &s->txn.hdr_idx, srv->bind_hdr_occ, NULL, &vptr, &vlen)) {
					((struct sockaddr_in *)&s->req->cons->addr.from)->sin_addr.s_addr =
						htonl(inetaddr_host_lim(vptr, vptr + vlen));
				}
				b_adv(s->req, rewind);
			}
			break;
		default:
			memset(&s->req->cons->addr.from, 0, sizeof(s->req->cons->addr.from));
		}
	}
	else if (s->be->options & PR_O_BIND_SRC) {
		switch (s->be->options & PR_O_TPXY_MASK) {
		case PR_O_TPXY_ADDR:
			s->req->cons->addr.from = s->be->tproxy_addr;
			break;
		case PR_O_TPXY_CLI:
		case PR_O_TPXY_CIP:
			/* FIXME: what can we do if the client connects in IPv6 or socket unix? */
			s->req->cons->addr.from = s->req->prod->addr.from;
			break;
		case PR_O_TPXY_DYN:
			if (s->be->bind_hdr_occ) {
				char *vptr;
				int vlen;
				int rewind;

				/* bind to the IP in a header */
				((struct sockaddr_in *)&s->req->cons->addr.from)->sin_family = AF_INET;
				((struct sockaddr_in *)&s->req->cons->addr.from)->sin_port = 0;
				((struct sockaddr_in *)&s->req->cons->addr.from)->sin_addr.s_addr = 0;

				b_rew(s->req, rewind = s->req->buf.o);
				if (http_get_hdr(&s->txn.req, s->be->bind_hdr_name, s->be->bind_hdr_len,
						 &s->txn.hdr_idx, s->be->bind_hdr_occ, NULL, &vptr, &vlen)) {
					((struct sockaddr_in *)&s->req->cons->addr.from)->sin_addr.s_addr =
						htonl(inetaddr_host_lim(vptr, vptr + vlen));
				}
				b_adv(s->req, rewind);
			}
			break;
		default:
			memset(&s->req->cons->addr.from, 0, sizeof(s->req->cons->addr.from));
		}
	}
#endif
}


/*
 * This function initiates a connection to the server assigned to this session
 * (s->target, s->req->cons->addr.to). It will assign a server if none
 * is assigned yet.
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
	struct server *srv;
	int err;

	if (!(s->flags & SN_ADDR_SET)) {
		err = assign_server_address(s);
		if (err != SRV_STATUS_OK)
			return SN_ERR_INTERNAL;
	}

	/* the target was only on the session, assign it to the SI now */
	copy_target(&s->req->cons->target, &s->target);

	/* set the correct protocol on the output stream interface */
	if (s->target.type == TARG_TYPE_SERVER) {
		s->req->cons->conn.ctrl = target_srv(&s->target)->proto;
		stream_interface_prepare(s->req->cons, target_srv(&s->target)->sock);
	}
	else if (s->target.type == TARG_TYPE_PROXY) {
		/* proxies exclusively run on sock_raw right now */
		s->req->cons->conn.ctrl = protocol_by_family(s->req->cons->addr.to.ss_family);
		stream_interface_prepare(s->req->cons, &sock_raw);
		if (!si_ctrl(s->req->cons))
			return SN_ERR_INTERNAL;
	}
	else
		return SN_ERR_INTERNAL;  /* how did we get there ? */

	/* process the case where the server requires the PROXY protocol to be sent */
	s->req->cons->send_proxy_ofs = 0;
	if (s->target.type == TARG_TYPE_SERVER && (s->target.ptr.s->state & SRV_SEND_PROXY)) {
		s->req->cons->send_proxy_ofs = 1; /* must compute size */
		si_get_to_addr(s->req->prod);
	}

	assign_tproxy_address(s);

	/* flag for logging source ip/port */
	if (s->fe->options2 & PR_O2_SRC_ADDR)
		s->req->cons->flags |= SI_FL_SRC_ADDR;

	err = si_connect(s->req->cons);

	if (err != SN_ERR_NONE)
		return err;

	srv = target_srv(&s->target);
	if (srv) {
		s->flags |= SN_CURR_SESS;
		srv->cur_sess++;
		if (srv->cur_sess > srv->counters.cur_sess_max)
			srv->counters.cur_sess_max = srv->cur_sess;
		if (s->be->lbprm.server_take_conn)
			s->be->lbprm.server_take_conn(srv);
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
	struct server *srv;
	int conn_err;

	/* We know that we don't have any connection pending, so we will
	 * try to get a new one, and wait in this state if it's queued
	 */
 redispatch:
	conn_err = assign_server_and_queue(t);
	srv = target_srv(&t->target);

	switch (conn_err) {
	case SRV_STATUS_OK:
		break;

	case SRV_STATUS_FULL:
		/* The server has reached its maxqueue limit. Either PR_O_REDISP is set
		 * and we can redispatch to another server, or it is not and we return
		 * 503. This only makes sense in DIRECT mode however, because normal LB
		 * algorithms would never select such a server, and hash algorithms
		 * would bring us on the same server again. Note that t->target is set
		 * in this case.
		 */
		if (((t->flags & (SN_DIRECT|SN_FORCE_PRST)) == SN_DIRECT) &&
		    (t->be->options & PR_O_REDISP)) {
			t->flags &= ~(SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET);
			goto redispatch;
		}

		if (!t->req->cons->err_type) {
			t->req->cons->err_type = SI_ET_QUEUE_ERR;
			t->req->cons->err_loc = srv;
		}

		srv->counters.failed_conns++;
		t->be->be_counters.failed_conns++;
		return 1;

	case SRV_STATUS_NOSRV:
		/* note: it is guaranteed that srv == NULL here */
		if (!t->req->cons->err_type) {
			t->req->cons->err_type = SI_ET_CONN_ERR;
			t->req->cons->err_loc = NULL;
		}

		t->be->be_counters.failed_conns++;
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
			t->req->cons->err_loc = srv;
		}

		if (srv)
			srv_inc_sess_ctr(srv);
		if (srv)
			srv->counters.failed_conns++;
		t->be->be_counters.failed_conns++;

		/* release other sessions waiting for this server */
		if (may_dequeue_tasks(srv, t->be))
			process_srv_queue(srv);
		return 1;
	}
	/* if we get here, it's because we got SRV_STATUS_OK, which also
	 * means that the connection has not been queued.
	 */
	return 0;
}

/* Apply RDP cookie persistence to the current session. For this, the function
 * tries to extract an RDP cookie from the request buffer, and look for the
 * matching server in the list. If the server is found, it is assigned to the
 * session. This always returns 1, and the analyser removes itself from the
 * list. Nothing is performed if a server was already assigned.
 */
int tcp_persist_rdp_cookie(struct session *s, struct channel *req, int an_bit)
{
	struct proxy    *px   = s->be;
	int              ret;
	struct sample    smp;
	struct server *srv = px->srv;
	struct sockaddr_in addr;
	char *p;
	struct arg       args[2];

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->i,
		req->analysers);

	if (s->flags & SN_ASSIGNED)
		goto no_cookie;

	memset(&smp, 0, sizeof(smp));

	args[0].type = ARGT_STR;
	args[0].data.str.str = s->be->rdp_cookie_name;
	args[0].data.str.len = s->be->rdp_cookie_len;
	args[1].type = ARGT_STOP;

	ret = smp_fetch_rdp_cookie(px, s, NULL, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, args, &smp);
	if (ret == 0 || (smp.flags & SMP_F_MAY_CHANGE) || smp.data.str.len == 0)
		goto no_cookie;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	/* Considering an rdp cookie detected using acl, str ended with <cr><lf> and should return */
	addr.sin_addr.s_addr = strtoul(smp.data.str.str, &p, 10);
	if (*p != '.')
		goto no_cookie;
	p++;
	addr.sin_port = (unsigned short)strtoul(p, &p, 10);
	if (*p != '.')
		goto no_cookie;

	clear_target(&s->target);
	while (srv) {
		if (memcmp(&addr, &(srv->addr), sizeof(addr)) == 0) {
			if ((srv->state & SRV_RUNNING) || (px->options & PR_O_PERSIST)) {
				/* we found the server and it is usable */
				s->flags |= SN_DIRECT | SN_ASSIGNED;
				set_target_server(&s->target, srv);
				break;
			}
		}
		srv = srv->next;
	}

no_cookie:
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;
}

int be_downtime(struct proxy *px) {
	if (px->lbprm.tot_weight && px->last_change < now.tv_sec)  // ignore negative time
		return px->down_time;

	return now.tv_sec - px->last_change + px->down_time;
}

/*
 * This function returns a string containing the balancing
 * mode of the proxy in a format suitable for stats.
 */

const char *backend_lb_algo_str(int algo) {

	if (algo == BE_LB_ALGO_RR)
		return "roundrobin";
	else if (algo == BE_LB_ALGO_SRR)
		return "static-rr";
	else if (algo == BE_LB_ALGO_FAS)
		return "first";
	else if (algo == BE_LB_ALGO_LC)
		return "leastconn";
	else if (algo == BE_LB_ALGO_SH)
		return "source";
	else if (algo == BE_LB_ALGO_UH)
		return "uri";
	else if (algo == BE_LB_ALGO_PH)
		return "url_param";
	else if (algo == BE_LB_ALGO_HH)
		return "hdr";
	else if (algo == BE_LB_ALGO_RCH)
		return "rdp-cookie";
	else
		return NULL;
}

/* This function parses a "balance" statement in a backend section describing
 * <curproxy>. It returns -1 if there is any error, otherwise zero. If it
 * returns -1, it will write an error message into the <err> buffer which will
 * automatically be allocated and must be passed as NULL. The trailing '\n'
 * will not be written. The function must be called with <args> pointing to the
 * first word after "balance".
 */
int backend_parse_balance(const char **args, char **err, struct proxy *curproxy)
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
	else if (!strcmp(args[0], "first")) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_FAS;
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

		curproxy->uri_whole = 0;

		while (*args[arg]) {
			if (!strcmp(args[arg], "len")) {
				if (!*args[arg+1] || (atoi(args[arg+1]) <= 0)) {
					memprintf(err, "%s : '%s' expects a positive integer (got '%s').", args[0], args[arg], args[arg+1]);
					return -1;
				}
				curproxy->uri_len_limit = atoi(args[arg+1]);
				arg += 2;
			}
			else if (!strcmp(args[arg], "depth")) {
				if (!*args[arg+1] || (atoi(args[arg+1]) <= 0)) {
					memprintf(err, "%s : '%s' expects a positive integer (got '%s').", args[0], args[arg], args[arg+1]);
					return -1;
				}
				/* hint: we store the position of the ending '/' (depth+1) so
				 * that we avoid a comparison while computing the hash.
				 */
				curproxy->uri_dirs_depth1 = atoi(args[arg+1]) + 1;
				arg += 2;
			}
			else if (!strcmp(args[arg], "whole")) {
				curproxy->uri_whole = 1;
				arg += 1;
			}
			else {
				memprintf(err, "%s only accepts parameters 'len', 'depth', and 'whole' (got '%s').", args[0], args[arg]);
				return -1;
			}
		}
	}
	else if (!strcmp(args[0], "url_param")) {
		if (!*args[1]) {
			memprintf(err, "%s requires an URL parameter name.", args[0]);
			return -1;
		}
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_PH;

		free(curproxy->url_param_name);
		curproxy->url_param_name = strdup(args[1]);
		curproxy->url_param_len  = strlen(args[1]);
		if (*args[2]) {
			if (strcmp(args[2], "check_post")) {
				memprintf(err, "%s only accepts 'check_post' modifier (got '%s').", args[0], args[2]);
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
			memprintf(err, "hdr requires an http header field name.");
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
				memprintf(err, "%s only accepts 'use_domain_only' modifier (got '%s').", args[0], args[1]);
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
				memprintf(err, "rdp-cookie : missing cookie name.");
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
			memprintf(err, "rdp-cookie : missing cookie name.");
			return -1;
		}
	}
	else {
		memprintf(err, "only supports 'roundrobin', 'static-rr', 'leastconn', 'source', 'uri', 'url_param', 'hdr(name)' and 'rdp-cookie(name)' options.");
		return -1;
	}
	return 0;
}


/************************************************************************/
/*             All supported keywords must be declared here.            */
/************************************************************************/

/* set temp integer to the number of enabled servers on the proxy.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
acl_fetch_nbsrv(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                const struct arg *args, struct sample *smp)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	px = args->data.prx;

	if (px->srv_act)
		smp->data.uint = px->srv_act;
	else if (px->lbprm.fbck)
		smp->data.uint = 1;
	else
		smp->data.uint = px->srv_bck;

	return 1;
}

/* report in smp->flags a success or failure depending on the designated
 * server's state. There is no match function involved since there's no pattern.
 * Accepts exactly 1 argument. Argument is a server, other types will lead to
 * undefined behaviour.
 */
static int
acl_fetch_srv_is_up(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                    const struct arg *args, struct sample *smp)
{
	struct server *srv = args->data.srv;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_BOOL;
	if (!(srv->state & SRV_MAINTAIN) &&
	    (!(srv->state & SRV_CHECKED) || (srv->state & SRV_RUNNING)))
		smp->data.uint = 1;
	else
		smp->data.uint = 0;
	return 1;
}

/* set temp integer to the number of enabled servers on the proxy.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
acl_fetch_connslots(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                    const struct arg *args, struct sample *smp)
{
	struct server *iterator;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;

	for (iterator = args->data.prx->srv; iterator; iterator = iterator->next) {
		if ((iterator->state & SRV_RUNNING) == 0)
			continue;

		if (iterator->maxconn == 0 || iterator->maxqueue == 0) {
			/* configuration is stupid */
			smp->data.uint = -1;  /* FIXME: stupid value! */
			return 1;
		}

		smp->data.uint += (iterator->maxconn - iterator->cur_sess)
		                       +  (iterator->maxqueue - iterator->nbpend);
	}

	return 1;
}

/* set temp integer to the id of the backend */
static int
acl_fetch_be_id(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                const struct arg *args, struct sample *smp)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->type = SMP_T_UINT;
	smp->data.uint = l4->be->uuid;
	return 1;
}

/* set temp integer to the id of the server */
static int
acl_fetch_srv_id(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                 const struct arg *args, struct sample *smp)
{
	if (!target_srv(&l4->target))
		return 0;

	smp->type = SMP_T_UINT;
	smp->data.uint = target_srv(&l4->target)->puid;

	return 1;
}

/* set temp integer to the number of connections per second reaching the backend.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
acl_fetch_be_sess_rate(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                       const struct arg *args, struct sample *smp)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = read_freq_ctr(&args->data.prx->be_sess_per_sec);
	return 1;
}

/* set temp integer to the number of concurrent connections on the backend.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
acl_fetch_be_conn(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                  const struct arg *args, struct sample *smp)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = args->data.prx->beconn;
	return 1;
}

/* set temp integer to the total number of queued connections on the backend.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
acl_fetch_queue_size(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                     const struct arg *args, struct sample *smp)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = args->data.prx->totpend;
	return 1;
}

/* set temp integer to the total number of queued connections on the backend divided
 * by the number of running servers and rounded up. If there is no running
 * server, we return twice the total, just as if we had half a running server.
 * This is more or less correct anyway, since we expect the last server to come
 * back soon.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
acl_fetch_avg_queue_size(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                         const struct arg *args, struct sample *smp)
{
	int nbsrv;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	px = args->data.prx;

	if (px->srv_act)
		nbsrv = px->srv_act;
	else if (px->lbprm.fbck)
		nbsrv = 1;
	else
		nbsrv = px->srv_bck;

	if (nbsrv > 0)
		smp->data.uint = (px->totpend + nbsrv - 1) / nbsrv;
	else
		smp->data.uint = px->totpend * 2;

	return 1;
}

/* set temp integer to the number of concurrent connections on the server in the backend.
 * Accepts exactly 1 argument. Argument is a server, other types will lead to
 * undefined behaviour.
 */
static int
acl_fetch_srv_conn(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                   const struct arg *args, struct sample *smp)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = args->data.srv->cur_sess;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {{ },{
	{ "avg_queue",    acl_parse_int,     acl_fetch_avg_queue_size, acl_match_int,     ACL_USE_NOTHING, ARG1(1,BE) },
	{ "be_conn",      acl_parse_int,     acl_fetch_be_conn,        acl_match_int,     ACL_USE_NOTHING, ARG1(1,BE) },
	{ "be_id",        acl_parse_int,     acl_fetch_be_id,          acl_match_int,     ACL_USE_NOTHING, 0 },
	{ "be_sess_rate", acl_parse_int,     acl_fetch_be_sess_rate,   acl_match_int,     ACL_USE_NOTHING, ARG1(1,BE) },
	{ "connslots",    acl_parse_int,     acl_fetch_connslots,      acl_match_int,     ACL_USE_NOTHING, ARG1(1,BE) },
	{ "nbsrv",        acl_parse_int,     acl_fetch_nbsrv,          acl_match_int,     ACL_USE_NOTHING, ARG1(1,BE) },
	{ "queue",        acl_parse_int,     acl_fetch_queue_size,     acl_match_int,     ACL_USE_NOTHING, ARG1(1,BE) },
	{ "srv_conn",     acl_parse_int,     acl_fetch_srv_conn,       acl_match_int,     ACL_USE_NOTHING, ARG1(1,SRV) },
	{ "srv_id",       acl_parse_int,     acl_fetch_srv_id,         acl_match_int,     ACL_USE_RTR_INTERNAL, 0 },
	{ "srv_is_up",    acl_parse_nothing, acl_fetch_srv_is_up,      acl_match_nothing, ACL_USE_NOTHING, ARG1(1,SRV) },
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
