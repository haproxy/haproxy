/*
 * Backend variables and functions.
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
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/hash.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/namespace.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/frontend.h>
#include <proto/lb_chash.h>
#include <proto/lb_fas.h>
#include <proto/lb_fwlc.h>
#include <proto/lb_fwrr.h>
#include <proto/lb_map.h>
#include <proto/log.h>
#include <proto/obj_type.h>
#include <proto/payload.h>
#include <proto/protocol.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/sample.h>
#include <proto/server.h>
#include <proto/stream.h>
#include <proto/raw_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#endif /* USE_OPENSSL */

int be_lastsession(const struct proxy *be)
{
	if (be->be_counters.last_sess)
		return now.tv_sec - be->be_counters.last_sess;

	return -1;
}

/* helper function to invoke the correct hash method */
static unsigned int gen_hash(const struct proxy* px, const char* key, unsigned long len)
{
	unsigned int hash;

	switch (px->lbprm.algo & BE_LB_HASH_FUNC) {
	case BE_LB_HFCN_DJB2:
		hash = hash_djb2(key, len);
		break;
	case BE_LB_HFCN_WT6:
		hash = hash_wt6(key, len);
		break;
	case BE_LB_HFCN_CRC32:
		hash = hash_crc32(key, len);
		break;
	case BE_LB_HFCN_SDBM:
		/* this is the default hash function */
	default:
		hash = hash_sdbm(key, len);
		break;
	}

	return hash;
}

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
		if (!srv_is_usable(srv))
			continue;

		if (srv->flags & SRV_F_BACKUP) {
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
	if ((px->lbprm.algo & BE_LB_HASH_MOD) == BE_LB_HMOD_AVAL)
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
	unsigned int hash = 0;
	int c;
	int slashes = 0;
	const char *start, *end;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	if (px->uri_len_limit)
		uri_len = MIN(uri_len, px->uri_len_limit);

	start = end = uri;
	while (uri_len--) {
		c = *end;
		if (c == '/') {
			slashes++;
			if (slashes == px->uri_dirs_depth1) /* depth+1 */
				break;
		}
		else if (c == '?' && !px->uri_whole)
			break;
		end++;
	}

	hash = gen_hash(px, start, (end - start));

	if ((px->lbprm.algo & BE_LB_HASH_MOD) == BE_LB_HMOD_AVAL)
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
	unsigned int hash = 0;
	const char *start, *end;
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
				start = end = p;
				uri_len -= plen + 1;

				while (uri_len && *end != '&') {
					uri_len--;
					end++;
				}
				hash = gen_hash(px, start, (end - start));

				if ((px->lbprm.algo & BE_LB_HASH_MOD) == BE_LB_HMOD_AVAL)
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
struct server *get_server_ph_post(struct stream *s)
{
	unsigned int hash = 0;
	struct http_txn *txn  = s->txn;
	struct channel  *req  = &s->req;
	struct http_msg *msg  = &txn->req;
	struct proxy    *px   = s->be;
	unsigned int     plen = px->url_param_len;
	unsigned long    len  = http_body_bytes(msg);
	const char      *params = b_ptr(req->buf, -http_data_rewind(msg));
	const char      *p    = params;
	const char      *start, *end;

	if (len == 0)
		return NULL;

	if (len > req->buf->data + req->buf->size - p)
		len = req->buf->data + req->buf->size - p;

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
				start = end = p;
				len -= plen + 1;

				while (len && *end != '&') {
					if (unlikely(!HTTP_IS_TOKEN(*p))) {
						/* if in a POST, body must be URI encoded or it's not a URI.
						 * Do not interpret any possible binary data as a parameter.
						 */
						if (likely(HTTP_IS_LWS(*p))) /* eol, uncertain uri len */
							break;
						return NULL;                 /* oh, no; this is not uri-encoded.
									      * This body does not contain parameters.
									      */
					}
					len--;
					end++;
					/* should we break if vlen exceeds limit? */
				}
				hash = gen_hash(px, start, (end - start));

				if ((px->lbprm.algo & BE_LB_HASH_MOD) == BE_LB_HMOD_AVAL)
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
struct server *get_server_hh(struct stream *s)
{
	unsigned int hash = 0;
	struct http_txn *txn  = s->txn;
	struct proxy    *px   = s->be;
	unsigned int     plen = px->hh_len;
	unsigned long    len;
	struct hdr_ctx   ctx;
	const char      *p;
	const char *start, *end;

	/* tot_weight appears to mean srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

	ctx.idx = 0;

	/* if the message is chunked, we skip the chunk size, but use the value as len */
	http_find_header2(px->hh_name, plen, b_ptr(s->req.buf, -http_hdr_rewind(&txn->req)), &txn->hdr_idx, &ctx);

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
		hash = gen_hash(px, p, len);
	} else {
		int dohash = 0;
		p += len;
		/* special computation, use only main domain name, not tld/host
		 * going back from the end of string, start hashing at first
		 * dot stop at next.
		 * This is designed to work with the 'Host' header, and requires
		 * a special option to activate this.
		 */
		end = p;
		while (len) {
			if (dohash) {
				/* Rewind the pointer until the previous char
				 * is a dot, this will allow to set the start
				 * position of the domain. */
				if (*(p - 1) == '.')
					break;
			}
			else if (*p == '.') {
				/* The pointer is rewinded to the dot before the
				 * tld, we memorize the end of the domain and
				 * can enter the domain processing. */
				end = p;
				dohash = 1;
			}
			p--;
			len--;
		}
		start = p;
		hash = gen_hash(px, start, (end - start));
	}
	if ((px->lbprm.algo & BE_LB_HASH_MOD) == BE_LB_HMOD_AVAL)
		hash = full_hash(hash);
 hash_done:
	if (px->lbprm.algo & BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash);
	else
		return map_get_server_hash(px, hash);
}

/* RDP Cookie HASH.  */
struct server *get_server_rch(struct stream *s)
{
	unsigned int hash = 0;
	struct proxy    *px   = s->be;
	unsigned long    len;
	int              ret;
	struct sample    smp;
	int rewind;

	/* tot_weight appears to mean srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

	memset(&smp, 0, sizeof(smp));

	b_rew(s->req.buf, rewind = s->req.buf->o);

	ret = fetch_rdp_cookie_name(s, &smp, px->hh_name, px->hh_len);
	len = smp.data.str.len;

	b_adv(s->req.buf, rewind);

	if (ret == 0 || (smp.flags & SMP_F_MAY_CHANGE) || len == 0)
		return NULL;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	/* Found a the hh_name in the headers.
	 * we will compute the hash based on this value ctx.val.
	 */
	hash = gen_hash(px, smp.data.str.str, len);

	if ((px->lbprm.algo & BE_LB_HASH_MOD) == BE_LB_HMOD_AVAL)
		hash = full_hash(hash);
 hash_done:
	if (px->lbprm.algo & BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash);
	else
		return map_get_server_hash(px, hash);
}
 
/*
 * This function applies the load-balancing algorithm to the stream, as
 * defined by the backend it is assigned to. The stream is then marked as
 * 'assigned'.
 *
 * This function MAY NOT be called with SF_ASSIGNED already set. If the stream
 * had a server previously assigned, it is rebalanced, trying to avoid the same
 * server, which should still be present in target_srv(&s->target) before the call.
 * The function tries to keep the original connection slot if it reconnects to
 * the same server, otherwise it releases it and tries to offer it.
 *
 * It is illegal to call this function with a stream in a queue.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK. ->srv and ->target are assigned.
 *   SRV_STATUS_NOSRV    if no server is available. Stream is not ASSIGNED
 *   SRV_STATUS_FULL     if all servers are saturated. Stream is not ASSIGNED
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the stream flag SF_ASSIGNED is set to indicate that
 * it does not need to be called anymore. This means that target_srv(&s->target)
 * can be trusted in balance and direct modes.
 *
 */

int assign_server(struct stream *s)
{
	struct connection *conn;
	struct server *conn_slot;
	struct server *srv, *prev_srv;
	int err;

	DPRINTF(stderr,"assign_server : s=%p\n",s);

	err = SRV_STATUS_INTERNAL;
	if (unlikely(s->pend_pos || s->flags & SF_ASSIGNED))
		goto out_err;

	prev_srv  = objt_server(s->target);
	conn_slot = s->srv_conn;

	/* We have to release any connection slot before applying any LB algo,
	 * otherwise we may erroneously end up with no available slot.
	 */
	if (conn_slot)
		sess_change_server(s, NULL);

	/* We will now try to find the good server and store it into <objt_server(s->target)>.
	 * Note that <objt_server(s->target)> may be NULL in case of dispatch or proxy mode,
	 * as well as if no server is available (check error code).
	 */

	srv = NULL;
	s->target = NULL;
	conn = objt_conn(s->si[1].end);

	if (conn &&
	    (conn->flags & CO_FL_CONNECTED) &&
	    objt_server(conn->target) && __objt_server(conn->target)->proxy == s->be &&
	    ((s->txn && s->txn->flags & TX_PREFER_LAST) ||
	     ((s->be->options & PR_O_PREF_LAST) &&
	      (!s->be->max_ka_queue ||
	       server_has_room(__objt_server(conn->target)) ||
	       (__objt_server(conn->target)->nbpend + 1) < s->be->max_ka_queue))) &&
	    srv_is_usable(__objt_server(conn->target))) {
		/* This stream was relying on a server in a previous request
		 * and the proxy has "option prefer-last-server" set, so
		 * let's try to reuse the same server.
		 */
		srv = __objt_server(conn->target);
		s->target = &srv->obj_type;
	}
	else if (s->be->lbprm.algo & BE_LB_KIND) {
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
				conn = objt_conn(strm_orig(s));
				if (conn && conn->addr.from.ss_family == AF_INET) {
					srv = get_server_sh(s->be,
							    (void *)&((struct sockaddr_in *)&conn->addr.from)->sin_addr,
							    4);
				}
				else if (conn && conn->addr.from.ss_family == AF_INET6) {
					srv = get_server_sh(s->be,
							    (void *)&((struct sockaddr_in6 *)&conn->addr.from)->sin6_addr,
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
				if (!s->txn || s->txn->req.msg_state < HTTP_MSG_BODY)
					break;
				srv = get_server_uh(s->be,
						    b_ptr(s->req.buf, -http_uri_rewind(&s->txn->req)),
						    s->txn->req.sl.rq.u_l);
				break;

			case BE_LB_HASH_PRM:
				/* URL Parameter hashing */
				if (!s->txn || s->txn->req.msg_state < HTTP_MSG_BODY)
					break;

				srv = get_server_ph(s->be,
						    b_ptr(s->req.buf, -http_uri_rewind(&s->txn->req)),
						    s->txn->req.sl.rq.u_l);

				if (!srv && s->txn->meth == HTTP_METH_POST)
					srv = get_server_ph_post(s);
				break;

			case BE_LB_HASH_HDR:
				/* Header Parameter hashing */
				if (!s->txn || s->txn->req.msg_state < HTTP_MSG_BODY)
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
		s->target = &srv->obj_type;
	}
	else if (s->be->options & (PR_O_DISPATCH | PR_O_TRANSP)) {
		s->target = &s->be->obj_type;
	}
	else if ((s->be->options & PR_O_HTTP_PROXY) &&
		 (conn = objt_conn(s->si[1].end)) &&
		 is_addr(&conn->addr.to)) {
		/* in proxy mode, we need a valid destination address */
		s->target = &s->be->obj_type;
	}
	else {
		err = SRV_STATUS_NOSRV;
		goto out;
	}

	s->flags |= SF_ASSIGNED;
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
 * This function assigns a server address to a stream, and sets SF_ADDR_SET.
 * The address is taken from the currently assigned server, or from the
 * dispatch or transparent address.
 *
 * It may return :
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 * Upon successful return, the stream flag SF_ADDR_SET is set. This flag is
 * not cleared, so it's to the caller to clear it if required.
 *
 * The caller is responsible for having already assigned a connection
 * to si->end.
 *
 */
int assign_server_address(struct stream *s)
{
	struct connection *cli_conn = objt_conn(strm_orig(s));
	struct connection *srv_conn = objt_conn(s->si[1].end);

#ifdef DEBUG_FULL
	fprintf(stderr,"assign_server_address : s=%p\n",s);
#endif

	if ((s->flags & SF_DIRECT) || (s->be->lbprm.algo & BE_LB_KIND)) {
		/* A server is necessarily known for this stream */
		if (!(s->flags & SF_ASSIGNED))
			return SRV_STATUS_INTERNAL;

		srv_conn->addr.to = objt_server(s->target)->addr;

		if (!is_addr(&srv_conn->addr.to) && cli_conn) {
			/* if the server has no address, we use the same address
			 * the client asked, which is handy for remapping ports
			 * locally on multiple addresses at once. Nothing is done
			 * for AF_UNIX addresses.
			 */
			conn_get_to_addr(cli_conn);

			if (cli_conn->addr.to.ss_family == AF_INET) {
				((struct sockaddr_in *)&srv_conn->addr.to)->sin_addr = ((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr;
			} else if (cli_conn->addr.to.ss_family == AF_INET6) {
				((struct sockaddr_in6 *)&srv_conn->addr.to)->sin6_addr = ((struct sockaddr_in6 *)&cli_conn->addr.to)->sin6_addr;
			}
		}

		/* if this server remaps proxied ports, we'll use
		 * the port the client connected to with an offset. */
		if ((objt_server(s->target)->flags & SRV_F_MAPPORTS) && cli_conn) {
			int base_port;

			conn_get_to_addr(cli_conn);

			/* First, retrieve the port from the incoming connection */
			base_port = get_host_port(&cli_conn->addr.to);

			/* Second, assign the outgoing connection's port */
			base_port += get_host_port(&srv_conn->addr.to);
			set_host_port(&srv_conn->addr.to, base_port);
		}
	}
	else if (s->be->options & PR_O_DISPATCH) {
		/* connect to the defined dispatch addr */
		srv_conn->addr.to = s->be->dispatch_addr;
	}
	else if ((s->be->options & PR_O_TRANSP) && cli_conn) {
		/* in transparent mode, use the original dest addr if no dispatch specified */
		conn_get_to_addr(cli_conn);

		if (cli_conn->addr.to.ss_family == AF_INET || cli_conn->addr.to.ss_family == AF_INET6)
			srv_conn->addr.to = cli_conn->addr.to;
	}
	else if (s->be->options & PR_O_HTTP_PROXY) {
		/* If HTTP PROXY option is set, then server is already assigned
		 * during incoming client request parsing. */
	}
	else {
		/* no server and no LB algorithm ! */
		return SRV_STATUS_INTERNAL;
	}

	/* Copy network namespace from client connection */
	srv_conn->proxy_netns = cli_conn ? cli_conn->proxy_netns : NULL;

	s->flags |= SF_ADDR_SET;
	return SRV_STATUS_OK;
}

/* This function assigns a server to stream <s> if required, and can add the
 * connection to either the assigned server's queue or to the proxy's queue.
 * If ->srv_conn is set, the stream is first released from the server.
 * It may also be called with SF_DIRECT and/or SF_ASSIGNED though. It will
 * be called before any connection and after any retry or redispatch occurs.
 *
 * It is not allowed to call this function with a stream in a queue.
 *
 * Returns :
 *
 *   SRV_STATUS_OK       if everything is OK.
 *   SRV_STATUS_NOSRV    if no server is available. objt_server(s->target) = NULL.
 *   SRV_STATUS_QUEUED   if the connection has been queued.
 *   SRV_STATUS_FULL     if the server(s) is/are saturated and the
 *                       connection could not be queued at the server's,
 *                       which may be NULL if we queue on the backend.
 *   SRV_STATUS_INTERNAL for other unrecoverable errors.
 *
 */
int assign_server_and_queue(struct stream *s)
{
	struct pendconn *p;
	struct server *srv;
	int err;

	if (s->pend_pos)
		return SRV_STATUS_INTERNAL;

	err = SRV_STATUS_OK;
	if (!(s->flags & SF_ASSIGNED)) {
		struct server *prev_srv = objt_server(s->target);

		err = assign_server(s);
		if (prev_srv) {
			/* This stream was previously assigned to a server. We have to
			 * update the stream's and the server's stats :
			 *  - if the server changed :
			 *    - set TX_CK_DOWN if txn.flags was TX_CK_VALID
			 *    - set SF_REDISP if it was successfully redispatched
			 *    - increment srv->redispatches and be->redispatches
			 *  - if the server remained the same : update retries.
			 */

			if (prev_srv != objt_server(s->target)) {
				if (s->txn && (s->txn->flags & TX_CK_MASK) == TX_CK_VALID) {
					s->txn->flags &= ~TX_CK_MASK;
					s->txn->flags |= TX_CK_DOWN;
				}
				s->flags |= SF_REDISP;
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
		/* we have SF_ASSIGNED set */
		srv = objt_server(s->target);
		if (!srv)
			return SRV_STATUS_OK;   /* dispatch or proxy mode */

		/* If we already have a connection slot, no need to check any queue */
		if (s->srv_conn == srv)
			return SRV_STATUS_OK;

		/* OK, this stream already has an assigned server, but no
		 * connection slot yet. Either it is a redispatch, or it was
		 * assigned from persistence information (direct mode).
		 */
		if ((s->flags & SF_REDIRECTABLE) && srv->rdr_len) {
			/* server scheduled for redirection, and already assigned. We
			 * don't want to go further nor check the queue.
			 */
			sess_change_server(s, srv); /* not really needed in fact */
			return SRV_STATUS_OK;
		}

		/* We might have to queue this stream if the assigned server is full.
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
		/* queue this stream into the proxy's queue */
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
 * assigned to the stream's pending connection. This function assumes that an
 * outgoing connection has already been assigned to s->si[1].end.
 */
static void assign_tproxy_address(struct stream *s)
{
#if defined(CONFIG_HAP_CTTPROXY) || defined(CONFIG_HAP_TRANSPARENT)
	struct server *srv = objt_server(s->target);
	struct conn_src *src;
	struct connection *cli_conn;
	struct connection *srv_conn = objt_conn(s->si[1].end);

	if (srv && srv->conn_src.opts & CO_SRC_BIND)
		src = &srv->conn_src;
	else if (s->be->conn_src.opts & CO_SRC_BIND)
		src = &s->be->conn_src;
	else
		return;

	switch (src->opts & CO_SRC_TPROXY_MASK) {
	case CO_SRC_TPROXY_ADDR:
		srv_conn->addr.from = src->tproxy_addr;
		break;
	case CO_SRC_TPROXY_CLI:
	case CO_SRC_TPROXY_CIP:
		/* FIXME: what can we do if the client connects in IPv6 or unix socket ? */
		cli_conn = objt_conn(strm_orig(s));
		if (cli_conn)
			srv_conn->addr.from = cli_conn->addr.from;
		else
			memset(&srv_conn->addr.from, 0, sizeof(srv_conn->addr.from));
		break;
	case CO_SRC_TPROXY_DYN:
		if (src->bind_hdr_occ && s->txn) {
			char *vptr;
			int vlen;
			int rewind;

			/* bind to the IP in a header */
			((struct sockaddr_in *)&srv_conn->addr.from)->sin_family = AF_INET;
			((struct sockaddr_in *)&srv_conn->addr.from)->sin_port = 0;
			((struct sockaddr_in *)&srv_conn->addr.from)->sin_addr.s_addr = 0;

			b_rew(s->req.buf, rewind = http_hdr_rewind(&s->txn->req));
			if (http_get_hdr(&s->txn->req, src->bind_hdr_name, src->bind_hdr_len,
					 &s->txn->hdr_idx, src->bind_hdr_occ, NULL, &vptr, &vlen)) {
				((struct sockaddr_in *)&srv_conn->addr.from)->sin_addr.s_addr =
					htonl(inetaddr_host_lim(vptr, vptr + vlen));
			}
			b_adv(s->req.buf, rewind);
		}
		break;
	default:
		memset(&srv_conn->addr.from, 0, sizeof(srv_conn->addr.from));
	}
#endif
}


/*
 * This function initiates a connection to the server assigned to this stream
 * (s->target, s->si[1].addr.to). It will assign a server if none
 * is assigned yet.
 * It can return one of :
 *  - SF_ERR_NONE if everything's OK
 *  - SF_ERR_SRVTO if there are no more servers
 *  - SF_ERR_SRVCL if the connection was refused by the server
 *  - SF_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SF_ERR_INTERNAL for any other purely internal errors
 * Additionnally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
 * The server-facing stream interface is expected to hold a pre-allocated connection
 * in s->si[1].conn.
 */
int connect_server(struct stream *s)
{
	struct connection *cli_conn;
	struct connection *srv_conn;
	struct server *srv;
	int reuse = 0;
	int err;

	srv_conn = objt_conn(s->si[1].end);
	if (srv_conn)
		reuse = s->target == srv_conn->target;

	if (reuse) {
		/* Disable connection reuse if a dynamic source is used.
		 * As long as we don't share connections between servers,
		 * we don't need to disable connection reuse on no-idempotent
		 * requests nor when PROXY protocol is used.
		 */
		srv = objt_server(s->target);
		if (srv && srv->conn_src.opts & CO_SRC_BIND) {
			if ((srv->conn_src.opts & CO_SRC_TPROXY_MASK) == CO_SRC_TPROXY_DYN)
				reuse = 0;
		}
		else if (s->be->conn_src.opts & CO_SRC_BIND) {
			if ((s->be->conn_src.opts & CO_SRC_TPROXY_MASK) == CO_SRC_TPROXY_DYN)
				reuse = 0;
		}
	}

	srv_conn = si_alloc_conn(&s->si[1], reuse);
	if (!srv_conn)
		return SF_ERR_RESOURCE;

	if (!(s->flags & SF_ADDR_SET)) {
		err = assign_server_address(s);
		if (err != SRV_STATUS_OK)
			return SF_ERR_INTERNAL;
	}

	if (!conn_xprt_ready(srv_conn)) {
		/* the target was only on the stream, assign it to the SI now */
		srv_conn->target = s->target;

		/* set the correct protocol on the output stream interface */
		if (objt_server(s->target)) {
			conn_prepare(srv_conn, protocol_by_family(srv_conn->addr.to.ss_family), objt_server(s->target)->xprt);
		}
		else if (obj_type(s->target) == OBJ_TYPE_PROXY) {
			/* proxies exclusively run on raw_sock right now */
			conn_prepare(srv_conn, protocol_by_family(srv_conn->addr.to.ss_family), &raw_sock);
			if (!objt_conn(s->si[1].end) || !objt_conn(s->si[1].end)->ctrl)
				return SF_ERR_INTERNAL;
		}
		else
			return SF_ERR_INTERNAL;  /* how did we get there ? */

		/* process the case where the server requires the PROXY protocol to be sent */
		srv_conn->send_proxy_ofs = 0;
		if (objt_server(s->target) && objt_server(s->target)->pp_opts) {
			srv_conn->send_proxy_ofs = 1; /* must compute size */
			cli_conn = objt_conn(strm_orig(s));
			if (cli_conn)
				conn_get_to_addr(cli_conn);
		}

		si_attach_conn(&s->si[1], srv_conn);

		assign_tproxy_address(s);
	}
	else {
		/* the connection is being reused, just re-attach it */
		si_attach_conn(&s->si[1], srv_conn);
		s->flags |= SF_SRV_REUSED;
	}

	/* flag for logging source ip/port */
	if (strm_fe(s)->options2 & PR_O2_SRC_ADDR)
		s->si[1].flags |= SI_FL_SRC_ADDR;

	/* disable lingering */
	if (s->be->options & PR_O_TCP_NOLING)
		s->si[1].flags |= SI_FL_NOLINGER;

	err = si_connect(&s->si[1]);

	if (err != SF_ERR_NONE)
		return err;

	/* set connect timeout */
	s->si[1].exp = tick_add_ifset(now_ms, s->be->timeout.connect);

	srv = objt_server(s->target);
	if (srv) {
		s->flags |= SF_CURR_SESS;
		srv->cur_sess++;
		if (srv->cur_sess > srv->counters.cur_sess_max)
			srv->counters.cur_sess_max = srv->cur_sess;
		if (s->be->lbprm.server_take_conn)
			s->be->lbprm.server_take_conn(srv);

#ifdef USE_OPENSSL
		if (srv->ssl_ctx.sni) {
			struct sample *smp;
			int rewind;

			/* Tricky case : we have already scheduled the pending
			 * HTTP request or TCP data for leaving. So in HTTP we
			 * rewind exactly the headers, otherwise we rewind the
			 * output data.
			 */
			rewind = s->txn ? http_hdr_rewind(&s->txn->req) : s->req.buf->o;
			b_rew(s->req.buf, rewind);

			smp = sample_fetch_as_type(s->be, s->sess, s, SMP_OPT_DIR_REQ | SMP_OPT_FINAL, srv->ssl_ctx.sni, SMP_T_STR);

			/* restore the pointers */
			b_adv(s->req.buf, rewind);

			if (smp) {
				/* get write access to terminate with a zero */
				smp_dup(smp);
				if (smp->data.str.len >= smp->data.str.size)
					smp->data.str.len = smp->data.str.size - 1;
				smp->data.str.str[smp->data.str.len] = 0;
				ssl_sock_set_servername(srv_conn, smp->data.str.str);
			}
		}
#endif /* USE_OPENSSL */

	}

	return SF_ERR_NONE;  /* connection is OK */
}


/* This function performs the "redispatch" part of a connection attempt. It
 * will assign a server if required, queue the connection if required, and
 * handle errors that might arise at this level. It can change the server
 * state. It will return 1 if it encounters an error, switches the server
 * state, or has to queue a connection. Otherwise, it will return 0 indicating
 * that the connection is ready to use.
 */

int srv_redispatch_connect(struct stream *s)
{
	struct server *srv;
	int conn_err;

	/* We know that we don't have any connection pending, so we will
	 * try to get a new one, and wait in this state if it's queued
	 */
 redispatch:
	conn_err = assign_server_and_queue(s);
	srv = objt_server(s->target);

	switch (conn_err) {
	case SRV_STATUS_OK:
		break;

	case SRV_STATUS_FULL:
		/* The server has reached its maxqueue limit. Either PR_O_REDISP is set
		 * and we can redispatch to another server, or it is not and we return
		 * 503. This only makes sense in DIRECT mode however, because normal LB
		 * algorithms would never select such a server, and hash algorithms
		 * would bring us on the same server again. Note that s->target is set
		 * in this case.
		 */
		if (((s->flags & (SF_DIRECT|SF_FORCE_PRST)) == SF_DIRECT) &&
		    (s->be->options & PR_O_REDISP)) {
			s->flags &= ~(SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);
			goto redispatch;
		}

		if (!s->si[1].err_type) {
			s->si[1].err_type = SI_ET_QUEUE_ERR;
		}

		srv->counters.failed_conns++;
		s->be->be_counters.failed_conns++;
		return 1;

	case SRV_STATUS_NOSRV:
		/* note: it is guaranteed that srv == NULL here */
		if (!s->si[1].err_type) {
			s->si[1].err_type = SI_ET_CONN_ERR;
		}

		s->be->be_counters.failed_conns++;
		return 1;

	case SRV_STATUS_QUEUED:
		s->si[1].exp = tick_add_ifset(now_ms, s->be->timeout.queue);
		s->si[1].state = SI_ST_QUE;
		/* do nothing else and do not wake any other stream up */
		return 1;

	case SRV_STATUS_INTERNAL:
	default:
		if (!s->si[1].err_type) {
			s->si[1].err_type = SI_ET_CONN_OTHER;
		}

		if (srv)
			srv_inc_sess_ctr(srv);
		if (srv)
			srv_set_sess_last(srv);
		if (srv)
			srv->counters.failed_conns++;
		s->be->be_counters.failed_conns++;

		/* release other streams waiting for this server */
		if (may_dequeue_tasks(srv, s->be))
			process_srv_queue(srv);
		return 1;
	}
	/* if we get here, it's because we got SRV_STATUS_OK, which also
	 * means that the connection has not been queued.
	 */
	return 0;
}

/* sends a log message when a backend goes down, and also sets last
 * change date.
 */
void set_backend_down(struct proxy *be)
{
	be->last_change = now.tv_sec;
	be->down_trans++;

	Alert("%s '%s' has no server available!\n", proxy_type_str(be), be->id);
	send_log(be, LOG_EMERG, "%s %s has no server available!\n", proxy_type_str(be), be->id);
}

/* Apply RDP cookie persistence to the current stream. For this, the function
 * tries to extract an RDP cookie from the request buffer, and look for the
 * matching server in the list. If the server is found, it is assigned to the
 * stream. This always returns 1, and the analyser removes itself from the
 * list. Nothing is performed if a server was already assigned.
 */
int tcp_persist_rdp_cookie(struct stream *s, struct channel *req, int an_bit)
{
	struct proxy    *px   = s->be;
	int              ret;
	struct sample    smp;
	struct server *srv = px->srv;
	struct sockaddr_in addr;
	char *p;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->buf->i,
		req->analysers);

	if (s->flags & SF_ASSIGNED)
		goto no_cookie;

	memset(&smp, 0, sizeof(smp));

	ret = fetch_rdp_cookie_name(s, &smp, s->be->rdp_cookie_name, s->be->rdp_cookie_len);
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

	s->target = NULL;
	while (srv) {
		if (srv->addr.ss_family == AF_INET &&
		    memcmp(&addr, &(srv->addr), sizeof(addr)) == 0) {
			if ((srv->state != SRV_ST_STOPPED) || (px->options & PR_O_PERSIST)) {
				/* we found the server and it is usable */
				s->flags |= SF_DIRECT | SF_ASSIGNED;
				s->target = &srv->obj_type;
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
/*      All supported sample and ACL keywords must be declared here.    */
/************************************************************************/

/* set temp integer to the number of enabled servers on the proxy.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_nbsrv(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct proxy *px;

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
smp_fetch_srv_is_up(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct server *srv = args->data.srv;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_BOOL;
	if (!(srv->admin & SRV_ADMF_MAINT) &&
	    (!(srv->check.state & CHK_ST_CONFIGURED) || (srv->state != SRV_ST_STOPPED)))
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
smp_fetch_connslots(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct server *iterator;

	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = 0;

	for (iterator = args->data.prx->srv; iterator; iterator = iterator->next) {
		if (iterator->state == SRV_ST_STOPPED)
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
smp_fetch_be_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TXN;
	smp->type = SMP_T_UINT;
	smp->data.uint = smp->strm->be->uuid;
	return 1;
}

/* set temp integer to the id of the server */
static int
smp_fetch_srv_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!objt_server(smp->strm->target))
		return 0;

	smp->type = SMP_T_UINT;
	smp->data.uint = objt_server(smp->strm->target)->puid;

	return 1;
}

/* set temp integer to the number of connections per second reaching the backend.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_be_sess_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
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
smp_fetch_be_conn(const struct arg *args, struct sample *smp, const char *kw, void *private)
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
smp_fetch_queue_size(const struct arg *args, struct sample *smp, const char *kw, void *private)
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
smp_fetch_avg_queue_size(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int nbsrv;
	struct proxy *px;

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
smp_fetch_srv_conn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = args->data.srv->cur_sess;
	return 1;
}

/* set temp integer to the number of enabled servers on the proxy.
 * Accepts exactly 1 argument. Argument is a server, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_srv_sess_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->type = SMP_T_UINT;
	smp->data.uint = read_freq_ctr(&args->data.srv->sess_per_sec);
	return 1;
}


/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "avg_queue",     smp_fetch_avg_queue_size, ARG1(1,BE),  NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "be_conn",       smp_fetch_be_conn,        ARG1(1,BE),  NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "be_id",         smp_fetch_be_id,          0,           NULL, SMP_T_UINT, SMP_USE_BKEND, },
	{ "be_sess_rate",  smp_fetch_be_sess_rate,   ARG1(1,BE),  NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "connslots",     smp_fetch_connslots,      ARG1(1,BE),  NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "nbsrv",         smp_fetch_nbsrv,          ARG1(1,BE),  NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "queue",         smp_fetch_queue_size,     ARG1(1,BE),  NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "srv_conn",      smp_fetch_srv_conn,       ARG1(1,SRV), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ "srv_id",        smp_fetch_srv_id,         0,           NULL, SMP_T_UINT, SMP_USE_SERVR, },
	{ "srv_is_up",     smp_fetch_srv_is_up,      ARG1(1,SRV), NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "srv_sess_rate", smp_fetch_srv_sess_rate,  ARG1(1,SRV), NULL, SMP_T_UINT, SMP_USE_INTRN, },
	{ /* END */ },
}};


/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ /* END */ },
}};


__attribute__((constructor))
static void __backend_init(void)
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
