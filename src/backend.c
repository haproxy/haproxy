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

#include <import/ebmbtree.h>

#include <haproxy/api.h>
#include <haproxy/acl.h>
#include <haproxy/activity.h>
#include <haproxy/arg.h>
#include <haproxy/backend.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/hash.h>
#include <haproxy/http.h>
#include <haproxy/http_ana.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/lb_chash.h>
#include <haproxy/lb_fas.h>
#include <haproxy/lb_fwlc.h>
#include <haproxy/lb_fwrr.h>
#include <haproxy/lb_map.h>
#include <haproxy/log.h>
#include <haproxy/namespace.h>
#include <haproxy/obj_type.h>
#include <haproxy/payload.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/queue.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>
#include <haproxy/trace.h>

#define TRACE_SOURCE &trace_strm

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
 * This functions is designed to be called before server's weight and state
 * commit so it uses 'next' weight and states values.
 *
 * threads: this is the caller responsibility to lock data. For now, this
 * function is called from lb modules, so it should be ok. But if you need to
 * call it from another place, be careful (and update this comment).
 */
void recount_servers(struct proxy *px)
{
	struct server *srv;

	px->srv_act = px->srv_bck = 0;
	px->lbprm.tot_wact = px->lbprm.tot_wbck = 0;
	px->lbprm.fbck = NULL;
	for (srv = px->srv; srv != NULL; srv = srv->next) {
		if (!srv_willbe_usable(srv))
			continue;

		if (srv->flags & SRV_F_BACKUP) {
			if (!px->srv_bck &&
			    !(px->options & PR_O_USE_ALL_BK))
				px->lbprm.fbck = srv;
			px->srv_bck++;
			srv->cumulative_weight = px->lbprm.tot_wbck;
			px->lbprm.tot_wbck += srv->next_eweight;
		} else {
			px->srv_act++;
			srv->cumulative_weight = px->lbprm.tot_wact;
			px->lbprm.tot_wact += srv->next_eweight;
		}
	}
}

/* This function simply updates the backend's tot_weight and tot_used values
 * after servers weights have been updated. It is designed to be used after
 * recount_servers() or equivalent.
 *
 * threads: this is the caller responsibility to lock data. For now, this
 * function is called from lb modules, so it should be ok. But if you need to
 * call it from another place, be careful (and update this comment).
 */
void update_backend_weight(struct proxy *px)
{
	if (px->srv_act) {
		px->lbprm.tot_weight = px->lbprm.tot_wact;
		px->lbprm.tot_used   = px->srv_act;
	}
	else if (px->lbprm.fbck) {
		/* use only the first backup server */
		px->lbprm.tot_weight = px->lbprm.fbck->next_eweight;
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
static struct server *get_server_sh(struct proxy *px, const char *addr, int len, const struct server *avoid)
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
	if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, h, avoid);
	else
		return map_get_server_hash(px, h);
}

/*
 * This function tries to find a running server for the proxy <px> following
 * the URI hash method. In order to optimize cache hits, the hash computation
 * ends at the question mark. Depending on the number of active/backup servers,
 * it will either look for active servers, or for backup servers.
 * If any server is found, it will be returned. If no valid server is found,
 * NULL is returned. The lbprm.arg_opt{1,2,3} values correspond respectively to
 * the "whole" optional argument (boolean, bit0), the "len" argument (numeric)
 * and the "depth" argument (numeric).
 *
 * This code was contributed by Guillaume Dallaire, who also selected this hash
 * algorithm out of a tens because it gave him the best results.
 *
 */
static struct server *get_server_uh(struct proxy *px, char *uri, int uri_len, const struct server *avoid)
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

	if (px->lbprm.arg_opt2) // "len"
		uri_len = MIN(uri_len, px->lbprm.arg_opt2);

	start = end = uri;
	while (uri_len--) {
		c = *end;
		if (c == '/') {
			slashes++;
			if (slashes == px->lbprm.arg_opt3) /* depth+1 */
				break;
		}
		else if (c == '?' && !(px->lbprm.arg_opt1 & 1)) // "whole"
			break;
		end++;
	}

	hash = gen_hash(px, start, (end - start));

	if ((px->lbprm.algo & BE_LB_HASH_MOD) == BE_LB_HMOD_AVAL)
		hash = full_hash(hash);
 hash_done:
	if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash, avoid);
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
static struct server *get_server_ph(struct proxy *px, const char *uri, int uri_len, const struct server *avoid)
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
	plen = px->lbprm.arg_len;
	params = p;

	while (uri_len > plen) {
		/* Look for the parameter name followed by an equal symbol */
		if (params[plen] == '=') {
			if (memcmp(params, px->lbprm.arg_str, plen) == 0) {
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

				if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
					return chash_get_server_hash(px, hash, avoid);
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
static struct server *get_server_ph_post(struct stream *s, const struct server *avoid)
{
	unsigned int hash = 0;
	struct channel  *req  = &s->req;
	struct proxy    *px   = s->be;
	struct htx      *htx = htxbuf(&req->buf);
	struct htx_blk  *blk;
	unsigned int     plen = px->lbprm.arg_len;
	unsigned long    len;
	const char      *params, *p, *start, *end;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	p = params = NULL;
	len = 0;
	for (blk = htx_get_first_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		enum htx_blk_type type = htx_get_blk_type(blk);
		struct ist v;

		if (type != HTX_BLK_DATA)
			continue;
		v = htx_get_blk_value(htx, blk);
		p = params = v.ptr;
		len = v.len;
		break;
	}

	while (len > plen) {
		/* Look for the parameter name followed by an equal symbol */
		if (params[plen] == '=') {
			if (memcmp(params, px->lbprm.arg_str, plen) == 0) {
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

				if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
					return chash_get_server_hash(px, hash, avoid);
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
 * is found, NULL is returned. When lbprm.arg_opt1 is set, the hash will only
 * apply to the middle part of a domain name ("use_domain_only" option).
 */
static struct server *get_server_hh(struct stream *s, const struct server *avoid)
{
	unsigned int hash = 0;
	struct proxy    *px   = s->be;
	unsigned int     plen = px->lbprm.arg_len;
	unsigned long    len;
	const char      *p;
	const char *start, *end;
	struct htx *htx = htxbuf(&s->req.buf);
	struct http_hdr_ctx ctx = { .blk = NULL };

	/* tot_weight appears to mean srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	http_find_header(htx, ist2(px->lbprm.arg_str, plen), &ctx, 0);

	/* if the header is not found or empty, let's fallback to round robin */
	if (!ctx.blk || !ctx.value.len)
		return NULL;

	/* Found a the param_name in the headers.
	 * we will compute the hash based on this value ctx.val.
	 */
	len = ctx.value.len;
	p   = ctx.value.ptr;

	if (!px->lbprm.arg_opt1) {
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
	if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash, avoid);
	else
		return map_get_server_hash(px, hash);
}

/* RDP Cookie HASH.  */
static struct server *get_server_rch(struct stream *s, const struct server *avoid)
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

	rewind = co_data(&s->req);
	c_rew(&s->req, rewind);

	ret = fetch_rdp_cookie_name(s, &smp, px->lbprm.arg_str, px->lbprm.arg_len);
	len = smp.data.u.str.data;

	c_adv(&s->req, rewind);

	if (ret == 0 || (smp.flags & SMP_F_MAY_CHANGE) || len == 0)
		return NULL;

	/* note: we won't hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	/* Found the param_name in the headers.
	 * we will compute the hash based on this value ctx.val.
	 */
	hash = gen_hash(px, smp.data.u.str.area, len);

	if ((px->lbprm.algo & BE_LB_HASH_MOD) == BE_LB_HMOD_AVAL)
		hash = full_hash(hash);
 hash_done:
	if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash, avoid);
	else
		return map_get_server_hash(px, hash);
}

/* random value  */
static struct server *get_server_rnd(struct stream *s, const struct server *avoid)
{
	unsigned int hash = 0;
	struct proxy  *px = s->be;
	struct server *prev, *curr;
	int draws = px->lbprm.arg_opt1; // number of draws

	/* tot_weight appears to mean srv_count */
	if (px->lbprm.tot_weight == 0)
		return NULL;

	curr = NULL;
	do {
		prev = curr;
		hash = statistical_prng();
		curr = chash_get_server_hash(px, hash, avoid);
		if (!curr)
			break;

		/* compare the new server to the previous best choice and pick
		 * the one with the least currently served requests.
		 */
		if (prev && prev != curr &&
		    curr->served * prev->cur_eweight > prev->served * curr->cur_eweight)
			curr = prev;
	} while (--draws > 0);

	/* if the selected server is full, pretend we have none so that we reach
	 * the backend's queue instead.
	 */
	if (curr &&
	    (curr->queue.length || (curr->maxconn && curr->served >= srv_dynamic_maxconn(curr))))
		curr = NULL;

	return curr;
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
	struct connection *conn = NULL;
	struct server *conn_slot;
	struct server *srv = NULL, *prev_srv;
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

	if ((s->be->lbprm.algo & BE_LB_KIND) != BE_LB_KIND_HI &&
	    ((s->sess->flags & SESS_FL_PREFER_LAST) ||
	     (s->be->options & PR_O_PREF_LAST))) {
		struct sess_srv_list *srv_list;
		list_for_each_entry(srv_list, &s->sess->srv_list, srv_list) {
			struct server *tmpsrv = objt_server(srv_list->target);

			if (tmpsrv && tmpsrv->proxy == s->be &&
			    ((s->sess->flags & SESS_FL_PREFER_LAST) ||
			     (!s->be->max_ka_queue ||
			      server_has_room(tmpsrv) || (
			      tmpsrv->queue.length + 1 < s->be->max_ka_queue))) &&
			    srv_currently_usable(tmpsrv)) {
				list_for_each_entry(conn, &srv_list->conn_list, session_list) {
					if (!(conn->flags & CO_FL_WAIT_XPRT)) {
						srv = tmpsrv;
						s->target = &srv->obj_type;
						if (conn->flags & CO_FL_SESS_IDLE) {
							conn->flags &= ~CO_FL_SESS_IDLE;
							s->sess->idle_conns--;
						}
						goto out_ok;
					}
				}
			}
		}
	}

	if (s->be->lbprm.algo & BE_LB_KIND) {
		/* we must check if we have at least one server available */
		if (!s->be->lbprm.tot_weight) {
			err = SRV_STATUS_NOSRV;
			goto out;
		}

		/* if there's some queue on the backend, with certain algos we
		 * know it's because all servers are full.
		 */
		if (s->be->queue.length && s->be->queue.length != s->be->beconn &&
		    (((s->be->lbprm.algo & (BE_LB_KIND|BE_LB_NEED|BE_LB_PARM)) == BE_LB_ALGO_FAS)||   // first
		     ((s->be->lbprm.algo & (BE_LB_KIND|BE_LB_NEED|BE_LB_PARM)) == BE_LB_ALGO_RR) ||   // roundrobin
		     ((s->be->lbprm.algo & (BE_LB_KIND|BE_LB_NEED|BE_LB_PARM)) == BE_LB_ALGO_SRR))) { // static-rr
			err = SRV_STATUS_FULL;
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
				/* static-rr (map) or random (chash) */
				if ((s->be->lbprm.algo & BE_LB_PARM) == BE_LB_RR_RANDOM)
					srv = get_server_rnd(s, prev_srv);
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
				const struct sockaddr_storage *src;

			case BE_LB_HASH_SRC:
				src = si_src(&s->si[0]);
				if (src && src->ss_family == AF_INET) {
					srv = get_server_sh(s->be,
							    (void *)&((struct sockaddr_in *)src)->sin_addr,
							    4, prev_srv);
				}
				else if (src && src->ss_family == AF_INET6) {
					srv = get_server_sh(s->be,
							    (void *)&((struct sockaddr_in6 *)src)->sin6_addr,
							    16, prev_srv);
				}
				else {
					/* unknown IP family */
					err = SRV_STATUS_INTERNAL;
					goto out;
				}
				break;

			case BE_LB_HASH_URI:
				/* URI hashing */
				if (IS_HTX_STRM(s) && s->txn->req.msg_state >= HTTP_MSG_BODY) {
					struct ist uri;

					uri = htx_sl_req_uri(http_get_stline(htxbuf(&s->req.buf)));
					if (s->be->lbprm.arg_opt1 & 2) {
						struct http_uri_parser parser =
						  http_uri_parser_init(uri);

						uri = http_parse_path(&parser);
						if (!isttest(uri))
							uri = ist("");
					}
					srv = get_server_uh(s->be, uri.ptr, uri.len, prev_srv);
				}
				break;

			case BE_LB_HASH_PRM:
				/* URL Parameter hashing */
				if (IS_HTX_STRM(s) && s->txn->req.msg_state >= HTTP_MSG_BODY) {
					struct ist uri;

					uri = htx_sl_req_uri(http_get_stline(htxbuf(&s->req.buf)));
					srv = get_server_ph(s->be, uri.ptr, uri.len, prev_srv);

					if (!srv && s->txn->meth == HTTP_METH_POST)
						srv = get_server_ph_post(s, prev_srv);
				}
				break;

			case BE_LB_HASH_HDR:
				/* Header Parameter hashing */
				if (IS_HTX_STRM(s) && s->txn->req.msg_state >= HTTP_MSG_BODY)
					srv = get_server_hh(s, prev_srv);
				break;

			case BE_LB_HASH_RDP:
				/* RDP Cookie hashing */
				srv = get_server_rch(s, prev_srv);
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
				if ((s->be->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
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
			_HA_ATOMIC_INC(&s->be->be_counters.cum_lbconn);
			_HA_ATOMIC_INC(&srv->counters.cum_lbconn);
		}
		s->target = &srv->obj_type;
	}
	else if (s->be->options & (PR_O_DISPATCH | PR_O_TRANSP)) {
		s->target = &s->be->obj_type;
	}
	else {
		err = SRV_STATUS_NOSRV;
		goto out;
	}

out_ok:
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

/* Allocate an address for the destination endpoint
 * The address is taken from the currently assigned server, or from the
 * dispatch or transparent address.
 *
 * Returns SRV_STATUS_OK on success.
 * On error, no address is allocated and SRV_STATUS_INTERNAL is returned.
 */
static int alloc_dst_address(struct sockaddr_storage **ss,
                             struct server *srv, struct stream *s)
{
	const struct sockaddr_storage *dst;

	*ss = NULL;
	if ((s->flags & SF_DIRECT) || (s->be->lbprm.algo & BE_LB_KIND)) {
		/* A server is necessarily known for this stream */
		if (!(s->flags & SF_ASSIGNED))
			return SRV_STATUS_INTERNAL;

		if (!sockaddr_alloc(ss, NULL, 0))
			return SRV_STATUS_INTERNAL;

		**ss = srv->addr;
		set_host_port(*ss, srv->svc_port);
		if (!is_addr(*ss)) {
			/* if the server has no address, we use the same address
			 * the client asked, which is handy for remapping ports
			 * locally on multiple addresses at once. Nothing is done
			 * for AF_UNIX addresses.
			 */
			dst = si_dst(&s->si[0]);
			if (dst && dst->ss_family == AF_INET) {
				((struct sockaddr_in *)*ss)->sin_family = AF_INET;
				((struct sockaddr_in *)*ss)->sin_addr =
				  ((struct sockaddr_in *)dst)->sin_addr;
			} else if (dst && dst->ss_family == AF_INET6) {
				((struct sockaddr_in6 *)*ss)->sin6_family = AF_INET6;
				((struct sockaddr_in6 *)*ss)->sin6_addr =
				  ((struct sockaddr_in6 *)dst)->sin6_addr;
			}
		}

		/* if this server remaps proxied ports, we'll use
		 * the port the client connected to with an offset. */
		if ((srv->flags & SRV_F_MAPPORTS)) {
			int base_port;

			dst = si_dst(&s->si[0]);
			if (dst) {
				/* First, retrieve the port from the incoming connection */
				base_port = get_host_port(dst);

				/* Second, assign the outgoing connection's port */
				base_port += get_host_port(*ss);
				set_host_port(*ss, base_port);
			}
		}
	}
	else if (s->be->options & PR_O_DISPATCH) {
		if (!sockaddr_alloc(ss, NULL, 0))
			return SRV_STATUS_INTERNAL;

		/* connect to the defined dispatch addr */
		**ss = s->be->dispatch_addr;
	}
	else if ((s->be->options & PR_O_TRANSP)) {
		if (!sockaddr_alloc(ss, NULL, 0))
			return SRV_STATUS_INTERNAL;

		/* in transparent mode, use the original dest addr if no dispatch specified */
		dst = si_dst(&s->si[0]);
		if (dst && (dst->ss_family == AF_INET || dst->ss_family == AF_INET6))
			**ss = *dst;
	}
	else {
		/* no server and no LB algorithm ! */
		return SRV_STATUS_INTERNAL;
	}

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
				_HA_ATOMIC_INC(&prev_srv->counters.redispatches);
				_HA_ATOMIC_INC(&s->be->be_counters.redispatches);
			} else {
				_HA_ATOMIC_INC(&prev_srv->counters.retries);
				_HA_ATOMIC_INC(&s->be->be_counters.retries);
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
		    (srv->queue.length || srv->served >= srv_dynamic_maxconn(srv))) {

			if (srv->maxqueue > 0 && srv->queue.length >= srv->maxqueue)
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

/* Allocate an address for source binding on the specified server or backend.
 * The allocation is only performed if the connection is intended to be used
 * with transparent mode.
 *
 * Returns SRV_STATUS_OK if no transparent mode or the address was successfully
 * allocated. Otherwise returns SRV_STATUS_INTERNAL.
 */
static int alloc_bind_address(struct sockaddr_storage **ss,
                              struct server *srv, struct stream *s)
{
#if defined(CONFIG_HAP_TRANSPARENT)
	const struct sockaddr_storage *addr;
	struct conn_src *src = NULL;
	struct sockaddr_in *sin;
	char *vptr;
	size_t vlen;
#endif

	*ss = NULL;

#if defined(CONFIG_HAP_TRANSPARENT)
	if (srv && srv->conn_src.opts & CO_SRC_BIND)
		src = &srv->conn_src;
	else if (s->be->conn_src.opts & CO_SRC_BIND)
		src = &s->be->conn_src;

	/* no transparent mode, no need to allocate an address, returns OK */
	if (!src)
		return SRV_STATUS_OK;

	switch (src->opts & CO_SRC_TPROXY_MASK) {
	case CO_SRC_TPROXY_ADDR:
		if (!sockaddr_alloc(ss, NULL, 0))
			return SRV_STATUS_INTERNAL;

		**ss = src->tproxy_addr;
		break;

	case CO_SRC_TPROXY_CLI:
	case CO_SRC_TPROXY_CIP:
		/* FIXME: what can we do if the client connects in IPv6 or unix socket ? */
		addr = si_src(&s->si[0]);
		if (!addr)
			return SRV_STATUS_INTERNAL;

		if (!sockaddr_alloc(ss, NULL, 0))
			return SRV_STATUS_INTERNAL;

		**ss = *addr;
		break;

	case CO_SRC_TPROXY_DYN:
		if (!src->bind_hdr_occ || !IS_HTX_STRM(s))
			return SRV_STATUS_INTERNAL;

		if (!sockaddr_alloc(ss, NULL, 0))
			return SRV_STATUS_INTERNAL;

		/* bind to the IP in a header */
		sin = (struct sockaddr_in *)*ss;
		sin->sin_family = AF_INET;
		sin->sin_port = 0;
		sin->sin_addr.s_addr = 0;
		if (!http_get_htx_hdr(htxbuf(&s->req.buf),
		                      ist2(src->bind_hdr_name, src->bind_hdr_len),
		                      src->bind_hdr_occ, NULL, &vptr, &vlen)) {
			sockaddr_free(ss);
			return SRV_STATUS_INTERNAL;
		}

		sin->sin_addr.s_addr = htonl(inetaddr_host_lim(vptr, vptr + vlen));
		break;

	default:
		;
	}
#endif

	return SRV_STATUS_OK;
}

/* Attempt to get a backend connection from the specified mt_list array
 * (safe or idle connections). The <is_safe> argument means what type of
 * connection the caller wants.
 */
static struct connection *conn_backend_get(struct stream *s, struct server *srv, int is_safe, int64_t hash)
{
	struct connection *conn = NULL;
	int i; // thread number
	int found = 0;
	int stop;

	/* We need to lock even if this is our own list, because another
	 * thread may be trying to migrate that connection, and we don't want
	 * to end up with two threads using the same connection.
	 */
	i = tid;
	HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	conn = srv_lookup_conn(is_safe ? &srv->per_thr[tid].safe_conns : &srv->per_thr[tid].idle_conns, hash);
	if (conn)
		conn_delete_from_tree(&conn->hash_node->node);

	/* If we failed to pick a connection from the idle list, let's try again with
	 * the safe list.
	 */
	if (!conn && !is_safe && srv->curr_safe_nb > 0) {
		conn = srv_lookup_conn(&srv->per_thr[tid].safe_conns, hash);
		if (conn) {
			conn_delete_from_tree(&conn->hash_node->node);
			is_safe = 1;
		}
	}
	HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);

	/* If we found a connection in our own list, and we don't have to
	 * steal one from another thread, then we're done.
	 */
	if (conn)
		goto done;

	/* pool sharing globally disabled ? */
	if (!(global.tune.options & GTUNE_IDLE_POOL_SHARED))
		goto done;

	/* Are we allowed to pick from another thread ? We'll still try
	 * it if we're running low on FDs as we don't want to create
	 * extra conns in this case, otherwise we can give up if we have
	 * too few idle conns.
	 */
	if (srv->curr_idle_conns < srv->low_idle_conns &&
	    ha_used_fds < global.tune.pool_low_count)
		goto done;

	/* Lookup all other threads for an idle connection, starting from last
	 * unvisited thread.
	 */
	stop = srv->next_takeover;
	if (stop >= global.nbthread)
		stop = 0;

	i = stop;
	do {
		if (!srv->curr_idle_thr[i] || i == tid)
			continue;

		if (HA_SPIN_TRYLOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock) != 0)
			continue;
		conn = srv_lookup_conn(is_safe ? &srv->per_thr[i].safe_conns : &srv->per_thr[i].idle_conns, hash);
		while (conn) {
			if (conn->mux->takeover && conn->mux->takeover(conn, i) == 0) {
				conn_delete_from_tree(&conn->hash_node->node);
				_HA_ATOMIC_INC(&activity[tid].fd_takeover);
				found = 1;
				break;
			}

			conn = srv_lookup_conn_next(conn);
		}

		if (!found && !is_safe && srv->curr_safe_nb > 0) {
			conn = srv_lookup_conn(&srv->per_thr[i].safe_conns, hash);
			while (conn) {
				if (conn->mux->takeover && conn->mux->takeover(conn, i) == 0) {
					conn_delete_from_tree(&conn->hash_node->node);
					_HA_ATOMIC_INC(&activity[tid].fd_takeover);
					found = 1;
					is_safe = 1;
					break;
				}

				conn = srv_lookup_conn_next(conn);
			}
		}
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock);
	} while (!found && (i = (i + 1 == global.nbthread) ? 0 : i + 1) != stop);

	if (!found)
		conn = NULL;
 done:
	if (conn) {
		_HA_ATOMIC_STORE(&srv->next_takeover, (i + 1 == global.nbthread) ? 0 : i + 1);

		srv_use_conn(srv, conn);

		_HA_ATOMIC_DEC(&srv->curr_idle_conns);
		_HA_ATOMIC_DEC(conn->flags & CO_FL_SAFE_LIST ? &srv->curr_safe_nb : &srv->curr_idle_nb);
		_HA_ATOMIC_DEC(&srv->curr_idle_thr[i]);
		conn->flags &= ~CO_FL_LIST_MASK;
		__ha_barrier_atomic_store();

		if ((s->be->options & PR_O_REUSE_MASK) == PR_O_REUSE_SAFE &&
		    conn->mux->flags & MX_FL_HOL_RISK) {
			/* attach the connection to the session private list
			 */
			conn->owner = s->sess;
			session_add_conn(s->sess, conn, conn->target);
		}
		else {
			ebmb_insert(&srv->per_thr[tid].avail_conns,
			            &conn->hash_node->node,
			            sizeof(conn->hash_node->hash));
		}
	}
	return conn;
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
 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
 * The server-facing stream interface is expected to hold a pre-allocated connection
 * in s->si[1].conn.
 */
int connect_server(struct stream *s)
{
	struct connection *cli_conn = objt_conn(strm_orig(s));
	struct connection *srv_conn = NULL;
	struct conn_stream *srv_cs = NULL;
	struct server *srv;
	const int reuse_mode = s->be->options & PR_O_REUSE_MASK;
	int reuse = 0;
	int init_mux = 0;
	int err;
#ifdef USE_OPENSSL
	struct sample *sni_smp = NULL;
#endif
	struct sockaddr_storage *bind_addr;
	int proxy_line_ret;
	int64_t hash = 0;
	struct conn_hash_params hash_params;

	/* in standard configuration, srv will be valid
	 * it can be NULL for dispatch mode or transparent backend */
	srv = objt_server(s->target);

	if (!(s->flags & SF_ADDR_SET)) {
		err = alloc_dst_address(&s->si[1].dst, srv, s);
		if (err != SRV_STATUS_OK)
			return SF_ERR_INTERNAL;

		s->flags |= SF_ADDR_SET;
	}

	err = alloc_bind_address(&bind_addr, srv, s);
	if (err != SRV_STATUS_OK)
		return SF_ERR_INTERNAL;

#ifdef USE_OPENSSL
	if (srv && srv->ssl_ctx.sni) {
		sni_smp = sample_fetch_as_type(s->be, s->sess, s,
		                               SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
		                               srv->ssl_ctx.sni, SMP_T_STR);
	}
#endif

	/* do not reuse if mode is not http */
	if (!IS_HTX_STRM(s)) {
		DBG_TRACE_STATE("skip idle connections reuse: no htx", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
		goto skip_reuse;
	}

	/* disable reuse if websocket stream and the protocol to use is not the
	 * same as the main protocol of the server.
	 */
	if (unlikely(s->flags & SF_WEBSOCKET) && srv) {
		if (!srv_check_reuse_ws(srv)) {
			DBG_TRACE_STATE("skip idle connections reuse: websocket stream", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
			goto skip_reuse;
		}
	}

	/* first, set unique connection parameters and then calculate hash */
	memset(&hash_params, 0, sizeof(hash_params));

	/* 1. target */
	hash_params.target = s->target;

#ifdef USE_OPENSSL
	/* 2. sni
	 * only test if the sample is not null as smp_make_safe (called before
	 * ssl_sock_set_servername) can only fails if this is not the case
	 */
	if (sni_smp) {
		hash_params.sni_prehash =
		  conn_hash_prehash(sni_smp->data.u.str.area,
		                    sni_smp->data.u.str.data);
	}
#endif /* USE_OPENSSL */

	/* 3. destination address */
	if (srv && (!is_addr(&srv->addr) || srv->flags & SRV_F_MAPPORTS))
		hash_params.dst_addr = s->si[1].dst;

	/* 4. source address */
	hash_params.src_addr = bind_addr;

	/* 5. proxy protocol */
	if (srv && srv->pp_opts) {
		proxy_line_ret = make_proxy_line(trash.area, trash.size, srv, cli_conn, s);
		if (proxy_line_ret) {
			hash_params.proxy_prehash =
			  conn_hash_prehash(trash.area, proxy_line_ret);
		}
	}

	hash = conn_calculate_hash(&hash_params);

	/* first, search for a matching connection in the session's idle conns */
	srv_conn = session_get_conn(s->sess, s->target, hash);
	if (srv_conn) {
		DBG_TRACE_STATE("reuse connection from session", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
		reuse = 1;
	}

	if (srv && !reuse && reuse_mode != PR_O_REUSE_NEVR) {
		/* Below we pick connections from the safe, idle  or
		 * available (which are safe too) lists based
		 * on the strategy, the fact that this is a first or second
		 * (retryable) request, with the indicated priority (1 or 2) :
		 *
		 *          SAFE                 AGGR                ALWS
		 *
		 *      +-----+-----+        +-----+-----+       +-----+-----+
		 *   req| 1st | 2nd |     req| 1st | 2nd |    req| 1st | 2nd |
		 *  ----+-----+-----+    ----+-----+-----+   ----+-----+-----+
		 *  safe|  -  |  2  |    safe|  1  |  2  |   safe|  1  |  2  |
		 *  ----+-----+-----+    ----+-----+-----+   ----+-----+-----+
		 *  idle|  -  |  1  |    idle|  -  |  1  |   idle|  2  |  1  |
		 *  ----+-----+-----+    ----+-----+-----+   ----+-----+-----+
		 *
		 * Idle conns are necessarily looked up on the same thread so
		 * that there is no concurrency issues.
		 */
		if (!eb_is_empty(&srv->per_thr[tid].avail_conns)) {
			srv_conn = srv_lookup_conn(&srv->per_thr[tid].avail_conns, hash);
			if (srv_conn) {
				DBG_TRACE_STATE("reuse connection from avail", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
				reuse = 1;
			}
		}

		/* if no available connections found, search for an idle/safe */
		if (!srv_conn && srv->max_idle_conns && srv->curr_idle_conns > 0) {
			const int not_first_req = s->txn && s->txn->flags & TX_NOT_FIRST;
			const int idle = srv->curr_idle_nb > 0;
			const int safe = srv->curr_safe_nb > 0;

			/* second column of the tables above,
			 * search for an idle then safe conn */
			if (not_first_req) {
				if (idle || safe)
					srv_conn = conn_backend_get(s, srv, 0, hash);
			}
			/* first column of the tables above */
			else if (reuse_mode >= PR_O_REUSE_AGGR) {
				/* search for a safe conn */
				if (safe)
					srv_conn = conn_backend_get(s, srv, 1, hash);

				/* search for an idle conn if no safe conn found
				 * on always reuse mode */
				if (!srv_conn &&
				    reuse_mode == PR_O_REUSE_ALWS && idle) {
					/* TODO conn_backend_get should not check the
					 * safe list is this case */
					srv_conn = conn_backend_get(s, srv, 0, hash);
				}
			}

			if (srv_conn) {
				DBG_TRACE_STATE("reuse connection from idle/safe", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
				reuse = 1;
			}
		}
	}


	/* here reuse might have been set above, indicating srv_conn finally
	 * is OK.
	 */

	if (ha_used_fds > global.tune.pool_high_count && srv) {
		struct connection *tokill_conn = NULL;
		struct conn_hash_node *conn_node = NULL;
		struct ebmb_node *node = NULL;

		/* We can't reuse a connection, and e have more FDs than deemd
		 * acceptable, attempt to kill an idling connection
		 */
		/* First, try from our own idle list */
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		node = ebmb_first(&srv->per_thr[tid].idle_conns);
		if (node) {
			conn_node = ebmb_entry(node, struct conn_hash_node, node);
			tokill_conn = conn_node->conn;
			ebmb_delete(node);
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);

			/* Release the idle lock before calling mux->destroy.
			 * It will in turn call srv_release_conn through
			 * conn_free which also uses it.
			 */
			tokill_conn->mux->destroy(tokill_conn->ctx);
		}
		else {
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		}

		/* If not, iterate over other thread's idling pool, and try to grab one */
		if (!tokill_conn) {
			int i;

			for (i = tid; (i = ((i + 1 == global.nbthread) ? 0 : i + 1)) != tid;) {
				// just silence stupid gcc which reports an absurd
				// out-of-bounds warning for <i> which is always
				// exactly zero without threads, but it seems to
				// see it possibly larger.
				ALREADY_CHECKED(i);

				if (HA_SPIN_TRYLOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock) != 0)
					continue;

				node = ebmb_first(&srv->per_thr[i].idle_conns);
				if (node) {
					conn_node = ebmb_entry(node, struct conn_hash_node, node);
					tokill_conn = conn_node->conn;
					ebmb_delete(node);
				}

				if (!tokill_conn) {
					node = ebmb_first(&srv->per_thr[i].safe_conns);
					if (node) {
						conn_node = ebmb_entry(node, struct conn_hash_node, node);
						tokill_conn = conn_node->conn;
						ebmb_delete(node);
					}
				}
				HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock);

				if (tokill_conn) {
					/* We got one, put it into the concerned thread's to kill list, and wake it's kill task */

					MT_LIST_APPEND(&idle_conns[i].toremove_conns,
					    (struct mt_list *)&tokill_conn->toremove_list);
					task_wakeup(idle_conns[i].cleanup_task, TASK_WOKEN_OTHER);
					break;
				}
			}
		}

	}

	if (reuse) {
		if (srv_conn->mux) {
			int avail = srv_conn->mux->avail_streams(srv_conn);

			if (avail <= 1) {
				/* No more streams available, remove it from the list */
				conn_delete_from_tree(&srv_conn->hash_node->node);
			}

			if (avail >= 1) {
				srv_cs = srv_conn->mux->attach(srv_conn, s->sess);
				if (srv_cs)
					si_attach_cs(&s->si[1], srv_cs);
				else
					srv_conn = NULL;
			}
			else
				srv_conn = NULL;
		}
		/* otherwise srv_conn is left intact */
	}
	else
		srv_conn = NULL;

skip_reuse:
	/* no reuse or failed to reuse the connection above, pick a new one */
	if (!srv_conn) {
		srv_conn = conn_new(s->target);
		srv_cs = NULL;

		if (srv_conn) {
			DBG_TRACE_STATE("alloc new be connection", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
			srv_conn->owner = s->sess;

			/* connection will be attached to the session if
			 * http-reuse mode is never or it is not targeted to a
			 * server */
			if (reuse_mode == PR_O_REUSE_NEVR || !srv)
				conn_set_private(srv_conn);

			/* assign bind_addr to srv_conn */
			srv_conn->src = bind_addr;
			bind_addr = NULL;

			if (!sockaddr_alloc(&srv_conn->dst, 0, 0)) {
				conn_free(srv_conn);
				return SF_ERR_RESOURCE;
			}

			srv_conn->hash_node->hash = hash;
		}
	}

	/* if bind_addr is non NULL free it */
	sockaddr_free(&bind_addr);

	/* srv_conn is still NULL only on allocation failure */
	if (!srv_conn)
		return SF_ERR_RESOURCE;

	/* copy the target address into the connection */
	*srv_conn->dst = *s->si[1].dst;

	/* Copy network namespace from client connection */
	srv_conn->proxy_netns = cli_conn ? cli_conn->proxy_netns : NULL;

	if (!srv_conn->xprt) {
		/* set the correct protocol on the output stream interface */
		if (srv) {
			if (conn_prepare(srv_conn, protocol_lookup(srv_conn->dst->ss_family, PROTO_TYPE_STREAM, 0), srv->xprt)) {
				conn_free(srv_conn);
				return SF_ERR_INTERNAL;
			}
		} else if (obj_type(s->target) == OBJ_TYPE_PROXY) {
			int ret;

			/* proxies exclusively run on raw_sock right now */
			ret = conn_prepare(srv_conn, protocol_lookup(srv_conn->dst->ss_family, PROTO_TYPE_STREAM, 0), xprt_get(XPRT_RAW));
			if (ret < 0 || !(srv_conn->ctrl)) {
				conn_free(srv_conn);
				return SF_ERR_INTERNAL;
			}
		}
		else {
			conn_free(srv_conn);
			return SF_ERR_INTERNAL;  /* how did we get there ? */
		}

		srv_cs = si_alloc_cs(&s->si[1], srv_conn);
		if (!srv_cs) {
			conn_free(srv_conn);
			return SF_ERR_RESOURCE;
		}
		srv_conn->ctx = srv_cs;
#if defined(USE_OPENSSL) && defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
		if (!srv ||
		    (srv->use_ssl != 1 || (!(srv->ssl_ctx.alpn_str) && !(srv->ssl_ctx.npn_str)) ||
		     srv->mux_proto || !IS_HTX_STRM(s)))
#endif
			init_mux = 1;

		/* process the case where the server requires the PROXY protocol to be sent */
		srv_conn->send_proxy_ofs = 0;

		if (srv && srv->pp_opts) {
			srv_conn->flags |= CO_FL_SEND_PROXY;
			srv_conn->send_proxy_ofs = 1; /* must compute size */
		}

		if (srv && (srv->flags & SRV_F_SOCKS4_PROXY)) {
			srv_conn->send_proxy_ofs = 1;
			srv_conn->flags |= CO_FL_SOCKS4;
		}

#if defined(USE_OPENSSL) && defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
		/* if websocket stream, try to update connection ALPN. */
		if (unlikely(s->flags & SF_WEBSOCKET) &&
		    srv && srv->use_ssl && srv->ssl_ctx.alpn_str) {
			char *alpn = "";
			int force = 0;

			switch (srv->ws) {
			case SRV_WS_AUTO:
				alpn = "\x08http/1.1";
				force = 0;
				break;
			case SRV_WS_H1:
				alpn = "\x08http/1.1";
				force = 1;
				break;
			case SRV_WS_H2:
				alpn = "\x02h2";
				force = 1;
				break;
			}

			if (!conn_update_alpn(srv_conn, ist(alpn), force))
				DBG_TRACE_STATE("update alpn for websocket", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
		}
#endif
	}
	else {
		s->flags |= SF_SRV_REUSED;

		/* Currently there seems to be no known cases of xprt ready
		 * without the mux installed here.
		 */
		BUG_ON(!srv_conn->mux);

		if (!(srv_conn->mux->ctl(srv_conn, MUX_STATUS, NULL) & MUX_STATUS_READY))
			s->flags |= SF_SRV_REUSED_ANTICIPATED;
	}

	/* flag for logging source ip/port */
	if (strm_fe(s)->options2 & PR_O2_SRC_ADDR)
		s->si[1].flags |= SI_FL_SRC_ADDR;

	/* disable lingering */
	if (s->be->options & PR_O_TCP_NOLING)
		s->si[1].flags |= SI_FL_NOLINGER;

	if (s->flags & SF_SRV_REUSED) {
		_HA_ATOMIC_INC(&s->be->be_counters.reuse);
		if (srv)
			_HA_ATOMIC_INC(&srv->counters.reuse);
	} else {
		_HA_ATOMIC_INC(&s->be->be_counters.connect);
		if (srv)
			_HA_ATOMIC_INC(&srv->counters.connect);
	}

	err = si_connect(&s->si[1], srv_conn);
	if (err != SF_ERR_NONE)
		return err;

#ifdef USE_OPENSSL
	if (!(s->flags & SF_SRV_REUSED)) {
		if (smp_make_safe(sni_smp))
			ssl_sock_set_servername(srv_conn, sni_smp->data.u.str.area);
	}
#endif /* USE_OPENSSL */

	/* The CO_FL_SEND_PROXY flag may have been set by the connect method,
	 * if so, add our handshake pseudo-XPRT now.
	 */
	if ((srv_conn->flags & CO_FL_HANDSHAKE)) {
		if (xprt_add_hs(srv_conn) < 0) {
			conn_full_close(srv_conn);
			return SF_ERR_INTERNAL;
		}
	}
	conn_xprt_start(srv_conn);

	/* We have to defer the mux initialization until after si_connect()
	 * has been called, as we need the xprt to have been properly
	 * initialized, or any attempt to recv during the mux init may
	 * fail, and flag the connection as CO_FL_ERROR.
	 */
	if (init_mux) {
		const struct mux_ops *alt_mux =
		  likely(!(s->flags & SF_WEBSOCKET)) ? NULL : srv_get_ws_proto(srv);
		if (conn_install_mux_be(srv_conn, srv_cs, s->sess, alt_mux) < 0) {
			conn_full_close(srv_conn);
			return SF_ERR_INTERNAL;
		}
		if (IS_HTX_STRM(s)) {
			/* If we're doing http-reuse always, and the connection
			 * is not private with available streams (an http2
			 * connection), add it to the available list, so that
			 * others can use it right away. If the connection is
			 * private or we're doing http-reuse safe and the mux
			 * protocol supports multiplexing, add it in the
			 * session server list.
			 */
			if (srv && reuse_mode == PR_O_REUSE_ALWS &&
			    !(srv_conn->flags & CO_FL_PRIVATE) &&
			    srv_conn->mux->avail_streams(srv_conn) > 0) {
				ebmb_insert(&srv->per_thr[tid].avail_conns, &srv_conn->hash_node->node, sizeof(srv_conn->hash_node->hash));
			}
			else if (srv_conn->flags & CO_FL_PRIVATE ||
			         (reuse_mode == PR_O_REUSE_SAFE &&
			          srv_conn->mux->flags & MX_FL_HOL_RISK)) {
				/* If it fail now, the same will be done in mux->detach() callback */
				session_add_conn(s->sess, srv_conn, srv_conn->target);
			}
		}
	}

#if defined(USE_OPENSSL) && (defined(OPENSSL_IS_BORINGSSL) || (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L))

	if (!reuse && cli_conn && srv && srv_conn->mux &&
	    (srv->ssl_ctx.options & SRV_SSL_O_EARLY_DATA) &&
	    /* Only attempt to use early data if either the client sent
	     * early data, so that we know it can handle a 425, or if
	     * we are allwoed to retry requests on early data failure, and
	     * it's our first try
	     */
	    ((cli_conn->flags & CO_FL_EARLY_DATA) ||
	     ((s->be->retry_type & PR_RE_EARLY_ERROR) &&
	      s->si[1].conn_retries == s->be->conn_retries)) &&
	    !channel_is_empty(si_oc(&s->si[1])) &&
	    srv_conn->flags & CO_FL_SSL_WAIT_HS)
		srv_conn->flags &= ~(CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN);
#endif

	/* set connect timeout */
	s->si[1].exp = tick_add_ifset(now_ms, s->be->timeout.connect);

	if (srv) {
		int count;

		s->flags |= SF_CURR_SESS;
		count = _HA_ATOMIC_ADD_FETCH(&srv->cur_sess, 1);
		HA_ATOMIC_UPDATE_MAX(&srv->counters.cur_sess_max, count);
		if (s->be->lbprm.server_take_conn)
			s->be->lbprm.server_take_conn(srv);
	}

	/* Now handle synchronously connected sockets. We know the stream-int
	 * is at least in state SI_ST_CON. These ones typically are UNIX
	 * sockets, socket pairs, and occasionally TCP connections on the
	 * loopback on a heavily loaded system.
	 */
	if ((srv_conn->flags & CO_FL_ERROR || srv_cs->flags & CS_FL_ERROR))
		s->si[1].flags |= SI_FL_ERR;

	/* If we had early data, and the handshake ended, then
	 * we can remove the flag, and attempt to wake the task up,
	 * in the event there's an analyser waiting for the end of
	 * the handshake.
	 */
	if (!(srv_conn->flags & (CO_FL_WAIT_XPRT | CO_FL_EARLY_SSL_HS)))
		srv_cs->flags &= ~CS_FL_WAIT_FOR_HS;

	if (!si_state_in(s->si[1].state, SI_SB_EST|SI_SB_DIS|SI_SB_CLO) &&
	    (srv_conn->flags & CO_FL_WAIT_XPRT) == 0) {
		s->si[1].exp = TICK_ETERNITY;
		si_oc(&s->si[1])->flags |= CF_WRITE_NULL;
		if (s->si[1].state == SI_ST_CON)
			s->si[1].state = SI_ST_RDY;
	}

	/* Report EOI on the channel if it was reached from the mux point of
	 * view.
	 *
	 * Note: This test is only required because si_cs_process is also the SI
	 *       wake callback. Otherwise si_cs_recv()/si_cs_send() already take
	 *       care of it.
	 */
	if ((srv_cs->flags & CS_FL_EOI) && !(si_ic(&s->si[1])->flags & CF_EOI))
		si_ic(&s->si[1])->flags |= (CF_EOI|CF_READ_PARTIAL);

	/* catch all sync connect while the mux is not already installed */
	if (!srv_conn->mux && !(srv_conn->flags & CO_FL_WAIT_XPRT)) {
		if (conn_create_mux(srv_conn) < 0) {
			conn_full_close(srv_conn);
			return SF_ERR_INTERNAL;
		}
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
			sockaddr_free(&s->si[1].dst);
			goto redispatch;
		}

		if (!s->si[1].err_type) {
			s->si[1].err_type = SI_ET_QUEUE_ERR;
		}

		_HA_ATOMIC_INC(&srv->counters.failed_conns);
		_HA_ATOMIC_INC(&s->be->be_counters.failed_conns);
		return 1;

	case SRV_STATUS_NOSRV:
		/* note: it is guaranteed that srv == NULL here */
		if (!s->si[1].err_type) {
			s->si[1].err_type = SI_ET_CONN_ERR;
		}

		_HA_ATOMIC_INC(&s->be->be_counters.failed_conns);
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
			_HA_ATOMIC_INC(&srv->counters.failed_conns);
		_HA_ATOMIC_INC(&s->be->be_counters.failed_conns);

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

/* Check if the connection request is in such a state that it can be aborted. */
static int back_may_abort_req(struct channel *req, struct stream *s)
{
	return ((req->flags & (CF_READ_ERROR)) ||
	        ((req->flags & (CF_SHUTW_NOW|CF_SHUTW)) &&  /* empty and client aborted */
	         (channel_is_empty(req) || (s->be->options & PR_O_ABRT_CLOSE))));
}

/* Update back stream interface status for input states SI_ST_ASS, SI_ST_QUE,
 * SI_ST_TAR. Other input states are simply ignored.
 * Possible output states are SI_ST_CLO, SI_ST_TAR, SI_ST_ASS, SI_ST_REQ, SI_ST_CON
 * and SI_ST_EST. Flags must have previously been updated for timeouts and other
 * conditions.
 */
void back_try_conn_req(struct stream *s)
{
	struct server *srv = objt_server(s->target);
	struct stream_interface *si = &s->si[1];
	struct channel *req = &s->req;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);

	if (si->state == SI_ST_ASS) {
		/* Server assigned to connection request, we have to try to connect now */
		int conn_err;

		/* Before we try to initiate the connection, see if the
		 * request may be aborted instead.
		 */
		if (back_may_abort_req(req, s)) {
			si->err_type |= SI_ET_CONN_ABRT;
			DBG_TRACE_STATE("connection aborted", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
			goto abort_connection;
		}

		conn_err = connect_server(s);
		srv = objt_server(s->target);

		if (conn_err == SF_ERR_NONE) {
			/* state = SI_ST_CON or SI_ST_EST now */
			if (srv)
				srv_inc_sess_ctr(srv);
			if (srv)
				srv_set_sess_last(srv);
			DBG_TRACE_STATE("connection attempt", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
			goto end;
		}

		/* We have received a synchronous error. We might have to
		 * abort, retry immediately or redispatch.
		 */
		if (conn_err == SF_ERR_INTERNAL) {
			if (!si->err_type) {
				si->err_type = SI_ET_CONN_OTHER;
			}

			if (srv)
				srv_inc_sess_ctr(srv);
			if (srv)
				srv_set_sess_last(srv);
			if (srv)
				_HA_ATOMIC_INC(&srv->counters.failed_conns);
			_HA_ATOMIC_INC(&s->be->be_counters.failed_conns);

			/* release other streams waiting for this server */
			sess_change_server(s, NULL);
			if (may_dequeue_tasks(srv, s->be))
				process_srv_queue(srv);

			/* Failed and not retryable. */
			si_shutr(si);
			si_shutw(si);
			req->flags |= CF_WRITE_ERROR;

			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);

			/* we may need to know the position in the queue for logging */
			pendconn_cond_unlink(s->pend_pos);

			/* no stream was ever accounted for this server */
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			DBG_TRACE_STATE("internal error during connection", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
			goto end;
		}

		/* We are facing a retryable error, but we don't want to run a
		 * turn-around now, as the problem is likely a source port
		 * allocation problem, so we want to retry now.
		 */
		si->state = SI_ST_CER;
		si->flags &= ~SI_FL_ERR;
		back_handle_st_cer(s);

		DBG_TRACE_STATE("connection error, retry", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
		/* now si->state is one of SI_ST_CLO, SI_ST_TAR, SI_ST_ASS, SI_ST_REQ */
	}
	else if (si->state == SI_ST_QUE) {
		/* connection request was queued, check for any update */
		if (!pendconn_dequeue(s)) {
			/* The connection is not in the queue anymore. Either
			 * we have a server connection slot available and we
			 * go directly to the assigned state, or we need to
			 * load-balance first and go to the INI state.
			 */
			si->exp = TICK_ETERNITY;
			if (unlikely(!(s->flags & SF_ASSIGNED)))
				si->state = SI_ST_REQ;
			else {
				s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
				si->state = SI_ST_ASS;
			}
			DBG_TRACE_STATE("dequeue connection request", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
			goto end;
		}

		/* Connection request still in queue... */
		if (si->flags & SI_FL_EXP) {
			/* ... and timeout expired */
			si->exp = TICK_ETERNITY;
			si->flags &= ~SI_FL_EXP;
			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);

			/* we may need to know the position in the queue for logging */
			pendconn_cond_unlink(s->pend_pos);

			if (srv)
				_HA_ATOMIC_INC(&srv->counters.failed_conns);
			_HA_ATOMIC_INC(&s->be->be_counters.failed_conns);
			si_shutr(si);
			si_shutw(si);
			req->flags |= CF_WRITE_TIMEOUT;
			if (!si->err_type)
				si->err_type = SI_ET_QUEUE_TO;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			DBG_TRACE_STATE("connection request still queued", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
			goto end;
		}

		/* Connection remains in queue, check if we have to abort it */
		if (back_may_abort_req(req, s)) {
			s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);

			/* we may need to know the position in the queue for logging */
			pendconn_cond_unlink(s->pend_pos);

			si->err_type |= SI_ET_QUEUE_ABRT;
			DBG_TRACE_STATE("abort queued connection request", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
			goto abort_connection;
		}

		/* Nothing changed */
	}
	else if (si->state == SI_ST_TAR) {
		/* Connection request might be aborted */
		if (back_may_abort_req(req, s)) {
			si->err_type |= SI_ET_CONN_ABRT;
			DBG_TRACE_STATE("connection aborted", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
			goto abort_connection;
		}

		if (!(si->flags & SI_FL_EXP))
			return;  /* still in turn-around */

		si->flags &= ~SI_FL_EXP;
		si->exp = TICK_ETERNITY;

		/* we keep trying on the same server as long as the stream is
		 * marked "assigned".
		 * FIXME: Should we force a redispatch attempt when the server is down ?
		 */
		if (s->flags & SF_ASSIGNED)
			si->state = SI_ST_ASS;
		else
			si->state = SI_ST_REQ;

		DBG_TRACE_STATE("retry connection now", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
	}

  end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
	return;

abort_connection:
	/* give up */
	si->exp = TICK_ETERNITY;
	si->flags &= ~SI_FL_EXP;
	si_shutr(si);
	si_shutw(si);
	si->state = SI_ST_CLO;
	if (s->srv_error)
		s->srv_error(s, si);
	DBG_TRACE_DEVEL("leaving on error", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
	return;
}

/* This function initiates a server connection request on a stream interface
 * already in SI_ST_REQ state. Upon success, the state goes to SI_ST_ASS for
 * a real connection to a server, indicating that a server has been assigned,
 * or SI_ST_EST for a successful connection to an applet. It may also return
 * SI_ST_QUE, or SI_ST_CLO upon error.
 */
void back_handle_st_req(struct stream *s)
{
	struct stream_interface *si = &s->si[1];

	if (si->state != SI_ST_REQ)
		return;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);

	if (unlikely(obj_type(s->target) == OBJ_TYPE_APPLET)) {
		/* the applet directly goes to the EST state */
		struct appctx *appctx = objt_appctx(si->end);

		if (!appctx || appctx->applet != __objt_applet(s->target))
			appctx = si_register_handler(si, objt_applet(s->target));

		if (!appctx) {
			/* No more memory, let's immediately abort. Force the
			 * error code to ignore the ERR_LOCAL which is not a
			 * real error.
			 */
			s->flags &= ~(SF_ERR_MASK | SF_FINST_MASK);

			si_shutr(si);
			si_shutw(si);
			s->req.flags |= CF_WRITE_ERROR;
			si->err_type = SI_ET_CONN_RES;
			si->state = SI_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, si);
			DBG_TRACE_STATE("failed to register applet", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
			goto end;
		}

		if (tv_iszero(&s->logs.tv_request))
			s->logs.tv_request = now;
		s->logs.t_queue   = tv_ms_elapsed(&s->logs.tv_accept, &now);
		si->state         = SI_ST_EST;
		si->err_type      = SI_ET_NONE;
		be_set_sess_last(s->be);

		DBG_TRACE_STATE("applet registered", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
		/* let back_establish() finish the job */
		goto end;
	}

	/* Try to assign a server */
	if (srv_redispatch_connect(s) != 0) {
		/* We did not get a server. Either we queued the
		 * connection request, or we encountered an error.
		 */
		if (si->state == SI_ST_QUE) {
			DBG_TRACE_STATE("connection request queued", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
			goto end;
		}

		/* we did not get any server, let's check the cause */
		si_shutr(si);
		si_shutw(si);
		s->req.flags |= CF_WRITE_ERROR;
		if (!si->err_type)
			si->err_type = SI_ET_CONN_OTHER;
		si->state = SI_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, si);
		DBG_TRACE_STATE("connection request failed", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
		goto end;
	}

	/* The server is assigned */
	s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);
	si->state = SI_ST_ASS;
	be_set_sess_last(s->be);
	DBG_TRACE_STATE("connection request assigned to a server", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);

  end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
}

/* This function is called with (si->state == SI_ST_CON) meaning that a
 * connection was attempted and that the file descriptor is already allocated.
 * We must check for timeout, error and abort. Possible output states are
 * SI_ST_CER (error), SI_ST_DIS (abort), and SI_ST_CON (no change). This only
 * works with connection-based streams. We know that there were no I/O event
 * when reaching this function. Timeouts and errors are *not* cleared.
 */
void back_handle_st_con(struct stream *s)
{
	struct stream_interface *si = &s->si[1];
	struct channel *req = &s->req;
	struct channel *rep = &s->res;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);

	/* the client might want to abort */
	if ((rep->flags & CF_SHUTW) ||
	    ((req->flags & CF_SHUTW_NOW) &&
	     (channel_is_empty(req) || (s->be->options & PR_O_ABRT_CLOSE)))) {
		si->flags |= SI_FL_NOLINGER;
		si_shutw(si);
		si->err_type |= SI_ET_CONN_ABRT;
		if (s->srv_error)
			s->srv_error(s, si);
		/* Note: state = SI_ST_DIS now */
		DBG_TRACE_STATE("client abort during connection attempt", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
		goto end;
	}

 done:
	/* retryable error ? */
	if (si->flags & (SI_FL_EXP|SI_FL_ERR)) {
		if (!si->err_type) {
			if (si->flags & SI_FL_ERR)
				si->err_type = SI_ET_CONN_ERR;
			else
				si->err_type = SI_ET_CONN_TO;
		}

		si->state  = SI_ST_CER;
		DBG_TRACE_STATE("connection failed, retry", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
	}

 end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
}

/* This function is called with (si->state == SI_ST_CER) meaning that a
 * previous connection attempt has failed and that the file descriptor
 * has already been released. Possible causes include asynchronous error
 * notification and time out. Possible output states are SI_ST_CLO when
 * retries are exhausted, SI_ST_TAR when a delay is wanted before a new
 * connection attempt, SI_ST_ASS when it's wise to retry on the same server,
 * and SI_ST_REQ when an immediate redispatch is wanted. The buffers are
 * marked as in error state. Timeouts and errors are cleared before retrying.
 */
void back_handle_st_cer(struct stream *s)
{
	struct stream_interface *si = &s->si[1];
	struct conn_stream *cs = objt_cs(si->end);
	struct connection *conn = cs_conn(cs);

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);

	si->exp    = TICK_ETERNITY;
	si->flags &= ~SI_FL_EXP;

	/* we probably have to release last stream from the server */
	if (objt_server(s->target)) {
		health_adjust(__objt_server(s->target), HANA_STATUS_L4_ERR);

		if (s->flags & SF_CURR_SESS) {
			s->flags &= ~SF_CURR_SESS;
			_HA_ATOMIC_DEC(&__objt_server(s->target)->cur_sess);
		}

		if ((si->flags & SI_FL_ERR) &&
		    conn && conn->err_code == CO_ER_SSL_MISMATCH_SNI) {
			/* We tried to connect to a server which is configured
			 * with "verify required" and which doesn't have the
			 * "verifyhost" directive. The server presented a wrong
			 * certificate (a certificate for an unexpected name),
			 * which implies that we have used SNI in the handshake,
			 * and that the server doesn't have the associated cert
			 * and presented a default one.
			 *
			 * This is a serious enough issue not to retry. It's
			 * especially important because this wrong name might
			 * either be the result of a configuration error, and
			 * retrying will only hammer the server, or is caused
			 * by the use of a wrong SNI value, most likely
			 * provided by the client and we don't want to let the
			 * client provoke retries.
			 */
			si->conn_retries = 0;
			DBG_TRACE_DEVEL("Bad SSL cert, disable connection retries", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
		}
	}

	/* ensure that we have enough retries left */
	si->conn_retries--;
	if (si->conn_retries < 0 || !(s->be->retry_type & PR_RE_CONN_FAILED)) {
		if (!si->err_type) {
			si->err_type = SI_ET_CONN_ERR;
		}

		if (objt_server(s->target))
			_HA_ATOMIC_INC(&objt_server(s->target)->counters.failed_conns);
		_HA_ATOMIC_INC(&s->be->be_counters.failed_conns);
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));

		/* shutw is enough so stop a connecting socket */
		si_shutw(si);
		s->req.flags |= CF_WRITE_ERROR;
		s->res.flags |= CF_READ_ERROR;

		si->state = SI_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, si);

		DBG_TRACE_STATE("connection failed", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
		goto end;
	}

	/* At this stage, we will trigger a connection retry (with or without
	 * redispatch). Thus we must release the SI endpoint on the server side
	 * an close the attached connection. It is especially important to do it
	 * now if the retry is not immediately performed, to be sure to release
	 * resources as soon as possible and to not catch errors from the lower
	 * layers in an unexpected state (i.e < ST_CONN).
	 *
	 * Note: the stream-interface will be switched to ST_REQ, ST_ASS or
	 * ST_TAR and SI_FL_ERR and SI_FL_EXP flags will be unset.
	 */
	si_release_endpoint(&s->si[1]);

	stream_choose_redispatch(s);

	if (si->flags & SI_FL_ERR) {
		/* The error was an asynchronous connection error, and we will
		 * likely have to retry connecting to the same server, most
		 * likely leading to the same result. To avoid this, we wait
		 * MIN(one second, connect timeout) before retrying. We don't
		 * do it when the failure happened on a reused connection
		 * though.
		 */

		int delay = 1000;
		const int reused = (s->flags & SF_SRV_REUSED) &&
		                   !(s->flags & SF_SRV_REUSED_ANTICIPATED);

		if (s->be->timeout.connect && s->be->timeout.connect < delay)
			delay = s->be->timeout.connect;

		if (!si->err_type)
			si->err_type = SI_ET_CONN_ERR;

		/* only wait when we're retrying on the same server */
		if ((si->state == SI_ST_ASS ||
		     (s->be->lbprm.algo & BE_LB_KIND) != BE_LB_KIND_RR ||
		     (s->be->srv_act <= 1)) && !reused) {
			si->state = SI_ST_TAR;
			si->exp = tick_add(now_ms, MS_TO_TICKS(delay));
		}
		si->flags &= ~SI_FL_ERR;
		DBG_TRACE_STATE("retry a new connection", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
	}

  end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
}

/* This function is called with (si->state == SI_ST_RDY) meaning that a
 * connection was attempted, that the file descriptor is already allocated,
 * and that it has succeeded. We must still check for errors and aborts.
 * Possible output states are SI_ST_EST (established), SI_ST_CER (error),
 * and SI_ST_DIS (abort). This only works with connection-based streams.
 * Timeouts and errors are *not* cleared.
 */
void back_handle_st_rdy(struct stream *s)
{
	struct stream_interface *si = &s->si[1];
	struct channel *req = &s->req;
	struct channel *rep = &s->res;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
	/* We know the connection at least succeeded, though it could have
	 * since met an error for any other reason. At least it didn't time out
	 * even though the timeout might have been reported right after success.
	 * We need to take care of various situations here :
	 *   - everything might be OK. We have to switch to established.
	 *   - an I/O error might have been reported after a successful transfer,
	 *     which is not retryable and needs to be logged correctly, and needs
	 *     established as well
	 *   - SI_ST_CON implies !CF_WROTE_DATA but not conversely as we could
	 *     have validated a connection with incoming data (e.g. TCP with a
	 *     banner protocol), or just a successful connect() probe.
	 *   - the client might have requested a connection abort, this needs to
	 *     be checked before we decide to retry anything.
	 */

	/* it's still possible to handle client aborts or connection retries
	 * before any data were sent.
	 */
	if (!(req->flags & CF_WROTE_DATA)) {
		/* client abort ? */
		if ((rep->flags & CF_SHUTW) ||
		    ((req->flags & CF_SHUTW_NOW) &&
		     (channel_is_empty(req) || (s->be->options & PR_O_ABRT_CLOSE)))) {
			/* give up */
			si->flags |= SI_FL_NOLINGER;
			si_shutw(si);
			si->err_type |= SI_ET_CONN_ABRT;
			if (s->srv_error)
				s->srv_error(s, si);
			DBG_TRACE_STATE("client abort during connection attempt", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
			goto end;
		}

		/* retryable error ? */
		if (si->flags & SI_FL_ERR) {
			if (!si->err_type)
				si->err_type = SI_ET_CONN_ERR;
			si->state = SI_ST_CER;
			DBG_TRACE_STATE("connection failed, retry", STRM_EV_STRM_PROC|STRM_EV_SI_ST|STRM_EV_STRM_ERR, s);
			goto end;
		}
	}

	/* data were sent and/or we had no error, back_establish() will
	 * now take over.
	 */
	DBG_TRACE_STATE("connection established", STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
	si->err_type = SI_ET_NONE;
	si->state    = SI_ST_EST;

  end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_SI_ST, s);
}

/* sends a log message when a backend goes down, and also sets last
 * change date.
 */
void set_backend_down(struct proxy *be)
{
	be->last_change = now.tv_sec;
	_HA_ATOMIC_INC(&be->down_trans);

	if (!(global.mode & MODE_STARTING)) {
		ha_alert("%s '%s' has no server available!\n", proxy_type_str(be), be->id);
		send_log(be, LOG_EMERG, "%s %s has no server available!\n", proxy_type_str(be), be->id);
	}
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
	uint16_t port;
	uint32_t addr;
	char *p;

	DBG_TRACE_ENTER(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);

	if (s->flags & SF_ASSIGNED)
		goto no_cookie;

	memset(&smp, 0, sizeof(smp));

	ret = fetch_rdp_cookie_name(s, &smp, s->be->rdp_cookie_name, s->be->rdp_cookie_len);
	if (ret == 0 || (smp.flags & SMP_F_MAY_CHANGE) || smp.data.u.str.data == 0)
		goto no_cookie;

	/* Considering an rdp cookie detected using acl, str ended with <cr><lf> and should return.
	 * The cookie format is <ip> "." <port> where "ip" is the integer corresponding to the
	 * server's IP address in network order, and "port" is the integer corresponding to the
	 * server's port in network order. Comments please Emeric.
	 */
	addr = strtoul(smp.data.u.str.area, &p, 10);
	if (*p != '.')
		goto no_cookie;
	p++;

	port = ntohs(strtoul(p, &p, 10));
	if (*p != '.')
		goto no_cookie;

	s->target = NULL;
	while (srv) {
		if (srv->addr.ss_family == AF_INET &&
		    port == srv->svc_port &&
		    addr == ((struct sockaddr_in *)&srv->addr)->sin_addr.s_addr) {
			if ((srv->cur_state != SRV_ST_STOPPED) || (px->options & PR_O_PERSIST)) {
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
	DBG_TRACE_LEAVE(STRM_EV_STRM_ANA|STRM_EV_TCP_ANA, s);
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
	else if (algo == BE_LB_ALGO_NONE)
		return "none";
	else
		return "unknown";
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

	if (strcmp(args[0], "roundrobin") == 0) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RR;
	}
	else if (strcmp(args[0], "static-rr") == 0) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_SRR;
	}
	else if (strcmp(args[0], "first") == 0) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_FAS;
	}
	else if (strcmp(args[0], "leastconn") == 0) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_LC;
	}
	else if (!strncmp(args[0], "random", 6)) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RND;
		curproxy->lbprm.arg_opt1 = 2;

		if (*(args[0] + 6) == '(' && *(args[0] + 7) != ')') { /* number of draws */
			const char *beg;
			char *end;

			beg = args[0] + 7;
			curproxy->lbprm.arg_opt1 = strtol(beg, &end, 0);

			if (*end != ')') {
				if (!*end)
					memprintf(err, "random : missing closing parenthesis.");
				else
					memprintf(err, "random : unexpected character '%c' after argument.", *end);
				return -1;
			}

			if (curproxy->lbprm.arg_opt1 < 1) {
				memprintf(err, "random : number of draws must be at least 1.");
				return -1;
			}
		}
	}
	else if (strcmp(args[0], "source") == 0) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_SH;
	}
	else if (strcmp(args[0], "uri") == 0) {
		int arg = 1;

		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_UH;
		curproxy->lbprm.arg_opt1 = 0; // "whole", "path-only"
		curproxy->lbprm.arg_opt2 = 0; // "len"
		curproxy->lbprm.arg_opt3 = 0; // "depth"

		while (*args[arg]) {
			if (strcmp(args[arg], "len") == 0) {
				if (!*args[arg+1] || (atoi(args[arg+1]) <= 0)) {
					memprintf(err, "%s : '%s' expects a positive integer (got '%s').", args[0], args[arg], args[arg+1]);
					return -1;
				}
				curproxy->lbprm.arg_opt2 = atoi(args[arg+1]);
				arg += 2;
			}
			else if (strcmp(args[arg], "depth") == 0) {
				if (!*args[arg+1] || (atoi(args[arg+1]) <= 0)) {
					memprintf(err, "%s : '%s' expects a positive integer (got '%s').", args[0], args[arg], args[arg+1]);
					return -1;
				}
				/* hint: we store the position of the ending '/' (depth+1) so
				 * that we avoid a comparison while computing the hash.
				 */
				curproxy->lbprm.arg_opt3 = atoi(args[arg+1]) + 1;
				arg += 2;
			}
			else if (strcmp(args[arg], "whole") == 0) {
				curproxy->lbprm.arg_opt1 |= 1;
				arg += 1;
			}
			else if (strcmp(args[arg], "path-only") == 0) {
				curproxy->lbprm.arg_opt1 |= 2;
				arg += 1;
			}
			else {
				memprintf(err, "%s only accepts parameters 'len', 'depth', 'path-only', and 'whole' (got '%s').", args[0], args[arg]);
				return -1;
			}
		}
	}
	else if (strcmp(args[0], "url_param") == 0) {
		if (!*args[1]) {
			memprintf(err, "%s requires an URL parameter name.", args[0]);
			return -1;
		}
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_PH;

		free(curproxy->lbprm.arg_str);
		curproxy->lbprm.arg_str = strdup(args[1]);
		curproxy->lbprm.arg_len = strlen(args[1]);
		if (*args[2]) {
			if (strcmp(args[2], "check_post") != 0) {
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

		free(curproxy->lbprm.arg_str);
		curproxy->lbprm.arg_len = end - beg;
		curproxy->lbprm.arg_str = my_strndup(beg, end - beg);
		curproxy->lbprm.arg_opt1 = 0;

		if (*args[1]) {
			if (strcmp(args[1], "use_domain_only") != 0) {
				memprintf(err, "%s only accepts 'use_domain_only' modifier (got '%s').", args[0], args[1]);
				return -1;
			}
			curproxy->lbprm.arg_opt1 = 1;
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

			free(curproxy->lbprm.arg_str);
			curproxy->lbprm.arg_str = my_strndup(beg, end - beg);
			curproxy->lbprm.arg_len = end - beg;
		}
		else if ( *(args[0] + 10 ) == '\0' ) { /* default cookie name 'mstshash' */
			free(curproxy->lbprm.arg_str);
			curproxy->lbprm.arg_str = strdup("mstshash");
			curproxy->lbprm.arg_len = strlen(curproxy->lbprm.arg_str);
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
	struct proxy *px = args->data.prx;

	if (px == NULL)
		return 0;
	if (px->cap & PR_CAP_DEF)
		px = smp->px;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;

	smp->data.u.sint = be_usable_srv(px);

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
	smp->data.type = SMP_T_BOOL;
	if (!(srv->cur_admin & SRV_ADMF_MAINT) &&
	    (!(srv->check.state & CHK_ST_CONFIGURED) || (srv->cur_state != SRV_ST_STOPPED)))
		smp->data.u.sint = 1;
	else
		smp->data.u.sint = 0;
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
	struct proxy *px = args->data.prx;

	if (px == NULL)
		return 0;
	if (px->cap & PR_CAP_DEF)
		px = smp->px;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	for (iterator = px->srv; iterator; iterator = iterator->next) {
		if (iterator->cur_state == SRV_ST_STOPPED)
			continue;

		if (iterator->maxconn == 0 || iterator->maxqueue == 0) {
			/* configuration is stupid */
			smp->data.u.sint = -1;  /* FIXME: stupid value! */
			return 1;
		}

		smp->data.u.sint += (iterator->maxconn - iterator->cur_sess)
		                       +  (iterator->maxqueue - iterator->queue.length);
	}

	return 1;
}

/* set temp integer to the id of the backend */
static int
smp_fetch_be_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct proxy *px = NULL;

	if (smp->strm)
		px = smp->strm->be;
	else if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		px = __objt_check(smp->sess->origin)->proxy;
	if (!px)
		return 0;

	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = px->uuid;
	return 1;
}

/* set string to the name of the backend */
static int
smp_fetch_be_name(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct proxy *px = NULL;

	if (smp->strm)
		px = smp->strm->be;
	else if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		px = __objt_check(smp->sess->origin)->proxy;
	if (!px)
		return 0;

	smp->data.u.str.area = (char *)px->id;
	if (!smp->data.u.str.area)
	        return 0;

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);

	return 1;
}

/* set temp integer to the id of the server */
static int
smp_fetch_srv_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct server *srv = NULL;

	if (smp->strm)
		srv = objt_server(smp->strm->target);
	else if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		srv = __objt_check(smp->sess->origin)->server;
	if (!srv)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = srv->puid;

	return 1;
}

/* set string to the name of the server */
static int
smp_fetch_srv_name(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct server *srv = NULL;

	if (smp->strm)
		srv = objt_server(smp->strm->target);
	else if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		srv = __objt_check(smp->sess->origin)->server;
	if (!srv)
		return 0;

	smp->data.u.str.area = srv->id;
	if (!smp->data.u.str.area)
	        return 0;

	smp->data.type = SMP_T_STR;
	smp->data.u.str.data = strlen(smp->data.u.str.area);

	return 1;
}

/* set temp integer to the number of connections per second reaching the backend.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_be_sess_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct proxy *px = args->data.prx;

	if (px == NULL)
		return 0;
	if (px->cap & PR_CAP_DEF)
		px = smp->px;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = read_freq_ctr(&px->be_sess_per_sec);
	return 1;
}

/* set temp integer to the number of concurrent connections on the backend.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_be_conn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct proxy *px = args->data.prx;

	if (px == NULL)
		return 0;
	if (px->cap & PR_CAP_DEF)
		px = smp->px;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = px->beconn;
	return 1;
}

/* set temp integer to the number of available connections across available
	*	servers on the backend.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
	*/
static int
smp_fetch_be_conn_free(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct server *iterator;
	struct proxy *px = args->data.prx;
	unsigned int maxconn;

	if (px == NULL)
		return 0;
	if (px->cap & PR_CAP_DEF)
		px = smp->px;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	for (iterator = px->srv; iterator; iterator = iterator->next) {
		if (iterator->cur_state == SRV_ST_STOPPED)
			continue;

		px = iterator->proxy;
		if (!srv_currently_usable(iterator) ||
		    ((iterator->flags & SRV_F_BACKUP) &&
		     (px->srv_act || (iterator != px->lbprm.fbck && !(px->options & PR_O_USE_ALL_BK)))))
			continue;

		if (iterator->maxconn == 0) {
			/* one active server is unlimited, return -1 */
			smp->data.u.sint = -1;
			return 1;
		}

		maxconn = srv_dynamic_maxconn(iterator);
		if (maxconn > iterator->cur_sess)
			smp->data.u.sint += maxconn - iterator->cur_sess;
	}

	return 1;
}

/* set temp integer to the total number of queued connections on the backend.
 * Accepts exactly 1 argument. Argument is a backend, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_queue_size(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct proxy *px = args->data.prx;

	if (px == NULL)
		return 0;
	if (px->cap & PR_CAP_DEF)
		px = smp->px;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = px->totpend;
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
	struct proxy *px = args->data.prx;
	int nbsrv;

	if (px == NULL)
		return 0;
	if (px->cap & PR_CAP_DEF)
		px = smp->px;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;

	nbsrv = be_usable_srv(px);

	if (nbsrv > 0)
		smp->data.u.sint = (px->totpend + nbsrv - 1) / nbsrv;
	else
		smp->data.u.sint = px->totpend * 2;

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
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = args->data.srv->cur_sess;
	return 1;
}

/* set temp integer to the number of available connections on the server in the backend.
 * Accepts exactly 1 argument. Argument is a server, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_srv_conn_free(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	unsigned int maxconn;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;

	if (args->data.srv->maxconn == 0) {
		/* one active server is unlimited, return -1 */
		smp->data.u.sint = -1;
		return 1;
	}

	maxconn = srv_dynamic_maxconn(args->data.srv);
	if (maxconn > args->data.srv->cur_sess)
		smp->data.u.sint = maxconn - args->data.srv->cur_sess;
	else
		smp->data.u.sint = 0;

	return 1;
}

/* set temp integer to the number of connections pending in the server's queue.
 * Accepts exactly 1 argument. Argument is a server, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_srv_queue(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = args->data.srv->queue.length;
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
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = read_freq_ctr(&args->data.srv->sess_per_sec);
	return 1;
}

/* set temp integer to the server weight.
 * Accepts exactly 1 argument. Argument is a server, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_srv_weight(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct server *srv = args->data.srv;
	struct proxy *px = srv->proxy;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (srv->cur_eweight * px->lbprm.wmult + px->lbprm.wdiv - 1) / px->lbprm.wdiv;
	return 1;
}

/* set temp integer to the server initial weight.
 * Accepts exactly 1 argument. Argument is a server, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_srv_iweight(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = args->data.srv->iweight;
	return 1;
}

/* set temp integer to the server user-specified weight.
 * Accepts exactly 1 argument. Argument is a server, other types will lead to
 * undefined behaviour.
 */
static int
smp_fetch_srv_uweight(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = args->data.srv->uweight;
	return 1;
}

static int
smp_fetch_be_server_timeout(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	struct proxy *px = NULL;

	if (smp->strm)
		px = smp->strm->be;
	else if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		px = __objt_check(smp->sess->origin)->proxy;
	if (!px)
		return 0;

	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = TICKS_TO_MS(px->timeout.server);
	return 1;
}

static int
smp_fetch_be_tunnel_timeout(const struct arg *args, struct sample *smp, const char *km, void *private)
{
	struct proxy *px = NULL;

	if (smp->strm)
		px = smp->strm->be;
	else if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		px = __objt_check(smp->sess->origin)->proxy;
	if (!px)
		return 0;

	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = TICKS_TO_MS(px->timeout.tunnel);
	return 1;
}

static int sample_conv_nbsrv(const struct arg *args, struct sample *smp, void *private)
{

	struct proxy *px;

	if (!smp_make_safe(smp))
		return 0;

	px = proxy_find_by_name(smp->data.u.str.area, PR_CAP_BE, 0);
	if (!px)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = be_usable_srv(px);

	return 1;
}

static int
sample_conv_srv_queue(const struct arg *args, struct sample *smp, void *private)
{
	struct proxy *px;
	struct server *srv;
	char *bksep;

	if (!smp_make_safe(smp))
		return 0;

	bksep = strchr(smp->data.u.str.area, '/');

	if (bksep) {
		*bksep = '\0';
		px = proxy_find_by_name(smp->data.u.str.area, PR_CAP_BE, 0);
		if (!px)
			return 0;
		smp->data.u.str.area = bksep + 1;
	} else {
		if (!(smp->px->cap & PR_CAP_BE))
			return 0;
		px = smp->px;
	}

	srv = server_find_by_name(px, smp->data.u.str.area);
	if (!srv)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = srv->queue.length;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "avg_queue",         smp_fetch_avg_queue_size,    ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "be_conn",           smp_fetch_be_conn,           ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "be_conn_free",      smp_fetch_be_conn_free,      ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "be_id",             smp_fetch_be_id,             0,           NULL, SMP_T_SINT, SMP_USE_BKEND, },
	{ "be_name",           smp_fetch_be_name,           0,           NULL, SMP_T_STR,  SMP_USE_BKEND, },
	{ "be_server_timeout", smp_fetch_be_server_timeout, 0,           NULL, SMP_T_SINT, SMP_USE_BKEND, },
	{ "be_sess_rate",      smp_fetch_be_sess_rate,      ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "be_tunnel_timeout", smp_fetch_be_tunnel_timeout, 0,           NULL, SMP_T_SINT, SMP_USE_BKEND, },
	{ "connslots",         smp_fetch_connslots,         ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "nbsrv",             smp_fetch_nbsrv,             ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "queue",             smp_fetch_queue_size,        ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_conn",          smp_fetch_srv_conn,          ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_conn_free",     smp_fetch_srv_conn_free,     ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_id",            smp_fetch_srv_id,            0,           NULL, SMP_T_SINT, SMP_USE_SERVR, },
	{ "srv_is_up",         smp_fetch_srv_is_up,         ARG1(1,SRV), NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "srv_name",          smp_fetch_srv_name,          0,           NULL, SMP_T_STR,  SMP_USE_SERVR, },
	{ "srv_queue",         smp_fetch_srv_queue,         ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_sess_rate",     smp_fetch_srv_sess_rate,     ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_weight",        smp_fetch_srv_weight,        ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_iweight",       smp_fetch_srv_iweight,       ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_uweight",       smp_fetch_srv_uweight,       ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_kws);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "nbsrv",     sample_conv_nbsrv,     0, NULL, SMP_T_STR, SMP_T_SINT },
	{ "srv_queue", sample_conv_srv_queue, 0, NULL, SMP_T_STR, SMP_T_SINT },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);

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
