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
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include <import/ceb64_tree.h>

#include <haproxy/api.h>
#include <haproxy/acl.h>
#include <haproxy/activity.h>
#include <haproxy/arg.h>
#include <haproxy/backend.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/counters.h>
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
#include <haproxy/lb_ss.h>
#include <haproxy/log.h>
#include <haproxy/namespace.h>
#include <haproxy/obj_type.h>
#include <haproxy/payload.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/queue.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>
#include <haproxy/trace.h>

#define TRACE_SOURCE &trace_strm

/* helper function to invoke the correct hash method */
unsigned int gen_hash(const struct proxy* px, const char* key, unsigned long len)
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
	case BE_LB_HFCN_NONE:
		/* use key as a hash */
		{
			const char *_key = key;

			hash = read_int64(&_key, _key + len);
		}
		break;
	case BE_LB_HFCN_SDBM:
		/* this is the default hash function */
	default:
		hash = hash_sdbm(key, len);
		break;
	}

	if ((px->lbprm.algo & BE_LB_HASH_MOD) == BE_LB_HMOD_AVAL)
		hash = full_hash(hash);

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
struct server *get_server_sh(struct proxy *px, const char *addr, int len, const struct server *avoid)
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
	/* FIXME: why don't we use gen_hash() here as well?
	 * -> we don't take into account hash function from "hash_type"
	 * options here..
	 */
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
struct server *get_server_uh(struct proxy *px, char *uri, int uri_len, const struct server *avoid)
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
struct server *get_server_ph(struct proxy *px, const char *uri, int uri_len, const struct server *avoid)
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
struct server *get_server_ph_post(struct stream *s, const struct server *avoid)
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
struct server *get_server_hh(struct stream *s, const struct server *avoid)
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
				/* The pointer is rewound to the dot before the
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

 hash_done:
	if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash, avoid);
	else
		return map_get_server_hash(px, hash);
}

/* RDP Cookie HASH.  */
struct server *get_server_rch(struct stream *s, const struct server *avoid)
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

 hash_done:
	if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash, avoid);
	else
		return map_get_server_hash(px, hash);
}

/* sample expression HASH. Returns NULL if the sample is not found or if there
 * are no server, relying on the caller to fall back to round robin instead.
 */
struct server *get_server_expr(struct stream *s, const struct server *avoid)
{
	struct proxy  *px = s->be;
	struct sample *smp;
	unsigned int hash = 0;

	if (px->lbprm.tot_weight == 0)
		return NULL;

	/* note: no need to hash if there's only one server left */
	if (px->lbprm.tot_used == 1)
		goto hash_done;

	smp = sample_fetch_as_type(px, s->sess, s, SMP_OPT_DIR_REQ | SMP_OPT_FINAL, px->lbprm.expr, SMP_T_BIN);
	if (!smp)
		return NULL;

	/* We have the desired data. Let's hash it according to the configured
	 * options and algorithm.
	 */
	hash = gen_hash(px, smp->data.u.str.area, smp->data.u.str.data);

 hash_done:
	if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
		return chash_get_server_hash(px, hash, avoid);
	else
		return map_get_server_hash(px, hash);
}

/* random value  */
struct server *get_server_rnd(struct stream *s, const struct server *avoid)
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
	    (curr->queueslength || (curr->maxconn && curr->served >= srv_dynamic_maxconn(curr))))
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
		struct sess_priv_conns *pconns;
		list_for_each_entry(pconns, &s->sess->priv_conns, sess_el) {
			struct server *tmpsrv = objt_server(pconns->target);

			if (tmpsrv && tmpsrv->proxy == s->be &&
			    ((s->sess->flags & SESS_FL_PREFER_LAST) ||
			     (!s->be->max_ka_queue ||
			      server_has_room(tmpsrv) || (
			      tmpsrv->queueslength + 1 < s->be->max_ka_queue))) &&
			    srv_currently_usable(tmpsrv)) {
				list_for_each_entry(conn, &pconns->conn_list, sess_el) {
					if (!(conn->flags & CO_FL_WAIT_XPRT)) {
						srv = tmpsrv;
						stream_set_srv_target(s, srv);
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
		if (s->be->queueslength && s->be->served && s->be->queueslength != s->be->beconn &&
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
				src = sc_src(s->scf);
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

			case BE_LB_HASH_SMP:
				/* sample expression hashing */
				srv = get_server_expr(s, prev_srv);
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
			if ((s->be->lbprm.algo & BE_LB_KIND) == BE_LB_KIND_SA) {
				/* some special algos that cannot be grouped together */

				if ((s->be->lbprm.algo & BE_LB_PARM) == BE_LB_SA_SS)
					srv = ss_get_server(s->be);

				break;
			}
			/* unknown balancing algorithm */
			err = SRV_STATUS_INTERNAL;
			goto out;
		}

		if (!srv) {
			err = SRV_STATUS_FULL;
			goto out;
		}
		else if (srv != prev_srv) {
			if (s->be_tgcounters)
				_HA_ATOMIC_INC(&s->be_tgcounters->cum_lbconn);
			if (srv->counters.shared.tg[tgid - 1])
				_HA_ATOMIC_INC(&srv->counters.shared.tg[tgid - 1]->cum_lbconn);
		}
		stream_set_srv_target(s, srv);
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

/* Allocate <*ss> address unless already set. Address is then set to the
 * destination endpoint of <srv> server, or via <s> from a dispatch or
 * transparent address.
 *
 * Note that no address is allocated if server relies on reverse HTTP.
 *
 * Returns SRV_STATUS_OK on success, or if already already set. Else an error
 * code is returned and <*ss> is not allocated.
 */
static int alloc_dst_address(struct sockaddr_storage **ss,
                             struct server *srv, struct stream *s)
{
	const struct sockaddr_storage *dst;

	if (*ss)
		return SRV_STATUS_OK;

	if (srv && (srv->flags & SRV_F_RHTTP)) {
		/* For reverse HTTP, destination address is unknown. */
		return SRV_STATUS_OK;
	}

	if ((s->flags & SF_DIRECT) || (s->be->lbprm.algo & BE_LB_KIND)) {
		/* A server is necessarily known for this stream */
		if (!(s->flags & SF_ASSIGNED))
			return SRV_STATUS_INTERNAL;

		if (!sockaddr_alloc(ss, NULL, 0))
			return SRV_STATUS_INTERNAL;

		ASSUME_NONNULL(srv); /* srv is guaranteed by SF_ASSIGNED */

		**ss = srv->addr;
		set_host_port(*ss, srv->svc_port);
		if (!is_addr(*ss)) {
			/* if the server has no address, we use the same address
			 * the client asked, which is handy for remapping ports
			 * locally on multiple addresses at once. Nothing is done
			 * for AF_UNIX addresses.
			 */
			dst = sc_dst(s->scf);
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

			dst = sc_dst(s->scf);
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
		dst = sc_dst(s->scf);
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
				if (prev_srv->counters.shared.tg[tgid - 1])
					_HA_ATOMIC_INC(&prev_srv->counters.shared.tg[tgid - 1]->redispatches);
				if (s->be_tgcounters)
					_HA_ATOMIC_INC(&s->be_tgcounters->redispatches);
			} else {
				if (prev_srv->counters.shared.tg[tgid - 1])
					_HA_ATOMIC_INC(&prev_srv->counters.shared.tg[tgid - 1]->retries);
				if (s->be_tgcounters)
					_HA_ATOMIC_INC(&s->be_tgcounters->retries);
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
		if (srv->maxconn) {
			struct queue *queue = &srv->per_tgrp[tgid - 1].queue;
			int served;
			int got_it = 0;

			/*
			 * Make sure that there's still a slot on the server.
			 * Try to increment its served, while making sure
			 * it is < maxconn.
			 */
			if (!queue->length &&
			    (served = srv->served) < srv_dynamic_maxconn(srv)) {
				/*
				 * Attempt to increment served, while
				 * making sure it is always below maxconn
				 */

				do {
					got_it = _HA_ATOMIC_CAS(&srv->served,
							        &served, served + 1);
				} while (!got_it && served < srv_dynamic_maxconn(srv) &&
					 __ha_cpu_relax());
			}
			if (!got_it) {
				if (srv->maxqueue > 0 && srv->queueslength >= srv->maxqueue)
					return SRV_STATUS_FULL;

				p = pendconn_add(s);
				if (p) {
					/* There's a TOCTOU here: it may happen that between the
					 * moment we decided to queue the request and the moment
					 * it was done, the last active request on the server
					 * ended and no new one will be able to dequeue that one.
					 * Since we already have our server we don't care, this
					 * will be handled by the caller which will check for
					 * this condition and will immediately dequeue it if
					 * possible.
					 */
					return SRV_STATUS_QUEUED;
				}
				else
					return SRV_STATUS_INTERNAL;
			}
		} else
			_HA_ATOMIC_INC(&srv->served);

		/* OK, we can use this server. Let's reserve our place */
		sess_change_server(s, srv);
		return SRV_STATUS_OK;

	case SRV_STATUS_FULL:
		/* queue this stream into the proxy's queue */
		p = pendconn_add(s);
		if (p) {
			/* There's a TOCTOU here: it may happen that between the
			 * moment we decided to queue the request and the moment
			 * it was done, the last active request in the backend
			 * ended and no new one will be able to dequeue that one.
			 * This is more visible with maxconn 1 where it can
			 * happen 1/1000 times, though the vast majority are
			 * correctly recovered from.
			 * To work around that, when a server is getting idle,
			 * it will set the ready_srv field of the proxy.
			 * Here, if ready_srv is non-NULL, we get that server,
			 * and we attempt to switch its served from 0 to 1.
			 * If it works, then we can just run, otherwise,
			 * it means another stream will be running, and will
			 * dequeue us eventually, so we can just do nothing.
			 */
			if (unlikely(s->be->ready_srv != NULL)) {
				struct server *newserv;

				newserv = HA_ATOMIC_XCHG(&s->be->ready_srv, NULL);
				if (newserv != NULL) {
					int got_slot = 0;

					while (_HA_ATOMIC_LOAD(&newserv->served) == 0) {
						int served = 0;

						if (_HA_ATOMIC_CAS(&newserv->served, &served, 1)) {
							got_slot = 1;
							break;
						}
					}
					if (!got_slot) {
						/*
						 * Somebody else can now
						 * wake up us, stop now.
						 */
						return SRV_STATUS_QUEUED;
					}

					HA_SPIN_LOCK(QUEUE_LOCK, &p->queue->lock);
					if (!p->node.node.leaf_p) {
						/*
						 * Okay we've been queued and
						 * unqueued already, just leave
						 */
						_HA_ATOMIC_DEC(&newserv->served);
						return SRV_STATUS_QUEUED;
					}
					eb32_delete(&p->node);
					HA_SPIN_UNLOCK(QUEUE_LOCK, &p->queue->lock);

					_HA_ATOMIC_DEC(&p->queue->length);

					if (p->queue->sv)
						_HA_ATOMIC_DEC(&p->queue->sv->queueslength);
					else
						_HA_ATOMIC_DEC(&p->queue->px->queueslength);

					_HA_ATOMIC_INC(&p->queue->idx);
					_HA_ATOMIC_DEC(&s->be->totpend);

					pool_free(pool_head_pendconn, p);

					s->flags |= SF_ASSIGNED;
					stream_set_srv_target(s, newserv);

					s->pend_pos = NULL;
					sess_change_server(s, newserv);
					return SRV_STATUS_OK;
				}
			}

			return SRV_STATUS_QUEUED;
		}
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

/* Allocate an address if an explicit source address must be used for a backend
 * connection.
 *
 * Two parameters are taken into account to check if specific source address is
 * configured. The first one is <srv> which is the server instance to connect
 * to. It may be NULL when dispatching is used. The second one <be> is the
 * backend instance which contains the target server or dispatch.
 *
 * A stream instance <s> can be used to set the stream owner of the backend
 * connection. It is a required parameter if the source address is a dynamic
 * parameter.
 *
 * Returns SRV_STATUS_OK if either no specific source address specified or its
 * allocation is done correctly. On error returns SRV_STATUS_INTERNAL.
 */
int alloc_bind_address(struct sockaddr_storage **ss,
                       struct server *srv, struct proxy *be,
                       struct stream *s)
{
#if defined(CONFIG_HAP_TRANSPARENT)
	const struct sockaddr_storage *addr;
	struct conn_src *src = NULL;
	struct sockaddr_in *sin;
	char *vptr;
	size_t vlen;
#endif

	/* Ensure the function will not overwrite an allocated address. */
	BUG_ON(*ss);

#if defined(CONFIG_HAP_TRANSPARENT)
	if (srv && srv->conn_src.opts & CO_SRC_BIND)
		src = &srv->conn_src;
	else if (be->conn_src.opts & CO_SRC_BIND)
		src = &be->conn_src;

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
		BUG_ON(!s); /* Dynamic source setting requires a stream instance. */

		/* FIXME: what can we do if the client connects in IPv6 or unix socket ? */
		addr = sc_src(s->scf);
		if (!addr)
			return SRV_STATUS_INTERNAL;

		if (!sockaddr_alloc(ss, NULL, 0))
			return SRV_STATUS_INTERNAL;

		**ss = *addr;
		if ((src->opts & CO_SRC_TPROXY_MASK) == CO_SRC_TPROXY_CIP) {
			/* always set port to zero when using "clientip", or
			 * the idle connection hash will include the port part.
			 */
			if (addr->ss_family == AF_INET)
				((struct sockaddr_in *)*ss)->sin_port = 0;
			else if (addr->ss_family == AF_INET6)
				((struct sockaddr_in6 *)*ss)->sin6_port = 0;
		}
		break;

	case CO_SRC_TPROXY_DYN:
		BUG_ON(!s); /* Dynamic source setting requires a stream instance. */

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

/* Attempt to retrieve a connection matching <hash> from <srv> server lists for
 * connection reuse. If <is_safe> is true, only connections considered safe for
 * reuse are inspected. Thread-local list is inspected first. If no matching
 * connection is found, takeover may be performed to steal a connection from a
 * foreign thread.
 *
 * If <reuse_mode> backend policy is safe and connection MUX is subject to
 * head-of-line blocking, connection is attached to <sess> session, which
 * prevents mixing several frontend client over it.
 *
 * Returns the connection instance if found.
 */
struct connection *conn_backend_get(int reuse_mode,
                                    struct server *srv, struct session *sess,
                                    int is_safe, int64_t hash)
{
	const struct tgroup_info *curtg = tg;
	struct connection *conn = NULL;
	unsigned int curtgid = tgid;
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
		conn_delete_from_tree(conn, tid);

	/* If we failed to pick a connection from the idle list, let's try again with
	 * the safe list.
	 */
	if (!conn && !is_safe && srv->curr_safe_nb > 0) {
		conn = srv_lookup_conn(&srv->per_thr[tid].safe_conns, hash);
		if (conn) {
			conn_delete_from_tree(conn, tid);
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
	 * too few idle conns and the server protocol supports establishing
	 * connections (i.e. not a reverse-http server for example).
	 */
	if (srv->curr_idle_conns < srv->low_idle_conns &&
	    ha_used_fds < global.tune.pool_low_count) {
		const struct protocol *srv_proto = protocol_lookup(srv->addr.ss_family, PROTO_TYPE_STREAM, 0);

		if (srv_proto && srv_proto->connect)
			goto done;
	}

	/* Lookup all other threads for an idle connection, starting from last
	 * unvisited thread, but always staying in the same group.
	 */
	stop = srv->per_tgrp[tgid - 1].next_takeover;
	if (stop >= curtg->count)
		stop %= curtg->count;
	stop += curtg->base;
check_tgid:
	i = stop;
	do {
		/* safe requests looked up conns in idle tree first, then safe
		 * tree; unsafe requests are looked up in the safe conns tree.
		 */
		int search_tree = is_safe ? 1 : 0; // 0 = idle, 1 = safe
		struct ceb_root **tree;

		if (!srv->curr_idle_thr[i] || i == tid)
			continue;

		if (HA_SPIN_TRYLOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock) != 0)
			continue;

		do {
			if ((search_tree && !srv->curr_safe_nb) ||
			    (!search_tree && !srv->curr_idle_nb))
				continue;

			tree = search_tree ? &srv->per_thr[i].safe_conns : &srv->per_thr[i].idle_conns;
			conn = srv_lookup_conn(tree, hash);
			while (conn) {
				if (conn->mux->takeover && conn->mux->takeover(conn, i, 0) == 0) {
					conn_delete_from_tree(conn, i);
					_HA_ATOMIC_INC(&activity[tid].fd_takeover);
					found = 1;
					break;
				}
				conn = srv_lookup_conn_next(tree, conn);
			}
		} while (!found && ++search_tree <= 1);

		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock);
	} while (!found && (i = (i + 1 == curtg->base + curtg->count) ? curtg->base : i + 1) != stop);

	if (!found && (global.tune.tg_takeover == FULL_THREADGROUP_TAKEOVER ||
	    (global.tune.tg_takeover == RESTRICTED_THREADGROUP_TAKEOVER &&
	    srv->flags & (SRV_F_RHTTP | SRV_F_STRICT_MAXCONN)))) {
		curtgid = curtgid + 1;
		if (curtgid == global.nbtgroups + 1)
			curtgid = 1;
		/* If we haven't looped yet */
		if (MAX_TGROUPS > 1 && curtgid != tgid) {
			curtg = &ha_tgroup_info[curtgid - 1];
			stop = curtg->base;
			goto check_tgid;
		}
	}
	if (!found)
		conn = NULL;
 done:
	if (conn) {
		_HA_ATOMIC_STORE(&srv->per_tgrp[tgid - 1].next_takeover, (i + 1 == tg->base + tg->count) ? tg->base : i + 1);

		srv_use_conn(srv, conn);

		_HA_ATOMIC_DEC(&srv->curr_idle_conns);
		_HA_ATOMIC_DEC(conn->flags & CO_FL_SAFE_LIST ? &srv->curr_safe_nb : &srv->curr_idle_nb);
		_HA_ATOMIC_DEC(&srv->curr_idle_thr[i]);
		conn->flags &= ~CO_FL_LIST_MASK;
		__ha_barrier_atomic_store();

		if (reuse_mode == PR_O_REUSE_SAFE && conn->mux->flags & MX_FL_HOL_RISK) {
			/* attach the connection to the session private list */
			conn->owner = sess;
			session_add_conn(sess, conn);
		}
		else {
			srv_add_to_avail_list(srv, conn);
		}
	}

	return conn;
}

static int do_connect_server(struct stream *s, struct connection *conn)
{
	int ret = SF_ERR_NONE;
	int conn_flags = 0;

	if (unlikely(!conn || !conn->ctrl || !conn->ctrl->connect))
		return SF_ERR_INTERNAL;

	if (co_data(&s->res))
		conn_flags |= CONNECT_HAS_DATA;
	if (s->conn_retries == s->max_retries)
		conn_flags |= CONNECT_CAN_USE_TFO;
	if (!conn_ctrl_ready(conn) || !conn_xprt_ready(conn)) {
		ret = conn->ctrl->connect(conn, conn_flags);
		if (ret != SF_ERR_NONE)
			return ret;

		/* we're in the process of establishing a connection */
		s->scb->state = SC_ST_CON;
	}
	else {
		/* try to reuse the existing connection, it will be
		 * confirmed once we can send on it.
		 */
		/* Is the connection really ready ? */
		if (conn->mux->ctl(conn, MUX_CTL_STATUS, NULL) & MUX_STATUS_READY)
			s->scb->state = SC_ST_RDY;
		else
			s->scb->state = SC_ST_CON;
	}

	/* needs src ip/port for logging */
	if (s->flags & SF_SRC_ADDR)
		conn_get_src(conn);

	return ret;
}

/*
 * Returns the first connection from a tree we managed to take over,
 * if any.
 */
static struct connection *
takeover_random_idle_conn(struct ceb_root **root, int curtid)
{
	struct connection *conn = NULL;

	conn = ceb64_item_first(root, hash_node.node, hash_node.key, struct connection);
	while (conn) {
		if (conn->mux->takeover && conn->mux->takeover(conn, curtid, 1) == 0) {
			conn_delete_from_tree(conn, curtid);
			return conn;
		}
		conn = ceb64_item_next(root, hash_node.node, hash_node.key, conn);
	}

	return NULL;
}

/*
 * Kills an idle connection, any idle connection we can get a hold on.
 * The goal is just to free a connection in case we reached the max and
 * have to establish a new one.
 * Returns -1 if there is no idle connection to kill, 0 if there are some
 * available but we failed to get one, and 1 if we successfully killed one.
 */
static int
kill_random_idle_conn(struct server *srv)
{
	struct connection *conn = NULL;
	int i;
	int curtid;
	/* No idle conn, then there is nothing we can do at this point */

	if (srv->curr_idle_conns == 0)
		return -1;
	for (i = 0; i < global.nbthread; i++) {
		curtid = (i + tid) % global.nbthread;

		if (HA_SPIN_TRYLOCK(IDLE_CONNS_LOCK, &idle_conns[curtid].idle_conns_lock) != 0)
			continue;
		conn = takeover_random_idle_conn(&srv->per_thr[curtid].idle_conns, curtid);
		if (!conn)
			conn = takeover_random_idle_conn(&srv->per_thr[curtid].safe_conns, curtid);
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[curtid].idle_conns_lock);
		if (conn)
			break;
	}
	if (conn) {
		/*
		 * We have to manually decrement counters, as srv_release_conn()
		 * will attempt to access the current tid's counters, while
		 * we may have taken the connection from a different thread.
		 */
		if (conn->flags & CO_FL_LIST_MASK) {
			_HA_ATOMIC_DEC(&srv->curr_idle_conns);
			_HA_ATOMIC_DEC(conn->flags & CO_FL_SAFE_LIST ? &srv->curr_safe_nb : &srv->curr_idle_nb);
			_HA_ATOMIC_DEC(&srv->curr_idle_thr[curtid]);
			conn->flags &= ~CO_FL_LIST_MASK;
			/*
			 * If we have no list flag then srv_release_conn()
			 * will consider the connection is used, so let's
			 * pretend it is.
			 */
			_HA_ATOMIC_INC(&srv->curr_used_conns);
		}
		conn->mux->destroy(conn->ctx);
		return 1;
	}
	return 0;
}

/* Returns backend reuse policy depending on <be>. It can be forced to always
 * mode if <srv> is not NULL and uses reverse HTTP.
 */
static int be_reuse_mode(struct proxy *be, struct server *srv)
{
	if (srv && srv->flags & SRV_F_RHTTP) {
		/* Override reuse-mode if reverse-connect is used. */
		return PR_O_REUSE_ALWS;
	}

	return be->options & PR_O_REUSE_MASK;
}

/* Calculate hash to select a matching connection for reuse. Here is the list
 * of input parameters :
 * - <srv> is the server instance. Can be NULL on dispatch/transparent proxy.
 * - <strm> is the stream instance. Can be NULL if no stream is used.
 * - <src> is the bind address if an explicit source address is used.
 * - <dst> is the destination address. Must be set in every cases, except on
 *   reverse HTTP.
 * - <name> is a string identifier associated to the connection. Set by
 *   pool-conn-name, also used for SSL SNI matching.
 *
 * Note that all input parameters can be NULL. The only requirement is that
 * it's not possible to have both <srv> and <strm> NULL at the same time.
 *
 * Returns the calculated hash.
 */
int64_t be_calculate_conn_hash(struct server *srv, struct stream *strm,
                               struct session *sess,
                               struct sockaddr_storage *src,
                               struct sockaddr_storage *dst,
                               struct ist name)
{
	struct conn_hash_params hash_params;

	/* Caller cannot set both <srv> and <strm> to NULL. */
	BUG_ON_HOT(!srv && !strm);

	/* first, set unique connection parameters and then calculate hash */
	memset(&hash_params, 0, sizeof(hash_params));

	/* 1. target */
	hash_params.target = srv ? &srv->obj_type : strm->target;

	/* 2. pool-conn-name */
	if (istlen(name)) {
		hash_params.name_prehash =
		  conn_hash_prehash(istptr(name), istlen(name));
	}

	/* 3. destination address */
	hash_params.dst_addr = dst;

	/* 4. source address */
	hash_params.src_addr = src;

	/* 5. proxy protocol */
	if (strm && srv && srv->pp_opts & SRV_PP_ENABLED) {
		struct connection *cli_conn = objt_conn(strm_orig(strm));
		int proxy_line_ret = make_proxy_line(trash.area, trash.size,
		                                     srv, cli_conn, strm, sess);
		if (proxy_line_ret) {
			hash_params.proxy_prehash =
			  conn_hash_prehash(trash.area, proxy_line_ret);
		}
	}

	/* 6. Custom mark, tos? */
	if (strm && (strm->flags & (SF_BC_MARK | SF_BC_TOS))) {
		/* mark: 32bits, tos: 8bits = 40bits
		 * last 2 bits are there to indicate if mark and/or tos are set
		 * total: 42bits:
		 *
		 * 63==== (unused) ====42    39----32 31-----------------------------0
		 * 0000000000000000000000 11 00000111 00000000000000000000000000000011
		 *                        ^^ ^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
		 *                        ||    |                     |
		 *                       /  \    \                     \
		 *                      /    \    \                     \
		 *                    tos?   mark? \             mark value (32bits)
		 *                            tos value (8bits)
		 * ie: in the above example:
		 *  - mark is set, mark = 3
		 *  - tos is set, tos = 7
		 */
		if (strm->flags & SF_BC_MARK) {
			hash_params.mark_tos_prehash |= strm->bc_mark;
			/* 41th bit: mark set */
			hash_params.mark_tos_prehash |= 1ULL << 40;
		}
		if (strm->flags & SF_BC_TOS) {
			hash_params.mark_tos_prehash |= (uint64_t)strm->bc_tos << 32;
			/* 42th bit: tos set */
			hash_params.mark_tos_prehash |= 1ULL << 41;
		}
	}

	return conn_calculate_hash(&hash_params);
}

/* Try to reuse a connection, first from <sess> session, then to <srv> server
 * lists if not NULL, matching <hash> value and <be> reuse policy. If reuse is
 * on <be> proxy successful, connection is attached to <sc> stconn instance.
 *
 * <target> must point either to the server instance, or a stream target on
 * dispatch/transparent proxy.
 *
 * <not_first_req> must be set if the underlying request is not the first one
 * conducted on <sess> session. This allows to use a connection not yet
 * labelled as safe under http-reuse safe policy.
 *
 * Returns SF_ERR_NONE if a connection has been reused. The connection instance
 * can be retrieve via <sc> stconn. SF_ERR_RESOURCE is returned if no matching
 * connection found. SF_ERR_INTERNAL is used on internal error.
 */
int be_reuse_connection(int64_t hash, struct session *sess,
                        struct proxy *be, struct server *srv,
                        struct stconn *sc, enum obj_type *target, int not_first_req)
{
	struct connection *srv_conn;
	const int reuse_mode = be_reuse_mode(be, srv);

	/* first, search for a matching connection in the session's idle conns */
	srv_conn = session_get_conn(sess, target, hash);
	if (srv_conn) {
		//DBG_TRACE_STATE("reuse connection from session", STRM_EV_STRM_PROC|STRM_EV_CS_ST, strm);
	}
	else if (srv && reuse_mode != PR_O_REUSE_NEVR) {
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
		if (!ceb_isempty(&srv->per_thr[tid].avail_conns)) {
			srv_conn = srv_lookup_conn(&srv->per_thr[tid].avail_conns, hash);
			if (srv_conn) {
				/* connection cannot be in idle list if used as an avail idle conn. */
				BUG_ON(LIST_INLIST(&srv_conn->idle_list));
				//DBG_TRACE_STATE("reuse connection from avail", STRM_EV_STRM_PROC|STRM_EV_CS_ST, strm);
			}
		}

		/* if no available connections found, search for an idle/safe */
		if (!srv_conn && srv->max_idle_conns && srv->curr_idle_conns > 0) {
			const int idle = srv->curr_idle_nb > 0;
			const int safe = srv->curr_safe_nb > 0;
			const int retry_safe = (be->retry_type & (PR_RE_CONN_FAILED | PR_RE_DISCONNECTED | PR_RE_TIMEOUT)) ==
			                                         (PR_RE_CONN_FAILED | PR_RE_DISCONNECTED | PR_RE_TIMEOUT);

			/* second column of the tables above, search for an idle then safe conn */
			if (not_first_req || retry_safe) {
				if (idle || safe)
					srv_conn = conn_backend_get(reuse_mode, srv, sess, 0, hash);
			}
			/* first column of the tables above */
			else if (reuse_mode >= PR_O_REUSE_AGGR) {
				/* search for a safe conn */
				if (safe)
					srv_conn = conn_backend_get(reuse_mode, srv, sess, 1, hash);

				/* search for an idle conn if no safe conn found on always reuse mode */
				if (!srv_conn &&
				    reuse_mode == PR_O_REUSE_ALWS && idle) {
					/* TODO conn_backend_get should not check the safe list is this case */
					srv_conn = conn_backend_get(reuse_mode, srv, sess, 0, hash);
				}
			}

			if (srv_conn) {
				//DBG_TRACE_STATE("reuse connection from idle/safe", STRM_EV_STRM_PROC|STRM_EV_CS_ST, strm);
			}
		}
	}

	if (srv_conn) {
		if (srv_conn->mux) {
			int avail = srv_conn->mux->avail_streams(srv_conn);

			if (avail <= 1) {
				/* no more streams available, remove it from the list */
				HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
				conn_delete_from_tree(srv_conn, tid);
				HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			}

			if (avail >= 1) {
				if (srv_conn->mux->attach(srv_conn, sc->sedesc, sess) == -1) {
					if (sc_reset_endp(sc) < 0)
						goto err;
					sc_ep_clr(sc, ~SE_FL_DETACHED);
				}
			}
			else {
				/* TODO cannot reuse conn finally due to no more avail
				 * streams. May be possible to lookup for a new conn
				 * to improve reuse rate, with a max retry limit.
				 */
				srv_conn = NULL;
			}
		}
	}

	return srv_conn ? SF_ERR_NONE : SF_ERR_RESOURCE;

 err:
	return SF_ERR_INTERNAL;
}

/*
 * This function initiates a connection to the server assigned to this stream
 * (s->target, (s->scb)->addr.to). It will assign a server if none
 * is assigned yet.
 * It can return one of :
 *  - SF_ERR_NONE if everything's OK
 *  - SF_ERR_SRVTO if there are no more servers
 *  - SF_ERR_SRVCL if the connection was refused by the server
 *  - SF_ERR_PRXCOND if the connection has been limited by the proxy (maxconn)
 *  - SF_ERR_RESOURCE if a system resource is lacking (eg: fd limits, ports, ...)
 *  - SF_ERR_INTERNAL for any other purely internal errors
 * Additionally, in the case of SF_ERR_RESOURCE, an emergency log will be emitted.
 * The server-facing stream connector is expected to hold a pre-allocated connection.
 */
int connect_server(struct stream *s)
{
	struct connection *cli_conn = objt_conn(strm_orig(s));
	struct connection *srv_conn = NULL;
	struct server *srv;
	int reuse_mode;
	int reuse __maybe_unused = 0;
	int may_use_early_data __maybe_unused = 1; // are we allowed to use early data ?
	int may_start_mux_now = 1; // are we allowed to start the mux now ?
	int err;
	struct sockaddr_storage *bind_addr = NULL;
	int64_t hash = 0;

	/* in standard configuration, srv will be valid
	 * it can be NULL for dispatch mode or transparent backend */
	srv = objt_server(s->target);
	reuse_mode = be_reuse_mode(s->be, srv);

	err = alloc_dst_address(&s->scb->dst, srv, s);
	if (err != SRV_STATUS_OK)
		return SF_ERR_INTERNAL;

	err = alloc_bind_address(&bind_addr, srv, s->be, s);
	if (err != SRV_STATUS_OK)
		return SF_ERR_INTERNAL;

	/* disable reuse if websocket stream and the protocol to use is not the
	 * same as the main protocol of the server.
	 */
	if (unlikely(s->flags & SF_WEBSOCKET) && srv && !srv_check_reuse_ws(srv)) {
		DBG_TRACE_STATE("skip idle connections reuse: websocket stream", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
	}
	else {
		const int not_first_req = s->txn && s->txn->flags & TX_NOT_FIRST;
		struct ist name = IST_NULL;
		struct sample *name_smp;

		if (srv && srv->pool_conn_name_expr) {
			name_smp = sample_fetch_as_type(s->be, s->sess, s,
			                                SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
			                                srv->pool_conn_name_expr, SMP_T_STR);
			if (name_smp) {
				name = ist2(name_smp->data.u.str.area,
				            name_smp->data.u.str.data);
			}
		}

		hash = be_calculate_conn_hash(srv, s, s->sess, bind_addr, s->scb->dst, name);
		err = be_reuse_connection(hash, s->sess, s->be, srv, s->scb,
		                          s->target, not_first_req);
		if (err == SF_ERR_INTERNAL)
			return err;

		if (err == SF_ERR_NONE) {
			srv_conn = sc_conn(s->scb);
			reuse = 1;
			may_start_mux_now = 0;
		}
	}

	if (ha_used_fds > global.tune.pool_high_count && srv) {
		/* We have more FDs than deemed acceptable, attempt to kill an idling connection. */
		struct connection *tokill_conn = NULL;
		/* First, try from our own idle list */
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		if (!LIST_ISEMPTY(&srv->per_thr[tid].idle_conn_list)) {
			tokill_conn = LIST_ELEM(srv->per_thr[tid].idle_conn_list.n, struct connection *, idle_list);
			conn_delete_from_tree(tokill_conn, tid);
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

				if (!LIST_ISEMPTY(&srv->per_thr[i].idle_conn_list)) {
					tokill_conn = LIST_ELEM(srv->per_thr[i].idle_conn_list.n, struct connection *, idle_list);
					conn_delete_from_tree(tokill_conn, i);
				}
				HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[i].idle_conns_lock);

				if (tokill_conn) {
					/* We got one, put it into the concerned thread's to kill list, and wake it's kill task */

					MT_LIST_APPEND(&idle_conns[i].toremove_conns,
					               &tokill_conn->toremove_list);
					task_wakeup(idle_conns[i].cleanup_task, TASK_WOKEN_OTHER);
					break;
				}

				if (!(global.tune.options & GTUNE_IDLE_POOL_SHARED))
					break;
			}
		}
	}

	/* no reuse or failed to reuse the connection above, pick a new one */
	if (!srv_conn) {
		unsigned int total_conns;

		if (srv && (srv->flags & SRV_F_RHTTP)) {
			DBG_TRACE_USER("cannot open a new connection for reverse server", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
			s->conn_err_type = STRM_ET_CONN_ERR;
			return SF_ERR_INTERNAL;
		}

		if (srv && (srv->flags & SRV_F_STRICT_MAXCONN)) {
			int kill_tries = 0;
			/*
			 * Before creating a new connection, make sure we still
			 * have a slot for that
			 */
			total_conns = srv->curr_total_conns;

			while (1) {
				if (total_conns < srv->maxconn) {
					if (_HA_ATOMIC_CAS(&srv->curr_total_conns,
					    &total_conns, total_conns + 1))
						break;
					__ha_cpu_relax();
				} else {
					int ret = kill_random_idle_conn(srv);

					/*
					 * There is no idle connection to kill
					 * so there is nothing we can do at
					 * that point but to report an
					 * error.
					 */
					if (ret == -1)
						return SF_ERR_RESOURCE;
					kill_tries++;
					/*
					 * We tried 3 times to kill an idle
					 * connection, we failed, give up now.
					 */
					if (ret == 0 && kill_tries == 3)
						return SF_ERR_RESOURCE;
				}
			}
		}
		srv_conn = conn_new(s->target);
		if (srv_conn) {
			DBG_TRACE_STATE("alloc new be connection", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
			srv_conn->owner = s->sess;

			/* connection will be attached to the session if
			 * http-reuse mode is never or it is not targeted to a
			 * server */
			if (reuse_mode == PR_O_REUSE_NEVR || !srv)
				conn_set_private(srv_conn);

			/* assign bind_addr to srv_conn */
			srv_conn->src = bind_addr;
			bind_addr = NULL;

			/* copy the target address into the connection */
			*srv_conn->dst = *s->scb->dst;

			/* mark? */
			if (s->flags & SF_BC_MARK) {
				srv_conn->mark = s->bc_mark;
				srv_conn->flags |= CO_FL_OPT_MARK;
			}

			/* tos? */
			if (s->flags & SF_BC_TOS) {
				srv_conn->tos = s->bc_tos;
				srv_conn->flags |= CO_FL_OPT_TOS;
			}

			srv_conn->hash_node.key = hash;
		} else if (srv && (srv->flags & SRV_F_STRICT_MAXCONN))
			_HA_ATOMIC_DEC(&srv->curr_total_conns);
	}

	/* if bind_addr is non NULL free it */
	sockaddr_free(&bind_addr);

	/* srv_conn is still NULL only on allocation failure */
	if (!srv_conn)
		return SF_ERR_RESOURCE;

#if defined(HAVE_SSL_0RTT)
	/* We may be allowed to use 0-RTT involving early data, to send
	 * the request. This may only be done in the following conditions:
	 *   - the SSL ctx does not support early data
	 *   - the connection was not reused (it must be a new one)
	 *   - the client already used early data, or we have L7 retries on
	 *   - 0rtt is configured on the server line and we have not yet failed
	 *     any connection attempt on this stream (in order to avoid failing
	 *     multiple times in a row)
	 *   - there are data to be sent
	 * otherwise we cannot make use of early data. Let's first eliminate
	 * the cases which don't match this above. The conditions will tighten
	 * later in the function when needed.
	 */

	if (!srv || !(srv->ssl_ctx.options & SRV_SSL_O_EARLY_DATA))
		may_use_early_data = 0;

	if (reuse)
		may_use_early_data = 0;

	if (!(cli_conn && cli_conn->flags & CO_FL_EARLY_DATA) &&
	    (!(s->be->retry_type & PR_RE_EARLY_ERROR) || s->conn_retries > 0))
		may_use_early_data = 0;

	if (!co_data(sc_oc(s->scb)))
		may_use_early_data = 0;
#endif

	/* Copy network namespace from client connection */
	srv_conn->proxy_netns = cli_conn ? cli_conn->proxy_netns : NULL;

	if (!srv_conn->xprt) {
		/* set the correct protocol on the output stream connector */

		if (srv) {
			struct protocol *proto = protocol_lookup(srv_conn->dst->ss_family, srv->addr_type.proto_type, srv->alt_proto);

			if (conn_prepare(srv_conn, proto, srv->xprt)) {
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

		if (sc_attach_mux(s->scb, NULL, srv_conn) < 0) {
			conn_free(srv_conn);
			return SF_ERR_INTERNAL;  /* how did we get there ? */
		}
		srv_conn->ctx = s->scb;

#if defined(USE_OPENSSL) && defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
		/* Delay mux initialization if SSL and ALPN/NPN is set. Note
		 * that this is skipped in TCP mode as we only want mux-pt
		 * anyway.
		 */
		if (IS_HTX_STRM(s) && srv && srv->use_ssl &&
		    (srv->ssl_ctx.alpn_str || srv->ssl_ctx.npn_str) &&
		    srv->path_params.nego_alpn[0] == 0)
			may_start_mux_now = 0;
#endif

		/* process the case where the server requires the PROXY protocol to be sent */
		srv_conn->send_proxy_ofs = 0;

		if (srv && (srv->pp_opts & SRV_PP_ENABLED)) {
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
				DBG_TRACE_STATE("update alpn for websocket", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
		}
#endif
	}
	else {
		s->flags |= SF_SRV_REUSED;

		/* Currently there seems to be no known cases of xprt ready
		 * without the mux installed here.
		 */
		BUG_ON(!srv_conn->mux);

		if (!(srv_conn->mux->ctl(srv_conn, MUX_CTL_STATUS, NULL) & MUX_STATUS_READY))
			s->flags |= SF_SRV_REUSED_ANTICIPATED;
	}

	/* flag for logging source ip/port */
	if (strm_fe(s)->options2 & PR_O2_SRC_ADDR)
		s->flags |= SF_SRC_ADDR;

	/* disable lingering */
	if (s->be->options & PR_O_TCP_NOLING)
		s->scb->flags |= SC_FL_NOLINGER;

	if (s->flags & SF_SRV_REUSED) {
		if (s->be_tgcounters)
			_HA_ATOMIC_INC(&s->be_tgcounters->reuse);
		if (s->sv_tgcounters)
			_HA_ATOMIC_INC(&s->sv_tgcounters->reuse);
	} else {
		if (s->be_tgcounters)
			_HA_ATOMIC_INC(&s->be_tgcounters->connect);
		if (s->sv_tgcounters)
			_HA_ATOMIC_INC(&s->sv_tgcounters->connect);
	}

	err = do_connect_server(s, srv_conn);
	if (err != SF_ERR_NONE)
		return err;

#ifdef USE_OPENSSL
	/* Set socket SNI unless connection is reused. */
	if (conn_is_ssl(srv_conn) && srv && srv->ssl_ctx.sni && !(s->flags & SF_SRV_REUSED)) {
		struct sample *sni_smp = NULL;

		sni_smp = sample_fetch_as_type(s->be, s->sess, s,
		                               SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
		                               srv->ssl_ctx.sni, SMP_T_STR);
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
	if (may_start_mux_now) {
		const struct mux_ops *alt_mux =
		  likely(!(s->flags & SF_WEBSOCKET)) ? NULL : srv_get_ws_proto(srv);
		if (conn_install_mux_be(srv_conn, s->scb, s->sess, alt_mux) < 0) {
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
				srv_add_to_avail_list(srv, srv_conn);
			}
			else if (srv_conn->flags & CO_FL_PRIVATE ||
			         (reuse_mode == PR_O_REUSE_SAFE &&
			          srv_conn->mux->flags & MX_FL_HOL_RISK)) {
				/* If it fail now, the same will be done in mux->detach() callback */
				session_add_conn(s->sess, srv_conn);
			}
		}
	}

#if defined(HAVE_SSL_0RTT)
	/* The flags change below deserve some explanation: when we want to
	 * use early data, we first want to make sure that a mux is installed
	 * (otherwise we'll have nothing to send), and then we'll temporarily
	 * pretend that we're done with the SSL handshake. This way the data
	 * layer of the stack will be able to start sending data. The xprt
	 * layer will notice that these data are sent in the context of 0-rtt,
	 * and will produce early data, and then immediately restore these
	 * flags to say "I was lying, the SSL layer is not ready in fact". This
	 * effectively allows early data to be sent with the very first SSL
	 * communication with the server, while still having the ability to
	 * later wait for the end of the handshake.
	 */
	if (may_use_early_data && srv && srv_conn->mux &&
	    srv_conn->flags & CO_FL_SSL_WAIT_HS)
		srv_conn->flags &= ~(CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN);
#endif

	/* set connect timeout */
	s->conn_exp = tick_add_ifset(now_ms, s->be->timeout.connect);

	if (srv) {
		int count;

		s->flags |= SF_CURR_SESS;
		count = _HA_ATOMIC_ADD_FETCH(&srv->cur_sess, 1);
		HA_ATOMIC_UPDATE_MAX(&srv->counters.cur_sess_max, count);
		if (s->be->lbprm.server_take_conn)
			s->be->lbprm.server_take_conn(srv);
	}

	/* Now handle synchronously connected sockets. We know the stream connector
	 * is at least in state SC_ST_CON. These ones typically are UNIX
	 * sockets, socket pairs, andoccasionally TCP connections on the
	 * loopback on a heavily loaded system.
	 */
	if (srv_conn->flags & CO_FL_ERROR)
		s->scb->flags |= SC_FL_ERROR;

	/* If we had early data, and the handshake ended, then
	 * we can remove the flag, and attempt to wake the task up,
	 * in the event there's an analyser waiting for the end of
	 * the handshake.
	 */
	if (!(srv_conn->flags & (CO_FL_WAIT_XPRT | CO_FL_EARLY_SSL_HS)))
		sc_ep_clr(s->scb, SE_FL_WAIT_FOR_HS);

	if (!sc_state_in(s->scb->state, SC_SB_EST|SC_SB_DIS|SC_SB_CLO) &&
	    (srv_conn->flags & CO_FL_WAIT_XPRT) == 0) {
		s->conn_exp = TICK_ETERNITY;
		sc_oc(s->scb)->flags |= CF_WRITE_EVENT;
		if (s->scb->state == SC_ST_CON)
			s->scb->state = SC_ST_RDY;
	}

	/* Report EOI on the channel if it was reached from the mux point of
	 * view.
	 *
	 * Note: This test is only required because si_cs_process is also the SI
	 *       wake callback. Otherwise si_cs_recv()/si_cs_send() already take
	 *       care of it.
	 */
	if (sc_ep_test(s->scb, SE_FL_EOI) && !(s->scb->flags & SC_FL_EOI)) {
		s->scb->flags |= SC_FL_EOI;
		sc_ic(s->scb)->flags |= CF_READ_EVENT;
	}

	/* catch all sync connect while the mux is not already installed */
	if (!srv_conn->mux && !(srv_conn->flags & CO_FL_WAIT_XPRT)) {
		int closed_connection;

		if (conn_create_mux(srv_conn, &closed_connection) < 0) {
			if (closed_connection == 0)
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
			s->flags &= ~(SF_DIRECT | SF_ASSIGNED);
			sockaddr_free(&s->scb->dst);
			goto redispatch;
		}

		if (!s->conn_err_type) {
			s->conn_err_type = STRM_ET_QUEUE_ERR;
		}

		if (s->sv_tgcounters)
			_HA_ATOMIC_INC(&s->sv_tgcounters->failed_conns);
		if (s->be_tgcounters)
			_HA_ATOMIC_INC(&s->be_tgcounters->failed_conns);
		return 1;

	case SRV_STATUS_NOSRV:
		/* note: it is guaranteed that srv == NULL here */
		if (!s->conn_err_type) {
			s->conn_err_type = STRM_ET_CONN_ERR;
		}

		if (s->be_tgcounters)
			_HA_ATOMIC_INC(&s->be_tgcounters->failed_conns);
		return 1;

	case SRV_STATUS_QUEUED:
		s->conn_exp = tick_add_ifset(now_ms, s->be->timeout.queue);
		s->scb->state = SC_ST_QUE;

		/* handle the unlikely event where we added to the server's
		 * queue just after checking the server was full and before
		 * it released its last entry (with extremely low maxconn).
		 * Not needed for backend queues, already handled in
		 * assign_server_and_queue().
		 */
		if (unlikely(srv && may_dequeue_tasks(srv, s->be)))
			process_srv_queue(srv);

		return 1;

	case SRV_STATUS_INTERNAL:
	default:
		if (!s->conn_err_type) {
			s->conn_err_type = STRM_ET_CONN_OTHER;
		}

		if (srv)
			srv_inc_sess_ctr(srv);
		if (srv)
			srv_set_sess_last(srv);
		if (s->sv_tgcounters)
			_HA_ATOMIC_INC(&s->sv_tgcounters->failed_conns);
		if (s->be_tgcounters)
			_HA_ATOMIC_INC(&s->be_tgcounters->failed_conns);

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
	return ((s->scf->flags & SC_FL_ERROR) ||
	        ((s->scb->flags & (SC_FL_SHUT_WANTED|SC_FL_SHUT_DONE)) &&  /* empty and client aborted */
	         (!co_data(req) || (s->be->options & PR_O_ABRT_CLOSE))));
}

/* Update back stream connector status for input states SC_ST_ASS, SC_ST_QUE,
 * SC_ST_TAR. Other input states are simply ignored.
 * Possible output states are SC_ST_CLO, SC_ST_TAR, SC_ST_ASS, SC_ST_REQ, SC_ST_CON
 * and SC_ST_EST. Flags must have previously been updated for timeouts and other
 * conditions.
 */
void back_try_conn_req(struct stream *s)
{
	struct server *srv = objt_server(s->target);
	struct stconn *sc = s->scb;
	struct channel *req = &s->req;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);

	if (sc->state == SC_ST_ASS) {
		/* Server assigned to connection request, we have to try to connect now */
		int conn_err;

		/* Before we try to initiate the connection, see if the
		 * request may be aborted instead.
		 */
		if (back_may_abort_req(req, s)) {
			s->conn_err_type |= STRM_ET_CONN_ABRT;
			DBG_TRACE_STATE("connection aborted", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
			goto abort_connection;
		}

		conn_err = connect_server(s);
		srv = objt_server(s->target);

		if (conn_err == SF_ERR_NONE) {
			/* state = SC_ST_CON or SC_ST_EST now */
			if (srv)
				srv_inc_sess_ctr(srv);
			if (srv)
				srv_set_sess_last(srv);
			DBG_TRACE_STATE("connection attempt", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
			goto end;
		}

		/* We have received a synchronous error. We might have to
		 * abort, retry immediately or redispatch.
		 */
		if (conn_err == SF_ERR_INTERNAL) {
			if (!s->conn_err_type) {
				s->conn_err_type = STRM_ET_CONN_OTHER;
			}

			if (srv)
				srv_inc_sess_ctr(srv);
			if (srv)
				srv_set_sess_last(srv);
			if (s->sv_tgcounters)
				_HA_ATOMIC_INC(&s->sv_tgcounters->failed_conns);
			if (s->be_tgcounters)
				_HA_ATOMIC_INC(&s->be_tgcounters->failed_conns);

			/* release other streams waiting for this server */
			sess_change_server(s, NULL);
			if (may_dequeue_tasks(srv, s->be))
				process_srv_queue(srv);

			/* Failed and not retryable. */
			sc_abort(sc);
			sc_shutdown(sc);
			sc->flags |= SC_FL_ERROR;

			s->logs.t_queue = ns_to_ms(now_ns - s->logs.accept_ts);

			/* we may need to know the position in the queue for logging */
			pendconn_cond_unlink(s->pend_pos);

			/* no stream was ever accounted for this server */
			sc->state = SC_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, sc);
			DBG_TRACE_STATE("internal error during connection", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
			goto end;
		}

		/* We are facing a retryable error, but we don't want to run a
		 * turn-around now, as the problem is likely a source port
		 * allocation problem, so we want to retry now.
		 */
		sc->state = SC_ST_CER;
		sc->flags &= ~SC_FL_ERROR;
		back_handle_st_cer(s);

		DBG_TRACE_STATE("connection error, retry", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
		/* now sc->state is one of SC_ST_CLO, SC_ST_TAR, SC_ST_ASS, SC_ST_REQ */
	}
	else if (sc->state == SC_ST_QUE) {
		/* connection request was queued, check for any update */
		if (!pendconn_dequeue(s)) {
			/* The connection is not in the queue anymore. Either
			 * we have a server connection slot available and we
			 * go directly to the assigned state, or we need to
			 * load-balance first and go to the INI state.
			 */
			s->conn_exp = TICK_ETERNITY;
			if (unlikely(!(s->flags & SF_ASSIGNED)))
				sc->state = SC_ST_REQ;
			else {
				s->logs.t_queue = ns_to_ms(now_ns - s->logs.accept_ts);
				sc->state = SC_ST_ASS;
			}
			DBG_TRACE_STATE("dequeue connection request", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
			goto end;
		}

		/* Connection request still in queue... */
		if (s->flags & SF_CONN_EXP) {
			/* ... and timeout expired */
			s->conn_exp = TICK_ETERNITY;
			s->flags &= ~SF_CONN_EXP;
			s->logs.t_queue = ns_to_ms(now_ns - s->logs.accept_ts);

			/* we may need to know the position in the queue for logging */
			pendconn_cond_unlink(s->pend_pos);

			if (s->sv_tgcounters)
				_HA_ATOMIC_INC(&s->sv_tgcounters->failed_conns);
			if (s->be_tgcounters)
				_HA_ATOMIC_INC(&s->be_tgcounters->failed_conns);
			sc_abort(sc);
			sc_shutdown(sc);
			req->flags |= CF_WRITE_TIMEOUT;
			if (!s->conn_err_type)
				s->conn_err_type = STRM_ET_QUEUE_TO;
			sc->state = SC_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, sc);
			DBG_TRACE_STATE("connection request still queued", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
			goto end;
		}

		/* Connection remains in queue, check if we have to abort it */
		if (back_may_abort_req(req, s)) {
			s->logs.t_queue = ns_to_ms(now_ns - s->logs.accept_ts);

			/* we may need to know the position in the queue for logging */
			pendconn_cond_unlink(s->pend_pos);

			s->conn_err_type |= STRM_ET_QUEUE_ABRT;
			DBG_TRACE_STATE("abort queued connection request", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
			goto abort_connection;
		}

		/* Nothing changed */
	}
	else if (sc->state == SC_ST_TAR) {
		/* Connection request might be aborted */
		if (back_may_abort_req(req, s)) {
			s->conn_err_type |= STRM_ET_CONN_ABRT;
			DBG_TRACE_STATE("connection aborted", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
			goto abort_connection;
		}

		if (!(s->flags & SF_CONN_EXP))
			return;  /* still in turn-around */

		s->flags &= ~SF_CONN_EXP;
		s->conn_exp = TICK_ETERNITY;

		/* we keep trying on the same server as long as the stream is
		 * marked "assigned".
		 * FIXME: Should we force a redispatch attempt when the server is down ?
		 */
		if (s->flags & SF_ASSIGNED)
			sc->state = SC_ST_ASS;
		else
			sc->state = SC_ST_REQ;

		DBG_TRACE_STATE("retry connection now", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
	}

  end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
	return;

abort_connection:
	/* give up */
	s->conn_exp = TICK_ETERNITY;
	s->flags &= ~SF_CONN_EXP;
	sc_abort(sc);
	sc_shutdown(sc);
	sc->state = SC_ST_CLO;
	if (s->srv_error)
		s->srv_error(s, sc);
	DBG_TRACE_DEVEL("leaving on error", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
	return;
}

/* This function initiates a server connection request on a stream connector
 * already in SC_ST_REQ state. Upon success, the state goes to SC_ST_ASS for
 * a real connection to a server, indicating that a server has been assigned,
 * or SC_ST_RDY for a successful connection to an applet. It may also return
 * SC_ST_QUE, or SC_ST_CLO upon error.
 */
void back_handle_st_req(struct stream *s)
{
	struct stconn *sc = s->scb;

	if (sc->state != SC_ST_REQ)
		return;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);

	if (unlikely(obj_type(s->target) == OBJ_TYPE_APPLET)) {
		struct appctx *appctx;

		/* The target is an applet but the SC is in SC_ST_REQ. Thus it
		 * means no appctx are attached to the SC. Otherwise, it will be
		 * in SC_ST_RDY state. So, try to create the appctx now.
		 */
		BUG_ON(sc_appctx(sc));
		appctx = sc_applet_create(sc, objt_applet(s->target));
		if (!appctx) {
			/* No more memory, let's immediately abort. Force the
			 * error code to ignore the ERR_LOCAL which is not a
			 * real error.
			 */
			s->flags &= ~(SF_ERR_MASK | SF_FINST_MASK);

			sc_abort(sc);
			sc_shutdown(sc);
			sc->flags |= SC_FL_ERROR;
			s->conn_err_type = STRM_ET_CONN_RES;
			sc->state = SC_ST_CLO;
			if (s->srv_error)
				s->srv_error(s, sc);
			DBG_TRACE_STATE("failed to register applet", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
			goto end;
		}

		DBG_TRACE_STATE("applet registered", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
		goto end;
	}

	/* Try to assign a server */
	if (srv_redispatch_connect(s) != 0) {
		/* We did not get a server. Either we queued the
		 * connection request, or we encountered an error.
		 */
		if (sc->state == SC_ST_QUE) {
			DBG_TRACE_STATE("connection request queued", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
			goto end;
		}

		/* we did not get any server, let's check the cause */
		sc_abort(sc);
		sc_shutdown(sc);
		sc->flags |= SC_FL_ERROR;
		if (!s->conn_err_type)
			s->conn_err_type = STRM_ET_CONN_OTHER;
		sc->state = SC_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, sc);
		DBG_TRACE_STATE("connection request failed", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
		goto end;
	}

	/* The server is assigned */
	s->logs.t_queue = ns_to_ms(now_ns - s->logs.accept_ts);
	sc->state = SC_ST_ASS;
	be_set_sess_last(s->be);
	DBG_TRACE_STATE("connection request assigned to a server", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);

  end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
}

/* This function is called with (sc->state == SC_ST_CON) meaning that a
 * connection was attempted and that the file descriptor is already allocated.
 * We must check for timeout, error and abort. Possible output states are
 * SC_ST_CER (error), SC_ST_DIS (abort), and SC_ST_CON (no change). This only
 * works with connection-based streams. We know that there were no I/O event
 * when reaching this function. Timeouts and errors are *not* cleared.
 */
void back_handle_st_con(struct stream *s)
{
	struct stconn *sc = s->scb;
	struct channel *req = &s->req;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);

	/* the client might want to abort */
	if ((s->scf->flags & SC_FL_SHUT_DONE) ||
	    ((s->scb->flags & SC_FL_SHUT_WANTED) &&
	     (!co_data(req) || (s->be->options & PR_O_ABRT_CLOSE)))) {
		sc->flags |= SC_FL_NOLINGER;
		sc_shutdown(sc);
		s->conn_err_type |= STRM_ET_CONN_ABRT;
		if (s->srv_error)
			s->srv_error(s, sc);
		/* Note: state = SC_ST_DIS now */
		DBG_TRACE_STATE("client abort during connection attempt", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
		goto end;
	}

 done:
	/* retryable error ? */
	if ((s->flags & SF_CONN_EXP) || (sc->flags & SC_FL_ERROR)) {
		if (!s->conn_err_type) {
			if ((sc->flags & SC_FL_ERROR))
				s->conn_err_type = STRM_ET_CONN_ERR;
			else
				s->conn_err_type = STRM_ET_CONN_TO;
		}

		sc->state  = SC_ST_CER;
		DBG_TRACE_STATE("connection failed, retry", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
	}

 end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
}

/* This function is called with (sc->state == SC_ST_CER) meaning that a
 * previous connection attempt has failed and that the file descriptor
 * has already been released. Possible causes include asynchronous error
 * notification and time out. Possible output states are SC_ST_CLO when
 * retries are exhausted, SC_ST_TAR when a delay is wanted before a new
 * connection attempt, SC_ST_ASS when it's wise to retry on the same server,
 * and SC_ST_REQ when an immediate redispatch is wanted. The buffers are
 * marked as in error state. Timeouts and errors are cleared before retrying.
 */
void back_handle_st_cer(struct stream *s)
{
	struct stconn *sc = s->scb;
	int must_tar = !!(sc->flags & SC_FL_ERROR);

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);

	s->conn_exp = TICK_ETERNITY;
	s->flags &= ~SF_CONN_EXP;

	/* we probably have to release last stream from the server */
	if (objt_server(s->target)) {
		struct connection *conn = sc_conn(sc);

		health_adjust(__objt_server(s->target), HANA_STATUS_L4_ERR);

		if (s->flags & SF_CURR_SESS) {
			s->flags &= ~SF_CURR_SESS;
			_HA_ATOMIC_DEC(&__objt_server(s->target)->cur_sess);
		}

		if ((sc->flags & SC_FL_ERROR) &&
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
			s->conn_retries = s->max_retries;
			DBG_TRACE_DEVEL("Bad SSL cert, disable connection retries", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
		}
	}

	/* ensure that we have enough retries left */
	if (s->conn_retries >= s->max_retries || !(s->be->retry_type & PR_RE_CONN_FAILED)) {
		if (!s->conn_err_type) {
			s->conn_err_type = STRM_ET_CONN_ERR;
		}

		if (s->sv_tgcounters)
			_HA_ATOMIC_INC(&s->sv_tgcounters->failed_conns);
		if (s->be_tgcounters)
			_HA_ATOMIC_INC(&s->be_tgcounters->failed_conns);
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));

		/* shutw is enough to stop a connecting socket */
		sc_shutdown(sc);
		sc->flags |= SC_FL_ERROR;

		sc->state = SC_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, sc);

		DBG_TRACE_STATE("connection failed", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
		goto end;
	}

	/* At this stage, we will trigger a connection retry (with or without
	 * redispatch). Thus we must reset the SI endpoint on the server side
	 * an close the attached connection. It is especially important to do it
	 * now if the retry is not immediately performed, to be sure to release
	 * resources as soon as possible and to not catch errors from the lower
	 * layers in an unexpected state (i.e < ST_CONN).
	 *
	 * Note: the stream connector will be switched to ST_REQ, ST_ASS or
	 * ST_TAR and SC_FL_ERROR and SF_CONN_EXP flags will be unset.
	 */
	if (sc_reset_endp(sc) < 0) {
		if (!s->conn_err_type)
			s->conn_err_type = STRM_ET_CONN_OTHER;

		if (s->sv_tgcounters)
			_HA_ATOMIC_INC(&s->sv_tgcounters->internal_errors);
		if (s->be_tgcounters)
			_HA_ATOMIC_INC(&s->be_tgcounters->internal_errors);
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));

		/* shutw is enough to stop a connecting socket */
		sc_shutdown(sc);
		sc->flags |= SC_FL_ERROR;

		sc->state = SC_ST_CLO;
		if (s->srv_error)
			s->srv_error(s, sc);

		DBG_TRACE_STATE("error resetting endpoint", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
		goto end;
	}

	s->conn_retries++;
	stream_choose_redispatch(s);

	if (must_tar) {
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

		if (!s->conn_err_type)
			s->conn_err_type = STRM_ET_CONN_ERR;

		/* only wait when we're retrying on the same server */
		if ((sc->state == SC_ST_ASS ||
		     (s->be->srv_act <= 1)) && !reused) {
			sc->state = SC_ST_TAR;
			s->conn_exp = tick_add(now_ms, MS_TO_TICKS(delay));
		}
		DBG_TRACE_STATE("retry a new connection", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
	}

  end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
}

/* This function is called with (sc->state == SC_ST_RDY) meaning that a
 * connection was attempted, that the file descriptor is already allocated,
 * and that it has succeeded. We must still check for errors and aborts.
 * Possible output states are SC_ST_EST (established), SC_ST_CER (error),
 * and SC_ST_DIS (abort). This only works with connection-based streams.
 * Timeouts and errors are *not* cleared.
 */
void back_handle_st_rdy(struct stream *s)
{
	struct stconn *sc = s->scb;
	struct channel *req = &s->req;

	DBG_TRACE_ENTER(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);

	if (unlikely(obj_type(s->target) == OBJ_TYPE_APPLET)) {
		/* Here the appctx must exists because the SC was set to
		 * SC_ST_RDY state when the appctx was created.
		 */
		BUG_ON(!sc_appctx(s->scb));

		if (!s->logs.request_ts)
			s->logs.request_ts = now_ns;
		s->logs.t_queue = ns_to_ms(now_ns - s->logs.accept_ts);
		be_set_sess_last(s->be);
	}

	/* We know the connection at least succeeded, though it could have
	 * since met an error for any other reason. At least it didn't time out
	 * even though the timeout might have been reported right after success.
	 * We need to take care of various situations here :
	 *   - everything might be OK. We have to switch to established.
	 *   - an I/O error might have been reported after a successful transfer,
	 *     which is not retryable and needs to be logged correctly, and needs
	 *     established as well
	 *   - SC_ST_CON implies !CF_WROTE_DATA but not conversely as we could
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
		if ((s->scf->flags & SC_FL_SHUT_DONE) ||
		    ((s->scb->flags & SC_FL_SHUT_WANTED) &&
		     (!co_data(req) || (s->be->options & PR_O_ABRT_CLOSE)))) {
			/* give up */
			sc->flags |= SC_FL_NOLINGER;
			sc_shutdown(sc);
			s->conn_err_type |= STRM_ET_CONN_ABRT;
			if (s->srv_error)
				s->srv_error(s, sc);
			DBG_TRACE_STATE("client abort during connection attempt", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
			goto end;
		}

		/* retryable error ? */
		if (sc->flags & SC_FL_ERROR) {
			if (!s->conn_err_type)
				s->conn_err_type = STRM_ET_CONN_ERR;
			sc->state = SC_ST_CER;
			DBG_TRACE_STATE("connection failed, retry", STRM_EV_STRM_PROC|STRM_EV_CS_ST|STRM_EV_STRM_ERR, s);
			goto end;
		}
	}

	/* data were sent and/or we had no error, back_establish() will
	 * now take over.
	 */
	DBG_TRACE_STATE("connection established", STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
	s->conn_err_type = STRM_ET_NONE;
	sc->state = SC_ST_EST;

  end:
	DBG_TRACE_LEAVE(STRM_EV_STRM_PROC|STRM_EV_CS_ST, s);
}

/* sends a log message when a backend goes down, and also sets last
 * change date.
 */
void set_backend_down(struct proxy *be)
{
	be->last_change = ns_to_sec(now_ns);
	HA_ATOMIC_STORE(&be->be_counters.shared.tg[tgid - 1]->last_state_change, be->last_change);
	_HA_ATOMIC_INC(&be->be_counters.shared.tg[tgid - 1]->down_trans);

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
				stream_set_srv_target(s, srv);
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
	if (px->lbprm.tot_weight && px->last_change < ns_to_sec(now_ns))  // ignore negative time
		return px->down_time;

	return ns_to_sec(now_ns) - px->last_change + px->down_time;
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
	else if (algo == BE_LB_ALGO_SMP)
		return "hash";
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
		/* if no option is set, use random by default */
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_RND;
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
	else if (strcmp(args[0], "hash") == 0) {
		if (!*args[1]) {
			memprintf(err, "%s requires a sample expression.", args[0]);
			return -1;
		}
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_SMP;

		ha_free(&curproxy->lbprm.arg_str);
		curproxy->lbprm.arg_str = strdup(args[1]);
		curproxy->lbprm.arg_len = strlen(args[1]);

		if (*args[2]) {
			memprintf(err, "%s takes no other argument (got '%s').", args[0], args[2]);
			return -1;
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
	else if (strcmp(args[0], "log-hash") == 0) {
		if (!*args[1]) {
			memprintf(err, "%s requires a converter list.", args[0]);
			return -1;
		}
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_LH;

		ha_free(&curproxy->lbprm.arg_str);
		curproxy->lbprm.arg_str = strdup(args[1]);
	}
	else if (strcmp(args[0], "sticky") == 0) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_SS;
	}
	else {
		memprintf(err, "only supports 'roundrobin', 'static-rr', 'leastconn', 'source', 'uri', 'url_param', 'hash', 'hdr(name)', 'rdp-cookie(name)', 'log-hash' and 'sticky' options.");
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
		                       +  (iterator->maxqueue - iterator->queueslength);
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
	smp->data.u.sint = COUNTERS_SHARED_TOTAL(px->be_counters.shared.tg, sess_per_sec, read_freq_ctr);
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
	smp->data.u.sint = args->data.srv->queueslength;
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
	smp->data.u.sint = COUNTERS_SHARED_TOTAL(args->data.srv->counters.shared.tg, sess_per_sec, read_freq_ctr);
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

static struct server *sample_conv_srv(struct sample *smp)
{
	struct proxy *px;
	char *bksep;

	if (!smp_make_safe(smp))
		return 0;

	bksep = strchr(smp->data.u.str.area, '/');

	if (bksep) {
		*bksep = '\0';
		px = proxy_find_by_name(smp->data.u.str.area, PR_CAP_BE, 0);
		if (!px)
			return NULL;
		smp->data.u.str.area = bksep + 1;
	} else {
		if (!(smp->px->cap & PR_CAP_BE))
			return NULL;
		px = smp->px;
	}

	return server_find(px, smp->data.u.str.area);
}

static int
sample_conv_srv_is_up(const struct arg *args, struct sample *smp, void *private)
{
	struct server *srv = sample_conv_srv(smp);

	if (!srv)
		return 0;

	smp->data.type = SMP_T_BOOL;
	if (!(srv->cur_admin & SRV_ADMF_MAINT) &&
	    (!(srv->check.state & CHK_ST_CONFIGURED) || (srv->cur_state != SRV_ST_STOPPED)))
		smp->data.u.sint = 1;
	else
		smp->data.u.sint = 0;
	return 1;
}

static int
sample_conv_srv_queue(const struct arg *args, struct sample *smp, void *private)
{
	struct server *srv = sample_conv_srv(smp);

	if (!srv)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = srv->queueslength;
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
	{ "srv_is_up", sample_conv_srv_is_up, 0, NULL, SMP_T_STR, SMP_T_BOOL },
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
