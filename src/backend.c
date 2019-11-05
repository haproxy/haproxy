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
#include <common/htx.h>
#include <common/initcall.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/namespace.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/frontend.h>
#include <proto/http_htx.h>
#include <proto/lb_chash.h>
#include <proto/lb_fas.h>
#include <proto/lb_fwlc.h>
#include <proto/lb_fwrr.h>
#include <proto/lb_map.h>
#include <proto/log.h>
#include <proto/mux_pt.h>
#include <proto/obj_type.h>
#include <proto/payload.h>
#include <proto/protocol.h>
#include <proto/http_ana.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/sample.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/ssl_sock.h>
#include <proto/task.h>

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
 * the "whole" optional argument (boolean), the "len" argument (numeric) and
 * the "depth" argument (numeric).
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
		else if (c == '?' && !px->lbprm.arg_opt1) // "whole"
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
		/* ensure all 32 bits are covered as long as RAND_MAX >= 65535 */
		hash = ((uint64_t)random() * ((uint64_t)RAND_MAX + 1)) ^ random();
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
			      tmpsrv->nbpend + 1 < s->be->max_ka_queue))) &&
			    srv_currently_usable(tmpsrv)) {
				list_for_each_entry(conn, &srv_list->conn_list, session_list) {
					if (conn->flags & CO_FL_CONNECTED) {

						srv = tmpsrv;
						s->target = &srv->obj_type;
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
				if ((s->be->lbprm.algo & BE_LB_PARM) == BE_LB_RR_RANDOM)
					srv = get_server_rnd(s, prev_srv);
				else if ((s->be->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
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
				if (conn && conn_get_src(conn) && conn->src->ss_family == AF_INET) {
					srv = get_server_sh(s->be,
							    (void *)&((struct sockaddr_in *)conn->src)->sin_addr,
							    4, prev_srv);
				}
				else if (conn && conn_get_src(conn) && conn->src->ss_family == AF_INET6) {
					srv = get_server_sh(s->be,
							    (void *)&((struct sockaddr_in6 *)conn->src)->sin6_addr,
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
			_HA_ATOMIC_ADD(&s->be->be_counters.cum_lbconn, 1);
			_HA_ATOMIC_ADD(&srv->counters.cum_lbconn, 1);
		}
		s->target = &srv->obj_type;
	}
	else if (s->be->options & (PR_O_DISPATCH | PR_O_TRANSP)) {
		s->target = &s->be->obj_type;
	}
	else if ((s->be->options & PR_O_HTTP_PROXY)) {
		conn = cs_conn(objt_cs(s->si[1].end));

		if (conn && conn->dst && is_addr(conn->dst)) {
			/* in proxy mode, we need a valid destination address */
			s->target = &s->be->obj_type;
		} else {
			err = SRV_STATUS_NOSRV;
			goto out;
		}
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
 */
int assign_server_address(struct stream *s)
{
	struct connection *cli_conn = objt_conn(strm_orig(s));

	DPRINTF(stderr,"assign_server_address : s=%p\n",s);

	if (!sockaddr_alloc(&s->target_addr))
		return SRV_STATUS_INTERNAL;

	if ((s->flags & SF_DIRECT) || (s->be->lbprm.algo & BE_LB_KIND)) {
		/* A server is necessarily known for this stream */
		if (!(s->flags & SF_ASSIGNED))
			return SRV_STATUS_INTERNAL;

		*s->target_addr = __objt_server(s->target)->addr;
		set_host_port(s->target_addr, __objt_server(s->target)->svc_port);

		if (!is_addr(s->target_addr) && cli_conn) {
			/* if the server has no address, we use the same address
			 * the client asked, which is handy for remapping ports
			 * locally on multiple addresses at once. Nothing is done
			 * for AF_UNIX addresses.
			 */
			if (!conn_get_dst(cli_conn)) {
				/* do nothing if we can't retrieve the address */
			} else if (cli_conn->dst->ss_family == AF_INET) {
				((struct sockaddr_in *)s->target_addr)->sin_addr = ((struct sockaddr_in *)cli_conn->dst)->sin_addr;
			} else if (cli_conn->dst->ss_family == AF_INET6) {
				((struct sockaddr_in6 *)s->target_addr)->sin6_addr = ((struct sockaddr_in6 *)cli_conn->dst)->sin6_addr;
			}
		}

		/* if this server remaps proxied ports, we'll use
		 * the port the client connected to with an offset. */
		if ((__objt_server(s->target)->flags & SRV_F_MAPPORTS) && cli_conn) {
			int base_port;

			if (conn_get_dst(cli_conn)) {
				/* First, retrieve the port from the incoming connection */
				base_port = get_host_port(cli_conn->dst);

				/* Second, assign the outgoing connection's port */
				base_port += get_host_port(s->target_addr);
				set_host_port(s->target_addr, base_port);
			}
		}
	}
	else if (s->be->options & PR_O_DISPATCH) {
		/* connect to the defined dispatch addr */
		*s->target_addr = s->be->dispatch_addr;
	}
	else if ((s->be->options & PR_O_TRANSP) && cli_conn) {
		/* in transparent mode, use the original dest addr if no dispatch specified */
		if (conn_get_dst(cli_conn) &&
		    (cli_conn->dst->ss_family == AF_INET || cli_conn->dst->ss_family == AF_INET6))
			*s->target_addr = *cli_conn->dst;
	}
	else if (s->be->options & PR_O_HTTP_PROXY) {
		/* If HTTP PROXY option is set, then server is already assigned
		 * during incoming client request parsing. */
	}
	else {
		/* no server and no LB algorithm ! */
		return SRV_STATUS_INTERNAL;
	}

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
				_HA_ATOMIC_ADD(&prev_srv->counters.redispatches, 1);
				_HA_ATOMIC_ADD(&s->be->be_counters.redispatches, 1);
			} else {
				_HA_ATOMIC_ADD(&prev_srv->counters.retries, 1);
				_HA_ATOMIC_ADD(&s->be->be_counters.retries, 1);
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
#if defined(CONFIG_HAP_TRANSPARENT)
	struct server *srv = objt_server(s->target);
	struct conn_src *src;
	struct connection *cli_conn;
	struct connection *srv_conn;

	if (objt_cs(s->si[1].end))
		srv_conn = cs_conn(__objt_cs(s->si[1].end));
	else
		srv_conn = objt_conn(s->si[1].end);

	if (srv && srv->conn_src.opts & CO_SRC_BIND)
		src = &srv->conn_src;
	else if (s->be->conn_src.opts & CO_SRC_BIND)
		src = &s->be->conn_src;
	else
		return;

	if (!sockaddr_alloc(&srv_conn->src))
		return;

	switch (src->opts & CO_SRC_TPROXY_MASK) {
	case CO_SRC_TPROXY_ADDR:
		*srv_conn->src = src->tproxy_addr;
		break;
	case CO_SRC_TPROXY_CLI:
	case CO_SRC_TPROXY_CIP:
		/* FIXME: what can we do if the client connects in IPv6 or unix socket ? */
		cli_conn = objt_conn(strm_orig(s));
		if (cli_conn && conn_get_src(cli_conn))
			*srv_conn->src = *cli_conn->src;
		else {
			sockaddr_free(&srv_conn->src);
		}
		break;
	case CO_SRC_TPROXY_DYN:
		if (src->bind_hdr_occ && IS_HTX_STRM(s)) {
			char *vptr;
			size_t vlen;

			/* bind to the IP in a header */
			((struct sockaddr_in *)srv_conn->src)->sin_family = AF_INET;
			((struct sockaddr_in *)srv_conn->src)->sin_port = 0;
			((struct sockaddr_in *)srv_conn->src)->sin_addr.s_addr = 0;
			if (http_get_htx_hdr(htxbuf(&s->req.buf),
					     ist2(src->bind_hdr_name, src->bind_hdr_len),
					     src->bind_hdr_occ, NULL, &vptr, &vlen)) {
				((struct sockaddr_in *)srv_conn->src)->sin_addr.s_addr =
					htonl(inetaddr_host_lim(vptr, vptr + vlen));
			}
		}
		break;
	default:
		sockaddr_free(&srv_conn->src);
	}
#endif
}

#if defined(USE_OPENSSL) && defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
/*
 * Pick the right mux once the connection is established, we should now have
 * an alpn if available, so we are now able to choose. In this specific case
 * the connection's context is &si[i].end.
 */
static int conn_complete_server(struct connection *conn)
{
	struct conn_stream *cs = NULL;
	struct stream *s = container_of(conn->ctx, struct stream, si[1].end);
	struct server *srv;

	task_wakeup(s->task, TASK_WOKEN_IO);
	conn_clear_xprt_done_cb(conn);
	/* Verify if the connection just established. */
	if (unlikely(!(conn->flags & (CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN | CO_FL_CONNECTED))))
		conn->flags |= CO_FL_CONNECTED;

	if (conn->flags & CO_FL_ERROR)
		goto fail;
	si_detach_endpoint(&s->si[1]);
	cs = si_alloc_cs(&s->si[1], conn);
	if (!cs)
		goto fail;
	if (conn_install_mux_be(conn, cs, s->sess) < 0)
		goto fail;
	srv = objt_server(s->target);
	if (srv && ((s->be->options & PR_O_REUSE_MASK) != PR_O_REUSE_NEVR) &&
			    conn->mux->avail_streams(conn) > 0)
				LIST_ADD(&srv->idle_conns[tid], &conn->list);

	return 0;

fail:
	si_detach_endpoint(&s->si[1]);

	if (cs)
		cs_free(cs);
	/* kill the connection now */
	conn_stop_tracking(conn);
	conn_full_close(conn);
	conn_free(conn);
	/* Let process_stream know it went wrong */
	s->si[1].flags |= SI_FL_ERR;
	return -1;
}
#endif


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
	struct connection *old_conn = NULL;
	struct conn_stream *srv_cs = NULL;
	struct sess_srv_list *srv_list;
	struct server *srv;
	int reuse = 0;
	int reuse_orphan = 0;
	int init_mux = 0;
	int alloced_cs = 0;
	int err;


	/* This will catch some corner cases such as lying connections resulting from
	 * retries or connect timeouts but will rarely trigger.
	 */
	si_release_endpoint(&s->si[1]);

	/* first, search for a matching connection in the session's idle conns */
	list_for_each_entry(srv_list, &s->sess->srv_list, srv_list) {
		if (srv_list->target == s->target) {
			list_for_each_entry(srv_conn, &srv_list->conn_list, session_list) {
				if (conn_xprt_ready(srv_conn) &&
				    srv_conn->mux && (srv_conn->mux->avail_streams(srv_conn) > 0)) {
					reuse = 1;
					break;
				}
			}
			break;
		}
	}

	if (!reuse) {
		/* no connection was found in our session's list. Pick any
		 * random one that we could trade against another one.
		 */
		srv_conn = NULL;
		if (!LIST_ISEMPTY(&s->sess->srv_list)) {
			srv_list = LIST_ELEM(s->sess->srv_list.n, struct sess_srv_list *, srv_list);
			if (!LIST_ISEMPTY(&srv_list->conn_list))
				srv_conn = LIST_ELEM(srv_list->conn_list.n, struct connection *, session_list);
		}

	}
	/* OK at this point we have this :
	 *   - srv_conn points to an existing connection or NULL
	 *   - if reuse is set, srv_conn holds a valid connection, otherwise it
	 *     points to any of our old connections we may want to trade against
	 *     another one
	 */

	old_conn = srv_conn;

	srv = objt_server(s->target);

	if (srv && !reuse) {
		srv_conn = NULL;

		/* Below we pick connections from the safe or idle lists based
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
		if (srv->idle_conns && !LIST_ISEMPTY(&srv->idle_conns[tid]) &&
		    ((s->be->options & PR_O_REUSE_MASK) != PR_O_REUSE_NEVR &&
		     s->txn && (s->txn->flags & TX_NOT_FIRST))) {
			srv_conn = LIST_ELEM(srv->idle_conns[tid].n, struct connection *, list);
		}
		else if (srv->safe_conns && !LIST_ISEMPTY(&srv->safe_conns[tid]) &&
			 ((s->txn && (s->txn->flags & TX_NOT_FIRST)) ||
			  (s->be->options & PR_O_REUSE_MASK) >= PR_O_REUSE_AGGR)) {
			srv_conn = LIST_ELEM(srv->safe_conns[tid].n, struct connection *, list);
		}
		else if (srv->idle_conns && !LIST_ISEMPTY(&srv->idle_conns[tid]) &&
			 (s->be->options & PR_O_REUSE_MASK) == PR_O_REUSE_ALWS) {
			srv_conn = LIST_ELEM(srv->idle_conns[tid].n, struct connection *, list);
		} else if (srv->idle_orphan_conns && !MT_LIST_ISEMPTY(&srv->idle_orphan_conns[tid]) &&
		    (((s->be->options & PR_O_REUSE_MASK) == PR_O_REUSE_ALWS) ||
		    (((s->be->options & PR_O_REUSE_MASK) != PR_O_REUSE_NEVR) &&
		     s->txn && (s->txn->flags & TX_NOT_FIRST)))) {
			srv_conn = MT_LIST_POP(&srv->idle_orphan_conns[tid],
			                           struct connection *, list);
			if (srv_conn)
				reuse_orphan = 1;
		}

		/* If we've picked a connection from the pool, we now have to
		 * detach it. We may have to get rid of the previous idle
		 * connection we had, so for this we try to swap it with the
		 * other owner's. That way it may remain alive for others to
		 * pick.
		 */
		if (srv_conn)
			reuse = 1;
	}


	/* here reuse might have been set above, indicating srv_conn finally
	 * is OK.
	 */
	if (reuse) {
		/* Disable connection reuse if a dynamic source is used.
		 * As long as we don't share connections between servers,
		 * we don't need to disable connection reuse on no-idempotent
		 * requests nor when PROXY protocol is used.
		 */
		if (srv && srv->conn_src.opts & CO_SRC_BIND) {
			if ((srv->conn_src.opts & CO_SRC_TPROXY_MASK) == CO_SRC_TPROXY_DYN)
				reuse = 0;
		}
		else if (s->be->conn_src.opts & CO_SRC_BIND) {
			if ((s->be->conn_src.opts & CO_SRC_TPROXY_MASK) == CO_SRC_TPROXY_DYN)
				reuse = 0;
		}
	}

	if (((!reuse || (srv_conn && !(srv_conn->flags & CO_FL_CONNECTED)))
	    && ha_used_fds > global.tune.pool_high_count) && srv && srv->idle_orphan_conns) {
		struct connection *tokill_conn;

		/* We can't reuse a connection, and e have more FDs than deemd
		 * acceptable, attempt to kill an idling connection
		 */
		/* First, try from our own idle list */
		tokill_conn = MT_LIST_POP(&srv->idle_orphan_conns[tid],
		    struct connection *, list);
		if (tokill_conn)
			tokill_conn->mux->destroy(tokill_conn->ctx);
		/* If not, iterate over other thread's idling pool, and try to grab one */
		else {
			int i;

			for (i = 0; i < global.nbthread; i++) {
				if (i == tid)
					continue;

				// just silence stupid gcc which reports an absurd
				// out-of-bounds warning for <i> which is always
				// exactly zero without threads, but it seems to
				// see it possibly larger.
				ALREADY_CHECKED(i);

				tokill_conn = MT_LIST_POP(&srv->idle_orphan_conns[i],
				    struct connection *, list);
				if (tokill_conn) {
					/* We got one, put it into the concerned thread's to kill list, and wake it's kill task */

					MT_LIST_ADDQ(&toremove_connections[i],
					    (struct mt_list *)&tokill_conn->list);
					task_wakeup(idle_conn_cleanup[i], TASK_WOKEN_OTHER);
					break;
				}
			}
		}

	}
	/* If we're really reusing the connection, remove it from the orphan
	 * list and add it back to the idle list.
	 */
	if (reuse) {
		if (reuse_orphan) {
			srv_conn->idle_time = 0;
			_HA_ATOMIC_SUB(&srv->curr_idle_conns, 1);
			__ha_barrier_atomic_store();
			srv->curr_idle_thr[tid]--;
			LIST_ADDQ(&srv->idle_conns[tid], &srv_conn->list);
		}
		else {
			if (srv_conn->flags & CO_FL_SESS_IDLE) {
				struct session *sess = srv_conn->owner;

				srv_conn->flags &= ~CO_FL_SESS_IDLE;
				sess->idle_conns--;
			}
		}
	}

	/* We're about to use another connection, let the mux know we're
	 * done with this one.
	 */
	if (old_conn != srv_conn && old_conn && reuse && !reuse_orphan) {
		struct session *sess = srv_conn->owner;

		if (sess) {
			if (old_conn && !(old_conn->flags & CO_FL_PRIVATE) &&
			    old_conn->mux != NULL) {
				if (old_conn->flags & CO_FL_SESS_IDLE)
					s->sess->idle_conns--;
				session_unown_conn(s->sess, old_conn);
				old_conn->owner = sess;
				if (!session_add_conn(sess, old_conn, old_conn->target)) {
					old_conn->flags &= ~CO_FL_SESS_IDLE;
					old_conn->owner = NULL;
					old_conn->mux->destroy(old_conn->ctx);
				} else
					session_check_idle_conn(sess, old_conn);
			}
		}
	}

	if (reuse) {
		if (srv_conn->mux) {
			int avail = srv_conn->mux->avail_streams(srv_conn);

			if (avail <= 1) {
				/* No more streams available, remove it from the list */
				LIST_DEL(&srv_conn->list);
				LIST_INIT(&srv_conn->list);
			}

			if (avail >= 1) {
				srv_cs = srv_conn->mux->attach(srv_conn, s->sess);
				if (srv_cs) {
					alloced_cs = 1;
					si_attach_cs(&s->si[1], srv_cs);
				} else
					srv_conn = NULL;
			}
			else
				srv_conn = NULL;
		}
		/* otherwise srv_conn is left intact */
	}
	else
		srv_conn = NULL;

	/* no reuse or failed to reuse the connection above, pick a new one */
	if (!srv_conn) {
		srv_conn = conn_new();
		if (srv_conn)
			srv_conn->target = s->target;
		srv_cs = NULL;
	}

	if (srv_conn && old_conn != srv_conn) {
		if (srv_conn->owner)
			session_unown_conn(srv_conn->owner, srv_conn);
		srv_conn->owner = s->sess;
		if (!session_add_conn(s->sess, srv_conn, srv_conn->target)) {
			/* If we failed to attach the connection, detach the
			 * conn_stream, possibly destroying the connection */
			if (alloced_cs)
				si_release_endpoint(&s->si[1]);
			srv_conn->owner = NULL;
			if (srv_conn->mux && !srv_add_to_idle_list(objt_server(srv_conn->target), srv_conn))
			/* The server doesn't want it, let's kill the connection right away */
				srv_conn->mux->destroy(srv_conn->ctx);
			srv_conn = NULL;

		}
	}

	if (!srv_conn || !sockaddr_alloc(&srv_conn->dst))
		return SF_ERR_RESOURCE;

	if (!(s->flags & SF_ADDR_SET)) {
		err = assign_server_address(s);
		if (err != SRV_STATUS_OK)
			return SF_ERR_INTERNAL;
	}

	/* copy the target address into the connection */
	*srv_conn->dst = *s->target_addr;

	/* Copy network namespace from client connection */
	srv_conn->proxy_netns = cli_conn ? cli_conn->proxy_netns : NULL;

	if (!conn_xprt_ready(srv_conn) && !srv_conn->mux) {
		/* set the correct protocol on the output stream interface */
		if (srv)
			conn_prepare(srv_conn, protocol_by_family(srv_conn->dst->ss_family), srv->xprt);
		else if (obj_type(s->target) == OBJ_TYPE_PROXY) {
			/* proxies exclusively run on raw_sock right now */
			conn_prepare(srv_conn, protocol_by_family(srv_conn->dst->ss_family), xprt_get(XPRT_RAW));
			if (!(srv_conn->ctrl))
				return SF_ERR_INTERNAL;
		}
		else
			return SF_ERR_INTERNAL;  /* how did we get there ? */

#if defined(USE_OPENSSL) && defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
		if (!srv ||
		    ((!(srv->ssl_ctx.alpn_str) && !(srv->ssl_ctx.npn_str)) ||
		    srv->mux_proto || s->be->mode != PR_MODE_HTTP))
#endif
		{
			srv_cs = objt_cs(s->si[1].end);
			if (!srv_cs || srv_cs->conn != srv_conn)
				srv_cs = si_alloc_cs(&s->si[1], srv_conn);
			if (!srv_cs) {
				conn_free(srv_conn);
				return SF_ERR_RESOURCE;
			}
			init_mux = 1;
		}
#if defined(USE_OPENSSL) && defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
		else {
			srv_conn->ctx = &s->si[1].end;
			/* Store the connection into the stream interface,
			 * while we still don't have a mux, so that if the
			 * stream is destroyed before the connection is
			 * established, we have a chance to destroy it even
			 * if it is no longer referenced in the session.
			 */
			s->si[1].end = &srv_conn->obj_type;
			conn_set_xprt_done_cb(srv_conn, conn_complete_server);
		}

#endif
		/* process the case where the server requires the PROXY protocol to be sent */
		srv_conn->send_proxy_ofs = 0;

		if (srv && srv->pp_opts) {
			srv_conn->flags |= CO_FL_PRIVATE;
			srv_conn->flags |= CO_FL_SEND_PROXY;
			srv_conn->send_proxy_ofs = 1; /* must compute size */
			if (cli_conn)
				conn_get_dst(cli_conn);
		}

		assign_tproxy_address(s);

		if (srv && (srv->flags & SRV_F_SOCKS4_PROXY)) {
			srv_conn->send_proxy_ofs = 1;
			srv_conn->flags |= CO_FL_SOCKS4;
		}
	}
	else if (!conn_xprt_ready(srv_conn)) {
		if (srv_conn->mux->reset)
			srv_conn->mux->reset(srv_conn);
	}
	else {
		/* Only consider we're doing reuse if the connection was
		 * ready.
		 */
		if (srv_conn->mux->ctl(srv_conn, MUX_STATUS, NULL) & MUX_STATUS_READY)
			s->flags |= SF_SRV_REUSED;
	}

	/* flag for logging source ip/port */
	if (strm_fe(s)->options2 & PR_O2_SRC_ADDR)
		s->si[1].flags |= SI_FL_SRC_ADDR;

	/* disable lingering */
	if (s->be->options & PR_O_TCP_NOLING)
		s->si[1].flags |= SI_FL_NOLINGER;

	if (s->flags & SF_SRV_REUSED) {
		_HA_ATOMIC_ADD(&s->be->be_counters.reuse, 1);
		if (srv)
			_HA_ATOMIC_ADD(&srv->counters.reuse, 1);
	} else {
		_HA_ATOMIC_ADD(&s->be->be_counters.connect, 1);
		if (srv)
			_HA_ATOMIC_ADD(&srv->counters.connect, 1);
	}

	err = si_connect(&s->si[1], srv_conn);
	if (err != SF_ERR_NONE)
		return err;

	/* We have to defer the mux initialization until after si_connect()
	 * has been called, as we need the xprt to have been properly
	 * initialized, or any attempt to recv during the mux init may
	 * fail, and flag the connection as CO_FL_ERROR.
	 */
	if (init_mux) {
		if (conn_install_mux_be(srv_conn, srv_cs, s->sess) < 0) {
			conn_full_close(srv_conn);
			return SF_ERR_INTERNAL;
		}
		/* If we're doing http-reuse always, and the connection
		 * is an http2 connection, add it to the available list,
		 * so that others can use it right away.
		 */
		if (srv && ((s->be->options & PR_O_REUSE_MASK) == PR_O_REUSE_ALWS) &&
		    srv_conn->mux->avail_streams(srv_conn) > 0)
			LIST_ADD(&srv->idle_conns[tid], &srv_conn->list);
	}
	/* The CO_FL_SEND_PROXY flag may have been set by the connect method,
	 * if so, add our handshake pseudo-XPRT now.
	 */
	if ((srv_conn->flags & CO_FL_HANDSHAKE_NOSSL)) {
		if (xprt_add_hs(srv_conn) < 0) {
			conn_full_close(srv_conn);
			return SF_ERR_INTERNAL;
		}
	}


#if USE_OPENSSL && (defined(OPENSSL_IS_BORINGSSL) || (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L))

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
		count = _HA_ATOMIC_ADD(&srv->cur_sess, 1);
		HA_ATOMIC_UPDATE_MAX(&srv->counters.cur_sess_max, count);
		if (s->be->lbprm.server_take_conn)
			s->be->lbprm.server_take_conn(srv);

#ifdef USE_OPENSSL
		if (srv->ssl_ctx.sni) {
			struct sample *smp;

			smp = sample_fetch_as_type(s->be, s->sess, s, SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
						   srv->ssl_ctx.sni, SMP_T_STR);
			if (smp_make_safe(smp)) {
				ssl_sock_set_servername(srv_conn,
							smp->data.u.str.area);
				srv_conn->flags |= CO_FL_PRIVATE;
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
			sockaddr_free(&s->target_addr);
			goto redispatch;
		}

		if (!s->si[1].err_type) {
			s->si[1].err_type = SI_ET_QUEUE_ERR;
		}

		_HA_ATOMIC_ADD(&srv->counters.failed_conns, 1);
		_HA_ATOMIC_ADD(&s->be->be_counters.failed_conns, 1);
		return 1;

	case SRV_STATUS_NOSRV:
		/* note: it is guaranteed that srv == NULL here */
		if (!s->si[1].err_type) {
			s->si[1].err_type = SI_ET_CONN_ERR;
		}

		_HA_ATOMIC_ADD(&s->be->be_counters.failed_conns, 1);
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
			_HA_ATOMIC_ADD(&srv->counters.failed_conns, 1);
		_HA_ATOMIC_ADD(&s->be->be_counters.failed_conns, 1);

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
	_HA_ATOMIC_ADD(&be->down_trans, 1);

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
	else if (!strcmp(args[0], "source")) {
		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_SH;
	}
	else if (!strcmp(args[0], "uri")) {
		int arg = 1;

		curproxy->lbprm.algo &= ~BE_LB_ALGO;
		curproxy->lbprm.algo |= BE_LB_ALGO_UH;
		curproxy->lbprm.arg_opt1 = 0; // "whole"
		curproxy->lbprm.arg_opt2 = 0; // "len"
		curproxy->lbprm.arg_opt3 = 0; // "depth"

		while (*args[arg]) {
			if (!strcmp(args[arg], "len")) {
				if (!*args[arg+1] || (atoi(args[arg+1]) <= 0)) {
					memprintf(err, "%s : '%s' expects a positive integer (got '%s').", args[0], args[arg], args[arg+1]);
					return -1;
				}
				curproxy->lbprm.arg_opt2 = atoi(args[arg+1]);
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
				curproxy->lbprm.arg_opt3 = atoi(args[arg+1]) + 1;
				arg += 2;
			}
			else if (!strcmp(args[arg], "whole")) {
				curproxy->lbprm.arg_opt1 = 1;
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

		free(curproxy->lbprm.arg_str);
		curproxy->lbprm.arg_str = strdup(args[1]);
		curproxy->lbprm.arg_len = strlen(args[1]);
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

		free(curproxy->lbprm.arg_str);
		curproxy->lbprm.arg_len = end - beg;
		curproxy->lbprm.arg_str = my_strndup(beg, end - beg);
		curproxy->lbprm.arg_opt1 = 0;

		if (*args[1]) {
			if (strcmp(args[1], "use_domain_only")) {
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
	struct proxy *px;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	px = args->data.prx;

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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	for (iterator = args->data.prx->srv; iterator; iterator = iterator->next) {
		if (iterator->cur_state == SRV_ST_STOPPED)
			continue;

		if (iterator->maxconn == 0 || iterator->maxqueue == 0) {
			/* configuration is stupid */
			smp->data.u.sint = -1;  /* FIXME: stupid value! */
			return 1;
		}

		smp->data.u.sint += (iterator->maxconn - iterator->cur_sess)
		                       +  (iterator->maxqueue - iterator->nbpend);
	}

	return 1;
}

/* set temp integer to the id of the backend */
static int
smp_fetch_be_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm)
		return 0;

	smp->flags = SMP_F_VOL_TXN;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = smp->strm->be->uuid;
	return 1;
}

/* set string to the name of the backend */
static int
smp_fetch_be_name(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm)
		return 0;

	smp->data.u.str.area = (char *)smp->strm->be->id;
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
	if (!smp->strm)
		return 0;

	if (!objt_server(smp->strm->target))
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = __objt_server(smp->strm->target)->puid;

	return 1;
}

/* set string to the name of the server */
static int
smp_fetch_srv_name(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm)
		return 0;

	if (!objt_server(smp->strm->target))
		return 0;

	smp->data.u.str.area = (char *)__objt_server(smp->strm->target)->id;
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
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = read_freq_ctr(&args->data.prx->be_sess_per_sec);
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
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = args->data.prx->beconn;
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
	struct proxy *px;
	unsigned int maxconn;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	for (iterator = args->data.prx->srv; iterator; iterator = iterator->next) {
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
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = args->data.prx->totpend;
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
	smp->data.type = SMP_T_SINT;
	px = args->data.prx;

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
	smp->data.u.sint = args->data.srv->nbpend;
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
	smp->data.u.sint = srv->nbpend;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "avg_queue",     smp_fetch_avg_queue_size, ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "be_conn",       smp_fetch_be_conn,        ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "be_conn_free",  smp_fetch_be_conn_free,   ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "be_id",         smp_fetch_be_id,          0,           NULL, SMP_T_SINT, SMP_USE_BKEND, },
	{ "be_name",       smp_fetch_be_name,        0,           NULL, SMP_T_STR,  SMP_USE_BKEND, },
	{ "be_sess_rate",  smp_fetch_be_sess_rate,   ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "connslots",     smp_fetch_connslots,      ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "nbsrv",         smp_fetch_nbsrv,          ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "queue",         smp_fetch_queue_size,     ARG1(1,BE),  NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_conn",      smp_fetch_srv_conn,       ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_conn_free", smp_fetch_srv_conn_free,  ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_id",        smp_fetch_srv_id,         0,           NULL, SMP_T_SINT, SMP_USE_SERVR, },
	{ "srv_is_up",     smp_fetch_srv_is_up,      ARG1(1,SRV), NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "srv_name",      smp_fetch_srv_name,       0,           NULL, SMP_T_STR,  SMP_USE_SERVR, },
	{ "srv_queue",     smp_fetch_srv_queue,      ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "srv_sess_rate", smp_fetch_srv_sess_rate,  ARG1(1,SRV), NULL, SMP_T_SINT, SMP_USE_INTRN, },
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
