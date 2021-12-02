/*
 * Name server resolution
 *
 * Copyright 2014 Baptiste Assmann <bedis9@gmail.com>
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
#include <unistd.h>

#include <sys/types.h>

#include <import/ebistree.h>

#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/cli.h>
#include <haproxy/dns.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/http_rules.h>
#include <haproxy/log.h>
#include <haproxy/net_helper.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/resolvers.h>
#include <haproxy/ring.h>
#include <haproxy/sample.h>
#include <haproxy/server.h>
#include <haproxy/stats.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>
#include <haproxy/xxhash.h>


struct list sec_resolvers  = LIST_HEAD_INIT(sec_resolvers);
struct list resolv_srvrq_list = LIST_HEAD_INIT(resolv_srvrq_list);

static THREAD_LOCAL struct list death_row; /* list of deferred resolutions to kill, local validity only */
static THREAD_LOCAL unsigned int recurse = 0; /* counter to track calls to public functions */
static THREAD_LOCAL uint64_t resolv_query_id_seed = 0; /* random seed */
struct resolvers *curr_resolvers = NULL;

DECLARE_STATIC_POOL(resolv_answer_item_pool, "resolv_answer_item", sizeof(struct resolv_answer_item));
DECLARE_STATIC_POOL(resolv_resolution_pool,  "resolv_resolution",  sizeof(struct resolv_resolution));
DECLARE_POOL(resolv_requester_pool,  "resolv_requester",  sizeof(struct resolv_requester));

static unsigned int resolution_uuid = 1;
unsigned int resolv_failed_resolutions = 0;
static struct task *process_resolvers(struct task *t, void *context, unsigned int state);
static void resolv_free_resolution(struct resolv_resolution *resolution);
static void _resolv_unlink_resolution(struct resolv_requester *requester);
static void enter_resolver_code();
static void leave_resolver_code();

enum {
	RSLV_STAT_ID,
	RSLV_STAT_PID,
	RSLV_STAT_SENT,
	RSLV_STAT_SND_ERROR,
	RSLV_STAT_VALID,
	RSLV_STAT_UPDATE,
	RSLV_STAT_CNAME,
	RSLV_STAT_CNAME_ERROR,
	RSLV_STAT_ANY_ERR,
	RSLV_STAT_NX,
	RSLV_STAT_TIMEOUT,
	RSLV_STAT_REFUSED,
	RSLV_STAT_OTHER,
	RSLV_STAT_INVALID,
	RSLV_STAT_TOO_BIG,
	RSLV_STAT_TRUNCATED,
	RSLV_STAT_OUTDATED,
	RSLV_STAT_END,
};

static struct name_desc resolv_stats[] = {
	[RSLV_STAT_ID]          = { .name = "id",          .desc = "ID" },
	[RSLV_STAT_PID]         = { .name = "pid",         .desc = "Parent ID" },
	[RSLV_STAT_SENT]        = { .name = "sent",        .desc = "Sent" },
	[RSLV_STAT_SND_ERROR]   = { .name = "send_error",  .desc = "Send error" },
	[RSLV_STAT_VALID]       = { .name = "valid",       .desc = "Valid" },
	[RSLV_STAT_UPDATE]      = { .name = "update",      .desc = "Update" },
	[RSLV_STAT_CNAME]       = { .name = "cname",       .desc = "CNAME" },
	[RSLV_STAT_CNAME_ERROR] = { .name = "cname_error", .desc = "CNAME error" },
	[RSLV_STAT_ANY_ERR]     = { .name = "any_err",     .desc = "Any errors" },
	[RSLV_STAT_NX]          = { .name = "nx",          .desc = "NX" },
	[RSLV_STAT_TIMEOUT]     = { .name = "timeout",     .desc = "Timeout" },
	[RSLV_STAT_REFUSED]     = { .name = "refused",     .desc = "Refused" },
	[RSLV_STAT_OTHER]       = { .name = "other",       .desc = "Other" },
	[RSLV_STAT_INVALID]     = { .name = "invalid",     .desc = "Invalid" },
	[RSLV_STAT_TOO_BIG]     = { .name = "too_big",     .desc = "Too big" },
	[RSLV_STAT_TRUNCATED]   = { .name = "truncated",   .desc = "Truncated" },
	[RSLV_STAT_OUTDATED]    = { .name = "outdated",    .desc = "Outdated" },
};

static struct dns_counters dns_counters;

static void resolv_fill_stats(void *d, struct field *stats)
{
	struct dns_counters *counters = d;
	stats[RSLV_STAT_ID]          = mkf_str(FO_CONFIG, counters->id);
	stats[RSLV_STAT_PID]         = mkf_str(FO_CONFIG, counters->pid);
	stats[RSLV_STAT_SENT]        = mkf_u64(FN_GAUGE, counters->sent);
	stats[RSLV_STAT_SND_ERROR]   = mkf_u64(FN_GAUGE, counters->snd_error);
	stats[RSLV_STAT_VALID]       = mkf_u64(FN_GAUGE, counters->app.resolver.valid);
	stats[RSLV_STAT_UPDATE]      = mkf_u64(FN_GAUGE, counters->app.resolver.update);
	stats[RSLV_STAT_CNAME]       = mkf_u64(FN_GAUGE, counters->app.resolver.cname);
	stats[RSLV_STAT_CNAME_ERROR] = mkf_u64(FN_GAUGE, counters->app.resolver.cname_error);
	stats[RSLV_STAT_ANY_ERR]     = mkf_u64(FN_GAUGE, counters->app.resolver.any_err);
	stats[RSLV_STAT_NX]          = mkf_u64(FN_GAUGE, counters->app.resolver.nx);
	stats[RSLV_STAT_TIMEOUT]     = mkf_u64(FN_GAUGE, counters->app.resolver.timeout);
	stats[RSLV_STAT_REFUSED]     = mkf_u64(FN_GAUGE, counters->app.resolver.refused);
	stats[RSLV_STAT_OTHER]       = mkf_u64(FN_GAUGE, counters->app.resolver.other);
	stats[RSLV_STAT_INVALID]     = mkf_u64(FN_GAUGE, counters->app.resolver.invalid);
	stats[RSLV_STAT_TOO_BIG]     = mkf_u64(FN_GAUGE, counters->app.resolver.too_big);
	stats[RSLV_STAT_TRUNCATED]   = mkf_u64(FN_GAUGE, counters->app.resolver.truncated);
	stats[RSLV_STAT_OUTDATED]    = mkf_u64(FN_GAUGE, counters->app.resolver.outdated);
}

static struct stats_module rslv_stats_module = {
	.name          = "resolvers",
	.domain_flags  = STATS_DOMAIN_RESOLVERS << STATS_DOMAIN,
	.fill_stats    = resolv_fill_stats,
	.stats         = resolv_stats,
	.stats_count   = RSLV_STAT_END,
	.counters      = &dns_counters,
	.counters_size = sizeof(dns_counters),
	.clearable     = 0,
};

INITCALL1(STG_REGISTER, stats_register_module, &rslv_stats_module);

/* Returns a pointer to the resolvers matching the id <id>. NULL is returned if
 * no match is found.
 */
struct resolvers *find_resolvers_by_id(const char *id)
{
	struct resolvers *res;

	list_for_each_entry(res, &sec_resolvers, list) {
		if (strcmp(res->id, id) == 0)
			return res;
	}
	return NULL;
}

/* Returns a pointer on the SRV request matching the name <name> for the proxy
 * <px>. NULL is returned if no match is found.
 */
struct resolv_srvrq *find_srvrq_by_name(const char *name, struct proxy *px)
{
	struct resolv_srvrq *srvrq;

	list_for_each_entry(srvrq, &resolv_srvrq_list, list) {
		if (srvrq->proxy == px && strcmp(srvrq->name, name) == 0)
			return srvrq;
	}
	return NULL;
}

/* Allocates a new SRVRQ for the given server with the name <fqdn>. It returns
 * NULL if an error occurred. */
struct resolv_srvrq *new_resolv_srvrq(struct server *srv, char *fqdn)
{
	struct proxy     *px    = srv->proxy;
	struct resolv_srvrq *srvrq = NULL;
	int fqdn_len, hostname_dn_len;

	fqdn_len = strlen(fqdn);
	hostname_dn_len = resolv_str_to_dn_label(fqdn, fqdn_len, trash.area,
					      trash.size);
	if (hostname_dn_len == -1) {
		ha_alert("%s '%s', server '%s': failed to parse FQDN '%s'\n",
			 proxy_type_str(px), px->id, srv->id, fqdn);
		goto err;
	}

	if ((srvrq = calloc(1, sizeof(*srvrq))) == NULL) {
		ha_alert("%s '%s', server '%s': out of memory\n",
			 proxy_type_str(px), px->id, srv->id);
		goto err;
	}
	srvrq->obj_type        = OBJ_TYPE_SRVRQ;
	srvrq->proxy           = px;
	srvrq->name            = strdup(fqdn);
	srvrq->hostname_dn     = strdup(trash.area);
	srvrq->hostname_dn_len = hostname_dn_len;
	if (!srvrq->name || !srvrq->hostname_dn) {
		ha_alert("%s '%s', server '%s': out of memory\n",
			 proxy_type_str(px), px->id, srv->id);
		goto err;
	}
	LIST_INIT(&srvrq->attached_servers);
	srvrq->named_servers = EB_ROOT;
	LIST_APPEND(&resolv_srvrq_list, &srvrq->list);
	return srvrq;

  err:
	if (srvrq) {
		free(srvrq->name);
		free(srvrq->hostname_dn);
		free(srvrq);
	}
	return NULL;
}


/* finds and return the SRV answer item associated to a requester (whose type is 'server').
 *
 * returns NULL in case of error or not found.
 */
struct resolv_answer_item *find_srvrq_answer_record(const struct resolv_requester *requester)
{
	struct resolv_resolution *res;
	struct eb32_node *eb32;
	struct server *srv;

	if (!requester)
		return NULL;

	if ((srv = objt_server(requester->owner)) == NULL)
		return NULL;
	/* check if the server is managed by a SRV record */
	if (srv->srvrq == NULL)
		return NULL;

	res = srv->srvrq->requester->resolution;

	/* search an ANSWER record whose target points to the server's hostname and whose port is
	 * the same as server's svc_port */
	for (eb32 = eb32_first(&res->response.answer_tree); eb32 != NULL;  eb32 = eb32_next(eb32)) {
		struct resolv_answer_item *item = eb32_entry(eb32, typeof(*item), link);

		if (memcmp(srv->hostname_dn, item->data.target, srv->hostname_dn_len) == 0 &&
		    (srv->svc_port == item->port))
			return item;
	}

	return NULL;
}

/* 2 bytes random generator to generate DNS query ID */
static inline uint16_t resolv_rnd16(void)
{
	if (!resolv_query_id_seed)
		resolv_query_id_seed = now_ms;
	resolv_query_id_seed ^= resolv_query_id_seed << 13;
	resolv_query_id_seed ^= resolv_query_id_seed >> 7;
	resolv_query_id_seed ^= resolv_query_id_seed << 17;
	return resolv_query_id_seed;
}


static inline int resolv_resolution_timeout(struct resolv_resolution *res)
{
	return res->resolvers->timeout.resolve;
}

/* Updates a resolvers' task timeout for next wake up and queue it */
static void resolv_update_resolvers_timeout(struct resolvers *resolvers)
{
	struct resolv_resolution *res;
	int next;

	next = tick_add(now_ms, resolvers->timeout.resolve);
	if (!LIST_ISEMPTY(&resolvers->resolutions.curr)) {
		res  = LIST_NEXT(&resolvers->resolutions.curr, struct resolv_resolution *, list);
		next = MIN(next, tick_add(res->last_query, resolvers->timeout.retry));
	}

	list_for_each_entry(res, &resolvers->resolutions.wait, list)
		next = MIN(next, tick_add(res->last_resolution, resolv_resolution_timeout(res)));

	resolvers->t->expire = next;
	task_queue(resolvers->t);
}

/* Forges a DNS query. It needs the following information from the caller:
 *  - <query_id>        : the DNS query id corresponding to this query
 *  - <query_type>      : DNS_RTYPE_* request DNS record type (A, AAAA, ANY...)
 *  - <hostname_dn>     : hostname in domain name format
 *  - <hostname_dn_len> : length of <hostname_dn>
 *
 * To store the query, the caller must pass a buffer <buf> and its size
 * <bufsize>. It returns the number of written bytes in success, -1 if <buf> is
 * too short.
 */
static int resolv_build_query(int query_id, int query_type, unsigned int accepted_payload_size,
                              char *hostname_dn, int hostname_dn_len, char *buf, int bufsize)
{
	struct dns_header            dns_hdr;
	struct dns_question          qinfo;
	struct dns_additional_record edns;
	char *p = buf;

	if (sizeof(dns_hdr) + sizeof(qinfo) +  sizeof(edns) + hostname_dn_len >= bufsize)
		return -1;

	memset(buf, 0, bufsize);

	/* Set dns query headers */
	dns_hdr.id      = (unsigned short) htons(query_id);
	dns_hdr.flags   = htons(0x0100); /* qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0 */
	dns_hdr.qdcount = htons(1);      /* 1 question */
	dns_hdr.ancount = 0;
	dns_hdr.nscount = 0;
	dns_hdr.arcount = htons(1);
	memcpy(p, &dns_hdr, sizeof(dns_hdr));
	p += sizeof(dns_hdr);

	/* Set up query hostname */
	memcpy(p, hostname_dn, hostname_dn_len);
	p += hostname_dn_len;
	*p++ = 0;

	/* Set up query info (type and class) */
	qinfo.qtype  = htons(query_type);
	qinfo.qclass = htons(DNS_RCLASS_IN);
	memcpy(p, &qinfo, sizeof(qinfo));
	p += sizeof(qinfo);

	/* Set the DNS extension */
	edns.name             = 0;
	edns.type             = htons(DNS_RTYPE_OPT);
	edns.udp_payload_size = htons(accepted_payload_size);
	edns.extension        = 0;
	edns.data_length      = 0;
	memcpy(p, &edns, sizeof(edns));
	p += sizeof(edns);

	return (p - buf);
}

/* Sends a DNS query to resolvers associated to a resolution. It returns 0 on
 * success or -1 if trash buffer is not large enough to build a valid query.
 */
static int resolv_send_query(struct resolv_resolution *resolution)
{
	struct resolvers  *resolvers = resolution->resolvers;
	struct dns_nameserver *ns;
	int len;

	/* Update resolution */
	resolution->nb_queries   = 0;
	resolution->nb_responses = 0;
	resolution->last_query   = now_ms;

	len = resolv_build_query(resolution->query_id, resolution->query_type,
	                      resolvers->accepted_payload_size,
	                      resolution->hostname_dn, resolution->hostname_dn_len,
	                      trash.area, trash.size);
	if (len < 0) {
		send_log(NULL, LOG_NOTICE,
			 "can not build the query message for %s, in resolvers %s.\n",
			 resolution->hostname_dn, resolvers->id);
		return -1;
	}

	list_for_each_entry(ns, &resolvers->nameservers, list) {
		if (dns_send_nameserver(ns, trash.area, len) >= 0)
			resolution->nb_queries++;
	}

	/* Push the resolution at the end of the active list */
	LIST_DEL_INIT(&resolution->list);
	LIST_APPEND(&resolvers->resolutions.curr, &resolution->list);
	return 0;
}

/* Prepares and sends a DNS resolution. It returns 1 if the query was sent, 0 if
 * skipped and -1 if an error occurred.
 */
static int
resolv_run_resolution(struct resolv_resolution *resolution)
{
	struct resolvers  *resolvers = resolution->resolvers;
	int query_id, i;

	/* Avoid sending requests for resolutions that don't yet have an
	 * hostname, ie resolutions linked to servers that do not yet have an
	 * fqdn */
	if (!resolution->hostname_dn)
		return 0;

	/* Check if a resolution has already been started for this server return
	 * directly to avoid resolution pill up. */
	if (resolution->step != RSLV_STEP_NONE)
		return 0;

	/* Generates a new query id. We try at most 100 times to find a free
	 * query id */
	for (i = 0; i < 100; ++i) {
		query_id = resolv_rnd16();
		if (!eb32_lookup(&resolvers->query_ids, query_id))
			break;
		query_id = -1;
	}
	if (query_id == -1) {
		send_log(NULL, LOG_NOTICE,
			 "could not generate a query id for %s, in resolvers %s.\n",
			 resolution->hostname_dn, resolvers->id);
		return -1;
	}

	/* Update resolution parameters */
	resolution->query_id     = query_id;
	resolution->qid.key      = query_id;
	resolution->step         = RSLV_STEP_RUNNING;
	resolution->query_type   = resolution->prefered_query_type;
	resolution->try          = resolvers->resolve_retries;
	eb32_insert(&resolvers->query_ids, &resolution->qid);

	/* Send the DNS query */
	resolution->try -= 1;
	resolv_send_query(resolution);
	return 1;
}

/* Performs a name resolution for the requester <req> */
void resolv_trigger_resolution(struct resolv_requester *req)
{
	struct resolvers  *resolvers;
	struct resolv_resolution *res;
	int exp;

	if (!req || !req->resolution)
		return;
	res       = req->resolution;
	resolvers = res->resolvers;

	enter_resolver_code();

	/* The resolution must not be triggered yet. Use the cached response, if
	 * valid */
	exp = tick_add(res->last_resolution, resolvers->hold.valid);
	if (resolvers->t && (res->status != RSLV_STATUS_VALID ||
	    !tick_isset(res->last_resolution) || tick_is_expired(exp, now_ms)))
		task_wakeup(resolvers->t, TASK_WOKEN_OTHER);

	leave_resolver_code();
}


/* Resets some resolution parameters to initial values and also delete the query
 * ID from the resolver's tree.
 */
static void resolv_reset_resolution(struct resolv_resolution *resolution)
{
	/* update resolution status */
	resolution->step            = RSLV_STEP_NONE;
	resolution->try             = 0;
	resolution->last_resolution = now_ms;
	resolution->nb_queries      = 0;
	resolution->nb_responses    = 0;
	resolution->query_type      = resolution->prefered_query_type;

	/* clean up query id */
	eb32_delete(&resolution->qid);
	resolution->query_id = 0;
	resolution->qid.key   = 0;
}

/* Returns the query id contained in a DNS response */
static inline unsigned short resolv_response_get_query_id(unsigned char *resp)
{
	return resp[0] * 256 + resp[1];
}


/* Analyses, re-builds and copies the name <name> from the DNS response packet
 * <buffer>.  <name> must point to the 'data_len' information or pointer 'c0'
 * for compressed data.  The result is copied into <dest>, ensuring we don't
 * overflow using <dest_len> Returns the number of bytes the caller can move
 * forward. If 0 it means an error occurred while parsing the name. <offset> is
 * the number of bytes the caller could move forward.
 */
int resolv_read_name(unsigned char *buffer, unsigned char *bufend,
		     unsigned char *name, char *destination, int dest_len,
		     int *offset, unsigned int depth)
{
	int nb_bytes = 0, n = 0;
	int label_len;
	unsigned char *reader = name;
	char *dest = destination;

	while (1) {
		if (reader >= bufend)
			goto err;

		/* Name compression is in use */
		if ((*reader & 0xc0) == 0xc0) {
			if (reader + 1 >= bufend)
				goto err;

			/* Must point BEFORE current position */
			if ((buffer + reader[1]) > reader)
				goto err;

			if (depth++ > 100)
				goto err;

			n = resolv_read_name(buffer, bufend, buffer + (*reader & 0x3f)*256 + reader[1],
			                     dest, dest_len - nb_bytes, offset, depth);
			if (n == 0)
				goto err;

			dest     += n;
			nb_bytes += n;
			goto out;
		}

		label_len = *reader;
		if (label_len == 0)
			goto out;

		/* Check if:
		 *  - we won't read outside the buffer
		 *  - there is enough place in the destination
		 */
		if ((reader + label_len >= bufend) || (nb_bytes + label_len >= dest_len))
			goto err;

		/* +1 to take label len + label string */
		label_len++;

		memcpy(dest, reader, label_len);

		dest     += label_len;
		nb_bytes += label_len;
		reader   += label_len;
	}

  out:
	/* offset computation:
	 * parse from <name> until finding either NULL or a pointer "c0xx"
	 */
	reader  = name;
	*offset = 0;
	while (reader < bufend) {
		if ((reader[0] & 0xc0) == 0xc0) {
			*offset += 2;
			break;
		}
		else if (*reader == 0) {
			*offset += 1;
			break;
		}
		*offset += 1;
		++reader;
	}
	return nb_bytes;

  err:
	return 0;
}

/* Reinitialize the list of aborted resolutions before calling certain
 * functions relying on it. The list must be processed by calling
 * leave_resolver_code() after operations.
 */
static void enter_resolver_code()
{
	if (!recurse)
		LIST_INIT(&death_row);
	recurse++;
}

/* Add a resolution to the death_row. */
static void abort_resolution(struct resolv_resolution *res)
{
	LIST_DEL_INIT(&res->list);
	LIST_APPEND(&death_row, &res->list);
}

/* This releases any aborted resolution found in the death row. It is mandatory
 * to call enter_resolver_code() first before the function (or loop) that
 * needs to defer deletions. Note that some of them are in relation via internal
 * objects and might cause the deletion of other ones from the same list, so we
 * must absolutely not use a list_for_each_entry_safe() nor any such thing here,
 * and solely rely on each call to remove the first remaining list element.
 */
static void leave_resolver_code()
{
	struct resolv_resolution *res;

	recurse--;
	if (recurse)
		return;

	while (!LIST_ISEMPTY(&death_row)) {
		res = LIST_NEXT(&death_row, struct resolv_resolution *, list);
		resolv_free_resolution(res);
	}

	/* make sure nobody tries to add anything without having initialized it */
	death_row = (struct list){ };
}

/* Cleanup fqdn/port and address of a server attached to a SRV resolution. This
 * happens when an SRV item is purged or when the server status is considered as
 * obsolete.
 *
 * Must be called with the DNS lock held, and with the death_row already
 * initialized via enter_resolver_code().
 */
static void resolv_srvrq_cleanup_srv(struct server *srv)
{
	_resolv_unlink_resolution(srv->resolv_requester);
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	srvrq_update_srv_status(srv, 1);
	ha_free(&srv->hostname);
	ha_free(&srv->hostname_dn);
	srv->hostname_dn_len = 0;
	memset(&srv->addr, 0, sizeof(srv->addr));
	srv->svc_port = 0;
	srv->flags |= SRV_F_NO_RESOLUTION;

	ebpt_delete(&srv->host_dn);
	ha_free(&srv->host_dn.key);

	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	LIST_DEL_INIT(&srv->srv_rec_item);
	LIST_APPEND(&srv->srvrq->attached_servers, &srv->srv_rec_item);

	srv->srvrq_check->expire = TICK_ETERNITY;
}

/* Takes care to cleanup a server resolution when it is outdated. This only
 * happens for a server relying on a SRV record.
 */
static struct task *resolv_srvrq_expire_task(struct task *t, void *context, unsigned int state)
{
	struct server *srv = context;

	if (!tick_is_expired(t->expire, now_ms))
		goto end;

	enter_resolver_code();
	HA_SPIN_LOCK(DNS_LOCK, &srv->srvrq->resolvers->lock);
	resolv_srvrq_cleanup_srv(srv);
	HA_SPIN_UNLOCK(DNS_LOCK, &srv->srvrq->resolvers->lock);
	leave_resolver_code();

  end:
	return t;
}

/* Checks for any obsolete record, also identify any SRV request, and try to
 * find a corresponding server.
 */
static void resolv_check_response(struct resolv_resolution *res)
{
	struct resolvers   *resolvers = res->resolvers;
	struct resolv_requester   *req;
	struct eb32_node          *eb32, *eb32_back;
	struct server          *srv, *srvback;
	struct resolv_srvrq       *srvrq;

	for (eb32 = eb32_first(&res->response.answer_tree); eb32 && (eb32_back = eb32_next(eb32), 1); eb32 = eb32_back) {
		struct resolv_answer_item *item = eb32_entry(eb32, typeof(*item), link);
		struct resolv_answer_item *ar_item = item->ar_item;

		/* clean up obsolete Additional record */
		if (ar_item && tick_is_lt(tick_add(ar_item->last_seen, resolvers->hold.obsolete), now_ms)) {
			/* Cleaning up the AR item will trigger an extra DNS  resolution, except if the SRV
			 * item is also obsolete.
			 */
			pool_free(resolv_answer_item_pool, ar_item);
			item->ar_item = NULL;
		}

		/* Remove obsolete items */
		if (tick_is_lt(tick_add(item->last_seen, resolvers->hold.obsolete), now_ms)) {
			if (item->type == DNS_RTYPE_A || item->type == DNS_RTYPE_AAAA) {
				/* Remove any associated server */
				list_for_each_entry_safe(srv, srvback, &item->attached_servers, ip_rec_item) {
					LIST_DEL_INIT(&srv->ip_rec_item);
				}
			}
			else if (item->type == DNS_RTYPE_SRV) {
				/* Remove any associated server */
				list_for_each_entry_safe(srv, srvback, &item->attached_servers, srv_rec_item)
					resolv_srvrq_cleanup_srv(srv);
			}

			eb32_delete(&item->link);
			if (item->ar_item) {
				pool_free(resolv_answer_item_pool, item->ar_item);
				item->ar_item = NULL;
			}
			pool_free(resolv_answer_item_pool, item);
			continue;
		}

		if (item->type != DNS_RTYPE_SRV)
			continue;

		/* Now process SRV records */
		list_for_each_entry(req, &res->requesters, list) {
			struct ebpt_node *node;
			char target[DNS_MAX_NAME_SIZE+1];

			int i;
			if ((srvrq = objt_resolv_srvrq(req->owner)) == NULL)
				continue;

			/* Check if a server already uses that record */
			srv = NULL;
			list_for_each_entry(srv, &item->attached_servers, srv_rec_item) {
				if (srv->srvrq == srvrq) {
					HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
					goto srv_found;
				}
			}


			/* If not empty we try to match a server
			 * in server state file tree with the same hostname
			 */
			if (!eb_is_empty(&srvrq->named_servers)) {
				srv = NULL;

				/* convert the key to lookup in lower case */
				for (i = 0 ; item->data.target[i] ; i++)
					target[i] = tolower(item->data.target[i]);
				target[i] = 0;

				node = ebis_lookup(&srvrq->named_servers, target);
				if (node) {
					srv = ebpt_entry(node, struct server, host_dn);
					HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);

					/* an entry was found with the same hostname
					 * let check this node if the port matches
					 * and try next node if the hostname
					 * is still the same
					 */
					while (1) {
						if (srv->svc_port == item->port) {
							/* server found, we remove it from tree */
							ebpt_delete(node);
							ha_free(&srv->host_dn.key);
							goto srv_found;
						}

						HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);

						node = ebpt_next(node);
						if (!node)
							break;

						srv = ebpt_entry(node, struct server, host_dn);
						HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);

						if ((item->data_len != srv->hostname_dn_len)
						    || memcmp(srv->hostname_dn, item->data.target, item->data_len) != 0) {
							HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
							break;
						}
					}
				}
			}

			/* Pick the first server listed in srvrq (those ones don't
			 * have hostname and are free to use)
			 */
			srv = NULL;
			list_for_each_entry(srv, &srvrq->attached_servers, srv_rec_item) {
				LIST_DEL_INIT(&srv->srv_rec_item);
				HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
				goto srv_found;
			}
			srv = NULL;

srv_found:
			/* And update this server, if found (srv is locked here) */
			if (srv) {
				/* re-enable DNS resolution for this server by default */
				srv->flags &= ~SRV_F_NO_RESOLUTION;
				srv->srvrq_check->expire = TICK_ETERNITY;

				/* Check if an Additional Record is associated to this SRV record.
				 * Perform some sanity checks too to ensure the record can be used.
				 * If all fine, we simply pick up the IP address found and associate
				 * it to the server. And DNS resolution is disabled for this server.
				 */
				if ((item->ar_item != NULL) &&
				    (item->ar_item->type == DNS_RTYPE_A || item->ar_item->type == DNS_RTYPE_AAAA))
				{

					switch (item->ar_item->type) {
						case DNS_RTYPE_A:
							srv_update_addr(srv, &item->ar_item->data.in4.sin_addr, AF_INET, "DNS additional record");
						break;
						case DNS_RTYPE_AAAA:
							srv_update_addr(srv, &item->ar_item->data.in6.sin6_addr, AF_INET6, "DNS additional record");
						break;
					}

					srv->flags |= SRV_F_NO_RESOLUTION;

					/* Unlink A/AAAA resolution for this server if there is an AR item.
					 * It is usless to perform an extra resolution
					 */
					_resolv_unlink_resolution(srv->resolv_requester);
				}

				if (!srv->hostname_dn) {
					const char *msg = NULL;
					char hostname[DNS_MAX_NAME_SIZE+1];

					if (resolv_dn_label_to_str(item->data.target, item->data_len,
					                           hostname, sizeof(hostname)) == -1) {
						HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
						continue;
					}
					msg = srv_update_fqdn(srv, hostname, "SRV record", 1);
					if (msg)
						send_log(srv->proxy, LOG_NOTICE, "%s", msg);
				}

				if (!LIST_INLIST(&srv->srv_rec_item))
					LIST_APPEND(&item->attached_servers, &srv->srv_rec_item);

				if (!(srv->flags & SRV_F_NO_RESOLUTION)) {
					/* If there is no AR item responsible of the FQDN resolution,
					 * trigger a dedicated DNS resolution
					 */
					if (!srv->resolv_requester || !srv->resolv_requester->resolution)
						resolv_link_resolution(srv, OBJ_TYPE_SERVER, 1);
				}

				/* Update the server status */
				srvrq_update_srv_status(srv, (srv->addr.ss_family != AF_INET && srv->addr.ss_family != AF_INET6));

				srv->svc_port = item->port;
				srv->flags   &= ~SRV_F_MAPPORTS;

				if (!srv->resolv_opts.ignore_weight) {
					char weight[9];
					int ha_weight;

					/* DNS weight range if from 0 to 65535
					 * HAProxy weight is from 0 to 256
					 * The rule below ensures that weight 0 is well respected
					 * while allowing a "mapping" from DNS weight into HAProxy's one.
					 */
					ha_weight = (item->weight + 255) / 256;

					snprintf(weight, sizeof(weight), "%d", ha_weight);
					server_parse_weight_change_request(srv, weight);
				}
				HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
			}
		}
	}
}

/* Validates that the buffer DNS response provided in <resp> and finishing
 * before <bufend> is valid from a DNS protocol point of view.
 *
 * The result is stored in <resolution>' response, buf_response,
 * response_query_records and response_answer_records members.
 *
 * This function returns one of the RSLV_RESP_* code to indicate the type of
 * error found.
 */
static int resolv_validate_dns_response(unsigned char *resp, unsigned char *bufend,
                                        struct resolv_resolution *resolution, int max_answer_records)
{
	unsigned char *reader;
	char *previous_dname, tmpname[DNS_MAX_NAME_SIZE];
	int len, flags, offset;
	int nb_saved_records;
	struct resolv_query_item *query;
	struct resolv_answer_item *answer_record, *tmp_record;
	struct resolv_response *r_res;
	struct eb32_node *eb32;
	uint32_t key = 0;
	int i, found = 0;
	int cause = RSLV_RESP_ERROR;

	reader         = resp;
	len            = 0;
	previous_dname = NULL;
	query      = NULL;
	answer_record = NULL;

	/* Initialization of response buffer and structure */
	r_res = &resolution->response;

	/* query id */
	if (reader + 2 >= bufend)
		goto invalid_resp;

	r_res->header.id = reader[0] * 256 + reader[1];
	reader += 2;

	/* Flags and rcode are stored over 2 bytes
	 * First byte contains:
	 *  - response flag (1 bit)
	 *  - opcode (4 bits)
	 *  - authoritative (1 bit)
	 *  - truncated (1 bit)
	 *  - recursion desired (1 bit)
	 */
	if (reader + 2 >= bufend)
		goto invalid_resp;

	flags = reader[0] * 256 + reader[1];

	if ((flags & DNS_FLAG_REPLYCODE) != DNS_RCODE_NO_ERROR) {
		if ((flags & DNS_FLAG_REPLYCODE) == DNS_RCODE_NX_DOMAIN) {
			cause = RSLV_RESP_NX_DOMAIN;
			goto return_error;
		}
		else if ((flags & DNS_FLAG_REPLYCODE) == DNS_RCODE_REFUSED) {
			cause = RSLV_RESP_REFUSED;
			goto return_error;
		}
		else {
			cause = RSLV_RESP_ERROR;
			goto return_error;
		}
	}

	/* Move forward 2 bytes for flags */
	reader += 2;

	/* 2 bytes for question count */
	if (reader + 2 >= bufend)
		goto invalid_resp;
	r_res->header.qdcount = reader[0] * 256 + reader[1];
	/* (for now) we send one query only, so we expect only one in the
	 * response too */
	if (r_res->header.qdcount != 1) {
		cause = RSLV_RESP_QUERY_COUNT_ERROR;
		goto return_error;
	}

	if (r_res->header.qdcount > DNS_MAX_QUERY_RECORDS)
		goto invalid_resp;
	reader += 2;

	/* 2 bytes for answer count */
	if (reader + 2 >= bufend)
		goto invalid_resp;
	r_res->header.ancount = reader[0] * 256 + reader[1];
	if (r_res->header.ancount == 0) {
		cause = RSLV_RESP_ANCOUNT_ZERO;
		goto return_error;
	}

	/* Check if too many records are announced */
	if (r_res->header.ancount > max_answer_records)
		goto invalid_resp;
	reader += 2;

	/* 2 bytes authority count */
	if (reader + 2 >= bufend)
		goto invalid_resp;
	r_res->header.nscount = reader[0] * 256 + reader[1];
	reader += 2;

	/* 2 bytes additional count */
	if (reader + 2 >= bufend)
		goto invalid_resp;
	r_res->header.arcount = reader[0] * 256 + reader[1];
	reader += 2;

	/* Parsing dns queries. For now there is only one query and it exists
	 * because (qdcount == 1).
	 */
	query = &resolution->response_query_records[0];

	/* Name is a NULL terminated string in our case, since we have
	 * one query per response and the first one can't be compressed
	 * (using the 0x0c format) */
	offset = 0;
	len = resolv_read_name(resp, bufend, reader, query->name, DNS_MAX_NAME_SIZE, &offset, 0);

	if (len == 0)
		goto invalid_resp;

	/* Now let's check the query's dname corresponds to the one we sent. */
	if (len != resolution->hostname_dn_len ||
	    memcmp(query->name, resolution->hostname_dn, resolution->hostname_dn_len) != 0) {
		cause = RSLV_RESP_WRONG_NAME;
		goto return_error;
	}

	reader += offset;
	previous_dname = query->name;

	/* move forward 2 bytes for question type */
	if (reader + 2 >= bufend)
		goto invalid_resp;
	query->type = reader[0] * 256 + reader[1];
	reader += 2;

	/* move forward 2 bytes for question class */
	if (reader + 2 >= bufend)
		goto invalid_resp;
	query->class = reader[0] * 256 + reader[1];
	reader += 2;

	/* TRUNCATED flag must be checked after we could read the query type
	 * because a TRUNCATED SRV query type response can still be exploited
	 */
	if (query->type != DNS_RTYPE_SRV && flags & DNS_FLAG_TRUNCATED) {
		cause = RSLV_RESP_TRUNCATED;
		goto return_error;
	}

	/* now parsing response records */
	nb_saved_records = 0;
	for (i = 0; i < r_res->header.ancount; i++) {
		if (reader >= bufend)
			goto invalid_resp;

		answer_record = pool_alloc(resolv_answer_item_pool);
		if (answer_record == NULL)
			goto invalid_resp;

		/* initialization */
		answer_record->ar_item = NULL;
		answer_record->last_seen = TICK_ETERNITY;
		LIST_INIT(&answer_record->attached_servers);
		answer_record->link.node.leaf_p = NULL;

		offset = 0;
		len = resolv_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE, &offset, 0);

		if (len == 0)
			goto invalid_resp;

		/* Check if the current record dname is valid.  previous_dname
		 * points either to queried dname or last CNAME target */
		if (query->type != DNS_RTYPE_SRV && memcmp(previous_dname, tmpname, len) != 0) {
			if (i == 0) {
				/* First record, means a mismatch issue between
				 * queried dname and dname found in the first
				 * record */
				goto invalid_resp;
			}
			else {
				/* If not the first record, this means we have a
				 * CNAME resolution error.
				 */
				cause = RSLV_RESP_CNAME_ERROR;
				goto return_error;
			}

		}

		memcpy(answer_record->name, tmpname, len);
		answer_record->name[len] = 0;

		reader += offset;
		if (reader >= bufend)
			goto invalid_resp;

		/* 2 bytes for record type (A, AAAA, CNAME, etc...) */
		if (reader + 2 > bufend)
			goto invalid_resp;

		answer_record->type = reader[0] * 256 + reader[1];
		reader += 2;

		/* 2 bytes for class (2) */
		if (reader + 2 > bufend)
			goto invalid_resp;

		answer_record->class = reader[0] * 256 + reader[1];
		reader += 2;

		/* 4 bytes for ttl (4) */
		if (reader + 4 > bufend)
			goto invalid_resp;

		answer_record->ttl =   reader[0] * 16777216 + reader[1] * 65536
		                     + reader[2] * 256 + reader[3];
		reader += 4;

		/* Now reading data len */
		if (reader + 2 > bufend)
			goto invalid_resp;

		answer_record->data_len = reader[0] * 256 + reader[1];

		/* Move forward 2 bytes for data len */
		reader += 2;

		if (reader + answer_record->data_len > bufend)
			goto invalid_resp;

		/* Analyzing record content */
		switch (answer_record->type) {
			case DNS_RTYPE_A:
				/* ipv4 is stored on 4 bytes */
				if (answer_record->data_len != 4)
					goto invalid_resp;

				answer_record->data.in4.sin_family = AF_INET;
				memcpy(&answer_record->data.in4.sin_addr, reader, answer_record->data_len);
				key = XXH32(reader, answer_record->data_len, answer_record->type);
				break;

			case DNS_RTYPE_CNAME:
				/* Check if this is the last record and update the caller about the status:
				 * no IP could be found and last record was a CNAME. Could be triggered
				 * by a wrong query type
				 *
				 * + 1 because answer_record_id starts at 0
				 * while number of answers is an integer and
				 * starts at 1.
				 */
				if (i + 1 == r_res->header.ancount) {
					cause = RSLV_RESP_CNAME_ERROR;
					goto return_error;
				}

				offset = 0;
				len = resolv_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE, &offset, 0);
				if (len == 0)
					goto invalid_resp;

				memcpy(answer_record->data.target, tmpname, len);
				answer_record->data.target[len] = 0;
				key = XXH32(tmpname, len, answer_record->type);
				previous_dname = answer_record->data.target;
				break;


			case DNS_RTYPE_SRV:
				/* Answer must contain :
				 * - 2 bytes for the priority
				 * - 2 bytes for the weight
				 * - 2 bytes for the port
				 * - the target hostname
				 */
				if (answer_record->data_len <= 6)
					goto invalid_resp;

				answer_record->priority = read_n16(reader);
				reader += sizeof(uint16_t);
				answer_record->weight = read_n16(reader);
				reader += sizeof(uint16_t);
				answer_record->port = read_n16(reader);
				reader += sizeof(uint16_t);
				offset = 0;
				len = resolv_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE, &offset, 0);
				if (len == 0)
					goto invalid_resp;

				answer_record->data_len = len;
				memcpy(answer_record->data.target, tmpname, len);
				answer_record->data.target[len] = 0;
				key = XXH32(tmpname, len, answer_record->type);
				if (answer_record->ar_item != NULL) {
					pool_free(resolv_answer_item_pool, answer_record->ar_item);
					answer_record->ar_item = NULL;
				}
				break;

			case DNS_RTYPE_AAAA:
				/* ipv6 is stored on 16 bytes */
				if (answer_record->data_len != 16)
					goto invalid_resp;

				answer_record->data.in6.sin6_family = AF_INET6;
				memcpy(&answer_record->data.in6.sin6_addr, reader, answer_record->data_len);
				key = XXH32(reader, answer_record->data_len, answer_record->type);
				break;

		} /* switch (record type) */

		/* Increment the counter for number of records saved into our
		 * local response */
		nb_saved_records++;

		/* Move forward answer_record->data_len for analyzing next
		 * record in the response */
		reader += ((answer_record->type == DNS_RTYPE_SRV)
			   ? offset
			   : answer_record->data_len);

		/* Lookup to see if we already had this entry */
		found = 0;

		for (eb32 = eb32_lookup(&r_res->answer_tree, key); eb32 != NULL;  eb32 = eb32_next(eb32)) {
			tmp_record = eb32_entry(eb32, typeof(*tmp_record), link);
			if (tmp_record->type != answer_record->type)
				continue;

			switch(tmp_record->type) {
				case DNS_RTYPE_A:
					if (!memcmp(&answer_record->data.in4.sin_addr,
						    &tmp_record->data.in4.sin_addr,
						    sizeof(answer_record->data.in4.sin_addr)))
						found = 1;
					break;

				case DNS_RTYPE_AAAA:
					if (!memcmp(&answer_record->data.in6.sin6_addr,
						    &tmp_record->data.in6.sin6_addr,
						    sizeof(answer_record->data.in6.sin6_addr)))
						found = 1;
					break;

			case DNS_RTYPE_SRV:
                                if (answer_record->data_len == tmp_record->data_len &&
				    memcmp(answer_record->data.target, tmp_record->data.target, answer_record->data_len) == 0 &&
				    answer_record->port == tmp_record->port) {
					tmp_record->weight = answer_record->weight;
                                        found = 1;
				}
                                break;

			default:
				break;
			}

			if (found == 1)
				break;
		}

		if (found == 1) {
			tmp_record->last_seen = now_ms;
			pool_free(resolv_answer_item_pool, answer_record);
			answer_record = NULL;
		}
		else {
			answer_record->last_seen = now_ms;
			answer_record->ar_item = NULL;
			answer_record->link.key = key;
			eb32_insert(&r_res->answer_tree, &answer_record->link);
			answer_record = NULL;
		}
	} /* for i 0 to ancount */

	/* Save the number of records we really own */
	r_res->header.ancount = nb_saved_records;

	/* now parsing additional records for SRV queries only */
	if (query->type != DNS_RTYPE_SRV)
		goto skip_parsing_additional_records;

	/* if we find Authority records, just skip them */
	for (i = 0; i < r_res->header.nscount; i++) {
		offset = 0;
		len = resolv_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE,
		                    &offset, 0);
		if (len == 0)
			continue;

		if (reader + offset + 10 >= bufend)
			goto invalid_resp;

		reader += offset;
		/* skip 2 bytes for class */
		reader += 2;
		/* skip 2 bytes for type */
		reader += 2;
		/* skip 4 bytes for ttl */
		reader += 4;
		/* read data len */
		len = reader[0] * 256 + reader[1];
		reader += 2;

		if (reader + len >= bufend)
			goto invalid_resp;

		reader += len;
	}

	nb_saved_records = 0;
	for (i = 0; i < r_res->header.arcount; i++) {
		if (reader >= bufend)
			goto invalid_resp;

		answer_record = pool_alloc(resolv_answer_item_pool);
		if (answer_record == NULL)
			goto invalid_resp;
		answer_record->last_seen = TICK_ETERNITY;
		LIST_INIT(&answer_record->attached_servers);

		offset = 0;
		len = resolv_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE, &offset, 0);

		if (len == 0) {
			pool_free(resolv_answer_item_pool, answer_record);
			answer_record = NULL;
			continue;
		}

		memcpy(answer_record->name, tmpname, len);
		answer_record->name[len] = 0;

		reader += offset;
		if (reader >= bufend)
			goto invalid_resp;

		/* 2 bytes for record type (A, AAAA, CNAME, etc...) */
		if (reader + 2 > bufend)
			goto invalid_resp;

		answer_record->type = reader[0] * 256 + reader[1];
		reader += 2;

		/* 2 bytes for class (2) */
		if (reader + 2 > bufend)
			goto invalid_resp;

		answer_record->class = reader[0] * 256 + reader[1];
		reader += 2;

		/* 4 bytes for ttl (4) */
		if (reader + 4 > bufend)
			goto invalid_resp;

		answer_record->ttl =   reader[0] * 16777216 + reader[1] * 65536
		                     + reader[2] * 256 + reader[3];
		reader += 4;

		/* Now reading data len */
		if (reader + 2 > bufend)
			goto invalid_resp;

		answer_record->data_len = reader[0] * 256 + reader[1];

		/* Move forward 2 bytes for data len */
		reader += 2;

		if (reader + answer_record->data_len > bufend)
			goto invalid_resp;

		/* Analyzing record content */
		switch (answer_record->type) {
			case DNS_RTYPE_A:
				/* ipv4 is stored on 4 bytes */
				if (answer_record->data_len != 4)
					goto invalid_resp;

				answer_record->data.in4.sin_family = AF_INET;
				memcpy(&answer_record->data.in4.sin_addr, reader, answer_record->data_len);
				break;

			case DNS_RTYPE_AAAA:
				/* ipv6 is stored on 16 bytes */
				if (answer_record->data_len != 16)
					goto invalid_resp;

				answer_record->data.in6.sin6_family = AF_INET6;
				memcpy(&answer_record->data.in6.sin6_addr, reader, answer_record->data_len);
				break;

			default:
				pool_free(resolv_answer_item_pool, answer_record);
				answer_record = NULL;
				continue;

		} /* switch (record type) */

		/* Increment the counter for number of records saved into our
		 * local response */
		nb_saved_records++;

		/* Move forward answer_record->data_len for analyzing next
		 * record in the response */
		reader += answer_record->data_len;

		/* Lookup to see if we already had this entry */
		found = 0;

		for (eb32 = eb32_first(&r_res->answer_tree); eb32 != NULL;  eb32 = eb32_next(eb32)) {
			struct resolv_answer_item *ar_item;

			tmp_record = eb32_entry(eb32, typeof(*tmp_record), link);
			if (tmp_record->type != DNS_RTYPE_SRV || !tmp_record->ar_item)
				continue;

			ar_item = tmp_record->ar_item;
			if (ar_item->type != answer_record->type || ar_item->last_seen == now_ms ||
			    len != tmp_record->data_len ||
			    memcmp(answer_record->name, tmp_record->data.target, tmp_record->data_len) != 0)
				continue;

			switch(ar_item->type) {
				case DNS_RTYPE_A:
					if (!memcmp(&answer_record->data.in4.sin_addr,
						    &ar_item->data.in4.sin_addr,
						    sizeof(answer_record->data.in4.sin_addr)))
						found = 1;
					break;

				case DNS_RTYPE_AAAA:
					if (!memcmp(&answer_record->data.in6.sin6_addr,
						    &ar_item->data.in6.sin6_addr,
						    sizeof(answer_record->data.in6.sin6_addr)))
						found = 1;
					break;

				default:
					break;
			}

			if (found == 1)
				break;
		}

		if (found == 1) {
			tmp_record->ar_item->last_seen = now_ms;
			pool_free(resolv_answer_item_pool, answer_record);
			answer_record = NULL;
		}
		else {
			answer_record->last_seen = now_ms;
			answer_record->ar_item = NULL;

			// looking for the SRV record in the response list linked to this additional record
			for (eb32 = eb32_first(&r_res->answer_tree); eb32 != NULL;  eb32 = eb32_next(eb32)) {
				tmp_record = eb32_entry(eb32, typeof(*tmp_record), link);

				if (tmp_record->type == DNS_RTYPE_SRV &&
				    tmp_record->ar_item == NULL &&
				    memcmp(tmp_record->data.target, answer_record->name, tmp_record->data_len) == 0) {
					/* Always use the received additional record to refresh info */
					if (tmp_record->ar_item)
						pool_free(resolv_answer_item_pool, tmp_record->ar_item);
					tmp_record->ar_item = answer_record;
					answer_record = NULL;
					break;
				}
			}
			if (answer_record) {
				pool_free(resolv_answer_item_pool, answer_record);
				answer_record = NULL;
			}
		}
	} /* for i 0 to arcount */

 skip_parsing_additional_records:

	/* Save the number of records we really own */
	r_res->header.arcount = nb_saved_records;
	resolv_check_response(resolution);
	return RSLV_RESP_VALID;

 invalid_resp:
	cause = RSLV_RESP_INVALID;

 return_error:
	pool_free(resolv_answer_item_pool, answer_record);
	return cause;
}

/* Searches dn_name resolution in resp.
 * If existing IP not found, return the first IP matching family_priority,
 * otherwise, first ip found
 * The following tasks are the responsibility of the caller:
 *   - <r_res> contains an error free DNS response
 * For both cases above, resolv_validate_dns_response is required
 * returns one of the RSLV_UPD_* code
 */
int resolv_get_ip_from_response(struct resolv_response *r_res,
                             struct resolv_options *resolv_opts, void *currentip,
                             short currentip_sin_family,
                             void **newip, short *newip_sin_family,
                             struct server *owner)
{
	struct resolv_answer_item *record, *found_record = NULL;
	struct eb32_node *eb32;
	int family_priority;
	int currentip_found;
	unsigned char *newip4, *newip6;
	int currentip_sel;
	int j;
	int score, max_score;
	int allowed_duplicated_ip;

	/* srv is linked to an alive ip record */
	if (owner && LIST_INLIST(&owner->ip_rec_item))
		return RSLV_UPD_NO;

	family_priority   = resolv_opts->family_prio;
	allowed_duplicated_ip = resolv_opts->accept_duplicate_ip;
	*newip = newip4   = newip6 = NULL;
	currentip_found   = 0;
	*newip_sin_family = AF_UNSPEC;
	max_score         = -1;

	/* Select an IP regarding configuration preference.
	 * Top priority is the preferred network ip version,
	 * second priority is the preferred network.
	 * the last priority is the currently used IP,
	 *
	 * For these three priorities, a score is calculated. The
	 * weight are:
	 *  8 - preferred ip version.
	 *  4 - preferred network.
	 *  2 - if the ip in the record is not affected to any other server in the same backend (duplication)
	 *  1 - current ip.
	 * The result with the biggest score is returned.
	 */

	for (eb32 = eb32_first(&r_res->answer_tree); eb32 != NULL;  eb32 = eb32_next(eb32)) {
		void *ip;
		unsigned char ip_type;

		record = eb32_entry(eb32, typeof(*record), link);
		if (record->type == DNS_RTYPE_A) {
			ip_type = AF_INET;
			ip = &record->data.in4.sin_addr;
		}
		else if (record->type == DNS_RTYPE_AAAA) {
			ip_type = AF_INET6;
			ip = &record->data.in6.sin6_addr;
		}
		else
			continue;
		score = 0;

		/* Check for preferred ip protocol. */
		if (ip_type == family_priority)
			score += 8;

		/* Check for preferred network. */
		for (j = 0; j < resolv_opts->pref_net_nb; j++) {

			/* Compare only the same addresses class. */
			if (resolv_opts->pref_net[j].family != ip_type)
				continue;

			if ((ip_type == AF_INET &&
			     in_net_ipv4(ip,
			                 &resolv_opts->pref_net[j].mask.in4,
			                 &resolv_opts->pref_net[j].addr.in4)) ||
			    (ip_type == AF_INET6 &&
			     in_net_ipv6(ip,
			                 &resolv_opts->pref_net[j].mask.in6,
			                 &resolv_opts->pref_net[j].addr.in6))) {
				score += 4;
				break;
			}
		}

		/* Check if the IP found in the record is already affected to a
		 * member of a group.  If not, the score should be incremented
		 * by 2. */
		if (owner) {
			struct server *srv;
			int already_used = 0;

			list_for_each_entry(srv, &record->attached_servers, ip_rec_item) {
				if (srv == owner)
					continue;
				if (srv->proxy == owner->proxy) {
					already_used = 1;
					break;
				}
			}
			if (already_used) {
				if (!allowed_duplicated_ip) {
					continue;
				}
			}
			else {
				score += 2;
			}
		} else {
			score += 2;
		}

		/* Check for current ip matching. */
		if (ip_type == currentip_sin_family &&
		    ((currentip_sin_family == AF_INET &&
		      !memcmp(ip, currentip, 4)) ||
		     (currentip_sin_family == AF_INET6 &&
		      !memcmp(ip, currentip, 16)))) {
			score++;
			currentip_sel = 1;
		}
		else
			currentip_sel = 0;

		/* Keep the address if the score is better than the previous
		 * score. The maximum score is 15, if this value is reached, we
		 * break the parsing. Implicitly, this score is reached the ip
		 * selected is the current ip. */
		if (score > max_score) {
			if (ip_type == AF_INET)
				newip4 = ip;
			else
				newip6 = ip;
			found_record = record;
			currentip_found = currentip_sel;
			if (score == 15) {
				/* this was not registered on the current record but it matches
				 * let's fix it (it may comes from state file */
				if (owner)
					LIST_APPEND(&found_record->attached_servers, &owner->ip_rec_item);
				return RSLV_UPD_NO;
			}
			max_score = score;
		}
	} /* list for each record entries */

	/* No IP found in the response */
	if (!newip4 && !newip6)
		return RSLV_UPD_NO_IP_FOUND;

	/* Case when the caller looks first for an IPv4 address */
	if (family_priority == AF_INET) {
		if (newip4) {
			*newip = newip4;
			*newip_sin_family = AF_INET;
		}
		else if (newip6) {
			*newip = newip6;
			*newip_sin_family = AF_INET6;
		}
	}
	/* Case when the caller looks first for an IPv6 address */
	else if (family_priority == AF_INET6) {
		if (newip6) {
			*newip = newip6;
			*newip_sin_family = AF_INET6;
		}
		else if (newip4) {
			*newip = newip4;
			*newip_sin_family = AF_INET;
		}
	}
	/* Case when the caller have no preference (we prefer IPv6) */
	else if (family_priority == AF_UNSPEC) {
		if (newip6) {
			*newip = newip6;
			*newip_sin_family = AF_INET6;
		}
		else if (newip4) {
			*newip = newip4;
			*newip_sin_family = AF_INET;
		}
	}

	/* the ip of this record was chosen for the server */
	if (owner && found_record) {
		LIST_DEL_INIT(&owner->ip_rec_item);
		LIST_APPEND(&found_record->attached_servers, &owner->ip_rec_item);
	}

	eb32 = eb32_first(&r_res->answer_tree);
	if (eb32) {
		/* Move the first record to the end of the list, for internal
		 * round robin.
		 */
		eb32_delete(eb32);
		eb32_insert(&r_res->answer_tree, eb32);
	}

	return (currentip_found ? RSLV_UPD_NO : RSLV_UPD_SRVIP_NOT_FOUND);
}

/* Turns a domain name label into a string: 3www7haproxy3org into www.haproxy.org
 *
 * <dn> contains the input label of <dn_len> bytes long and does not need to be
 * null-terminated. <str> must be allocated large enough to contain a full host
 * name plus the trailing zero, and the allocated size must be passed in
 * <str_len>.
 *
 * In case of error, -1 is returned, otherwise, the number of bytes copied in
 * <str> (including the terminating null byte).
 */
int resolv_dn_label_to_str(const char *dn, int dn_len, char *str, int str_len)
{
	char *ptr;
	int i, sz;

	if (str_len < dn_len)
		return -1;

	ptr = str;
	for (i = 0; i < dn_len; ++i) {
		sz = dn[i];
		if (i)
			*ptr++ = '.';
		/* copy the string at i+1 to lower case */
		for (; sz > 0; sz--)
			*(ptr++) = tolower(dn[++i]);
	}
	*ptr++ = '\0';
	return (ptr - str);
}

/* Turns a string into domain name label: www.haproxy.org into 3www7haproxy3org
 *
 * <str> contains the input string that is <str_len> bytes long (trailing zero
 * not needed). <dn> buffer must be allocated large enough to contain the
 * encoded string and a trailing zero, so it must be at least str_len+2, and
 * this allocated buffer size must be passed in <dn_len>.
 *
 * In case of error, -1 is returned, otherwise, the number of bytes copied in
 * <dn> (excluding the terminating null byte).
 */
int resolv_str_to_dn_label(const char *str, int str_len, char *dn, int dn_len)
{
	int i, offset;

	if (dn_len < str_len + 2)
		return -1;

	/* First byte of dn will be used to store the length of the first
	 * label */
	offset = 0;
	for (i = 0; i < str_len; ++i) {
		if (str[i] == '.') {
			/* 2 or more consecutive dots is invalid */
			if (i == offset)
				return -1;

			/* ignore trailing dot */
			if (i + 1 == str_len) {
				i++;
				break;
			}

			dn[offset] = (i - offset);
			offset = i+1;
			continue;
		}
		dn[i+1] = tolower(str[i]);
	}
	dn[offset] = i - offset;
	dn[i+1] = '\0';
	return i+1;
}

/* Validates host name:
 *  - total size
 *  - each label size individually
 * returns:
 *  0 in case of error. If <err> is not NULL, an error message is stored there.
 *  1 when no error. <err> is left unaffected.
 */
int resolv_hostname_validation(const char *string, char **err)
{
	int i;

	if (strlen(string) > DNS_MAX_NAME_SIZE) {
		if (err)
			*err = DNS_TOO_LONG_FQDN;
		return 0;
	}

	while (*string) {
		i = 0;
		while (*string && *string != '.' && i < DNS_MAX_LABEL_SIZE) {
			if (!(*string == '-' || *string == '_' ||
			      (*string >= 'a' && *string <= 'z') ||
			      (*string >= 'A' && *string <= 'Z') ||
			      (*string >= '0' && *string <= '9'))) {
				if (err)
					*err = DNS_INVALID_CHARACTER;
				return 0;
			}
			i++;
			string++;
		}

		if (!(*string))
			break;

		if (*string != '.' && i >= DNS_MAX_LABEL_SIZE) {
			if (err)
				*err = DNS_LABEL_TOO_LONG;
			return 0;
		}

		string++;
	}
	return 1;
}

/* Picks up an available resolution from the different resolution list
 * associated to a resolvers section, in this order:
 *   1. check in resolutions.curr for the same hostname and query_type
 *   2. check in resolutions.wait for the same hostname and query_type
 *   3. Get a new resolution from resolution pool
 *
 * Returns an available resolution, NULL if none found.
 */
static struct resolv_resolution *resolv_pick_resolution(struct resolvers *resolvers,
							char **hostname_dn, int hostname_dn_len,
							int query_type)
{
	struct resolv_resolution *res;

	if (!*hostname_dn)
		goto from_pool;

	/* Search for same hostname and query type in resolutions.curr */
	list_for_each_entry(res, &resolvers->resolutions.curr, list) {
		if (!res->hostname_dn)
			continue;
		if ((query_type == res->prefered_query_type) &&
		    hostname_dn_len == res->hostname_dn_len  &&
		    memcmp(*hostname_dn, res->hostname_dn, hostname_dn_len) == 0)
			return res;
	}

	/* Search for same hostname and query type in resolutions.wait */
	list_for_each_entry(res, &resolvers->resolutions.wait, list) {
		if (!res->hostname_dn)
			continue;
		if ((query_type == res->prefered_query_type) &&
		    hostname_dn_len == res->hostname_dn_len  &&
		    memcmp(*hostname_dn, res->hostname_dn, hostname_dn_len) == 0)
			return res;
	}

  from_pool:
	/* No resolution could be found, so let's allocate a new one */
	res = pool_zalloc(resolv_resolution_pool);
	if (res) {
		res->resolvers  = resolvers;
		res->uuid       = resolution_uuid;
		res->status     = RSLV_STATUS_NONE;
		res->step       = RSLV_STEP_NONE;
		res->last_valid = now_ms;

		LIST_INIT(&res->requesters);
		res->response.answer_tree = EB_ROOT;

		res->prefered_query_type = query_type;
		res->query_type          = query_type;
		res->hostname_dn         = *hostname_dn;
		res->hostname_dn_len     = hostname_dn_len;

		++resolution_uuid;

		/* Move the resolution to the resolvers wait queue */
		LIST_APPEND(&resolvers->resolutions.wait, &res->list);
	}
	return res;
}

/* deletes and frees all answer_items from the resolution's answer_list */
static void resolv_purge_resolution_answer_records(struct resolv_resolution *resolution)
{
	struct eb32_node *eb32, *eb32_back;
	struct resolv_answer_item *item;

	for (eb32 = eb32_first(&resolution->response.answer_tree);
	     eb32 && (eb32_back = eb32_next(eb32), 1);
	     eb32 = eb32_back) {
		item = eb32_entry(eb32, typeof(*item), link);
		eb32_delete(&item->link);
		pool_free(resolv_answer_item_pool, item->ar_item);
		pool_free(resolv_answer_item_pool, item);
	}
}

/* Releases a resolution from its requester(s) and move it back to the pool */
static void resolv_free_resolution(struct resolv_resolution *resolution)
{
	struct resolv_requester *req, *reqback;

	/* clean up configuration */
	resolv_reset_resolution(resolution);
	resolution->hostname_dn = NULL;
	resolution->hostname_dn_len = 0;

	list_for_each_entry_safe(req, reqback, &resolution->requesters, list) {
		LIST_DEL_INIT(&req->list);
		req->resolution = NULL;
	}
	resolv_purge_resolution_answer_records(resolution);

	LIST_DEL_INIT(&resolution->list);
	pool_free(resolv_resolution_pool, resolution);
}

/* If *<req> is not NULL, returns it, otherwise tries to allocate a requester
 * and makes it owned by this obj_type, with the proposed callback and error
 * callback. On success, *req is assigned the allocated requester. Returns
 * NULL on allocation failure.
 */
static struct resolv_requester *
resolv_get_requester(struct resolv_requester **req, enum obj_type *owner,
                     int (*cb)(struct resolv_requester *, struct dns_counters *),
                     int (*err_cb)(struct resolv_requester *, int))
{
	struct resolv_requester *tmp;

	if (*req)
		return *req;

	tmp = pool_alloc(resolv_requester_pool);
	if (!tmp)
		goto end;

	LIST_INIT(&tmp->list);
	tmp->owner              = owner;
	tmp->resolution         = NULL;
	tmp->requester_cb       = cb;
	tmp->requester_error_cb = err_cb;
	*req = tmp;
 end:
	return tmp;
}

/* Links a requester (a server or a resolv_srvrq) with a resolution. It returns 0
 * on success, -1 otherwise.
 */
int resolv_link_resolution(void *requester, int requester_type, int requester_locked)
{
	struct resolv_resolution *res = NULL;
	struct resolv_requester  *req;
	struct resolvers  *resolvers;
	struct server         *srv   = NULL;
	struct resolv_srvrq      *srvrq = NULL;
	struct stream         *stream = NULL;
	char **hostname_dn;
	int   hostname_dn_len, query_type;

	enter_resolver_code();
	switch (requester_type) {
		case OBJ_TYPE_SERVER:
			srv             = (struct server *)requester;

			if (!requester_locked)
				HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);

			req = resolv_get_requester(&srv->resolv_requester,
			                           &srv->obj_type,
				                   snr_resolution_cb,
				                   snr_resolution_error_cb);

			if (!requester_locked)
				HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);

			if (!req)
				goto err;

			hostname_dn     = &srv->hostname_dn;
			hostname_dn_len = srv->hostname_dn_len;
			resolvers       = srv->resolvers;
			query_type      = ((srv->resolv_opts.family_prio == AF_INET)
					   ? DNS_RTYPE_A
					   : DNS_RTYPE_AAAA);
			break;

		case OBJ_TYPE_SRVRQ:
			srvrq           = (struct resolv_srvrq *)requester;

			req = resolv_get_requester(&srvrq->requester,
			                           &srvrq->obj_type,
			                           snr_resolution_cb,
			                           srvrq_resolution_error_cb);
			if (!req)
				goto err;

			hostname_dn     = &srvrq->hostname_dn;
			hostname_dn_len = srvrq->hostname_dn_len;
			resolvers       = srvrq->resolvers;
			query_type      = DNS_RTYPE_SRV;
			break;

		case OBJ_TYPE_STREAM:
			stream          = (struct stream *)requester;

			req = resolv_get_requester(&stream->resolv_ctx.requester,
			                           &stream->obj_type,
			                           act_resolution_cb,
			                           act_resolution_error_cb);
			if (!req)
				goto err;

			hostname_dn     = &stream->resolv_ctx.hostname_dn;
			hostname_dn_len = stream->resolv_ctx.hostname_dn_len;
			resolvers       = stream->resolv_ctx.parent->arg.resolv.resolvers;
			query_type      = ((stream->resolv_ctx.parent->arg.resolv.opts->family_prio == AF_INET)
					   ? DNS_RTYPE_A
					   : DNS_RTYPE_AAAA);
			break;
		default:
			goto err;
	}

	/* Get a resolution from the resolvers' wait queue or pool */
	if ((res = resolv_pick_resolution(resolvers, hostname_dn, hostname_dn_len, query_type)) == NULL)
		goto err;

	req->resolution = res;

	LIST_APPEND(&res->requesters, &req->list);
	leave_resolver_code();
	return 0;

  err:
	if (res && LIST_ISEMPTY(&res->requesters))
		resolv_free_resolution(res);
	leave_resolver_code();
	return -1;
}

/* This function removes all server/srvrq references on answer items. */
void resolv_detach_from_resolution_answer_items(struct resolv_resolution *res,  struct resolv_requester *req)
{
	struct eb32_node *eb32, *eb32_back;
	struct resolv_answer_item *item;
	struct server *srv, *srvback;
	struct resolv_srvrq    *srvrq;

	enter_resolver_code();
	if ((srv = objt_server(req->owner)) != NULL) {
		LIST_DEL_INIT(&srv->ip_rec_item);
	}
	else if ((srvrq = objt_resolv_srvrq(req->owner)) != NULL) {
		for (eb32 = eb32_first(&res->response.answer_tree);
		     eb32 && (eb32_back = eb32_next(eb32), 1);
		     eb32 = eb32_back) {
			item = eb32_entry(eb32, typeof(*item), link);
			if (item->type == DNS_RTYPE_SRV) {
				list_for_each_entry_safe(srv, srvback, &item->attached_servers, srv_rec_item) {
					if (srv->srvrq == srvrq)
						resolv_srvrq_cleanup_srv(srv);
				}
			}
		}
	}
	leave_resolver_code();
}

/* Removes a requester from a DNS resolution. It takes takes care of all the
 * consequences. It also cleans up some parameters from the requester.
 */
static void _resolv_unlink_resolution(struct resolv_requester *requester)
{
	struct resolv_resolution *res;
	struct resolv_requester  *req;

	/* Nothing to do */
	if (!requester || !requester->resolution)
		return;
	res = requester->resolution;

	/* Clean up the requester */
	LIST_DEL_INIT(&requester->list);
	requester->resolution = NULL;

	/* remove ref from the resolution answer item list to the requester */
	resolv_detach_from_resolution_answer_items(res,  requester);

	/* We need to find another requester linked on this resolution */
	if (!LIST_ISEMPTY(&res->requesters))
		req = LIST_NEXT(&res->requesters, struct resolv_requester *, list);
	else {
		abort_resolution(res);
		return;
	}

	/* Move hostname_dn related pointers to the next requester */
	switch (obj_type(req->owner)) {
		case OBJ_TYPE_SERVER:
			res->hostname_dn     = __objt_server(req->owner)->hostname_dn;
			res->hostname_dn_len = __objt_server(req->owner)->hostname_dn_len;
			break;
		case OBJ_TYPE_SRVRQ:
			res->hostname_dn     = __objt_resolv_srvrq(req->owner)->hostname_dn;
			res->hostname_dn_len = __objt_resolv_srvrq(req->owner)->hostname_dn_len;
			break;
		case OBJ_TYPE_STREAM:
			res->hostname_dn     = __objt_stream(req->owner)->resolv_ctx.hostname_dn;
			res->hostname_dn_len = __objt_stream(req->owner)->resolv_ctx.hostname_dn_len;
			break;
		default:
			res->hostname_dn     = NULL;
			res->hostname_dn_len = 0;
			break;
	}
}

/* The public version of the function above that deals with the death row. */
void resolv_unlink_resolution(struct resolv_requester *requester)
{
	enter_resolver_code();
	_resolv_unlink_resolution(requester);
	leave_resolver_code();
}

/* Called when a network IO is generated on a name server socket for an incoming
 * packet. It performs the following actions:
 *  - check if the packet requires processing (not outdated resolution)
 *  - ensure the DNS packet received is valid and call requester's callback
 *  - call requester's error callback if invalid response
 *  - check the dn_name in the packet against the one sent
 */
static int resolv_process_responses(struct dns_nameserver *ns)
{
	struct dns_counters   *tmpcounters;
	struct resolvers  *resolvers;
	struct resolv_resolution *res;
	unsigned char  buf[DNS_MAX_UDP_MESSAGE + 1];
	unsigned char *bufend;
	int buflen, dns_resp;
	int max_answer_records;
	unsigned short query_id;
	struct eb32_node *eb;
	struct resolv_requester *req;
	int keep_answer_items;

	resolvers = ns->parent;
	enter_resolver_code();
	HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);

	/* process all pending input messages */
	while (1) {
		/* read message received */
		memset(buf, '\0', resolvers->accepted_payload_size + 1);
		if ((buflen = dns_recv_nameserver(ns, (void *)buf, sizeof(buf))) <= 0) {
			break;
		}

		/* message too big */
		if (buflen > resolvers->accepted_payload_size) {
			ns->counters->app.resolver.too_big++;
			continue;
		}

		/* initializing variables */
		bufend = buf + buflen;	/* pointer to mark the end of the buffer */

		/* read the query id from the packet (16 bits) */
		if (buf + 2 > bufend) {
			ns->counters->app.resolver.invalid++;
			continue;
		}
		query_id = resolv_response_get_query_id(buf);

		/* search the query_id in the pending resolution tree */
		eb = eb32_lookup(&resolvers->query_ids, query_id);
		if (eb == NULL) {
			/* unknown query id means an outdated response and can be safely ignored */
			ns->counters->app.resolver.outdated++;
			continue;
		}

		/* known query id means a resolution in progress */
		res = eb32_entry(eb, struct resolv_resolution, qid);
		/* number of responses received */
		res->nb_responses++;

		max_answer_records = (resolvers->accepted_payload_size - DNS_HEADER_SIZE) / DNS_MIN_RECORD_SIZE;
		dns_resp = resolv_validate_dns_response(buf, bufend, res, max_answer_records);

		switch (dns_resp) {
			case RSLV_RESP_VALID:
				break;

			case RSLV_RESP_INVALID:
			case RSLV_RESP_QUERY_COUNT_ERROR:
			case RSLV_RESP_WRONG_NAME:
				res->status = RSLV_STATUS_INVALID;
				ns->counters->app.resolver.invalid++;
				break;

			case RSLV_RESP_NX_DOMAIN:
				res->status = RSLV_STATUS_NX;
				ns->counters->app.resolver.nx++;
				break;

			case RSLV_RESP_REFUSED:
				res->status = RSLV_STATUS_REFUSED;
				ns->counters->app.resolver.refused++;
				break;

			case RSLV_RESP_ANCOUNT_ZERO:
				res->status = RSLV_STATUS_OTHER;
				ns->counters->app.resolver.any_err++;
				break;

			case RSLV_RESP_CNAME_ERROR:
				res->status = RSLV_STATUS_OTHER;
				ns->counters->app.resolver.cname_error++;
				break;

			case RSLV_RESP_TRUNCATED:
				res->status = RSLV_STATUS_OTHER;
				ns->counters->app.resolver.truncated++;
				break;

			case RSLV_RESP_NO_EXPECTED_RECORD:
			case RSLV_RESP_ERROR:
			case RSLV_RESP_INTERNAL:
				res->status = RSLV_STATUS_OTHER;
				ns->counters->app.resolver.other++;
				break;
		}

		/* Wait all nameservers response to handle errors */
		if (dns_resp != RSLV_RESP_VALID && res->nb_responses < res->nb_queries)
			continue;

		/* Process error codes */
		if (dns_resp != RSLV_RESP_VALID)  {
			if (res->prefered_query_type != res->query_type) {
				/* The fallback on the query type was already performed,
				 * so check the try counter. If it falls to 0, we can
				 * report an error. Else, wait the next attempt. */
				if (!res->try)
					goto report_res_error;
			}
			else {
				/* Fallback from A to AAAA or the opposite and re-send
				 * the resolution immediately. try counter is not
				 * decremented. */
				if (res->prefered_query_type == DNS_RTYPE_A) {
					res->query_type = DNS_RTYPE_AAAA;
					resolv_send_query(res);
				}
				else if (res->prefered_query_type == DNS_RTYPE_AAAA) {
					res->query_type = DNS_RTYPE_A;
					resolv_send_query(res);
				}
			}
			continue;
		}

		/* So the resolution succeeded */
		res->status     = RSLV_STATUS_VALID;
		res->last_valid = now_ms;
		ns->counters->app.resolver.valid++;
		goto report_res_success;

	report_res_error:
		keep_answer_items = 0;
		list_for_each_entry(req, &res->requesters, list)
			keep_answer_items |= req->requester_error_cb(req, dns_resp);
		if (!keep_answer_items)
			resolv_purge_resolution_answer_records(res);
		resolv_reset_resolution(res);
		LIST_DEL_INIT(&res->list);
		LIST_APPEND(&resolvers->resolutions.wait, &res->list);
		continue;

	report_res_success:
		/* Only the 1rst requester s managed by the server, others are
		 * from the cache */
		tmpcounters = ns->counters;
		list_for_each_entry(req, &res->requesters, list) {
			struct server *s = objt_server(req->owner);

			if (s)
				HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
			req->requester_cb(req, tmpcounters);
			if (s)
				HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
			tmpcounters = NULL;
		}

		resolv_reset_resolution(res);
		LIST_DEL_INIT(&res->list);
		LIST_APPEND(&resolvers->resolutions.wait, &res->list);
		continue;
	}
	resolv_update_resolvers_timeout(resolvers);
	HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
	leave_resolver_code();
	return buflen;
}

/* Processes DNS resolution. First, it checks the active list to detect expired
 * resolutions and retry them if possible. Else a timeout is reported. Then, it
 * checks the wait list to trigger new resolutions.
 */
static struct task *process_resolvers(struct task *t, void *context, unsigned int state)
{
	struct resolvers  *resolvers = context;
	struct resolv_resolution *res, *resback;
	int exp;

	enter_resolver_code();
	HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);

	/* Handle all expired resolutions from the active list. Elements that
	 * need to be removed will in fact be moved to the death_row. Other
	 * ones will be handled normally.
	 */

	res  = LIST_NEXT(&resolvers->resolutions.curr, struct resolv_resolution *, list);
	while (&res->list != &resolvers->resolutions.curr) {
		resback = LIST_NEXT(&res->list, struct resolv_resolution *, list);

		if (LIST_ISEMPTY(&res->requesters)) {
			abort_resolution(res);
			res = resback;
			continue;
		}

		/* When we find the first resolution in the future, then we can
		 * stop here */
		exp = tick_add(res->last_query, resolvers->timeout.retry);
		if (!tick_is_expired(exp, now_ms))
			break;

		/* If current resolution has been tried too many times and
		 * finishes in timeout we update its status and remove it from
		 * the list */
		if (!res->try) {
			struct resolv_requester *req;
			int keep_answer_items = 0;

			/* Notify the result to the requesters */
			if (!res->nb_responses)
				res->status = RSLV_STATUS_TIMEOUT;
			list_for_each_entry(req, &res->requesters, list)
				keep_answer_items |= req->requester_error_cb(req, res->status);
			if (!keep_answer_items)
				resolv_purge_resolution_answer_records(res);

			/* Clean up resolution info and remove it from the
			 * current list */
			resolv_reset_resolution(res);

			/* subsequent entries might have been deleted here */
			resback = LIST_NEXT(&res->list, struct resolv_resolution *, list);
			LIST_DEL_INIT(&res->list);
			LIST_APPEND(&resolvers->resolutions.wait, &res->list);
			res = resback;
		}
		else {
			/* Otherwise resend the DNS query and requeue the resolution */
			if (!res->nb_responses || res->prefered_query_type != res->query_type) {
				/* No response received (a real timeout) or fallback already done */
				res->query_type = res->prefered_query_type;
				res->try--;
			}
			else {
				/* Fallback from A to AAAA or the opposite and re-send
				 * the resolution immediately. try counter is not
				 * decremented. */
				if (res->prefered_query_type == DNS_RTYPE_A)
					res->query_type = DNS_RTYPE_AAAA;
				else if (res->prefered_query_type == DNS_RTYPE_AAAA)
					res->query_type = DNS_RTYPE_A;
				else
					res->try--;
			}
			resolv_send_query(res);
			resback = LIST_NEXT(&res->list, struct resolv_resolution *, list);
			res = resback;
		}
	}

	/* Handle all resolutions in the wait list */
	list_for_each_entry_safe(res, resback, &resolvers->resolutions.wait, list) {
		if (LIST_ISEMPTY(&res->requesters)) {
			abort_resolution(res);
			continue;
		}

		exp = tick_add(res->last_resolution, resolv_resolution_timeout(res));
		if (tick_isset(res->last_resolution) && !tick_is_expired(exp, now_ms))
			continue;

		if (resolv_run_resolution(res) != 1) {
			res->last_resolution = now_ms;
			LIST_DEL_INIT(&res->list);
			LIST_APPEND(&resolvers->resolutions.wait, &res->list);
		}
	}
	resolv_update_resolvers_timeout(resolvers);
	HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);

	/* now we can purge all queued deletions */
	leave_resolver_code();
	return t;
}

/* Release memory allocated by DNS */
static void resolvers_deinit(void)
{
	struct resolvers  *resolvers, *resolversback;
	struct dns_nameserver *ns, *nsback;
	struct resolv_resolution *res, *resback;
	struct resolv_requester  *req, *reqback;
	struct resolv_srvrq    *srvrq, *srvrqback;

	enter_resolver_code();
	list_for_each_entry_safe(resolvers, resolversback, &sec_resolvers, list) {
		list_for_each_entry_safe(ns, nsback, &resolvers->nameservers, list) {
			free(ns->id);
			free((char *)ns->conf.file);
			if (ns->dgram) {
				if (ns->dgram->conn.t.sock.fd != -1) {
					fd_delete(ns->dgram->conn.t.sock.fd);
					close(ns->dgram->conn.t.sock.fd);
				}
				if (ns->dgram->ring_req)
					ring_free(ns->dgram->ring_req);
				free(ns->dgram);
			}
			if (ns->stream) {
				if (ns->stream->ring_req)
					ring_free(ns->stream->ring_req);
				if (ns->stream->task_req)
					task_destroy(ns->stream->task_req);
				if (ns->stream->task_rsp)
					task_destroy(ns->stream->task_rsp);
				free(ns->stream);
			}
			LIST_DEL_INIT(&ns->list);
			EXTRA_COUNTERS_FREE(ns->extra_counters);
			free(ns);
		}

		list_for_each_entry_safe(res, resback, &resolvers->resolutions.curr, list) {
			list_for_each_entry_safe(req, reqback, &res->requesters, list) {
				LIST_DEL_INIT(&req->list);
				pool_free(resolv_requester_pool, req);
			}
			abort_resolution(res);
		}

		list_for_each_entry_safe(res, resback, &resolvers->resolutions.wait, list) {
			list_for_each_entry_safe(req, reqback, &res->requesters, list) {
				LIST_DEL_INIT(&req->list);
				pool_free(resolv_requester_pool, req);
			}
			abort_resolution(res);
		}

		free(resolvers->id);
		free((char *)resolvers->conf.file);
		task_destroy(resolvers->t);
		LIST_DEL_INIT(&resolvers->list);
		free(resolvers);
	}

	list_for_each_entry_safe(srvrq, srvrqback, &resolv_srvrq_list, list) {
		free(srvrq->name);
		free(srvrq->hostname_dn);
		LIST_DEL_INIT(&srvrq->list);
		free(srvrq);
	}

	leave_resolver_code();
}

/* Finalizes the DNS configuration by allocating required resources and checking
 * live parameters.
 * Returns 0 on success, ERR_* flags otherwise.
 */
static int resolvers_finalize_config(void)
{
	struct resolvers *resolvers;
	struct proxy	     *px;
	int err_code = 0;

	enter_resolver_code();

	/* allocate pool of resolution per resolvers */
	list_for_each_entry(resolvers, &sec_resolvers, list) {
		struct dns_nameserver *ns;
		struct task           *t;

		/* Check if we can create the socket with nameservers info */
		list_for_each_entry(ns, &resolvers->nameservers, list) {
			int fd;

			if (ns->dgram) {
				/* Check nameserver info */
				if ((fd = socket(ns->dgram->conn.addr.to.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
					ha_alert("resolvers '%s': can't create socket for nameserver '%s'.\n",
						 resolvers->id, ns->id);
					err_code |= (ERR_ALERT|ERR_ABORT);
					continue;
				}
				if (connect(fd, (struct sockaddr*)&ns->dgram->conn.addr.to, get_addr_len(&ns->dgram->conn.addr.to)) == -1) {
					ha_alert("resolvers '%s': can't connect socket for nameserver '%s'.\n",
						 resolvers->id, ns->id);
					close(fd);
					err_code |= (ERR_ALERT|ERR_ABORT);
					continue;
				}
				close(fd);
			}
		}

		/* Create the task associated to the resolvers section */
		if ((t = task_new_anywhere()) == NULL) {
			ha_alert("resolvers '%s' : out of memory.\n", resolvers->id);
			err_code |= (ERR_ALERT|ERR_ABORT);
			goto err;
		}

		/* Update task's parameters */
		t->process   = process_resolvers;
		t->context   = resolvers;
		resolvers->t = t;
		task_wakeup(t, TASK_WOKEN_INIT);
	}

	for (px = proxies_list; px; px = px->next) {
		struct server *srv;

		for (srv = px->srv; srv; srv = srv->next) {
			struct resolvers *resolvers;

			if (!srv->resolvers_id)
				continue;

			if ((resolvers = find_resolvers_by_id(srv->resolvers_id)) == NULL) {
				ha_alert("%s '%s', server '%s': unable to find required resolvers '%s'\n",
					 proxy_type_str(px), px->id, srv->id, srv->resolvers_id);
				err_code |= (ERR_ALERT|ERR_ABORT);
				continue;
			}
			srv->resolvers = resolvers;
			srv->srvrq_check = NULL;
			if (srv->srvrq) {
				if (!srv->srvrq->resolvers) {
					srv->srvrq->resolvers = srv->resolvers;
					if (resolv_link_resolution(srv->srvrq, OBJ_TYPE_SRVRQ, 0) == -1) {
						ha_alert("%s '%s' : unable to set DNS resolution for server '%s'.\n",
							 proxy_type_str(px), px->id, srv->id);
						err_code |= (ERR_ALERT|ERR_ABORT);
						continue;
					}
				}

				srv->srvrq_check = task_new_anywhere();
				if (!srv->srvrq_check) {
					ha_alert("%s '%s' : unable to create SRVRQ task for server '%s'.\n",
						 proxy_type_str(px), px->id, srv->id);
					err_code |= (ERR_ALERT|ERR_ABORT);
					goto err;
				}
				srv->srvrq_check->process = resolv_srvrq_expire_task;
				srv->srvrq_check->context = srv;
				srv->srvrq_check->expire = TICK_ETERNITY;
			}
			else if (resolv_link_resolution(srv, OBJ_TYPE_SERVER, 0) == -1) {
				ha_alert("%s '%s', unable to set DNS resolution for server '%s'.\n",
					 proxy_type_str(px), px->id, srv->id);
				err_code |= (ERR_ALERT|ERR_ABORT);
				continue;
			}

			srv->flags |= SRV_F_NON_PURGEABLE;
		}
	}

	if (err_code & (ERR_ALERT|ERR_ABORT))
		goto err;

	leave_resolver_code();
	return err_code;
  err:
	leave_resolver_code();
	resolvers_deinit();
	return err_code;

}

static int stats_dump_resolv_to_buffer(struct stream_interface *si,
                                    struct dns_nameserver *ns,
                                    struct field *stats, size_t stats_count,
                                    struct list *stat_modules)
{
	struct appctx *appctx = __objt_appctx(si->end);
	struct channel *rep = si_ic(si);
	struct stats_module *mod;
	size_t idx = 0;

	memset(stats, 0, sizeof(struct field) * stats_count);

	list_for_each_entry(mod, stat_modules, list) {
		struct counters_node *counters = EXTRA_COUNTERS_GET(ns->extra_counters, mod);

		mod->fill_stats(counters, stats + idx);
		idx += mod->stats_count;
	}

	if (!stats_dump_one_line(stats, idx, appctx))
		return 0;

	if (!stats_putchk(rep, NULL, &trash))
		goto full;

	return 1;

  full:
	si_rx_room_rdy(si);
	return 0;
}

/* Uses <appctx.ctx.stats.obj1> as a pointer to the current resolver and <obj2>
 * as a pointer to the current nameserver.
 */
int stats_dump_resolvers(struct stream_interface *si,
                         struct field *stats, size_t stats_count,
                         struct list *stat_modules)
{
	struct appctx *appctx = __objt_appctx(si->end);
	struct channel *rep = si_ic(si);
	struct resolvers *resolver = appctx->ctx.stats.obj1;
	struct dns_nameserver *ns = appctx->ctx.stats.obj2;

	if (!resolver)
		resolver = LIST_NEXT(&sec_resolvers, struct resolvers *, list);

	/* dump resolvers */
	list_for_each_entry_from(resolver, &sec_resolvers, list) {
		appctx->ctx.stats.obj1 = resolver;

		ns = appctx->ctx.stats.obj2 ?
		     appctx->ctx.stats.obj2 :
		     LIST_NEXT(&resolver->nameservers, struct dns_nameserver *, list);

		list_for_each_entry_from(ns, &resolver->nameservers, list) {
			appctx->ctx.stats.obj2 = ns;

			if (buffer_almost_full(&rep->buf))
				goto full;

			if (!stats_dump_resolv_to_buffer(si, ns,
			                                 stats, stats_count,
			                                 stat_modules)) {
				return 0;
			}
		}

		appctx->ctx.stats.obj2 = NULL;
	}

	return 1;

  full:
	si_rx_room_blk(si);
	return 0;
}

void resolv_stats_clear_counters(int clrall, struct list *stat_modules)
{
	struct resolvers  *resolvers;
	struct dns_nameserver *ns;
	struct stats_module *mod;
	void *counters;

	list_for_each_entry(mod, stat_modules, list) {
		if (!mod->clearable && !clrall)
			continue;

		list_for_each_entry(resolvers, &sec_resolvers, list) {
			list_for_each_entry(ns, &resolvers->nameservers, list) {
				counters = EXTRA_COUNTERS_GET(ns->extra_counters, mod);
				memcpy(counters, mod->counters, mod->counters_size);
			}
		}
	}

}

int resolv_allocate_counters(struct list *stat_modules)
{
	struct stats_module *mod;
	struct resolvers *resolvers;
	struct dns_nameserver *ns;

	list_for_each_entry(resolvers, &sec_resolvers, list) {
		list_for_each_entry(ns, &resolvers->nameservers, list) {
			EXTRA_COUNTERS_REGISTER(&ns->extra_counters, COUNTERS_RSLV,
			                        alloc_failed);

			list_for_each_entry(mod, stat_modules, list) {
				EXTRA_COUNTERS_ADD(mod,
				                   ns->extra_counters,
				                   mod->counters,
				                   mod->counters_size);
			}

			EXTRA_COUNTERS_ALLOC(ns->extra_counters, alloc_failed);

			list_for_each_entry(mod, stat_modules, list) {
				memcpy(ns->extra_counters->data + mod->counters_off[ns->extra_counters->type],
				       mod->counters, mod->counters_size);

				/* Store the ns counters pointer */
				if (strcmp(mod->name, "resolvers") == 0) {
					ns->counters = (struct dns_counters *)ns->extra_counters->data + mod->counters_off[COUNTERS_RSLV];
					ns->counters->id = ns->id;
					ns->counters->pid = resolvers->id;
				}
			}
		}
	}

	return 1;

alloc_failed:
	return 0;
}

/* if an arg is found, it sets the resolvers section pointer into cli.p0 */
static int cli_parse_stat_resolvers(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct resolvers *presolvers;

	if (*args[2]) {
		list_for_each_entry(presolvers, &sec_resolvers, list) {
			if (strcmp(presolvers->id, args[2]) == 0) {
				appctx->ctx.cli.p0 = presolvers;
				break;
			}
		}
		if (appctx->ctx.cli.p0 == NULL)
			return cli_err(appctx, "Can't find that resolvers section\n");
	}
	return 0;
}

/* Dumps counters from all resolvers section and associated name servers. It
 * returns 0 if the output buffer is full and it needs to be called again,
 * otherwise non-zero. It may limit itself to the resolver pointed to by
 * <cli.p0> if it's not null.
 */
static int cli_io_handler_dump_resolvers_to_buffer(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct resolvers    *resolvers;
	struct dns_nameserver   *ns;

	chunk_reset(&trash);

	switch (appctx->st2) {
	case STAT_ST_INIT:
		appctx->st2 = STAT_ST_LIST; /* let's start producing data */
		/* fall through */

	case STAT_ST_LIST:
		if (LIST_ISEMPTY(&sec_resolvers)) {
			chunk_appendf(&trash, "No resolvers found\n");
		}
		else {
			list_for_each_entry(resolvers, &sec_resolvers, list) {
				if (appctx->ctx.cli.p0 != NULL && appctx->ctx.cli.p0 != resolvers)
					continue;

				chunk_appendf(&trash, "Resolvers section %s\n", resolvers->id);
				list_for_each_entry(ns, &resolvers->nameservers, list) {
					chunk_appendf(&trash, " nameserver %s:\n", ns->id);
					chunk_appendf(&trash, "  sent:        %lld\n", ns->counters->sent);
					chunk_appendf(&trash, "  snd_error:   %lld\n", ns->counters->snd_error);
					chunk_appendf(&trash, "  valid:       %lld\n", ns->counters->app.resolver.valid);
					chunk_appendf(&trash, "  update:      %lld\n", ns->counters->app.resolver.update);
					chunk_appendf(&trash, "  cname:       %lld\n", ns->counters->app.resolver.cname);
					chunk_appendf(&trash, "  cname_error: %lld\n", ns->counters->app.resolver.cname_error);
					chunk_appendf(&trash, "  any_err:     %lld\n", ns->counters->app.resolver.any_err);
					chunk_appendf(&trash, "  nx:          %lld\n", ns->counters->app.resolver.nx);
					chunk_appendf(&trash, "  timeout:     %lld\n", ns->counters->app.resolver.timeout);
					chunk_appendf(&trash, "  refused:     %lld\n", ns->counters->app.resolver.refused);
					chunk_appendf(&trash, "  other:       %lld\n", ns->counters->app.resolver.other);
					chunk_appendf(&trash, "  invalid:     %lld\n", ns->counters->app.resolver.invalid);
					chunk_appendf(&trash, "  too_big:     %lld\n", ns->counters->app.resolver.too_big);
					chunk_appendf(&trash, "  truncated:   %lld\n", ns->counters->app.resolver.truncated);
					chunk_appendf(&trash, "  outdated:    %lld\n",  ns->counters->app.resolver.outdated);
				}
				chunk_appendf(&trash, "\n");
			}
		}

		/* display response */
		if (ci_putchk(si_ic(si), &trash) == -1) {
			/* let's try again later from this session. We add ourselves into
			 * this session's users so that it can remove us upon termination.
			 */
			si_rx_room_blk(si);
			return 0;
		}
		/* fall through */

	default:
		appctx->st2 = STAT_ST_FIN;
		return 1;
	}
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ }, {
		{ { "show", "resolvers", NULL }, "show resolvers [id]                     : dumps counters from all resolvers section and associated name servers",
		  cli_parse_stat_resolvers, cli_io_handler_dump_resolvers_to_buffer },
		{{},}
	}
};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/*
 * Prepare <rule> for hostname resolution.
 * Returns -1 in case of any allocation failure, 0 if not.
 * On error, a global failure counter is also incremented.
 */
static int action_prepare_for_resolution(struct stream *stream, const char *hostname, int hostname_len)
{
	char *hostname_dn;
	int   hostname_dn_len;
	struct buffer *tmp = get_trash_chunk();

	if (!hostname)
		return 0;

	hostname_dn     = tmp->area;
	hostname_dn_len = resolv_str_to_dn_label(hostname, hostname_len,
	                                         hostname_dn, tmp->size);
	if (hostname_dn_len == -1)
		goto err;


	stream->resolv_ctx.hostname_dn     = strdup(hostname_dn);
	stream->resolv_ctx.hostname_dn_len = hostname_dn_len;
	if (!stream->resolv_ctx.hostname_dn)
		goto err;

	return 0;

 err:
	ha_free(&stream->resolv_ctx.hostname_dn);
	resolv_failed_resolutions += 1;
	return -1;
}


/*
 * Execute the "do-resolution" action. May be called from {tcp,http}request.
 */
enum act_return resolv_action_do_resolve(struct act_rule *rule, struct proxy *px,
					      struct session *sess, struct stream *s, int flags)
{
	struct resolv_resolution *resolution;
	struct sample *smp;
	struct resolv_requester *req;
	struct resolvers  *resolvers;
	struct resolv_resolution *res;
	int exp, locked = 0;
	enum act_return ret = ACT_RET_CONT;

	resolvers = rule->arg.resolv.resolvers;

	enter_resolver_code();

	/* we have a response to our DNS resolution */
 use_cache:
	if (s->resolv_ctx.requester && s->resolv_ctx.requester->resolution != NULL) {
		resolution = s->resolv_ctx.requester->resolution;
		if (!locked) {
			HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);
			locked = 1;
		}

		if (resolution->step == RSLV_STEP_RUNNING)
			goto yield;
		if (resolution->step == RSLV_STEP_NONE) {
			/* We update the variable only if we have a valid response. */
			if (resolution->status == RSLV_STATUS_VALID) {
				struct sample smp;
				short ip_sin_family = 0;
				void *ip = NULL;

				resolv_get_ip_from_response(&resolution->response, rule->arg.resolv.opts, NULL,
							 0, &ip, &ip_sin_family, NULL);

				switch (ip_sin_family) {
				case AF_INET:
					smp.data.type = SMP_T_IPV4;
					memcpy(&smp.data.u.ipv4, ip, 4);
					break;
				case AF_INET6:
					smp.data.type = SMP_T_IPV6;
					memcpy(&smp.data.u.ipv6, ip, 16);
					break;
				default:
					ip = NULL;
				}

				if (ip) {
					smp.px = px;
					smp.sess = sess;
					smp.strm = s;

					vars_set_by_name(rule->arg.resolv.varname, strlen(rule->arg.resolv.varname), &smp);
				}
			}
		}

		goto release_requester;
	}

	/* need to configure and start a new DNS resolution */
	smp = sample_fetch_as_type(px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL, rule->arg.resolv.expr, SMP_T_STR);
	if (smp == NULL)
		goto end;

	if (action_prepare_for_resolution(s, smp->data.u.str.area, smp->data.u.str.data) == -1)
		goto end; /* on error, ignore the action */

	s->resolv_ctx.parent = rule;

	HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);
	locked = 1;

	resolv_link_resolution(s, OBJ_TYPE_STREAM, 0);

	/* Check if there is a fresh enough response in the cache of our associated resolution */
	req = s->resolv_ctx.requester;
	if (!req || !req->resolution)
		goto release_requester; /* on error, ignore the action */
	res = req->resolution;

	exp = tick_add(res->last_resolution, resolvers->hold.valid);
	if (resolvers->t && res->status == RSLV_STATUS_VALID && tick_isset(res->last_resolution)
	    && !tick_is_expired(exp, now_ms)) {
		goto use_cache;
	}

	resolv_trigger_resolution(s->resolv_ctx.requester);

  yield:
	if (flags & ACT_OPT_FINAL)
		goto release_requester;
	ret = ACT_RET_YIELD;

  end:
	leave_resolver_code();
	if (locked)
		HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
	return ret;

  release_requester:
	ha_free(&s->resolv_ctx.hostname_dn);
	s->resolv_ctx.hostname_dn_len = 0;
	if (s->resolv_ctx.requester) {
		_resolv_unlink_resolution(s->resolv_ctx.requester);
		pool_free(resolv_requester_pool, s->resolv_ctx.requester);
		s->resolv_ctx.requester = NULL;
	}
	goto end;
}

static void release_resolv_action(struct act_rule *rule)
{
	release_sample_expr(rule->arg.resolv.expr);
	free(rule->arg.resolv.varname);
	free(rule->arg.resolv.resolvers_id);
	free(rule->arg.resolv.opts);
}


/* parse "do-resolve" action
 * This action takes the following arguments:
 *   do-resolve(<varName>,<resolversSectionName>,<resolvePrefer>) <expr>
 *
 *   - <varName> is the variable name where the result of the DNS resolution will be stored
 *     (mandatory)
 *   - <resolversSectionName> is the name of the resolvers section to use to perform the resolution
 *     (mandatory)
 *   - <resolvePrefer> can be either 'ipv4' or 'ipv6' and is the IP family we would like to resolve first
 *     (optional), defaults to ipv6
 *   - <expr> is an HAProxy expression used to fetch the name to be resolved
 */
enum act_parse_ret resolv_parse_do_resolve(const char **args, int *orig_arg, struct proxy *px, struct act_rule *rule, char **err)
{
	int cur_arg;
	struct sample_expr *expr;
	unsigned int where;
	const char *beg, *end;

	/* orig_arg points to the first argument, but we need to analyse the command itself first */
	cur_arg = *orig_arg - 1;

	/* locate varName, which is mandatory */
	beg = strchr(args[cur_arg], '(');
	if (beg == NULL)
		goto do_resolve_parse_error;
	beg = beg + 1; /* beg should points to the first character after opening parenthesis '(' */
	end = strchr(beg, ',');
	if (end == NULL)
		goto do_resolve_parse_error;
	rule->arg.resolv.varname = my_strndup(beg, end - beg);
	if (rule->arg.resolv.varname == NULL)
		goto do_resolve_parse_error;


	/* locate resolversSectionName, which is mandatory.
	 * Since next parameters are optional, the delimiter may be comma ','
	 * or closing parenthesis ')'
	 */
	beg = end + 1;
	end = strchr(beg, ',');
	if (end == NULL)
		end = strchr(beg, ')');
	if (end == NULL)
		goto do_resolve_parse_error;
	rule->arg.resolv.resolvers_id = my_strndup(beg, end - beg);
	if (rule->arg.resolv.resolvers_id == NULL)
		goto do_resolve_parse_error;


	rule->arg.resolv.opts = calloc(1, sizeof(*rule->arg.resolv.opts));
	if (rule->arg.resolv.opts == NULL)
		goto do_resolve_parse_error;

	/* Default priority is ipv6 */
	rule->arg.resolv.opts->family_prio = AF_INET6;

	/* optional arguments accepted for now:
	 *  ipv4 or ipv6
	 */
	while (*end != ')') {
		beg = end + 1;
		end = strchr(beg, ',');
		if (end == NULL)
			end = strchr(beg, ')');
		if (end == NULL)
			goto do_resolve_parse_error;

		if (strncmp(beg, "ipv4", end - beg) == 0) {
			rule->arg.resolv.opts->family_prio = AF_INET;
		}
		else if (strncmp(beg, "ipv6", end - beg) == 0) {
			rule->arg.resolv.opts->family_prio = AF_INET6;
		}
		else {
			goto do_resolve_parse_error;
		}
	}

	cur_arg = cur_arg + 1;

	expr = sample_parse_expr((char **)args, &cur_arg, px->conf.args.file, px->conf.args.line, err, &px->conf.args, NULL);
	if (!expr)
		goto do_resolve_parse_error;


	where = 0;
	if (px->cap & PR_CAP_FE)
		where |= SMP_VAL_FE_HRQ_HDR;
	if (px->cap & PR_CAP_BE)
		where |= SMP_VAL_BE_HRQ_HDR;

	if (!(expr->fetch->val & where)) {
		memprintf(err,
			  "fetch method '%s' extracts information from '%s', none of which is available here",
			  args[cur_arg-1], sample_src_names(expr->fetch->use));
		free(expr);
		return ACT_RET_PRS_ERR;
	}
	rule->arg.resolv.expr = expr;
	rule->action = ACT_CUSTOM;
	rule->action_ptr = resolv_action_do_resolve;
	*orig_arg = cur_arg;

	rule->check_ptr = check_action_do_resolve;
	rule->release_ptr = release_resolv_action;

	return ACT_RET_PRS_OK;

 do_resolve_parse_error:
	ha_free(&rule->arg.resolv.varname);
	ha_free(&rule->arg.resolv.resolvers_id);
	memprintf(err, "Can't parse '%s'. Expects 'do-resolve(<varname>,<resolvers>[,<options>]) <expr>'. Available options are 'ipv4' and 'ipv6'",
			args[cur_arg]);
	return ACT_RET_PRS_ERR;
}

static struct action_kw_list http_req_kws = { { }, {
	{ "do-resolve", resolv_parse_do_resolve, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_kws);

static struct action_kw_list tcp_req_cont_actions = {ILH, {
	{ "do-resolve", resolv_parse_do_resolve, KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_cont_actions);

/* Check an "http-request do-resolve" action.
 *
 * The function returns 1 in success case, otherwise, it returns 0 and err is
 * filled.
 */
int check_action_do_resolve(struct act_rule *rule, struct proxy *px, char **err)
{
	struct resolvers *resolvers = NULL;

	if (rule->arg.resolv.resolvers_id == NULL) {
		memprintf(err,"Proxy '%s': %s", px->id, "do-resolve action without resolvers");
		return 0;
	}

	resolvers = find_resolvers_by_id(rule->arg.resolv.resolvers_id);
	if (resolvers == NULL) {
		memprintf(err,"Can't find resolvers section '%s' for do-resolve action", rule->arg.resolv.resolvers_id);
		return 0;
	}
	rule->arg.resolv.resolvers = resolvers;

	return 1;
}

void resolvers_setup_proxy(struct proxy *px)
{
	px->last_change = now.tv_sec;
	px->cap = PR_CAP_FE | PR_CAP_BE;
	px->maxconn = 0;
	px->conn_retries = 1;
	px->timeout.server = TICK_ETERNITY;
	px->timeout.client = TICK_ETERNITY;
	px->timeout.connect = TICK_ETERNITY;
	px->accept = NULL;
	px->options2 |= PR_O2_INDEPSTR | PR_O2_SMARTCON;
}

/*
 * Parse a <resolvers> section.
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cfg_parse_resolvers(const char *file, int linenum, char **args, int kwm)
{
	const char *err;
	int err_code = 0;
	char *errmsg = NULL;
	struct proxy *p;

	if (strcmp(args[0], "resolvers") == 0) { /* new resolvers section */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing name for resolvers section.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in '%s' name '%s'.\n",
				 file, linenum, *err, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		list_for_each_entry(curr_resolvers, &sec_resolvers, list) {
			/* Error if two resolvers owns the same name */
			if (strcmp(curr_resolvers->id, args[1]) == 0) {
				ha_alert("Parsing [%s:%d]: resolvers '%s' has same name as another resolvers (declared at %s:%d).\n",
					 file, linenum, args[1], curr_resolvers->conf.file, curr_resolvers->conf.line);
				err_code |= ERR_ALERT | ERR_ABORT;
			}
		}

		if ((curr_resolvers = calloc(1, sizeof(*curr_resolvers))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

                /* allocate new proxy to tcp servers */
                p = calloc(1, sizeof *p);
                if (!p) {
                        ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
                        err_code |= ERR_ALERT | ERR_FATAL;
                        goto out;
                }

                init_new_proxy(p);
                resolvers_setup_proxy(p);
                p->parent = curr_resolvers;
                p->id = strdup(args[1]);
                p->conf.args.file = p->conf.file = strdup(file);
                p->conf.args.line = p->conf.line = linenum;
                curr_resolvers->px = p;

		/* default values */
		LIST_APPEND(&sec_resolvers, &curr_resolvers->list);
		curr_resolvers->conf.file = strdup(file);
		curr_resolvers->conf.line = linenum;
		curr_resolvers->id = strdup(args[1]);
		curr_resolvers->query_ids = EB_ROOT;
		/* default maximum response size */
		curr_resolvers->accepted_payload_size = 512;
		/* default hold period for nx, other, refuse and timeout is 30s */
		curr_resolvers->hold.nx = 30000;
		curr_resolvers->hold.other = 30000;
		curr_resolvers->hold.refused = 30000;
		curr_resolvers->hold.timeout = 30000;
		curr_resolvers->hold.obsolete = 0;
		/* default hold period for valid is 10s */
		curr_resolvers->hold.valid = 10000;
		curr_resolvers->timeout.resolve = 1000;
		curr_resolvers->timeout.retry   = 1000;
		curr_resolvers->resolve_retries = 3;
		LIST_INIT(&curr_resolvers->nameservers);
		LIST_INIT(&curr_resolvers->resolutions.curr);
		LIST_INIT(&curr_resolvers->resolutions.wait);
		HA_SPIN_INIT(&curr_resolvers->lock);
	}
	else if (strcmp(args[0], "nameserver") == 0) { /* nameserver definition */
		struct dns_nameserver *newnameserver = NULL;
		struct sockaddr_storage *sk;
		int port1, port2;
		struct protocol *proto;

		if (!*args[2]) {
			ha_alert("parsing [%s:%d] : '%s' expects <name> and <addr>[:<port>] as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		err = invalid_char(args[1]);
		if (err) {
			ha_alert("parsing [%s:%d] : character '%c' is not permitted in server name '%s'.\n",
				 file, linenum, *err, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		list_for_each_entry(newnameserver, &curr_resolvers->nameservers, list) {
			/* Error if two resolvers owns the same name */
			if (strcmp(newnameserver->id, args[1]) == 0) {
				ha_alert("Parsing [%s:%d]: nameserver '%s' has same name as another nameserver (declared at %s:%d).\n",
					 file, linenum, args[1], newnameserver->conf.file, newnameserver->conf.line);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
		}

		sk = str2sa_range(args[2], NULL, &port1, &port2, NULL, &proto,
		                  &errmsg, NULL, NULL, PA_O_RESOLVE | PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_DGRAM | PA_O_STREAM | PA_O_DEFAULT_DGRAM);
		if (!sk) {
			ha_alert("parsing [%s:%d] : '%s %s' : %s\n", file, linenum, args[0], args[1], errmsg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if ((newnameserver = calloc(1, sizeof(*newnameserver))) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if (proto && proto->ctrl_type == SOCK_STREAM) {
			err_code |= parse_server(file, linenum, args, curr_resolvers->px, NULL,
			                         SRV_PARSE_PARSE_ADDR|SRV_PARSE_INITIAL_RESOLVE);
			if (err_code & (ERR_FATAL|ERR_ABORT)) {
				err_code |= ERR_ABORT;
				goto out;
			}

			if (dns_stream_init(newnameserver, curr_resolvers->px->srv) < 0) {
				ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
				err_code |= ERR_ALERT|ERR_ABORT;
				goto out;
			}
		}
		else if (dns_dgram_init(newnameserver, sk) < 0) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if ((newnameserver->conf.file = strdup(file)) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		if ((newnameserver->id = strdup(args[1])) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_ABORT;
			goto out;
		}

		newnameserver->parent = curr_resolvers;
		newnameserver->process_responses = resolv_process_responses;
		newnameserver->conf.line = linenum;
		/* the nameservers are linked backward first */
		LIST_APPEND(&curr_resolvers->nameservers, &newnameserver->list);
	}
	else if (strcmp(args[0], "parse-resolv-conf") == 0) {
		struct dns_nameserver *newnameserver = NULL;
		const char *whitespace = "\r\n\t ";
		char *resolv_line = NULL;
		int resolv_linenum = 0;
		FILE *f = NULL;
		char *address = NULL;
		struct sockaddr_storage *sk = NULL;
		struct protocol *proto;
		int duplicate_name = 0;

		if ((resolv_line = malloc(sizeof(*resolv_line) * LINESIZE)) == NULL) {
			ha_alert("parsing [%s:%d] : out of memory.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto resolv_out;
		}

		if ((f = fopen("/etc/resolv.conf", "r")) == NULL) {
			ha_alert("parsing [%s:%d] : failed to open /etc/resolv.conf.\n",
				 file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto resolv_out;
		}

		sk = calloc(1, sizeof(*sk));
		if (sk == NULL) {
			ha_alert("parsing [/etc/resolv.conf:%d] : out of memory.\n",
				 resolv_linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto resolv_out;
		}

		while (fgets(resolv_line, LINESIZE, f) != NULL) {
			resolv_linenum++;
			if (strncmp(resolv_line, "nameserver", 10) != 0)
				continue;

			address = strtok(resolv_line + 10, whitespace);
			if (address == resolv_line + 10)
				continue;

			if (address == NULL) {
				ha_warning("parsing [/etc/resolv.conf:%d] : nameserver line is missing address.\n",
					   resolv_linenum);
				err_code |= ERR_WARN;
				continue;
			}

			duplicate_name = 0;
			list_for_each_entry(newnameserver, &curr_resolvers->nameservers, list) {
				if (strcmp(newnameserver->id, address) == 0) {
					ha_warning("Parsing [/etc/resolv.conf:%d] : generated name for /etc/resolv.conf nameserver '%s' conflicts with another nameserver (declared at %s:%d), it appears to be a duplicate and will be excluded.\n",
						 resolv_linenum, address, newnameserver->conf.file, newnameserver->conf.line);
					err_code |= ERR_WARN;
					duplicate_name = 1;
				}
			}

			if (duplicate_name)
				continue;

			memset(sk, 0, sizeof(*sk));
			if (!str2ip2(address, sk, 1)) {
				ha_warning("parsing [/etc/resolv.conf:%d] : address '%s' could not be recognized, nameserver will be excluded.\n",
					   resolv_linenum, address);
				err_code |= ERR_WARN;
				continue;
			}

			set_host_port(sk, 53);

			proto = protocol_lookup(sk->ss_family, PROTO_TYPE_STREAM, 0);
			if (!proto || !proto->connect) {
				ha_warning("parsing [/etc/resolv.conf:%d] : '%s' : connect() not supported for this address family.\n",
					   resolv_linenum, address);
				err_code |= ERR_WARN;
				continue;
			}

			if ((newnameserver = calloc(1, sizeof(*newnameserver))) == NULL) {
				ha_alert("parsing [/etc/resolv.conf:%d] : out of memory.\n", resolv_linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto resolv_out;
			}

			if (dns_dgram_init(newnameserver, sk) < 0) {
				ha_alert("parsing [/etc/resolv.conf:%d] : out of memory.\n", resolv_linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(newnameserver);
				goto resolv_out;
			}

			newnameserver->conf.file = strdup("/etc/resolv.conf");
			if (newnameserver->conf.file == NULL) {
				ha_alert("parsing [/etc/resolv.conf:%d] : out of memory.\n", resolv_linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				free(newnameserver);
				goto resolv_out;
			}

			newnameserver->id = strdup(address);
			if (newnameserver->id == NULL) {
				ha_alert("parsing [/etc/resolv.conf:%d] : out of memory.\n", resolv_linenum);
				err_code |= ERR_ALERT | ERR_FATAL;
				free((char *)newnameserver->conf.file);
				free(newnameserver);
				goto resolv_out;
			}

			newnameserver->parent = curr_resolvers;
			newnameserver->process_responses = resolv_process_responses;
			newnameserver->conf.line = resolv_linenum;
			LIST_APPEND(&curr_resolvers->nameservers, &newnameserver->list);
		}

resolv_out:
		free(sk);
		free(resolv_line);
		if (f != NULL)
			fclose(f);
	}
	else if (strcmp(args[0], "hold") == 0) { /* hold periods */
		const char *res;
		unsigned int time;

		if (!*args[2]) {
			ha_alert("parsing [%s:%d] : '%s' expects an <event> and a <time> as arguments.\n",
				 file, linenum, args[0]);
			ha_alert("<event> can be either 'valid', 'nx', 'refused', 'timeout', or 'other'\n");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		res = parse_time_err(args[2], &time, TIME_UNIT_MS);
		if (res == PARSE_TIME_OVER) {
			ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s>, maximum value is 2147483647 ms (~24.8 days).\n",
			         file, linenum, args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (res == PARSE_TIME_UNDER) {
			ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s>, minimum non-null value is 1 ms.\n",
			         file, linenum, args[1], args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (res) {
			ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s>.\n",
				 file, linenum, *res, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		if (strcmp(args[1], "nx") == 0)
			curr_resolvers->hold.nx = time;
		else if (strcmp(args[1], "other") == 0)
			curr_resolvers->hold.other = time;
		else if (strcmp(args[1], "refused") == 0)
			curr_resolvers->hold.refused = time;
		else if (strcmp(args[1], "timeout") == 0)
			curr_resolvers->hold.timeout = time;
		else if (strcmp(args[1], "valid") == 0)
			curr_resolvers->hold.valid = time;
		else if (strcmp(args[1], "obsolete") == 0)
			curr_resolvers->hold.obsolete = time;
		else {
			ha_alert("parsing [%s:%d] : '%s' unknown <event>: '%s', expects either 'nx', 'timeout', 'valid', 'obsolete' or 'other'.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

	}
	else if (strcmp(args[0], "accepted_payload_size") == 0) {
		int i = 0;

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects <nb> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		i = atoi(args[1]);
		if (i < DNS_HEADER_SIZE || i > DNS_MAX_UDP_MESSAGE) {
			ha_alert("parsing [%s:%d] : '%s' must be between %d and %d inclusive (was %s).\n",
				 file, linenum, args[0], DNS_HEADER_SIZE, DNS_MAX_UDP_MESSAGE, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		curr_resolvers->accepted_payload_size = i;
	}
	else if (strcmp(args[0], "resolution_pool_size") == 0) {
		ha_alert("parsing [%s:%d] : '%s' directive is not supported anymore (it never appeared in a stable release).\n",
			   file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	else if (strcmp(args[0], "resolve_retries") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects <nb> as argument.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		curr_resolvers->resolve_retries = atoi(args[1]);
	}
	else if (strcmp(args[0], "timeout") == 0) {
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : '%s' expects 'retry' or 'resolve' and <time> as arguments.\n",
				 file, linenum, args[0]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		else if (strcmp(args[1], "retry") == 0 ||
			 strcmp(args[1], "resolve") == 0) {
			const char *res;
			unsigned int tout;

			if (!*args[2]) {
				ha_alert("parsing [%s:%d] : '%s %s' expects <time> as argument.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			res = parse_time_err(args[2], &tout, TIME_UNIT_MS);
			if (res == PARSE_TIME_OVER) {
				ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s %s>, maximum value is 2147483647 ms (~24.8 days).\n",
					 file, linenum, args[2], args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (res == PARSE_TIME_UNDER) {
				ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s %s>, minimum non-null value is 1 ms.\n",
					 file, linenum, args[2], args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (res) {
				ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s %s>.\n",
					 file, linenum, *res, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (args[1][2] == 't')
				curr_resolvers->timeout.retry = tout;
			else
				curr_resolvers->timeout.resolve = tout;
		}
		else {
			ha_alert("parsing [%s:%d] : '%s' expects 'retry' or 'resolve' and <time> as arguments got '%s'.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}
	else if (*args[0] != 0) {
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

 out:
	free(errmsg);
	return err_code;
}
int cfg_post_parse_resolvers()
{
	int err_code = 0;
	struct server *srv;

	if (curr_resolvers) {

		/* prepare forward server descriptors */
		if (curr_resolvers->px) {
			srv = curr_resolvers->px->srv;
			while (srv) {
				/* init ssl if needed */
				if (srv->use_ssl == 1 && xprt_get(XPRT_SSL) && xprt_get(XPRT_SSL)->prepare_srv) {
					if (xprt_get(XPRT_SSL)->prepare_srv(srv)) {
						ha_alert("unable to prepare SSL for server '%s' in resolvers section '%s'.\n", srv->id, curr_resolvers->id);
						err_code |= ERR_ALERT | ERR_FATAL;
						break;
					}
				}
				srv = srv->next;
			}
		}
	}
	curr_resolvers = NULL;
	return err_code;
}

REGISTER_CONFIG_SECTION("resolvers",      cfg_parse_resolvers, cfg_post_parse_resolvers);
REGISTER_POST_DEINIT(resolvers_deinit);
REGISTER_CONFIG_POSTPARSER("dns runtime resolver", resolvers_finalize_config);
