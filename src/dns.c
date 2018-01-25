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

#include <common/errors.h>
#include <common/time.h>
#include <common/ticks.h>
#include <common/net_helper.h>

#include <types/applet.h>
#include <types/cli.h>
#include <types/global.h>
#include <types/dns.h>
#include <types/stats.h>

#include <proto/channel.h>
#include <proto/cli.h>
#include <proto/checks.h>
#include <proto/dns.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/server.h>
#include <proto/task.h>
#include <proto/proto_udp.h>
#include <proto/proxy.h>
#include <proto/stream_interface.h>

struct list dns_resolvers  = LIST_HEAD_INIT(dns_resolvers);
struct list dns_srvrq_list = LIST_HEAD_INIT(dns_srvrq_list);

static THREAD_LOCAL int64_t dns_query_id_seed = 0; /* random seed */
static struct pool_head *dns_answer_item_pool = NULL;
static struct pool_head *dns_resolution_pool  = NULL;
static unsigned int resolution_uuid = 1;

/* Returns a pointer to the resolvers matching the id <id>. NULL is returned if
 * no match is found.
 */
struct dns_resolvers *find_resolvers_by_id(const char *id)
{
	struct dns_resolvers *res;

	list_for_each_entry(res, &dns_resolvers, list) {
		if (!strcmp(res->id, id))
			return res;
	}
	return NULL;
}

/* Returns a pointer on the SRV request matching the name <name> for the proxy
 * <px>. NULL is returned if no match is found.
 */
struct dns_srvrq *find_srvrq_by_name(const char *name, struct proxy *px)
{
	struct dns_srvrq *srvrq;

	list_for_each_entry(srvrq, &dns_srvrq_list, list) {
		if (srvrq->proxy == px && !strcmp(srvrq->name, name))
			return srvrq;
	}
	return NULL;
}

/* Allocates a new SRVRQ for the given server with the name <fqdn>. It returns
 * NULL if an error occurred. */
struct dns_srvrq *new_dns_srvrq(struct server *srv, char *fqdn)
{
	struct proxy     *px    = srv->proxy;
	struct dns_srvrq *srvrq = NULL;
	int fqdn_len, hostname_dn_len;

	fqdn_len = strlen(fqdn);
	hostname_dn_len = dns_str_to_dn_label(fqdn, fqdn_len + 1, trash.str, trash.size);
	if (hostname_dn_len == -1) {
		ha_alert("config : %s '%s', server '%s': failed to parse FQDN '%s'\n",
			 proxy_type_str(px), px->id, srv->id, fqdn);
		goto err;
	}

	if ((srvrq = calloc(1, sizeof(*srvrq))) == NULL) {
		ha_alert("config : %s '%s', server '%s': out of memory\n",
			 proxy_type_str(px), px->id, srv->id);
		goto err;
	}
	srvrq->obj_type        = OBJ_TYPE_SRVRQ;
	srvrq->proxy           = px;
	srvrq->name            = strdup(fqdn);
	srvrq->hostname_dn     = strdup(trash.str);
	srvrq->hostname_dn_len = hostname_dn_len;
	if (!srvrq->name || !srvrq->hostname_dn) {
		ha_alert("config : %s '%s', server '%s': out of memory\n",
			 proxy_type_str(px), px->id, srv->id);
		goto err;
	}
	LIST_ADDQ(&dns_srvrq_list, &srvrq->list);
	return srvrq;

  err:
	if (srvrq) {
		free(srvrq->name);
		free(srvrq->hostname_dn);
		free(srvrq);
	}
	return NULL;
}


/* 2 bytes random generator to generate DNS query ID */
static inline uint16_t dns_rnd16(void)
{
	if (!dns_query_id_seed)
		dns_query_id_seed = now_ms;
	dns_query_id_seed ^= dns_query_id_seed << 13;
	dns_query_id_seed ^= dns_query_id_seed >> 7;
	dns_query_id_seed ^= dns_query_id_seed << 17;
	return dns_query_id_seed;
}


static inline int dns_resolution_timeout(struct dns_resolution *res)
{
	switch (res->status) {
		case RSLV_STATUS_VALID: return res->resolvers->hold.valid;
		default:                return res->resolvers->timeout.resolve;
	}
}

/* Updates a resolvers' task timeout for next wake up and queue it */
static void dns_update_resolvers_timeout(struct dns_resolvers *resolvers)
{
	struct dns_resolution *res;
	int next;

	next = tick_add(now_ms, resolvers->timeout.resolve);
	if (!LIST_ISEMPTY(&resolvers->resolutions.curr)) {
		res  = LIST_NEXT(&resolvers->resolutions.curr, struct dns_resolution *, list);
		next = MIN(next, tick_add(res->last_query, resolvers->timeout.retry));
	}

	list_for_each_entry(res, &resolvers->resolutions.wait, list)
		next = MIN(next, tick_add(res->last_resolution, dns_resolution_timeout(res)));

	resolvers->t->expire = next;
	task_queue(resolvers->t);
}

/* Opens an UDP socket on the namesaver's IP/Port, if required. Returns 0 on
 * success, -1 otherwise.
 */
static int dns_connect_namesaver(struct dns_nameserver *ns)
{
	struct dgram_conn *dgram = ns->dgram;
	int fd;

	/* Already connected */
	if (dgram->t.sock.fd != -1)
		return 0;

	/* Create an UDP socket and connect it on the nameserver's IP/Port */
	if ((fd = socket(ns->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		send_log(NULL, LOG_WARNING,
			 "DNS : resolvers '%s': can't create socket for nameserver '%s'.\n",
			 ns->resolvers->id, ns->id);
		return -1;
	}
	if (connect(fd, (struct sockaddr*)&ns->addr, get_addr_len(&ns->addr)) == -1) {
		send_log(NULL, LOG_WARNING,
			 "DNS : resolvers '%s': can't connect socket for nameserver '%s'.\n",
			 ns->resolvers->id, ns->id);
		close(fd);
		return -1;
	}

	/* Make the socket non blocking */
	fcntl(fd, F_SETFL, O_NONBLOCK);

	/* Add the fd in the fd list and update its parameters */
	dgram->t.sock.fd = fd;
	fd_insert(fd, dgram, dgram_fd_handler, MAX_THREADS_MASK);
	fd_want_recv(fd);
	return 0;
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
static int dns_build_query(int query_id, int query_type, unsigned int accepted_payload_size,
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
 * success, -1 otherwise.
 */
static int dns_send_query(struct dns_resolution *resolution)
{
	struct dns_resolvers  *resolvers = resolution->resolvers;
	struct dns_nameserver *ns;

	list_for_each_entry(ns, &resolvers->nameservers, list) {
		int fd = ns->dgram->t.sock.fd;
		if (fd == -1) {
			if (dns_connect_namesaver(ns) == -1)
				continue;
			fd = ns->dgram->t.sock.fd;
			resolvers->nb_nameservers++;
		}
		fd_want_send(fd);
	}

	/* Update resolution */
	resolution->nb_queries   = 0;
	resolution->nb_responses = 0;
	resolution->last_query   = now_ms;

	/* Push the resolution at the end of the active list */
	LIST_DEL(&resolution->list);
	LIST_ADDQ(&resolvers->resolutions.curr, &resolution->list);
	return 0;
}

/* Prepares and sends a DNS resolution. It returns 1 if the query was sent, 0 if
 * skipped and -1 if an error occurred.
 */
static int
dns_run_resolution(struct dns_resolution *resolution)
{
	struct dns_resolvers  *resolvers = resolution->resolvers;
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
		query_id = dns_rnd16();
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
	dns_send_query(resolution);
	return 1;
}

/* Performs a name resolution for the requester <req> */
void dns_trigger_resolution(struct dns_requester *req)
{
	struct dns_resolvers  *resolvers;
	struct dns_resolution *res;
	int exp;

	if (!req || !req->resolution)
		return;
	res       = req->resolution;
	resolvers = res->resolvers;

	/* The resolution must not be triggered yet. Use the cached response, if
	 * valid */
	exp = tick_add(res->last_resolution, resolvers->hold.valid);
	if (res->status == RSLV_STATUS_VALID &&
	    tick_isset(res->last_resolution) && !tick_is_expired(exp, now_ms))
		req->requester_cb(req, NULL);
	else
		dns_run_resolution(res);
}


/* Resets some resolution parameters to initial values and also delete the query
 * ID from the resolver's tree.
 */
static void dns_reset_resolution(struct dns_resolution *resolution)
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
static inline unsigned short dns_response_get_query_id(unsigned char *resp)
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
int dns_read_name(unsigned char *buffer, unsigned char *bufend,
		  unsigned char *name, char *destination, int dest_len,
		  int *offset)
{
	int nb_bytes = 0, n = 0;
	int label_len;
	unsigned char *reader = name;
	char *dest = destination;

	while (1) {
		/* Name compression is in use */
		if ((*reader & 0xc0) == 0xc0) {
			/* Must point BEFORE current position */
			if ((buffer + reader[1]) > reader)
				goto err;

			n = dns_read_name(buffer, bufend, buffer + reader[1],
					  dest, dest_len - nb_bytes, offset);
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

/* Checks for any obsolete record, also identify any SRV request, and try to
 * find a corresponding server.
*/
static void dns_check_dns_response(struct dns_resolution *res)
{
	struct dns_resolvers   *resolvers = res->resolvers;
	struct dns_requester   *req, *reqback;
	struct dns_answer_item *item, *itemback;
	struct server          *srv;
	struct dns_srvrq       *srvrq;

	list_for_each_entry_safe(item, itemback, &res->response.answer_list, list) {

		/* Remove obsolete items */
		if ((item->last_seen + resolvers->hold.obsolete / 1000) < now.tv_sec) {
			if (item->type != DNS_RTYPE_SRV)
				goto rm_obselete_item;

			list_for_each_entry_safe(req, reqback, &res->requesters, list) {
				if ((srvrq = objt_dns_srvrq(req->owner)) == NULL)
					continue;

				/* Remove any associated server */
				for (srv = srvrq->proxy->srv; srv != NULL; srv = srv->next) {
					HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
					if (srv->srvrq == srvrq && srv->svc_port == item->port &&
					    item->data_len == srv->hostname_dn_len &&
					    !memcmp(srv->hostname_dn, item->target, item->data_len)) {
						snr_update_srv_status(srv, 1);
						free(srv->hostname);
						free(srv->hostname_dn);
						srv->hostname        = NULL;
						srv->hostname_dn     = NULL;
						srv->hostname_dn_len = 0;
						dns_unlink_resolution(srv->dns_requester);
					}
					HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
				}
			}

		  rm_obselete_item:
			LIST_DEL(&item->list);
			pool_free(dns_answer_item_pool, item);
			continue;
		}

		if (item->type != DNS_RTYPE_SRV)
			continue;

		/* Now process SRV records */
		list_for_each_entry_safe(req, reqback, &res->requesters, list) {
			if ((srvrq = objt_dns_srvrq(req->owner)) == NULL)
				continue;

			/* Check if a server already uses that hostname */
			for (srv = srvrq->proxy->srv; srv != NULL; srv = srv->next) {
				HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
				if (srv->srvrq == srvrq && srv->svc_port == item->port &&
				    item->data_len == srv->hostname_dn_len &&
				    !memcmp(srv->hostname_dn, item->target, item->data_len)) {
					int ha_weight;

					/* Make sure weight is at least 1, so
					 * that the server will be used.
					 */
					ha_weight = item->weight / 256 + 1;
					if (srv->uweight != ha_weight) {
						char weight[9];

						snprintf(weight, sizeof(weight), "%d", ha_weight);
						server_parse_weight_change_request(srv, weight);
					}
					HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
					break;
				}
				HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
			}
			if (srv)
				continue;

			/* If not, try to find a server with undefined hostname */
			for (srv = srvrq->proxy->srv; srv != NULL; srv = srv->next) {
				HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
				if (srv->srvrq == srvrq && !srv->hostname_dn)
					break;
				HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
			}
			/* And update this server, if found */
			if (srv) {
				const char *msg = NULL;
				char weight[9];
				int ha_weight;
				char hostname[DNS_MAX_NAME_SIZE];

				if (dns_dn_label_to_str(item->target, item->data_len+1,
							hostname, DNS_MAX_NAME_SIZE) == -1) {
					HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
					continue;
				}
				msg = update_server_fqdn(srv, hostname, "SRV record", 1);
				if (msg)
					send_log(srv->proxy, LOG_NOTICE, "%s", msg);

				srv->svc_port = item->port;
				srv->flags   &= ~SRV_F_MAPPORTS;
				if ((srv->check.state & CHK_ST_CONFIGURED) &&
				    !(srv->flags & SRV_F_CHECKPORT))
					srv->check.port = item->port;

				/* Make sure weight is at least 1, so
				 * that the server will be used.
				 */
				ha_weight = item->weight / 256 + 1;

				snprintf(weight, sizeof(weight), "%d", ha_weight);
				server_parse_weight_change_request(srv, weight);
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
 * This function returns one of the DNS_RESP_* code to indicate the type of
 * error found.
 */
static int dns_validate_dns_response(unsigned char *resp, unsigned char *bufend,
				     struct dns_resolution *resolution, int max_answer_records)
{
	unsigned char *reader;
	char *previous_dname, tmpname[DNS_MAX_NAME_SIZE];
	int len, flags, offset;
	int dns_query_record_id;
	int nb_saved_records;
	struct dns_query_item *dns_query;
	struct dns_answer_item *dns_answer_record, *tmp_record;
	struct dns_response_packet *dns_p;
	int i, found = 0;

	reader         = resp;
	len            = 0;
	previous_dname = NULL;
	dns_query      = NULL;

	/* Initialization of response buffer and structure */
	dns_p = &resolution->response;

	/* query id */
	if (reader + 2 >= bufend)
		return DNS_RESP_INVALID;
	dns_p->header.id = reader[0] * 256 + reader[1];
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
		return DNS_RESP_INVALID;

	flags = reader[0] * 256 + reader[1];

	if ((flags & DNS_FLAG_REPLYCODE) != DNS_RCODE_NO_ERROR) {
		if ((flags & DNS_FLAG_REPLYCODE) == DNS_RCODE_NX_DOMAIN)
			return DNS_RESP_NX_DOMAIN;
		else if ((flags & DNS_FLAG_REPLYCODE) == DNS_RCODE_REFUSED)
			return DNS_RESP_REFUSED;
		return DNS_RESP_ERROR;
	}

	/* Move forward 2 bytes for flags */
	reader += 2;

	/* 2 bytes for question count */
	if (reader + 2 >= bufend)
		return DNS_RESP_INVALID;
	dns_p->header.qdcount = reader[0] * 256 + reader[1];
	/* (for now) we send one query only, so we expect only one in the
	 * response too */
	if (dns_p->header.qdcount != 1)
		return DNS_RESP_QUERY_COUNT_ERROR;
	if (dns_p->header.qdcount > DNS_MAX_QUERY_RECORDS)
		return DNS_RESP_INVALID;
	reader += 2;

	/* 2 bytes for answer count */
	if (reader + 2 >= bufend)
		return DNS_RESP_INVALID;
	dns_p->header.ancount = reader[0] * 256 + reader[1];
	if (dns_p->header.ancount == 0)
		return DNS_RESP_ANCOUNT_ZERO;
	/* Check if too many records are announced */
	if (dns_p->header.ancount > max_answer_records)
		return DNS_RESP_INVALID;
	reader += 2;

	/* 2 bytes authority count */
	if (reader + 2 >= bufend)
		return DNS_RESP_INVALID;
	dns_p->header.nscount = reader[0] * 256 + reader[1];
	reader += 2;

	/* 2 bytes additional count */
	if (reader + 2 >= bufend)
		return DNS_RESP_INVALID;
	dns_p->header.arcount = reader[0] * 256 + reader[1];
	reader += 2;

	/* Parsing dns queries */
	LIST_INIT(&dns_p->query_list);
	for (dns_query_record_id = 0; dns_query_record_id < dns_p->header.qdcount; dns_query_record_id++) {
		/* Use next pre-allocated dns_query_item after ensuring there is
		 * still one available.
		 * It's then added to our packet query list. */
		if (dns_query_record_id > DNS_MAX_QUERY_RECORDS)
			return DNS_RESP_INVALID;
		dns_query = &resolution->response_query_records[dns_query_record_id];
		LIST_ADDQ(&dns_p->query_list, &dns_query->list);

		/* Name is a NULL terminated string in our case, since we have
		 * one query per response and the first one can't be compressed
		 * (using the 0x0c format) */
		offset = 0;
		len = dns_read_name(resp, bufend, reader, dns_query->name, DNS_MAX_NAME_SIZE, &offset);

		if (len == 0)
			return DNS_RESP_INVALID;

		reader += offset;
		previous_dname = dns_query->name;

		/* move forward 2 bytes for question type */
		if (reader + 2 >= bufend)
			return DNS_RESP_INVALID;
		dns_query->type = reader[0] * 256 + reader[1];
		reader += 2;

		/* move forward 2 bytes for question class */
		if (reader + 2 >= bufend)
			return DNS_RESP_INVALID;
		dns_query->class = reader[0] * 256 + reader[1];
		reader += 2;
	}

	/* TRUNCATED flag must be checked after we could read the query type
	 * because a TRUNCATED SRV query type response can still be exploited */
	if (dns_query->type != DNS_RTYPE_SRV && flags & DNS_FLAG_TRUNCATED)
		return DNS_RESP_TRUNCATED;

	/* now parsing response records */
	nb_saved_records = 0;
	for (i = 0; i < dns_p->header.ancount; i++) {
		if (reader >= bufend)
			return DNS_RESP_INVALID;

		dns_answer_record = pool_alloc(dns_answer_item_pool);
		if (dns_answer_record == NULL)
			return (DNS_RESP_INVALID);

		offset = 0;
		len = dns_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE, &offset);

		if (len == 0) {
			pool_free(dns_answer_item_pool, dns_answer_record);
			return DNS_RESP_INVALID;
		}

		/* Check if the current record dname is valid.  previous_dname
		 * points either to queried dname or last CNAME target */
		if (dns_query->type != DNS_RTYPE_SRV && memcmp(previous_dname, tmpname, len) != 0) {
			pool_free(dns_answer_item_pool, dns_answer_record);
			if (i == 0) {
				/* First record, means a mismatch issue between
				 * queried dname and dname found in the first
				 * record */
				return DNS_RESP_INVALID;
			}
			else {
				/* If not the first record, this means we have a
				 * CNAME resolution error */
				return DNS_RESP_CNAME_ERROR;
			}

		}

		memcpy(dns_answer_record->name, tmpname, len);
		dns_answer_record->name[len] = 0;

		reader += offset;
		if (reader >= bufend) {
			pool_free(dns_answer_item_pool, dns_answer_record);
			return DNS_RESP_INVALID;
		}

		/* 2 bytes for record type (A, AAAA, CNAME, etc...) */
		if (reader + 2 > bufend) {
			pool_free(dns_answer_item_pool, dns_answer_record);
			return DNS_RESP_INVALID;
		}
		dns_answer_record->type = reader[0] * 256 + reader[1];
		reader += 2;

		/* 2 bytes for class (2) */
		if (reader + 2 > bufend) {
			pool_free(dns_answer_item_pool, dns_answer_record);
			return DNS_RESP_INVALID;
		}
		dns_answer_record->class = reader[0] * 256 + reader[1];
		reader += 2;

		/* 4 bytes for ttl (4) */
		if (reader + 4 > bufend) {
			pool_free(dns_answer_item_pool, dns_answer_record);
			return DNS_RESP_INVALID;
		}
		dns_answer_record->ttl =   reader[0] * 16777216 + reader[1] * 65536
			                 + reader[2] * 256 + reader[3];
		reader += 4;

		/* Now reading data len */
		if (reader + 2 > bufend) {
			pool_free(dns_answer_item_pool, dns_answer_record);
			return DNS_RESP_INVALID;
		}
		dns_answer_record->data_len = reader[0] * 256 + reader[1];

		/* Move forward 2 bytes for data len */
		reader += 2;

		/* Analyzing record content */
		switch (dns_answer_record->type) {
			case DNS_RTYPE_A:
				/* ipv4 is stored on 4 bytes */
				if (dns_answer_record->data_len != 4) {
					pool_free(dns_answer_item_pool, dns_answer_record);
					return DNS_RESP_INVALID;
				}
				dns_answer_record->address.sa_family = AF_INET;
				memcpy(&(((struct sockaddr_in *)&dns_answer_record->address)->sin_addr),
						reader, dns_answer_record->data_len);
				break;

			case DNS_RTYPE_CNAME:
				/* Check if this is the last record and update the caller about the status:
				 * no IP could be found and last record was a CNAME. Could be triggered
				 * by a wrong query type
				 *
				 * + 1 because dns_answer_record_id starts at 0
				 * while number of answers is an integer and
				 * starts at 1.
				 */
				if (i + 1 == dns_p->header.ancount) {
					pool_free(dns_answer_item_pool, dns_answer_record);
					return DNS_RESP_CNAME_ERROR;
				}

				offset = 0;
				len = dns_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE, &offset);
				if (len == 0) {
					pool_free(dns_answer_item_pool, dns_answer_record);
					return DNS_RESP_INVALID;
				}

				memcpy(dns_answer_record->target, tmpname, len);
				dns_answer_record->target[len] = 0;
				previous_dname = dns_answer_record->target;
				break;


			case DNS_RTYPE_SRV:
				/* Answer must contain :
				 * - 2 bytes for the priority
				 * - 2 bytes for the weight
				 * - 2 bytes for the port
				 * - the target hostname
				 */
				if (dns_answer_record->data_len <= 6) {
					pool_free(dns_answer_item_pool, dns_answer_record);
					return DNS_RESP_INVALID;
				}
				dns_answer_record->priority = read_n16(reader);
				reader += sizeof(uint16_t);
				dns_answer_record->weight = read_n16(reader);
				reader += sizeof(uint16_t);
				dns_answer_record->port = read_n16(reader);
				reader += sizeof(uint16_t);
				offset = 0;
				len = dns_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE, &offset);
				if (len == 0) {
					pool_free(dns_answer_item_pool, dns_answer_record);
					return DNS_RESP_INVALID;
				}
				dns_answer_record->data_len = len;
				memcpy(dns_answer_record->target, tmpname, len);
				dns_answer_record->target[len] = 0;
				break;

			case DNS_RTYPE_AAAA:
				/* ipv6 is stored on 16 bytes */
				if (dns_answer_record->data_len != 16) {
					pool_free(dns_answer_item_pool, dns_answer_record);
					return DNS_RESP_INVALID;
				}
				dns_answer_record->address.sa_family = AF_INET6;
				memcpy(&(((struct sockaddr_in6 *)&dns_answer_record->address)->sin6_addr),
						reader, dns_answer_record->data_len);
				break;

		} /* switch (record type) */

		/* Increment the counter for number of records saved into our
		 * local response */
		nb_saved_records++;

		/* Move forward dns_answer_record->data_len for analyzing next
		 * record in the response */
		reader += ((dns_answer_record->type == DNS_RTYPE_SRV)
			   ? offset
			   : dns_answer_record->data_len);

		/* Lookup to see if we already had this entry */
		found = 0;
		list_for_each_entry(tmp_record, &dns_p->answer_list, list) {
			if (tmp_record->type != dns_answer_record->type)
				continue;

			switch(tmp_record->type) {
				case DNS_RTYPE_A:
					if (!memcmp(&((struct sockaddr_in *)&dns_answer_record->address)->sin_addr,
						    &((struct sockaddr_in *)&tmp_record->address)->sin_addr,
						    sizeof(in_addr_t)))
						found = 1;
					break;

				case DNS_RTYPE_AAAA:
					if (!memcmp(&((struct sockaddr_in6 *)&dns_answer_record->address)->sin6_addr,
						    &((struct sockaddr_in6 *)&tmp_record->address)->sin6_addr,
						    sizeof(struct in6_addr)))
						found = 1;
					break;

			case DNS_RTYPE_SRV:
                                if (dns_answer_record->data_len == tmp_record->data_len &&
				    !memcmp(dns_answer_record->target, tmp_record->target, dns_answer_record->data_len) &&
				    dns_answer_record->port == tmp_record->port) {
					tmp_record->weight = dns_answer_record->weight;
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
			tmp_record->last_seen = now.tv_sec;
			pool_free(dns_answer_item_pool, dns_answer_record);
		}
		else {
			dns_answer_record->last_seen = now.tv_sec;
			LIST_ADDQ(&dns_p->answer_list, &dns_answer_record->list);
		}
	} /* for i 0 to ancount */

	/* Save the number of records we really own */
	dns_p->header.ancount = nb_saved_records;
	dns_check_dns_response(resolution);
	return DNS_RESP_VALID;
}

/* Searches dn_name resolution in resp.
 * If existing IP not found, return the first IP matching family_priority,
 * otherwise, first ip found
 * The following tasks are the responsibility of the caller:
 *   - <dns_p> contains an error free DNS response
 * For both cases above, dns_validate_dns_response is required
 * returns one of the DNS_UPD_* code
 */
#define DNS_MAX_IP_REC 20
int dns_get_ip_from_response(struct dns_response_packet *dns_p,
                             struct dns_options *dns_opts, void *currentip,
                             short currentip_sin_family,
                             void **newip, short *newip_sin_family,
                             void *owner)
{
	struct dns_answer_item *record;
	int family_priority;
	int currentip_found;
	unsigned char *newip4, *newip6;
	int currentip_sel;
	int j;
	int score, max_score;

	family_priority   = dns_opts->family_prio;
	*newip = newip4   = newip6 = NULL;
	currentip_found   = 0;
	*newip_sin_family = AF_UNSPEC;
	max_score         = -1;

	/* Select an IP regarding configuration preference.
	 * Top priority is the prefered network ip version,
	 * second priority is the prefered network.
	 * the last priority is the currently used IP,
	 *
	 * For these three priorities, a score is calculated. The
	 * weight are:
	 *  8 - prefered netwok ip version.
	 *  4 - prefered network.
	 *  2 - if the ip in the record is not affected to any other server in the same backend (duplication)
	 *  1 - current ip.
	 * The result with the biggest score is returned.
	 */

	list_for_each_entry(record, &dns_p->answer_list, list) {
		void *ip;
		unsigned char ip_type;

		if (record->type == DNS_RTYPE_A) {
			ip = &(((struct sockaddr_in *)&record->address)->sin_addr);
			ip_type = AF_INET;
		}
		else if (record->type == DNS_RTYPE_AAAA) {
			ip_type = AF_INET6;
			ip = &(((struct sockaddr_in6 *)&record->address)->sin6_addr);
		}
		else
			continue;
		score = 0;

		/* Check for prefered ip protocol. */
		if (ip_type == family_priority)
			score += 8;

		/* Check for prefered network. */
		for (j = 0; j < dns_opts->pref_net_nb; j++) {

			/* Compare only the same adresses class. */
			if (dns_opts->pref_net[j].family != ip_type)
				continue;

			if ((ip_type == AF_INET &&
			     in_net_ipv4(ip,
			                 &dns_opts->pref_net[j].mask.in4,
			                 &dns_opts->pref_net[j].addr.in4)) ||
			    (ip_type == AF_INET6 &&
			     in_net_ipv6(ip,
			                 &dns_opts->pref_net[j].mask.in6,
			                 &dns_opts->pref_net[j].addr.in6))) {
				score += 4;
				break;
			}
		}

		/* Check if the IP found in the record is already affected to a
		 * member of a group.  If yes, the score should be incremented
		 * by 2. */
		if (owner && snr_check_ip_callback(owner, ip, &ip_type))
			continue;

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
			currentip_found = currentip_sel;
			if (score == 15)
				return DNS_UPD_NO;
			max_score = score;
		}
	} /* list for each record entries */

	/* No IP found in the response */
	if (!newip4 && !newip6)
		return DNS_UPD_NO_IP_FOUND;

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
		if (!currentip_found)
			goto not_found;
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
		if (!currentip_found)
			goto not_found;
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
		if (!currentip_found)
			goto not_found;
	}

	/* No reason why we should change the server's IP address */
	return DNS_UPD_NO;

 not_found:
	list_for_each_entry(record, &dns_p->answer_list, list) {
		/* Move the first record to the end of the list, for internal
		 * round robin */
		LIST_DEL(&record->list);
		LIST_ADDQ(&dns_p->answer_list, &record->list);
		break;
	}
	return DNS_UPD_SRVIP_NOT_FOUND;
}

/* Turns a domain name label into a string.
 *
 * <dn> must be a null-terminated string. <dn_len> must include the terminating
 * null byte. <str> must be allocated and its size must be passed in <str_len>.
 *
 *  In case of error, -1 is returned, otherwise, the number of bytes copied in
 * <str> (including the terminating null byte).
 */
int dns_dn_label_to_str(const char *dn, int dn_len, char *str, int str_len)
{
	char *ptr;
	int i, sz;

	if (str_len < dn_len - 1)
		return -1;

	ptr = str;
	for (i = 0; i < dn_len-1; ++i) {
		sz = dn[i];
		if (i)
			*ptr++ = '.';
		memcpy(ptr, dn+i+1, sz);
		ptr += sz;
		i   += sz;
	}
	*ptr++ = '\0';
	return (ptr - str);
}

/* Turns a string into domain name label: www.haproxy.org into 3www7haproxy3org
 *
 * <str> must be a null-terminated string. <str_len> must include the
 * terminating null byte. <dn> buffer must be allocated and its size must be
 * passed in <dn_len>.
 *
 *  In case of error, -1 is returned, otherwise, the number of bytes copied in
 * <dn> (excluding the terminating null byte).
 */
int dns_str_to_dn_label(const char *str, int str_len, char *dn, int dn_len)
{
	int i, offset;

	if (dn_len < str_len + 1)
		return -1;

	/* First byte of dn will be used to store the length of the first
	 * label */
	offset = 0;
	for (i = 0; i < str_len; ++i) {
		if (str[i] == '.') {
			/* 2 or more consecutive dots is invalid */
			if (i == offset)
				return -1;

			dn[offset] = (i - offset);
			offset = i+1;
			continue;
		}
		dn[i+1] = str[i];
	}
	dn[offset] = (i - offset - 1);
	dn[i] = '\0';
	return i;
}

/* Validates host name:
 *  - total size
 *  - each label size individually
 * returns:
 *  0 in case of error. If <err> is not NULL, an error message is stored there.
 *  1 when no error. <err> is left unaffected.
 */
int dns_hostname_validation(const char *string, char **err)
{
	const char *c, *d;
	int i;

	if (strlen(string) > DNS_MAX_NAME_SIZE) {
		if (err)
			*err = DNS_TOO_LONG_FQDN;
		return 0;
	}

	c = string;
	while (*c) {
		d = c;

		i = 0;
		while (*d != '.' && *d && i <= DNS_MAX_LABEL_SIZE) {
			i++;
			if (!((*d == '-') || (*d == '_') ||
			      ((*d >= 'a') && (*d <= 'z')) ||
			      ((*d >= 'A') && (*d <= 'Z')) ||
			      ((*d >= '0') && (*d <= '9')))) {
				if (err)
					*err = DNS_INVALID_CHARACTER;
				return 0;
			}
			d++;
		}

		if ((i >= DNS_MAX_LABEL_SIZE) && (d[i] != '.')) {
			if (err)
				*err = DNS_LABEL_TOO_LONG;
			return 0;
		}

		if (*d == '\0')
			goto out;

		c = ++d;
	}
 out:
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
static struct dns_resolution *dns_pick_resolution(struct dns_resolvers *resolvers,
						  char **hostname_dn, int hostname_dn_len,
						  int query_type)
{
	struct dns_resolution *res;

	if (!*hostname_dn)
		goto from_pool;

	/* Search for same hostname and query type in resolutions.curr */
	list_for_each_entry(res, &resolvers->resolutions.curr, list) {
		if (!res->hostname_dn)
			continue;
		if ((query_type == res->prefered_query_type) &&
		    hostname_dn_len == res->hostname_dn_len  &&
		    !memcmp(*hostname_dn, res->hostname_dn, hostname_dn_len))
			return res;
	}

	/* Search for same hostname and query type in resolutions.wait */
	list_for_each_entry(res, &resolvers->resolutions.wait, list) {
		if (!res->hostname_dn)
			continue;
		if ((query_type == res->prefered_query_type) &&
		    hostname_dn_len == res->hostname_dn_len  &&
		    !memcmp(*hostname_dn, res->hostname_dn, hostname_dn_len))
			return res;
	}

  from_pool:
	/* No resolution could be found, so let's allocate a new one */
	res = pool_alloc(dns_resolution_pool);
	if (res) {
		memset(res, 0, sizeof(*res));
		res->resolvers  = resolvers;
		res->uuid       = resolution_uuid;
		res->status     = RSLV_STATUS_NONE;
		res->step       = RSLV_STEP_NONE;
		res->last_valid = now_ms;

		LIST_INIT(&res->requesters);
		LIST_INIT(&res->response.answer_list);

		res->prefered_query_type = query_type;
		res->query_type          = query_type;
		res->hostname_dn         = *hostname_dn;
		res->hostname_dn_len     = hostname_dn_len;

		++resolution_uuid;

		/* Move the resolution to the resolvers wait queue */
		LIST_ADDQ(&resolvers->resolutions.wait, &res->list);
	}
	return res;
}

/* Releases a resolution from its requester(s) and move it back to the pool */
static void dns_free_resolution(struct dns_resolution *resolution)
{
	struct dns_requester *req, *reqback;

	/* clean up configuration */
	dns_reset_resolution(resolution);
	resolution->hostname_dn = NULL;
	resolution->hostname_dn_len = 0;

	list_for_each_entry_safe(req, reqback, &resolution->requesters, list) {
		LIST_DEL(&req->list);
		req->resolution = NULL;
	}

	LIST_DEL(&resolution->list);
	pool_free(dns_resolution_pool, resolution);
}

/* Links a requester (a server or a dns_srvrq) with a resolution. It returns 0
 * on success, -1 otherwise.
 */
int dns_link_resolution(void *requester, int requester_type, int requester_locked)
{
	struct dns_resolution *res = NULL;
	struct dns_requester  *req;
	struct dns_resolvers  *resolvers;
	struct server         *srv   = NULL;
	struct dns_srvrq      *srvrq = NULL;
	char **hostname_dn;
	int   hostname_dn_len, query_type;

	switch (requester_type) {
		case OBJ_TYPE_SERVER:
			srv             = (struct server *)requester;
			hostname_dn     = &srv->hostname_dn;
			hostname_dn_len = srv->hostname_dn_len;
			resolvers       = srv->resolvers;
			query_type      = ((srv->dns_opts.family_prio == AF_INET)
					   ? DNS_RTYPE_A
					   : DNS_RTYPE_AAAA);
			break;

		case OBJ_TYPE_SRVRQ:
			srvrq           = (struct dns_srvrq *)requester;
			hostname_dn     = &srvrq->hostname_dn;
			hostname_dn_len = srvrq->hostname_dn_len;
			resolvers       = srvrq->resolvers;
			query_type      = DNS_RTYPE_SRV;
			break;

		default:
			goto err;
	}

	/* Get a resolution from the resolvers' wait queue or pool */
	if ((res = dns_pick_resolution(resolvers, hostname_dn, hostname_dn_len, query_type)) == NULL)
		goto err;

	if (srv) {
		if (!requester_locked)
			HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
		if (srv->dns_requester == NULL) {
			if ((req = calloc(1, sizeof(*req))) == NULL) {
				if (!requester_locked)
					HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
				goto err;
			}
			req->owner         = &srv->obj_type;
			srv->dns_requester = req;
		}
		else
			req = srv->dns_requester;
		if (!requester_locked)
			HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
	}
	else if (srvrq) {
		if (srvrq->dns_requester == NULL) {
			if ((req = calloc(1, sizeof(*req))) == NULL)
				goto err;
			req->owner           = &srvrq->obj_type;
			srvrq->dns_requester = req;
		}
		else
			req = srvrq->dns_requester;
	}
	else
		goto err;

	req->resolution         = res;
	req->requester_cb       = snr_resolution_cb;
	req->requester_error_cb = snr_resolution_error_cb;

	LIST_ADDQ(&res->requesters, &req->list);
	return 0;

  err:
	if (res && LIST_ISEMPTY(&res->requesters))
		dns_free_resolution(res);
	return -1;
}

/* Removes a requester from a DNS resoltion. It takes takes care of all the
 * consequences. It also cleans up some parameters from the requester.
 */
void dns_unlink_resolution(struct dns_requester *requester)
{
	struct dns_resolution *res;
	struct dns_requester  *req;

	/* Nothing to do */
	if (!requester || !requester->resolution)
		return;
	res = requester->resolution;

	/* Clean up the requester */
	LIST_DEL(&requester->list);
	requester->resolution = NULL;

	/* We need to find another requester linked on this resolution */
	if (!LIST_ISEMPTY(&res->requesters))
		req = LIST_NEXT(&res->requesters, struct dns_requester *, list);
	else {
		dns_free_resolution(res);
		return;
	}

	/* Move hostname_dn related pointers to the next requester */
	switch (obj_type(req->owner)) {
		case OBJ_TYPE_SERVER:
			res->hostname_dn     = objt_server(req->owner)->hostname_dn;
			res->hostname_dn_len = objt_server(req->owner)->hostname_dn_len;
			break;
		case OBJ_TYPE_SRVRQ:
			res->hostname_dn     = objt_dns_srvrq(req->owner)->hostname_dn;
			res->hostname_dn_len = objt_dns_srvrq(req->owner)->hostname_dn_len;
			break;
		default:
			res->hostname_dn     = NULL;
			res->hostname_dn_len = 0;
			break;
	}
}

/* Called when a network IO is generated on a name server socket for an incoming
 * packet. It performs the following actions:
 *  - check if the packet requires processing (not outdated resolution)
 *  - ensure the DNS packet received is valid and call requester's callback
 *  - call requester's error callback if invalid response
 *  - check the dn_name in the packet against the one sent
 */
static void dns_resolve_recv(struct dgram_conn *dgram)
{
	struct dns_nameserver *ns, *tmpns;
	struct dns_resolvers  *resolvers;
	struct dns_resolution *res;
	struct dns_query_item *query;
	unsigned char  buf[DNS_MAX_UDP_MESSAGE + 1];
	unsigned char *bufend;
	int fd, buflen, dns_resp;
	int max_answer_records;
	unsigned short query_id;
	struct eb32_node *eb;
	struct dns_requester *req;

	fd = dgram->t.sock.fd;

	/* check if ready for reading */
	if (!fd_recv_ready(fd))
		return;

	/* no need to go further if we can't retrieve the nameserver */
	if ((ns = dgram->owner) == NULL)
		return;

	resolvers = ns->resolvers;
	HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);

	/* process all pending input messages */
	while (1) {
		/* read message received */
		memset(buf, '\0', resolvers->accepted_payload_size + 1);
		if ((buflen = recv(fd, (char*)buf , resolvers->accepted_payload_size + 1, 0)) < 0) {
			/* FIXME : for now we consider EAGAIN only */
			fd_cant_recv(fd);
			break;
		}

		/* message too big */
		if (buflen > resolvers->accepted_payload_size) {
			ns->counters.too_big++;
			continue;
		}

		/* initializing variables */
		bufend = buf + buflen;	/* pointer to mark the end of the buffer */

		/* read the query id from the packet (16 bits) */
		if (buf + 2 > bufend) {
			ns->counters.invalid++;
			continue;
		}
		query_id = dns_response_get_query_id(buf);

		/* search the query_id in the pending resolution tree */
		eb = eb32_lookup(&resolvers->query_ids, query_id);
		if (eb == NULL) {
			/* unknown query id means an outdated response and can be safely ignored */
			ns->counters.outdated++;
			continue;
		}

		/* known query id means a resolution in prgress */
		res = eb32_entry(eb, struct dns_resolution, qid);
		if (!res) {
			ns->counters.outdated++;
			continue;
		}

		/* number of responses received */
		res->nb_responses++;

		max_answer_records = (resolvers->accepted_payload_size - DNS_HEADER_SIZE) / DNS_MIN_RECORD_SIZE;
		dns_resp = dns_validate_dns_response(buf, bufend, res, max_answer_records);

		switch (dns_resp) {
			case DNS_RESP_VALID:
				break;

			case DNS_RESP_INVALID:
			case DNS_RESP_QUERY_COUNT_ERROR:
			case DNS_RESP_WRONG_NAME:
				res->status = RSLV_STATUS_INVALID;
				ns->counters.invalid++;
				break;

			case DNS_RESP_NX_DOMAIN:
				res->status = RSLV_STATUS_NX;
				ns->counters.nx++;
				break;

			case DNS_RESP_REFUSED:
				res->status = RSLV_STATUS_REFUSED;
				ns->counters.refused++;
				break;

			case DNS_RESP_ANCOUNT_ZERO:
				res->status = RSLV_STATUS_OTHER;
				ns->counters.any_err++;
				break;

			case DNS_RESP_CNAME_ERROR:
				res->status = RSLV_STATUS_OTHER;
				ns->counters.cname_error++;
				break;

			case DNS_RESP_TRUNCATED:
				res->status = RSLV_STATUS_OTHER;
				ns->counters.truncated++;
				break;

			case DNS_RESP_NO_EXPECTED_RECORD:
			case DNS_RESP_ERROR:
			case DNS_RESP_INTERNAL:
				res->status = RSLV_STATUS_OTHER;
				ns->counters.other++;
				break;
		}

		/* Wait all nameservers response to handle errors */
		if (dns_resp != DNS_RESP_VALID && res->nb_responses < resolvers->nb_nameservers)
			continue;

		/* Process error codes */
		if (dns_resp != DNS_RESP_VALID)  {
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
					dns_send_query(res);
				}
				else if (res->prefered_query_type == DNS_RTYPE_AAAA) {
					res->query_type = DNS_RTYPE_A;
					dns_send_query(res);
				}
			}
			continue;
		}

		/* Now let's check the query's dname corresponds to the one we
		 * sent. We can check only the first query of the list. We send
		 * one query at a time so we get one query in the response */
		query = LIST_NEXT(&res->response.query_list, struct dns_query_item *, list);
		if (query && memcmp(query->name, res->hostname_dn, res->hostname_dn_len) != 0) {
			dns_resp = DNS_RESP_WRONG_NAME;
			ns->counters.other++;
			goto report_res_error;
		}

		/* So the resolution succeeded */
		res->status     = RSLV_STATUS_VALID;
		res->last_valid = now_ms;
		ns->counters.valid++;
		goto report_res_success;

	report_res_error:
		list_for_each_entry(req, &res->requesters, list)
			req->requester_error_cb(req, dns_resp);
		dns_reset_resolution(res);
		LIST_DEL(&res->list);
		LIST_ADDQ(&resolvers->resolutions.wait, &res->list);
		continue;

	report_res_success:
		/* Only the 1rst requester s managed by the server, others are
		 * from the cache */
		tmpns = ns;
		list_for_each_entry(req, &res->requesters, list) {
			struct server *s = objt_server(req->owner);

			if (s)
				HA_SPIN_LOCK(SERVER_LOCK, &s->lock);
			req->requester_cb(req, tmpns);
			if (s)
				HA_SPIN_UNLOCK(SERVER_LOCK, &s->lock);
			tmpns = NULL;
		}

		dns_reset_resolution(res);
		LIST_DEL(&res->list);
		LIST_ADDQ(&resolvers->resolutions.wait, &res->list);
		continue;
	}
	dns_update_resolvers_timeout(resolvers);
	HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
}

/* Called when a resolvers network socket is ready to send data */
static void dns_resolve_send(struct dgram_conn *dgram)
{
	struct dns_resolvers  *resolvers;
	struct dns_nameserver *ns;
	struct dns_resolution *res;
	int fd;

	fd = dgram->t.sock.fd;

	/* check if ready for sending */
	if (!fd_send_ready(fd))
		return;

	/* we don't want/need to be waked up any more for sending */
	fd_stop_send(fd);

	/* no need to go further if we can't retrieve the nameserver */
	if ((ns = dgram->owner) == NULL)
		return;

	resolvers = ns->resolvers;
	HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);

	list_for_each_entry(res, &resolvers->resolutions.curr, list) {
		int ret;

		if (res->nb_queries == resolvers->nb_nameservers)
			continue;

		trash.len = dns_build_query(res->query_id, res->query_type,
					    resolvers->accepted_payload_size,
					    res->hostname_dn, res->hostname_dn_len,
					    trash.str, trash.size);
		if (trash.len == -1)
			goto snd_error;

		ret = send(fd, trash.str, trash.len, 0);
		if (ret != trash.len)
			goto snd_error;

		ns->counters.sent++;
		res->nb_queries++;
		continue;

	  snd_error:
		ns->counters.snd_error++;
		res->nb_queries++;
	}
	HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
}

/* Processes DNS resolution. First, it checks the active list to detect expired
 * resolutions and retry them if possible. Else a timeout is reported. Then, it
 * checks the wait list to trigger new resolutions.
 */
static struct task *dns_process_resolvers(struct task *t)
{
	struct dns_resolvers  *resolvers = t->context;
	struct dns_resolution *res, *resback;
	int exp;

	HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);

	/* Handle all expired resolutions from the active list */
	list_for_each_entry_safe(res, resback, &resolvers->resolutions.curr, list) {
		/* When we find the first resolution in the future, then we can
		 * stop here */
		exp = tick_add(res->last_query, resolvers->timeout.retry);
		if (!tick_is_expired(exp, now_ms))
			break;

		/* If current resolution has been tried too many times and
		 * finishes in timeout we update its status and remove it from
		 * the list */
		if (!res->try) {
			struct dns_requester *req;

			/* Notify the result to the requesters */
			if (!res->nb_responses)
				res->status = RSLV_STATUS_TIMEOUT;
			list_for_each_entry(req, &res->requesters, list)
				req->requester_error_cb(req, res->status);

			/* Clean up resolution info and remove it from the
			 * current list */
			dns_reset_resolution(res);
			LIST_DEL(&res->list);
			LIST_ADDQ(&resolvers->resolutions.wait, &res->list);

			/* This might be triggered by too big UDP packets
			 * dropped somewhere on the network, so lowering the
			 * accepted_payload_size announced */
			if (resolvers->accepted_payload_size > 1280)
				resolvers->accepted_payload_size = 1280;
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
			dns_send_query(res);
		}
	}

	/* Handle all resolutions in the wait list */
	list_for_each_entry_safe(res, resback, &resolvers->resolutions.wait, list) {
		exp = tick_add(res->last_resolution, dns_resolution_timeout(res));
		if (tick_isset(res->last_resolution) && !tick_is_expired(exp, now_ms))
			continue;

		if (dns_run_resolution(res) != 1) {
			res->last_resolution = now_ms;
			LIST_DEL(&res->list);
			LIST_ADDQ(&resolvers->resolutions.wait, &res->list);
		}
	}

	dns_update_resolvers_timeout(resolvers);
	HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
	return t;
}

/* proto_udp callback functions for a DNS resolution */
struct dgram_data_cb resolve_dgram_cb = {
	.recv = dns_resolve_recv,
	.send = dns_resolve_send,
};

/* Release memory allocated by DNS */
static void dns_deinit(void)
{
	struct dns_resolvers  *resolvers, *resolversback;
	struct dns_nameserver *ns, *nsback;
	struct dns_resolution *res, *resback;
	struct dns_requester  *req, *reqback;
	struct dns_srvrq      *srvrq, *srvrqback;

	list_for_each_entry_safe(resolvers, resolversback, &dns_resolvers, list) {
		list_for_each_entry_safe(ns, nsback, &resolvers->nameservers, list) {
			free(ns->id);
			free((char *)ns->conf.file);
			if (ns->dgram && ns->dgram->t.sock.fd != -1)
				fd_delete(ns->dgram->t.sock.fd);
			free(ns->dgram);
			LIST_DEL(&ns->list);
			free(ns);
		}

		list_for_each_entry_safe(res, resback, &resolvers->resolutions.curr, list) {
			list_for_each_entry_safe(req, reqback, &res->requesters, list) {
				LIST_DEL(&req->list);
				free(req);
			}
			dns_free_resolution(res);
		}

		list_for_each_entry_safe(res, resback, &resolvers->resolutions.wait, list) {
			list_for_each_entry_safe(req, reqback, &res->requesters, list) {
				LIST_DEL(&req->list);
				free(req);
			}
			dns_free_resolution(res);
		}

		free(resolvers->id);
		free((char *)resolvers->conf.file);
		task_delete(resolvers->t);
		task_free(resolvers->t);
		LIST_DEL(&resolvers->list);
		free(resolvers);
	}

	list_for_each_entry_safe(srvrq, srvrqback, &dns_srvrq_list, list) {
		free(srvrq->name);
		free(srvrq->hostname_dn);
		LIST_DEL(&srvrq->list);
		free(srvrq);
	}

	pool_destroy(dns_answer_item_pool);
	pool_destroy(dns_resolution_pool);
}

/* Finalizes the DNS configuration by allocating required resources and checking
 * live parameters.
 * Returns 0 on success, ERR_* flags otherwise.
 */
static int dns_finalize_config(void)
{
	struct dns_resolvers *resolvers;
	struct proxy	     *px;
	int err_code = 0;

	/* allocate pool of resolution per resolvers */
	list_for_each_entry(resolvers, &dns_resolvers, list) {
		struct dns_nameserver *ns;
		struct task           *t;

		/* Check if we can create the socket with nameservers info */
		list_for_each_entry(ns, &resolvers->nameservers, list) {
			struct dgram_conn *dgram = NULL;
			int fd;

			/* Check nameserver info */
			if ((fd = socket(ns->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
				ha_alert("config : resolvers '%s': can't create socket for nameserver '%s'.\n",
					 resolvers->id, ns->id);
				err_code |= (ERR_ALERT|ERR_ABORT);
				continue;
			}
			if (connect(fd, (struct sockaddr*)&ns->addr, get_addr_len(&ns->addr)) == -1) {
				ha_alert("config : resolvers '%s': can't connect socket for nameserver '%s'.\n",
					 resolvers->id, ns->id);
				close(fd);
				err_code |= (ERR_ALERT|ERR_ABORT);
				continue;
			}
			close(fd);

			/* Create dgram structure that will hold the UPD socket
			 * and attach it on the current nameserver */
			if ((dgram = calloc(1, sizeof(*dgram))) == NULL) {
				ha_alert("config: resolvers '%s' : out of memory.\n",
					 resolvers->id);
				err_code |= (ERR_ALERT|ERR_ABORT);
				goto err;
			}

			/* Leave dgram partially initialized, no FD attached for
			 * now. */
			dgram->owner     = ns;
			dgram->data      = &resolve_dgram_cb;
			dgram->t.sock.fd = -1;
			ns->dgram        = dgram;
		}

		/* Create the task associated to the resolvers section */
		if ((t = task_new(MAX_THREADS_MASK)) == NULL) {
			ha_alert("config : resolvers '%s' : out of memory.\n", resolvers->id);
			err_code |= (ERR_ALERT|ERR_ABORT);
			goto err;
		}

		/* Update task's parameters */
		t->process   = dns_process_resolvers;
		t->context   = resolvers;
		resolvers->t = t;
		task_wakeup(t, TASK_WOKEN_INIT);
	}

	for (px = proxies_list; px; px = px->next) {
		struct server *srv;

		for (srv = px->srv; srv; srv = srv->next) {
			struct dns_resolvers *resolvers;

			if (!srv->resolvers_id)
				continue;

			if ((resolvers = find_resolvers_by_id(srv->resolvers_id)) == NULL) {
				ha_alert("config : %s '%s', server '%s': unable to find required resolvers '%s'\n",
					 proxy_type_str(px), px->id, srv->id, srv->resolvers_id);
				err_code |= (ERR_ALERT|ERR_ABORT);
				continue;
			}
			srv->resolvers = resolvers;

			if (srv->srvrq && !srv->srvrq->resolvers) {
				srv->srvrq->resolvers = srv->resolvers;
				if (dns_link_resolution(srv->srvrq, OBJ_TYPE_SRVRQ, 0) == -1) {
					ha_alert("config : %s '%s' : unable to set DNS resolution for server '%s'.\n",
						 proxy_type_str(px), px->id, srv->id);
					err_code |= (ERR_ALERT|ERR_ABORT);
					continue;
				}
			}
			if (dns_link_resolution(srv, OBJ_TYPE_SERVER, 0) == -1) {
				ha_alert("config : %s '%s', unable to set DNS resolution for server '%s'.\n",
					 proxy_type_str(px), px->id, srv->id);
				err_code |= (ERR_ALERT|ERR_ABORT);
				continue;
			}
		}
	}

	if (err_code & (ERR_ALERT|ERR_ABORT))
		goto err;

	return err_code;
  err:
	dns_deinit();
	return err_code;

}

/* if an arg is found, it sets the resolvers section pointer into cli.p0 */
static int cli_parse_stat_resolvers(char **args, struct appctx *appctx, void *private)
{
	struct dns_resolvers *presolvers;

	if (*args[2]) {
		list_for_each_entry(presolvers, &dns_resolvers, list) {
			if (strcmp(presolvers->id, args[2]) == 0) {
				appctx->ctx.cli.p0 = presolvers;
				break;
			}
		}
		if (appctx->ctx.cli.p0 == NULL) {
			appctx->ctx.cli.severity = LOG_ERR;
			appctx->ctx.cli.msg = "Can't find that resolvers section\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}
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
	struct dns_resolvers    *resolvers;
	struct dns_nameserver   *ns;

	chunk_reset(&trash);

	switch (appctx->st2) {
	case STAT_ST_INIT:
		appctx->st2 = STAT_ST_LIST; /* let's start producing data */
		/* fall through */

	case STAT_ST_LIST:
		if (LIST_ISEMPTY(&dns_resolvers)) {
			chunk_appendf(&trash, "No resolvers found\n");
		}
		else {
			list_for_each_entry(resolvers, &dns_resolvers, list) {
				if (appctx->ctx.cli.p0 != NULL && appctx->ctx.cli.p0 != resolvers)
					continue;

				chunk_appendf(&trash, "Resolvers section %s\n", resolvers->id);
				list_for_each_entry(ns, &resolvers->nameservers, list) {
					chunk_appendf(&trash, " nameserver %s:\n", ns->id);
					chunk_appendf(&trash, "  sent:        %lld\n", ns->counters.sent);
					chunk_appendf(&trash, "  snd_error:   %lld\n", ns->counters.snd_error);
					chunk_appendf(&trash, "  valid:       %lld\n", ns->counters.valid);
					chunk_appendf(&trash, "  update:      %lld\n", ns->counters.update);
					chunk_appendf(&trash, "  cname:       %lld\n", ns->counters.cname);
					chunk_appendf(&trash, "  cname_error: %lld\n", ns->counters.cname_error);
					chunk_appendf(&trash, "  any_err:     %lld\n", ns->counters.any_err);
					chunk_appendf(&trash, "  nx:          %lld\n", ns->counters.nx);
					chunk_appendf(&trash, "  timeout:     %lld\n", ns->counters.timeout);
					chunk_appendf(&trash, "  refused:     %lld\n", ns->counters.refused);
					chunk_appendf(&trash, "  other:       %lld\n", ns->counters.other);
					chunk_appendf(&trash, "  invalid:     %lld\n", ns->counters.invalid);
					chunk_appendf(&trash, "  too_big:     %lld\n", ns->counters.too_big);
					chunk_appendf(&trash, "  truncated:   %lld\n", ns->counters.truncated);
					chunk_appendf(&trash, "  outdated:    %lld\n",  ns->counters.outdated);
				}
				chunk_appendf(&trash, "\n");
			}
		}

		/* display response */
		if (ci_putchk(si_ic(si), &trash) == -1) {
			/* let's try again later from this session. We add ourselves into
			 * this session's users so that it can remove us upon termination.
			 */
			si->flags |= SI_FL_WAIT_ROOM;
			return 0;
		}

		appctx->st2 = STAT_ST_FIN;
		/* fall through */

	default:
		appctx->st2 = STAT_ST_FIN;
		return 1;
	}
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ }, {
		{ { "show", "resolvers", NULL }, "show resolvers [id]: dumps counters from all resolvers section and\n"
		  "                     associated name servers",
		  cli_parse_stat_resolvers, cli_io_handler_dump_resolvers_to_buffer },
		{{},}
	}
};


__attribute__((constructor))
static void __dns_init(void)
{
	dns_answer_item_pool = create_pool("dns_answer_item", sizeof(struct dns_answer_item), MEM_F_SHARED);
	dns_resolution_pool  = create_pool("dns_resolution",  sizeof(struct dns_resolution),  MEM_F_SHARED);

	hap_register_post_check(dns_finalize_config);
	hap_register_post_deinit(dns_deinit);

	cli_register_kw(&cli_kws);
}
