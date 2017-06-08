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

#include <common/time.h>
#include <common/ticks.h>

#include <import/lru.h>
#include <import/xxhash.h>

#include <types/applet.h>
#include <types/cli.h>
#include <types/global.h>
#include <types/dns.h>
#include <types/proto_udp.h>
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
#include <proto/stream_interface.h>

struct list dns_resolvers = LIST_HEAD_INIT(dns_resolvers);
struct dns_resolution *resolution = NULL;

static int64_t dns_query_id_seed;	/* random seed */

static struct lru64_head *dns_lru_tree;
static int dns_cache_size = 1024;       /* arbitrary DNS cache size */

/* proto_udp callback functions for a DNS resolution */
struct dgram_data_cb resolve_dgram_cb = {
	.recv = dns_resolve_recv,
	.send = dns_resolve_send,
};

/* local function prototypes */
static int dns_run_resolution(struct dns_requester *requester);

#if DEBUG
/*
 * go through the resolutions associated to a resolvers section and print the ID and hostname in
 * domain name format
 * should be used for debug purpose only
 */
void dns_print_current_resolutions(struct dns_resolvers *resolvers)
{
	list_for_each_entry(resolution, &resolvers->resolution.curr, list) {
		printf("  resolution %d for %s\n", resolution->query_id, resolution->hostname_dn);
	}
}
#endif

void dump_dns_config()
{
	struct dns_resolvers *curr_resolvers = NULL;
	struct dns_nameserver *curr_nameserver = NULL;
	struct dns_resolution *curr_resolution = NULL;
	struct dns_requester *curr_requester = NULL;

	printf("===============\n");
	list_for_each_entry(curr_resolvers, &dns_resolvers, list) {
		printf("Resolvers: %s\n", curr_resolvers->id);

		printf("  nameservers:\n");
		list_for_each_entry(curr_nameserver, &curr_resolvers->nameserver_list, list) {
			printf("    %s\n", curr_nameserver->id);
		}

/*
		printf("  resolution.pool list:\n");
		list_for_each_entry(curr_resolution, &curr_resolvers->resolution.pool, list) {
			printf("    %p\n", curr_resolution);
		}
*/

		printf("  resolution.wait list:\n");
		list_for_each_entry(curr_resolution, &curr_resolvers->resolution.wait, list) {
			printf("    %p %s\n", curr_resolution, curr_resolution->hostname_dn);
			printf("      requester.wait list:\n");
			list_for_each_entry(curr_requester, &curr_resolution->requester.wait, list) {
				printf("        %p %s %d\n", curr_requester, objt_server(curr_requester->requester)->id, curr_requester->prefered_query_type);
			}
			printf("      requester.curr list:\n");
			list_for_each_entry(curr_requester, &curr_resolution->requester.curr, list) {
				printf("        %p %s %d\n", curr_requester, objt_server(curr_requester->requester)->id, curr_requester->prefered_query_type);
			}
		}
		printf("  resolution.curr list:\n");
		list_for_each_entry(curr_resolution, &curr_resolvers->resolution.curr, list) {
			printf("    %p %s\n", curr_resolution, curr_resolution->hostname_dn);
			printf("      requester.wait list:\n");
			list_for_each_entry(curr_requester, &curr_resolution->requester.wait, list) {
				printf("        %p %s %d\n", curr_requester, objt_server(curr_requester->requester)->id, curr_requester->prefered_query_type);
			}
			printf("      requester.curr list:\n");
			list_for_each_entry(curr_requester, &curr_resolution->requester.curr, list) {
				printf("        %p %s %d\n", curr_requester, objt_server(curr_requester->requester)->id, curr_requester->prefered_query_type);
			}
		}
	}

	printf("===============\n");
}

/*
 * Initiates a new name resolution:
 *  - generates a query id
 *  - configure the resolution structure
 *  - startup the resolvers task if required
 *
 * returns:
 *  -  0 if everything started properly
 *  - -1 in case of error or if resolution already running
 */
int dns_trigger_resolution(struct dns_resolution *resolution)
{
	struct dns_requester *requester = NULL, *tmprequester;
	struct dns_resolvers *resolvers = NULL;
	int inter;

	/* process the element of the wait queue */
	list_for_each_entry_safe(requester, tmprequester, &resolution->requester.wait, list) {
		inter = 0;

		switch (obj_type(requester->requester)) {
			case OBJ_TYPE_SERVER:
				inter = objt_server(requester->requester)->check.inter;
				resolvers = objt_server(requester->requester)->resolvers;
				break;
			case OBJ_TYPE_NONE:
			default:
				return -1;
		}

		/* if data is fresh enough, let's use it */
		if (!tick_is_expired(tick_add(resolution->last_resolution, inter), now_ms)) {
			/* we only use cache if the response there is valid.
			 * If not valid, we run the resolution and move the requester to
			 * the run queue. */
			if (resolution->status != RSLV_STATUS_VALID) {
				LIST_DEL(&requester->list);
				LIST_ADDQ(&resolution->requester.curr, &requester->list);
				dns_run_resolution(requester);
				continue;
			}

			requester->requester_cb(requester, NULL);
		}
		else {
			LIST_DEL(&requester->list);
			LIST_ADDQ(&resolution->requester.curr, &requester->list);
			dns_run_resolution(requester);
		}
	}

	if (resolvers)
		dns_update_resolvers_timeout(resolvers);

	return 0;
}

/*
 * Prepare and send a DNS resolution.
 *
 * Return code:
 * -  0 if no error occured
 * - -1 in case of error
 */
static int
dns_run_resolution(struct dns_requester *requester)
{
	struct dns_resolution *resolution;
	struct dns_resolvers *resolvers;
	int query_id, query_type, i;
	struct proxy *proxy;

	resolution = NULL;
	resolvers = NULL;
	proxy = NULL;
	query_type = -1;
	switch (obj_type(requester->requester)) {
		case OBJ_TYPE_SERVER:
			resolution = objt_server(requester->requester)->resolution;
			resolvers = objt_server(requester->requester)->resolvers;
			proxy = objt_server(requester->requester)->proxy;
			query_type = requester->prefered_query_type;
			break;
		case OBJ_TYPE_NONE:
		default:
			return -1;
	}

	/*
	 * check if a resolution has already been started for this server
	 * return directly to avoid resolution pill up.
	 */
	if (resolution->step != RSLV_STEP_NONE)
		return 0;

	/* generates a query id */
	i = 0;
	do {
		query_id = dns_rnd16();
		/* we do try only 100 times to find a free query id */
		if (i++ > 100) {
			chunk_printf(&trash, "could not generate a query id for %s, in resolvers %s",
						resolution->hostname_dn, resolvers->id);

			if (proxy)
				send_log(proxy, LOG_NOTICE, "%s.\n", trash.str);
			return -1;
		}
	} while (eb32_lookup(&resolvers->query_ids, query_id));

	/* move the resolution into the run queue */
	LIST_DEL(&resolution->list);
	LIST_ADDQ(&resolvers->resolution.curr, &resolution->list);

	/* now update resolution parameters */
	resolution->query_id = query_id;
	resolution->qid.key = query_id;
	resolution->step = RSLV_STEP_RUNNING;
	resolution->query_type = query_type;
	resolution->try = resolvers->resolve_retries;
	resolution->try_cname = 0;
	resolution->nb_responses = 0;
	eb32_insert(&resolvers->query_ids, &resolution->qid);

	dns_send_query(resolution);
	resolution->try -= 1;

	/* update wakeup date if this resolution is the only one in the FIFO list */
	if (dns_check_resolution_queue(resolvers) == 1) {
		/* update task timeout */
		dns_update_resolvers_timeout(resolvers);
		task_queue(resolvers->t);
	}

	return 0;
}

/*
 * check if there is more than 1 resolution in the resolver's resolution list
 * return value:
 * 0: empty list
 * 1: exactly one entry in the list
 * 2: more than one entry in the list
 */
int dns_check_resolution_queue(struct dns_resolvers *resolvers)
{

	if (LIST_ISEMPTY(&resolvers->resolution.curr))
		return 0;

	if ((resolvers->resolution.curr.n) && (resolvers->resolution.curr.n == resolvers->resolution.curr.p))
		return 1;

	if (! ((resolvers->resolution.curr.n == resolvers->resolution.curr.p)
			&& (&resolvers->resolution.curr != resolvers->resolution.curr.n)))
		return 2;

	return 0;
}

/*
 * reset some resolution parameters to initial values and also delete the
 * query ID from the resolver's tree.
 */
void dns_reset_resolution(struct dns_resolution *resolution)
{
	/* update resolution status */
	resolution->step = RSLV_STEP_NONE;

	resolution->try = 0;
	resolution->try_cname = 0;
	resolution->last_resolution = now_ms;
	resolution->nb_responses = 0;

	/* clean up query id */
	eb32_delete(&resolution->qid);
	resolution->query_id = 0;
	resolution->qid.key = 0;
}

/*
 * function called when a network IO is generated on a name server socket for an incoming packet
 * It performs the following actions:
 *  - check if the packet requires processing (not outdated resolution)
 *  - ensure the DNS packet received is valid and call requester's callback
 *  - call requester's error callback if invalid response
 *  - check the dn_name in the packet against the one sent
 */
void dns_resolve_recv(struct dgram_conn *dgram)
{
	struct dns_nameserver *nameserver, *tmpnameserver;
	struct dns_resolvers *resolvers;
	struct dns_resolution *resolution = NULL;
	struct dns_query_item *query;
	unsigned char buf[DNS_MAX_UDP_MESSAGE + 1];
	unsigned char *bufend;
	int fd, buflen, dns_resp, need_resend = 0;
	unsigned short query_id;
	struct eb32_node *eb;
	struct lru64 *lru = NULL;
	struct dns_requester *requester = NULL, *tmprequester = NULL;

	fd = dgram->t.sock.fd;

	/* check if ready for reading */
	if (!fd_recv_ready(fd))
		return;

	/* no need to go further if we can't retrieve the nameserver */
	if ((nameserver = dgram->owner) == NULL)
		return;

	resolvers = nameserver->resolvers;

	/* process all pending input messages */
	while (1) {
		/* read message received */
		memset(buf, '\0', DNS_MAX_UDP_MESSAGE + 1);
		if ((buflen = recv(fd, (char*)buf , DNS_MAX_UDP_MESSAGE, 0)) < 0) {
			/* FIXME : for now we consider EAGAIN only */
			fd_cant_recv(fd);
			break;
		}

		/* message too big */
		if (buflen > DNS_MAX_UDP_MESSAGE) {
			nameserver->counters.too_big += 1;
			continue;
		}

		/* initializing variables */
		bufend = buf + buflen;	/* pointer to mark the end of the buffer */

		/* read the query id from the packet (16 bits) */
		if (buf + 2 > bufend) {
			nameserver->counters.invalid += 1;
			continue;
		}
		query_id = dns_response_get_query_id(buf);

		/* search the query_id in the pending resolution tree */
		eb = eb32_lookup(&resolvers->query_ids, query_id);
		if (eb == NULL) {
			/* unknown query id means an outdated response and can be safely ignored */
			nameserver->counters.outdated += 1;
			continue;
		}

		/* known query id means a resolution in prgress */
		resolution = eb32_entry(eb, struct dns_resolution, qid);

		if (!resolution) {
			nameserver->counters.outdated += 1;
			continue;
		}

		/* number of responses received */
		resolution->nb_responses += 1;

		dns_resp = dns_validate_dns_response(buf, bufend, resolution);

		switch (dns_resp) {
			case DNS_RESP_VALID:
				need_resend = 0;
				break;

			case DNS_RESP_INVALID:
			case DNS_RESP_QUERY_COUNT_ERROR:
			case DNS_RESP_WRONG_NAME:
				if (resolution->status != RSLV_STATUS_INVALID) {
					resolution->status = RSLV_STATUS_INVALID;
					resolution->last_status_change = now_ms;
				}
				nameserver->counters.invalid += 1;
				need_resend = 0;
				break;

			case DNS_RESP_ANCOUNT_ZERO:
				if (resolution->status != RSLV_STATUS_OTHER) {
					resolution->status = RSLV_STATUS_OTHER;
					resolution->last_status_change = now_ms;
				}
				nameserver->counters.any_err += 1;
				need_resend = 1;
				break;

			case DNS_RESP_NX_DOMAIN:
				if (resolution->status != RSLV_STATUS_NX) {
					resolution->status = RSLV_STATUS_NX;
					resolution->last_status_change = now_ms;
				}
				nameserver->counters.nx += 1;
				need_resend = 0;
				break;

			case DNS_RESP_REFUSED:
				if (resolution->status != RSLV_STATUS_REFUSED) {
					resolution->status = RSLV_STATUS_REFUSED;
					resolution->last_status_change = now_ms;
				}
				nameserver->counters.refused += 1;
				need_resend = 0;
				break;

			case DNS_RESP_CNAME_ERROR:
				if (resolution->status != RSLV_STATUS_OTHER) {
					resolution->status = RSLV_STATUS_OTHER;
					resolution->last_status_change = now_ms;
				}
				nameserver->counters.cname_error += 1;
				need_resend = 1;
				break;

			case DNS_RESP_TRUNCATED:
				if (resolution->status != RSLV_STATUS_OTHER) {
					resolution->status = RSLV_STATUS_OTHER;
					resolution->last_status_change = now_ms;
				}
				nameserver->counters.truncated += 1;
				need_resend = 1;
				break;

			case DNS_RESP_NO_EXPECTED_RECORD:
				if (resolution->status != RSLV_STATUS_OTHER) {
					resolution->status = RSLV_STATUS_OTHER;
					resolution->last_status_change = now_ms;
				}
				nameserver->counters.other += 1;
				need_resend = 1;
				break;

			case DNS_RESP_ERROR:
			case DNS_RESP_INTERNAL:
				if (resolution->status != RSLV_STATUS_OTHER) {
					resolution->status = RSLV_STATUS_OTHER;
					resolution->last_status_change = now_ms;
				}
				nameserver->counters.other += 1;
				need_resend = 1;
				break;
		}

		/* some error codes trigger a re-send of the query, but switching the
		 * query type.
		 * This is the case for the following error codes:
		 *   DNS_RESP_ANCOUNT_ZERO
		 *   DNS_RESP_TRUNCATED
		 *   DNS_RESP_ERROR
		 *   DNS_RESP_INTERNAL
		 *   DNS_RESP_NO_EXPECTED_RECORD
		 *   DNS_RESP_CNAME_ERROR
		 */
		if (need_resend) {
			int family_prio;
			int res_preferred_afinet, res_preferred_afinet6;

			requester = LIST_NEXT(&resolution->requester.curr, struct dns_requester *, list);
			switch (obj_type(requester->requester)) {
				case OBJ_TYPE_SERVER:
					family_prio = objt_server(requester->requester)->dns_opts.family_prio;
					break;
				case OBJ_TYPE_NONE:
				default:
					family_prio = AF_INET6;
			}
			res_preferred_afinet = family_prio == AF_INET && resolution->query_type == DNS_RTYPE_A;
			res_preferred_afinet6 = family_prio == AF_INET6 && resolution->query_type == DNS_RTYPE_AAAA;
			if ((res_preferred_afinet || res_preferred_afinet6)
					|| (resolution->try > 0)) {
				/* let's change the query type */
				if (res_preferred_afinet6) {
                                        /* fallback from AAAA to A */
                                        resolution->query_type = DNS_RTYPE_A;
                                }
                                else if (res_preferred_afinet) {
                                        /* fallback from A to AAAA */
                                        resolution->query_type = DNS_RTYPE_AAAA;
                                }
                                else {
                                        resolution->try -= 1;
                                        if (family_prio == AF_INET) {
                                                resolution->query_type = DNS_RTYPE_A;
                                        } else {
                                                resolution->query_type = DNS_RTYPE_AAAA;
                                        }
                                }

				dns_send_query(resolution);
                                /*
				 * move the resolution to the last element of the FIFO queue
				 * and update timeout wakeup based on the new first entry
				 */
				if (dns_check_resolution_queue(resolvers) > 1) {
				/* second resolution becomes first one */
					LIST_DEL(&resolution->list);
					/* ex first resolution goes to the end of the queue */
					LIST_ADDQ(&resolvers->resolution.curr, &resolution->list);
				}

				dns_update_resolvers_timeout(resolvers);
				goto next_packet;
			}

			/* if we're there, this means that we already ran out of chances to re-send
			 * the query */
			list_for_each_entry_safe(requester, tmprequester, &resolution->requester.curr, list) {
				requester->requester_error_cb(requester, dns_resp);
			}
			goto next_packet;
		}

		/* now processing those error codes only:
		 *   DNS_RESP_NX_DOMAIN
		 *   DNS_RESP_REFUSED
		 */
		if (dns_resp != DNS_RESP_VALID) {
			/* now parse list of requesters currently waiting for this resolution */
			list_for_each_entry_safe(requester, tmprequester, &resolution->requester.curr, list) {
				requester->requester_error_cb(requester, dns_resp);

				/* we can move the requester the wait queue */
				LIST_DEL(&requester->list);
				LIST_ADDQ(&resolution->requester.wait, &requester->list);
			}
			goto next_packet;
		}

		/* Now let's check the query's dname corresponds to the one we sent.
		 * We can check only the first query of the list. We send one query at a time
		 * so we get one query in the response */
		query = LIST_NEXT(&resolution->response.query_list, struct dns_query_item *, list);
		if (query && memcmp(query->name, resolution->hostname_dn, resolution->hostname_dn_len) != 0) {
			nameserver->counters.other += 1;
			/* now parse list of requesters currently waiting for this resolution */
			list_for_each_entry_safe(requester, tmprequester, &resolution->requester.curr, list) {
				requester->requester_error_cb(requester, DNS_RESP_WRONG_NAME);
				/* we can move the requester the wait queue */
				LIST_DEL(&requester->list);
				LIST_ADDQ(&resolution->requester.wait, &requester->list);
			}
			goto next_packet;
		}

		/* no errors, we can save the response in the cache */
		if (dns_lru_tree) {
			unsigned long long seed = 1;
			struct chunk *buf = get_trash_chunk();
			struct chunk *tmp = NULL;

			chunk_reset(buf);
			tmp = dns_cache_key(resolution->query_type, resolution->hostname_dn,
					    resolution->hostname_dn_len, buf);
			if (!tmp) {
				nameserver->counters.other += 1;
				/* now parse list of requesters currently waiting for this resolution */
				list_for_each_entry_safe(requester, tmprequester, &resolution->requester.curr, list) {
					requester->requester_error_cb(requester, DNS_RESP_ERROR);
					/* we can move the requester the wait queue */
					LIST_DEL(&requester->list);
					LIST_ADDQ(&resolution->requester.wait, &requester->list);
				}
				goto next_packet;
			}

			lru = lru64_get(XXH64(buf->str, buf->len, seed),
					dns_lru_tree, nameserver->resolvers, 1);

			lru64_commit(lru, resolution, nameserver->resolvers, 1, NULL);
		}

		if (resolution->status != RSLV_STATUS_VALID) {
			resolution->status = RSLV_STATUS_VALID;
			resolution->last_status_change = now_ms;
		}

		nameserver->counters.valid += 1;
		/* now parse list of requesters currently waiting for this resolution */
		tmpnameserver = nameserver;
		list_for_each_entry_safe(requester, tmprequester, &resolution->requester.curr, list) {
			requester->requester_cb(requester, tmpnameserver);
			/* we can move the requester the wait queue */
			LIST_DEL(&requester->list);
			LIST_ADDQ(&resolution->requester.wait, &requester->list);
			/* first response is managed by the server, others are from the cache */
			tmpnameserver = NULL;
		}

 next_packet:
		/* resolution may be NULL when we receive an ICMP unreachable packet */
		if (resolution && LIST_ISEMPTY(&resolution->requester.curr)) {
			/* move the resolution into the wait queue */
			LIST_DEL(&resolution->list);
			LIST_ADDQ(&resolvers->resolution.wait, &resolution->list);
			/* update last resolution date and time */
			resolution->last_resolution = now_ms;
			/* reset current status flag */
			resolution->step = RSLV_STEP_NONE;
			/* reset values */
			dns_reset_resolution(resolution);
		}

	} // end of while "packets" loop

	dns_update_resolvers_timeout(nameserver->resolvers);
}

/*
 * function called when a resolvers network socket is ready to send data
 * It performs the following actions:
 */
void dns_resolve_send(struct dgram_conn *dgram)
{
	int fd;
	struct dns_nameserver *nameserver;
	struct dns_resolvers *resolvers;
	struct dns_resolution *resolution;

	fd = dgram->t.sock.fd;

	/* check if ready for sending */
	if (!fd_send_ready(fd))
		return;

	/* we don't want/need to be waked up any more for sending */
	fd_stop_send(fd);

	/* no need to go further if we can't retrieve the nameserver */
	if ((nameserver = dgram->owner) == NULL)
		return;

	resolvers = nameserver->resolvers;
	resolution = LIST_NEXT(&resolvers->resolution.curr, struct dns_resolution *, list);

	dns_send_query(resolution);
	dns_update_resolvers_timeout(resolvers);
}

/*
 * forge and send a DNS query to resolvers associated to a resolution
 * It performs the following actions:
 * returns:
 *  0 in case of error or safe ignorance
 *  1 if no error
 */
int dns_send_query(struct dns_resolution *resolution)
{
	struct dns_resolvers *resolvers = NULL;
	struct dns_nameserver *nameserver;
	struct dns_requester *requester = NULL;
	int ret, bufsize, fd;

	/* nothing to do */
	if (LIST_ISEMPTY(&resolution->requester.curr))
		return 0;

	requester = LIST_NEXT(&resolution->requester.curr, struct dns_requester *, list);

	switch (obj_type(requester->requester)) {
		case OBJ_TYPE_SERVER:
			resolvers = objt_server(requester->requester)->resolvers;
			break;
		case OBJ_TYPE_NONE:
		default:
			return 0;
	}

	if (!resolvers)
		return 0;

	bufsize = dns_build_query(resolution->query_id, resolution->query_type, resolution->hostname_dn,
			resolution->hostname_dn_len, trash.str, trash.size);

	if (bufsize == -1)
		return 0;

	list_for_each_entry(nameserver, &resolvers->nameserver_list, list) {
		fd = nameserver->dgram->t.sock.fd;
		errno = 0;

		ret = send(fd, trash.str, bufsize, 0);

		if (ret > 0)
			nameserver->counters.sent += 1;

		if (ret == 0 || errno == EAGAIN) {
			/* nothing written, let's update the poller that we wanted to send
			 * but we were not able to */
			fd_want_send(fd);
			fd_cant_send(fd);
		}
	}

	/* update resolution */
	resolution->nb_responses = 0;
	resolution->last_sent_packet = now_ms;

	return 1;
}

/*
 * update a resolvers' task timeout for next wake up
 */
void dns_update_resolvers_timeout(struct dns_resolvers *resolvers)
{
	struct dns_resolution *resolution;
	struct dns_requester *requester;

	if ((LIST_ISEMPTY(&resolvers->resolution.curr)) && (LIST_ISEMPTY(&resolvers->resolution.wait))) {
		resolvers->t->expire = TICK_ETERNITY;
	}
	else if (!LIST_ISEMPTY(&resolvers->resolution.curr)) {
		resolution = LIST_NEXT(&resolvers->resolution.curr, struct dns_resolution *, list);
		if (!resolvers->t->expire || tick_is_le(resolvers->t->expire, tick_add(resolution->last_sent_packet, resolvers->timeout.retry))) {
			resolvers->t->expire = tick_add(resolution->last_sent_packet, resolvers->timeout.retry);
		}
	}
	else if (!LIST_ISEMPTY(&resolvers->resolution.wait)) {
		int valid_period, inter, need_wakeup;
		struct dns_resolution *res_back;
		need_wakeup = 0;
		list_for_each_entry_safe(resolution, res_back, &resolvers->resolution.wait, list) {
			valid_period = 0;
			inter = 0;

			requester = LIST_NEXT(&resolution->requester.wait, struct dns_requester *, list);

			switch (obj_type(requester->requester)) {
				case OBJ_TYPE_SERVER:
					valid_period = objt_server(requester->requester)->check.inter;
					break;
				case OBJ_TYPE_NONE:
				default:
					continue;
			}

			if (resolvers->hold.valid < valid_period)
				inter = resolvers->hold.valid;
			else
				inter = valid_period;

			if (tick_is_expired(tick_add(resolution->last_resolution, inter), now_ms)) {
				switch (obj_type(requester->requester)) {
					case OBJ_TYPE_SERVER:
						dns_trigger_resolution(objt_server(requester->requester)->resolution);
						break;
					case OBJ_TYPE_NONE:
					default:
						;;
				}
			}
			else {
				need_wakeup = 1;
			}
		}
		/* in such case, we wake up in 1s */
		if (need_wakeup) {
			int r = 1000;

			resolution = LIST_NEXT(&resolvers->resolution.wait, struct dns_resolution *, list);
			if (tick_is_le(resolvers->t->expire, tick_add(now_ms, r)))
				resolvers->t->expire = tick_add(now_ms, r);
			resolvers->t->expire = tick_add(now_ms, 1000);
		}
	}

	task_queue(resolvers->t);
}

/*
 * Analyse, re-build and copy the name <name> from the DNS response packet <buffer>.
 * <name> must point to the 'data_len' information or pointer 'c0' for compressed data.
 * The result is copied into <dest>, ensuring we don't overflow using <dest_len>
 * Returns the number of bytes the caller can move forward. If 0 it means an error occured
 * while parsing the name.
 * <offset> is the number of bytes the caller could move forward.
 */
int dns_read_name(unsigned char *buffer, unsigned char *bufend, unsigned char *name, char *destination, int dest_len, int *offset)
{
	int nb_bytes = 0, n = 0;
	int label_len;
	unsigned char *reader = name;
	char *dest = destination;

	while (1) {
		/* name compression is in use */
		if ((*reader & 0xc0) == 0xc0) {
			/* a pointer must point BEFORE current position */
			if ((buffer + reader[1]) > reader) {
				goto out_error;
			}

			n = dns_read_name(buffer, bufend, buffer + reader[1], dest, dest_len - nb_bytes, offset);
			if (n == 0)
				goto out_error;

			dest += n;
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
			goto out_error;

		/* +1 to take label len + label string */
		label_len += 1;

		memcpy(dest, reader, label_len);

		dest += label_len;
		nb_bytes += label_len;
		reader += label_len;
	}

 out:
	/* offset computation:
	 * parse from <name> until finding either NULL or a pointer "c0xx"
	 */
	reader = name;
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

 out_error:
	return 0;
}

/*
 * Function to validate that the buffer DNS response provided in <resp> and
 * finishing before <bufend> is valid from a DNS protocol point of view.
 *
 * The result is stored in <resolution>' response, buf_response, response_query_records
 * and response_answer_records members.
 *
 * This function returns one of the DNS_RESP_* code to indicate the type of
 * error found.
 */
int dns_validate_dns_response(unsigned char *resp, unsigned char *bufend, struct dns_resolution *resolution)
{
	unsigned char *reader;
	char *previous_dname, tmpname[DNS_MAX_NAME_SIZE];
	int len, flags, offset, ret;
	int dns_query_record_id, dns_answer_record_id;
	int nb_saved_records;
	struct dns_query_item *dns_query;
	struct dns_answer_item *dns_answer_record;
	struct dns_response_packet *dns_p;
	struct chunk *dns_response_buffer;

	reader = resp;
	len = 0;
	previous_dname = NULL;

	/* initialization of response buffer and structure */
	dns_p = &resolution->response;
	dns_response_buffer = &resolution->response_buffer;
	memset(dns_p, '\0', sizeof(struct dns_response_packet));
	chunk_reset(dns_response_buffer);

	/* query id */
	if (reader + 2 >= bufend)
		return DNS_RESP_INVALID;
	dns_p->header.id = reader[0] * 256 + reader[1];
	reader += 2;

	/*
	 * flags and rcode are stored over 2 bytes
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

	if (flags & DNS_FLAG_TRUNCATED)
		return DNS_RESP_TRUNCATED;

	if ((flags & DNS_FLAG_REPLYCODE) != DNS_RCODE_NO_ERROR) {
		if ((flags & DNS_FLAG_REPLYCODE) == DNS_RCODE_NX_DOMAIN)
			return DNS_RESP_NX_DOMAIN;
		else if ((flags & DNS_FLAG_REPLYCODE) == DNS_RCODE_REFUSED)
			return DNS_RESP_REFUSED;

		return DNS_RESP_ERROR;
	}

	/* move forward 2 bytes for flags */
	reader += 2;

	/* 2 bytes for question count */
	if (reader + 2 >= bufend)
		return DNS_RESP_INVALID;
	dns_p->header.qdcount = reader[0] * 256 + reader[1];
	/* (for now) we send one query only, so we expect only one in the response too */
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
	/* check if too many records are announced */
	if (dns_p->header.ancount > DNS_MAX_ANSWER_RECORDS)
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

	/* parsing dns queries */
	LIST_INIT(&dns_p->query_list);
	for (dns_query_record_id = 0; dns_query_record_id < dns_p->header.qdcount; dns_query_record_id++) {
		/* use next pre-allocated dns_query_item after ensuring there is
		 * still one available.
		 * It's then added to our packet query list.
		 */
		if (dns_query_record_id > DNS_MAX_QUERY_RECORDS)
			return DNS_RESP_INVALID;
		dns_query = &resolution->response_query_records[dns_query_record_id];
		LIST_ADDQ(&dns_p->query_list, &dns_query->list);

		/* name is a NULL terminated string in our case, since we have
		 * one query per response and the first one can't be compressed
		 * (using the 0x0c format)
		 */
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

	/* now parsing response records */
	LIST_INIT(&dns_p->answer_list);
	nb_saved_records = 0;
	for (dns_answer_record_id = 0; dns_answer_record_id < dns_p->header.ancount; dns_answer_record_id++) {
		if (reader >= bufend)
			return DNS_RESP_INVALID;

		/* pull next response record from the list, if still one available, then add it
		 * to the record list */
		if (dns_answer_record_id > DNS_MAX_ANSWER_RECORDS)
			return DNS_RESP_INVALID;
		dns_answer_record = &resolution->response_answer_records[dns_answer_record_id];
		LIST_ADDQ(&dns_p->answer_list, &dns_answer_record->list);

		offset = 0;
		len = dns_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE, &offset);

		if (len == 0)
			return DNS_RESP_INVALID;

		/* check if the current record dname is valid.
		 * previous_dname points either to queried dname or last CNAME target
		 */
		if (memcmp(previous_dname, tmpname, len) != 0) {
			if (dns_answer_record_id == 0) {
				/* first record, means a mismatch issue between queried dname
				 * and dname found in the first record */
				return DNS_RESP_INVALID;
			} else {
				/* if not the first record, this means we have a CNAME resolution
				 * error */
				return DNS_RESP_CNAME_ERROR;
			}

		}

		dns_answer_record->name = chunk_newstr(dns_response_buffer);
		if (dns_answer_record->name == NULL)
			return DNS_RESP_INVALID;

		ret = chunk_strncat(dns_response_buffer, tmpname, len);
		if (ret == 0)
			return DNS_RESP_INVALID;

		reader += offset;
		if (reader >= bufend)
			return DNS_RESP_INVALID;

		if (reader >= bufend)
			return DNS_RESP_INVALID;

		/* 2 bytes for record type (A, AAAA, CNAME, etc...) */
		if (reader + 2 > bufend)
			return DNS_RESP_INVALID;
		dns_answer_record->type = reader[0] * 256 + reader[1];
		reader += 2;

		/* 2 bytes for class (2) */
		if (reader + 2 > bufend)
			return DNS_RESP_INVALID;
		dns_answer_record->class = reader[0] * 256 + reader[1];
		reader += 2;

		/* 4 bytes for ttl (4) */
		if (reader + 4 > bufend)
			return DNS_RESP_INVALID;
		dns_answer_record->ttl =   reader[0] * 16777216 + reader[1] * 65536
			                 + reader[2] * 256 + reader[3];
		reader += 4;

		/* now reading data len */
		if (reader + 2 > bufend)
			return DNS_RESP_INVALID;
		dns_answer_record->data_len = reader[0] * 256 + reader[1];

		/* move forward 2 bytes for data len */
		reader += 2;

		/* analyzing record content */
		switch (dns_answer_record->type) {
			case DNS_RTYPE_A:
				/* ipv4 is stored on 4 bytes */
				if (dns_answer_record->data_len != 4)
					return DNS_RESP_INVALID;
				dns_answer_record->address.sa_family = AF_INET;
				memcpy(&(((struct sockaddr_in *)&dns_answer_record->address)->sin_addr),
						reader, dns_answer_record->data_len);
				break;

			case DNS_RTYPE_CNAME:
				/* check if this is the last record and update the caller about the status:
				 * no IP could be found and last record was a CNAME. Could be triggered
				 * by a wrong query type
				 *
				 * + 1 because dns_answer_record_id starts at 0 while number of answers
				 * is an integer and starts at 1.
				 */
				if (dns_answer_record_id + 1 == dns_p->header.ancount)
					return DNS_RESP_CNAME_ERROR;

				offset = 0;
				len = dns_read_name(resp, bufend, reader, tmpname, DNS_MAX_NAME_SIZE, &offset);

				if (len == 0)
					return DNS_RESP_INVALID;

				dns_answer_record->target = chunk_newstr(dns_response_buffer);
				if (dns_answer_record->target == NULL)
					return DNS_RESP_INVALID;

				ret = chunk_strncat(dns_response_buffer, tmpname, len);
				if (ret == 0)
					return DNS_RESP_INVALID;

				previous_dname = dns_answer_record->target;

				break;

			case DNS_RTYPE_AAAA:
				/* ipv6 is stored on 16 bytes */
				if (dns_answer_record->data_len != 16)
					return DNS_RESP_INVALID;
				dns_answer_record->address.sa_family = AF_INET6;
				memcpy(&(((struct sockaddr_in6 *)&dns_answer_record->address)->sin6_addr),
						reader, dns_answer_record->data_len);
				break;

		} /* switch (record type) */

		/* increment the counter for number of records saved into our local response */
		nb_saved_records += 1;

		/* move forward dns_answer_record->data_len for analyzing next record in the response */
		reader += dns_answer_record->data_len;
	} /* for i 0 to ancount */

	/* let's add a last \0 to close our last string */
	ret = chunk_strncat(dns_response_buffer, "\0", 1);
	if (ret == 0)
		return DNS_RESP_INVALID;

	/* save the number of records we really own */
	dns_p->header.ancount = nb_saved_records;

	return DNS_RESP_VALID;
}

/*
 * search dn_name resolution in resp.
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
	int i, currentip_found;
	unsigned char *newip4, *newip6;
	struct {
		void *ip;
		unsigned char type;
	} rec[DNS_MAX_IP_REC];
	int currentip_sel;
	int j;
	int rec_nb = 0;
	int score, max_score;

	family_priority = dns_opts->family_prio;
	*newip = newip4 = newip6 = NULL;
	currentip_found = 0;
	*newip_sin_family = AF_UNSPEC;

	/* now parsing response records */
	list_for_each_entry(record, &dns_p->answer_list, list) {
		/* analyzing record content */
		switch (record->type) {
			case DNS_RTYPE_A:
				/* Store IPv4, only if some room is avalaible. */
				if (rec_nb < DNS_MAX_IP_REC) {
					rec[rec_nb].ip = &(((struct sockaddr_in *)&record->address)->sin_addr);
					rec[rec_nb].type = AF_INET;
					rec_nb++;
				}
				break;

			/* we're looking for IPs only. CNAME validation is done when
			 * parsing the response buffer for the first time */
			case DNS_RTYPE_CNAME:
				break;

			case DNS_RTYPE_AAAA:
				/* Store IPv6, only if some room is avalaible. */
				if (rec_nb < DNS_MAX_IP_REC) {
					rec[rec_nb].ip = &(((struct sockaddr_in6 *)&record->address)->sin6_addr);
					rec[rec_nb].type = AF_INET6;
					rec_nb++;
				}
				break;

		} /* switch (record type) */
	} /* list for each record entries */

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
	max_score = -1;
	for (i = 0; i < rec_nb; i++) {
		int record_ip_already_affected = 0;

		score = 0;

		/* Check for prefered ip protocol. */
		if (rec[i].type == family_priority)
			score += 8;

		/* Check for prefered network. */
		for (j = 0; j < dns_opts->pref_net_nb; j++) {

			/* Compare only the same adresses class. */
			if (dns_opts->pref_net[j].family != rec[i].type)
				continue;

			if ((rec[i].type == AF_INET &&
			     in_net_ipv4(rec[i].ip,
			                 &dns_opts->pref_net[j].mask.in4,
			                 &dns_opts->pref_net[j].addr.in4)) ||
			    (rec[i].type == AF_INET6 &&
			     in_net_ipv6(rec[i].ip,
			                 &dns_opts->pref_net[j].mask.in6,
			                 &dns_opts->pref_net[j].addr.in6))) {
				score += 4;
				break;
			}
		}

		/* Check if the IP found in the record is already affected to a member of a group.
		 * If yes, the score should be incremented by 2.
		 */
		if (owner) {
			if (snr_check_ip_callback(owner, rec[i].ip, &rec[i].type))
				record_ip_already_affected = 1;
		}
		if (record_ip_already_affected == 0)
			score += 2;

		/* Check for current ip matching. */
		if (rec[i].type == currentip_sin_family &&
		    ((currentip_sin_family == AF_INET &&
		      memcmp(rec[i].ip, currentip, 4) == 0) ||
		     (currentip_sin_family == AF_INET6 &&
		      memcmp(rec[i].ip, currentip, 16) == 0))) {
			score += 1;
			currentip_sel = 1;
		} else
			currentip_sel = 0;


		/* Keep the address if the score is better than the previous
		 * score. The maximum score is 15, if this value is reached,
		 * we break the parsing. Implicitly, this score is reached
		 * the ip selected is the current ip.
		 */
		if (score > max_score) {
			if (rec[i].type == AF_INET)
				newip4 = rec[i].ip;
			else
				newip6 = rec[i].ip;
			currentip_found = currentip_sel;
			if (score == 15)
				return DNS_UPD_NO;
			max_score = score;
		}
	}

	/* no IP found in the response */
	if (!newip4 && !newip6) {
		return DNS_UPD_NO_IP_FOUND;
	}

	/* case when the caller looks first for an IPv4 address */
	if (family_priority == AF_INET) {
		if (newip4) {
			*newip = newip4;
			*newip_sin_family = AF_INET;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			goto return_DNS_UPD_SRVIP_NOT_FOUND;
		}
		else if (newip6) {
			*newip = newip6;
			*newip_sin_family = AF_INET6;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			goto return_DNS_UPD_SRVIP_NOT_FOUND;
		}
	}
	/* case when the caller looks first for an IPv6 address */
	else if (family_priority == AF_INET6) {
		if (newip6) {
			*newip = newip6;
			*newip_sin_family = AF_INET6;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			goto return_DNS_UPD_SRVIP_NOT_FOUND;
		}
		else if (newip4) {
			*newip = newip4;
			*newip_sin_family = AF_INET;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			goto return_DNS_UPD_SRVIP_NOT_FOUND;
		}
	}
	/* case when the caller have no preference (we prefer IPv6) */
	else if (family_priority == AF_UNSPEC) {
		if (newip6) {
			*newip = newip6;
			*newip_sin_family = AF_INET6;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			goto return_DNS_UPD_SRVIP_NOT_FOUND;
		}
		else if (newip4) {
			*newip = newip4;
			*newip_sin_family = AF_INET;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			goto return_DNS_UPD_SRVIP_NOT_FOUND;
		}
	}

	/* no reason why we should change the server's IP address */
	return DNS_UPD_NO;

 return_DNS_UPD_SRVIP_NOT_FOUND:
	list_for_each_entry(record, &dns_p->answer_list, list) {
		/* move the first record to the end of the list, for internal round robin */
		if (record) {
			LIST_DEL(&record->list);
			LIST_ADDQ(&dns_p->answer_list, &record->list);
			break;
		}
	}
	return DNS_UPD_SRVIP_NOT_FOUND;
}

/*
 * returns the query id contained in a DNS response
 */
unsigned short dns_response_get_query_id(unsigned char *resp)
{
	/* read the query id from the response */
	return resp[0] * 256 + resp[1];
}

/*
 * used during haproxy's init phase
 * parses resolvers sections and initializes:
 *  - task (time events) for each resolvers section
 *  - the datagram layer (network IO events) for each nameserver
 * It takes one argument:
 *  - close_first takes 2 values: 0 or 1. If 1, the connection is closed first.
 * returns:
 *  0 in case of error
 *  1 when no error
 */
int dns_init_resolvers(int close_socket)
{
	struct dns_resolvers *curr_resolvers;
	struct dns_nameserver *curnameserver;
	struct dns_resolution *resolution, *res_back;
	struct dgram_conn *dgram;
	struct task *t;
	int fd;

	/* initialize our DNS resolution cache */
	dns_lru_tree = lru64_new(dns_cache_size);

	/* give a first random value to our dns query_id seed */
	dns_query_id_seed = random();

	/* run through the resolvers section list */
	list_for_each_entry(curr_resolvers, &dns_resolvers, list) {
		/* create the task associated to the resolvers section */
		if ((t = task_new()) == NULL) {
			Alert("Starting [%s] resolvers: out of memory.\n", curr_resolvers->id);
			return 0;
		}

		/* update task's parameters */
		t->process = dns_process_resolve;
		t->context = curr_resolvers;
		t->expire = 0;

		/* no need to keep the new task if one is already affected to our resolvers
		 * section */
		if (!curr_resolvers->t)
			curr_resolvers->t = t;
		else
			task_free(t);

		list_for_each_entry(curnameserver, &curr_resolvers->nameserver_list, list) {
			dgram = NULL;

			if (close_socket == 1) {
				if (curnameserver->dgram) {
					fd_delete(curnameserver->dgram->t.sock.fd);
					memset(curnameserver->dgram, '\0', sizeof(*dgram));
					dgram = curnameserver->dgram;
				}
			}

			/* allocate memory only if it has not already been allocated
			 * by a previous call to this function */
			if (!dgram && (dgram = calloc(1, sizeof(*dgram))) == NULL) {
				Alert("Starting [%s/%s] nameserver: out of memory.\n", curr_resolvers->id,
						curnameserver->id);
				return 0;
			}
			/* update datagram's parameters */
			dgram->owner = (void *)curnameserver;
			dgram->data = &resolve_dgram_cb;

			/* create network UDP socket for this nameserver */
			if ((fd = socket(curnameserver->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
				Alert("Starting [%s/%s] nameserver: can't create socket.\n", curr_resolvers->id,
						curnameserver->id);
				free(dgram);
				dgram = NULL;
				return 0;
			}

			/* "connect" the UDP socket to the name server IP */
			if (connect(fd, (struct sockaddr*)&curnameserver->addr, get_addr_len(&curnameserver->addr)) == -1) {
				Alert("Starting [%s/%s] nameserver: can't connect socket.\n", curr_resolvers->id,
						curnameserver->id);
				close(fd);
				free(dgram);
				dgram = NULL;
				return 0;
			}

			/* make the socket non blocking */
			fcntl(fd, F_SETFL, O_NONBLOCK);

			/* add the fd in the fd list and update its parameters */
			fd_insert(fd);
			fdtab[fd].owner = dgram;
			fdtab[fd].iocb = dgram_fd_handler;
			fd_want_recv(fd);
			dgram->t.sock.fd = fd;

			/* update nameserver's datagram property */
			curnameserver->dgram = dgram;

			continue;
		}

		if (close_socket == 0)
			continue;

		/* now, we can trigger DNS resolution */
		list_for_each_entry_safe(resolution, res_back, &curr_resolvers->resolution.wait, list) {
			/* if there is no requester in the wait queue, no need to trigger the resolution */
			if (LIST_ISEMPTY(&resolution->requester.wait))
				continue;

			dns_trigger_resolution(resolution);
		}

		/* task can be queued */
		task_queue(t);
	}

	return 1;
}

/*
 * Allocate a pool of resolution to a resolvers section.
 * Each resolution is associated with a UUID.
 *
 * Return code:
 * -  0 if everything went smoothly
 * - -1 if an error occured
 */
int dns_alloc_resolution_pool(struct dns_resolvers *resolvers)
{
	int i;
	struct dns_resolution *resolution;

	/* return if a pool has already been set for this resolvers */
	if (!LIST_ISEMPTY(&resolvers->resolution.pool)) {
		return 0;
	}

	for (i = 0; i < resolvers->resolution_pool_size; i++) {
		resolution = dns_alloc_resolution();
		if (!resolution) {
			Alert("Starting [%s] resolvers: can't allocate memory for DNS resolution pool.\n", resolvers->id);
			return -1;
		}
		resolution->uuid = i;
		LIST_ADDQ(&resolvers->resolution.pool, &resolution->list);
	}

	return 0;
}

/*
 * Forge a DNS query. It needs the following information from the caller:
 *  - <query_id>: the DNS query id corresponding to this query
 *  - <query_type>: DNS_RTYPE_* request DNS record type (A, AAAA, ANY, etc...)
 *  - <hostname_dn>: hostname in domain name format
 *  - <hostname_dn_len>: length of <hostname_dn>
 * To store the query, the caller must pass a buffer <buf> and its size <bufsize>
 *
 * the DNS query is stored in <buf>
 * returns:
 *  -1 if <buf> is too short
 */
int dns_build_query(int query_id, int query_type, char *hostname_dn, int hostname_dn_len, char *buf, int bufsize)
{
	struct dns_header *dns;
	struct dns_question qinfo;
	char *ptr, *bufend;

	memset(buf, '\0', bufsize);
	ptr = buf;
	bufend = buf + bufsize;

	/* check if there is enough room for DNS headers */
	if (ptr + sizeof(struct dns_header) >= bufend)
		return -1;

	/* set dns query headers */
	dns = (struct dns_header *)ptr;
	dns->id = (unsigned short) htons(query_id);
	dns->flags = htons(0x0100); /* qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0 */
	dns->qdcount = htons(1);	/* 1 question */
	dns->ancount = 0;
	dns->nscount = 0;
	dns->arcount = 0;

	/* move forward ptr */
	ptr += sizeof(struct dns_header);

	/* check if there is enough room for query hostname */
	if ((ptr + hostname_dn_len) >= bufend)
		return -1;

	/* set up query hostname */
	memcpy(ptr, hostname_dn, hostname_dn_len);
	ptr[hostname_dn_len + 1] = '\0';

	/* move forward ptr */
	ptr += (hostname_dn_len + 1);

	/* check if there is enough room for query hostname*/
	if (ptr + sizeof(struct dns_question) >= bufend)
		return -1;

	/* set up query info (type and class) */
	qinfo.qtype = htons(query_type);
	qinfo.qclass = htons(DNS_RCLASS_IN);
	memcpy(ptr, &qinfo, sizeof(qinfo));

	ptr += sizeof(struct dns_question);

	return ptr - buf;
}

/*
 * turn a string into domain name label:
 * www.haproxy.org into 3www7haproxy3org
 * if dn memory is pre-allocated, you must provide its size in dn_len
 * if dn memory isn't allocated, dn_len must be set to 0.
 * In the second case, memory will be allocated.
 * in case of error, -1 is returned, otherwise, number of bytes copied in dn
 */
char *dns_str_to_dn_label(const char *string, char *dn, int dn_len)
{
	char *c, *d;
	int i, offset;

	/* offset between string size and theorical dn size */
	offset = 1;

	/*
	 * first, get the size of the string turned into its domain name version
	 * This function also validates the string respect the RFC
	 */
	if ((i = dns_str_to_dn_label_len(string)) == -1)
		return NULL;

	/* yes, so let's check there is enough memory */
	if (dn_len < i + offset)
		return NULL;

	i = strlen(string);
	memcpy(dn + offset, string, i);
	dn[i + offset] = '\0';
	/* avoid a '\0' at the beginning of dn string which may prevent the for loop
	 * below from working.
	 * Actually, this is the reason of the offset. */
	dn[0] = '0';

	for (c = dn; *c ; ++c) {
		/* c points to the first '0' char or a dot, which we don't want to read */
		d = c + offset;
		i = 0;
		while (*d != '.' && *d) {
			i++;
			d++;
		}
		*c = i;

		c = d - 1; /* because of c++ of the for loop */
	}

	return dn;
}

/*
 * compute and return the length of <string> it it were translated into domain name
 * label:
 * www.haproxy.org into 3www7haproxy3org would return 16
 * NOTE: add +1 for '\0' when allocating memory ;)
 */
int dns_str_to_dn_label_len(const char *string)
{
	return strlen(string) + 1;
}

/*
 * validates host name:
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

/*
 * 2 bytes random generator to generate DNS query ID
 */
uint16_t dns_rnd16(void)
{
	dns_query_id_seed ^= dns_query_id_seed << 13;
	dns_query_id_seed ^= dns_query_id_seed >> 7;
	dns_query_id_seed ^= dns_query_id_seed << 17;
	return dns_query_id_seed;
}


/*
 * function called when a timeout occurs during name resolution process
 * if max number of tries is reached, then stop, otherwise, retry.
 */
struct task *dns_process_resolve(struct task *t)
{
	struct dns_resolvers *resolvers = t->context;
	struct dns_resolution *resolution, *res_back;
	int res_preferred_afinet, res_preferred_afinet6;
	struct dns_options *dns_opts = NULL;

	/* if both there is no resolution in the run queue, we can re-schedule a wake up */
	if (LIST_ISEMPTY(&resolvers->resolution.curr)) {
		/* no first entry, so wake up was useless */
		dns_update_resolvers_timeout(resolvers);
		return t;
	}

	/* look for the first resolution which is not expired */
	list_for_each_entry_safe(resolution, res_back, &resolvers->resolution.curr, list) {
		struct dns_requester *requester = NULL;

		/* when we find the first resolution in the future, then we can stop here */
		if (tick_is_le(now_ms, resolution->last_sent_packet))
			goto out;

		if (LIST_ISEMPTY(&resolution->requester.curr))
			goto out;

		/*
		 * if current resolution has been tried too many times and finishes in timeout
		 * we update its status and remove it from the list
		 */
		if (resolution->try <= 0) {
			struct dns_requester *tmprequester;
			/* clean up resolution information and remove from the list */
			dns_reset_resolution(resolution);

			LIST_DEL(&resolution->list);
			LIST_ADDQ(&resolvers->resolution.wait, &resolution->list);

			if (resolution->status != RSLV_STATUS_TIMEOUT) {
				resolution->status = RSLV_STATUS_TIMEOUT;
				resolution->last_status_change = now_ms;
			}

			/* notify the result to the requesters */
			list_for_each_entry_safe(requester, tmprequester, &resolution->requester.curr, list) {
				requester->requester_error_cb(requester, DNS_RESP_TIMEOUT);
				LIST_DEL(&requester->list);
				LIST_ADDQ(&resolution->requester.wait, &requester->list);
			}
			goto out;
		}

		resolution->try -= 1;

		/* running queue is empty, nothing to do but wait */
		if (LIST_ISEMPTY(&resolution->requester.curr))
			goto out;

		requester = LIST_NEXT(&resolution->requester.curr, struct dns_requester *, list);

		switch (obj_type(requester->requester)) {
			case OBJ_TYPE_SERVER:
				dns_opts = &(objt_server(requester->requester)->dns_opts);
				break;

			case OBJ_TYPE_NONE:
			default:
				/* clean up resolution information and remove from the list */
				dns_reset_resolution(resolution);

				LIST_DEL(&resolution->list);
				LIST_ADDQ(&resolvers->resolution.wait, &resolution->list);

				/* notify the result to the requester */
				requester->requester_error_cb(requester, DNS_RESP_INTERNAL);
				goto out;
		}

		res_preferred_afinet = dns_opts->family_prio == AF_INET && resolution->query_type == DNS_RTYPE_A;
		res_preferred_afinet6 = dns_opts->family_prio == AF_INET6 && resolution->query_type == DNS_RTYPE_AAAA;

		/* let's change the query type if needed */
		if (res_preferred_afinet6) {
			/* fallback from AAAA to A */
			resolution->query_type = DNS_RTYPE_A;
		}
		else if (res_preferred_afinet) {
			/* fallback from A to AAAA */
			resolution->query_type = DNS_RTYPE_AAAA;
		}

		/* resend the DNS query */
		dns_send_query(resolution);

		/* check if we have more than one resolution in the list */
		if (dns_check_resolution_queue(resolvers) > 1) {
			/* move the rsolution to the end of the list */
			LIST_DEL(&resolution->list);
			LIST_ADDQ(&resolvers->resolution.curr, &resolution->list);
		}
	}

 out:
	dns_update_resolvers_timeout(resolvers);
	return t;
}

/*
 * build a dns cache key composed as follow:
 *   <query type>#<hostname in domain name format>
 * and store it into <str>.
 * It's up to the caller to allocate <buf> and to reset it.
 * The function returns NULL in case of error (IE <buf> too small) or a pointer
 * to buf if successful
 */
struct chunk *
dns_cache_key(int query_type, char *hostname_dn, int hostname_dn_len, struct chunk *buf)
{
	int len, size;
	char *str;

	str = buf->str;
	len = buf->len;
	size = buf->size;

	switch (query_type) {
		case DNS_RTYPE_A:
			if (len + 1 > size)
				return NULL;
			memcpy(&str[len], "A", 1);
			len += 1;
			break;
		case DNS_RTYPE_AAAA:
			if (len + 4 > size)
				return NULL;
			memcpy(&str[len], "AAAA", 4);
			len += 4;
			break;
		default:
			return NULL;
	}

	if (len + 1 > size)
		return NULL;
	memcpy(&str[len], "#", 1);
	len += 1;

	if (len + hostname_dn_len + 1 > size) // +1 for trailing zero
		return NULL;
	memcpy(&str[len], hostname_dn, hostname_dn_len);
	len += hostname_dn_len;
	str[len] = '\0';

	return buf;
}

/*
 * returns a pointer to a cache entry which may still be considered as up to date
 * by the caller.
 * returns NULL if no entry can be found or if the data found is outdated.
 */
struct lru64 *
dns_cache_lookup(int query_type, char *hostname_dn, int hostname_dn_len, int valid_period, void *cache_domain) {
	struct lru64 *elem = NULL;
	struct dns_resolution *resolution = NULL;
	struct dns_resolvers *resolvers = NULL;
	struct dns_requester *requester = NULL;
	int inter = 0;
	struct chunk *buf = get_trash_chunk();
	struct chunk *tmp = NULL;

	if (!dns_lru_tree)
		return NULL;

	chunk_reset(buf);
	tmp = dns_cache_key(query_type, hostname_dn, hostname_dn_len, buf);
	if (tmp == NULL)
		return NULL;

	elem = lru64_lookup(XXH64(buf->str, buf->len, 1), dns_lru_tree, cache_domain, 1);

	if (!elem || !elem->data)
		return NULL;

	resolution = elem->data;

	/* since we can change the fqdn of a server at run time, it may happen that
	 * we got an innacurate elem.
	 * This is because resolution->hostname_dn points to (owner)->hostname_dn (which
	 * may be changed at run time)
	 */
	if ((hostname_dn_len == resolution->hostname_dn_len) &&
	    (memcmp(hostname_dn, resolution->hostname_dn, hostname_dn_len) != 0)) {
		return NULL;
	}

	requester = LIST_NEXT(&resolution->requester.wait, struct dns_requester *, list);

	switch (obj_type(requester->requester)) {
		case OBJ_TYPE_SERVER:
			resolvers = objt_server(requester->requester)->resolvers;
			break;
		case OBJ_TYPE_NONE:
		default:
			return NULL;
	}

	if (!resolvers)
		return NULL;

	if (resolvers->hold.valid < valid_period)
		inter = resolvers->hold.valid;
	else
		inter = valid_period;

	if (!tick_is_expired(tick_add(resolution->last_resolution, inter), now_ms))
		return elem;

	return NULL;
}

/* if an arg is found, it sets the resolvers section pointer into cli.p0 */
static int cli_parse_stat_resolvers(char **args, struct appctx *appctx, void *private)
{
	struct dns_resolvers *presolvers;

	if (*args[3]) {
		list_for_each_entry(presolvers, &dns_resolvers, list) {
			if (strcmp(presolvers->id, args[3]) == 0) {
				appctx->ctx.cli.p0 = presolvers;
				break;
			}
		}
		if (appctx->ctx.cli.p0 == NULL) {
			appctx->ctx.cli.msg = "Can't find that resolvers section\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}
	}
	return 0;
}

/*
 * if <resolution> is provided, then the function skips the memory allocation part.
 * It does the linking only.
 *
 * if <resolution> is NULL, the function links a dns resolution to a requester:
 *  - it allocates memory for the struct requester used to link
 *    the resolution to the requester
 *  - it configures the resolution if this is the first requester to be linked to it
 *  - it updates the requester with a pointer to the resolution
 *
 * Return code:
 * -  0 if everything happened smoothly
 * - -1 if an error occured. Of course, no resolution is linked to the requester
 */
int dns_link_resolution(void *requester, int requester_type, struct dns_resolution *resolution)
{
	struct dns_resolution *tmpresolution = NULL;
	struct dns_requester *tmprequester = NULL;
	struct dns_resolvers *resolvers = NULL;
	char *hostname_dn = NULL;
	int new_resolution;

	if (!resolution) {
		tmprequester = calloc(1, sizeof(*tmprequester));
		if (!tmprequester)
			return -1;

		switch (requester_type) {
			case OBJ_TYPE_SERVER:
				tmprequester->requester = &((struct server *)requester)->obj_type;
				hostname_dn = objt_server(tmprequester->requester)->hostname_dn;
				resolvers = objt_server(tmprequester->requester)->resolvers;
				switch (objt_server(tmprequester->requester)->dns_opts.family_prio) {
					case AF_INET:
						tmprequester->prefered_query_type = DNS_RTYPE_A;
						break;
					default:
						tmprequester->prefered_query_type = DNS_RTYPE_AAAA;
				}

				break;
			case OBJ_TYPE_NONE:
			default:
				free(tmprequester);
				return -1;
		}

		/* get a resolution from the resolvers' wait queue or pool */
		tmpresolution = dns_resolution_list_get(resolvers, hostname_dn, tmprequester->prefered_query_type);
		if (!tmpresolution) {
			free(tmprequester);
			return -1;
		}
	}
	else {
		tmpresolution = resolution;

		switch (requester_type) {
			case OBJ_TYPE_SERVER:
				tmprequester = ((struct server *)requester)->dns_requester;
				resolvers = ((struct server *)requester)->resolvers;
				break;
			case OBJ_TYPE_NONE:
			default:
				return -1;
		}
	}

	/* flag this resolution as NEW if applicable (not already linked to any requester).
	 * this is required to decide which parameters we have to update on the resolution.
	 * If new, it means we pulled up the resolution from the resolvers' pool.
	 */
	if (LIST_ISEMPTY(&tmpresolution->requester.wait)) {
		new_resolution = 1;
	}
	else
		new_resolution = 0;

	/* those parameters are related to the requester type */
	switch (obj_type(tmprequester->requester)) {
		case OBJ_TYPE_SERVER:
			/* some parameters should be set only if the resolution is brand new */
			if (new_resolution) {
				tmpresolution->query_type = tmprequester->prefered_query_type;
				tmpresolution->hostname_dn = objt_server(tmprequester->requester)->hostname_dn;
				tmpresolution->hostname_dn_len = objt_server(tmprequester->requester)->hostname_dn_len;
			}

			/* update requester as well, only if we just allocated it */
			objt_server(tmprequester->requester)->resolution = tmpresolution;
			if (!resolution) {
				tmprequester->requester_cb = snr_resolution_cb;
				tmprequester->requester_error_cb = snr_resolution_error_cb;
				objt_server(tmprequester->requester)->dns_requester = tmprequester;
			}
			break;
		case OBJ_TYPE_NONE:
		default:
			free(tmprequester);
			return -1;
	}

	/* update some parameters only if this is a brand new resolution */
	if (new_resolution) {
		/* move the resolution to the requesters' wait queue */
		LIST_DEL(&tmpresolution->list);
		LIST_ADDQ(&resolvers->resolution.wait, &tmpresolution->list);

		tmpresolution->status = RSLV_STATUS_NONE;
		tmpresolution->step = RSLV_STEP_NONE;
		tmpresolution->revision = 1;
	}

	/* add the requester to the resolution's wait queue */
	if (resolution)
		LIST_DEL(&tmprequester->list);
	LIST_ADDQ(&tmpresolution->requester.wait, &tmprequester->list);

	return 0;
}

/*
 * pick up an available resolution from the different resolution list associated to a resolvers section,
 * in this order:
 * 1. check in resolution.curr for the same hostname and query_type
 * 2. check in resolution.wait for the same hostname and query_type
 * 3. take an available resolution from resolution.pool
 *
 * return an available resolution, NULL if none found.
 */
struct dns_resolution *dns_resolution_list_get(struct dns_resolvers *resolvers, char *hostname_dn, int query_type)
{
	struct dns_resolution *resolution, *tmpresolution;
	struct dns_requester *requester;

	/* search for same hostname and query type in resolution.curr */
	list_for_each_entry_safe(resolution, tmpresolution, &resolvers->resolution.curr, list) {
		requester = NULL;

		if (!LIST_ISEMPTY(&resolution->requester.wait))
			requester = LIST_NEXT(&resolution->requester.wait, struct dns_requester *, list);
		else if (!LIST_ISEMPTY(&resolution->requester.curr))
			requester = LIST_NEXT(&resolution->requester.curr, struct dns_requester *, list);

		if (!requester)
			continue;

		if ((query_type == requester->prefered_query_type) &&
		    (strcmp(hostname_dn, resolution->hostname_dn) == 0)) {
			return resolution;
		}
	}

	/* search for same hostname and query type in resolution.wait */
	list_for_each_entry_safe(resolution, tmpresolution, &resolvers->resolution.wait, list) {
		requester = NULL;

		if (!LIST_ISEMPTY(&resolution->requester.wait))
			requester = LIST_NEXT(&resolution->requester.wait, struct dns_requester *, list);
		else if (!LIST_ISEMPTY(&resolution->requester.curr))
			requester = LIST_NEXT(&resolution->requester.curr, struct dns_requester *, list);

		if (!requester)
			continue;

		if ((query_type == requester->prefered_query_type) &&
		    (strcmp(hostname_dn, resolution->hostname_dn) == 0)) {
			return resolution;
		}
	}

	/* take the first one (hopefully) from the pool */
	list_for_each_entry_safe(resolution, tmpresolution, &resolvers->resolution.pool, list) {
		if (LIST_ISEMPTY(&resolution->requester.wait)) {
			return resolution;
		}
	}

	return NULL;
}

/* This function allocates memory for a DNS resolution structure.
 * It's up to the caller to set the parameters
 * Returns a pointer to the structure resolution or NULL if memory could
 * not be allocated.
 */
struct dns_resolution *dns_alloc_resolution(void)
{
	struct dns_resolution *resolution = NULL;
	char *buffer = NULL;

	resolution = calloc(1, sizeof(*resolution));
	buffer = calloc(1, global.tune.bufsize);

	if (!resolution || !buffer) {
		free(buffer);
		free(resolution);
		return NULL;
	}

	chunk_init(&resolution->response_buffer, buffer, global.tune.bufsize);
	LIST_INIT(&resolution->requester.wait);
	LIST_INIT(&resolution->requester.curr);

	return resolution;
}

/* This function free the memory allocated to a DNS resolution */
void dns_free_resolution(struct dns_resolution *resolution)
{
	chunk_destroy(&resolution->response_buffer);
	free(resolution);

	return;
}

/* this function free a resolution from its requester(s) and move it back to the pool */
void dns_resolution_free(struct dns_resolvers *resolvers, struct dns_resolution *resolution)
{
	struct dns_requester *requester, *tmprequester;

	/* clean up configuration */
	dns_reset_resolution(resolution);
	resolution->hostname_dn = NULL;
	resolution->hostname_dn_len = 0;

	list_for_each_entry_safe(requester, tmprequester, &resolution->requester.wait, list) {
		LIST_DEL(&requester->list);
	}
	list_for_each_entry_safe(requester, tmprequester, &resolution->requester.curr, list) {
		LIST_DEL(&requester->list);
	}

	LIST_DEL(&resolution->list);
	LIST_ADDQ(&resolvers->resolution.pool, &resolution->list);

	return;
}

/*
 * this function remove a requester from a resolution
 * and takes care of all the consequences.
 * It also cleans up some parameters from the requester
 */
void dns_rm_requester_from_resolution(struct dns_requester *requester, struct dns_resolution *resolution)
{
	char *hostname_dn;
	struct dns_requester *tmprequester;

	/* resolution is still used by other requesters, we need to move
	 * some pointers to an other requester if needed
	 */
	switch (obj_type(requester->requester)) {
		case OBJ_TYPE_SERVER:
			hostname_dn = objt_server(requester->requester)->hostname_dn;
			break;
		case OBJ_TYPE_NONE:
		default:
			hostname_dn = NULL;
			break;
	}

	if (resolution->hostname_dn != hostname_dn)
		return;

	/* First, we need to find this other requester */
	tmprequester = NULL;
	list_for_each_entry(tmprequester, &resolution->requester.wait, list) {
		if (tmprequester != requester)
			break;
	}
	if (!tmprequester) {
		/* if we can't find it in wait queue, let's get one in run queue */
		list_for_each_entry(tmprequester, &resolution->requester.curr, list) {
			if (tmprequester != requester)
				break;
		}
	}

	/* move hostname_dn related pointers to the next requester */
	switch (obj_type(tmprequester->requester)) {
		case OBJ_TYPE_SERVER:
			resolution->hostname_dn = objt_server(tmprequester->requester)->hostname_dn;
			resolution->hostname_dn_len = objt_server(tmprequester->requester)->hostname_dn_len;
			break;
		case OBJ_TYPE_NONE:
		default:
			;;
	}


	/* clean up the requester */
	LIST_DEL(&requester->list);
	switch (obj_type(requester->requester)) {
		case OBJ_TYPE_SERVER:
			objt_server(requester->requester)->resolution = NULL;
			break;
		case OBJ_TYPE_NONE:
		default:
			;;
	}
}

/* This function dumps counters from all resolvers section and associated name
 * servers. It returns 0 if the output buffer is full and it needs to be called
 * again, otherwise non-zero. It may limit itself to the resolver pointed to by
 * <cli.p0> if it's not null.
 */
static int cli_io_handler_dump_resolvers_to_buffer(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct dns_resolvers *presolvers;
	struct dns_nameserver *pnameserver;

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
			list_for_each_entry(presolvers, &dns_resolvers, list) {
				if (appctx->ctx.cli.p0 != NULL && appctx->ctx.cli.p0 != presolvers)
					continue;

				chunk_appendf(&trash, "Resolvers section %s\n", presolvers->id);
				list_for_each_entry(pnameserver, &presolvers->nameserver_list, list) {
					chunk_appendf(&trash, " nameserver %s:\n", pnameserver->id);
					chunk_appendf(&trash, "  sent: %ld\n", pnameserver->counters.sent);
					chunk_appendf(&trash, "  valid: %ld\n", pnameserver->counters.valid);
					chunk_appendf(&trash, "  update: %ld\n", pnameserver->counters.update);
					chunk_appendf(&trash, "  cname: %ld\n", pnameserver->counters.cname);
					chunk_appendf(&trash, "  cname_error: %ld\n", pnameserver->counters.cname_error);
					chunk_appendf(&trash, "  any_err: %ld\n", pnameserver->counters.any_err);
					chunk_appendf(&trash, "  nx: %ld\n", pnameserver->counters.nx);
					chunk_appendf(&trash, "  timeout: %ld\n", pnameserver->counters.timeout);
					chunk_appendf(&trash, "  refused: %ld\n", pnameserver->counters.refused);
					chunk_appendf(&trash, "  other: %ld\n", pnameserver->counters.other);
					chunk_appendf(&trash, "  invalid: %ld\n", pnameserver->counters.invalid);
					chunk_appendf(&trash, "  too_big: %ld\n", pnameserver->counters.too_big);
					chunk_appendf(&trash, "  truncated: %ld\n", pnameserver->counters.truncated);
					chunk_appendf(&trash, "  outdated: %ld\n", pnameserver->counters.outdated);
				}
			}
		}

		/* display response */
		if (bi_putchk(si_ic(si), &trash) == -1) {
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
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "stat", "resolvers", NULL }, "show stat resolvers [id]: dumps counters from all resolvers section and\n"
	                                         "                          associated name servers",
	                                         cli_parse_stat_resolvers, cli_io_handler_dump_resolvers_to_buffer },
	{{},}
}};


__attribute__((constructor))
static void __dns_init(void)
{
	cli_register_kw(&cli_kws);
}

