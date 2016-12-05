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

/*
 * pre-allocated memory for maximum record names in a DNS response
 * Each name is DNS_MAX_NAME_SIZE, we add 1 for the NULL character
 *
 * WARNING: this is not thread safe...
 */
struct dns_response_packet dns_response;
struct chunk dns_trash = { };
struct dns_query_item dns_query_records[DNS_MAX_QUERY_RECORDS];
struct dns_answer_item dns_answer_records[DNS_MAX_ANSWER_RECORDS];

static int64_t dns_query_id_seed;	/* random seed */

/* proto_udp callback functions for a DNS resolution */
struct dgram_data_cb resolve_dgram_cb = {
	.recv = dns_resolve_recv,
	.send = dns_resolve_send,
};

#if DEBUG
/*
 * go through the resolutions associated to a resolvers section and print the ID and hostname in
 * domain name format
 * should be used for debug purpose only
 */
void dns_print_current_resolutions(struct dns_resolvers *resolvers)
{
	list_for_each_entry(resolution, &resolvers->curr_resolution, list) {
		printf("  resolution %d for %s\n", resolution->query_id, resolution->hostname_dn);
	}
}
#endif

/*
 * check if there is more than 1 resolution in the resolver's resolution list
 * return value:
 * 0: empty list
 * 1: exactly one entry in the list
 * 2: more than one entry in the list
 */
int dns_check_resolution_queue(struct dns_resolvers *resolvers)
{

	if (LIST_ISEMPTY(&resolvers->curr_resolution))
		return 0;

	if ((resolvers->curr_resolution.n) && (resolvers->curr_resolution.n == resolvers->curr_resolution.p))
		return 1;

	if (! ((resolvers->curr_resolution.n == resolvers->curr_resolution.p)
			&& (&resolvers->curr_resolution != resolvers->curr_resolution.n)))
		return 2;

	return 0;
}

/*
 * reset all parameters of a DNS resolution to 0 (or equivalent)
 * and clean it up from all associated lists (resolution->qid and resolution->list)
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

	/* default values */
	if (resolution->opts->family_prio == AF_INET) {
		resolution->query_type = DNS_RTYPE_A;
	} else {
		resolution->query_type = DNS_RTYPE_AAAA;
	}

	/* the second resolution in the queue becomes the first one */
	LIST_DEL(&resolution->list);
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
	struct dns_nameserver *nameserver;
	struct dns_resolvers *resolvers;
	struct dns_resolution *resolution;
	struct dns_query_item *query;
	unsigned char buf[DNS_MAX_UDP_MESSAGE + 1];
	unsigned char *bufend;
	int fd, buflen, ret;
	unsigned short query_id;
	struct eb32_node *eb;
	struct dns_response_packet *dns_p = &dns_response;

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

		ret = dns_validate_dns_response(buf, bufend, dns_p);

		/* treat only errors */
		switch (ret) {
		case DNS_RESP_QUERY_COUNT_ERROR:
		case DNS_RESP_INVALID:
			nameserver->counters.invalid += 1;
			resolution->requester_error_cb(resolution, DNS_RESP_INVALID);
			continue;

		case DNS_RESP_ERROR:
			nameserver->counters.other += 1;
			resolution->requester_error_cb(resolution, DNS_RESP_ERROR);
			continue;

		case DNS_RESP_ANCOUNT_ZERO:
			nameserver->counters.any_err += 1;
			resolution->requester_error_cb(resolution, DNS_RESP_ANCOUNT_ZERO);
			continue;

		case DNS_RESP_NX_DOMAIN:
			nameserver->counters.nx += 1;
			resolution->requester_error_cb(resolution, DNS_RESP_NX_DOMAIN);
			continue;

		case DNS_RESP_REFUSED:
			nameserver->counters.refused += 1;
			resolution->requester_error_cb(resolution, DNS_RESP_REFUSED);
			continue;

		case DNS_RESP_CNAME_ERROR:
			nameserver->counters.cname_error += 1;
			resolution->requester_error_cb(resolution, DNS_RESP_CNAME_ERROR);
			continue;

		case DNS_RESP_TRUNCATED:
			nameserver->counters.truncated += 1;
			resolution->requester_error_cb(resolution, DNS_RESP_TRUNCATED);
			continue;

		case DNS_RESP_NO_EXPECTED_RECORD:
			nameserver->counters.other += 1;
			resolution->requester_error_cb(resolution, DNS_RESP_NO_EXPECTED_RECORD);
			continue;
		}

		/* Now let's check the query's dname corresponds to the one we sent.
		 * We can check only the first query of the list. We send one query at a time
		 * so we get one query in the response */
		query = LIST_NEXT(&dns_p->query_list, struct dns_query_item *, list);
		if (query && memcmp(query->name, resolution->hostname_dn, resolution->hostname_dn_len) != 0) {
			nameserver->counters.other += 1;
			resolution->requester_error_cb(resolution, DNS_RESP_WRONG_NAME);
			continue;
		}

		nameserver->counters.valid += 1;
		resolution->requester_cb(resolution, nameserver, dns_p);
	}
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
	resolution = LIST_NEXT(&resolvers->curr_resolution, struct dns_resolution *, list);

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
	struct dns_resolvers *resolvers;
	struct dns_nameserver *nameserver;
	int ret, bufsize, fd;

	resolvers = resolution->resolvers;

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

	if (LIST_ISEMPTY(&resolvers->curr_resolution)) {
		/* no more resolution pending, so no wakeup anymore */
		resolvers->t->expire = TICK_ETERNITY;
	}
	else {
		resolution = LIST_NEXT(&resolvers->curr_resolution, struct dns_resolution *, list);
		resolvers->t->expire = tick_add(resolution->last_sent_packet, resolvers->timeout.retry);
	}
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
 * The result is stored in the structured pointed by <dns_p>.
 * It's up to the caller to allocate memory for <dns_p>.
 *
 * This function returns one of the DNS_RESP_* code to indicate the type of
 * error found.
 */
int dns_validate_dns_response(unsigned char *resp, unsigned char *bufend, struct dns_response_packet *dns_p)
{
	unsigned char *reader;
	char *previous_dname, tmpname[DNS_MAX_NAME_SIZE];
	int len, flags, offset, ret;
	int dns_query_record_id, dns_answer_record_id;
	struct dns_query_item *dns_query;
	struct dns_answer_item *dns_answer_record;

	reader = resp;
	len = 0;
	previous_dname = NULL;

	/* initialization of local buffer */
	memset(dns_p, '\0', sizeof(struct dns_response_packet));
	chunk_reset(&dns_trash);

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
		dns_query = &dns_query_records[dns_query_record_id];
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
	for (dns_answer_record_id = 0; dns_answer_record_id < dns_p->header.ancount; dns_answer_record_id++) {
		if (reader >= bufend)
			return DNS_RESP_INVALID;

		/* pull next response record from the list, if still one available, then add it
		 * to the record list */
		if (dns_answer_record_id > DNS_MAX_ANSWER_RECORDS)
			return DNS_RESP_INVALID;
		dns_answer_record = &dns_answer_records[dns_answer_record_id];
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

		dns_answer_record->name = chunk_newstr(&dns_trash);
		if (dns_answer_record->name == NULL)
			return DNS_RESP_INVALID;

		ret = chunk_strncat(&dns_trash, tmpname, len);
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

				dns_answer_record->target = chunk_newstr(&dns_trash);
				if (dns_answer_record->target == NULL)
					return DNS_RESP_INVALID;

				ret = chunk_strncat(&dns_trash, tmpname, len);
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

		/* move forward dns_answer_record->data_len for analyzing next record in the response */
		reader += dns_answer_record->data_len;
	} /* for i 0 to ancount */

	/* let's add a last \0 to close our last string */
	ret = chunk_strncat(&dns_trash, "\0", 1);
	if (ret == 0)
		return DNS_RESP_INVALID;

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
                             struct dns_resolution *resol, void *currentip,
                             short currentip_sin_family,
                             void **newip, short *newip_sin_family)
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

	family_priority = resol->opts->family_prio;
	*newip = newip4 = newip6 = NULL;
	currentip_found = 0;
	*newip_sin_family = AF_UNSPEC;

	/* now parsing response records */
	list_for_each_entry(record, &dns_response.answer_list, list) {
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
	 *  4 - prefered netwok ip version.
	 *  2 - prefered network.
	 *  1 - current ip.
	 * The result with the biggest score is returned.
	 */
	max_score = -1;
	for (i = 0; i < rec_nb; i++) {

		score = 0;

		/* Check for prefered ip protocol. */
		if (rec[i].type == family_priority)
			score += 4;

		/* Check for prefered network. */
		for (j = 0; j < resol->opts->pref_net_nb; j++) {

			/* Compare only the same adresses class. */
			if (resol->opts->pref_net[j].family != rec[i].type)
				continue;

			if ((rec[i].type == AF_INET &&
			     in_net_ipv4(rec[i].ip,
			                 &resol->opts->pref_net[j].mask.in4,
			                 &resol->opts->pref_net[j].addr.in4)) ||
			    (rec[i].type == AF_INET6 &&
			     in_net_ipv6(rec[i].ip,
			                 &resol->opts->pref_net[j].mask.in6,
			                 &resol->opts->pref_net[j].addr.in6))) {
				score += 2;
				break;
			}
		}

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
		 * score. The maximum score is 7, if this value is reached,
		 * we break the parsing. Implicitly, this score is reached
		 * the ip selected is the current ip.
		 */
		if (score > max_score) {
			if (rec[i].type == AF_INET)
				newip4 = rec[i].ip;
			else
				newip6 = rec[i].ip;
			currentip_found = currentip_sel;
			if (score == 7)
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
			return DNS_UPD_SRVIP_NOT_FOUND;
		}
		else if (newip6) {
			*newip = newip6;
			*newip_sin_family = AF_INET6;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			return DNS_UPD_SRVIP_NOT_FOUND;
		}
	}
	/* case when the caller looks first for an IPv6 address */
	else if (family_priority == AF_INET6) {
		if (newip6) {
			*newip = newip6;
			*newip_sin_family = AF_INET6;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			return DNS_UPD_SRVIP_NOT_FOUND;
		}
		else if (newip4) {
			*newip = newip4;
			*newip_sin_family = AF_INET;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			return DNS_UPD_SRVIP_NOT_FOUND;
		}
	}
	/* case when the caller have no preference (we prefer IPv6) */
	else if (family_priority == AF_UNSPEC) {
		if (newip6) {
			*newip = newip6;
			*newip_sin_family = AF_INET6;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			return DNS_UPD_SRVIP_NOT_FOUND;
		}
		else if (newip4) {
			*newip = newip4;
			*newip_sin_family = AF_INET;
			if (currentip_found == 1)
				return DNS_UPD_NO;
			return DNS_UPD_SRVIP_NOT_FOUND;
		}
	}

	/* no reason why we should change the server's IP address */
	return DNS_UPD_NO;
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
 * returns:
 *  0 in case of error
 *  1 when no error
 */
int dns_init_resolvers(void)
{
	struct dns_resolvers *curr_resolvers;
	struct dns_nameserver *curnameserver;
	struct dgram_conn *dgram;
	struct task *t;
	char *dns_trash_str;
	int fd;

	dns_trash_str = malloc(global.tune.bufsize);
	if (dns_trash_str == NULL) {
		Alert("Starting resolvers: out of memory.\n");
		return 0;
	}

	/* allocate memory for the dns_trash buffer used to temporarily store
	 * the records of the received response */
	chunk_init(&dns_trash, dns_trash_str, global.tune.bufsize);

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
		t->expire = TICK_ETERNITY;

		curr_resolvers->t = t;

		list_for_each_entry(curnameserver, &curr_resolvers->nameserver_list, list) {
			if ((dgram = calloc(1, sizeof(*dgram))) == NULL) {
				Alert("Starting [%s/%s] nameserver: out of memory.\n", curr_resolvers->id,
						curnameserver->id);
				return 0;
			}
			/* update datagram's parameters */
			dgram->owner = (void *)curnameserver;
			dgram->data = &resolve_dgram_cb;

			/* create network UDP socket for this nameserver */
			if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
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

		/* task can be queued */
		task_queue(t);
	}

	return 1;
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

	/* timeout occurs inevitably for the first element of the FIFO queue */
	if (LIST_ISEMPTY(&resolvers->curr_resolution)) {
		/* no first entry, so wake up was useless */
		t->expire = TICK_ETERNITY;
		return t;
	}

	/* look for the first resolution which is not expired */
	list_for_each_entry_safe(resolution, res_back, &resolvers->curr_resolution, list) {
		/* when we find the first resolution in the future, then we can stop here */
		if (tick_is_le(now_ms, resolution->last_sent_packet))
			goto out;

		/*
		 * if current resolution has been tried too many times and finishes in timeout
		 * we update its status and remove it from the list
		 */
		if (resolution->try <= 0) {
			/* clean up resolution information and remove from the list */
			dns_reset_resolution(resolution);

			/* notify the result to the requester */
			resolution->requester_error_cb(resolution, DNS_RESP_TIMEOUT);
			goto out;
		}

		resolution->try -= 1;

		res_preferred_afinet = resolution->opts->family_prio == AF_INET && resolution->query_type == DNS_RTYPE_A;
		res_preferred_afinet6 = resolution->opts->family_prio == AF_INET6 && resolution->query_type == DNS_RTYPE_AAAA;

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
			LIST_ADDQ(&resolvers->curr_resolution, &resolution->list);
		}
	}

 out:
	dns_update_resolvers_timeout(resolvers);
	return t;
}

static int cli_parse_stat_resolvers(char **args, struct appctx *appctx, void *private)
{
	struct dns_resolvers *presolvers;

	if (*args[3]) {
		appctx->ctx.resolvers.ptr = NULL;
		list_for_each_entry(presolvers, &dns_resolvers, list) {
			if (strcmp(presolvers->id, args[3]) == 0) {
				appctx->ctx.resolvers.ptr = presolvers;
				break;
			}
		}
		if (appctx->ctx.resolvers.ptr == NULL) {
			appctx->ctx.cli.msg = "Can't find that resolvers section\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}
	}
	return 0;
}

/* This function dumps counters from all resolvers section and associated name servers.
 * It returns 0 if the output buffer is full and it needs
 * to be called again, otherwise non-zero.
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
				if (appctx->ctx.resolvers.ptr != NULL && appctx->ctx.resolvers.ptr != presolvers)
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

