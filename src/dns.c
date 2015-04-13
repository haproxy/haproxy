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

#include <types/global.h>
#include <types/dns.h>
#include <types/proto_udp.h>

#include <proto/checks.h>
#include <proto/dns.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/server.h>
#include <proto/task.h>
#include <proto/proto_udp.h>

struct list dns_resolvers = LIST_HEAD_INIT(dns_resolvers);
struct dns_resolution *resolution = NULL;

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
	resolution->query_type = DNS_RTYPE_ANY;

	/* the second resolution in the queue becomes the first one */
	LIST_DEL(&resolution->list);
}

/*
 * function called when a network IO is generated on a name server socket for an incoming packet
 * It performs the following actions:
 *  - check if the packet requires processing (not outdated resolution)
 *  - ensure the DNS packet received is valid and call requester's callback
 *  - call requester's error callback if invalid response
 */
void dns_resolve_recv(struct dgram_conn *dgram)
{
	struct dns_nameserver *nameserver;
	struct dns_resolvers *resolvers;
	struct dns_resolution *resolution;
	unsigned char buf[DNS_MAX_UDP_MESSAGE + 1];
	unsigned char *bufend;
	int fd, buflen, ret;
	unsigned short query_id;
	struct eb32_node *eb;

	fd = dgram->t.sock.fd;

	/* check if ready for reading */
	if (!fd_recv_ready(fd))
		return;

	/* no need to go further if we can't retrieve the nameserver */
	if ((nameserver = (struct dns_nameserver *)dgram->owner) == NULL)
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
		if ((eb = eb32_lookup(&resolvers->query_ids, query_id)) == NULL) {
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

		ret = dns_validate_dns_response(buf, bufend, resolution->hostname_dn, resolution->hostname_dn_len);

		/* treat only errors */
		switch (ret) {
		case DNS_RESP_INVALID:
		case DNS_RESP_WRONG_NAME:
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

		}

		resolution->requester_cb(resolution, nameserver, buf, buflen);
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
	if ((nameserver = (struct dns_nameserver *)dgram->owner) == NULL)
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
	int ret, send_error, bufsize, fd;

	resolvers = resolution->resolvers;

	ret = send_error = 0;
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
	resolution->try += 1;
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
 * Function to validate that the buffer DNS response provided in <resp> and
 * finishing before <bufend> is valid from a DNS protocol point of view.
 * The caller can also ask the function to check if the response contains data
 * for a domain name <dn_name> whose length is <dn_name_len> returns one of the
 * DNS_RESP_* code.
 */
int dns_validate_dns_response(unsigned char *resp, unsigned char *bufend, char *dn_name, int dn_name_len)
{
	unsigned char *reader, *cname, *ptr;
	int i, len, type, ancount, cnamelen;

	reader = resp;
	cname = NULL;
	cnamelen = 0;
	len = 0;

	/* move forward 2 bytes for the query id */
	reader += 2;
	if (reader >= bufend)
		return DNS_RESP_INVALID;

	/*
	 * analyzing flags
	 * 1st byte can be ignored for now
	 * rcode is at the beginning of the second byte
	 */
	reader += 1;
	if (reader >= bufend)
		return DNS_RESP_INVALID;

	/*
	 * rcode is 4 latest bits
	 * ignore response if it contains an error
	 */
	if ((*reader & 0x0f) != DNS_RCODE_NO_ERROR) {
		if ((*reader & 0x0f) == DNS_RCODE_NX_DOMAIN)
			return DNS_RESP_NX_DOMAIN;
		else if ((*reader & 0x0f) == DNS_RCODE_REFUSED)
			return DNS_RESP_REFUSED;

		return DNS_RESP_ERROR;
	}

	/* move forward 1 byte for rcode */
	reader += 1;
	if (reader >= bufend)
		return DNS_RESP_INVALID;

	/* move forward 2 bytes for question count */
	reader += 2;
	if (reader >= bufend)
		return DNS_RESP_INVALID;

	/* analyzing answer count */
	if (reader + 2 > bufend)
		return DNS_RESP_INVALID;
	ancount = reader[0] * 256 + reader[1];

	if (ancount == 0)
		return DNS_RESP_ANCOUNT_ZERO;

	/* move forward 2 bytes for answer count */
	reader += 2;
	if (reader >= bufend)
		return DNS_RESP_INVALID;

	/* move forward 4 bytes authority and additional count */
	reader += 4;
	if (reader >= bufend)
		return DNS_RESP_INVALID;

	/* check if the name can stand in response */
	if (dn_name && ((reader + dn_name_len + 1) > bufend))
		return DNS_RESP_INVALID;

	/* check hostname */
	if (dn_name && (memcmp(reader, dn_name, dn_name_len) != 0))
		return DNS_RESP_WRONG_NAME;

	/* move forward hostname len bytes + 1 for NULL byte */
	if (dn_name) {
		reader = reader + dn_name_len + 1;
	}
	else {
		ptr = reader;
		while (*ptr) {
			ptr++;
			if (ptr >= bufend)
				return DNS_RESP_INVALID;
		}
		reader = ptr + 1;
	}

	/* move forward 4 bytes for question type and question class */
	reader += 4;
	if (reader >= bufend)
		return DNS_RESP_INVALID;

	/* now parsing response records */
	for (i = 1; i <= ancount; i++) {
		if (reader >= bufend)
			return DNS_RESP_INVALID;

		/*
		 * name can be a pointer, so move forward reader cursor accordingly
		 * if 1st byte is '11XXXXXX', it means name is a pointer
		 * and 2nd byte gives the offset from resp where the hostname can
		 * be found
		 */
		if ((*reader & 0xc0) == 0xc0) {
			/*
			 * pointer, hostname can be found at resp + *(reader + 1)
			 */
			if (reader + 1 > bufend)
				return DNS_RESP_INVALID;

			ptr = resp + *(reader + 1);

			/* check if the pointer points inside the buffer */
			if (ptr >= bufend)
				return DNS_RESP_INVALID;
		}
		else {
			/*
			 * name is a string which starts at first byte
			 * checking against last cname when recursing through the response
			 */
			/* look for the end of the string and ensure it's in the buffer */
			ptr = reader;
			len = 0;
			while (*ptr) {
				++len;
				++ptr;
				if (ptr >= bufend)
					return DNS_RESP_INVALID;
			}

			/* if cname is set, it means a CNAME recursion is in progress */
			ptr = reader;
		}

		/* ptr now points to the name */
		/* if cname is set, it means a CNAME recursion is in progress */
		if (cname) {
			/* check if the name can stand in response */
			if ((reader + cnamelen) > bufend)
				return DNS_RESP_INVALID;
			/* compare cname and current name */
			if (memcmp(ptr, cname, cnamelen) != 0)
				return DNS_RESP_CNAME_ERROR;
		}
		/* compare server hostname to current name */
		else if (dn_name) {
			/* check if the name can stand in response */
			if ((reader + dn_name_len) > bufend)
				return DNS_RESP_INVALID;
			if (memcmp(ptr, dn_name, dn_name_len) != 0)
				return DNS_RESP_WRONG_NAME;
		}

		if ((*reader & 0xc0) == 0xc0) {
			/* move forward 2 bytes for information pointer and address pointer */
			reader += 2;
		}
		else {
			if (cname) {
				cname = reader;
				cnamelen = dns_str_to_dn_label_len((const char *)cname);

				/* move forward cnamelen bytes + NULL byte */
				reader += (cnamelen + 1);
			}
			else {
				reader += (len + 1);
			}
		}
		if (reader >= bufend)
			return DNS_RESP_INVALID;

		/*
		 * we know the record is either for our server hostname
		 * or a valid CNAME in a crecursion
		 */

		/* now reading record type (A, AAAA, CNAME, etc...) */
		if (reader + 2 > bufend)
			return DNS_RESP_INVALID;
		type = reader[0] * 256 + reader[1];

		/* move forward 2 bytes for type (2) */
		reader += 2;

		/* move forward 6 bytes for class (2) and ttl (4) */
		reader += 6;
		if (reader >= bufend)
			return DNS_RESP_INVALID;

		/* now reading data len */
		if (reader + 2 > bufend)
			return DNS_RESP_INVALID;
		len = reader[0] * 256 + reader[1];

		/* move forward 2 bytes for data len */
		reader += 2;

		/* analyzing record content */
		switch (type) {
			case DNS_RTYPE_A:
				/* ipv4 is stored on 4 bytes */
				if (len != 4)
					return DNS_RESP_INVALID;
				break;

			case DNS_RTYPE_CNAME:
				cname = reader;
				cnamelen = len;
				break;

			case DNS_RTYPE_AAAA:
				/* ipv6 is stored on 16 bytes */
				if (len != 16)
					return DNS_RESP_INVALID;
				break;
		} /* switch (record type) */

		/* move forward len for analyzing next record in the response */
		reader += len;
	} /* for i 0 to ancount */

	return DNS_RESP_VALID;
}

/*
 * search dn_name resolution in resp.
 * If existing IP not found, return the first IP matching family_priority,
 * otherwise, first ip found
 * The following tasks are the responsibility of the caller:
 *   - resp contains an error free DNS response
 *   - the response matches the dn_name
 * For both cases above, dns_validate_dns_response is required
 * returns one of the DNS_UPD_* code
 */
int dns_get_ip_from_response(unsigned char *resp, unsigned char *resp_end,
		char *dn_name, int dn_name_len, void *currentip, short currentip_sin_family,
		int family_priority, void **newip, short *newip_sin_family)
{
	int i, ancount, cnamelen, type, data_len, currentip_found;
	unsigned char *reader, *cname, *ptr, *newip4, *newip6;

	cname = *newip = newip4 = newip6 = NULL;
	cnamelen = currentip_found = 0;
	*newip_sin_family = AF_UNSPEC;
	ancount = (((struct dns_header *)resp)->ancount);
	ancount = *(resp + 7);

	/* bypass DNS response header */
	reader = resp + sizeof(struct dns_header);

	/* bypass DNS query section */
	/* move forward hostname len bytes + 1 for NULL byte */
	reader = reader + dn_name_len + 1;

	/* move forward 4 bytes for question type and question class */
	reader += 4;

	/* now parsing response records */
	for (i = 1; i <= ancount; i++) {
		/*
		 * name can be a pointer, so move forward reader cursor accordingly
		 * if 1st byte is '11XXXXXX', it means name is a pointer
		 * and 2nd byte gives the offset from buf where the hostname can
		 * be found
		 */
		if ((*reader & 0xc0) == 0xc0)
			ptr = resp + *(reader + 1);
		else
			ptr = reader;

		if (cname && memcmp(ptr, cname, cnamelen))
			return DNS_UPD_NAME_ERROR;
		else if (memcmp(ptr, dn_name, dn_name_len))
			return DNS_UPD_NAME_ERROR;

		if ((*reader & 0xc0) == 0xc0) {
			/* move forward 2 bytes for information pointer and address pointer */
			reader += 2;
		}
		else {
			if (cname) {
				cname = reader;
				cnamelen = dns_str_to_dn_label_len((char *)cname);

				/* move forward cnamelen bytes + NULL byte */
				reader += (cnamelen + 1);
			}
			else {
				/* move forward dn_name_len bytes + NULL byte */
				reader += (dn_name_len + 1);
			}
		}

		/*
		 * we know the record is either for our server hostname
		 * or a valid CNAME in a crecursion
		 */

		/* now reading record type (A, AAAA, CNAME, etc...) */
		type = reader[0] * 256 + reader[1];

		/* move forward 2 bytes for type (2) */
		reader += 2;

		/* move forward 6 bytes for class (2) and ttl (4) */
		reader += 6;

		/* now reading data len */
		data_len = reader[0] * 256 + reader[1];

		/* move forward 2 bytes for data len */
		reader += 2;

		/* analyzing record content */
		switch (type) {
			case DNS_RTYPE_A:
				/* check if current reccord's IP is the same as server one's */
				if ((currentip_sin_family == AF_INET)
						&& (*(uint32_t *)reader == *(uint32_t *)currentip)) {
					currentip_found = 1;
					newip4 = reader;
					/* we can stop now if server's family preference is IPv4
					 * and its current IP is found in the response list */
					if (family_priority == AF_INET)
						return DNS_UPD_NO; /* DNS_UPD matrix #1 */
				}
				else if (!newip4) {
					newip4 = reader;
				}

				/* move forward data_len for analyzing next record in the response */
				reader += data_len;
				break;

			case DNS_RTYPE_CNAME:
				cname = reader;
				cnamelen = data_len;

				reader += data_len;
				break;

			case DNS_RTYPE_AAAA:
				/* check if current record's IP is the same as server's one */
				if ((currentip_sin_family == AF_INET6) && (memcmp(reader, currentip, 16) == 0)) {
					currentip_found = 1;
					newip6 = reader;
					/* we can stop now if server's preference is IPv6 or is not
					 * set (which implies we prioritize IPv6 over IPv4 */
					if (family_priority == AF_INET6)
						return DNS_UPD_NO;
				}
				else if (!newip6) {
					newip6 = reader;
				}

				/* move forward data_len for analyzing next record in the response */
				reader += data_len;
				break;

			default:
				/* not supported record type */
				/* move forward data_len for analyzing next record in the response */
				reader += data_len;
		} /* switch (record type) */
	} /* for i 0 to ancount */

	/* only CNAMEs in the response, no IP found */
	if (cname && !newip4 && !newip6) {
		return DNS_UPD_CNAME;
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
int dns_response_get_query_id(unsigned char *resp)
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
	int fd;

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
			if ((dgram = calloc(1, sizeof(struct dgram_conn))) == NULL) {
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
			if (connect(fd, (struct sockaddr*)&curnameserver->addr, sizeof(curnameserver->addr)) == -1) {
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
	struct dns_question *qinfo;
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
	dns->qr = 0;			/* query */
	dns->opcode = 0;
	dns->aa = 0;
	dns->tc = 0;
	dns->rd = 1;			/* recursion desired */
	dns->ra = 0;
	dns->z = 0;
	dns->rcode = 0;
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
	qinfo = (struct dns_question *)ptr;
	qinfo->qtype = htons(query_type);
	qinfo->qclass = htons(DNS_RCLASS_IN);

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
char *dns_str_to_dn_label(char *string, char *dn, int dn_len)
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

	i = strlen(string) + offset;
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
		if (resolution->try >= resolvers->resolve_retries) {
			/* clean up resolution information and remove from the list */
			dns_reset_resolution(resolution);

			/* notify the result to the requester */
			resolution->requester_error_cb(resolution, DNS_RESP_TIMEOUT);
		}

		/* check current resolution status */
		if (resolution->step == RSLV_STEP_RUNNING) {
			/* resend the DNS query */
			dns_send_query(resolution);

			/* check if we have more than one resolution in the list */
			if (dns_check_resolution_queue(resolvers) > 1) {
				/* move the rsolution to the end of the list */
				LIST_DEL(&resolution->list);
				LIST_ADDQ(&resolvers->curr_resolution, &resolution->list);
			}
		}
	}

 out:
	dns_update_resolvers_timeout(resolvers);
	return t;
}
