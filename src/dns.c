/*
 * Name server resolution
 *
 * Copyright 2020 Haproxy Technologies
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

#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/cli.h>
#include <haproxy/dgram.h>
#include <haproxy/dns.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/log.h>
#include <haproxy/ring.h>

static THREAD_LOCAL char *dns_msg_trash;

/* Opens an UDP socket on the namesaver's IP/Port, if required. Returns 0 on
 * success, -1 otherwise.
 */
static int dns_connect_nameserver(struct dns_nameserver *ns)
{
	if (ns->dgram) {
		struct dgram_conn *dgram = &ns->dgram->conn;
		int fd;

		/* Already connected */
		if (dgram->t.sock.fd != -1)
			return 0;

		/* Create an UDP socket and connect it on the nameserver's IP/Port */
		if ((fd = socket(dgram->addr.to.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			send_log(NULL, LOG_WARNING,
			         "DNS : section '%s': can't create socket for nameserver '%s'.\n",
			         ns->counters->pid, ns->id);
			return -1;
		}
		if (connect(fd, (struct sockaddr*)&dgram->addr.to, get_addr_len(&dgram->addr.to)) == -1) {
			send_log(NULL, LOG_WARNING,
			         "DNS : section '%s': can't connect socket for nameserver '%s'.\n",
			         ns->counters->id, ns->id);
			close(fd);
			return -1;
		}

		/* Make the socket non blocking */
		fcntl(fd, F_SETFL, O_NONBLOCK);

		/* Add the fd in the fd list and update its parameters */
		dgram->t.sock.fd = fd;
		fd_insert(fd, dgram, dgram_fd_handler, MAX_THREADS_MASK);
		fd_want_recv(fd);
	}
	return 0;
}

/* Sends a message to a name server
 * It returns message length on success
 * or -1 in error case
 * 0 is returned in case of output ring buffer is full
 */
int dns_send_nameserver(struct dns_nameserver *ns, void *buf, size_t len)
{
	int ret = -1;

	if (ns->dgram) {
		struct dgram_conn *dgram = &ns->dgram->conn;
		int fd = dgram->t.sock.fd;

		if (dgram->t.sock.fd == -1) {
			if (dns_connect_nameserver(ns) == -1)
				return -1;
			fd = dgram->t.sock.fd;
		}

		ret = send(fd, buf, len, 0);
		if (ret < 0) {
			if (errno == EAGAIN) {
				struct ist myist;

				myist.ptr = buf;
				myist.len = len;
				ret = ring_write(ns->dgram->ring_req, DNS_TCP_MSG_MAX_SIZE, NULL, 0, &myist, 1);
				if (!ret) {
					ns->counters->snd_error++;
					return -1;
				}
				fd_cant_send(fd);
				return ret;
			}
			ns->counters->snd_error++;
			fd_delete(fd);
			close(fd);
			dgram->t.sock.fd = -1;
			return -1;
		}
		ns->counters->sent++;
	}

	return ret;
}

/* Receives a dns message
 * Returns message length
 * 0 is returned if no more message available
 * -1 in error case
 */
ssize_t dns_recv_nameserver(struct dns_nameserver *ns, void *data, size_t size)
{
        ssize_t ret = -1;

	if (ns->dgram) {
		struct dgram_conn *dgram = &ns->dgram->conn;
		int fd = dgram->t.sock.fd;

		if (fd == -1)
			return -1;

		if ((ret = recv(fd, data, size, 0)) < 0) {
			if (errno == EAGAIN) {
				fd_cant_recv(fd);
				return 0;
			}
			fd_delete(fd);
			close(fd);
			dgram->t.sock.fd = -1;
			return -1;
		}
	}

	return ret;
}

static void dns_resolve_recv(struct dgram_conn *dgram)
{
	struct dns_nameserver *ns;
	int fd;

	fd = dgram->t.sock.fd;

	/* check if ready for reading */
	if (!fd_recv_ready(fd))
		return;

	/* no need to go further if we can't retrieve the nameserver */
	if ((ns = dgram->owner) == NULL) {
		_HA_ATOMIC_AND(&fdtab[fd].ev, ~(FD_POLL_HUP|FD_POLL_ERR));
		fd_stop_recv(fd);
		return;
	}

	ns->process_responses(ns);
}

/* Called when a dns network socket is ready to send data */
static void dns_resolve_send(struct dgram_conn *dgram)
{
	int fd;
	struct dns_nameserver *ns;
	struct ring *ring;
	struct buffer *buf;
	uint64_t msg_len;
	size_t len, cnt, ofs;

	fd = dgram->t.sock.fd;

	/* check if ready for sending */
	if (!fd_send_ready(fd))
		return;

	/* no need to go further if we can't retrieve the nameserver */
	if ((ns = dgram->owner) == NULL) {
		_HA_ATOMIC_AND(&fdtab[fd].ev, ~(FD_POLL_HUP|FD_POLL_ERR));
		fd_stop_send(fd);
		return;
	}

	ring = ns->dgram->ring_req;
	buf = &ring->buf;

	HA_RWLOCK_RDLOCK(DNS_LOCK, &ring->lock);
	ofs = ns->dgram->ofs_req;

	/* explanation for the initialization below: it would be better to do
	 * this in the parsing function but this would occasionally result in
	 * dropped events because we'd take a reference on the oldest message
	 * and keep it while being scheduled. Thus instead let's take it the
	 * first time we enter here so that we have a chance to pass many
	 * existing messages before grabbing a reference to a location. This
	 * value cannot be produced after initialization.
	 */
	if (unlikely(ofs == ~0)) {
		ofs = 0;
		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
	}

	/* we were already there, adjust the offset to be relative to
	 * the buffer's head and remove us from the counter.
	 */
	ofs -= ring->ofs;
	BUG_ON(ofs >= buf->size);
	HA_ATOMIC_SUB(b_peek(buf, ofs), 1);

	while (ofs + 1 < b_data(buf)) {
		int ret;

		cnt = 1;
		len = b_peek_varint(buf, ofs + cnt, &msg_len);
		if (!len)
			break;
		cnt += len;
		BUG_ON(msg_len + ofs + cnt + 1 > b_data(buf));
		if (unlikely(msg_len > DNS_TCP_MSG_MAX_SIZE)) {
			/* too large a message to ever fit, let's skip it */
			ofs += cnt + msg_len;
			continue;
		}

		len = b_getblk(buf, dns_msg_trash, msg_len, ofs + cnt);

		ret = send(fd, dns_msg_trash, len, 0);
		if (ret < 0) {
			if (errno == EAGAIN) {
				fd_cant_send(fd);
				goto out;
			}
			ns->counters->snd_error++;
			fd_delete(fd);
			close(fd);
			fd = dgram->t.sock.fd = -1;
			goto out;
		}
		ns->counters->sent++;

		ofs += cnt + len;
	}

	/* we don't want/need to be waked up any more for sending
	 * because all ring content is sent */
	fd_stop_send(fd);

out:

	HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
	ofs += ring->ofs;
	ns->dgram->ofs_req = ofs;
	HA_RWLOCK_RDUNLOCK(DNS_LOCK, &ring->lock);

}

/* proto_udp callback functions for a DNS resolution */
struct dgram_data_cb dns_dgram_cb = {
	.recv = dns_resolve_recv,
	.send = dns_resolve_send,
};

int dns_dgram_init(struct dns_nameserver *ns, struct sockaddr_storage *sk)
{
	struct dns_dgram_server *dgram;

	 if ((dgram = calloc(1, sizeof(*dgram))) == NULL)
		return -1;

	/* Leave dgram partially initialized, no FD attached for
	 * now. */
	dgram->conn.owner     = ns;
	dgram->conn.data      = &dns_dgram_cb;
	dgram->conn.t.sock.fd = -1;
	dgram->conn.addr.to = *sk;
	ns->dgram = dgram;

	dgram->ofs_req = ~0; /* init ring offset */
	dgram->ring_req = ring_new(2*DNS_TCP_MSG_RING_MAX_SIZE);
	if (!dgram->ring_req) {
		ha_alert("memory allocation error initializing the ring for nameserver.\n");
		goto out;
	}

	/* attach the task as reader */
	if (!ring_attach(dgram->ring_req)) {
		/* mark server attached to the ring */
		ha_alert("nameserver sets too many watchers > 255 on ring. This is a bug and should not happen.\n");
		goto out;
	}
	return 0;
out:
	if (dgram->ring_req)
		ring_free(dgram->ring_req);

	free(dgram);

	return -1;
}

int init_dns_buffers()
{
	dns_msg_trash = malloc(DNS_TCP_MSG_MAX_SIZE);
	if (!dns_msg_trash)
		return 0;

        return 1;
}

void deinit_dns_buffers()
{
	free(dns_msg_trash);
	dns_msg_trash = NULL;
}

REGISTER_PER_THREAD_ALLOC(init_dns_buffers);
REGISTER_PER_THREAD_FREE(deinit_dns_buffers);
