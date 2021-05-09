/*
 * Name server resolution
 *
 * Copyright 2020 HAProxy Technologies
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
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/tools.h>

static THREAD_LOCAL char *dns_msg_trash;

DECLARE_STATIC_POOL(dns_session_pool, "dns_session", sizeof(struct dns_session));
DECLARE_STATIC_POOL(dns_query_pool, "dns_query", sizeof(struct dns_query));
DECLARE_STATIC_POOL(dns_msg_buf, "dns_msg_buf", DNS_TCP_MSG_RING_MAX_SIZE);

/* Opens an UDP socket on the namesaver's IP/Port, if required. Returns 0 on
 * success, -1 otherwise. ns->dgram must be defined.
 */
static int dns_connect_nameserver(struct dns_nameserver *ns)
{
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

				myist = ist2(buf, len);
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
			dgram->t.sock.fd = -1;
			return -1;
		}
		ns->counters->sent++;
	}
	else if (ns->stream) {
		struct ist myist;

		myist = ist2(buf, len);
                ret = ring_write(ns->stream->ring_req, DNS_TCP_MSG_MAX_SIZE, NULL, 0, &myist, 1);
		if (!ret) {
			ns->counters->snd_error++;
			return -1;
		}
		task_wakeup(ns->stream->task_req, TASK_WOKEN_MSG);
		return ret;
	}

	return ret;
}

void dns_session_free(struct dns_session *);

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
			dgram->t.sock.fd = -1;
			return -1;
		}
	}
	else if (ns->stream) {
		struct dns_stream_server *dss = ns->stream;
		struct dns_session *ds;

		HA_SPIN_LOCK(DNS_LOCK, &dss->lock);

		if (!LIST_ISEMPTY(&dss->wait_sess)) {
			ds = LIST_NEXT(&dss->wait_sess, struct dns_session *, waiter);
			fprintf(stderr, "ds: %p\n", ds);
			ret = ds->rx_msg.len < size ? ds->rx_msg.len : size;
			memcpy(data, ds->rx_msg.area, ret);

			ds->rx_msg.len = 0;

			/* This barrier is here to ensure that all data is
			 * stored if the appctx detect the elem is out of the list */
			__ha_barrier_store();

			LIST_DEL_INIT(&ds->waiter);

			if (ds->appctx) {
				/* This second barrier is here to ensure that
				 * the waked up appctx won't miss that the
				 * elem is removed from the list */
				__ha_barrier_store();

				/* awake appctx because it may have other
				 * message to receive
				 */
				appctx_wakeup(ds->appctx);

				/* dns_session could already be into free_sess list
				 * so we firstly remove it */
				LIST_DEL_INIT(&ds->list);

				/* decrease nb_queries to free a slot for a new query on that sess */
				ds->nb_queries--;
				if (ds->nb_queries) {
					/* it remains pipelined unanswered request
					 * into this session but we just decrease
					 * the counter so the session
					 * can not be full of pipelined requests
					 * so we can add if to free_sess list
					 * to receive a new request
					*/
					LIST_INSERT(&ds->dss->free_sess, &ds->list);
				}
				else {
					/* there is no more pipelined requests
					 * into this session, so we move it
					 * to idle_sess list */
					LIST_INSERT(&ds->dss->idle_sess, &ds->list);

					/* update the counter of idle sessions */
					ds->dss->idle_conns++;

					/* Note: this is useless there to update
					 * the max_active_conns since we increase
					 * the idle count */
				}
			}
			else {
				/* there is no more appctx for this session
				 * it means it is ready to die
				 */
				dns_session_free(ds);
			}


		}

		HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
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
		_HA_ATOMIC_AND(&fdtab[fd].state, ~(FD_POLL_HUP|FD_POLL_ERR));
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
		_HA_ATOMIC_AND(&fdtab[fd].state, ~(FD_POLL_HUP|FD_POLL_ERR));
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
		HA_ATOMIC_INC(b_peek(buf, ofs));
		ofs += ring->ofs;
	}

	/* we were already there, adjust the offset to be relative to
	 * the buffer's head and remove us from the counter.
	 */
	ofs -= ring->ofs;
	BUG_ON(ofs >= buf->size);
	HA_ATOMIC_DEC(b_peek(buf, ofs));

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

	HA_ATOMIC_INC(b_peek(buf, ofs));
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

/*
 * IO Handler to handle message push to dns tcp server
 */
static void dns_session_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct dns_session *ds = appctx->ctx.sft.ptr;
	struct ring *ring = &ds->ring;
	struct buffer *buf = &ring->buf;
	uint64_t msg_len;
	int available_room;
	size_t len, cnt, ofs;
	int ret = 0;

	/* if stopping was requested, close immediately */
	if (unlikely(stopping))
		goto close;

	/* we want to be sure to not miss that we have been awaked for a shutdown */
	__ha_barrier_load();

	/* that means the connection was requested to shutdown
	 * for instance idle expire */
	if (ds->shutdown)
		goto close;

	/* an error was detected */
	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		goto close;

	/* con closed by server side, we will skip data write and drain data from channel */
	if ((si_oc(si)->flags & CF_SHUTW)) {
		goto read;
	}

	/* if the connection is not established, inform the stream that we want
	 * to be notified whenever the connection completes.
	 */
	if (si_opposite(si)->state < SI_ST_EST) {
		si_cant_get(si);
		si_rx_conn_blk(si);
		si_rx_endp_more(si);
		return;
	}


	ofs = ds->ofs;

	HA_RWLOCK_WRLOCK(DNS_LOCK, &ring->lock);
	LIST_DEL_INIT(&appctx->wait_entry);
	HA_RWLOCK_WRUNLOCK(DNS_LOCK, &ring->lock);

	HA_RWLOCK_RDLOCK(DNS_LOCK, &ring->lock);

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

		HA_ATOMIC_INC(b_peek(buf, ofs));
		ofs += ring->ofs;
	}

	/* in this loop, ofs always points to the counter byte that precedes
	 * the message so that we can take our reference there if we have to
	 * stop before the end (ret=0).
	 */
	if (si_opposite(si)->state == SI_ST_EST) {
		/* we were already there, adjust the offset to be relative to
		 * the buffer's head and remove us from the counter.
		 */
		ofs -= ring->ofs;
		BUG_ON(ofs >= buf->size);
		HA_ATOMIC_DEC(b_peek(buf, ofs));

		ret = 1;
		while (ofs + 1 < b_data(buf)) {
			struct dns_query *query;
			uint16_t original_qid;
			uint16_t new_qid;

			cnt = 1;
			len = b_peek_varint(buf, ofs + cnt, &msg_len);
			if (!len)
				break;
			cnt += len;
			BUG_ON(msg_len + ofs + cnt + 1 > b_data(buf));

			/* retrieve available room on output channel */
			available_room = channel_recv_max(si_ic(si));

			/* tx_msg_offset null means we are at the start of a new message */
			if (!ds->tx_msg_offset) {
				uint16_t slen;

				/* check if there is enough room to put message len and query id */
				if (available_room < sizeof(slen) + sizeof(new_qid)) {
					si_rx_room_blk(si);
					ret = 0;
					break;
				}

				/* put msg len into then channel */
				slen = (uint16_t)msg_len;
				slen = htons(slen);
				ci_putblk(si_ic(si), (char *)&slen, sizeof(slen));
				available_room -= sizeof(slen);

				/* backup original query id */
				len = b_getblk(buf, (char *)&original_qid, sizeof(original_qid), ofs + cnt);
				if (!len) {
					/* should never happen since messages are atomically
					 * written into ring
					 */
					ret = 0;
					break;
				}

				/* generates new query id */
				new_qid = ++ds->query_counter;
				new_qid = htons(new_qid);

				/* put new query id into the channel */
				ci_putblk(si_ic(si), (char *)&new_qid, sizeof(new_qid));
				available_room -= sizeof(new_qid);

				/* keep query id mapping */

				query = pool_alloc(dns_query_pool);
				if (query) {
					query->qid.key = new_qid;
					query->original_qid = original_qid;
					query->expire = tick_add(now_ms, 5000);
					LIST_INIT(&query->list);
					if (LIST_ISEMPTY(&ds->queries)) {
						/* enable task to handle expire */
						ds->task_exp->expire = query->expire;
						/* ensure this will be executed by the same
						 * thread than ds_session_release
						 * to ensure session_release is free
						 * to destroy the task */
						task_queue(ds->task_exp);
					}
					LIST_APPEND(&ds->queries, &query->list);
					eb32_insert(&ds->query_ids, &query->qid);
					ds->onfly_queries++;
				}

				/* update the tx_offset to handle output in 16k streams */
				ds->tx_msg_offset = sizeof(original_qid);

			}

			/* check if it remains available room on output chan */
			if (unlikely(!available_room)) {
				si_rx_room_blk(si);
				ret = 0;
				break;
			}

			chunk_reset(&trash);
			if ((msg_len - ds->tx_msg_offset) > available_room) {
				/* remaining msg data is too large to be written in output channel at one time */

				len = b_getblk(buf, trash.area, available_room, ofs + cnt + ds->tx_msg_offset);

				/* update offset to complete mesg forwarding later */
				ds->tx_msg_offset += len;
			}
			else {
				/* remaining msg data can be written in output channel at one time */
				len = b_getblk(buf, trash.area, msg_len - ds->tx_msg_offset, ofs + cnt + ds->tx_msg_offset);

				/* reset tx_msg_offset to mark forward fully processed */
				ds->tx_msg_offset = 0;
			}
			trash.data += len;

			if (ci_putchk(si_ic(si), &trash) == -1) {
				/* should never happen since we
				 * check available_room is large
				 * enough here.
				 */
				si_rx_room_blk(si);
				ret = 0;
				break;
			}

			if (ds->tx_msg_offset) {
				/* msg was not fully processed, we must  be awake to drain pending data */

				si_rx_room_blk(si);
				ret = 0;
				break;
			}
			/* switch to next message */
			ofs += cnt + msg_len;
		}

		HA_ATOMIC_INC(b_peek(buf, ofs));
		ofs += ring->ofs;
		ds->ofs = ofs;
	}
	HA_RWLOCK_RDUNLOCK(DNS_LOCK, &ring->lock);

	if (ret) {
		/* let's be woken up once new request to write arrived */
		HA_RWLOCK_WRLOCK(DNS_LOCK, &ring->lock);
		LIST_APPEND(&ring->waiters, &appctx->wait_entry);
		HA_RWLOCK_WRUNLOCK(DNS_LOCK, &ring->lock);
		si_rx_endp_done(si);
	}

read:

	/* if session is not a waiter it means there is no committed
	 * message into rx_buf and we are free to use it
	 * Note: we need a load barrier here to not miss the
	 * delete from the list
	 */
	__ha_barrier_load();
	if (!LIST_INLIST(&ds->waiter)) {
		while (1) {
			uint16_t query_id;
			struct eb32_node *eb;
			struct dns_query *query;

			if (!ds->rx_msg.len) {
				/* next message len is not fully available into the channel */
				if (co_data(si_oc(si)) < 2)
					break;

				/* retrieve message len */
				co_getblk(si_oc(si), (char *)&msg_len, 2, 0);

				/* mark as consumed */
				co_skip(si_oc(si), 2);

				/* store message len */
				ds->rx_msg.len = ntohs(msg_len);
			}

			if (!co_data(si_oc(si))) {
				/* we need more data but nothing is available */
				break;
			}

			if (co_data(si_oc(si)) + ds->rx_msg.offset < ds->rx_msg.len) {
				/* message only partially available */

				/* read available data */
				co_getblk(si_oc(si), ds->rx_msg.area + ds->rx_msg.offset, co_data(si_oc(si)), 0);

				/* update message offset */
				ds->rx_msg.offset += co_data(si_oc(si));

				/* consume all pending data from the channel */
				co_skip(si_oc(si), co_data(si_oc(si)));

				/* we need to wait for more data */
				break;
			}

			/* enough data is available into the channel to read the message until the end */

			/* read from the channel until the end of the message */
			co_getblk(si_oc(si), ds->rx_msg.area + ds->rx_msg.offset, ds->rx_msg.len - ds->rx_msg.offset, 0);

			/* consume all data until the end of the message from the channel */
			co_skip(si_oc(si), ds->rx_msg.len - ds->rx_msg.offset);

			/* reset reader offset to 0 for next message reand */
			ds->rx_msg.offset = 0;

			/* try remap query id to original */
			memcpy(&query_id, ds->rx_msg.area, sizeof(query_id));
			eb = eb32_lookup(&ds->query_ids, query_id);
			if (!eb) {
				/* query id not found means we have an unknown corresponding
				 * request, perhaps server's bug or or the query reached
				 * timeout
				*/
				ds->rx_msg.len = 0;
				continue;
			}

			/* re-map the original query id set by the requester */
			query = eb32_entry(eb, struct dns_query, qid);
			memcpy(ds->rx_msg.area, &query->original_qid, sizeof(query->original_qid));

			/* remove query ids mapping from pending queries list/tree */
			eb32_delete(&query->qid);
			LIST_DELETE(&query->list);
			pool_free(dns_query_pool, query);
			ds->onfly_queries--;

			/* lock the dns_stream_server containing lists heads */
			HA_SPIN_LOCK(DNS_LOCK, &ds->dss->lock);

			/* the dns_session is also added in queue of the
			 * wait_sess list where the task processing
			 * response will pop available responses
			 */
			LIST_APPEND(&ds->dss->wait_sess, &ds->waiter);

			/* lock the dns_stream_server containing lists heads */
			HA_SPIN_UNLOCK(DNS_LOCK, &ds->dss->lock);

			/* awake the task processing the responses */
			task_wakeup(ds->dss->task_rsp, TASK_WOKEN_INIT);

			break;
		}

		if (!LIST_INLIST(&ds->waiter)) {
			/* there is no more pending data to read and the con was closed by the server side */
			if (!co_data(si_oc(si)) && (si_oc(si)->flags & CF_SHUTW)) {
				goto close;
			}
		}

	}


	return;
close:
	si_shutw(si);
	si_shutr(si);
	si_ic(si)->flags |= CF_READ_NULL;
}

void dns_queries_flush(struct dns_session *ds)
{
	struct dns_query *query, *queryb;

	list_for_each_entry_safe(query, queryb, &ds->queries, list) {
		eb32_delete(&query->qid);
		LIST_DELETE(&query->list);
		pool_free(dns_query_pool, query);
	}
}

void dns_session_free(struct dns_session *ds)
{
	if (ds->rx_msg.area)
		pool_free(dns_msg_buf, ds->rx_msg.area);
	if (ds->tx_ring_area)
		pool_free(dns_msg_buf, ds->tx_ring_area);
	if (ds->task_exp)
		task_destroy(ds->task_exp);

	dns_queries_flush(ds);

	ds->dss->cur_conns--;
	/* Note: this is useless to update
	 * max_active_conns here because
	 * we decrease the value
	 */
	pool_free(dns_session_pool, ds);
}

static struct appctx *dns_session_create(struct dns_session *ds);

/*
 * Function to release a DNS tcp session
 */
static void dns_session_release(struct appctx *appctx)
{
	struct dns_session *ds = appctx->ctx.sft.ptr;
	struct dns_stream_server *dss __maybe_unused;

	if (!ds)
		return;

	dss = ds->dss;

	HA_SPIN_LOCK(DNS_LOCK, &dss->lock);
	LIST_DEL_INIT(&ds->list);

	if (stopping) {
		dns_session_free(ds);
		HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
		return;
	}

	if (!ds->nb_queries) {
		/* this is an idle session */
		/* Note: this is useless to update max_active_sess
		 * here because we decrease idle_conns but
		 * dns_session_free decrease curconns
		 */

		ds->dss->idle_conns--;
		dns_session_free(ds);
		HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
		return;
	}

	if (ds->onfly_queries == ds->nb_queries) {
		/* the session can be released because
		 * it means that all queries AND
		 * responses are in fly */
		dns_session_free(ds);
		HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
		return;
	}

	/* We do not call ring_appctx_detach here
	 * because we want to keep readers counters
	 * to retry a con with a different appctx*/
	HA_RWLOCK_WRLOCK(DNS_LOCK, &ds->ring.lock);
	LIST_DEL_INIT(&appctx->wait_entry);
	HA_RWLOCK_WRUNLOCK(DNS_LOCK, &ds->ring.lock);

	/* if there is no pending complete response
	 * message, ensure to reset
	 * message offsets if the session
	 * was closed with an incomplete pending response
	 */
	if (!LIST_INLIST(&ds->waiter))
		ds->rx_msg.len = ds->rx_msg.offset = 0;

	/* we flush pending sent queries because we never
	 * have responses
	 */
	ds->nb_queries -= ds->onfly_queries;
	dns_queries_flush(ds);

	/* reset offset to be sure to start from message start */
	ds->tx_msg_offset = 0;

	/* here the ofs and the attached counter
	 * are kept unchanged
	 */

	/* Create a new appctx, We hope we can
	 * create from the release callback! */
	ds->appctx = dns_session_create(ds);
	if (!ds->appctx) {
		dns_session_free(ds);
		HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
		return;
	}

	if (ds->nb_queries < DNS_STREAM_MAX_PIPELINED_REQ)
		LIST_INSERT(&ds->dss->free_sess, &ds->list);

	HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
}

/* DNS tcp session applet */
static struct applet dns_session_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<STRMDNS>", /* used for logging */
	.fct = dns_session_io_handler,
	.release = dns_session_release,
};

/*
 * Function used to create an appctx for a DNS session
 */
static struct appctx *dns_session_create(struct dns_session *ds)
{
	struct appctx *appctx;
	struct session *sess;
	struct stream *s;
	struct applet *applet = &dns_session_applet;

	appctx = appctx_new(applet, tid_bit);
	if (!appctx)
		goto out_close;

	appctx->ctx.sft.ptr = (void *)ds;

	sess = session_new(ds->dss->srv->proxy, NULL, &appctx->obj_type);
	if (!sess) {
		ha_alert("out of memory in peer_session_create().\n");
		goto out_free_appctx;
	}

	if ((s = stream_new(sess, &appctx->obj_type, &BUF_NULL)) == NULL) {
		ha_alert("Failed to initialize stream in peer_session_create().\n");
		goto out_free_sess;
	}


	s->target = &ds->dss->srv->obj_type;
	if (!sockaddr_alloc(&s->target_addr, &ds->dss->srv->addr, sizeof(ds->dss->srv->addr)))
		goto out_free_strm;
	s->flags = SF_ASSIGNED|SF_ADDR_SET;
	s->si[1].flags |= SI_FL_NOLINGER;

	s->do_log = NULL;
	s->uniq_id = 0;

	s->res.flags |= CF_READ_DONTWAIT;
	/* for rto and rex to eternity to not expire on idle recv:
	 * We are using a syslog server.
	 */
	s->res.rto = TICK_ETERNITY;
	s->res.rex = TICK_ETERNITY;
	ds->appctx = appctx;
	task_wakeup(s->task, TASK_WOKEN_INIT);
	return appctx;

	/* Error unrolling */
 out_free_strm:
	LIST_DELETE(&s->list);
	pool_free(pool_head_stream, s);
 out_free_sess:
	session_free(sess);
 out_free_appctx:
	appctx_free(appctx);
 out_close:
	return NULL;
}

/* Task processing expiration of unresponded queries, this one is supposed
 * to be stuck on the same thread than the appctx handler
 */
static struct task *dns_process_query_exp(struct task *t, void *context, unsigned int state)
{
	struct dns_session *ds = (struct dns_session *)context;
	struct dns_query *query, *queryb;

	t->expire = TICK_ETERNITY;

	list_for_each_entry_safe(query, queryb, &ds->queries, list) {
		if (tick_is_expired(query->expire, now_ms)) {
			eb32_delete(&query->qid);
			LIST_DELETE(&query->list);
			pool_free(dns_query_pool, query);
			ds->onfly_queries--;
		}
		else {
			t->expire = query->expire;
			break;
		}
	}

	return t;
}

/* Task processing expiration of idle sessions */
static struct task *dns_process_idle_exp(struct task *t, void *context, unsigned int state)
{
	struct dns_stream_server *dss = (struct dns_stream_server *)context;
	struct dns_session *ds, *dsb;
	int target = 0;
	int cur_active_conns;

	HA_SPIN_LOCK(DNS_LOCK, &dss->lock);


	cur_active_conns = dss->cur_conns - dss->idle_conns;
	if (cur_active_conns > dss->max_active_conns)
		dss->max_active_conns = cur_active_conns;

	target = (dss->max_active_conns - cur_active_conns) / 2;
	list_for_each_entry_safe(ds, dsb, &dss->idle_sess, list) {
		if (!target)
			break;

		/* remove conn to pending list to ensure it won't be reused */
		LIST_DEL_INIT(&ds->list);

		/* force session shutdown */
		ds->shutdown = 1;

		/* to be sure that the appctx won't miss shutdown */
		__ha_barrier_store();

		/* wake appctx to perform the shutdown */
		appctx_wakeup(ds->appctx);
	}

	/* reset max to current active conns */
	dss->max_active_conns = cur_active_conns;

	HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);

	t->expire = tick_add(now_ms, 5000);

	return t;
}

struct dns_session *dns_session_new(struct dns_stream_server *dss)
{
	struct dns_session *ds;

	if (dss->maxconn && (dss->maxconn <= dss->cur_conns))
		return NULL;

	ds = pool_alloc(dns_session_pool);
	if (!ds)
		return NULL;

	ds->ofs = ~0;
	ds->dss = dss;
	LIST_INIT(&ds->list);
	LIST_INIT(&ds->queries);
	LIST_INIT(&ds->waiter);
	ds->rx_msg.offset = ds->rx_msg.len = 0;
	ds->rx_msg.area = NULL;
	ds->tx_ring_area = NULL;
	ds->task_exp = NULL;
	ds->appctx = NULL;
	ds->shutdown = 0;
	ds->nb_queries = 0;
	ds->query_ids = EB_ROOT_UNIQUE;
	ds->rx_msg.area = pool_alloc(dns_msg_buf);
	if (!ds->rx_msg.area)
		goto error;

	ds->tx_ring_area = pool_alloc(dns_msg_buf);
	if (!ds->tx_ring_area)
		goto error;

	ring_init(&ds->ring, ds->tx_ring_area, DNS_TCP_MSG_RING_MAX_SIZE);
	/* never fail because it is the first watcher attached to the ring */
	DISGUISE(ring_attach(&ds->ring));

	if ((ds->task_exp = task_new(tid_bit)) == NULL)
		goto error;

	ds->task_exp->process = dns_process_query_exp;
	ds->task_exp->context = ds;

	ds->appctx = dns_session_create(ds);
	if (!ds->appctx)
		goto error;

	dss->cur_conns++;

	return ds;

error:
	if (ds->task_exp)
		task_destroy(ds->task_exp);
	if (ds->rx_msg.area)
		pool_free(dns_msg_buf, ds->rx_msg.area);
	if (ds->tx_ring_area)
		pool_free(dns_msg_buf, ds->tx_ring_area);

	pool_free(dns_session_pool, ds);

	return NULL;
}

/*
 * Task used to consume pending messages from nameserver ring
 * and forward them to dns_session ring.
 * Note: If no slot found a new dns_session is allocated
 */
static struct task *dns_process_req(struct task *t, void *context, unsigned int state)
{
	struct dns_nameserver *ns = (struct dns_nameserver *)context;
	struct dns_stream_server *dss = ns->stream;
	struct ring *ring = dss->ring_req;
	struct buffer *buf = &ring->buf;
	uint64_t msg_len;
	size_t len, cnt, ofs;
	struct dns_session *ds, *ads;
	HA_SPIN_LOCK(DNS_LOCK, &dss->lock);

	ofs = dss->ofs_req;

	HA_RWLOCK_RDLOCK(DNS_LOCK, &ring->lock);

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
		HA_ATOMIC_INC(b_peek(buf, ofs));
		ofs += ring->ofs;
	}

	/* we were already there, adjust the offset to be relative to
	 * the buffer's head and remove us from the counter.
	 */
	ofs -= ring->ofs;
	BUG_ON(ofs >= buf->size);
	HA_ATOMIC_DEC(b_peek(buf, ofs));

	while (ofs + 1 < b_data(buf)) {
		struct ist myist;

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

		myist = ist2(dns_msg_trash, len);

		ads = NULL;
		/* try to push request into active sess with free slot */
		if (!LIST_ISEMPTY(&dss->free_sess)) {
			ds = LIST_NEXT(&dss->free_sess, struct dns_session *, list);

			if (ring_write(&ds->ring, DNS_TCP_MSG_MAX_SIZE, NULL, 0, &myist, 1) > 0) {
				ds->nb_queries++;
				if (ds->nb_queries >= DNS_STREAM_MAX_PIPELINED_REQ)
					LIST_DEL_INIT(&ds->list);
				ads = ds;
			}
			else {
				/* it means we were unable to put a request in this slot,
				 * it may be close to be full so we put it at the end
				 * of free conn list */
				LIST_DEL_INIT(&ds->list);
				LIST_APPEND(&dss->free_sess, &ds->list);
			}
		}

		if (!ads) {
			/* try to push request into idle, this one should have enough free space */
			if (!LIST_ISEMPTY(&dss->idle_sess)) {
				ds = LIST_NEXT(&dss->idle_sess, struct dns_session *, list);

				/* ring is empty so this ring_write should never fail */
				ring_write(&ds->ring, DNS_TCP_MSG_MAX_SIZE, NULL, 0, &myist, 1);
				ds->nb_queries++;
				LIST_DEL_INIT(&ds->list);

				ds->dss->idle_conns--;

				/* we may have to update the max_active_conns */
				if (ds->dss->max_active_conns < ds->dss->cur_conns - ds->dss->idle_conns)
					ds->dss->max_active_conns = ds->dss->cur_conns - ds->dss->idle_conns;

				/* since we may unable to find a free list to handle
				 * this request, this request may be large and fill
				 * the ring buffer so we prefer to put at the end of free
				 * list. */
				LIST_APPEND(&dss->free_sess, &ds->list);
				ads = ds;
			}
		}

		/* we didn't find a session available with large enough room */
		if (!ads) {
			/* allocate a new session */
			ads = dns_session_new(dss);
			if (ads) {
				/* ring is empty so this ring_write should never fail */
				ring_write(&ads->ring, DNS_TCP_MSG_MAX_SIZE, NULL, 0, &myist, 1);
				ads->nb_queries++;
				LIST_INSERT(&dss->free_sess, &ads->list);
			}
			else
				ns->counters->snd_error++;
		}

		if (ads)
			ns->counters->sent++;

		ofs += cnt + len;
	}

	HA_ATOMIC_INC(b_peek(buf, ofs));
	ofs += ring->ofs;
	dss->ofs_req = ofs;
	HA_RWLOCK_RDUNLOCK(DNS_LOCK, &ring->lock);


	HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
	return t;
}

/*
 * Task used to consume response
 * Note: upper layer callback is called
 */
static struct task *dns_process_rsp(struct task *t, void *context, unsigned int state)
{
	struct dns_nameserver *ns = (struct dns_nameserver *)context;

	ns->process_responses(ns);

	return t;
}

/* Function used to initialize an TCP nameserver */
int dns_stream_init(struct dns_nameserver *ns, struct server *srv)
{
	struct dns_stream_server *dss = NULL;

        dss = calloc(1, sizeof(*dss));
        if (!dss) {
		ha_alert("memory allocation error initializing dns tcp server '%s'.\n", srv->id);
		goto out;
	}

	dss->srv = srv;
	dss->maxconn = srv->maxconn;

	dss->ofs_req = ~0; /* init ring offset */
	dss->ring_req = ring_new(2*DNS_TCP_MSG_RING_MAX_SIZE);
	if (!dss->ring_req) {
		ha_alert("memory allocation error initializing the ring for dns tcp server '%s'.\n", srv->id);
		goto out;
	}
	/* Create the task associated to the resolver target handling conns */
	if ((dss->task_req = task_new(MAX_THREADS_MASK)) == NULL) {
		ha_alert("memory allocation error initializing the ring for dns tcp server '%s'.\n", srv->id);
		goto out;
	}

	/* Update task's parameters */
	dss->task_req->process = dns_process_req;
	dss->task_req->context = ns;

	/* attach the task as reader */
	if (!ring_attach(dss->ring_req)) {
		/* mark server attached to the ring */
		ha_alert("server '%s': too many watchers for ring. this should never happen.\n", srv->id);
		goto out;
	}

	/* Create the task associated to the resolver target handling conns */
	if ((dss->task_rsp = task_new(MAX_THREADS_MASK)) == NULL) {
		ha_alert("memory allocation error initializing the ring for dns tcp server '%s'.\n", srv->id);
		goto out;
	}

	/* Update task's parameters */
	dss->task_rsp->process = dns_process_rsp;
	dss->task_rsp->context = ns;

	/* Create the task associated to the resolver target handling conns */
	if ((dss->task_idle = task_new(MAX_THREADS_MASK)) == NULL) {
		ha_alert("memory allocation error initializing the ring for dns tcp server '%s'.\n", srv->id);
		goto out;
	}

	/* Update task's parameters */
	dss->task_idle->process = dns_process_idle_exp;
	dss->task_idle->context = dss;
	dss->task_idle->expire = tick_add(now_ms, 5000);

	/* let start the task to free idle conns immediately */
	task_queue(dss->task_idle);

	LIST_INIT(&dss->free_sess);
	LIST_INIT(&dss->idle_sess);
	LIST_INIT(&dss->wait_sess);
	HA_SPIN_INIT(&dss->lock);
	ns->stream = dss;
	return 0;
out:
	if (dss && dss->task_rsp)
		task_destroy(dss->task_rsp);
	if (dss && dss->task_req)
		task_destroy(dss->task_req);
	if (dss && dss->ring_req)
		ring_free(dss->ring_req);

	free(dss);
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
	ha_free(&dns_msg_trash);
}

REGISTER_PER_THREAD_ALLOC(init_dns_buffers);
REGISTER_PER_THREAD_FREE(deinit_dns_buffers);
