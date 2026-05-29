/*
 * include/haproxy/quic_sock.h
 * This file contains declarations for QUIC sockets.
 *
 * Copyright 2020 Frederic Lecaille <flecaille@haproxy.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_QUIC_SOCK_H
#define _HAPROXY_QUIC_SOCK_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <sys/socket.h>
#include <sys/types.h>

#include <haproxy/api.h>
#include <haproxy/connection-t.h>
#include <haproxy/fd-t.h>
#include <haproxy/listener-t.h>
#include <haproxy/obj_type.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_sock-t.h>

int quic_session_accept(struct connection *cli_conn);
int quic_sock_get_src(struct connection *conn, struct sockaddr *addr, socklen_t len);
int quic_sock_get_dst(struct connection *conn, struct sockaddr *addr, socklen_t len);
int quic_sock_accepting_conn(const struct receiver *rx);
struct connection *quic_sock_accept_conn(struct listener *l, int *status);

struct task *quic_lstnr_dghdlr(struct task *t, void *ctx, unsigned int state);
void quic_lstnr_sock_fd_iocb(int fd);
int quic_dgram_requeue(struct quic_dgram *dgram, int cid_tid);
int qc_snd_buf(struct quic_conn *qc, const struct buffer *buf, size_t count,
               int flags, uint16_t gso_size);
int qc_rcv_buf(struct quic_conn *qc);
void quic_conn_sock_fd_iocb(int fd);
void quic_conn_closed_sock_fd_iocb(int fd);

void qc_alloc_fd(struct quic_conn *qc, const struct sockaddr_storage *src,
                 const struct sockaddr_storage *dst);
void qc_release_fd(struct quic_conn *qc, int reinit);
void qc_want_recv(struct quic_conn *qc);

void quic_accept_push_qc(struct quic_conn *qc);

int quic_listener_max_handshake(const struct listener *l);
int quic_listener_max_accept(const struct listener *l);

/* Set default value for <qc> socket as uninitialized. */
static inline void qc_init_fd(struct quic_conn *qc)
{
	qc->fd = -1;
}

/* Returns true if <qc> socket is initialized else false. */
static inline char qc_test_fd(struct quic_conn *qc)
{
	/* quic-conn socket should not be accessed once it has been released. */
	BUG_ON(qc->fd == DEAD_FD_MAGIC);
	return qc->fd >= 0;
}

/* Returns active socket for <qc> connection. This may be its owned connection
 * socket or the listener one as a fallback.
 */
static inline int qc_fd(struct quic_conn *qc)
{
	/* For backends, qc->fd is always initialized */
	return qc_test_fd(qc) ? qc->fd : qc->li->rx.fd;
}

/* Try to increment <l> handshake current counter. If listener limit is
 * reached, incrementation is rejected and 0 is returned.
 */
static inline int quic_increment_curr_handshake(struct listener *l)
{
	unsigned int count, next;
	const int max = quic_listener_max_handshake(l);

	do {
		count = l->rx.quic_curr_handshake;
		if (count >= max) {
			/* maxconn reached */
			next = 0;
			goto end;
		}

		/* try to increment quic_curr_handshake */
		next = count + 1;
	} while (!_HA_ATOMIC_CAS(&l->rx.quic_curr_handshake, &count, next) && __ha_cpu_relax());

 end:
	return next;
}

/* Initializes <dst> sockaddr_storage from <src> union sockaddr_in46 type.
 * Only unspec, IPv4 and IPv6 addresses are supported.
 */
static inline void in46un_to_addr(const union sockaddr_in46 *src,
                                  struct sockaddr_storage *dst)
{
	struct sockaddr_in  *in;
	struct sockaddr_in6 *in6;

	switch (((struct sockaddr_storage *)src)->ss_family) {
	case AF_UNSPEC:
		memset(dst, 0, sizeof(*dst));
		break;

	case AF_INET:
		in = (struct sockaddr_in *)dst;
		in->sin_family = AF_INET;
		in->sin_addr = src->in4.sin_addr;
		in->sin_port = src->in4.sin_port;
		break;

	case AF_INET6:
		in6 = (struct sockaddr_in6 *)dst;
		in6->sin6_family = AF_INET6;
		in6->sin6_addr = src->in6.sin6_addr;
		in6->sin6_port = src->in6.sin6_port;
		in6->sin6_flowinfo = src->in6.sin6_flowinfo;
		in6->sin6_scope_id = src->in6.sin6_scope_id;
		break;

	default:
		ABORT_NOW();
		break;
	}
}

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
