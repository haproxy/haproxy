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
#include <haproxy/listener-t.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_sock-t.h>

int quic_session_accept(struct connection *cli_conn);
int quic_sock_get_src(struct connection *conn, struct sockaddr *addr, socklen_t len);
int quic_sock_get_dst(struct connection *conn, struct sockaddr *addr, socklen_t len);
int quic_sock_accepting_conn(const struct receiver *rx);
struct connection *quic_sock_accept_conn(struct listener *l, int *status);

struct task *quic_lstnr_dghdlr(struct task *t, void *ctx, unsigned int state);
void quic_lstnr_sock_fd_iocb(int fd);
int qc_snd_buf(struct quic_conn *qc, const struct buffer *buf, size_t count,
               int flags, int *syscall_errno);
int qc_rcv_buf(struct quic_conn *qc);

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

void qc_alloc_fd(struct quic_conn *qc, const struct sockaddr_storage *src,
                 const struct sockaddr_storage *dst);
void qc_release_fd(struct quic_conn *qc, int reinit);

void quic_accept_push_qc(struct quic_conn *qc);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_SOCK_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
