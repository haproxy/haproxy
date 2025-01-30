/*
 * RAW transport layer over SOCK_STREAM sockets.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/tcp.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/pipe.h>
#include <haproxy/proxy.h>
#include <haproxy/tools.h>


#if defined(USE_LINUX_SPLICE)

/* A pipe contains 16 segments max, and it's common to see segments of 1448 bytes
 * because of timestamps. Use this as a hint for not looping on splice().
 */
#define SPLICE_FULL_HINT	16*1448

/* how many data we attempt to splice at once when the buffer is configured for
 * infinite forwarding */
#define MAX_SPLICE_AT_ONCE	(1<<30)

/* Returns :
 *   -1 if splice() is not supported
 *   >= 0 to report the amount of spliced bytes.
 *   connection flags are updated (error, read0, wait_room, wait_data).
 *   The caller must have previously allocated the pipe.
 */
int raw_sock_to_pipe(struct connection *conn, void *xprt_ctx, struct pipe *pipe, unsigned int count)
{
	int ret;
	int retval = 0;


	if (!conn_ctrl_ready(conn))
		return 0;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	conn->flags &= ~CO_FL_WAIT_ROOM;
	errno = 0;

	/* Under Linux, if FD_POLL_HUP is set, we have reached the end.
	 * Since older splice() implementations were buggy and returned
	 * EAGAIN on end of read, let's bypass the call to splice() now.
	 */
	if (unlikely(!(fdtab[conn->handle.fd].state & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->handle.fd].state & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP) {
			conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_poll_hup);
			goto out_read0;
		}

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->handle.fd].state & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_poll_err);
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			conn_set_errcode(conn, CO_ER_POLLERR);
			errno = 0; /* let the caller do a getsockopt() if it wants it */
			goto leave;
		}
	}

	while (count) {
		if (count > MAX_SPLICE_AT_ONCE)
			count = MAX_SPLICE_AT_ONCE;

		ret = splice(conn->handle.fd, NULL, pipe->prod, NULL, count,
			     SPLICE_F_MOVE|SPLICE_F_NONBLOCK);

		if (ret <= 0) {
			if (ret == 0) {
				conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_shutr);
				goto out_read0;
			}

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* there are two reasons for EAGAIN :
				 *   - nothing in the socket buffer (standard)
				 *   - pipe is full
				 * The difference between these two situations
				 * is problematic. Since we don't know if the
				 * pipe is full, we'll stop if the pipe is not
				 * empty. Anyway, we will almost always fill or
				 * empty the pipe.
				 */
				if (pipe->data) {
					/* always stop reading until the pipe is flushed */
					conn->flags |= CO_FL_WAIT_ROOM;
					break;
				}
				/* socket buffer exhausted */
				fd_cant_recv(conn->handle.fd);
				break;
			}
			else if (errno == ENOSYS || errno == EINVAL || errno == EBADF) {
				/* splice not supported on this end, disable it.
				 * We can safely return -1 since there is no
				 * chance that any data has been piped yet.
				 */
				retval = -1;
				goto leave;
			}
			else if (errno == EINTR) {
				/* try again */
				continue;
			}
			/* here we have another error */
			conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_rcv_err);
			conn->flags |= CO_FL_ERROR;
			conn_set_errno(conn, errno);
			break;
		} /* ret <= 0 */

		retval += ret;
		pipe->data += ret;
		count -= ret;

		if (pipe->data >= SPLICE_FULL_HINT || ret >= global.tune.recv_enough) {
			/* We've read enough of it for this time, let's stop before
			 * being asked to poll.
			 */
			conn->flags |= CO_FL_WAIT_ROOM;
			break;
		}
	} /* while */

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && retval)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

 leave:
	if (retval > 0)
		increment_send_rate(retval, 1);

	return retval;

 out_read0:
	conn_sock_read0(conn);
	conn->flags &= ~CO_FL_WAIT_L4_CONN;
	goto leave;
}

/* Send as many bytes as possible from the pipe to the connection's socket.
 */
int raw_sock_from_pipe(struct connection *conn, void *xprt_ctx, struct pipe *pipe, unsigned int count)
{
	int ret, done;

	if (!conn_ctrl_ready(conn))
		return 0;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (!fd_send_ready(conn->handle.fd))
		return 0;

	if (conn->flags & CO_FL_SOCK_WR_SH) {
		/* it's already closed */
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH;
		errno = EPIPE;
		conn_set_errno(conn, errno);
		return 0;
	}

	if (unlikely(count > pipe->data))
		count = pipe->data;

	done = 0;
	while (count) {
		ret = splice(pipe->cons, NULL, conn->handle.fd, NULL, count,
			     SPLICE_F_MOVE|SPLICE_F_NONBLOCK);

		if (ret <= 0) {
			if (ret == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
				fd_cant_send(conn->handle.fd);
				break;
			}
			else if (errno == EINTR)
				continue;

			/* here we have another error */
			conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_snd_err);
			conn->flags |= CO_FL_ERROR;
			conn_set_errno(conn, errno);
			break;
		}

		done += ret;
		count -= ret;
		pipe->data -= ret;
	}
	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done) {
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	}

	return done;
}

#endif /* USE_LINUX_SPLICE */


/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 * errno is cleared before starting so that the caller knows that if it spots an
 * error without errno, it's pending and can be retrieved via getsockopt(SO_ERROR).
 */
static size_t raw_sock_to_buf(struct connection *conn, void *xprt_ctx, struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done = 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	conn->flags &= ~CO_FL_WAIT_ROOM;
	errno = 0;

	if (unlikely(!(fdtab[conn->handle.fd].state & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->handle.fd].state & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP) {
			conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_poll_hup);
			goto read0;
		}

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->handle.fd].state & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_connect_poll_err);
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			conn_set_errcode(conn, CO_ER_POLLERR);
			goto leave;
		}
	}

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {
		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > count)
			try = count;

		ret = recv(conn->handle.fd, b_tail(buf), try, 0);

		if (ret > 0) {
			b_add(buf, ret);
			done += ret;
			if (ret < try) {
				/* socket buffer exhausted */
				fd_cant_recv(conn->handle.fd);

				/* unfortunately, on level-triggered events, POLL_HUP
				 * is generally delivered AFTER the system buffer is
				 * empty, unless the poller supports POLL_RDHUP. If
				 * we know this is the case, we don't try to read more
				 * as we know there's no more available. Similarly, if
				 * there's no problem with lingering we don't even try
				 * to read an unlikely close from the client since we'll
				 * close first anyway.
				 */
				if (fdtab[conn->handle.fd].state & FD_POLL_HUP) {
					conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_poll_hup);
					goto read0;
				}

				if (!(fdtab[conn->handle.fd].state & FD_LINGER_RISK) ||
				    (cur_poller.flags & HAP_POLL_F_RDHUP)) {
					break;
				}
			}
			count -= ret;

			if (flags & CO_RFL_READ_ONCE)
				break;
		}
		else if (ret == 0) {
			conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_shutr);
			goto read0;
		}
		else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN) {
			/* socket buffer exhausted */
			fd_cant_recv(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_rcv_err);
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			conn_set_errno(conn, errno);
			break;
		}
	}

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

 leave:
	return done;

 read0:
	conn_sock_read0(conn);
	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	/* Now a final check for a possible asynchronous low-level error
	 * report. This can happen when a connection receives a reset
	 * after a shutdown, both POLL_HUP and POLL_ERR are queued, and
	 * we might have come from there by just checking POLL_HUP instead
	 * of recv()'s return value 0, so we have no way to tell there was
	 * an error without checking.
	 */
	if (unlikely(!done && fdtab[conn->handle.fd].state & FD_POLL_ERR)) {
		conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_poll_err);
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
		conn_set_errcode(conn, CO_ER_POLLERR);
	}
	goto leave;
}


/* Send up to <count> pending bytes from buffer <buf> to connection <conn>'s
 * socket. <flags> may contain some CO_SFL_* flags to hint the system about
 * other pending data for example, but this flag is ignored at the moment.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this. It's up to the caller to update the buffer's contents
 * based on the return value.
 */
static size_t raw_sock_from_buf(struct connection *conn, void *xprt_ctx, const struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done;
	int send_flag;

	if (!conn_ctrl_ready(conn))
		return 0;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (!fd_send_ready(conn->handle.fd))
		return 0;

	if (unlikely(fdtab[conn->handle.fd].state & FD_POLL_ERR)) {
		/* an error was reported on the FD, we can't send anymore */
		conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_poll_err);
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_WR_SH | CO_FL_SOCK_RD_SH;
		conn_set_errcode(conn, CO_ER_POLLERR);
		errno = EPIPE;
		return 0;
	}

	if (conn->flags & CO_FL_SOCK_WR_SH) {
		/* it's already closed */
		conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_snd_err);
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH;
		errno = EPIPE;
		conn_set_errno(conn, errno);
		return 0;
	}

	done = 0;
	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (count) {
		try = b_contig_data(buf, done);
		if (try > count)
			try = count;

		send_flag = MSG_DONTWAIT | MSG_NOSIGNAL;
		if (try < count || flags & CO_SFL_MSG_MORE)
			send_flag |= MSG_MORE;

		ret = send(conn->handle.fd, b_peek(buf, done), try, send_flag);

		if (ret > 0) {
			count -= ret;
			done += ret;

			/* if the system buffer is full, don't insist */
			if (ret < try) {
				fd_cant_send(conn->handle.fd);
				break;
			}
			if (!count)
				fd_stop_send(conn->handle.fd);
		}
		else if (ret == 0 || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN || errno == EINPROGRESS) {
			/* nothing written, we need to poll for write first */
			fd_cant_send(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn_report_term_evt(conn, tevt_loc_fd, fd_tevt_type_snd_err);
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			conn_set_errno(conn, errno);
			break;
		}
	}
	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done) {
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	}

	if (done > 0)
		increment_send_rate(done, 0);

	return done;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0.
 */
static int raw_sock_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	return conn_subscribe(conn, xprt_ctx, event_type, es);
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int raw_sock_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	return conn_unsubscribe(conn, xprt_ctx, event_type, es);
}

static void raw_sock_close(struct connection *conn, void *xprt_ctx)
{
	if (conn->subs != NULL) {
		conn_unsubscribe(conn, NULL, conn->subs->events, conn->subs);
	}
}

/* We can't have an underlying XPRT, so just return -1 to signify failure */
static int raw_sock_remove_xprt(struct connection *conn, void *xprt_ctx, void *toremove_ctx, const struct xprt_ops *newops, void *newctx)
{
	/* This is the lowest xprt we can have, so if we get there we didn't
	 * find the xprt we wanted to remove, that's a bug
	 */
	BUG_ON(1);
	return -1;
}

/* transport-layer operations for RAW sockets */
static struct xprt_ops raw_sock = {
	.snd_buf  = raw_sock_from_buf,
	.rcv_buf  = raw_sock_to_buf,
	.subscribe = raw_sock_subscribe,
	.unsubscribe = raw_sock_unsubscribe,
	.remove_xprt = raw_sock_remove_xprt,
#if defined(USE_LINUX_SPLICE)
	.rcv_pipe = raw_sock_to_pipe,
	.snd_pipe = raw_sock_from_pipe,
#endif
	.shutr    = NULL,
	.shutw    = NULL,
	.close    = raw_sock_close,
	.name     = "RAW",
};


static void __raw_sock_init(void)
{
	xprt_register(XPRT_RAW, &raw_sock);
}

INITCALL0(STG_REGISTER, __raw_sock_init);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
