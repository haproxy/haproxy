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

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/log.h>
#include <proto/pipe.h>
#include <proto/raw_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

#include <types/global.h>


#if defined(CONFIG_HAP_LINUX_SPLICE)
#include <common/splice.h>

/* A pipe contains 16 segments max, and it's common to see segments of 1448 bytes
 * because of timestamps. Use this as a hint for not looping on splice().
 */
#define SPLICE_FULL_HINT	16*1448

/* how many data we attempt to splice at once when the buffer is configured for
 * infinite forwarding */
#define MAX_SPLICE_AT_ONCE	(1<<30)

/* Versions of splice between 2.6.25 and 2.6.27.12 were bogus and would return EAGAIN
 * on incoming shutdowns. On these versions, we have to call recv() after such a return
 * in order to find whether splice is OK or not. Since 2.6.27.13 we don't need to do
 * this anymore, and we can avoid this logic by defining ASSUME_SPLICE_WORKS.
 */

/* Returns :
 *   -1 if splice() is not supported
 *   >= 0 to report the amount of spliced bytes.
 *   connection flags are updated (error, read0, wait_room, wait_data).
 *   The caller must have previously allocated the pipe.
 */
int raw_sock_to_pipe(struct connection *conn, struct pipe *pipe, unsigned int count)
{
#ifndef ASSUME_SPLICE_WORKS
	static int splice_detects_close;
#endif
	int ret;
	int retval = 0;


	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_recv_ready(conn->t.sock.fd))
		return 0;

	errno = 0;

	/* Under Linux, if FD_POLL_HUP is set, we have reached the end.
	 * Since older splice() implementations were buggy and returned
	 * EAGAIN on end of read, let's bypass the call to splice() now.
	 */
	if (unlikely(!(fdtab[conn->t.sock.fd].ev & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->t.sock.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP)
			goto out_read0;

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->t.sock.fd].ev & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			errno = 0; /* let the caller do a getsockopt() if it wants it */
			return retval;
		}
	}

	while (count) {
		if (count > MAX_SPLICE_AT_ONCE)
			count = MAX_SPLICE_AT_ONCE;

		ret = splice(conn->t.sock.fd, NULL, pipe->prod, NULL, count,
			     SPLICE_F_MOVE|SPLICE_F_NONBLOCK);

		if (ret <= 0) {
			if (ret == 0) {
				/* connection closed. This is only detected by
				 * recent kernels (>= 2.6.27.13). If we notice
				 * it works, we store the info for later use.
				 */
#ifndef ASSUME_SPLICE_WORKS
				splice_detects_close = 1;
#endif
				goto out_read0;
			}

			if (errno == EAGAIN) {
				/* there are two reasons for EAGAIN :
				 *   - nothing in the socket buffer (standard)
				 *   - pipe is full
				 *   - the connection is closed (kernel < 2.6.27.13)
				 * The last case is annoying but know if we can detect it
				 * and if we can't then we rely on the call to recv() to
				 * get a valid verdict. The difference between the first
				 * two situations is problematic. Since we don't know if
				 * the pipe is full, we'll stop if the pipe is not empty.
				 * Anyway, we will almost always fill/empty the pipe.
				 */
				if (pipe->data) {
					/* alway stop reading until the pipe is flushed */
					conn->flags |= CO_FL_WAIT_ROOM;
					break;
				}

				/* We don't know if the connection was closed,
				 * but if we know splice detects close, then we
				 * know it for sure.
				 * But if we're called upon POLLIN with an empty
				 * pipe and get EAGAIN, it is suspect enough to
				 * try to fall back to the normal recv scheme
				 * which will be able to deal with the situation.
				 */
#ifndef ASSUME_SPLICE_WORKS
				if (splice_detects_close)
#endif
					fd_cant_recv(conn->t.sock.fd); /* we know for sure that it's EAGAIN */
				break;
			}
			else if (errno == ENOSYS || errno == EINVAL || errno == EBADF) {
				/* splice not supported on this end, disable it.
				 * We can safely return -1 since there is no
				 * chance that any data has been piped yet.
				 */
				return -1;
			}
			else if (errno == EINTR) {
				/* try again */
				continue;
			}
			/* here we have another error */
			conn->flags |= CO_FL_ERROR;
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
			fd_done_recv(conn->t.sock.fd);
			break;
		}
	} /* while */

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && retval)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	return retval;

 out_read0:
	conn_sock_read0(conn);
	conn->flags &= ~CO_FL_WAIT_L4_CONN;
	return retval;
}

/* Send as many bytes as possible from the pipe to the connection's socket.
 */
int raw_sock_from_pipe(struct connection *conn, struct pipe *pipe)
{
	int ret, done;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_send_ready(conn->t.sock.fd))
		return 0;

	done = 0;
	while (pipe->data) {
		ret = splice(pipe->cons, NULL, conn->t.sock.fd, NULL, pipe->data,
			     SPLICE_F_MOVE|SPLICE_F_NONBLOCK);

		if (ret <= 0) {
			if (ret == 0 || errno == EAGAIN) {
				fd_cant_send(conn->t.sock.fd);
				break;
			}
			else if (errno == EINTR)
				continue;

			/* here we have another error */
			conn->flags |= CO_FL_ERROR;
			break;
		}

		done += ret;
		pipe->data -= ret;
	}
	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	return done;
}

#endif /* CONFIG_HAP_LINUX_SPLICE */


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
static int raw_sock_to_buf(struct connection *conn, struct buffer *buf, int count)
{
	int ret, done = 0;
	int try;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_recv_ready(conn->t.sock.fd))
		return 0;

	errno = 0;

	if (unlikely(!(fdtab[conn->t.sock.fd].ev & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->t.sock.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP)
			goto read0;

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->t.sock.fd].ev & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			return done;
		}
	}

	/* let's realign the buffer to optimize I/O */
	if (buffer_empty(buf))
		buf->p = buf->data;

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {
		/* first check if we have some room after p+i */
		try = buf->data + buf->size - (buf->p + buf->i);
		/* otherwise continue between data and p-o */
		if (try <= 0) {
			try = buf->p - (buf->data + buf->o);
			if (try <= 0)
				break;
		}
		if (try > count)
			try = count;

		ret = recv(conn->t.sock.fd, bi_end(buf), try, 0);

		if (ret > 0) {
			buf->i += ret;
			done += ret;
			if (ret < try) {
				/* unfortunately, on level-triggered events, POLL_HUP
				 * is generally delivered AFTER the system buffer is
				 * empty, so this one might never match.
				 */
				if (fdtab[conn->t.sock.fd].ev & FD_POLL_HUP)
					goto read0;

				fd_done_recv(conn->t.sock.fd);
				break;
			}
			count -= ret;
		}
		else if (ret == 0) {
			goto read0;
		}
		else if (errno == EAGAIN || errno == ENOTCONN) {
			fd_cant_recv(conn->t.sock.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
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
	if (unlikely(fdtab[conn->t.sock.fd].ev & FD_POLL_ERR))
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	return done;
}


/* Send all pending bytes from buffer <buf> to connection <conn>'s socket.
 * <flags> may contain some CO_SFL_* flags to hint the system about other
 * pending data for example.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this.
 */
static int raw_sock_from_buf(struct connection *conn, struct buffer *buf, int flags)
{
	int ret, try, done, send_flag;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_send_ready(conn->t.sock.fd))
		return 0;

	done = 0;
	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (buf->o) {
		try = buf->o;
		/* outgoing data may wrap at the end */
		if (buf->data + try > buf->p)
			try = buf->data + try - buf->p;

		send_flag = MSG_DONTWAIT | MSG_NOSIGNAL;
		if (try < buf->o || flags & CO_SFL_MSG_MORE)
			send_flag |= MSG_MORE;

		ret = send(conn->t.sock.fd, bo_ptr(buf), try, send_flag);

		if (ret > 0) {
			buf->o -= ret;
			done += ret;

			if (likely(buffer_empty(buf)))
				/* optimize data alignment in the buffer */
				buf->p = buf->data;

			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN || errno == ENOTCONN) {
			/* nothing written, we need to poll for write first */
			fd_cant_send(conn->t.sock.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}
	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;
	return done;
}


/* transport-layer operations for RAW sockets */
struct xprt_ops raw_sock = {
	.snd_buf  = raw_sock_from_buf,
	.rcv_buf  = raw_sock_to_buf,
#if defined(CONFIG_HAP_LINUX_SPLICE)
	.rcv_pipe = raw_sock_to_pipe,
	.snd_pipe = raw_sock_from_pipe,
#endif
	.shutr    = NULL,
	.shutw    = NULL,
	.close    = NULL,
};

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
