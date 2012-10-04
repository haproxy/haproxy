/*
 * Functions used to send/receive data using SOCK_STREAM sockets.
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

/* Returns :
 *   -1 if splice() is not supported
 *   >= 0 to report the amount of spliced bytes.
 *   connection flags are updated (error, read0, wait_room, wait_data).
 *   The caller must have previously allocated the pipe.
 */
int raw_sock_to_pipe(struct connection *conn, struct pipe *pipe, unsigned int count)
{
	static int splice_detects_close;
	int ret;
	int retval = 0;

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
			conn->flags |= CO_FL_ERROR;
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
				splice_detects_close = 1;
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
				if (splice_detects_close)
					__conn_data_poll_recv(conn); /* we know for sure that it's EAGAIN */
				break;
			}
			else if (errno == ENOSYS || errno == EINVAL) {
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

		if (pipe->data >= SPLICE_FULL_HINT || ret >= global.tune.recv_enough) {
			/* We've read enough of it for this time, let's stop before
			 * being asked to poll.
			 */
			break;
		}
	} /* while */

	return retval;

 out_read0:
	conn_sock_read0(conn);
	return retval;
}

/* Send as many bytes as possible from the pipe to the connection's socket.
 */
int raw_sock_from_pipe(struct connection *conn, struct pipe *pipe)
{
	int ret, done;

	done = 0;
	while (pipe->data) {
		ret = splice(pipe->cons, NULL, conn->t.sock.fd, NULL, pipe->data,
			     SPLICE_F_MOVE|SPLICE_F_NONBLOCK);

		if (ret <= 0) {
			if (ret == 0 || errno == EAGAIN) {
				__conn_data_poll_send(conn);
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
	return done;
}

#endif /* CONFIG_HAP_LINUX_SPLICE */


/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. The caller must ensure that <count> is always smaller
 * than the buffer's size. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 */
static int raw_sock_to_buf(struct connection *conn, struct buffer *buf, int count)
{
	int ret, done = 0;
	int try = count;

	if (unlikely(!(fdtab[conn->t.sock.fd].ev & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->t.sock.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP)
			goto read0;

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->t.sock.fd].ev & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn->flags |= CO_FL_ERROR;
			return done;
		}
	}

	/* compute the maximum block size we can read at once. */
	if (buffer_empty(buf)) {
		/* let's realign the buffer to optimize I/O */
		buf->p = buf->data;
	}
	else if (buf->data + buf->o < buf->p &&
		 buf->p + buf->i < buf->data + buf->size) {
		/* remaining space wraps at the end, with a moving limit */
		if (try > buf->data + buf->size - (buf->p + buf->i))
			try = buf->data + buf->size - (buf->p + buf->i);
	}

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (try) {
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
				break;
			}
			count -= ret;
			try = count;
		}
		else if (ret == 0) {
			goto read0;
		}
		else if (errno == EAGAIN) {
			__conn_data_poll_recv(conn);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR;
			break;
		}
	}
	return done;

 read0:
	conn_sock_read0(conn);
	return done;
}


/* Send all pending bytes from buffer <buf> to connection <conn>'s socket.
 * <flags> may contain MSG_MORE to make the system hold on without sending
 * data too fast.
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
		if (try < buf->o)
			send_flag = MSG_MORE;

		ret = send(conn->t.sock.fd, bo_ptr(buf), try, send_flag | flags);

		if (ret > 0) {
			buf->o -= ret;
			done += ret;

			if (likely(!buffer_len(buf)))
				/* optimize data alignment in the buffer */
				buf->p = buf->data;

			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN) {
			/* nothing written, we need to poll for write first */
			__conn_data_poll_send(conn);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR;
			break;
		}
	}
	return done;
}


/* data-layer operations for RAW sockets */
struct data_ops raw_sock = {
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
