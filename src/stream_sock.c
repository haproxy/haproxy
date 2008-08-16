/*
 * Functions operating on SOCK_STREAM and buffers.
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/client.h>
#include <proto/fd.h>
#include <proto/stream_sock.h>
#include <proto/task.h>


/*
 * this function is called on a read event from a stream socket.
 * It returns 0 if we have a high confidence that we will not be
 * able to read more data without polling first. Returns non-zero
 * otherwise.
 */
int stream_sock_read(int fd) {
	__label__ out_wakeup, out_shutdown_r, out_error;
	struct buffer *b = fdtab[fd].cb[DIR_RD].b;
	int ret, max, retval, cur_read;
	int read_poll = MAX_READ_POLL_LOOPS;

#ifdef DEBUG_FULL
	fprintf(stderr,"stream_sock_read : fd=%d, ev=0x%02x, owner=%p\n", fd, fdtab[fd].ev, fdtab[fd].owner);
#endif

	retval = 1;

	/* stop immediately on errors */
	if (fdtab[fd].state == FD_STERROR || (fdtab[fd].ev & FD_POLL_ERR))
		goto out_error;

	/* stop here if we reached the end of data */
	if ((fdtab[fd].ev & (FD_POLL_IN|FD_POLL_HUP)) == FD_POLL_HUP)
		goto out_shutdown_r;

	cur_read = 0;
	while (1) {
		/*
		 * 1. compute the maximum block size we can read at once.
		 */
		if (b->l == 0) { /* let's realign the buffer to optimize I/O */
			b->r = b->w = b->lr  = b->data;
			max = b->rlim - b->data;
		}
		else if (b->r > b->w) {
			max = b->rlim - b->r;
		}
		else {
			max = b->w - b->r;
			/* FIXME: theorically, if w>0, we shouldn't have rlim < data+size anymore
			 * since it means that the rewrite protection has been removed. This
			 * implies that the if statement can be removed.
			 */
			if (max > b->rlim - b->data)
				max = b->rlim - b->data;
		}
	    
		if (unlikely(max == 0)) {
			/* Not anymore room to store data. This should theorically
			 * never happen, but better safe than sorry !
			 */
			EV_FD_CLR(fd, DIR_RD);
			b->rex = TICK_ETERNITY;
			goto out_wakeup;
		}

		/*
		 * 2. read the largest possible block
		 */
#ifndef MSG_NOSIGNAL
		{
			int skerr;
			socklen_t lskerr = sizeof(skerr);

			ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
			if (ret == -1 || skerr)
				ret = -1;
			else
				ret = recv(fd, b->r, max, 0);
		}
#else
		ret = recv(fd, b->r, max, MSG_NOSIGNAL);
#endif
		if (ret > 0) {
			b->r += ret;
			b->l += ret;
			cur_read += ret;
			b->flags |= BF_PARTIAL_READ;
	
			if (b->r == b->data + BUFSIZE) {
				b->r = b->data; /* wrap around the buffer */
			}

			b->total += ret;

			if (b->l == b->rlim - b->data) {
				/* The buffer is now full, there's no point in going through
				 * the loop again.
				 */
				if (!(b->flags & BF_STREAMER_FAST) && (cur_read == b->l)) {
					b->xfer_small = 0;
					b->xfer_large++;
					if (b->xfer_large >= 3) {
						/* we call this buffer a fast streamer if it manages
						 * to be filled in one call 3 consecutive times.
						 */
						b->flags |= (BF_STREAMER | BF_STREAMER_FAST);
						//fputc('+', stderr);
					}
				}
				else if ((b->flags & (BF_STREAMER | BF_STREAMER_FAST)) &&
					 (cur_read <= BUFSIZE / 2)) {
					b->xfer_large = 0;
					b->xfer_small++;
					if (b->xfer_small >= 2) {
						/* if the buffer has been at least half full twice,
						 * we receive faster than we send, so at least it
						 * is not a "fast streamer".
						 */
						b->flags &= ~BF_STREAMER_FAST;
						//fputc('-', stderr);
					}
				}
				else {
					b->xfer_small = 0;
					b->xfer_large = 0;
				}

				EV_FD_CLR(fd, DIR_RD);
				b->rex = TICK_ETERNITY;
				goto out_wakeup;
			}

			/* if too many bytes were missing from last read, it means that
			 * it's pointless trying to read again because the system does
			 * not have them in buffers. BTW, if FD_POLL_HUP was present,
			 * it means that we have reached the end and that the connection
			 * is closed.
			 */
			if (ret < max) {
				if ((b->flags & (BF_STREAMER | BF_STREAMER_FAST)) &&
				    (cur_read <= BUFSIZE / 2)) {
					b->xfer_large = 0;
					b->xfer_small++;
					if (b->xfer_small >= 3) {
						/* we have read less than half of the buffer in
						 * one pass, and this happened at least 3 times.
						 * This is definitely not a streamer.
						 */
						b->flags &= ~(BF_STREAMER | BF_STREAMER_FAST);
						//fputc('!', stderr);
					}
				}
				if (fdtab[fd].ev & FD_POLL_HUP)
					goto out_shutdown_r;
				break;
			}

			/* generally if we read something smaller than 1 or 2 MSS,
			 * it means that it's not worth trying to read again. It may
			 * also happen on headers, but the application then can stop
			 * reading before we start polling.
			 */
			if (ret < MIN_RET_FOR_READ_LOOP)
				break;

			if (--read_poll <= 0)
				break;

		}
		else if (ret == 0) {
			/* connection closed */
			goto out_shutdown_r;
		}
		else if (errno == EAGAIN) {
			/* Ignore EAGAIN but inform the poller that there is
			 * nothing to read left. But we may have done some work
			 * justifying to notify the task.
			 */
			retval = 0;
			break;
		}
		else {
			goto out_error;
		}
	} /* while (1) */

	/*
	 * The only way to get out of this loop is to have stopped reading
	 * without any error nor close, either by limiting the number of
	 * loops, or because of an EAGAIN. We only rearm the timer if we
	 * have at least read something.
	 */

	if (tick_isset(b->rex) && b->flags & BF_PARTIAL_READ)
		b->rex = tick_add_ifset(now_ms, b->rto);

 out_wakeup:
	if (b->flags & BF_READ_STATUS)
		task_wakeup(fdtab[fd].owner);
	fdtab[fd].ev &= ~FD_POLL_IN;
	return retval;

 out_shutdown_r:
	fdtab[fd].ev &= ~FD_POLL_HUP;
	b->flags |= BF_READ_NULL;
	b->rex = TICK_ETERNITY;
	goto out_wakeup;

 out_error:
	/* There was an error. we must wakeup the task. No need to clear
	 * the events, the task will do it.
	 */
	fdtab[fd].state = FD_STERROR;
	fdtab[fd].ev &= ~FD_POLL_STICKY;
	b->flags |= BF_READ_ERROR;
	b->rex = TICK_ETERNITY;
	goto out_wakeup;
}


/*
 * this function is called on a write event from a stream socket.
 * It returns 0 if we have a high confidence that we will not be
 * able to write more data without polling first. Returns non-zero
 * otherwise.
 */
int stream_sock_write(int fd) {
	__label__ out_wakeup, out_error;
	struct buffer *b = fdtab[fd].cb[DIR_WR].b;
	int ret, max, retval;
	int write_poll = MAX_WRITE_POLL_LOOPS;

#ifdef DEBUG_FULL
	fprintf(stderr,"stream_sock_write : fd=%d, owner=%p\n", fd, fdtab[fd].owner);
#endif

	retval = 1;
	if (fdtab[fd].state == FD_STERROR || (fdtab[fd].ev & FD_POLL_ERR))
		goto out_error;

	while (1) {
		if (b->l == 0) { /* let's realign the buffer to optimize I/O */
			b->r = b->w = b->lr  = b->data;
			max = 0;
		}
		else if (b->r > b->w) {
			max = b->r - b->w;
		}
		else {
			max = b->data + BUFSIZE - b->w;
		}

		if (max == 0) {
			/* may be we have received a connection acknowledgement in TCP mode without data */
			if (likely(fdtab[fd].state == FD_STCONN)) {
				/* We have no data to send to check the connection, and
				 * getsockopt() will not inform us whether the connection
				 * is still pending. So we'll reuse connect() to check the
				 * state of the socket. This has the advantage of givig us
				 * the following info :
				 *  - error
				 *  - connecting (EALREADY, EINPROGRESS)
				 *  - connected (EISCONN, 0)
				 */
				if ((connect(fd, fdtab[fd].peeraddr, fdtab[fd].peerlen) == 0))
					errno = 0;

				if (errno == EALREADY || errno == EINPROGRESS) {
					retval = 0;
					goto out_wakeup;
				}

				if (errno && errno != EISCONN)
					goto out_error;

				/* OK we just need to indicate that we got a connection
				 * and that we wrote nothing.
				 */
				b->flags |= BF_WRITE_NULL;
				fdtab[fd].state = FD_STREADY;
			}

			/* Funny, we were called to write something but there wasn't
			 * anything. Theorically we cannot get there, but just in case,
			 * let's disable the write event and pretend we never came there.
			 */
			EV_FD_CLR(fd, DIR_WR);
			b->wex = TICK_ETERNITY;
			goto out_wakeup;
		}

#ifndef MSG_NOSIGNAL
		{
			int skerr;
			socklen_t lskerr = sizeof(skerr);

			ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
			if (ret == -1 || skerr)
				ret = -1;
			else
				ret = send(fd, b->w, max, MSG_DONTWAIT);
		}
#else
		ret = send(fd, b->w, max, MSG_DONTWAIT | MSG_NOSIGNAL);
#endif

		if (ret > 0) {
			b->l -= ret;
			b->w += ret;
	    
			b->flags |= BF_PARTIAL_WRITE;
	    
			if (b->w == b->data + BUFSIZE) {
				b->w = b->data; /* wrap around the buffer */
			}

			if (!b->l) {
				EV_FD_CLR(fd, DIR_WR);
				b->wex = TICK_ETERNITY;
				goto out_wakeup;
			}

			/* if the system buffer is full, don't insist */
			if (ret < max)
				break;

			if (--write_poll <= 0)
				break;
		}
		else if (ret == 0 || errno == EAGAIN) {
			/* nothing written, just pretend we were never called
			 * and wait for the socket to be ready. But we may have
			 * done some work justifying to notify the task.
			 */
			retval = 0;
			break;
		}
		else {
			goto out_error;
		}
	} /* while (1) */

	/*
	 * The only way to get out of this loop is to have stopped writing
	 * without any error, either by limiting the number of loops, or
	 * because of an EAGAIN. We only rearm the timer if we have at least
	 * written something.
	 */

	if (tick_isset(b->wex) && b->flags & BF_PARTIAL_WRITE) {
		b->wex = tick_add_ifset(now_ms, b->wto);
		if (tick_isset(b->wex)) {
			/* FIXME: to prevent the client from expiring read timeouts during writes,
			 * we refresh it. A solution would be to merge read+write timeouts into a
			 * unique one, although that needs some study particularly on full-duplex
			 * TCP connections. */
			if (tick_isset(b->rex) && !(b->flags & BF_SHUTR))
				b->rex = b->wex;
		}
	}

 out_wakeup:
	if (b->flags & BF_WRITE_STATUS)
		task_wakeup(fdtab[fd].owner);
	fdtab[fd].ev &= ~FD_POLL_OUT;
	return retval;

 out_error:
	/* There was an error. we must wakeup the task. No need to clear
	 * the events, the task will do it.
	 */
	fdtab[fd].state = FD_STERROR;
	fdtab[fd].ev &= ~FD_POLL_STICKY;
	b->flags |= BF_WRITE_ERROR;
	b->wex = TICK_ETERNITY;
	goto out_wakeup;
}



/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
