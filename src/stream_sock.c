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

#include <proto/buffers.h>
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
	struct stream_interface *si = fdtab[fd].owner;
	struct buffer *b = si->ib;
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
			b->flags |= BF_FULL;
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
			b->flags |= BF_READ_PARTIAL;
			b->flags &= ~BF_EMPTY;
	
			if (b->r == b->data + BUFSIZE) {
				b->r = b->data; /* wrap around the buffer */
			}

			b->total += ret;

			if (b->l >= b->rlim - b->data) {
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

				b->flags |= BF_FULL;
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
				/* unfortunately, on level-triggered events, POLL_HUP
				 * is generally delivered AFTER the system buffer is
				 * empty, so this one might never match.
				 */
				if (fdtab[fd].ev & FD_POLL_HUP)
					goto out_shutdown_r;

				/* if a streamer has read few data, it may be because we
				 * have exhausted system buffers. It's not worth trying
				 * again.
				 */
				if (b->flags & BF_STREAMER)
					break;
			}

			/* generally if we read something smaller than 1 or 2 MSS,
			 * it means that either we have exhausted the system's
			 * buffers (streamer or question-response protocol) or that
			 * the connection will be closed. Streamers are easily
			 * detected so we return early. For other cases, it's still
			 * better to perform a last read to be sure, because it may
			 * save one complete poll/read/wakeup cycle in case of shutdown.
			 */
			if (ret < MIN_RET_FOR_READ_LOOP && b->flags & BF_STREAMER)
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

	if (tick_isset(b->rex) && b->flags & BF_READ_PARTIAL)
		b->rex = tick_add_ifset(now_ms, b->rto);

	if (!(b->flags & BF_READ_ACTIVITY))
		goto out_skip_wakeup;
 out_wakeup:
	task_wakeup(si->owner, TASK_WOKEN_IO);

 out_skip_wakeup:
	fdtab[fd].ev &= ~FD_POLL_IN;
	return retval;

 out_shutdown_r:
	/* we received a shutdown */
	fdtab[fd].ev &= ~FD_POLL_HUP;
	b->flags |= BF_READ_NULL;
	buffer_shutr(b);

	/* Maybe we have to completely close the local socket */
	if (si->ob->flags & BF_SHUTW)
		goto do_close_and_return;
	EV_FD_CLR(fd, DIR_RD);
	goto out_wakeup;

 out_error:
	/* There was an error. we must wakeup the task. No need to clear
	 * the events, the task will do it.
	 */
	fdtab[fd].state = FD_STERROR;
	fdtab[fd].ev &= ~FD_POLL_STICKY;
	b->rex = TICK_ETERNITY;

	/* Read error on the file descriptor. We close the FD and set
	 * the error on both buffers.
	 * Note: right now we only support connected sockets.
	 */
	if (si->state != SI_ST_EST)
		goto out_wakeup;

	if (!si->err_type)
		si->err_type = SI_ET_DATA_ERR;

	buffer_shutr(b);
	b->flags |= BF_READ_ERROR;
	buffer_shutw(si->ob);
	si->ob->flags |= BF_WRITE_ERROR;

 do_close_and_return:
	fd_delete(fd);
	si->state = SI_ST_CLO;
	task_wakeup(si->owner, TASK_WOKEN_IO);
	return 1;
}


/*
 * this function is called on a write event from a stream socket.
 * It returns 0 if we have a high confidence that we will not be
 * able to write more data without polling first. Returns non-zero
 * otherwise.
 */
int stream_sock_write(int fd) {
	__label__ out_wakeup, out_error;
	struct stream_interface *si = fdtab[fd].owner;
	struct buffer *b = si->ob;
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
					goto out_may_wakeup;
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
	    
			b->flags |= BF_WRITE_PARTIAL;

			if (b->l < b->rlim - b->data)
				b->flags &= ~BF_FULL;
	    
			if (b->w == b->data + BUFSIZE) {
				b->w = b->data; /* wrap around the buffer */
			}

			if (!b->l) {
				b->flags |= BF_EMPTY;

				/* Maybe we just wrote the last chunk and need to close ? */
				if ((b->flags & (BF_SHUTW|BF_EMPTY|BF_HIJACK|BF_WRITE_ENA|BF_SHUTR)) == (BF_EMPTY|BF_WRITE_ENA|BF_SHUTR)) {
					if (si->state == SI_ST_EST) {
						buffer_shutw(b);
						if (si->ib->flags & BF_SHUTR)
							goto do_close_and_return;
						shutdown(fd, SHUT_WR);
					}
				}

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

	if (tick_isset(b->wex) && b->flags & BF_WRITE_PARTIAL) {
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

 out_may_wakeup:
	if (!(b->flags & BF_WRITE_ACTIVITY))
		goto out_skip_wakeup;
 out_wakeup:
	task_wakeup(si->owner, TASK_WOKEN_IO);

 out_skip_wakeup:
	fdtab[fd].ev &= ~FD_POLL_OUT;
	return retval;

 out_error:
	/* There was an error. we must wakeup the task. No need to clear
	 * the events, the task will do it.
	 */
	fdtab[fd].state = FD_STERROR;
	fdtab[fd].ev &= ~FD_POLL_STICKY;
	b->wex = TICK_ETERNITY;
	/* Read error on the file descriptor. We close the FD and set
	 * the error on both buffers.
	 * Note: right now we only support connected sockets.
	 */
	if (si->state != SI_ST_EST)
		goto out_wakeup;

	if (!si->err_type)
		si->err_type = SI_ET_DATA_ERR;

	buffer_shutw(b);
	b->flags |= BF_WRITE_ERROR;
	buffer_shutr(si->ib);
	si->ib->flags |= BF_READ_ERROR;
 do_close_and_return:
	fd_delete(fd);
	si->state = SI_ST_CLO;
	task_wakeup(si->owner, TASK_WOKEN_IO);
	return 1;
}

/*
 * This function performs a shutdown-write on a stream interface in a connected or
 * init state (it does nothing for other states). It either shuts the write side
 * closes the file descriptor and marks itself as closed. No buffer flags are
 * changed, it's up to the caller to adjust them. The sole purpose of this
 * function is to be called from the other stream interface to notify of a
 * close_read, or by itself upon a full write leading to an empty buffer.
 * It normally returns zero, unless it has completely closed the socket, in
 * which case it returns 1.
 */
int stream_sock_shutw(struct stream_interface *si)
{
	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return 0;

	if (si->ib->flags & BF_SHUTR) {
		fd_delete(si->fd);
		si->state = SI_ST_CLO;
		return 1;
	}
	EV_FD_CLR(si->fd, DIR_WR);
	shutdown(si->fd, SHUT_WR);
	return 0;
}

/*
 * This function performs a shutdown-read on a stream interface in a connected or
 * init state (it does nothing for other states). It either shuts the read side or
 * closes the file descriptor and marks itself as closed. No buffer flags are
 * changed, it's up to the caller to adjust them. The sole purpose of this
 * function is to be called from the other stream interface to notify of a
 * close_read, or by itself upon a full write leading to an empty buffer.
 * It normally returns zero, unless it has completely closed the socket, in
 * which case it returns 1.
 */
int stream_sock_shutr(struct stream_interface *si)
{
	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return 0;

	if (si->ib->flags & BF_SHUTW) {
		fd_delete(si->fd);
		si->state = SI_ST_CLO;
		return 1;
	}
	EV_FD_CLR(si->fd, DIR_RD);
	return 0;
}

/*
 * This function only has to be called once after a wakeup event in case of
 * suspected timeout. It controls the stream interface timeouts and sets
 * si->flags accordingly. It does NOT close anything, as this timeout may
 * be used for any purpose. It returns 1 if the timeout fired, otherwise
 * zero.
 */
int stream_sock_check_timeouts(struct stream_interface *si)
{
	if (tick_is_expired(si->exp, now_ms)) {
		si->flags |= SI_FL_EXP;
		return 1;
	}
	return 0;
}

/*
 * Manages a stream_sock connection during its data phase. The buffers are
 * examined for various cases of shutdown, then file descriptor and buffers'
 * flags are updated accordingly.
 */
int stream_sock_data_update(int fd)
{
	struct buffer *ib = fdtab[fd].cb[DIR_RD].b;
	struct buffer *ob = fdtab[fd].cb[DIR_WR].b;

	DPRINTF(stderr,"[%u] %s: fd=%d owner=%p ib=%p, ob=%p, exp(r,w)=%u,%u ibf=%08x obf=%08x ibl=%d obl=%d si=%d\n",
		now_ms, __FUNCTION__,
		fd, fdtab[fd].owner,
		ib, ob,
		ib->rex, ob->wex,
		ib->flags, ob->flags,
		ib->l, ob->l, ob->cons->state);

	/* Check if we need to close the read side */
	if (!(ib->flags & BF_SHUTR)) {
		/* Last read, forced read-shutdown, or other end closed */
		if (ib->flags & (BF_SHUTR_NOW|BF_SHUTW)) {
			//trace_term(t, TT_HTTP_SRV_10);
			buffer_shutr(ib);
			if (ob->flags & BF_SHUTW) {
				fd_delete(fd);
				ob->cons->state = SI_ST_CLO;
				return 0;
			}
			EV_FD_CLR(fd, DIR_RD);
		}
	}

	/* Check if we need to close the write side */
	if (!(ob->flags & BF_SHUTW)) {
		/* Forced write-shutdown or other end closed with empty buffer. */
		if ((ob->flags & BF_SHUTW_NOW) ||
		    (ob->flags & (BF_EMPTY|BF_HIJACK|BF_WRITE_ENA|BF_SHUTR)) == (BF_EMPTY|BF_WRITE_ENA|BF_SHUTR)) {
			//trace_term(t, TT_HTTP_SRV_11);
			buffer_shutw(ob);
			if (ib->flags & BF_SHUTR) {
				fd_delete(fd);
				ob->cons->state = SI_ST_CLO;
				return 0;
			}
			EV_FD_CLR(fd, DIR_WR);
			shutdown(fd, SHUT_WR);
		}
	}
	return 0; /* other cases change nothing */
}


/*
 * Updates a connected stream_sock file descriptor status and timeouts
 * according to the buffers' flags. It should only be called once after the
 * buffer flags have settled down, and before they are cleared. It doesn't
 * harm to call it as often as desired (it just slightly hurts performance).
 */
int stream_sock_data_finish(int fd)
{
	struct buffer *ib = fdtab[fd].cb[DIR_RD].b;
	struct buffer *ob = fdtab[fd].cb[DIR_WR].b;

	DPRINTF(stderr,"[%u] %s: fd=%d owner=%p ib=%p, ob=%p, exp(r,w)=%u,%u ibf=%08x obf=%08x ibl=%d obl=%d si=%d\n",
		now_ms, __FUNCTION__,
		fd, fdtab[fd].owner,
		ib, ob,
		ib->rex, ob->wex,
		ib->flags, ob->flags,
		ib->l, ob->l, ob->cons->state);

	/* Check if we need to close the read side */
	if (!(ib->flags & BF_SHUTR)) {
		/* Read not closed, update FD status and timeout for reads */
		if (ib->flags & (BF_FULL|BF_HIJACK)) {
			/* stop reading */
			EV_FD_COND_C(fd, DIR_RD);
			ib->rex = TICK_ETERNITY;
		}
		else {
			/* (re)start reading and update timeout. Note: we don't recompute the timeout
			 * everytime we get here, otherwise it would risk never to expire. We only
			 * update it if is was not yet set, or if we already got some read status.
			 */
			EV_FD_COND_S(fd, DIR_RD);
			if (!tick_isset(ib->rex) || ib->flags & BF_READ_ACTIVITY)
				ib->rex = tick_add_ifset(now_ms, ib->rto);
		}
	}

	/* Check if we need to close the write side */
	if (!(ob->flags & BF_SHUTW)) {
		/* Write not closed, update FD status and timeout for writes */
		if ((ob->flags & BF_EMPTY) ||
		    (ob->flags & (BF_HIJACK|BF_WRITE_ENA)) == 0) {
			/* stop writing */
			EV_FD_COND_C(fd, DIR_WR);
			ob->wex = TICK_ETERNITY;
		}
		else {
			/* (re)start writing and update timeout. Note: we don't recompute the timeout
			 * everytime we get here, otherwise it would risk never to expire. We only
			 * update it if is was not yet set, or if we already got some write status.
			 */
			EV_FD_COND_S(fd, DIR_WR);
			if (!tick_isset(ob->wex) || ob->flags & BF_WRITE_ACTIVITY) {
				ob->wex = tick_add_ifset(now_ms, ob->wto);
				if (tick_isset(ob->wex) && tick_isset(ib->rex)) {
					/* Note: depending on the protocol, we don't know if we're waiting
					 * for incoming data or not. So in order to prevent the socket from
					 * expiring read timeouts during writes, we refresh the read timeout,
					 * except if it was already infinite.
					 */
					ib->rex = ob->wex;
				}
			}
		}
	}
	return 0;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
