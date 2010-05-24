/*
 * Functions operating on SOCK_STREAM and buffers.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
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

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/buffers.h>
#include <proto/fd.h>
#include <proto/pipe.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

#include <types/global.h>

/* On recent Linux kernels, the splice() syscall may be used for faster data copy.
 * But it's not always defined on some OS versions, and it even happens that some
 * definitions are wrong with some glibc due to an offset bug in syscall().
 */

#if defined(CONFIG_HAP_LINUX_SPLICE)
#include <unistd.h>
#include <sys/syscall.h>

#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE           0x1
#endif

#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK       0x2
#endif

#ifndef SPLICE_F_MORE
#define SPLICE_F_MORE           0x4
#endif

#ifndef __NR_splice
#if defined(__powerpc__) || defined(__powerpc64__)
#define __NR_splice             283
#elif defined(__sparc__) || defined(__sparc64__)
#define __NR_splice             232
#elif defined(__x86_64__)
#define __NR_splice             275
#elif defined(__alpha__)
#define __NR_splice             468
#elif defined (__i386__)
#define __NR_splice             313
#else
#warning unsupported architecture, guessing __NR_splice=313 like x86...
#define __NR_splice             313
#endif /* $arch */

_syscall6(int, splice, int, fdin, loff_t *, off_in, int, fdout, loff_t *, off_out, size_t, len, unsigned long, flags)

#endif /* __NR_splice */

/* A pipe contains 16 segments max, and it's common to see segments of 1448 bytes
 * because of timestamps. Use this as a hint for not looping on splice().
 */
#define SPLICE_FULL_HINT	16*1448

/* how many data we attempt to splice at once when the buffer is configured for
 * infinite forwarding */
#define MAX_SPLICE_AT_ONCE	(1<<30)

/* Returns :
 *   -1 if splice is not possible or not possible anymore and we must switch to
 *      user-land copy (eg: to_forward reached)
 *    0 when we know that polling is required to get more data (EAGAIN)
 *    1 for all other cases (we can safely try again, or if an activity has been
 *      detected (DATA/NULL/ERR))
 * Sets :
 *   BF_READ_NULL
 *   BF_READ_PARTIAL
 *   BF_WRITE_PARTIAL (during copy)
 *   BF_OUT_EMPTY (during copy)
 *   SI_FL_ERR
 *   SI_FL_WAIT_ROOM
 *   (SI_FL_WAIT_RECV)
 *
 * This function automatically allocates a pipe from the pipe pool. It also
 * carefully ensures to clear b->pipe whenever it leaves the pipe empty.
 */
static int stream_sock_splice_in(struct buffer *b, struct stream_interface *si)
{
	int fd = si->fd;
	int ret;
	unsigned long max;
	int retval = 1;

	if (!b->to_forward)
		return -1;

	if (!(b->flags & BF_KERN_SPLICING))
		return -1;

	if (b->l) {
		/* We're embarrassed, there are already data pending in
		 * the buffer and we don't want to have them at two
		 * locations at a time. Let's indicate we need some
		 * place and ask the consumer to hurry.
		 */
		si->flags |= SI_FL_WAIT_ROOM;
		EV_FD_CLR(fd, DIR_RD);
		b->rex = TICK_ETERNITY;
		b->cons->chk_snd(b->cons);
		return 1;
	}

	if (unlikely(b->pipe == NULL)) {
		if (pipes_used >= global.maxpipes || !(b->pipe = get_pipe())) {
			b->flags &= ~BF_KERN_SPLICING;
			return -1;
		}
	}

	/* At this point, b->pipe is valid */

	while (1) {
		if (b->to_forward == BUF_INFINITE_FORWARD)
			max = MAX_SPLICE_AT_ONCE;
		else
			max = b->to_forward;

		if (!max) {
			/* It looks like the buffer + the pipe already contain
			 * the maximum amount of data to be transferred. Try to
			 * send those data immediately on the other side if it
			 * is currently waiting.
			 */
			retval = -1; /* end of forwarding */
			break;
		}

		ret = splice(fd, NULL, b->pipe->prod, NULL, max,
			     SPLICE_F_MOVE|SPLICE_F_NONBLOCK);

		if (ret <= 0) {
			if (ret == 0) {
				/* connection closed. This is only detected by
				 * recent kernels (>= 2.6.27.13).
				 */
				b->flags |= BF_READ_NULL;
				retval = 1; /* no need for further polling */
				break;
			}

			if (errno == EAGAIN) {
				/* there are two reasons for EAGAIN :
				 *   - nothing in the socket buffer (standard)
				 *   - pipe is full
				 *   - the connection is closed (kernel < 2.6.27.13)
				 * Since we don't know if pipe is full, we'll
				 * stop if the pipe is not empty. Anyway, we
				 * will almost always fill/empty the pipe.
				 */

				if (b->pipe->data) {
					si->flags |= SI_FL_WAIT_ROOM;
					retval = 1;
					break;
				}

				/* We don't know if the connection was closed.
				 * But if we're called upon POLLIN with an empty
				 * pipe and get EAGAIN, it is suspect enought to
				 * try to fall back to the normal recv scheme
				 * which will be able to deal with the situation.
				 */
				retval = -1;
				break;
			}

			if (errno == ENOSYS || errno == EINVAL) {
				/* splice not supported on this end, disable it */
				b->flags &= ~BF_KERN_SPLICING;
				si->flags &= ~SI_FL_CAP_SPLICE;
				put_pipe(b->pipe);
				b->pipe = NULL;
				return -1;
			}

			/* here we have another error */
			si->flags |= SI_FL_ERR;
			retval = 1;
			break;
		} /* ret <= 0 */

		if (b->to_forward != BUF_INFINITE_FORWARD)
			b->to_forward -= ret;
		b->total += ret;
		b->pipe->data += ret;
		b->flags |= BF_READ_PARTIAL;
		b->flags &= ~BF_OUT_EMPTY;

		if (b->pipe->data >= SPLICE_FULL_HINT ||
		    ret >= global.tune.recv_enough) {
			/* We've read enough of it for this time. */
			retval = 1;
			break;
		}
	} /* while */

	if (unlikely(!b->pipe->data)) {
		put_pipe(b->pipe);
		b->pipe = NULL;
	}

	return retval;
}

#endif /* CONFIG_HAP_LINUX_SPLICE */


/*
 * this function is called on a read event from a stream socket.
 * It returns 0 if we have a high confidence that we will not be
 * able to read more data without polling first. Returns non-zero
 * otherwise.
 */
int stream_sock_read(int fd) {
	struct stream_interface *si = fdtab[fd].owner;
	struct buffer *b = si->ib;
	int ret, max, retval, cur_read;
	int read_poll = MAX_READ_POLL_LOOPS;

#ifdef DEBUG_FULL
	fprintf(stderr,"stream_sock_read : fd=%d, ev=0x%02x, owner=%p\n", fd, fdtab[fd].ev, fdtab[fd].owner);
#endif

	retval = 1;

	/* stop immediately on errors. Note that we DON'T want to stop on
	 * POLL_ERR, as the poller might report a write error while there
	 * are still data available in the recv buffer. This typically
	 * happens when we send too large a request to a backend server
	 * which rejects it before reading it all.
	 */
	if (fdtab[fd].state == FD_STERROR)
		goto out_error;

	/* stop here if we reached the end of data */
	if ((fdtab[fd].ev & (FD_POLL_IN|FD_POLL_HUP)) == FD_POLL_HUP)
		goto out_shutdown_r;

	/* maybe we were called immediately after an asynchronous shutr */
	if (b->flags & BF_SHUTR)
		goto out_wakeup;

#if defined(CONFIG_HAP_LINUX_SPLICE)
	if (b->to_forward && b->flags & BF_KERN_SPLICING) {

		/* Under Linux, if FD_POLL_HUP is set, we have reached the end.
		 * Since older splice() implementations were buggy and returned
		 * EAGAIN on end of read, let's bypass the call to splice() now.
		 */
		if (fdtab[fd].ev & FD_POLL_HUP)
			goto out_shutdown_r;

		retval = stream_sock_splice_in(b, si);

		if (retval >= 0) {
			if (si->flags & SI_FL_ERR)
				goto out_error;
			if (b->flags & BF_READ_NULL)
				goto out_shutdown_r;
			goto out_wakeup;
		}
		/* splice not possible (anymore), let's go on on standard copy */
	}
#endif
	cur_read = 0;
	while (1) {
		max = buffer_max_len(b) - b->l;

		if (max <= 0) {
			b->flags |= BF_FULL;
			si->flags |= SI_FL_WAIT_ROOM;
			break;
		}

		/*
		 * 1. compute the maximum block size we can read at once.
		 */
		if (b->l == 0) {
			/* let's realign the buffer to optimize I/O */
			b->r = b->w = b->lr = b->data;
		}
		else if (b->r > b->w) {
			/* remaining space wraps at the end, with a moving limit */
			if (max > b->data + b->size - b->r)
				max = b->data + b->size - b->r;
		}
		/* else max is already OK */

		/*
		 * 2. read the largest possible block
		 */
		ret = recv(fd, b->r, max, 0);

		if (ret > 0) {
			b->r += ret;
			b->l += ret;
			cur_read += ret;

			/* if we're allowed to directly forward data, we must update send_max */
			if (b->to_forward && !(b->flags & (BF_SHUTW|BF_SHUTW_NOW))) {
				unsigned long fwd = ret;
				if (b->to_forward != BUF_INFINITE_FORWARD) {
					if (fwd > b->to_forward)
						fwd = b->to_forward;
					b->to_forward -= fwd;
				}
				b->send_max += fwd;
				b->flags &= ~BF_OUT_EMPTY;
			}

			if (fdtab[fd].state == FD_STCONN)
				fdtab[fd].state = FD_STREADY;

			b->flags |= BF_READ_PARTIAL;

			if (b->r == b->data + b->size) {
				b->r = b->data; /* wrap around the buffer */
			}

			b->total += ret;

			if (b->l >= buffer_max_len(b)) {
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
					 (cur_read <= b->size / 2)) {
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
				si->flags |= SI_FL_WAIT_ROOM;
				break;
			}

			/* if too many bytes were missing from last read, it means that
			 * it's pointless trying to read again because the system does
			 * not have them in buffers. BTW, if FD_POLL_HUP was present,
			 * it means that we have reached the end and that the connection
			 * is closed.
			 */
			if (ret < max) {
				if ((b->flags & (BF_STREAMER | BF_STREAMER_FAST)) &&
				    (cur_read <= b->size / 2)) {
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

				/* generally if we read something smaller than 1 or 2 MSS,
				 * it means that either we have exhausted the system's
				 * buffers (streamer or question-response protocol) or
				 * that the connection will be closed. Streamers are
				 * easily detected so we return early. For other cases,
				 * it's still better to perform a last read to be sure,
				 * because it may save one complete poll/read/wakeup cycle
				 * in case of shutdown.
				 */
				if (ret < MIN_RET_FOR_READ_LOOP && b->flags & BF_STREAMER)
					break;

				/* if we read a large block smaller than what we requested,
				 * it's almost certain we'll never get anything more.
				 */
				if (ret >= global.tune.recv_enough)
					break;
			}

			if ((b->flags & BF_READ_DONTWAIT) || --read_poll <= 0)
				break;
		}
		else if (ret == 0) {
			/* connection closed */
			goto out_shutdown_r;
		}
		else if (errno == EAGAIN) {
			/* Ignore EAGAIN but inform the poller that there is
			 * nothing to read left if we did not read much, ie
			 * less than what we were still expecting to read.
			 * But we may have done some work justifying to notify
			 * the task.
			 */
			if (cur_read < MIN_RET_FOR_READ_LOOP)
				retval = 0;
			break;
		}
		else {
			goto out_error;
		}
	} /* while (1) */

 out_wakeup:
	/* We might have some data the consumer is waiting for */
	if (!(b->flags & BF_OUT_EMPTY) && (b->cons->flags & SI_FL_WAIT_DATA)) {
		int last_len = b->pipe ? b->pipe->data : 0;

		b->cons->chk_snd(b->cons);

		/* check if the consumer has freed some space */
		if (!(b->flags & BF_FULL) &&
		    (!last_len || !b->pipe || b->pipe->data < last_len))
			si->flags &= ~SI_FL_WAIT_ROOM;
	}

	if (si->flags & SI_FL_WAIT_ROOM) {
		EV_FD_CLR(fd, DIR_RD);
		b->rex = TICK_ETERNITY;
	}
	else if ((b->flags & (BF_SHUTR|BF_READ_PARTIAL|BF_FULL|BF_DONT_READ|BF_READ_NOEXP)) == BF_READ_PARTIAL)
		b->rex = tick_add_ifset(now_ms, b->rto);

	/* we have to wake up if there is a special event or if we don't have
	 * any more data to forward.
	 */
	if ((b->flags & (BF_READ_NULL|BF_READ_ERROR|BF_SHUTR|BF_READ_DONTWAIT)) ||
	    !b->to_forward ||
	    si->state != SI_ST_EST ||
	    b->cons->state != SI_ST_EST ||
	    (si->flags & SI_FL_ERR))
		task_wakeup(si->owner, TASK_WOKEN_IO);
	
	b->flags &= ~BF_READ_DONTWAIT;
	fdtab[fd].ev &= ~FD_POLL_IN;
	return retval;

 out_shutdown_r:
	/* we received a shutdown */
	fdtab[fd].ev &= ~FD_POLL_HUP;
	b->flags |= BF_READ_NULL;
	if (b->flags & BF_AUTO_CLOSE)
		buffer_shutw_now(b);
	stream_sock_shutr(si);
	goto out_wakeup;

 out_error:
	/* Read error on the file descriptor. We mark the FD as STERROR so
	 * that we don't use it anymore. The error is reported to the stream
	 * interface which will take proper action. We must not perturbate the
	 * buffer because the stream interface wants to ensure transparent
	 * connection retries.
	 */

	fdtab[fd].state = FD_STERROR;
	fdtab[fd].ev &= ~FD_POLL_STICKY;
	EV_FD_REM(fd);
	si->flags |= SI_FL_ERR;
	retval = 1;
	goto out_wakeup;
}


/*
 * This function is called to send buffer data to a stream socket.
 * It returns -1 in case of unrecoverable error, 0 if the caller needs to poll
 * before calling it again, otherwise 1. If a pipe was associated with the
 * buffer and it empties it, it releases it as well.
 */
static int stream_sock_write_loop(struct stream_interface *si, struct buffer *b)
{
	int write_poll = MAX_WRITE_POLL_LOOPS;
	int retval = 1;
	int ret, max;

#if defined(CONFIG_HAP_LINUX_SPLICE)
	while (b->pipe) {
		ret = splice(b->pipe->cons, NULL, si->fd, NULL, b->pipe->data,
			     SPLICE_F_MOVE|SPLICE_F_NONBLOCK);
		if (ret <= 0) {
			if (ret == 0 || errno == EAGAIN) {
				retval = 0;
				return retval;
			}
			/* here we have another error */
			retval = -1;
			return retval;
		}

		b->flags |= BF_WRITE_PARTIAL;
		b->pipe->data -= ret;

		if (!b->pipe->data) {
			put_pipe(b->pipe);
			b->pipe = NULL;
			break;
		}

		if (--write_poll <= 0)
			return retval;
	}

	/* At this point, the pipe is empty, but we may still have data pending
	 * in the normal buffer.
	 */
#endif
	if (!b->send_max) {
		b->flags |= BF_OUT_EMPTY;
		return retval;
	}

	/* when we're in this loop, we already know that there is no spliced
	 * data left, and that there are sendable buffered data.
	 */
	while (1) {
		if (b->r > b->w)
			max = b->r - b->w;
		else
			max = b->data + b->size - b->w;

		/* limit the amount of outgoing data if required */
		if (max > b->send_max)
			max = b->send_max;

		/* check if we want to inform the kernel that we're interested in
		 * sending more data after this call. We want this if :
		 *  - we're about to close after this last send and want to merge
		 *    the ongoing FIN with the last segment.
		 *  - we know we can't send everything at once and must get back
		 *    here because of unaligned data
		 *  - there is still a finite amount of data to forward
		 * The test is arranged so that the most common case does only 2
		 * tests.
		 */

		if (MSG_NOSIGNAL && MSG_MORE) {
			unsigned int send_flag = MSG_DONTWAIT | MSG_NOSIGNAL;

			if (((b->to_forward && b->to_forward != BUF_INFINITE_FORWARD) ||
			     ((b->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_HIJACK)) == BF_SHUTW_NOW && (max == b->send_max)) ||
			     (max != b->l && max != b->send_max))
			    && (fdtab[si->fd].flags & FD_FL_TCP)) {
				send_flag |= MSG_MORE;
			}
			else if (b->flags & BF_EXPECT_MORE) {
				/* it was forced on the buffer, this flag is one-shoot */
				b->flags &= ~BF_EXPECT_MORE;
				send_flag |= MSG_MORE;
			}

			/* this flag has precedence over the rest */
			if (b->flags & BF_SEND_DONTWAIT)
				send_flag &= ~MSG_MORE;

			ret = send(si->fd, b->w, max, send_flag);

			/* disable it only once everything has been sent */
			if (ret == max && (b->flags & BF_SEND_DONTWAIT))
				b->flags &= ~BF_SEND_DONTWAIT;
		} else {
			int skerr;
			socklen_t lskerr = sizeof(skerr);

			ret = getsockopt(si->fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
			if (ret == -1 || skerr)
				ret = -1;
			else
				ret = send(si->fd, b->w, max, MSG_DONTWAIT);
		}

		if (ret > 0) {
			if (fdtab[si->fd].state == FD_STCONN)
				fdtab[si->fd].state = FD_STREADY;

			b->flags |= BF_WRITE_PARTIAL;

			b->w += ret;
			if (b->w == b->data + b->size)
				b->w = b->data; /* wrap around the buffer */

			b->l -= ret;
			if (likely(b->l < buffer_max_len(b)))
				b->flags &= ~BF_FULL;

			if (likely(!b->l))
				/* optimize data alignment in the buffer */
				b->r = b->w = b->lr = b->data;

			b->send_max -= ret;
			if (!b->send_max) {
				if (likely(!b->pipe))
					b->flags |= BF_OUT_EMPTY;
				break;
			}

			/* if the system buffer is full, don't insist */
			if (ret < max)
				break;

			if (--write_poll <= 0)
				break;
		}
		else if (ret == 0 || errno == EAGAIN) {
			/* nothing written, we need to poll for write first */
			retval = 0;
			break;
		}
		else {
			/* bad, we got an error */
			retval = -1;
			break;
		}
	} /* while (1) */

	return retval;
}


/*
 * This function is called on a write event from a stream socket.
 * It returns 0 if the caller needs to poll before calling it again, otherwise
 * non-zero.
 */
int stream_sock_write(int fd)
{
	struct stream_interface *si = fdtab[fd].owner;
	struct buffer *b = si->ob;
	int retval = 1;

#ifdef DEBUG_FULL
	fprintf(stderr,"stream_sock_write : fd=%d, owner=%p\n", fd, fdtab[fd].owner);
#endif

	retval = 1;
	if (fdtab[fd].state == FD_STERROR)
		goto out_error;

	/* we might have been called just after an asynchronous shutw */
	if (b->flags & BF_SHUTW)
		goto out_wakeup;

	if (likely(!(b->flags & BF_OUT_EMPTY))) {
		/* OK there are data waiting to be sent */
		retval = stream_sock_write_loop(si, b);
		if (retval < 0)
			goto out_error;
	}
	else  {
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
			if ((connect(fd, fdinfo[fd].peeraddr, fdinfo[fd].peerlen) == 0))
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
		 * anything. We can get there, for example if we were woken up
		 * on a write event to finish the splice, but the send_max is 0
		 * so we cannot write anything from the buffer. Let's disable
		 * the write event and pretend we never came there.
		 */
	}

	if (b->flags & BF_OUT_EMPTY) {
		/* the connection is established but we can't write. Either the
		 * buffer is empty, or we just refrain from sending because the
		 * send_max limit was reached. Maybe we just wrote the last
		 * chunk and need to close.
		 */
		if (((b->flags & (BF_SHUTW|BF_HIJACK|BF_SHUTW_NOW)) == BF_SHUTW_NOW) &&
		    (si->state == SI_ST_EST)) {
			stream_sock_shutw(si);
			goto out_wakeup;
		}
		
		if ((b->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_FULL|BF_HIJACK)) == 0)
			si->flags |= SI_FL_WAIT_DATA;

		EV_FD_CLR(fd, DIR_WR);
		b->wex = TICK_ETERNITY;
	}

 out_may_wakeup:
	if (b->flags & BF_WRITE_ACTIVITY) {
		/* update timeout if we have written something */
		if ((b->flags & (BF_OUT_EMPTY|BF_SHUTW|BF_WRITE_PARTIAL)) == BF_WRITE_PARTIAL)
			b->wex = tick_add_ifset(now_ms, b->wto);

	out_wakeup:
		if (tick_isset(si->ib->rex) && !(si->flags & SI_FL_INDEP_STR)) {
			/* Note: to prevent the client from expiring read timeouts
			 * during writes, we refresh it. We only do this if the
			 * interface is not configured for "independant streams",
			 * because for some applications it's better not to do this,
			 * for instance when continuously exchanging small amounts
			 * of data which can full the socket buffers long before a
			 * write timeout is detected.
			 */
			si->ib->rex = tick_add_ifset(now_ms, si->ib->rto);
		}

		/* the producer might be waiting for more room to store data */
		if (likely((b->flags & (BF_SHUTW|BF_WRITE_PARTIAL|BF_FULL|BF_DONT_READ)) == BF_WRITE_PARTIAL &&
			   (b->prod->flags & SI_FL_WAIT_ROOM)))
			b->prod->chk_rcv(b->prod);

		/* we have to wake up if there is a special event or if we don't have
		 * any more data to forward and it's not planned to send any more.
		 */
		if (likely((b->flags & (BF_WRITE_NULL|BF_WRITE_ERROR|BF_SHUTW)) ||
			   ((b->flags & BF_OUT_EMPTY) && !b->to_forward) ||
			   si->state != SI_ST_EST ||
			   b->prod->state != SI_ST_EST))
			task_wakeup(si->owner, TASK_WOKEN_IO);
	}

	fdtab[fd].ev &= ~FD_POLL_OUT;
	return retval;

 out_error:
	/* Write error on the file descriptor. We mark the FD as STERROR so
	 * that we don't use it anymore. The error is reported to the stream
	 * interface which will take proper action. We must not perturbate the
	 * buffer because the stream interface wants to ensure transparent
	 * connection retries.
	 */

	fdtab[fd].state = FD_STERROR;
	fdtab[fd].ev &= ~FD_POLL_STICKY;
	EV_FD_REM(fd);
	si->flags |= SI_FL_ERR;
	task_wakeup(si->owner, TASK_WOKEN_IO);
	return 1;
}

/*
 * This function performs a shutdown-write on a stream interface in a connected or
 * init state (it does nothing for other states). It either shuts the write side
 * or closes the file descriptor and marks itself as closed. The buffer flags are
 * updated to reflect the new state. It does also close everything is the SI was
 * marked as being in error state.
 */
void stream_sock_shutw(struct stream_interface *si)
{
	si->ob->flags &= ~BF_SHUTW_NOW;
	if (si->ob->flags & BF_SHUTW)
		return;
	si->ob->flags |= BF_SHUTW;
	si->ob->wex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_DATA;

	switch (si->state) {
	case SI_ST_EST:
		/* we have to shut before closing, otherwise some short messages
		 * may never leave the system, especially when there are remaining
		 * unread data in the socket input buffer, or when nolinger is set.
		 * However, if SI_FL_NOLINGER is explicitly set, we know there is
		 * no risk so we close both sides immediately.
		 */
		if (si->flags & SI_FL_ERR) {
			/* quick close, the socket is already shut. Remove pending flags. */
			si->flags &= ~SI_FL_NOLINGER;
		} else if (si->flags & SI_FL_NOLINGER) {
			si->flags &= ~SI_FL_NOLINGER;
			setsockopt(si->fd, SOL_SOCKET, SO_LINGER,
				   (struct linger *) &nolinger, sizeof(struct linger));
		} else {
			EV_FD_CLR(si->fd, DIR_WR);
			shutdown(si->fd, SHUT_WR);

			if (!(si->ib->flags & (BF_SHUTR|BF_DONT_READ)))
				return;
		}

		/* fall through */
	case SI_ST_CON:
		/* we may have to close a pending connection, and mark the
		 * response buffer as shutr
		 */
		fd_delete(si->fd);
		/* fall through */
	case SI_ST_CER:
		si->state = SI_ST_DIS;
	default:
		si->flags &= ~SI_FL_WAIT_ROOM;
		si->ib->flags |= BF_SHUTR;
		si->ib->rex = TICK_ETERNITY;
		si->exp = TICK_ETERNITY;
		return;
	}
}

/*
 * This function performs a shutdown-read on a stream interface in a connected or
 * init state (it does nothing for other states). It either shuts the read side
 * or closes the file descriptor and marks itself as closed. The buffer flags are
 * updated to reflect the new state.
 */
void stream_sock_shutr(struct stream_interface *si)
{
	si->ib->flags &= ~BF_SHUTR_NOW;
	if (si->ib->flags & BF_SHUTR)
		return;
	si->ib->flags |= BF_SHUTR;
	si->ib->rex = TICK_ETERNITY;
	si->flags &= ~SI_FL_WAIT_ROOM;

	if (si->state != SI_ST_EST && si->state != SI_ST_CON)
		return;

	if (si->ob->flags & BF_SHUTW) {
		fd_delete(si->fd);
		si->state = SI_ST_DIS;
		si->exp = TICK_ETERNITY;
		return;
	}
	EV_FD_CLR(si->fd, DIR_RD);
	return;
}

/*
 * Updates a connected stream_sock file descriptor status and timeouts
 * according to the buffers' flags. It should only be called once after the
 * buffer flags have settled down, and before they are cleared. It doesn't
 * harm to call it as often as desired (it just slightly hurts performance).
 */
void stream_sock_data_finish(struct stream_interface *si)
{
	struct buffer *ib = si->ib;
	struct buffer *ob = si->ob;
	int fd = si->fd;

	DPRINTF(stderr,"[%u] %s: fd=%d owner=%p ib=%p, ob=%p, exp(r,w)=%u,%u ibf=%08x obf=%08x ibl=%d obl=%d si=%d\n",
		now_ms, __FUNCTION__,
		fd, fdtab[fd].owner,
		ib, ob,
		ib->rex, ob->wex,
		ib->flags, ob->flags,
		ib->l, ob->l, si->state);

	/* Check if we need to close the read side */
	if (!(ib->flags & BF_SHUTR)) {
		/* Read not closed, update FD status and timeout for reads */
		if (ib->flags & (BF_FULL|BF_HIJACK|BF_DONT_READ)) {
			/* stop reading */
			if ((ib->flags & (BF_FULL|BF_HIJACK|BF_DONT_READ)) == BF_FULL)
				si->flags |= SI_FL_WAIT_ROOM;
			EV_FD_COND_C(fd, DIR_RD);
			ib->rex = TICK_ETERNITY;
		}
		else {
			/* (re)start reading and update timeout. Note: we don't recompute the timeout
			 * everytime we get here, otherwise it would risk never to expire. We only
			 * update it if is was not yet set. The stream socket handler will already
			 * have updated it if there has been a completed I/O.
			 */
			si->flags &= ~SI_FL_WAIT_ROOM;
			EV_FD_COND_S(fd, DIR_RD);
			if (!(ib->flags & (BF_READ_NOEXP|BF_DONT_READ)) && !tick_isset(ib->rex))
				ib->rex = tick_add_ifset(now_ms, ib->rto);
		}
	}

	/* Check if we need to close the write side */
	if (!(ob->flags & BF_SHUTW)) {
		/* Write not closed, update FD status and timeout for writes */
		if (ob->flags & BF_OUT_EMPTY) {
			/* stop writing */
			if ((ob->flags & (BF_FULL|BF_HIJACK|BF_SHUTW_NOW)) == 0)
				si->flags |= SI_FL_WAIT_DATA;
			EV_FD_COND_C(fd, DIR_WR);
			ob->wex = TICK_ETERNITY;
		}
		else {
			/* (re)start writing and update timeout. Note: we don't recompute the timeout
			 * everytime we get here, otherwise it would risk never to expire. We only
			 * update it if is was not yet set. The stream socket handler will already
			 * have updated it if there has been a completed I/O.
			 */
			si->flags &= ~SI_FL_WAIT_DATA;
			EV_FD_COND_S(fd, DIR_WR);
			if (!tick_isset(ob->wex)) {
				ob->wex = tick_add_ifset(now_ms, ob->wto);
				if (tick_isset(ib->rex) && !(si->flags & SI_FL_INDEP_STR)) {
					/* Note: depending on the protocol, we don't know if we're waiting
					 * for incoming data or not. So in order to prevent the socket from
					 * expiring read timeouts during writes, we refresh the read timeout,
					 * except if it was already infinite or if we have explicitly setup
					 * independant streams.
					 */
					ib->rex = tick_add_ifset(now_ms, ib->rto);
				}
			}
		}
	}
}

/* This function is used for inter-stream-interface calls. It is called by the
 * consumer to inform the producer side that it may be interested in checking
 * for free space in the buffer. Note that it intentionally does not update
 * timeouts, so that we can still check them later at wake-up.
 */
void stream_sock_chk_rcv(struct stream_interface *si)
{
	struct buffer *ib = si->ib;

	DPRINTF(stderr,"[%u] %s: fd=%d owner=%p ib=%p, ob=%p, exp(r,w)=%u,%u ibf=%08x obf=%08x ibl=%d obl=%d si=%d\n",
		now_ms, __FUNCTION__,
		si->fd, fdtab[si->fd].owner,
		ib, si->ob,
		ib->rex, si->ob->wex,
		ib->flags, si->ob->flags,
		ib->l, si->ob->l, si->state);

	if (unlikely(si->state != SI_ST_EST || (ib->flags & BF_SHUTR)))
		return;

	if (ib->flags & (BF_FULL|BF_HIJACK|BF_DONT_READ)) {
		/* stop reading */
		if ((ib->flags & (BF_FULL|BF_HIJACK|BF_DONT_READ)) == BF_FULL)
			si->flags |= SI_FL_WAIT_ROOM;
		EV_FD_COND_C(si->fd, DIR_RD);
	}
	else {
		/* (re)start reading */
		si->flags &= ~SI_FL_WAIT_ROOM;
		EV_FD_COND_S(si->fd, DIR_RD);
	}
}


/* This function is used for inter-stream-interface calls. It is called by the
 * producer to inform the consumer side that it may be interested in checking
 * for data in the buffer. Note that it intentionally does not update timeouts,
 * so that we can still check them later at wake-up.
 */
void stream_sock_chk_snd(struct stream_interface *si)
{
	struct buffer *ob = si->ob;
	int retval;

	DPRINTF(stderr,"[%u] %s: fd=%d owner=%p ib=%p, ob=%p, exp(r,w)=%u,%u ibf=%08x obf=%08x ibl=%d obl=%d si=%d\n",
		now_ms, __FUNCTION__,
		si->fd, fdtab[si->fd].owner,
		si->ib, ob,
		si->ib->rex, ob->wex,
		si->ib->flags, ob->flags,
		si->ib->l, ob->l, si->state);

	if (unlikely(si->state != SI_ST_EST || (ob->flags & BF_SHUTW)))
		return;

	if (!(si->flags & SI_FL_WAIT_DATA) ||        /* not waiting for data */
	    (fdtab[si->fd].ev & FD_POLL_OUT) ||      /* we'll be called anyway */
	    (ob->flags & BF_OUT_EMPTY))              /* called with nothing to send ! */
		return;

	retval = stream_sock_write_loop(si, ob);
	/* here, we have :
	 *   retval < 0 if an error was encountered during write.
	 *   retval = 0 if we can't write anymore without polling
	 *   retval = 1 if we're invited to come back when desired
	 */
	if (retval < 0) {
		/* Write error on the file descriptor. We mark the FD as STERROR so
		 * that we don't use it anymore and we notify the task.
		 */
		fdtab[si->fd].state = FD_STERROR;
		fdtab[si->fd].ev &= ~FD_POLL_STICKY;
		EV_FD_REM(si->fd);
		si->flags |= SI_FL_ERR;
		goto out_wakeup;
	}

	/* OK, so now we know that retval >= 0 means that some data might have
	 * been sent, and that we may have to poll first. We have to do that
	 * too if the buffer is not empty.
	 */
	if (ob->flags & BF_OUT_EMPTY) {
		/* the connection is established but we can't write. Either the
		 * buffer is empty, or we just refrain from sending because the
		 * send_max limit was reached. Maybe we just wrote the last
		 * chunk and need to close.
		 */
		if (((ob->flags & (BF_SHUTW|BF_HIJACK|BF_AUTO_CLOSE|BF_SHUTW_NOW)) ==
		     (BF_AUTO_CLOSE|BF_SHUTW_NOW)) &&
		    (si->state == SI_ST_EST)) {
			stream_sock_shutw(si);
			goto out_wakeup;
		}

		if ((ob->flags & (BF_SHUTW|BF_SHUTW_NOW|BF_FULL|BF_HIJACK)) == 0)
			si->flags |= SI_FL_WAIT_DATA;
		ob->wex = TICK_ETERNITY;
	}
	else {
		/* Otherwise there are remaining data to be sent in the buffer,
		 * which means we have to poll before doing so.
		 */
		EV_FD_COND_S(si->fd, DIR_WR);
		si->flags &= ~SI_FL_WAIT_DATA;
		if (!tick_isset(ob->wex))
			ob->wex = tick_add_ifset(now_ms, ob->wto);
	}

	if (likely(ob->flags & BF_WRITE_ACTIVITY)) {
		/* update timeout if we have written something */
		if ((ob->flags & (BF_OUT_EMPTY|BF_SHUTW|BF_WRITE_PARTIAL)) == BF_WRITE_PARTIAL)
			ob->wex = tick_add_ifset(now_ms, ob->wto);

		if (tick_isset(si->ib->rex) && !(si->flags & SI_FL_INDEP_STR)) {
			/* Note: to prevent the client from expiring read timeouts
			 * during writes, we refresh it. We only do this if the
			 * interface is not configured for "independant streams",
			 * because for some applications it's better not to do this,
			 * for instance when continuously exchanging small amounts
			 * of data which can full the socket buffers long before a
			 * write timeout is detected.
			 */
			si->ib->rex = tick_add_ifset(now_ms, si->ib->rto);
		}
	}

	/* in case of special condition (error, shutdown, end of write...), we
	 * have to notify the task.
	 */
	if (likely((ob->flags & (BF_WRITE_NULL|BF_WRITE_ERROR|BF_SHUTW)) ||
		   ((ob->flags & BF_OUT_EMPTY) && !ob->to_forward) ||
		   si->state != SI_ST_EST)) {
	out_wakeup:
		if (!(si->flags & SI_FL_DONT_WAKE) && si->owner)
			task_wakeup(si->owner, TASK_WOKEN_IO);
	}
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
