/*
 * Functions operating on SOCK_STREAM and buffers.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
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
#include <common/standard.h>
#include <common/time.h>

#include <types/buffers.h>
#include <types/global.h>
#include <types/polling.h>

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
	__label__ out_wakeup;
	struct buffer *b = fdtab[fd].cb[DIR_RD].b;
	int ret, max, retval;
	int read_poll = MAX_READ_POLL_LOOPS;

#ifdef DEBUG_FULL
	fprintf(stderr,"stream_sock_read : fd=%d, owner=%p\n", fd, fdtab[fd].owner);
#endif

	retval = 1;

	if (unlikely(fdtab[fd].state == FD_STERROR || (fdtab[fd].ev & FD_POLL_ERR))) {
		/* read/write error */
		b->flags |= BF_READ_ERROR;
		fdtab[fd].state = FD_STERROR;
		goto out_wakeup;
	}

	if (unlikely(fdtab[fd].ev & FD_POLL_HUP)) {
		/* connection closed */
		b->flags |= BF_READ_NULL;
		goto out_wakeup;
	}

	retval = 0;
	while (read_poll-- > 0)	{
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
	    
		if (max == 0) {  /* not anymore room to store data */
			EV_FD_CLR(fd, DIR_RD);
			break;
		}

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
			b->flags |= BF_PARTIAL_READ;
			retval = 1;
	
			if (b->r == b->data + BUFSIZE) {
				b->r = b->data; /* wrap around the buffer */
			}

			b->total += ret;

			/* generally if we read something smaller than the 1 or 2 MSS,
			 * it means that it's not worth trying to read again. It may
			 * also happen on headers, but the application then can stop
			 * reading before we start polling.
			 */
			if (ret < MIN_RET_FOR_READ_LOOP)
				break;

			if (!read_poll)
				break;

			/* we hope to read more data or to get a close on next round */
			continue;
		}
		else if (ret == 0) {
			b->flags |= BF_READ_NULL;
			retval = 1;     // connection closed
			break;
		}
		else if (errno == EAGAIN) {/* ignore EAGAIN */
			retval = 0;
			break;
		}
		else {
			retval = 1;
			b->flags |= BF_READ_ERROR;
			fdtab[fd].state = FD_STERROR;
			break;
		}
	} /* while (read_poll) */

	if (b->flags & BF_READ_STATUS) {
	out_wakeup:
		if (b->rto && EV_FD_ISSET(fd, DIR_RD))
			tv_delayfrom(&b->rex, &now, b->rto);
		else
			tv_eternity(&b->rex);
	
		task_wakeup(&rq, fdtab[fd].owner);
	}

	fdtab[fd].ev &= ~FD_POLL_RD;
	return retval;
}


/*
 * this function is called on a write event from a stream socket.
 * It returns 0 if we have a high confidence that we will not be
 * able to write more data without polling first. Returns non-zero
 * otherwise.
 */
int stream_sock_write(int fd) {
	__label__ out_eternity;
	struct buffer *b = fdtab[fd].cb[DIR_WR].b;
	int ret, max, retval;
	int write_poll = MAX_WRITE_POLL_LOOPS;

#ifdef DEBUG_FULL
	fprintf(stderr,"stream_sock_write : fd=%d, owner=%p\n", fd, fdtab[fd].owner);
#endif

	retval = 1;

	if (unlikely(fdtab[fd].state == FD_STERROR || (fdtab[fd].ev & FD_POLL_ERR))) {
		/* read/write error */
		b->flags |= BF_WRITE_ERROR;
		fdtab[fd].state = FD_STERROR;
		EV_FD_CLR(fd, DIR_WR);
		goto out_eternity;
	}

	retval = 0;
	while (write_poll-- > 0) {
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
			if (!(b->flags & BF_PARTIAL_WRITE)
			    && fdtab[fd].state == FD_STCONN) {
				int skerr;
				socklen_t lskerr = sizeof(skerr);
				ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
				if (ret == -1 || skerr) {
					b->flags |= BF_WRITE_ERROR;
					fdtab[fd].state = FD_STERROR;
					EV_FD_CLR(fd, DIR_WR);
					retval = 1;
					goto out_eternity;
				}
			}

			b->flags |= BF_WRITE_NULL;
			fdtab[fd].state = FD_STREADY;
			EV_FD_CLR(fd, DIR_WR);
			retval = 1;
			goto out_eternity;
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
			retval = 1;
	    
			if (b->w == b->data + BUFSIZE) {
				b->w = b->data; /* wrap around the buffer */
			}

			if (!write_poll)
				break;

			/* we hope to be able to write more data */
			continue;
		}
		else if (ret == 0) {
			/* nothing written, just pretend we were never called */
			retval = 0;
			break;
		}
		else if (errno == EAGAIN) {/* ignore EAGAIN */
			retval = 0;
			break;
		}
		else {
			b->flags |= BF_WRITE_ERROR;
			fdtab[fd].state = FD_STERROR;
			EV_FD_CLR(fd, DIR_WR);
			retval = 1;
			goto out_eternity;
		}
	} /* while (write_poll) */

	if (b->flags & BF_WRITE_STATUS) {
		if (b->wto) {
			tv_delayfrom(&b->wex, &now, b->wto);
			/* FIXME: to prevent the client from expiring read timeouts during writes,
			 * we refresh it. A solution would be to merge read+write timeouts into a
			 * unique one, although that needs some study particularly on full-duplex
			 * TCP connections. */
			b->rex = b->wex;
		}
		else {
		out_eternity:
			tv_eternity(&b->wex);
		}
	}

	task_wakeup(&rq, fdtab[fd].owner);
	fdtab[fd].ev &= ~FD_POLL_WR;
	return retval;
}



/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
