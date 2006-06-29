/*
 * Functions operating on SOCK_STREAM and buffers.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
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
#include <common/time.h>

#include <types/backend.h>
#include <types/buffers.h>
#include <types/global.h>
#include <types/httperr.h>
#include <types/polling.h>
#include <types/proxy.h>
#include <types/server.h>
#include <types/session.h>

#include <proto/client.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/stream_sock.h>
#include <proto/task.h>


/*
 * this function is called on a read event from a client socket.
 * It returns 0.
 */
int event_cli_read(int fd) {
	struct task *t = fdtab[fd].owner;
	struct session *s = t->context;
	struct buffer *b = s->req;
	int ret, max;

#ifdef DEBUG_FULL
	fprintf(stderr,"event_cli_read : fd=%d, s=%p\n", fd, s);
#endif

	if (fdtab[fd].state != FD_STERROR) {
#ifdef FILL_BUFFERS
		while (1)
#else
		do
#endif
		{
			if (b->l == 0) { /* let's realign the buffer to optimize I/O */
				b->r = b->w = b->h = b->lr  = b->data;
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
				FD_CLR(fd, StaticReadEvent);
				break;
			}

#ifndef MSG_NOSIGNAL
			{
				int skerr;
				socklen_t lskerr = sizeof(skerr);
	
				getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
				if (skerr)
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
				s->res_cr = RES_DATA;
	
				if (b->r == b->data + BUFSIZE) {
					b->r = b->data; /* wrap around the buffer */
				}

				b->total += ret;
				/* we hope to read more data or to get a close on next round */
				continue;
			}
			else if (ret == 0) {
				s->res_cr = RES_NULL;
				break;
			}
			else if (errno == EAGAIN) {/* ignore EAGAIN */
				break;
			}
			else {
				s->res_cr = RES_ERROR;
				fdtab[fd].state = FD_STERROR;
				break;
			}
		} /* while(1) */
#ifndef FILL_BUFFERS
		while (0);
#endif
	}
	else {
		s->res_cr = RES_ERROR;
		fdtab[fd].state = FD_STERROR;
	}

	if (s->res_cr != RES_SILENT) {
		if (s->proxy->clitimeout && FD_ISSET(fd, StaticReadEvent))
			tv_delayfrom(&s->crexpire, &now, s->proxy->clitimeout);
		else
			tv_eternity(&s->crexpire);
	
		task_wakeup(&rq, t);
	}

	return 0;
}


/*
 * this function is called on a write event from a client socket.
 * It returns 0.
 */
int event_cli_write(int fd) {
	struct task *t = fdtab[fd].owner;
	struct session *s = t->context;
	struct buffer *b = s->rep;
	int ret, max;

#ifdef DEBUG_FULL
	fprintf(stderr,"event_cli_write : fd=%d, s=%p\n", fd, s);
#endif

	if (b->l == 0) { /* let's realign the buffer to optimize I/O */
		b->r = b->w = b->h = b->lr  = b->data;
		//	max = BUFSIZE;		BUG !!!!
		max = 0;
	}
	else if (b->r > b->w) {
		max = b->r - b->w;
	}
	else
		max = b->data + BUFSIZE - b->w;
    
	if (fdtab[fd].state != FD_STERROR) {
		if (max == 0) {
			s->res_cw = RES_NULL;
			task_wakeup(&rq, t);
			tv_eternity(&s->cwexpire);
			FD_CLR(fd, StaticWriteEvent);
			return 0;
		}

#ifndef MSG_NOSIGNAL
		{
			int skerr;
			socklen_t lskerr = sizeof(skerr);

			getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
			if (skerr)
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
	    
			s->res_cw = RES_DATA;
	    
			if (b->w == b->data + BUFSIZE) {
				b->w = b->data; /* wrap around the buffer */
			}
		}
		else if (ret == 0) {
			/* nothing written, just make as if we were never called */
			//	    s->res_cw = RES_NULL;
			return 0;
		}
		else if (errno == EAGAIN) /* ignore EAGAIN */
			return 0;
		else {
			s->res_cw = RES_ERROR;
			fdtab[fd].state = FD_STERROR;
		}
	}
	else {
		s->res_cw = RES_ERROR;
		fdtab[fd].state = FD_STERROR;
	}

	if (s->proxy->clitimeout) {
		tv_delayfrom(&s->cwexpire, &now, s->proxy->clitimeout);
		/* FIXME: to prevent the client from expiring read timeouts during writes,
		 * we refresh it. A solution would be to merge read+write timeouts into a
		 * unique one, although that needs some study particularly on full-duplex
		 * TCP connections. */
		s->crexpire = s->cwexpire;
	}
	else
		tv_eternity(&s->cwexpire);

	task_wakeup(&rq, t);
	return 0;
}


/*
 * this function is called on a read event from a server socket.
 * It returns 0.
 */
int event_srv_read(int fd) {
    struct task *t = fdtab[fd].owner;
    struct session *s = t->context;
    struct buffer *b = s->rep;
    int ret, max;

#ifdef DEBUG_FULL
    fprintf(stderr,"event_srv_read : fd=%d, s=%p\n", fd, s);
#endif

    if (fdtab[fd].state != FD_STERROR) {
#ifdef FILL_BUFFERS
	while (1)
#else
	do
#endif
	{
	    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
		b->r = b->w = b->h = b->lr  = b->data;
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
		FD_CLR(fd, StaticReadEvent);
		break;
	    }

#ifndef MSG_NOSIGNAL
	    {
		int skerr;
		socklen_t lskerr = sizeof(skerr);

		getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
		if (skerr)
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
		s->res_sr = RES_DATA;
	    
		if (b->r == b->data + BUFSIZE) {
		    b->r = b->data; /* wrap around the buffer */
		}

		b->total += ret;
		/* we hope to read more data or to get a close on next round */
		continue;
	    }
	    else if (ret == 0) {
		s->res_sr = RES_NULL;
		break;
	    }
	    else if (errno == EAGAIN) {/* ignore EAGAIN */
		break;
	    }
	    else {
		s->res_sr = RES_ERROR;
		fdtab[fd].state = FD_STERROR;
		break;
	    }
	} /* while(1) */
#ifndef FILL_BUFFERS
	while (0);
#endif
    }
    else {
	s->res_sr = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }

    if (s->res_sr != RES_SILENT) {
	if (s->proxy->srvtimeout && FD_ISSET(fd, StaticReadEvent))
	    tv_delayfrom(&s->srexpire, &now, s->proxy->srvtimeout);
	else
	    tv_eternity(&s->srexpire);
	
	task_wakeup(&rq, t);
    }

    return 0;
}


/*
 * this function is called on a write event from a server socket.
 * It returns 0.
 */
int event_srv_write(int fd) {
    struct task *t = fdtab[fd].owner;
    struct session *s = t->context;
    struct buffer *b = s->req;
    int ret, max;

#ifdef DEBUG_FULL
    fprintf(stderr,"event_srv_write : fd=%d, s=%p\n", fd, s);
#endif

    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
	b->r = b->w = b->h = b->lr = b->data;
	//	max = BUFSIZE;		BUG !!!!
	max = 0;
    }
    else if (b->r > b->w) {
	max = b->r - b->w;
    }
    else
	max = b->data + BUFSIZE - b->w;
    
    if (fdtab[fd].state != FD_STERROR) {
	if (max == 0) {
	    /* may be we have received a connection acknowledgement in TCP mode without data */
	    if (s->srv_state == SV_STCONN) {
		int skerr;
		socklen_t lskerr = sizeof(skerr);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
		if (skerr) {
		    s->res_sw = RES_ERROR;
		    fdtab[fd].state = FD_STERROR;
		    task_wakeup(&rq, t);
		    tv_eternity(&s->swexpire);
		    FD_CLR(fd, StaticWriteEvent);
		    return 0;
		}
	    }

	    s->res_sw = RES_NULL;
	    task_wakeup(&rq, t);
	    fdtab[fd].state = FD_STREADY;
	    tv_eternity(&s->swexpire);
	    FD_CLR(fd, StaticWriteEvent);
	    return 0;
	}

#ifndef MSG_NOSIGNAL
	{
	    int skerr;
	    socklen_t lskerr = sizeof(skerr);
	    getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
	    if (skerr)
		ret = -1;
	    else
		ret = send(fd, b->w, max, MSG_DONTWAIT);
	}
#else
	ret = send(fd, b->w, max, MSG_DONTWAIT | MSG_NOSIGNAL);
#endif
	fdtab[fd].state = FD_STREADY;
	if (ret > 0) {
	    b->l -= ret;
	    b->w += ret;
	    
	    s->res_sw = RES_DATA;
	    
	    if (b->w == b->data + BUFSIZE) {
		b->w = b->data; /* wrap around the buffer */
	    }
	}
	else if (ret == 0) {
	    /* nothing written, just make as if we were never called */
	    // s->res_sw = RES_NULL;
	    return 0;
	}
	else if (errno == EAGAIN) /* ignore EAGAIN */
	    return 0;
	else {
	    s->res_sw = RES_ERROR;
	    fdtab[fd].state = FD_STERROR;
	}
    }
    else {
	s->res_sw = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }

    /* We don't want to re-arm read/write timeouts if we're trying to connect,
     * otherwise it could loop indefinitely !
     */
    if (s->srv_state != SV_STCONN) {
	if (s->proxy->srvtimeout) {
	    tv_delayfrom(&s->swexpire, &now, s->proxy->srvtimeout);
	    /* FIXME: to prevent the server from expiring read timeouts during writes,
	     * we refresh it. A solution would be to merge read+write+connect timeouts
	     * into a unique one since we don't mind expiring on read or write, and none
	     * of them is enabled while waiting for connect(), although that needs some
	     * study particularly on full-duplex TCP connections. */
	    s->srexpire = s->swexpire;
	}
	else
	    tv_eternity(&s->swexpire);
    }

    task_wakeup(&rq, t);
    return 0;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
