/*
 * SSL data transfer functions between buffers and SOCK_STREAM sockets
 *
 * Copyright (C) 2012 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#include <openssl/ssl.h>

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
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/protocols.h>
#include <proto/ssl_sock.h>
#include <proto/task.h>

#include <types/global.h>


static int sslconns = 0;

void ssl_sock_infocbk(const SSL *ssl, int where, int ret)
{
	struct connection *conn = (struct connection *)SSL_get_app_data(ssl);
	(void)ret; /* shut gcc stupid warning */

	if (where & SSL_CB_HANDSHAKE_START) {
		/* Disable renegotiation (CVE-2009-3555) */
		if (conn->flags & CO_FL_CONNECTED)
			conn->flags |= CO_FL_ERROR;
	}
}

/*
 * This function is called if SSL * context is not yet allocated. The function
 * is designed to be called before any other data-layer operation and sets the
 * handshake flag on the connection. It is safe to call it multiple times.
 * It returns 0 on success and -1 in error case.
 */
static int ssl_sock_init(struct connection *conn)
{
	/* already initialized */
	if (conn->data_ctx)
		return 0;

	if (global.maxsslconn && sslconns >= global.maxsslconn)
		return -1;

	/* If it is in client mode initiate SSL session
	   in connect state otherwise accept state */
	if (target_srv(&conn->target)) {
		/* Alloc a new SSL session ctx */
		conn->data_ctx = SSL_new(target_srv(&conn->target)->ssl_ctx.ctx);
		if (!conn->data_ctx)
			return -1;

		SSL_set_connect_state(conn->data_ctx);
		if (target_srv(&conn->target)->ssl_ctx.reused_sess)
			SSL_set_session(conn->data_ctx, target_srv(&conn->target)->ssl_ctx.reused_sess);

		/* set fd on SSL session context */
		SSL_set_fd(conn->data_ctx, conn->t.sock.fd);

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;

		sslconns++;
		return 0;
	}
	else if (target_client(&conn->target)) {
		/* Alloc a new SSL session ctx */
		conn->data_ctx = SSL_new(target_client(&conn->target)->ssl_conf->ctx);
		if (!conn->data_ctx)
			return -1;

		SSL_set_accept_state(conn->data_ctx);

		/* set fd on SSL session context */
		SSL_set_fd(conn->data_ctx, conn->t.sock.fd);

		/* set connection pointer */
		SSL_set_app_data(conn->data_ctx, conn);

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;

		sslconns++;
		return 0;
	}
	/* don't know how to handle such a target */
	return -1;
}


/* This is the callback which is used when an SSL handshake is pending. It
 * updates the FD status if it wants some polling before being called again.
 * It returns 0 if it fails in a fatal way or needs to poll to go further,
 * otherwise it returns non-zero and removes itself from the connection's
 * flags (the bit is provided in <flag> by the caller).
 */
int ssl_sock_handshake(struct connection *conn, unsigned int flag)
{
	int ret;

	if (!conn->data_ctx)
		goto out_error;

	ret = SSL_do_handshake(conn->data_ctx);
	if (ret != 1) {
		/* handshake did not complete, let's find why */
		ret = SSL_get_error(conn->data_ctx, ret);

		if (ret == SSL_ERROR_WANT_WRITE) {
			/* SSL handshake needs to write, L4 connection may not be ready */
			__conn_sock_stop_recv(conn);
			__conn_sock_poll_send(conn);
			return 0;
		}
		else if (ret == SSL_ERROR_WANT_READ) {
			/* SSL handshake needs to read, L4 connection is ready */
			if (conn->flags & CO_FL_WAIT_L4_CONN)
				conn->flags &= ~CO_FL_WAIT_L4_CONN;
			__conn_sock_stop_send(conn);
			__conn_sock_poll_recv(conn);
			return 0;
		}
		else {
			/* Fail on all other handshake errors */
			goto out_error;
		}
	}

	/* Handshake succeeded */
	if (target_srv(&conn->target)) {
		if (!SSL_session_reused(conn->data_ctx)) {
			/* check if session was reused, if not store current session on server for reuse */
			if (target_srv(&conn->target)->ssl_ctx.reused_sess)
				SSL_SESSION_free(target_srv(&conn->target)->ssl_ctx.reused_sess);

			target_srv(&conn->target)->ssl_ctx.reused_sess = SSL_get1_session(conn->data_ctx);
		}
	}

	/* The connection is now established at both layers, it's time to leave */
	conn->flags &= ~(flag | CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN);
	return 1;

 out_error:
	/* Fail on all other handshake errors */
	conn->flags |= CO_FL_ERROR;
	conn->flags &= ~flag;
	return 0;
}

/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. The caller must ensure that <count> is always smaller
 * than the buffer's size. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 */
static int ssl_sock_to_buf(struct connection *conn, struct buffer *buf, int count)
{
	int ret, done = 0;
	int try = count;

	if (!conn->data_ctx)
		goto out_error;

	if (conn->flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return 0;

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
		ret = SSL_read(conn->data_ctx, bi_end(buf), try);
		if (conn->flags & CO_FL_ERROR) {
			/* CO_FL_ERROR may be set by ssl_sock_infocbk */
			break;
		}
		if (ret > 0) {
			buf->i += ret;
			done += ret;
			if (ret < try)
				break;
			count -= ret;
			try = count;
		}
		else if (ret == 0) {
			goto read0;
		}
		else {
			ret =  SSL_get_error(conn->data_ctx, ret);
			if (ret == SSL_ERROR_WANT_WRITE) {
				/* handshake is running, and it needs to poll for a write event */
				conn->flags |= CO_FL_SSL_WAIT_HS;
				__conn_sock_poll_send(conn);
				break;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				/* we need to poll for retry a read later */
				__conn_data_poll_recv(conn);
				break;
			}
			/* otherwise it's a real error */
			goto out_error;
		}
	}
	return done;

 read0:
	conn_sock_read0(conn);
	return done;
 out_error:
	conn->flags |= CO_FL_ERROR;
	return done;
}


/* Send all pending bytes from buffer <buf> to connection <conn>'s socket.
 * <flags> may contain MSG_MORE to make the system hold on without sending
 * data too fast, but this flag is ignored at the moment.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this.
 */
static int ssl_sock_from_buf(struct connection *conn, struct buffer *buf, int flags)
{
	int ret, try, done;

	done = 0;

	if (!conn->data_ctx)
		goto out_error;

	if (conn->flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return 0;

	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (buf->o) {
		try = buf->o;
		/* outgoing data may wrap at the end */
		if (buf->data + try > buf->p)
			try = buf->data + try - buf->p;

		ret = SSL_write(conn->data_ctx, bo_ptr(buf), try);
		if (conn->flags & CO_FL_ERROR) {
			/* CO_FL_ERROR may be set by ssl_sock_infocbk */
			break;
		}
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
		else {
			ret = SSL_get_error(conn->data_ctx, ret);
			if (ret == SSL_ERROR_WANT_WRITE) {
				/* we need to poll to retry a write later */
				__conn_data_poll_send(conn);
				break;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				/* handshake is running, and
				   it needs to poll for a read event,
				   write polling must be disabled cause
				   we are sure we can't write anything more
				   before handshake re-performed */
				conn->flags |= CO_FL_SSL_WAIT_HS;
				__conn_sock_poll_recv(conn);
				break;
			}
			goto out_error;
		}
	}
	return done;

 out_error:
	conn->flags |= CO_FL_ERROR;
	return done;
}


static void ssl_sock_close(struct connection *conn) {

	if (conn->data_ctx) {
		SSL_free(conn->data_ctx);
		conn->data_ctx = NULL;
		sslconns--;
	}
}

/* This function tries to perform a clean shutdown on an SSL connection, and in
 * any case, flags the connection as reusable if no handshake was in progress.
 */
static void ssl_sock_shutw(struct connection *conn, int clean)
{
	if (conn->flags & CO_FL_HANDSHAKE)
		return;
	/* no handshake was in progress, try a clean ssl shutdown */
	if (clean)
		SSL_shutdown(conn->data_ctx);

	/* force flag on ssl to keep session in cache regardless shutdown result */
	SSL_set_shutdown(conn->data_ctx, SSL_SENT_SHUTDOWN);
}


/* data-layer operations for SSL sockets */
struct data_ops ssl_sock = {
	.snd_buf  = ssl_sock_from_buf,
	.rcv_buf  = ssl_sock_to_buf,
	.rcv_pipe = NULL,
	.snd_pipe = NULL,
	.shutr    = NULL,
	.shutw    = ssl_sock_shutw,
	.close    = ssl_sock_close,
	.init     = ssl_sock_init,
};

__attribute__((constructor))
static void __ssl_sock_init(void) {
	STACK_OF(SSL_COMP)* cm;

	SSL_library_init();
	cm = SSL_COMP_get_compression_methods();
	sk_SSL_COMP_zero(cm);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
