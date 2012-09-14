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
 * Acknowledgement:
 *   We'd like to specially thank the Stud project authors for a very clean
 *   and well documented code which helped us understand how the OpenSSL API
 *   ought to be used in non-blocking mode. This is one difficult part which
 *   is not easy to get from the OpenSSL doc, and reading the Stud code made
 *   it much more obvious than the examples in the OpenSSL package. Keep up
 *   the good works, guys !
 *
 *   Stud is an extremely efficient and scalable SSL/TLS proxy which combines
 *   particularly well with haproxy. For more info about this project, visit :
 *       https://github.com/bumptech/stud
 *
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <ebsttree.h>

#include <types/global.h>
#include <types/ssl_sock.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/frontend.h>
#include <proto/log.h>
#include <proto/protocols.h>
#include <proto/shctx.h>
#include <proto/ssl_sock.h>
#include <proto/task.h>

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

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
/* Sets the SSL ctx of <ssl> to match the advertised server name. Returns a
 * warning when no match is found, which implies the default (first) cert
 * will keep being used.
 */
static int ssl_sock_switchctx_cbk(SSL *ssl, int *al, struct ssl_conf *s)
{
	const char *servername;
	const char *wildp = NULL;
	struct ebmb_node *node;
	int i;
	(void)al; /* shut gcc stupid warning */

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername)
		return SSL_TLSEXT_ERR_NOACK;

	for (i = 0; i < trashlen; i++) {
		if (!servername[i])
			break;
		trash[i] = tolower(servername[i]);
		if (!wildp && (trash[i] == '.'))
			wildp = &trash[i];
	}
	trash[i] = 0;

	/* lookup in full qualified names */
	node = ebst_lookup(&s->sni_ctx, trash);
	if (!node) {
		if (!wildp)
			return SSL_TLSEXT_ERR_ALERT_WARNING;

		/* lookup in full wildcards names */
		node = ebst_lookup(&s->sni_w_ctx, wildp);
		if (!node)
			return SSL_TLSEXT_ERR_ALERT_WARNING;
	}

	/* switch ctx */
	SSL_set_SSL_CTX(ssl,  container_of(node, struct sni_ctx, name)->ctx);
	return SSL_TLSEXT_ERR_OK;
}
#endif /* SSL_CTRL_SET_TLSEXT_HOSTNAME */

/* Loads a certificate key and CA chain from a file. Returns 0 on error, -1 if
 * an early error happens and the caller must call SSL_CTX_free() by itelf.
 */
int ssl_sock_load_cert_chain_file(SSL_CTX *ctx, const char *file, struct ssl_conf *s)
{
	BIO *in;
	X509 *x = NULL, *ca;
	int i, len, err;
	int ret = -1;
	int order = 0;
	X509_NAME *xname;
	char *str;
	struct sni_ctx *sc;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	STACK_OF(GENERAL_NAME) *names;
#endif

	in = BIO_new(BIO_s_file());
	if (in == NULL)
		goto end;

	if (BIO_read_filename(in, file) <= 0)
		goto end;

	x = PEM_read_bio_X509_AUX(in, NULL, ctx->default_passwd_callback, ctx->default_passwd_callback_userdata);
	if (x == NULL)
		goto end;

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	names = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
	if (names) {
		for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
			GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
			if (name->type == GEN_DNS) {
				if (ASN1_STRING_to_UTF8((unsigned char **)&str, name->d.dNSName) >= 0) {
					if ((len = strlen(str))) {
						int j;

						if (*str != '*') {
							sc = malloc(sizeof(struct sni_ctx) + len + 1);
							for (j = 0; j < len; j++)
								sc->name.key[j] = tolower(str[j]);
							sc->name.key[len] = 0;
							sc->order = order++;
							sc->ctx = ctx;
							ebst_insert(&s->sni_ctx, &sc->name);
						}
						else {
							sc = malloc(sizeof(struct sni_ctx) + len);
							for (j = 1; j < len; j++)
								sc->name.key[j-1] = tolower(str[j]);
							sc->name.key[len-1] = 0;
							sc->order = order++;
							sc->ctx = ctx;
							ebst_insert(&s->sni_w_ctx, &sc->name);
						}
					}
					OPENSSL_free(str);
				}
			}
		}
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
	}
#endif /* SSL_CTRL_SET_TLSEXT_HOSTNAME */

	xname = X509_get_subject_name(x);
	i = -1;
	while ((i = X509_NAME_get_index_by_NID(xname, NID_commonName, i)) != -1) {
		X509_NAME_ENTRY *entry = X509_NAME_get_entry(xname, i);
		if (ASN1_STRING_to_UTF8((unsigned char **)&str, entry->value) >= 0) {
			if ((len = strlen(str))) {
				int j;

				if (*str != '*') {
					sc = malloc(sizeof(struct sni_ctx) + len + 1);
					for (j = 0; j < len; j++)
						sc->name.key[j] = tolower(str[j]);
					sc->name.key[len] = 0;
					sc->order = order++;
					sc->ctx = ctx;
					ebst_insert(&s->sni_ctx, &sc->name);
				}
				else {
					sc = malloc(sizeof(struct sni_ctx) + len);
					for (j = 1; j < len; j++)
						sc->name.key[j-1] = tolower(str[j]);
					sc->name.key[len-1] = 0;
					sc->order = order++;
					sc->ctx = ctx;
					ebst_insert(&s->sni_w_ctx, &sc->name);
				}
			}
			OPENSSL_free(str);
		}
	}

	ret = 0; /* the caller must not free the SSL_CTX argument anymore */
	if (!SSL_CTX_use_certificate(ctx, x))
		goto end;

	if (ctx->extra_certs != NULL) {
		sk_X509_pop_free(ctx->extra_certs, X509_free);
		ctx->extra_certs = NULL;
	}

	while ((ca = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback, ctx->default_passwd_callback_userdata))) {
		if (!SSL_CTX_add_extra_chain_cert(ctx, ca)) {
			X509_free(ca);
			goto end;
		}
	}

	err = ERR_get_error();
	if (!err || (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
		/* we successfully reached the last cert in the file */
		ret = 1;
	}
	ERR_clear_error();

end:
	if (x)
		X509_free(x);

	if (in)
		BIO_free(in);

	return ret;
}

int ssl_sock_load_cert_file(const char *path, struct ssl_conf *ssl_conf, struct proxy *curproxy)
{
	int ret;
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		Alert("Proxy '%s': unable to allocate SSL context for bind '%s' at [%s:%d] using cert '%s'.\n",
		      curproxy->id, ssl_conf->arg, ssl_conf->file, ssl_conf->line, path);
		return 1;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM) <= 0) {
		Alert("Proxy '%s': unable to load SSL private key from file '%s' in bind '%s' at [%s:%d].\n",
			      curproxy->id, path, ssl_conf->arg, ssl_conf->file, ssl_conf->line);
		SSL_CTX_free(ctx);
		return 1;
	}

	ret = ssl_sock_load_cert_chain_file(ctx, path, ssl_conf);
	if (ret <= 0) {
		Alert("Proxy '%s': unable to load SSL certificate from file '%s' in bind '%s' at [%s:%d].\n",
		      curproxy->id, path, ssl_conf->arg, ssl_conf->file, ssl_conf->line);
		if (ret < 0) /* serious error, must do that ourselves */
			SSL_CTX_free(ctx);
		return 1;
	}
	/* we must not free the SSL_CTX anymore below, since it's already in
	 * the tree, so it will be discovered and cleaned in time.
	 */
#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
	if (ssl_conf->default_ctx) {
		Alert("Proxy '%s': file '%s' : this version of openssl cannot load multiple SSL certificates in bind '%s' at [%s:%d].\n",
		      curproxy->id, path, ssl_conf->arg, ssl_conf->file, ssl_conf->line);
		return 1;
	}
#endif
	if (!ssl_conf->default_ctx)
		ssl_conf->default_ctx = ctx;

	return 0;
}

int ssl_sock_load_cert(char *path, struct ssl_conf *ssl_conf, struct proxy *curproxy)
{
	struct dirent *de;
	DIR *dir;
	struct stat buf;
	int pathlen = 0;
	char *end, *fp;
	int cfgerr = 0;

	if (!(dir = opendir(path)))
		return ssl_sock_load_cert_file(path, ssl_conf, curproxy);

	/* strip trailing slashes, including first one */
	for (end = path + strlen(path) - 1; end >= path && *end == '/'; end--)
		*end = 0;

	if (end >= path)
		pathlen = end + 1 - path;
	fp = malloc(pathlen + 1 + NAME_MAX + 1);

	while ((de = readdir(dir))) {
		snprintf(fp, pathlen + 1 + NAME_MAX + 1, "%s/%s", path, de->d_name);
		if (stat(fp, &buf) != 0) {
			Alert("Proxy '%s': unable to stat SSL certificate from file '%s' in bind '%s' at [%s:%d] : %s.\n",
			      curproxy->id, fp, ssl_conf->arg, ssl_conf->file, ssl_conf->line, strerror(errno));
			cfgerr++;
			continue;
		}
		if (!S_ISREG(buf.st_mode))
			continue;
		cfgerr += ssl_sock_load_cert_file(fp, ssl_conf, curproxy);
	}
	free(fp);
	closedir(dir);
	return cfgerr;
}

#ifndef SSL_OP_CIPHER_SERVER_PREFERENCE                 /* needs OpenSSL >= 0.9.7 */
#define SSL_OP_CIPHER_SERVER_PREFERENCE 0
#endif

#ifndef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   /* needs OpenSSL >= 0.9.7 */
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION 0
#endif
#ifndef SSL_OP_NO_COMPRESSION                           /* needs OpenSSL >= 0.9.9 */
#define SSL_OP_NO_COMPRESSION 0
#endif
#ifndef SSL_MODE_RELEASE_BUFFERS                        /* needs OpenSSL >= 1.0.0 */
#define SSL_MODE_RELEASE_BUFFERS 0
#endif
int ssl_sock_prepare_ctx(struct ssl_conf *ssl_conf, SSL_CTX *ctx, struct proxy *curproxy)
{
	int cfgerr = 0;
	int ssloptions =
		SSL_OP_ALL | /* all known workarounds for bugs */
		SSL_OP_NO_SSLv2 |
		SSL_OP_NO_COMPRESSION |
		SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
	int sslmode =
		SSL_MODE_ENABLE_PARTIAL_WRITE |
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
		SSL_MODE_RELEASE_BUFFERS;

	if (ssl_conf->nosslv3)
		ssloptions |= SSL_OP_NO_SSLv3;
	if (ssl_conf->notlsv1)
		ssloptions |= SSL_OP_NO_TLSv1;
	if (ssl_conf->prefer_server_ciphers)
		ssloptions |= SSL_OP_CIPHER_SERVER_PREFERENCE;

	SSL_CTX_set_options(ctx, ssloptions);
	SSL_CTX_set_mode(ctx, sslmode);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	shared_context_set_cache(ctx);
	if (ssl_conf->ciphers &&
	    !SSL_CTX_set_cipher_list(ctx, ssl_conf->ciphers)) {
		Alert("Proxy '%s': unable to set SSL cipher list to '%s' for bind '%s' at [%s:%d].\n",
		curproxy->id, ssl_conf->ciphers, ssl_conf->arg, ssl_conf->file, ssl_conf->line);
		cfgerr++;
	}

	SSL_CTX_set_info_callback(ctx, ssl_sock_infocbk);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
	SSL_CTX_set_tlsext_servername_arg(ctx, ssl_conf);
#endif
	return cfgerr;
}

/* Walks down the two trees in ssl_conf and prepares all certs. The pointer may
 * be NULL, in which case nothing is done. Returns the number of errors
 * encountered.
 */
int ssl_sock_prepare_all_ctx(struct ssl_conf *ssl_conf, struct proxy *px)
{
	struct ebmb_node *node;
	struct sni_ctx *sni;
	int err = 0;

	if (!ssl_conf)
		return 0;

	node = ebmb_first(&ssl_conf->sni_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		if (!sni->order) /* only initialize the CTX on its first occurrence */
			err += ssl_sock_prepare_ctx(ssl_conf, sni->ctx, px);
		node = ebmb_next(node);
	}

	node = ebmb_first(&ssl_conf->sni_w_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		if (!sni->order) /* only initialize the CTX on its first occurrence */
			err += ssl_sock_prepare_ctx(ssl_conf, sni->ctx, px);
		node = ebmb_next(node);
	}
	return err;
}

/* Walks down the two trees in ssl_conf and frees all the certs. The pointer may
 * be NULL, in which case nothing is done. The default_ctx is nullified too.
 */
void ssl_sock_free_all_ctx(struct ssl_conf *ssl_conf)
{
	struct ebmb_node *node, *back;
	struct sni_ctx *sni;

	if (!ssl_conf)
		return;

	node = ebmb_first(&ssl_conf->sni_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		back = ebmb_next(node);
		ebmb_delete(node);
		if (!sni->order) /* only free the CTX on its first occurrence */
			SSL_CTX_free(sni->ctx);
		free(sni);
		node = back;
	}

	node = ebmb_first(&ssl_conf->sni_w_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		back = ebmb_next(node);
		ebmb_delete(node);
		if (!sni->order) /* only free the CTX on its first occurrence */
			SSL_CTX_free(sni->ctx);
		free(sni);
		node = back;
	}

	ssl_conf->default_ctx = NULL;
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
		conn->data_ctx = SSL_new(target_client(&conn->target)->ssl_conf->default_ctx);
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

/***** Below are some sample fetching functions for ACL/patterns *****/

/* boolean, returns true if data layer is SSL */
static int
smp_fetch_is_ssl(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                 const struct arg *args, struct sample *smp)
{
	smp->type = SMP_T_BOOL;
	smp->data.uint = (l4->si[0].conn.data == &ssl_sock);
	return 1;
}

/* boolean, returns true if data layer is SSL */
static int
smp_fetch_has_sni(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                  const struct arg *args, struct sample *smp)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	smp->type = SMP_T_BOOL;
	smp->data.uint = (l4->si[0].conn.data == &ssl_sock) &&
		l4->si[0].conn.data_ctx &&
		SSL_get_servername(l4->si[0].conn.data_ctx, TLSEXT_NAMETYPE_host_name) != NULL;
	return 1;
#else
	return 0;
#endif
}

static int
smp_fetch_ssl_sni(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                  const struct arg *args, struct sample *smp)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	smp->flags = 0;
	smp->type = SMP_T_CSTR;

	if (!l4 || !l4->si[0].conn.data_ctx || l4->si[0].conn.data != &ssl_sock)
		return 0;

	smp->data.str.str = (char *)SSL_get_servername(l4->si[0].conn.data_ctx, TLSEXT_NAMETYPE_host_name);
	if (!smp->data.str.str)
		return 0;

	smp->data.str.len = strlen(smp->data.str.str);
	return 1;
#else
	return 0;
#endif
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {{ },{
	{ "is_ssl",       smp_fetch_is_ssl,   0,    NULL,    SMP_T_BOOL, SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_has_sni",  smp_fetch_has_sni,  0,    NULL,    SMP_T_BOOL, SMP_CAP_REQ|SMP_CAP_RES },
	{ "ssl_sni",      smp_fetch_ssl_sni,  0,    NULL,    SMP_T_CSTR, SMP_CAP_REQ|SMP_CAP_RES },
	{ NULL, NULL, 0, 0, 0 },
}};

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {{ },{
	{ "is_ssl",      acl_parse_int,   smp_fetch_is_ssl,   acl_match_nothing,  ACL_USE_L6REQ_PERMANENT, 0 },
	{ "ssl_has_sni", acl_parse_int,   smp_fetch_has_sni,  acl_match_nothing,  ACL_USE_L6REQ_PERMANENT, 0 },
	{ "ssl_sni",     acl_parse_str,   smp_fetch_ssl_sni,  acl_match_str,      ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ "ssl_sni_end", acl_parse_str,   smp_fetch_ssl_sni,  acl_match_end,      ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ "ssl_sni_reg", acl_parse_str,   smp_fetch_ssl_sni,  acl_match_reg,      ACL_USE_L6REQ_PERMANENT|ACL_MAY_LOOKUP, 0 },
	{ NULL, NULL, NULL, NULL },
}};


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
	sample_register_fetches(&sample_fetch_keywords);
	acl_register_keywords(&acl_kws);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
