#include <haproxy/errors.h>
#include <haproxy/ncbuf.h>
#include <haproxy/proxy.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_rx.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_ssl.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_tp.h>
#include <haproxy/quic_trace.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/trace.h>

DECLARE_POOL(pool_head_quic_ssl_sock_ctx, "quic_ssl_sock_ctx", sizeof(struct ssl_sock_ctx));

/* Set the encoded version of the transport parameter into the TLS
 * stack depending on <ver> QUIC version and <server> boolean which must
 * be set to 1 for a QUIC server, 0 for a client.
 * Return 1 if succeeded, 0 if not.
 */
static int qc_ssl_set_quic_transport_params(struct quic_conn *qc,
                                            const struct quic_version *ver, int server)
{
	int ret = 0;
#ifdef USE_QUIC_OPENSSL_COMPAT
	unsigned char *in = qc->enc_params;
	size_t insz = sizeof qc->enc_params;
	size_t *enclen = &qc->enc_params_len;
#else
	unsigned char tps[QUIC_TP_MAX_ENCLEN];
	size_t tpslen;
	unsigned char *in = tps;
	size_t insz = sizeof tps;
	size_t *enclen = &tpslen;
#endif

	TRACE_ENTER(QUIC_EV_CONN_RWSEC, qc);
	*enclen = quic_transport_params_encode(in, in + insz, &qc->rx.params, ver, server);
	if (!*enclen) {
		TRACE_ERROR("quic_transport_params_encode() failed", QUIC_EV_CONN_RWSEC);
		goto leave;
	}

	if (!SSL_set_quic_transport_params(qc->xprt_ctx->ssl, in, *enclen)) {
		TRACE_ERROR("SSL_set_quic_transport_params() failed", QUIC_EV_CONN_RWSEC);
		goto leave;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RWSEC, qc);
	return ret;
}

/* This function copies the CRYPTO data provided by the TLS stack found at <data>
 * with <len> as size in CRYPTO buffers dedicated to store the information about
 * outgoing CRYPTO frames so that to be able to replay the CRYPTO data streams.
 * It fails (returns 0) only if it could not managed to allocate enough CRYPTO
 * buffers to store all the data.
 * Note that CRYPTO data may exist at any encryption level except at 0-RTT.
 */
static int qc_ssl_crypto_data_cpy(struct quic_conn *qc, struct quic_enc_level *qel,
                                  const unsigned char *data, size_t len)
{
	struct quic_crypto_buf **qcb;
	/* The remaining byte to store in CRYPTO buffers. */
	size_t cf_offset, cf_len, *nb_buf;
	unsigned char *pos;
	int ret = 0;

	nb_buf = &qel->tx.crypto.nb_buf;
	qcb = &qel->tx.crypto.bufs[*nb_buf - 1];
	cf_offset = (*nb_buf - 1) * QUIC_CRYPTO_BUF_SZ + (*qcb)->sz;
	cf_len = len;

	TRACE_ENTER(QUIC_EV_CONN_ADDDATA, qc);

	while (len) {
		size_t to_copy, room;

		pos = (*qcb)->data + (*qcb)->sz;
		room = QUIC_CRYPTO_BUF_SZ  - (*qcb)->sz;
		to_copy = len > room ? room : len;
		if (to_copy) {
			memcpy(pos, data, to_copy);
			/* Increment the total size of this CRYPTO buffers by <to_copy>. */
			qel->tx.crypto.sz += to_copy;
			(*qcb)->sz += to_copy;
			len -= to_copy;
			data += to_copy;
		}
		else {
			struct quic_crypto_buf **tmp;

			// FIXME: realloc!
			tmp = realloc(qel->tx.crypto.bufs,
			              (*nb_buf + 1) * sizeof *qel->tx.crypto.bufs);
			if (tmp) {
				qel->tx.crypto.bufs = tmp;
				qcb = &qel->tx.crypto.bufs[*nb_buf];
				*qcb = pool_alloc(pool_head_quic_crypto_buf);
				if (!*qcb) {
					TRACE_ERROR("Could not allocate crypto buf", QUIC_EV_CONN_ADDDATA, qc);
					goto leave;
				}

				(*qcb)->sz = 0;
				++*nb_buf;
			}
			else {
				break;
			}
		}
	}

	/* Allocate a TX CRYPTO frame only if all the CRYPTO data
	 * have been buffered.
	 */
	if (!len) {
		struct quic_frame *frm;
		struct quic_frame *found = NULL;

		/* There is at most one CRYPTO frame in this packet number
		 * space. Let's look for it.
		 */
		list_for_each_entry(frm, &qel->pktns->tx.frms, list) {
			if (frm->type != QUIC_FT_CRYPTO)
				continue;

			/* Found */
			found = frm;
			break;
		}

		if (found) {
			found->crypto.len += cf_len;
		}
		else {
			frm = qc_frm_alloc(QUIC_FT_CRYPTO);
			if (!frm) {
				TRACE_ERROR("Could not allocate quic frame", QUIC_EV_CONN_ADDDATA, qc);
				goto leave;
			}

			frm->crypto.offset = cf_offset;
			frm->crypto.len = cf_len;
			frm->crypto.qel = qel;
			LIST_APPEND(&qel->pktns->tx.frms, &frm->list);
		}
	}
	ret = len == 0;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_ADDDATA, qc);
	return ret;
}

/* returns 0 on error, 1 on success */
static int ha_quic_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
                                          const uint8_t *read_secret,
                                          const uint8_t *write_secret, size_t secret_len)
{
	int ret = 0;
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	struct quic_enc_level **qel = ssl_to_qel_addr(qc, level);
	struct quic_pktns **pktns = ssl_to_quic_pktns(qc, level);
	struct quic_tls_ctx *tls_ctx;
	const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
	struct quic_tls_secrets *rx = NULL, *tx = NULL;
	const struct quic_version *ver =
		qc->negotiated_version ? qc->negotiated_version : qc->original_version;

	TRACE_ENTER(QUIC_EV_CONN_RWSEC, qc);
	BUG_ON(secret_len > QUIC_TLS_SECRET_LEN);

	if (!*qel && !qc_enc_level_alloc(qc, pktns, qel, level)) {
		TRACE_PROTO("Could not allocate an encryption level", QUIC_EV_CONN_ADDDATA, qc);
		goto leave;
	}

	tls_ctx = &(*qel)->tls_ctx;

	if (qc->flags & QUIC_FL_CONN_TO_KILL) {
		TRACE_PROTO("connection to be killed", QUIC_EV_CONN_ADDDATA, qc);
		goto out;
	}

	if (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("CC required", QUIC_EV_CONN_RWSEC, qc);
		goto out;
	}

	if (!read_secret)
		goto write;

	rx = &tls_ctx->rx;
	rx->aead = tls_aead(cipher);
	rx->md   = tls_md(cipher);
	rx->hp   = tls_hp(cipher);
	if (!rx->aead || !rx->md || !rx->hp)
		goto leave;

	if (!quic_tls_secrets_keys_alloc(rx)) {
		TRACE_ERROR("RX keys allocation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_derive_keys(rx->aead, rx->hp, rx->md, ver, rx->key, rx->keylen,
	                          rx->iv, rx->ivlen, rx->hp_key, sizeof rx->hp_key,
	                          read_secret, secret_len)) {
		TRACE_ERROR("TX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_rx_ctx_init(&rx->ctx, rx->aead, rx->key)) {
		TRACE_ERROR("could not initial RX TLS cipher context", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_dec_aes_ctx_init(&rx->hp_ctx, rx->hp, rx->hp_key)) {
		TRACE_ERROR("could not initial RX TLS cipher context for HP", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	/* Enqueue this connection asap if we could derive O-RTT secrets as
	 * listener. Note that a listener derives only RX secrets for this
	 * level.
	 */
	if (qc_is_listener(qc) && level == ssl_encryption_early_data) {
		TRACE_DEVEL("pushing connection into accept queue", QUIC_EV_CONN_RWSEC, qc);
		quic_accept_push_qc(qc);
	}

write:

	if (!write_secret)
		goto keyupdate_init;

	tx = &tls_ctx->tx;
	tx->aead = tls_aead(cipher);
	tx->md   = tls_md(cipher);
	tx->hp   = tls_hp(cipher);
	if (!tx->aead || !tx->md || !tx->hp)
		goto leave;

	if (!quic_tls_secrets_keys_alloc(tx)) {
		TRACE_ERROR("TX keys allocation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_derive_keys(tx->aead, tx->hp, tx->md, ver, tx->key, tx->keylen,
	                          tx->iv, tx->ivlen, tx->hp_key, sizeof tx->hp_key,
	                          write_secret, secret_len)) {
		TRACE_ERROR("TX key derivation failed", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_tx_ctx_init(&tx->ctx, tx->aead, tx->key)) {
		TRACE_ERROR("could not initial RX TLS cipher context", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	if (!quic_tls_enc_aes_ctx_init(&tx->hp_ctx, tx->hp, tx->hp_key)) {
		TRACE_ERROR("could not initial TX TLS cipher context for HP", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	/* Set the transport parameters in the TLS stack. */
	if (level == ssl_encryption_handshake && qc_is_listener(qc) &&
	    !qc_ssl_set_quic_transport_params(qc, ver, 1))
		goto leave;

 keyupdate_init:
	/* Store the secret provided by the TLS stack, required for keyupdate. */
	if (level == ssl_encryption_application) {
		struct quic_tls_kp *prv_rx = &qc->ku.prv_rx;
		struct quic_tls_kp *nxt_rx = &qc->ku.nxt_rx;
		struct quic_tls_kp *nxt_tx = &qc->ku.nxt_tx;

		if (rx) {
			if (!(rx->secret = pool_alloc(pool_head_quic_tls_secret))) {
				TRACE_ERROR("Could not allocate RX Application secrete keys", QUIC_EV_CONN_RWSEC, qc);
				goto leave;
			}

			memcpy(rx->secret, read_secret, secret_len);
			rx->secretlen = secret_len;
		}

		if (tx) {
			if (!(tx->secret = pool_alloc(pool_head_quic_tls_secret))) {
				TRACE_ERROR("Could not allocate TX Application secrete keys", QUIC_EV_CONN_RWSEC, qc);
				goto leave;
			}

			memcpy(tx->secret, write_secret, secret_len);
			tx->secretlen = secret_len;
		}

		/* Initialize all the secret keys lengths */
		prv_rx->secretlen = nxt_rx->secretlen = nxt_tx->secretlen = secret_len;
	}

 out:
	ret = 1;
 leave:
	if (!ret) {
		/* Release the CRYPTO frames which have been provided by the TLS stack
		 * to prevent the transmission of ack-eliciting packets.
		 */
		qc_release_pktns_frms(qc, qc->ipktns);
		qc_release_pktns_frms(qc, qc->hpktns);
		qc_release_pktns_frms(qc, qc->apktns);
		quic_set_tls_alert(qc, SSL_AD_HANDSHAKE_FAILURE);
	}

	TRACE_LEAVE(QUIC_EV_CONN_RWSEC, qc, &level);
	return ret;
}

#if defined(OPENSSL_IS_AWSLC)
/* compatibility function for split read/write encryption secrets to be used
 * with the API which uses 2 callbacks. */
static inline int ha_quic_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
                                   const SSL_CIPHER *cipher, const uint8_t *secret,
                                   size_t secret_len)
{
	return ha_quic_set_encryption_secrets(ssl, level, secret, NULL, secret_len);

}

static inline int ha_quic_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
                                   const SSL_CIPHER *cipher, const uint8_t *secret,
                                   size_t secret_len)
{

	return ha_quic_set_encryption_secrets(ssl, level, NULL, secret, secret_len);

}
#endif

/* ->add_handshake_data QUIC TLS callback used by the QUIC TLS stack when it
 * wants to provide the QUIC layer with CRYPTO data.
 * Returns 1 if succeeded, 0 if not.
 */
static int ha_quic_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
                                      const uint8_t *data, size_t len)
{
	int ret = 0;
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	struct quic_enc_level **qel = ssl_to_qel_addr(qc, level);
	struct quic_pktns **pktns = ssl_to_quic_pktns(qc, level);

	TRACE_ENTER(QUIC_EV_CONN_ADDDATA, qc);

	if (qc->flags & QUIC_FL_CONN_TO_KILL) {
		TRACE_PROTO("connection to be killed", QUIC_EV_CONN_ADDDATA, qc);
		goto out;
	}

	if (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
		TRACE_PROTO("CC required", QUIC_EV_CONN_ADDDATA, qc);
		goto out;
	}

	if (!*qel && !qc_enc_level_alloc(qc, pktns, qel, level))
		goto leave;

	if (!qc_ssl_crypto_data_cpy(qc, *qel, data, len)) {
		TRACE_ERROR("Could not bufferize", QUIC_EV_CONN_ADDDATA, qc);
		goto leave;
	}

	TRACE_DEVEL("CRYPTO data buffered", QUIC_EV_CONN_ADDDATA,
	            qc, &level, &len);
 out:
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_ADDDATA, qc);
	return ret;
}

static int ha_quic_flush_flight(SSL *ssl)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_FFLIGHT, qc);
	TRACE_LEAVE(QUIC_EV_CONN_FFLIGHT, qc);

	return 1;
}

static int ha_quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_SSLALERT, qc);

	TRACE_PROTO("Received TLS alert", QUIC_EV_CONN_SSLALERT, qc, &alert, &level);

	quic_set_tls_alert(qc, alert);
	TRACE_LEAVE(QUIC_EV_CONN_SSLALERT, qc);
	return 1;
}

/* QUIC TLS methods */
#if defined(OPENSSL_IS_AWSLC)
/* write/read set secret splitted */
static SSL_QUIC_METHOD ha_quic_method = {
	.set_read_secret        = ha_quic_set_read_secret,
	.set_write_secret       = ha_quic_set_write_secret,
	.add_handshake_data     = ha_quic_add_handshake_data,
	.flush_flight           = ha_quic_flush_flight,
	.send_alert             = ha_quic_send_alert,
};

#else

static SSL_QUIC_METHOD ha_quic_method = {
	.set_encryption_secrets = ha_quic_set_encryption_secrets,
	.add_handshake_data     = ha_quic_add_handshake_data,
	.flush_flight           = ha_quic_flush_flight,
	.send_alert             = ha_quic_send_alert,
};
#endif

/* Initialize the TLS context of a listener with <bind_conf> as configuration.
 * Returns an error count.
 */
int ssl_quic_initial_ctx(struct bind_conf *bind_conf)
{
	struct ssl_bind_conf __maybe_unused *ssl_conf_cur;
	int cfgerr = 0;

	long options =
		(SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
		SSL_OP_SINGLE_ECDH_USE |
		SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_server_method());
	bind_conf->initial_ctx = ctx;

	SSL_CTX_set_options(ctx, options);
	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
# if defined(HAVE_SSL_CLIENT_HELLO_CB)
#  if defined(SSL_OP_NO_ANTI_REPLAY)
	if (bind_conf->ssl_conf.early_data) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
#   if defined(USE_QUIC_OPENSSL_COMPAT) || defined(OPENSSL_IS_AWSLC)
		ha_warning("Binding [%s:%d] for %s %s: 0-RTT is not supported in limited QUIC compatibility mode, ignored.\n",
		           bind_conf->file, bind_conf->line, proxy_type_str(bind_conf->frontend), bind_conf->frontend->id);
#   else
		SSL_CTX_set_max_early_data(ctx, 0xffffffff);
#   endif /* ! USE_QUIC_OPENSSL_COMPAT */
	}
#  endif /* !SSL_OP_NO_ANTI_REPLAY */
	SSL_CTX_set_client_hello_cb(ctx, ssl_sock_switchctx_cbk, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
# else /* ! HAVE_SSL_CLIENT_HELLO_CB */
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
# endif
	SSL_CTX_set_tlsext_servername_arg(ctx, bind_conf);
#endif
#ifdef USE_QUIC_OPENSSL_COMPAT
	if (!quic_tls_compat_init(bind_conf, ctx))
		cfgerr++;
#endif

	return cfgerr;
}

/* This function gives the detail of the SSL error. It is used only
 * if the debug mode and the verbose mode are activated. It dump all
 * the SSL error until the stack was empty.
 */
static forceinline void qc_ssl_dump_errors(struct connection *conn)
{
	if (unlikely(global.mode & MODE_DEBUG)) {
		while (1) {
			const char *func = NULL;
			unsigned long ret;

			ERR_peek_error_func(&func);
			ret = ERR_get_error();
			if (!ret)
				return;

			fprintf(stderr, "conn. @%p OpenSSL error[0x%lx] %s: %s\n", conn, ret,
			        func, ERR_reason_error_string(ret));
		}
	}
}

/* Provide CRYPTO data to the TLS stack found at <data> with <len> as length
 * from <qel> encryption level with <ctx> as QUIC connection context.
 * Remaining parameter are there for debugging purposes.
 * Return 1 if succeeded, 0 if not.
 */
int qc_ssl_provide_quic_data(struct ncbuf *ncbuf,
                             enum ssl_encryption_level_t level,
                             struct ssl_sock_ctx *ctx,
                             const unsigned char *data, size_t len)
{
#ifdef DEBUG_STRICT
	enum ncb_ret ncb_ret;
#endif
	int ssl_err, state;
	struct quic_conn *qc;
	int ret = 0;

	ssl_err = SSL_ERROR_NONE;
	qc = ctx->qc;

	TRACE_ENTER(QUIC_EV_CONN_SSLDATA, qc);

	if (SSL_provide_quic_data(ctx->ssl, level, data, len) != 1) {
		TRACE_ERROR("SSL_provide_quic_data() error",
		            QUIC_EV_CONN_SSLDATA, qc, NULL, NULL, ctx->ssl);
		goto leave;
	}

	state = qc->state;
	if (state < QUIC_HS_ST_COMPLETE) {
		ssl_err = SSL_do_handshake(ctx->ssl);

		if (qc->flags & QUIC_FL_CONN_TO_KILL) {
			TRACE_DEVEL("connection to be killed", QUIC_EV_CONN_IO_CB, qc);
			goto leave;
		}

		/* Finalize the connection as soon as possible if the peer transport parameters
		 * have been received. This may be useful to send packets even if this
		 * handshake fails.
		 */
		if ((qc->flags & QUIC_FL_CONN_TX_TP_RECEIVED) && !qc_conn_finalize(qc, 1)) {
			TRACE_ERROR("connection finalization failed", QUIC_EV_CONN_IO_CB, qc, &state);
			goto leave;
		}

		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_PROTO("SSL handshake in progress",
				            QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
				goto out;
			}

			TRACE_ERROR("SSL handshake error", QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
			HA_ATOMIC_INC(&qc->prx_counters->hdshk_fail);
			qc_ssl_dump_errors(ctx->conn);
			ERR_clear_error();
			goto leave;
		}

		TRACE_PROTO("SSL handshake OK", QUIC_EV_CONN_IO_CB, qc, &state);

		/* Check the alpn could be negotiated */
		if (!qc->app_ops) {
			TRACE_ERROR("No negotiated ALPN", QUIC_EV_CONN_IO_CB, qc, &state);
			quic_set_tls_alert(qc, SSL_AD_NO_APPLICATION_PROTOCOL);
			goto leave;
		}

		/* I/O callback switch */
		qc->wait_event.tasklet->process = quic_conn_app_io_cb;
		if (qc_is_listener(ctx->qc)) {
			qc->flags |= QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS;
			qc->state = QUIC_HS_ST_CONFIRMED;
			/* The connection is ready to be accepted. */
			quic_accept_push_qc(qc);

			BUG_ON(qc->li->rx.quic_curr_handshake == 0);
			HA_ATOMIC_DEC(&qc->li->rx.quic_curr_handshake);
		}
		else {
			qc->state = QUIC_HS_ST_COMPLETE;
		}

		/* Prepare the next key update */
		if (!quic_tls_key_update(qc)) {
			TRACE_ERROR("quic_tls_key_update() failed", QUIC_EV_CONN_IO_CB, qc);
			goto leave;
		}
	} else {
		ssl_err = SSL_process_quic_post_handshake(ctx->ssl);
		if (ssl_err != 1) {
			ssl_err = SSL_get_error(ctx->ssl, ssl_err);
			if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
				TRACE_PROTO("SSL post handshake in progress",
				            QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
				goto out;
			}

			TRACE_ERROR("SSL post handshake error",
			            QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
			goto leave;
		}

		TRACE_STATE("SSL post handshake succeeded", QUIC_EV_CONN_IO_CB, qc, &state);
	}

 out:
	ret = 1;
 leave:
	/* The CRYPTO data are consumed even in case of an error to release
	 * the memory asap.
	 */
	if (!ncb_is_null(ncbuf)) {
#ifdef DEBUG_STRICT
		ncb_ret = ncb_advance(ncbuf, len);
		/* ncb_advance() must always succeed. This is guaranteed as
		 * this is only done inside a data block. If false, this will
		 * lead to handshake failure with quic_enc_level offset shifted
		 * from buffer data.
		 */
		BUG_ON(ncb_ret != NCB_RET_OK);
#else
		ncb_advance(ncbuf, len);
#endif
	}

	TRACE_LEAVE(QUIC_EV_CONN_SSLDATA, qc);
	return ret;
}

/* Provide all the stored in order CRYPTO data received from the peer to the TLS.
 * Return 1 if succeeded, 0 if not.
 */
int qc_ssl_provide_all_quic_data(struct quic_conn *qc, struct ssl_sock_ctx *ctx)
{
	int ret = 0;
	struct quic_enc_level *qel;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);
	list_for_each_entry(qel, &qc->qel_list, list) {
		int ssl_ret;
		struct quic_cstream *cstream = qel->cstream;
		struct ncbuf *ncbuf;
		struct qf_crypto *qf_crypto, *qf_back;

		if (!qel->cstream) {
			TRACE_DEVEL("no cstream", QUIC_EV_CONN_PHPKTS, qc, qel);
			continue;
		}

		ssl_ret = 1;
		ncbuf = &cstream->rx.ncbuf;
		list_for_each_entry_safe(qf_crypto, qf_back, &qel->rx.crypto_frms, list) {

			ssl_ret = qc_ssl_provide_quic_data(ncbuf, qel->level, ctx,
			                                   qf_crypto->data, qf_crypto->len);
			/* Free this frame asap */
			LIST_DELETE(&qf_crypto->list);
			pool_free(pool_head_qf_crypto, qf_crypto);

			if (!ssl_ret) {
				TRACE_DEVEL("null ssl_ret", QUIC_EV_CONN_PHPKTS, qc, qel);
				break;
			}

			TRACE_DEVEL("buffered crypto data were provided to TLS stack",
						QUIC_EV_CONN_PHPKTS, qc, qel);
		}

		if (!qc_treat_rx_crypto_frms(qc, qel, ctx))
			ssl_ret = 0;

		if (!ssl_ret)
			goto leave;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
	return ret;
}

/* Try to allocate the <*ssl> SSL session object for <qc> QUIC connection
 * with <ssl_ctx> as SSL context inherited settings. Also set the transport
 * parameters of this session.
 * This is the responsibility of the caller to check the validity of all the
 * pointers passed as parameter to this function.
 * Return 0 if succeeded, -1 if not. If failed, sets the ->err_code member of <qc->conn> to
 * CO_ER_SSL_NO_MEM.
 */
static int qc_ssl_sess_init(struct quic_conn *qc, SSL_CTX *ssl_ctx, SSL **ssl)
{
	int retry, ret = -1;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	retry = 1;
 retry:
	*ssl = SSL_new(ssl_ctx);
	if (!*ssl) {
		if (!retry--)
			goto leave;

		pool_gc(NULL);
		goto retry;
	}

	if (!SSL_set_ex_data(*ssl, ssl_qc_app_data_index, qc) ||
	    !SSL_set_quic_method(*ssl, &ha_quic_method)) {
		SSL_free(*ssl);
		*ssl = NULL;
		if (!retry--)
			goto leave;

		pool_gc(NULL);
		goto retry;
	}

	ret = 0;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
}

/* Allocate the ssl_sock_ctx from connection <qc>. This creates the tasklet
 * used to process <qc> received packets. The allocated context is stored in
 * <qc.xprt_ctx>.
 *
 * Returns 0 on success else non-zero.
 */
int qc_alloc_ssl_sock_ctx(struct quic_conn *qc)
{
	int ret = 0;
	struct bind_conf *bc = qc->li->bind_conf;
	struct ssl_sock_ctx *ctx = NULL;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	ctx = pool_alloc(pool_head_quic_ssl_sock_ctx);
	if (!ctx) {
		TRACE_ERROR("SSL context allocation failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	ctx->conn = NULL;
	ctx->bio = NULL;
	ctx->xprt = NULL;
	ctx->xprt_ctx = NULL;
	memset(&ctx->wait_event, 0, sizeof(ctx->wait_event));
	ctx->subs = NULL;
	ctx->xprt_st = 0;
	ctx->error_code = 0;
	ctx->early_buf = BUF_NULL;
	ctx->sent_early_data = 0;
	ctx->qc = qc;

	if (qc_is_listener(qc)) {
		if (qc_ssl_sess_init(qc, bc->initial_ctx, &ctx->ssl) == -1)
		        goto err;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L) && !defined(OPENSSL_IS_AWSLC)
#ifndef USE_QUIC_OPENSSL_COMPAT
		/* Enabling 0-RTT */
		if (bc->ssl_conf.early_data)
			SSL_set_quic_early_data_enabled(ctx->ssl, 1);
#endif
#endif

		SSL_set_accept_state(ctx->ssl);
	}

	ctx->xprt = xprt_get(XPRT_QUIC);

	/* Store the allocated context in <qc>. */
	qc->xprt_ctx = ctx;

	/* global.sslconns is already incremented on INITIAL packet parsing. */
	_HA_ATOMIC_INC(&global.totalsslconns);

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return !ret;

 err:
	pool_free(pool_head_quic_ssl_sock_ctx, ctx);
	goto leave;
}
