#include <haproxy/errors.h>
#include <haproxy/ncbuf.h>
#include <haproxy/proxy.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_ssl.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_tp.h>
#include <haproxy/quic_trace.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/trace.h>

static BIO_METHOD *ha_quic_meth;

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

	if (!quic_tls_dec_hp_ctx_init(&rx->hp_ctx, rx->hp, rx->hp_key)) {
		TRACE_ERROR("could not initial RX TLS cipher context for HP", QUIC_EV_CONN_RWSEC, qc);
		goto leave;
	}

	/* Enqueue this connection asap if we could derive O-RTT secrets as
	 * listener and if a token was received. Note that a listener derives only RX
	 * secrets for this level.
	 */
	if (qc_is_listener(qc) && level == ssl_encryption_early_data) {
		if (qc->flags & QUIC_FL_CONN_NO_TOKEN_RCVD) {
			/* Leave a chance to the address validation to be completed by the
			 * handshake without starting the mux: one does not want to process
			 * the 0RTT data in this case.
			 */
			TRACE_PROTO("0RTT session without token", QUIC_EV_CONN_RWSEC, qc);
		}
		else {
			TRACE_DEVEL("pushing connection into accept queue", QUIC_EV_CONN_RWSEC, qc);
			quic_accept_push_qc(qc);
		}
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

	if (!quic_tls_enc_hp_ctx_init(&tx->hp_ctx, tx->hp, tx->hp_key)) {
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

	TRACE_PROTO("ha_quic_add_handshake_data() called", QUIC_EV_CONN_IO_CB, qc, NULL, NULL, ssl);

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
/* write/read set secret split */
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

	if (global_ssl.security_level > -1)
		SSL_CTX_set_security_level(ctx, global_ssl.security_level);
	SSL_CTX_set_options(ctx, options);
	SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

	if (bind_conf->ssl_conf.early_data) {
#if !defined(HAVE_SSL_0RTT_QUIC)
		ha_warning("Binding [%s:%d] for %s %s: 0-RTT with QUIC is not supported by this SSL library, ignored.\n",
		           bind_conf->file, bind_conf->line, proxy_type_str(bind_conf->frontend), bind_conf->frontend->id);
#elif defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
		SSL_CTX_set_early_data_enabled(ctx, 1);
#else
		SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
		SSL_CTX_set_max_early_data(ctx, 0xffffffff);
#endif /* ! HAVE_SSL_0RTT_QUIC  */
	}

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
# if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
	SSL_CTX_set_select_certificate_cb(ctx, ssl_sock_switchctx_cbk);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
# elif defined(HAVE_SSL_CLIENT_HELLO_CB)
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
static int qc_ssl_provide_quic_data(struct ncbuf *ncbuf,
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
		TRACE_PROTO("SSL_do_handshake() called", QUIC_EV_CONN_IO_CB, qc, NULL, NULL, ctx->ssl);

		if (qc->flags & QUIC_FL_CONN_TO_KILL) {
			TRACE_DEVEL("connection to be killed", QUIC_EV_CONN_IO_CB, qc, &state, NULL, ctx->ssl);
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
#if defined(LIBRESSL_VERSION_NUMBER)
		else if (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) {
			/* Some libressl versions emit TLS alerts without making the handshake
			 * (SSL_do_handshake()) fail. This is at least the case for
			 * libressl-3.9.0 when forcing the TLS cipher to TLS_AES_128_CCM_SHA256.
			 */
			TRACE_ERROR("SSL handshake error", QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
			HA_ATOMIC_INC(&qc->prx_counters->hdshk_fail);
			goto leave;
		}
#endif

#if defined(OPENSSL_IS_AWSLC)
		/* As a server, if early data is accepted, SSL_do_handshake will
		 * complete as soon as the ClientHello is processed and server flight sent.
		 * SSL_write may be used to send half-RTT data. SSL_read will consume early
		 * data and transition to 1-RTT data as appropriate. Prior to the
		 * transition, SSL_in_init will report the handshake is still in progress.
		 * Callers may use it or SSL_in_early_data to defer or reject requests
		 * as needed.
		 * (see https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#Early-data)
		 */

		/* If we do not returned here, the handshake is considered as completed/confirmed.
		 * This has as bad side effect to discard the Handshake packet number space,
		 * so without sending the Handshake level CRYPTO data.
		 */
		if (SSL_in_early_data(ctx->ssl)) {
			TRACE_PROTO("SSL handshake in progrees with early data",
			            QUIC_EV_CONN_IO_CB, qc, &state, &ssl_err);
			goto out;
		}
#endif

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

			if (!(qc->flags & QUIC_FL_CONN_ACCEPT_REGISTERED)) {
				quic_accept_push_qc(qc);
			}
			else {
				/* Connection already accepted if 0-RTT used.
				 * In this case, schedule quic-conn to ensure
				 * post-handshake frames are emitted.
				 */
				tasklet_wakeup(qc->wait_event.tasklet);
			}

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
	struct ncbuf *ncbuf;
	ncb_sz_t data;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);
	list_for_each_entry(qel, &qc->qel_list, list) {
		struct quic_cstream *cstream = qel->cstream;

		if (!cstream)
			continue;

		ncbuf = &cstream->rx.ncbuf;
		if (ncb_is_null(ncbuf))
			continue;

		/* TODO not working if buffer is wrapping */
		while ((data = ncb_data(ncbuf, 0))) {
			const unsigned char *cdata = (const unsigned char *)ncb_head(ncbuf);

			if (!qc_ssl_provide_quic_data(&qel->cstream->rx.ncbuf, qel->level,
			                              ctx, cdata, data))
				goto leave;

			cstream->rx.offset += data;
			TRACE_DEVEL("buffered crypto data were provided to TLS stack",
			            QUIC_EV_CONN_PHPKTS, qc, qel);
		}

		if (!ncb_is_null(ncbuf) && ncb_is_empty(ncbuf)) {
			TRACE_DEVEL("freeing crypto buf", QUIC_EV_CONN_PHPKTS, qc, qel);
			quic_free_ncbuf(ncbuf);
		}
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

#ifdef HAVE_SSL_0RTT_QUIC

/* Enable early data for <ssl> QUIC TLS session.
 * Return 1 if succeeded, 0 if not.
 */
static int qc_set_quic_early_data_enabled(struct quic_conn *qc, SSL *ssl)
{
#if defined(OPENSSL_IS_AWSLC)
	struct quic_transport_params p = {0};
	unsigned char buf[128];
	size_t len;

	/* Apply default values to <p> transport parameters. */
	quic_transport_params_init(&p, 1);
	/* The stateless_reset_token transport parameter is not needed. */
	p.with_stateless_reset_token = 0;
	len = quic_transport_params_encode(buf, buf + sizeof buf, &p, NULL, 1);
	if (!len) {
		TRACE_ERROR("quic_transport_params_encode() failed", QUIC_EV_CONN_RWSEC, qc);
		return 0;
	}

	/* XXX TODO: Should also add the application settings. XXX */
	if (!SSL_set_quic_early_data_context(ssl, buf, len)) {
		TRACE_ERROR("SSL_set_quic_early_data_context() failed", QUIC_EV_CONN_RWSEC, qc);
		return 0;
	}

	SSL_set_early_data_enabled(ssl, 1);
#else
	SSL_set_quic_early_data_enabled(ssl, 1);
#endif

	return 1;
}
#endif // HAVE_SSL_0RTT_QUIC

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
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L) && defined(HAVE_SSL_0RTT_QUIC)
		/* Enabling 0-RTT */
		if (bc->ssl_conf.early_data && !qc_set_quic_early_data_enabled(qc, ctx->ssl))
			goto err;
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

static void __quic_conn_init(void)
{
	ha_quic_meth = BIO_meth_new(0x666, "ha QUIC methods");
}
INITCALL0(STG_REGISTER, __quic_conn_init);

static void __quic_conn_deinit(void)
{
	BIO_meth_free(ha_quic_meth);
}
REGISTER_POST_DEINIT(__quic_conn_deinit);
