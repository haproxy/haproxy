#ifndef USE_QUIC
#error "Must define USE_QUIC"
#endif

#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/openssl-compat.h>
/* Highly inspired from nginx QUIC TLS compatibility code */
#include <openssl/kdf.h>

#include <haproxy/quic_conn.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_trace.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/trace.h>

#ifndef HAVE_SSL_KEYLOG
#error "HAVE_SSL_KEYLOG is not defined"
#endif

#define QUIC_OPENSSL_COMPAT_RECORD_SIZE          1024

#define QUIC_TLS_KEY_LABEL "key"
#define QUIC_TLS_IV_LABEL  "iv"

struct quic_tls_compat_record {
	unsigned char type;
	const unsigned char *payload;
	size_t payload_len;
	uint64_t number;
	struct quic_tls_compat_keys *keys;
};

/* Callback used to set the local transport parameters into the TLS stack.
 * Must be called after having been set at the QUIC connection level.
 */
static int qc_ssl_compat_add_tps_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                                    const unsigned char **out, size_t *outlen,
                                    X509 *x, size_t chainidx, int *al, void *add_arg)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);

	*out = qc->enc_params;
	*outlen = qc->enc_params_len;

	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return 1;
}

/* Set the keylog callback used to derive TLS secrets and the callback
 * used to pass local transport parameters to the TLS stack.
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_compat_init(struct bind_conf *bind_conf, SSL_CTX *ctx)
{
	/* Ignore non-QUIC connections */
	if (bind_conf->xprt != xprt_get(XPRT_QUIC))
		return 1;

	/* This callback is already registered if the TLS keylog is activated for
	 * traffic decryption analysis.
	 */
	if (!global_ssl.keylog)
		SSL_CTX_set_keylog_callback(ctx, quic_tls_compat_keylog_callback);

	if (SSL_CTX_has_client_custom_ext(ctx, QUIC_OPENSSL_COMPAT_SSL_TP_EXT))
		return 1;

	if (!SSL_CTX_add_custom_ext(ctx, QUIC_OPENSSL_COMPAT_SSL_TP_EXT,
	                            SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
	                            qc_ssl_compat_add_tps_cb, NULL, NULL,
	                            NULL, NULL))
		return 0;

	return 1;
}

static int quic_tls_compat_set_encryption_secret(struct quic_conn *qc,
                                                 struct quic_tls_compat_keys *keys,
                                                 enum ssl_encryption_level_t level,
                                                 const SSL_CIPHER *cipher,
                                                 const uint8_t *secret, size_t secret_len)
{
	int ret = 0, key_len;
	struct quic_tls_secret *peer_secret;

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);

	peer_secret = &keys->secret;
	if (sizeof(peer_secret->secret.data) < secret_len)
		goto leave;

	keys->cipher = tls_aead(cipher);
	if (!keys->cipher)
		goto leave;

	key_len = EVP_CIPHER_key_length(keys->cipher);

	peer_secret->secret.len = secret_len;
	memcpy(peer_secret->secret.data, secret, secret_len);

	peer_secret->key.len = key_len;
	peer_secret->iv.len = QUIC_OPENSSL_COMPAT_TLS_IV_LEN;
	if (!quic_hkdf_expand_label(tls_md(cipher),
	                            peer_secret->key.data, peer_secret->key.len,
	                            secret, secret_len,
	                            (const unsigned char *)QUIC_TLS_KEY_LABEL,
	                            sizeof(QUIC_TLS_KEY_LABEL) - 1) ||
	    !quic_hkdf_expand_label(tls_md(cipher),
	                            peer_secret->iv.data, peer_secret->iv.len,
	                            secret, secret_len,
	                            (const unsigned char *)QUIC_TLS_IV_LABEL,
	                            sizeof(QUIC_TLS_IV_LABEL) - 1))
		goto leave;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return ret;
}

/* Callback used to get the Handshake and Application level secrets from
 * the TLS stack.
 */
void quic_tls_compat_keylog_callback(const SSL *ssl, const char *line)
{
	unsigned char ch, value;
	const char *start, *p;
	size_t n;
	unsigned int write;
	struct quic_openssl_compat *compat;
	enum ssl_encryption_level_t level;
	unsigned char secret[EVP_MAX_MD_SIZE];
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	/* Ignore non-QUIC connections */
	if (!qc)
	    return;

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);

	p = line;
	for (start = p; *p && *p != ' '; p++);
	n = p - start;

	if (sizeof(QUIC_OPENSSL_COMPAT_CLIENT_HANDSHAKE) - 1 == n &&
	    !strncmp(start, QUIC_OPENSSL_COMPAT_CLIENT_HANDSHAKE, n)) {
		level = ssl_encryption_handshake;
		write = 0;
	}
	else if (sizeof(QUIC_OPENSSL_COMPAT_SERVER_HANDSHAKE) - 1 == n &&
	         !strncmp(start, QUIC_OPENSSL_COMPAT_SERVER_HANDSHAKE, n)) {
		level = ssl_encryption_handshake;
		write = 1;
	}
	else if (sizeof(QUIC_OPENSSL_COMPAT_CLIENT_APPLICATION) - 1 == n &&
	         !strncmp(start, QUIC_OPENSSL_COMPAT_CLIENT_APPLICATION, n)) {
		level = ssl_encryption_application;
		write = 0;
	}
	else if (sizeof(QUIC_OPENSSL_COMPAT_SERVER_APPLICATION) - 1 == n &&
	         !strncmp(start, QUIC_OPENSSL_COMPAT_SERVER_APPLICATION, n)) {
		level = ssl_encryption_application;
		write = 1;
	}
	else
		goto leave;

	if (*p++ == '\0')
		goto leave;

	while (*p && *p != ' ')
		p++;

	if (*p++ == '\0')
		goto leave;

	for (n = 0, start = p; *p; p++) {
		ch = *p;
		if (ch >= '0' && ch <= '9') {
			value = ch - '0';
			goto next;
		}

		ch = (unsigned char) (ch | 0x20);
		if (ch >= 'a' && ch <= 'f') {
			value = ch - 'a' + 10;
			goto next;
		}

		goto leave;

next:
		if ((p - start) % 2) {
			secret[n++] += value;
		}
		else {
			if (n >= EVP_MAX_MD_SIZE)
				goto leave;

			secret[n] = (value << 4);
		}
	}

	/* Secret successfully parsed */
	compat = &qc->openssl_compat;
	if (write) {
		compat->method->set_encryption_secrets((SSL *) ssl, level, NULL, secret, n);
		compat->write_level = level;

	} else {
		const SSL_CIPHER *cipher;

		cipher = SSL_get_current_cipher(ssl);
		/* AES_128_CCM_SHA256 not supported at this time. Furthermore, this
		 * algorithm is silently disabled by the TLS stack. But it can be
		 * enabled with "ssl-default-bind-ciphersuites" setting.
		 */
		if (SSL_CIPHER_get_id(cipher) == TLS1_3_CK_AES_128_CCM_SHA256) {
			quic_set_tls_alert(qc, SSL_AD_HANDSHAKE_FAILURE);
			goto leave;
		}

		compat->method->set_encryption_secrets((SSL *) ssl, level, secret, NULL, n);
		compat->read_level = level;
		compat->read_record = 0;
		quic_tls_compat_set_encryption_secret(qc, &compat->keys, level,
		                                      cipher, secret, n);
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
}

static size_t quic_tls_compat_create_header(struct quic_conn *qc,
                                            struct quic_tls_compat_record *rec,
                                            unsigned char *out, int plain)
{
	unsigned char type;
	size_t len;

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);

	len = rec->payload_len;
	if (plain) {
		type = rec->type;
	}
	else {
		type = SSL3_RT_APPLICATION_DATA;
		len += EVP_GCM_TLS_TAG_LEN;
	}

	out[0] = type;
	out[1] = 0x03;
	out[2] = 0x03;
	out[3] = (len >> 8);
	out[4] = len;

	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return 5;
}

static void quic_tls_compute_nonce(unsigned char *nonce, size_t len, uint64_t pn)
{
	nonce[len - 8] ^= (pn >> 56) & 0x3f;
	nonce[len - 7] ^= (pn >> 48) & 0xff;
	nonce[len - 6] ^= (pn >> 40) & 0xff;
	nonce[len - 5] ^= (pn >> 32) & 0xff;
	nonce[len - 4] ^= (pn >> 24) & 0xff;
	nonce[len - 3] ^= (pn >> 16) & 0xff;
	nonce[len - 2] ^= (pn >> 8) & 0xff;
	nonce[len - 1] ^= pn & 0xff;
}

/* Cipher <in> buffer data into <out> with <cipher> as AEAD cipher, <s> as secret.
 * <ad> is the buffer for the additional data.
 */
static int quic_tls_tls_seal(struct quic_conn *qc,
                             const EVP_CIPHER *cipher, struct quic_tls_secret *s,
                             unsigned char *out, size_t *outlen, unsigned char *nonce,
                             const unsigned char *in, size_t inlen,
                             const unsigned char *ad, size_t adlen)
{
	int ret = 0, wlen;
	EVP_CIPHER_CTX *ctx;
	int aead_nid = EVP_CIPHER_nid(cipher);

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		goto leave;

	/* Note that the following encryption code works with NID_aes_128_ccm, but leads
	 * to an handshake failure with "bad record mac" (20) TLS alert received from
	 * the peer.
	 */
	if (!EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) ||
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, s->iv.len, NULL) ||
	    (aead_nid == NID_aes_128_ccm &&
	     !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, NULL)) ||
	    !EVP_EncryptInit_ex(ctx, NULL, NULL, s->key.data, nonce) ||
	    (aead_nid == NID_aes_128_ccm &&
	     !EVP_EncryptUpdate(ctx, NULL, &wlen, NULL, inlen)) ||
	    !EVP_EncryptUpdate(ctx, NULL, &wlen, ad, adlen) ||
	    !EVP_EncryptUpdate(ctx, out, &wlen, in, inlen) ||
	    !EVP_EncryptFinal_ex(ctx, out + wlen, &wlen) ||
	    (aead_nid != NID_aes_128_ccm &&
	     !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN, out + inlen))) {
		goto leave;
	}

	*outlen = inlen + adlen + EVP_GCM_TLS_TAG_LEN;
	ret = 1;
 leave:
	/* Safe to call EVP_CIPHER_CTX_free() with null ctx */
	EVP_CIPHER_CTX_free(ctx);
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return ret;
}

static int quic_tls_compat_create_record(struct quic_conn *qc,
                                         enum ssl_encryption_level_t level,
                                         struct quic_tls_compat_record *rec,
                                         unsigned char *res)
{
	int ret = 0;
	unsigned char *ad;
	size_t adlen;
	unsigned char *out;
	size_t outlen;
	struct quic_tls_secret *secret;
	unsigned char nonce[QUIC_OPENSSL_COMPAT_TLS_IV_LEN];

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);

	ad = res;
	adlen = quic_tls_compat_create_header(qc, rec, ad, 0);

	out = res + adlen;
	outlen = rec->payload_len + EVP_GCM_TLS_TAG_LEN;

	secret = &rec->keys->secret;

	memcpy(nonce, secret->iv.data, secret->iv.len);
	quic_tls_compute_nonce(nonce, sizeof(nonce), rec->number);

	if (!quic_tls_tls_seal(qc, rec->keys->cipher, secret, out, &outlen,
	                       nonce, rec->payload, rec->payload_len, ad, adlen))
		goto leave;

	ret = outlen;
leave:
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return ret;
}

/* Callback use to parse TLS messages for <ssl> TLS session. */
void quic_tls_compat_msg_callback(struct connection *conn,
                                  int write_p, int version, int content_type,
                                  const void *buf, size_t len, SSL *ssl)
{
	unsigned int alert;
	enum ssl_encryption_level_t   level;
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	struct quic_openssl_compat *com;

	if (!write_p || !qc)
		goto leave;

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);

	com = &qc->openssl_compat;
	level = com->write_level;
	switch (content_type) {
	case SSL3_RT_HANDSHAKE:
		com->method->add_handshake_data(ssl, level, buf, len);
		break;
	case SSL3_RT_ALERT:
		if (len >= 2) {
			alert = ((unsigned char *) buf)[1];
			com->method->send_alert(ssl, level, alert);
		}
		break;
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
}

int SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *quic_method)
{
	int ret = 0;
	BIO *rbio, *wbio = NULL;
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);

	rbio = BIO_new(BIO_s_mem());
	if (!rbio)
		goto err;

	wbio = BIO_new(BIO_s_null());
	if (!wbio)
		goto err;

	SSL_set_bio(ssl, rbio, wbio);
	/* No ealy data support */
	SSL_set_max_early_data(ssl, 0);

	qc->openssl_compat.rbio = rbio;
	qc->openssl_compat.wbio = wbio;
	qc->openssl_compat.method = quic_method;
	qc->openssl_compat.read_level = ssl_encryption_initial;
	qc->openssl_compat.write_level = ssl_encryption_initial;
	ret = 1;

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return ret;
 err:
	BIO_free(rbio);
	BIO_free(wbio);
	goto leave;
}

enum ssl_encryption_level_t SSL_quic_read_level(const SSL *ssl)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return qc->openssl_compat.read_level;
}


enum ssl_encryption_level_t SSL_quic_write_level(const SSL *ssl)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return qc->openssl_compat.write_level;
}

int SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level,
                          const uint8_t *data, size_t len)
{
	int ret = 0;
	BIO *rbio;
	struct quic_tls_compat_record rec;
	unsigned char in[QUIC_OPENSSL_COMPAT_RECORD_SIZE + 1];
	unsigned char out[QUIC_OPENSSL_COMPAT_RECORD_SIZE + 1 +
		SSL3_RT_HEADER_LENGTH + EVP_GCM_TLS_TAG_LEN];
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	size_t n;

	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);

	rbio = SSL_get_rbio(ssl);

	while (len) {
		memset(&rec, 0, sizeof rec);
		rec.type = SSL3_RT_HANDSHAKE;
		rec.number = qc->openssl_compat.read_record++;
		rec.keys = &qc->openssl_compat.keys;
		if (level == ssl_encryption_initial) {
			n = QUIC_MIN(len, (size_t)65535);
			rec.payload = (unsigned char *)data;
			rec.payload_len = n;
			quic_tls_compat_create_header(qc, &rec, out, 1);
			BIO_write(rbio, out, SSL3_RT_HEADER_LENGTH);
			BIO_write(rbio, data, n);
		}
		else {
			size_t outlen;
			unsigned char *p = in;

			n = QUIC_MIN(len, (size_t)QUIC_OPENSSL_COMPAT_RECORD_SIZE);
			memcpy(in, data, n);
			p += n;
			*p++ = SSL3_RT_HANDSHAKE;

			rec.payload = in;
			rec.payload_len = p - in;

			if (!rec.keys->cipher)
				goto leave;

			outlen = quic_tls_compat_create_record(qc, level, &rec, out);
			if (!outlen)
				goto leave;

			BIO_write(rbio, out, outlen);
		}

		data += n;
		len -= n;
	}

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return ret;
}

int SSL_process_quic_post_handshake(SSL *ssl)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);

	/* Do nothing: rely on the TLS message callback to parse alert messages. */
	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return 1;
}

int SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params, size_t params_len)
{
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
	/* The local transport parameters are stored into the quic_conn object.
	 * There is no need to add an intermediary to store pointers to these
	 * transport paraemters.
	 */
	TRACE_ENTER(QUIC_EV_CONN_SSL_COMPAT, qc);
	TRACE_LEAVE(QUIC_EV_CONN_SSL_COMPAT, qc);
	return 1;
}

