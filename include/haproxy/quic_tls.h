/*
 * include/proto/quic_tls.h
 * This file provides definitions for QUIC-TLS.
 *
 * Copyright 2019 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _PROTO_QUIC_TLS_H
#define _PROTO_QUIC_TLS_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#define TRACE_SOURCE &trace_quic

#include <stdlib.h>
#include <openssl/ssl.h>

#include <haproxy/dynbuf.h>
#include <haproxy/quic_tls-t.h>
#include <haproxy/trace.h>
#include <haproxy/xprt_quic.h>

void quic_tls_keys_hexdump(struct buffer *buf, struct quic_tls_secrets *secs);

void quic_tls_secret_hexdump(struct buffer *buf,
                             const unsigned char *secret, size_t secret_len);

int quic_derive_initial_secret(const EVP_MD *md,
                               unsigned char *initial_secret, size_t initial_secret_sz,
                               const unsigned char *secret, size_t secret_sz);

int quic_tls_derive_initial_secrets(const EVP_MD *md,
                                    unsigned char *rx, size_t rx_sz,
                                    unsigned char *tx, size_t tx_sz,
                                    const unsigned char *secret, size_t secret_sz,
                                    int server);

int quic_tls_encrypt(unsigned char *buf, size_t len,
                     const unsigned char *aad, size_t aad_len,
                     const EVP_CIPHER *aead,
                     const unsigned char *key, const unsigned char *iv);

int quic_tls_decrypt(unsigned char *buf, size_t len,
                     unsigned char *aad, size_t aad_len,
                     const EVP_CIPHER *aead,
                     const unsigned char *key, const unsigned char *iv);

int quic_tls_derive_keys(const EVP_CIPHER *aead, const EVP_CIPHER *hp,
                         const EVP_MD *md,
                         unsigned char *key, size_t keylen,
                         unsigned char *iv, size_t ivlen,
                         unsigned char *hp_key, size_t hp_keylen,
                         const unsigned char *secret, size_t secretlen);

int quic_aead_iv_build(unsigned char *iv, size_t ivlen,
                       unsigned char *aead_iv, size_t aead_ivlen, uint64_t pn);

static inline const EVP_CIPHER *tls_aead(const SSL_CIPHER *cipher)
{
	switch (SSL_CIPHER_get_id(cipher)) {
	case TLS1_3_CK_AES_128_GCM_SHA256:
		return EVP_aes_128_gcm();
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return EVP_aes_256_gcm();
#ifndef OPENSSL_IS_BORINGSSL
	/* XXX TO DO XXX */
    /* Note that for chacha20_poly1305, there exists EVP_AEAD_chacha20_poly135() function
     * which returns a pointer to const EVP_AEAD.
     */
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
		return EVP_chacha20_poly1305();
	case TLS1_3_CK_AES_128_CCM_SHA256:
		return EVP_aes_128_ccm();
#endif
	default:
		return NULL;
	}
}

static inline const EVP_MD *tls_md(const SSL_CIPHER *cipher)
{
	switch (SSL_CIPHER_get_id(cipher)) {
	case TLS1_3_CK_AES_128_GCM_SHA256:
#ifndef OPENSSL_IS_BORINGSSL
	/* XXX TO DO XXX */
    /* Note that for chacha20_poly1305, there exists EVP_AEAD_chacha20_poly135() function
     * which returns a pointer to const EVP_AEAD.
     */
	case TLS1_3_CK_AES_128_CCM_SHA256:
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
#endif
		return EVP_sha256();
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return EVP_sha384();
	default:
		return NULL;
	}
}

static inline const EVP_CIPHER *tls_hp(const SSL_CIPHER *cipher)
{
	switch (SSL_CIPHER_get_id(cipher)) {
#ifndef OPENSSL_IS_BORINGSSL
	/* XXX TO DO XXX */
    /* Note that for chacha20_poly1305, there exists EVP_AEAD_chacha20_poly135() function
     * which returns a pointer to const EVP_AEAD.
     */
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
		return EVP_chacha20();
	case TLS1_3_CK_AES_128_CCM_SHA256:
#endif
	case TLS1_3_CK_AES_128_GCM_SHA256:
		return EVP_aes_128_ctr();
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return EVP_aes_256_ctr();
	default:
		return NULL;
	}

}

/* These following functions map TLS implementation encryption level to ours */
static inline enum quic_tls_enc_level ssl_to_quic_enc_level(enum ssl_encryption_level_t level)
{
	switch (level) {
	case ssl_encryption_initial:
		return QUIC_TLS_ENC_LEVEL_INITIAL;
	case ssl_encryption_early_data:
		return QUIC_TLS_ENC_LEVEL_EARLY_DATA;
	case ssl_encryption_handshake:
		return QUIC_TLS_ENC_LEVEL_HANDSHAKE;
	case ssl_encryption_application:
		return QUIC_TLS_ENC_LEVEL_APP;
	default:
		return -1;
	}
}

/* These two following functions map our encryption level to the TLS implementation ones. */
static inline enum quic_tls_enc_level quic_to_ssl_enc_level(enum quic_tls_enc_level level)
{
	switch (level) {
	case QUIC_TLS_ENC_LEVEL_INITIAL:
		return ssl_encryption_initial;
	case QUIC_TLS_ENC_LEVEL_EARLY_DATA:
		return ssl_encryption_early_data;
	case QUIC_TLS_ENC_LEVEL_HANDSHAKE:
		return ssl_encryption_handshake;
	case QUIC_TLS_ENC_LEVEL_APP:
		return ssl_encryption_application;
	default:
		return -1;
	}
}

/* Return a human readable string from <state> QUIC handshake state of NULL
 * for unknown state values (for debug purpose).
 */
static inline char *quic_hdshk_state_str(const enum quic_handshake_state state)
{
	switch (state) {
	case QUIC_HS_ST_CLIENT_INITIAL:
		return "CI";
	case QUIC_HS_ST_CLIENT_HANDSHAKE:
		return "CH";
	case QUIC_HS_ST_CLIENT_HANDSHAKE_FAILED:
		return "CF";
	case QUIC_HS_ST_SERVER_INITIAL:
		return "SI";
	case QUIC_HS_ST_SERVER_HANDSHAKE:
		return "SH";
	case QUIC_HS_ST_SERVER_HANDSHAKE_FAILED:
		return "SF";
	case QUIC_HS_ST_COMPLETE:
		return "CP";
	case QUIC_HS_ST_CONFIRMED:
		return "CF";
	}

	return NULL;
}

/* Return a human readable string from <err> SSL error (returned from
 * SSL_get_error())
 */
static inline const char *ssl_error_str(int err)
{
	switch (err) {
	case SSL_ERROR_NONE:
		return "NONE";
	case SSL_ERROR_SSL:
		return "SSL";
	case SSL_ERROR_WANT_READ:
		return "WANT_READ";
	case SSL_ERROR_WANT_WRITE:
		return "WANT_WRITE";
	case SSL_ERROR_WANT_X509_LOOKUP:
		return "X509_LOOKUP";
	case SSL_ERROR_SYSCALL:
		return "SYSCALL";
	case SSL_ERROR_ZERO_RETURN:
		return "ZERO_RETURN";
	case SSL_ERROR_WANT_CONNECT:
		return "WANT_CONNECT";
	case SSL_ERROR_WANT_ACCEPT:
		return "WANT_ACCEPT";
#ifndef OPENSSL_IS_BORINGSSL
	case SSL_ERROR_WANT_ASYNC:
		return "WANT_ASYNC";
	case SSL_ERROR_WANT_ASYNC_JOB:
		return "WANT_ASYNC_JOB";
	case SSL_ERROR_WANT_CLIENT_HELLO_CB:
		return "WANT_CLIENT_HELLO_CB";
#endif
	default:
		return "UNKNOWN";
	}
}


/* Return a character identifying the encryption level from <level> QUIC TLS
 * encryption level (for debug purpose).
 * Initial -> 'I', Early Data -> 'E', Handshake -> 'H', Application -> 'A' and
 * '-' if undefined.
 */
static inline char quic_enc_level_char(enum quic_tls_enc_level level)
{
	switch (level) {
	case QUIC_TLS_ENC_LEVEL_INITIAL:
		return 'I';
	case QUIC_TLS_ENC_LEVEL_EARLY_DATA:
		return 'E';
	case QUIC_TLS_ENC_LEVEL_HANDSHAKE:
		return 'H';
	case QUIC_TLS_ENC_LEVEL_APP:
		return 'A';
	default:
		return '-';
	}
}

/* Return a character identifying <qel> encryption level from <qc> QUIC connection
 * (for debug purpose).
 * Initial -> 'I', Early Data -> 'E', Handshake -> 'H', Application -> 'A' and
 * '-' if undefined.
 */
static inline char quic_enc_level_char_from_qel(const struct quic_enc_level *qel,
                                                const struct quic_conn *qc)
{
	if (qel == &qc->els[QUIC_TLS_ENC_LEVEL_INITIAL])
		return 'I';
	else if (qel == &qc->els[QUIC_TLS_ENC_LEVEL_EARLY_DATA])
		return 'E';
	else if (qel == &qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE])
		return 'H';
	else if (qel == &qc->els[QUIC_TLS_ENC_LEVEL_APP])
		return 'A';
	return '-';
}

/* Return a character identifying the encryption level of a packet depending on
 * its <type> type, and its <long_header> header length (for debug purpose).
 * Initial -> 'I', ORTT -> '0', Handshake -> 'H', Application -> 'A' and
 * '-' if undefined.
 */
static inline char quic_packet_type_enc_level_char(int packet_type)
{
	switch (packet_type) {
	case QUIC_PACKET_TYPE_INITIAL:
		return 'I';
	case QUIC_PACKET_TYPE_0RTT:
		return '0';
	case QUIC_PACKET_TYPE_HANDSHAKE:
		return 'H';
	case QUIC_PACKET_TYPE_SHORT:
		return 'A';
	default:
		return '-';
	}
}

/* Return the TLS encryption level to be used for <packet_type>
 * QUIC packet type.
 * Returns -1 if there is no TLS encryption level for <packet_type>
 * packet type.
 */
static inline enum quic_tls_enc_level quic_packet_type_enc_level(enum quic_pkt_type packet_type)
{
	switch (packet_type) {
	case QUIC_PACKET_TYPE_INITIAL:
		return QUIC_TLS_ENC_LEVEL_INITIAL;
	case QUIC_PACKET_TYPE_0RTT:
		return QUIC_TLS_ENC_LEVEL_EARLY_DATA;
	case QUIC_PACKET_TYPE_HANDSHAKE:
		return QUIC_TLS_ENC_LEVEL_HANDSHAKE;
	case QUIC_PACKET_TYPE_RETRY:
		return QUIC_TLS_ENC_LEVEL_NONE;
	case QUIC_PACKET_TYPE_SHORT:
		return QUIC_TLS_ENC_LEVEL_APP;
	default:
		return QUIC_TLS_ENC_LEVEL_NONE;
	}
}

static inline enum quic_tls_pktns quic_tls_pktns(enum quic_tls_enc_level level)
{
	switch (level) {
	case QUIC_TLS_ENC_LEVEL_INITIAL:
		return QUIC_TLS_PKTNS_INITIAL;
	case QUIC_TLS_ENC_LEVEL_EARLY_DATA:
	case QUIC_TLS_ENC_LEVEL_APP:
		return QUIC_TLS_PKTNS_01RTT;
	case QUIC_TLS_ENC_LEVEL_HANDSHAKE:
		return QUIC_TLS_PKTNS_HANDSHAKE;
	default:
		return -1;
	}
}

/* Initialize a TLS cryptographic context for the Initial encryption level. */
static inline void quic_initial_tls_ctx_init(struct quic_tls_ctx *ctx)
{
	ctx->rx.aead = ctx->tx.aead = EVP_aes_128_gcm();
	ctx->rx.md   = ctx->tx.md   = EVP_sha256();
	ctx->rx.hp   = ctx->tx.hp   = EVP_aes_128_ctr();
}

static inline int quic_tls_level_pkt_type(enum quic_tls_enc_level level)
{
	switch (level) {
	case QUIC_TLS_ENC_LEVEL_INITIAL:
		return QUIC_PACKET_TYPE_INITIAL;
	case QUIC_TLS_ENC_LEVEL_EARLY_DATA:
		return QUIC_PACKET_TYPE_0RTT;
	case QUIC_TLS_ENC_LEVEL_HANDSHAKE:
		return QUIC_PACKET_TYPE_HANDSHAKE;
	default:
		return -1;
	}
}

/* Set <*level> and <*next_level> depending on <state> QUIC handshake state. */
static inline int quic_get_tls_enc_levels(enum quic_tls_enc_level *level,
                                          enum quic_tls_enc_level *next_level,
                                          enum quic_handshake_state state)
{
	switch (state) {
	case QUIC_HS_ST_SERVER_INITIAL:
	case QUIC_HS_ST_CLIENT_INITIAL:
		*level = QUIC_TLS_ENC_LEVEL_INITIAL;
		*next_level = QUIC_TLS_ENC_LEVEL_HANDSHAKE;
		break;
	case QUIC_HS_ST_SERVER_HANDSHAKE:
	case QUIC_HS_ST_CLIENT_HANDSHAKE:
	case QUIC_HS_ST_COMPLETE:
	case QUIC_HS_ST_CONFIRMED:
		*level = QUIC_TLS_ENC_LEVEL_HANDSHAKE;
		*next_level = QUIC_TLS_ENC_LEVEL_APP;
		break;
	default:
		return 0;
	}

	return 1;
}

/* Flag the keys at <qel> encryption level as discarded. */
static inline void quic_tls_discard_keys(struct quic_enc_level *qel)
{
	qel->tls_ctx.rx.flags |= QUIC_FL_TLS_SECRETS_DCD;
	qel->tls_ctx.tx.flags |= QUIC_FL_TLS_SECRETS_DCD;
}

/* Derive the initial secrets with <ctx> as QUIC TLS context which is the
 * cryptographic context for the first encryption level (Initial) from
 * <cid> connection ID with <cidlen> as length (in bytes) for a server or not
 * depending on <server> boolean value.
 * Return 1 if succeeded or 0 if not.
 */
static inline int qc_new_isecs(struct connection *conn,
                               const unsigned char *cid, size_t cidlen, int server)
{
	unsigned char initial_secret[32];
	/* Initial secret to be derived for incoming packets */
	unsigned char rx_init_sec[32];
	/* Initial secret to be derived for outgoing packets */
	unsigned char tx_init_sec[32];
	struct quic_tls_secrets *rx_ctx, *tx_ctx;
	struct quic_tls_ctx *ctx;

	TRACE_ENTER(QUIC_EV_CONN_ISEC, conn);
	ctx = &conn->qc->els[QUIC_TLS_ENC_LEVEL_INITIAL].tls_ctx;
	quic_initial_tls_ctx_init(ctx);
	if (!quic_derive_initial_secret(ctx->rx.md,
	                                initial_secret, sizeof initial_secret,
	                                cid, cidlen))
		goto err;

	if (!quic_tls_derive_initial_secrets(ctx->rx.md,
	                                     rx_init_sec, sizeof rx_init_sec,
	                                     tx_init_sec, sizeof tx_init_sec,
	                                     initial_secret, sizeof initial_secret, server))
		goto err;

	rx_ctx = &ctx->rx;
	tx_ctx = &ctx->tx;
	if (!quic_tls_derive_keys(ctx->rx.aead, ctx->rx.hp, ctx->rx.md,
	                          rx_ctx->key, sizeof rx_ctx->key,
	                          rx_ctx->iv, sizeof rx_ctx->iv,
	                          rx_ctx->hp_key, sizeof rx_ctx->hp_key,
	                          rx_init_sec, sizeof rx_init_sec))
		goto err;

	rx_ctx->flags |= QUIC_FL_TLS_SECRETS_SET;
	if (!quic_tls_derive_keys(ctx->tx.aead, ctx->tx.hp, ctx->tx.md,
	                          tx_ctx->key, sizeof tx_ctx->key,
	                          tx_ctx->iv, sizeof tx_ctx->iv,
	                          tx_ctx->hp_key, sizeof tx_ctx->hp_key,
	                          tx_init_sec, sizeof tx_init_sec))
		goto err;

	tx_ctx->flags |= QUIC_FL_TLS_SECRETS_SET;
	TRACE_LEAVE(QUIC_EV_CONN_ISEC, conn, rx_init_sec, tx_init_sec);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ISEC, conn);
	return 0;
}

#endif /* USE_QUIC */
#endif /* _PROTO_QUIC_TLS_H */

