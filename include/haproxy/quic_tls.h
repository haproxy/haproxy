/*
 * include/proto/quic_tls.h
 * This file provides definitions for QUIC-TLS.
 *
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#include <stdlib.h>
#include <string.h>

#include <haproxy/dynbuf.h>
#include <haproxy/pool.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_tls-t.h>
#include <haproxy/quic_tx.h>
#include <haproxy/quic_trace.h>
#include <haproxy/trace.h>

int quic_tls_finalize(struct quic_conn *qc, int server);
void quic_tls_ctx_free(struct quic_tls_ctx **ctx);
void quic_pktns_release(struct quic_conn *qc, struct quic_pktns **pktns);
int qc_enc_level_alloc(struct quic_conn *qc, struct quic_pktns **pktns,
                       struct quic_enc_level **qel, enum ssl_encryption_level_t level);
void qc_enc_level_free(struct quic_conn *qc, struct quic_enc_level **qel);

void quic_tls_keys_hexdump(struct buffer *buf,
                           const struct quic_tls_secrets *secs);
void quic_tls_kp_keys_hexdump(struct buffer *buf,
                              const struct quic_tls_kp *kp);

void quic_conn_enc_level_uninit(struct quic_conn *qc, struct quic_enc_level *qel);
void quic_tls_secret_hexdump(struct buffer *buf,
                             const unsigned char *secret, size_t secret_len);

int quic_derive_initial_secret(const EVP_MD *md,
                               const unsigned char *initial_salt, size_t initial_salt_sz,
                               unsigned char *initial_secret, size_t initial_secret_sz,
                               const unsigned char *secret, size_t secret_sz);

int quic_tls_derive_initial_secrets(const EVP_MD *md,
                                    unsigned char *rx, size_t rx_sz,
                                    unsigned char *tx, size_t tx_sz,
                                    const unsigned char *secret, size_t secret_sz,
                                    int server);

int quic_tls_encrypt(unsigned char *buf, size_t len,
                     const unsigned char *aad, size_t aad_len,
                     QUIC_AEAD_CTX *ctx, const QUIC_AEAD *aead,
                     const unsigned char *iv);

int quic_tls_decrypt2(unsigned char *out,
                      unsigned char *in, size_t ilen,
                      unsigned char *aad, size_t aad_len,
                      QUIC_AEAD_CTX *ctx, const QUIC_AEAD *aead,
                      const unsigned char *key, const unsigned char *iv);

int quic_tls_decrypt(unsigned char *buf, size_t len,
                     unsigned char *aad, size_t aad_len,
                     QUIC_AEAD_CTX *tls_ctx, const QUIC_AEAD *aead,
                     const unsigned char *key, const unsigned char *iv);

int quic_tls_generate_retry_integrity_tag(unsigned char *odcid, unsigned char odcid_len,
                                          unsigned char *buf, size_t len,
                                          const struct quic_version *qv);

int quic_tls_derive_keys(const QUIC_AEAD *aead, const EVP_CIPHER *hp,
                         const EVP_MD *md, const struct quic_version *qv,
                         unsigned char *key, size_t keylen,
                         unsigned char *iv, size_t ivlen,
                         unsigned char *hp_key, size_t hp_keylen,
                         const unsigned char *secret, size_t secretlen);

int quic_tls_derive_retry_token_secret(const EVP_MD *md,
                                       unsigned char *key, size_t keylen,
                                       unsigned char *iv, size_t ivlen,
                                       const unsigned char *salt, size_t saltlen,
                                       const unsigned char *secret, size_t secretlen);

int quic_tls_derive_token_secret(const EVP_MD *md,
                                 unsigned char *key, size_t keylen,
                                 unsigned char *iv, size_t ivlen,
                                 const unsigned char *salt, size_t saltlen,
                                 const unsigned char *secret, size_t secretlen);

int quic_hkdf_expand(const EVP_MD *md,
                     unsigned char *buf, size_t buflen,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *label, size_t labellen);

int quic_hkdf_expand_label(const EVP_MD *md,
                           unsigned char *buf, size_t buflen,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *label, size_t labellen);

int quic_hkdf_extract_and_expand(const EVP_MD *md,
                                 unsigned char *buf, size_t buflen,
                                 const unsigned char *key, size_t keylen,
                                 const unsigned char *salt, size_t saltlen,
                                 const unsigned char *label, size_t labellen);

int quic_tls_rx_ctx_init(QUIC_AEAD_CTX **rx_ctx,
                         const QUIC_AEAD *aead, unsigned char *key);
int quic_tls_tx_ctx_init(QUIC_AEAD_CTX **tx_ctx,
                         const QUIC_AEAD *aead, unsigned char *key);

int quic_tls_sec_update(const EVP_MD *md, const struct quic_version *qv,
                        unsigned char *new_sec, size_t new_seclen,
                        const unsigned char *sec, size_t seclen);

void quic_aead_iv_build(unsigned char *iv, size_t ivlen,
                        unsigned char *aead_iv, size_t aead_ivlen, uint64_t pn);

/* HP protection (AES) */
int quic_tls_dec_hp_ctx_init(EVP_CIPHER_CTX **aes_ctx,
                              const EVP_CIPHER *aes, unsigned char *key);
int quic_tls_enc_hp_ctx_init(EVP_CIPHER_CTX **aes_ctx,
                              const EVP_CIPHER *aes, unsigned char *key);
int quic_tls_hp_decrypt(unsigned char *out,
                         const unsigned char *in, size_t inlen,
                         EVP_CIPHER_CTX *ctx, unsigned char *key);
int quic_tls_hp_encrypt(unsigned char *out,
                         const unsigned char *in, size_t inlen,
                         EVP_CIPHER_CTX *ctx, unsigned char *key);

int quic_tls_key_update(struct quic_conn *qc);
void quic_tls_rotate_keys(struct quic_conn *qc);

static inline const QUIC_AEAD *tls_aead(const SSL_CIPHER *cipher)
{
	switch (SSL_CIPHER_get_id(cipher)) {
	case TLS1_3_CK_AES_128_GCM_SHA256:
#ifdef QUIC_AEAD_API
		return EVP_aead_aes_128_gcm();
#else
		return EVP_aes_128_gcm();
#endif

	case TLS1_3_CK_AES_256_GCM_SHA384:
#ifdef QUIC_AEAD_API
		return EVP_aead_aes_256_gcm();
#else
		return EVP_aes_256_gcm();
#endif

#if (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER >= 0x4000000fL)
	/* WT: LibreSSL has an issue with CHACHA20 running in-place till 3.9.2
	 *     included, but the fix is already identified and will be merged
	 *     into next major version. Given that on machines without AES-NI
	 *     CHACHA20 is selected by default, this makes connections freeze
	 *     on non-x86 machines, so we prefer to break them so that the
	 *     client falls back to TCP. See GH issue #2569 for the context.
	 *     Thanks to Theo Buehler for his help!
	 */
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
# ifdef QUIC_AEAD_API
		return EVP_aead_chacha20_poly1305();
# else
		return EVP_chacha20_poly1305();
# endif
#endif
#if !defined(USE_OPENSSL_WOLFSSL) && !defined(OPENSSL_IS_AWSLC)
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
	case TLS1_3_CK_AES_128_CCM_SHA256:
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
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
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
#ifdef QUIC_AEAD_API
		return EVP_CIPHER_CHACHA20;
#else
		return EVP_chacha20();
#endif
	case TLS1_3_CK_AES_128_CCM_SHA256:
	case TLS1_3_CK_AES_128_GCM_SHA256:
		return EVP_aes_128_ctr();
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return EVP_aes_256_ctr();
	default:
		return NULL;
	}

}

/* These following functions map TLS implementation encryption level to ours */
static inline struct quic_pktns **ssl_to_quic_pktns(struct quic_conn *qc,
                                                    enum ssl_encryption_level_t level)
{
	switch (level) {
	case ssl_encryption_initial:
		return &qc->ipktns;
	case ssl_encryption_early_data:
		return &qc->apktns;
	case ssl_encryption_handshake:
		return &qc->hpktns;
	case ssl_encryption_application:
		return &qc->apktns;
	default:
		return NULL;
	}
}

/* These following functions map TLS implementation encryption level to ours */
static inline struct quic_pktns **qel_to_quic_pktns(struct quic_conn *qc,
                                                    enum quic_tls_enc_level level)
{
	switch (level) {
	case QUIC_TLS_ENC_LEVEL_INITIAL:
		return &qc->ipktns;
	case QUIC_TLS_ENC_LEVEL_EARLY_DATA:
		return &qc->apktns;
	case QUIC_TLS_ENC_LEVEL_HANDSHAKE:
		return &qc->hpktns;
	case QUIC_TLS_ENC_LEVEL_APP:
		return &qc->apktns;
	default:
		return NULL;
	}
}

/* Map <level> TLS stack encryption level to our internal QUIC TLS encryption level
 * if succeeded, or -1 if failed.
 */
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

/* Return the address of the QUIC TLS encryption level associated to <level> TLS
 * stack encryption level and attached to <qc> QUIC connection if succeeded, or
 * NULL if failed.
 */
static inline struct quic_enc_level **ssl_to_qel_addr(struct quic_conn *qc,
                                                      enum ssl_encryption_level_t level)
{
	switch (level) {
	case ssl_encryption_initial:
		return &qc->iel;
	case ssl_encryption_early_data:
		return &qc->eel;
	case ssl_encryption_handshake:
		return &qc->hel;
	case ssl_encryption_application:
		return &qc->ael;
	default:
		return NULL;
	}
}

/* Return the address of the QUIC TLS encryption level associated to <level> internal
 * encryption level and attached to <qc> QUIC connection if succeeded, or
 * NULL if failed.
 */
static inline struct quic_enc_level **qel_to_qel_addr(struct quic_conn *qc,
                                                      enum quic_tls_enc_level level)
{
	switch (level) {
	case QUIC_TLS_ENC_LEVEL_INITIAL:
		return &qc->iel;
	case QUIC_TLS_ENC_LEVEL_EARLY_DATA:
		return &qc->eel;
	case QUIC_TLS_ENC_LEVEL_HANDSHAKE:
		return &qc->hel;
	case QUIC_TLS_ENC_LEVEL_APP:
		return &qc->ael;
	default:
		return NULL;
	}
}

/* Return the QUIC TLS encryption level associated to <level> internal encryption
 * level attached to <qc> QUIC connection if succeeded, or NULL if failed.
 */
static inline struct quic_enc_level *qc_quic_enc_level(const struct quic_conn *qc,
                                                       enum quic_tls_enc_level level)
{
	switch (level) {
	case QUIC_TLS_ENC_LEVEL_INITIAL:
		return qc->iel;
	case QUIC_TLS_ENC_LEVEL_EARLY_DATA:
		return qc->eel;
	case QUIC_TLS_ENC_LEVEL_HANDSHAKE:
		return qc->hel;
	case QUIC_TLS_ENC_LEVEL_APP:
		return qc->ael;
	default:
		return NULL;
	}
}

/* These two following functions map our encryption level to the TLS implementation ones. */
static inline enum ssl_encryption_level_t quic_to_ssl_enc_level(enum quic_tls_enc_level level)
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
		return "HCP";
	case QUIC_HS_ST_CONFIRMED:
		return "HCF";
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
#if !defined(LIBRESSL_VERSION_NUMBER) && !defined(USE_OPENSSL_WOLFSSL) && !defined(OPENSSL_IS_AWSLC)
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
	if (qel == qc->iel)
		return 'I';
	else if (qel == qc->eel)
		return 'E';
	else if (qel == qc->hel)
		return 'H';
	else if (qel == qc->ael)
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

/* Initialize a QUIC packet number space.
 * Never fails.
 */
static inline int quic_pktns_init(struct quic_conn *qc, struct quic_pktns **p)
{
	struct quic_pktns *pktns;

	pktns = pool_alloc(pool_head_quic_pktns);
	if (!pktns)
		return 0;

	LIST_INIT(&pktns->tx.frms);
	pktns->tx.next_pn = -1;
	pktns->tx.pkts = EB_ROOT_UNIQUE;
	pktns->tx.time_of_last_eliciting = 0;
	pktns->tx.loss_time = TICK_ETERNITY;
	pktns->tx.pto_probe = 0;
	pktns->tx.in_flight = 0;
	pktns->tx.ack_delay = 0;

	pktns->rx.largest_pn = -1;
	pktns->rx.largest_acked_pn = -1;
	pktns->rx.arngs.root = EB_ROOT_UNIQUE;
	pktns->rx.arngs.sz = 0;
	pktns->rx.arngs.enc_sz = 0;
	pktns->rx.nb_aepkts_since_last_ack = 0;
	pktns->rx.largest_time_received = 0;

	pktns->flags = 0;
	if (p == &qc->hpktns && qc->apktns)
		LIST_INSERT(&qc->ipktns->list, &pktns->list);
	else
		LIST_APPEND(&qc->pktns_list, &pktns->list);
	*p = pktns;

	return 1;
}

static inline void quic_pktns_tx_pkts_release(struct quic_pktns *pktns, struct quic_conn *qc)
{
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);

	node = eb64_first(&pktns->tx.pkts);
	while (node) {
		struct quic_tx_packet *pkt;
		struct quic_frame *frm, *frmbak;

		pkt = eb64_entry(node, struct quic_tx_packet, pn_node);
		node = eb64_next(node);
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->ifae_pkts--;
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list) {
			TRACE_DEVEL("freeing frame from packet",
			            QUIC_EV_CONN_PRSAFRM, qc, frm, &pkt->pn_node.key);
			qc_frm_unref(frm, qc);
			LIST_DEL_INIT(&frm->list);
			quic_tx_packet_refdec(frm->pkt);
			qc_frm_free(qc, &frm);
		}
		eb64_delete(&pkt->pn_node);
		quic_tx_packet_refdec(pkt);
	}

	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
}

/* Discard <pktns> packet number space attached to <qc> QUIC connection.
 * Its loss information are reset. Deduce the outstanding bytes for this
 * packet number space from the outstanding bytes for the path of this
 * connection.
 * Note that all the non acknowledged TX packets and their frames are freed.
 * Always succeeds.
 */
static inline void quic_pktns_discard(struct quic_pktns *pktns,
                                      struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);

	if (pktns == qc->ipktns)
		qc->flags |= QUIC_FL_CONN_IPKTNS_DCD;
	else if (pktns == qc->hpktns)
		qc->flags |= QUIC_FL_CONN_HPKTNS_DCD;
	qc->path->in_flight -= pktns->tx.in_flight;
	qc->path->prep_in_flight -= pktns->tx.in_flight;
	qc->path->loss.pto_count = 0;

	pktns->tx.time_of_last_eliciting = 0;
	pktns->tx.loss_time = TICK_ETERNITY;
	pktns->tx.pto_probe = 0;
	pktns->tx.in_flight = 0;
	quic_pktns_tx_pkts_release(pktns, qc);

	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
}


/* Release all the frames attached to <pktns> packet number space */
static inline void qc_release_pktns_frms(struct quic_conn *qc,
                                         struct quic_pktns *pktns)
{
	struct quic_frame *frm, *frmbak;

	TRACE_ENTER(QUIC_EV_CONN_PHPKTS, qc);

	if (!pktns)
		goto leave;

	list_for_each_entry_safe(frm, frmbak, &pktns->tx.frms, list)
		qc_frm_free(qc, &frm);

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PHPKTS, qc);
}

/* Return 1 if <pktns> matches with the Application packet number space of
 * <conn> connection which is common to the 0-RTT and 1-RTT encryption levels, 0
 * if not (handshake packets).
 */
static inline int quic_application_pktns(struct quic_pktns *pktns, struct quic_conn *qc)
{
	return pktns == qc->apktns;
}

/* Returns the current largest acknowledged packet number if exists, -1 if not */
static inline int64_t quic_pktns_get_largest_acked_pn(struct quic_pktns *pktns)
{
	struct eb64_node *ar = eb64_last(&pktns->rx.arngs.root);

	if (!ar)
		return -1;

	return eb64_entry(ar, struct quic_arng_node, first)->last;
}

/* Return a character to identify the packet number space <pktns> of <qc> QUIC
 * connection. 'I' for Initial packet number space, 'H' for Handshake packet
 * space, and 'A' for Application data number space, or '-' if not found.
 */
static inline char quic_pktns_char(const struct quic_conn *qc,
                                   const struct quic_pktns *pktns)
{
	if (pktns == qc->apktns)
		return 'A';
	else if (pktns == qc->hpktns)
		return 'H';
	else if (pktns == qc->ipktns)
		return 'I';

	return '-';
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

/* Return 1 if <pktns> packet number space attached to <qc> connection has been discarded,
 * 0 if not.
 */
static inline int quic_tls_pktns_is_dcd(struct quic_conn *qc, struct quic_pktns *pktns)
{
	if (pktns == qc->apktns)
		return 0;

	if ((pktns == qc->ipktns && (qc->flags & QUIC_FL_CONN_IPKTNS_DCD)) ||
	    (pktns == qc->hpktns && (qc->flags & QUIC_FL_CONN_HPKTNS_DCD)))
		return 1;

	return 0;
}

/* Return 1 the packet number space attached to <qc> connection with <type> associated
 * packet type has been discarded, 0 if not.
 */
static inline int quic_tls_pkt_type_pktns_dcd(struct quic_conn *qc, unsigned char type)
{
	if ((type == QUIC_PACKET_TYPE_INITIAL && (qc->flags & QUIC_FL_CONN_IPKTNS_DCD)) ||
	    (type == QUIC_PACKET_TYPE_HANDSHAKE && (qc->flags & QUIC_FL_CONN_HPKTNS_DCD)))
		return 1;

	return 0;
}

/* Select the correct TLS cipher context to used to decipher an RX packet
 * with <type> as type and <version> as version and attached to <qc>
 * connection from <qel> encryption level.
 */
static inline struct quic_tls_ctx *qc_select_tls_ctx(struct quic_conn *qc,
                                                     struct quic_enc_level *qel,
                                                     unsigned char type,
                                                     const struct quic_version *version)
{
	return type != QUIC_PACKET_TYPE_INITIAL ? &qel->tls_ctx :
		version == qc->negotiated_version ? qc->nictx : &qel->tls_ctx;
}

/* Reset all members of <ctx> to default values, ->hp_key[] excepted */
static inline void quic_tls_ctx_reset(struct quic_tls_ctx *ctx)
{
	ctx->rx.ctx = NULL;
	ctx->rx.aead = NULL;
	ctx->rx.md = NULL;
	ctx->rx.hp_ctx = NULL;
	ctx->rx.hp = NULL;
	ctx->rx.secret = NULL;
	ctx->rx.secretlen = 0;
	ctx->rx.iv = NULL;
	ctx->rx.ivlen = 0;
	ctx->rx.key = NULL;
	ctx->rx.keylen = 0;
	ctx->rx.pn = 0;

	ctx->tx.ctx = NULL;
	ctx->tx.aead = NULL;
	ctx->tx.md = NULL;
	ctx->tx.hp_ctx = NULL;
	ctx->tx.hp = NULL;
	ctx->tx.secret = NULL;
	ctx->tx.secretlen = 0;
	ctx->tx.iv = NULL;
	ctx->tx.ivlen = 0;
	ctx->tx.key = NULL;
	ctx->tx.keylen = 0;
	/* Not used on the TX path. */
	ctx->tx.pn = 0;

	ctx->flags = 0;
}

/* Erase and free the secrets for a QUIC encryption level with <ctx> as
 * context.
 * Always succeeds.
 */
static inline void quic_tls_ctx_secs_free(struct quic_tls_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->rx.iv) {
		memset(ctx->rx.iv, 0, ctx->rx.ivlen);
		ctx->rx.ivlen = 0;
	}
	if (ctx->rx.key) {
		memset(ctx->rx.key, 0, ctx->rx.keylen);
		ctx->rx.keylen = 0;
	}
	if (ctx->tx.iv) {
		memset(ctx->tx.iv, 0, ctx->tx.ivlen);
		ctx->tx.ivlen = 0;
	}
	if (ctx->tx.key) {
		memset(ctx->tx.key, 0, ctx->tx.keylen);
		ctx->tx.keylen = 0;
	}

	/* RX HP protection */
#ifdef QUIC_AEAD_API
	if (ctx->rx.hp_ctx != EVP_CIPHER_CTX_CHACHA20)
		EVP_CIPHER_CTX_free(ctx->rx.hp_ctx);
#else
	EVP_CIPHER_CTX_free(ctx->rx.hp_ctx);
#endif
	/* RX AEAD decryption */
	QUIC_AEAD_CTX_free(ctx->rx.ctx);
	pool_free(pool_head_quic_tls_iv,  ctx->rx.iv);
	pool_free(pool_head_quic_tls_key, ctx->rx.key);

	/* TX HP protection */
#ifdef QUIC_AEAD_API
	if (ctx->tx.hp_ctx != EVP_CIPHER_CTX_CHACHA20)
		EVP_CIPHER_CTX_free(ctx->tx.hp_ctx);
#else
	EVP_CIPHER_CTX_free(ctx->tx.hp_ctx);
#endif
	/* TX AEAD encryption */
	QUIC_AEAD_CTX_free(ctx->tx.ctx);
	pool_free(pool_head_quic_tls_iv,  ctx->tx.iv);
	pool_free(pool_head_quic_tls_key, ctx->tx.key);

	quic_tls_ctx_reset(ctx);
}

/* Allocate the secrete keys for a QUIC encryption level with <ctx> as context.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_tls_ctx_keys_alloc(struct quic_tls_ctx *ctx)
{
	if (ctx->rx.key)
		goto write;

	if (!(ctx->rx.iv = pool_alloc(pool_head_quic_tls_iv)) ||
	    !(ctx->rx.key = pool_alloc(pool_head_quic_tls_key)))
		goto err;

 write:
	if (ctx->tx.key)
		goto out;

	if (!(ctx->tx.iv = pool_alloc(pool_head_quic_tls_iv)) ||
	    !(ctx->tx.key = pool_alloc(pool_head_quic_tls_key)))
		goto err;

	ctx->rx.ivlen = ctx->tx.ivlen = QUIC_TLS_IV_LEN;
	ctx->rx.keylen = ctx->tx.keylen = QUIC_TLS_KEY_LEN;
out:
	return 1;

 err:
	quic_tls_ctx_secs_free(ctx);
	return 0;
}

/* Release the memory allocated for <secs> secrets */
static inline void quic_tls_secrets_keys_free(struct quic_tls_secrets *secs)
{
	if (secs->iv) {
		memset(secs->iv, 0, secs->ivlen);
		secs->ivlen = 0;
	}

	if (secs->key) {
		memset(secs->key, 0, secs->keylen);
		secs->keylen = 0;
	}

	/* HP protection */
	EVP_CIPHER_CTX_free(secs->hp_ctx);
	/* AEAD decryption */
	QUIC_AEAD_CTX_free(secs->ctx);
	pool_free(pool_head_quic_tls_iv,  secs->iv);
	pool_free(pool_head_quic_tls_key, secs->key);

	secs->iv = secs->key = NULL;
}

/* Allocate the memory for the <secs> secrets.
 * Return 1 if succeeded, 0 if not.
 */
static inline int quic_tls_secrets_keys_alloc(struct quic_tls_secrets *secs)
{
	if (!(secs->iv = pool_alloc(pool_head_quic_tls_iv)) ||
	    !(secs->key = pool_alloc(pool_head_quic_tls_key)))
		goto err;

	secs->ivlen = QUIC_TLS_IV_LEN;
	secs->keylen = QUIC_TLS_KEY_LEN;

	return 1;

 err:
	quic_tls_secrets_keys_free(secs);
	return 0;
}

/* Release the memory allocated for the negotiated Initial QUIC TLS context
 * attached to <qc> connection.
 */
static inline void quic_nictx_free(struct quic_conn *qc)
{
	quic_tls_ctx_secs_free(qc->nictx);
	pool_free(pool_head_quic_tls_ctx, qc->nictx);
	qc->nictx = NULL;
}

/* Initialize a TLS cryptographic context for the Initial encryption level. */
static inline int quic_initial_tls_ctx_init(struct quic_tls_ctx *ctx)
{
#ifdef QUIC_AEAD_API
	ctx->rx.aead = ctx->tx.aead = EVP_aead_aes_128_gcm();
#else
	ctx->rx.aead = ctx->tx.aead = EVP_aes_128_gcm();
#endif
	ctx->rx.md   = ctx->tx.md   = EVP_sha256();
	ctx->rx.hp   = ctx->tx.hp   = EVP_aes_128_ctr();

	ctx->rx.iv   = NULL;
	ctx->rx.ivlen = 0;
	ctx->rx.key  = NULL;
	ctx->rx.keylen = 0;
	ctx->rx.secret = NULL;
	ctx->rx.secretlen = 0;

	ctx->tx.iv   = NULL;
	ctx->tx.ivlen = 0;
	ctx->tx.key  = NULL;
	ctx->tx.keylen = 0;
	ctx->tx.secret = NULL;
	ctx->tx.secretlen = 0;

	return quic_tls_ctx_keys_alloc(ctx);
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
	case QUIC_TLS_ENC_LEVEL_APP:
		return QUIC_PACKET_TYPE_SHORT;
	default:
		return -1;
	}
}

/* Return the packet type associated to <qel> encryption for <qc> QUIC connection,
 * or -1 if not found.
 */
static inline enum quic_pkt_type quic_enc_level_pkt_type(struct quic_conn *qc,
                                                         struct quic_enc_level *qel)
{
	if (qel == qc->iel)
		return QUIC_PACKET_TYPE_INITIAL;
	else if (qel == qc->hel)
		return QUIC_PACKET_TYPE_HANDSHAKE;
	else if (qel == qc->eel)
		return QUIC_PACKET_TYPE_0RTT;
	else if (qel == qc->ael)
		return QUIC_PACKET_TYPE_SHORT;
	else
		return -1;
}

/* Derive the initial secrets with <ctx> as QUIC TLS context which is the
 * cryptographic context for the first encryption level (Initial) from
 * <cid> connection ID with <cidlen> as length (in bytes) for a server or not
 * depending on <server> boolean value.
 * Return 1 if succeeded or 0 if not.
 */
static inline int qc_new_isecs(struct quic_conn *qc,
                               struct quic_tls_ctx *ctx, const struct quic_version *ver,
                               const unsigned char *cid, size_t cidlen, int server)
{
	unsigned char initial_secret[32];
	/* Initial secret to be derived for incoming packets */
	unsigned char rx_init_sec[32];
	/* Initial secret to be derived for outgoing packets */
	unsigned char tx_init_sec[32];
	struct quic_tls_secrets *rx_ctx, *tx_ctx;

	TRACE_ENTER(QUIC_EV_CONN_ISEC);
	if (!quic_initial_tls_ctx_init(ctx))
		goto err;

	if (!quic_derive_initial_secret(ctx->rx.md,
	                                ver->initial_salt, ver->initial_salt_len,
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
	if (!quic_tls_derive_keys(ctx->rx.aead, ctx->rx.hp, ctx->rx.md, ver,
	                          rx_ctx->key, rx_ctx->keylen,
	                          rx_ctx->iv, rx_ctx->ivlen,
	                          rx_ctx->hp_key, sizeof rx_ctx->hp_key,
	                          rx_init_sec, sizeof rx_init_sec))
		goto err;

	if (!quic_tls_rx_ctx_init(&rx_ctx->ctx, rx_ctx->aead, rx_ctx->key))
		goto err;

	if (!quic_tls_enc_hp_ctx_init(&rx_ctx->hp_ctx, rx_ctx->hp, rx_ctx->hp_key))
		goto err;

	if (!quic_tls_derive_keys(ctx->tx.aead, ctx->tx.hp, ctx->tx.md, ver,
	                          tx_ctx->key, tx_ctx->keylen,
	                          tx_ctx->iv, tx_ctx->ivlen,
	                          tx_ctx->hp_key, sizeof tx_ctx->hp_key,
	                          tx_init_sec, sizeof tx_init_sec))
		goto err;

	if (!quic_tls_tx_ctx_init(&tx_ctx->ctx, tx_ctx->aead, tx_ctx->key))
		goto err;

	if (!quic_tls_enc_hp_ctx_init(&tx_ctx->hp_ctx, tx_ctx->hp, tx_ctx->hp_key))
		goto err;

	TRACE_LEAVE(QUIC_EV_CONN_ISEC, qc, rx_init_sec, tx_init_sec);

	return 1;

 err:
	TRACE_DEVEL("leaving in error", QUIC_EV_CONN_ISEC);
	return 0;
}

/* Reset all members of <tls_kp> to default values. */
static inline void quic_tls_ku_reset(struct quic_tls_kp *tls_kp)
{
	tls_kp->ctx = NULL;
	tls_kp->secret = NULL;
	tls_kp->iv = NULL;
	tls_kp->key = NULL;
}

/* Release the memory allocated for all the key update key phase
 * structures for <qc> QUIC connection.
 * Always succeeds.
 */
static inline void quic_tls_ku_free(struct quic_conn *qc)
{
	QUIC_AEAD_CTX_free(qc->ku.prv_rx.ctx);
	pool_free(pool_head_quic_tls_secret, qc->ku.prv_rx.secret);
	pool_free(pool_head_quic_tls_iv,     qc->ku.prv_rx.iv);
	pool_free(pool_head_quic_tls_key,    qc->ku.prv_rx.key);
	quic_tls_ku_reset(&qc->ku.prv_rx);
	QUIC_AEAD_CTX_free(qc->ku.nxt_rx.ctx);
	pool_free(pool_head_quic_tls_secret, qc->ku.nxt_rx.secret);
	pool_free(pool_head_quic_tls_iv,     qc->ku.nxt_rx.iv);
	pool_free(pool_head_quic_tls_key,    qc->ku.nxt_rx.key);
	quic_tls_ku_reset(&qc->ku.nxt_rx);
	QUIC_AEAD_CTX_free(qc->ku.nxt_tx.ctx);
	pool_free(pool_head_quic_tls_secret, qc->ku.nxt_tx.secret);
	pool_free(pool_head_quic_tls_iv,     qc->ku.nxt_tx.iv);
	pool_free(pool_head_quic_tls_key,    qc->ku.nxt_tx.key);
	quic_tls_ku_reset(&qc->ku.nxt_tx);
}

/* Initialize <kp> key update secrets, allocating the required memory.
 * Return 1 if all the secrets could be allocated, 0 if not.
 * This is the responsibility of the caller to release the memory
 * allocated by this function in case of failure.
 */
static inline int quic_tls_kp_init(struct quic_tls_kp *kp)
{
	kp->count = 0;
	kp->pn = 0;
	kp->flags = 0;
	kp->secret = pool_alloc(pool_head_quic_tls_secret);
	kp->secretlen = QUIC_TLS_SECRET_LEN;
	kp->iv = pool_alloc(pool_head_quic_tls_iv);
	kp->ivlen = QUIC_TLS_IV_LEN;
	kp->key = pool_alloc(pool_head_quic_tls_key);
	kp->keylen = QUIC_TLS_KEY_LEN;

	return kp->secret && kp->iv && kp->key;
}

/* Initialize all the key update key phase structures for <qc>
 * QUIC connection, allocating the required memory.
 *
 * Returns 1 if succeeded, 0 if not. The caller is responsible to use
 * quic_tls_ku_free() on error to cleanup partially allocated content.
 */
static inline int quic_tls_ku_init(struct quic_conn *qc)
{
	struct quic_tls_kp *prv_rx = &qc->ku.prv_rx;
	struct quic_tls_kp *nxt_rx = &qc->ku.nxt_rx;
	struct quic_tls_kp *nxt_tx = &qc->ku.nxt_tx;

	if (!quic_tls_kp_init(prv_rx) ||
	    !quic_tls_kp_init(nxt_rx) ||
	    !quic_tls_kp_init(nxt_tx))
		goto err;

	return 1;

 err:
	return 0;
}

/* Return 1 if <qel> has RX secrets, 0 if not. */
static inline int quic_tls_has_rx_sec(const struct quic_enc_level *qel)
{
	return qel && !!qel->tls_ctx.rx.key;
}

/* Return 1 if <qel> has TX secrets, 0 if not. */
static inline int quic_tls_has_tx_sec(const struct quic_enc_level *qel)
{
	return qel && !!qel->tls_ctx.tx.key;
}

/* Return 1 if there is RX packets for <qel> QUIC encryption level, 0 if not */
static inline int qc_el_rx_pkts(struct quic_enc_level *qel)
{
	int ret;

	ret = !eb_is_empty(&qel->rx.pkts);

	return ret;
}

/* Delete all RX packets for <qel> QUIC encryption level */
static inline void qc_el_rx_pkts_del(struct quic_enc_level *qel)
{
	struct eb64_node *node;

	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt =
			eb64_entry(node, struct quic_rx_packet, pn_node);

		node = eb64_next(node);
		eb64_delete(&pkt->pn_node);
		quic_rx_packet_refdec(pkt);
	}
}

static inline void qc_list_qel_rx_pkts(struct quic_enc_level *qel)
{
	struct eb64_node *node;

	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt;

		pkt = eb64_entry(node, struct quic_rx_packet, pn_node);
		fprintf(stderr, "pkt@%p type=%d pn=%llu\n",
		        pkt, pkt->type, (ull)pkt->pn_node.key);
		node = eb64_next(node);
	}
}

/* Returns a boolean if <qc> needs to emit frames for <qel> encryption level. */
static inline int qc_need_sending(struct quic_conn *qc, struct quic_enc_level *qel)
{
	return (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) ||
	       (qel->pktns->flags & QUIC_FL_PKTNS_ACK_REQUIRED) ||
	       qel->pktns->tx.pto_probe ||
	       !LIST_ISEMPTY(&qel->pktns->tx.frms);
}

/* Return 1 if <qc> connection may probe the Initial packet number space, 0 if not.
 * This is not the case if the remote peer address is not validated and if
 * it cannot send at least QUIC_INITIAL_PACKET_MINLEN bytes.
 */
static inline int qc_may_probe_ipktns(struct quic_conn *qc)
{
	return quic_peer_validated_addr(qc) ||
		quic_may_send_bytes(qc) >= QUIC_INITIAL_PACKET_MINLEN;
}



#endif /* USE_QUIC */
#endif /* _PROTO_QUIC_TLS_H */

