#include <string.h>

#include <haproxy/clock.h>
#include <haproxy/global.h>
#include <haproxy/quic_retry.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_trace-t.h>
#include <haproxy/trace.h>

#define TRACE_SOURCE &trace_quic

/* Salt length used to derive retry token secret */
#define QUIC_RETRY_TOKEN_SALTLEN       16 /* bytes */

/* Copy <saddr> socket address data into <buf> buffer.
 * This is the responsibility of the caller to check the output buffer is big
 * enough to contain these socket address data.
 * Return the number of bytes copied.
 */
static inline size_t quic_saddr_cpy(unsigned char *buf,
                                    const struct sockaddr_storage *saddr)
{
	void *port, *addr;
	unsigned char *p;
	size_t port_len, addr_len;

	p = buf;
	if (saddr->ss_family == AF_INET6) {
		port = &((struct sockaddr_in6 *)saddr)->sin6_port;
		addr = &((struct sockaddr_in6 *)saddr)->sin6_addr;
		port_len = sizeof ((struct sockaddr_in6 *)saddr)->sin6_port;
		addr_len = sizeof ((struct sockaddr_in6 *)saddr)->sin6_addr;
	}
	else {
		port = &((struct sockaddr_in *)saddr)->sin_port;
		addr = &((struct sockaddr_in *)saddr)->sin_addr;
		port_len = sizeof ((struct sockaddr_in *)saddr)->sin_port;
		addr_len = sizeof ((struct sockaddr_in *)saddr)->sin_addr;
	}
	memcpy(p, port, port_len);
	p += port_len;
	memcpy(p, addr, addr_len);
	p += addr_len;

	return p - buf;
}


/* QUIC server only function.
 * Add AAD to <add> buffer from <cid> connection ID and <addr> socket address.
 * This is the responsibility of the caller to check <aad> size is big enough
 * to contain these data.
 * Return the number of bytes copied to <aad>.
 */
static int quic_generate_retry_token_aad(unsigned char *aad,
                                         uint32_t version,
                                         const struct quic_cid *cid,
                                         const struct sockaddr_storage *addr)
{
	unsigned char *p;

	p = aad;
	write_u32(p, htonl(version));
	p += sizeof version;
	p += quic_saddr_cpy(p, addr);
	memcpy(p, cid->data, cid->len);
	p += cid->len;

	return p - aad;
}

/* QUIC server only function.
 * Generate the token to be used in Retry packets. The token is written to
 * <token> with <len> as length. <odcid> is the original destination connection
 * ID and <dcid> is our side destination connection ID (or client source
 * connection ID).
 * Returns the length of the encoded token or 0 on error.
 */
int quic_generate_retry_token(unsigned char *token, size_t len,
                              const uint32_t version,
                              const struct quic_cid *odcid,
                              const struct quic_cid *dcid,
                              struct sockaddr_storage *addr)
{
	int ret = 0;
	unsigned char *p;
	unsigned char aad[sizeof(uint32_t) + sizeof(in_port_t) +
	                  sizeof(struct in6_addr) + QUIC_CID_MAXLEN];
	size_t aadlen;
	unsigned char salt[QUIC_RETRY_TOKEN_SALTLEN];
	unsigned char key[QUIC_TLS_KEY_LEN];
	unsigned char iv[QUIC_TLS_IV_LEN];
	const unsigned char *sec = global.cluster_secret;
	size_t seclen = sizeof global.cluster_secret;
	QUIC_AEAD_CTX *ctx = NULL;
#ifdef QUIC_AEAD_API
	const QUIC_AEAD *aead = EVP_aead_aes_128_gcm();
#else
	const QUIC_AEAD *aead = EVP_aes_128_gcm();
#endif
	uint32_t timestamp = (uint32_t)date.tv_sec;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT);

	/* The token is made of the token format byte, the ODCID prefixed by its one byte
	 * length, the creation timestamp, an AEAD TAG, and finally
	 * the random bytes used to derive the secret to encrypt the token.
	 */
	if (1 + odcid->len + 1 + sizeof(timestamp) + QUIC_TLS_TAG_LEN + QUIC_RETRY_TOKEN_SALTLEN > len)
		goto err;

	aadlen = quic_generate_retry_token_aad(aad, version, dcid, addr);
	/* TODO: RAND_bytes() should be replaced */
	if (RAND_bytes(salt, sizeof salt) != 1) {
		TRACE_ERROR("RAND_bytes()", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	if (!quic_tls_derive_retry_token_secret(EVP_sha256(), key, sizeof key, iv, sizeof iv,
	                                        salt, sizeof salt, sec, seclen)) {
		TRACE_ERROR("quic_tls_derive_retry_token_secret() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	if (!quic_tls_tx_ctx_init(&ctx, aead, key)) {
		TRACE_ERROR("quic_tls_tx_ctx_init() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	/* Token build */
	p = token;
	*p++ = QUIC_TOKEN_FMT_RETRY,
	*p++ = odcid->len;
	memcpy(p, odcid->data, odcid->len);
	p += odcid->len;
	write_u32(p, htonl(timestamp));
	p += sizeof timestamp;

	/* Do not encrypt the QUIC_TOKEN_FMT_RETRY byte */
	if (!quic_tls_encrypt(token + 1, p - token - 1, aad, aadlen, ctx, aead, iv)) {
		TRACE_ERROR("quic_tls_encrypt() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	p += QUIC_TLS_TAG_LEN;
	memcpy(p, salt, sizeof salt);
	p += sizeof salt;
	QUIC_AEAD_CTX_free(ctx);

	ret = p - token;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT);
	return ret;

 err:
	if (ctx)
		QUIC_AEAD_CTX_free(ctx);
	goto leave;
}

/* Parse the Retry token from buffer <token> with <end> a pointer to
 * one byte past the end of this buffer. This will extract the ODCID
 * which will be stored into <odcid>
 *
 * Returns 0 on success else non-zero.
 */
int parse_retry_token(struct quic_conn *qc,
                      const unsigned char *token, const unsigned char *end,
                      struct quic_cid *odcid)
{
	int ret = 0;
	uint64_t odcid_len;
	uint32_t timestamp;
	uint32_t now_sec = (uint32_t)date.tv_sec;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	if (!quic_dec_int(&odcid_len, &token, end)) {
		TRACE_ERROR("quic_dec_int() error", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	/* RFC 9000 7.2. Negotiating Connection IDs:
	 * When an Initial packet is sent by a client that has not previously
	 * received an Initial or Retry packet from the server, the client
	 * populates the Destination Connection ID field with an unpredictable
	 * value. This Destination Connection ID MUST be at least 8 bytes in length.
	 */
	if (odcid_len < QUIC_ODCID_MINLEN || odcid_len > QUIC_CID_MAXLEN) {
		TRACE_ERROR("wrong ODCID length", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	if (end - token < odcid_len + sizeof timestamp) {
		TRACE_ERROR("too long ODCID length", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	timestamp = ntohl(read_u32(token + odcid_len));
	/* check if elapsed time is +/- QUIC_RETRY_DURATION_SEC
	 * to tolerate token generator is not perfectly time synced
	 */
	if ((uint32_t)(now_sec - timestamp) > QUIC_RETRY_DURATION_SEC &&
            (uint32_t)(timestamp - now_sec) > QUIC_RETRY_DURATION_SEC) {
		TRACE_ERROR("token has expired", QUIC_EV_CONN_LPKT, qc);
		goto leave;
	}

	ret = 1;
	memcpy(odcid->data, token, odcid_len);
	odcid->len = odcid_len;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return !ret;
}

/* QUIC server only function.
 *
 * Check the validity of the Retry token from Initial packet <pkt>. <dgram> is
 * the UDP datagram containing <pkt> and <l> is the listener instance on which
 * it was received. If the token is valid, the ODCID of <qc> QUIC connection
 * will be put into <odcid>. <qc> is used to retrieve the QUIC version needed
 * to validate the token but it can be NULL : in this case the version will be
 * retrieved from the packet.
 *
 * Return 1 if succeeded, 0 if not.
 */

int quic_retry_token_check(struct quic_rx_packet *pkt,
                           struct quic_dgram *dgram,
                           struct listener *l,
                           struct quic_conn *qc,
                           struct quic_cid *odcid)
{
	struct proxy *prx;
	struct quic_counters *prx_counters;
	int ret = 0;
	unsigned char *token = pkt->token;
	const uint64_t tokenlen = pkt->token_len;
	unsigned char buf[128];
	unsigned char aad[sizeof(uint32_t) + QUIC_CID_MAXLEN +
	                  sizeof(in_port_t) + sizeof(struct in6_addr)];
	size_t aadlen;
	const unsigned char *salt;
	unsigned char key[QUIC_TLS_KEY_LEN];
	unsigned char iv[QUIC_TLS_IV_LEN];
	const unsigned char *sec = global.cluster_secret;
	size_t seclen = sizeof global.cluster_secret;
	QUIC_AEAD_CTX *ctx = NULL;
	const struct quic_version *qv = qc ? qc->original_version :
	                                     pkt->version;
#ifdef QUIC_AEAD_API
	const QUIC_AEAD *aead = EVP_aead_aes_128_gcm();
#else
	const QUIC_AEAD *aead = EVP_aes_128_gcm();
#endif

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	/* The caller must ensure this. */
	BUG_ON(!pkt->token_len || *pkt->token != QUIC_TOKEN_FMT_RETRY);

	prx = l->bind_conf->frontend;
	prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe, &quic_stats_module);

	if (sizeof buf < tokenlen) {
		TRACE_ERROR("too short buffer", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	/* The token is made of the token format byte, the ODCID prefixed by its one byte
	 * length, the creation timestamp, an AEAD TAG, and finally
	 * the random bytes used to derive the secret to encrypt the token.
	 */
	if (tokenlen < 2 + QUIC_ODCID_MINLEN + sizeof(uint32_t) + QUIC_TLS_TAG_LEN + QUIC_RETRY_TOKEN_SALTLEN ||
	    tokenlen > 2 + QUIC_CID_MAXLEN + sizeof(uint32_t) + QUIC_TLS_TAG_LEN + QUIC_RETRY_TOKEN_SALTLEN) {
		TRACE_ERROR("invalid token length", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	aadlen = quic_generate_retry_token_aad(aad, qv->num, &pkt->scid, &dgram->saddr);
	salt = token + tokenlen - QUIC_RETRY_TOKEN_SALTLEN;
	if (!quic_tls_derive_retry_token_secret(EVP_sha256(), key, sizeof key, iv, sizeof iv,
	                                        salt, QUIC_RETRY_TOKEN_SALTLEN, sec, seclen)) {
		TRACE_ERROR("Could not derive retry secret", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	if (!quic_tls_rx_ctx_init(&ctx, aead, key)) {
		TRACE_ERROR("quic_tls_rx_ctx_init() failed", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	/* The token is prefixed by a one-byte length format which is not ciphered. */
	if (!quic_tls_decrypt2(buf, token + 1, tokenlen - QUIC_RETRY_TOKEN_SALTLEN - 1, aad, aadlen,
	                       ctx, aead, key, iv)) {
		TRACE_ERROR("Could not decrypt retry token", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	if (parse_retry_token(qc, buf, buf + tokenlen - QUIC_RETRY_TOKEN_SALTLEN - 1, odcid)) {
		TRACE_ERROR("Error during Initial token parsing", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	QUIC_AEAD_CTX_free(ctx);

	ret = 1;
	HA_ATOMIC_INC(&prx_counters->retry_validated);

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return ret;

 err:
	HA_ATOMIC_INC(&prx_counters->retry_error);
	if (ctx)
		QUIC_AEAD_CTX_free(ctx);
	goto leave;
}


