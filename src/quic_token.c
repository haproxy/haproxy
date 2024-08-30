#include <haproxy/tools.h>
#include <haproxy/net_helper.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_token.h>

#define TRACE_SOURCE &trace_quic

#define QUIC_TOKEN_RAND_DLEN 16

/* Build a token into <token> buffer with <len> as length and cipher
 * it with AEAD as cryptographic algorithm. <addr> are use as AAD.
 * Return 1 if succeeded, 0 if not.
 */
int quic_generate_token(unsigned char *token, size_t len,
                        struct sockaddr_storage *addr)
{
#ifdef QUIC_AEAD_API
	const QUIC_AEAD *aead = EVP_aead_aes_128_gcm();
#else
	const QUIC_AEAD *aead = EVP_aes_128_gcm();
#endif
	int ret = 0;
	unsigned char *p;
	unsigned char aad[sizeof(struct in6_addr)];
	size_t aadlen;
	uint32_t ts = (uint32_t)date.tv_sec;
	uint64_t rand_u64;
	unsigned char rand[QUIC_TOKEN_RAND_DLEN];
	unsigned char key[16];
	unsigned char iv[QUIC_TLS_IV_LEN];
	const unsigned char *sec = global.cluster_secret;
	size_t seclen = sizeof(global.cluster_secret);
	QUIC_AEAD_CTX *ctx = NULL;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT);

	/* Generate random data to be used as salt to derive the token secret. */
	rand_u64 = ha_random64();
	write_u64(rand, rand_u64);
	rand_u64 = ha_random64();
	write_u64(rand + sizeof(rand_u64), rand_u64);

	if (len < QUIC_TOKEN_LEN) {
		TRACE_ERROR("too small buffer", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	/* Generate the AAD. */
	aadlen = ipaddrcpy(aad, addr);
	if (!quic_tls_derive_token_secret(EVP_sha256(), key, sizeof key,
	                                  iv, sizeof iv, rand, sizeof(rand),
	                                  sec, seclen)) {
		TRACE_ERROR("quic_tls_derive_token_secret() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	if (!quic_tls_tx_ctx_init(&ctx, aead, key)) {
		TRACE_ERROR("quic_tls_tx_ctx_init() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	/* Clear token build */
	p = token;
	*p++ = QUIC_TOKEN_FMT_NEW;
	write_u32(p, htonl(ts));
	p += sizeof(ts);

	if (!quic_tls_encrypt(token + 1, p - token - 1, aad, aadlen, ctx, aead, iv)) {
		TRACE_ERROR("quic_tls_encrypt() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}

	p += QUIC_TLS_TAG_LEN;
	memcpy(p, rand, sizeof(rand));
	p += sizeof(rand);

	ret = p - token;
 leave:
	if (ctx)
		QUIC_AEAD_CTX_free(ctx);
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT);
	return ret;

 err:
	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_TXPKT);
	goto leave;
}

/* QUIC server only function.
 *
 * Check the validity of the token from Initial packet <pkt>. <dgram> is
 * the UDP datagram containing <pkt> and <l> is the listener instance on which
 * it was received. <qc> is used only for debugging purposes (traces).
 *
 * Return 1 if succeeded, 0 if not.
 */
int quic_token_check(struct quic_rx_packet *pkt,
                     struct quic_dgram *dgram,
                     struct quic_conn *qc)
{
	int ret = 0;
	unsigned char *token = pkt->token;
	size_t tokenlen = pkt->token_len;
	const unsigned char *rand;
	unsigned char buf[128];
	unsigned char aad[sizeof(struct in6_addr)];
	size_t aadlen;
	unsigned char key[16];
	unsigned char iv[QUIC_TLS_IV_LEN];
	const unsigned char *sec = global.cluster_secret;
	size_t seclen = sizeof(global.cluster_secret);
	uint32_t ts;
	uint32_t now_sec = (uint32_t)date.tv_sec;

	QUIC_AEAD_CTX *ctx = NULL;

#ifdef QUIC_AEAD_API
	const QUIC_AEAD *aead = EVP_aead_aes_128_gcm();
#else
	const QUIC_AEAD *aead = EVP_aes_128_gcm();
#endif

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	BUG_ON(!tokenlen || *token != QUIC_TOKEN_FMT_NEW);

	if (sizeof(buf) < tokenlen) {
		TRACE_ERROR("too short buffer", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	/* Generate the AAD. */
	aadlen = ipaddrcpy(aad, &dgram->saddr);
	rand = token + tokenlen - QUIC_TOKEN_RAND_DLEN;
	if (!quic_tls_derive_token_secret(EVP_sha256(), key, sizeof key, iv, sizeof iv,
	                                  rand, QUIC_TOKEN_RAND_DLEN, sec, seclen)) {
		TRACE_ERROR("Could not derive token secret", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	if (!quic_tls_rx_ctx_init(&ctx, aead, key)) {
		TRACE_ERROR("quic_tls_rx_ctx_init() failed", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	/* The token is prefixed by a one-byte length format which is not ciphered. */
	if (!quic_tls_decrypt2(buf, token + 1, tokenlen - QUIC_TOKEN_RAND_DLEN - 1, aad, aadlen,
	                       ctx, aead, key, iv)) {
		TRACE_ERROR("Could not decrypt token", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	ts = ntohl(read_u32(buf));
	if (now_sec - ts > QUIC_TOKEN_DURATION_SEC) {
		TRACE_ERROR("expired token", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	ret = 1;
 leave:
	if (ctx)
		QUIC_AEAD_CTX_free(ctx);
	TRACE_LEAVE(QUIC_EV_CONN_LPKT);
	return ret;

 err:
	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_LPKT);
	goto leave;
}

