#include <string.h>

#include <openssl/ssl.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/xprt_quic.h>


DECLARE_POOL(pool_head_quic_tls_secret, "quic_tls_secret", QUIC_TLS_SECRET_LEN);
DECLARE_POOL(pool_head_quic_tls_iv,     "quic_tls_iv",     QUIC_TLS_IV_LEN);
DECLARE_POOL(pool_head_quic_tls_key,    "quic_tls_key",    QUIC_TLS_KEY_LEN);

__attribute__((format (printf, 3, 4)))
void hexdump(const void *buf, size_t buflen, const char *title_fmt, ...);

/* Dump the RX/TX secrets of <secs> QUIC TLS secrets. */
void quic_tls_keys_hexdump(struct buffer *buf,
                           const struct quic_tls_secrets *secs)
{
	int i;
	size_t aead_keylen = (size_t)EVP_CIPHER_key_length(secs->aead);
	size_t aead_ivlen = (size_t)EVP_CIPHER_iv_length(secs->aead);
	size_t hp_len = (size_t)EVP_CIPHER_key_length(secs->hp);

	chunk_appendf(buf, "\n          key=");
	for (i = 0; i < aead_keylen; i++)
		chunk_appendf(buf, "%02x", secs->key[i]);
	chunk_appendf(buf, "\n          iv=");
	for (i = 0; i < aead_ivlen; i++)
		chunk_appendf(buf, "%02x", secs->iv[i]);
	chunk_appendf(buf, "\n          hp=");
	for (i = 0; i < hp_len; i++)
		chunk_appendf(buf, "%02x", secs->hp_key[i]);
}

/* Dump <secret> TLS secret. */
void quic_tls_secret_hexdump(struct buffer *buf,
                             const unsigned char *secret, size_t secret_len)
{
	int i;

	chunk_appendf(buf, " secret=");
	for (i = 0; i < secret_len; i++)
		chunk_appendf(buf, "%02x", secret[i]);
}

int quic_hkdf_extract(const EVP_MD *md,
                      unsigned char *buf, size_t buflen,
                      const unsigned char *key, size_t keylen,
                      const unsigned char *salt, size_t saltlen)
{
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx)
        return 0;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, saltlen) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, key, keylen) <= 0 ||
        EVP_PKEY_derive(ctx, buf, &buflen) <= 0)
        goto err;

    EVP_PKEY_CTX_free(ctx);
    return 1;

 err:
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int quic_hkdf_expand(const EVP_MD *md,
                     unsigned char *buf, size_t buflen,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *label, size_t labellen)
{
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx)
        return 0;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, key, keylen) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, label, labellen) <= 0 ||
        EVP_PKEY_derive(ctx, buf, &buflen) <= 0)
        goto err;

    EVP_PKEY_CTX_free(ctx);
    return 1;

 err:
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

/* Extracts a peudo-random secret key from <key> which is eventually not
 * pseudo-random and expand it to a new pseudo-random key into
 * <buf> with <buflen> as key length according to HKDF specifications
 * (https://datatracker.ietf.org/doc/html/rfc5869).
 * According to this specifications it is highly recommended to use
 * a salt, even if optional (NULL value).
 * Return 1 if succeeded, 0 if not.
 */
int quic_hkdf_extract_and_expand(const EVP_MD *md,
                                 unsigned char *buf, size_t buflen,
                                 const unsigned char *key, size_t keylen,
                                 const unsigned char *salt, size_t saltlen,
                                 const unsigned char *label, size_t labellen)
{
	EVP_PKEY_CTX *ctx;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx)
		return 0;

	if (EVP_PKEY_derive_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0 ||
	    EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0 ||
	    EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, saltlen) <= 0 ||
	    EVP_PKEY_CTX_set1_hkdf_key(ctx, key, keylen) <= 0 ||
	    EVP_PKEY_CTX_add1_hkdf_info(ctx, label, labellen) <= 0 ||
	    EVP_PKEY_derive(ctx, buf, &buflen) <= 0)
		goto err;

	EVP_PKEY_CTX_free(ctx);
	return 1;

 err:
	EVP_PKEY_CTX_free(ctx);
	return 0;
}

/* https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#protection-keys
 * refers to:
 *
 * https://tools.ietf.org/html/rfc8446#section-7.1:
 * 7.1.  Key Schedule
 *
 * The key derivation process makes use of the HKDF-Extract and
 * HKDF-Expand functions as defined for HKDF [RFC5869], as well as the
 * functions defined below:
 *
 *     HKDF-Expand-Label(Secret, Label, Context, Length) =
 *          HKDF-Expand(Secret, HkdfLabel, Length)
 *
 *     Where HkdfLabel is specified as:
 *
 *     struct {
 *         uint16 length = Length;
 *         opaque label<7..255> = "tls13 " + Label;
 *         opaque context<0..255> = Context;
 *     } HkdfLabel;
 *
 *     Derive-Secret(Secret, Label, Messages) =
 *          HKDF-Expand-Label(Secret, Label,
 *                            Transcript-Hash(Messages), Hash.length)
 *
 */
int quic_hkdf_expand_label(const EVP_MD *md,
                           unsigned char *buf, size_t buflen,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *label, size_t labellen)
{
	unsigned char hdkf_label[256], *pos;
	const unsigned char hdkf_label_label[] = "tls13 ";
	size_t hdkf_label_label_sz = sizeof hdkf_label_label - 1;

	pos = hdkf_label;
	*pos++ = buflen >> 8;
	*pos++ = buflen & 0xff;
	*pos++ = hdkf_label_label_sz + labellen;
	memcpy(pos, hdkf_label_label, hdkf_label_label_sz);
	pos += hdkf_label_label_sz;
	memcpy(pos, label, labellen);
	pos += labellen;
	*pos++ = '\0';

	return quic_hkdf_expand(md, buf, buflen,
	                        key, keylen, hdkf_label, pos - hdkf_label);
}

/*
 * This function derives two keys from <secret> is <ctx> as TLS cryptographic context.
 * ->key is the TLS key to be derived to encrypt/decrypt data at TLS level.
 * ->iv is the initialization vector to be used with ->key.
 * ->hp_key is the key to be derived for header protection.
 * Obviouly these keys have the same size becaused derived with the same TLS cryptographic context.
 */
int quic_tls_derive_keys(const EVP_CIPHER *aead, const EVP_CIPHER *hp,
                         const EVP_MD *md, const struct quic_version *qv,
                         unsigned char *key, size_t keylen,
                         unsigned char *iv, size_t ivlen,
                         unsigned char *hp_key, size_t hp_keylen,
                         const unsigned char *secret, size_t secretlen)
{
	size_t aead_keylen = (size_t)EVP_CIPHER_key_length(aead);
	size_t aead_ivlen = (size_t)EVP_CIPHER_iv_length(aead);
	size_t hp_len = hp ? (size_t)EVP_CIPHER_key_length(hp) : 0;

	if (aead_keylen > keylen || aead_ivlen > ivlen || hp_len > hp_keylen)
		return 0;

	if (!quic_hkdf_expand_label(md, key, aead_keylen, secret, secretlen,
	                            qv->key_label,qv->key_label_len) ||
	    !quic_hkdf_expand_label(md, iv, aead_ivlen, secret, secretlen,
	                            qv->iv_label, qv->iv_label_len) ||
	    (hp_key && !quic_hkdf_expand_label(md, hp_key, hp_len, secret, secretlen,
	                                       qv->hp_label, qv->hp_label_len)))
		return 0;

	return 1;
}

/*
 * Derive the initial secret from <secret> and QUIC version dependent salt.
 * Returns the size of the derived secret if succeeded, 0 if not.
 */
int quic_derive_initial_secret(const EVP_MD *md,
                               const unsigned char *initial_salt, size_t initial_salt_sz,
                               unsigned char *initial_secret, size_t initial_secret_sz,
                               const unsigned char *secret, size_t secret_sz)
{
	if (!quic_hkdf_extract(md, initial_secret, initial_secret_sz, secret, secret_sz,
	                       initial_salt, initial_salt_sz))
		return 0;

	return 1;
}

/*
 * Derive the client initial secret from the initial secret.
 * Returns the size of the derived secret if succeeded, 0 if not.
 */
int quic_tls_derive_initial_secrets(const EVP_MD *md,
                                    unsigned char *rx, size_t rx_sz,
                                    unsigned char *tx, size_t tx_sz,
                                    const unsigned char *secret, size_t secret_sz,
                                    int server)
{
	const unsigned char client_label[] = "client in";
	const unsigned char server_label[] = "server in";
	const unsigned char *tx_label, *rx_label;
	size_t rx_label_sz, tx_label_sz;

	if (server) {
		rx_label = client_label;
		rx_label_sz = sizeof client_label;
		tx_label = server_label;
		tx_label_sz = sizeof server_label;
	}
	else {
		rx_label = server_label;
		rx_label_sz = sizeof server_label;
		tx_label = client_label;
		tx_label_sz = sizeof client_label;
	}

	if (!quic_hkdf_expand_label(md, rx, rx_sz, secret, secret_sz,
	                            rx_label, rx_label_sz - 1) ||
	    !quic_hkdf_expand_label(md, tx, tx_sz, secret, secret_sz,
	                            tx_label, tx_label_sz - 1))
	    return 0;

	return 1;
}

/* Update <sec> secret key into <new_sec> according to RFC 9001 6.1.
 * Always succeeds.
 */
int quic_tls_sec_update(const EVP_MD *md, const struct quic_version *qv,
                        unsigned char *new_sec, size_t new_seclen,
                        const unsigned char *sec, size_t seclen)
{
	return quic_hkdf_expand_label(md, new_sec, new_seclen, sec, seclen,
	                              qv->ku_label, qv->ku_label_len);
}

/*
 * Build an IV into <iv> buffer with <ivlen> as size from <aead_iv> with
 * <aead_ivlen> as size depending on <pn> packet number.
 * This is the function which must be called to build an AEAD IV for the AEAD cryptographic algorithm
 * used to encrypt/decrypt the QUIC packet payloads depending on the packet number <pn>.
 * This function fails and return 0 only if the two buffer lengths are different, 1 if not.
 */
int quic_aead_iv_build(unsigned char *iv, size_t ivlen,
                       unsigned char *aead_iv, size_t aead_ivlen, uint64_t pn)
{
	int i;
	unsigned int shift;
	unsigned char *pos = iv;

	if (ivlen != aead_ivlen)
		return 0;

	for (i = 0; i < ivlen - sizeof pn; i++)
		*pos++ = *aead_iv++;

	/* Only the remaining (sizeof pn) bytes are XOR'ed. */
	shift = 56;
	for (i = aead_ivlen - sizeof pn; i < aead_ivlen ; i++, shift -= 8)
		*pos++ = *aead_iv++ ^ (pn >> shift);

	return 1;
}

/* Initialize the cipher context for RX part of <tls_ctx> QUIC TLS context.
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_rx_ctx_init(EVP_CIPHER_CTX **rx_ctx,
                         const EVP_CIPHER *aead, unsigned char *key)
{
	EVP_CIPHER_CTX *ctx;
	int aead_nid = EVP_CIPHER_nid(aead);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (!EVP_DecryptInit_ex(ctx, aead, NULL, NULL, NULL) ||
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, QUIC_TLS_IV_LEN, NULL) ||
	    (aead_nid == NID_aes_128_ccm &&
	     !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, QUIC_TLS_TAG_LEN, NULL)) ||
	    !EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL))
		goto err;

	*rx_ctx = ctx;

	return 1;

 err:
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

/* Initialize the cipher context for TX part of <tls_ctx> QUIC TLS context.
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_tx_ctx_init(EVP_CIPHER_CTX **tx_ctx,
                         const EVP_CIPHER *aead, unsigned char *key)
{
	EVP_CIPHER_CTX *ctx;
	int aead_nid = EVP_CIPHER_nid(aead);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (!EVP_EncryptInit_ex(ctx, aead, NULL, NULL, NULL) ||
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, QUIC_TLS_IV_LEN, NULL) ||
	    (aead_nid == NID_aes_128_ccm &&
	     !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, QUIC_TLS_TAG_LEN, NULL)) ||
	    !EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
		goto err;

	*tx_ctx = ctx;

	return 1;

 err:
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

/*
 * https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#aead
 *
 * 5.3. AEAD Usage
 *
 * Packets are protected prior to applying header protection (Section 5.4).
 * The unprotected packet header is part of the associated data (A). When removing
 * packet protection, an endpoint first removes the header protection.
 * (...)
 * These ciphersuites have a 16-byte authentication tag and produce an output 16
 * bytes larger than their input.
 * The key and IV for the packet are computed as described in Section 5.1. The nonce,
 * N, is formed by combining the packet protection IV with the packet number. The 62
 * bits of the reconstructed QUIC packet number in network byte order are left-padded
 * with zeros to the size of the IV. The exclusive OR of the padded packet number and
 * the IV forms the AEAD nonce.
 *
 * The associated data, A, for the AEAD is the contents of the QUIC header, starting
 * from the flags byte in either the short or long header, up to and including the
 * unprotected packet number.
 *
 * The input plaintext, P, for the AEAD is the payload of the QUIC packet, as described
 * in [QUIC-TRANSPORT].
 *
 * The output ciphertext, C, of the AEAD is transmitted in place of P.
 *
 * Some AEAD functions have limits for how many packets can be encrypted under the same
 * key and IV (see for example [AEBounds]). This might be lower than the packet number limit.
 * An endpoint MUST initiate a key update (Section 6) prior to exceeding any limit set for
 * the AEAD that is in use.
 */

/* Encrypt in place <buf> plaintext with <len> as length with QUIC_TLS_TAG_LEN
 * included tailing bytes for the tag.
 * Note that for CCM mode, we must set the the ciphertext length if AAD data
 * are provided from <aad> buffer with <aad_len> as length. This is always the
 * case here. So the caller of this function must provide <aad>.
 *
 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
 */
int quic_tls_encrypt(unsigned char *buf, size_t len,
                     const unsigned char *aad, size_t aad_len,
                     EVP_CIPHER_CTX *ctx, const EVP_CIPHER *aead,
                     const unsigned char *key, const unsigned char *iv)
{
	int outlen;
	int aead_nid = EVP_CIPHER_nid(aead);

	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) ||
	    (aead_nid == NID_aes_128_ccm &&
	     !EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, len)) ||
		!EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len) ||
		!EVP_EncryptUpdate(ctx, buf, &outlen, buf, len) ||
		!EVP_EncryptFinal_ex(ctx, buf + outlen, &outlen) ||
		!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, QUIC_TLS_TAG_LEN, buf + len))
		return 0;

	return 1;
}

/* Decrypt in place <buf> ciphertext with <len> as length with QUIC_TLS_TAG_LEN
 * included tailing bytes for the tag.
 * Note that for CCM mode, we must set the the ciphertext length if AAD data
 * are provided from <aad> buffer with <aad_len> as length. This is always the
 * case here. So the caller of this function must provide <aad>. Also not the
 * there is no need to call EVP_DecryptFinal_ex for CCM mode.
 *
 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
 */
int quic_tls_decrypt(unsigned char *buf, size_t len,
                     unsigned char *aad, size_t aad_len,
                     EVP_CIPHER_CTX *ctx, const EVP_CIPHER *aead,
                     const unsigned char *key, const unsigned char *iv)
{
	int outlen;
	int aead_nid = EVP_CIPHER_nid(aead);

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv) ||
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, QUIC_TLS_TAG_LEN,
	                         buf + len - QUIC_TLS_TAG_LEN) ||
	    (aead_nid == NID_aes_128_ccm &&
	     !EVP_DecryptUpdate(ctx, NULL, &outlen, NULL, len - QUIC_TLS_TAG_LEN)) ||
		!EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len) ||
		!EVP_DecryptUpdate(ctx, buf, &outlen, buf, len - QUIC_TLS_TAG_LEN) ||
		(aead_nid != NID_aes_128_ccm &&
		 !EVP_DecryptFinal_ex(ctx, buf + outlen, &outlen)))
		return 0;

	return 1;
}

/* Similar to quic_tls_decrypt(), except that this function does not decrypt
 * in place its ciphertest if <out> output buffer ciphertest with <len> as length
 * is different from <in> input buffer. This is the responbality of the caller
 * to check that the output buffer has at least the same size as the input buffer.
 * Note that for CCM mode, we must set the the ciphertext length if AAD data
 * are provided from <aad> buffer with <aad_len> as length. This is always the
 * case here. So the caller of this function must provide <aad>. Also note that
 * there is no need to call EVP_DecryptFinal_ex for CCM mode.
 *
 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
 *
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_decrypt2(unsigned char *out,
                      unsigned char *in, size_t len,
                      unsigned char *aad, size_t aad_len,
                      EVP_CIPHER_CTX *ctx, const EVP_CIPHER *aead,
                      const unsigned char *key, const unsigned char *iv)
{
	int outlen;
	int aead_nid = EVP_CIPHER_nid(aead);

	len -= QUIC_TLS_TAG_LEN;
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv) ||
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, QUIC_TLS_TAG_LEN, in + len) ||
	    (aead_nid == NID_aes_128_ccm &&
	     !EVP_DecryptUpdate(ctx, NULL, &outlen, NULL, len)) ||
	    !EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len) ||
	    !EVP_DecryptUpdate(ctx, out, &outlen, in, len) ||
	    (aead_nid != NID_aes_128_ccm &&
	     !EVP_DecryptFinal_ex(ctx, out + outlen, &outlen)))
		return 0;

	return 1;
}

/* Derive <key> and <iv> key and IV to be used to encrypt a retry token
 * with <secret> which is not pseudo-random.
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_derive_retry_token_secret(const EVP_MD *md,
                                       unsigned char *key, size_t keylen,
                                       unsigned char *iv, size_t ivlen,
                                       const unsigned char *salt, size_t saltlen,
                                       const unsigned char *secret, size_t secretlen)
{
	unsigned char tmpkey[QUIC_TLS_KEY_LEN];
	const unsigned char tmpkey_label[] = "retry token";
	const unsigned char key_label[] = "retry token key";
	const unsigned char iv_label[] = "retry token iv";

	if (!quic_hkdf_extract_and_expand(md, tmpkey, sizeof tmpkey,
	                                  secret, secretlen, salt, saltlen,
	                                  tmpkey_label, sizeof tmpkey_label - 1) ||
	    !quic_hkdf_expand(md, key, keylen, tmpkey, sizeof tmpkey,
	                      key_label, sizeof key_label - 1) ||
	    !quic_hkdf_expand(md, iv, ivlen, secret, secretlen,
	                      iv_label, sizeof iv_label - 1))
		return 0;

	return 1;
}

/* Generate the AEAD tag for the Retry packet <pkt> of <pkt_len> bytes and
 * write it to <tag>. The tag is written just after the <pkt> area. It should
 * be at least 16 bytes longs. <odcid> is the CID of the Initial packet
 * received which triggers the Retry.
 *
 * Returns non-zero on success else zero.
 */
int quic_tls_generate_retry_integrity_tag(unsigned char *odcid, unsigned char odcid_len,
                                          unsigned char *pkt, size_t pkt_len,
                                          const struct quic_version *qv)
{
	const EVP_CIPHER *evp = EVP_aes_128_gcm();
	EVP_CIPHER_CTX *ctx;

	/* encryption buffer - not used as only AEAD tag generation is proceed */
	unsigned char *out = NULL;
	/* address to store the AEAD tag */
	unsigned char *tag = pkt + pkt_len;
	int outlen, ret = 0;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	/* rfc9001 5.8. Retry Packet Integrity
	 *
	 * AEAD is proceed over a pseudo-Retry packet used as AAD. It contains
	 * the ODCID len + data and the Retry packet itself.
	 */
	if (!EVP_EncryptInit_ex(ctx, evp, NULL, qv->retry_tag_key, qv->retry_tag_nonce) ||
	    /* specify pseudo-Retry as AAD */
	    !EVP_EncryptUpdate(ctx, NULL, &outlen, &odcid_len, sizeof(odcid_len)) ||
	    !EVP_EncryptUpdate(ctx, NULL, &outlen, odcid, odcid_len) ||
	    !EVP_EncryptUpdate(ctx, NULL, &outlen, pkt, pkt_len) ||
	    /* finalize */
	    !EVP_EncryptFinal_ex(ctx, out, &outlen) ||
	    /* store the tag */
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, QUIC_TLS_TAG_LEN, tag)) {
		goto out;
	}
	ret = 1;

 out:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}
