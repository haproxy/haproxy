#include <haproxy/quic_tls.h>

#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>

#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/pool.h>
#include <haproxy/quic_ack.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_rx.h>
#include <haproxy/quic_stream.h>


DECLARE_POOL(pool_head_quic_enc_level,  "quic_enc_level",  sizeof(struct quic_enc_level));
DECLARE_POOL(pool_head_quic_pktns,      "quic_pktns",      sizeof(struct quic_pktns));
DECLARE_POOL(pool_head_quic_tls_ctx,    "quic_tls_ctx",    sizeof(struct quic_tls_ctx));
DECLARE_POOL(pool_head_quic_tls_secret, "quic_tls_secret", QUIC_TLS_SECRET_LEN);
DECLARE_POOL(pool_head_quic_tls_iv,     "quic_tls_iv",     QUIC_TLS_IV_LEN);
DECLARE_POOL(pool_head_quic_tls_key,    "quic_tls_key",    QUIC_TLS_KEY_LEN);

DECLARE_POOL(pool_head_quic_crypto_buf, "quic_crypto_buf", sizeof(struct quic_crypto_buf));
DECLARE_STATIC_POOL(pool_head_quic_cstream, "quic_cstream", sizeof(struct quic_cstream));

/* Initial salt depending on QUIC version to derive client/server initial secrets.
 * This one is for draft-29 QUIC version.
 */
const unsigned char initial_salt_draft_29[20] = {
	0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
	0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
	0x43, 0x90, 0xa8, 0x99
};

const unsigned char initial_salt_v1[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

const unsigned char initial_salt_v2[20] = {
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9
};

/* Dump the RX/TX secrets of <secs> QUIC TLS secrets. */
void quic_tls_keys_hexdump(struct buffer *buf,
                           const struct quic_tls_secrets *secs)
{
	int i;
	size_t aead_keylen;
	size_t aead_ivlen;
	size_t hp_len;

	if (!secs->aead || !secs->hp)
		return;
	aead_keylen = (size_t)QUIC_AEAD_key_length(secs->aead);
	aead_ivlen = (size_t)QUIC_AEAD_iv_length(secs->aead);
	hp_len = (size_t)EVP_CIPHER_key_length(secs->hp);

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

/* Dump the RX/TX secrets of <kp> QUIC TLS key phase */
void quic_tls_kp_keys_hexdump(struct buffer *buf,
                              const struct quic_tls_kp *kp)
{
	int i;

	chunk_appendf(buf, "\n        secret=");
	for (i = 0; i < kp->secretlen; i++)
		chunk_appendf(buf, "%02x", kp->secret[i]);
	chunk_appendf(buf, "\n        key=");
	for (i = 0; i < kp->keylen; i++)
		chunk_appendf(buf, "%02x", kp->key[i]);
	chunk_appendf(buf, "\n        iv=");
	for (i = 0; i < kp->ivlen; i++)
		chunk_appendf(buf, "%02x", kp->iv[i]);
}

/* Release the memory of <pktns> packet number space attached to <qc> QUIC connection. */
void quic_pktns_release(struct quic_conn *qc, struct quic_pktns **pktns)
{
	if (!*pktns)
		return;

	quic_pktns_tx_pkts_release(*pktns, qc);
	qc_release_pktns_frms(qc, *pktns);
	quic_free_arngs(qc, &(*pktns)->rx.arngs);
	LIST_DEL_INIT(&(*pktns)->list);
	pool_free(pool_head_quic_pktns, *pktns);
	*pktns = NULL;
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

/* Release the memory allocated for <cs> CRYPTO stream */
void quic_cstream_free(struct quic_cstream *cs)
{
	if (!cs) {
		/* This is the case for ORTT encryption level */
		return;
	}

	quic_free_ncbuf(&cs->rx.ncbuf);

	qc_stream_desc_release(cs->desc, 0, NULL);
	pool_free(pool_head_quic_cstream, cs);
}

/* Allocate a new QUIC stream for <qc>.
 * Return it if succeeded, NULL if not.
 */
struct quic_cstream *quic_cstream_new(struct quic_conn *qc)
{
	struct quic_cstream *cs, *ret_cs = NULL;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);
	cs = pool_alloc(pool_head_quic_cstream);
	if (!cs) {
		TRACE_ERROR("crypto stream allocation failed", QUIC_EV_CONN_INIT, qc);
		goto leave;
	}

	cs->rx.offset = 0;
	cs->rx.ncbuf = NCBUF_NULL;
	cs->rx.offset = 0;

	cs->tx.offset = 0;
	cs->tx.sent_offset = 0;
	cs->tx.buf = BUF_NULL;
	cs->desc = qc_stream_desc_new((uint64_t)-1, -1, cs, qc);
	if (!cs->desc) {
		TRACE_ERROR("crypto stream allocation failed", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	ret_cs = cs;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return ret_cs;

 err:
	pool_free(pool_head_quic_cstream, cs);
	goto leave;
}

/* Uninitialize <qel> QUIC encryption level. Never fails. */
void quic_conn_enc_level_uninit(struct quic_conn *qc, struct quic_enc_level *qel)
{
	int i;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	for (i = 0; i < qel->tx.crypto.nb_buf; i++) {
		if (qel->tx.crypto.bufs[i]) {
			pool_free(pool_head_quic_crypto_buf, qel->tx.crypto.bufs[i]);
			qel->tx.crypto.bufs[i] = NULL;
		}
	}

	ha_free(&qel->tx.crypto.bufs);
	quic_cstream_free(qel->cstream);

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Initialize QUIC TLS encryption level with <level<> as level for <qc> QUIC
 * connection allocating everything needed.
 *
 * Returns 1 if succeeded, 0 if not. On error the caller is responsible to use
 * quic_conn_enc_level_uninit() to cleanup partially allocated content.
 */
static int quic_conn_enc_level_init(struct quic_conn *qc,
                                    struct quic_enc_level **el,
                                    struct quic_pktns *pktns,
                                    enum ssl_encryption_level_t level)
{
	int ret = 0;
	struct quic_enc_level *qel;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	qel = pool_alloc(pool_head_quic_enc_level);
	if (!qel)
		goto leave;

	LIST_INIT(&qel->el_send);
	qel->send_frms = NULL;

	qel->tx.crypto.bufs = NULL;
	qel->tx.crypto.nb_buf = 0;
	qel->cstream = NULL;
	qel->pktns = pktns;
	qel->level = level;
	quic_tls_ctx_reset(&qel->tls_ctx);

	qel->rx.pkts = EB_ROOT;
	LIST_INIT(&qel->rx.pqpkts);

	/* Allocate only one buffer. */
	/* TODO: use a pool */
	qel->tx.crypto.bufs = malloc(sizeof *qel->tx.crypto.bufs);
	if (!qel->tx.crypto.bufs)
		goto err;

	qel->tx.crypto.bufs[0] = pool_alloc(pool_head_quic_crypto_buf);
	if (!qel->tx.crypto.bufs[0])
		goto err;


	qel->tx.crypto.bufs[0]->sz = 0;
	qel->tx.crypto.nb_buf = 1;

	qel->tx.crypto.sz = 0;
	qel->tx.crypto.offset = 0;
	/* No CRYPTO data for early data TLS encryption level */
	if (level == ssl_encryption_early_data)
		qel->cstream = NULL;
	else {
		qel->cstream = quic_cstream_new(qc);
		if (!qel->cstream)
			goto err;
	}

	/* Ensure early-data encryption is not inserted at the end of this ->qel_list
	 * list. This would perturbate the sender during handshakes. This latter adds
	 * PADDING frames to datagrams from the last encryption level in this list,
	 * for datagram with at least an ack-eliciting Initial packet inside.
	 * But a QUIC server has nothing to send from this early-data encryption
	 * level, contrary to the client.
	 * Here early-data is added after the Initial encryption level which is
	 * always already present.
	 */
	if (level == ssl_encryption_early_data) {
		if (qc->iel)
			LIST_APPEND(&qc->iel->list, &qel->list);
		else
			LIST_INSERT(&qc->qel_list, &qel->list);
	}
	else
		LIST_APPEND(&qc->qel_list, &qel->list);
	*el = qel;
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;

 err:
	quic_conn_enc_level_uninit(qc, qel);
	pool_free(pool_head_quic_enc_level, qel);
	goto leave;
}

/* Allocate a QUIC TLS encryption with <level> as TLS stack encryption to be
 * attached to <qc> QUIC connection. Also allocate the associated packet number
 * space object with <pktns> as address to be attached to <qc> if not already
 * allocated.
 * Return 1 if succeeded, 0 if not.
 */
int qc_enc_level_alloc(struct quic_conn *qc, struct quic_pktns **pktns,
                       struct quic_enc_level **qel, enum ssl_encryption_level_t level)
{
	int ret = 0;

	BUG_ON(!qel || !pktns);
	BUG_ON(*qel && !*pktns);

	if (!*pktns && !quic_pktns_init(qc, pktns))
		goto leave;

	if (!*qel && !quic_conn_enc_level_init(qc, qel, *pktns, level))
	    goto leave;

	ret = 1;
 leave:
	return ret;
}

/* Free the memory allocated to the encryption level attached to <qc> connection
 * with <qel> as pointer address. Also remove it from the list of the encryption
 * levels attached to this connection and reset its value to NULL.
 * Never fails.
 */
void qc_enc_level_free(struct quic_conn *qc, struct quic_enc_level **qel)
{
	if (!*qel)
		return;

	quic_tls_ctx_secs_free(&(*qel)->tls_ctx);
	quic_conn_enc_level_uninit(qc, *qel);
	LIST_DEL_INIT(&(*qel)->list);
	pool_free(pool_head_quic_enc_level, *qel);
	*qel = NULL;
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
int quic_tls_derive_keys(const QUIC_AEAD *aead, const EVP_CIPHER *hp,
                         const EVP_MD *md, const struct quic_version *qv,
                         unsigned char *key, size_t keylen,
                         unsigned char *iv, size_t ivlen,
                         unsigned char *hp_key, size_t hp_keylen,
                         const unsigned char *secret, size_t secretlen)
{
	size_t aead_keylen = (size_t)QUIC_AEAD_key_length(aead);
	size_t aead_ivlen = (size_t)QUIC_AEAD_iv_length(aead);
#ifdef QUIC_AEAD_API
	size_t hp_len = 0;

	if (hp == EVP_CIPHER_CHACHA20)
		hp_len = 32;
	else if (hp)
		hp_len = (size_t)EVP_CIPHER_key_length(hp);
#else
	size_t hp_len = hp ? (size_t)EVP_CIPHER_key_length(hp) : 0;
#endif

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
 */
void quic_aead_iv_build(unsigned char *iv, size_t ivlen,
                        unsigned char *aead_iv, size_t aead_ivlen, uint64_t pn)
{
	int i;
	unsigned int shift;
	unsigned char *pos = iv;

	/* Input buffers must have the same size. */
	BUG_ON(ivlen != aead_ivlen);

	for (i = 0; i < ivlen - sizeof pn; i++)
		*pos++ = *aead_iv++;

	/* Only the remaining (sizeof pn) bytes are XOR'ed. */
	shift = 56;
	for (i = aead_ivlen - sizeof pn; i < aead_ivlen ; i++, shift -= 8)
		*pos++ = *aead_iv++ ^ (pn >> shift);
}

/* Initialize the cipher context for RX part of <tls_ctx> QUIC TLS context.
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_rx_ctx_init(QUIC_AEAD_CTX **rx_ctx,
                         const QUIC_AEAD *aead, unsigned char *key)
{

#ifdef QUIC_AEAD_API
	QUIC_AEAD_CTX *ctx = EVP_AEAD_CTX_new(aead, key, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH);
	if (!ctx)
		return 0;

#else
	int aead_nid = EVP_CIPHER_nid(aead);
	QUIC_AEAD_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (!EVP_DecryptInit_ex(ctx, aead, NULL, NULL, NULL) ||
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, QUIC_TLS_IV_LEN, NULL) ||
	    (aead_nid == NID_aes_128_ccm &&
	     !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, QUIC_TLS_TAG_LEN, NULL)) ||
	    !EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL))
		goto err;

#endif
	*rx_ctx = ctx;
	return 1;

 err:
	QUIC_AEAD_CTX_free(ctx);
	return 0;
}

/* Initialize <*hp_ctx> cipher context with <key> as key for header protection encryption */
int quic_tls_enc_hp_ctx_init(EVP_CIPHER_CTX **hp_ctx,
                              const EVP_CIPHER *hp, unsigned char *key)
{
	EVP_CIPHER_CTX *ctx;

#ifdef QUIC_AEAD_API

	if (hp == EVP_CIPHER_CHACHA20) {
		*hp_ctx = EVP_CIPHER_CTX_CHACHA20;
		return 1;
	}
#endif

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (!EVP_EncryptInit_ex(ctx, hp, NULL, key, NULL))
		goto err;

	*hp_ctx = ctx;
	return 1;

 err:
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

/* Encrypt <inlen> bytes from <in> buffer into <out> with <ctx> as
 * cipher context. This is the responsibility of the caller to check there
 * is at least <inlen> bytes of available space in <out> buffer.
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_hp_encrypt(unsigned char *out,
                         const unsigned char *in, size_t inlen,
                         EVP_CIPHER_CTX *ctx, unsigned char *key)
{
	int ret = 0;

#ifdef QUIC_AEAD_API

	if (ctx == EVP_CIPHER_CTX_CHACHA20) {
		uint32_t counter;
		/* According to RFC 9001, 5.4.4. ChaCha20-Based Header Protection:
		 * The first 4 bytes of the sampled ciphertext are the block counter.
		 * The remaining 12 bytes are used as the nonce.
		 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		counter = (uint32_t)in[0] + (uint32_t)(in[1] << 8) + (uint32_t)(in[2] << 16) + (uint32_t)(in[3] << 24);
#else
		memcpy(&counter, in, sizeof(counter));
#endif
		CRYPTO_chacha_20(out, out, inlen, key, in + sizeof(counter), counter);
		return 1;
	}

#endif

	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, in) ||
	    !EVP_EncryptUpdate(ctx, out, &ret, out, inlen) ||
	    !EVP_EncryptFinal_ex(ctx, out, &ret))
		return 0;

	return 1;
}

/* Initialize <*hp_ctx> cipher context with <key> as key for header protection decryption */
int quic_tls_dec_hp_ctx_init(EVP_CIPHER_CTX **hp_ctx,
                              const EVP_CIPHER *hp, unsigned char *key)
{
	EVP_CIPHER_CTX *ctx;

#ifdef QUIC_AEAD_API

	if (hp == EVP_CIPHER_CHACHA20) {
		*hp_ctx = EVP_CIPHER_CTX_CHACHA20;
		return 1;
	}
#endif

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 0;

	if (!EVP_DecryptInit_ex(ctx, hp, NULL, key, NULL))
		goto err;

	*hp_ctx = ctx;
	return 1;

 err:
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

/* Decrypt <in> data into <out> with <ctx> as cipher context.
 * This is the responsibility of the caller to check there is at least
 * <outlen> bytes into <in> buffer.
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_hp_decrypt(unsigned char *out,
                         const unsigned char *in, size_t inlen,
                         EVP_CIPHER_CTX *ctx, unsigned char *key)
{
	int ret = 0;

#ifdef QUIC_AEAD_API
	if (ctx == EVP_CIPHER_CTX_CHACHA20) {
		uint32_t counter;

		/* According to RFC 9001, 5.4.4. ChaCha20-Based Header Protection:
		 * The first 4 bytes of the sampled ciphertext are the block counter.
		 * The remaining 12 bytes are used as the nonce.
		 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		counter = (uint32_t)in[0] + (uint32_t)(in[1] << 8) + (uint32_t)(in[2] << 16) + (uint32_t)(in[3] << 24);
#else
		memcpy(&counter, in, sizeof(counter));
#endif
		CRYPTO_chacha_20(out, out, inlen, key, in + sizeof(counter), counter);
		return 1;
	}

#endif

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, in) ||
	    !EVP_DecryptUpdate(ctx, out, &ret, out, inlen) ||
	    !EVP_DecryptFinal_ex(ctx, out, &ret))
		return 0;

	return 1;
}

/* Initialize the cipher context for TX part of <tls_ctx> QUIC TLS context.
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_tx_ctx_init(QUIC_AEAD_CTX **tx_ctx,
                         const QUIC_AEAD *aead, unsigned char *key)
{
#ifdef QUIC_AEAD_API
	QUIC_AEAD_CTX *ctx = EVP_AEAD_CTX_new(aead, key, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH);
	if (!ctx)
		return 0;

#else
	int aead_nid = EVP_CIPHER_nid(aead);
	QUIC_AEAD_CTX *ctx = EVP_CIPHER_CTX_new();

	if (!ctx)
		return 0;

	if (!EVP_EncryptInit_ex(ctx, aead, NULL, NULL, NULL) ||
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, QUIC_TLS_IV_LEN, NULL) ||
	    (aead_nid == NID_aes_128_ccm &&
	     !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, QUIC_TLS_TAG_LEN, NULL)) ||
	    !EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
		goto err;
#endif

	*tx_ctx = ctx;
	return 1;

 err:
	QUIC_AEAD_CTX_free(ctx);
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
                     QUIC_AEAD_CTX *ctx, const QUIC_AEAD *aead,
                     const unsigned char *iv)
{
#ifdef QUIC_AEAD_API
	size_t outlen;

	if (!EVP_AEAD_CTX_seal(ctx, buf, &outlen, len + EVP_AEAD_max_overhead(aead),
	                       iv, QUIC_TLS_IV_LEN,
	                       buf, len,
	                       aad, aad_len))
		return 0;
#else
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


#endif

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
                     QUIC_AEAD_CTX *ctx, const QUIC_AEAD *aead,
                     const unsigned char *key, const unsigned char *iv)
{
#ifdef QUIC_AEAD_API
	size_t outlen;

	if (!EVP_AEAD_CTX_open(ctx, buf, &outlen, len,
	                       iv, QUIC_TLS_IV_LEN,
	                       buf, len,
	                       aad, aad_len))
		return 0;

#else

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

#endif

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
                      QUIC_AEAD_CTX *ctx, const QUIC_AEAD *aead,
                      const unsigned char *key, const unsigned char *iv)
{
#ifdef QUIC_AEAD_API
	size_t outlen;

	if (!EVP_AEAD_CTX_open(ctx, out, &outlen, len,
	                       iv, QUIC_TLS_IV_LEN,
	                       in, len,
	                       aad, aad_len))
		return 0;

#else

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
#endif

	return 1;
}

/* Derive <key> and <iv> key and IV to be used to encrypt a retry token
 * with <secret> which is not pseudo-random.
 * Return 1 if succeeded, 0 if not.
 */
static inline int quic_do_tls_derive_token_secret(const EVP_MD *md, unsigned char *key, size_t keylen,
                                                  unsigned char *iv, size_t ivlen,
                                                  const unsigned char *salt, size_t saltlen,
                                                  const unsigned char *secret, size_t secretlen,
                                                  const unsigned char *klabel, size_t klabellen,
                                                  const unsigned char *ivlabel, size_t ivlabellen)
{
	unsigned char tmpkey[QUIC_TLS_KEY_LEN];

	if (!quic_hkdf_extract(md, tmpkey, sizeof tmpkey,
	                       secret, secretlen, salt, saltlen) ||
	    !quic_hkdf_expand(md, key, keylen, tmpkey, sizeof tmpkey,
	                      klabel, klabellen) ||
	    !quic_hkdf_expand(md, iv, ivlen, tmpkey, sizeof tmpkey,
	                      ivlabel, ivlabellen))
		return 0;

	return 1;
}

int quic_tls_derive_retry_token_secret(const EVP_MD *md,
                                       unsigned char *key, size_t keylen,
                                       unsigned char *iv, size_t ivlen,
                                       const unsigned char *salt, size_t saltlen,
                                       const unsigned char *secret, size_t secretlen)
{
	const unsigned char key_label[] = "retry token key";
	const unsigned char iv_label[] = "retry token iv";

	return quic_do_tls_derive_token_secret(md, key, keylen, iv, ivlen,
	                                       salt, saltlen, secret, secretlen,
	                                       key_label, sizeof(key_label) - 1,
	                                       iv_label, sizeof(iv_label) -1);
}

int quic_tls_derive_token_secret(const EVP_MD *md,
                                 unsigned char *key, size_t keylen,
                                 unsigned char *iv, size_t ivlen,
                                 const unsigned char *salt, size_t saltlen,
                                 const unsigned char *secret, size_t secretlen)
{
	const unsigned char key_label[] = "token key";
	const unsigned char iv_label[] = "token iv";

	return quic_do_tls_derive_token_secret(md, key, keylen, iv, ivlen,
	                                       salt, saltlen, secret, secretlen,
	                                       key_label, sizeof(key_label) - 1,
	                                       iv_label, sizeof(iv_label) -1);
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

/* Derive new keys and ivs required for Key Update feature for <qc> QUIC
 * connection.
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_key_update(struct quic_conn *qc)
{
	struct quic_tls_ctx *tls_ctx = &qc->ael->tls_ctx;
	struct quic_tls_secrets *rx = &tls_ctx->rx;
	struct quic_tls_secrets *tx = &tls_ctx->tx;
	/* Used only for the traces */
	struct quic_kp_trace kp_trace = {
		.rx_sec = rx->secret,
		.rx_seclen = rx->secretlen,
		.tx_sec = tx->secret,
		.tx_seclen = tx->secretlen,
	};
	/* The next key phase secrets to be derived */
	struct quic_tls_kp *nxt_rx = &qc->ku.nxt_rx;
	struct quic_tls_kp *nxt_tx = &qc->ku.nxt_tx;
	const struct quic_version *ver =
		qc->negotiated_version ? qc->negotiated_version : qc->original_version;
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_KP, qc);

	nxt_rx = &qc->ku.nxt_rx;
	nxt_tx = &qc->ku.nxt_tx;

	TRACE_PRINTF(TRACE_LEVEL_DEVELOPER, QUIC_EV_CONN_SPPKTS, qc, 0, 0, 0,
	             "nxt_rx->secretlen=%llu rx->secretlen=%llu",
	             (ull)nxt_rx->secretlen, (ull)rx->secretlen);
	/* Prepare new RX secrets */
	if (!quic_tls_sec_update(rx->md, ver, nxt_rx->secret, nxt_rx->secretlen,
	                         rx->secret, rx->secretlen)) {
		TRACE_ERROR("New RX secret update failed", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	if (!quic_tls_derive_keys(rx->aead, NULL, rx->md, ver,
	                          nxt_rx->key, nxt_rx->keylen,
	                          nxt_rx->iv, nxt_rx->ivlen, NULL, 0,
	                          nxt_rx->secret, nxt_rx->secretlen)) {
		TRACE_ERROR("New RX key derivation failed", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	kp_trace.rx = nxt_rx;
	/* Prepare new TX secrets */
	if (!quic_tls_sec_update(tx->md, ver, nxt_tx->secret, nxt_tx->secretlen,
	                         tx->secret, tx->secretlen)) {
		TRACE_ERROR("New TX secret update failed", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	if (!quic_tls_derive_keys(tx->aead, NULL, tx->md, ver,
	                          nxt_tx->key, nxt_tx->keylen,
	                          nxt_tx->iv, nxt_tx->ivlen, NULL, 0,
	                          nxt_tx->secret, nxt_tx->secretlen)) {
		TRACE_ERROR("New TX key derivation failed", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	kp_trace.tx = nxt_tx;
	if (nxt_rx->ctx) {
		QUIC_AEAD_CTX_free(nxt_rx->ctx);
		nxt_rx->ctx = NULL;
	}

	if (!quic_tls_rx_ctx_init(&nxt_rx->ctx, tls_ctx->rx.aead, nxt_rx->key)) {
		TRACE_ERROR("could not initialize RX TLS cipher context", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	if (nxt_tx->ctx) {
		QUIC_AEAD_CTX_free(nxt_tx->ctx);
		nxt_tx->ctx = NULL;
	}

	if (!quic_tls_tx_ctx_init(&nxt_tx->ctx, tls_ctx->tx.aead, nxt_tx->key)) {
		TRACE_ERROR("could not initialize TX TLS cipher context", QUIC_EV_CONN_KP, qc);
		goto leave;
	}

	ret = 1;
 leave:
	TRACE_PROTO("key update", QUIC_EV_CONN_KP, qc, &kp_trace);
	TRACE_LEAVE(QUIC_EV_CONN_KP, qc);
	return ret;
}

/* Rotate the Key Update information for <qc> QUIC connection.
 * Must be used after having updated them.
 * Always succeeds.
 */
void quic_tls_rotate_keys(struct quic_conn *qc)
{
	struct quic_tls_ctx *tls_ctx = &qc->ael->tls_ctx;
	unsigned char *curr_secret, *curr_iv, *curr_key;
	QUIC_AEAD_CTX *curr_ctx;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);

	/* Rotate the RX secrets */
	curr_ctx = tls_ctx->rx.ctx;
	curr_secret = tls_ctx->rx.secret;
	curr_iv = tls_ctx->rx.iv;
	curr_key = tls_ctx->rx.key;

	tls_ctx->rx.ctx     = qc->ku.nxt_rx.ctx;
	tls_ctx->rx.secret  = qc->ku.nxt_rx.secret;
	tls_ctx->rx.iv      = qc->ku.nxt_rx.iv;
	tls_ctx->rx.key     = qc->ku.nxt_rx.key;

	qc->ku.nxt_rx.ctx    = qc->ku.prv_rx.ctx;
	qc->ku.nxt_rx.secret = qc->ku.prv_rx.secret;
	qc->ku.nxt_rx.iv     = qc->ku.prv_rx.iv;
	qc->ku.nxt_rx.key    = qc->ku.prv_rx.key;

	qc->ku.prv_rx.ctx    = curr_ctx;
	qc->ku.prv_rx.secret = curr_secret;
	qc->ku.prv_rx.iv     = curr_iv;
	qc->ku.prv_rx.key    = curr_key;
	qc->ku.prv_rx.pn     = tls_ctx->rx.pn;

	/* Update the TX secrets */
	curr_ctx = tls_ctx->tx.ctx;
	curr_secret = tls_ctx->tx.secret;
	curr_iv = tls_ctx->tx.iv;
	curr_key = tls_ctx->tx.key;

	tls_ctx->tx.ctx    = qc->ku.nxt_tx.ctx;
	tls_ctx->tx.secret = qc->ku.nxt_tx.secret;
	tls_ctx->tx.iv     = qc->ku.nxt_tx.iv;
	tls_ctx->tx.key    = qc->ku.nxt_tx.key;

	qc->ku.nxt_tx.ctx    = curr_ctx;
	qc->ku.nxt_tx.secret = curr_secret;
	qc->ku.nxt_tx.iv     = curr_iv;
	qc->ku.nxt_tx.key    = curr_key;

	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
}

/* Release the memory allocated for the QUIC TLS context with <ctx> as address. */
void quic_tls_ctx_free(struct quic_tls_ctx **ctx)
{
	if (!*ctx)
		return;

	quic_tls_ctx_secs_free(*ctx);
	pool_free(pool_head_quic_tls_ctx, *ctx);
	*ctx = NULL;
}

/* Finalize <qc> QUIC connection:
 * - allocated and initialize the Initial QUIC TLS context for negotiated
 *   version if needed,
 * - derive the secrets for this context,
 * - set them into the TLS stack,
 *
 * Return 1 if succeeded, 0 if not.
 */
int quic_tls_finalize(struct quic_conn *qc, int server)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	if (!qc->negotiated_version)
		goto done;

	qc->nictx = pool_alloc(pool_head_quic_tls_ctx);
	if (!qc->nictx)
		goto err;

	quic_tls_ctx_reset(qc->nictx);
	if (!qc_new_isecs(qc, qc->nictx, qc->negotiated_version,
	                  qc->odcid.data, qc->odcid.len, server))
		goto err;

 done:
	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;

 err:
	quic_tls_ctx_free(&qc->nictx);
	goto out;
}
