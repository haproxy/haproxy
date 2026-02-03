/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>

#include <haproxy/jwt.h>
#include <haproxy/tools.h>
#include <haproxy/base64.h>
#include <haproxy/chunk.h>
#include <haproxy/init.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_utils.h>
#include <haproxy/buf.h>
#include <haproxy/sample.h>
#include <haproxy/thread.h>
#include <haproxy/arg.h>
#include <haproxy/vars.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/ssl_ckch.h>

#include <import/mjson.h>

#if defined(HAVE_JWS)

#ifdef USE_OPENSSL

struct alg_enc {
	const char *name;
	int value;
};

/* https://datatracker.ietf.org/doc/html/rfc7518#section-4.1 */
typedef enum {
	JWE_ALG_UNMANAGED = -1,
	JWE_ALG_RSA1_5,
	JWE_ALG_RSA_OAEP,
	JWE_ALG_RSA_OAEP_256,
	JWE_ALG_A128KW,
	JWE_ALG_A192KW,
	JWE_ALG_A256KW,
	JWE_ALG_DIR,
	// JWE_ALG_ECDH_ES,
	// JWE_ALG_ECDH_ES_A128KW,
	// JWE_ALG_ECDH_ES_A192KW,
	// JWE_ALG_ECDH_ES_A256KW,
	JWE_ALG_A128GCMKW,
	JWE_ALG_A192GCMKW,
	JWE_ALG_A256GCMKW,
	// JWE_ALG_PBES2_HS256_A128KW,
	// JWE_ALG_PBES2_HS384_A192KW,
	// JWE_ALG_PBES2_HS512_A256KW,
} jwe_alg;

struct alg_enc jwe_algs[] = {
	{ "RSA1_5", JWE_ALG_RSA1_5 },
	{ "RSA-OAEP", JWE_ALG_RSA_OAEP },
	{ "RSA-OAEP-256", JWE_ALG_RSA_OAEP_256 },
	{ "A128KW", JWE_ALG_A128KW },
	{ "A192KW", JWE_ALG_A192KW },
	{ "A256KW", JWE_ALG_A256KW },
	{ "dir", JWE_ALG_DIR },
	{ "ECDH-ES", JWE_ALG_UNMANAGED },
	{ "ECDH-ES+A128KW", JWE_ALG_UNMANAGED },
	{ "ECDH-ES+A192KW", JWE_ALG_UNMANAGED },
	{ "ECDH-ES+A256KW", JWE_ALG_UNMANAGED },
	{ "A128GCMKW", JWE_ALG_A128GCMKW },
	{ "A192GCMKW", JWE_ALG_A192GCMKW },
	{ "A256GCMKW", JWE_ALG_A256GCMKW },
	{ "PBES2-HS256+A128KW", JWE_ALG_UNMANAGED },
	{ "PBES2-HS384+A192KW", JWE_ALG_UNMANAGED },
	{ "PBES2-HS512+A256KW", JWE_ALG_UNMANAGED },
	{ NULL, JWE_ALG_UNMANAGED },
};

/* https://datatracker.ietf.org/doc/html/rfc7518#section-5.1 */
typedef enum {
	JWE_ENC_UNMANAGED = -1,
	JWE_ENC_A128CBC_HS256,
	JWE_ENC_A192CBC_HS384,
	JWE_ENC_A256CBC_HS512,
	JWE_ENC_A128GCM,
	JWE_ENC_A192GCM,
	JWE_ENC_A256GCM,
} jwe_enc;

struct alg_enc jwe_encodings[] = {
	{ "A128CBC-HS256", JWE_ENC_A128CBC_HS256 },
	{ "A192CBC-HS384", JWE_ENC_A192CBC_HS384 },
	{ "A256CBC-HS512", JWE_ENC_A256CBC_HS512 },
	{ "A128GCM", JWE_ENC_A128GCM },
	{ "A192GCM", JWE_ENC_A192GCM },
	{ "A256GCM", JWE_ENC_A256GCM },
	{ NULL, JWE_ENC_UNMANAGED },
};


/*
 * In the JWE Compact Serialization, a JWE is represented as the concatenation:
 *     BASE64URL(UTF8(JWE Protected Header)) || '.' ||
 *     BASE64URL(JWE Encrypted Key) || '.' ||
 *     BASE64URL(JWE Initialization Vector) || '.' ||
 *     BASE64URL(JWE Ciphertext) || '.' ||
 *     BASE64URL(JWE Authentication Tag)
 */
enum jwe_elt {
	JWE_ELT_JOSE = 0,
	JWE_ELT_CEK,
	JWE_ELT_IV,
	JWE_ELT_CIPHERTEXT,
	JWE_ELT_TAG,
	JWE_ELT_MAX
};


struct jose_fields {
	struct buffer *tag;
	struct buffer *iv;
};


/*
 * Parse contents of "alg" or "enc" field of the JOSE header.
 */
static inline int parse_alg_enc(struct buffer *buf, struct alg_enc *array)
{
	struct alg_enc *item = array;
	int val = -1;

	while (item->name) {
		if (strncmp(item->name, b_orig(buf), (int)b_data(buf)) == 0) {
			val = item->value;
			break;
		}
		++item;
	}

	return val;
}

/*
 * Look for field <field_name> in JSON <decoded_jose> and base64url decode its
 * content in buffer <out>.
 * The field might not be found, it won't be raised as an error.
 */
static inline int decode_jose_field(struct buffer *decoded_jose, const char *field_name, struct buffer *out)
{
	struct buffer *trash = get_trash_chunk();
	int size = 0;

	if (!out)
		return 0;

	size = mjson_get_string(b_orig(decoded_jose), b_data(decoded_jose), field_name,
				b_orig(trash), b_size(trash));
	if (size != -1) {
		trash->data = size;
		size = base64urldec(b_orig(trash), b_data(trash),
				    b_orig(out), b_size(out));
		if (size < 0)
			return 1;
		out->data = size;
	}

	return 0;
}


/*
 * Extract the "alg" and "enc" of the JOSE header as well as some algo-specific
 * base64url encoded fields.
 */
static int parse_jose(struct buffer *decoded_jose, int *alg, int *enc, struct jose_fields *jose_fields)
{
	struct buffer *trash = NULL;
	int retval = 0;
	int size = 0;

	/* Look for "alg" field */
	trash = get_trash_chunk();
	size = mjson_get_string(b_orig(decoded_jose), b_data(decoded_jose), "$.alg",
	                        b_orig(trash), b_size(trash));
	if (size == -1)
		goto end;
	trash->data = size;
	*alg = parse_alg_enc(trash, jwe_algs);
	if (*alg == JWE_ALG_UNMANAGED)
		goto end;

	/* Look for "enc" field */
	chunk_reset(trash);
	size = mjson_get_string(b_orig(decoded_jose), b_data(decoded_jose), "$.enc",
	                        b_orig(trash), b_size(trash));
	if (size == -1)
		goto end;
	trash->data = size;
	*enc = parse_alg_enc(trash, jwe_encodings);
	if (*enc == JWE_ENC_UNMANAGED)
		goto end;

	/* Look for "tag" field (used by aes gcm encryption) */
	if (decode_jose_field(decoded_jose, "$.tag", jose_fields->tag))
		goto end;

	/* Look for "iv" field (used by aes gcm encryption) */
	if (decode_jose_field(decoded_jose, "$.iv", jose_fields->iv))
		goto end;

	retval = 1;

end:
	return retval;
}


/*
 * Decrypt Encrypted Key <cek> encrypted with AES GCM Key Wrap algorithm and
 * dump the decrypted key into <decrypted_cek> buffer. The decryption is done
 * thanks to <iv> Initialization Vector, <secret> key and authentication check
 * is performed with <aead_tag>. All those buffers must be in raw format,
 * already base64url decoded.
 * Return 0 in case of error, 1 otherwise.
 */
static int decrypt_cek_aesgcmkw(struct buffer *cek, struct buffer *aead_tag, struct buffer *iv,
                                struct buffer *decrypted_cek, struct buffer *secret, jwe_alg crypt_alg)
{
	int retval = 0;
	int key_size = 0;
	int size = 0;

	switch(crypt_alg) {
	case JWE_ALG_A128GCMKW: key_size = 128; break;
	case JWE_ALG_A192GCMKW: key_size = 192; break;
	case JWE_ALG_A256GCMKW: key_size = 256; break;
		break;
	default:
		goto end;
	}

	size = aes_process(cek, iv, secret, key_size, aead_tag, NULL, decrypted_cek, 1, 1);

	if (size < 0)
		goto end;

	decrypted_cek->data = size;

	retval = 1;

end:
	return retval;
}


/*
 * Decrypt Encrypted Key <cek> encrypted with AES CBC Key Wrap algorithm and
 * dump the decrypted key into <decrypted_cek> buffer. The decryption is done
 * thanks to <iv> Initialization Vector and <secret> key. All those buffers must
 * be in raw format, already base64url decoded.
 * Return 0 in case of error, 1 otherwise.
 */
static int decrypt_cek_aeskw(struct buffer *cek, struct buffer *decrypted_cek, struct buffer *secret, jwe_alg crypt_alg)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = NULL;
	struct buffer *iv = NULL;
	int iv_size = 0;
	int retval = 0;
	int length = 0;

	ctx = EVP_CIPHER_CTX_new();

	if (!ctx)
		goto end;

	switch(crypt_alg) {
#ifndef OPENSSL_IS_AWSLC
	/*  AWS-LC does not support EVP_aes_128_wrap or EVP_aes_192_wrap */
	case JWE_ALG_A128KW: cipher = EVP_aes_128_wrap(); break;
	case JWE_ALG_A192KW: cipher = EVP_aes_192_wrap(); break;
#endif
	case JWE_ALG_A256KW: cipher = EVP_aes_256_wrap(); break;
	default:
		goto end;
	}

#ifndef OPENSSL_IS_AWSLC
	/* Comment from AWS-LC (in include/openssl/cipher.h):
	 * EVP_aes_256_wrap implements AES-256 in Key Wrap mode. OpenSSL 1.1.1
	 * required |EVP_CIPHER_CTX_FLAG_WRAP_ALLOW| to be set with
	 * |EVP_CIPHER_CTX_set_flags|, in order for |EVP_aes_256_wrap| to work.
	 * This is not required in AWS-LC and they are no-op flags maintained
	 * for compatibility.
	 */
	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
#endif

	iv_size = EVP_CIPHER_iv_length(cipher);
	iv = alloc_trash_chunk();
	if (!iv)
		goto end;
	/* Default IV for AES KW (see RFC3394 section-2.2.3.1) */
	memset(iv->area, 0xA6, iv_size);
	iv->data = iv_size;

	/* Initialise IV and key */
	if (EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char*)b_orig(secret), (unsigned char*)b_orig(iv)) <= 0)
		goto end;

	if (EVP_DecryptUpdate(ctx, (unsigned char*)b_orig(decrypted_cek), &length,
			      (unsigned char*)b_orig(cek), b_data(cek)) <= 0)
		goto end;

	if (EVP_DecryptFinal_ex(ctx, (unsigned char*)decrypted_cek->area + length, (int*)&decrypted_cek->data) <= 0)
		goto end;

	decrypted_cek->data += length;

	retval = 1;

end:
	EVP_CIPHER_CTX_free(ctx);
	free_trash_chunk(iv);
	return retval;
}


/*
 * Build a signature tag when AES-CBC encoding is used and check that it matches
 * the one found in the JWE token.
 * The tag is built out of a HMAC of some concatenated data taken from the JWE
 * token (see https://datatracker.ietf.org/doc/html/rfc7518#section-5.2). The
 * firest half of the previously decrypted cek is used as HMAC key.
 * Returns 0 in case of success, 1 otherwise.
 */
static int build_and_check_tag(jwe_enc enc,  struct jwt_item items[JWE_ELT_MAX],
                               struct buffer *decoded_items[JWE_ELT_MAX],
                               struct buffer *decrypted_cek)
{
	int retval = 1;
	const EVP_MD *hash = NULL;
	int mac_key_len = 0;
	uint64_t aad_len = my_htonll(items[JWE_ELT_JOSE].length << 3);

	struct buffer *tag_data = alloc_trash_chunk();
	struct buffer *hmac = alloc_trash_chunk();

	if (!tag_data || !hmac)
		goto end;

	/*
	 * Concatenate the AAD (base64url encoded JOSE header),
	 * the Initialization Vector, the ciphertext,
	 * and the AL value (number of bits in the AAD in 64bits big endian)
	 */
	if (!chunk_memcpy(tag_data, items[JWE_ELT_JOSE].start, items[JWE_ELT_JOSE].length) ||
	    !chunk_memcat(tag_data, b_orig(decoded_items[JWE_ELT_IV]), b_data(decoded_items[JWE_ELT_IV])) ||
	    !chunk_memcat(tag_data, b_orig(decoded_items[JWE_ELT_CIPHERTEXT]), b_data(decoded_items[JWE_ELT_CIPHERTEXT])) ||
	    !chunk_memcat(tag_data, (char*)&aad_len, sizeof(aad_len)))
		goto end;

	switch(enc) {
	case JWE_ENC_A128CBC_HS256: mac_key_len = 16; hash = EVP_sha256(); break;
	case JWE_ENC_A192CBC_HS384: mac_key_len = 24; hash = EVP_sha384(); break;
	case JWE_ENC_A256CBC_HS512: mac_key_len = 32; hash = EVP_sha512(); break;
	default: goto end;
	}

	if (b_data(decrypted_cek) < mac_key_len)
		goto end;

	/* Compute the HMAC SHA-XXX of the concatenated value above */
	if (!HMAC(hash, b_orig(decrypted_cek), mac_key_len,
	          (unsigned char*)b_orig(tag_data), b_data(tag_data),
	          (unsigned char*)b_orig(hmac), (unsigned int*)&hmac->data))
		goto end;

	/* Use the first half of the HMAC output M as the Authentication Tag output T */
	retval = memcmp(b_orig(decoded_items[JWE_ELT_TAG]), b_orig(hmac), b_data(hmac) >> 1);

end:
	free_trash_chunk(tag_data);
	free_trash_chunk(hmac);
	return retval;
}


/*
 * Decrypt the ciphertext.
 * Returns 0 in case of success, 1 otherwise.
 */
static int decrypt_ciphertext(jwe_enc enc, struct jwt_item items[JWE_ELT_MAX],
			      struct buffer *decoded_items[JWE_ELT_MAX],
                              struct buffer *decrypted_cek, struct buffer **out)
{
	struct buffer **ciphertext = NULL, **iv = NULL, **aead_tag = NULL, *aad = NULL;
	int size = 0;
	int gcm = 0;
	int key_size = 0;
	struct buffer *aes_key = NULL;
	int retval = 1;

	switch (enc) {
	case JWE_ENC_A128CBC_HS256: gcm = 0; key_size = 16; break;
	case JWE_ENC_A192CBC_HS384: gcm = 0; key_size = 24; break;
	case JWE_ENC_A256CBC_HS512: gcm = 0; key_size = 32; break;
	case JWE_ENC_A128GCM: gcm = 1; key_size = 16; break;
	case JWE_ENC_A192GCM: gcm = 1; key_size = 24; break;
	case JWE_ENC_A256GCM: gcm = 1; key_size = 32; break;
	default: goto end;
	}

	/* Base64 decode cipher text */
	ciphertext = &decoded_items[JWE_ELT_CIPHERTEXT];
	*ciphertext = alloc_trash_chunk();
	if (!*ciphertext)
		goto end;
	size = base64urldec(items[JWE_ELT_CIPHERTEXT].start, items[JWE_ELT_CIPHERTEXT].length,
	                    (*ciphertext)->area, (*ciphertext)->size);
	if (size < 0)
		goto end;
	(*ciphertext)->data = size;

	/* Base64 decode Initialization Vector */
	iv = &decoded_items[JWE_ELT_IV];
	*iv = alloc_trash_chunk();
	if (!*iv)
		goto end;
	size = base64urldec(items[JWE_ELT_IV].start, items[JWE_ELT_IV].length,
	                    (*iv)->area, (*iv)->size);
	if (size < 0)
		goto end;
	(*iv)->data = size;

	/* Base64 decode Additional Data  */
	aead_tag = &decoded_items[JWE_ELT_TAG];
	*aead_tag = alloc_trash_chunk();
	if (!*aead_tag)
		goto end;
	size = base64urldec(items[JWE_ELT_TAG].start, items[JWE_ELT_TAG].length,
	                    (*aead_tag)->area, (*aead_tag)->size);
	if (size < 0)
		goto end;
	(*aead_tag)->data = size;

	if (gcm) {
		aad = alloc_trash_chunk();
		if (!aad)
			goto end;
		chunk_memcpy(aad, items[JWE_ELT_JOSE].start, items[JWE_ELT_JOSE].length);

		aes_key = decrypted_cek;
	} else {
		/* https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1
		 * Build the authentication tag out of the first part of the
		 * cipher key and a combination of information extracted from
		 * the JWE token.
		 */
		if (build_and_check_tag(enc, items, decoded_items, decrypted_cek))
			goto end;

		aes_key = alloc_trash_chunk();
		if (!aes_key)
			goto end;

		/* Only use the second part of the decrypted key for actual
		 * content decryption. */
		if (b_data(decrypted_cek) != key_size * 2)
			goto end;
		chunk_memcpy(aes_key, decrypted_cek->area + key_size, key_size);
	}

	*out = alloc_trash_chunk();
	if (!*out)
		goto end;

	size = aes_process(*ciphertext, *iv, aes_key, key_size*8, *aead_tag, aad, *out, 1, gcm);
	if (size < 0)
		goto end;

	retval = 0;

end:
	free_trash_chunk(aad);
	if (!gcm)
		free_trash_chunk(aes_key);
	return retval;
}

static inline void clear_decoded_items(struct buffer *decoded_items[JWE_ELT_MAX])
{
	struct buffer *buf = NULL;
	int idx = JWE_ELT_JOSE;

	while(idx != JWE_ELT_MAX) {
		buf = decoded_items[idx];
		free_trash_chunk(buf);

		++idx;
	}
}


/*
 * Decrypt the contents of a JWE token thanks to the user-provided base64
 * encoded secret. This converter can only be used for tokens that have a
 * symetric algorithm (AESKW, AESGCMKW or "dir" special case).
 * Returns the decrypted contents, or nothing if any error happened.
 */
static int sample_conv_jwt_decrypt_secret(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *input = NULL;
	unsigned int item_num = JWE_ELT_MAX;
	int retval = 0;
	struct jwt_item items[JWE_ELT_MAX] = {};
	struct buffer *decoded_items[JWE_ELT_MAX] = {};
	struct sample secret_smp;
	struct buffer *secret = NULL;
	struct buffer **cek = NULL;
	struct buffer *decrypted_cek = NULL;
	struct buffer *out = NULL;
	struct buffer *alg_tag = NULL;
	struct buffer *alg_iv = NULL;
	int size = 0;
	jwe_alg alg = JWE_ALG_UNMANAGED;
	jwe_enc enc = JWE_ENC_UNMANAGED;
	int gcm = 0;
	struct jose_fields fields = {};

	input = alloc_trash_chunk();
	if (!input)
		return 0;

	if (!chunk_cpy(input, &smp->data.u.str))
		goto end;

	if (jwt_tokenize(input, items, &item_num) || item_num != JWE_ELT_MAX)
		goto end;

	alg_tag = alloc_trash_chunk();
	if (!alg_tag)
		goto end;
	alg_iv = alloc_trash_chunk();
	if (!alg_iv)
		goto end;

	fields.tag = alg_tag;
	fields.iv = alg_iv;

	/* Base64Url decode the JOSE header */
	decoded_items[JWE_ELT_JOSE] = alloc_trash_chunk();
	if (!decoded_items[JWE_ELT_JOSE])
		goto end;
	size = base64urldec(items[JWE_ELT_JOSE].start, items[JWE_ELT_JOSE].length,
			    b_orig(decoded_items[JWE_ELT_JOSE]), b_size(decoded_items[JWE_ELT_JOSE]));
	if (size < 0)
		goto end;
	decoded_items[JWE_ELT_JOSE]->data = size;

	if (!parse_jose(decoded_items[JWE_ELT_JOSE], &alg, &enc, &fields))
		goto end;

	/* Check if "alg" fits secret-based JWEs */
	switch (alg) {
	case JWE_ALG_A128KW:
	case JWE_ALG_A192KW:
	case JWE_ALG_A256KW:
		gcm = 0;
		break;
	case JWE_ALG_A128GCMKW:
	case JWE_ALG_A192GCMKW:
	case JWE_ALG_A256GCMKW:
		gcm = 1;
		break;
	case JWE_ALG_DIR:
		break;
	default:
		/* Cannot use a secret for this type of "alg" */
		goto end;
	}

	/* Parse secret argument and base64dec it if it comes from a variable. */
	smp_set_owner(&secret_smp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_str(&args[0], &secret_smp))
		goto end;

	if (args[0].type == ARGT_VAR) {
		secret = alloc_trash_chunk();
		if (!secret)
			goto end;
		size = base64dec(secret_smp.data.u.str.area, secret_smp.data.u.str.data, secret->area, secret->size);
		if (size < 0)
			goto end;
		secret->data = size;
		secret_smp.data.u.str = *secret;
	}

	if (items[JWE_ELT_CEK].length) {
		int cek_size = 0;

		cek = &decoded_items[JWE_ELT_CEK];

		*cek = alloc_trash_chunk();
		if (!*cek)
			goto end;

		decrypted_cek = alloc_trash_chunk();
		if (!decrypted_cek) {
			goto end;
		}

		cek_size = base64urldec(items[JWE_ELT_CEK].start, items[JWE_ELT_CEK].length,
		                        (*cek)->area, (*cek)->size);
		if (cek_size < 0) {
			goto end;
		}
		(*cek)->data = cek_size;

		if (gcm) {
			if (!decrypt_cek_aesgcmkw(*cek, alg_tag, alg_iv, decrypted_cek, &secret_smp.data.u.str, alg))
				goto end;
		} else {
			if (!decrypt_cek_aeskw(*cek, decrypted_cek, &secret_smp.data.u.str, alg))
				goto end;
		}
	} else if (alg == JWE_ALG_DIR) {
		/* The secret given as parameter should be used directly to
		 * decode the encrypted content. */
		decrypted_cek = alloc_trash_chunk();
		if (!decrypted_cek)
			goto end;

		chunk_memcpy(decrypted_cek, secret_smp.data.u.str.area, secret_smp.data.u.str.data);
	}

	/* Decode the encrypted content thanks to decrypted_cek secret */
	if (decrypt_ciphertext(enc, items, decoded_items, decrypted_cek, &out))
		goto end;

	smp->data.u.str.data = b_data(out);
	smp->data.u.str.area = b_orig(out);
	smp->data.type = SMP_T_BIN;
	smp_dup(smp);

	retval = 1;

end:
	free_trash_chunk(input);
	free_trash_chunk(decrypted_cek);
	free_trash_chunk(out);
	free_trash_chunk(alg_tag);
	free_trash_chunk(alg_iv);
	clear_decoded_items(decoded_items);
	return retval;
}


/*
 * Decrypt the content of <cek> buffer into <decrypted_cek> buffer thanks to the
 * private key <pkey> using algorithm <crypt_alg> (RSA).
 * Returns 0 in case of success, 1 otherwise.
 */
static int do_decrypt_cek_rsa(struct buffer *cek, struct buffer *decrypted_cek,
                              EVP_PKEY *pkey, jwe_alg crypt_alg)
{
	EVP_PKEY_CTX *ctx = NULL;
	const EVP_MD *md = NULL;
	int retval = 1;
	int pad = 0;
	size_t outl = b_size(decrypted_cek);

	switch(crypt_alg) {
	case JWE_ALG_RSA1_5:
		pad = RSA_PKCS1_PADDING;
		md = EVP_sha1();
		break;
	case JWE_ALG_RSA_OAEP:
		pad = RSA_PKCS1_OAEP_PADDING;
		md = EVP_sha1();
		break;
	case JWE_ALG_RSA_OAEP_256:
		pad = RSA_PKCS1_OAEP_PADDING;
		md = EVP_sha256();
		break;
	default:
		goto end;
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);

	if (!ctx)
		goto end;

	if (EVP_PKEY_decrypt_init(ctx) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0)
		goto end;

	if (pad == RSA_PKCS1_OAEP_PADDING) {
		if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
			goto end;

		if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
			goto end;
	}

	if (EVP_PKEY_decrypt(ctx, (unsigned char*)b_orig(decrypted_cek), &outl,
			     (unsigned char*)b_orig(cek), b_data(cek)) <= 0)
		goto end;

	decrypted_cek->data = outl;

	retval = 0;

end:
	EVP_PKEY_CTX_free(ctx);
	return retval;
}


/*
 * Look for <cert> in the ckch_store tree and use its private key to decrypt
 * <cek> into <decrypted_cek> using <crypt_alg> algorithm (of the RSA alg
 * family).
 * Returns 0 in case of success, 1 otherwise.
 */
static int decrypt_cek_rsa(struct buffer *cek, struct buffer *decrypted_cek,
                           struct buffer *cert, jwe_alg crypt_alg)
{
	EVP_PKEY *pkey = NULL;
	int retval = 1;

	struct ckch_store *store = NULL;

	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		goto end;

	store = ckchs_lookup(b_orig(cert));
	if (!store || !store->data->key || !store->conf.jwt) {
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		goto end;
	}

	pkey = store->data->key;

	EVP_PKEY_up_ref(pkey);

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	if (do_decrypt_cek_rsa(cek, decrypted_cek, pkey, crypt_alg))
		goto end;

	retval = 0;
end:
	EVP_PKEY_free(pkey);
	return retval;
}


/*
 * Decrypt the contents of a JWE token thanks to the user-provided certificate
 * and private key. This converter can only be used for tokens that have an
 * asymetric algorithm (RSA only for now).
 * Returns the decrypted contents, or nothing if any error happened.
 */
static int sample_conv_jwt_decrypt_cert(const struct arg *args, struct sample *smp, void *private)
{
	struct sample cert_smp;
	struct buffer *input = NULL;
	unsigned int item_num = JWE_ELT_MAX;
	int retval = 0;
	struct jwt_item items[JWE_ELT_MAX] = {};
	struct buffer *decoded_items[JWE_ELT_MAX] = {};
	jwe_alg alg = JWE_ALG_UNMANAGED;
	jwe_enc enc = JWE_ENC_UNMANAGED;
	int rsa = 0;
	int size = 0;
	struct buffer *cert = NULL;
	struct buffer **cek = NULL;
	struct buffer *decrypted_cek = NULL;
	struct buffer *out = NULL;
	struct jose_fields fields = {};

	input = alloc_trash_chunk();
	if (!input)
		return 0;

	if (!chunk_cpy(input, &smp->data.u.str))
		goto end;

	if (jwt_tokenize(input, items, &item_num) || item_num != JWE_ELT_MAX)
		goto end;

	/* Base64Url decode the JOSE header */
	decoded_items[JWE_ELT_JOSE] = alloc_trash_chunk();
	if (!decoded_items[JWE_ELT_JOSE])
		goto end;
	size = base64urldec(items[JWE_ELT_JOSE].start, items[JWE_ELT_JOSE].length,
			    b_orig(decoded_items[JWE_ELT_JOSE]), b_size(decoded_items[JWE_ELT_JOSE]));
	if (size < 0)
		goto end;
	decoded_items[JWE_ELT_JOSE]->data = size;

	if (!parse_jose(decoded_items[JWE_ELT_JOSE], &alg, &enc, &fields))
		goto end;

	/* Check if "alg" fits certificate-based JWEs */
	switch (alg) {
	case JWE_ALG_RSA1_5:
	case JWE_ALG_RSA_OAEP:
	case JWE_ALG_RSA_OAEP_256:
		rsa = 1;
		break;
	default:
		/* Not managed yet */
		goto end;
	}

	cert = alloc_trash_chunk();
	if (!cert)
		goto end;

	smp_set_owner(&cert_smp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_str(&args[0], &cert_smp))
		goto end;
	if (chunk_printf(cert, "%.*s", (int)b_data(&cert_smp.data.u.str), b_orig(&cert_smp.data.u.str)) <= 0)
		goto end;

	/* With asymetric crypto algorithms we should always have a CEK */
	if (!items[JWE_ELT_CEK].length)
		goto end;

	cek = &decoded_items[JWE_ELT_CEK];

	*cek = alloc_trash_chunk();
	if (!*cek)
		goto end;

	decrypted_cek = alloc_trash_chunk();
	if (!decrypted_cek) {
		goto end;
	}

	size = base64urldec(items[JWE_ELT_CEK].start, items[JWE_ELT_CEK].length,
	                    (*cek)->area, (*cek)->size);
	if (size < 0) {
		goto end;
	}
	(*cek)->data = size;

	if (rsa && decrypt_cek_rsa(*cek, decrypted_cek, cert, alg))
		goto end;

	if (decrypt_ciphertext(enc, items, decoded_items, decrypted_cek, &out))
		goto end;

	smp->data.u.str.data = b_data(out);
	smp->data.u.str.area = b_orig(out);
	smp->data.type = SMP_T_BIN;
	smp_dup(smp);

	retval = 1;

end:
	free_trash_chunk(input);
	free_trash_chunk(cert);
	free_trash_chunk(decrypted_cek);
	free_trash_chunk(out);
	clear_decoded_items(decoded_items);
	return retval;
}

/* "jwt_decrypt_cert" converter check function.
 * The first and only parameter should be a path to a pem certificate or a
 * variable holding a path to a pem certificate. The certificate must already
 * exist in the certificate store.
 * This converter will be used for JWEs with an RSA type "alg" field in their
 * JOSE header.
 */
static int sample_conv_jwt_decrypt_cert_check(struct arg *args, struct sample_conv *conv,
                                              const char *file, int line, char **err)
{
	vars_check_arg(&args[0], NULL);

	if (args[0].type == ARGT_STR) {
		struct ckch_store *store = NULL;

		if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
			return 0;
		store = ckchs_lookup(args[0].data.str.area);
		if (!store) {
			memprintf(err, "unknown certificate %s", args[0].data.str.area);
			HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
			return 0;
		} else if (!store->conf.jwt) {
			memprintf(err, "unusable certificate %s (\"jwt\" option not set to \"on\")", args[0].data.str.area);
			HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
			return 0;
		}
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	}

	return 1;
}

/* "jwt_decrypt_secret" converter check function.
 * The first and only parameter should be a base64 encoded secret or a variable
 * holding a base64 encoded secret. This converter will be used mainly for JWEs
 * with an AES type "alg" field in their JOSE header.
 */
static int sample_conv_jwt_decrypt_secret_check(struct arg *args, struct sample_conv *conv,
                                                const char *file, int line, char **err)
{
	/* Try to decode variables. */
	if (!sample_check_arg_base64(&args[0], err)) {
		memprintf(err, "failed to parse secret: %s", *err);
		return 0;
	}

	return 1;
}


/*
 * Convert a base64url encoded buffer into a BIGNUM.
 */
static BIGNUM *base64url_to_BIGNUM(struct buffer *b64url_buf)
{
	BIGNUM *bn = NULL;
	struct buffer *decoded = get_trash_chunk();
	int size = 0;

	if (!b64url_buf)
		return NULL;

	size = base64urldec(b_orig(b64url_buf), b_data(b64url_buf),
			    b_orig(decoded), b_size(decoded));
	if (size < 0)
		return NULL;
	decoded->data = size;

	bn = BN_bin2bn((const unsigned char *)b_orig(decoded), b_data(decoded), NULL);

	return bn;
}

/*
 * Extract a field named <field> of type string out of the <jwk> JSON buffer and
 * dump its value in <out>.
 * Return 0 in case of success, 1 in case of error (JSON parsing error or value
 * not found).
 */
static int get_jwk_field(struct buffer *jwk, const char *field, struct buffer *out)
{
	int size = 0;

	chunk_reset(out);

	size = mjson_get_string(b_orig(jwk), b_data(jwk), field,
				b_orig(out), b_size(out));
	if (size == -1)
		return 1;

	out->data = size;
	return 0;
}

enum {
	RSA_BIGNUM_N,
	RSA_BIGNUM_E,
	RSA_BIGNUM_D,
	RSA_BIGNUM_P,
	RSA_BIGNUM_Q,
	RSA_BIGNUM_DP,
	RSA_BIGNUM_DQ,
	RSA_BIGNUM_QI,

	RSA_BIGNUM_COUNT
};


/*
 * Build the EVP_PKEY out of the BIGNUMs parsed by the caller.
 * The RSA_set0_ functions were deprecated in OpenSSL3, hence the two different
 * code blocks.
 * Returns 0 in case of success, 1 otherwise.
 */
static int do_build_RSA_PKEY(BIGNUM *nums[RSA_BIGNUM_COUNT], EVP_PKEY **pkey)
#if HA_OPENSSL_VERSION_NUMBER >= 0x30000000L
{
	int retval = 1;
	OSSL_PARAM *params = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	EVP_PKEY_CTX *pctx = NULL;

	param_bld = OSSL_PARAM_BLD_new();

	if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, nums[RSA_BIGNUM_N]) ||
	    !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, nums[RSA_BIGNUM_E]) ||
	    !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, nums[RSA_BIGNUM_D]) ||
	    !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR1, nums[RSA_BIGNUM_P]) ||
	    !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR2, nums[RSA_BIGNUM_Q]) ||
	    !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, nums[RSA_BIGNUM_DP]) ||
	    !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, nums[RSA_BIGNUM_DQ]) ||
	    !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, nums[RSA_BIGNUM_QI]))
		goto end;

	params = OSSL_PARAM_BLD_to_param(param_bld);

	if (!params)
		goto end;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!pctx)
		goto end;
	if (EVP_PKEY_fromdata_init(pctx) != 1)
		goto end;

	if (EVP_PKEY_fromdata(pctx, pkey, EVP_PKEY_KEYPAIR, params) != 1)
		goto end;

	retval = 0;
end:
	OSSL_PARAM_BLD_free(param_bld);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(pctx);

	return retval;
}
#else /* HA_OPENSSL_VERSION_NUMBER < 0x30000000L */
{
	int retval = 1;
	RSA *rsa = NULL;

	rsa = RSA_new();
	if (!rsa)
		goto end;

	if (RSA_set0_key(rsa, nums[RSA_BIGNUM_N], nums[RSA_BIGNUM_E], nums[RSA_BIGNUM_D]) != 1 ||
	    RSA_set0_factors(rsa, nums[RSA_BIGNUM_P], nums[RSA_BIGNUM_Q]) != 1 ||
	    RSA_set0_crt_params(rsa, nums[RSA_BIGNUM_DP], nums[RSA_BIGNUM_DQ], nums[RSA_BIGNUM_QI]) != 1)
		goto end;

	*pkey = EVP_PKEY_new();
	if (!*pkey)
		goto end;

	if (EVP_PKEY_set1_RSA(*pkey, rsa) != 1)
		goto end;

	retval = 0;
end:
	RSA_free(rsa);
	return retval;
}
#endif

static inline void clear_bignums(BIGNUM *nums[RSA_BIGNUM_COUNT])
{
	int idx = 0;

	while (idx < RSA_BIGNUM_COUNT)
		BN_free(nums[idx++]);
}

/*
 * Build an EVP_PKEY that contains an RSA private key out of a JWK buffer that
 * must have an "RSA" key type ("kty" field).
 * Return 0 in case of success, 1 otherwise.
 */
static int build_RSA_PKEY_from_buf(struct buffer *jwk, EVP_PKEY **pkey)
{
	BIGNUM *nums[RSA_BIGNUM_COUNT] = {};
	int retval = 1;

	struct buffer *tmpbuf = alloc_trash_chunk();

	if (!tmpbuf)
		goto end;

	/*
	 * Extract all the mandatory fields that all represent BIGNUMs out of
	 * the JWK buffer.
	 */
	if (get_jwk_field(jwk, "$.n", tmpbuf) || (nums[RSA_BIGNUM_N] = base64url_to_BIGNUM(tmpbuf)) == NULL)
		goto end;
	if (get_jwk_field(jwk, "$.e", tmpbuf) || (nums[RSA_BIGNUM_E] = base64url_to_BIGNUM(tmpbuf)) == NULL)
		goto end;
	if (get_jwk_field(jwk, "$.d", tmpbuf) || (nums[RSA_BIGNUM_D] = base64url_to_BIGNUM(tmpbuf)) == NULL)
		goto end;
	if (get_jwk_field(jwk, "$.p", tmpbuf) || (nums[RSA_BIGNUM_P] = base64url_to_BIGNUM(tmpbuf)) == NULL)
		goto end;
	if (get_jwk_field(jwk, "$.q", tmpbuf) || (nums[RSA_BIGNUM_Q] = base64url_to_BIGNUM(tmpbuf)) == NULL)
		goto end;
	if (get_jwk_field(jwk, "$.dp", tmpbuf) || (nums[RSA_BIGNUM_DP] = base64url_to_BIGNUM(tmpbuf)) == NULL)
		goto end;
	if (get_jwk_field(jwk, "$.dq", tmpbuf) || (nums[RSA_BIGNUM_DQ] = base64url_to_BIGNUM(tmpbuf)) == NULL)
		goto end;
	if (get_jwk_field(jwk, "$.qi", tmpbuf) || (nums[RSA_BIGNUM_QI] = base64url_to_BIGNUM(tmpbuf)) == NULL)
		goto end;

	retval = do_build_RSA_PKEY(nums, pkey);

end:
	/* The bignums are duplicated with OpenSSL3+ but not with the older API */
#if HA_OPENSSL_VERSION_NUMBER >= 0x30000000L
	clear_bignums(nums);
#else
	if (retval)
		clear_bignums(nums);
#endif

	free_trash_chunk(tmpbuf);
	if (retval) {
		EVP_PKEY_free(*pkey);
		*pkey = NULL;
	}

	return retval;
}



typedef enum {
	JWK_KTY_OCT,
	JWK_KTY_RSA,
// 	JWK_KTY_EC
} jwk_type;

struct jwk {
	jwk_type type;
	struct buffer *kid;
	union {
		EVP_PKEY *pkey;
		struct buffer *secret;
	};
};

static void clear_jwk(struct jwk *jwk)
{
	if (!jwk)
		return;

	free_trash_chunk(jwk->kid);
	jwk->kid = NULL;

	switch (jwk->type) {
	case JWK_KTY_OCT:
		free_trash_chunk(jwk->secret);
		jwk->secret = NULL;
		break;
	case JWK_KTY_RSA:
		EVP_PKEY_free(jwk->pkey);
		jwk->pkey = NULL;
		break;
	default:
		break;
	}
}


/*
 * Convert a JWK in buffer <jwk_buf> into either an RSA private key stored in an
 * EVP_PKEY or a secret (for symmetric algorithms).
 * Returns 0 in case of success, 1 otherwise.
 */
static int process_jwk(struct buffer *jwk_buf, struct jwk *jwk)
{
	struct buffer *kty = NULL;
	int retval = 1;

	kty = get_trash_chunk();
	if (get_jwk_field(jwk_buf, "$.kty", kty))
		goto end;

	/* Look for optional "kid" field */
	jwk->kid = alloc_trash_chunk();
	if (!jwk->kid)
		goto end;
	get_jwk_field(jwk_buf, "$.kid", jwk->kid);

	if (chunk_strcmp(kty, "oct") == 0) {
		struct buffer *tmpbuf = get_trash_chunk();
		int size = 0;

		jwk->type = JWK_KTY_OCT;

		jwk->secret = alloc_trash_chunk();
		if (!jwk->secret)
			goto end;

		if (get_jwk_field(jwk_buf, "$.k", tmpbuf))
			goto end;

		size = base64urldec(b_orig(tmpbuf), b_data(tmpbuf),
				    b_orig(jwk->secret), b_size(jwk->secret));
		if (size < 0) {
			goto end;
		}
		jwk->secret->data = size;

	} else if (chunk_strcmp(kty, "RSA") == 0) {
		jwk->type = JWK_KTY_RSA;

		if (build_RSA_PKEY_from_buf(jwk_buf, &jwk->pkey))
			goto end;
	} else
		goto end;

	retval = 0;

end:
	if (retval)
		clear_jwk(jwk);
	return retval;
}


static int sample_conv_jwt_decrypt_check(struct arg *args, struct sample_conv *conv,
                                         const char *file, int line, char **err)
{
	vars_check_arg(&args[0], NULL);

	if (args[0].type == ARGT_STR) {
		EVP_PKEY *pkey = NULL;
		struct buffer *trash = get_trash_chunk();

		if (get_jwk_field(&args[0].data.str, "$.kty", trash) == 0) {
			if (chunk_strcmp(trash, "oct") == 0) {
				struct buffer *key = get_trash_chunk();
				if (get_jwk_field(&args[0].data.str, "$.k", key)) {
					memprintf(err, "Missing 'k' field in JWK");
					return 0;
				}
			} else if (chunk_strcmp(trash, "RSA") == 0) {
				if (build_RSA_PKEY_from_buf(&args[0].data.str, &pkey)) {
					memprintf(err, "Failed to parse JWK");
					return 0;
				}
				EVP_PKEY_free(pkey);
			} else {
				memprintf(err, "Unmanaged key type (expected 'oct' or 'RSA'");
				return 0;
			}
		} else {
			memprintf(err, "Missing key type (expected 'oct' or 'RSA')");
			return 0;
		}
	}

	return 1;
}


/*
 * Decrypt the contents of a JWE token thanks to the user-provided JWK that can
 * either contain an RSA private key or a secret.
 * Returns the decrypted contents, or nothing if any error happened.
 */
static int sample_conv_jwt_decrypt(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *input = NULL;
	unsigned int item_num = JWE_ELT_MAX;
	struct sample jwk_smp;
	struct jwt_item items[JWE_ELT_MAX] = {};
	struct buffer *decoded_items[JWE_ELT_MAX] = {};
	jwe_alg alg = JWE_ALG_UNMANAGED;
	jwe_enc enc = JWE_ENC_UNMANAGED;
	int size = 0;
	int rsa = 0;
	int dir = 0;
	int gcm = 0;
	int oct = 0;
	int retval = 0;
	struct buffer **cek = NULL;
	struct buffer *decrypted_cek = NULL;
	struct buffer *out = NULL;
	struct jose_fields fields = {};

	struct buffer *alg_tag = NULL;
	struct buffer *alg_iv = NULL;

	struct buffer *jwk_buf = NULL;
	struct jwk jwk = {};

	smp_set_owner(&jwk_smp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_str(&args[0], &jwk_smp))
		goto end;

	/* Copy JWK parameter */
	jwk_buf = alloc_trash_chunk();
	if (!jwk_buf)
		goto end;
	if (!chunk_cpy(jwk_buf, &jwk_smp.data.u.str))
		goto end;

	/* Copy JWE input token */
	input = alloc_trash_chunk();
	if (!input)
		goto end;
	if (!chunk_cpy(input, &smp->data.u.str))
		goto end;

	if (jwt_tokenize(input, items, &item_num) || item_num != JWE_ELT_MAX)
		goto end;

	alg_tag = alloc_trash_chunk();
	if (!alg_tag)
		goto end;
	alg_iv = alloc_trash_chunk();
	if (!alg_iv)
		goto end;

	fields.tag = alg_tag;
	fields.iv = alg_iv;

	/* Base64Url decode the JOSE header */
	decoded_items[JWE_ELT_JOSE] = alloc_trash_chunk();
	if (!decoded_items[JWE_ELT_JOSE])
		goto end;
	size = base64urldec(items[JWE_ELT_JOSE].start, items[JWE_ELT_JOSE].length,
			    b_orig(decoded_items[JWE_ELT_JOSE]), b_size(decoded_items[JWE_ELT_JOSE]));
	if (size < 0)
		goto end;
	decoded_items[JWE_ELT_JOSE]->data = size;

	if (!parse_jose(decoded_items[JWE_ELT_JOSE], &alg, &enc, &fields))
		goto end;

	/* Check if "alg" fits certificate-based JWEs */
	switch (alg) {
	case JWE_ALG_RSA1_5:
	case JWE_ALG_RSA_OAEP:
	case JWE_ALG_RSA_OAEP_256:
		rsa = 1;
		break;
	case JWE_ALG_A128KW:
	case JWE_ALG_A192KW:
	case JWE_ALG_A256KW:
		gcm = 0;
		oct = 1;
		break;
	case JWE_ALG_A128GCMKW:
	case JWE_ALG_A192GCMKW:
	case JWE_ALG_A256GCMKW:
		gcm = 1;
		oct = 1;
		break;
	case JWE_ALG_DIR:
		dir = 1;
		oct = 1;
		break;
	default:
		/* Not managed yet */
		goto end;
	}

	/* Parse JWK argument. */
	if (process_jwk(jwk_buf, &jwk))
		goto end;

	/* Check that the provided JWK is of the proper type */
	if ((oct && jwk.type != JWK_KTY_OCT) ||
	    (rsa && jwk.type != JWK_KTY_RSA))
		goto end;

	if (dir) {
		/* The secret given as parameter should be used directly to
		 * decode the encrypted content. */
		decrypted_cek = alloc_trash_chunk();
		if (!decrypted_cek)
			goto end;

		chunk_memcpy(decrypted_cek, b_orig(jwk.secret), b_data(jwk.secret));
	} else {
		/* With algorithms other than "dir" we should always have a CEK */
		if (!items[JWE_ELT_CEK].length)
			goto end;

		cek = &decoded_items[JWE_ELT_CEK];

		*cek = alloc_trash_chunk();
		if (!*cek)
			goto end;

		decrypted_cek = alloc_trash_chunk();
		if (!decrypted_cek) {
			goto end;
		}

		size = base64urldec(items[JWE_ELT_CEK].start, items[JWE_ELT_CEK].length,
				    (*cek)->area, (*cek)->size);
		if (size < 0) {
			goto end;
		}
		(*cek)->data = size;

		if (rsa) {
			if (do_decrypt_cek_rsa(*cek, decrypted_cek, jwk.pkey, alg))
				goto end;
		} else {
			if (gcm) {
				if (!decrypt_cek_aesgcmkw(*cek, alg_tag, alg_iv, decrypted_cek, jwk.secret, alg))
					goto end;
			} else {
				if (!decrypt_cek_aeskw(*cek, decrypted_cek, jwk.secret, alg))
					goto end;
			}
		}
	}

	if (decrypt_ciphertext(enc, items, decoded_items, decrypted_cek, &out))
		goto end;

	smp->data.u.str.data = b_data(out);
	smp->data.u.str.area = b_orig(out);
	smp->data.type = SMP_T_BIN;
	smp_dup(smp);

	retval = 1;

end:
	clear_jwk(&jwk);
	free_trash_chunk(jwk_buf);
	free_trash_chunk(input);
	free_trash_chunk(decrypted_cek);
	free_trash_chunk(out);
	free_trash_chunk(alg_tag);
	free_trash_chunk(alg_iv);
	clear_decoded_items(decoded_items);
	return retval;
}


static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	/* JSON Web Token converters */
	{ "jwt_decrypt_secret",    sample_conv_jwt_decrypt_secret, ARG1(1,STR), sample_conv_jwt_decrypt_secret_check, SMP_T_BIN, SMP_T_BIN },
	{ "jwt_decrypt_cert",      sample_conv_jwt_decrypt_cert,   ARG1(1,STR), sample_conv_jwt_decrypt_cert_check,   SMP_T_BIN, SMP_T_BIN },
	{ "jwt_decrypt",           sample_conv_jwt_decrypt,        ARG1(1,STR), sample_conv_jwt_decrypt_check,        SMP_T_BIN, SMP_T_BIN },
	{ NULL, NULL, 0, 0, 0 },

}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);

#endif /* USE_OPENSSL */

#endif /* HAVE_JWS */

