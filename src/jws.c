/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>

#include <haproxy/base64.h>
#include <haproxy/chunk.h>
#include <haproxy/init.h>
#include <haproxy/openssl-compat.h>

#if defined(HAVE_JWS)

/*
 * Convert an OpenSSL BIGNUM to a base64url representation
 * Fill a buffer <dst> of <dsize> max size
 *
 * Return the size of the data dumped in <dst>
 */
int bn2base64url(const BIGNUM *bn, char *dst, size_t dsize)
{
	struct buffer *bin;
	int binlen;
	int ret = 0;

	if ((bin = get_trash_chunk()) == NULL)
		goto out;

	binlen = BN_num_bytes(bn);
	if (binlen > bin->size)
		goto out;

	if (BN_bn2bin(bn, (unsigned char *)bin->area) != binlen)
		goto out;

	ret = a2base64url(bin->area, binlen, dst, dsize);
out:
	return ret;
}

/* https://datatracker.ietf.org/doc/html/rfc8422#appendix-A */
/* SECG to NIST curves name */
static struct curves { char *name; int nid; } curves_list [] =
{
	{ "secp256r1",  NID_X9_62_prime256v1 },
	{ "prime256v1", NID_X9_62_prime256v1 },
	{ "P-256",      NID_X9_62_prime256v1 },

	{ "secp384r1",  NID_secp384r1 },
	{ "P-384",      NID_secp384r1 },

	{ "secp521r1",  NID_secp521r1 },
	{ "P-521",      NID_secp521r1 },
	{ NULL,         0 },
};

/* convert a curves name to a openssl NID */
int curves2nid(const char *curve)
{
	struct curves *curves = curves_list;

	while (curves->name) {
		if (strcmp(curve, curves->name) == 0)
			return curves->nid;
		curves++;
	}
	return -1;
}

/* convert an OpenSSL NID to a NIST curves name */
const char *nid2nist(int nid)
{
	switch (nid) {
		case NID_X9_62_prime256v1: return "P-256";
		case NID_secp384r1:        return "P-384";
		case NID_secp521r1:        return "P-521";
		default:                   return NULL;
	}
}


/*
 * Convert a EC <pkey> to a public key JWK
 * Fill a buffer <dst> of <dsize> max size
 *
 * Return the size of the data or 0
 */
static int EVP_PKEY_EC_to_pub_jwk(EVP_PKEY *pkey, char *dst, size_t dsize)
{
	BIGNUM *x = NULL, *y = NULL;
	struct buffer *str_x = NULL, *str_y = NULL;
	int ret = 0;
	const char *crv = NULL;

#if HA_OPENSSL_VERSION_NUMBER > 0x30000000L
	char curve[32] = {};
	size_t curvelen;
	int nid;

	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y);

	if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve, sizeof(curve), &curvelen) == 0)
		goto out;

	crv = curve;

	/* convert to NIST format */
	nid = curves2nid(curve);
	if (nid > 0) {
		crv = nid2nist(nid);
		if (crv == NULL)
			crv = curve;
	}
#else
	const EC_KEY *ec = NULL;
	const EC_GROUP *ec_group = NULL;
	const EC_POINT *ec_point = NULL;

	/* get EC from EVP */
	if ((ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL)
		goto out;
	if ((ec_group = EC_KEY_get0_group(ec)) == NULL)
		goto out;
	if ((ec_point = EC_KEY_get0_public_key(ec)) == NULL)
		goto out;

	/* get group, point, x, y */
	if ((x = BN_new()) == NULL)
		goto out;
	if ((y = BN_new()) == NULL)
		goto out;
	if ((EC_POINT_get_affine_coordinates(ec_group, ec_point, x, y, NULL)) == 0)
		goto out;
	if ((crv = EC_curve_nid2nist(EC_GROUP_get_curve_name(ec_group))) == NULL)
		goto out;
#endif

	/* allocate trash */
	if ((str_x = alloc_trash_chunk()) == NULL)
		goto out;
	if ((str_y = alloc_trash_chunk()) == NULL)
		goto out;

	/* convert x, y to base64url */
	str_x->data = bn2base64url(x, str_x->area, str_x->size);
	str_y->data = bn2base64url(y, str_y->area, str_y->size);
	if (str_x->data == 0 || str_y->data == 0)
		goto out;

	ret = snprintf(dst, dsize, "{\n"
			"    \"kty\": \"%s\",\n"
			"    \"crv\": \"%s\",\n"
			"    \"x\":   \"%s\",\n"
			"    \"y\":   \"%s\"\n"
			"}\n",
			"EC", crv, str_x->area, str_y->area);
	if (ret >= dsize)
		ret = 0;

out:
	free_trash_chunk(str_x);
	free_trash_chunk(str_y);

	BN_free(x);
	BN_free(y);

	return ret;
}

/*
 * Convert a RSA <pkey> to a public key JWK
 * Fill a buffer <dst> of <dsize> max size
 *
 * Return the size of the data or 0
 */
static int EVP_PKEY_RSA_to_pub_jwk(EVP_PKEY *pkey, char *dst, size_t dsize)
{
	BIGNUM *n = NULL, *e = NULL;
	struct buffer *str_n = NULL, *str_e = NULL;
	int ret = 0;

#if HA_OPENSSL_VERSION_NUMBER > 0x30000000L

	if ((EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n)) == 0)
		goto out;
	if ((EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) == 0)
		goto out;
#else
	const RSA *rsa;

	if ((rsa = EVP_PKEY_get0_RSA(pkey)) == NULL)
		goto out;
	if ((n = (BIGNUM *)BN_dup(RSA_get0_n(rsa))) == NULL)
		goto out;
	if ((e = (BIGNUM *)BN_dup(RSA_get0_e(rsa))) == NULL)
		goto out;
#endif

	/* allocate trash */
	if ((str_n = alloc_trash_chunk()) == NULL)
		goto out;
	if ((str_e = alloc_trash_chunk()) == NULL)
		goto out;

	/* convert n, e to base64url */
	str_n->data = bn2base64url(n, str_n->area, str_n->size);
	str_e->data = bn2base64url(e, str_e->area, str_e->size);
	if (str_n->data == 0 || str_e->data == 0)
		goto out;

	ret = snprintf(dst, dsize, "{\n"
			"    \"kty\": \"%s\",\n"
			"    \"n\":   \"%s\",\n"
			"    \"e\":   \"%s\"\n"
			"}\n",
			"RSA", str_n->area, str_e->area);
	if (ret >= dsize)
		ret = 0;

out:
	BN_free(n);
	BN_free(e);
	free_trash_chunk(str_n);
	free_trash_chunk(str_e);

	return ret;
}

/* Convert an EVP_PKEY to a public key JWK
 * Fill a buffer <dst> of <dsize> max size
 *
 * Return the size of the data or 0
 */
int EVP_PKEY_to_pub_jwk(EVP_PKEY *pkey, char *dst, size_t dsize)
{
	int ret = 0;

	switch (EVP_PKEY_base_id(pkey)) {
		case EVP_PKEY_RSA:
			ret = EVP_PKEY_RSA_to_pub_jwk(pkey, dst, dsize);
			break;
		case EVP_PKEY_EC:
			ret = EVP_PKEY_EC_to_pub_jwk(pkey, dst, dsize);
			break;
		default:
			break;
	}
	return ret;
}


/*
 * Generate the JWS payload and converts it to base64url.
 * Use either <kid> or <jwk>, but won't use both
 *
 * Return the size of the data or 0
 */

int jws_b64_protected(const char *alg, char *kid, char *jwk, char *nonce, char *url,
                      char *dst, size_t dsize)
{
	char *acc;
	char *acctype;
	int ret = 0;
	struct buffer *json = NULL;

	if ((json = alloc_trash_chunk()) == NULL)
		goto out;

	/* kid or jwk ? */
	acc = kid ? kid : jwk;
	acctype = kid ? "kid" : "jwk";

	ret = snprintf(json->area, json->size, "{\n"
			"    \"alg\": \"%s\",\n"
			"    \"%s\":  %s%s%s,\n"
			"    \"nonce\":   \"%s\",\n"
			"    \"url\":   \"%s\"\n"
			"}\n",
			alg, acctype, kid ? "\"" : "", acc, kid ? "\"" : "", nonce, url);
	if (ret >= json->size) {
		ret = 0;
		goto out;
	}


	json->data = ret;

	ret = a2base64url(json->area, json->data, dst, dsize);
out:
	free_trash_chunk(json);
	return ret;
}

/*
 * Converts the JWS payload to base64url
 *
 * Return the size of the data or 0
 */

int jws_b64_payload(char *payload, char *dst, size_t dsize)
{
	int ret = 0;

	ret = a2base64url(payload, strlen(payload), dst, dsize);

	return ret;
}

/*
 * Generate a JWS signature using the base64url protected buffer and the base64url payload buffer
 *
 *  For RSA it uses the RS256 algorithm (EVP_sha256)
 *  For ECDSA, the ES256, ES384 or ES512 is chosen depending on the curves of the key
 *
 *  Return the size of the data or 0
 */
int jws_b64_signature(EVP_PKEY *pkey, char *b64protected, char *b64payload, char *dst, size_t dsize)
{
	EVP_MD_CTX *ctx;
	const EVP_MD *evp_md = NULL;
	int ret = 0;
	struct buffer *sign = NULL;
	size_t out_sign_len = 0;

	if ((sign = alloc_trash_chunk()) == NULL)
		goto out;

	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
#if HA_OPENSSL_VERSION_NUMBER > 0x30000000L
		char curve[32] = {};
		size_t curvelen;
		int nid;

		if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve, sizeof(curve), &curvelen) == 0)
			goto out;

		nid = curves2nid(curve);

#else
		const EC_KEY *ec = NULL;
		const EC_GROUP *ec_group = NULL;
		int nid = -1;

		if ((ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL)
			goto out;
		if ((ec_group = EC_KEY_get0_group(ec)) == NULL)
			goto out;

		nid = EC_GROUP_get_curve_name(ec_group);
#endif

		/* https://www.rfc-editor.org/rfc/rfc7518#section-3.1 */
		switch (nid) {
			/* ES256: ECDSA using P-256 and SHA-256 */
			case NID_X9_62_prime256v1:
				evp_md = EVP_sha256();
				break;
			/* ES384: ECDSA using P-384 and SHA-384 */
			case NID_secp384r1:
				evp_md = EVP_sha384();
				break;
			/* ES512: ECDSA using P-521 and SHA-512 */
			case NID_secp521r1:
				evp_md = EVP_sha512();
				break;
			default:
				evp_md = NULL;
				break;
		}

	} else {
		evp_md = EVP_sha256();
	}

	if ((ctx = EVP_MD_CTX_new()) == NULL)
		goto out;

	if (EVP_DigestSignInit(ctx, NULL, evp_md, NULL, pkey) == 0)
		goto out;

	if (EVP_DigestSignUpdate(ctx, b64protected, strlen(b64protected)) == 0)
		goto out;

	if (EVP_DigestSignUpdate(ctx, ".", 1) == 0)
		goto out;

	if (EVP_DigestSignUpdate(ctx, b64payload, strlen(b64payload)) == 0)
		goto out;

	if (EVP_DigestSignFinal(ctx, NULL, &out_sign_len) == 0)
		goto out;

	if (out_sign_len > sign->size)
		goto out;

	if (EVP_DigestSignFinal(ctx, (unsigned char *)sign->area, &out_sign_len) == 0)
		goto out;

	sign->data = out_sign_len;


	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
		/* Convert the DigestSign output to an ECDSA_SIG (R and S parameters concatenatedi,
		 * see section 3.4 of RFC7518), and output R and S padded.
		 */
		ECDSA_SIG *sig = NULL;
		const BIGNUM *r = NULL, *s = NULL;
		int bignum_len;

		/* need to pad to byte size, essentialy for P-521 */
		bignum_len = (EVP_PKEY_bits(pkey) + 7) / 8;

		if ((sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&sign->area, sign->data)) == NULL)
			goto out;

		if ((r = ECDSA_SIG_get0_r(sig)) == NULL)
			goto out;

		if ((s = ECDSA_SIG_get0_s(sig)) == NULL)
			goto out;

		if (BN_bn2binpad(r, (unsigned char *)sign->area, bignum_len) != bignum_len)
			goto out;

		if (BN_bn2binpad(s, (unsigned char *)sign->area + bignum_len, bignum_len) != bignum_len)
			goto out;

		sign->data = bignum_len * 2;

	}

	/* Then encode the whole thing in base64url */
	ret = a2base64url(sign->area, sign->data, dst, dsize);

out:
	free_trash_chunk(sign);

	return ret;

}

int jws_flattened(char *protected, char *payload, char *signature, char *dst, size_t dsize)
{
	int ret = 0;

	ret = snprintf(dst, dsize, "{\n"
			"    \"protected\": \"%s\",\n"
			"    \"payload\":   \"%s\",\n"
			"    \"signature\": \"%s\"\n"
			"}\n",
			protected, payload, signature);

	if (ret >= dsize)
		ret = 0;
	return ret;
}

int jwk_debug(int argc, char **argv)
{
	FILE *f = NULL;
	EVP_PKEY *pkey = NULL;
	char msg[1024];
	int ret = 1;
	const char *filename;

	if (argc < 1)
		goto out;

	filename = argv[1];

	if ((f = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "fopen!\n");
		goto out;
	}
	if ((pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		fprintf(stderr, "PEM_read_PrivateKey!\n");
		goto out;
	}

	ret = !EVP_PKEY_to_pub_jwk(pkey, msg, sizeof(msg));
	fprintf(stdout, "%s\n", msg);

	EVP_PKEY_free(pkey);
out:

	return ret;
}

static void __jws_init(void)
{
	hap_register_unittest("jwk", jwk_debug);
}


INITCALL0(STG_REGISTER, __jws_init);

#endif /* HAVE_JWS */

