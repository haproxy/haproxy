/* SPDX-License-Identifier: GPL-2.0-or-later */

/* FIPS compliance checks for AWS-LC builds */

#include <stdlib.h>

#include <openssl/ec.h>

#include <haproxy/errors.h>
#include <haproxy/obj_type.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/tools.h>

/* FIPS-approved bulk cipher NIDs (TLS 1.2).  NID_undef terminates the list.
 * DHE and CCM entries are FIPS-approved but not implemented by AWS-LC. */
static const int fips_approved_cipher_nids[] = {
	NID_aes_128_gcm,
	NID_aes_256_gcm,
	NID_aes_128_ccm,
	NID_aes_256_ccm,
	NID_undef
};

/* FIPS-approved elliptic curve NIDs (NIST P-curves).  NID_undef terminates the list. */
static const int fips_approved_curve_nids[] = {
	NID_X9_62_prime256v1,  /* P-256 */
	NID_secp384r1,          /* P-384 */
	NID_secp521r1,          /* P-521 */
	NID_undef
};

/* FIPS-approved signature algorithm names.  NULL terminates the list. */
static const char *fips_approved_sigalgs[] = {
	"ecdsa_secp256r1_sha256",
	"ecdsa_secp384r1_sha384",
	"ecdsa_secp521r1_sha512",
	"rsa_pss_rsae_sha256",
	"rsa_pss_rsae_sha384",
	"rsa_pss_rsae_sha512",
	"rsa_pss_pss_sha256",
	"rsa_pss_pss_sha384",
	"rsa_pss_pss_sha512",
	"rsa_pkcs1_sha256",
	"rsa_pkcs1_sha384",
	"rsa_pkcs1_sha512",
	NULL
};

/* FIPS-approved TLS 1.3 ciphersuite names.  NULL terminates the list.
 * TLS_AES_128_CCM_SHA256 is FIPS-approved but not implemented by AWS-LC. */
static const char *fips_approved_ciphersuites[] = {
	"TLS_AES_128_GCM_SHA256",
	"TLS_AES_256_GCM_SHA384",
	"TLS_AES_128_CCM_SHA256",
	NULL
};

/* Fill display fields from <obj> for use in error messages. */
static void fips_obj_info(const enum obj_type *obj,
                          const char **proxy_name, const char **type_str,
                          const char **obj_name,
                          const char **file, int *line)
{
	switch (obj_type(obj)) {
	case OBJ_TYPE_SERVER: {
		struct server *s = objt_server((enum obj_type *)obj);
		*proxy_name = s->proxy->id ? s->proxy->id : "-";
		*type_str   = "server";
		*obj_name   = s->id ? s->id : "-";
		*file       = s->conf.file;
		*line       = s->conf.line;
		break;
	}
	case OBJ_TYPE_LISTENER: {
		struct listener *li = objt_listener((enum obj_type *)obj);
		*proxy_name = li->bind_conf->frontend->id ? li->bind_conf->frontend->id : "-";
		*type_str   = "bind";
		*obj_name   = li->bind_conf->arg ? li->bind_conf->arg : "-";
		*file       = li->bind_conf->file;
		*line       = li->bind_conf->line;
		break;
	}
	default:
		*proxy_name = *type_str = *obj_name = *file = NULL;
		*line = 0;
		break;
	}
}

/* Check that the signature algorithm list <sigalgs> is FIPS-compliant. */
int ssl_fips_check_sigalgs(const char *sigalgs, const enum obj_type *obj)
{
	const char *proxy_name, *type_str, *obj_name, *file;
	const char *p, *end;
	char *list = NULL;
	int i, line;
	size_t len;

	if (!FIPS_mode() || !sigalgs)
		return 0;

	p = sigalgs;
	while (p && *p) {
		end = strchr(p, ':');
		len = end ? (size_t)(end - p) : strlen(p);

		for (i = 0; fips_approved_sigalgs[i]; i++) {
			if (strlen(fips_approved_sigalgs[i]) == len &&
			    strncmp(p, fips_approved_sigalgs[i], len) == 0)
				goto next;
		}
		memprintf(&list, "%s%s'%.*s'", list ? list : "",
		          list ? ", " : "", (int)len, p);
	next:
		p = end ? end + 1 : NULL;
	}

	if (list) {
		fips_obj_info(obj, &proxy_name, &type_str, &obj_name, &file, &line);
		if (file)
			ha_alert("[%s:%d] %s '%s/%s': FIPS mode active but non-FIPS signature algorithm(s) configured: %s.\n",
			         file, line, type_str, proxy_name, obj_name, list);
		else
			ha_alert("%s '%s/%s': FIPS mode active but non-FIPS signature algorithm(s) configured: %s.\n",
			         type_str, proxy_name, obj_name, list);
		free(list);
		return ERR_ALERT | ERR_ABORT | ERR_FATAL;
	}
	return 0;
}

/* Check that the TLS 1.3 ciphersuite list <ciphersuites> is FIPS-compliant. */
int ssl_fips_check_ciphersuites(const char *ciphersuites, const enum obj_type *obj)
{
	const char *proxy_name, *type_str, *obj_name, *file;
	const char *p, *end;
	char *list = NULL;
	int i, line;
	size_t len;

	if (!FIPS_mode() || !ciphersuites)
		return 0;

	p = ciphersuites;
	while (p && *p) {
		end = strchr(p, ':');
		len = end ? (size_t)(end - p) : strlen(p);

		for (i = 0; fips_approved_ciphersuites[i]; i++) {
			if (strlen(fips_approved_ciphersuites[i]) == len &&
			    strncmp(p, fips_approved_ciphersuites[i], len) == 0)
				goto next;
		}
		memprintf(&list, "%s%s'%.*s'", list ? list : "",
		          list ? ", " : "", (int)len, p);
	next:
		p = end ? end + 1 : NULL;
	}

	if (list) {
		fips_obj_info(obj, &proxy_name, &type_str, &obj_name, &file, &line);
		if (file)
			ha_alert("[%s:%d] %s '%s/%s': FIPS mode active but non-FIPS ciphersuite(s) configured: %s.\n",
			         file, line, type_str, proxy_name, obj_name, list);
		else
			ha_alert("%s '%s/%s': FIPS mode active but non-FIPS ciphersuite(s) configured: %s.\n",
			         type_str, proxy_name, obj_name, list);
		free(list);
		return ERR_ALERT | ERR_ABORT | ERR_FATAL;
	}
	return 0;
}

/* Check that the elliptic curve list <curves> is FIPS-compliant. */
int ssl_fips_check_curves(const char *curves, const enum obj_type *obj)
{
	const char *proxy_name, *type_str, *obj_name, *file;
	const char *p, *end;
	char *list = NULL;
	char name[64];
	int i, nid, line;
	size_t len;

	if (!FIPS_mode() || !curves)
		return 0;

	p = curves;
	while (p && *p) {
		end = strchr(p, ':');
		len = end ? (size_t)(end - p) : strlen(p);

		if (len < sizeof(name)) {
			memcpy(name, p, len);
			name[len] = '\0';
			nid = OBJ_txt2nid(name);
			if (nid == NID_undef)
				nid = EC_curve_nist2nid(name);
			for (i = 0; fips_approved_curve_nids[i] != NID_undef; i++) {
				if (nid == fips_approved_curve_nids[i])
					goto next;
			}
		}
		memprintf(&list, "%s%s'%.*s'", list ? list : "",
		          list ? ", " : "", (int)len, p);
	next:
		p = end ? end + 1 : NULL;
	}

	if (list) {
		fips_obj_info(obj, &proxy_name, &type_str, &obj_name, &file, &line);
		if (file)
			ha_alert("[%s:%d] %s '%s/%s': FIPS mode active but non-FIPS curve(s) configured: %s.\n",
			         file, line, type_str, proxy_name, obj_name, list);
		else
			ha_alert("%s '%s/%s': FIPS mode active but non-FIPS curve(s) configured: %s.\n",
			         type_str, proxy_name, obj_name, list);
		free(list);
		return ERR_ALERT | ERR_ABORT | ERR_FATAL;
	}
	return 0;
}

/* Check that the TLS 1.2 cipher list configured on <ctx> is FIPS-compliant. */
int ssl_fips_check_ciphers(SSL_CTX *ctx, const enum obj_type *obj)
{
	const char *proxy_name, *type_str, *obj_name, *file;
	STACK_OF(SSL_CIPHER) *cipher_list;
	const SSL_CIPHER *cipher;
	int i, j, cipher_nid, kx_nid, line;
	char *list = NULL;

	if (!FIPS_mode())
		return 0;

	cipher_list = SSL_CTX_get_ciphers(ctx);
	if (!cipher_list)
		return 0;

	for (i = 0; i < sk_SSL_CIPHER_num(cipher_list); i++) {
		cipher     = sk_SSL_CIPHER_value(cipher_list, i);
		cipher_nid = SSL_CIPHER_get_cipher_nid(cipher);

		kx_nid = SSL_CIPHER_get_kx_nid(cipher);
		if (kx_nid == NID_kx_ecdhe
#ifdef NID_kx_dhe
		    || kx_nid == NID_kx_dhe
#endif
		    ) {
			for (j = 0; fips_approved_cipher_nids[j] != NID_undef; j++) {
				if (cipher_nid == fips_approved_cipher_nids[j])
					goto next;
			}
		}
		memprintf(&list, "%s%s'%s'", list ? list : "",
		          list ? ", " : "", SSL_CIPHER_get_name(cipher));
	next:;
	}

	if (list) {
		fips_obj_info(obj, &proxy_name, &type_str, &obj_name, &file, &line);
		if (file)
			ha_alert("[%s:%d] %s '%s/%s': FIPS mode active but non-FIPS cipher(s) configured: %s.\n",
			         file, line, type_str, proxy_name, obj_name, list);
		else
			ha_alert("%s '%s/%s': FIPS mode active but non-FIPS cipher(s) configured: %s.\n",
			         type_str, proxy_name, obj_name, list);
		free(list);
		return ERR_ALERT | ERR_ABORT | ERR_FATAL;
	}
	return 0;
}

/* Check that the minimum TLS version <min_ver> is FIPS-compliant. */
int ssl_fips_check_version(int min_ver, const enum obj_type *obj)
{
	const char *proxy_name, *type_str, *obj_name, *file;
	int line;

	if (!FIPS_mode())
		return 0;

	if (min_ver && min_ver < CONF_TLSV12) {
		fips_obj_info(obj, &proxy_name, &type_str, &obj_name, &file, &line);
		if (file)
			ha_alert("[%s:%d] %s '%s/%s': FIPS mode active but ssl-min-ver is set below TLS 1.2.\n",
			         file, line, type_str, proxy_name, obj_name);
		else
			ha_alert("%s '%s/%s': FIPS mode active but ssl-min-ver is set below TLS 1.2.\n",
			         type_str, proxy_name, obj_name);
		return ERR_ALERT | ERR_ABORT | ERR_FATAL;
	}
	return 0;
}
