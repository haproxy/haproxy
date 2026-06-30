/* SPDX-License-Identifier: GPL-2.0-or-later */

/* FIPS compliance checks for AWS-LC builds */

#include <stdlib.h>

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

/* Check that the TLS 1.2 cipher list configured on <ctx> is FIPS-compliant. */
int ssl_fips_check_ciphers(SSL_CTX *ctx, const enum obj_type *obj, char **err)
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
			memprintf(err, "%s[%s:%d] %s '%s/%s': FIPS mode active but non-FIPS cipher(s) configured: %s.\n",
			          (err && *err) ? *err : "", file, line, type_str, proxy_name, obj_name, list);
		else
			memprintf(err, "%s%s '%s/%s': FIPS mode active but non-FIPS cipher(s) configured: %s.\n",
			          (err && *err) ? *err : "", type_str, proxy_name, obj_name, list);
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
