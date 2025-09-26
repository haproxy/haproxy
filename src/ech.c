/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifdef USE_ECH


#include <dirent.h>
#include <sys/stat.h>

#include <haproxy/applet.h>
#include <haproxy/cli.h>
#include <haproxy/ech.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/obj_type.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/proxy.h>
#include <haproxy/ssl_sock-t.h>


/*
 * load any key files called <name>.ech we find in the named
 * directory
 */
int load_echkeys(SSL_CTX *ctx, char *dirname, int *loaded)
{
	struct dirent **de_list = NULL;
	struct stat thestat;
	int rv = 0, i, nrv, somekeyworked = 0;
	char *den = NULL, *last4 = NULL, privname[PATH_MAX];
	size_t elen = 0, nlen = 0;
	OSSL_ECHSTORE * const es = OSSL_ECHSTORE_new(NULL, NULL);

	if (es == NULL)
		goto end;
	nrv = scandir(dirname, &de_list, 0, alphasort);
	if (nrv < 0)
		goto end;
	for (i = 0; i != nrv; i++) {
		struct dirent *de = de_list[i];

		den = de->d_name;
		nlen = strlen(den);
		if (nlen > 4) {
			last4 = den + nlen - 4;
			if (strncmp(last4, ".ech", 4))
				goto ignore_entry;
			if ((elen + 1 + nlen + 1) >= PATH_MAX)
				goto ignore_entry;
			snprintf(privname, PATH_MAX,"%s/%s", dirname, den);
			if (stat(privname, &thestat) == 0) {
				BIO *in = BIO_new_file(privname, "r");
				const int is_retry_config = OSSL_ECH_FOR_RETRY;

				if (in != NULL && 1 == OSSL_ECHSTORE_read_pem(es, in, is_retry_config))
					somekeyworked = 1;
				BIO_free_all(in);
			}
		}
ignore_entry:
		free(de);
	}

	if (somekeyworked == 0)
		goto end;
	if (OSSL_ECHSTORE_num_keys(es, loaded) != 1)
		goto end;
	if (1 != SSL_CTX_set1_echstore(ctx, es))
		goto end;
	rv = 1;
end:
	free(de_list);
	OSSL_ECHSTORE_free(es);
	return rv;
}

/*
 * Place an ECH status string into a trash buffer
 * ECH status string examples:
 *      SSL_ECH_STATUS_GREASE
 *      SSL_ECH_STATUS_NOT_TRIED
 *      SSL_ECH_STATUS_SUCCESS
 * The status values are those defined in <openssl/ech.h>
 * as the define'd returns from `SSL_ech_get1_status()`
 */
int conn_get_ech_status(struct connection *conn, struct buffer *buf)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);
	char *sni_ech = NULL;
	char *sni_clr = NULL;
	const char *lstr = NULL;

	if (!ctx)
		return 0;
#define s(x) #x
	switch (SSL_ech_get1_status(ctx->ssl, &sni_ech, &sni_clr)) {
		case SSL_ECH_STATUS_SUCCESS:   lstr = s(SSL_ECH_STATUS_SUCCESS);   break;
		case SSL_ECH_STATUS_NOT_TRIED: lstr = s(SSL_ECH_STATUS_NOT_TRIED); break;
		case SSL_ECH_STATUS_FAILED:    lstr = s(SSL_ECH_STATUS_FAILED);    break;
		case SSL_ECH_STATUS_BAD_NAME:  lstr = s(SSL_ECH_STATUS_BAD_NAME);  break;
		case SSL_ECH_STATUS_BAD_CALL:  lstr = s(SSL_ECH_STATUS_BAD_CALL);  break;
		case SSL_ECH_STATUS_GREASE:    lstr = s(SSL_ECH_STATUS_GREASE);    break;
		case SSL_ECH_STATUS_BACKEND:   lstr = s(SSL_ECH_STATUS_BACKEND);   break;
		default:                       lstr = "";                         break;
	}
#undef s
	chunk_printf(buf, "%s", lstr);
	OPENSSL_free(sni_ech);
	OPENSSL_free(sni_clr);
	return 1;
}

/* If ECH succeeded, return the outer SNI value seen */
int conn_get_ech_outer_sni(struct connection *conn, struct buffer *buf)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);
	char *sni_ech = NULL;
	char *sni_clr = NULL;

	if (!ctx)
		return 0;
	if (SSL_ech_get1_status(ctx->ssl, &sni_ech, &sni_clr)
	    == SSL_ECH_STATUS_SUCCESS && sni_clr != NULL)
		chunk_printf(buf, "%s", sni_clr);
	OPENSSL_free(sni_ech);
	OPENSSL_free(sni_clr);
	return 1;
}

static int bind_parse_ech(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!experimental_directives_allowed) {
		memprintf(err, "'%s' directive is experimental, must be allowed via a global 'expose-experimental-directives'",
		               args[0]);
		return -1;
	}
	mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);

	free(conf->ssl_conf.ech_filedir);
	conf->ssl_conf.ech_filedir = strdup(args[cur_arg+1]);
	return 0;
}


static struct bind_kw_list bind_kws = { "SSL", { }, {
	{ "ech",    bind_parse_ech,     1 }, /* set ECH PEM file */
	{ 0, NULL, 0 },
}};


INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

#endif
