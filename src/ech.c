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

struct show_ech_ctx {
	struct proxy *pp;
	struct bind_conf *b;
	SSL_CTX *specific_ctx;
	char *specific_name;
	enum {
		SHOW_ECH_ALL = 0,
		SHOW_ECH_SPECIFIC,
	} state;                       /* phase of the current dump */
};

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

/* find a named SSL_CTX, returns 1 if found
 *
 * <name> should be in the format "frontend/@<filename>:<linenum>"
 * Example:
 *   "http1/@haproxy.cfg:1234"
 */
static int cli_find_ech_specific_ctx(const char *name, SSL_CTX **sctx)
{
	struct proxy *p;
	struct bind_conf *bind_conf;
	char *pname; /* proxy name */
	char *bname; /* bind_name */
	struct buffer *tmp = get_trash_chunk();

	if (!name || !sctx)
		return 0;


	b_putblk(tmp, name, strlen(name) + 1);

	for (pname = bname = tmp->area; *bname != '\0' && *bname != '/'; bname++)
		;

	if (*bname) {
		*bname = '\0'; /* replace / by '\0' */
		bname++; /* there's a bind_conf name or id */
	}

	if (!*pname || !*bname)
		return 0;

	p = proxy_find_by_name(pname, PR_CAP_FE, 0);
	if (!p)
		return 0;

	bind_conf = bind_conf_find_by_name(p, bname);
	if (!bind_conf)
		return 0;

	if (bind_conf->initial_ctx) {
		*sctx = bind_conf->initial_ctx;
		return 1;
	}
	return 0;
}

/* parsing function for 'show ssl ech [echfile]' */
static int cli_parse_show_ech(char **args, char *payload,
                              struct appctx *appctx, void *private)
{
	struct show_ech_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	/* no parameter, shows only file list */
	if (*args[3]) {
		SSL_CTX *sctx = NULL;
		ctx->specific_name = strdup(args[3]);

		if (cli_find_ech_specific_ctx(args[3], &sctx) != 1)
			return cli_err(appctx, "'show ssl ech' unable to locate referenced name\n");
		ctx->specific_ctx = sctx;
		ctx->state = SHOW_ECH_SPECIFIC;
		ctx->pp = NULL;
		ctx->b = NULL;
	} else {
		ctx->specific_name = NULL;
		ctx->specific_ctx = NULL;
		ctx->pp = proxies_list;
		ctx->b = NULL;
		ctx->state = SHOW_ECH_ALL;
	}

	return 0;
}

static void cli_print_ech_info(SSL_CTX *ctx, struct buffer *trash)
{
	int oi_ind, oi_cnt = 0;
	OSSL_ECHSTORE *es = NULL;
	BIO *out = NULL;

	out = BIO_new(BIO_s_mem());
	if (!out) {
		chunk_appendf(trash, "error making BIO\n");
		return;
	}
	if ((es = SSL_CTX_get1_echstore(ctx)) == NULL
	    || OSSL_ECHSTORE_num_entries(es, &oi_cnt) != 1) {
		chunk_appendf(trash, "error accessing ECH store\n");
		goto end;
	}
	if (oi_cnt <= 0)
		chunk_appendf(trash, "no ECH config\n");
	for (oi_ind = 0; oi_ind < oi_cnt; oi_ind++) {
		time_t secs = 0;
		char *pn = NULL, *ec = NULL;
		int has_priv, for_retry, returned;
		struct buffer *tmp = alloc_trash_chunk();

		if (!tmp) {
			chunk_appendf(trash, "error making tmp buffer\n");
			goto end;
		}
		if (OSSL_ECHSTORE_get1_info(es, oi_ind, &secs, &pn, &ec,
		                            &has_priv, &for_retry) != 1) {
			chunk_appendf(trash, "error printing ECH Info\n");
			OPENSSL_free(pn); /* just in case */
			OPENSSL_free(ec);
			goto end;
		}
		BIO_printf(out, "ECH entry: %d public_name: %s age: %lld%s\n",
		           oi_ind, pn, (long long)secs,
		           has_priv ? " (has private key)" : "");
		BIO_printf(out, "\t%s\n", ec);
		OPENSSL_free(pn);
		OPENSSL_free(ec);
		returned = BIO_read(out, tmp->area, tmp->size-1);
		tmp->area[returned] = '\0';
		chunk_appendf(trash, "\n%s", tmp->area);
		free_trash_chunk(tmp);
	}
end:
	BIO_free(out);
	OSSL_ECHSTORE_free(es);
	return;
}

/*
 * Print out ECH details where they (might) exist
 *
 * The applet_putchk() calls will emit text to the "stats" socket
 * which is more or less a command line UI. If that returns a -1
 * then we should break off processing to allow other threads to
 * do stuff. That's why all the "goto end" stuff and why the code
 * is kind of re-entrant.
 */

static int cli_io_handler_ech_details(struct appctx *appctx)
{
	struct buffer *trash = get_trash_chunk();
	struct show_ech_ctx *ctx = appctx->svcctx;
	int ret = 0;
	struct proxy *p = NULL;
	struct bind_conf *bind_conf = NULL;
	if (!ctx) return 1;

	if (ctx->state == SHOW_ECH_SPECIFIC) {
		chunk_appendf(trash, "***\nECH for %s ", ctx->specific_name);
		cli_print_ech_info(ctx->specific_ctx, trash);
		if (applet_putchk(appctx, trash) == -1)
			return 0;
		return 1;
	}

	if (ctx->state == SHOW_ECH_ALL) {

		bind_conf = ctx->b;
		p = ctx->pp;

		for (; p; p = p->next) {

			if (!(p->cap & PR_CAP_FE) || LIST_ISEMPTY(&p->conf.bind))
				continue;

			if (!bind_conf) {
				bind_conf = LIST_ELEM(p->conf.bind.n, typeof(bind_conf), by_fe);
				chunk_appendf(trash, "***\nfrontend: %s\n", bind_conf->frontend->id);
			}

			/* loop on binds */
			list_for_each_entry_from(bind_conf, &p->conf.bind, by_fe) {

				if (bind_conf->initial_ctx) {
					/* print stuff */

					chunk_appendf(trash, "\nbind: %s/@%s:%d\n", bind_conf->frontend->id, bind_conf->file, bind_conf->line);
					cli_print_ech_info(bind_conf->initial_ctx, trash);
					if (applet_putchk(appctx, trash) == -1) {
						goto end;
					}
				}
			}
			bind_conf =  NULL;
		}
		p = NULL;
		ret = 1; /* we're all done */
	}

end:
	ctx->pp = p;
	ctx->b = bind_conf;
	return ret;
}

#define ECH_SUCCESS_MSG_MAX 256

/*
 * For the add and set commands below one needs to provide the ECH PEM file
 * content on the command line. That can be done via:
 *
 *          $ openssl ech -public_name htest.com -pemout htest.pem
 *          $ echo -e "add ssl ech ECH-front <<EOF\n$(cat htest.pem)\nEOF\n" | socat /tmp/haproxy.sock -
 *          added a new ECH config to ECH-front
 *
 */

/* add ssl ech <name> <pemesni> */
static int cli_parse_add_ech(char **args, char *payload, struct appctx *appctx, void *private)
{
	SSL_CTX *sctx = NULL;
	char success_message[ECH_SUCCESS_MSG_MAX];
	OSSL_ECHSTORE *es = NULL;
	BIO *es_in = NULL;

	if (!*args[3] || !payload)
		return cli_err(appctx, "syntax: add ssl ech <name> <PEM file content>");
	if (cli_find_ech_specific_ctx(args[3], &sctx) != 1)
		return cli_err(appctx, "'add ssl ech' unable to locate referenced name\n");
	if ((es_in = BIO_new_mem_buf(payload, strlen(payload))) == NULL
	    || (es = SSL_CTX_get1_echstore(sctx)) == NULL
	    || OSSL_ECHSTORE_read_pem(es, es_in, OSSL_ECH_FOR_RETRY) != 1
	    || SSL_CTX_set1_echstore(sctx, es) != 1) {
		OSSL_ECHSTORE_free(es);
		BIO_free_all(es_in);
		return cli_err(appctx, "'add ssl ech' error adding provided PEM ECH value\n");
	}
	OSSL_ECHSTORE_free(es);
	BIO_free_all(es_in);
	snprintf(success_message, ECH_SUCCESS_MSG_MAX,
	         "added a new ECH config to %s", args[3]);
	return cli_msg(appctx, LOG_INFO, success_message);
}

/* set ssl ech <name> <pemesni> */
static int cli_parse_set_ech(char **args, char *payload, struct appctx *appctx, void *private)
{
	SSL_CTX *sctx = NULL;
	char success_message[ECH_SUCCESS_MSG_MAX];
	OSSL_ECHSTORE *es = NULL;
	BIO *es_in = NULL;

	if (!*args[3] || !payload)
		return cli_err(appctx, "syntax: set ssl ech <name> <PEM file content>");
	if (cli_find_ech_specific_ctx(args[3], &sctx) != 1)
		return cli_err(appctx, "'set ssl ech' unable to locate referenced name\n");
	if ((es_in = BIO_new_mem_buf(payload, strlen(payload))) == NULL
	    || (es = OSSL_ECHSTORE_new(NULL, NULL)) == NULL
	    || OSSL_ECHSTORE_read_pem(es, es_in, OSSL_ECH_FOR_RETRY) != 1
	    || SSL_CTX_set1_echstore(sctx, es) != 1) {
		OSSL_ECHSTORE_free(es);
		BIO_free_all(es_in);
		return cli_err(appctx, "'set ssl ech' error adding provided PEM ECH value\n");
	}
	OSSL_ECHSTORE_free(es);
	BIO_free_all(es_in);
	snprintf(success_message, ECH_SUCCESS_MSG_MAX,
	         "set new ECH configs for %s", args[3]);
	return cli_msg(appctx, LOG_INFO, success_message);
}

/* del ssl ech <name> [<age-in-secs>] */
static int cli_parse_del_ech(char **args, char *payload, struct appctx *appctx, void *private)
{
	SSL_CTX *sctx = NULL;
	time_t age = 0;
	char success_message[ECH_SUCCESS_MSG_MAX];
	OSSL_ECHSTORE *es = NULL;

	if (!*args[3])
		return cli_err(appctx, "syntax: del ssl ech <name>");
	if (*args[4])
		age = atoi(args[4]);
	if (cli_find_ech_specific_ctx(args[3], &sctx) != 1)
		return cli_err(appctx, "'del ssl ech' unable to locate referenced name\n");
	if ((es = SSL_CTX_get1_echstore(sctx)) == NULL
	    || OSSL_ECHSTORE_flush_keys(es, age) != 1
	    || SSL_CTX_set1_echstore(sctx, es) != 1) {
		OSSL_ECHSTORE_free(es);
		return cli_err(appctx, "'del ssl ech' error removing old ECH values\n");
	}
	OSSL_ECHSTORE_free(es);
	memset(success_message, 0, ECH_SUCCESS_MSG_MAX);
	if (!age)
		snprintf(success_message, ECH_SUCCESS_MSG_MAX,
		         "deleted all ECH configs from %s", args[3]);
	else
		snprintf(success_message, ECH_SUCCESS_MSG_MAX,
		         "deleted ECH configs older than %ld seconds from %s", age, args[3]);
	return cli_msg(appctx, LOG_INFO, success_message);
}


static void cli_release_ech(struct appctx *appctx)
{
	struct show_ech_ctx *ctx = appctx->svcctx;

	ha_free(&ctx->specific_name);
}


static struct cli_kw_list cli_kws = {{ },{
    { { "show", "ssl", "ech", NULL},  "show ssl ech [<name>]                   : display a named ECH configuration or all",      cli_parse_show_ech, cli_io_handler_ech_details, cli_release_ech, NULL, ACCESS_EXPERIMENTAL },
    { { "add", "ssl", "ech", NULL },  "add ssl ech <name> <payload>            : add a new PEM-formatted ECH config and key ",  cli_parse_add_ech, NULL, NULL, NULL, ACCESS_EXPERIMENTAL },
    { { "set", "ssl", "ech", NULL },  "set ssl ech <name> <payload>            : replace all ECH configs with that provided",   cli_parse_set_ech, NULL, NULL, NULL, ACCESS_EXPERIMENTAL },
    { { "del", "ssl", "ech", NULL },  "del ssl ech <name> [<age-in-secs>]      : delete ECH configs",                           cli_parse_del_ech, NULL, NULL, NULL, ACCESS_EXPERIMENTAL },
    { { NULL }, NULL, NULL, NULL, NULL },

}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

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
