/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifdef USE_ECH

#include <haproxy/buf-t.h>
#include <haproxy/applet-t.h>
#include <haproxy/global-t.h>
#include <haproxy/ech-t.h>
#include <haproxy/global.h>
#include <haproxy/fd.h>
#include <haproxy/obj_type.h>
#include <haproxy/applet.h>
#include <haproxy/cli.h>
#include <haproxy/proxy.h>
#include <haproxy/log.h>
#include <haproxy/ech.h>

#include <openssl/ssl.h>
#include <dirent.h>
#include <sys/stat.h>

/* 
 * load any key files called <name>.ech we find in the named
 * directory 
 */
int load_echkeys(SSL_CTX *ctx, char *dirname, int *loaded)
{
    struct dirent **de_list = NULL;
    struct stat thestat;
    /*
     * I really can't see a reason to want >1024 private key files
     * to have to be checked in a directory, but if there were a
     * reason then you could change this I guess or make it a 
     * config setting.
     * TODO: revisit this limit
     */
    int rv = 0, i, nrv, somekeyworked = 0, maxkeyfiles = 1024;
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
            if (!--maxkeyfiles) /* just so we don't loop forever, ever */
                return 0;
            if (stat(privname, &thestat) == 0) {
                BIO *in = BIO_new_file(privname, "r");
                const int is_retry_config = OSSL_ECH_FOR_RETRY;

                if (in != NULL
                    && 1 == OSSL_ECHSTORE_read_pem(es, in, is_retry_config))
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
 * ECH key management
 *
 * "show" syntax: "show ssl ech [name]" where name is a frontend.
 *
 * To use this, start haproxy, then (with out test configs)
 *
 *      $ socat /tmp/haproxy.sock stdio
 *      prompt
 *      > show ssl ech
 *      ...
 *      >
 *
 * After running socat, you have to type "prompt" to get the
 * command line.
 *
 * Right now the output (for haproxymin.conf) looks like:
 *
 *     $ socat /tmp/haproxy.sock stdio
 *     prompt
 *     > show ssl ech
 *     ***
 *     frontend: ECH-front
 *     ECH details (3 configs total)
 *     index: 0: loaded 4 seconds, SNI (inner:NULL;outer:NULL), ALPN (inner:NULL;outer:NULL)
 *         [fe0d,bb,example.com,0020,[0001,0001],62c7607bf2c5fe1108446f132ca4339cf19df1552e5a42960fd02c697360163c,00,00]
 *     index: 1: loaded 4 seconds, SNI (inner:NULL;outer:NULL), ALPN (inner:NULL;outer:NULL)
 *         [fe0d,64,example.com,0020,[0001,0001],cc12c8fb828c202d11b5adad67e15d0cccce1aaa493e1df34a770e4a5cdcd103,00,00]
 *     index: 2: loaded 4 seconds, SNI (inner:NULL;outer:NULL), ALPN (inner:NULL;outer:NULL)
 *         [fe0d,bb,example.com,0020,[0001,0001],62c7607bf2c5fe1108446f132ca4339cf19df1552e5a42960fd02c697360163c,00,00]
 *     ***
 *     frontend: Two-TLS
 *     ECH details (3 configs total)
 *     index: 0: loaded 4 seconds, SNI (inner:NULL;outer:NULL), ALPN (inner:NULL;outer:NULL)
 *         [fe0d,bb,example.com,0020,[0001,0001],62c7607bf2c5fe1108446f132ca4339cf19df1552e5a42960fd02c697360163c,00,00]
 *     index: 1: loaded 4 seconds, SNI (inner:NULL;outer:NULL), ALPN (inner:NULL;outer:NULL)
 *         [fe0d,64,example.com,0020,[0001,0001],cc12c8fb828c202d11b5adad67e15d0cccce1aaa493e1df34a770e4a5cdcd103,00,00]
 *     index: 2: loaded 4 seconds, SNI (inner:NULL;outer:NULL), ALPN (inner:NULL;outer:NULL)
 *         [fe0d,bb,example.com,0020,[0001,0001],62c7607bf2c5fe1108446f132ca4339cf19df1552e5a42960fd02c697360163c,00,00]
 *
 * CRTL-d will exit from the command line.
 *
 * You can also do it without the prompt:
 *
 *     $ echo "show ssl ech" | socat /tmp/haproxy.sock stdio
 *     ...
 *
 * We find the SSL_CTX pointers differently for a frontend as follows:
 *
 * frontend: objt_listener(fdtab[*]).bind_conf->initial_ctx, named via
 * objt_listener(fdtab[*]).bind_conf->frontend->id
 *
 * note that not all entries will have ECH configs, nor SSL_CTX values
 *
 * If we ever add client-side ECH between haproxy and backends then we'd
 * also be interested in proxies_list[*].srv->ssl_ctx.ctx but for now
 * we'll not include those.
 */

/* find a named SSL_CTX, returns 1 if found */
static int cli_find_ech_specific_ctx(char *name, SSL_CTX **sctx)
{
    struct fdtab *fdt = NULL;
    struct listener *li = NULL;
    int found = 0, fd = 0;
    SSL_CTX *res = NULL;

    if (!name || !sctx)
        return 0;
    /* check fd's for frontend cases */
    while (!found && fd < global.maxsock) {
        fdt = &fdtab[fd++];
        if (!fdt->owner)
            continue;
        li = objt_listener(fdt->owner);
        if (li && li->bind_conf && li->bind_conf->initial_ctx
            && li->bind_conf->frontend
            && !strcmp(li->bind_conf->frontend->id, name)) {
            found = 1;
            res = li->bind_conf->initial_ctx;
        }
    }
    if (found)
        *sctx = res;
    return found;
}

/* parsing function for 'show ssl ech [echfile]' */
int cli_parse_show_ech(char **args, char *payload,
                       struct appctx *appctx, void *private)
{
    struct show_ech_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	/* no parameter, shows only file list */
	if (*args[3]) {
        SSL_CTX *sctx = NULL;

        if (cli_find_ech_specific_ctx(args[3], &sctx) != 1)
            return cli_err(appctx, "'show ssl ech' unable to locate referenced name\n");
        ctx->specific_name = args[3];
        ctx->specific_ctx = sctx;
        ctx->state = SHOW_ECH_SPECIFIC;
        ctx->fd = 0;
        ctx->pp = NULL;
    } else {
        ctx->specific_name = NULL;
        ctx->specific_ctx = NULL;
        ctx->pp = proxies_list;
        ctx->fd = 0;
        ctx->state = SHOW_ECH_FD;
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

int cli_io_handler_ech_details(struct appctx *appctx)
{
    struct buffer *trash = get_trash_chunk();
    struct show_ech_ctx *ctx = appctx->svcctx;
    struct listener *li = NULL;
    int ret = 0;

    if (!ctx) return 1;

    /*
     * isolate the threads once per round. We're limited to a buffer worth
     * of output anyway, it cannot last very long.
     */
    thread_isolate();

    if (ctx->state == SHOW_ECH_SPECIFIC) {
        chunk_appendf(trash, "***\nECH for %s ", ctx->specific_name);
        cli_print_ech_info(ctx->specific_ctx, trash);
        if (applet_putchk(appctx, trash) == -1)
            return 0;
        thread_release();
        return 1;
    }

    if (ctx->state == SHOW_ECH_FD) {
        struct fdtab *fdt = NULL;

        /* not sure of right limit */
        while (ctx->fd < global.maxsock) {
            fdt = &fdtab[ctx->fd++];
            if (fdt->owner) {
                li = objt_listener(fdt->owner);
                if (li && li->bind_conf && li->bind_conf->initial_ctx) {
                    /* print stuff */
                    if (li->bind_conf->frontend)
                        chunk_appendf(trash, "***\nfrontend: %s ", li->bind_conf->frontend->id);
                    else
                        chunk_appendf(trash, "***\nfrontend fd; %d ", ctx->fd-1);
                    cli_print_ech_info(li->bind_conf->initial_ctx, trash);
                    if (applet_putchk(appctx, trash) == -1)
                        goto end;
                }
            }
        }
        ret = 1; /* we're all done */
    }

end:
    thread_release();
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
int cli_parse_add_ech(char **args, char *payload, struct appctx *appctx,
                      void *private)
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
int cli_parse_set_ech(char **args, char *payload,
                      struct appctx *appctx, void *private)
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
int cli_parse_del_ech(char **args, char *payload,
                      struct appctx *appctx, void *private)
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

#endif
