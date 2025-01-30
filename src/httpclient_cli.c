/* SPDX-License-Identifier: GPL-2.0-or-later */

/* "httpclient" CLI command */


#include <haproxy/cli.h>
#include <haproxy/cfgparse.h>
#include <haproxy/global.h>
#include <haproxy/istbuf.h>
#include <haproxy/h1_htx.h>
#include <haproxy/http_client.h>
#include <haproxy/tools.h>

#include <string.h>

/* --- This part of the file implement an HTTP client over the CLI ---
 * The functions will be  starting by "hc_cli" for "httpclient cli"
 */

#define HC_F_RES_STLINE     0x01
#define HC_F_RES_HDR        0x02
#define HC_F_RES_BODY       0x04
#define HC_F_RES_END        0x08

/* the CLI context for the httpclient command */
struct hcli_svc_ctx {
	struct httpclient *hc;  /* the httpclient instance */
	uint flags;             /* flags from HC_CLI_F_* above */
	uint is_htx:1;          /* is the response an htx buffer */
};

/* These are the callback used by the HTTP Client when it needs to notify new
 * data, we only sets a flag in the IO handler via the svcctx.
 */
void hc_cli_res_stline_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;
	struct hcli_svc_ctx *ctx;

	if (!appctx)
		return;

	ctx = appctx->svcctx;
	ctx->flags |= HC_F_RES_STLINE;
	appctx_wakeup(appctx);
}

void hc_cli_res_headers_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;
	struct hcli_svc_ctx *ctx;

	if (!appctx)
		return;

	ctx = appctx->svcctx;
	ctx->flags |= HC_F_RES_HDR;
	appctx_wakeup(appctx);
}

void hc_cli_res_body_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;
	struct hcli_svc_ctx *ctx;

	if (!appctx)
		return;

	ctx = appctx->svcctx;
	ctx->flags |= HC_F_RES_BODY;
	appctx_wakeup(appctx);
}

void hc_cli_res_end_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;
	struct hcli_svc_ctx *ctx;

	if (!appctx)
		return;

	ctx = appctx->svcctx;
	ctx->flags |= HC_F_RES_END;
	appctx_wakeup(appctx);
}

/*
 * Parse an httpclient keyword on the cli:
 * httpclient [--htx] <method> <URI>
 */
static int hc_cli_parse(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct hcli_svc_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct httpclient *hc;
	char *err = NULL;
	enum http_meth_t meth;
	char *meth_str;
	struct ist uri;
	struct ist body = IST_NULL;
	int cur_arg = 1;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	/* look at optional keywords */
	while (*args[cur_arg] == '-') {
		if (strcmp(args[cur_arg], "--htx") == 0) {
			ctx->is_htx = 1;
		}
		else if (strcmp(args[cur_arg], "--") == 0) {
			cur_arg++;
			break;
		} else {
			memprintf(&err, ": Unknown '%s' optional keyword", args[cur_arg]);
			goto err;
		}
		cur_arg++;
	}

	if (!*args[cur_arg] || !*args[cur_arg+1]) {
		memprintf(&err, ": not enough parameters");
		goto err;
	}

	meth_str = args[cur_arg];
	uri = ist(args[cur_arg+1]);

	if (payload)
		body = ist(payload);

	meth = find_http_meth(meth_str, strlen(meth_str));

	hc = httpclient_new(appctx, meth, uri);
	if (!hc) {
		goto err;
	}

	/* update the httpclient callbacks */
	hc->ops.res_stline = hc_cli_res_stline_cb;
	hc->ops.res_headers = hc_cli_res_headers_cb;
	hc->ops.res_payload = hc_cli_res_body_cb;
	hc->ops.res_end = hc_cli_res_end_cb;

	ctx->hc = hc; /* store the httpclient ptr in the applet */
	ctx->flags = 0;

	/* enable the HTX mode for reception */
	if (ctx->is_htx)
		hc->options |= HTTPCLIENT_O_RES_HTX;

	if (httpclient_req_gen(hc, hc->req.url, hc->req.meth, NULL, body) != ERR_NONE)
		goto err;


	if (!httpclient_start(hc))
		goto err;

	return 0;

err:
	memprintf(&err, "Can't start the HTTP client%s.\n", err ? err : "");
	return cli_err(appctx, err);
}

/* This function dumps the content of the httpclient receive buffer
 * on the CLI output
 *
 * Return 1 when the processing is finished
 * return 0 if it needs to be called again
 */
static int hc_cli_io_handler(struct appctx *appctx)
{
	struct hcli_svc_ctx *ctx = appctx->svcctx;
	struct httpclient *hc = ctx->hc;
	struct http_hdr *hdrs, *hdr;
	struct htx *hc_htx = NULL;

	if (ctx->is_htx && ctx->flags & (HC_F_RES_STLINE|HC_F_RES_HDR|HC_F_RES_BODY)) {
		hc_htx = htxbuf(&hc->res.buf);

		if (!hc_htx)
			goto error;

		if (htx_is_empty(hc_htx))
			goto error;
	}

	if (ctx->flags & HC_F_RES_STLINE) {
		chunk_reset(&trash);
		if (!ctx->is_htx) {
			chunk_printf(&trash, "%.*s %d %.*s\n", (unsigned int)istlen(hc->res.vsn), istptr(hc->res.vsn),
			             hc->res.status, (unsigned int)istlen(hc->res.reason), istptr(hc->res.reason));
		}
		if (applet_putchk(appctx, &trash) == -1)
			goto more;
		ctx->flags &= ~HC_F_RES_STLINE;
	}

	if (ctx->flags & HC_F_RES_HDR) {
		chunk_reset(&trash);
		if (!ctx->is_htx) {
			hdrs = hc->res.hdrs;
			for (hdr = hdrs; isttest(hdr->v); hdr++) {
				if (!h1_format_htx_hdr(hdr->n, hdr->v, &trash))
					goto too_many_hdrs;
			}
			if (!chunk_memcat(&trash, "\r\n", 2))
				goto too_many_hdrs;
		}
		if (applet_putchk(appctx, &trash) == -1)
			goto more;
		ctx->flags &= ~HC_F_RES_HDR;
	}

	if (ctx->flags & HC_F_RES_BODY) {
		if (!ctx->is_htx) {
			httpclient_res_xfer(hc, &appctx->outbuf);
			/* remove the flag if the buffer was emptied */
			if (httpclient_data(hc))
				goto more;
		}
		ctx->flags &= ~HC_F_RES_BODY;
	}

	if (ctx->is_htx && hc_htx) {
		struct htx_blk *blk = NULL;

		chunk_reset(&trash);
		htx_dump(&trash, hc_htx, 1);
		if (applet_putchk(appctx, &trash) == -1)
			goto more;
		blk = htx_get_head_blk(hc_htx);
		while (blk)
			blk = htx_remove_blk(hc_htx, blk);
		htx_to_buf(hc_htx, &hc->res.buf);

	}

	/* we must close only if F_END is the last flag */
	if (ctx->flags ==  HC_F_RES_END) {
		ctx->flags &= ~HC_F_RES_END;
		goto end;
	}

more:
	if (!ctx->flags)
		applet_have_no_more_data(appctx);
	return 0;
end:
	return 1;

too_many_hdrs:
	return cli_err(appctx, "Too many headers.\n");
error:
	return cli_err(appctx, "Unknown error.\n");
}

static void hc_cli_release(struct appctx *appctx)
{
	struct hcli_svc_ctx *ctx = appctx->svcctx;
	struct httpclient *hc = ctx->hc;

	/* Everything possible was printed on the CLI, we can destroy the client */
	httpclient_stop_and_destroy(hc);

	return;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "httpclient", NULL }, "httpclient <method> <URI>               : launch an HTTP request", hc_cli_parse, hc_cli_io_handler, hc_cli_release,  NULL, ACCESS_EXPERT},
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

