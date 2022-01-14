/*
 * HTTP Client
 *
 * Copyright (C) 2021 HAProxy Technologies, William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This file implements an HTTP Client API.
 *
 */

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/cli.h>
#include <haproxy/dynbuf.h>
#include <haproxy/cfgparse.h>
#include <haproxy/connection.h>
#include <haproxy/global.h>
#include <haproxy/istbuf.h>
#include <haproxy/h1_htx.h>
#include <haproxy/http.h>
#include <haproxy/http_client.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/stream_interface.h>
#include <haproxy/tools.h>

#include <string.h>


static struct proxy *httpclient_proxy;
static struct server *httpclient_srv_raw;
#ifdef USE_OPENSSL
static struct server *httpclient_srv_ssl;
#endif
static struct applet httpclient_applet;

/* --- This part of the file implement an HTTP client over the CLI ---
 * The functions will be  starting by "hc_cli" for "httpclient cli"
 */

/* What kind of data we need to read */
#define HC_CLI_F_RES_STLINE     0x01
#define HC_CLI_F_RES_HDR        0x02
#define	HC_CLI_F_RES_BODY       0x04
#define HC_CLI_F_RES_END        0x08


/* These are the callback used by the HTTP Client when it needs to notify new
 * data, we only sets a flag in the IO handler  */

void hc_cli_res_stline_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;

	if (!appctx)
		return;

	appctx->ctx.cli.i0 |= HC_CLI_F_RES_STLINE;
	appctx_wakeup(appctx);
}

void hc_cli_res_headers_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;

	if (!appctx)
		return;

	appctx->ctx.cli.i0 |= HC_CLI_F_RES_HDR;
	appctx_wakeup(appctx);
}

void hc_cli_res_body_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;

	if (!appctx)
		return;

	appctx->ctx.cli.i0 |= HC_CLI_F_RES_BODY;
	appctx_wakeup(appctx);
}

void hc_cli_res_end_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;

	if (!appctx)
		return;

	appctx->ctx.cli.i0 |= HC_CLI_F_RES_END;
	appctx_wakeup(appctx);
}

/*
 * Parse an httpclient keyword on the cli:
 * httpclient <ID> <method> <URI>
 */
static int hc_cli_parse(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct httpclient *hc;
	char *err = NULL;
	enum http_meth_t meth;
	char *meth_str;
	struct ist uri;
	struct ist body = IST_NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[1] || !*args[2]) {
		memprintf(&err, ": not enough parameters");
		goto err;
	}

	meth_str = args[1];
	uri = ist(args[2]);

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

	appctx->ctx.cli.p0 = hc; /* store the httpclient ptr in the applet */
	appctx->ctx.cli.i0 = 0;

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
	struct stream_interface *si = appctx->owner;
	struct buffer *trash = alloc_trash_chunk();
	struct httpclient *hc = appctx->ctx.cli.p0;
	struct http_hdr *hdrs, *hdr;

	if (!trash)
		goto out;
	if (appctx->ctx.cli.i0 & HC_CLI_F_RES_STLINE) {
		chunk_appendf(trash, "%s %d %s\n",istptr(hc->res.vsn), hc->res.status, istptr(hc->res.reason));
		if (ci_putchk(si_ic(si), trash) == -1)
			si_rx_room_blk(si);
		appctx->ctx.cli.i0 &= ~HC_CLI_F_RES_STLINE;
		goto out;
	}

	if (appctx->ctx.cli.i0 & HC_CLI_F_RES_HDR) {
		hdrs = hc->res.hdrs;
		for (hdr = hdrs; isttest(hdr->v); hdr++) {
			if (!h1_format_htx_hdr(hdr->n, hdr->v, trash))
				goto out;
		}
		if (!chunk_memcat(trash, "\r\n", 2))
			goto out;
		if (ci_putchk(si_ic(si), trash) == -1)
			si_rx_room_blk(si);
		appctx->ctx.cli.i0 &= ~HC_CLI_F_RES_HDR;
		goto out;
	}

	if (appctx->ctx.cli.i0 & HC_CLI_F_RES_BODY) {
		int ret;

		ret = httpclient_res_xfer(hc, &si_ic(si)->buf);
		channel_add_input(si_ic(si), ret); /* forward what we put in the buffer channel */

		if (!httpclient_data(hc)) {/* remove the flag if the buffer was emptied */
			appctx->ctx.cli.i0 &= ~HC_CLI_F_RES_BODY;
		}
		goto out;
	}

	/* we must close only if F_END is the last flag */
	if (appctx->ctx.cli.i0 ==  HC_CLI_F_RES_END) {
		si_shutw(si);
		si_shutr(si);
		appctx->ctx.cli.i0 &= ~HC_CLI_F_RES_END;
		goto out;
	}

out:
	/* we didn't clear every flags, we should come back to finish things */
	if (appctx->ctx.cli.i0)
		si_rx_room_blk(si);

	free_trash_chunk(trash);
	return 0;
}

static void hc_cli_release(struct appctx *appctx)
{
	struct httpclient *hc = appctx->ctx.cli.p0;

	/* Everything possible was printed on the CLI, we can destroy the client */
	httpclient_stop_and_destroy(hc);

	return;
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "httpclient", NULL }, "httpclient <method> <URI>   : launch an HTTP request", hc_cli_parse, hc_cli_io_handler, hc_cli_release,  NULL, ACCESS_EXPERT},
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);


/* --- This part of the file implements the actual HTTP client API --- */

/*
 * Generate a simple request and fill the httpclient request buffer with it.
 * The request contains a request line generated from the absolute <url> and
 * <meth> as well as list of headers <hdrs>.
 *
 * If the buffer was filled correctly the function returns 0, if not it returns
 * an error_code but there is no guarantee that the buffer wasn't modified.
 */
int httpclient_req_gen(struct httpclient *hc, const struct ist url, enum http_meth_t meth, const struct http_hdr *hdrs, const struct ist payload)
{
	struct htx_sl *sl;
	struct htx *htx;
	int err_code = 0;
	struct ist meth_ist, vsn;
	unsigned int flags = HTX_SL_F_VER_11 | HTX_SL_F_NORMALIZED_URI | HTX_SL_F_HAS_SCHM;
	int i;
	int foundhost = 0, foundaccept = 0, foundua = 0;

	if (meth >= HTTP_METH_OTHER)
		goto error;

	meth_ist = http_known_methods[meth];

	vsn = ist("HTTP/1.1");

	htx = htx_from_buf(&hc->req.buf);
	if (!htx)
		goto error;

	if (!hc->ops.req_payload && !isttest(payload))
		flags |= HTX_SL_F_BODYLESS;

	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, meth_ist, url, vsn);
	if (!sl) {
		goto error;
	}
	sl->info.req.meth = meth;

	for (i = 0; hdrs && hdrs[i].n.len; i++) {
		/* Don't check the value length because a header value may be empty */
		if (isttest(hdrs[i].v) == 0)
			continue;

		if (isteqi(hdrs[i].n, ist("host")))
			foundhost = 1;
		else if (isteqi(hdrs[i].n, ist("accept")))
			foundaccept = 1;
		else if (isteqi(hdrs[i].n, ist("user-agent")))
			foundua = 1;

		if (!htx_add_header(htx, hdrs[i].n, hdrs[i].v))
			goto error;
	}

	if (!foundhost) {
		/* Add Host Header from URL */
		if (!htx_add_header(htx, ist("Host"), ist("h")))
			goto error;
		if (!http_update_host(htx, sl, url))
			goto error;
	}

	if (!foundaccept) {
		if (!htx_add_header(htx, ist("Accept"), ist("*/*")))
			goto error;
	}

	if (!foundua) {
		if (!htx_add_header(htx, ist("User-Agent"), ist(HTTPCLIENT_USERAGENT)))
			goto error;
	}


	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto error;

	if (isttest(payload)) {
		/* add the payload if it can feat in the buffer, no need to set
		 * the Content-Length, the data will be sent chunked */
		if (!htx_add_data_atonce(htx, payload))
			goto error;
	}

	/* If req.payload was set, does not set the end of stream which *MUST*
	 * be set in the callback */
	if (!hc->ops.req_payload)
		htx->flags |= HTX_FL_EOM;

	htx_to_buf(htx, &hc->req.buf);

	return 0;
error:
	err_code |= ERR_ALERT | ERR_ABORT;
	return err_code;
}

/*
 * transfer the response to the destination buffer and wakeup the HTTP client
 * applet so it could fill again its buffer.
 *
 * Return the number of bytes transferred.
 */
int httpclient_res_xfer(struct httpclient *hc, struct buffer *dst)
{
	int ret;

	ret = b_force_xfer(dst, &hc->res.buf, MIN(1024, b_data(&hc->res.buf)));
	/* call the client once we consumed all data */
	if (!b_data(&hc->res.buf) && hc->appctx)
		appctx_wakeup(hc->appctx);
	return ret;
}

/*
 * Transfer raw HTTP payload from src, and insert it into HTX format in the
 * httpclient.
 *
 * Must be used to transfer the request body.
 * Then wakeup the httpclient so it can transfer it.
 *
 * <end> tries to add the ending data flag if it succeed to copy all data.
 *
 * Return the number of bytes copied from src.
 */
int httpclient_req_xfer(struct httpclient *hc, struct ist src, int end)
{
	int ret = 0;
	struct htx *htx;

	htx = htx_from_buf(&hc->req.buf);
	if (!htx)
		goto error;

	if (hc->appctx)
		appctx_wakeup(hc->appctx);

	ret += htx_add_data(htx, src);


	/* if we copied all the data and the end flag is set */
	if ((istlen(src) == ret) && end) {
		htx->flags |= HTX_FL_EOM;
	}
	htx_to_buf(htx, &hc->req.buf);

error:

	return ret;
}


/*
 * Start the HTTP client
 * Create the appctx, session, stream and wakeup the applet
 *
 * FIXME: It also fill the sockaddr with the IP address, but currently only IP
 * in the URL are supported, it lacks a resolver.
 *
 * Return the <appctx> or NULL if it failed
 */
struct appctx *httpclient_start(struct httpclient *hc)
{
	struct applet *applet = &httpclient_applet;
	struct appctx *appctx;
	struct session *sess;
	struct stream *s;
	int len;
	struct split_url out;

	/* parse URI and fill sockaddr_storage */
	/* FIXME: use a resolver */
	len = url2sa(istptr(hc->req.url), istlen(hc->req.url), &hc->dst, &out);
	if (len == -1) {
		ha_alert("httpclient: cannot parse uri '%s'.\n", istptr(hc->req.url));
		goto out;
	}

	/* The HTTP client will be created in the same thread as the caller,
	 * avoiding threading issues */
	appctx = appctx_new(applet);
	if (!appctx)
		goto out;

	sess = session_new(httpclient_proxy, NULL, &appctx->obj_type);
	if (!sess) {
		ha_alert("httpclient: out of memory in %s:%d.\n", __FUNCTION__, __LINE__);
		goto out_free_appctx;
	}
	if ((s = stream_new(sess, &appctx->obj_type, &BUF_NULL)) == NULL) {
		ha_alert("httpclient: Failed to initialize stream %s:%d.\n", __FUNCTION__, __LINE__);
		goto out_free_appctx;
	}

	if (!sockaddr_alloc(&s->si[1].dst, &hc->dst, sizeof(hc->dst))) {
		ha_alert("httpclient: Failed to initialize stream in %s:%d.\n", __FUNCTION__, __LINE__);
		goto out_free_stream;
	}

	/* choose the SSL server or not */
	switch (out.scheme) {
		case SCH_HTTP:
			s->target = &httpclient_srv_raw->obj_type;
			break;
		case SCH_HTTPS:
#ifdef USE_OPENSSL
			s->target = &httpclient_srv_ssl->obj_type;
#else
			ha_alert("httpclient: OpenSSL is not available %s:%d.\n", __FUNCTION__, __LINE__);
			goto out_free_stream;
#endif
			break;
	}

	s->flags |= SF_ASSIGNED|SF_ADDR_SET;
	s->si[1].flags |= SI_FL_NOLINGER;
	s->res.flags |= CF_READ_DONTWAIT;

	/* applet is waiting for data */
	si_cant_get(&s->si[0]);
	appctx_wakeup(appctx);

	task_wakeup(s->task, TASK_WOKEN_INIT);
	hc->appctx = appctx;
	hc->flags |= HTTPCLIENT_FS_STARTED;
	appctx->ctx.httpclient.ptr = hc;
	appctx->st0 = HTTPCLIENT_S_REQ;

	return appctx;

out_free_stream:
	LIST_DELETE(&s->list);
	pool_free(pool_head_stream, s);
out_free_sess:
	session_free(sess);
out_free_appctx:
	appctx_free(appctx);
out:

	return NULL;
}

/*
 * This function tries to destroy the httpclient if it wasn't running.
 * If it was running, stop the client and ask it to autodestroy itself.
 *
 * Once this function is used, all pointer sto the client must be removed
 *
 */
void httpclient_stop_and_destroy(struct httpclient *hc)
{

	/* The httpclient was already stopped or never started, we can safely destroy it */
	if (hc->flags & HTTPCLIENT_FS_ENDED || !(hc->flags & HTTPCLIENT_FS_STARTED)) {
		httpclient_destroy(hc);
	} else {
	/* if the client wasn't stopped, ask for a stop and destroy */
		hc->flags |= (HTTPCLIENT_FA_AUTOKILL | HTTPCLIENT_FA_STOP);
		if (hc->appctx)
			appctx_wakeup(hc->appctx);
	}
}

/* Free the httpclient */
void httpclient_destroy(struct httpclient *hc)
{
	struct http_hdr *hdrs;


	if (!hc)
		return;

	/* we should never destroy a client which was started but not stopped  */
	BUG_ON(httpclient_started(hc) && !httpclient_ended(hc));

	/* request */
	istfree(&hc->req.url);
	b_free(&hc->req.buf);
	/* response */
	istfree(&hc->res.vsn);
	istfree(&hc->res.reason);
	hdrs = hc->res.hdrs;
	while (hdrs && isttest(hdrs->n)) {
		istfree(&hdrs->n);
		istfree(&hdrs->v);
		hdrs++;
	}
	ha_free(&hc->res.hdrs);
	b_free(&hc->res.buf);


	free(hc);

	return;
}

/* Allocate an httpclient and its buffers
 * Return NULL on failure */
struct httpclient *httpclient_new(void *caller, enum http_meth_t meth, struct ist url)
{
	struct httpclient *hc;
	struct buffer *b;

	hc = calloc(1, sizeof(*hc));
	if (!hc)
		goto err;

	b = b_alloc(&hc->req.buf);
	if (!b)
		goto err;
	b = b_alloc(&hc->res.buf);
	if (!b)
		goto err;

	hc->caller = caller;
	hc->req.url = istdup(url);
	hc->req.meth = meth;

	return hc;

err:
	httpclient_destroy(hc);
	return NULL;
}

static void httpclient_applet_io_handler(struct appctx *appctx)
{
	struct httpclient *hc = appctx->ctx.httpclient.ptr;
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct channel *req = &s->req;
	struct channel *res = &s->res;
	struct htx_blk *blk = NULL;
	struct htx *htx;
	struct htx_sl *sl = NULL;
	int32_t pos;
	uint32_t hdr_num;
	int ret;


	while (1) {

		/* required to stop */
		if (hc->flags & HTTPCLIENT_FA_STOP)
			goto end;

		switch(appctx->st0) {

			case HTTPCLIENT_S_REQ:
				/* we know that the buffer is empty here, since
				 * it's the first call, we can freely copy the
				 * request from the httpclient buffer */
				ret = b_xfer(&req->buf, &hc->req.buf, b_data(&hc->req.buf));
				if (!ret)
					goto more;

				htx = htx_from_buf(&req->buf);
				if (!htx)
					goto more;

				channel_add_input(req, htx->data);

				if (htx->flags & HTX_FL_EOM) /* check if a body need to be added */
					appctx->st0 = HTTPCLIENT_S_RES_STLINE;
				else
					appctx->st0 = HTTPCLIENT_S_REQ_BODY;

				goto more; /* we need to leave the IO handler once we wrote the request */
			break;
			case HTTPCLIENT_S_REQ_BODY:
				/* call the payload callback */
				{
					if (hc->ops.req_payload) {

						/* call the request callback */
						hc->ops.req_payload(hc);
						/* check if the request buffer is empty */

						htx = htx_from_buf(&req->buf);
						if (!htx_is_empty(htx))
							goto more;
						/* Here htx_to_buf() will set buffer data to 0 because
						 * the HTX is empty, and allow us to do an xfer.
						 */
						htx_to_buf(htx, &req->buf);

						ret = b_xfer(&req->buf, &hc->req.buf, b_data(&hc->req.buf));
						if (!ret)
							goto more;
						htx = htx_from_buf(&req->buf);
						if (!htx)
							goto more;

						channel_add_input(req, htx->data);
					}

					htx = htx_from_buf(&req->buf);
					if (!htx)
						goto more;

					/* if the request contains the HTX_FL_EOM, we finished the request part. */
					if (htx->flags & HTX_FL_EOM)
						appctx->st0 = HTTPCLIENT_S_RES_STLINE;

					goto more; /* we need to leave the IO handler once we wrote the request */
				}
			break;

			case HTTPCLIENT_S_RES_STLINE:
				/* copy the start line in the hc structure,then remove the htx block */
				if (!b_data(&res->buf))
					goto more;
				htx = htxbuf(&res->buf);
				if (!htx)
					goto more;
				blk = htx_get_first_blk(htx);
				if (blk && (htx_get_blk_type(blk) == HTX_BLK_RES_SL))
					sl = htx_get_blk_ptr(htx, blk);
				if (!sl || (!(sl->flags & HTX_SL_F_IS_RESP)))
					goto more;

				/* copy the status line in the httpclient */
				hc->res.status = sl->info.res.status;
				hc->res.vsn = istdup(htx_sl_res_vsn(sl));
				hc->res.reason = istdup(htx_sl_res_reason(sl));
				co_htx_remove_blk(res, htx, blk);
				/* caller callback */
				if (hc->ops.res_stline)
					hc->ops.res_stline(hc);

				/* if there is no HTX data anymore and the EOM flag is
				 * set, leave (no body) */
				if (htx_is_empty(htx) && htx->flags & HTX_FL_EOM)
					appctx->st0 = HTTPCLIENT_S_RES_END;
				else
					appctx->st0 = HTTPCLIENT_S_RES_HDR;
				break;

			case HTTPCLIENT_S_RES_HDR:
				/* first copy the headers in a local hdrs
				 * structure, once we the total numbers of the
				 * header we allocate the right size and copy
				 * them. The htx block of the headers are
				 * removed each time one is read  */
				{
					struct http_hdr hdrs[global.tune.max_http_hdr];

					if (!b_data(&res->buf))
						goto more;
					htx = htxbuf(&res->buf);
					if (!htx)
						goto more;

					hdr_num = 0;

					for (pos = htx_get_first(htx);  pos != -1; pos = htx_get_next(htx, pos)) {
						struct htx_blk *blk = htx_get_blk(htx, pos);
						enum htx_blk_type type = htx_get_blk_type(blk);

						if (type == HTX_BLK_EOH) {
							hdrs[hdr_num].n = IST_NULL;
							hdrs[hdr_num].v = IST_NULL;
							co_htx_remove_blk(res, htx, blk);
							break;
						}

						if (type != HTX_BLK_HDR)
							continue;

						hdrs[hdr_num].n = istdup(htx_get_blk_name(htx, blk));
						hdrs[hdr_num].v = istdup(htx_get_blk_value(htx, blk));
						if (!isttest(hdrs[hdr_num].v) || !isttest(hdrs[hdr_num].n))
							goto end;
						co_htx_remove_blk(res, htx, blk);
						hdr_num++;
					}

					if (hdr_num) {
						/* alloc and copy the headers in the httpclient struct */
						hc->res.hdrs = calloc((hdr_num + 1), sizeof(*hc->res.hdrs));
						if (!hc->res.hdrs)
							goto end;
						memcpy(hc->res.hdrs, hdrs, sizeof(struct http_hdr) * (hdr_num + 1));

						/* caller callback */
						if (hc->ops.res_headers)
							hc->ops.res_headers(hc);
					}

					/* if there is no HTX data anymore and the EOM flag is
					 * set, leave (no body) */
					if (htx_is_empty(htx) && htx->flags & HTX_FL_EOM) {
						appctx->st0 = HTTPCLIENT_S_RES_END;
					} else {
						appctx->st0 = HTTPCLIENT_S_RES_BODY;
					}
				}
			break;

			case HTTPCLIENT_S_RES_BODY:
				/*
				 * The IO handler removes the htx blocks in the response buffer and
				 * push them in the hc->res.buf buffer in a raw format.
				 */
				htx = htxbuf(&res->buf);
				if (!htx || htx_is_empty(htx))
					goto more;

				if (b_full(&hc->res.buf))
				goto process_data;

				/* decapsule the htx data to raw data */
				for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
					enum htx_blk_type type;

					blk = htx_get_blk(htx, pos);
					type = htx_get_blk_type(blk);
					if (type == HTX_BLK_DATA) {
						struct ist v = htx_get_blk_value(htx, blk);

						if ((b_room(&hc->res.buf) < v.len) )
							goto process_data;

						__b_putblk(&hc->res.buf, v.ptr, v.len);
						co_htx_remove_blk(res, htx, blk);
						/* the data must be processed by the caller in the receive phase */
						if (hc->ops.res_payload)
							hc->ops.res_payload(hc);
					} else {
						/* remove any block which is not a data block */
						co_htx_remove_blk(res, htx, blk);
					}
				}
				/* if not finished, should be called again */
				if (!(htx->flags & HTX_FL_EOM))
					goto more;

				/* end of message, we should quit */
				appctx->st0 = HTTPCLIENT_S_RES_END;
			break;

			case HTTPCLIENT_S_RES_END:
				goto end;
			break;
		}
	}

process_data:

	si_rx_chan_rdy(si);

	return;
more:
	/* There was not enough data in the response channel */

	si_rx_room_blk(si);

	if (appctx->st0 == HTTPCLIENT_S_RES_END)
		goto end;

	/* The state machine tries to handle as much data as possible, if there
	 * isn't any data to handle and a shutdown is detected, let's stop
	 * everything */
	if ((req->flags & (CF_SHUTR|CF_SHUTR_NOW)) ||
	    (res->flags & (CF_SHUTW|CF_SHUTW_NOW))) {
		goto end;
	}
	return;

end:
	if (hc->ops.res_end)
		hc->ops.res_end(hc);
	si_shutw(si);
	si_shutr(si);
	return;
}

static void httpclient_applet_release(struct appctx *appctx)
{
	struct httpclient *hc = appctx->ctx.httpclient.ptr;

	/* mark the httpclient as ended */
	hc->flags |= HTTPCLIENT_FS_ENDED;
	/* the applet is leaving, remove the ptr so we don't try to call it
	 * again from the caller */
	hc->appctx = NULL;


	/* destroy the httpclient when set to autotokill */
	if (hc->flags & HTTPCLIENT_FA_AUTOKILL) {
		httpclient_destroy(hc);
	}

	return;
}

/* HTTP client applet */
static struct applet httpclient_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<HTTPCLIENT>",
	.fct = httpclient_applet_io_handler,
	.release = httpclient_applet_release,
};

/*
 * Initialize the proxy for the HTTP client with 2 servers, one for raw HTTP,
 * the other for HTTPS.
 */

static int httpclient_init()
{
	int err_code = 0;
	char *errmsg = NULL;

	httpclient_proxy = alloc_new_proxy("<HTTPCLIENT>", PR_CAP_LISTEN|PR_CAP_INT, &errmsg);
	if (!httpclient_proxy) {
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	proxy_preset_defaults(httpclient_proxy);

	httpclient_proxy->options2 |= PR_O2_INDEPSTR;
	httpclient_proxy->mode = PR_MODE_HTTP;
	httpclient_proxy->maxconn = 0;
	httpclient_proxy->accept = NULL;
	httpclient_proxy->timeout.client = TICK_ETERNITY;
	/* The HTTP Client use the "option httplog" with the global log server */
	httpclient_proxy->conf.logformat_string = default_http_log_format;
	httpclient_proxy->http_needed = 1;

	/* clear HTTP server */
	httpclient_srv_raw = new_server(httpclient_proxy);
	if (!httpclient_srv_raw) {
		err_code |= ERR_ALERT | ERR_FATAL;
		memprintf(&errmsg, "out of memory.");
		goto err;
	}

	httpclient_srv_raw->iweight = 0;
	httpclient_srv_raw->uweight = 0;
	httpclient_srv_raw->xprt = xprt_get(XPRT_RAW);
	httpclient_srv_raw->id = strdup("<HTTPCLIENT>");
	if (!httpclient_srv_raw->id)
		goto err;

#ifdef USE_OPENSSL
	/* SSL HTTP server */
	httpclient_srv_ssl = new_server(httpclient_proxy);
	if (!httpclient_srv_ssl) {
		memprintf(&errmsg, "out of memory.");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}
	httpclient_srv_ssl->iweight = 0;
	httpclient_srv_ssl->uweight = 0;
	httpclient_srv_ssl->xprt = xprt_get(XPRT_SSL);
	httpclient_srv_ssl->use_ssl = 1;
	httpclient_srv_ssl->id = strdup("<HTTPSCLIENT>");
	if (!httpclient_srv_ssl->id)
		goto err;

	httpclient_srv_ssl->ssl_ctx.verify = SSL_SOCK_VERIFY_NONE;
#endif

	/* add the proxy in the proxy list only if everything is successful */
	httpclient_proxy->next = proxies_list;
	proxies_list = httpclient_proxy;

	/* link the 2 servers in the proxy */
	httpclient_srv_raw->next = httpclient_proxy->srv;
	httpclient_proxy->srv = httpclient_srv_raw;

#ifdef USE_OPENSSL
	httpclient_srv_ssl->next = httpclient_proxy->srv;
	httpclient_proxy->srv = httpclient_srv_ssl;
#endif


	return 0;

err:
	ha_alert("httpclient: cannot initialize.\n");
	free(errmsg);
	srv_drop(httpclient_srv_raw);
#ifdef USE_OPENSSL
	srv_drop(httpclient_srv_ssl);
#endif
	free_proxy(httpclient_proxy);
	return err_code;
}

static int httpclient_cfg_postparser()
{
	struct logsrv *logsrv;
	struct proxy *curproxy = httpclient_proxy;

	/* copy logs from "global" log list */
	list_for_each_entry(logsrv, &global.logsrvs, list) {
		struct logsrv *node = malloc(sizeof(*node));

		if (!node) {
			ha_alert("httpclient: cannot allocate memory.\n");
			goto err;
		}

		memcpy(node, logsrv, sizeof(*node));
		LIST_INIT(&node->list);
		LIST_APPEND(&curproxy->logsrvs, &node->list);
	}
	if (curproxy->conf.logformat_string) {
		char *err = NULL;

		curproxy->conf.args.ctx = ARGC_LOG;
		if (!parse_logformat_string(curproxy->conf.logformat_string, curproxy, &curproxy->logformat,
					    LOG_OPT_MANDATORY|LOG_OPT_MERGE_SPACES,
					    SMP_VAL_FE_LOG_END, &err)) {
			ha_alert("httpclient: failed to parse log-format : %s.\n", err);
			free(err);
			goto err;
		}
		curproxy->conf.args.file = NULL;
		curproxy->conf.args.line = 0;
	}
	return 0;
err:
	return 1;
}

/* initialize the proxy and servers for the HTTP client */

INITCALL0(STG_REGISTER, httpclient_init);
REGISTER_CONFIG_POSTPARSER("httpclient", httpclient_cfg_postparser);
