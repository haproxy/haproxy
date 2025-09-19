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
#include <haproxy/ssl_ckch.h>
#include <haproxy/dynbuf.h>
#include <haproxy/cfgparse.h>
#include <haproxy/global.h>
#include <haproxy/istbuf.h>
#include <haproxy/h1_htx.h>
#include <haproxy/http.h>
#include <haproxy/http_ana-t.h>
#include <haproxy/http_client.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_rules.h>
#include <haproxy/htx.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/resolvers.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/sock_inet.h>
#include <haproxy/stconn.h>
#include <haproxy/tools.h>

#include <string.h>

static struct proxy *httpclient_proxy;

#ifdef USE_OPENSSL
/* if the httpclient is not configured, error are ignored and features are limited */
static int hard_error_ssl = 0;
static int httpclient_ssl_verify = SSL_SOCK_VERIFY_REQUIRED;
static char *httpclient_ssl_ca_file = NULL;
#endif
static struct applet httpclient_applet;

/* if the httpclient is not configured, error are ignored and features are limited */
static int hard_error_resolvers = 0;
static char *resolvers_id = NULL;
static char *resolvers_prefer = NULL;
static int resolvers_disabled = 0;

static int httpclient_retries = CONN_RETRIES;
static int httpclient_timeout_connect = MS_TO_TICKS(5000);

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
	unsigned int flags = HTX_SL_F_VER_11 | HTX_SL_F_HAS_SCHM | HTX_SL_F_HAS_AUTHORITY;
	int i;
	int foundhost = 0, foundaccept = 0, foundua = 0;

	if (!(hc->options & HTTPCLIENT_O_HTTPPROXY))
		flags |= HTX_SL_F_NORMALIZED_URI;

	if (!b_alloc(&hc->req.buf, DB_CHANNEL))
		goto error;

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

	if (isttest(payload) && istlen(payload)) {
		/* add the Content-Length of the payload when not using the callback */

		if (!htx_add_header(htx, ist("Content-Length"), ist(ultoa(istlen(payload)))))
			goto error;

	}

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto error;

	if (isttest(payload) && istlen(payload)) {
		/* add the payload if it can feat in the buffer, Content-Length was added before */

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
	size_t room = b_room(dst);
	int ret;

	ret = b_force_xfer(dst, &hc->res.buf, MIN(room, b_data(&hc->res.buf)));

	/* call the client once we consumed all data */
	if (!b_data(&hc->res.buf)) {
		b_free(&hc->res.buf);
		if (ret && hc->appctx)
			appctx_wakeup(hc->appctx);
	}
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

	if (hc->flags & HTTPCLIENT_FA_DRAIN_REQ) {
		ret = istlen(src);
		goto end;
	}

	if (!b_alloc(&hc->req.buf, DB_CHANNEL))
		goto end;

	htx = htx_from_buf(&hc->req.buf);
	if (!htx)
		goto end;
	ret += htx_add_data(htx, src);

	if (ret && hc->appctx)
		appctx_wakeup(hc->appctx);

	/* if we copied all the data and the end flag is set */
	if ((istlen(src) == ret) && end) {
		/* no more data are expected. If the HTX buffer is empty, be
		 * sure to add something (EOT block in this case) to have
		 * something to send. It is important to be sure the EOM flags
		 * will be handled by the endpoint. Because the message is
		 * empty, this should not fail. Otherwise it is an error
		 */
		if (htx_is_empty(htx)) {
			if (!htx_add_endof(htx, HTX_BLK_EOT))
				goto end;
		}
		htx->flags |= HTX_FL_EOM;
	}
	htx_to_buf(htx, &hc->req.buf);

  end:

	return ret;
}

/* Set the 'timeout server' in ms for the next httpclient request */
void httpclient_set_timeout(struct httpclient *hc, int timeout)
{
	hc->timeout_server = timeout;
}

/*
 * Sets a destination for the httpclient from an HAProxy addr format
 * This will prevent to determine the destination from the URL
 * Return 0 in case of success or -1 otherwise.
 */
int httpclient_set_dst(struct httpclient *hc, const char *dst)
{
	struct sockaddr_storage *sk;
	char *errmsg = NULL;

	sockaddr_free(&hc->dst);
	/* 'sk' is statically allocated (no need to be freed). */
	sk = str2sa_range(dst, NULL, NULL, NULL, NULL, NULL, NULL,
	                  &errmsg, NULL, NULL, NULL,
	                  PA_O_PORT_OK | PA_O_STREAM | PA_O_XPRT | PA_O_CONNECT);
	if (!sk) {
		ha_alert("httpclient: Failed to parse destination address in %s\n", errmsg);
		free(errmsg);
		return -1;
	}

	if (!sockaddr_alloc(&hc->dst, sk, sizeof(*sk))) {
		ha_alert("httpclient: Failed to allocate sockaddr in %s:%d.\n", __FUNCTION__, __LINE__);
		return -1;
	}

	return 0;
}

/*
 * Split <url> in <scheme>, <host>, <port>
 */
static int httpclient_spliturl(struct ist url, enum http_scheme *scheme,
                               struct ist *host, int *port)
{
	enum http_scheme scheme_tmp = SCH_HTTP;
	int port_tmp = 0;
	struct ist scheme_ist, authority_ist, host_ist, port_ist;
	char *p, *end;
	struct http_uri_parser parser;

	parser = http_uri_parser_init(url);
	scheme_ist = http_parse_scheme(&parser);
	if (!isttest(scheme_ist)) {
		return 0;
	}

	if (isteqi(scheme_ist, ist("http://"))){
		scheme_tmp = SCH_HTTP;
		port_tmp = 80;
	} else if (isteqi(scheme_ist, ist("https://"))) {
		scheme_tmp = SCH_HTTPS;
		port_tmp = 443;
	}

	authority_ist = http_parse_authority(&parser, 1);
	if (!isttest(authority_ist)) {
		return 0;
	}
	p = end = istend(authority_ist);

	/* look for a port at the end of the authority */
	while (p > istptr(authority_ist) && isdigit((unsigned char)*--p))
		;

	if (*p == ':') {
		host_ist = ist2(istptr(authority_ist), p - istptr(authority_ist));
		port_ist = istnext(ist2(p, end - p));
		ist2str(trash.area, port_ist);
		port_tmp = atoi(trash.area);
	} else {
		host_ist = authority_ist;
	}

	if (scheme)
		*scheme = scheme_tmp;
	if (host)
		*host = host_ist;
	if (port)
		*port = port_tmp;

	return 1;
}

/*
 * Start the HTTP client
 * Create the appctx, session, stream and wakeup the applet
 *
 * Return the <appctx> or NULL if it failed
 */
struct appctx *httpclient_start(struct httpclient *hc)
{
	struct applet *applet = &httpclient_applet;
	struct appctx *appctx;

	/* if the client was started and not ended, an applet is already
	 * running, we shouldn't try anything */
	if (httpclient_started(hc) && !httpclient_ended(hc))
		return NULL;

	/* The HTTP client will be created in the same thread as the caller,
	 * avoiding threading issues */
	appctx = appctx_new_here(applet, NULL);
	if (!appctx)
		goto out;
	appctx->svcctx = hc;
	hc->flags = 0;

	if (appctx_init(appctx) == -1) {
		ha_alert("httpclient: Failed to initialize appctx %s:%d.\n", __FUNCTION__, __LINE__);
		goto out_free_appctx;
	}

	return appctx;

out_free_appctx:
	appctx_free_on_early_error(appctx);
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
		/* the calling applet doesn't exist anymore */
		hc->caller = NULL;
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

	if (!(hc->options & HTTPCLIENT_O_RES_HTX)) {
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
	}

	b_free(&hc->res.buf);
	sockaddr_free(&hc->dst);

	free(hc);

	return;
}

/* Allocate an httpclient and its buffers
 * Use the default httpclient_proxy
 *
 * Return NULL on failure */
struct httpclient *httpclient_new(void *caller, enum http_meth_t meth, struct ist url)
{
	struct httpclient *hc;

	if (!httpclient_proxy)
		return NULL;

	hc = calloc(1, sizeof(*hc));
	if (!hc)
		goto err;

	hc->req.buf = BUF_NULL;
	hc->res.buf = BUF_NULL;
	hc->caller = caller;
	hc->req.url = istdup(url);
	hc->req.meth = meth;
	httpclient_set_proxy(hc, httpclient_proxy);

	return hc;

err:
	httpclient_destroy(hc);
	return NULL;
}

/* Allocate an httpclient and its buffers,
 * Use the proxy <px>
 *
 * Return and httpclient or NULL.
 */
struct httpclient *httpclient_new_from_proxy(struct proxy *px, void *caller, enum http_meth_t meth, struct ist url)
{
	struct httpclient *hc;

	if (!px)
		return NULL;

	hc = httpclient_new(caller, meth, url);
	if (!hc)
		return NULL;

	httpclient_set_proxy(hc, px);

	return hc;
}

/*
 * Configure an httpclient with a specific proxy <px>
 *
 * The proxy <px> must contains 2 srv, one configured for clear connections, the other for SSL.
 *
 */
int httpclient_set_proxy(struct httpclient *hc, struct proxy *px)
{
	struct server *srv;

	hc->px = px;

	for (srv = px->srv; srv != NULL; srv = srv->next) {
		if (srv->xprt == xprt_get(XPRT_RAW)) {
			hc->srv_raw = srv;
#ifdef USE_OPENSSL
		} else if (srv->xprt == xprt_get(XPRT_SSL)) {
			hc->srv_ssl = srv;
#endif
		}
	}

	return 0;
}

void httpclient_applet_io_handler(struct appctx *appctx)
{
	struct httpclient *hc = appctx->svcctx;
	struct buffer *outbuf, *inbuf;
	struct htx_blk *blk = NULL;
	struct htx *htx;
	struct htx_sl *sl = NULL;
	uint32_t hdr_num;
	int ret;

	if (unlikely(applet_fl_test(appctx, APPCTX_FL_EOS|APPCTX_FL_ERROR))) {
		applet_reset_input(appctx);
		goto out;
	}

	/* The IO handler could be called after the release, so we need to
	 * check if hc is still there to run the IO handler */
	if (!hc)
		goto out;

	while (1) {
		/* required to stop */
		if (hc->flags & HTTPCLIENT_FA_STOP)
			goto error;

		switch(appctx->st0) {
			case HTTPCLIENT_S_REQ:
				outbuf = applet_get_outbuf(appctx);
				if (outbuf == NULL) {
					applet_have_more_data(appctx);
					goto out;
				}

				/* we know that the buffer is empty here, since
				 * it's the first call, we can freely copy the
				 * request from the httpclient buffer */
				ret = b_xfer(outbuf, &hc->req.buf, b_data(&hc->req.buf));
				if (!ret) {
					applet_have_more_data(appctx);
					goto out;
				}

				if (!b_data(&hc->req.buf))
					b_free(&hc->req.buf);

				htx = htxbuf(outbuf);
				if (htx_is_empty(htx)) {
					applet_have_more_data(appctx);
					goto out;
				}

				if (htx->flags & HTX_FL_EOM) { /* check if a body need to be added */
					appctx->st0 = HTTPCLIENT_S_RES_STLINE;
					applet_set_eoi(appctx);
					goto out; /* we need to leave the IO handler once we wrote the request */
				}

				applet_have_more_data(appctx);
				appctx->st0 = HTTPCLIENT_S_REQ_BODY;
				__fallthrough;

			case HTTPCLIENT_S_REQ_BODY:
				outbuf = applet_get_outbuf(appctx);
				if (outbuf == NULL) {
					applet_have_more_data(appctx);
					goto out;
				}

				/* call the payload callback */
				if (hc->ops.req_payload) {
					struct htx *hc_htx;

					if (applet_input_data(appctx)) {
						/* A response was received but we are still process the request.
						 * It is unexpected and not really supported with the current API.
						 * So lets drain the request to avoid any issue.
						 */
						b_reset(outbuf);
						hc->flags |= HTTPCLIENT_FA_DRAIN_REQ;
						appctx->st0 = HTTPCLIENT_S_RES_STLINE;
						break;
					}

					/* call the request callback */
					hc->ops.req_payload(hc);

					hc_htx = htxbuf(&hc->req.buf);
					if (htx_is_empty(hc_htx))
						goto out;

					htx = htx_from_buf(outbuf);
					if (htx_is_empty(htx)) {
						/* Here htx_to_buf() will set buffer data to 0 because
						 * the HTX is empty, and allow us to do an xfer.
						 */
						htx_to_buf(hc_htx, &hc->req.buf);
						htx_to_buf(htx, outbuf);
						b_xfer(outbuf, &hc->req.buf, b_data(&hc->req.buf));
					} else {
						struct htx_ret ret;

						ret = htx_xfer_blks(htx, hc_htx, htx_used_space(hc_htx), HTX_BLK_UNUSED);
						if (!ret.ret) {
							applet_have_more_data(appctx);
							goto out;
						}

						/* we must copy the EOM if we empty the buffer */
						if (htx_is_empty(hc_htx)) {
							htx->flags |= (hc_htx->flags & HTX_FL_EOM);
						}
						htx_to_buf(htx, outbuf);
						htx_to_buf(hc_htx, &hc->req.buf);
					}

					if (!b_data(&hc->req.buf))
						b_free(&hc->req.buf);
				}

				htx = htxbuf(outbuf);

				/* if the request contains the HTX_FL_EOM, we finished the request part. */
				if (htx->flags & HTX_FL_EOM) {
					appctx->st0 = HTTPCLIENT_S_RES_STLINE;
					applet_set_eoi(appctx);
					goto out; /* we need to leave the IO handler once we wrote the request */
				}

				applet_have_more_data(appctx);
				goto out;

			case HTTPCLIENT_S_RES_STLINE:
				applet_will_consume(appctx);
				inbuf = applet_get_inbuf(appctx);
				if (inbuf == NULL || !applet_input_data(appctx)) {
					applet_need_more_data(appctx);
					goto out;
				}

				/* in HTX mode, don't try to copy the stline
				 * alone, we must copy the headers with it */
                                if (hc->options & HTTPCLIENT_O_RES_HTX) {
					appctx->st0 = HTTPCLIENT_S_RES_HDR;
					break;
				}

				/* copy the start line in the hc structure,then remove the htx block */
				htx = htxbuf(inbuf);
				if (htx_get_head_type(htx) != HTX_BLK_RES_SL)
					goto error;
				blk = DISGUISE(htx_get_head_blk(htx));
				sl = htx_get_blk_ptr(htx, blk);

				/* Skipp any 1XX interim responses */
				if (sl->info.res.status < 200) {
					/* Upgrade are not supported. Report an error */
					if (sl->info.res.status == 101)
						goto error;

					while (blk) {
						enum htx_blk_type type = htx_get_blk_type(blk);

						blk = htx_remove_blk(htx, blk);
						if (type == HTX_BLK_EOH) {
							htx_to_buf(htx, inbuf);
							break;
						}
					}
					break;
				}

				/* copy the status line in the httpclient */
				hc->res.status = sl->info.res.status;
				hc->res.vsn = istdup(htx_sl_res_vsn(sl));
				hc->res.reason = istdup(htx_sl_res_reason(sl));
				htx_remove_blk(htx, blk);

				/* caller callback */
				if (hc->ops.res_stline)
					hc->ops.res_stline(hc);

				/* if there is no HTX data anymore and the EOM flag is
				 * set, leave (no body) */
				if (htx_is_empty(htx) && htx->flags & HTX_FL_EOM)
					appctx->st0 = HTTPCLIENT_S_RES_END;
				else
					appctx->st0 = HTTPCLIENT_S_RES_HDR;

				applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);
				htx_to_buf(htx, inbuf);
				break;

			case HTTPCLIENT_S_RES_HDR:
				applet_will_consume(appctx);
				inbuf = applet_get_inbuf(appctx);
				if (inbuf == NULL || !applet_input_data(appctx)) {
					applet_need_more_data(appctx);
					goto out;
				}

				htx = htxbuf(inbuf);
				BUG_ON(htx_is_empty(htx));

				if (hc->options & HTTPCLIENT_O_RES_HTX) {
					/* HTX mode transfers the header to the hc buffer */
					struct htx *hc_htx;
					struct htx_ret ret;

					if (!b_alloc(&hc->res.buf, DB_MUX_TX)) {
						applet_wont_consume(appctx);
						goto out;
					}
					hc_htx = htxbuf(&hc->res.buf);

					/* xfer the headers */
					ret = htx_xfer_blks(hc_htx, htx, htx_used_space(htx), HTX_BLK_EOH);
					if (!ret.ret) {
						applet_need_more_data(appctx);
						goto out;
					}
					else
						applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);

					if (htx->flags & HTX_FL_EOM)
						hc_htx->flags |= HTX_FL_EOM;

					htx_to_buf(hc_htx, &hc->res.buf);

				} else {
				/* first copy the headers in a local hdrs
				 * structure, once we the total numbers of the
				 * header we allocate the right size and copy
				 * them. The htx block of the headers are
				 * removed each time one is read  */
					struct http_hdr hdrs[global.tune.max_http_hdr];

					hdr_num = 0;
					blk = htx_get_head_blk(htx);
					while (blk) {
						enum htx_blk_type type = htx_get_blk_type(blk);

						if (type == HTX_BLK_HDR) {
							hdrs[hdr_num].n = istdup(htx_get_blk_name(htx, blk));
							hdrs[hdr_num].v = istdup(htx_get_blk_value(htx, blk));
							hdr_num++;
						}
						else if (type == HTX_BLK_EOH) {
							/* create a NULL end of array and leave the loop */
							hdrs[hdr_num].n = IST_NULL;
							hdrs[hdr_num].v = IST_NULL;
							htx_remove_blk(htx, blk);
							break;
						}
						blk = htx_remove_blk(htx, blk);
					}

					if (hdr_num) {
						/* alloc and copy the headers in the httpclient struct */
						hc->res.hdrs = calloc((hdr_num + 1), sizeof(*hc->res.hdrs));
						if (!hc->res.hdrs)
							goto error;
						memcpy(hc->res.hdrs, hdrs, sizeof(struct http_hdr) * (hdr_num + 1));
						applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);
					}
				}
				/* caller callback */
				if (hc->ops.res_headers)
					hc->ops.res_headers(hc);

				/* if there is no HTX data anymore and the EOM flag is
				 * set, leave (no body) */
				if (htx_is_empty(htx) && htx->flags & HTX_FL_EOM) {
					appctx->st0 = HTTPCLIENT_S_RES_END;
				} else {
					appctx->st0 = HTTPCLIENT_S_RES_BODY;
				}

				htx_to_buf(htx, inbuf);
				break;

			case HTTPCLIENT_S_RES_BODY:
				applet_will_consume(appctx);
				inbuf = applet_get_inbuf(appctx);
				if (inbuf == NULL || !applet_input_data(appctx)) {
					applet_need_more_data(appctx);
					goto out;
				}

				/*
				 * The IO handler removes the htx blocks in the response buffer and
				 * push them in the hc->res.buf buffer in a raw format.
				 */
				htx = htxbuf(inbuf);
				if (htx_is_empty(htx)) {
					applet_need_more_data(appctx);
					goto out;
				}

				if (!b_alloc(&hc->res.buf, DB_MUX_TX)) {
					applet_wont_consume(appctx);
					goto out;
				}

				if (hc->options & HTTPCLIENT_O_RES_HTX) {
					/* HTX mode transfers the header to the hc buffer */
					struct htx *hc_htx;
					struct htx_ret ret;

					hc_htx = htxbuf(&hc->res.buf);

					ret = htx_xfer_blks(hc_htx, htx, htx_used_space(htx), HTX_BLK_UNUSED);
					if (!ret.ret)
						applet_wont_consume(appctx);
					else
						applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);

					if (htx_is_empty(htx) && (htx->flags & HTX_FL_EOM))
						hc_htx->flags |= HTX_FL_EOM;

					htx_to_buf(hc_htx, &hc->res.buf);
				} else {

					/* decapsule the htx data to raw data */
					blk = htx_get_head_blk(htx);
					while (blk) {
						enum htx_blk_type type = htx_get_blk_type(blk);

						/* we should try to copy the maximum output data in a block, which fit
						 * the destination buffer */
						if (type == HTX_BLK_DATA) {
							struct ist v = htx_get_blk_value(htx, blk);
							uint32_t room = b_room(&hc->res.buf);
							uint32_t vlen;

							vlen = MIN(v.len, room);
							__b_putblk(&hc->res.buf, v.ptr, vlen);

							if (vlen == v.len)
								blk = htx_remove_blk(htx, blk);
							else {
								htx_cut_data_blk(htx, blk, vlen);
								/* cannot copy everything, need to process */
								applet_wont_consume(appctx);
								break;
							}
						} else {
							/* remove any block which is not a data block */
							blk = htx_remove_blk(htx, blk);
						}
					}
				}

				applet_fl_clr(appctx, APPCTX_FL_INBLK_FULL);

				/* the data must be processed by the caller in the receive phase */
				if (hc->ops.res_payload)
					hc->ops.res_payload(hc);

				/* if not finished, should be called again */
				if ((htx_is_empty(htx) && (htx->flags & HTX_FL_EOM))) {
					appctx->st0 = HTTPCLIENT_S_RES_END;
					htx_to_buf(htx, inbuf);
					break;
				}

				htx_to_buf(htx, inbuf);
				applet_need_more_data(appctx);
				goto out;

			case HTTPCLIENT_S_RES_END:
				applet_set_eos(appctx);
				goto out;
		}
	}

out:
	return;

error:
	applet_set_eos(appctx);
	applet_set_error(appctx);
	goto out;
}

int httpclient_applet_init(struct appctx *appctx)
{
	struct httpclient *hc = appctx->svcctx;
	struct stream *s;
	struct sockaddr_storage *addr = NULL;
	struct sockaddr_storage ss_url = {};
	struct sockaddr_storage *ss_dst;
	enum obj_type *target = NULL;
	struct ist host = IST_NULL;
	enum http_scheme scheme;
	int port;
	int doresolve = 0;


	/* parse the URL and  */
	if (!httpclient_spliturl(hc->req.url, &scheme, &host, &port))
		goto out_error;

	if (hc->dst) {
		/* if httpclient_set_dst() was used, sets the alternative address */
		ss_dst = hc->dst;
	} else {
		/* set the dst using the host, or 0.0.0.0 to resolve */
		ist2str(trash.area, host);
		ss_dst = str2ip2(trash.area, &ss_url, 0);
		if (!ss_dst) { /* couldn't get an IP from that, try to resolve */
			doresolve = 1;
			ss_dst = str2ip2("0.0.0.0", &ss_url, 0);
		}
		sock_inet_set_port(ss_dst, port);
	}

	if (!sockaddr_alloc(&addr, ss_dst, sizeof(*ss_dst)))
		goto out_error;

	/* choose the SSL server or not */
	switch (scheme) {
		case SCH_HTTP:
			target = &hc->srv_raw->obj_type;
			break;
		case SCH_HTTPS:
#ifdef USE_OPENSSL
			if (hc->srv_ssl) {
				target = &hc->srv_ssl->obj_type;
			} else {
				ha_alert("httpclient: SSL was disabled (wrong verify/ca-file)!\n");
				goto out_free_addr;
			}
#else
			ha_alert("httpclient: OpenSSL is not available %s:%d.\n", __FUNCTION__, __LINE__);
			goto out_free_addr;
#endif
			break;
	}

	if (appctx_finalize_startup(appctx, hc->px, &hc->req.buf) == -1) {
		ha_alert("httpclient: Failed to initialize appctx %s:%d.\n", __FUNCTION__, __LINE__);
		goto out_free_addr;
	}

	s = appctx_strm(appctx);
	s->target = target;
	if (objt_server(s->target))
		s->sv_tgcounters = __objt_server(s->target)->counters.shared.tg[tgid - 1];

	/* set the "timeout server" */
	s->scb->ioto = hc->timeout_server;

	if (doresolve) {
		/* in order to do the set-dst we need to put the address on the front */
		s->scf->dst = addr;
	} else {
		/* in cases we don't use the resolve we already have the address
		 * and must put it on the backend side, some of the cases are
		 * not meant to be used on the frontend (sockpair, unix socket etc.) */
		s->scb->dst = addr;
	}

	s->scb->flags |= (SC_FL_RCV_ONCE|SC_FL_NOLINGER);
	s->flags |= SF_ASSIGNED;

	/* applet is waiting for data */
	applet_need_more_data(appctx);
	appctx_wakeup(appctx);

	hc->appctx = appctx;
	hc->flags |= HTTPCLIENT_FS_STARTED;

	/* The request was transferred when the stream was created. So switch
	 * directly to REQ_BODY or RES_STLINE state
	 */
	if (hc->ops.req_payload)
		appctx->st0 = HTTPCLIENT_S_REQ_BODY;
	else {
		appctx->st0 =  HTTPCLIENT_S_RES_STLINE;
		applet_set_eoi(appctx);
	}
	return 0;

 out_free_addr:
	sockaddr_free(&addr);
 out_error:
	return -1;
}

void httpclient_applet_release(struct appctx *appctx)
{
	struct httpclient *hc = appctx->svcctx;

	/* mark the httpclient as ended */
	hc->flags |= HTTPCLIENT_FS_ENDED;
	/* the applet is leaving, remove the ptr so we don't try to call it
	 * again from the caller */
	hc->appctx = NULL;

	if (hc->ops.res_end)
		hc->ops.res_end(hc);

	/* destroy the httpclient when set to autotokill */
	if (hc->flags & HTTPCLIENT_FA_AUTOKILL) {
		httpclient_destroy(hc);
	}

	/* be sure not to use this ptr anymore if the IO handler is called a
	 * last time */
	appctx->svcctx = NULL;

	return;
}

/* HTTP client applet */
static struct applet httpclient_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.flags = APPLET_FL_NEW_API|APPLET_FL_HTX,
	.name = "<HTTPCLIENT>",
	.fct = httpclient_applet_io_handler,
	.rcv_buf = appctx_htx_rcv_buf,
	.snd_buf = appctx_htx_snd_buf,
	.init = httpclient_applet_init,
	.release = httpclient_applet_release,
};


static int httpclient_resolve_init(struct proxy *px)
{
	struct act_rule *rule;
	int i;
	char *do_resolve = NULL;
	char *http_rules[][11] = {
	       { "set-var(txn.hc_ip)", "dst", "" },
	       { do_resolve, "hdr(Host),host_only", "if", "{", "var(txn.hc_ip)", "-m", "ip", "0.0.0.0", "}", "" },
	       { "return", "status", "503", "if", "{", "var(txn.hc_ip)", "-m", "ip", "0.0.0.0", "}", "" },
	       { "capture", "var(txn.hc_ip)", "len", "40", "" },
	       { "set-dst", "var(txn.hc_ip)", "" },
	       { "" }
	};


	if (resolvers_disabled)
		return 0;

	if (!resolvers_id)
		resolvers_id = strdup("default");

	memprintf(&do_resolve, "do-resolve(txn.hc_ip,%s%s%s)", resolvers_id, resolvers_prefer ? "," : "", resolvers_prefer ? resolvers_prefer : "");
	http_rules[1][0] = do_resolve;

	/* Try to create the default resolvers section */
	resolvers_create_default();

	/* if the resolver does not exist and no hard_error was set, simply ignore resolving */
	if (!find_resolvers_by_id(resolvers_id) && !hard_error_resolvers) {
		free(do_resolve);
		return 0;
	}


	for (i = 0; *http_rules[i][0] != '\0'; i++) {
		rule = parse_http_req_cond((const char **)http_rules[i], "httpclient", 0, px);
		if (!rule) {
			free(do_resolve);
			ha_alert("Couldn't setup the httpclient resolver.\n");
			return 1;
		}
		LIST_APPEND(&px->http_req_rules, &rule->list);
	}

	free(do_resolve);
	return 0;
}

/*
 * Creates an internal proxy which will be used for httpclient.
 * This will allocate 2 servers (raw and ssl) and 1 proxy.
 *
 * This function must be called from a precheck callback.
 *
 * Return a proxy or NULL.
 */
struct proxy *httpclient_create_proxy(const char *id)
{
	int err_code = ERR_NONE;
	char *errmsg = NULL;
	struct proxy *px = NULL;
	struct server *srv_raw = NULL;
#ifdef USE_OPENSSL
	struct server *srv_ssl = NULL;
#endif

	/* the httpclient is not usable in the master process */
	if (master)
		return ERR_NONE;

	px = alloc_new_proxy(id, PR_CAP_LISTEN|PR_CAP_INT|PR_CAP_HTTPCLIENT, &errmsg);
	if (!px) {
		memprintf(&errmsg, "couldn't allocate proxy.");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	px->options |= PR_O_WREQ_BODY;
	px->retry_type |= PR_RE_CONN_FAILED | PR_RE_DISCONNECTED | PR_RE_TIMEOUT;
	px->options2 |= PR_O2_INDEPSTR;
	px->mode = PR_MODE_HTTP;
	px->maxconn = 0;
	px->accept = NULL;
	px->conn_retries = httpclient_retries;
	px->timeout.connect = httpclient_timeout_connect;
	px->timeout.client = TICK_ETERNITY;
	/* The HTTP Client use the "option httplog" with the global loggers */
	px->logformat.str = httpclient_log_format;
	px->logformat.conf.file = strdup("httpclient");
	px->http_needed = 1;

	/* clear HTTP server */
	srv_raw = new_server(px);
	if (!srv_raw) {
		memprintf(&errmsg, "out of memory.");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

	srv_settings_cpy(srv_raw, px->defsrv, 0);
	srv_raw->iweight = 0;
	srv_raw->uweight = 0;
	srv_raw->xprt = xprt_get(XPRT_RAW);
	srv_raw->flags |= SRV_F_MAPPORTS;  /* needed to apply the port change with resolving */
	srv_raw->id = strdup("<HTTPCLIENT>");
	if (!srv_raw->id) {
		memprintf(&errmsg, "out of memory.");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

#ifdef USE_OPENSSL
	/* SSL HTTP server */
	srv_ssl = new_server(px);
	if (!srv_ssl) {
		memprintf(&errmsg, "out of memory.");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}
	srv_settings_cpy(srv_ssl, px->defsrv, 0);
	srv_ssl->iweight = 0;
	srv_ssl->uweight = 0;
	srv_ssl->xprt = xprt_get(XPRT_SSL);
	srv_ssl->use_ssl = 1;
	srv_ssl->flags |= SRV_F_MAPPORTS;  /* needed to apply the port change with resolving */
	srv_ssl->id = strdup("<HTTPSCLIENT>");
	if (!srv_ssl->id) {
		memprintf(&errmsg, "out of memory.");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	if (ssl_sock_parse_alpn("h2,http/1.1", &srv_ssl->ssl_ctx.alpn_str, &srv_ssl->ssl_ctx.alpn_len, &errmsg) != 0) {
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}
#endif
	srv_ssl->ssl_ctx.verify = httpclient_ssl_verify;
	/* if the verify is required, try to load the system CA */
	if (httpclient_ssl_verify == SSL_SOCK_VERIFY_REQUIRED) {

		srv_ssl->ssl_ctx.ca_file = strdup(httpclient_ssl_ca_file ? httpclient_ssl_ca_file : "@system-ca");
		if (!__ssl_store_load_locations_file(srv_ssl->ssl_ctx.ca_file, 1, CAFILE_CERT, !hard_error_ssl)) {
			/* if we failed to load the ca-file, only quits in
			 * error with hard_error, otherwise just disable the
			 * feature. */
			if (hard_error_ssl) {
				memprintf(&errmsg, "cannot initialize SSL verify with 'ca-file \"%s\"'.", srv_ssl->ssl_ctx.ca_file);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto err;
			} else {
				ha_free(&srv_ssl->ssl_ctx.ca_file);
				srv_detach(srv_ssl);
				srv_drop(srv_ssl);
				srv_ssl = NULL;
			}
		}
	}

#endif

	/* add the proxy in the proxy list only if everything is successful */
	px->next = proxies_list;
	proxies_list = px;

	if (httpclient_resolve_init(px) != 0) {
		memprintf(&errmsg, "cannot initialize resolvers.");
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

err:
	if (err_code & ERR_CODE) {
		ha_alert("httpclient: cannot initialize: %s\n", errmsg);
		free(errmsg);
		free_proxy(px);

		return NULL;
	}
	return px;
}

/*
 * Initialize the proxy for the HTTP client with 2 servers, one for raw HTTP,
 * the other for HTTPS.
 */
static int httpclient_precheck()
{
	/* the httpclient is not usable in the master process */
	if (master)
		return ERR_NONE;

	/* initialize the default httpclient_proxy which is used for the CLI and the lua */
	httpclient_proxy = httpclient_create_proxy("<HTTPCLIENT>");
	if (!httpclient_proxy)
		return ERR_RETRYABLE;

	return ERR_NONE;
}

/* Initialize the logs for every proxy dedicated to the httpclient */
static int httpclient_postcheck_proxy(struct proxy *curproxy)
{
	int err_code = ERR_NONE;
	struct logger *logger;
	char *errmsg = NULL;
#ifdef USE_OPENSSL
	struct server *srv = NULL;
	struct server *srv_ssl = NULL;
#endif

	/* the httpclient is not usable in the master process */
	if (master)
		return ERR_NONE;

	if (!(curproxy->cap & PR_CAP_HTTPCLIENT))
		return ERR_NONE; /* nothing to do */

	/* copy logs from "global" log list */
	list_for_each_entry(logger, &global.loggers, list) {
		struct logger *node = dup_logger(logger);

		if (!node) {
			memprintf(&errmsg, "out of memory.");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}
		LIST_APPEND(&curproxy->loggers, &node->list);
	}

#ifdef USE_OPENSSL
	/* initialize the SNI for the SSL servers */

	for (srv = curproxy->srv; srv != NULL; srv = srv->next) {
		if (srv->xprt == xprt_get(XPRT_SSL)) {
			srv_ssl = srv;
		}
	}
	if (srv_ssl && !srv_ssl->sni_expr) {
		/* init the SNI expression */
		/* always use the host header as SNI, without the port */
		srv_ssl->sni_expr = strdup("req.hdr(host),field(1,:)");
		srv_ssl->ssl_ctx.sni = _parse_srv_expr(srv_ssl->sni_expr,
		                                       &curproxy->conf.args,
		                                       NULL, 0, NULL);
		if (!srv_ssl->ssl_ctx.sni) {
			memprintf(&errmsg, "failed to configure sni.");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		srv_ssl->pool_conn_name = strdup(srv_ssl->sni_expr);
		srv_ssl->pool_conn_name_expr = _parse_srv_expr(srv_ssl->pool_conn_name,
		                                               &curproxy->conf.args,
		                                               NULL, 0, NULL);
		if (!srv_ssl->pool_conn_name_expr) {
			memprintf(&errmsg, "failed to configure pool-conn-name.");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}
	}
#endif

err:
	if (err_code & ERR_CODE) {
		ha_alert("httpclient: failed to initialize: %s\n", errmsg);
		free(errmsg);

	}
	return err_code;
}

/* initialize the proxy and servers for the HTTP client */

REGISTER_PRE_CHECK(httpclient_precheck);
REGISTER_POST_PROXY_CHECK(httpclient_postcheck_proxy);

static int httpclient_parse_global_resolvers(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	/* any configuration should set the hard_error flag */
	hard_error_resolvers = 1;

	free(resolvers_id);
	resolvers_id = strdup(args[1]);

	return 0;
}

/* config parser for global "httpclient.resolvers.disabled", accepts "on" or "off" */
static int httpclient_parse_global_resolvers_disabled(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		resolvers_disabled = 1;
	else if (strcmp(args[1], "off") == 0)
		resolvers_disabled = 0;
	else {
		memprintf(err, "'%s' expects either 'on' or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

static int httpclient_parse_global_prefer(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	/* any configuration should set the hard_error flag */
	hard_error_resolvers = 1;


	if (strcmp(args[1],"ipv4") == 0)
		resolvers_prefer = "ipv4";
	else if (strcmp(args[1],"ipv6") == 0)
		resolvers_prefer = "ipv6";
	else {
		ha_alert("parsing [%s:%d] : '%s' expects 'ipv4' or 'ipv6' as argument.\n", file, line, args[0]);
		return -1;
	}

	return 0;
}


#ifdef USE_OPENSSL
static int httpclient_parse_global_ca_file(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	/* any configuration should set the hard_error flag */
	hard_error_ssl = 1;

	free(httpclient_ssl_ca_file);
	httpclient_ssl_ca_file = strdup(args[1]);

	return 0;
}

static int httpclient_parse_global_verify(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	/* any configuration should set the hard_error flag */
	hard_error_ssl = 1;

	if (strcmp(args[1],"none") == 0)
		httpclient_ssl_verify = SSL_SOCK_VERIFY_NONE;
	else if (strcmp(args[1],"required") == 0)
		httpclient_ssl_verify = SSL_SOCK_VERIFY_REQUIRED;
	else {
		ha_alert("parsing [%s:%d] : '%s' expects 'none' or 'required' as argument.\n", file, line, args[0]);
		return -1;
	}

	return 0;
}
#endif /* ! USE_OPENSSL */

static int httpclient_parse_global_retries(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n",
			 file, line, args[0]);
		return -1;
	}
	httpclient_retries = atol(args[1]);

	return 0;
}

static int httpclient_parse_global_timeout_connect(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	const char *res;
	unsigned timeout;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		ha_alert("parsing [%s:%d] : '%s' expects an integer argument.\n",
			 file, line, args[0]);
		return -1;
	}

	res = parse_time_err(args[1], &timeout, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[1], args[0]);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' (minimum non-null value is 1 ms)",
			  args[1], args[0]);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in '%s'", *res, args[0]);
		return -1;
	}

	if (*args[2] != 0) {
		memprintf(err, "'%s' : unexpected extra argument '%s' after value '%s'.", args[0], args[2], args[1]);
		return -1;
	}

	httpclient_timeout_connect = MS_TO_TICKS(timeout);

	return 0;
}


static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "httpclient.resolvers.disabled", httpclient_parse_global_resolvers_disabled },
	{ CFG_GLOBAL, "httpclient.resolvers.id", httpclient_parse_global_resolvers },
	{ CFG_GLOBAL, "httpclient.resolvers.prefer", httpclient_parse_global_prefer },
	{ CFG_GLOBAL, "httpclient.retries", httpclient_parse_global_retries },
	{ CFG_GLOBAL, "httpclient.timeout.connect", httpclient_parse_global_timeout_connect },
#ifdef USE_OPENSSL
	{ CFG_GLOBAL, "httpclient.ssl.verify", httpclient_parse_global_verify },
	{ CFG_GLOBAL, "httpclient.ssl.ca-file", httpclient_parse_global_ca_file },
#endif
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
