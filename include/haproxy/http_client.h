#ifndef _HAPROXY_HTTPCLIENT_H
#define _HAPROXY_HTTPCLIENT_H

#include <haproxy/http_client-t.h>

void httpclient_destroy(struct httpclient *hc);
void httpclient_stop_and_destroy(struct httpclient *hc);
struct httpclient *httpclient_new(void *caller, enum http_meth_t meth, struct ist url);

struct appctx *httpclient_start(struct httpclient *hc);
int httpclient_res_xfer(struct httpclient *hc, struct buffer *dst);
int httpclient_req_gen(struct httpclient *hc, const struct ist url, enum http_meth_t meth, const struct http_hdr *hdrs, const struct ist payload);
int httpclient_req_xfer(struct httpclient *hc, struct ist src, int end);

/* Return the amount of data available in the httpclient response buffer */
static inline int httpclient_data(struct httpclient *hc)
{
	return b_data(&hc->res.buf);
}

/* Return 1 if the httpclient ended and won't receive any new data */
static inline int httpclient_ended(struct httpclient *hc)
{
	return !!(hc->flags & HTTPCLIENT_FS_ENDED);
}

/* Return 1 if the httpclient started */
static inline int httpclient_started(struct httpclient *hc)
{

	return !!(hc->flags & HTTPCLIENT_FS_STARTED);
}

#endif /* ! _HAPROXY_HTTCLIENT_H */
