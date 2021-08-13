#ifndef _HAPROXY_HTTPCLIENT_H
#define _HAPROXY_HTTPCLIENT_H

void httpclient_destroy(struct httpclient *hc);
struct httpclient *httpclient_new(void *caller, enum http_meth_t meth, struct ist url);

struct appctx *httpclient_start(struct httpclient *hc);
int httpclient_res_xfer(struct httpclient *hc, struct buffer *dst);
int httpclient_req_gen(struct httpclient *hc, const struct ist url, enum http_meth_t meth, const struct http_hdr *hdrs);

#endif /* ! _HAPROXY_HTTCLIENT_H */
