#ifndef _HAPROXY_HTTPCLIENT_T_H
#define _HAPROXY_HTTPCLIENT_T_H

#include <haproxy/http-t.h>

struct httpclient {
	struct {
		struct ist url;                /* URL of the request */
		enum http_meth_t meth;       /* method of the request */
		struct buffer buf;             /* output buffer, HTX */
	} req;
	struct {
		struct ist vsn;
		uint16_t status;
		struct ist reason;
		struct http_hdr *hdrs;         /* headers */
		struct buffer buf;             /* input buffer, raw HTTP */
	} res;
	struct {
               /* callbacks used to send the request, */
		void (*req_payload)(struct httpclient *hc);          /* send a payload */

		/* callbacks used to receive the response, if not set, the IO
		 * handler will consume the data without doing anything */
		void (*res_stline)(struct httpclient *hc);          /* start line received */
		void (*res_headers)(struct httpclient *hc);         /* headers received */
		void (*res_payload)(struct httpclient *hc);         /* payload received */
		void (*res_end)(struct httpclient *hc);             /* end of the response */
	} ops;
	struct sockaddr_storage dst;          /* destination address */
	struct appctx *appctx;                /* HTTPclient appctx */
	void *caller;                         /* ptr of the caller */
	unsigned int flags;                   /* other flags */
};

/* Action (FA) to do */
#define    HTTPCLIENT_FA_STOP         0x00000001   /* stops the httpclient at the next IO handler call */
#define    HTTPCLIENT_FA_AUTOKILL     0x00000002   /* sets the applet to destroy the httpclient struct itself */

/* status (FS) */
#define    HTTPCLIENT_FS_STARTED      0x00010000 /* the httpclient was started */
#define    HTTPCLIENT_FS_ENDED        0x00020000 /* the httpclient is stopped */

/* States of the HTTP Client Appctx */
enum {
	HTTPCLIENT_S_REQ = 0,
	HTTPCLIENT_S_REQ_BODY,
	HTTPCLIENT_S_RES_STLINE,
	HTTPCLIENT_S_RES_HDR,
	HTTPCLIENT_S_RES_BODY,
	HTTPCLIENT_S_RES_END,
};

#define HTTPCLIENT_USERAGENT "HAProxy"

#endif /* ! _HAPROXY_HTTCLIENT__T_H */
