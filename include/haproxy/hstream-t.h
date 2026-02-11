#ifndef _HAPROXY_HSTREAM_T_H
#define _HAPROXY_HSTREAM_T_H

#include <haproxy/dynbuf-t.h>
#include <haproxy/http-t.h>
#include <haproxy/obj_type-t.h>

/* hastream stream */
struct hstream {
	enum obj_type obj_type;
	struct session *sess;

	struct stconn *sc;
	struct task *task;

	struct buffer req;
	struct buffer res;
	unsigned long long to_write; /* #of response data bytes to write after headers */
	struct buffer_wait buf_wait; /* Wait list for buffer allocation */

	int flags;

	int ka;                      /* .0: keep-alive  .1: forced  .2: http/1.1, .3: was_reused */
	int req_cache;
	unsigned long long req_size; /* values passed in the URI to override the server's */
	unsigned long long req_body; /* remaining body to be consumed from the request */
	int req_code;
	int res_wait;                /* time to wait before replying in ms */
	int res_time;
	int req_chunked;
	int req_random;
	int req_after_res;           /* Drain the request body after having sent the response */
	enum http_meth_t req_meth;
};

#endif /* _HAPROXY_HSTREAM_T_H */
