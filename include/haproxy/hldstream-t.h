#ifndef _HAPROXY_HDLSTREAM_T_H
#define _HAPROXY_HDLSTREAM_T_H

#include <haproxy/buf-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/dynbuf-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/session-t.h>
#include <haproxy/stconn-t.h>
#include <haproxy/task-t.h>

struct hldstream {
	enum obj_type obj_type;
	struct connection *conn;
	int64_t hash;
	struct hld_usr *usr;
	struct hld_url *url;
	const char *path;
	struct stconn *sc;
	struct buffer bi, bo;
	struct buffer_wait buf_wait; /* wait list for buffer allocation */
	struct task *task;
	int flags;
	int state;
	unsigned long long to_send; /* number of body data bytes to send */
	struct timeval req_date;
	struct list list;
};

#endif /* _HAPROXY_HDLSTREAM_T_H */
