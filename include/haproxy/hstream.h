#ifndef _HAPROXY_HSTREAM_H
#define  _HAPROXY_HSTREAM_H

#include <haproxy/cfgparse.h>
#include <haproxy/hstream-t.h>

struct task *sc_hstream_io_cb(struct task *t, void *ctx, unsigned int state);
int hstream_wake(struct stconn *sc);
void hstream_shutdown(struct stconn *sc);
void *hstream_new(struct session *sess, struct stconn *sc, struct buffer *input);

#endif /* _HAPROXY_HSTREAM_H */
