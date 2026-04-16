#ifndef _HAPROXY_HLDSTREAM_H
#define _HAPROXY_HLDSTREAM_H

#include <haproxy/hldstream-t.h>

struct task *hld_io_cb(struct task *t, void *context, unsigned int state);

#endif /* _HAPROXY_HLDSTREAM_H */
