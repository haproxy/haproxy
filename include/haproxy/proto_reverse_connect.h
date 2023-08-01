#ifndef _HAPROXY_PROTO_REVERSE_CONNECT_H
#define _HAPROXY_PROTO_REVERSE_CONNECT_H

#include <haproxy/listener-t.h>
#include <haproxy/receiver-t.h>

int rev_bind_receiver(struct receiver *rx, char **errmsg);

int rev_bind_listener(struct listener *listener, char *errmsg, int errlen);

int rev_accepting_conn(const struct receiver *rx);

#endif /* _HAPROXY_PROTO_REVERSE_CONNECT_H */
