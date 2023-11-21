#ifndef _HAPROXY_PROTO_RHTTP_H
#define _HAPROXY_PROTO_RHTTP_H

#include <haproxy/connection-t.h>
#include <haproxy/listener-t.h>
#include <haproxy/receiver-t.h>

int rev_bind_receiver(struct receiver *rx, char **errmsg);

int rev_bind_listener(struct listener *listener, char *errmsg, int errlen);
void rev_enable_listener(struct listener *l);
void rev_disable_listener(struct listener *l);
struct connection *rev_accept_conn(struct listener *l, int *status);
void rev_unbind_receiver(struct listener *l);
int rev_set_affinity(struct connection *conn, int new_tid);

int rev_accepting_conn(const struct receiver *rx);

void rev_notify_preconn_err(struct listener *l);

#endif /* _HAPROXY_PROTO_RHTTP_H */
