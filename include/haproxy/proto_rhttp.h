#ifndef _HAPROXY_PROTO_RHTTP_H
#define _HAPROXY_PROTO_RHTTP_H

#include <haproxy/connection-t.h>
#include <haproxy/listener-t.h>
#include <haproxy/receiver-t.h>

int rhttp_bind_receiver(struct receiver *rx, char **errmsg);

int rhttp_bind_listener(struct listener *listener, char *errmsg, int errlen);
void rhttp_enable_listener(struct listener *l);
void rhttp_disable_listener(struct listener *l);
int rhttp_suspend_listener(struct listener *l);
struct connection *rhttp_accept_conn(struct listener *l, int *status);
void rhttp_unbind_receiver(struct listener *l);
int rhttp_bind_tid_prep(struct connection *conn, int new_tid);

int rhttp_accepting_conn(const struct receiver *rx);

void rhttp_notify_preconn_err(struct listener *l);

#endif /* _HAPROXY_PROTO_RHTTP_H */
