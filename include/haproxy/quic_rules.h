#ifndef _HAPROXY_QUIC_RULES_H
#define _HAPROXY_QUIC_RULES_H

#include <haproxy/action-t.h>
#include <haproxy/quic_sock-t.h>

struct listener;
struct quic_dgram;

extern struct action_kw_list quic_init_actions_list;

int quic_init_exec_rules(struct listener *li, struct quic_dgram *dgram);

struct action_kw *action_quic_init_custom(const char *kw);

#endif /* _HAPROXY_QUIC_RULES_H */
