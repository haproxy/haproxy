#ifndef _HAPROXY_QUIC_RULES_H
#define _HAPROXY_QUIC_RULES_H

#include <sys/socket.h>

#include <haproxy/action-t.h>

struct listener;

extern struct action_kw_list quic_init_actions_list;

int quic_init_exec_rules(struct listener *li,
                         struct sockaddr_storage *saddr,
                         struct sockaddr_storage *daddr);

struct action_kw *action_quic_init_custom(const char *kw);

#endif /* _HAPROXY_QUIC_RULES_H */
