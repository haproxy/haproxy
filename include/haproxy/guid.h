#ifndef _HAPROXY_GUID_H
#define _HAPROXY_GUID_H

#include <haproxy/api-t.h>
#include <haproxy/guid-t.h>
#include <haproxy/thread-t.h>

__decl_thread(extern HA_RWLOCK_T guid_lock);

void guid_init(struct guid_node *node);
int guid_insert(enum obj_type *obj_type, const char *uid, char **errmsg);
void guid_remove(struct guid_node *guid);
struct guid_node *guid_lookup(const char *uid);

int guid_is_valid_fmt(const char *uid, char **errmsg);
char *guid_name(const struct guid_node *guid);

#endif /* _HAPROXY_GUID_H */
