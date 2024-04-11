#ifndef _HAPROXY_GUID_H
#define _HAPROXY_GUID_H

#include <haproxy/guid-t.h>

extern struct eb_root guid_tree;

void guid_init(struct guid_node *node);
int guid_insert(enum obj_type *obj_type, const char *uid, char **errmsg);
void guid_remove(struct guid_node *guid);
struct guid_node *guid_lookup(const char *uid);

int guid_is_valid_fmt(const char *uid, char **errmsg);
char *guid_name(const struct guid_node *guid);

#endif /* _HAPROXY_GUID_H */
