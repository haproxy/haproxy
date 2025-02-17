#ifndef _HAPROXY_GUID_T_H
#define _HAPROXY_GUID_T_H

#include <import/cebtree.h>
#include <haproxy/obj_type-t.h>

/* Maximum GUID size excluding final '\0' */
#define GUID_MAX_LEN 127

struct guid_node {
	struct ceb_node node;    /* attach point into GUID global tree */
	char *key;               /* the key itself */
	enum obj_type *obj_type; /* pointer to GUID obj owner */
};

#endif /* _HAPROXY_GUID_T_H */
