#ifndef _HAPROXY_GUID_T_H
#define _HAPROXY_GUID_T_H

#include <import/ebtree-t.h>
#include <haproxy/obj_type-t.h>

/* Maximum GUID size excluding final '\0' */
#define GUID_MAX_LEN 127

struct guid_node {
	struct ebpt_node node;   /* attach point into GUID global tree */
	enum obj_type *obj_type; /* pointer to GUID obj owner */
};

#endif /* _HAPROXY_GUID_T_H */
