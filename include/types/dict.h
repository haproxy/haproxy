#ifndef _TYPES_DICT_H
#define _TYPES_DICT_H

#include <common/hathreads.h>
#include <ebpttree.h>

struct dict_entry {
	struct ebpt_node value;
	unsigned int refcount;
	size_t len;
};

struct dict {
	const char *name;
	struct eb_root values;
	__decl_hathreads(HA_RWLOCK_T rwlock);
};

#endif /* _TYPES_DICT_H */
