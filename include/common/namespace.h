#ifndef _NAMESPACE_H
#define _NAMESPACE_H

#include <stdlib.h>
#include <ebistree.h>

#ifdef USE_NS

struct netns_entry
{
	struct ebpt_node node;
	size_t name_len;
	int fd;
};

int my_socketat(const struct netns_entry *ns, int domain, int type, int protocol);
struct netns_entry* netns_store_insert(const char *ns_name);
const struct netns_entry* netns_store_lookup(const char *ns_name, size_t ns_name_len);

int netns_init(void);

#else /* no namespace support */

struct netns_entry;

static inline int my_socketat(const struct netns_entry *ns, int domain, int type, int protocol)
{
	return socket(domain, type, protocol);
}

#endif /* USE_NS */

#endif /* _NAMESPACE_H */
