#define _GNU_SOURCE

#include <common/namespace.h>
#include <common/compiler.h>
#include <common/hash.h>
#include <common/errors.h>
#include <proto/log.h>
#include <types/global.h>

#include <sched.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>

#include <string.h>
#ifdef CONFIG_HAP_NS

/* Opens the namespace <ns_name> and returns the FD or -1 in case of error
 * (check errno).
 */
static int open_named_namespace(const char *ns_name)
{
	if (chunk_printf(&trash, "/var/run/netns/%s", ns_name) < 0)
		return -1;
	return open(trash.str, O_RDONLY);
}

static int default_namespace = -1;

static int init_default_namespace()
{
	if (chunk_printf(&trash, "/proc/%d/ns/net", getpid()) < 0)
		return -1;
	default_namespace = open(trash.str, O_RDONLY);
	return default_namespace;
}

static struct eb_root namespace_tree_root = EB_ROOT;

int netns_init(void)
{
	int err_code = 0;

	/* if no namespaces have been defined in the config then
	 * there is no point in trying to initialize anything:
	 * my_socketat() will never be called with a valid namespace
	 * structure and thus switching back to the default namespace
	 * is not needed either */
	if (!eb_is_empty(&namespace_tree_root)) {
		if (init_default_namespace() < 0) {
			Alert("Failed to open the default namespace.\n");
			err_code |= ERR_ALERT | ERR_FATAL;
		}
	}

	return err_code;
}

struct netns_entry* netns_store_insert(const char *ns_name)
{
	struct netns_entry *entry = NULL;
	int fd = open_named_namespace(ns_name);
	if (fd == -1)
		goto out;

	entry = (struct netns_entry *)calloc(1, sizeof(struct netns_entry));
	if (!entry)
		goto out;
	entry->fd = fd;
	entry->node.key = strdup(ns_name);
	entry->name_len = strlen(ns_name);
	ebis_insert(&namespace_tree_root, &entry->node);
out:
	return entry;
}

const struct netns_entry* netns_store_lookup(const char *ns_name, size_t ns_name_len)
{
	struct ebpt_node *node;

	node = ebis_lookup_len(&namespace_tree_root, ns_name, ns_name_len);
	if (node)
		return ebpt_entry(node, struct netns_entry, node);
	else
		return NULL;
}
#endif

/* Opens a socket in the namespace described by <ns> with the parameters <domain>,
 * <type> and <protocol> and returns the FD or -1 in case of error (check errno).
 */
int my_socketat(const struct netns_entry *ns, int domain, int type, int protocol)
{
	int sock;

#ifdef CONFIG_HAP_NS
	if (default_namespace < 0 ||
	    (ns && setns(ns->fd, CLONE_NEWNET) == -1))
		return -1;
#endif
	sock = socket(domain, type, protocol);

#ifdef CONFIG_HAP_NS
	if (ns && setns(default_namespace, CLONE_NEWNET) == -1) {
		close(sock);
		return -1;
	}
#endif

	return sock;
}
