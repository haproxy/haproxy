#include <string.h>

#include <proto/dict.h>

#include <eb32tree.h>
#include <ebistree.h>

struct dict *new_dict(const char *name)
{
	struct dict *dict;

	dict = malloc(sizeof *dict);
	if (!dict)
		return NULL;

	dict->name     = name;
	dict->values   = EB_ROOT_UNIQUE;
	HA_RWLOCK_INIT(&dict->rwlock);

	return dict;
}

/*
 * Allocate a new dictionary entry with <s> as string value which is strdup()'ed.
 * Returns the new allocated entry if succeeded, NULL if not.
 */
static struct dict_entry *new_dict_entry(char *s)
{
	struct dict_entry *de;

	de = calloc(1, sizeof *de);
	if (!de)
		return NULL;

	de->value.key = strdup(s);
	if (!de->value.key)
		goto err;

	de->refcount = 1;

	return de;

 err:
	free(de->value.key);
	de->value.key = NULL;
	free(de);
	return NULL;
}

/*
 * Release the memory allocated for <de> dictionary entry.
 */
static void free_dict_entry(struct dict_entry *de)
{
	de->refcount = 0;
	free(de->value.key);
	de->value.key = NULL;
	free(de);
}

/*
 * Simple function to lookup dictionary entries with <s> as value.
 */
static struct dict_entry *__dict_lookup(struct dict *d, const char *s)
{
	struct dict_entry *de;
	struct ebpt_node *node;

	de = NULL;
	node = ebis_lookup(&d->values, s);
	if (node)
		de = container_of(node, struct dict_entry, value);

	return de;
}

/*
 * Insert <node> node in <root> ebtree, deleting any already existing node with
 * the same value.
 */
static struct ebpt_node *__dict_insert(struct eb_root *root, struct ebpt_node *node)
{
	struct ebpt_node *n;

	n = ebis_insert(root, node);
	if (n != node) {
		ebpt_delete(n);
		free_dict_entry(container_of(n, struct dict_entry, value));
		ebis_insert(root, node);
	}

	return node;
}

/*
 * Insert an entry in <d> dictionary with <s> as value. *
 */
struct dict_entry *dict_insert(struct dict *d, char *s)
{
	struct dict_entry *de;

	HA_RWLOCK_RDLOCK(DICT_LOCK, &d->rwlock);
	de = __dict_lookup(d, s);
	HA_RWLOCK_RDUNLOCK(DICT_LOCK, &d->rwlock);
	if (de)
		return de;

	de = new_dict_entry(s);
	if (!de)
		return NULL;

	HA_RWLOCK_WRLOCK(DICT_LOCK, &d->rwlock);
	__dict_insert(&d->values, &de->value);
	HA_RWLOCK_WRUNLOCK(DICT_LOCK, &d->rwlock);

	return de;
}

