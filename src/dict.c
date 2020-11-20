#include <string.h>

#include <import/eb32tree.h>
#include <import/ebistree.h>
#include <haproxy/dict.h>
#include <haproxy/thread.h>

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

	de->len = strlen(s);
	de->refcount = 1;

	return de;

 err:
	free(de->value.key);
	de->value.key = NULL;
	de->len = 0;
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
 * Insert an entry in <d> dictionary with <s> as value. *
 */
struct dict_entry *dict_insert(struct dict *d, char *s)
{
	struct dict_entry *de;
	struct ebpt_node *n;

	HA_RWLOCK_RDLOCK(DICT_LOCK, &d->rwlock);
	de = __dict_lookup(d, s);
	HA_RWLOCK_RDUNLOCK(DICT_LOCK, &d->rwlock);
	if (de) {
		HA_ATOMIC_ADD(&de->refcount, 1);
		return de;
	}

	de = new_dict_entry(s);
	if (!de)
		return NULL;

	HA_RWLOCK_WRLOCK(DICT_LOCK, &d->rwlock);
	n = ebis_insert(&d->values, &de->value);
	HA_RWLOCK_WRUNLOCK(DICT_LOCK, &d->rwlock);
	if (n != &de->value) {
		free_dict_entry(de);
		de = container_of(n, struct dict_entry, value);
	}

	return de;
}


/*
 * Unreference a dict entry previously acquired with <dict_insert>.
 * If this is the last live reference to the entry, it is
 * removed from the dictionary.
 */
void dict_entry_unref(struct dict *d, struct dict_entry *de)
{
	if (!de)
		return;

	if (HA_ATOMIC_SUB(&de->refcount, 1) != 0)
		return;

	HA_RWLOCK_WRLOCK(DICT_LOCK, &d->rwlock);
	ebpt_delete(&de->value);
	HA_RWLOCK_WRUNLOCK(DICT_LOCK, &d->rwlock);

	free_dict_entry(de);
}
