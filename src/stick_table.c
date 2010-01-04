/*
 * Stick tables management functions.
 *
 * Copyright 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <string.h>

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>

#include <ebmbtree.h>
#include <ebsttree.h>

#include <types/stick_table.h>

#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/task.h>


/*
 * Free an allocate sticked session <ts>.
 * Decrease table <t> sticked session counter .
 */
void stksess_free(struct stktable *t, struct stksess *ts)
{
	t->current--;
	pool_free2(t->pool,ts);
}

/*
 * Init or modify <key> of th sticked session <ts> present in table <t>.
 */
void stksess_key(struct stktable *t, struct stksess *ts, struct stktable_key *key)
{
	if (t->type != STKTABLE_TYPE_STRING)
		memcpy(ts->keys.key, key->key , t->key_size);
	else {
		memcpy(ts->keys.key, key->key, MIN(t->key_size - 1, key->key_len));
		ts->keys.key[MIN(t->key_size - 1, key->key_len)] = 0;
	}
}


/*
 * Init sticked session <ts> using <key>.
 */
struct stksess *stksess_init(struct stktable *t, struct stksess * ts, struct stktable_key *key)
{
	ts->keys.node.leaf_p = NULL;
	ts->exps.node.leaf_p = NULL;
	ts->sid = 0;
	stksess_key(t, ts, key);

	return ts;
}

/*
 * Trash oldest <to_batch> sticked sessions from table <t>
 * Returns number of trashed sticked session.
 */
static int stktable_trash_oldest(struct stktable *t, int to_batch)
{
	struct stksess *ts;
	struct eb32_node *eb;
	int batched = 0;

	eb = eb32_lookup_ge(&t->exps, now_ms - TIMER_LOOK_BACK);

	while (batched < to_batch) {

		if (unlikely(!eb)) {
			/* we might have reached the end of the tree, typically because
			 * <now_ms> is in the first half and we're first scanning the last
			 * half. Let's loop back to the beginning of the tree now.
			 */
			eb = eb32_first(&t->exps);
			if (likely(!eb))
				break;
		}

		/* timer looks expired, detach it from the queue */
		ts = eb32_entry(eb, struct stksess, exps);
		eb = eb32_next(eb);

		eb32_delete(&ts->exps);

		if (ts->expire != ts->exps.key) {

			if (!tick_isset(ts->expire))
				continue;

			ts->exps.key = ts->expire;

			eb32_insert(&t->exps, &ts->exps);

			if (!eb || eb->key > ts->exps.key)
				eb = &ts->exps;

			continue;
		}
		/* session expired, trash it */

		ebmb_delete(&ts->keys);
		stksess_free(t, ts);
		batched++;
	}

	return batched;
}

/*
 *  Allocate and initialise a new sticked session.
 *  The new sticked session is returned or NULL in case of lack of memory.
 *  Sticked sessions should only be allocated this way, and must be
 *  freed using stksess_free().
 *  Increase table <t> sticked session counter.
 */
struct stksess *stksess_new(struct stktable *t, struct stktable_key *key)
{
	struct stksess *ts;

	if (unlikely(t->current == t->size)) {
		if ( t->nopurge )
			return NULL;

		if (!stktable_trash_oldest(t, t->size >> 8))
			return NULL;
	}

	ts = pool_alloc2(t->pool);
	if (ts) {
		t->current++;
		stksess_init(t, ts, key);
	}

	return ts;
}

/*
 * Lookup in table <t> for a sticked session identified by <key>.
 * Returns pointer on requested sticked session or NULL if no one found.
 */
struct stksess *stktable_lookup(struct stktable *t, struct stktable_key *key)
{
	struct ebmb_node *eb;

	/* lookup on track session */
	if (t->type == STKTABLE_TYPE_STRING)
		eb = ebst_lookup_len(&t->keys, key->key, key->key_len);
	else
		eb = ebmb_lookup(&t->keys, key->key, t->key_size);

	if (unlikely(!eb)) {
		/* no session found */
		return NULL;
	}

	/* Existing session, returns server id */
	return ebmb_entry(eb, struct stksess, keys);
}

/*
 * Store sticked session if not present in table.
 * Il already present, update the existing session.
 */
int stktable_store(struct stktable *t, struct stksess *tsess, int sid)
{
	struct stksess *ts;
	struct ebmb_node *eb;

	if (t->type == STKTABLE_TYPE_STRING)
		eb = ebst_lookup(&(t->keys), (char *)tsess->keys.key);
	else
		eb = ebmb_lookup(&(t->keys), tsess->keys.key, t->key_size);

	if (unlikely(!eb)) {
		tsess->sid = sid;
		ebmb_insert(&t->keys, &tsess->keys, t->key_size);

		tsess->exps.key = tsess->expire = tick_add(now_ms, MS_TO_TICKS(t->expire));
		eb32_insert(&t->exps, &tsess->exps);

		if (t->expire) {
			t->exp_task->expire = t->exp_next = tick_first(tsess->expire, t->exp_next);
			task_queue(t->exp_task);
		}
		return 0;
	}

	/* Existing track session */
	ts = ebmb_entry(eb, struct stksess, keys);

	if ( ts->sid != sid )
		ts->sid = sid;
	return 1;
}

/*
 * Trash expired sticked sessions from table <t>.
 */
static int stktable_trash_expired(struct stktable *t)
{
	struct stksess *ts;
	struct eb32_node *eb;

	eb = eb32_lookup_ge(&t->exps, now_ms - TIMER_LOOK_BACK);

	while (1) {
		if (unlikely(!eb)) {
			/* we might have reached the end of the tree, typically because
			 * <now_ms> is in the first half and we're first scanning the last
			 * half. Let's loop back to the beginning of the tree now.
			 */
			eb = eb32_first(&t->exps);
			if (likely(!eb))
				break;
		}

		if (likely(tick_is_lt(now_ms, eb->key))) {
			/* timer not expired yet, revisit it later */
			t->exp_next = eb->key;
			return t->exp_next;
		}

		/* timer looks expired, detach it from the queue */
		ts = eb32_entry(eb, struct stksess, exps);
		eb = eb32_next(eb);

		eb32_delete(&ts->exps);

		if (!tick_is_expired(ts->expire, now_ms)) {
			if (!tick_isset(ts->expire))
				continue;

			ts->exps.key = ts->expire;
			eb32_insert(&t->exps, &ts->exps);

			if (!eb || eb->key > ts->exps.key)
				eb = &ts->exps;
			continue;
		}

		/* session expired, trash it */
		ebmb_delete(&ts->keys);
		stksess_free(t, ts);
	}

	/* We have found no task to expire in any tree */
	t->exp_next = TICK_ETERNITY;
	return t->exp_next;
}

/*
 * Task processing function to trash expired sticked sessions.
 */
static struct task *process_table_expire(struct task * task)
{
	struct stktable *t = (struct stktable *)task->context;

	task->expire = stktable_trash_expired(t);
	return task;
}

/* Perform minimal intializations, report 0 in case of error, 1 if OK. */
int stktable_init(struct stktable *t)
{
	if (t->size) {
		memset(&t->keys, 0, sizeof(t->keys));
		memset(&t->exps, 0, sizeof(t->exps));

		t->pool = create_pool("sticktables", sizeof(struct stksess) + t->key_size, MEM_F_SHARED);

		t->exp_next = TICK_ETERNITY;
		if ( t->expire ) {
			t->exp_task = task_new();
			t->exp_task->process = process_table_expire;
			t->exp_task->expire = TICK_ETERNITY;
			t->exp_task->context = (void *)t;
		}
		return t->pool != NULL;
	}
	return 1;
}

/*
 * Configuration keywords of known table types
 */
struct stktable_type stktable_types[STKTABLE_TYPES] = { { "ip", 0, 4 } ,
						        { "integer", 0, 4 },
						        { "string", STKTABLE_TYPEFLAG_CUSTOMKEYSIZE, 32 } };


/*
 * Parse table type configuration.
 * Returns 0 on successful parsing, else 1.
 * <myidx> is set at next configuration <args> index.
 */
int stktable_parse_type(char **args, int *myidx, unsigned long *type, size_t *key_size)
{
	for (*type = 0; *type < STKTABLE_TYPES; (*type)++) {
		if (strcmp(args[*myidx], stktable_types[*type].kw) != 0)
			continue;

		*key_size =  stktable_types[*type].default_size;
		(*myidx)++;

		if (stktable_types[*type].flags & STKTABLE_TYPEFLAG_CUSTOMKEYSIZE) {
			if (strcmp("len", args[*myidx]) == 0) {
				(*myidx)++;
				*key_size = atol(args[*myidx]);
				if ( !*key_size )
					break;
				/* null terminated string needs +1 for '\0'. */
				(*key_size)++;
				(*myidx)++;
			}
		}
		return 0;
	}
	return 1;
}


