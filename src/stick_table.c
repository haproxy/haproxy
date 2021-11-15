/*
 * Stick tables management functions.
 *
 * Copyright 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <string.h>
#include <errno.h>

#include <import/ebmbtree.h>
#include <import/ebsttree.h>
#include <import/ebistree.h>

#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli.h>
#include <haproxy/dict.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/http_rules.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/net_helper.h>
#include <haproxy/peers.h>
#include <haproxy/pool.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/stats-t.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>


/* structure used to return a table key built from a sample */
static THREAD_LOCAL struct stktable_key static_table_key;
static int (*smp_fetch_src)(const struct arg *, struct sample *, const char *, void *);

struct stktable *stktables_list;
struct eb_root stktable_by_name = EB_ROOT;

#define round_ptr_size(i) (((i) + (sizeof(void *) - 1)) &~ (sizeof(void *) - 1))

/* This function inserts stktable <t> into the tree of known stick-table.
 * The stick-table ID is used as the storing key so it must already have
 * been initialized.
 */
void stktable_store_name(struct stktable *t)
{
	t->name.key = t->id;
	ebis_insert(&stktable_by_name, &t->name);
}

struct stktable *stktable_find_by_name(const char *name)
{
	struct ebpt_node *node;
	struct stktable *t;

	node = ebis_lookup(&stktable_by_name, name);
	if (node) {
		t = container_of(node, struct stktable, name);
		if (strcmp(t->id, name) == 0)
			return t;
	}

	return NULL;
}

/*
 * Free an allocated sticky session <ts>, and decrease sticky sessions counter
 * in table <t>.
 */
void __stksess_free(struct stktable *t, struct stksess *ts)
{
	t->current--;
	pool_free(t->pool, (void *)ts - round_ptr_size(t->data_size));
}

/*
 * Free an allocated sticky session <ts>, and decrease sticky sessions counter
 * in table <t>.
 * This function locks the table
 */
void stksess_free(struct stktable *t, struct stksess *ts)
{
	void *data;
	data = stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_KEY);
	if (data) {
		dict_entry_unref(&server_key_dict, stktable_data_cast(data, std_t_dict));
		stktable_data_cast(data, std_t_dict) = NULL;
	}
	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	__stksess_free(t, ts);
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);
}

/*
 * Kill an stksess (only if its ref_cnt is zero).
 */
int __stksess_kill(struct stktable *t, struct stksess *ts)
{
	if (ts->ref_cnt)
		return 0;

	eb32_delete(&ts->exp);
	eb32_delete(&ts->upd);
	ebmb_delete(&ts->key);
	__stksess_free(t, ts);
	return 1;
}

/*
 * Decrease the refcount if decrefcnt is not 0.
 * and try to kill the stksess
 * This function locks the table
 */
int stksess_kill(struct stktable *t, struct stksess *ts, int decrefcnt)
{
	int ret;

	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	if (decrefcnt)
		ts->ref_cnt--;
	ret = __stksess_kill(t, ts);
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);

	return ret;
}

/*
 * Initialize or update the key in the sticky session <ts> present in table <t>
 * from the value present in <key>.
 */
void stksess_setkey(struct stktable *t, struct stksess *ts, struct stktable_key *key)
{
	if (t->type != SMP_T_STR)
		memcpy(ts->key.key, key->key, t->key_size);
	else {
		memcpy(ts->key.key, key->key, MIN(t->key_size - 1, key->key_len));
		ts->key.key[MIN(t->key_size - 1, key->key_len)] = 0;
	}
}


/*
 * Init sticky session <ts> of table <t>. The data parts are cleared and <ts>
 * is returned.
 */
static struct stksess *__stksess_init(struct stktable *t, struct stksess * ts)
{
	memset((void *)ts - t->data_size, 0, t->data_size);
	ts->ref_cnt = 0;
	ts->key.node.leaf_p = NULL;
	ts->exp.node.leaf_p = NULL;
	ts->upd.node.leaf_p = NULL;
	ts->expire = tick_add(now_ms, MS_TO_TICKS(t->expire));
	HA_RWLOCK_INIT(&ts->lock);
	return ts;
}

/*
 * Trash oldest <to_batch> sticky sessions from table <t>
 * Returns number of trashed sticky sessions. It may actually trash less
 * than expected if finding these requires too long a search time (e.g.
 * most of them have ts->ref_cnt>0).
 */
int __stktable_trash_oldest(struct stktable *t, int to_batch)
{
	struct stksess *ts;
	struct eb32_node *eb;
	int max_search = to_batch * 2; // no more than 50% misses
	int batched = 0;
	int looped = 0;

	eb = eb32_lookup_ge(&t->exps, now_ms - TIMER_LOOK_BACK);

	while (batched < to_batch) {

		if (unlikely(!eb)) {
			/* we might have reached the end of the tree, typically because
			 * <now_ms> is in the first half and we're first scanning the last
			 * half. Let's loop back to the beginning of the tree now if we
			 * have not yet visited it.
			 */
			if (looped)
				break;
			looped = 1;
			eb = eb32_first(&t->exps);
			if (likely(!eb))
				break;
		}

		if (--max_search < 0)
			break;

		/* timer looks expired, detach it from the queue */
		ts = eb32_entry(eb, struct stksess, exp);
		eb = eb32_next(eb);

		/* don't delete an entry which is currently referenced */
		if (ts->ref_cnt)
			continue;

		eb32_delete(&ts->exp);

		if (ts->expire != ts->exp.key) {
			if (!tick_isset(ts->expire))
				continue;

			ts->exp.key = ts->expire;
			eb32_insert(&t->exps, &ts->exp);

			if (!eb || eb->key > ts->exp.key)
				eb = &ts->exp;

			continue;
		}

		/* session expired, trash it */
		ebmb_delete(&ts->key);
		eb32_delete(&ts->upd);
		__stksess_free(t, ts);
		batched++;
	}

	return batched;
}

/*
 * Trash oldest <to_batch> sticky sessions from table <t>
 * Returns number of trashed sticky sessions.
 * This function locks the table
 */
int stktable_trash_oldest(struct stktable *t, int to_batch)
{
	int ret;

	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	ret = __stktable_trash_oldest(t, to_batch);
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);

	return ret;
}
/*
 * Allocate and initialise a new sticky session.
 * The new sticky session is returned or NULL in case of lack of memory.
 * Sticky sessions should only be allocated this way, and must be freed using
 * stksess_free(). Table <t>'s sticky session counter is increased. If <key>
 * is not NULL, it is assigned to the new session.
 */
struct stksess *__stksess_new(struct stktable *t, struct stktable_key *key)
{
	struct stksess *ts;

	if (unlikely(t->current == t->size)) {
		if ( t->nopurge )
			return NULL;

		if (!__stktable_trash_oldest(t, (t->size >> 8) + 1))
			return NULL;
	}

	ts = pool_alloc(t->pool);
	if (ts) {
		t->current++;
		ts = (void *)ts + round_ptr_size(t->data_size);
		__stksess_init(t, ts);
		if (key)
			stksess_setkey(t, ts, key);
	}

	return ts;
}
/*
 * Allocate and initialise a new sticky session.
 * The new sticky session is returned or NULL in case of lack of memory.
 * Sticky sessions should only be allocated this way, and must be freed using
 * stksess_free(). Table <t>'s sticky session counter is increased. If <key>
 * is not NULL, it is assigned to the new session.
 * This function locks the table
 */
struct stksess *stksess_new(struct stktable *t, struct stktable_key *key)
{
	struct stksess *ts;

	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	ts = __stksess_new(t, key);
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);

	return ts;
}

/*
 * Looks in table <t> for a sticky session matching key <key>.
 * Returns pointer on requested sticky session or NULL if none was found.
 */
struct stksess *__stktable_lookup_key(struct stktable *t, struct stktable_key *key)
{
	struct ebmb_node *eb;

	if (t->type == SMP_T_STR)
		eb = ebst_lookup_len(&t->keys, key->key, key->key_len+1 < t->key_size ? key->key_len : t->key_size-1);
	else
		eb = ebmb_lookup(&t->keys, key->key, t->key_size);

	if (unlikely(!eb)) {
		/* no session found */
		return NULL;
	}

	return ebmb_entry(eb, struct stksess, key);
}

/*
 * Looks in table <t> for a sticky session matching key <key>.
 * Returns pointer on requested sticky session or NULL if none was found.
 * The refcount of the found entry is increased and this function
 * is protected using the table lock
 */
struct stksess *stktable_lookup_key(struct stktable *t, struct stktable_key *key)
{
	struct stksess *ts;

	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	ts = __stktable_lookup_key(t, key);
	if (ts)
		ts->ref_cnt++;
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);

	return ts;
}

/*
 * Looks in table <t> for a sticky session with same key as <ts>.
 * Returns pointer on requested sticky session or NULL if none was found.
 */
struct stksess *__stktable_lookup(struct stktable *t, struct stksess *ts)
{
	struct ebmb_node *eb;

	if (t->type == SMP_T_STR)
		eb = ebst_lookup(&(t->keys), (char *)ts->key.key);
	else
		eb = ebmb_lookup(&(t->keys), ts->key.key, t->key_size);

	if (unlikely(!eb))
		return NULL;

	return ebmb_entry(eb, struct stksess, key);
}

/*
 * Looks in table <t> for a sticky session with same key as <ts>.
 * Returns pointer on requested sticky session or NULL if none was found.
 * The refcount of the found entry is increased and this function
 * is protected using the table lock
 */
struct stksess *stktable_lookup(struct stktable *t, struct stksess *ts)
{
	struct stksess *lts;

	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	lts = __stktable_lookup(t, ts);
	if (lts)
		lts->ref_cnt++;
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);

	return lts;
}

/* Update the expiration timer for <ts> but do not touch its expiration node.
 * The table's expiration timer is updated if set.
 * The node will be also inserted into the update tree if needed, at a position
 * depending if the update is a local or coming from a remote node
 */
void __stktable_touch_with_exp(struct stktable *t, struct stksess *ts, int local, int expire)
{
	struct eb32_node * eb;
	ts->expire = expire;
	if (t->expire) {
		t->exp_task->expire = t->exp_next = tick_first(ts->expire, t->exp_next);
		task_queue(t->exp_task);
	}

	/* If sync is enabled */
	if (t->sync_task) {
		if (local) {
			/* If this entry is not in the tree
			   or not scheduled for at least one peer */
			if (!ts->upd.node.leaf_p
			    || (int)(t->commitupdate - ts->upd.key) >= 0
			    || (int)(ts->upd.key - t->localupdate) >= 0) {
				ts->upd.key = ++t->update;
				t->localupdate = t->update;
				eb32_delete(&ts->upd);
				eb = eb32_insert(&t->updates, &ts->upd);
				if (eb != &ts->upd)  {
					eb32_delete(eb);
					eb32_insert(&t->updates, &ts->upd);
				}
			}
			task_wakeup(t->sync_task, TASK_WOKEN_MSG);
		}
		else {
			/* If this entry is not in the tree */
			if (!ts->upd.node.leaf_p) {
				ts->upd.key= (++t->update)+(2147483648U);
				eb = eb32_insert(&t->updates, &ts->upd);
				if (eb != &ts->upd) {
					eb32_delete(eb);
					eb32_insert(&t->updates, &ts->upd);
				}
			}
		}
	}
}

/* Update the expiration timer for <ts> but do not touch its expiration node.
 * The table's expiration timer is updated using the date of expiration coming from
 * <t> stick-table configuration.
 * The node will be also inserted into the update tree if needed, at a position
 * considering the update is coming from a remote node
 */
void stktable_touch_remote(struct stktable *t, struct stksess *ts, int decrefcnt)
{
	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	__stktable_touch_with_exp(t, ts, 0, ts->expire);
	if (decrefcnt)
		ts->ref_cnt--;
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);
}

/* Update the expiration timer for <ts> but do not touch its expiration node.
 * The table's expiration timer is updated using the date of expiration coming from
 * <t> stick-table configuration.
 * The node will be also inserted into the update tree if needed, at a position
 * considering the update was made locally
 */
void stktable_touch_local(struct stktable *t, struct stksess *ts, int decrefcnt)
{
	int expire = tick_add(now_ms, MS_TO_TICKS(t->expire));

	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	__stktable_touch_with_exp(t, ts, 1, expire);
	if (decrefcnt)
		ts->ref_cnt--;
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);
}
/* Just decrease the ref_cnt of the current session. Does nothing if <ts> is NULL */
static void stktable_release(struct stktable *t, struct stksess *ts)
{
	if (!ts)
		return;
	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	ts->ref_cnt--;
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);
}

/* Insert new sticky session <ts> in the table. It is assumed that it does not
 * yet exist (the caller must check this). The table's timeout is updated if it
 * is set. <ts> is returned.
 */
void __stktable_store(struct stktable *t, struct stksess *ts)
{

	ebmb_insert(&t->keys, &ts->key, t->key_size);
	ts->exp.key = ts->expire;
	eb32_insert(&t->exps, &ts->exp);
	if (t->expire) {
		t->exp_task->expire = t->exp_next = tick_first(ts->expire, t->exp_next);
		task_queue(t->exp_task);
	}
}

/* Returns a valid or initialized stksess for the specified stktable_key in the
 * specified table, or NULL if the key was NULL, or if no entry was found nor
 * could be created. The entry's expiration is updated.
 */
struct stksess *__stktable_get_entry(struct stktable *table, struct stktable_key *key)
{
	struct stksess *ts;

	if (!key)
		return NULL;

	ts = __stktable_lookup_key(table, key);
	if (ts == NULL) {
		/* entry does not exist, initialize a new one */
		ts = __stksess_new(table, key);
		if (!ts)
			return NULL;
		__stktable_store(table, ts);
	}
	return ts;
}
/* Returns a valid or initialized stksess for the specified stktable_key in the
 * specified table, or NULL if the key was NULL, or if no entry was found nor
 * could be created. The entry's expiration is updated.
 * This function locks the table, and the refcount of the entry is increased.
 */
struct stksess *stktable_get_entry(struct stktable *table, struct stktable_key *key)
{
	struct stksess *ts;

	HA_SPIN_LOCK(STK_TABLE_LOCK, &table->lock);
	ts = __stktable_get_entry(table, key);
	if (ts)
		ts->ref_cnt++;
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &table->lock);

	return ts;
}

/* Lookup for an entry with the same key and store the submitted
 * stksess if not found.
 */
struct stksess *__stktable_set_entry(struct stktable *table, struct stksess *nts)
{
	struct stksess *ts;

	ts = __stktable_lookup(table, nts);
	if (ts == NULL) {
		ts = nts;
		__stktable_store(table, ts);
	}
	return ts;
}

/* Lookup for an entry with the same key and store the submitted
 * stksess if not found.
 * This function locks the table, and the refcount of the entry is increased.
 */
struct stksess *stktable_set_entry(struct stktable *table, struct stksess *nts)
{
	struct stksess *ts;

	HA_SPIN_LOCK(STK_TABLE_LOCK, &table->lock);
	ts = __stktable_set_entry(table, nts);
	ts->ref_cnt++;
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &table->lock);

	return ts;
}
/*
 * Trash expired sticky sessions from table <t>. The next expiration date is
 * returned.
 */
static int stktable_trash_expired(struct stktable *t)
{
	struct stksess *ts;
	struct eb32_node *eb;
	int looped = 0;

	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);
	eb = eb32_lookup_ge(&t->exps, now_ms - TIMER_LOOK_BACK);

	while (1) {
		if (unlikely(!eb)) {
			/* we might have reached the end of the tree, typically because
			 * <now_ms> is in the first half and we're first scanning the last
			 * half. Let's loop back to the beginning of the tree now if we
			 * have not yet visited it.
			 */
			if (looped)
				break;
			looped = 1;
			eb = eb32_first(&t->exps);
			if (likely(!eb))
				break;
		}

		if (likely(tick_is_lt(now_ms, eb->key))) {
			/* timer not expired yet, revisit it later */
			t->exp_next = eb->key;
			goto out_unlock;
		}

		/* timer looks expired, detach it from the queue */
		ts = eb32_entry(eb, struct stksess, exp);
		eb = eb32_next(eb);

		/* don't delete an entry which is currently referenced */
		if (ts->ref_cnt)
			continue;

		eb32_delete(&ts->exp);

		if (!tick_is_expired(ts->expire, now_ms)) {
			if (!tick_isset(ts->expire))
				continue;

			ts->exp.key = ts->expire;
			eb32_insert(&t->exps, &ts->exp);

			if (!eb || eb->key > ts->exp.key)
				eb = &ts->exp;
			continue;
		}

		/* session expired, trash it */
		ebmb_delete(&ts->key);
		eb32_delete(&ts->upd);
		__stksess_free(t, ts);
	}

	/* We have found no task to expire in any tree */
	t->exp_next = TICK_ETERNITY;
out_unlock:
	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);
	return t->exp_next;
}

/*
 * Task processing function to trash expired sticky sessions. A pointer to the
 * task itself is returned since it never dies.
 */
struct task *process_table_expire(struct task *task, void *context, unsigned int state)
{
	struct stktable *t = context;

	task->expire = stktable_trash_expired(t);
	return task;
}

/* Perform minimal stick table intializations, report 0 in case of error, 1 if OK. */
int stktable_init(struct stktable *t)
{
	int peers_retval = 0;
	if (t->size) {
		t->keys = EB_ROOT_UNIQUE;
		memset(&t->exps, 0, sizeof(t->exps));
		t->updates = EB_ROOT_UNIQUE;
		HA_SPIN_INIT(&t->lock);

		t->pool = create_pool("sticktables", sizeof(struct stksess) + round_ptr_size(t->data_size) + t->key_size, MEM_F_SHARED);

		t->exp_next = TICK_ETERNITY;
		if ( t->expire ) {
			t->exp_task = task_new_anywhere();
			if (!t->exp_task)
				return 0;
			t->exp_task->process = process_table_expire;
			t->exp_task->context = (void *)t;
		}
		if (t->peers.p && t->peers.p->peers_fe && !(t->peers.p->peers_fe->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
			peers_retval = peers_register_table(t->peers.p, t);
		}

		return (t->pool != NULL) && !peers_retval;
	}
	return 1;
}

/*
 * Configuration keywords of known table types
 */
struct stktable_type stktable_types[SMP_TYPES] = {
	[SMP_T_SINT] = { "integer", 0,                     4 },
	[SMP_T_IPV4] = { "ip",      0,                     4 },
	[SMP_T_IPV6] = { "ipv6",    0,                    16 },
	[SMP_T_STR]  = { "string",  STK_F_CUSTOM_KEYSIZE, 32 },
	[SMP_T_BIN]  = { "binary",  STK_F_CUSTOM_KEYSIZE, 32 }
};

/*
 * Parse table type configuration.
 * Returns 0 on successful parsing, else 1.
 * <myidx> is set at next configuration <args> index.
 */
int stktable_parse_type(char **args, int *myidx, unsigned long *type, size_t *key_size)
{
	for (*type = 0; *type < SMP_TYPES; (*type)++) {
		if (!stktable_types[*type].kw)
			continue;
		if (strcmp(args[*myidx], stktable_types[*type].kw) != 0)
			continue;

		*key_size =  stktable_types[*type].default_size;
		(*myidx)++;

		if (stktable_types[*type].flags & STK_F_CUSTOM_KEYSIZE) {
			if (strcmp("len", args[*myidx]) == 0) {
				(*myidx)++;
				*key_size = atol(args[*myidx]);
				if (!*key_size)
					break;
				if (*type == SMP_T_STR) {
					/* null terminated string needs +1 for '\0'. */
					(*key_size)++;
				}
				(*myidx)++;
			}
		}
		return 0;
	}
	return 1;
}

/* reserve some space for data type <type>, there is 2 optionnals
 * argument at <sa> and <sa2> to configure this data type and
 * they can be NULL if unused for a given type.
 * Returns PE_NONE (0) if OK or an error code among :
 *   - PE_ENUM_OOR if <type> does not exist
 *   - PE_EXIST if <type> is already registered
 *   - PE_ARG_NOT_USE if <sa>/<sa2> was provided but not expected
 *   - PE_ARG_MISSING if <sa>/<sa2> was expected but not provided
 *   - PE_ARG_VALUE_OOR if type is an array and <sa> it out of array size range.
 */
int stktable_alloc_data_type(struct stktable *t, int type, const char *sa, const char *sa2)

{
	if (type >= STKTABLE_DATA_TYPES)
		return PE_ENUM_OOR;

	if (t->data_ofs[type])
		/* already allocated */
		return PE_EXIST;

	t->data_nbelem[type] = 1;
	if (stktable_data_types[type].is_array) {
		/* arrays take their element count on first argument */
		if (!sa)
			return PE_ARG_MISSING;
		t->data_nbelem[type] = atoi(sa);
		if (!t->data_nbelem[type] || (t->data_nbelem[type] > STKTABLE_MAX_DT_ARRAY_SIZE))
			return PE_ARG_VALUE_OOR;
		sa = sa2;
	}

	switch (stktable_data_types[type].arg_type) {
	case ARG_T_NONE:
		if (sa)
			return PE_ARG_NOT_USED;
		break;
	case ARG_T_INT:
		if (!sa)
			return PE_ARG_MISSING;
		t->data_arg[type].i = atoi(sa);
		break;
	case ARG_T_DELAY:
		if (!sa)
			return PE_ARG_MISSING;
		sa = parse_time_err(sa, &t->data_arg[type].u, TIME_UNIT_MS);
		if (sa)
			return PE_ARG_INVC; /* invalid char */
		break;
	}

	t->data_size      += t->data_nbelem[type] * stktable_type_size(stktable_data_types[type].std_type);
	t->data_ofs[type]  = -t->data_size;
	return PE_NONE;
}

/*
 * Parse a line with <linenum> as number in <file> configuration file to configure
 * the stick-table with <t> as address and  <id> as ID.
 * <peers> provides the "peers" section pointer only if this function is called
 * from a "peers" section.
 * <nid> is the stick-table name which is sent over the network. It must be equal
 * to <id> if this stick-table is parsed from a proxy section, and prefixed by <peers>
 * "peers" section name followed by a '/' character if parsed from a "peers" section.
 * This is the responsibility of the caller to check this.
 * Return an error status with ERR_* flags set if required, 0 if no error was encountered.
 */
int parse_stick_table(const char *file, int linenum, char **args,
                      struct stktable *t, char *id, char *nid, struct peers *peers)
{
	int err_code = 0;
	int idx = 1;
	unsigned int val;

	if (!id || !*id) {
		ha_alert("parsing [%s:%d] : %s: ID not provided.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_ABORT;
		goto out;
	}

	/* Store the "peers" section if this function is called from a "peers" section. */
	if (peers) {
		t->peers.p = peers;
		idx++;
	}

	t->id =  id;
	t->nid =  nid;
	t->type = (unsigned int)-1;
	t->conf.file = file;
	t->conf.line = linenum;

	while (*args[idx]) {
		const char *err;

		if (strcmp(args[idx], "size") == 0) {
			idx++;
			if (!*(args[idx])) {
				ha_alert("parsing [%s:%d] : %s: missing argument after '%s'.\n",
					 file, linenum, args[0], args[idx-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if ((err = parse_size_err(args[idx], &t->size))) {
				ha_alert("parsing [%s:%d] : %s: unexpected character '%c' in argument of '%s'.\n",
					 file, linenum, args[0], *err, args[idx-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			idx++;
		}
		/* This argument does not exit in "peers" section. */
		else if (!peers && strcmp(args[idx], "peers") == 0) {
			idx++;
			if (!*(args[idx])) {
				ha_alert("parsing [%s:%d] : %s: missing argument after '%s'.\n",
					 file, linenum, args[0], args[idx-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			t->peers.name = strdup(args[idx++]);
		}
		else if (strcmp(args[idx], "expire") == 0) {
			idx++;
			if (!*(args[idx])) {
				ha_alert("parsing [%s:%d] : %s: missing argument after '%s'.\n",
					 file, linenum, args[0], args[idx-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			err = parse_time_err(args[idx], &val, TIME_UNIT_MS);
			if (err == PARSE_TIME_OVER) {
				ha_alert("parsing [%s:%d]: %s: timer overflow in argument <%s> to <%s>, maximum value is 2147483647 ms (~24.8 days).\n",
					 file, linenum, args[0], args[idx], args[idx-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (err == PARSE_TIME_UNDER) {
				ha_alert("parsing [%s:%d]: %s: timer underflow in argument <%s> to <%s>, minimum non-null value is 1 ms.\n",
					 file, linenum, args[0], args[idx], args[idx-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (err) {
				ha_alert("parsing [%s:%d] : %s: unexpected character '%c' in argument of '%s'.\n",
					 file, linenum, args[0], *err, args[idx-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			t->expire = val;
			idx++;
		}
		else if (strcmp(args[idx], "nopurge") == 0) {
			t->nopurge = 1;
			idx++;
		}
		else if (strcmp(args[idx], "type") == 0) {
			idx++;
			if (stktable_parse_type(args, &idx, &t->type, &t->key_size) != 0) {
				ha_alert("parsing [%s:%d] : %s: unknown type '%s'.\n",
					 file, linenum, args[0], args[idx]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			/* idx already points to next arg */
		}
		else if (strcmp(args[idx], "store") == 0) {
			int type, err;
			char *cw, *nw, *sa, *sa2;

			idx++;
			nw = args[idx];
			while (*nw) {
				/* the "store" keyword supports a comma-separated list */
				cw = nw;
				sa = NULL; /* store arg */
				sa2 = NULL;
				while (*nw && *nw != ',') {
					if (*nw == '(') {
						*nw = 0;
						sa = ++nw;
						while (*nw != ')') {
							if (!*nw) {
								ha_alert("parsing [%s:%d] : %s: missing closing parenthesis after store option '%s'.\n",
									 file, linenum, args[0], cw);
								err_code |= ERR_ALERT | ERR_FATAL;
								goto out;
							}
							if (*nw == ',') {
								*nw = '\0';
								sa2 = nw + 1;
							}
							nw++;
						}
						*nw = '\0';
					}
					nw++;
				}
				if (*nw)
					*nw++ = '\0';
				type = stktable_get_data_type(cw);
				if (type < 0) {
					ha_alert("parsing [%s:%d] : %s: unknown store option '%s'.\n",
						 file, linenum, args[0], cw);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}

				err = stktable_alloc_data_type(t, type, sa, sa2);
				switch (err) {
				case PE_NONE: break;
				case PE_EXIST:
					ha_warning("parsing [%s:%d]: %s: store option '%s' already enabled, ignored.\n",
						   file, linenum, args[0], cw);
					err_code |= ERR_WARN;
					break;

				case PE_ARG_MISSING:
					ha_alert("parsing [%s:%d] : %s: missing argument to store option '%s'.\n",
						 file, linenum, args[0], cw);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;

				case PE_ARG_NOT_USED:
					ha_alert("parsing [%s:%d] : %s: unexpected argument to store option '%s'.\n",
						 file, linenum, args[0], cw);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				case PE_ARG_VALUE_OOR:
					ha_alert("parsing [%s:%d] : %s: array size is out of allowed range (1-%d) for store option '%s'.\n",
						 file, linenum, args[0], STKTABLE_MAX_DT_ARRAY_SIZE, cw);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;

				default:
					ha_alert("parsing [%s:%d] : %s: error when processing store option '%s'.\n",
						 file, linenum, args[0], cw);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			idx++;
			if (t->data_ofs[STKTABLE_DT_GPT] && t->data_ofs[STKTABLE_DT_GPT0]) {
				ha_alert("parsing [%s:%d] : %s: simultaneous usage of 'gpt' and 'gpt0' in a same table is not permitted as 'gpt' overrides 'gpt0'.\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (t->data_ofs[STKTABLE_DT_GPC] && (t->data_ofs[STKTABLE_DT_GPC0] || t->data_ofs[STKTABLE_DT_GPC1])) {
				ha_alert("parsing [%s:%d] : %s: simultaneous usage of 'gpc' and 'gpc[0/1]' in a same table is not permitted as 'gpc' overrides 'gpc[0/1]'.\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			else if (t->data_ofs[STKTABLE_DT_GPC_RATE] && (t->data_ofs[STKTABLE_DT_GPC0_RATE] || t->data_ofs[STKTABLE_DT_GPC1_RATE])) {
				ha_alert("parsing [%s:%d] : %s: simultaneous usage of 'gpc_rate' and 'gpc[0/1]_rate' in a same table is not permitted as 'gpc_rate' overrides 'gpc[0/1]_rate'.\n",
					 file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
		}
		else if (strcmp(args[idx], "srvkey") == 0) {
			char *keytype;
			idx++;
			keytype = args[idx];
			if (strcmp(keytype, "name") == 0) {
				t->server_key_type = STKTABLE_SRV_NAME;
			}
			else if (strcmp(keytype, "addr") == 0) {
				t->server_key_type = STKTABLE_SRV_ADDR;
			}
			else {
				ha_alert("parsing [%s:%d] : %s : unknown server key type '%s'.\n",
						file, linenum, args[0], keytype);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;

			}
			idx++;
		}
		else {
			ha_alert("parsing [%s:%d] : %s: unknown argument '%s'.\n",
				 file, linenum, args[0], args[idx]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	}

	if (!t->size) {
		ha_alert("parsing [%s:%d] : %s: missing size.\n",
			 file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	if (t->type == (unsigned int)-1) {
		ha_alert("parsing [%s:%d] : %s: missing type.\n",
			 file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

 out:
	return err_code;
}

/* Prepares a stktable_key from a sample <smp> to search into table <t>.
 * Note that the sample *is* modified and that the returned key may point
 * to it, so the sample must not be modified afterwards before the lookup.
 * Returns NULL if the sample could not be converted (eg: no matching type),
 * otherwise a pointer to the static stktable_key filled with what is needed
 * for the lookup.
 */
struct stktable_key *smp_to_stkey(struct sample *smp, struct stktable *t)
{
	/* Convert sample. */
	if (!sample_convert(smp, t->type))
		return NULL;

	/* Fill static_table_key. */
	switch (t->type) {

	case SMP_T_IPV4:
		static_table_key.key = &smp->data.u.ipv4;
		static_table_key.key_len = 4;
		break;

	case SMP_T_IPV6:
		static_table_key.key = &smp->data.u.ipv6;
		static_table_key.key_len = 16;
		break;

	case SMP_T_SINT:
		/* The stick table require a 32bit unsigned int, "sint" is a
		 * signed 64 it, so we can convert it inplace.
		 */
		smp->data.u.sint = (unsigned int)smp->data.u.sint;
		static_table_key.key = &smp->data.u.sint;
		static_table_key.key_len = 4;
		break;

	case SMP_T_STR:
		if (!smp_make_safe(smp))
			return NULL;
		static_table_key.key = smp->data.u.str.area;
		static_table_key.key_len = smp->data.u.str.data;
		break;

	case SMP_T_BIN:
		if (smp->data.u.str.data < t->key_size) {
			/* This type needs padding with 0. */
			if (!smp_make_rw(smp))
				return NULL;

			if (smp->data.u.str.size < t->key_size)
				if (!smp_dup(smp))
					return NULL;
			if (smp->data.u.str.size < t->key_size)
				return NULL;
			memset(smp->data.u.str.area + smp->data.u.str.data, 0,
			       t->key_size - smp->data.u.str.data);
			smp->data.u.str.data = t->key_size;
		}
		static_table_key.key = smp->data.u.str.area;
		static_table_key.key_len = smp->data.u.str.data;
		break;

	default: /* impossible case. */
		return NULL;
	}

	return &static_table_key;
}

/*
 * Process a fetch + format conversion as defined by the sample expression <expr>
 * on request or response considering the <opt> parameter. Returns either NULL if
 * no key could be extracted, or a pointer to the converted result stored in
 * static_table_key in format <table_type>. If <smp> is not NULL, it will be reset
 * and its flags will be initialized so that the caller gets a copy of the input
 * sample, and knows why it was not accepted (eg: SMP_F_MAY_CHANGE is present
 * without SMP_OPT_FINAL). The output will be usable like this :
 *
 * return MAY_CHANGE FINAL   Meaning for the sample
 *  NULL      0        *     Not present and will never be (eg: header)
 *  NULL      1        0     Not present or unstable, could change (eg: req_len)
 *  NULL      1        1     Not present, will not change anymore
 *   smp      0        *     Present and will not change (eg: header)
 *   smp      1        0     not possible
 *   smp      1        1     Present, last known value (eg: request length)
 */
struct stktable_key *stktable_fetch_key(struct stktable *t, struct proxy *px, struct session *sess, struct stream *strm,
                                        unsigned int opt, struct sample_expr *expr, struct sample *smp)
{
	if (smp)
		memset(smp, 0, sizeof(*smp));

	smp = sample_process(px, sess, strm, opt, expr, smp);
	if (!smp)
		return NULL;

	if ((smp->flags & SMP_F_MAY_CHANGE) && !(opt & SMP_OPT_FINAL))
		return NULL; /* we can only use stable samples */

	return smp_to_stkey(smp, t);
}

/*
 * Returns 1 if sample expression <expr> result can be converted to table key of
 * type <table_type>, otherwise zero. Used in configuration check.
 */
int stktable_compatible_sample(struct sample_expr *expr, unsigned long table_type)
{
	int out_type;

	if (table_type >= SMP_TYPES || !stktable_types[table_type].kw)
		return 0;

	out_type = smp_expr_output_type(expr);

	/* Convert sample. */
	if (!sample_casts[out_type][table_type])
		return 0;

	return 1;
}

/* Extra data types processing : after the last one, some room may remain
 * before STKTABLE_DATA_TYPES that may be used to register extra data types
 * at run time.
 */
struct stktable_data_type stktable_data_types[STKTABLE_DATA_TYPES] = {
	[STKTABLE_DT_SERVER_ID]     = { .name = "server_id",      .std_type = STD_T_SINT  },
	[STKTABLE_DT_GPT0]          = { .name = "gpt0",           .std_type = STD_T_UINT  },
	[STKTABLE_DT_GPC0]          = { .name = "gpc0",           .std_type = STD_T_UINT  },
	[STKTABLE_DT_GPC0_RATE]     = { .name = "gpc0_rate",      .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY  },
	[STKTABLE_DT_CONN_CNT]      = { .name = "conn_cnt",       .std_type = STD_T_UINT  },
	[STKTABLE_DT_CONN_RATE]     = { .name = "conn_rate",      .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY  },
	[STKTABLE_DT_CONN_CUR]      = { .name = "conn_cur",       .std_type = STD_T_UINT, .is_local = 1 },
	[STKTABLE_DT_SESS_CNT]      = { .name = "sess_cnt",       .std_type = STD_T_UINT  },
	[STKTABLE_DT_SESS_RATE]     = { .name = "sess_rate",      .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY  },
	[STKTABLE_DT_HTTP_REQ_CNT]  = { .name = "http_req_cnt",   .std_type = STD_T_UINT  },
	[STKTABLE_DT_HTTP_REQ_RATE] = { .name = "http_req_rate",  .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY  },
	[STKTABLE_DT_HTTP_ERR_CNT]  = { .name = "http_err_cnt",   .std_type = STD_T_UINT  },
	[STKTABLE_DT_HTTP_ERR_RATE] = { .name = "http_err_rate",  .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY  },
	[STKTABLE_DT_BYTES_IN_CNT]  = { .name = "bytes_in_cnt",   .std_type = STD_T_ULL   },
	[STKTABLE_DT_BYTES_IN_RATE] = { .name = "bytes_in_rate",  .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY },
	[STKTABLE_DT_BYTES_OUT_CNT] = { .name = "bytes_out_cnt",  .std_type = STD_T_ULL   },
	[STKTABLE_DT_BYTES_OUT_RATE]= { .name = "bytes_out_rate", .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY },
	[STKTABLE_DT_GPC1]          = { .name = "gpc1",           .std_type = STD_T_UINT  },
	[STKTABLE_DT_GPC1_RATE]     = { .name = "gpc1_rate",      .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY  },
	[STKTABLE_DT_SERVER_KEY]    = { .name = "server_key",     .std_type = STD_T_DICT  },
	[STKTABLE_DT_HTTP_FAIL_CNT] = { .name = "http_fail_cnt",  .std_type = STD_T_UINT  },
	[STKTABLE_DT_HTTP_FAIL_RATE]= { .name = "http_fail_rate", .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY  },
	[STKTABLE_DT_GPT]           = { .name = "gpt",            .std_type = STD_T_UINT, .is_array = 1 },
	[STKTABLE_DT_GPC]           = { .name = "gpc",            .std_type = STD_T_UINT, .is_array = 1 },
	[STKTABLE_DT_GPC_RATE]      = { .name = "gpc_rate",       .std_type = STD_T_FRQP, .is_array = 1, .arg_type = ARG_T_DELAY },
};

/* Registers stick-table extra data type with index <idx>, name <name>, type
 * <std_type> and arg type <arg_type>. If the index is negative, the next free
 * index is automatically allocated. The allocated index is returned, or -1 if
 * no free index was found or <name> was already registered. The <name> is used
 * directly as a pointer, so if it's not stable, the caller must allocate it.
 */
int stktable_register_data_store(int idx, const char *name, int std_type, int arg_type)
{
	if (idx < 0) {
		for (idx = 0; idx < STKTABLE_DATA_TYPES; idx++) {
			if (!stktable_data_types[idx].name)
				break;

			if (strcmp(stktable_data_types[idx].name, name) == 0)
				return -1;
		}
	}

	if (idx >= STKTABLE_DATA_TYPES)
		return -1;

	if (stktable_data_types[idx].name != NULL)
		return -1;

	stktable_data_types[idx].name = name;
	stktable_data_types[idx].std_type = std_type;
	stktable_data_types[idx].arg_type = arg_type;
	return idx;
}

/*
 * Returns the data type number for the stktable_data_type whose name is <name>,
 * or <0 if not found.
 */
int stktable_get_data_type(char *name)
{
	int type;

	for (type = 0; type < STKTABLE_DATA_TYPES; type++) {
		if (!stktable_data_types[type].name)
			continue;
		if (strcmp(name, stktable_data_types[type].name) == 0)
			return type;
	}
	/* For backwards compatibility */
	if (strcmp(name, "server_name") == 0)
		return STKTABLE_DT_SERVER_KEY;
	return -1;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns true if found, false otherwise. The input
 * type is STR so that input samples are converted to string (since all types
 * can be converted to strings), then the function casts the string again into
 * the table's type. This is a double conversion, but in the future we might
 * support automatic input types to perform the cast on the fly.
 */
static int sample_conv_in_table(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = !!ts;
	smp->flags = SMP_F_VOL_TEST;
	stktable_release(t, ts);
	return 1;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the data rate received from clients in bytes/s
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_bytes_in_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_BYTES_IN_RATE);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
                                                       t->data_arg[STKTABLE_DT_BYTES_IN_RATE].u);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of connections for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_conn_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_CONN_CNT);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the number of concurrent connections for the
 * key if the key is present in the table, otherwise zero, so that comparisons
 * can be easily performed. If the inspected parameter is not stored in the
 * table, <not found> is returned.
 */
static int sample_conv_table_conn_cur(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_CONN_CUR);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the rate of incoming connections from the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_conn_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_CONN_RATE);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
                                                       t->data_arg[STKTABLE_DT_CONN_RATE].u);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the data rate sent to clients in bytes/s
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_bytes_out_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_BYTES_OUT_RATE);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
                                                       t->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg_p(1), and looks
 * it up into this table. Returns the value of the GPT[arg_p(0)] tag for the key
 * if the key is present in the table, otherwise false, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_gpt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;
	unsigned int idx;

	idx = arg_p[0].data.sint;

	t = arg_p[1].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr_idx(t, ts, STKTABLE_DT_GPT, idx);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the value of the GPT0 tag for the key
 * if the key is present in the table, otherwise false, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_gpt0(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_GPT0);
	if (!ptr)
		ptr = stktable_data_ptr_idx(t, ts, STKTABLE_DT_GPT, 0);

	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg_p(1), and looks
 * it up into this table. Returns the value of the GPC[arg_p(0)] counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_gpc(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;
	unsigned int idx;

	idx = arg_p[0].data.sint;

	t = arg_p[1].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr_idx(t, ts, STKTABLE_DT_GPC, idx);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg_p(1), and looks
 * it up into this table. Returns the event rate of the GPC[arg_p(0)] counter
 * for the key if the key is present in the table, otherwise zero, so that
 * comparisons can be easily performed. If the inspected parameter is not
 * stored in the table, <not found> is returned.
 */
static int sample_conv_table_gpc_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;
	unsigned int idx;

	idx = arg_p[0].data.sint;

	t = arg_p[1].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr_idx(t, ts, STKTABLE_DT_GPC_RATE, idx);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
		                                        t->data_arg[STKTABLE_DT_GPC_RATE].u);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the value of the GPC0 counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_gpc0(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_GPC0);
	if (!ptr) {
		/* fallback on the gpc array */
		ptr = stktable_data_ptr_idx(t, ts, STKTABLE_DT_GPC, 0);
	}

	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the event rate of the GPC0 counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_gpc0_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_GPC0_RATE);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
                                                       t->data_arg[STKTABLE_DT_GPC0_RATE].u);
	else {
		/* fallback on the gpc array */
		ptr = stktable_data_ptr_idx(t, ts, STKTABLE_DT_GPC_RATE, 0);
		if (ptr)
			smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
			                                        t->data_arg[STKTABLE_DT_GPC_RATE].u);
	}

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the value of the GPC1 counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_gpc1(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_GPC1);
	if (!ptr) {
		/* fallback on the gpc array */
		ptr = stktable_data_ptr_idx(t, ts, STKTABLE_DT_GPC, 1);
	}

	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the event rate of the GPC1 counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_gpc1_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_GPC1_RATE);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
                                                       t->data_arg[STKTABLE_DT_GPC1_RATE].u);
	else {
		/* fallback on the gpc array */
		ptr = stktable_data_ptr_idx(t, ts, STKTABLE_DT_GPC_RATE, 1);
		if (ptr)
			smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
			                                        t->data_arg[STKTABLE_DT_GPC_RATE].u);
	}

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of HTTP request errors
 * for the key if the key is present in the table, otherwise zero, so that
 * comparisons can be easily performed. If the inspected parameter is not stored
 * in the table, <not found> is returned.
 */
static int sample_conv_table_http_err_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_ERR_CNT);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the HTTP request error rate the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_http_err_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_ERR_RATE);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
                                                       t->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of HTTP response failures
 * for the key if the key is present in the table, otherwise zero, so that
 * comparisons can be easily performed. If the inspected parameter is not stored
 * in the table, <not found> is returned.
 */
static int sample_conv_table_http_fail_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_FAIL_CNT);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the HTTP response failure rate for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_http_fail_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_FAIL_RATE);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
                                                       t->data_arg[STKTABLE_DT_HTTP_FAIL_RATE].u);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of HTTP request for the
 * key if the key is present in the table, otherwise zero, so that comparisons
 * can be easily performed. If the inspected parameter is not stored in the
 * table, <not found> is returned.
 */
static int sample_conv_table_http_req_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_CNT);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the HTTP request rate the key if the key is
 * present in the table, otherwise zero, so that comparisons can be easily
 * performed. If the inspected parameter is not stored in the table, <not found>
 * is returned.
 */
static int sample_conv_table_http_req_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_HTTP_REQ_RATE);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
                                                       t->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the volume of datareceived from clients in kbytes
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_kbytes_in(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_BYTES_IN_CNT);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_ull) >> 10;

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the volume of data sent to clients in kbytes
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_kbytes_out(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_BYTES_OUT_CNT);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_ull) >> 10;

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the server ID associated with the key if the
 * key is present in the table, otherwise zero, so that comparisons can be
 * easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int sample_conv_table_server_id(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_ID);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_sint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of sessions for the
 * key if the key is present in the table, otherwise zero, so that comparisons
 * can be easily performed. If the inspected parameter is not stored in the
 * table, <not found> is returned.
 */
static int sample_conv_table_sess_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_SESS_CNT);
	if (ptr)
		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the session rate the key if the key is
 * present in the table, otherwise zero, so that comparisons can be easily
 * performed. If the inspected parameter is not stored in the table, <not found>
 * is returned.
 */
static int sample_conv_table_sess_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_SESS_RATE);
	if (ptr)
		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
                                                       t->data_arg[STKTABLE_DT_SESS_RATE].u);

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the amount of concurrent connections tracking
 * the same key if the key is present in the table, otherwise zero, so that
 * comparisons can be easily performed. If the inspected parameter is not
 * stored in the table, <not found> is returned.
 */
static int sample_conv_table_trackers(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stktable_key *key;
	struct stksess *ts;

	t = arg_p[0].data.t;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts)
		return 1;

	smp->data.u.sint = ts->ref_cnt;

	stktable_release(t, ts);
	return 1;
}

/* This function increments the gpc counter at index 'rule->arg.gpc.idx' of the
 * array on the tracksc counter of index 'rule->arg.gpc.sc' stored into the
 * <stream> or directly in the session <sess> if <stream> is set to NULL
 *
 * This function always returns ACT_RET_CONT and parameter flags is unused.
 */
static enum act_return action_inc_gpc(struct act_rule *rule, struct proxy *px,
                                      struct session *sess, struct stream *s, int flags)
{
	struct stksess *ts;
	struct stkctr *stkctr;

	/* Extract the stksess, return OK if no stksess available. */
	if (s)
		stkctr = &s->stkctr[rule->arg.gpc.sc];
	else
		stkctr = &sess->stkctr[rule->arg.gpc.sc];

	ts = stkctr_entry(stkctr);
	if (ts) {
		void *ptr1, *ptr2;

		/* First, update gpc_rate if it's tracked. Second, update its gpc if tracked. */
		ptr1 = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPC_RATE, rule->arg.gpc.idx);
		ptr2 = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPC, rule->arg.gpc.idx);

		if (ptr1 || ptr2) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

			if (ptr1)
				update_freq_ctr_period(&stktable_data_cast(ptr1, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u, 1);

			if (ptr2)
				stktable_data_cast(ptr2, std_t_uint)++;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, ts, 0);
		}
	}
	return ACT_RET_CONT;
}

/* Same as action_inc_gpc() but for gpc0 only */
static enum act_return action_inc_gpc0(struct act_rule *rule, struct proxy *px,
                                       struct session *sess, struct stream *s, int flags)
{
	struct stksess *ts;
	struct stkctr *stkctr;
	unsigned int period = 0;

	/* Extract the stksess, return OK if no stksess available. */
	if (s)
		stkctr = &s->stkctr[rule->arg.gpc.sc];
	else
		stkctr = &sess->stkctr[rule->arg.gpc.sc];

	ts = stkctr_entry(stkctr);
	if (ts) {
		void *ptr1, *ptr2;

		/* First, update gpc0_rate if it's tracked. Second, update its gpc0 if tracked. */
		ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GPC0_RATE);
		if (ptr1) {
			period = stkctr->table->data_arg[STKTABLE_DT_GPC0_RATE].u;
		}
		else {
			/* fallback on the gpc array */
			ptr1 = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPC_RATE, 0);
			if (ptr1)
				period = stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u;
		}

		ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GPC0);
		if (!ptr2) {
			/* fallback on the gpc array */
			ptr2 = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPC, 0);
		}

		if (ptr1 || ptr2) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

			if (ptr1)
				update_freq_ctr_period(&stktable_data_cast(ptr1, std_t_frqp),
				                       period, 1);

			if (ptr2)
				stktable_data_cast(ptr2, std_t_uint)++;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, ts, 0);
		}
	}
	return ACT_RET_CONT;
}

/* Same as action_inc_gpc() but for gpc1 only */
static enum act_return action_inc_gpc1(struct act_rule *rule, struct proxy *px,
                                       struct session *sess, struct stream *s, int flags)
{
	struct stksess *ts;
	struct stkctr *stkctr;
	unsigned int period = 0;

	/* Extract the stksess, return OK if no stksess available. */
	if (s)
		stkctr = &s->stkctr[rule->arg.gpc.sc];
	else
		stkctr = &sess->stkctr[rule->arg.gpc.sc];

	ts = stkctr_entry(stkctr);
	if (ts) {
		void *ptr1, *ptr2;

		/* First, update gpc1_rate if it's tracked. Second, update its gpc1 if tracked. */
		ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GPC1_RATE);
		if (ptr1) {
			period = stkctr->table->data_arg[STKTABLE_DT_GPC1_RATE].u;
		}
		else {
			/* fallback on the gpc array */
			ptr1 = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPC_RATE, 1);
			if (ptr1)
				period = stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u;
		}

		ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GPC1);
		if (!ptr2) {
			/* fallback on the gpc array */
			ptr2 = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPC, 1);
		}

		if (ptr1 || ptr2) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

			if (ptr1)
				update_freq_ctr_period(&stktable_data_cast(ptr1, std_t_frqp),
				                       period, 1);

			if (ptr2)
				stktable_data_cast(ptr2, std_t_uint)++;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, ts, 0);
		}
	}
	return ACT_RET_CONT;
}

/* This function is a common parser for actions incrementing the GPC
 * (General Purpose Counters). It understands the formats:
 *
 *   sc-inc-gpc(<gpc IDX>,<track ID>)
 *   sc-inc-gpc0([<track ID>])
 *   sc-inc-gpc1([<track ID>])
 *
 * It returns ACT_RET_PRS_ERR if fails and <err> is filled with an error
 * message. Otherwise it returns ACT_RET_PRS_OK.
 */
static enum act_parse_ret parse_inc_gpc(const char **args, int *arg, struct proxy *px,
                                        struct act_rule *rule, char **err)
{
	const char *cmd_name = args[*arg-1];
	char *error;

	cmd_name += strlen("sc-inc-gpc");
	if (*cmd_name == '(') {
		cmd_name++; /* skip the '(' */
		rule->arg.gpc.idx = strtoul(cmd_name, &error, 10); /* Convert stick table id. */
		if (*error != ',') {
			memprintf(err, "Missing gpc ID '%s'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)", args[*arg-1]);
			return ACT_RET_PRS_ERR;
		}
		else {
			cmd_name = error + 1; /* skip the ',' */
			rule->arg.gpc.sc = strtol(cmd_name, &error, 10); /* Convert stick table id. */
			if (*error != ')') {
				memprintf(err, "invalid stick table track ID '%s'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)", args[*arg-1]);
				return ACT_RET_PRS_ERR;
			}

			if (rule->arg.gpc.sc >= MAX_SESS_STKCTR) {
				memprintf(err, "invalid stick table track ID '%s'. The max allowed ID is %d",
				          args[*arg-1], MAX_SESS_STKCTR-1);
				return ACT_RET_PRS_ERR;
			}
		}
		rule->action_ptr = action_inc_gpc;
	}
	else if (*cmd_name == '0' ||*cmd_name == '1') {
		char c = *cmd_name;

		cmd_name++;
		if (*cmd_name == '\0') {
			/* default stick table id. */
			rule->arg.gpc.sc = 0;
		} else {
			/* parse the stick table id. */
			if (*cmd_name != '(') {
				memprintf(err, "invalid stick table track ID. Expects %s(<Track ID>)", args[*arg-1]);
				return ACT_RET_PRS_ERR;
			}
			cmd_name++; /* jump the '(' */
			rule->arg.gpc.sc = strtol(cmd_name, &error, 10); /* Convert stick table id. */
			if (*error != ')') {
				memprintf(err, "invalid stick table track ID. Expects %s(<Track ID>)", args[*arg-1]);
				return ACT_RET_PRS_ERR;
			}

			if (rule->arg.gpc.sc >= MAX_SESS_STKCTR) {
				memprintf(err, "invalid stick table track ID. The max allowed ID is %d",
				          MAX_SESS_STKCTR-1);
				return ACT_RET_PRS_ERR;
			}
		}
		if (c == '1')
			rule->action_ptr = action_inc_gpc1;
		else
			rule->action_ptr = action_inc_gpc0;
	}
	else {
		/* default stick table id. */
		memprintf(err, "invalid gpc ID '%s'. Expects sc-set-gpc(<GPC ID>,<Track ID>)", args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}
	rule->action = ACT_CUSTOM;
	return ACT_RET_PRS_OK;
}

/* This function sets the gpt at index 'rule->arg.gpt.idx' of the array on the
 * tracksc counter of index 'rule->arg.gpt.sc' stored into the <stream> or
 * directly in the session <sess> if <stream> is set to NULL. This gpt is
 * set to the value computed by the expression 'rule->arg.gpt.expr' or if
 * 'rule->arg.gpt.expr' is null directly to the value of 'rule->arg.gpt.value'.
 *
 * This function always returns ACT_RET_CONT and parameter flags is unused.
 */
static enum act_return action_set_gpt(struct act_rule *rule, struct proxy *px,
                                      struct session *sess, struct stream *s, int flags)
{
	void *ptr;
	struct stksess *ts;
	struct stkctr *stkctr;
	unsigned int value = 0;
	struct sample *smp;
	int smp_opt_dir;

	/* Extract the stksess, return OK if no stksess available. */
	if (s)
		stkctr = &s->stkctr[rule->arg.gpt.sc];
	else
		stkctr = &sess->stkctr[rule->arg.gpt.sc];

	ts = stkctr_entry(stkctr);
	if (!ts)
		return ACT_RET_CONT;

	/* Store the sample in the required sc, and ignore errors. */
	ptr = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPT, rule->arg.gpt.idx);
	if (ptr) {

		if (!rule->arg.gpt.expr)
			value = (unsigned int)(rule->arg.gpt.value);
		else {
			switch (rule->from) {
			case ACT_F_TCP_REQ_SES: smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_TCP_REQ_CNT: smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_TCP_RES_CNT: smp_opt_dir = SMP_OPT_DIR_RES; break;
			case ACT_F_HTTP_REQ:    smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_HTTP_RES:    smp_opt_dir = SMP_OPT_DIR_RES; break;
			default:
				send_log(px, LOG_ERR, "stick table: internal error while setting gpt%u.", rule->arg.gpt.idx);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					ha_alert("stick table: internal error while executing setting gpt%u.\n", rule->arg.gpt.idx);
				return ACT_RET_CONT;
			}

			/* Fetch and cast the expression. */
			smp = sample_fetch_as_type(px, sess, s, smp_opt_dir|SMP_OPT_FINAL, rule->arg.gpt.expr, SMP_T_SINT);
			if (!smp) {
				send_log(px, LOG_WARNING, "stick table: invalid expression or data type while setting gpt%u.", rule->arg.gpt.idx);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					ha_alert("stick table: invalid expression or data type while setting gpt%u.\n", rule->arg.gpt.idx);
				return ACT_RET_CONT;
			}
			value = (unsigned int)(smp->data.u.sint);
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

		stktable_data_cast(ptr, std_t_uint) = value;

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

		stktable_touch_local(stkctr->table, ts, 0);
	}

	return ACT_RET_CONT;
}

/* Always returns 1. */
static enum act_return action_set_gpt0(struct act_rule *rule, struct proxy *px,
                                       struct session *sess, struct stream *s, int flags)
{
	void *ptr;
	struct stksess *ts;
	struct stkctr *stkctr;
	unsigned int value = 0;
	struct sample *smp;
	int smp_opt_dir;

	/* Extract the stksess, return OK if no stksess available. */
	if (s)
		stkctr = &s->stkctr[rule->arg.gpt.sc];
	else
		stkctr = &sess->stkctr[rule->arg.gpt.sc];

	ts = stkctr_entry(stkctr);
	if (!ts)
		return ACT_RET_CONT;

	/* Store the sample in the required sc, and ignore errors. */
	ptr = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GPT0);
	if (!ptr)
		ptr = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPT, 0);

	if (ptr) {
		if (!rule->arg.gpt.expr)
			value = (unsigned int)(rule->arg.gpt.value);
		else {
			switch (rule->from) {
			case ACT_F_TCP_REQ_SES: smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_TCP_REQ_CNT: smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_TCP_RES_CNT: smp_opt_dir = SMP_OPT_DIR_RES; break;
			case ACT_F_HTTP_REQ:    smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_HTTP_RES:    smp_opt_dir = SMP_OPT_DIR_RES; break;
			default:
				send_log(px, LOG_ERR, "stick table: internal error while setting gpt0.");
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					ha_alert("stick table: internal error while executing setting gpt0.\n");
				return ACT_RET_CONT;
			}

			/* Fetch and cast the expression. */
			smp = sample_fetch_as_type(px, sess, s, smp_opt_dir|SMP_OPT_FINAL, rule->arg.gpt.expr, SMP_T_SINT);
			if (!smp) {
				send_log(px, LOG_WARNING, "stick table: invalid expression or data type while setting gpt0.");
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					ha_alert("stick table: invalid expression or data type while setting gpt0.\n");
				return ACT_RET_CONT;
			}
			value = (unsigned int)(smp->data.u.sint);
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

		stktable_data_cast(ptr, std_t_uint) = value;

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

		stktable_touch_local(stkctr->table, ts, 0);
	}

	return ACT_RET_CONT;
}

/* This function is a parser for the "sc-set-gpt" and "sc-set-gpt0" actions.
 * It understands the formats:
 *
 *   sc-set-gpt(<gpt IDX>,<track ID>) <expression>
 *   sc-set-gpt0(<track ID>) <expression>
 *
 * It returns ACT_RET_PRS_ERR if fails and <err> is filled with an error message.
 * Otherwise, it returns ACT_RET_PRS_OK and the variable 'rule->arg.gpt.expr'
 * is filled with the pointer to the expression to execute or NULL if the arg
 * is directly an integer stored into 'rule->arg.gpt.value'.
 */
static enum act_parse_ret parse_set_gpt(const char **args, int *arg, struct proxy *px,
                                         struct act_rule *rule, char **err)
{
	const char *cmd_name = args[*arg-1];
	char *error;
	int smp_val;

	cmd_name += strlen("sc-set-gpt");
	if (*cmd_name == '(') {
		cmd_name++; /* skip the '(' */
		rule->arg.gpt.idx = strtoul(cmd_name, &error, 10); /* Convert stick table id. */
		if (*error != ',') {
			memprintf(err, "Missing gpt ID '%s'. Expects sc-set-gpt(<GPT ID>,<Track ID>)", args[*arg-1]);
			return ACT_RET_PRS_ERR;
		}
		else {
			cmd_name = error + 1; /* skip the ',' */
			rule->arg.gpt.sc = strtol(cmd_name, &error, 10); /* Convert stick table id. */
			if (*error != ')') {
				memprintf(err, "invalid stick table track ID '%s'. Expects sc-set-gpt(<GPT ID>,<Track ID>)", args[*arg-1]);
				return ACT_RET_PRS_ERR;
			}

			if (rule->arg.gpt.sc >= MAX_SESS_STKCTR) {
				memprintf(err, "invalid stick table track ID '%s'. The max allowed ID is %d",
				          args[*arg-1], MAX_SESS_STKCTR-1);
				return ACT_RET_PRS_ERR;
			}
		}
		rule->action_ptr = action_set_gpt;
	}
	else if (*cmd_name == '0') {
		cmd_name++;
		if (*cmd_name == '\0') {
			/* default stick table id. */
			rule->arg.gpt.sc = 0;
		} else {
			/* parse the stick table id. */
			if (*cmd_name != '(') {
				memprintf(err, "invalid stick table track ID '%s'. Expects sc-set-gpt0(<Track ID>)", args[*arg-1]);
				return ACT_RET_PRS_ERR;
			}
			cmd_name++; /* jump the '(' */
			rule->arg.gpt.sc = strtol(cmd_name, &error, 10); /* Convert stick table id. */
			if (*error != ')') {
				memprintf(err, "invalid stick table track ID '%s'. Expects sc-set-gpt0(<Track ID>)", args[*arg-1]);
				return ACT_RET_PRS_ERR;
			}

			if (rule->arg.gpt.sc >= MAX_SESS_STKCTR) {
				memprintf(err, "invalid stick table track ID '%s'. The max allowed ID is %d",
				          args[*arg-1], MAX_SESS_STKCTR-1);
				return ACT_RET_PRS_ERR;
			}
		}
		rule->action_ptr = action_set_gpt0;
	}
	else {
		/* default stick table id. */
		memprintf(err, "invalid gpt ID '%s'. Expects sc-set-gpt(<GPT ID>,<Track ID>)", args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}

	/* value may be either an integer or an expression */
	rule->arg.gpt.expr = NULL;
	rule->arg.gpt.value = strtol(args[*arg], &error, 10);
	if (*error == '\0') {
		/* valid integer, skip it */
		(*arg)++;
	} else {
		rule->arg.gpt.expr = sample_parse_expr((char **)args, arg, px->conf.args.file,
		                                       px->conf.args.line, err, &px->conf.args, NULL);
		if (!rule->arg.gpt.expr)
			return ACT_RET_PRS_ERR;

		switch (rule->from) {
		case ACT_F_TCP_REQ_SES: smp_val = SMP_VAL_FE_SES_ACC; break;
		case ACT_F_TCP_REQ_CNT: smp_val = SMP_VAL_FE_REQ_CNT; break;
		case ACT_F_TCP_RES_CNT: smp_val = SMP_VAL_BE_RES_CNT; break;
		case ACT_F_HTTP_REQ:    smp_val = SMP_VAL_FE_HRQ_HDR; break;
		case ACT_F_HTTP_RES:    smp_val = SMP_VAL_BE_HRS_HDR; break;
		default:
			memprintf(err, "internal error, unexpected rule->from=%d, please report this bug!", rule->from);
			return ACT_RET_PRS_ERR;
		}
		if (!(rule->arg.gpt.expr->fetch->val & smp_val)) {
			memprintf(err, "fetch method '%s' extracts information from '%s', none of which is available here", args[*arg-1],
			          sample_src_names(rule->arg.gpt.expr->fetch->use));
			free(rule->arg.gpt.expr);
			return ACT_RET_PRS_ERR;
		}
	}

	rule->action = ACT_CUSTOM;

	return ACT_RET_PRS_OK;
}

/* set temp integer to the number of used entries in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
smp_fetch_table_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = args->data.t->current;
	return 1;
}

/* set temp integer to the number of free entries in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
smp_fetch_table_avl(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stktable *t;

	t = args->data.t;
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = t->size - t->current;
	return 1;
}

/* Returns a pointer to a stkctr depending on the fetch keyword name.
 * It is designed to be called as sc[0-9]_* sc_* or src_* exclusively.
 * sc[0-9]_* will return a pointer to the respective field in the
 * stream <l4>. sc_* requires an UINT argument specifying the stick
 * counter number. src_* will fill a locally allocated structure with
 * the table and entry corresponding to what is specified with src_*.
 * NULL may be returned if the designated stkctr is not tracked. For
 * the sc_* and sc[0-9]_* forms, an optional table argument may be
 * passed. When present, the currently tracked key is then looked up
 * in the specified table instead of the current table. The purpose is
 * to be able to convert multiple values per key (eg: have gpc0 from
 * multiple tables). <strm> is allowed to be NULL, in which case only
 * the session will be consulted.
 */
struct stkctr *
smp_fetch_sc_stkctr(struct session *sess, struct stream *strm, const struct arg *args, const char *kw, struct stkctr *stkctr)
{
	struct stkctr *stkptr;
	struct stksess *stksess;
	unsigned int num = kw[2] - '0';
	int arg = 0;

	if (num == '_' - '0') {
		/* sc_* variant, args[0] = ctr# (mandatory) */
		num = args[arg++].data.sint;
	}
	else if (num > 9) { /* src_* variant, args[0] = table */
		struct stktable_key *key;
		struct connection *conn = objt_conn(sess->origin);
		struct sample smp;

		if (!conn)
			return NULL;

		/* Fetch source address in a sample. */
		smp.px = NULL;
		smp.sess = sess;
		smp.strm = strm;
		if (!smp_fetch_src || !smp_fetch_src(empty_arg_list, &smp, "src", NULL))
			return NULL;

		/* Converts into key. */
		key = smp_to_stkey(&smp, args->data.t);
		if (!key)
			return NULL;

		stkctr->table = args->data.t;
		stkctr_set_entry(stkctr, stktable_lookup_key(stkctr->table, key));
		return stkctr;
	}

	/* Here, <num> contains the counter number from 0 to 9 for
	 * the sc[0-9]_ form, or even higher using sc_(num) if needed.
	 * args[arg] is the first optional argument. We first lookup the
	 * ctr form the stream, then from the session if it was not there.
	 * But we must be sure the counter does not exceed MAX_SESS_STKCTR.
	 */
	if (num >= MAX_SESS_STKCTR)
		return NULL;

	if (strm)
		stkptr = &strm->stkctr[num];
	if (!strm || !stkctr_entry(stkptr)) {
		stkptr = &sess->stkctr[num];
		if (!stkctr_entry(stkptr))
			return NULL;
	}

	stksess = stkctr_entry(stkptr);
	if (!stksess)
		return NULL;

	if (unlikely(args[arg].type == ARGT_TAB)) {
		/* an alternate table was specified, let's look up the same key there */
		stkctr->table = args[arg].data.t;
		stkctr_set_entry(stkctr, stktable_lookup(stkctr->table, stksess));
		return stkctr;
	}
	return stkptr;
}

/* same as smp_fetch_sc_stkctr() but dedicated to src_* and can create
 * the entry if it doesn't exist yet. This is needed for a few fetch
 * functions which need to create an entry, such as src_inc_gpc* and
 * src_clr_gpc*.
 */
struct stkctr *
smp_create_src_stkctr(struct session *sess, struct stream *strm, const struct arg *args, const char *kw, struct stkctr *stkctr)
{
	struct stktable_key *key;
	struct connection *conn = objt_conn(sess->origin);
	struct sample smp;

	if (strncmp(kw, "src_", 4) != 0)
		return NULL;

	if (!conn)
		return NULL;

	/* Fetch source address in a sample. */
	smp.px = NULL;
	smp.sess = sess;
	smp.strm = strm;
	if (!smp_fetch_src || !smp_fetch_src(empty_arg_list, &smp, "src", NULL))
		return NULL;

	/* Converts into key. */
	key = smp_to_stkey(&smp, args->data.t);
	if (!key)
		return NULL;

	stkctr->table = args->data.t;
	stkctr_set_entry(stkctr, stktable_get_entry(stkctr->table, key));
	return stkctr;
}

/* set return a boolean indicating if the requested stream counter is
 * currently being tracked or not.
 * Supports being called as "sc[0-9]_tracked" only.
 */
static int
smp_fetch_sc_tracked(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_BOOL;
	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	smp->data.u.sint = !!stkctr;

	/* release the ref count */
	if (stkctr == &tmpstkctr)
		stktable_release(stkctr->table, stkctr_entry(stkctr));

	return 1;
}

/* set <smp> to the General Purpose Tag of index set as first arg
 * to value from the stream's tracked frontend counters or from the src.
 * Supports being called as "sc_get_gpt(<gpt-idx>,<sc-idx>[,<table>])" or
 * "src_get_gpt(<gpt-idx>[,<table>])" only. Value zero is returned if
 * the key is new or gpt is not stored.
 */
static int
smp_fetch_sc_get_gpt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	unsigned int idx;

	idx = args[0].data.sint;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPT, idx);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the General Purpose Flag 0 value from the stream's tracked
 * frontend counters or from the src.
 * Supports being called as "sc[0-9]_get_gpc0" or "src_get_gpt0" only. Value
 * zero is returned if the key is new.
 */
static int
smp_fetch_sc_get_gpt0(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPT0);
		if (!ptr)
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPT, 0);

		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the GPC[args(0)]'s value from the stream's tracked
 * frontend counters or from the src.
 * Supports being called as "sc_get_gpc(<gpc-idx>,<sc-idx>[,<table>])" or
 * "src_get_gpc(<gpc-idx>[,<table>])" only. Value
 * Value zero is returned if the key is new or gpc is not stored.
 */
static int
smp_fetch_sc_get_gpc(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	unsigned int idx;

	idx = args[0].data.sint;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr  = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, idx);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the General Purpose Counter 0 value from the stream's tracked
 * frontend counters or from the src.
 * Supports being called as "sc[0-9]_get_gpc0" or "src_get_gpc0" only. Value
 * zero is returned if the key is new.
 */
static int
smp_fetch_sc_get_gpc0(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr  = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0);
		if (!ptr) {
			/* fallback on the gpc array */
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, 0);
		}

		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the General Purpose Counter 1 value from the stream's tracked
 * frontend counters or from the src.
 * Supports being called as "sc[0-9]_get_gpc1" or "src_get_gpc1" only. Value
 * zero is returned if the key is new.
 */
static int
smp_fetch_sc_get_gpc1(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr  = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC1);
		if (!ptr) {
			/* fallback on the gpc array */
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, 1);
		}

		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the GPC[args(0)]'s event rate from the stream's
 * tracked frontend counters or from the src.
 * Supports being called as "sc_gpc_rate(<gpc-idx>,<sc-idx>[,<table])"
 * or "src_gpc_rate(<gpc-idx>[,<table>])" only.
 * Value zero is returned if the key is new or gpc_rate is not stored.
 */
static int
smp_fetch_sc_gpc_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	unsigned int idx;

	idx = args[0].data.sint;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC_RATE, idx);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
		                   stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the General Purpose Counter 0's event rate from the stream's
 * tracked frontend counters or from the src.
 * Supports being called as "sc[0-9]_gpc0_rate" or "src_gpc0_rate" only.
 * Value zero is returned if the key is new.
 */
static int
smp_fetch_sc_gpc0_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	unsigned int period;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0_RATE);
		if (ptr) {
			period = stkctr->table->data_arg[STKTABLE_DT_GPC0_RATE].u;
		}
		else {
			/* fallback on the gpc array */
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC_RATE, 0);
			if (ptr)
				period = stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u;
		}

		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp), period);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the General Purpose Counter 1's event rate from the stream's
 * tracked frontend counters or from the src.
 * Supports being called as "sc[0-9]_gpc1_rate" or "src_gpc1_rate" only.
 * Value zero is returned if the key is new.
 */
static int
smp_fetch_sc_gpc1_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	unsigned int period;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC1_RATE);
		if (ptr) {
			period = stkctr->table->data_arg[STKTABLE_DT_GPC1_RATE].u;
		}
		else {
			/* fallback on the gpc array */
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC_RATE, 1);
			if (ptr)
				period = stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u;
		}

		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp), period);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* Increment the GPC[args(0)] value from the stream's tracked
 * frontend counters and return it into temp integer.
 * Supports being called as "sc_inc_gpc(<gpc-idx>,<sc-idx>[,<table>])"
 * or "src_inc_gpc(<gpc-idx>[,<table>])" only.
 */
static int
smp_fetch_sc_inc_gpc(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	unsigned int idx;

	idx = args[0].data.sint;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!stkctr_entry(stkctr))
		stkctr = smp_create_src_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (stkctr && stkctr_entry(stkctr)) {
		void *ptr1,*ptr2;


		/* First, update gpc0_rate if it's tracked. Second, update its
		 * gpc0 if tracked. Returns gpc0's value otherwise the curr_ctr.
		 */
		ptr1 = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC_RATE, idx);
		ptr2 = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, idx);
		if (ptr1 || ptr2) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

			if (ptr1) {
				update_freq_ctr_period(&stktable_data_cast(ptr1, std_t_frqp),
						       stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u, 1);
				smp->data.u.sint = (&stktable_data_cast(ptr1, std_t_frqp))->curr_ctr;
			}

			if (ptr2)
				smp->data.u.sint = ++stktable_data_cast(ptr2, std_t_uint);

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, stkctr_entry(stkctr), (stkctr == &tmpstkctr) ? 1 : 0);
		}
		else if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* Increment the General Purpose Counter 0 value from the stream's tracked
 * frontend counters and return it into temp integer.
 * Supports being called as "sc[0-9]_inc_gpc0" or "src_inc_gpc0" only.
 */
static int
smp_fetch_sc_inc_gpc0(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	unsigned int period = 0;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!stkctr_entry(stkctr))
		stkctr = smp_create_src_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (stkctr && stkctr_entry(stkctr)) {
		void *ptr1,*ptr2;


		/* First, update gpc0_rate if it's tracked. Second, update its
		 * gpc0 if tracked. Returns gpc0's value otherwise the curr_ctr.
		 */
		ptr1 = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0_RATE);
		if (ptr1) {
			period = stkctr->table->data_arg[STKTABLE_DT_GPC0_RATE].u;
		}
		else {
			/* fallback on the gpc array */
			ptr1 = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC_RATE, 0);
			if (ptr1)
				period = stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u;
		}

		ptr2 = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0);
		if (!ptr2) {
			/* fallback on the gpc array */
			ptr2 = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, 0);
		}

		if (ptr1 || ptr2) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

			if (ptr1) {
				update_freq_ctr_period(&stktable_data_cast(ptr1, std_t_frqp),
						       period, 1);
				smp->data.u.sint = (&stktable_data_cast(ptr1, std_t_frqp))->curr_ctr;
			}

			if (ptr2)
				smp->data.u.sint = ++stktable_data_cast(ptr2, std_t_uint);

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, stkctr_entry(stkctr), (stkctr == &tmpstkctr) ? 1 : 0);
		}
		else if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* Increment the General Purpose Counter 1 value from the stream's tracked
 * frontend counters and return it into temp integer.
 * Supports being called as "sc[0-9]_inc_gpc1" or "src_inc_gpc1" only.
 */
static int
smp_fetch_sc_inc_gpc1(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	unsigned int period = 0;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!stkctr_entry(stkctr))
		stkctr = smp_create_src_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (stkctr && stkctr_entry(stkctr)) {
		void *ptr1,*ptr2;


		/* First, update gpc1_rate if it's tracked. Second, update its
		 * gpc1 if tracked. Returns gpc1's value otherwise the curr_ctr.
		 */
		ptr1 = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC1_RATE);
		if (ptr1) {
			period = stkctr->table->data_arg[STKTABLE_DT_GPC1_RATE].u;
		}
		else {
			/* fallback on the gpc array */
			ptr1 = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC_RATE, 1);
			if (ptr1)
				period = stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u;
		}

		ptr2 = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC1);
		if (!ptr2) {
			/* fallback on the gpc array */
			ptr2 = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, 1);
		}

		if (ptr1 || ptr2) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

			if (ptr1) {
				update_freq_ctr_period(&stktable_data_cast(ptr1, std_t_frqp),
						       period, 1);
				smp->data.u.sint = (&stktable_data_cast(ptr1, std_t_frqp))->curr_ctr;
			}

			if (ptr2)
				smp->data.u.sint = ++stktable_data_cast(ptr2, std_t_uint);

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, stkctr_entry(stkctr), (stkctr == &tmpstkctr) ? 1 : 0);
		}
		else if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* Clear the GPC[args(0)] value from the stream's tracked
 * frontend counters and return its previous value into temp integer.
 * Supports being called as "sc_clr_gpc(<gpc-idx>,<sc-idx>[,<table>])"
 * or "src_clr_gpc(<gpc-idx>[,<table>])" only.
 */
static int
smp_fetch_sc_clr_gpc(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	unsigned int idx;

	idx = args[0].data.sint;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!stkctr_entry(stkctr))
		stkctr = smp_create_src_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (stkctr && stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, idx);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);
		stktable_data_cast(ptr, std_t_uint) = 0;

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		/* If data was modified, we need to touch to re-schedule sync */
		stktable_touch_local(stkctr->table, stkctr_entry(stkctr), (stkctr == &tmpstkctr) ? 1 : 0);
	}
	return 1;
}

/* Clear the General Purpose Counter 0 value from the stream's tracked
 * frontend counters and return its previous value into temp integer.
 * Supports being called as "sc[0-9]_clr_gpc0" or "src_clr_gpc0" only.
 */
static int
smp_fetch_sc_clr_gpc0(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!stkctr_entry(stkctr))
		stkctr = smp_create_src_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (stkctr && stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0);
		if (!ptr) {
			/* fallback on the gpc array */
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, 0);
		}

		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);
		stktable_data_cast(ptr, std_t_uint) = 0;

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		/* If data was modified, we need to touch to re-schedule sync */
		stktable_touch_local(stkctr->table, stkctr_entry(stkctr), (stkctr == &tmpstkctr) ? 1 : 0);
	}
	return 1;
}

/* Clear the General Purpose Counter 1 value from the stream's tracked
 * frontend counters and return its previous value into temp integer.
 * Supports being called as "sc[0-9]_clr_gpc1" or "src_clr_gpc1" only.
 */
static int
smp_fetch_sc_clr_gpc1(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!stkctr_entry(stkctr))
		stkctr = smp_create_src_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (stkctr && stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC1);
		if (!ptr) {
			/* fallback on the gpc array */
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, 1);
		}

		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);
		stktable_data_cast(ptr, std_t_uint) = 0;

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		/* If data was modified, we need to touch to re-schedule sync */
		stktable_touch_local(stkctr->table, stkctr_entry(stkctr), (stkctr == &tmpstkctr) ? 1 : 0);
	}
	return 1;
}

/* set <smp> to the cumulated number of connections from the stream's tracked
 * frontend counters. Supports being called as "sc[0-9]_conn_cnt" or
 * "src_conn_cnt" only.
 */
static int
smp_fetch_sc_conn_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_CNT);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));


	}
	return 1;
}

/* set <smp> to the connection rate from the stream's tracked frontend
 * counters. Supports being called as "sc[0-9]_conn_rate" or "src_conn_rate"
 * only.
 */
static int
smp_fetch_sc_conn_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_RATE);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_CONN_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set temp integer to the number of connections from the stream's source address
 * in the table pointed to by expr, after updating it.
 * Accepts exactly 1 argument of type table.
 */
static int
smp_fetch_src_updt_conn_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = objt_conn(smp->sess->origin);
	struct stksess *ts;
	struct stktable_key *key;
	void *ptr;
	struct stktable *t;

	if (!conn)
		return 0;

	/* Fetch source address in a sample. */
	if (!smp_fetch_src || !smp_fetch_src(empty_arg_list, smp, "src", NULL))
		return 0;

	/* Converts into key. */
	key = smp_to_stkey(smp, args->data.t);
	if (!key)
		return 0;

	t = args->data.t;

	if ((ts = stktable_get_entry(t, key)) == NULL)
		/* entry does not exist and could not be created */
		return 0;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_CONN_CNT);
	if (!ptr) {
		return 0; /* parameter not stored in this table */
	}

	smp->data.type = SMP_T_SINT;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

	smp->data.u.sint = ++stktable_data_cast(ptr, std_t_uint);

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

	smp->flags = SMP_F_VOL_TEST;

	stktable_touch_local(t, ts, 1);

	/* Touch was previously performed by stktable_update_key */
	return 1;
}

/* set <smp> to the number of concurrent connections from the stream's tracked
 * frontend counters. Supports being called as "sc[0-9]_conn_cur" or
 * "src_conn_cur" only.
 */
static int
smp_fetch_sc_conn_cur(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_CUR);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the cumulated number of streams from the stream's tracked
 * frontend counters. Supports being called as "sc[0-9]_sess_cnt" or
 * "src_sess_cnt" only.
 */
static int
smp_fetch_sc_sess_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_CNT);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the stream rate from the stream's tracked frontend counters.
 * Supports being called as "sc[0-9]_sess_rate" or "src_sess_rate" only.
 */
static int
smp_fetch_sc_sess_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_RATE);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_SESS_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the cumulated number of HTTP requests from the stream's tracked
 * frontend counters. Supports being called as "sc[0-9]_http_req_cnt" or
 * "src_http_req_cnt" only.
 */
static int
smp_fetch_sc_http_req_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_CNT);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the HTTP request rate from the stream's tracked frontend
 * counters. Supports being called as "sc[0-9]_http_req_rate" or
 * "src_http_req_rate" only.
 */
static int
smp_fetch_sc_http_req_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_RATE);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the cumulated number of HTTP requests errors from the stream's
 * tracked frontend counters. Supports being called as "sc[0-9]_http_err_cnt" or
 * "src_http_err_cnt" only.
 */
static int
smp_fetch_sc_http_err_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_ERR_CNT);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the HTTP request error rate from the stream's tracked frontend
 * counters. Supports being called as "sc[0-9]_http_err_rate" or
 * "src_http_err_rate" only.
 */
static int
smp_fetch_sc_http_err_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_ERR_RATE);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the cumulated number of HTTP response failures from the stream's
 * tracked frontend counters. Supports being called as "sc[0-9]_http_fail_cnt" or
 * "src_http_fail_cnt" only.
 */
static int
smp_fetch_sc_http_fail_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_FAIL_CNT);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the HTTP response failure rate from the stream's tracked frontend
 * counters. Supports being called as "sc[0-9]_http_fail_rate" or
 * "src_http_fail_rate" only.
 */
static int
smp_fetch_sc_http_fail_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_FAIL_RATE);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_FAIL_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the number of kbytes received from clients, as found in the
 * stream's tracked frontend counters. Supports being called as
 * "sc[0-9]_kbytes_in" or "src_kbytes_in" only.
 */
static int
smp_fetch_sc_kbytes_in(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_IN_CNT);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_ull) >> 10;

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the data rate received from clients in bytes/s, as found
 * in the stream's tracked frontend counters. Supports being called as
 * "sc[0-9]_bytes_in_rate" or "src_bytes_in_rate" only.
 */
static int
smp_fetch_sc_bytes_in_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_IN_RATE);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_BYTES_IN_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the number of kbytes sent to clients, as found in the
 * stream's tracked frontend counters. Supports being called as
 * "sc[0-9]_kbytes_out" or "src_kbytes_out" only.
 */
static int
smp_fetch_sc_kbytes_out(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_OUT_CNT);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_ull) >> 10;

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the data rate sent to clients in bytes/s, as found in the
 * stream's tracked frontend counters. Supports being called as
 * "sc[0-9]_bytes_out_rate" or "src_bytes_out_rate" only.
 */
static int
smp_fetch_sc_bytes_out_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_OUT_RATE);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the number of active trackers on the SC entry in the stream's
 * tracked frontend counters. Supports being called as "sc[0-9]_trackers" only.
 */
static int
smp_fetch_sc_trackers(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	if (stkctr == &tmpstkctr) {
		smp->data.u.sint = stkctr_entry(stkctr) ? (stkctr_entry(stkctr)->ref_cnt-1) : 0;
		stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	else {
		smp->data.u.sint = stkctr_entry(stkctr) ? stkctr_entry(stkctr)->ref_cnt : 0;
	}

	return 1;
}


/* The functions below are used to manipulate table contents from the CLI.
 * There are 3 main actions, "clear", "set" and "show". The code is shared
 * between all actions, and the action is encoded in the void *private in
 * the appctx as well as in the keyword registration, among one of the
 * following values.
 */

enum {
	STK_CLI_ACT_CLR,
	STK_CLI_ACT_SET,
	STK_CLI_ACT_SHOW,
};

/* Dump the status of a table to a stream interface's
 * read buffer. It returns 0 if the output buffer is full
 * and needs to be called again, otherwise non-zero.
 */
static int table_dump_head_to_buffer(struct buffer *msg,
                                     struct stream_interface *si,
                                     struct stktable *t, struct stktable *target)
{
	struct stream *s = si_strm(si);

	chunk_appendf(msg, "# table: %s, type: %s, size:%d, used:%d\n",
		     t->id, stktable_types[t->type].kw, t->size, t->current);

	/* any other information should be dumped here */

	if (target && (strm_li(s)->bind_conf->level & ACCESS_LVL_MASK) < ACCESS_LVL_OPER)
		chunk_appendf(msg, "# contents not dumped due to insufficient privileges\n");

	if (ci_putchk(si_ic(si), msg) == -1) {
		si_rx_room_blk(si);
		return 0;
	}

	return 1;
}

/* Dump a table entry to a stream interface's
 * read buffer. It returns 0 if the output buffer is full
 * and needs to be called again, otherwise non-zero.
 */
static int table_dump_entry_to_buffer(struct buffer *msg,
                                      struct stream_interface *si,
                                      struct stktable *t, struct stksess *entry)
{
	int dt;

	chunk_appendf(msg, "%p:", entry);

	if (t->type == SMP_T_IPV4) {
		char addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_appendf(msg, " key=%s", addr);
	}
	else if (t->type == SMP_T_IPV6) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_appendf(msg, " key=%s", addr);
	}
	else if (t->type == SMP_T_SINT) {
		chunk_appendf(msg, " key=%u", read_u32(entry->key.key));
	}
	else if (t->type == SMP_T_STR) {
		chunk_appendf(msg, " key=");
		dump_text(msg, (const char *)entry->key.key, t->key_size);
	}
	else {
		chunk_appendf(msg, " key=");
		dump_binary(msg, (const char *)entry->key.key, t->key_size);
	}

	chunk_appendf(msg, " use=%d exp=%d", entry->ref_cnt - 1, tick_remain(now_ms, entry->expire));

	for (dt = 0; dt < STKTABLE_DATA_TYPES; dt++) {
		void *ptr;

		if (t->data_ofs[dt] == 0)
			continue;
		if (stktable_data_types[dt].is_array) {
			char tmp[16] = {};
			const char *name_pfx = stktable_data_types[dt].name;
			const char *name_sfx = NULL;
			unsigned int idx = 0;
			int i = 0;

			/* split name to show index before first _ of the name
			 * for example: 'gpc3_rate' if array name is 'gpc_rate'.
			 */
			for (i = 0 ; i < (sizeof(tmp) - 1); i++) {
				if (!name_pfx[i])
					break;
				if (name_pfx[i] == '_') {
					name_pfx = &tmp[0];
					name_sfx = &stktable_data_types[dt].name[i];
					break;
				}
				tmp[i] = name_pfx[i];
			}

			ptr = stktable_data_ptr_idx(t, entry, dt, idx);
			while (ptr) {
				if (stktable_data_types[dt].arg_type == ARG_T_DELAY)
					chunk_appendf(msg, " %s%u%s(%u)=", name_pfx, idx, name_sfx ? name_sfx : "", t->data_arg[dt].u);
				else
					chunk_appendf(msg, " %s%u%s=", name_pfx, idx, name_sfx ? name_sfx : "");
				switch (stktable_data_types[dt].std_type) {
				case STD_T_SINT:
					chunk_appendf(msg, "%d", stktable_data_cast(ptr, std_t_sint));
					break;
				case STD_T_UINT:
					chunk_appendf(msg, "%u", stktable_data_cast(ptr, std_t_uint));
					break;
				case STD_T_ULL:
					chunk_appendf(msg, "%llu", stktable_data_cast(ptr, std_t_ull));
					break;
				case STD_T_FRQP:
					chunk_appendf(msg, "%u",
						     read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
									  t->data_arg[dt].u));
					break;
				}
				ptr = stktable_data_ptr_idx(t, entry, dt, ++idx);
			}
			continue;
		}
		if (stktable_data_types[dt].arg_type == ARG_T_DELAY)
			chunk_appendf(msg, " %s(%u)=", stktable_data_types[dt].name, t->data_arg[dt].u);
		else
			chunk_appendf(msg, " %s=", stktable_data_types[dt].name);

		ptr = stktable_data_ptr(t, entry, dt);
		switch (stktable_data_types[dt].std_type) {
		case STD_T_SINT:
			chunk_appendf(msg, "%d", stktable_data_cast(ptr, std_t_sint));
			break;
		case STD_T_UINT:
			chunk_appendf(msg, "%u", stktable_data_cast(ptr, std_t_uint));
			break;
		case STD_T_ULL:
			chunk_appendf(msg, "%llu", stktable_data_cast(ptr, std_t_ull));
			break;
		case STD_T_FRQP:
			chunk_appendf(msg, "%u",
				     read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
							  t->data_arg[dt].u));
			break;
		case STD_T_DICT: {
			struct dict_entry *de;
			de = stktable_data_cast(ptr, std_t_dict);
			chunk_appendf(msg, "%s", de ? (char *)de->value.key : "-");
			break;
		}
		}
	}
	chunk_appendf(msg, "\n");

	if (ci_putchk(si_ic(si), msg) == -1) {
		si_rx_room_blk(si);
		return 0;
	}

	return 1;
}


/* Processes a single table entry matching a specific key passed in argument.
 * returns 0 if wants to be called again, 1 if has ended processing.
 */
static int table_process_entry_per_key(struct appctx *appctx, char **args)
{
	struct stream_interface *si = appctx->owner;
	struct stktable *t = appctx->ctx.table.target;
	struct stksess *ts;
	uint32_t uint32_key;
	unsigned char ip6_key[sizeof(struct in6_addr)];
	long long value;
	int data_type;
	int cur_arg;
	void *ptr;
	struct freq_ctr *frqp;

	if (!*args[4])
		return cli_err(appctx, "Key value expected\n");

	switch (t->type) {
	case SMP_T_IPV4:
		uint32_key = htonl(inetaddr_host(args[4]));
		static_table_key.key = &uint32_key;
		break;
	case SMP_T_IPV6:
		if (inet_pton(AF_INET6, args[4], ip6_key) <= 0)
			return cli_err(appctx, "Invalid key\n");
		static_table_key.key = &ip6_key;
		break;
	case SMP_T_SINT:
		{
			char *endptr;
			unsigned long val;
			errno = 0;
			val = strtoul(args[4], &endptr, 10);
			if ((errno == ERANGE && val == ULONG_MAX) ||
			    (errno != 0 && val == 0) || endptr == args[4] ||
			    val > 0xffffffff)
				return cli_err(appctx, "Invalid key\n");
			uint32_key = (uint32_t) val;
			static_table_key.key = &uint32_key;
			break;
		}
		break;
	case SMP_T_STR:
		static_table_key.key = args[4];
		static_table_key.key_len = strlen(args[4]);
		break;
	default:
		switch (appctx->ctx.table.action) {
		case STK_CLI_ACT_SHOW:
			return cli_err(appctx, "Showing keys from tables of type other than ip, ipv6, string and integer is not supported\n");
		case STK_CLI_ACT_CLR:
			return cli_err(appctx, "Removing keys from tables of type other than ip, ipv6, string and integer is not supported\n");
		case STK_CLI_ACT_SET:
			return cli_err(appctx, "Inserting keys into tables of type other than ip, ipv6, string and integer is not supported\n");
		default:
			return cli_err(appctx, "Unknown action\n");
		}
	}

	/* check permissions */
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	switch (appctx->ctx.table.action) {
	case STK_CLI_ACT_SHOW:
		ts = stktable_lookup_key(t, &static_table_key);
		if (!ts)
			return 1;
		chunk_reset(&trash);
		if (!table_dump_head_to_buffer(&trash, si, t, t)) {
			stktable_release(t, ts);
			return 0;
		}
		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ts->lock);
		if (!table_dump_entry_to_buffer(&trash, si, t, ts)) {
			HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);
			stktable_release(t, ts);
			return 0;
		}
		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);
		stktable_release(t, ts);
		break;

	case STK_CLI_ACT_CLR:
		ts = stktable_lookup_key(t, &static_table_key);
		if (!ts)
			return 1;

		if (!stksess_kill(t, ts, 1)) {
			/* don't delete an entry which is currently referenced */
			return cli_err(appctx, "Entry currently in use, cannot remove\n");
		}
		break;

	case STK_CLI_ACT_SET:
		ts = stktable_get_entry(t, &static_table_key);
		if (!ts) {
			/* don't delete an entry which is currently referenced */
			return cli_err(appctx, "Unable to allocate a new entry\n");
		}
		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
		for (cur_arg = 5; *args[cur_arg]; cur_arg += 2) {
			if (strncmp(args[cur_arg], "data.", 5) != 0) {
				cli_err(appctx, "\"data.<type>\" followed by a value expected\n");
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_local(t, ts, 1);
				return 1;
			}

			data_type = stktable_get_data_type(args[cur_arg] + 5);
			if (data_type < 0) {
				cli_err(appctx, "Unknown data type\n");
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_local(t, ts, 1);
				return 1;
			}

			if (!t->data_ofs[data_type]) {
				cli_err(appctx, "Data type not stored in this table\n");
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_local(t, ts, 1);
				return 1;
			}

			if (!*args[cur_arg+1] || strl2llrc(args[cur_arg+1], strlen(args[cur_arg+1]), &value) != 0) {
				cli_err(appctx, "Require a valid integer value to store\n");
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_local(t, ts, 1);
				return 1;
			}

			ptr = stktable_data_ptr(t, ts, data_type);

			switch (stktable_data_types[data_type].std_type) {
			case STD_T_SINT:
				stktable_data_cast(ptr, std_t_sint) = value;
				break;
			case STD_T_UINT:
				stktable_data_cast(ptr, std_t_uint) = value;
				break;
			case STD_T_ULL:
				stktable_data_cast(ptr, std_t_ull) = value;
				break;
			case STD_T_FRQP:
				/* We set both the current and previous values. That way
				 * the reported frequency is stable during all the period
				 * then slowly fades out. This allows external tools to
				 * push measures without having to update them too often.
				 */
				frqp = &stktable_data_cast(ptr, std_t_frqp);
				/* First bit is reserved for the freq_ctr lock
				   Note: here we're still protected by the stksess lock
				   so we don't need to update the update the freq_ctr
				   using its internal lock */
				frqp->curr_tick = now_ms & ~0x1;
				frqp->prev_ctr = 0;
				frqp->curr_ctr = value;
				break;
			}
		}
		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
		stktable_touch_local(t, ts, 1);
		break;

	default:
		return cli_err(appctx, "Unknown action\n");
	}
	return 1;
}

/* Prepares the appctx fields with the data-based filters from the command line.
 * Returns 0 if the dump can proceed, 1 if has ended processing.
 */
static int table_prepare_data_request(struct appctx *appctx, char **args)
{
	int i;
	char *err = NULL;

	if (appctx->ctx.table.action != STK_CLI_ACT_SHOW && appctx->ctx.table.action != STK_CLI_ACT_CLR)
		return cli_err(appctx, "content-based lookup is only supported with the \"show\" and \"clear\" actions\n");

	for (i = 0; i < STKTABLE_FILTER_LEN; i++) {
		if (i > 0 && !*args[3+3*i])  // number of filter entries can be less than STKTABLE_FILTER_LEN
			break;
		/* condition on stored data value */
		appctx->ctx.table.data_type[i] = stktable_get_data_type(args[3+3*i] + 5);
		if (appctx->ctx.table.data_type[i] < 0)
			return cli_dynerr(appctx, memprintf(&err, "Filter entry #%i: Unknown data type\n", i + 1));

		if (!((struct stktable *)appctx->ctx.table.target)->data_ofs[appctx->ctx.table.data_type[i]])
			return cli_dynerr(appctx, memprintf(&err, "Filter entry #%i: Data type not stored in this table\n", i + 1));

		appctx->ctx.table.data_op[i] = get_std_op(args[4+3*i]);
		if (appctx->ctx.table.data_op[i] < 0)
			return cli_dynerr(appctx, memprintf(&err, "Filter entry #%i: Require and operator among \"eq\", \"ne\", \"le\", \"ge\", \"lt\", \"gt\"\n", i + 1));

		if (!*args[5+3*i] || strl2llrc(args[5+3*i], strlen(args[5+3*i]), &appctx->ctx.table.value[i]) != 0)
			return cli_dynerr(appctx, memprintf(&err, "Filter entry #%i: Require a valid integer value to compare against\n", i + 1));
	}

	if (*args[3+3*i]) {
		return cli_dynerr(appctx, memprintf(&err, "Detected extra data in filter, %ith word of input, after '%s'\n", 3+3*i + 1, args[2+3*i]));
	}

	/* OK we're done, all the fields are set */
	return 0;
}

/* returns 0 if wants to be called, 1 if has ended processing */
static int cli_parse_table_req(char **args, char *payload, struct appctx *appctx, void *private)
{
	int i;

	for (i = 0; i < STKTABLE_FILTER_LEN; i++)
		appctx->ctx.table.data_type[i] = -1;
	appctx->ctx.table.target = NULL;
	appctx->ctx.table.entry = NULL;
	appctx->ctx.table.action = (long)private; // keyword argument, one of STK_CLI_ACT_*

	if (*args[2]) {
		appctx->ctx.table.target = stktable_find_by_name(args[2]);
		if (!appctx->ctx.table.target)
			return cli_err(appctx, "No such table\n");
	}
	else {
		if (appctx->ctx.table.action != STK_CLI_ACT_SHOW)
			goto err_args;
		return 0;
	}

	if (strcmp(args[3], "key") == 0)
		return table_process_entry_per_key(appctx, args);
	else if (strncmp(args[3], "data.", 5) == 0)
		return table_prepare_data_request(appctx, args);
	else if (*args[3])
		goto err_args;

	return 0;

err_args:
	switch (appctx->ctx.table.action) {
	case STK_CLI_ACT_SHOW:
		return cli_err(appctx, "Optional argument only supports \"data.<store_data_type>\" <operator> <value> and key <key>\n");
	case STK_CLI_ACT_CLR:
		return cli_err(appctx, "Required arguments: <table> \"data.<store_data_type>\" <operator> <value> or <table> key <key>\n");
	case STK_CLI_ACT_SET:
		return cli_err(appctx, "Required arguments: <table> key <key> [data.<store_data_type> <value>]*\n");
	default:
		return cli_err(appctx, "Unknown action\n");
	}
}

/* This function is used to deal with table operations (dump or clear depending
 * on the action stored in appctx->private). It returns 0 if the output buffer is
 * full and it needs to be called again, otherwise non-zero.
 */
static int cli_io_handler_table(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct ebmb_node *eb;
	int skip_entry;
	int show = appctx->ctx.table.action == STK_CLI_ACT_SHOW;

	/*
	 * We have 3 possible states in appctx->st2 :
	 *   - STAT_ST_INIT : the first call
	 *   - STAT_ST_INFO : the proxy pointer points to the next table to
	 *     dump, the entry pointer is NULL ;
	 *   - STAT_ST_LIST : the proxy pointer points to the current table
	 *     and the entry pointer points to the next entry to be dumped,
	 *     and the refcount on the next entry is held ;
	 *   - STAT_ST_END : nothing left to dump, the buffer may contain some
	 *     data though.
	 */

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW))) {
		/* in case of abort, remove any refcount we might have set on an entry */
		if (appctx->st2 == STAT_ST_LIST) {
			stksess_kill_if_expired(appctx->ctx.table.t, appctx->ctx.table.entry, 1);
		}
		return 1;
	}

	chunk_reset(&trash);

	while (appctx->st2 != STAT_ST_FIN) {
		switch (appctx->st2) {
		case STAT_ST_INIT:
			appctx->ctx.table.t = appctx->ctx.table.target;
			if (!appctx->ctx.table.t)
				appctx->ctx.table.t = stktables_list;

			appctx->ctx.table.entry = NULL;
			appctx->st2 = STAT_ST_INFO;
			break;

		case STAT_ST_INFO:
			if (!appctx->ctx.table.t ||
			    (appctx->ctx.table.target &&
			     appctx->ctx.table.t != appctx->ctx.table.target)) {
				appctx->st2 = STAT_ST_END;
				break;
			}

			if (appctx->ctx.table.t->size) {
				if (show && !table_dump_head_to_buffer(&trash, si, appctx->ctx.table.t, appctx->ctx.table.target))
					return 0;

				if (appctx->ctx.table.target &&
				    (strm_li(s)->bind_conf->level & ACCESS_LVL_MASK) >= ACCESS_LVL_OPER) {
					/* dump entries only if table explicitly requested */
					HA_SPIN_LOCK(STK_TABLE_LOCK, &appctx->ctx.table.t->lock);
					eb = ebmb_first(&appctx->ctx.table.t->keys);
					if (eb) {
						appctx->ctx.table.entry = ebmb_entry(eb, struct stksess, key);
						appctx->ctx.table.entry->ref_cnt++;
						appctx->st2 = STAT_ST_LIST;
						HA_SPIN_UNLOCK(STK_TABLE_LOCK, &appctx->ctx.table.t->lock);
						break;
					}
					HA_SPIN_UNLOCK(STK_TABLE_LOCK, &appctx->ctx.table.t->lock);
				}
			}
			appctx->ctx.table.t = appctx->ctx.table.t->next;
			break;

		case STAT_ST_LIST:
			skip_entry = 0;

			HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &appctx->ctx.table.entry->lock);

			if (appctx->ctx.table.data_type[0] >= 0) {
				/* we're filtering on some data contents */
				void *ptr;
				int dt, i;
				signed char op;
				long long data, value;


				for (i = 0; i < STKTABLE_FILTER_LEN; i++) {
					if (appctx->ctx.table.data_type[i] == -1)
						break;
					dt = appctx->ctx.table.data_type[i];
					ptr = stktable_data_ptr(appctx->ctx.table.t,
								appctx->ctx.table.entry,
								dt);

					data = 0;
					switch (stktable_data_types[dt].std_type) {
					case STD_T_SINT:
						data = stktable_data_cast(ptr, std_t_sint);
						break;
					case STD_T_UINT:
						data = stktable_data_cast(ptr, std_t_uint);
						break;
					case STD_T_ULL:
						data = stktable_data_cast(ptr, std_t_ull);
						break;
					case STD_T_FRQP:
						data = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
									    appctx->ctx.table.t->data_arg[dt].u);
						break;
					}

					op = appctx->ctx.table.data_op[i];
					value = appctx->ctx.table.value[i];

					/* skip the entry if the data does not match the test and the value */
					if ((data < value &&
					     (op == STD_OP_EQ || op == STD_OP_GT || op == STD_OP_GE)) ||
					    (data == value &&
					     (op == STD_OP_NE || op == STD_OP_GT || op == STD_OP_LT)) ||
					    (data > value &&
					     (op == STD_OP_EQ || op == STD_OP_LT || op == STD_OP_LE))) {
						skip_entry = 1;
						break;
					}
				}
			}

			if (show && !skip_entry &&
			    !table_dump_entry_to_buffer(&trash, si, appctx->ctx.table.t, appctx->ctx.table.entry)) {
				HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &appctx->ctx.table.entry->lock);
				return 0;
			}

			HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &appctx->ctx.table.entry->lock);

			HA_SPIN_LOCK(STK_TABLE_LOCK, &appctx->ctx.table.t->lock);
			appctx->ctx.table.entry->ref_cnt--;

			eb = ebmb_next(&appctx->ctx.table.entry->key);
			if (eb) {
				struct stksess *old = appctx->ctx.table.entry;
				appctx->ctx.table.entry = ebmb_entry(eb, struct stksess, key);
				if (show)
					__stksess_kill_if_expired(appctx->ctx.table.t, old);
				else if (!skip_entry && !appctx->ctx.table.entry->ref_cnt)
					__stksess_kill(appctx->ctx.table.t, old);
				appctx->ctx.table.entry->ref_cnt++;
				HA_SPIN_UNLOCK(STK_TABLE_LOCK, &appctx->ctx.table.t->lock);
				break;
			}


			if (show)
				__stksess_kill_if_expired(appctx->ctx.table.t, appctx->ctx.table.entry);
			else if (!skip_entry && !appctx->ctx.table.entry->ref_cnt)
				__stksess_kill(appctx->ctx.table.t, appctx->ctx.table.entry);

			HA_SPIN_UNLOCK(STK_TABLE_LOCK, &appctx->ctx.table.t->lock);

			appctx->ctx.table.t = appctx->ctx.table.t->next;
			appctx->st2 = STAT_ST_INFO;
			break;

		case STAT_ST_END:
			appctx->st2 = STAT_ST_FIN;
			break;
		}
	}
	return 1;
}

static void cli_release_show_table(struct appctx *appctx)
{
	if (appctx->st2 == STAT_ST_LIST) {
		stksess_kill_if_expired(appctx->ctx.table.t, appctx->ctx.table.entry, 1);
	}
}

static void stkt_late_init(void)
{
	struct sample_fetch *f;

	f = find_sample_fetch("src", strlen("src"));
	if (f)
		smp_fetch_src = f->process;
}

INITCALL0(STG_INIT, stkt_late_init);

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "clear", "table", NULL }, "clear table <table> [<filter>]*         : remove an entry from a table (filter: data/key)",                           cli_parse_table_req, cli_io_handler_table, cli_release_show_table, (void *)STK_CLI_ACT_CLR },
	{ { "set",   "table", NULL }, "set table <table> key <k> [data.* <v>]* : update or create a table entry's data",                                     cli_parse_table_req, cli_io_handler_table, NULL, (void *)STK_CLI_ACT_SET },
	{ { "show",  "table", NULL }, "show table <table> [<filter>]*          : report table usage stats or dump this table's contents (filter: data/key)", cli_parse_table_req, cli_io_handler_table, cli_release_show_table, (void *)STK_CLI_ACT_SHOW },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

static struct action_kw_list tcp_conn_kws = { { }, {
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_conn_keywords_register, &tcp_conn_kws);

static struct action_kw_list tcp_sess_kws = { { }, {
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_sess_keywords_register, &tcp_sess_kws);

static struct action_kw_list tcp_req_kws = { { }, {
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_kws);

static struct action_kw_list tcp_res_kws = { { }, {
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_kws);

static struct action_kw_list http_req_kws = { { }, {
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_kws);

static struct action_kw_list http_res_kws = { { }, {
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_kws);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_fetch_keywords = {ILH, {
	{ "sc_bytes_in_rate",   smp_fetch_sc_bytes_in_rate,  ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_bytes_out_rate",  smp_fetch_sc_bytes_out_rate, ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_clr_gpc",         smp_fetch_sc_clr_gpc,        ARG3(2,SINT,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_clr_gpc0",        smp_fetch_sc_clr_gpc0,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_clr_gpc1",        smp_fetch_sc_clr_gpc1,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN },
	{ "sc_conn_cnt",        smp_fetch_sc_conn_cnt,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_conn_cur",        smp_fetch_sc_conn_cur,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_conn_rate",       smp_fetch_sc_conn_rate,      ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_get_gpt",         smp_fetch_sc_get_gpt,        ARG3(2,SINT,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_get_gpt0",        smp_fetch_sc_get_gpt0,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_get_gpc",         smp_fetch_sc_get_gpc,        ARG3(2,SINT,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_get_gpc0",        smp_fetch_sc_get_gpc0,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_get_gpc1",        smp_fetch_sc_get_gpc1,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN },
	{ "sc_gpc_rate",        smp_fetch_sc_gpc_rate,       ARG3(2,SINT,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_gpc0_rate",       smp_fetch_sc_gpc0_rate,      ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_gpc1_rate",       smp_fetch_sc_gpc1_rate,      ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_err_cnt",    smp_fetch_sc_http_err_cnt,   ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_err_rate",   smp_fetch_sc_http_err_rate,  ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_fail_cnt",   smp_fetch_sc_http_fail_cnt,  ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_fail_rate",  smp_fetch_sc_http_fail_rate, ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_req_cnt",    smp_fetch_sc_http_req_cnt,   ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_req_rate",   smp_fetch_sc_http_req_rate,  ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_inc_gpc",         smp_fetch_sc_inc_gpc,        ARG3(2,SINT,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_inc_gpc0",        smp_fetch_sc_inc_gpc0,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_inc_gpc1",        smp_fetch_sc_inc_gpc1,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_kbytes_in",       smp_fetch_sc_kbytes_in,      ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc_kbytes_out",      smp_fetch_sc_kbytes_out,     ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc_sess_cnt",        smp_fetch_sc_sess_cnt,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_sess_rate",       smp_fetch_sc_sess_rate,      ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_tracked",         smp_fetch_sc_tracked,        ARG2(1,SINT,TAB), NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc_trackers",        smp_fetch_sc_trackers,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_clr_gpc1",       smp_fetch_sc_clr_gpc1,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_get_gpt0",       smp_fetch_sc_get_gpt0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_get_gpc1",       smp_fetch_sc_get_gpc1,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_gpc1_rate",      smp_fetch_sc_gpc1_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_fail_cnt",  smp_fetch_sc_http_fail_cnt,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_fail_rate", smp_fetch_sc_http_fail_rate, ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_inc_gpc1",       smp_fetch_sc_inc_gpc1,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc0_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc0_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_tracked",        smp_fetch_sc_tracked,        ARG1(0,TAB),      NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc0_trackers",       smp_fetch_sc_trackers,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_clr_gpc",        smp_fetch_sc_clr_gpc,        ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_clr_gpc1",       smp_fetch_sc_clr_gpc1,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_get_gpt0",       smp_fetch_sc_get_gpt0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_get_gpc1",       smp_fetch_sc_get_gpc1,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_gpc1_rate",      smp_fetch_sc_gpc1_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_fail_cnt",  smp_fetch_sc_http_fail_cnt,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_fail_rate", smp_fetch_sc_http_fail_rate, ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_inc_gpc1",       smp_fetch_sc_inc_gpc1,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc1_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc1_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_tracked",        smp_fetch_sc_tracked,        ARG1(0,TAB),      NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc1_trackers",       smp_fetch_sc_trackers,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_clr_gpc1",       smp_fetch_sc_clr_gpc1,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_get_gpt0",       smp_fetch_sc_get_gpt0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_get_gpc1",       smp_fetch_sc_get_gpc1,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_gpc1_rate",      smp_fetch_sc_gpc1_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_fail_cnt",  smp_fetch_sc_http_fail_cnt,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_fail_rate", smp_fetch_sc_http_fail_rate, ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_inc_gpc1",       smp_fetch_sc_inc_gpc1,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc2_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc2_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_tracked",        smp_fetch_sc_tracked,        ARG1(0,TAB),      NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc2_trackers",       smp_fetch_sc_trackers,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "src_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_clr_gpc",        smp_fetch_sc_clr_gpc,        ARG2(2,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_clr_gpc1",       smp_fetch_sc_clr_gpc1,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_get_gpt" ,       smp_fetch_sc_get_gpt,        ARG2(2,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_get_gpt0",       smp_fetch_sc_get_gpt0,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_get_gpc",        smp_fetch_sc_get_gpc,        ARG2(2,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_get_gpc1",       smp_fetch_sc_get_gpc1,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_gpc_rate",       smp_fetch_sc_gpc_rate,       ARG2(2,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_gpc1_rate",      smp_fetch_sc_gpc1_rate,      ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_fail_cnt",  smp_fetch_sc_http_fail_cnt,  ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_fail_rate", smp_fetch_sc_http_fail_rate, ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_inc_gpc",        smp_fetch_sc_inc_gpc,        ARG2(2,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_inc_gpc1",       smp_fetch_sc_inc_gpc1,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_updt_conn_cnt",  smp_fetch_src_updt_conn_cnt, ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "table_avl",          smp_fetch_table_avl,         ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "table_cnt",          smp_fetch_table_cnt,         ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_fetch_keywords);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "in_table",             sample_conv_in_table,             ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_BOOL  },
	{ "table_bytes_in_rate",  sample_conv_table_bytes_in_rate,  ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_bytes_out_rate", sample_conv_table_bytes_out_rate, ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_conn_cnt",       sample_conv_table_conn_cnt,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_conn_cur",       sample_conv_table_conn_cur,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_conn_rate",      sample_conv_table_conn_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpt",            sample_conv_table_gpt,            ARG2(2,SINT,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpt0",           sample_conv_table_gpt0,           ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc",            sample_conv_table_gpc,            ARG2(2,SINT,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc0",           sample_conv_table_gpc0,           ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc1",           sample_conv_table_gpc1,           ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc_rate",       sample_conv_table_gpc_rate,       ARG2(2,SINT,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc0_rate",      sample_conv_table_gpc0_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc1_rate",      sample_conv_table_gpc1_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_err_cnt",   sample_conv_table_http_err_cnt,   ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_err_rate",  sample_conv_table_http_err_rate,  ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_fail_cnt",  sample_conv_table_http_fail_cnt,  ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_fail_rate", sample_conv_table_http_fail_rate, ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_req_cnt",   sample_conv_table_http_req_cnt,   ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_req_rate",  sample_conv_table_http_req_rate,  ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_kbytes_in",      sample_conv_table_kbytes_in,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_kbytes_out",     sample_conv_table_kbytes_out,     ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_server_id",      sample_conv_table_server_id,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_sess_cnt",       sample_conv_table_sess_cnt,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_sess_rate",      sample_conv_table_sess_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_trackers",       sample_conv_table_trackers,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);
