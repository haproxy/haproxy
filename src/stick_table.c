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

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>

#include <ebmbtree.h>
#include <ebsttree.h>

#include <types/cli.h>
#include <types/global.h>
#include <types/stats.h>

#include <proto/arg.h>
#include <proto/cli.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/stick_table.h>
#include <proto/task.h>
#include <proto/peers.h>
#include <proto/tcp_rules.h>

/* structure used to return a table key built from a sample */
static THREAD_LOCAL struct stktable_key static_table_key;

/*
 * Free an allocated sticky session <ts>, and decrease sticky sessions counter
 * in table <t>.
 */
void __stksess_free(struct stktable *t, struct stksess *ts)
{
	t->current--;
	pool_free(t->pool, (void *)ts - t->data_size);
}

/*
 * Free an allocated sticky session <ts>, and decrease sticky sessions counter
 * in table <t>.
 * This function locks the table
 */
void stksess_free(struct stktable *t, struct stksess *ts)
{
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
 * Returns number of trashed sticky sessions.
 */
int __stktable_trash_oldest(struct stktable *t, int to_batch)
{
	struct stksess *ts;
	struct eb32_node *eb;
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
		ts = (void *)ts + t->data_size;
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
/* Just decrease the ref_cnt of the current session */
void stktable_release(struct stktable *t, struct stksess *ts)
{
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
static struct task *process_table_expire(struct task *task)
{
	struct stktable *t = task->context;

	task->expire = stktable_trash_expired(t);
	return task;
}

/* Perform minimal stick table intializations, report 0 in case of error, 1 if OK. */
int stktable_init(struct stktable *t)
{
	if (t->size) {
		t->keys = EB_ROOT_UNIQUE;
		memset(&t->exps, 0, sizeof(t->exps));
		t->updates = EB_ROOT_UNIQUE;
		HA_SPIN_INIT(&t->lock);

		t->pool = create_pool("sticktables", sizeof(struct stksess) + t->data_size + t->key_size, MEM_F_SHARED);

		t->exp_next = TICK_ETERNITY;
		if ( t->expire ) {
			t->exp_task = task_new(MAX_THREADS_MASK);
			t->exp_task->process = process_table_expire;
			t->exp_task->context = (void *)t;
		}
		if (t->peers.p && t->peers.p->peers_fe && t->peers.p->peers_fe->state != PR_STSTOPPED) {
			peers_register_table(t->peers.p, t);
		}

		return t->pool != NULL;
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
		*(unsigned int *)&smp->data.u.sint = (unsigned int)smp->data.u.sint;
		static_table_key.key = &smp->data.u.sint;
		static_table_key.key_len = 4;
		break;

	case SMP_T_STR:
		if (!smp_make_safe(smp))
			return NULL;
		static_table_key.key = smp->data.u.str.str;
		static_table_key.key_len = smp->data.u.str.len;
		break;

	case SMP_T_BIN:
		if (smp->data.u.str.len < t->key_size) {
			/* This type needs padding with 0. */
			if (!smp_make_rw(smp))
				return NULL;

			if (smp->data.u.str.size < t->key_size)
				if (!smp_dup(smp))
					return NULL;
			if (smp->data.u.str.size < t->key_size)
				return NULL;
			memset(smp->data.u.str.str + smp->data.u.str.len, 0,
			       t->key_size - smp->data.u.str.len);
			smp->data.u.str.len = t->key_size;
		}
		static_table_key.key = smp->data.u.str.str;
		static_table_key.key_len = smp->data.u.str.len;
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
	[STKTABLE_DT_CONN_CUR]      = { .name = "conn_cur",       .std_type = STD_T_UINT  },
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

	t = &arg_p[0].data.prx->table;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = !!ts;
	smp->flags = SMP_F_VOL_TEST;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, bytes_in_rate),
					       t->data_arg[STKTABLE_DT_BYTES_IN_RATE].u);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, conn_cnt);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, conn_cur);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, conn_rate),
					       t->data_arg[STKTABLE_DT_CONN_RATE].u);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, bytes_out_rate),
					       t->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, gpt0);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, gpc0);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, gpc0_rate),
	                                      t->data_arg[STKTABLE_DT_GPC0_RATE].u);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, http_err_cnt);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, http_err_rate),
					       t->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, http_req_cnt);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
					       t->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, bytes_in_cnt) >> 10;
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, bytes_out_cnt) >> 10;
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, server_id);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = stktable_data_cast(ptr, sess_cnt);
	return 1;
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

	t = &arg_p[0].data.prx->table;

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
	if (!ptr)
		return 0; /* parameter not stored */

	smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, sess_rate),
					       t->data_arg[STKTABLE_DT_SESS_RATE].u);
	return 1;
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

	t = &arg_p[0].data.prx->table;

	key = smp_to_stkey(smp, t);
	if (!key)
		return 0;

	ts = stktable_lookup_key(t, key);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (ts)
		smp->data.u.sint = ts->ref_cnt;

	return 1;
}

/* Always returns 1. */
static enum act_return action_inc_gpc0(struct act_rule *rule, struct proxy *px,
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

		/* First, update gpc0_rate if it's tracked. Second, update its gpc0 if tracked. */
		ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GPC0_RATE);
		ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GPC0);
		if (ptr1 || ptr2) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

			if (ptr1)
				update_freq_ctr_period(&stktable_data_cast(ptr1, gpc0_rate),
					       stkctr->table->data_arg[STKTABLE_DT_GPC0_RATE].u, 1);

			if (ptr2)
				stktable_data_cast(ptr2, gpc0)++;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, ts, 0);
		}
	}
	return ACT_RET_CONT;
}

/* This function is a common parser for using variables. It understands
 * the formats:
 *
 *   sc-inc-gpc0(<stick-table ID>)
 *
 * It returns 0 if fails and <err> is filled with an error message. Otherwise,
 * it returns 1 and the variable <expr> is filled with the pointer to the
 * expression to execute.
 */
static enum act_parse_ret parse_inc_gpc0(const char **args, int *arg, struct proxy *px,
                                         struct act_rule *rule, char **err)
{
	const char *cmd_name = args[*arg-1];
	char *error;

	cmd_name += strlen("sc-inc-gpc0");
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

		if (rule->arg.gpc.sc >= ACT_ACTION_TRK_SCMAX) {
			memprintf(err, "invalid stick table track ID. The max allowed ID is %d",
			          ACT_ACTION_TRK_SCMAX-1);
			return ACT_RET_PRS_ERR;
		}
	}
	rule->action = ACT_CUSTOM;
	rule->action_ptr = action_inc_gpc0;
	return ACT_RET_PRS_OK;
}

/* Always returns 1. */
static enum act_return action_set_gpt0(struct act_rule *rule, struct proxy *px,
                                       struct session *sess, struct stream *s, int flags)
{
	void *ptr;
	struct stksess *ts;
	struct stkctr *stkctr;

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
	if (ptr) {
		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

		stktable_data_cast(ptr, gpt0) = rule->arg.gpt.value;

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

		stktable_touch_local(stkctr->table, ts, 0);
	}

	return ACT_RET_CONT;
}

/* This function is a common parser for using variables. It understands
 * the format:
 *
 *   set-gpt0(<stick-table ID>) <expression>
 *
 * It returns 0 if fails and <err> is filled with an error message. Otherwise,
 * it returns 1 and the variable <expr> is filled with the pointer to the
 * expression to execute.
 */
static enum act_parse_ret parse_set_gpt0(const char **args, int *arg, struct proxy *px,
                                         struct act_rule *rule, char **err)


{
	const char *cmd_name = args[*arg-1];
	char *error;

	cmd_name += strlen("sc-set-gpt0");
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

		if (rule->arg.gpt.sc >= ACT_ACTION_TRK_SCMAX) {
			memprintf(err, "invalid stick table track ID '%s'. The max allowed ID is %d",
			          args[*arg-1], ACT_ACTION_TRK_SCMAX-1);
			return ACT_RET_PRS_ERR;
		}
	}

	rule->arg.gpt.value = strtol(args[*arg], &error, 10);
	if (*error != '\0') {
		memprintf(err, "invalid integer value '%s'", args[*arg]);
		return ACT_RET_PRS_ERR;
	}
	(*arg)++;

	rule->action = ACT_CUSTOM;
	rule->action_ptr = action_set_gpt0;

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
	smp->data.u.sint = args->data.prx->table.current;
	return 1;
}

/* set temp integer to the number of free entries in the table pointed to by expr.
 * Accepts exactly 1 argument of type table.
 */
static int
smp_fetch_table_avl(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct proxy *px;

	px = args->data.prx;
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = px->table.size - px->table.current;
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
 * to be able to convery multiple values per key (eg: have gpc0 from
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
		if (num >= MAX_SESS_STKCTR)
			return NULL;
	}
	else if (num > 9) { /* src_* variant, args[0] = table */
		struct stktable_key *key;
		struct connection *conn = objt_conn(sess->origin);
		struct sample smp;

		if (!conn)
			return NULL;

		/* Fetch source adress in a sample. */
		smp.px = NULL;
		smp.sess = sess;
		smp.strm = strm;
		if (!smp_fetch_src(NULL, &smp, NULL, NULL))
			return NULL;

		/* Converts into key. */
		key = smp_to_stkey(&smp, &args->data.prx->table);
		if (!key)
			return NULL;

		stkctr->table = &args->data.prx->table;
		stkctr_set_entry(stkctr, stktable_lookup_key(stkctr->table, key));
		return stkctr;
	}

	/* Here, <num> contains the counter number from 0 to 9 for
	 * the sc[0-9]_ form, or even higher using sc_(num) if needed.
	 * args[arg] is the first optional argument. We first lookup the
	 * ctr form the stream, then from the session if it was not there.
	 */

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
		stkctr->table = &args[arg].data.prx->table;
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

	/* Fetch source adress in a sample. */
	smp.px = NULL;
	smp.sess = sess;
	smp.strm = strm;
	if (!smp_fetch_src(NULL, &smp, NULL, NULL))
		return NULL;

	/* Converts into key. */
	key = smp_to_stkey(&smp, &args->data.prx->table);
	if (!key)
		return NULL;

	stkctr->table = &args->data.prx->table;
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
	if ((stkctr == &tmpstkctr) &&  stkctr_entry(stkctr))
		stktable_release(stkctr->table, stkctr_entry(stkctr));

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
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, gpt0);

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
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, gpc0);

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

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0_RATE);
		if (!ptr) {
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, gpc0_rate),
		                  stkctr->table->data_arg[STKTABLE_DT_GPC0_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (stkctr == &tmpstkctr)
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
		ptr2 = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0);
		if (ptr1 || ptr2) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

			if (ptr1) {
				update_freq_ctr_period(&stktable_data_cast(ptr1, gpc0_rate),
						       stkctr->table->data_arg[STKTABLE_DT_GPC0_RATE].u, 1);
				smp->data.u.sint = (&stktable_data_cast(ptr1, gpc0_rate))->curr_ctr;
			}

			if (ptr2)
				smp->data.u.sint = ++stktable_data_cast(ptr2, gpc0);

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(stkctr->table, stkctr_entry(stkctr), (stkctr == &tmpstkctr) ? 1 : 0);
		}
		else if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
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
			if (stkctr == &tmpstkctr)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, gpc0);
		stktable_data_cast(ptr, gpc0) = 0;

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

		smp->data.u.sint = stktable_data_cast(ptr, conn_cnt);

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

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, conn_rate),
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
	struct proxy *px;

	if (!conn)
		return 0;

	/* Fetch source adress in a sample. */
	if (!smp_fetch_src(NULL, smp, NULL, NULL))
		return 0;

	/* Converts into key. */
	key = smp_to_stkey(smp, &args->data.prx->table);
	if (!key)
		return 0;

	px = args->data.prx;

	if ((ts = stktable_get_entry(&px->table, key)) == NULL)
		/* entry does not exist and could not be created */
		return 0;

	ptr = stktable_data_ptr(&px->table, ts, STKTABLE_DT_CONN_CNT);
	if (!ptr) {
		return 0; /* parameter not stored in this table */
	}

	smp->data.type = SMP_T_SINT;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

	smp->data.u.sint = ++stktable_data_cast(ptr, conn_cnt);

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

	smp->flags = SMP_F_VOL_TEST;

	stktable_touch_local(&px->table, ts, 1);

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

		smp->data.u.sint = stktable_data_cast(ptr, conn_cur);

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

		smp->data.u.sint = stktable_data_cast(ptr, sess_cnt);

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

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, sess_rate),
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

		smp->data.u.sint = stktable_data_cast(ptr, http_req_cnt);

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

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
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

		smp->data.u.sint = stktable_data_cast(ptr, http_err_cnt);

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

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, http_err_rate),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u);

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

		smp->data.u.sint = stktable_data_cast(ptr, bytes_in_cnt) >> 10;

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

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, bytes_in_rate),
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

		smp->data.u.sint = stktable_data_cast(ptr, bytes_out_cnt) >> 10;

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

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, bytes_out_rate),
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
static int table_dump_head_to_buffer(struct chunk *msg, struct stream_interface *si,
                                     struct proxy *proxy, struct proxy *target)
{
	struct stream *s = si_strm(si);

	chunk_appendf(msg, "# table: %s, type: %s, size:%d, used:%d\n",
		     proxy->id, stktable_types[proxy->table.type].kw, proxy->table.size, proxy->table.current);

	/* any other information should be dumped here */

	if (target && (strm_li(s)->bind_conf->level & ACCESS_LVL_MASK) < ACCESS_LVL_OPER)
		chunk_appendf(msg, "# contents not dumped due to insufficient privileges\n");

	if (ci_putchk(si_ic(si), msg) == -1) {
		si_applet_cant_put(si);
		return 0;
	}

	return 1;
}

/* Dump a table entry to a stream interface's
 * read buffer. It returns 0 if the output buffer is full
 * and needs to be called again, otherwise non-zero.
 */
static int table_dump_entry_to_buffer(struct chunk *msg, struct stream_interface *si,
                                      struct proxy *proxy, struct stksess *entry)
{
	int dt;

	chunk_appendf(msg, "%p:", entry);

	if (proxy->table.type == SMP_T_IPV4) {
		char addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_appendf(msg, " key=%s", addr);
	}
	else if (proxy->table.type == SMP_T_IPV6) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, (const void *)&entry->key.key, addr, sizeof(addr));
		chunk_appendf(msg, " key=%s", addr);
	}
	else if (proxy->table.type == SMP_T_SINT) {
		chunk_appendf(msg, " key=%u", *(unsigned int *)entry->key.key);
	}
	else if (proxy->table.type == SMP_T_STR) {
		chunk_appendf(msg, " key=");
		dump_text(msg, (const char *)entry->key.key, proxy->table.key_size);
	}
	else {
		chunk_appendf(msg, " key=");
		dump_binary(msg, (const char *)entry->key.key, proxy->table.key_size);
	}

	chunk_appendf(msg, " use=%d exp=%d", entry->ref_cnt - 1, tick_remain(now_ms, entry->expire));

	for (dt = 0; dt < STKTABLE_DATA_TYPES; dt++) {
		void *ptr;

		if (proxy->table.data_ofs[dt] == 0)
			continue;
		if (stktable_data_types[dt].arg_type == ARG_T_DELAY)
			chunk_appendf(msg, " %s(%d)=", stktable_data_types[dt].name, proxy->table.data_arg[dt].u);
		else
			chunk_appendf(msg, " %s=", stktable_data_types[dt].name);

		ptr = stktable_data_ptr(&proxy->table, entry, dt);
		switch (stktable_data_types[dt].std_type) {
		case STD_T_SINT:
			chunk_appendf(msg, "%d", stktable_data_cast(ptr, std_t_sint));
			break;
		case STD_T_UINT:
			chunk_appendf(msg, "%u", stktable_data_cast(ptr, std_t_uint));
			break;
		case STD_T_ULL:
			chunk_appendf(msg, "%lld", stktable_data_cast(ptr, std_t_ull));
			break;
		case STD_T_FRQP:
			chunk_appendf(msg, "%d",
				     read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
							  proxy->table.data_arg[dt].u));
			break;
		}
	}
	chunk_appendf(msg, "\n");

	if (ci_putchk(si_ic(si), msg) == -1) {
		si_applet_cant_put(si);
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
	struct proxy *px = appctx->ctx.table.target;
	struct stksess *ts;
	uint32_t uint32_key;
	unsigned char ip6_key[sizeof(struct in6_addr)];
	long long value;
	int data_type;
	int cur_arg;
	void *ptr;
	struct freq_ctr_period *frqp;

	if (!*args[4]) {
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Key value expected\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	switch (px->table.type) {
	case SMP_T_IPV4:
		uint32_key = htonl(inetaddr_host(args[4]));
		static_table_key.key = &uint32_key;
		break;
	case SMP_T_IPV6:
		inet_pton(AF_INET6, args[4], ip6_key);
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
			    val > 0xffffffff) {
				appctx->ctx.cli.severity = LOG_ERR;
				appctx->ctx.cli.msg = "Invalid key\n";
				appctx->st0 = CLI_ST_PRINT;
				return 1;
			}
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
			appctx->ctx.cli.severity = LOG_ERR;
			appctx->ctx.cli.msg = "Showing keys from tables of type other than ip, ipv6, string and integer is not supported\n";
			break;
		case STK_CLI_ACT_CLR:
			appctx->ctx.cli.severity = LOG_ERR;
			appctx->ctx.cli.msg = "Removing keys from tables of type other than ip, ipv6, string and integer is not supported\n";
			break;
		case STK_CLI_ACT_SET:
			appctx->ctx.cli.severity = LOG_ERR;
			appctx->ctx.cli.msg = "Inserting keys into tables of type other than ip, ipv6, string and integer is not supported\n";
			break;
		default:
			appctx->ctx.cli.severity = LOG_ERR;
			appctx->ctx.cli.msg = "Unknown action\n";
			break;
		}
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	/* check permissions */
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	switch (appctx->ctx.table.action) {
	case STK_CLI_ACT_SHOW:
		ts = stktable_lookup_key(&px->table, &static_table_key);
		if (!ts)
			return 1;
		chunk_reset(&trash);
		if (!table_dump_head_to_buffer(&trash, si, px, px)) {
			stktable_release(&px->table, ts);
			return 0;
		}
		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ts->lock);
		if (!table_dump_entry_to_buffer(&trash, si, px, ts)) {
			HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);
			stktable_release(&px->table, ts);
			return 0;
		}
		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);
		stktable_release(&px->table, ts);
		break;

	case STK_CLI_ACT_CLR:
		ts = stktable_lookup_key(&px->table, &static_table_key);
		if (!ts)
			return 1;

		if (!stksess_kill(&px->table, ts, 1)) {
			/* don't delete an entry which is currently referenced */
			appctx->ctx.cli.severity = LOG_ERR;
			appctx->ctx.cli.msg = "Entry currently in use, cannot remove\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}

		break;

	case STK_CLI_ACT_SET:
		ts = stktable_get_entry(&px->table, &static_table_key);
		if (!ts) {
			/* don't delete an entry which is currently referenced */
			appctx->ctx.cli.severity = LOG_ERR;
			appctx->ctx.cli.msg = "Unable to allocate a new entry\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
		for (cur_arg = 5; *args[cur_arg]; cur_arg += 2) {
			if (strncmp(args[cur_arg], "data.", 5) != 0) {
				appctx->ctx.cli.severity = LOG_ERR;
				appctx->ctx.cli.msg = "\"data.<type>\" followed by a value expected\n";
				appctx->st0 = CLI_ST_PRINT;
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_local(&px->table, ts, 1);
				return 1;
			}

			data_type = stktable_get_data_type(args[cur_arg] + 5);
			if (data_type < 0) {
				appctx->ctx.cli.severity = LOG_ERR;
				appctx->ctx.cli.msg = "Unknown data type\n";
				appctx->st0 = CLI_ST_PRINT;
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_local(&px->table, ts, 1);
				return 1;
			}

			if (!px->table.data_ofs[data_type]) {
				appctx->ctx.cli.severity = LOG_ERR;
				appctx->ctx.cli.msg = "Data type not stored in this table\n";
				appctx->st0 = CLI_ST_PRINT;
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_local(&px->table, ts, 1);
				return 1;
			}

			if (!*args[cur_arg+1] || strl2llrc(args[cur_arg+1], strlen(args[cur_arg+1]), &value) != 0) {
				appctx->ctx.cli.severity = LOG_ERR;
				appctx->ctx.cli.msg = "Require a valid integer value to store\n";
				appctx->st0 = CLI_ST_PRINT;
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_local(&px->table, ts, 1);
				return 1;
			}

			ptr = stktable_data_ptr(&px->table, ts, data_type);

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
				/* First bit is reserved for the freq_ctr_period lock
				   Note: here we're still protected by the stksess lock
				   so we don't need to update the update the freq_ctr_period
				   using its internal lock */
				frqp->curr_tick = now_ms & ~0x1;
				frqp->prev_ctr = 0;
				frqp->curr_ctr = value;
				break;
			}
		}
		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
		stktable_touch_local(&px->table, ts, 1);
		break;

	default:
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Unknown action\n";
		appctx->st0 = CLI_ST_PRINT;
		break;
	}
	return 1;
}

/* Prepares the appctx fields with the data-based filters from the command line.
 * Returns 0 if the dump can proceed, 1 if has ended processing.
 */
static int table_prepare_data_request(struct appctx *appctx, char **args)
{
	if (appctx->ctx.table.action != STK_CLI_ACT_SHOW && appctx->ctx.table.action != STK_CLI_ACT_CLR) {
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "content-based lookup is only supported with the \"show\" and \"clear\" actions";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	/* condition on stored data value */
	appctx->ctx.table.data_type = stktable_get_data_type(args[3] + 5);
	if (appctx->ctx.table.data_type < 0) {
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Unknown data type\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	if (!((struct proxy *)appctx->ctx.table.target)->table.data_ofs[appctx->ctx.table.data_type]) {
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Data type not stored in this table\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	appctx->ctx.table.data_op = get_std_op(args[4]);
	if (appctx->ctx.table.data_op < 0) {
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Require and operator among \"eq\", \"ne\", \"le\", \"ge\", \"lt\", \"gt\"\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	if (!*args[5] || strl2llrc(args[5], strlen(args[5]), &appctx->ctx.table.value) != 0) {
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Require a valid integer value to compare against\n";
		appctx->st0 = CLI_ST_PRINT;
		return 1;
	}

	/* OK we're done, all the fields are set */
	return 0;
}

/* returns 0 if wants to be called, 1 if has ended processing */
static int cli_parse_table_req(char **args, struct appctx *appctx, void *private)
{
	appctx->ctx.table.data_type = -1;
	appctx->ctx.table.target = NULL;
	appctx->ctx.table.proxy = NULL;
	appctx->ctx.table.entry = NULL;
	appctx->ctx.table.action = (long)private; // keyword argument, one of STK_CLI_ACT_*

	if (*args[2]) {
		appctx->ctx.table.target = proxy_tbl_by_name(args[2]);
		if (!appctx->ctx.table.target) {
			appctx->ctx.cli.severity = LOG_ERR;
			appctx->ctx.cli.msg = "No such table\n";
			appctx->st0 = CLI_ST_PRINT;
			return 1;
		}
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
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Optional argument only supports \"data.<store_data_type>\" <operator> <value> and key <key>\n";
		break;
	case STK_CLI_ACT_CLR:
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Required arguments: <table> \"data.<store_data_type>\" <operator> <value> or <table> key <key>\n";
		break;
	case STK_CLI_ACT_SET:
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Required arguments: <table> key <key> [data.<store_data_type> <value>]*\n";
		break;
	default:
		appctx->ctx.cli.severity = LOG_ERR;
		appctx->ctx.cli.msg = "Unknown action\n";
		break;
	}
	appctx->st0 = CLI_ST_PRINT;
	return 1;
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
	int dt;
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
			stksess_kill_if_expired(&appctx->ctx.table.proxy->table, appctx->ctx.table.entry, 1);
		}
		return 1;
	}

	chunk_reset(&trash);

	while (appctx->st2 != STAT_ST_FIN) {
		switch (appctx->st2) {
		case STAT_ST_INIT:
			appctx->ctx.table.proxy = appctx->ctx.table.target;
			if (!appctx->ctx.table.proxy)
				appctx->ctx.table.proxy = proxies_list;

			appctx->ctx.table.entry = NULL;
			appctx->st2 = STAT_ST_INFO;
			break;

		case STAT_ST_INFO:
			if (!appctx->ctx.table.proxy ||
			    (appctx->ctx.table.target &&
			     appctx->ctx.table.proxy != appctx->ctx.table.target)) {
				appctx->st2 = STAT_ST_END;
				break;
			}

			if (appctx->ctx.table.proxy->table.size) {
				if (show && !table_dump_head_to_buffer(&trash, si, appctx->ctx.table.proxy, appctx->ctx.table.target))
					return 0;

				if (appctx->ctx.table.target &&
				    (strm_li(s)->bind_conf->level & ACCESS_LVL_MASK) >= ACCESS_LVL_OPER) {
					/* dump entries only if table explicitly requested */
					HA_SPIN_LOCK(STK_TABLE_LOCK, &appctx->ctx.table.proxy->table.lock);
					eb = ebmb_first(&appctx->ctx.table.proxy->table.keys);
					if (eb) {
						appctx->ctx.table.entry = ebmb_entry(eb, struct stksess, key);
						appctx->ctx.table.entry->ref_cnt++;
						appctx->st2 = STAT_ST_LIST;
						HA_SPIN_UNLOCK(STK_TABLE_LOCK, &appctx->ctx.table.proxy->table.lock);
						break;
					}
					HA_SPIN_UNLOCK(STK_TABLE_LOCK, &appctx->ctx.table.proxy->table.lock);
				}
			}
			appctx->ctx.table.proxy = appctx->ctx.table.proxy->next;
			break;

		case STAT_ST_LIST:
			skip_entry = 0;

			HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &appctx->ctx.table.entry->lock);

			if (appctx->ctx.table.data_type >= 0) {
				/* we're filtering on some data contents */
				void *ptr;
				long long data;


				dt = appctx->ctx.table.data_type;
				ptr = stktable_data_ptr(&appctx->ctx.table.proxy->table,
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
								    appctx->ctx.table.proxy->table.data_arg[dt].u);
					break;
				}

				/* skip the entry if the data does not match the test and the value */
				if ((data < appctx->ctx.table.value &&
				     (appctx->ctx.table.data_op == STD_OP_EQ ||
				      appctx->ctx.table.data_op == STD_OP_GT ||
				      appctx->ctx.table.data_op == STD_OP_GE)) ||
				    (data == appctx->ctx.table.value &&
				     (appctx->ctx.table.data_op == STD_OP_NE ||
				      appctx->ctx.table.data_op == STD_OP_GT ||
				      appctx->ctx.table.data_op == STD_OP_LT)) ||
				    (data > appctx->ctx.table.value &&
				     (appctx->ctx.table.data_op == STD_OP_EQ ||
				      appctx->ctx.table.data_op == STD_OP_LT ||
				      appctx->ctx.table.data_op == STD_OP_LE)))
					skip_entry = 1;
			}

			if (show && !skip_entry &&
			    !table_dump_entry_to_buffer(&trash, si, appctx->ctx.table.proxy, appctx->ctx.table.entry)) {
				HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &appctx->ctx.table.entry->lock);
				return 0;
			}

			HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &appctx->ctx.table.entry->lock);

			HA_SPIN_LOCK(STK_TABLE_LOCK, &appctx->ctx.table.proxy->table.lock);
			appctx->ctx.table.entry->ref_cnt--;

			eb = ebmb_next(&appctx->ctx.table.entry->key);
			if (eb) {
				struct stksess *old = appctx->ctx.table.entry;
				appctx->ctx.table.entry = ebmb_entry(eb, struct stksess, key);
				if (show)
					__stksess_kill_if_expired(&appctx->ctx.table.proxy->table, old);
				else if (!skip_entry && !appctx->ctx.table.entry->ref_cnt)
					__stksess_kill(&appctx->ctx.table.proxy->table, old);
				appctx->ctx.table.entry->ref_cnt++;
				HA_SPIN_UNLOCK(STK_TABLE_LOCK, &appctx->ctx.table.proxy->table.lock);
				break;
			}


			if (show)
				__stksess_kill_if_expired(&appctx->ctx.table.proxy->table, appctx->ctx.table.entry);
			else if (!skip_entry && !appctx->ctx.table.entry->ref_cnt)
				__stksess_kill(&appctx->ctx.table.proxy->table, appctx->ctx.table.entry);

			HA_SPIN_UNLOCK(STK_TABLE_LOCK, &appctx->ctx.table.proxy->table.lock);

			appctx->ctx.table.proxy = appctx->ctx.table.proxy->next;
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
		stksess_kill_if_expired(&appctx->ctx.table.proxy->table, appctx->ctx.table.entry, 1);
	}
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "clear", "table", NULL }, "clear table    : remove an entry from a table", cli_parse_table_req, cli_io_handler_table, cli_release_show_table, (void *)STK_CLI_ACT_CLR },
	{ { "set",   "table", NULL }, "set table [id] : update or create a table entry's data", cli_parse_table_req, cli_io_handler_table, NULL, (void *)STK_CLI_ACT_SET },
	{ { "show",  "table", NULL }, "show table [id]: report table usage stats or dump this table's contents", cli_parse_table_req, cli_io_handler_table, cli_release_show_table, (void *)STK_CLI_ACT_SHOW },
	{{},}
}};


static struct action_kw_list tcp_conn_kws = { { }, {
	{ "sc-inc-gpc0", parse_inc_gpc0, 1 },
	{ "sc-set-gpt0", parse_set_gpt0, 1 },
	{ /* END */ }
}};

static struct action_kw_list tcp_sess_kws = { { }, {
	{ "sc-inc-gpc0", parse_inc_gpc0, 1 },
	{ "sc-set-gpt0", parse_set_gpt0, 1 },
	{ /* END */ }
}};

static struct action_kw_list tcp_req_kws = { { }, {
	{ "sc-inc-gpc0", parse_inc_gpc0, 1 },
	{ "sc-set-gpt0", parse_set_gpt0, 1 },
	{ /* END */ }
}};

static struct action_kw_list tcp_res_kws = { { }, {
	{ "sc-inc-gpc0", parse_inc_gpc0, 1 },
	{ "sc-set-gpt0", parse_set_gpt0, 1 },
	{ /* END */ }
}};

static struct action_kw_list http_req_kws = { { }, {
	{ "sc-inc-gpc0", parse_inc_gpc0, 1 },
	{ "sc-set-gpt0", parse_set_gpt0, 1 },
	{ /* END */ }
}};

static struct action_kw_list http_res_kws = { { }, {
	{ "sc-inc-gpc0", parse_inc_gpc0, 1 },
	{ "sc-set-gpt0", parse_set_gpt0, 1 },
	{ /* END */ }
}};

///* Note: must not be declared <const> as its list will be overwritten.
// * Please take care of keeping this list alphabetically sorted.
// */
//static struct sample_fetch_kw_list smp_fetch_keywords = {ILH, {
//	{ "table_avl",          smp_fetch_table_avl,         ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
//	{ "table_cnt",          smp_fetch_table_cnt,         ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
//	{ /* END */ },
//}};
/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list smp_fetch_keywords = {ILH, {
	{ "sc_bytes_in_rate",   smp_fetch_sc_bytes_in_rate,  ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_bytes_out_rate",  smp_fetch_sc_bytes_out_rate, ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_clr_gpc0",        smp_fetch_sc_clr_gpc0,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_conn_cnt",        smp_fetch_sc_conn_cnt,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_conn_cur",        smp_fetch_sc_conn_cur,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_conn_rate",       smp_fetch_sc_conn_rate,      ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_get_gpt0",        smp_fetch_sc_get_gpt0,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_get_gpc0",        smp_fetch_sc_get_gpc0,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_gpc0_rate",       smp_fetch_sc_gpc0_rate,      ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_err_cnt",    smp_fetch_sc_http_err_cnt,   ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_err_rate",   smp_fetch_sc_http_err_rate,  ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_req_cnt",    smp_fetch_sc_http_req_cnt,   ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_http_req_rate",   smp_fetch_sc_http_req_rate,  ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_inc_gpc0",        smp_fetch_sc_inc_gpc0,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_kbytes_in",       smp_fetch_sc_kbytes_in,      ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc_kbytes_out",      smp_fetch_sc_kbytes_out,     ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc_sess_cnt",        smp_fetch_sc_sess_cnt,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_sess_rate",       smp_fetch_sc_sess_rate,      ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_tracked",         smp_fetch_sc_tracked,        ARG2(1,SINT,TAB), NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc_trackers",        smp_fetch_sc_trackers,       ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_get_gpt0",       smp_fetch_sc_get_gpt0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc0_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc0_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_tracked",        smp_fetch_sc_tracked,        ARG1(0,TAB),      NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc0_trackers",       smp_fetch_sc_trackers,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_get_gpt0",       smp_fetch_sc_get_gpt0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc1_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc1_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_tracked",        smp_fetch_sc_tracked,        ARG1(0,TAB),      NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc1_trackers",       smp_fetch_sc_trackers,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_get_gpt0",       smp_fetch_sc_get_gpt0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc2_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "sc2_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_tracked",        smp_fetch_sc_tracked,        ARG1(0,TAB),      NULL, SMP_T_BOOL, SMP_USE_INTRN, },
	{ "sc2_trackers",       smp_fetch_sc_trackers,       ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "src_bytes_in_rate",  smp_fetch_sc_bytes_in_rate,  ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_bytes_out_rate", smp_fetch_sc_bytes_out_rate, ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_clr_gpc0",       smp_fetch_sc_clr_gpc0,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_conn_cnt",       smp_fetch_sc_conn_cnt,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_conn_cur",       smp_fetch_sc_conn_cur,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_conn_rate",      smp_fetch_sc_conn_rate,      ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_get_gpt0",       smp_fetch_sc_get_gpt0,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_get_gpc0",       smp_fetch_sc_get_gpc0,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_gpc0_rate",      smp_fetch_sc_gpc0_rate,      ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_err_cnt",   smp_fetch_sc_http_err_cnt,   ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_err_rate",  smp_fetch_sc_http_err_rate,  ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_req_cnt",   smp_fetch_sc_http_req_cnt,   ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_http_req_rate",  smp_fetch_sc_http_req_rate,  ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_inc_gpc0",       smp_fetch_sc_inc_gpc0,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_kbytes_in",      smp_fetch_sc_kbytes_in,      ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_kbytes_out",     smp_fetch_sc_kbytes_out,     ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_sess_cnt",       smp_fetch_sc_sess_cnt,       ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_sess_rate",      smp_fetch_sc_sess_rate,      ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_updt_conn_cnt",  smp_fetch_src_updt_conn_cnt, ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "table_avl",          smp_fetch_table_avl,         ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "table_cnt",          smp_fetch_table_cnt,         ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ /* END */ },
}};


/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "in_table",             sample_conv_in_table,             ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_BOOL  },
	{ "table_bytes_in_rate",  sample_conv_table_bytes_in_rate,  ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_bytes_out_rate", sample_conv_table_bytes_out_rate, ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_conn_cnt",       sample_conv_table_conn_cnt,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_conn_cur",       sample_conv_table_conn_cur,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_conn_rate",      sample_conv_table_conn_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpt0",           sample_conv_table_gpt0,           ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc0",           sample_conv_table_gpc0,           ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc0_rate",      sample_conv_table_gpc0_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_err_cnt",   sample_conv_table_http_err_cnt,   ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_err_rate",  sample_conv_table_http_err_rate,  ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
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

__attribute__((constructor))
static void __stick_table_init(void)
{
	/* register som action keywords. */
	tcp_req_conn_keywords_register(&tcp_conn_kws);
	tcp_req_sess_keywords_register(&tcp_sess_kws);
	tcp_req_cont_keywords_register(&tcp_req_kws);
	tcp_res_cont_keywords_register(&tcp_res_kws);
	http_req_keywords_register(&http_req_kws);
	http_res_keywords_register(&http_res_kws);

	/* register sample fetch and format conversion keywords */
	sample_register_fetches(&smp_fetch_keywords);
	sample_register_convs(&sample_conv_kws);
	cli_register_kw(&cli_kws);
}
