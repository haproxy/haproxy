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
#include <haproxy/applet.h>
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
#include <haproxy/sc_strm.h>
#include <haproxy/stats-t.h>
#include <haproxy/stconn.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>
#include <haproxy/xxhash.h>

#if defined(USE_PROMEX)
#include <promex/promex.h>
#endif

/* stick table base fields */
enum sticktable_field {
	STICKTABLE_SIZE = 0,
	STICKTABLE_USED,
	/* must always be the last one */
	STICKTABLE_TOTAL_FIELDS
};


/* structure used to return a table key built from a sample */
static THREAD_LOCAL struct stktable_key static_table_key;
static int (*smp_fetch_src)(const struct arg *, struct sample *, const char *, void *);
struct pool_head *pool_head_stk_ctr __read_mostly = NULL;
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
 * in table <t>. It's safe to call it under or out of a lock.
 */
void __stksess_free(struct stktable *t, struct stksess *ts)
{
	HA_ATOMIC_DEC(&t->current);
	pool_free(t->pool, (void *)ts - round_ptr_size(t->data_size));
}

/*
 * Free an allocated sticky session <ts>, and decrease sticky sessions counter
 * in table <t>.
 * This function locks the table
 */
void stksess_free(struct stktable *t, struct stksess *ts)
{
	uint shard;
	size_t len;
	void *data;

	data = stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_KEY);
	if (data) {
		dict_entry_unref(&server_key_dict, stktable_data_cast(data, std_t_dict));
		stktable_data_cast(data, std_t_dict) = NULL;
	}

	if (t->type == SMP_T_STR)
		len = strlen((const char *)ts->key.key);
	else
		len = t->key_size;

	shard = stktable_calc_shard_num(t, ts->key.key, len);

	/* make the compiler happy when shard is not used without threads */
	ALREADY_CHECKED(shard);

	__stksess_free(t, ts);
}

/*
 * Kill an stksess (only if its ref_cnt is zero). This must be called under the
 * write lock. Returns zero if could not deleted, non-zero otherwise.
 */
int __stksess_kill(struct stktable *t, struct stksess *ts)
{
	int updt_locked = 0;

	if (HA_ATOMIC_LOAD(&ts->ref_cnt))
		return 0;

	if (ts->upd.node.leaf_p) {
		updt_locked = 1;
		HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->updt_lock);
		if (HA_ATOMIC_LOAD(&ts->ref_cnt))
			goto out_unlock;
	}
	eb32_delete(&ts->exp);
	eb32_delete(&ts->upd);
	ebmb_delete(&ts->key);
	__stksess_free(t, ts);

  out_unlock:
	if (updt_locked)
		HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->updt_lock);
	return 1;
}

/*
 * Decrease the refcount of a stksess and relase it if the refcount falls to 0.
 * Returns non-zero if deleted, zero otherwise.
 *
 * This function locks the corresponding table shard to proceed. When this
 * function is called, the caller must be sure it owns a reference on the
 * stksess (refcount >= 1).
 */
int stksess_kill(struct stktable *t, struct stksess *ts)
{
	uint shard;
	size_t len;
	int ret = 0;

	if (t->type == SMP_T_STR)
		len = strlen((const char *)ts->key.key);
	else
		len = t->key_size;

	shard = stktable_calc_shard_num(t, ts->key.key, len);

	/* make the compiler happy when shard is not used without threads */
	ALREADY_CHECKED(shard);

	HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
	if (!HA_ATOMIC_SUB_FETCH(&ts->ref_cnt, 1))
		ret = __stksess_kill(t, ts);
	HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);

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
 * Get the key in the sticky session <ts> present in table <t>
 * It cannot fail as it is assumed that if <ts> exists, then the key has
 * been set.
 * It uses static_table_key to store the key
 */
struct stktable_key *stksess_getkey(struct stktable *t, struct stksess *ts)
{
	if (t->type != SMP_T_STR) {
		static_table_key.key = ts->key.key;
		static_table_key.key_len = t->key_size;
	}
	else {
		static_table_key.key = ts->key.key;
		static_table_key.key_len = strnlen2((char *)ts->key.key, t->key_size);
	}
	return &static_table_key;
}

/* return a shard number for key <key> of len <len> present in table <t>. This
 * takes into account the presence or absence of a peers section with shards
 * and the number of shards, the table's hash_seed, and of course the key. The
 * caller must pass a valid <key> and <len>. The shard number to be used by the
 * entry is returned (from 1 to nb_shards, otherwise 0 for none).
 */
int stktable_get_key_shard(struct stktable *t, const void *key, size_t len)
{
	/* no peers section or no shards in the peers section */
	if (!t->peers.p || !t->peers.p->nb_shards)
		return 0;

	return XXH64(key, len, t->hash_seed) % t->peers.p->nb_shards + 1;
}

/*
 * Set the shard for <key> key of <ts> sticky session attached to <t> stick table.
 * Use zero for stick-table without peers synchronisation.
 */
static void stksess_setkey_shard(struct stktable *t, struct stksess *ts,
                                 struct stktable_key *key)
{
	size_t keylen;

	if (t->type == SMP_T_STR)
		keylen = key->key_len;
	else
		keylen = t->key_size;

	ts->shard = stktable_get_key_shard(t, key->key, keylen);
}

/*
 * Init sticky session <ts> of table <t>. The data parts are cleared and <ts>
 * is returned.
 */
static struct stksess *__stksess_init(struct stktable *t, struct stksess * ts)
{
	memset((void *)ts - t->data_size, 0, t->data_size);
	ts->ref_cnt = 0;
	ts->shard = 0;
	ts->seen = 0;
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
 * most of them have ts->ref_cnt>0). This function locks the table.
 */
int stktable_trash_oldest(struct stktable *t, int to_batch)
{
	struct stksess *ts;
	struct eb32_node *eb;
	int max_search = to_batch * 2; // no more than 50% misses
	int max_per_shard = (to_batch + CONFIG_HAP_TBL_BUCKETS - 1) / CONFIG_HAP_TBL_BUCKETS;
	int done_per_shard;
	int batched = 0;
	int updt_locked;
	int looped;
	int shard;

	shard = 0;

	while (batched < to_batch) {
		done_per_shard = 0;
		looped = 0;
		updt_locked = 0;

		HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);

		eb = eb32_lookup_ge(&t->shards[shard].exps, now_ms - TIMER_LOOK_BACK);
		while (batched < to_batch && done_per_shard < max_per_shard) {
			if (unlikely(!eb)) {
				/* we might have reached the end of the tree, typically because
				 * <now_ms> is in the first half and we're first scanning the last
				 * half. Let's loop back to the beginning of the tree now if we
				 * have not yet visited it.
				 */
				if (looped)
					break;
				looped = 1;
				eb = eb32_first(&t->shards[shard].exps);
				if (likely(!eb))
					break;
			}

			if (--max_search < 0)
				break;

			/* timer looks expired, detach it from the queue */
			ts = eb32_entry(eb, struct stksess, exp);
			eb = eb32_next(eb);

			/* don't delete an entry which is currently referenced */
			if (HA_ATOMIC_LOAD(&ts->ref_cnt) != 0)
				continue;

			eb32_delete(&ts->exp);

			if (ts->expire != ts->exp.key) {
				if (!tick_isset(ts->expire))
					continue;

				ts->exp.key = ts->expire;
				eb32_insert(&t->shards[shard].exps, &ts->exp);

				/* the update might have jumped beyond the next element,
				 * possibly causing a wrapping. We need to check whether
				 * the next element should be used instead. If the next
				 * element doesn't exist it means we're on the right
				 * side and have to check the first one then. If it
				 * exists and is closer, we must use it, otherwise we
				 * use the current one.
				 */
				if (!eb)
					eb = eb32_first(&t->shards[shard].exps);

				if (!eb || tick_is_lt(ts->exp.key, eb->key))
					eb = &ts->exp;

				continue;
			}

			/* if the entry is in the update list, we must be extremely careful
			 * because peers can see it at any moment and start to use it. Peers
			 * will take the table's updt_lock for reading when doing that, and
			 * with that lock held, will grab a ref_cnt before releasing the
			 * lock. So we must take this lock as well and check the ref_cnt.
			 */
			if (ts->upd.node.leaf_p) {
				if (!updt_locked) {
					updt_locked = 1;
					HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->updt_lock);
				}
				/* now we're locked, new peers can't grab it anymore,
				 * existing ones already have the ref_cnt.
				 */
				if (HA_ATOMIC_LOAD(&ts->ref_cnt))
					continue;
			}

			/* session expired, trash it */
			ebmb_delete(&ts->key);
			eb32_delete(&ts->upd);
			__stksess_free(t, ts);
			batched++;
			done_per_shard++;
		}

		if (updt_locked)
			HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->updt_lock);

		HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);

		if (max_search <= 0)
			break;

		shard = (shard + 1) % CONFIG_HAP_TBL_BUCKETS;
		if (!shard)
			break;
	}

	return batched;
}

/*
 * Allocate and initialise a new sticky session.
 * The new sticky session is returned or NULL in case of lack of memory.
 * Sticky sessions should only be allocated this way, and must be freed using
 * stksess_free(). Table <t>'s sticky session counter is increased. If <key>
 * is not NULL, it is assigned to the new session. It must be called unlocked
 * as it may rely on a lock to trash older entries.
 */
struct stksess *stksess_new(struct stktable *t, struct stktable_key *key)
{
	struct stksess *ts;
	unsigned int current;

	current = HA_ATOMIC_FETCH_ADD(&t->current, 1);

	if (unlikely(current >= t->size)) {
		/* the table was already full, we may have to purge entries */
		if ((t->flags & STK_FL_NOPURGE) ||
		    !stktable_trash_oldest(t, (t->size >> 8) + 1)) {
			HA_ATOMIC_DEC(&t->current);
			return NULL;
		}
	}

	ts = pool_alloc(t->pool);
	if (ts) {
		ts = (void *)ts + round_ptr_size(t->data_size);
		__stksess_init(t, ts);
		if (key) {
			stksess_setkey(t, ts, key);
			stksess_setkey_shard(t, ts, key);
		}
	}

	return ts;
}

/*
 * Looks in table <t> for a sticky session matching key <key> in shard <shard>.
 * Returns pointer on requested sticky session or NULL if none was found.
 */
struct stksess *__stktable_lookup_key(struct stktable *t, struct stktable_key *key, uint shard)
{
	struct ebmb_node *eb;

	if (t->type == SMP_T_STR)
		eb = ebst_lookup_len(&t->shards[shard].keys, key->key, key->key_len + 1 < t->key_size ? key->key_len : t->key_size - 1);
	else
		eb = ebmb_lookup(&t->shards[shard].keys, key->key, t->key_size);

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
	uint shard;
	size_t len;

	if (t->type == SMP_T_STR)
		len = key->key_len + 1 < t->key_size ? key->key_len : t->key_size - 1;
	else
		len = t->key_size;

	shard = stktable_calc_shard_num(t, key->key, len);

	HA_RWLOCK_RDLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
	ts = __stktable_lookup_key(t, key, shard);
	if (ts)
		HA_ATOMIC_INC(&ts->ref_cnt);
	HA_RWLOCK_RDUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);

	return ts;
}

/*
 * Looks in table <t> for a sticky session matching ptr <ptr>.
 * Returns pointer on requested sticky session or NULL if none was found.
 * The refcount of the found entry is increased and this function
 * is protected using the table lock
 */
struct stksess *stktable_lookup_ptr(struct stktable *t, void *ptr)
{
	struct stksess *ts = NULL;
	struct ebmb_node *eb;
	int shard;

	for (shard = 0; shard < CONFIG_HAP_TBL_BUCKETS; shard++) {
		HA_RWLOCK_RDLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
		/* linear search is performed, this could be optimized by adding
		 * an eb node dedicated to ptr lookups into stksess struct to
		 * leverage eb_lookup function instead.
		 */
		eb = ebmb_first(&t->shards[shard].keys);
		while (eb) {
			struct stksess *cur;

			cur = ebmb_entry(eb, struct stksess, key);
			if (cur == ptr) {
				ts = cur;
				break;
			}
			eb = ebmb_next(eb);
		}
		if (ts)
			HA_ATOMIC_INC(&ts->ref_cnt);
		HA_RWLOCK_RDUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
		if (ts)
			return ts;
	}

	return ts;
}

/*
 * Looks in table <t> for a sticky session with same key as <ts>.
 * Returns pointer on requested sticky session or NULL if none was found.
 *
 * <ts> must originate from a table with same key type and length than <t>,
 * else it is undefined behavior.
 */
struct stksess *__stktable_lookup(struct stktable *t, struct stksess *ts, uint shard)
{
	struct ebmb_node *eb;

	if (t->type == SMP_T_STR)
		eb = ebst_lookup(&t->shards[shard].keys, (char *)ts->key.key);
	else
		eb = ebmb_lookup(&t->shards[shard].keys, ts->key.key, t->key_size);

	if (unlikely(!eb))
		return NULL;

	return ebmb_entry(eb, struct stksess, key);
}

/*
 * Looks in table <t> for a sticky session with same key as <ts>.
 * Returns pointer on requested sticky session or NULL if none was found.
 * The refcount of the found entry is increased and this function
 * is protected using the table lock
 *
 * <ts> must originate from a table with same key type and length than <t>,
 * else it is undefined behavior.
 */
struct stksess *stktable_lookup(struct stktable *t, struct stksess *ts)
{
	struct stksess *lts;
	uint shard;
	size_t len;

	if (t->type == SMP_T_STR)
		len = strlen((const char *)ts->key.key);
	else
		len = t->key_size;

	shard = stktable_calc_shard_num(t, ts->key.key, len);

	HA_RWLOCK_RDLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
	lts = __stktable_lookup(t, ts, shard);
	if (lts)
		HA_ATOMIC_INC(&lts->ref_cnt);
	HA_RWLOCK_RDUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);

	return lts;
}

/* Update the expiration timer for <ts> but do not touch its expiration node.
 * The table's expiration timer is updated if set.
 * The node will be also inserted into the update tree if needed, at a position
 * depending if the update is a local or coming from a remote node.
 * If <decrefcnt> is set, the ts entry's ref_cnt will be decremented. The table's
 * updt_lock may be taken for writes.
 */
void stktable_touch_with_exp(struct stktable *t, struct stksess *ts, int local, int expire, int decrefcnt)
{
	struct eb32_node * eb;
	int use_wrlock = 0;
	int do_wakeup = 0;

	if (expire != HA_ATOMIC_LOAD(&ts->expire)) {
		/* we'll need to set the expiration and to wake up the expiration timer .*/
		HA_ATOMIC_STORE(&ts->expire, expire);
		stktable_requeue_exp(t, ts);
	}

	/* If sync is enabled */
	if (t->sync_task) {
		if (local) {
			/* Check if this entry is not in the tree or not
			 * scheduled for at least one peer.
			 */
			if (!ts->upd.node.leaf_p || _HA_ATOMIC_LOAD(&ts->seen)) {
				/* Time to upgrade the read lock to write lock */
				HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->updt_lock);
				use_wrlock = 1;

				/* here we're write-locked */

				ts->seen = 0;
				ts->upd.key = ++t->update;
				t->localupdate = t->update;
				eb32_delete(&ts->upd);
				eb = eb32_insert(&t->updates, &ts->upd);
				if (eb != &ts->upd)  {
					eb32_delete(eb);
					eb32_insert(&t->updates, &ts->upd);
				}
			}
			do_wakeup = 1;
		}
		else {
			/* Note: we land here when learning new entries from
			 * remote peers. We hold one ref_cnt so the entry
			 * cannot vanish under us, however if two peers create
			 * the same key at the exact same time, we must be
			 * careful not to perform two parallel inserts! Hence
			 * we need to first check leaf_p to know if the entry
			 * is new, then lock the tree and check the entry again
			 * (since another thread could have created it in the
			 * mean time).
			 */
			if (!ts->upd.node.leaf_p) {
				/* Time to upgrade the read lock to write lock if needed */
				HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->updt_lock);
				use_wrlock = 1;

				/* here we're write-locked */
				if (!ts->upd.node.leaf_p) {
					ts->seen = 0;
					ts->upd.key= (++t->update)+(2147483648U);
					eb = eb32_insert(&t->updates, &ts->upd);
					if (eb != &ts->upd) {
						eb32_delete(eb);
						eb32_insert(&t->updates, &ts->upd);
					}
				}
			}
		}

		/* drop the lock now */
		if (use_wrlock)
			HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->updt_lock);
	}

	if (decrefcnt)
		HA_ATOMIC_DEC(&ts->ref_cnt);

	if (do_wakeup)
		task_wakeup(t->sync_task, TASK_WOKEN_MSG);
}

/* Update the expiration timer for <ts> but do not touch its expiration node.
 * The table's expiration timer is updated using the date of expiration coming from
 * <t> stick-table configuration.
 * The node will be also inserted into the update tree if needed, at a position
 * considering the update is coming from a remote node
 */
void stktable_touch_remote(struct stktable *t, struct stksess *ts, int decrefcnt)
{
	stktable_touch_with_exp(t, ts, 0, ts->expire, decrefcnt);
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

	stktable_touch_with_exp(t, ts, 1, expire, decrefcnt);
}
/* Just decrease the ref_cnt of the current session. Does nothing if <ts> is NULL.
 * Note that we still need to take the read lock because a number of other places
 * (including in Lua and peers) update the ref_cnt non-atomically under the write
 * lock.
 */
static void stktable_release(struct stktable *t, struct stksess *ts)
{
	if (!ts)
		return;
	HA_ATOMIC_DEC(&ts->ref_cnt);
}

/* Insert new sticky session <ts> in the table. It is assumed that it does not
 * yet exist (the caller must check this). The table's timeout is updated if it
 * is set. <ts> is returned if properly inserted, otherwise the one already
 * present if any.
 */
struct stksess *__stktable_store(struct stktable *t, struct stksess *ts, uint shard)
{
	struct ebmb_node *eb;

	eb = ebmb_insert(&t->shards[shard].keys, &ts->key, t->key_size);
	if (likely(eb == &ts->key)) {
		ts->exp.key = ts->expire;
		eb32_insert(&t->shards[shard].exps, &ts->exp);
	}
	return ebmb_entry(eb, struct stksess, key); // most commonly this is <ts>
}

/* requeues the table's expiration task to take the recently added <ts> into
 * account. This is performed atomically and doesn't require any lock.
 */
void stktable_requeue_exp(struct stktable *t, const struct stksess *ts)
{
	int old_exp, new_exp;
	int expire = ts->expire;

	if (!t->expire)
		return;

	/* set the task's expire to the newest expiration date. */
	old_exp = HA_ATOMIC_LOAD(&t->exp_task->expire);
	new_exp = tick_first(expire, old_exp);

	/* let's not go further if we're already up to date */
	if (new_exp == old_exp)
		return;

	HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->lock);

	while (new_exp != old_exp &&
	       !HA_ATOMIC_CAS(&t->exp_task->expire, &old_exp, new_exp)) {
		__ha_cpu_relax();
		new_exp = tick_first(expire, old_exp);
	}

	task_queue(t->exp_task);

	HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->lock);
}

/* Returns a valid or initialized stksess for the specified stktable_key in the
 * specified table, or NULL if the key was NULL, or if no entry was found nor
 * could be created. The entry's expiration is updated. This function locks the
 * table, and the refcount of the entry is increased.
 */
struct stksess *stktable_get_entry(struct stktable *table, struct stktable_key *key)
{
	struct stksess *ts, *ts2;
	uint shard;
	size_t len;

	if (!key)
		return NULL;

	if (table->type == SMP_T_STR)
		len = key->key_len + 1 < table->key_size ? key->key_len : table->key_size - 1;
	else
		len = table->key_size;

	shard = stktable_calc_shard_num(table, key->key, len);

	HA_RWLOCK_RDLOCK(STK_TABLE_LOCK, &table->shards[shard].sh_lock);
	ts = __stktable_lookup_key(table, key, shard);
	if (ts)
		HA_ATOMIC_INC(&ts->ref_cnt);
	HA_RWLOCK_RDUNLOCK(STK_TABLE_LOCK, &table->shards[shard].sh_lock);
	if (ts)
		return ts;

	/* No such entry exists, let's try to create a new one. this doesn't
	 * require locking yet.
	 */

	ts = stksess_new(table, key);
	if (!ts)
		return NULL;

	/* Now we're certain to have a ts. We need to store it. For this we'll
	 * need an exclusive access. We don't need an atomic upgrade, this is
	 * rare and an unlock+lock sequence will do the job fine. Given that
	 * this will not be atomic, the missing entry might appear in the mean
	 * tome so we have to be careful that the one we try to insert is the
	 * one we find.
	 */

	HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &table->shards[shard].sh_lock);

	ts2 = __stktable_store(table, ts, shard);

	HA_ATOMIC_INC(&ts2->ref_cnt);
	HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &table->shards[shard].sh_lock);

	if (unlikely(ts2 != ts)) {
		/* another entry was added in the mean time, let's
		 * switch to it.
		 */
		__stksess_free(table, ts);
		ts = ts2;
	}

	stktable_requeue_exp(table, ts);
	return ts;
}

/* Lookup for an entry with the same key and store the submitted
 * stksess if not found. This function locks the table either shared or
 * exclusively, and the refcount of the entry is increased.
 */
struct stksess *stktable_set_entry(struct stktable *table, struct stksess *nts)
{
	struct stksess *ts;
	uint shard;
	size_t len;

	if (table->type == SMP_T_STR)
		len = strlen((const char *)nts->key.key);
	else
		len = table->key_size;

	shard = stktable_calc_shard_num(table, nts->key.key, len);

	HA_RWLOCK_RDLOCK(STK_TABLE_LOCK, &table->shards[shard].sh_lock);
	ts = __stktable_lookup(table, nts, shard);
	if (ts) {
		HA_ATOMIC_INC(&ts->ref_cnt);
		HA_RWLOCK_RDUNLOCK(STK_TABLE_LOCK, &table->shards[shard].sh_lock);
		return ts;
	}
	ts = nts;

	/* let's increment it before switching to exclusive */
	HA_ATOMIC_INC(&ts->ref_cnt);

	if (HA_RWLOCK_TRYRDTOSK(STK_TABLE_LOCK, &table->shards[shard].sh_lock) != 0) {
		/* upgrade to seek lock failed, let's drop and take */
		HA_RWLOCK_RDUNLOCK(STK_TABLE_LOCK, &table->shards[shard].sh_lock);
		HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &table->shards[shard].sh_lock);
	}
	else
		HA_RWLOCK_SKTOWR(STK_TABLE_LOCK, &table->shards[shard].sh_lock);

	/* now we're write-locked */

	__stktable_store(table, ts, shard);
	HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &table->shards[shard].sh_lock);

	stktable_requeue_exp(table, ts);
	return ts;
}

/*
 * Task processing function to trash expired sticky sessions. A pointer to the
 * task itself is returned since it never dies.
 */
struct task *process_table_expire(struct task *task, void *context, unsigned int state)
{
	struct stktable *t = context;
	struct stksess *ts;
	struct eb32_node *eb;
	int updt_locked;
	int looped;
	int exp_next;
	int task_exp;
	int shard;

	task_exp = TICK_ETERNITY;

	for (shard = 0; shard < CONFIG_HAP_TBL_BUCKETS; shard++) {
		updt_locked = 0;
		looped = 0;
		HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
		eb = eb32_lookup_ge(&t->shards[shard].exps, now_ms - TIMER_LOOK_BACK);

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
				eb = eb32_first(&t->shards[shard].exps);
				if (likely(!eb))
					break;
			}

			if (likely(tick_is_lt(now_ms, eb->key))) {
				/* timer not expired yet, revisit it later */
				exp_next = eb->key;
				goto out_unlock;
			}

			/* timer looks expired, detach it from the queue */
			ts = eb32_entry(eb, struct stksess, exp);
			eb = eb32_next(eb);

			/* don't delete an entry which is currently referenced */
			if (HA_ATOMIC_LOAD(&ts->ref_cnt) != 0)
				continue;

			eb32_delete(&ts->exp);

			if (!tick_is_expired(ts->expire, now_ms)) {
				if (!tick_isset(ts->expire))
					continue;

				ts->exp.key = ts->expire;
				eb32_insert(&t->shards[shard].exps, &ts->exp);

				/* the update might have jumped beyond the next element,
				 * possibly causing a wrapping. We need to check whether
				 * the next element should be used instead. If the next
				 * element doesn't exist it means we're on the right
				 * side and have to check the first one then. If it
				 * exists and is closer, we must use it, otherwise we
				 * use the current one.
				 */
				if (!eb)
					eb = eb32_first(&t->shards[shard].exps);

				if (!eb || tick_is_lt(ts->exp.key, eb->key))
					eb = &ts->exp;
				continue;
			}

			/* if the entry is in the update list, we must be extremely careful
			 * because peers can see it at any moment and start to use it. Peers
			 * will take the table's updt_lock for reading when doing that, and
			 * with that lock held, will grab a ref_cnt before releasing the
			 * lock. So we must take this lock as well and check the ref_cnt.
			 */
			if (ts->upd.node.leaf_p) {
				if (!updt_locked) {
					updt_locked = 1;
					HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->updt_lock);
				}
				/* now we're locked, new peers can't grab it anymore,
				 * existing ones already have the ref_cnt.
				 */
				if (HA_ATOMIC_LOAD(&ts->ref_cnt))
					continue;
			}

			/* session expired, trash it */
			ebmb_delete(&ts->key);
			eb32_delete(&ts->upd);
			__stksess_free(t, ts);
		}

		/* We have found no task to expire in any tree */
		exp_next = TICK_ETERNITY;

	out_unlock:
		if (updt_locked)
			HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->updt_lock);

		task_exp = tick_first(task_exp, exp_next);
		HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
	}

	/* Reset the task's expiration. We do this under the lock so as not
	 * to ruin a call to task_queue() in stktable_requeue_exp() if we
	 * were to update with TICK_ETERNITY.
	 */
	HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->lock);
	task->expire = task_exp;
	HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->lock);

	return task;
}

/* Perform minimal stick table initialization. In case of error, the
 * function will return 0 and <err_msg> will contain hints about the
 * error and it is up to the caller to free it.
 *
 * Returns 1 on success
 */
int stktable_init(struct stktable *t, char **err_msg)
{
	int peers_retval = 0;
	int shard;

	t->hash_seed = XXH64(t->id, t->idlen, 0);

	if (t->size) {
		for (shard = 0; shard < CONFIG_HAP_TBL_BUCKETS; shard++) {
			t->shards[shard].keys = EB_ROOT_UNIQUE;
			memset(&t->shards[shard].exps, 0, sizeof(t->shards[shard].exps));
			HA_RWLOCK_INIT(&t->shards[shard].sh_lock);
		}

		t->updates = EB_ROOT_UNIQUE;
		HA_RWLOCK_INIT(&t->lock);

		t->pool = create_pool("sticktables", sizeof(struct stksess) + round_ptr_size(t->data_size) + t->key_size, MEM_F_SHARED);

		if ( t->expire ) {
			t->exp_task = task_new_anywhere();
			if (!t->exp_task)
				goto mem_error;
			t->exp_task->process = process_table_expire;
			t->exp_task->context = (void *)t;
		}
		if (t->peers.p && t->peers.p->peers_fe && !(t->peers.p->peers_fe->flags & (PR_FL_DISABLED|PR_FL_STOPPED))) {
			peers_retval = peers_register_table(t->peers.p, t);
		}

		if (t->pool == NULL || peers_retval)
			goto mem_error;
	}
	if (t->write_to.name) {
		struct stktable *table;

		/* postresolve write_to table */
		table = stktable_find_by_name(t->write_to.name);
		if (!table) {
			memprintf(err_msg, "write-to: table '%s' doesn't exist", t->write_to.name);
			ha_free(&t->write_to.name); /* no longer need this */
			return 0;
		}
		ha_free(&t->write_to.name); /* no longer need this */
		if (table->write_to.ptr) {
			memprintf(err_msg, "write-to: table '%s' is already used as a source table", table->id);
			return 0;
		}
		if (table->type != t->type) {
			memprintf(err_msg, "write-to: cannot mix table types ('%s' has '%s' type and '%s' has '%s' type)",
			          table->id, stktable_types[table->type].kw,
			          t->id, stktable_types[t->type].kw);
			return 0;
		}
		if (table->key_size != t->key_size) {
			memprintf(err_msg, "write-to: cannot mix key sizes ('%s' has '%ld' key_size and '%s' has '%ld' key_size)",
			          table->id, (long)table->key_size,
			          t->id, (long)t->key_size);
			return 0;
		}

		t->write_to.t = table;
	}
	return 1;

 mem_error:
	memprintf(err_msg, "memory allocation error");
	return 0;
}

/* Performs stick table cleanup: it's meant to be called after the table
 * has been initialized ith stktable_init(), else it will lead to undefined
 * behavior.
 *
 * However it does not free the table pointer itself
 */
void stktable_deinit(struct stktable *t)
{
	if (!t)
		return;
	task_destroy(t->exp_task);
	pool_destroy(t->pool);
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
int stktable_parse_type(char **args, int *myidx, unsigned long *type, size_t *key_size, const char *file, int linenum)
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
				char *stop;

				(*myidx)++;
				*key_size = strtol(args[*myidx], &stop, 10);
				if (*stop != '\0' || !*key_size) {
					ha_alert("parsing [%s:%d] : 'len' expects a positive integer argument.\n", file, linenum);
					return 1;
				}
				if (*type == SMP_T_STR) {
					/* null terminated string needs +1 for '\0'. */
					(*key_size)++;
				}
				(*myidx)++;
			}
		}
		return 0;
	}
	ha_alert("parsing [%s:%d] : %s: unknown type '%s'.\n", file, linenum, args[0], args[*myidx]);
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
	t->idlen = strlen(id);
	t->nid =  nid;
	t->type = (unsigned int)-1;
	t->conf.file = copy_file_name(file);
	t->conf.line = linenum;
	t->write_to.name = NULL;
	t->brates_factor = 1;

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
			ha_free(&t->peers.name);
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
			t->flags |= STK_FL_NOPURGE;
			idx++;
		}
		else if (strcmp(args[idx], "type") == 0) {
			idx++;
			if (stktable_parse_type(args, &idx, &t->type, &t->key_size, file, linenum) != 0) {
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
		else if (strcmp(args[idx], "recv-only") == 0) {
			t->flags |= STK_FL_RECV_ONLY;
			idx++;
		}
		else if (strcmp(args[idx], "write-to") == 0) {
			char *write_to;

			idx++;
			write_to = args[idx];
			if (!write_to[0]) {
				ha_alert("parsing [%s:%d] : %s : write-to requires table name.\n",
						file, linenum, args[0]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;

			}
			ha_free(&t->write_to.name);
			t->write_to.name = strdup(write_to);
			idx++;
		}
		else if (strcmp(args[idx], "brates-factor") == 0) {
			idx++;
			if (!*(args[idx])) {
				ha_alert("parsing [%s:%d] : %s: missing argument after '%s'.\n",
					 file, linenum, args[0], args[idx-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if ((err = parse_size_err(args[idx], &t->brates_factor))) {
				ha_alert("parsing [%s:%d] : %s: unexpected character '%c' in argument of '%s'.\n",
					 file, linenum, args[0], *err, args[idx-1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			if (t->brates_factor == 0 || t->brates_factor > 1024) {
				ha_alert("parsing [%s:%d] : %s: argument '%s' must be greater than 0 and lower or equal than 1024.\n",
					 file, linenum, args[0], args[idx-1]);
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
	{
		union {
			uint32_t u32;
			int64_t s64;
		} conv;

		/* The stick table require a 32bit unsigned int, "sint" is a
		 * signed 64 it, so we can convert it inplace.
		 */
		conv.s64 = 0;
		conv.u32 = smp->data.u.sint;
		smp->data.u.sint = conv.s64;

		static_table_key.key = &smp->data.u.sint;
		static_table_key.key_len = 4;
		break;
	}

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

/* reverse operation for smp_to_stkey(): fills input <smp> with content of
 * <key>
 * smp_make_safe() may be applied to smp before returning to ensure it can be
 * used even if the key is no longer available upon return.
 * Returns 1 on success and 0 on failure
 */
int stkey_to_smp(struct sample *smp, struct stktable_key *key, int key_type)
{
	smp->data.type = key_type;
	smp->flags = 0;

	switch (key_type) {

	case SMP_T_IPV4:
		memcpy(&smp->data.u.ipv4, static_table_key.key, sizeof(struct in_addr));
		break;
	case SMP_T_IPV6:
		memcpy(&smp->data.u.ipv6, static_table_key.key, sizeof(struct in6_addr));
		break;

	case SMP_T_SINT:
		/* The stick table require a 32bit unsigned int, "sint" is a
		 * signed 64 it, so we can convert it inplace.
		 */
		smp->data.u.sint = *(unsigned int *)static_table_key.key;
		break;

	case SMP_T_STR:
	case SMP_T_BIN:
		smp->data.u.str.area = static_table_key.key;
		smp->data.u.str.data = static_table_key.key_len;
		smp->flags = SMP_F_CONST;
		if (!smp_make_safe(smp))
			return 0;
		break;

	default: /* impossible case. */
		return 0;
	}

	return 1;
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
	[STKTABLE_DT_SERVER_ID]     = { .name = "server_id",      .std_type = STD_T_SINT, .as_is = 1  },
	[STKTABLE_DT_GPT0]          = { .name = "gpt0",           .std_type = STD_T_UINT, .as_is = 1  },
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
	[STKTABLE_DT_SERVER_KEY]    = { .name = "server_key",     .std_type = STD_T_DICT, .as_is = 1  },
	[STKTABLE_DT_HTTP_FAIL_CNT] = { .name = "http_fail_cnt",  .std_type = STD_T_UINT  },
	[STKTABLE_DT_HTTP_FAIL_RATE]= { .name = "http_fail_rate", .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY  },
	[STKTABLE_DT_GPT]           = { .name = "gpt",            .std_type = STD_T_UINT, .is_array = 1, .as_is = 1  },
	[STKTABLE_DT_GPC]           = { .name = "gpc",            .std_type = STD_T_UINT, .is_array = 1 },
	[STKTABLE_DT_GPC_RATE]      = { .name = "gpc_rate",       .std_type = STD_T_FRQP, .is_array = 1, .arg_type = ARG_T_DELAY },
	[STKTABLE_DT_GLITCH_CNT]    = { .name = "glitch_cnt",     .std_type = STD_T_UINT  },
	[STKTABLE_DT_GLITCH_RATE]   = { .name = "glitch_rate",    .std_type = STD_T_FRQP, .arg_type = ARG_T_DELAY  },
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

/*
 * Same as stktable_get_data_type() but also expects optional index after the
 * name in the form "name[idx]", but only for array types
 * If index optional argument is not provided, default value (0) is applied
 *
 * Returns the data type number on success, or < 0 if not found.
 */
int stktable_get_data_type_idx(char *name, unsigned int *idx)
{
	int type;
	size_t stop = strcspn(name, "[");

	if (!name[stop]) {
		/* no idx argument */
		*idx = 0;
		return stktable_get_data_type(name);
	}

	for (type = 0; type < STKTABLE_DATA_TYPES; type++) {
		char *ret;

		if (!stktable_data_types[type].name ||
		    !stktable_data_types[type].is_array)
			continue;
		if (strncmp(name, stktable_data_types[type].name, stop))
			continue;

		/* we've got a match */
		name += stop + 1;
		*idx = strtoul(name, &ret, 10);
		if (ret == name || *ret != ']')
			return -1; // bad value
		if (ret[1])
			return -1; // unexpected data

		return type;
	}

	return -1; // not found
}

/* Perform a lookup in <table> based on <smp> and returns stksess entry or NULL
 * if not found. Set <create> to force the entry creation if it doesn't exist.
 *
 * <smp> may be modified by underlying functions
 */
static struct stksess *smp_fetch_stksess(struct stktable *table, struct sample *smp, int create)
{
	struct stktable_key *key;

	/* Converts smp into key. */
	key = smp_to_stkey(smp, table);
	if (!key)
		return NULL;

	if (create)
		return stktable_get_entry(table, key);
	return stktable_lookup_key(table, key);
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
	struct stksess *ts;

	t = arg_p[0].data.t;

	ts = smp_fetch_stksess(t, smp, 0);

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
static int smp_fetch_bytes_in_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_bytes_in_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_bytes_in_rate(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the data rate sent to clients in bytes/s
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_bytes_out_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_bytes_out_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_bytes_out_rate(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(1), and looks
 * it up into this table. Clears the general purpose counter at GPC[arg_p(0)]
 * and return its previous value if the key is present in the table,
 * otherwise zero. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_clr_gpc(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt);
static int sample_conv_table_clr_gpc(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;
	unsigned int idx;

	idx = arg_p[0].data.sint;
	stkctr.table = arg_p[1].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 1));

	return smp_fetch_clr_gpc(&stkctr, smp, idx, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Clears the general purpose counter at GPC0
 * and return its previous value if the key is present in the table,
 * otherwise zero. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_clr_gpc0(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_clr_gpc0(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 1));

	return smp_fetch_clr_gpc0(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Clears the general purpose counter at GPC1
 * and return its previous value if the key is present in the table,
 * otherwise zero. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_clr_gpc1(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_clr_gpc1(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 1));

	return smp_fetch_clr_gpc1(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of connections for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_conn_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_conn_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_conn_cnt(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the number of concurrent connections for the
 * key if the key is present in the table, otherwise zero, so that comparisons
 * can be easily performed. If the inspected parameter is not stored in the
 * table, <not found> is returned.
 */
static int smp_fetch_conn_cur(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_conn_cur(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_conn_cur(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the rate of incoming connections from the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_conn_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_conn_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_conn_rate(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the expiration delay for the key if the key is
 * present in the table, otherwise the default value provided as second argument
 * if any, if not (no default value), <not found> is returned.
 */
static int sample_conv_table_expire(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stksess *ts;

	t = arg_p[0].data.t;

	ts = smp_fetch_stksess(t, smp, 0);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) { /* key not present */
		if (arg_p[1].type == ARGT_STOP)
			return 0;

		/* default value */
		smp->data.u.sint = arg_p[1].data.sint;
		return 1;
	}

	smp->data.u.sint = tick_remain(now_ms, ts->expire);

	stktable_release(t, ts);
	return 1;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the time the key remains unused if the key is
 * present in the table,  otherwise the default value provided as second argument
 * if any, if not (no default value), <not found> is returned.
 */
static int sample_conv_table_idle(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stktable *t;
	struct stksess *ts;

	t = arg_p[0].data.t;

	ts = smp_fetch_stksess(t, smp, 0);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) { /* key not present */
		if (arg_p[1].type == ARGT_STOP)
			return 0;

		/* default value */
		smp->data.u.sint = arg_p[1].data.sint;
		return 1;
	}

	smp->data.u.sint = tick_remain(tick_remain(now_ms, ts->expire), t->expire);

	stktable_release(t, ts);
	return 1;
}

/* Casts sample <smp> to the type of the table specified in arg(1), and looks
 * it up into this table. Increases the general purpose counter at GPC[arg_p(0)]
 * and return its new value if the key is present in the table, otherwise zero.
 * If the inspected parameter is not stored in the table, <not found> is returned.
 */
static int smp_fetch_inc_gpc(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt);
static int sample_conv_table_inc_gpc(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;
	unsigned int idx;

	idx = arg_p[0].data.sint;
	stkctr.table = arg_p[1].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 1));

	return smp_fetch_inc_gpc(&stkctr, smp, idx, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Increases the general purpose counter at GPC0
 * and return its new value if the key is present in the table, otherwise
 * zero. If the inspected parameter is not stored in the table, <not found>
 * is returned.
 */
static int smp_fetch_inc_gpc0(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_inc_gpc0(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 1));

	return smp_fetch_inc_gpc0(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Increases the general purpose counter at GPC1
 * and return its new value if the key is present in the table, otherwise
 * zero. If the inspected parameter is not stored in the table, <not found>
 * is returned.
 */
static int smp_fetch_inc_gpc1(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_inc_gpc1(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 1));

	return smp_fetch_inc_gpc1(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of front glitches for the
 * key if the key is present in the table, otherwise zero, so that comparisons
 * can be easily performed. If the inspected parameter is not stored in the
 * table, <not found> is returned.
 */
static int smp_fetch_glitch_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_glitch_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_glitch_cnt(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the front glitch rate the key if the key is
 * present in the table, otherwise zero, so that comparisons can be easily
 * performed. If the inspected parameter is not stored in the table, <not found>
 * is returned.
 */
static int smp_fetch_glitch_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_glitch_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_glitch_rate(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg_p(1), and looks
 * it up into this table. Returns the value of the GPT[arg_p(0)] tag for the key
 * if the key is present in the table, otherwise false, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_get_gpt(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt);
static int sample_conv_table_gpt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;
	unsigned int idx;

	idx = arg_p[0].data.sint;
	stkctr.table = arg_p[1].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_get_gpt(&stkctr, smp, idx, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the value of the GPT0 tag for the key
 * if the key is present in the table, otherwise false, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_get_gpt0(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_gpt0(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_get_gpt0(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg_p(1), and looks
 * it up into this table. Returns the value of the GPC[arg_p(0)] counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_get_gpc(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt);
static int sample_conv_table_gpc(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;
	unsigned int idx;

	idx = arg_p[0].data.sint;
	stkctr.table = arg_p[1].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_get_gpc(&stkctr, smp, idx, 1);
}

/* Casts sample <smp> to the type of the table specified in arg_p(1), and looks
 * it up into this table. Returns the event rate of the GPC[arg_p(0)] counter
 * for the key if the key is present in the table, otherwise zero, so that
 * comparisons can be easily performed. If the inspected parameter is not
 * stored in the table, <not found> is returned.
 */
static int smp_fetch_gpc_rate(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt);
static int sample_conv_table_gpc_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;
	unsigned int idx;

	idx = arg_p[0].data.sint;
	stkctr.table = arg_p[1].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_gpc_rate(&stkctr, smp, idx, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the value of the GPC0 counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_get_gpc0(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_gpc0(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_get_gpc0(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the event rate of the GPC0 counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_gpc0_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_gpc0_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_gpc0_rate(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the value of the GPC1 counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_get_gpc1(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_gpc1(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_get_gpc1(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the event rate of the GPC1 counter for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_gpc1_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_gpc1_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_gpc1_rate(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of HTTP request errors
 * for the key if the key is present in the table, otherwise zero, so that
 * comparisons can be easily performed. If the inspected parameter is not stored
 * in the table, <not found> is returned.
 */
static int smp_fetch_http_err_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_http_err_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_http_err_cnt(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the HTTP request error rate the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_http_err_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_http_err_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_http_err_rate(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of HTTP response failures
 * for the key if the key is present in the table, otherwise zero, so that
 * comparisons can be easily performed. If the inspected parameter is not stored
 * in the table, <not found> is returned.
 */
static int smp_fetch_http_fail_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_http_fail_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_http_fail_cnt(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the HTTP response failure rate for the key
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_http_fail_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_http_fail_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_http_fail_rate(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of HTTP request for the
 * key if the key is present in the table, otherwise zero, so that comparisons
 * can be easily performed. If the inspected parameter is not stored in the
 * table, <not found> is returned.
 */
static int smp_fetch_http_req_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_http_req_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_http_req_cnt(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the HTTP request rate the key if the key is
 * present in the table, otherwise zero, so that comparisons can be easily
 * performed. If the inspected parameter is not stored in the table, <not found>
 * is returned.
 */
static int smp_fetch_http_req_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_http_req_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_http_req_rate(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the volume of datareceived from clients in kbytes
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_kbytes_in(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_kbytes_in(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_kbytes_in(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the volume of data sent to clients in kbytes
 * if the key is present in the table, otherwise zero, so that comparisons can
 * be easily performed. If the inspected parameter is not stored in the table,
 * <not found> is returned.
 */
static int smp_fetch_kbytes_out(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_kbytes_out(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_kbytes_out(&stkctr, smp, 1);
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
	struct stksess *ts;
	void *ptr;

	t = arg_p[0].data.t;

	ts = smp_fetch_stksess(t, smp, 0);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts) /* key not present */
		return 1;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_SERVER_ID);
	if (ptr) {
		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ts->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_sint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);
	}

	stktable_release(t, ts);
	return !!ptr;
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the cumulated number of sessions for the
 * key if the key is present in the table, otherwise zero, so that comparisons
 * can be easily performed. If the inspected parameter is not stored in the
 * table, <not found> is returned.
 */
static int smp_fetch_sess_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_sess_cnt(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_sess_cnt(&stkctr, smp, 1);
}

/* Casts sample <smp> to the type of the table specified in arg(0), and looks
 * it up into this table. Returns the session rate the key if the key is
 * present in the table, otherwise zero, so that comparisons can be easily
 * performed. If the inspected parameter is not stored in the table, <not found>
 * is returned.
 */
static int smp_fetch_sess_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt);
static int sample_conv_table_sess_rate(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct stkctr stkctr;

	stkctr.table = arg_p[0].data.t;
	stkctr_set_entry(&stkctr, smp_fetch_stksess(stkctr.table, smp, 0));

	return smp_fetch_sess_rate(&stkctr, smp, 1);
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
	struct stksess *ts;

	t = arg_p[0].data.t;

	ts = smp_fetch_stksess(t, smp, 0);

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (!ts)
		return 1;

	smp->data.u.sint = HA_ATOMIC_LOAD(&ts->ref_cnt);

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
	struct stkctr *stkctr = NULL;
	unsigned int period = 0;

	/* Extract the stksess, return OK if no stksess available. */
	if (s && s->stkctr)
		stkctr = &s->stkctr[rule->arg.gpc.sc];
	else if (sess->stkctr)
		stkctr = &sess->stkctr[rule->arg.gpc.sc];
	else
		return ACT_RET_CONT;

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

	if (!global.tune.nb_stk_ctr) {
		memprintf(err, "Cannot use '%s', stick-counters are disabled via tune.stick-counters", args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}

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

			if (rule->arg.gpc.sc >= global.tune.nb_stk_ctr) {
				memprintf(err, "invalid stick table track ID '%s'. The max allowed ID is %d (tune.stick-counters)",
				          args[*arg-1], global.tune.nb_stk_ctr-1);
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

			if (rule->arg.gpc.sc >= global.tune.nb_stk_ctr) {
				memprintf(err, "invalid stick table track ID. The max allowed ID is %d (tune.stick-counters)",
				          global.tune.nb_stk_ctr-1);
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
		memprintf(err, "invalid gpc ID '%s'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)", args[*arg-1]);
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
	struct stkctr *stkctr = NULL;
	unsigned int value = 0;
	struct sample *smp;
	int smp_opt_dir;

	/* Extract the stksess, return OK if no stksess available. */
	if (s && s->stkctr)
		stkctr = &s->stkctr[rule->arg.gpt.sc];
	else if (sess->stkctr)
		stkctr = &sess->stkctr[rule->arg.gpt.sc];
	else
		return ACT_RET_CONT;

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
			case ACT_F_TCP_REQ_CON: smp_opt_dir = SMP_OPT_DIR_REQ; break;
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
	struct stkctr *stkctr = NULL;
	unsigned int value = 0;
	struct sample *smp;
	int smp_opt_dir;

	/* Extract the stksess, return OK if no stksess available. */
	if (s && s->stkctr)
		stkctr = &s->stkctr[rule->arg.gpt.sc];
	else if (sess->stkctr)
		stkctr = &sess->stkctr[rule->arg.gpt.sc];
	else
		return ACT_RET_CONT;

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
			case ACT_F_TCP_REQ_CON: smp_opt_dir = SMP_OPT_DIR_REQ; break;
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

	if (!global.tune.nb_stk_ctr) {
		memprintf(err, "Cannot use '%s', stick-counters are disabled via tune.stick-counters", args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}

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

			if (rule->arg.gpt.sc >= global.tune.nb_stk_ctr) {
				memprintf(err, "invalid stick table track ID '%s'. The max allowed ID is %d",
				          args[*arg-1], global.tune.nb_stk_ctr-1);
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

			if (rule->arg.gpt.sc >= global.tune.nb_stk_ctr) {
				memprintf(err, "invalid stick table track ID '%s'. The max allowed ID is %d",
				          args[*arg-1], global.tune.nb_stk_ctr-1);
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
		case ACT_F_TCP_REQ_CON: smp_val = SMP_VAL_FE_CON_ACC; break;
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

/* This function updates the gpc at index 'rule->arg.gpc.idx' of the array on
 * the tracksc counter of index 'rule->arg.gpc.sc' stored into the <stream> or
 * directly in the session <sess> if <stream> is set to NULL. This gpc is
 * set to the value computed by the expression 'rule->arg.gpc.expr' or if
 * 'rule->arg.gpc.expr' is null directly to the value of 'rule->arg.gpc.value'.
 *
 * This function always returns ACT_RET_CONT and parameter flags is unused.
 */
static enum act_return action_add_gpc(struct act_rule *rule, struct proxy *px,
                                      struct session *sess, struct stream *s, int flags)
{
	void *ptr1, *ptr2;
	struct stksess *ts;
	struct stkctr *stkctr;
	unsigned int value = 0;
	struct sample *smp;
	int smp_opt_dir;

	/* Extract the stksess, return OK if no stksess available. */
	if (s)
		stkctr = &s->stkctr[rule->arg.gpc.sc];
	else
		stkctr = &sess->stkctr[rule->arg.gpc.sc];

	ts = stkctr_entry(stkctr);
	if (!ts)
		return ACT_RET_CONT;

	/* First, update gpc_rate if it's tracked. Second, update its gpc if tracked. */
	ptr1 = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPC_RATE, rule->arg.gpc.idx);
	ptr2 = stktable_data_ptr_idx(stkctr->table, ts, STKTABLE_DT_GPC, rule->arg.gpc.idx);

	if (ptr1 || ptr2) {
		if (!rule->arg.gpc.expr)
			value = (unsigned int)(rule->arg.gpc.value);
		else {
			switch (rule->from) {
			case ACT_F_TCP_REQ_CON: smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_TCP_REQ_SES: smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_TCP_REQ_CNT: smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_TCP_RES_CNT: smp_opt_dir = SMP_OPT_DIR_RES; break;
			case ACT_F_HTTP_REQ:    smp_opt_dir = SMP_OPT_DIR_REQ; break;
			case ACT_F_HTTP_RES:    smp_opt_dir = SMP_OPT_DIR_RES; break;
			default:
				send_log(px, LOG_ERR, "stick table: internal error while setting gpc%u.", rule->arg.gpc.idx);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					ha_alert("stick table: internal error while executing setting gpc%u.\n", rule->arg.gpc.idx);
				return ACT_RET_CONT;
			}

			/* Fetch and cast the expression. */
			smp = sample_fetch_as_type(px, sess, s, smp_opt_dir|SMP_OPT_FINAL, rule->arg.gpc.expr, SMP_T_SINT);
			if (!smp) {
				send_log(px, LOG_WARNING, "stick table: invalid expression or data type while setting gpc%u.", rule->arg.gpc.idx);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					ha_alert("stick table: invalid expression or data type while setting gpc%u.\n", rule->arg.gpc.idx);
				return ACT_RET_CONT;
			}
			value = (unsigned int)(smp->data.u.sint);
		}

		if (value) {
			/* only update the value if non-null increment */
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

			if (ptr1)
				update_freq_ctr_period(&stktable_data_cast(ptr1, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u, value);

			if (ptr2)
				stktable_data_cast(ptr2, std_t_uint) += value;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
		}
		/* always touch the table so that it doesn't expire */
		stktable_touch_local(stkctr->table, ts, 0);
	}

	return ACT_RET_CONT;
}

/* This function is a parser for the "sc-add-gpc" action. It understands the
 * format:
 *
 *   sc-add-gpc(<gpc IDX>,<track ID>) <expression>
 *
 * It returns ACT_RET_PRS_ERR if fails and <err> is filled with an error message.
 * Otherwise, it returns ACT_RET_PRS_OK and the variable 'rule->arg.gpc.expr'
 * is filled with the pointer to the expression to execute or NULL if the arg
 * is directly an integer stored into 'rule->arg.gpt.value'.
 */
static enum act_parse_ret parse_add_gpc(const char **args, int *arg, struct proxy *px,
                                         struct act_rule *rule, char **err)
{
	const char *cmd_name = args[*arg-1];
	char *error;
	int smp_val;

	cmd_name += strlen("sc-add-gpc");
	if (*cmd_name != '(') {
		memprintf(err, "Missing or invalid arguments for '%s'. Expects sc-add-gpc(<GPC ID>,<Track ID>)", args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}
	cmd_name++; /* skip the '(' */
	rule->arg.gpc.idx = strtoul(cmd_name, &error, 10); /* Convert stick table id. */
	if (*error != ',') {
		memprintf(err, "Missing gpc ID. Expects %s(<GPC ID>,<Track ID>)", args[*arg-1]);
		return ACT_RET_PRS_ERR;
	}
	else {
		cmd_name = error + 1; /* skip the ',' */
		rule->arg.gpc.sc = strtol(cmd_name, &error, 10); /* Convert stick table id. */
		if (*error != ')') {
			memprintf(err, "invalid stick table track ID '%s'. Expects %s(<GPC ID>,<Track ID>)", cmd_name, args[*arg-1]);
			return ACT_RET_PRS_ERR;
		}

		if (rule->arg.gpc.sc >= MAX_SESS_STKCTR) {
			memprintf(err, "invalid stick table track ID '%s' for '%s'. The max allowed ID is %d",
				  cmd_name, args[*arg-1], MAX_SESS_STKCTR-1);
			return ACT_RET_PRS_ERR;
		}
	}
	rule->action_ptr = action_add_gpc;

	/* value may be either an integer or an expression */
	rule->arg.gpc.expr = NULL;
	rule->arg.gpc.value = strtol(args[*arg], &error, 10);
	if (*error == '\0') {
		/* valid integer, skip it */
		(*arg)++;
	} else {
		rule->arg.gpc.expr = sample_parse_expr((char **)args, arg, px->conf.args.file,
		                                       px->conf.args.line, err, &px->conf.args, NULL);
		if (!rule->arg.gpc.expr)
			return ACT_RET_PRS_ERR;

		switch (rule->from) {
		case ACT_F_TCP_REQ_CON: smp_val = SMP_VAL_FE_CON_ACC; break;
		case ACT_F_TCP_REQ_SES: smp_val = SMP_VAL_FE_SES_ACC; break;
		case ACT_F_TCP_REQ_CNT: smp_val = SMP_VAL_FE_REQ_CNT; break;
		case ACT_F_TCP_RES_CNT: smp_val = SMP_VAL_BE_RES_CNT; break;
		case ACT_F_HTTP_REQ:    smp_val = SMP_VAL_FE_HRQ_HDR; break;
		case ACT_F_HTTP_RES:    smp_val = SMP_VAL_BE_HRS_HDR; break;
		default:
			memprintf(err, "internal error, unexpected rule->from=%d, please report this bug!", rule->from);
			return ACT_RET_PRS_ERR;
		}

		if (!(rule->arg.gpc.expr->fetch->val & smp_val)) {
			memprintf(err, "fetch method '%s' extracts information from '%s', none of which is available here", args[*arg-1],
			          sample_src_names(rule->arg.gpc.expr->fetch->use));
			free(rule->arg.gpc.expr);
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

	BUG_ON(num > 9, "unexpected value");

	/* Here, <num> contains the counter number from 0 to 9 for
	 * the sc[0-9]_ form, or even higher using sc_(num) if needed.
	 * args[arg] is the first optional argument. We first lookup the
	 * ctr form the stream, then from the session if it was not there.
	 * But we must be sure the counter does not exceed global.tune.nb_stk_ctr.
	 */
	if (num >= global.tune.nb_stk_ctr)
		return NULL;

	stkptr = NULL;
	if (strm && strm->stkctr)
		stkptr = &strm->stkctr[num];
	if (!strm || !stkptr || !stkctr_entry(stkptr)) {
		if (sess->stkctr)
			stkptr = &sess->stkctr[num];
		else
			return NULL;
		if (!stkctr_entry(stkptr))
			return NULL;
	}

	stksess = stkctr_entry(stkptr);
	if (!stksess)
		return NULL;

	if (unlikely(args[arg].type == ARGT_TAB)) {
		/* an alternate table was specified, let's look up the same key there
		 * unless the table key type or length differs from the tracked one
		 */
		if (args[arg].data.t->type != stkptr->table->type ||
		    args[arg].data.t->key_size != stkptr->table->key_size)
			return NULL;
		stkctr->table = args[arg].data.t;
		stkctr_set_entry(stkctr, stktable_lookup(stkctr->table, stksess));
		return stkctr;
	}
	return stkptr;
}

/* same as smp_fetch_sc_stkctr() but dedicated to src_* and can create
 * the entry if it doesn't exist yet and <create> is set to 1.
 */
struct stkctr *
smp_fetch_src_stkctr(struct session *sess, struct stream *strm,
                     const struct arg *args, struct stkctr *stkctr, int create)
{
	struct stksess *entry;
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

	entry = smp_fetch_stksess(args->data.t, &smp, create);

	stkctr->table = args->data.t;
	stkctr_set_entry(stkctr, entry);
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

static int smp_fetch_get_gpt(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPT, idx);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args + 1, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_get_gpt(stkctr, smp, idx, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_get_gpt0(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPT0);
		if (!ptr)
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPT, 0);

		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_get_gpt0(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_get_gpc(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr  = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, idx);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args + 1, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_get_gpc(stkctr, smp, idx, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_get_gpc0(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
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
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_get_gpc0(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_get_gpc1(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
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
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_get_gpc1(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_gpc_rate(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC_RATE, idx);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
		                   stkctr->table->data_arg[STKTABLE_DT_GPC_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args + 1, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_gpc_rate(stkctr, smp, idx, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_gpc0_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	unsigned int period;

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
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp), period);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_gpc0_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_gpc1_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	unsigned int period;

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
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp), period);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_gpc1_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_inc_gpc(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

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
			stktable_touch_local(stkctr->table, stkctr_entry(stkctr), decrefcnt);
		}
		else if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args + 1, &tmpstkctr, 1);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_inc_gpc(stkctr, smp, idx, (stkctr == &tmpstkctr) ? 1 : 0);
}


static int smp_fetch_inc_gpc0(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	unsigned int period = 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

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
			stktable_touch_local(stkctr->table, stkctr_entry(stkctr), decrefcnt);
		}
		else if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 1);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_inc_gpc0(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_inc_gpc1(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	unsigned int period = 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

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
			stktable_touch_local(stkctr->table, stkctr_entry(stkctr), (decrefcnt) ? 1 : 0);
		}
		else if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 1);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_inc_gpc1(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_clr_gpc(struct stkctr *stkctr, struct sample *smp, unsigned int idx, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr && stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, idx);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);
		stktable_data_cast(ptr, std_t_uint) = 0;

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		/* If data was modified, we need to touch to re-schedule sync */
		stktable_touch_local(stkctr->table, stkctr_entry(stkctr), decrefcnt);
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args + 1, &tmpstkctr, 1);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args + 1, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_clr_gpc(stkctr, smp, idx, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_clr_gpc0(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr && stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC0);
		if (!ptr) {
			/* fallback on the gpc array */
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, 0);
		}

		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);
		stktable_data_cast(ptr, std_t_uint) = 0;

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		/* If data was modified, we need to touch to re-schedule sync */
		stktable_touch_local(stkctr->table, stkctr_entry(stkctr), decrefcnt);
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 1);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_clr_gpc0(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_clr_gpc1(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	if (stkctr && stkctr_entry(stkctr)) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC1);
		if (!ptr) {
			/* fallback on the gpc array */
			ptr = stktable_data_ptr_idx(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GPC, 1);
		}

		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);
		stktable_data_cast(ptr, std_t_uint) = 0;

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		/* If data was modified, we need to touch to re-schedule sync */
		stktable_touch_local(stkctr->table, stkctr_entry(stkctr), decrefcnt);
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 1);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_clr_gpc1(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_conn_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_CNT);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
			stktable_release(stkctr->table, stkctr_entry(stkctr));


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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_conn_cnt(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_conn_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_RATE);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_CONN_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_conn_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_updt_conn_cnt(struct stkctr *stkctr, struct sample *smp)
{
	void *ptr;

	if (!stkctr_entry(stkctr))
		return 0; /* not found */

	ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_CNT);
	if (!ptr) {
		return 0; /* parameter not stored in this table */
	}

	smp->data.type = SMP_T_SINT;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

	smp->data.u.sint = ++stktable_data_cast(ptr, std_t_uint);

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

	smp->flags = SMP_F_VOL_TEST;

	stktable_touch_local(stkctr->table, stkctr_entry(stkctr), 1);

	/* Touch was previously performed by stktable_update_key */
	return 1;
}

/* set temp integer to the number of connections from the stream's source address
 * in the table pointed to by expr, after updating it.
 * Accepts exactly 1 argument of type table.
 */
static int
smp_fetch_src_updt_conn_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 1);

	if (!stkctr)
		return 0;

	return smp_fetch_updt_conn_cnt(stkctr, smp);
}

static int smp_fetch_conn_cur(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_CONN_CUR);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_conn_cur(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_glitch_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GLITCH_CNT);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the cumulated number of glitches from the stream or session's
 * tracked frontend counters. Supports being called as "sc[0-9]_glitch_cnt" or
 * "src_glitch_cnt" only.
 */
static int
smp_fetch_sc_glitch_cnt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_glitch_cnt(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_glitch_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_GLITCH_RATE);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_GLITCH_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
			stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	return 1;
}

/* set <smp> to the rate of glitches from the stream or session's tracked
 * frontend counters. Supports being called as "sc[0-9]_glitch_rate" or
 * "src_glitch_rate" only.
 */
static int
smp_fetch_sc_glitch_rate(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_glitch_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_sess_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_CNT);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_sess_cnt(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_sess_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_SESS_RATE);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_SESS_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_sess_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_http_req_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_CNT);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_http_req_cnt(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_http_req_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_RATE);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_http_req_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_http_err_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_ERR_CNT);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_http_err_cnt(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_http_err_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_ERR_RATE);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_http_err_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_http_fail_cnt(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_FAIL_CNT);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_uint);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_http_fail_cnt(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_http_fail_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_FAIL_RATE);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_FAIL_RATE].u);

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_http_fail_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_kbytes_in(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_IN_CNT);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_ull) >> 10;

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_kbytes_in(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_bytes_in_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_IN_RATE);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = (uint64_t)read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
								  stkctr->table->data_arg[STKTABLE_DT_BYTES_IN_RATE].u) * stkctr->table->brates_factor;

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_bytes_in_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

static int smp_fetch_kbytes_out(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_OUT_CNT);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = stktable_data_cast(ptr, std_t_ull) >> 10;

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_kbytes_out(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
}

/* set <smp> to the key associated to the stream's tracked entry.
 * Supports being called as "sc[0-9]_key" or "sc_key" only.
 */
static int
smp_fetch_sc_key(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct stkctr tmpstkctr;
	struct stkctr *stkctr;
	struct stksess *entry;

	stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);
	if (!stkctr)
		return 0;

	entry = stkctr_entry(stkctr);
	if (entry != NULL) {
		int ret = stkey_to_smp(smp, stksess_getkey(stkctr->table, entry), stkctr->table->type);

		if (stkctr == &tmpstkctr)
			stktable_release(stkctr->table, entry);

		return !!ret;
	}
	return 0; /* nothing currently tracked */
}

static int smp_fetch_bytes_out_rate(struct stkctr *stkctr, struct sample *smp, int decrefcnt)
{
	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;
	if (stkctr_entry(stkctr) != NULL) {
		void *ptr;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_BYTES_OUT_RATE);
		if (!ptr) {
			if (decrefcnt)
				stktable_release(stkctr->table, stkctr_entry(stkctr));
			return 0; /* parameter not stored */
		}

		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		smp->data.u.sint = (uint64_t)read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
								  stkctr->table->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u) * stkctr->table->brates_factor;

		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &stkctr_entry(stkctr)->lock);

		if (decrefcnt)
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

	if (strncmp(kw, "src_", 4) == 0)
		stkctr = smp_fetch_src_stkctr(smp->sess, smp->strm, args, &tmpstkctr, 0);
	else
		stkctr = smp_fetch_sc_stkctr(smp->sess, smp->strm, args, kw, &tmpstkctr);

	if (!stkctr)
		return 0;

	return smp_fetch_bytes_out_rate(stkctr, smp, (stkctr == &tmpstkctr) ? 1 : 0);
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
		smp->data.u.sint = stkctr_entry(stkctr) ? (HA_ATOMIC_LOAD(&stkctr_entry(stkctr)->ref_cnt) - 1) : 0;
		stktable_release(stkctr->table, stkctr_entry(stkctr));
	}
	else {
		smp->data.u.sint = stkctr_entry(stkctr) ? HA_ATOMIC_LOAD(&stkctr_entry(stkctr)->ref_cnt) : 0;
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

/* Dump the status of a table to a stream connector's
 * read buffer. It returns 0 if the output buffer is full
 * and needs to be called again, otherwise non-zero.
 */
static int table_dump_head_to_buffer(struct buffer *msg,
                                     struct appctx *appctx,
                                     struct stktable *t, struct stktable *target)
{
	struct stream *s = __sc_strm(appctx_sc(appctx));

	chunk_appendf(msg, "# table: %s, type: %s, size:%d, used:%d\n",
		     t->id, stktable_types[t->type].kw, t->size, t->current);

	/* any other information should be dumped here */

	if (target && (strm_li(s)->bind_conf->level & ACCESS_LVL_MASK) < ACCESS_LVL_OPER)
		chunk_appendf(msg, "# contents not dumped due to insufficient privileges\n");

	if (applet_putchk(appctx, msg) == -1)
		return 0;

	return 1;
}

/* Dump a table entry to a stream connector's
 * read buffer. It returns 0 if the output buffer is full
 * and needs to be called again, otherwise non-zero.
 */
static int table_dump_entry_to_buffer(struct buffer *msg,
                                      struct appctx *appctx,
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

	chunk_appendf(msg, " use=%d exp=%d shard=%d", HA_ATOMIC_LOAD(&entry->ref_cnt) - 1, tick_remain(now_ms, entry->expire), entry->shard);

	for (dt = 0; dt < STKTABLE_DATA_TYPES; dt++) {
		void *ptr;
		long long data;

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
					data = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
								    t->data_arg[dt].u);
					if (dt == STKTABLE_DT_BYTES_IN_RATE || dt == STKTABLE_DT_BYTES_OUT_RATE)
						data *= t->brates_factor;
					chunk_appendf(msg, "%llu", data);
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
			data = read_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
						    t->data_arg[dt].u);
			if (dt == STKTABLE_DT_BYTES_IN_RATE || dt == STKTABLE_DT_BYTES_OUT_RATE)
				data *= t->brates_factor;
			chunk_appendf(msg, "%llu", data);
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

	if (applet_putchk(appctx, msg) == -1)
		return 0;

	return 1;
}

/* appctx context used by the "show table" command */
struct show_table_ctx {
	void *target;                               /* table we want to dump, or NULL for all */
	struct stktable *t;                         /* table being currently dumped (first if NULL) */
	struct stksess *entry;                      /* last entry we were trying to dump (or first if NULL) */
	int tree_head;                              /* tree head currently being visited */
	long long value[STKTABLE_FILTER_LEN];       /* value to compare against */
	signed char data_type[STKTABLE_FILTER_LEN]; /* type of data to compare, or -1 if none */
	signed char data_op[STKTABLE_FILTER_LEN];   /* operator (STD_OP_*) when data_type set */
	unsigned int data_idx[STKTABLE_FILTER_LEN]; /* index of data to consider for array types */
	enum {
		STATE_NEXT = 0,                     /* px points to next table, entry=NULL */
		STATE_DUMP,                         /* px points to curr table, entry is valid, refcount held */
		STATE_DONE,                         /* done dumping */
	} state;
	char action;                                /* action on the table : one of STK_CLI_ACT_* */
};

/* Processes a single table entry <ts>.
 * returns 0 if it wants to be called again, 1 if has ended processing.
 */
static int table_process_entry(struct appctx *appctx, struct stksess *ts, char **args)
{
	struct show_table_ctx *ctx = appctx->svcctx;
	struct stktable *t = ctx->target;
	long long value;
	int data_type;
	int cur_arg;
	void *ptr;
	struct freq_ctr *frqp;

	switch (t->type) {
	case SMP_T_IPV4:
	case SMP_T_IPV6:
	case SMP_T_SINT:
	case SMP_T_STR:
		break;
	default:
		switch (ctx->action) {
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

	if (!ts)
		return 1;

	switch (ctx->action) {
	case STK_CLI_ACT_SHOW:
		chunk_reset(&trash);
		if (!table_dump_head_to_buffer(&trash, appctx, t, t)) {
			stktable_release(t, ts);
			return 0;
		}
		HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ts->lock);
		if (!table_dump_entry_to_buffer(&trash, appctx, t, ts)) {
			HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);
			stktable_release(t, ts);
			return 0;
		}
		HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ts->lock);
		stktable_release(t, ts);
		break;

	case STK_CLI_ACT_CLR:
		if (!stksess_kill(t, ts)) {
			/* don't delete an entry which is currently referenced */
			return cli_err(appctx, "Entry currently in use, cannot remove\n");
		}
		break;

	case STK_CLI_ACT_SET:
		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
		for (cur_arg = 5; *args[cur_arg]; cur_arg += 2) {
			unsigned int idx;

			if (strncmp(args[cur_arg], "data.", 5) != 0) {
				cli_err(appctx, "\"data.<type>\" followed by a value expected\n");
				HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
				stktable_touch_local(t, ts, 1);
				return 1;
			}

			data_type = stktable_get_data_type_idx(args[cur_arg] + 5, &idx);
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

			if (stktable_data_types[data_type].is_array) {
				ptr = stktable_data_ptr_idx(t, ts, data_type, idx);
				if (!ptr) {
					cli_err(appctx, "index out of range in this data array\n");
					HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);
					stktable_touch_local(t, ts, 1);
					return 1;
				}
			}
			else
				ptr = __stktable_data_ptr(t, ts, data_type);

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

/* Processes a single table entry matching a specific key passed in argument.
 * returns 0 if wants to be called again, 1 if has ended processing.
 */
static int table_process_entry_per_key(struct appctx *appctx, char **args)
{
	struct show_table_ctx *ctx = appctx->svcctx;
	struct stktable *t = ctx->target;
	struct stksess *ts;
	struct sample key;

	if (!*args[4])
		return cli_err(appctx, "Key value expected\n");

	memset(&key, 0, sizeof(key));
	key.data.type = SMP_T_STR;
	key.data.u.str.area = args[4];
	key.data.u.str.data = strlen(args[4]);

	switch (t->type) {
	case SMP_T_IPV4:
	case SMP_T_IPV6:
		/* prefer input format over table type when parsing ip addresses,
		 * then let smp_to_stkey() do the conversion for us when needed
		 */
		BUG_ON(!sample_casts[key.data.type][SMP_T_ADDR]);
		if (!sample_casts[key.data.type][SMP_T_ADDR](&key))
			return cli_err(appctx, "Invalid key\n");
		break;
	default:
		/* nothing to do */
		break;
	}

	/* try to convert key according to table type
	 * (it will fill static_table_key on success)
	 */
	if (!smp_to_stkey(&key, t))
		return cli_err(appctx, "Invalid key\n");

	if (ctx->action == STK_CLI_ACT_SET) {
		ts = stktable_get_entry(t, &static_table_key);
		if (!ts)
			return cli_err(appctx, "Unable to allocate a new entry\n");
	} else
		ts = stktable_lookup_key(t, &static_table_key);

	return table_process_entry(appctx, ts, args);
}

/* Processes a single table entry matching a specific ptr passed in argument.
 * returns 0 if wants to be called again, 1 if has ended processing.
 */
static int table_process_entry_per_ptr(struct appctx *appctx, char **args)
{
	struct show_table_ctx *ctx = appctx->svcctx;
	struct stktable *t = ctx->target;
	ulong ptr;
	char *error;
	struct stksess *ts;

	if (!*args[4] || args[4][0] != '0' || args[4][1] != 'x')
		return cli_err(appctx, "Pointer expected (0xffff notation)\n");

	/* Convert argument to integer value */
	ptr = strtoul(args[4], &error, 16);
	if (*error != '\0')
		return cli_err(appctx, "Malformed ptr.\n");

	ts = stktable_lookup_ptr(t, (void *)ptr);
	if (!ts)
		return cli_err(appctx, "No entry can be found matching ptr.\n");

	return table_process_entry(appctx, ts, args);
}

/* Prepares the appctx fields with the data-based filters from the command line.
 * Returns 0 if the dump can proceed, 1 if has ended processing.
 */
static int table_prepare_data_request(struct appctx *appctx, char **args)
{
	struct show_table_ctx *ctx = appctx->svcctx;
	int i;
	char *err = NULL;

	if (ctx->action != STK_CLI_ACT_SHOW && ctx->action != STK_CLI_ACT_CLR)
		return cli_err(appctx, "content-based lookup is only supported with the \"show\" and \"clear\" actions\n");

	for (i = 0; i < STKTABLE_FILTER_LEN; i++) {
		if (i > 0 && !*args[3+3*i])  // number of filter entries can be less than STKTABLE_FILTER_LEN
			break;
		/* condition on stored data value */
		ctx->data_type[i] = stktable_get_data_type_idx(args[3+3*i] + 5, &ctx->data_idx[i]);
		if (ctx->data_type[i] < 0)
			return cli_dynerr(appctx, memprintf(&err, "Filter entry #%i: Unknown data type\n", i + 1));

		if (!((struct stktable *)ctx->target)->data_ofs[ctx->data_type[i]])
			return cli_dynerr(appctx, memprintf(&err, "Filter entry #%i: Data type not stored in this table\n", i + 1));

		ctx->data_op[i] = get_std_op(args[4+3*i]);
		if (ctx->data_op[i] < 0)
			return cli_dynerr(appctx, memprintf(&err, "Filter entry #%i: Require and operator among \"eq\", \"ne\", \"le\", \"ge\", \"lt\", \"gt\"\n", i + 1));

		if (!*args[5+3*i] || strl2llrc(args[5+3*i], strlen(args[5+3*i]), &ctx->value[i]) != 0)
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
	struct show_table_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int i;

	for (i = 0; i < STKTABLE_FILTER_LEN; i++)
		ctx->data_type[i] = -1;
	ctx->target = NULL;
	ctx->entry = NULL;
	ctx->action = (long)private; // keyword argument, one of STK_CLI_ACT_*

	if (*args[2]) {
		ctx->t = ctx->target = stktable_find_by_name(args[2]);
		if (!ctx->target)
			return cli_err(appctx, "No such table\n");
	}
	else {
		ctx->t = stktables_list;
		if (ctx->action != STK_CLI_ACT_SHOW)
			goto err_args;
		return 0;
	}

	if (strcmp(args[3], "key") == 0)
		return table_process_entry_per_key(appctx, args);
	if (strcmp(args[3], "ptr") == 0)
		return table_process_entry_per_ptr(appctx, args);
	else if (strncmp(args[3], "data.", 5) == 0)
		return table_prepare_data_request(appctx, args);
	else if (*args[3])
		goto err_args;

	return 0;

err_args:
	switch (ctx->action) {
	case STK_CLI_ACT_SHOW:
		return cli_err(appctx, "Optional argument only supports \"data.<store_data_type>\" <operator> <value> or key <key> or ptr <ptr>\n");
	case STK_CLI_ACT_CLR:
		return cli_err(appctx, "Required arguments: <table> \"data.<store_data_type>\" <operator> <value> or <table> key <key> or <table> ptr <ptr>\n");
	case STK_CLI_ACT_SET:
		return cli_err(appctx, "Required arguments: <table> key <key> [data.<store_data_type> <value>]* or <table> ptr <ptr> [data.<store_data_type> <value>]*\n");
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
	struct show_table_ctx *ctx = appctx->svcctx;
	struct stconn *sc = appctx_sc(appctx);
	struct stream *s = __sc_strm(sc);
	struct ebmb_node *eb;
	int skip_entry;
	int show = ctx->action == STK_CLI_ACT_SHOW;
	int shard = ctx->tree_head;

	/*
	 * We have 3 possible states in ctx->state :
	 *   - STATE_NEXT : the proxy pointer points to the next table to
	 *     dump, the entry pointer is NULL ;
	 *   - STATE_DUMP : the proxy pointer points to the current table
	 *     and the entry pointer points to the next entry to be dumped,
	 *     and the refcount on the next entry is held ;
	 *   - STATE_DONE : nothing left to dump, the buffer may contain some
	 *     data though.
	 */

	chunk_reset(&trash);

	while (ctx->state != STATE_DONE) {
		switch (ctx->state) {
		case STATE_NEXT:
			if (!ctx->t ||
			    (ctx->target &&
			     ctx->t != ctx->target)) {
				ctx->state = STATE_DONE;
				break;
			}

			if (ctx->t->size) {
				if (show && !shard && !table_dump_head_to_buffer(&trash, appctx, ctx->t, ctx->target))
					return 0;

				if (ctx->target &&
				    (strm_li(s)->bind_conf->level & ACCESS_LVL_MASK) >= ACCESS_LVL_OPER) {
					/* dump entries only if table explicitly requested */
					HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &ctx->t->shards[shard].sh_lock);
					eb = ebmb_first(&ctx->t->shards[shard].keys);
					if (eb) {
						ctx->entry = ebmb_entry(eb, struct stksess, key);
						HA_ATOMIC_INC(&ctx->entry->ref_cnt);
						ctx->state = STATE_DUMP;
						HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &ctx->t->shards[shard].sh_lock);
						break;
					}
					HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &ctx->t->shards[shard].sh_lock);

					/* we come here if we didn't find any entry in this shard */
					shard = ++ctx->tree_head;
					if (shard < CONFIG_HAP_TBL_BUCKETS)
						break; // try again on new shard

					/* fall through next table */
					shard = ctx->tree_head = 0;
				}
			}
			ctx->t = ctx->t->next;
			break;

		case STATE_DUMP:
			skip_entry = 0;

			HA_RWLOCK_RDLOCK(STK_SESS_LOCK, &ctx->entry->lock);

			if (ctx->data_type[0] >= 0) {
				/* we're filtering on some data contents */
				void *ptr;
				int dt, i;
				signed char op;
				long long data, value;


				for (i = 0; i < STKTABLE_FILTER_LEN; i++) {
					if (ctx->data_type[i] == -1)
						break;
					dt = ctx->data_type[i];
					if (stktable_data_types[dt].is_array) {
						ptr = stktable_data_ptr_idx(ctx->t,
									    ctx->entry,
									    dt, ctx->data_idx[i]);
						if (!ptr) {
							/* index out of range */
							skip_entry = 1;
							break;
						}
					}
					else {
						ptr = stktable_data_ptr(ctx->t,
									ctx->entry,
									dt);
						/* table_prepare_data_request() normally ensures the
						 * type is both valid and stored
						 */
						BUG_ON(!ptr);
					}

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
									    ctx->t->data_arg[dt].u);
						if (dt == STKTABLE_DT_BYTES_IN_RATE || dt == STKTABLE_DT_BYTES_OUT_RATE)
							data *= ctx->t->brates_factor;
						break;
					}

					op = ctx->data_op[i];
					value = ctx->value[i];

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
			    !table_dump_entry_to_buffer(&trash, appctx, ctx->t, ctx->entry)) {
				HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ctx->entry->lock);
				return 0;
			}

			HA_RWLOCK_RDUNLOCK(STK_SESS_LOCK, &ctx->entry->lock);

			HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &ctx->t->shards[shard].sh_lock);
			HA_ATOMIC_DEC(&ctx->entry->ref_cnt);

			eb = ebmb_next(&ctx->entry->key);
			if (eb) {
				struct stksess *old = ctx->entry;
				ctx->entry = ebmb_entry(eb, struct stksess, key);
				if (show)
					__stksess_kill_if_expired(ctx->t, old);
				else if (!skip_entry && !ctx->entry->ref_cnt)
					__stksess_kill(ctx->t, old);
				HA_ATOMIC_INC(&ctx->entry->ref_cnt);
				HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &ctx->t->shards[shard].sh_lock);
				break;
			}


			if (show)
				__stksess_kill_if_expired(ctx->t, ctx->entry);
			else if (!skip_entry && !HA_ATOMIC_LOAD(&ctx->entry->ref_cnt))
				__stksess_kill(ctx->t, ctx->entry);

			HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &ctx->t->shards[shard].sh_lock);

			shard = ++ctx->tree_head;
			if (shard >= CONFIG_HAP_TBL_BUCKETS) {
				shard = ctx->tree_head = 0;
				ctx->t = ctx->t->next;
			}
			ctx->state = STATE_NEXT;
			break;

		default:
			break;
		}
	}
	return 1;
}

static void cli_release_show_table(struct appctx *appctx)
{
	struct show_table_ctx *ctx = appctx->svcctx;

	if (ctx->state == STATE_DUMP) {
		stksess_kill_if_expired(ctx->t, ctx->entry);
	}
}

static int stk_parse_stick_counters(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	char *error;
	int counters;

	counters = strtol(args[1], &error, 10);
	if (*error != 0) {
		memprintf(err, "%s: '%s' is an invalid number", args[0], args[1]);
		return -1;
	}

	if (counters < 0) {
		memprintf(err, "%s: the number of stick-counters may not be negative (was %d)", args[0], counters);
		return -1;
	}

	global.tune.nb_stk_ctr = counters;
	return 0;
}

/* This function creates the stk_ctr pools after the configuration parsing. It
 * returns 0 on success otherwise ERR_*. If nb_stk_ctr is 0, the pool remains
 * NULL.
 */
static int stkt_create_stk_ctr_pool(void)
{
	if (!global.tune.nb_stk_ctr)
		return 0;

	pool_head_stk_ctr = create_pool("stk_ctr", sizeof(*((struct session*)0)->stkctr) * global.tune.nb_stk_ctr, MEM_F_SHARED);
	if (!pool_head_stk_ctr) {
		ha_alert("out of memory while creating the stick-counters pool.\n");
		return ERR_ABORT;
	}
	return 0;
}

static void stkt_late_init(void)
{
	struct sample_fetch *f;

	f = find_sample_fetch("src", strlen("src"));
	if (f)
		smp_fetch_src = f->process;
	hap_register_post_check(stkt_create_stk_ctr_pool);
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
	{ "sc-add-gpc",  parse_add_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_conn_keywords_register, &tcp_conn_kws);

static struct action_kw_list tcp_sess_kws = { { }, {
	{ "sc-add-gpc",  parse_add_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_sess_keywords_register, &tcp_sess_kws);

static struct action_kw_list tcp_req_kws = { { }, {
	{ "sc-add-gpc",  parse_add_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_req_cont_keywords_register, &tcp_req_kws);

static struct action_kw_list tcp_res_kws = { { }, {
	{ "sc-add-gpc",  parse_add_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, tcp_res_cont_keywords_register, &tcp_res_kws);

static struct action_kw_list http_req_kws = { { }, {
	{ "sc-add-gpc",  parse_add_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_kws);

static struct action_kw_list http_res_kws = { { }, {
	{ "sc-add-gpc",  parse_add_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_res_keywords_register, &http_res_kws);

static struct action_kw_list http_after_res_kws = { { }, {
	{ "sc-add-gpc",  parse_add_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc",  parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc0", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-inc-gpc1", parse_inc_gpc,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt",  parse_set_gpt,  KWF_MATCH_PREFIX },
	{ "sc-set-gpt0", parse_set_gpt,  KWF_MATCH_PREFIX },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_after_res_keywords_register, &http_after_res_kws);

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
	{ "sc_glitch_cnt",      smp_fetch_sc_glitch_cnt,     ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc_glitch_rate",     smp_fetch_sc_glitch_rate,    ARG2(1,SINT,TAB), NULL, SMP_T_SINT, SMP_USE_INTRN, },
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
	{ "sc_key",             smp_fetch_sc_key,            ARG1(1,SINT),     NULL, SMP_T_ANY,  SMP_USE_INTRN, },
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
	{ "sc0_glitch_cnt",     smp_fetch_sc_glitch_cnt,     ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc0_glitch_rate",    smp_fetch_sc_glitch_rate,    ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
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
	{ "sc0_key",            smp_fetch_sc_key,            0,                NULL, SMP_T_ANY,  SMP_USE_INTRN, },
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
	{ "sc1_glitch_cnt",     smp_fetch_sc_glitch_cnt,     ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc1_glitch_rate",    smp_fetch_sc_glitch_rate,    ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
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
	{ "sc1_key",            smp_fetch_sc_key,            0,                NULL, SMP_T_ANY,  SMP_USE_INTRN, },
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
	{ "sc2_glitch_cnt",     smp_fetch_sc_glitch_cnt,     ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
	{ "sc2_glitch_rate",    smp_fetch_sc_glitch_rate,    ARG1(0,TAB),      NULL, SMP_T_SINT, SMP_USE_INTRN, },
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
	{ "sc2_key",            smp_fetch_sc_key,            0,                NULL, SMP_T_ANY,  SMP_USE_INTRN, },
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
	{ "src_glitch_cnt",     smp_fetch_sc_glitch_cnt,     ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
	{ "src_glitch_rate",    smp_fetch_sc_glitch_rate,    ARG1(1,TAB),      NULL, SMP_T_SINT, SMP_USE_L4CLI, },
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
	{ "table_clr_gpc",        sample_conv_table_clr_gpc,        ARG2(2,SINT,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_clr_gpc0",       sample_conv_table_clr_gpc0,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_clr_gpc1",       sample_conv_table_clr_gpc1,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_conn_cnt",       sample_conv_table_conn_cnt,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_conn_cur",       sample_conv_table_conn_cur,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_conn_rate",      sample_conv_table_conn_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_expire",         sample_conv_table_expire,         ARG2(1,TAB,SINT),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpt",            sample_conv_table_gpt,            ARG2(2,SINT,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpt0",           sample_conv_table_gpt0,           ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc",            sample_conv_table_gpc,            ARG2(2,SINT,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc0",           sample_conv_table_gpc0,           ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc1",           sample_conv_table_gpc1,           ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc_rate",       sample_conv_table_gpc_rate,       ARG2(2,SINT,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc0_rate",      sample_conv_table_gpc0_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_gpc1_rate",      sample_conv_table_gpc1_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_glitch_cnt",     sample_conv_table_glitch_cnt,     ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_glitch_rate",    sample_conv_table_glitch_rate,    ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_err_cnt",   sample_conv_table_http_err_cnt,   ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_err_rate",  sample_conv_table_http_err_rate,  ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_fail_cnt",  sample_conv_table_http_fail_cnt,  ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_fail_rate", sample_conv_table_http_fail_rate, ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_req_cnt",   sample_conv_table_http_req_cnt,   ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_http_req_rate",  sample_conv_table_http_req_rate,  ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_idle",           sample_conv_table_idle,           ARG2(1,TAB,SINT),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_inc_gpc",        sample_conv_table_inc_gpc,        ARG2(2,SINT,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_inc_gpc0",       sample_conv_table_inc_gpc0,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_inc_gpc1",       sample_conv_table_inc_gpc1,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_kbytes_in",      sample_conv_table_kbytes_in,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_kbytes_out",     sample_conv_table_kbytes_out,     ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_server_id",      sample_conv_table_server_id,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_sess_cnt",       sample_conv_table_sess_cnt,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_sess_rate",      sample_conv_table_sess_rate,      ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ "table_trackers",       sample_conv_table_trackers,       ARG1(1,TAB),  NULL, SMP_T_ANY,  SMP_T_SINT  },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);

static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "tune.stick-counters", stk_parse_stick_counters },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);


#if defined(USE_PROMEX)

static int stk_promex_metric_info(unsigned int id, struct promex_metric *metric, struct ist *desc)
{
	switch (id) {
		case STICKTABLE_SIZE:
			*metric = (struct promex_metric){ .n = ist("size"), .type = PROMEX_MT_GAUGE, .flags = PROMEX_FL_MODULE_METRIC };
			*desc = ist("Stick table size.");
			break;
		case STICKTABLE_USED:
			*metric = (struct promex_metric){ .n = ist("used"), .type = PROMEX_MT_GAUGE, .flags = PROMEX_FL_MODULE_METRIC };
			*desc = ist("Number of entries used in this stick table.");
			break;
		default:
			return -1;
	}
	return 1;
}

static void *stk_promex_start_ts(void *unused, unsigned int id)
{
	return stktables_list;
}

static void *stk_promex_next_ts(void *unused, void *metric_ctx, unsigned int id)
{
	struct stktable *t = metric_ctx;

	return t->next;
}

static int stk_promex_fill_ts(void *unused, void *metric_ctx, unsigned int id, struct promex_label *labels, struct field *field)
{
	struct stktable *t = metric_ctx;

	if (!t->size)
		return 0;

	labels[0].name  = ist("name");
	labels[0].value = ist(t->id);
	labels[1].name  = ist("type");
	labels[1].value = ist(stktable_types[t->type].kw);

	switch (id) {
		case STICKTABLE_SIZE:
			*field = mkf_u32(FN_GAUGE, t->size);
			break;
		case STICKTABLE_USED:
			*field = mkf_u32(FN_GAUGE, t->current);
			break;
		default:
			return -1;
	}
	return 1;
}

static struct promex_module promex_sticktable_module = {
	.name        = IST("sticktable"),
	.metric_info = stk_promex_metric_info,
	.start_ts    = stk_promex_start_ts,
	.next_ts     = stk_promex_next_ts,
	.fill_ts     = stk_promex_fill_ts,
	.nb_metrics  = STICKTABLE_TOTAL_FIELDS,
};

INITCALL1(STG_REGISTER, promex_register_module, &promex_sticktable_module);

#endif
