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

#include <common/config.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>

#include <ebmbtree.h>
#include <ebsttree.h>

#include <proto/arg.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/stream.h>
#include <proto/stick_table.h>
#include <proto/task.h>
#include <proto/peers.h>
#include <types/global.h>

/* structure used to return a table key built from a sample */
struct stktable_key *static_table_key;

/*
 * Free an allocated sticky session <ts>, and decrease sticky sessions counter
 * in table <t>.
 */
void stksess_free(struct stktable *t, struct stksess *ts)
{
	t->current--;
	pool_free2(t->pool, (void *)ts - t->data_size);
}

/*
 * Kill an stksess (only if its ref_cnt is zero).
 */
void stksess_kill(struct stktable *t, struct stksess *ts)
{
	if (ts->ref_cnt)
		return;

	eb32_delete(&ts->exp);
	eb32_delete(&ts->upd);
	ebmb_delete(&ts->key);
	stksess_free(t, ts);
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
static struct stksess *stksess_init(struct stktable *t, struct stksess * ts)
{
	memset((void *)ts - t->data_size, 0, t->data_size);
	ts->ref_cnt = 0;
	ts->key.node.leaf_p = NULL;
	ts->exp.node.leaf_p = NULL;
	ts->upd.node.leaf_p = NULL;
	return ts;
}

/*
 * Trash oldest <to_batch> sticky sessions from table <t>
 * Returns number of trashed sticky sessions.
 */
int stktable_trash_oldest(struct stktable *t, int to_batch)
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
		stksess_free(t, ts);
		batched++;
	}

	return batched;
}

/*
 * Allocate and initialise a new sticky session.
 * The new sticky session is returned or NULL in case of lack of memory.
 * Sticky sessions should only be allocated this way, and must be freed using
 * stksess_free(). Table <t>'s sticky session counter is increased. If <key>
 * is not NULL, it is assigned to the new session.
 */
struct stksess *stksess_new(struct stktable *t, struct stktable_key *key)
{
	struct stksess *ts;

	if (unlikely(t->current == t->size)) {
		if ( t->nopurge )
			return NULL;

		if (!stktable_trash_oldest(t, (t->size >> 8) + 1))
			return NULL;
	}

	ts = pool_alloc2(t->pool) + t->data_size;
	if (ts) {
		t->current++;
		stksess_init(t, ts);
		if (key)
			stksess_setkey(t, ts, key);
	}

	return ts;
}

/*
 * Looks in table <t> for a sticky session matching key <key>.
 * Returns pointer on requested sticky session or NULL if none was found.
 */
struct stksess *stktable_lookup_key(struct stktable *t, struct stktable_key *key)
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

/* Lookup and touch <key> in <table>, or create the entry if it does not exist.
 * This is mainly used for situations where we want to refresh a key's usage so
 * that it does not expire, and we want to have it created if it was not there.
 * The stksess is returned, or NULL if it could not be created.
 */
struct stksess *stktable_update_key(struct stktable *table, struct stktable_key *key)
{
	struct stksess *ts;

	ts = stktable_lookup_key(table, key);
	if (likely(ts))
		return stktable_touch(table, ts, 1);

	/* entry does not exist, initialize a new one */
	ts = stksess_new(table, key);
	if (likely(ts))
		stktable_store(table, ts, 1);
	return ts;
}

/*
 * Looks in table <t> for a sticky session with same key as <ts>.
 * Returns pointer on requested sticky session or NULL if none was found.
 */
struct stksess *stktable_lookup(struct stktable *t, struct stksess *ts)
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

/* Update the expiration timer for <ts> but do not touch its expiration node.
 * The table's expiration timer is updated if set.
 */
struct stksess *stktable_touch(struct stktable *t, struct stksess *ts, int local)
{
	struct eb32_node * eb;
	ts->expire = tick_add(now_ms, MS_TO_TICKS(t->expire));
	if (t->expire) {
		t->exp_task->expire = t->exp_next = tick_first(ts->expire, t->exp_next);
		task_queue(t->exp_task);
	}

	/* If sync is enabled and update is local */
	if (t->sync_task && local) {
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
	return ts;
}

/* Insert new sticky session <ts> in the table. It is assumed that it does not
 * yet exist (the caller must check this). The table's timeout is updated if it
 * is set. <ts> is returned.
 */
struct stksess *stktable_store(struct stktable *t, struct stksess *ts, int local)
{
	ebmb_insert(&t->keys, &ts->key, t->key_size);
	stktable_touch(t, ts, local);
	ts->exp.key = ts->expire;
	eb32_insert(&t->exps, &ts->exp);
	return ts;
}

/* Returns a valid or initialized stksess for the specified stktable_key in the
 * specified table, or NULL if the key was NULL, or if no entry was found nor
 * could be created. The entry's expiration is updated.
 */
struct stksess *stktable_get_entry(struct stktable *table, struct stktable_key *key)
{
	struct stksess *ts;

	if (!key)
		return NULL;

	ts = stktable_lookup_key(table, key);
	if (ts == NULL) {
		/* entry does not exist, initialize a new one */
		ts = stksess_new(table, key);
		if (!ts)
			return NULL;
		stktable_store(table, ts, 1);
	}
	else
		stktable_touch(table, ts, 1);
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
			return t->exp_next;
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
		stksess_free(t, ts);
	}

	/* We have found no task to expire in any tree */
	t->exp_next = TICK_ETERNITY;
	return t->exp_next;
}

/*
 * Task processing function to trash expired sticky sessions. A pointer to the
 * task itself is returned since it never dies.
 */
static struct task *process_table_expire(struct task *task)
{
	struct stktable *t = (struct stktable *)task->context;

	task->expire = stktable_trash_expired(t);
	return task;
}

/* Perform minimal stick table intializations, report 0 in case of error, 1 if OK. */
int stktable_init(struct stktable *t)
{
	if (t->size) {
		memset(&t->keys, 0, sizeof(t->keys));
		memset(&t->exps, 0, sizeof(t->exps));
		t->updates = EB_ROOT_UNIQUE;

		t->pool = create_pool("sticktables", sizeof(struct stksess) + t->data_size + t->key_size, MEM_F_SHARED);

		t->exp_next = TICK_ETERNITY;
		if ( t->expire ) {
			t->exp_task = task_new();
			t->exp_task->process = process_table_expire;
			t->exp_task->expire = TICK_ETERNITY;
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
		static_table_key->key = &smp->data.u.ipv4;
		static_table_key->key_len = 4;
		break;

	case SMP_T_IPV6:
		static_table_key->key = &smp->data.u.ipv6;
		static_table_key->key_len = 16;
		break;

	case SMP_T_SINT:
		/* The stick table require a 32bit unsigned int, "sint" is a
		 * signed 64 it, so we can convert it inplace.
		 */
		*(unsigned int *)&smp->data.u.sint = (unsigned int)smp->data.u.sint;
		static_table_key->key = &smp->data.u.sint;
		static_table_key->key_len = 4;
		break;

	case SMP_T_STR:
		/* Must be NULL terminated. */
		if (smp->data.u.str.len >= smp->data.u.str.size ||
		    smp->data.u.str.str[smp->data.u.str.len] != '\0') {
			if (!smp_dup(smp))
				return NULL;
			if (smp->data.u.str.len >= smp->data.u.str.size)
				return NULL;
			smp->data.u.str.str[smp->data.u.str.len] = '\0';
		}
		static_table_key->key = smp->data.u.str.str;
		static_table_key->key_len = smp->data.u.str.len;
		break;

	case SMP_T_BIN:
		if (smp->data.u.str.len < t->key_size) {
			/* This type needs padding with 0. */
			if (smp->data.u.str.size < t->key_size)
				if (!smp_dup(smp))
					return NULL;
			if (smp->data.u.str.size < t->key_size)
				return NULL;
			memset(smp->data.u.str.str + smp->data.u.str.len, 0,
			       t->key_size - smp->data.u.str.len);
			smp->data.u.str.len = t->key_size;
		}
		static_table_key->key = smp->data.u.str.str;
		static_table_key->key_len = smp->data.u.str.len;
		break;

	default: /* impossible case. */
		return NULL;
	}

	return static_table_key;
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
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

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 0;

	ts = stktable_lookup_key(t, key);
	if (ts)
		smp->data.u.sint = ts->ref_cnt;

	return 1;
}

/* Always returns 1. */
static enum act_return action_inc_gpc0(struct act_rule *rule, struct proxy *px,
                                       struct session *sess, struct stream *s, int flags)
{
	void *ptr;
	struct stksess *ts;
	struct stkctr *stkctr;

	/* Extract the stksess, return OK if no stksess available. */
	if (s)
		stkctr = &s->stkctr[rule->arg.gpc.sc];
	else
		stkctr = &sess->stkctr[rule->arg.gpc.sc];
	ts = stkctr_entry(stkctr);
	if (!ts)
		return ACT_RET_CONT;

	/* Store the sample in the required sc, and ignore errors. */
	ptr = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GPC0);
	if (!ptr)
		return ACT_RET_CONT;

	stktable_data_cast(ptr, gpc0)++;
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
	if (ptr)
		stktable_data_cast(ptr, gpt0) = rule->arg.gpt.value;
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

static struct action_kw_list tcp_conn_kws = { { }, {
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

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "in_table",             sample_conv_in_table,             ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_BOOL  },
	{ "table_bytes_in_rate",  sample_conv_table_bytes_in_rate,  ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_bytes_out_rate", sample_conv_table_bytes_out_rate, ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_conn_cnt",       sample_conv_table_conn_cnt,       ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_conn_cur",       sample_conv_table_conn_cur,       ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_conn_rate",      sample_conv_table_conn_rate,      ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_gpt0",           sample_conv_table_gpt0,           ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_gpc0",           sample_conv_table_gpc0,           ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_gpc0_rate",      sample_conv_table_gpc0_rate,      ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_http_err_cnt",   sample_conv_table_http_err_cnt,   ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_http_err_rate",  sample_conv_table_http_err_rate,  ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_http_req_cnt",   sample_conv_table_http_req_cnt,   ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_http_req_rate",  sample_conv_table_http_req_rate,  ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_kbytes_in",      sample_conv_table_kbytes_in,      ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_kbytes_out",     sample_conv_table_kbytes_out,     ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_server_id",      sample_conv_table_server_id,      ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_sess_cnt",       sample_conv_table_sess_cnt,       ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_sess_rate",      sample_conv_table_sess_rate,      ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ "table_trackers",       sample_conv_table_trackers,       ARG1(1,TAB),  NULL, SMP_T_STR,  SMP_T_SINT  },
	{ /* END */ },
}};

__attribute__((constructor))
static void __stick_table_init(void)
{
	/* register som action keywords. */
	tcp_req_conn_keywords_register(&tcp_conn_kws);
	tcp_req_cont_keywords_register(&tcp_req_kws);
	tcp_res_cont_keywords_register(&tcp_res_kws);
	http_req_keywords_register(&http_req_kws);
	http_res_keywords_register(&http_res_kws);

	/* register sample fetch and format conversion keywords */
	sample_register_convs(&sample_conv_kws);
}
