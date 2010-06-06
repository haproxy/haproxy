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

#include <types/stick_table.h>

#include <proto/pattern.h>
#include <proto/proxy.h>
#include <proto/session.h>
#include <proto/task.h>


/* static structure used to return a table key built from a pattern */
static struct stktable_key static_table_key;

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
 * Initialize or update the key in the sticky session <ts> present in table <t>
 * from the value present in <key>.
 */
void stksess_setkey(struct stktable *t, struct stksess *ts, struct stktable_key *key)
{
	if (t->type != STKTABLE_TYPE_STRING)
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
	ts->sid = 0;
	ts->key.node.leaf_p = NULL;
	ts->exp.node.leaf_p = NULL;
	return ts;
}

/*
 * Trash oldest <to_batch> sticky sessions from table <t>
 * Returns number of trashed sticky sessions.
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
		ts = eb32_entry(eb, struct stksess, exp);
		eb = eb32_next(eb);

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
		stksess_free(t, ts);
		batched++;
	}

	return batched;
}

/*
 * Allocate and initialise a new sticky session.
 * The new sticky session is returned or NULL in case of lack of memory.
 * Sticky sessions should only be allocated this way, and must be freed using
 * stksess_free(). Increase table <t> sticky session counter.
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

	ts = pool_alloc2(t->pool) + t->data_size;
	if (ts) {
		t->current++;
		stksess_init(t, ts);
		stksess_setkey(t, ts, key);
	}

	return ts;
}

/*
 * Looks in table <t> for a sticky session matching <key>.
 * Returns pointer on requested sticky session or NULL if none was found.
 */
struct stksess *stktable_lookup(struct stktable *t, struct stktable_key *key)
{
	struct ebmb_node *eb;

	if (t->type == STKTABLE_TYPE_STRING)
		eb = ebst_lookup_len(&t->keys, key->key, key->key_len);
	else
		eb = ebmb_lookup(&t->keys, key->key, t->key_size);

	if (unlikely(!eb)) {
		/* no session found */
		return NULL;
	}

	return ebmb_entry(eb, struct stksess, key);
}

/* Try to store sticky session <ts> in the table. If another entry already
 * exists with the same key, its server ID is updated with <sid> and a non
 * zero value is returned so that the caller knows it can release its stksess.
 * If no similar entry was present, <ts> is inserted into the tree and assigned
 * server ID <sid>. Zero is returned in this case, and the caller must not
 * release the stksess.
 */
int stktable_store(struct stktable *t, struct stksess *ts, int sid)
{
	struct ebmb_node *eb;

	if (t->type == STKTABLE_TYPE_STRING)
		eb = ebst_lookup(&(t->keys), (char *)ts->key.key);
	else
		eb = ebmb_lookup(&(t->keys), ts->key.key, t->key_size);

	if (unlikely(!eb)) {
		/* no existing session, insert ours */
		ts->sid = sid;
		ebmb_insert(&t->keys, &ts->key, t->key_size);

		ts->exp.key = ts->expire = tick_add(now_ms, MS_TO_TICKS(t->expire));
		eb32_insert(&t->exps, &ts->exp);

		if (t->expire) {
			t->exp_task->expire = t->exp_next = tick_first(ts->expire, t->exp_next);
			task_queue(t->exp_task);
		}
		return 0;
	}

	ts = ebmb_entry(eb, struct stksess, key);

	if ( ts->sid != sid )
		ts->sid = sid;
	return 1;
}

/*
 * Trash expired sticky sessions from table <t>. The next expiration date is
 * returned.
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
		ts = eb32_entry(eb, struct stksess, exp);
		eb = eb32_next(eb);

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

		t->pool = create_pool("sticktables", sizeof(struct stksess) + t->data_size + t->key_size, MEM_F_SHARED);

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
						        { "string", STK_F_CUSTOM_KEYSIZE, 32 } };


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

		if (stktable_types[*type].flags & STK_F_CUSTOM_KEYSIZE) {
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

/*****************************************************************/
/*    typed pattern to typed table key functions                 */
/*****************************************************************/

static void *k_int2int(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	return (void *)&pdata->integer;
}

static void *k_ip2ip(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	return (void *)&pdata->ip.s_addr;
}

static void *k_ip2int(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	kdata->integer = ntohl(pdata->ip.s_addr);
	return (void *)&kdata->integer;
}

static void *k_int2ip(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	kdata->ip.s_addr = htonl(pdata->integer);
	return (void *)&kdata->ip.s_addr;
}

static void *k_str2str(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	*len = pdata->str.len;
	return (void *)pdata->str.str;
}

static void *k_ip2str(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	if (!inet_ntop(AF_INET, &pdata->ip, kdata->buf, sizeof(kdata->buf)))
		return NULL;

	*len = strlen((const char *)kdata->buf);
	return (void *)kdata->buf;
}

static void *k_int2str(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	void *key;

	key = (void *)ultoa_r(pdata->integer,  kdata->buf,  sizeof(kdata->buf));
	if (!key)
		return NULL;

	*len = strlen((const char *)key);
	return key;
}

static void *k_str2ip(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	if (!buf2ip(pdata->str.str, pdata->str.len, &kdata->ip))
		return NULL;

	return (void *)&kdata->ip.s_addr;
}


static void *k_str2int(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	int i;

	kdata->integer = 0;
	for (i = 0; i < pdata->str.len; i++) {
		uint32_t val = pdata->str.str[i] - '0';

		if (val > 9)
			break;

		kdata->integer = kdata->integer * 10 + val;
	}
	return (void *)&kdata->integer;
}

/*****************************************************************/
/*      typed pattern to typed table key matrix:                 */
/*         pattern_to_key[from pattern type][to table key type]  */
/*         NULL pointer used for impossible pattern casts        */
/*****************************************************************/

typedef void *(*pattern_to_key_fct)(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len);
static pattern_to_key_fct pattern_to_key[PATTERN_TYPES][STKTABLE_TYPES] = {
	{ k_ip2ip,  k_ip2int,  k_ip2str  },
	{ k_int2ip, k_int2int, k_int2str },
	{ k_str2ip, k_str2int, k_str2str },
};


/*
 * Process a fetch + format conversion as defined by the pattern expression <expr>
 * on request or response considering the <dir> parameter. Returns either NULL if
 * no key could be extracted, or a pointer to the converted result stored in
 * static_table_key in format <table_type>.
 */
struct stktable_key *stktable_fetch_key(struct proxy *px, struct session *l4, void *l7, int dir,
					struct pattern_expr *expr, unsigned long table_type)
{
	struct pattern *ptrn;

	ptrn = pattern_process(px, l4, l7, dir, expr, NULL);
	if (!ptrn)
		return NULL;

	static_table_key.key_len = (size_t)-1;
	static_table_key.key = pattern_to_key[ptrn->type][table_type](&ptrn->data, &static_table_key.data, &static_table_key.key_len);

	if (!static_table_key.key)
		return NULL;

	return &static_table_key;
}

/*
 * Returns 1 if pattern expression <expr> result can be converted to table key of
 * type <table_type>, otherwise zero. Used in configuration check.
 */
int stktable_compatible_pattern(struct pattern_expr *expr, unsigned long table_type)
{
	if (table_type >= STKTABLE_TYPES)
		return 0;

	if (LIST_ISEMPTY(&expr->conv_exprs)) {
		if (!pattern_to_key[expr->fetch->out_type][table_type])
			return 0;
	} else {
		struct pattern_conv_expr *conv_expr;
		conv_expr = LIST_PREV(&expr->conv_exprs, typeof(conv_expr), list);

		if (!pattern_to_key[conv_expr->conv->out_type][table_type])
			return 0;
	}
	return 1;
}

/* Extra data types processing */
struct stktable_data_type stktable_data_types[STKTABLE_DATA_TYPES] = {
	[STKTABLE_DT_CONN_CUM] = { .name = "conn_cum", .data_length = stktable_data_size(conn_cum) },
};

/*
 * Returns the data type number for the stktable_data_type whose name is <name>,
 * or <0 if not found.
 */
int stktable_get_data_type(char *name)
{
	int type;

	for (type = 0; type < STKTABLE_DATA_TYPES; type++) {
		if (strcmp(name, stktable_data_types[type].name) == 0)
			return type;
	}
	return -1;
}

