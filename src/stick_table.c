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

#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/session.h>
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

	if (t->type == STKTABLE_TYPE_STRING)
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

	if (t->type == STKTABLE_TYPE_STRING)
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

	if (t->sync_task && local) {
		ts->upd.key = ++t->update;
		t->localupdate = t->update;
		eb32_delete(&ts->upd);
		eb = eb32_insert(&t->updates, &ts->upd);
		if (eb != &ts->upd)  {
			eb32_delete(eb);
			eb32_insert(&t->updates, &ts->upd);
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

		t->pool = create_pool("sticktables", sizeof(struct stksess) + t->data_size + t->key_size, MEM_F_SHARED);

		t->exp_next = TICK_ETERNITY;
		if ( t->expire ) {
			t->exp_task = task_new();
			t->exp_task->process = process_table_expire;
			t->exp_task->expire = TICK_ETERNITY;
			t->exp_task->context = (void *)t;
		}
		if (t->peers.p && t->peers.p->peers_fe) {
			peers_register_table(t->peers.p, t);
		}

		return t->pool != NULL;
	}
	return 1;
}

/*
 * Configuration keywords of known table types
 */
struct stktable_type stktable_types[STKTABLE_TYPES] =  {{ "ip", 0, 4 },
						        { "ipv6", 0, 16 },
						        { "integer", 0, 4 },
						        { "string", STK_F_CUSTOM_KEYSIZE, 32 },
						        { "binary", STK_F_CUSTOM_KEYSIZE, 32 } };


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
				if (!*key_size)
					break;
				if (*type == STKTABLE_TYPE_STRING) {
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

/*****************************************************************/
/*    typed sample to typed table key functions                  */
/*****************************************************************/

static void *k_int2int(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	return (void *)&smp->data.uint;
}

static void *k_ip2ip(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	if (smp->type == SMP_T_IPV6) {
		v6tov4(&kdata->ip, &smp->data.ipv6);
		return (void *)&kdata->ip.s_addr;
	}
	else {
		return (void *)&smp->data.ipv4.s_addr;
	}
}

static void *k_ip2ipv6(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	if (smp->type == SMP_T_IPV6) {
		return (void *)&smp->data.ipv6.s6_addr;
	}
	else {
		v4tov6(&kdata->ipv6, &smp->data.ipv4);
		return (void *)&kdata->ipv6.s6_addr;
	}
}

static void *k_ip2int(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	if (smp->type == SMP_T_IPV6) {
		if (!v6tov4(&kdata->ip, &smp->data.ipv6))
			return NULL;
		kdata->integer = ntohl(kdata->ip.s_addr);
	}
	else {
		kdata->integer = ntohl(smp->data.ipv4.s_addr);
	}
	return (void *)&kdata->integer;
}

static void *k_int2ip(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	kdata->ip.s_addr = htonl(smp->data.uint);
	return (void *)&kdata->ip.s_addr;
}

static void *k_str2str(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	*len = smp->data.str.len;
	return (void *)smp->data.str.str;
}

static void *k_ip2str(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	if (smp->type == SMP_T_IPV6) {
		if (!inet_ntop(AF_INET6, &smp->data.ipv6, kdata->buf, *len))
			return NULL;
	}
	else {
		if (!inet_ntop(AF_INET, &smp->data.ipv4, kdata->buf, *len))
			return NULL;
	}

	*len = strlen((const char *)kdata->buf);
	return (void *)kdata->buf;
}

static void *k_bin2str(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	unsigned char c;
	int ptr = 0;
	int max = *len;
	int size = 0;

	while (ptr < smp->data.str.len && size <= max - 2) {
		c = smp->data.str.str[ptr++];
		kdata->buf[size++] = hextab[(c >> 4) & 0xF];
		kdata->buf[size++] = hextab[c & 0xF];
	}
	*len = size;
	return (void *)kdata->buf;
}

static void *k_int2str(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	void *key;

	key = (void *)ultoa_r(smp->data.uint, kdata->buf, *len);
	if (!key)
		return NULL;

	*len = strlen((const char *)key);
	return key;
}

static void *k_str2ip(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	if (!buf2ip(smp->data.str.str, smp->data.str.len, &kdata->ip))
		return NULL;

	return (void *)&kdata->ip.s_addr;
}

static void *k_str2ipv6(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	if (!inet_pton(AF_INET6, smp->data.str.str, &kdata->ipv6))
		return NULL;

	return (void *)&kdata->ipv6.s6_addr;
}

static void *k_str2int(struct sample *smp, union stktable_key_data *kdata, size_t *len)
{
	int i;

	kdata->integer = 0;
	for (i = 0; i < smp->data.str.len; i++) {
		uint32_t val = smp->data.str.str[i] - '0';

		if (val > 9)
			break;

		kdata->integer = kdata->integer * 10 + val;
	}
	return (void *)&kdata->integer;
}

/*****************************************************************/
/*      typed sample to typed table key matrix:                  */
/*         sample_to_key[from sample type][to table key type]    */
/*         NULL pointer used for impossible sample casts         */
/*****************************************************************/

typedef void *(*sample_to_key_fct)(struct sample *smp, union stktable_key_data *kdata, size_t *len);
static sample_to_key_fct sample_to_key[SMP_TYPES][STKTABLE_TYPES] = {
/*       table type:   IP          IPV6         INTEGER    STRING      BINARY    */
/* patt. type: BOOL */ { NULL,     NULL,        k_int2int, k_int2str,  NULL      },
/*             UINT */ { k_int2ip, NULL,        k_int2int, k_int2str,  NULL      },
/*             SINT */ { k_int2ip, NULL,        k_int2int, k_int2str,  NULL      },
/*             ADDR */ { k_ip2ip,  k_ip2ipv6,   k_ip2int,  k_ip2str,   NULL      },
/*             IPV4 */ { k_ip2ip,  k_ip2ipv6,   k_ip2int,  k_ip2str,   NULL      },
/*             IPV6 */ { k_ip2ip,  k_ip2ipv6,   k_ip2int,  k_ip2str,   NULL      },
/*              STR */ { k_str2ip, k_str2ipv6,  k_str2int, k_str2str,  k_str2str },
/*              BIN */ { NULL,     NULL,        NULL,      k_bin2str,  k_str2str },
};


/*
 * Process a fetch + format conversion as defined by the sample expression <expr>
 * on request or response considering the <opt> parameter. Returns either NULL if
 * no key could be extracted, or a pointer to the converted result stored in
 * static_table_key in format <table_type>. If <smp> is not NULL, it will be reset
 * and its flags will be initialized so that the caller gets a copy of the input
 * sample, and knows why it was not accepted (eg: SMP_F_MAY_CHANGE is present).
 */
struct stktable_key *stktable_fetch_key(struct stktable *t, struct proxy *px, struct session *l4, void *l7,
                                        unsigned int opt, struct sample_expr *expr, struct sample *smp)
{
	if (smp)
		memset(smp, 0, sizeof(*smp));

	smp = sample_process(px, l4, l7, opt, expr, smp);
	if (!smp)
		return NULL;

	if ((smp->flags & SMP_F_MAY_CHANGE) && !(opt & SMP_OPT_FINAL))
		return NULL; /* we can only use stable samples */

	if (!sample_to_key[smp->type][t->type])
		return NULL;

	static_table_key->key_len = t->key_size;
	static_table_key->key = sample_to_key[smp->type][t->type](smp, &static_table_key->data, &static_table_key->key_len);

	if (!static_table_key->key)
		return NULL;

	if (static_table_key->key_len == 0)
		return NULL;

	if ((static_table_key->key_len < t->key_size) && (t->type != STKTABLE_TYPE_STRING)) {
		/* need padding with null */

		/* assume static_table_key.key_len is less than sizeof(static_table_key.data.buf)
		cause t->key_size is necessary less than sizeof(static_table_key.data) */

		if ((char *)static_table_key->key > (char *)&static_table_key->data &&
		    (char *)static_table_key->key <  (char *)&static_table_key->data + global.tune.bufsize) {
			/* key buffer is part of the static_table_key private data buffer, but is not aligned */

			if (global.tune.bufsize - ((char *)static_table_key->key - (char *)&static_table_key->data) < t->key_size) {
				/* if not remain enough place for padding , process a realign */
				memmove(static_table_key->data.buf, static_table_key->key, static_table_key->key_len);
				static_table_key->key = static_table_key->data.buf;
			}
		}
		else if (static_table_key->key != static_table_key->data.buf) {
			/* key definitly not part of the static_table_key private data buffer */

			memcpy(static_table_key->data.buf, static_table_key->key, static_table_key->key_len);
			static_table_key->key = static_table_key->data.buf;
		}

		memset(static_table_key->key + static_table_key->key_len, 0, t->key_size - static_table_key->key_len);
	}

	return static_table_key;
}

/*
 * Returns 1 if sample expression <expr> result can be converted to table key of
 * type <table_type>, otherwise zero. Used in configuration check.
 */
int stktable_compatible_sample(struct sample_expr *expr, unsigned long table_type)
{
	int out_type;

	if (table_type >= STKTABLE_TYPES)
		return 0;

	out_type = smp_expr_output_type(expr);
	if (!sample_to_key[out_type][table_type])
		return 0;

	return 1;
}

/* Extra data types processing */
struct stktable_data_type stktable_data_types[STKTABLE_DATA_TYPES] = {
	[STKTABLE_DT_SERVER_ID]     = { .name = "server_id",      .std_type = STD_T_SINT  },
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

/* Returns pointer to proxy containing table <name> or NULL if not found */
struct proxy *find_stktable(const char *name)
{
	struct proxy *px;
	struct ebpt_node *node;

	for (node = ebis_lookup(&proxy_by_name, name); node; node = ebpt_next(node)) {
		px = container_of(node, struct proxy, conf.by_name);

		if (strcmp(px->id, name) != 0)
			break;

		if (px->table.size)
			return px;
	}
	return NULL;
}
