/*
 * include/haproxy/stick_table.h
 * Functions for stick tables management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2010 Willy Tarreau <w@1wt.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_STICK_TABLE_H
#define _HAPROXY_STICK_TABLE_H

#include <haproxy/api.h>
#include <haproxy/dict-t.h>
#include <haproxy/errors.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/sample-t.h>
#include <haproxy/stick_table-t.h>
#include <haproxy/thread.h>
#include <haproxy/ticks.h>
#include <haproxy/xxhash.h>

extern struct stktable *stktables_list;
extern struct pool_head *pool_head_stk_ctr;
extern struct stktable_type stktable_types[];

#define stktable_data_size(type) (sizeof(((union stktable_data*)0)->type))
#define stktable_data_cast(ptr, type) ((union stktable_data*)(ptr))->type

void stktable_store_name(struct stktable *t);
struct stktable *stktable_find_by_name(const char *name);
struct stksess *stksess_new(struct stktable *t, struct stktable_key *key);
void stksess_setkey(struct stktable *t, struct stksess *ts, struct stktable_key *key);
void stksess_free(struct stktable *t, struct stksess *ts);
int stksess_kill(struct stktable *t, struct stksess *ts);
int stktable_get_key_shard(struct stktable *t, const void *key, size_t len);

int stktable_init(struct stktable *t, char **err_msg);
void stktable_deinit(struct stktable *t);
int stktable_parse_type(char **args, int *idx, unsigned long *type, size_t *key_size, const char *file, int linenum);
int parse_stick_table(const char *file, int linenum, char **args,
                      struct stktable *t, char *id, char *nid, struct peers *peers);
struct stksess *stktable_get_entry(struct stktable *table, struct stktable_key *key);
struct stksess *stktable_set_entry(struct stktable *table, struct stksess *nts);
void stktable_requeue_exp(struct stktable *t, const struct stksess *ts);
void stktable_touch_with_exp(struct stktable *t, struct stksess *ts, int decrefcount, int expire, int decrefcnt);
void stktable_touch_remote(struct stktable *t, struct stksess *ts, int decrefcnt);
void stktable_touch_local(struct stktable *t, struct stksess *ts, int decrefccount);
struct stksess *stktable_lookup(struct stktable *t, struct stksess *ts);
struct stksess *stktable_lookup_key(struct stktable *t, struct stktable_key *key);
struct stksess *stktable_update_key(struct stktable *table, struct stktable_key *key);
struct stktable_key *smp_to_stkey(struct sample *smp, struct stktable *t);
struct stktable_key *stktable_fetch_key(struct stktable *t, struct proxy *px, struct session *sess,
                                        struct stream *strm, unsigned int opt,
                                        struct sample_expr *expr, struct sample *smp);
struct stkctr *smp_fetch_sc_stkctr(struct session *sess, struct stream *strm, const struct arg *args, const char *kw, struct stkctr *stkctr);
struct stkctr *smp_create_src_stkctr(struct session *sess, struct stream *strm, const struct arg *args, const char *kw, struct stkctr *stkctr);
int stktable_compatible_sample(struct sample_expr *expr, unsigned long table_type);
int stktable_register_data_store(int idx, const char *name, int std_type, int arg_type);
int stktable_get_data_type(char *name);
int stktable_trash_oldest(struct stktable *t, int to_batch);
int __stksess_kill(struct stktable *t, struct stksess *ts);

/************************* Composite address manipulation *********************
 * Composite addresses are simply unsigned long data in which the higher bits
 * represent a pointer, and the two lower bits are flags. There are several
 * places where we just want to associate one or two flags to a pointer (eg,
 * to type it), and these functions permit this. The pointer is necessarily a
 * 32-bit aligned pointer, as its two lower bits will be cleared and replaced
 * with the flags.
 *****************************************************************************/

/* Masks the two lower bits of a composite address and converts it to a
 * pointer. This is used to mix some bits with some aligned pointers to
 * structs and to retrieve the original (32-bit aligned) pointer.
 */
static inline void *caddr_to_ptr(unsigned long caddr)
{
	return (void *)(caddr & ~3UL);
}

/* Only retrieves the two lower bits of a composite address. This is used to mix
 * some bits with some aligned pointers to structs and to retrieve the original
 * data (2 bits).
 */
static inline unsigned int caddr_to_data(unsigned long caddr)
{
	return (caddr & 3UL);
}

/* Combines the aligned pointer whose 2 lower bits will be masked with the bits
 * from <data> to form a composite address. This is used to mix some bits with
 * some aligned pointers to structs and to retrieve the original (32-bit aligned)
 * pointer.
 */
static inline unsigned long caddr_from_ptr(void *ptr, unsigned int data)
{
	return (((unsigned long)ptr) & ~3UL) + (data & 3);
}

/* sets the 2 bits of <data> in the <caddr> composite address */
static inline unsigned long caddr_set_flags(unsigned long caddr, unsigned int data)
{
	return caddr | (data & 3);
}

/* clears the 2 bits of <data> in the <caddr> composite address */
static inline unsigned long caddr_clr_flags(unsigned long caddr, unsigned int data)
{
	return caddr & ~(unsigned long)(data & 3);
}


/* return allocation size for standard data type <type> */
static inline int stktable_type_size(int type)
{
	switch(type) {
	case STD_T_SINT:
	case STD_T_UINT:
		return sizeof(int);
	case STD_T_ULL:
		return sizeof(unsigned long long);
	case STD_T_FRQP:
		return sizeof(struct freq_ctr);
	case STD_T_DICT:
		return sizeof(struct dict_entry *);
	}
	return 0;
}

int stktable_alloc_data_type(struct stktable *t, int type, const char *sa, const char *sa2);

/* return pointer for data type <type> in sticky session <ts> of table <t>, all
 * of which must exist (otherwise use stktable_data_ptr() if unsure).
 */
static inline void *__stktable_data_ptr(struct stktable *t, struct stksess *ts, int type)
{
	return (void *)ts + t->data_ofs[type];
}

/* return pointer for data type <type> in sticky session <ts> of table <t>, or
 * NULL if either <ts> is NULL or the type is not stored.
 */
static inline void *stktable_data_ptr(struct stktable *t, struct stksess *ts, int type)
{
	if (type >= STKTABLE_DATA_TYPES)
		return NULL;

	if (!t->data_ofs[type]) /* type not stored */
		return NULL;

	if (!ts)
		return NULL;

	return __stktable_data_ptr(t, ts, type);
}

/* return pointer on the element of index <idx> from the array data type <type>
 * in sticky session <ts> of table <t>, or NULL if either <ts> is NULL
 * or this element is not stored because this type is not stored or
 * requested index is greater than the number of elements of the array.
 * Note: this function is also usable on non array types, they are
 * considered as array of size 1, so a call with <idx> at 0
 * as the same behavior than 'stktable_data_ptr'.
 */
static inline void *stktable_data_ptr_idx(struct stktable *t, struct stksess *ts, int type, unsigned int idx)
{
	if (type >= STKTABLE_DATA_TYPES)
		return NULL;

	if (!t->data_ofs[type]) /* type not stored */
		return NULL;

	if (!ts)
		return NULL;

	if (t->data_nbelem[type] <= idx)
		return NULL;

	return __stktable_data_ptr(t, ts, type) + idx*stktable_type_size(stktable_data_types[type].std_type);
}

/* return a shard number for key <key> of len <len> present in table <t>, for
 * use with the tree indexing. The value will be from 0 to
 * CONFIG_HAP_TBL_BUCKETS-1.
 */
static inline uint stktable_calc_shard_num(const struct stktable *t, const void *key, size_t len)
{
#if CONFIG_HAP_TBL_BUCKETS > 1
	return XXH32(key, len, t->hash_seed) % CONFIG_HAP_TBL_BUCKETS;
#else
	return 0;
#endif
}

/* kill an entry if it's expired and its ref_cnt is zero */
static inline int __stksess_kill_if_expired(struct stktable *t, struct stksess *ts)
{
	if (t->expire != TICK_ETERNITY && tick_is_expired(ts->expire, now_ms))
		return __stksess_kill(t, ts);

	return 0;
}

/*
 * Decrease the refcount of a stksess and release it if the refcount falls to 0
 * _AND_ if the session expired. Note,, the refcount is always decremented.
 *
 * This function locks the corresponding table shard to proceed. When this
 * function is called, the caller must be sure it owns a reference on the
 * stksess (refcount >= 1).
 */
static inline void stksess_kill_if_expired(struct stktable *t, struct stksess *ts)
{
	uint shard;
	size_t len;

	if (t->expire != TICK_ETERNITY && tick_is_expired(ts->expire, now_ms)) {
		if (t->type == SMP_T_STR)
			len = strlen((const char *)ts->key.key);
		else
			len = t->key_size;

		shard = stktable_calc_shard_num(t, ts->key.key, len);

		/* make the compiler happy when shard is not used without threads */
		ALREADY_CHECKED(shard);

		HA_RWLOCK_WRLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
		if (!HA_ATOMIC_SUB_FETCH(&ts->ref_cnt, 1))
			__stksess_kill_if_expired(t, ts);
		HA_RWLOCK_WRUNLOCK(STK_TABLE_LOCK, &t->shards[shard].sh_lock);
	}
	else
		HA_ATOMIC_SUB_FETCH(&ts->ref_cnt, 1);
}

/* sets the stick counter's entry pointer */
static inline void stkctr_set_entry(struct stkctr *stkctr, struct stksess *entry)
{
	stkctr->entry = caddr_from_ptr(entry, 0);
}

/* returns the entry pointer from a stick counter */
static inline struct stksess *stkctr_entry(struct stkctr *stkctr)
{
	return caddr_to_ptr(stkctr->entry);
}

/* returns the two flags from a stick counter */
static inline unsigned int stkctr_flags(struct stkctr *stkctr)
{
	return caddr_to_data(stkctr->entry);
}

/* sets up to two flags at a time on a composite address */
static inline void stkctr_set_flags(struct stkctr *stkctr, unsigned int flags)
{
	stkctr->entry = caddr_set_flags(stkctr->entry, flags);
}

/* returns the two flags from a stick counter */
static inline void stkctr_clr_flags(struct stkctr *stkctr, unsigned int flags)
{
	stkctr->entry = caddr_clr_flags(stkctr->entry, flags);
}

/* Increase the number of cumulated HTTP requests in the tracked counter
 * <stkctr>. It returns 0 if the entry pointer does not exist and nothing is
 * performed. Otherwise it returns 1.
 */
static inline int stkctr_inc_http_req_ctr(struct stkctr *stkctr)
{
	struct stksess *ts;
	void *ptr1, *ptr2;

	ts = stkctr_entry(stkctr);
	if (!ts)
		return 0;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

	ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_REQ_CNT);
	if (ptr1)
		stktable_data_cast(ptr1, std_t_uint)++;

	ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_REQ_RATE);
	if (ptr2)
		update_freq_ctr_period(&stktable_data_cast(ptr2, std_t_frqp),
				       stkctr->table->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u, 1);

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

	/* If data was modified, we need to touch to re-schedule sync */
	if (ptr1 || ptr2)
		stktable_touch_local(stkctr->table, ts, 0);
	return 1;
}

/* Increase the number of cumulated failed HTTP requests in the tracked counter
 * <stkctr>. It returns 0 if the entry pointer does not exist and nothing is
 * performed. Otherwise it returns 1.
 */
static inline int stkctr_inc_http_err_ctr(struct stkctr *stkctr)
{
	struct stksess *ts;
	void *ptr1, *ptr2;

	ts = stkctr_entry(stkctr);
	if (!ts)
		return 0;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

	ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_ERR_CNT);
	if (ptr1)
		stktable_data_cast(ptr1, std_t_uint)++;

	ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_ERR_RATE);
	if (ptr2)
		update_freq_ctr_period(&stktable_data_cast(ptr2, std_t_frqp),
				       stkctr->table->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u, 1);

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

	/* If data was modified, we need to touch to re-schedule sync */
	if (ptr1 || ptr2)
		stktable_touch_local(stkctr->table, ts, 0);
	return 1;
}

/* Increase the number of cumulated failed HTTP responses in the tracked counter
 * <stkctr>. It returns 0 if the entry pointer does not exist and nothing is
 * performed. Otherwise it returns 1.
 */
static inline int stkctr_inc_http_fail_ctr(struct stkctr *stkctr)
{
	struct stksess *ts;
	void *ptr1, *ptr2;

	ts = stkctr_entry(stkctr);
	if (!ts)
		return 0;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

	ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_FAIL_CNT);
	if (ptr1)
		stktable_data_cast(ptr1, std_t_uint)++;

	ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_FAIL_RATE);
	if (ptr2)
		update_freq_ctr_period(&stktable_data_cast(ptr2, std_t_frqp),
				       stkctr->table->data_arg[STKTABLE_DT_HTTP_FAIL_RATE].u, 1);

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

	/* If data was modified, we need to touch to re-schedule sync */
	if (ptr1 || ptr2)
		stktable_touch_local(stkctr->table, ts, 0);
	return 1;
}

/* Increase the number of bytes received in the tracked counter <stkctr>. It
 * returns 0 if the entry pointer does not exist and nothing is
 * performed. Otherwise it returns 1.
 */
static inline int stkctr_inc_bytes_in_ctr(struct stkctr *stkctr, unsigned long long bytes)
{
	struct stksess *ts;
	void *ptr1, *ptr2;

	ts = stkctr_entry(stkctr);
	if (!ts)
		return 0;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
	ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_BYTES_IN_CNT);
	if (ptr1)
		stktable_data_cast(ptr1, std_t_ull) += bytes;

	ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_BYTES_IN_RATE);
	if (ptr2)
		update_freq_ctr_period(&stktable_data_cast(ptr2, std_t_frqp),
				       stkctr->table->data_arg[STKTABLE_DT_BYTES_IN_RATE].u,
				       div64_32(bytes + stkctr->table->brates_factor - 1, stkctr->table->brates_factor));
	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);


	/* If data was modified, we need to touch to re-schedule sync */
	if (ptr1 || ptr2)
		stktable_touch_local(stkctr->table, ts, 0);
	return 1;
}

/* Increase the number of bytes sent in the tracked counter <stkctr>. It
 * returns 0 if the entry pointer does not exist and nothing is
 * performed. Otherwise it returns 1.
 */
static inline int stkctr_inc_bytes_out_ctr(struct stkctr *stkctr, unsigned long long bytes)
{
	struct stksess *ts;
	void *ptr1, *ptr2;

	ts = stkctr_entry(stkctr);
	if (!ts)
		return 0;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);
	ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_BYTES_OUT_CNT);
	if (ptr1)
		stktable_data_cast(ptr1, std_t_ull) += bytes;

	ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_BYTES_OUT_RATE);
	if (ptr2)
		update_freq_ctr_period(&stktable_data_cast(ptr2, std_t_frqp),
				       stkctr->table->data_arg[STKTABLE_DT_BYTES_OUT_RATE].u,
				       div64_32(bytes + stkctr->table->brates_factor - 1, stkctr->table->brates_factor));
	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);


	/* If data was modified, we need to touch to re-schedule sync */
	if (ptr1 || ptr2)
		stktable_touch_local(stkctr->table, ts, 0);
	return 1;
}

/* Add <inc> to the number of cumulated front glitches in the tracked counter
 * <stkctr>. It returns 0 if the entry pointer does not exist and nothing is
 * performed. Otherwise it returns 1.
 */
static inline int stkctr_add_glitch_ctr(struct stkctr *stkctr, uint inc)
{
	struct stksess *ts;
	void *ptr1, *ptr2;

	ts = stkctr_entry(stkctr);
	if (!ts)
		return 0;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

	ptr1 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GLITCH_CNT);
	if (ptr1)
		stktable_data_cast(ptr1, std_t_uint) += inc;

	ptr2 = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_GLITCH_RATE);
	if (ptr2)
		update_freq_ctr_period(&stktable_data_cast(ptr2, std_t_frqp),
				       stkctr->table->data_arg[STKTABLE_DT_GLITCH_RATE].u, inc);

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

	/* If data was modified, we need to touch to re-schedule sync */
	if (ptr1 || ptr2)
		stktable_touch_local(stkctr->table, ts, 0);
	return 1;
}

#endif /* _HAPROXY_STICK_TABLE_H */
