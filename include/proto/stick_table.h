/*
 * include/proto/stick_table.h
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

#ifndef _PROTO_STICK_TABLE_H
#define _PROTO_STICK_TABLE_H

#include <common/errors.h>
#include <common/ticks.h>
#include <common/time.h>
#include <types/stick_table.h>
#include <types/dict.h>

extern struct stktable *stktables_list;

#define stktable_data_size(type) (sizeof(((union stktable_data*)0)->type))
#define stktable_data_cast(ptr, type) ((union stktable_data*)(ptr))->type

void stktable_store_name(struct stktable *t);
struct stktable *stktable_find_by_name(const char *name);
struct stksess *stksess_new(struct stktable *t, struct stktable_key *key);
void stksess_setkey(struct stktable *t, struct stksess *ts, struct stktable_key *key);
void stksess_free(struct stktable *t, struct stksess *ts);
int stksess_kill(struct stktable *t, struct stksess *ts, int decrefcount);

int stktable_init(struct stktable *t);
int stktable_parse_type(char **args, int *idx, unsigned long *type, size_t *key_size);
int parse_stick_table(const char *file, int linenum, char **args,
                      struct stktable *t, char *id, char *nid, struct peers *peers);
struct stksess *stktable_get_entry(struct stktable *table, struct stktable_key *key);
struct stksess *stktable_set_entry(struct stktable *table, struct stksess *nts);
void stktable_touch_with_exp(struct stktable *t, struct stksess *ts, int decrefcount, int expire);
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
		return sizeof(struct freq_ctr_period);
	case STD_T_DICT:
		return sizeof(struct dict_entry *);
	}
	return 0;
}

/* reserve some space for data type <type>, and associate argument at <sa> if
 * not NULL. Returns PE_NONE (0) if OK or an error code among :
 *   - PE_ENUM_OOR if <type> does not exist
 *   - PE_EXIST if <type> is already registered
 *   - PE_ARG_NOT_USE if <sa> was provided but not expected
 *   - PE_ARG_MISSING if <sa> was expected but not provided
 */
static inline int stktable_alloc_data_type(struct stktable *t, int type, const char *sa)
{
	if (type >= STKTABLE_DATA_TYPES)
		return PE_ENUM_OOR;

	if (t->data_ofs[type])
		/* already allocated */
		return PE_EXIST;

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

	t->data_size      += stktable_type_size(stktable_data_types[type].std_type);
	t->data_ofs[type]  = -t->data_size;
	return PE_NONE;
}

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

/* kill an entry if it's expired and its ref_cnt is zero */
static inline int __stksess_kill_if_expired(struct stktable *t, struct stksess *ts)
{
	if (t->expire != TICK_ETERNITY && tick_is_expired(ts->expire, now_ms))
		return __stksess_kill(t, ts);

	return 0;
}

static inline void stksess_kill_if_expired(struct stktable *t, struct stksess *ts, int decrefcnt)
{
	HA_SPIN_LOCK(STK_TABLE_LOCK, &t->lock);

	if (decrefcnt)
		ts->ref_cnt--;

	if (t->expire != TICK_ETERNITY && tick_is_expired(ts->expire, now_ms))
		__stksess_kill_if_expired(t, ts);

	HA_SPIN_UNLOCK(STK_TABLE_LOCK, &t->lock);
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

#endif /* _PROTO_STICK_TABLE_H */
