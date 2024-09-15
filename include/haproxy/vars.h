/*
 * include/haproxy/vars.h
 * Prototypes for variables.
 *
 * Copyright (C) 2015 Thierry FOURNIER <tfournier@arpalert.org>
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

#ifndef _HAPROXY_VARS_H
#define _HAPROXY_VARS_H

#include <import/cebu64_tree.h>

#include <haproxy/api-t.h>
#include <haproxy/session-t.h>
#include <haproxy/stream-t.h>
#include <haproxy/thread.h>
#include <haproxy/vars-t.h>

extern struct vars proc_vars;
struct sample;
struct arg;

void vars_init_head(struct vars *vars, enum vars_scope scope);
void var_accounting_diff(struct vars *vars, struct session *sess, struct stream *strm, int size);
unsigned int var_clear(struct vars *vars, struct var *var, int force);
void vars_prune_per_sess(struct vars *vars);
int var_set(const struct var_desc *desc, struct sample *smp, uint flags);
int var_unset(const struct var_desc *desc, struct sample *smp);
int vars_get_by_name(const char *name, size_t len, struct sample *smp, const struct buffer *def);
int vars_set_by_name_ifexist(const char *name, size_t len, struct sample *smp);
int vars_set_by_name(const char *name, size_t len, struct sample *smp);
int vars_unset_by_name_ifexist(const char *name, size_t len, struct sample *smp);
int vars_get_by_desc(const struct var_desc *var_desc, struct sample *smp, const struct buffer *def);
int vars_check_arg(struct arg *arg, char **err);

/* locks the <vars> for writes if it's in a shared scope */
static inline void vars_wrlock(struct vars *vars)
{
	if (vars->scope == SCOPE_PROC)
		HA_RWLOCK_WRLOCK(VARS_LOCK, &vars->rwlock);
}

/* unlocks the <vars> for writes if it's in a shared scope */
static inline void vars_wrunlock(struct vars *vars)
{
	if (vars->scope == SCOPE_PROC)
		HA_RWLOCK_WRUNLOCK(VARS_LOCK, &vars->rwlock);
}

/* locks the <vars> for reads if it's in a shared scope */
static inline void vars_rdlock(struct vars *vars)
{
	if (vars->scope == SCOPE_PROC)
		HA_RWLOCK_RDLOCK(VARS_LOCK, &vars->rwlock);
}

/* unlocks the <vars> for reads if it's in a shared scope */
static inline void vars_rdunlock(struct vars *vars)
{
	if (vars->scope == SCOPE_PROC)
		HA_RWLOCK_RDUNLOCK(VARS_LOCK, &vars->rwlock);
}

/* This function free all the memory used by all the variables
 * in the list.
 */
static inline void vars_prune(struct vars *vars, struct session *sess, struct stream *strm)
{
	struct ceb_node *node;
	struct var *var;
	unsigned int size = 0;
	int i;

	for (i = 0; i < VAR_NAME_ROOTS; i++) {
		while ((node = cebu64_first(&vars->name_root[i]))) {
			var = container_of(node, struct var, node);
			size += var_clear(vars, var, 1);
		}
	}

	if (!size)
		return;

	var_accounting_diff(vars, sess, strm, -size);
}

#endif
