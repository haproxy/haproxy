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

#include <haproxy/api-t.h>
#include <haproxy/session-t.h>
#include <haproxy/stream-t.h>
#include <haproxy/vars-t.h>

void vars_init(struct vars *vars, enum vars_scope scope);
void var_accounting_diff(struct vars *vars, struct session *sess, struct stream *strm, int size);
unsigned int var_clear(struct var *var);
void vars_prune(struct vars *vars, struct session *sess, struct stream *strm);
void vars_prune_per_sess(struct vars *vars);
int vars_get_by_name(const char *name, size_t len, struct sample *smp);
int vars_set_by_name_ifexist(const char *name, size_t len, struct sample *smp);
int vars_set_by_name(const char *name, size_t len, struct sample *smp);
int vars_unset_by_name_ifexist(const char *name, size_t len, struct sample *smp);
int vars_get_by_desc(const struct var_desc *var_desc, struct sample *smp);
int vars_check_arg(struct arg *arg, char **err);

#endif
