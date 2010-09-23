/*
 * include/proto/pattern.h
 * Functions for patterns management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#ifndef _PROTO_PATTERN_H
#define _PROTO_PATTERN_H

#include <types/pattern.h>
#include <types/stick_table.h>

struct pattern_expr *pattern_parse_expr(char **str, int *idx, char *err, int err_size);
struct pattern *pattern_process(struct proxy *px, struct session *l4,
                                void *l7, int dir, struct pattern_expr *expr,
                                struct pattern *p);
void pattern_register_fetches(struct pattern_fetch_kw_list *psl);
void pattern_register_convs(struct pattern_conv_kw_list *psl);

int pattern_arg_ipmask(const char *arg_str, struct pattern_arg **arg_p, int *arg_i);
int pattern_arg_str(const char *arg_str, struct pattern_arg **arg_p, int *arg_i);
#endif
