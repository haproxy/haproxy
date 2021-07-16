/*
 * include/haproxy/cfgcond.h
 * Configuration condition preprocessor
 *
 * Copyright (C) 2000-2021 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_CFGCOND_H
#define _HAPROXY_CFGCOND_H

#include <haproxy/api.h>
#include <haproxy/cfgcond-t.h>

const struct cond_pred_kw *cfg_lookup_cond_pred(const char *str);
int cfg_eval_condition(char **args, char **err, const char **errptr);

#endif
