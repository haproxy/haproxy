/*
 * include/proto/sample.h
 * Functions for samples management.
 *
 * Copyright (C) 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2012 Willy Tarreau <w@1wt.eu>
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

#ifndef _PROTO_SAMPLE_H
#define _PROTO_SAMPLE_H

#include <types/sample.h>
#include <types/stick_table.h>

struct sample_expr *sample_parse_expr(char **str, int *idx, char *err, int err_size);
struct sample *sample_process(struct proxy *px, struct session *l4,
                               void *l7, unsigned int dir, struct sample_expr *expr,
                               struct sample *p);
void sample_register_fetches(struct sample_fetch_kw_list *psl);
void sample_register_convs(struct sample_conv_kw_list *psl);
struct chunk *sample_get_trash_chunk(void);

#endif /* _PROTO_SAMPLE_H */
