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

extern const char *smp_to_type[SMP_TYPES];

struct sample_expr *sample_parse_expr(char **str, int *idx, const char *file, int line, char **err, struct arg_list *al);
struct sample_conv *find_sample_conv(const char *kw, int len);
struct sample *sample_process(struct proxy *px, struct session *l4,
                               void *l7, unsigned int dir, struct sample_expr *expr,
                               struct sample *p);
struct sample *sample_fetch_string(struct proxy *px, struct session *l4, void *l7,
                                   unsigned int opt, struct sample_expr *expr);
void sample_register_fetches(struct sample_fetch_kw_list *psl);
void sample_register_convs(struct sample_conv_kw_list *psl);
const char *sample_src_names(unsigned int use);
const char *sample_ckp_names(unsigned int use);
struct sample_fetch *find_sample_fetch(const char *kw, int len);
int smp_resolve_args(struct proxy *p);
int smp_expr_output_type(struct sample_expr *expr);
int c_none(struct sample *smp);
int smp_dup(struct sample *smp);

/*
 * This function just apply a cast on sample. It returns 0 if the cast is not
 * avalaible or if the cast fails, otherwise returns 1. It does not modify the
 * input sample on failure.
 */
static inline
int sample_convert(struct sample *sample, int req_type)
{
	if (!sample_casts[sample->type][req_type])
		return 0;
	if (sample_casts[sample->type][req_type] == c_none)
		return 1;
	return sample_casts[sample->type][req_type](sample);
}

#endif /* _PROTO_SAMPLE_H */
