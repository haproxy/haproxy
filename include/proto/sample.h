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
struct sample *sample_process(struct proxy *px, struct session *sess,
                              struct stream *strm, unsigned int opt,
                              struct sample_expr *expr, struct sample *p);
struct sample *sample_fetch_as_type(struct proxy *px, struct session *sess,
                                   struct stream *strm, unsigned int opt,
                                   struct sample_expr *expr, int smp_type);
void release_sample_expr(struct sample_expr *expr);
void sample_register_fetches(struct sample_fetch_kw_list *psl);
void sample_register_convs(struct sample_conv_kw_list *psl);
const char *sample_src_names(unsigned int use);
const char *sample_ckp_names(unsigned int use);
struct sample_fetch *find_sample_fetch(const char *kw, int len);
struct sample_fetch *sample_fetch_getnext(struct sample_fetch *current, int *idx);
struct sample_conv *sample_conv_getnext(struct sample_conv *current, int *idx);
int smp_resolve_args(struct proxy *p);
int smp_check_date_unit(struct arg *args, char **err);
int smp_expr_output_type(struct sample_expr *expr);
int c_none(struct sample *smp);
int smp_dup(struct sample *smp);

/*
 * This function just apply a cast on sample. It returns 0 if the cast is not
 * available or if the cast fails, otherwise returns 1. It does not modify the
 * input sample on failure.
 */
static inline
int sample_convert(struct sample *sample, int req_type)
{
	if (!sample_casts[sample->data.type][req_type])
		return 0;
	if (sample_casts[sample->data.type][req_type] == c_none)
		return 1;
	return sample_casts[sample->data.type][req_type](sample);
}

static inline
struct sample *smp_set_owner(struct sample *smp, struct proxy *px,
                             struct session *sess, struct stream *strm, int opt)
{
	smp->px   = px;
	smp->sess = sess;
	smp->strm = strm;
	smp->opt  = opt;
	return smp;
}


/* Returns 1 if a sample may be safely used. It performs a few checks on the
 * string length versus size, same for the binary version, and ensures that
 * strings are properly terminated by a zero. If this last point is not granted
 * but the string is not const, then the \0 is appended. Otherwise it returns 0,
 * meaning the caller may need to call smp_dup() before going further.
 */
static inline
int smp_is_safe(struct sample *smp)
{
	switch (smp->data.type) {
	case SMP_T_METH:
		if (smp->data.u.meth.meth != HTTP_METH_OTHER)
			return 1;
		/* Fall through */

	case SMP_T_STR:
		if (smp->data.u.str.size && smp->data.u.str.data >= smp->data.u.str.size)
			return 0;

		if (smp->data.u.str.area[smp->data.u.str.data] == 0)
			return 1;

		if (!smp->data.u.str.size || (smp->flags & SMP_F_CONST))
			return 0;

		smp->data.u.str.area[smp->data.u.str.data] = 0;
		return 1;

	case SMP_T_BIN:
		return !smp->data.u.str.size || smp->data.u.str.data <= smp->data.u.str.size;

	default:
		return 1;
	}
}

/* checks that a sample may freely be used, or duplicates it to normalize it.
 * Returns 1 on success, 0 if the sample must not be used. The function also
 * checks for NULL to simplify the calling code.
 */
static inline
int smp_make_safe(struct sample *smp)
{
	return smp && (smp_is_safe(smp) || smp_dup(smp));
}

/* Returns 1 if a sample may be safely modified in place. It performs a few
 * checks on the string length versus size, same for the binary version, and
 * ensures that strings are properly terminated by a zero, and of course that
 * the size is allocate and that the SMP_F_CONST flag is not set. If only the
 * trailing zero is missing, it is appended. Otherwise it returns 0, meaning
 * the caller may need to call smp_dup() before going further.
 */
static inline
int smp_is_rw(struct sample *smp)
{
	if (smp->flags & SMP_F_CONST)
		return 0;

	switch (smp->data.type) {
	case SMP_T_METH:
		if (smp->data.u.meth.meth != HTTP_METH_OTHER)
			return 1;
		/* Fall through */

	case SMP_T_STR:
		if (!smp->data.u.str.size ||
		    smp->data.u.str.data >= smp->data.u.str.size)
			return 0;

		if (smp->data.u.str.area[smp->data.u.str.data] != 0)
			smp->data.u.str.area[smp->data.u.str.data] = 0;
		return 1;

	case SMP_T_BIN:
		return smp->data.u.str.size &&
		       smp->data.u.str.data <= smp->data.u.str.size;

	default:
		return 1;
	}
}

/* checks that a sample may freely be modified, or duplicates it to normalize
 * it and make it R/W. Returns 1 on success, 0 if the sample must not be used.
 * The function also checks for NULL to simplify the calling code.
 */
static inline
int smp_make_rw(struct sample *smp)
{
	return smp && (smp_is_rw(smp) || smp_dup(smp));
}

#endif /* _PROTO_SAMPLE_H */
