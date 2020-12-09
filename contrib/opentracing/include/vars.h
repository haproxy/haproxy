/***
 * Copyright 2020 HAProxy Technologies
 *
 * This file is part of the HAProxy OpenTracing filter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef _OPENTRACING_VARS_H_
#define _OPENTRACING_VARS_H_

#define FLT_OT_VARS_SCOPE       "txn"
#define FLT_OT_VAR_CHAR_DASH    'D'
#define FLT_OT_VAR_CHAR_SPACE   'S'


#ifndef DEBUG_OT
#  define flt_ot_vars_dump(...)   while (0)
#else
void                 flt_ot_vars_dump(struct stream *s);
#endif
int                  flt_ot_var_register(const char *scope, const char *prefix, const char *name, char **err);
int                  flt_ot_var_set(struct stream *s, const char *scope, const char *prefix, const char *name, const char *value, uint opt, char **err);
int                  flt_ot_var_unset(struct stream *s, const char *scope, const char *prefix, const char *name, uint opt, char **err);
int                  flt_ot_vars_unset(struct stream *s, const char *scope, const char *prefix, uint opt, char **err);
int                  flt_ot_var_get(struct stream *s, const char *scope, const char *prefix, const char *name, char **value, uint opt, char **err);
struct otc_text_map *flt_ot_vars_get(struct stream *s, const char *scope, const char *prefix, uint opt, char **err);

#endif /* _OPENTRACING_VARS_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
