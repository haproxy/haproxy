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
#ifndef _OPENTRACING_POOL_H_
#define _OPENTRACING_POOL_H_

void          *flt_ot_pool_alloc(struct pool_head *pool, size_t size, bool flag_clear, char **err);
void          *flt_ot_pool_strndup(struct pool_head *pool, const char *s, size_t size, char **err);
void           flt_ot_pool_free(struct pool_head *pool, void **ptr);

struct buffer *flt_ot_trash_alloc(bool flag_clear, char **err);
void           flt_ot_trash_free(struct buffer **ptr);

#endif /* _OPENTRACING_POOL_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
