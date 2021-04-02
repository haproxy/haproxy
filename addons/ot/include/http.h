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
#ifndef _OPENTRACING_HTTP_H_
#define _OPENTRACING_HTTP_H_

#ifndef DEBUG_OT
#  define flt_ot_http_headers_dump(...)   while (0)
#else
void                 flt_ot_http_headers_dump(const struct channel *chn);
#endif
struct otc_text_map *flt_ot_http_headers_get(struct channel *chn, const char *prefix, size_t len, char **err);
int                  flt_ot_http_header_set(struct channel *chn, const char *prefix, const char *name, const char *value, char **err);
int                  flt_ot_http_headers_remove(struct channel *chn, const char *prefix, char **err);

#endif /* _OPENTRACING_HTTP_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
