/*
 * include/haproxy/stats.h
 * This file contains definitions of some primitives to dedicated to
 * statistics output.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_STATS_H
#define _HAPROXY_STATS_H

#include <haproxy/api.h>
#include <haproxy/applet-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/stream_interface-t.h>
#include <haproxy/tools-t.h>


/* These two structs contains all field names and descriptions according to
 * the the number of entries in "enum stat_field" and "enum info_field"
 */
extern const struct name_desc stat_fields[];
extern const struct name_desc info_fields[];
extern const char *stat_status_codes[];
extern struct applet http_stats_applet;
extern THREAD_LOCAL struct field info[];
extern THREAD_LOCAL struct field *stat_l[];

struct htx;
int stats_putchk(struct channel *chn, struct htx *htx, struct buffer *chk);

int stats_dump_one_line(const struct field *stats, size_t stats_count, struct appctx *appctx);

int stats_fill_info(struct field *info, int len, uint flags);
int stats_fill_fe_stats(struct proxy *px, struct field *stats, int len,
			enum stat_field *selected_field);
int stats_fill_li_stats(struct proxy *px, struct listener *l, int flags,
                        struct field *stats, int len, enum stat_field *selected_field);
int stats_fill_sv_stats(struct proxy *px, struct server *sv, int flags,
                        struct field *stats, int len, enum stat_field *selected_field);
int stats_fill_be_stats(struct proxy *px, int flags, struct field *stats, int len,
			enum stat_field *selected_field);

void stats_io_handler(struct stream_interface *si);
int stats_emit_raw_data_field(struct buffer *out, const struct field *f);
int stats_emit_typed_data_field(struct buffer *out, const struct field *f);
int stats_emit_field_tags(struct buffer *out, const struct field *f,
			  char delim);


static inline enum field_format field_format(const struct field *f, int e)
{
	return f[e].type & FF_MASK;
}

static inline enum field_origin field_origin(const struct field *f, int e)
{
	return f[e].type & FO_MASK;
}

static inline enum field_scope field_scope(const struct field *f, int e)
{
	return f[e].type & FS_MASK;
}

static inline enum field_nature field_nature(const struct field *f, int e)
{
	return f[e].type & FN_MASK;
}

static inline const char *field_str(const struct field *f, int e)
{
	return (field_format(f, e) == FF_STR && f[e].u.str) ? f[e].u.str : "";
}

static inline struct field mkf_s32(uint32_t type, int32_t value)
{
	struct field f = { .type = FF_S32 | type, .u.s32 = value };
	return f;
}

static inline struct field mkf_u32(uint32_t type, uint32_t value)
{
	struct field f = { .type = FF_U32 | type, .u.u32 = value };
	return f;
}

static inline struct field mkf_s64(uint32_t type, int64_t value)
{
	struct field f = { .type = FF_S64 | type, .u.s64 = value };
	return f;
}

static inline struct field mkf_u64(uint32_t type, uint64_t value)
{
	struct field f = { .type = FF_U64 | type, .u.u64 = value };
	return f;
}

static inline struct field mkf_str(uint32_t type, const char *value)
{
	struct field f = { .type = FF_STR | type, .u.str = value };
	return f;
}

static inline struct field mkf_flt(uint32_t type, double value)
{
	struct field f = { .type = FF_FLT | type, .u.flt = value };
	return f;
}

#define MK_STATS_PROXY_DOMAIN(px_cap) \
	((px_cap) << STATS_PX_CAP | STATS_DOMAIN_PROXY)

int stats_allocate_proxy_counters_internal(struct extra_counters **counters,
                                           int type, int px_cap);
int stats_allocate_proxy_counters(struct proxy *px);

void stats_register_module(struct stats_module *m);

#endif /* _HAPROXY_STATS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
