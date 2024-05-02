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
#include <haproxy/listener-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/tools-t.h>

struct channel;
struct buffer;
struct proxy;
struct appctx;
struct htx;
struct stconn;

/* These two structs contains all column names and descriptions according to
 * the the number of entries in "enum stat_idx_px" and "enum stat_idx_info"
 */
extern const struct stat_col stat_cols_px[];
extern const struct name_desc stat_cols_info[];
extern const char *stat_status_codes[];
extern struct applet http_stats_applet;
extern struct list stats_module_list[];
extern THREAD_LOCAL struct field stat_line_info[];
extern THREAD_LOCAL struct field *stat_lines[];
extern struct name_desc *stat_cols[STATS_DOMAIN_COUNT];
extern size_t stat_cols_len[STATS_DOMAIN_COUNT];

int generate_stat_tree(struct eb_root *st_tree, const struct stat_col cols[]);

struct htx;
int stats_putchk(struct appctx *appctx, struct buffer *buf, struct htx *htx);
int stats_is_full(struct appctx *appctx, struct buffer *buf, struct htx *htx);

const char *stats_scope_ptr(struct appctx *appctx);

int stats_dump_one_line(const struct field *line, size_t stats_count, struct appctx *appctx);

int stats_fill_info(struct field *info, int len, uint flags);
int stats_fill_fe_line(struct proxy *px, int flags, struct field *line, int len,
                       enum stat_idx_px *index);
int stats_fill_li_line(struct proxy *px, struct listener *l, int flags,
                       struct field *line, int len, enum stat_idx_px *index);
int stats_fill_sv_line(struct proxy *px, struct server *sv, int flags,
                       struct field *line, int len, enum stat_idx_px *index);
int stats_fill_be_line(struct proxy *px, int flags, struct field *line, int len,
                       enum stat_idx_px *index);

int stats_dump_stat_to_buffer(struct stconn *sc, struct buffer *buf, struct htx *htx);

int stats_emit_raw_data_field(struct buffer *out, const struct field *f);
int stats_emit_typed_data_field(struct buffer *out, const struct field *f);
int stats_emit_field_tags(struct buffer *out, const struct field *f,
			  char delim);


/* Returns true if <col> is fully defined, false if only used as name-desc. */
static inline int stcol_is_generic(const struct stat_col *col)
{
	return !!(col->cap);
}

static inline enum field_format stcol_format(const struct stat_col *col)
{
	return col->type & FF_MASK;
}

static inline enum field_nature stcol_nature(const struct stat_col *col)
{
	return col->type & FN_MASK;
}

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

static inline uint8_t stats_get_domain(uint32_t domain)
{
	return domain >> STATS_DOMAIN & STATS_DOMAIN_MASK;
}

static inline enum stats_domain_px_cap stats_px_get_cap(uint32_t domain)
{
	return domain >> STATS_PX_CAP & STATS_PX_CAP_MASK;
}

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
