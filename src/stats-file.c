#include <haproxy/stats-file.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <import/ebmbtree.h>
#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/guid-t.h>
#include <haproxy/list.h>
#include <haproxy/listener-t.h>
#include <haproxy/obj_type.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>
#include <haproxy/stats.h>

/* Dump all fields from <stats> into <out> for stats-file. */
int stats_dump_fields_file(struct buffer *out,
                           const struct field *line, size_t stats_count,
                           struct show_stat_ctx *ctx)
{
	struct guid_node *guid;
	struct listener *l;
	int i;

	switch (ctx->px_st) {
	case STAT_PX_ST_FE:
	case STAT_PX_ST_BE:
		guid = &__objt_proxy(ctx->obj1)->guid;
		break;

	case STAT_PX_ST_LI:
		l = LIST_ELEM(ctx->obj2, struct listener *, by_fe);
		guid = &l->guid;
		break;

	case STAT_PX_ST_SV:
		guid = &__objt_server(ctx->obj2)->guid;
		break;

	default:
		ABORT_NOW();
		return 1;
	}

	/* Skip objects without GUID. */
	if (!guid->node.key)
		return 1;

	chunk_appendf(out, "%s,", (char *)guid->node.key);

	for (i = 0; i < stats_count; ++i) {
		/* Empty field for stats-file is used to skip its output,
		 * including any separator.
		 */
		if (field_format(line, i) == FF_EMPTY)
			continue;

		if (!stats_emit_raw_data_field(out, &line[i]))
			return 0;
		if (!chunk_strcat(out, ","))
			return 0;
	}

	chunk_strcat(out, "\n");
	return 1;
}

void stats_dump_file_header(int type, struct buffer *out)
{
	const struct stat_col *col;
	int i;

	/* Caller must specified ither FE or BE. */
	BUG_ON(!(type & ((1 << STATS_TYPE_FE) | (1 << STATS_TYPE_BE))));

	if (type & (1 << STATS_TYPE_FE)) {
		chunk_strcat(out, "#fe guid,");
		for (i = 0; i < ST_I_PX_MAX; ++i) {
			col = &stat_cols_px[i];
			if (stcol_nature(col) == FN_COUNTER && (col->cap & (STATS_PX_CAP_FE|STATS_PX_CAP_LI)))
				chunk_appendf(out, "%s,", col->name);
		}
	}
	else {
		chunk_appendf(out, "#be guid,");
		for (i = 0; i < ST_I_PX_MAX; ++i) {
			col = &stat_cols_px[i];
			if (stcol_nature(col) == FN_COUNTER && (col->cap & (STATS_PX_CAP_BE|STATS_PX_CAP_SRV)))
				chunk_appendf(out, "%s,", col->name);
		}
	}

	chunk_strcat(out, "\n");
}

/* Parse a stats-file and preload haproxy internal counters. */
void apply_stats_file(void)
{
	struct eb_root st_tree = EB_ROOT;
	FILE *file;
	char *line = NULL;
	ssize_t len;
	size_t alloc_len;
	int linenum;

	if (!global.stats_file)
		return;

	file = fopen(global.stats_file, "r");
	if (!file) {
		ha_warning("config: Can't load stats file: cannot open file.\n");
		return;
	}

	/* Generate stat columns map indexed by name. */
	if (generate_stat_tree(&st_tree, stat_cols_px)) {
		ha_warning("config: Can't load stats file: not enough memory.\n");
		goto out;
	}

	linenum = 0;
	while (1) {
		len = getline(&line, &alloc_len, file);
		if (len < 0)
			break;

		++linenum;
		if (!len || (len == 1 && line[0] == '\n'))
			continue;
	}

 out:
	while (!eb_is_empty(&st_tree)) {
		struct ebmb_node *node = ebmb_first(&st_tree);
		struct stcol_node *snode = ebmb_entry(node, struct stcol_node, name);

		ebmb_delete(node);
		ha_free(&snode);
	}

	ha_free(&line);
	fclose(file);
}
