#include <haproxy/stats-file.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <import/ebmbtree.h>
#include <import/ebsttree.h>
#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/clock.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/guid.h>
#include <haproxy/intops.h>
#include <haproxy/list.h>
#include <haproxy/listener-t.h>
#include <haproxy/obj_type.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>
#include <haproxy/stats.h>
#include <haproxy/time.h>

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
			if (stcol_is_generic(col) &&
			    col->cap & (STATS_PX_CAP_FE|STATS_PX_CAP_LI)) {
				chunk_appendf(out, "%s,", col->name);
			}
		}
	}
	else {
		chunk_appendf(out, "#be guid,");
		for (i = 0; i < ST_I_PX_MAX; ++i) {
			col = &stat_cols_px[i];
			if (stcol_is_generic(col) &&
			    col->cap & (STATS_PX_CAP_BE|STATS_PX_CAP_SRV)) {
				chunk_appendf(out, "%s,", col->name);
			}
		}
	}

	chunk_strcat(out, "\n");
}

/* Parse an identified header line <header> starting with '#' character.
 *
 * If the section is recognized, <domain> will point to the current stats-file
 * scope. <cols> will be filled as a matrix to identify each stat_col position
 * using <st_tree> as prefilled proxy stats columns. If stats-file section is
 * unknown, only <domain> will be set to STFILE_DOMAIN_UNSET.
 *
 * Returns 0 on success. On fatal error, non-zero is returned and parsing should
 * be interrupted.
 */
static int parse_header_line(struct ist header, struct eb_root *st_tree,
                             enum stfile_domain *domain,
                             const struct stat_col *cols[])
{
	enum stfile_domain dom = STFILE_DOMAIN_UNSET;
	struct ist token;
	char last;
	int i;

	header = iststrip(header);
	last = istptr(header)[istlen(header) - 1];
	token = istsplit(&header, ' ');

	/* A header line is considered valid if:
	 * - a space delimiter is found and first token is several chars
	 * - last line character must be a comma separator
	 */
	if (!istlen(header) || istlen(token) == 1 || last != ',')
		goto err;

	if (isteq(token, ist("#fe")))
		dom = STFILE_DOMAIN_PX_FE;
	else if (isteq(token, ist("#be")))
		dom = STFILE_DOMAIN_PX_BE;

	/* Remove 'guid' field. */
	token = istsplit(&header, ',');
	if (!isteq(token, ist("guid"))) {
		/* Fatal error if FE/BE domain without guid token. */
		if (dom == STFILE_DOMAIN_PX_FE || dom == STFILE_DOMAIN_PX_BE)
			goto err;
	}

	/* Unknown domain. Following lines should be ignored until next header. */
	if (dom == STFILE_DOMAIN_UNSET)
		return 0;

	/* Generate matrix of stats column into cols[]. */
	memset(cols, 0, sizeof(void *) * STAT_FILE_MAX_COL_COUNT);

	i = 0;
	while (istlen(header) && i < STAT_FILE_MAX_COL_COUNT) {
		struct stcol_node *col_node;
		const struct stat_col *col;
		struct ebmb_node *node;

		/* Lookup column by its name into <st_tree>. */
		token = istsplit(&header, ',');
		node = ebst_lookup(st_tree, ist0(token));
		if (!node) {
			++i;
			continue;
		}

		col_node = ebmb_entry(node, struct stcol_node, name);
		col = col_node->col;

		/* Ignore column if its cap is not valid with current stats-file section. */
		if ((dom == STFILE_DOMAIN_PX_FE &&
		    !(col->cap & (STATS_PX_CAP_FE|STATS_PX_CAP_LI))) ||
		    (dom == STFILE_DOMAIN_PX_BE &&
		     !(col->cap & (STATS_PX_CAP_BE|STATS_PX_CAP_SRV)))) {
			++i;
			continue;
		}

		cols[i] = col;
		++i;
	}

	*domain = dom;
	return 0;

 err:
	*domain = STFILE_DOMAIN_UNSET;
	return 1;
}

/* Preload an individual counter instance stored at <counter> with <token>
 * value> for the <col> stat column.
 *
 * Returns 0 on success else non-zero if counter was not updated.
 */
static int load_ctr(const struct stat_col *col, const struct ist token,
                    void* counter)
{
	const enum field_nature fn = stcol_nature(col);
	const enum field_format ff = stcol_format(col);
	const char *ptr = istptr(token);
	struct field value;

	switch (ff) {
	case FF_U64:
		value.u.u64 = read_uint64(&ptr, istend(token));
		break;

	case FF_S32:
	case FF_U32:
		value.u.u32 = read_uint(&ptr, istend(token));
		break;

	default:
		/* Unsupported field nature. */
		return 1;
	}

	/* Do not load value if non numeric characters present. */
	if (ptr != istend(token))
		return 1;

	if (fn == FN_COUNTER && ff == FF_U64) {
		*(uint64_t *)counter = value.u.u64;
	}
	else if (fn == FN_RATE && ff == FF_U32) {
		preload_freq_ctr(counter, value.u.u32);
	}
	else if (fn == FN_AGE && (ff == FF_U32 || ff == FF_S32)) {
		*(uint32_t *)counter = ns_to_sec(now_ns) - value.u.u32;
	}
	else {
		/* Unsupported field format/nature combination. */
		return 1;
	}

	return 0;
}

/* Parse a non header stats-file line <line>. Specify current parsing <domain>
 * and <cols> stats column matrix derived from the last header line.
 *
 * Returns 0 on success else non-zero.
 */
static int parse_stat_line(struct ist line,
                           enum stfile_domain domain,
                           const struct stat_col *cols[])
{
	struct guid_node *node;
	struct listener *li;
	struct server *srv;
	struct proxy *px;
	struct ist token;
	char *base_off;
	char *guid;
	int i, off;

	token = istsplit(&line, ',');
	guid = ist0(token);
	if (!guid_is_valid_fmt(guid, NULL))
		goto err;

	node = guid_lookup(guid);
	if (!node) {
		/* Silently ignored unknown GUID. */
		return 0;
	}

	switch (obj_type(node->obj_type)) {
	case OBJ_TYPE_PROXY:
		px = __objt_proxy(node->obj_type);

		if (domain == STFILE_DOMAIN_PX_FE) {
			if (!(px->cap & PR_CAP_FE))
				return 0; /* silently ignored fe/be mismatch */
			base_off = (char *)&px->fe_counters;
			off = 0;
		}
		else if (domain == STFILE_DOMAIN_PX_BE) {
			if (!(px->cap & PR_CAP_BE))
				return 0; /* silently ignored fe/be mismatch */
			base_off = (char *)&px->be_counters;
			off = 1;
		}
		else {
			goto err;
		}

		break;

	case OBJ_TYPE_LISTENER:
		if (domain != STFILE_DOMAIN_PX_FE)
			goto err;

		li = __objt_listener(node->obj_type);
		/* Listeners counters are not allocated if 'option socket-stats' unset. */
		if (!li->counters)
			return 0;

		base_off = (char *)li->counters;
		off = 0;
		break;

	case OBJ_TYPE_SERVER:
		if (domain != STFILE_DOMAIN_PX_BE)
			goto err;

		srv = __objt_server(node->obj_type);
		base_off = (char *)&srv->counters;
		off = 1;
		break;

	default:
		goto err;
	}

	i = 0;
	while (istlen(line) && i < STAT_FILE_MAX_COL_COUNT) {
		const struct stat_col *col = cols[i++];

		token = istsplit(&line, ',');
		if (!istlen(token))
			continue;

		if (!col)
			continue;

		load_ctr(col, token, base_off + col->metric.offset[off]);
	}

	return 0;

 err:
	return 1;
}

/* Parse a stats-file and preload haproxy internal counters. */
void apply_stats_file(void)
{
	const struct stat_col *cols[STAT_FILE_MAX_COL_COUNT];
	struct eb_root st_tree = EB_ROOT;
	enum stfile_domain domain;
	int valid_format = 0;
	FILE *file;
	struct ist istline;
	char *line = NULL;
	int linenum;

	if (!global.stats_file)
		return;

	file = fopen(global.stats_file, "r");
	if (!file) {
		ha_warning("config: Can't load stats-file '%s': cannot open file.\n", global.stats_file);
		return;
	}

	/* Generate stat columns map indexed by name. */
	if (generate_stat_tree(&st_tree, stat_cols_px)) {
		ha_warning("config: Can't load stats-file '%s': not enough memory.\n", global.stats_file);
		goto out;
	}

	line = malloc(sizeof(char) * LINESIZE);
	if (!line) {
		ha_warning("config: Can't load stats-file '%s': line alloc error.\n", global.stats_file);
		goto out;
	}

	linenum = 0;
	domain = STFILE_DOMAIN_UNSET;
	while (1) {
		if (!fgets(line, LINESIZE, file))
			break;

		++linenum;
		istline = iststrip(ist(line));
		if (!istlen(istline))
			continue;

		/* comment line starts by // */
		if (istmatch(istline, ist("//")) != 0)
			continue;

		if (*istptr(istline) == '#') {
			if (parse_header_line(istline, &st_tree, &domain, cols)) {
				if (!valid_format) {
					ha_warning("config: Invalid stats-file format in file '%s'.\n", global.stats_file);
					break;
				}

				ha_warning("config: Ignored stats-file header line '%d' in file '%s'.\n", linenum, global.stats_file);
			}

			valid_format = 1;
		}
		else if (domain != STFILE_DOMAIN_UNSET) {
			if (parse_stat_line(istline, domain, cols))
				ha_warning("config: Ignored stats-file line %d in file '%s'.\n", linenum, global.stats_file);
		}
		else {
			/* Stop parsing if first line is not a valid header.
			 * Allows to immediately stop reading garbage file.
			 */
			if (!valid_format) {
				ha_warning("config: Invalid stats-file format in file '%s'.\n", global.stats_file);
				break;
			}
		}
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
