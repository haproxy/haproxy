#include <haproxy/stats-file.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <import/ebmbtree.h>
#include <import/ebsttree.h>
#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/atomic.h>
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
#include <haproxy/task.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

struct shm_stats_file_hdr *shm_stats_file_hdr = NULL;
static int shm_stats_file_fd = -1;
int shm_stats_file_slot = -1;
int shm_stats_file_max_objects = -1;

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
	char *base_off, *base_off_shared;
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

			base_off_shared = (char *)px->fe_counters.shared.tg[0];
			base_off = (char *)&px->fe_counters;

			off = 0;
		}
		else if (domain == STFILE_DOMAIN_PX_BE) {
			if (!(px->cap & PR_CAP_BE))
				return 0; /* silently ignored fe/be mismatch */

			base_off_shared = (char *)px->be_counters.shared.tg[0];
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

		base_off_shared = (char *)li->counters->shared.tg[0];
		base_off = (char *)li->counters;

		off = 0;
		break;

	case OBJ_TYPE_SERVER:
		if (domain != STFILE_DOMAIN_PX_BE)
			goto err;

		srv = __objt_server(node->obj_type);
		base_off_shared = (char *)srv->counters.shared.tg[0];
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

		if (col->flags & STAT_COL_FL_SHARED)
			load_ctr(col, token, base_off_shared + col->metric.offset[off]);
		else
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

/* returns 1 if <hdr> shm version is compatible with current version
 * defined in stats-file-t.h or 0 if it is not compatible.
 */
static int shm_stats_file_check_ver(struct shm_stats_file_hdr *hdr)
{
	/* for now we don't even support minor version difference but this may
	 * change later
	 */
	if (hdr->version.major != SHM_STATS_FILE_VER_MAJOR ||
	    hdr->version.minor != SHM_STATS_FILE_VER_MINOR)
		return 0;
	return 1;
}

static inline int shm_hb_is_stale(int hb)
{
	return (hb == TICK_ETERNITY || tick_is_expired(hb, now_ms));
}

/* returns free slot id on success or -1 if no more slots are available
 * on success, the free slot is already reserved for the process pid
 */
int shm_stats_file_get_free_slot(struct shm_stats_file_hdr *hdr)
{
	int it = 0;
	int hb;

	while (it < sizeof(hdr->slots) / sizeof(hdr->slots[0])) {
		hb = HA_ATOMIC_LOAD(&hdr->slots[it].heartbeat);
		/* try to own a stale entry */
		while (shm_hb_is_stale(hb)) {
			int new_hb = tick_add(now_ms, MS_TO_TICKS(SHM_STATS_FILE_HEARTBEAT_TIMEOUT * 1000));

			if (HA_ATOMIC_CAS(&hdr->slots[it].heartbeat, &hb, new_hb)) {
				shm_stats_file_hdr->slots[it].pid = getpid();
				return it;
			}
			/* another process was faster than us */
			__ha_cpu_relax();
		}
		it += 1;
	}
	return -1;
}

/* since shm file was opened using O_APPEND flag, let's grow
 * the file by <bytes> in an atomic manner (O_APPEND offers such guarantee),
 * so that even if multiple processes try to grow the file simultaneously,
 * the file can only grow bigger and never shrink
 *
 * We do this way because ftruncate() between multiple processes
 * could result in the file being shrunk if one of the process
 * is not aware that the file was already expanded in the meantime
 *
 * Returns 1 on success and 0 on failure
 */
static int shm_file_grow(unsigned int bytes)
{
	char buf[1024] = {0};
	ssize_t ret;

	while (bytes) {
		ret = write(shm_stats_file_fd, buf, MIN(sizeof(buf), bytes));
		if (ret <= 0)
			return 0;
		bytes -= ret;
	}
	return 1;
}

static struct task *shm_stats_file_hb(struct task *task, void *context, unsigned int state)
{
	if (stopping)
		return NULL;

	/* only update the heartbeat if it hasn't expired. Else it means the slot could have
	 * been reused and it isn't safe to use anymore.
	 * If this happens, raise a warning and stop using it
	 */
	if (tick_is_expired(HA_ATOMIC_LOAD(&shm_stats_file_hdr->slots[shm_stats_file_slot].heartbeat), now_ms)) {
		ha_warning("shm_stats_file: heartbeat for the current process slot already expired, it is not safe to use it anymore\n");
		task->expire = TICK_ETERNITY;
		return task;
	}
	HA_ATOMIC_STORE(&shm_stats_file_hdr->slots[shm_stats_file_slot].heartbeat,
	                tick_add(now_ms, MS_TO_TICKS(SHM_STATS_FILE_HEARTBEAT_TIMEOUT * 1000)));
	task->expire = tick_add(now_ms, 1000); // next update in 1 sec

	return task;
}

/* prepare and and initialize shm stats memory file as needed */
int shm_stats_file_prepare(void)
{
	struct task *heartbeat_task;
	int first = 0; // process responsible for initializing the shm memory
	int slot;

	/* do nothing if master process or shm_stats_file not configured */
	if (master || !global.shm_stats_file)
		return ERR_NONE;

	/* compute final shm_stats_file_max_objects value */
	if (shm_stats_file_max_objects == -1)
		shm_stats_file_max_objects = SHM_STATS_FILE_MAX_OBJECTS * global.nbtgroups;
	else
		shm_stats_file_max_objects = shm_stats_file_max_objects * global.nbtgroups;

	shm_stats_file_fd = open(global.shm_stats_file, O_RDWR | O_APPEND | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (shm_stats_file_fd == -1) {
		shm_stats_file_fd = open(global.shm_stats_file, O_RDWR | O_APPEND, S_IRUSR | S_IWUSR);
		if (shm_stats_file_fd == -1) {
			ha_alert("config: cannot open shm stats file '%s': %s\n", global.shm_stats_file, strerror(errno));
			return ERR_ALERT | ERR_FATAL;
		}
	}
	else {
		first = 1;
		if (shm_file_grow(sizeof(*shm_stats_file_hdr)) == 0) {
			ha_alert("config: unable to resize shm stats file '%s'\n", global.shm_stats_file);
			return ERR_ALERT | ERR_FATAL;
		}
	}
	/* mmap maximum contiguous address space for expected objects even if the backing shm is
	 * smaller: it will allow for on the fly shm resizing without having to remap
	 */
	shm_stats_file_hdr = mmap(NULL,
	                          SHM_STATS_FILE_MAPPING_SIZE(shm_stats_file_max_objects),
	                          PROT_READ | PROT_WRITE, MAP_SHARED, shm_stats_file_fd, 0);
	if (shm_stats_file_hdr == MAP_FAILED || shm_stats_file_hdr == NULL) {
		ha_alert("config: failed to map shm stats file '%s'\n", global.shm_stats_file);
		return ERR_ALERT | ERR_FATAL;
	}

	if (first) {
		/* let's init some members */
		memset(shm_stats_file_hdr, 0, sizeof(*shm_stats_file_hdr));
		shm_stats_file_hdr->version.major = SHM_STATS_FILE_VER_MAJOR;
		shm_stats_file_hdr->version.minor = SHM_STATS_FILE_VER_MINOR;

		/* set global clock for the first time */
		shm_stats_file_hdr->global_now_ms = *global_now_ms;
		shm_stats_file_hdr->global_now_ns = *global_now_ns;
		shm_stats_file_hdr->now_offset = clock_get_now_offset();
	}
	else if (!shm_stats_file_check_ver(shm_stats_file_hdr))
		goto err_version;

	/* from now on use the shared global time */
	global_now_ms = &shm_stats_file_hdr->global_now_ms;
	global_now_ns = &shm_stats_file_hdr->global_now_ns;

	if (!first) {
		llong adjt_offset;

		/* set adjusted offset which corresponds to the corrected offset
		 * relative to the initial offset stored in the shared memory instead
		 * of our process-local one
		 */
		adjt_offset = -clock_get_now_offset() + shm_stats_file_hdr->now_offset;

		/* we now rely on global_now_* from the shm, so the boot
		 * offset that was initially applied in clock_init_process_date()
		 * is no longer relevant. So we fix it by applying the one from the
		 * initial process instead
		 */
		now_ns = now_ns + adjt_offset;
		start_time_ns = start_time_ns + adjt_offset;
		clock_set_now_offset(shm_stats_file_hdr->now_offset);

		/* ensure global_now_* is consistent before continuing */
		clock_update_global_date();
	}

	/* now that global_now_ns is accurate, recompute precise now_offset
	 * if needed (in case it is dynamic when monotonic clock not available)
	 */
	if (!th_ctx->curr_mono_time)
		clock_set_now_offset(HA_ATOMIC_LOAD(global_now_ns) - tv_to_ns(&date));

	/* sync local and global clocks, so all clocks are consistent */
	clock_update_date(0, 1);

	/* reserve our slot */
	slot = shm_stats_file_get_free_slot(shm_stats_file_hdr);
	if (slot == -1) {
		ha_warning("config: failed to get shm stats file slot for '%s', all slots are occupied\n", global.shm_stats_file);
		munmap(shm_stats_file_hdr, sizeof(*shm_stats_file_hdr));
		return ERR_WARN;
	}

	shm_stats_file_slot = slot;

	/* start the task responsible for updating the heartbeat */
	heartbeat_task = task_new_anywhere();
	if (!heartbeat_task) {
		ha_alert("config: failed to create the heartbeat task for shm stats file '%s'\n", global.shm_stats_file);
		return ERR_ALERT | ERR_FATAL;
	}
	heartbeat_task->process = shm_stats_file_hb;
	task_schedule(heartbeat_task, tick_add(now_ms, 1000));

 end:
	return ERR_NONE;

 err_version:
		ha_warning("config: incompatible map shm stats file version '%s'\n", global.shm_stats_file);
	return ERR_WARN;
}

static void cleanup_shm_stats_file(void)
{
	if (shm_stats_file_hdr) {
		/* mark the process slot we occupied as unused */
		HA_ATOMIC_STORE(&shm_stats_file_hdr->slots[shm_stats_file_slot].heartbeat, TICK_ETERNITY);
		shm_stats_file_hdr->slots[shm_stats_file_slot].pid = -1;

		munmap(shm_stats_file_hdr, SHM_STATS_FILE_MAPPING_SIZE(shm_stats_file_max_objects));
		close(shm_stats_file_fd);
	}
}
REGISTER_POST_DEINIT(cleanup_shm_stats_file);
