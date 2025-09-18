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
	if (!guid->key)
		return 1;

	chunk_appendf(out, "%s,", (char *)guid->key);

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
			if (!base_off_shared)
				return 0; // not allocated

			base_off = (char *)&px->fe_counters;

			off = 0;
		}
		else if (domain == STFILE_DOMAIN_PX_BE) {
			if (!(px->cap & PR_CAP_BE))
				return 0; /* silently ignored fe/be mismatch */

			base_off_shared = (char *)px->be_counters.shared.tg[0];
			if (!base_off_shared)
				return 0; // not allocated

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
		if (!base_off_shared)
			return 0; // not allocated

		base_off = (char *)li->counters;

		off = 0;
		break;

	case OBJ_TYPE_SERVER:
		if (domain != STFILE_DOMAIN_PX_BE)
			goto err;

		srv = __objt_server(node->obj_type);
		base_off_shared = (char *)srv->counters.shared.tg[0];
		if (!base_off_shared)
			return 0; // not allocated

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

/* returns 1 if the slot <id> is free in <hdr>, else 0
 */
static int shm_stats_file_slot_isfree(struct shm_stats_file_hdr *hdr, int id)
{
	int hb;

	hb = HA_ATOMIC_LOAD(&hdr->slots[id].heartbeat);
	return shm_hb_is_stale(hb);
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

/* returns NULL if no free object or pointer to existing object if
 * object can be reused
 */
static struct shm_stats_file_object *shm_stats_file_reuse_object(void)
{
	int it = 0;
	int objects;
	struct shm_stats_file_object *free_obj;

	BUG_ON(!shm_stats_file_hdr);
	objects = HA_ATOMIC_LOAD(&shm_stats_file_hdr->objects);
	if (!objects)
		return NULL;
	while (it < objects) {
		uint64_t users;
		int free = 0;

		free_obj = SHM_STATS_FILE_OBJECT(shm_stats_file_hdr, it);
		users = HA_ATOMIC_LOAD(&free_obj->users);
		if (!users)
			free = 1; // no doubt, no user using this object
		else {
			int slot = 0;

			/* if one or multiple users crashed or forgot to remove their bit
			 * from obj->users but aren't making use of it anymore, we can detect
			 * it by checking if the process related to "used" users slot are still
			 * effectively active
			 */
			free = 1; // consider all users are inactive for now

			while (slot < sizeof(shm_stats_file_hdr->slots) / sizeof(shm_stats_file_hdr->slots[0])) {
				if ((users & (1ULL << slot)) &&
				    !shm_stats_file_slot_isfree(shm_stats_file_hdr, slot)) {
					/* user still alive, so supposedly making use of it */
					free = 0;
					break;
				}
				slot++;
			}
		}
		if (free) {
			uint64_t nusers = (1ULL << shm_stats_file_slot);

			/* we use CAS here because we want to make sure that we are the only
			 * process who exclusively owns the object as we are about to reset it.
			 * In case of failure, we also don't expect our bit to be set, so
			 * CAS is the best fit here. First we set the obj's users bits to 0
			 * to make sure no other process will try to preload it (it may hold
			 * garbage content) as we are about to reset it with our data, then
			 * we do another CAS to confirm we are the owner of the object
			 */
			if (HA_ATOMIC_CAS(&free_obj->users, &users, 0)) {
				/* we set obj tgid to 0 so it can't be looked up in
				 * shm_stats_file_preload (tgid 0 is invalid)
				 */
				HA_ATOMIC_STORE(&free_obj->tgid, 0);

				/* now we finally try to acquire the object */
				users = 0;
				if (HA_ATOMIC_CAS(&free_obj->users, &users, nusers))
					return free_obj;
			}
			/* failed to CAS because of concurrent access, give up on this one */
		}
		it += 1;
	}
	return NULL;
}

/* returns pointer to new object in case of success and NULL in case
 * of failure (if adding the maximum number of objects is already
 * reached)
 *
 * <errmsg> will be set in case of failure to give more hints about the
 * error, it must be freed accordingly
 */
struct shm_stats_file_object *shm_stats_file_add_object(char **errmsg)
{
	struct shm_stats_file_object *new_obj;
	uint64_t expected_users;
	int objects, objects_slots;
	static uint last_failed_attempt = TICK_ETERNITY;

	/* if previous object reuse failed, don't try a new opportunistic
	 * reuse immediately because chances are high the new reuse attempt
	 * will also fail, and repeated failed reuse attempts could be costly
	 * with large number of objects
	 */
	if (last_failed_attempt != TICK_ETERNITY &&
	    !tick_is_expired(last_failed_attempt + MS_TO_TICKS(50), now_ms))
		goto add;

	new_obj = shm_stats_file_reuse_object();
	if (new_obj) {
		last_failed_attempt = TICK_ETERNITY;
		return new_obj;
	}
	else
		last_failed_attempt = now_ms;

 add:
	objects = HA_ATOMIC_LOAD(&shm_stats_file_hdr->objects);

	if (objects >= shm_stats_file_max_objects) {
		memprintf(errmsg, "Cannot add additionnal object to '%s' file, maximum number already reached (%d). "
		           "Adjust \"shm-stats-file-max-objects\" directive if needed.",
		           global.shm_stats_file, shm_stats_file_max_objects / global.nbtgroups);
		return NULL;
	}

	objects_slots = HA_ATOMIC_LOAD(&shm_stats_file_hdr->objects_slots);
	/* we increase objects slots by following half power of two curve to
	 * reduce waste while ensuring we don't grow the shm file (costly)
	 * too often
	 */
	if (objects + 1 > objects_slots) {
		int nobjects_slots;

		if (objects_slots < 2)
			nobjects_slots = objects_slots + 1;
		else if ((objects_slots & (objects_slots - 1)) == 0)
			nobjects_slots = objects_slots + objects_slots / 2;
		else
			nobjects_slots = (objects_slots & (objects_slots - 1)) * 2;

		if (shm_file_grow((nobjects_slots - objects_slots) * sizeof(struct shm_stats_file_object)) == 0) {
			memprintf(errmsg, "Error when trying to increase shm stats file size for '%s': %s",
			          global.shm_stats_file, strerror(errno));
			return NULL;
		}
		HA_ATOMIC_ADD(&shm_stats_file_hdr->objects_slots, nobjects_slots - objects_slots);
	}

	/* try to use this new slot */
	new_obj = SHM_STATS_FILE_OBJECT(shm_stats_file_hdr, objects);
	memset(new_obj, 0, sizeof(*new_obj)); // ensure object is reset before using it

	if (HA_ATOMIC_FETCH_ADD(&shm_stats_file_hdr->objects, 1) != objects) {
		/* a concurrent shm_stats_file_add_object stole our slot, retry */
		__ha_cpu_relax();
		goto add;
	}

	expected_users = 0;
	if (!HA_ATOMIC_CAS(&new_obj->users, &expected_users, (1ULL << shm_stats_file_slot))) {
		/* a parallel reuse stole us the object, retry */
		__ha_cpu_relax();
		goto add;
	}

	return new_obj;
};

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

/* loads shm_stats_file content and tries to associate existing objects from
 * the shared memory (if any) to objects defined in current haproxy config
 * based on GUIDs
 */
static void shm_stats_file_preload(void)
{
	int it = 0;
	int objects;
	struct shm_stats_file_object *curr_obj;

	BUG_ON(!shm_stats_file_hdr);
	objects = HA_ATOMIC_LOAD(&shm_stats_file_hdr->objects);
	if (!objects)
		return; // nothing to do

	while (it < objects) {
		struct guid_node *node;
		uint64_t users;
		uint8_t obj_tgid;

		curr_obj = SHM_STATS_FILE_OBJECT(shm_stats_file_hdr, it);

		users = HA_ATOMIC_FETCH_OR(&curr_obj->users, (1ULL << shm_stats_file_slot));

		/* ignore object if not used by anyone: when a process properly deinits,
		 * it removes its user bit from the object, thus an object without any
		 * bit should be considered as empty object
		*/
		if (!users)
			goto release;

		obj_tgid = HA_ATOMIC_LOAD(&curr_obj->tgid);

		/* ignore object if greater than our max tgid */
		if (obj_tgid <= global.nbtgroups &&
		    (node = guid_lookup(curr_obj->guid))) {
			switch (*node->obj_type) {
				case OBJ_TYPE_LISTENER:
				{
					struct listener *li;

					BUG_ON(curr_obj->type != SHM_STATS_FILE_OBJECT_TYPE_FE);
					li = __objt_listener(node->obj_type);
					// counters are optional for listeners
					if (li->counters && li->counters->shared.tg[obj_tgid - 1])
						li->counters->shared.tg[obj_tgid - 1] = &curr_obj->data.fe;
					break;
				}
				case OBJ_TYPE_SERVER:
				{
					struct server *sv;

					BUG_ON(curr_obj->type != SHM_STATS_FILE_OBJECT_TYPE_BE);
					sv = __objt_server(node->obj_type);
					if (sv->counters.shared.tg[obj_tgid - 1])
						sv->counters.shared.tg[obj_tgid - 1] = &curr_obj->data.be;
					break;
				}
				case OBJ_TYPE_PROXY:
				{
					struct proxy *px;

					px = __objt_proxy(node->obj_type);
					if (curr_obj->type == SHM_STATS_FILE_OBJECT_TYPE_FE &&
					    px->fe_counters.shared.tg[obj_tgid - 1])
						px->fe_counters.shared.tg[obj_tgid - 1] = &curr_obj->data.fe;
					else if (curr_obj->type == SHM_STATS_FILE_OBJECT_TYPE_BE &&
					        px->be_counters.shared.tg[obj_tgid - 1])
						px->be_counters.shared.tg[obj_tgid - 1] = &curr_obj->data.be;
					else
						goto release; // not supported
					break;
				}
				default:
					/* not supported */
					goto release;
			}
			/* success */
			goto next;
		}

release:
		/* we don't use this object, remove ourselves from object's users */
		HA_ATOMIC_AND(&curr_obj->users, ~(1ULL << shm_stats_file_slot));
next:
		it += 1;
	}
}

/* prepare and and initialize shm stats memory file as needed */
int shm_stats_file_prepare(void)
{
	struct task *heartbeat_task;
	int first = 0; // process responsible for initializing the shm memory
	int slot;
	int objects;

	BUG_ON(sizeof(struct shm_stats_file_hdr) != 672, "shm_stats_file_hdr struct size changed, "
	       "it is part of the exported API: ensure all precautions were taken (ie: shm_stats_file "
	       "version change) before adjusting this");
	BUG_ON(sizeof(struct shm_stats_file_object) != 544, "shm_stats_file_object struct size changed, "
	       "is is part of the exported API: ensure all precautions were taken (ie: shm_stats_file "
	       "version change) before adjusting this");

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

	/* check if the map is outdated and must be reset:
	 * let's consider the map is outdated unless we find an occupied slot
	 */
 check_outdated:
	if (first)
		goto skip_check_outdated; // not needed
	first = 1;
	slot = 0;
	objects = HA_ATOMIC_LOAD(&shm_stats_file_hdr->objects);
	while (slot < sizeof(shm_stats_file_hdr->slots) / sizeof(shm_stats_file_hdr->slots[0])) {
		if (!shm_stats_file_slot_isfree(shm_stats_file_hdr, slot)) {
			first = 0;
			break;
		}
		slot += 1;
	}
	if (first) {
		/* no more slots occupied, let's reset the map but take some precautions
		 * to ensure another reset doesn't occur in parallel
		 */
		if (!HA_ATOMIC_CAS(&shm_stats_file_hdr->objects, &objects, 0)) {
			__ha_cpu_relax();
			goto check_outdated;
		}
	}

 skip_check_outdated:

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

	/* try to preload existing objects in the shm (if any) */
	shm_stats_file_preload();

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
