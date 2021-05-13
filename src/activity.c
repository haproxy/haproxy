/*
 * activity measurement functions.
 *
 * Copyright 2000-2018 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/activity-t.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/stream_interface.h>
#include <haproxy/tools.h>

#if defined(DEBUG_MEM_STATS)
/* these ones are macros in bug.h when DEBUG_MEM_STATS is set, and will
 * prevent the new ones from being redefined.
 */
#undef calloc
#undef malloc
#undef realloc
#endif

/* bit field of profiling options. Beware, may be modified at runtime! */
unsigned int profiling __read_mostly = HA_PROF_TASKS_AOFF;
unsigned long task_profiling_mask __read_mostly = 0;

/* One struct per thread containing all collected measurements */
struct activity activity[MAX_THREADS] __attribute__((aligned(64))) = { };

/* One struct per function pointer hash entry (256 values, 0=collision) */
struct sched_activity sched_activity[256] __attribute__((aligned(64))) = { };


#if USE_MEMORY_PROFILING
/* determine the number of buckets to store stats */
#define MEMPROF_HASH_BITS 10
#define MEMPROF_HASH_BUCKETS (1U << MEMPROF_HASH_BITS)

enum memprof_method {
	MEMPROF_METH_UNKNOWN = 0,
	MEMPROF_METH_MALLOC,
	MEMPROF_METH_CALLOC,
	MEMPROF_METH_REALLOC,
	MEMPROF_METH_FREE,
	MEMPROF_METH_METHODS /* count, must be last */
};

static const char *const memprof_methods[MEMPROF_METH_METHODS] = {
	"unknown", "malloc", "calloc", "realloc", "free",
};

/* stats:
 *   - malloc increases alloc
 *   - free increases free (if non null)
 *   - realloc increases either depending on the size change.
 * when the real size is known (malloc_usable_size()), it's used in free_tot
 * and alloc_tot, otherwise the requested size is reported in alloc_tot and
 * zero in free_tot.
 */
struct memprof_stats {
	const void *caller;
	enum memprof_method method;
	/* 4-7 bytes hole here */
	unsigned long long alloc_calls;
	unsigned long long free_calls;
	unsigned long long alloc_tot;
	unsigned long long free_tot;
};

/* last one is for hash collisions ("others") and has no caller address */
struct memprof_stats memprof_stats[MEMPROF_HASH_BUCKETS + 1] = { };

/* used to detect recursive calls */
static THREAD_LOCAL int in_memprof = 0;

/* perform a pointer hash by scrambling its bits and retrieving the most
 * mixed ones (topmost ones in 32-bit, middle ones in 64-bit).
 */
static unsigned int memprof_hash_ptr(const void *p)
{
	unsigned long long x = (unsigned long)p;

	x = 0xcbda9653U * x;
	if (sizeof(long) == 4)
		x >>= 32;
	else
		x >>= 33 - MEMPROF_HASH_BITS / 2;
	return x & (MEMPROF_HASH_BUCKETS - 1);
}

/* These ones are used by glibc and will be called early. They are in charge of
 * initializing the handlers with the original functions.
 */
static void *memprof_malloc_initial_handler(size_t size);
static void *memprof_calloc_initial_handler(size_t nmemb, size_t size);
static void *memprof_realloc_initial_handler(void *ptr, size_t size);
static void  memprof_free_initial_handler(void *ptr);

/* Fallback handlers for the main alloc/free functions. They are preset to
 * the initializer in order to save a test in the functions's critical path.
 */
static void *(*memprof_malloc_handler)(size_t size)               = memprof_malloc_initial_handler;
static void *(*memprof_calloc_handler)(size_t nmemb, size_t size) = memprof_calloc_initial_handler;
static void *(*memprof_realloc_handler)(void *ptr, size_t size)   = memprof_realloc_initial_handler;
static void  (*memprof_free_handler)(void *ptr)                   = memprof_free_initial_handler;

/* Used to force to die if it's not possible to retrieve the allocation
 * functions. We cannot even use stdio in this case.
 */
static __attribute__((noreturn)) void memprof_die(const char *msg)
{
	DISGUISE(write(2, msg, strlen(msg)));
	exit(1);
}

/* Resolve original allocation functions and initialize all handlers.
 * This must be called very early at boot, before the very first malloc()
 * call, and is not thread-safe! It's not even possible to use stdio there.
 * Worse, we have to account for the risk of reentrance from dlsym() when
 * it tries to prepare its error messages. Here its ahndled by in_memprof
 * that makes allocators return NULL. dlsym() handles it gracefully. An
 * alternate approach consists in calling aligned_alloc() from these places
 * but that would mean not being able to intercept it later if considered
 * useful to do so.
 */
static void memprof_init()
{
	in_memprof++;
	memprof_malloc_handler  = get_sym_next_addr("malloc");
	if (!memprof_malloc_handler)
		memprof_die("FATAL: malloc() function not found.\n");

	memprof_calloc_handler  = get_sym_next_addr("calloc");
	if (!memprof_calloc_handler)
		memprof_die("FATAL: calloc() function not found.\n");

	memprof_realloc_handler = get_sym_next_addr("realloc");
	if (!memprof_realloc_handler)
		memprof_die("FATAL: realloc() function not found.\n");

	memprof_free_handler    = get_sym_next_addr("free");
	if (!memprof_free_handler)
		memprof_die("FATAL: free() function not found.\n");
	in_memprof--;
}

/* the initial handlers will initialize all regular handlers and will call the
 * one they correspond to. A single one of these functions will typically be
 * called, though it's unknown which one (as any might be called before main).
 */
static void *memprof_malloc_initial_handler(size_t size)
{
	if (in_memprof) {
		/* it's likely that dlsym() needs malloc(), let's fail */
		return NULL;
	}

	memprof_init();
	return memprof_malloc_handler(size);
}

static void *memprof_calloc_initial_handler(size_t nmemb, size_t size)
{
	if (in_memprof) {
		/* it's likely that dlsym() needs calloc(), let's fail */
		return NULL;
	}
	memprof_init();
	return memprof_calloc_handler(nmemb, size);
}

static void *memprof_realloc_initial_handler(void *ptr, size_t size)
{
	if (in_memprof) {
		/* it's likely that dlsym() needs realloc(), let's fail */
		return NULL;
	}

	memprof_init();
	return memprof_realloc_handler(ptr, size);
}

static void  memprof_free_initial_handler(void *ptr)
{
	memprof_init();
	memprof_free_handler(ptr);
}

/* Assign a bin for the memprof_stats to the return address. May perform a few
 * attempts before finding the right one, but always succeeds (in the worst
 * case, returns a default bin). The caller address is atomically set except
 * for the default one which is never set.
 */
static struct memprof_stats *memprof_get_bin(const void *ra, enum memprof_method meth)
{
	int retries = 16; // up to 16 consecutive entries may be tested.
	const void *old;
	unsigned int bin;

	bin = memprof_hash_ptr(ra);
	for (; memprof_stats[bin].caller != ra; bin = (bin + 1) & (MEMPROF_HASH_BUCKETS - 1)) {
		if (!--retries) {
			bin = MEMPROF_HASH_BUCKETS;
			break;
		}

		old = NULL;
		if (!memprof_stats[bin].caller &&
		    HA_ATOMIC_CAS(&memprof_stats[bin].caller, &old, ra)) {
			memprof_stats[bin].method = meth;
			break;
		}
	}
	return &memprof_stats[bin];
}

/* This is the new global malloc() function. It must optimize for the normal
 * case (i.e. profiling disabled) hence the first test to permit a direct jump.
 * It must remain simple to guarantee the lack of reentrance. stdio is not
 * possible there even for debugging. The reported size is the really allocated
 * one as returned by malloc_usable_size(), because this will allow it to be
 * compared to the one before realloc() or free(). This is a GNU and jemalloc
 * extension but other systems may also store this size in ptr[-1].
 */
void *malloc(size_t size)
{
	struct memprof_stats *bin;
	void *ret;

	if (likely(!(profiling & HA_PROF_MEMORY)))
		return memprof_malloc_handler(size);

	ret = memprof_malloc_handler(size);
	size = malloc_usable_size(ret);

	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_MALLOC);
	_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
	_HA_ATOMIC_ADD(&bin->alloc_tot, size);
	return ret;
}

/* This is the new global calloc() function. It must optimize for the normal
 * case (i.e. profiling disabled) hence the first test to permit a direct jump.
 * It must remain simple to guarantee the lack of reentrance. stdio is not
 * possible there even for debugging. The reported size is the really allocated
 * one as returned by malloc_usable_size(), because this will allow it to be
 * compared to the one before realloc() or free(). This is a GNU and jemalloc
 * extension but other systems may also store this size in ptr[-1].
 */
void *calloc(size_t nmemb, size_t size)
{
	struct memprof_stats *bin;
	void *ret;

	if (likely(!(profiling & HA_PROF_MEMORY)))
		return memprof_calloc_handler(nmemb, size);

	ret = memprof_calloc_handler(nmemb, size);
	size = malloc_usable_size(ret);

	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_CALLOC);
	_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
	_HA_ATOMIC_ADD(&bin->alloc_tot, size);
	return ret;
}

/* This is the new global realloc() function. It must optimize for the normal
 * case (i.e. profiling disabled) hence the first test to permit a direct jump.
 * It must remain simple to guarantee the lack of reentrance. stdio is not
 * possible there even for debugging. The reported size is the really allocated
 * one as returned by malloc_usable_size(), because this will allow it to be
 * compared to the one before realloc() or free(). This is a GNU and jemalloc
 * extension but other systems may also store this size in ptr[-1].
 * Depending on the old vs new size, it's considered as an allocation or a free
 * (or neither if the size remains the same).
 */
void *realloc(void *ptr, size_t size)
{
	struct memprof_stats *bin;
	size_t size_before;
	void *ret;

	if (likely(!(profiling & HA_PROF_MEMORY)))
		return memprof_realloc_handler(ptr, size);

	size_before = malloc_usable_size(ptr);
	ret = memprof_realloc_handler(ptr, size);
	size = malloc_usable_size(ret);

	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_REALLOC);
	if (size > size_before) {
		_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
		_HA_ATOMIC_ADD(&bin->alloc_tot, size - size_before);
	} else if (size < size_before) {
		_HA_ATOMIC_ADD(&bin->free_calls, 1);
		_HA_ATOMIC_ADD(&bin->free_tot, size_before - size);
	}
	return ret;
}

/* This is the new global free() function. It must optimize for the normal
 * case (i.e. profiling disabled) hence the first test to permit a direct jump.
 * It must remain simple to guarantee the lack of reentrance. stdio is not
 * possible there even for debugging. The reported size is the really allocated
 * one as returned by malloc_usable_size(), because this will allow it to be
 * compared to the one before realloc() or free(). This is a GNU and jemalloc
 * extension but other systems may also store this size in ptr[-1]. Since
 * free() is often called on NULL pointers to collect garbage at the end of
 * many functions or during config parsing, as a special case free(NULL)
 * doesn't update any stats.
 */
void free(void *ptr)
{
	struct memprof_stats *bin;
	size_t size_before;

	if (likely(!(profiling & HA_PROF_MEMORY) || !ptr)) {
		memprof_free_handler(ptr);
		return;
	}

	size_before = malloc_usable_size(ptr);
	memprof_free_handler(ptr);

	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_FREE);
	_HA_ATOMIC_ADD(&bin->free_calls, 1);
	_HA_ATOMIC_ADD(&bin->free_tot, size_before);
}

#endif // USE_MEMORY_PROFILING

/* Updates the current thread's statistics about stolen CPU time. The unit for
 * <stolen> is half-milliseconds.
 */
void report_stolen_time(uint64_t stolen)
{
	activity[tid].cpust_total += stolen;
	update_freq_ctr(&activity[tid].cpust_1s, stolen);
	update_freq_ctr_period(&activity[tid].cpust_15s, 15000, stolen);
}

#ifdef USE_MEMORY_PROFILING
/* config parser for global "profiling.memory", accepts "on" or "off" */
static int cfg_parse_prof_memory(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		profiling |= HA_PROF_MEMORY;
	else if (strcmp(args[1], "off") == 0)
		profiling &= ~HA_PROF_MEMORY;
	else {
		memprintf(err, "'%s' expects either 'on' or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}
#endif // USE_MEMORY_PROFILING

/* config parser for global "profiling.tasks", accepts "on" or "off" */
static int cfg_parse_prof_tasks(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_ON;
	else if (strcmp(args[1], "auto") == 0)
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_AOFF;
	else if (strcmp(args[1], "off") == 0)
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_OFF;
	else {
		memprintf(err, "'%s' expects either 'on', 'auto', or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* parse a "set profiling" command. It always returns 1. */
static int cli_parse_set_profiling(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (strcmp(args[2], "memory") == 0) {
#ifdef USE_MEMORY_PROFILING
		if (strcmp(args[3], "on") == 0) {
			unsigned int old = profiling;
			int i;

			while (!_HA_ATOMIC_CAS(&profiling, &old, old | HA_PROF_MEMORY))
				;

			/* also flush current profiling stats */
			for (i = 0; i < sizeof(memprof_stats) / sizeof(memprof_stats[0]); i++) {
				HA_ATOMIC_STORE(&memprof_stats[i].alloc_calls, 0);
				HA_ATOMIC_STORE(&memprof_stats[i].free_calls, 0);
				HA_ATOMIC_STORE(&memprof_stats[i].alloc_tot, 0);
				HA_ATOMIC_STORE(&memprof_stats[i].free_tot, 0);
				HA_ATOMIC_STORE(&memprof_stats[i].caller, NULL);
			}
		}
		else if (strcmp(args[3], "off") == 0) {
			unsigned int old = profiling;

			while (!_HA_ATOMIC_CAS(&profiling, &old, old & ~HA_PROF_MEMORY))
				;
		}
		else
			return cli_err(appctx, "Expects either 'on' or 'off'.\n");
		return 1;
#else
		return cli_err(appctx, "Memory profiling not compiled in.\n");
#endif
	}

	if (strcmp(args[2], "tasks") != 0)
		return cli_err(appctx, "Expects either 'tasks' or 'memory'.\n");

	if (strcmp(args[3], "on") == 0) {
		unsigned int old = profiling;
		int i;

		while (!_HA_ATOMIC_CAS(&profiling, &old, (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_ON))
			;
		/* also flush current profiling stats */
		for (i = 0; i < 256; i++) {
			HA_ATOMIC_STORE(&sched_activity[i].calls, 0);
			HA_ATOMIC_STORE(&sched_activity[i].cpu_time, 0);
			HA_ATOMIC_STORE(&sched_activity[i].lat_time, 0);
			HA_ATOMIC_STORE(&sched_activity[i].func, NULL);
		}
	}
	else if (strcmp(args[3], "auto") == 0) {
		unsigned int old = profiling;
		unsigned int new;

		do {
			if ((old & HA_PROF_TASKS_MASK) >= HA_PROF_TASKS_AON)
				new = (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_AON;
			else
				new = (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_AOFF;
		} while (!_HA_ATOMIC_CAS(&profiling, &old, new));
	}
	else if (strcmp(args[3], "off") == 0) {
		unsigned int old = profiling;
		while (!_HA_ATOMIC_CAS(&profiling, &old, (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_OFF))
			;
	}
	else
		return cli_err(appctx, "Expects 'on', 'auto', or 'off'.\n");

	return 1;
}

static int cmp_sched_activity_calls(const void *a, const void *b)
{
	const struct sched_activity *l = (const struct sched_activity *)a;
	const struct sched_activity *r = (const struct sched_activity *)b;

	if (l->calls > r->calls)
		return -1;
	else if (l->calls < r->calls)
		return 1;
	else
		return 0;
}

static int cmp_sched_activity_addr(const void *a, const void *b)
{
	const struct sched_activity *l = (const struct sched_activity *)a;
	const struct sched_activity *r = (const struct sched_activity *)b;

	if (l->func > r->func)
		return -1;
	else if (l->func < r->func)
		return 1;
	else
		return 0;
}

#if USE_MEMORY_PROFILING
/* used by qsort below */
static int cmp_memprof_stats(const void *a, const void *b)
{
	const struct memprof_stats *l = (const struct memprof_stats *)a;
	const struct memprof_stats *r = (const struct memprof_stats *)b;

	if (l->alloc_tot + l->free_tot > r->alloc_tot + r->free_tot)
		return -1;
	else if (l->alloc_tot + l->free_tot < r->alloc_tot + r->free_tot)
		return 1;
	else
		return 0;
}

static int cmp_memprof_addr(const void *a, const void *b)
{
	const struct memprof_stats *l = (const struct memprof_stats *)a;
	const struct memprof_stats *r = (const struct memprof_stats *)b;

	if (l->caller > r->caller)
		return -1;
	else if (l->caller < r->caller)
		return 1;
	else
		return 0;
}
#endif // USE_MEMORY_PROFILING

/* This function dumps all profiling settings. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero.
 * It dumps some parts depending on the following states:
 *    ctx.cli.i0:
 *       0, 4: dump status, then jump to 1 if 0
 *       1, 5: dump tasks, then jump to 2 if 1
 *       2, 6: dump memory, then stop
 *    ctx.cli.i1:
 *       restart line for each step (starts at zero)
 *    ctx.cli.o0:
 *       may contain a configured max line count for each step (0=not set)
 *    ctx.cli.o1:
 *       0: sort by usage
 *       1: sort by address
 */
static int cli_io_handler_show_profiling(struct appctx *appctx)
{
	struct sched_activity tmp_activity[256] __attribute__((aligned(64)));
#if USE_MEMORY_PROFILING
	struct memprof_stats tmp_memstats[MEMPROF_HASH_BUCKETS + 1];
	unsigned long long tot_alloc_calls, tot_free_calls;
	unsigned long long tot_alloc_bytes, tot_free_bytes;
#endif
	struct stream_interface *si = appctx->owner;
	struct buffer *name_buffer = get_trash_chunk();
	const char *str;
	int max_lines;
	int i, max;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	switch (profiling & HA_PROF_TASKS_MASK) {
	case HA_PROF_TASKS_AOFF: str="auto-off"; break;
	case HA_PROF_TASKS_AON:  str="auto-on"; break;
	case HA_PROF_TASKS_ON:   str="on"; break;
	default:                 str="off"; break;
	}

	if ((appctx->ctx.cli.i0 & 3) != 0)
		goto skip_status;

	chunk_printf(&trash,
	             "Per-task CPU profiling              : %-8s      # set profiling tasks {on|auto|off}\n"
	             "Memory usage profiling              : %-8s      # set profiling memory {on|off}\n",
	             str, (profiling & HA_PROF_MEMORY) ? "on" : "off");

	if (ci_putchk(si_ic(si), &trash) == -1) {
		/* failed, try again */
		si_rx_room_blk(si);
		return 0;
	}

	appctx->ctx.cli.i1 = 0; // reset first line to dump
	if ((appctx->ctx.cli.i0 & 4) == 0)
		appctx->ctx.cli.i0++; // next step

 skip_status:
	if ((appctx->ctx.cli.i0 & 3) != 1)
		goto skip_tasks;

	memcpy(tmp_activity, sched_activity, sizeof(tmp_activity));
	if (appctx->ctx.cli.o1)
		qsort(tmp_activity, 256, sizeof(tmp_activity[0]), cmp_sched_activity_addr);
	else
		qsort(tmp_activity, 256, sizeof(tmp_activity[0]), cmp_sched_activity_calls);

	if (!appctx->ctx.cli.i1)
		chunk_appendf(&trash, "Tasks activity:\n"
		                      "  function                      calls   cpu_tot   cpu_avg   lat_tot   lat_avg\n");

	max_lines = appctx->ctx.cli.o0;
	if (!max_lines)
		max_lines = 256;

	for (i = appctx->ctx.cli.i1; i < max_lines && tmp_activity[i].calls; i++) {
		appctx->ctx.cli.i1 = i;
		chunk_reset(name_buffer);

		if (!tmp_activity[i].func)
			chunk_printf(name_buffer, "other");
		else
			resolve_sym_name(name_buffer, "", tmp_activity[i].func);

		/* reserve 35 chars for name+' '+#calls, knowing that longer names
		 * are often used for less often called functions.
		 */
		max = 35 - name_buffer->data;
		if (max < 1)
			max = 1;
		chunk_appendf(&trash, "  %s%*llu", name_buffer->area, max, (unsigned long long)tmp_activity[i].calls);

		print_time_short(&trash, "   ", tmp_activity[i].cpu_time, "");
		print_time_short(&trash, "   ", tmp_activity[i].cpu_time / tmp_activity[i].calls, "");
		print_time_short(&trash, "   ", tmp_activity[i].lat_time, "");
		print_time_short(&trash, "   ", tmp_activity[i].lat_time / tmp_activity[i].calls, "\n");

		if (ci_putchk(si_ic(si), &trash) == -1) {
			/* failed, try again */
			si_rx_room_blk(si);
			return 0;
		}
	}

	if (ci_putchk(si_ic(si), &trash) == -1) {
		/* failed, try again */
		si_rx_room_blk(si);
		return 0;
	}

	appctx->ctx.cli.i1 = 0; // reset first line to dump
	if ((appctx->ctx.cli.i0 & 4) == 0)
		appctx->ctx.cli.i0++; // next step

 skip_tasks:

#if USE_MEMORY_PROFILING
	if ((appctx->ctx.cli.i0 & 3) != 2)
		goto skip_mem;

	memcpy(tmp_memstats, memprof_stats, sizeof(tmp_memstats));
	if (appctx->ctx.cli.o1)
		qsort(tmp_memstats, MEMPROF_HASH_BUCKETS+1, sizeof(tmp_memstats[0]), cmp_memprof_addr);
	else
		qsort(tmp_memstats, MEMPROF_HASH_BUCKETS+1, sizeof(tmp_memstats[0]), cmp_memprof_stats);

	if (!appctx->ctx.cli.i1)
		chunk_appendf(&trash,
		              "Alloc/Free statistics by call place:\n"
		              "         Calls         |         Tot Bytes           |       Caller and method\n"
		              "<- alloc -> <- free  ->|<-- alloc ---> <-- free ---->|\n");

	max_lines = appctx->ctx.cli.o0;
	if (!max_lines)
		max_lines = MEMPROF_HASH_BUCKETS + 1;

	for (i = appctx->ctx.cli.i1; i < max_lines; i++) {
		struct memprof_stats *entry = &tmp_memstats[i];

		appctx->ctx.cli.i1 = i;
		if (!entry->alloc_calls && !entry->free_calls)
			continue;
		chunk_appendf(&trash, "%11llu %11llu %14llu %14llu| %16p ",
			      entry->alloc_calls, entry->free_calls,
			      entry->alloc_tot, entry->free_tot,
			      entry->caller);

		if (entry->caller)
			resolve_sym_name(&trash, NULL, entry->caller);
		else
			chunk_appendf(&trash, "[other]");

		chunk_appendf(&trash," %s(%lld)\n", memprof_methods[entry->method],
			      (long long)(entry->alloc_tot - entry->free_tot) / (long long)(entry->alloc_calls + entry->free_calls));

		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			return 0;
		}
	}

	if (ci_putchk(si_ic(si), &trash) == -1) {
		si_rx_room_blk(si);
		return 0;
	}

	tot_alloc_calls = tot_free_calls = tot_alloc_bytes = tot_free_bytes = 0;
	for (i = 0; i < max_lines; i++) {
		tot_alloc_calls += tmp_memstats[i].alloc_calls;
		tot_free_calls  += tmp_memstats[i].free_calls;
		tot_alloc_bytes += tmp_memstats[i].alloc_tot;
		tot_free_bytes  += tmp_memstats[i].free_tot;
	}

	chunk_appendf(&trash,
	              "-----------------------|-----------------------------|\n"
		      "%11llu %11llu %14llu %14llu| <- Total; Delta_calls=%lld; Delta_bytes=%lld\n",
		      tot_alloc_calls, tot_free_calls,
		      tot_alloc_bytes, tot_free_bytes,
		      tot_alloc_calls - tot_free_calls,
		      tot_alloc_bytes - tot_free_bytes);

	if (ci_putchk(si_ic(si), &trash) == -1) {
		si_rx_room_blk(si);
		return 0;
	}

	appctx->ctx.cli.i1 = 0; // reset first line to dump
	if ((appctx->ctx.cli.i0 & 4) == 0)
		appctx->ctx.cli.i0++; // next step

 skip_mem:
#endif // USE_MEMORY_PROFILING

	return 1;
}

/* parse a "show profiling" command. It returns 1 on failure, 0 if it starts to dump.
 *  - cli.i0 is set to the first state (0=all, 4=status, 5=tasks, 6=memory)
 *  - cli.o1 is set to 1 if the output must be sorted by addr instead of usage
 *  - cli.o0 is set to the number of lines of output
 */
static int cli_parse_show_profiling(char **args, char *payload, struct appctx *appctx, void *private)
{
	int arg;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	for (arg = 2; *args[arg]; arg++) {
		if (strcmp(args[arg], "all") == 0) {
			appctx->ctx.cli.i0 = 0; // will cycle through 0,1,2; default
		}
		else if (strcmp(args[arg], "status") == 0) {
			appctx->ctx.cli.i0 = 4; // will visit status only
		}
		else if (strcmp(args[arg], "tasks") == 0) {
			appctx->ctx.cli.i0 = 5; // will visit tasks only
		}
		else if (strcmp(args[arg], "memory") == 0) {
			appctx->ctx.cli.i0 = 6; // will visit memory only
		}
		else if (strcmp(args[arg], "byaddr") == 0) {
			appctx->ctx.cli.o1 = 1; // sort output by address instead of usage
		}
		else if (isdigit((unsigned char)*args[arg])) {
			appctx->ctx.cli.o0 = atoi(args[arg]); // number of entries to dump
		}
		else
			return cli_err(appctx, "Expects either 'all', 'status', 'tasks', 'memory', 'byaddr' or a max number of output lines.\n");
	}
	return 0;
}

/* This function scans all threads' run queues and collects statistics about
 * running tasks. It returns 0 if the output buffer is full and it needs to be
 * called again, otherwise non-zero.
 */
static int cli_io_handler_show_tasks(struct appctx *appctx)
{
	struct sched_activity tmp_activity[256] __attribute__((aligned(64)));
	struct stream_interface *si = appctx->owner;
	struct buffer *name_buffer = get_trash_chunk();
	struct sched_activity *entry;
	const struct tasklet *tl;
	const struct task *t;
	uint64_t now_ns, lat;
	struct eb32sc_node *rqnode;
	uint64_t tot_calls;
	int thr, queue;
	int i, max;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	/* It's not possible to scan queues in small chunks and yield in the
	 * middle of the dump and come back again. So what we're doing instead
	 * is to freeze all threads and inspect their queues at once as fast as
	 * possible, using a sched_activity array to collect metrics with
	 * limited collision, then we'll report statistics only. The tasks'
	 * #calls will reflect the number of occurrences, and the lat_time will
	 * reflect the latency when set. We prefer to take the time before
	 * calling thread_isolate() so that the wait time doesn't impact the
	 * measurement accuracy. However this requires to take care of negative
	 * times since tasks might be queued after we retrieve it.
	 */

	now_ns = now_mono_time();
	memset(tmp_activity, 0, sizeof(tmp_activity));

	thread_isolate();

	/* 1. global run queue */

#ifdef USE_THREAD
	rqnode = eb32sc_first(&rqueue, ~0UL);
	while (rqnode) {
		t = eb32sc_entry(rqnode, struct task, rq);
		entry = sched_activity_entry(tmp_activity, t->process);
		if (t->call_date) {
			lat = now_ns - t->call_date;
			if ((int64_t)lat > 0)
				entry->lat_time += lat;
		}
		entry->calls++;
		rqnode = eb32sc_next(rqnode, ~0UL);
	}
#endif
	/* 2. all threads's local run queues */
	for (thr = 0; thr < global.nbthread; thr++) {
		/* task run queue */
		rqnode = eb32sc_first(&task_per_thread[thr].rqueue, ~0UL);
		while (rqnode) {
			t = eb32sc_entry(rqnode, struct task, rq);
			entry = sched_activity_entry(tmp_activity, t->process);
			if (t->call_date) {
				lat = now_ns - t->call_date;
				if ((int64_t)lat > 0)
					entry->lat_time += lat;
			}
			entry->calls++;
			rqnode = eb32sc_next(rqnode, ~0UL);
		}

		/* shared tasklet list */
		list_for_each_entry(tl, mt_list_to_list(&task_per_thread[thr].shared_tasklet_list), list) {
			t = (const struct task *)tl;
			entry = sched_activity_entry(tmp_activity, t->process);
			if (!TASK_IS_TASKLET(t) && t->call_date) {
				lat = now_ns - t->call_date;
				if ((int64_t)lat > 0)
					entry->lat_time += lat;
			}
			entry->calls++;
		}

		/* classful tasklets */
		for (queue = 0; queue < TL_CLASSES; queue++) {
			list_for_each_entry(tl, &task_per_thread[thr].tasklets[queue], list) {
				t = (const struct task *)tl;
				entry = sched_activity_entry(tmp_activity, t->process);
				if (!TASK_IS_TASKLET(t) && t->call_date) {
					lat = now_ns - t->call_date;
					if ((int64_t)lat > 0)
						entry->lat_time += lat;
				}
				entry->calls++;
			}
		}
	}

	/* hopefully we're done */
	thread_release();

	chunk_reset(&trash);

	tot_calls = 0;
	for (i = 0; i < 256; i++)
		tot_calls += tmp_activity[i].calls;

	qsort(tmp_activity, 256, sizeof(tmp_activity[0]), cmp_sched_activity_calls);

	chunk_appendf(&trash, "Running tasks: %d (%d threads)\n"
		      "  function                     places     %%    lat_tot   lat_avg\n",
		      (int)tot_calls, global.nbthread);

	for (i = 0; i < 256 && tmp_activity[i].calls; i++) {
		chunk_reset(name_buffer);

		if (!tmp_activity[i].func)
			chunk_printf(name_buffer, "other");
		else
			resolve_sym_name(name_buffer, "", tmp_activity[i].func);

		/* reserve 35 chars for name+' '+#calls, knowing that longer names
		 * are often used for less often called functions.
		 */
		max = 35 - name_buffer->data;
		if (max < 1)
			max = 1;
		chunk_appendf(&trash, "  %s%*llu  %3d.%1d",
		              name_buffer->area, max, (unsigned long long)tmp_activity[i].calls,
		              (int)(100ULL * tmp_activity[i].calls / tot_calls),
		              (int)((1000ULL * tmp_activity[i].calls / tot_calls)%10));
		print_time_short(&trash, "   ", tmp_activity[i].lat_time, "");
		print_time_short(&trash, "   ", tmp_activity[i].lat_time / tmp_activity[i].calls, "\n");
	}

	if (ci_putchk(si_ic(si), &trash) == -1) {
		/* failed, try again */
		si_rx_room_blk(si);
		return 0;
	}
	return 1;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
#ifdef USE_MEMORY_PROFILING
	{ CFG_GLOBAL, "profiling.memory",     cfg_parse_prof_memory     },
#endif
	{ CFG_GLOBAL, "profiling.tasks",      cfg_parse_prof_tasks      },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "set",  "profiling", NULL }, "set profiling <what> {auto|on|off}      : enable/disable resource profiling (tasks,memory)", cli_parse_set_profiling,  NULL },
	{ { "show", "profiling", NULL }, "show profiling [<what>|<#lines>|byaddr]*: show profiling state (all,status,tasks,memory)",   cli_parse_show_profiling, cli_io_handler_show_profiling, NULL },
	{ { "show", "tasks", NULL },     "show tasks                              : show running tasks",                               NULL, cli_io_handler_show_tasks,     NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
