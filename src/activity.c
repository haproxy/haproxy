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

#include <errno.h>
#include <haproxy/activity-t.h>
#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/cfgparse.h>
#include <haproxy/clock.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/listener.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stconn.h>
#include <haproxy/tools.h>

/* CLI context for the "show profiling" command */
struct show_prof_ctx {
	int dump_step;  /* 0,1,2,4,5,6; see cli_iohandler_show_profiling() */
	int linenum;    /* next line to be dumped (starts at 0) */
	int maxcnt;     /* max line count per step (0=not set)  */
	int by_what;    /* 0=sort by usage, 1=sort by address, 2=sort by time */
	int aggr;       /* 0=dump raw, 1=aggregate on callee    */
};

/* CLI context for the "show activity" command */
struct show_activity_ctx {
	int thr;         /* thread ID to show or -1 for all */
	int line;        /* line number being dumped */
	int col;         /* columnline being dumped, 0 to nbt+1 */
};

#if defined(DEBUG_MEM_STATS)
/* these ones are macros in bug.h when DEBUG_MEM_STATS is set, and will
 * prevent the new ones from being redefined.
 */
#undef calloc
#undef malloc
#undef realloc
#undef strdup
#endif

/* bit field of profiling options. Beware, may be modified at runtime! */
unsigned int profiling __read_mostly = HA_PROF_TASKS_AOFF;

/* start/stop dates of profiling */
uint64_t prof_task_start_ns = 0;
uint64_t prof_task_stop_ns = 0;
uint64_t prof_mem_start_ns = 0;
uint64_t prof_mem_stop_ns = 0;

/* One struct per thread containing all collected measurements */
struct activity activity[MAX_THREADS] __attribute__((aligned(64))) = { };

/* One struct per function pointer hash entry (SCHED_ACT_HASH_BUCKETS values, 0=collision) */
struct sched_activity sched_activity[SCHED_ACT_HASH_BUCKETS] __attribute__((aligned(64))) = { };


#ifdef USE_MEMORY_PROFILING

static const char *const memprof_methods[MEMPROF_METH_METHODS] = {
	"unknown", "malloc", "calloc", "realloc", "strdup", "free", "p_alloc", "p_free",
	"strndup", "valloc", "aligned_valloc", "posix_memalign", "memalign", "pvalloc",
};

/* last one is for hash collisions ("others") and has no caller address */
struct memprof_stats memprof_stats[MEMPROF_HASH_BUCKETS + 1] = { };

/* used to detect recursive calls */
static THREAD_LOCAL int in_memprof = 0;

/* These ones are used by glibc and will be called early. They are in charge of
 * initializing the handlers with the original functions.
 */
static void *memprof_malloc_initial_handler(size_t size);
static void *memprof_calloc_initial_handler(size_t nmemb, size_t size);
static void *memprof_realloc_initial_handler(void *ptr, size_t size);
static char *memprof_strdup_initial_handler(const char *s);
static void  memprof_free_initial_handler(void *ptr);

/* these ones are optional but may be used by some dependecies */
static char *memprof_strndup_initial_handler(const char *s, size_t n);
static void *memprof_valloc_initial_handler(size_t sz);
static void *memprof_pvalloc_initial_handler(size_t sz);
static void *memprof_memalign_initial_handler(size_t al, size_t sz);
static void *memprof_aligned_alloc_initial_handler(size_t al, size_t sz);
static int   memprof_posix_memalign_initial_handler(void **ptr, size_t al, size_t sz);

/* Fallback handlers for the main alloc/free functions. They are preset to
 * the initializer in order to save a test in the functions's critical path.
 */
static void *(*memprof_malloc_handler)(size_t size)               = memprof_malloc_initial_handler;
static void *(*memprof_calloc_handler)(size_t nmemb, size_t size) = memprof_calloc_initial_handler;
static void *(*memprof_realloc_handler)(void *ptr, size_t size)   = memprof_realloc_initial_handler;
static char *(*memprof_strdup_handler)(const char *s)             = memprof_strdup_initial_handler;
static void  (*memprof_free_handler)(void *ptr)                   = memprof_free_initial_handler;

/* these ones are optional but may be used by some dependecies */
static char *(*memprof_strndup_handler)(const char *s, size_t n)                 = memprof_strndup_initial_handler;
static void *(*memprof_valloc_handler)(size_t sz)                                = memprof_valloc_initial_handler;
static void *(*memprof_pvalloc_handler)(size_t sz)                               = memprof_pvalloc_initial_handler;
static void *(*memprof_memalign_handler)(size_t al, size_t sz)                   = memprof_memalign_initial_handler;
static void *(*memprof_aligned_alloc_handler)(size_t al, size_t sz)              = memprof_aligned_alloc_initial_handler;
static int   (*memprof_posix_memalign_handler)(void **ptr, size_t al, size_t sz) = memprof_posix_memalign_initial_handler;

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

	memprof_strdup_handler  = get_sym_next_addr("strdup");
	if (!memprof_strdup_handler)
		memprof_die("FATAL: strdup() function not found.\n");

	memprof_free_handler    = get_sym_next_addr("free");
	if (!memprof_free_handler)
		memprof_die("FATAL: free() function not found.\n");

	/* these ones are not always implemented, rarely used and may not exist
	 * so we don't fail on them.
	 */
	memprof_strndup_handler        = get_sym_next_addr("strndup");
	memprof_valloc_handler         = get_sym_next_addr("valloc");
	memprof_pvalloc_handler        = get_sym_next_addr("pvalloc");
	memprof_memalign_handler       = get_sym_next_addr("memalign");
	memprof_aligned_alloc_handler  = get_sym_next_addr("aligned_alloc");
	memprof_posix_memalign_handler = get_sym_next_addr("posix_memalign");

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

static char *memprof_strdup_initial_handler(const char *s)
{
	if (in_memprof) {
		/* probably that dlsym() needs strdup(), let's fail */
		return NULL;
	}

	memprof_init();
	return memprof_strdup_handler(s);
}

static void  memprof_free_initial_handler(void *ptr)
{
	memprof_init();
	memprof_free_handler(ptr);
}

/* optional handlers */

static char *memprof_strndup_initial_handler(const char *s, size_t n)
{
	if (in_memprof) {
		/* probably that dlsym() needs strndup(), let's fail */
		return NULL;
	}

	memprof_init();
	return memprof_strndup_handler(s, n);
}

static void *memprof_valloc_initial_handler(size_t sz)
{
	if (in_memprof) {
		/* probably that dlsym() needs valloc(), let's fail */
		return NULL;
	}

	memprof_init();
	return memprof_valloc_handler(sz);
}

static void *memprof_pvalloc_initial_handler(size_t sz)
{
	if (in_memprof) {
		/* probably that dlsym() needs pvalloc(), let's fail */
		return NULL;
	}

	memprof_init();
	return memprof_pvalloc_handler(sz);
}

static void *memprof_memalign_initial_handler(size_t al, size_t sz)
{
	if (in_memprof) {
		/* probably that dlsym() needs memalign(), let's fail */
		return NULL;
	}

	memprof_init();
	return memprof_memalign_handler(al, sz);
}

static void *memprof_aligned_alloc_initial_handler(size_t al, size_t sz)
{
	if (in_memprof) {
		/* probably that dlsym() needs aligned_alloc(), let's fail */
		return NULL;
	}

	memprof_init();
	return memprof_aligned_alloc_handler(al, sz);
}

static int memprof_posix_memalign_initial_handler(void **ptr, size_t al, size_t sz)
{
	if (in_memprof) {
		/* probably that dlsym() needs posix_memalign(), let's fail */
		return ENOMEM;
	}

	memprof_init();
	return memprof_posix_memalign_handler(ptr, al, sz);
}

/* Assign a bin for the memprof_stats to the return address. May perform a few
 * attempts before finding the right one, but always succeeds (in the worst
 * case, returns a default bin). The caller address is atomically set except
 * for the default one which is never set.
 */
struct memprof_stats *memprof_get_bin(const void *ra, enum memprof_method meth)
{
	int retries = 16; // up to 16 consecutive entries may be tested.
	const void *old;
	unsigned int bin;

	if (unlikely(!ra)) {
		bin = MEMPROF_HASH_BUCKETS;
		goto leave;
	}
	bin = ptr_hash(ra, MEMPROF_HASH_BITS);
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
leave:
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
	size = malloc_usable_size(ret) + sizeof(void *);

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
	size = malloc_usable_size(ret) + sizeof(void *);

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

	/* only count the extra link for new allocations */
	if (!ptr)
		size += sizeof(void *);

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

/* This is the new global strdup() function. It must optimize for the normal
 * case (i.e. profiling disabled) hence the first test to permit a direct jump.
 * It must remain simple to guarantee the lack of reentrance. stdio is not
 * possible there even for debugging. The reported size is the really allocated
 * one as returned by malloc_usable_size(), because this will allow it to be
 * compared to the one before realloc() or free(). This is a GNU and jemalloc
 * extension but other systems may also store this size in ptr[-1].
 */
char *strdup(const char *s)
{
	struct memprof_stats *bin;
	size_t size;
	char *ret;

	if (likely(!(profiling & HA_PROF_MEMORY)))
		return memprof_strdup_handler(s);

	ret = memprof_strdup_handler(s);
	size = malloc_usable_size(ret) + sizeof(void *);

	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_STRDUP);
	_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
	_HA_ATOMIC_ADD(&bin->alloc_tot, size);
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

	size_before = malloc_usable_size(ptr) + sizeof(void *);
	memprof_free_handler(ptr);

	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_FREE);
	_HA_ATOMIC_ADD(&bin->free_calls, 1);
	_HA_ATOMIC_ADD(&bin->free_tot, size_before);
}

/* optional handlers below, essentially to monitor libs activities */

char *strndup(const char *s, size_t size)
{
	struct memprof_stats *bin;
	char *ret;

	if (!memprof_strndup_handler)
		return NULL;

	ret = memprof_strndup_handler(s, size);
	if (likely(!(profiling & HA_PROF_MEMORY)))
		return ret;

	size = malloc_usable_size(ret) + sizeof(void *);
	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_STRNDUP);
	_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
	_HA_ATOMIC_ADD(&bin->alloc_tot, size);
	return ret;
}

void *valloc(size_t size)
{
	struct memprof_stats *bin;
	void *ret;

	if (!memprof_valloc_handler)
		return NULL;

	ret = memprof_valloc_handler(size);
	if (likely(!(profiling & HA_PROF_MEMORY)))
		return ret;

	size = malloc_usable_size(ret) + sizeof(void *);
	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_VALLOC);
	_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
	_HA_ATOMIC_ADD(&bin->alloc_tot, size);
	return ret;
}

void *pvalloc(size_t size)
{
	struct memprof_stats *bin;
	void *ret;

	if (!memprof_pvalloc_handler)
		return NULL;

	ret = memprof_pvalloc_handler(size);
	if (likely(!(profiling & HA_PROF_MEMORY)))
		return ret;

	size = malloc_usable_size(ret) + sizeof(void *);
	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_PVALLOC);
	_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
	_HA_ATOMIC_ADD(&bin->alloc_tot, size);
	return ret;
}

void *memalign(size_t align, size_t size)
{
	struct memprof_stats *bin;
	void *ret;

	if (!memprof_memalign_handler)
		return NULL;

	ret = memprof_memalign_handler(align, size);
	if (likely(!(profiling & HA_PROF_MEMORY)))
		return ret;

	size = malloc_usable_size(ret) + sizeof(void *);
	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_MEMALIGN);
	_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
	_HA_ATOMIC_ADD(&bin->alloc_tot, size);
	return ret;
}

void *aligned_alloc(size_t align, size_t size)
{
	struct memprof_stats *bin;
	void *ret;

	if (!memprof_aligned_alloc_handler)
		return NULL;

	ret = memprof_aligned_alloc_handler(align, size);
	if (likely(!(profiling & HA_PROF_MEMORY)))
		return ret;

	size = malloc_usable_size(ret) + sizeof(void *);
	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_ALIGNED_ALLOC);
	_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
	_HA_ATOMIC_ADD(&bin->alloc_tot, size);
	return ret;
}

int posix_memalign(void **ptr, size_t align, size_t size)
{
	struct memprof_stats *bin;
	int ret;

	if (!memprof_posix_memalign_handler)
		return ENOMEM;

	ret = memprof_posix_memalign_handler(ptr, align, size);
	if (likely(!(profiling & HA_PROF_MEMORY)))
		return ret;

	if (ret != 0) // error
		return ret;

	size = malloc_usable_size(*ptr) + sizeof(void *);
	bin = memprof_get_bin(__builtin_return_address(0), MEMPROF_METH_POSIX_MEMALIGN);
	_HA_ATOMIC_ADD(&bin->alloc_calls, 1);
	_HA_ATOMIC_ADD(&bin->alloc_tot, size);
	return ret;
}

/* remove info from entries matching <info>. This needs to be used by callers
 * of pool_destroy() so that we don't keep a reference to a dead pool. Nothing
 * is done if <info> is NULL.
 */
void memprof_remove_stale_info(const void *info)
{
	int i;

	if (!info)
		return;

	for (i = 0; i < MEMPROF_HASH_BUCKETS; i++) {
		if (_HA_ATOMIC_LOAD(&memprof_stats[i].info) == info)
			_HA_ATOMIC_STORE(&memprof_stats[i].info, NULL);
	}
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

/* Update avg_loop value for the current thread and possibly decide to enable
 * task-level profiling on the current thread based on its average run time.
 * The <run_time> argument is the number of microseconds elapsed since the
 * last time poll() returned.
 */
void activity_count_runtime(uint32_t run_time)
{
	uint32_t up, down;

	/* 1 millisecond per loop on average over last 1024 iterations is
	 * enough to turn on profiling.
	 */
	up = 1000;
	down = up * 99 / 100;

	run_time = swrate_add(&activity[tid].avg_loop_us, TIME_STATS_SAMPLES, run_time);

	/* In automatic mode, reaching the "up" threshold on average switches
	 * profiling to "on" when automatic, and going back below the "down"
	 * threshold switches to off. The forced modes don't check the load.
	 */
	if (!(_HA_ATOMIC_LOAD(&th_ctx->flags) & TH_FL_TASK_PROFILING)) {
		if (unlikely((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_ON ||
		             ((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_AON &&
		             swrate_avg(run_time, TIME_STATS_SAMPLES) >= up)))
			_HA_ATOMIC_OR(&th_ctx->flags, TH_FL_TASK_PROFILING);
	} else {
		if (unlikely((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_OFF ||
		             ((profiling & HA_PROF_TASKS_MASK) == HA_PROF_TASKS_AOFF &&
		             swrate_avg(run_time, TIME_STATS_SAMPLES) <= down)))
			_HA_ATOMIC_AND(&th_ctx->flags, ~TH_FL_TASK_PROFILING);
	}
}

#ifdef USE_MEMORY_PROFILING
/* config parser for global "profiling.memory", accepts "on" or "off" */
static int cfg_parse_prof_memory(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0) {
		profiling |= HA_PROF_MEMORY;
		HA_ATOMIC_STORE(&prof_mem_start_ns, now_ns);
	}
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

	if (strcmp(args[1], "on") == 0) {
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_ON;
		HA_ATOMIC_STORE(&prof_task_start_ns, now_ns);
	}
	else if (strcmp(args[1], "auto") == 0) {
		profiling = (profiling & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_AOFF;
		HA_ATOMIC_STORE(&prof_task_start_ns, now_ns);
	}
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

			HA_ATOMIC_STORE(&prof_mem_start_ns, now_ns);
			HA_ATOMIC_STORE(&prof_mem_stop_ns, 0);

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

			if (HA_ATOMIC_LOAD(&prof_mem_start_ns))
				HA_ATOMIC_STORE(&prof_mem_stop_ns, now_ns);
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

		HA_ATOMIC_STORE(&prof_task_start_ns, now_ns);
		HA_ATOMIC_STORE(&prof_task_stop_ns, 0);

		/* also flush current profiling stats */
		for (i = 0; i < SCHED_ACT_HASH_BUCKETS; i++) {
			HA_ATOMIC_STORE(&sched_activity[i].calls, 0);
			HA_ATOMIC_STORE(&sched_activity[i].cpu_time, 0);
			HA_ATOMIC_STORE(&sched_activity[i].lat_time, 0);
			HA_ATOMIC_STORE(&sched_activity[i].func, NULL);
			HA_ATOMIC_STORE(&sched_activity[i].caller, NULL);
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

		HA_ATOMIC_STORE(&prof_task_start_ns, now_ns);
		HA_ATOMIC_STORE(&prof_task_stop_ns, 0);
	}
	else if (strcmp(args[3], "off") == 0) {
		unsigned int old = profiling;
		while (!_HA_ATOMIC_CAS(&profiling, &old, (old & ~HA_PROF_TASKS_MASK) | HA_PROF_TASKS_OFF))
			;

		if (HA_ATOMIC_LOAD(&prof_task_start_ns))
			HA_ATOMIC_STORE(&prof_task_stop_ns, now_ns);
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

/* sort by address first, then by call count */
static int cmp_sched_activity_addr(const void *a, const void *b)
{
	const struct sched_activity *l = (const struct sched_activity *)a;
	const struct sched_activity *r = (const struct sched_activity *)b;

	if (l->func > r->func)
		return -1;
	else if (l->func < r->func)
		return 1;
	else if (l->calls > r->calls)
		return -1;
	else if (l->calls < r->calls)
		return 1;
	else
		return 0;
}

/* sort by cpu time first, then by inverse call count (to spot highest offenders) */
static int cmp_sched_activity_cpu(const void *a, const void *b)
{
	const struct sched_activity *l = (const struct sched_activity *)a;
	const struct sched_activity *r = (const struct sched_activity *)b;

	if (l->cpu_time > r->cpu_time)
		return -1;
	else if (l->cpu_time < r->cpu_time)
		return 1;
	else if (l->calls < r->calls)
		return -1;
	else if (l->calls > r->calls)
		return 1;
	else
		return 0;
}

#ifdef USE_MEMORY_PROFILING
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

/* Computes the index of function pointer <func> and caller <caller> for use
 * with sched_activity[] or any other similar array passed in <array>, and
 * returns a pointer to the entry after having atomically assigned it to this
 * function pointer and caller combination. Note that in case of collision,
 * the first entry is returned instead ("other").
 */
struct sched_activity *sched_activity_entry(struct sched_activity *array, const void *func, const void *caller)
{
	uint32_t hash = ptr2_hash(func, caller, SCHED_ACT_HASH_BITS);
	struct sched_activity *ret;
	const void *old;
	int tries = 16;

	for (tries = 16; tries > 0; tries--, hash++) {
		ret = &array[hash];

		while (1) {
			if (likely(ret->func)) {
				if (likely(ret->func == func && ret->caller == caller))
					return ret;
				break;
			}

			/* try to create the new entry. Func is sufficient to
			 * reserve the node.
			 */
			old = NULL;
			if (HA_ATOMIC_CAS(&ret->func, &old, func)) {
				ret->caller = caller;
				return ret;
			}
			/* changed in parallel, check again */
		}
	}

	return array;
}

/* This function dumps all profiling settings. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero.
 * It dumps some parts depending on the following states from show_prof_ctx:
 *    dump_step:
 *       0, 4: dump status, then jump to 1 if 0
 *       1, 5: dump tasks, then jump to 2 if 1
 *       2, 6: dump memory, then stop
 *    linenum:
 *       restart line for each step (starts at zero)
 *    maxcnt:
 *       may contain a configured max line count for each step (0=not set)
 *    byaddr:
 *       0: sort by usage
 *       1: sort by address
 */
static int cli_io_handler_show_profiling(struct appctx *appctx)
{
	struct show_prof_ctx *ctx = appctx->svcctx;
	struct sched_activity tmp_activity[SCHED_ACT_HASH_BUCKETS] __attribute__((aligned(64)));
#ifdef USE_MEMORY_PROFILING
	struct memprof_stats tmp_memstats[MEMPROF_HASH_BUCKETS + 1];
	unsigned long long tot_alloc_calls, tot_free_calls;
	unsigned long long tot_alloc_bytes, tot_free_bytes;
#endif
	struct buffer *name_buffer = get_trash_chunk();
	const struct ha_caller *caller;
	const char *str;
	int max_lines;
	int i, j, max;
	int dumped;

	chunk_reset(&trash);

	switch (profiling & HA_PROF_TASKS_MASK) {
	case HA_PROF_TASKS_AOFF: str="auto-off"; break;
	case HA_PROF_TASKS_AON:  str="auto-on"; break;
	case HA_PROF_TASKS_ON:   str="on"; break;
	default:                 str="off"; break;
	}

	if ((ctx->dump_step & 3) != 0)
		goto skip_status;

	chunk_printf(&trash,
	             "Per-task CPU profiling              : %-8s      # set profiling tasks {on|auto|off}\n"
	             "Memory usage profiling              : %-8s      # set profiling memory {on|off}\n",
	             str, (profiling & HA_PROF_MEMORY) ? "on" : "off");

	if (applet_putchk(appctx, &trash) == -1) {
		/* failed, try again */
		return 0;
	}

	ctx->linenum = 0; // reset first line to dump
	if ((ctx->dump_step & 4) == 0)
		ctx->dump_step++; // next step

 skip_status:
	if ((ctx->dump_step & 3) != 1)
		goto skip_tasks;

	memcpy(tmp_activity, sched_activity, sizeof(tmp_activity));
	/* for addr sort and for callee aggregation we have to first sort by address */
	if (ctx->aggr || ctx->by_what == 1) // sort by addr
		qsort(tmp_activity, SCHED_ACT_HASH_BUCKETS, sizeof(tmp_activity[0]), cmp_sched_activity_addr);	

	if (ctx->aggr) {
		/* merge entries for the same callee and reset their count */
		for (i = j = 0; i < SCHED_ACT_HASH_BUCKETS; i = j) {
			for (j = i + 1; j < SCHED_ACT_HASH_BUCKETS && tmp_activity[j].func == tmp_activity[i].func; j++) {
				tmp_activity[i].calls    += tmp_activity[j].calls;
				tmp_activity[i].cpu_time += tmp_activity[j].cpu_time;
				tmp_activity[i].lat_time += tmp_activity[j].lat_time;
				tmp_activity[j].calls = 0;
			}
		}
	}

	if (!ctx->by_what) // sort by usage
		qsort(tmp_activity, SCHED_ACT_HASH_BUCKETS, sizeof(tmp_activity[0]), cmp_sched_activity_calls);
	else if (ctx->by_what == 2) // by cpu_tot
		qsort(tmp_activity, SCHED_ACT_HASH_BUCKETS, sizeof(tmp_activity[0]), cmp_sched_activity_cpu);

	if (!ctx->linenum)
		chunk_appendf(&trash, "Tasks activity over %.3f sec till %.3f sec ago:\n"
		                      "  function                      calls   cpu_tot   cpu_avg   lat_tot   lat_avg\n",
			      (prof_task_start_ns ? (prof_task_stop_ns ? prof_task_stop_ns : now_ns) - prof_task_start_ns : 0) / 1000000000.0,
			      (prof_task_stop_ns ? now_ns - prof_task_stop_ns : 0) / 1000000000.0);

	max_lines = ctx->maxcnt;
	if (!max_lines)
		max_lines = SCHED_ACT_HASH_BUCKETS;

	dumped = 0;
	for (i = ctx->linenum; i < max_lines; i++) {
		if (!tmp_activity[i].calls)
			continue; // skip aggregated or empty entries

		ctx->linenum = i;

		/* resolve_sym_name() may be slow, better dump a few entries at a time */
		if (dumped >= 10)
			return 0;

		chunk_reset(name_buffer);
		caller = HA_ATOMIC_LOAD(&tmp_activity[i].caller);

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
		print_time_short(&trash, "   ", tmp_activity[i].lat_time / tmp_activity[i].calls, "");

		if (caller && !ctx->aggr && caller->what <= WAKEUP_TYPE_APPCTX_WAKEUP)
			chunk_appendf(&trash, " <- %s@%s:%d %s",
				      caller->func, caller->file, caller->line,
				      task_wakeup_type_str(caller->what));

		b_putchr(&trash, '\n');

		if (applet_putchk(appctx, &trash) == -1) {
			/* failed, try again */
			return 0;
		}
		dumped++;
	}

	if (applet_putchk(appctx, &trash) == -1) {
		/* failed, try again */
		return 0;
	}

	ctx->linenum = 0; // reset first line to dump
	if ((ctx->dump_step & 4) == 0)
		ctx->dump_step++; // next step

 skip_tasks:

#ifdef USE_MEMORY_PROFILING
	if ((ctx->dump_step & 3) != 2)
		goto skip_mem;

	memcpy(tmp_memstats, memprof_stats, sizeof(tmp_memstats));
	if (ctx->by_what)
		qsort(tmp_memstats, MEMPROF_HASH_BUCKETS+1, sizeof(tmp_memstats[0]), cmp_memprof_addr);
	else
		qsort(tmp_memstats, MEMPROF_HASH_BUCKETS+1, sizeof(tmp_memstats[0]), cmp_memprof_stats);

	if (!ctx->linenum)
		chunk_appendf(&trash,
		              "Alloc/Free statistics by call place over %.3f sec till %.3f sec ago:\n"
		              "         Calls         |         Tot Bytes           |       Caller and method\n"
		              "<- alloc -> <- free  ->|<-- alloc ---> <-- free ---->|\n",
			      (prof_mem_start_ns ? (prof_mem_stop_ns ? prof_mem_stop_ns : now_ns) - prof_mem_start_ns : 0) / 1000000000.0,
			      (prof_mem_stop_ns ? now_ns - prof_mem_stop_ns : 0) / 1000000000.0);

	max_lines = ctx->maxcnt;
	if (!max_lines)
		max_lines = MEMPROF_HASH_BUCKETS + 1;

	dumped = 0;
	for (i = ctx->linenum; i < max_lines; i++) {
		struct memprof_stats *entry = &tmp_memstats[i];

		ctx->linenum = i;
		if (!entry->alloc_calls && !entry->free_calls)
			continue;

		/* resolve_sym_name() may be slow, better dump a few entries at a time */
		if (dumped >= 10)
			return 0;

		chunk_appendf(&trash, "%11llu %11llu %14llu %14llu| %16p ",
			      entry->alloc_calls, entry->free_calls,
			      entry->alloc_tot, entry->free_tot,
			      entry->caller);

		if (entry->caller)
			resolve_sym_name(&trash, NULL, entry->caller);
		else
			chunk_appendf(&trash, "[other]");

		if (((1UL << tmp_memstats[i].method) & MEMPROF_FREE_MASK) || !entry->alloc_calls) {
			chunk_appendf(&trash," %s(%lld)", memprof_methods[entry->method],
				(long long)(entry->alloc_tot - entry->free_tot) / (long long)(entry->alloc_calls + entry->free_calls));
		} else
			chunk_appendf(&trash," %s(%lld)", memprof_methods[entry->method],
				(long long)(entry->alloc_tot) / (long long)(entry->alloc_calls));

		if (entry->alloc_tot && entry->free_tot) {
			/* that's a realloc, show the total diff to help spot leaks */
			chunk_appendf(&trash," [delta=%lld]", (long long)(entry->alloc_tot - entry->free_tot));
		}

		if (entry->info) {
			/* that's a pool name */
			const struct pool_head *pool = entry->info;
			chunk_appendf(&trash," [pool=%s]", pool->name);
		}

		chunk_appendf(&trash, "\n");

		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		dumped++;
	}

	if (applet_putchk(appctx, &trash) == -1)
		return 0;

	tot_alloc_calls = tot_free_calls = tot_alloc_bytes = tot_free_bytes = 0;
	for (i = 0; i < max_lines; i++) {
		tot_alloc_calls += tmp_memstats[i].alloc_calls;
		tot_alloc_bytes += tmp_memstats[i].alloc_tot;
		if ((1UL << tmp_memstats[i].method) & MEMPROF_FREE_MASK) {
			tot_free_calls  += tmp_memstats[i].free_calls;
			tot_free_bytes  += tmp_memstats[i].free_tot;
		}
	}

	/* last step: summarize by DSO. We create one entry per new DSO in
	 * tmp_memstats, which is thus destroyed. The DSO's name is allocated
	 * and stored into tmp_stats.info. Must be freed at the end. We store
	 * <max> dso entries total. There are very few so we do that in a single
	 * pass and append it after the total.
	 */
	for (i = max = 0; i < max_lines; i++) {
		struct memprof_stats *entry = &tmp_memstats[i];

		if (!entry->alloc_calls && !entry->free_calls)
			continue;

		chunk_reset(name_buffer);
		if (!entry->caller)
			chunk_printf(name_buffer, "other");
		else
			resolve_dso_name(name_buffer, "", entry->caller);

		/* look it up among known names (0..max) */
		for (j = 0; j < max; j++) {
			if (tmp_memstats[j].info && strcmp(name_buffer->area, tmp_memstats[j].info) == 0)
				break;
		}

		if (j == max) {
			/* not found, create a new entry at <j>. We need to be
			 * careful as it could be the same as <entry> (i)!
			 */
			max++;

			if (j != i) // set max to keep min caller's address
				tmp_memstats[j].caller = (void*)-1;

			tmp_memstats[j].info = strdup(name_buffer->area);   // may fail, but checked when used
			tmp_memstats[j].alloc_calls = entry->alloc_calls;
			tmp_memstats[j].alloc_tot   = entry->alloc_tot;
			if ((1UL << entry->method) & MEMPROF_FREE_MASK) {
				tmp_memstats[j].free_calls  = entry->free_calls;
				tmp_memstats[j].free_tot    = entry->free_tot;
			} else {
				tmp_memstats[j].free_calls  = 0;
				tmp_memstats[j].free_tot    = 0;
			}
		} else {
			tmp_memstats[j].alloc_calls += entry->alloc_calls;
			tmp_memstats[j].alloc_tot += entry->alloc_tot;
			if ((1UL << entry->method) & MEMPROF_FREE_MASK) {
				tmp_memstats[j].free_calls  += entry->free_calls;
				tmp_memstats[j].free_tot  += entry->free_tot;
			}
		}

		if (entry->caller &&
		    tmp_memstats[j].caller > entry->caller)
			tmp_memstats[j].caller = entry->caller; // keep lowest address
	}

	/* now we have entries 0..max-1 that are filled with per-DSO stats. This is
	 * compact enough to fit next to the total line in one buffer, hence no
	 * state kept.
	 */
	chunk_appendf(&trash,
	              "-----------------------|-----------------------------| "
		      " - min caller - | -- by DSO below --\n");

	for (i = 0; i < max; i++) {
		struct memprof_stats *entry = &tmp_memstats[i];

		chunk_appendf(&trash, "%11llu %11llu %14llu %14llu| %16p DSO:%s;",
			      entry->alloc_calls, entry->free_calls,
			      entry->alloc_tot, entry->free_tot,
			      entry->caller == (void*)-1 ? 0 : entry->caller, entry->info ? (const char*)entry->info : "other");

		if (entry->alloc_tot != entry->free_tot)
			chunk_appendf(&trash, " delta_calls=%lld; delta_bytes=%lld",
				      (long long)(entry->alloc_calls - entry->free_calls),
				      (long long)(entry->alloc_tot - entry->free_tot));
		chunk_appendf(&trash, "\n");
	}

	chunk_appendf(&trash,
	              "-----------------------|-----------------------------|\n"
		      "%11llu %11llu %14llu %14llu| <- Total; Delta_calls=%lld; Delta_bytes=%lld\n",
		      tot_alloc_calls, tot_free_calls,
		      tot_alloc_bytes, tot_free_bytes,
		      tot_alloc_calls - tot_free_calls,
		      tot_alloc_bytes - tot_free_bytes);

	if (applet_putchk(appctx, &trash) == -1)
		return 0;

	ctx->linenum = 0; // reset first line to dump
	if ((ctx->dump_step & 4) == 0)
		ctx->dump_step++; // next step

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
	struct show_prof_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int arg;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	for (arg = 2; *args[arg]; arg++) {
		if (strcmp(args[arg], "all") == 0) {
			ctx->dump_step = 0; // will cycle through 0,1,2; default
		}
		else if (strcmp(args[arg], "status") == 0) {
			ctx->dump_step = 4; // will visit status only
		}
		else if (strcmp(args[arg], "tasks") == 0) {
			ctx->dump_step = 5; // will visit tasks only
		}
		else if (strcmp(args[arg], "memory") == 0) {
			ctx->dump_step = 6; // will visit memory only
		}
		else if (strcmp(args[arg], "byaddr") == 0) {
			ctx->by_what = 1; // sort output by address instead of usage
		}
		else if (strcmp(args[arg], "bytime") == 0) {
			ctx->by_what = 2; // sort output by total time instead of usage
		}
		else if (strcmp(args[arg], "aggr") == 0) {
			ctx->aggr = 1;    // aggregate output by callee
		}
		else if (isdigit((unsigned char)*args[arg])) {
			ctx->maxcnt = atoi(args[arg]); // number of entries to dump
		}
		else
			return cli_err(appctx, "Expects either 'all', 'status', 'tasks', 'memory', 'byaddr', 'bytime', 'aggr' or a max number of output lines.\n");
	}
	return 0;
}

/* This function scans all threads' run queues and collects statistics about
 * running tasks. It returns 0 if the output buffer is full and it needs to be
 * called again, otherwise non-zero.
 */
static int cli_io_handler_show_tasks(struct appctx *appctx)
{
	struct sched_activity tmp_activity[SCHED_ACT_HASH_BUCKETS] __attribute__((aligned(64)));
	struct buffer *name_buffer = get_trash_chunk();
	struct sched_activity *entry;
	const struct tasklet *tl;
	const struct task *t;
	uint64_t now_ns, lat;
	struct eb32_node *rqnode;
	uint64_t tot_calls;
	int thr, queue;
	int i, max;

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
	for (thr = 0; thr < global.nbthread; thr++) {
		/* task run queue */
		rqnode = eb32_first(&ha_thread_ctx[thr].rqueue_shared);
		while (rqnode) {
			t = eb32_entry(rqnode, struct task, rq);
			entry = sched_activity_entry(tmp_activity, t->process, NULL);
			if (t->wake_date) {
				lat = now_ns - t->wake_date;
				if ((int64_t)lat > 0)
					entry->lat_time += lat;
			}
			entry->calls++;
			rqnode = eb32_next(rqnode);
		}
	}
#endif
	/* 2. all threads's local run queues */
	for (thr = 0; thr < global.nbthread; thr++) {
		/* task run queue */
		rqnode = eb32_first(&ha_thread_ctx[thr].rqueue);
		while (rqnode) {
			t = eb32_entry(rqnode, struct task, rq);
			entry = sched_activity_entry(tmp_activity, t->process, NULL);
			if (t->wake_date) {
				lat = now_ns - t->wake_date;
				if ((int64_t)lat > 0)
					entry->lat_time += lat;
			}
			entry->calls++;
			rqnode = eb32_next(rqnode);
		}

		/* shared tasklet list */
		list_for_each_entry(tl, mt_list_to_list(&ha_thread_ctx[thr].shared_tasklet_list), list) {
			t = (const struct task *)tl;
			entry = sched_activity_entry(tmp_activity, t->process, NULL);
			if (!TASK_IS_TASKLET(t) && t->wake_date) {
				lat = now_ns - t->wake_date;
				if ((int64_t)lat > 0)
					entry->lat_time += lat;
			}
			entry->calls++;
		}

		/* classful tasklets */
		for (queue = 0; queue < TL_CLASSES; queue++) {
			list_for_each_entry(tl, &ha_thread_ctx[thr].tasklets[queue], list) {
				t = (const struct task *)tl;
				entry = sched_activity_entry(tmp_activity, t->process, NULL);
				if (!TASK_IS_TASKLET(t) && t->wake_date) {
					lat = now_ns - t->wake_date;
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
	for (i = 0; i < SCHED_ACT_HASH_BUCKETS; i++)
		tot_calls += tmp_activity[i].calls;

	qsort(tmp_activity, SCHED_ACT_HASH_BUCKETS, sizeof(tmp_activity[0]), cmp_sched_activity_calls);

	chunk_appendf(&trash, "Running tasks: %d (%d threads)\n"
		      "  function                     places     %%    lat_tot   lat_avg\n",
		      (int)tot_calls, global.nbthread);

	for (i = 0; i < SCHED_ACT_HASH_BUCKETS && tmp_activity[i].calls; i++) {
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

	if (applet_putchk(appctx, &trash) == -1) {
		/* failed, try again */
		return 0;
	}
	return 1;
}

/* This function dumps some activity counters used by developers and support to
 * rule out some hypothesis during bug reports. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero. It dumps
 * everything at once in the buffer and is not designed to do it in multiple
 * passes.
 */
static int cli_io_handler_show_activity(struct appctx *appctx)
{
	struct show_activity_ctx *actctx = appctx->svcctx;
	int tgt = actctx->thr; // target thread, -1 for all, 0 for total only
	uint up_sec, up_usec;
	int base_line;
	ullong up;

	/* this macro is used below to dump values. The thread number is "thr",
	 * and runs from 0 to nbt-1 when values are printed using the formula.
	 * We normally try to dmup integral lines in order to keep counters
	 * consistent. If we fail once on a line, we'll detect it next time
	 * because we'll have committed actctx->col=1 thanks to the header
	 * always being dumped individually. We'll be called again thanks to
	 * the header being present, leaving some data in the buffer. In this
	 * case once we restart we'll proceed one column at a time to make sure
	 * we don't overflow the buffer again.
	 */
#undef SHOW_VAL
#define SHOW_VAL(header, x, formula)					\
	do {								\
		unsigned int _v[MAX_THREADS];				\
		unsigned int _tot;					\
		const int _nbt = global.nbthread;			\
		int restarted = actctx->col > 0;			\
		int thr;						\
		_tot = thr = 0;						\
		do {							\
			_tot += _v[thr] = (x);				\
		} while (++thr < _nbt);					\
		for (thr = actctx->col - 2; thr <= _nbt; thr++) {	\
			if (thr == -2) {				\
				/* line header */			\
				chunk_appendf(&trash, "%s", header);	\
			}						\
			else if (thr == -1) {				\
				/* aggregate value only for multi-thread: all & 0 */ \
				if (_nbt > 1 && tgt <= 0)		\
					chunk_appendf(&trash, " %u%s",	\
						      (formula),	\
						      (tgt < 0) ?	\
						      " [" : "");	\
			}						\
			else if (thr < _nbt) {				\
				/* individual value only for all or exact value */ \
				if (tgt == -1 || tgt == thr+1)		\
					chunk_appendf(&trash, " %u",	\
						      _v[thr]);		\
			}						\
			else /* thr == _nbt */ {			\
				chunk_appendf(&trash, "%s\n",		\
					      (_nbt > 1 && tgt < 0) ?	\
					      " ]" : "");		\
			}						\
			if (thr == -2 || restarted) {			\
				/* failed once, emit one column at a time */\
				if (applet_putchk(appctx, &trash) == -1) \
					break; /* main loop handles it */ \
				chunk_reset(&trash);			\
				actctx->col = thr + 3;			\
			}						\
		}							\
		if (applet_putchk(appctx, &trash) == -1)		\
			break; /* main loop will handle it */		\
		/* OK dump done for this line */			\
		chunk_reset(&trash);					\
		if (thr > _nbt)						\
			actctx->col = 0;				\
	} while (0)

	/* retrieve uptime */
	up = now_ns - start_time_ns;
	up_sec = ns_to_sec(up);
	up_usec = (up / 1000U) % 1000000U;

	/* iterate over all dump lines. It happily skips over holes so it's
	 * not a problem not to have an exact match, we just need to have
	 * stable and consistent lines during a dump.
	 */
	base_line = __LINE__;
	do {
		chunk_reset(&trash);

		switch (actctx->line + base_line) {
		case __LINE__: chunk_appendf(&trash, "thread_id: %u (%u..%u)\n", tid + 1, 1, global.nbthread); break;
		case __LINE__: chunk_appendf(&trash, "date_now: %lu.%06lu\n", (ulong)date.tv_sec, (ulong)date.tv_usec); break;
		case __LINE__: chunk_appendf(&trash, "uptime_now: %u.%06u\n", up_sec, up_usec); break;
		case __LINE__: SHOW_VAL("ctxsw:",        activity[thr].ctxsw, _tot); break;
		case __LINE__: SHOW_VAL("tasksw:",       activity[thr].tasksw, _tot); break;
		case __LINE__: SHOW_VAL("empty_rq:",     activity[thr].empty_rq, _tot); break;
		case __LINE__: SHOW_VAL("long_rq:",      activity[thr].long_rq, _tot); break;
		case __LINE__: SHOW_VAL("curr_rq:",      _HA_ATOMIC_LOAD(&ha_thread_ctx[thr].rq_total), _tot); break;
		case __LINE__: SHOW_VAL("loops:",        activity[thr].loops, _tot); break;
		case __LINE__: SHOW_VAL("wake_tasks:",   activity[thr].wake_tasks, _tot); break;
		case __LINE__: SHOW_VAL("wake_signal:",  activity[thr].wake_signal, _tot); break;
		case __LINE__: SHOW_VAL("poll_io:",      activity[thr].poll_io, _tot); break;
		case __LINE__: SHOW_VAL("poll_exp:",     activity[thr].poll_exp, _tot); break;
		case __LINE__: SHOW_VAL("poll_drop_fd:", activity[thr].poll_drop_fd, _tot); break;
		case __LINE__: SHOW_VAL("poll_skip_fd:", activity[thr].poll_skip_fd, _tot); break;
		case __LINE__: SHOW_VAL("conn_dead:",    activity[thr].conn_dead, _tot); break;
		case __LINE__: SHOW_VAL("stream_calls:", activity[thr].stream_calls, _tot); break;
		case __LINE__: SHOW_VAL("pool_fail:",    activity[thr].pool_fail, _tot); break;
		case __LINE__: SHOW_VAL("buf_wait:",     activity[thr].buf_wait, _tot); break;
		case __LINE__: SHOW_VAL("cpust_ms_tot:", activity[thr].cpust_total / 2, _tot); break;
		case __LINE__: SHOW_VAL("cpust_ms_1s:",  read_freq_ctr(&activity[thr].cpust_1s) / 2, _tot); break;
		case __LINE__: SHOW_VAL("cpust_ms_15s:", read_freq_ctr_period(&activity[thr].cpust_15s, 15000) / 2, _tot); break;
		case __LINE__: SHOW_VAL("avg_cpu_pct:",  (100 - ha_thread_ctx[thr].idle_pct), (_tot + _nbt/2) / _nbt); break;
		case __LINE__: SHOW_VAL("avg_loop_us:",  swrate_avg(activity[thr].avg_loop_us, TIME_STATS_SAMPLES), (_tot + _nbt/2) / _nbt); break;
		case __LINE__: SHOW_VAL("accepted:",     activity[thr].accepted, _tot); break;
		case __LINE__: SHOW_VAL("accq_pushed:",  activity[thr].accq_pushed, _tot); break;
		case __LINE__: SHOW_VAL("accq_full:",    activity[thr].accq_full, _tot); break;
#ifdef USE_THREAD
		case __LINE__: SHOW_VAL("accq_ring:",    accept_queue_ring_len(&accept_queue_rings[thr]), _tot); break;
		case __LINE__: SHOW_VAL("fd_takeover:",  activity[thr].fd_takeover, _tot); break;
		case __LINE__: SHOW_VAL("check_adopted:",activity[thr].check_adopted, _tot); break;
#endif
		case __LINE__: SHOW_VAL("check_started:",activity[thr].check_started, _tot); break;
		case __LINE__: SHOW_VAL("check_active:", _HA_ATOMIC_LOAD(&ha_thread_ctx[thr].active_checks), _tot); break;
		case __LINE__: SHOW_VAL("check_running:",_HA_ATOMIC_LOAD(&ha_thread_ctx[thr].running_checks), _tot); break;

#if defined(DEBUG_DEV)
			/* keep these ones at the end */
		case __LINE__: SHOW_VAL("ctr0:",         activity[thr].ctr0, _tot); break;
		case __LINE__: SHOW_VAL("ctr1:",         activity[thr].ctr1, _tot); break;
		case __LINE__: SHOW_VAL("ctr2:",         activity[thr].ctr2, _tot); break;
#endif
		}
#undef SHOW_VAL

		/* try to dump what was possibly not dumped yet */

		if (applet_putchk(appctx, &trash) == -1) {
			/* buffer full, retry later */
			return 0;
		}
		/* line was dumped, let's commit it */
		actctx->line++;
	} while (actctx->line + base_line < __LINE__);

	/* dump complete */
	return 1;
}

/* parse a "show activity" CLI request. Returns 0 if it needs to continue, 1 if it
 * wants to stop here. It sets a show_activity_ctx context where, if a specific
 * thread is requested, it puts the thread number into ->thr otherwise sets it to
 * -1.
 */
static int cli_parse_show_activity(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_activity_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	ctx->thr = -1; // show all by default
	if (*args[2])
		ctx->thr = atoi(args[2]);

	if (ctx->thr < -1 || ctx->thr > global.nbthread)
		return cli_err(appctx, "Thread ID number must be between -1 and nbthread\n");

	return 0;
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
	{ { "show", "activity", NULL },  "show activity [-1|0|thread_num]         : show per-thread activity stats (for support/developers)", cli_parse_show_activity, cli_io_handler_show_activity, NULL },
	{ { "show", "profiling", NULL }, "show profiling [<what>|<#lines>|<opts>]*: show profiling state (all,status,tasks,memory)",   cli_parse_show_profiling, cli_io_handler_show_profiling, NULL },
	{ { "show", "tasks", NULL },     "show tasks                              : show running tasks",                               NULL, cli_io_handler_show_tasks,     NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
