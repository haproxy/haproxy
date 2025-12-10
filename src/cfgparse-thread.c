#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>

#include <signal.h>
#include <unistd.h>
#ifdef _POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#endif

#ifdef USE_THREAD
#  include <pthread.h>
#endif

#ifdef USE_CPU_AFFINITY
#  include <sched.h>
#  if defined(__FreeBSD__) || defined(__DragonFly__)
#    include <pthread_np.h>
#  endif
#  ifdef __APPLE__
#    include <mach/mach_types.h>
#    include <mach/thread_act.h>
#    include <mach/thread_policy.h>
#  endif
#  include <haproxy/cpuset.h>
#  include <haproxy/cpu_topo.h>
#endif

#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>

/* Parse a string representing a thread set in one of the following forms:
 *
 * - { "all" | "odd" | "even" | <abs_num> [ "-" <abs_num> ] }[,...]
 *   => these are (lists of) absolute thread numbers
 *
 * - <tgnum> "/" { "all" | "odd" | "even" | <rel_num> [ "-" <rel_num> ][,...]
 *   => these are (lists of) per-group relative thread numbers. All numbers
 *      must be lower than or equal to LONGBITS. When multiple list elements
 *      are provided, each of them must contain the thread group number.
 *
 * Minimum value for a thread or group number is always 1. Maximum value for an
 * absolute thread number is MAX_THREADS, maximum value for a relative thread
 * number is MAX_THREADS_PER_GROUP, an maximum value for a thread group is
 * MAX_TGROUPS. "all", "even" and "odd" will be bound by MAX_THREADS and/or
 * MAX_THREADS_PER_GROUP in any case. In ranges, a missing digit before "-"
 * is implicitly 1, and a missing digit after "-" is implicitly the highest of
 * its class. As such "-" is equivalent to "all", allowing to build strings
 * such as "${MIN}-${MAX}" where both MIN and MAX are optional.
 *
 * It is not valid to mix absolute and relative numbers. As such:
 * - all               valid (all absolute threads)
 * - 12-19,24-31       valid (abs threads 12 to 19 and 24 to 31)
 * - 1/all             valid (all 32 or 64 threads of group 1)
 * - 1/1-4,1/8-10,2/1  valid
 * - 1/1-4,8-10        invalid (mixes relatve "1/1-4" with absolute "8-10")
 * - 1-4,8-10,2/1      invalid (mixes absolute "1-4,8-10" with relative "2/1")
 * - 1/odd-4           invalid (mixes range with boundary)
 *
 * The target thread set is *completed* with supported threads, which means
 * that it's the caller's responsibility for pre-initializing it. If the target
 * thread set is NULL, it's not updated and the function only verifies that the
 * input parses.
 *
 * On success, it returns 0. otherwise it returns non-zero with an error
 * message in <err>.
 */
int parse_thread_set(const char *arg, struct thread_set *ts, char **err)
{
	const char *set;
	const char *sep;
	int v, min, max, tg;
	int is_rel;

	/* search for the first delimiter (',', '-' or '/') to decide whether
	 * we're facing an absolute or relative form. The relative form always
	 * starts with a number followed by a slash.
	 */
	for (sep = arg; isdigit((uchar)*sep); sep++)
		;

	is_rel = (/*sep > arg &&*/ *sep == '/'); /* relative form */

	/* from there we have to cut the thread spec around commas */

	set = arg;
	tg = 0;
	while (*set) {
		/* note: we can't use strtol() here because "-3" would parse as
		 * (-3) while we want to stop before the "-", so we find the
		 * separator ourselves and rely on atoi() whose value we may
		 * ignore depending where the separator is.
		 */
		for (sep = set; isdigit((uchar)*sep); sep++)
			;

		if (sep != set && *sep && *sep != '/' && *sep != '-' && *sep != ',') {
			memprintf(err, "invalid character '%c' in thread set specification: '%s'.", *sep, set);
			return -1;
		}

		v = (sep != set) ? atoi(set) : 0;

		/* Now we know that the string is made of an optional series of digits
		 * optionally followed by one of the delimiters above, or that it
		 * starts with a different character.
		 */

		/* first, let's search for the thread group (digits before '/') */

		if (tg || !is_rel) {
			/* thread group already specified or not expected if absolute spec */
			if (*sep == '/') {
				if (tg)
					memprintf(err, "redundant thread group specification '%s' for group %d", set, tg);
				else
					memprintf(err, "group-relative thread specification '%s' is not permitted after a absolute thread range.", set);
				return -1;
			}
		} else {
			/* this is a group-relative spec, first field is the group number */
			if (sep == set && *sep == '/') {
				memprintf(err, "thread group number expected before '%s'.", set);
				return -1;
			}

			if (*sep != '/') {
				memprintf(err, "absolute thread specification '%s' is not permitted after a group-relative thread range.", set);
				return -1;
			}

			if (v < 1 || v > MAX_TGROUPS) {
				memprintf(err, "invalid thread group number '%d', permitted range is 1..%d in '%s'.", v, MAX_TGROUPS, set);
				return -1;
			}

			tg = v;

			/* skip group number and go on with set,sep,v as if
			 * there was no group number.
			 */
			set = sep + 1;
			continue;
		}

		/* Now 'set' starts at the min thread number, whose value is in v if any,
		 * and preset the max to it, unless the range is filled at once via "all"
		 * (stored as 1:0), "odd" (stored as) 1:-1, or "even" (stored as 1:-2).
		 * 'sep' points to the next non-digit which may be set itself e.g. for
		 * "all" etc or "-xx".
		 */

		if (!*set) {
			/* empty set sets no restriction */
			min = 1;
			max = is_rel ? MAX_THREADS_PER_GROUP : MAX_THREADS;
		}
		else {
			if (sep != set && *sep && *sep != '-' && *sep != ',') {
				// Only delimiters are permitted around digits.
				memprintf(err, "invalid character '%c' in thread set specification: '%s'.", *sep, set);
				return -1;
			}

			/* for non-digits, find next delim */
			for (; *sep && *sep != '-' && *sep != ','; sep++)
				;

			min = max = 1;
			if (sep != set) {
				/* non-empty first thread */
				if (isteq(ist2(set, sep-set), ist("all")))
					max = 0;
				else if (isteq(ist2(set, sep-set), ist("odd")))
					max = -1;
				else if (isteq(ist2(set, sep-set), ist("even")))
					max = -2;
				else if (v)
					min = max = v;
				else
					max = min = 0; // throw an error below
			}

			if (min < 1 || min > MAX_THREADS || (is_rel && min > MAX_THREADS_PER_GROUP)) {
				memprintf(err, "invalid first thread number '%s', permitted range is 1..%d, or 'all', 'odd', 'even'.",
					  set, is_rel ? MAX_THREADS_PER_GROUP : MAX_THREADS);
				return -1;
			}

			/* is this a range ? */
			if (*sep == '-') {
				if (min != max) {
					memprintf(err, "extraneous range after 'all', 'odd' or 'even': '%s'.", set);
					return -1;
				}

				/* this is a seemingly valid range, there may be another number  */
				for (set = ++sep; isdigit((uchar)*sep); sep++)
					;
				v = atoi(set);

				if (sep == set) { // no digit: to the max
					max = is_rel ? MAX_THREADS_PER_GROUP : MAX_THREADS;
					if (*sep && *sep != ',')
						max = 0; // throw an error below
				} else
					max = v;

				if (max < 1 || max > MAX_THREADS || (is_rel && max > MAX_THREADS_PER_GROUP)) {
					memprintf(err, "invalid last thread number '%s', permitted range is 1..%d.",
						  set, is_rel ? MAX_THREADS_PER_GROUP : MAX_THREADS);
					return -1;
				}
			}

			/* here sep points to the first non-digit after the thread spec,
			 * must be a valid delimiter.
			 */
			if (*sep && *sep != ',') {
				memprintf(err, "invalid character '%c' after thread set specification: '%s'.", *sep, set);
				return -1;
			}
		}

		/* store values */
		if (ts) {
			if (is_rel) {
				/* group-relative thread numbers */
				ts->grps |= 1UL << (tg - 1);

				if (max >= min) {
					for (v = min; v <= max; v++)
						ts->rel[tg - 1] |= 1UL << (v - 1);
				} else {
					memset(&ts->rel[tg - 1],
					       (max == 0) ? 0xff /* all */ : (max == -1) ? 0x55 /* odd */: 0xaa /* even */,
					       sizeof(ts->rel[tg - 1]));
				}
			} else {
				/* absolute thread numbers */
				if (max >= min) {
					for (v = min; v <= max; v++)
						ts->abs[(v - 1) / LONGBITS] |= 1UL << ((v - 1) % LONGBITS);
				} else {
					memset(&ts->abs,
					       (max == 0) ? 0xff /* all */ : (max == -1) ? 0x55 /* odd */: 0xaa /* even */,
					       sizeof(ts->abs));
				}
			}
		}

		set = *sep ? sep + 1 : sep;
		tg = 0;
	}
	return 0;
}

/* Parse the "nbthread" global directive, which takes an integer argument that
 * contains the desired number of threads.
 */
static int cfg_parse_nbthread(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	long nbthread;
	char *errptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (non_global_section_parsed == 1) {
		memprintf(err, "'%s' not allowed if a non-global section was previously defined. This parameter must be declared in the first global section", args[0]);
		return -1;
	}

	nbthread = strtol(args[1], &errptr, 10);
	if (!*args[1] || *errptr) {
		memprintf(err, "'%s' passed a missing or unparsable integer value in '%s'", args[0], args[1]);
		return -1;
	}

#ifndef USE_THREAD
	if (nbthread != 1) {
		memprintf(err, "'%s' specified with a value other than 1 while HAProxy is not compiled with threads support. Please check build options for USE_THREAD", args[0]);
		return -1;
	}
#else
	if (nbthread < 1 || nbthread > MAX_THREADS) {
		memprintf(err, "'%s' value must be between 1 and %d (was %ld)", args[0], MAX_THREADS, nbthread);
		return -1;
	}
#endif

	HA_DIAG_WARNING_COND(global.nbthread,
	                     "parsing [%s:%d] : '%s' is already defined and will be overridden.\n",
	                     file, line, args[0]);

	global.nbthread = nbthread;
	return 0;
}

/* Parse the "thread-hard-limit" global directive, which takes an integer
 * argument that contains the desired maximum number of threads that will
 * not be crossed.
 */
static int cfg_parse_thread_hard_limit(char **args, int section_type, struct proxy *curpx,
                              const struct proxy *defpx, const char *file, int line,
                              char **err)
{
	long nbthread;
	char *errptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	nbthread = strtol(args[1], &errptr, 10);
	if (!*args[1] || *errptr) {
		memprintf(err, "'%s' passed a missing or unparsable integer value in '%s'", args[0], args[1]);
		return -1;
	}

	if (nbthread < 1 || nbthread > MAX_THREADS) {
		memprintf(err, "'%s' value must be at least 1 (was %ld)", args[0], nbthread);
		return -1;
	}

	global.thread_limit = nbthread;
	return 0;
}

/* Parse the "thread-group" global directive, which takes an integer argument
 * that designates a thread group, and a list of threads to put into that group.
 */
static int cfg_parse_thread_group(char **args, int section_type, struct proxy *curpx,
                                  const struct proxy *defpx, const char *file, int line,
                                  char **err)
{
	char *errptr;
	long tnum, tend, tgroup;
	int arg, tot;

	if (non_global_section_parsed == 1) {
		memprintf(err, "'%s' not allowed if a non-global section was previously defined. This parameter must be declared in the first global section", args[0]);
		return -1;
	}

	tgroup = strtol(args[1], &errptr, 10);
	if (!*args[1] || *errptr) {
		memprintf(err, "'%s' passed a missing or unparsable integer value in '%s'", args[0], args[1]);
		return -1;
	}

	if (tgroup < 1 || tgroup > MAX_TGROUPS) {
		memprintf(err, "'%s' thread-group number must be between 1 and %d (was %ld)", args[0], MAX_TGROUPS, tgroup);
		return -1;
	}

	/* look for a preliminary definition of any thread pointing to this
	 * group, and remove them.
	 */
	if (ha_tgroup_info[tgroup-1].count) {
		ha_warning("parsing [%s:%d] : '%s %ld' was already defined and will be overridden.\n",
		           file, line, args[0], tgroup);

		for (tnum = ha_tgroup_info[tgroup-1].base;
		     tnum < ha_tgroup_info[tgroup-1].base + ha_tgroup_info[tgroup-1].count;
		     tnum++) {
			if (ha_thread_info[tnum-1].tg == &ha_tgroup_info[tgroup-1]) {
				ha_thread_info[tnum-1].tg = NULL;
				ha_thread_info[tnum-1].tgid = 0;
				ha_thread_info[tnum-1].tg_ctx = NULL;
			}
		}
		ha_tgroup_info[tgroup-1].count = ha_tgroup_info[tgroup-1].base = 0;
	}

	tot = 0;
	for (arg = 2; args[arg] && *args[arg]; arg++) {
		tend = tnum = strtol(args[arg], &errptr, 10);

		if (*errptr == '-')
			tend = strtol(errptr + 1, &errptr, 10);

		if (*errptr || tnum < 1 || tend < 1 || tnum > MAX_THREADS || tend > MAX_THREADS) {
			memprintf(err, "'%s %ld' passed an unparsable or invalid thread number '%s' (valid range is 1 to %d)", args[0], tgroup, args[arg], MAX_THREADS);
			return -1;
		}

		for(; tnum <= tend; tnum++) {
			if (ha_thread_info[tnum-1].tg == &ha_tgroup_info[tgroup-1]) {
				ha_warning("parsing [%s:%d] : '%s %ld': thread %ld assigned more than once on the same line.\n",
				           file, line, args[0], tgroup, tnum);
			} else if (ha_thread_info[tnum-1].tg) {
				ha_warning("parsing [%s:%d] : '%s %ld': thread %ld was previously assigned to thread group %ld and will be overridden.\n",
				           file, line, args[0], tgroup, tnum,
				           (long)(ha_thread_info[tnum-1].tg - &ha_tgroup_info[0] + 1));
			}

			if (!ha_tgroup_info[tgroup-1].count) {
				ha_tgroup_info[tgroup-1].base = tnum-1;
				ha_tgroup_info[tgroup-1].count = 1;
			}
			else if (tnum >= ha_tgroup_info[tgroup-1].base + ha_tgroup_info[tgroup-1].count) {
				ha_tgroup_info[tgroup-1].count = tnum - ha_tgroup_info[tgroup-1].base;
			}
			else if (tnum < ha_tgroup_info[tgroup-1].base) {
				ha_tgroup_info[tgroup-1].count += ha_tgroup_info[tgroup-1].base - tnum-1;
				ha_tgroup_info[tgroup-1].base = tnum - 1;
			}

			ha_thread_info[tnum-1].tgid = tgroup;
			ha_thread_info[tnum-1].tg = &ha_tgroup_info[tgroup-1];
			ha_thread_info[tnum-1].tg_ctx = &ha_tgroup_ctx[tgroup-1];
			tot++;
		}
	}

	if (ha_tgroup_info[tgroup-1].count > tot) {
		memprintf(err, "'%s %ld' assigned sparse threads, only contiguous supported", args[0], tgroup);
		return -1;
	}

	if (ha_tgroup_info[tgroup-1].count > MAX_THREADS_PER_GROUP) {
		memprintf(err, "'%s %ld' assigned too many threads (%d, max=%d)", args[0], tgroup, tot, MAX_THREADS_PER_GROUP);
		return -1;
	}

	return 0;
}

/* Parse the "thread-groups" global directive, which takes an integer argument
 * that contains the desired number of thread groups.
 */
static int cfg_parse_thread_groups(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	long nbtgroups;
	char *errptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (non_global_section_parsed == 1) {
		memprintf(err, "'%s' not allowed if a non-global section was previously defined. This parameter must be declared in the first global section", args[0]);
		return -1;
	}

	nbtgroups = strtol(args[1], &errptr, 10);
	if (!*args[1] || *errptr) {
		memprintf(err, "'%s' passed a missing or unparsable integer value in '%s'", args[0], args[1]);
		return -1;
	}

#ifndef USE_THREAD
	if (nbtgroups != 1) {
		memprintf(err, "'%s' specified with a value other than 1 while HAProxy is not compiled with threads support. Please check build options for USE_THREAD", args[0]);
		return -1;
	}
#else
	if (nbtgroups < 1 || nbtgroups > MAX_TGROUPS) {
		memprintf(err, "'%s' value must be between 1 and %d (was %ld)", args[0], MAX_TGROUPS, nbtgroups);
		return -1;
	}
#endif

	HA_DIAG_WARNING_COND(global.nbtgroups,
	                     "parsing [%s:%d] : '%s' is already defined and will be overridden.\n",
	                     file, line, args[0]);

	global.nbtgroups = nbtgroups;
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "thread-hard-limit", cfg_parse_thread_hard_limit, 0 },
	{ CFG_GLOBAL, "nbthread",       cfg_parse_nbthread, 0 },
	{ CFG_GLOBAL, "thread-group",   cfg_parse_thread_group, 0 },
	{ CFG_GLOBAL, "thread-groups",  cfg_parse_thread_groups, 0 },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
