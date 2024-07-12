/*
 * Handlers for process resources limits.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later.
 *
 */

#include <haproxy/global.h>
#include <haproxy/limits.h>
#include <haproxy/proxy.h>


unsigned int rlim_fd_cur_at_boot = 0;
unsigned int rlim_fd_max_at_boot = 0;

/* Sets the RLIMIT_NOFILE setting to <new_limit> and returns the previous one
 * in <old_limit> if the pointer is not NULL, even if set_rlimit() fails. The
 * two pointers may point to the same variable as the copy happens after
 * setting the new value. The value is only changed if at least one of the new
 * limits is strictly higher than the current one, otherwise returns 0 without
 * changing anything. The getrlimit() or setrlimit() syscall return value is
 * returned and errno is preserved.
 */
int raise_rlim_nofile(struct rlimit *old_limit, struct rlimit *new_limit)
{
	struct rlimit limit = { };
	int ret = 0;

	ret = getrlimit(RLIMIT_NOFILE, &limit);

	if (ret == 0 &&
	    (limit.rlim_max < new_limit->rlim_max ||
	     limit.rlim_cur < new_limit->rlim_cur)) {
		ret = setrlimit(RLIMIT_NOFILE, new_limit);
	}

	if (old_limit)
		*old_limit = limit;

	return ret;
}

/* Encapsulates the check of all supported for now process internal limits,
 * which could be provided via config or/and cmdline. Returns 1, if even only
 * one supported limit is set, otherwise 0.
 */
static int is_any_limit_configured()
{
       int ret = 0;

       if (global.maxconn || global.rlimit_nofile || global.rlimit_memmax ||
               global.fd_hard_limit)
               ret = 1;

       return ret;
}

/* considers splicing proxies' maxconn, computes the ideal global.maxpipes
 * setting, and returns it. It may return -1 meaning "unlimited" if some
 * unlimited proxies have been found and the global.maxconn value is not yet
 * set. It may also return a value greater than maxconn if it's not yet set.
 * Note that a value of zero means there is no need for pipes. -1 is never
 * returned if global.maxconn is valid.
 */
int compute_ideal_maxpipes()
{
	struct proxy *cur;
	int nbfe = 0, nbbe = 0;
	int unlimited = 0;
	int pipes;
	int max;

	for (cur = proxies_list; cur; cur = cur->next) {
		if (cur->options2 & (PR_O2_SPLIC_ANY)) {
			if (cur->cap & PR_CAP_FE) {
				max = cur->maxconn;
				nbfe += max;
				if (!max) {
					unlimited = 1;
					break;
				}
			}
			if (cur->cap & PR_CAP_BE) {
				max = cur->fullconn ? cur->fullconn : global.maxconn;
				nbbe += max;
				if (!max) {
					unlimited = 1;
					break;
				}
			}
		}
	}

	pipes = MAX(nbfe, nbbe);
	if (global.maxconn) {
		if (pipes > global.maxconn || unlimited)
			pipes = global.maxconn;
	} else if (unlimited) {
		pipes = -1;
	}

	return pipes >= 4 ? pipes / 4 : pipes;
}

/* considers global.maxsocks, global.maxpipes, async engines, SSL frontends and
 * rlimits and computes an ideal maxconn. It's meant to be called only when
 * maxsock contains the sum of listening FDs, before it is updated based on
 * maxconn and pipes. If there are not enough FDs left, DEFAULT_MAXCONN (by
 * default 100) is returned as it is expected that it will even run on tight
 * environments, and will maintain compatibility with previous packages that
 * used to rely on this value as the default one. The system will emit a
 * warning indicating how many FDs are missing anyway if needed.
 */
int compute_ideal_maxconn()
{
	int ssl_sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;
	int engine_fds = global.ssl_used_async_engines * ssl_sides;
	int pipes = compute_ideal_maxpipes();
	int remain = MAX(rlim_fd_cur_at_boot, rlim_fd_max_at_boot);
	int maxconn;

	/* we have to take into account these elements :
	 *   - number of engine_fds, which inflates the number of FD needed per
	 *     connection by this number.
	 *   - number of pipes per connection on average : for the unlimited
	 *     case, this is 0.5 pipe FDs per connection, otherwise it's a
	 *     fixed value of 2*pipes.
	 *   - two FDs per connection
	 */

	/* on some modern distros for archs like amd64 fs.nr_open (kernel max)
	 * could be in order of 1 billion. Systemd since the version 256~rc3-3
	 * bumped fs.nr_open as the hard RLIMIT_NOFILE (rlim_fd_max_at_boot).
	 * If we are started without any limits, we risk to finish with computed
	 * maxconn = ~500000000, maxsock = ~2*maxconn. So, fdtab will be
	 * extremely large and watchdog will kill the process, when it will try
	 * to loop over the fdtab (see fd_reregister_all). Please note, that
	 * fd_hard_limit is taken in account implicitly via 'ideal_maxconn'
	 * value in all global.maxconn adjustements, when global.rlimit_memmax
	 * is set:
	 *
	 *   MIN(global.maxconn, capped by global.rlimit_memmax, ideal_maxconn);
	 *
	 * It also caps global.rlimit_nofile, if it couldn't be set as rlim_cur
	 * and as rlim_max. So, fd_hard_limitit is a good parameter to serve as
	 * a safeguard, when no haproxy-specific limits are set, i.e.
	 * rlimit_memmax, maxconn, rlimit_nofile. But it must be kept as a zero,
	 * if only one of these ha-specific limits is presented in config or in
	 * the cmdline.
	 */
	if (!is_any_limit_configured())
		global.fd_hard_limit = DEFAULT_MAXFD;

	if (remain > global.fd_hard_limit)
		remain = global.fd_hard_limit;

	/* subtract listeners and checks */
	remain -= global.maxsock;

	/* one epoll_fd/kqueue_fd per thread */
	remain -= global.nbthread;

	/* one wake-up pipe (2 fd) per thread */
	remain -= 2 * global.nbthread;

	/* Fixed pipes values : we only subtract them if they're not larger
	 * than the remaining FDs because pipes are optional.
	 */
	if (pipes >= 0 && pipes * 2 < remain)
		remain -= pipes * 2;

	if (pipes < 0) {
		/* maxsock = maxconn * 2 + maxconn/4 * 2 + maxconn * engine_fds.
		 *         = maxconn * (2 + 0.5 + engine_fds)
		 *         = maxconn * (4 + 1 + 2*engine_fds) / 2
		 */
		maxconn = 2 * remain / (5 + 2 * engine_fds);
	} else {
		/* maxsock = maxconn * 2 + maxconn * engine_fds.
		 *         = maxconn * (2 + engine_fds)
		 */
		maxconn = remain / (2 + engine_fds);
	}

	return MAX(maxconn, DEFAULT_MAXCONN);
}

/* computes the estimated maxsock value for the given maxconn based on the
 * possibly set global.maxpipes and existing partial global.maxsock. It may
 * temporarily change global.maxconn for the time needed to propagate the
 * computations, and will reset it.
 */
int compute_ideal_maxsock(int maxconn)
{
	int maxpipes = global.maxpipes;
	int maxsock  = global.maxsock;


	if (!maxpipes) {
		int old_maxconn = global.maxconn;

		global.maxconn = maxconn;
		maxpipes = compute_ideal_maxpipes();
		global.maxconn = old_maxconn;
	}

	maxsock += maxconn * 2;         /* each connection needs two sockets */
	maxsock += maxpipes * 2;        /* each pipe needs two FDs */
	maxsock += global.nbthread;     /* one epoll_fd/kqueue_fd per thread */
	maxsock += 2 * global.nbthread; /* one wake-up pipe (2 fd) per thread */

	/* compute fd used by async engines */
	if (global.ssl_used_async_engines) {
		int sides = !!global.ssl_used_frontend + !!global.ssl_used_backend;

		maxsock += maxconn * sides * global.ssl_used_async_engines;
	}
	return maxsock;
}

/* Tests if it is possible to set the current process's RLIMIT_NOFILE to
 * <maxsock>, then sets it back to the previous value. Returns non-zero if the
 * value is accepted, non-zero otherwise. This is used to determine if an
 * automatic limit may be applied or not. When it is not, the caller knows that
 * the highest we can do is the rlim_max at boot. In case of error, we return
 * that the setting is possible, so that we defer the error processing to the
 * final stage in charge of enforcing this.
 */
int check_if_maxsock_permitted(int maxsock)
{
	struct rlimit orig_limit, test_limit;
	int ret;

	if (global.fd_hard_limit && maxsock > global.fd_hard_limit)
		return 0;

	if (getrlimit(RLIMIT_NOFILE, &orig_limit) != 0)
		return 1;

	/* don't go further if we can't even set to what we have */
	if (raise_rlim_nofile(NULL, &orig_limit) != 0)
		return 1;

	test_limit.rlim_max = MAX(maxsock, orig_limit.rlim_max);
	test_limit.rlim_cur = test_limit.rlim_max;
	ret = raise_rlim_nofile(NULL, &test_limit);

	if (raise_rlim_nofile(NULL, &orig_limit) != 0)
		return 1;

	return ret == 0;
}
