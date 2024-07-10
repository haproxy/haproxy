/*
 * Handlers for process resources limits.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later.
 *
 */

#include <haproxy/compat.h>
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
