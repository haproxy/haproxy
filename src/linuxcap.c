/*
 * Minimal handling of Linux kernel capabilities
 *
 * Copyright 2000-2023 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

/* Depending on distros, some have capset(), others use the more complicated
 * libcap. Let's stick to what we need and the kernel documents (capset).
 * Note that prctl is needed here.
 */
#include <sys/prctl.h>
#include <errno.h>
#include <unistd.h>
#include <syscall.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/linuxcap.h>
#include <haproxy/tools.h>

struct __user_cap_header_struct cap_hdr_haproxy = {
	.pid = 0, /* current process */
	.version = _LINUX_CAPABILITY_VERSION_3,
};

/* supported names, zero-terminated */
static const struct {
	int cap;
	const char *name;
} known_caps[] = {
#ifdef CAP_NET_RAW
	{ CAP_NET_RAW, "cap_net_raw" },
#endif
#ifdef CAP_NET_ADMIN
	{ CAP_NET_ADMIN, "cap_net_admin" },
#endif
#ifdef CAP_NET_BIND_SERVICE
	{ CAP_NET_BIND_SERVICE, "cap_net_bind_service" },
#endif
#ifdef CAP_SYS_ADMIN
	{ CAP_SYS_ADMIN, "cap_sys_admin" },
#endif
	/* must be last */
	{ 0, 0 }
};

/* provided by sys/capability.h on some distros */
static inline int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return syscall(SYS_capset, hdrp, datap);
}

/* defaults to zero, i.e. we don't keep any cap after setuid() */
static uint32_t caplist;

/* try to check if CAP_NET_ADMIN, CAP_NET_RAW or CAP_SYS_ADMIN are in the
 * process Effective set in the case when euid is non-root. If there is a
 * match, LSTCHK_NETADM or LSTCHK_SYSADM is unset respectively from
 * global.last_checks to avoid warning due to global.last_checks verifications
 * later at the process init stage.
 * If there is no any supported by haproxy capability in the process Effective
 * set, try to check the process Permitted set. In this case we promote from
 * Permitted set to Effective only the capabilities, that were marked by user
 * via 'capset' keyword in the global section (caplist). If there is match with
 * caplist and CAP_NET_ADMIN/CAP_NET_RAW or CAP_SYS_ADMIN are in this list,
 * LSTCHK_NETADM or/and LSTCHK_SYSADM will be unset by the same reason.
 * We do this only if the current euid is non-root and there is no global.uid.
 * Otherwise, the process will continue either to run under root, or it will do
 * a transition to unprivileged user later in prepare_caps_for_setuid(),
 * which specially manages its capabilities in that case.
 * Always returns 0. Diagnostic warnings will be emitted only, if
 * LSTCHK_NETADM/LSTCHK_SYSADM is presented in global.last_checks and some
 * failures are encountered.
 */
int prepare_caps_from_permitted_set(int from_uid, int to_uid)
{
	/* _LINUX_CAPABILITY_U32S_1 = 1 and corresponds to version 1, which is three
	 * 32-bit integers set. So kernel in capset()/capget() will copy_from/to_user
	 * only _LINUX_CAPABILITY_U32S_1 * (sizeof(struct __user_cap_data_struct)),
	 * i.e. only the __user_cap_data_struct[0].
	 */
	struct __user_cap_data_struct start_cap_data[_LINUX_CAPABILITY_U32S_3] = { };

	/* started as root */
	if (!from_uid)
		return 0;

	/* will change ruid and euid later in set_identity() */
	if (to_uid)
		return 0;

	/* first, let's check if CAP_NET_ADMIN or CAP_NET_RAW is already in
	 * the process effective set. This may happen, when administrator sets
	 * these capabilities and the file effective bit on haproxy binary via
	 * setcap, see capabilities man page for details.
	 */
	if (capget(&cap_hdr_haproxy, start_cap_data) == -1) {
		if (global.last_checks & (LSTCHK_NETADM | LSTCHK_SYSADM))
			ha_diag_warning("Failed to get process capabilities using capget(): %s. "
					"Can't use capabilities that might be set on %s binary "
					"by administrator.\n", strerror(errno), progname);
		return 0;
	}

	if (start_cap_data[0].effective & ((1 << CAP_NET_ADMIN)|(1 << CAP_NET_RAW))) {
		global.last_checks &= ~LSTCHK_NETADM;
		return 0;
	}

	if (start_cap_data[0].effective & ((1 << CAP_SYS_ADMIN))) {
		global.last_checks &= ~LSTCHK_SYSADM;
		return 0;
	}

	/* second, try to check process permitted set, in this case caplist is
	 * necessary. Allows to put cap_net_bind_service in process effective
	 * set, if it is in the caplist and also presented in the binary
	 * permitted set.
	 */
	if (caplist && start_cap_data[0].permitted & caplist) {
		start_cap_data[0].effective |= start_cap_data[0].permitted & caplist;
		if (capset(&cap_hdr_haproxy, start_cap_data) == 0) {
			if (caplist & ((1 << CAP_NET_ADMIN)|(1 << CAP_NET_RAW)))
				global.last_checks &= ~LSTCHK_NETADM;
			if (caplist & (1 << CAP_SYS_ADMIN))
				global.last_checks &= ~LSTCHK_SYSADM;
		} else if (global.last_checks & (LSTCHK_NETADM|LSTCHK_SYSADM)) {
			ha_diag_warning("Failed to put capabilities from caplist in %s "
					"process Effective capabilities set using capset(): %s\n",
					progname, strerror(errno));
		}
	}

	return 0;
}

/* try to apply capabilities before switching UID from <from_uid> to <to_uid>.
 * In practice we need to do this in 4 steps:
 *   - set PR_SET_KEEPCAPS to preserve caps across the final setuid()
 *   - set the effective and permitted caps ;
 *   - switch euid to non-zero
 *   - set the effective and permitted caps again
 *   - then the caller can safely call setuid()
 * On success LSTCHK_NETADM is unset from global.last_checks, if CAP_NET_ADMIN
 * or CAP_NET_RAW was found in the caplist from config. Same for
 * LSTCHK_SYSADM, if CAP_SYS_ADMIN was found in the caplist from config.
 * We don't do this if the current euid is not zero or if the target uid
 * is zero. Returns 0 on success, negative on failure. Alerts may be emitted.
 */
int prepare_caps_for_setuid(int from_uid, int to_uid)
{
	/* _LINUX_CAPABILITY_U32S_1 = 1 and corresponds to version 1, which is three
	 * 32-bit integers set. So kernel in capset()/capget() will copy_from/to_user
	 * only _LINUX_CAPABILITY_U32S_1 * (sizeof(struct __user_cap_data_struct)),
	 * i.e. only the __user_cap_data_struct[0].
	 */
	struct __user_cap_data_struct cap_data[_LINUX_CAPABILITY_U32S_3] = { };

	if (from_uid != 0)
		return 0;

	if (!to_uid)
		return 0;

	if (!caplist)
		return 0;

	if (prctl(PR_SET_KEEPCAPS, 1) == -1) {
		ha_alert("Failed to preserve capabilities using prctl(): %s\n", strerror(errno));
		return -1;
	}

	cap_data[0].effective = cap_data[0].permitted = caplist | (1 << CAP_SETUID);
	if (capset(&cap_hdr_haproxy, cap_data) == -1) {
		ha_alert("Failed to preset the capabilities to preserve using capset(): %s\n", strerror(errno));
		return -1;
	}

	if (seteuid(to_uid) == -1) {
		ha_alert("Failed to set effective uid to %d: %s\n", to_uid, strerror(errno));
		return -1;
	}

	cap_data[0].effective = cap_data[0].permitted = caplist | (1 << CAP_SETUID);
	if (capset(&cap_hdr_haproxy, cap_data) == -1) {
		ha_alert("Failed to set the final capabilities using capset(): %s\n", strerror(errno));
		return -1;
	}

	if (caplist & ((1 << CAP_NET_ADMIN)|(1 << CAP_NET_RAW)))
		global.last_checks &= ~LSTCHK_NETADM;

	if (caplist & (1 << CAP_SYS_ADMIN))
		global.last_checks &= ~LSTCHK_SYSADM;

	/* all's good */
	return 0;
}

/* finalize the capabilities after setuid(). The most important is to drop the
 * CAP_SET_SETUID capability, which would otherwise allow to switch back to any
 * UID and recover everything.
 */
int finalize_caps_after_setuid(int from_uid, int to_uid)
{
	struct __user_cap_data_struct cap_data[_LINUX_CAPABILITY_U32S_3] = { };

	if (from_uid != 0)
		return 0;

	if (!to_uid)
		return 0;

	if (!caplist)
		return 0;

	cap_data[0].effective = cap_data[0].permitted = caplist;
	if (capset(&cap_hdr_haproxy, cap_data) == -1) {
		ha_alert("Failed to drop the setuid capability using capset(): %s\n", strerror(errno));
		return -1;
	}

	/* all's good */
	return 0;
}

/* parse the "setcap" global keyword. Returns -1 on failure, 0 on success. */
static int cfg_parse_global_setcap(char **args, int section_type,
                                   struct proxy *curpx, const struct proxy *defpx,
                                   const char *file, int line, char **err)
{
	char *name = args[1];
	char *next;
	uint32_t caps = 0;
	int id;

	if (!*name) {
		memprintf(err, "'%s' : missing capability name(s). ", args[0]);
		goto dump_caps;
	}

	while (name && *name) {
		next = strchr(name, ',');
		if (next)
			*(next++) = '\0';

		for (id = 0; known_caps[id].cap; id++) {
			if (strcmp(name, known_caps[id].name) == 0) {
				caps |= 1U << known_caps[id].cap;
				break;
			}
		}

		if (!known_caps[id].cap) {
			memprintf(err, "'%s' : unsupported capability '%s'. ", args[0], args[1]);
			goto dump_caps;
		}
		name = next;
	}

	caplist |= caps;
	return 0;


 dump_caps:
	memprintf(err, "%s Supported ones are: ", *err);

	for (id = 0; known_caps[id].cap; id++)
		memprintf(err, "%s%s%s%s", *err,
			  id ? known_caps[id+1].cap ? ", " : " and " : "",
			  known_caps[id].name, known_caps[id+1].cap ? "" : ".");
	return -1;
}

static struct cfg_kw_list cfg_kws = {ILH, {
        { CFG_GLOBAL, "setcap", cfg_parse_global_setcap },
        { 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
