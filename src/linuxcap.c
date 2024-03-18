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
#include <linux/capability.h>
#include <sys/prctl.h>
#include <errno.h>
#include <unistd.h>
#include <syscall.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/tools.h>

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

/* try to apply capabilities before switching UID from <from_uid> to <to_uid>.
 * In practice we need to do this in 4 steps:
 *   - set PR_SET_KEEPCAPS to preserve caps across the final setuid()
 *   - set the effective and permitted caps ;
 *   - switch euid to non-zero
 *   - set the effective and permitted caps again
 *   - then the caller can safely call setuid()
 * On success LSTCHK_NETADM is unset from global.last_checks, if CAP_NET_ADMIN
 * or CAP_NET_RAW was found in the caplist from config.
 * We don't do this if the current euid is not zero or if the target uid
 * is zero. Returns 0 on success, negative on failure. Alerts may be emitted.
 */
int prepare_caps_for_setuid(int from_uid, int to_uid)
{
	struct __user_cap_data_struct cap_data = { };
	struct __user_cap_header_struct cap_hdr = {
		.pid = 0, /* current process */
		.version = _LINUX_CAPABILITY_VERSION_1,
	};

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

	cap_data.effective = cap_data.permitted = caplist | (1 << CAP_SETUID);
	if (capset(&cap_hdr, &cap_data) == -1) {
		ha_alert("Failed to preset the capabilities to preserve using capset(): %s\n", strerror(errno));
		return -1;
	}

	if (seteuid(to_uid) == -1) {
		ha_alert("Failed to set effective uid to %d: %s\n", to_uid, strerror(errno));
		return -1;
	}

	cap_data.effective = cap_data.permitted = caplist | (1 << CAP_SETUID);
	if (capset(&cap_hdr, &cap_data) == -1) {
		ha_alert("Failed to set the final capabilities using capset(): %s\n", strerror(errno));
		return -1;
	}

	if (caplist & ((1 << CAP_NET_ADMIN)|(1 << CAP_NET_RAW)))
		global.last_checks &= ~LSTCHK_NETADM;

	/* all's good */
	return 0;
}

/* finalize the capabilities after setuid(). The most important is to drop the
 * CAP_SET_SETUID capability, which would otherwise allow to switch back to any
 * UID and recover everything.
 */
int finalize_caps_after_setuid(int from_uid, int to_uid)
{
	struct __user_cap_data_struct cap_data = { };
	struct __user_cap_header_struct cap_hdr = {
		.pid = 0, /* current process */
		.version = _LINUX_CAPABILITY_VERSION_1,
	};

	if (from_uid != 0)
		return 0;

	if (!to_uid)
		return 0;

	if (!caplist)
		return 0;

	cap_data.effective = cap_data.permitted = caplist;
	if (capset(&cap_hdr, &cap_data) == -1) {
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
