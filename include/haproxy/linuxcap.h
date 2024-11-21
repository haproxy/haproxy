#ifndef _HAPROXY_LINUXCAP_H
#define _HAPROXY_LINUXCAP_H
#include <syscall.h>
#include <linux/capability.h>

#define CAPS_TO_ULLONG(low, high)    (((ullong)high << 32) | (ullong)low)

/* for haproxy process itself, allocate this 8 byte-size struct only once in
 * .data and makes it accessible from other compile-units, because we always
 * fill it with the same values and because we could use it to collect
 * capabilities for post_mortem debug info.
 */
extern struct __user_cap_header_struct cap_hdr_haproxy;

/* provided by sys/capability.h on some distros, declared here, as could be used
 * in debug.c, in order to collect info about process capabilities before
 * applying its configuration and at runtime.
 */
static inline int capget(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return syscall(SYS_capget, hdrp, datap);
}
int prepare_caps_for_setuid(int from_uid, int to_uid);
int finalize_caps_after_setuid(int from_uid, int to_uid);
int prepare_caps_from_permitted_set(int from_uid, int to_uid);

#endif /* _HAPROXY_LINUXCAP_H */
