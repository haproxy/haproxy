#ifndef _HAPROXY_STATS_FILE_T_H
#define _HAPROXY_STATS_FILE_T_H

#include <inttypes.h>
#include <haproxy/compat.h>
#include <haproxy/counters-t.h>
#include <haproxy/guid-t.h>

/* Sections present in stats-file separated by header lines. */
enum stfile_domain {
	STFILE_DOMAIN_UNSET = 0,

	STFILE_DOMAIN_PX_FE,  /* #fe headers */
	STFILE_DOMAIN_PX_BE,  /* #be headers */
};

#define SHM_STATS_FILE_VER_MAJOR         1
#define SHM_STATS_FILE_VER_MINOR         0

#define SHM_STATS_FILE_HEARTBEAT_TIMEOUT 60 /* passed this delay (seconds) process which has not
                                             * sent heartbeat will be considered down
                                             */

/* header for shm stats file ("shm-stats-file")
 *
 * exported struct:
 * any change in size or ordering would represent breaking change and
 * should cause a version change
 */
struct shm_stats_file_hdr {
	/* to check if the header is compatible with current haproxy version */
	struct {
		uint8_t major;
		uint8_t minor;
	} version;
	/* 2 bytes hole */
	uint global_now_ms;   /* global monotonic date (ms) common to all processes using the shm */
	ullong global_now_ns; /* global monotonic date (ns) common to all processes using the shm */
	llong now_offset;     /* offset applied to global monotonic date on startup */
	/* each process uses one slot and is identified using its pid, max 64 in order
	 * to be able to use bitmask to refer to a process and then look its pid in the
	 * "slots.pid" map
	 * "heartbeat"is used to store the last activity + timeout of the process to check
	 * whether it should be considered as alive or dead
	 * no thread safety mechanism is employed, we assume co-processes are not started
	 * simultaneously
	 */
	struct {
		pid_t pid;
		int heartbeat; // last activity of this process + heartbeat timeout, in ticks
	} slots[64];
	int objects; /* actual number of objects stored in the shm */
	int objects_slots; /* total available objects slots unless map is resized */
	ALWAYS_PAD(128); // reserve 128 bytes for future usage
};

#define SHM_STATS_FILE_OBJECT_TYPE_FE 0x0
#define SHM_STATS_FILE_OBJECT_TYPE_BE 0x1

/*
 * exported struct:
 * any change in size or ordering would represent breaking change and
 * should cause a version change
 */
struct shm_stats_file_object {
	char guid[GUID_MAX_LEN + 1];
	uint8_t tgid; // thread group ID from 1 to 64
	uint8_t type; // SHM_STATS_FILE_OBJECT_TYPE_* to know how to handle object.data
	ALWAYS_PAD(6); // 6 bytes hole, ensure it remains the same size 32 vs 64 bits arch
	uint64_t users; // bitfield that corresponds to users of the object (see shm_stats_file_hdr slots)
	/* as the struct may hold any of the types described here, let's make it
	 * so it may store up to the heaviest one using an union
	 */
	union {
		struct fe_counters_shared_tg fe;
		struct be_counters_shared_tg be;
	} data;
	ALWAYS_PAD(64); // reserve 64 bytes for future usage
};

#define SHM_STATS_FILE_MAPPING_SIZE(obj) (sizeof(struct shm_stats_file_hdr) + (obj) * sizeof(struct shm_stats_file_object))
#define SHM_STATS_FILE_OBJECT(mem, it) (struct shm_stats_file_object *)((char *)mem + sizeof(struct shm_stats_file_hdr) + (it) * sizeof(struct shm_stats_file_object))

#endif /* _HAPROXY_STATS_FILE_T_H */
