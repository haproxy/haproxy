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

/* header for shm stats file ("shm-stats-file") */
struct shm_stats_file_hdr {
	/* to check if the header is compatible with current haproxy version */
	struct {
		uint8_t major;
		uint8_t minor;
	} version;
	uint global_now_ms;   /* global monotonic date (ms) common to all processes using the shm */
	ullong global_now_ns; /* global monotonic date (ns) common to all processes using the shm */
	llong now_offset;     /* offset applied to global monotonic date on startup */
};

struct shm_stats_file_object {
};

#define SHM_STATS_FILE_MAPPING_SIZE(obj) (sizeof(struct shm_stats_file_hdr) + (obj) * sizeof(struct shm_stats_file_object))

#endif /* _HAPROXY_STATS_FILE_T_H */
