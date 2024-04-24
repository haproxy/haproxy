#ifndef _HAPROXY_STATS_FILE_T_H
#define _HAPROXY_STATS_FILE_T_H

/* Sections present in stats-file separated by header lines. */
enum stfile_domain {
	STFILE_DOMAIN_UNSET = 0,

	STFILE_DOMAIN_PX_FE,  /* #fe headers */
	STFILE_DOMAIN_PX_BE,  /* #be headers */
};

#endif /* _HAPROXY_STATS_FILE_T_H */
