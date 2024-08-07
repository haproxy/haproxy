#ifndef _HAPROXY_TIME_T_H
#define _HAPROXY_TIME_T_H

/* Type used to account a total time over distinct periods. */
struct tot_time {
	uint32_t curr; /* timestamp of start date or 0 if timer stopped */
	uint32_t tot;  /* total already accounted since last stop */
};

#endif /* _HAPROXY_TIME_T_H */
