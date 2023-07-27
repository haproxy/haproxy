#include <sys/time.h>
#include <sys/epoll.h>

#define gettimeofday(tv, tz) timeshift_gettimeofday(tv, tz)
#define clock_gettime(clk_id, tp) timeshift_clock_gettime(clk_id, tp)
#define epoll_wait(epfd, events, maxevents, timeout) timeshift_epoll_wait(epfd, events, maxevents, timeout)

int timeshift_gettimeofday(struct timeval *tv, void *tz);
int timeshift_clock_gettime(clockid_t clk_id, struct timespec *tp);
int timeshift_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
