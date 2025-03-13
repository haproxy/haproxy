#ifndef _HAPROXY_CPU_TOPO_H
#define _HAPROXY_CPU_TOPO_H

#include <haproxy/api.h>
#include <haproxy/cpuset.h>
#include <haproxy/cpu_topo-t.h>

extern int cpu_topo_maxcpus;
extern int cpu_topo_lastcpu;
extern struct ha_cpu_topo *ha_cpu_topo;

#endif /* _HAPROXY_CPU_TOPO_H */
