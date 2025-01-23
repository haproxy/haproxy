#ifndef _HAPROXY_CPU_TOPO_H
#define _HAPROXY_CPU_TOPO_H

#include <haproxy/api.h>
#include <haproxy/cpuset.h>
#include <haproxy/cpu_topo-t.h>

extern int cpu_topo_maxcpus;
extern int cpu_topo_lastcpu;
extern struct ha_cpu_topo *ha_cpu_topo;

/* Dump the CPU topology <topo> for up to cpu_topo_maxcpus CPUs for
 * debugging purposes. Offline CPUs are skipped.
 */
void cpu_dump_topology(const struct ha_cpu_topo *topo);

#endif /* _HAPROXY_CPU_TOPO_H */
