#ifndef _HAPROXY_CPU_TOPO_H
#define _HAPROXY_CPU_TOPO_H

#include <haproxy/api.h>
#include <haproxy/cpuset.h>
#include <haproxy/cpu_topo-t.h>

extern struct ha_cpu_topo *ha_cpu_topo;

/* Dump the CPU topology <topo> for up to <maxcpus> for debugging purposes.
 * Offline CPUs are skipped.
 */
void cpu_dump_topology(const struct ha_cpu_topo *topo, int maxcpus);

#endif /* _HAPROXY_CPU_TOPO_H */
