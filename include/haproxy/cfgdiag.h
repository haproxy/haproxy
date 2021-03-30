#ifndef _HAPROXY_CFGDIAG_H
#define _HAPROXY_CFGDIAG_H

/* Placeholder to execute various diagnostic checks after the configuration file
 * has been fully parsed. It will output a warning for each diagnostic found.
 *
 * Returns 0 if no diagnostic message has been found else 1.
 */
int cfg_run_diagnostics();

#endif /* _HAPROXY_CFGDIAG_H */
