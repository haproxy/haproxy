/*
 * Version reporting : all user-visible version information should come from
 * this file so that rebuilding only this one is enough to report the latest
 * code version.
 */

#include <common/version.h>

/* These ones are made variables and not constants so that they are stored into
 * the data region and prominently appear in core files.
 */
char haproxy_version_here[] = "HAProxy version follows";
char haproxy_version[]      = HAPROXY_VERSION;
char haproxy_date[]         = HAPROXY_DATE;
char stats_version_string[] = STATS_VERSION_STRING;
