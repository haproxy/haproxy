/*
 * Version reporting : all user-visible version information should come from
 * this file so that rebuilding only this one is enough to report the latest
 * code version.
 */

#include <common/version.h>

const char *haproxy_version      = HAPROXY_VERSION;
const char *haproxy_date         = HAPROXY_DATE;
const char *stats_version_string = STATS_VERSION_STRING;
