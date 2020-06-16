/*
 * Version reporting : all user-visible version information should come from
 * this file so that rebuilding only this one is enough to report the latest
 * code version.
 */

#include <haproxy/global.h>
#include <haproxy/version.h>

/* These ones are made variables and not constants so that they are stored into
 * the data region and prominently appear in core files.
 */
char haproxy_version_here[] = "HAProxy version follows";
char haproxy_version[]      = HAPROXY_VERSION;
char haproxy_date[]         = HAPROXY_DATE;
char stats_version_string[] = STATS_VERSION_STRING;

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#define SANITIZE_STRING " with address sanitizer"
#else
#define SANITIZE_STRING ""
#endif

#if defined(__clang_version__)
REGISTER_BUILD_OPTS("Built with clang compiler version " __clang_version__ "" SANITIZE_STRING);
#elif defined(__VERSION__)
REGISTER_BUILD_OPTS("Built with gcc compiler version " __VERSION__ "" SANITIZE_STRING);
#endif
