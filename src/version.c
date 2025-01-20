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

/* the build options string depending on known settings */
char build_opts_string[]    = ""
#ifdef BUILD_TARGET
	       "\n  TARGET  = " BUILD_TARGET
#endif
#ifdef BUILD_CC
	       "\n  CC      = " BUILD_CC
#endif
#ifdef BUILD_CFLAGS
	       "\n  CFLAGS  = " BUILD_CFLAGS
#endif
#ifdef BUILD_OPTIONS
	       "\n  OPTIONS = " BUILD_OPTIONS
#endif
#ifdef BUILD_DEBUG
	       "\n  DEBUG   = " BUILD_DEBUG
#endif
	"";

/* compact string of toolchain options for post-mortem */
const char pm_toolchain_opts[] = ""
#ifdef BUILD_CC
	BUILD_CC
#endif
#ifdef BUILD_CFLAGS
	" " BUILD_CFLAGS
#endif
#ifdef BUILD_DEBUG
	" " BUILD_DEBUG
#endif
	"";

/* compact string of target options for post-mortem */
const char pm_target_opts[] = ""
#ifdef BUILD_TARGET
	"TARGET='" BUILD_TARGET "'"
#endif
#ifdef BUILD_OPTIONS
	" " BUILD_OPTIONS
#endif
	"";

/* Build features may be passed by the makefile */
#ifdef BUILD_FEATURES
char *build_features = BUILD_FEATURES;
#else
char *build_features = "";
#endif

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
