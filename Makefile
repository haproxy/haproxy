# This GNU Makefile supports different OS and CPU combinations.
#
# You should use it this way :
#   [g]make TARGET=os [CFLAGS=...] USE_xxx=1 ...
#
# When in doubt, invoke help, possibly with a known target :
#   [g]make help
#   [g]make help TARGET=linux-glibc
#
# By default the detailed commands are hidden for a cleaner output, but you may
# see them by appending "V=1" to the make command.
#
# Valid USE_* options are enumerated in the "use_opts" variable and are listed
# below. Most of them are automatically set by the TARGET, others have to be
# explicitly specified :
#   USE_EPOLL               : enable epoll() on Linux 2.6. Automatic.
#   USE_KQUEUE              : enable kqueue() on BSD. Automatic.
#   USE_EVPORTS             : enable event ports on SunOS systems. Automatic.
#   USE_NETFILTER           : enable netfilter on Linux. Automatic.
#   USE_PCRE                : enable use of libpcre for regex.
#   USE_PCRE_JIT            : enable JIT for faster regex on libpcre >= 8.32
#   USE_PCRE2               : enable use of libpcre2 for regex. Recommended.
#   USE_PCRE2_JIT           : enable JIT for faster regex on libpcre2
#   USE_POLL                : enable poll(). Automatic.
#   USE_THREAD              : enable threads support.
#   USE_STATIC_PCRE         : enable static libpcre.
#   USE_STATIC_PCRE2        : enable static libpcre2. Recommended.
#   USE_TPROXY              : enable transparent proxy. Automatic.
#   USE_LINUX_TPROXY        : enable full transparent proxy. Automatic.
#   USE_LINUX_SPLICE        : enable kernel 2.6 splicing. Automatic.
#   USE_LINUX_CAP           : enable Linux capabilities.
#   USE_LIBCRYPT            : enable encrypted passwords using -lcrypt
#   USE_CRYPT_H             : set it if your system requires including crypt.h
#   USE_GETADDRINFO         : use getaddrinfo() to resolve IPv6 host names.
#   USE_OPENSSL             : enable use of OpenSSL. Recommended, but see below.
#   USE_OPENSSL_AWSLC       : enable use of AWS-LC
#   USE_OPENSSL_WOLFSSL     : enable use of wolfSSL with the OpenSSL API
#   USE_QUIC                : enable use of QUIC with the quictls API (quictls, libressl, boringssl)
#   USE_QUIC_OPENSSL_COMPAT : enable use of QUIC with the standard openssl API (limited features)
#   USE_ENGINE              : enable use of OpenSSL Engine.
#   USE_LUA                 : enable Lua support.
#   USE_ACCEPT4             : enable use of accept4() on linux. Automatic.
#   USE_CLOSEFROM           : enable use of closefrom() on *bsd, solaris. Automatic.
#   USE_PRCTL               : enable use of prctl(). Automatic.
#   USE_PROCCTL             : enable use of procctl(). Automatic.
#   USE_ZLIB                : enable zlib library support and disable SLZ
#   USE_SLZ                 : enable slz library instead of zlib (default=enabled)
#   USE_CPU_AFFINITY        : enable pinning processes to CPU on Linux. Automatic.
#   USE_TFO                 : enable TCP fast open. Supported on Linux >= 3.7.
#   USE_NS                  : enable network namespace support. Supported on Linux >= 2.6.24.
#   USE_DL                  : enable it if your system requires -ldl. Automatic on Linux.
#   USE_MATH                : enable use of -lm. Automatic.
#   USE_RT                  : enable it if your system requires -lrt. Automatic on Linux.
#   USE_BACKTRACE           : enable backtrace(). Automatic on Linux.
#   USE_PROMEX              : enable the Prometheus exporter
#   USE_DEVICEATLAS         : enable DeviceAtlas api.
#   USE_51DEGREES           : enable third party device detection library from 51Degrees
#   USE_WURFL               : enable WURFL detection library from Scientiamobile
#   USE_OBSOLETE_LINKER     : use when the linker fails to emit __start_init/__stop_init
#   USE_THREAD_DUMP         : use the more advanced thread state dump system. Automatic.
#   USE_OT                  : enable the OpenTracing filter
#   USE_MEMORY_PROFILING    : enable the memory profiler. Linux-glibc only.
#   USE_LIBATOMIC           : force to link with/without libatomic. Automatic.
#   USE_PTHREAD_EMULATION   : replace pthread's rwlocks with ours
#
# Options can be forced by specifying "USE_xxx=1" or can be disabled by using
# "USE_xxx=" (empty string). The list of enabled and disabled options for a
# given TARGET is enumerated at the end of "make help". Most of these options
# support specific xxx_CFLAGS and/or xxx_LDFLAGS that can be individually
# forced. The currently active ones for a given set of options are listed in
# "make opts USE_xxx=1 ...".
#
# Variables useful for packagers :
#   CC is set to "cc" by default and is used for compilation only.
#   LD is set to "cc" by default and is used for linking only.
#   OPT_CFLAGS sets the default optimization level (-O2).
#   CFLAGS may be used to append any flags for the C compiler.
#   LDFLAGS is automatically set to -g and may be overridden.
#   ARCH_FLAGS for flags common to both CC and LD. Defaults to -g.
#   DEP may be cleared to ignore changes to include files during development
#   DEBUG may be used to set some internal debugging options.
#   ERR may be set to non-empty to pass -Werror to the compiler
#   FAILFAST may be set to non-empty to pass -Wfatal-errors to the compiler
#   WARN_CFLAGS overrides the default set of enabled warning options
#   NOWARN_CFLAGS overrides the default set of disabled warning options
#   ADDINC may be used to complete the include path in the form -Ipath.
#   ADDLIB may be used to complete the library list in the form -Lpath -llib.
#   DEFINE may be used to specify any additional define, which will be reported
#          by "haproxy -vv" in CFLAGS.
#   SILENT_DEFINE may be used to specify other defines which will not be
#     reported by "haproxy -vv".
#   EXTRA   is used to force building or not building some extra tools.
#   DESTDIR is not set by default and is used for installation only.
#           It might be useful to set DESTDIR if you want to install haproxy
#           in a sandbox.
#   INSTALL is set to "install" by default and is used to provide the name of
#           the install binary used by the install targets and any additional
#           flags.
#   PREFIX  is set to "/usr/local" by default and is used for installation only.
#   SBINDIR is set to "$(PREFIX)/sbin" by default and is used for installation
#           only.
#   MANDIR  is set to "$(PREFIX)/share/man" by default and is used for
#           installation only.
#   DOCDIR  is set to "$(PREFIX)/doc/haproxy" by default and is used for
#           installation only.
#   HLUA_PREPEND_PATH may be used to prepend a folder to Lua's default package.path.
#   HLUA_PREPEND_CPATH may be used to prepend a folder to Lua's default package.cpath.
#
# Other variables :
#   PCRE_CONFIG    : force the binary path to get pcre config (by default
#                                                              pcre-config)
#   PCREDIR        : force the path to libpcre.
#   PCRE_LIB       : force the lib path to libpcre (defaults to $PCREDIR/lib).
#   PCRE_INC       : force the include path to libpcre ($PCREDIR/inc)
#   PCRE2_CONFIG   : force the binary path to get pcre2 config (by default
#                                                               pcre2-config)
#   SSL_LIB        : force the lib path to libssl/libcrypto
#   SSL_INC        : force the include path to libssl/libcrypto
#   LUA_LIB        : force the lib path to lua
#   LUA_INC        : force the include path to lua
#   LUA_LIB_NAME   : force the lib name (or automatically evaluated, by order of
#                                        priority : lua5.4, lua54, lua5.3, lua53, lua).
#   OT_DEBUG       : compile the OpenTracing filter in debug mode
#   OT_INC         : force the include path to libopentracing-c-wrapper
#   OT_LIB         : force the lib path to libopentracing-c-wrapper
#   OT_RUNPATH     : add RUNPATH for libopentracing-c-wrapper to haproxy executable
#   OT_USE_VARS    : allows the use of variables for the OpenTracing context
#   IGNOREGIT      : ignore GIT commit versions if set.
#   VERSION        : force haproxy version reporting.
#   SUBVERS        : add a sub-version (eg: platform, model, ...).
#   EXTRAVERSION   : local version string to append (e.g. build number etc)
#   VERDATE        : force haproxy's release date.
#   VTEST_PROGRAM  : location of the vtest program to run reg-tests.
#   DEBUG_USE_ABORT: use abort() for program termination, see include/haproxy/bug.h for details

#### Add -Werror when set to non-empty, and make Makefile stop on warnings.
#### It must be declared before includes because it's used there.
ERR =

include include/make/verbose.mk
include include/make/errors.mk
include include/make/compiler.mk
include include/make/options.mk

#### Installation options.
DESTDIR =
INSTALL = install
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
DOCDIR = $(PREFIX)/doc/haproxy

#### TARGET system
# Use TARGET=<target_name> to optimize for a specific target OS among the
# following list (use the default "generic" if uncertain) :
#    linux-glibc, linux-glibc-legacy, linux-musl, solaris, freebsd, freebsd-glibc,
#    dragonfly, openbsd, netbsd, cygwin, haiku, aix51, aix52, aix72-gcc, osx, generic,
#    custom
TARGET =

#### No longer used
CPU =
ifneq ($(CPU),)
ifneq ($(CPU),generic)
$(call $(complain),the "CPU" variable was forced to "$(CPU)" but is no longer \
  used and will be ignored. For native builds, modern compilers generally     \
  prefer that the string "-march=native" is passed in CPU_CFLAGS or CFLAGS.   \
  For other CPU-specific options, please read suggestions in the INSTALL file.)
endif
endif

#### No longer used
ARCH =
ifneq ($(ARCH),)
$(call $(complain),the "ARCH" variable was forced to "$(ARCH)" but is no \
  longer used and will be ignored. Please check the INSTALL file for other \
  options, but usually in order to pass arch-specific options, ARCH_FLAGS, \
  CFLAGS or LDFLAGS are preferred.)
endif

#### Toolchain options.
CC = cc
LD = $(CC)

#### Default optimizations
# Those are integrated early in the list of CFLAGS, and may be overridden by
# other CFLAGS options if needed.
OPT_CFLAGS = -O2

#### No longer used
DEBUG_CFLAGS =
ifneq ($(DEBUG_CFLAGS),)
$(call $(complain),DEBUG_CFLAGS was forced to "$(DEBUG_CFLAGS)" but is no     \
  longer used and will be ignored. If you have ported this build setting from \
  and older version, it is likely that you just want to pass these options    \
  to the CFLAGS variable. If you are passing some debugging-related options   \
  such as -g/-ggdb3/-pg etc, they can now be passed in ARCH_FLAGS at once for \
  both the compilation and linking stages.)
endif

#### May be used to force running a specific set of reg-tests
REG_TEST_FILES =
REG_TEST_SCRIPT=./scripts/run-regtests.sh

#### Standard C definition
# Compiler-specific flags that may be used to set the standard behavior we
# rely on and to disable some negative over-optimization. More specifically,
# we rely on signed integer wraparound on overflow, however recently clang and
# gcc decided to change their code generation regarding this and abuse the
# undefined behavior to silently produce invalid code. For this reason we have
# to use -fwrapv or -fno-strict-overflow to guarantee the intended behavior.
# It is preferable not to change this option in order to avoid breakage.
STD_CFLAGS  := $(call cc-opt-alt,-fwrapv,-fno-strict-overflow)

#### Compiler-specific flags to enable certain classes of warnings.
# Some are hard-coded, others are enabled only if supported.
WARN_CFLAGS := -Wall -Wextra -Wundef -Wdeclaration-after-statement            \
               $(call cc-all-fast,                                            \
                 -Wtype-limits -Wshift-negative-value -Wshift-overflow=2      \
                 -Wduplicated-cond -Wnull-dereference)

#### Compiler-specific flags to enable certain classes of warnings.
NOWARN_CFLAGS := $(cc-wnouwo)
NOWARN_CFLAGS += $(call cc-nowarn,address-of-packed-member)
NOWARN_CFLAGS += $(call cc-nowarn,unused-label)
NOWARN_CFLAGS += $(call cc-nowarn,sign-compare)
NOWARN_CFLAGS += $(call cc-nowarn,unused-parameter)
NOWARN_CFLAGS += $(call cc-nowarn,clobbered)
NOWARN_CFLAGS += $(call cc-nowarn,missing-field-initializers)
NOWARN_CFLAGS += $(call cc-nowarn,cast-function-type)
NOWARN_CFLAGS += $(call cc-nowarn,string-plus-int)
NOWARN_CFLAGS += $(call cc-nowarn,atomic-alignment)

#### CFLAGS defining error handling
# ERROR_CFLAGS are just accumulators for these variables, they're not meant
# to be exposed nor manipulated outside of this. They're not reported in
# VERBOSE_CFLAGS and don't cause a rebuild when changed.
ERROR_CFLAGS :=
ifneq ($(ERR:0=),)
  ERROR_CFLAGS += -Werror
endif

ifneq ($(FAILFAST:0=),)
  ERROR_CFLAGS += -Wfatal-errors
endif

#### No longer used
SMALL_OPTS =
ifneq ($(SMALL_OPTS),)
$(call $(complain),SMALL_OPTS was forced to "$(SMALL_OPTS)" but is no longer \
  used and will be ignored. Please check if this setting are still relevant, \
  and move it either to DEFINE or to CFLAGS instead.)
endif

#### Debug settings
# You can enable debugging on specific code parts by setting DEBUG=-DDEBUG_xxx.
# Use quotes and spaces if multiple options are needed (the DEBUG variables is
# passed as-is to CFLAGS). Please check sources for their exact meaning or do
# not use them at all. Some even more obscure ones might also be available
# without appearing here. Currently defined DEBUG macros include DEBUG_FULL,
# DEBUG_MEM_STATS, DEBUG_DONT_SHARE_POOLS, DEBUG_FD, DEBUG_POOL_INTEGRITY,
# DEBUG_NO_POOLS, DEBUG_FAIL_ALLOC, DEBUG_STRICT_ACTION=[0-3], DEBUG_HPACK,
# DEBUG_AUTH, DEBUG_SPOE, DEBUG_UAF, DEBUG_THREAD, DEBUG_STRICT, DEBUG_DEV,
# DEBUG_TASK, DEBUG_MEMORY_POOLS, DEBUG_POOL_TRACING, DEBUG_QPACK, DEBUG_LIST,
# DEBUG_GLITCHES, DEBUG_STRESS.
DEBUG =

#### Trace options
# Use TRACE=1 to trace function calls to file "trace.out" or to stderr if not
# possible.
TRACE =

#### Additional include and library dirs
# Redefine this if you want to add some special PATH to include/libs
ADDINC =
ADDLIB =

#### Specific macro definitions
# Use DEFINE=-Dxxx to set any tunable macro. Anything declared here will appear
# in the build options reported by "haproxy -vv". Use SILENT_DEFINE if you do
# not want to pollute the report with complex defines.
# The following settings might be of interest when SSL is enabled :
#   LISTEN_DEFAULT_CIPHERS is a cipher suite string used to set the default SSL
#           ciphers on "bind" lines instead of using OpenSSL's defaults.
#   CONNECT_DEFAULT_CIPHERS is a cipher suite string used to set the default
#           SSL ciphers on "server" lines instead of using OpenSSL's defaults.
DEFINE =
SILENT_DEFINE =

#### extra programs to build
# Force this to enable building extra programs or to disable them.
# It's automatically appended depending on the targets.
EXTRA =

#### CPU dependent optimizations
# This may optionally be used to pass CPU-specific optimizations such as
# -march=native, -mcpu=something, -m64 etc independently of CFLAGS if it is
# considered more convenient. Historically, the optimization level was also
# passed there. This is still supported but not recommended though; OPT_CFLAGS
# is better suited. The default is empty.
CPU_CFLAGS        =

#### Architecture dependent flags.
# These flags are passed both to the compiler and to the linker. A number of
# settings may need to be passed to both tools, among which some arch-specific
# options such as -m32 or -m64, some debugging options (-g), some profiling
# options (-pg), some options affecting how the linkage is done (-flto), as
# well as some code analysers such as -fsanitize=address. All of these make
# sense here and will be consistently propagated to both stages. By default
# only the debugging is enabled (-g).
ARCH_FLAGS        = -g

#### Extra CFLAGS
# These CFLAGS are empty by default and are appended at the end of all the
# flags passed to the compiler, so that it is possible to use them to force
# some optimization levels, architecture types and/or disable certain warnings.
# Just set CFLAGS to the desired ones on the "make" command line.
CFLAGS =

#### Extra LDFLAGS
# These LDFLAGS are used as the first "ld" options just after ARCH_FLAGS,
# regardless of any library path or any other option. They may be used to add
# any linker-specific option at the beginning of the ld command line. It may be
# convenient to set a run time search path (-rpath), see INSTALL for more info.
LDFLAGS =

#### list of all "USE_*" options. These ones must be updated if new options are
# added, so that the relevant options are properly added to the CFLAGS and to
# the reported build options.
#
# Relevant *_CFLAGS/*_LDFLAGS will be concatenated in the order defined here.
# Note that PCRE last position is advisable as it relies on pcre configuration
# detection tool which may generate default include/lib paths overriding more
# specific entries if present before them.
use_opts = USE_EPOLL USE_KQUEUE USE_NETFILTER USE_POLL                        \
           USE_THREAD USE_PTHREAD_EMULATION USE_BACKTRACE                     \
           USE_TPROXY USE_LINUX_TPROXY USE_LINUX_CAP                          \
           USE_LINUX_SPLICE USE_LIBCRYPT USE_CRYPT_H USE_ENGINE               \
           USE_GETADDRINFO USE_OPENSSL USE_OPENSSL_WOLFSSL USE_OPENSSL_AWSLC  \
           USE_SSL USE_LUA USE_ACCEPT4 USE_CLOSEFROM USE_ZLIB USE_SLZ         \
           USE_CPU_AFFINITY USE_TFO USE_NS USE_DL USE_RT USE_LIBATOMIC        \
           USE_MATH USE_DEVICEATLAS USE_51DEGREES                             \
           USE_WURFL USE_OBSOLETE_LINKER USE_PRCTL USE_PROCCTL                \
           USE_THREAD_DUMP USE_EVPORTS USE_OT USE_QUIC USE_PROMEX             \
           USE_MEMORY_PROFILING                                               \
           USE_STATIC_PCRE USE_STATIC_PCRE2                                   \
           USE_PCRE USE_PCRE_JIT USE_PCRE2 USE_PCRE2_JIT USE_QUIC_OPENSSL_COMPAT

# preset all variables for all supported build options among use_opts
$(reset_opts_vars)

# Check that any USE_* variable that was forced actually exist.
$(warn_unknown_options)

#### Target system options

# poll() is always supported, unless explicitly disabled by passing USE_POLL=""
# on the make command line.
USE_POLL   = default

# SLZ is always supported unless explicitly disabled by passing USE_SLZ=""
# or disabled by enabling ZLIB using USE_ZLIB=1
ifeq ($(USE_ZLIB:0=),)
  USE_SLZ    = default
endif

# generic system target has nothing specific
ifeq ($(TARGET),generic)
  set_target_defaults = $(call default_opts,USE_POLL USE_TPROXY)
endif

# Haiku
ifeq ($(TARGET),haiku)
  TARGET_LDFLAGS = -lnetwork
  set_target_defaults = $(call default_opts,USE_POLL USE_TPROXY USE_OBSOLETE_LINKER)
endif

# For linux >= 2.6.28 and glibc
ifeq ($(TARGET),linux-glibc)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_DL USE_RT USE_CRYPT_H USE_NETFILTER  \
    USE_CPU_AFFINITY USE_THREAD USE_EPOLL USE_LINUX_TPROXY USE_LINUX_CAP      \
    USE_ACCEPT4 USE_LINUX_SPLICE USE_PRCTL USE_THREAD_DUMP USE_NS USE_TFO     \
    USE_GETADDRINFO USE_BACKTRACE)
  INSTALL = install -v
endif

# For linux >= 2.6.28, glibc without new features
ifeq ($(TARGET),linux-glibc-legacy)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_DL USE_RT USE_CRYPT_H USE_NETFILTER  \
    USE_CPU_AFFINITY USE_THREAD USE_EPOLL USE_LINUX_TPROXY USE_LINUX_CAP      \
    USE_ACCEPT4 USE_LINUX_SPLICE USE_PRCTL USE_THREAD_DUMP USE_GETADDRINFO)
  INSTALL = install -v
endif

# For linux >= 2.6.28 and musl
ifeq ($(TARGET),linux-musl)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_DL USE_RT USE_CRYPT_H USE_NETFILTER  \
    USE_CPU_AFFINITY USE_THREAD USE_EPOLL USE_LINUX_TPROXY USE_LINUX_CAP      \
    USE_ACCEPT4 USE_LINUX_SPLICE USE_PRCTL USE_THREAD_DUMP USE_NS USE_TFO     \
    USE_GETADDRINFO)
  INSTALL = install -v
endif

# Solaris 10 and above
ifeq ($(TARGET),solaris)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_CRYPT_H USE_GETADDRINFO USE_THREAD \
    USE_RT USE_OBSOLETE_LINKER USE_EVPORTS USE_CLOSEFROM)
  TARGET_CFLAGS  = -DFD_SETSIZE=65536 -D_REENTRANT -D_XOPEN_SOURCE=600 -D__EXTENSIONS__
  TARGET_LDFLAGS = -lnsl -lsocket
endif

# FreeBSD 10 and above
ifeq ($(TARGET),freebsd)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_THREAD USE_CPU_AFFINITY USE_KQUEUE   \
    USE_ACCEPT4 USE_CLOSEFROM USE_GETADDRINFO USE_PROCCTL)
endif

# kFreeBSD glibc
ifeq ($(TARGET),freebsd-glibc)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_THREAD USE_CPU_AFFINITY USE_KQUEUE   \
    USE_ACCEPT4 USE_GETADDRINFO USE_CRYPT_H USE_DL)
endif

# DragonFlyBSD 4.3 and above
ifeq ($(TARGET),dragonfly)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_THREAD USE_CPU_AFFINITY USE_KQUEUE   \
    USE_ACCEPT4 USE_CLOSEFROM USE_GETADDRINFO)
endif

# Mac OS/X
ifeq ($(TARGET),osx)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_THREAD USE_CPU_AFFINITY USE_KQUEUE   \
    USE_GETADDRINFO)
  EXPORT_SYMBOL  = -export_dynamic
endif

# OpenBSD 6.3 and above
ifeq ($(TARGET),openbsd)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_THREAD USE_KQUEUE USE_ACCEPT4        \
    USE_CLOSEFROM USE_GETADDRINFO)
endif

# NetBSD 8 and above
ifeq ($(TARGET),netbsd)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_THREAD USE_KQUEUE USE_ACCEPT4        \
    USE_CLOSEFROM USE_GETADDRINFO)
endif

# AIX 5.1 only
ifeq ($(TARGET),aix51)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_LIBCRYPT USE_OBSOLETE_LINKER)
  TARGET_CFLAGS   = -Dss_family=__ss_family -Dip6_hdr=ip6hdr -DSTEVENS_API -D_LINUX_SOURCE_COMPAT -Dunsetenv=my_unsetenv
endif

# AIX 5.2
ifeq ($(TARGET),aix52)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_LIBCRYPT USE_OBSOLETE_LINKER)
  TARGET_CFLAGS   = -D_MSGQSUPPORT
endif

# AIX 7.2 and above
ifeq ($(TARGET),aix72-gcc)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_THREAD USE_LIBCRYPT USE_OBSOLETE_LINKER USE_GETADDRINFO)
  TARGET_CFLAGS   = -D_H_XMEM -D_H_VAR
  USE_LIBATOMIC   = implicit
endif

# Cygwin
ifeq ($(TARGET),cygwin)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_OBSOLETE_LINKER)
  # Cygwin adds IPv6 support only in version 1.7 (in beta right now).
  TARGET_CFLAGS  = $(if $(filter 1.5.%, $(shell uname -r)), -DUSE_IPV6 -DAF_INET6=23 -DINET6_ADDRSTRLEN=46, )
endif

# set the default settings according to the target above
$(set_target_defaults)

# Some architectures require to link with libatomic for atomics of certain
# sizes. These ones are reported as value 1 in the *_LOCK_FREE macros. Value
# 2 indicates that the builtin is native thus doesn't require libatomic. Hence
# any occurrence of 1 indicates libatomic is necessary. It's better to avoid
# linking with it by default as it's not always available nor deployed
# (especially on archs which do not need it).
ifneq ($(USE_THREAD:0=),)
  ifneq ($(shell $(CC) $(OPT_CFLAGS) $(ARCH_FLAGS) $(CPU_CFLAGS) $(STD_CFLAGS) $(WARN_CFLAGS) $(NOWARN_CFLAGS) $(ERROR_CFLAGS) $(CFLAGS) -dM -E -xc - </dev/null 2>/dev/null | grep -c 'LOCK_FREE.*1'),0)
    USE_LIBATOMIC   = implicit
  endif
endif

#### Determine version, sub-version and release date.
# If GIT is found, and IGNOREGIT is not set, VERSION, SUBVERS and VERDATE are
# extracted from the last commit. Otherwise, use the contents of the files
# holding the same names in the current directory.

ifeq ($(IGNOREGIT),)
  VERSION := $(shell [ -d .git/. ] && (git describe --tags --match 'v*' --abbrev=0 | cut -c 2-) 2>/dev/null)
  ifneq ($(VERSION),)
    # OK git is there and works.
    SUBVERS := $(shell comms=`git log --format=oneline --no-merges v$(VERSION).. 2>/dev/null | wc -l | tr -d '[:space:]'`; commit=`(git log -1 --pretty=%h --abbrev=6) 2>/dev/null`; [ $$comms -gt 0 ] && echo "-$$commit-$$comms")
    VERDATE := $(shell git log -1 --pretty=format:%ci | cut -f1 -d' ' | tr '-' '/')
  endif
endif

# Last commit version not found, take it from the files.
ifeq ($(VERSION),)
  VERSION := $(shell cat VERSION 2>/dev/null || touch VERSION)
endif
ifeq ($(SUBVERS),)
  SUBVERS := $(shell (grep -v '\$$Format' SUBVERS 2>/dev/null || touch SUBVERS) | head -n 1)
endif
ifeq ($(VERDATE),)
  VERDATE := $(shell (grep -v '^\$$Format' VERDATE 2>/dev/null || touch VERDATE) | head -n 1 | cut -f1 -d' ' | tr '-' '/')
endif

# this one is always empty by default and appended verbatim
EXTRAVERSION =

#### Build options
# Do not change these ones, enable USE_* variables instead.
OPTIONS_CFLAGS  =
OPTIONS_LDFLAGS =
OPTIONS_OBJS    =

#### Extra objects to be built and integrated (used only for development)
EXTRA_OBJS =

# This variable collects all USE_* values except those set to "implicit". This
# is used to report a list of all flags which were used to build this version.
# Do not assign anything to it.
BUILD_OPTIONS  := $(call build_options)

# All USE_* options have their equivalent macro defined in the code (some might
# possibly be unused though)
OPTIONS_CFLAGS += $(call opts_as_defines)

ifneq ($(USE_LIBCRYPT:0=),)
  ifneq ($(TARGET),openbsd)
    ifneq ($(TARGET),osx)
      LIBCRYPT_LDFLAGS = -lcrypt
    endif
  endif
endif

ifneq ($(USE_ZLIB:0=),)
  # Use ZLIB_INC and ZLIB_LIB to force path to zlib.h and libz.{a,so} if needed.
  ZLIB_CFLAGS      = $(if $(ZLIB_INC),-I$(ZLIB_INC))
  ZLIB_LDFLAGS     = $(if $(ZLIB_LIB),-L$(ZLIB_LIB)) -lz
endif

ifneq ($(USE_SLZ:0=),)
  OPTIONS_OBJS   += src/slz.o
endif

ifneq ($(USE_POLL:0=),)
  OPTIONS_OBJS   += src/ev_poll.o
endif

ifneq ($(USE_EPOLL:0=),)
  OPTIONS_OBJS   += src/ev_epoll.o
endif

ifneq ($(USE_KQUEUE:0=),)
  OPTIONS_OBJS   += src/ev_kqueue.o
endif

ifneq ($(USE_EVPORTS:0=),)
  OPTIONS_OBJS   += src/ev_evports.o
endif

ifneq ($(USE_RT:0=),)
  RT_LDFLAGS = -lrt
endif

ifneq ($(USE_THREAD:0=),)
  THREAD_LDFLAGS = -pthread
endif

ifneq ($(USE_BACKTRACE:0=),)
  BACKTRACE_LDFLAGS = -Wl,$(if $(EXPORT_SYMBOL),$(EXPORT_SYMBOL),--export-dynamic)
endif

ifneq ($(USE_CPU_AFFINITY:0=),)
  OPTIONS_OBJS   += src/cpuset.o
endif

# OpenSSL is packaged in various forms and with various dependencies.
# In general -lssl is enough, but on some platforms, -lcrypto may be needed,
# reason why it's added by default. Some even need -lz, then you'll need to
# pass it in the "ADDLIB" variable if needed. If your SSL libraries are not
# in the usual path, use SSL_INC=/path/to/inc and SSL_LIB=/path/to/lib.

# This is for the WolfSSL variant of the OpenSSL API. Setting it implies
# OPENSSL so it's not necessary to set the latter.
ifneq ($(USE_OPENSSL_WOLFSSL:0=),)
  SSL_CFLAGS      := $(if $(SSL_INC),-I$(SSL_INC)/wolfssl -I$(SSL_INC))
  SSL_LDFLAGS     := $(if $(SSL_LIB),-L$(SSL_LIB)) -lwolfssl
  # always automatically set USE_OPENSSL
  USE_OPENSSL     := $(if $(USE_OPENSSL:0=),$(USE_OPENSSL:0=),implicit)
endif

# This is for the AWS-LC variant of the OpenSSL API. Setting it implies
# OPENSSL so it's not necessary to set the latter.
ifneq ($(USE_OPENSSL_AWSLC:0=),)
  # always automatically set USE_OPENSSL
  USE_OPENSSL     := $(if $(USE_OPENSSL:0=),$(USE_OPENSSL:0=),implicit)
endif

# This is for any variant of the OpenSSL API. By default it uses OpenSSL.
ifneq ($(USE_OPENSSL:0=),)
  # only preset these for the regular openssl
  ifeq ($(USE_OPENSSL_WOLFSSL:0=),)
    SSL_CFLAGS    := $(if $(SSL_INC),-I$(SSL_INC))
    SSL_LDFLAGS   := $(if $(SSL_LIB),-L$(SSL_LIB)) -lssl -lcrypto
  endif
  USE_SSL         := $(if $(USE_SSL:0=),$(USE_SSL:0=),implicit)
  OPTIONS_OBJS += src/ssl_sock.o src/ssl_ckch.o src/ssl_ocsp.o src/ssl_crtlist.o src/ssl_sample.o src/cfgparse-ssl.o src/ssl_gencert.o src/ssl_utils.o src/jwt.o src/ssl_clienthello.o
endif

ifneq ($(USE_ENGINE:0=),)
  # OpenSSL 3.0 emits loud deprecation warnings by default when building with
  # engine support, and this option is made to silence them. Better use it
  # only when absolutely necessary, until there's a viable alternative to the
  # engine API.
  ENGINE_CFLAGS   = -DOPENSSL_SUPPRESS_DEPRECATED
endif

ifneq ($(USE_QUIC:0=),)

OPTIONS_OBJS += src/mux_quic.o src/h3.o src/quic_rx.o src/quic_tx.o	\
                src/quic_conn.o src/quic_frame.o src/quic_sock.o	\
                src/quic_tls.o src/quic_ssl.o src/proto_quic.o		\
                src/quic_cli.o src/quic_trace.o src/quic_tp.o		\
                src/quic_cid.o src/quic_stream.o			\
                src/quic_retransmit.o src/quic_loss.o			\
                src/hq_interop.o src/quic_cc_cubic.o			\
                src/quic_cc_bbr.o src/quic_retry.o			\
                src/cfgparse-quic.o src/xprt_quic.o src/quic_token.o	\
                src/quic_ack.o src/qpack-dec.o src/quic_cc_newreno.o	\
                src/qmux_http.o src/qmux_trace.o src/quic_rules.o	\
                src/quic_cc_nocc.o src/quic_cc.o src/quic_pacing.o	\
                src/h3_stats.o src/quic_stats.o src/qpack-enc.o		\
                src/qpack-tbl.o src/quic_cc_drs.o src/quic_fctl.o	\
                src/cbuf.o
endif

ifneq ($(USE_QUIC_OPENSSL_COMPAT:0=),)
OPTIONS_OBJS += src/quic_openssl_compat.o
endif

ifneq ($(USE_LUA:0=),)
  check_lua_inc = $(shell if [ -d $(2)$(1) ]; then echo $(2)$(1); fi;)
  LUA_INC      := $(firstword $(foreach lib,lua5.4 lua54 lua5.3 lua53 lua,$(call check_lua_inc,$(lib),"/usr/include/")))

  check_lua_lib = $(shell echo "int main(){}" | $(CC) -o /dev/null -x c - $(2) -l$(1) 2>/dev/null && echo $(1))
  LUA_LD_FLAGS := -Wl,$(if $(EXPORT_SYMBOL),$(EXPORT_SYMBOL),--export-dynamic) $(if $(LUA_LIB),-L$(LUA_LIB))

  # Try to automatically detect the Lua library if not set
  ifeq ($(LUA_LIB_NAME),)
    LUA_LIB_NAME := $(firstword $(foreach lib,lua5.4 lua54 lua5.3 lua53 lua,$(call check_lua_lib,$(lib),$(LUA_LD_FLAGS))))
  endif

  # Lua lib name must be set now (forced/detected above)
  ifeq ($(LUA_LIB_NAME),)
    $(error unable to automatically detect the Lua library name, you can enforce its name with LUA_LIB_NAME=<name> (where <name> can be lua5.4, lua54, lua, ...))
  endif

  ifneq ($(HLUA_PREPEND_PATH),)
    LUA_CFLAGS      += -DHLUA_PREPEND_PATH=$(HLUA_PREPEND_PATH)
    BUILD_OPTIONS   += HLUA_PREPEND_PATH=$(HLUA_PREPEND_PATH)
  endif # HLUA_PREPEND_PATH

  ifneq ($(HLUA_PREPEND_CPATH),)
    LUA_CFLAGS      += -DHLUA_PREPEND_CPATH=$(HLUA_PREPEND_CPATH)
    BUILD_OPTIONS   += HLUA_PREPEND_CPATH=$(HLUA_PREPEND_CPATH)
  endif # HLUA_PREPEND_CPATH

  USE_MATH         = implicit
  LUA_CFLAGS      += $(if $(LUA_INC),-I$(LUA_INC))
  LUA_LDFLAGS      = $(LUA_LD_FLAGS) -l$(LUA_LIB_NAME)
  OPTIONS_OBJS    += src/hlua.o src/hlua_fcn.o
endif # USE_LUA

ifneq ($(USE_PROMEX:0=),)
  OPTIONS_OBJS    += addons/promex/service-prometheus.o
  PROMEX_CFLAGS    = -Iaddons/promex/include
endif

ifneq ($(USE_DEVICEATLAS:0=),)
  # Use DEVICEATLAS_SRC and possibly DEVICEATLAS_INC and DEVICEATLAS_LIB to force path
  # to DeviceAtlas headers and libraries if needed. In this context, DEVICEATLAS_NOCACHE
  # can be used to disable the cache support if needed (this also removes the necessity of having
  # a C++ toolchain installed).
  DEVICEATLAS_INC = $(DEVICEATLAS_SRC)
  DEVICEATLAS_LIB = $(DEVICEATLAS_SRC)
  include addons/deviceatlas/Makefile.inc
  OPTIONS_OBJS += addons/deviceatlas/da.o
endif

# Use 51DEGREES_SRC and possibly 51DEGREES_INC and 51DEGREES_LIB to force path
# to 51degrees v3/v4 headers and libraries if needed. Note that the SRC/INC/
# LIB/CFLAGS/LDFLAGS variables names all use 51DEGREES as the prefix,
# regardless of the version since they are mutually exclusive. The version
# (51DEGREES_VER) must be either 3 or 4, and defaults to 3 if not set.
51DEGREES_INC = $(51DEGREES_SRC)
51DEGREES_LIB = $(51DEGREES_SRC)
51DEGREES_VER = 3

ifneq ($(USE_51DEGREES:0=),)
  ifeq ($(51DEGREES_VER),4)  # v4 here
    _51DEGREES_SRC      = $(shell find $(51DEGREES_LIB) -maxdepth 2 -name '*.c')
    OPTIONS_OBJS       += $(_51DEGREES_SRC:%.c=%.o)
    51DEGREES_CFLAGS   += -DUSE_51DEGREES_V4
    ifeq ($(USE_THREAD:0=),)
      51DEGREES_CFLAGS += -DFIFTYONEDEGREES_NO_THREADING -DFIFTYONE_DEGREES_NO_THREADING
    endif
    USE_LIBATOMIC       = implicit
  endif # 51DEGREES_VER==4

  ifeq ($(51DEGREES_VER),3)  # v3 here
    OPTIONS_OBJS       += $(51DEGREES_LIB)/../cityhash/city.o
    OPTIONS_OBJS       += $(51DEGREES_LIB)/51Degrees.o
    ifeq ($(USE_THREAD:0=),)
      51DEGREES_CFLAGS += -DFIFTYONEDEGREES_NO_THREADING
    else
      OPTIONS_OBJS     += $(51DEGREES_LIB)/../threading.o
    endif
  else
    ifneq ($(51DEGREES_VER),4)
      $(error 51Degrees version (51DEGREES_VER) must be either 3 or 4)
    endif
  endif # 51DEGREES_VER==3

  OPTIONS_OBJS        += addons/51degrees/51d.o
  51DEGREES_CFLAGS    += $(if $(51DEGREES_INC),-I$(51DEGREES_INC))
  51DEGREES_LDFLAGS   += $(if $(51DEGREES_LIB),-L$(51DEGREES_LIB))
  USE_MATH             = implicit
endif # USE_51DEGREES

ifneq ($(USE_WURFL:0=),)
  # Use WURFL_SRC and possibly WURFL_INC and WURFL_LIB to force path
  # to WURFL headers and libraries if needed.
  WURFL_INC = $(WURFL_SRC)
  WURFL_LIB = $(WURFL_SRC)
  OPTIONS_OBJS    += addons/wurfl/wurfl.o
  WURFL_CFLAGS     = $(if $(WURFL_INC),-I$(WURFL_INC))
  ifneq ($(WURFL_DEBUG),)
    WURFL_CFLAGS  += -DWURFL_DEBUG
  endif
  ifneq ($(WURFL_HEADER_WITH_DETAILS),)
    WURFL_CFLAGS  += -DWURFL_HEADER_WITH_DETAILS
  endif
  WURFL_LDFLAGS    = $(if $(WURFL_LIB),-L$(WURFL_LIB)) -lwurfl
endif

ifneq ($(USE_PCRE:0=)$(USE_STATIC_PCRE:0=)$(USE_PCRE_JIT:0=),)
  ifneq ($(USE_PCRE2:0=)$(USE_STATIC_PCRE2:0=)$(USE_PCRE2_JIT:0=),)
    $(error cannot compile both PCRE and PCRE2 support)
  endif
  # PCREDIR is used to automatically construct the PCRE_INC and PCRE_LIB paths,
  # by appending /include and /lib respectively. If your system does not use the
  # same sub-directories, simply force these variables instead of PCREDIR. It is
  # automatically detected but can be forced if required (for cross-compiling).
  # Forcing PCREDIR to an empty string will let the compiler use the default
  # locations.

  # in case only USE_STATIC_PCRE/USE_PCRE_JIT were set
  USE_PCRE    := $(if $(USE_PCRE:0=),$(USE_PCRE:0=),implicit)
  PCRE_CONFIG := pcre-config
  PCREDIR     := $(shell $(PCRE_CONFIG) --prefix 2>/dev/null || echo /usr/local)
  ifneq ($(PCREDIR),)
    PCRE_INC := $(PCREDIR)/include
    PCRE_LIB := $(PCREDIR)/lib
  endif

  PCRE_CFLAGS := $(if $(PCRE_INC),-I$(PCRE_INC))
  ifeq ($(USE_STATIC_PCRE:0=),)
    PCRE_LDFLAGS := $(if $(PCRE_LIB),-L$(PCRE_LIB)) -lpcreposix -lpcre
  else
    PCRE_LDFLAGS := $(if $(PCRE_LIB),-L$(PCRE_LIB)) -Wl,-Bstatic -lpcreposix -lpcre -Wl,-Bdynamic
  endif
endif # USE_PCRE

ifneq ($(USE_PCRE2:0=)$(USE_STATIC_PCRE2:0=)$(USE_PCRE2_JIT:0=),)
  # in case only USE_STATIC_PCRE2/USE_PCRE2_JIT were set
  USE_PCRE2    := $(if $(USE_PCRE2:0=),$(USE_PCRE2:0=),implicit)
  PCRE2_CONFIG := pcre2-config
  PCRE2DIR     := $(shell $(PCRE2_CONFIG) --prefix 2>/dev/null || echo /usr/local)
  ifneq ($(PCRE2DIR),)
    PCRE2_INC := $(PCRE2DIR)/include
    PCRE2_LIB := $(PCRE2DIR)/lib

    ifeq ($(PCRE2_WIDTH),)
      PCRE2_WIDTH = 8
    endif

    ifneq ($(PCRE2_WIDTH),8)
      ifneq ($(PCRE2_WIDTH),16)
        ifneq ($(PCRE2_WIDTH),32)
          $(error PCRE2_WIDTH needs to be set to either 8,16 or 32)
        endif
      endif
    endif

    PCRE2_CFLAGS  := -DPCRE2_CODE_UNIT_WIDTH=$(PCRE2_WIDTH) $(if $(PCRE2_INC), -I$(PCRE2_INC))
    PCRE2_LDFLAGS := $(shell $(PCRE2_CONFIG) --libs$(PCRE2_WIDTH) 2>/dev/null || echo -L/usr/local/lib -lpcre2-$(PCRE2_WIDTH))

    ifeq ($(PCRE2_LDFLAGS),)
      $(error libpcre2-$(PCRE2_WIDTH) not found)
    else
      ifeq ($(PCRE2_WIDTH),8)
        PCRE2_LDFLAGS += -lpcre2-posix
      endif
    endif

    ifneq ($(USE_STATIC_PCRE2:0=),)
      PCRE2_LDFLAGS := $(if $(PCRE2_LIB),-L$(PCRE2_LIB)) -Wl,-Bstatic -L$(PCRE2_LIB) $(PCRE2_LDFLAGS) -Wl,-Bdynamic
    else
      PCRE2_LDFLAGS := $(if $(PCRE2_LIB),-L$(PCRE2_LIB)) -L$(PCRE2_LIB) $(PCRE2_LDFLAGS)
    endif
  endif # PCRE2DIR
endif # USE_PCRE2

ifneq ($(USE_NS:0=),)
  OPTIONS_OBJS  += src/namespace.o
endif

ifneq ($(USE_LINUX_CAP:0=),)
  OPTIONS_OBJS   += src/linuxcap.o
endif

ifneq ($(USE_OT:0=),)
  include addons/ot/Makefile
endif

# better keep this one close to the end, as several libs above may need it
ifneq ($(USE_DL:0=),)
  DL_LDFLAGS = -ldl
endif

ifneq ($(USE_MATH:0=),)
  MATH_LDFLAGS = -lm
endif

ifneq ($(USE_LIBATOMIC:0=),)
  LIBATOMIC_LDFLAGS = -latomic
endif

#### End of the USE_* options handling, any such option that would be added
#### below could be silently ignored.

# appends all foo_{C,LD}FLAGS to OPTIONS_{C,LD}FLAGS
$(collect_opts_flags)

#### Global compile options
VERBOSE_CFLAGS = $(OPT_CFLAGS) $(ARCH_FLAGS) $(CPU_CFLAGS) $(STD_CFLAGS) $(TARGET_CFLAGS) $(CFLAGS) $(DEFINE)
COPTS  = -Iinclude

COPTS += $(OPT_CFLAGS) $(ARCH_FLAGS) $(CPU_CFLAGS) $(STD_CFLAGS) $(WARN_CFLAGS) $(NOWARN_CFLAGS) $(ERROR_CFLAGS) $(TARGET_CFLAGS) $(DEFINE) $(SILENT_DEFINE)
COPTS += $(DEBUG) $(OPTIONS_CFLAGS) $(CFLAGS) $(ADDINC)

ifneq ($(VERSION)$(SUBVERS)$(EXTRAVERSION),)
  COPTS += -DCONFIG_HAPROXY_VERSION=\"$(VERSION)$(SUBVERS)$(EXTRAVERSION)\"
endif

ifneq ($(VERDATE),)
  COPTS += -DCONFIG_HAPROXY_DATE=\"$(VERDATE)\"
endif

ifneq ($(TRACE),)
  # if tracing is enabled, we want it to be as fast as possible
  TRACE_COPTS := $(filter-out -O0 -O1 -O2 -pg -finstrument-functions,$(COPTS)) -O3 -fomit-frame-pointer
  COPTS += -finstrument-functions
endif

#### Global link options
# These options are added at the end of the "ld" command line. Use LDFLAGS to
# add options at the beginning of the "ld" command line if needed.
LDOPTS = $(TARGET_LDFLAGS) $(OPTIONS_LDFLAGS) $(ADDLIB)

ifeq ($(TARGET),)
all:
	@echo "Building HAProxy without specifying a TARGET is not supported."
	@echo
	@echo "Usage:"
	@echo
	@echo "    $ make help                       # To print a full explanation."
	@echo "    $ make TARGET=xxx USE_<feature>=1 # To build HAProxy."
	@echo
	@echo "The most commonly used targets are:"
	@echo
	@echo "    linux-glibc    - Modern Linux with glibc"
	@echo "    linux-musl     - Modern Linux with musl"
	@echo "    freebsd        - FreeBSD"
	@echo "    openbsd        - OpenBSD"
	@echo "    netbsd         - NetBSD"
	@echo "    osx            - macOS"
	@echo "    solaris        - Solaris"
	@echo
	@echo "Choose the target which matches your OS the most in order to"
	@echo "gain the maximum performance out of it."
	@echo
	@echo "Common features you might want to include in your build are:"
	@echo
	@echo "    USE_OPENSSL=1 - Support for TLS encrypted connections"
	@echo "    USE_ZLIB=1    - Support for HTTP response compression"
	@echo "    USE_PCRE=1    - Support for PCRE regular expressions"
	@echo "    USE_LUA=1     - Support for dynamic processing using Lua"
	@echo
	@echo "Use 'make help' to print a full explanation of supported targets"
	@echo "and features, and 'make ... opts' to show the variables in use"
	@echo "for a given set of build options, in a reusable form."
	@echo
	@exit 1
else
ifneq ($(filter $(TARGET), linux linux22 linux24 linux24e linux26 linux2628),)
all:
	@echo
	@echo "Target '$(TARGET)' was removed from HAProxy 2.0 due to being irrelevant and"
	@echo "often wrong. Please use 'linux-glibc' instead or define your custom target"
	@echo "by checking available options using 'make help TARGET=<your-target>'."
	@echo
	@exit 1
else
all: dev/flags/flags haproxy $(EXTRA)
endif # obsolete targets
endif # TARGET

OBJS =

ifneq ($(EXTRA_OBJS),)
  OBJS += $(EXTRA_OBJS)
endif

OBJS += src/mux_h2.o src/mux_h1.o src/mux_fcgi.o src/log.o		\
        src/server.o src/stream.o src/tcpcheck.o src/http_ana.o		\
        src/stick_table.o src/tools.o src/mux_spop.o src/sample.o	\
        src/activity.o src/cfgparse.o src/peers.o src/cli.o		\
        src/backend.o src/connection.o src/resolvers.o src/proxy.o	\
        src/cache.o src/stconn.o src/http_htx.o src/debug.o		\
        src/check.o src/stats-html.o src/haproxy.o src/listener.o	\
        src/applet.o src/pattern.o src/cfgparse-listen.o		\
        src/flt_spoe.o src/cebuis_tree.o src/http_ext.o			\
        src/http_act.o src/http_fetch.o src/cebus_tree.o		\
        src/cebuib_tree.o src/http_client.o src/dns.o			\
        src/cebub_tree.o src/vars.o src/event_hdl.o src/tcp_rules.o	\
        src/trace.o src/stats-proxy.o src/pool.o src/stats.o		\
        src/cfgparse-global.o src/filters.o src/mux_pt.o		\
        src/flt_http_comp.o src/sock.o src/h1.o src/sink.o		\
        src/cebua_tree.o src/session.o src/payload.o src/htx.o		\
        src/cebul_tree.o src/cebu32_tree.o src/cebu64_tree.o		\
        src/server_state.o src/proto_rhttp.o src/flt_trace.o src/fd.o	\
        src/task.o src/map.o src/fcgi-app.o src/h2.o src/mworker.o	\
        src/tcp_sample.o src/mjson.o src/h1_htx.o src/tcp_act.o		\
        src/ring.o src/flt_bwlim.o src/acl.o src/thread.o src/queue.o	\
        src/http_rules.o src/http.o src/channel.o src/proto_tcp.o	\
        src/mqtt.o src/lb_chash.o src/extcheck.o src/dns_ring.o		\
        src/errors.o src/ncbuf.o src/compression.o src/http_conv.o	\
        src/frontend.o src/stats-json.o src/proto_sockpair.o		\
        src/raw_sock.o src/action.o src/stats-file.o src/buf.o		\
        src/xprt_handshake.o src/proto_uxst.o src/lb_fwrr.o		\
        src/uri_normalizer.o src/mailers.o src/protocol.o		\
        src/cfgcond.o src/proto_udp.o src/lb_fwlc.o src/ebmbtree.o	\
        src/proto_uxdg.o src/cfgdiag.o src/sock_unix.o src/sha1.o	\
        src/lb_fas.o src/clock.o src/sock_inet.o src/ev_select.o	\
        src/lb_map.o src/shctx.o src/mworker-prog.o src/hpack-dec.o	\
        src/arg.o src/signal.o src/fix.o src/dynbuf.o src/guid.o	\
        src/cfgparse-tcp.o src/lb_ss.o src/chunk.o			\
        src/cfgparse-unix.o src/regex.o src/fcgi.o src/uri_auth.o	\
        src/eb64tree.o src/eb32tree.o src/eb32sctree.o src/lru.o	\
        src/limits.o src/ebimtree.o src/wdt.o src/hpack-tbl.o		\
        src/ebistree.o src/base64.o src/auth.o src/time.o		\
        src/ebsttree.o src/freq_ctr.o src/systemd.o src/init.o		\
        src/http_acl.o src/dict.o src/dgram.o src/pipe.o		\
        src/hpack-huff.o src/hpack-enc.o src/ebtree.o src/hash.o	\
        src/version.o

ifneq ($(TRACE),)
  OBJS += src/calltrace.o
endif

# Used only for forced dependency checking. May be cleared during development.
INCLUDES = $(wildcard include/*/*.h)
DEP = $(INCLUDES) .build_opts

help:
	@sed -ne "/^[^#]*$$/q;s/^# \{0,1\}\(.*\)/\1/;p" Makefile
	@echo; \
	   if [ -n "$(TARGET)" ]; then \
	     if [ -n "$(set_target_defaults)" ]; then \
	        echo "Current TARGET: $(TARGET)"; \
	     else \
	        echo "Current TARGET: $(TARGET) (custom target)"; \
	     fi; \
	     echo;echo "Enabled features for TARGET '$(TARGET)' (disable with 'USE_xxx=') :"; \
	     set -- $(enabled_opts); echo "  $$*" | (fmt || cat) 2>/dev/null; \
	     echo;echo "Disabled features for TARGET '$(TARGET)' (enable with 'USE_xxx=1') :"; \
	     set -- $(disabled_opts); echo "  $$*" | (fmt || cat) 2>/dev/null; \
	   else \
	     echo "TARGET not set, you should pass 'TARGET=xxx' to set one among :";\
	     echo "  linux-glibc, linux-glibc-legacy, solaris, freebsd, dragonfly, netbsd,"; \
	     echo "  osx, openbsd, aix51, aix52, aix72-gcc, cygwin, haiku, generic,"; \
	     echo "  custom"; \
	   fi

# Used only to force a rebuild if some build options change, but we don't do
# it for certain build targets which take no build options nor when the
# TARGET variable is not set since we're not building, by definition.
IGNORE_OPTS=help install install-man install-doc install-bin \
	uninstall clean tags cscope tar git-tar version update-version \
	opts reg-tests reg-tests-help admin/halog/halog dev/flags/flags \
	dev/haring/haring dev/ncpu/ncpu dev/poll/poll dev/tcploop/tcploop \
	dev/term_events/term_events

ifneq ($(TARGET),)
ifeq ($(filter $(firstword $(MAKECMDGOALS)),$(IGNORE_OPTS)),)
build_opts = $(shell rm -f .build_opts.new; echo \'$(TARGET) $(BUILD_OPTIONS) $(VERBOSE_CFLAGS) $(WARN_CFLAGS) $(NOWARN_CFLAGS) $(DEBUG)\' > .build_opts.new; if cmp -s .build_opts .build_opts.new; then rm -f .build_opts.new; else mv -f .build_opts.new .build_opts; fi)
.build_opts: $(build_opts)
else
.build_opts:
endif # ignore_opts
else
.build_opts:
endif # non-empty target

haproxy: $(OPTIONS_OBJS) $(OBJS)
	$(cmd_LD) $(ARCH_FLAGS) $(LDFLAGS) -o $@ $^ $(LDOPTS)

objsize: haproxy
	$(Q)objdump -t $^|grep ' g '|grep -F '.text'|awk '{print $$5 FS $$6}'|sort

%.o:	%.c $(DEP)
	$(cmd_CC) $(COPTS) -c -o $@ $<

admin/halog/halog: admin/halog/halog.o admin/halog/fgets2.o src/ebtree.o src/eb32tree.o src/eb64tree.o src/ebmbtree.o src/ebsttree.o src/ebistree.o src/ebimtree.o
	$(cmd_LD) $(ARCH_FLAGS) $(LDFLAGS) -o $@ $^ $(LDOPTS)

admin/dyncookie/dyncookie: admin/dyncookie/dyncookie.o
	$(cmd_LD) $(ARCH_FLAGS) $(LDFLAGS) -o $@ $^ $(LDOPTS)

dev/flags/flags: dev/flags/flags.o
	$(cmd_LD) $(ARCH_FLAGS) $(LDFLAGS) -o $@ $^ $(LDOPTS)

dev/haring/haring: dev/haring/haring.o
	$(cmd_LD) $(ARCH_FLAGS) $(LDFLAGS) -o $@ $^ $(LDOPTS)

dev/hpack/%: dev/hpack/%.o
	$(cmd_LD) $(ARCH_FLAGS) $(LDFLAGS) -o $@ $^ $(LDOPTS)

dev/ncpu/ncpu:
	$(cmd_MAKE) -C dev/ncpu ncpu V='$(V)'

dev/poll/poll:
	$(cmd_MAKE) -C dev/poll poll CC='$(CC)' OPTIMIZE='$(COPTS)' V='$(V)'

dev/qpack/decode: dev/qpack/decode.o
	$(cmd_LD) $(ARCH_FLAGS) $(LDFLAGS) -o $@ $^ $(LDOPTS)

dev/tcploop/tcploop:
	$(cmd_MAKE) -C dev/tcploop tcploop CC='$(CC)' OPTIMIZE='$(COPTS)' V='$(V)'

dev/udp/udp-perturb: dev/udp/udp-perturb.o
	$(cmd_LD) $(ARCH_FLAGS) $(LDFLAGS) -o $@ $^ $(LDOPTS)

dev/term_events/term_events: dev/term_events/term_events.o
	$(cmd_LD) $(ARCH_FLAGS) $(LDFLAGS) -o $@ $^ $(LDOPTS)

# rebuild it every time
.PHONY: src/version.c dev/ncpu/ncpu dev/poll/poll dev/tcploop/tcploop

src/calltrace.o: src/calltrace.c $(DEP)
	$(cmd_CC) $(TRACE_COPTS) -c -o $@ $<

src/version.o:	src/version.c $(DEP)
	$(cmd_CC) $(COPTS) \
	      -DBUILD_TARGET='"$(strip $(TARGET))"' \
	      -DBUILD_CC='"$(strip $(CC))"' \
	      -DBUILD_CFLAGS='"$(strip $(VERBOSE_CFLAGS))"' \
	      -DBUILD_OPTIONS='"$(strip $(BUILD_OPTIONS))"' \
	      -DBUILD_DEBUG='"$(strip $(DEBUG))"' \
	      -DBUILD_FEATURES='"$(strip $(build_features))"' \
	       -c -o $@ $<

install-man:
	$(Q)$(INSTALL) -d "$(DESTDIR)$(MANDIR)"/man1
	$(Q)$(INSTALL) -m 644 doc/haproxy.1 "$(DESTDIR)$(MANDIR)"/man1

EXCLUDE_DOCUMENTATION = lgpl gpl coding-style
DOCUMENTATION = $(filter-out $(EXCLUDE_DOCUMENTATION),$(patsubst doc/%.txt,%,$(wildcard doc/*.txt)))

install-doc:
	$(Q)$(INSTALL) -d "$(DESTDIR)$(DOCDIR)"
	$(Q)for x in $(DOCUMENTATION); do \
		$(INSTALL) -m 644 doc/$$x.txt "$(DESTDIR)$(DOCDIR)" ; \
	done

install-bin:
	$(Q)for i in haproxy $(EXTRA); do \
		if ! [ -e "$$i" ]; then \
			echo "Please run 'make' before 'make install'."; \
			exit 1; \
		fi; \
	done
	$(Q)$(INSTALL) -d "$(DESTDIR)$(SBINDIR)"
	$(Q)$(INSTALL) haproxy $(EXTRA) "$(DESTDIR)$(SBINDIR)"

install: install-bin install-man install-doc

uninstall:
	$(Q)rm -f "$(DESTDIR)$(MANDIR)"/man1/haproxy.1
	$(Q)for x in $(DOCUMENTATION); do \
		rm -f "$(DESTDIR)$(DOCDIR)"/$$x.txt ; \
	done
	$(Q)-rmdir "$(DESTDIR)$(DOCDIR)"
	$(Q)rm -f "$(DESTDIR)$(SBINDIR)"/haproxy

clean:
	$(Q)rm -f *.[oas] src/*.[oas] haproxy test .build_opts .build_opts.new
	$(Q)for dir in . src dev/* admin/* addons/* include/* doc; do rm -f $$dir/*~ $$dir/*.rej $$dir/core; done
	$(Q)rm -f haproxy-$(VERSION).tar.gz haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION).tar.gz
	$(Q)rm -f haproxy-$(VERSION) haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION) nohup.out gmon.out
	$(Q)rm -f addons/promex/*.[oas]
	$(Q)rm -f addons/51degrees/*.[oas] addons/51degrees/dummy/*.[oas] addons/51degrees/dummy/*/*.[oas]
	$(Q)rm -f addons/deviceatlas/*.[oas] addons/deviceatlas/dummy/*.[oas] addons/deviceatlas/dummy/*.o
	$(Q)rm -f addons/deviceatlas/dummy/Os/*.o
	$(Q)rm -f addons/ot/src/*.[oas]
	$(Q)rm -f addons/wurfl/*.[oas] addons/wurfl/dummy/*.[oas]
	$(Q)rm -f admin/*/*.[oas] admin/*/*/*.[oas]
	$(Q)rm -f dev/*/*.[oas]
	$(Q)rm -f dev/flags/flags

distclean: clean
	$(Q)rm -f admin/iprange/iprange admin/iprange/ip6range admin/halog/halog
	$(Q)rm -f admin/dyncookie/dyncookie
	$(Q)rm -f dev/haring/haring dev/ncpu/ncpu{,.so} dev/poll/poll dev/tcploop/tcploop
	$(Q)rm -f dev/hpack/decode dev/hpack/gen-enc dev/hpack/gen-rht
	$(Q)rm -f dev/qpack/decode

tags:
	$(Q)find src include \( -name '*.c' -o -name '*.h' \) -print0 | \
	   xargs -0 etags --declarations --members

cscope:
	$(Q)find src include -name "*.[ch]" -print | cscope -q -b -i -

tar:	clean
	$(Q)ln -s . haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION)
	$(Q)tar --exclude=haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION)/.git \
	    --exclude=haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION)/haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION) \
	    --exclude=haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION)/haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION).tar.gz \
	    -cf - haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION)/* | gzip -c9 >haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION).tar.gz
	$(Q)echo haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION).tar.gz
	$(Q)rm -f haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION)

git-tar:
	$(Q)git archive --format=tar --prefix="haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION)/" HEAD | gzip -9 > haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION).tar.gz
	$(Q)echo haproxy-$(VERSION)$(SUBVERS)$(EXTRAVERSION).tar.gz

version:
	@echo "VERSION: $(VERSION)"
	@echo "SUBVERS: $(SUBVERS)"
	@echo "VERDATE: $(VERDATE)"

# never use this one if you don't know what it is used for.
update-version:
	@echo "Ready to update the following versions :"
	@echo "VERSION: $(VERSION)"
	@echo "SUBVERS: $(SUBVERS)"
	@echo "VERDATE: $(VERDATE)"
	@echo "Press [ENTER] to continue or Ctrl-C to abort now.";read
	echo "$(VERSION)" > VERSION
	echo "$(SUBVERS)" > SUBVERS
	echo "$(VERDATE)" > VERDATE

# just display the build options. The "USE_*" options and their respective
# settings are also listed if they're explicitly set on the command line, or if
# they are not empty. Implicit "USE_*" are not listed.
opts:
	@echo 'Using the following variables (copy-pastable as make arguments):'
	@echo '  TARGET="$(strip $(TARGET))" '\\
	@echo '  ARCH="$(strip $(ARCH))" '\\
	@echo '  CC="$(strip $(CC))" '\\
	@echo '  OPT_CFLAGS="$(strip $(OPT_CFLAGS))" '\\
	@echo '  ARCH_FLAGS="$(strip $(ARCH_FLAGS))" '\\
	@echo '  CPU_CFLAGS="$(strip $(CPU_CFLAGS))" '\\
	@echo '  STD_CFLAGS="$(strip $(STD_CFLAGS))" '\\
	@echo '  WARN_CFLAGS="$(strip $(WARN_CFLAGS))" '\\
	@echo '  NOWARN_CFLAGS="$(strip $(NOWARN_CFLAGS))" '\\
	@echo '  ERROR_CFLAGS="$(strip $(ERROR_CFLAGS))" '\\
	@echo '  CFLAGS="$(strip $(CFLAGS))" '\\
	@$(foreach opt,$(enabled_opts),\
		$(if $(subst command line,,$(origin USE_$(opt))),,\
			echo '  USE_$(opt)=$(USE_$(opt:0=)) '\\;) \
		$(if $(subst command line,,$(origin $(opt)_CFLAGS)),\
			$(if $($(opt)_CFLAGS),echo '  $(opt)_CFLAGS="$($(opt)_CFLAGS)" '\\;),\
			echo '  $(opt)_CFLAGS="$($(opt)_CFLAGS)" '\\;) \
		$(if $(subst command line,,$(origin $(opt)_LDFLAGS)),\
			$(if $($(opt)_LDFLAGS),echo '  $(opt)_LDFLAGS="$($(opt)_LDFLAGS)" '\\;),\
			echo '  $(opt)_LDFLAGS="$($(opt)_LDFLAGS)" '\\;))
	@echo '  LDFLAGS="$(strip $(LDFLAGS))"'
	@echo
	@echo 'COPTS="$(strip $(COPTS))"'
	@echo 'LDOPTS="$(strip $(LDOPTS))"'
	@echo 'OPTIONS_OBJS="$(strip $(OPTIONS_OBJS))"'
	@echo 'OBJS="$(strip $(OBJS))"'

ifeq (reg-tests, $(firstword $(MAKECMDGOALS)))
  REGTEST_ARGS := $(wordlist 2, $(words $(MAKECMDGOALS)), $(MAKECMDGOALS))
  $(eval $(REGTEST_ARGS):;@true)
endif

# Target to run the regression testing script files.
reg-tests:
	$(Q)$(REG_TEST_SCRIPT) --type "$(REGTESTS_TYPES)" $(REGTEST_ARGS) $(REG_TEST_FILES)
.PHONY: $(REGTEST_ARGS)

reg-tests-help:
	@echo
	@echo "To launch the reg tests for haproxy, first export to your environment "
	@echo "VTEST_PROGRAM variable to point to your vtest program:"
	@echo "    $$ export VTEST_PROGRAM=/opt/local/bin/vtest"
	@echo "or"
	@echo "    $$ setenv VTEST_PROGRAM /opt/local/bin/vtest"
	@echo
	@echo "The same thing may be done to set your haproxy program with HAPROXY_PROGRAM "
	@echo "but with ./haproxy as default value."
	@echo
	@echo "To run all the tests:"
	@echo "    $$ make reg-tests"
	@echo
	@echo "You can also set the programs to be used on the command line:"
	@echo "    $$ VTEST_PROGRAM=<...> HAPROXY_PROGRAM=<...> make reg-tests"
	@echo
	@echo "To run tests with specific types:"
	@echo "    $$ REGTESTS_TYPES=slow,default make reg-tests"
	@echo
	@echo "with 'default,bug,devel,slow' as default value for REGTESTS_TYPES variable."
	@echo
	@echo "About the reg test types:"
	@echo "    any         : all the tests without distinction (this is the default"
	@echo "                  value of REGTESTS_TYPES."
	@echo "    default     : dedicated to pure haproxy compliance tests."
	@echo "    slow        : scripts which take non negligible time to run."
	@echo "    bug         : scripts in relation with bugs they help to reproduce."
	@echo "    broken      : scripts triggering known broken behaviors for which"
	@echo "                  there is still no fix."
	@echo "    experimental: for scripts which are experimental, typically used to"
	@echo "                  develop new scripts."
	@echo
	@echo "Note that 'reg-tests' target run '"$(REG_TEST_SCRIPT)"' script"
	@echo "(see --help option of this script for more information)."

.PHONY: reg-tests reg-tests-help

# "make range" iteratively builds using "make all" and the exact same build
# options for all commits within RANGE. RANGE may be either a git range
# such as ref1..ref2 or a single commit, in which case all commits from
# the master branch to this one will be tested.

range:
	$(Q)[ -d .git/. ] || { echo "## Fatal: \"make $@\" may only be used inside a Git repository."; exit 1; }

	$(Q)if git diff-index --name-only HEAD 2>/dev/null | grep -q ^; then \
		echo "Fatal: \"make $@\" requires a clean working tree."; exit 1; fi

	$(Q)[ -n "$(RANGE)" ] || { echo "## Fatal: \"make $@\" requires a git commit range in RANGE."; exit 1; }
	$(Q)[ -n "$(TARGET)" ] || { echo "## Fatal: \"make $@\" needs the same variables as \"all\" (TARGET etc)."; exit 1; }

	$(Q) (  die() { echo;echo "## Stopped in error at index [ $$index/$$count ] commit $$commit";\
			echo "Previous branch was $$BRANCH"; exit $$1; }; \
		BRANCH=$$(git branch --show-current HEAD 2>/dev/null); \
		[ -n "$$BRANCH" ] || { echo "Fatal: \"make $@\" may only be used inside a checked out branch."; exit 1; }; \
		[ -z "$${RANGE##*..*}" ] || RANGE="master..$${RANGE}"; \
		COMMITS=$$(git rev-list --abbrev-commit --reverse "$${RANGE}"); \
		index=1; count=$$(echo $$COMMITS | wc -w); \
		[ "$${count}" -gt 0 ] || { echo "## Fatal: no commit(s) found in range $${RANGE}."; exit 1; }; \
		echo "Found $${count} commit(s) in range $${RANGE}." ; \
		echo "Current branch is $$BRANCH"; \
		echo "Starting to building now..."; \
		for commit in $$COMMITS; do \
			echo "[ $$index/$$count ]   $$commit #############################"; \
			git checkout -q $$commit || die 1; \
			$(MAKE) all || die 1; \
			index=$$((index + 1)); \
		done; \
		echo;echo "Done! $${count} commit(s) built successfully for RANGE $${RANGE}" ; \
		git checkout -q "$$BRANCH"; \
	)
