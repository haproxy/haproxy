# This GNU Makefile supports different OS and CPU combinations.
#
# You should use it this way :
#   [g]make TARGET=os [ARCH=arch] [CPU=cpu] USE_xxx=1 ...
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
#   USE_EPOLL            : enable epoll() on Linux 2.6. Automatic.
#   USE_KQUEUE           : enable kqueue() on BSD. Automatic.
#   USE_EVPORTS          : enable event ports on SunOS systems. Automatic.
#   USE_MY_EPOLL         : redefine epoll_* syscalls. Automatic.
#   USE_MY_SPLICE        : redefine the splice syscall if build fails without.
#   USE_NETFILTER        : enable netfilter on Linux. Automatic.
#   USE_PCRE             : enable use of libpcre for regex. Recommended.
#   USE_PCRE_JIT         : enable JIT for faster regex on libpcre >= 8.32
#   USE_PCRE2            : enable use of libpcre2 for regex.
#   USE_PCRE2_JIT        : enable JIT for faster regex on libpcre2
#   USE_POLL             : enable poll(). Automatic.
#   USE_PRIVATE_CACHE    : disable shared memory cache of ssl sessions.
#   USE_THREAD           : enable threads support.
#   USE_PTHREAD_PSHARED  : enable pthread process shared mutex on sslcache.
#   USE_REGPARM          : enable regparm optimization. Recommended on x86.
#   USE_STATIC_PCRE      : enable static libpcre. Recommended.
#   USE_STATIC_PCRE2     : enable static libpcre2.
#   USE_TPROXY           : enable transparent proxy. Automatic.
#   USE_LINUX_TPROXY     : enable full transparent proxy. Automatic.
#   USE_LINUX_SPLICE     : enable kernel 2.6 splicing. Automatic.
#   USE_LIBCRYPT         : enable crypted passwords using -lcrypt
#   USE_CRYPT_H          : set it if your system requires including crypt.h
#   USE_VSYSCALL         : enable vsyscall on Linux x86, bypassing libc
#   USE_GETADDRINFO      : use getaddrinfo() to resolve IPv6 host names.
#   USE_OPENSSL          : enable use of OpenSSL. Recommended, but see below.
#   USE_LUA              : enable Lua support.
#   USE_FUTEX            : enable use of futex on kernel 2.6. Automatic.
#   USE_ACCEPT4          : enable use of accept4() on linux. Automatic.
#   USE_MY_ACCEPT4       : use own implemention of accept4() if glibc < 2.10.
#   USE_PRCTL            : enable use of prctl(). Automatic.
#   USE_ZLIB             : enable zlib library support.
#   USE_SLZ              : enable slz library instead of zlib (pick at most one).
#   USE_CPU_AFFINITY     : enable pinning processes to CPU on Linux. Automatic.
#   USE_TFO              : enable TCP fast open. Supported on Linux >= 3.7.
#   USE_NS               : enable network namespace support. Supported on Linux >= 2.6.24.
#   USE_DL               : enable it if your system requires -ldl. Automatic on Linux.
#   USE_RT               : enable it if your system requires -lrt. Automatic on Linux.
#   USE_DEVICEATLAS      : enable DeviceAtlas api.
#   USE_51DEGREES        : enable third party device detection library from 51Degrees
#   USE_WURFL            : enable WURFL detection library from Scientiamobile
#   USE_SYSTEMD          : enable sd_notify() support.
#   USE_OBSOLETE_LINKER  : use when the linker fails to emit __start_init/__stop_init
#   USE_THREAD_DUMP      : use the more advanced thread state dump system. Automatic.
#
# Options can be forced by specifying "USE_xxx=1" or can be disabled by using
# "USE_xxx=" (empty string). The list of enabled and disabled options for a
# given TARGET is enumerated at the end of "make help".
#
# Variables useful for packagers :
#   CC is set to "gcc" by default and is used for compilation only.
#   LD is set to "gcc" by default and is used for linking only.
#   ARCH may be useful to force build of 32-bit binary on 64-bit systems
#   CFLAGS is automatically set for the specified CPU and may be overridden.
#   LDFLAGS is automatically set to -g and may be overridden.
#   DEP may be cleared to ignore changes to include files during development
#   SMALL_OPTS may be used to specify some options to shrink memory usage.
#   DEBUG may be used to set some internal debugging options.
#   ERR may be set to non-empty to pass -Werror to the compiler
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
#   PREFIX  is set to "/usr/local" by default and is used for installation only.
#   SBINDIR is set to "$(PREFIX)/sbin" by default and is used for installation
#           only.
#   MANDIR  is set to "$(PREFIX)/share/man" by default and is used for
#           installation only.
#   DOCDIR  is set to "$(PREFIX)/doc/haproxy" by default and is used for
#           installation only.
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
#                                        priority : lua5.3, lua53, lua).
#   IGNOREGIT      : ignore GIT commit versions if set.
#   VERSION        : force haproxy version reporting.
#   SUBVERS        : add a sub-version (eg: platform, model, ...).
#   VERDATE        : force haproxy's release date.
#   VTEST_PROGRAM  : location of the vtest program to run reg-tests.

# verbosity: pass V=1 for verbose shell invocation
V = 0
Q = @
ifeq ($V,1)
Q=
endif

# Function used to detect support of a given option by the compiler.
# Usage: CFLAGS += $(call cc-opt,option). Eg: $(call cc-opt,-fwrapv)
# Note: ensure the referencing variable is assigned using ":=" and not "=" to
#       call it only once.
cc-opt = $(shell set -e; if $(CC) $(1) -E -xc - -o /dev/null </dev/null >&0 2>&0; then echo "$(1)"; fi;)

# same but emits $2 if $1 is not supported
cc-opt-alt = $(shell set -e; if $(CC) $(1) -E -xc - -o /dev/null </dev/null >&0 2>&0; then echo "$(1)"; else echo "$(2)"; fi;)

# Disable a warning when supported by the compiler. Don't put spaces around the
# warning! And don't use cc-opt which doesn't always report an error until
# another one is also returned.
# Usage: CFLAGS += $(call cc-nowarn,warning). Eg: $(call cc-opt,format-truncation)
cc-nowarn = $(shell set -e; if $(CC) -W$(1) -E -xc - -o /dev/null </dev/null >&0 2>&0; then echo "-Wno-$(1)"; fi;)

#### Installation options.
DESTDIR =
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
DOCDIR = $(PREFIX)/doc/haproxy

#### TARGET system
# Use TARGET=<target_name> to optimize for a specifc target OS among the
# following list (use the default "generic" if uncertain) :
#    linux-glibc, linux-glibc-legacy, solaris, freebsd, openbsd, netbsd,
#    cygwin, haiku, aix51, aix52, osx, generic, custom
TARGET =

#### TARGET CPU
# Use CPU=<cpu_name> to optimize for a particular CPU, among the following
# list :
#    generic, native, i586, i686, ultrasparc, custom
CPU = generic

#### Architecture, used when not building for native architecture
# Use ARCH=<arch_name> to force build for a specific architecture. Known
# architectures will lead to "-m32" or "-m64" being added to CFLAGS and
# LDFLAGS. This can be required to build 32-bit binaries on 64-bit targets.
# Currently, only 32, 64, x86_64, i386, i486, i586 and i686 are understood.
ARCH =

#### Toolchain options.
# GCC is normally used both for compiling and linking.
CC = gcc
LD = $(CC)

#### Debug flags (typically "-g").
# Those flags only feed CFLAGS so it is not mandatory to use this form.
DEBUG_CFLAGS = -g

#### Add -Werror when set to non-empty
ERR =

#### May be used to force running a specific set of reg-tests
REG_TEST_FILES =
REG_TEST_SCRIPT=./scripts/run-regtests.sh

#### Compiler-specific flags that may be used to disable some negative over-
# optimization or to silence some warnings. -fno-strict-aliasing is needed with
# gcc >= 4.4.
# We rely on signed integer wraparound on overflow, however clang think it
# can do whatever it wants since it's an undefined behavior, so use -fwrapv
# to be sure we get the intended behavior.
SPEC_CFLAGS := -fno-strict-aliasing -Wdeclaration-after-statement
SPEC_CFLAGS += $(call cc-opt-alt,-fwrapv,$(call cc-opt,-fno-strict-overflow))
SPEC_CFLAGS += $(call cc-nowarn,address-of-packed-member)
SPEC_CFLAGS += $(call cc-nowarn,unused-label)
SPEC_CFLAGS += $(call cc-nowarn,sign-compare)
SPEC_CFLAGS += $(call cc-nowarn,unused-parameter)
SPEC_CFLAGS += $(call cc-nowarn,old-style-declaration)
SPEC_CFLAGS += $(call cc-nowarn,ignored-qualifiers)
SPEC_CFLAGS += $(call cc-nowarn,clobbered)
SPEC_CFLAGS += $(call cc-nowarn,missing-field-initializers)
SPEC_CFLAGS += $(call cc-nowarn,implicit-fallthrough)
SPEC_CFLAGS += $(call cc-nowarn,stringop-overflow)
SPEC_CFLAGS += $(call cc-nowarn,cast-function-type)
SPEC_CFLAGS += $(call cc-nowarn,string-plus-int)
SPEC_CFLAGS += $(call cc-opt,-Wtype-limits)
SPEC_CFLAGS += $(call cc-opt,-Wshift-negative-value)
SPEC_CFLAGS += $(call cc-opt,-Wshift-overflow=2)
SPEC_CFLAGS += $(call cc-opt,-Wduplicated-cond)
SPEC_CFLAGS += $(call cc-opt,-Wnull-dereference)

#### Memory usage tuning
# If small memory footprint is required, you can reduce the buffer size. There
# are 2 buffers per concurrent session, so 16 kB buffers will eat 32 MB memory
# with 1000 concurrent sessions. Putting it slightly lower than a page size
# will prevent the additional parameters to go beyond a page. 8030 bytes is
# exactly 5.5 TCP segments of 1460 bytes and is generally good. Useful tuning
# macros include :
#    SYSTEM_MAXCONN, BUFSIZE, MAXREWRITE, REQURI_LEN, CAPTURE_LEN.
# Example: SMALL_OPTS = -DBUFSIZE=8030 -DMAXREWRITE=1030 -DSYSTEM_MAXCONN=1024
SMALL_OPTS =

#### Debug settings
# You can enable debugging on specific code parts by setting DEBUG=-DDEBUG_xxx.
# Currently defined DEBUG macros include DEBUG_FULL, DEBUG_MEMORY, DEBUG_FSM,
# DEBUG_HASH, DEBUG_AUTH, DEBUG_SPOE, DEBUG_UAF and DEBUG_THREAD, DEBUG_STRICT,
# DEBUG_DEV. Please check sources for exact meaning or do not use at all.
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

#### CPU dependant optimizations
# Some CFLAGS are set by default depending on the target CPU. Those flags only
# feed CPU_CFLAGS, which in turn feed CFLAGS, so it is not mandatory to use
# them. You should not have to change these options. Better use CPU_CFLAGS or
# even CFLAGS instead.
CPU_CFLAGS.generic    = -O2
CPU_CFLAGS.native     = -O2 -march=native
CPU_CFLAGS.i586       = -O2 -march=i586
CPU_CFLAGS.i686       = -O2 -march=i686
CPU_CFLAGS.ultrasparc = -O6 -mcpu=v9 -mtune=ultrasparc
CPU_CFLAGS            = $(CPU_CFLAGS.$(CPU))

#### ARCH dependant flags, may be overridden by CPU flags
ARCH_FLAGS.32     = -m32
ARCH_FLAGS.64     = -m64
ARCH_FLAGS.i386   = -m32 -march=i386
ARCH_FLAGS.i486   = -m32 -march=i486
ARCH_FLAGS.i586   = -m32 -march=i586
ARCH_FLAGS.i686   = -m32 -march=i686
ARCH_FLAGS.x86_64 = -m64 -march=x86-64
ARCH_FLAGS        = $(ARCH_FLAGS.$(ARCH))

#### Common CFLAGS
# These CFLAGS contain general optimization options, CPU-specific optimizations
# and debug flags. They may be overridden by some distributions which prefer to
# set all of them at once instead of playing with the CPU and DEBUG variables.
CFLAGS = $(ARCH_FLAGS) $(CPU_CFLAGS) $(DEBUG_CFLAGS) $(SPEC_CFLAGS)

#### Common LDFLAGS
# These LDFLAGS are used as the first "ld" options, regardless of any library
# path or any other option. They may be changed to add any linker-specific
# option at the beginning of the ld command line.
LDFLAGS = $(ARCH_FLAGS) -g

#### list of all "USE_*" options. These ones must be updated if new options are
# added, so that the relevant options are properly added to the CFLAGS and to
# the reported build options.
use_opts = USE_EPOLL USE_KQUEUE USE_MY_EPOLL USE_MY_SPLICE USE_NETFILTER      \
           USE_PCRE USE_PCRE_JIT USE_PCRE2 USE_PCRE2_JIT USE_POLL             \
           USE_PRIVATE_CACHE USE_THREAD USE_PTHREAD_PSHARED USE_REGPARM       \
           USE_STATIC_PCRE USE_STATIC_PCRE2 USE_TPROXY USE_LINUX_TPROXY       \
           USE_LINUX_SPLICE USE_LIBCRYPT USE_CRYPT_H USE_VSYSCALL             \
           USE_GETADDRINFO USE_OPENSSL USE_LUA USE_FUTEX USE_ACCEPT4          \
           USE_MY_ACCEPT4 USE_ZLIB USE_SLZ USE_CPU_AFFINITY USE_TFO USE_NS    \
           USE_DL USE_RT USE_DEVICEATLAS USE_51DEGREES USE_WURFL USE_SYSTEMD  \
           USE_OBSOLETE_LINKER USE_PRCTL USE_THREAD_DUMP USE_EVPORTS

#### Target system options
# Depending on the target platform, some options are set, as well as some
# CFLAGS and LDFLAGS. All variables pre-set here will not appear in the build
# options string. They may be set to any value, but are historically set to
# "implicit" which eases debugging. You should not have to change anything
# there unless you're adding support for a new platform.
default_opts = $(foreach name,$(1),$(eval $(name)=implicit))

# poll() is always supported, unless explicitly disabled by passing USE_POLL=""
# on the make command line.
USE_POLL   = default

# Always enable threads support by default and let the Makefile detect if
# HAProxy can be compiled with threads or not.

# generic system target has nothing specific
ifeq ($(TARGET),generic)
  set_target_defaults = $(call default_opts,USE_POLL USE_TPROXY)
endif

# Haiku
ifeq ($(TARGET),haiku)
  TARGET_LDFLAGS = -lnetwork
  set_target_defaults = $(call default_opts,USE_POLL USE_TPROXY)
endif

# For linux >= 2.6.28 and glibc
ifeq ($(TARGET),linux-glibc)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_DL USE_RT USE_CRYPT_H USE_NETFILTER  \
    USE_CPU_AFFINITY USE_THREAD USE_EPOLL USE_FUTEX USE_LINUX_TPROXY          \
    USE_ACCEPT4 USE_LINUX_SPLICE USE_PRCTL USE_THREAD_DUMP USE_NS USE_TFO     \
    USE_GETADDRINFO)
endif

# For linux >= 2.6.28, glibc without new features
ifeq ($(TARGET),linux-glibc-legacy)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_DL USE_RT USE_CRYPT_H USE_NETFILTER  \
    USE_CPU_AFFINITY USE_THREAD USE_EPOLL USE_FUTEX USE_LINUX_TPROXY          \
    USE_ACCEPT4 USE_LINUX_SPLICE USE_PRCTL USE_THREAD_DUMP USE_GETADDRINFO)
endif

# Solaris 8 and above
ifeq ($(TARGET),solaris)
  # We also enable getaddrinfo() which works since solaris 8.
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_CRYPT_H USE_GETADDRINFO USE_THREAD \
    USE_RT USE_OBSOLETE_LINKER USE_EVPORTS)
  TARGET_CFLAGS  = -DFD_SETSIZE=65536 -D_REENTRANT -D_XOPEN_SOURCE=500 -D__EXTENSIONS__
  TARGET_LDFLAGS = -lnsl -lsocket
endif

# FreeBSD 5 and above
ifeq ($(TARGET),freebsd)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_THREAD USE_CPU_AFFINITY USE_KQUEUE   \
    USE_CLOSEFROM)
endif

# Mac OS/X
ifeq ($(TARGET),osx)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_LIBCRYPT USE_THREAD USE_CPU_AFFINITY USE_KQUEUE)
  EXPORT_SYMBOL  = -export_dynamic
endif

# OpenBSD 5.7 and above
ifeq ($(TARGET),openbsd)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_THREAD USE_KQUEUE USE_ACCEPT4)
endif

# NetBSD
ifeq ($(TARGET),netbsd)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_TPROXY USE_KQUEUE)
endif

# AIX 5.1 only
ifeq ($(TARGET),aix51)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_LIBCRYPT USE_OBSOLETE_LINKER USE_PRIVATE_CACHE)
  TARGET_CFLAGS   = -Dss_family=__ss_family -Dip6_hdr=ip6hdr -DSTEVENS_API -D_LINUX_SOURCE_COMPAT -Dunsetenv=my_unsetenv
  DEBUG_CFLAGS    =
endif

# AIX 5.2 and above
ifeq ($(TARGET),aix52)
  set_target_defaults = $(call default_opts, \
    USE_POLL USE_LIBCRYPT USE_OBSOLETE_LINKER)
  TARGET_CFLAGS   = -D_MSGQSUPPORT
  DEBUG_CFLAGS    =
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

#### Build options
# Do not change these ones, enable USE_* variables instead.
OPTIONS_CFLAGS  =
OPTIONS_LDFLAGS =
OPTIONS_OBJS    =

#### Extra objects to be built and integrated (used only for development)
EXTRA_OBJS =

# Return USE_xxx=$(USE_xxx) if the variable was set from the environment or the
# command line.
# Usage:
#   BUILD_OPTIONS += $(call ignore_implicit,USE_xxx)
ignore_implicit = $(if $(subst environment,,$(origin $(1))),         \
                       $(if $(subst command line,,$(origin $(1))),,  \
                            $(1)=$($(1))),                           \
                       $(1)=$($(1)))                                 \

# This variable collects all USE_* values except those set to "implicit". This
# is used to report a list of all flags which were used to build this version.
# Do not assign anything to it.
BUILD_OPTIONS  := $(foreach opt,$(use_opts),$(call ignore_implicit,$(opt)))
BUILD_FEATURES := $(foreach opt,$(patsubst USE_%,%,$(use_opts)),$(if $(USE_$(opt)),+$(opt),-$(opt)))

# All USE_* options have their equivalent macro defined in the code (some might
# possibly be unused though)
OPTIONS_CFLAGS += $(foreach opt,$(use_opts),$(if $($(opt)),-D$(opt),))

ifneq ($(USE_LIBCRYPT),)
ifneq ($(TARGET),osx)
OPTIONS_LDFLAGS += -lcrypt
endif
endif

ifneq ($(USE_SLZ),)
# Use SLZ_INC and SLZ_LIB to force path to zlib.h and libz.{a,so} if needed.
SLZ_INC =
SLZ_LIB =
OPTIONS_CFLAGS  += $(if $(SLZ_INC),-I$(SLZ_INC))
OPTIONS_LDFLAGS += $(if $(SLZ_LIB),-L$(SLZ_LIB)) -lslz
endif

ifneq ($(USE_ZLIB),)
# Use ZLIB_INC and ZLIB_LIB to force path to zlib.h and libz.{a,so} if needed.
ZLIB_INC =
ZLIB_LIB =
OPTIONS_CFLAGS  += $(if $(ZLIB_INC),-I$(ZLIB_INC))
OPTIONS_LDFLAGS += $(if $(ZLIB_LIB),-L$(ZLIB_LIB)) -lz
endif

ifneq ($(USE_POLL),)
OPTIONS_OBJS   += src/ev_poll.o
endif

ifneq ($(USE_EPOLL),)
OPTIONS_OBJS   += src/ev_epoll.o
endif

ifneq ($(USE_KQUEUE),)
OPTIONS_OBJS   += src/ev_kqueue.o
endif

ifneq ($(USE_EVPORTS),)
OPTIONS_OBJS   += src/ev_evports.o
endif

ifneq ($(USE_VSYSCALL),)
OPTIONS_OBJS   += src/i386-linux-vsys.o
endif

ifneq ($(USE_REGPARM),)
OPTIONS_CFLAGS += -DCONFIG_REGPARM=3
endif

ifneq ($(USE_DL),)
OPTIONS_LDFLAGS += -ldl
endif

ifneq ($(USE_THREAD),)
OPTIONS_LDFLAGS += -lpthread
endif

ifneq ($(USE_RT),)
OPTIONS_LDFLAGS += -lrt
endif

ifneq ($(USE_OPENSSL),)
# OpenSSL is packaged in various forms and with various dependencies.
# In general -lssl is enough, but on some platforms, -lcrypto may be needed,
# reason why it's added by default. Some even need -lz, then you'll need to
# pass it in the "ADDLIB" variable if needed. If your SSL libraries are not
# in the usual path, use SSL_INC=/path/to/inc and SSL_LIB=/path/to/lib.
OPTIONS_CFLAGS  += $(if $(SSL_INC),-I$(SSL_INC))
OPTIONS_LDFLAGS += $(if $(SSL_LIB),-L$(SSL_LIB)) -lssl -lcrypto
ifneq ($(USE_DL),)
OPTIONS_LDFLAGS += -ldl
endif
OPTIONS_OBJS  += src/ssl_sock.o
endif

# The private cache option affect the way the shctx is built
ifeq ($(USE_PRIVATE_CACHE),)
ifneq ($(USE_PTHREAD_PSHARED),)
OPTIONS_LDFLAGS += -lpthread
endif
endif

ifneq ($(USE_LUA),)
check_lua_lib = $(shell echo "int main(){}" | $(CC) -o /dev/null -x c - $(2) -l$(1) 2>/dev/null && echo $(1))
check_lua_inc = $(shell if [ -d $(2)$(1) ]; then echo $(2)$(1); fi;)

OPTIONS_CFLAGS  += $(if $(LUA_INC),-I$(LUA_INC))
LUA_LD_FLAGS := -Wl,$(if $(EXPORT_SYMBOL),$(EXPORT_SYMBOL),--export-dynamic) $(if $(LUA_LIB),-L$(LUA_LIB))
ifeq ($(LUA_LIB_NAME),)
# Try to automatically detect the Lua library
LUA_LIB_NAME := $(firstword $(foreach lib,lua5.3 lua53 lua,$(call check_lua_lib,$(lib),$(LUA_LD_FLAGS))))
ifeq ($(LUA_LIB_NAME),)
$(error unable to automatically detect the Lua library name, you can enforce its name with LUA_LIB_NAME=<name> (where <name> can be lua5.3, lua53, lua, ...))
endif
LUA_INC := $(firstword $(foreach lib,lua5.3 lua53 lua,$(call check_lua_inc,$(lib),"/usr/include/")))
ifneq ($(LUA_INC),)
OPTIONS_CFLAGS  += -I$(LUA_INC)
endif
endif

OPTIONS_LDFLAGS += $(LUA_LD_FLAGS) -l$(LUA_LIB_NAME) -lm
ifneq ($(USE_DL),)
OPTIONS_LDFLAGS += -ldl
endif
OPTIONS_OBJS    += src/hlua.o src/hlua_fcn.o
endif

ifneq ($(USE_DEVICEATLAS),)
ifeq ($(USE_PCRE),)
$(error the DeviceAtlas module needs the PCRE library in order to compile)
endif
# Use DEVICEATLAS_SRC and possibly DEVICEATLAS_INC and DEVICEATLAS_LIB to force path
# to DeviceAtlas headers and libraries if needed.
DEVICEATLAS_SRC =
DEVICEATLAS_INC = $(DEVICEATLAS_SRC)
DEVICEATLAS_LIB = $(DEVICEATLAS_SRC)
ifeq ($(DEVICEATLAS_SRC),)
OPTIONS_LDFLAGS += -lda
else
OPTIONS_OBJS	+= $(DEVICEATLAS_LIB)/json.o
OPTIONS_OBJS	+= $(DEVICEATLAS_LIB)/dac.o
endif
OPTIONS_OBJS	+= src/da.o
OPTIONS_CFLAGS += $(if $(DEVICEATLAS_INC),-I$(DEVICEATLAS_INC))
endif

ifneq ($(USE_51DEGREES),)
# Use 51DEGREES_SRC and possibly 51DEGREES_INC and 51DEGREES_LIB to force path
# to 51degrees headers and libraries if needed.
51DEGREES_SRC =
51DEGREES_INC = $(51DEGREES_SRC)
51DEGREES_LIB = $(51DEGREES_SRC)
OPTIONS_OBJS    += $(51DEGREES_LIB)/../cityhash/city.o
OPTIONS_OBJS    += $(51DEGREES_LIB)/51Degrees.o
OPTIONS_OBJS    += src/51d.o
OPTIONS_CFLAGS  += $(if $(51DEGREES_INC),-I$(51DEGREES_INC))
ifeq ($(USE_THREAD),)
OPTIONS_CFLAGS  += -DFIFTYONEDEGREES_NO_THREADING
else
OPTIONS_OBJS    += $(51DEGREES_LIB)/../threading.o
endif

OPTIONS_LDFLAGS += $(if $(51DEGREES_LIB),-L$(51DEGREES_LIB)) -lm
endif

ifneq ($(USE_WURFL),)
# Use WURFL_SRC and possibly WURFL_INC and WURFL_LIB to force path
# to WURFL headers and libraries if needed.
WURFL_SRC =
WURFL_INC = $(WURFL_SRC)
WURFL_LIB = $(WURFL_SRC)
OPTIONS_OBJS    += src/wurfl.o
OPTIONS_CFLAGS  += $(if $(WURFL_INC),-I$(WURFL_INC))
ifneq ($(WURFL_DEBUG),)
OPTIONS_CFLAGS  += -DWURFL_DEBUG
endif
ifneq ($(WURFL_HEADER_WITH_DETAILS),)
OPTIONS_CFLAGS  += -DWURFL_HEADER_WITH_DETAILS
endif
OPTIONS_LDFLAGS += $(if $(WURFL_LIB),-L$(WURFL_LIB)) -lwurfl
endif

ifneq ($(USE_SYSTEMD),)
OPTIONS_LDFLAGS += -lsystemd
endif

ifneq ($(USE_PCRE)$(USE_STATIC_PCRE)$(USE_PCRE_JIT),)
ifneq ($(USE_PCRE2)$(USE_STATIC_PCRE2)$(USE_PCRE2_JIT),)
$(error cannot compile both PCRE and PCRE2 support)
endif
# PCREDIR is used to automatically construct the PCRE_INC and PCRE_LIB paths,
# by appending /include and /lib respectively. If your system does not use the
# same sub-directories, simply force these variables instead of PCREDIR. It is
# automatically detected but can be forced if required (for cross-compiling).
# Forcing PCREDIR to an empty string will let the compiler use the default
# locations.

PCRE_CONFIG    	:= pcre-config
PCREDIR	        := $(shell $(PCRE_CONFIG) --prefix 2>/dev/null || echo /usr/local)
ifneq ($(PCREDIR),)
PCRE_INC        := $(PCREDIR)/include
PCRE_LIB        := $(PCREDIR)/lib
endif

ifeq ($(USE_STATIC_PCRE),)
# dynamic PCRE
OPTIONS_CFLAGS  += -DUSE_PCRE $(if $(PCRE_INC),-I$(PCRE_INC))
OPTIONS_LDFLAGS += $(if $(PCRE_LIB),-L$(PCRE_LIB)) -lpcreposix -lpcre
else
# static PCRE
OPTIONS_CFLAGS  += -DUSE_PCRE $(if $(PCRE_INC),-I$(PCRE_INC))
OPTIONS_LDFLAGS += $(if $(PCRE_LIB),-L$(PCRE_LIB)) -Wl,-Bstatic -lpcreposix -lpcre -Wl,-Bdynamic
endif
endif

ifneq ($(USE_PCRE2)$(USE_STATIC_PCRE2)$(USE_PCRE2_JIT),)
PCRE2_CONFIG 	:= pcre2-config
PCRE2DIR	:= $(shell $(PCRE2_CONFIG) --prefix 2>/dev/null || echo /usr/local)
ifneq ($(PCRE2DIR),)
PCRE2_INC       := $(PCRE2DIR)/include
PCRE2_LIB       := $(PCRE2DIR)/lib

ifeq ($(PCRE2_WIDTH),)
PCRE2_WIDTH	= 8
endif

ifneq ($(PCRE2_WIDTH),8)
ifneq ($(PCRE2_WIDTH),16)
ifneq ($(PCRE2_WIDTH),32)
$(error PCRE2_WIDTH needs to be set to either 8,16 or 32)
endif
endif
endif


PCRE2_LDFLAGS	:= $(shell $(PCRE2_CONFIG) --libs$(PCRE2_WIDTH) 2>/dev/null || echo -L/usr/local/lib -lpcre2-$(PCRE2_WIDTH))

ifeq ($(PCRE2_LDFLAGS),)
$(error libpcre2-$(PCRE2_WIDTH) not found)
else
ifeq ($(PCRE2_WIDTH),8)
PCRE2_LDFLAGS	+= -lpcre2-posix
endif
endif

OPTIONS_CFLAGS	+= -DUSE_PCRE2 -DPCRE2_CODE_UNIT_WIDTH=$(PCRE2_WIDTH)
OPTIONS_CFLAGS  += $(if $(PCRE2_INC), -I$(PCRE2_INC))

ifneq ($(USE_STATIC_PCRE2),)
OPTIONS_LDFLAGS += $(if $(PCRE2_LIB),-L$(PCRE2_LIB)) -Wl,-Bstatic -L$(PCRE2_LIB) $(PCRE2_LDFLAGS) -Wl,-Bdynamic
else
OPTIONS_LDFLAGS += $(if $(PCRE2_LIB),-L$(PCRE2_LIB)) -L$(PCRE2_LIB) $(PCRE2_LDFLAGS)
endif

endif
endif

# This one can be changed to look for ebtree files in an external directory
EBTREE_DIR := ebtree

#### Global compile options
VERBOSE_CFLAGS = $(CFLAGS) $(TARGET_CFLAGS) $(SMALL_OPTS) $(DEFINE)
COPTS  = -Iinclude -I$(EBTREE_DIR) -Wall -Wextra

ifneq ($(ERR),)
COPTS += -Werror
endif

COPTS += $(CFLAGS) $(TARGET_CFLAGS) $(SMALL_OPTS) $(DEFINE) $(SILENT_DEFINE)
COPTS += $(DEBUG) $(OPTIONS_CFLAGS) $(ADDINC)

ifneq ($(VERSION)$(SUBVERS),)
COPTS += -DCONFIG_HAPROXY_VERSION=\"$(VERSION)$(SUBVERS)\"
endif

ifneq ($(VERDATE),)
COPTS += -DCONFIG_HAPROXY_DATE=\"$(VERDATE)\"
endif

ifneq ($(TRACE),)
# if tracing is enabled, we want it to be as fast as possible
TRACE_COPTS := $(filter-out -O0 -O1 -O2 -pg -finstrument-functions,$(COPTS)) -O3 -fomit-frame-pointer
COPTS += -finstrument-functions
endif

ifneq ($(USE_NS),)
OPTIONS_OBJS  += src/namespace.o
endif

#### Global link options
# These options are added at the end of the "ld" command line. Use LDFLAGS to
# add options at the beginning of the "ld" command line if needed.
LDOPTS = $(TARGET_LDFLAGS) $(OPTIONS_LDFLAGS) $(ADDLIB)

ifeq ($V,1)
cmd_CC = $(CC)
cmd_LD = $(LD)
cmd_AR = $(AR)
else
cmd_CC = $(Q)echo "  CC      $@";$(CC)
cmd_LD = $(Q)echo "  LD      $@";$(LD)
cmd_AR = $(Q)echo "  AR      $@";$(AR)
endif

ifeq ($(TARGET),)
all:
	@echo
	@echo "Due to too many reports of suboptimized setups, building without"
	@echo "specifying the target is no longer supported. Please specify the"
	@echo "target OS in the TARGET variable, in the following form:"
	@echo
	@echo "   $ make TARGET=xxx"
	@echo
	@echo "Please choose the target among the following supported list :"
	@echo
	@echo "   linux-glibc, linux-glibc-legacy, solaris, freebsd, openbsd, netbsd,"
	@echo "   cygwin, haiku, aix51, aix52, osx, generic, custom"
	@echo
	@echo "Use \"generic\" if you don't want any optimization, \"custom\" if you"
	@echo "want to precisely tweak every option, or choose the target which"
	@echo "matches your OS the most in order to gain the maximum performance"
	@echo "out of it. Please check the Makefile in case of doubts."
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
all: haproxy $(EXTRA)
endif
endif

OBJS = src/http_ana.o src/cfgparse-listen.o src/stream.o                      \
       src/mux_h2.o src/stats.o src/flt_spoe.o src/server.o src/checks.o      \
       src/haproxy.o src/cfgparse.o src/flt_http_comp.o src/http_fetch.o      \
       src/dns.o src/stick_table.o src/mux_h1.o src/peers.o src/standard.o    \
       src/proxy.o src/cli.o src/log.o src/backend.o src/pattern.o            \
       src/sample.o src/stream_interface.o src/proto_tcp.o src/listener.o     \
       src/h1.o src/cfgparse-global.o src/cache.o src/http_rules.o            \
       src/http_act.o src/tcp_rules.o src/filters.o src/connection.o          \
       src/session.o src/acl.o src/vars.o src/raw_sock.o src/map.o src/sink.o \
       src/proto_uxst.o src/payload.o src/fd.o src/queue.o src/flt_trace.o    \
       src/task.o src/lb_chash.o src/frontend.o src/applet.o src/mux_pt.o     \
       src/signal.o src/ev_select.o src/proto_sockpair.o src/compression.o    \
       src/http_conv.o src/memory.o src/lb_fwrr.o src/channel.o src/htx.o     \
       src/uri_auth.o src/regex.o src/chunk.o src/pipe.o src/lb_fas.o         \
       src/lb_map.o src/lb_fwlc.o src/auth.o src/time.o src/hathreads.o       \
       src/http_htx.o src/buffer.o src/hpack-tbl.o src/shctx.o src/sha1.o     \
       src/http.o src/hpack-dec.o src/action.o src/proto_udp.o src/http_acl.o \
       src/xxhash.o src/hpack-enc.o src/h2.o src/freq_ctr.o src/lru.o         \
       src/protocol.o src/arg.o src/hpack-huff.o src/base64.o src/ring.o      \
       src/hash.o src/mailers.o src/activity.o src/version.o src/trace.o      \
       src/mworker.o src/mworker-prog.o src/debug.o src/wdt.o src/dict.o      \
       src/xprt_handshake.o src/h1_htx.o src/fcgi.o src/fcgi-app.o src/mux_fcgi.o

EBTREE_OBJS = $(EBTREE_DIR)/ebtree.o $(EBTREE_DIR)/eb32sctree.o \
              $(EBTREE_DIR)/eb32tree.o $(EBTREE_DIR)/eb64tree.o \
              $(EBTREE_DIR)/ebmbtree.o $(EBTREE_DIR)/ebsttree.o \
              $(EBTREE_DIR)/ebimtree.o $(EBTREE_DIR)/ebistree.o

ifneq ($(TRACE),)
OBJS += src/calltrace.o
endif

ifneq ($(EXTRA_OBJS),)
OBJS += $(EXTRA_OBJS)
endif

# Not used right now
LIB_EBTREE = $(EBTREE_DIR)/libebtree.a

# Used only for forced dependency checking. May be cleared during development.
INCLUDES = $(wildcard include/*/*.h ebtree/*.h)
DEP = $(INCLUDES) .build_opts

help:
	$(Q)sed -ne "/^[^#]*$$/q;s/^# \{0,1\}\(.*\)/\1/;p" Makefile
	$(Q)echo; \
	   if [ -n "$(TARGET)" ]; then \
	     if [ -n "$(set_target_defaults)" ]; then \
	        echo "Current TARGET: $(TARGET)"; \
	     else \
	        echo "Current TARGET: $(TARGET) (custom target)"; \
	     fi; \
	   else \
	     echo "TARGET not set, you may pass 'TARGET=xxx' to set one among :";\
	     echo "  linux-glibc, linux-glibc-legacy, solaris, freebsd, netbsd, osx,"; \
	     echo "  openbsd, aix51, aix52, cygwin, haiku, generic, custom"; \
	   fi
	$(Q)echo;echo "Enabled features for TARGET '$(TARGET)' (disable with 'USE_xxx=') :"
	$(Q)set -- $(foreach opt,$(patsubst USE_%,%,$(use_opts)),$(if $(USE_$(opt)),$(opt),)); echo "  $$*" | (fmt || cat) 2>/dev/null
	$(Q)echo;echo "Disabled features for TARGET '$(TARGET)' (enable with 'USE_xxx=1') :"
	$(Q)set -- $(foreach opt,$(patsubst USE_%,%,$(use_opts)),$(if $(USE_$(opt)),,$(opt))); echo "  $$*" | (fmt || cat) 2>/dev/null

# Used only to force a rebuild if some build options change
build_opts = $(shell rm -f .build_opts.new; echo \'$(TARGET) $(BUILD_OPTIONS) $(VERBOSE_CFLAGS)\' > .build_opts.new; if cmp -s .build_opts .build_opts.new; then rm -f .build_opts.new; else mv -f .build_opts.new .build_opts; fi)
.build_opts: $(build_opts)

haproxy: $(OPTIONS_OBJS) $(OBJS) $(EBTREE_OBJS)
	$(cmd_LD) $(LDFLAGS) -o $@ $^ $(LDOPTS)

$(LIB_EBTREE): $(EBTREE_OBJS)
	$(cmd_AR) rv $@ $^

objsize: haproxy
	$(Q)objdump -t $^|grep ' g '|grep -F '.text'|awk '{print $$5 FS $$6}'|sort

%.o:	%.c $(DEP)
	$(cmd_CC) $(COPTS) -c -o $@ $<

# rebuild it every time
.PHONY: src/version.c

src/calltrace.o: src/calltrace.c $(DEP)
	$(cmd_CC) $(TRACE_COPTS) -c -o $@ $<

src/haproxy.o:	src/haproxy.c $(DEP)
	$(cmd_CC) $(COPTS) \
	      -DBUILD_TARGET='"$(strip $(TARGET))"' \
	      -DBUILD_ARCH='"$(strip $(ARCH))"' \
	      -DBUILD_CPU='"$(strip $(CPU))"' \
	      -DBUILD_CC='"$(strip $(CC))"' \
	      -DBUILD_CFLAGS='"$(strip $(VERBOSE_CFLAGS))"' \
	      -DBUILD_OPTIONS='"$(strip $(BUILD_OPTIONS))"' \
	      -DBUILD_FEATURES='"$(strip $(BUILD_FEATURES))"' \
	       -c -o $@ $<

install-man:
	$(Q)install -v -d "$(DESTDIR)$(MANDIR)"/man1
	$(Q)install -v -m 644 doc/haproxy.1 "$(DESTDIR)$(MANDIR)"/man1

EXCLUDE_DOCUMENTATION = lgpl gpl coding-style
DOCUMENTATION = $(filter-out $(EXCLUDE_DOCUMENTATION),$(patsubst doc/%.txt,%,$(wildcard doc/*.txt)))

install-doc:
	$(Q)install -v -d "$(DESTDIR)$(DOCDIR)"
	$(Q)for x in $(DOCUMENTATION); do \
		install -v -m 644 doc/$$x.txt "$(DESTDIR)$(DOCDIR)" ; \
	done

install-bin:
	$(Q)for i in haproxy $(EXTRA); do \
		if ! [ -e "$$i" ]; then \
			echo "Please run 'make' before 'make install'."; \
			exit 1; \
		fi; \
	done
	$(Q)install -v -d "$(DESTDIR)$(SBINDIR)"
	$(Q)install -v haproxy $(EXTRA) "$(DESTDIR)$(SBINDIR)"

install: install-bin install-man install-doc

uninstall:
	$(Q)rm -f "$(DESTDIR)$(MANDIR)"/man1/haproxy.1
	$(Q)for x in $(DOCUMENTATION); do \
		rm -f "$(DESTDIR)$(DOCDIR)"/$$x.txt ; \
	done
	$(Q)-rmdir "$(DESTDIR)$(DOCDIR)"
	$(Q)rm -f "$(DESTDIR)$(SBINDIR)"/haproxy

clean:
	$(Q)rm -f *.[oas] src/*.[oas] ebtree/*.[oas] haproxy test .build_opts .build_opts.new
	$(Q)for dir in . src include/* doc ebtree; do rm -f $$dir/*~ $$dir/*.rej $$dir/core; done
	$(Q)rm -f haproxy-$(VERSION).tar.gz haproxy-$(VERSION)$(SUBVERS).tar.gz
	$(Q)rm -f haproxy-$(VERSION) haproxy-$(VERSION)$(SUBVERS) nohup.out gmon.out

tags:
	$(Q)find src include \( -name '*.c' -o -name '*.h' \) -print0 | \
	   xargs -0 etags --declarations --members

cscope:
	$(Q)find src include -name "*.[ch]" -print | cscope -q -b -i -

tar:	clean
	$(Q)ln -s . haproxy-$(VERSION)$(SUBVERS)
	$(Q)tar --exclude=haproxy-$(VERSION)$(SUBVERS)/.git \
	    --exclude=haproxy-$(VERSION)$(SUBVERS)/haproxy-$(VERSION)$(SUBVERS) \
	    --exclude=haproxy-$(VERSION)$(SUBVERS)/haproxy-$(VERSION)$(SUBVERS).tar.gz \
	    -cf - haproxy-$(VERSION)$(SUBVERS)/* | gzip -c9 >haproxy-$(VERSION)$(SUBVERS).tar.gz
	$(Q)echo haproxy-$(VERSION)$(SUBVERS).tar.gz
	$(Q)rm -f haproxy-$(VERSION)$(SUBVERS)

git-tar:
	$(Q)git archive --format=tar --prefix="haproxy-$(VERSION)$(SUBVERS)/" HEAD | gzip -9 > haproxy-$(VERSION)$(SUBVERS).tar.gz
	$(Q)echo haproxy-$(VERSION)$(SUBVERS).tar.gz

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

# just display the build options
opts:
	@echo -n 'Using: '
	@echo -n 'TARGET="$(strip $(TARGET))" '
	@echo -n 'ARCH="$(strip $(ARCH))" '
	@echo -n 'CPU="$(strip $(CPU))" '
	@echo -n 'CC="$(strip $(CC))" '
	@echo -n 'ARCH_FLAGS="$(strip $(ARCH_FLAGS))" '
	@echo -n 'CPU_CFLAGS="$(strip $(CPU_CFLAGS))" '
	@echo -n 'DEBUG_CFLAGS="$(strip $(DEBUG_CFLAGS))" '
	@echo "$(strip $(BUILD_OPTIONS))"
	@echo 'COPTS="$(strip $(COPTS))"'
	@echo 'LDFLAGS="$(strip $(LDFLAGS))"'
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
	@echo "with 'any' as default value for REGTESTS_TYPES variable."
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
