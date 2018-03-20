# This GNU Makefile supports different OS and CPU combinations.
#
# You should use it this way :
#   [g]make TARGET=os ARCH=arch CPU=cpu USE_xxx=1 ...
#
# Valid USE_* options are the following. Most of them are automatically set by
# the TARGET, others have to be explictly specified :
#   USE_DLMALLOC         : enable use of dlmalloc (see DLMALLOC_SRC)
#   USE_EPOLL            : enable epoll() on Linux 2.6. Automatic.
#   USE_KQUEUE           : enable kqueue() on BSD. Automatic.
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
#   USE_ZLIB             : enable zlib library support.
#   USE_SLZ              : enable slz library instead of zlib (pick at most one).
#   USE_CPU_AFFINITY     : enable pinning processes to CPU on Linux. Automatic.
#   USE_TFO              : enable TCP fast open. Supported on Linux >= 3.7.
#   USE_NS               : enable network namespace support. Supported on Linux >= 2.6.24.
#   USE_DL               : enable it if your system requires -ldl. Automatic on Linux.
#   USE_DEVICEATLAS      : enable DeviceAtlas api.
#   USE_51DEGREES        : enable third party device detection library from 51Degrees
#   USE_WURFL            : enable WURFL detection library from Scientiamobile
#   USE_SYSTEMD          : enable sd_notify() support.
#
# Options can be forced by specifying "USE_xxx=1" or can be disabled by using
# "USE_xxx=" (empty string).
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
#   DLMALLOC_SRC   : build with dlmalloc, indicate the location of dlmalloc.c.
#   DLMALLOC_THRES : should match PAGE_SIZE on every platform (default: 4096).
#   PCREDIR        : force the path to libpcre.
#   PCRE_LIB       : force the lib path to libpcre (defaults to $PCREDIR/lib).
#   PCRE_INC       : force the include path to libpcre ($PCREDIR/inc)
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

# Function used to detect support of a given option by the compiler.
# Usage: CFLAGS += $(call cc-opt,option). Eg: $(call cc-opt,-fwrapv)
# Note: ensure the referencing variable is assigned using ":=" and not "=" to
#       call it only once.
cc-opt = $(shell set -e; if $(CC) $(1) -c -xc - -o /dev/null </dev/null >&0 2>&0; then echo "$(1)"; fi;)

# Disable a warning when supported by the compiler. Don't put spaces around the
# warning! And don't use cc-opt which doesn't always report an error until
# another one is also returned.
# Usage: CFLAGS += $(call cc-nowarn,warning). Eg: $(call cc-opt,format-truncation)
cc-nowarn = $(shell set -e; if $(CC) -W$(1) -c -xc - -o /dev/null </dev/null >&0 2>&0; then echo "-Wno-$(1)"; fi;)

#### Installation options.
DESTDIR =
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
DOCDIR = $(PREFIX)/doc/haproxy

#### TARGET system
# Use TARGET=<target_name> to optimize for a specifc target OS among the
# following list (use the default "generic" if uncertain) :
#    generic, linux22, linux24, linux24e, linux26, solaris,
#    freebsd, openbsd, netbsd, cygwin, haiku, custom, aix51, aix52
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

#### Compiler-specific flags that may be used to disable some negative over-
# optimization or to silence some warnings. -fno-strict-aliasing is needed with
# gcc >= 4.4.
# We rely on signed integer wraparound on overflow, however clang think it
# can do whatever it wants since it's an undefined behavior, so use -fwrapv
# to be sure we get the intended behavior.
SPEC_CFLAGS := -fno-strict-aliasing -Wdeclaration-after-statement
SPEC_CFLAGS += $(call cc-opt,-fwrapv)
SPEC_CFLAGS += $(call cc-opt,-fno-strict-overflow)
SPEC_CFLAGS += $(call cc-nowarn,format-truncation)
SPEC_CFLAGS += $(call cc-nowarn,address-of-packed-member)
SPEC_CFLAGS += $(call cc-nowarn,null-dereference)
SPEC_CFLAGS += $(call cc-nowarn,unused-label)

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
# DEBUG_HASH, DEBUG_AUTH, DEBUG_SPOE, DEBUG_UAF and DEBUG_THREAD. Please check
# sources for exact meaning or do not use at all.
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

#### ARCH dependant flags, may be overriden by CPU flags
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

#### Target system options
# Depending on the target platform, some options are set, as well as some
# CFLAGS and LDFLAGS. The USE_* values are set to "implicit" so that they are
# not reported in the build options string. You should not have to change
# anything there. poll() is always supported, unless explicitly disabled by
# passing USE_POLL="" on the make command line.
USE_POLL   = default

# Always enable threads support by default and let the Makefile detect if
# HAProxy can be compiled with threads or not.

ifeq ($(TARGET),generic)
  # generic system target has nothing specific
  USE_POLL   = implicit
  USE_TPROXY = implicit
else
ifeq ($(TARGET),haiku)
  # For Haiku
  TARGET_LDFLAGS = -lnetwork
  USE_POLL = implicit
  USE_TPROXY = implicit
else
ifeq ($(TARGET),linux22)
  # This is for Linux 2.2
  USE_POLL        = implicit
  USE_TPROXY      = implicit
  USE_LIBCRYPT    = implicit
  USE_DL          = implicit
else
ifeq ($(TARGET),linux24)
  # This is for standard Linux 2.4 with netfilter but without epoll()
  USE_NETFILTER   = implicit
  USE_POLL        = implicit
  USE_TPROXY      = implicit
  USE_LIBCRYPT    = implicit
  USE_DL          = implicit
else
ifeq ($(TARGET),linux24e)
  # This is for enhanced Linux 2.4 with netfilter and epoll() patch > 0.21
  USE_NETFILTER   = implicit
  USE_POLL        = implicit
  USE_EPOLL       = implicit
  USE_MY_EPOLL    = implicit
  USE_TPROXY      = implicit
  USE_LIBCRYPT    = implicit
  USE_DL          = implicit
else
ifeq ($(TARGET),linux26)
  # This is for standard Linux 2.6 with netfilter and standard epoll()
  USE_NETFILTER   = implicit
  USE_POLL        = implicit
  USE_EPOLL       = implicit
  USE_TPROXY      = implicit
  USE_LIBCRYPT    = implicit
  USE_FUTEX       = implicit
  USE_DL          = implicit
else
ifeq ($(TARGET),linux2628)
  # This is for standard Linux >= 2.6.28 with netfilter, epoll, tproxy and splice
  USE_NETFILTER   = implicit
  USE_POLL        = implicit
  USE_EPOLL       = implicit
  USE_TPROXY      = implicit
  USE_LIBCRYPT    = implicit
  USE_LINUX_SPLICE= implicit
  USE_LINUX_TPROXY= implicit
  USE_ACCEPT4     = implicit
  USE_FUTEX       = implicit
  USE_CPU_AFFINITY= implicit
  ASSUME_SPLICE_WORKS= implicit
  USE_DL          = implicit
  USE_THREAD      = implicit
else
ifeq ($(TARGET),solaris)
  # This is for Solaris 8
  # We also enable getaddrinfo() which works since solaris 8.
  USE_POLL       = implicit
  TARGET_CFLAGS  = -fomit-frame-pointer -DFD_SETSIZE=65536 -D_REENTRANT -D_XOPEN_SOURCE=500 -D__EXTENSIONS__
  TARGET_LDFLAGS = -lnsl -lsocket
  USE_TPROXY     = implicit
  USE_LIBCRYPT    = implicit
  USE_CRYPT_H     = implicit
  USE_GETADDRINFO = implicit
  USE_THREAD      = implicit
else
ifeq ($(TARGET),freebsd)
  # This is for FreeBSD
  USE_POLL       = implicit
  USE_KQUEUE     = implicit
  USE_TPROXY     = implicit
  USE_LIBCRYPT   = implicit
  USE_THREAD     = implicit
  USE_CPU_AFFINITY= implicit
else
ifeq ($(TARGET),osx)
  # This is for Mac OS/X
  USE_POLL       = implicit
  USE_KQUEUE     = implicit
  USE_TPROXY     = implicit
  EXPORT_SYMBOL  = -export_dynamic
else
ifeq ($(TARGET),openbsd)
  # This is for OpenBSD >= 5.7
  USE_POLL       = implicit
  USE_KQUEUE     = implicit
  USE_TPROXY     = implicit
  USE_ACCEPT4    = implicit
  USE_THREAD     = implicit
else
ifeq ($(TARGET),netbsd)
  # This is for NetBSD
  USE_POLL       = implicit
  USE_KQUEUE     = implicit
  USE_TPROXY     = implicit
else
ifeq ($(TARGET),aix51)
  # This is for AIX 5.1
  USE_POLL        = implicit
  USE_LIBCRYPT    = implicit
  TARGET_CFLAGS   = -Dss_family=__ss_family
  DEBUG_CFLAGS    =
else
ifeq ($(TARGET),aix52)
  # This is for AIX 5.2 and later
  USE_POLL        = implicit
  USE_LIBCRYPT    = implicit
  TARGET_CFLAGS   = -D_MSGQSUPPORT
  DEBUG_CFLAGS    =
else
ifeq ($(TARGET),cygwin)
  # This is for Cygwin
  # Cygwin adds IPv6 support only in version 1.7 (in beta right now). 
  USE_POLL   = implicit
  USE_TPROXY = implicit
  TARGET_CFLAGS  = $(if $(filter 1.5.%, $(shell uname -r)), -DUSE_IPV6 -DAF_INET6=23 -DINET6_ADDRSTRLEN=46, )
endif # cygwin
endif # aix52
endif # aix51
endif # netbsd
endif # openbsd
endif # osx
endif # freebsd
endif # solaris
endif # linux2628
endif # linux26
endif # linux24e
endif # linux24
endif # linux22
endif # haiku
endif # generic


#### Old-style REGEX library settings for compatibility with previous setups.
# It is still possible to use REGEX=<regex_lib> to select an alternative regex
# library. By default, we use libc's regex. On Solaris 8/Sparc, grouping seems
# to be broken using libc, so consider using pcre instead. Supported values are
# "libc", "pcre", and "static-pcre". Use of this method is deprecated in favor
# of "USE_PCRE" and "USE_STATIC_PCRE" (see build options below).
REGEX = libc

ifeq ($(REGEX),pcre)
USE_PCRE = 1
$(warning WARNING! use of "REGEX=pcre" is deprecated, consider using "USE_PCRE=1" instead.)
endif

ifeq ($(REGEX),static-pcre)
USE_STATIC_PCRE = 1
$(warning WARNING! use of "REGEX=pcre-static" is deprecated, consider using "USE_STATIC_PCRE=1" instead.)
endif

#### Old-style TPROXY settings
ifneq ($(findstring -DTPROXY,$(DEFINE)),)
USE_TPROXY = 1
$(warning WARNING! use of "DEFINE=-DTPROXY" is deprecated, consider using "USE_TPROXY=1" instead.)
endif


#### Determine version, sub-version and release date.
# If GIT is found, and IGNOREGIT is not set, VERSION, SUBVERS and VERDATE are
# extracted from the last commit. Otherwise, use the contents of the files
# holding the same names in the current directory.

ifeq ($(IGNOREGIT),)
VERSION := $(shell [ -d .git/. ] && ref=`(git describe --tags --match 'v*' --abbrev=0) 2>/dev/null` && ref=$${ref%-g*} && echo "$${ref\#v}")
ifneq ($(VERSION),)
# OK git is there and works.
SUBVERS := $(shell comms=`git log --format=oneline --no-merges v$(VERSION).. 2>/dev/null | wc -l | tr -dc '0-9'`; commit=`(git log -1 --pretty=%h --abbrev=6) 2>/dev/null`; [ $$comms -gt 0 ] && echo "-$$commit-$$comms")
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

# This variable collects all USE_* values except those set to "implicit". This
# is used to report a list of all flags which were used to build this version.
# Do not assign anything to it.
BUILD_OPTIONS =

# Return USE_xxx=$(USE_xxx) unless $(USE_xxx) = "implicit"
# Usage: 
#   BUILD_OPTIONS += $(call ignore_implicit,USE_xxx)
ignore_implicit = $(patsubst %=implicit,,$(1)=$($(1)))

ifneq ($(USE_TCPSPLICE),)
$(error experimental option USE_TCPSPLICE has been removed, check USE_LINUX_SPLICE)
endif

ifneq ($(USE_LINUX_SPLICE),)
OPTIONS_CFLAGS += -DCONFIG_HAP_LINUX_SPLICE
BUILD_OPTIONS  += $(call ignore_implicit,USE_LINUX_SPLICE)
endif

ifneq ($(USE_TPROXY),)
OPTIONS_CFLAGS += -DTPROXY
BUILD_OPTIONS  += $(call ignore_implicit,USE_TPROXY)
endif

ifneq ($(USE_LINUX_TPROXY),)
OPTIONS_CFLAGS += -DCONFIG_HAP_LINUX_TPROXY
BUILD_OPTIONS  += $(call ignore_implicit,USE_LINUX_TPROXY)
endif

ifneq ($(USE_LIBCRYPT),)
OPTIONS_CFLAGS  += -DCONFIG_HAP_CRYPT
BUILD_OPTIONS   += $(call ignore_implicit,USE_LIBCRYPT)
OPTIONS_LDFLAGS += -lcrypt
endif

ifneq ($(USE_CRYPT_H),)
OPTIONS_CFLAGS  += -DNEED_CRYPT_H
BUILD_OPTIONS   += $(call ignore_implicit,USE_CRYPT_H)
endif

ifneq ($(USE_GETADDRINFO),)
OPTIONS_CFLAGS  += -DUSE_GETADDRINFO
BUILD_OPTIONS   += $(call ignore_implicit,USE_GETADDRINFO)
endif

ifneq ($(USE_SLZ),)
# Use SLZ_INC and SLZ_LIB to force path to zlib.h and libz.{a,so} if needed.
SLZ_INC =
SLZ_LIB =
OPTIONS_CFLAGS  += -DUSE_SLZ $(if $(SLZ_INC),-I$(SLZ_INC))
BUILD_OPTIONS   += $(call ignore_implicit,USE_SLZ)
OPTIONS_LDFLAGS += $(if $(SLZ_LIB),-L$(SLZ_LIB)) -lslz
endif

ifneq ($(USE_ZLIB),)
# Use ZLIB_INC and ZLIB_LIB to force path to zlib.h and libz.{a,so} if needed.
ZLIB_INC =
ZLIB_LIB =
OPTIONS_CFLAGS  += -DUSE_ZLIB $(if $(ZLIB_INC),-I$(ZLIB_INC))
BUILD_OPTIONS   += $(call ignore_implicit,USE_ZLIB)
OPTIONS_LDFLAGS += $(if $(ZLIB_LIB),-L$(ZLIB_LIB)) -lz
endif

ifneq ($(USE_POLL),)
OPTIONS_CFLAGS += -DENABLE_POLL
OPTIONS_OBJS   += src/ev_poll.o
BUILD_OPTIONS  += $(call ignore_implicit,USE_POLL)
endif

ifneq ($(USE_EPOLL),)
OPTIONS_CFLAGS += -DENABLE_EPOLL
OPTIONS_OBJS   += src/ev_epoll.o
BUILD_OPTIONS  += $(call ignore_implicit,USE_EPOLL)
endif

ifneq ($(USE_MY_EPOLL),)
OPTIONS_CFLAGS += -DUSE_MY_EPOLL
BUILD_OPTIONS  += $(call ignore_implicit,USE_MY_EPOLL)
endif

ifneq ($(USE_KQUEUE),)
OPTIONS_CFLAGS += -DENABLE_KQUEUE
OPTIONS_OBJS   += src/ev_kqueue.o
BUILD_OPTIONS  += $(call ignore_implicit,USE_KQUEUE)
endif

ifneq ($(USE_VSYSCALL),)
OPTIONS_OBJS   += src/i386-linux-vsys.o
OPTIONS_CFLAGS += -DCONFIG_HAP_LINUX_VSYSCALL
BUILD_OPTIONS  += $(call ignore_implicit,USE_VSYSCALL)
endif

ifneq ($(USE_CPU_AFFINITY),)
OPTIONS_CFLAGS += -DUSE_CPU_AFFINITY
BUILD_OPTIONS  += $(call ignore_implicit,USE_CPU_AFFINITY)
endif

ifneq ($(USE_MY_SPLICE),)
OPTIONS_CFLAGS += -DUSE_MY_SPLICE
BUILD_OPTIONS  += $(call ignore_implicit,USE_MY_SPLICE)
endif

ifneq ($(ASSUME_SPLICE_WORKS),)
OPTIONS_CFLAGS += -DASSUME_SPLICE_WORKS
BUILD_OPTIONS  += $(call ignore_implicit,ASSUME_SPLICE_WORKS)
endif

ifneq ($(USE_ACCEPT4),)
OPTIONS_CFLAGS += -DUSE_ACCEPT4
BUILD_OPTIONS  += $(call ignore_implicit,USE_ACCEPT4)
endif

ifneq ($(USE_MY_ACCEPT4),)
OPTIONS_CFLAGS += -DUSE_MY_ACCEPT4
BUILD_OPTIONS  += $(call ignore_implicit,USE_MY_ACCEPT4)
endif

ifneq ($(USE_NETFILTER),)
OPTIONS_CFLAGS += -DNETFILTER
BUILD_OPTIONS  += $(call ignore_implicit,USE_NETFILTER)
endif

ifneq ($(USE_REGPARM),)
OPTIONS_CFLAGS += -DCONFIG_REGPARM=3
BUILD_OPTIONS  += $(call ignore_implicit,USE_REGPARM)
endif

ifneq ($(USE_DL),)
BUILD_OPTIONS   += $(call ignore_implicit,USE_DL)
OPTIONS_LDFLAGS += -ldl
endif

ifneq ($(USE_THREAD),)
BUILD_OPTIONS   += $(call ignore_implicit,USE_THREAD)
OPTIONS_CFLAGS  += -DUSE_THREAD
OPTIONS_LDFLAGS += -lpthread
endif

# report DLMALLOC_SRC only if explicitly specified
ifneq ($(DLMALLOC_SRC),)
BUILD_OPTIONS += DLMALLOC_SRC=$(DLMALLOC_SRC)
endif

ifneq ($(USE_DLMALLOC),)
BUILD_OPTIONS  += $(call ignore_implicit,USE_DLMALLOC)
ifeq ($(DLMALLOC_SRC),)
DLMALLOC_SRC=src/dlmalloc.c
endif
endif

ifneq ($(DLMALLOC_SRC),)
# DLMALLOC_THRES may be changed to match PAGE_SIZE on every platform
DLMALLOC_THRES = 4096
OPTIONS_OBJS  += src/dlmalloc.o
endif

ifneq ($(USE_OPENSSL),)
# OpenSSL is packaged in various forms and with various dependencies.
# In general -lssl is enough, but on some platforms, -lcrypto may be needed,
# reason why it's added by default. Some even need -lz, then you'll need to
# pass it in the "ADDLIB" variable if needed. If your SSL libraries are not
# in the usual path, use SSL_INC=/path/to/inc and SSL_LIB=/path/to/lib.
BUILD_OPTIONS   += $(call ignore_implicit,USE_OPENSSL)
OPTIONS_CFLAGS  += -DUSE_OPENSSL $(if $(SSL_INC),-I$(SSL_INC))
OPTIONS_LDFLAGS += $(if $(SSL_LIB),-L$(SSL_LIB)) -lssl -lcrypto
ifneq ($(USE_DL),)
OPTIONS_LDFLAGS += -ldl
endif
OPTIONS_OBJS  += src/ssl_sock.o
endif

# The private cache option affect the way the shctx is built
ifneq ($(USE_PRIVATE_CACHE),)
OPTIONS_CFLAGS  += -DUSE_PRIVATE_CACHE
else
ifneq ($(USE_PTHREAD_PSHARED),)
OPTIONS_CFLAGS  += -DUSE_PTHREAD_PSHARED
OPTIONS_LDFLAGS += -lpthread
else
ifneq ($(USE_FUTEX),)
OPTIONS_CFLAGS  += -DUSE_SYSCALL_FUTEX
endif
endif
endif

ifneq ($(USE_LUA),)
check_lua_lib = $(shell echo "int main(){}" | $(CC) -o /dev/null -x c - $(2) -l$(1) 2>/dev/null && echo $(1))
check_lua_inc = $(shell if [ -d $(2)$(1) ]; then echo $(2)$(1); fi;)

BUILD_OPTIONS   += $(call ignore_implicit,USE_LUA)
OPTIONS_CFLAGS  += -DUSE_LUA $(if $(LUA_INC),-I$(LUA_INC))
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
OPTIONS_CFLAGS += -DUSE_DEVICEATLAS $(if $(DEVICEATLAS_INC),-I$(DEVICEATLAS_INC))
BUILD_OPTIONS  += $(call ignore_implicit,USE_DEVICEATLAS)
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
OPTIONS_CFLAGS  += -DUSE_51DEGREES -DFIFTYONEDEGREES_NO_THREADING $(if $(51DEGREES_INC),-I$(51DEGREES_INC))
BUILD_OPTIONS   += $(call ignore_implicit,USE_51DEGREES)
OPTIONS_LDFLAGS += $(if $(51DEGREES_LIB),-L$(51DEGREES_LIB)) -lm
endif

ifneq ($(USE_WURFL),)
# Use WURFL_SRC and possibly WURFL_INC and WURFL_LIB to force path
# to WURFL headers and libraries if needed.
WURFL_SRC =
WURFL_INC = $(WURFL_SRC)
WURFL_LIB = $(WURFL_SRC)
OPTIONS_OBJS    += src/wurfl.o
OPTIONS_CFLAGS  += -DUSE_WURFL $(if $(WURFL_INC),-I$(WURFL_INC))
ifneq ($(WURFL_DEBUG),)
OPTIONS_CFLAGS  += -DWURFL_DEBUG
endif
ifneq ($(WURFL_HEADER_WITH_DETAILS),)
OPTIONS_CFLAGS  += -DWURFL_HEADER_WITH_DETAILS
endif
BUILD_OPTIONS   += $(call ignore_implicit,USE_WURFL)
OPTIONS_LDFLAGS += $(if $(WURFL_LIB),-L$(WURFL_LIB)) -lwurfl
endif

ifneq ($(USE_SYSTEMD),)
BUILD_OPTIONS   += $(call ignore_implicit,USE_SYSTEMD)
OPTIONS_CFLAGS  += -DUSE_SYSTEMD
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

PCREDIR	        := $(shell pcre-config --prefix 2>/dev/null || echo /usr/local)
ifneq ($(PCREDIR),)
PCRE_INC        := $(PCREDIR)/include
PCRE_LIB        := $(PCREDIR)/lib
endif

ifeq ($(USE_STATIC_PCRE),)
# dynamic PCRE
OPTIONS_CFLAGS  += -DUSE_PCRE $(if $(PCRE_INC),-I$(PCRE_INC))
OPTIONS_LDFLAGS += $(if $(PCRE_LIB),-L$(PCRE_LIB)) -lpcreposix -lpcre
BUILD_OPTIONS   += $(call ignore_implicit,USE_PCRE)
else
# static PCRE
OPTIONS_CFLAGS  += -DUSE_PCRE $(if $(PCRE_INC),-I$(PCRE_INC))
OPTIONS_LDFLAGS += $(if $(PCRE_LIB),-L$(PCRE_LIB)) -Wl,-Bstatic -lpcreposix -lpcre -Wl,-Bdynamic
BUILD_OPTIONS   += $(call ignore_implicit,USE_STATIC_PCRE)
endif
# JIT PCRE
ifneq ($(USE_PCRE_JIT),)
OPTIONS_CFLAGS  += -DUSE_PCRE_JIT
BUILD_OPTIONS   += $(call ignore_implicit,USE_PCRE_JIT)
endif
endif

ifneq ($(USE_PCRE2)$(USE_STATIC_PCRE2)$(USE_PCRE2_JIT),)
PCRE2DIR	:= $(shell pcre2-config --prefix 2>/dev/null || echo /usr/local)
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


PCRE2_LDFLAGS	:= $(shell pcre2-config --libs$(PCRE2_WIDTH) 2>/dev/null || echo -L/usr/local/lib -lpcre2-$(PCRE2_WIDTH))

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
BUILD_OPTIONS   += $(call ignore_implicit,USE_STATIC_PCRE2)
else
OPTIONS_LDFLAGS += $(if $(PCRE2_LIB),-L$(PCRE2_LIB)) -L$(PCRE2_LIB) $(PCRE2_LDFLAGS)
BUILD_OPTIONS   += $(call ignore_implicit,USE_PCRE2)
endif

ifneq ($(USE_PCRE2_JIT),)
OPTIONS_CFLAGS  += -DUSE_PCRE2_JIT
BUILD_OPTIONS   += $(call ignore_implicit,USE_PCRE2_JIT)
endif

endif
endif

# TCP Fast Open
ifneq ($(USE_TFO),)
OPTIONS_CFLAGS  += -DUSE_TFO
BUILD_OPTIONS   += $(call ignore_implicit,USE_TFO)
endif

# This one can be changed to look for ebtree files in an external directory
EBTREE_DIR := ebtree

#### Global compile options
VERBOSE_CFLAGS = $(CFLAGS) $(TARGET_CFLAGS) $(SMALL_OPTS) $(DEFINE)
COPTS  = -Iinclude -I$(EBTREE_DIR) -Wall
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
OPTIONS_CFLAGS += -DCONFIG_HAP_NS
BUILD_OPTIONS  += $(call ignore_implicit,USE_NS)
endif

#### Global link options
# These options are added at the end of the "ld" command line. Use LDFLAGS to
# add options at the beginning of the "ld" command line if needed.
LDOPTS = $(TARGET_LDFLAGS) $(OPTIONS_LDFLAGS) $(ADDLIB)

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
	@echo "   linux2628, linux26, linux24, linux24e, linux22, solaris"
	@echo "   freebsd, openbsd, cygwin, custom, generic"
	@echo
	@echo "Use \"generic\" if you don't want any optimization, \"custom\" if you"
	@echo "want to precisely tweak every option, or choose the target which"
	@echo "matches your OS the most in order to gain the maximum performance"
	@echo "out of it. Please check the Makefile in case of doubts."
	@echo
	@exit 1
else
all: haproxy $(EXTRA)
endif

OBJS = src/proto_http.o src/cfgparse.o src/server.o src/stream.o        \
       src/flt_spoe.o src/stick_table.o src/stats.o src/mux_h2.o        \
       src/checks.o src/haproxy.o src/log.o src/dns.o src/peers.o       \
       src/standard.o src/sample.o src/cli.o src/stream_interface.o     \
       src/proto_tcp.o src/backend.o src/proxy.o src/tcp_rules.o        \
       src/listener.o src/flt_http_comp.o src/pattern.o src/cache.o     \
       src/filters.o src/vars.o src/acl.o src/payload.o                 \
       src/connection.o src/raw_sock.o src/proto_uxst.o                 \
       src/flt_trace.o src/session.o src/ev_select.o src/channel.o      \
       src/task.o src/queue.o src/applet.o src/map.o src/frontend.o     \
       src/freq_ctr.o src/lb_fwlc.o src/mux_pt.o src/auth.o src/fd.o    \
       src/hpack-dec.o src/memory.o src/lb_fwrr.o src/lb_chash.o        \
       src/lb_fas.o src/hathreads.o src/chunk.o src/lb_map.o            \
       src/xxhash.o src/regex.o src/shctx.o src/buffer.o src/action.o   \
       src/h1.o src/compression.o src/pipe.o src/namespace.o            \
       src/sha1.o src/hpack-tbl.o src/hpack-enc.o src/uri_auth.o        \
       src/time.o src/proto_udp.o src/arg.o src/signal.o                \
       src/protocol.o src/lru.o src/hdr_idx.o src/hpack-huff.o          \
       src/mailers.o src/h2.o src/base64.o src/hash.o

EBTREE_OBJS = $(EBTREE_DIR)/ebtree.o $(EBTREE_DIR)/eb32sctree.o \
              $(EBTREE_DIR)/eb32tree.o $(EBTREE_DIR)/eb64tree.o \
              $(EBTREE_DIR)/ebmbtree.o $(EBTREE_DIR)/ebsttree.o \
              $(EBTREE_DIR)/ebimtree.o $(EBTREE_DIR)/ebistree.o

ifneq ($(TRACE),)
OBJS += src/trace.o
endif


# Not used right now
LIB_EBTREE = $(EBTREE_DIR)/libebtree.a

# Used only for forced dependency checking. May be cleared during development.
INCLUDES = $(wildcard include/*/*.h ebtree/*.h)
DEP = $(INCLUDES) .build_opts

# Used only to force a rebuild if some build options change
.build_opts: $(shell rm -f .build_opts.new; echo \'$(TARGET) $(BUILD_OPTIONS) $(VERBOSE_CFLAGS)\' > .build_opts.new; if cmp -s .build_opts .build_opts.new; then rm -f .build_opts.new; else mv -f .build_opts.new .build_opts; fi)

haproxy: $(OPTIONS_OBJS) $(EBTREE_OBJS) $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LDOPTS)

$(LIB_EBTREE): $(EBTREE_OBJS)
	$(AR) rv $@ $^

objsize: haproxy
	@objdump -t $^|grep ' g '|grep -F '.text'|awk '{print $$5 FS $$6}'|sort

%.o:	%.c $(DEP)
	$(CC) $(COPTS) -c -o $@ $<

src/trace.o: src/trace.c $(DEP)
	$(CC) $(TRACE_COPTS) -c -o $@ $<

src/haproxy.o:	src/haproxy.c $(DEP)
	$(CC) $(COPTS) \
	      -DBUILD_TARGET='"$(strip $(TARGET))"' \
	      -DBUILD_ARCH='"$(strip $(ARCH))"' \
	      -DBUILD_CPU='"$(strip $(CPU))"' \
	      -DBUILD_CC='"$(strip $(CC))"' \
	      -DBUILD_CFLAGS='"$(strip $(VERBOSE_CFLAGS))"' \
	      -DBUILD_OPTIONS='"$(strip $(BUILD_OPTIONS))"' \
	       -c -o $@ $<

src/dlmalloc.o: $(DLMALLOC_SRC) $(DEP)
	$(CC) $(COPTS) -DDEFAULT_MMAP_THRESHOLD=$(DLMALLOC_THRES) -c -o $@ $<

install-man:
	install -d "$(DESTDIR)$(MANDIR)"/man1
	install -m 644 doc/haproxy.1 "$(DESTDIR)$(MANDIR)"/man1

EXCLUDE_DOCUMENTATION = lgpl gpl coding-style
DOCUMENTATION = $(filter-out $(EXCLUDE_DOCUMENTATION),$(patsubst doc/%.txt,%,$(wildcard doc/*.txt)))

install-doc:
	install -d "$(DESTDIR)$(DOCDIR)"
	for x in $(DOCUMENTATION); do \
		install -m 644 doc/$$x.txt "$(DESTDIR)$(DOCDIR)" ; \
	done

install-bin:
	@for i in haproxy $(EXTRA); do \
		if ! [ -e "$$i" ]; then \
			echo "Please run 'make' before 'make install'."; \
			exit 1; \
		fi; \
	done
	install -d "$(DESTDIR)$(SBINDIR)"
	install haproxy $(EXTRA) "$(DESTDIR)$(SBINDIR)"

install: install-bin install-man install-doc

uninstall:
	rm -f "$(DESTDIR)$(MANDIR)"/man1/haproxy.1
	for x in $(DOCUMENTATION); do \
		rm -f "$(DESTDIR)$(DOCDIR)"/$$x.txt ; \
	done
	-rmdir "$(DESTDIR)$(DOCDIR)"
	rm -f "$(DESTDIR)$(SBINDIR)"/haproxy

clean:
	rm -f *.[oas] src/*.[oas] ebtree/*.[oas] haproxy test .build_opts .build_opts.new
	for dir in . src include/* doc ebtree; do rm -f $$dir/*~ $$dir/*.rej $$dir/core; done
	rm -f haproxy-$(VERSION).tar.gz haproxy-$(VERSION)$(SUBVERS).tar.gz
	rm -f haproxy-$(VERSION) haproxy-$(VERSION)$(SUBVERS) nohup.out gmon.out

tags:
	find src include \( -name '*.c' -o -name '*.h' \) -print0 | \
	   xargs -0 etags --declarations --members

cscope:
	find src include -name "*.[ch]" -print | cscope -q -b -i -

tar:	clean
	ln -s . haproxy-$(VERSION)$(SUBVERS)
	tar --exclude=haproxy-$(VERSION)$(SUBVERS)/.git \
	    --exclude=haproxy-$(VERSION)$(SUBVERS)/haproxy-$(VERSION)$(SUBVERS) \
	    --exclude=haproxy-$(VERSION)$(SUBVERS)/haproxy-$(VERSION)$(SUBVERS).tar.gz \
	    -cf - haproxy-$(VERSION)$(SUBVERS)/* | gzip -c9 >haproxy-$(VERSION)$(SUBVERS).tar.gz
	rm -f haproxy-$(VERSION)$(SUBVERS)

git-tar:
	git archive --format=tar --prefix="haproxy-$(VERSION)$(SUBVERS)/" HEAD | gzip -9 > haproxy-$(VERSION)$(SUBVERS).tar.gz

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
