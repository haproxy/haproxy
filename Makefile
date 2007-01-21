# This makefile supports different OS and CPU setups.
# You should use it this way :
#   make TARGET=os CPU=cpu REGEX=lib


# Select target OS. TARGET must match a system for which COPTS and LIBS are
# correctly defined below.
#TARGET = linux26
TARGET = linux24
#TARGET = linux24e
#TARGET = linux22
#TARGET = solaris

# pass CPU=<cpu_name> to make to optimize for a particular CPU
CPU = generic
#CPU = i586
#CPU = i686
#CPU = ultrasparc

# By default, we use libc's regex. WARNING! On Solaris 8/Sparc, group
# references seem broken using libc ! Use pcre instead.
REGEX=libc
#REGEX=pcre
#REGEX=static-pcre

# tools options
CC = gcc
LD = gcc

# This is the directory hosting include/pcre.h and lib/libpcre.* when REGEX=pcre
PCREDIR	:= $(shell pcre-config --prefix 2>/dev/null || :)
#PCREDIR=/usr/local

# This is the directory hosting libtcpsplice.[ah] when USE_TCPSPLICE is set
TCPSPLICEDIR :=

# This is for standard Linux 2.6 with netfilter and epoll()
COPTS.linux26 = -DNETFILTER -DENABLE_POLL -DENABLE_EPOLL
LIBS.linux26 =

# This is for enhanced Linux 2.4 with netfilter and epoll() patch.
# Warning! If kernel is 2.4 with epoll-lt <= 0.21, then you must add
# -DEPOLL_CTL_MOD_WORKAROUND to workaround a very rare bug.
#COPTS.linux24e = -DNETFILTER -DENABLE_POLL -DENABLE_EPOLL -DUSE_MY_EPOLL -DEPOLL_CTL_MOD_WORKAROUND
COPTS.linux24e = -DNETFILTER -DENABLE_POLL -DENABLE_EPOLL -DUSE_MY_EPOLL
LIBS.linux24e =

# This is for standard Linux 2.4 with netfilter but without epoll()
COPTS.linux24 = -DNETFILTER -DENABLE_POLL
LIBS.linux24 =

# This is for Linux 2.2
COPTS.linux22 = -DUSE_GETSOCKNAME -DENABLE_POLL
LIBS.linux22 =

# This is for Solaris 8
COPTS.solaris = -fomit-frame-pointer -DENABLE_POLL -DFD_SETSIZE=65536
LIBS.solaris = -lnsl -lsocket

# CPU dependant optimizations
COPTS.generic = -O2
COPTS.i586 = -O2 -march=i586 -DCONFIG_HAP_USE_REGPARM
COPTS.i686 = -O2 -march=i686 -DCONFIG_HAP_USE_REGPARM
COPTS.ultrasparc = -O6 -mcpu=v9 -mtune=ultrasparc

# options for standard regex library
COPTS.libc=
LIBS.libc=

# options for libpcre
COPTS.pcre=-DUSE_PCRE -I$(PCREDIR)/include
LIBS.pcre=-L$(PCREDIR)/lib -lpcreposix -lpcre

# options for static libpcre
COPTS.static-pcre=-DUSE_PCRE -I$(PCREDIR)/include
LIBS.static-pcre=-L$(PCREDIR)/lib -Wl,-Bstatic -lpcreposix -lpcre -Wl,-Bdynamic

# you can enable debug arguments with "DEBUG=-g" or disable them with "DEBUG="
#DEBUG = -g -DDEBUG_MEMORY -DDEBUG_FULL
DEBUG = -g

# if small memory footprint is required, you can reduce the buffer size. There
# are 2 buffers per concurrent session, so 16 kB buffers will eat 32 MB memory
# with 1000 concurrent sessions. Putting it slightly lower than a page size
# will avoid the additionnal paramters to overflow a page. 8030 bytes is
# exactly 5.5 TCP segments of 1460 bytes.
#SMALL_OPTS = -DBUFSIZE=8030 -DMAXREWRITE=1030 -DSYSTEM_MAXCONN=1024
SMALL_OPTS =

# redefine this if you want to add some special PATH to include/libs
ADDINC =
ADDLIB =

# set some defines when needed.
# Known ones are -DENABLE_POLL, -DENABLE_EPOLL, and -DUSE_MY_EPOLL
# - use -DTPROXY to compile with transparent proxy support.
# - use -DCONFIG_HAP_CTTPROXY to enable full transparent proxy support
DEFINE = -DTPROXY

# Now let's determine the version, sub-version and release date.
# If we're in the GIT tree, we can use the last commit's version and date.
ifeq ($(IGNOREGIT),)
VERSION := $(shell [ -d .git/. ] && ref=$$(git-describe --tags 2>/dev/null) && ref=$${ref%-g*} && echo "$${ref\#v}" )
endif

ifneq ($(VERSION),)
# OK git is there and works.
SUBVERS := $(shell comms=$$(git-log --no-merges v$(VERSION).. 2>/dev/null |grep -c ^commit ); [ $$comms -gt 0 ] && echo "-$$comms" )
VERDATE := $(shell date +%Y/%m/%d -d "$$(git-log HEAD^.. 2>/dev/null | grep -m 1 ^Date: | cut -f2- -d: | cut -f1 -d+)" )
else
# Otherwise, use the hard-coded version of last tag, number of changes
# since last tag, and release date.
VERSION := 1.3.6
SUBVERS := 
VERDATE := 2007/01/22
endif

#### build options

# do not change this one, enable USE_* variables instead.
OPTIONS =

ifneq ($(USE_TCPSPLICE),)
OPTIONS += -DCONFIG_HAP_TCPSPLICE
endif

ifneq ($(USE_CTTPROXY),)
OPTIONS += -DCONFIG_HAP_CTTPROXY
endif

ifneq ($(USE_TPROXY),)
OPTIONS += -DTPROXY
endif

ifneq ($(USE_POLL),)
OPTIONS += -DENABLE_POLL
endif

ifneq ($(USE_EPOLL),)
OPTIONS += -DENABLE_EPOLL
endif

ifneq ($(USE_MY_EPOLL),)
OPTIONS += -DUSE_MY_EPOLL
endif

ifneq ($(USE_NETFILTER),)
OPTIONS += -DNETFILTER
endif

ifneq ($(USE_EPOLL_WORKAROUND),)
OPTIONS += -DEPOLL_CTL_MOD_WORKAROUND
endif

ifneq ($(USE_GETSOCKNAME),)
OPTIONS += -DUSE_GETSOCKNAME
endif

ifneq ($(USE_REGPARM),)
OPTIONS += -DCONFIG_HAP_USE_REGPARM
endif

ifneq ($(VERSION),)
OPTIONS += -DCONFIG_HAPROXY_VERSION=\"$(VERSION)$(SUBVERS)\"
endif

ifneq ($(VERDATE),)
OPTIONS += -DCONFIG_HAPROXY_DATE=\"$(VERDATE)\"
endif

#### end of build options


# global options
TARGET_OPTS=$(COPTS.$(TARGET))
REGEX_OPTS=$(COPTS.$(REGEX))
CPU_OPTS=$(COPTS.$(CPU))

COPTS = -Iinclude $(CPU_OPTS) $(TARGET_OPTS) $(REGEX_OPTS) $(SMALL_OPTS) $(DEFINE) $(OPTIONS)
LIBS=$(LIBS.$(TARGET)) $(LIBS.$(REGEX))

ifneq ($(USE_TCPSPLICE),)
COPTS += -I$(TCPSPLICEDIR)
LIBS  += -L$(TCPSPLICEDIR) -ltcpsplice
endif

COPTS += $(ADDINC)
LIBS += $(ADDLIB)

CFLAGS = -Wall $(COPTS) $(DEBUG)
LDFLAGS = -g

all: haproxy

OBJS = src/haproxy.o src/list.o src/chtbl.o src/hashpjw.o src/base64.o \
       src/uri_auth.o src/standard.o src/buffers.o src/log.o src/task.o \
       src/time.o src/fd.o src/regex.o src/cfgparse.o src/server.o \
       src/checks.o src/queue.o src/capture.o src/client.o src/proxy.o \
       src/proto_http.o src/stream_sock.o src/appsession.o src/backend.o \
       src/session.o src/hdr_idx.o src/rbtree.o

haproxy: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

objsize: haproxy
	@objdump -t $^|grep ' g '|grep -F '.text'|awk '{print $$5 FS $$6}'|sort

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.[oas] src/*.[oas] core haproxy test
	for dir in . src include/* doc; do rm -f $$dir/*~ $$dir/*.rej;done
	rm -f haproxy-$(VERSION).tar.gz haproxy-$(VERSION)$(SUBVERS).tar.gz
	rm -f haproxy-$(VERSION) nohup.out gmon.out

tar:	clean
	ln -s . haproxy-$(VERSION)
	tar --exclude=haproxy-$(VERSION)/.git \
	    --exclude=haproxy-$(VERSION)/haproxy-$(VERSION) \
	    --exclude=haproxy-$(VERSION)/haproxy-$(VERSION).tar.gz \
	    -cf - haproxy-$(VERSION)/* | gzip -c9 >haproxy-$(VERSION).tar.gz
	rm -f haproxy-$(VERSION)

git-tar: clean
	git-tar-tree HEAD haproxy-$(VERSION) | gzip -9 > haproxy-$(VERSION)$(SUBVERS).tar.gz
