# Select target OS. TARGET must match a system for which COPTS and LIBS are
# correctly defined below.
# You can set it on make's command line. eg: make TARGET=solaris
TARGET = linux24
#TARGET = linux22
#TARGET = solaris
#TARGET = solarisv9
#TARGET = openbsd

CC = gcc
LD = gcc

# By default, we use libc's regex.
REGEX=libc
#REGEX=pcre

# This is the directory hosting include/pcre.h and lib/libpcre.* when REGEX=pcre
PCREDIR	:= $(shell pcre-config --prefix 2>/dev/null || :)
#PCREDIR=/usr/local

# This is for Linux 2.4 with netfilter
COPTS.linux24 = -O2 -DNETFILTER
LIBS.linux24 =

# This is for Linux 2.2
COPTS.linux22 = -O2 -DUSE_GETSOCKNAME
LIBS.linux22 =

# This is for Solaris 8
COPTS.solaris = -O2 -fomit-frame-pointer -DSOLARIS
LIBS.solaris = -lnsl -lsocket

# This is for Solaris 8 on UltraSparc2 processor
COPTS.solarisv9 = -O6 -mcpu=v9 -fomit-frame-pointer -DSOLARIS
LIBS.solarisv9 = -lnsl -lsocket

# This is for OpenBSD 3.0
COPTS.openbsd = -O2
LIBS.openbsd =

COPTS.libc=
LIBS.libs=

COPTS.pcre=-DUSE_PCRE -I$(PCREDIR)/include
LIBS.pcre=-L$(PCREDIR)/lib -lpcreposix -lpcre

#DEBUG =
DEBUG = -g

COPTS=$(COPTS.$(TARGET)) $(COPTS.$(REGEX))
LIBS=$(LIBS.$(TARGET)) $(LIBS.$(REGEX))

# - use -DSTATTIME=0 to disable statistics, else specify an interval in
#   milliseconds.
# - use -DTPROXY to compile with transparent proxy support.
CFLAGS = -Wall $(COPTS) $(DEBUG) -DSTATTIME=0 -DTPROXY
LDFLAGS = -g

all: haproxy

haproxy: haproxy.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.[oas] *~ core haproxy test nohup.out gmon.out

