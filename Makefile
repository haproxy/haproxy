CC = gcc
LD = gcc

# This is for Linux 2.4
COPTS.linux = -O2
LIBS.linux =

# This is for solaris 8
COPTS.solaris = -O2 -fomit-frame-pointer -DSOLARIS -DHAVE_STRLCPY
LIBS.solaris = -lnsl -lsocket

# Select target OS. TARGET must match a system for which COPTS and LIBS are
# correctly defined above.
TARGET = linux
#TARGET = solaris

DEBUG =
#DEBUG = -g

COPTS=$(COPTS.$(TARGET))
LIBS=$(LIBS.$(TARGET))

CFLAGS = -Wall $(COPTS) -DSTATTIME=0
LDFLAGS = -g

all: haproxy

haproxy: haproxy.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -vf *.[oas] *~ core haproxy test nohup.out gmon.out
