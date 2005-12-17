CC = gcc
LD = gcc

COPTS = -O2 -g -DSTATTIME=0
LIBS =

# to compile under solaris, uncomment these two lines
#COPTS = -O2 -fomit-frame-pointer -DSOLARIS
#LIBS = -lnsl -lsocket

CFLAGS = -Wall $(COPTS)
LDFLAGS = -g

all: haproxy

haproxy: haproxy.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -vf *.[oas] *~ core haproxy test nohup.out gmon.out
