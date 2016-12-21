DESTDIR =
PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin

CC = gcc
LD = $(CC)

CFLAGS  = -g -O2 -Wall -Werror -pthread
LDFLAGS = -lpthread  -levent -levent_pthreads
INCS += -I../../include
LIBS =

OBJS = spoa.o


spoa: $(OBJS)
	$(LD) $(LDFLAGS) $(LIBS) -o $@ $^

install: spoa
	install spoa $(DESTDIR)$(BINDIR)

clean:
	rm -f spoa $(OBJS)

%.o:	%.c
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<
