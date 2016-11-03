DESTDIR =
PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin

CC = gcc
LD = $(CC)

CFLAGS  = -g -O2 -Wall -Werror -pthread
LDFLAGS = -lpthread

OBJS = spoa.o


spoa: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

install: spoa
	install spoa $(DESTDIR)$(BINDIR)

clean:
	rm -f spoa $(OBJS)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<
