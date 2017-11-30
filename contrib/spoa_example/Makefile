DESTDIR =
PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin

CC = gcc
LD = $(CC)

CFLAGS  = -g -O2 -Wall -Werror -pthread
INCS += -I../../ebtree -I./include
LIBS = -lpthread -levent -levent_pthreads

OBJS = spoa.o


spoa: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

install: spoa
	install spoa $(DESTDIR)$(BINDIR)

clean:
	rm -f spoa $(OBJS)

%.o:	%.c
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<
