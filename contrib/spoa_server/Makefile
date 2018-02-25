DESTDIR =
PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin

CC = gcc
LD = $(CC)

CFLAGS  = -g -O2 -Wall -Werror -pthread
LDFLAGS = -lpthread

OBJS = spoa.o

ifneq ($(USE_LUA),)
OBJS += ps_lua.o
ifneq ($(LUA_INC),)
CFLAGS += -I$(LUA_INC)
endif
ifneq ($(LUA_LIB),)
LDLIBS += -L$(LUA_LIB)
endif
LDLIBS += -ldl -Wl,--export-dynamic -llua -lm -Wl,--no-export-dynamic
endif

ifneq ($(USE_PYTHON),)
OBJS += ps_python.o
CFLAGS += -I/usr/include/python2.7
LDLIBS += -lpython2.7
endif

spoa: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: spoa
	install spoa $(DESTDIR)$(BINDIR)

clean:
	rm -f spoa $(OBJS)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<
