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

# "--embed" flag is supported (and required) only from python 3.8+
check_python_config := $(shell if python3-config --embed > /dev/null 2>&1 ; then echo "python3.8+"; \
elif hash python3-config > /dev/null 2>&1 ; then echo "python3"; \
elif hash python-config > /dev/null 2>&1 ; then echo "python2"; fi)

ifeq ($(check_python_config), python3.8+)
PYTHON_DEFAULT_INC := $(shell python3-config --includes)
PYTHON_DEFAULT_LIB := $(shell python3-config --libs --embed)
else ifeq ($(check_python_config), python3)
PYTHON_DEFAULT_INC := $(shell python3-config --includes)
PYTHON_DEFAULT_LIB := $(shell python3-config --libs)
else ifeq ($(check_python_config), python2)
PYTHON_DEFAULT_INC := $(shell python-config --includes)
PYTHON_DEFAULT_LIB := $(shell python-config --libs)
endif


# Add default path
ifneq ($(PYTHON_DEFAULT_INC),)
CFLAGS += $(PYTHON_DEFAULT_INC)
else
CFLAGS += -I/usr/include/python2.7
endif
ifneq ($(PYTHON_DEFAULT_LIB),)
LDLIBS += $(PYTHON_DEFAULT_LIB)
else
LDLIBS += -lpython2.7
endif

# Add user additional paths if any
ifneq ($(PYTHON_INC),)
CFLAGS += -I$(PYTHON_INC)
endif
ifneq ($(PYTHON_LIB),)
LDLIBS += -L$(PYTHON_LIB)
endif

LDLIBS +=-Wl,--export-dynamic
endif

spoa: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: spoa
	install spoa $(DESTDIR)$(BINDIR)

clean:
	rm -f spoa $(OBJS)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<
