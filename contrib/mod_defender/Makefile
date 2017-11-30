DESTDIR    =
PREFIX     = /usr/local
BINDIR     = $(PREFIX)/bin

CC ?= gcc
LD = $(CC)

CXX ?= g++

ifeq ($(MOD_DEFENDER_SRC),)
MOD_DEFENDER_SRC := ./mod_defender_src
endif

ifeq ($(APACHE2_INC),)
APACHE2_INC := /usr/include/apache2
endif

ifeq ($(APR_INC),)
APR_INC := /usr/include/apr-1.0
endif

ifeq ($(EVENT_LIB),)
EVENT_LIB := -levent
endif

ifeq ($(EVENT_INC),)
EVENT_INC := /usr/include
endif

CFLAGS  += -g -Wall -pthread
INCS += -I../../include -I../../ebtree -I$(MOD_DEFENDER_SRC) -I$(APACHE2_INC) -I$(APR_INC) -I$(EVENT_INC)
LIBS += -lpthread  $(EVENT_LIB) -levent_pthreads -lapr-1 -laprutil-1 -lstdc++ -lm

CXXFLAGS = -g -std=gnu++11
CXXINCS += -I$(MOD_DEFENDER_SRC) -I$(MOD_DEFENDER_SRC)/deps -I$(APACHE2_INC) -I$(APR_INC)

SRCS = standalone.o spoa.o defender.o \
	$(wildcard $(MOD_DEFENDER_SRC)/deps/libinjection/*.c)
OBJS = $(patsubst %.c, %.o, $(SRCS))

CXXSRCS = $(wildcard $(MOD_DEFENDER_SRC)/*.cpp)
CXXOBJS = $(patsubst %.cpp, %.o, $(CXXSRCS))

defender: $(OBJS) $(CXXOBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

install: defender
	install defender $(DESTDIR)$(BINDIR)

clean:
	rm -f defender $(OBJS) $(CXXOBJS)

%.o:	%.c
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

%.o:	%.cpp
	$(CXX) $(CXXFLAGS) $(CXXINCS) -c -o $@ $<
