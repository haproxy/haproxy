include ../../include/make/verbose.mk

CC       = cc
OPTIMIZE = -O2 -g
DEFINE   =
INCLUDE  =
OBJS     = ncpu.so

all:	$(OBJS)

%.so: %.c
	$(cmd_CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -fPIC -shared -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
