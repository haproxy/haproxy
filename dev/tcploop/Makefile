CC       = gcc
OPTIMIZE = -O2 -g
DEFINE   =
INCLUDE  =
OBJS     = tcploop

V = 0
Q = @
ifeq ($V,1)
Q=
endif

ifeq ($V,1)
cmd_CC = $(CC)
else
ifeq (3.81,$(firstword $(sort $(MAKE_VERSION) 3.81)))
# 3.81 or above
cmd_CC = $(info $   CC      $@) $(Q)$(CC)
else
# 3.80 or older
cmd_CC = $(Q)echo "  CC      $@";$(CC)
endif
endif

tcploop: tcploop.c
	$(cmd_CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
