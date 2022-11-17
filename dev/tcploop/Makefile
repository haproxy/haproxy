include ../../include/make/verbose.mk

CC       = gcc
OPTIMIZE = -O2 -g
DEFINE   =
INCLUDE  =
OBJS     = tcploop

tcploop: tcploop.c
	$(cmd_CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
