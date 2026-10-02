include ../../include/make/verbose.mk

CC       = gcc
OPTIMIZE = -O2 -g
DEFINE   =
INCLUDE  =
OBJS     = sse-latency

sse-latency: sse-latency.c
	$(cmd_CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
