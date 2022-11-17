include ../../include/make/verbose.mk

CC       = cc
OPTIMIZE = -O2 -g
DEFINE   =
INCLUDE  =
OBJS     = poll

poll: poll.c
	$(cmd_CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
