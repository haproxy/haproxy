CC       = cc
OPTIMIZE = -O2 -g
DEFINE   =
INCLUDE  =
OBJS     = poll

poll: poll.c
	$(CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
