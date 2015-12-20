INCLUDE  = -I../../include -I../../ebtree

CC       = gcc
OPTIMIZE = -O2
DEFINE   =
OBJS     = flags

flags: flags.c
	$(CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
