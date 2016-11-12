CC       = gcc
OPTIMIZE = -O2 -g
DEFINE   =
INCLUDE  =
OBJS     = tcploop

tcploop: tcploop.c
	$(CC) $(OPTIMIZE) $(DEFINE) $(INCLUDE) -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
