CC       = gcc
OPTIMIZE = -O3
LDFLAGS  = -s

OBJS     = ip6range

all: $(OBJS)

%: %.c
	$(CC) $(LDFLAGS) $(OPTIMIZE) -o $@ $^

clean:
	rm -f $(OBJS) *.o *.a *~
