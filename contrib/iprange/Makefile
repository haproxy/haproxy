CC       = gcc
OPTIMIZE = -O3
LDFLAGS  = -s

OBJS     = iprange

all: $(OBJS)

%: %.c
	$(CC) $(LDFLAGS) $(OPTIMIZE) -o $@ $^

clean:
	rm -f $(OBJS) *.o *.a *~
