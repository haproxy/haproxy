CFLAGS = -O2 -Wall -g -I../../include -I../../ebtree -fwrapv -fno-strict-aliasing
OBJS = gen-rht gen-enc decode

all: $(OBJS)

%: %.c

clean:
	-rm -vf $(OBJS) *.o *.a *~
