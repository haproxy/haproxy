INCLUDE  = -I../../include
OPTIMIZE = -O3 -mtune=pentium-m
CC       = gcc

OBJS     = halog

halog: halog.c
	$(CC) $(OPTIMIZE) -o $@ $(INCLUDE) ../../src/ebtree.c ../../src/eb32tree.c $^

clean:
	rm -vf $(OBJS)
