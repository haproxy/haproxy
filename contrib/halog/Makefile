INCLUDE  = -I../../include
#OPTIMIZE = -O3 -mtune=pentium-m
OPTIMIZE = -O3

OBJS     = halog halog64

halog: halog.c fgets2.c
	$(CC) $(OPTIMIZE) -o $@ $(INCLUDE) ../../src/ebtree.c ../../src/eb32tree.c $^

halog64: halog.c fgets2-64.c
	$(CC) $(OPTIMIZE) -o $@ $(INCLUDE) ../../src/ebtree.c ../../src/eb32tree.c $^

clean:
	rm -vf $(OBJS)
