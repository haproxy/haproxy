EBTREE_DIR = ../../ebtree
INCLUDE  = -I../../include -I$(EBTREE_DIR)
SRC      = ../../src

CC       = gcc

# note: it is recommended to also add -fomit-frame-pointer on i386
OPTIMIZE = -O3

# most recent glibc provide platform-specific optimizations that make
# memchr faster than the generic C implementation (eg: SSE and prefetch
# on x86_64). Try with an without. In general, on x86_64 it's better to
# use memchr using the define below.
# DEFINE   = -DUSE_MEMCHR
DEFINE   =

OBJS     = halog

halog: halog.c fgets2.c
	$(CC) $(OPTIMIZE) $(DEFINE) -o $@ $(INCLUDE) $(SRC)/ebtree.c $(SRC)/eb32tree.c $(SRC)/eb64tree.c $(SRC)/ebmbtree.c $(SRC)/ebsttree.c $(SRC)/ebistree.c $(SRC)/ebimtree.c $^

clean:
	rm -f $(OBJS) *.[oas]
