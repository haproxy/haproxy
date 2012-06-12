EBTREE_DIR = ../../ebtree
INCLUDE  = -I../../include -I$(EBTREE_DIR)

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
	$(CC) $(OPTIMIZE) $(DEFINE) -o $@ $(INCLUDE) $(EBTREE_DIR)/ebtree.c $(EBTREE_DIR)/eb32tree.c $(EBTREE_DIR)/eb64tree.c $(EBTREE_DIR)/ebmbtree.c $(EBTREE_DIR)/ebsttree.c $(EBTREE_DIR)/ebistree.c $(EBTREE_DIR)/ebimtree.c $^

clean:
	rm -f $(OBJS) *.[oas]
