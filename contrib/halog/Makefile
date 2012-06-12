EBTREE_DIR = ../../ebtree
INCLUDE  = -I../../include -I$(EBTREE_DIR)

CC       = gcc

# note: it is recommended to also add -fomit-frame-pointer on i386
OPTIMIZE = -O3

OBJS     = halog

halog: halog.c fgets2.c
	$(CC) $(OPTIMIZE) -o $@ $(INCLUDE) $(EBTREE_DIR)/ebtree.c $(EBTREE_DIR)/eb32tree.c $(EBTREE_DIR)/eb64tree.c $(EBTREE_DIR)/ebmbtree.c $(EBTREE_DIR)/ebsttree.c $(EBTREE_DIR)/ebistree.c $(EBTREE_DIR)/ebimtree.c $^

clean:
	rm -f $(OBJS) *.[oas]
