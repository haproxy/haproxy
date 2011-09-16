EBTREE_DIR = ../../ebtree
INCLUDE  = -I../../include -I$(EBTREE_DIR)

CC       = gcc
OPTIMIZE = -O3

OBJS     = halog halog64

halog: halog.c fgets2.c
	$(CC) $(OPTIMIZE) -o $@ $(INCLUDE) $(EBTREE_DIR)/ebtree.c $(EBTREE_DIR)/eb32tree.c $(EBTREE_DIR)/eb64tree.c $(EBTREE_DIR)/ebmbtree.c $(EBTREE_DIR)/ebsttree.c $(EBTREE_DIR)/ebistree.c $(EBTREE_DIR)/ebimtree.c $^

halog64: halog.c fgets2-64.c
	$(CC) $(OPTIMIZE) -o $@ $(INCLUDE) $(EBTREE_DIR)/ebtree.c $(EBTREE_DIR)/eb32tree.c $(EBTREE_DIR)/eb64tree.c $(EBTREE_DIR)/ebmbtree.c $(EBTREE_DIR)/ebsttree.c $(EBTREE_DIR)/ebistree.c $(EBTREE_DIR)/ebimtree.c $^

clean:
	rm -f $(OBJS)
