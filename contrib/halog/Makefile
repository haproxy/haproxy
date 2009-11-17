EBTREE_DIR = ../../ebtree
INCLUDE  = -I../../include -I$(EBTREE_DIR)
OPTIMIZE = -O3

OBJS     = halog halog64

halog: halog.c fgets2.c
	$(CC) $(OPTIMIZE) -o $@ $(INCLUDE) $(EBTREE_DIR)/ebtree.c $(EBTREE_DIR)/eb32tree.c $^

halog64: halog.c fgets2-64.c
	$(CC) $(OPTIMIZE) -o $@ $(INCLUDE) $(EBTREE_DIR)/ebtree.c $(EBTREE_DIR)/eb32tree.c $^

clean:
	rm -vf $(OBJS)
