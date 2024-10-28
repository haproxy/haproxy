# sets $tag and $node from $arg0, for internal use only
define _ebtree_set_tag_node
  set $tag = (unsigned long)$arg0 & 0x1
  set $node = (unsigned long)$arg0 & 0xfffffffffffffffe
  set $node = (struct eb_node *)$node
end

# get root from any node (leaf of node), returns in $node
define ebtree_root
  set $node = (struct eb_root *)$arg0->node_p
  if $node == 0
    # sole node
    set $node = (struct eb_root *)$arg0->leaf_p
  end
  # walk up
  while 1
    _ebtree_set_tag_node $node
    if $node->branches.b[1] == 0
      break
    end
    set $node = $node->node_p
  end
  # root returned in $node
end

# returns $node filled with the first node of ebroot $arg0
define ebtree_first
  # browse ebtree left until encoutering leaf
  set $node = (struct eb_node *)$arg0->b[0]
  while 1
    _ebtree_set_tag_node $node
    if $tag == 0
      loop_break
    end
    set $node = (struct eb_root *)$node->branches.b[0]
  end
  # extract last node
  _ebtree_set_tag_node $node
end

# finds next ebtree node after $arg0, and returns it in $node
define ebtree_next
  # get parent
  set $node = (struct eb_root *)$arg0->leaf_p
  # Walking up from right branch, so we cannot be below root
  # while (eb_gettag(t) != EB_LEFT) // #define EB_LEFT 0
  while 1
    _ebtree_set_tag_node $node
    if $tag == 0
      loop_break
    end
    set $node = (struct eb_root *)$node->node_p
  end
  set $node = (struct eb_root *)$node->branches.b[1]
  # walk down (left side => 0)
  # while (eb_gettag(start) == EB_NODE) // #define EB_NODE 1
  while 1
    _ebtree_set_tag_node $node
    if $node == 0
      loop_break
    end
    if $tag != 1
      loop_break
    end
    set $node = (struct eb_root *)$node->branches.b[0]
  end
end


# sets $tag and $node from $arg0, for internal use only
define _ebsctree_set_tag_node
  set $tag = (unsigned long)$arg0 & 0x1
  set $node = (unsigned long)$arg0 & 0xfffffffffffffffe
  set $node = (struct eb32sc_node *)$node
end

# returns $node filled with the first node of ebroot $arg0
define ebsctree_first
  # browse ebsctree left until encoutering leaf
  set $node = (struct eb32sc_node *)$arg0->b[0]
  while 1
    _ebsctree_set_tag_node $node
    if $tag == 0
      loop_break
    end
    set $node = (struct eb_root *)$node->branches.b[0]
  end
  # extract last node
  _ebsctree_set_tag_node $node
end

# finds next ebtree node after $arg0, and returns it in $node
define ebsctree_next
  # get parent
  set $node = (struct eb_root *)$arg0->node.leaf_p
  # Walking up from right branch, so we cannot be below root
  # while (eb_gettag(t) != EB_LEFT) // #define EB_LEFT 0
  while 1
    _ebsctree_set_tag_node $node
    if $tag == 0
      loop_break
    end
    set $node = (struct eb_root *)$node->node.node_p
  end
  set $node = (struct eb_root *)$node->node.branches.b[1]
  # walk down (left side => 0)
  # while (eb_gettag(start) == EB_NODE) // #define EB_NODE 1
  while 1
    _ebsctree_set_tag_node $node
    if $node == 0
      loop_break
    end
    if $tag != 1
      loop_break
    end
    set $node = (struct eb_root *)$node->node.branches.b[0]
  end
end
