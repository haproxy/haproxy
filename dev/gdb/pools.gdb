# dump pool contents (2.9 and above, with buckets)
define pools_dump
  set $h = $po
  set $p = *(void **)$h
  while ($p != $h)
    set $e = (struct pool_head *)(((char *)$p) - (unsigned long)&((struct pool_head *)0)->list)

    set $total = 0
    set $used = 0
    set $idx = 0
    while $idx < sizeof($e->buckets) / sizeof($e->buckets[0])
      set $total=$total + $e->buckets[$idx].allocated
      set $used=$used + $e->buckets[$idx].used
      set $idx=$idx + 1
    end

    set $mem = $total * $e->size
    printf "list=%#lx pool_head=%p name=%s size=%u alloc=%u used=%u mem=%u\n", $p, $e, $e->name, $e->size, $total, $used, $mem
    set $p = *(void **)$p
  end
end
