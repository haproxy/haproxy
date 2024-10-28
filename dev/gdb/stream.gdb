# list all streams for all threads
define stream_dump
  set $t = 0
  while $t < $g.nbthread
    set $h = &$tc[$t].streams
    printf "Tid %4d: &streams=%p\n", $t, $h
    set $p = *(void **)$h
    while ($p != $h)
      set $s = (struct stream *)(((char *)$p) - (unsigned long)&((struct stream *)0)->list)
      printf "  &list=%#lx strm=%p uid=%u strm.fe=%s strm.flg=%#x strm.list={n=%p,p=%p}\n", $p, $s, $s->uniq_id, $s->sess->fe->id, $s->flags, $s->list.n, $s->list.p
      if ($p == 0)
         loop_break
      end
      set $p = *(void **)$p
    end
    set $t = $t + 1
  end
end
