# list info about current threads (ptr, now_ms, queue, current)
define thread_dump
  set $t = 0
  while $t < $g.nbthread
    set $i = $ti[$t].pth_id
    set $h = $tc[$t].current
    printf "Tid %4d: pth=%p mono=%llu now_ms=%u fl=0x%02x rq=%d cq=%d current=%p\n", $t, $i, $tc[$t].curr_mono_time, (unsigned)(($tc[$t].curr_mono_time + now_offset)/1000000), $tc[$t].flags, $tc[$t].current_queue, $tc[$t].rq_total, $h
    set $t = $t + 1
  end
end
