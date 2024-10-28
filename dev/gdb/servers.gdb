# list servers in a proxy whose pointer is passed in argument
define px_list_srv
  set $h = (struct proxy *)$arg0
  set $p = ($h)->srv
  while ($p != 0)
    printf "%#lx %s maxconn=%u cur_sess=%u max_sess=%u served=%u queued=%u st=%u->%u ew=%u sps_max=%u\n", $p, $p->id, $p->maxconn, $p->cur_sess, $p->counters.cur_sess_max, $p->served, $p->queue.length, $p->cur_state, $p->next_state, $p->cur_eweight, $p->counters.sps_max
    set $p = ($p)->next
  end
end
