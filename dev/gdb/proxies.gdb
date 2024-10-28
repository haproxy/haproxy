# list proxies starting with the one in argument (typically $pxh)
define px_list
  set $p = (struct proxy *)$arg0
  while ($p != 0)
    printf "%p (", $p
    if $p->cap & 0x10
      printf "LB,"
    end
    if $p->cap & 0x1
      printf "FE,"
    end
    if $p->cap & 0x2
      printf "BE,"
    end
    printf "%s)", $p->id
    if $p->cap & 0x1
      printf " feconn=%u cmax=%u cum_conn=%llu cpsmax=%u", $p->feconn, $p->fe_counters.conn_max, $p->fe_counters.cum_conn, $p->fe_counters.cps_max
    end
    if $p->cap & 0x2
      printf " beconn=%u served=%u queued=%u qmax=%u cum_sess=%llu wact=%u", $p->beconn, $p->served, $p->queue.length, $p->be_counters.nbpend_max, $p->be_counters.cum_sess, $p->lbprm.tot_wact
    end
    printf "\n"
    set $p = ($p)->next
  end
end
