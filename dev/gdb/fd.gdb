# list info about open FD
define fd_dump
  set $f = 0
  while $f < $g.maxsock
    if fdtab[$f].owner != 0
      printf "fd %5d: rm=%#lx tm=%#lx um=%#lx cb=%p ownr=%p st=%#x refc=%#x tkov=%u gen=%u\n", $f, fdtab[$f].running_mask, fdtab[$f].thread_mask, fdtab[$f].update_mask, fdtab[$f].iocb, fdtab[$f].owner, fdtab[$f].state, fdtab[$f].refc_tgid, fdtab[$f].nb_takeover, fdtab[$f].generation
    end
    set $f = $f + 1
  end
end

# only those attached to a listener
define fd_dump_listener
  set $f = 0
  while $f < $g.maxsock
    if fdtab[$f].owner != 0 && fdtab[$f].iocb == &sock_accept_iocb
      set $c = (struct listener *)fdtab[$f].owner
      printf "fd %5d: rm=%#lx tm=%#lx um=%#lx st=%#x refc=%#x tkov=%u gen=%u listener=%p(%s): flg=%#x state=%d fe=%p(%s) acc=%p\n", $f, fdtab[$f].running_mask, fdtab[$f].thread_mask, fdtab[$f].update_mask, fdtab[$f].state, fdtab[$f].refc_tgid, fdtab[$f].nb_takeover, fdtab[$f].generation, fdtab[$f].owner, $c->name, $c->flags, $c->state, $c->bind_conf.frontend, $c->bind_conf.frontend.id, $c->bind_conf.accept
    end
    set $f = $f + 1
  end
end

# only those attached to a connection
define fd_dump_conn
  set $f = 0
  while $f < $g.maxsock
    if fdtab[$f].owner != 0 && fdtab[$f].iocb == &sock_conn_iocb
      set $c = (struct connection *)fdtab[$f].owner
      printf "fd %5d: rm=%#lx tm=%#lx um=%#lx st=%#x refc=%#x tkov=%u gen=%u conn=%p: flg=%#x err=%#x ctrl=%p xprt=%p mux=%p", $f, fdtab[$f].running_mask, fdtab[$f].thread_mask, fdtab[$f].update_mask, fdtab[$f].state, fdtab[$f].refc_tgid, fdtab[$f].nb_takeover, fdtab[$f].generation, fdtab[$f].owner, $c->flags, $c->err_code, $c->ctrl, $c->xprt, $c->mux
      if *$c->target == OBJ_TYPE_LISTENER
        set $s = (struct session *)$c->owner
        printf " sess=%p: fe=%p id=%s age=%dms", $s, $s->fe, $s->fe->id, (*global_now_ns - $s->accept_ts) / 1000000
      end
      printf "\n"
    end
    set $f = $f + 1
  end
end
