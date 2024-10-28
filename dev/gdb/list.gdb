# lists entries starting at list head $arg0
define list_dump
  set $h = $arg0
  set $p = *(void **)$h
  while ($p != $h)
    printf "%#lx\n", $p
    if ($p == 0)
      loop_break
    end
    set $p = *(void **)$p
  end
end

# list all entries starting at list head $arg0 until meeting $arg1
define list_find
  set $h = $arg0
  set $k = $arg1
  set $p = *(void **)$h
  while ($p != $h)
    printf "%#lx\n", $p
    if ($p == 0 || $p == $k)
      loop_break
    end
    set $p = *(void **)$p
  end
end
