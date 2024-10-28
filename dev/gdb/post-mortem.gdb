# This script will set the post_mortem struct pointer ($pm) from the one found
# in the "post_mortem" symbol. If not found or if not correct, it's the same
# address as the "_post_mortem" section, which can be found using "info files"
# or "objdump -h" on the executable. The guessed value is the by a first call
# to pm_init, but if not correct, you just need to call pm_init again with the
# correct pointer, e.g:
#   pm_init 0xcfd400

define pm_init
  set $pm = (struct post_mortem*)$arg0
  set $g = $pm.global
  set $ti = $pm.thread_info
  set $tc = $pm.thread_ctx
  set $tgi = $pm.tgroup_info
  set $tgc = $pm.tgroup_ctx
  set $fd = $pm.fdtab
  set $pxh = *$pm.proxies
  set $po  = $pm.pools
  set $ac  = $pm.activity
end

# show basic info on the running process (OS, uid, etc)
define pm_show_info
  print $pm->platform
  print $pm->process
end

# show thread IDs to easily map between gdb threads and tid
define pm_show_threads
  set $t = 0
  while $t < $g.nbthread
    printf "Tid %4d: pthread_id=%#lx  stack_top=%#lx\n", $t, $ti[$t].pth_id, $ti[$t].stack_top
    set $t = $t + 1
  end
end

# dump all threads' dump buffers
define pm_show_thread_dump
  set $t = 0
  while $t < $g.nbthread
    printf "%s\n", $tc[$t].thread_dump_buffer->area
    set $t = $t + 1
  end
end

# initialize the various pointers
pm_init &post_mortem
