# lists all tasks in the wait queue whose ebroot pointed to by $arg0
# e.g.
#   task_dump_wq &ha_tgroup_ctx[0].timers
#   task_dump_wq &ha_thread_ctx[0].timers
#
define task_dump_rq
   set $tot=0
   ebtree_first ($arg0)
   while ($node != 0)
      set $tot = $tot+1
      set $p = (struct task *)((void*)$node-(long)&((struct task*)0).rq)
      printf "task %p ",$p
      p -pretty off -- /a *$p
      ebtree_next $node
   end
   printf "Total: %d tasks.\n",$tot
end

define task_dump_wq
   set $tot=0
   ebtree_first ($arg0)
   while ($node != 0)
      set $tot = $tot+1
      set $p = (struct task *)((void*)$node-(long)&((struct task*)0).wq)
      printf "task %p ",$p
      p -pretty off -- /a *$p
      ebtree_next $node
   end
   printf "Total: %d tasks.\n",$tot
end

