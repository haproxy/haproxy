/*
 * include/proto/signal.h
 * Asynchronous signal delivery functions.
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <signal.h>
#include <common/standard.h>
#include <types/signal.h>
#include <types/task.h>

extern int signal_queue_len;
extern struct signal_descriptor signal_state[];
extern struct pool_head *pool2_sig_handlers;

void signal_handler(int sig);
void __signal_process_queue();
int signal_init();
void deinit_signals();
struct sig_handler *signal_register_fct(int sig, void (*fct)(struct sig_handler *), int arg);
struct sig_handler *signal_register_task(int sig, struct task *task, int reason);
void signal_unregister_handler(struct sig_handler *handler);
void signal_unregister_target(int sig, void *target);

static inline void signal_process_queue()
{
	if (unlikely(signal_queue_len > 0))
		__signal_process_queue();
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
