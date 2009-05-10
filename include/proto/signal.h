/*
 * Asynchronous signal delivery functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
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

extern int signal_queue_len;
extern struct signal_descriptor signal_state[];

void signal_init();
void signal_handler(int sig);
void signal_register(int sig, void (*handler)(int));
void __signal_process_queue();

static inline void signal_process_queue()
{
	if (unlikely(signal_queue_len > 0))
		__signal_process_queue();
}
