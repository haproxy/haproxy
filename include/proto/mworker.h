/*
 * Master Worker
 *
 * Copyright HAProxy Technologies 2019 - William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef PROTO_MWORKER_H_
#define PROTO_MWORKER_H_

#include <types/signal.h>

void mworker_proc_list_to_env();
void mworker_env_to_proc_list();


void mworker_block_signals();
void mworker_unblock_signals();

void mworker_broadcast_signal(struct sig_handler *sh);
void mworker_catch_sighup(struct sig_handler *sh);
void mworker_catch_sigterm(struct sig_handler *sh);
void mworker_catch_sigchld(struct sig_handler *sh);

void mworker_accept_wrapper(int fd);

void mworker_cleanlisteners();

int mworker_child_nb();

int mworker_ext_launch_all();

void mworker_kill_max_reloads(int sig);

void mworker_free_child(struct mworker_proc *);

#endif /* PROTO_MWORKER_H_ */
