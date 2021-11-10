/*
 * include/haproxy/mworker-t.h
 * Master Worker type definitions.
 *
 * Copyright HAProxy Technologies 2019 - William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _HAPROXY_MWORKER_T_H_
#define _HAPROXY_MWORKER_T_H_

#include <haproxy/list.h>
#include <haproxy/signal-t.h>

/* options for mworker_proc */

#define PROC_O_TYPE_MASTER           0x00000001
#define PROC_O_TYPE_WORKER           0x00000002
#define PROC_O_TYPE_PROG             0x00000004
/* 0x00000008 unused */
#define PROC_O_LEAVING               0x00000010  /* this process should be leaving */
/* 0x00000020 to 0x00000080 unused */
#define PROC_O_START_RELOAD          0x00000100  /* Start the process even if the master was re-executed */

/*
 * Structure used to describe the processes in master worker mode
 */
struct server;
struct mworker_proc {
	int pid;
	int options;
	char *id;
	char **command;
	char *path;
	char *version;
	int ipc_fd[2]; /* 0 is master side, 1 is worker side */
	int reloads;
	int failedreloads; /* number of failed reloads since the last successful one */
	int timestamp;
	struct server *srv; /* the server entry in the master proxy */
	struct list list;
	int uid;
	int gid;
};

#endif /* _HAPROXY_MWORKER_T_H_ */
