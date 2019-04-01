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

#include <stdlib.h>
#include <string.h>

#include <common/mini-clist.h>

#include <proto/mworker.h>

#include <types/global.h>



/*
 * serialize the proc list and put it in the environment
 */
void mworker_proc_list_to_env()
{
	char *msg = NULL;
	struct mworker_proc *child;

	list_for_each_entry(child, &proc_list, list) {
		if (child->pid > -1)
			memprintf(&msg, "%s|type=%c;fd=%d;pid=%d;rpid=%d;reloads=%d;timestamp=%d", msg ? msg : "", child->type, child->ipc_fd[0], child->pid, child->relative_pid, child->reloads, child->timestamp);
	}
	if (msg)
		setenv("HAPROXY_PROCESSES", msg, 1);
}

/*
 * unserialize the proc list from the environment
 */
void mworker_env_to_proc_list()
{
	char *msg, *token = NULL, *s1;

	msg = getenv("HAPROXY_PROCESSES");
	if (!msg)
		return;

	while ((token = strtok_r(msg, "|", &s1))) {
		struct mworker_proc *child;
		char *subtoken = NULL;
		char *s2;

		msg = NULL;

		child = calloc(1, sizeof(*child));

		while ((subtoken = strtok_r(token, ";", &s2))) {

			token = NULL;

			if (strncmp(subtoken, "type=", 5) == 0) {
				child->type = *(subtoken+5);
				if (child->type == 'm') /* we are in the master, assign it */
					proc_self = child;
			} else if (strncmp(subtoken, "fd=", 3) == 0) {
				child->ipc_fd[0] = atoi(subtoken+3);
			} else if (strncmp(subtoken, "pid=", 4) == 0) {
				child->pid = atoi(subtoken+4);
			} else if (strncmp(subtoken, "rpid=", 5) == 0) {
				child->relative_pid = atoi(subtoken+5);
			} else if (strncmp(subtoken, "reloads=", 8) == 0) {
				/* we reloaded this process once more */
				child->reloads = atoi(subtoken+8) + 1;
			} else if (strncmp(subtoken, "timestamp=", 10) == 0) {
				child->timestamp = atoi(subtoken+10);
			}
		}
		if (child->pid)
			LIST_ADDQ(&proc_list, &child->list);
		else
			free(child);
	}

	unsetenv("HAPROXY_PROCESSES");
}
