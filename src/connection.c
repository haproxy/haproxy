/*
 * Connection management functions
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/compat.h>
#include <common/config.h>

#include <types/connection.h>
#include <types/stream_interface.h>

/* I/O callback for fd-based connections. It calls the read/write handlers
 * provided by the connection's sock_ops, which must be valid. It returns
 * FD_WAIT_*.
 */
int conn_fd_handler(int fd)
{
	struct stream_interface *si = fdtab[fd].owner;
	int ret = 0;

	if (!si)
		return ret;

	if (si->conn.flags & CO_FL_ERROR)
		return ret;

	if (fdtab[fd].ev & (FD_POLL_IN | FD_POLL_HUP | FD_POLL_ERR))
		if (!si->conn.data->read(fd))
			ret |= FD_WAIT_READ;

	if (si->conn.flags & CO_FL_ERROR)
		return ret;

	if (fdtab[fd].ev & (FD_POLL_OUT | FD_POLL_ERR))
		if (!si->conn.data->write(fd))
			ret |= FD_WAIT_WRITE;

	return ret;
}
