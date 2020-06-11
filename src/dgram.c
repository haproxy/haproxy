/*
 * Datagram processing functions
 *
 * Copyright 2014 Baptiste Assmann <bedis9@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/fd.h>
#include <haproxy/dgram.h>

/* datagram handler callback */
void dgram_fd_handler(int fd)
{
	struct dgram_conn *dgram = fdtab[fd].owner;

	if (unlikely(!dgram))
		return;

	if (fd_recv_ready(fd))
		dgram->data->recv(dgram);
	if (fd_send_ready(fd))
		dgram->data->send(dgram);

	return;
}
