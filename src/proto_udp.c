/*
 * UDP protocol related functions
 *
 * Copyright 2014 Baptiste Assmann <bedis9@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <types/global.h>
#include <types/fd.h>
#include <types/proto_udp.h>

#include <proto/fd.h>

/* datagram handler callback */
int dgram_fd_handler(int fd)
{
	struct dgram_conn *dgram = fdtab[fd].owner;

	if (unlikely(!dgram))
		return 0;

	if (fd_recv_ready(fd))
		dgram->data->recv(dgram);
	else if (fd_send_ready(fd))
		dgram->data->send(dgram);

	return 0;
}
