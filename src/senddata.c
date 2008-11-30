/*
 * Helper functions to send data over a socket and buffer.
 * Should probably move somewhere else, but where ?
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/version.h>

#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/fd.h>
#include <proto/senddata.h>
#include <proto/session.h>

/*
 * returns a message to the client ; the connection is shut down for read,
 * and the request is cleared so that no server connection can be initiated.
 * The client must be in a valid state for this (HEADER, DATA ...).
 * Nothing is performed on the server side. The message is contained in a
 * "chunk". If it is null, then an empty message is used.
 * The reply buffer doesn't need to be empty before this.
 */
void client_retnclose(struct session *s, const struct chunk *msg)
{
	//FIXME: must move to lower level
	//EV_FD_CLR(s->cli_fd, DIR_RD);
	//EV_FD_SET(s->cli_fd, DIR_WR);
	buffer_abort(s->req);

	s->cli_state = CL_STSHUTR; // FIXME: still used by unix sockets
	buffer_flush(s->rep);
	buffer_shutr_now(s->rep);
	if (msg && msg->len)
		buffer_write(s->rep, msg->str, msg->len);

	s->rep->wex = tick_add_ifset(now_ms, s->rep->wto);
	buffer_write_ena(s->rep);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
