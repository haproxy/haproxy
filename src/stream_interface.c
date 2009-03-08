/*
 * Functions managing stream_interface structures
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/buffers.h>
#include <proto/client.h>
#include <proto/fd.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

/*
 * This function only has to be called once after a wakeup event in case of
 * suspected timeout. It controls the stream interface timeouts and sets
 * si->flags accordingly. It does NOT close anything, as this timeout may
 * be used for any purpose. It returns 1 if the timeout fired, otherwise
 * zero.
 */
int stream_int_check_timeouts(struct stream_interface *si)
{
	if (tick_is_expired(si->exp, now_ms)) {
		si->flags |= SI_FL_EXP;
		return 1;
	}
	return 0;
}

/* to be called only when in SI_ST_DIS with SI_FL_ERR */
void stream_int_report_error(struct stream_interface *si)
{
	if (!si->err_type)
		si->err_type = SI_ET_DATA_ERR;

	si->ob->flags |= BF_WRITE_ERROR;
	si->ib->flags |= BF_READ_ERROR;
}

/*
 * Erase any content from input and output buffers, and return a message into
 * the output buffer. The message is provided as a "chunk". If it is null,
 * then an empty message is used.
 */
void stream_int_return(struct stream_interface *si, const struct chunk *msg)
{
	buffer_erase(si->ib);
	buffer_erase(si->ob);
	if (msg && msg->len)
		buffer_write(si->ob, msg->str, msg->len);
}

/*
 * Returns a message to the client ; the connection is shut down for read,
 * and the request is cleared so that no server connection can be initiated.
 * The buffer is marked for read shutdown on the other side to protect the
 * message, and the buffer write is enabled. The message is contained in a
 * "chunk". If it is null, then an empty message is used. The reply buffer
 * doesn't need to be empty before this. The goal of this function is to
 * return error messages to a client.
 */
void stream_int_retnclose(struct stream_interface *si, const struct chunk *msg)
{
	buffer_abort(si->ib);
	buffer_erase(si->ob);
	buffer_shutr_now(si->ob);
	if (msg && msg->len)
		buffer_write(si->ob, msg->str, msg->len);

	si->ob->wex = tick_add_ifset(now_ms, si->ob->wto);
	buffer_write_ena(si->ob);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
