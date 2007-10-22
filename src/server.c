/*
 * Server management functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/time.h>

#include <types/backend.h>
#include <types/proxy.h>
#include <types/server.h>

int srv_downtime(struct server *s) {

	if ((s->state & SRV_RUNNING) && s->last_change < now.tv_sec)		// ignore negative time
		return s->down_time;

	return now.tv_sec - s->last_change + s->down_time;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
