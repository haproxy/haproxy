/*
 * Server management functions.
 *
 * Copyright 2000-2006 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2008 Krzysztof Piotr Oledzki <ole@ans.pl>
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

int srv_getinter(struct server *s) {

	if ((s->state & SRV_CHECKED) && (s->health == s->rise + s->fall - 1))
		return s->inter;

	if (!(s->state & SRV_RUNNING) && s->health==0)
		return (s->downinter)?(s->downinter):(s->inter);

	return (s->fastinter)?(s->fastinter):(s->inter);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
