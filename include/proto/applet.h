/*
 * include/proto/applet.h
 * This file contains applet function prototypes
 *
 * Copyright (C) 2000-2015 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _PROTO_APPLET_H
#define _PROTO_APPLET_H

#include <stdlib.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <types/applet.h>
#include <proto/connection.h>

extern unsigned int nb_applets;
extern unsigned int applets_active_queue;

extern struct list applet_active_queue;

void applet_run_active();


static int inline appctx_res_wakeup(struct appctx *appctx);


/* Initializes all required fields for a new appctx. Note that it does the
 * minimum acceptable initialization for an appctx. This means only the
 * 3 integer states st0, st1, st2 are zeroed.
 */
static inline void appctx_init(struct appctx *appctx)
{
	appctx->st0 = appctx->st1 = appctx->st2 = 0;
	appctx->io_release = NULL;
}

/* Tries to allocate a new appctx and initialize its main fields. The appctx
 * is returned on success, NULL on failure. The appctx must be released using
 * pool_free2(connection) or appctx_free(), since it's allocated from the
 * connection pool. <applet> is assigned as the applet, but it can be NULL.
 */
static inline struct appctx *appctx_new(struct applet *applet)
{
	struct appctx *appctx;

	appctx = pool_alloc2(pool2_connection);
	if (likely(appctx != NULL)) {
		appctx->obj_type = OBJ_TYPE_APPCTX;
		appctx->applet = applet;
		appctx_init(appctx);
		LIST_INIT(&appctx->runq);
		LIST_INIT(&appctx->buffer_wait.list);
		appctx->buffer_wait.target = appctx;
		appctx->buffer_wait.wakeup_cb = (int (*)(void *))appctx_res_wakeup;
		nb_applets++;
	}
	return appctx;
}

/* Releases an appctx previously allocated by appctx_new(). Note that
 * we share the connection pool.
 */
static inline void appctx_free(struct appctx *appctx)
{
	if (!LIST_ISEMPTY(&appctx->runq)) {
		LIST_DEL(&appctx->runq);
		applets_active_queue--;
	}
	if (!LIST_ISEMPTY(&appctx->buffer_wait.list)) {
		LIST_DEL(&appctx->buffer_wait.list);
		LIST_INIT(&appctx->buffer_wait.list);
	}
	pool_free2(pool2_connection, appctx);
	nb_applets--;
}

/* wakes up an applet when conditions have changed */
static inline void appctx_wakeup(struct appctx *appctx)
{
	if (LIST_ISEMPTY(&appctx->runq)) {
		LIST_ADDQ(&applet_active_queue, &appctx->runq);
		applets_active_queue++;
	}
}

/* removes an applet from the list of active applets */
static inline void appctx_pause(struct appctx *appctx)
{
	if (!LIST_ISEMPTY(&appctx->runq)) {
		LIST_DEL(&appctx->runq);
		LIST_INIT(&appctx->runq);
		applets_active_queue--;
	}
}

/* Callback used to wake up an applet when a buffer is available. The applet
 * <appctx> is woken up is if it is not already in the list of "active"
 * applets. This functions returns 1 is the stream is woken up, otherwise it
 * returns 0. */
static inline int appctx_res_wakeup(struct appctx *appctx)
{
	if (!LIST_ISEMPTY(&appctx->runq))
		return 0;
	appctx_wakeup(appctx);
	return 1;
}


#endif /* _PROTO_APPLET_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
