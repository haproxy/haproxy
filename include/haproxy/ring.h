/*
 * include/haproxy/ring.h
 * Exported functions for ring buffers used for disposable data.
 *
 * Copyright (C) 2000-2019 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_RING_H
#define _HAPROXY_RING_H

#include <stdlib.h>
#include <import/ist.h>
#include <haproxy/ring-t.h>

struct ring *ring_new(size_t size);
void ring_init(struct ring *ring, void* area, size_t size);
struct ring *ring_resize(struct ring *ring, size_t size);
void ring_free(struct ring *ring);
ssize_t ring_write(struct ring *ring, size_t maxlen, const struct ist pfx[], size_t npfx, const struct ist msg[], size_t nmsg);
int ring_attach(struct ring *ring);
void ring_detach_appctx(struct ring *ring, struct appctx *appctx, size_t ofs);
int ring_attach_cli(struct ring *ring, struct appctx *appctx);
int cli_io_handler_show_ring(struct appctx *appctx);
void cli_io_release_show_ring(struct appctx *appctx);

#endif /* _HAPROXY_RING_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
