/*
 * include/proto/proto_uxst.h
 * This file contains UNIX-stream socket protocol definitions.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_PROTO_UXST_H
#define _PROTO_PROTO_UXST_H

#include <common/config.h>
#include <types/session.h>
#include <types/task.h>

void uxst_add_listener(struct listener *listener);
int uxst_pause_listener(struct listener *l);
int uxst_get_src(int fd, struct sockaddr *sa, socklen_t salen, int dir);
int uxst_get_dst(int fd, struct sockaddr *sa, socklen_t salen, int dir);

#endif /* _PROTO_PROTO_UXST_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
