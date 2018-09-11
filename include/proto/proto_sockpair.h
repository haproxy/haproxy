/*
 * Socket Pair protocol layer (sockpair)
 *
 * Copyright HAProxy Technologies - William Lallemand <wlallemand@haproxy.com>
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

#ifndef _PROTO_PROTO_SOCKPAIR_H
# define _PROTO_PROTO_SOCKPAIR_H

int recv_fd_uxst(int sock);
int send_fd_uxst(int fd, int send_fd);

#endif /* _PROTO_PROTO_SOCKPAIR_H  */

