/*
 * include/haproxy/payload.h
 * Definitions for payload-based sample fetches and ACLs
 *
 * Copyright (C) 2000-2013 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_PAYLOAD_H
#define _HAPROXY_PAYLOAD_H

#include <haproxy/api.h>
#include <haproxy/sample-t.h>
#include <haproxy/stream-t.h>

int fetch_rdp_cookie_name(struct stream *s, struct sample *smp, const char *cname, int clen);
int val_payload_lv(struct arg *arg, char **err_msg);

#endif /* _HAPROXY_PAYLOAD_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
