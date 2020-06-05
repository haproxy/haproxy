/*
 * include/haproxy/mailer.h
 * This file lists exported variables and functions for mailers.
 *
 * Copyright 2015 Horms Solutions Ltd., Simon Horman <horms@verge.net.au>
 * Copyright 2020 Willy Tarreau <w@1wt.eu>
 *
 * Based on include/haproxy/peers-t.h
 *
 * Copyright 2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#ifndef _HAPROXY_MAILERS_H
#define _HAPROXY_MAILERS_H

#include <haproxy/mailers-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>

extern struct mailers *mailers;

int init_email_alert(struct mailers *mailers, struct proxy *p, char **err);
void send_email_alert(struct server *s, int priority, const char *format, ...)
	__attribute__ ((format(printf, 3, 4)));


#endif /* _HAPROXY_MAILERS_H */
