/*
  include/proto/server.h
  This file defines everything related to servers.

  Copyright (C) 2000-2009 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _PROTO_SERVER_H
#define _PROTO_SERVER_H

#include <unistd.h>

#include <common/config.h>
#include <types/proxy.h>
#include <types/queue.h>
#include <types/server.h>

#include <proto/queue.h>
#include <proto/freq_ctr.h>

int srv_downtime(struct server *s);
int srv_getinter(struct server *s);

/* increase the number of cumulated connections on the designated server */
static void inline srv_inc_sess_ctr(struct server *s)
{
	s->counters.cum_sess++;
	update_freq_ctr(&s->sess_per_sec, 1);
	if (s->sess_per_sec.curr_ctr > s->sps_max)
		s->sps_max = s->sess_per_sec.curr_ctr;
}

#endif /* _PROTO_SERVER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
