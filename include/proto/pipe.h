/*
  include/proto/pipe.h
  Pipe management

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

#ifndef _PROTO_PIPE_H
#define _PROTO_PIPE_H

#include <common/config.h>
#include <types/pipe.h>

extern int pipes_used;	/* # of pipes in use (2 fds each) */
extern int pipes_free;	/* # of pipes unused (2 fds each) */

/* return a pre-allocated empty pipe. Try to allocate one if there isn't any
 * left. NULL is returned if a pipe could not be allocated.
 */
struct pipe *get_pipe();

/* destroy a pipe, possibly because an error was encountered on it. Its FDs
 * will be closed and it will not be reinjected into the live pool.
 */
void kill_pipe(struct pipe *p);

/* put back a unused pipe into the live pool. If it still has data in it, it is
 * closed and not reinjected into the live pool. The caller is not allowed to
 * use it once released.
 */
void put_pipe(struct pipe *p);

#endif /* _PROTO_PIPE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
