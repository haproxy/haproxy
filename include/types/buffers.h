/*
  include/types/buffers.h
  Buffer management definitions, macros and inline functions.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
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

#ifndef _TYPES_BUFFERS_H
#define _TYPES_BUFFERS_H

#include <common/config.h>
#include <common/memory.h>

#include <sys/time.h>
#include <sys/types.h>

/* The BF_* macros designate Buffer Flags, which may be ORed in the bit field
 * member 'flags' in struct buffer.
 */
#define BF_SHUTR_PENDING        1
#define BF_SHUTR_DONE           2
#define BF_SHUTW_PENDING        4
#define BF_SHUTW_DONE           8

#define BF_PARTIAL_READ        16
#define BF_COMPLETE_READ       32
#define BF_READ_ERROR          64
#define BF_READ_NULL          128
#define BF_READ_STATUS        (BF_PARTIAL_READ|BF_COMPLETE_READ|BF_READ_ERROR|BF_READ_NULL)
#define BF_CLEAR_READ         (~BF_READ_STATUS)

#define BF_PARTIAL_WRITE      256
#define BF_COMPLETE_WRITE     512
#define BF_WRITE_ERROR        1024
#define BF_WRITE_NULL         2048
#define BF_WRITE_STATUS       (BF_PARTIAL_WRITE|BF_COMPLETE_WRITE|BF_WRITE_ERROR|BF_WRITE_NULL)
#define BF_CLEAR_WRITE        (~BF_WRITE_STATUS)



/* describes a chunk of string */
struct chunk {
	char *str;	/* beginning of the string itself. Might not be 0-terminated */
	int len;	/* size of the string from first to last char. <0 = uninit. */
};

struct buffer {
	unsigned int flags;             /* BF_* */
	struct timeval rex;             /* expiration date for a read  */
	struct timeval wex;             /* expiration date for a write */
	struct timeval cex;             /* expiration date for a connect */
	int rto;                        /* read timeout */
	int wto;                        /* write timeout */
	int cto;                        /* connect timeout */
	unsigned int l;                 /* data length */
	char *r, *w, *h, *lr;           /* read ptr, write ptr, last header ptr, last read */
	char *rlim;                     /* read limit, used for header rewriting */
	unsigned long long total;       /* total data read */
	char data[BUFSIZE];
};

#define sizeof_buffer   sizeof(struct buffer)
extern void **pool_buffer;


#endif /* _TYPES_BUFFERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
