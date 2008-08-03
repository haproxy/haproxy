/*
  include/types/buffers.h
  Buffer management definitions, macros and inline functions.

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu
  
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

/* The BF_* macros designate Buffer Flags, which may be ORed in the bit field
 * member 'flags' in struct buffer.
 */
#define BF_SHUTR_PENDING        1  /* ignored if BF_SHUTW_DONE */
#define BF_SHUTR_DONE           2  /* takes precedence over BF_SHUTR_PENDING */
#define BF_SHUTR_STATUS         (BF_SHUTR_PENDING|BF_SHUTR_DONE)

#define BF_SHUTW_PENDING        4  /* ignored if BF_SHUTW_DONE */
#define BF_SHUTW_DONE           8  /* takes precedence over BF_SHUTW_PENDING */
#define BF_SHUTW_STATUS         (BF_SHUTW_PENDING|BF_SHUTW_DONE)

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

#define BF_STREAMER           4096
#define BF_STREAMER_FAST      8192


/* describes a chunk of string */
struct chunk {
	char *str;	/* beginning of the string itself. Might not be 0-terminated */
	int len;	/* size of the string from first to last char. <0 = uninit. */
};

struct buffer {
	unsigned int flags;             /* BF_* */
	int rex;                        /* expiration date for a read, in ticks */
	int wex;                        /* expiration date for a write, in ticks */
	int cex;                        /* expiration date for a connect, in ticks */
	int rto;                        /* read timeout, in ticks */
	int wto;                        /* write timeout, in ticks */
	int cto;                        /* connect timeout, in ticks */
	unsigned int l;                 /* data length */
	char *r, *w, *lr;               /* read ptr, write ptr, last read */
	char *rlim;                     /* read limit, used for header rewriting */
	unsigned char xfer_large;       /* number of consecutive large xfers */
	unsigned char xfer_small;       /* number of consecutive small xfers */
	unsigned long long total;       /* total data read */
	char data[BUFSIZE];
};


#endif /* _TYPES_BUFFERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
