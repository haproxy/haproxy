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
#include <types/stream_interface.h>

/* The BF_* macros designate Buffer Flags, which may be ORed in the bit field
 * member 'flags' in struct buffer. Here we have several types of flags :
 *
 *   - pure status flags, reported by the lower layer, which must be cleared
 *     before doing further I/O :
 *     BF_*_NULL, BF_*_PARTIAL
 *
 *   - pure status flags, reported by mid-layer, which must also be cleared
 *     before doing further I/O :
 *     BF_*_TIMEOUT, BF_*_ERROR
 *
 *   - read-only indicators reported by lower levels :
 *     BF_STREAMER, BF_STREAMER_FAST
 *
 *   - write-once status flags reported by the mid-level : BF_SHUTR, BF_SHUTW
 *
 *   - persistent control flags managed only by higher level :
 *     BF_SHUT*_NOW, BF_*_ENA, BF_HIJACK
 *
 * The flags have been arranged for readability, so that the read and write
 * bits have se same position in a byte (read being the lower byte and write
 * the second one).
 */

#define BF_READ_NULL      0x000001  /* last read detected on producer side */
#define BF_READ_PARTIAL   0x000002  /* some data were read from producer */
#define BF_READ_TIMEOUT   0x000004  /* timeout while waiting for producer */
#define BF_READ_ERROR     0x000008  /* unrecoverable error on producer side */
#define BF_READ_ACTIVITY  (BF_READ_NULL|BF_READ_PARTIAL|BF_READ_ERROR)

#define BF_FULL           0x000010  /* buffer cannot accept any more data (l >= rlim-data) */
#define BF_SHUTR          0x000020  /* producer has already shut down */
#define BF_SHUTR_NOW      0x000040  /* the producer must shut down for reads immediately */
#define BF_READ_ENA       0x000080  /* producer is allowed to feed data into the buffer */

#define BF_WRITE_NULL     0x000100  /* write(0) or connect() succeeded on consumer side */
#define BF_WRITE_PARTIAL  0x000200  /* some data were written to the consumer */
#define BF_WRITE_TIMEOUT  0x000400  /* timeout while waiting for consumer */
#define BF_WRITE_ERROR    0x000800  /* unrecoverable error on consumer side */
#define BF_WRITE_ACTIVITY (BF_WRITE_NULL|BF_WRITE_PARTIAL|BF_WRITE_ERROR)

#define BF_EMPTY          0x001000  /* buffer is empty */
#define BF_SHUTW          0x002000  /* consumer has already shut down */
#define BF_SHUTW_NOW      0x004000  /* the consumer must shut down for writes immediately */
#define BF_WRITE_ENA      0x008000  /* consumer is allowed to forward all buffer contents */

#define BF_STREAMER       0x010000  /* the producer is identified as streaming data */
#define BF_STREAMER_FAST  0x020000  /* the consumer seems to eat the stream very fast */

/* When either BF_SHUTR_NOW or BF_HIJACK is set, it is strictly forbidden for
 * the stream interface to alter the buffer contents. When BF_SHUTW_NOW is set,
 * it is strictly forbidden for the stream interface to send anything from the
 * buffer.
 */
#define BF_HIJACK         0x040000  /* the producer is temporarily replaced */
#define BF_ANA_TIMEOUT    0x080000  /* the analyser timeout has expired */
#define BF_READ_ATTACHED  0x100000  /* the read side is attached for the first time */

/* Use these masks to clear the flags before going back to lower layers */
#define BF_CLEAR_READ     (~(BF_READ_NULL|BF_READ_PARTIAL|BF_READ_ERROR|BF_READ_ATTACHED))
#define BF_CLEAR_WRITE    (~(BF_WRITE_NULL|BF_WRITE_PARTIAL|BF_WRITE_ERROR))
#define BF_CLEAR_TIMEOUT  (~(BF_READ_TIMEOUT|BF_WRITE_TIMEOUT|BF_ANA_TIMEOUT))

/* Masks which define input events for stream analysers */
#define BF_MASK_ANALYSER        (BF_READ_ATTACHED|BF_READ_ACTIVITY|BF_READ_TIMEOUT|BF_ANA_TIMEOUT|BF_WRITE_ACTIVITY)

/* Mask for static flags which are not events, but might change during processing */
#define BF_MASK_STATIC          (BF_EMPTY|BF_FULL|BF_HIJACK|BF_WRITE_ENA|BF_READ_ENA|BF_SHUTR|BF_SHUTW|BF_SHUTR_NOW|BF_SHUTW_NOW)


/* Analysers (buffer->analysers).
 * Those bits indicate that there are some processing to do on the buffer
 * contents. It will probably evolved into a linked list later. Those
 * analysers could be compared to higher level processors.
 * The field is blanked by buffer_init() and only by analysers themselves
 * afterwards.
 */
#define AN_REQ_INSPECT          0x00000001  /* inspect request contents */
#define AN_REQ_HTTP_HDR         0x00000002  /* inspect HTTP request headers */
#define AN_REQ_HTTP_BODY        0x00000004  /* inspect HTTP request body */
#define AN_REQ_HTTP_TARPIT      0x00000008  /* wait for end of HTTP tarpit */
#define AN_RTR_HTTP_HDR         0x00000010  /* inspect HTTP response headers */

/* describes a chunk of string */
struct chunk {
	char *str;	/* beginning of the string itself. Might not be 0-terminated */
	int len;	/* size of the string from first to last char. <0 = uninit. */
};

struct buffer {
	unsigned int flags;             /* BF_* */
	int rex;                        /* expiration date for a read, in ticks */
	int wex;                        /* expiration date for a write or connect, in ticks */
	int rto;                        /* read timeout, in ticks */
	int wto;                        /* write timeout, in ticks */
	int cto;                        /* connect timeout, in ticks */
	unsigned int l;                 /* data length */
	char *r, *w, *lr;               /* read ptr, write ptr, last read */
	char *rlim;                     /* read limit, used for header rewriting */
	unsigned int analysers;         /* bit field indicating what to do on the buffer */
	int analyse_exp;                /* expiration date for current analysers (if set) */
	unsigned char xfer_large;       /* number of consecutive large xfers */
	unsigned char xfer_small;       /* number of consecutive small xfers */
	unsigned long long total;       /* total data read */
	struct stream_interface *prod;  /* producer attached to this buffer */
	struct stream_interface *cons;  /* consumer attached to this buffer */
	char data[BUFSIZE];
};


#endif /* _TYPES_BUFFERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
