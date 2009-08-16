/*
  include/types/buffers.h
  Buffer management definitions, macros and inline functions.

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

#define BF_FULL           0x000010  /* buffer cannot accept any more data (l >= max_len) */
#define BF_SHUTR          0x000020  /* producer has already shut down */
#define BF_SHUTR_NOW      0x000040  /* the producer must shut down for reads immediately */
#define BF_READ_NOEXP     0x000080  /* producer should not expire */

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
#define BF_HIJACK         0x040000  /* the producer is temporarily replaced by ->hijacker */
#define BF_ANA_TIMEOUT    0x080000  /* the analyser timeout has expired */
#define BF_READ_ATTACHED  0x100000  /* the read side is attached for the first time */
#define BF_KERN_SPLICING  0x200000  /* kernel splicing desired for this buffer */
#define BF_READ_DONTWAIT  0x400000  /* wake the task up after every read (eg: HTTP request) */

/* Use these masks to clear the flags before going back to lower layers */
#define BF_CLEAR_READ     (~(BF_READ_NULL|BF_READ_PARTIAL|BF_READ_ERROR|BF_READ_ATTACHED))
#define BF_CLEAR_WRITE    (~(BF_WRITE_NULL|BF_WRITE_PARTIAL|BF_WRITE_ERROR))
#define BF_CLEAR_TIMEOUT  (~(BF_READ_TIMEOUT|BF_WRITE_TIMEOUT|BF_ANA_TIMEOUT))

/* Masks which define input events for stream analysers */
#define BF_MASK_ANALYSER        (BF_READ_ATTACHED|BF_READ_ACTIVITY|BF_READ_TIMEOUT|BF_ANA_TIMEOUT|BF_WRITE_ACTIVITY)

/* Mask for static flags which are not events, but might change during processing */
#define BF_MASK_STATIC          (BF_EMPTY|BF_FULL|BF_HIJACK|BF_WRITE_ENA|BF_SHUTR|BF_SHUTW|BF_SHUTR_NOW|BF_SHUTW_NOW)


/* Analysers (buffer->analysers).
 * Those bits indicate that there are some processing to do on the buffer
 * contents. It will probably evolve into a linked list later. Those
 * analysers could be compared to higher level processors.
 * The field is blanked by buffer_init() and only by analysers themselves
 * afterwards.
 */
#define AN_REQ_INSPECT          0x00000001  /* inspect request contents */
#define AN_REQ_WAIT_HTTP        0x00000002  /* wait for an HTTP request */
#define AN_REQ_HTTP_PROCESS_FE  0x00000004  /* process the frontend's HTTP part */
#define AN_REQ_SWITCHING_RULES  0x00000008  /* apply the switching rules */
#define AN_REQ_HTTP_PROCESS_BE  0x00000010  /* process the backend's HTTP part */
#define AN_REQ_HTTP_INNER       0x00000020  /* inner processing of HTTP request */
#define AN_REQ_HTTP_TARPIT      0x00000040  /* wait for end of HTTP tarpit */
#define AN_REQ_HTTP_BODY        0x00000080  /* inspect HTTP request body */
#define AN_REQ_STATS_SOCK       0x00000100  /* process stats socket request */

#define AN_RTR_HTTP_HDR         0x00000200  /* inspect HTTP response headers */
#define AN_REQ_PRST_RDP_COOKIE  0x00000400  /* persistence on rdp cookie */

/* describes a chunk of string */
struct chunk {
	char *str;	/* beginning of the string itself. Might not be 0-terminated */
	int len;	/* size of the string from first to last char. <0 = uninit. */
};

/* needed for a declaration below */
struct session;

struct buffer {
	unsigned int flags;             /* BF_* */
	int rex;                        /* expiration date for a read, in ticks */
	int wex;                        /* expiration date for a write or connect, in ticks */
	int rto;                        /* read timeout, in ticks */
	int wto;                        /* write timeout, in ticks */
	int cto;                        /* connect timeout, in ticks */
	unsigned int l;                 /* data length */
	char *r, *w, *lr;               /* read ptr, write ptr, last read */
	unsigned int size;              /* buffer size in bytes */
	unsigned int max_len;           /* read limit, used to keep room for header rewriting */
	unsigned int send_max;          /* number of bytes the sender can consume om this buffer, <= l */
	unsigned int to_forward;        /* number of bytes to forward after send_max without a wake-up */
	unsigned int analysers;         /* bit field indicating what to do on the buffer */
	int analyse_exp;                /* expiration date for current analysers (if set) */
	void (*hijacker)(struct session *, struct buffer *); /* alternative content producer */
	unsigned char xfer_large;       /* number of consecutive large xfers */
	unsigned char xfer_small;       /* number of consecutive small xfers */
	unsigned long long total;       /* total data read */
	struct stream_interface *prod;  /* producer attached to this buffer */
	struct stream_interface *cons;  /* consumer attached to this buffer */
	struct pipe *pipe;		/* non-NULL only when data present */
	char data[0];                   /* <size> bytes */
};


/* Note about the buffer structure

   The buffer contains two length indicators, one to_forward counter and one
   send_max limit. First, it must be understood that the buffer is in fact
   split in two parts :
     - the visible data (->data, for ->l bytes)
     - the invisible data, typically in kernel buffers forwarded directly from
       the source stream sock to the destination stream sock (->pipe->data
       bytes). Those are used only during forward.

   In order not to mix data streams, the producer may only feed the invisible
   data with data to forward, and only when the visible buffer is empty. The
   consumer may not always be able to feed the invisible buffer due to platform
   limitations (lack of kernel support).

   Conversely, the consumer must always take data from the invisible data first
   before ever considering visible data. There is no limit to the size of data
   to consume from the invisible buffer, as platform-specific implementations
   will rarely leave enough control on this. So any byte fed into the invisible
   buffer is expected to reach the destination file descriptor, by any means.
   However, it's the consumer's responsibility to ensure that the invisible
   data has been entirely consumed before consuming visible data. This must be
   reflected by ->pipe->data. This is very important as this and only this can
   ensure strict ordering of data between buffers.

   The producer is responsible for decreasing ->to_forward and increasing
   ->send_max. The ->to_forward parameter indicates how many bytes may be fed
   into either data buffer without waking the parent up. The ->send_max
   parameter says how many bytes may be read from the visible buffer. Thus it
   may never exceed ->l. This parameter is updated by any buffer_write() as
   well as any data forwarded through the visible buffer.

   The consumer is responsible for decreasing ->send_max when it sends data
   from the visible buffer, and ->pipe->data when it sends data from the
   invisible buffer.

   A real-world example consists in part in an HTTP response waiting in a
   buffer to be forwarded. We know the header length (300) and the amount of
   data to forward (content-length=9000). The buffer already contains 1000
   bytes of data after the 300 bytes of headers. Thus the caller will set
   ->send_max to 300 indicating that it explicitly wants to send those data,
   and set ->to_forward to 9000 (content-length). This value must be normalised
   immediately after updating ->to_forward : since there are already 1300 bytes
   in the buffer, 300 of which are already counted in ->send_max, and that size
   is smaller than ->to_forward, we must update ->send_max to 1300 to flush the
   whole buffer, and reduce ->to_forward to 8000. After that, the producer may
   try to feed the additional data through the invisible buffer using a
   platform-specific method such as splice().
 */

#endif /* _TYPES_BUFFERS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
