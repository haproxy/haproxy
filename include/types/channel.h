/*
 * include/types/channel.h
 * Channel management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _TYPES_CHANNEL_H
#define _TYPES_CHANNEL_H

#include <common/config.h>
#include <common/chunk.h>
#include <common/buffer.h>
#include <types/stream_interface.h>

/* The BF_* macros designate Channel Flags (originally "Buffer Flags"), which
 * may be ORed in the bit field member 'flags' in struct channel. Here we have
 * several types of flags :
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
 * bits have the same position in a byte (read being the lower byte and write
 * the second one). All flag names are relative to the channel. For instance,
 * 'write' indicates the direction from the channel to the stream interface.
 */

#define BF_READ_NULL      0x000001  /* last read detected on producer side */
#define BF_READ_PARTIAL   0x000002  /* some data were read from producer */
#define BF_READ_TIMEOUT   0x000004  /* timeout while waiting for producer */
#define BF_READ_ERROR     0x000008  /* unrecoverable error on producer side */
#define BF_READ_ACTIVITY  (BF_READ_NULL|BF_READ_PARTIAL|BF_READ_ERROR)

#define BF_FULL           0x000010  /* channel cannot accept any more data (l >= max len) */
#define BF_SHUTR          0x000020  /* producer has already shut down */
#define BF_SHUTR_NOW      0x000040  /* the producer must shut down for reads ASAP */
#define BF_READ_NOEXP     0x000080  /* producer should not expire */

#define BF_WRITE_NULL     0x000100  /* write(0) or connect() succeeded on consumer side */
#define BF_WRITE_PARTIAL  0x000200  /* some data were written to the consumer */
#define BF_WRITE_TIMEOUT  0x000400  /* timeout while waiting for consumer */
#define BF_WRITE_ERROR    0x000800  /* unrecoverable error on consumer side */
#define BF_WRITE_ACTIVITY (BF_WRITE_NULL|BF_WRITE_PARTIAL|BF_WRITE_ERROR)

/* unused: 0x001000 */
#define BF_SHUTW          0x002000  /* consumer has already shut down */
#define BF_SHUTW_NOW      0x004000  /* the consumer must shut down for writes ASAP */
#define BF_AUTO_CLOSE     0x008000  /* producer can forward shutdown to other side */

/* When either BF_SHUTR_NOW or BF_HIJACK is set, it is strictly forbidden for
 * the producer to alter the buffer contents. When BF_SHUTW_NOW is set, the
 * consumer is free to perform a shutw() when it has consumed the last contents,
 * otherwise the session processor will do it anyway.
 *
 * The SHUT* flags work like this :
 *
 *  SHUTR SHUTR_NOW  meaning
 *    0       0      normal case, connection still open and data is being read
 *    0       1      closing : the producer cannot feed data anymore but can close
 *    1       0      closed: the producer has closed its input channel.
 *    1       1      impossible
 *
 *  SHUTW SHUTW_NOW  meaning
 *    0       0      normal case, connection still open and data is being written
 *    0       1      closing: the consumer can send last data and may then close
 *    1       0      closed: the consumer has closed its output channel.
 *    1       1      impossible
 *
 * The SHUTW_NOW flag should be set by the session processor when SHUTR and AUTO_CLOSE
 * are both set. It may also be set by a hijacker at the end of data. And it may also
 * be set by the producer when it detects SHUTR while directly forwarding data to the
 * consumer.
 *
 * The SHUTR_NOW flag is mostly used to force the producer to abort when an error is
 * detected on the consumer side.
 */

#define BF_STREAMER       0x010000  /* the producer is identified as streaming data */
#define BF_STREAMER_FAST  0x020000  /* the consumer seems to eat the stream very fast */

#define BF_HIJACK         0x040000  /* the producer is temporarily replaced by ->hijacker */
#define BF_ANA_TIMEOUT    0x080000  /* the analyser timeout has expired */
#define BF_READ_ATTACHED  0x100000  /* the read side is attached for the first time */
#define BF_KERN_SPLICING  0x200000  /* kernel splicing desired for this channel */
#define BF_READ_DONTWAIT  0x400000  /* wake the task up after every read (eg: HTTP request) */
#define BF_AUTO_CONNECT   0x800000  /* consumer may attempt to establish a new connection */

#define BF_DONT_READ     0x1000000  /* disable reading for now */
#define BF_EXPECT_MORE   0x2000000  /* more data expected to be sent very soon (one-shoot) */
#define BF_SEND_DONTWAIT 0x4000000  /* don't wait for sending data (one-shoot) */
#define BF_NEVER_WAIT    0x8000000  /* never wait for sending data (permanent) */

#define BF_WAKE_ONCE    0x10000000  /* pretend there is activity on this channel (one-shoot) */

/* Use these masks to clear the flags before going back to lower layers */
#define BF_CLEAR_READ     (~(BF_READ_NULL|BF_READ_PARTIAL|BF_READ_ERROR|BF_READ_ATTACHED))
#define BF_CLEAR_WRITE    (~(BF_WRITE_NULL|BF_WRITE_PARTIAL|BF_WRITE_ERROR))
#define BF_CLEAR_TIMEOUT  (~(BF_READ_TIMEOUT|BF_WRITE_TIMEOUT|BF_ANA_TIMEOUT))

/* Masks which define input events for stream analysers */
#define BF_MASK_ANALYSER        (BF_READ_ATTACHED|BF_READ_ACTIVITY|BF_READ_TIMEOUT|BF_ANA_TIMEOUT|BF_WRITE_ACTIVITY|BF_WAKE_ONCE)

/* Mask for static flags which cause analysers to be woken up when they change */
#define BF_MASK_STATIC          (BF_FULL|BF_SHUTR|BF_SHUTW|BF_SHUTR_NOW|BF_SHUTW_NOW)


/* Analysers (channel->analysers).
 * Those bits indicate that there are some processing to do on the buffer
 * contents. It will probably evolve into a linked list later. Those
 * analysers could be compared to higher level processors.
 * The field is blanked by buffer_init() and only by analysers themselves
 * afterwards.
 */
#define AN_REQ_DECODE_PROXY     0x00000001  /* take the proxied address from a 'PROXY' line */
#define AN_REQ_INSPECT_FE       0x00000002  /* inspect request contents in the frontend */
#define AN_REQ_WAIT_HTTP        0x00000004  /* wait for an HTTP request */
#define AN_REQ_HTTP_PROCESS_FE  0x00000008  /* process the frontend's HTTP part */
#define AN_REQ_SWITCHING_RULES  0x00000010  /* apply the switching rules */
#define AN_REQ_INSPECT_BE       0x00000020  /* inspect request contents in the backend */
#define AN_REQ_HTTP_PROCESS_BE  0x00000040  /* process the backend's HTTP part */
#define AN_REQ_SRV_RULES        0x00000080  /* use-server rules */
#define AN_REQ_HTTP_INNER       0x00000100  /* inner processing of HTTP request */
#define AN_REQ_HTTP_TARPIT      0x00000200  /* wait for end of HTTP tarpit */
#define AN_REQ_HTTP_BODY        0x00000400  /* inspect HTTP request body */
#define AN_REQ_STICKING_RULES   0x00000800  /* table persistence matching */
#define AN_REQ_PRST_RDP_COOKIE  0x00001000  /* persistence on rdp cookie */
#define AN_REQ_HTTP_XFER_BODY   0x00002000  /* forward request body */

/* response analysers */
#define AN_RES_INSPECT          0x00010000  /* content inspection */
#define AN_RES_WAIT_HTTP        0x00020000  /* wait for HTTP response */
#define AN_RES_HTTP_PROCESS_BE  0x00040000  /* process backend's HTTP part */
#define AN_RES_HTTP_PROCESS_FE  0x00040000  /* process frontend's HTTP part (same for now) */
#define AN_RES_STORE_RULES      0x00080000  /* table persistence matching */
#define AN_RES_HTTP_XFER_BODY   0x00100000  /* forward response body */


/* Magic value to forward infinite size (TCP, ...), used with ->to_forward */
#define BUF_INFINITE_FORWARD    MAX_RANGE(int)

/* needed for a declaration below */
struct session;

struct channel {
	unsigned int flags;             /* BF_* */
	int rex;                        /* expiration date for a read, in ticks */
	int wex;                        /* expiration date for a write or connect, in ticks */
	int rto;                        /* read timeout, in ticks */
	int wto;                        /* write timeout, in ticks */
	unsigned int to_forward;        /* number of bytes to forward after out without a wake-up */
	unsigned int analysers;         /* bit field indicating what to do on the channel */
	int analyse_exp;                /* expiration date for current analysers (if set) */
	void (*hijacker)(struct session *, struct channel *); /* alternative content producer */
	unsigned char xfer_large;       /* number of consecutive large xfers */
	unsigned char xfer_small;       /* number of consecutive small xfers */
	unsigned long long total;       /* total data read */
	struct stream_interface *prod;  /* producer attached to this channel */
	struct stream_interface *cons;  /* consumer attached to this channel */
	struct pipe *pipe;		/* non-NULL only when data present */
	struct buffer buf;		/* embedded buffer for now, will move */
};


/* Note about the buffer structure

   The buffer contains two length indicators, one to_forward counter and one
   ->o limit. First, it must be understood that the buffer is in fact
   split in two parts :
     - the visible data (->data, for ->l bytes)
     - the invisible data, typically in kernel buffers forwarded directly from
       the source stream sock to the destination stream sock (->pipe->data
       bytes). Those are used only during forward.

   In order not to mix data streams, the producer may only feed the invisible
   data with data to forward, and only when the visible buffer is empty. The
   producer may not always be able to feed the invisible buffer due to platform
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
   ->o. The ->to_forward parameter indicates how many bytes may be fed
   into either data buffer without waking the parent up. The special value
   BUF_INFINITE_FORWARD is never decreased nor increased. The ->o
   parameter says how many bytes may be consumed from the visible buffer. Thus
   it may never exceed ->l. This parameter is updated by any buffer_write() as
   well as any data forwarded through the visible buffer. Since the ->to_forward
   attribute applies to data after ->w+o, an analyser will not see a
   buffer which has a non-null to_forward with o < l. A producer is
   responsible for raising ->o by min(to_forward, l-o) when it
   injects data into the buffer.

   The consumer is responsible for decreasing ->o when it sends data
   from the visible buffer, and ->pipe->data when it sends data from the
   invisible buffer.

   A real-world example consists in part in an HTTP response waiting in a
   buffer to be forwarded. We know the header length (300) and the amount of
   data to forward (content-length=9000). The buffer already contains 1000
   bytes of data after the 300 bytes of headers. Thus the caller will set
   ->o to 300 indicating that it explicitly wants to send those data,
   and set ->to_forward to 9000 (content-length). This value must be normalised
   immediately after updating ->to_forward : since there are already 1300 bytes
   in the buffer, 300 of which are already counted in ->o, and that size
   is smaller than ->to_forward, we must update ->o to 1300 to flush the
   whole buffer, and reduce ->to_forward to 8000. After that, the producer may
   try to feed the additional data through the invisible buffer using a
   platform-specific method such as splice().

   The ->to_forward entry is also used to detect whether we can fill the buffer
   or not. The idea is that we need to save some space for data manipulation
   (mainly header rewriting in HTTP) so we don't want to have a full buffer on
   input before processing a request or response. Thus, we ensure that there is
   always global.maxrewrite bytes of free space. Since we don't want to forward
   chunks without filling the buffer, we rely on ->to_forward. When ->to_forward
   is null, we may have some processing to do so we don't want to fill the
   buffer. When ->to_forward is non-null, we know we don't care for at least as
   many bytes. In the end, we know that each of the ->to_forward bytes will
   eventually leave the buffer. So as long as ->to_forward is larger than
   global.maxrewrite, we can fill the buffer. If ->to_forward is smaller than
   global.maxrewrite, then we don't want to fill the buffer with more than
   ->size - global.maxrewrite + ->to_forward.

   Note that this also means that anyone touching ->to_forward must also take
   care of updating the BF_FULL flag. For this reason, it's really advised to
   use buffer_forward() only.

   A buffer may contain up to 5 areas :
     - the data waiting to be sent. These data are located between ->w and
       ->w+o ;
     - the data to process and possibly transform. These data start at
       ->w+o and may be up to r-w bytes long. Generally ->lr remains in
       this area ;
     - the data to preserve. They start at the end of the previous one and stop
       at ->r. The limit between the two solely depends on the protocol being
       analysed ; ->lr may be used as a marker.
     - the spare area : it is the remainder of the buffer, which can be used to
       store new incoming data. It starts at ->r and is up to ->size-l long. It
       may be limited by global.maxrewrite.
     - the reserved are : this is the area which must not be filled and is
       reserved for possible rewrites ; it is up to global.maxrewrite bytes
       long.
 */

#endif /* _TYPES_CHANNEL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
