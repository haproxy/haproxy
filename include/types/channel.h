/*
 * include/types/channel.h
 * Channel management definitions, macros and inline functions.
 *
 * Copyright (C) 2000-2014 Willy Tarreau - w@1wt.eu
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
#include <common/buffer.h>

/* The CF_* macros designate Channel Flags, which may be ORed in the bit field
 * member 'flags' in struct channel. Here we have several types of flags :
 *
 *   - pure status flags, reported by the data layer, which must be cleared
 *     before doing further I/O :
 *     CF_*_NULL, CF_*_PARTIAL
 *
 *   - pure status flags, reported by stream-interface layer, which must also
 *     be cleared before doing further I/O :
 *     CF_*_TIMEOUT, CF_*_ERROR
 *
 *   - read-only indicators reported by lower data levels :
 *     CF_STREAMER, CF_STREAMER_FAST
 *
 *   - write-once status flags reported by the stream-interface layer :
 *     CF_SHUTR, CF_SHUTW
 *
 *   - persistent control flags managed only by application level :
 *     CF_SHUT*_NOW, CF_*_ENA
 *
 * The flags have been arranged for readability, so that the read and write
 * bits have the same position in a byte (read being the lower byte and write
 * the second one). All flag names are relative to the channel. For instance,
 * 'write' indicates the direction from the channel to the stream interface.
 */

#define CF_READ_NULL      0x00000001  /* last read detected on producer side */
#define CF_READ_PARTIAL   0x00000002  /* some data were read from producer */
#define CF_READ_TIMEOUT   0x00000004  /* timeout while waiting for producer */
#define CF_READ_ERROR     0x00000008  /* unrecoverable error on producer side */
#define CF_READ_ACTIVITY  (CF_READ_NULL|CF_READ_PARTIAL|CF_READ_ERROR)

/* unused: 0x00000010 */
#define CF_SHUTR          0x00000020  /* producer has already shut down */
#define CF_SHUTR_NOW      0x00000040  /* the producer must shut down for reads ASAP */
#define CF_READ_NOEXP     0x00000080  /* producer should not expire */

#define CF_WRITE_NULL     0x00000100  /* write(0) or connect() succeeded on consumer side */
#define CF_WRITE_PARTIAL  0x00000200  /* some data were written to the consumer */
#define CF_WRITE_TIMEOUT  0x00000400  /* timeout while waiting for consumer */
#define CF_WRITE_ERROR    0x00000800  /* unrecoverable error on consumer side */
#define CF_WRITE_ACTIVITY (CF_WRITE_NULL|CF_WRITE_PARTIAL|CF_WRITE_ERROR)

#define CF_WAKE_WRITE     0x00001000  /* wake the task up when there's write activity */
#define CF_SHUTW          0x00002000  /* consumer has already shut down */
#define CF_SHUTW_NOW      0x00004000  /* the consumer must shut down for writes ASAP */
#define CF_AUTO_CLOSE     0x00008000  /* producer can forward shutdown to other side */

/* When CF_SHUTR_NOW is set, it is strictly forbidden for the producer to alter
 * the buffer contents. When CF_SHUTW_NOW is set, the consumer is free to perform
 * a shutw() when it has consumed the last contents, otherwise the session processor
 * will do it anyway.
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
 * are both set. And it may also be set by the producer when it detects SHUTR while
 * directly forwarding data to the consumer.
 *
 * The SHUTR_NOW flag is mostly used to force the producer to abort when an error is
 * detected on the consumer side.
 */

#define CF_STREAMER       0x00010000  /* the producer is identified as streaming data */
#define CF_STREAMER_FAST  0x00020000  /* the consumer seems to eat the stream very fast */

#define CF_WROTE_DATA     0x00040000  /* some data were sent from this buffer */
#define CF_ANA_TIMEOUT    0x00080000  /* the analyser timeout has expired */
#define CF_READ_ATTACHED  0x00100000  /* the read side is attached for the first time */
#define CF_KERN_SPLICING  0x00200000  /* kernel splicing desired for this channel */
#define CF_READ_DONTWAIT  0x00400000  /* wake the task up after every read (eg: HTTP request) */
#define CF_AUTO_CONNECT   0x00800000  /* consumer may attempt to establish a new connection */

#define CF_DONT_READ      0x01000000  /* disable reading for now */
#define CF_EXPECT_MORE    0x02000000  /* more data expected to be sent very soon (one-shoot) */
#define CF_SEND_DONTWAIT  0x04000000  /* don't wait for sending data (one-shoot) */
#define CF_NEVER_WAIT     0x08000000  /* never wait for sending data (permanent) */

#define CF_WAKE_ONCE      0x10000000  /* pretend there is activity on this channel (one-shoot) */
#define CF_FLT_ANALYZE    0x20000000  /* at least one filter is still analyzing this channel */
#define CF_EOI            0x40000000  /* end-of-input has been reached */
#define CF_ISRESP         0x80000000  /* 0 = request channel, 1 = response channel */

/* Masks which define input events for stream analysers */
#define CF_MASK_ANALYSER  (CF_READ_ATTACHED|CF_READ_ACTIVITY|CF_READ_TIMEOUT|CF_ANA_TIMEOUT|CF_WRITE_ACTIVITY|CF_WAKE_ONCE)

/* Mask for static flags which cause analysers to be woken up when they change */
#define CF_MASK_STATIC    (CF_SHUTR|CF_SHUTW|CF_SHUTR_NOW|CF_SHUTW_NOW)


/* Analysers (channel->analysers).
 * Those bits indicate that there are some processing to do on the buffer
 * contents. It will probably evolve into a linked list later. Those
 * analysers could be compared to higher level processors.
 * The field is blanked by channel_init() and only by analysers themselves
 * afterwards.
 */
/* AN_REQ_FLT_START_FE:         0x00000001 */
#define AN_REQ_INSPECT_FE       0x00000002  /* inspect request contents in the frontend */
#define AN_REQ_WAIT_HTTP        0x00000004  /* wait for an HTTP request */
#define AN_REQ_HTTP_BODY        0x00000008  /* wait for HTTP request body */
#define AN_REQ_HTTP_PROCESS_FE  0x00000010  /* process the frontend's HTTP part */
#define AN_REQ_SWITCHING_RULES  0x00000020  /* apply the switching rules */
/* AN_REQ_FLT_START_BE:         0x00000040 */
#define AN_REQ_INSPECT_BE       0x00000080  /* inspect request contents in the backend */
#define AN_REQ_HTTP_PROCESS_BE  0x00000100  /* process the backend's HTTP part */
#define AN_REQ_HTTP_TARPIT      0x00000200  /* wait for end of HTTP tarpit */
#define AN_REQ_SRV_RULES        0x00000400  /* use-server rules */
#define AN_REQ_HTTP_INNER       0x00000800  /* inner processing of HTTP request */
#define AN_REQ_PRST_RDP_COOKIE  0x00001000  /* persistence on rdp cookie */
#define AN_REQ_STICKING_RULES   0x00002000  /* table persistence matching */
/* AN_REQ_FLT_HTTP_HDRS:        0x00004000 */
#define AN_REQ_HTTP_XFER_BODY   0x00008000  /* forward request body */
#define AN_REQ_WAIT_CLI         0x00010000
/* AN_REQ_FLT_XFER_DATA:        0x00020000 */
/* AN_REQ_FLT_END:              0x00040000 */
#define AN_REQ_ALL              0x0001bfbe  /* all of the request analysers */

/* response analysers */
/* AN_RES_FLT_START_FE:         0x00080000 */
/* AN_RES_FLT_START_BE:         0x00100000 */
#define AN_RES_INSPECT          0x00200000  /* content inspection */
#define AN_RES_WAIT_HTTP        0x00400000  /* wait for HTTP response */
#define AN_RES_STORE_RULES      0x00800000  /* table persistence matching */
#define AN_RES_HTTP_PROCESS_BE  0x01000000  /* process backend's HTTP part */
#define AN_RES_HTTP_PROCESS_FE  0x01000000  /* process frontend's HTTP part (same for now) */
/* AN_RES_FLT_HTTP_HDRS:        0x02000000 */
#define AN_RES_HTTP_XFER_BODY   0x04000000  /* forward response body */
#define AN_RES_WAIT_CLI         0x08000000
/* AN_RES_FLT_XFER_DATA:        0x10000000 */
/* AN_RES_FLT_END:              0x20000000 */
#define AN_RES_ALL              0x0de00000  /* all of the response analysers */

/* filters interleaved with analysers, see above */
#define AN_REQ_FLT_START_FE     0x00000001
#define AN_REQ_FLT_START_BE     0x00000040
#define AN_REQ_FLT_HTTP_HDRS    0x00004000
#define AN_REQ_FLT_XFER_DATA    0x00020000
#define AN_REQ_FLT_END          0x00040000

#define AN_RES_FLT_START_FE     0x00080000
#define AN_RES_FLT_START_BE     0x00100000
#define AN_RES_FLT_HTTP_HDRS    0x02000000
#define AN_RES_FLT_XFER_DATA    0x10000000
#define AN_RES_FLT_END          0x20000000

/* Magic value to forward infinite size (TCP, ...), used with ->to_forward */
#define CHN_INFINITE_FORWARD    MAX_RANGE(unsigned int)


struct channel {
	unsigned int flags;             /* CF_* */
	unsigned int analysers;         /* bit field indicating what to do on the channel */
	struct buffer buf;		/* buffer attached to the channel, always present but may move */
	struct pipe *pipe;		/* non-NULL only when data present */
	size_t output;                  /* part of buffer which is to be forwarded */
	unsigned int to_forward;        /* number of bytes to forward after out without a wake-up */
	unsigned short last_read;       /* 16 lower bits of last read date (max pause=65s) */
	unsigned char xfer_large;       /* number of consecutive large xfers */
	unsigned char xfer_small;       /* number of consecutive small xfers */
	unsigned long long total;       /* total data read */
	int rex;                        /* expiration date for a read, in ticks */
	int wex;                        /* expiration date for a write or connect, in ticks */
	int rto;                        /* read timeout, in ticks */
	int wto;                        /* write timeout, in ticks */
	int analyse_exp;                /* expiration date for current analysers (if set) */
};


/* Note about the channel structure

   A channel stores information needed to reliably transport data in a single
   direction. It stores status flags, timeouts, counters, subscribed analysers,
   pointers to a data producer and to a data consumer, and information about
   the amount of data which is allowed to flow directly from the producer to
   the consumer without waking up the analysers.

   A channel may buffer data into two locations :
     - a visible buffer (->buf)
     - an invisible buffer which right now consists in a pipe making use of
       kernel buffers that cannot be tampered with.

   Data stored into the first location may be analysed and altered by analysers
   while data stored in pipes is only aimed at being transported from one
   network socket to another one without being subject to memory copies. This
   buffer may only be used when both the socket layer and the data layer of the
   producer and the consumer support it, which typically is the case with Linux
   splicing over sockets, and when there are enough data to be transported
   without being analyzed (transport of TCP/HTTP payload or tunnelled data,
   which is indicated by ->to_forward).

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

   The producer is responsible for decreasing ->to_forward. The ->to_forward
   parameter indicates how many bytes may be fed into either data buffer
   without waking the parent up. The special value CHN_INFINITE_FORWARD is
   never decreased nor increased.

   The buf->o parameter says how many bytes may be consumed from the visible
   buffer. This parameter is updated by any buffer_write() as well as any data
   forwarded through the visible buffer. Since the ->to_forward attribute
   applies to data after buf->p, an analyser will not see a buffer which has a
   non-null ->to_forward with buf->i > 0. A producer is responsible for raising
   buf->o by min(to_forward, buf->i) when it injects data into the buffer.

   The consumer is responsible for decreasing ->buf->o when it sends data
   from the visible buffer, and ->pipe->data when it sends data from the
   invisible buffer.

   A real-world example consists in part in an HTTP response waiting in a
   buffer to be forwarded. We know the header length (300) and the amount of
   data to forward (content-length=9000). The buffer already contains 1000
   bytes of data after the 300 bytes of headers. Thus the caller will set
   buf->o to 300 indicating that it explicitly wants to send those data, and
   set ->to_forward to 9000 (content-length). This value must be normalised
   immediately after updating ->to_forward : since there are already 1300 bytes
   in the buffer, 300 of which are already counted in buf->o, and that size
   is smaller than ->to_forward, we must update buf->o to 1300 to flush the
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
   buf->size - global.maxrewrite + ->to_forward.

   A buffer may contain up to 5 areas :
     - the data waiting to be sent. These data are located between buf->p-o and
       buf->p ;
     - the data to process and possibly transform. These data start at
       buf->p and may be up to ->i bytes long.
     - the data to preserve. They start at ->p and stop at ->p+i. The limit
       between the two solely depends on the protocol being analysed.
     - the spare area : it is the remainder of the buffer, which can be used to
       store new incoming data. It starts at ->p+i and is up to ->size-i-o long.
       It may be limited by global.maxrewrite.
     - the reserved area : this is the area which must not be filled and is
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
