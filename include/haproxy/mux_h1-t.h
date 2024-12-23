/*
 * include/haproxy/mux_h1-t.h
 * Definitions for basic H1 mux internal types, constants and flags.
 *
 * Copyright 2022 Christopher Faulet <cfaulet@haproxy.com>
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

#ifndef _HAPROXY_MUX_H1_T_H
#define _HAPROXY_MUX_H1_T_H

#include <haproxy/api-t.h>
#include <haproxy/show_flags-t.h>

/**** Connection flags (32 bit), in h1c->flags ****/
#define H1C_F_NONE           0x00000000

/* Flags indicating why writing output data are blocked */
#define H1C_F_OUT_ALLOC      0x00000001 /* mux is blocked on lack of output buffer */
#define H1C_F_OUT_FULL       0x00000002 /* mux is blocked on output buffer full */
#define H1C_F_OUT_MAYALLOC   0x00000004 /* mux was just unblocked and may try to alloc out again */

/* Flags indicating why reading input data are blocked. */
#define H1C_F_IN_MAYALLOC    0x00000008 /* mux was just unblocked and may try to alloc in again */
#define H1C_F_IN_ALLOC       0x00000010 /* mux is blocked on lack of input buffer */
#define H1C_F_IN_FULL        0x00000020 /* mux is blocked on input buffer full */
#define H1C_F_IN_SALLOC      0x00000040 /* mux is blocked on lack of stream's request buffer */
#define H1C_F_IN_SMAYALLOC   0x00000080 /* mux was just unblocked and may try to alloc strm again */

#define H1C_F_EOS            0x00000100 /* End-of-stream seen on the H1 connection (read0 detected) */
#define H1C_F_ERR_PENDING    0x00000200 /* A write error was detected (block sends but not reads) */
#define H1C_F_ERROR          0x00000400 /* A read error was detected (handled has an abort) */
#define H1C_F_SILENT_SHUT    0x00000800 /* if H1C is closed closed, silent (or dirty) shutdown must be performed */
#define H1C_F_ABRT_PENDING   0x00001000 /* An error must be sent (previous attempt failed) and H1 connection must be closed ASAP */
#define H1C_F_ABRTED         0x00002000 /* An error must be sent (previous attempt failed) and H1 connection must be closed ASAP */
#define H1C_F_WANT_FASTFWD   0x00004000 /* Don't read into a buffer because we want to fast forward data */
#define H1C_F_WAIT_NEXT_REQ  0x00008000 /*  waiting for the next request to start, use keep-alive timeout */
#define H1C_F_UPG_H2C        0x00010000 /* set if an upgrade to h2 should be done */
#define H1C_F_CO_MSG_MORE    0x00020000 /* set if CO_SFL_MSG_MORE must be set when calling xprt->snd_buf() */
#define H1C_F_CO_STREAMER    0x00040000 /* set if CO_SFL_STREAMER must be set when calling xprt->snd_buf() */
#define H1C_F_CANT_FASTFWD   0x00080000 /* Fast-forwarding is not supported (exclusive with WANT_FASTFWD) */

/* 0x00100000 - 0x40000000 unused */
#define H1C_F_IS_BACK        0x80000000 /* Set on outgoing connection */


/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *h1c_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(H1C_F_OUT_ALLOC, _(H1C_F_OUT_FULL, _(H1C_F_OUT_MAYALLOC,
	_(H1C_F_IN_MAYALLOC, _(H1C_F_IN_ALLOC, _(H1C_F_IN_FULL, _(H1C_F_IN_SALLOC, _(H1C_F_IN_SMAYALLOC,
	_(H1C_F_EOS, _(H1C_F_ERR_PENDING, _(H1C_F_ERROR,
	_(H1C_F_SILENT_SHUT, _(H1C_F_ABRT_PENDING, _(H1C_F_ABRTED,
	_(H1C_F_WANT_FASTFWD, _(H1C_F_WAIT_NEXT_REQ, _(H1C_F_UPG_H2C, _(H1C_F_CO_MSG_MORE,
	_(H1C_F_CO_STREAMER, _(H1C_F_CANT_FASTFWD, _(H1C_F_IS_BACK)))))))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}


/**** H1 stream flags (32 bit), in h1s->flags ****/
#define H1S_F_NONE           0x00000000

#define H1S_F_RX_BLK         0x00100000 /* Don't process more input data, waiting sync with output side */
#define H1S_F_TX_BLK         0x00200000 /* Don't process more output data, waiting sync with input side */
#define H1S_F_RX_CONGESTED   0x00000004 /* Cannot process input data RX path is congested (waiting for more space in channel's buffer) */

/* 0x00000008 unused */
#define H1S_F_WANT_KAL       0x00000010
#define H1S_F_WANT_TUN       0x00000020
#define H1S_F_WANT_CLO       0x00000040
#define H1S_F_WANT_MSK       0x00000070
#define H1S_F_NOT_FIRST      0x00000080 /* The H1 stream is not the first one */
/* 0x00000100 unused */

#define H1S_F_INTERNAL_ERROR 0x00000200 /* Set when an internal error occurred during the message parsing */
#define H1S_F_NOT_IMPL_ERROR 0x00000400 /* Set when a feature is not implemented during the message parsing */
#define H1S_F_PARSING_ERROR  0x00000800 /* Set when an error occurred during the message parsing */
#define H1S_F_PROCESSING_ERROR 0x00001000 /* Set when an error occurred during the message xfer */

#define H1S_F_DEMUX_ERROR (H1S_F_INTERNAL_ERROR|H1S_F_NOT_IMPL_ERROR|H1S_F_PARSING_ERROR)
#define H1S_F_MUX_ERROR   (H1S_F_INTERNAL_ERROR|H1S_F_PROCESSING_ERROR)

#define H1S_F_HAVE_SRV_NAME  0x00002000 /* Set during output process if the server name header was added to the request */
#define H1S_F_HAVE_O_CONN    0x00004000 /* Set during output process to know connection mode was processed */
#define H1S_F_HAVE_WS_KEY    0x00008000 /* Set during output process to know WS key was found or generated */
#define H1S_F_HAVE_CLEN      0x00010000 /* Set during output process to know C*L header was found or generated */
#define H1S_F_HAVE_CHNK      0x00020000 /* Set during output process to know "T-E; chunk" header was found or generated */

#define H1S_F_BODYLESS_REQ   0x00040000 /* Bodyless request message */
#define H1S_F_BODYLESS_RESP  0x00080000 /* Bodyless response message */

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *h1s_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(H1S_F_RX_BLK, _(H1S_F_TX_BLK, _(H1S_F_RX_CONGESTED,
	_(H1S_F_WANT_KAL, _(H1S_F_WANT_TUN, _(H1S_F_WANT_CLO,
	_(H1S_F_NOT_FIRST,
	_(H1S_F_INTERNAL_ERROR, _(H1S_F_NOT_IMPL_ERROR, _(H1S_F_PARSING_ERROR, _(H1S_F_PROCESSING_ERROR,
	_(H1S_F_HAVE_SRV_NAME, _(H1S_F_HAVE_O_CONN, _(H1S_F_HAVE_WS_KEY,
	_(H1S_F_HAVE_CLEN, _(H1S_F_HAVE_CHNK, _(H1S_F_BODYLESS_REQ, _(H1S_F_BODYLESS_RESP))))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/* H1 connection state, in h1c->state */
enum h1_cs {
	H1_CS_IDLE,        /* IDLE connection. A freashly open or a reusable connection (H1S is NULL) */
	H1_CS_EMBRYONIC,   /* Connection is waiting for the message headers (H1S is not NULL, not attached to a SC - Frontend connection only) */
	H1_CS_UPGRADING,   /* TCP>H1 upgrade in-progress (H1S is not NULL and attached to a SC - Frontend connection only) */
	H1_CS_RUNNING,     /* Connection fully established and the H1S is processing data (H1S is not NULL and attached to a SC) */
	H1_CS_DRAINING,    /* H1C is draining the message before destroying the H1S (H1S is not NULL but no SC attached) */
	H1_CS_CLOSING,     /* Send pending outgoing data and close the connection ASAP  (H1S may be NULL) */
	H1_CS_CLOSED,      /* Connection must be closed now and H1C must be released (H1S is NULL) */
	H1_CS_ENTRIES,
} __attribute__((packed));


/**** tiny state decoding functions for debug helpers ****/

/* returns a h1c state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *h1c_st_to_str(enum h1_cs st)
{
	switch (st) {
	case H1_CS_IDLE:      return "IDL";
	case H1_CS_EMBRYONIC: return "EMB";
	case H1_CS_UPGRADING: return "UPG";
	case H1_CS_RUNNING:   return "RUN";
	case H1_CS_DRAINING:  return "DRN";
	case H1_CS_CLOSING:   return "CLI";
	case H1_CS_CLOSED:    return "CLD";
	default:              return "???";
	}
}


#endif /* _HAPROXY_MUX_H1_T_H */
