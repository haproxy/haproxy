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

/**** Connection flags (32 bit), in h1c->flags ****/
#define H1C_F_NONE           0x00000000

/* Flags indicating why writing output data are blocked */
#define H1C_F_OUT_ALLOC      0x00000001 /* mux is blocked on lack of output buffer */
#define H1C_F_OUT_FULL       0x00000002 /* mux is blocked on output buffer full */
/* 0x00000004 - 0x00000008 unused */

/* Flags indicating why reading input data are blocked. */
#define H1C_F_IN_ALLOC       0x00000010 /* mux is blocked on lack of input buffer */
#define H1C_F_IN_FULL        0x00000020 /* mux is blocked on input buffer full */
#define H1C_F_IN_SALLOC      0x00000040 /* mux is blocked on lack of stream's request buffer */

/* Flags indicating the connection state */
#define H1C_F_ST_EMBRYONIC   0x00000100 /* Set when a H1 stream with no stream connector is attached to the connection */
#define H1C_F_ST_ATTACHED    0x00000200 /* Set when a H1 stream with a stream connector is attached to the connection (may be not READY) */
#define H1C_F_ST_IDLE        0x00000400 /* connection is idle and may be reused
					 * (exclusive to all H1C_F_ST flags and never set when an h1s is attached) */
#define H1C_F_ST_ERROR       0x00000800 /* connection must be closed ASAP because an error occurred (stream connector may still be attached) */
#define H1C_F_ST_SHUTDOWN    0x00001000 /* connection must be shut down ASAP flushing output first (stream connector may still be attached) */
#define H1C_F_ST_READY       0x00002000 /* Set in ATTACHED state with a READY stream connector. A stream connector is not ready when
					 * a TCP>H1 upgrade is in progress Thus this flag is only set if ATTACHED is also set */
#define H1C_F_ST_ALIVE       (H1C_F_ST_IDLE|H1C_F_ST_EMBRYONIC|H1C_F_ST_ATTACHED)
#define H1C_F_ST_SILENT_SHUT 0x00004000 /* silent (or dirty) shutdown must be performed (implied ST_SHUTDOWN) */
/* 0x00008000 unused */

#define H1C_F_WANT_SPLICE    0x00010000 /* Don't read into a buffer because we want to use or we are using splicing */
#define H1C_F_ERR_PENDING    0x00020000 /* Send an error and close the connection ASAP (implies H1C_F_ST_ERROR) */
#define H1C_F_WAIT_NEXT_REQ  0x00040000 /*  waiting for the next request to start, use keep-alive timeout */
#define H1C_F_UPG_H2C        0x00080000 /* set if an upgrade to h2 should be done */
#define H1C_F_CO_MSG_MORE    0x00100000 /* set if CO_SFL_MSG_MORE must be set when calling xprt->snd_buf() */
#define H1C_F_CO_STREAMER    0x00200000 /* set if CO_SFL_STREAMER must be set when calling xprt->snd_buf() */

/* 0x00400000 - 0x40000000 unusued*/
#define H1C_F_IS_BACK        0x80000000 /* Set on outgoing connection */


/**** H1 stream flags (32 bit), in h1s->flags ****/
#define H1S_F_NONE           0x00000000

#define H1S_F_RX_BLK         0x00100000 /* Don't process more input data, waiting sync with output side */
#define H1S_F_TX_BLK         0x00200000 /* Don't process more output data, waiting sync with input side */
#define H1S_F_RX_CONGESTED   0x00000004 /* Cannot process input data RX path is congested (waiting for more space in channel's buffer) */

#define H1S_F_REOS           0x00000008 /* End of input stream seen even if not delivered yet */
#define H1S_F_WANT_KAL       0x00000010
#define H1S_F_WANT_TUN       0x00000020
#define H1S_F_WANT_CLO       0x00000040
#define H1S_F_WANT_MSK       0x00000070
#define H1S_F_NOT_FIRST      0x00000080 /* The H1 stream is not the first one */
#define H1S_F_BODYLESS_RESP  0x00000100 /* Bodyless response message */

/* 0x00000200 unused */
#define H1S_F_NOT_IMPL_ERROR 0x00000400 /* Set when a feature is not implemented during the message parsing */
#define H1S_F_PARSING_ERROR  0x00000800 /* Set when an error occurred during the message parsing */
#define H1S_F_PROCESSING_ERROR 0x00001000 /* Set when an error occurred during the message xfer */
#define H1S_F_ERROR          0x00001800 /* stream error mask */

#define H1S_F_HAVE_SRV_NAME  0x00002000 /* Set during output process if the server name header was added to the request */
#define H1S_F_HAVE_O_CONN    0x00004000 /* Set during output process to know connection mode was processed */


#endif /* _HAPROXY_MUX_H1_T_H */
