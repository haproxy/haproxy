/*
 * include/haproxy/mux_h2-t.h
 * Definitions for basic H2 mux internal types, constants and flags.
 *
 * Copyright 2017-2022 Willy Tarreau <w@1wt.eu>
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

#ifndef _HAPROXY_MUX_H2_T_H
#define _HAPROXY_MUX_H2_T_H

#include <haproxy/api-t.h>
#include <haproxy/show_flags-t.h>

/**** Connection flags (32 bit), in h2c->flags ****/

#define H2_CF_NONE              0x00000000

/* Flags indicating why writing to the mux is blocked. */
#define H2_CF_MUX_MALLOC        0x00000001  // mux blocked on lack of connection's mux buffer
#define H2_CF_MUX_MFULL         0x00000002  // mux blocked on connection's mux buffer full
#define H2_CF_MUX_BLOCK_ANY     0x00000003  // aggregate of the mux flags above

/* Flags indicating why writing to the demux is blocked.
 * The first two ones directly affect the ability for the mux to receive data
 * from the connection. The other ones affect the mux's ability to demux
 * received data.
 */
#define H2_CF_DEM_DALLOC        0x00000004  // demux blocked on lack of connection's demux buffer
#define H2_CF_DEM_DFULL         0x00000008  // demux blocked on connection's demux buffer full
#define H2_CF_DEM_RXBUF         0x00000010  // demux blocked on missing rxbuf slots
#define H2_CF_DEM_MROOM         0x00000020  // demux blocked on lack of room in mux buffer
#define H2_CF_DEM_SALLOC        0x00000040  // demux blocked on lack of stream's request buffer
#define H2_CF_DEM_SFULL         0x00000080  // demux blocked on stream request buffer full
#define H2_CF_DEM_TOOMANY       0x00000100  // demux blocked waiting for some stream connectors to leave
#define H2_CF_DEM_BLOCK_ANY     0x000001F0  // aggregate of the demux flags above except DALLOC/DFULL
                                            // (SHORT_READ is also excluded)

#define H2_CF_DEM_SHORT_READ    0x00000200  // demux blocked on incomplete frame
#define H2_CF_DEM_IN_PROGRESS   0x00000400  // demux in progress (dsi,dfl,dft are valid)

/* other flags */
#define H2_CF_MBUF_HAS_DATA     0x00000800  // some stream data (data, headers) still in mbuf
#define H2_CF_GOAWAY_SENT       0x00001000  // a GOAWAY frame was successfully sent
#define H2_CF_GOAWAY_FAILED     0x00002000  // a GOAWAY frame failed to be sent
#define H2_CF_WAIT_FOR_HS       0x00004000  // We did check that at least a stream was waiting for handshake
#define H2_CF_IS_BACK           0x00008000  // this is an outgoing connection
#define H2_CF_WINDOW_OPENED     0x00010000  // demux increased window already advertised
#define H2_CF_RCVD_SHUT         0x00020000  // a recv() attempt already failed on a shutdown
#define H2_CF_END_REACHED       0x00040000  // pending data too short with RCVD_SHUT present

#define H2_CF_RCVD_RFC8441      0x00100000  // settings from RFC8441 has been received indicating support for Extended CONNECT
#define H2_CF_SHTS_UPDATED      0x00200000  // SETTINGS_HEADER_TABLE_SIZE updated
#define H2_CF_DTSU_EMITTED      0x00400000  // HPACK Dynamic Table Size Update opcode emitted

#define H2_CF_ERR_PENDING       0x00800000  // A write error was detected (block sends but not reads)
#define H2_CF_ERROR             0x01000000  //A read error was detected (handled has an abort)
#define H2_CF_WAIT_INLIST       0x02000000  // there is at least one stream blocked by another stream in send_list/fctl_list

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *h2c_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(H2_CF_MUX_MALLOC, _(H2_CF_MUX_MFULL, _(H2_CF_DEM_DALLOC,
	_(H2_CF_DEM_DFULL, _(H2_CF_WAIT_INLIST, _(H2_CF_DEM_RXBUF, _(H2_CF_DEM_MROOM,
	_(H2_CF_DEM_SALLOC, _(H2_CF_DEM_SFULL, _(H2_CF_DEM_TOOMANY,
	_(H2_CF_DEM_SHORT_READ, _(H2_CF_DEM_IN_PROGRESS, _(H2_CF_MBUF_HAS_DATA,
	_(H2_CF_GOAWAY_SENT, _(H2_CF_GOAWAY_FAILED, _(H2_CF_WAIT_FOR_HS, _(H2_CF_IS_BACK,
	_(H2_CF_WINDOW_OPENED, _(H2_CF_RCVD_SHUT, _(H2_CF_END_REACHED,
	_(H2_CF_RCVD_RFC8441, _(H2_CF_SHTS_UPDATED, _(H2_CF_DTSU_EMITTED,
	_(H2_CF_ERR_PENDING, _(H2_CF_ERROR)))))))))))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}


/**** HTTP/2 stream flags (32 bit), in h2s->flags ****/

#define H2_SF_NONE              0x00000000
#define H2_SF_ES_RCVD           0x00000001
#define H2_SF_ES_SENT           0x00000002

#define H2_SF_RST_RCVD          0x00000004 // received RST_STREAM
#define H2_SF_RST_SENT          0x00000008 // sent RST_STREAM

/* stream flags indicating the reason the stream is blocked */
#define H2_SF_BLK_MBUSY         0x00000010 // blocked waiting for mux access (transient)
#define H2_SF_BLK_MROOM         0x00000020 // blocked waiting for room in the mux (must be in send list)
#define H2_SF_BLK_MFCTL         0x00000040 // blocked due to mux fctl (must be in fctl list)
#define H2_SF_BLK_SFCTL         0x00000080 // blocked due to stream fctl (must be in blocked list)
#define H2_SF_BLK_ANY           0x000000F0 // any of the reasons above

/* stream flags indicating how data is supposed to be sent */
#define H2_SF_DATA_CLEN         0x00000100 // data sent using content-length
#define H2_SF_BODYLESS_RESP     0x00000200 /* Bodyless response message */
#define H2_SF_BODY_TUNNEL       0x00000400 // Attempt to establish a Tunnelled stream (the result depends on the status code)

#define H2_SF_NOTIFIED          0x00000800  // a paused stream was notified to try to send again
#define H2_SF_HEADERS_SENT      0x00001000  // a HEADERS frame was sent for this stream
#define H2_SF_OUTGOING_DATA     0x00002000  // set whenever we've seen outgoing data

#define H2_SF_HEADERS_RCVD      0x00004000  // a HEADERS frame was received for this stream

#define H2_SF_WANT_SHUTR        0x00008000  // a stream couldn't shutr() (mux full/busy)
#define H2_SF_WANT_SHUTW        0x00010000  // a stream couldn't shutw() (mux full/busy)

#define H2_SF_EXT_CONNECT_SENT  0x00040000  // rfc 8441 an Extended CONNECT has been sent
#define H2_SF_EXT_CONNECT_RCVD  0x00080000  // rfc 8441 an Extended CONNECT has been received and parsed

#define H2_SF_TUNNEL_ABRT       0x00100000  // A tunnel attempt was aborted
#define H2_SF_MORE_HTX_DATA     0x00200000  // more data expected from HTX
#define H2_SF_EXPECT_RXDATA     0x00400000  // more data expected from the peer


/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *h2s_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(H2_SF_ES_RCVD, _(H2_SF_ES_SENT, _(H2_SF_RST_RCVD, _(H2_SF_RST_SENT,
	_(H2_SF_BLK_MBUSY, _(H2_SF_BLK_MROOM, _(H2_SF_BLK_MFCTL,
	_(H2_SF_BLK_SFCTL, _(H2_SF_DATA_CLEN, _(H2_SF_BODYLESS_RESP,
	_(H2_SF_BODY_TUNNEL, _(H2_SF_NOTIFIED, _(H2_SF_HEADERS_SENT,
	_(H2_SF_OUTGOING_DATA, _(H2_SF_HEADERS_RCVD, _(H2_SF_WANT_SHUTR,
	_(H2_SF_WANT_SHUTW, _(H2_SF_EXT_CONNECT_SENT, _(H2_SF_EXT_CONNECT_RCVD,
	_(H2_SF_TUNNEL_ABRT, _(H2_SF_MORE_HTX_DATA, _(H2_SF_EXPECT_RXDATA))))))))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}


/* H2 connection state, in h2c->st0 */
enum h2_cs {
	H2_CS_PREFACE,   // init done, waiting for connection preface
	H2_CS_SETTINGS1, // preface OK, waiting for first settings frame
	H2_CS_FRAME_H,   // first settings frame ok, waiting for frame header
	H2_CS_FRAME_P,   // frame header OK, waiting for frame payload
	H2_CS_FRAME_A,   // frame payload OK, trying to send ACK frame
	H2_CS_FRAME_E,   // frame payload OK, trying to send RST frame
	H2_CS_ERROR,     // send GOAWAY(errcode) and close the connection ASAP
	H2_CS_ERROR2,    // GOAWAY(errcode) sent, close the connection ASAP
	H2_CS_ENTRIES    // must be last
} __attribute__((packed));

/* H2 stream state, in h2s->st */
enum h2_ss {
	H2_SS_IDLE = 0, // idle
	H2_SS_RLOC,     // reserved(local)
	H2_SS_RREM,     // reserved(remote)
	H2_SS_OPEN,     // open
	H2_SS_HREM,     // half-closed(remote)
	H2_SS_HLOC,     // half-closed(local)
	H2_SS_ERROR,    // an error needs to be sent using RST_STREAM
	H2_SS_CLOSED,   // closed
	H2_SS_ENTRIES   // must be last
} __attribute__((packed));


/* 32 buffers: one for the ring's root, rest for the mbuf itself */
#define H2C_MBUF_CNT 32

/**** tiny state decoding functions for debug helpers ****/

/* returns a h2c state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *h2c_st_to_str(enum h2_cs st)
{
	switch (st) {
	case H2_CS_PREFACE:   return "PRF";
	case H2_CS_SETTINGS1: return "STG";
	case H2_CS_FRAME_H:   return "FRH";
	case H2_CS_FRAME_P:   return "FRP";
	case H2_CS_FRAME_A:   return "FRA";
	case H2_CS_FRAME_E:   return "FRE";
	case H2_CS_ERROR:     return "ERR";
	case H2_CS_ERROR2:    return "ER2";
	default:              return "???";
	}
}

/* returns a h2s state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *h2s_st_to_str(enum h2_ss st)
{
	switch (st) {
	case H2_SS_IDLE:   return "IDL"; // idle
	case H2_SS_RLOC:   return "RSL"; // reserved local
	case H2_SS_RREM:   return "RSR"; // reserved remote
	case H2_SS_OPEN:   return "OPN"; // open
	case H2_SS_HREM:   return "HCR"; // half-closed remote
	case H2_SS_HLOC:   return "HCL"; // half-closed local
	case H2_SS_ERROR : return "ERR"; // error
	case H2_SS_CLOSED: return "CLO"; // closed
	default:           return "???";
	}
}

#endif /* _HAPROXY_MUX_H2_T_H */
