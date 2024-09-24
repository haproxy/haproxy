/* SPDX-License-Identifier: LGPL-2.0-or-later */

#ifndef _HAPROXY_MUX_SPOP_T_H
#define _HAPROXY_MUX_SPOP_T_H

#include <haproxy/api-t.h>
#include <haproxy/show_flags-t.h>

/**** SPOP connection flags (32 bit), in spop_conn->flags ****/
#define SPOP_CF_NONE           0x00000000

/* Flags indicating why writing to the mux is blocked */
#define SPOP_CF_MUX_MALLOC      0x00000001 /* mux is blocked on lack connection's mux buffer */
#define SPOP_CF_MUX_MFULL       0x00000002 /* mux is blocked on connection's mux buffer full */
#define SPOP_CF_MUX_BLOCK_ANY   0x00000003 /* mux is blocked on connection's mux buffer full */

#define SPOP_CF_WAIT_INLIST     0x00000010  // there is at least one stream blocked by another stream in send_list
#define SPOP_CF_DEM_DALLOC      0x00000020  /* demux blocked on lack of connection's demux buffer */
#define SPOP_CF_DEM_DFULL       0x00000040  /* demux blocked on connection's demux buffer full */
#define SPOP_CF_DEM_MROOM       0x00000080  /* demux blocked on lack of room in mux buffer */
#define SPOP_CF_DEM_SALLOC      0x00000100  /* demux blocked on lack of stream's rx buffer */
#define SPOP_CF_DEM_SFULL       0x00000200  /* demux blocked on stream request buffer full */
#define SPOP_CF_DEM_TOOMANY     0x00000400  /* demux blocked waiting for some stream connectors to leave */
#define SPOP_CF_DEM_BLOCK_ANY   0x000007E0  /* aggregate of the demux flags above except DALLOC/DFULL */

/* Other flags */
#define SPOP_CF_DISCO_SENT      0x00001000  /* a frame DISCONNECT was successfully sent */
#define SPOP_CF_DISCO_FAILED    0x00002000  /* failed to disconnect */
#define SPOP_CF_WAIT_FOR_HS     0x00004000  /* We did check that at least a stream was waiting for handshake */
#define SPOP_CF_DEM_SHORT_READ  0x00008000  // demux blocked on incomplete frame
/* unused  0x00010000 */
#define SPOP_CF_RCVD_SHUT       0x00020000  // a recv() attempt already failed on a shutdown
#define SPOP_CF_END_REACHED     0x00040000  // pending data too short with RCVD_SHUT present
#define SPOP_CF_ERR_PENDING     0x00080000  /* A write error was detected (block sends but not reads) */
#define SPOP_CF_ERROR           0x00100000  /* A read error was detected (handled has an abort) */


/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *spop_conn_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(SPOP_CF_MUX_MALLOC, _(SPOP_CF_MUX_MFULL, _(SPOP_CF_WAIT_INLIST,
	_(SPOP_CF_DEM_DALLOC, _(SPOP_CF_DEM_DFULL, _(SPOP_CF_DEM_MROOM,
	_(SPOP_CF_DEM_SALLOC, _(SPOP_CF_DEM_SFULL, _(SPOP_CF_DEM_TOOMANY,
	_(SPOP_CF_DISCO_SENT, _(SPOP_CF_DISCO_FAILED, _(SPOP_CF_WAIT_FOR_HS,
	_(SPOP_CF_DEM_SHORT_READ, _(SPOP_CF_RCVD_SHUT, _(SPOP_CF_END_REACHED,
	_(SPOP_CF_ERR_PENDING, _(SPOP_CF_ERROR)))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/**** SPOP stream flags (32 bit), in spop_strm->flags ****/
#define SPOP_SF_NONE           0x00000000
// #define SPOP_SF_ACK_RCVD       0x00000001 /* ACK freme received */
//#define SPOP_SF_ES_SENT        0x00000002 /* end-of-stream sent */
//#define SPOP_SF_EP_SENT        0x00000004 /* end-of-param sent */
//#define SPOP_SF_DISCON_SENT      0x00000008 /* disconnect sent */

/* Stream flags indicating the reason the stream is blocked */
#define SPOP_SF_BLK_MBUSY      0x00000010 /* blocked waiting for mux access (transient) */
#define SPOP_SF_BLK_MROOM      0x00000020 /* blocked waiting for room in the mux */
#define SPOP_SF_BLK_ANY        0x00000030 /* any of the reasons above */

//#define SPOP_SF_BEGIN_SENT     0x00000100  /* a BEGIN_REQUEST record was sent for this stream */
//#define SPOP_SF_OUTGOING_DATA  0x00000200  /* set whenever we've seen outgoing data */
#define SPOP_SF_NOTIFIED       0x00000400  /* a paused stream was notified to try to send again */

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *spop_strm_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(SPOP_SF_BLK_MBUSY, _(SPOP_SF_BLK_MROOM, _(SPOP_SF_NOTIFIED)));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/* SPOP connection state (spop_conn->state) */
enum spop_conn_st {
	SPOP_CS_HA_HELLO = 0, /* init done, waiting for sending HELLO frame */
	SPOP_CS_AGENT_HELLO,     /* HELLO frame sent, waiting for agent HELLO frame to define the connection settings */
	SPOP_CS_FRAME_H,       /* HELLO handshake finished, waiting for a frame header */
	SPOP_CS_FRAME_P,       /* Frame header received, waiting for a frame data */
	SPOP_CS_ERROR,         /* send DISCONNECT frame to be able ti close the connection */
	SPOP_CS_CLOSING,       /* DISCONNECT frame sent, waiting for the agent DISCONNECT frame before closing */
	SPOP_CS_CLOSED,        /* Agent DISCONNECT frame received and  close the connection ASAP */
	SPOP_CS_ENTRIES
} __attribute__((packed));

/* returns a spop_conn state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *spop_conn_st_to_str(enum spop_conn_st st)
{
	switch (st) {
		case SPOP_CS_HA_HELLO   : return "HHL";
		case SPOP_CS_AGENT_HELLO: return "AHL";
		case SPOP_CS_FRAME_H    : return "FRH";
		case SPOP_CS_FRAME_P    : return "FRP";
		case SPOP_CS_ERROR      : return "ERR";
		case SPOP_CS_CLOSING    : return "CLI";
		case SPOP_CS_CLOSED     : return "CLO";
		default                 : return "???";
	}
}

/* SPOP stream state, in spop_strm->state */
enum spop_strm_st {
	SPOP_SS_IDLE = 0,
	SPOP_SS_OPEN,
	SPOP_SS_HREM,     // half-closed(remote)
	SPOP_SS_HLOC,     // half-closed(local)
	SPOP_SS_ERROR,
	SPOP_SS_CLOSED,
	SPOP_SS_ENTRIES
} __attribute__((packed));


/* returns a spop_strm state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *spop_strm_st_to_str(enum spop_strm_st st)
{
	switch (st) {
		case SPOP_SS_IDLE   : return "IDL";
		case SPOP_SS_OPEN   : return "OPN";
		case SPOP_SS_HREM   : return "RCL";
		case SPOP_SS_HLOC   : return "HCL";
		case SPOP_SS_ERROR  : return "ERR";
		case SPOP_SS_CLOSED : return "CLO";
		default             : return "???";
	}
}


#endif /* _HAPROXY_MUX_SPOP_T_H */
