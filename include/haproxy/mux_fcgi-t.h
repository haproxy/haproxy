/*
 * include/haproxy/mux_fcgi-t.h
 * Definitions for basic FCGI mux internal types, constants and flags.
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

#ifndef _HAPROXY_MUX_FCGI_T_H
#define _HAPROXY_MUX_FCGI_T_H

#include <haproxy/api-t.h>
#include <haproxy/show_flags-t.h>

/**** FCGI connection flags (32 bit), in fcgi_conn->flags ****/
#define FCGI_CF_NONE           0x00000000

/* Flags indicating why writing to the mux is blocked */
#define FCGI_CF_MUX_MALLOC      0x00000001 /* mux is blocked on lack connection's mux buffer */
#define FCGI_CF_MUX_MFULL       0x00000002 /* mux is blocked on connection's mux buffer full */
#define FCGI_CF_MUX_BLOCK_ANY   0x00000003 /* mux is blocked on connection's mux buffer full */

/* Flags indicating why writing to the demux is blocked.
 * The first two ones directly affect the ability for the mux to receive data
 * from the connection. The other ones affect the mux's ability to demux
 * received data.
 */
#define FCGI_CF_DEM_DALLOC      0x00000004  /* demux blocked on lack of connection's demux buffer */
#define FCGI_CF_DEM_DFULL       0x00000008  /* demux blocked on connection's demux buffer full */
#define FCGI_CF_DEM_MROOM       0x00000010  /* demux blocked on lack of room in mux buffer */
#define FCGI_CF_DEM_SALLOC      0x00000020  /* demux blocked on lack of stream's rx buffer */
#define FCGI_CF_DEM_SFULL       0x00000040  /* demux blocked on stream request buffer full */
#define FCGI_CF_DEM_TOOMANY     0x00000080  /* demux blocked waiting for some stream connectors to leave */
#define FCGI_CF_DEM_BLOCK_ANY   0x000000F0  /* aggregate of the demux flags above except DALLOC/DFULL */

/* Other flags */
#define FCGI_CF_MPXS_CONNS      0x00000100  /* connection multiplexing is supported */
#define FCGI_CF_ABRTS_SENT      0x00000200  /* a record ABORT was successfully sent to all active streams */
#define FCGI_CF_ABRTS_FAILED    0x00000400  /* failed to abort processing of all streams */
#define FCGI_CF_WAIT_FOR_HS     0x00000800  /* We did check that at least a stream was waiting for handshake */
#define FCGI_CF_KEEP_CONN       0x00001000  /* HAProxy is responsible to close the connection */
#define FCGI_CF_GET_VALUES      0x00002000  /* retrieve settings */

#define FCGI_CF_EOS             0x00004000  /* End-of-stream seen on the H1 connection (read0 detected) */
#define FCGI_CF_ERR_PENDING     0x00008000  /* A write error was detected (block sends but not reads) */
#define FCGI_CF_ERROR           0x00010000  /* A read error was detected (handled has an abort) */


/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *fconn_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(FCGI_CF_MUX_MALLOC, _(FCGI_CF_MUX_MFULL,
	_(FCGI_CF_DEM_DALLOC, _(FCGI_CF_DEM_DFULL, _(FCGI_CF_DEM_MROOM,
	_(FCGI_CF_DEM_SALLOC, _(FCGI_CF_DEM_SFULL, _(FCGI_CF_DEM_TOOMANY,
	_(FCGI_CF_MPXS_CONNS, _(FCGI_CF_ABRTS_SENT, _(FCGI_CF_ABRTS_FAILED,
	_(FCGI_CF_WAIT_FOR_HS, _(FCGI_CF_KEEP_CONN, _(FCGI_CF_GET_VALUES,
	_(FCGI_CF_EOS, _(FCGI_CF_ERR_PENDING, _(FCGI_CF_ERROR)))))))))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/**** FCGI stream flags (32 bit), in fcgi_strm->flags ****/
#define FCGI_SF_NONE           0x00000000
#define FCGI_SF_ES_RCVD        0x00000001 /* end-of-stream received (empty STDOUT or EDN_REQUEST record) */
#define FCGI_SF_ES_SENT        0x00000002 /* end-of-stream sent (empty STDIN record) */
#define FCGI_SF_EP_SENT        0x00000004 /* end-of-param sent (empty PARAMS  record) */
#define FCGI_SF_ABRT_SENT      0x00000008 /* abort sent (ABORT_REQUEST record) */

/* Stream flags indicating the reason the stream is blocked */
#define FCGI_SF_BLK_MBUSY      0x00000010 /* blocked waiting for mux access (transient) */
#define FCGI_SF_BLK_MROOM      0x00000020 /* blocked waiting for room in the mux */
#define FCGI_SF_BLK_ANY        0x00000030 /* any of the reasons above */

#define FCGI_SF_BEGIN_SENT     0x00000100  /* a BEGIN_REQUEST record was sent for this stream */
#define FCGI_SF_OUTGOING_DATA  0x00000200  /* set whenever we've seen outgoing data */
#define FCGI_SF_NOTIFIED       0x00000400  /* a paused stream was notified to try to send again */

#define FCGI_SF_WANT_SHUTR     0x00001000  /* a stream couldn't shutr() (mux full/busy) */
#define FCGI_SF_WANT_SHUTW     0x00002000  /* a stream couldn't shutw() (mux full/busy) */

/* This function is used to report flags in debugging tools. Please reflect
 * below any single-bit flag addition above in the same order via the
 * __APPEND_FLAG macro. The new end of the buffer is returned.
 */
static forceinline char *fstrm_show_flags(char *buf, size_t len, const char *delim, uint flg)
{
#define _(f, ...) __APPEND_FLAG(buf, len, delim, flg, f, #f, __VA_ARGS__)
	/* prologue */
	_(0);
	/* flags */
	_(FCGI_SF_ES_RCVD, _(FCGI_SF_ES_SENT, _(FCGI_SF_EP_SENT, _(FCGI_SF_ABRT_SENT,
	_(FCGI_SF_BLK_MBUSY, _(FCGI_SF_BLK_MROOM,
	_(FCGI_SF_BEGIN_SENT, _(FCGI_SF_OUTGOING_DATA, _(FCGI_SF_NOTIFIED,
	_(FCGI_SF_WANT_SHUTR, _(FCGI_SF_WANT_SHUTW)))))))))));
	/* epilogue */
	_(~0U);
	return buf;
#undef _
}

/* FCGI connection state (fcgi_conn->state) */
enum fcgi_conn_st {
	FCGI_CS_INIT = 0,    /* init done, waiting for sending GET_VALUES record */
	FCGI_CS_SETTINGS,    /* GET_VALUES sent, waiting for the GET_VALUES_RESULT record */
	FCGI_CS_RECORD_H,    /* GET_VALUES_RESULT received, waiting for a record header */
	FCGI_CS_RECORD_D,    /* Record header OK, waiting for a record data */
	FCGI_CS_RECORD_P,    /* Record processed, remains the padding */
	FCGI_CS_CLOSED,      /* abort requests if necessary and  close the connection ASAP */
	FCGI_CS_ENTRIES
} __attribute__((packed));

/* returns a fconn state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *fconn_st_to_str(enum fcgi_conn_st st)
{
	switch (st) {
		case FCGI_CS_INIT     : return "INI";
		case FCGI_CS_SETTINGS : return "STG";
		case FCGI_CS_RECORD_H : return "RDH";
		case FCGI_CS_RECORD_D : return "RDD";
		case FCGI_CS_RECORD_P : return "RDP";
		case FCGI_CS_CLOSED   : return "CLO";
		default               : return "???";
	}
}

/* FCGI stream state, in fcgi_strm->state */
enum fcgi_strm_st {
	FCGI_SS_IDLE = 0,
	FCGI_SS_OPEN,
	FCGI_SS_HREM,     // half-closed(remote)
	FCGI_SS_HLOC,     // half-closed(local)
	FCGI_SS_ERROR,
	FCGI_SS_CLOSED,
	FCGI_SS_ENTRIES
} __attribute__((packed));


/* returns a fstrm state as an abbreviated 3-letter string, or "???" if unknown */
static inline const char *fstrm_st_to_str(enum fcgi_strm_st st)
{
	switch (st) {
		case FCGI_SS_IDLE   : return "IDL";
		case FCGI_SS_OPEN   : return "OPN";
		case FCGI_SS_HREM   : return "RCL";
		case FCGI_SS_HLOC   : return "HCL";
		case FCGI_SS_ERROR  : return "ERR";
		case FCGI_SS_CLOSED : return "CLO";
		default             : return "???";
	}
}


#endif /* _HAPROXY_MUX_FCGI_T_H */
