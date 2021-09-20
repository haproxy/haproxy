/*
 * include/haproxy/mux_quic-t.h
 * This file containts types for QUIC mux-demux.
 *
 * Copyright 2021 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_MUX_QUIC_T_H
#define _HAPROXY_MUX_QUIC_T_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <stdint.h>

#include <haproxy/buf-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/dynbuf-t.h>

#include <import/eb64tree.h>

/* Bit shift to get the stream sub ID for internal use which is obtained
 * shifting the stream IDs by this value, knowing that the
 * QCS_ID_TYPE_SHIFT less significant bits identify the stream ID
 * types (client initiated bidirectional, server initiated bidirectional,
 * client initiated unidirectional, server initiated bidirectional).
 * Note that there is no reference to such stream sub IDs in the RFC.
 */
#define QCS_ID_TYPE_MASK         0x3
#define QCS_ID_TYPE_SHIFT          2
/* The less significant bit of a stream ID is set for a server initiated stream */
#define QCS_ID_SRV_INTIATOR_BIT  0x1
/* This bit is set for unidirectional streams */
#define QCS_ID_DIR_BIT           0x2
#define QCS_ID_DIR_BIT_SHIFT       1

#define OUQS_SF_TXBUF_MALLOC 0x00000001
#define OUQS_SF_TXBUF_FULL   0x00000002

/* Connection flags (32 bit), in qcc->flags */
#define QC_CF_NONE              0x00000000

/* Flags indicating why writing to the mux is blocked. */
#define QC_CF_MUX_MALLOC        0x00000001  // mux blocked on lack of connection's mux buffer
#define QC_CF_MUX_MFULL         0x00000002  // mux blocked on connection's mux buffer full
#define QC_CF_MUX_BLOCK_ANY     0x00000003  // aggregate of the mux flags above

/* Flags indicating why writing to the demux is blocked.
 * The first two ones directly affect the ability for the mux to receive data
 * from the connection. The other ones affect the mux's ability to demux
 * received data.
 */
#define QC_CF_DEM_DFULL         0x00000004  // demux blocked on connection's demux buffer full

#define QC_CF_DEM_MBUSY         0x00000008  // demux blocked on connection's mux side busy
#define QC_CF_DEM_MROOM         0x00000010  // demux blocked on lack of room in mux buffer
#define QC_CF_DEM_SALLOC        0x00000020  // demux blocked on lack of stream's request buffer
#define QC_CF_DEM_SFULL         0x00000040  // demux blocked on stream request buffer full
#define QC_CF_DEM_TOOMANY       0x00000100  // demux blocked waiting for some conn_streams to leave
#define QC_CF_DEM_BLOCK_ANY     0x00000170  // aggregate of the demux flags above except DFULL

/* other flags */
#define QC_CF_IS_BACK           0x00008000  // this is an outgoing connection

extern struct pool_head *pool_head_qcs;

/* Stream types */
enum qcs_type {
	QCS_CLT_BIDI,
	QCS_SRV_BIDI,
	QCS_CLT_UNI,
	QCS_SRV_UNI,
	/* Must be the last one */
	QCS_MAX_TYPES,
};

/* 32 buffers: one for the ring's root, rest for the mbuf itself */
#define QCC_MBUF_CNT 32

/* Stream direction types */
enum qcs_dir {
	QCS_BIDI    = 0,
	QCS_UNI     = 1,
	/* Must be the last one */
	QCS_MAX_DIR = 2,
};

/* QUIC connection state, in qcc->st0 */
enum qc_cs {
	/* Initial state */
	QC_CS_NOERR,
	QC_CS_ERROR,
};

/* QUIC connection descriptor */
struct qcc {
	struct connection *conn; /* mux state */
	enum qc_cs st0; /* connection flags: QC_CF_* */
	unsigned int errcode;
	uint32_t flags;
	/* Stream information, one by direction and by initiator */
	struct {
		uint64_t max_streams; /* maximum number of concurrent streams */
		uint64_t largest_id;  /* Largest ID of the open streams */
		uint64_t nb_streams;  /* Number of open streams */
		struct {
			uint64_t max_data; /* Maximum number of bytes which may be received */
			uint64_t bytes;    /* Number of bytes received */
		} rx;
		struct {
			uint64_t max_data; /* Maximum number of bytes which may be sent */
			uint64_t bytes;    /* Number of bytes sent */
		} tx;
	} strms[QCS_MAX_TYPES];
	struct {
		uint64_t max_data; /* Maximum number of bytes which may be received */
		uint64_t bytes;    /* Number of bytes received */
		uint64_t inmux;    /* Number of bytes received but not already demultiplexed. */
	} rx;
	struct {
		uint64_t max_data; /* Maximum number of bytes which may be sent */
		uint64_t bytes;    /* Number of bytes sent */
	} tx;

	struct eb_root streams_by_id; /* all active streams by their ID */

	/* states for the mux direction */
	struct buffer mbuf[QCC_MBUF_CNT];   /* mux buffers (ring) */

	int timeout;        /* idle timeout duration in ticks */
	int shut_timeout;   /* idle timeout duration in ticks after GOAWAY was sent */
	unsigned int nb_cs;       /* number of attached conn_streams */
	unsigned int stream_cnt;  /* total number of streams seen */
	struct proxy *proxy; /* the proxy this connection was created for */
	struct task *task;  /* timeout management task */
	struct qc_counters *px_counters; /* quic counters attached to proxy */
	struct list send_list; /* list of blocked streams requesting to send */
	struct list fctl_list; /* list of streams blocked by connection's fctl */
	struct list blocked_list; /* list of streams blocked for other reasons (e.g. sfctl, dep) */
	struct buffer_wait buf_wait; /* wait list for buffer allocations */
	struct wait_event wait_event;  /* To be used if we're waiting for I/Os */
	struct wait_event *subs;      /* recv wait_event the mux associated is waiting on (via quic_conn_subscribe) */
	struct mt_list qcs_rxbuf_wlist; /* list of streams waiting for their rxbuf */
	void *ctx; /* Application layer context */
	const struct qcc_app_ops *app_ops;
};

/* QUIC RX states */
enum qcs_rx_st {
	QC_RX_SS_IDLE = 0,   // idle
	QC_RX_SS_RECV,       // receive
	QC_RX_SS_SIZE_KNOWN, // stream size known
	/* Terminal states */
	QC_RX_SS_DATA_RECVD, // all data received
	QC_RX_SS_DATA_READ,  // app. read all data
	QC_RX_SS_RST_RECVD,  // reset received
	QC_RX_SS_RST_READ,   // app. read reset
};

/* QUIC TX states */
enum qcs_tx_st {
	QC_TX_SS_IDLE = 0,
	QC_TX_SS_READY,      // ready
	QC_TX_SS_SEND,       // send
	QC_TX_SS_DATA_SENT,  // all data sent
	/* Terminal states */
	QC_TX_SS_DATA_RECVD, // all data received
	QC_TX_SS_RST_SENT,   // reset sent
	QC_TX_SS_RST_RECVD,  // reset received
};

/* QUIC stream flags (32 bit), in qcs->flags */
#define QC_SF_NONE              0x00000000

#define QC_SF_TXBUF_MALLOC      0x00000001 // blocked on lack of TX buffer
/* stream flags indicating the reason the stream is blocked */
#define QC_SF_BLK_MBUSY         0x00000010 // blocked waiting for mux access (transient)
#define QC_SF_BLK_MROOM         0x00000020 // blocked waiting for room in the mux (must be in send list)
#define QC_SF_BLK_MFCTL         0x00000040 // blocked due to mux fctl (must be in fctl list)
#define QC_SF_BLK_SFCTL         0x00000080 // blocked due to stream fctl (must be in blocked list)
#define QC_SF_BLK_ANY           0x000000F0 // any of the reasons above

#define QC_SF_NOTIFIED          0x00000800  // a paused stream was notified to try to send again

#define QC_SF_WANT_SHUTR        0x00008000  // a stream couldn't shutr() (mux full/busy)
#define QC_SF_WANT_SHUTW        0x00010000  // a stream couldn't shutw() (mux full/busy)
#define QC_SF_KILL_CONN         0x00020000  // kill the whole connection with this stream

#define QC_SF_FIN_STREAM        0x00040000  // FIN bit must be set for last frame of the stream

/* QUIC stream descriptor, describing the stream as it appears in the QUIC_CONN, and as
 * it is being processed in the internal HTTP representation (HTX).
 */
struct qcs {
	struct conn_stream *cs;
	struct session *sess;
	struct qcc *qcc;
	struct eb64_node by_id; /* place in qcc's streams_by_id */
	uint64_t id; /* stream ID */
	uint32_t flags;      /* QC_SF_* */
	struct {
		enum qcs_rx_st st; /* RX state */
		uint64_t max_data; /* maximum number of bytes which may be received */
		uint64_t offset;   /* the current offset of received data */
		uint64_t bytes;    /* number of bytes received */
		struct buffer buf; /* receive buffer, always valid (buf_empty or real buffer) */
		struct eb_root frms; /* received frames ordered by their offsets */
	} rx;
	struct {
		enum qcs_tx_st st; /* TX state */
		uint64_t max_data; /* maximum number of bytes which may be sent */
		uint64_t offset;   /* the current offset of data to send */
		uint64_t bytes;    /* number of bytes sent */
		uint64_t ack_offset; /* last acked ordered byte offset */
		struct eb_root acked_frms; /* acked frames ordered by their offsets */
		struct buffer buf; /* transmit buffer, always valid (buf_empty or real buffer) */
		struct buffer mbuf[QCC_MBUF_CNT];
		uint64_t left;     /* data currently stored in mbuf waiting for send */
	} tx;
	struct wait_event *subs;  /* recv wait_event the conn_stream associated is waiting on (via qc_subscribe) */
	struct list list; /* To be used when adding in qcc->send_list or qcc->fctl_lsit */
	struct tasklet *shut_tl;  /* deferred shutdown tasklet, to retry to send an RST after we failed to,
				   * in case there's no other subscription to do it */
};

/* QUIC application layer operations */
struct qcc_app_ops {
	int (*init)(struct qcc *qcc);
	int (*attach_ruqs)(struct qcs *qcs, void *ctx);
	int (*decode_qcs)(struct qcs *qcs, void *ctx);
	int (*finalize)(void *ctx);
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_MUX_QUIC_T_H */
