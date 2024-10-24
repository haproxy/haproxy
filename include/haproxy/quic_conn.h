/*
 * include/haproxy/quic_conn.h
 *
 * Copyright 2020 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_QUIC_CONN_H
#define _HAPROXY_QUIC_CONN_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <inttypes.h>

#include <import/eb64tree.h>
#include <import/ebmbtree.h>

#include <haproxy/chunk.h>
#include <haproxy/dynbuf.h>
#include <haproxy/ncbuf.h>
#include <haproxy/net_helper.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ticks.h>

#include <haproxy/listener.h>
#include <haproxy/proto_quic.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_cid.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_loss.h>
#include <haproxy/quic_pacing.h>
#include <haproxy/quic_rx.h>
#include <haproxy/mux_quic.h>

#include <openssl/rand.h>

extern struct pool_head *pool_head_quic_connection_id;

int qc_conn_finalize(struct quic_conn *qc, int server);
int ssl_quic_initial_ctx(struct bind_conf *bind_conf);
struct quic_cstream *quic_cstream_new(struct quic_conn *qc);
void quic_cstream_free(struct quic_cstream *cs);
void quic_free_arngs(struct quic_conn *qc, struct quic_arngs *arngs);
struct quic_cstream *quic_cstream_new(struct quic_conn *qc);
struct task *quic_conn_app_io_cb(struct task *t, void *context, unsigned int state);

void quic_conn_closed_err_count_inc(struct quic_conn *qc, struct quic_frame *frm);
int qc_h3_request_reject(struct quic_conn *qc, uint64_t id);
struct quic_conn *qc_new_conn(const struct quic_version *qv, int ipv4,
                              struct quic_cid *dcid, struct quic_cid *scid,
                              const struct quic_cid *token_odcid,
                              struct quic_connection_id *conn_id,
                              struct sockaddr_storage *local_addr,
                              struct sockaddr_storage *peer_addr,
                              int server, int token, void *owner);
int quic_build_post_handshake_frames(struct quic_conn *qc);
const struct quic_version *qc_supported_version(uint32_t version);
int quic_peer_validated_addr(struct quic_conn *qc);
void qc_set_timer(struct quic_conn *qc);
void qc_detach_th_ctx_list(struct quic_conn *qc, int closing);
void qc_idle_timer_do_rearm(struct quic_conn *qc, int arm_ack);
void qc_idle_timer_rearm(struct quic_conn *qc, int read, int arm_ack);
void qc_check_close_on_released_mux(struct quic_conn *qc);
int quic_stateless_reset_token_cpy(unsigned char *pos, size_t len,
                                   const unsigned char *salt, size_t saltlen);

static inline int qc_is_listener(struct quic_conn *qc)
{
	return qc->flags & QUIC_FL_CONN_LISTENER;
}

/* Free the CIDs attached to <conn> QUIC connection. */
static inline void free_quic_conn_cids(struct quic_conn *conn)
{
	struct eb64_node *node;

	if (!conn->cids)
		return;

	node = eb64_first(conn->cids);
	while (node) {
		struct quic_connection_id *conn_id;

		conn_id = eb64_entry(node, struct quic_connection_id, seq_num);

		/* remove the CID from the receiver tree */
		quic_cid_delete(conn_id);

		/* remove the CID from the quic_conn tree */
		node = eb64_next(node);
		eb64_delete(&conn_id->seq_num);
		pool_free(pool_head_quic_connection_id, conn_id);
	}
}

/* Move all the connection IDs from <conn> QUIC connection to <cc_conn> */
static inline void quic_conn_mv_cids_to_cc_conn(struct quic_conn_closed *cc_conn,
                                                struct quic_conn *conn)
{
	struct eb64_node *node;

	node = eb64_first(conn->cids);
	while (node) {
		struct quic_connection_id *conn_id;

		conn_id = eb64_entry(node, struct quic_connection_id, seq_num);
		conn_id->qc = (struct quic_conn *)cc_conn;
		node = eb64_next(node);
	}

}

/* Allocate the underlying required memory for <ncbuf> non-contiguous buffer */
static inline struct ncbuf *quic_get_ncbuf(struct ncbuf *ncbuf)
{
	struct buffer buf = BUF_NULL;

	if (!ncb_is_null(ncbuf))
		return ncbuf;

	b_alloc(&buf, DB_MUX_RX);
	BUG_ON(b_is_null(&buf));

	*ncbuf = ncb_make(buf.area, buf.size, 0);
	ncb_init(ncbuf, 0);

	return ncbuf;
}

/* Release the underlying memory use by <ncbuf> non-contiguous buffer */
static inline void quic_free_ncbuf(struct ncbuf *ncbuf)
{
	struct buffer buf;

	if (ncb_is_null(ncbuf))
		return;

	buf = b_make(ncbuf->area, ncbuf->size, 0, 0);
	b_free(&buf);
	offer_buffers(NULL, 1);

	*ncbuf = NCBUF_NULL;
}

void chunk_frm_appendf(struct buffer *buf, const struct quic_frame *frm);
void quic_set_connection_close(struct quic_conn *qc, const struct quic_err err);
void quic_set_tls_alert(struct quic_conn *qc, int alert);
int quic_set_app_ops(struct quic_conn *qc, const unsigned char *alpn, size_t alpn_len);
int qc_check_dcid(struct quic_conn *qc, unsigned char *dcid, size_t dcid_len);

void qc_notify_err(struct quic_conn *qc);
int qc_notify_send(struct quic_conn *qc);

void qc_check_close_on_released_mux(struct quic_conn *qc);

void quic_conn_release(struct quic_conn *qc);

void qc_kill_conn(struct quic_conn *qc);

int qc_parse_hd_form(struct quic_rx_packet *pkt,
                     unsigned char **buf, const unsigned char *end);

int qc_bind_tid_prep(struct quic_conn *qc, uint new_tid);
void qc_bind_tid_commit(struct quic_conn *qc, struct listener *new_li);
void qc_bind_tid_reset(struct quic_conn *qc);
void qc_finalize_tid_rebind(struct quic_conn *qc);

int qc_handle_conn_migration(struct quic_conn *qc,
                             const struct sockaddr_storage *peer_addr,
                             const struct sockaddr_storage *local_addr);

/* Function pointer that can be used to compute a hash from first generated CID (derived from ODCID) */
extern uint64_t (*quic_hash64_from_cid)(const unsigned char *cid, int size, const unsigned char *secret, size_t secretlen);
/* Function pointer that can be used to derive a new CID from the previously computed hash */
extern void (*quic_newcid_from_hash64)(unsigned char *cid, int size, uint64_t hash, const unsigned char *secret, size_t secretlen);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_CONN_H */
