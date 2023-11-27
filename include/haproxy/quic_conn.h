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

#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/ncbuf-t.h>
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

struct quic_connection_id *new_quic_cid(struct eb_root *root,
                                        struct quic_conn *qc,
                                        const struct quic_cid *orig,
                                        const struct sockaddr_storage *addr);
void qc_cc_err_count_inc(struct quic_conn *qc, struct quic_frame *frm);
int qc_h3_request_reject(struct quic_conn *qc, uint64_t id);
int qc_build_new_connection_id_frm(struct quic_conn *qc,
                                   struct quic_connection_id *conn_id);
struct quic_conn *qc_new_conn(const struct quic_version *qv, int ipv4,
                              struct quic_cid *dcid, struct quic_cid *scid,
                              const struct quic_cid *token_odcid,
                              struct quic_connection_id *conn_id,
                              struct sockaddr_storage *local_addr,
                              struct sockaddr_storage *peer_addr,
                              int server, int token, void *owner);
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
static inline void quic_conn_mv_cids_to_cc_conn(struct quic_cc_conn *cc_conn,
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

/* Copy <src> new connection ID information to <dst> NEW_CONNECTION_ID frame.
 * Always succeeds.
 */
static inline void quic_connection_id_to_frm_cpy(struct quic_frame *dst,
                                                 struct quic_connection_id *src)
{
	struct qf_new_connection_id *ncid_frm = &dst->new_connection_id;

	ncid_frm->seq_num = src->seq_num.key;
	ncid_frm->retire_prior_to = src->retire_prior_to;
	ncid_frm->cid.len = src->cid.len;
	ncid_frm->cid.data = src->cid.data;
	ncid_frm->stateless_reset_token = src->stateless_reset_token;
}

/* Initialize <p> QUIC network path depending on <ipv4> boolean
 * which is true for an IPv4 path, if not false for an IPv6 path.
 */
static inline void quic_path_init(struct quic_path *path, int ipv4, unsigned long max_cwnd,
                                  struct quic_cc_algo *algo, struct quic_conn *qc)
{
	unsigned int max_dgram_sz;

	max_dgram_sz = ipv4 ? QUIC_INITIAL_IPV4_MTU : QUIC_INITIAL_IPV6_MTU;
	quic_loss_init(&path->loss);
	path->mtu = max_dgram_sz;
	path->cwnd = QUIC_MIN(10 * max_dgram_sz, QUIC_MAX(max_dgram_sz << 1, 14720U));
	path->mcwnd = path->cwnd;
	path->max_cwnd = max_cwnd;
	path->min_cwnd = max_dgram_sz << 1;
	path->prep_in_flight = 0;
	path->in_flight = 0;
	path->ifae_pkts = 0;
	quic_cc_init(&path->cc, algo, qc);
}

/* Return the remaining <room> available on <path> QUIC path for prepared data
 * (before being sent). Almost the same that for the QUIC path room, except that
 * here this is the data which have been prepared which are taken into an account.
 */
static inline size_t quic_path_prep_data(struct quic_path *path)
{
	if (path->prep_in_flight > path->cwnd)
		return 0;

	return path->cwnd - path->prep_in_flight;
}

/* Return 1 if <pkt> header form is long, 0 if not. */
static inline int qc_pkt_long(const struct quic_rx_packet *pkt)
{
	return pkt->type != QUIC_PACKET_TYPE_SHORT;
}

void chunk_frm_appendf(struct buffer *buf, const struct quic_frame *frm);

void quic_set_connection_close(struct quic_conn *qc, const struct quic_err err);
void quic_set_tls_alert(struct quic_conn *qc, int alert);
int quic_set_app_ops(struct quic_conn *qc, const unsigned char *alpn, size_t alpn_len);
int qc_check_dcid(struct quic_conn *qc, unsigned char *dcid, size_t dcid_len);
struct quic_cid quic_derive_cid(const struct quic_cid *orig,
                                const struct sockaddr_storage *addr);
int quic_get_cid_tid(const unsigned char *cid, size_t cid_len,
                     const struct sockaddr_storage *cli_addr,
                     unsigned char *buf, size_t buf_len);
int qc_send_mux(struct quic_conn *qc, struct list *frms);

void qc_notify_err(struct quic_conn *qc);
int qc_notify_send(struct quic_conn *qc);

void qc_check_close_on_released_mux(struct quic_conn *qc);

void quic_conn_release(struct quic_conn *qc);

void qc_kill_conn(struct quic_conn *qc);

int qc_parse_hd_form(struct quic_rx_packet *pkt,
                     unsigned char **buf, const unsigned char *end);
int quic_dgram_parse(struct quic_dgram *dgram, struct quic_conn *qc,
                     struct listener *li);

int qc_set_tid_affinity(struct quic_conn *qc, uint new_tid, struct listener *new_li);
void qc_finalize_affinity_rebind(struct quic_conn *qc);

/* Function pointer that can be used to compute a hash from first generated CID (derived from ODCID) */
extern uint64_t (*quic_hash64_from_cid)(const unsigned char *cid, int size, const unsigned char *secret, size_t secretlen);
/* Function pointer that can be used to derive a new CID from the previously computed hash */
extern void (*quic_newcid_from_hash64)(unsigned char *cid, int size, uint64_t hash, const unsigned char *secret, size_t secretlen);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_CONN_H */
