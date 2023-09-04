/*
 * QUIC protocol implementation. Lower layer with internal features implemented
 * here such as QUIC encryption, idle timeout, acknowledgement and
 * retransmission.
 *
 * Copyright 2020 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/quic_conn.h>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <import/ebmbtree.h>

#include <haproxy/buf-t.h>
#include <haproxy/compat.h>
#include <haproxy/api.h>
#include <haproxy/debug.h>
#include <haproxy/tools.h>
#include <haproxy/ticks.h>
#include <haproxy/xxhash.h>

#include <haproxy/connection.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/global.h>
#include <haproxy/h3.h>
#include <haproxy/hq_interop.h>
#include <haproxy/log.h>
#include <haproxy/mux_quic.h>
#include <haproxy/ncbuf.h>
#include <haproxy/pipe.h>
#include <haproxy/proxy.h>
#include <haproxy/quic_ack.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_cli-t.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_loss.h>
#include <haproxy/quic_rx.h>
#include <haproxy/quic_ssl.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_stats.h>
#include <haproxy/quic_stream.h>
#include <haproxy/quic_tp.h>
#include <haproxy/quic_trace.h>
#include <haproxy/quic_tx.h>
#include <haproxy/cbuf.h>
#include <haproxy/proto_quic.h>
#include <haproxy/quic_tls.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/trace.h>

/* list of supported QUIC versions by this implementation */
const struct quic_version quic_versions[] = {
	{
		.num              = QUIC_PROTOCOL_VERSION_DRAFT_29,
		.initial_salt     = initial_salt_draft_29,
		.initial_salt_len = sizeof initial_salt_draft_29,
		.key_label        = (const unsigned char *)QUIC_HKDF_KEY_LABEL_V1,
		.key_label_len    = sizeof(QUIC_HKDF_KEY_LABEL_V1) - 1,
		.iv_label         = (const unsigned char *)QUIC_HKDF_IV_LABEL_V1,
		.iv_label_len     = sizeof(QUIC_HKDF_IV_LABEL_V1) - 1,
		.hp_label         = (const unsigned char *)QUIC_HKDF_HP_LABEL_V1,
		.hp_label_len     = sizeof(QUIC_HKDF_HP_LABEL_V1) - 1,
		.ku_label         = (const unsigned char *)QUIC_HKDF_KU_LABEL_V1,
		.ku_label_len     = sizeof(QUIC_HKDF_KU_LABEL_V1) - 1,
		.retry_tag_key    = (const unsigned char *)QUIC_TLS_RETRY_KEY_DRAFT,
		.retry_tag_nonce  = (const unsigned char *)QUIC_TLS_RETRY_NONCE_DRAFT,
	},
	{
		.num              = QUIC_PROTOCOL_VERSION_1,
		.initial_salt     = initial_salt_v1,
		.initial_salt_len = sizeof initial_salt_v1,
		.key_label        = (const unsigned char *)QUIC_HKDF_KEY_LABEL_V1,
		.key_label_len    = sizeof(QUIC_HKDF_KEY_LABEL_V1) - 1,
		.iv_label         = (const unsigned char *)QUIC_HKDF_IV_LABEL_V1,
		.iv_label_len     = sizeof(QUIC_HKDF_IV_LABEL_V1) - 1,
		.hp_label         = (const unsigned char *)QUIC_HKDF_HP_LABEL_V1,
		.hp_label_len     = sizeof(QUIC_HKDF_HP_LABEL_V1) - 1,
		.ku_label         = (const unsigned char *)QUIC_HKDF_KU_LABEL_V1,
		.ku_label_len     = sizeof(QUIC_HKDF_KU_LABEL_V1) - 1,
		.retry_tag_key    = (const unsigned char *)QUIC_TLS_RETRY_KEY_V1,
		.retry_tag_nonce  = (const unsigned char *)QUIC_TLS_RETRY_NONCE_V1,
	},
	{
		.num              = QUIC_PROTOCOL_VERSION_2,
		.initial_salt     = initial_salt_v2,
		.initial_salt_len = sizeof initial_salt_v2,
		.key_label        = (const unsigned char *)QUIC_HKDF_KEY_LABEL_V2,
		.key_label_len    = sizeof(QUIC_HKDF_KEY_LABEL_V2) - 1,
		.iv_label         = (const unsigned char *)QUIC_HKDF_IV_LABEL_V2,
		.iv_label_len     = sizeof(QUIC_HKDF_IV_LABEL_V2) - 1,
		.hp_label         = (const unsigned char *)QUIC_HKDF_HP_LABEL_V2,
		.hp_label_len     = sizeof(QUIC_HKDF_HP_LABEL_V2) - 1,
		.ku_label         = (const unsigned char *)QUIC_HKDF_KU_LABEL_V2,
		.ku_label_len     = sizeof(QUIC_HKDF_KU_LABEL_V2) - 1,
		.retry_tag_key    = (const unsigned char *)QUIC_TLS_RETRY_KEY_V2,
		.retry_tag_nonce  = (const unsigned char *)QUIC_TLS_RETRY_NONCE_V2,
	},
};

/* The total number of supported versions */
const size_t quic_versions_nb = sizeof quic_versions / sizeof *quic_versions;
/* Listener only preferred version */
const struct quic_version *preferred_version;
/* RFC 8999 5.4. Version
 * A Version field with a
 * value of 0x00000000 is reserved for version negotiation
 */
const struct quic_version quic_version_VN_reserved = { .num = 0, };

static BIO_METHOD *ha_quic_meth;

DECLARE_STATIC_POOL(pool_head_quic_conn, "quic_conn", sizeof(struct quic_conn));
DECLARE_STATIC_POOL(pool_head_quic_cc_conn, "quic_cc_conn", sizeof(struct quic_cc_conn));
DECLARE_STATIC_POOL(pool_head_quic_cids, "quic_cids", sizeof(struct eb_root));
DECLARE_POOL(pool_head_quic_connection_id,
             "quic_connection_id", sizeof(struct quic_connection_id));
DECLARE_POOL(pool_head_quic_crypto_buf, "quic_crypto_buf", sizeof(struct quic_crypto_buf));
DECLARE_STATIC_POOL(pool_head_quic_cstream, "quic_cstream", sizeof(struct quic_cstream));

struct task *quic_conn_app_io_cb(struct task *t, void *context, unsigned int state);
static int quic_conn_init_timer(struct quic_conn *qc);
static int quic_conn_init_idle_timer_task(struct quic_conn *qc);

/* Returns 1 if the peer has validated <qc> QUIC connection address, 0 if not. */
int quic_peer_validated_addr(struct quic_conn *qc)
{
	if (!qc_is_listener(qc))
		return 1;

	if ((qc->hpktns && (qc->hpktns->flags & QUIC_FL_PKTNS_PKT_RECEIVED)) ||
	    (qc->apktns && (qc->apktns->flags & QUIC_FL_PKTNS_PKT_RECEIVED)) ||
	    qc->state >= QUIC_HS_ST_COMPLETE)
		return 1;

	BUG_ON(qc->bytes.prep > 3 * qc->bytes.rx);

	return 0;
}

/* To be called to kill a connection as soon as possible (without sending any packet). */
void qc_kill_conn(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_KILL, qc);
	TRACE_PROTO("killing the connection", QUIC_EV_CONN_KILL, qc);
	qc->flags |= QUIC_FL_CONN_TO_KILL;
	task_wakeup(qc->idle_timer_task, TASK_WOKEN_OTHER);

	qc_notify_err(qc);

	TRACE_LEAVE(QUIC_EV_CONN_KILL, qc);
}

/* Set the timer attached to the QUIC connection with <ctx> as I/O handler and used for
 * both loss detection and PTO and schedule the task assiated to this timer if needed.
 */
void qc_set_timer(struct quic_conn *qc)
{
	struct quic_pktns *pktns;
	unsigned int pto;
	int handshake_confirmed;

	TRACE_ENTER(QUIC_EV_CONN_STIMER, qc);
	TRACE_PROTO("set timer", QUIC_EV_CONN_STIMER, qc, NULL, NULL, &qc->path->ifae_pkts);

	pktns = NULL;
	if (!qc->timer_task) {
		TRACE_PROTO("already released timer task", QUIC_EV_CONN_STIMER, qc);
		goto leave;
	}

	pktns = quic_loss_pktns(qc);
	if (tick_isset(pktns->tx.loss_time)) {
		qc->timer = pktns->tx.loss_time;
		goto out;
	}

	/* anti-amplification: the timer must be
	 * cancelled for a server which reached the anti-amplification limit.
	 */
	if (!quic_peer_validated_addr(qc) &&
	    (qc->flags & QUIC_FL_CONN_ANTI_AMPLIFICATION_REACHED)) {
		TRACE_PROTO("anti-amplification reached", QUIC_EV_CONN_STIMER, qc);
		qc->timer = TICK_ETERNITY;
		goto out;
	}

	if (!qc->path->ifae_pkts && quic_peer_validated_addr(qc)) {
		TRACE_PROTO("timer cancellation", QUIC_EV_CONN_STIMER, qc);
		/* Timer cancellation. */
		qc->timer = TICK_ETERNITY;
		goto out;
	}

	handshake_confirmed = qc->state >= QUIC_HS_ST_CONFIRMED;
	pktns = quic_pto_pktns(qc, handshake_confirmed, &pto);
	if (tick_isset(pto))
		qc->timer = pto;
 out:
	if (qc->timer == TICK_ETERNITY) {
		qc->timer_task->expire = TICK_ETERNITY;
	}
	else  if (tick_is_expired(qc->timer, now_ms)) {
		TRACE_DEVEL("wakeup asap timer task", QUIC_EV_CONN_STIMER, qc);
		task_wakeup(qc->timer_task, TASK_WOKEN_MSG);
	}
	else {
		TRACE_DEVEL("timer task scheduling", QUIC_EV_CONN_STIMER, qc);
		task_schedule(qc->timer_task, qc->timer);
	}
 leave:
	TRACE_PROTO("set timer", QUIC_EV_CONN_STIMER, qc, pktns);
	TRACE_LEAVE(QUIC_EV_CONN_STIMER, qc);
}

/* Prepare the emission of CONNECTION_CLOSE with error <err>. All send/receive
 * activity for <qc> will be interrupted.
 */
void quic_set_connection_close(struct quic_conn *qc, const struct quic_err err)
{
	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);
	if (qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE)
		goto leave;

	TRACE_STATE("setting immediate close", QUIC_EV_CONN_CLOSE, qc);
	qc->flags |= QUIC_FL_CONN_IMMEDIATE_CLOSE;
	qc->err.code = err.code;
	qc->err.app  = err.app;

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Set <alert> TLS alert as QUIC CRYPTO_ERROR error */
void quic_set_tls_alert(struct quic_conn *qc, int alert)
{
	TRACE_ENTER(QUIC_EV_CONN_SSLALERT, qc);

	if (!(qc->flags & QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED)) {
		qc->flags |= QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED;
		TRACE_DEVEL("dec half open counter", QUIC_EV_CONN_SSLALERT, qc);
		HA_ATOMIC_DEC(&qc->prx_counters->half_open_conn);
	}
	quic_set_connection_close(qc, quic_err_tls(alert));
	qc->flags |= QUIC_FL_CONN_TLS_ALERT;
	TRACE_STATE("Alert set", QUIC_EV_CONN_SSLALERT, qc);

	TRACE_LEAVE(QUIC_EV_CONN_SSLALERT, qc);
}

/* Set the application for <qc> QUIC connection.
 * Return 1 if succeeded, 0 if not.
 */
int quic_set_app_ops(struct quic_conn *qc, const unsigned char *alpn, size_t alpn_len)
{
	if (alpn_len >= 2 && memcmp(alpn, "h3", 2) == 0)
		qc->app_ops = &h3_ops;
	else if (alpn_len >= 10 && memcmp(alpn, "hq-interop", 10) == 0)
		qc->app_ops = &hq_interop_ops;
	else
		return 0;

	return 1;
}

/* Schedule a CONNECTION_CLOSE emission on <qc> if the MUX has been released
 * and all STREAM data are acknowledged. The MUX is responsible to have set
 * <qc.err> before as it is reused for the CONNECTION_CLOSE frame.
 *
 * TODO this should also be called on lost packet detection
 */
void qc_check_close_on_released_mux(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	if (qc->mux_state == QC_MUX_RELEASED && eb_is_empty(&qc->streams_by_id)) {
		/* Reuse errcode which should have been previously set by the MUX on release. */
		quic_set_connection_close(qc, qc->err);
		tasklet_wakeup(qc->wait_event.tasklet);
	}

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

int ssl_sock_get_alpn(const struct connection *conn, void *xprt_ctx,
                      const char **str, int *len);

/* Finalize <qc> QUIC connection:

 * MUST be called after having received the remote transport parameters which
 * are parsed when the TLS callback for the ClientHello message is called upon
 * SSL_do_handshake() calls, not necessarily at the first time as this TLS
 * message may be split between packets
 * Return 1 if succeeded, 0 if not.
 */
int qc_conn_finalize(struct quic_conn *qc, int server)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	if (qc->flags & QUIC_FL_CONN_FINALIZED)
		goto finalized;

	if (!quic_tls_finalize(qc, server))
	    goto out;

	/* This connection is functional (ready to send/receive) */
	qc->flags |= QUIC_FL_CONN_FINALIZED;

 finalized:
	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
}

void qc_cc_err_count_inc(struct quic_conn *qc, struct quic_frame *frm)
{
	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	if (frm->type == QUIC_FT_CONNECTION_CLOSE)
		quic_stats_transp_err_count_inc(qc->prx_counters, frm->connection_close.error_code);
	else if (frm->type == QUIC_FT_CONNECTION_CLOSE_APP) {
		if (qc->mux_state != QC_MUX_READY || !qc->qcc->app_ops->inc_err_cnt)
			goto out;

		qc->qcc->app_ops->inc_err_cnt(qc->qcc->ctx, frm->connection_close_app.error_code);
	}

 out:
	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Cancel a request on connection <qc> for stream id <id>. This is useful when
 * the client opens a new stream but the MUX has already been released. A
 * STOP_SENDING + RESET_STREAM frames are prepared for emission.
 *
 * TODO this function is closely related to H3. Its place should be in H3 layer
 * instead of quic-conn but this requires an architecture adjustment.
 *
 * Returns 1 on success else 0.
 */
int qc_h3_request_reject(struct quic_conn *qc, uint64_t id)
{
	int ret = 0;
	struct quic_frame *ss, *rs;
	struct quic_enc_level *qel = qc->ael;
	const uint64_t app_error_code = H3_REQUEST_REJECTED;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);

	/* Do not emit rejection for unknown unidirectional stream as it is
	 * forbidden to close some of them (H3 control stream and QPACK
	 * encoder/decoder streams).
	 */
	if (quic_stream_is_uni(id)) {
		ret = 1;
		goto out;
	}

	ss = qc_frm_alloc(QUIC_FT_STOP_SENDING);
	if (!ss) {
		TRACE_ERROR("failed to allocate quic_frame", QUIC_EV_CONN_PRSHPKT, qc);
		goto out;
	}

	ss->stop_sending.id = id;
	ss->stop_sending.app_error_code = app_error_code;

	rs = qc_frm_alloc(QUIC_FT_RESET_STREAM);
	if (!rs) {
		TRACE_ERROR("failed to allocate quic_frame", QUIC_EV_CONN_PRSHPKT, qc);
		qc_frm_free(qc, &ss);
		goto out;
	}

	rs->reset_stream.id = id;
	rs->reset_stream.app_error_code = app_error_code;
	rs->reset_stream.final_size = 0;

	LIST_APPEND(&qel->pktns->tx.frms, &ss->list);
	LIST_APPEND(&qel->pktns->tx.frms, &rs->list);
	ret = 1;
 out:
	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return ret;
}

/* Build a NEW_CONNECTION_ID frame for <conn_id> CID of <qc> connection.
 *
 * Returns 1 on success else 0.
 */
int qc_build_new_connection_id_frm(struct quic_conn *qc,
                                   struct quic_connection_id *conn_id)
{
	int ret = 0;
	struct quic_frame *frm;
	struct quic_enc_level *qel;

	TRACE_ENTER(QUIC_EV_CONN_PRSHPKT, qc);

	qel = qc->ael;
	frm = qc_frm_alloc(QUIC_FT_NEW_CONNECTION_ID);
	if (!frm) {
		TRACE_ERROR("frame allocation error", QUIC_EV_CONN_IO_CB, qc);
		goto leave;
	}

	quic_connection_id_to_frm_cpy(frm, conn_id);
	LIST_APPEND(&qel->pktns->tx.frms, &frm->list);
	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_PRSHPKT, qc);
	return ret;
}


/* Remove a <qc> quic-conn from its ha_thread_ctx list. If <closing> is true,
 * it will immediately be reinserted in the ha_thread_ctx quic_conns_clo list.
 */
void qc_detach_th_ctx_list(struct quic_conn *qc, int closing)
{
	struct bref *bref, *back;

	/* Detach CLI context watchers currently dumping this connection.
	 * Reattach them to the next quic_conn instance.
	 */
	list_for_each_entry_safe(bref, back, &qc->back_refs, users) {
		/* Remove watcher from this quic_conn instance. */
		LIST_DEL_INIT(&bref->users);

		/* Attach it to next instance unless it was the last list element. */
		if (qc->el_th_ctx.n != &th_ctx->quic_conns &&
		    qc->el_th_ctx.n != &th_ctx->quic_conns_clo) {
			struct quic_conn *next = LIST_NEXT(&qc->el_th_ctx,
			                                   struct quic_conn *,
			                                   el_th_ctx);
			LIST_APPEND(&next->back_refs, &bref->users);
		}
		bref->ref = qc->el_th_ctx.n;
		__ha_barrier_store();
	}

	/* Remove quic_conn from global ha_thread_ctx list. */
	LIST_DEL_INIT(&qc->el_th_ctx);

	if (closing)
		LIST_APPEND(&th_ctx->quic_conns_clo, &qc->el_th_ctx);
}


/* Copy at <pos> position a stateless reset token depending on the
 * <salt> salt input. This is the cluster secret which will be derived
 * as HKDF input secret to generate this token.
 * Return 1 if succeeded, 0 if not.
 */
int quic_stateless_reset_token_cpy(unsigned char *pos, size_t len,
                                   const unsigned char *salt, size_t saltlen)
{
	/* Input secret */
	const unsigned char *key = (const unsigned char *)global.cluster_secret;
	size_t keylen = strlen(global.cluster_secret);
	/* Info */
	const unsigned char label[] = "stateless token";
	size_t labellen = sizeof label - 1;
	int ret;

	ret = quic_hkdf_extract_and_expand(EVP_sha256(), pos, len,
	                                    key, keylen, salt, saltlen, label, labellen);
	return ret;
}

/* Initialize the stateless reset token attached to <conn_id> connection ID.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_stateless_reset_token_init(struct quic_connection_id *conn_id)
{
	int ret;

	if (global.cluster_secret) {
		/* Output secret */
		unsigned char *token = conn_id->stateless_reset_token;
		size_t tokenlen = sizeof conn_id->stateless_reset_token;
		/* Salt */
		const unsigned char *cid = conn_id->cid.data;
		size_t cidlen = conn_id->cid.len;

		ret = quic_stateless_reset_token_cpy(token, tokenlen, cid, cidlen);
	}
	else {
		/* TODO: RAND_bytes() should be replaced */
		ret = RAND_bytes(conn_id->stateless_reset_token,
		                 sizeof conn_id->stateless_reset_token) == 1;
	}

	return ret;
}

/* Generate a CID directly derived from <orig> CID and <addr> address.
 *
 * Returns the derived CID.
 */
struct quic_cid quic_derive_cid(const struct quic_cid *orig,
                                const struct sockaddr_storage *addr)
{
	struct quic_cid cid;
	const struct sockaddr_in *in;
	const struct sockaddr_in6 *in6;
	char *pos = trash.area;
	size_t idx = 0;
	uint64_t hash;
	int i;

	/* Prepare buffer for hash using original CID first. */
	memcpy(pos, orig->data, orig->len);
	idx += orig->len;

	/* Concatenate client address. */
	switch (addr->ss_family) {
	case AF_INET:
		in = (struct sockaddr_in *)addr;

		memcpy(&pos[idx], &in->sin_addr, sizeof(in->sin_addr));
		idx += sizeof(in->sin_addr);
		memcpy(&pos[idx], &in->sin_port, sizeof(in->sin_port));
		idx += sizeof(in->sin_port);
		break;

	case AF_INET6:
		in6 = (struct sockaddr_in6 *)addr;

		memcpy(&pos[idx], &in6->sin6_addr, sizeof(in6->sin6_addr));
		idx += sizeof(in6->sin6_addr);
		memcpy(&pos[idx], &in6->sin6_port, sizeof(in6->sin6_port));
		idx += sizeof(in6->sin6_port);
		break;

	default:
		/* TODO to implement */
		ABORT_NOW();
	}

	/* Avoid similar values between multiple haproxy process. */
	memcpy(&pos[idx], boot_seed, sizeof(boot_seed));
	idx += sizeof(boot_seed);

	/* Hash the final buffer content. */
	hash = XXH64(pos, idx, 0);

	for (i = 0; i < sizeof(hash); ++i)
		cid.data[i] = hash >> ((sizeof(hash) * 7) - (8 * i));
	cid.len = sizeof(hash);

	return cid;
}

/* Retrieve the thread ID associated to QUIC connection ID <cid> of length
 * <cid_len>. CID may be not found on the CID tree because it is an ODCID. In
 * this case, it will derived using client address <cli_addr> as hash
 * parameter. However, this is done only if <pos> points to an INITIAL or 0RTT
 * packet of length <len>.
 *
 * Returns the thread ID or a negative error code.
 */
int quic_get_cid_tid(const unsigned char *cid, size_t cid_len,
                     const struct sockaddr_storage *cli_addr,
                     unsigned char *pos, size_t len)
{
	struct quic_cid_tree *tree;
	struct quic_connection_id *conn_id;
	struct ebmb_node *node;

	tree = &quic_cid_trees[_quic_cid_tree_idx(cid)];
	HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
	node = ebmb_lookup(&tree->root, cid, cid_len);
	HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);

	if (!node) {
		struct quic_cid orig, derive_cid;
		struct quic_rx_packet pkt;

		if (!qc_parse_hd_form(&pkt, &pos, pos + len))
			goto not_found;

		if (pkt.type != QUIC_PACKET_TYPE_INITIAL &&
		    pkt.type != QUIC_PACKET_TYPE_0RTT) {
			goto not_found;
		}

		memcpy(orig.data, cid, cid_len);
		orig.len = cid_len;
		derive_cid = quic_derive_cid(&orig, cli_addr);

		tree = &quic_cid_trees[quic_cid_tree_idx(&derive_cid)];
		HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
		node = ebmb_lookup(&tree->root, cid, cid_len);
		HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);
	}

	if (!node)
		goto not_found;

	conn_id = ebmb_entry(node, struct quic_connection_id, node);
	return HA_ATOMIC_LOAD(&conn_id->tid);

 not_found:
	return -1;
}

/* Allocate a new CID and attach it to <root> ebtree.
 *
 * If <orig> and <addr> params are non null, the new CID value is directly
 * derived from them. Else a random value is generated. The CID is then marked
 * with the current thread ID.
 *
 * Returns the new CID if succeeded, NULL if not.
 */
struct quic_connection_id *new_quic_cid(struct eb_root *root,
                                        struct quic_conn *qc,
                                        const struct quic_cid *orig,
                                        const struct sockaddr_storage *addr)
{
	struct quic_connection_id *conn_id;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	/* Caller must set either none or both values. */
	BUG_ON(!!orig != !!addr);

	conn_id = pool_alloc(pool_head_quic_connection_id);
	if (!conn_id) {
		TRACE_ERROR("cid allocation failed", QUIC_EV_CONN_TXPKT, qc);
		goto err;
	}

	conn_id->cid.len = QUIC_HAP_CID_LEN;

	if (!orig) {
		/* TODO: RAND_bytes() should be replaced */
		if (RAND_bytes(conn_id->cid.data, conn_id->cid.len) != 1) {
			TRACE_ERROR("RAND_bytes() failed", QUIC_EV_CONN_TXPKT, qc);
			goto err;
		}
	}
	else {
		/* Derive the new CID value from original CID. */
		conn_id->cid = quic_derive_cid(orig, addr);
	}

	if (quic_stateless_reset_token_init(conn_id) != 1) {
		TRACE_ERROR("quic_stateless_reset_token_init() failed", QUIC_EV_CONN_TXPKT, qc);
		goto err;
	}

	conn_id->qc = qc;
	HA_ATOMIC_STORE(&conn_id->tid, tid);

	conn_id->seq_num.key = qc ? qc->next_cid_seq_num++ : 0;
	conn_id->retire_prior_to = 0;
	/* insert the allocated CID in the quic_conn tree */
	if (root)
		eb64_insert(root, &conn_id->seq_num);

	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return conn_id;

 err:
	pool_free(pool_head_quic_connection_id, conn_id);
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
	return NULL;
}

/* QUIC connection packet handler task (post handshake) */
struct task *quic_conn_app_io_cb(struct task *t, void *context, unsigned int state)
{
	struct quic_conn *qc = context;
	struct quic_enc_level *qel;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);

	qel = qc->ael;
	TRACE_STATE("connection handshake state", QUIC_EV_CONN_IO_CB, qc, &qc->state);

	if (qc_test_fd(qc))
		qc_rcv_buf(qc);

	/* Prepare post-handshake frames
	 * - after connection is instantiated (accept is done)
	 * - handshake state is completed (may not be the case here in 0-RTT)
	 */
	if ((qc->flags & QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS) && qc->conn &&
	    qc->state >= QUIC_HS_ST_COMPLETE) {
		quic_build_post_handshake_frames(qc);
	}

	/* Retranmissions */
	if (qc->flags & QUIC_FL_CONN_RETRANS_NEEDED) {
		TRACE_STATE("retransmission needed", QUIC_EV_CONN_IO_CB, qc);
		qc->flags &= ~QUIC_FL_CONN_RETRANS_NEEDED;
		if (!qc_dgrams_retransmit(qc))
			goto out;
	}

	if (!qc_treat_rx_pkts(qc)) {
		TRACE_DEVEL("qc_treat_rx_pkts() failed", QUIC_EV_CONN_IO_CB, qc);
		goto out;
	}

	if (qc->flags & QUIC_FL_CONN_TO_KILL) {
		TRACE_DEVEL("connection to be killed", QUIC_EV_CONN_IO_CB, qc);
		goto out;
	}

	if ((qc->flags & QUIC_FL_CONN_DRAINING) &&
	    !(qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE)) {
		TRACE_STATE("draining connection (must not send packets)", QUIC_EV_CONN_IO_CB, qc);
		goto out;
	}

	/* XXX TODO: how to limit the list frames to send */
	if (!qc_send_app_pkts(qc, &qel->pktns->tx.frms)) {
		TRACE_DEVEL("qc_send_app_pkts() failed", QUIC_EV_CONN_IO_CB, qc);
		goto out;
	}

 out:
	if ((qc->flags & QUIC_FL_CONN_CLOSING) && qc->mux_state != QC_MUX_READY) {
		quic_conn_release(qc);
		qc = NULL;
	}

	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc);
	return t;
}

static void quic_release_cc_conn(struct quic_cc_conn *cc_qc)
{
	struct quic_conn *qc = (struct quic_conn *)cc_qc;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, cc_qc);

	if (qc_test_fd(qc))
		_HA_ATOMIC_DEC(&jobs);

	/* Close quic-conn socket fd. */
	qc_release_fd(qc, 0);

	task_destroy(cc_qc->idle_timer_task);
	cc_qc->idle_timer_task = NULL;
	tasklet_free(qc->wait_event.tasklet);
	free_quic_conn_cids(qc);
	pool_free(pool_head_quic_cids, cc_qc->cids);
	cc_qc->cids = NULL;
	pool_free(pool_head_quic_cc_buf, cc_qc->cc_buf_area);
	cc_qc->cc_buf_area = NULL;
	/* free the SSL sock context */
	qc_free_ssl_sock_ctx(&cc_qc->xprt_ctx);
	pool_free(pool_head_quic_cc_conn, cc_qc);

	TRACE_ENTER(QUIC_EV_CONN_IO_CB);
}

/* QUIC connection packet handler task used when in "closing connection" state. */
static struct task *quic_cc_conn_io_cb(struct task *t, void *context, unsigned int state)
{
	struct quic_cc_conn *cc_qc = context;
	struct quic_conn *qc = (struct quic_conn *)cc_qc;
	struct buffer buf;
	uint16_t dglen;
	struct quic_tx_packet *first_pkt;
	size_t headlen = sizeof dglen + sizeof first_pkt;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);

	if (qc_test_fd(qc))
		qc_rcv_buf(qc);

	/* Do not send too much data if the peer address was not validated. */
	if ((qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE) &&
	    !(qc->flags & QUIC_FL_CONN_PEER_VALIDATED_ADDR) &&
	    quic_may_send_bytes(qc) < cc_qc->cc_dgram_len)
		goto leave;

	buf = b_make(cc_qc->cc_buf_area + headlen,
	             QUIC_MAX_CC_BUFSIZE - headlen, 0, cc_qc->cc_dgram_len);
	if (qc_snd_buf(qc, &buf, buf.data, 0) < 0) {
		TRACE_ERROR("sendto fatal error", QUIC_EV_CONN_IO_CB, qc);
		quic_release_cc_conn(cc_qc);
		cc_qc = NULL;
		qc = NULL;
		t = NULL;
		goto leave;
	}

	qc->flags &= ~QUIC_FL_CONN_IMMEDIATE_CLOSE;

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc);

	return t;
}

/* The task handling the idle timeout of a connection in "connection close" state */
static struct task *qc_cc_idle_timer_task(struct task *t, void *ctx, unsigned int state)
{
	struct quic_cc_conn *cc_qc = ctx;

	quic_release_cc_conn(cc_qc);

	return NULL;
}

/* Allocate a new connection in "connection close" state and return it
 * if succeeded, NULL if not. This function is also responsible of
 * copying enough and the least possible information from <qc> original
 * connection to the newly allocated connection so that to keep it
 * functionnal until its idle timer expires.
 */
static struct quic_cc_conn *qc_new_cc_conn(struct quic_conn *qc)
{
	struct quic_cc_conn *cc_qc;

	cc_qc = pool_alloc(pool_head_quic_cc_conn);
	if (!cc_qc)
		return NULL;

	quic_conn_mv_cids_to_cc_conn(cc_qc, qc);

	cc_qc->fd = qc->fd;
	fdtab[cc_qc->fd].owner = cc_qc;
	cc_qc->flags = qc->flags;
	if (quic_peer_validated_addr(qc))
	    cc_qc->flags |= QUIC_FL_CONN_PEER_VALIDATED_ADDR;
	cc_qc->err = qc->err;

	cc_qc->nb_pkt_for_cc = qc->nb_pkt_for_cc;
	cc_qc->nb_pkt_since_cc = qc->nb_pkt_since_cc;

	cc_qc->local_addr = qc->local_addr;
	cc_qc->peer_addr = qc->peer_addr;

	cc_qc->wait_event.tasklet = qc->wait_event.tasklet;
	cc_qc->wait_event.tasklet->process = quic_cc_conn_io_cb;
	cc_qc->wait_event.tasklet->context = cc_qc;
	cc_qc->wait_event.events = 0;
	cc_qc->subs = NULL;

	cc_qc->bytes.prep = qc->bytes.prep;
	cc_qc->bytes.tx = qc->bytes.tx;
	cc_qc->bytes.rx = qc->bytes.rx;

	cc_qc->odcid = qc->odcid;
	cc_qc->dcid = qc->dcid;
	cc_qc->scid = qc->scid;

	cc_qc->li = qc->li;
	cc_qc->cids = qc->cids;

	cc_qc->idle_timer_task = qc->idle_timer_task;
	cc_qc->idle_timer_task->process = qc_cc_idle_timer_task;
	cc_qc->idle_timer_task->context = cc_qc;
	cc_qc->idle_expire = qc->idle_expire;

	cc_qc->xprt_ctx = qc->xprt_ctx;
	qc->xprt_ctx = NULL;
	cc_qc->conn = qc->conn;
	qc->conn = NULL;

	cc_qc->cc_buf_area = qc->tx.cc_buf_area;
	cc_qc->cc_dgram_len = qc->tx.cc_dgram_len;
	TRACE_PRINTF(TRACE_LEVEL_PROTO, QUIC_EV_CONN_IO_CB, qc, 0, 0, 0,
	             "switch qc@%p to cc_qc@%p", qc, cc_qc);

	return cc_qc;
}

/* QUIC connection packet handler task. */
struct task *quic_conn_io_cb(struct task *t, void *context, unsigned int state)
{
	int ret;
	struct quic_conn *qc = context;
	struct buffer *buf = NULL;
	int st;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);

	st = qc->state;
	TRACE_PROTO("connection state", QUIC_EV_CONN_IO_CB, qc, &st);

	/* Retranmissions */
	if (qc->flags & QUIC_FL_CONN_RETRANS_NEEDED) {
		TRACE_DEVEL("retransmission needed", QUIC_EV_CONN_PHPKTS, qc);
		qc->flags &= ~QUIC_FL_CONN_RETRANS_NEEDED;
		if (!qc_dgrams_retransmit(qc))
			goto out;
	}

	if (qc_test_fd(qc))
		qc_rcv_buf(qc);

	if (!qc_treat_rx_pkts(qc))
		goto out;

	if (qc->flags & QUIC_FL_CONN_TO_KILL) {
		TRACE_DEVEL("connection to be killed", QUIC_EV_CONN_PHPKTS, qc);
		goto out;
	}

	if ((qc->flags & QUIC_FL_CONN_DRAINING) &&
	    !(qc->flags & QUIC_FL_CONN_IMMEDIATE_CLOSE))
		goto out;

	st = qc->state;
	if (st >= QUIC_HS_ST_COMPLETE) {
		if (!(qc->flags & QUIC_FL_CONN_HPKTNS_DCD)) {
			/* Discard the Handshake packet number space. */
			TRACE_PROTO("discarding Handshake pktns", QUIC_EV_CONN_PHPKTS, qc);
			quic_pktns_discard(qc->hel->pktns, qc);
			qc_set_timer(qc);
			qc_el_rx_pkts_del(qc->hel);
			qc_release_pktns_frms(qc, qc->hel->pktns);
		}
	}

	buf = qc_get_txb(qc);
	if (!buf)
		goto out;

	if (b_data(buf) && !qc_purge_txbuf(qc, buf))
		goto out;

	/* Currently buf cannot be non-empty at this stage. Even if a previous
	 * sendto() has failed it is emptied to simulate packet emission and
	 * rely on QUIC lost detection to try to emit it.
	 */
	BUG_ON_HOT(b_data(buf));
	b_reset(buf);

	ret = qc_prep_hpkts(qc, buf, NULL);
	if (ret == -1) {
		qc_txb_release(qc);
		goto out;
	}

	if (ret && !qc_send_ppkts(buf, qc->xprt_ctx)) {
		if (qc->flags & QUIC_FL_CONN_TO_KILL)
			qc_txb_release(qc);
		goto out;
	}

	qc_txb_release(qc);

 out:
	/* Release the Handshake encryption level and packet number space if
	 * the Handshake is confirmed and if there is no need to send
	 * anymore Handshake packets.
	 */
	if (quic_tls_pktns_is_dcd(qc, qc->hpktns) &&
	    !qc_need_sending(qc, qc->hel)) {
		/* Ensure Initial packet encryption level and packet number space have
		 * been released.
		 */
		qc_enc_level_free(qc, &qc->iel);
		quic_pktns_release(qc, &qc->ipktns);
		qc_enc_level_free(qc, &qc->hel);
		quic_pktns_release(qc, &qc->hpktns);
		/* Also release the negotiated Inital TLS context. */
		quic_nictx_free(qc);
	}

	if ((qc->flags & QUIC_FL_CONN_CLOSING) && qc->mux_state != QC_MUX_READY) {
		quic_conn_release(qc);
		qc = NULL;
	}

	TRACE_PROTO("ssl error", QUIC_EV_CONN_IO_CB, qc, &st);
	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc);
	return t;
}

/* Release the memory allocated for <cs> CRYPTO stream */
void quic_cstream_free(struct quic_cstream *cs)
{
	if (!cs) {
		/* This is the case for ORTT encryption level */
		return;
	}

	quic_free_ncbuf(&cs->rx.ncbuf);

	qc_stream_desc_release(cs->desc);
	pool_free(pool_head_quic_cstream, cs);
}

/* Allocate a new QUIC stream for <qc>.
 * Return it if succeeded, NULL if not.
 */
struct quic_cstream *quic_cstream_new(struct quic_conn *qc)
{
	struct quic_cstream *cs, *ret_cs = NULL;

	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);
	cs = pool_alloc(pool_head_quic_cstream);
	if (!cs) {
		TRACE_ERROR("crypto stream allocation failed", QUIC_EV_CONN_INIT, qc);
		goto leave;
	}

	cs->rx.offset = 0;
	cs->rx.ncbuf = NCBUF_NULL;
	cs->rx.offset = 0;

	cs->tx.offset = 0;
	cs->tx.sent_offset = 0;
	cs->tx.buf = BUF_NULL;
	cs->desc = qc_stream_desc_new((uint64_t)-1, -1, cs, qc);
	if (!cs->desc) {
		TRACE_ERROR("crypto stream allocation failed", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	ret_cs = cs;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return ret_cs;

 err:
	pool_free(pool_head_quic_cstream, cs);
	goto leave;
}

/* Callback called upon loss detection and PTO timer expirations. */
struct task *qc_process_timer(struct task *task, void *ctx, unsigned int state)
{
	struct quic_conn *qc = ctx;
	struct quic_pktns *pktns;

	TRACE_ENTER(QUIC_EV_CONN_PTIMER, qc);
	TRACE_PROTO("process timer", QUIC_EV_CONN_PTIMER, qc,
	            NULL, NULL, &qc->path->ifae_pkts);

	task->expire = TICK_ETERNITY;
	pktns = quic_loss_pktns(qc);

	if (qc->flags & (QUIC_FL_CONN_DRAINING|QUIC_FL_CONN_TO_KILL)) {
		TRACE_PROTO("cancelled action (draining state)", QUIC_EV_CONN_PTIMER, qc);
		task = NULL;
		goto out;
	}

	if (tick_isset(pktns->tx.loss_time)) {
		struct list lost_pkts = LIST_HEAD_INIT(lost_pkts);

		qc_packet_loss_lookup(pktns, qc, &lost_pkts);
		if (!LIST_ISEMPTY(&lost_pkts))
		    tasklet_wakeup(qc->wait_event.tasklet);
		if (qc_release_lost_pkts(qc, pktns, &lost_pkts, now_ms))
			qc_set_timer(qc);
		goto out;
	}

	if (qc->path->in_flight) {
		pktns = quic_pto_pktns(qc, qc->state >= QUIC_HS_ST_CONFIRMED, NULL);
		if (!pktns->tx.in_flight) {
			TRACE_PROTO("No in flight packets to probe with", QUIC_EV_CONN_TXPKT, qc);
			goto out;
		}

		if (pktns == qc->ipktns) {
			if (qc_may_probe_ipktns(qc)) {
				qc->flags |= QUIC_FL_CONN_RETRANS_NEEDED;
				pktns->flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
				TRACE_STATE("needs to probe Initial packet number space", QUIC_EV_CONN_TXPKT, qc);
			}
			else {
				TRACE_STATE("Cannot probe Initial packet number space", QUIC_EV_CONN_TXPKT, qc);
			}
			if (qc->hpktns && qc->hpktns->tx.in_flight) {
				qc->flags |= QUIC_FL_CONN_RETRANS_NEEDED;
				qc->hpktns->flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
				TRACE_STATE("needs to probe Handshake packet number space", QUIC_EV_CONN_TXPKT, qc);
			}
		}
		else if (pktns == qc->hpktns) {
			TRACE_STATE("needs to probe Handshake packet number space", QUIC_EV_CONN_TXPKT, qc);
			qc->flags |= QUIC_FL_CONN_RETRANS_NEEDED;
			pktns->flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
			if (qc->ipktns && qc->ipktns->tx.in_flight) {
				if (qc_may_probe_ipktns(qc)) {
					qc->ipktns->flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
					TRACE_STATE("needs to probe Initial packet number space", QUIC_EV_CONN_TXPKT, qc);
				}
				else {
					TRACE_STATE("Cannot probe Initial packet number space", QUIC_EV_CONN_TXPKT, qc);
				}
			}
		}
		else if (pktns == qc->apktns) {
			pktns->tx.pto_probe = QUIC_MAX_NB_PTO_DGRAMS;
			/* Wake up upper layer if waiting to send new data. */
			if (!qc_notify_send(qc)) {
				TRACE_STATE("needs to probe 01RTT packet number space", QUIC_EV_CONN_TXPKT, qc);
				qc->flags |= QUIC_FL_CONN_RETRANS_NEEDED;
				pktns->flags |= QUIC_FL_PKTNS_PROBE_NEEDED;
			}
		}
	}
	else if (!qc_is_listener(qc) && qc->state <= QUIC_HS_ST_COMPLETE) {
		if (quic_tls_has_tx_sec(qc->hel))
			qc->hel->pktns->tx.pto_probe = 1;
		if (quic_tls_has_tx_sec(qc->iel))
			qc->iel->pktns->tx.pto_probe = 1;
	}

	tasklet_wakeup(qc->wait_event.tasklet);
	qc->path->loss.pto_count++;

 out:
	TRACE_PROTO("process timer", QUIC_EV_CONN_PTIMER, qc, pktns);
	TRACE_LEAVE(QUIC_EV_CONN_PTIMER, qc);

	return task;
}

/* Allocate a new QUIC connection with <version> as QUIC version. <ipv4>
 * boolean is set to 1 for IPv4 connection, 0 for IPv6. <server> is set to 1
 * for QUIC servers (or haproxy listeners).
 * <dcid> is the destination connection ID, <scid> is the source connection ID.
 * This latter <scid> CID as the same value on the wire as the one for <conn_id>
 * which is the first CID of this connection but a different internal representation used to build
 * NEW_CONNECTION_ID frames. This is the responsability of the caller to insert
 * <conn_id> in the CIDs tree for this connection (qc->cids).
 * <token> is the token found to be used for this connection with <token_len> as
 * length. Endpoints addresses are specified via <local_addr> and <peer_addr>.
 * Returns the connection if succeeded, NULL if not.
 */
struct quic_conn *qc_new_conn(const struct quic_version *qv, int ipv4,
                              struct quic_cid *dcid, struct quic_cid *scid,
                              const struct quic_cid *token_odcid,
                              struct quic_connection_id *conn_id,
                              struct sockaddr_storage *local_addr,
                              struct sockaddr_storage *peer_addr,
                              int server, int token, void *owner)
{
	int i;
	struct quic_conn *qc;
	struct listener *l = NULL;
	struct quic_cc_algo *cc_algo = NULL;

	TRACE_ENTER(QUIC_EV_CONN_INIT);

	qc = pool_alloc(pool_head_quic_conn);
	if (!qc) {
		TRACE_ERROR("Could not allocate a new connection", QUIC_EV_CONN_INIT);
		goto err;
	}

	/* Initialize in priority qc members required for a safe dealloc. */
	qc->nictx = NULL;
	/* Prevents these CID to be dumped by TRACE() calls */
	qc->scid.len = qc->odcid.len = qc->dcid.len = 0;
	/* required to use MTLIST_IN_LIST */
	MT_LIST_INIT(&qc->accept_list);

	LIST_INIT(&qc->rx.pkt_list);

	qc->streams_by_id = EB_ROOT_UNIQUE;

	/* Required to call free_quic_conn_cids() from quic_conn_release() */
	qc->cids = NULL;
	qc_init_fd(qc);

	LIST_INIT(&qc->back_refs);
	LIST_INIT(&qc->el_th_ctx);

	qc->wait_event.tasklet = NULL;

	/* Required to destroy <qc> tasks from quic_conn_release() */
	qc->timer_task = NULL;
	qc->idle_timer_task = NULL;

	qc->xprt_ctx = NULL;
	qc->conn = NULL;
	qc->qcc = NULL;
	qc->app_ops = NULL;
	qc->path = NULL;

	/* Keyupdate: required to safely call quic_tls_ku_free() from
	 * quic_conn_release().
	 */
	quic_tls_ku_reset(&qc->ku.prv_rx);
	quic_tls_ku_reset(&qc->ku.nxt_rx);
	quic_tls_ku_reset(&qc->ku.nxt_tx);

	/* Encryption levels */
	qc->iel = qc->eel = qc->hel = qc->ael = NULL;
	LIST_INIT(&qc->qel_list);
	/* Packet number spaces */
	qc->ipktns = qc->hpktns = qc->apktns = NULL;
	LIST_INIT(&qc->pktns_list);

	/* Required to safely call quic_conn_prx_cntrs_update() from quic_conn_release(). */
	qc->prx_counters = NULL;

	/* Now proceeds to allocation of qc members. */
	qc->rx.buf.area = pool_alloc(pool_head_quic_conn_rxbuf);
	if (!qc->rx.buf.area) {
		TRACE_ERROR("Could not allocate a new RX buffer", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	qc->cids = pool_alloc(pool_head_quic_cids);
	if (!qc->cids) {
		TRACE_ERROR("Could not allocate a new CID tree", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	*qc->cids = EB_ROOT;
	/* QUIC Server (or listener). */
	if (server) {
		struct proxy *prx;

		l = owner;
		prx = l->bind_conf->frontend;
		cc_algo = l->bind_conf->quic_cc_algo;

		qc->prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe,
		                                      &quic_stats_module);
		qc->flags = QUIC_FL_CONN_LISTENER;
		qc->state = QUIC_HS_ST_SERVER_INITIAL;
		/* Copy the client original DCID. */
		qc->odcid = *dcid;
		/* Copy the packet SCID to reuse it as DCID for sending */
		qc->dcid = *scid;
		qc->tx.buf = BUF_NULL;
		qc->li = l;
	}
	/* QUIC Client (outgoing connection to servers) */
	else {
		qc->state = QUIC_HS_ST_CLIENT_INITIAL;
		if (dcid->len)
			memcpy(qc->dcid.data, dcid->data, dcid->len);
		qc->dcid.len = dcid->len;
		qc->li = NULL;
	}
	qc->mux_state = QC_MUX_NULL;
	qc->err = quic_err_transport(QC_ERR_NO_ERROR);

	conn_id->qc = qc;

	if ((global.tune.options & GTUNE_QUIC_SOCK_PER_CONN) &&
	    is_addr(local_addr)) {
		TRACE_USER("Allocate a socket for QUIC connection", QUIC_EV_CONN_INIT, qc);
		qc_alloc_fd(qc, local_addr, peer_addr);

		/* haproxy soft-stop is supported only for QUIC connections
		 * with their owned socket.
		 */
		if (qc_test_fd(qc))
			_HA_ATOMIC_INC(&jobs);
	}

	/* Select our SCID which is the first CID with 0 as sequence number. */
	qc->scid = conn_id->cid;

	if (!qc_enc_level_alloc(qc, &qc->ipktns, &qc->iel, ssl_encryption_initial)) {
		TRACE_ERROR("Could not initialize an encryption level", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	qc->original_version = qv;
	qc->negotiated_version = NULL;
	qc->tps_tls_ext = (qc->original_version->num & 0xff000000) == 0xff000000 ?
		TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS_DRAFT:
		TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS;
	/* TX part. */
	qc->bytes.tx = qc->bytes.prep = 0;
	memset(&qc->tx.params, 0, sizeof(qc->tx.params));
	qc->tx.buf = BUF_NULL;
	qc->tx.cc_buf = BUF_NULL;
	qc->tx.cc_buf_area = NULL;
	qc->tx.cc_dgram_len = 0;
	/* RX part. */
	qc->bytes.rx = 0;
	memset(&qc->rx.params, 0, sizeof(qc->rx.params));
	qc->rx.buf = b_make(qc->rx.buf.area, QUIC_CONN_RX_BUFSZ, 0, 0);
	for (i = 0; i < QCS_MAX_TYPES; i++)
		qc->rx.strms[i].nb_streams = 0;

	qc->nb_pkt_for_cc = 1;
	qc->nb_pkt_since_cc = 0;

	if (!quic_tls_ku_init(qc)) {
		TRACE_ERROR("Key update initialization failed", QUIC_EV_CONN_INIT, qc);
		goto err;
	}

	qc->max_ack_delay = 0;
	/* Only one path at this time (multipath not supported) */
	qc->path = &qc->paths[0];
	quic_path_init(qc->path, ipv4, cc_algo ? cc_algo : default_quic_cc_algo, qc);

	qc->stream_buf_count = 0;
	memcpy(&qc->local_addr, local_addr, sizeof(qc->local_addr));
	memcpy(&qc->peer_addr, peer_addr, sizeof qc->peer_addr);

	if (server && !qc_lstnr_params_init(qc, &l->bind_conf->quic_params,
	                                    conn_id->stateless_reset_token,
	                                    dcid->data, dcid->len,
	                                    qc->scid.data, qc->scid.len, token_odcid))
		goto err;

	/* Initialize the idle timeout of the connection at the "max_idle_timeout"
	 * value from local transport parameters.
	 */
	qc->max_idle_timeout = qc->rx.params.max_idle_timeout;
	qc->wait_event.tasklet = tasklet_new();
	if (!qc->wait_event.tasklet) {
		TRACE_ERROR("tasklet_new() failed", QUIC_EV_CONN_TXPKT);
		goto err;
	}
	qc->wait_event.tasklet->process = quic_conn_io_cb;
	qc->wait_event.tasklet->context = qc;
	qc->wait_event.events = 0;
	qc->subs = NULL;

	if (qc_alloc_ssl_sock_ctx(qc) ||
	    !quic_conn_init_timer(qc) ||
	    !quic_conn_init_idle_timer_task(qc))
		goto err;

	if (!qc_new_isecs(qc, &qc->iel->tls_ctx, qc->original_version, dcid->data, dcid->len, 1))
		goto err;

	/* Counters initialization */
	memset(&qc->cntrs, 0, sizeof qc->cntrs);

	LIST_APPEND(&th_ctx->quic_conns, &qc->el_th_ctx);
	qc->qc_epoch = HA_ATOMIC_LOAD(&qc_epoch);

	TRACE_LEAVE(QUIC_EV_CONN_INIT, qc);

	return qc;

 err:
	quic_conn_release(qc);
	TRACE_LEAVE(QUIC_EV_CONN_INIT);
	return NULL;
}

/* Update the proxy counters of <qc> QUIC connection from its counters */
static inline void quic_conn_prx_cntrs_update(struct quic_conn *qc)
{
	if (!qc->prx_counters)
		return;

	HA_ATOMIC_ADD(&qc->prx_counters->dropped_pkt, qc->cntrs.dropped_pkt);
	HA_ATOMIC_ADD(&qc->prx_counters->dropped_pkt_bufoverrun, qc->cntrs.dropped_pkt_bufoverrun);
	HA_ATOMIC_ADD(&qc->prx_counters->dropped_parsing, qc->cntrs.dropped_parsing);
	HA_ATOMIC_ADD(&qc->prx_counters->socket_full, qc->cntrs.socket_full);
	HA_ATOMIC_ADD(&qc->prx_counters->sendto_err, qc->cntrs.sendto_err);
	HA_ATOMIC_ADD(&qc->prx_counters->sendto_err_unknown, qc->cntrs.sendto_err_unknown);
	HA_ATOMIC_ADD(&qc->prx_counters->sent_pkt, qc->cntrs.sent_pkt);
	/* It is possible that ->path was not initialized. For instance if a
	 * QUIC connection allocation has failed.
	 */
	if (qc->path)
		HA_ATOMIC_ADD(&qc->prx_counters->lost_pkt, qc->path->loss.nb_lost_pkt);
	HA_ATOMIC_ADD(&qc->prx_counters->conn_migration_done, qc->cntrs.conn_migration_done);
	/* Stream related counters */
	HA_ATOMIC_ADD(&qc->prx_counters->data_blocked, qc->cntrs.data_blocked);
	HA_ATOMIC_ADD(&qc->prx_counters->stream_data_blocked, qc->cntrs.stream_data_blocked);
	HA_ATOMIC_ADD(&qc->prx_counters->streams_blocked_bidi, qc->cntrs.streams_blocked_bidi);
	HA_ATOMIC_ADD(&qc->prx_counters->streams_blocked_uni, qc->cntrs.streams_blocked_uni);
}

/* Release the quic_conn <qc>. The connection is removed from the CIDs tree.
 * The connection tasklet is killed.
 *
 * This function must only be called by the thread responsible of the quic_conn
 * tasklet.
 */
void quic_conn_release(struct quic_conn *qc)
{
	struct eb64_node *node;
	struct quic_rx_packet *pkt, *pktback;
	struct quic_cc_conn *cc_qc;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	if (!qc)
		goto leave;

	/* We must not free the quic-conn if the MUX is still allocated. */
	BUG_ON(qc->mux_state == QC_MUX_READY);

	cc_qc = NULL;
	if ((qc->flags & QUIC_FL_CONN_CLOSING) && !(qc->flags & QUIC_FL_CONN_EXP_TIMER) &&
	    qc->tx.cc_buf_area)
		cc_qc = qc_new_cc_conn(qc);

	if (!cc_qc) {
		if (qc_test_fd(qc))
			_HA_ATOMIC_DEC(&jobs);

		/* Close quic-conn socket fd. */
		qc_release_fd(qc, 0);
		task_destroy(qc->idle_timer_task);
		qc->idle_timer_task = NULL;
		tasklet_free(qc->wait_event.tasklet);
		/* remove the connection from receiver cids trees */
		free_quic_conn_cids(qc);
		pool_free(pool_head_quic_cids, qc->cids);
		qc->cids = NULL;
		pool_free(pool_head_quic_cc_buf, qc->tx.cc_buf_area);
		qc->tx.cc_buf_area = NULL;
		/* free the SSL sock context */
		qc_free_ssl_sock_ctx(&qc->xprt_ctx);
	}

	/* in the unlikely (but possible) case the connection was just added to
	 * the accept_list we must delete it from there.
	 */
	MT_LIST_DELETE(&qc->accept_list);

	/* free remaining stream descriptors */
	node = eb64_first(&qc->streams_by_id);
	while (node) {
		struct qc_stream_desc *stream;

		stream = eb64_entry(node, struct qc_stream_desc, by_id);
		node = eb64_next(node);

		/* all streams attached to the quic-conn are released, so
		 * qc_stream_desc_free will liberate the stream instance.
		 */
		BUG_ON(!stream->release);
		qc_stream_desc_free(stream, 1);
	}

	/* Purge Rx packet list. */
	list_for_each_entry_safe(pkt, pktback, &qc->rx.pkt_list, qc_rx_pkt_list) {
		LIST_DELETE(&pkt->qc_rx_pkt_list);
		pool_free(pool_head_quic_rx_packet, pkt);
	}

	task_destroy(qc->timer_task);
	qc->timer_task = NULL;

	quic_tls_ku_free(qc);
	if (qc->ael) {
		struct quic_tls_ctx *actx = &qc->ael->tls_ctx;

		/* Secrets used by keyupdate */
		pool_free(pool_head_quic_tls_secret, actx->rx.secret);
		pool_free(pool_head_quic_tls_secret, actx->tx.secret);
	}

	qc_enc_level_free(qc, &qc->iel);
	qc_enc_level_free(qc, &qc->eel);
	qc_enc_level_free(qc, &qc->hel);
	qc_enc_level_free(qc, &qc->ael);

	quic_tls_ctx_free(&qc->nictx);

	quic_pktns_release(qc, &qc->ipktns);
	quic_pktns_release(qc, &qc->hpktns);
	quic_pktns_release(qc, &qc->apktns);

	qc_detach_th_ctx_list(qc, 0);

	quic_conn_prx_cntrs_update(qc);
	pool_free(pool_head_quic_conn_rxbuf, qc->rx.buf.area);
	qc->rx.buf.area = NULL;
	pool_free(pool_head_quic_conn, qc);
	qc = NULL;

	TRACE_PROTO("QUIC conn. freed", QUIC_EV_CONN_FREED, qc);
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Initialize the timer task of <qc> QUIC connection.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_conn_init_timer(struct quic_conn *qc)
{
	int ret = 0;
	/* Attach this task to the same thread ID used for the connection */
	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	qc->timer_task = task_new_here();
	if (!qc->timer_task) {
		TRACE_ERROR("timer task allocation failed", QUIC_EV_CONN_NEW, qc);
		goto leave;
	}

	qc->timer = TICK_ETERNITY;
	qc->timer_task->process = qc_process_timer;
	qc->timer_task->context = qc;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
}

/* Rearm the idle timer or the ack timer (if not already armde) for <qc> QUIC
 * connection. */
void qc_idle_timer_do_rearm(struct quic_conn *qc, int arm_ack)
{
	unsigned int expire;

	if (stopping && qc->flags & (QUIC_FL_CONN_CLOSING|QUIC_FL_CONN_DRAINING)) {
		TRACE_PROTO("executing idle timer immediately on stopping", QUIC_EV_CONN_IDLE_TIMER, qc);
		qc->ack_expire = TICK_ETERNITY;
		task_wakeup(qc->idle_timer_task, TASK_WOKEN_MSG);
	}
	else {
		expire = QUIC_MAX(3 * quic_pto(qc), qc->max_idle_timeout);
		qc->idle_expire = tick_add(now_ms, MS_TO_TICKS(expire));
		if (arm_ack) {
			/* Arm the ack timer only if not already armed. */
			if (!tick_isset(qc->ack_expire)) {
				qc->ack_expire = tick_add(now_ms, MS_TO_TICKS(QUIC_ACK_DELAY));
				qc->idle_timer_task->expire = qc->ack_expire;
				task_queue(qc->idle_timer_task);
				TRACE_PROTO("ack timer armed", QUIC_EV_CONN_IDLE_TIMER, qc);
			}
		}
		else {
			qc->idle_timer_task->expire = tick_first(qc->ack_expire, qc->idle_expire);
			task_queue(qc->idle_timer_task);
			TRACE_PROTO("idle timer armed", QUIC_EV_CONN_IDLE_TIMER, qc);
		}
	}
}

/* Rearm the idle timer or ack timer for <qc> QUIC connection depending on <read>
 * and <arm_ack> booleans. The former is set to 1 when receiving a packet ,
 * and 0 when sending packet. <arm_ack> is set to 1 if this is the ack timer
 * which must be rearmed.
 */
void qc_idle_timer_rearm(struct quic_conn *qc, int read, int arm_ack)
{
	TRACE_ENTER(QUIC_EV_CONN_IDLE_TIMER, qc);

	if (read) {
		qc->flags |= QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ;
	}
	else {
		qc->flags &= ~QUIC_FL_CONN_IDLE_TIMER_RESTARTED_AFTER_READ;
	}
	qc_idle_timer_do_rearm(qc, arm_ack);

	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
}

/* The task handling the idle timeout */
struct task *qc_idle_timer_task(struct task *t, void *ctx, unsigned int state)
{
	struct quic_conn *qc = ctx;
	struct quic_counters *prx_counters = qc->prx_counters;
	unsigned int qc_flags = qc->flags;

	TRACE_ENTER(QUIC_EV_CONN_IDLE_TIMER, qc);

	if ((state & TASK_WOKEN_ANY) == TASK_WOKEN_TIMER && !tick_is_expired(t->expire, now_ms))
		goto requeue;

	if (tick_is_expired(qc->ack_expire, now_ms)) {
		TRACE_PROTO("ack timer expired", QUIC_EV_CONN_IDLE_TIMER, qc);
		qc->ack_expire = TICK_ETERNITY;
		/* Note that ->idle_expire is always set. */
		t->expire = qc->idle_expire;
		/* Do not wakeup the I/O handler in DRAINING state or if the
		 * connection must be killed as soon as possible.
		 */
		if (!(qc->flags & (QUIC_FL_CONN_DRAINING|QUIC_FL_CONN_TO_KILL))) {
			qc->flags |= QUIC_FL_CONN_ACK_TIMER_FIRED;
			tasklet_wakeup(qc->wait_event.tasklet);
		}

		goto requeue;
	}

	TRACE_PROTO("idle timer task running", QUIC_EV_CONN_IDLE_TIMER, qc);
	/* Notify the MUX before settings QUIC_FL_CONN_EXP_TIMER or the MUX
	 * might free the quic-conn too early via quic_close().
	 */
	qc_notify_err(qc);

	/* If the MUX is still alive, keep the quic-conn. The MUX is
	 * responsible to call quic_close to release it.
	 */
	qc->flags |= QUIC_FL_CONN_EXP_TIMER;
	if (qc->mux_state != QC_MUX_READY) {
		quic_conn_release(qc);
		qc = NULL;
	}

	/* TODO if the quic-conn cannot be freed because of the MUX, we may at
	 * least clean some parts of it such as the tasklet.
	 */

	if (!(qc_flags & QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED)) {
		qc_flags |= QUIC_FL_CONN_HALF_OPEN_CNT_DECREMENTED;
		TRACE_DEVEL("dec half open counter", QUIC_EV_CONN_IDLE_TIMER, qc);
		HA_ATOMIC_DEC(&prx_counters->half_open_conn);
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
	return NULL;

 requeue:
	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
	return t;
}

/* Initialize the idle timeout task for <qc>.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_conn_init_idle_timer_task(struct quic_conn *qc)
{
	int ret = 0;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);

	qc->idle_timer_task = task_new_here();
	if (!qc->idle_timer_task) {
		TRACE_ERROR("Idle timer task allocation failed", QUIC_EV_CONN_NEW, qc);
		goto leave;
	}

	qc->idle_timer_task->process = qc_idle_timer_task;
	qc->idle_timer_task->context = qc;
	qc->ack_expire = TICK_ETERNITY;
	qc_idle_timer_rearm(qc, 1, 0);
	task_queue(qc->idle_timer_task);

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_NEW, qc);
	return ret;
}

/* Return the QUIC version (quic_version struct) with <version> as version number
 * if supported or NULL if not.
 */
const struct quic_version *qc_supported_version(uint32_t version)
{
	int i;

	if (unlikely(!version))
		return &quic_version_VN_reserved;

	for (i = 0; i < quic_versions_nb; i++)
		if (quic_versions[i].num == version)
			return &quic_versions[i];

	return NULL;
}

static void __quic_conn_init(void)
{
	ha_quic_meth = BIO_meth_new(0x666, "ha QUIC methods");
}
INITCALL0(STG_REGISTER, __quic_conn_init);

static void __quic_conn_deinit(void)
{
	BIO_meth_free(ha_quic_meth);
}
REGISTER_POST_DEINIT(__quic_conn_deinit);

/* Check if connection ID <dcid> of length <dcid_len> belongs to <qc> local
 * CIDs. This can be used to determine if a datagram is addressed to the right
 * connection instance.
 *
 * Returns a boolean value.
 */
int qc_check_dcid(struct quic_conn *qc, unsigned char *dcid, size_t dcid_len)
{
	const uchar idx = _quic_cid_tree_idx(dcid);
	struct quic_connection_id *conn_id;
	struct ebmb_node *node = NULL;
	struct quic_cid_tree *tree = &quic_cid_trees[idx];

	/* Test against our default CID or client ODCID. */
	if ((qc->scid.len == dcid_len &&
	     memcmp(qc->scid.data, dcid, dcid_len) == 0) ||
	    (qc->odcid.len == dcid_len &&
	     memcmp(qc->odcid.data, dcid, dcid_len) == 0)) {
		return 1;
	}

	/* Test against our other CIDs. This can happen if the client has
	 * decided to switch to a new one.
	 *
	 * TODO to avoid locking, loop through qc.cids as an alternative.
	 *
	 * TODO set it to our default CID to avoid this operation next time.
	 */
	HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
	node = ebmb_lookup(&tree->root, dcid, dcid_len);
	HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);

	if (node) {
		conn_id = ebmb_entry(node, struct quic_connection_id, node);
		if (qc == conn_id->qc)
			return 1;
	}

	return 0;
}

/* Retrieve the DCID from a QUIC datagram or packet at <pos> position,
 * <end> being at one byte past the end of this datagram.
 * Returns 1 if succeeded, 0 if not.
 */
int quic_get_dgram_dcid(unsigned char *pos, const unsigned char *end,
                        unsigned char **dcid, size_t *dcid_len)
{
	int ret = 0, long_header;
	size_t minlen, skip;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);

	if (!(*pos & QUIC_PACKET_FIXED_BIT)) {
		TRACE_PROTO("fixed bit not set", QUIC_EV_CONN_RXPKT);
		goto err;
	}

	long_header = *pos & QUIC_PACKET_LONG_HEADER_BIT;
	minlen = long_header ? QUIC_LONG_PACKET_MINLEN :
		QUIC_SHORT_PACKET_MINLEN + QUIC_HAP_CID_LEN + QUIC_TLS_TAG_LEN;
	skip = long_header ? QUIC_LONG_PACKET_DCID_OFF : QUIC_SHORT_PACKET_DCID_OFF;
	if (end - pos < minlen)
		goto err;

	pos += skip;
	*dcid_len = long_header ? *pos++ : QUIC_HAP_CID_LEN;
	if (*dcid_len > QUIC_CID_MAXLEN || end - pos <= *dcid_len)
		goto err;

	*dcid = pos;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT);
	return ret;

 err:
	TRACE_PROTO("wrong datagram", QUIC_EV_CONN_RXPKT);
	goto leave;
}

/* Notify upper layer of a fatal error which forces to close the connection. */
void qc_notify_err(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	if (qc->mux_state == QC_MUX_READY) {
		TRACE_STATE("error notified to mux", QUIC_EV_CONN_CLOSE, qc);

		/* Mark socket as closed. */
		qc->conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;

		/* TODO quic-conn layer must stay active until MUX is released.
		 * Thus, we have to wake up directly to ensure upper stream
		 * layer will be notified of the error. If a proper separation
		 * is made between MUX and quic-conn layer, wake up could be
		 * conducted only with qc.subs.
		 */
		tasklet_wakeup(qc->qcc->wait_event.tasklet);
	}

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Move a <qc> QUIC connection and its resources from the current thread to the
 * new one <new_tid> optionally in association with <new_li> (since it may need
 * to change when migrating to a thread from a different group, otherwise leave
 * it NULL). After this call, the connection cannot be dereferenced anymore on
 * the current thread.
 *
 * Returns 0 on success else non-zero.
 */
int qc_set_tid_affinity(struct quic_conn *qc, uint new_tid, struct listener *new_li)
{
	struct task *t1 = NULL, *t2 = NULL;
	struct tasklet *t3 = NULL;

	struct quic_connection_id *conn_id;
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_SET_AFFINITY, qc);

	/* Pre-allocate all required resources. This ensures we do not left a
	 * connection with only some of its field rebinded.
	 */
	if (((t1 = task_new_on(new_tid)) == NULL) ||
	    (qc->timer_task && (t2 = task_new_on(new_tid)) == NULL) ||
	    (t3 = tasklet_new()) == NULL) {
		goto err;
	}

	/* Reinit idle timer task. */
	task_kill(qc->idle_timer_task);
	t1->expire = qc->idle_timer_task->expire;
	qc->idle_timer_task = t1;
	qc->idle_timer_task->process = qc_idle_timer_task;
	qc->idle_timer_task->context = qc;

	/* Reinit timer task if allocated. */
	if (qc->timer_task) {
		task_kill(qc->timer_task);
		qc->timer_task = t2;
		qc->timer_task->process = qc_process_timer;
		qc->timer_task->context = qc;
	}

	/* Reinit IO tasklet. */
	if (qc->wait_event.tasklet->state & TASK_IN_LIST)
		qc->flags |= QUIC_FL_CONN_IO_TO_REQUEUE;
	tasklet_kill(qc->wait_event.tasklet);
	/* In most cases quic_conn_app_io_cb is used but for 0-RTT quic_conn_io_cb can be still activated. */
	t3->process = qc->wait_event.tasklet->process;
	qc->wait_event.tasklet = t3;
	qc->wait_event.tasklet->tid = new_tid;
	qc->wait_event.tasklet->context = qc;
	qc->wait_event.events = 0;

	/* Rebind the connection FD. */
	if (qc_test_fd(qc)) {
		/* Reading is reactivated by the new thread. */
		fd_migrate_on(qc->fd, new_tid);
	}

	/* Remove conn from per-thread list instance. It will be hidden from
	 * "show quic" until rebinding is completed.
	 */
	qc_detach_th_ctx_list(qc, 0);

	node = eb64_first(qc->cids);
	BUG_ON(!node || eb64_next(node)); /* One and only one CID must be present before affinity rebind. */
	conn_id = eb64_entry(node, struct quic_connection_id, seq_num);

	/* At this point no connection was accounted for yet on this
	 * listener so it's OK to just swap the pointer.
	 */
	if (new_li && new_li != qc->li)
		qc->li = new_li;

	/* Rebinding is considered done when CID points to the new thread. No
	 * access should be done to quic-conn instance after it.
	 */
	qc->flags |= QUIC_FL_CONN_AFFINITY_CHANGED;
	HA_ATOMIC_STORE(&conn_id->tid, new_tid);
	qc = NULL;

	TRACE_LEAVE(QUIC_EV_CONN_SET_AFFINITY, NULL);
	return 0;

 err:
	task_destroy(t1);
	task_destroy(t2);
	tasklet_free(t3);

	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_SET_AFFINITY, qc);
	return 1;
}

/* Must be called after qc_set_tid_affinity() on the new thread. */
void qc_finalize_affinity_rebind(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_SET_AFFINITY, qc);

	/* This function must not be called twice after an affinity rebind. */
	BUG_ON(!(qc->flags & QUIC_FL_CONN_AFFINITY_CHANGED));
	qc->flags &= ~QUIC_FL_CONN_AFFINITY_CHANGED;

	/* A connection must not pass to closing state until affinity rebind
	 * is completed. Else quic_handle_stopping() may miss it during process
	 * stopping cleanup.
	 */
	BUG_ON(qc->flags & (QUIC_FL_CONN_CLOSING|QUIC_FL_CONN_DRAINING));

	/* Reinsert connection in ha_thread_ctx global list. */
	LIST_APPEND(&th_ctx->quic_conns, &qc->el_th_ctx);
	qc->qc_epoch = HA_ATOMIC_LOAD(&qc_epoch);

	/* Reactivate FD polling if connection socket is active. */
	qc_want_recv(qc);

	/* Reactivate timer task if needed. */
	qc_set_timer(qc);

	/* Idle timer task is always active. */
	task_queue(qc->idle_timer_task);

	/* Reactivate IO tasklet if needed. */
	if (qc->flags & QUIC_FL_CONN_IO_TO_REQUEUE) {
		tasklet_wakeup(qc->wait_event.tasklet);
		qc->flags &= ~QUIC_FL_CONN_IO_TO_REQUEUE;
	}

	TRACE_LEAVE(QUIC_EV_CONN_SET_AFFINITY, qc);
}

static void init_quic()
{
	int thr;

	for (thr = 0; thr < MAX_THREADS; ++thr) {
		LIST_INIT(&ha_thread_ctx[thr].quic_conns);
		LIST_INIT(&ha_thread_ctx[thr].quic_conns_clo);
	}
}
INITCALL0(STG_INIT, init_quic);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
