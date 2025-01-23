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

#include <haproxy/connection.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/frontend.h>
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
#include <haproxy/quic_cid.h>
#include <haproxy/quic_cli-t.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_loss.h>
#include <haproxy/quic_rx.h>
#include <haproxy/quic_ssl.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_stats.h>
#include <haproxy/quic_stream.h>
#include <haproxy/quic_token.h>
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

/* Function pointers, can be used to compute a hash from first generated CID and to derive new CIDs */
uint64_t (*quic_hash64_from_cid)(const unsigned char *cid, int size, const unsigned char *secret, size_t secretlen) = NULL;
void (*quic_newcid_from_hash64)(unsigned char *cid, int size, uint64_t hash, const unsigned char *secret, size_t secretlen) = NULL;

/* The total number of supported versions */
const size_t quic_versions_nb = sizeof quic_versions / sizeof *quic_versions;
/* Listener only preferred version */
const struct quic_version *preferred_version;
/* RFC 8999 5.4. Version
 * A Version field with a
 * value of 0x00000000 is reserved for version negotiation
 */
const struct quic_version quic_version_VN_reserved = { .num = 0, };

DECLARE_STATIC_POOL(pool_head_quic_conn, "quic_conn", sizeof(struct quic_conn));
DECLARE_STATIC_POOL(pool_head_quic_conn_closed, "quic_conn_closed", sizeof(struct quic_conn_closed));
DECLARE_STATIC_POOL(pool_head_quic_cids, "quic_cids", sizeof(struct eb_root));
DECLARE_POOL(pool_head_quic_connection_id,
             "quic_connection_id", sizeof(struct quic_connection_id));

struct task *quic_conn_app_io_cb(struct task *t, void *context, unsigned int state);
static int quic_conn_init_timer(struct quic_conn *qc);
static int quic_conn_init_idle_timer_task(struct quic_conn *qc, struct proxy *px);

/* Returns 1 if the peer has validated <qc> QUIC connection address, 0 if not. */
int quic_peer_validated_addr(struct quic_conn *qc)
{
	if (!qc_is_listener(qc))
		return 1;

	if (qc->flags & QUIC_FL_CONN_PEER_VALIDATED_ADDR)
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
	qc->flags &= ~QUIC_FL_CONN_RETRANS_NEEDED;

	if (!(qc->flags & QUIC_FL_CONN_EXP_TIMER))
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

void quic_conn_closed_err_count_inc(struct quic_conn *qc, struct quic_frame *frm)
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
	const uint64_t app_error_code = H3_ERR_REQUEST_REJECTED;

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
	const unsigned char *key = global.cluster_secret;
	size_t keylen = sizeof global.cluster_secret;
	/* Info */
	const unsigned char label[] = "stateless token";
	size_t labellen = sizeof label - 1;
	int ret;

	ret = quic_hkdf_extract_and_expand(EVP_sha256(), pos, len,
	                                    key, keylen, salt, saltlen, label, labellen);
	return ret;
}

/* Build all the frames which must be sent just after the handshake have succeeded.
 * This is essentially NEW_CONNECTION_ID frames. A QUIC server must also send
 * a HANDSHAKE_DONE frame.
 * Return 1 if succeeded, 0 if not.
 */
int quic_build_post_handshake_frames(struct quic_conn *qc)
{
	int ret = 0, max = 0;
	struct quic_enc_level *qel;
	struct quic_frame *frm, *frmbak;
	struct list frm_list = LIST_HEAD_INIT(frm_list);
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);

	qel = qc->ael;
	/* Only servers must send a HANDSHAKE_DONE frame. */
	if (qc_is_listener(qc)) {
		size_t new_token_frm_len;

		frm = qc_frm_alloc(QUIC_FT_HANDSHAKE_DONE);
		if (!frm) {
			TRACE_ERROR("frame allocation error", QUIC_EV_CONN_IO_CB, qc);
			goto leave;
		}

		LIST_APPEND(&frm_list, &frm->list);

		frm = qc_frm_alloc(QUIC_FT_NEW_TOKEN);
		if (!frm) {
			TRACE_ERROR("frame allocation error", QUIC_EV_CONN_IO_CB, qc);
			goto err;
		}

		new_token_frm_len =
			quic_generate_token(frm->new_token.data,
			                    sizeof(frm->new_token.data), &qc->peer_addr);
		if (!new_token_frm_len) {
			TRACE_ERROR("token generation failed", QUIC_EV_CONN_IO_CB, qc);
			goto err;
		}

		BUG_ON(new_token_frm_len != sizeof(frm->new_token.data));
		frm->new_token.len = new_token_frm_len;
		LIST_APPEND(&frm_list, &frm->list);
	}

	/* Initialize <max> connection IDs minus one: there is
	 * already one connection ID used for the current connection. Also limit
	 * the number of connection IDs sent to the peer to 4 (3 from this function
	 * plus 1 for the current connection.
	 * Note that active_connection_id_limit >= 2: this has been already checked
	 * when receiving this parameter.
	 */
	max = QUIC_MIN(qc->tx.params.active_connection_id_limit - 1, (uint64_t)3);
	while (max--) {
		struct quic_connection_id *conn_id;

		frm = qc_frm_alloc(QUIC_FT_NEW_CONNECTION_ID);
		if (!frm) {
			TRACE_ERROR("frame allocation error", QUIC_EV_CONN_IO_CB, qc);
			goto err;
		}

		conn_id = new_quic_cid(qc->cids, qc, NULL, NULL);
		if (!conn_id) {
			qc_frm_free(qc, &frm);
			TRACE_ERROR("CID allocation error", QUIC_EV_CONN_IO_CB, qc);
			goto err;
		}

		/* TODO To prevent CID tree locking, all CIDs created here
		 * could be allocated at the same time as the first one.
		 */
		_quic_cid_insert(conn_id);

		quic_connection_id_to_frm_cpy(frm, conn_id);
		LIST_APPEND(&frm_list, &frm->list);
	}

	LIST_SPLICE(&qel->pktns->tx.frms, &frm_list);
	qc->flags &= ~QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS;

	ret = 1;
 leave:
	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc);
	return ret;

 err:
	/* free the frames */
	list_for_each_entry_safe(frm, frmbak, &frm_list, list)
		qc_frm_free(qc, &frm);

	/* The first CID sequence number value used to allocated CIDs by this function is 1,
	 * 0 being the sequence number of the CID for this connection.
	 */
	node = eb64_lookup_ge(qc->cids, 1);
	while (node) {
		struct quic_connection_id *conn_id;

		conn_id = eb64_entry(node, struct quic_connection_id, seq_num);
		if (conn_id->seq_num.key >= max)
			break;

		node = eb64_next(node);
		quic_cid_delete(conn_id);

		eb64_delete(&conn_id->seq_num);
		pool_free(pool_head_quic_connection_id, conn_id);
	}
	goto leave;
}

/* QUIC connection packet handler task (post handshake) */
struct task *quic_conn_app_io_cb(struct task *t, void *context, unsigned int state)
{
	struct list send_list = LIST_HEAD_INIT(send_list);
	struct quic_conn *qc = context;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);
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
	if (qel_need_sending(qc->ael, qc))
		qel_register_send(&send_list, qc->ael, &qc->ael->pktns->tx.frms);

	if (!qc_send(qc, 0, &send_list, 0)) {
		TRACE_DEVEL("qc_send() failed", QUIC_EV_CONN_IO_CB, qc);
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

static void quic_release_cc_conn(struct quic_conn_closed *cc_qc)
{
	struct quic_conn *qc = (struct quic_conn *)cc_qc;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, cc_qc);

	task_destroy(cc_qc->idle_timer_task);
	cc_qc->idle_timer_task = NULL;
	tasklet_free(qc->wait_event.tasklet);
	free_quic_conn_cids(qc);
	pool_free(pool_head_quic_cids, cc_qc->cids);
	cc_qc->cids = NULL;
	pool_free(pool_head_quic_cc_buf, cc_qc->cc_buf_area);
	cc_qc->cc_buf_area = NULL;
	/* free the SSL sock context */
	pool_free(pool_head_quic_conn_closed, cc_qc);

	TRACE_ENTER(QUIC_EV_CONN_IO_CB);
}

/* QUIC connection packet handler task used when in "closing connection" state. */
static struct task *quic_conn_closed_io_cb(struct task *t, void *context, unsigned int state)
{
	struct quic_conn_closed *cc_qc = context;
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
	if (qc_snd_buf(qc, &buf, buf.data, 0, 0) < 0) {
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
static struct task *quic_conn_closed_idle_timer_task(struct task *t, void *ctx, unsigned int state)
{
	struct quic_conn_closed *cc_qc = ctx;

	quic_release_cc_conn(cc_qc);

	return NULL;
}

/* Allocate a new connection in "connection close" state and return it
 * if succeeded, NULL if not. This function is also responsible of
 * copying enough and the least possible information from <qc> original
 * connection to the newly allocated connection so that to keep it
 * functional until its idle timer expires.
 */
static struct quic_conn_closed *qc_new_cc_conn(struct quic_conn *qc)
{
	struct quic_conn_closed *cc_qc;

	cc_qc = pool_alloc(pool_head_quic_conn_closed);
	if (!cc_qc)
		return NULL;

	quic_conn_mv_cids_to_cc_conn(cc_qc, qc);

	qc_init_fd((struct quic_conn *)cc_qc);

	cc_qc->flags = qc->flags;
	cc_qc->err = qc->err;

	cc_qc->nb_pkt_for_cc = qc->nb_pkt_for_cc;
	cc_qc->nb_pkt_since_cc = qc->nb_pkt_since_cc;

	cc_qc->local_addr = qc->local_addr;
	cc_qc->peer_addr = qc->peer_addr;

	cc_qc->wait_event.tasklet = qc->wait_event.tasklet;
	cc_qc->wait_event.tasklet->process = quic_conn_closed_io_cb;
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
	cc_qc->idle_timer_task->process = quic_conn_closed_idle_timer_task;
	cc_qc->idle_timer_task->context = cc_qc;
	cc_qc->idle_expire = qc->idle_expire;

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
	struct quic_conn *qc = context;
	struct list send_list = LIST_HEAD_INIT(send_list);
	struct quic_enc_level *qel;
	int st;
	struct tasklet *tl = (struct tasklet *)t;

	TRACE_ENTER(QUIC_EV_CONN_IO_CB, qc);

	st = qc->state;
	TRACE_PROTO("connection state", QUIC_EV_CONN_IO_CB, qc, &st);

	/* TASK_HEAVY is set when received CRYPTO data have to be handled. */
	if (HA_ATOMIC_LOAD(&tl->state) & TASK_HEAVY) {
		qc_ssl_provide_all_quic_data(qc, qc->xprt_ctx);
		HA_ATOMIC_AND(&tl->state, ~TASK_HEAVY);
	}

	if (qc->flags & QUIC_FL_CONN_TO_KILL) {
		TRACE_DEVEL("connection to be killed", QUIC_EV_CONN_PHPKTS, qc);
		goto out;
	}

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

	/* TASK_HEAVY is set when received CRYPTO data have to be handled. These data
	 * must be acknowledged asap and replied to with others CRYPTO data. In this
	 * case, it is more optimal to delay the ACK to send it with the CRYPTO data
	 * from the same datagram.
	 */
	if (HA_ATOMIC_LOAD(&tl->state) & TASK_HEAVY) {
		tasklet_wakeup(tl);
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

		/* Note: if no token for address validation was received
		 * for a 0RTT connection, some 0RTT packet could still be
		 * waiting for HP removal AFTER the successful handshake completion.
		 * Indeed a successful handshake completion implicitely valids
		 * the peer address. In this case, one wants to process
		 * these ORTT packets AFTER the succesful handshake completion.
		 *
		 * On the contrary, when a token for address validation was received,
		 * release 0RTT packets still waiting for HP removal. These
		 * packets are considered unneeded after handshake completion.
		 * They will be freed later from Rx buf via quic_rx_pkts_del().
		 */
		if (qc->eel && !LIST_ISEMPTY(&qc->eel->rx.pqpkts) &&
		    !(qc->flags & QUIC_FL_CONN_NO_TOKEN_RCVD)) {
			struct quic_rx_packet *pqpkt, *pkttmp;
			list_for_each_entry_safe(pqpkt, pkttmp, &qc->eel->rx.pqpkts, list) {
				LIST_DEL_INIT(&pqpkt->list);
				quic_rx_packet_refdec(pqpkt);
			}

			/* RFC 9001 4.9.3. Discarding 0-RTT Keys
			 * Additionally, a server MAY discard 0-RTT keys as soon as it receives
			 * a 1-RTT packet. However, due to packet reordering, a 0-RTT packet
			 * could arrive after a 1-RTT packet. Servers MAY temporarily retain 0-
			 * RTT keys to allow decrypting reordered packets without requiring
			 * their contents to be retransmitted with 1-RTT keys. After receiving a
			 * 1-RTT packet, servers MUST discard 0-RTT keys within a short time;
			 * the RECOMMENDED time period is three times the Probe Timeout (PTO,
			 * see [QUIC-RECOVERY]). A server MAY discard 0-RTT keys earlier if it
			 * determines that it has received all 0-RTT packets, which can be done
			 * by keeping track of missing packet numbers.
			 *
			 * TODO implement discarding of 0-RTT keys
			 */
		}

		/* Wake up connection layer if on wait-for-handshake. */
		if (qc->subs && qc->subs->events & SUB_RETRY_RECV) {
			TRACE_STATE("notify upper layer (recv)", QUIC_EV_CONN_IO_CB, qc);
			tasklet_wakeup(qc->subs->tasklet);
			qc->subs->events &= ~SUB_RETRY_RECV;
			if (!qc->subs->events)
				qc->subs = NULL;
		}
	}

	/* Insert each QEL into sending list if needed. */
	list_for_each_entry(qel, &qc->qel_list, list) {
		if (qel_need_sending(qel, qc))
			qel_register_send(&send_list, qel, &qel->pktns->tx.frms);
	}

	if (!qc_send(qc, 0, &send_list, 0)) {
		TRACE_DEVEL("qc_send() failed", QUIC_EV_CONN_IO_CB, qc);
		goto out;
	}

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
		/* Also release the negotiated Initial TLS context. */
		quic_nictx_free(qc);
	}

	if ((qc->flags & QUIC_FL_CONN_CLOSING) && qc->mux_state != QC_MUX_READY) {
		quic_conn_release(qc);
		qc = NULL;
	}

	TRACE_PROTO("ssl status", QUIC_EV_CONN_IO_CB, qc, &st);
	TRACE_LEAVE(QUIC_EV_CONN_IO_CB, qc);
	return t;
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
		goto out;
	}

	if (tick_isset(pktns->tx.loss_time)) {
		struct list lost_pkts = LIST_HEAD_INIT(lost_pkts);

		qc_packet_loss_lookup(pktns, qc, &lost_pkts, NULL);
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
 * which is the first CID of this connection but a different internal
 * representation used to build
 * NEW_CONNECTION_ID frames. This is the responsibility of the caller to insert
 * <conn_id> in the CIDs tree for this connection (qc->cids).
 * <token> is a boolean denoting if a token was received for this connection
 * from an Initial packet.
 * <token_odcid> is the original destination connection ID which was embedded
 * into the Retry token sent to the client before instantiated this connection.
 * Endpoints addresses are specified via <local_addr> and <peer_addr>.
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
	struct quic_conn *qc = NULL;
	struct listener *l = server ? owner : NULL;
	struct proxy *prx = l ? l->bind_conf->frontend : NULL;
	struct quic_cc_algo *cc_algo = NULL;
	unsigned int next_actconn = 0, next_sslconn = 0, next_handshake = 0;

	TRACE_ENTER(QUIC_EV_CONN_INIT);

	next_actconn = increment_actconn();
	if (!next_actconn) {
		_HA_ATOMIC_INC(&maxconn_reached);
		TRACE_STATE("maxconn reached", QUIC_EV_CONN_INIT);
		goto err;
	}

	next_sslconn = increment_sslconn();
	if (!next_sslconn) {
		TRACE_STATE("sslconn reached", QUIC_EV_CONN_INIT);
		goto err;
	}

	if (server) {
		next_handshake = quic_increment_curr_handshake(l);
		if (!next_handshake) {
			TRACE_STATE("max handshake reached", QUIC_EV_CONN_INIT);
			goto err;
		}
	}

	qc = pool_alloc(pool_head_quic_conn);
	if (!qc) {
		TRACE_ERROR("Could not allocate a new connection", QUIC_EV_CONN_INIT);
		goto err;
	}

	/* Now that quic_conn instance is allocated, quic_conn_release() will
	 * ensure global accounting is decremented.
	 */
	next_handshake = next_sslconn = next_actconn = 0;

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
	qc->tx.cc_buf_area = NULL;
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

	/* QUIC Server (or listener). */
	if (server) {
		cc_algo = l->bind_conf->quic_cc_algo;

		qc->prx_counters = EXTRA_COUNTERS_GET(prx->extra_counters_fe,
		                                      &quic_stats_module);
		qc->flags = QUIC_FL_CONN_LISTENER;
		/* Mark this connection as having not received any token when 0-RTT is enabled. */
		if (l->bind_conf->ssl_conf.early_data && !token)
			qc->flags |= QUIC_FL_CONN_NO_TOKEN_RCVD;
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

	/* If connection is instantiated due to an INITIAL packet with an
	 * already checked token, consider the peer address as validated.
	 */
	if (token) {
		TRACE_STATE("validate peer address due to initial token",
		            QUIC_EV_CONN_INIT, qc);
		qc->flags |= QUIC_FL_CONN_PEER_VALIDATED_ADDR;
	}
	else {
		HA_ATOMIC_INC(&qc->prx_counters->half_open_conn);
	}

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

	conn_id->qc = qc;

	if (HA_ATOMIC_LOAD(&l->rx.quic_mode) == QUIC_SOCK_MODE_CONN &&
	    (global.tune.options & GTUNE_QUIC_SOCK_PER_CONN) &&
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
	quic_cc_path_init(qc->path, ipv4, server ? l->bind_conf->max_cwnd : 0,
	                  cc_algo ? cc_algo : default_quic_cc_algo, qc);

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
	/* Enable TASK_F_WANTS_TIME task flag for congestion control algorithms with
	 * delivery rate estimation only.
	 */
	if (qc->path->cc.algo->get_drs)
		qc->wait_event.tasklet->state |= TASK_F_WANTS_TIME;
	qc->wait_event.events = 0;
	qc->subs = NULL;

	if (qc_alloc_ssl_sock_ctx(qc) ||
	    !quic_conn_init_timer(qc) ||
	    !quic_conn_init_idle_timer_task(qc, prx))
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

	/* Decrement global counters. Done only for errors happening before or
	 * on pool_head_quic_conn alloc. All other cases are covered by
	 * quic_conn_release().
	 */
	if (next_actconn)
		_HA_ATOMIC_DEC(&actconn);
	if (next_sslconn)
		_HA_ATOMIC_DEC(&global.sslconns);
	if (next_handshake)
		_HA_ATOMIC_DEC(&l->rx.quic_curr_handshake);

	TRACE_LEAVE(QUIC_EV_CONN_INIT);
	return NULL;
}

/* React to a connection migration initiated on <qc> by a client with the new
 * path addresses <peer_addr>/<local_addr>.
 *
 * Returns 0 on success else non-zero.
 */
int qc_handle_conn_migration(struct quic_conn *qc,
                             const struct sockaddr_storage *peer_addr,
                             const struct sockaddr_storage *local_addr)
{
	TRACE_ENTER(QUIC_EV_CONN_LPKT, qc);

	/* RFC 9000. Connection Migration
	 *
	 * If the peer sent the disable_active_migration transport parameter,
	 * an endpoint also MUST NOT send packets (including probing packets;
	 * see Section 9.1) from a different local address to the address the peer
	 * used during the handshake, unless the endpoint has acted on a
	 * preferred_address transport parameter from the peer.
	 */
	if (qc->li->bind_conf->quic_params.disable_active_migration) {
		TRACE_ERROR("Active migration was disabled, datagram dropped", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	/* RFC 9000 9. Connection Migration
	 *
	 * The design of QUIC relies on endpoints retaining a stable address for
	 * the duration of the handshake.  An endpoint MUST NOT initiate
	 * connection migration before the handshake is confirmed, as defined in
	 * Section 4.1.2 of [QUIC-TLS].
	 */
	if (qc->state < QUIC_HS_ST_COMPLETE) {
		TRACE_STATE("Connection migration during handshake rejected", QUIC_EV_CONN_LPKT, qc);
		goto err;
	}

	/* RFC 9000 9. Connection Migration
	 *
	 * TODO
	 * An endpoint MUST
	 * perform path validation (Section 8.2) if it detects any change to a
	 * peer's address, unless it has previously validated that address.
	 */

	/* Update quic-conn owned socket if in used.
	 * TODO try to reuse it instead of closing and opening a new one.
	 */
	if (qc_test_fd(qc)) {
		/* TODO try to reuse socket instead of closing it and opening a new one. */
		TRACE_STATE("Connection migration detected, allocate a new connection socket", QUIC_EV_CONN_LPKT, qc);
		qc_release_fd(qc, 1);
		/* TODO need to adjust <jobs> on socket allocation failure. */
		qc_alloc_fd(qc, local_addr, peer_addr);
	}

	qc->local_addr = *local_addr;
	qc->peer_addr = *peer_addr;
	qc->cntrs.conn_migration_done++;

	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return 0;

 err:
	TRACE_LEAVE(QUIC_EV_CONN_LPKT, qc);
	return 1;
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
	struct quic_conn_closed *cc_qc;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	if (!qc)
		goto leave;

	/* Must not delete a quic_conn if thread affinity rebind in progress. */
	BUG_ON(qc->flags & QUIC_FL_CONN_TID_REBIND);

	/* We must not free the quic-conn if the MUX is still allocated. */
	BUG_ON(qc->mux_state == QC_MUX_READY);

	cc_qc = NULL;
	if ((qc->flags & QUIC_FL_CONN_CLOSING) && !(qc->flags & QUIC_FL_CONN_EXP_TIMER) &&
	    qc->tx.cc_buf_area)
		cc_qc = qc_new_cc_conn(qc);

	if (!cc_qc) {
		task_destroy(qc->idle_timer_task);
		qc->idle_timer_task = NULL;
		tasklet_free(qc->wait_event.tasklet);
		/* remove the connection from receiver cids trees */
		free_quic_conn_cids(qc);
		pool_free(pool_head_quic_cids, qc->cids);
		qc->cids = NULL;
		pool_free(pool_head_quic_cc_buf, qc->tx.cc_buf_area);
		qc->tx.cc_buf_area = NULL;
	}

	if (qc_test_fd(qc))
		_HA_ATOMIC_DEC(&jobs);

	/* Close quic-conn socket fd. */
	qc_release_fd(qc, 0);

	/* in the unlikely (but possible) case the connection was just added to
	 * the accept_list we must delete it from there.
	 */
	if (MT_LIST_INLIST(&qc->accept_list)) {
		MT_LIST_DELETE(&qc->accept_list);
		BUG_ON(qc->li->rx.quic_curr_accept == 0);
		HA_ATOMIC_DEC(&qc->li->rx.quic_curr_accept);
	}

	/* free remaining stream descriptors */
	node = eb64_first(&qc->streams_by_id);
	while (node) {
		struct qc_stream_desc *stream;

		stream = eb64_entry(node, struct qc_stream_desc, by_id);
		node = eb64_next(node);

		/* all streams attached to the quic-conn are released, so
		 * qc_stream_desc_free will liberate the stream instance.
		 */
		BUG_ON(!(stream->flags & QC_SD_FL_RELEASE));
		qc_stream_desc_free(stream, 1);
	}

	/* free the SSL sock context */
	qc_free_ssl_sock_ctx(&qc->xprt_ctx);
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

	/* Connection released before peer address validated. */
	if (unlikely(!(qc->flags & QUIC_FL_CONN_PEER_VALIDATED_ADDR))) {
		BUG_ON(!qc->prx_counters->half_open_conn);
		HA_ATOMIC_DEC(&qc->prx_counters->half_open_conn);
	}

	/* Connection released before handshake completion. */
	if (unlikely(qc->state < QUIC_HS_ST_COMPLETE)) {
		if (qc_is_listener(qc)) {
			BUG_ON(qc->li->rx.quic_curr_handshake == 0);
			HA_ATOMIC_DEC(&qc->li->rx.quic_curr_handshake);
		}
	}

	pool_free(pool_head_quic_conn, qc);
	qc = NULL;

	/* Decrement global counters when quic_conn is deallocated.
	 * quic_conn_closed instances are not accounted as they run for a short
	 * time with limited resources.
	 */
	_HA_ATOMIC_DEC(&actconn);
	_HA_ATOMIC_DEC(&global.sslconns);

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

	/* It is possible the idle timer task has been already released. */
	if (!qc->idle_timer_task)
		return;

	if (qc->flags & (QUIC_FL_CONN_CLOSING|QUIC_FL_CONN_DRAINING)) {
		/* RFC 9000 10.2. Immediate Close
		 *
		 * The closing and draining connection states exist to ensure that
		 * connections close cleanly and that delayed or reordered packets are
		 * properly discarded. These states SHOULD persist for at least three
		 * times the current PTO interval as defined in [QUIC-RECOVERY].
		 */

		/* Delay is limited to 1s which should cover most of network
		 * conditions. The process should not be impacted by a
		 * connection with a high RTT.
		 */
		expire = MIN(3 * quic_pto(qc), 1000);
	}
	else {
		/* RFC 9000 10.1. Idle Timeout
		 *
		 * To avoid excessively small idle timeout periods, endpoints MUST
		 * increase the idle timeout period to be at least three times the
		 * current Probe Timeout (PTO). This allows for multiple PTOs to expire,
		 * and therefore multiple probes to be sent and lost, prior to idle
		 * timeout.
		 */
		expire = QUIC_MAX(3 * quic_pto(qc), qc->max_idle_timeout);
	}

	qc->idle_expire = tick_add(now_ms, MS_TO_TICKS(expire));
	/* Note that the ACK timer is not armed during the handshake. So,
	 * the handshake expiration date is taken into an account only
	 * when <arm_ack> is false.
	 */
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
		if (qc->state < QUIC_HS_ST_COMPLETE)
			qc->idle_timer_task->expire = tick_first(qc->hs_expire, qc->idle_expire);
		task_queue(qc->idle_timer_task);
		TRACE_PROTO("idle timer armed", QUIC_EV_CONN_IDLE_TIMER, qc);
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

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
}

/* The task handling the idle timeout */
struct task *qc_idle_timer_task(struct task *t, void *ctx, unsigned int state)
{
	struct quic_conn *qc = ctx;

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
	else {
		task_destroy(t);
		qc->idle_timer_task = NULL;
	}

	t = NULL;

	/* TODO if the quic-conn cannot be freed because of the MUX, we may at
	 * least clean some parts of it such as the tasklet.
	 */

 requeue:
	TRACE_LEAVE(QUIC_EV_CONN_IDLE_TIMER, qc);
	return t;
}

/* Initialize the idle timeout task for <qc>.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_conn_init_idle_timer_task(struct quic_conn *qc,
                                          struct proxy *px)
{
	int ret = 0;
	int timeout;

	TRACE_ENTER(QUIC_EV_CONN_NEW, qc);


	timeout = px->timeout.client_hs ? px->timeout.client_hs : px->timeout.client;
	qc->idle_timer_task = task_new_here();
	if (!qc->idle_timer_task) {
		TRACE_ERROR("Idle timer task allocation failed", QUIC_EV_CONN_NEW, qc);
		goto leave;
	}

	qc->idle_timer_task->process = qc_idle_timer_task;
	qc->idle_timer_task->context = qc;
	qc->ack_expire = TICK_ETERNITY;
	qc->hs_expire = tick_add_ifset(now_ms, MS_TO_TICKS(timeout));
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

/* Check if connection ID <dcid> of length <dcid_len> belongs to <qc> local
 * CIDs. This can be used to determine if a datagram is addressed to the right
 * connection instance.
 *
 * Returns a boolean value.
 */
int qc_check_dcid(struct quic_conn *qc, unsigned char *dcid, size_t dcid_len)
{
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
	return quic_cmp_cid_conn(dcid, dcid_len, qc);
}

/* Wake-up upper layer for sending if all conditions are met :
 * - room in congestion window or probe packet to sent
 * - socket FD ready to sent or listener socket used
 *
 * Returns 1 if upper layer has been woken up else 0.
 */
int qc_notify_send(struct quic_conn *qc)
{
	const struct quic_pktns *pktns = qc->apktns;

	TRACE_STATE("notify upper layer (send)", QUIC_EV_CONN_IO_CB, qc);

	/* Wake up MUX for new emission unless there is no congestion room or
	 * connection FD is not ready.
	 */
	if (qc->subs && qc->subs->events & SUB_RETRY_SEND) {
		/* RFC 9002 7.5. Probe Timeout
		 *
		 * Probe packets MUST NOT be blocked by the congestion controller.
		 */
		if ((quic_cc_path_prep_data(qc->path) || pktns->tx.pto_probe) &&
		    (!qc_test_fd(qc) || !fd_send_active(qc->fd))) {
			tasklet_wakeup(qc->subs->tasklet);
			qc->subs->events &= ~SUB_RETRY_SEND;
			if (!qc->subs->events)
				qc->subs = NULL;

			return 1;
		}
	}

	/* Wake up streams layer waiting for buffer. Useful after congestion
	 * window increase.
	 */
	if (qc->mux_state == QC_MUX_READY && (qc->qcc->flags & QC_CF_CONN_FULL))
		qcc_notify_buf(qc->qcc, 0);

	return 0;
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

/* Prepare <qc> QUIC connection rebinding to a new thread <new_tid>. Stop and
 * release associated tasks and tasklet and allocate new ones binded to the new
 * thread.
 *
 * Returns 0 on success else non-zero.
 */
int qc_bind_tid_prep(struct quic_conn *qc, uint new_tid)
{
	struct task *t1 = NULL, *t2 = NULL;
	struct tasklet *t3 = NULL;

	TRACE_ENTER(QUIC_EV_CONN_BIND_TID, qc);

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

	/* Remove conn from per-thread list instance. It will be hidden from
	 * "show quic" until qc_finalize_tid_rebind().
	 */
	qc_detach_th_ctx_list(qc, 0);

	qc->flags |= QUIC_FL_CONN_TID_REBIND;

	TRACE_LEAVE(QUIC_EV_CONN_BIND_TID, qc);
	return 0;

 err:
	task_destroy(t1);
	task_destroy(t2);
	tasklet_free(t3);

	TRACE_DEVEL("leaving on error", QUIC_EV_CONN_BIND_TID, qc);
	return 1;
}

/* Complete <qc> rebinding to an already selected new thread and associate it
 * to <new_li> if necessary as required when migrating to a new thread group.
 *
 * After this function, <qc> instance must only be accessed via its newly
 * associated thread. qc_finalize_tid_rebind() must be called to
 * reactivate quic_conn elements.
 */
void qc_bind_tid_commit(struct quic_conn *qc, struct listener *new_li)
{
	const uint new_tid = qc->wait_event.tasklet->tid;
	struct quic_connection_id *conn_id;
	struct eb64_node *node;

	TRACE_ENTER(QUIC_EV_CONN_BIND_TID, qc);

	/* Must only be called after qc_bind_tid_prep(). */
	BUG_ON(!(qc->flags & QUIC_FL_CONN_TID_REBIND));

	/* At this point no connection was accounted for yet on this
	 * listener so it's OK to just swap the pointer.
	 */
	if (new_li && new_li != qc->li)
		qc->li = new_li;

	/* Rebind the connection FD. */
	if (qc_test_fd(qc)) {
		/* Reading is reactivated by the new thread. */
		fd_migrate_on(qc->fd, new_tid);
	}

	node = eb64_first(qc->cids);
	/* One and only one CID must be present before affinity rebind.
	 *
	 * This could be triggered fairly easily if tasklet is scheduled just
	 * before thread migration for post-handshake state to generate new
	 * CIDs. In this case, QUIC_FL_CONN_IO_TO_REQUEUE should be used
	 * instead of tasklet_wakeup().
	 */
	BUG_ON(!node || eb64_next(node));
	conn_id = eb64_entry(node, struct quic_connection_id, seq_num);

	/* Rebinding is considered done when CID points to the new
	 * thread. quic-conn instance cannot be derefence after it.
	 */
	HA_ATOMIC_STORE(&conn_id->tid, new_tid);
	qc = NULL;

	TRACE_LEAVE(QUIC_EV_CONN_BIND_TID, NULL);
}

/* Interrupt <qc> thread migration and stick to the current tid.
 * qc_finalize_tid_rebind() must be called to reactivate quic_conn elements.
 */
void qc_bind_tid_reset(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_BIND_TID, qc);

	/* Must only be called after qc_bind_tid_prep(). */
	BUG_ON(!(qc->flags & QUIC_FL_CONN_TID_REBIND));

	/* Reset tasks affinity to the current thread. quic_conn will remain
	 * inactive until qc_finalize_tid_rebind().
	 */
	task_set_thread(qc->idle_timer_task, tid);
	if (qc->timer_task)
		task_set_thread(qc->timer_task, tid);
	tasklet_set_tid(qc->wait_event.tasklet, tid);

	TRACE_LEAVE(QUIC_EV_CONN_BIND_TID, qc);
}

/* Must be called after TID rebind commit or reset on the new thread. */
void qc_finalize_tid_rebind(struct quic_conn *qc)
{
	TRACE_ENTER(QUIC_EV_CONN_BIND_TID, qc);

	/* This function must not be called twice after an affinity rebind. */
	BUG_ON(!(qc->flags & QUIC_FL_CONN_TID_REBIND));
	qc->flags &= ~QUIC_FL_CONN_TID_REBIND;

	/* If quic_conn is closing it is unnecessary to migrate it as it will
	 * be soon released. Besides, special care must be taken for CLOSING
	 * connections (using quic_conn_closed and th_ctx.quic_conns_clo list for
	 * instance). This should never occur as CLOSING connections are
	 * skipped by quic_sock_accept_conn().
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

	TRACE_LEAVE(QUIC_EV_CONN_BIND_TID, qc);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
