#ifndef _HAPROXY_MUX_QUIC_H
#define _HAPROXY_MUX_QUIC_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/api.h>
#include <haproxy/connection.h>
#include <haproxy/list.h>
#include <haproxy/mux_quic-t.h>
#include <haproxy/stream.h>

struct qcs *qcc_init_stream_local(struct qcc *qcc, int bidi);
struct buffer *qc_get_buf(struct qcs *qcs, struct buffer *bptr);

int qcs_subscribe(struct qcs *qcs, int event_type, struct wait_event *es);
void qcs_notify_recv(struct qcs *qcs);
void qcs_notify_send(struct qcs *qcs);

void qcc_emit_cc_app(struct qcc *qcc, int err, int immediate);
void qcc_reset_stream(struct qcs *qcs, int err);
int qcc_recv(struct qcc *qcc, uint64_t id, uint64_t len, uint64_t offset,
             char fin, char *data);
int qcc_recv_max_data(struct qcc *qcc, uint64_t max);
int qcc_recv_max_stream_data(struct qcc *qcc, uint64_t id, uint64_t max);
int qcc_recv_reset_stream(struct qcc *qcc, uint64_t id, uint64_t err, uint64_t final_size);
int qcc_recv_stop_sending(struct qcc *qcc, uint64_t id, uint64_t err);
void qcc_streams_sent_done(struct qcs *qcs, uint64_t data, uint64_t offset);

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

static inline enum qcs_type qcs_id_type(uint64_t id)
{
	return id & QCS_ID_TYPE_MASK;
}

/* Return true if stream has been opened locally. */
static inline int quic_stream_is_local(struct qcc *qcc, uint64_t id)
{
	return conn_is_back(qcc->conn) == !(id & QCS_ID_SRV_INTIATOR_BIT);
}

/* Return true if stream is opened by peer. */
static inline int quic_stream_is_remote(struct qcc *qcc, uint64_t id)
{
	return !quic_stream_is_local(qcc, id);
}

static inline int quic_stream_is_uni(uint64_t id)
{
	return id & QCS_ID_DIR_BIT;
}

static inline int quic_stream_is_bidi(uint64_t id)
{
	return !quic_stream_is_uni(id);
}

static inline char *qcs_st_to_str(enum qcs_state st)
{
	switch (st) {
	case QC_SS_IDLE: return "IDL";
	case QC_SS_OPEN: return "OPN";
	case QC_SS_HLOC: return "HCL";
	case QC_SS_HREM: return "HCR";
	case QC_SS_CLO:  return "CLO";
	default:         return "???";
	}
}

int qcc_install_app_ops(struct qcc *qcc, const struct qcc_app_ops *app_ops);

static inline struct stconn *qc_attach_sc(struct qcs *qcs, struct buffer *buf)
{
	struct qcc *qcc = qcs->qcc;
	struct session *sess = qcc->conn->owner;

	qcs->sd = sedesc_new();
	if (!qcs->sd)
		return NULL;

	qcs->sd->se   = qcs;
	qcs->sd->conn = qcc->conn;
	se_fl_set(qcs->sd, SE_FL_T_MUX | SE_FL_ORPHAN | SE_FL_NOT_FIRST);

	/* TODO duplicated from mux_h2 */
	sess->t_idle = tv_ms_elapsed(&sess->tv_accept, &now) - sess->t_handshake;

	if (!sc_new_from_endp(qcs->sd, sess, buf))
		return NULL;

	/* QC_SF_HREQ_RECV must be set once for a stream. Else, nb_hreq counter
	 * will be incorrect for the connection.
	 */
	BUG_ON_HOT(qcs->flags & QC_SF_HREQ_RECV);
	qcs->flags |= QC_SF_HREQ_RECV;
	++qcc->nb_sc;
	++qcc->nb_hreq;

	/* TODO duplicated from mux_h2 */
	sess->accept_date = date;
	sess->tv_accept   = now;
	sess->t_handshake = 0;
	sess->t_idle = 0;

	/* A stream must have been registered for HTTP wait before attaching
	 * it to sedesc. See <qcs_wait_http_req> for more info.
	 */
	BUG_ON_HOT(!LIST_INLIST(&qcs->el_opening));
	LIST_DEL_INIT(&qcs->el_opening);

	return qcs->sd->sc;
}

/* Register <qcs> stream for http-request timeout. If the stream is not yet
 * attached in the configured delay, qcc timeout task will be triggered. This
 * means the full header section was not received in time.
 *
 * This function should be called by the application protocol layer on request
 * streams initialization.
 */
static inline void qcs_wait_http_req(struct qcs *qcs)
{
	struct qcc *qcc = qcs->qcc;

	/* A stream cannot be registered several times. */
	BUG_ON_HOT(tick_isset(qcs->start));
	qcs->start = now_ms;

	/* qcc.opening_list size is limited by flow-control so no custom
	 * restriction is needed here.
	 */
	LIST_APPEND(&qcc->opening_list, &qcs->el_opening);
}

#endif /* USE_QUIC */

#endif /* _HAPROXY_MUX_QUIC_H */
