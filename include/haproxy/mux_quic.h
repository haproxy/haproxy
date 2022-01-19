#ifndef _HAPROXY_MUX_QUIC_H
#define _HAPROXY_MUX_QUIC_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/api.h>
#include <haproxy/mux_quic-t.h>

void quic_mux_transport_params_update(struct qcc *qcc);
struct qcs *qcs_new(struct qcc *qcc, uint64_t id, enum qcs_type type);
void uni_qcs_free(struct qcs *qcs);

struct buffer *qc_get_buf(struct qcs *qcs, struct buffer *bptr);

int qcs_subscribe(struct qcs *qcs, int event_type, struct wait_event *es);
void qcs_notify_recv(struct qcs *qcs);
void qcs_notify_send(struct qcs *qcs);

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

/* Return 1 if the stream with <id> as ID attached to <qcc> connection
 * has been locally initiated, 0 if not.
 */
static inline int qc_local_stream_id(struct qcc *qcc, uint64_t id)
{
	return id & QCS_ID_SRV_INTIATOR_BIT;
}

static inline int qcs_get_next_id(struct qcc *qcc, enum qcs_type type)
{
	BUG_ON(qcc->strms[type].nb_streams + 1 > qcc->strms[type].max_streams);
	return (qcc->strms[type].nb_streams++ << QCS_ID_TYPE_SHIFT) | type;
}

struct eb64_node *qcc_get_qcs(struct qcc *qcc, uint64_t id);

/* Install the <app_ops> applicative layer of a QUIC connection on mux <qcc>.
 * Returns 0 on success else non-zero.
 */
static inline int qcc_install_app_ops(struct qcc *qcc,
                                      const struct qcc_app_ops *app_ops)
{
	qcc->app_ops = app_ops;
	if (qcc->app_ops->init && !qcc->app_ops->init(qcc))
		return 1;

	if (qcc->app_ops->finalize)
		qcc->app_ops->finalize(qcc->ctx);

	return 0;
}

#endif /* USE_QUIC */

#endif /* _HAPROXY_MUX_QUIC_H */
