#ifndef _HAPROXY_QUIC_CID_H
#define _HAPROXY_QUIC_CID_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <import/ebmbtree.h>

#include <haproxy/buf-t.h>
#include <haproxy/chunk.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_cid-t.h>
#include <haproxy/quic_rx-t.h>
#include <haproxy/proto_quic.h>

extern struct quic_cid_tree *quic_cid_trees;

struct quic_connection_id *new_quic_cid(struct eb_root *root,
                                        struct quic_conn *qc,
                                        const struct quic_cid *orig,
                                        const struct sockaddr_storage *addr);

int quic_cid_insert(struct quic_connection_id *conn_id, int *new_tid);
int quic_cmp_cid_conn(const unsigned char *cid, size_t cid_len,
                      struct quic_conn *qc);
int quic_get_cid_tid(const unsigned char *cid, size_t cid_len,
                     const struct sockaddr_storage *cli_addr,
                     unsigned char *pos, size_t len);

struct quic_conn *retrieve_qc_conn_from_cid(struct quic_rx_packet *pkt,
                                            struct sockaddr_storage *saddr,
                                            int *new_tid);
int qc_build_new_connection_id_frm(struct quic_conn *qc,
                                   struct quic_connection_id *conn_id);

/* Copy <src> QUIC CID to <dst>.
 * This is the responsibility of the caller to check there is enough room in
 * <dst> to copy <src>.
 * Always succeeds.
 */
static inline void quic_cid_cpy(struct quic_cid *dst, const struct quic_cid *src)
{
	memcpy(dst->data, src->data, src->len);
	dst->len = src->len;
}

/* Dump the QUIC connection ID value if present (non null length). Used only for
 * debugging purposes.
 * Always succeeds.
 */
static inline void quic_cid_dump(struct buffer *buf,
                                 const struct quic_cid *cid)
{
	int i;

	chunk_appendf(buf, "(%d", cid->len);
	if (cid->len)
		chunk_appendf(buf, ",");
	for (i = 0; i < cid->len; i++)
		chunk_appendf(buf, "%02x", cid->data[i]);
	chunk_appendf(buf, ")");
}

/* Return tree index where <cid> is stored. */
static inline uchar _quic_cid_tree_idx(const unsigned char *cid)
{
	return cid[0];
}

/* Return tree index where <cid> is stored. */
static inline uchar quic_cid_tree_idx(const struct quic_cid *cid)
{
	return _quic_cid_tree_idx(cid->data);
}

/* Insert <conn_id> into global CID tree. Do not check if value is already
 * present in the tree. As such, it should not be used for the first DCID of a
 * connection instance.
 */
static inline void _quic_cid_insert(struct quic_connection_id *conn_id)
{
	const uchar idx = quic_cid_tree_idx(&conn_id->cid);
	struct quic_cid_tree *tree = &quic_cid_trees[idx];

	HA_RWLOCK_WRLOCK(QC_CID_LOCK, &tree->lock);
	ebmb_insert(&tree->root, &conn_id->node, conn_id->cid.len);
	HA_RWLOCK_WRUNLOCK(QC_CID_LOCK, &tree->lock);
}

/* Remove <conn_id> from global CID tree as a thread-safe operation. */
static inline void quic_cid_delete(struct quic_connection_id *conn_id)
{
	const uchar idx = quic_cid_tree_idx(&conn_id->cid);
	struct quic_cid_tree __maybe_unused *tree = &quic_cid_trees[idx];

	HA_RWLOCK_WRLOCK(QC_CID_LOCK, &tree->lock);
	ebmb_delete(&conn_id->node);
	HA_RWLOCK_WRUNLOCK(QC_CID_LOCK, &tree->lock);
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

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_CID_H */
