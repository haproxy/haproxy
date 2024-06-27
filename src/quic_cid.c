#include <import/eb64tree.h>
#include <import/ebmbtree.h>

#include <haproxy/pool.h>
#include <haproxy/quic_cid.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_rx-t.h>
#include <haproxy/quic_trace.h>
#include <haproxy/trace.h>
#include <haproxy/xxhash.h>

/* Initialize the stateless reset token attached to <conn_id> connection ID.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_stateless_reset_token_init(struct quic_connection_id *conn_id)
{
	/* Output secret */
	unsigned char *token = conn_id->stateless_reset_token;
	size_t tokenlen = sizeof conn_id->stateless_reset_token;
	/* Salt */
	const unsigned char *cid = conn_id->cid.data;
	size_t cidlen = conn_id->cid.len;

	return quic_stateless_reset_token_cpy(token, tokenlen, cid, cidlen);
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
		if (quic_newcid_from_hash64)
			quic_newcid_from_hash64(conn_id->cid.data, conn_id->cid.len, qc->hash64,
						global.cluster_secret, sizeof(global.cluster_secret));
		else if (RAND_bytes(conn_id->cid.data, conn_id->cid.len) != 1) {
			/* TODO: RAND_bytes() should be replaced */
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
	int cid_tid = -1;

	tree = &quic_cid_trees[_quic_cid_tree_idx(cid)];
	HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
	node = ebmb_lookup(&tree->root, cid, cid_len);
	if (node) {
		conn_id = ebmb_entry(node, struct quic_connection_id, node);
		cid_tid = HA_ATOMIC_LOAD(&conn_id->tid);
	}
	HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);

	/* If CID not found, it may be an ODCID, thus not stored in global CID
	 * tree. Derive it to its associated DCID value and reperform a lookup.
	 */
	if (cid_tid < 0) {
		struct quic_cid orig, derive_cid;
		struct quic_rx_packet pkt;

		if (!qc_parse_hd_form(&pkt, &pos, pos + len))
			goto out;

		/* ODCID are only used in INITIAL or 0-RTT packets */
		if (pkt.type != QUIC_PACKET_TYPE_INITIAL &&
		    pkt.type != QUIC_PACKET_TYPE_0RTT) {
			goto out;
		}

		memcpy(orig.data, cid, cid_len);
		orig.len = cid_len;
		derive_cid = quic_derive_cid(&orig, cli_addr);

		tree = &quic_cid_trees[quic_cid_tree_idx(&derive_cid)];
		HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
		node = ebmb_lookup(&tree->root, cid, cid_len);
		if (node) {
			conn_id = ebmb_entry(node, struct quic_connection_id, node);
			cid_tid = HA_ATOMIC_LOAD(&conn_id->tid);
		}
		HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);
	}

 out:
	return cid_tid;
}

/* Retrieve a quic_conn instance from the <pkt> DCID field. If the packet is an
 * INITIAL or 0RTT type, we may have to use client address <saddr> if an ODCID
 * is used.
 *
 * Returns the instance or NULL if not found.
 */
struct quic_conn *retrieve_qc_conn_from_cid(struct quic_rx_packet *pkt,
                                            struct sockaddr_storage *saddr,
                                            int *new_tid)
{
	struct quic_conn *qc = NULL;
	struct ebmb_node *node;
	struct quic_connection_id *conn_id;
	struct quic_cid_tree *tree;
	uint conn_id_tid;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT);
	*new_tid = -1;

	/* First look into DCID tree. */
	tree = &quic_cid_trees[_quic_cid_tree_idx(pkt->dcid.data)];
	HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
	node = ebmb_lookup(&tree->root, pkt->dcid.data, pkt->dcid.len);

	/* If not found on an Initial/0-RTT packet, it could be because an
	 * ODCID is reused by the client. Calculate the derived CID value to
	 * retrieve it from the DCID tree.
	 */
	if (!node && (pkt->type == QUIC_PACKET_TYPE_INITIAL ||
	     pkt->type == QUIC_PACKET_TYPE_0RTT)) {
		const struct quic_cid derive_cid = quic_derive_cid(&pkt->dcid, saddr);

		HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);

		tree = &quic_cid_trees[quic_cid_tree_idx(&derive_cid)];
		HA_RWLOCK_RDLOCK(QC_CID_LOCK, &tree->lock);
		node = ebmb_lookup(&tree->root, derive_cid.data, derive_cid.len);
	}

	if (!node)
		goto end;

	conn_id = ebmb_entry(node, struct quic_connection_id, node);
	conn_id_tid = HA_ATOMIC_LOAD(&conn_id->tid);
	if (conn_id_tid != tid) {
		*new_tid = conn_id_tid;
		goto end;
	}
	qc = conn_id->qc;

 end:
	HA_RWLOCK_RDUNLOCK(QC_CID_LOCK, &tree->lock);
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
	return qc;
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
