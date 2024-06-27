#ifndef _HAPROXY_QUIC_CID_T_H
#define _HAPROXY_QUIC_CID_T_H

#include <import/ebtree-t.h>
#include <haproxy/quic_tp-t.h>
#include <haproxy/thread.h>

struct quic_cid_tree {
	struct eb_root root;
	__decl_thread(HA_RWLOCK_T lock);
};

/* QUIC connection ID maximum length for version 1. */
#define QUIC_CID_MAXLEN               20 /* bytes */

/* QUIC connection id data.
 *
 * This struct is used by ebmb_node structs as last member of flexible arrays.
 * So do not change the order of the member of quic_cid struct.
 * <data> member must be the first one.
 */
struct quic_cid {
	unsigned char data[QUIC_CID_MAXLEN];
	unsigned char len; /* size of QUIC CID */
};

/* QUIC connection id attached to a QUIC connection.
 *
 * This structure is used to match received packets DCIDs with the
 * corresponding QUIC connection.
 */
struct quic_connection_id {
	struct eb64_node seq_num;
	uint64_t retire_prior_to;
	unsigned char stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];

	struct ebmb_node node; /* node for receiver tree, cid.data as key */
	struct quic_cid cid;   /* CID data */

	struct quic_conn *qc;  /* QUIC connection using this CID */
	uint tid;              /* Attached Thread ID for the connection. */
};

#endif /* _HAPROXY_QUIC_CID_T_H */
