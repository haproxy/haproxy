#include <inttypes.h>

#include <import/eb64tree.h>

#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_trace.h>
#include <haproxy/trace.h>

DECLARE_STATIC_POOL(pool_head_quic_arng, "quic_arng", sizeof(struct quic_arng_node));

/* Deallocate <l> list of ACK ranges. */
void quic_free_arngs(struct quic_conn *qc, struct quic_arngs *arngs)
{
	struct eb64_node *n;
	struct quic_arng_node *ar;

	TRACE_ENTER(QUIC_EV_CONN_CLOSE, qc);

	n = eb64_first(&arngs->root);
	while (n) {
		struct eb64_node *next;

		ar = eb64_entry(n, struct quic_arng_node, first);
		next = eb64_next(n);
		eb64_delete(n);
		pool_free(pool_head_quic_arng, ar);
		n = next;
	}

	TRACE_LEAVE(QUIC_EV_CONN_CLOSE, qc);
}

/* Return the gap value between <p> and <q> ACK ranges where <q> follows <p> in
 * descending order.
 */
static inline size_t sack_gap(struct quic_arng_node *p,
                              struct quic_arng_node *q)
{
	return p->first.key - q->last - 2;
}

/* Set the encoded size of <arngs> QUIC ack ranges. */
static void quic_arngs_set_enc_sz(struct quic_conn *qc, struct quic_arngs *arngs)
{
	struct eb64_node *node, *next;
	struct quic_arng_node *ar, *ar_next;

	TRACE_ENTER(QUIC_EV_CONN_TXPKT, qc);

	node = eb64_last(&arngs->root);
	if (!node)
		goto leave;

	ar = eb64_entry(node, struct quic_arng_node, first);
	arngs->enc_sz = quic_int_getsize(ar->last) +
		quic_int_getsize(ar->last - ar->first.key) + quic_int_getsize(arngs->sz - 1);

	while ((next = eb64_prev(node))) {
		ar_next = eb64_entry(next, struct quic_arng_node, first);
		arngs->enc_sz += quic_int_getsize(sack_gap(ar, ar_next)) +
			quic_int_getsize(ar_next->last - ar_next->first.key);
		node = next;
		ar = eb64_entry(node, struct quic_arng_node, first);
	}

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_TXPKT, qc);
}

/* Insert <ar> ack range into <argns> tree of ack ranges.
 * Returns the ack range node which has been inserted if succeeded, NULL if not.
 */
static inline
struct quic_arng_node *quic_insert_new_range(struct quic_conn *qc,
                                             struct quic_arngs *arngs,
                                             struct quic_arng *ar)
{
	struct quic_arng_node *new_ar;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);

	if (arngs->sz >= QUIC_MAX_ACK_RANGES) {
		struct eb64_node *first;

		first = eb64_first(&arngs->root);
		BUG_ON(first == NULL);
		eb64_delete(first);
		pool_free(pool_head_quic_arng, first);
		arngs->sz--;
	}

	new_ar = pool_alloc(pool_head_quic_arng);
	if (!new_ar) {
		TRACE_ERROR("ack range allocation failed", QUIC_EV_CONN_RXPKT, qc);
		goto leave;
	}

	new_ar->first.key = ar->first;
	new_ar->last = ar->last;
	eb64_insert(&arngs->root, &new_ar->first);
	arngs->sz++;

 leave:
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
	return new_ar;
}

/* Update <arngs> tree of ACK ranges with <ar> as new ACK range value.
 * Note that this function computes the number of bytes required to encode
 * this tree of ACK ranges in descending order.
 *
 *    Descending order
 *    ------------->
 *                range1                  range2
 *    ..........|--------|..............|--------|
 *              ^        ^              ^        ^
 *              |        |              |        |
 *            last1     first1        last2    first2
 *    ..........+--------+--------------+--------+......
 *                 diff1       gap12       diff2
 *
 * To encode the previous list of ranges we must encode integers as follows in
 * descending order:
 *          enc(last2),enc(diff2),enc(gap12),enc(diff1)
 *  with diff1 = last1 - first1
 *       diff2 = last2 - first2
 *       gap12 = first1 - last2 - 2 (>= 0)
 *

returns 0 on error

 */
int quic_update_ack_ranges_list(struct quic_conn *qc,
                                struct quic_arngs *arngs,
                                struct quic_arng *ar)
{
	int ret = 0;
	struct eb64_node *le;
	struct quic_arng_node *new_node;
	struct eb64_node *new;

	TRACE_ENTER(QUIC_EV_CONN_RXPKT, qc);

	new = NULL;
	if (eb_is_empty(&arngs->root)) {
		new_node = quic_insert_new_range(qc, arngs, ar);
		if (new_node)
			ret = 1;

		goto leave;
	}

	le = eb64_lookup_le(&arngs->root, ar->first);
	if (!le) {
		new_node = quic_insert_new_range(qc, arngs, ar);
		if (!new_node)
			goto leave;

		new = &new_node->first;
	}
	else {
		struct quic_arng_node *le_ar =
			eb64_entry(le, struct quic_arng_node, first);

		/* Already existing range */
		if (le_ar->last >= ar->last) {
			ret = 1;
		}
		else if (le_ar->last + 1 >= ar->first) {
			le_ar->last = ar->last;
			new = le;
			new_node = le_ar;
		}
		else {
			new_node = quic_insert_new_range(qc, arngs, ar);
			if (!new_node)
				goto leave;

			new = &new_node->first;
		}
	}

	/* Verify that the new inserted node does not overlap the nodes
	 * which follow it.
	 */
	if (new) {
		struct eb64_node *next;
		struct quic_arng_node *next_node;

		while ((next = eb64_next(new))) {
			next_node =
				eb64_entry(next, struct quic_arng_node, first);
			if (new_node->last + 1 < next_node->first.key)
				break;

			if (next_node->last > new_node->last)
				new_node->last = next_node->last;
			eb64_delete(next);
			pool_free(pool_head_quic_arng, next_node);
			/* Decrement the size of these ranges. */
			arngs->sz--;
		}
	}

	ret = 1;
 leave:
	quic_arngs_set_enc_sz(qc, arngs);
	TRACE_LEAVE(QUIC_EV_CONN_RXPKT, qc);
	return ret;
}

/* Remove already sent ranges of acknowledged packet numbers from
 * <pktns> packet number space tree below <largest_acked_pn> possibly
 * updating the range which contains <largest_acked_pn>.
 * Never fails.
 */
void qc_treat_ack_of_ack(struct quic_conn *qc, struct quic_arngs *arngs,
                         int64_t largest_acked_pn)
{
	struct eb64_node *ar, *next_ar;

	TRACE_ENTER(QUIC_EV_CONN_PRSAFRM, qc);

	ar = eb64_first(&arngs->root);
	while (ar) {
		struct quic_arng_node *ar_node;

		next_ar = eb64_next(ar);
		ar_node = eb64_entry(ar, struct quic_arng_node, first);

		if ((int64_t)ar_node->first.key > largest_acked_pn) {
			TRACE_DEVEL("first.key > largest", QUIC_EV_CONN_PRSAFRM, qc);
			break;
		}

		if (largest_acked_pn < ar_node->last) {
			eb64_delete(ar);
			ar_node->first.key = largest_acked_pn + 1;
			eb64_insert(&arngs->root, ar);
			break;
		}

		/* Do not empty the tree: the first ACK range contains the
		 * largest acknowledged packet number.
		 */
		if (arngs->sz == 1)
			break;

		eb64_delete(ar);
		pool_free(pool_head_quic_arng, ar_node);
		arngs->sz--;
		ar = next_ar;
	}

	TRACE_LEAVE(QUIC_EV_CONN_PRSAFRM, qc);
}

