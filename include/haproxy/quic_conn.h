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
#include <haproxy/quic_cc.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_loss.h>
#include <haproxy/mux_quic.h>

#include <openssl/rand.h>

extern struct pool_head *pool_head_quic_connection_id;

int ssl_quic_initial_ctx(struct bind_conf *bind_conf);

/* Return the long packet type matching with <qv> version and <type> */
static inline int quic_pkt_type(int type, uint32_t version)
{
	if (version != QUIC_PROTOCOL_VERSION_2)
		return type;

	switch (type) {
	case QUIC_PACKET_TYPE_INITIAL:
		return 1;
	case QUIC_PACKET_TYPE_0RTT:
		return 2;
	case QUIC_PACKET_TYPE_HANDSHAKE:
		return 3;
	case QUIC_PACKET_TYPE_RETRY:
		return 0;
	}

	return -1;
}

static inline int qc_is_listener(struct quic_conn *qc)
{
	return qc->flags & QUIC_FL_CONN_LISTENER;
}

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

/* Copy <saddr> socket address data into <buf> buffer.
 * This is the responsibility of the caller to check the output buffer is big
 * enough to contain these socket address data.
 * Return the number of bytes copied.
 */
static inline size_t quic_saddr_cpy(unsigned char *buf,
                                    const struct sockaddr_storage *saddr)
{
	void *port, *addr;
	unsigned char *p;
	size_t port_len, addr_len;

	p = buf;
	if (saddr->ss_family == AF_INET6) {
		port = &((struct sockaddr_in6 *)saddr)->sin6_port;
		addr = &((struct sockaddr_in6 *)saddr)->sin6_addr;
		port_len = sizeof ((struct sockaddr_in6 *)saddr)->sin6_port;
		addr_len = sizeof ((struct sockaddr_in6 *)saddr)->sin6_addr;
	}
	else {
		port = &((struct sockaddr_in *)saddr)->sin_port;
		addr = &((struct sockaddr_in *)saddr)->sin_addr;
		port_len = sizeof ((struct sockaddr_in *)saddr)->sin_port;
		addr_len = sizeof ((struct sockaddr_in *)saddr)->sin_addr;
	}
	memcpy(p, port, port_len);
	p += port_len;
	memcpy(p, addr, addr_len);
	p += addr_len;

	return p - buf;
}

/* Concatenate the port and address of <saddr> to <cid> QUIC connection ID. The
 * <addrlen> field of <cid> will be updated with the size of the concatenated
 * address.
 *
 * Returns the number of bytes concatenated to <cid>.
 */
static inline size_t quic_cid_saddr_cat(struct quic_cid *cid,
                                        struct sockaddr_storage *saddr)
{
	void *port, *addr;
	size_t port_len, addr_len;

	cid->addrlen = 0;

	if (saddr->ss_family == AF_INET6) {
		port = &((struct sockaddr_in6 *)saddr)->sin6_port;
		addr = &((struct sockaddr_in6 *)saddr)->sin6_addr;
		port_len = sizeof ((struct sockaddr_in6 *)saddr)->sin6_port;
		addr_len = sizeof ((struct sockaddr_in6 *)saddr)->sin6_addr;
	}
	else {
		port = &((struct sockaddr_in *)saddr)->sin_port;
		addr = &((struct sockaddr_in *)saddr)->sin_addr;
		port_len = sizeof ((struct sockaddr_in *)saddr)->sin_port;
		addr_len = sizeof ((struct sockaddr_in *)saddr)->sin_addr;
	}

	memcpy(cid->data + cid->len, port, port_len);
	cid->addrlen += port_len;
	memcpy(cid->data + cid->len + port_len, addr, addr_len);
	cid->addrlen += addr_len;

	return port_len + addr_len;
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

/* Free the CIDs attached to <conn> QUIC connection. This must be called under
 * the CID lock.
 */
static inline void free_quic_conn_cids(struct quic_conn *conn)
{
	struct eb64_node *node;

	node = eb64_first(&conn->cids);
	while (node) {
		struct quic_connection_id *cid;

		cid = eb64_entry(node, struct quic_connection_id, seq_num);

		/* remove the CID from the receiver tree */
		ebmb_delete(&cid->node);

		/* remove the CID from the quic_conn tree */
		node = eb64_next(node);
		eb64_delete(&cid->seq_num);
		pool_free(pool_head_quic_connection_id, cid);
	}
}

/* Copy <src> new connection ID information to <dst> NEW_CONNECTION_ID frame.
 * Always succeeds.
 */
static inline void quic_connection_id_to_frm_cpy(struct quic_frame *dst,
                                                 struct quic_connection_id *src)
{
	struct quic_new_connection_id *to = &dst->new_connection_id;

	to->seq_num = src->seq_num.key;
	to->retire_prior_to = src->retire_prior_to;
	to->cid.len = src->cid.len;
	to->cid.data = src->cid.data;
	to->stateless_reset_token = src->stateless_reset_token;
}

/* extract a TID from a CID for receiver <rx>, from 0 to global.nbthread-1 and
 * in any case no more than 4095. It takes into account the bind_conf's thread
 * group and the bind_conf's thread mask. The algorithm is the following: most
 * packets contain a valid thread ID for the bind_conf, which means that the
 * retrieved ID directly maps to a bound thread ID. If that's not the case,
 * then we have to remap it. The resulting thread ID will then differ but will
 * be correctly encoded and decoded.
 */
static inline uint quic_get_cid_tid(const unsigned char *cid, const struct receiver *rx)
{
	uint id, grp;
	uint base, count;

	id = read_n16(cid) & 4095;
	grp = rx->bind_tgroup;
	base  = ha_tgroup_info[grp - 1].base;
	count = ha_tgroup_info[grp - 1].count;

	if (base <= id && id < base + count &&
	    rx->bind_thread & ha_thread_info[id].ltid_bit)
		return id; // part of the group and bound: valid

	/* The thread number isn't valid, it doesn't map to a thread bound on
	 * this receiver. Let's reduce it to one of the thread(s) valid for
	 * that receiver.
	 */
	count = my_popcountl(rx->bind_thread);
	id = count - 1 - id % count;
	id = mask_find_rank_bit(id, rx->bind_thread);
	id += base;
	return id;
}

/* Modify <cid> to have a CID linked to the thread ID <target_tid> that
 * quic_get_cid_tid() will be able to extract return.
 */
static inline void quic_pin_cid_to_tid(unsigned char *cid, uint target_tid)
{
	uint16_t prev_id;

	prev_id = read_n16(cid);
	write_n16(cid, (prev_id & ~4095) | target_tid);
}

/* Return a 32-bits integer in <val> from QUIC packet with <buf> as address.
 * Makes <buf> point to the data after this 32-bits value if succeeded.
 * Note that these 32-bits integers are network bytes ordered.
 * Returns 0 if failed (not enough data in the buffer), 1 if succeeded.
 */
static inline int quic_read_uint32(uint32_t *val,
                                   const unsigned char **buf,
                                   const unsigned char *end)
{
	if (end - *buf < sizeof *val)
		return 0;

	*val = ntohl(*(uint32_t *)*buf);
	*buf += sizeof *val;

	return 1;
}

/* Write a 32-bits integer to a buffer with <buf> as address.
 * Make <buf> point to the data after this 32-buts value if succeeded.
 * Note that these 32-bits integers are networkg bytes ordered.
 * Returns 0 if failed (not enough room in the buffer), 1 if succeeded.
 */
static inline int quic_write_uint32(unsigned char **buf,
                                    const unsigned char *end, uint32_t val)
{
	if (end - *buf < sizeof val)
		return 0;

	*(uint32_t *)*buf = htonl(val);
	*buf += sizeof val;

	return 1;
}


/* Return the maximum number of bytes we must use to completely fill a
 * buffer with <sz> as size for a data field of bytes prefixed by its QUIC
 * variable-length (may be 0).
 * Also put in <*len_sz> the size of this QUIC variable-length.
 * So after returning from this function we have : <*len_sz> + <ret> <= <sz>
 * (<*len_sz> = { max(i), i + ret <= <sz> }) .
 */
static inline size_t max_available_room(size_t sz, size_t *len_sz)
{
	size_t sz_sz, ret;
	size_t diff;

	sz_sz = quic_int_getsize(sz);
	if (sz <= sz_sz)
		return 0;

	ret = sz - sz_sz;
	*len_sz = quic_int_getsize(ret);
	/* Difference between the two sizes. Note that <sz_sz> >= <*len_sz>. */
	diff = sz_sz - *len_sz;
	if (unlikely(diff > 0)) {
		/* Let's try to take into an account remaining bytes.
		 *
		 *                  <----------------> <sz_sz>
		 *  <--------------><-------->  +----> <max_int>
		 *       <ret>       <len_sz>   |
		 *  +---------------------------+-----------....
		 *  <--------------------------------> <sz>
		 */
		size_t max_int = quic_max_int(*len_sz);

		if (max_int + *len_sz <= sz)
			ret = max_int;
		else
			ret = sz - diff;
	}

	return ret;
}

/* This function computes the maximum data we can put into a buffer with <sz> as
 * size prefixed with a variable-length field "Length" whose value is the
 * remaining data length, already filled of <ilen> bytes which must be taken
 * into an account by "Length" field, and finally followed by the data we want
 * to put in this buffer prefixed again by a variable-length field.
 * <sz> is the size of the buffer to fill.
 * <ilen> the number of bytes already put after the "Length" field.
 * <dlen> the number of bytes we want to at most put in the buffer.
 * Also set <*dlen_sz> to the size of the data variable-length we want to put in
 * the buffer. This is typically this function which must be used to fill as
 * much as possible a QUIC packet made of only one CRYPTO or STREAM frames.
 * Returns this computed size if there is enough room in the buffer, 0 if not.
 */
static inline size_t max_stream_data_size(size_t sz, size_t ilen, size_t dlen)
{
	size_t ret, len_sz, dlen_sz;

	/*
	 * The length of variable-length QUIC integers are powers of two.
	 * Look for the first 3length" field value <len_sz> which match our need.
	 * As we must put <ilen> bytes in our buffer, the minimum value for
	 * <len_sz> is the number of bytes required to encode <ilen>.
	 */
	for (len_sz = quic_int_getsize(ilen);
	     len_sz <= QUIC_VARINT_MAX_SIZE;
	     len_sz <<= 1) {
		if (sz < len_sz + ilen)
			return 0;

		ret = max_available_room(sz - len_sz - ilen, &dlen_sz);
		if (!ret)
			return 0;

		/* Check that <*len_sz> matches <ret> value */
		if (len_sz + ilen + dlen_sz + ret <= quic_max_int(len_sz))
			return ret < dlen ? ret : dlen;
	}

	return 0;
}

/* Return the length in bytes of <pn> packet number depending on
 * <largest_acked_pn> the largest ackownledged packet number.
 */
static inline size_t quic_packet_number_length(int64_t pn,
                                               int64_t largest_acked_pn)
{
	int64_t max_nack_pkts;

	/* About packet number encoding, the RFC says:
	 * The sender MUST use a packet number size able to represent more than
	 * twice as large a range than the difference between the largest
	 * acknowledged packet and packet number being sent.
	 */
	max_nack_pkts = 2 * (pn - largest_acked_pn) + 1;
	if (max_nack_pkts > 0xffffff)
		return 4;
	if (max_nack_pkts > 0xffff)
		return 3;
	if (max_nack_pkts > 0xff)
		return 2;

	return 1;
}

/* Encode <pn> packet number with <pn_len> as length in byte into a buffer with
 * <buf> as current copy address and <end> as pointer to one past the end of
 * this buffer. This is the responsibility of the caller to check there is
 * enough room in the buffer to copy <pn_len> bytes.
 * Never fails.
 */
static inline int quic_packet_number_encode(unsigned char **buf,
                                            const unsigned char *end,
                                            uint64_t pn, size_t pn_len)
{
	if (end - *buf < pn_len)
		return 0;

	/* Encode the packet number. */
	switch (pn_len) {
	case 1:
		**buf = pn;
		break;
	case 2:
		write_n16(*buf, pn);
		break;
	case 3:
		(*buf)[0] = pn >> 16;
		(*buf)[1] = pn >> 8;
		(*buf)[2] = pn;
		break;
	case 4:
		write_n32(*buf, pn);
		break;
	}
	*buf += pn_len;

	return 1;
}

/* Returns the <ack_delay> field value in milliseconds from <ack_frm> ACK frame for
 * <conn> QUIC connection. Note that the value of <ack_delay> coming from
 * ACK frame is in microseconds.
 */
static inline unsigned int quic_ack_delay_ms(struct quic_ack *ack_frm,
                                             struct quic_conn *conn)
{
	return (ack_frm->ack_delay << conn->tx.params.ack_delay_exponent) / 1000;
}

/* Returns the <ack_delay> field value in microsecond to be set in an ACK frame
 * depending on the time the packet with a new largest packet number was received.
 */
static inline uint64_t quic_compute_ack_delay_us(unsigned int time_received,
                                                 struct quic_conn *conn)
{
	return ((now_ms - time_received) * 1000) >> conn->tx.params.ack_delay_exponent;
}

/* Initialize a QUIC packet number space.
 * Never fails.
 */
static inline void quic_pktns_init(struct quic_pktns *pktns)
{
	LIST_INIT(&pktns->tx.frms);
	pktns->tx.next_pn = -1;
	pktns->tx.pkts = EB_ROOT_UNIQUE;
	pktns->tx.time_of_last_eliciting = 0;
	pktns->tx.loss_time = TICK_ETERNITY;
	pktns->tx.in_flight = 0;
	pktns->tx.ack_delay = 0;

	pktns->rx.largest_pn = -1;
	pktns->rx.largest_acked_pn = -1;
	pktns->rx.arngs.root = EB_ROOT_UNIQUE;
	pktns->rx.arngs.sz = 0;
	pktns->rx.arngs.enc_sz = 0;
	pktns->rx.nb_aepkts_since_last_ack = 0;
	pktns->rx.largest_time_received = 0;

	pktns->flags = 0;
}

/* Returns the current largest acknowledged packet number if exists, -1 if not */
static inline int64_t quic_pktns_get_largest_acked_pn(struct quic_pktns *pktns)
{
	struct eb64_node *ar = eb64_last(&pktns->rx.arngs.root);

	if (!ar)
		return -1;

	return eb64_entry(ar, struct quic_arng_node, first)->last;
}

/* The TX packets sent in the same datagram are linked to each others in
 * the order they are built. This function detach a packet from its successor
 * and predecessor in the same datagram.
 */
static inline void quic_tx_packet_dgram_detach(struct quic_tx_packet *pkt)
{
	if (pkt->prev)
		pkt->prev->next = pkt->next;
	if (pkt->next)
		pkt->next->prev = pkt->prev;
}


/* Increment the reference counter of <pkt> */
static inline void quic_tx_packet_refinc(struct quic_tx_packet *pkt)
{
	pkt->refcnt++;
}

/* Decrement the reference counter of <pkt> */
static inline void quic_tx_packet_refdec(struct quic_tx_packet *pkt)
{
	if (--pkt->refcnt == 0) {
		BUG_ON(!LIST_ISEMPTY(&pkt->frms));
		/* If there are others packet in the same datagram <pkt> is attached to,
		 * detach the previous one and the next one from <pkt>.
		 */
		quic_tx_packet_dgram_detach(pkt);
		pool_free(pool_head_quic_tx_packet, pkt);
	}
}

static inline void quic_pktns_tx_pkts_release(struct quic_pktns *pktns, struct quic_conn *qc)
{
	struct eb64_node *node;

	node = eb64_first(&pktns->tx.pkts);
	while (node) {
		struct quic_tx_packet *pkt;
		struct quic_frame *frm, *frmbak;

		pkt = eb64_entry(node, struct quic_tx_packet, pn_node);
		node = eb64_next(node);
		if (pkt->flags & QUIC_FL_TX_PACKET_ACK_ELICITING)
			qc->path->ifae_pkts--;
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list) {
			qc_frm_unref(frm, qc);
			LIST_DEL_INIT(&frm->list);
			quic_tx_packet_refdec(frm->pkt);
			qc_frm_free(&frm);
		}
		eb64_delete(&pkt->pn_node);
		quic_tx_packet_refdec(pkt);
	}
}

/* Discard <pktns> packet number space attached to <qc> QUIC connection.
 * Its loss information are reset. Deduce the outstanding bytes for this
 * packet number space from the outstanding bytes for the path of this
 * connection.
 * Note that all the non acknowledged TX packets and their frames are freed.
 * Always succeeds.
 */
static inline void quic_pktns_discard(struct quic_pktns *pktns,
                                      struct quic_conn *qc)
{
	qc->path->in_flight -= pktns->tx.in_flight;
	qc->path->prep_in_flight -= pktns->tx.in_flight;
	qc->path->loss.pto_count = 0;

	pktns->tx.time_of_last_eliciting = 0;
	pktns->tx.loss_time = TICK_ETERNITY;
	pktns->tx.pto_probe = 0;
	pktns->tx.in_flight = 0;
	quic_pktns_tx_pkts_release(pktns, qc);
}

/* Initialize <p> QUIC network path depending on <ipv4> boolean
 * which is true for an IPv4 path, if not false for an IPv6 path.
 */
static inline void quic_path_init(struct quic_path *path, int ipv4,
                                  struct quic_cc_algo *algo, struct quic_conn *qc)
{
	unsigned int max_dgram_sz;

	max_dgram_sz = ipv4 ? QUIC_INITIAL_IPV4_MTU : QUIC_INITIAL_IPV6_MTU;
	quic_loss_init(&path->loss);
	path->mtu = max_dgram_sz;
	path->cwnd = QUIC_MIN(10 * max_dgram_sz, QUIC_MAX(max_dgram_sz << 1, 14720U));
	path->min_cwnd = max_dgram_sz << 1;
	path->prep_in_flight = 0;
	path->in_flight = 0;
	path->ifae_pkts = 0;
	quic_cc_init(&path->cc, algo, qc);
}

/* Return the remaining <room> available on <path> QUIC path. In fact this this
 *the remaining number of bytes available in the congestion controller window.
 */
static inline size_t quic_path_room(struct quic_path *path)
{
	if (path->in_flight > path->cwnd)
		return 0;

	return path->cwnd - path->in_flight;
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

/* Return 1 if <pktns> matches with the Application packet number space of
 * <conn> connection which is common to the 0-RTT and 1-RTT encryption levels, 0
 * if not (handshake packets).
 */
static inline int quic_application_pktns(struct quic_pktns *pktns, struct quic_conn *conn)
{
	return pktns == &conn->pktns[QUIC_TLS_PKTNS_01RTT];
}

/* CRYPTO data buffer handling functions. */
static inline unsigned char *c_buf_getpos(struct quic_enc_level *qel, uint64_t offset)
{
	int idx;
	unsigned char *data;

	idx = offset >> QUIC_CRYPTO_BUF_SHIFT;
	data = qel->tx.crypto.bufs[idx]->data;
	return data + (offset & QUIC_CRYPTO_BUF_MASK);
}

/* Returns 1 if the CRYPTO buffer at <qel> encryption level has been
 * consumed (sent to the peer), 0 if not.
 */
static inline int c_buf_consumed(struct quic_enc_level *qel)
{
	return qel->tx.crypto.offset == qel->tx.crypto.sz;
}

/* Return 1 if <pkt> header form is long, 0 if not. */
static inline int qc_pkt_long(const struct quic_rx_packet *pkt)
{
	return pkt->type != QUIC_PACKET_TYPE_SHORT;
}

/* Return 1 if there is RX packets for <qel> QUIC encryption level, 0 if not */
static inline int qc_el_rx_pkts(struct quic_enc_level *qel)
{
	int ret;

	ret = !eb_is_empty(&qel->rx.pkts);

	return ret;
}

/* Release the memory for the RX packets which are no more referenced
 * and consume their payloads which have been copied to the RX buffer
 * for the connection.
 * Always succeeds.
 */
static inline void quic_rx_pkts_del(struct quic_conn *qc)
{
	struct quic_rx_packet *pkt, *pktback;

	list_for_each_entry_safe(pkt, pktback, &qc->rx.pkt_list, qc_rx_pkt_list) {
		if (pkt->data != (unsigned char *)b_head(&qc->rx.buf)) {
			size_t cdata;

			cdata = b_contig_data(&qc->rx.buf, 0);
			if (cdata && !*b_head(&qc->rx.buf)) {
				/* Consume the remaining data */
				b_del(&qc->rx.buf, cdata);
			}
			break;
		}

		if (pkt->refcnt)
			break;

		b_del(&qc->rx.buf, pkt->raw_len);
		LIST_DELETE(&pkt->qc_rx_pkt_list);
		pool_free(pool_head_quic_rx_packet, pkt);
	}

	/* In frequent cases the buffer will be emptied at this stage. */
	b_realign_if_empty(&qc->rx.buf);
}

/* Increment the reference counter of <pkt> */
static inline void quic_rx_packet_refinc(struct quic_rx_packet *pkt)
{
	pkt->refcnt++;
}

/* Decrement the reference counter of <pkt> while remaining positive */
static inline void quic_rx_packet_refdec(struct quic_rx_packet *pkt)
{
	if (pkt->refcnt)
		pkt->refcnt--;
}

/* Delete all RX packets for <qel> QUIC encryption level */
static inline void qc_el_rx_pkts_del(struct quic_enc_level *qel)
{
	struct eb64_node *node;

	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt =
			eb64_entry(node, struct quic_rx_packet, pn_node);

		node = eb64_next(node);
		eb64_delete(&pkt->pn_node);
		quic_rx_packet_refdec(pkt);
	}
}

static inline void qc_list_qel_rx_pkts(struct quic_enc_level *qel)
{
	struct eb64_node *node;

	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt;

		pkt = eb64_entry(node, struct quic_rx_packet, pn_node);
		fprintf(stderr, "pkt@%p type=%d pn=%llu\n",
		        pkt, pkt->type, (ull)pkt->pn_node.key);
		node = eb64_next(node);
	}
}

static inline void qc_list_all_rx_pkts(struct quic_conn *qc)
{
	fprintf(stderr, "REMAINING QEL RX PKTS:\n");
	qc_list_qel_rx_pkts(&qc->els[QUIC_TLS_ENC_LEVEL_INITIAL]);
	qc_list_qel_rx_pkts(&qc->els[QUIC_TLS_ENC_LEVEL_EARLY_DATA]);
	qc_list_qel_rx_pkts(&qc->els[QUIC_TLS_ENC_LEVEL_HANDSHAKE]);
	qc_list_qel_rx_pkts(&qc->els[QUIC_TLS_ENC_LEVEL_APP]);
}

void chunk_frm_appendf(struct buffer *buf, const struct quic_frame *frm);

void quic_set_connection_close(struct quic_conn *qc, const struct quic_err err);
void quic_set_tls_alert(struct quic_conn *qc, int alert);
int quic_set_app_ops(struct quic_conn *qc, const unsigned char *alpn, size_t alpn_len);
int qc_check_dcid(struct quic_conn *qc, unsigned char *dcid, size_t dcid_len);
int quic_get_dgram_dcid(unsigned char *buf, const unsigned char *end,
                        unsigned char **dcid, size_t *dcid_len);
int qc_send_mux(struct quic_conn *qc, struct list *frms);

void qc_notify_close(struct quic_conn *qc);

void qc_release_frm(struct quic_conn *qc, struct quic_frame *frm);

void qc_check_close_on_released_mux(struct quic_conn *qc);

void quic_conn_release(struct quic_conn *qc);

void qc_kill_conn(struct quic_conn *qc);

int quic_dgram_parse(struct quic_dgram *dgram, struct quic_conn *qc,
                     struct listener *li);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_CONN_H */
