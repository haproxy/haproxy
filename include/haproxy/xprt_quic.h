/*
 * include/haproxy/xprt_quic.h
 * This file contains QUIC xprt function prototypes
 *
 * Copyright 2020 HAProxy Technologies, Frédéric Lécaille <flecaille@haproxy.com>
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

#ifndef _HAPROXY_XPRT_QUIC_H
#define _HAPROXY_XPRT_QUIC_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <stdint.h>

#include <import/eb64tree.h>
#include <import/ebmbtree.h>

#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/net_helper.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ticks.h>

#include <haproxy/listener.h>
#include <haproxy/quic_cc.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_loss.h>
#include <haproxy/mux_quic.h>
#include <haproxy/xprt_quic-t.h>

#include <openssl/rand.h>

extern struct pool_head *pool_head_quic_connection_id;

int ssl_quic_initial_ctx(struct bind_conf *bind_conf);

static inline int qc_is_listener(struct quic_conn *qc)
{
	return qc->flags & QUIC_FL_CONN_LISTENER;
}

/* Update the mux stream-related transport parameters from <qc> connection */
static inline void quic_transport_params_update(struct quic_conn *qc)
{
	quic_mux_transport_params_update(qc->qcc);
}

/* Returns the required length in bytes to encode <cid> QUIC connection ID. */
static inline size_t sizeof_quic_cid(const struct quic_cid *cid)
{
	return sizeof cid->len + cid->len;
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

/* Simply compute a thread ID from a CID */
static inline unsigned long quic_get_cid_tid(const struct quic_cid *cid)
{
	return cid->data[0] % global.nbthread;
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

		cid = eb64_entry(&node->node, struct quic_connection_id, seq_num);

		/* remove the CID from the receiver tree */
		ebmb_delete(&cid->node);

		/* remove the CID from the quic_conn tree */
		node = eb64_next(node);
		eb64_delete(&cid->seq_num);
		pool_free(pool_head_quic_connection_id, cid);
	}
}

/* Copy <src> new connection ID information to <to> NEW_CONNECTION_ID frame data.
 * Always succeeds.
 */
static inline void quic_connection_id_to_frm_cpy(struct quic_frame *dst,
                                                 struct quic_connection_id *src)
{
	struct quic_new_connection_id *to = &dst->new_connection_id;

	dst->type = QUIC_FT_NEW_CONNECTION_ID;
	to->seq_num = src->seq_num.key;
	to->retire_prior_to = src->retire_prior_to;
	to->cid.len = src->cid.len;
	to->cid.data = src->cid.data;
	to->stateless_reset_token = src->stateless_reset_token;
}

/* Allocate a new CID with <seq_num> as sequence number and attach it to <root>
 * ebtree.
 * Returns the new CID if succeeded, NULL if not.
 */
static inline struct quic_connection_id *new_quic_cid(struct eb_root *root,
                                                      struct quic_conn *qc,
                                                      int seq_num)
{
	struct quic_connection_id *cid;

	cid = pool_alloc(pool_head_quic_connection_id);
	if (!cid)
		return NULL;

	cid->cid.len = QUIC_HAP_CID_LEN;
	if (RAND_bytes(cid->cid.data, cid->cid.len) != 1 ||
	    RAND_bytes(cid->stateless_reset_token,
	               sizeof cid->stateless_reset_token) != 1) {
		fprintf(stderr, "Could not generate %d random bytes\n", cid->cid.len);
		goto err;
	}

	cid->qc = qc;

	cid->seq_num.key = seq_num;
	cid->retire_prior_to = 0;
	/* insert the allocated CID in the quic_conn tree */
	eb64_insert(root, &cid->seq_num);

	return cid;

 err:
	pool_free(pool_head_quic_connection_id, cid);
	return NULL;
}

/* The maximum size of a variable-length QUIC integer encoded with 1 byte */
#define QUIC_VARINT_1_BYTE_MAX       ((1UL <<  6) - 1)
/* The maximum size of a variable-length QUIC integer encoded with 2 bytes */
#define QUIC_VARINT_2_BYTE_MAX       ((1UL <<  14) - 1)
/* The maximum size of a variable-length QUIC integer encoded with 4 bytes */
#define QUIC_VARINT_4_BYTE_MAX       ((1UL <<  30) - 1)
/* The maximum size of a variable-length QUIC integer encoded with 8 bytes */
#define QUIC_VARINT_8_BYTE_MAX       ((1ULL <<  62) - 1)

/* The maximum size of a variable-length QUIC integer */
#define QUIC_VARINT_MAX_SIZE       8

/* The two most significant bits of byte #0 from a QUIC packet gives the 2 
 * logarithm of the length of a variable length encoded integer.
 */
#define QUIC_VARINT_BYTE_0_BITMASK 0x3f
#define QUIC_VARINT_BYTE_0_SHIFT   6

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

/* Return the difference between the encoded length of <val> and the encoded
 * length of <val+1>.
 */
static inline size_t quic_incint_size_diff(uint64_t val)
{
	switch (val) {
	case QUIC_VARINT_1_BYTE_MAX:
		return 1;
	case QUIC_VARINT_2_BYTE_MAX:
		return 2;
	case QUIC_VARINT_4_BYTE_MAX:
		return 4;
	default:
		return 0;
	}
}

/* Return the difference between the encoded length of <val> and the encoded
 * length of <val-1>.
 */
static inline size_t quic_decint_size_diff(uint64_t val)
{
	switch (val) {
	case QUIC_VARINT_1_BYTE_MAX + 1:
		return 1;
	case QUIC_VARINT_2_BYTE_MAX + 1:
		return 2;
	case QUIC_VARINT_4_BYTE_MAX + 1:
		return 4;
	default:
		return 0;
	}
}


/* Returns the maximum value of a QUIC variable-length integer with <sz> as size */
static inline uint64_t quic_max_int(size_t sz)
{
	switch (sz) {
	case 1:
		return QUIC_VARINT_1_BYTE_MAX;
	case 2:
		return QUIC_VARINT_2_BYTE_MAX;
	case 4:
		return QUIC_VARINT_4_BYTE_MAX;
	case 8:
		return QUIC_VARINT_8_BYTE_MAX;
	}

	return -1;
}

/* Return the maximum number of bytes we must use to completely fill a
 * buffer with <sz> as size for a data field of bytes prefixed by its QUIC
 * variable-length (may be 0).
 * Also put in <*len_sz> the size of this QUIC variable-length.
 * So after returning from this function we have : <*len_sz> + <ret> = <sz>.
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
	if (unlikely(diff > 0))
		ret += diff;

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

/* Returns the <ack_delay> field value from <ack_frm> ACK frame for
 * <conn> QUIC connection.
 */
static inline unsigned int quic_ack_delay_ms(struct quic_ack *ack_frm,
                                             struct quic_conn *conn)
{
	return ack_frm->ack_delay << conn->tx.params.ack_delay_exponent;
}

/* Initialize <dst> transport parameters with default values (when absent)
 * from <quic_dflt_trasports_params>.
 * Never fails.
 */
static inline void quic_dflt_transport_params_cpy(struct quic_transport_params *dst)
{
	dst->max_udp_payload_size = quic_dflt_transport_params.max_udp_payload_size;
	dst->ack_delay_exponent   = quic_dflt_transport_params.ack_delay_exponent;
	dst->max_ack_delay        = quic_dflt_transport_params.max_ack_delay;
	dst->active_connection_id_limit = quic_dflt_transport_params.active_connection_id_limit;
}

/* Initialize <p> transport parameters depending <server> boolean value which
 * must be set to 1 for a server (haproxy listener), 0 for a client (connection
 * to haproxy server).
 * Never fails.
 */
static inline void quic_transport_params_init(struct quic_transport_params *p,
                                              int server)
{
	/* Default values (when absent) */
	quic_dflt_transport_params_cpy(p);

	p->max_idle_timeout                    = 30000;

	p->initial_max_data                    = 1 * 1024 * 1024;
	p->initial_max_stream_data_bidi_local  = 256 * 1024;
	p->initial_max_stream_data_bidi_remote = 256 * 1024;
	p->initial_max_stream_data_uni         = 256 * 1024;
	p->initial_max_streams_bidi            = 100;
	p->initial_max_streams_uni             = 3;

	if (server)
		p->with_stateless_reset_token      = 1;
	p->active_connection_id_limit          = 8;

	p->retry_source_connection_id.len = 0;

}

/* Encode <addr> preferred address transport parameter in <buf> without its
 * "type+len" prefix. Note that the IP addresses must be encoded in network byte
 * order.
 * So ->ipv4_addr and ->ipv6_addr, which are buffers, must contained values
 * already encoded in network byte order.
 * It is the responsibility of the caller to check there is enough room in <buf> to encode
 * this address.
 * Never fails.
 */
static inline void quic_transport_param_enc_pref_addr_val(unsigned char **buf,
                                                          const unsigned char *end,
                                                          struct preferred_address *addr)
{
	write_n16(*buf, addr->ipv4_port);
	*buf += sizeof addr->ipv4_port;

	memcpy(*buf, addr->ipv4_addr, sizeof addr->ipv4_addr);
	*buf += sizeof addr->ipv4_addr;

	write_n16(*buf, addr->ipv6_port);
	*buf += sizeof addr->ipv6_port;

	memcpy(*buf, addr->ipv6_addr, sizeof addr->ipv6_addr);
	*buf += sizeof addr->ipv6_addr;

	*(*buf)++ = addr->cid.len;
	if (addr->cid.len) {
		memcpy(*buf, addr->cid.data, addr->cid.len);
		*buf += addr->cid.len;
	}

	memcpy(*buf, addr->stateless_reset_token, sizeof addr->stateless_reset_token);
	*buf += sizeof addr->stateless_reset_token;
}

/* Decode into <addr> preferred address transport parameter found in <*buf> buffer.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_transport_param_dec_pref_addr(struct preferred_address *addr,
                                                     const unsigned char **buf,
                                                     const unsigned char *end)
{
	ssize_t addr_len;

	addr_len = sizeof addr->ipv4_port + sizeof addr->ipv4_addr;
	addr_len += sizeof addr->ipv6_port + sizeof addr->ipv6_addr;
	addr_len += sizeof addr->cid.len;

	if (end - *buf < addr_len)
		return 0;

	addr->ipv4_port = read_n16(*buf);
	*buf += sizeof addr->ipv4_port;

	memcpy(addr->ipv4_addr, *buf, sizeof addr->ipv4_addr);
	*buf += sizeof addr->ipv4_addr;

	addr->ipv6_port = read_n16(*buf);
	*buf += sizeof addr->ipv6_port;

	memcpy(addr->ipv6_addr, *buf, sizeof addr->ipv6_addr);
	*buf += sizeof addr->ipv6_addr;

	addr->cid.len = *(*buf)++;
	if (addr->cid.len) {
		if (end - *buf > addr->cid.len || addr->cid.len > sizeof addr->cid.data)
			return 0;
		memcpy(addr->cid.data, *buf, addr->cid.len);
		*buf += addr->cid.len;
	}

	if (end - *buf != sizeof addr->stateless_reset_token)
		return 0;

	memcpy(addr->stateless_reset_token, *buf, end - *buf);
	*buf += sizeof addr->stateless_reset_token;

	return *buf == end;
}

/* Decode into <p> struct a transport parameter found in <*buf> buffer with
 * <type> as type and <len> as length, depending on <server> boolean value which
 * must be set to 1 for a server (haproxy listener) or 0 for a client (connection
 * to an haproxy server).
 */
static inline int quic_transport_param_decode(struct quic_transport_params *p,
                                              int server, uint64_t type,
                                              const unsigned char **buf, size_t len)
{
	const unsigned char *end = *buf + len;

	quic_dflt_transport_params_cpy(p);
	switch (type) {
	case QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID:
		if (!server || len >= sizeof p->original_destination_connection_id.data)
			return 0;

		if (len)
			memcpy(p->original_destination_connection_id.data, *buf, len);
		p->original_destination_connection_id.len = len;
		*buf += len;
		p->original_destination_connection_id_present = 1;
		break;
	case QUIC_TP_INITIAL_SOURCE_CONNECTION_ID:
		if (len >= sizeof p->initial_source_connection_id.data)
			return 0;

		if (len)
			memcpy(p->initial_source_connection_id.data, *buf, len);
		p->initial_source_connection_id.len = len;
		*buf += len;
		p->initial_source_connection_id_present = 1;
		break;
	case QUIC_TP_STATELESS_RESET_TOKEN:
		if (!server || len != sizeof p->stateless_reset_token)
			return 0;
		memcpy(p->stateless_reset_token, *buf, len);
		*buf += len;
		p->with_stateless_reset_token = 1;
		break;
	case QUIC_TP_PREFERRED_ADDRESS:
		if (!server)
			return 0;
		if (!quic_transport_param_dec_pref_addr(&p->preferred_address, buf, *buf + len))
			return 0;
		p->with_preferred_address = 1;
		break;
	case QUIC_TP_MAX_IDLE_TIMEOUT:
		if (!quic_dec_int(&p->max_idle_timeout, buf, end))
			return 0;
		break;
	case QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
		if (!quic_dec_int(&p->max_udp_payload_size, buf, end))
			return 0;
		break;
	case QUIC_TP_INITIAL_MAX_DATA:
		if (!quic_dec_int(&p->initial_max_data, buf, end))
			return 0;
		break;
	case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
		if (!quic_dec_int(&p->initial_max_stream_data_bidi_local, buf, end))
			return 0;
		break;
	case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
		if (!quic_dec_int(&p->initial_max_stream_data_bidi_remote, buf, end))
			return 0;
		break;
	case QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
		if (!quic_dec_int(&p->initial_max_stream_data_uni, buf, end))
			return 0;
		break;
	case QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
		if (!quic_dec_int(&p->initial_max_streams_bidi, buf, end))
			return 0;
		break;
	case QUIC_TP_INITIAL_MAX_STREAMS_UNI:
		if (!quic_dec_int(&p->initial_max_streams_uni, buf, end))
			return 0;
		break;
	case QUIC_TP_ACK_DELAY_EXPONENT:
		if (!quic_dec_int(&p->ack_delay_exponent, buf, end) ||
			p->ack_delay_exponent > QUIC_TP_ACK_DELAY_EXPONENT_LIMIT)
			return 0;
		break;
	case QUIC_TP_MAX_ACK_DELAY:
		if (!quic_dec_int(&p->max_ack_delay, buf, end) ||
			p->max_ack_delay > QUIC_TP_MAX_ACK_DELAY_LIMIT)
			return 0;
		break;
	case QUIC_TP_DISABLE_ACTIVE_MIGRATION:
		/* Zero-length parameter type. */
		if (len != 0)
			return 0;
		p->disable_active_migration = 1;
		break;
	case QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
		if (!quic_dec_int(&p->active_connection_id_limit, buf, end))
			return 0;
		break;
	default:
		*buf += len;
	};

	return *buf == end;
}

/* Encode <type> and <len> variable length values in <buf>.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_transport_param_encode_type_len(unsigned char **buf,
                                                       const unsigned char *end,
                                                       uint64_t type, uint64_t len)
{
	return quic_enc_int(buf, end, type) && quic_enc_int(buf, end, len);
}

/* Decode variable length type and length values of a QUIC transport parameter
 * into <type> and <len> found in <*buf> buffer.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_transport_param_decode_type_len(uint64_t *type, uint64_t *len,
                                                       const unsigned char **buf,
                                                       const unsigned char *end)
{
	return quic_dec_int(type, buf, end) && quic_dec_int(len, buf, end);
}

/* Encode <param> bytes stream with <type> as type and <length> as length into buf.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_transport_param_enc_mem(unsigned char **buf, const unsigned char *end,
                                               uint64_t type, void *param, uint64_t length)
{
	if (!quic_transport_param_encode_type_len(buf, end, type, length))
		return 0;

	if (end - *buf < length)
		return 0;

	if (length)
		memcpy(*buf, param, length);
	*buf += length;

	return 1;
}

/* Encode <val> 64-bits value as variable length integer into <buf>.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_transport_param_enc_int(unsigned char **buf,
                                               const unsigned char *end,
                                               uint64_t type, uint64_t val)
{
	size_t len;

	len = quic_int_getsize(val);

	return len && quic_transport_param_encode_type_len(buf, end, type, len) &&
		quic_enc_int(buf, end, val);
}

/* Encode <addr> preferred address into <buf>.
 * Note that the IP addresses must be encoded in network byte order.
 * So ->ipv4_addr and ->ipv6_addr, which are buffers, must contained
 * values already encoded in network byte order.
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_transport_param_enc_pref_addr(unsigned char **buf,
                                                     const unsigned char *end,
                                                     struct preferred_address *addr)
{
	uint64_t addr_len = 0;

	addr_len += sizeof addr->ipv4_port + sizeof addr->ipv4_addr;
	addr_len += sizeof addr->ipv6_port + sizeof addr->ipv6_addr;
	addr_len += sizeof_quic_cid(&addr->cid);
	addr_len += sizeof addr->stateless_reset_token;

	if (!quic_transport_param_encode_type_len(buf, end, QUIC_TP_PREFERRED_ADDRESS, addr_len))
		return 0;

	if (end - *buf < addr_len)
		return 0;

	quic_transport_param_enc_pref_addr_val(buf, end, addr);

	return 1;
}

/* Encode <p> transport parameter into <buf> depending on <server> value which
 * must be set to 1 for a server (haproxy listener) or 0 for a client
 * (connection to a haproxy server).
 * Return the number of bytes consumed if succeeded, 0 if not.
 */
static inline int quic_transport_params_encode(unsigned char *buf,
                                               const unsigned char *end,
                                               struct quic_transport_params *p,
                                               int server)
{
	unsigned char *head;
	unsigned char *pos;

	head = pos = buf;
	if (server) {
		if (!quic_transport_param_enc_mem(&pos, end,
		                                  QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID,
		                                  p->original_destination_connection_id.data,
		                                  p->original_destination_connection_id.len))
			return 0;

		if (p->retry_source_connection_id.len) {
			if (!quic_transport_param_enc_mem(&pos, end,
			                                  QUIC_TP_RETRY_SOURCE_CONNECTION_ID,
			                                  p->retry_source_connection_id.data,
			                                  p->retry_source_connection_id.len))
				return 0;
		}

		if (p->with_stateless_reset_token &&
			!quic_transport_param_enc_mem(&pos, end, QUIC_TP_STATELESS_RESET_TOKEN,
			                              p->stateless_reset_token,
			                              sizeof p->stateless_reset_token))
			return 0;
		if (p->with_preferred_address &&
			!quic_transport_param_enc_pref_addr(&pos, end, &p->preferred_address))
			return 0;
	}

	if (!quic_transport_param_enc_mem(&pos, end,
	                                  QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
	                                  p->initial_source_connection_id.data,
	                                  p->initial_source_connection_id.len))
		return 0;

	if (p->max_idle_timeout &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_MAX_IDLE_TIMEOUT, p->max_idle_timeout))
		return 0;

	/*
	 * "max_packet_size" transport parameter must be transmitted only if different
	 * of the default value.
	 */
	if (p->max_udp_payload_size != QUIC_DFLT_MAX_UDP_PAYLOAD_SIZE &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_MAX_UDP_PAYLOAD_SIZE, p->max_udp_payload_size))
		return 0;

	if (p->initial_max_data &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_DATA, p->initial_max_data))
	    return 0;

	if (p->initial_max_stream_data_bidi_local &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
	                                          p->initial_max_stream_data_bidi_local))
	    return 0;

	if (p->initial_max_stream_data_bidi_remote &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
	                                          p->initial_max_stream_data_bidi_remote))
	    return 0;

	if (p->initial_max_stream_data_uni &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
	                                          p->initial_max_stream_data_uni))
	    return 0;

	if (p->initial_max_streams_bidi &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
	                                          p->initial_max_streams_bidi))
	    return 0;

	if (p->initial_max_streams_uni &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_INITIAL_MAX_STREAMS_UNI,
	                                          p->initial_max_streams_uni))
	    return 0;

	/*
	 * "ack_delay_exponent" transport parameter must be transmitted only if different
	 * of the default value.
	 */
	if (p->ack_delay_exponent != QUIC_DFLT_ACK_DELAY_COMPONENT  &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_ACK_DELAY_EXPONENT, p->ack_delay_exponent))
	    return 0;

	/*
	 * "max_ack_delay" transport parameter must be transmitted only if different
	 * of the default value.
	 */
	if (p->max_ack_delay != QUIC_DFLT_MAX_ACK_DELAY &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_MAX_ACK_DELAY, p->max_ack_delay))
	    return 0;

	/* 0-length value */
	if (p->disable_active_migration &&
	    !quic_transport_param_encode_type_len(&pos, end, QUIC_TP_DISABLE_ACTIVE_MIGRATION, 0))
		return 0;

	if (p->active_connection_id_limit &&
	    p->active_connection_id_limit != QUIC_ACTIVE_CONNECTION_ID_LIMIT &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
	                                  p->active_connection_id_limit))
	    return 0;

	return pos - head;
}

/* Decode transport parameters found in <buf> buffer into <p>, depending on
 * <server> boolean value which must be set to 1 for a server (haproxy listener)
 * or 0 for a client (connection to a haproxy server).
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_transport_params_decode(struct quic_transport_params *p, int server,
                                               const unsigned char *buf,
                                               const unsigned char *end)
{
	const unsigned char *pos;

	pos = buf;

	quic_transport_params_init(p, server);
	while (pos != end) {
		uint64_t type, len;

		if (!quic_transport_param_decode_type_len(&type, &len, &pos, end))
			return 0;

		if (end - pos < len)
			return 0;

		if (!quic_transport_param_decode(p, server, type, &pos, len))
			return 0;
	}

	/*
	 * A server MUST send original_destination_connection_id transport parameter.
	 * initial_source_connection_id must be present both for server and client.
	 */
	if ((server && !p->original_destination_connection_id_present) ||
	    !p->initial_source_connection_id_present)
		return 0;

	return 1;
}

/* Store transport parameters found in <buf> buffer into <conn> QUIC connection
 * depending on <server> value which must be 1 for a server (haproxy listener)
 * or 0 for a client (connection to a haproxy server).
 * Returns 1 if succeeded, 0 if not.
 */
static inline int quic_transport_params_store(struct quic_conn *conn, int server,
                                              const unsigned char *buf,
                                              const unsigned char *end)
{
	if (!quic_transport_params_decode(&conn->tx.params, server, buf, end))
		return 0;

	if (conn->tx.params.max_ack_delay)
		conn->max_ack_delay = conn->tx.params.max_ack_delay;

	return 1;
}

/* Initialize a QUIC packet number space.
 * Never fails.
 */
static inline void quic_pktns_init(struct quic_pktns *pktns)
{
	LIST_INIT(&pktns->tx.frms);
	pktns->tx.next_pn = -1;
	pktns->tx.pkts = EB_ROOT_UNIQUE;
	pktns->tx.largest_acked_pn = -1;
	pktns->tx.time_of_last_eliciting = 0;
	pktns->tx.loss_time = TICK_ETERNITY;
	pktns->tx.in_flight = 0;

	pktns->rx.largest_pn = -1;
	pktns->rx.arngs.root = EB_ROOT_UNIQUE;
	pktns->rx.arngs.sz = 0;
	pktns->rx.arngs.enc_sz = 0;

	pktns->flags = 0;
}

/* Discard <pktns> packet number space attached to <qc> QUIC connection.
 * Its loss information are reset. Deduce the outstanding bytes for this
 * packet number space from the outstanding bytes for the path of this
 * connection§.
 * Note that all the non acknowledged TX packets and their frames are freed.
 * Always succeeds. 
 */
static inline void quic_pktns_discard(struct quic_pktns *pktns,
                                      struct quic_conn *qc)
{
	struct eb64_node *node;

	pktns->tx.time_of_last_eliciting = 0;
	pktns->tx.loss_time = TICK_ETERNITY;
	pktns->tx.pto_probe = 0;
	pktns->tx.in_flight = 0;
	qc->path->loss.pto_count = 0;
	qc->path->in_flight -= pktns->tx.in_flight;

	node = eb64_first(&pktns->tx.pkts);
	while (node) {
		struct quic_tx_packet *pkt;
		struct quic_frame *frm, *frmbak;

		pkt = eb64_entry(&node->node, struct quic_tx_packet, pn_node);
		node = eb64_next(node);
		list_for_each_entry_safe(frm, frmbak, &pkt->frms, list) {
			LIST_DELETE(&frm->list);
			pool_free(pool_head_quic_frame, frm);
		}
		eb64_delete(&pkt->pn_node);
		pool_free(pool_head_quic_tx_packet, pkt);
	}
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
	if (path->in_flight > path->cwnd)
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

	HA_RWLOCK_RDLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);
	ret = !eb_is_empty(&qel->rx.pkts);
	HA_RWLOCK_RDUNLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);

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

		if (HA_ATOMIC_LOAD(&pkt->refcnt))
			break;

		b_del(&qc->rx.buf, pkt->raw_len);
		LIST_DELETE(&pkt->qc_rx_pkt_list);
		pool_free(pool_head_quic_rx_packet, pkt);
	}
}

/* Increment the reference counter of <pkt> */
static inline void quic_rx_packet_refinc(struct quic_rx_packet *pkt)
{
	HA_ATOMIC_ADD(&pkt->refcnt, 1);
}

/* Decrement the reference counter of <pkt> while remaining positive */
static inline void quic_rx_packet_refdec(struct quic_rx_packet *pkt)
{
	unsigned int refcnt;

	do {
		refcnt = HA_ATOMIC_LOAD(&pkt->refcnt);
	} while (refcnt && !HA_ATOMIC_CAS(&pkt->refcnt, &refcnt, refcnt - 1));
}

/* Increment the reference counter of <pkt> */
static inline void quic_tx_packet_refinc(struct quic_tx_packet *pkt)
{
	HA_ATOMIC_ADD(&pkt->refcnt, 1);
}

/* Decrement the reference counter of <pkt> */
static inline void quic_tx_packet_refdec(struct quic_tx_packet *pkt)
{
	if (!HA_ATOMIC_SUB_FETCH(&pkt->refcnt, 1))
		pool_free(pool_head_quic_tx_packet, pkt);
}

/* Delete all RX packets for <qel> QUIC encryption level */
static inline void qc_el_rx_pkts_del(struct quic_enc_level *qel)
{
	struct eb64_node *node;

	HA_RWLOCK_WRLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);
	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt =
			eb64_entry(&node->node, struct quic_rx_packet, pn_node);

		node = eb64_next(node);
		eb64_delete(&pkt->pn_node);
		quic_rx_packet_refdec(pkt);
	}
	HA_RWLOCK_WRUNLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);
}

static inline void qc_list_qel_rx_pkts(struct quic_enc_level *qel)
{
	struct eb64_node *node;

	HA_RWLOCK_RDLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);
	node = eb64_first(&qel->rx.pkts);
	while (node) {
		struct quic_rx_packet *pkt;

		pkt = eb64_entry(&node->node, struct quic_rx_packet, pn_node);
		fprintf(stderr, "pkt@%p type=%d pn=%llu\n",
		        pkt, pkt->type, (ull)pkt->pn_node.key);
		node = eb64_next(node);
	}
	HA_RWLOCK_RDUNLOCK(QUIC_LOCK, &qel->rx.pkts_rwlock);
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

void quic_set_tls_alert(struct quic_conn *qc, int alert);
int quic_set_app_ops(struct quic_conn *qc, const unsigned char *alpn, size_t alpn_len);
ssize_t quic_lstnr_dgram_read(struct buffer *buf, size_t len, void *owner,
                              struct sockaddr_storage *saddr);

#endif /* USE_QUIC */
#endif /* _HAPROXY_XPRT_QUIC_H */
