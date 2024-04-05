#include <arpa/inet.h>
#include <string.h>

#include <haproxy/global.h>
#include <haproxy/ncbuf-t.h>
#include <haproxy/net_helper.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_enc.h>
#include <haproxy/quic_tp.h>
#include <haproxy/quic_trace.h>
#include <haproxy/trace.h>

#define QUIC_MAX_UDP_PAYLOAD_SIZE     2048

/* This is the values of some QUIC transport parameters when absent.
 * Should be used to initialize any transport parameters (local or remote)
 * before updating them with customized values.
 */
struct quic_transport_params quic_dflt_transport_params = {
	.max_udp_payload_size = QUIC_TP_DFLT_MAX_UDP_PAYLOAD_SIZE,
	.ack_delay_exponent   = QUIC_TP_DFLT_ACK_DELAY_COMPONENT,
	.max_ack_delay        = QUIC_TP_DFLT_MAX_ACK_DELAY,
	.active_connection_id_limit = QUIC_TP_DFLT_ACTIVE_CONNECTION_ID_LIMIT,
};

/* Initialize <dst> transport parameters with default values (when absent)
 * from <quic_dflt_transport_params>.
 * Never fails.
 */
static void quic_dflt_transport_params_cpy(struct quic_transport_params *dst)
{
	dst->max_udp_payload_size = quic_dflt_transport_params.max_udp_payload_size;
	dst->ack_delay_exponent   = quic_dflt_transport_params.ack_delay_exponent;
	dst->max_ack_delay        = quic_dflt_transport_params.max_ack_delay;
	dst->active_connection_id_limit = quic_dflt_transport_params.active_connection_id_limit;
}

/* Initialize <p> transport parameters. <server> is a boolean, set if TPs are
 * used by a server (haproxy frontend) else this is for a client (haproxy
 * backend).
 *
 * This must only be used for haproxy local parameters. To initialize peer
 * parameters, see quic_dflt_transport_params_cpy().
 *
 * Never fails.
 */
void quic_transport_params_init(struct quic_transport_params *p, int server)
{
	const uint64_t ncb_size = global.tune.bufsize - NCB_RESERVED_SZ;
	const int max_streams_bidi = global.tune.quic_frontend_max_streams_bidi;
	const int max_streams_uni = 3;

	/* Set RFC default values for unspecified parameters. */
	quic_dflt_transport_params_cpy(p);

	/* Set the max_udp_payload_size value. If not would equal to
	 * QUIC_TP_DFLT_MAX_UDP_PAYLOAD_SIZE
	 */
	p->max_udp_payload_size = QUIC_MAX_UDP_PAYLOAD_SIZE;
	if (server)
		p->max_idle_timeout = global.tune.quic_frontend_max_idle_timeout;
	else
		p->max_idle_timeout = global.tune.quic_backend_max_idle_timeout;

	p->initial_max_streams_bidi            = max_streams_bidi;
	p->initial_max_streams_uni             = max_streams_uni;
	p->initial_max_stream_data_bidi_local  = ncb_size;
	p->initial_max_stream_data_bidi_remote = ncb_size;
	p->initial_max_stream_data_uni         = ncb_size;
	p->initial_max_data = (max_streams_bidi + max_streams_uni) * ncb_size;

	if (server) {
		p->with_stateless_reset_token  = 1;
		p->disable_active_migration    = 1;
	}

	p->active_connection_id_limit          = 8;

	p->retry_source_connection_id.len = 0;
}

/* Encode <addr> preferred address transport parameter in <buf> without its
 * "type+len" prefix.
 * It is the responsibility of the caller to check there is enough room in <buf> to encode
 * this address.
 * Never fails.
 */
static void quic_transport_param_enc_pref_addr_val(unsigned char **buf,
                                                   const unsigned char *end,
                                                   struct tp_preferred_address *addr)
{
	write_n16(*buf, addr->ipv4_port);
	*buf += sizeof addr->ipv4_port;

	memcpy(*buf, (uint8_t *)&addr->ipv4_addr.s_addr, sizeof(addr->ipv4_addr.s_addr));
	*buf += sizeof(addr->ipv4_addr.s_addr);

	write_n16(*buf, addr->ipv6_port);
	*buf += sizeof addr->ipv6_port;

	memcpy(*buf, addr->ipv6_addr.s6_addr, sizeof(addr->ipv6_addr.s6_addr));
	*buf += sizeof(addr->ipv6_addr.s6_addr);

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
static int quic_transport_param_dec_pref_addr(struct tp_preferred_address *addr,
                                              const unsigned char **buf,
                                              const unsigned char *end)
{
	ssize_t addr_len;

	addr_len = sizeof(addr->ipv4_port) + sizeof(addr->ipv4_addr.s_addr);
	addr_len += sizeof(addr->ipv6_port) + sizeof(addr->ipv6_addr.s6_addr);
	addr_len += sizeof(addr->cid.len);

	if (end - *buf < addr_len)
		return 0;

	memcpy((uint8_t *)&addr->ipv4_addr.s_addr, *buf, sizeof(addr->ipv4_addr.s_addr));
	*buf += sizeof(addr->ipv4_addr.s_addr);

	addr->ipv4_port = read_n16(*buf);
	*buf += sizeof addr->ipv4_port;

	memcpy(addr->ipv6_addr.s6_addr, *buf, sizeof(addr->ipv6_addr.s6_addr));
	*buf += sizeof(addr->ipv6_addr.s6_addr);

	addr->ipv6_port = read_n16(*buf);
	*buf += sizeof addr->ipv6_port;

	addr->cid.len = *(*buf)++;
	if (addr->cid.len) {
		if (end - sizeof(addr->stateless_reset_token) - *buf > addr->cid.len ||
		    addr->cid.len > sizeof(addr->cid.data)) {
			return 0;
		}

		memcpy(addr->cid.data, *buf, addr->cid.len);
		*buf += addr->cid.len;
	}

	if (end - *buf != sizeof(addr->stateless_reset_token))
		return 0;

	memcpy(addr->stateless_reset_token, *buf, end - *buf);
	*buf += sizeof addr->stateless_reset_token;

	return *buf == end;
}

/* Decode into <v> version information received transport parameters from <*buf>
 * buffer. <server> must be set to 1 for QUIC clients which receive server
 * transport parameters, and 0 for QUIC servers which receive client transport
 * parameters.
 * Also set the QUIC negotiated version into <tp>.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_transport_param_dec_version_info(struct tp_version_information *tp,
                                                 const unsigned char **buf,
                                                 const unsigned char *end, int server)
{
	size_t tp_len = end - *buf;
	const unsigned char *ver, *others;

	/* <tp_len> must be a multiple of sizeof(uint32_t) */
	if (tp_len < sizeof tp->chosen || (tp_len & 0x3))
		return 0;

	tp->chosen = ntohl(read_u32(*buf));
	/* Must not be null */
	if (!tp->chosen)
		return 0;

	*buf += sizeof tp->chosen;
	others = *buf;

	/* Others versions must not be null */
	for (ver = others; ver < end; ver += 4) {
		if (!read_u32(ver))
			return 0;
	}

	if (server)
		/* TODO: not supported */
		return 0;

	for (ver = others; ver < end; ver += 4) {
		if (!tp->negotiated_version) {
			int i;

			for (i = 0; i < quic_versions_nb; i++) {
				if (ntohl(read_u32(ver)) == quic_versions[i].num) {
					tp->negotiated_version = &quic_versions[i];
					break;
				}
			}
		}

		if (preferred_version && ntohl(read_u32(ver)) == preferred_version->num) {
			tp->negotiated_version = preferred_version;
			goto out;
		}
	}

 out:
	*buf = end;

	return 1;
}

/* Decode into <p> struct a transport parameter found in <*buf> buffer with
 * <type> as type and <len> as length, depending on <server> boolean value which
 * must be set to 1 for a server (haproxy listener) or 0 for a client (connection
 * to an haproxy server).
 */
static int quic_transport_param_decode(struct quic_transport_params *p,
                                       int server, uint64_t type,
                                       const unsigned char **buf, size_t len)
{
	const unsigned char *end = *buf + len;

	switch (type) {
	case QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID:
		if (!server || len > sizeof p->original_destination_connection_id.data)
			return 0;

		if (len)
			memcpy(p->original_destination_connection_id.data, *buf, len);
		p->original_destination_connection_id.len = len;
		*buf += len;
		p->original_destination_connection_id_present = 1;
		break;
	case QUIC_TP_INITIAL_SOURCE_CONNECTION_ID:
		if (len > sizeof p->initial_source_connection_id.data)
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
	case QUIC_TP_VERSION_INFORMATION:
		if (!quic_transport_param_dec_version_info(&p->version_information,
		                                           buf, *buf + len, server))
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
static int quic_transport_param_encode_type_len(unsigned char **buf,
                                                const unsigned char *end,
                                                uint64_t type, uint64_t len)
{
	return quic_enc_int(buf, end, type) && quic_enc_int(buf, end, len);
}

/* Decode variable length type and length values of a QUIC transport parameter
 * into <type> and <len> found in <*buf> buffer.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_transport_param_decode_type_len(uint64_t *type, uint64_t *len,
                                                const unsigned char **buf,
                                                const unsigned char *end)
{
	return quic_dec_int(type, buf, end) && quic_dec_int(len, buf, end);
}

/* Encode <param> bytes stream with <type> as type and <length> as length into buf.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_transport_param_enc_mem(unsigned char **buf, const unsigned char *end,
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
static int quic_transport_param_enc_int(unsigned char **buf,
                                        const unsigned char *end,
                                        uint64_t type, uint64_t val)
{
	size_t len;

	len = quic_int_getsize(val);

	return len && quic_transport_param_encode_type_len(buf, end, type, len) &&
		quic_enc_int(buf, end, val);
}

/* Returns the required length in bytes to encode <cid> QUIC connection ID. */
static inline size_t sizeof_quic_cid(const struct tp_cid *cid)
{
	return sizeof cid->len + cid->len;
}

/* Encode <addr> preferred address into <buf>.
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_transport_param_enc_pref_addr(unsigned char **buf,
                                              const unsigned char *end,
                                              struct tp_preferred_address *addr)
{
	uint64_t addr_len = 0;

	addr_len += sizeof(addr->ipv4_port) + sizeof(addr->ipv4_addr.s_addr);
	addr_len += sizeof(addr->ipv6_port) + sizeof(addr->ipv6_addr.s6_addr);
	addr_len += sizeof_quic_cid(&addr->cid);
	addr_len += sizeof(addr->stateless_reset_token);

	if (!quic_transport_param_encode_type_len(buf, end, QUIC_TP_PREFERRED_ADDRESS, addr_len))
		return 0;

	if (end - *buf < addr_len)
		return 0;

	quic_transport_param_enc_pref_addr_val(buf, end, addr);

	return 1;
}

/* Encode version information transport parameters with <chosen_version> as chosen
 * version.
 * Return 1 if succeeded, 0 if not.
 */
static int quic_transport_param_enc_version_info(unsigned char **buf,
                                                 const unsigned char *end,
                                                 const struct quic_version *chosen_version,
                                                 int server)
{
	int i;
	uint64_t tp_len;
	uint32_t ver;

	tp_len = sizeof chosen_version->num + quic_versions_nb * sizeof(uint32_t);
	if (!quic_transport_param_encode_type_len(buf, end,
	                                          QUIC_TP_VERSION_INFORMATION,
	                                          tp_len))
		return 0;

	if (end - *buf < tp_len)
		return 0;

	/* First: chosen version */
	ver = htonl(chosen_version->num);
	memcpy(*buf, &ver, sizeof ver);
	*buf += sizeof ver;
	/* For servers: all supported version, chosen included */
	for (i = 0; i < quic_versions_nb; i++) {
		ver = htonl(quic_versions[i].num);
		memcpy(*buf, &ver, sizeof ver);
		*buf += sizeof ver;
	}

	return 1;
}

/* Encode <p> transport parameter into <buf> depending on <server> value which
 * must be set to 1 for a server (haproxy listener) or 0 for a client
 * (connection to a haproxy server).
 * Return the number of bytes consumed if succeeded, 0 if not.
 */
int quic_transport_params_encode(unsigned char *buf,
                                 const unsigned char *end,
                                 struct quic_transport_params *p,
                                 const struct quic_version *chosen_version,
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
	if (p->max_udp_payload_size != QUIC_TP_DFLT_MAX_UDP_PAYLOAD_SIZE &&
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
	if (p->ack_delay_exponent != QUIC_TP_DFLT_ACK_DELAY_COMPONENT  &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_ACK_DELAY_EXPONENT, p->ack_delay_exponent))
	    return 0;

	/*
	 * "max_ack_delay" transport parameter must be transmitted only if different
	 * of the default value.
	 */
	if (p->max_ack_delay != QUIC_TP_DFLT_MAX_ACK_DELAY &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_MAX_ACK_DELAY, p->max_ack_delay))
	    return 0;

	/* 0-length value */
	if (p->disable_active_migration &&
	    !quic_transport_param_encode_type_len(&pos, end, QUIC_TP_DISABLE_ACTIVE_MIGRATION, 0))
		return 0;

	if (p->active_connection_id_limit &&
	    p->active_connection_id_limit != QUIC_TP_DFLT_ACTIVE_CONNECTION_ID_LIMIT &&
	    !quic_transport_param_enc_int(&pos, end, QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
	                                  p->active_connection_id_limit))
	    return 0;

	if (chosen_version && !quic_transport_param_enc_version_info(&pos, end, chosen_version, server))
		return 0;

	return pos - head;
}

/* Decode transport parameters found in <buf> buffer into <p>, depending on
 * <server> boolean value which must be set to 1 for a server (haproxy listener)
 * or 0 for a client (connection to a haproxy server).
 * Returns 1 if succeeded, 0 if not.
 */
static int quic_transport_params_decode(struct quic_transport_params *p, int server,
                                        const unsigned char *buf,
                                        const unsigned char *end)
{
	const unsigned char *pos;
	uint64_t type, len = 0;

	pos = buf;

	while (pos != end) {
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

	/* Note that if not received by the peer, active_connection_id_limit will
	 * have QUIC_TP_DFLT_ACTIVE_CONNECTION_ID_LIMIT as default value. This
	 * is also the minimum value for this transport parameter.
	 */
	if (p->active_connection_id_limit < QUIC_TP_DFLT_ACTIVE_CONNECTION_ID_LIMIT)
		return 0;

	return 1;
}

/* Store transport parameters found in <buf> buffer into <qc> QUIC connection
 * depending on <server> value which must be 1 for a server (haproxy listener)
 * or 0 for a client (connection to a haproxy server).
 * Note that peer transport parameters are stored in the TX part of the connection:
 * they are used to send packets to the peer with its transport parameters as
 * limitations.
 * Returns 1 if succeeded, 0 if not.
 */
int quic_transport_params_store(struct quic_conn *qc, int server,
                                const unsigned char *buf,
                                const unsigned char *end)
{
	struct quic_transport_params *tx_params = &qc->tx.params;
	struct quic_transport_params *rx_params = &qc->rx.params;
	/* Initial source connection ID */
	struct tp_cid *iscid;

	/* initialize peer TPs to RFC default value */
	quic_dflt_transport_params_cpy(tx_params);

	if (!quic_transport_params_decode(tx_params, server, buf, end))
		return 0;

	/* Update the connection from transport parameters received */
	if (tx_params->version_information.negotiated_version &&
	    tx_params->version_information.negotiated_version != qc->original_version)
		qc->negotiated_version =
			qc->tx.params.version_information.negotiated_version;

	if (tx_params->max_ack_delay)
		qc->max_ack_delay = tx_params->max_ack_delay;

	if (tx_params->max_idle_timeout && rx_params->max_idle_timeout)
		qc->max_idle_timeout =
			QUIC_MIN(tx_params->max_idle_timeout, rx_params->max_idle_timeout);
	else
		qc->max_idle_timeout =
			QUIC_MAX(tx_params->max_idle_timeout, rx_params->max_idle_timeout);
	TRACE_PROTO("\nTX(remote) transp. params.", QUIC_EV_TRANSP_PARAMS, qc, tx_params);

	/* Check that the "initial_source_connection_id" transport parameter matches
	 * the SCID received which is also the DCID of the connection.
	 */
	iscid = &tx_params->initial_source_connection_id;
	if (qc->dcid.len != iscid->len ||
	    (qc->dcid.len && memcmp(qc->dcid.data, iscid->data, qc->dcid.len))) {
		TRACE_PROTO("initial_source_connection_id transport parameter mismatch",
		            QUIC_EV_TRANSP_PARAMS, qc);
		/* Kill the connection as soon as possible */
		qc_kill_conn(qc);
	}

	return 1;
}

/* QUIC server (or haproxy listener) only function.
 * Initialize the local transport parameters <rx_params> from <listener_params>
 * coming from configuration and Initial packet information (destination
 * connection ID, source connection ID, original destination connection ID) from
 * client token.
 * Returns 1 if succeeded, 0 if not.
 */
int qc_lstnr_params_init(struct quic_conn *qc,
                         const struct quic_transport_params *listener_params,
                         const unsigned char *stateless_reset_token,
                         const unsigned char *dcid, size_t dcidlen,
                         const unsigned char *scid, size_t scidlen,
                         const struct quic_cid *token_odcid)
{
	struct quic_transport_params *rx_params = &qc->rx.params;
	struct tp_cid *odcid_param = &rx_params->original_destination_connection_id;

	/* Copy the transport parameters. */
	*rx_params = *listener_params;
	/* Copy the stateless reset token */
	memcpy(rx_params->stateless_reset_token, stateless_reset_token,
	       sizeof rx_params->stateless_reset_token);
	/* Copy original_destination_connection_id transport parameter. */
	if (token_odcid->len) {
		memcpy(odcid_param->data, token_odcid->data, token_odcid->len);
		odcid_param->len = token_odcid->len;
		/* Copy retry_source_connection_id transport parameter. */
		memcpy(rx_params->retry_source_connection_id.data, dcid, dcidlen);
		rx_params->retry_source_connection_id.len = dcidlen;
	}
	else {
		memcpy(odcid_param->data, dcid, dcidlen);
		odcid_param->len = dcidlen;
	}

	/* Copy the initial source connection ID. */
	memcpy(rx_params->initial_source_connection_id.data, scid, scidlen);
	rx_params->initial_source_connection_id.len = scidlen;
	TRACE_PROTO("\nRX(local) transp. params.", QUIC_EV_TRANSP_PARAMS, qc, rx_params);

	return 1;
}

