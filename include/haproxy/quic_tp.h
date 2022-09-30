#ifndef _HAPROXY_QUIC_TP_H
#define _HAPROXY_QUIC_TP_H
#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <haproxy/chunk.h>
#include <haproxy/quic_conn-t.h>
#include <haproxy/quic_tp-t.h>

void quic_transport_params_init(struct quic_transport_params *p, int server);
int quic_transport_params_encode(unsigned char *buf,
                                 const unsigned char *end,
                                 struct quic_transport_params *p,
                                 const struct quic_version *choosen_version,
                                 int server);

int quic_transport_params_store(struct quic_conn *conn, int server,
                                const unsigned char *buf,
                                const unsigned char *end);

int qc_lstnr_params_init(struct quic_conn *qc,
                         const struct quic_transport_params *listener_params,
                         const unsigned char *stateless_reset_token,
                         const unsigned char *dcid, size_t dcidlen,
                         const unsigned char *scid, size_t scidlen,
                         const struct quic_cid *token_odcid);

/* Dump <cid> transport parameter connection ID value if present (non null length).
 * Used only for debugging purposes.
 */
static inline void quic_tp_cid_dump(struct buffer *buf,
                                    const struct tp_cid *cid)
{
	int i;

	chunk_appendf(buf, "(%d", cid->len);
	if (cid->len)
		chunk_appendf(buf, ",");
	for (i = 0; i < cid->len; i++)
		chunk_appendf(buf, "%02x", cid->data[i]);
	chunk_appendf(buf, ")");
}

static inline void quic_tp_version_info_dump(struct buffer *b,
                                             const struct tp_version_information *tp, int local)
{
	if (!tp->choosen)
		return;

	chunk_appendf(b, "\n\tversion_information:(choosen=0x%08x", tp->choosen);
	if (tp->nb_others) {
		int i = 0;
		const uint32_t *ver;
		chunk_appendf(b, ",others=");
		for (ver = tp->others; i < tp->nb_others; i++, ver++) {
			if (i != 0)
				chunk_appendf(b, ",");
			if (local)
				chunk_appendf(b, "0x%08x", *ver);
			else
				chunk_appendf(b, "0x%08x", ntohl(*ver));
		}
		chunk_appendf(b, ")\n");
	}
}

static inline void quic_transport_params_dump(struct buffer *b,
                                              const struct quic_conn *qc,
                                              const struct quic_transport_params *p)
{
	int local = p == &qc->rx.params;

	chunk_appendf(b, "\n\toriginal_destination_connection_id:");
	quic_tp_cid_dump(b, &p->original_destination_connection_id);
	chunk_appendf(b, "\n\tinitial_source_connection_id:");
	quic_tp_cid_dump(b, &p->initial_source_connection_id);
	chunk_appendf(b, "\n\tretry_source_connection_id:");
	quic_tp_cid_dump(b, &p->retry_source_connection_id);

	chunk_appendf(b, "\n\tmax_idle_timeout=%llu", (ull)p->max_idle_timeout);
	chunk_appendf(b, "\n\tmax_udp_payload_size=%llu", (ull)p->max_udp_payload_size);
	chunk_appendf(b, "\n\tinitial_max_data=%llu", (ull)p->initial_max_data);
	chunk_appendf(b, "\n\tinitial_max_stream_data_bidi_local=%llu",
	              (ull)p->initial_max_stream_data_bidi_local);
	chunk_appendf(b, "\n\tinitial_max_stream_data_bidi_remote=%llu",
	              (ull)p->initial_max_stream_data_bidi_remote);
	chunk_appendf(b, "\n\tinitial_max_stream_data_uni=%llu",
	              (ull)p->initial_max_stream_data_uni);
	chunk_appendf(b, "\n\tinitial_max_streams_bidi=%llu", (ull)p->initial_max_streams_bidi);
	chunk_appendf(b, "\n\tinitial_max_streams_uni=%llu", (ull)p->initial_max_streams_uni);
	chunk_appendf(b, "\n\tack_delay_exponent=%llu", (ull)p->ack_delay_exponent);
	chunk_appendf(b, "\n\tmax_ack_delay=%llu", (ull)p->max_ack_delay);
	chunk_appendf(b, "\n\tactive_connection_id_limit=%llu", (ull)p->active_connection_id_limit);
	chunk_appendf(b, "\n\tdisable_active_migration? %s", p->disable_active_migration ? "yes" : "no");
	chunk_appendf(b, "\n\twith_stateless_reset_token? %s", p->with_stateless_reset_token ? "yes" : "no");
	chunk_appendf(b, "\n\twith_preferred_address? %s", p->with_preferred_address ? "yes" : "no");
	quic_tp_version_info_dump(b, &p->version_information, local);
}

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_TP_H */
