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
                                 const struct quic_version *chosen_version,
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

	for (i = 0; i < cid->len; i++)
		chunk_appendf(buf, "%02x", cid->data[i]);
}

static inline void quic_tp_version_info_dump(struct buffer *b,
                                             const struct tp_version_information *tp, int local)
{
	if (!tp->chosen)
		return;

	chunk_appendf(b, "    version_information:(chosen=0x%08x", tp->chosen);
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
	}
	chunk_appendf(b, ")\n");
}

static inline void quic_transport_params_dump(struct buffer *b,
                                              const struct quic_conn *qc,
                                              const struct quic_transport_params *p)
{
	int local = p == &qc->rx.params;

	if (p->original_destination_connection_id.len) {
		chunk_appendf(b, " odcid=");
		quic_tp_cid_dump(b, &p->original_destination_connection_id);
	}
	chunk_appendf(b, " iscid=");
	quic_tp_cid_dump(b, &p->initial_source_connection_id);
	if (p->retry_source_connection_id.len) {
		chunk_appendf(b, "  rscid=");
		quic_tp_cid_dump(b, &p->retry_source_connection_id);
	}
	chunk_appendf(b, "\n");

	chunk_appendf(b, "    midle_timeout=%llums", (ull)p->max_idle_timeout);
	chunk_appendf(b, " mudp_payload_sz=%llu", (ull)p->max_udp_payload_size);
	chunk_appendf(b, " ack_delay_exp=%llu", (ull)p->ack_delay_exponent);
	chunk_appendf(b, " mack_delay=%llums", (ull)p->max_ack_delay);
	chunk_appendf(b, " act_cid_limit=%llu\n", (ull)p->active_connection_id_limit);

	chunk_appendf(b, "    md=%llu", (ull)p->initial_max_data);
	chunk_appendf(b, " msd_bidi_l=%llu",
	              (ull)p->initial_max_stream_data_bidi_local);
	chunk_appendf(b, " msd_bidi_r=%llu",
	              (ull)p->initial_max_stream_data_bidi_remote);
	chunk_appendf(b, " msd_uni=%llu",
	              (ull)p->initial_max_stream_data_uni);
	chunk_appendf(b, " ms_bidi=%llu", (ull)p->initial_max_streams_bidi);
	chunk_appendf(b, " ms_uni=%llu\n", (ull)p->initial_max_streams_uni);

	if (p->disable_active_migration || p->with_stateless_reset_token ||
	    p->with_preferred_address) {
		int prev = 0;

		chunk_appendf(b, "    (");
		if (p->disable_active_migration) {
			if (prev)
				chunk_appendf(b, ",");
			prev = 1;
			chunk_appendf(b, "no_act_migr");
		}
		if (p->with_stateless_reset_token) {
			if (prev)
				chunk_appendf(b, ",");
			prev = 1;
			chunk_appendf(b, "stless_rst_tok");
		}
		if (p->with_preferred_address) {
			if (prev)
				chunk_appendf(b, ",");
			prev = 1;
			chunk_appendf(b, "pref_addr");
		}
		chunk_appendf(b, ")\n");
	}

	quic_tp_version_info_dump(b, &p->version_information, local);
}

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_TP_H */
