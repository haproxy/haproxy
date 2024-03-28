#include <haproxy/quic_frame-t.h>
#include <haproxy/quic_stats-t.h>
#include <haproxy/stats.h>

static struct stat_col quic_stats[] = {
	[QUIC_ST_RXBUF_FULL]          = { .name = "quic_rxbuf_full",
	                                  .desc = "Total number of cancelled reception due to full receiver buffer" },
	[QUIC_ST_DROPPED_PACKET]      = { .name = "quic_dropped_pkt",
	                                  .desc = "Total number of dropped packets" },
	[QUIC_ST_DROPPED_PACKET_BUFOVERRUN] = { .name = "quic_dropped_pkt_bufoverrun",
	                                  .desc = "Total number of dropped packets because of buffer overrun" },
	[QUIC_ST_DROPPED_PARSING]     = { .name = "quic_dropped_parsing_pkt",
	                                  .desc = "Total number of dropped packets upon parsing error" },
	[QUIC_ST_SOCKET_FULL]         = { .name = "quic_socket_full",
	                                  .desc = "Total number of EAGAIN error on sendto() calls" },
	[QUIC_ST_SENDTO_ERR]          = { .name = "quic_sendto_err",
	                                  .desc = "Total number of error on sendto() calls, EAGAIN excepted" },
	[QUIC_ST_SENDTO_ERR_UNKNWN]   = { .name = "quic_sendto_err_unknwn",
	                                  .desc = "Total number of error on sendto() calls not explicitly listed" },
	[QUIC_ST_SENT_PACKET]         = { .name = "quic_sent_pkt",
	                                  .desc = "Total number of sent packets" },
	[QUIC_ST_LOST_PACKET]         = { .name = "quic_lost_pkt",
	                                  .desc = "Total number of lost sent packets" },
	[QUIC_ST_TOO_SHORT_INITIAL_DGRAM] = { .name = "quic_too_short_dgram",
	                                  .desc = "Total number of too short dgrams with Initial packets" },
	[QUIC_ST_RETRY_SENT]          = { .name = "quic_retry_sent",
	                                  .desc = "Total number of Retry sent" },
	[QUIC_ST_RETRY_VALIDATED]     = { .name = "quic_retry_validated",
	                                  .desc = "Total number of validated Retry tokens" },
	[QUIC_ST_RETRY_ERRORS]        = { .name = "quic_retry_error",
	                                  .desc = "Total number of Retry tokens errors" },
	[QUIC_ST_HALF_OPEN_CONN]      = { .name = "quic_half_open_conn",
	                                  .desc = "Total number of half open connections" },
	[QUIC_ST_HDSHK_FAIL]          = { .name = "quic_hdshk_fail",
	                                  .desc = "Total number of handshake failures" },
	[QUIC_ST_STATELESS_RESET_SENT] = { .name = "quic_stless_rst_sent",
	                                  .desc = "Total number of stateless reset packet sent" },
	/* Special events of interest */
	[QUIC_ST_CONN_MIGRATION_DONE] = { .name = "quic_conn_migration_done",
	                                  .desc = "Total number of connection migration proceeded" },
	/* Transport errors */
	[QUIC_ST_TRANSP_ERR_NO_ERROR] = { .name = "quic_transp_err_no_error",
	                                  .desc = "Total number of NO_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_INTERNAL_ERROR]     = { .name = "quic_transp_err_internal_error",
	                                            .desc = "Total number of INTERNAL_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_CONNECTION_REFUSED] = { .name = "quic_transp_err_connection_refused",
	                                            .desc = "Total number of CONNECTION_REFUSED errors received" },
	[QUIC_ST_TRANSP_ERR_FLOW_CONTROL_ERROR] = { .name = "quic_transp_err_flow_control_error",
	                                            .desc = "Total number of FLOW_CONTROL_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_STREAM_LIMIT_ERROR] = { .name = "quic_transp_err_stream_limit_error",
	                                            .desc = "Total number of STREAM_LIMIT_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_STREAM_STATE_ERROR] = { .name = "quic_transp_err_stream_state_error",
	                                            .desc = "Total number of STREAM_STATE_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_FINAL_SIZE_ERROR]   = { .name = "quic_transp_err_final_size_error",
	                                            .desc = "Total number of FINAL_SIZE_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_FRAME_ENCODING_ERROR]      = { .name = "quic_transp_err_frame_encoding_error",
	                                                   .desc = "Total number of FRAME_ENCODING_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_TRANSPORT_PARAMETER_ERROR] = { .name = "quic_transp_err_transport_parameter_error",
	                                                   .desc = "Total number of TRANSPORT_PARAMETER_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_CONNECTION_ID_LIMIT_ERROR] = { .name = "quic_transp_err_connection_id_limit",
	                                                   .desc = "Total number of CONNECTION_ID_LIMIT_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_PROTOCOL_VIOLATION]        = { .name = "quic_transp_err_protocol_violation_error",
	                                                   .desc = "Total number of PROTOCOL_VIOLATION errors received" },
	[QUIC_ST_TRANSP_ERR_INVALID_TOKEN]          = { .name = "quic_transp_err_invalid_token",
	                                                .desc = "Total number of INVALID_TOKEN errors received" },
	[QUIC_ST_TRANSP_ERR_APPLICATION_ERROR]      = { .name = "quic_transp_err_application_error",
	                                                .desc = "Total number of APPLICATION_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_CRYPTO_BUFFER_EXCEEDED] = { .name = "quic_transp_err_crypto_buffer_exceeded",
	                                                .desc = "Total number of CRYPTO_BUFFER_EXCEEDED errors received" },
	[QUIC_ST_TRANSP_ERR_KEY_UPDATE_ERROR]       = { .name = "quic_transp_err_key_update_error",
	                                                .desc = "Total number of KEY_UPDATE_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_AEAD_LIMIT_REACHED]     = { .name = "quic_transp_err_aead_limit_reached",
	                                                .desc = "Total number of AEAD_LIMIT_REACHED errors received" },
	[QUIC_ST_TRANSP_ERR_NO_VIABLE_PATH] = { .name = "quic_transp_err_no_viable_path",
	                                        .desc = "Total number of NO_VIABLE_PATH errors received" },
	[QUIC_ST_TRANSP_ERR_CRYPTO_ERROR]   = { .name = "quic_transp_err_crypto_error",
	                                        .desc = "Total number of CRYPTO_ERROR errors received" },
	[QUIC_ST_TRANSP_ERR_UNKNOWN_ERROR]  = { .name = "quic_transp_err_unknown_error",
	                                        .desc = "Total number of UNKNOWN_ERROR errors received" },
	/* Streams related counters */
	[QUIC_ST_DATA_BLOCKED]              = { .name = "quic_data_blocked",
	                                        .desc = "Total number of received DATA_BLOCKED frames" },
	[QUIC_ST_STREAM_DATA_BLOCKED]       = { .name = "quic_stream_data_blocked",
	                                        .desc = "Total number of received STREAM_DATA_BLOCKED frames" },
	[QUIC_ST_STREAMS_BLOCKED_BIDI]      = { .name = "quic_streams_blocked_bidi",
	                                        .desc = "Total number of received STREAMS_BLOCKED_BIDI frames" },
	[QUIC_ST_STREAMS_BLOCKED_UNI]       = { .name = "quic_streams_blocked_uni",
	                                        .desc = "Total number of received STREAMS_BLOCKED_UNI frames" },
};

struct quic_counters quic_counters;

static int quic_fill_stats(void *data, struct field *stats, unsigned int *selected_field)
{
	struct quic_counters *counters = data;
	unsigned int current_field = (selected_field != NULL ? *selected_field : 0);

	for (; current_field < QUIC_STATS_COUNT; current_field++) {
		struct field metric = { 0 };

		switch (current_field) {
		case QUIC_ST_RXBUF_FULL:
			metric = mkf_u64(FN_COUNTER, counters->rxbuf_full);
			break;
		case QUIC_ST_DROPPED_PACKET:
			metric = mkf_u64(FN_COUNTER, counters->dropped_pkt);
			break;
		case QUIC_ST_DROPPED_PACKET_BUFOVERRUN:
			metric = mkf_u64(FN_COUNTER, counters->dropped_pkt_bufoverrun);
			break;
		case QUIC_ST_DROPPED_PARSING:
			metric = mkf_u64(FN_COUNTER, counters->dropped_parsing);
			break;
		case QUIC_ST_SOCKET_FULL:
			metric = mkf_u64(FN_COUNTER, counters->socket_full);
			break;
		case QUIC_ST_SENDTO_ERR:
			metric = mkf_u64(FN_COUNTER, counters->sendto_err);
			break;
		case QUIC_ST_SENDTO_ERR_UNKNWN:
			metric = mkf_u64(FN_COUNTER, counters->sendto_err_unknown);
			break;
		case QUIC_ST_SENT_PACKET:
			metric = mkf_u64(FN_COUNTER, counters->sent_pkt);
			break;
		case QUIC_ST_LOST_PACKET:
			metric = mkf_u64(FN_COUNTER, counters->lost_pkt);
			break;
		case QUIC_ST_TOO_SHORT_INITIAL_DGRAM:
			metric = mkf_u64(FN_COUNTER, counters->too_short_initial_dgram);
			break;
		case QUIC_ST_RETRY_SENT:
			metric = mkf_u64(FN_COUNTER, counters->retry_sent);
			break;
		case QUIC_ST_RETRY_VALIDATED:
			metric = mkf_u64(FN_COUNTER, counters->retry_validated);
			break;
		case QUIC_ST_RETRY_ERRORS:
			metric = mkf_u64(FN_COUNTER, counters->retry_error);
			break;
		case QUIC_ST_HALF_OPEN_CONN:
			metric = mkf_u64(FN_GAUGE, counters->half_open_conn);
			break;
		case QUIC_ST_HDSHK_FAIL:
			metric = mkf_u64(FN_COUNTER, counters->hdshk_fail);
			break;
		case QUIC_ST_STATELESS_RESET_SENT:
			metric = mkf_u64(FN_COUNTER, counters->stateless_reset_sent);
			break;

		/* Special events of interest */
		case QUIC_ST_CONN_MIGRATION_DONE:
			metric = mkf_u64(FN_COUNTER, counters->conn_migration_done);
			break;

		/* Transport errors */
		case QUIC_ST_TRANSP_ERR_NO_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_no_error);
			break;
		case QUIC_ST_TRANSP_ERR_INTERNAL_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_internal_error);
			break;
		case QUIC_ST_TRANSP_ERR_CONNECTION_REFUSED:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_connection_refused);
			break;
		case QUIC_ST_TRANSP_ERR_FLOW_CONTROL_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_flow_control_error);
			break;
		case QUIC_ST_TRANSP_ERR_STREAM_LIMIT_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_stream_limit_error);
			break;
		case QUIC_ST_TRANSP_ERR_STREAM_STATE_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_stream_state_error);
			break;
		case QUIC_ST_TRANSP_ERR_FINAL_SIZE_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_final_size_error);
			break;
		case QUIC_ST_TRANSP_ERR_FRAME_ENCODING_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_frame_encoding_error);
			break;
		case QUIC_ST_TRANSP_ERR_TRANSPORT_PARAMETER_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_transport_parameter_error);
			break;
		case QUIC_ST_TRANSP_ERR_CONNECTION_ID_LIMIT_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_connection_id_limit);
			break;
		case QUIC_ST_TRANSP_ERR_PROTOCOL_VIOLATION:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_protocol_violation);
			break;
		case QUIC_ST_TRANSP_ERR_INVALID_TOKEN:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_invalid_token);
			break;
		case QUIC_ST_TRANSP_ERR_APPLICATION_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_application_error);
			break;
		case QUIC_ST_TRANSP_ERR_CRYPTO_BUFFER_EXCEEDED:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_crypto_buffer_exceeded);
			break;
		case QUIC_ST_TRANSP_ERR_KEY_UPDATE_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_key_update_error);
			break;
		case QUIC_ST_TRANSP_ERR_AEAD_LIMIT_REACHED:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_aead_limit_reached);
			break;
		case QUIC_ST_TRANSP_ERR_NO_VIABLE_PATH:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_no_viable_path);
			break;
		case QUIC_ST_TRANSP_ERR_CRYPTO_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_crypto_error);
			break;
		case QUIC_ST_TRANSP_ERR_UNKNOWN_ERROR:
			metric = mkf_u64(FN_COUNTER, counters->quic_transp_err_unknown_error);
			break;

		/* Streams related counters */
		case QUIC_ST_DATA_BLOCKED:
			metric = mkf_u64(FN_COUNTER, counters->data_blocked);
			break;
		case QUIC_ST_STREAM_DATA_BLOCKED:
			metric = mkf_u64(FN_COUNTER, counters->stream_data_blocked);
			break;
		case QUIC_ST_STREAMS_BLOCKED_BIDI:
			metric = mkf_u64(FN_COUNTER, counters->streams_blocked_bidi);
			break;
		case QUIC_ST_STREAMS_BLOCKED_UNI:
			metric = mkf_u64(FN_COUNTER, counters->streams_blocked_uni);
			break;
		default:
			/* not used for frontends. If a specific metric
			 * is requested, return an error. Otherwise continue.
			 */
			if (selected_field != NULL)
				return 0;
			continue;
		}
		stats[current_field] = metric;
		if (selected_field != NULL)
			break;
	}
	return 1;
}

struct stats_module quic_stats_module = {
	.name          = "quic",
	.fill_stats    = quic_fill_stats,
	.stats         = quic_stats,
	.stats_count   = QUIC_STATS_COUNT,
	.counters      = &quic_counters,
	.counters_size = sizeof(quic_counters),
	.domain_flags  = MK_STATS_PROXY_DOMAIN(STATS_PX_CAP_FE),
	.clearable     = 1,
};

INITCALL1(STG_REGISTER, stats_register_module, &quic_stats_module);

void quic_stats_transp_err_count_inc(struct quic_counters *ctrs, int error_code)
{
	switch (error_code) {
	case QC_ERR_NO_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_no_error);
		break;
	case QC_ERR_INTERNAL_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_internal_error);
		break;
	case QC_ERR_CONNECTION_REFUSED:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_connection_refused);
		break;
	case QC_ERR_FLOW_CONTROL_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_flow_control_error);
		break;
	case QC_ERR_STREAM_LIMIT_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_stream_limit_error);
		break;
	case QC_ERR_STREAM_STATE_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_stream_state_error);
		break;
	case QC_ERR_FINAL_SIZE_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_final_size_error);
		break;
	case QC_ERR_FRAME_ENCODING_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_frame_encoding_error);
		break;
	case QC_ERR_TRANSPORT_PARAMETER_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_transport_parameter_error);
		break;
	case QC_ERR_CONNECTION_ID_LIMIT_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_connection_id_limit);
		break;
	case QC_ERR_PROTOCOL_VIOLATION:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_protocol_violation);
		break;
	case QC_ERR_INVALID_TOKEN:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_invalid_token);
		break;
	case QC_ERR_APPLICATION_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_application_error);
		break;
	case QC_ERR_CRYPTO_BUFFER_EXCEEDED:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_crypto_buffer_exceeded);
		break;
	case QC_ERR_KEY_UPDATE_ERROR:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_key_update_error);
		break;
	case QC_ERR_AEAD_LIMIT_REACHED:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_aead_limit_reached);
		break;
	case QC_ERR_NO_VIABLE_PATH:
		HA_ATOMIC_INC(&ctrs->quic_transp_err_no_viable_path);
		break;
	default:
		if (error_code >= 0x100 && error_code <= 0x1ff)
			HA_ATOMIC_INC(&ctrs->quic_transp_err_crypto_error);
		else
			HA_ATOMIC_INC(&ctrs->quic_transp_err_unknown_error);
	}
}
