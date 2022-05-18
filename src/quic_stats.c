#include <haproxy/quic_stats-t.h>
#include <haproxy/stats.h>

enum {
	QUIC_ST_DROPPED_PACKETS,
	QUIC_ST_RETRY_SENT,
	QUIC_ST_RETRY_VALIDATED,
	QUIC_ST_RETRY_ERRORS,
	QUIC_ST_CONN_OPENINGS,
	QUIC_ST_HDSHK_FAILS,
	/* Stream related counters */
	QUIC_ST_DATA_BLOCKED,
	QUIC_ST_STREAM_DATA_BLOCKED,
	QUIC_ST_STREAMS_DATA_BLOCKED_BIDI,
	QUIC_ST_STREAMS_DATA_BLOCKED_UNI,
	QUIC_STATS_COUNT /* must be the last */
};

static struct name_desc quic_stats[] = {
	[QUIC_ST_DROPPED_PACKETS]     = { .name = "quic_dropped_pkt",
	                                  .desc = "Total number of dropped packets" },
	[QUIC_ST_RETRY_SENT]          = { .name = "quic_retry_sent",
	                                  .desc = "Total number of Retry sent" },
	[QUIC_ST_RETRY_VALIDATED]     = { .name = "quic_retry_validated",
	                                  .desc = "Total number of validated Retry tokens" },
	[QUIC_ST_RETRY_ERRORS]        = { .name = "quic_retry_error",
	                                  .desc = "Total number of Retry tokens errors" },
	[QUIC_ST_CONN_OPENINGS]       = { .name = "quic_conn_opening",
	                                  .desc = "Total number of connection openings" },
	[QUIC_ST_HDSHK_FAILS]         = { .name = "quic_hdshk_fail",
	                                  .desc = "Total number of handshake failures" },
	/* Streams related counters */
	[QUIC_ST_DATA_BLOCKED]              = { .name = "quic_data_blocked",
	                                        .desc = "Total number of times DATA_BLOCKED frame was received" },
	[QUIC_ST_STREAM_DATA_BLOCKED]       = { .name = "quic_stream_data_blocked",
	                                        .desc = "Total number of times STREAMS_BLOCKED frame was received" },
	[QUIC_ST_STREAMS_DATA_BLOCKED_BIDI] = { .name = "quic_streams_data_blocked_bidi",
	                                        .desc = "Total number of times STREAM_DATA_BLOCKED_BIDI frame was received" },
	[QUIC_ST_STREAMS_DATA_BLOCKED_UNI]  = { .name = "quic_streams_data_blocked_bidi",
	                                        .desc = "Total number of times STREAM_DATA_BLOCKED_UNI frame was received" },
};

struct quic_counters quic_counters;

static void quic_fill_stats(void *data, struct field *stats)
{
	struct quic_counters *counters = data;

	stats[QUIC_ST_DROPPED_PACKETS]   = mkf_u64(FN_COUNTER, counters->dropped_pkt);
	stats[QUIC_ST_RETRY_SENT]        = mkf_u64(FN_COUNTER, counters->retry_sent);
	stats[QUIC_ST_RETRY_VALIDATED]   = mkf_u64(FN_COUNTER, counters->retry_validated);
	stats[QUIC_ST_RETRY_ERRORS]      = mkf_u64(FN_COUNTER, counters->retry_error);
	stats[QUIC_ST_CONN_OPENINGS]     = mkf_u64(FN_GAUGE, counters->conn_opening);
	stats[QUIC_ST_HDSHK_FAILS]       = mkf_u64(FN_COUNTER, counters->hdshk_fail);
	/* Streams related counters */
	stats[QUIC_ST_DATA_BLOCKED]              = mkf_u64(FN_COUNTER, counters->data_blocked);
	stats[QUIC_ST_STREAM_DATA_BLOCKED]       = mkf_u64(FN_COUNTER, counters->stream_data_blocked);
	stats[QUIC_ST_STREAMS_DATA_BLOCKED_BIDI] = mkf_u64(FN_COUNTER, counters->streams_data_blocked_bidi);
	stats[QUIC_ST_STREAMS_DATA_BLOCKED_UNI]  = mkf_u64(FN_COUNTER, counters->streams_data_blocked_uni);
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
