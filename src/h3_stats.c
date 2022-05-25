#include <haproxy/h3.h>
#include <haproxy/stats.h>

enum {
	/* h3 frame type counters */
	H3_ST_DATA,
	H3_ST_HEADERS,
	H3_ST_CANCEL_PUSH,
	H3_ST_PUSH_PROMISE,
	H3_ST_MAX_PUSH_ID,
	H3_ST_GOAWAY,
	H3_ST_SETTINGS,
	/* h3 error counters */
	H3_ST_H3_NO_ERROR,
	H3_ST_H3_GENERAL_PROTOCOL_ERROR,
	H3_ST_H3_INTERNAL_ERROR,
	H3_ST_H3_STREAM_CREATION_ERROR,
	H3_ST_H3_CLOSED_CRITICAL_STREAM,
	H3_ST_H3_FRAME_UNEXPECTED,
	H3_ST_H3_FRAME_ERROR,
	H3_ST_H3_EXCESSIVE_LOAD,
	H3_ST_H3_ID_ERROR,
	H3_ST_H3_SETTINGS_ERROR,
	H3_ST_H3_MISSING_SETTINGS,
	H3_ST_H3_REQUEST_REJECTED,
	H3_ST_H3_REQUEST_CANCELLED,
	H3_ST_H3_REQUEST_INCOMPLETE,
	H3_ST_H3_MESSAGE_ERROR,
	H3_ST_H3_CONNECT_ERROR,
	H3_ST_H3_VERSION_FALLBACK,
	/* QPACK error counters */
	H3_ST_QPACK_DECOMPRESSION_FAILED,
	H3_ST_QPACK_ENCODER_STREAM_ERROR,
	H3_ST_QPACK_DECODER_STREAM_ERROR,
	H3_STATS_COUNT /* must be the last */
};

static struct name_desc h3_stats[] = {
	/* h3 frame type counters */
	[H3_ST_DATA]         = { .name = "h3_data",
	                         .desc = "Total number of DATA frames received" },
	[H3_ST_HEADERS]      = { .name = "h3_headers",
	                         .desc = "Total number of HEADERS frames received" },
	[H3_ST_CANCEL_PUSH]  = { .name = "h3_cancel_push",
	                         .desc = "Total number of CANCEL_PUSH frames received" },
	[H3_ST_PUSH_PROMISE] = { .name = "h3_push_promise",
	                         .desc = "Total number of PUSH_PROMISE frames received" },
	[H3_ST_MAX_PUSH_ID]  = { .name = "h3_max_push_id",
	                         .desc = "Total number of MAX_PUSH_ID frames received" },
	[H3_ST_GOAWAY]       = { .name = "h3_goaway",
	                         .desc = "Total number of GOAWAY frames received" },
	[H3_ST_SETTINGS]     = { .name = "h3_settings",
	                         .desc = "Total number of SETTINGS frames received" },
	/* h3 error counters */
	[H3_ST_H3_NO_ERROR]                = { .name = "h3_no_error",
	                                       .desc = "Total number of H3_NO_ERROR errors received" },
	[H3_ST_H3_GENERAL_PROTOCOL_ERROR]  = { .name = "h3_general_protocol_error",
	                                       .desc = "Total number of H3_GENERAL_PROTOCOL_ERROR errors received" },
	[H3_ST_H3_INTERNAL_ERROR]          = { .name = "h3_internal_error",
	                                       .desc = "Total number of H3_INTERNAL_ERROR errors received" },
	[H3_ST_H3_STREAM_CREATION_ERROR]   = { .name = "h3_stream_creation_error",
	                                       .desc = "Total number of H3_STREAM_CREATION_ERROR errors received" },
	[H3_ST_H3_CLOSED_CRITICAL_STREAM]  = { .name = "h3_closed_critical_stream",
	                                       .desc = "Total number of H3_CLOSED_CRITICAL_STREAM errors received" },
	[H3_ST_H3_FRAME_UNEXPECTED]        = { .name = "h3_frame_unexpected",
	                                       .desc = "Total number of H3_FRAME_UNEXPECTED errors received" },
	[H3_ST_H3_FRAME_ERROR]             = { .name = "h3_frame_error",
	                                       .desc = "Total number of H3_FRAME_ERROR errors received" },
	[H3_ST_H3_EXCESSIVE_LOAD]          = { .name = "h3_excessive_load",
	                                       .desc = "Total number of H3_EXCESSIVE_LOAD errors received" },
	[H3_ST_H3_ID_ERROR]                = { .name = "h3_id_error",
	                                       .desc = "Total number of H3_ID_ERROR errors received" },
	[H3_ST_H3_SETTINGS_ERROR]          = { .name = "h3_settings_error",
	                                       .desc = "Total number of H3_SETTINGS_ERROR errors received" },
	[H3_ST_H3_MISSING_SETTINGS]        = { .name = "h3_missing_settings",
	                                       .desc = "Total number of H3_MISSING_SETTINGS errors received" },
	[H3_ST_H3_REQUEST_REJECTED]        = { .name = "h3_request_rejected",
	                                       .desc = "Total number of H3_REQUEST_REJECTED errors received" },
	[H3_ST_H3_REQUEST_CANCELLED]       = { .name = "h3_request_cancelled",
	                                       .desc = "Total number of H3_REQUEST_CANCELLED errors received" },
	[H3_ST_H3_REQUEST_INCOMPLETE]      = { .name = "h3_request_incomplete",
	                                       .desc = "Total number of H3_REQUEST_INCOMPLETE errors received" },
	[H3_ST_H3_MESSAGE_ERROR]           = { .name = "h3_message_error",
	                                       .desc = "Total number of H3_MESSAGE_ERROR errors received" },
	[H3_ST_H3_CONNECT_ERROR]           = { .name = "h3_connect_error",
	                                       .desc = "Total number of H3_CONNECT_ERROR errors received" },
	[H3_ST_H3_VERSION_FALLBACK]        = { .name = "h3_version_fallback",
	                                       .desc = "Total number of H3_VERSION_FALLBACK errors received" },
	/* QPACK error counters */
	[H3_ST_QPACK_DECOMPRESSION_FAILED] = { .name = "pack_decompression_failed",
	                                       .desc = "Total number of QPACK_DECOMPRESSION_FAILED errors received" },
	[H3_ST_QPACK_ENCODER_STREAM_ERROR] = { .name = "qpack_encoder_stream_error",
	                                       .desc = "Total number of QPACK_ENCODER_STREAM_ERROR errors received" },
	[H3_ST_QPACK_DECODER_STREAM_ERROR] = { .name = "qpack_decoder_stream_error",
	                                       .desc = "Total number of QPACK_DECODER_STREAM_ERROR errors received" },
};

static struct h3_counters {
	/* h3 frame type counters */
	long long h3_data;         /* total number of DATA frames received */
	long long h3_headers;      /* total number of HEADERS frames received */
	long long h3_cancel_push;  /* total number of CANCEL_PUSH frames received */
	long long h3_push_promise; /* total number of PUSH_PROMISE frames received */
	long long h3_max_push_id;  /* total number of MAX_PUSH_ID frames received */
	long long h3_goaway;       /* total number of GOAWAY frames received */
	long long h3_settings;      /* total number of SETTINGS frames received */
	/* h3 error counters */
	long long h3_no_error;                /* total number of H3_NO_ERROR errors received */
	long long h3_general_protocol_error;  /* total number of H3_GENERAL_PROTOCOL_ERROR errors received */
	long long h3_internal_error;          /* total number of H3_INTERNAL_ERROR errors received */
	long long h3_stream_creation_error;   /* total number of H3_STREAM_CREATION_ERROR errors received */
	long long h3_closed_critical_stream;  /* total number of H3_CLOSED_CRITICAL_STREAM errors received */
	long long h3_frame_unexpected;        /* total number of H3_FRAME_UNEXPECTED errors received */
	long long h3_frame_error;             /* total number of H3_FRAME_ERROR errors received */
	long long h3_excessive_load;          /* total number of H3_EXCESSIVE_LOAD errors received */
	long long h3_id_error;                /* total number of H3_ID_ERROR errors received */
	long long h3_settings_error;          /* total number of H3_SETTINGS_ERROR errors received */
	long long h3_missing_settings;        /* total number of H3_MISSING_SETTINGS errors received */
	long long h3_request_rejected;        /* total number of H3_REQUEST_REJECTED errors received */
	long long h3_request_cancelled;       /* total number of H3_REQUEST_CANCELLED errors received */
	long long h3_request_incomplete;      /* total number of H3_REQUEST_INCOMPLETE errors received */
	long long h3_message_error;           /* total number of H3_MESSAGE_ERROR errors received */
	long long h3_connect_error;           /* total number of H3_CONNECT_ERROR errors received */
	long long h3_version_fallback;        /* total number of H3_VERSION_FALLBACK errors received */
	/* QPACK error counters */
	long long qpack_decompression_failed; /* total number of QPACK_DECOMPRESSION_FAILED errors received */
	long long qpack_encoder_stream_error; /* total number of QPACK_ENCODER_STREAM_ERROR errors received */
	long long qpack_decoder_stream_error; /* total number of QPACK_DECODER_STREAM_ERROR errors received */
} h3_counters;

static void h3_fill_stats(void *data, struct field *stats)
{
	struct h3_counters *counters = data;

	/* h3 frame type counters */
	stats[H3_ST_DATA]         = mkf_u64(FN_COUNTER, counters->h3_data);
	stats[H3_ST_HEADERS]      = mkf_u64(FN_COUNTER, counters->h3_headers);
	stats[H3_ST_CANCEL_PUSH]  = mkf_u64(FN_COUNTER, counters->h3_cancel_push);
	stats[H3_ST_PUSH_PROMISE] = mkf_u64(FN_COUNTER, counters->h3_push_promise);
	stats[H3_ST_MAX_PUSH_ID]  = mkf_u64(FN_COUNTER, counters->h3_max_push_id);
	stats[H3_ST_GOAWAY]       = mkf_u64(FN_COUNTER, counters->h3_goaway);
	stats[H3_ST_SETTINGS]     = mkf_u64(FN_COUNTER, counters->h3_settings);
	/* h3 error counters */
	stats[H3_ST_H3_NO_ERROR]               = mkf_u64(FN_COUNTER, counters->h3_no_error);
	stats[H3_ST_H3_GENERAL_PROTOCOL_ERROR] = mkf_u64(FN_COUNTER, counters->h3_general_protocol_error);
	stats[H3_ST_H3_INTERNAL_ERROR]         = mkf_u64(FN_COUNTER, counters->h3_internal_error);
	stats[H3_ST_H3_STREAM_CREATION_ERROR]  = mkf_u64(FN_COUNTER, counters->h3_stream_creation_error);
	stats[H3_ST_H3_CLOSED_CRITICAL_STREAM] = mkf_u64(FN_COUNTER, counters->h3_closed_critical_stream);
	stats[H3_ST_H3_FRAME_UNEXPECTED]       = mkf_u64(FN_COUNTER, counters->h3_frame_unexpected);
	stats[H3_ST_H3_FRAME_ERROR]            = mkf_u64(FN_COUNTER, counters->h3_frame_error);
	stats[H3_ST_H3_EXCESSIVE_LOAD]         = mkf_u64(FN_COUNTER, counters->h3_excessive_load);
	stats[H3_ST_H3_ID_ERROR]               = mkf_u64(FN_COUNTER, counters->h3_id_error);
	stats[H3_ST_H3_SETTINGS_ERROR]         = mkf_u64(FN_COUNTER, counters->h3_settings_error);
	stats[H3_ST_H3_MISSING_SETTINGS]       = mkf_u64(FN_COUNTER, counters->h3_missing_settings);
	stats[H3_ST_H3_REQUEST_REJECTED]       = mkf_u64(FN_COUNTER, counters->h3_request_rejected);
	stats[H3_ST_H3_REQUEST_CANCELLED]      = mkf_u64(FN_COUNTER, counters->h3_request_cancelled);
	stats[H3_ST_H3_REQUEST_INCOMPLETE]     = mkf_u64(FN_COUNTER, counters->h3_request_incomplete);
	stats[H3_ST_H3_MESSAGE_ERROR]          = mkf_u64(FN_COUNTER, counters->h3_message_error);
	stats[H3_ST_H3_CONNECT_ERROR]          = mkf_u64(FN_COUNTER, counters->h3_connect_error);
	stats[H3_ST_H3_VERSION_FALLBACK]       = mkf_u64(FN_COUNTER, counters->h3_version_fallback);
	/* QPACK error counters */
	stats[H3_ST_QPACK_DECOMPRESSION_FAILED] = mkf_u64(FN_COUNTER, counters->qpack_decompression_failed);
	stats[H3_ST_QPACK_ENCODER_STREAM_ERROR] = mkf_u64(FN_COUNTER, counters->qpack_encoder_stream_error);
	stats[H3_ST_QPACK_DECODER_STREAM_ERROR] = mkf_u64(FN_COUNTER, counters->qpack_decoder_stream_error);
}

struct stats_module h3_stats_module = {
	.name          = "h3",
	.fill_stats    = h3_fill_stats,
	.stats         = h3_stats,
	.stats_count   = H3_STATS_COUNT,
	.counters      = &h3_counters,
	.counters_size = sizeof(h3_counters),
	.domain_flags  = MK_STATS_PROXY_DOMAIN(STATS_PX_CAP_FE),
	.clearable     = 1,
};

INITCALL1(STG_REGISTER, stats_register_module, &h3_stats_module);

void h3_inc_err_cnt(struct h3_counters *ctrs, int error_code)
{
	switch (error_code) {
	case H3_NO_ERROR:
		HA_ATOMIC_INC(&ctrs->h3_no_error);
		break;
	case H3_GENERAL_PROTOCOL_ERROR:
		HA_ATOMIC_INC(&ctrs->h3_general_protocol_error);
		break;
	case H3_INTERNAL_ERROR:
		HA_ATOMIC_INC(&ctrs->h3_internal_error);
		break;
	case H3_STREAM_CREATION_ERROR:
		HA_ATOMIC_INC(&ctrs->h3_stream_creation_error);
		break;
	case H3_CLOSED_CRITICAL_STREAM:
		HA_ATOMIC_INC(&ctrs->h3_closed_critical_stream);
		break;
	case H3_FRAME_UNEXPECTED:
		HA_ATOMIC_INC(&ctrs->h3_frame_unexpected);
		break;
	case H3_FRAME_ERROR:
		HA_ATOMIC_INC(&ctrs->h3_frame_error);
		break;
	case H3_EXCESSIVE_LOAD:
		HA_ATOMIC_INC(&ctrs->h3_excessive_load);
		break;
	case H3_ID_ERROR:
		HA_ATOMIC_INC(&ctrs->h3_id_error);
		break;
	case H3_SETTINGS_ERROR:
		HA_ATOMIC_INC(&ctrs->h3_settings_error);
		break;
	case H3_MISSING_SETTINGS:
		HA_ATOMIC_INC(&ctrs->h3_missing_settings);
		break;
	case H3_REQUEST_REJECTED:
		HA_ATOMIC_INC(&ctrs->h3_request_rejected);
		break;
	case H3_REQUEST_CANCELLED:
		HA_ATOMIC_INC(&ctrs->h3_request_cancelled);
		break;
	case H3_REQUEST_INCOMPLETE:
		HA_ATOMIC_INC(&ctrs->h3_request_incomplete);
		break;
	case H3_MESSAGE_ERROR:
		HA_ATOMIC_INC(&ctrs->h3_message_error);
		break;
	case H3_CONNECT_ERROR:
		HA_ATOMIC_INC(&ctrs->h3_connect_error);
		break;
	case H3_VERSION_FALLBACK:
		HA_ATOMIC_INC(&ctrs->h3_version_fallback);
		break;
	case QPACK_DECOMPRESSION_FAILED:
		HA_ATOMIC_INC(&ctrs->qpack_decompression_failed);
		break;
	case QPACK_ENCODER_STREAM_ERROR:
		HA_ATOMIC_INC(&ctrs->qpack_encoder_stream_error);
		break;
	case QPACK_DECODER_STREAM_ERROR:
		HA_ATOMIC_INC(&ctrs->qpack_decoder_stream_error);
		break;
	default:
		break;

	}
}

void h3_inc_frame_type_cnt(struct h3_counters *ctrs, int frm_type)
{
	switch (frm_type) {
	case H3_FT_DATA:
		HA_ATOMIC_INC(&ctrs->h3_data);
		break;
	case H3_FT_HEADERS:
		HA_ATOMIC_INC(&ctrs->h3_headers);
		break;
	case H3_FT_CANCEL_PUSH:
		HA_ATOMIC_INC(&ctrs->h3_cancel_push);
		break;
	case H3_FT_PUSH_PROMISE:
		HA_ATOMIC_INC(&ctrs->h3_push_promise);
		break;
	case H3_FT_MAX_PUSH_ID:
		HA_ATOMIC_INC(&ctrs->h3_max_push_id);
		break;
	case H3_FT_GOAWAY:
		HA_ATOMIC_INC(&ctrs->h3_goaway);
		break;
	case H3_FT_SETTINGS:
		HA_ATOMIC_INC(&ctrs->h3_settings);
		break;
	default:
		break;
	}
}
