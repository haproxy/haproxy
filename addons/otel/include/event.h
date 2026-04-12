/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_EVENT_H_
#define _OTEL_EVENT_H_

/*
 * This must be defined in order for macro FLT_OTEL_EVENT_DEFINES
 * and structure flt_otel_event_data to have the correct contents.
 */
#define AN__NONE                    0
#define AN__STREAM_START            0     /* on-stream-start */
#define AN__STREAM_STOP             0     /* on-stream-stop */
#define AN__IDLE_TIMEOUT            0     /* on-idle-timeout */
#define AN__BACKEND_SET             0     /* on-backend-set */
#define AN_REQ_HTTP_HEADERS         0     /* on-http-headers-request */
#define AN_RES_HTTP_HEADERS         0     /* on-http-headers-response */
#define AN_REQ_HTTP_END             0     /* on-http-end-request */
#define AN_RES_HTTP_END             0     /* on-http-end-response */
#define AN_RES_HTTP_REPLY           0     /* on-http-reply */
#define AN_REQ_CLIENT_SESS_START    0
#define AN_REQ_SERVER_UNAVAILABLE   0
#define AN_REQ_CLIENT_SESS_END      0
#define AN_RES_SERVER_SESS_START    0
#define AN_RES_SERVER_SESS_END      0
#define SMP_VAL_FE_                 0
#define SMP_VAL_BE_                 0
#define SMP_OPT_DIR_                0xff

/*
 * Event names are selected to be somewhat compatible with the SPOE filter,
 * from which the following names are taken:
 *   - on-client-session -> on-client-session-start
 *   - on-frontend-tcp-request
 *   - on-frontend-http-request
 *   - on-backend-tcp-request
 *   - on-backend-http-request
 *   - on-server-session -> on-server-session-start
 *   - on-tcp-response
 *   - on-http-response
 *
 * FLT_OTEL_EVENT_NONE is used as an index for 'otel-scope' sections that do not
 * have an event defined.  The 'otel-scope' sections thus defined can be used
 * within the 'otel-group' section.
 *
 * A description of the macro arguments can be found in the structure
 * flt_otel_event_data definition.
 *
 * The following table is derived from the definitions AN_REQ_* and AN_RES_*
 * found in the HAProxy include file include/haproxy/channel-t.h.
 */
#define FLT_OTEL_EVENT_DEFINES                                                                                \
	/* Stream lifecycle pseudo-events (an_bit = 0, not tied to a channel analyzer) */                     \
	FLT_OTEL_EVENT_DEF(              NONE,    ,        ,        , 0, "")                                  \
	FLT_OTEL_EVENT_DEF(      STREAM_START,    ,        ,        , 0, "on-stream-start")                   \
	FLT_OTEL_EVENT_DEF(       STREAM_STOP,    ,        ,        , 0, "on-stream-stop")                    \
	FLT_OTEL_EVENT_DEF( CLIENT_SESS_START, REQ, CON_ACC,        , 1, "on-client-session-start")           \
	FLT_OTEL_EVENT_DEF(      IDLE_TIMEOUT,    ,        ,        , 0, "on-idle-timeout")                   \
	FLT_OTEL_EVENT_DEF(       BACKEND_SET,    ,        ,        , 0, "on-backend-set")                    \
	                                                                                                      \
	/* Request analyzers */                                                                               \
/*	FLT_OTEL_EVENT_DEF(      FLT_START_FE, REQ,        ,        ,  , "on-filter-start") */                \
	FLT_OTEL_EVENT_DEF(        INSPECT_FE, REQ, REQ_CNT,        , 1, "on-frontend-tcp-request")           \
	FLT_OTEL_EVENT_DEF(         WAIT_HTTP, REQ,        ,        , 1, "on-http-wait-request")              \
	FLT_OTEL_EVENT_DEF(         HTTP_BODY, REQ,        ,        , 1, "on-http-body-request")              \
	FLT_OTEL_EVENT_DEF(   HTTP_PROCESS_FE, REQ, HRQ_HDR,        , 1, "on-frontend-http-request")          \
	FLT_OTEL_EVENT_DEF(   SWITCHING_RULES, REQ,        ,        , 1, "on-switching-rules-request")        \
/*	FLT_OTEL_EVENT_DEF(      FLT_START_BE, REQ,        ,        ,  , "") */                               \
	FLT_OTEL_EVENT_DEF(        INSPECT_BE, REQ, REQ_CNT, REQ_CNT, 1, "on-backend-tcp-request")            \
	FLT_OTEL_EVENT_DEF(   HTTP_PROCESS_BE, REQ, HRQ_HDR, HRQ_HDR, 1, "on-backend-http-request")           \
/*	FLT_OTEL_EVENT_DEF(       HTTP_TARPIT, REQ,        ,        , 1, "on-http-tarpit-request") */         \
	FLT_OTEL_EVENT_DEF(         SRV_RULES, REQ,        ,        , 1, "on-process-server-rules-request")   \
	FLT_OTEL_EVENT_DEF(        HTTP_INNER, REQ,        ,        , 1, "on-http-process-request")           \
	FLT_OTEL_EVENT_DEF(   PRST_RDP_COOKIE, REQ,        ,        , 1, "on-tcp-rdp-cookie-request")         \
	FLT_OTEL_EVENT_DEF(    STICKING_RULES, REQ,        ,        , 1, "on-process-sticking-rules-request") \
/*	FLT_OTEL_EVENT_DEF(     FLT_HTTP_HDRS, REQ,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(    HTTP_XFER_BODY, REQ,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(          WAIT_CLI, REQ,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(     FLT_XFER_DATA, REQ,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(           FLT_END, REQ,        ,        ,  , "") */                               \
	FLT_OTEL_EVENT_DEF(      HTTP_HEADERS, REQ, HRQ_HDR, HRQ_HDR, 1, "on-http-headers-request")           \
	FLT_OTEL_EVENT_DEF(          HTTP_END, REQ,        ,        , 1, "on-http-end-request")               \
	FLT_OTEL_EVENT_DEF(   CLIENT_SESS_END, REQ,        ,        , 0, "on-client-session-end")             \
	FLT_OTEL_EVENT_DEF(SERVER_UNAVAILABLE, REQ,        ,        , 0, "on-server-unavailable")             \
	                                                                                                      \
	/* Response analyzers */                                                                              \
	FLT_OTEL_EVENT_DEF( SERVER_SESS_START, RES,        , SRV_CON, 0, "on-server-session-start")           \
/*	FLT_OTEL_EVENT_DEF(      FLT_START_FE, RES,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(      FLT_START_BE, RES,        ,        ,  , "") */                               \
	FLT_OTEL_EVENT_DEF(           INSPECT, RES, RES_CNT, RES_CNT, 0, "on-tcp-response")                   \
	FLT_OTEL_EVENT_DEF(         WAIT_HTTP, RES,        ,        , 1, "on-http-wait-response")             \
	FLT_OTEL_EVENT_DEF(       STORE_RULES, RES,        ,        , 1, "on-process-store-rules-response")   \
	FLT_OTEL_EVENT_DEF(   HTTP_PROCESS_BE, RES, HRS_HDR, HRS_HDR, 1, "on-http-response")                  \
	FLT_OTEL_EVENT_DEF(      HTTP_HEADERS, RES, HRS_HDR, HRS_HDR, 1, "on-http-headers-response")          \
	FLT_OTEL_EVENT_DEF(          HTTP_END, RES,        ,        , 0, "on-http-end-response")              \
	FLT_OTEL_EVENT_DEF(        HTTP_REPLY, RES,        ,        , 0, "on-http-reply")                     \
/*	FLT_OTEL_EVENT_DEF(   HTTP_PROCESS_FE, RES,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(     FLT_HTTP_HDRS, RES,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(    HTTP_XFER_BODY, RES,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(          WAIT_CLI, RES,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(     FLT_XFER_DATA, RES,        ,        ,  , "") */                               \
/*	FLT_OTEL_EVENT_DEF(           FLT_END, RES,        ,        ,  , "") */                               \
	FLT_OTEL_EVENT_DEF(   SERVER_SESS_END, RES,        ,        , 0, "on-server-session-end")

enum FLT_OTEL_EVENT_enum {
#define FLT_OTEL_EVENT_DEF(a,b,c,d,e,f)   FLT_OTEL_EVENT_##b##_##a,
	FLT_OTEL_EVENT_DEFINES
	FLT_OTEL_EVENT_MAX
#undef FLT_OTEL_EVENT_DEF
};

/* Per-event metadata mapping analyzer bits to filter event names. */
struct flt_otel_event_data {
	uint        an_bit;           /* Used channel analyser. */
	const char *an_name;          /* Channel analyser name. */
	uint        smp_opt_dir;      /* Fetch direction (request/response). */
	uint        smp_val_fe;       /* Valid FE fetch location. */
	uint        smp_val_be;       /* Valid BE fetch location. */
	bool        flag_http_inject; /* Span context injection allowed. */
	const char *name;             /* Filter event name. */
};


/* Per-event metadata table indexed by FLT_OTEL_EVENT_* constants. */
extern const struct flt_otel_event_data flt_otel_event_data[FLT_OTEL_EVENT_MAX];

#endif /* _OTEL_EVENT_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
