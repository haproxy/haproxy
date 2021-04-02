/***
 * Copyright 2020 HAProxy Technologies
 *
 * This file is part of the HAProxy OpenTracing filter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef _OPENTRACING_EVENT_H_
#define _OPENTRACING_EVENT_H_

/*
 * This must be defined in order for macro FLT_OT_EVENT_DEFINES
 * and structure flt_ot_event_data to have the correct contents.
 */
#define AN_REQ_NONE                 0
#define AN_REQ_CLIENT_SESS_START    0
#define AN_REQ_SERVER_UNAVAILABLE   0
#define AN_REQ_CLIENT_SESS_END      0
#define AN_RES_SERVER_SESS_START    0
#define AN_RES_SERVER_SESS_END      0
#define SMP_VAL_FE_                 0
#define SMP_VAL_BE_                 0

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
 * FLT_OT_EVENT_NONE is used as an index for 'ot-scope' sections that do not
 * have an event defined.  The 'ot-scope' sections thus defined can be used
 * within the 'ot-group' section.
 *
 * A description of the macro arguments can be found in the structure
 * flt_ot_event_data definition
 */
#define FLT_OT_EVENT_DEFINES                                                                                \
	FLT_OT_EVENT_DEF(              NONE, REQ,        ,        , 0, "")                                  \
	FLT_OT_EVENT_DEF( CLIENT_SESS_START, REQ, CON_ACC,        , 1, "on-client-session-start")           \
	FLT_OT_EVENT_DEF(        INSPECT_FE, REQ, REQ_CNT,        , 1, "on-frontend-tcp-request")           \
	FLT_OT_EVENT_DEF(         WAIT_HTTP, REQ,        ,        , 1, "on-http-wait-request")              \
	FLT_OT_EVENT_DEF(         HTTP_BODY, REQ,        ,        , 1, "on-http-body-request")              \
	FLT_OT_EVENT_DEF(   HTTP_PROCESS_FE, REQ, HRQ_HDR,        , 1, "on-frontend-http-request")          \
	FLT_OT_EVENT_DEF(   SWITCHING_RULES, REQ,        ,        , 1, "on-switching-rules-request")        \
	FLT_OT_EVENT_DEF(        INSPECT_BE, REQ, REQ_CNT, REQ_CNT, 1, "on-backend-tcp-request")            \
	FLT_OT_EVENT_DEF(   HTTP_PROCESS_BE, REQ, HRQ_HDR, HRQ_HDR, 1, "on-backend-http-request")           \
/*	FLT_OT_EVENT_DEF(       HTTP_TARPIT, REQ,        ,        , 1, "on-http-tarpit-request") */         \
	FLT_OT_EVENT_DEF(         SRV_RULES, REQ,        ,        , 1, "on-process-server-rules-request")   \
	FLT_OT_EVENT_DEF(        HTTP_INNER, REQ,        ,        , 1, "on-http-process-request")           \
	FLT_OT_EVENT_DEF(   PRST_RDP_COOKIE, REQ,        ,        , 1, "on-tcp-rdp-cookie-request")         \
	FLT_OT_EVENT_DEF(    STICKING_RULES, REQ,        ,        , 1, "on-process-sticking-rules-request") \
	FLT_OT_EVENT_DEF(   CLIENT_SESS_END, REQ,        ,        , 0, "on-client-session-end")             \
	FLT_OT_EVENT_DEF(SERVER_UNAVAILABLE, REQ,        ,        , 0, "on-server-unavailable")             \
                                                                                                            \
	FLT_OT_EVENT_DEF( SERVER_SESS_START, RES,        , SRV_CON, 0, "on-server-session-start")           \
	FLT_OT_EVENT_DEF(           INSPECT, RES, RES_CNT, RES_CNT, 0, "on-tcp-response")                   \
	FLT_OT_EVENT_DEF(         WAIT_HTTP, RES,        ,        , 1, "on-http-wait-response")             \
	FLT_OT_EVENT_DEF(       STORE_RULES, RES,        ,        , 1, "on-process-store-rules-response")   \
	FLT_OT_EVENT_DEF(   HTTP_PROCESS_BE, RES, HRS_HDR, HRS_HDR, 1, "on-http-response")                  \
	FLT_OT_EVENT_DEF(   SERVER_SESS_END, RES,        ,        , 0, "on-server-session-end")

enum FLT_OT_EVENT_enum {
#define FLT_OT_EVENT_DEF(a,b,c,d,e,f)   FLT_OT_EVENT_##b##_##a,
	FLT_OT_EVENT_DEFINES
	FLT_OT_EVENT_MAX
#undef FLT_OT_EVENT_DEF
};

enum FLT_OT_EVENT_SAMPLE_enum {
	FLT_OT_EVENT_SAMPLE_TAG = 0,
	FLT_OT_EVENT_SAMPLE_LOG,
	FLT_OT_EVENT_SAMPLE_BAGGAGE,
};

struct flt_ot_event_data {
	uint        an_bit;           /* Used channel analyser. */
	uint        smp_opt_dir;      /* Fetch direction (request/response). */
	uint        smp_val_fe;       /* Valid FE fetch location. */
	uint        smp_val_be;       /* Valid BE fetch location. */
	bool        flag_http_inject; /* Span context injection allowed. */
	const char *name;             /* Filter event name. */
};

struct flt_ot_conf_scope;


extern const struct flt_ot_event_data flt_ot_event_data[FLT_OT_EVENT_MAX];


int flt_ot_scope_run(struct stream *s, struct filter *f, struct channel *chn, struct flt_ot_conf_scope *conf_scope, const struct timespec *ts, uint dir, char **err);
int flt_ot_event_run(struct stream *s, struct filter *f, struct channel *chn, int event, char **err);

#endif /* _OPENTRACING_EVENT_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
