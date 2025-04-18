/*
 * SSL traces
 *
 * Copyright 2000-2025
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <inttypes.h>

#include <haproxy/api-t.h>
#include <haproxy/chunk.h>
#include <haproxy/trace.h>
#include <haproxy/ssl_trace-t.h>
#include <haproxy/connection.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_sock-t.h>
#include <haproxy/ssl_utils.h>

static void ssl_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                       const struct ist where, const struct ist func,
                       const void *a1, const void *a2, const void *a3, const void *a4);

static const struct trace_event ssl_trace_events[] = {
	{ .mask = SSL_EV_CONN_NEW,            .name = "sslc_new",            .desc = "new SSL connection" },
	{ .mask = SSL_EV_CONN_CLOSE,          .name = "sslc_close",          .desc = "close SSL connection" },
	{ .mask = SSL_EV_CONN_END,            .name = "sslc_end",            .desc = "SSL connection end" },
	{ .mask = SSL_EV_CONN_ERR,            .name = "sslc_err",            .desc = "SSL error"},
	{ .mask = SSL_EV_CONN_SEND,           .name = "sslc_send",           .desc = "Tx on SSL connection" },
	{ .mask = SSL_EV_CONN_SEND_EARLY,     .name = "sslc_send_early",     .desc = "Tx on SSL connection (early data)" },
	{ .mask = SSL_EV_CONN_RECV,           .name = "sslc_recv",           .desc = "Rx on SSL connection" },
	{ .mask = SSL_EV_CONN_RECV_EARLY,     .name = "sslc_recv_early",     .desc = "Rx on SSL connection (early data)" },
	{ }
};


static const struct name_desc ssl_trace_lockon_args[4] = {
	/* arg1 */ { /* already used by the connection */ },
	/* arg2 */ { },
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct name_desc ssl_trace_decoding[] = {
#define SSL_VERB_CLEAN    1
	{ .name="clean",    .desc="only user-friendly stuff, generally suitable for level \"user\"" },
#define SSL_VERB_MINIMAL  2
	{ .name="minimal",  .desc="report only conn, no real decoding" },
#define SSL_VERB_SIMPLE   3
	{ .name="simple",   .desc="add error messages" },
#define SSL_VERB_ADVANCED 4
	{ .name="advanced", .desc="add handshake-related details" },
#define SSL_VERB_COMPLETE 5
	{ .name="complete", .desc="add full data dump when available" },
	{ /* end */ }
};


struct trace_source trace_ssl = {
	.name = IST("ssl"),
	.desc = "SSL xprt",
	.arg_def = TRC_ARG1_CONN,  /* TRACE()'s first argument is always a conn */
	.default_cb = ssl_trace,
	.known_events = ssl_trace_events,
	.lockon_args = ssl_trace_lockon_args,
	.decoding = ssl_trace_decoding,
	.report_events = ~0,  /* report everything by default */
};

INITCALL1(STG_REGISTER, trace_register_source, &trace_ssl);

/* Trace callback for SSL.
 * These traces always expect that arg1, if non-null, is of type connection.
 */
static void ssl_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                      const struct ist where, const struct ist func,
                      const void *a1, const void *a2, const void *a3, const void *a4)
{
	struct connection *conn = (struct connection*)a1;

	if (src->verbosity <= SSL_VERB_CLEAN)
		return;

	if (conn) {
		struct proxy *px = conn_get_proxy(conn);
		chunk_appendf(&trace_buf, " : [%c(%s)] conn=%p(0x%08x)", conn_is_back(conn) ? 'B' : 'F',
			      px ? px->id : "", conn, conn->flags);
	}

	if (src->verbosity <= SSL_VERB_MINIMAL)
		return;

	if (src->verbosity <= SSL_VERB_SIMPLE && !(mask & SSL_EV_CONN_ERR))
		return;


	if (mask & SSL_EV_CONN_RECV || mask & SSL_EV_CONN_SEND) {

		if (mask & SSL_EV_CONN_ERR) {
			const unsigned int *ssl_err_code = a2;
			chunk_appendf(&trace_buf, " : ssl_err_code=%d ssl_err_str=\"%s\"", *ssl_err_code,
				      ERR_error_string(*ssl_err_code, NULL));
		} else if (src->verbosity > SSL_VERB_SIMPLE) {
			const ssize_t *size = a2;

			if (size)
				chunk_appendf(&trace_buf, " : size=%ld", *size);
		}
	}

}

