/*
 * AF_INET/AF_INET6 SOCK_STREAM protocol layer (tcp)
 *
 * Copyright 2000-2013 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/listener-t.h>
#include <haproxy/namespace.h>
#include <haproxy/proxy-t.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/session.h>
#include <haproxy/tools.h>

/* Fetch the connection's source IPv4/IPv6 address. Depending on the keyword, it
 * may be the frontend or the backend connection.
 */
static int
smp_fetch_src(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	const struct sockaddr_storage *src = NULL;

	if (kw[0] == 'b') { /* bc_src */
		struct connection *conn = ((obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
					   ? sc_conn(__objt_check(smp->sess->origin)->sc)
					   : (smp->strm ? sc_conn(smp->strm->scb): NULL));
		if (conn && conn_get_src(conn))
			src = conn_src(conn);
	}
	else if (kw[0] == 'f') { /* fc_src */
		struct connection *conn = objt_conn(smp->sess->origin);

		if (conn && conn_get_src(conn))
			src = conn_src(conn);
	}
        else /* src */
		src = (smp->strm ? sc_src(smp->strm->scf) : sess_src(smp->sess));

	if (!src)
		return 0;

	switch (src->ss_family) {
	case AF_INET:
		smp->data.u.ipv4 = ((struct sockaddr_in *)src)->sin_addr;
		smp->data.type = SMP_T_IPV4;
		break;
	case AF_INET6:
		smp->data.u.ipv6 = ((struct sockaddr_in6 *)src)->sin6_addr;
		smp->data.type = SMP_T_IPV6;
		break;
	default:
		return 0;
	}

	smp->flags = 0;
	return 1;
}

/* set temp integer to the connection's source port. Depending on the
 * keyword, it may be the frontend or the backend connection.
 */
static int
smp_fetch_sport(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	const struct sockaddr_storage *src = NULL;

	if (kw[0] == 'b') { /* bc_src_port */
		struct connection *conn = ((obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
					   ? sc_conn(__objt_check(smp->sess->origin)->sc)
					   : (smp->strm ? sc_conn(smp->strm->scb): NULL));
		if (conn && conn_get_src(conn))
			src = conn_src(conn);
	}
	else if (kw[0] == 'f') { /* fc_src_port */
		struct connection *conn = objt_conn(smp->sess->origin);

		if (conn && conn_get_src(conn))
			src = conn_src(conn);
	}
        else /* src_port */
		src = (smp->strm ? sc_src(smp->strm->scf) : sess_src(smp->sess));

	if (!src)
		return 0;

	smp->data.type = SMP_T_SINT;
	if (!(smp->data.u.sint = get_host_port(src)))
		return 0;

	smp->flags = 0;
	return 1;
}

/* fetch the connection's destination IPv4/IPv6 address. Depending on the
 * keyword, it may be the frontend or the backend connection.
 */
static int
smp_fetch_dst(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	const struct sockaddr_storage *dst = NULL;

	if (kw[0] == 'b') { /* bc_dst */
		struct connection *conn = ((obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
					   ? sc_conn(__objt_check(smp->sess->origin)->sc)
					   : (smp->strm ? sc_conn(smp->strm->scb): NULL));
		if (conn && conn_get_dst(conn))
			dst = conn_dst(conn);
	}
	else if (kw[0] == 'f') { /* fc_dst */
		struct connection *conn = objt_conn(smp->sess->origin);

		if (conn && conn_get_dst(conn))
			dst = conn_dst(conn);
	}
        else /* dst */
		dst = (smp->strm ? sc_dst(smp->strm->scf) : sess_dst(smp->sess));

	if (!dst)
		return 0;

	switch (dst->ss_family) {
	case AF_INET:
		smp->data.u.ipv4 = ((struct sockaddr_in *)dst)->sin_addr;
		smp->data.type = SMP_T_IPV4;
		break;
	case AF_INET6:
		smp->data.u.ipv6 = ((struct sockaddr_in6 *)dst)->sin6_addr;
		smp->data.type = SMP_T_IPV6;
		break;
	default:
		return 0;
	}

	smp->flags = 0;
	return 1;
}

/* check if the destination address of the front connection is local to the
 * system or if it was intercepted.
 */
int smp_fetch_dst_is_local(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct listener *li = smp->sess->listener;
	const struct sockaddr_storage *dst = NULL;

	if (kw[0] == 'f') { /* fc_dst_is_local */
		struct connection *conn = objt_conn(smp->sess->origin);

		if (conn && conn_get_dst(conn))
			dst = conn_dst(conn);
	}
	else /* dst_is_local */
		dst = (smp->strm ? sc_dst(smp->strm->scf) : sess_dst(smp->sess));

	if (!dst)
		return 0;

	smp->data.type = SMP_T_BOOL;
	smp->flags = 0;
	smp->data.u.sint = addr_is_local(li->rx.settings->netns, dst);
	return smp->data.u.sint >= 0;
}

/* check if the source address of the front connection is local to the system
 * or not.
 */
int smp_fetch_src_is_local(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct listener *li = smp->sess->listener;
	const struct sockaddr_storage *src = NULL;

	if (kw[0] == 'f') { /* fc_src_is_local */
		struct connection *conn = objt_conn(smp->sess->origin);

		if (conn && conn_get_src(conn))
			src = conn_src(conn);
	}
	else /* src_is_local */
		src = (smp->strm ? sc_src(smp->strm->scf) : sess_src(smp->sess));

	if (!src)
		return 0;

	smp->data.type = SMP_T_BOOL;
	smp->flags = 0;
	smp->data.u.sint = addr_is_local(li->rx.settings->netns, src);
	return smp->data.u.sint >= 0;
}

/* set temp integer to the connexion's destination port. Depending on the
 * keyword, it may be the frontend or the backend connection.
 */
static int
smp_fetch_dport(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	const struct sockaddr_storage *dst = NULL;

	if (kw[0] == 'b') { /* bc_dst_port */
		struct connection *conn = ((obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
					   ? sc_conn(__objt_check(smp->sess->origin)->sc)
					   : (smp->strm ? sc_conn(smp->strm->scb): NULL));
		if (conn && conn_get_dst(conn))
			dst = conn_dst(conn);
	}
	else if (kw[0] == 'f') { /* fc_dst_port */
		struct connection *conn = objt_conn(smp->sess->origin);

		if (conn && conn_get_dst(conn))
			dst = conn_dst(conn);
	}
        else /* dst_port */
		dst = (smp->strm ? sc_dst(smp->strm->scf) : sess_dst(smp->sess));

	if (!dst)
		return 0;

	smp->data.type = SMP_T_SINT;
	if (!(smp->data.u.sint = get_host_port(dst)))
		return 0;

	smp->flags = 0;
	return 1;
}

#ifdef TCP_INFO


/* Validates the arguments passed to "fc_*" fetch keywords returning a time
 * value. These keywords support an optional string representing the unit of the
 * result: "us" for microseconds and "ms" for milliseconds". Returns 0 on error
 * and non-zero if OK.
 */
static int val_fc_time_value(struct arg *args, char **err)
{
	if (args[0].type == ARGT_STR) {
		if (strcmp(args[0].data.str.area, "us") == 0) {
			chunk_destroy(&args[0].data.str);
			args[0].type = ARGT_SINT;
			args[0].data.sint = TIME_UNIT_US;
		}
		else if (strcmp(args[0].data.str.area, "ms") == 0) {
			chunk_destroy(&args[0].data.str);
			args[0].type = ARGT_SINT;
			args[0].data.sint = TIME_UNIT_MS;
		}
		else {
			memprintf(err, "expects 'us' or 'ms', got '%s'",
				  args[0].data.str.area);
			return 0;
		}
	}
	else {
		memprintf(err, "Unexpected arg type");
		return 0;
	}

	return 1;
}

/* Validates the arguments passed to "fc_*" fetch keywords returning a
 * counter. These keywords should be used without any keyword, but because of a
 * bug in previous versions, an optional string argument may be passed. In such
 * case, the argument is ignored and a warning is emitted. Returns 0 on error
 * and non-zero if OK.
 */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
static int var_fc_counter(struct arg *args, char **err)
{
	if (args[0].type != ARGT_STOP) {
		ha_warning("no argument supported for 'fc_*' sample expressions returning counters.\n");
		if (args[0].type == ARGT_STR)
			chunk_destroy(&args[0].data.str);
		args[0].type = ARGT_STOP;
	}

	return 1;
}
#endif

/* Returns some tcp_info data if it's available. "dir" must be set to 0 if
 * the client connection is required, otherwise it is set to 1. "val" represents
 * the required value.
 * If the function fails it returns 0, otherwise it returns 1 and "result" is filled.
 */
static inline int get_tcp_info(const struct arg *args, struct sample *smp,
                               int dir, int val)
{
	struct connection *conn;

	/* strm can be null. */
	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	/* get the object associated with the stream connector.The
	 * object can be other thing than a connection. For example,
	 * it could be an appctx.
	 */
	conn = (dir == 0 ? sc_conn(smp->strm->scf) : sc_conn(smp->strm->scb));
	if (!conn || !conn->ctrl->get_info ||
	    !conn->ctrl->get_info(conn, &smp->data.u.sint, val))
		return 0;


	return 1;
}

/* get the mean rtt of a client connection */
static int
smp_fetch_fc_rtt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 0))
		return 0;

	/* By default or if explicitly specified, convert rtt to ms */
	if (!args || args[0].type == ARGT_STOP || args[0].data.sint == TIME_UNIT_MS)
		smp->data.u.sint = (smp->data.u.sint + 500) / 1000;

	return 1;
}

/* get the variance of the mean rtt of a client connection */
static int
smp_fetch_fc_rttvar(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 1))
		return 0;

	/* By default or if explicitly specified, convert rttvar to ms */
	if (!args || args[0].type == ARGT_STOP || args[0].data.sint == TIME_UNIT_MS)
		smp->data.u.sint = (smp->data.u.sint + 500) / 1000;

	return 1;
}

/* get the mean rtt of a backend connection */
static int
smp_fetch_bc_rtt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 1, 0))
		return 0;

	/* By default or if explicitly specified, convert rtt to ms */
	if (!args || args[0].type == ARGT_STOP || args[0].data.sint == TIME_UNIT_MS)
		smp->data.u.sint = (smp->data.u.sint + 500) / 1000;

	return 1;
}

/* get the variance of the mean rtt of a backend connection */
static int
smp_fetch_bc_rttvar(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 1, 1))
		return 0;

	/* By default or if explicitly specified, convert rttvar to ms */
	if (!args || args[0].type == ARGT_STOP || args[0].data.sint == TIME_UNIT_MS)
		smp->data.u.sint = (smp->data.u.sint + 500) / 1000;

	return 1;
}


#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
/* get the unacked counter on a client connection */
static int
smp_fetch_fc_unacked(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 2))
		return 0;
	return 1;
}
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
/* get the sacked counter on a client connection */
static int
smp_fetch_fc_sacked(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 3))
		return 0;
	return 1;
}
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
/* get the lost counter on a client connection */
static int
smp_fetch_fc_lost(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 4))
		return 0;
	return 1;
}
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
/* get the retrans counter on a client connection */
static int
smp_fetch_fc_retrans(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 5))
		return 0;
	return 1;
}
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
/* get the fackets counter on a client connection */
static int
smp_fetch_fc_fackets(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 6))
		return 0;
	return 1;
}
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
/* get the reordering counter on a client connection */
static int
smp_fetch_fc_reordering(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 7))
		return 0;
	return 1;
}
#endif
#endif // TCP_INFO

/* Validates the data unit argument passed to "accept_date" fetch. Argument 0 support an
 * optional string representing the unit of the result: "s" for seconds, "ms" for
 * milliseconds and "us" for microseconds.
 * Returns 0 on error and non-zero if OK.
 */
int smp_check_accept_date_unit(struct arg *args, char **err)
{
	if (args[0].type == ARGT_STR) {
		long long int unit;

		if (strcmp(args[0].data.str.area, "s") == 0) {
			unit = TIME_UNIT_S;
		}
		else if (strcmp(args[0].data.str.area, "ms") == 0) {
			unit = TIME_UNIT_MS;
		}
		else if (strcmp(args[0].data.str.area, "us") == 0) {
			unit = TIME_UNIT_US;
		}
		else {
			memprintf(err, "expects 's', 'ms' or 'us', got '%s'",
				  args[0].data.str.area);
			return 0;
		}

		chunk_destroy(&args[0].data.str);
		args[0].type = ARGT_SINT;
		args[0].data.sint = unit;
	}
	else if (args[0].type != ARGT_STOP) {
		memprintf(err, "Unexpected arg type");
		return 0;
	}

	return 1;
}

/* retrieve the accept or request date in epoch time, converts it to milliseconds
 * or microseconds if asked to in optional args[1] unit param */
static int
smp_fetch_accept_date(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct strm_logs *logs;
	struct timeval tv;

	if (!smp->strm)
		return 0;

	logs = &smp->strm->logs;

	if (kw[0] == 'r') {  /* request_date */
		tv_ms_add(&tv, &logs->accept_date, logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0);
	} else {             /* accept_date */
		tv.tv_sec = logs->accept_date.tv_sec;
		tv.tv_usec = logs->accept_date.tv_usec;
	}

	smp->data.u.sint = tv.tv_sec;

	/* report in milliseconds */
	if (args[0].type == ARGT_SINT && args[0].data.sint == TIME_UNIT_MS) {
		smp->data.u.sint *= 1000;
		smp->data.u.sint += tv.tv_usec / 1000;
	}
	/* report in microseconds */
	else if (args[0].type == ARGT_SINT && args[0].data.sint == TIME_UNIT_US) {
		smp->data.u.sint *= 1000000;
		smp->data.u.sint += tv.tv_usec;
	}

	smp->data.type = SMP_T_SINT;
	smp->flags |= SMP_F_VOL_TEST | SMP_F_MAY_CHANGE;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Note: fetches that may return multiple types should be declared using the
 * appropriate pseudo-type. If not available it must be declared as the lowest
 * common denominator, the type that can be casted into all other ones.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	/* timestamps */
	{ "accept_date", smp_fetch_accept_date,  ARG1(0,STR), smp_check_accept_date_unit, SMP_T_SINT, SMP_USE_L4CLI },
	{ "request_date", smp_fetch_accept_date,  ARG1(0,STR), smp_check_accept_date_unit, SMP_T_SINT, SMP_USE_HRQHP },

	{ "bc_dst",      smp_fetch_dst,   0, NULL, SMP_T_ADDR, SMP_USE_L4SRV },
	{ "bc_dst_port", smp_fetch_dport, 0, NULL, SMP_T_SINT, SMP_USE_L4SRV },
	{ "bc_src",      smp_fetch_src,   0, NULL, SMP_T_ADDR, SMP_USE_L4SRV },
	{ "bc_src_port", smp_fetch_sport, 0, NULL, SMP_T_SINT, SMP_USE_L4SRV },

	{ "dst",      smp_fetch_dst,   0, NULL, SMP_T_ADDR, SMP_USE_L4CLI },
	{ "dst_is_local", smp_fetch_dst_is_local, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "dst_port", smp_fetch_dport, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },

	{ "fc_dst",      smp_fetch_dst,   0, NULL, SMP_T_ADDR, SMP_USE_L4CLI },
	{ "fc_dst_is_local", smp_fetch_dst_is_local, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "fc_dst_port", smp_fetch_dport, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },

	{ "fc_src",      smp_fetch_src,   0, NULL, SMP_T_ADDR, SMP_USE_L4CLI },
	{ "fc_src_is_local", smp_fetch_src_is_local, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "fc_src_port", smp_fetch_sport, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },

	{ "src",      smp_fetch_src,   0, NULL, SMP_T_ADDR, SMP_USE_L4CLI },
	{ "src_is_local", smp_fetch_src_is_local, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "src_port", smp_fetch_sport, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
#ifdef TCP_INFO
	{ "fc_rtt",           smp_fetch_fc_rtt,           ARG1(0,STR), val_fc_time_value, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_rttvar",        smp_fetch_fc_rttvar,        ARG1(0,STR), val_fc_time_value, SMP_T_SINT, SMP_USE_L4CLI },
	{ "bc_rtt",           smp_fetch_bc_rtt,           ARG1(0,STR), val_fc_time_value, SMP_T_SINT, SMP_USE_L4CLI },
	{ "bc_rttvar",        smp_fetch_bc_rttvar,        ARG1(0,STR), val_fc_time_value, SMP_T_SINT, SMP_USE_L4CLI },

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	{ "fc_unacked",       smp_fetch_fc_unacked,       ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
#endif
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	{ "fc_sacked",        smp_fetch_fc_sacked,        ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
#endif
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	{ "fc_retrans",       smp_fetch_fc_retrans,       ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
#endif
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	{ "fc_fackets",       smp_fetch_fc_fackets,       ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
#endif
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	{ "fc_lost",          smp_fetch_fc_lost,          ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
#endif
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	{ "fc_reordering",    smp_fetch_fc_reordering,    ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
#endif
#endif // TCP_INFO
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
