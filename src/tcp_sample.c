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

/* this is to have tcp_info defined on systems using musl
 * library, such as Alpine Linux.
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
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
#include <haproxy/global.h>
#include <haproxy/listener-t.h>
#include <haproxy/namespace.h>
#include <haproxy/proxy-t.h>
#include <haproxy/sample.h>
#include <haproxy/tools.h>


/* Fetch the connection's source IPv4/IPv6 address. Depending on the keyword, it
 * may be the frontend or the backend connection.
 */
static int
smp_fetch_src(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
                conn = (kw[0] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
        else
                conn = (kw[0] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	if (!conn)
		return 0;

	if (!conn_get_src(conn))
		return 0;

	switch (conn->src->ss_family) {
	case AF_INET:
		smp->data.u.ipv4 = ((struct sockaddr_in *)conn->src)->sin_addr;
		smp->data.type = SMP_T_IPV4;
		break;
	case AF_INET6:
		smp->data.u.ipv6 = ((struct sockaddr_in6 *)conn->src)->sin6_addr;
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
	struct connection *conn;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
                conn = (kw[0] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
        else
                conn = (kw[0] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	if (!conn)
		return 0;

	if (!conn_get_src(conn))
		return 0;

	smp->data.type = SMP_T_SINT;
	if (!(smp->data.u.sint = get_host_port(conn->src)))
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
	struct connection *conn;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
                conn = (kw[0] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
        else
                conn = (kw[0] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	if (!conn)
		return 0;

	if (!conn_get_dst(conn))
		return 0;

	switch (conn->dst->ss_family) {
	case AF_INET:
		smp->data.u.ipv4 = ((struct sockaddr_in *)conn->dst)->sin_addr;
		smp->data.type = SMP_T_IPV4;
		break;
	case AF_INET6:
		smp->data.u.ipv6 = ((struct sockaddr_in6 *)conn->dst)->sin6_addr;
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
	struct connection *conn = objt_conn(smp->sess->origin);
	struct listener *li = smp->sess->listener;

	if (!conn)
		return 0;

	if (!conn_get_dst(conn))
		return 0;

	smp->data.type = SMP_T_BOOL;
	smp->flags = 0;
	smp->data.u.sint = addr_is_local(li->rx.settings->netns, conn->dst);
	return smp->data.u.sint >= 0;
}

/* check if the source address of the front connection is local to the system
 * or not.
 */
int smp_fetch_src_is_local(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = objt_conn(smp->sess->origin);
	struct listener *li = smp->sess->listener;

	if (!conn)
		return 0;

	if (!conn_get_src(conn))
		return 0;

	smp->data.type = SMP_T_BOOL;
	smp->flags = 0;
	smp->data.u.sint = addr_is_local(li->rx.settings->netns, conn->src);
	return smp->data.u.sint >= 0;
}

/* set temp integer to the connexion's destination port. Depending on the
 * keyword, it may be the frontend or the backend connection.
 */
static int
smp_fetch_dport(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
                conn = (kw[0] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
        else
                conn = (kw[0] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	if (!conn)
		return 0;

	if (!conn_get_dst(conn))
		return 0;

	smp->data.type = SMP_T_SINT;
	if (!(smp->data.u.sint = get_host_port(conn->dst)))
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

/* Returns some tcp_info data if it's available. "dir" must be set to 0 if
 * the client connection is required, otherwise it is set to 1. "val" represents
 * the required value.
 * If the function fails it returns 0, otherwise it returns 1 and "result" is filled.
 */
static inline int get_tcp_info(const struct arg *args, struct sample *smp,
                               int dir, int val)
{
	struct connection *conn;
	struct tcp_info info;
	socklen_t optlen;

	/* strm can be null. */
	if (!smp->strm)
		return 0;

	/* get the object associated with the stream interface.The
	 * object can be other thing than a connection. For example,
	 * it be a appctx. */
	conn = cs_conn(objt_cs(smp->strm->si[dir].end));
	if (!conn)
		return 0;

	/* The fd may not be available for the tcp_info struct, and the
	  syscal can fail. */
	optlen = sizeof(info);
	if (getsockopt(conn->handle.fd, IPPROTO_TCP, TCP_INFO, &info, &optlen) == -1)
		return 0;

	/* extract the value. */
	smp->data.type = SMP_T_SINT;
	switch (val) {
	case 0:  smp->data.u.sint = info.tcpi_rtt;            break;
	case 1:  smp->data.u.sint = info.tcpi_rttvar;         break;
#if defined(__linux__)
	/* these ones are common to all Linux versions */
	case 2:  smp->data.u.sint = info.tcpi_unacked;        break;
	case 3:  smp->data.u.sint = info.tcpi_sacked;         break;
	case 4:  smp->data.u.sint = info.tcpi_lost;           break;
	case 5:  smp->data.u.sint = info.tcpi_retrans;        break;
	case 6:  smp->data.u.sint = info.tcpi_fackets;        break;
	case 7:  smp->data.u.sint = info.tcpi_reordering;     break;
#elif defined(__FreeBSD__) || defined(__NetBSD__)
	/* the ones are found on FreeBSD and NetBSD featuring TCP_INFO */
	case 2:  smp->data.u.sint = info.__tcpi_unacked;      break;
	case 3:  smp->data.u.sint = info.__tcpi_sacked;       break;
	case 4:  smp->data.u.sint = info.__tcpi_lost;         break;
	case 5:  smp->data.u.sint = info.__tcpi_retrans;      break;
	case 6:  smp->data.u.sint = info.__tcpi_fackets;      break;
	case 7:  smp->data.u.sint = info.__tcpi_reordering;   break;
#endif
	default: return 0;
	}

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

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)

/* get the unacked counter on a client connection */
static int
smp_fetch_fc_unacked(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 2))
		return 0;
	return 1;
}

/* get the sacked counter on a client connection */
static int
smp_fetch_fc_sacked(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 3))
		return 0;
	return 1;
}

/* get the lost counter on a client connection */
static int
smp_fetch_fc_lost(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 4))
		return 0;
	return 1;
}

/* get the retrans counter on a client connection */
static int
smp_fetch_fc_retrans(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 5))
		return 0;
	return 1;
}

/* get the fackets counter on a client connection */
static int
smp_fetch_fc_fackets(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 6))
		return 0;
	return 1;
}

/* get the reordering counter on a client connection */
static int
smp_fetch_fc_reordering(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!get_tcp_info(args, smp, 0, 7))
		return 0;
	return 1;
}
#endif // linux || freebsd || netbsd
#endif // TCP_INFO

/* Note: must not be declared <const> as its list will be overwritten.
 * Note: fetches that may return multiple types must be declared as the lowest
 * common denominator, the type that can be casted into all other ones. For
 * instance v4/v6 must be declared v4.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "bc_dst",      smp_fetch_dst,   0, NULL, SMP_T_SINT, SMP_USE_L4SRV },
	{ "bc_dst_port", smp_fetch_dport, 0, NULL, SMP_T_SINT, SMP_USE_L4SRV },
	{ "bc_src",      smp_fetch_src,   0, NULL, SMP_T_SINT, SMP_USE_L4SRV },
	{ "bc_src_port", smp_fetch_sport, 0, NULL, SMP_T_SINT, SMP_USE_L4SRV },

	{ "dst",      smp_fetch_dst,   0, NULL, SMP_T_IPV4, SMP_USE_L4CLI },
	{ "dst_is_local", smp_fetch_dst_is_local, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "dst_port", smp_fetch_dport, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
	{ "src",      smp_fetch_src,   0, NULL, SMP_T_IPV4, SMP_USE_L4CLI },
	{ "src_is_local", smp_fetch_src_is_local, 0, NULL, SMP_T_BOOL, SMP_USE_L4CLI },
	{ "src_port", smp_fetch_sport, 0, NULL, SMP_T_SINT, SMP_USE_L4CLI },
#ifdef TCP_INFO
	{ "fc_rtt",           smp_fetch_fc_rtt,           ARG1(0,STR), val_fc_time_value, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_rttvar",        smp_fetch_fc_rttvar,        ARG1(0,STR), val_fc_time_value, SMP_T_SINT, SMP_USE_L4CLI },
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
	{ "fc_unacked",       smp_fetch_fc_unacked,       ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_sacked",        smp_fetch_fc_sacked,        ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_retrans",       smp_fetch_fc_retrans,       ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_fackets",       smp_fetch_fc_fackets,       ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_lost",          smp_fetch_fc_lost,          ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
	{ "fc_reordering",    smp_fetch_fc_reordering,    ARG1(0,STR), var_fc_counter, SMP_T_SINT, SMP_USE_L4CLI },
#endif // linux || freebsd || netbsd
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
