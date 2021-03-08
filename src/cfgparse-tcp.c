/*
 * Configuration parsing for TCP (bind and server keywords)
 *
 * Copyright 2000-2020 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

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
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/namespace.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server.h>
#include <haproxy/tools.h>


#ifdef IPV6_V6ONLY
/* parse the "v4v6" bind keyword */
static int bind_parse_v4v6(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->settings.options |= RX_O_V4V6;
	return 0;
}

/* parse the "v6only" bind keyword */
static int bind_parse_v6only(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->settings.options |= RX_O_V6ONLY;
	return 0;
}
#endif

#ifdef CONFIG_HAP_TRANSPARENT
/* parse the "transparent" bind keyword */
static int bind_parse_transparent(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->settings.options |= RX_O_FOREIGN;
	return 0;
}
#endif

#if defined(TCP_DEFER_ACCEPT) || defined(SO_ACCEPTFILTER)
/* parse the "defer-accept" bind keyword */
static int bind_parse_defer_accept(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->rx.addr.ss_family == AF_INET || l->rx.addr.ss_family == AF_INET6)
			l->options |= LI_O_DEF_ACCEPT;
	}

	return 0;
}
#endif

#ifdef TCP_FASTOPEN
/* parse the "tfo" bind keyword */
static int bind_parse_tfo(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->rx.addr.ss_family == AF_INET || l->rx.addr.ss_family == AF_INET6)
			l->options |= LI_O_TCP_FO;
	}

	return 0;
}
#endif

#ifdef TCP_MAXSEG
/* parse the "mss" bind keyword */
static int bind_parse_mss(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;
	int mss;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing MSS value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	mss = atoi(args[cur_arg + 1]);
	if (!mss || abs(mss) > 65535) {
		memprintf(err, "'%s' : expects an MSS with and absolute value between 1 and 65535", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->rx.addr.ss_family == AF_INET || l->rx.addr.ss_family == AF_INET6)
			l->maxseg = mss;
	}

	return 0;
}
#endif

#ifdef TCP_USER_TIMEOUT
/* parse the "tcp-ut" bind keyword */
static int bind_parse_tcp_ut(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	const char *ptr = NULL;
	struct listener *l;
	unsigned int timeout;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing TCP User Timeout value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	ptr = parse_time_err(args[cur_arg + 1], &timeout, TIME_UNIT_MS);
	if (ptr == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[cur_arg+1], args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	else if (ptr == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' (minimum non-null value is 1 ms)",
			  args[cur_arg+1], args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	else if (ptr) {
		memprintf(err, "'%s' : expects a positive delay in milliseconds", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	list_for_each_entry(l, &conf->listeners, by_bind) {
		if (l->rx.addr.ss_family == AF_INET || l->rx.addr.ss_family == AF_INET6)
			l->tcp_ut = timeout;
	}

	return 0;
}
#endif

#ifdef SO_BINDTODEVICE
/* parse the "interface" bind keyword */
static int bind_parse_interface(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing interface name", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->settings.interface = strdup(args[cur_arg + 1]);
	return 0;
}
#endif

#ifdef USE_NS
/* parse the "namespace" bind keyword */
static int bind_parse_namespace(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char *namespace = NULL;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing namespace id", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	namespace = args[cur_arg + 1];

	conf->settings.netns = netns_store_lookup(namespace, strlen(namespace));

	if (conf->settings.netns == NULL)
		conf->settings.netns = netns_store_insert(namespace);

	if (conf->settings.netns == NULL) {
		ha_alert("Cannot open namespace '%s'.\n", args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}
#endif

#ifdef TCP_USER_TIMEOUT
/* parse the "tcp-ut" server keyword */
static int srv_parse_tcp_ut(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	const char *ptr = NULL;
	unsigned int timeout;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing TCP User Timeout value", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	ptr = parse_time_err(args[*cur_arg + 1], &timeout, TIME_UNIT_MS);
	if (ptr == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' (maximum value is 2147483647 ms or ~24.8 days)",
			  args[*cur_arg+1], args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	else if (ptr == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' (minimum non-null value is 1 ms)",
			  args[*cur_arg+1], args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	else if (ptr) {
		memprintf(err, "'%s' : expects a positive delay in milliseconds", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (newsrv->addr.ss_family == AF_INET || newsrv->addr.ss_family == AF_INET6)
		newsrv->tcp_ut = timeout;

	return 0;
}
#endif


/************************************************************************/
/*           All supported bind keywords must be declared here.         */
/************************************************************************/

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct bind_kw_list bind_kws = { "TCP", { }, {
#if defined(TCP_DEFER_ACCEPT) || defined(SO_ACCEPTFILTER)
	{ "defer-accept",  bind_parse_defer_accept, 0 }, /* wait for some data for 1 second max before doing accept */
#endif
#ifdef SO_BINDTODEVICE
	{ "interface",     bind_parse_interface,    1 }, /* specifically bind to this interface */
#endif
#ifdef TCP_MAXSEG
	{ "mss",           bind_parse_mss,          1 }, /* set MSS of listening socket */
#endif
#ifdef TCP_USER_TIMEOUT
	{ "tcp-ut",        bind_parse_tcp_ut,       1 }, /* set User Timeout on listening socket */
#endif
#ifdef TCP_FASTOPEN
	{ "tfo",           bind_parse_tfo,          0 }, /* enable TCP_FASTOPEN of listening socket */
#endif
#ifdef CONFIG_HAP_TRANSPARENT
	{ "transparent",   bind_parse_transparent,  0 }, /* transparently bind to the specified addresses */
#endif
#ifdef IPV6_V6ONLY
	{ "v4v6",          bind_parse_v4v6,         0 }, /* force socket to bind to IPv4+IPv6 */
	{ "v6only",        bind_parse_v6only,       0 }, /* force socket to bind to IPv6 only */
#endif
#ifdef USE_NS
	{ "namespace",     bind_parse_namespace,    1 },
#endif
	/* the versions with the NULL parse function*/
	{ "defer-accept",  NULL,  0 },
	{ "interface",     NULL,  1 },
	{ "mss",           NULL,  1 },
	{ "transparent",   NULL,  0 },
	{ "v4v6",          NULL,  0 },
	{ "v6only",        NULL,  0 },
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

static struct srv_kw_list srv_kws = { "TCP", { }, {
#ifdef TCP_USER_TIMEOUT
	{ "tcp-ut",        srv_parse_tcp_ut,        1,  1,  0 }, /* set TCP user timeout on server */
#endif
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, srv_register_keywords, &srv_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
