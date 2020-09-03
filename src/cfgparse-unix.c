/*
 * Configuration parsing for UNIX sockets (bind and server keywords)
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
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

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

/* parse the "mode" bind keyword */
static int bind_parse_mode(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char *endptr;

	conf->settings.ux.mode = strtol(args[cur_arg + 1], &endptr, 8);

	if (!*args[cur_arg + 1] || *endptr) {
		memprintf(err, "'%s' : missing or invalid mode '%s' (octal integer expected)", args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "gid" bind keyword */
static int bind_parse_gid(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->settings.ux.gid = atol(args[cur_arg + 1]);
	return 0;
}

/* parse the "group" bind keyword */
static int bind_parse_group(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct group *group;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing group name", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	group = getgrnam(args[cur_arg + 1]);
	if (!group) {
		memprintf(err, "'%s' : unknown group name '%s'", args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->settings.ux.gid = group->gr_gid;
	return 0;
}

/* parse the "uid" bind keyword */
static int bind_parse_uid(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing value", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->settings.ux.uid = atol(args[cur_arg + 1]);
	return 0;
}

/* parse the "user" bind keyword */
static int bind_parse_user(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct passwd *user;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing user name", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	user = getpwnam(args[cur_arg + 1]);
	if (!user) {
		memprintf(err, "'%s' : unknown user name '%s'", args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->settings.ux.uid = user->pw_uid;
	return 0;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct bind_kw_list bind_kws = { "UNIX", { }, {
	{ "gid",   bind_parse_gid,   1 },      /* set the socket's gid */
	{ "group", bind_parse_group, 1 },      /* set the socket's gid from the group name */
	{ "mode",  bind_parse_mode,  1 },      /* set the socket's mode (eg: 0644)*/
	{ "uid",   bind_parse_uid,   1 },      /* set the socket's uid */
	{ "user",  bind_parse_user,  1 },      /* set the socket's uid from the user name */
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);
