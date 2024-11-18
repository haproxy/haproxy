/*
 * Datagram processing functions
 *
 * Copyright 2014 Baptiste Assmann <bedis9@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/fd.h>
#include <haproxy/cfgparse.h>
#include <haproxy/dgram.h>
#include <haproxy/errors.h>
#include <haproxy/tools.h>

/* datagram handler callback */
void dgram_fd_handler(int fd)
{
	struct dgram_conn *dgram = fdtab[fd].owner;

	if (unlikely(!dgram))
		return;

	if (fd_recv_ready(fd))
		dgram->data->recv(dgram);
	if (fd_send_ready(fd))
		dgram->data->send(dgram);

	return;
}

/* config parser for global "tune.{rcv,snd}buf.{frontend,backend}" */
static int dgram_parse_tune_bufs(char **args, int section_type, struct proxy *curpx,
                                 const struct proxy *defpx, const char *file, int line,
                                 char **err)
{
	const char *res;
	uint *valptr;
	uint val;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* "tune.rcvbuf.frontend", "tune.rcvbuf.backend",
	 * "tune.sndbuf.frontend", "tune.sndbuf.backend"
	 */
	valptr = (args[0][5] == 'r' && args[0][12] == 'f') ? &global.tune.frontend_rcvbuf :
		 (args[0][5] == 'r' && args[0][12] == 'b') ? &global.tune.backend_rcvbuf :
		 (args[0][5] == 's' && args[0][12] == 'f') ? &global.tune.frontend_sndbuf :
		 &global.tune.backend_sndbuf;

	if (*valptr != 0) {
		memprintf(err, "parsing [%s:%d] : ignoring '%s' which was already specified.\n", file, line, args[0]);
		return 1;
	}

	res = parse_size_err(args[1], &val);
	if (res != NULL) {
		memprintf(err, "parsing [%s:%d]: unexpected '%s' after size passed to '%s'", file, line, res, args[0]);
		return -1;
	}

	if (*(args[1]) == 0 || val <= 0) {
		memprintf(err, "parsing [%s:%d] : '%s' expects a strictly positive integer argument.\n", file, line, args[0]);
		return -1;
	}

	*valptr = val;
	return 0;
}

/* register "global" section keywords */
static struct cfg_kw_list dgram_cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.rcvbuf.backend",  dgram_parse_tune_bufs },
	{ CFG_GLOBAL, "tune.rcvbuf.frontend", dgram_parse_tune_bufs },
	{ CFG_GLOBAL, "tune.sndbuf.backend",  dgram_parse_tune_bufs },
	{ CFG_GLOBAL, "tune.sndbuf.frontend", dgram_parse_tune_bufs },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &dgram_cfg_kws);
