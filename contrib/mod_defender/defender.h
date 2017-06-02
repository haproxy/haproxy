/*
 * Mod Defender for HAProxy
 *
 * Copyright 2017 HAProxy Technologies, Dragan Dosen <ddosen@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 3 of the License, or (at your option) any later version.
 *
 */
#ifndef __DEFENDER_H__
#define __DEFENDER_H__

#include <types/sample.h>

struct defender_request {
	struct sample clientip;
	struct sample id;
	struct sample method;
	struct sample path;
	struct sample query;
	struct sample version;
	struct sample headers;
	struct sample body;
};

struct defender_header {
	struct {
		char     *str;
		uint64_t  len;
	} name;
	struct {
		char     *str;
		uint64_t  len;
	} value;
};

int defender_init(const char *config_file, const char *log_file);
int defender_process_request(struct worker *worker, struct defender_request *request);

#endif /* __DEFENDER_H__ */
