/*
 * Modsecurity wrapper for haproxy
 *
 * This file contains the headers of the wrapper which sends data
 * in ModSecurity and returns the verdict.
 *
 * Copyright 2016 OZON, Thierry Fournier <thierry.fournier@ozon.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#ifndef __MODSEC_WRAPPER_H__
#define __MODSEC_WRAPPER_H__

#include "spoa.h"

struct modsecurity_parameters {
	struct sample uniqueid;
	struct sample method;
	struct sample path;
	struct sample query;
	struct sample vers;
	struct sample hdrs_bin;
	struct sample body_length;
	struct sample body;
};

int modsecurity_load(const char *file);
int modsecurity_process(struct worker *worker, struct modsecurity_parameters *params);

#endif /* __MODSEC_WRAPPER_H__ */
