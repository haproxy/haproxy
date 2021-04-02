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
#ifndef _OPENTRACING_INCLUDE_H_
#define _OPENTRACING_INCLUDE_H_

#include <errno.h>
#include <stdbool.h>

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/acl.h>
#include <haproxy/cli.h>
#include <haproxy/filters.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_rules.h>
#include <haproxy/log.h>
#include <haproxy/sample.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/vars.h>

#include "config.h"
#include "debug.h"
#include "define.h"
#include "cli.h"
#include "event.h"
#include "conf.h"
#include "filter.h"
#include "group.h"
#include "http.h"
#include "opentracing.h"
#include "parser.h"
#include "pool.h"
#include "scope.h"
#include "util.h"
#include "vars.h"

#endif /* _OPENTRACING_INCLUDE_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
