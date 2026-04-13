/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_INCLUDE_H_
#define _OTEL_INCLUDE_H_

#include <errno.h>
#include <stdbool.h>
#include <math.h>
#include <values.h>
#ifdef USE_THREAD
#  include <pthread.h>
#endif

#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/acl.h>
#include <haproxy/cli.h>
#include <haproxy/clock.h>
#include <haproxy/filters.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_rules.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/tcp_rules.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>

#include <opentelemetry-c-wrapper/include.h>

#include "config.h"
#include "debug.h"
#include "define.h"
#include "cli.h"
#include "event.h"
#include "conf.h"
#include "conf_funcs.h"
#include "filter.h"
#include "group.h"
#include "http.h"
#include "otelc.h"
#include "parser.h"
#include "pool.h"
#include "scope.h"
#include "util.h"
#include "vars.h"

#endif /* _OTEL_INCLUDE_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
