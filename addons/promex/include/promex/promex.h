/*
 * include/promex/promex.h
 * This file contains definitions, macros and inline functions dedicated to
 * the prometheus exporter for HAProxy.
 *
 * Copyright 2024 Christopher Faulet <cfaulet@haproxy.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _PROMEX_PROMEX_H
#define _PROMEX_PROMEX_H

#include <import/ist.h>

#include <haproxy/api-t.h>
#include <haproxy/list-t.h>

#include <haproxy/stats.h>

/* Prometheus exporter flags (ctx->flags) */
#define PROMEX_FL_METRIC_HDR        0x00000001
#define PROMEX_FL_INFO_METRIC       0x00000002
#define PROMEX_FL_FRONT_METRIC      0x00000004
#define PROMEX_FL_BACK_METRIC       0x00000008
#define PROMEX_FL_SRV_METRIC        0x00000010
#define PROMEX_FL_LI_METRIC         0x00000020
#define PROMEX_FL_MODULE_METRIC     0x00000040
#define PROMEX_FL_SCOPE_GLOBAL      0x00000080
#define PROMEX_FL_SCOPE_FRONT       0x00000100
#define PROMEX_FL_SCOPE_BACK        0x00000200
#define PROMEX_FL_SCOPE_SERVER      0x00000400
#define PROMEX_FL_SCOPE_LI          0x00000800
#define PROMEX_FL_SCOPE_MODULE      0x00001000
#define PROMEX_FL_NO_MAINT_SRV      0x00002000
#define PROMEX_FL_EXTRA_COUNTERS    0x00004000
#define PROMEX_FL_INC_METRIC_BY_DEFAULT 0x00008000
#define PROMEX_FL_DESC_LABELS       0x00010000

#define PROMEX_FL_SCOPE_ALL (PROMEX_FL_SCOPE_GLOBAL | PROMEX_FL_SCOPE_FRONT | \
			     PROMEX_FL_SCOPE_LI | PROMEX_FL_SCOPE_BACK | \
			     PROMEX_FL_SCOPE_SERVER | PROMEX_FL_SCOPE_MODULE)

/* The max number of labels per metric */
#define PROMEX_MAX_LABELS 8

/* Promtheus metric type (gauge or counter) */
enum promex_mt_type {
	PROMEX_MT_GAUGE   = 1,
	PROMEX_MT_COUNTER = 2,
};

/* Describe a prometheus metric */
struct promex_metric {
	struct ist          n;      /* The metric name */
	enum promex_mt_type type;   /* The metric type (gauge or counter) */
	unsigned int        flags;  /* PROMEX_FL_* flags */
};

/* Describe a prometheus metric label. It is just a key/value pair */
struct promex_label {
	struct ist name;
	struct ist value;
};

/* Entity used to expose custom metrics on HAProxy.
 *
 *     * start_metric_dump(): It is an optional callback function. If defined, it
 *                            is responsible to initialize the dump context use
 *                            as the first restart point.
 *
 *     * stop_metric_dump(): It is an optional callback function. If defined, it
 *                           is responsible to deinit the dump context.
 *
 *     * metric_info(): This one is mandatory. It returns the info about the
 *                      metric: name, type and flags and description.
 *
 *     * start_ts(): This one is mandatory, it initializes the context for a time
 *                   series for a given metric. This context is the second
 *                   restart point.
 *
 *    * next_ts(): This one is mandatory. It iterates on time series for a
 *                 given metrics. It is also responsible to handle end of a
 *                 time series and deinit the context.
 *
 *    * fill_ts(): It fills info on the time series for a given metric : the
 *                 labels and the value.
 */
struct promex_module {
	struct list list;
	struct ist name;                                                  /* The promex module name */
	int   (*metric_info)(unsigned int id,                             /* Return info for the given id */
			     struct promex_metric *metric,
			     struct ist *desc);
	void *(*start_metrics_dump)();                                    /* Start a dump (may be NULL) */
	void  (*stop_metrics_dump)(void *ctx);                            /* Stop a dump (may be NULL) */
	void *(*start_ts)(void *ctx, unsigned int id);                    /* Start a time series for the given metric */
	void *(*next_ts)(void *ctx, void *ts_ctx, unsigned int id);       /* move to the next time series for the given metric */
	int   (*fill_ts)(void *ctx, void *ts_ctx, unsigned int id,        /* fill the time series for the given metric */
			 struct promex_label *labels, struct field *field);

	size_t nb_metrics;                                                /* # of metrics */
};

extern struct list promex_module_list;

void promex_register_module(struct promex_module *m);

#endif /* _PROMEX_PROMEX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
