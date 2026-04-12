/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_CONFIG_H_
#define _OTEL_CONFIG_H_

/* Memory pool selection flags. */
#define USE_POOL_BUFFER
#define USE_POOL_OTEL_SPAN_CONTEXT
#define USE_POOL_OTEL_SCOPE_SPAN
#define USE_POOL_OTEL_SCOPE_CONTEXT
#define USE_POOL_OTEL_RUNTIME_CONTEXT
#define USE_TRASH_CHUNK

/* Enable per-event and per-stream diagnostic counters in debug builds. */
#if defined(DEBUG_OTEL) && !defined(FLT_OTEL_USE_COUNTERS)
#  define FLT_OTEL_USE_COUNTERS
#endif

#define FLT_OTEL_ID_MAXLEN        64            /* Maximum identifier length. */
#define FLT_OTEL_DEBUG_LEVEL   0b11101111111 /* Default debug bitmask. */

#define FLT_OTEL_ATTR_INIT_SIZE   8 /* Initial attribute array capacity. */
#define FLT_OTEL_ATTR_INC_SIZE    4 /* Attribute array growth increment. */

#endif /* _OTEL_CONFIG_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
