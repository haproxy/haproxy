/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_DEBUG_H_
#define _OTEL_DEBUG_H_

#ifdef DEBUG_FULL
#  define DEBUG_OTEL
#endif

/*
 * FLT_OTEL_DBG_ARGS - include extra debug-only function parameters.
 * FLT_OTEL_DBG_BUF  - dump a buffer structure for debugging.
 *
 * When DEBUG_OTEL is not defined, these expand to nothing.
 */
#ifdef DEBUG_OTEL
#  define FLT_OTEL_DBG_ARGS(a, ...)   a, ##__VA_ARGS__
#  define FLT_OTEL_DBG_BUF(l,a)       OTELC_DBG(l, "%p:{ %zu %p %zu %zu }", (a), (a)->size, (a)->area, (a)->data, (a)->head)
#else
#  define FLT_OTEL_DBG_ARGS(...)
#  define FLT_OTEL_DBG_BUF(...)       while (0)
#endif /* DEBUG_OTEL */

/*
 *  ON  | NOLOGNORM |
 * -----+-----------+-------------
 *   0  |     0     |  no log
 *   0  |     1     |  no log
 *   1  |     0     |  log all
 *   1  |     1     |  log errors
 * -----+-----------+-------------
 */
#define FLT_OTEL_LOG(l,f, ...)                                                                                                   \
	do {                                                                                                                     \
		if (!(conf->instr->logging & FLT_OTEL_LOGGING_ON))                                                               \
			OTELC_DBG(DEBUG, "NOLOG[%d]: [" FLT_OTEL_SCOPE "]: [%s] " f, (l), conf->id, ##__VA_ARGS__);              \
		else if ((conf->instr->logging & FLT_OTEL_LOGGING_NOLOGNORM) && ((l) > LOG_ERR))                                 \
			OTELC_DBG(NOTICE, "NOLOG[%d]: [" FLT_OTEL_SCOPE "]: [%s] " f, (l), conf->id, ##__VA_ARGS__);             \
		else {                                                                                                           \
			send_log(&(conf->instr->proxy_log), (l), "[" FLT_OTEL_SCOPE "]: [%s] " f "\n", conf->id, ##__VA_ARGS__); \
			                                                                                                         \
			OTELC_DBG(INFO, "LOG[%d]: %s", (l), logline);                                                            \
		}                                                                                                                \
	} while (0)

#endif /* _OTEL_DEBUG_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
