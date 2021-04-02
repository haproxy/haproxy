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
#ifndef _OPENTRACING_DEBUG_H_
#define _OPENTRACING_DEBUG_H_

#ifdef DEBUG_FULL
#  define DEBUG_OT
#endif

#ifdef DEBUG_OT
#  ifdef DEBUG_OT_SYSTIME
#     define FLT_OT_DBG_FMT(f)      "[% 2d] %ld.%06ld [" FLT_OT_SCOPE "]: " f, tid, now.tv_sec, now.tv_usec
#  else
#     define FLT_OT_DBG_FMT(f)      "[% 2d] %11.6f [" FLT_OT_SCOPE "]: " f, tid, FLT_OT_TV_UDIFF(&(flt_ot_debug.start), &now) / 1e6
#  endif
#  define FLT_OT_DBG_INDENT         "                                                                                "
#  define FLT_OT_DBG(l,f, ...)                                                             \
	do {                                                                               \
		if (!(l) || (flt_ot_debug.level & (1 << (l))))                             \
			(void)fprintf(stderr, FLT_OT_DBG_FMT("%.*s" f "\n"),               \
			              dbg_indent_level, FLT_OT_DBG_INDENT, ##__VA_ARGS__); \
	} while (0)
#  define FLT_OT_FUNC(f, ...)       do { FLT_OT_DBG(1, "%s(" f ") {", __func__, ##__VA_ARGS__); dbg_indent_level += 3; } while (0)
#  define FLT_OT_RETURN(a)          do { dbg_indent_level -= 3; FLT_OT_DBG(1, "}"); return a; } while (0)
#  define FLT_OT_DBG_IFDEF(a,b)     a
#  define FLT_OT_DBG_ARGS(a, ...)   a, ##__VA_ARGS__

struct flt_ot_debug {
#ifndef DEBUG_OT_SYSTIME
	struct timeval start;
#endif
	uint8_t        level;
};


extern THREAD_LOCAL int    dbg_indent_level;
extern struct flt_ot_debug flt_ot_debug;

#else

#  define FLT_OT_DBG(...)           while (0)
#  define FLT_OT_FUNC(...)          while (0)
#  define FLT_OT_RETURN(a)          return a
#  define FLT_OT_DBG_IFDEF(a,b)     b
#  define FLT_OT_DBG_ARGS(...)
#endif /* DEBUG_OT */

/*
 *  ON  | NOLOGNORM |
 * -----+-----------+-------------
 *   0  |     0     |  no log
 *   0  |     1     |  no log
 *   1  |     0     |  log all
 *   1  |     1     |  log errors
 * -----+-----------+-------------
 */
#define FLT_OT_LOG(l,f, ...)                                                                                                    \
	do {                                                                                                                    \
		if (!(conf->tracer->logging & FLT_OT_LOGGING_ON))                                                               \
			FLT_OT_DBG(3, "NOLOG[%d]: [" FLT_OT_SCOPE "]: [%s] " f, (l), conf->id, ##__VA_ARGS__);                  \
		else if ((conf->tracer->logging & FLT_OT_LOGGING_NOLOGNORM) && ((l) > LOG_ERR))                                 \
			FLT_OT_DBG(2, "NOLOG[%d]: [" FLT_OT_SCOPE "]: [%s] " f, (l), conf->id, ##__VA_ARGS__);                  \
		else {                                                                                                          \
			send_log(&(conf->tracer->proxy_log), (l), "[" FLT_OT_SCOPE "]: [%s] " f "\n", conf->id, ##__VA_ARGS__); \
                                                                                                                                \
			FLT_OT_DBG(1, "LOG[%d]: %s", (l), logline);                                                             \
		}                                                                                                               \
	} while (0)

#endif /* _OPENTRACING_DEBUG_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
