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
#ifndef _OPENTRACING_CONFIG_H_
#define _OPENTRACING_CONFIG_H_

#undef  DEBUG_OT_SYSTIME
#define USE_POOL_BUFFER
#define USE_POOL_OT_SPAN_CONTEXT
#define USE_POOL_OT_SCOPE_SPAN
#define USE_POOL_OT_SCOPE_CONTEXT
#define USE_POOL_OT_RUNTIME_CONTEXT
#define USE_TRASH_CHUNK

#define FLT_OT_ID_MAXLEN        64
#define FLT_OT_MAXTAGS          8
#define FLT_OT_MAXBAGGAGES      8
#define FLT_OT_RATE_LIMIT_MAX   100.0
#define FLT_OT_DEBUG_LEVEL      0b00001111

#endif /* _OPENTRACING_CONFIG_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
