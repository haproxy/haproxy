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
#ifndef _OPENTRACING_CLI_H_
#define _OPENTRACING_CLI_H_

#define FLT_OT_CLI_CMD                 "flt-ot"

#define FLT_OT_CLI_LOGGING_OFF         "off"
#define FLT_OT_CLI_LOGGING_ON          "on"
#define FLT_OT_CLI_LOGGING_NOLOGNORM   "dontlog-normal"
#define FLT_OT_CLI_LOGGING_STATE(a)    ((a) & FLT_OT_LOGGING_ON) ? (((a) & FLT_OT_LOGGING_NOLOGNORM) ? "enabled, " FLT_OT_CLI_LOGGING_NOLOGNORM : "enabled") : "disabled"

#define FLT_OT_CLI_MSG_CAT(a)          ((a) == NULL) ? "" : (a), ((a) == NULL) ? "" : "\n"

enum FLT_OT_LOGGING_enum {
	FLT_OT_LOGGING_OFF       = 0,
	FLT_OT_LOGGING_ON        = 1 << 0,
	FLT_OT_LOGGING_NOLOGNORM = 1 << 1,
};


void flt_ot_cli_init(void);

#endif /* _OPENTRACING_CLI_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
