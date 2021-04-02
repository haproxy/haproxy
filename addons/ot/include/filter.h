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
#ifndef _OPENTRACING_FILTER_H_
#define _OPENTRACING_FILTER_H_

#define FLT_OT_FMT_NAME           "'" FLT_OT_OPT_NAME "' : "
#define FLT_OT_FMT_TYPE           "'filter' : "
#define FTL_OT_VAR_UUID           "sess", "ot", "uuid"
#define FLT_OT_ALERT(f, ...)      ha_alert(FLT_OT_FMT_TYPE FLT_OT_FMT_NAME f "\n", ##__VA_ARGS__)

#define FLT_OT_CONDITION_IF       "if"
#define FLT_OT_CONDITION_UNLESS   "unless"

enum FLT_OT_RET_enum {
	FLT_OT_RET_ERROR  = -1,
	FLT_OT_RET_WAIT   = 0,
	FLT_OT_RET_IGNORE = 0,
	FLT_OT_RET_OK     = 1,
};

#define FLT_OT_DBG_LIST(d,m,p,t,v,f)                                 \
	do {                                                         \
		if (LIST_ISEMPTY(&((d)->m##s))) {                    \
			FLT_OT_DBG(3, p "- no " #m "s " t);          \
		} else {                                             \
			const struct flt_ot_conf_##m *v;             \
                                                                     \
			FLT_OT_DBG(3, p "- " t " " #m "s: %s",       \
			           flt_ot_list_debug(&((d)->m##s))); \
			list_for_each_entry(v, &((d)->m##s), list)   \
				do { f; } while (0);                 \
		}                                                    \
	} while (0)


extern const char     *ot_flt_id;
extern struct flt_ops  flt_ot_ops;


bool flt_ot_is_disabled(const struct filter *f FLT_OT_DBG_ARGS(, int event));

#endif /* _OPENTRACING_FILTER_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
