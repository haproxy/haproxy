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
#ifndef _OPENTRACING_GROUP_H_
#define _OPENTRACING_GROUP_H_

#define FLT_OT_ACTION_GROUP   "ot-group"

enum FLT_OT_ARG_enum {
	FLT_OT_ARG_FILTER_ID = 0,
	FLT_OT_ARG_GROUP_ID,

	FLT_OT_ARG_FLT_CONF = 0,
	FLT_OT_ARG_CONF,
	FLT_OT_ARG_GROUP,
};

/*
 * A description of the macro arguments can be found in the structure
 * flt_ot_group_data definition
 */
#define FLT_OT_GROUP_DEFINES                                                     \
	FLT_OT_GROUP_DEF(ACT_F_TCP_REQ_CON, SMP_VAL_FE_CON_ACC, SMP_OPT_DIR_REQ) \
	FLT_OT_GROUP_DEF(ACT_F_TCP_REQ_SES, SMP_VAL_FE_SES_ACC, SMP_OPT_DIR_REQ) \
	FLT_OT_GROUP_DEF(ACT_F_TCP_REQ_CNT, SMP_VAL_FE_REQ_CNT, SMP_OPT_DIR_REQ) \
	FLT_OT_GROUP_DEF(ACT_F_TCP_RES_CNT, SMP_VAL_BE_RES_CNT, SMP_OPT_DIR_RES) \
	FLT_OT_GROUP_DEF(ACT_F_HTTP_REQ,    SMP_VAL_FE_HRQ_HDR, SMP_OPT_DIR_REQ) \
	FLT_OT_GROUP_DEF(ACT_F_HTTP_RES,    SMP_VAL_BE_HRS_HDR, SMP_OPT_DIR_RES)

struct flt_ot_group_data {
	enum act_from act_from;    /* ACT_F_* */
	uint          smp_val;     /* Valid FE/BE fetch location. */
	uint          smp_opt_dir; /* Fetch direction (request/response). */
};

#endif /* _OPENTRACING_GROUP_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
