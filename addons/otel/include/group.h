/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_GROUP_H_
#define _OTEL_GROUP_H_

#define FLT_OTEL_ACTION_GROUP   "otel-group"

/* Argument indices for the otel-group action rule. */
enum FLT_OTEL_ARG_enum {
	FLT_OTEL_ARG_FILTER_ID = 0,
	FLT_OTEL_ARG_GROUP_ID,

	FLT_OTEL_ARG_FLT_CONF = 0,
	FLT_OTEL_ARG_CONF,
	FLT_OTEL_ARG_GROUP,
};

/*
 * A description of the macro arguments can be found in the structure
 * flt_otel_group_data definition
 */
#define FLT_OTEL_GROUP_DEFINES                                                     \
	FLT_OTEL_GROUP_DEF(ACT_F_TCP_REQ_CON, SMP_VAL_FE_CON_ACC, SMP_OPT_DIR_REQ) \
	FLT_OTEL_GROUP_DEF(ACT_F_TCP_REQ_SES, SMP_VAL_FE_SES_ACC, SMP_OPT_DIR_REQ) \
	FLT_OTEL_GROUP_DEF(ACT_F_TCP_REQ_CNT, SMP_VAL_FE_REQ_CNT, SMP_OPT_DIR_REQ) \
	FLT_OTEL_GROUP_DEF(ACT_F_TCP_RES_CNT, SMP_VAL_BE_RES_CNT, SMP_OPT_DIR_RES) \
	FLT_OTEL_GROUP_DEF(ACT_F_HTTP_REQ,    SMP_VAL_FE_HRQ_HDR, SMP_OPT_DIR_REQ) \
	FLT_OTEL_GROUP_DEF(ACT_F_HTTP_RES,    SMP_VAL_BE_HRS_HDR, SMP_OPT_DIR_RES)

/* Per-action-from metadata mapping action types to fetch directions. */
struct flt_otel_group_data {
	enum act_from act_from;    /* ACT_F_* */
	uint          smp_val;     /* Valid FE/BE fetch location. */
	uint          smp_opt_dir; /* Fetch direction (request/response). */
};

#endif /* _OTEL_GROUP_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
