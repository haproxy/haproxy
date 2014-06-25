/*
 * Sample management functions.
 *
 * Copyright 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#include <types/global.h>

#include <common/chunk.h>
#include <common/standard.h>
#include <common/uri_auth.h>
#include <common/base64.h>

#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/stick_table.h>

/* sample type names */
const char *smp_to_type[SMP_TYPES] = {
	[SMP_T_BOOL] = "bool",
	[SMP_T_UINT] = "uint",
	[SMP_T_SINT] = "sint",
	[SMP_T_ADDR] = "addr",
	[SMP_T_IPV4] = "ipv4",
	[SMP_T_IPV6] = "ipv6",
	[SMP_T_STR]  = "str",
	[SMP_T_BIN]  = "bin",
};

/* static sample used in sample_process() when <p> is NULL */
static struct sample temp_smp;

/* list head of all known sample fetch keywords */
static struct sample_fetch_kw_list sample_fetches = {
	.list = LIST_HEAD_INIT(sample_fetches.list)
};

/* list head of all known sample format conversion keywords */
static struct sample_conv_kw_list sample_convs = {
	.list = LIST_HEAD_INIT(sample_convs.list)
};

const unsigned int fetch_cap[SMP_SRC_ENTRIES] = {
	[SMP_SRC_INTRN] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_LISTN] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_FTEND] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_L4CLI] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_L5CLI] = (SMP_VAL___________ | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_TRACK] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_L6REQ] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________),

	[SMP_SRC_HRQHV] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________),

	[SMP_SRC_HRQHP] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_HRQBO] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________),

	[SMP_SRC_BKEND] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_SERVR] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_L4SRV] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_L5SRV] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_L6RES] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL___________),

	[SMP_SRC_HRSHV] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL___________),

	[SMP_SRC_HRSHP] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_HRSBO] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL___________),

	[SMP_SRC_RQFIN] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_RSFIN] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_TXFIN] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_FE_LOG_END),

	[SMP_SRC_SSFIN] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_FE_LOG_END),
};

static const char *fetch_src_names[SMP_SRC_ENTRIES] = {
	[SMP_SRC_INTRN] = "internal state",
	[SMP_SRC_LISTN] = "listener",
	[SMP_SRC_FTEND] = "frontend",
	[SMP_SRC_L4CLI] = "client address",
	[SMP_SRC_L5CLI] = "client-side connection",
	[SMP_SRC_TRACK] = "track counters",
	[SMP_SRC_L6REQ] = "request buffer",
	[SMP_SRC_HRQHV] = "HTTP request headers",
	[SMP_SRC_HRQHP] = "HTTP request",
	[SMP_SRC_HRQBO] = "HTTP request body",
	[SMP_SRC_BKEND] = "backend",
	[SMP_SRC_SERVR] = "server",
	[SMP_SRC_L4SRV] = "server address",
	[SMP_SRC_L5SRV] = "server-side connection",
	[SMP_SRC_L6RES] = "response buffer",
	[SMP_SRC_HRSHV] = "HTTP response headers",
	[SMP_SRC_HRSHP] = "HTTP response",
	[SMP_SRC_HRSBO] = "HTTP response body",
	[SMP_SRC_RQFIN] = "request buffer statistics",
	[SMP_SRC_RSFIN] = "response buffer statistics",
	[SMP_SRC_TXFIN] = "transaction statistics",
	[SMP_SRC_SSFIN] = "session statistics",
};

static const char *fetch_ckp_names[SMP_CKP_ENTRIES] = {
	[SMP_CKP_FE_CON_ACC] = "frontend tcp-request connection rule",
	[SMP_CKP_FE_SES_ACC] = "frontend tcp-request session rule",
	[SMP_CKP_FE_REQ_CNT] = "frontend tcp-request content rule",
	[SMP_CKP_FE_HRQ_HDR] = "frontend http-request header rule",
	[SMP_CKP_FE_HRQ_BDY] = "frontend http-request body rule",
	[SMP_CKP_FE_SET_BCK] = "frontend use-backend rule",
	[SMP_CKP_BE_REQ_CNT] = "backend tcp-request content rule",
	[SMP_CKP_BE_HRQ_HDR] = "backend http-request header rule",
	[SMP_CKP_BE_HRQ_BDY] = "backend http-request body rule",
	[SMP_CKP_BE_SET_SRV] = "backend use-server, balance or stick-match rule",
	[SMP_CKP_BE_SRV_CON] = "server source selection",
	[SMP_CKP_BE_RES_CNT] = "backend tcp-response content rule",
	[SMP_CKP_BE_HRS_HDR] = "backend http-response header rule",
	[SMP_CKP_BE_HRS_BDY] = "backend http-response body rule",
	[SMP_CKP_BE_STO_RUL] = "backend stick-store rule",
	[SMP_CKP_FE_RES_CNT] = "frontend tcp-response content rule",
	[SMP_CKP_FE_HRS_HDR] = "frontend http-response header rule",
	[SMP_CKP_FE_HRS_BDY] = "frontend http-response body rule",
	[SMP_CKP_FE_LOG_END] = "logs",
};

/* This function returns the type of the data returned by the sample_expr.
 * It assumes that the <expr> and all of its converters are properly
 * initialized.
 */
inline
int smp_expr_output_type(struct sample_expr *expr)
{
	struct sample_conv_expr *smp_expr;

	if (!LIST_ISEMPTY(&expr->conv_exprs)) {
		smp_expr = LIST_PREV(&expr->conv_exprs, struct sample_conv_expr *, list);
		return smp_expr->conv->out_type;
	}
	return expr->fetch->out_type;
}


/* fill the trash with a comma-delimited list of source names for the <use> bit
 * field which must be composed of a non-null set of SMP_USE_* flags. The return
 * value is the pointer to the string in the trash buffer.
 */
const char *sample_src_names(unsigned int use)
{
	int bit;

	trash.len = 0;
	trash.str[0] = '\0';
	for (bit = 0; bit < SMP_SRC_ENTRIES; bit++) {
		if (!(use & ~((1 << bit) - 1)))
			break; /* no more bits */

		if (!(use & (1 << bit)))
			continue; /* bit not set */

		trash.len += snprintf(trash.str + trash.len, trash.size - trash.len, "%s%s",
				      (use & ((1 << bit) - 1)) ? "," : "",
		                      fetch_src_names[bit]);
	}
	return trash.str;
}

/* return a pointer to the correct sample checkpoint name, or "unknown" when
 * the flags are invalid. Only the lowest bit is used, higher bits are ignored
 * if set.
 */
const char *sample_ckp_names(unsigned int use)
{
	int bit;

	for (bit = 0; bit < SMP_CKP_ENTRIES; bit++)
		if (use & (1 << bit))
			return fetch_ckp_names[bit];
	return "unknown sample check place, please report this bug";
}

/*
 * Registers the sample fetch keyword list <kwl> as a list of valid keywords
 * for next parsing sessions. The fetch keywords capabilities are also computed
 * from their ->use field.
 */
void sample_register_fetches(struct sample_fetch_kw_list *kwl)
{
	struct sample_fetch *sf;
	int bit;

	for (sf = kwl->kw; sf->kw != NULL; sf++) {
		for (bit = 0; bit < SMP_SRC_ENTRIES; bit++)
			if (sf->use & (1 << bit))
				sf->val |= fetch_cap[bit];
	}
	LIST_ADDQ(&sample_fetches.list, &kwl->list);
}

/*
 * Registers the sample format coverstion keyword list <pckl> as a list of valid keywords for next
 * parsing sessions.
 */
void sample_register_convs(struct sample_conv_kw_list *pckl)
{
	LIST_ADDQ(&sample_convs.list, &pckl->list);
}

/*
 * Returns the pointer on sample fetch keyword structure identified by
 * string of <len> in buffer <kw>.
 *
 */
struct sample_fetch *find_sample_fetch(const char *kw, int len)
{
	int index;
	struct sample_fetch_kw_list *kwl;

	list_for_each_entry(kwl, &sample_fetches.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (strncmp(kwl->kw[index].kw, kw, len) == 0 &&
			    kwl->kw[index].kw[len] == '\0')
				return &kwl->kw[index];
		}
	}
	return NULL;
}

/*
 * Returns the pointer on sample format conversion keyword structure identified by
 * string of <len> in buffer <kw>.
 *
 */
struct sample_conv *find_sample_conv(const char *kw, int len)
{
	int index;
	struct sample_conv_kw_list *kwl;

	list_for_each_entry(kwl, &sample_convs.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (strncmp(kwl->kw[index].kw, kw, len) == 0 &&
			    kwl->kw[index].kw[len] == '\0')
				return &kwl->kw[index];
		}
	}
	return NULL;
}

/******************************************************************/
/*          Sample casts functions                                */
/*   Note: these functions do *NOT* set the output type on the    */
/*   sample, the caller is responsible for doing this on return.  */
/******************************************************************/

static int c_ip2int(struct sample *smp)
{
	smp->data.uint = ntohl(smp->data.ipv4.s_addr);
	smp->type = SMP_T_UINT;
	return 1;
}

static int c_ip2str(struct sample *smp)
{
	struct chunk *trash = get_trash_chunk();

	if (!inet_ntop(AF_INET, (void *)&smp->data.ipv4, trash->str, trash->size))
		return 0;

	trash->len = strlen(trash->str);
	smp->data.str = *trash;
	smp->type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;

	return 1;
}

static int c_ip2ipv6(struct sample *smp)
{
	v4tov6(&smp->data.ipv6, &smp->data.ipv4);
	smp->type = SMP_T_IPV6;
	return 1;
}

static int c_ipv62str(struct sample *smp)
{
	struct chunk *trash = get_trash_chunk();

	if (!inet_ntop(AF_INET6, (void *)&smp->data.ipv6, trash->str, trash->size))
		return 0;

	trash->len = strlen(trash->str);
	smp->data.str = *trash;
	smp->type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/*
static int c_ipv62ip(struct sample *smp)
{
	return v6tov4(&smp->data.ipv4, &smp->data.ipv6);
}
*/

static int c_int2ip(struct sample *smp)
{
	smp->data.ipv4.s_addr = htonl(smp->data.uint);
	smp->type = SMP_T_IPV4;
	return 1;
}

static int c_str2addr(struct sample *smp)
{
	if (!buf2ip(smp->data.str.str, smp->data.str.len, &smp->data.ipv4)) {
		if (!buf2ip6(smp->data.str.str, smp->data.str.len, &smp->data.ipv6))
			return 0;
		smp->type = SMP_T_IPV6;
		smp->flags &= ~SMP_F_CONST;
		return 1;
	}
	smp->type = SMP_T_IPV4;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int c_str2ip(struct sample *smp)
{
	if (!buf2ip(smp->data.str.str, smp->data.str.len, &smp->data.ipv4))
		return 0;
	smp->type = SMP_T_IPV4;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int c_str2ipv6(struct sample *smp)
{
	if (!buf2ip6(smp->data.str.str, smp->data.str.len, &smp->data.ipv6))
		return 0;
	smp->type = SMP_T_IPV6;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* The sample is always copied into a new one so that smp->size is always
 * valid. The NULL char always enforces the end of string if it is met.
 */
static int c_bin2str(struct sample *smp)
{
	struct chunk *trash = get_trash_chunk();
	unsigned char c;
	int ptr = 0;

	while (ptr < smp->data.str.len) {
		c = smp->data.str.str[ptr];
		if (!c)
			break;
		trash->str[ptr] = c;
		ptr++;
	}
	trash->len = ptr;
	trash->str[ptr] = 0;
	smp->data.str = *trash;
	smp->type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int c_int2str(struct sample *smp)
{
	struct chunk *trash = get_trash_chunk();
	char *pos;

	pos = ultoa_r(smp->data.uint, trash->str, trash->size);

	if (!pos)
		return 0;

	trash->size = trash->size - (pos - trash->str);
	trash->str = pos;
	trash->len = strlen(pos);
	smp->data.str = *trash;
	smp->type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* This function duplicates data and removes the flag "const". */
int smp_dup(struct sample *smp)
{
	struct chunk *trash;

	/* If the const flag is not set, we don't need to duplicate the
	 * pattern as it can be modified in place.
	 */
	if (!(smp->flags & SMP_F_CONST))
		return 1;

	switch (smp->type) {
	case SMP_T_BOOL:
	case SMP_T_UINT:
	case SMP_T_SINT:
	case SMP_T_ADDR:
	case SMP_T_IPV4:
	case SMP_T_IPV6:
		/* These type are not const. */
		break;
	case SMP_T_STR:
	case SMP_T_BIN:
		/* Duplicate data. */
		trash = get_trash_chunk();
		trash->len = smp->data.str.len < trash->size ? smp->data.str.len : trash->size;
		memcpy(trash->str, smp->data.str.str, trash->len);
		smp->data.str = *trash;
		break;
	default:
		/* Other cases are unexpected. */
		return 0;
	}

	/* remove const flag */
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

int c_none(struct sample *smp)
{
	return 1;
}

static int c_str2int(struct sample *smp)
{
	int i;
	uint32_t ret = 0;

	if (smp->data.str.len == 0)
		return 0;

	for (i = 0; i < smp->data.str.len; i++) {
		uint32_t val = smp->data.str.str[i] - '0';

		if (val > 9) {
			if (i == 0)
				return 0;
			break;
		}

		ret = ret * 10 + val;
	}

	smp->data.uint = ret;
	smp->type = SMP_T_UINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int c_str2meth(struct sample *smp)
{
	enum http_meth_t meth;
	int len;

	meth = find_http_meth(smp->data.str.str, smp->data.str.len);
	if (meth == HTTP_METH_OTHER) {
		len = smp->data.str.len;
		smp->data.meth.str.str = smp->data.str.str;
		smp->data.meth.str.len = len;
	}
	else
		smp->flags &= ~SMP_F_CONST;
	smp->data.meth.meth = meth;
	smp->type = SMP_T_METH;
	return 1;
}

static int c_meth2str(struct sample *smp)
{
	int len;
	enum http_meth_t meth;

	if (smp->data.meth.meth == HTTP_METH_OTHER) {
		/* The method is unknown. Copy the original pointer. */
		len = smp->data.meth.str.len;
		smp->data.str.str = smp->data.meth.str.str;
		smp->data.str.len = len;
		smp->type = SMP_T_STR;
	}
	else if (smp->data.meth.meth < HTTP_METH_OTHER) {
		/* The method is known, copy the pointer containing the string. */
		meth = smp->data.meth.meth;
		smp->data.str.str = http_known_methods[meth].name;
		smp->data.str.len = http_known_methods[meth].len;
		smp->flags |= SMP_F_CONST;
		smp->type = SMP_T_STR;
	}
	else {
		/* Unknown method */
		return 0;
	}
	return 1;
}

/*****************************************************************/
/*      Sample casts matrix:                                     */
/*           sample_casts[from type][to type]                    */
/*           NULL pointer used for impossible sample casts       */
/*****************************************************************/

sample_cast_fct sample_casts[SMP_TYPES][SMP_TYPES] = {
/*            to:  BOOL       UINT       SINT       ADDR        IPV4      IPV6        STR         BIN         METH */
/* from: BOOL */ { c_none,    c_none,    c_none,    NULL,       NULL,     NULL,       c_int2str,  NULL,       NULL,       },
/*       UINT */ { c_none,    c_none,    c_none,    c_int2ip,   c_int2ip, NULL,       c_int2str,  NULL,       NULL,       },
/*       SINT */ { c_none,    c_none,    c_none,    c_int2ip,   c_int2ip, NULL,       c_int2str,  NULL,       NULL,       },
/*       ADDR */ { NULL,      NULL,      NULL,      NULL,       NULL,     NULL,       NULL,       NULL,       NULL,       },
/*       IPV4 */ { NULL,      c_ip2int,  c_ip2int,  c_none,     c_none,   c_ip2ipv6,  c_ip2str,   NULL,       NULL,       },
/*       IPV6 */ { NULL,      NULL,      NULL,      c_none,     NULL,     c_none,     c_ipv62str, NULL,       NULL,       },
/*        STR */ { c_str2int, c_str2int, c_str2int, c_str2addr, c_str2ip, c_str2ipv6, c_none,     c_none,     c_str2meth, },
/*        BIN */ { NULL,      NULL,      NULL,      NULL,       NULL,     NULL,       c_bin2str,  c_none,     c_str2meth, },
/*       METH */ { NULL,      NULL,      NULL,      NULL,       NULL,     NULL,       c_meth2str, c_meth2str, c_none,     },
};

/*
 * Parse a sample expression configuration:
 *        fetch keyword followed by format conversion keywords.
 * Returns a pointer on allocated sample expression structure.
 * The caller must have set al->ctx.
 */
struct sample_expr *sample_parse_expr(char **str, int *idx, const char *file, int line, char **err_msg, struct arg_list *al)
{
	const char *begw; /* beginning of word */
	const char *endw; /* end of word */
	const char *endt; /* end of term */
	struct sample_expr *expr;
	struct sample_fetch *fetch;
	struct sample_conv *conv;
	unsigned long prev_type;
	char *fkw = NULL;
	char *ckw = NULL;
	int err_arg;

	begw = str[*idx];
	for (endw = begw; *endw && *endw != '(' && *endw != ','; endw++);

	if (endw == begw) {
		memprintf(err_msg, "missing fetch method");
		goto out_error;
	}

	/* keep a copy of the current fetch keyword for error reporting */
	fkw = my_strndup(begw, endw - begw);

	fetch = find_sample_fetch(begw, endw - begw);
	if (!fetch) {
		memprintf(err_msg, "unknown fetch method '%s'", fkw);
		goto out_error;
	}

	endt = endw;
	if (*endt == '(') {
		/* look for the end of this term and skip the opening parenthesis */
		endt = ++endw;
		while (*endt && *endt != ')')
			endt++;
		if (*endt != ')') {
			memprintf(err_msg, "missing closing ')' after arguments to fetch keyword '%s'", fkw);
			goto out_error;
		}
	}

	/* At this point, we have :
	 *   - begw : beginning of the keyword
	 *   - endw : end of the keyword, first character not part of keyword
	 *            nor the opening parenthesis (so first character of args
	 *            if present).
	 *   - endt : end of the term (=endw or last parenthesis if args are present)
	 */

	if (fetch->out_type >= SMP_TYPES) {
		memprintf(err_msg, "returns type of fetch method '%s' is unknown", fkw);
		goto out_error;
	}
	prev_type = fetch->out_type;

	expr = calloc(1, sizeof(struct sample_expr));
	if (!expr)
		goto out_error;

	LIST_INIT(&(expr->conv_exprs));
	expr->fetch = fetch;
	expr->arg_p = empty_arg_list;

	/* Note that we call the argument parser even with an empty string,
	 * this allows it to automatically create entries for mandatory
	 * implicit arguments (eg: local proxy name).
	 */
	al->kw = expr->fetch->kw;
	al->conv = NULL;
	if (make_arg_list(endw, endt - endw, fetch->arg_mask, &expr->arg_p, err_msg, NULL, &err_arg, al) < 0) {
		memprintf(err_msg, "fetch method '%s' : %s", fkw, *err_msg);
		goto out_error;
	}

	if (!expr->arg_p) {
		expr->arg_p = empty_arg_list;
	}
	else if (fetch->val_args && !fetch->val_args(expr->arg_p, err_msg)) {
		memprintf(err_msg, "invalid args in fetch method '%s' : %s", fkw, *err_msg);
		goto out_error;
	}

	/* Now process the converters if any. We have two supported syntaxes
	 * for the converters, which can be combined :
	 *  - comma-delimited list of converters just after the keyword and args ;
	 *  - one converter per keyword
	 * The combination allows to have each keyword being a comma-delimited
	 * series of converters.
	 *
	 * We want to process the former first, then the latter. For this we start
	 * from the beginning of the supposed place in the exiting conv chain, which
	 * starts at the last comma (endt).
	 */

	while (1) {
		struct sample_conv_expr *conv_expr;

		if (*endt == ')') /* skip last closing parenthesis */
			endt++;

		if (*endt && *endt != ',') {
			if (ckw)
				memprintf(err_msg, "missing comma after conv keyword '%s'", ckw);
			else
				memprintf(err_msg, "missing comma after fetch keyword '%s'", fkw);
			goto out_error;
		}

		while (*endt == ',') /* then trailing commas */
			endt++;

		begw = endt; /* start of conv keyword */

		if (!*begw) {
			/* none ? skip to next string */
			(*idx)++;
			begw = str[*idx];
			if (!begw || !*begw)
				break;
		}

		for (endw = begw; *endw && *endw != '(' && *endw != ','; endw++);

		free(ckw);
		ckw = my_strndup(begw, endw - begw);

		conv = find_sample_conv(begw, endw - begw);
		if (!conv) {
			/* we found an isolated keyword that we don't know, it's not ours */
			if (begw == str[*idx])
				break;
			memprintf(err_msg, "unknown conv method '%s'", ckw);
			goto out_error;
		}

		endt = endw;
		if (*endt == '(') {
			/* look for the end of this term */
			while (*endt && *endt != ')')
				endt++;
			if (*endt != ')') {
				memprintf(err_msg, "syntax error: missing ')' after conv keyword '%s'", ckw);
				goto out_error;
			}
		}

		if (conv->in_type >= SMP_TYPES || conv->out_type >= SMP_TYPES) {
			memprintf(err_msg, "returns type of conv method '%s' is unknown", ckw);
			goto out_error;
		}

		/* If impossible type conversion */
		if (!sample_casts[prev_type][conv->in_type]) {
			memprintf(err_msg, "conv method '%s' cannot be applied", ckw);
			goto out_error;
		}

		prev_type = conv->out_type;
		conv_expr = calloc(1, sizeof(struct sample_conv_expr));
		if (!conv_expr)
			goto out_error;

		LIST_ADDQ(&(expr->conv_exprs), &(conv_expr->list));
		conv_expr->conv = conv;

		if (endt != endw) {
			int err_arg;

			if (!conv->arg_mask) {
				memprintf(err_msg, "conv method '%s' does not support any args", ckw);
				goto out_error;
			}

			al->kw = expr->fetch->kw;
			al->conv = conv_expr->conv->kw;
			if (make_arg_list(endw + 1, endt - endw - 1, conv->arg_mask, &conv_expr->arg_p, err_msg, NULL, &err_arg, al) < 0) {
				memprintf(err_msg, "invalid arg %d in conv method '%s' : %s", err_arg+1, ckw, *err_msg);
				goto out_error;
			}

			if (!conv_expr->arg_p)
				conv_expr->arg_p = empty_arg_list;

			if (conv->val_args && !conv->val_args(conv_expr->arg_p, conv, file, line, err_msg)) {
				memprintf(err_msg, "invalid args in conv method '%s' : %s", ckw, *err_msg);
				goto out_error;
			}
		}
		else if (ARGM(conv->arg_mask)) {
			memprintf(err_msg, "missing args for conv method '%s'", ckw);
			goto out_error;
		}
	}

 out:
	free(fkw);
	free(ckw);
	return expr;

out_error:
	/* TODO: prune_sample_expr(expr); */
	expr = NULL;
	goto out;
}

/*
 * Process a fetch + format conversion of defined by the sample expression <expr>
 * on request or response considering the <opt> parameter.
 * Returns a pointer on a typed sample structure containing the result or NULL if
 * sample is not found or when format conversion failed.
 *  If <p> is not null, function returns results in structure pointed by <p>.
 *  If <p> is null, functions returns a pointer on a static sample structure.
 *
 * Note: the fetch functions are required to properly set the return type. The
 * conversion functions must do so too. However the cast functions do not need
 * to since they're made to cast mutiple types according to what is required.
 */
struct sample *sample_process(struct proxy *px, struct session *l4, void *l7,
                              unsigned int opt,
                              struct sample_expr *expr, struct sample *p)
{
	struct sample_conv_expr *conv_expr;

	if (p == NULL) {
		p = &temp_smp;
		memset(p, 0, sizeof(*p));
	}

	if (!expr->fetch->process(px, l4, l7, opt, expr->arg_p, p, expr->fetch->kw))
		return NULL;

	list_for_each_entry(conv_expr, &expr->conv_exprs, list) {
		/* we want to ensure that p->type can be casted into
		 * conv_expr->conv->in_type. We have 3 possibilities :
		 *  - NULL   => not castable.
		 *  - c_none => nothing to do (let's optimize it)
		 *  - other  => apply cast and prepare to fail
		 */
		if (!sample_casts[p->type][conv_expr->conv->in_type])
			return NULL;

		if (sample_casts[p->type][conv_expr->conv->in_type] != c_none &&
		    !sample_casts[p->type][conv_expr->conv->in_type](p))
			return NULL;

		/* OK cast succeeded */

		if (!conv_expr->conv->process(conv_expr->arg_p, p))
			return NULL;
	}
	return p;
}

/*
 * Resolve all remaining arguments in proxy <p>. Returns the number of
 * errors or 0 if everything is fine.
 */
int smp_resolve_args(struct proxy *p)
{
	struct arg_list *cur, *bak;
	const char *ctx, *where;
	const char *conv_ctx, *conv_pre, *conv_pos;
	struct userlist *ul;
	struct arg *arg;
	int cfgerr = 0;

	list_for_each_entry_safe(cur, bak, &p->conf.args.list, list) {
		struct proxy *px;
		struct server *srv;
		char *pname, *sname;

		arg = cur->arg;

		/* prepare output messages */
		conv_pre = conv_pos = conv_ctx = "";
		if (cur->conv) {
			conv_ctx = cur->conv;
			conv_pre = "conversion keyword '";
			conv_pos = "' for ";
		}

		where = "in";
		ctx = "sample fetch keyword";
		switch (cur->ctx) {
		case ARGC_STK:where = "in stick rule in"; break;
		case ARGC_TRK: where = "in tracking rule in"; break;
		case ARGC_LOG: where = "in log-format string in"; break;
		case ARGC_HRQ: where = "in http-request header format string in"; break;
		case ARGC_HRS: where = "in http-response header format string in"; break;
		case ARGC_UIF: where = "in unique-id-format string in"; break;
		case ARGC_RDR: where = "in redirect format string in"; break;
		case ARGC_CAP: where = "in capture rule in"; break;
		case ARGC_ACL: ctx = "ACL keyword"; break;
		}

		/* set a few default settings */
		px = p;
		pname = p->id;

		switch (arg->type) {
		case ARGT_SRV:
			if (!arg->data.str.len) {
				Alert("parsing [%s:%d] : missing server name in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
				      cur->file, cur->line,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				continue;
			}

			/* we support two formats : "bck/srv" and "srv" */
			sname = strrchr(arg->data.str.str, '/');

			if (sname) {
				*sname++ = '\0';
				pname = arg->data.str.str;

				px = findproxy(pname, PR_CAP_BE);
				if (!px) {
					Alert("parsing [%s:%d] : unable to find proxy '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					      cur->file, cur->line, pname,
					      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
					cfgerr++;
					break;
				}
			}
			else
				sname = arg->data.str.str;

			srv = findserver(px, sname);
			if (!srv) {
				Alert("parsing [%s:%d] : unable to find server '%s' in proxy '%s', referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
				      cur->file, cur->line, sname, pname,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			free(arg->data.str.str);
			arg->data.str.str = NULL;
			arg->unresolved = 0;
			arg->data.srv = srv;
			break;

		case ARGT_FE:
			if (arg->data.str.len) {
				pname = arg->data.str.str;
				px = findproxy(pname, PR_CAP_FE);
			}

			if (!px) {
				Alert("parsing [%s:%d] : unable to find frontend '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
				      cur->file, cur->line, pname,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			if (!(px->cap & PR_CAP_FE)) {
				Alert("parsing [%s:%d] : proxy '%s', referenced in arg %d of %s%s%s%s '%s' %s proxy '%s', has not frontend capability.\n",
				      cur->file, cur->line, pname,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			free(arg->data.str.str);
			arg->data.str.str = NULL;
			arg->unresolved = 0;
			arg->data.prx = px;
			break;

		case ARGT_BE:
			if (arg->data.str.len) {
				pname = arg->data.str.str;
				px = findproxy(pname, PR_CAP_BE);
			}

			if (!px) {
				Alert("parsing [%s:%d] : unable to find backend '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
				      cur->file, cur->line, pname,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			if (!(px->cap & PR_CAP_BE)) {
				Alert("parsing [%s:%d] : proxy '%s', referenced in arg %d of %s%s%s%s '%s' %s proxy '%s', has not backend capability.\n",
				      cur->file, cur->line, pname,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			free(arg->data.str.str);
			arg->data.str.str = NULL;
			arg->unresolved = 0;
			arg->data.prx = px;
			break;

		case ARGT_TAB:
			if (arg->data.str.len) {
				pname = arg->data.str.str;
				px = find_stktable(pname);
			}

			if (!px) {
				Alert("parsing [%s:%d] : unable to find table '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
				      cur->file, cur->line, pname,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			if (!px->table.size) {
				Alert("parsing [%s:%d] : no table in proxy '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
				      cur->file, cur->line, pname,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			free(arg->data.str.str);
			arg->data.str.str = NULL;
			arg->unresolved = 0;
			arg->data.prx = px;
			break;

		case ARGT_USR:
			if (!arg->data.str.len) {
				Alert("parsing [%s:%d] : missing userlist name in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
				      cur->file, cur->line,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			if (p->uri_auth && p->uri_auth->userlist &&
			    !strcmp(p->uri_auth->userlist->name, arg->data.str.str))
				ul = p->uri_auth->userlist;
			else
				ul = auth_find_userlist(arg->data.str.str);

			if (!ul) {
				Alert("parsing [%s:%d] : unable to find userlist '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
				      cur->file, cur->line, arg->data.str.str,
				      cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			free(arg->data.str.str);
			arg->data.str.str = NULL;
			arg->unresolved = 0;
			arg->data.usr = ul;
			break;
		}

		LIST_DEL(&cur->list);
		free(cur);
	} /* end of args processing */

	return cfgerr;
}

/*
 * Process a fetch + format conversion as defined by the sample expression
 * <expr> on request or response considering the <opt> parameter. The output is
 * always of type string. If a stable sample can be fetched, or an unstable one
 * when <opt> contains SMP_OPT_FINAL, the sample is converted to a string and
 * returned without the SMP_F_MAY_CHANGE flag. If an unstable sample is found
 * and <opt> does not contain SMP_OPT_FINAL, then the sample is returned as-is
 * with its SMP_F_MAY_CHANGE flag so that the caller can check it and decide to
 * take actions (eg: wait longer). If a sample could not be found or could not
 * be converted, NULL is returned.
 */
struct sample *sample_fetch_string(struct proxy *px, struct session *l4, void *l7,
                                   unsigned int opt, struct sample_expr *expr)
{
	struct sample *smp = &temp_smp;

	memset(smp, 0, sizeof(*smp));

	if (!sample_process(px, l4, l7, opt, expr, smp)) {
		if ((smp->flags & SMP_F_MAY_CHANGE) && !(opt & SMP_OPT_FINAL))
			return smp;
		return NULL;
	}

	if (!sample_casts[smp->type][SMP_T_STR])
		return NULL;

	if (!sample_casts[smp->type][SMP_T_STR](smp))
		return NULL;

	smp->type = SMP_T_STR;
	smp->flags &= ~SMP_F_MAY_CHANGE;
	return smp;
}

/*****************************************************************/
/*    Sample format convert functions                            */
/*    These functions set the data type on return.               */
/*****************************************************************/

static int sample_conv_bin2base64(const struct arg *arg_p, struct sample *smp)
{
	struct chunk *trash = get_trash_chunk();
	int b64_len;

	trash->len = 0;
	b64_len = a2base64(smp->data.str.str, smp->data.str.len, trash->str, trash->size);
	if (b64_len < 0)
		return 0;

	trash->len = b64_len;
	smp->data.str = *trash;
	smp->type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int sample_conv_bin2hex(const struct arg *arg_p, struct sample *smp)
{
	struct chunk *trash = get_trash_chunk();
	unsigned char c;
	int ptr = 0;

	trash->len = 0;
	while (ptr < smp->data.str.len && trash->len <= trash->size - 2) {
		c = smp->data.str.str[ptr++];
		trash->str[trash->len++] = hextab[(c >> 4) & 0xF];
		trash->str[trash->len++] = hextab[c & 0xF];
	}
	smp->data.str = *trash;
	smp->type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int sample_conv_str2lower(const struct arg *arg_p, struct sample *smp)
{
	int i;

	if (!smp_dup(smp))
		return 0;

	if (!smp->data.str.size)
		return 0;

	for (i = 0; i < smp->data.str.len; i++) {
		if ((smp->data.str.str[i] >= 'A') && (smp->data.str.str[i] <= 'Z'))
			smp->data.str.str[i] += 'a' - 'A';
	}
	return 1;
}

static int sample_conv_str2upper(const struct arg *arg_p, struct sample *smp)
{
	int i;

	if (!smp_dup(smp))
		return 0;

	if (!smp->data.str.size)
		return 0;

	for (i = 0; i < smp->data.str.len; i++) {
		if ((smp->data.str.str[i] >= 'a') && (smp->data.str.str[i] <= 'z'))
			smp->data.str.str[i] += 'A' - 'a';
	}
	return 1;
}

/* takes the netmask in arg_p */
static int sample_conv_ipmask(const struct arg *arg_p, struct sample *smp)
{
	smp->data.ipv4.s_addr &= arg_p->data.ipv4.s_addr;
	smp->type = SMP_T_IPV4;
	return 1;
}

/************************************************************************/
/*       All supported sample fetch functions must be declared here     */
/************************************************************************/

/* force TRUE to be returned at the fetch level */
static int
smp_fetch_true(struct proxy *px, struct session *s, void *l7, unsigned int opt,
               const struct arg *args, struct sample *smp, const char *kw)
{
	smp->type = SMP_T_BOOL;
	smp->data.uint = 1;
	return 1;
}

/* force FALSE to be returned at the fetch level */
static int
smp_fetch_false(struct proxy *px, struct session *s, void *l7, unsigned int opt,
                const struct arg *args, struct sample *smp, const char *kw)
{
	smp->type = SMP_T_BOOL;
	smp->data.uint = 0;
	return 1;
}

/* retrieve environment variable $1 as a string */
static int
smp_fetch_env(struct proxy *px, struct session *s, void *l7, unsigned int opt,
              const struct arg *args, struct sample *smp, const char *kw)
{
	char *env;

	if (!args || args[0].type != ARGT_STR)
		return 0;

	env = getenv(args[0].data.str.str);
	if (!env)
		return 0;

	smp->type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.str.str = env;
	smp->data.str.len = strlen(env);
	return 1;
}

/* retrieve the current local date in epoch time, and applies an optional offset
 * of args[0] seconds.
 */
static int
smp_fetch_date(struct proxy *px, struct session *s, void *l7, unsigned int opt,
               const struct arg *args, struct sample *smp, const char *kw)
{
	smp->data.uint = date.tv_sec;

	/* add offset */
	if (args && (args[0].type == ARGT_SINT || args[0].type == ARGT_UINT))
		smp->data.uint += args[0].data.sint;

	smp->type = SMP_T_UINT;
	smp->flags |= SMP_F_VOL_TEST | SMP_F_MAY_CHANGE;
	return 1;
}

/* generate a random 32-bit integer for whatever purpose, with an optional
 * range specified in argument.
 */
static int
smp_fetch_rand(struct proxy *px, struct session *s, void *l7, unsigned int opt,
               const struct arg *args, struct sample *smp, const char *kw)
{
	smp->data.uint = random();

	/* reduce if needed. Don't do a modulo, use all bits! */
	if (args && args[0].type == ARGT_UINT)
		smp->data.uint = ((uint64_t)smp->data.uint * args[0].data.uint) >> 32;

	smp->type = SMP_T_UINT;
	smp->flags |= SMP_F_VOL_TEST | SMP_F_MAY_CHANGE;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Note: fetches that may return multiple types must be declared as the lowest
 * common denominator, the type that can be casted into all other ones. For
 * instance IPv4/IPv6 must be declared IPv4.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "always_false", smp_fetch_false, 0,            NULL, SMP_T_BOOL, SMP_USE_INTRN },
	{ "always_true",  smp_fetch_true,  0,            NULL, SMP_T_BOOL, SMP_USE_INTRN },
	{ "env",          smp_fetch_env,   ARG1(1,STR),  NULL, SMP_T_STR,  SMP_USE_INTRN },
	{ "date",         smp_fetch_date,  ARG1(0,SINT), NULL, SMP_T_UINT, SMP_USE_INTRN },
	{ "rand",         smp_fetch_rand,  ARG1(0,UINT), NULL, SMP_T_UINT, SMP_USE_INTRN },
	{ /* END */ },
}};

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "base64", sample_conv_bin2base64,0,            NULL, SMP_T_BIN,  SMP_T_STR  },
	{ "upper",  sample_conv_str2upper, 0,            NULL, SMP_T_STR,  SMP_T_STR  },
	{ "lower",  sample_conv_str2lower, 0,            NULL, SMP_T_STR,  SMP_T_STR  },
	{ "hex",    sample_conv_bin2hex,   0,            NULL, SMP_T_BIN,  SMP_T_STR  },
	{ "ipmask", sample_conv_ipmask,    ARG1(1,MSK4), NULL, SMP_T_IPV4, SMP_T_IPV4 },
	{ NULL, NULL, 0, 0, 0 },
}};

__attribute__((constructor))
static void __sample_init(void)
{
	/* register sample fetch and format conversion keywords */
	sample_register_fetches(&smp_kws);
	sample_register_convs(&sample_conv_kws);
}
