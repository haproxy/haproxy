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

#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#include <import/mjson.h>
#include <import/sha1.h>

#include <haproxy/acl.h>
#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/auth.h>
#include <haproxy/base64.h>
#include <haproxy/buf.h>
#include <haproxy/cfgparse.h>
#include <haproxy/chunk.h>
#include <haproxy/clock.h>
#include <haproxy/errors.h>
#include <haproxy/fix.h>
#include <haproxy/global.h>
#include <haproxy/hash.h>
#include <haproxy/http.h>
#include <haproxy/http_ana-t.h>
#include <haproxy/istbuf.h>
#include <haproxy/mqtt.h>
#include <haproxy/net_helper.h>
#include <haproxy/protobuf.h>
#include <haproxy/proxy.h>
#include <haproxy/regex.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/sink.h>
#include <haproxy/stick_table.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/uri_auth-t.h>
#include <haproxy/vars.h>
#include <haproxy/xxhash.h>
#include <haproxy/jwt.h>

/* sample type names */
const char *smp_to_type[SMP_TYPES] = {
	[SMP_T_ANY]  = "any",
	[SMP_T_SAME] = "same",
	[SMP_T_BOOL] = "bool",
	[SMP_T_SINT] = "sint",
	[SMP_T_ADDR] = "addr",
	[SMP_T_IPV4] = "ipv4",
	[SMP_T_IPV6] = "ipv6",
	[SMP_T_STR]  = "str",
	[SMP_T_BIN]  = "bin",
	[SMP_T_METH] = "meth",
};

/* Returns SMP_T_* smp matching with <type> name or SMP_TYPES if
 * not found.
 */
int type_to_smp(const char *type)
{
	int it = 0;

	while (it < SMP_TYPES) {
		if (strcmp(type, smp_to_type[it]) == 0)
			break; // found
		it += 1;
	}
	return it;
}

/* static sample used in sample_process() when <p> is NULL */
static THREAD_LOCAL struct sample temp_smp;

/* list head of all known sample fetch keywords */
static struct sample_fetch_kw_list sample_fetches = {
	.list = LIST_HEAD_INIT(sample_fetches.list)
};

/* list head of all known sample format conversion keywords */
static struct sample_conv_kw_list sample_convs = {
	.list = LIST_HEAD_INIT(sample_convs.list)
};

const unsigned int fetch_cap[SMP_SRC_ENTRIES] = {
	[SMP_SRC_CONST] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL_BE_CHK_RUL | SMP_VAL_CFG_PARSER |
	                   SMP_VAL_CLI_PARSER ),

	[SMP_SRC_INTRN] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL_CLI_PARSER ),

	[SMP_SRC_LISTN] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_FTEND] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_L4CLI] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_L5CLI] = (SMP_VAL___________ | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_TRACK] = (SMP_VAL_FE_CON_ACC | SMP_VAL_FE_SES_ACC | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_L6REQ] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_HRQHV] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_HRQHP] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_FE_REQ_CNT |
	                   SMP_VAL_FE_HRQ_HDR | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_HRQBO] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL_FE_HRQ_BDY | SMP_VAL_FE_SET_BCK |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_BKEND] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_BE_REQ_CNT | SMP_VAL_BE_HRQ_HDR | SMP_VAL_BE_HRQ_BDY |
	                   SMP_VAL_BE_SET_SRV | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_SERVR] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL_BE_SRV_CON | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_L4SRV] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_L5SRV] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_L6RES] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL___________ | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_HRSHV] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL___________ | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_HRSHP] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL_BE_RES_CNT |
	                   SMP_VAL_BE_HRS_HDR | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL_FE_LOG_END | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_HRSBO] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL_BE_HRS_BDY | SMP_VAL_BE_STO_RUL |
	                   SMP_VAL_FE_RES_CNT | SMP_VAL_FE_HRS_HDR | SMP_VAL_FE_HRS_BDY |
	                   SMP_VAL___________ | SMP_VAL_BE_CHK_RUL | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_RQFIN] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_FE_LOG_END | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_RSFIN] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_FE_LOG_END | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_TXFIN] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_FE_LOG_END | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),

	[SMP_SRC_SSFIN] = (SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL_FE_LOG_END | SMP_VAL___________ | SMP_VAL___________ |
	                   SMP_VAL___________ ),
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
	[SMP_CKP_BE_CHK_RUL] = "backend tcp-check rule",
	[SMP_CKP_CFG_PARSER] = "configuration parser",
	[SMP_CKP_CLI_PARSER] = "CLI parser",
};

/* This function returns the most accurate expected type of the data returned
 * by the sample_expr. It assumes that the <expr> and all of its converters are
 * properly initialized.
 */
int smp_expr_output_type(struct sample_expr *expr)
{
	struct sample_conv_expr *cur_smp = NULL;
	int cur_type = SMP_T_ANY;  /* current type in the chain */
	int next_type = SMP_T_ANY; /* next type in the chain */

	if (!LIST_ISEMPTY(&expr->conv_exprs)) {
		/* Ignore converters that output SMP_T_SAME if switching to them is
		 * conversion-free. (such converter's output match with input, thus only
		 * their input is considered)
		 *
		 * We start looking at the end of conv list and then loop back until the
		 * sample fetch for better performance (it is more likely to find the last
		 * effective output type near the end of the chain)
		 */
		do {
			struct list *cur_head = (cur_smp) ? &cur_smp->list : &expr->conv_exprs;

			cur_smp = LIST_PREV(cur_head, struct sample_conv_expr *, list);
			if (cur_smp->conv->out_type != SMP_T_SAME) {
				/* current converter has effective out_type */
				cur_type = cur_smp->conv->out_type;
				goto out;
			}
			else if (sample_casts[cur_type][next_type] != c_none)
				return next_type; /* switching to next type is not conversion-free */

			next_type = cur_smp->conv->in_type;
		} while (cur_smp != LIST_NEXT(&expr->conv_exprs, struct sample_conv_expr *, list));
	}
	/* conv list empty or doesn't have effective out_type,
	 * falling back to sample fetch out_type
	 */
	cur_type = expr->fetch->out_type;
 out:
	if (sample_casts[cur_type][next_type] != c_none)
		return next_type; /* switching to next type is not conversion-free */
	return cur_type;
}


/* fill the trash with a comma-delimited list of source names for the <use> bit
 * field which must be composed of a non-null set of SMP_USE_* flags. The return
 * value is the pointer to the string in the trash buffer.
 */
const char *sample_src_names(unsigned int use)
{
	int bit;

	trash.data = 0;
	trash.area[0] = '\0';
	for (bit = 0; bit < SMP_SRC_ENTRIES; bit++) {
		if (!(use & ~((1 << bit) - 1)))
			break; /* no more bits */

		if (!(use & (1 << bit)))
			continue; /* bit not set */

		trash.data += snprintf(trash.area + trash.data,
				       trash.size - trash.data, "%s%s",
				       (use & ((1 << bit) - 1)) ? "," : "",
				       fetch_src_names[bit]);
	}
	return trash.area;
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
	LIST_APPEND(&sample_fetches.list, &kwl->list);
}

/*
 * Registers the sample format coverstion keyword list <pckl> as a list of valid keywords for next
 * parsing sessions.
 */
void sample_register_convs(struct sample_conv_kw_list *pckl)
{
	LIST_APPEND(&sample_convs.list, &pckl->list);
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

/* dump list of registered sample fetch keywords on stdout */
void smp_dump_fetch_kw(void)
{
	struct sample_fetch_kw_list *kwl;
	struct sample_fetch *kwp, *kw;
	uint64_t mask;
	int index;
	int arg;
	int bit;

	for (bit = 0; bit <= SMP_CKP_ENTRIES + 1; bit++) {
		putchar('#');
		for (index = 0; bit + index <= SMP_CKP_ENTRIES; index++)
			putchar(' ');
		for (index = 0; index < bit && index < SMP_CKP_ENTRIES; index++)
			printf((bit <= SMP_CKP_ENTRIES) ? "/ " : " |");
		for (index = bit; bit < SMP_CKP_ENTRIES && index < SMP_CKP_ENTRIES + 2; index++)
			if (index == bit)
				putchar('_');
			else if (index == bit + 1)
				putchar('.');
			else
				putchar('-');
		printf(" %s\n", (bit < SMP_CKP_ENTRIES) ? fetch_ckp_names[bit] : "");
	}

	for (kw = kwp = NULL;; kwp = kw) {
		list_for_each_entry(kwl, &sample_fetches.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (strordered(kwp ? kwp->kw : NULL,
					       kwl->kw[index].kw,
					       kw != kwp ? kw->kw : NULL))
					kw = &kwl->kw[index];
			}
		}

		if (kw == kwp)
			break;

		printf("[ ");
		for (bit = 0; bit < SMP_CKP_ENTRIES; bit++)
			printf("%s", (kw->val & (1 << bit)) ? "Y " : ". ");

		printf("] %s", kw->kw);
		if (kw->arg_mask) {
			mask = kw->arg_mask >> ARGM_BITS;
			printf("(");
			for (arg = 0;
			     arg < ARGM_NBARGS && ((mask >> (arg * ARGT_BITS)) & ARGT_MASK);
			     arg++) {
				if (arg == (kw->arg_mask & ARGM_MASK)) {
					/* now dumping extra args */
					printf("[");
				}
				if (arg)
					printf(",");
				printf("%s", arg_type_names[(mask >> (arg * ARGT_BITS)) & ARGT_MASK]);
			}
			if (arg > (kw->arg_mask & ARGM_MASK)) {
				/* extra args were dumped */
				printf("]");
			}
			printf(")");
		}
		printf(": %s", smp_to_type[kw->out_type]);
		printf("\n");
	}
}

/* dump list of registered sample converter keywords on stdout */
void smp_dump_conv_kw(void)
{
	struct sample_conv_kw_list *kwl;
	struct sample_conv *kwp, *kw;
	uint64_t mask;
	int index;
	int arg;

	for (kw = kwp = NULL;; kwp = kw) {
		list_for_each_entry(kwl, &sample_convs.list, list) {
			for (index = 0; kwl->kw[index].kw != NULL; index++) {
				if (strordered(kwp ? kwp->kw : NULL,
					       kwl->kw[index].kw,
					       kw != kwp ? kw->kw : NULL))
					kw = &kwl->kw[index];
			}
		}

		if (kw == kwp)
			break;

		printf("%s", kw->kw);
		if (kw->arg_mask) {
			mask = kw->arg_mask >> ARGM_BITS;
			printf("(");
			for (arg = 0;
			     arg < ARGM_NBARGS && ((mask >> (arg * ARGT_BITS)) & ARGT_MASK);
			     arg++) {
				if (arg == (kw->arg_mask & ARGM_MASK)) {
					/* now dumping extra args */
					printf("[");
				}
				if (arg)
					printf(",");
				printf("%s", arg_type_names[(mask >> (arg * ARGT_BITS)) & ARGT_MASK]);
			}
			if (arg > (kw->arg_mask & ARGM_MASK)) {
				/* extra args were dumped */
				printf("]");
			}
			printf(")");
		}
		printf(": %s => %s", smp_to_type[kw->out_type], smp_to_type[kw->in_type]);
		printf("\n");
	}
}

/* This function browses the list of available sample fetches. <current> is
 * the last used sample fetch. If it is the first call, it must set to NULL.
 * <idx> is the index of the next sample fetch entry. It is used as private
 * value. It is useless to initiate it.
 *
 * It returns always the new fetch_sample entry, and NULL when the end of
 * the list is reached.
 */
struct sample_fetch *sample_fetch_getnext(struct sample_fetch *current, int *idx)
{
	struct sample_fetch_kw_list *kwl;
	struct sample_fetch *base;

	if (!current) {
		/* Get first kwl entry. */
		kwl = LIST_NEXT(&sample_fetches.list, struct sample_fetch_kw_list *, list);
		(*idx) = 0;
	} else {
		/* Get kwl corresponding to the current entry. */
		base = current + 1 - (*idx);
		kwl = container_of(base, struct sample_fetch_kw_list, kw);
	}

	while (1) {

		/* Check if kwl is the last entry. */
		if (&kwl->list == &sample_fetches.list)
			return NULL;

		/* idx contain the next keyword. If it is available, return it. */
		if (kwl->kw[*idx].kw) {
			(*idx)++;
			return &kwl->kw[(*idx)-1];
		}

		/* get next entry in the main list, and return NULL if the end is reached. */
		kwl = LIST_NEXT(&kwl->list, struct sample_fetch_kw_list *, list);

		/* Set index to 0, ans do one other loop. */
		(*idx) = 0;
	}
}

/* This function browses the list of available converters. <current> is
 * the last used converter. If it is the first call, it must set to NULL.
 * <idx> is the index of the next converter entry. It is used as private
 * value. It is useless to initiate it.
 *
 * It returns always the next sample_conv entry, and NULL when the end of
 * the list is reached.
 */
struct sample_conv *sample_conv_getnext(struct sample_conv *current, int *idx)
{
	struct sample_conv_kw_list *kwl;
	struct sample_conv *base;

	if (!current) {
		/* Get first kwl entry. */
		kwl = LIST_NEXT(&sample_convs.list, struct sample_conv_kw_list *, list);
		(*idx) = 0;
	} else {
		/* Get kwl corresponding to the current entry. */
		base = current + 1 - (*idx);
		kwl = container_of(base, struct sample_conv_kw_list, kw);
	}

	while (1) {
		/* Check if kwl is the last entry. */
		if (&kwl->list == &sample_convs.list)
			return NULL;

		/* idx contain the next keyword. If it is available, return it. */
		if (kwl->kw[*idx].kw) {
			(*idx)++;
			return &kwl->kw[(*idx)-1];
		}

		/* get next entry in the main list, and return NULL if the end is reached. */
		kwl = LIST_NEXT(&kwl->list, struct sample_conv_kw_list *, list);

		/* Set index to 0, ans do one other loop. */
		(*idx) = 0;
	}
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
/******************************************************************/

static int c_ip2int(struct sample *smp)
{
	smp->data.u.sint = ntohl(smp->data.u.ipv4.s_addr);
	smp->data.type = SMP_T_SINT;
	return 1;
}

static int c_ip2str(struct sample *smp)
{
	struct buffer *trash = get_trash_chunk();

	if (!inet_ntop(AF_INET, (void *)&smp->data.u.ipv4, trash->area, trash->size))
		return 0;

	trash->data = strlen(trash->area);
	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;

	return 1;
}

static int c_ip2ipv6(struct sample *smp)
{
	v4tov6(&smp->data.u.ipv6, &smp->data.u.ipv4);
	smp->data.type = SMP_T_IPV6;
	return 1;
}

static int c_ipv62ip(struct sample *smp)
{
	if (!v6tov4(&smp->data.u.ipv4, &smp->data.u.ipv6))
		return 0;
	smp->data.type = SMP_T_IPV4;
	return 1;
}

static int c_ipv62str(struct sample *smp)
{
	struct buffer *trash = get_trash_chunk();

	if (!inet_ntop(AF_INET6, (void *)&smp->data.u.ipv6, trash->area, trash->size))
		return 0;

	trash->data = strlen(trash->area);
	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/*
static int c_ipv62ip(struct sample *smp)
{
	return v6tov4(&smp->data.u.ipv4, &smp->data.u.ipv6);
}
*/

static int c_int2ip(struct sample *smp)
{
	smp->data.u.ipv4.s_addr = htonl((unsigned int)smp->data.u.sint);
	smp->data.type = SMP_T_IPV4;
	return 1;
}

static int c_int2ipv6(struct sample *smp)
{
	smp->data.u.ipv4.s_addr = htonl((unsigned int)smp->data.u.sint);
	v4tov6(&smp->data.u.ipv6, &smp->data.u.ipv4);
	smp->data.type = SMP_T_IPV6;
	return 1;
}

static int c_str2addr(struct sample *smp)
{
	if (!buf2ip(smp->data.u.str.area, smp->data.u.str.data, &smp->data.u.ipv4)) {
		if (!buf2ip6(smp->data.u.str.area, smp->data.u.str.data, &smp->data.u.ipv6))
			return 0;
		smp->data.type = SMP_T_IPV6;
		smp->flags &= ~SMP_F_CONST;
		return 1;
	}
	smp->data.type = SMP_T_IPV4;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int c_str2ip(struct sample *smp)
{
	if (!buf2ip(smp->data.u.str.area, smp->data.u.str.data, &smp->data.u.ipv4))
		return 0;
	smp->data.type = SMP_T_IPV4;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int c_str2ipv6(struct sample *smp)
{
	if (!buf2ip6(smp->data.u.str.area, smp->data.u.str.data, &smp->data.u.ipv6))
		return 0;
	smp->data.type = SMP_T_IPV6;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/*
 * The NULL char always enforces the end of string if it is met.
 * Data is never changed, so we can ignore the CONST case
 */
static int c_bin2str(struct sample *smp)
{
	int i;

	for (i = 0; i < smp->data.u.str.data; i++) {
		if (!smp->data.u.str.area[i]) {
			smp->data.u.str.data = i;
			break;
		}
	}
	smp->data.type = SMP_T_STR;
	return 1;
}

static int c_int2str(struct sample *smp)
{
	struct buffer *trash = get_trash_chunk();
	char *pos;

	pos = lltoa_r(smp->data.u.sint, trash->area, trash->size);
	if (!pos)
		return 0;

	trash->size = trash->size - (pos - trash->area);
	trash->area = pos;
	trash->data = strlen(pos);
	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* This function unconditionally duplicates data and removes the "const" flag.
 * For strings and binary blocks, it also provides a known allocated size with
 * a length that is capped to the size, and ensures a trailing zero is always
 * appended for strings. This is necessary for some operations which may
 * require to extend the length. It returns 0 if it fails, 1 on success.
 */
int smp_dup(struct sample *smp)
{
	struct buffer *trash;

	switch (smp->data.type) {
	case SMP_T_BOOL:
	case SMP_T_SINT:
	case SMP_T_ADDR:
	case SMP_T_IPV4:
	case SMP_T_IPV6:
		/* These type are not const. */
		break;

	case SMP_T_METH:
		if (smp->data.u.meth.meth != HTTP_METH_OTHER)
			break;
		__fallthrough;

	case SMP_T_STR:
		trash = get_trash_chunk();
		trash->data = smp->data.type == SMP_T_STR ?
		    smp->data.u.str.data : smp->data.u.meth.str.data;
		if (trash->data > trash->size - 1)
			trash->data = trash->size - 1;

		memcpy(trash->area, smp->data.type == SMP_T_STR ?
		    smp->data.u.str.area : smp->data.u.meth.str.area,
		    trash->data);
		trash->area[trash->data] = 0;
		smp->data.u.str = *trash;
		break;

	case SMP_T_BIN:
		trash = get_trash_chunk();
		trash->data = smp->data.u.str.data;
		if (trash->data > trash->size)
			trash->data = trash->size;

		memcpy(trash->area, smp->data.u.str.area, trash->data);
		smp->data.u.str = *trash;
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

/* special converter function used by pseudo types in the compatibility matrix
 * to inform that the conversion is theoretically allowed at parsing time.
 *
 * However, being a pseudo type, it may not be emitted by fetches or converters
 * so this function should never be called. If this is the case, then it means
 * that a pseudo type has been used as a final output type at runtime, which is
 * considered as a bug and should be fixed. To help spot this kind of bug, the
 * process will crash in this case.
 */
int c_pseudo(struct sample *smp)
{
	ABORT_NOW(); // die loudly
	/* never reached */
	return 0;
}

static int c_str2int(struct sample *smp)
{
	const char *str;
	const char *end;

	if (smp->data.u.str.data == 0)
		return 0;

	str = smp->data.u.str.area;
	end = smp->data.u.str.area + smp->data.u.str.data;

	smp->data.u.sint = read_int64(&str, end);
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int c_str2meth(struct sample *smp)
{
	enum http_meth_t meth;
	int len;

	meth = find_http_meth(smp->data.u.str.area, smp->data.u.str.data);
	if (meth == HTTP_METH_OTHER) {
		len = smp->data.u.str.data;
		smp->data.u.meth.str.area = smp->data.u.str.area;
		smp->data.u.meth.str.data = len;
	}
	else
		smp->flags &= ~SMP_F_CONST;
	smp->data.u.meth.meth = meth;
	smp->data.type = SMP_T_METH;
	return 1;
}

static int c_meth2str(struct sample *smp)
{
	int len;
	enum http_meth_t meth;

	if (smp->data.u.meth.meth == HTTP_METH_OTHER) {
		/* The method is unknown. Copy the original pointer. */
		len = smp->data.u.meth.str.data;
		smp->data.u.str.area = smp->data.u.meth.str.area;
		smp->data.u.str.data = len;
		smp->data.type = SMP_T_STR;
	}
	else if (smp->data.u.meth.meth < HTTP_METH_OTHER) {
		/* The method is known, copy the pointer containing the string. */
		meth = smp->data.u.meth.meth;
		smp->data.u.str.area = http_known_methods[meth].ptr;
		smp->data.u.str.data = http_known_methods[meth].len;
		smp->flags |= SMP_F_CONST;
		smp->data.type = SMP_T_STR;
	}
	else {
		/* Unknown method */
		return 0;
	}
	return 1;
}

static int c_addr2bin(struct sample *smp)
{
	struct buffer *chk = get_trash_chunk();

	if (smp->data.type == SMP_T_IPV4) {
		chk->data = 4;
		memcpy(chk->area, &smp->data.u.ipv4, chk->data);
	}
	else if (smp->data.type == SMP_T_IPV6) {
		chk->data = 16;
		memcpy(chk->area, &smp->data.u.ipv6, chk->data);
	}
	else
		return 0;

	smp->data.u.str = *chk;
	smp->data.type = SMP_T_BIN;
	return 1;
}

static int c_int2bin(struct sample *smp)
{
	struct buffer *chk = get_trash_chunk();

	*(unsigned long long int *) chk->area = my_htonll(smp->data.u.sint);
	chk->data = 8;

	smp->data.u.str = *chk;
	smp->data.type = SMP_T_BIN;
	return 1;
}

static int c_bool2bin(struct sample *smp)
{
	struct buffer *chk = get_trash_chunk();

	*(unsigned long long int *)chk->area = my_htonll(!!smp->data.u.sint);
	chk->data = 8;
	smp->data.u.str = *chk;
	smp->data.type = SMP_T_BIN;
	return 1;
}


/*****************************************************************/
/*      Sample casts matrix:                                     */
/*           sample_casts[from type][to type]                    */
/*           NULL pointer used for impossible sample casts       */
/*****************************************************************/

sample_cast_fct sample_casts[SMP_TYPES][SMP_TYPES] = {
/*            to:  ANY     SAME      BOOL       SINT       ADDR        IPV4       IPV6        STR         BIN         METH */
/* from:  ANY */ { c_none, NULL,     c_pseudo,  c_pseudo,  c_pseudo,   c_pseudo,  c_pseudo,   c_pseudo,   c_pseudo,   c_pseudo   },
/*       SAME */ { NULL,   NULL,     NULL,      NULL,      NULL,       NULL,      NULL,       NULL,       NULL,       NULL       },
/*       BOOL */ { c_none, NULL,     c_none,    c_none,    NULL,       NULL,      NULL,       c_int2str,  c_bool2bin, NULL       },
/*       SINT */ { c_none, NULL,     c_none,    c_none,    c_int2ip,   c_int2ip,  c_int2ipv6, c_int2str,  c_int2bin,  NULL       },
/*       ADDR */ { c_none, NULL,     NULL,      NULL,      c_pseudo,   c_pseudo,  c_pseudo,   c_pseudo,   c_pseudo,   NULL       },
/*       IPV4 */ { c_none, NULL,     NULL,      c_ip2int,  c_none,     c_none,    c_ip2ipv6,  c_ip2str,   c_addr2bin, NULL       },
/*       IPV6 */ { c_none, NULL,     NULL,      NULL,      c_none,     c_ipv62ip, c_none,     c_ipv62str, c_addr2bin, NULL       },
/*        STR */ { c_none, NULL,     c_str2int, c_str2int, c_str2addr, c_str2ip,  c_str2ipv6, c_none,     c_none,     c_str2meth },
/*        BIN */ { c_none, NULL,     NULL,      NULL,      NULL,       NULL,      NULL,       c_bin2str,  c_none,     c_str2meth },
/*       METH */ { c_none, NULL,     NULL,      NULL,      NULL,       NULL,      NULL,       c_meth2str, c_meth2str, c_none     }
};

/* Process the converters (if any) for a sample expr after the first fetch
 * keyword. We have two supported syntaxes for the converters, which can be
 * combined:
 *  - comma-delimited list of converters just after the keyword and args ;
 *  - one converter per keyword (if <idx> != NULL)
 *    FIXME: should we continue to support this old syntax?
 * The combination allows to have each keyword being a comma-delimited
 * series of converters.
 *
 * We want to process the former first, then the latter. For this we start
 * from the beginning of the supposed place in the exiting conv chain, which
 * starts at the last comma (<start> which is then referred to as endt).
 *
 * If <endptr> is non-nul, it will be set to the first unparsed character
 * (which may be the final '\0') on success. If it is nul, the expression
 * must be properly terminated by a '\0' otherwise an error is reported.
 *
 * <expr> should point the the sample expression that is already initialized
 * with the sample fetch that precedes the converters chain.
 *
 * The function returns a positive value for success and 0 for failure, in which
 * case <err_msg> will point to an allocated string that brings some info
 * about the failure. It is the caller's responsibility to free it.
 */
int sample_parse_expr_cnv(char **str, int *idx, char **endptr, char **err_msg, struct arg_list *al, const char *file, int line,
                          struct sample_expr *expr, const char *start)
{
	struct sample_conv *conv;
	const char *endt = start; /* end of term */
	const char *begw;         /* beginning of word */
	const char *endw;         /* end of word */
	char *ckw = NULL;
	unsigned long prev_type = expr->fetch->out_type;
	int success = 1;

	while (1) {
		struct sample_conv_expr *conv_expr;
		int err_arg;
		int argcnt;

		if (*endt && *endt != ',') {
			if (endptr) {
				/* end found, let's stop here */
				break;
			}
			if (ckw)
				memprintf(err_msg, "missing comma after converter '%s'", ckw);
			else
				memprintf(err_msg, "missing comma after fetch keyword");
			goto out_error;
		}

		/* FIXME: how long should we support such idiocies ? Maybe we
		 * should already warn ?
		 */
		while (*endt == ',') /* then trailing commas */
			endt++;

		begw = endt; /* start of converter */

		if (!*begw) {
			/* none ? skip to next string if idx is set */
			if (!idx)
				break; /* end of converters */
			(*idx)++;
			begw = str[*idx];
			if (!begw || !*begw)
				break;
		}

		for (endw = begw; is_idchar(*endw); endw++)
			;

		ha_free(&ckw);
		ckw = my_strndup(begw, endw - begw);

		conv = find_sample_conv(begw, endw - begw);
		if (!conv) {
			/* we found an isolated keyword that we don't know, it's not ours */
			if (idx && begw == str[*idx]) {
				endt = begw;
				break;
			}
			memprintf(err_msg, "unknown converter '%s'", ckw);
			goto out_error;
		}

		if (conv->in_type >= SMP_TYPES || conv->out_type >= SMP_TYPES) {
			memprintf(err_msg, "return type of converter '%s' is unknown", ckw);
			goto out_error;
		}

		/* If impossible type conversion */
		if (!sample_casts[prev_type][conv->in_type]) {
			memprintf(err_msg, "converter '%s' cannot be applied", ckw);
			goto out_error;
		}

		/* Ignore converters that output SMP_T_SAME if switching to them is
		 * conversion-free. (such converter's output match with input, thus only
		 * their input is considered)
		 */
		if (conv->out_type != SMP_T_SAME)
			prev_type = conv->out_type;
		else if (sample_casts[prev_type][conv->in_type] != c_none)
			prev_type = conv->in_type;

		conv_expr = calloc(1, sizeof(*conv_expr));
		if (!conv_expr)
			goto out_error;

		LIST_APPEND(&(expr->conv_exprs), &(conv_expr->list));
		conv_expr->conv = conv;

		if (al) {
			al->kw = expr->fetch->kw;
			al->conv = conv_expr->conv->kw;
		}
		argcnt = make_arg_list(endw, -1, conv->arg_mask, &conv_expr->arg_p, err_msg, &endt, &err_arg, al);
		if (argcnt < 0) {
			memprintf(err_msg, "invalid arg %d in converter '%s' : %s", err_arg+1, ckw, *err_msg);
			goto out_error;
		}

		if (argcnt && !conv->arg_mask) {
			memprintf(err_msg, "converter '%s' does not support any args", ckw);
			goto out_error;
		}

		if (!conv_expr->arg_p)
			conv_expr->arg_p = empty_arg_list;

		if (conv->val_args && !conv->val_args(conv_expr->arg_p, conv, file, line, err_msg)) {
			memprintf(err_msg, "invalid args in converter '%s' : %s", ckw, *err_msg);
			goto out_error;
		}
	}

	if (endptr) {
		/* end found, let's stop here */
		*endptr = (char *)endt;
	}
 out:
	free(ckw);
	return success;

 out_error:
	success = 0;
	goto out;
}

/*
 * Parse a sample expression configuration:
 *        fetch keyword followed by format conversion keywords.
 *
 * <al> is an arg_list serving as a list head to report missing dependencies.
 * It may be NULL if such dependencies are not allowed. Otherwise, the caller
 * must have set al->ctx if al is set.
 *
 * Returns a pointer on allocated sample expression structure or NULL in case
 * of error, in which case <err_msg> will point to an allocated string that
 * brings some info about the failure. It is the caller's responsibility to
 * free it.
 */
struct sample_expr *sample_parse_expr(char **str, int *idx, const char *file, int line, char **err_msg, struct arg_list *al, char **endptr)
{
	const char *begw; /* beginning of word */
	const char *endw; /* end of word */
	const char *endt; /* end of term */
	struct sample_expr *expr = NULL;
	struct sample_fetch *fetch;
	char *fkw = NULL;
	int err_arg;

	begw = str[*idx];
	for (endw = begw; is_idchar(*endw); endw++)
		;

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

	/* At this point, we have :
	 *   - begw : beginning of the keyword
	 *   - endw : end of the keyword, first character not part of keyword
	 */

	if (fetch->out_type >= SMP_TYPES) {
		memprintf(err_msg, "returns type of fetch method '%s' is unknown", fkw);
		goto out_error;
	}

	expr = calloc(1, sizeof(*expr));
	if (!expr)
		goto out_error;

	LIST_INIT(&(expr->conv_exprs));
	expr->fetch = fetch;
	expr->arg_p = empty_arg_list;

	/* Note that we call the argument parser even with an empty string,
	 * this allows it to automatically create entries for mandatory
	 * implicit arguments (eg: local proxy name).
	 */
	if (al) {
		al->kw = expr->fetch->kw;
		al->conv = NULL;
	}
	if (make_arg_list(endw, -1, fetch->arg_mask, &expr->arg_p, err_msg, &endt, &err_arg, al) < 0) {
		memprintf(err_msg, "fetch method '%s' : %s", fkw, *err_msg);
		goto out_error;
	}

	/* now endt is our first char not part of the arg list, typically the
	 * comma after the sample fetch name or after the closing parenthesis,
	 * or the NUL char.
	 */

	if (!expr->arg_p) {
		expr->arg_p = empty_arg_list;
	}
	else if (fetch->val_args && !fetch->val_args(expr->arg_p, err_msg)) {
		memprintf(err_msg, "invalid args in fetch method '%s' : %s", fkw, *err_msg);
		goto out_error;
	}

	if (!sample_parse_expr_cnv(str, idx, endptr, err_msg, al, file, line, expr, endt))
		goto out_error;

 out:
	free(fkw);
	return expr;

out_error:
	release_sample_expr(expr);
	expr = NULL;
	goto out;
}

/*
 * Helper function to process the converter list of a given sample expression
 * <expr> using the sample <p> (which is assumed to be properly initialized)
 * as input.
 *
 * Returns 1 on success and 0 on failure.
 */
int sample_process_cnv(struct sample_expr *expr, struct sample *p)
{
	struct sample_conv_expr *conv_expr;

	list_for_each_entry(conv_expr, &expr->conv_exprs, list) {
		/* we want to ensure that p->type can be casted into
		 * conv_expr->conv->in_type. We have 3 possibilities :
		 *  - NULL   => not castable.
		 *  - c_none => nothing to do (let's optimize it)
		 *  - other  => apply cast and prepare to fail
		 */
		if (p->data.type != conv_expr->conv->in_type) {
			if (!sample_casts[p->data.type][conv_expr->conv->in_type])
				return 0;

			if (sample_casts[p->data.type][conv_expr->conv->in_type] != c_none &&
			    !sample_casts[p->data.type][conv_expr->conv->in_type](p))
				return 0;
		}

		/* OK cast succeeded */

		if (!conv_expr->conv->process(conv_expr->arg_p, p, conv_expr->conv->private))
			return 0;
	}
	return 1;
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
 * to since they're made to cast multiple types according to what is required.
 *
 * The caller may indicate in <opt> if it considers the result final or not.
 * The caller needs to check the SMP_F_MAY_CHANGE flag in p->flags to verify
 * if the result is stable or not, according to the following table :
 *
 * return MAY_CHANGE FINAL   Meaning for the sample
 *  NULL      0        *     Not present and will never be (eg: header)
 *  NULL      1        0     Not present yet, could change (eg: POST param)
 *  NULL      1        1     Not present yet, will not change anymore
 *   smp      0        *     Present and will not change (eg: header)
 *   smp      1        0     Present, may change (eg: request length)
 *   smp      1        1     Present, last known value (eg: request length)
 */
struct sample *sample_process(struct proxy *px, struct session *sess,
                              struct stream *strm, unsigned int opt,
                              struct sample_expr *expr, struct sample *p)
{
	if (p == NULL) {
		p = &temp_smp;
		memset(p, 0, sizeof(*p));
	}

	smp_set_owner(p, px, sess, strm, opt);
	if (!expr->fetch->process(expr->arg_p, p, expr->fetch->kw, expr->fetch->private))
		return NULL;

	if (!sample_process_cnv(expr, p))
		return NULL;
	return p;
}

/*
 * Resolve all remaining arguments in proxy <p>. Returns the number of
 * errors or 0 if everything is fine. If at least one error is met, it will
 * be appended to *err. If *err==NULL it will be allocated first.
 */
int smp_resolve_args(struct proxy *p, char **err)
{
	struct arg_list *cur, *bak;
	const char *ctx, *where;
	const char *conv_ctx, *conv_pre, *conv_pos;
	struct userlist *ul;
	struct my_regex *reg;
	struct arg *arg;
	int cfgerr = 0;
	int rflags;

	list_for_each_entry_safe(cur, bak, &p->conf.args.list, list) {
		struct proxy *px;
		struct server *srv;
		struct stktable *t;
		char *pname, *sname, *stktname;
		char *err2;

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
		case ARGC_STK:   where = "in stick rule in"; break;
		case ARGC_TRK:   where = "in tracking rule in"; break;
		case ARGC_LOG:   where = "in log-format string in"; break;
		case ARGC_LOGSD: where = "in log-format-sd string in"; break;
		case ARGC_HRQ:   where = "in http-request expression in"; break;
		case ARGC_HRS:   where = "in http-response response in"; break;
		case ARGC_UIF:   where = "in unique-id-format string in"; break;
		case ARGC_RDR:   where = "in redirect format string in"; break;
		case ARGC_CAP:   where = "in capture rule in"; break;
		case ARGC_ACL:   ctx = "ACL keyword"; break;
		case ARGC_SRV:   where = "in server directive in"; break;
		case ARGC_SPOE:  where = "in spoe-message directive in"; break;
		case ARGC_UBK:   where = "in use_backend expression in"; break;
		case ARGC_USRV:  where = "in use-server or balance expression in"; break;
		case ARGC_HERR:  where = "in http-error directive in"; break;
		case ARGC_OT:    where = "in ot-scope directive in"; break;
		case ARGC_OPT:   where = "in option directive in"; break;
		case ARGC_TCO:   where = "in tcp-request connection expression in"; break;
		case ARGC_TSE:   where = "in tcp-request session expression in"; break;
		case ARGC_TRQ:   where = "in tcp-request content expression in"; break;
		case ARGC_TRS:   where = "in tcp-response content expression in"; break;
		case ARGC_TCK:   where = "in tcp-check expression in"; break;
		case ARGC_CFG:   where = "in configuration expression in"; break;
		case ARGC_CLI:   where = "in CLI expression in"; break;
		}

		/* set a few default settings */
		px = p;
		pname = p->id;

		switch (arg->type) {
		case ARGT_ID:
			err2 = NULL;

			if (arg->resolve_ptr && !arg->resolve_ptr(arg, &err2)) {
				memprintf(err, "%sparsing [%s:%d]: error in identifier '%s' in arg %d of %s%s%s%s '%s' %s proxy '%s' : %s.\n",
					  *err ? *err : "", cur->file, cur->line,
					 arg->data.str.area,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id, err2);
				ha_free(&err2);
				cfgerr++;
				continue;
			}
			break;

		case ARGT_SRV:
			if (!arg->data.str.data) {
				memprintf(err, "%sparsing [%s:%d]: missing server name in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					 *err ? *err : "", cur->file, cur->line,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				continue;
			}

			/* we support two formats : "bck/srv" and "srv" */
			sname = strrchr(arg->data.str.area, '/');

			if (sname) {
				*sname++ = '\0';
				pname = arg->data.str.area;

				px = proxy_be_by_name(pname);
				if (!px) {
					memprintf(err, "%sparsing [%s:%d]: unable to find proxy '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
						 *err ? *err : "", cur->file, cur->line, pname,
						 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
					cfgerr++;
					break;
				}
			}
			else {
				if (px->cap & PR_CAP_DEF) {
					memprintf(err, "%sparsing [%s:%d]: backend name must be set in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
						  *err ? *err : "", cur->file, cur->line,
						  cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
					cfgerr++;
					break;
				}
				sname = arg->data.str.area;
			}

			srv = findserver(px, sname);
			if (!srv) {
				memprintf(err, "%sparsing [%s:%d]: unable to find server '%s' in proxy '%s', referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					 *err ? *err : "", cur->file, cur->line, sname, pname,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			srv->flags |= SRV_F_NON_PURGEABLE;

			chunk_destroy(&arg->data.str);
			arg->unresolved = 0;
			arg->data.srv = srv;
			break;

		case ARGT_FE:
			if (arg->data.str.data) {
				pname = arg->data.str.area;
				px = proxy_fe_by_name(pname);
			}

			if (!px) {
				memprintf(err, "%sparsing [%s:%d]: unable to find frontend '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					 *err ? *err : "", cur->file, cur->line, pname,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			if (!(px->cap & PR_CAP_FE)) {
				memprintf(err, "%sparsing [%s:%d]: proxy '%s', referenced in arg %d of %s%s%s%s '%s' %s proxy '%s', has not frontend capability.\n",
					 *err ? *err : "", cur->file, cur->line, pname,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			chunk_destroy(&arg->data.str);
			arg->unresolved = 0;
			arg->data.prx = px;
			break;

		case ARGT_BE:
			if (arg->data.str.data) {
				pname = arg->data.str.area;
				px = proxy_be_by_name(pname);
			}

			if (!px) {
				memprintf(err, "%sparsing [%s:%d]: unable to find backend '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					 *err ? *err : "", cur->file, cur->line, pname,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			if (!(px->cap & PR_CAP_BE)) {
				memprintf(err, "%sparsing [%s:%d]: proxy '%s', referenced in arg %d of %s%s%s%s '%s' %s proxy '%s', has not backend capability.\n",
					 *err ? *err : "", cur->file, cur->line, pname,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			chunk_destroy(&arg->data.str);
			arg->unresolved = 0;
			arg->data.prx = px;
			break;

		case ARGT_TAB:
			if (arg->data.str.data)
				stktname = arg->data.str.area;
			else {
				if (px->cap & PR_CAP_DEF) {
					memprintf(err, "%sparsing [%s:%d]: table name must be set in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
						  *err ? *err : "", cur->file, cur->line,
						  cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
					cfgerr++;
					break;
				}
				stktname = px->id;
			}

			t = stktable_find_by_name(stktname);
			if (!t) {
				memprintf(err, "%sparsing [%s:%d]: unable to find table '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					 *err ? *err : "", cur->file, cur->line, stktname,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			if (!t->size) {
				memprintf(err, "%sparsing [%s:%d]: no table in proxy '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					 *err ? *err : "", cur->file, cur->line, stktname,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			if (!in_proxies_list(t->proxies_list, p)) {
				p->next_stkt_ref = t->proxies_list;
				t->proxies_list = p;
			}

			chunk_destroy(&arg->data.str);
			arg->unresolved = 0;
			arg->data.t = t;
			break;

		case ARGT_USR:
			if (!arg->data.str.data) {
				memprintf(err, "%sparsing [%s:%d]: missing userlist name in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					 *err ? *err : "", cur->file, cur->line,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			if (p->uri_auth && p->uri_auth->userlist &&
			    strcmp(p->uri_auth->userlist->name, arg->data.str.area) == 0)
				ul = p->uri_auth->userlist;
			else
				ul = auth_find_userlist(arg->data.str.area);

			if (!ul) {
				memprintf(err, "%sparsing [%s:%d]: unable to find userlist '%s' referenced in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					 *err ? *err : "", cur->file, cur->line,
					 arg->data.str.area,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				break;
			}

			chunk_destroy(&arg->data.str);
			arg->unresolved = 0;
			arg->data.usr = ul;
			break;

		case ARGT_REG:
			if (!arg->data.str.data) {
				memprintf(err, "%sparsing [%s:%d]: missing regex in arg %d of %s%s%s%s '%s' %s proxy '%s'.\n",
					 *err ? *err : "", cur->file, cur->line,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id);
				cfgerr++;
				continue;
			}

			rflags = 0;
			rflags |= (arg->type_flags & ARGF_REG_ICASE) ? REG_ICASE : 0;
			err2 = NULL;

			if (!(reg = regex_comp(arg->data.str.area, !(rflags & REG_ICASE), 1 /* capture substr */, &err2))) {
				memprintf(err, "%sparsing [%s:%d]: error in regex '%s' in arg %d of %s%s%s%s '%s' %s proxy '%s' : %s.\n",
					  *err ? *err : "", cur->file, cur->line,
					 arg->data.str.area,
					 cur->arg_pos + 1, conv_pre, conv_ctx, conv_pos, ctx, cur->kw, where, p->id, err2);
				ha_free(&err2);
				cfgerr++;
				continue;
			}

			chunk_destroy(&arg->data.str);
			arg->unresolved = 0;
			arg->data.reg = reg;
			break;


		}

		LIST_DELETE(&cur->list);
		free(cur);
	} /* end of args processing */

	return cfgerr;
}

/*
 * Process a fetch + format conversion as defined by the sample expression
 * <expr> on request or response considering the <opt> parameter. The output is
 * not explicitly set to <smp_type>, but shall be compatible with it as
 * specified by 'sample_casts' table. If a stable sample can be fetched, or an
 * unstable one when <opt> contains SMP_OPT_FINAL, the sample is converted and
 * returned without the SMP_F_MAY_CHANGE flag. If an unstable sample is found
 * and <opt> does not contain SMP_OPT_FINAL, then the sample is returned as-is
 * with its SMP_F_MAY_CHANGE flag so that the caller can check it and decide to
 * take actions (eg: wait longer). If a sample could not be found or could not
 * be converted, NULL is returned. The caller MUST NOT use the sample if the
 * SMP_F_MAY_CHANGE flag is present, as it is used only as a hint that there is
 * still hope to get it after waiting longer, and is not converted to string.
 * The possible output combinations are the following :
 *
 * return MAY_CHANGE FINAL   Meaning for the sample
 *  NULL      *        *     Not present and will never be (eg: header)
 *   smp      0        *     Final value converted (eg: header)
 *   smp      1        0     Not present yet, may appear later (eg: header)
 *   smp      1        1     never happens (either flag is cleared on output)
 */
struct sample *sample_fetch_as_type(struct proxy *px, struct session *sess,
                                   struct stream *strm, unsigned int opt,
                                   struct sample_expr *expr, int smp_type)
{
	struct sample *smp = &temp_smp;

	memset(smp, 0, sizeof(*smp));

	if (!sample_process(px, sess, strm, opt, expr, smp)) {
		if ((smp->flags & SMP_F_MAY_CHANGE) && !(opt & SMP_OPT_FINAL))
			return smp;
		return NULL;
	}

	if (smp->data.type != smp_type) {
		if (!sample_casts[smp->data.type][smp_type])
			return NULL;

		if (sample_casts[smp->data.type][smp_type] != c_none &&
		    !sample_casts[smp->data.type][smp_type](smp))
			return NULL;
	}

	smp->flags &= ~SMP_F_MAY_CHANGE;
	return smp;
}

static void release_sample_arg(struct arg *p)
{
	struct arg *p_back = p;

	if (!p)
		return;

	while (p->type != ARGT_STOP) {
		if (p->type == ARGT_STR || p->unresolved) {
			chunk_destroy(&p->data.str);
			p->unresolved = 0;
		}
		else if (p->type == ARGT_REG) {
			regex_free(p->data.reg);
			p->data.reg = NULL;
		}
		p++;
	}

	if (p_back != empty_arg_list)
		free(p_back);
}

void release_sample_expr(struct sample_expr *expr)
{
	struct sample_conv_expr *conv_expr, *conv_exprb;

	if (!expr)
		return;

	list_for_each_entry_safe(conv_expr, conv_exprb, &expr->conv_exprs, list) {
		LIST_DELETE(&conv_expr->list);
		release_sample_arg(conv_expr->arg_p);
		free(conv_expr);
	}

	release_sample_arg(expr->arg_p);
	free(expr);
}

/*****************************************************************/
/*    Sample format convert functions                            */
/*    These functions set the data type on return.               */
/*****************************************************************/

static int sample_conv_debug(const struct arg *arg_p, struct sample *smp, void *private)
{
	int i;
	struct sample tmp;
	struct buffer *buf;
	struct sink *sink;
	struct ist line;
	char *pfx;

	buf = alloc_trash_chunk();
	if (!buf)
		goto end;

	sink = (struct sink *)arg_p[1].data.ptr;
	BUG_ON(!sink);

	pfx = arg_p[0].data.str.area;
	BUG_ON(!pfx);

	chunk_printf(buf, "[debug] %s: type=%s ", pfx, smp_to_type[smp->data.type]);
	if (!sample_casts[smp->data.type][SMP_T_STR])
		goto nocast;

	/* Copy sample fetch. This puts the sample as const, the
	 * cast will copy data if a transformation is required.
	 */
	memcpy(&tmp, smp, sizeof(struct sample));
	tmp.flags = SMP_F_CONST;

	if (!sample_casts[smp->data.type][SMP_T_STR](&tmp))
		goto nocast;

	/* Display the displayable chars*. */
	b_putchr(buf, '<');
	for (i = 0; i < tmp.data.u.str.data; i++) {
		if (isprint((unsigned char)tmp.data.u.str.area[i]))
			b_putchr(buf, tmp.data.u.str.area[i]);
		else
			b_putchr(buf, '.');
	}
	b_putchr(buf, '>');

 done:
	line = ist2(buf->area, buf->data);
	sink_write(sink, LOG_HEADER_NONE, 0, &line, 1);
 end:
	free_trash_chunk(buf);
	return 1;
 nocast:
	chunk_appendf(buf, "(undisplayable)");
	goto done;
}

// This function checks the "debug" converter's arguments.
static int smp_check_debug(struct arg *args, struct sample_conv *conv,
                           const char *file, int line, char **err)
{
	const char *name = "buf0";
	struct sink *sink = NULL;

	if (args[0].type != ARGT_STR) {
		/* optional prefix */
		args[0].data.str.area = "";
		args[0].data.str.data = 0;
	}

	if (args[1].type == ARGT_STR)
		name = args[1].data.str.area;

	sink = sink_find_early(name, "debug converter", file, line);
	if (!sink) {
		memprintf(err, "Memory error while setting up sink '%s'", name);
		return 0;
	}

	chunk_destroy(&args[1].data.str);
	args[1].type = ARGT_PTR;
	args[1].data.ptr = sink;
	return 1;
}

static int sample_conv_base642bin(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	int bin_len;

	trash->data = 0;
	bin_len = base64dec(smp->data.u.str.area, smp->data.u.str.data,
			    trash->area, trash->size);
	if (bin_len < 0)
		return 0;

	trash->data = bin_len;
	smp->data.u.str = *trash;
	smp->data.type = SMP_T_BIN;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int sample_conv_base64url2bin(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	int bin_len;

	trash->data = 0;
	bin_len = base64urldec(smp->data.u.str.area, smp->data.u.str.data,
			    trash->area, trash->size);
	if (bin_len < 0)
		return 0;

	trash->data = bin_len;
	smp->data.u.str = *trash;
	smp->data.type = SMP_T_BIN;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int sample_conv_bin2base64(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	int b64_len;

	trash->data = 0;
	b64_len = a2base64(smp->data.u.str.area, smp->data.u.str.data,
			   trash->area, trash->size);
	if (b64_len < 0)
		return 0;

	trash->data = b64_len;
	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int sample_conv_bin2base64url(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	int b64_len;

	trash->data = 0;
	b64_len = a2base64url(smp->data.u.str.area, smp->data.u.str.data,
			   trash->area, trash->size);
	if (b64_len < 0)
		return 0;

	trash->data = b64_len;
	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* This function returns a sample struct filled with the conversion of variable
 * <var> to sample type <type> (SMP_T_*), via a cast to the target type. If the
 * variable cannot be retrieved or casted, 0 is returned, otherwise 1.
 *
 * Keep in mind that the sample content may be written to a pre-allocated
 * trash chunk as returned by get_trash_chunk().
 */
int sample_conv_var2smp(const struct var_desc *var, struct sample *smp, int type)
{
	if (!vars_get_by_desc(var, smp, NULL))
		return 0;
	if (!sample_casts[smp->data.type][type])
		return 0;
	if (!sample_casts[smp->data.type][type](smp))
		return 0;
	return 1;
}

static int sample_conv_sha1(const struct arg *arg_p, struct sample *smp, void *private)
{
	blk_SHA_CTX ctx;
	struct buffer *trash = get_trash_chunk();

	memset(&ctx, 0, sizeof(ctx));

	blk_SHA1_Init(&ctx);
	blk_SHA1_Update(&ctx, smp->data.u.str.area, smp->data.u.str.data);
	blk_SHA1_Final((unsigned char *) trash->area, &ctx);

	trash->data = 20;
	smp->data.u.str = *trash;
	smp->data.type = SMP_T_BIN;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* This function returns a sample struct filled with an <arg> content.
 * If the <arg> contains a string, it is returned in the sample flagged as
 * SMP_F_CONST. If the <arg> contains a variable descriptor, the sample is
 * filled with the content of the variable by using vars_get_by_desc().
 *
 * Keep in mind that the sample content may be written to a pre-allocated
 * trash chunk as returned by get_trash_chunk().
 *
 * This function returns 0 if an error occurs, otherwise it returns 1.
 */
int sample_conv_var2smp_str(const struct arg *arg, struct sample *smp)
{
	switch (arg->type) {
	case ARGT_STR:
		smp->data.type = SMP_T_STR;
		smp->data.u.str = arg->data.str;
		smp->flags = SMP_F_CONST;
		return 1;
	case ARGT_VAR:
		return sample_conv_var2smp(&arg->data.var, smp, SMP_T_STR);
	default:
		return 0;
	}
}

static int sample_conv_be2dec_check(struct arg *args, struct sample_conv *conv,
                                    const char *file, int line, char **err)
{
	if (args[1].data.sint <= 0 || args[1].data.sint > sizeof(unsigned long long)) {
		memprintf(err, "chunk_size out of [1..%u] range (%lld)", (uint)sizeof(unsigned long long), args[1].data.sint);
		return 0;
	}

	if (args[2].data.sint != 0 && args[2].data.sint != 1) {
		memprintf(err, "Unsupported truncate value (%lld)", args[2].data.sint);
		return 0;
	}

	return 1;
}

/* Converts big-endian binary input sample to a string containing an unsigned
 * integer number per <chunk_size> input bytes separated with <separator>.
 * Optional <truncate> flag indicates if input is truncated at <chunk_size>
 * boundaries.
 * Arguments: separator (string), chunk_size (integer), truncate (0,1)
 */
static int sample_conv_be2dec(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	const int last = args[2].data.sint ? smp->data.u.str.data - args[1].data.sint + 1 : smp->data.u.str.data;
	int max_size = trash->size - 2;
	int i;
	int start;
	int ptr = 0;
	unsigned long long number;
	char *pos;

	trash->data = 0;

	while (ptr < last && trash->data <= max_size) {
		start = trash->data;
		if (ptr) {
			/* Add separator */
			memcpy(trash->area + trash->data, args[0].data.str.area, args[0].data.str.data);
			trash->data += args[0].data.str.data;
		}
		else
			max_size -= args[0].data.str.data;

		/* Add integer */
		for (number = 0, i = 0; i < args[1].data.sint && ptr < smp->data.u.str.data; i++)
			number = (number << 8) + (unsigned char)smp->data.u.str.area[ptr++];

		pos = ulltoa(number, trash->area + trash->data, trash->size - trash->data);
		if (pos)
			trash->data = pos - trash->area;
		else {
			trash->data = start;
			break;
		}
	}

	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int sample_conv_be2hex_check(struct arg *args, struct sample_conv *conv,
                                    const char *file, int line, char **err)
{
	if (args[1].data.sint <= 0 && (args[0].data.str.data > 0 || args[2].data.sint != 0)) {
		memprintf(err, "chunk_size needs to be positive (%lld)", args[1].data.sint);
		return 0;
	}

	if (args[2].data.sint != 0 && args[2].data.sint != 1) {
		memprintf(err, "Unsupported truncate value (%lld)", args[2].data.sint);
		return 0;
	}

	return 1;
}

/* Converts big-endian binary input sample to a hex string containing two hex
 * digits per input byte. <separator> is put every <chunk_size> binary input
 * bytes if specified. Optional <truncate> flag indicates if input is truncated
 * at <chunk_size> boundaries.
 * Arguments: separator (string), chunk_size (integer), truncate (0,1)
 */
static int sample_conv_be2hex(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	int chunk_size = args[1].data.sint;
	const int last = args[2].data.sint ? smp->data.u.str.data - chunk_size + 1 : smp->data.u.str.data;
	int i;
	int max_size;
	int ptr = 0;
	unsigned char c;

	trash->data = 0;
	if (args[0].data.str.data == 0 && args[2].data.sint == 0)
		chunk_size = smp->data.u.str.data;
	max_size = trash->size - 2 * chunk_size;

	while (ptr < last && trash->data <= max_size) {
		if (ptr) {
			/* Add separator */
			memcpy(trash->area + trash->data, args[0].data.str.area, args[0].data.str.data);
			trash->data += args[0].data.str.data;
		}
		else
			max_size -= args[0].data.str.data;

		/* Add hex */
		for (i = 0; i < chunk_size && ptr < smp->data.u.str.data; i++) {
			c = smp->data.u.str.area[ptr++];
			trash->area[trash->data++] = hextab[(c >> 4) & 0xF];
			trash->area[trash->data++] = hextab[c & 0xF];
		}
	}

	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int sample_conv_bin2hex(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	unsigned char c;
	int ptr = 0;

	trash->data = 0;
	while (ptr < smp->data.u.str.data && trash->data <= trash->size - 2) {
		c = smp->data.u.str.area[ptr++];
		trash->area[trash->data++] = hextab[(c >> 4) & 0xF];
		trash->area[trash->data++] = hextab[c & 0xF];
	}
	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

static int sample_conv_hex2int(const struct arg *arg_p, struct sample *smp, void *private)
{
	long long int n = 0;
	int i, c;

	for (i = 0; i < smp->data.u.str.data; i++) {
		if ((c = hex2i(smp->data.u.str.area[i])) < 0)
			return 0;
		n = (n << 4) + c;
	}

	smp->data.u.sint = n;
	smp->data.type = SMP_T_SINT;
	smp->flags &= ~SMP_F_CONST;
	return 1;
}

/* hashes the binary input into a 32-bit unsigned int */
static int sample_conv_djb2(const struct arg *arg_p, struct sample *smp, void *private)
{
	smp->data.u.sint = hash_djb2(smp->data.u.str.area,
				     smp->data.u.str.data);
	if (arg_p->data.sint)
		smp->data.u.sint = full_hash(smp->data.u.sint);
	smp->data.type = SMP_T_SINT;
	return 1;
}

static int sample_conv_length(const struct arg *arg_p, struct sample *smp, void *private)
{
	int i = smp->data.u.str.data;
	smp->data.u.sint = i;
	smp->data.type = SMP_T_SINT;
	return 1;
}


static int sample_conv_str2lower(const struct arg *arg_p, struct sample *smp, void *private)
{
	int i;

	if (!smp_make_rw(smp))
		return 0;

	for (i = 0; i < smp->data.u.str.data; i++) {
		if ((smp->data.u.str.area[i] >= 'A') && (smp->data.u.str.area[i] <= 'Z'))
			smp->data.u.str.area[i] += 'a' - 'A';
	}
	return 1;
}

static int sample_conv_str2upper(const struct arg *arg_p, struct sample *smp, void *private)
{
	int i;

	if (!smp_make_rw(smp))
		return 0;

	for (i = 0; i < smp->data.u.str.data; i++) {
		if ((smp->data.u.str.area[i] >= 'a') && (smp->data.u.str.area[i] <= 'z'))
			smp->data.u.str.area[i] += 'A' - 'a';
	}
	return 1;
}

/* takes the IPv4 mask in args[0] and an optional IPv6 mask in args[1] */
static int sample_conv_ipmask(const struct arg *args, struct sample *smp, void *private)
{
	/* Attempt to convert to IPv4 to apply the correct mask. */
	c_ipv62ip(smp);

	if (smp->data.type == SMP_T_IPV4) {
		smp->data.u.ipv4.s_addr &= args[0].data.ipv4.s_addr;
		smp->data.type = SMP_T_IPV4;
	}
	else if (smp->data.type == SMP_T_IPV6) {
		/* IPv6 cannot be converted without an IPv6 mask. */
		if (args[1].type != ARGT_IPV6)
			return 0;

		write_u64(&smp->data.u.ipv6.s6_addr[0],
			  read_u64(&smp->data.u.ipv6.s6_addr[0]) & read_u64(&args[1].data.ipv6.s6_addr[0]));
		write_u64(&smp->data.u.ipv6.s6_addr[8],
			  read_u64(&smp->data.u.ipv6.s6_addr[8]) & read_u64(&args[1].data.ipv6.s6_addr[8]));
		smp->data.type = SMP_T_IPV6;
	}

	return 1;
}

/*
 * This function implement a conversion specifier seeker for %N so it could be
 * replaced before doing strftime.
 *
 * <format> is the input format string which is used as a haystack
 *
 * The function fills multiple variables:
 * <skip> is the len of the conversion specifier string which was found (ex: strlen(%N):2, strlen(%3N):3 strlen(%123N): 5)
 * <width> is the width argument, default width is 9 (ex: %3N: 3, %4N: 4: %N: 9, %5N: 5)
 *
 * Returns a ptr to the first character of the conversion specifier or NULL if not found
 */
static const char *lookup_convspec_N(const char *format, int *skip, int *width)
{
	const char *p, *needle;
	const char *digits;
	int state;

	p = format;

	/* this looks for % in loop. The iteration stops when a %N conversion
	 * specifier was found or there is no '%' anymore */
lookagain:
	while (p && *p) {
		state = 0;
		digits = NULL;

		p = needle = strchr(p, '%');
		/* Once we find a % we try to move forward in the string
		 *
		 * state 0: found %
		 * state 1: digits (precision)
		 * state 2: N
		 */
		while (p && *p) {
			switch (state) {
				case 0:
					state = 1;
					break;

				case 1:
					if (isdigit((unsigned char)*p) && !digits) /* set the start of the digits */
						digits = p;

					if (isdigit((unsigned char)*p))
						break;
					else
						state = 2;
					/* if this is not a number anymore, we
					* don't want to increment p but try the
					* next state directly */
					__fallthrough;
				case 2:
					if (*p == 'N')
						goto found;
					else
						/* this was not a %N, start again */
						goto lookagain;
					break;
			}
			p++;
		}
	}

	*skip = 0;
	*width = 0;
	return NULL;

found:
	*skip = p - needle + 1;
	if (digits)
		*width = atoi(digits);
	else
		*width = 9;
	return needle;
}

 /*
  * strftime(3) does not implement nanoseconds, but we still want them in our
  * date format.
  *
  * This function implements %N like in date(1) which gives you the nanoseconds part of the timestamp
  * An optional field width can be specified, a maximum width of 9 is supported (ex: %3N %6N %9N)
  *
  * <format> is the format string
  * <curr_date> in seconds since epoch
  * <ns> only the nanoseconds part of the timestamp
  * <local> chose the localtime instead of UTC time
  *
  * Return the results of strftime in the trash buffer
  */
static struct buffer *conv_time_common(const char *format, time_t curr_date, uint64_t ns, int local)
{
	struct buffer *tmp_format = NULL;
	struct buffer *res = NULL;
	struct tm tm;
	const char *p;
	char ns_str[10] = {};
	int set = 0;

	if (local)
		get_localtime(curr_date, &tm);
	else
		get_gmtime(curr_date, &tm);


	/* we need to iterate in order to replace all the %N in the string */

	p = format;
	while (*p) {
		const char *needle;
		int skip = 0;
		int cpy = 0;
		int width = 0;

		/* look for the next %N onversion specifier */
		if (!(needle = lookup_convspec_N(p, &skip, &width)))
			break;

		if (width > 9) /* we don't handle more that 9 */
			width = 9;
		cpy = needle - p;

		if (!tmp_format)
			tmp_format = alloc_trash_chunk();
		if (!tmp_format)
			goto error;

		if (set != 9) /* if the snprintf wasn't done yet */
			set = snprintf(ns_str, sizeof(ns_str), "%.9llu", (unsigned long long)ns);

		if (chunk_istcat(tmp_format, ist2(p, cpy)) == 0) /* copy before the %N */
			goto error;
		if (chunk_istcat(tmp_format, ist2(ns_str, width)) == 0) /* copy the %N result with the right precision  */
			goto error;

		p += skip + cpy; /* skip the %N */
	}


	if (tmp_format) { /* %N was found */
		if (chunk_strcat(tmp_format, p) == 0)  /* copy the end of the string if needed or just the \0 */
			goto error;
		res = get_trash_chunk();
		res->data = strftime(res->area, res->size, tmp_format->area , &tm);
	} else {
		res = get_trash_chunk();
		res->data = strftime(res->area, res->size, format, &tm);
	}

error:
	free_trash_chunk(tmp_format);
	return res;
}



/*
 * same as sample_conv_ltime but input is us and %N is supported
 */
static int sample_conv_us_ltime(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *temp;
	time_t curr_date = smp->data.u.sint / 1000000; /* convert us to s */
	uint64_t ns = (smp->data.u.sint % 1000000) * 1000; /*  us part to ns */

	/* add offset */
	if (args[1].type == ARGT_SINT)
		curr_date += args[1].data.sint;

	temp = conv_time_common(args[0].data.str.area, curr_date, ns, 1);
	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;
	return 1;
}

/*
 * same as sample_conv_ltime but input is ms and %N is supported
 */
static int sample_conv_ms_ltime(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *temp;
	time_t curr_date = smp->data.u.sint / 1000; /* convert ms to s */
	uint64_t ns = (smp->data.u.sint % 1000) * 1000000; /*  ms part to ns */

	/* add offset */
	if (args[1].type == ARGT_SINT)
		curr_date += args[1].data.sint;

	temp = conv_time_common(args[0].data.str.area, curr_date, ns, 1);
	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;
	return 1;
}


/* takes an UINT value on input supposed to represent the time since EPOCH,
 * adds an optional offset found in args[1] and emits a string representing
 * the local time in the format specified in args[1] using strftime().
 */
static int sample_conv_ltime(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *temp;
	/* With high numbers, the date returned can be negative, the 55 bits mask prevent this. */
	time_t curr_date = smp->data.u.sint & 0x007fffffffffffffLL;
	struct tm tm;

	/* add offset */
	if (args[1].type == ARGT_SINT)
		curr_date += args[1].data.sint;

	get_localtime(curr_date, &tm);

	temp = get_trash_chunk();
	temp->data = strftime(temp->area, temp->size, args[0].data.str.area, &tm);
	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;
	return 1;
}

/* hashes the binary input into a 32-bit unsigned int */
static int sample_conv_sdbm(const struct arg *arg_p, struct sample *smp, void *private)
{
	smp->data.u.sint = hash_sdbm(smp->data.u.str.area,
				     smp->data.u.str.data);
	if (arg_p->data.sint)
		smp->data.u.sint = full_hash(smp->data.u.sint);
	smp->data.type = SMP_T_SINT;
	return 1;
}

/*
 * same as sample_conv_utime but input is us and %N is supported
 */
static int sample_conv_us_utime(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *temp;
	time_t curr_date = smp->data.u.sint / 1000000; /* convert us to s */
	uint64_t ns = (smp->data.u.sint % 1000000) * 1000; /*  us part to ns */

	/* add offset */
	if (args[1].type == ARGT_SINT)
		curr_date += args[1].data.sint;

	temp = conv_time_common(args[0].data.str.area, curr_date, ns, 0);
	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;
	return 1;
}

/*
 * same as sample_conv_utime but input is ms and %N is supported
 */
static int sample_conv_ms_utime(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *temp;
	time_t curr_date = smp->data.u.sint / 1000; /* convert ms to s */
	uint64_t ns = (smp->data.u.sint % 1000) * 1000000; /*  ms part to ns */

	/* add offset */
	if (args[1].type == ARGT_SINT)
		curr_date += args[1].data.sint;

	temp = conv_time_common(args[0].data.str.area, curr_date, ns, 0);
	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;
	return 1;
}

/* takes an UINT value on input supposed to represent the time since EPOCH,
 * adds an optional offset found in args[1] and emits a string representing
 * the UTC date in the format specified in args[1] using strftime().
 */
static int sample_conv_utime(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *temp;
	/* With high numbers, the date returned can be negative, the 55 bits mask prevent this. */
	time_t curr_date = smp->data.u.sint & 0x007fffffffffffffLL;
	struct tm tm;

	/* add offset */
	if (args[1].type == ARGT_SINT)
		curr_date += args[1].data.sint;

	get_gmtime(curr_date, &tm);

	temp = get_trash_chunk();
	temp->data = strftime(temp->area, temp->size, args[0].data.str.area, &tm);
	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;
	return 1;
}

/* hashes the binary input into a 32-bit unsigned int */
static int sample_conv_wt6(const struct arg *arg_p, struct sample *smp, void *private)
{
	smp->data.u.sint = hash_wt6(smp->data.u.str.area,
				    smp->data.u.str.data);
	if (arg_p->data.sint)
		smp->data.u.sint = full_hash(smp->data.u.sint);
	smp->data.type = SMP_T_SINT;
	return 1;
}

/* hashes the binary input into a 32-bit unsigned int using xxh.
 * The seed of the hash defaults to 0 but can be changd in argument 1.
 */
static int sample_conv_xxh32(const struct arg *arg_p, struct sample *smp, void *private)
{
	unsigned int seed;

	if (arg_p->data.sint)
		seed = arg_p->data.sint;
	else
		seed = 0;
	smp->data.u.sint = XXH32(smp->data.u.str.area, smp->data.u.str.data,
				 seed);
	smp->data.type = SMP_T_SINT;
	return 1;
}

/* hashes the binary input into a 64-bit unsigned int using xxh.
 * In fact, the function returns a 64 bit unsigned, but the sample
 * storage of haproxy only proposes 64-bits signed, so the value is
 * cast as signed. This cast doesn't impact the hash repartition.
 * The seed of the hash defaults to 0 but can be changd in argument 1.
 */
static int sample_conv_xxh64(const struct arg *arg_p, struct sample *smp, void *private)
{
	unsigned long long int seed;

	if (arg_p->data.sint)
		seed = (unsigned long long int)arg_p->data.sint;
	else
		seed = 0;
	smp->data.u.sint = (long long int)XXH64(smp->data.u.str.area,
						smp->data.u.str.data, seed);
	smp->data.type = SMP_T_SINT;
	return 1;
}

static int sample_conv_xxh3(const struct arg *arg_p, struct sample *smp, void *private)
{
	unsigned long long int seed;

	if (arg_p->data.sint)
		seed = (unsigned long long int)arg_p->data.sint;
	else
		seed = 0;
	smp->data.u.sint = (long long int)XXH3(smp->data.u.str.area,
	                                       smp->data.u.str.data, seed);
	smp->data.type = SMP_T_SINT;
	return 1;
}

/* hashes the binary input into a 32-bit unsigned int */
static int sample_conv_crc32(const struct arg *arg_p, struct sample *smp, void *private)
{
	smp->data.u.sint = hash_crc32(smp->data.u.str.area,
				      smp->data.u.str.data);
	if (arg_p->data.sint)
		smp->data.u.sint = full_hash(smp->data.u.sint);
	smp->data.type = SMP_T_SINT;
	return 1;
}

/* hashes the binary input into crc32c (RFC4960, Appendix B [8].) */
static int sample_conv_crc32c(const struct arg *arg_p, struct sample *smp, void *private)
{
	smp->data.u.sint = hash_crc32c(smp->data.u.str.area,
				       smp->data.u.str.data);
	if (arg_p->data.sint)
		smp->data.u.sint = full_hash(smp->data.u.sint);
	smp->data.type = SMP_T_SINT;
	return 1;
}

/* This function escape special json characters. The returned string can be
 * safely set between two '"' and used as json string. The json string is
 * defined like this:
 *
 *    any Unicode character except '"' or '\' or control character
 *    \", \\, \/, \b, \f, \n, \r, \t, \u + four-hex-digits
 *
 * The enum input_type contain all the allowed mode for decoding the input
 * string.
 */
enum input_type {
	IT_ASCII = 0,
	IT_UTF8,
	IT_UTF8S,
	IT_UTF8P,
	IT_UTF8PS,
};

static int sample_conv_json_check(struct arg *arg, struct sample_conv *conv,
                                  const char *file, int line, char **err)
{
	enum input_type type;

	if (strcmp(arg->data.str.area, "") == 0)
		type = IT_ASCII;
	else if (strcmp(arg->data.str.area, "ascii") == 0)
		type = IT_ASCII;
	else if (strcmp(arg->data.str.area, "utf8") == 0)
		type = IT_UTF8;
	else if (strcmp(arg->data.str.area, "utf8s") == 0)
		type = IT_UTF8S;
	else if (strcmp(arg->data.str.area, "utf8p") == 0)
		type = IT_UTF8P;
	else if (strcmp(arg->data.str.area, "utf8ps") == 0)
		type = IT_UTF8PS;
	else {
		memprintf(err, "Unexpected input code type. "
			  "Allowed value are 'ascii', 'utf8', 'utf8s', 'utf8p' and 'utf8ps'");
		return 0;
	}

	chunk_destroy(&arg->data.str);
	arg->type = ARGT_SINT;
	arg->data.sint = type;
	return 1;
}

static int sample_conv_json(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *temp;
	char _str[7]; /* \u + 4 hex digit + null char for sprintf. */
	const char *str;
	int len;
	enum input_type input_type = IT_ASCII;
	unsigned int c;
	unsigned int ret;
	char *p;

	input_type = arg_p->data.sint;

	temp = get_trash_chunk();
	temp->data = 0;

	p = smp->data.u.str.area;
	while (p < smp->data.u.str.area + smp->data.u.str.data) {

		if (input_type == IT_ASCII) {
			/* Read input as ASCII. */
			c = *(unsigned char *)p;
			p++;
		}
		else {
			/* Read input as UTF8. */
			ret = utf8_next(p,
					smp->data.u.str.data - ( p - smp->data.u.str.area),
					&c);
			p += utf8_return_length(ret);

			if (input_type == IT_UTF8 && utf8_return_code(ret) != UTF8_CODE_OK)
					return 0;
			if (input_type == IT_UTF8S && utf8_return_code(ret) != UTF8_CODE_OK)
					continue;
			if (input_type == IT_UTF8P && utf8_return_code(ret) & (UTF8_CODE_INVRANGE|UTF8_CODE_BADSEQ))
					return 0;
			if (input_type == IT_UTF8PS && utf8_return_code(ret) & (UTF8_CODE_INVRANGE|UTF8_CODE_BADSEQ))
					continue;

			/* Check too big values. */
			if ((unsigned int)c > 0xffff) {
				if (input_type == IT_UTF8 || input_type == IT_UTF8P)
					return 0;
				continue;
			}
		}

		/* Convert character. */
		if (c == '"') {
			len = 2;
			str = "\\\"";
		}
		else if (c == '\\') {
			len = 2;
			str = "\\\\";
		}
		else if (c == '/') {
			len = 2;
			str = "\\/";
		}
		else if (c == '\b') {
			len = 2;
			str = "\\b";
		}
		else if (c == '\f') {
			len = 2;
			str = "\\f";
		}
		else if (c == '\r') {
			len = 2;
			str = "\\r";
		}
		else if (c == '\n') {
			len = 2;
			str = "\\n";
		}
		else if (c == '\t') {
			len = 2;
			str = "\\t";
		}
		else if (c > 0xff || !isprint((unsigned char)c)) {
			/* isprint generate a segfault if c is too big. The man says that
			 * c must have the value of an unsigned char or EOF.
			 */
			len = 6;
			_str[0] = '\\';
			_str[1] = 'u';
			snprintf(&_str[2], 5, "%04x", (unsigned short)c);
			str = _str;
		}
		else {
			len = 1;
			_str[0] = c;
			str = _str;
		}

		/* Check length */
		if (temp->data + len > temp->size)
			return 0;

		/* Copy string. */
		memcpy(temp->area + temp->data, str, len);
		temp->data += len;
	}

	smp->flags &= ~SMP_F_CONST;
	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;

	return 1;
}

/* This sample function is designed to extract some bytes from an input buffer.
 * First arg is the offset.
 * Optional second arg is the length to truncate */
static int sample_conv_bytes(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct sample smp_arg0, smp_arg1;
	long long start_idx, length;

	// determine the start_idx and length of the output
	smp_set_owner(&smp_arg0, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_sint(&arg_p[0], &smp_arg0) || smp_arg0.data.u.sint < 0) {
		/* invalid or negative value */
		goto fail;
	}

	if (smp_arg0.data.u.sint >= smp->data.u.str.data) {
		// arg0 >= the input length
		if (smp->opt & SMP_OPT_FINAL) {
			// empty output value on final smp
			smp->data.u.str.data = 0;
			goto end;
		}
		goto wait;
	}
	start_idx = smp_arg0.data.u.sint;

	// length comes from arg1 if present, otherwise it's the remaining length
	length = smp->data.u.str.data - start_idx;
	if (arg_p[1].type != ARGT_STOP) {
		smp_set_owner(&smp_arg1, smp->px, smp->sess, smp->strm, smp->opt);
		if (!sample_conv_var2smp_sint(&arg_p[1], &smp_arg1) || smp_arg1.data.u.sint < 0) {
			// invalid or negative value
			goto fail;
		}

		if (smp_arg1.data.u.sint > (smp->data.u.str.data - start_idx)) {
			// arg1 value is greater than the remaining length
			if (smp->opt & SMP_OPT_FINAL) {
				// truncate to remaining length
				length = smp->data.u.str.data - start_idx;
				goto end;
			}
			goto wait;
		}
		length = smp_arg1.data.u.sint;
	}

	// update the output using the start_idx and length
	smp->data.u.str.area += start_idx;
	smp->data.u.str.data = length;

  end:
	return 1;

  fail:
	smp->flags &= ~SMP_F_MAY_CHANGE;
  wait:
	smp->data.u.str.data = 0;
	return 0;
}

static int sample_conv_field_check(struct arg *args, struct sample_conv *conv,
                                  const char *file, int line, char **err)
{
	struct arg *arg = args;

	if (arg->type != ARGT_SINT) {
		memprintf(err, "Unexpected arg type");
		return 0;
	}

	if (!arg->data.sint) {
		memprintf(err, "Unexpected value 0 for index");
		return 0;
	}

	arg++;

	if (arg->type != ARGT_STR) {
		memprintf(err, "Unexpected arg type");
		return 0;
	}

	if (!arg->data.str.data) {
		memprintf(err, "Empty separators list");
		return 0;
	}

	return 1;
}

/* This sample function is designed to a return selected part of a string (field).
 * First arg is the index of the field (start at 1)
 * Second arg is a char list of separators (type string)
 */
static int sample_conv_field(const struct arg *arg_p, struct sample *smp, void *private)
{
	int field;
	char *start, *end;
	int i;
	int count = (arg_p[2].type == ARGT_SINT) ? arg_p[2].data.sint : 1;

	if (!arg_p[0].data.sint)
		return 0;

	if (arg_p[0].data.sint < 0) {
		field = -1;
		end = start = smp->data.u.str.area + smp->data.u.str.data;
		while (start > smp->data.u.str.area) {
			for (i = 0 ; i < arg_p[1].data.str.data; i++) {
				if (*(start-1) == arg_p[1].data.str.area[i]) {
					if (field == arg_p[0].data.sint) {
						if (count == 1)
							goto found;
						else if (count > 1)
							count--;
					} else {
						end = start-1;
						field--;
					}
					break;
				}
			}
			start--;
		}
	} else {
		field = 1;
		end = start = smp->data.u.str.area;
		while (end - smp->data.u.str.area < smp->data.u.str.data) {
			for (i = 0 ; i < arg_p[1].data.str.data; i++) {
				if (*end == arg_p[1].data.str.area[i]) {
					if (field == arg_p[0].data.sint) {
						if (count == 1)
							goto found;
						else if (count > 1)
							count--;
					} else {
						start = end+1;
						field++;
					}
					break;
				}
			}
			end++;
		}
	}

	/* Field not found */
	if (field != arg_p[0].data.sint) {
		smp->data.u.str.data = 0;
		return 0;
	}
found:
	smp->data.u.str.data = end - start;
	/* If ret string is len 0, no need to
           change pointers or to update size */
	if (!smp->data.u.str.data)
		return 1;

	/* Compute remaining size if needed
           Note: smp->data.u.str.size cannot be set to 0 */
	if (smp->data.u.str.size)
		smp->data.u.str.size -= start - smp->data.u.str.area;

	smp->data.u.str.area = start;

	return 1;
}

/* This sample function is designed to return a word from a string.
 * First arg is the index of the word (start at 1)
 * Second arg is a char list of words separators (type string)
 */
static int sample_conv_word(const struct arg *arg_p, struct sample *smp, void *private)
{
	int word;
	char *start, *end;
	int i, issep, inword;
	int count = (arg_p[2].type == ARGT_SINT) ? arg_p[2].data.sint : 1;

	if (!arg_p[0].data.sint)
		return 0;

	word = 0;
	inword = 0;
	if (arg_p[0].data.sint < 0) {
		end = start = smp->data.u.str.area + smp->data.u.str.data;
		while (start > smp->data.u.str.area) {
			issep = 0;
			for (i = 0 ; i < arg_p[1].data.str.data; i++) {
				if (*(start-1) == arg_p[1].data.str.area[i]) {
					issep = 1;
					break;
				}
			}
			if (!inword) {
				if (!issep) {
					if (word != arg_p[0].data.sint) {
						word--;
						end = start;
					}
					inword = 1;
				}
			}
			else if (issep) {
				if (word == arg_p[0].data.sint) {
					if (count == 1)
						goto found;
					else if (count > 1)
						count--;
				}
				inword = 0;
			}
			start--;
		}
	} else {
		end = start = smp->data.u.str.area;
		while (end - smp->data.u.str.area < smp->data.u.str.data) {
			issep = 0;
			for (i = 0 ; i < arg_p[1].data.str.data; i++) {
				if (*end == arg_p[1].data.str.area[i]) {
					issep = 1;
					break;
				}
			}
			if (!inword) {
				if (!issep) {
					if (word != arg_p[0].data.sint) {
						word++;
						start = end;
					}
					inword = 1;
				}
			}
			else if (issep) {
				if (word == arg_p[0].data.sint) {
					if (count == 1)
						goto found;
					else if (count > 1)
						count--;
				}
				inword = 0;
			}
			end++;
		}
	}

	/* Field not found */
	if (word != arg_p[0].data.sint) {
		smp->data.u.str.data = 0;
		return 0;
	}
found:
	smp->data.u.str.data = end - start;
	/* If ret string is len 0, no need to
           change pointers or to update size */
	if (!smp->data.u.str.data)
		return 1;


	/* Compute remaining size if needed
           Note: smp->data.u.str.size cannot be set to 0 */
	if (smp->data.u.str.size)
		smp->data.u.str.size -= start - smp->data.u.str.area;

	smp->data.u.str.area = start;

	return 1;
}

static int sample_conv_param_check(struct arg *arg, struct sample_conv *conv,
                                   const char *file, int line, char **err)
{
	if (arg[1].type == ARGT_STR && arg[1].data.str.data != 1) {
		memprintf(err, "Delimiter must be exactly 1 character.");
		return 0;
	}

	return 1;
}

static int sample_conv_param(const struct arg *arg_p, struct sample *smp, void *private)
{
	char *pos, *end, *pend, *equal;
	char delim = '&';
	const char *name = arg_p[0].data.str.area;
	size_t name_l = arg_p[0].data.str.data;

	if (arg_p[1].type == ARGT_STR)
		delim = *arg_p[1].data.str.area;

	pos = smp->data.u.str.area;
	end = pos + smp->data.u.str.data;
	while (pos < end) {
		equal = pos + name_l;
		/* Parameter not found */
		if (equal > end)
			break;

		if (equal == end || *equal == delim) {
			if (memcmp(pos, name, name_l) == 0) {
				/* input contains parameter, but no value is supplied */
				smp->data.u.str.data = 0;
				return 1;
			}
			pos = equal + 1;
			continue;
		}

		if (*equal == '=' && memcmp(pos, name, name_l) == 0) {
			pos = equal + 1;
			pend = memchr(pos, delim, end - pos);
			if (pend == NULL)
				pend = end;

			if (smp->data.u.str.size)
				smp->data.u.str.size -= pos - smp->data.u.str.area;
			smp->data.u.str.area = pos;
			smp->data.u.str.data = pend - pos;
			return 1;
		}
		/* find the next delimiter and set position to character after that */
		pos = memchr(pos, delim, end - pos);
		if (pos == NULL)
			pos = end;
		else
			pos++;
	}
	/* Parameter not found */
	smp->data.u.str.data = 0;
	return 0;
}

static int sample_conv_regsub_check(struct arg *args, struct sample_conv *conv,
                                    const char *file, int line, char **err)
{
	struct arg *arg = args;
	char *p;
	int len;

	/* arg0 is a regex, it uses type_flag for ICASE and global match */
	arg[0].type_flags = 0;

	if (arg[2].type != ARGT_STR)
		return 1;

	p = arg[2].data.str.area;
	len = arg[2].data.str.data;
	while (len) {
		if (*p == 'i') {
			arg[0].type_flags |= ARGF_REG_ICASE;
		}
		else if (*p == 'g') {
			arg[0].type_flags |= ARGF_REG_GLOB;
		}
		else {
			memprintf(err, "invalid regex flag '%c', only 'i' and 'g' are supported", *p);
			return 0;
		}
		p++;
		len--;
	}
	return 1;
}

/* This sample function is designed to do the equivalent of s/match/replace/ on
 * the input string. It applies a regex and restarts from the last matched
 * location until nothing matches anymore. First arg is the regex to apply to
 * the input string, second arg is the replacement expression.
 */
static int sample_conv_regsub(const struct arg *arg_p, struct sample *smp, void *private)
{
	char *start, *end;
	struct my_regex *reg = arg_p[0].data.reg;
	regmatch_t pmatch[MAX_MATCH];
	struct buffer *trash = get_trash_chunk();
	struct buffer *output;
	int flag, max;
	int found;

	start = smp->data.u.str.area;
	end = start + smp->data.u.str.data;

	flag = 0;
	while (1) {
		/* check for last round which is used to copy remaining parts
		 * when not running in global replacement mode.
		 */
		found = 0;
		if ((arg_p[0].type_flags & ARGF_REG_GLOB) || !(flag & REG_NOTBOL)) {
			/* Note: we can have start == end on empty strings or at the end */
			found = regex_exec_match2(reg, start, end - start, MAX_MATCH, pmatch, flag);
		}

		if (!found)
			pmatch[0].rm_so = end - start;

		/* copy the heading non-matching part (which may also be the tail if nothing matches) */
		max = trash->size - trash->data;
		if (max && pmatch[0].rm_so > 0) {
			if (max > pmatch[0].rm_so)
				max = pmatch[0].rm_so;
			memcpy(trash->area + trash->data, start, max);
			trash->data += max;
		}

		if (!found)
			break;

		output = alloc_trash_chunk();
		if (!output)
			break;

		output->data = exp_replace(output->area, output->size, start, arg_p[1].data.str.area, pmatch);

		/* replace the matching part */
		max = output->size - output->data;
		if (max) {
			if (max > output->data)
				max = output->data;
			memcpy(trash->area + trash->data,
			       output->area, max);
			trash->data += max;
		}

		free_trash_chunk(output);

		/* stop here if we're done with this string */
		if (start >= end)
			break;

		/* We have a special case for matches of length 0 (eg: "x*y*").
		 * These ones are considered to match in front of a character,
		 * so we have to copy that character and skip to the next one.
		 */
		if (!pmatch[0].rm_eo) {
			if (trash->data < trash->size)
				trash->area[trash->data++] = start[pmatch[0].rm_eo];
			pmatch[0].rm_eo++;
		}

		start += pmatch[0].rm_eo;
		flag |= REG_NOTBOL;
	}

	smp->data.u.str = *trash;
	return 1;
}

/* This function check an operator entry. It expects a string.
 * The string can be an integer or a variable name.
 */
static int check_operator(struct arg *args, struct sample_conv *conv,
                          const char *file, int line, char **err)
{
	const char *str;
	const char *end;
	long long int i;

	/* Try to decode a variable. The 'err' variable is intentionnaly left
	 * NULL since the operators accept an integer as argument in which case
	 * vars_check_arg call will fail.
	 */
	if (vars_check_arg(&args[0], NULL))
		return 1;

	/* Try to convert an integer */
	str = args[0].data.str.area;
	end = str + strlen(str);
	i = read_int64(&str, end);
	if (*str != '\0') {
		memprintf(err, "expects an integer or a variable name");
		return 0;
	}

	chunk_destroy(&args[0].data.str);
	args[0].type = ARGT_SINT;
	args[0].data.sint = i;
	return 1;
}

/* This function returns a sample struct filled with an arg content.
 * If the arg contain an integer, the integer is returned in the
 * sample. If the arg contains a variable descriptor, it returns the
 * variable value.
 *
 * This function returns 0 if an error occurs, otherwise it returns 1.
 */
int sample_conv_var2smp_sint(const struct arg *arg, struct sample *smp)
{
	switch (arg->type) {
	case ARGT_SINT:
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = arg->data.sint;
		return 1;
	case ARGT_VAR:
		return sample_conv_var2smp(&arg->data.var, smp, SMP_T_SINT);
	default:
		return 0;
	}
}

/* Takes a SINT on input, applies a binary twos complement and returns the SINT
 * result.
 */
static int sample_conv_binary_cpl(const struct arg *arg_p, struct sample *smp, void *private)
{
	smp->data.u.sint = ~smp->data.u.sint;
	return 1;
}

/* Takes a SINT on input, applies a binary "and" with the SINT directly in
 * arg_p or in the variable described in arg_p, and returns the SINT result.
 */
static int sample_conv_binary_and(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct sample tmp;

	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_sint(arg_p, &tmp))
		return 0;
	smp->data.u.sint &= tmp.data.u.sint;
	return 1;
}

/* Takes a SINT on input, applies a binary "or" with the SINT directly in
 * arg_p or in the variable described in arg_p, and returns the SINT result.
 */
static int sample_conv_binary_or(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct sample tmp;

	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_sint(arg_p, &tmp))
		return 0;
	smp->data.u.sint |= tmp.data.u.sint;
	return 1;
}

/* Takes a SINT on input, applies a binary "xor" with the SINT directly in
 * arg_p or in the variable described in arg_p, and returns the SINT result.
 */
static int sample_conv_binary_xor(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct sample tmp;

	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_sint(arg_p, &tmp))
		return 0;
	smp->data.u.sint ^= tmp.data.u.sint;
	return 1;
}

static inline long long int arith_add(long long int a, long long int b)
{
	/* Prevent overflow and makes capped calculus.
	 * We must ensure that the check calculus doesn't
	 * exceed the signed 64 bits limits.
	 *
	 *        +----------+----------+
	 *        |   a<0    |   a>=0   |
	 * +------+----------+----------+
	 * | b<0  | MIN-a>b  | no check |
	 * +------+----------+----------+
	 * | b>=0 | no check | MAX-a<b  |
	 * +------+----------+----------+
	 */
	if ((a ^ b) >= 0) {
		/* signs are same. */
		if (a < 0) {
			if (LLONG_MIN - a > b)
				return LLONG_MIN;
		}
		else if (LLONG_MAX - a < b)
			return LLONG_MAX;
	}
	return a + b;
}

/* Takes a SINT on input, applies an arithmetic "add" with the SINT directly in
 * arg_p or in the variable described in arg_p, and returns the SINT result.
 */
static int sample_conv_arith_add(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct sample tmp;

	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_sint(arg_p, &tmp))
		return 0;
	smp->data.u.sint = arith_add(smp->data.u.sint, tmp.data.u.sint);
	return 1;
}

/* Takes a SINT on input, applies an arithmetic "sub" with the SINT directly in
 * arg_p or in the variable described in arg_p, and returns the SINT result.
 */
static int sample_conv_arith_sub(const struct arg *arg_p,
                                 struct sample *smp, void *private)
{
	struct sample tmp;

	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_sint(arg_p, &tmp))
		return 0;

	/* We cannot represent -LLONG_MIN because abs(LLONG_MIN) is greater
	 * than abs(LLONG_MAX). So, the following code use LLONG_MAX in place
	 * of -LLONG_MIN and correct the result.
	 */
	if (tmp.data.u.sint == LLONG_MIN) {
		smp->data.u.sint = arith_add(smp->data.u.sint, LLONG_MAX);
		if (smp->data.u.sint < LLONG_MAX)
			smp->data.u.sint++;
		return 1;
	}

	/* standard subtraction: we use the "add" function and negate
	 * the second operand.
	 */
	smp->data.u.sint = arith_add(smp->data.u.sint, -tmp.data.u.sint);
	return 1;
}

/* Takes a SINT on input, applies an arithmetic "mul" with the SINT directly in
 * arg_p or in the variable described in arg_p, and returns the SINT result.
 * If the result makes an overflow, then the largest possible quantity is
 * returned.
 */
static int sample_conv_arith_mul(const struct arg *arg_p,
                                 struct sample *smp, void *private)
{
	struct sample tmp;
	long long int c;

	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_sint(arg_p, &tmp))
		return 0;

	/* prevent divide by 0 during the check */
	if (!smp->data.u.sint || !tmp.data.u.sint) {
		smp->data.u.sint = 0;
		return 1;
	}

	/* The multiply between LLONG_MIN and -1 returns a
	 * "floating point exception".
	 */
	if (smp->data.u.sint == LLONG_MIN && tmp.data.u.sint == -1) {
		smp->data.u.sint = LLONG_MAX;
		return 1;
	}

	/* execute standard multiplication. */
	c = smp->data.u.sint * tmp.data.u.sint;

	/* check for overflow and makes capped multiply. */
	if (smp->data.u.sint != c / tmp.data.u.sint) {
		if ((smp->data.u.sint < 0) == (tmp.data.u.sint < 0)) {
			smp->data.u.sint = LLONG_MAX;
			return 1;
		}
		smp->data.u.sint = LLONG_MIN;
		return 1;
	}
	smp->data.u.sint = c;
	return 1;
}

/* Takes a SINT on input, applies an arithmetic "div" with the SINT directly in
 * arg_p or in the variable described in arg_p, and returns the SINT result.
 * If arg_p makes the result overflow, then the largest possible quantity is
 * returned.
 */
static int sample_conv_arith_div(const struct arg *arg_p,
                                 struct sample *smp, void *private)
{
	struct sample tmp;

	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_sint(arg_p, &tmp))
		return 0;

	if (tmp.data.u.sint) {
		/* The divide between LLONG_MIN and -1 returns a
		 * "floating point exception".
		 */
		if (smp->data.u.sint == LLONG_MIN && tmp.data.u.sint == -1) {
			smp->data.u.sint = LLONG_MAX;
			return 1;
		}
		smp->data.u.sint /= tmp.data.u.sint;
		return 1;
	}
	smp->data.u.sint = LLONG_MAX;
	return 1;
}

/* Takes a SINT on input, applies an arithmetic "mod" with the SINT directly in
 * arg_p or in the variable described in arg_p, and returns the SINT result.
 * If arg_p makes the result overflow, then 0 is returned.
 */
static int sample_conv_arith_mod(const struct arg *arg_p,
                                 struct sample *smp, void *private)
{
	struct sample tmp;

	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_sint(arg_p, &tmp))
		return 0;

	if (tmp.data.u.sint) {
		/* The divide between LLONG_MIN and -1 returns a
		 * "floating point exception".
		 */
		if (smp->data.u.sint == LLONG_MIN && tmp.data.u.sint == -1) {
			smp->data.u.sint = 0;
			return 1;
		}
		smp->data.u.sint %= tmp.data.u.sint;
		return 1;
	}
	smp->data.u.sint = 0;
	return 1;
}

/* Takes an SINT on input, applies an arithmetic "neg" and returns the SINT
 * result.
 */
static int sample_conv_arith_neg(const struct arg *arg_p,
                                 struct sample *smp, void *private)
{
	if (smp->data.u.sint == LLONG_MIN)
		smp->data.u.sint = LLONG_MAX;
	else
		smp->data.u.sint = -smp->data.u.sint;
	return 1;
}

/* Takes a SINT on input, returns true is the value is non-null, otherwise
 * false. The output is a BOOL.
 */
static int sample_conv_arith_bool(const struct arg *arg_p,
                                  struct sample *smp, void *private)
{
	smp->data.u.sint = !!smp->data.u.sint;
	smp->data.type = SMP_T_BOOL;
	return 1;
}

/* Takes a SINT on input, returns false is the value is non-null, otherwise
 * truee. The output is a BOOL.
 */
static int sample_conv_arith_not(const struct arg *arg_p,
                                 struct sample *smp, void *private)
{
	smp->data.u.sint = !smp->data.u.sint;
	smp->data.type = SMP_T_BOOL;
	return 1;
}

/* Takes a SINT on input, returns true is the value is odd, otherwise false.
 * The output is a BOOL.
 */
static int sample_conv_arith_odd(const struct arg *arg_p,
                                 struct sample *smp, void *private)
{
	smp->data.u.sint = smp->data.u.sint & 1;
	smp->data.type = SMP_T_BOOL;
	return 1;
}

/* Takes a SINT on input, returns true is the value is even, otherwise false.
 * The output is a BOOL.
 */
static int sample_conv_arith_even(const struct arg *arg_p,
                                  struct sample *smp, void *private)
{
	smp->data.u.sint = !(smp->data.u.sint & 1);
	smp->data.type = SMP_T_BOOL;
	return 1;
}

/* appends an optional const string, an optional variable contents and another
 * optional const string to an existing string.
 */
static int sample_conv_concat(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *trash;
	struct sample tmp;
	int max;

	trash = alloc_trash_chunk();
	if (!trash)
		return 0;

	trash->data = smp->data.u.str.data;
	if (trash->data > trash->size - 1)
		trash->data = trash->size - 1;

	memcpy(trash->area, smp->data.u.str.area, trash->data);
	trash->area[trash->data] = 0;

	/* append first string */
	max = arg_p[0].data.str.data;
	if (max > trash->size - 1 - trash->data)
		max = trash->size - 1 - trash->data;

	if (max) {
		memcpy(trash->area + trash->data, arg_p[0].data.str.area, max);
		trash->data += max;
		trash->area[trash->data] = 0;
	}

	/* append second string (variable) if it's found and we can turn it
	 * into a string.
	 */
	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (arg_p[1].type == ARGT_VAR && vars_get_by_desc(&arg_p[1].data.var, &tmp, NULL) &&
	    (sample_casts[tmp.data.type][SMP_T_STR] == c_none ||
	     sample_casts[tmp.data.type][SMP_T_STR](&tmp))) {

		max = tmp.data.u.str.data;
		if (max > trash->size - 1 - trash->data)
			max = trash->size - 1 - trash->data;

		if (max) {
			memcpy(trash->area + trash->data, tmp.data.u.str.area,
			       max);
			trash->data += max;
			trash->area[trash->data] = 0;
		}
	}

	/* append third string */
	max = arg_p[2].data.str.data;
	if (max > trash->size - 1 - trash->data)
		max = trash->size - 1 - trash->data;

	if (max) {
		memcpy(trash->area + trash->data, arg_p[2].data.str.area, max);
		trash->data += max;
		trash->area[trash->data] = 0;
	}

	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp_dup(smp);
	free_trash_chunk(trash);
	return 1;
}

/* This function checks the "concat" converter's arguments and extracts the
 * variable name and its scope.
 */
static int smp_check_concat(struct arg *args, struct sample_conv *conv,
                           const char *file, int line, char **err)
{
	/* Try to decode a variable. */
	if (args[1].data.str.data > 0 && !vars_check_arg(&args[1], NULL)) {
		memprintf(err, "failed to register variable name '%s'",
			  args[1].data.str.area);
		return 0;
	}
	return 1;
}

/* Append delimiter (only to a non empty input) followed by the optional
 * variable contents concatenated with the optional sufix.
 */
static int sample_conv_add_item(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *tmpbuf;
	struct sample tmp;
	size_t max;
	int var_available;

	tmpbuf = alloc_trash_chunk();
	if (!tmpbuf)
		return 0;

	tmpbuf->data = smp->data.u.str.data;
	if (tmpbuf->data > tmpbuf->size - 1)
		tmpbuf->data = tmpbuf->size - 1;

	memcpy(tmpbuf->area, smp->data.u.str.area, tmpbuf->data);
	tmpbuf->area[tmpbuf->data] = 0;

	/* Check if variable is found and we can turn into a string. */
	var_available = 0;
	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (arg_p[1].type == ARGT_VAR && vars_get_by_desc(&arg_p[1].data.var, &tmp, NULL) &&
	    (sample_casts[tmp.data.type][SMP_T_STR] == c_none ||
	     sample_casts[tmp.data.type][SMP_T_STR](&tmp)))
		var_available = 1;

	/* Append delimiter only if input is not empty and either
	 * the variable or the suffix are not empty
	 */
	if (smp->data.u.str.data && ((var_available && tmp.data.u.str.data) ||
	    arg_p[2].data.str.data)) {
		max = arg_p[0].data.str.data;
		if (max > tmpbuf->size - 1 - tmpbuf->data)
			max = tmpbuf->size - 1 - tmpbuf->data;

		if (max) {
			memcpy(tmpbuf->area + tmpbuf->data, arg_p[0].data.str.area, max);
			tmpbuf->data += max;
			tmpbuf->area[tmpbuf->data] = 0;
		}
	}

	/* Append variable contents if variable is found and turned into string. */
	if (var_available) {
		max = tmp.data.u.str.data;
		if (max > tmpbuf->size - 1 - tmpbuf->data)
			max = tmpbuf->size - 1 - tmpbuf->data;

		if (max) {
			memcpy(tmpbuf->area + tmpbuf->data, tmp.data.u.str.area, max);
			tmpbuf->data += max;
			tmpbuf->area[tmpbuf->data] = 0;
		}
	}

	/* Append optional suffix. */
	max = arg_p[2].data.str.data;
	if (max > tmpbuf->size - 1 - tmpbuf->data)
		max = tmpbuf->size - 1 - tmpbuf->data;

	if (max) {
		memcpy(tmpbuf->area + tmpbuf->data, arg_p[2].data.str.area, max);
		tmpbuf->data += max;
		tmpbuf->area[tmpbuf->data] = 0;
	}

	smp->data.u.str = *tmpbuf;
	smp->data.type = SMP_T_STR;
	smp_dup(smp);
	free_trash_chunk(tmpbuf);
	return 1;
}

/* Check the "add_item" converter's arguments and extracts the
 * variable name and its scope.
 */
static int smp_check_add_item(struct arg *args, struct sample_conv *conv,
                           const char *file, int line, char **err)
{
	/* Try to decode a variable. */
	if (args[1].data.str.data > 0 && !vars_check_arg(&args[1], NULL)) {
		memprintf(err, "failed to register variable name '%s'",
			  args[1].data.str.area);
		return 0;
	}

	if (args[1].data.str.data == 0 && args[2].data.str.data == 0) {
		memprintf(err, "one of the optional arguments has to be nonempty");
		return 0;
	}

	return 1;
}

/* Compares string with a variable containing a string. Return value
 * is compatible with strcmp(3)'s return value.
 */
static int sample_conv_strcmp(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct sample tmp;
	int max, result;

	smp_set_owner(&tmp, smp->px, smp->sess, smp->strm, smp->opt);
	if (arg_p[0].type != ARGT_VAR)
		return 0;

	if (!sample_conv_var2smp(&arg_p[0].data.var, &tmp, SMP_T_STR))
		return 0;

	max = MIN(smp->data.u.str.data, tmp.data.u.str.data);
	result = strncmp(smp->data.u.str.area, tmp.data.u.str.area, max);
	if (result == 0) {
		if (smp->data.u.str.data != tmp.data.u.str.data) {
			if (smp->data.u.str.data < tmp.data.u.str.data) {
				result = -1;
			}
			else {
				result = 1;
			}
		}
	}

	smp->data.u.sint = result;
	smp->data.type = SMP_T_SINT;
	return 1;
}
/*
 * This converter can takes a Host header value as defined by rfc9110#section-7.2
 * Host = uri-host [ ":" port ] ;
 * It returns the uri-host value in lowecase with the port stripped.
 */
static int sample_conv_host_only(const struct arg *arg_p, struct sample *smp, void *private)
{
	/* Working cases: hostname00, hostname00:80, 127.0.0.1, 127.0.0.1:80, [::1], [::1]:80 */
	char *beg = smp->data.u.str.area;
	char *end = smp->data.u.str.area + smp->data.u.str.data - 1;
	char *p;

	for (p = end; p >= beg; p--) {
		if (*p == ':' || *p == ']')
			break;
	}

	if (p >= beg && *p == ':')
		smp->data.u.str.data = p - beg;
	/* if no port part was found, the hostname is the whole string */

	smp->data.type = SMP_T_STR;

	return sample_conv_str2lower(arg_p, smp, NULL);
}

/*
 * This converter can takes a Host header value as defined by rfc9110#section-7.2
 * Host = uri-host [ ":" port ] ;
 * It returns the port value as a int.
 */
static int sample_conv_port_only(const struct arg *arg_p, struct sample *smp, void *private)
{
	/* Working cases: hostname00, hostname00:80, 127.0.0.1, 127.0.0.1:80, [::1], [::1]:80 */
	char *beg = smp->data.u.str.area;
	char *end = smp->data.u.str.area + smp->data.u.str.data - 1;
	char *p;

	for (p = end; p >= beg; p--) {
		if (*p == ':' || *p == ']')
			break;
	}

	smp->data.type = SMP_T_SINT;
	if (p >= beg && *p == ':' && ++p <= end) {
		smp->data.u.sint = strl2ui(p, smp->data.u.str.data + smp->data.u.str.area - p);
	} else {
		smp->data.u.sint = 0;
	}
	return 1;
}


/* Takes a boolean as input. Returns the first argument if that boolean is true and
 * the second argument otherwise.
 */
static int sample_conv_iif(const struct arg *arg_p, struct sample *smp, void *private)
{
	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_CONST;

	if (smp->data.u.sint) {
		smp->data.u.str.data = arg_p[0].data.str.data;
		smp->data.u.str.area = arg_p[0].data.str.area;
	}
	else {
		smp->data.u.str.data = arg_p[1].data.str.data;
		smp->data.u.str.area = arg_p[1].data.str.area;
	}

	return 1;
}

enum {
	WHEN_COND_STOPPING,
	WHEN_COND_NORMAL,
	WHEN_COND_ERROR,
	WHEN_COND_FORWARDED,
	WHEN_COND_TOAPPLET,
	WHEN_COND_PROCESSED,
	WHEN_COND_ACL,
	WHEN_COND_CONDITIONS
};

const char *when_cond_kw[WHEN_COND_CONDITIONS] = {
	[WHEN_COND_STOPPING]    = "stopping",
	[WHEN_COND_NORMAL]      = "normal",
	[WHEN_COND_ERROR]       = "error",
	[WHEN_COND_FORWARDED]	= "forwarded",
	[WHEN_COND_TOAPPLET]	= "toapplet",
	[WHEN_COND_PROCESSED]	= "processed",
	[WHEN_COND_ACL]         = "acl",
};

/* Evaluates a condition and decides whether or not to pass the input sample
 * to the output. The purpose is to hide some info when certain conditions are
 * (not) met. These conditions belong to a fixed list that can verify internal
 * states (debug mode, too high load, reloading, server down, stream in error
 * etc). The condition's sign is placed in arg_p[0].data.int. 0=direct, 1=inv.
 * The condition keyword is in arg_p[1].data.int (WHEN_COND_*).
 */
static int sample_conv_when(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct session *sess = smp->sess;
	struct stream *strm = smp->strm;
	int neg  = arg_p[0].data.sint;
	int cond = arg_p[1].data.sint;
	struct acl_sample *acl_sample;
	int ret = 0;

	switch (cond) {
	case WHEN_COND_STOPPING:
		ret = !!stopping;
		break;

	case WHEN_COND_NORMAL:
		neg = !neg;
		__fallthrough;

	case WHEN_COND_ERROR:
		if (strm &&
		    ((strm->flags & SF_REDISP) ||
		     ((strm->flags & SF_ERR_MASK) > SF_ERR_LOCAL) ||
		     (((strm->flags & SF_ERR_MASK) == SF_ERR_NONE) && strm->conn_retries) ||
		     ((sess->fe->mode == PR_MODE_HTTP) && strm->txn && strm->txn->status >= 500)))
			ret = 1;
		break;

	case WHEN_COND_FORWARDED: // true if forwarded to a connection
		ret = !!sc_conn(smp->strm->scb);
		break;

	case WHEN_COND_TOAPPLET:  // true if handled as an applet
		ret = !!sc_appctx(smp->strm->scb);
		break;

	case WHEN_COND_PROCESSED: // true if forwarded or appctx
		ret = sc_conn(smp->strm->scb) || sc_appctx(smp->strm->scb);
		break;

	case WHEN_COND_ACL: // true if the ACL pointed to by args[2] evaluates to true
		acl_sample = arg_p[2].data.ptr;
		ret = acl_exec_cond(&acl_sample->cond, smp->px, smp->sess, smp->strm, smp->opt) == ACL_TEST_PASS;
		break;
	}

	ret = !!ret ^ !!neg;
	if (!ret) {
		/* kill the sample */
		return 0;
	}

	/* pass the sample as-is */
	return 1;
}

/* checks and resolves the type of the argument passed to when().
 * It supports an optional '!' to negate the condition, followed by
 * a keyword among the list above. Note that we're purposely declaring
 * one extra arg because the first one will be split into two.
 */
static int check_when_cond(struct arg *args, struct sample_conv *conv,
                             const char *file, int line, char **err)
{
	struct acl_sample *acl_sample;
	const char *kw;
	int neg = 0;
	int i;

	kw = args[0].data.str.area;
	if (*kw == '!') {
		kw++;
		neg = 1;
	}

	for (i = 0; i < WHEN_COND_CONDITIONS; i++) {
		if (strcmp(kw, when_cond_kw[i]) == 0)
			break;
	}

	if (i == WHEN_COND_CONDITIONS) {
		memprintf(err, "expects a supported keyword among {");
		for (i = 0; i < WHEN_COND_CONDITIONS; i++)
			memprintf(err, "%s%s%s", *err, when_cond_kw[i],  (i == WHEN_COND_CONDITIONS - 1) ? "}" : ",");
		memprintf(err, "%s but got '%s'", *err, kw);
		return 0;
	}

	if (i == WHEN_COND_ACL) {
		if (args[1].type != ARGT_STR || !*args[1].data.str.area) {
			memprintf(err, "'acl' selector requires an extra argument with the ACL name");
			return 0;
		}

		if (!curproxy) {
			memprintf(err, "'acl' selector may only be used in the context of a proxy");
			return 0;
		}

		acl_sample = calloc(1, sizeof(struct acl_sample) + sizeof(struct acl_term));
		if (!acl_sample) {
			memprintf(err, "not enough memory for 'acl' selector");
			return 0;
		}

		LIST_INIT(&acl_sample->suite.terms);
		LIST_INIT(&acl_sample->cond.suites);
		LIST_APPEND(&acl_sample->cond.suites, &acl_sample->suite.list);
		LIST_APPEND(&acl_sample->suite.terms, &acl_sample->terms[0].list);
		acl_sample->cond.val = ~0U; // the keyword is valid everywhere for now.

		/* build one term based on the ACL kw */
		if (!(acl_sample->terms[0].acl = find_acl_by_name(args[1].data.str.area, &curproxy->acl)) &&
		    !(acl_sample->terms[0].acl = find_acl_default(args[1].data.str.area, &curproxy->acl, err, NULL, NULL, 0))) {
			memprintf(err, "ACL '%s' not found", args[1].data.str.area);
			return 0;
		}

		acl_sample->cond.use |= acl_sample->terms[0].acl->use;
		acl_sample->cond.val &= acl_sample->terms[0].acl->val;

		args[2].type = ARGT_PTR;
		args[2].unresolved = 0;
		args[2].resolve_ptr = NULL;
		args[2].data.ptr = acl_sample;
	}

	chunk_destroy(&args[0].data.str);
	if (args[1].type == ARGT_STR)
		chunk_destroy(&args[1].data.str);

	if (args[2].type == ARGT_STR)
		chunk_destroy(&args[2].data.str);

	// store condition
	args[0].type = ARGT_SINT;
	args[0].data.sint = neg; // '!' present

	// and keyword
	args[1].type = ARGT_SINT;
	args[1].data.sint = i;
	return 1;
}

#define GRPC_MSG_COMPRESS_FLAG_SZ 1 /* 1 byte */
#define GRPC_MSG_LENGTH_SZ        4 /* 4 bytes */
#define GRPC_MSG_HEADER_SZ        (GRPC_MSG_COMPRESS_FLAG_SZ + GRPC_MSG_LENGTH_SZ)

/*
 * Extract the field value of an input binary sample. Takes a mandatory argument:
 * the protocol buffers field identifier (dotted notation) internally represented
 * as an array of unsigned integers and its size.
 * Return 1 if the field was found, 0 if not.
 */
static int sample_conv_ungrpc(const struct arg *arg_p, struct sample *smp, void *private)
{
	unsigned char *pos;
	size_t grpc_left;

	pos = (unsigned char *)smp->data.u.str.area;
	grpc_left = smp->data.u.str.data;

	while (grpc_left > GRPC_MSG_HEADER_SZ) {
		size_t grpc_msg_len, left;

		grpc_msg_len = left = ntohl(read_u32(pos + GRPC_MSG_COMPRESS_FLAG_SZ));

		pos += GRPC_MSG_HEADER_SZ;
		grpc_left -= GRPC_MSG_HEADER_SZ;

		if (grpc_left < left)
			return 0;

		if (protobuf_field_lookup(arg_p, smp, &pos, &left))
			return 1;

		grpc_left -= grpc_msg_len;
	}

	return 0;
}

static int sample_conv_protobuf(const struct arg *arg_p, struct sample *smp, void *private)
{
	unsigned char *pos;
	size_t left;

	pos = (unsigned char *)smp->data.u.str.area;
	left = smp->data.u.str.data;

	return protobuf_field_lookup(arg_p, smp, &pos, &left);
}

static int sample_conv_protobuf_check(struct arg *args, struct sample_conv *conv,
                                      const char *file, int line, char **err)
{
	if (!args[1].type) {
		args[1].type = ARGT_SINT;
		args[1].data.sint = PBUF_T_BINARY;
	}
	else {
		int pbuf_type;

		pbuf_type = protobuf_type(args[1].data.str.area);
		if (pbuf_type == -1) {
			memprintf(err, "Wrong protocol buffer type '%s'", args[1].data.str.area);
			return 0;
		}

		chunk_destroy(&args[1].data.str);
		args[1].type = ARGT_SINT;
		args[1].data.sint = pbuf_type;
	}

	return 1;
}

/*
 * Extract the tag value of an input binary sample. Takes a mandatory argument:
 * the FIX protocol tag identifier.
 * Return 1 if the tag was found, 0 if not.
 */
static int sample_conv_fix_tag_value(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct ist value;

	smp->flags &= ~SMP_F_MAY_CHANGE;
	value = fix_tag_value(ist2(smp->data.u.str.area, smp->data.u.str.data),
			      arg_p[0].data.sint);
	if (!istlen(value)) {
		if (isttest(value)) {
			/* value != IST_NULL, need more data */
			smp->flags |= SMP_F_MAY_CHANGE;
		}
		return 0;
	}

	smp->data.u.str = ist2buf(value);
	smp->flags |= SMP_F_CONST;

	return 1;
}

/* This function checks the "fix_tag_value" converter configuration.
 * It expects a "known" (by HAProxy) tag name or ID.
 * Tag string names are converted to their ID counterpart because this is the
 * format they are sent over the wire.
 */
static int sample_conv_fix_value_check(struct arg *args, struct sample_conv *conv,
				       const char *file, int line, char **err)
{
	struct ist str;
	unsigned int tag;

	str = ist2(args[0].data.str.area, args[0].data.str.data);
	tag = fix_tagid(str);
	if (!tag) {
		memprintf(err, "Unknown FIX tag name '%s'", args[0].data.str.area);
		return 0;
	}

	chunk_destroy(&args[0].data.str);
	args[0].type = ARGT_SINT;
	args[0].data.sint = tag;

	return 1;
}

/*
 * Checks that a buffer contains a valid FIX message
 *
 * Return 1 if the check could be run, 0 if not.
 * The result of the analyse itself is stored in <smp> as a boolean
 */
static int sample_conv_fix_is_valid(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct ist msg;

	msg = ist2(smp->data.u.str.area, smp->data.u.str.data);

	smp->flags &= ~SMP_F_MAY_CHANGE;
	switch (fix_validate_message(msg)) {
	case FIX_VALID_MESSAGE:
		smp->data.type = SMP_T_BOOL;
		smp->data.u.sint = 1;
		return 1;
	case FIX_NEED_MORE_DATA:
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	case FIX_INVALID_MESSAGE:
		smp->data.type = SMP_T_BOOL;
		smp->data.u.sint = 0;
		return 1;
	}
	return 0;
}

/*
 * Extract the field value of an input binary sample containing an MQTT packet.
 * Takes 2 mandatory arguments:
 * - packet type
 * - field name
 *
 * return 1 if the field was found, 0 if not.
 */
static int sample_conv_mqtt_field_value(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct ist pkt, value;
	int type, fieldname_id;

	pkt = ist2(smp->data.u.str.area, smp->data.u.str.data);
	type = arg_p[0].data.sint;
	fieldname_id = arg_p[1].data.sint;

	smp->flags &= ~SMP_F_MAY_CHANGE;
	value = mqtt_field_value(pkt, type, fieldname_id);
	if (!istlen(value)) {
		if (isttest(value)) {
			/* value != IST_NULL, need more data */
			smp->flags |= SMP_F_MAY_CHANGE;
		}
		return 0;
	}

	smp->data.u.str = ist2buf(value);
	smp->flags |= SMP_F_CONST;
	return 1;
}

/*
 * this function checks the "mqtt_field_value" converter configuration.
 * It expects a known packet type name or ID and a field name, in this order
 *
 * Args[0] will be turned into a MQTT_CPT_* value for direct matching when parsing
 * a packet.
 */
static int sample_conv_mqtt_field_value_check(struct arg *args, struct sample_conv *conv,
					      const char *file, int line, char **err)
{
	int type, fieldname_id;

	/* check the MQTT packet type is valid */
	type = mqtt_typeid(ist2(args[0].data.str.area, args[0].data.str.data));
	if (type == MQTT_CPT_INVALID) {
		memprintf(err, "Unknown MQTT type '%s'", args[0].data.str.area);
		return 0;
	}

	/* check the field name belongs to the MQTT packet type */
	fieldname_id = mqtt_check_type_fieldname(type, ist2(args[1].data.str.area, args[1].data.str.data));
	if (fieldname_id == MQTT_FN_INVALID) {
		memprintf(err, "Unknown MQTT field name '%s' for packet type '%s'", args[1].data.str.area,
			  args[0].data.str.area);
		return 0;
	}

	/* save numeric counterparts of type and field name */
	chunk_destroy(&args[0].data.str);
	chunk_destroy(&args[1].data.str);
	args[0].type = ARGT_SINT;
	args[0].data.sint = type;
	args[1].type = ARGT_SINT;
	args[1].data.sint = fieldname_id;

	return 1;
}

/*
 * Checks that <smp> contains a valid MQTT message
 *
 * The function returns 1 if the check was run to its end, 0 otherwise.
 * The result of the analyse itself is stored in <smp> as a boolean.
 */
static int sample_conv_mqtt_is_valid(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct ist msg;

	msg = ist2(smp->data.u.str.area, smp->data.u.str.data);

	smp->flags &= ~SMP_F_MAY_CHANGE;
	switch (mqtt_validate_message(msg, NULL)) {
	case FIX_VALID_MESSAGE:
		smp->data.type = SMP_T_BOOL;
		smp->data.u.sint = 1;
		return 1;
	case FIX_NEED_MORE_DATA:
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	case FIX_INVALID_MESSAGE:
		smp->data.type = SMP_T_BOOL;
		smp->data.u.sint = 0;
		return 1;
	}
	return 0;
}

/* This function checks the "strcmp" converter's arguments and extracts the
 * variable name and its scope.
 */
static int smp_check_strcmp(struct arg *args, struct sample_conv *conv,
                           const char *file, int line, char **err)
{
	if (!args[0].data.str.data) {
		memprintf(err, "missing variable name");
		return 0;
	}

	/* Try to decode a variable. */
	if (vars_check_arg(&args[0], NULL))
		return 1;

	memprintf(err, "failed to register variable name '%s'",
		  args[0].data.str.area);
	return 0;
}

/**/
static int sample_conv_htonl(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct buffer *tmp;
	uint32_t n;

	n = htonl((uint32_t)smp->data.u.sint);
	tmp = get_trash_chunk();

	memcpy(b_head(tmp), &n, 4);
	b_add(tmp, 4);

	smp->data.u.str = *tmp;
	smp->data.type = SMP_T_BIN;
	return 1;
}

/**/
static int sample_conv_cut_crlf(const struct arg *arg_p, struct sample *smp, void *private)
{
	char *p;
	size_t l;

	p = smp->data.u.str.area;
	for (l = 0; l < smp->data.u.str.data; l++) {
		if (*(p+l) == '\r' || *(p+l) == '\n')
			break;
	}
	smp->data.u.str.data = l;
	return 1;
}

/**/
static int sample_conv_ltrim(const struct arg *arg_p, struct sample *smp, void *private)
{
	char *delimiters, *p;
	size_t dlen, l;

	delimiters =  arg_p[0].data.str.area;
	dlen = arg_p[0].data.str.data;

	l = smp->data.u.str.data;
	p = smp->data.u.str.area;
	while (l && memchr(delimiters, *p, dlen) != NULL) {
		p++;
		l--;
	}

	smp->data.u.str.area = p;
	smp->data.u.str.data = l;
	return 1;
}

/**/
static int sample_conv_rtrim(const struct arg *arg_p, struct sample *smp, void *private)
{
	char *delimiters, *p;
	size_t dlen, l;

	delimiters =  arg_p[0].data.str.area;
	dlen = arg_p[0].data.str.data;

	l = smp->data.u.str.data;
	p = smp->data.u.str.area + l - 1;
	while (l && memchr(delimiters, *p, dlen) != NULL) {
		p--;
		l--;
	}

	smp->data.u.str.data = l;
	return 1;
}

/* This function checks the "json_query" converter's arguments. */
static int sample_check_json_query(struct arg *arg, struct sample_conv *conv,
                           const char *file, int line, char **err)
{
	if (arg[0].data.str.data == 0) {
		memprintf(err, "json_path must not be empty");
		return 0;
	}

	if (arg[1].data.str.data != 0) {
		if (strcmp(arg[1].data.str.area, "int") != 0) {
			memprintf(err, "output_type only supports \"int\" as argument");
			return 0;
		} else {
			arg[1].type = ARGT_SINT;
			arg[1].data.sint = 0;
		}
	}
	return 1;
}

/* Limit JSON integer values to the range [-(2**53)+1, (2**53)-1] as per
 * the recommendation for interoperable integers in section 6 of RFC 7159.
 */
#define JSON_INT_MAX ((1LL << 53) - 1)
#define JSON_INT_MIN (-JSON_INT_MAX)

/* This sample function get the value from a given json string.
 * The mjson library is used to parse the JSON struct
 */
static int sample_conv_json_query(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();
	const char *token; /* holds the temporary string from mjson_find */
	int token_size;    /* holds the length of <token> */

	enum mjson_tok token_type;

	token_type = mjson_find(smp->data.u.str.area, smp->data.u.str.data, args[0].data.str.area, &token, &token_size);

	switch (token_type) {
		case MJSON_TOK_NUMBER:
			if (args[1].type == ARGT_SINT) {
				smp->data.u.sint = strtoll(token, NULL, 0);

				if (smp->data.u.sint < JSON_INT_MIN || smp->data.u.sint > JSON_INT_MAX)
					return 0;

				smp->data.type = SMP_T_SINT;

				return 1;
			} else {
				double double_val;

				if (mjson_get_number(smp->data.u.str.area, smp->data.u.str.data, args[0].data.str.area, &double_val) == 0)
					return 0;

				trash->data = snprintf(trash->area,trash->size,"%g",double_val);
				smp->data.u.str = *trash;
				smp->data.type = SMP_T_STR;

				return 1;
			}
		case MJSON_TOK_TRUE:
			smp->data.type = SMP_T_BOOL;
			smp->data.u.sint = 1;

			return 1;
		case MJSON_TOK_FALSE:
			smp->data.type = SMP_T_BOOL;
			smp->data.u.sint = 0;

			return 1;
		case MJSON_TOK_STRING: {
			int len;

			len = mjson_get_string(smp->data.u.str.area, smp->data.u.str.data, args[0].data.str.area, trash->area, trash->size);

			if (len == -1) {
				/* invalid string */
				return 0;
			}

			trash->data = len;
			smp->data.u.str = *trash;
			smp->data.type = SMP_T_STR;

			return 1;
		}
               case MJSON_TOK_ARRAY: {
                       // We copy the complete array, including square brackets into the return buffer
                       // result looks like: ["manage-account","manage-account-links","view-profile"]
                       trash->data = b_putblk(trash, token, token_size);
                       smp->data.u.str = *trash;
                       smp->data.type = SMP_T_STR;
                       return 1;
               }
		case MJSON_TOK_NULL:
		case MJSON_TOK_OBJECT:
			/* We cannot handle these. */
			return 0;
		case MJSON_TOK_INVALID:
			/* Nothing matches the query. */
			return 0;
		case MJSON_TOK_KEY:
			/* This is not a valid return value according to the
			 * mjson documentation, but we handle it to benefit
			 * from '-Wswitch'.
			 */
			return 0;
	}

	my_unreachable();
	return 0;
}

#ifdef USE_OPENSSL
static int sample_conv_jwt_verify_check(struct arg *args, struct sample_conv *conv,
					const char *file, int line, char **err)
{
	enum jwt_alg alg = JWT_ALG_DEFAULT;

	vars_check_arg(&args[0], NULL);
	vars_check_arg(&args[1], NULL);

	if (args[0].type == ARGT_STR) {
		alg = jwt_parse_alg(args[0].data.str.area, args[0].data.str.data);

		if (alg == JWT_ALG_DEFAULT) {
			memprintf(err, "unknown JWT algorithm: %s", args[0].data.str.area);
			return 0;
		}
	}

	if (args[1].type == ARGT_STR) {
		switch (alg) {
			JWS_ALG_HS256:
			JWS_ALG_HS384:
			JWS_ALG_HS512:
			/* don't try to load a file with HMAC algorithms */
				break;
			default:
				jwt_tree_load_cert(args[1].data.str.area, args[1].data.str.data, err);
				break;
		}
	}

	return 1;
}

/* Check that a JWT's signature is correct */
static int sample_conv_jwt_verify(const struct arg *args, struct sample *smp, void *private)
{
	struct sample alg_smp, key_smp;
	enum jwt_vrfy_status ret;

	smp_set_owner(&alg_smp, smp->px, smp->sess, smp->strm, smp->opt);
	smp_set_owner(&key_smp, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_str(&args[0], &alg_smp))
		return 0;
	if (!sample_conv_var2smp_str(&args[1], &key_smp))
		return 0;

	ret = jwt_verify(&smp->data.u.str,  &alg_smp.data.u.str, &key_smp.data.u.str);

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = ret;
	return 1;
}


/*
 * Returns the decoded header or payload of a JWT if no parameter is given, or
 * the value of the specified field of the corresponding JWT subpart if a
 * parameter is given.
 */
static int sample_conv_jwt_member_query(const struct arg *args, struct sample *smp,
					void *private, enum jwt_elt member)
{
	struct jwt_item items[JWT_ELT_MAX] = { { 0 } };
	unsigned int item_num = member + 1; /* We don't need to tokenize the full token */
	struct buffer *decoded_header = get_trash_chunk();
	int retval = 0;
	int ret;

	jwt_tokenize(&smp->data.u.str, items, &item_num);

	if (item_num < member + 1)
		goto end;

	ret = base64urldec(items[member].start, items[member].length,
	                   decoded_header->area, decoded_header->size);
	if (ret == -1)
		goto end;

	decoded_header->data = ret;
	if (args[0].type != ARGT_STR) {
		smp->data.u.str = *decoded_header;
		smp->data.type = SMP_T_STR;
		goto end;
	}

	/* We look for a specific field of the header or payload part of the JWT */
	smp->data.u.str = *decoded_header;

	retval = sample_conv_json_query(args, smp, private);

end:
	return retval;
}

/* This function checks the "jwt_header_query" and "jwt_payload_query" converters' arguments.
 * It is based on the "json_query" converter's check with the only difference
 * being that the jwt converters can take 0 parameters as well.
 */
static int sample_conv_jwt_query_check(struct arg *arg, struct sample_conv *conv,
				       const char *file, int line, char **err)
{
	if (arg[1].data.str.data != 0) {
		if (strcmp(arg[1].data.str.area, "int") != 0) {
			memprintf(err, "output_type only supports \"int\" as argument");
			return 0;
		} else {
			arg[1].type = ARGT_SINT;
			arg[1].data.sint = 0;
		}
	}
	return 1;
}

/*
 * If no parameter is given, return the decoded header part of a JWT (the first
 * base64 encoded part, corresponding to the JOSE header).
 * If a parameter is given, this converter acts as a "json_query" on this
 * decoded JSON.
 */
static int sample_conv_jwt_header_query(const struct arg *args, struct sample *smp, void *private)
{
	return sample_conv_jwt_member_query(args, smp, private, JWT_ELT_JOSE);
}

/*
 * If no parameter is given, return the decoded payload part of a JWT (the
 * second base64 encoded part, which contains all the claims).  If a parameter
 * is given, this converter acts as a "json_query" on this decoded JSON.
 */
static int sample_conv_jwt_payload_query(const struct arg *args, struct sample *smp, void *private)
{
	return sample_conv_jwt_member_query(args, smp, private, JWT_ELT_CLAIMS);
}

#endif /* USE_OPENSSL */

/************************************************************************/
/*       All supported sample fetch functions must be declared here     */
/************************************************************************/


/* returns the actconn */
static int
smp_fetch_actconn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = actconn;
	return 1;
}


/* force TRUE to be returned at the fetch level */
static int
smp_fetch_true(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp_make_rw(smp))
		return 0;

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = 1;
	return 1;
}

/* force FALSE to be returned at the fetch level */
static int
smp_fetch_false(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = 0;
	return 1;
}

/* retrieve environment variable $1 as a string */
static int
smp_fetch_env(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	char *env;

	if (args[0].type != ARGT_STR)
		return 0;

	env = getenv(args[0].data.str.area);
	if (!env)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.area = env;
	smp->data.u.str.data = strlen(env);
	return 1;
}

/* Validates the data unit argument passed to "date" fetch. Argument 1 support an
 * optional string representing the unit of the result: "s" for seconds, "ms" for
 * milliseconds and "us" for microseconds.
 * Returns 0 on error and non-zero if OK.
 */
int smp_check_date_unit(struct arg *args, char **err)
{
        if (args[1].type == ARGT_STR) {
		long long int unit;

                if (strcmp(args[1].data.str.area, "s") == 0) {
                        unit = TIME_UNIT_S;
                }
                else if (strcmp(args[1].data.str.area, "ms") == 0) {
                        unit = TIME_UNIT_MS;
                }
                else if (strcmp(args[1].data.str.area, "us") == 0) {
                        unit = TIME_UNIT_US;
                }
                else {
                        memprintf(err, "expects 's', 'ms' or 'us', got '%s'",
                                  args[1].data.str.area);
                        return 0;
                }

		chunk_destroy(&args[1].data.str);
                args[1].type = ARGT_SINT;
		args[1].data.sint = unit;
        }
        else if (args[1].type != ARGT_STOP) {
                memprintf(err, "Unexpected arg type");
                return 0;
        }

        return 1;
}

/* retrieve the current local date in epoch time, converts it to milliseconds
 * or microseconds if asked to in optional args[1] unit param, and applies an
 * optional args[0] offset.
 */
static int
smp_fetch_date(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.u.sint = date.tv_sec;

	/* report in milliseconds */
	if (args[1].type == ARGT_SINT && args[1].data.sint == TIME_UNIT_MS) {
		smp->data.u.sint *= 1000;
		smp->data.u.sint += date.tv_usec / 1000;
	}
	/* report in microseconds */
	else if (args[1].type == ARGT_SINT && args[1].data.sint == TIME_UNIT_US) {
		smp->data.u.sint *= 1000000;
		smp->data.u.sint += date.tv_usec;
	}

	/* add offset */
	if (args[0].type == ARGT_SINT)
		smp->data.u.sint += args[0].data.sint;

	smp->data.type = SMP_T_SINT;
	smp->flags |= SMP_F_VOL_TEST | SMP_F_MAY_CHANGE;
	return 1;
}

/* retrieve the current microsecond part of the date  */
static int
smp_fetch_date_us(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.u.sint = date.tv_usec;
	smp->data.type = SMP_T_SINT;
	smp->flags |= SMP_F_VOL_TEST | SMP_F_MAY_CHANGE;
	return 1;
}


/* returns the hostname */
static int
smp_fetch_hostname(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.area = hostname;
	smp->data.u.str.data = strlen(hostname);
	return 1;
}

/* returns the number of processes */
static int
smp_fetch_nbproc(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 1;
	return 1;
}

/* returns the PID of the current process */
static int
smp_fetch_pid(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = pid;
	return 1;
}


/* returns the number of the current process (between 1 and nbproc */
static int
smp_fetch_proc(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = 1;
	return 1;
}

/* returns the number of the current thread (between 1 and nbthread */
static int
smp_fetch_thread(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = tid;
	return 1;
}

/* generate a random 32-bit integer for whatever purpose, with an optional
 * range specified in argument.
 */
static int
smp_fetch_rand(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.u.sint = statistical_prng();

	/* reduce if needed. Don't do a modulo, use all bits! */
	if (args[0].type == ARGT_SINT)
		smp->data.u.sint = ((u64)smp->data.u.sint * (u64)args[0].data.sint) >> 32;

	smp->data.type = SMP_T_SINT;
	smp->flags |= SMP_F_VOL_TEST | SMP_F_MAY_CHANGE;
	return 1;
}

/* returns true if the current process is stopping */
static int
smp_fetch_stopping(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = stopping;
	return 1;
}

/* returns the number of calls of the current stream's process_stream() */
static int
smp_fetch_cpu_calls(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = smp->strm->task->calls;
	return 1;
}

/* returns the average number of nanoseconds spent processing the stream per call */
static int
smp_fetch_cpu_ns_avg(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = smp->strm->task->calls ? smp->strm->cpu_time / smp->strm->task->calls : 0;
	return 1;
}

/* returns the total number of nanoseconds spent processing the stream */
static int
smp_fetch_cpu_ns_tot(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = smp->strm->cpu_time;
	return 1;
}

/* returns the average number of nanoseconds per call spent waiting for other tasks to be processed */
static int
smp_fetch_lat_ns_avg(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = smp->strm->task->calls ? smp->strm->lat_time / smp->strm->task->calls : 0;
	return 1;
}

/* returns the total number of nanoseconds per call spent waiting for other tasks to be processed */
static int
smp_fetch_lat_ns_tot(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = smp->strm->lat_time;
	return 1;
}

static int smp_fetch_const_str(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags |= SMP_F_CONST;
	smp->data.type = SMP_T_STR;
	smp->data.u.str.area = args[0].data.str.area;
	smp->data.u.str.data = args[0].data.str.data;
	return 1;
}

static int smp_check_const_bool(struct arg *args, char **err)
{
	if (strcasecmp(args[0].data.str.area, "true") == 0 ||
	    strcasecmp(args[0].data.str.area, "1") == 0) {
		chunk_destroy(&args[0].data.str);
		args[0].type = ARGT_SINT;
		args[0].data.sint = 1;
		return 1;
	}
	if (strcasecmp(args[0].data.str.area, "false") == 0 ||
	    strcasecmp(args[0].data.str.area, "0") == 0) {
		chunk_destroy(&args[0].data.str);
		args[0].type = ARGT_SINT;
		args[0].data.sint = 0;
		return 1;
	}
	memprintf(err, "Expects 'true', 'false', '0' or '1'");
	return 0;
}

static int smp_fetch_const_bool(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = args[0].data.sint;
	return 1;
}

static int smp_fetch_const_int(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = args[0].data.sint;
	return 1;
}

static int smp_fetch_const_ipv4(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_IPV4;
	smp->data.u.ipv4 = args[0].data.ipv4;
	return 1;
}

static int smp_fetch_const_ipv6(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_IPV6;
	smp->data.u.ipv6 = args[0].data.ipv6;
	return 1;
}

static int smp_check_const_bin(struct arg *args, char **err)
{
	char *binstr = NULL;
	int binstrlen;

	if (!parse_binary(args[0].data.str.area, &binstr, &binstrlen, err))
		return 0;
	chunk_destroy(&args[0].data.str);
	args[0].type = ARGT_STR;
	args[0].data.str.area = binstr;
	args[0].data.str.data = binstrlen;
	return 1;
}

static int smp_fetch_const_bin(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->flags |= SMP_F_CONST;
	smp->data.type = SMP_T_BIN;
	smp->data.u.str.area = args[0].data.str.area;
	smp->data.u.str.data = args[0].data.str.data;
	return 1;
}

static int smp_check_const_meth(struct arg *args, char **err)
{
	enum http_meth_t meth;
	int i;

	meth = find_http_meth(args[0].data.str.area, args[0].data.str.data);
	if (meth != HTTP_METH_OTHER) {
		chunk_destroy(&args[0].data.str);
		args[0].type = ARGT_SINT;
		args[0].data.sint = meth;
	} else {
		/* Check method availability. A method is a token defined as :
		 * tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
		 *         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
		 * token = 1*tchar
		 */
		for (i = 0; i < args[0].data.str.data; i++) {
			if (!HTTP_IS_TOKEN(args[0].data.str.area[i])) {
				memprintf(err, "expects valid method.");
				return 0;
			}
		}
	}
	return 1;
}

static int smp_fetch_const_meth(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_METH;
	if (args[0].type == ARGT_SINT) {
		smp->flags &= ~SMP_F_CONST;
		smp->data.u.meth.meth = args[0].data.sint;
		smp->data.u.meth.str.area = "";
		smp->data.u.meth.str.data = 0;
	} else {
		smp->flags |= SMP_F_CONST;
		smp->data.u.meth.meth = HTTP_METH_OTHER;
		smp->data.u.meth.str.area = args[0].data.str.area;
		smp->data.u.meth.str.data = args[0].data.str.data;
	}
	return 1;
}

// This function checks the "uuid" sample's arguments.
// Function won't get called when no parameter is specified (maybe a bug?)
static int smp_check_uuid(struct arg *args, char **err)
{
	if (!args[0].type) {
		args[0].type = ARGT_SINT;
		args[0].data.sint = 4;
	} else {
		switch (args[0].data.sint) {
		case 4:
		case 7:
			break;
		default:
			memprintf(err, "Unsupported UUID version: '%lld'", args[0].data.sint);
			return 0;
		}
	}

	return 1;
}

// Generate a RFC 9562 UUID (default is v4 = fully random)
static int smp_fetch_uuid(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	long long int type = -1;

	if (!args[0].type) {
		type = 4;
	} else {
		type = args[0].data.sint;
	}

	switch (type) {
	case 4:
		ha_generate_uuid_v4(&trash);
		break;
	case 7:
		ha_generate_uuid_v7(&trash);
		break;
	default:
		return 0;
	}

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_VOL_TEST | SMP_F_MAY_CHANGE;
	smp->data.u.str = trash;
	return 1;
}

/* returns the uptime in seconds */
static int
smp_fetch_uptime(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = ns_to_sec(now_ns - start_time_ns);
	return 1;
}


/* Check if QUIC support was compiled and was not disabled by "no-quic" global option */
static int smp_fetch_quic_enabled(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	smp->data.type = SMP_T_BOOL;
	smp->flags = 0;
#ifdef USE_QUIC
	smp->data.u.sint = !(global.tune.options & GTUNE_NO_QUIC);
#else
	smp->data.u.sint = 0;
#endif
	return smp->data.u.sint;
}

/* Timing events re{q,s}.timer.  */
static int smp_fetch_reX_timers(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct strm_logs *logs;
	int t_request = -1;

	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->flags = 0;

	logs = &smp->strm->logs;


	if ((llong)(logs->request_ts - logs->accept_ts) >= 0)
		t_request = ns_to_ms(logs->request_ts - logs->accept_ts);

	/* req.timer. */
	if (kw[2] == 'q') {

		switch (kw[10]) {

			/* req.timer.idle (%Ti)  */
			case 'i':
				smp->data.u.sint = logs->t_idle;
				break;

			/* req.timer.tq (%Tq) */
			case 't':
				smp->data.u.sint = t_request;
				break;

			/* req.timer.hdr (%TR) */
			case 'h':
				smp->data.u.sint = (t_request >= 0) ? t_request - logs->t_idle - logs->t_handshake : -1;
				break;

			/* req.timer.queue (%Tw) */
			case 'q':
				smp->data.u.sint = (logs->t_queue >= 0) ? logs->t_queue - t_request : -1;
				break;

			default:
				goto error;

		}
	} else {
		/* res.timer. */
		switch (kw[10]) {
			/* res.timer.hdr (%Tr) */
			case 'h':
				smp->data.u.sint = (logs->t_data >= 0) ? logs->t_data - logs->t_connect : -1;
			break;

			/* res.timer.data (%Td) */
			case 'd':
				smp->data.u.sint = (logs->t_data >= 0) ? logs->t_close - logs->t_data : -1;
			break;

			default:
				goto error;

		}

	}

		return 1;
error:

		return 0;
	}


/* Timing events  txn. */
static int smp_fetch_txn_timers(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct strm_logs *logs;

	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->flags = 0;

	logs = &smp->strm->logs;

	/* txn.timer. */
	switch (kw[10]) {

		/* txn.timer.total (%Ta) */
		case 't':
			smp->data.u.sint = logs->t_close - (logs->t_idle >= 0 ? logs->t_idle + logs->t_handshake : 0);
		break;


		/* txn.timer.user (%Tu) */
		case 'u':
			smp->data.u.sint = logs->t_close - (logs->t_idle >= 0 ? logs->t_idle : 0);
		break;

		default:
			goto error;

	}

	return 1;
error:

	return 0;
}

/* Server conn queueing infos - bc_{be,srv}_queue */
static int smp_fetch_conn_queues(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct strm_logs *logs;

	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->flags = 0;

	logs = &smp->strm->logs;

	if (kw[3] == 'b') {
		/* bc_be_queue */
		smp->data.u.sint = logs->prx_queue_pos;
	}
	else {
		/* bc_srv_queue */
		smp->data.u.sint = logs->srv_queue_pos;
	}
	return 1;
}

/* Timing events {f,bc}.timer.  */
static int smp_fetch_conn_timers(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct strm_logs *logs;

	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->flags = 0;

	logs = &smp->strm->logs;

	if (kw[0] == 'b') {
		/* fc.timer. */
		switch (kw[9]) {

			/* bc.timer.connect (%Tc) */
			case 'c':
				smp->data.u.sint = (logs->t_connect >= 0) ? logs->t_connect - logs->t_queue : -1;
				break;

			default:
				goto error;
		}

	} else {

		/* fc.timer. */
		switch (kw[9]) {

			/* fc.timer.handshake (%Th) */
			case 'h':
				smp->data.u.sint = logs->t_handshake;
				break;

			/* fc,timer.total (%Tt) */
			case 't':
				smp->data.u.sint = logs->t_close;
				break;

			default:
				goto error;
		}

	}

	return 1;
error:

	return 0;
}

/* bytes_{in,out} */
static int smp_fetch_bytes(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct strm_logs *logs;

	if (!smp->strm)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->flags = 0;

	logs = &smp->strm->logs;
	if (!logs)
		return 0;

	if (kw[6] == 'i') { /* bytes_in */
		smp->data.u.sint = logs->bytes_in;
	} else { /* bytes_out */
		smp->data.u.sint = logs->bytes_out;
	}

	return 1;
}

static int sample_conv_bytes_check(struct arg *args, struct sample_conv *conv,
                          const char *file, int line, char **err)
{
	// arg0 is not optional, must be >= 0
	if (!check_operator(&args[0], conv, file, line, err)) {
		return 0;
	}
	if (args[0].type != ARGT_VAR) {
		if (args[0].type != ARGT_SINT || args[0].data.sint < 0) {
			memprintf(err, "expects a non-negative integer");
			return 0;
		}
	}
	// arg1 is optional, must be > 0
	if (args[1].type != ARGT_STOP) {
		if (!check_operator(&args[1], conv, file, line, err)) {
			return 0;
		}
		if (args[1].type != ARGT_VAR) {
			if (args[1].type != ARGT_SINT || args[1].data.sint <= 0) {
				memprintf(err, "expects a positive integer");
				return 0;
			}
		}
	}

	return 1;
}

static struct sample_fetch_kw_list smp_logs_kws = {ILH, {
	{ "bytes_in",             smp_fetch_bytes,        0,         NULL, SMP_T_SINT, SMP_USE_INTRN },
	{ "bytes_out",            smp_fetch_bytes,        0,         NULL, SMP_T_SINT, SMP_USE_INTRN },

	{ "txn.timer.total",      smp_fetch_txn_timers,   0,         NULL, SMP_T_SINT, SMP_USE_TXFIN }, /* "Ta" */
	{ "txn.timer.user",       smp_fetch_txn_timers,   0,         NULL, SMP_T_SINT, SMP_USE_TXFIN }, /* "Tu" */

	{ "bc.timer.connect",     smp_fetch_conn_timers,  0,         NULL, SMP_T_SINT, SMP_USE_L4SRV }, /* "Tc" */
	{ "bc_be_queue",          smp_fetch_conn_queues,  0,         NULL, SMP_T_SINT, SMP_USE_L4SRV }, /* "bq" */
	{ "bc_srv_queue",         smp_fetch_conn_queues,  0,         NULL, SMP_T_SINT, SMP_USE_L4SRV }, /* "sq" */

	{ "fc.timer.handshake",   smp_fetch_conn_timers,  0,         NULL, SMP_T_SINT, SMP_USE_L4CLI }, /* "Th" */
	{ "fc.timer.total",       smp_fetch_conn_timers,  0,         NULL, SMP_T_SINT, SMP_USE_SSFIN }, /* "Tt" */

	{ "req.timer.idle",       smp_fetch_reX_timers,   0,         NULL, SMP_T_SINT, SMP_USE_HRQHV }, /* "Ti" */
	{ "req.timer.tq",         smp_fetch_reX_timers,   0,         NULL, SMP_T_SINT, SMP_USE_HRQHV }, /* "Tq" */
	{ "req.timer.hdr",        smp_fetch_reX_timers,   0,         NULL, SMP_T_SINT, SMP_USE_HRQHV }, /* "TR" */
	{ "req.timer.queue",      smp_fetch_reX_timers,   0,         NULL, SMP_T_SINT, SMP_USE_L4SRV }, /* "Tw" */
	{ "res.timer.data",       smp_fetch_reX_timers,   0,         NULL, SMP_T_SINT, SMP_USE_RSFIN }, /* "Td" */
	{ "res.timer.hdr",        smp_fetch_reX_timers,   0,         NULL, SMP_T_SINT, SMP_USE_HRSHV }, /* "Tr" */
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_logs_kws);

/* Note: must not be declared <const> as its list will be overwritten.
 * Note: fetches that may return multiple types should be declared using the
 * appropriate pseudo-type. If not available it must be declared as the lowest
 * common denominator, the type that can be casted into all other ones.
 */
static struct sample_fetch_kw_list smp_kws = {ILH, {
	{ "act_conn",     smp_fetch_actconn, 0,          NULL, SMP_T_SINT, SMP_USE_CONST },
	{ "always_false", smp_fetch_false, 0,            NULL, SMP_T_BOOL, SMP_USE_CONST },
	{ "always_true",  smp_fetch_true,  0,            NULL, SMP_T_BOOL, SMP_USE_CONST },
	{ "env",          smp_fetch_env,   ARG1(1,STR),  NULL, SMP_T_STR,  SMP_USE_CONST },
	{ "date",         smp_fetch_date,  ARG2(0,SINT,STR), smp_check_date_unit, SMP_T_SINT, SMP_USE_CONST },
	{ "date_us",      smp_fetch_date_us,  0,         NULL, SMP_T_SINT, SMP_USE_CONST },
	{ "hostname",     smp_fetch_hostname, 0,         NULL, SMP_T_STR,  SMP_USE_CONST },
	{ "nbproc",       smp_fetch_nbproc,0,            NULL, SMP_T_SINT, SMP_USE_CONST },
	{ "pid",          smp_fetch_pid,   0,            NULL, SMP_T_SINT, SMP_USE_CONST },
	{ "proc",         smp_fetch_proc,  0,            NULL, SMP_T_SINT, SMP_USE_CONST },
	{ "quic_enabled", smp_fetch_quic_enabled, 0,     NULL, SMP_T_BOOL, SMP_USE_CONST },
	{ "thread",       smp_fetch_thread,  0,          NULL, SMP_T_SINT, SMP_USE_CONST },
	{ "rand",         smp_fetch_rand,  ARG1(0,SINT), NULL, SMP_T_SINT, SMP_USE_CONST },
	{ "stopping",     smp_fetch_stopping, 0,         NULL, SMP_T_BOOL, SMP_USE_INTRN },
	{ "uptime",       smp_fetch_uptime,   0,         NULL, SMP_T_SINT, SMP_USE_CONST },
	{ "uuid",         smp_fetch_uuid,  ARG1(0, SINT),      smp_check_uuid, SMP_T_STR, SMP_USE_CONST },

	{ "cpu_calls",    smp_fetch_cpu_calls,  0,       NULL, SMP_T_SINT, SMP_USE_INTRN },
	{ "cpu_ns_avg",   smp_fetch_cpu_ns_avg, 0,       NULL, SMP_T_SINT, SMP_USE_INTRN },
	{ "cpu_ns_tot",   smp_fetch_cpu_ns_tot, 0,       NULL, SMP_T_SINT, SMP_USE_INTRN },
	{ "lat_ns_avg",   smp_fetch_lat_ns_avg, 0,       NULL, SMP_T_SINT, SMP_USE_INTRN },
	{ "lat_ns_tot",   smp_fetch_lat_ns_tot, 0,       NULL, SMP_T_SINT, SMP_USE_INTRN },

	{ "str",  smp_fetch_const_str,  ARG1(1,STR),  NULL                , SMP_T_STR,  SMP_USE_CONST },
	{ "bool", smp_fetch_const_bool, ARG1(1,STR),  smp_check_const_bool, SMP_T_BOOL, SMP_USE_CONST },
	{ "int",  smp_fetch_const_int,  ARG1(1,SINT), NULL                , SMP_T_SINT, SMP_USE_CONST },
	{ "ipv4", smp_fetch_const_ipv4, ARG1(1,IPV4), NULL                , SMP_T_IPV4, SMP_USE_CONST },
	{ "ipv6", smp_fetch_const_ipv6, ARG1(1,IPV6), NULL                , SMP_T_IPV6, SMP_USE_CONST },
	{ "bin",  smp_fetch_const_bin,  ARG1(1,STR),  smp_check_const_bin , SMP_T_BIN,  SMP_USE_CONST },
	{ "meth", smp_fetch_const_meth, ARG1(1,STR),  smp_check_const_meth, SMP_T_METH, SMP_USE_CONST },

	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &smp_kws);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "add_item",sample_conv_add_item,     ARG3(2,STR,STR,STR),   smp_check_add_item,       SMP_T_STR,  SMP_T_STR  },
	{ "debug",   sample_conv_debug,        ARG2(0,STR,STR),       smp_check_debug,          SMP_T_ANY,  SMP_T_SAME },
	{ "b64dec",  sample_conv_base642bin,   0,                     NULL,                     SMP_T_STR,  SMP_T_BIN  },
	{ "base64",  sample_conv_bin2base64,   0,                     NULL,                     SMP_T_BIN,  SMP_T_STR  },
	{ "concat",  sample_conv_concat,       ARG3(1,STR,STR,STR),   smp_check_concat,         SMP_T_STR,  SMP_T_STR  },
	{ "ub64enc", sample_conv_bin2base64url,0,                     NULL,                     SMP_T_BIN,  SMP_T_STR  },
	{ "ub64dec", sample_conv_base64url2bin,0,                     NULL,                     SMP_T_STR,  SMP_T_BIN  },
	{ "upper",   sample_conv_str2upper,    0,                     NULL,                     SMP_T_STR,  SMP_T_STR  },
	{ "lower",   sample_conv_str2lower,    0,                     NULL,                     SMP_T_STR,  SMP_T_STR  },
	{ "length",  sample_conv_length,       0,                     NULL,                     SMP_T_STR,  SMP_T_SINT },
	{ "be2dec",  sample_conv_be2dec,       ARG3(1,STR,SINT,SINT), sample_conv_be2dec_check, SMP_T_BIN,  SMP_T_STR  },
	{ "be2hex",  sample_conv_be2hex,       ARG3(1,STR,SINT,SINT), sample_conv_be2hex_check, SMP_T_BIN,  SMP_T_STR  },
	{ "hex",     sample_conv_bin2hex,      0,                     NULL,                     SMP_T_BIN,  SMP_T_STR  },
	{ "hex2i",   sample_conv_hex2int,      0,                     NULL,                     SMP_T_STR,  SMP_T_SINT },
	{ "ipmask",  sample_conv_ipmask,       ARG2(1,MSK4,MSK6),     NULL,                     SMP_T_ADDR, SMP_T_ADDR },
	{ "ltime",   sample_conv_ltime,        ARG2(1,STR,SINT),      NULL,                     SMP_T_SINT, SMP_T_STR  },
	{ "ms_ltime",   sample_conv_ms_ltime,        ARG2(1,STR,SINT),      NULL,                     SMP_T_SINT, SMP_T_STR  },
	{ "us_ltime",   sample_conv_us_ltime,        ARG2(1,STR,SINT),      NULL,                     SMP_T_SINT, SMP_T_STR  },
	{ "utime",   sample_conv_utime,        ARG2(1,STR,SINT),      NULL,                     SMP_T_SINT, SMP_T_STR  },
	{ "ms_utime",   sample_conv_ms_utime,        ARG2(1,STR,SINT),      NULL,                     SMP_T_SINT, SMP_T_STR  },
	{ "us_utime",   sample_conv_us_utime,        ARG2(1,STR,SINT),      NULL,                     SMP_T_SINT, SMP_T_STR  },
	{ "crc32",   sample_conv_crc32,        ARG1(0,SINT),          NULL,                     SMP_T_BIN,  SMP_T_SINT },
	{ "crc32c",  sample_conv_crc32c,       ARG1(0,SINT),          NULL,                     SMP_T_BIN,  SMP_T_SINT },
	{ "djb2",    sample_conv_djb2,         ARG1(0,SINT),          NULL,                     SMP_T_BIN,  SMP_T_SINT },
	{ "sdbm",    sample_conv_sdbm,         ARG1(0,SINT),          NULL,                     SMP_T_BIN,  SMP_T_SINT },
	{ "wt6",     sample_conv_wt6,          ARG1(0,SINT),          NULL,                     SMP_T_BIN,  SMP_T_SINT },
	{ "xxh3",    sample_conv_xxh3,         ARG1(0,SINT),          NULL,                     SMP_T_BIN,  SMP_T_SINT },
	{ "xxh32",   sample_conv_xxh32,        ARG1(0,SINT),          NULL,                     SMP_T_BIN,  SMP_T_SINT },
	{ "xxh64",   sample_conv_xxh64,        ARG1(0,SINT),          NULL,                     SMP_T_BIN,  SMP_T_SINT },
	{ "json",    sample_conv_json,         ARG1(1,STR),           sample_conv_json_check,   SMP_T_STR,  SMP_T_STR  },
	{ "bytes",   sample_conv_bytes,        ARG2(1,STR,STR),       sample_conv_bytes_check,  SMP_T_BIN,  SMP_T_BIN  },
	{ "field",   sample_conv_field,        ARG3(2,SINT,STR,SINT), sample_conv_field_check,  SMP_T_STR,  SMP_T_STR  },
	{ "word",    sample_conv_word,         ARG3(2,SINT,STR,SINT), sample_conv_field_check,  SMP_T_STR,  SMP_T_STR  },
	{ "param",   sample_conv_param,        ARG2(1,STR,STR),       sample_conv_param_check,  SMP_T_STR,  SMP_T_STR  },
	{ "regsub",  sample_conv_regsub,       ARG3(2,REG,STR,STR),   sample_conv_regsub_check, SMP_T_STR,  SMP_T_STR  },
	{ "sha1",    sample_conv_sha1,         0,                     NULL,                     SMP_T_BIN,  SMP_T_BIN  },
	{ "strcmp",  sample_conv_strcmp,       ARG1(1,STR),           smp_check_strcmp,         SMP_T_STR,  SMP_T_SINT },
	{ "host_only", sample_conv_host_only,  0,                     NULL,                     SMP_T_STR,  SMP_T_STR  },
	{ "port_only", sample_conv_port_only,  0,                     NULL,                     SMP_T_STR,  SMP_T_SINT },

	/* gRPC converters. */
	{ "ungrpc", sample_conv_ungrpc,    ARG2(1,PBUF_FNUM,STR), sample_conv_protobuf_check, SMP_T_BIN, SMP_T_BIN  },
	{ "protobuf", sample_conv_protobuf, ARG2(1,PBUF_FNUM,STR), sample_conv_protobuf_check, SMP_T_BIN, SMP_T_BIN  },

	/* FIX converters */
	{ "fix_is_valid",  sample_conv_fix_is_valid,  0,           NULL,                        SMP_T_BIN, SMP_T_BOOL  },
	{ "fix_tag_value", sample_conv_fix_tag_value, ARG1(1,STR), sample_conv_fix_value_check, SMP_T_BIN, SMP_T_BIN  },

	/* MQTT converters */
	{ "mqtt_is_valid",    sample_conv_mqtt_is_valid,     0,               NULL,                               SMP_T_BIN, SMP_T_BOOL },
	{ "mqtt_field_value", sample_conv_mqtt_field_value,  ARG2(2,STR,STR), sample_conv_mqtt_field_value_check, SMP_T_BIN, SMP_T_STR },

	{ "iif", sample_conv_iif, ARG2(2, STR, STR), NULL, SMP_T_BOOL, SMP_T_STR },

	{ "and",    sample_conv_binary_and, ARG1(1,STR), check_operator, SMP_T_SINT, SMP_T_SINT  },
	{ "or",     sample_conv_binary_or,  ARG1(1,STR), check_operator, SMP_T_SINT, SMP_T_SINT  },
	{ "xor",    sample_conv_binary_xor, ARG1(1,STR), check_operator, SMP_T_SINT, SMP_T_SINT  },
	{ "cpl",    sample_conv_binary_cpl,           0, NULL, SMP_T_SINT, SMP_T_SINT  },
	{ "bool",   sample_conv_arith_bool,           0, NULL, SMP_T_SINT, SMP_T_BOOL },
	{ "not",    sample_conv_arith_not,            0, NULL, SMP_T_SINT, SMP_T_BOOL },
	{ "odd",    sample_conv_arith_odd,            0, NULL, SMP_T_SINT, SMP_T_BOOL },
	{ "even",   sample_conv_arith_even,           0, NULL, SMP_T_SINT, SMP_T_BOOL },
	{ "add",    sample_conv_arith_add,  ARG1(1,STR), check_operator, SMP_T_SINT, SMP_T_SINT  },
	{ "sub",    sample_conv_arith_sub,  ARG1(1,STR), check_operator, SMP_T_SINT, SMP_T_SINT  },
	{ "mul",    sample_conv_arith_mul,  ARG1(1,STR), check_operator, SMP_T_SINT, SMP_T_SINT  },
	{ "div",    sample_conv_arith_div,  ARG1(1,STR), check_operator, SMP_T_SINT, SMP_T_SINT  },
	{ "mod",    sample_conv_arith_mod,  ARG1(1,STR), check_operator, SMP_T_SINT, SMP_T_SINT  },
	{ "neg",    sample_conv_arith_neg,            0, NULL, SMP_T_SINT, SMP_T_SINT  },

	{ "htonl",    sample_conv_htonl,              0, NULL, SMP_T_SINT, SMP_T_BIN  },
	{ "cut_crlf", sample_conv_cut_crlf,           0, NULL, SMP_T_STR,  SMP_T_STR  },
	{ "ltrim",    sample_conv_ltrim,    ARG1(1,STR), NULL, SMP_T_STR,  SMP_T_STR  },
	{ "rtrim",    sample_conv_rtrim,    ARG1(1,STR), NULL, SMP_T_STR,  SMP_T_STR  },
	{ "json_query", sample_conv_json_query, ARG2(1,STR,STR),  sample_check_json_query , SMP_T_STR, SMP_T_ANY },

#ifdef USE_OPENSSL
	/* JSON Web Token converters */
	{ "jwt_header_query",  sample_conv_jwt_header_query,  ARG2(0,STR,STR), sample_conv_jwt_query_check,   SMP_T_BIN, SMP_T_ANY },
	{ "jwt_payload_query", sample_conv_jwt_payload_query, ARG2(0,STR,STR), sample_conv_jwt_query_check,   SMP_T_BIN, SMP_T_ANY },
	{ "jwt_verify",        sample_conv_jwt_verify,        ARG2(2,STR,STR), sample_conv_jwt_verify_check,  SMP_T_BIN, SMP_T_SINT },
#endif
	{ "when",              sample_conv_when,              ARG3(1,STR,STR,STR), check_when_cond,               SMP_T_ANY, SMP_T_ANY  },
	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);
