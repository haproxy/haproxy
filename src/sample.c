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

#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/log.h>
#include <proto/proxy.h>
#include <proto/sample.h>
#include <proto/stick_table.h>

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
	return 1;
}

static int c_ip2str(struct sample *smp)
{
	struct chunk *trash = get_trash_chunk();

	if (!inet_ntop(AF_INET, (void *)&smp->data.ipv4, trash->str, trash->size))
		return 0;

	trash->len = strlen(trash->str);
	smp->data.str = *trash;

	return 1;
}

static int c_ip2ipv6(struct sample *smp)
{
	v4tov6(&smp->data.ipv6, &smp->data.ipv4);
	return 1;
}

static int c_ipv62str(struct sample *smp)
{
	struct chunk *trash = get_trash_chunk();

	if (!inet_ntop(AF_INET6, (void *)&smp->data.ipv6, trash->str, trash->size))
		return 0;

	trash->len = strlen(trash->str);
	smp->data.str = *trash;
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
	return 1;
}

static int c_str2ip(struct sample *smp)
{
	if (!buf2ip(smp->data.str.str, smp->data.str.len, &smp->data.ipv4))
		return 0;
	return 1;
}

static int c_str2ipv6(struct sample *smp)
{
	return inet_pton(AF_INET6, smp->data.str.str, &smp->data.ipv6);
}

static int c_bin2str(struct sample *smp)
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
	return 1;
}

static int c_datadup(struct sample *smp)
{
	struct chunk *trash = get_trash_chunk();

	trash->len = smp->data.str.len < trash->size ? smp->data.str.len : trash->size;
	memcpy(trash->str, smp->data.str.str, trash->len);
	smp->data.str = *trash;
	return 1;
}


static int c_none(struct sample *smp)
{
	return 1;
}

static int c_str2int(struct sample *smp)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < smp->data.str.len; i++) {
		uint32_t val = smp->data.str.str[i] - '0';

		if (val > 9)
			break;

		ret = ret * 10 + val;
	}

	smp->data.uint = ret;
	return 1;
}

/*****************************************************************/
/*      Sample casts matrix:                                     */
/*           sample_casts[from type][to type]                    */
/*           NULL pointer used for impossible sample casts       */
/*****************************************************************/

typedef int (*sample_cast_fct)(struct sample *smp);
static sample_cast_fct sample_casts[SMP_TYPES][SMP_TYPES] = {
/*            to:  BOOL       UINT       SINT       IPV4      IPV6        STR         BIN        CSTR        CBIN   */
/* from: BOOL */ { c_none,    c_none,    c_none,    NULL,     NULL,       c_int2str,  NULL,      c_int2str,  NULL   },
/*       UINT */ { c_none,    c_none,    c_none,    c_int2ip, NULL,       c_int2str,  NULL,      c_int2str,  NULL   },
/*       SINT */ { c_none,    c_none,    c_none,    c_int2ip, NULL,       c_int2str,  NULL,      c_int2str,  NULL   },
/*       IPV4 */ { NULL,      c_ip2int,  c_ip2int,  c_none,   c_ip2ipv6,  c_ip2str,   NULL,      c_ip2str,   NULL   },
/*       IPV6 */ { NULL,      NULL,      NULL,      NULL,     c_none,     c_ipv62str, NULL,      c_ipv62str, NULL   },
/*        STR */ { c_str2int, c_str2int, c_str2int, c_str2ip, c_str2ipv6, c_none,     c_none,    c_none,     c_none },
/*        BIN */ { NULL,      NULL,      NULL,      NULL,     NULL,       c_bin2str,  c_none,    c_bin2str,  c_none },
/*       CSTR */ { c_str2int, c_str2int, c_str2int, c_str2ip, c_str2ipv6, c_datadup,  c_datadup, c_none,     c_none },
/*       CBIN */ { NULL,      NULL,      NULL,      NULL,     NULL,       c_bin2str,  c_datadup, c_bin2str,  c_none },
};

/*
 * Parse a sample expression configuration:
 *        fetch keyword followed by format conversion keywords.
 * Returns a pointer on allocated sample expression structure.
 * The caller must have set al->ctx.
 */
struct sample_expr *sample_parse_expr(char **str, int *idx, char *err, int err_size, struct arg_list *al)
{
	const char *endw;
	const char *end;
	struct sample_expr *expr;
	struct sample_fetch *fetch;
	struct sample_conv *conv;
	unsigned long prev_type;
	char *p;

	snprintf(err, err_size, "memory error.");
	if (!str[*idx]) {

		snprintf(err, err_size, "missing fetch method.");
		goto out_error;
	}

	end = str[*idx] + strlen(str[*idx]);
	endw = strchr(str[*idx], '(');

	if (!endw)
		endw = end;
	else if ((end-1)[0] != ')') {
		p = my_strndup(str[*idx], endw - str[*idx]);
		if (p) {
			snprintf(err, err_size, "syntax error: missing ')' after keyword '%s'.", p);
			free(p);
		}
		goto out_error;
	}

	fetch = find_sample_fetch(str[*idx], endw - str[*idx]);
	if (!fetch) {
		p = my_strndup(str[*idx], endw - str[*idx]);
		if (p) {
			snprintf(err, err_size, "unknown fetch method '%s'.", p);
			free(p);
		}
		goto out_error;
	}
	if (fetch->out_type >= SMP_TYPES) {

		p = my_strndup(str[*idx], endw - str[*idx]);
		if (p) {
			snprintf(err, err_size, "returns type of fetch method '%s' is unknown.", p);
			free(p);
		}
		goto out_error;
	}

	prev_type = fetch->out_type;
	expr = calloc(1, sizeof(struct sample_expr));
	if (!expr)
		goto out_error;

	LIST_INIT(&(expr->conv_exprs));
	expr->fetch = fetch;
	expr->arg_p = empty_arg_list;

	if (end != endw) {
		char *err_msg = NULL;
		int err_arg;

		if (!fetch->arg_mask) {
			p = my_strndup(str[*idx], endw - str[*idx]);
			if (p) {
				snprintf(err, err_size, "fetch method '%s' does not support any args.", p);
				free(p);
			}
			goto out_error;
		}

		al->kw = expr->fetch->kw;
		al->conv = NULL;
		if (make_arg_list(endw + 1, end - endw - 2, fetch->arg_mask, &expr->arg_p, &err_msg, NULL, &err_arg, al) < 0) {
			p = my_strndup(str[*idx], endw - str[*idx]);
			if (p) {
				snprintf(err, err_size, "invalid arg %d in fetch method '%s' : %s.", err_arg+1, p, err_msg);
				free(p);
			}
			free(err_msg);
			goto out_error;
		}

		if (!expr->arg_p)
			expr->arg_p = empty_arg_list;

		if (fetch->val_args && !fetch->val_args(expr->arg_p, &err_msg)) {
			p = my_strndup(str[*idx], endw - str[*idx]);
			if (p) {
				snprintf(err, err_size, "invalid args in fetch method '%s' : %s.", p, err_msg);
				free(p);
			}
			free(err_msg);
			goto out_error;
		}
	}
	else if (ARGM(fetch->arg_mask)) {
		p = my_strndup(str[*idx], endw - str[*idx]);
		if (p) {
			snprintf(err, err_size, "missing args for fetch method '%s'.", p);
			free(p);
		}
		goto out_error;
	}

	for (*idx += 1; *(str[*idx]); (*idx)++) {
		struct sample_conv_expr *conv_expr;

		end = str[*idx] + strlen(str[*idx]);
		endw = strchr(str[*idx], '(');

		if (!endw)
			endw = end;
		else if ((end-1)[0] != ')') {
			p = my_strndup(str[*idx], endw - str[*idx]);
			if (p) {
				snprintf(err, err_size, "syntax error, missing ')' after keyword '%s'.", p);
				free(p);
			}
			goto out_error;
		}

		conv = find_sample_conv(str[*idx], endw - str[*idx]);
		if (!conv)
			break;

		if (conv->in_type >= SMP_TYPES ||
		    conv->out_type >= SMP_TYPES) {
			p = my_strndup(str[*idx], endw - str[*idx]);
			if (p) {
				snprintf(err, err_size, "returns type of conv method '%s' is unknown.", p);
				free(p);
			}
			goto out_error;
		}

		/* If impossible type conversion */
		if (!sample_casts[prev_type][conv->in_type]) {
			p = my_strndup(str[*idx], endw - str[*idx]);
			if (p) {
				snprintf(err, err_size, "conv method '%s' cannot be applied.", p);
				free(p);
			}
			goto out_error;
		}

		prev_type = conv->out_type;
		conv_expr = calloc(1, sizeof(struct sample_conv_expr));
		if (!conv_expr)
			goto out_error;

		LIST_ADDQ(&(expr->conv_exprs), &(conv_expr->list));
		conv_expr->conv = conv;

		if (end != endw) {
			char *err_msg = NULL;
			int err_arg;

			if (!conv->arg_mask) {
				p = my_strndup(str[*idx], endw - str[*idx]);

				if (p) {
					snprintf(err, err_size, "conv method '%s' does not support any args.", p);
					free(p);
				}
				goto out_error;
			}

			al->kw = expr->fetch->kw;
			al->conv = conv_expr->conv->kw;
			if (make_arg_list(endw + 1, end - endw - 2, conv->arg_mask, &conv_expr->arg_p, &err_msg, NULL, &err_arg, al) < 0) {
				p = my_strndup(str[*idx], endw - str[*idx]);
				if (p) {
					snprintf(err, err_size, "invalid arg %d in conv method '%s' : %s.", err_arg+1, p, err_msg);
					free(p);
				}
				free(err_msg);
				goto out_error;
			}

			if (!conv_expr->arg_p)
				conv_expr->arg_p = empty_arg_list;

			if (conv->val_args && !conv->val_args(conv_expr->arg_p, &err_msg)) {
				p = my_strndup(str[*idx], endw - str[*idx]);
				if (p) {
					snprintf(err, err_size, "invalid args in conv method '%s' : %s.", p, err_msg);
					free(p);
				}
				free(err_msg);
				goto out_error;
			}
		}
		else if (conv->arg_mask) {
			p = my_strndup(str[*idx], endw - str[*idx]);
			if (p) {
				snprintf(err, err_size, "missing args for conv method '%s'.", p);
				free(p);
			}
			goto out_error;
		}

	}

	return expr;

out_error:
	/* TODO: prune_sample_expr(expr); */
	return NULL;
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

	if (p == NULL)
		p = &temp_smp;

	p->flags = 0;
	if (!expr->fetch->process(px, l4, l7, opt, expr->arg_p, p))
		return NULL;

	if (p->flags & SMP_F_MAY_CHANGE)
		return NULL; /* we can only use stable samples */

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

		/* force the output type after a cast */
		p->type = conv_expr->conv->in_type;
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
		case ARGC_HDR: where = "in HTTP header format string in"; break;
		case ARGC_UIF: where = "in unique-id-format string in"; break;
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
 * Process a fetch + format conversion as defined by the sample expression <expr>
 * on request or response considering the <opt> parameter. The output is always of
 * type string. Returns either NULL if no sample could be extracted, or a pointer
 * to the converted result stored in static temp_smp in format string.
 */
struct sample *sample_fetch_string(struct proxy *px, struct session *l4, void *l7,
                                   unsigned int opt, struct sample_expr *expr)
{
	struct sample *smp;

	smp = sample_process(px, l4, l7, opt, expr, NULL);
	if (!smp)
		return NULL;

	if (!sample_casts[smp->type][SMP_T_CSTR])
		return NULL;

	if (!sample_casts[smp->type][SMP_T_CSTR](smp))
		return NULL;

	smp->type = SMP_T_CSTR;
	return smp;
}

/*****************************************************************/
/*    Sample format convert functions                            */
/*    These functions set the data type on return.               */
/*****************************************************************/

static int sample_conv_str2lower(const struct arg *arg_p, struct sample *smp)
{
	int i;

	if (!smp->data.str.size)
		return 0;

	for (i = 0; i < smp->data.str.len; i++) {
		if ((smp->data.str.str[i] >= 'A') && (smp->data.str.str[i] <= 'Z'))
			smp->data.str.str[i] += 'a' - 'A';
	}
	smp->type = SMP_T_STR;
	return 1;
}

static int sample_conv_str2upper(const struct arg *arg_p, struct sample *smp)
{
	int i;

	if (!smp->data.str.size)
		return 0;

	for (i = 0; i < smp->data.str.len; i++) {
		if ((smp->data.str.str[i] >= 'a') && (smp->data.str.str[i] <= 'z'))
			smp->data.str.str[i] += 'A' - 'a';
	}
	smp->type = SMP_T_STR;
	return 1;
}

/* takes the netmask in arg_p */
static int sample_conv_ipmask(const struct arg *arg_p, struct sample *smp)
{
	smp->data.ipv4.s_addr &= arg_p->data.ipv4.s_addr;
	smp->type = SMP_T_IPV4;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {{ },{
	{ "upper",  sample_conv_str2upper, 0,            NULL, SMP_T_STR,  SMP_T_STR  },
	{ "lower",  sample_conv_str2lower, 0,            NULL, SMP_T_STR,  SMP_T_STR  },
	{ "ipmask", sample_conv_ipmask,    ARG1(1,MSK4), NULL, SMP_T_IPV4, SMP_T_IPV4 },
	{ NULL, NULL, 0, 0, 0 },
}};

__attribute__((constructor))
static void __sample_init(void)
{
	/* register sample format convert keywords */
	sample_register_convs(&sample_conv_kws);
}
