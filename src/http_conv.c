/*
 * HTTP sample conversion
 *
 * Copyright 2000-2018 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/types.h>

#include <ctype.h>
#include <string.h>
#include <time.h>

#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/http.h>
#include <common/initcall.h>
#include <common/memory.h>
#include <common/standard.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/global.h>

#include <proto/arg.h>
#include <proto/sample.h>
#include <proto/stream.h>

static int smp_check_http_date_unit(struct arg *args, struct sample_conv *conv,
                                    const char *file, int line, char **err)
{
    return smp_check_date_unit(args, err);
}

/* takes an UINT value on input supposed to represent the time since EPOCH,
 * adds an optional offset found in args[0] and emits a string representing
 * the date in RFC-1123/5322 format. If optional unit param in args[1] is
 * provided, decode timestamp in milliseconds ("ms") or microseconds("us"),
 * and use relevant output date format.
 */
static int sample_conv_http_date(const struct arg *args, struct sample *smp, void *private)
{
	const char day[7][4] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	struct buffer *temp;
	struct tm *tm;
	int sec_frac = 0;
	time_t curr_date;

	/* add offset */
	if (args && (args[0].type == ARGT_SINT))
		smp->data.u.sint += args[0].data.sint;

        /* report in milliseconds */
        if (args && args[1].type == ARGT_SINT && args[1].data.sint == TIME_UNIT_MS) {
		sec_frac = smp->data.u.sint % 1000;
                smp->data.u.sint /= 1000;
        }
        /* report in microseconds */
        else if (args && args[1].type == ARGT_SINT && args[1].data.sint == TIME_UNIT_US) {
		sec_frac = smp->data.u.sint % 1000000;
                smp->data.u.sint /= 1000000;
        }

	/* With high numbers, the date returned can be negative, the 55 bits mask prevent this. */
	curr_date = smp->data.u.sint & 0x007fffffffffffffLL;

	tm = gmtime(&curr_date);
	if (!tm)
		return 0;

	temp = get_trash_chunk();
	if (args && args[1].type == ARGT_SINT && args[1].data.sint != TIME_UNIT_S) {
	    temp->data = snprintf(temp->area, temp->size - temp->data,
	                          "%s, %02d %s %04d %02d:%02d:%02d.%d GMT",
			          day[tm->tm_wday], tm->tm_mday, mon[tm->tm_mon],
			          1900+tm->tm_year,
			          tm->tm_hour, tm->tm_min, tm->tm_sec, sec_frac);
	} else {
	    temp->data = snprintf(temp->area, temp->size - temp->data,
	                          "%s, %02d %s %04d %02d:%02d:%02d GMT",
			          day[tm->tm_wday], tm->tm_mday, mon[tm->tm_mon],
			          1900+tm->tm_year,
			          tm->tm_hour, tm->tm_min, tm->tm_sec);
        }

	smp->data.u.str = *temp;
	smp->data.type = SMP_T_STR;
	return 1;
}

/* Arguments: The list of expected value, the number of parts returned and the separator */
static int sample_conv_q_preferred(const struct arg *args, struct sample *smp, void *private)
{
	const char *al = smp->data.u.str.area;
	const char *end = al + smp->data.u.str.data;
	const char *token;
	int toklen;
	int qvalue;
	const char *str;
	const char *w;
	int best_q = 0;

	/* Set the constant to the sample, because the output of the
	 * function will be peek in the constant configuration string.
	 */
	smp->flags |= SMP_F_CONST;
	smp->data.u.str.size = 0;
	smp->data.u.str.area = "";
	smp->data.u.str.data = 0;

	/* Parse the accept language */
	while (1) {

		/* Jump spaces, quit if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			break;

		/* Start of the fisrt word. */
		token = al;

		/* Look for separator: isspace(), ',' or ';'. Next value if 0 length word. */
		while (al < end && *al != ';' && *al != ',' && !isspace((unsigned char)*al))
			al++;
		if (al == token)
			goto expect_comma;

		/* Length of the token. */
		toklen = al - token;
		qvalue = 1000;

		/* Check if the token exists in the list. If the token not exists,
		 * jump to the next token.
		 */
		str = args[0].data.str.area;
		w = str;
		while (1) {
			if (*str == ';' || *str == '\0') {
				if (http_language_range_match(token, toklen, w, str - w))
					goto look_for_q;
				if (*str == '\0')
					goto expect_comma;
				w = str + 1;
			}
			str++;
		}
		goto expect_comma;

look_for_q:

		/* Jump spaces, quit if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			goto process_value;

		/* If ',' is found, process the result */
		if (*al == ',')
			goto process_value;

		/* If the character is different from ';', look
		 * for the end of the header part in best effort.
		 */
		if (*al != ';')
			goto expect_comma;

		/* Assumes that the char is ';', now expect "q=". */
		al++;

		/* Jump spaces, process value if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			goto process_value;

		/* Expect 'q'. If no 'q', continue in best effort */
		if (*al != 'q')
			goto process_value;
		al++;

		/* Jump spaces, process value if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			goto process_value;

		/* Expect '='. If no '=', continue in best effort */
		if (*al != '=')
			goto process_value;
		al++;

		/* Jump spaces, process value if the end is detected. */
		while (al < end && isspace((unsigned char)*al))
			al++;
		if (al >= end)
			goto process_value;

		/* Parse the q value. */
		qvalue = http_parse_qvalue(al, &al);

process_value:

		/* If the new q value is the best q value, then store the associated
		 * language in the response. If qvalue is the biggest value (1000),
		 * break the process.
		 */
		if (qvalue > best_q) {
			smp->data.u.str.area = (char *)w;
			smp->data.u.str.data = str - w;
			if (qvalue >= 1000)
				break;
			best_q = qvalue;
		}

expect_comma:

		/* Expect comma or end. If the end is detected, quit the loop. */
		while (al < end && *al != ',')
			al++;
		if (al >= end)
			break;

		/* Comma is found, jump it and restart the analyzer. */
		al++;
	}

	/* Set default value if required. */
	if (smp->data.u.str.data == 0 && args[1].type == ARGT_STR) {
		smp->data.u.str.area = args[1].data.str.area;
		smp->data.u.str.data = args[1].data.str.data;
	}

	/* Return true only if a matching language was found. */
	return smp->data.u.str.data != 0;
}

/* This fetch url-decode any input string. */
static int sample_conv_url_dec(const struct arg *args, struct sample *smp, void *private)
{
	int len;

	/* If the constant flag is set or if not size is available at
	 * the end of the buffer, copy the string in other buffer
	  * before decoding.
	 */
	if (smp->flags & SMP_F_CONST || smp->data.u.str.size <= smp->data.u.str.data) {
		struct buffer *str = get_trash_chunk();
		memcpy(str->area, smp->data.u.str.area, smp->data.u.str.data);
		smp->data.u.str.area = str->area;
		smp->data.u.str.size = str->size;
		smp->flags &= ~SMP_F_CONST;
	}

	/* Add final \0 required by url_decode(), and convert the input string. */
	smp->data.u.str.area[smp->data.u.str.data] = '\0';
	len = url_decode(smp->data.u.str.area);
	if (len < 0)
		return 0;
	smp->data.u.str.data = len;
	return 1;
}

static int smp_conv_req_capture(const struct arg *args, struct sample *smp, void *private)
{
	struct proxy *fe = strm_fe(smp->strm);
	int idx, i;
	struct cap_hdr *hdr;
	int len;

	if (!args || args->type != ARGT_SINT)
		return 0;

	idx = args->data.sint;

	/* Check the availibity of the capture id. */
	if (idx > fe->nb_req_cap - 1)
		return 0;

	/* Look for the original configuration. */
	for (hdr = fe->req_cap, i = fe->nb_req_cap - 1;
	     hdr != NULL && i != idx ;
	     i--, hdr = hdr->next);
	if (!hdr)
		return 0;

	/* check for the memory allocation */
	if (smp->strm->req_cap[hdr->index] == NULL)
		smp->strm->req_cap[hdr->index] = pool_alloc(hdr->pool);
	if (smp->strm->req_cap[hdr->index] == NULL)
		return 0;

	/* Check length. */
	len = smp->data.u.str.data;
	if (len > hdr->len)
		len = hdr->len;

	/* Capture input data. */
	memcpy(smp->strm->req_cap[idx], smp->data.u.str.area, len);
	smp->strm->req_cap[idx][len] = '\0';

	return 1;
}

static int smp_conv_res_capture(const struct arg *args, struct sample *smp, void *private)
{
	struct proxy *fe = strm_fe(smp->strm);
	int idx, i;
	struct cap_hdr *hdr;
	int len;

	if (!args || args->type != ARGT_SINT)
		return 0;

	idx = args->data.sint;

	/* Check the availibity of the capture id. */
	if (idx > fe->nb_rsp_cap - 1)
		return 0;

	/* Look for the original configuration. */
	for (hdr = fe->rsp_cap, i = fe->nb_rsp_cap - 1;
	     hdr != NULL && i != idx ;
	     i--, hdr = hdr->next);
	if (!hdr)
		return 0;

	/* check for the memory allocation */
	if (smp->strm->res_cap[hdr->index] == NULL)
		smp->strm->res_cap[hdr->index] = pool_alloc(hdr->pool);
	if (smp->strm->res_cap[hdr->index] == NULL)
		return 0;

	/* Check length. */
	len = smp->data.u.str.data;
	if (len > hdr->len)
		len = hdr->len;

	/* Capture input data. */
	memcpy(smp->strm->res_cap[idx], smp->data.u.str.area, len);
	smp->strm->res_cap[idx][len] = '\0';

	return 1;
}

/************************************************************************/
/*        All supported converter keywords must be declared here.       */
/************************************************************************/

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "http_date",      sample_conv_http_date,    ARG2(0,SINT,STR),     smp_check_http_date_unit,   SMP_T_SINT, SMP_T_STR},
	{ "language",       sample_conv_q_preferred,  ARG2(1,STR,STR),  NULL,   SMP_T_STR,  SMP_T_STR},
	{ "capture-req",    smp_conv_req_capture,     ARG1(1,SINT),     NULL,   SMP_T_STR,  SMP_T_STR},
	{ "capture-res",    smp_conv_res_capture,     ARG1(1,SINT),     NULL,   SMP_T_STR,  SMP_T_STR},
	{ "url_dec",        sample_conv_url_dec,      0,                NULL,   SMP_T_STR,  SMP_T_STR},
	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
