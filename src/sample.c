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

#include <common/chunk.h>
#include <common/standard.h>

#include <proto/arg.h>
#include <proto/sample.h>

/* static sample used in sample_process() when <p> is NULL */
static struct sample temp_smp;

/* trash chunk used for sample conversions */
static struct chunk trash_chunk;

/* trash buffers used or sample conversions */
static char sample_trash_buf1[BUFSIZE];
static char sample_trash_buf2[BUFSIZE];

/* sample_trash_buf point on used buffer*/
static char *sample_trash_buf = sample_trash_buf1;

/* list head of all known sample fetch keywords */
static struct sample_fetch_kw_list sample_fetches = {
	.list = LIST_HEAD_INIT(sample_fetches.list)
};

/* list head of all known sample format conversion keywords */
static struct sample_conv_kw_list sample_convs = {
	.list = LIST_HEAD_INIT(sample_convs.list)
};

/*
 * Registers the sample fetch keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void sample_register_fetches(struct sample_fetch_kw_list *pfkl)
{
	LIST_ADDQ(&sample_fetches.list, &pfkl->list);
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


/*
* Returns a static trash struct chunk to use in sample casts or format conversions
* Swiths the 2 available trash buffers to protect data during convert
*/
static struct chunk *get_trash_chunk(void)
{
	if (sample_trash_buf == sample_trash_buf1)
		sample_trash_buf = sample_trash_buf2;
	else
		sample_trash_buf = sample_trash_buf1;

	chunk_init(&trash_chunk, sample_trash_buf, BUFSIZE);

	return &trash_chunk;
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
/* from: BOOL */ { c_none,    c_none,    c_none,    NULL,     NULL,       NULL,       NULL,      NULL,       NULL   },
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
 */
struct sample_expr *sample_parse_expr(char **str, int *idx, char *err, int err_size)
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

		if (make_arg_list(endw + 1, end - endw - 2, fetch->arg_mask, &expr->arg_p, &err_msg, NULL, &err_arg) < 0) {
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

			if (make_arg_list(endw + 1, end - endw - 2, conv->arg_mask, &conv_expr->arg_p, &err_msg, NULL, &err_arg) < 0) {
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
