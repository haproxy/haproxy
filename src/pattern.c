/*
 * Patterns management functions.
 *
 * Copyright 2009-2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <string.h>
#include <arpa/inet.h>

#include <proto/arg.h>
#include <proto/pattern.h>
#include <proto/buffers.h>
#include <common/standard.h>

/* static sample used in pattern_process() when <p> is NULL */
static struct sample temp_smp;

/* trash chunk used for pattern conversions */
static struct chunk trash_chunk;

/* trash buffers used or pattern conversions */
static char pattern_trash_buf1[BUFSIZE];
static char pattern_trash_buf2[BUFSIZE];

/* pattern_trash_buf point on used buffer*/
static char *pattern_trash_buf = pattern_trash_buf1;

/* list head of all known pattern fetch keywords */
static struct pattern_fetch_kw_list pattern_fetches = {
	.list = LIST_HEAD_INIT(pattern_fetches.list)
};

/* list head of all known pattern format conversion keywords */
static struct pattern_conv_kw_list pattern_convs = {
	.list = LIST_HEAD_INIT(pattern_convs.list)
};

/*
 * Registers the pattern fetch keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void pattern_register_fetches(struct pattern_fetch_kw_list *pfkl)
{
	LIST_ADDQ(&pattern_fetches.list, &pfkl->list);
}

/*
 * Registers the pattern format coverstion keyword list <pckl> as a list of valid keywords for next
 * parsing sessions.
 */
void pattern_register_convs(struct pattern_conv_kw_list *pckl)
{
	LIST_ADDQ(&pattern_convs.list, &pckl->list);
}

/*
 * Returns the pointer on pattern fetch keyword structure identified by
 * string of <len> in buffer <kw>.
 *
 */
struct pattern_fetch *find_pattern_fetch(const char *kw, int len)
{
	int index;
	struct pattern_fetch_kw_list *kwl;

	list_for_each_entry(kwl, &pattern_fetches.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (strncmp(kwl->kw[index].kw, kw, len) == 0 &&
			    kwl->kw[index].kw[len] == '\0')
				return &kwl->kw[index];
		}
	}
	return NULL;
}

/*
 * Returns the pointer on pattern format conversion keyword structure identified by
 * string of <len> in buffer <kw>.
 *
 */
struct pattern_conv *find_pattern_conv(const char *kw, int len)
{
	int index;
	struct pattern_conv_kw_list *kwl;

	list_for_each_entry(kwl, &pattern_convs.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (strncmp(kwl->kw[index].kw, kw, len) == 0 &&
			    kwl->kw[index].kw[len] == '\0')
				return &kwl->kw[index];
		}
	}
	return NULL;
}


/*
* Returns a static trash struct chunk to use in pattern casts or format conversions
* Swiths the 2 available trash buffers to protect data during convert
*/
static struct chunk *get_trash_chunk(void)
{
	if (pattern_trash_buf == pattern_trash_buf1)
		pattern_trash_buf = pattern_trash_buf2;
	else
		pattern_trash_buf = pattern_trash_buf1;

	chunk_init(&trash_chunk, pattern_trash_buf, BUFSIZE);

	return &trash_chunk;
}

/******************************************************************/
/*          Pattern casts functions                               */
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
/*      Pattern casts matrix:                                    */
/*           pattern_casts[from type][to type]                   */
/*           NULL pointer used for impossible pattern casts      */
/*****************************************************************/

typedef int (*pattern_cast_fct)(struct sample *smp);
static pattern_cast_fct pattern_casts[SMP_TYPES][SMP_TYPES] = {
/*            to:  BOOL       UINT       SINT       IPV4      IPV6        STR         BIN        CSTR        CBIN   */
/* from: BOOL */ { c_none,    c_none,    c_none,    NULL,     NULL,       NULL,       NULL,      NULL,       NULL   },
/*       UINT */ { c_none,    c_none,    c_none,    c_int2ip, NULL,       c_int2str,  NULL,      c_int2str,  NULL   },
/*       SINT */ { c_none,    c_none,    c_none,    c_int2ip, NULL,       c_int2str,  NULL,      c_int2str,  NULL   },
/*       IPV4 */ { NULL,      c_ip2int,  c_ip2int,  c_none,   c_ip2ipv6,  c_ip2str,   NULL,      c_ip2str,   NULL   },
/*       IPV6 */ { NULL,      NULL,      NULL,      NULL,     c_none,     c_ipv62str, NULL,      c_ipv62str, NULL   },
/*        STR */ { c_str2int, c_str2int, c_str2int, c_str2ip, c_str2ipv6, c_none,     c_none,    c_none,     c_none },
/*        BIN */ { NULL,      NULL,      NULL,      NULL,     NULL,       NULL,       c_none,    NULL,       c_none },
/*       CSTR */ { c_str2int, c_str2int, c_str2int, c_str2ip, c_str2ipv6, c_datadup,  c_datadup, c_none,     c_none },
/*       CBIN */ { NULL,      NULL,      NULL,      NULL,     NULL,       NULL,       c_datadup, NULL,       c_none },
};

/*
 * Parse a pattern expression configuration:
 *        fetch keyword followed by format conversion keywords.
 * Returns a pointer on allocated pattern expression structure.
 */
struct pattern_expr *pattern_parse_expr(char **str, int *idx, char *err, int err_size)
{
	const char *endw;
	const char *end;
	struct pattern_expr *expr;
	struct pattern_fetch *fetch;
	struct pattern_conv *conv;
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

	fetch = find_pattern_fetch(str[*idx], endw - str[*idx]);
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
	expr = calloc(1, sizeof(struct pattern_expr));
	if (!expr)
		goto out_error;

	LIST_INIT(&(expr->conv_exprs));
	expr->fetch = fetch;

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
	else if (fetch->arg_mask) {
		p = my_strndup(str[*idx], endw - str[*idx]);
		if (p) {
			snprintf(err, err_size, "missing args for fetch method '%s'.", p);
			free(p);
		}
		goto out_error;
	}

	for (*idx += 1; *(str[*idx]); (*idx)++) {
		struct pattern_conv_expr *conv_expr;

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

		conv = find_pattern_conv(str[*idx], endw - str[*idx]);
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
		if (!pattern_casts[prev_type][conv->in_type]) {
			p = my_strndup(str[*idx], endw - str[*idx]);
			if (p) {
				snprintf(err, err_size, "conv method '%s' cannot be applied.", p);
				free(p);
			}
			goto out_error;
		}

		prev_type = conv->out_type;
		conv_expr = calloc(1, sizeof(struct pattern_conv_expr));
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
	/* TODO: prune_pattern_expr(expr); */
	return NULL;
}

/*
 * Process a fetch + format conversion of defined by the pattern expression <expr>
 * on request or response considering the <dir> parameter.
 * Returns a pointer on a typed pattern structure containing the result or NULL if
 * pattern is not found or when format conversion failed.
 *  If <p> is not null, function returns results in structure pointed by <p>.
 *  If <p> is null, functions returns a pointer on a static pattern structure.
 */
struct sample *pattern_process(struct proxy *px, struct session *l4, void *l7, int dir,
                               struct pattern_expr *expr, struct sample *p)
{
	struct pattern_conv_expr *conv_expr;

	if (p == NULL)
		p = &temp_smp;

	p->flags = 0;
	if (!expr->fetch->process(px, l4, l7, dir, expr->arg_p, p))
		return NULL;

	p->type = expr->fetch->out_type;

	list_for_each_entry(conv_expr, &expr->conv_exprs, list) {
		if (!pattern_casts[p->type][conv_expr->conv->in_type](p))
			return NULL;

		p->type = conv_expr->conv->in_type;
		if (!conv_expr->conv->process(conv_expr->arg_p, p))
			return NULL;

		p->type = conv_expr->conv->out_type;
	}
	return p;
}

/*****************************************************************/
/*    Pattern format convert functions                           */
/*****************************************************************/

static int pattern_conv_str2lower(const struct arg *arg_p, struct sample *smp)
{
	int i;

	if (!smp->data.str.size)
		return 0;

	for (i = 0; i < smp->data.str.len; i++) {
		if ((smp->data.str.str[i] >= 'A') && (smp->data.str.str[i] <= 'Z'))
			smp->data.str.str[i] += 'a' - 'A';
	}
	return 1;
}

static int pattern_conv_str2upper(const struct arg *arg_p, struct sample *smp)
{
	int i;

	if (!smp->data.str.size)
		return 0;

	for (i = 0; i < smp->data.str.len; i++) {
		if ((smp->data.str.str[i] >= 'a') && (smp->data.str.str[i] <= 'z'))
			smp->data.str.str[i] += 'A' - 'a';
	}
	return 1;
}

/* takes the netmask in arg_p */
static int pattern_conv_ipmask(const struct arg *arg_p, struct sample *smp)
{
	smp->data.ipv4.s_addr &= arg_p->data.ipv4.s_addr;
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten */
static struct pattern_conv_kw_list pattern_conv_kws = {{ },{
	{ "upper",  pattern_conv_str2upper, 0,            NULL, SMP_T_STR,  SMP_T_STR  },
	{ "lower",  pattern_conv_str2lower, 0,            NULL, SMP_T_STR,  SMP_T_STR  },
	{ "ipmask", pattern_conv_ipmask,    ARG1(1,MSK4), NULL, SMP_T_IPV4, SMP_T_IPV4 },
	{ NULL, NULL, 0, 0, 0 },
}};

__attribute__((constructor))
static void __pattern_init(void)
{
	/* register pattern format convert keywords */
	pattern_register_convs(&pattern_conv_kws);
}
