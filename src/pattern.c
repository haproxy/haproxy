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
#include <types/stick_table.h>

#include <proto/pattern.h>
#include <common/standard.h>

/* static structure used on pattern_process if <p> is NULL*/
static struct pattern spattern;

/* trash chunk used for pattern conversions */
static struct chunk trash_chunk;

/* trash buffers used or pattern conversions */
static char pattern_trash_buf1[BUFSIZE];
static char pattern_trash_buf2[BUFSIZE];

/* pattern_trash_buf point on used buffer*/
static char *pattern_trash_buf = pattern_trash_buf1;

/* static structure used to returns builded table key from a pattern*/
static struct stktable_key stable_key;

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

	trash_chunk.str = pattern_trash_buf;
	trash_chunk.len = 0;
	trash_chunk.size = BUFSIZE;

	return &trash_chunk;
}

/*
* Used to set pattern data from a struct chunk, could be the trash struct chunk
*/
static void pattern_data_setstring(union pattern_data *data, struct chunk *c)
{
	data->str.str = c->str;
	data->str.len = c->len;
	data->str.size = c->size;
}

/******************************************************************/
/*          Pattern casts functions                               */
/******************************************************************/

static int c_ip2int(union pattern_data *data)
{
	data->integer = ntohl(data->ip.s_addr);
	return 1;
}

static int c_ip2str(union pattern_data *data)
{
	struct chunk *trash = get_trash_chunk();

	if (!inet_ntop(AF_INET, (void *)&data->ip, trash->str, trash->size))
		return 0;

	trash->len = strlen(trash->str);
	pattern_data_setstring(data, trash);

	return 1;
}

static int c_int2ip(union pattern_data *data)
{
	data->ip.s_addr = htonl(data->integer);
	return 1;
}

/* Convert a fixed-length string to an IP address. Returns 0 in case of error,
 * or the number of chars read in case of success.
 */
static int buf2ip(const char *buf, size_t len, struct in_addr *dst)
{
	const char *addr;
	int saw_digit, octets, ch;
	u_char tmp[4], *tp;
	const char *cp = buf;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;

	for (addr = buf; addr - buf < len; addr++) {
		unsigned char digit = (ch = *addr) - '0';

		if (digit > 9 && ch != '.')
			break;

		if (digit <= 9) {
			u_int new = *tp * 10 + digit;

			if (new > 255)
				return 0;

			*tp = new;

			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;

			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}

	if (octets < 4)
		return 0;

	memcpy(&dst->s_addr, tmp, 4);
	return addr - cp;
}

static int c_str2ip(union pattern_data *data)
{
	if (!buf2ip(data->str.str, data->str.len, &data->ip))
		return 0;
	return 1;
}

static int c_int2str(union pattern_data *data)
{
	struct chunk *trash = get_trash_chunk();
	char *pos;

	pos = ultoa_r(data->integer, trash->str, trash->size);

	if (!pos)
		return 0;

	trash->str = pos;
	trash->len = strlen(pos);

	pattern_data_setstring(data, trash);

	return 1;
}

static int c_donothing(union pattern_data *data)
{
	return 1;
}

static int c_str2int(union pattern_data *data)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < data->str.len; i++) {
		uint32_t val = data->str.str[i] - '0';

		if (val > 9)
			break;

		ret = ret * 10 + val;
	}

	data->integer = ret;
	return 1;
}

/*****************************************************************/
/*      Pattern casts matrix:                                    */
/*           pattern_casts[from type][to type]                   */
/*           NULL pointer used for impossible pattern casts      */
/*****************************************************************/

typedef int (*pattern_cast)(union pattern_data *data);
static pattern_cast pattern_casts[PATTERN_TYPES][PATTERN_TYPES] = { { c_donothing, c_ip2int, c_ip2str  },
								    { c_int2ip, c_donothing, c_int2str },
								    { c_str2ip, c_str2int, c_donothing } };


/*****************************************************************/
/*    typed pattern to typed table key functions                 */
/*****************************************************************/

static void *k_int2int(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	return (void *)&pdata->integer;
}

static void *k_ip2ip(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	return (void *)&pdata->ip.s_addr;
}

static void *k_ip2int(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	kdata->integer = ntohl(pdata->ip.s_addr);
	return (void *)&kdata->integer;
}

static void *k_int2ip(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	kdata->ip.s_addr = htonl(pdata->integer);
	return (void *)&kdata->ip.s_addr;
}

static void *k_str2str(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	*len = pdata->str.len;
	return (void *)pdata->str.str;
}

static void *k_ip2str(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	if (!inet_ntop(AF_INET, &pdata->ip, kdata->buf, sizeof(kdata->buf)))
		return NULL;

	*len = strlen((const char *)kdata->buf);
	return (void *)kdata->buf;
}

static void *k_int2str(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	void *key;

	key = (void *)ultoa_r(pdata->integer,  kdata->buf,  sizeof(kdata->buf));
	if (!key)
		return NULL;

	*len = strlen((const char *)key);
	return key;
}

static void *k_str2ip(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	if (!buf2ip(pdata->str.str, pdata->str.len, &kdata->ip))
		return NULL;

	return (void *)&kdata->ip.s_addr;
}


static void *k_str2int(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len)
{
	int i;

	kdata->integer = 0;
	for (i = 0; i < pdata->str.len; i++) {
		uint32_t val = pdata->str.str[i] - '0';

		if (val > 9)
			break;

		kdata->integer = kdata->integer * 10 + val;
	}
	return (void *)&kdata->integer;
}

/*****************************************************************/
/*      typed pattern to typed table key matrix:                 */
/*           pattern_keys[from pattern type][to table key type]  */
/*           NULL pointer used for impossible pattern casts      */
/*****************************************************************/

typedef void *(*pattern_key)(union pattern_data *pdata, union stktable_key_data *kdata, size_t *len);
static pattern_key pattern_keys[PATTERN_TYPES][STKTABLE_TYPES] = { { k_ip2ip,  k_ip2int,  k_ip2str  },
                                                                   { k_int2ip, k_int2int, k_int2str },
                                                                   { k_str2ip, k_str2int, k_str2str } };
/*
 * Parse a pattern expression configuration:
 *        fetch keyword followed by format conversion keywords.
 * Returns a pointer on allocated pattern expression structure.
 */
struct pattern_expr *pattern_parse_expr(char **str, int *idx)
{
	const char *endw;
	const char *end;
	struct pattern_expr *expr;
	struct pattern_fetch *fetch;
	struct pattern_conv *conv;
	unsigned long prev_type;

	if (!str[*idx])
		goto out_error;

	end = str[*idx] + strlen(str[*idx]);
	endw = strchr(str[*idx], '(');

	if (!endw)
		endw = end;
	else if ((end-1)[0] != ')')
		goto out_error;

	fetch = find_pattern_fetch(str[*idx], endw - str[*idx]);
	if (!fetch)
		goto out_error;

	if (fetch->out_type >= PATTERN_TYPES)
		goto out_error;

	prev_type = fetch->out_type;
	expr = calloc(1, sizeof(struct pattern_expr));

	LIST_INIT(&(expr->conv_exprs));
	expr->fetch = fetch;

	if (end != endw) {
		expr->arg_len = end - endw - 2;
		expr->arg = malloc(expr->arg_len + 1);
		expr->arg = memcpy(expr->arg, endw + 1, expr->arg_len);
		expr->arg[expr->arg_len] = '\0';
	}

	for (*idx += 1; *(str[*idx]); (*idx)++) {
		struct pattern_conv_expr *conv_expr;

		end = str[*idx] + strlen(str[*idx]);
		endw = strchr(str[*idx], '(');

		if (!endw)
			endw = end;
		else if ((end-1)[0] != ')')
			goto out_error;

		conv = find_pattern_conv(str[*idx], endw - str[*idx]);
		if (!conv)
			break;

		if (conv->in_type >= PATTERN_TYPES ||
		    conv->out_type >= PATTERN_TYPES)
			goto out_error;

		/* If impossible type conversion */
		if (!pattern_casts[prev_type][conv->in_type])
			goto out_error;

		prev_type = conv->out_type;
		conv_expr = calloc(1, sizeof(struct pattern_conv_expr));

		LIST_ADDQ(&(expr->conv_exprs), &(conv_expr->list));
		conv_expr->conv = conv;

		if (end != endw) {
			int i = end - endw - 2;
			char *p = my_strndup(endw + 1, i);

			if (conv->parse_args) {
				i = conv->parse_args(p, &conv_expr->arg_p, &conv_expr->arg_i);
				free(p);
				if (!i)
					goto out_error;
			} else {
				conv_expr->arg_i = i;
				conv_expr->arg_p = p;
			}
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
struct pattern *pattern_process(struct proxy *px, struct session *l4, void *l7, int dir,
                                struct pattern_expr *expr, struct pattern *p)
{
	struct pattern_conv_expr *conv_expr;

	if (p == NULL)
		p = &spattern;

	if (!expr->fetch->process(px, l4, l7, dir, expr->arg, expr->arg_len, &p->data))
		return NULL;

	p->type = expr->fetch->out_type;

	list_for_each_entry(conv_expr, &expr->conv_exprs, list) {
		if (!pattern_casts[p->type][conv_expr->conv->in_type](&p->data))
			return NULL;

		p->type = conv_expr->conv->in_type;
		if (!conv_expr->conv->process(conv_expr->arg_p, conv_expr->arg_i, &p->data))
			return NULL;

		p->type = conv_expr->conv->out_type;
	}
	return p;
}

/*
 *  Process a fetch + format conversion of defined by the pattern expression <expr>
 *  on request or response considering the <dir> parameter.
 *  Returns a pointer on a static tablekey  structure of type <table_type> of
 *  the converted result.
 */
struct stktable_key *pattern_process_key(struct proxy *px, struct session *l4, void *l7, int dir,
                                         struct pattern_expr *expr, unsigned long table_type)
{
	struct pattern *ptrn;

	ptrn = pattern_process(px, l4, l7, dir, expr, NULL);
	if (!ptrn)
		return NULL;

	stable_key.key_len = (size_t)-1;
	stable_key.key = pattern_keys[ptrn->type][table_type](&ptrn->data, &stable_key.data, &stable_key.key_len);

	if (!stable_key.key)
		return NULL;

	return &stable_key;
}

/*
 * Returns 1 if pattern expression <expr> result cannot be converted to table key of
 * type <table_type> .
 *
 * Used in configuration check
 */
int pattern_notusable_key(struct pattern_expr *expr, unsigned long table_type)
{

	if (table_type >= STKTABLE_TYPES)
		return 1;

	if (LIST_ISEMPTY(&expr->conv_exprs)) {
		if (!pattern_keys[expr->fetch->out_type][table_type])
			return 1;
	} else {
		struct pattern_conv_expr *conv_expr;
		conv_expr = LIST_PREV(&expr->conv_exprs, typeof(conv_expr), list);

		if (!pattern_keys[conv_expr->conv->out_type][table_type])
			return 1;
	}
	return 0;
}

/*****************************************************************/
/*    Pattern format convert functions                           */
/*****************************************************************/

static int pattern_conv_str2lower(const void *arg_p, int arg_i, union pattern_data *data)
{
	int i;

	for (i = 0; i < data->str.len; i++) {
		if ((data->str.str[i] >= 'A') && (data->str.str[i] <= 'Z'))
			data->str.str[i] += 'a' - 'A';
	}
	return 1;
}

static int pattern_conv_str2upper(const void *arg_p, int arg_i, union pattern_data *data)
{
	int i;

	for (i = 0; i < data->str.len; i++) {
		if ((data->str.str[i] >= 'a') && (data->str.str[i] <= 'z'))
			data->str.str[i] += 'A' - 'a';
	}
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten */
static struct pattern_conv_kw_list pattern_conv_kws = {{ },{
	{ "upper",       pattern_conv_str2upper, PATTERN_TYPE_STRING, PATTERN_TYPE_STRING },
	{ "lower",       pattern_conv_str2lower, PATTERN_TYPE_STRING, PATTERN_TYPE_STRING },
	{ NULL, NULL, 0, 0 },
}};

__attribute__((constructor))
static void __pattern_init(void)
{
	/* register pattern format convert keywords */
	pattern_register_convs(&pattern_conv_kws);
}
