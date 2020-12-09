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
#include "include.h"


#ifdef DEBUG_OT

/***
 * NAME
 *   flt_ot_args_dump -
 *
 * ARGUMENTS
 *   args -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_args_dump(char **args)
{
	int i, n;

	for (n = 1; FLT_OT_ARG_ISVALID(n); n++);

	(void)fprintf(stderr, FLT_OT_DBG_FMT("%.*sargs[%d]: { '%s' "), dbg_indent_level, FLT_OT_DBG_INDENT, n, args[0]);

	for (i = 1; FLT_OT_ARG_ISVALID(i); i++)
		(void)fprintf(stderr, "'%s' ", args[i]);

	(void)fprintf(stderr, "}\n");
}


/***
 * NAME
 *   flt_ot_filters_dump -
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_filters_dump(void)
{
	struct flt_conf *fconf;
	struct proxy    *px;

	FLT_OT_FUNC("");

	for (px = proxies_list; px != NULL; px = px->next) {
		FLT_OT_DBG(2, "proxy '%s'", px->id);

		list_for_each_entry(fconf, &(px->filter_configs), list)
			if (fconf->id == ot_flt_id) {
				struct flt_ot_conf *conf = fconf->conf;

				FLT_OT_DBG(2, "  OT filter '%s'", conf->id);
			}
	}

	FLT_OT_RETURN();
}


/***
 * NAME
 *   flt_ot_chn_label -
 *
 * ARGUMENTS
 *   chn -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
const char *flt_ot_chn_label(const struct channel *chn)
{
	return (chn->flags & CF_ISRESP) ? "RESponse" : "REQuest";
}


/***
 * NAME
 *   flt_ot_pr_mode -
 *
 * ARGUMENTS
 *   s -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
const char *flt_ot_pr_mode(const struct stream *s)
{
	struct proxy *px = (s->flags & SF_BE_ASSIGNED) ? s->be : strm_fe(s);

	return (px->mode == PR_MODE_HTTP) ? "HTTP" : "TCP";
}


/***
 * NAME
 *   flt_ot_stream_pos -
 *
 * ARGUMENTS
 *   s -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
const char *flt_ot_stream_pos(const struct stream *s)
{
	return (s->flags & SF_BE_ASSIGNED) ? "backend" : "frontend";
}


/***
 * NAME
 *   flt_ot_type -
 *
 * ARGUMENTS
 *   f -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
const char *flt_ot_type(const struct filter *f)
{
	return (f->flags & FLT_FL_IS_BACKEND_FILTER) ? "backend" : "frontend";
}


/***
 * NAME
 *   flt_ot_analyzer -
 *
 * ARGUMENTS
 *   an_bit -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
const char *flt_ot_analyzer(uint an_bit)
{
#define FLT_OT_AN_DEF(a)   { a, #a },
	static const struct {
		uint        an_bit;
		const char *str;
	} flt_ot_an[] = { FLT_OT_AN_DEFINES };
#undef FLT_OT_AN_DEF
	const char *retptr = "invalid an_bit";
	int         i;

	for (i = 0; i < FLT_OT_TABLESIZE(flt_ot_an); i++)
		if (flt_ot_an[i].an_bit == an_bit) {
			retptr = flt_ot_an[i].str;

			break;
		}

	return retptr;
}


/***
 * NAME
 *   flt_ot_str_hex -
 *
 * ARGUMENTS
 *   data -
 *   size -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
const char *flt_ot_str_hex(const void *data, size_t size)
{
	static THREAD_LOCAL char  retbuf[BUFSIZ];
	const uint8_t            *ptr = data;
	size_t                    i;

	if (data == NULL)
		return "(null)";
	else if (size == 0)
		return "()";

	for (i = 0, size <<= 1; (i < (sizeof(retbuf) - 2)) && (i < size); ptr++) {
		retbuf[i++] = FLT_OT_NIBBLE_TO_HEX(*ptr >> 4);
		retbuf[i++] = FLT_OT_NIBBLE_TO_HEX(*ptr & 0x0f);
	}

	retbuf[i] = '\0';

	return retbuf;
}


/***
 * NAME
 *   flt_ot_str_ctrl -
 *
 * ARGUMENTS
 *   data -
 *   size -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
const char *flt_ot_str_ctrl(const void *data, size_t size)
{
	static THREAD_LOCAL char  retbuf[BUFSIZ];
	const uint8_t            *ptr = data;
	size_t                    i, n = 0;

	if (data == NULL)
		return "(null)";
	else if (size == 0)
		return "()";

	for (i = 0; (n < (sizeof(retbuf) - 1)) && (i < size); i++)
		retbuf[n++] = ((ptr[i] >= 0x20) && (ptr[i] <= 0x7e)) ? ptr[i] : '.';

	retbuf[n] = '\0';

	return retbuf;
}


/***
 * NAME
 *   flt_ot_list_debug -
 *
 * ARGUMENTS
 *   head -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
const char *flt_ot_list_debug(const struct list *head)
{
	FLT_OT_BUFFER_THR(retbuf, 4, 64, retptr);

	if ((head == NULL) || LIST_ISEMPTY(head)) {
		(void)strncpy(retptr, (head == NULL) ? "{ null list }" : "{ empty list }", sizeof(retbuf[0]));
	}
	else if (head->p == head->n) {
		(void)snprintf(retptr, sizeof(retbuf[0]), "{ %p * 1 }", head->p);
	}
	else {
		const struct list *ptr;
		size_t             count = 0;

		for (ptr = head->n; ptr != head; ptr = ptr->n, count++);

		(void)snprintf(retptr, sizeof(retbuf[0]), "{ %p %p %zu }", head->p, head->n, count);
	}

	return (retptr);
}

#endif /* DEBUG_OT */


/***
 * NAME
 *   flt_ot_chunk_add -
 *
 * ARGUMENTS
 *   chk -
 *   src -
 *   n   -
 *   err -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
ssize_t flt_ot_chunk_add(struct buffer *chk, const void *src, size_t n, char **err)
{
	FLT_OT_FUNC("%p, %p, %zu, %p:%p", chk, src, n, FLT_OT_DPTR_ARGS(err));

	if ((chk == NULL) || (src == NULL))
		FLT_OT_RETURN(-1);

	if (chk->area == NULL)
		chunk_init(chk, FLT_OT_CALLOC(1, global.tune.bufsize), global.tune.bufsize);

	if (chk->area == NULL) {
		FLT_OT_ERR("out of memory");

		FLT_OT_RETURN(-1);
	}
	else if (n > (chk->size - chk->data)) {
		FLT_OT_ERR("chunk size too small");

		FLT_OT_RETURN(-1);
	}

	(void)memcpy(chk->area + chk->data, src, n);
	chk->data += n;

	FLT_OT_RETURN(chk->data);
}


/***
 * NAME
 *   flt_ot_args_count -
 *
 * ARGUMENTS
 *   args -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_args_count(char **args)
{
	int retval = 0;

	if (args != NULL)
		for ( ; FLT_OT_ARG_ISVALID(retval); retval++);

	return retval;
}


/***
 * NAME
 *   flt_ot_args_to_str -
 *
 * ARGUMENTS
 *   args -
 *   idx  -
 *   str  -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_ot_args_to_str(char **args, int idx, char **str)
{
	int i;

	if ((args == NULL) || (*args == NULL))
		return;

	for (i = idx; FLT_OT_ARG_ISVALID(i); i++)
		(void)memprintf(str, "%s%s%s", (*str == NULL) ? "" : *str, (i == idx) ? "" : " ", args[i]);
}


/***
 * NAME
 *   flt_ot_strtod -
 *
 * ARGUMENTS
 *   nptr      -
 *   limit_min -
 *   limit_max -
 *   err       -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
double flt_ot_strtod(const char *nptr, double limit_min, double limit_max, char **err)
{
	char   *endptr = NULL;
	double  retval;

	errno = 0;

	retval = strtod(nptr, &endptr);
	if ((errno != 0) || FLT_OT_STR_ISVALID(endptr))
		FLT_OT_ERR("'%s' : invalid value", nptr);
	else if (!FLT_OT_IN_RANGE(retval, limit_min, limit_max))
		FLT_OT_ERR("'%s' : value out of range [%.2f, %.2f]", nptr, limit_min, limit_max);

	return retval;
}


/***
 * NAME
 *   flt_ot_strtoll -
 *
 * ARGUMENTS
 *   nptr      -
 *   limit_min -
 *   limit_max -
 *   err       -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int64_t flt_ot_strtoll(const char *nptr, int64_t limit_min, int64_t limit_max, char **err)
{
	char    *endptr = NULL;
	int64_t  retval;

	errno = 0;

	retval = strtoll(nptr, &endptr, 0);
	if ((errno != 0) || FLT_OT_STR_ISVALID(endptr))
		FLT_OT_ERR("'%s' : invalid value", nptr);
	else if (!FLT_OT_IN_RANGE(retval, limit_min, limit_max))
		FLT_OT_ERR("'%s' : value out of range [%" PRId64 ", %" PRId64 "]", nptr, limit_min, limit_max);

	return retval;
}


/***
 * NAME
 *   flt_ot_sample_to_str -
 *
 * ARGUMENTS
 *   data  -
 *   value -
 *   size  -
 *   err   -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_sample_to_str(const struct sample_data *data, char *value, size_t size, char **err)
{
	int retval = -1;

	FLT_OT_FUNC("%p, %p, %zu, %p:%p", data, value, size, FLT_OT_DPTR_ARGS(err));

	if ((data == NULL) || (value == NULL) || (size == 0))
		FLT_OT_RETURN(retval);

	*value = '\0';

	if (data->type == SMP_T_ANY) {
		FLT_OT_ERR("invalid sample data type %d", data->type);
	}
	else if (data->type == SMP_T_BOOL) {
		value[0] = data->u.sint ? '1' : '0';
		value[1] = '\0';

		retval = 1;
	}
	else if (data->type == SMP_T_SINT) {
		retval = snprintf(value, size, "%lld", data->u.sint);
	}
	else if (data->type == SMP_T_ADDR) {
		/* This type is never used to qualify a sample. */
	}
	else if (data->type == SMP_T_IPV4) {
		if (INET_ADDRSTRLEN > size)
			FLT_OT_ERR("sample data size too large");
		else if (inet_ntop(AF_INET, &(data->u.ipv4), value, INET_ADDRSTRLEN) == NULL)
			FLT_OT_ERR("invalid IPv4 address");
		else
			retval = strlen(value);
	}
	else if (data->type == SMP_T_IPV6) {
		if (INET6_ADDRSTRLEN > size)
			FLT_OT_ERR("sample data size too large");
		else if (inet_ntop(AF_INET6, &(data->u.ipv6), value, INET6_ADDRSTRLEN) == NULL)
			FLT_OT_ERR("invalid IPv6 address");
		else
			retval = strlen(value);
	}
	else if (data->type == SMP_T_STR) {
		if (data->u.str.data >= size) {
			FLT_OT_ERR("sample data size too large");
		}
		else if (data->u.str.data > 0) {
			retval = data->u.str.data;

			(void)strncat(value, data->u.str.area, retval);
		}
		else {
			/*
			 * There is no content to add but we will still return
			 * the correct status.
			 */
			retval = 0;
		}
	}
	else if (data->type == SMP_T_BIN) {
		FLT_OT_ERR("invalid sample data type %d", data->type);
	}
	else if (data->type != SMP_T_METH) {
		FLT_OT_ERR("invalid sample data type %d", data->type);
	}
	else if (data->u.meth.meth == HTTP_METH_OPTIONS) {
		retval = FLT_OT_STR_SIZE(HTTP_METH_STR_OPTIONS);

		(void)memcpy(value, HTTP_METH_STR_OPTIONS, retval + 1);
	}
	else if (data->u.meth.meth == HTTP_METH_GET) {
		retval = FLT_OT_STR_SIZE(HTTP_METH_STR_GET);

		(void)memcpy(value, HTTP_METH_STR_GET, retval + 1);
	}
	else if (data->u.meth.meth == HTTP_METH_HEAD) {
		retval = FLT_OT_STR_SIZE(HTTP_METH_STR_HEAD);

		(void)memcpy(value, HTTP_METH_STR_HEAD, retval + 1);
	}
	else if (data->u.meth.meth == HTTP_METH_POST) {
		retval = FLT_OT_STR_SIZE(HTTP_METH_STR_POST);

		(void)memcpy(value, HTTP_METH_STR_POST, retval + 1);
	}
	else if (data->u.meth.meth == HTTP_METH_PUT) {
		retval = FLT_OT_STR_SIZE(HTTP_METH_STR_PUT);

		(void)memcpy(value, HTTP_METH_STR_PUT, retval + 1);
	}
	else if (data->u.meth.meth == HTTP_METH_DELETE) {
		retval = FLT_OT_STR_SIZE(HTTP_METH_STR_DELETE);

		(void)memcpy(value, HTTP_METH_STR_DELETE, retval + 1);
	}
	else if (data->u.meth.meth == HTTP_METH_TRACE) {
		retval = FLT_OT_STR_SIZE(HTTP_METH_STR_TRACE);

		(void)memcpy(value, HTTP_METH_STR_TRACE, retval + 1);
	}
	else if (data->u.meth.meth == HTTP_METH_CONNECT) {
		retval = FLT_OT_STR_SIZE(HTTP_METH_STR_CONNECT);

		(void)memcpy(value, HTTP_METH_STR_CONNECT, retval + 1);
	}
	else if (data->u.meth.meth == HTTP_METH_OTHER) {
		if (data->u.meth.str.data >= size) {
			FLT_OT_ERR("sample data size too large");
		} else {
			retval = data->u.meth.str.data;

			(void)strncat(value, data->u.meth.str.area, retval);
		}
	}
	else {
		FLT_OT_ERR("invalid HTTP method");
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_sample_to_value -
 *
 * ARGUMENTS
 *   key   -
 *   data  -
 *   value -
 *   err   -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   -
 */
int flt_ot_sample_to_value(const char *key, const struct sample_data *data, struct otc_value *value, char **err)
{
	int retval = -1;

	FLT_OT_FUNC("\"%s\", %p, %p, %p:%p", key, data, value, FLT_OT_DPTR_ARGS(err));

	if ((data == NULL) || (value == NULL))
		FLT_OT_RETURN(retval);

	if (data->type == SMP_T_BOOL) {
		value->type             = otc_value_bool;
		value->value.bool_value = data->u.sint ? 1 : 0;

		retval = sizeof(value->value.bool_value);
	}
	else if (data->type == SMP_T_SINT) {
		value->type              = otc_value_int64;
		value->value.int64_value = data->u.sint;

		retval = sizeof(value->value.int64_value);
	}
	else {
		value->type               = otc_value_string;
		value->value.string_value = FLT_OT_MALLOC(global.tune.bufsize);

		if (value->value.string_value == NULL)
			FLT_OT_ERR("out of memory");
		else
			retval = flt_ot_sample_to_str(data, (char *)value->value.string_value, global.tune.bufsize, err);
	}

	FLT_OT_RETURN(retval);
}


/***
 * NAME
 *   flt_ot_sample_add -
 *
 * ARGUMENTS
 *   s      -
 *   dir    -
 *   sample -
 *   data   -
 *   type   -
 *   err    -
 *
 * DESCRIPTION
 *   -
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
int flt_ot_sample_add(struct stream *s, uint dir, struct flt_ot_conf_sample *sample, struct flt_ot_scope_data *data, int type, char **err)
{
	const struct flt_ot_conf_sample_expr *expr;
	struct sample                         smp;
	struct otc_value                      value;
	struct buffer                         buffer;
	int                                   idx = 0, rc, retval = FLT_OT_RET_OK;

	FLT_OT_FUNC("%p, %u, %p, %p, %d, %p:%p", s, dir, data, sample, type, FLT_OT_DPTR_ARGS(err));

	FLT_OT_DBG_CONF_SAMPLE("sample ", sample);

	(void)memset(&buffer, 0, sizeof(buffer));

	list_for_each_entry(expr, &(sample->exprs), list) {
		FLT_OT_DBG_CONF_SAMPLE_EXPR("sample expression ", expr);

		(void)memset(&smp, 0, sizeof(smp));

		/*
		 * If we have only one expression to process, then the data
		 * type that is the result of the expression is converted to
		 * an equivalent data type (if possible) that is written to
		 * the tracer.
		 *
		 * If conversion is not possible, or if we have multiple
		 * expressions to process, then the result is converted to
		 * a string and as such sent to the tracer.
		 */
		if (sample_process(s->be, s->sess, s, dir | SMP_OPT_FINAL, expr->expr, &smp) != NULL) {
			FLT_OT_DBG(3, "data type %d: '%s'", smp.data.type, expr->value);
		} else {
			FLT_OT_DBG(2, "WARNING: failed to fetch '%s' value", expr->value);

			/*
			 * In case the fetch failed, we will set the result
			 * (sample) to an empty static string.
			 */
			(void)memset(&(smp.data), 0, sizeof(smp.data));
			smp.data.type       = SMP_T_STR;
			smp.data.u.str.area = "";
		}

		if ((sample->num_exprs == 1) && (type == FLT_OT_EVENT_SAMPLE_TAG)) {
			if (flt_ot_sample_to_value(sample->key, &(smp.data), &value, err) == -1)
				retval = FLT_OT_RET_ERROR;
		} else {
			if (buffer.area == NULL) {
				chunk_init(&buffer, FLT_OT_CALLOC(1, global.tune.bufsize), global.tune.bufsize);
				if (buffer.area == NULL) {
					FLT_OT_ERR("out of memory");

					retval = FLT_OT_RET_ERROR;

					break;
				}
			}

			rc = flt_ot_sample_to_str(&(smp.data), buffer.area + buffer.data, buffer.size - buffer.data, err);
			if (rc == -1) {
				retval = FLT_OT_RET_ERROR;
			} else {
				buffer.data += rc;

				if (sample->num_exprs == ++idx) {
					value.type               = otc_value_string;
					value.value.string_value = buffer.area;
				}
			}
		}
	}

	if (retval == FLT_OT_RET_ERROR) {
		/* Do nothing. */
	}
	else if (type == FLT_OT_EVENT_SAMPLE_TAG) {
		struct otc_tag *tag = data->tags + data->num_tags++;

		tag->key = sample->key;
		(void)memcpy(&(tag->value), &value, sizeof(tag->value));
	}
	else if (type == FLT_OT_EVENT_SAMPLE_LOG) {
		struct otc_log_field *log_field = data->log_fields + data->num_log_fields++;

		log_field->key = sample->key;
		(void)memcpy(&(log_field->value), &value, sizeof(log_field->value));
	}
	else {
		if (data->baggage == NULL)
			data->baggage = otc_text_map_new(NULL, FLT_OT_MAXBAGGAGES);

		if (data->baggage == NULL) {
			FLT_OT_ERR("out of memory");

			retval = FLT_OT_RET_ERROR;
		}
		else if (otc_text_map_add(data->baggage, sample->key, 0, value.value.string_value, 0, 0) == -1) {
			FLT_OT_ERR("out of memory");

			retval = FLT_OT_RET_ERROR;
		}
		else
			FLT_OT_DBG(3, "baggage[%zu]: '%s' -> '%s'", data->baggage->count - 1, data->baggage->key[data->baggage->count - 1], data->baggage->value[data->baggage->count - 1]);
	}

	FLT_OT_RETURN(retval);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
