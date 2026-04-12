/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "../include/include.h"


#ifdef DEBUG_OTEL

/***
 * NAME
 *   flt_otel_args_dump - debug configuration arguments dump
 *
 * SYNOPSIS
 *   void flt_otel_args_dump(const char **args)
 *
 * ARGUMENTS
 *   args - configuration line arguments array
 *
 * DESCRIPTION
 *   Dumps all configuration arguments to stderr.  Counts the number of valid
 *   arguments via flt_otel_args_count() and prints each one surrounded by
 *   single quotes.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_args_dump(const char **args)
{
	int i, argc;

	argc = flt_otel_args_count(args);

	(void)fprintf(stderr, OTELC_DBG_FMT("args[%d]: { '%s' "), argc, args[0]);

	for (i = 1; i < argc; i++)
		(void)fprintf(stderr, "'%s' ", args[i]);

	(void)fprintf(stderr, "}\n");
}


/***
 * NAME
 *   flt_otel_list_dump - debug list summary
 *
 * SYNOPSIS
 *   const char *flt_otel_list_dump(const struct list *head)
 *
 * ARGUMENTS
 *   head - list head to summarize
 *
 * DESCRIPTION
 *   Returns a concise summary string describing the state of a linked list.
 *   For NULL or empty lists, returns a descriptive label.  For single-element
 *   lists, returns the element pointer.  For multi-element lists, returns the
 *   first and last pointers along with the element count.  Uses a rotating
 *   thread-local buffer for the return value.
 *
 * RETURN VALUE
 *   Returns a pointer to a thread-local string describing the list.
 */
const char *flt_otel_list_dump(const struct list *head)
{
	FLT_OTEL_BUFFER_THR(retbuf, 4, 64, retptr);

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

#endif /* DEBUG_OTEL */


/***
 * NAME
 *   flt_otel_args_count - argument count
 *
 * SYNOPSIS
 *   int flt_otel_args_count(const char **args)
 *
 * ARGUMENTS
 *   args - configuration line arguments array
 *
 * DESCRIPTION
 *   Counts the number of valid (non-NULL) arguments in <args>.  Scans up to
 *   MAX_LINE_ARGS entries, handling gaps from blank arguments by returning the
 *   index of the last valid argument incremented by one.
 *
 * RETURN VALUE
 *   Returns the number of valid arguments.
 */
int flt_otel_args_count(const char **args)
{
	int i, retval = 0;

	if (args == NULL)
		return retval;

	/*
	 * It is possible that some arguments within the configuration line
	 * are not specified; that is, they are set to a blank string.
	 *
	 * For example:
	 *   keyword '' arg_2
	 *
	 * In that case the content of the args field will be like this:
	 *   args[0]:                  'keyword'
	 *   args[1]:                  NULL pointer
	 *   args[2]:                  'arg_2'
	 *   args[3 .. MAX_LINE_ARGS): NULL pointers
	 *
	 * The total number of arguments is the index of the last argument
	 * (increased by 1) that is not a NULL pointer.
	 */
	for (i = 0; i < MAX_LINE_ARGS; i++)
		if (FLT_OTEL_ARG_ISVALID(i))
			retval = i + 1;

	return retval;
}


/***
 * NAME
 *   flt_otel_args_concat - argument concatenation
 *
 * SYNOPSIS
 *   int flt_otel_args_concat(const char **args, int idx, int n, char **str)
 *
 * ARGUMENTS
 *   args - configuration line arguments array
 *   idx  - starting index for concatenation
 *   n    - maximum number of arguments to concatenate (0 means all)
 *   str  - indirect pointer to the result string
 *
 * DESCRIPTION
 *   Concatenates arguments starting from index <idx> into a single
 *   space-separated string.  The result is built via memprintf() into <*str>.
 *   NULL arguments within the range are treated as empty strings.
 *
 * RETURN VALUE
 *   Returns the number of concatenated arguments, or FLT_OTEL_RET_ERROR on
 *   failure.
 */
int flt_otel_args_concat(const char **args, int idx, int n, char **str)
{
	int i, argc;

	if ((args == NULL) || (str == NULL))
		return FLT_OTEL_RET_ERROR;
	else if ((idx < 0) || (n < 0))
		return FLT_OTEL_RET_ERROR;

	argc = (n == 0) ? flt_otel_args_count(args) : OTELC_MIN(flt_otel_args_count(args), idx + n);

	for (i = idx; i < argc; i++)
		(void)memprintf(str, "%s%s%s", (*str == NULL) ? "" : *str, (i == idx) ? "" : " ", (args[i] == NULL) ? "" : args[i]);

	OTELC_DBG(DEBUG, "args[%d, %d]: '%s'", idx, argc, (*str == NULL) ? "" : *str);

	return (*str == NULL) ? FLT_OTEL_RET_ERROR : (i - idx);
}


/***
 * NAME
 *   flt_otel_strtod - string to double conversion with range check
 *
 * SYNOPSIS
 *   bool flt_otel_strtod(const char *nptr, double *value, double limit_min, double limit_max, char **err)
 *
 * ARGUMENTS
 *   nptr      - string to parse
 *   value     - pointer to store the parsed double result
 *   limit_min - minimum allowed value
 *   limit_max - maximum allowed value
 *   err       - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses the string <nptr> as a double-precision floating-point number.
 *   Validates that the entire string is consumed and that the result falls
 *   within the range [<limit_min>, <limit_max>].  On parse error or range
 *   violation, an error message is stored via <err>.
 *
 * RETURN VALUE
 *   Returns true on success, false on failure.
 */
bool flt_otel_strtod(const char *nptr, double *value, double limit_min, double limit_max, char **err)
{
	char *endptr = NULL;
	bool  retval = false;

	if (value == NULL)
		return retval;

	errno = 0;

	*value = strtod(nptr, &endptr);
	if ((errno != 0) || OTELC_STR_IS_VALID(endptr))
		FLT_OTEL_ERR("'%s' : invalid value", nptr);
	else if (!OTELC_IN_RANGE(*value, limit_min, limit_max))
		FLT_OTEL_ERR("'%s' : value out of range [%.2f, %.2f]", nptr, limit_min, limit_max);
	else
		retval = true;

	return retval;
}


/***
 * NAME
 *   flt_otel_strtoll - string to int64_t conversion with range check
 *
 * SYNOPSIS
 *   bool flt_otel_strtoll(const char *nptr, int64_t *value, int64_t limit_min, int64_t limit_max, char **err)
 *
 * ARGUMENTS
 *   nptr      - string to parse
 *   value     - pointer to store the parsed int64_t result
 *   limit_min - minimum allowed value
 *   limit_max - maximum allowed value
 *   err       - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Parses the string <nptr> as a 64-bit integer using base auto-detection.
 *   Validates that the entire string is consumed and that the result falls
 *   within the range [<limit_min>, <limit_max>].  On parse error or range
 *   violation, an error message is stored via <err>.
 *
 * RETURN VALUE
 *   Returns true on success, false on failure.
 */
bool flt_otel_strtoll(const char *nptr, int64_t *value, int64_t limit_min, int64_t limit_max, char **err)
{
	char *endptr = NULL;
	bool  retval = false;

	if (value == NULL)
		return retval;

	errno = 0;

	*value = strtoll(nptr, &endptr, 0);
	if ((errno != 0) || OTELC_STR_IS_VALID(endptr))
		FLT_OTEL_ERR("'%s' : invalid value", nptr);
	else if (!OTELC_IN_RANGE(*value, limit_min, limit_max))
		FLT_OTEL_ERR("'%s' : value out of range [%" PRId64 ", %" PRId64 "]", nptr, limit_min, limit_max);
	else
		retval = true;

	return retval;
}


/***
 * NAME
 *   flt_otel_sample_to_str - sample data to string conversion
 *
 * SYNOPSIS
 *   int flt_otel_sample_to_str(const struct sample_data *data, char *value, size_t size, char **err)
 *
 * ARGUMENTS
 *   data  - sample data to convert
 *   value - output buffer for the string representation
 *   size  - output buffer size
 *   err   - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Converts sample data to its string representation.  Handles bool, sint,
 *   IPv4, IPv6, str, and HTTP method types.  Boolean values are written as
 *   "0" or "1".  Integer values use snprintf().  IP addresses are converted
 *   via inet_ntop().  String values are copied directly.  HTTP methods are
 *   resolved to their standard string names; the HTTP_METH_OTHER type uses
 *   the method's raw string data.  Binary and unknown types produce an error.
 *
 * RETURN VALUE
 *   Returns the number of characters written to <value>,
 *   or FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_sample_to_str(const struct sample_data *data, char *value, size_t size, char **err)
{
	int retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("%p, %p, %zu, %p:%p", data, value, size, OTELC_DPTR_ARGS(err));

	if ((data == NULL) || (value == NULL) || (size == 0))
		OTELC_RETURN_INT(retval);

	*value = '\0';

	/* Convert the sample value to a string based on its type. */
	if (data->type == SMP_T_ANY) {
		FLT_OTEL_ERR("invalid sample data type %d", data->type);
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
			FLT_OTEL_ERR("sample data size too large");
		else if (inet_ntop(AF_INET, &(data->u.ipv4), value, INET_ADDRSTRLEN) == NULL)
			FLT_OTEL_ERR("invalid IPv4 address");
		else
			retval = strlen(value);
	}
	else if (data->type == SMP_T_IPV6) {
		if (INET6_ADDRSTRLEN > size)
			FLT_OTEL_ERR("sample data size too large");
		else if (inet_ntop(AF_INET6, &(data->u.ipv6), value, INET6_ADDRSTRLEN) == NULL)
			FLT_OTEL_ERR("invalid IPv6 address");
		else
			retval = strlen(value);
	}
	else if (data->type == SMP_T_STR) {
		if (data->u.str.data >= size) {
			FLT_OTEL_ERR("sample data size too large");
		}
		else if (data->u.str.data > 0) {
			retval = data->u.str.data;
			(void)memcpy(value, data->u.str.area, retval);
			value[retval] = '\0';
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
		FLT_OTEL_ERR("invalid sample data type %d", data->type);
	}
	else if (data->type != SMP_T_METH) {
		FLT_OTEL_ERR("invalid sample data type %d", data->type);
	}
	else if (OTELC_IN_RANGE(data->u.meth.meth, HTTP_METH_OPTIONS, HTTP_METH_CONNECT)) {
#define FLT_OTEL_HTTP_METH_DEF(a)   { #a, FLT_OTEL_STR_SIZE(#a) },
		static const struct {
			const char *str;
			size_t      len;
		} http_meth_str[] = { FLT_OTEL_HTTP_METH_DEFINES };
#undef FLT_OTEL_HTTP_METH_DEF

		retval = http_meth_str[data->u.meth.meth].len;
		(void)memcpy(value, http_meth_str[data->u.meth.meth].str, retval + 1);
	}
	else if (data->u.meth.meth == HTTP_METH_OTHER) {
		if (data->u.meth.str.data >= size) {
			FLT_OTEL_ERR("sample data size too large");
		} else {
			retval = data->u.meth.str.data;
			(void)memcpy(value, data->u.meth.str.area, retval);
			value[retval] = '\0';
		}
	}
	else {
		FLT_OTEL_ERR("invalid HTTP method");
	}

	if (retval != FLT_OTEL_RET_ERROR)
		OTELC_DBG(DEBUG, "sample value (%d): '%.*s' %d", data->type, retval, value, retval);

	OTELC_RETURN_INT(retval);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
