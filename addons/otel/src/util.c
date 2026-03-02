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
 *   flt_otel_filters_dump - debug OTel filter instances dump
 *
 * SYNOPSIS
 *   void flt_otel_filters_dump(void)
 *
 * ARGUMENTS
 *   This function takes no arguments.
 *
 * DESCRIPTION
 *   Dumps all OTel filter instances across all proxies.  Iterates the global
 *   proxy list, logging each proxy name and its associated OTel filter IDs.
 *
 * RETURN VALUE
 *   This function does not return a value.
 */
void flt_otel_filters_dump(void)
{
	struct flt_conf *fconf;
	struct proxy    *px;

	OTELC_FUNC("");

	for (px = proxies_list; px != NULL; px = px->next) {
		OTELC_DBG(NOTICE, "proxy '%s'", px->id);

		list_for_each_entry(fconf, &(px->filter_configs), list)
			if (fconf->id == otel_flt_id) {
				struct flt_otel_conf *conf = fconf->conf;

				OTELC_DBG(NOTICE, "  OTEL filter '%s'", conf->id);
			}
	}

	OTELC_RETURN();
}


/***
 * NAME
 *   flt_otel_chn_label - channel direction label
 *
 * SYNOPSIS
 *   const char *flt_otel_chn_label(const struct channel *chn)
 *
 * ARGUMENTS
 *   chn - channel to identify
 *
 * DESCRIPTION
 *   Returns a human-readable label indicating the channel direction based on
 *   the CF_ISRESP flag.
 *
 * RETURN VALUE
 *   Returns "RESponse" for response channels, or "REQuest" for request
 *   channels.
 */
const char *flt_otel_chn_label(const struct channel *chn)
{
	return (chn == NULL) ? "-" : ((chn->flags & CF_ISRESP) ? "RESponse" : "REQuest");
}


/***
 * NAME
 *   flt_otel_pr_mode - proxy mode label
 *
 * SYNOPSIS
 *   const char *flt_otel_pr_mode(const struct stream *s)
 *
 * ARGUMENTS
 *   s - stream to check
 *
 * DESCRIPTION
 *   Returns a human-readable label indicating the proxy mode.  Uses the
 *   backend proxy if a backend is assigned, otherwise the frontend proxy.
 *
 * RETURN VALUE
 *   Returns "HTTP" for HTTP mode proxies, or "TCP" for TCP mode proxies.
 */
const char *flt_otel_pr_mode(const struct stream *s)
{
	struct proxy *px = (s->flags & SF_BE_ASSIGNED) ? s->be : strm_fe(s);

	return (px->mode == PR_MODE_HTTP) ? "HTTP" : "TCP";
}


/***
 * NAME
 *   flt_otel_stream_pos - stream position label
 *
 * SYNOPSIS
 *   const char *flt_otel_stream_pos(const struct stream *s)
 *
 * ARGUMENTS
 *   s - stream to check
 *
 * DESCRIPTION
 *   Returns a human-readable label indicating the stream position based on the
 *   SF_BE_ASSIGNED flag.
 *
 * RETURN VALUE
 *   Returns "backend" if a backend is assigned, or "frontend" otherwise.
 */
const char *flt_otel_stream_pos(const struct stream *s)
{
	return (s->flags & SF_BE_ASSIGNED) ? "backend" : "frontend";
}


/***
 * NAME
 *   flt_otel_type - filter type label
 *
 * SYNOPSIS
 *   const char *flt_otel_type(const struct filter *f)
 *
 * ARGUMENTS
 *   f - filter instance to check
 *
 * DESCRIPTION
 *   Returns a human-readable label indicating the filter type based on the
 *   FLT_FL_IS_BACKEND_FILTER flag.
 *
 * RETURN VALUE
 *   Returns "backend" for backend filters, or "frontend" for frontend filters.
 */
const char *flt_otel_type(const struct filter *f)
{
	return (f->flags & FLT_FL_IS_BACKEND_FILTER) ? "backend" : "frontend";
}


/***
 * NAME
 *   flt_otel_analyzer - analyzer bit name lookup
 *
 * SYNOPSIS
 *   const char *flt_otel_analyzer(uint an_bit)
 *
 * ARGUMENTS
 *   an_bit - the analyzer identifier bit
 *
 * DESCRIPTION
 *   Looks up the human-readable analyzer name for the given <an_bit> value from
 *   the flt_otel_event_data table.  If the bit is not found, a formatted error
 *   string is returned from a thread-local buffer.
 *
 * RETURN VALUE
 *   Returns the analyzer name string, or a formatted error message if the bit
 *   is invalid.
 */
const char *flt_otel_analyzer(uint an_bit)
{
	static THREAD_LOCAL char  retbuf[32];
	const char               *retptr = NULL;
	int                       i;

	for (i = 0; i < OTELC_TABLESIZE(flt_otel_event_data); i++)
		if (flt_otel_event_data[i].an_bit == an_bit) {
			retptr = flt_otel_event_data[i].an_name;

			break;
		}

	if (retptr == NULL)
		(void)snprintf(retbuf, sizeof(retbuf), "invalid an_bit: 0x%08x", an_bit);

	return (retptr == NULL) ? retbuf : retptr;
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


/*
 * Comparator for qsort: ascending order of doubles.  Values within
 * FLT_OTEL_DBL_EPSILON of each other are treated as equal.
 */
int flt_otel_qsort_compar_double(const void *p1, const void *p2)
{
	double a = *(const double *)p1;
	double b = *(const double *)p2;

	return (fabs(a - b) < FLT_OTEL_DBL_EPSILON) ? 0 : ((a < b) ? -1 : 1);
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


/***
 * NAME
 *   flt_otel_sample_to_value - sample data to OTel value conversion
 *
 * SYNOPSIS
 *   int flt_otel_sample_to_value(const char *key, const struct sample_data *data, struct otelc_value *value, char **err)
 *
 * ARGUMENTS
 *   key   - sample key name (for debug output)
 *   data  - sample data to convert
 *   value - output OTel value structure
 *   err   - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Converts sample data to an otelc_value structure.  Boolean samples are
 *   stored as OTELC_VALUE_BOOL, integer samples as OTELC_VALUE_INT64.  All
 *   other types are converted to a string via flt_otel_sample_to_str() and
 *   stored as OTELC_VALUE_DATA with heap-allocated storage.
 *
 * RETURN VALUE
 *   Returns the size of the converted value, or FLT_OTEL_RET_ERROR on failure.
 */
int flt_otel_sample_to_value(const char *key, const struct sample_data *data, struct otelc_value *value, char **err)
{
	int retval = FLT_OTEL_RET_ERROR;

	OTELC_FUNC("\"%s\", %p, %p, %p:%p", OTELC_STR_ARG(key), data, value, OTELC_DPTR_ARGS(err));

	if ((data == NULL) || (value == NULL))
		OTELC_RETURN_INT(retval);

	/* Convert the sample value to an otelc_value based on its type. */
	if (data->type == SMP_T_BOOL) {
		value->u_type       = OTELC_VALUE_BOOL;
		value->u.value_bool = data->u.sint ? 1 : 0;

		retval = sizeof(value->u.value_bool);
	}
	else if (data->type == SMP_T_SINT) {
		value->u_type        = OTELC_VALUE_INT64;
		value->u.value_int64 = data->u.sint;

		retval = sizeof(value->u.value_int64);
	}
	else {
		value->u_type       = OTELC_VALUE_DATA;
		value->u.value_data = OTELC_MALLOC(global.tune.bufsize);

		if (value->u.value_data == NULL)
			FLT_OTEL_ERR("out of memory");
		else
			retval = flt_otel_sample_to_str(data, value->u.value_data, global.tune.bufsize, err);
	}

	OTELC_RETURN_INT(retval);
}


/***
 * NAME
 *   flt_otel_sample_add_event - span event attribute addition
 *
 * SYNOPSIS
 *   static int flt_otel_sample_add_event(struct list *events, struct flt_otel_conf_sample *sample, const struct otelc_value *value)
 *
 * ARGUMENTS
 *   events - list of span events (flt_otel_scope_data_event)
 *   sample - configured sample with event name and key
 *   value  - OTel value to add as an attribute
 *
 * DESCRIPTION
 *   Adds a sample value as a span event attribute.  Searches the existing
 *   events list for an event with a matching name; if not found, creates a new
 *   event entry with an initial attribute array of FLT_OTEL_ATTR_INIT_SIZE
 *   elements.  If the attribute array is full, it is grown by
 *   FLT_OTEL_ATTR_INC_SIZE elements.  The key-value pair is appended to the
 *   event's attribute array.
 *
 * RETURN VALUE
 *   Returns the attribute count for the event, or FLT_OTEL_RET_ERROR on
 *   failure.
 */
static int flt_otel_sample_add_event(struct list *events, struct flt_otel_conf_sample *sample, const struct otelc_value *value)
{
	struct flt_otel_scope_data_event *ptr, *event = NULL;
	struct otelc_kv                  *attr = NULL;
	bool                              flag_list_insert = 0;

	OTELC_FUNC("%p, %p, %p", events, sample, value);

	if ((events == NULL) || (sample == NULL) || (value == NULL))
		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

	/*
	 * First try to find an event with the same name in the list of events,
	 * if it succeeds, new data is added to the event found.
	 */
	if (!LIST_ISEMPTY(events))
		list_for_each_entry(ptr, events, list)
			if (strcmp(ptr->name, OTELC_VALUE_STR(&(sample->extra))) == 0) {
				event = ptr;

				break;
			}

	/*
	 * If an event with the required name is not found, a new event is added
	 * to the list.  Initially, the number of attributes for the new event
	 * is set to FLT_OTEL_ATTR_INIT_SIZE.
	 */
	if (event == NULL) {
		event = OTELC_CALLOC(1, sizeof(*event));
		if (event == NULL)
			OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

		event->name = OTELC_STRDUP(OTELC_VALUE_STR(&(sample->extra)));
		event->attr = OTELC_CALLOC(FLT_OTEL_ATTR_INIT_SIZE, sizeof(*(event->attr)));
		event->cnt  = 0;
		event->size = FLT_OTEL_ATTR_INIT_SIZE;
		if ((event->name == NULL) || (event->attr == NULL)) {
			OTELC_SFREE(event->name);
			OTELC_SFREE(event->attr);
			OTELC_SFREE(event);

			OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);
		}

		flag_list_insert = 1;

		OTELC_DBG(DEBUG, "scope event data initialized");
	}

	/*
	 * In case event attributes are added to an already existing event in
	 * the list, it is checked whether the number of attributes should be
	 * increased.  If necessary, it will be increased by the amount
	 * FLT_OTEL_ATTR_INC_SIZE.
	 */
	if (event->cnt == event->size) {
		typeof(event->attr) ptr = OTELC_REALLOC(event->attr, sizeof(*ptr) * (event->size + FLT_OTEL_ATTR_INC_SIZE));
		if (ptr == NULL)
			OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

		event->attr  = ptr;
		event->size += FLT_OTEL_ATTR_INC_SIZE;

		OTELC_DBG(DEBUG, "scope event data reallocated");
	}

	attr                 = event->attr + event->cnt++;
	attr->key            = sample->key;
	attr->key_is_dynamic = false;
	(void)memcpy(&(attr->value), value, sizeof(attr->value));

	if (flag_list_insert) {
		if (LIST_ISEMPTY(events))
			LIST_INIT(events);

		LIST_INSERT(events, &(event->list));
	}

	OTELC_RETURN_INT(event->cnt);
}


/***
 * NAME
 *   flt_otel_sample_set_status - span status setter
 *
 * SYNOPSIS
 *   static int flt_otel_sample_set_status(struct flt_otel_scope_data_status *status, struct flt_otel_conf_sample *sample, const struct otelc_value *value, char **err)
 *
 * ARGUMENTS
 *   status - span status structure to populate
 *   sample - configured sample with status code in extra data
 *   value  - OTel value for the status description
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Sets the span status code and description from sample data.  The status
 *   code is taken from the sample's extra field (an int32 value) and the
 *   description from <value>, which must be a string type.  Multiple status
 *   settings for the same span are rejected with an error.
 *
 * RETURN VALUE
 *   Returns 1 on success, or FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_sample_set_status(struct flt_otel_scope_data_status *status, struct flt_otel_conf_sample *sample, const struct otelc_value *value, char **err)
{
	OTELC_FUNC("%p, %p, %p, %p:%p", status, sample, value, OTELC_DPTR_ARGS(err));

	if ((status == NULL) || (sample == NULL) || (value == NULL))
		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

	/*
	 * This scenario should never occur, but the check is still enforced -
	 * multiple status settings are not allowed within the filter
	 * configuration for each span event.
	 */
	if (status->description != NULL) {
		FLT_OTEL_ERR("'%s' : span status already set", sample->key);

		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);
	}
	else if ((value->u_type != OTELC_VALUE_STRING) && (value->u_type != OTELC_VALUE_DATA)) {
		FLT_OTEL_ERR("'%s' : status description must be a string value", sample->key);

		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);
	}

	status->code        = sample->extra.u.value_int32;
	status->description = OTELC_STRDUP(OTELC_VALUE_STR(value));
	if (status->description == NULL) {
		FLT_OTEL_ERR("out of memory");

		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);
	}

	OTELC_RETURN_INT(1);
}


/***
 * NAME
 *   flt_otel_sample_add_kv - key-value attribute addition
 *
 * SYNOPSIS
 *   static int flt_otel_sample_add_kv(struct flt_otel_scope_data_kv *kv, const char *key, const struct otelc_value *value)
 *
 * ARGUMENTS
 *   kv    - key-value storage (attributes or baggage)
 *   key   - attribute or baggage key name
 *   value - OTel value to add
 *
 * DESCRIPTION
 *   Adds a sample value as a key-value attribute or baggage entry.  If the
 *   key-value array is not yet allocated, it is created with
 *   FLT_OTEL_ATTR_INIT_SIZE elements via otelc_kv_new().  When the array is
 *   full, it is grown by FLT_OTEL_ATTR_INC_SIZE elements.  The key-value pair
 *   is appended to the array.
 *
 * RETURN VALUE
 *   Returns the current element count, or FLT_OTEL_RET_ERROR on failure.
 */
static int flt_otel_sample_add_kv(struct flt_otel_scope_data_kv *kv, const char *key, const struct otelc_value *value)
{
	struct otelc_kv *attr = NULL;

	OTELC_FUNC("%p, \"%s\", %p", kv, OTELC_STR_ARG(key), value);

	if ((kv == NULL) || (key == NULL) || (value == NULL))
		OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

	if (kv->attr == NULL) {
		kv->attr = otelc_kv_new(FLT_OTEL_ATTR_INIT_SIZE);
		if (kv->attr == NULL)
			OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

		kv->cnt  = 0;
		kv->size = FLT_OTEL_ATTR_INIT_SIZE;

		OTELC_DBG(DEBUG, "scope kv data initialized");
	}

	if (kv->cnt == kv->size) {
		typeof(kv->attr) ptr = OTELC_REALLOC(kv->attr, sizeof(*ptr) * (kv->size + FLT_OTEL_ATTR_INC_SIZE));
		if (ptr == NULL)
			OTELC_RETURN_INT(FLT_OTEL_RET_ERROR);

		kv->attr  = ptr;
		kv->size += FLT_OTEL_ATTR_INC_SIZE;

		OTELC_DBG(DEBUG, "scope kv data reallocated");
	}

	attr                 = kv->attr + kv->cnt++;
	attr->key            = (typeof(attr->key))key;
	attr->key_is_dynamic = false;
	(void)memcpy(&(attr->value), value, sizeof(attr->value));

	OTELC_RETURN_INT(kv->cnt);
}


/***
 * NAME
 *   flt_otel_sample_add - top-level sample evaluator
 *
 * SYNOPSIS
 *   int flt_otel_sample_add(struct stream *s, uint dir, struct flt_otel_conf_sample *sample, struct flt_otel_scope_data *data, int type, char **err)
 *
 * ARGUMENTS
 *   s      - current stream
 *   dir    - the sample fetch direction (SMP_OPT_DIR_REQ/RES)
 *   sample - configured sample definition
 *   data   - scope data to populate
 *   type   - sample type (FLT_OTEL_EVENT_SAMPLE_*)
 *   err    - indirect pointer to error message string
 *
 * DESCRIPTION
 *   Processes all sample expressions for a configured sample definition,
 *   converts the results, and dispatches to the appropriate handler.  For
 *   single-expression attributes and events, native type preservation is
 *   attempted via flt_otel_sample_to_value().  For multi-expression samples,
 *   all results are concatenated into a string buffer.  The final value is
 *   dispatched to flt_otel_sample_add_kv() for attributes and baggage,
 *   flt_otel_sample_add_event() for events, or flt_otel_sample_set_status()
 *   for status.
 *
 * RETURN VALUE
 *   Returns a negative value if an error occurs, 0 if it needs to wait,
 *   any other value otherwise.
 */
int flt_otel_sample_add(struct stream *s, uint dir, struct flt_otel_conf_sample *sample, struct flt_otel_scope_data *data, int type, char **err)
{
	const struct flt_otel_conf_sample_expr *expr;
	struct sample                           smp;
	struct otelc_value                      value;
	struct buffer                           buffer;
	int                                     idx = 0, rc, retval = FLT_OTEL_RET_OK;

	OTELC_FUNC("%p, %u, %p, %p, %d, %p:%p", s, dir, sample, data, type, OTELC_DPTR_ARGS(err));

	FLT_OTEL_DBG_CONF_SAMPLE("sample ", sample);

	(void)memset(&value, 0, sizeof(value));
	(void)memset(&buffer, 0, sizeof(buffer));

	/* Evaluate the sample: log-format path or expression list path. */
	if (sample->lf_used) {
		/*
		 * Log-format path: evaluate the log-format expression into a
		 * dynamically allocated buffer.
		 */
		chunk_init(&buffer, OTELC_CALLOC(1, global.tune.bufsize), global.tune.bufsize);
		if (buffer.area == NULL) {
			FLT_OTEL_ERR("out of memory");

			retval = FLT_OTEL_RET_ERROR;
		} else {
			buffer.data = build_logline(s, buffer.area, buffer.size, &(sample->lf_expr));

			value.u_type       = OTELC_VALUE_DATA;
			value.u.value_data = buffer.area;
		}
	} else {
		list_for_each_entry(expr, &(sample->exprs), list) {
			FLT_OTEL_DBG_CONF_SAMPLE_EXPR("sample expression ", expr);

			(void)memset(&smp, 0, sizeof(smp));

			if (sample_process(s->be, s->sess, s, dir | SMP_OPT_FINAL, expr->expr, &smp) != NULL) {
				OTELC_DBG(DEBUG, "data type %d: '%s'", smp.data.type, expr->fmt_expr);
			} else {
				OTELC_DBG(NOTICE, "WARNING: failed to fetch '%s' value", expr->fmt_expr);

				/*
				 * In case the fetch failed, we will set the result
				 * (sample) to an empty static string.
				 */
				(void)memset(&(smp.data), 0, sizeof(smp.data));
				smp.data.type       = SMP_T_STR;
				smp.data.u.str.area = "";
			}

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
			if ((sample->num_exprs == 1) && ((type == FLT_OTEL_EVENT_SAMPLE_ATTRIBUTE) || (type == FLT_OTEL_EVENT_SAMPLE_EVENT))) {
				if (flt_otel_sample_to_value(sample->key, &(smp.data), &value, err) == FLT_OTEL_RET_ERROR)
					retval = FLT_OTEL_RET_ERROR;
			} else {
				if (buffer.area == NULL) {
					chunk_init(&buffer, OTELC_CALLOC(1, global.tune.bufsize), global.tune.bufsize);
					if (buffer.area == NULL) {
						FLT_OTEL_ERR("out of memory");

						retval = FLT_OTEL_RET_ERROR;

						break;
					}
				}

				rc = flt_otel_sample_to_str(&(smp.data), buffer.area + buffer.data, buffer.size - buffer.data, err);
				if (rc == FLT_OTEL_RET_ERROR) {
					retval = FLT_OTEL_RET_ERROR;
				} else {
					buffer.data += rc;

					if (sample->num_exprs == ++idx) {
						value.u_type       = OTELC_VALUE_DATA;
						value.u.value_data = buffer.area;
					}
				}
			}
		}
	}

	/* Dispatch the evaluated value to the appropriate collection. */
	if (retval == FLT_OTEL_RET_ERROR) {
		/* Do nothing. */
	}
	else if (type == FLT_OTEL_EVENT_SAMPLE_ATTRIBUTE) {
		retval = flt_otel_sample_add_kv(&(data->attributes), sample->key, &value);
		if (retval == FLT_OTEL_RET_ERROR)
			FLT_OTEL_ERR("out of memory");
	}
	else if (type == FLT_OTEL_EVENT_SAMPLE_EVENT) {
		retval = flt_otel_sample_add_event(&(data->events), sample, &value);
		if (retval == FLT_OTEL_RET_ERROR)
			FLT_OTEL_ERR("out of memory");
	}
	else if (type == FLT_OTEL_EVENT_SAMPLE_BAGGAGE) {
		retval = flt_otel_sample_add_kv(&(data->baggage), sample->key, &value);
		if (retval == FLT_OTEL_RET_ERROR)
			FLT_OTEL_ERR("out of memory");
	}
	else if (type == FLT_OTEL_EVENT_SAMPLE_STATUS) {
		retval = flt_otel_sample_set_status(&(data->status), sample, &value, err);
	}
	else {
		FLT_OTEL_ERR("invalid event sample type: %d", type);

		retval = FLT_OTEL_RET_ERROR;
	}

	/*
	 * Free dynamically allocated value data that was not transferred to
	 * a key-value array.  For ATTRIBUTE, EVENT, and BAGGAGE, the value
	 * pointer is shallow-copied into the kv array on success and will be
	 * freed by otelc_kv_destroy().  For STATUS, the handler creates its
	 * own copy, so the original must be freed.  On any error, no handler
	 * consumed the value.
	 */
	if ((retval != FLT_OTEL_RET_ERROR) && (type != FLT_OTEL_EVENT_SAMPLE_STATUS))
		/* Do nothing. */;
	else if (buffer.area != NULL)
		OTELC_SFREE(buffer.area);
	else if (value.u_type == OTELC_VALUE_DATA)
		OTELC_SFREE(value.u.value_data);

	flt_otel_scope_data_dump(data);

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
