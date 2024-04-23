#include <haproxy/stats-json.h>

#include <stdio.h>

#include <haproxy/applet.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/stats.h>

/* Emits an encoding of the field type as JSON.
  * Returns non-zero on success, 0 if the buffer is full.
  */
static int stats_emit_json_field_tags(struct buffer *out, const struct field *f)
{
	const char *origin, *nature, *scope;
	int old_len;

	switch (field_origin(f, 0)) {
	case FO_METRIC:  origin = "Metric";  break;
	case FO_STATUS:  origin = "Status";  break;
	case FO_KEY:     origin = "Key";     break;
	case FO_CONFIG:  origin = "Config";  break;
	case FO_PRODUCT: origin = "Product"; break;
	default:         origin = "Unknown"; break;
	}

	switch (field_nature(f, 0)) {
	case FN_GAUGE:    nature = "Gauge";    break;
	case FN_LIMIT:    nature = "Limit";    break;
	case FN_MIN:      nature = "Min";      break;
	case FN_MAX:      nature = "Max";      break;
	case FN_RATE:     nature = "Rate";     break;
	case FN_COUNTER:  nature = "Counter";  break;
	case FN_DURATION: nature = "Duration"; break;
	case FN_AGE:      nature = "Age";      break;
	case FN_TIME:     nature = "Time";     break;
	case FN_NAME:     nature = "Name";     break;
	case FN_OUTPUT:   nature = "Output";   break;
	case FN_AVG:      nature = "Avg";      break;
	default:          nature = "Unknown";  break;
	}

	switch (field_scope(f, 0)) {
	case FS_PROCESS: scope = "Process"; break;
	case FS_SERVICE: scope = "Service"; break;
	case FS_SYSTEM:  scope = "System";  break;
	case FS_CLUSTER: scope = "Cluster"; break;
	default:         scope = "Unknown"; break;
	}

	old_len = out->data;
	chunk_appendf(out, "\"tags\":{"
			    "\"origin\":\"%s\","
			    "\"nature\":\"%s\","
			    "\"scope\":\"%s\""
			   "}", origin, nature, scope);
	return !(old_len == out->data);
}

/* Limit JSON integer values to the range [-(2**53)+1, (2**53)-1] as per
 * the recommendation for interoperable integers in section 6 of RFC 7159.
 */
#define JSON_INT_MAX ((1ULL << 53) - 1)
#define JSON_INT_MIN (0 - JSON_INT_MAX)

/* Emits a stats field value and its type in JSON.
 * Returns non-zero on success, 0 on error.
 */
static int stats_emit_json_data_field(struct buffer *out, const struct field *f)
{
	int old_len;
	char buf[20];
	const char *type, *value = buf, *quote = "";

	switch (field_format(f, 0)) {
	case FF_EMPTY: return 1;
	case FF_S32:   type = "\"s32\"";
		       snprintf(buf, sizeof(buf), "%d", f->u.s32);
		       break;
	case FF_U32:   type = "\"u32\"";
		       snprintf(buf, sizeof(buf), "%u", f->u.u32);
		       break;
	case FF_S64:   type = "\"s64\"";
		       if (f->u.s64 < JSON_INT_MIN || f->u.s64 > JSON_INT_MAX)
			       return 0;
		       type = "\"s64\"";
		       snprintf(buf, sizeof(buf), "%lld", (long long)f->u.s64);
		       break;
	case FF_U64:   if (f->u.u64 > JSON_INT_MAX)
			       return 0;
		       type = "\"u64\"";
		       snprintf(buf, sizeof(buf), "%llu",
				(unsigned long long) f->u.u64);
		       break;
	case FF_FLT:   type = "\"flt\"";
		       flt_trim(buf, 0, snprintf(buf, sizeof(buf), "%f", f->u.flt));
		       break;
	case FF_STR:   type = "\"str\"";
		       value = field_str(f, 0);
		       quote = "\"";
		       break;
	default:       snprintf(buf, sizeof(buf), "%u", f->type);
		       type = buf;
		       value = "unknown";
		       quote = "\"";
		       break;
	}

	old_len = out->data;
	chunk_appendf(out, ",\"value\":{\"type\":%s,\"value\":%s%s%s}",
		      type, quote, value, quote);
	return !(old_len == out->data);
}

static void stats_print_proxy_field_json(struct buffer *out,
                                         const struct field *stat,
                                         const char *name,
                                         int pos,
                                         uint32_t field_type,
                                         uint32_t iid,
                                         uint32_t sid,
                                         uint32_t pid)
{
	const char *obj_type;
	switch (field_type) {
		case STATS_TYPE_FE: obj_type = "Frontend"; break;
		case STATS_TYPE_BE: obj_type = "Backend";  break;
		case STATS_TYPE_SO: obj_type = "Listener"; break;
		case STATS_TYPE_SV: obj_type = "Server";   break;
		default:            obj_type = "Unknown";  break;
	}

	chunk_appendf(out,
	              "{"
	              "\"objType\":\"%s\","
	              "\"proxyId\":%u,"
	              "\"id\":%u,"
	              "\"field\":{\"pos\":%d,\"name\":\"%s\"},"
	              "\"processNum\":%u,",
	              obj_type, iid, sid, pos, name, pid);
}

static void stats_print_rslv_field_json(struct buffer *out,
                                        const struct field *stat,
                                        const char *name,
                                        int pos)
{
	chunk_appendf(out,
	              "{"
	              "\"field\":{\"pos\":%d,\"name\":\"%s\"},",
	              pos, name);
}


/* Dumps the stats JSON header to <out> buffer. The caller is responsible for
 * clearing it if needed.
 */
void stats_dump_json_header(struct buffer *out)
{
	chunk_strcat(out, "[");
}

/* Dump all fields from <line> into <out> using a typed "field:desc:type:value" format */
int stats_dump_fields_json(struct buffer *out,
                           const struct field *line, size_t stats_count,
                           struct show_stat_ctx *ctx)
{
	int flags = ctx->flags;
	int domain = ctx->domain;
	int started = (ctx->field) ? 1 : 0;
	int ready_data = 0;

	if (!started && (flags & STAT_F_STARTED) && !chunk_strcat(out, ","))
		return 0;
	if (!started && !chunk_strcat(out, "["))
		return 0;

	for (; ctx->field < stats_count; ctx->field++) {
		int old_len;
		int i = ctx->field;

		if (!line[i].type)
			continue;

		if (started && !chunk_strcat(out, ","))
			goto err;
		started = 1;

		old_len = out->data;
		if (domain == STATS_DOMAIN_PROXY) {
			stats_print_proxy_field_json(out, &line[i],
			                             stat_cols[domain][i].name,
			                             i,
			                             line[ST_I_PX_TYPE].u.u32,
			                             line[ST_I_PX_IID].u.u32,
			                             line[ST_I_PX_SID].u.u32,
			                             line[ST_I_PX_PID].u.u32);
		} else if (domain == STATS_DOMAIN_RESOLVERS) {
			stats_print_rslv_field_json(out, &line[i],
			                            stat_cols[domain][i].name,
			                            i);
		}

		if (old_len == out->data)
			goto err;

		if (!stats_emit_json_field_tags(out, &line[i]))
			goto err;

		if (!stats_emit_json_data_field(out, &line[i]))
			goto err;

		if (!chunk_strcat(out, "}"))
			goto err;
		ready_data = out->data;
	}

	if (!chunk_strcat(out, "]"))
		goto err;

	ctx->field = 0; /* we're done */
	return 1;

err:
	if (!ready_data) {
		/* not enough buffer space for a single entry.. */
		chunk_reset(out);
		if (ctx->flags & STAT_F_STARTED)
			chunk_strcat(out, ",");
		chunk_appendf(out, "{\"errorStr\":\"output buffer too short\"}");
		return 0; /* hard error */
	}
	/* push ready data and wait for a new buffer to complete the dump */
	out->data = ready_data;
	return 1;
}

/* Dumps the JSON stats trailer block to <out> buffer. The caller is
 * responsible for clearing it if needed.
 */
void stats_dump_json_end(struct buffer *out)
{
	chunk_strcat(out, "]\n");
}

/* Dump all fields from <stats> into <out> using the "show info json" format */
int stats_dump_json_info_fields(struct buffer *out,
                                const struct field *info,
                                struct show_stat_ctx *ctx)
{
	int started = (ctx->field) ? 1 : 0;
	int ready_data = 0;

	if (!started && !chunk_strcat(out, "["))
		return 0;

	for (; ctx->field < ST_I_INF_MAX; ctx->field++) {
		int old_len;
		int i = ctx->field;

		if (!field_format(info, i))
			continue;

		if (started && !chunk_strcat(out, ","))
			goto err;
		started = 1;

		old_len = out->data;
		chunk_appendf(out,
			      "{\"field\":{\"pos\":%d,\"name\":\"%s\"},"
			      "\"processNum\":%u,",
			      i, stat_cols_info[i].name,
			      info[ST_I_INF_PROCESS_NUM].u.u32);
		if (old_len == out->data)
			goto err;

		if (!stats_emit_json_field_tags(out, &info[i]))
			goto err;

		if (!stats_emit_json_data_field(out, &info[i]))
			goto err;

		if (!chunk_strcat(out, "}"))
			goto err;
		ready_data = out->data;
	}

	if (!chunk_strcat(out, "]\n"))
		goto err;
	ctx->field = 0; /* we're done */
	return 1;

err:
	if (!ready_data) {
		/* not enough buffer space for a single entry.. */
		chunk_reset(out);
		chunk_appendf(out, "{\"errorStr\":\"output buffer too short\"}\n");
		return 0; /* hard error */
	}
	/* push ready data and wait for a new buffer to complete the dump */
	out->data = ready_data;
	return 1;
}

/* This function dumps the schema onto the stream connector's read buffer.
 * It returns 0 as long as it does not complete, non-zero upon completion.
 * No state is used.
 *
 * Integer values bounded to the range [-(2**53)+1, (2**53)-1] as
 * per the recommendation for interoperable integers in section 6 of RFC 7159.
 */
void stats_dump_json_schema(struct buffer *out)
{

	int old_len = out->data;

	chunk_strcat(out,
		     "{"
		      "\"$schema\":\"http://json-schema.org/draft-04/schema#\","
		      "\"oneOf\":["
		       "{"
			"\"title\":\"Info\","
			"\"type\":\"array\","
			"\"items\":{"
			 "\"title\":\"InfoItem\","
			 "\"type\":\"object\","
			 "\"properties\":{"
			  "\"field\":{\"$ref\":\"#/definitions/field\"},"
			  "\"processNum\":{\"$ref\":\"#/definitions/processNum\"},"
			  "\"tags\":{\"$ref\":\"#/definitions/tags\"},"
			  "\"value\":{\"$ref\":\"#/definitions/typedValue\"}"
			 "},"
			 "\"required\":[\"field\",\"processNum\",\"tags\","
				       "\"value\"]"
			"}"
		       "},"
		       "{"
			"\"title\":\"Stat\","
			"\"type\":\"array\","
			"\"items\":{"
			 "\"title\":\"InfoItem\","
			 "\"type\":\"object\","
			 "\"properties\":{"
			  "\"objType\":{"
			   "\"enum\":[\"Frontend\",\"Backend\",\"Listener\","
				     "\"Server\",\"Unknown\"]"
			  "},"
			  "\"proxyId\":{"
			   "\"type\":\"integer\","
			   "\"minimum\":0"
			  "},"
			  "\"id\":{"
			   "\"type\":\"integer\","
			   "\"minimum\":0"
			  "},"
			  "\"field\":{\"$ref\":\"#/definitions/field\"},"
			  "\"processNum\":{\"$ref\":\"#/definitions/processNum\"},"
			  "\"tags\":{\"$ref\":\"#/definitions/tags\"},"
			  "\"typedValue\":{\"$ref\":\"#/definitions/typedValue\"}"
			 "},"
			 "\"required\":[\"objType\",\"proxyId\",\"id\","
				       "\"field\",\"processNum\",\"tags\","
				       "\"value\"]"
			"}"
		       "},"
		       "{"
			"\"title\":\"Error\","
			"\"type\":\"object\","
			"\"properties\":{"
			 "\"errorStr\":{"
			  "\"type\":\"string\""
			 "}"
			"},"
			"\"required\":[\"errorStr\"]"
		       "}"
		      "],"
		      "\"definitions\":{"
		       "\"field\":{"
			"\"type\":\"object\","
			"\"pos\":{"
			 "\"type\":\"integer\","
			 "\"minimum\":0"
			"},"
			"\"name\":{"
			 "\"type\":\"string\""
			"},"
			"\"required\":[\"pos\",\"name\"]"
		       "},"
		       "\"processNum\":{"
			"\"type\":\"integer\","
			"\"minimum\":1"
		       "},"
		       "\"tags\":{"
			"\"type\":\"object\","
			"\"origin\":{"
			 "\"type\":\"string\","
			 "\"enum\":[\"Metric\",\"Status\",\"Key\","
				   "\"Config\",\"Product\",\"Unknown\"]"
			"},"
			"\"nature\":{"
			 "\"type\":\"string\","
			 "\"enum\":[\"Gauge\",\"Limit\",\"Min\",\"Max\","
				   "\"Rate\",\"Counter\",\"Duration\","
				   "\"Age\",\"Time\",\"Name\",\"Output\","
				   "\"Avg\", \"Unknown\"]"
			"},"
			"\"scope\":{"
			 "\"type\":\"string\","
			 "\"enum\":[\"Cluster\",\"Process\",\"Service\","
				   "\"System\",\"Unknown\"]"
			"},"
			"\"required\":[\"origin\",\"nature\",\"scope\"]"
		       "},"
		       "\"typedValue\":{"
			"\"type\":\"object\","
			"\"oneOf\":["
			 "{\"$ref\":\"#/definitions/typedValue/definitions/s32Value\"},"
			 "{\"$ref\":\"#/definitions/typedValue/definitions/s64Value\"},"
			 "{\"$ref\":\"#/definitions/typedValue/definitions/u32Value\"},"
			 "{\"$ref\":\"#/definitions/typedValue/definitions/u64Value\"},"
			 "{\"$ref\":\"#/definitions/typedValue/definitions/strValue\"}"
			"],"
			"\"definitions\":{"
			 "\"s32Value\":{"
			  "\"properties\":{"
			   "\"type\":{"
			    "\"type\":\"string\","
			    "\"enum\":[\"s32\"]"
			   "},"
			   "\"value\":{"
			    "\"type\":\"integer\","
			    "\"minimum\":-2147483648,"
			    "\"maximum\":2147483647"
			   "}"
			  "},"
			  "\"required\":[\"type\",\"value\"]"
			 "},"
			 "\"s64Value\":{"
			  "\"properties\":{"
			   "\"type\":{"
			    "\"type\":\"string\","
			    "\"enum\":[\"s64\"]"
			   "},"
			   "\"value\":{"
			    "\"type\":\"integer\","
			    "\"minimum\":-9007199254740991,"
			    "\"maximum\":9007199254740991"
			   "}"
			  "},"
			  "\"required\":[\"type\",\"value\"]"
			 "},"
			 "\"u32Value\":{"
			  "\"properties\":{"
			   "\"type\":{"
			    "\"type\":\"string\","
			    "\"enum\":[\"u32\"]"
			   "},"
			   "\"value\":{"
			    "\"type\":\"integer\","
			    "\"minimum\":0,"
			    "\"maximum\":4294967295"
			   "}"
			  "},"
			  "\"required\":[\"type\",\"value\"]"
			 "},"
			 "\"u64Value\":{"
			  "\"properties\":{"
			   "\"type\":{"
			    "\"type\":\"string\","
			    "\"enum\":[\"u64\"]"
			   "},"
			   "\"value\":{"
			    "\"type\":\"integer\","
			    "\"minimum\":0,"
			    "\"maximum\":9007199254740991"
			   "}"
			  "},"
			  "\"required\":[\"type\",\"value\"]"
			 "},"
			 "\"strValue\":{"
			  "\"properties\":{"
			   "\"type\":{"
			    "\"type\":\"string\","
			    "\"enum\":[\"str\"]"
			   "},"
			   "\"value\":{\"type\":\"string\"}"
			  "},"
			  "\"required\":[\"type\",\"value\"]"
			 "},"
			 "\"unknownValue\":{"
			  "\"properties\":{"
			   "\"type\":{"
			    "\"type\":\"integer\","
			    "\"minimum\":0"
			   "},"
			   "\"value\":{"
			    "\"type\":\"string\","
			    "\"enum\":[\"unknown\"]"
			   "}"
			  "},"
			  "\"required\":[\"type\",\"value\"]"
			 "}"
			"}"
		       "}"
		      "}"
		     "}");

	if (old_len == out->data) {
		chunk_reset(out);
		chunk_appendf(out,
			      "{\"errorStr\":\"output buffer too short\"}");
	}
	chunk_appendf(out, "\n");
}

/* This function dumps the schema onto the stream connector's read buffer.
 * It returns 0 as long as it does not complete, non-zero upon completion.
 * No state is used.
 */
int stats_dump_json_schema_to_buffer(struct appctx *appctx)
{
	struct show_stat_ctx *ctx = appctx->svcctx;
	struct buffer *chk = &ctx->chunk;

	chunk_reset(chk);

	stats_dump_json_schema(chk);

	if (applet_putchk(appctx, chk) == -1)
		return 0;

	return 1;
}
