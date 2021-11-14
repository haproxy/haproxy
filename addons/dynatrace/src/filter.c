#include <stdio.h>

#include <haproxy/filters.h>
#include <haproxy/http_htx.h>
#include <haproxy/tools.h>

#include <onesdk/onesdk.h>

const char *dynatrace_flt_id = "Dynatrace filter";
struct flt_ops flt_dynatrace_ops;

struct dynatrace_config {
	struct proxy 			*proxy;
	struct proxy 			*be;
	char 					*name;
	char 					*service_name;
	
	char *host;
	char *full_path;
	char *method;
	char *full_url;

	onesdk_result_t			onesdk_init_result;

	onesdk_tracer_handle_t  tracer_incoming_web_quest;
	onesdk_tracer_handle_t  tracer_outgoing_web_quest;

	onesdk_tracer_handle_t tracer_AN_REQ_HTTP_BODY;
	onesdk_tracer_handle_t tracer_AN_REQ_HTTP_INNER;
	onesdk_tracer_handle_t tracer_AN_REQ_HTTP_PROCESS_BE;
	onesdk_tracer_handle_t tracer_AN_REQ_HTTP_PROCESS_FE;
	onesdk_tracer_handle_t tracer_AN_REQ_HTTP_TARPIT;
	onesdk_tracer_handle_t tracer_AN_REQ_HTTP_XFER_BODY;
	onesdk_tracer_handle_t tracer_AN_REQ_INSPECT_BE;
	onesdk_tracer_handle_t tracer_AN_REQ_INSPECT_FE;
	onesdk_tracer_handle_t tracer_AN_REQ_PRST_RDP_COOKIE;
	onesdk_tracer_handle_t tracer_AN_REQ_SRV_RULES;
	onesdk_tracer_handle_t tracer_AN_REQ_STICKING_RULES;
	onesdk_tracer_handle_t tracer_AN_REQ_SWITCHING_RULES;
	onesdk_tracer_handle_t tracer_AN_REQ_WAIT_HTTP;
	onesdk_tracer_handle_t tracer_AN_RES_HTTP_PROCESS_FE;
	onesdk_tracer_handle_t tracer_AN_RES_HTTP_XFER_BODY;
	onesdk_tracer_handle_t tracer_AN_RES_INSPECT;
	onesdk_tracer_handle_t tracer_AN_RES_STORE_RULES;
	onesdk_tracer_handle_t tracer_AN_RES_WAIT_HTTP;

};

static void dynatrace_debug(char const* message) {
    fputs(message, stderr);
}

static int flt_dynatrace_init(struct proxy *p, struct flt_conf *fconf)
{

	struct dynatrace_config *conf = fconf->conf;
	conf->name = memprintf(&conf->name, "Dynatrace/%s", p->id);
	conf->service_name = memprintf(&conf->service_name, "HAProxy (%s)", p->id);

	fconf->flags |= FLT_CFG_FL_HTX;

	// Here we initialize the OneAgent SDK
	conf->onesdk_init_result = onesdk_initialize();
	printf("dynatrace - Initialized the OneAgent SDK with agent state: %d\n", conf->onesdk_init_result);
	onesdk_agent_set_verbose_callback(dynatrace_debug);

    return 0;
}

/* Free resources allocated by the dynatrace filter. */
static void
flt_dynatrace_deinit(struct proxy *px, struct flt_conf *fconf)
{
	struct dynatrace_config *conf = fconf->conf;
	if (conf) {
		if (conf->onesdk_init_result == ONESDK_SUCCESS)
			onesdk_shutdown();
		free(conf);
	}
	fconf->conf = NULL;
}

/* Called when a backend is set for a stream */
static int
flt_dynatrace_stream_set_backend(struct stream *s, struct filter *filter,
			 struct proxy *be)
{
	struct dynatrace_config *conf = FLT_CONF(filter);
	conf->be = be;
	return 0;
}


static void add_headers_to_tracer(struct dynatrace_config *conf, struct htx *htx, int is_req) {

	int32_t pos;

	// Parse the headers
		for (pos = htx_get_first(htx); pos != -1; pos = htx_get_next(htx, pos)) {
			struct htx_blk *blk = htx_get_blk(htx, pos);
			enum htx_blk_type type = htx_get_blk_type(blk);
			struct ist n, v;

			if (type == HTX_BLK_EOH)
				break;
			if (type != HTX_BLK_HDR)
				continue;

			n = htx_get_blk_name(htx, blk); // Header name, all lower case
			v = htx_get_blk_value(htx, blk); // Header value

			
			if (is_req) {
				// Add remote address
				if (strncmp(n.ptr, "host", 4) == 0) {
					conf->host = strndup(n.ptr, n.len);
					onesdk_incomingwebrequesttracer_set_remote_address(conf->tracer_incoming_web_quest, onesdk_asciistr(conf->host));
				}

				// Add request headers
				onesdk_incomingwebrequesttracer_add_request_header(
					conf->tracer_incoming_web_quest,
					 onesdk_asciistr(strndup(n.ptr, n.len)),
					 onesdk_asciistr(strndup(v.ptr, v.len)));
			} else {
				// Add response headers
				onesdk_incomingwebrequesttracer_add_response_header(
					conf->tracer_incoming_web_quest,
					 onesdk_asciistr(strndup(n.ptr, n.len)),
					 onesdk_asciistr(strndup(v.ptr, v.len)));
			}

		}
}

static void start_outgoing_tracer(struct dynatrace_config *conf, struct htx *htx) {
	// OneSDK variables
	onesdk_size_t string_tag_size = 0;
	char* string_tag = NULL;
	struct ist x_dynatrace_name = ist("x-dynatrace");
	struct http_hdr_ctx ctx;

	conf->full_url = memprintf(&conf->full_url, "http://%s%s", conf->be->id, conf->full_path);
	conf->tracer_outgoing_web_quest = onesdk_outgoingwebrequesttracer_create(
	onesdk_asciistr(conf->full_url),
	onesdk_asciistr(conf->method));
	onesdk_tracer_start(conf->tracer_outgoing_web_quest);

	onesdk_tracer_get_outgoing_dynatrace_string_tag(conf->tracer_outgoing_web_quest, NULL, 0, &string_tag_size);
	if (string_tag_size != 0) {
	string_tag = (char*)malloc(string_tag_size);
	if (string_tag != NULL)
		string_tag_size = onesdk_tracer_get_outgoing_dynatrace_string_tag(conf->tracer_outgoing_web_quest, string_tag, string_tag_size, NULL);
	}

	ctx.blk = NULL;
	if (http_find_header(htx, x_dynatrace_name, &ctx, 1)) {
		http_replace_header(htx, &ctx, x_dynatrace_name, ist(string_tag));	
	}else{
		http_add_header(htx, x_dynatrace_name, ist(string_tag));	
	}

	free(string_tag);
}

static void parse_request_headers(struct dynatrace_config *conf, struct htx *htx) {
	add_headers_to_tracer(conf, htx, 1);
}

static void parse_response_headers(struct dynatrace_config *conf, struct htx *htx) {
	add_headers_to_tracer(conf, htx, 0);
}

/**************************************************************************
 * Hooks to filter HTTP messages
 *************************************************************************/
static int
flt_dynatrace_http_headers(struct stream *s, struct filter *filter,
		   struct http_msg *msg)
{
	struct dynatrace_config *conf = FLT_CONF(filter);
	struct htx *htx = htxbuf(&msg->chn->buf);
	struct htx_sl *sl = http_get_stline(htx);

	onesdk_webapplicationinfo_handle_t web_application_info_handle = ONESDK_INVALID_HANDLE;

	if (!(msg->chn->flags & CF_ISRESP)) {
		// This is the REQUEST arriving in HAProxy
		conf->method = strndup(HTX_SL_P1_PTR(sl), HTX_SL_P1_LEN(sl));
		conf->full_path = strndup(HTX_SL_P2_PTR(sl), HTX_SL_P2_LEN(sl));

		web_application_info_handle = onesdk_webapplicationinfo_create(
        	onesdk_asciistr(conf->service_name), /* TODO: This should be a parameter of the filter*/
	        onesdk_asciistr(conf->service_name), /* TODO: This should be a parameter of the filter*/  
    	    onesdk_asciistr("/"));   

		conf->tracer_incoming_web_quest = onesdk_incomingwebrequesttracer_create(
			web_application_info_handle,
			onesdk_asciistr(conf->full_path),
			onesdk_asciistr(conf->method));   
		
		parse_request_headers(conf, htx);

		// printf("Starting tracer %ld for %s %s\n", conf->tracer_incoming_web_quest, conf->method, conf->full_path);
		onesdk_tracer_start(conf->tracer_incoming_web_quest);

		start_outgoing_tracer(conf, htx);

	} else {
		// Here we are dealing with the RESPONSE, so we have response headers
		parse_response_headers(conf, htx);

		// printf("Ending tracer %ld\n", conf->tracer_incoming_web_quest);
		onesdk_tracer_end(conf->tracer_incoming_web_quest);
	}
	return 1;
}

/**************************************************************************
 * Hooks to handle channels activity
 *************************************************************************/
/* Called when analyze starts for a given channel */
static int
flt_dynatrace_chn_start_analyze(struct stream *s, struct filter *filter,
			struct channel *chn)
{
	filter->pre_analyzers  |= (AN_REQ_ALL | AN_RES_ALL);
	filter->post_analyzers |= (AN_REQ_ALL | AN_RES_ALL);
	register_data_filter(s, chn, filter);
	return 1;
}

void 
start_or_end_custom_tracer(char* method_name, onesdk_tracer_handle_t *tracer, int is_pre) {
	if (is_pre) {
		*tracer = onesdk_customservicetracer_create(onesdk_asciistr(method_name), onesdk_asciistr("HAProxy Analyzers"));
		// printf("Started %ld\n", *tracer);
		onesdk_tracer_start(*tracer);
	} else {
		// printf("Ended %ld\n", *tracer);
		onesdk_tracer_end(*tracer);
	}
}

/* Called before a processing happens on a given channel */
static int
flt_dynatrace_chn_analyze(struct stream *s, struct filter *filter,
		  struct channel *chn, unsigned an_bit)
{
	struct dynatrace_config *conf = FLT_CONF(filter);
	char                *ana;
	int is_pre = (chn->analysers & an_bit);

	switch (an_bit) {
		case AN_REQ_INSPECT_FE:
			ana = "AN_REQ_INSPECT_FE";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_INSPECT_FE, is_pre);
			break;
		case AN_REQ_WAIT_HTTP:
			ana = "AN_REQ_WAIT_HTTP";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_WAIT_HTTP, is_pre);
			break;
		case AN_REQ_HTTP_BODY:
			ana = "AN_REQ_HTTP_BODY";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_HTTP_BODY, is_pre);
			break;
		case AN_REQ_HTTP_PROCESS_FE:
			ana = "AN_REQ_HTTP_PROCESS_FE";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_HTTP_PROCESS_FE, is_pre);
			break;
		case AN_REQ_SWITCHING_RULES:
			ana = "AN_REQ_SWITCHING_RULES";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_SWITCHING_RULES, is_pre);
			break;
		case AN_REQ_INSPECT_BE:
			ana = "AN_REQ_INSPECT_BE";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_INSPECT_BE, is_pre);
			break;
		case AN_REQ_HTTP_PROCESS_BE:
			ana = "AN_REQ_HTTP_PROCESS_BE";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_HTTP_PROCESS_BE, is_pre);
			break;
		case AN_REQ_SRV_RULES:
			ana = "AN_REQ_SRV_RULES";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_SRV_RULES, is_pre);
			break;
		case AN_REQ_HTTP_INNER:
			ana = "AN_REQ_HTTP_INNER";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_HTTP_INNER, is_pre);
			break;
		case AN_REQ_HTTP_TARPIT:
			ana = "AN_REQ_HTTP_TARPIT";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_HTTP_TARPIT, is_pre);
			break;
		case AN_REQ_STICKING_RULES:
			ana = "AN_REQ_STICKING_RULES";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_STICKING_RULES, is_pre);
			break;
		case AN_REQ_PRST_RDP_COOKIE:
			ana = "AN_REQ_PRST_RDP_COOKIE";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_PRST_RDP_COOKIE, is_pre);
			break;
		case AN_REQ_HTTP_XFER_BODY:
			ana = "AN_REQ_HTTP_XFER_BODY";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_REQ_HTTP_XFER_BODY, is_pre);
			break;
		case AN_RES_INSPECT:
			ana = "AN_RES_INSPECT";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_RES_INSPECT, is_pre);
			break;
		case AN_RES_WAIT_HTTP:
			ana = "AN_RES_WAIT_HTTP";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_RES_WAIT_HTTP, is_pre);

			if (!is_pre) 
				onesdk_tracer_end(conf->tracer_outgoing_web_quest);
			break;
		case AN_RES_HTTP_PROCESS_FE: // AN_RES_HTTP_PROCESS_BE
			ana = "AN_RES_HTTP_PROCESS_FE/BE";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_RES_HTTP_PROCESS_FE, is_pre);
			break;
		case AN_RES_STORE_RULES:
			ana = "AN_RES_STORE_RULES";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_RES_STORE_RULES, is_pre);
			break;
		case AN_RES_HTTP_XFER_BODY:
			ana = "AN_RES_HTTP_XFER_BODY";
			start_or_end_custom_tracer(ana, &conf->tracer_AN_RES_HTTP_XFER_BODY, is_pre);
			break;
		default:
			ana = "unknown";
	}
	return 1;
}



struct flt_ops flt_dynatrace_ops = {
	/* Callbacks to manage the filter lifecycle. */
	.init                  = flt_dynatrace_init,
	.deinit                = flt_dynatrace_deinit,

	// /* Stream callbacks. */
	.stream_set_backend    = flt_dynatrace_stream_set_backend,

	// /* Channel callbacks. */
	.channel_start_analyze = flt_dynatrace_chn_start_analyze,
	.channel_pre_analyze   = flt_dynatrace_chn_analyze,
	.channel_post_analyze  = flt_dynatrace_chn_analyze,

	// /* HTTP callbacks. */
	.http_headers          = flt_dynatrace_http_headers,
};


/* Return -1 on error, else 0 */
static int
parse_dynatrace_flt(char **args, int *cur_arg, struct proxy *px,
                struct flt_conf *fconf, char **err, void *private)
{
	struct dynatrace_config *conf;
	int pos = *cur_arg;

	conf = calloc(1, sizeof(*conf));
	if (!conf) {
		memprintf(err, "%s: out of memory", args[*cur_arg]);
		return -1;
	}
	conf->proxy = px;
	

	// If we don't do this, the filter parsing breaks
	// it thinks there are keywords remaining in the line, but it is the filter name
	pos++; 
	*cur_arg = pos;


	fconf->id = dynatrace_flt_id;
	fconf->ops = &flt_dynatrace_ops;
	fconf->conf = conf;

	return 0;

 error:
	free(conf);
	return -1;
}

/* Declare the filter parser for "dynatrace" keyword */
static struct flt_kw_list flt_kws = { "DYNATRACE", { }, {
		{ "dynatrace", parse_dynatrace_flt, NULL },
		{ NULL, NULL, NULL },
	}
};

INITCALL1(STG_REGISTER, flt_register_keywords, &flt_kws);
