/*
 * Mod Defender for HAProxy
 *
 * Copyright 2017 HAProxy Technologies, Dragan Dosen <ddosen@haproxy.com>
 *
 * Mod Defender
 * Copyright (c) 2017 Annihil (https://github.com/VultureProject/mod_defender)
 *
 * Parts of code based on Apache HTTP Server source
 * Copyright 2015 The Apache Software Foundation (http://www.apache.org/)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 3 of the License, or (at your option) any later version.
 *
 */
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>

#include <common/defaults.h>
#include <common/standard.h>
#include <common/chunk.h>
#include <common/time.h>

#include <proto/spoe.h>

#include <http_core.h>
#include <http_main.h>
#include <http_log.h>
#include <http_request.h>

#include <apr_pools.h>
#include <apr_strings.h>

#include "spoa.h"
#include "standalone.h"
#include "defender.h"

#define DEFENDER_NAME "defender"
#define DEFENDER_INPUT_FILTER "DEFENDER_IN"
#define DEFENDER_DEFAULT_UNIQUE_ID "unique_id"
#define DEFENDER_BRIGADE_REQUEST "defender-brigade-request"

extern module AP_MODULE_DECLARE_DATA defender_module;

DECLARE_HOOK(int,post_config,(apr_pool_t *pconf,apr_pool_t *plog, apr_pool_t *ptemp,server_rec *s))
DECLARE_HOOK(int,fixups,(request_rec *r))
DECLARE_HOOK(int,header_parser,(request_rec *r))

char *defender_name = DEFENDER_NAME;
const char *defender_argv[] = { DEFENDER_NAME, NULL };
const char *defender_unknown_hostname = "";

void *defender_module_config = NULL;
static server_rec *server = NULL;
apr_pool_t *defender_pool = NULL;

char hostname[MAX_HOSTNAME_LEN];
char defender_cwd[MAXPATHLEN];

static apr_status_t defender_bucket_read(apr_bucket *b, const char **str,
                                         apr_size_t *len, apr_read_type_e block);
static void defender_bucket_destroy(void *data);

static const apr_bucket_type_t apr_bucket_type_defender = {
	"defender", 8, APR_BUCKET_DATA,
	defender_bucket_destroy,
	defender_bucket_read,
	apr_bucket_setaside_noop,
	apr_bucket_shared_split,
	apr_bucket_shared_copy
};

struct apr_bucket_defender {
	apr_bucket_refcount refcount;
	struct buffer buf;
};

static apr_status_t defender_bucket_read(apr_bucket *b, const char **str,
                                         apr_size_t *len, apr_read_type_e block)
{
	struct apr_bucket_defender *d = b->data;

	*str = d->buf.area;
	*len = d->buf.data;

	return APR_SUCCESS;
}

static void defender_bucket_destroy(void *data)
{
	struct apr_bucket_defender *d = data;

	if (apr_bucket_shared_destroy(d))
		apr_bucket_free(d);
}

static apr_bucket *defender_bucket_make(apr_bucket *b,
					const struct buffer *buf)
{
	struct apr_bucket_defender *d;

	d = apr_bucket_alloc(sizeof(*d), b->list);

	d->buf.area = buf->area;
	d->buf.data = buf->data;
	d->buf.size = 0;

	b = apr_bucket_shared_make(b, d, 0, buf->data);
	b->type = &apr_bucket_type_defender;
	return b;
}

static apr_bucket *defender_bucket_create(const struct buffer *buf,
                                          apr_bucket_alloc_t *list)
{
	apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

	APR_BUCKET_INIT(b);
	b->free = apr_bucket_free;
	b->list = list;
	return defender_bucket_make(b, buf);
}

static void defender_logger(int level, char *str)
{
	LOG(&null_worker, "%s", str);
}

static char *defender_strdup(apr_pool_t *pool, const char *src, uint64_t len)
{
	char *dst;

	if (!(dst = apr_pcalloc(pool, len + 1)))
		return NULL;

	memcpy(dst, src, len);
	dst[len] = '\0';

	return dst;
}

static char *defender_printf(apr_pool_t *pool, const char *fmt, ...)
{
	va_list argp;
	char *dst;
	int len;

	va_start(argp, fmt);
	len = vsnprintf(NULL, 0, fmt, argp);
	va_end(argp);

	if (len < 0)
		return NULL;

	if (!(dst = apr_pcalloc(pool, len + 1)))
		return NULL;

	va_start(argp, fmt);
	len = vsnprintf(dst, len + 1, fmt, argp);
	va_end(argp);

	return dst;
}

static char *defender_addr2str(apr_pool_t *pool, struct sample *addr)
{
	sa_family_t family;
	const void *src;
	char *dst;

	switch (addr->data.type) {
	case SMP_T_IPV4:
		src = &addr->data.u.ipv4;
		family = AF_INET;
		break;
	case SMP_T_IPV6:
		src = &addr->data.u.ipv6;
		family = AF_INET6;
		break;
	default:
		return NULL;
	}

	if (!(dst = apr_pcalloc(pool, INET6_ADDRSTRLEN + 1)))
		return NULL;

	if (inet_ntop(family, src, dst, INET6_ADDRSTRLEN))
		return dst;

	return NULL;
}

static void defender_pre_config()
{
	apr_pool_t *ptemp = NULL;

	defender_module.module_index = 0;
	defender_module.register_hooks(defender_pool);

	apr_pool_create(&ptemp, defender_pool);
	run_ap_hook_post_config(defender_pool, defender_pool, ptemp, server);
	apr_pool_destroy(ptemp);
}

static const char *defender_read_config(const char *file)
{
	apr_pool_t *ptemp = NULL;
	const char *err;
	const char *fullname;

	defender_module_config = defender_module.create_dir_config(defender_pool, "/");
	if (defender_module_config == NULL) {
		return "cannot allocate space for the configuration structure";
	}

	apr_pool_create(&ptemp, defender_pool);

	fullname = ap_server_root_relative(ptemp, file);

	err = read_module_config(server, defender_module_config,
	                         defender_module.cmds,
	                         defender_pool, ptemp, fullname);

	apr_pool_destroy(ptemp);

    return err;
}

static void defender_post_config()
{
	apr_pool_t *ptemp = NULL;

	apr_pool_create(&ptemp, defender_pool);
	run_ap_hook_post_config(defender_pool, defender_pool, ptemp, server);
	apr_pool_destroy(ptemp);
}

static const char *defender_set_logger(const char *file)
{
	char *logname;

	logger = defender_logger;

	if (file == NULL)
		return NULL;

	logname = ap_server_root_relative(defender_pool, file);

	if (apr_file_open(&server->error_log, logname,
	                  APR_APPEND | APR_WRITE | APR_CREATE | APR_LARGEFILE,
	                  APR_OS_DEFAULT, defender_pool) != APR_SUCCESS) {
		return apr_pstrcat(defender_pool, "Cannot open log file, ",
		                   logname, NULL);
	}
	server->error_fname = logname;

	return NULL;
}

static apr_status_t defender_input_filter(ap_filter_t *f,
                                          apr_bucket_brigade *new_bb,
                                          ap_input_mode_t mode,
                                          apr_read_type_e block,
                                          apr_off_t readbytes)
{
	apr_bucket_brigade *bb = NULL;
	apr_bucket *b = NULL, *a = NULL;
	apr_status_t rv;

	bb = (apr_bucket_brigade *)apr_table_get(f->r->notes, DEFENDER_BRIGADE_REQUEST);

	if (bb == NULL || (bb && !APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb)))) {
		b = apr_bucket_eos_create(f->c->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(new_bb, b);
		if (bb == NULL)
			return APR_SUCCESS;
	}

	rv = apr_brigade_partition(bb, readbytes, &a);
	if (rv != APR_SUCCESS && rv != APR_INCOMPLETE)
		return rv;

	b = APR_BRIGADE_FIRST(bb);

	while (b != a) {
		if (APR_BUCKET_IS_EOS(b))
			ap_remove_input_filter(f);

		APR_BUCKET_REMOVE(b);
		APR_BRIGADE_INSERT_TAIL(new_bb, b);
		b = APR_BRIGADE_FIRST(bb);
	}

	return APR_SUCCESS;
}

static conn_rec *defender_create_conn()
{
	conn_rec *c = NULL;
	apr_pool_t *ptrans = NULL;

	apr_pool_create(&ptrans, defender_pool);

	c = apr_pcalloc(ptrans, sizeof(conn_rec));

	c->pool = ptrans;
	c->local_ip = "127.0.0.1";
	c->local_addr = server->addrs->host_addr;
	c->local_host = defender_name;
	c->client_addr = server->addrs->host_addr;
	c->remote_host = defender_name;

	c->id = 1;
	c->base_server = server;
	c->bucket_alloc = apr_bucket_alloc_create(ptrans);

	return c;
}

static request_rec *defender_create_request(conn_rec *conn)
{
	request_rec *r = NULL;
	apr_pool_t *p = NULL;
	struct ap_logconf *l;

	apr_pool_create(&p, conn->pool);

	r = apr_pcalloc(p, sizeof(request_rec));

	r->pool = p;
	r->connection = conn;
	r->server = conn->base_server;

	r->headers_in = apr_table_make(p, 25);
	r->headers_out = apr_table_make(p, 12);
	r->subprocess_env = apr_table_make(p, 25);
	r->err_headers_out = apr_table_make(p, 5);
	r->notes = apr_table_make(p, 5);

	r->request_config = apr_palloc(p, sizeof(void *));
	r->per_dir_config = apr_palloc(p, sizeof(void *));
	((void **)r->per_dir_config)[0] = defender_module_config;

	r->handler = defender_name;

	r->parsed_uri.scheme = "http";
	r->parsed_uri.is_initialized = 1;
	r->parsed_uri.port = 80;
	r->parsed_uri.port_str = "80";
	r->parsed_uri.fragment = "";

	r->input_filters = NULL;
	r->output_filters = NULL;

	l = apr_pcalloc(p, sizeof(struct ap_logconf));
	l->level = APLOG_DEBUG;
	r->log = l;

	return r;
}

static int defender_process_headers(request_rec *r)
{
	return run_ap_hook_header_parser(r);
}

static int defender_process_body(request_rec *r)
{
	ap_add_input_filter(DEFENDER_INPUT_FILTER, NULL, r, r->connection);
	return run_ap_hook_fixups(r);
}

int defender_init(const char *config_file, const char *log_file)
{
	apr_status_t rv;
	const char *msg;

	if (!config_file) {
		LOG(&null_worker, "Mod Defender configuration file not specified.\n");
		return 0;
	}

	apr_initialize();
	apr_pool_create(&defender_pool, NULL);
	apr_hook_global_pool = defender_pool;

	ap_server_root = getcwd(defender_cwd, APR_PATH_MAX);

	server = (server_rec *) apr_palloc(defender_pool, sizeof(server_rec));
	server->process = apr_palloc(defender_pool, sizeof(process_rec));
	server->process->argc = 1;
	server->process->argv = defender_argv;
	server->process->short_name = defender_name;
	server->process->pconf = defender_pool;
	server->process->pool = defender_pool;

	server->addrs = apr_palloc(defender_pool, sizeof(server_addr_rec));
	rv = apr_sockaddr_info_get(&server->addrs->host_addr,
	                           "127.0.0.1", APR_UNSPEC, 0, 0,
	                           defender_pool);
	if (rv != APR_SUCCESS) {
		LOG(&null_worker, "Mod Defender getaddrinfo failed.\n");
		return 0;
	}

	server->path = "/";
	server->pathlen = strlen(server->path);
	server->port = 0;
	server->server_admin = defender_name;
	server->server_scheme = "";
	server->error_fname = NULL;
	server->error_log = NULL;
	server->limit_req_line = DEFAULT_LIMIT_REQUEST_LINE;
	server->limit_req_fieldsize = DEFAULT_LIMIT_REQUEST_FIELDSIZE;
	server->limit_req_fields = DEFAULT_LIMIT_REQUEST_FIELDS;
	server->timeout = apr_time_from_sec(DEFAULT_TIMEOUT);

	memset(hostname, 0, sizeof(hostname));
	gethostname(hostname, sizeof(hostname) - 1);
	server->server_hostname = hostname;

	server->addrs->host_port = 0;
	server->names = server->wild_names = NULL;
	server->is_virtual = 0;

	server->lookup_defaults = NULL;
	server->module_config = NULL;

	msg = defender_set_logger(log_file);
	if (msg != NULL) {
		LOG(&null_worker, "Mod Defender init failed: %s\n", msg);
		return 0;
	}

	ap_register_input_filter(DEFENDER_INPUT_FILTER, defender_input_filter,
	                         NULL, AP_FTYPE_RESOURCE);

	defender_pre_config();

	msg = defender_read_config(config_file);
	if (msg != NULL) {
		LOG(&null_worker, "Mod Defender configuration failed: %s\n", msg);
		return 0;
	}

	defender_post_config();

	return 1;
}

int defender_process_request(struct worker *worker, struct defender_request *request)
{
	struct conn_rec *c = NULL;
	struct request_rec *r = NULL;

	struct apr_bucket_brigade *bb = NULL;
	struct apr_bucket *d = NULL, *e = NULL;

	struct buffer *method;
	struct buffer *path;
	struct buffer *query;
	struct buffer *version;
	struct buffer *body;

	struct defender_header hdr;
	char *hdr_ptr, *hdr_end;

	const char *ptr;

	int status = DECLINED;

	if (!(c = defender_create_conn()))
		goto out;

	if (!(r = defender_create_request(c)))
		goto out;

	/* request */
	r->request_time = apr_time_now();

	if (request->clientip.data.type != SMP_T_IPV4 &&
	    request->clientip.data.type != SMP_T_IPV6)
		goto out;

	if (!(r->useragent_ip = defender_addr2str(r->pool, &request->clientip)))
		goto out;

	if (request->id.data.u.str.area && request->id.data.u.str.data > 0) {
		apr_table_setn(r->subprocess_env, "UNIQUE_ID",
		               defender_strdup(r->pool, request->id.data.u.str.area,
		                               request->id.data.u.str.data));
	}
	else {
		apr_table_setn(r->subprocess_env, "UNIQUE_ID",
		               DEFENDER_DEFAULT_UNIQUE_ID);
	}

	method = &request->method.data.u.str;
	path = &request->path.data.u.str;
	query = &request->query.data.u.str;
	version = &request->version.data.u.str;

	r->method_number = lookup_builtin_method(method->area, method->data);
	if (!(r->method = defender_strdup(r->pool, method->area, method->data)))
		goto out;

	r->unparsed_uri = defender_printf(r->pool, "%.*s%s%.*s",
	                                  path->data, path->area,
	                                  query->data > 0 ? "?" : "",
	                                  query->data, query->area);
	if (!r->unparsed_uri)
		goto out;

	if (!(r->uri = defender_strdup(r->pool, path->area, path->data)))
		goto out;

	r->parsed_uri.path = r->filename = r->uri;

	if (!(r->args = defender_strdup(r->pool, query->area, query->data)))
		goto out;

	r->parsed_uri.query = r->args;

	r->protocol = defender_printf(r->pool, "%s%.*s",
	                              version->data > 0 ? "HTTP/" : "",
	                              version->data, version->area);
	if (!r->protocol)
		goto out;

	r->the_request = defender_printf(r->pool, "%.*s %s%s%s",
	                                 method->data, method->area,
	                                 r->unparsed_uri,
	                                 version->data > 0 ? " " : "",
	                                 r->protocol);
	if (!r->the_request)
		goto out;

	/* headers */
	if (request->headers.data.type != SMP_T_BIN)
		goto misc;

	hdr_ptr = request->headers.data.u.str.area;
	hdr_end = hdr_ptr + request->headers.data.u.str.data;

	while (1) {
		memset(&hdr, 0, sizeof(hdr));

		if (decode_varint(&hdr_ptr, hdr_end, &hdr.name.len) == -1)
			goto out;
		if (!(hdr.name.str = defender_strdup(r->pool, hdr_ptr, hdr.name.len)))
			goto out;

		hdr_ptr += hdr.name.len;
		if (hdr_ptr > hdr_end)
			goto out;

		if (decode_varint(&hdr_ptr, hdr_end, &hdr.value.len) == -1)
			goto out;
		if (!(hdr.value.str = defender_strdup(r->pool, hdr_ptr, hdr.value.len)))
			goto out;

		hdr_ptr += hdr.value.len;
		if (hdr_ptr > hdr_end)
			goto out;

		if (!hdr.name.len && !hdr.value.len)
			break;

		apr_table_setn(r->headers_in, hdr.name.str, hdr.value.str);
	}

misc:

	r->hostname = apr_table_get(r->headers_in, "Host");
	if (!r->hostname)
		r->hostname = defender_unknown_hostname;
	r->parsed_uri.hostname = (char *)r->hostname;

	r->content_type = apr_table_get(r->headers_in, "Content-Type");
	r->content_encoding = apr_table_get(r->headers_in, "Content-Encoding");
	ptr = apr_table_get(r->headers_in, "Content-Length");
	if (ptr)
		r->clength = strtol(ptr, NULL, 10);

	/* body */
	body = &request->body.data.u.str;

	bb = apr_brigade_create(r->pool, c->bucket_alloc);
	if (bb == NULL)
		goto out;

	d = defender_bucket_create(body, c->bucket_alloc);
	if (d == NULL)
		goto out;

	APR_BRIGADE_INSERT_TAIL(bb, d);

	e = apr_bucket_eos_create(c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, e);

	apr_table_setn(r->notes, DEFENDER_BRIGADE_REQUEST, (char *)bb);

	/* process */
	status = defender_process_headers(r);

	if (status == DECLINED)
		status = defender_process_body(r);

	apr_brigade_cleanup(bb);

	/* success */
	if (status == DECLINED)
		status = OK;

out:

	if (r && r->pool) {
		apr_table_clear(r->headers_in);
		apr_table_clear(r->headers_out);
		apr_table_clear(r->subprocess_env);
		apr_table_clear(r->err_headers_out);
		apr_table_clear(r->notes);
		apr_pool_destroy(r->pool);
	}

	if (c && c->pool) {
		apr_bucket_alloc_destroy(c->bucket_alloc);
		apr_pool_destroy(c->pool);
	}

	return status;
}
