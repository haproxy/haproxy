/*
 * Modsecurity wrapper for haproxy
 *
 * This file contains the wrapper which sends data in ModSecurity
 * and returns the verdict.
 *
 * Copyright 2016 OZON, Thierry Fournier <thierry.fournier@ozon.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>

#include <common/time.h>

#include <types/global.h>
#include <types/stream.h>

#include <proto/arg.h>
#include <proto/hdr_idx.h>
#include <proto/hlua.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/spoe.h>

#include <api.h>

#include "modsec_wrapper.h"
#include "spoa.h"

static char host_name[60];

/* Note: The document and the code of "apr_table_make" considers
 * that this function doesn't fails. The Apache APR code says
 * other thing. If the system doesn't have any more memory, a
 * a segfault occurs :(. Be carrefull with this module.
 */

struct directory_config *modsec_config = NULL;
static server_rec *modsec_server = NULL;

struct apr_bucket_haproxy {
	apr_bucket_refcount refcount;
	char *buffer;
	size_t length;
};

static void haproxy_bucket_destroy(void *data)
{
	struct apr_bucket_haproxy *bucket = data;

	if (apr_bucket_shared_destroy(bucket))
		apr_bucket_free(bucket);
}

static apr_status_t haproxy_bucket_read(apr_bucket *bucket, const char **str,
                                        apr_size_t *len, apr_read_type_e block)
{
	struct apr_bucket_haproxy *data = bucket->data;

	if (bucket->start) {
		*str = NULL;
		*len = 0;
		return APR_SUCCESS;
	}

	*str = data->buffer;
	*len = data->length;
	bucket->start = 1; /* Just a flag to say that the read is started */

	return APR_SUCCESS;
}

static const apr_bucket_type_t apr_bucket_type_haproxy = {
	"HAProxy", 7, APR_BUCKET_DATA,
	haproxy_bucket_destroy,
	haproxy_bucket_read,
	apr_bucket_setaside_noop,
	apr_bucket_shared_split,
	apr_bucket_shared_copy
};

static char *chunk_strdup(struct request_rec *req, const char *str, size_t len)
{
	char *out;

	out = apr_pcalloc(req->pool, len + 1);
	if (!out)
		return NULL;
	memcpy(out, str, len);
	out[len] = '\0';
	return out;
}

static char *printf_dup(struct request_rec *req, char *fmt, ...)
{
	char *out;
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if (len == -1)
		return NULL;

	out = apr_pcalloc(req->pool, len + 1);
	if (!out)
		return NULL;

	va_start(ap, fmt);
	len = vsnprintf(out, len + 1, fmt, ap);
	va_end(ap);

	if (len == -1)
		return NULL;

	return out;
}

/* This function send logs. For now, it do nothing. */
static void modsec_log(void *obj, int level, char *str)
{
	LOG(&null_worker, "%s", str);
}

/* This fucntion load the ModSecurity file. It returns -1 if the
 * initialisation fails.
 */
int modsecurity_load(const char *file)
{
	const char *msg;
	char cwd[128];

	/* Initialises modsecurity. */

	modsec_server = modsecInit();
	if (modsec_server == NULL) {
		LOG(&null_worker, "ModSecurity initilisation failed.\n");
		return -1;
	}

	modsecSetLogHook(NULL, modsec_log);

	gethostname(host_name, 60);
	modsec_server->server_hostname = host_name;

	modsecStartConfig();

	modsec_config = modsecGetDefaultConfig();
	if (modsec_config == NULL) {
		LOG(&null_worker, "ModSecurity default configuration initilisation failed.\n");
		return -1;
	}

	msg = modsecProcessConfig(modsec_config, file, getcwd(cwd, 128));
	if (msg != NULL) {
		LOG(&null_worker, "ModSecurity load configuration failed.\n");
		return -1;
	}

	modsecFinalizeConfig();

	modsecInitProcess();

	return 1;
}

struct modsec_hdr {
	const char *name;
	uint64_t name_len;
	const char *value;
	uint64_t value_len;
};

int modsecurity_process(struct worker *worker, struct modsecurity_parameters *params)
{
	struct conn_rec *cr;
	struct request_rec *req;
	struct apr_bucket_brigade *brigade;
	struct apr_bucket *link_bucket;
	struct apr_bucket_haproxy *data_bucket;
	struct apr_bucket *last_bucket;
	int i;
	long clength;
	char *err;
	int fail;
	const char *lang;
	char *name, *value;
	// int body_partial;
	struct timeval now;
	int ret;
	char *buf;
	char *end;
	const char *uniqueid;
	uint64_t uniqueid_len;
	const char *meth;
	uint64_t meth_len;
	const char *path;
	uint64_t path_len;
	const char *qs;
	uint64_t qs_len;
	const char *vers;
	uint64_t vers_len;
	const char *body;
	uint64_t body_len;
	uint64_t body_exposed_len;
	uint64_t hdr_nb;
	struct modsec_hdr hdrs[255];
	struct modsec_hdr hdr;
	int status;
	int return_code = -1;

	/* Decode uniqueid. */
	uniqueid = params->uniqueid.data.u.str.str;
	uniqueid_len = params->uniqueid.data.u.str.len;

	/* Decode method. */
	meth = params->method.data.u.str.str;
	meth_len = params->method.data.u.str.len;

	/* Decode path. */
	path = params->path.data.u.str.str;
	path_len = params->path.data.u.str.len;

	/* Decode query string. */
	qs = params->query.data.u.str.str;
	qs_len = params->query.data.u.str.len;

	/* Decode version. */
	vers = params->vers.data.u.str.str;
	vers_len = params->vers.data.u.str.len;

	/* Decode header binary block. */
	buf = params->hdrs_bin.data.u.str.str;
	end = buf + params->hdrs_bin.data.u.str.len;

	/* Decode each header. */
	hdr_nb = 0;
	while (1) {

		/* Initialise the storage struct. It is useless
		 * because the process fail if the struct is not
		 * fully filled. This init is just does in order
		 * to prevent bug after some improvements.
		 */
		memset(&hdr, 0, sizeof(hdr));

		/* Decode header name. */
		ret = decode_varint(&buf, end, &hdr.name_len);
		if (ret == -1)
			return -1;
		hdr.name = buf;
		buf += hdr.name_len;
		if (buf > end)
			return -1;

		/* Decode header value. */
		ret = decode_varint(&buf, end, &hdr.value_len);
		if (ret == -1)
			return -1;
		hdr.value = buf;
		buf += hdr.value_len;
		if (buf > end)
			return -1;

		/* Detect the end of the headers. */
		if (hdr.name_len == 0 && hdr.value_len == 0)
			break;

		/* Store the header. */
		if (hdr_nb < 255) {
			memcpy(&hdrs[hdr_nb], &hdr, sizeof(hdr));
			hdr_nb++;
		}
	}

	/* Decode body length. Note that the following control
	 * is just set for avoifing a gcc warning.
	 */
	body_exposed_len = (uint64_t)params->body_length.data.u.sint;
	if (body_exposed_len < 0)
		return -1;

	/* Decode body. */
	body = params->body.data.u.str.str;
	body_len = params->body.data.u.str.len;

	fail = 1;

	/* Init processing */

	cr = modsecNewConnection();
	req = modsecNewRequest(cr, modsec_config);

	/* Load request. */

	req->proxyreq = PROXYREQ_NONE;
	req->header_only = 0; /* May modified later */

	/* Copy header list. */

	for (i = 0; i < hdr_nb; i++) {
		name = chunk_strdup(req, hdrs[i].name, hdrs[i].name_len);
		if (!name) {
			errno = ENOMEM;
			goto fail;
		}
		value = chunk_strdup(req, hdrs[i].value, hdrs[i].value_len);
		if (!value) {
			errno = ENOMEM;
			goto fail;
		}
		apr_table_setn(req->headers_in, name, value);
	}

	/* Process special headers. */
	req->range = apr_table_get(req->headers_in, "Range");
	req->content_type = apr_table_get(req->headers_in, "Content-Type");
	req->content_encoding = apr_table_get(req->headers_in, "Content-Encoding");
	req->hostname = apr_table_get(req->headers_in, "Host");
	req->parsed_uri.hostname = chunk_strdup(req, req->hostname, strlen(req->hostname));

	lang = apr_table_get(req->headers_in, "Content-Languages");
	if (lang != NULL) {
		req->content_languages = apr_array_make(req->pool, 1, sizeof(const char *));
		*(const char **)apr_array_push(req->content_languages) = lang;
	}

	lang = apr_table_get(req->headers_in, "Content-Length");
	if (lang) {
		errno = 0;
		clength = strtol(lang, &err, 10);
		if (*err != '\0' || errno != 0 || clength < 0 || clength > INT_MAX) {
			errno = ERANGE;
			goto fail;
		}
		req->clength = clength;
	}

	/* Copy the first line of the request. */
	req->the_request = printf_dup(req, "%.*s %.*s%s%.*s %.*s",
	                              meth_len, meth,
	                              path_len, path,
	                              qs_len > 0 ? "?" : "",
	                              qs_len, qs,
	                              vers_len, vers);
	if (!req->the_request) {
		errno = ENOMEM;
		goto fail;
	}

	/* Copy the method. */
	req->method = chunk_strdup(req, meth, meth_len);
	if (!req->method) {
		errno = ENOMEM;
		goto fail;
	}

	/* Set the method number. */
	if (meth_len < 3) {
		errno = EINVAL;
		goto fail;
	}

	/* Detect the method */
	switch (meth_len) {
	case 3:
		if (strncmp(req->method, "GET", 3) == 0)
			req->method_number = M_GET;
		else if (strncmp(req->method, "PUT", 3) == 0)
			req->method_number = M_PUT;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 4:
		if (strncmp(req->method, "POST", 4) == 0)
			req->method_number = M_POST;
		else if (strncmp(req->method, "HEAD", 4) == 0) {
			req->method_number = M_GET;
			req->header_only = 1;
		}
		else if (strncmp(req->method, "COPY", 4) == 0)
			req->method_number = M_COPY;
		else if (strncmp(req->method, "MOVE", 4) == 0)
			req->method_number = M_MOVE;
		else if (strncmp(req->method, "LOCK", 4) == 0)
			req->method_number = M_LOCK;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 5:
		if (strncmp(req->method, "TRACE", 5) == 0)
			req->method_number = M_TRACE;
		else if (strncmp(req->method, "PATCH", 5) == 0)
			req->method_number = M_PATCH;
		else if (strncmp(req->method, "MKCOL", 5) == 0)
			req->method_number = M_MKCOL;
		else if (strncmp(req->method, "MERGE", 5) == 0)
			req->method_number = M_MERGE;
		else if (strncmp(req->method, "LABEL", 5) == 0)
			req->method_number = M_LABEL;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 6:
		if (strncmp(req->method, "DELETE", 6) == 0)
			req->method_number = M_DELETE;
		else if (strncmp(req->method, "REPORT", 6) == 0)
			req->method_number = M_REPORT;
		else if (strncmp(req->method, "UPDATE", 6) == 0)
			req->method_number = M_UPDATE;
		else if (strncmp(req->method, "UNLOCK", 6) == 0)
			req->method_number = M_UNLOCK;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 7:
		if (strncmp(req->method, "CHECKIN", 7) == 0)
			req->method_number = M_CHECKIN;
		else if (strncmp(req->method, "INVALID", 7) == 0)
			req->method_number = M_INVALID;
		else if (strncmp(req->method, "CONNECT", 7) == 0)
			req->method_number = M_CONNECT;
		else if (strncmp(req->method, "OPTIONS", 7) == 0)
			req->method_number = M_OPTIONS;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 8:
		if (strncmp(req->method, "PROPFIND", 8) == 0)
			req->method_number = M_PROPFIND;
		else if (strncmp(req->method, "CHECKOUT", 8) == 0)
			req->method_number = M_CHECKOUT;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 9:
		if (strncmp(req->method, "PROPPATCH", 9) == 0)
			req->method_number = M_PROPPATCH;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 10:
		if (strncmp(req->method, "MKACTIVITY", 10) == 0)
			req->method_number = M_MKACTIVITY;
		else if (strncmp(req->method, "UNCHECKOUT", 10) == 0)
			req->method_number = M_UNCHECKOUT;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 11:
		if (strncmp(req->method, "MKWORKSPACE", 11) == 0)
			req->method_number = M_MKWORKSPACE;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 15:
		if (strncmp(req->method, "VERSION_CONTROL", 15) == 0)
			req->method_number = M_VERSION_CONTROL;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	case 16:
		if (strncmp(req->method, "BASELINE_CONTROL", 16) == 0)
			req->method_number = M_BASELINE_CONTROL;
		else {
			errno = EINVAL;
			goto fail;
		}
		break;
	default:
		errno = EINVAL;
		goto fail;
	}

	/* Copy the protocol. */
	req->protocol = chunk_strdup(req, vers, vers_len);
	if (!req->protocol) {
		errno = ENOMEM;
		goto fail;
	}

	/* Compute the protocol number. */
	if (vers_len >= 8)
		req->proto_num = 1000 + !!(vers[7] == '1');

	/* The request time. */
	gettimeofday(&now, NULL);
	req->request_time = apr_time_make(now.tv_sec, now.tv_usec / 1000);

	/* No status line. */
	req->status_line = NULL;
	req->status = 0;

	/* Copy path. */
	req->parsed_uri.path = chunk_strdup(req, path, path_len);
	if (!req->parsed_uri.path) {
		errno = ENOMEM;
		goto fail;
	}

	/* Copy args (query string). */
	req->args = chunk_strdup(req, qs, qs_len);
	if (!req->args) {
		errno = ENOMEM;
		goto fail;
	}

	/* Set parsed_uri */

	req->parsed_uri.scheme = "http";

	if (req->hostname && req->parsed_uri.scheme && req->parsed_uri.path) {
		i = snprintf(NULL, 0, "%s://%s%s",
		             req->parsed_uri.scheme, req->hostname, req->parsed_uri.path);
		req->uri = apr_pcalloc(req->pool, i + 1);
		if (!req->uri) {
			errno = ENOMEM;
			goto fail;
		}
		i = snprintf(req->uri, i + 1, "%s://%s%s",
		             req->parsed_uri.scheme, req->hostname, req->parsed_uri.path);
	}

	req->filename = req->parsed_uri.path;

	/* Set unique id */

	apr_table_setn(req->subprocess_env, "UNIQUE_ID", chunk_strdup(req, uniqueid, uniqueid_len));

	/*
	 *
	 * Load body.
	 *
	 */

	/* Create an empty bucket brigade */
	brigade = apr_brigade_create(req->pool, req->connection->bucket_alloc);
	if (!brigade) {
		errno = ENOMEM;
		goto fail;
	}

	/* Stores HTTP body avalaible data in a bucket */
	data_bucket = apr_bucket_alloc(sizeof(*data_bucket), req->connection->bucket_alloc);
	if (!data_bucket) {
		errno = ENOMEM;
		goto fail;
	}
	data_bucket->buffer = (char *)body;
	data_bucket->length = body_len;

	/* Create linked bucket */
	link_bucket = apr_bucket_alloc(sizeof(*link_bucket), req->connection->bucket_alloc);
	if (!link_bucket) {
		errno = ENOMEM;
		goto fail;
	}
	APR_BUCKET_INIT(link_bucket); /* link */
	link_bucket->free = apr_bucket_free;
	link_bucket->list = req->connection->bucket_alloc;
	link_bucket = apr_bucket_shared_make(link_bucket, data_bucket, 0, body_len);
	link_bucket->type = &apr_bucket_type_haproxy;

	/* Insert the bucket at the end of the brigade. */
	APR_BRIGADE_INSERT_TAIL(brigade, link_bucket);

	/* Insert the last bucket. */
	last_bucket = apr_bucket_eos_create(req->connection->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(brigade, last_bucket);

	/* Declares the bucket brigade in modsecurity */
	modsecSetBodyBrigade(req, brigade);

	/*
	 *
	 * Process analysis.
	 *
	 */

	/* Process request headers analysis. */
	status = modsecProcessRequestHeaders(req);
	if (status != DECLINED && status != DONE)
		return_code = status;

	/* Process request body analysis. */
	status = modsecProcessRequestBody(req);
	if (status != DECLINED && status != DONE)
		return_code = status;

	/* End processing. */

	fail = 0;
	if (return_code == -1)
		return_code = 0;

fail:

	modsecFinishRequest(req);
	modsecFinishConnection(cr);

	if (fail) {

		/* errno == ERANGE / ENOMEM / EINVAL */
		switch (errno) {
		case ERANGE: LOG(worker, "Invalid range");
		case ENOMEM: LOG(worker, "Out of memory error");
		case EINVAL: LOG(worker, "Invalid value");
		default:     LOG(worker, "Unknown error");
		}
	}

	return return_code;
}
