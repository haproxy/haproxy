/*
 * Mod Defender for HAProxy
 *
 * Support for the Mod Defender code on non-Apache platforms.
 *
 * Copyright 2017 HAProxy Technologies, Dragan Dosen <ddosen@haproxy.com>
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

#include <http_core.h>
#include <http_main.h>
#include <http_log.h>

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_fnmatch.h>

#include "standalone.h"

#define MAX_ARGC 64
#define MAX_INCLUDE_DIR_DEPTH 128

#define SLASHES "/"

#define FILTER_POOL apr_hook_global_pool
#define TRIE_INITIAL_SIZE 4

typedef struct filter_trie_node filter_trie_node;

typedef struct {
	int c;
	filter_trie_node *child;
} filter_trie_child_ptr;

struct filter_trie_node {
	ap_filter_rec_t *frec;
	filter_trie_child_ptr *children;
	int nchildren;
	int size;
};

typedef struct {
	const char *fname;
} fnames;

AP_DECLARE_DATA const char *ap_server_root = "/";

void (*logger)(int level, char *str) = NULL;

static void str_tolower(char *str)
{
	while (*str) {
		*str = apr_tolower(*str);
		++str;
	}
}

static char x2c(const char *what)
{
	char digit;

#if !APR_CHARSET_EBCDIC
	digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10
	        : (what[0] - '0'));
	digit *= 16;
	digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10
	         : (what[1] - '0'));
#else /*APR_CHARSET_EBCDIC*/
	char xstr[5];
	xstr[0]='0';
	xstr[1]='x';
	xstr[2]=what[0];
	xstr[3]=what[1];
	xstr[4]='\0';
	digit = apr_xlate_conv_byte(ap_hdrs_from_ascii,
	                            0xFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
	return (digit);
}

static int unescape_url(char *url, const char *forbid, const char *reserved)
{
	int badesc, badpath;
	char *x, *y;

	badesc = 0;
	badpath = 0;
	/* Initial scan for first '%'. Don't bother writing values before
	 * seeing a '%' */
	y = strchr(url, '%');
	if (y == NULL) {
		return OK;
	}
	for (x = y; *y; ++x, ++y) {
		if (*y != '%') {
			*x = *y;
		}
		else {
			if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
				badesc = 1;
				*x = '%';
			}
			else {
				char decoded;
				decoded = x2c(y + 1);
				if ((decoded == '\0')
				    || (forbid && ap_strchr_c(forbid, decoded))) {
					badpath = 1;
					*x = decoded;
					y += 2;
				}
				else if (reserved && ap_strchr_c(reserved, decoded)) {
					*x++ = *y++;
					*x++ = *y++;
					*x = *y;
				}
				else {
					*x = decoded;
					y += 2;
				}
			}
		}
	}
	*x = '\0';
	if (badesc) {
		return HTTP_BAD_REQUEST;
	}
	else if (badpath) {
		return HTTP_NOT_FOUND;
	}
	else {
		return OK;
	}
}

AP_DECLARE(int) ap_unescape_url(char *url)
{
	/* Traditional */
	return unescape_url(url, SLASHES, NULL);
}

AP_DECLARE(void) ap_get_server_revision(ap_version_t *version)
{
	version->major = AP_SERVER_MAJORVERSION_NUMBER;
	version->minor = AP_SERVER_MINORVERSION_NUMBER;
	version->patch = AP_SERVER_PATCHLEVEL_NUMBER;
	version->add_string = AP_SERVER_ADD_STRING;
}

static void log_error_core(const char *file, int line, int module_index,
                           int level,
                           apr_status_t status, const server_rec *s,
                           const conn_rec *c,
                           const request_rec *r, apr_pool_t *pool,
                           const char *fmt, va_list args)
{
	char errstr[MAX_STRING_LEN];

	apr_vsnprintf(errstr, MAX_STRING_LEN, fmt, args);

	if (logger != NULL)
		logger(level, errstr);
}

AP_DECLARE(void) ap_log_error_(const char *file, int line, int module_index,
                               int level, apr_status_t status,
                               const server_rec *s, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_error_core(file, line, module_index, level, status, s, NULL, NULL,
	               NULL, fmt, args);
	va_end(args);
}

AP_DECLARE(void) ap_log_rerror_(const char *file, int line, int module_index,
                                int level, apr_status_t status,
                                const request_rec *r, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_error_core(file, line, module_index, level, status, r->server, NULL, r,
	               NULL, fmt, args);
	va_end(args);
}

AP_DECLARE(void) ap_log_cerror_(const char *file, int line, int module_index,
                                int level, apr_status_t status,
                                const conn_rec *c, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_error_core(file, line, module_index, level, status, c->base_server, c,
	               NULL, NULL, fmt, args);
	va_end(args);
}

AP_DECLARE(piped_log *) ap_open_piped_log(apr_pool_t *p, const char *program)
{
	return NULL;
}

AP_DECLARE(apr_file_t *) ap_piped_log_write_fd(piped_log *pl)
{
	return NULL;
}

static cmd_parms default_parms =
{NULL, 0, 0, NULL, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

AP_DECLARE(char *) ap_server_root_relative(apr_pool_t *p, const char *file)
{
	char *newpath = NULL;
	apr_status_t rv;
	rv = apr_filepath_merge(&newpath, ap_server_root, file,
	                        APR_FILEPATH_TRUENAME, p);
	if (newpath && (rv == APR_SUCCESS || APR_STATUS_IS_EPATHWILD(rv)
	                                  || APR_STATUS_IS_ENOENT(rv)
	                                  || APR_STATUS_IS_ENOTDIR(rv))) {
		return newpath;
	}
	else {
		return NULL;
	}
}

AP_DECLARE(apr_status_t) ap_get_brigade(ap_filter_t *next,
                                        apr_bucket_brigade *bb,
                                        ap_input_mode_t mode,
                                        apr_read_type_e block,
                                        apr_off_t readbytes)
{
	if (next) {
		return next->frec->filter_func.in_func(next, bb, mode, block,
		                                       readbytes);
	}
	return AP_NOBODY_READ;
}

static void
argstr_to_table(char *str, apr_table_t *parms)
{
	char *key;
	char *value;
	char *strtok_state;

	if (str == NULL) {
		return;
	}

	key = apr_strtok(str, "&", &strtok_state);
	while (key) {
		value = strchr(key, '=');
		if (value) {
			*value = '\0';      /* Split the string in two */
			value++;            /* Skip passed the = */
		}
		else {
			value = "1";
		}
		ap_unescape_url(key);
		ap_unescape_url(value);
		apr_table_set(parms, key, value);
		key = apr_strtok(NULL, "&", &strtok_state);
	}
}

AP_DECLARE(void) ap_args_to_table(request_rec *r, apr_table_t **table)
{
	apr_table_t *t = apr_table_make(r->pool, 10);
	argstr_to_table(apr_pstrdup(r->pool, r->args), t);
	*table = t;
}

/* Link a trie node to its parent
 */
static void trie_node_link(apr_pool_t *p, filter_trie_node *parent,
                           filter_trie_node *child, int c)
{
	int i, j;

	if (parent->nchildren == parent->size) {
		filter_trie_child_ptr *new;
		parent->size *= 2;
		new = (filter_trie_child_ptr *)apr_palloc(p, parent->size *
		                                          sizeof(filter_trie_child_ptr));
		memcpy(new, parent->children, parent->nchildren *
		       sizeof(filter_trie_child_ptr));
		parent->children = new;
	}

	for (i = 0; i < parent->nchildren; i++) {
		if (c == parent->children[i].c) {
			return;
		}
		else if (c < parent->children[i].c) {
			break;
		}
	}
	for (j = parent->nchildren; j > i; j--) {
		parent->children[j].c = parent->children[j - 1].c;
		parent->children[j].child = parent->children[j - 1].child;
	}
	parent->children[i].c = c;
	parent->children[i].child = child;

	parent->nchildren++;
}

/* Allocate a new node for a trie.
 * If parent is non-NULL, link the new node under the parent node with
 * key 'c' (or, if an existing child node matches, return that one)
 */
static filter_trie_node *trie_node_alloc(apr_pool_t *p,
                                         filter_trie_node *parent, char c)
{
	filter_trie_node *new_node;
	if (parent) {
		int i;
		for (i = 0; i < parent->nchildren; i++) {
			if (c == parent->children[i].c) {
				return parent->children[i].child;
			}
			else if (c < parent->children[i].c) {
				break;
			}
		}
		new_node = (filter_trie_node *)apr_palloc(p, sizeof(filter_trie_node));
		trie_node_link(p, parent, new_node, c);
	}
	else { /* No parent node */
		new_node = (filter_trie_node *)apr_palloc(p,
		           sizeof(filter_trie_node));
	}

	new_node->frec = NULL;
	new_node->nchildren = 0;
	new_node->size = TRIE_INITIAL_SIZE;
	new_node->children = (filter_trie_child_ptr *)apr_palloc(p,
	                     new_node->size * sizeof(filter_trie_child_ptr));
	return new_node;
}

static filter_trie_node *registered_output_filters = NULL;
static filter_trie_node *registered_input_filters = NULL;


static apr_status_t filter_cleanup(void *ctx)
{
	registered_output_filters = NULL;
	registered_input_filters = NULL;
	return APR_SUCCESS;
}

static ap_filter_rec_t *register_filter(const char *name,
                                        ap_filter_func filter_func,
                                        ap_init_filter_func filter_init,
                                        ap_filter_type ftype,
                                        filter_trie_node **reg_filter_set)
{
	ap_filter_rec_t *frec;
	char *normalized_name;
	const char *n;
	filter_trie_node *node;

	if (!*reg_filter_set) {
		*reg_filter_set = trie_node_alloc(FILTER_POOL, NULL, 0);
	}

	normalized_name = apr_pstrdup(FILTER_POOL, name);
	str_tolower(normalized_name);

	node = *reg_filter_set;
	for (n = normalized_name; *n; n++) {
		filter_trie_node *child = trie_node_alloc(FILTER_POOL, node, *n);
		if (apr_isalpha(*n)) {
			trie_node_link(FILTER_POOL, node, child, apr_toupper(*n));
		}
		node = child;
	}
	if (node->frec) {
		frec = node->frec;
	}
	else {
		frec = apr_pcalloc(FILTER_POOL, sizeof(*frec));
		node->frec = frec;
		frec->name = normalized_name;
	}
	frec->filter_func = filter_func;
	frec->filter_init_func = filter_init;
	frec->ftype = ftype;

	apr_pool_cleanup_register(FILTER_POOL, NULL, filter_cleanup,
	                          apr_pool_cleanup_null);
	return frec;
}

AP_DECLARE(ap_filter_rec_t *) ap_register_input_filter(const char *name,
                                                       ap_in_filter_func filter_func,
                                                       ap_init_filter_func filter_init,
                                                       ap_filter_type ftype)
{
	ap_filter_func f;
	f.in_func = filter_func;
	return register_filter(name, f, filter_init, ftype,
	                       &registered_input_filters);
}

static ap_filter_t *add_any_filter_handle(ap_filter_rec_t *frec, void *ctx,
                                          request_rec *r, conn_rec *c,
                                          ap_filter_t **r_filters,
                                          ap_filter_t **p_filters,
                                          ap_filter_t **c_filters)
{
	apr_pool_t *p = frec->ftype < AP_FTYPE_CONNECTION && r ? r->pool : c->pool;
	ap_filter_t *f = apr_palloc(p, sizeof(*f));
	ap_filter_t **outf;

	if (frec->ftype < AP_FTYPE_PROTOCOL) {
		if (r) {
			outf = r_filters;
		}
		else {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(00080)
			              "a content filter was added without a request: %s", frec->name);
			return NULL;
		}
	}
	else if (frec->ftype < AP_FTYPE_CONNECTION) {
		if (r) {
			outf = p_filters;
		}
		else {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(00081)
			              "a protocol filter was added without a request: %s", frec->name);
			return NULL;
		}
	}
	else {
		outf = c_filters;
	}

	f->frec = frec;
	f->ctx = ctx;
	/* f->r must always be NULL for connection filters */
	f->r = frec->ftype < AP_FTYPE_CONNECTION ? r : NULL;
	f->c = c;
	f->next = NULL;

	if (INSERT_BEFORE(f, *outf)) {
		f->next = *outf;

		if (*outf) {
			ap_filter_t *first = NULL;

			if (r) {
				/* If we are adding our first non-connection filter,
				 * Then don't try to find the right location, it is
				 * automatically first.
				 */
				if (*r_filters != *c_filters) {
					first = *r_filters;
					while (first && (first->next != (*outf))) {
						first = first->next;
					}
				}
			}
			if (first && first != (*outf)) {
				first->next = f;
			}
		}
		*outf = f;
	}
	else {
		ap_filter_t *fscan = *outf;
		while (!INSERT_BEFORE(f, fscan->next))
			fscan = fscan->next;

		f->next = fscan->next;
		fscan->next = f;
	}

	if (frec->ftype < AP_FTYPE_CONNECTION && (*r_filters == *c_filters)) {
		*r_filters = *p_filters;
	}
	return f;
}

static ap_filter_t *add_any_filter(const char *name, void *ctx,
                                   request_rec *r, conn_rec *c,
                                   const filter_trie_node *reg_filter_set,
                                   ap_filter_t **r_filters,
                                   ap_filter_t **p_filters,
                                   ap_filter_t **c_filters)
{
	if (reg_filter_set) {
		const char *n;
		const filter_trie_node *node;

		node = reg_filter_set;
		for (n = name; *n; n++) {
			int start, end;
			start = 0;
			end = node->nchildren - 1;
			while (end >= start) {
				int middle = (end + start) / 2;
				char ch = node->children[middle].c;
				if (*n == ch) {
					node = node->children[middle].child;
					break;
				}
				else if (*n < ch) {
					end = middle - 1;
				}
				else {
					start = middle + 1;
				}
			}
			if (end < start) {
				node = NULL;
				break;
			}
		}

		if (node && node->frec) {
			return add_any_filter_handle(node->frec, ctx, r, c, r_filters,
			                             p_filters, c_filters);
		}
	}

	ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, r ? r->connection : c, APLOGNO(00082)
	              "an unknown filter was not added: %s", name);
	return NULL;
}

AP_DECLARE(ap_filter_t *) ap_add_input_filter(const char *name, void *ctx,
                                              request_rec *r, conn_rec *c)
{
	return add_any_filter(name, ctx, r, c, registered_input_filters,
	                      r ? &r->input_filters : NULL,
	                      r ? &r->proto_input_filters : NULL,
	                      &c->input_filters);
}

static void remove_any_filter(ap_filter_t *f, ap_filter_t **r_filt, ap_filter_t **p_filt,
                              ap_filter_t **c_filt)
{
	ap_filter_t **curr = r_filt ? r_filt : c_filt;
	ap_filter_t *fscan = *curr;

	if (p_filt && *p_filt == f)
		*p_filt = (*p_filt)->next;

	if (*curr == f) {
		*curr = (*curr)->next;
		return;
	}

	while (fscan->next != f) {
		if (!(fscan = fscan->next)) {
			return;
		}
	}

	fscan->next = f->next;
}

AP_DECLARE(void) ap_remove_input_filter(ap_filter_t *f)
{
	remove_any_filter(f, f->r ? &f->r->input_filters : NULL,
	                  f->r ? &f->r->proto_input_filters : NULL,
	                  &f->c->input_filters);
}

static int cfg_closefile(ap_configfile_t *cfp)
{
#ifdef DEBUG
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
	             "Done with config file %s", cfp->name);
#endif
	return (cfp->close == NULL) ? 0 : cfp->close(cfp->param);
}

/* we can't use apr_file_* directly because of linking issues on Windows */
static apr_status_t cfg_close(void *param)
{
	return apr_file_close(param);
}

static apr_status_t cfg_getch(char *ch, void *param)
{
	return apr_file_getc(ch, param);
}

static apr_status_t cfg_getstr(void *buf, apr_size_t bufsiz, void *param)
{
	return apr_file_gets(buf, bufsiz, param);
}

/* Read one line from open ap_configfile_t, strip LF, increase line number */
/* If custom handler does not define a getstr() function, read char by char */
static apr_status_t cfg_getline_core(char *buf, apr_size_t bufsize,
                                     apr_size_t offset, ap_configfile_t *cfp)
{
	apr_status_t rc;
	/* If a "get string" function is defined, use it */
	if (cfp->getstr != NULL) {
		char *cp;
		char *cbuf = buf + offset;
		apr_size_t cbufsize = bufsize - offset;

		while (1) {
			++cfp->line_number;
			rc = cfp->getstr(cbuf, cbufsize, cfp->param);
			if (rc == APR_EOF) {
				if (cbuf != buf + offset) {
					*cbuf = '\0';
					break;
				}
				else {
					return APR_EOF;
				}
			}
			if (rc != APR_SUCCESS) {
				return rc;
			}

			/*
			 *  check for line continuation,
			 *  i.e. match [^\\]\\[\r]\n only
			 */
			cp = cbuf;
			cp += strlen(cp);
			if (cp > buf && cp[-1] == LF) {
				cp--;
				if (cp > buf && cp[-1] == CR)
					cp--;
				if (cp > buf && cp[-1] == '\\') {
					cp--;
					/*
					 * line continuation requested -
					 * then remove backslash and continue
					 */
					cbufsize -= (cp-cbuf);
					cbuf = cp;
					continue;
				}
			}
			else if (cp - buf >= bufsize - 1) {
				return APR_ENOSPC;
			}
			break;
		}
	} else {
		/* No "get string" function defined; read character by character */
		apr_size_t i = offset;

		if (bufsize < 2) {
			/* too small, assume caller is crazy */
			return APR_EINVAL;
		}
		buf[offset] = '\0';

		while (1) {
			char c;
			rc = cfp->getch(&c, cfp->param);
			if (rc == APR_EOF) {
				if (i > offset)
					break;
				else
					return APR_EOF;
			}
			if (rc != APR_SUCCESS)
				return rc;
			if (c == LF) {
				++cfp->line_number;
				/* check for line continuation */
				if (i > 0 && buf[i-1] == '\\') {
					i--;
					continue;
				}
				else {
					break;
				}
			}
			buf[i] = c;
			++i;
			if (i >= bufsize - 1) {
				return APR_ENOSPC;
			}
		}
		buf[i] = '\0';
	}
	return APR_SUCCESS;
}

static int cfg_trim_line(char *buf)
{
	char *start, *end;
	/*
	 * Leading and trailing white space is eliminated completely
	 */
	start = buf;
	while (apr_isspace(*start))
		++start;
	/* blast trailing whitespace */
	end = &start[strlen(start)];
	while (--end >= start && apr_isspace(*end))
		*end = '\0';
	/* Zap leading whitespace by shifting */
	if (start != buf)
		memmove(buf, start, end - start + 2);
#ifdef DEBUG_CFG_LINES
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, APLOGNO(00555) "Read config: '%s'", buf);
#endif
	return end - start + 1;
}

/* Read one line from open ap_configfile_t, strip LF, increase line number */
/* If custom handler does not define a getstr() function, read char by char */
static apr_status_t cfg_getline(char *buf, apr_size_t bufsize,
                                ap_configfile_t *cfp)
{
	apr_status_t rc = cfg_getline_core(buf, bufsize, 0, cfp);
	if (rc == APR_SUCCESS)
		cfg_trim_line(buf);
	return rc;
}

static char *substring_conf(apr_pool_t *p, const char *start, int len,
                            char quote)
{
	char *result = apr_palloc(p, len + 1);
	char *resp = result;
	int i;

	for (i = 0; i < len; ++i) {
		if (start[i] == '\\' && (start[i + 1] == '\\'
		                         || (quote && start[i + 1] == quote)))
			*resp++ = start[++i];
		else
			*resp++ = start[i];
	}

	*resp++ = '\0';
#if RESOLVE_ENV_PER_TOKEN
	return (char *)ap_resolve_env(p,result);
#else
	return result;
#endif
}

static char *getword_conf(apr_pool_t *p, const char **line)
{
	const char *str = *line, *strend;
	char *res;
	char quote;

	while (apr_isspace(*str))
		++str;

	if (!*str) {
		*line = str;
		return "";
	}

	if ((quote = *str) == '"' || quote == '\'') {
		strend = str + 1;
		while (*strend && *strend != quote) {
			if (*strend == '\\' && strend[1] &&
			    (strend[1] == quote || strend[1] == '\\')) {
				strend += 2;
			}
			else {
				++strend;
			}
		}
		res = substring_conf(p, str + 1, strend - str - 1, quote);

		if (*strend == quote)
			++strend;
	}
	else {
		strend = str;
		while (*strend && !apr_isspace(*strend))
			++strend;

		res = substring_conf(p, str, strend - str, 0);
	}

	while (apr_isspace(*strend))
		++strend;
	*line = strend;
	return res;
}

/* Open a ap_configfile_t as FILE, return open ap_configfile_t struct pointer */
static apr_status_t pcfg_openfile(ap_configfile_t **ret_cfg,
                                  apr_pool_t *p, const char *name)
{
	ap_configfile_t *new_cfg;
	apr_file_t *file = NULL;
	apr_finfo_t finfo;
	apr_status_t status;
#ifdef DEBUG
	char buf[120];
#endif

	if (name == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(00552)
		             "Internal error: pcfg_openfile() called with NULL filename");
		return APR_EBADF;
	}

	status = apr_file_open(&file, name, APR_READ | APR_BUFFERED,
	                       APR_OS_DEFAULT, p);
#ifdef DEBUG
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, APLOGNO(00553)
	             "Opening config file %s (%s)",
	             name, (status != APR_SUCCESS) ?
	             apr_strerror(status, buf, sizeof(buf)) : "successful");
#endif
	if (status != APR_SUCCESS)
		return status;

	status = apr_file_info_get(&finfo, APR_FINFO_TYPE, file);
	if (status != APR_SUCCESS)
		return status;

	if (finfo.filetype != APR_REG &&
		strcmp(name, "/dev/null") != 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(00554)
		             "Access to file %s denied by server: not a regular file",
		             name);
		apr_file_close(file);
		return APR_EBADF;
	}

	new_cfg = apr_palloc(p, sizeof(*new_cfg));
	new_cfg->param = file;
	new_cfg->name = apr_pstrdup(p, name);
	new_cfg->getch = cfg_getch;
	new_cfg->getstr = cfg_getstr;
	new_cfg->close = cfg_close;
	new_cfg->line_number = 0;
	*ret_cfg = new_cfg;
	return APR_SUCCESS;
}

static const command_rec *find_command(const char *name,
                                       const command_rec *cmds)
{
	while (cmds->name) {
		if (!strcasecmp(name, cmds->name))
			return cmds;
		++cmds;
	}

	return NULL;
}

static const char *invoke_cmd(const command_rec *cmd, cmd_parms *parms,
                              void *mconfig, const char *args)
{
	int override_list_ok = 0;
	char *w, *w2, *w3;
	const char *errmsg = NULL;

	/** Have we been provided a list of acceptable directives? */
	if (parms->override_list != NULL) {
		if (apr_table_get(parms->override_list, cmd->name) != NULL) {
			override_list_ok = 1;
		}
	}

	if ((parms->override & cmd->req_override) == 0 && !override_list_ok) {
		return apr_pstrcat(parms->pool, cmd->name,
		                   " not allowed here", NULL);
	}

	parms->info = cmd->cmd_data;
	parms->cmd = cmd;

	switch (cmd->args_how) {
	case RAW_ARGS:
#ifdef RESOLVE_ENV_PER_TOKEN
		args = ap_resolve_env(parms->pool,args);
#endif
		return cmd->AP_RAW_ARGS(parms, mconfig, args);

	case TAKE_ARGV:
		{
			char *argv[MAX_ARGC];
			int argc = 0;

			do {
				w = getword_conf(parms->pool, &args);
				if (*w == '\0' && *args == '\0') {
					break;
				}
				argv[argc] = w;
				argc++;
			} while (argc < MAX_ARGC && *args != '\0');

			return cmd->AP_TAKE_ARGV(parms, mconfig, argc, argv);
		}

	case NO_ARGS:
		if (*args != 0)
			return apr_pstrcat(parms->pool, cmd->name, " takes no arguments",
			                   NULL);

		return cmd->AP_NO_ARGS(parms, mconfig);

	case TAKE1:
		w = getword_conf(parms->pool, &args);

		if (*w == '\0' || *args != 0)
			return apr_pstrcat(parms->pool, cmd->name, " takes one argument",
			                   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

		return cmd->AP_TAKE1(parms, mconfig, w);

	case TAKE2:
		w = getword_conf(parms->pool, &args);
		w2 = getword_conf(parms->pool, &args);

		if (*w == '\0' || *w2 == '\0' || *args != 0)
			return apr_pstrcat(parms->pool, cmd->name, " takes two arguments",
			                   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

		return cmd->AP_TAKE2(parms, mconfig, w, w2);

	case TAKE12:
		w = getword_conf(parms->pool, &args);
		w2 = getword_conf(parms->pool, &args);

		if (*w == '\0' || *args != 0)
			return apr_pstrcat(parms->pool, cmd->name, " takes 1-2 arguments",
			                   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

		return cmd->AP_TAKE2(parms, mconfig, w, *w2 ? w2 : NULL);

	case TAKE3:
		w = getword_conf(parms->pool, &args);
		w2 = getword_conf(parms->pool, &args);
		w3 = getword_conf(parms->pool, &args);

		if (*w == '\0' || *w2 == '\0' || *w3 == '\0' || *args != 0)
			return apr_pstrcat(parms->pool, cmd->name, " takes three arguments",
			                   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

		return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

	case TAKE23:
		w = getword_conf(parms->pool, &args);
		w2 = getword_conf(parms->pool, &args);
		w3 = *args ? getword_conf(parms->pool, &args) : NULL;

		if (*w == '\0' || *w2 == '\0' || *args != 0)
			return apr_pstrcat(parms->pool, cmd->name,
			                   " takes two or three arguments",
			                   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

		return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

	case TAKE123:
		w = getword_conf(parms->pool, &args);
		w2 = *args ? getword_conf(parms->pool, &args) : NULL;
		w3 = *args ? getword_conf(parms->pool, &args) : NULL;

		if (*w == '\0' || *args != 0)
			return apr_pstrcat(parms->pool, cmd->name,
			                   " takes one, two or three arguments",
			                   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

		return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

	case TAKE13:
		w = getword_conf(parms->pool, &args);
		w2 = *args ? getword_conf(parms->pool, &args) : NULL;
		w3 = *args ? getword_conf(parms->pool, &args) : NULL;

		if (*w == '\0' || (w2 && *w2 && !w3) || *args != 0)
			return apr_pstrcat(parms->pool, cmd->name,
			                   " takes one or three arguments",
			                   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

		return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

	case ITERATE:
		w = getword_conf(parms->pool, &args);

		if (*w == '\0')
			return apr_pstrcat(parms->pool, cmd->name,
			                   " requires at least one argument",
			                   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

		while (*w != '\0') {
			errmsg = cmd->AP_TAKE1(parms, mconfig, w);

			if (errmsg && strcmp(errmsg, DECLINE_CMD) != 0)
				return errmsg;

			w = getword_conf(parms->pool, &args);
		}

		return errmsg;

	case ITERATE2:
		w = getword_conf(parms->pool, &args);

		if (*w == '\0' || *args == 0)
			return apr_pstrcat(parms->pool, cmd->name,
			                   " requires at least two arguments",
			                   cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

		while (*(w2 = getword_conf(parms->pool, &args)) != '\0') {

			errmsg = cmd->AP_TAKE2(parms, mconfig, w, w2);

			if (errmsg && strcmp(errmsg, DECLINE_CMD) != 0)
				return errmsg;
		}

		return errmsg;

	case FLAG:
		/*
		 * This is safe to use temp_pool here, because the 'flag' itself is not
		 * forwarded as-is
		 */
		w = getword_conf(parms->temp_pool, &args);

		if (*w == '\0' || (strcasecmp(w, "on") && strcasecmp(w, "off")))
			return apr_pstrcat(parms->pool, cmd->name, " must be On or Off",
			                   NULL);

		return cmd->AP_FLAG(parms, mconfig, strcasecmp(w, "off") != 0);

	default:
		return apr_pstrcat(parms->pool, cmd->name,
		                   " is improperly configured internally (server bug)",
		                   NULL);
	}
}

static int is_directory(apr_pool_t *p, const char *path)
{
	apr_finfo_t finfo;

	if (apr_stat(&finfo, path, APR_FINFO_TYPE, p) != APR_SUCCESS)
		return 0;                /* in error condition, just return no */

	return (finfo.filetype == APR_DIR);
}

static char *make_full_path(apr_pool_t *a, const char *src1,
                            const char *src2)
{
	apr_size_t len1, len2;
	char *path;

	len1 = strlen(src1);
	len2 = strlen(src2);
	/* allocate +3 for '/' delimiter, trailing NULL and overallocate
	 * one extra byte to allow the caller to add a trailing '/'
	 */
	path = (char *)apr_palloc(a, len1 + len2 + 3);
	if (len1 == 0) {
		*path = '/';
		memcpy(path + 1, src2, len2 + 1);
	}
	else {
		char *next;
		memcpy(path, src1, len1);
		next = path + len1;
		if (next[-1] != '/') {
			*next++ = '/';
		}
		memcpy(next, src2, len2 + 1);
	}
	return path;
}

static int fname_alphasort(const void *fn1, const void *fn2)
{
	const fnames *f1 = fn1;
	const fnames *f2 = fn2;

	return strcmp(f1->fname,f2->fname);
}

static const char *process_resource_config(const char *fname,
                                           apr_array_header_t *ari,
                                           apr_pool_t *p,
                                           apr_pool_t *ptemp)
{
	*(char **)apr_array_push(ari) = (char *)fname;
	return NULL;
}

static const char *process_resource_config_nofnmatch(const char *fname,
                                                     apr_array_header_t *ari,
                                                     apr_pool_t *p,
                                                     apr_pool_t *ptemp,
                                                     unsigned depth,
                                                     int optional)
{
	const char *error;
	apr_status_t rv;

	if (is_directory(ptemp, fname)) {
		apr_dir_t *dirp;
		apr_finfo_t dirent;
		int current;
		apr_array_header_t *candidates = NULL;
		fnames *fnew;
		char *path = apr_pstrdup(ptemp, fname);

		if (++depth > MAX_INCLUDE_DIR_DEPTH) {
			return apr_psprintf(p, "Directory %s exceeds the maximum include "
			                    "directory nesting level of %u. You have "
			                    "probably a recursion somewhere.", path,
			                    MAX_INCLUDE_DIR_DEPTH);
		}

		/*
		 * first course of business is to grok all the directory
		 * entries here and store 'em away. Recall we need full pathnames
		 * for this.
		 */
		rv = apr_dir_open(&dirp, path, ptemp);
		if (rv != APR_SUCCESS) {
			return apr_psprintf(p, "Could not open config directory %s: %pm",
			                    path, &rv);
		}

		candidates = apr_array_make(ptemp, 1, sizeof(fnames));
		while (apr_dir_read(&dirent, APR_FINFO_DIRENT, dirp) == APR_SUCCESS) {
			/* strip out '.' and '..' */
			if (strcmp(dirent.name, ".")
			    && strcmp(dirent.name, "..")) {
				fnew = (fnames *) apr_array_push(candidates);
				fnew->fname = make_full_path(ptemp, path, dirent.name);
			}
		}

		apr_dir_close(dirp);
		if (candidates->nelts != 0) {
			qsort((void *) candidates->elts, candidates->nelts,
			      sizeof(fnames), fname_alphasort);

			/*
			 * Now recurse these... we handle errors and subdirectories
			 * via the recursion, which is nice
			 */
			for (current = 0; current < candidates->nelts; ++current) {
				fnew = &((fnames *) candidates->elts)[current];
				error = process_resource_config_nofnmatch(fnew->fname,
				                                          ari, p, ptemp,
				                                          depth, optional);
				if (error) {
					return error;
				}
			}
		}

		return NULL;
	}

	return process_resource_config(fname, ari, p, ptemp);
}

static const char *process_resource_config_fnmatch(const char *path,
                                                   const char *fname,
                                                   apr_array_header_t *ari,
                                                   apr_pool_t *p,
                                                   apr_pool_t *ptemp,
                                                   unsigned depth,
                                                   int optional)
{
	const char *rest;
	apr_status_t rv;
	apr_dir_t *dirp;
	apr_finfo_t dirent;
	apr_array_header_t *candidates = NULL;
	fnames *fnew;
	int current;

	/* find the first part of the filename */
	rest = ap_strchr_c(fname, '/');
	if (rest) {
		fname = apr_pstrndup(ptemp, fname, rest - fname);
		rest++;
	}

	/* optimisation - if the filename isn't a wildcard, process it directly */
	if (!apr_fnmatch_test(fname)) {
		path = make_full_path(ptemp, path, fname);
		if (!rest) {
			return process_resource_config_nofnmatch(path,
			                                         ari, p,
			                                         ptemp, 0, optional);
		}
		else {
			return process_resource_config_fnmatch(path, rest,
			                                       ari, p,
			                                       ptemp, 0, optional);
		}
	}

	/*
	 * first course of business is to grok all the directory
	 * entries here and store 'em away. Recall we need full pathnames
	 * for this.
	 */
	rv = apr_dir_open(&dirp, path, ptemp);
	if (rv != APR_SUCCESS) {
		return apr_psprintf(p, "Could not open config directory %s: %pm",
		                    path, &rv);
	}

	candidates = apr_array_make(ptemp, 1, sizeof(fnames));
	while (apr_dir_read(&dirent, APR_FINFO_DIRENT | APR_FINFO_TYPE, dirp) == APR_SUCCESS) {
		/* strip out '.' and '..' */
		if (strcmp(dirent.name, ".")
		    && strcmp(dirent.name, "..")
		    && (apr_fnmatch(fname, dirent.name,
			                APR_FNM_PERIOD) == APR_SUCCESS)) {
			const char *full_path = make_full_path(ptemp, path, dirent.name);
			/* If matching internal to path, and we happen to match something
			 * other than a directory, skip it
			 */
			if (rest && (rv == APR_SUCCESS) && (dirent.filetype != APR_DIR)) {
				continue;
			}
			fnew = (fnames *) apr_array_push(candidates);
			fnew->fname = full_path;
		}
	}

	apr_dir_close(dirp);
	if (candidates->nelts != 0) {
		const char *error;

		qsort((void *) candidates->elts, candidates->nelts,
		      sizeof(fnames), fname_alphasort);

		/*
		 * Now recurse these... we handle errors and subdirectories
		 * via the recursion, which is nice
		 */
		for (current = 0; current < candidates->nelts; ++current) {
			fnew = &((fnames *) candidates->elts)[current];
			if (!rest) {
				error = process_resource_config_nofnmatch(fnew->fname,
				                                          ari, p,
				                                          ptemp, 0, optional);
			}
			else {
				error = process_resource_config_fnmatch(fnew->fname, rest,
				                                        ari, p,
				                                        ptemp, 0, optional);
			}
			if (error) {
				return error;
			}
		}
	}
	else {

		if (!optional) {
			return apr_psprintf(p, "No matches for the wildcard '%s' in '%s', failing "
			                    "(use IncludeOptional if required)", fname, path);
		}
	}

	return NULL;
}

static const char *process_fnmatch_configs(const char *fname,
                                           apr_array_header_t *ari,
                                           apr_pool_t *p,
                                           apr_pool_t *ptemp,
                                           int optional)
{
	if (!apr_fnmatch_test(fname)) {
		return process_resource_config_nofnmatch(fname, ari, p, ptemp, 0, optional);
	}
	else {
		apr_status_t status;
		const char *rootpath, *filepath = fname;

		/* locate the start of the directories proper */
		status = apr_filepath_root(&rootpath, &filepath, APR_FILEPATH_TRUENAME, ptemp);

		/* we allow APR_SUCCESS and APR_EINCOMPLETE */
		if (APR_ERELATIVE == status) {
			return apr_pstrcat(p, "Include must have an absolute path, ", fname, NULL);
		}
		else if (APR_EBADPATH == status) {
			return apr_pstrcat(p, "Include has a bad path, ", fname, NULL);
		}

		/* walk the filepath */
		return process_resource_config_fnmatch(rootpath, filepath, ari, p, ptemp,
		                                       0, optional);
	}
}

const char *read_module_config(server_rec *s, void *mconfig,
                               const command_rec *cmds,
                               apr_pool_t *p, apr_pool_t *ptemp,
                               const char *filename)
{
	apr_array_header_t *ari, *arr;
	ap_directive_t *newdir;
	cmd_parms *parms;

	char line[MAX_STRING_LEN];
	const char *errmsg;
	const char *err = NULL;

	ari = apr_array_make(p, 1, sizeof(char *));
	arr = apr_array_make(p, 1, sizeof(cmd_parms));

	errmsg = process_fnmatch_configs(filename, ari, p, ptemp, 0);

	if (errmsg != NULL)
		goto out;

	while (ari->nelts || arr->nelts) {

		/* similar to process_command_config() */
		if (ari->nelts) {
			char *inc = *(char **)apr_array_pop(ari);

			parms = (cmd_parms *)apr_array_push(arr);
			*parms = default_parms;
			parms->pool = p;
			parms->temp_pool = ptemp;
			parms->server = s;
			parms->override = (RSRC_CONF | ACCESS_CONF);
			parms->override_opts = OPT_ALL | OPT_SYM_OWNER | OPT_MULTI;

			if (pcfg_openfile(&parms->config_file, p, inc) != APR_SUCCESS) {
				apr_array_pop(arr);
				errmsg = apr_pstrcat(p, "Cannot open file: ", inc, NULL);
				goto out;
			}
		}

		if (arr->nelts > MAX_INCLUDE_DIR_DEPTH) {
			errmsg = apr_psprintf(p, "Exceeded the maximum include "
			                      "directory nesting level of %u. You have "
			                      "probably a recursion somewhere.",
			                      MAX_INCLUDE_DIR_DEPTH);
			goto out;
		}

		if (!(parms = (cmd_parms *)apr_array_pop(arr)))
			break;

		while (!(cfg_getline(line, MAX_STRING_LEN, parms->config_file))) {

			const command_rec *cmd;
			char *cmd_name;
			const char *args = line;
			int optional = 0;

			if (*line == '#' || *line == '\0')
				continue;

			if (!(cmd_name = getword_conf(p, &args)))
				continue;

			/* similar to invoke_cmd() */
			if (!strcasecmp(cmd_name, "IncludeOptional") ||
			    !strcasecmp(cmd_name, "Include"))
			{
				char *w, *fullname;

				if (!strcasecmp(cmd_name, "IncludeOptional"))
					optional = 1;

				w = getword_conf(parms->pool, &args);

				if (*w == '\0' || *args != 0) {
					errmsg = apr_pstrcat(parms->pool, cmd_name, " takes one argument", NULL);
					goto out;
				}

				fullname = ap_server_root_relative(ptemp, w);
				errmsg = process_fnmatch_configs(fullname, ari, p, ptemp, optional);

				*(cmd_parms *)apr_array_push(arr) = *parms;

				if(errmsg != NULL)
					goto out;

				parms = NULL;
				break;
			}

			if (!(cmd = find_command(cmd_name, cmds))) {
				errmsg = apr_pstrcat(parms->pool, "Invalid command '",
				                     cmd_name, "'", NULL);
				goto out;
			}

			newdir = apr_pcalloc(p, sizeof(ap_directive_t));
			newdir->filename = parms->config_file->name;
			newdir->line_num = parms->config_file->line_number;
			newdir->directive = cmd_name;
			newdir->args = apr_pstrdup(p, args);

			parms->directive = newdir;

			if ((errmsg = invoke_cmd(cmd, parms, mconfig, args)) != NULL)
				break;
		}

		if (parms != NULL)
			cfg_closefile(parms->config_file);

		if (errmsg != NULL)
			break;
	}

	if (errmsg) {
		if (parms) {
			err = apr_psprintf(p, "Syntax error on line %d of %s: %s",
			                   parms->config_file->line_number,
			                   parms->config_file->name,
			                   errmsg);
			errmsg = err;
		}
	}

out:

	while ((parms = (cmd_parms *)apr_array_pop(arr)) != NULL)
		cfg_closefile(parms->config_file);

	return errmsg;
}

int lookup_builtin_method(const char *method, apr_size_t len)
{
	/* Note: from Apache 2 HTTP Server source. */

	/* Note: the following code was generated by the "shilka" tool from
	   the "cocom" parsing/compilation toolkit. It is an optimized lookup
	   based on analysis of the input keywords. Postprocessing was done
	   on the shilka output, but the basic structure and analysis is
	   from there. Should new HTTP methods be added, then manual insertion
	   into this code is fine, or simply re-running the shilka tool on
	   the appropriate input. */

	/* Note: it is also quite reasonable to just use our method_registry,
	   but I'm assuming (probably incorrectly) we want more speed here
	   (based on the optimizations the previous code was doing). */

	switch (len)
	{
	case 3:
		switch (method[0])
		{
		case 'P':
			return (method[1] == 'U'
			        && method[2] == 'T'
			        ? M_PUT : UNKNOWN_METHOD);
		case 'G':
			return (method[1] == 'E'
			        && method[2] == 'T'
			        ? M_GET : UNKNOWN_METHOD);
		default:
			return UNKNOWN_METHOD;
		}

	case 4:
		switch (method[0])
		{
		case 'H':
			return (method[1] == 'E'
			        && method[2] == 'A'
			        && method[3] == 'D'
			        ? M_GET : UNKNOWN_METHOD);
		case 'P':
			return (method[1] == 'O'
			        && method[2] == 'S'
			        && method[3] == 'T'
			        ? M_POST : UNKNOWN_METHOD);
		case 'M':
			return (method[1] == 'O'
			        && method[2] == 'V'
			        && method[3] == 'E'
			        ? M_MOVE : UNKNOWN_METHOD);
		case 'L':
			return (method[1] == 'O'
			        && method[2] == 'C'
			        && method[3] == 'K'
			        ? M_LOCK : UNKNOWN_METHOD);
		case 'C':
			return (method[1] == 'O'
			        && method[2] == 'P'
			        && method[3] == 'Y'
			        ? M_COPY : UNKNOWN_METHOD);
		default:
			return UNKNOWN_METHOD;
		}

	case 5:
		switch (method[2])
		{
		case 'T':
			return (memcmp(method, "PATCH", 5) == 0
			        ? M_PATCH : UNKNOWN_METHOD);
		case 'R':
			return (memcmp(method, "MERGE", 5) == 0
			        ? M_MERGE : UNKNOWN_METHOD);
		case 'C':
			return (memcmp(method, "MKCOL", 5) == 0
			        ? M_MKCOL : UNKNOWN_METHOD);
		case 'B':
			return (memcmp(method, "LABEL", 5) == 0
			        ? M_LABEL : UNKNOWN_METHOD);
		case 'A':
			return (memcmp(method, "TRACE", 5) == 0
			        ? M_TRACE : UNKNOWN_METHOD);
		default:
			return UNKNOWN_METHOD;
		}

	case 6:
		switch (method[0])
		{
		case 'U':
			switch (method[5])
			{
			case 'K':
				return (memcmp(method, "UNLOCK", 6) == 0
				        ? M_UNLOCK : UNKNOWN_METHOD);
			case 'E':
				return (memcmp(method, "UPDATE", 6) == 0
				        ? M_UPDATE : UNKNOWN_METHOD);
			default:
				return UNKNOWN_METHOD;
			}
		case 'R':
			return (memcmp(method, "REPORT", 6) == 0
			        ? M_REPORT : UNKNOWN_METHOD);
		case 'D':
			return (memcmp(method, "DELETE", 6) == 0
			        ? M_DELETE : UNKNOWN_METHOD);
		default:
			return UNKNOWN_METHOD;
		}

	case 7:
		switch (method[1])
		{
		case 'P':
			return (memcmp(method, "OPTIONS", 7) == 0
			        ? M_OPTIONS : UNKNOWN_METHOD);
		case 'O':
			return (memcmp(method, "CONNECT", 7) == 0
			        ? M_CONNECT : UNKNOWN_METHOD);
		case 'H':
			return (memcmp(method, "CHECKIN", 7) == 0
			        ? M_CHECKIN : UNKNOWN_METHOD);
		default:
			return UNKNOWN_METHOD;
		}

	case 8:
		switch (method[0])
		{
		case 'P':
			return (memcmp(method, "PROPFIND", 8) == 0
			        ? M_PROPFIND : UNKNOWN_METHOD);
		case 'C':
			return (memcmp(method, "CHECKOUT", 8) == 0
			        ? M_CHECKOUT : UNKNOWN_METHOD);
		default:
			return UNKNOWN_METHOD;
		}

	case 9:
		return (memcmp(method, "PROPPATCH", 9) == 0
                ? M_PROPPATCH : UNKNOWN_METHOD);

	case 10:
		switch (method[0])
		{
		case 'U':
			return (memcmp(method, "UNCHECKOUT", 10) == 0
			        ? M_UNCHECKOUT : UNKNOWN_METHOD);
		case 'M':
			return (memcmp(method, "MKACTIVITY", 10) == 0
			        ? M_MKACTIVITY : UNKNOWN_METHOD);
		default:
			return UNKNOWN_METHOD;
		}

	case 11:
		return (memcmp(method, "MKWORKSPACE", 11) == 0
		        ? M_MKWORKSPACE : UNKNOWN_METHOD);

	case 15:
		return (memcmp(method, "VERSION-CONTROL", 15) == 0
		        ? M_VERSION_CONTROL : UNKNOWN_METHOD);

	case 16:
		return (memcmp(method, "BASELINE-CONTROL", 16) == 0
		        ? M_BASELINE_CONTROL : UNKNOWN_METHOD);

	default:
		return UNKNOWN_METHOD;
	}

	/* NOTREACHED */
}
