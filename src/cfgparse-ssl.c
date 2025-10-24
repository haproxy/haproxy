/*
 *
 * Copyright (C) 2012 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2020 HAProxy Technologies, William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 *
 * Configuration parsing for SSL.
 * This file is split in 3 parts:
 * - global section parsing
 * - bind keyword parsing
 * - server keyword parsing
 *
 *  Please insert the new keywords at the right place
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <import/ebsttree.h>

#include <haproxy/api.h>
#include <haproxy/base64.h>
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/listener.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/ssl_utils.h>
#include <haproxy/tools.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_crtlist.h>
#include <haproxy/ssl_ocsp.h>
#include <haproxy/ssl_sock.h>


/****************** Global Section Parsing ********************************************/

static int ssl_load_global_issuers_from_path(char **args, int section_type, struct proxy *curpx,
					      const struct proxy *defpx, const char *file, int line,
					      char **err)
{
	char *path;
	struct dirent **de_list;
	int i, n;
	struct stat buf;
	char *end;
	char fp[MAXPATHLEN+1];

	if (too_many_args(1, args, err, NULL))
		return -1;

	path = args[1];
	if (*path == 0 || stat(path, &buf)) {
		memprintf(err, "%sglobal statement '%s' expects a directory path as an argument.\n",
			  err && *err ? *err : "", args[0]);
		return -1;
	}
	if (S_ISDIR(buf.st_mode) == 0) {
		memprintf(err, "%sglobal statement '%s': %s is not a directory.\n",
			  err && *err ? *err : "", args[0], path);
		return -1;
	}

	/* strip trailing slashes, including first one */
	for (end = path + strlen(path) - 1; end >= path && *end == '/'; end--)
		*end = 0;
	/* path already parsed? */
	if (global_ssl.issuers_chain_path && strcmp(global_ssl.issuers_chain_path, path) == 0)
		return 0;
	/* overwrite old issuers_chain_path */
	free(global_ssl.issuers_chain_path);
	global_ssl.issuers_chain_path = strdup(path);
	ssl_free_global_issuers();

	n = scandir(path, &de_list, 0, alphasort);
	if (n < 0) {
		memprintf(err, "%sglobal statement '%s': unable to scan directory '%s' : %s.\n",
			  err && *err ? *err : "", args[0], path, strerror(errno));
		return -1;
	}
	for (i = 0; i < n; i++) {
		struct dirent *de = de_list[i];
		BIO *in = NULL;
		char *warn = NULL;

		snprintf(fp, sizeof(fp), "%s/%s", path, de->d_name);
		free(de);
		if (stat(fp, &buf) != 0) {
			ha_warning("unable to stat certificate from file '%s' : %s.\n", fp, strerror(errno));
			goto next;
		}
		if (!S_ISREG(buf.st_mode))
			goto next;

		in = BIO_new(BIO_s_file());
		if (in == NULL)
			goto next;
		if (BIO_read_filename(in, fp) <= 0)
			goto next;
		ssl_load_global_issuer_from_BIO(in, fp, &warn);
		if (warn) {
			ha_warning("%s", warn);
			ha_free(&warn);
		}
	next:
		if (in)
			BIO_free(in);
	}
	free(de_list);

	return 0;
}

/* parse the "ssl-mode-async" keyword in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ssl_async(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
#ifdef SSL_MODE_ASYNC
	global_ssl.async = 1;
	global.ssl_used_async_engines = nb_engines;
	return 0;
#else
	memprintf(err, "'%s': openssl library does not support async mode", args[0]);
	return -1;
#endif
}

#if defined(USE_ENGINE) && !defined(OPENSSL_NO_ENGINE)
/* parse the "ssl-engine" keyword in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ssl_engine(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	char *algo;
	int ret = -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a valid engine name as an argument.", args[0]);
		return ret;
	}

	if (*(args[2]) == 0) {
		/* if no list of algorithms is given, it defaults to ALL */
		algo = strdup("ALL");
		goto add_engine;
	}

	/* otherwise the expected format is ssl-engine <engine_name> algo <list of algo> */
	if (strcmp(args[2], "algo") != 0) {
		memprintf(err, "global statement '%s' expects to have algo keyword.", args[0]);
		return ret;
	}

	if (*(args[3]) == 0) {
		memprintf(err, "global statement '%s' expects algorithm names as an argument.", args[0]);
		return ret;
	}
	algo = strdup(args[3]);

add_engine:
	if (ssl_init_single_engine(args[1], algo)==0) {
		openssl_engines_initialized++;
		ret = 0;
	}
	free(algo);
	return ret;
}
#endif

#ifdef HAVE_SSL_PROVIDERS
/* parse the "ssl-propquery" keyword in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ssl_propquery(char **args, int section_type, struct proxy *curpx,
					  const struct proxy *defpx, const char *file, int line,
					  char **err)
{
	int ret = -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a property string as an argument.", args[0]);
		return ret;
	}

	if (EVP_set_default_properties(NULL, args[1]))
		ret = 0;

	return ret;
}

/* parse the "ssl-provider" keyword in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ssl_provider(char **args, int section_type, struct proxy *curpx,
					 const struct proxy *defpx, const char *file, int line,
					 char **err)
{
	int ret = -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a valid engine provider name as an argument.", args[0]);
		return ret;
	}

	if (ssl_init_provider(args[1]) == 0)
		ret = 0;

	return ret;
}

/* parse the "ssl-provider-path" keyword in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ssl_provider_path(char **args, int section_type, struct proxy *curpx,
					      const struct proxy *defpx, const char *file, int line,
					      char **err)
{
	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a directory path as an argument.", args[0]);
		return -1;
	}

	OSSL_PROVIDER_set_default_search_path(NULL, args[1]);

	return 0;
}
#endif

/* parse the "ssl-default-bind-ciphers" / "ssl-default-server-ciphers" keywords
 * in global section. Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ciphers(char **args, int section_type, struct proxy *curpx,
                                    const struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	char **target;

	target = (args[0][12] == 'b') ? &global_ssl.listen_default_ciphers : &global_ssl.connect_default_ciphers;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a cipher suite as an argument.", args[0]);
		return -1;
	}

	free(*target);
	*target = strdup(args[1]);
	return 0;
}

/* parse the "ssl-default-bind-ciphersuites" / "ssl-default-server-ciphersuites" keywords
 * in global section. Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ciphersuites(char **args, int section_type, struct proxy *curpx,
                                    const struct proxy *defpx, const char *file, int line,
                                    char **err)
{
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	char **target;

	target = (args[0][12] == 'b') ? &global_ssl.listen_default_ciphersuites : &global_ssl.connect_default_ciphersuites;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a cipher suite as an argument.", args[0]);
		return -1;
	}

	free(*target);
	*target = strdup(args[1]);
	return 0;
#else /* ! HAVE_SSL_CTX_SET_CIPHERSUITES */
	memprintf(err, "'%s' not supported for your SSL library (%s).", args[0], OPENSSL_VERSION_TEXT);
	return -1;

#endif
}

#if defined(SSL_CTX_set1_curves_list)
/*
 * parse the "ssl-default-bind-curves" keyword in a global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_curves(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
				   char **err)
{
	char **target;
	target = (args[0][12] == 'b') ? &global_ssl.listen_default_curves : &global_ssl.connect_default_curves;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a curves suite as an arguments.", args[0]);
		return -1;
	}

	free(*target);
	*target = strdup(args[1]);
	return 0;
}
#endif

#if defined(SSL_CTX_set1_sigalgs_list)
/*
 * parse the "ssl-default-bind-sigalgs" and "ssl-default-server-sigalgs" keyword in a global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_sigalgs(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
				   char **err)
{
	char **target;

	target = (args[0][12] == 'b') ? &global_ssl.listen_default_sigalgs : &global_ssl.connect_default_sigalgs;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a curves suite as an arguments.", args[0]);
		return -1;
	}

	free(*target);
	*target = strdup(args[1]);
	return 0;
}
#endif

#if defined(SSL_CTX_set1_client_sigalgs_list)
/*
 * parse the "ssl-default-bind-client-sigalgs" keyword in a global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_client_sigalgs(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
				   char **err)
{
	char **target;

	target = (args[0][12] == 'b') ? &global_ssl.listen_default_client_sigalgs : &global_ssl.connect_default_client_sigalgs;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects signature algorithms as an arguments.", args[0]);
		return -1;
	}

	free(*target);
	*target = strdup(args[1]);
	return 0;
}
#endif

/* parse various global tune.ssl settings consisting in positive integers.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_int(char **args, int section_type, struct proxy *curpx,
                                const struct proxy *defpx, const char *file, int line,
                                char **err)
{
	int *target;

	if (strcmp(args[0], "tune.ssl.cachesize") == 0)
		target = &global.tune.sslcachesize;
	else if (strcmp(args[0], "tune.ssl.maxrecord") == 0)
		target = (int *)&global_ssl.max_record;
	else if (strcmp(args[0], "tune.ssl.hard-maxrecord") == 0)
		target = (int *)&global_ssl.hard_max_record;
	else if (strcmp(args[0], "tune.ssl.ssl-ctx-cache-size") == 0)
		target = &global_ssl.ctx_cache;
	else if (strcmp(args[0], "maxsslconn") == 0)
		target = &global.maxsslconn;
	else if (strcmp(args[0], "tune.ssl.capture-buffer-size") == 0)
		target = &global_ssl.capture_buffer_size;
	else if (strcmp(args[0], "tune.ssl.capture-cipherlist-size") == 0) {
		target = &global_ssl.capture_buffer_size;
		ha_warning("parsing [%s:%d]: '%s' is deprecated and will be removed in version 2.7. Please use 'tune.ssl.capture-buffer-size' instead.\n",
		           file, line, args[0]);
	}
	else {
		memprintf(err, "'%s' keyword not unhandled (please report this bug).", args[0]);
		return -1;
	}

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an integer argument.", args[0]);
		return -1;
	}

	*target = atoi(args[1]);
	if (*target < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

static int ssl_parse_global_capture_buffer(char **args, int section_type, struct proxy *curpx,
                                           const struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	int ret;

	ret = ssl_parse_global_int(args, section_type, curpx, defpx, file, line, err);
	if (ret != 0)
		return ret;

	if (pool_head_ssl_capture) {
		memprintf(err, "'%s' is already configured.", args[0]);
		return -1;
	}

	pool_head_ssl_capture = create_pool("ssl-capture", sizeof(struct ssl_capture) + global_ssl.capture_buffer_size, MEM_F_SHARED);
	if (!pool_head_ssl_capture) {
		memprintf(err, "Out of memory error.");
		return -1;
	}
	return 0;
}

/* init the SSLKEYLOGFILE pool */
#ifdef HAVE_SSL_KEYLOG
static int ssl_parse_global_keylog(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global_ssl.keylog = 1;
	else if (strcmp(args[1], "off") == 0)
		global_ssl.keylog = 0;
	else {
		memprintf(err, "'%s' expects either 'on' or 'off' but got '%s'.", args[0], args[1]);
		return -1;
	}

	if (pool_head_ssl_keylog) /* already configured */
		return 0;

	pool_head_ssl_keylog = create_pool("ssl-keylogfile", sizeof(struct ssl_keylog), MEM_F_SHARED);
	if (!pool_head_ssl_keylog) {
		memprintf(err, "Out of memory error.");
		return -1;
	}

	pool_head_ssl_keylog_str = create_pool("ssl-keylogfile-str", sizeof(char) * SSL_KEYLOG_MAX_SECRET_SIZE, MEM_F_SHARED);
	if (!pool_head_ssl_keylog_str) {
		memprintf(err, "Out of memory error.");
		return -1;
	}

	return 0;
}
#else
static int ssl_parse_global_keylog(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	memprintf(err, "'%s' requires at least OpenSSL 1.1.1.", args[0]);
	return -1;
}
#endif

/* parse "ssl.force-private-cache".
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_private_cache(char **args, int section_type, struct proxy *curpx,
                                          const struct proxy *defpx, const char *file, int line,
                                          char **err)
{
	if (too_many_args(0, args, err, NULL))
		return -1;

	global_ssl.private_cache = 1;
	return 0;
}

/* parse "ssl.lifetime".
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_lifetime(char **args, int section_type, struct proxy *curpx,
                                     const struct proxy *defpx, const char *file, int line,
                                     char **err)
{
	const char *res;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects ssl sessions <lifetime> in seconds as argument.", args[0]);
		return -1;
	}

	res = parse_time_err(args[1], &global_ssl.life_time, TIME_UNIT_S);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to <%s> (maximum value is 2147483647 s or ~68 years).",
			  args[1], args[0]);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to <%s> (minimum non-null value is 1 s).",
			  args[1], args[0]);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in argument to <%s>.", *res, args[0]);
		return -1;
	}
	return 0;
}

#ifndef OPENSSL_NO_DH
/* parse "ssl-dh-param-file".
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_dh_param_file(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a file path as an argument.", args[0]);
		return -1;
	}

	if (ssl_sock_load_global_dh_param_from_file(args[1])) {
		memprintf(err, "'%s': unable to load DH parameters from file <%s>.", args[0], args[1]);
		return -1;
	}
	return 0;
}

#endif

/* parse "ssl.default-dh-param".
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_default_dh(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
#ifndef OPENSSL_NO_DH

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an integer argument.", args[0]);
		return -1;
	}

	global_ssl.default_dh_param = atoi(args[1]);
	if (global_ssl.default_dh_param < 1024) {
		memprintf(err, "'%s' expects a value >= 1024.", args[0]);
		return -1;
	}
	return 0;
#else
	memprintf(err, "'%s' is not supported by %s, keyword ignored", args[0], OpenSSL_version(OPENSSL_VERSION));
	return ERR_WARN;
#endif

}


/*
 * parse "ssl-load-extra-files".
 * multiple arguments are allowed: "bundle", "sctl", "ocsp", "issuer", "all", "none"
 */
static int ssl_parse_global_extra_files(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	int i;
	int gf = SSL_GF_NONE;

	if (*(args[1]) == 0)
		goto err_arg;

	for (i = 1; *args[i]; i++) {

		if (strcmp("bundle", args[i]) == 0) {
			gf |= SSL_GF_BUNDLE;

		} else if (strcmp("sctl", args[i]) == 0) {
			gf |= SSL_GF_SCTL;

		} else if (strcmp("ocsp", args[i]) == 0){
			gf |= SSL_GF_OCSP;

		} else if (strcmp("issuer", args[i]) == 0){
			gf |= SSL_GF_OCSP_ISSUER;

		} else if (strcmp("key", args[i]) == 0) {
			gf |= SSL_GF_KEY;

		} else if (strcmp("none", args[i]) == 0) {
			if (gf != SSL_GF_NONE)
				goto err_alone;
			gf = SSL_GF_NONE;
			i++;
			break;

		} else if (strcmp("all", args[i]) == 0) {
			if (gf != SSL_GF_NONE)
				goto err_alone;
			gf = SSL_GF_ALL;
			i++;
			break;
		} else {
			goto err_arg;
		}
	}
	/* break from loop but there are still arguments */
	if (*args[i])
		goto err_alone;

	global_ssl.extra_files = gf;

	return 0;

err_alone:
	memprintf(err, "'%s' 'none' and 'all' can be only used alone", args[0]);
	return -1;

err_arg:
	memprintf(err, "'%s' expects one or multiple arguments (none, all, bundle, sctl, ocsp, issuer).", args[0]);
	return -1;
}


/* parse 'ssl-load-extra-del-ext */
static int ssl_parse_global_extra_noext(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	global_ssl.extra_files_noext = 1;
	return 0;
}


/* parse 'ssl-passphrase-cmd' */
static int ssl_parse_global_passphrase_cmd(char **args, int section_type, struct proxy *curpx,
					   const struct proxy *defpx, const char *file, int line,
					   char **err)
{
	int arg_cnt = 0;
	int i;

	if (!*args[1]) {
		memprintf(err, "global statement '%s' expects a command line to a passphrase-providing tool (script/binary...) and its arguments.", args[0]);
		return 1;
	}

	for (; *args[arg_cnt + 2]; ++arg_cnt)
		;

	/* The first argument, by convention, should point to the filename
	 * associated with the file being executed. The array of pointers must
	 * be terminated by a null pointer.
	 * The certificate path will also be passed as first arg so we must
	 * leave enough space .
	 */
	global_ssl.passphrase_cmd_args_cnt = arg_cnt + 1 + 1 + 1;

	global_ssl.passphrase_cmd = calloc(global_ssl.passphrase_cmd_args_cnt, sizeof(*global_ssl.passphrase_cmd));
	if (!global_ssl.passphrase_cmd) {
		memprintf(err, "'%s' : Could not allocate memory", args[0]);
		return ERR_ALERT | ERR_FATAL;
	}

	global_ssl.passphrase_cmd[0] = strdup(args[1]);

	if (!global_ssl.passphrase_cmd[0]) {
		memprintf(err, "'%s' : Could not allocate memory", args[0]);
		goto err_alloc;
	}

	for (i = 0; i < arg_cnt; ++i) {
		/* The first two slots have a special use, they will contain the
		 * command path and the certificate path. */
		global_ssl.passphrase_cmd[i + 2] = strdup(args[i + 2]);
		if (!global_ssl.passphrase_cmd[i + 2]) {
			memprintf(err, "'%s' : Could not allocate memory (command line)", args[0]);
			goto err_alloc;
		}
	}

	return 0;

err_alloc:
	for (i = 0; i < arg_cnt; ++i) {
		ha_free(&global_ssl.passphrase_cmd[i]);
	}
	ha_free(&global_ssl.passphrase_cmd);

	return ERR_ALERT | ERR_FATAL;
}


/***************************** Bind keyword Parsing ********************************************/

/* for ca-file and ca-verify-file */
static int ssl_bind_parse_ca_file_common(char **args, int cur_arg, char **ca_file_p, int from_cli, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing CAfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && (*args[cur_arg + 1] != '@') && global_ssl.ca_base)
		memprintf(ca_file_p, "%s/%s", global_ssl.ca_base, args[cur_arg + 1]);
	else
		memprintf(ca_file_p, "%s", args[cur_arg + 1]);

	if (!ssl_store_load_locations_file(*ca_file_p, !from_cli, CAFILE_CERT)) {
		memprintf(err, "'%s' : unable to load %s", args[cur_arg], *ca_file_p);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}

/* parse the "ca-file" bind keyword */
static int ssl_bind_parse_ca_file(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	return ssl_bind_parse_ca_file_common(args, cur_arg, &conf->ca_file, from_cli, err);
}
static int bind_parse_ca_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ca_file(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "ca-verify-file" bind keyword */
static int ssl_bind_parse_ca_verify_file(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	return ssl_bind_parse_ca_file_common(args, cur_arg, &conf->ca_verify_file, from_cli, err);
}
static int bind_parse_ca_verify_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ca_verify_file(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "ca-sign-file" bind keyword */
static int bind_parse_ca_sign_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing CAfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && (*args[cur_arg + 1] != '@') && global_ssl.ca_base)
		memprintf(&conf->ca_sign_file, "%s/%s", global_ssl.ca_base, args[cur_arg + 1]);
	else
		memprintf(&conf->ca_sign_file, "%s", args[cur_arg + 1]);

	return 0;
}

/* parse the "ca-sign-pass" bind keyword */
static int bind_parse_ca_sign_pass(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing CAkey password", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	memprintf(&conf->ca_sign_pass, "%s", args[cur_arg + 1]);
	return 0;
}

/* parse the "ciphers" bind keyword */
static int ssl_bind_parse_ciphers(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->ciphers);
	conf->ciphers = strdup(args[cur_arg + 1]);
	return 0;
}
static int bind_parse_ciphers(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ciphers(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "ciphersuites" bind keyword */
static int ssl_bind_parse_ciphersuites(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->ciphersuites);
	conf->ciphersuites = strdup(args[cur_arg + 1]);
	return 0;
#else
	memprintf(err, "'%s' keyword not supported for this SSL library version (%s).", args[cur_arg], OPENSSL_VERSION_TEXT);
	return ERR_ALERT | ERR_FATAL;
#endif
}

static int bind_parse_ciphersuites(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ciphersuites(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "crt" bind keyword. Returns a set of ERR_* flags possibly with an error in <err>. */
static int bind_parse_crt(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char path[MAXPATHLEN];
	int default_crt = *args[cur_arg] == 'd' ? CKCH_INST_EXPL_DEFAULT : CKCH_INST_NO_DEFAULT;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate location", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '@') && (*args[cur_arg + 1] != '/' ) && global_ssl.crt_base) {
		if ((strlen(global_ssl.crt_base) + 1 + strlen(args[cur_arg + 1]) + 1) > sizeof(path) ||
		    snprintf(path, sizeof(path), "%s/%s",  global_ssl.crt_base, args[cur_arg + 1]) > sizeof(path)) {
			memprintf(err, "'%s' : path too long", args[cur_arg]);
			return ERR_ALERT | ERR_FATAL;
		}
		return ssl_sock_load_cert(path, conf, default_crt, err);
	}

	return ssl_sock_load_cert(args[cur_arg + 1], conf, default_crt, err);
}

/* parse the "crt-list" bind keyword. Returns a set of ERR_* flags possibly with an error in <err>. */
static int bind_parse_crt_list(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int err_code;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate location", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	err_code = ssl_sock_load_cert_list_file(args[cur_arg + 1], 0, conf, px, err);
	if (err_code)
		memprintf(err, "'%s' : %s", args[cur_arg], *err);

	return err_code;
}

/* parse the "crl-file" bind keyword */
static int ssl_bind_parse_crl_file(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
#ifndef X509_V_FLAG_CRL_CHECK
	memprintf(err, "'%s' : library does not support CRL verify", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing CRLfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && (*args[cur_arg + 1] != '@') && global_ssl.ca_base)
		memprintf(&conf->crl_file, "%s/%s", global_ssl.ca_base, args[cur_arg + 1]);
	else
		memprintf(&conf->crl_file, "%s", args[cur_arg + 1]);

	if (!ssl_store_load_locations_file(conf->crl_file, !from_cli, CAFILE_CRL)) {
		memprintf(err, "'%s' : unable to load %s", args[cur_arg], conf->crl_file);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
#endif
}
static int bind_parse_crl_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_crl_file(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "curves" bind keyword keyword */
static int ssl_bind_parse_curves(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
#if defined(SSL_CTX_set1_curves_list)
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing curve suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	conf->curves = strdup(args[cur_arg + 1]);
	return 0;
#else
	memprintf(err, "'%s' : library does not support curve suite", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}
static int bind_parse_curves(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_curves(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "ktls" bind keyword */
static int ssl_bind_parse_ktls(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' expects \"on\" or \"off\" as an argument.",
			  args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (!experimental_directives_allowed) {
		memprintf(err, "'%s' directive is experimental, must be allowed via a global 'expose-experimental-directive'", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (!strcasecmp(args[cur_arg + 1], "on")) {
		conf->ktls = 1;
	} else if (!strcasecmp(args[cur_arg + 1], "off")) {
		conf->ktls = 0;
	} else {
		memprintf(err, "'%s' expects \"on\" or \"off\" as an argument, got '%s'.",
			  args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}
	mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);
	return 0;

}

static int bind_parse_ktls(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ktls(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "sigalgs" bind keyword */
static int ssl_bind_parse_sigalgs(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
#if defined(SSL_CTX_set1_sigalgs_list)
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing signature algorithm list", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	conf->sigalgs = strdup(args[cur_arg + 1]);
	return 0;
#else
	memprintf(err, "'%s' : library does not support setting signature algorithms", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}
static int bind_parse_sigalgs(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_sigalgs(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "client-sigalgs" bind keyword */
static int ssl_bind_parse_client_sigalgs(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
#if defined(SSL_CTX_set1_client_sigalgs_list)
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing signature algorithm list", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	conf->client_sigalgs = strdup(args[cur_arg + 1]);
	return 0;
#else
	memprintf(err, "'%s' : library does not support setting signature algorithms", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}
static int bind_parse_client_sigalgs(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_client_sigalgs(args, cur_arg, px, &conf->ssl_conf, 0, err);
}


/* parse the "ecdhe" bind keyword keyword */
static int ssl_bind_parse_ecdhe(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
#if !defined(SSL_CTX_set_tmp_ecdh)
	memprintf(err, "'%s' : library does not support elliptic curve Diffie-Hellman (too old)", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#elif defined(OPENSSL_NO_ECDH)
	memprintf(err, "'%s' : library does not support elliptic curve Diffie-Hellman (disabled via OPENSSL_NO_ECDH)", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing named curve", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->ecdhe = strdup(args[cur_arg + 1]);

	return 0;
#endif
}
static int bind_parse_ecdhe(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ecdhe(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "crt-ignore-err" and "ca-ignore-err" bind keywords */
static int bind_parse_ignore_err(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int code;
	char *s1 = NULL, *s2 = NULL;
	char *token = NULL;
	char *p = args[cur_arg + 1];
	char *str;
	unsigned long long *ignerr = conf->crt_ignerr_bitfield;

	if (!*p) {
		memprintf(err, "'%s' : missing error IDs list", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg], "ca-ignore-err") == 0)
		ignerr = conf->ca_ignerr_bitfield;

	if (strcmp(p, "all") == 0) {
		cert_ignerr_bitfield_set_all(ignerr);
		return 0;
	}

	/* copy the string to be able to dump the complete one in case of
	 * error, because strtok_r is writing \0 inside. */
	str = strdup(p);
	if (!str) {
		memprintf(err, "'%s' : Could not allocate memory", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	s1 = str;
	while ((token = strtok_r(s1, ",", &s2))) {
		s1 = NULL;
		if (isdigit((int)*token)) {
			code = atoi(token);
			if ((code <= 0) || (code > SSL_MAX_VFY_ERROR_CODE)) {
				memprintf(err, "'%s' : ID '%d' out of range (1..%d) in error IDs list '%s'",
				          args[cur_arg], code, SSL_MAX_VFY_ERROR_CODE, args[cur_arg + 1]);
				free(str);
				return ERR_ALERT | ERR_FATAL;
			}
		} else {
			code = x509_v_err_str_to_int(token);
			if (code < 0) {
				memprintf(err, "'%s' : error constant '%s' unknown in error IDs list '%s'",
					  args[cur_arg], token, args[cur_arg + 1]);
				free(str);
				return ERR_ALERT | ERR_FATAL;
			}
		}
		cert_ignerr_bitfield_set(ignerr, code);
	}

	free(str);
	return 0;
}

/* parse tls_method_options "no-xxx" and "force-xxx" */
static int parse_tls_method_options(char *arg, struct tls_version_filter *methods, char **err)
{
	uint16_t v;
	char *p;
	p = strchr(arg, '-');
	if (!p)
		goto fail;
	p++;
	if (strcmp(p, "sslv3") == 0)
		v = CONF_SSLV3;
	else if (strcmp(p, "tlsv10") == 0)
		v = CONF_TLSV10;
	else if (strcmp(p, "tlsv11") == 0)
		v = CONF_TLSV11;
	else if (strcmp(p, "tlsv12") == 0)
		v = CONF_TLSV12;
	else if (strcmp(p, "tlsv13") == 0)
		v = CONF_TLSV13;
	else
		goto fail;
	if (!strncmp(arg, "no-", 3))
		methods->flags |= methodVersions[v].flag;
	else if (!strncmp(arg, "force-", 6))
		methods->min = methods->max = v;
	else
		goto fail;
	return 0;
 fail:
	memprintf(err, "'%s' : option not implemented", arg);
	return ERR_ALERT | ERR_FATAL;
}

static int bind_parse_tls_method_options(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return parse_tls_method_options(args[cur_arg], &conf->ssl_conf.ssl_methods, err);
}

static int srv_parse_tls_method_options(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	return parse_tls_method_options(args[*cur_arg], &newsrv->ssl_ctx.methods, err);
}

/* parse tls_method min/max: "ssl-min-ver" and "ssl-max-ver" */
static int parse_tls_method_minmax(char **args, int cur_arg, struct tls_version_filter *methods, char **err)
{
	uint16_t i, v = 0;
	char *argv = args[cur_arg + 1];
	if (!*argv) {
		memprintf(err, "'%s' : missing the ssl/tls version", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++)
		if (strcmp(argv, methodVersions[i].name) == 0)
			v = i;
	if (!v) {
		memprintf(err, "'%s' : unknown ssl/tls version", args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (strcmp("ssl-min-ver", args[cur_arg]) == 0)
		methods->min = v;
	else if (strcmp("ssl-max-ver", args[cur_arg]) == 0)
		methods->max = v;
	else {
		memprintf(err, "'%s' : option not implemented", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}

static int ssl_bind_parse_tls_method_minmax(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	int ret;

#if (HA_OPENSSL_VERSION_NUMBER < 0x10101000L) && !defined(OPENSSL_IS_BORINGSSL)
	ha_warning("crt-list: ssl-min-ver and ssl-max-ver are not supported with this Openssl version (skipped).\n");
#endif
	ret = parse_tls_method_minmax(args, cur_arg, &conf->ssl_methods_cfg, err);
	if (ret != ERR_NONE)
		return ret;

	conf->ssl_methods.min = conf->ssl_methods_cfg.min;
	conf->ssl_methods.max = conf->ssl_methods_cfg.max;

	return ret;
}
static int bind_parse_tls_method_minmax(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return parse_tls_method_minmax(args, cur_arg, &conf->ssl_conf.ssl_methods, err);
}

static int srv_parse_tls_method_minmax(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	return parse_tls_method_minmax(args, *cur_arg, &newsrv->ssl_ctx.methods, err);
}

/* parse the "no-tls-tickets" and "tls-tickets" bind keywords */
static int bind_parse_no_tls_tickets(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (strncmp(args[cur_arg], "no-", 3) == 0)
		conf->ssl_options |= BC_SSL_O_NO_TLS_TICKETS;
	else
		conf->ssl_options &= ~BC_SSL_O_NO_TLS_TICKETS;
	return 0;
}

/* parse the "allow-0rtt" bind keyword */
static int ssl_bind_parse_allow_0rtt(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	conf->early_data = 1;
	return 0;
}

static int bind_parse_allow_0rtt(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_conf.early_data = 1;
	return 0;
}

/* parse the "npn" bind keyword */
static int ssl_bind_parse_npn(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	char *p1, *p2;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing the comma-delimited NPN protocol suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->npn_str);

	/* the NPN string is built as a suite of (<len> <name>)*,
	 * so we reuse each comma to store the next <len> and need
	 * one more for the end of the string.
	 */
	conf->npn_len = strlen(args[cur_arg + 1]) + 1;
	conf->npn_str = calloc(1, conf->npn_len + 1);
	if (!conf->npn_str) {
		memprintf(err, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}

	memcpy(conf->npn_str + 1, args[cur_arg + 1], conf->npn_len);

	/* replace commas with the name length */
	p1 = conf->npn_str;
	p2 = p1 + 1;
	while (1) {
		p2 = memchr(p1 + 1, ',', conf->npn_str + conf->npn_len - (p1 + 1));
		if (!p2)
			p2 = p1 + 1 + strlen(p1 + 1);

		if (p2 - (p1 + 1) > 255) {
			*p2 = '\0';
			memprintf(err, "'%s' : NPN protocol name too long : '%s'", args[cur_arg], p1 + 1);
			return ERR_ALERT | ERR_FATAL;
		}

		*p1 = p2 - (p1 + 1);
		p1 = p2;

		if (!*p2)
			break;

		*(p2++) = '\0';
	}
	return 0;
#else
	memprintf(err, "'%s' : library does not support TLS NPN extension", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

static int bind_parse_npn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_npn(args, cur_arg, px, &conf->ssl_conf, 0, err);
}


/* Parses a alpn string and converts it to the right format for the SSL api */
int ssl_sock_parse_alpn(char *arg, char **alpn_str, int *alpn_len, char **err)
{
	char *p1, *p2, *alpn = NULL;
	int len, ret = 0;

	*alpn_str = NULL;
	*alpn_len = 0;

	if (!*arg) {
		memprintf(err, "missing the comma-delimited ALPN protocol suite");
		goto error;
	}

	/* the ALPN string is built as a suite of (<len> <name>)*,
	 * so we reuse each comma to store the next <len> and need
	 * one more for the end of the string.
	 */
	len  = strlen(arg) + 1;
	alpn = calloc(1, len+1);
	if (!alpn) {
		memprintf(err, "'%s' : out of memory", arg);
		goto error;
	}
	memcpy(alpn+1, arg, len);

	/* replace commas with the name length */
	p1 = alpn;
	p2 = p1 + 1;
	while (1) {
		p2 = memchr(p1 + 1, ',', alpn + len - (p1 + 1));
		if (!p2)
			p2 = p1 + 1 + strlen(p1 + 1);

		if (p2 - (p1 + 1) > 255) {
			*p2 = '\0';
			memprintf(err, "ALPN protocol name too long : '%s'", p1 + 1);
			goto error;
		}

		*p1 = p2 - (p1 + 1);
		p1 = p2;

		if (!*p2)
			break;

		*(p2++) = '\0';
	}

	*alpn_str = alpn;
	*alpn_len = len;

  out:
	return ret;

  error:
	free(alpn);
	ret = ERR_ALERT | ERR_FATAL;
	goto out;
}

/* parse the "alpn" bind keyword */
static int ssl_bind_parse_alpn(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	int ret;

	free(conf->alpn_str);

	ret = ssl_sock_parse_alpn(args[cur_arg + 1], &conf->alpn_str, &conf->alpn_len, err);
	if (ret)
		memprintf(err, "'%s' : %s", args[cur_arg], *err);
	return ret;
#else
	memprintf(err, "'%s' : library does not support TLS ALPN extension", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

static int bind_parse_alpn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_alpn(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "ssl" bind keyword */
static int bind_parse_ssl(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->options |= BC_O_USE_SSL;

	if (global_ssl.listen_default_ciphers && !conf->ssl_conf.ciphers)
		conf->ssl_conf.ciphers = strdup(global_ssl.listen_default_ciphers);
#if defined(SSL_CTX_set1_curves_list)
	if (global_ssl.listen_default_curves && !conf->ssl_conf.curves)
		conf->ssl_conf.curves = strdup(global_ssl.listen_default_curves);
#endif
#if defined(SSL_CTX_set1_sigalgs_list)
	if (global_ssl.listen_default_sigalgs && !conf->ssl_conf.sigalgs)
		conf->ssl_conf.sigalgs = strdup(global_ssl.listen_default_sigalgs);
#endif
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	if (global_ssl.listen_default_ciphersuites && !conf->ssl_conf.ciphersuites)
		conf->ssl_conf.ciphersuites = strdup(global_ssl.listen_default_ciphersuites);
#endif
	conf->ssl_options |= global_ssl.listen_default_ssloptions;
	conf->ssl_conf.ssl_methods.flags |= global_ssl.listen_default_sslmethods.flags;
	if (!conf->ssl_conf.ssl_methods.min)
		conf->ssl_conf.ssl_methods.min = global_ssl.listen_default_sslmethods.min;
	if (!conf->ssl_conf.ssl_methods.max)
		conf->ssl_conf.ssl_methods.max = global_ssl.listen_default_sslmethods.max;

	return 0;
}

/* parse the "prefer-client-ciphers" bind keyword */
static int bind_parse_pcc(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
        conf->ssl_options |= BC_SSL_O_PREF_CLIE_CIPH;
        return 0;
}

/* parse the "generate-certificates" bind keyword */
static int bind_parse_generate_certs(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#if (defined SSL_CTRL_SET_TLSEXT_HOSTNAME && !defined SSL_NO_GENERATE_CERTIFICATES)
	conf->options |= BC_O_GENERATE_CERTS;
#else
	memprintf(err, "%sthis version of openssl cannot generate SSL certificates.\n",
		  err && *err ? *err : "");
#endif
	return 0;
}

/* parse the "strict-sni" and "no-strict-sni" bind keywords */
static int bind_parse_strict_sni(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (strncmp(args[cur_arg], "no-", 3) != 0)
		conf->ssl_options |= BC_SSL_O_STRICT_SNI;
	else
		conf->ssl_options &= ~BC_SSL_O_STRICT_SNI;
	return 0;
}

/* parse the "tls-ticket-keys" bind keyword */
static int bind_parse_tls_ticket_keys(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
	FILE *f = NULL;
	int i = 0;
	char thisline[LINESIZE];
	struct tls_keys_ref *keys_ref = NULL;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing TLS ticket keys file path", args[cur_arg]);
		goto fail;
	}

	keys_ref = tlskeys_ref_lookup(args[cur_arg + 1]);
	if (keys_ref) {
		keys_ref->refcount++;
		conf->keys_ref = keys_ref;
		return 0;
	}

	keys_ref = calloc(1, sizeof(*keys_ref));
	if (!keys_ref) {
		memprintf(err, "'%s' : allocation error", args[cur_arg+1]);
		goto fail;
	}

	keys_ref->tlskeys = malloc(TLS_TICKETS_NO * sizeof(union tls_sess_key));
	if (!keys_ref->tlskeys) {
		memprintf(err, "'%s' : allocation error", args[cur_arg+1]);
		goto fail;
	}

	if ((f = fopen(args[cur_arg + 1], "r")) == NULL) {
		memprintf(err, "'%s' : unable to load ssl tickets keys file", args[cur_arg+1]);
		goto fail;
	}

	keys_ref->filename = strdup(args[cur_arg + 1]);
	if (!keys_ref->filename) {
		memprintf(err, "'%s' : allocation error", args[cur_arg+1]);
		goto fail;
	}

	keys_ref->key_size_bits = 0;
	while (fgets(thisline, sizeof(thisline), f) != NULL) {
		int len = strlen(thisline);
		int dec_size;

		/* Strip newline characters from the end */
		if(thisline[len - 1] == '\n')
			thisline[--len] = 0;

		if(thisline[len - 1] == '\r')
			thisline[--len] = 0;

		dec_size = base64dec(thisline, len, (char *) (keys_ref->tlskeys + i % TLS_TICKETS_NO), sizeof(union tls_sess_key));
		if (dec_size < 0) {
			memprintf(err, "'%s' : unable to decode base64 key on line %d", args[cur_arg+1], i + 1);
			goto fail;
		}
		else if (!keys_ref->key_size_bits && (dec_size == sizeof(struct tls_sess_key_128))) {
			keys_ref->key_size_bits = 128;
		}
		else if (!keys_ref->key_size_bits && (dec_size == sizeof(struct tls_sess_key_256))) {
			keys_ref->key_size_bits = 256;
		}
		else if (((dec_size != sizeof(struct tls_sess_key_128)) && (dec_size != sizeof(struct tls_sess_key_256)))
			 || ((dec_size == sizeof(struct tls_sess_key_128) && (keys_ref->key_size_bits != 128)))
			 || ((dec_size == sizeof(struct tls_sess_key_256) && (keys_ref->key_size_bits != 256)))) {
			memprintf(err, "'%s' : wrong sized key on line %d", args[cur_arg+1], i + 1);
			goto fail;
		}
		i++;
	}

	if (i < TLS_TICKETS_NO) {
		memprintf(err, "'%s' : please supply at least %d keys in the tls-tickets-file", args[cur_arg+1], TLS_TICKETS_NO);
		goto fail;
	}

	fclose(f);

	/* Use penultimate key for encryption, handle when TLS_TICKETS_NO = 1 */
	i -= 2;
	keys_ref->tls_ticket_enc_index = i < 0 ? 0 : i % TLS_TICKETS_NO;
	keys_ref->unique_id = -1;
	keys_ref->refcount = 1;
	HA_RWLOCK_INIT(&keys_ref->lock);
	conf->keys_ref = keys_ref;

	LIST_INSERT(&tlskeys_reference, &keys_ref->list);

	return 0;

  fail:
	if (f)
		fclose(f);
	if (keys_ref) {
		free(keys_ref->filename);
		free(keys_ref->tlskeys);
		free(keys_ref);
	}
	return ERR_ALERT | ERR_FATAL;

#else
	memprintf(err, "'%s' : TLS ticket callback extension not supported", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif /* SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB */
}

/* parse the "verify" bind keyword */
static int ssl_bind_parse_verify(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing verify method", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg + 1], "none") == 0)
		conf->verify = SSL_SOCK_VERIFY_NONE;
	else if (strcmp(args[cur_arg + 1], "optional") == 0)
		conf->verify = SSL_SOCK_VERIFY_OPTIONAL;
	else if (strcmp(args[cur_arg + 1], "required") == 0)
		conf->verify = SSL_SOCK_VERIFY_REQUIRED;
	else {
		memprintf(err, "'%s' : unknown verify method '%s', only 'none', 'optional', and 'required' are supported\n",
		          args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}
static int bind_parse_verify(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_verify(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/* parse the "no-alpn" ssl-bind keyword, storing an empty ALPN string */
static int ssl_bind_parse_no_alpn(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	free(conf->alpn_str);
	conf->alpn_len = 0;
	conf->alpn_str = strdup("");

	if (!conf->alpn_str) {
		memprintf(err, "'%s' : out of memory", *args);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}

/* parse the "no-alpn" bind keyword, storing an empty ALPN string */
static int bind_parse_no_alpn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_no_alpn(args, cur_arg, px, &conf->ssl_conf, 0, err);
}


/* parse the "no-ca-names" bind keyword */
static int ssl_bind_parse_no_ca_names(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	conf->no_ca_names = 1;
	return 0;
}

static int bind_parse_no_ca_names(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_no_ca_names(args, cur_arg, px, &conf->ssl_conf, 0, err);
}

/***************************** "server" keywords Parsing ********************************************/

/* parse the "npn" bind keyword */
static int srv_parse_npn(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	char *p1, *p2;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing the comma-delimited NPN protocol suite", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->ssl_ctx.npn_str);

	/* the NPN string is built as a suite of (<len> <name>)*,
	 * so we reuse each comma to store the next <len> and need
	 * one more for the end of the string.
	 */
	newsrv->ssl_ctx.npn_len = strlen(args[*cur_arg + 1]) + 1;
	newsrv->ssl_ctx.npn_str = calloc(1, newsrv->ssl_ctx.npn_len + 1);
	if (!newsrv->ssl_ctx.npn_str) {
		memprintf(err, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}

	memcpy(newsrv->ssl_ctx.npn_str + 1, args[*cur_arg + 1],
	    newsrv->ssl_ctx.npn_len);

	/* replace commas with the name length */
	p1 = newsrv->ssl_ctx.npn_str;
	p2 = p1 + 1;
	while (1) {
		p2 = memchr(p1 + 1, ',', newsrv->ssl_ctx.npn_str +
		    newsrv->ssl_ctx.npn_len - (p1 + 1));
		if (!p2)
			p2 = p1 + 1 + strlen(p1 + 1);

		if (p2 - (p1 + 1) > 255) {
			*p2 = '\0';
			memprintf(err, "'%s' : NPN protocol name too long : '%s'", args[*cur_arg], p1 + 1);
			return ERR_ALERT | ERR_FATAL;
		}

		*p1 = p2 - (p1 + 1);
		p1 = p2;

		if (!*p2)
			break;

		*(p2++) = '\0';
	}
	return 0;
#else
	memprintf(err, "'%s' : library does not support TLS NPN extension", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int parse_alpn(char *alpn, char **out_alpn_str, int *out_alpn_len, char **err)
{
	free(*out_alpn_str);
	return ssl_sock_parse_alpn(alpn, out_alpn_str, out_alpn_len, err);
}
#endif

/* parse the "alpn" server keyword */
static int srv_parse_alpn(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	int ret = parse_alpn(args[*cur_arg + 1],
	                     &newsrv->ssl_ctx.alpn_str,
	                     &newsrv->ssl_ctx.alpn_len, err);
	if (ret)
		memprintf(err, "'%s' : %s", args[*cur_arg], *err);
	return ret;
#else
	memprintf(err, "'%s' : library does not support TLS ALPN extension", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* parse the "check-alpn" server keyword */
static int srv_parse_check_alpn(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	int ret = parse_alpn(args[*cur_arg + 1],
	                     &newsrv->check.alpn_str,
	                     &newsrv->check.alpn_len, err);
	if (ret)
		memprintf(err, "'%s' : %s", args[*cur_arg], *err);
	return ret;
#else
	memprintf(err, "'%s' : library does not support TLS ALPN extension", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* parse the "ca-file" server keyword */
static int srv_parse_ca_file(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	const int create_if_none = newsrv->flags & SRV_F_DYNAMIC ? 0 : 1;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing CAfile path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '/') && (*args[*cur_arg + 1] != '@') && global_ssl.ca_base)
		memprintf(&newsrv->ssl_ctx.ca_file, "%s/%s", global_ssl.ca_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.ca_file, "%s", args[*cur_arg + 1]);

	if (!ssl_store_load_locations_file(newsrv->ssl_ctx.ca_file, create_if_none, CAFILE_CERT)) {
		memprintf(err, "'%s' : unable to load %s", args[*cur_arg], newsrv->ssl_ctx.ca_file);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "check-sni" server keyword */
static int srv_parse_check_sni(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing SNI", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->check.sni);
	newsrv->check.sni = strdup(args[*cur_arg + 1]);
	if (!newsrv->check.sni) {
		memprintf(err, "'%s' : failed to allocate memory", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;

}

/* parse the "renegotiate" server keyword */
static int srv_parse_renegotiate(char **args, int *cur_arg, struct proxy *px,
                                 struct server *newsrv, char **err)
{

#if !defined(OPENSSL_IS_AWSLC) && !defined(SSL_OP_NO_RENEGOTIATION)
	memprintf(err, "'%s' not supported for your SSL library (%s), either SSL_OP_NO_RENEGOTIATION or SSL_set_renegotiate_mode() must be defined.",
	          args[0], OPENSSL_VERSION_TEXT);
	return -1;
#endif

	if (strncmp(*args, "no-", 3) == 0)
		newsrv->ssl_ctx.renegotiate = SSL_RENEGOTIATE_OFF;
	else
		newsrv->ssl_ctx.renegotiate = SSL_RENEGOTIATE_ON;

	return 0;
}

/* common function to init ssl_ctx */
static int ssl_sock_init_srv(struct server *s)
{
	if (global_ssl.connect_default_ciphers && !s->ssl_ctx.ciphers)
		s->ssl_ctx.ciphers = strdup(global_ssl.connect_default_ciphers);
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	if (global_ssl.connect_default_ciphersuites && !s->ssl_ctx.ciphersuites) {
		s->ssl_ctx.ciphersuites = strdup(global_ssl.connect_default_ciphersuites);
		if (!s->ssl_ctx.ciphersuites)
			return 1;
	}
#endif
	s->ssl_ctx.options |= global_ssl.connect_default_ssloptions;
	s->ssl_ctx.methods.flags |= global_ssl.connect_default_sslmethods.flags;

	if (!s->ssl_ctx.methods.min)
		s->ssl_ctx.methods.min = global_ssl.connect_default_sslmethods.min;

	if (!s->ssl_ctx.methods.max)
		s->ssl_ctx.methods.max = global_ssl.connect_default_sslmethods.max;

#if defined(SSL_CTX_set1_sigalgs_list)
	if (global_ssl.connect_default_sigalgs && !s->ssl_ctx.sigalgs) {
		s->ssl_ctx.sigalgs = strdup(global_ssl.connect_default_sigalgs);
		if (!s->ssl_ctx.sigalgs)
			return 1;
	}
#endif

#if defined(SSL_CTX_set1_client_sigalgs_list)
	if (global_ssl.connect_default_client_sigalgs && !s->ssl_ctx.client_sigalgs) {
		s->ssl_ctx.client_sigalgs = strdup(global_ssl.connect_default_client_sigalgs);
		if (!s->ssl_ctx.client_sigalgs)
			return 1;
	}
#endif

#if defined(SSL_CTX_set1_curves_list)
	if (global_ssl.connect_default_curves && !s->ssl_ctx.curves) {
		s->ssl_ctx.curves = strdup(global_ssl.connect_default_curves);
		if (!s->ssl_ctx.curves)
			return 1;
	}
#endif

	if (global_ssl.renegotiate && !s->ssl_ctx.renegotiate)
		s->ssl_ctx.renegotiate = global_ssl.renegotiate;

	return 0;
}

/* parse the "check-ssl" server keyword */
static int srv_parse_check_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->check.use_ssl = 1;
	if (ssl_sock_init_srv(newsrv)) {
		memprintf(err, "'%s' : not enough memory", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "ciphers" server keyword */
static int srv_parse_ciphers(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->ssl_ctx.ciphers);
	newsrv->ssl_ctx.ciphers = strdup(args[*cur_arg + 1]);

	if (!newsrv->ssl_ctx.ciphers) {
		memprintf(err, "'%s' : not enough memory", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "ciphersuites" server keyword */
static int srv_parse_ciphersuites(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->ssl_ctx.ciphersuites);
	newsrv->ssl_ctx.ciphersuites = strdup(args[*cur_arg + 1]);

	if (!newsrv->ssl_ctx.ciphersuites) {
		memprintf(err, "'%s' : not enough memory", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
#else /* ! HAVE_SSL_CTX_SET_CIPHERSUITES */
	memprintf(err, "'%s' not supported for your SSL library (%s).", args[*cur_arg], OPENSSL_VERSION_TEXT);
	return ERR_ALERT | ERR_FATAL;

#endif
}

/* parse the "client-sigalgs" server keyword */
static int srv_parse_client_sigalgs(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifndef SSL_CTX_set1_client_sigalgs_list
	memprintf(err, "'%s' : library does not support setting signature algorithms", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' : missing signature algorithm list", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	newsrv->ssl_ctx.client_sigalgs = strdup(arg);
	if (!newsrv->ssl_ctx.client_sigalgs) {
		memprintf(err, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
#endif
}


/* parse the "crl-file" server keyword */
static int srv_parse_crl_file(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifndef X509_V_FLAG_CRL_CHECK
	memprintf(err, "'%s' : library does not support CRL verify", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	const int create_if_none = newsrv->flags & SRV_F_DYNAMIC ? 0 : 1;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing CRLfile path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '/') && (*args[*cur_arg + 1] != '@') && global_ssl.ca_base)
		memprintf(&newsrv->ssl_ctx.crl_file, "%s/%s", global_ssl.ca_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.crl_file, "%s", args[*cur_arg + 1]);

	if (!ssl_store_load_locations_file(newsrv->ssl_ctx.crl_file, create_if_none, CAFILE_CRL)) {
		memprintf(err, "'%s' : unable to load %s", args[*cur_arg], newsrv->ssl_ctx.crl_file);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
#endif
}

/* parse the "curves" server keyword */
static int srv_parse_curves(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifndef SSL_CTX_set1_curves_list
	memprintf(err, "'%s' : library does not support setting curves list", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' : missing curves list", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	newsrv->ssl_ctx.curves = strdup(arg);
	if (!newsrv->ssl_ctx.curves) {
		memprintf(err, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
#endif
}

/* parse the "crt" server keyword */
static int srv_parse_crt(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate file path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '@') && (*args[*cur_arg + 1] != '/') && global_ssl.crt_base)
		memprintf(&newsrv->ssl_ctx.client_crt, "%s/%s", global_ssl.crt_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.client_crt, "%s", args[*cur_arg + 1]);

	return 0;
}

/* parse the "check-sni-auto" server keyword */
static int srv_parse_check_sni_auto(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->flags &= ~SRV_F_CHK_NO_AUTO_SNI;
	return 0;
}

/* parse the "no-check-sni-auto" server keyword */
static int srv_parse_no_check_sni_auto(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->flags |= SRV_F_CHK_NO_AUTO_SNI;
	return 0;
}

/* parse the "no-check-ssl" server keyword */
static int srv_parse_no_check_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->check.use_ssl = -1;
	ha_free(&newsrv->ssl_ctx.ciphers);
	newsrv->ssl_ctx.options &= ~global_ssl.connect_default_ssloptions;
	return 0;
}

/* parse the "no-send-proxy-v2-ssl" server keyword */
static int srv_parse_no_send_proxy_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->pp_opts &= ~SRV_PP_V2;
	newsrv->pp_opts &= ~SRV_PP_V2_SSL;
	return 0;
}

/* parse the "no-send-proxy-v2-ssl-cn" server keyword */
static int srv_parse_no_send_proxy_cn(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->pp_opts &= ~SRV_PP_V2;
	newsrv->pp_opts &= ~SRV_PP_V2_SSL;
	newsrv->pp_opts &= ~SRV_PP_V2_SSL_CN;
	return 0;
}

/* parse the "no-ssl" server keyword */
static int srv_parse_no_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	/* if default-server have use_ssl, prepare ssl settings */
	if (newsrv->use_ssl == 1) {
		if (ssl_sock_init_srv(newsrv)) {
			memprintf(err, "'%s' : not enough memory", args[*cur_arg]);
			return ERR_ALERT | ERR_FATAL;
		}
	}
	else {
		ha_free(&newsrv->ssl_ctx.ciphers);
	}
	newsrv->use_ssl = -1;
	return 0;
}

/* parse the "ktls" server keywod */
static int srv_parse_ktls(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' expects \"on\" or \"off\" as an argument.",
			  args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (!experimental_directives_allowed) {
		memprintf(err, "'%s' directive is experimental, must be allowed via a global 'expose-experimental-directive'", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (!strcasecmp(args[*cur_arg + 1], "on")) {
		newsrv->ssl_ctx.options |= SRV_SSL_O_KTLS;
	} else if (!strcasecmp(args[*cur_arg + 1], "off")) {
		newsrv->ssl_ctx.options &= ~SRV_SSL_O_KTLS;
	} else {
		memprintf(err, "'%s' expects \"on\" or \"off\" as an argument, got '%s'.",
			  args[*cur_arg], args[*cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}
	mark_tainted(TAINTED_CONFIG_EXP_KW_DECLARED);
	return 0;
}

/* parse the "allow-0rtt" server keyword */
static int srv_parse_allow_0rtt(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_EARLY_DATA;
	return 0;
}

/* parse the "no-ssl-reuse" server keyword */
static int srv_parse_no_ssl_reuse(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_REUSE;
	return 0;
}

/* parse the "no-tls-tickets" server keyword */
static int srv_parse_no_tls_tickets(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_TLS_TICKETS;
	return 0;
}
/* parse the "send-proxy-v2-ssl" server keyword */
static int srv_parse_send_proxy_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->pp_opts |= SRV_PP_V2;
	newsrv->pp_opts |= SRV_PP_V2_SSL;
	return 0;
}

/* parse the "send-proxy-v2-ssl-cn" server keyword */
static int srv_parse_send_proxy_cn(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->pp_opts |= SRV_PP_V2;
	newsrv->pp_opts |= SRV_PP_V2_SSL;
	newsrv->pp_opts |= SRV_PP_V2_SSL_CN;
	return 0;
}

/* parse the "sigalgs" server keyword */
static int srv_parse_sigalgs(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifndef SSL_CTX_set1_sigalgs_list
	memprintf(err, "'%s' : library does not support setting signature algorithms", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' : missing signature algorithm list", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	newsrv->ssl_ctx.sigalgs = strdup(arg);
	if (!newsrv->ssl_ctx.sigalgs) {
		memprintf(err, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
#endif
}

/* parse the "sni" server keyword */
static int srv_parse_sni(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
	memprintf(err, "'%s' : the current SSL library doesn't support the SNI TLS extension", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' : missing sni expression", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->sni_expr);
	newsrv->sni_expr = strdup(arg);
	if (!newsrv->sni_expr) {
		memprintf(err, "out of memory");
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
#endif
}

/* parse the "sni-auto" server keyword */
static int srv_parse_sni_auto(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options &= ~SRV_SSL_O_NO_AUTO_SNI;
	return 0;
}

/* parse the "no-sni-auto" server keyword */
static int srv_parse_no_sni_auto(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_AUTO_SNI;
	return 0;
}

/* parse the "ssl" server keyword */
static int srv_parse_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->use_ssl = 1;
	if (ssl_sock_init_srv(newsrv)) {
		memprintf(err, "'%s' : not enough memory", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "ssl-reuse" server keyword */
static int srv_parse_ssl_reuse(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options &= ~SRV_SSL_O_NO_REUSE;
	return 0;
}

/* parse the "tls-tickets" server keyword */
static int srv_parse_tls_tickets(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options &= ~SRV_SSL_O_NO_TLS_TICKETS;
	return 0;
}

/* parse the "verify" server keyword */
static int srv_parse_verify(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing verify method", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[*cur_arg + 1], "none") == 0)
		newsrv->ssl_ctx.verify = SSL_SOCK_VERIFY_NONE;
	else if (strcmp(args[*cur_arg + 1], "required") == 0)
		newsrv->ssl_ctx.verify = SSL_SOCK_VERIFY_REQUIRED;
	else {
		memprintf(err, "'%s' : unknown verify method '%s', only 'none' and 'required' are supported\n",
		          args[*cur_arg], args[*cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "verifyhost" server keyword */
static int srv_parse_verifyhost(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing hostname to verify against", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->ssl_ctx.verify_host);
	newsrv->ssl_ctx.verify_host = strdup(args[*cur_arg + 1]);

	if (!newsrv->ssl_ctx.verify_host) {
		memprintf(err, "'%s' : not enough memory", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "ssl-default-bind-options" keyword in global section */
static int ssl_parse_default_bind_options(char **args, int section_type, struct proxy *curpx,
                                          const struct proxy *defpx, const char *file, int line,
                                          char **err) {
	int i = 1;

	if (*(args[i]) == 0) {
		memprintf(err, "global statement '%s' expects an option as an argument.", args[0]);
		return -1;
	}
	while (*(args[i])) {
		if (strcmp(args[i], "no-tls-tickets") == 0)
			global_ssl.listen_default_ssloptions |= BC_SSL_O_NO_TLS_TICKETS;
		else if (strcmp(args[i], "tls-tickets") == 0)
			global_ssl.listen_default_ssloptions &= ~BC_SSL_O_NO_TLS_TICKETS;
		else if (strcmp(args[i], "prefer-client-ciphers") == 0)
			global_ssl.listen_default_ssloptions |= BC_SSL_O_PREF_CLIE_CIPH;
		else if (strcmp(args[i], "strict-sni") == 0)
			global_ssl.listen_default_ssloptions |= BC_SSL_O_STRICT_SNI;
		else if (strcmp(args[i], "no-strict-sni") == 0)
			global_ssl.listen_default_ssloptions &= ~BC_SSL_O_STRICT_SNI;
		else if (strcmp(args[i], "ssl-min-ver") == 0 || strcmp(args[i], "ssl-max-ver") == 0) {
			if (!parse_tls_method_minmax(args, i, &global_ssl.listen_default_sslmethods, err))
				i++;
			else {
				memprintf(err, "%s on global statement '%s'.", *err, args[0]);
				return -1;
			}
		}
		else if (parse_tls_method_options(args[i], &global_ssl.listen_default_sslmethods, err)) {
			memprintf(err, "unknown option '%s' on global statement '%s'.", args[i], args[0]);
			return -1;
		}
		i++;
	}
	return 0;
}

/* parse the "ssl-default-server-options" keyword in global section */
static int ssl_parse_default_server_options(char **args, int section_type, struct proxy *curpx,
                                            const struct proxy *defpx, const char *file, int line,
                                            char **err) {
	int i = 1;

	if (*(args[i]) == 0) {
		memprintf(err, "global statement '%s' expects an option as an argument.", args[0]);
		return -1;
	}
	while (*(args[i])) {
		if (strcmp(args[i], "no-tls-tickets") == 0)
			global_ssl.connect_default_ssloptions |= SRV_SSL_O_NO_TLS_TICKETS;
		else if (strcmp(args[i], "ssl-min-ver") == 0 || strcmp(args[i], "ssl-max-ver") == 0) {
			if (!parse_tls_method_minmax(args, i, &global_ssl.connect_default_sslmethods, err))
				i++;
			else {
				memprintf(err, "%s on global statement '%s'.", *err, args[0]);
				return -1;
			}
		}
		else if (strcmp(args[i], "renegotiate") == 0 || strcmp(args[i], "no-renegotiate") == 0) {
#if !defined(OPENSSL_IS_AWSLC) && !defined(SSL_OP_NO_RENEGOTIATION)
			memprintf(err, "'%s' not supported for your SSL library (%s), either SSL_OP_NO_RENEGOTIATION or SSL_set_renegotiate_mode() must be defined.",
				  args[i], OPENSSL_VERSION_TEXT);
			return -1;
#else
			global_ssl.renegotiate = (*args[i] == 'n') ? SSL_RENEGOTIATE_OFF : SSL_RENEGOTIATE_ON;
#endif
		}
		else if (parse_tls_method_options(args[i], &global_ssl.connect_default_sslmethods, err)) {
			memprintf(err, "unknown option '%s' on global statement '%s'.", args[i], args[0]);
			return -1;
		}
		i++;
	}
	return 0;
}

/* parse the "ca-base" / "crt-base" / "key-base" keywords in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_path_base(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	char **target;

	if (args[0][1] == 'a')
		target = &global_ssl.ca_base;
	else if (args[0][1] == 'r')
		target = &global_ssl.crt_base;
	else if (args[0][1] == 'e')
		target = &global_ssl.key_base;
	else
		return -1;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*target) {
		memprintf(err, "'%s' already specified.", args[0]);
		return -1;
	}

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a directory path as an argument.", args[0]);
		return -1;
	}
	*target = strdup(args[1]);
	return 0;
}

/* parse the "ssl-security-level" keyword in global section.  */
static int ssl_parse_security_level(char **args, int section_type, struct proxy *curpx,
					 const struct proxy *defpx, const char *file, int linenum,
					 char **err)
{
#ifndef HAVE_SSL_SET_SECURITY_LEVEL
	memprintf(err, "global statement '%s' requires at least OpenSSL 1.1.1.", args[0]);
	return -1;
#else
	char *endptr;

	if (!*args[1]) {
		ha_alert("parsing [%s:%d] : '%s' : missing value\n", file, linenum, args[0]);
		return -1;
	}

	global_ssl.security_level = strtol(args[1], &endptr, 10);
	if (*endptr != '\0') {
		ha_alert("parsing [%s:%d] : '%s' : expects an integer argument, found '%s'\n",
			 file, linenum, args[0], args[1]);
		return -1;
	}

	if (global_ssl.security_level < 0 || global_ssl.security_level > 5) {
		ha_alert("parsing [%s:%d] : '%s' : expects a value between 0 and 5\n",
			 file, linenum, args[0]);
		return -1;
	}
#endif

	return 0;
}

/* parse the "ssl-skip-self-issued-ca" keyword in global section.  */
static int ssl_parse_skip_self_issued_ca(char **args, int section_type, struct proxy *curpx,
					 const struct proxy *defpx, const char *file, int line,
					 char **err)
{
#ifdef SSL_CTX_build_cert_chain
	global_ssl.skip_self_issued_ca = 1;
	return 0;
#else
	memprintf(err, "global statement '%s' requires at least OpenSSL 1.0.2.", args[0]);
	return -1;
#endif
}

struct cfg_crt_node {
	int linenum;
	char *filename;
	struct ssl_bind_conf *ssl_conf;
	struct ckch_conf *ckch_conf;
	struct list list;
};

/* list used for inline crt-list initialization */
static struct list cur_crtlist = LIST_HEAD_INIT(cur_crtlist);
/*
 * Parse a "ssl-f-use" line in a frontend.
 */
static int proxy_parse_ssl_f_use(char **args, int section_type, struct proxy *curpx,
                                 const struct proxy *defpx, const char *file, int linenum,
                                 char **err)
{
	int cfgerr = 0;
	struct ssl_bind_conf *ssl_conf = NULL;
	struct ckch_conf *ckch_conf = NULL;
	struct cfg_crt_node *cfg_crt_node = NULL;
	int cur_arg = 1;
	int i;

	cfg_crt_node = calloc(1, sizeof *cfg_crt_node);
	if (!cfg_crt_node) {
		memprintf(err, "not enough memory!");
		goto error;
	}
	cfg_crt_node->filename = strdup(file);
	if (!cfg_crt_node->filename) {
		memprintf(err, "not enough memory!");
		goto error;
	}
	cfg_crt_node->linenum = linenum;


	ckch_conf = calloc(1, sizeof *ckch_conf);
	if (!ckch_conf) {
		memprintf(err, "not enough memory!");
		goto error;
	}

	while (*args[cur_arg]) {
		int foundcrtstore = 0; /* found a crt-store keyword */
		int found = 0;         /* found a crt-list or crt-store keyword */

		if (strcmp("crt", args[cur_arg]) == 0) {
			char path[MAXPATHLEN+1];
			const char *arg = args[cur_arg+1];

			if (ckch_conf->crt) {
				memprintf(err, "'%s' already specified, aborting.", "crt");
				goto error;
			}
			if (*arg != '@' && *arg != '/' && global_ssl.crt_base) {
				if ((strlen(global_ssl.crt_base) + 1 + strlen(arg)) > sizeof(path) ||
				     snprintf(path, sizeof(path), "%s/%s",  global_ssl.crt_base, arg) > sizeof(path)) {
					memprintf(err, "parsing [%s:%d]: '%s' : path too long",
					          file, linenum, arg);
					cfgerr |= ERR_ALERT | ERR_FATAL;
					goto error;
				}
				arg = path;
			}
			free(ckch_conf->crt);
			ckch_conf->crt = strdup(arg);
			cur_arg += 2;
			found = 1;
			goto next;
		}

		/* first look for crt-list keywords */
		for (i = 0; ssl_crtlist_kws[i].kw != NULL; i++) {
			if (strcmp(ssl_crtlist_kws[i].kw, args[cur_arg]) == 0) {

				if (!ssl_conf)
					ssl_conf = calloc(1, sizeof *ssl_conf);
				if (!ssl_conf) {
					memprintf(err, "not enough memory!");
					goto error;
				}

				cfgerr |= ssl_crtlist_kws[i].parse(args, cur_arg, NULL, ssl_conf, 0, err);
				if (cfgerr & ERR_CODE)
					goto error;
				cur_arg += 1 + ssl_crtlist_kws[i].skip;
				found = 1;
				goto next;
			}
		}

		/* then look for ckch_conf keywords */
		cfgerr |= ckch_conf_parse(args, cur_arg, ckch_conf, &foundcrtstore, file, linenum, err);
		if (cfgerr & ERR_CODE)
			goto error;
		if (foundcrtstore) {
			found = 1;
			cur_arg += 2;  /* skip 2 words if the keyword was found */
			ckch_conf->used = CKCH_CONF_SET_CRTLIST; /* if they are options they must be used everywhere */
			goto next;
		}

next:
		if (!found) {
			memprintf(err, "unknown crt keyword '%s'", args[cur_arg]);
			goto error;
		}
	}

	cfg_crt_node->ssl_conf = ssl_conf;
	cfg_crt_node->ckch_conf = ckch_conf;
	LIST_INSERT(&cur_crtlist, &cfg_crt_node->list);

	return 0;
error:
	ckch_conf_clean(ckch_conf);
	ha_free(&ckch_conf);
	ssl_sock_free_ssl_conf(ssl_conf);
	ha_free(&ssl_conf);
	ha_free(&cfg_crt_node->filename);
	ha_free(&cfg_crt_node);
	return -1;
}

/*
 * After parsing the ssl-f-use keywords in a frontend/listen section, create the corresponding crt-list and initialize the
 * certificates
 */

static int post_section_frontend_crt_init()
{
	struct crtlist *newlist = NULL;
	struct crtlist_entry *entry = NULL;
	int err_code = 0;
	struct cfg_crt_node *n, *r;
	struct bind_conf *b;
	char *crtlist_name = NULL;
	char *err = NULL;

	list_for_each_entry_safe(n, r, &cur_crtlist, list) {

		/* create a new crt-list with the frontend name or a specified name */
		if (!crtlist_name)
			memprintf(&crtlist_name, "@%s", curproxy->id);
		if (!crtlist_name) {
			memprintf(&err, "Not enough memory!");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto error;
		}

		if (!newlist)
			newlist = crtlist_new(crtlist_name, 0);
		if (!newlist) {
			memprintf(&err, "Not enough memory!");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto error;
		}

		entry = crtlist_entry_new();
		if (entry == NULL) {
			memprintf(&err, "Not enough memory!");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto error;
		}

		/* must set the ssl_conf in case of duplication of the crtlist_entry */
		entry->ssl_conf = n->ssl_conf;

		err_code |= crtlist_load_crt(n->ckch_conf->crt, n->ckch_conf, newlist, entry, n->filename, n->linenum, &err);
		if (err_code & ERR_CODE)
			goto error;

		LIST_DELETE(&n->list);
		/* n->ssl_conf is reused so we don't free them here */
		free(n->ckch_conf);
		free(n->filename);
		free(n);
	}

	if (newlist) {

		if (ebst_insert(&crtlists_tree, &newlist->node) != &newlist->node) {
			memprintf(&err, "Couldn't create the crt-list '%s', this name is already used by another crt-list!", crtlist_name);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto error;
		}

		/* look for "ssl" bind lines */
		list_for_each_entry(b, &curproxy->conf.bind, by_fe) {
			if (b->options & BC_O_USE_SSL) {
				err_code |= ssl_sock_load_cert_list_file(crtlist_name, 0, b, curproxy, &err);
				if (err_code & ERR_CODE)
					goto error;
			}
		}
	}

	goto end;

error:

	if (err)
		ha_alert("%s.\n", err);
	free(err);

	list_for_each_entry_safe(n, r, &cur_crtlist, list) {
		ckch_conf_clean(n->ckch_conf);
		ha_free(&n->ckch_conf);
		ssl_sock_free_ssl_conf(n->ssl_conf);
		ha_free(&n->ssl_conf);
		LIST_DELETE(&n->list);
		ha_free(&n);
	}

	crtlist_entry_free(entry);
	crtlist_free(newlist);

end:
	ha_free(&crtlist_name);
	return err_code;
}

REGISTER_CONFIG_POST_SECTION("listen",   post_section_frontend_crt_init);
REGISTER_CONFIG_POST_SECTION("frontend", post_section_frontend_crt_init);


/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */

/* the <ssl_crtlist_kws> keywords are used for crt-list parsing, they *MUST* be safe
 * with their proxy argument NULL and must only fill the ssl_bind_conf
 *
 * /!\ Please update configuration.txt at the crt-list option of the Bind options
 * section when adding a keyword in ssl_crtlist_kws. /!\
 *
 */
struct ssl_crtlist_kw ssl_crtlist_kws[] = {
	{ "allow-0rtt",            ssl_bind_parse_allow_0rtt,       0 }, /* allow 0-RTT */
	{ "alpn",                  ssl_bind_parse_alpn,             1 }, /* set ALPN supported protocols */
	{ "ca-file",               ssl_bind_parse_ca_file,          1 }, /* set CAfile to process ca-names and verify on client cert */
	{ "ca-verify-file",        ssl_bind_parse_ca_verify_file,   1 }, /* set CAverify file to process verify on client cert */
	{ "ciphers",               ssl_bind_parse_ciphers,          1 }, /* set SSL cipher suite */
	{ "ciphersuites",          ssl_bind_parse_ciphersuites,     1 }, /* set TLS 1.3 cipher suite */
	{ "client-sigalgs",        ssl_bind_parse_client_sigalgs,     1 }, /* set SSL client signature algorithms */
	{ "crl-file",              ssl_bind_parse_crl_file,         1 }, /* set certificate revocation list file use on client cert verify */
	{ "curves",                ssl_bind_parse_curves,           1 }, /* set SSL curve suite */
	{ "ecdhe",                 ssl_bind_parse_ecdhe,            1 }, /* defines named curve for elliptic curve Diffie-Hellman */
	{ "ktls",                  ssl_bind_parse_ktls,             1 }, /* enables or disables kTLS */
	{ "no-alpn",               ssl_bind_parse_no_alpn,          0 }, /* disable sending ALPN */
	{ "no-ca-names",           ssl_bind_parse_no_ca_names,      0 }, /* do not send ca names to clients (ca_file related) */
	{ "npn",                   ssl_bind_parse_npn,              1 }, /* set NPN supported protocols */
	{ "sigalgs",               ssl_bind_parse_sigalgs,          1 }, /* set SSL signature algorithms */
	{ "ssl-min-ver",           ssl_bind_parse_tls_method_minmax,1 }, /* minimum version */
	{ "ssl-max-ver",           ssl_bind_parse_tls_method_minmax,1 }, /* maximum version */
	{ "verify",                ssl_bind_parse_verify,           1 }, /* set SSL verify method */
	{ NULL, NULL, 0 },
};

/* no initcall for ssl_bind_kws, these ones are parsed in the parser loop */

static struct bind_kw_list bind_kws = { "SSL", { }, {
	{ "allow-0rtt",            bind_parse_allow_0rtt,         0 }, /* Allow 0RTT */
	{ "alpn",                  bind_parse_alpn,               1 }, /* set ALPN supported protocols */
	{ "ca-file",               bind_parse_ca_file,            1 }, /* set CAfile to process ca-names and verify on client cert */
	{ "ca-verify-file",        bind_parse_ca_verify_file,     1 }, /* set CAverify file to process verify on client cert */
	{ "ca-ignore-err",         bind_parse_ignore_err,         1 }, /* set error IDs to ignore on verify depth > 0 */
	{ "ca-sign-file",          bind_parse_ca_sign_file,       1 }, /* set CAFile used to generate and sign server certs */
	{ "ca-sign-pass",          bind_parse_ca_sign_pass,       1 }, /* set CAKey passphrase */
	{ "ciphers",               bind_parse_ciphers,            1 }, /* set SSL cipher suite */
	{ "ciphersuites",          bind_parse_ciphersuites,       1 }, /* set TLS 1.3 cipher suite */
	{ "client-sigalgs",        bind_parse_client_sigalgs,     1 }, /* set SSL client signature algorithms */
	{ "crl-file",              bind_parse_crl_file,           1 }, /* set certificate revocation list file use on client cert verify */
	{ "crt",                   bind_parse_crt,                1 }, /* load SSL certificates from this location */
	{ "crt-ignore-err",        bind_parse_ignore_err,         1 }, /* set error IDs to ignore on verify depth == 0 */
	{ "crt-list",              bind_parse_crt_list,           1 }, /* load a list of crt from this location */
	{ "curves",                bind_parse_curves,             1 }, /* set SSL curve suite */
	{ "default-crt",           bind_parse_crt,                1 }, /* load SSL certificates from this location */
	{ "ecdhe",                 bind_parse_ecdhe,              1 }, /* defines named curve for elliptic curve Diffie-Hellman */
	{ "force-sslv3",           bind_parse_tls_method_options, 0 }, /* force SSLv3 */
	{ "force-tlsv10",          bind_parse_tls_method_options, 0 }, /* force TLSv10 */
	{ "force-tlsv11",          bind_parse_tls_method_options, 0 }, /* force TLSv11 */
	{ "force-tlsv12",          bind_parse_tls_method_options, 0 }, /* force TLSv12 */
	{ "force-tlsv13",          bind_parse_tls_method_options, 0 }, /* force TLSv13 */
	{ "generate-certificates", bind_parse_generate_certs,     0 }, /* enable the server certificates generation */
	{ "ktls",                  bind_parse_ktls,               1 }, /* enable or disable kTLS */
	{ "no-alpn",               bind_parse_no_alpn,            0 }, /* disable sending ALPN */
	{ "no-ca-names",           bind_parse_no_ca_names,        0 }, /* do not send ca names to clients (ca_file related) */
	{ "no-sslv3",              bind_parse_tls_method_options, 0 }, /* disable SSLv3 */
	{ "no-strict-sni",         bind_parse_strict_sni,         0 }, /* do not refuse negotiation if sni doesn't match a certificate */
	{ "no-tlsv10",             bind_parse_tls_method_options, 0 }, /* disable TLSv10 */
	{ "no-tlsv11",             bind_parse_tls_method_options, 0 }, /* disable TLSv11 */
	{ "no-tlsv12",             bind_parse_tls_method_options, 0 }, /* disable TLSv12 */
	{ "no-tlsv13",             bind_parse_tls_method_options, 0 }, /* disable TLSv13 */
	{ "no-tls-tickets",        bind_parse_no_tls_tickets,     0 }, /* disable session resumption tickets */
	{ "sigalgs",               bind_parse_sigalgs,            1 }, /* set SSL signature algorithms */
	{ "ssl",                   bind_parse_ssl,                0 }, /* enable SSL processing */
	{ "ssl-min-ver",           bind_parse_tls_method_minmax,  1 }, /* minimum version */
	{ "ssl-max-ver",           bind_parse_tls_method_minmax,  1 }, /* maximum version */
	{ "strict-sni",            bind_parse_strict_sni,         0 }, /* refuse negotiation if sni doesn't match a certificate */
	{ "tls-tickets",           bind_parse_no_tls_tickets,     0 }, /* enable session resumption tickets */
	{ "tls-ticket-keys",       bind_parse_tls_ticket_keys,    1 }, /* set file to load TLS ticket keys from */
	{ "verify",                bind_parse_verify,             1 }, /* set SSL verify method */
	{ "npn",                   bind_parse_npn,                1 }, /* set NPN supported protocols */
	{ "prefer-client-ciphers", bind_parse_pcc,                0 }, /* prefer client ciphers */
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct srv_kw_list srv_kws = { "SSL", { }, {
	{ "allow-0rtt",              srv_parse_allow_0rtt,         0, 1, 1 }, /* Allow using early data on this server */
	{ "alpn",                    srv_parse_alpn,               1, 1, 1 }, /* Set ALPN supported protocols */
	{ "ca-file",                 srv_parse_ca_file,            1, 1, 1 }, /* set CAfile to process verify server cert */
	{ "check-alpn",              srv_parse_check_alpn,         1, 1, 1 }, /* Set ALPN used for checks */
	{ "check-sni",               srv_parse_check_sni,          1, 1, 1 }, /* set SNI */
	{ "check-sni-auto",          srv_parse_check_sni_auto,     0, 1, 0 }, /* enable automatic SNI selection for health checks */
	{ "check-ssl",               srv_parse_check_ssl,          0, 1, 1 }, /* enable SSL for health checks */
	{ "ciphers",                 srv_parse_ciphers,            1, 1, 1 }, /* select the cipher suite */
	{ "ciphersuites",            srv_parse_ciphersuites,       1, 1, 1 }, /* select the cipher suite */
	{ "client-sigalgs",          srv_parse_client_sigalgs,     1, 1, 1 }, /* signature algorithms */
	{ "crl-file",                srv_parse_crl_file,           1, 1, 1 }, /* set certificate revocation list file use on server cert verify */
	{ "curves",                  srv_parse_curves,             1, 1, 1 }, /* set TLS curves list */
	{ "crt",                     srv_parse_crt,                1, 1, 1 }, /* set client certificate */
	{ "force-sslv3",             srv_parse_tls_method_options, 0, 1, 1 }, /* force SSLv3 */
	{ "force-tlsv10",            srv_parse_tls_method_options, 0, 1, 1 }, /* force TLSv10 */
	{ "force-tlsv11",            srv_parse_tls_method_options, 0, 1, 1 }, /* force TLSv11 */
	{ "force-tlsv12",            srv_parse_tls_method_options, 0, 1, 1 }, /* force TLSv12 */
	{ "force-tlsv13",            srv_parse_tls_method_options, 0, 1, 1 }, /* force TLSv13 */
	{ "ktls",                    srv_parse_ktls,               1, 1, 1 }, /* enable or disable kTLS */
	{ "no-check-sni-auto",       srv_parse_no_check_sni_auto,  0, 1, 0 }, /* disable automatic SNI selection for health checks */
	{ "no-check-ssl",            srv_parse_no_check_ssl,       0, 1, 0 }, /* disable SSL for health checks */
	{ "no-renegotiate",          srv_parse_renegotiate,        0, 1, 1 }, /* Disable renegotiation */
	{ "no-send-proxy-v2-ssl",    srv_parse_no_send_proxy_ssl,  0, 1, 0 }, /* do not send PROXY protocol header v2 with SSL info */
	{ "no-send-proxy-v2-ssl-cn", srv_parse_no_send_proxy_cn,   0, 1, 0 }, /* do not send PROXY protocol header v2 with CN */
	{ "no-sni-auto",             srv_parse_no_sni_auto,        0, 1, 0 }, /* disable automatic SNI selection */
	{ "no-ssl",                  srv_parse_no_ssl,             0, 1, 0 }, /* disable SSL processing */
	{ "no-ssl-reuse",            srv_parse_no_ssl_reuse,       0, 1, 1 }, /* disable session reuse */
	{ "no-sslv3",                srv_parse_tls_method_options, 0, 0, 1 }, /* disable SSLv3 */
	{ "no-tlsv10",               srv_parse_tls_method_options, 0, 0, 1 }, /* disable TLSv10 */
	{ "no-tlsv11",               srv_parse_tls_method_options, 0, 0, 1 }, /* disable TLSv11 */
	{ "no-tlsv12",               srv_parse_tls_method_options, 0, 0, 1 }, /* disable TLSv12 */
	{ "no-tlsv13",               srv_parse_tls_method_options, 0, 0, 1 }, /* disable TLSv13 */
	{ "no-tls-tickets",          srv_parse_no_tls_tickets,     0, 1, 1 }, /* disable session resumption tickets */
	{ "npn",                     srv_parse_npn,                1, 1, 1 }, /* Set NPN supported protocols */
	{ "renegotiate",             srv_parse_renegotiate,        0, 1, 1 }, /* Allow secure renegotiation */
	{ "send-proxy-v2-ssl",       srv_parse_send_proxy_ssl,     0, 1, 1 }, /* send PROXY protocol header v2 with SSL info */
	{ "send-proxy-v2-ssl-cn",    srv_parse_send_proxy_cn,      0, 1, 1 }, /* send PROXY protocol header v2 with CN */
	{ "sigalgs",                 srv_parse_sigalgs,            1, 1, 1 }, /* signature algorithms */
	{ "sni",                     srv_parse_sni,                1, 1, 1 }, /* send SNI extension */
	{ "sni-auto",                srv_parse_sni_auto,           0, 1, 0 }, /* enable automatic SNI selection */
	{ "ssl",                     srv_parse_ssl,                0, 1, 1 }, /* enable SSL processing */
	{ "ssl-min-ver",             srv_parse_tls_method_minmax,  1, 1, 1 }, /* minimum version */
	{ "ssl-max-ver",             srv_parse_tls_method_minmax,  1, 1, 1 }, /* maximum version */
	{ "ssl-reuse",               srv_parse_ssl_reuse,          0, 1, 0 }, /* enable session reuse */
	{ "tls-tickets",             srv_parse_tls_tickets,        0, 1, 1 }, /* enable session resumption tickets */
	{ "verify",                  srv_parse_verify,             1, 1, 1 }, /* set SSL verify method */
	{ "verifyhost",              srv_parse_verifyhost,         1, 1, 1 }, /* require that SSL cert verifies for hostname */
	{ NULL, NULL, 0, 0 },
}};

INITCALL1(STG_REGISTER, srv_register_keywords, &srv_kws);

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "ca-base",  ssl_parse_global_path_base },
	{ CFG_GLOBAL, "crt-base", ssl_parse_global_path_base },
	{ CFG_GLOBAL, "key-base", ssl_parse_global_path_base },
	{ CFG_GLOBAL, "issuers-chain-path", ssl_load_global_issuers_from_path },
	{ CFG_GLOBAL, "maxsslconn", ssl_parse_global_int },
	{ CFG_GLOBAL, "ssl-default-bind-options", ssl_parse_default_bind_options },
	{ CFG_GLOBAL, "ssl-default-server-options", ssl_parse_default_server_options },
#ifndef OPENSSL_NO_DH
	{ CFG_GLOBAL, "ssl-dh-param-file", ssl_parse_global_dh_param_file },
#endif
	{ CFG_GLOBAL, "ssl-mode-async",  ssl_parse_global_ssl_async },
#if defined(USE_ENGINE) && !defined(OPENSSL_NO_ENGINE)
	{ CFG_GLOBAL, "ssl-engine",  ssl_parse_global_ssl_engine },
#endif
#ifdef HAVE_SSL_PROVIDERS
	{ CFG_GLOBAL, "ssl-propquery",  ssl_parse_global_ssl_propquery },
	{ CFG_GLOBAL, "ssl-provider",  ssl_parse_global_ssl_provider },
	{ CFG_GLOBAL, "ssl-provider-path",  ssl_parse_global_ssl_provider_path },
#endif
	{ CFG_GLOBAL, "ssl-security-level", ssl_parse_security_level },
	{ CFG_GLOBAL, "ssl-skip-self-issued-ca", ssl_parse_skip_self_issued_ca },
	{ CFG_GLOBAL, "tune.ssl.cachesize", ssl_parse_global_int },
	{ CFG_GLOBAL, "tune.ssl.default-dh-param", ssl_parse_global_default_dh },
	{ CFG_GLOBAL, "tune.ssl.force-private-cache",  ssl_parse_global_private_cache },
	{ CFG_GLOBAL, "tune.ssl.lifetime", ssl_parse_global_lifetime },
	{ CFG_GLOBAL, "tune.ssl.maxrecord", ssl_parse_global_int },
	{ CFG_GLOBAL, "tune.ssl.hard-maxrecord", ssl_parse_global_int },
	{ CFG_GLOBAL, "tune.ssl.ssl-ctx-cache-size", ssl_parse_global_int },
	{ CFG_GLOBAL, "tune.ssl.capture-cipherlist-size", ssl_parse_global_capture_buffer },
	{ CFG_GLOBAL, "tune.ssl.capture-buffer-size", ssl_parse_global_capture_buffer },
	{ CFG_GLOBAL, "tune.ssl.keylog", ssl_parse_global_keylog },
	{ CFG_GLOBAL, "ssl-default-bind-ciphers", ssl_parse_global_ciphers },
	{ CFG_GLOBAL, "ssl-default-server-ciphers", ssl_parse_global_ciphers },
#if defined(SSL_CTX_set1_curves_list)
	{ CFG_GLOBAL, "ssl-default-bind-curves", ssl_parse_global_curves },
	{ CFG_GLOBAL, "ssl-default-server-curves", ssl_parse_global_curves },
#endif
#if defined(SSL_CTX_set1_sigalgs_list)
	{ CFG_GLOBAL, "ssl-default-bind-sigalgs", ssl_parse_global_sigalgs },
	{ CFG_GLOBAL, "ssl-default-server-sigalgs", ssl_parse_global_sigalgs },
#endif
#if defined(SSL_CTX_set1_client_sigalgs_list)
	{ CFG_GLOBAL, "ssl-default-bind-client-sigalgs", ssl_parse_global_client_sigalgs },
	{ CFG_GLOBAL, "ssl-default-server-client-sigalgs", ssl_parse_global_client_sigalgs },
#endif
	{ CFG_GLOBAL, "ssl-default-bind-ciphersuites", ssl_parse_global_ciphersuites },
	{ CFG_GLOBAL, "ssl-default-server-ciphersuites", ssl_parse_global_ciphersuites },
	{ CFG_GLOBAL, "ssl-load-extra-files", ssl_parse_global_extra_files },
	{ CFG_GLOBAL, "ssl-load-extra-del-ext", ssl_parse_global_extra_noext },

	{ CFG_LISTEN, "ssl-f-use", proxy_parse_ssl_f_use },

	{ CFG_GLOBAL, "ssl-passphrase-cmd", ssl_parse_global_passphrase_cmd },

	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
