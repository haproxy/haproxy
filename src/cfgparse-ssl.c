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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <haproxy/api.h>
#include <haproxy/base64.h>
#include <haproxy/cfgparse.h>
#include <haproxy/errors.h>
#include <haproxy/listener.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/tools.h>
#include <haproxy/ssl_ckch.h>


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

#ifndef OPENSSL_NO_ENGINE
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

#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
/* parse the "ssl-default-bind-ciphersuites" / "ssl-default-server-ciphersuites" keywords
 * in global section. Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ciphersuites(char **args, int section_type, struct proxy *curpx,
                                    const struct proxy *defpx, const char *file, int line,
                                    char **err)
{
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
}
#endif

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
	target = &global_ssl.listen_default_curves;

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

/* parse "ssl.default-dh-param".
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_default_dh(char **args, int section_type, struct proxy *curpx,
                                       const struct proxy *defpx, const char *file, int line,
                                       char **err)
{
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
}
#endif


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

/***************************** Bind keyword Parsing ********************************************/

/* for ca-file and ca-verify-file */
static int ssl_bind_parse_ca_file_common(char **args, int cur_arg, char **ca_file_p, int from_cli, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing CAfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && global_ssl.ca_base)
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

	if ((*args[cur_arg + 1] != '/') && global_ssl.ca_base)
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

#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
/* parse the "ciphersuites" bind keyword */
static int ssl_bind_parse_ciphersuites(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, int from_cli, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->ciphersuites);
	conf->ciphersuites = strdup(args[cur_arg + 1]);
	return 0;
}
static int bind_parse_ciphersuites(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ciphersuites(args, cur_arg, px, &conf->ssl_conf, 0, err);
}
#endif

/* parse the "crt" bind keyword. Returns a set of ERR_* flags possibly with an error in <err>. */
static int bind_parse_crt(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char path[MAXPATHLEN];

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate location", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/' ) && global_ssl.crt_base) {
		if ((strlen(global_ssl.crt_base) + 1 + strlen(args[cur_arg + 1]) + 1) > MAXPATHLEN) {
			memprintf(err, "'%s' : path too long", args[cur_arg]);
			return ERR_ALERT | ERR_FATAL;
		}
		snprintf(path, sizeof(path), "%s/%s",  global_ssl.crt_base, args[cur_arg + 1]);
		return ssl_sock_load_cert(path, conf, err);
	}

	return ssl_sock_load_cert(args[cur_arg + 1], conf, err);
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

	if ((*args[cur_arg + 1] != '/') && global_ssl.ca_base)
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
	char *p = args[cur_arg + 1];
	unsigned long long *ignerr = &conf->crt_ignerr;

	if (!*p) {
		memprintf(err, "'%s' : missing error IDs list", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg], "ca-ignore-err") == 0)
		ignerr = &conf->ca_ignerr;

	if (strcmp(p, "all") == 0) {
		*ignerr = ~0ULL;
		return 0;
	}

	while (p) {
		code = atoi(p);
		if ((code <= 0) || (code > 63)) {
			memprintf(err, "'%s' : ID '%d' out of range (1..63) in error IDs list '%s'",
			          args[cur_arg], code, args[cur_arg + 1]);
			return ERR_ALERT | ERR_FATAL;
		}
		*ignerr |= 1ULL << code;
		p = strchr(p, ',');
		if (p)
			p++;
	}

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

/* parse the "no-tls-tickets" bind keyword */
static int bind_parse_no_tls_tickets(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_NO_TLS_TICKETS;
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
	/* Do not change the xprt for QUIC. */
	if (conf->xprt != xprt_get(XPRT_QUIC))
		conf->xprt = &ssl_sock;
	conf->is_ssl = 1;

	if (global_ssl.listen_default_ciphers && !conf->ssl_conf.ciphers)
		conf->ssl_conf.ciphers = strdup(global_ssl.listen_default_ciphers);
#if defined(SSL_CTX_set1_curves_list)
	if (global_ssl.listen_default_curves && !conf->ssl_conf.curves)
		conf->ssl_conf.curves = strdup(global_ssl.listen_default_curves);
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
	conf->generate_certs = 1;
#else
	memprintf(err, "%sthis version of openssl cannot generate SSL certificates.\n",
		  err && *err ? *err : "");
#endif
	return 0;
}

/* parse the "strict-sni" bind keyword */
static int bind_parse_strict_sni(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->strict_sni = 1;
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

	if ((*args[*cur_arg + 1] != '/') && global_ssl.ca_base)
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

	newsrv->check.sni = strdup(args[*cur_arg + 1]);
	if (!newsrv->check.sni) {
		memprintf(err, "'%s' : failed to allocate memory", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
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

#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
/* parse the "ciphersuites" server keyword */
static int srv_parse_ciphersuites(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
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
}
#endif

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

	if ((*args[*cur_arg + 1] != '/') && global_ssl.ca_base)
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

/* parse the "crt" server keyword */
static int srv_parse_crt(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate file path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '/') && global_ssl.crt_base)
		memprintf(&newsrv->ssl_ctx.client_crt, "%s/%s", global_ssl.crt_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.client_crt, "%s", args[*cur_arg + 1]);

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
		else if (strcmp(args[i], "prefer-client-ciphers") == 0)
			global_ssl.listen_default_ssloptions |= BC_SSL_O_PREF_CLIE_CIPH;
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
		else if (parse_tls_method_options(args[i], &global_ssl.connect_default_sslmethods, err)) {
			memprintf(err, "unknown option '%s' on global statement '%s'.", args[i], args[0]);
			return -1;
		}
		i++;
	}
	return 0;
}

/* parse the "ca-base" / "crt-base" keywords in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ca_crt_base(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	char **target;

	target = (args[0][1] == 'a') ? &global_ssl.ca_base : &global_ssl.crt_base;

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





/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */

/* the <ssl_bind_kws> keywords are used for crt-list parsing, they *MUST* be safe
 * with their proxy argument NULL and must only fill the ssl_bind_conf */
struct ssl_bind_kw ssl_bind_kws[] = {
	{ "allow-0rtt",            ssl_bind_parse_allow_0rtt,       0 }, /* allow 0-RTT */
	{ "alpn",                  ssl_bind_parse_alpn,             1 }, /* set ALPN supported protocols */
	{ "ca-file",               ssl_bind_parse_ca_file,          1 }, /* set CAfile to process ca-names and verify on client cert */
	{ "ca-verify-file",        ssl_bind_parse_ca_verify_file,   1 }, /* set CAverify file to process verify on client cert */
	{ "ciphers",               ssl_bind_parse_ciphers,          1 }, /* set SSL cipher suite */
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	{ "ciphersuites",          ssl_bind_parse_ciphersuites,     1 }, /* set TLS 1.3 cipher suite */
#endif
	{ "crl-file",              ssl_bind_parse_crl_file,         1 }, /* set certificate revocation list file use on client cert verify */
	{ "curves",                ssl_bind_parse_curves,           1 }, /* set SSL curve suite */
	{ "ecdhe",                 ssl_bind_parse_ecdhe,            1 }, /* defines named curve for elliptic curve Diffie-Hellman */
	{ "no-ca-names",           ssl_bind_parse_no_ca_names,      0 }, /* do not send ca names to clients (ca_file related) */
	{ "npn",                   ssl_bind_parse_npn,              1 }, /* set NPN supported protocols */
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
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	{ "ciphersuites",          bind_parse_ciphersuites,       1 }, /* set TLS 1.3 cipher suite */
#endif
	{ "crl-file",              bind_parse_crl_file,           1 }, /* set certificate revocation list file use on client cert verify */
	{ "crt",                   bind_parse_crt,                1 }, /* load SSL certificates from this location */
	{ "crt-ignore-err",        bind_parse_ignore_err,         1 }, /* set error IDs to ignore on verify depth == 0 */
	{ "crt-list",              bind_parse_crt_list,           1 }, /* load a list of crt from this location */
	{ "curves",                bind_parse_curves,             1 }, /* set SSL curve suite */
	{ "ecdhe",                 bind_parse_ecdhe,              1 }, /* defines named curve for elliptic curve Diffie-Hellman */
	{ "force-sslv3",           bind_parse_tls_method_options, 0 }, /* force SSLv3 */
	{ "force-tlsv10",          bind_parse_tls_method_options, 0 }, /* force TLSv10 */
	{ "force-tlsv11",          bind_parse_tls_method_options, 0 }, /* force TLSv11 */
	{ "force-tlsv12",          bind_parse_tls_method_options, 0 }, /* force TLSv12 */
	{ "force-tlsv13",          bind_parse_tls_method_options, 0 }, /* force TLSv13 */
	{ "generate-certificates", bind_parse_generate_certs,     0 }, /* enable the server certificates generation */
	{ "no-ca-names",           bind_parse_no_ca_names,        0 }, /* do not send ca names to clients (ca_file related) */
	{ "no-sslv3",              bind_parse_tls_method_options, 0 }, /* disable SSLv3 */
	{ "no-tlsv10",             bind_parse_tls_method_options, 0 }, /* disable TLSv10 */
	{ "no-tlsv11",             bind_parse_tls_method_options, 0 }, /* disable TLSv11 */
	{ "no-tlsv12",             bind_parse_tls_method_options, 0 }, /* disable TLSv12 */
	{ "no-tlsv13",             bind_parse_tls_method_options, 0 }, /* disable TLSv13 */
	{ "no-tls-tickets",        bind_parse_no_tls_tickets,     0 }, /* disable session resumption tickets */
	{ "ssl",                   bind_parse_ssl,                0 }, /* enable SSL processing */
	{ "ssl-min-ver",           bind_parse_tls_method_minmax,  1 }, /* minimum version */
	{ "ssl-max-ver",           bind_parse_tls_method_minmax,  1 }, /* maximum version */
	{ "strict-sni",            bind_parse_strict_sni,         0 }, /* refuse negotiation if sni doesn't match a certificate */
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
	{ "check-ssl",               srv_parse_check_ssl,          0, 1, 1 }, /* enable SSL for health checks */
	{ "ciphers",                 srv_parse_ciphers,            1, 1, 1 }, /* select the cipher suite */
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	{ "ciphersuites",            srv_parse_ciphersuites,       1, 1, 1 }, /* select the cipher suite */
#endif
	{ "crl-file",                srv_parse_crl_file,           1, 1, 1 }, /* set certificate revocation list file use on server cert verify */
	{ "crt",                     srv_parse_crt,                1, 1, 1 }, /* set client certificate */
	{ "force-sslv3",             srv_parse_tls_method_options, 0, 1, 1 }, /* force SSLv3 */
	{ "force-tlsv10",            srv_parse_tls_method_options, 0, 1, 1 }, /* force TLSv10 */
	{ "force-tlsv11",            srv_parse_tls_method_options, 0, 1, 1 }, /* force TLSv11 */
	{ "force-tlsv12",            srv_parse_tls_method_options, 0, 1, 1 }, /* force TLSv12 */
	{ "force-tlsv13",            srv_parse_tls_method_options, 0, 1, 1 }, /* force TLSv13 */
	{ "no-check-ssl",            srv_parse_no_check_ssl,       0, 1, 0 }, /* disable SSL for health checks */
	{ "no-send-proxy-v2-ssl",    srv_parse_no_send_proxy_ssl,  0, 1, 0 }, /* do not send PROXY protocol header v2 with SSL info */
	{ "no-send-proxy-v2-ssl-cn", srv_parse_no_send_proxy_cn,   0, 1, 0 }, /* do not send PROXY protocol header v2 with CN */
	{ "no-ssl",                  srv_parse_no_ssl,             0, 1, 0 }, /* disable SSL processing */
	{ "no-ssl-reuse",            srv_parse_no_ssl_reuse,       0, 1, 1 }, /* disable session reuse */
	{ "no-sslv3",                srv_parse_tls_method_options, 0, 0, 1 }, /* disable SSLv3 */
	{ "no-tlsv10",               srv_parse_tls_method_options, 0, 0, 1 }, /* disable TLSv10 */
	{ "no-tlsv11",               srv_parse_tls_method_options, 0, 0, 1 }, /* disable TLSv11 */
	{ "no-tlsv12",               srv_parse_tls_method_options, 0, 0, 1 }, /* disable TLSv12 */
	{ "no-tlsv13",               srv_parse_tls_method_options, 0, 0, 1 }, /* disable TLSv13 */
	{ "no-tls-tickets",          srv_parse_no_tls_tickets,     0, 1, 1 }, /* disable session resumption tickets */
	{ "npn",                     srv_parse_npn,                1, 1, 1 }, /* Set NPN supported protocols */
	{ "send-proxy-v2-ssl",       srv_parse_send_proxy_ssl,     0, 1, 1 }, /* send PROXY protocol header v2 with SSL info */
	{ "send-proxy-v2-ssl-cn",    srv_parse_send_proxy_cn,      0, 1, 1 }, /* send PROXY protocol header v2 with CN */
	{ "sni",                     srv_parse_sni,                1, 1, 1 }, /* send SNI extension */
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
	{ CFG_GLOBAL, "ca-base",  ssl_parse_global_ca_crt_base },
	{ CFG_GLOBAL, "crt-base", ssl_parse_global_ca_crt_base },
	{ CFG_GLOBAL, "issuers-chain-path", ssl_load_global_issuers_from_path },
	{ CFG_GLOBAL, "maxsslconn", ssl_parse_global_int },
	{ CFG_GLOBAL, "ssl-default-bind-options", ssl_parse_default_bind_options },
	{ CFG_GLOBAL, "ssl-default-server-options", ssl_parse_default_server_options },
#ifndef OPENSSL_NO_DH
	{ CFG_GLOBAL, "ssl-dh-param-file", ssl_parse_global_dh_param_file },
#endif
	{ CFG_GLOBAL, "ssl-mode-async",  ssl_parse_global_ssl_async },
#ifndef OPENSSL_NO_ENGINE
	{ CFG_GLOBAL, "ssl-engine",  ssl_parse_global_ssl_engine },
#endif
	{ CFG_GLOBAL, "ssl-skip-self-issued-ca", ssl_parse_skip_self_issued_ca },
	{ CFG_GLOBAL, "tune.ssl.cachesize", ssl_parse_global_int },
#ifndef OPENSSL_NO_DH
	{ CFG_GLOBAL, "tune.ssl.default-dh-param", ssl_parse_global_default_dh },
#endif
	{ CFG_GLOBAL, "tune.ssl.force-private-cache",  ssl_parse_global_private_cache },
	{ CFG_GLOBAL, "tune.ssl.lifetime", ssl_parse_global_lifetime },
	{ CFG_GLOBAL, "tune.ssl.maxrecord", ssl_parse_global_int },
	{ CFG_GLOBAL, "tune.ssl.ssl-ctx-cache-size", ssl_parse_global_int },
	{ CFG_GLOBAL, "tune.ssl.capture-cipherlist-size", ssl_parse_global_capture_buffer },
	{ CFG_GLOBAL, "tune.ssl.capture-buffer-size", ssl_parse_global_capture_buffer },
	{ CFG_GLOBAL, "tune.ssl.keylog", ssl_parse_global_keylog },
	{ CFG_GLOBAL, "ssl-default-bind-ciphers", ssl_parse_global_ciphers },
	{ CFG_GLOBAL, "ssl-default-server-ciphers", ssl_parse_global_ciphers },
#if defined(SSL_CTX_set1_curves_list)
	{ CFG_GLOBAL, "ssl-default-bind-curves", ssl_parse_global_curves },
#endif
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	{ CFG_GLOBAL, "ssl-default-bind-ciphersuites", ssl_parse_global_ciphersuites },
	{ CFG_GLOBAL, "ssl-default-server-ciphersuites", ssl_parse_global_ciphersuites },
#endif
	{ CFG_GLOBAL, "ssl-load-extra-files", ssl_parse_global_extra_files },
	{ CFG_GLOBAL, "ssl-load-extra-del-ext", ssl_parse_global_extra_noext },
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
