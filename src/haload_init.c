#include <errno.h>

#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/hbuf.h>
#include <haproxy/haload.h>
#include <haproxy/proxy.h>
#include <haproxy/version.h>
#include <haproxy/server.h>

static int hld_debug;
struct hld_url_cfg *hld_url_cfgs;
char *srv_opts, *tls_ciphers, *tls_ciphersuites, *tls_curves;

static void  hld_usage(char *name, int argc, int line)
{
	fprintf(stderr,
		"Usage : %s [opts] [URL]*\n"
		"where <opts> may be any combination of:\n"
		"        -d <time>       test duration in seconds (0)\n"
		"        -l              enable long output format; double for raw values\n"
		"        -m <streams>    maximum concurrent streams (1)\n"
		"        -n <reqs>       maximum total requests (-1)\n"
		"        -r <reqs>       number of requests per connection (-1)\n"
		"        -s <time>       soft start: time in sec to reach 100%% load\n"
		"        -t <threads>    number of threads\n"
		"        -u <users>      number of users (1)\n"
		"        -w <time>       I/O timeout in milliseconds (10000)\n"
		"        -C              dump the configuration and exit\n"
		"        -H \"foo:bar\"  add this header name and value\n"
		"        -I              use HEAD instead of GET\n"
		"        -v              shows version\n"
		"        --default <str> add a string to default section\n"
		"        --global <str>  add a string to global section\n"
		"        --server <opts> set server <opt> options as defined for \"server\" haproxy keyword\n"
		"        --show-status-codes show HTTP status codes distribution\n"
		"        --traces        enable the traces for all the HTTP protocols\n"
		"SSL options:\n"
		"        --tls-ciphers <ciphers>       for TLS1.2 and below\n"
		"        --tls-ciphersuites <ciphers>  for TLS1.3 and above\n"
		"        --tls-curves <curves>\n"
		"URL formats:\n"
		"        (http|https)://<addr>:<port>/<path> with <addr> any address as supported by haproxy\n"
		"        (see haproxy documentation about addresses formats)\n",
		name);
	exit(1);
}

static const char *hld_cfg_traces_str =
	"traces\n"
		"\ttrace haload sink stderr level developer start now verbosity clean\n"
		"\ttrace quic sink stderr level developer start now\n"
		"\ttrace ssl sink stderr level developer start now verbosity minimal\n"
		"\ttrace h1 sink stderr level developer start now verbosity minimal\n"
		"\ttrace h2 sink stderr level developer start now verbosity minimal\n"
		"\ttrace h3 sink stderr level developer start now verbosity minimal\n"
		"\ttrace qmux sink stderr level developer start now verbosity minimal\n";

static struct hld_hdr *hld_parse_hdr(char *hdr_str)
{
	struct hld_hdr *hdr= NULL;
	char *value = strchr(hdr_str, ':');

	if (value) {
		*value++ = '\0';
		if (!*value)
			value = NULL;
	}

	if (strcasecmp(hdr_str, "host") == 0)
		arg_host = value;
	else if (strcasecmp(hdr_str, "connection") == 0)
		arg_conn_hdr = value;

	hdr = malloc(sizeof(*hdr));
	if (hdr) {
		hdr->name = ist(hdr_str);
		hdr->value = ist(value);
	}

	return hdr;
}

static int hld_add_opt_to_buf(struct hbuf *buf,
                              const char *kw, const char *value)
{
	if (hbuf_is_null(buf)) {
		if (hbuf_alloc(buf) == NULL) {
			ha_alert("failed to allocate a buffer.\n");
			return 0;
		}
	}
	else
		hbuf_appendf(buf, " ");

	hbuf_appendf(buf, "%s", kw);
	hbuf_appendf(buf, " ");
	hbuf_appendf(buf, "%s", value);
	return 1;
}

static inline void hld_free_url_cfg(struct hld_url_cfg *h)
{
	free(h->addr);
	free(h->srv_opts);
	free(h->tls_opts);
	free(h);
}

static inline void hld_free_url_cfgs(void)
{
	struct hld_url_cfg *purl;

	purl = hld_url_cfgs;

	while (purl) {
		struct hld_url_cfg *purl_next;
		struct hld_path *path;

		path = purl->paths;
		while (path) {
			struct hld_path *path_next;

			path_next = path->next;
			free(path->path);
			free(path);
			path = path_next;
		}

		purl_next = purl->next;

		hld_free_url_cfg(purl);
		purl = purl_next;
	}
}

/* Allocate a URL from <url> command line argument without
 * duplicating it, and append it to <hld_url_cfgs> list of URL.
 * A URL is identified by its peer address and if it uses
 * SSL or not. When a URL with the same peer address already
 * exists, this function only add a new path to the list
 * of paths attaached to the URL.
 * Return the URL if succeeded, NULL if not.
 */
static struct hld_url_cfg *hld_alloc_url(char *url)
{
	int ssl = 0;
	char *addr = NULL, *raw_addr = NULL, *path = NULL;
	struct hld_url_cfg *hld_url_cfg = NULL;
	struct hld_url_cfg *purl;
	struct hld_path *p = NULL;
	struct hbuf opts_buf = HBUF_NULL;

	if (strncmp(url, "http://", 7) == 0)
		addr = url + 7;
	else if (strncmp(url, "https://", 8) == 0) {
		ssl = 1;
		addr = url + 8;
	}
	else
		addr = url;

	path = strchr(addr, '/');
	if (path) {
		char *new_path = strdup(path);
		*path = '\0';
		path = new_path;
	}
	else
		path = strdup("/");

	if (!path)
		goto err;

	for (purl = hld_url_cfgs; purl; purl = purl->next) {
		/* XXX TODO: improve this check for QUIC XXX */
		if (strcmp(purl->addr, addr) == 0 && purl->ssl == ssl) {
			/* Already existing URL with the same address. */
			hld_url_cfg = purl;

			p = calloc(1, sizeof(*p));
			if (!p)
				goto err;

			/* Append a new path to this URL */
			p->path = path;
			p->next = hld_url_cfg->paths;
			hld_url_cfg->paths = p;

			return hld_url_cfg;
		}
	}

	addr = strdup(addr);
	if (!addr)
		goto err;

	raw_addr = strchr(addr, '@');
	if (!raw_addr)
		raw_addr = strchr(addr, '+');

	raw_addr = raw_addr ? raw_addr + 1: addr;

	hld_url_cfg = calloc(1, sizeof(*hld_url_cfg));
	p = malloc(sizeof(*p));
	if (!hld_url_cfg || !p)
		goto err;

	p->path = path;
	p->next = NULL;

	hld_url_cfg->ssl = ssl;
	hld_url_cfg->addr = addr;
	hld_url_cfg->raw_addr = raw_addr;

	if (srv_opts) {
		hld_url_cfg->srv_opts = strdup(srv_opts);
		if (!hld_url_cfg->srv_opts)
			goto err;
	}

	if (tls_ciphers &&
	    !hld_add_opt_to_buf(&opts_buf, "ciphers", tls_ciphers))
		goto err;

	if (tls_ciphersuites &&
	    !hld_add_opt_to_buf(&opts_buf, "ciphersuites", tls_ciphersuites))
		goto err;

	if (tls_curves &&
	    !hld_add_opt_to_buf(&opts_buf, "curves", tls_curves))
		goto err;

	if (!hbuf_is_null(&opts_buf))
		hld_url_cfg->tls_opts = strdup(opts_buf.area);

	free_hbuf(&opts_buf);
	hld_url_cfg->srv = NULL;
	hld_url_cfg->paths = p;
	/* Append this new URL to the list */
	hld_url_cfg->next = hld_url_cfgs;
	hld_url_cfgs = hld_url_cfg;

	return hld_url_cfg;
 err:
	hld_free_url_cfgs();
	hld_free_url_cfg(hld_url_cfg);
	free(p);
	free(path);
	return NULL;
}

static void hld_parse_long(int *val, char *opt, int *argc, char ***argv)
{
	char *endptr;

	if (!*opt) {
		++*argv; --*argc;
		if (*argc <= 0 || ***argv == '-')
			hld_usage(progname, *argc, __LINE__);

		opt = **argv;
	}

	*val = strtol(opt, &endptr, 0);
	if (endptr == opt || *val < 0)
		hld_usage(progname, *argc, __LINE__);
}

static inline void hld_url_cfgs_inv(void)
{
	struct hld_url_cfg *urls = NULL, *url = hld_url_cfgs, *next_url;

	/* inverse the URLs order */
	while (url) {
		struct hld_path *paths = NULL, *path = url->paths, *next_path;

		/* inverse the paths order */
		while (path) {
			next_path = path->next;
			path->next = paths;
			paths = path;
			path = next_path;
		}
		url->paths = paths;

		next_url = url->next;
		url->next = urls;
		urls = url;
		url = next_url;
	}

	hld_url_cfgs = urls;
}


void haproxy_init_args(int argc, char **argv)
{
	int err = 1, dump = 0;
	struct hbuf buf = HBUF_NULL;  // cfgfile
	struct hbuf gbuf = HBUF_NULL; // "global" section
	struct hbuf tbuf = HBUF_NULL; // "traces" section
	struct hbuf dbuf = HBUF_NULL; // "default" section

	if (argc <= 1)
		hld_usage(progname, argc, __LINE__);

	if (hbuf_alloc(&gbuf) == NULL) {
		ha_alert("failed to allocate a buffer.\n");
		goto leave;
	}

	/* use 3MB of local cache per thread mainly for QUIC.
	 * Also trust the server certificates
	 */
	hbuf_appendf(&gbuf, "global\n");
	hbuf_appendf(&gbuf, "\ttune.memory.hot-size 3145728\n");
	hbuf_appendf(&gbuf, "\tssl-server-verify none\n");

	if (hbuf_alloc(&buf) == NULL) {
		ha_alert("failed to allocate a buffer\n");
		exit(1);
	}

	fileless_mode = 1;
	client_mode = 1;
	/* skip program name and start */
	argc--; argv++;

	while (argc > 0) {
		if (**argv == '-') {
			char *opt = *argv + 1;

			//fprintf(stderr, "||||**argv='%c' argc=%d\n", **argv, argc);
			//fprintf(stderr, "====> *opt='%c'\n", *opt);
			if (*opt == '-') {
				/* long option */
				opt++;
				if (strcmp(opt, "default") == 0) {
					argv++; argc--;
					if (argc <= 0 || **argv == '-')
						hld_usage(progname, argc, __LINE__);

					if (hbuf_is_null(&dbuf)) {
						if (hbuf_alloc(&dbuf) == NULL) {
							ha_alert("failed to allocate a buffer.\n");
							goto leave;
						}

						hbuf_appendf(&dbuf, "default\n");
					}

					hbuf_str_append(&dbuf, *argv);
				}
				else if (strcmp(opt, "global") == 0) {
					argv++; argc--;
					if (argc <= 0 || **argv == '-')
						hld_usage(progname, argc, __LINE__);

					hbuf_str_append(&gbuf, *argv);
				}
				else if (strcmp(opt, "server") == 0) {
					argv++, argc--;
					if ((argc <= 0 || **argv == '-'))
						hld_usage(progname, argc, __LINE__);

					opt = *argv;
					free(srv_opts);
					srv_opts = strdup(opt);
				}
				else if (strcmp(opt, "show-status-codes") == 0) {
					arg_hscd = 1;
				}
				else if (strcmp(opt, "tls-ciphers") == 0) {
					argv++, argc--;
					if ((argc <= 0 || **argv == '-'))
						hld_usage(progname, argc, __LINE__);
					opt = *argv;
					free(tls_ciphers);
					tls_ciphers = strdup(opt);
				}
				else if (strcmp(opt, "tls-ciphersuites") == 0) {
					argv++, argc--;
					if ((argc <= 0 || **argv == '-'))
						hld_usage(progname, argc, __LINE__);
					opt = *argv;
					free(tls_ciphersuites);
					tls_ciphersuites = strdup(opt);
				}
				else if (strcmp(opt, "tls-curves") == 0) {
					argv++, argc--;
					if ((argc <= 0 || **argv == '-'))
						hld_usage(progname, argc, __LINE__);
					opt = *argv;
					free(tls_curves);
					tls_curves = strdup(opt);
				}
				else if (strcmp(opt, "traces") == 0) {
					hld_debug = 1;
				}
				else
					hld_usage(progname, argc, __LINE__);
			}
			else if (*opt == 'd') {
				opt++;
				hld_parse_long(&arg_dura, opt, &argc, &argv);
			}
			else if (*opt == 'l') {
				arg_long++;
				while (*++opt && *opt == 'l')
					arg_long++;
			}
			else if (*opt == 'm') {
				opt++;
				hld_parse_long(&arg_mreqs, opt, &argc, &argv);
			}
			else if (*opt == 'n') {
				opt++;
				hld_parse_long(&arg_reqs, opt, &argc, &argv);
			}
			else if (*opt == 'r') {
				opt++;
				hld_parse_long(&arg_rcon, opt, &argc, &argv);
			}
			else if (*opt == 's') {
				opt++;
				hld_parse_long(&arg_slow, opt, &argc, &argv);
				arg_slow *= 1000;
			}
			else if (*opt == 't') {
				opt++;
				hld_parse_long(&arg_nbthrds, opt, &argc, &argv);
			}
			else if (*opt == 'u') {
				opt++;
				hld_parse_long(&arg_usr, opt, &argc, &argv);
			}
			else if (*opt == 'w') {
				opt++;
				hld_parse_long(&arg_wait, opt, &argc, &argv);
			}
			else if (*opt == 'C') {
				/* empty option */
				if (*(opt + 1))
					hld_usage(progname, argc, __LINE__);

				dump = 1;
			}
			else if (*opt == 'H') {
				char *hdr_str;
				struct hld_hdr *hdr;

				opt++;
				if (!*opt) {
					argv++; argc--;
					if ((argc <= 0 || **argv == '-'))
						hld_usage(progname, argc, __LINE__);

					opt = *argv;
				}

				hdr_str = opt;
				hdr = hld_parse_hdr(hdr_str);
				if (!hdr) {
					ha_alert("could not allocate a header\n");
					goto leave;
				}

				LIST_APPEND(&hld_hdrs, &hdr->list);
			}
			else if (*opt == 'I') {
				/* empty option */
				if (*(opt + 1))
					hld_usage(progname, argc, __LINE__);

				arg_head = 1;
			}
			else if (*opt == 'v') {
				/* empty option */
				if (*(opt + 1))
					hld_usage(progname, argc, __LINE__);

				printf("haload version " HAPROXY_VERSION " released " HAPROXY_DATE "\n");
				exit(0);
			}
			else
				hld_usage(progname, argc, __LINE__);
		}
		else {
			struct hld_url_cfg *url;

			url = hld_alloc_url(*argv);
			if (!url) {
				ha_alert("could not parse a new URL\n");
				goto leave;
			}


		}

		argv++; argc--;
		//fprintf(stderr, "///argc=%d argv='%s'\n", argc, *argv);
	}

	if (arg_rcon > 0 && arg_rcon < arg_mreqs) {
		ha_warning("number of maximum concurrent streams is greater that number of requests by connection\n");
		ha_warning("set both these parameters values to %d (number of requests by connection)\n", arg_rcon);
		arg_mreqs = arg_rcon;
	}

	if (!hld_url_cfgs) {
		ha_alert("no URL provided\n");
		goto leave;
	}

	/* "global" section */
	hbuf_appendf(&buf, "%.*s", (int)gbuf.data, gbuf.area);
	if (arg_nbthrds != -1)
		hbuf_appendf(&buf, "\tnbthread %d\n", arg_nbthrds);
	/* "traces" section */
	if (hld_debug) {
		hbuf_appendf(&buf, "%s", hld_cfg_traces_str);
		if (!hbuf_is_null(&tbuf))
			hbuf_appendf(&buf, "%.*s\n", (int)tbuf.data, tbuf.area);
	}
	/* "default section */
	if (!hbuf_is_null(&dbuf))
		hbuf_appendf(&buf, "%.*s\n", (int)dbuf.data, dbuf.area);

	fileless_cfg.filename = strdup("haterm cfgfile");
	fileless_cfg.content = strdup(buf.area);
	if (!fileless_cfg.filename || !fileless_cfg.content) {
		ha_alert("cfgfile strdup() failed.\n");
		goto leave;
	}

	fileless_cfg.size = buf.data;

	/* Config dump */
	if (dump) {
		fprintf(stdout, "%.*s", (int)fileless_cfg.size, fileless_cfg.content);
		exit(0);
	}

#if 0
	if (arg_reqs > 0 && arg_reqs < arg_usr) {
		ha_alert("user count must not exceed request count\n");
		goto leave;
	}
#endif

	/* Inverse the URLs and their paths */
	hld_url_cfgs_inv();
	err = 0;
leave:
	free_hbuf(&gbuf);
	free_hbuf(&buf);
	if (err)
		exit(1);
}

/* Dummy argv copier function */
char **copy_argv(int argc, char **argv)
{
	char **ret = calloc(1, sizeof(*ret));

	if (ret)
		*ret = strdup("");

	return ret;
}

static int hld_pre_check(void)
{
	char *errmsg = NULL;

	if (!setup_new_proxy(&hld_proxy, "<HALOAD-BE>",
	                     PR_CAP_FE | PR_CAP_BE | PR_CAP_INT, &errmsg)) {
		ha_alert("could not setup internal proxy: %s\n", errmsg);
		ha_free(&errmsg);
		return ERR_FATAL;
	}

	hld_proxy.mode = PR_MODE_HTTP;
	hld_proxy.next = proxies_list;
    proxies_list = &hld_proxy;

    hld_proxy.timeout.server = 60000;
    hld_proxy.timeout.connect = 60000;

	return ERR_NONE;
}
REGISTER_PRE_CHECK(hld_pre_check);

static int hld_deinit(void)
{
	ha_free(&old_argv[0]);
	ha_free(&old_argv);
	return 1;
}
REGISTER_POST_DEINIT(hld_deinit);
