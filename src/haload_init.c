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
char *ssl_opts;

__attribute__((unused))
static const char *hld_cfg_dflt_str =
	"defaults\n"
		"\tmode http\n"
		"\thttp-reuse never\n"
		"\ttimeout connect 5s\n"
		"\ttimeout server 40s\n";

static void  hld_usage(char *name, int argc, int line)
{
	fprintf(stderr, "argc=%d\n", argc);
	fprintf(stderr,
		"%d: Usage : %s [opts]\n"
		"        -d <time>      test duration in seconds (0)\n"
		"        -l             enable long output format; double for raw values\n"
		"        -n <reqs>      maximum total requests (-1)\n"
		"        -r <reqs>      number of requests per connection (-1)\n"
		"        -u <users>     number of users (1)\n"
		"        -w <time>      I/O timeout in milliseconds (10000)\n"
		"        -C             dump the configuration and exit\n"
		"        -H \"foo:bar\"   add this header name and value\n"
		"        -I             use HEAD instead of GET\n"
		"        -v             shows version\n"
		"        --traces       enable the traces for all the HTTP protocols\n"
		"where <opts> may be any combination of:\n",
		line, name);
	exit(1);
}

static const char *hld_cfg_traces_str =
	"traces\n"
		"\ttrace ssl sink stdout level developer start now verbosity clean\n"
		"\ttrace haload sink stdout level developer start now verbosity clean\n"
		"\ttrace quic sink stdout level developer start now\n"
		"\ttrace h1 sink stdout level developer start now verbosity minimal\n"
		"\ttrace h2 sink stdout level developer start now verbosity minimal\n"
		"\ttrace h3 sink stdout level developer start now verbosity minimal\n"
		"\ttrace qmux sink stdout level developer start now verbosity minimal\n";

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
	struct hld_path *p;

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

			p = malloc(sizeof(*p));
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

	hld_url_cfg = malloc(sizeof(*hld_url_cfg));
	p = malloc(sizeof(*p));
	if (!hld_url_cfg || !p)
		goto err;

	p->path = path;
	p->next = NULL;

	hld_url_cfg->ssl = ssl;
	hld_url_cfg->addr = addr;
	hld_url_cfg->raw_addr = raw_addr;

	if (ssl_opts) {
		hld_url_cfg->ssl_opts = ssl_opts;
		ssl_opts = NULL;
	}
	else
		hld_url_cfg->ssl_opts = NULL;

	hld_url_cfg->srv = NULL;
	hld_url_cfg->paths = p;
	/* Append this new URL to the list */
	hld_url_cfg->next = hld_url_cfgs;
	hld_url_cfgs = hld_url_cfg;

	return hld_url_cfg;
 err:
	free(addr);
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
				if (strcmp(opt, "traces") == 0) {
					hld_debug = 1;
#if 0
					/* optional argument */
					if (argc - 1 > 0 && **(argv + 1) != '-') {
						fprintf(stderr, "trace arg: '%s'\n", *(argv + 1));
						if (hbuf_is_null(&tbuf) && hbuf_alloc(&tbuf) == NULL) {
							ha_alert("failed to allocate a buffer.\n");
							goto leave;
						}

						hbuf_str_append(&tbuf, *(argv + 1));
						argc--; argv++;
					}
#endif
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
				if (!*opt) {
					argv++, argc--;

					if ((argc <= 0 || **argv == '-'))
						hld_usage(progname, argc, __LINE__);

					opt = *argv;
				}
				ssl_opts = strdup(opt);
			}
			else if (*opt == 'u') {
				opt++;
				hld_parse_long(&arg_usr, opt, &argc, &argv);
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
			else if (*opt == 'G') {
				argv++; argc--;
				if (argc <= 0 || **argv == '-')
					hld_usage(progname, argc, __LINE__);

				hbuf_str_append(&gbuf, *argv);
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

	if (!hld_url_cfgs) {
		ha_alert("no URL provided\n");
		goto leave;
	}

	/* "global" section */
	if (!hbuf_is_null(&gbuf))
		hbuf_appendf(&buf, "%.*s\n", (int)gbuf.data, gbuf.area);
	/* "traces" section */
	if (hld_debug) {
		hbuf_appendf(&buf, "%s", hld_cfg_traces_str);
		if (!hbuf_is_null(&tbuf))
			hbuf_appendf(&buf, "%.*s\n", (int)tbuf.data, tbuf.area);
	}

	//hbuf_appendf(&buf, "%s\n", hld_cfg_dflt_str);

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

	if (arg_reqs > 0 && arg_reqs < arg_usr) {
		ha_alert("user count must not exceed request count\n");
		goto leave;
	}

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

    hld_proxy.timeout.server = 20000;
    hld_proxy.timeout.connect = 25000;

	return ERR_NONE;
}
REGISTER_PRE_CHECK(hld_pre_check);
