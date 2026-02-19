#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/version.h>

static int haterm_debug;

/*
 * This function prints the command line usage for haterm and exits
 */
static void haterm_usage(char *name)
{
	fprintf(stderr,
		"Usage : %s -L [<ip>]:<clear port>[:<TCP&QUIC SSL port>] [-L...]* [opts]\n"
		"where <opts> may be any combination of:\n"
		"        -G <line> : multiple option; append <line> to the \"global\" section\n"
		"        -F <line> : multiple option; append <line> to the \"frontend\" section\n"
		"        -T <line> : multiple option; append <line> to the \"traces\" section\n"
		"        -C : dump the configuration and exit\n"
		"        -D : goes daemon\n"
		"        -v : shows version\n"
		"        -d : enable the traces for all http protocols\n", name);
	exit(1);
}

#define HATERM_FRONTEND_NAME   "___haterm_frontend___"
#define HATERM_RSA_CERT_NAME   "haterm.pem.rsa"
#define HATERM_ECDSA_CERT_NAME "haterm.pem.ecdsa"

static const char *haterm_cfg_dflt_str =
        "defaults\n"
            "\tmode haterm\n"
            "\ttimeout client 25s\n";

static const char *haterm_cfg_crt_store_str =
        "crt-store\n"
            "\tload generate-dummy on keytype RSA crt "   HATERM_RSA_CERT_NAME   "\n"
            "\tload generate-dummy on keytype ECDSA crt " HATERM_ECDSA_CERT_NAME "\n";

static const char *haterm_cfg_traces_str =
        "traces\n"
            "\ttrace h1 sink stderr level user start now verbosity minimal\n"
            "\ttrace h2 sink stderr level user start now verbosity minimal\n"
            "\ttrace h3 sink stderr level user start now verbosity minimal\n"
            "\ttrace qmux sink stderr level user start now verbosity minimal\n";

/* Very small API similar to buffer API to carefully build some strings */
#define HBUF_NULL ((struct hbuf) { })
#define HBUF_SIZE (16 << 10) /* bytes */
struct hbuf {
	char *area;
	size_t data;
	size_t size;
};

static struct hbuf *hbuf_alloc(struct hbuf *h)
{
	h->area = malloc(HBUF_SIZE);
	if (!h->area)
		return NULL;

	h->size = HBUF_SIZE;
	h->data = 0;
	return h;
}

static inline void free_hbuf(struct hbuf *h)
{
	free(h->area);
	h->area = NULL;
}

__attribute__ ((format(printf, 2, 3)))
static void hbuf_appendf(struct hbuf *h, char *fmt, ...)
{
	va_list argp;
	size_t room;
	int ret;

	room = h->size - h->data;
	if (!room)
		return;

	va_start(argp, fmt);
	ret = vsnprintf(h->area + h->data, room, fmt, argp);
	if (ret >= room)
		h->area[h->data] = '\0';
	else
		h->data += ret;
	va_end(argp);
}

static inline size_t hbuf_is_null(const struct hbuf *h)
{
	return h->size == 0;
}

/* Simple function, to append <line> to <b> without without
 * trailing '\0' character.
 * Take into an account the '\t' and '\n' escaped sequeces.
 */
static void hstream_str_buf_append(struct hbuf *h, const char *line)
{
	const char *p, *end;
	char *to = h->area + h->data;
	char *wrap = h->area + h->size;
	int nl = 0; /* terminal '\n' */

	p = line;
	end = line + strlen(line);

	/* prepend '\t' if missing */
	if (strncmp(line, "\\t", 2) != 0 && to < wrap) {
		*to++ = '\t';
		h->data++;
	}

	while (p < end && to < wrap) {
		if (*p == '\\') {
			if (!*++p || p >= end)
				break;
			if (*p == 'n') {
				*to++ = '\n';
				if (p + 1 >= end)
					nl = 1;
			}
			else if (*p == 't')
				*to++ = '\t';
			p++;
			h->data++;
		}
		else {
			*to++ = *p++;
			h->data++;
		}
	}

	/* add a terminal '\n' if not already present */
	if (to < wrap && !nl) {
		*to++ = '\n';
		h->data++;
	}
}

/* This function initialises the haterm HTTP benchmark server from
 * <argv>. This consists in building a configuration file in memory
 * using the haproxy configuration language.
 * Make exit(1) the process in case of any failure.
 */
void haproxy_init_args(int argc, char **argv)
{
	/* Initialize haterm fileless cfgfile from <argv> arguments array.
	 * Never fails.
	 */
	int has_bind = 0, err = 1, dump = 0, has_ssl = 0;
	struct hbuf gbuf = HBUF_NULL; // "global" section
	struct hbuf mbuf = HBUF_NULL; // to build the main of the cfgfile
	struct hbuf fbuf = HBUF_NULL; // "frontend" section
	struct hbuf tbuf = HBUF_NULL; // "traces" section

	fileless_mode = 1;
	if (argc <= 1)
		haterm_usage(progname);

	if (hbuf_alloc(&mbuf) == NULL) {
		ha_alert("failed to alloce a buffer.\n");
		exit(1);
	}

	/* skip program name and start */
	argc--; argv++;
	while (argc > 0) {
		char *opt;

		if (**argv == '-') {
			opt = *argv + 1;
			if (*opt == 'd') {
				/* empty option */
				if (*(opt + 1))
					haterm_usage(progname);

				/* debug mode */
				haterm_debug = 1;
			}
			else if (*opt == 'C') {
				/* empty option */
				if (*(opt + 1))
					haterm_usage(progname);

				dump = 1;
			}
			else if (*opt == 'D') {
				/* empty option */
				if (*(opt + 1))
					haterm_usage(progname);

				global.mode |= MODE_DAEMON;
			}
			else if (*opt == 'v') {
				/* empty option */
				if (*(opt + 1))
					haterm_usage(progname);

				printf("HATerm version " HAPROXY_VERSION " released " HAPROXY_DATE "\n");
				exit(0);
			}
			else if (*opt == 'F') {
				argv++; argc--;
				if (argc <= 0 || **argv == '-')
					haterm_usage(progname);

				if (hbuf_is_null(&fbuf)) {
					if (hbuf_alloc(&fbuf) == NULL) {
						ha_alert("failed to allocate a buffer.\n");
						goto leave;
					}

					hbuf_appendf(&fbuf, "frontend " HATERM_FRONTEND_NAME "\n");
					hbuf_appendf(&fbuf, "\toption accept-unsafe-violations-in-http-request\n");
				}

				hstream_str_buf_append(&fbuf, *argv);
			}
			else if (*opt == 'G') {
				argv++; argc--;
				if (argc <= 0 || **argv == '-')
					haterm_usage(progname);

				if (hbuf_is_null(&gbuf)) {
					if (hbuf_alloc(&gbuf) == NULL) {
						ha_alert("failed to allocate a buffer.\n");
						goto leave;
					}

					hbuf_appendf(&gbuf, "global\n");
				}

				hstream_str_buf_append(&gbuf, *argv);
			}
			else if (*opt == 'T') {
				argv++; argc--;
				if (argc <= 0 || **argv == '-')
					haterm_usage(progname);

				if (hbuf_is_null(&tbuf) && hbuf_alloc(&tbuf) == NULL) {
					ha_alert("failed to allocate a buffer.\n");
					goto leave;
				}

				haterm_debug = 1;
				hstream_str_buf_append(&tbuf, *argv);
			}
			else if (*opt == 'L') {
				/* binding */
				int __maybe_unused ipv6 = 0;
				char *ip, *port, *port1 = NULL, *port2 = NULL;

				argv++; argc--;
				if (argc <= 0 || **argv == '-')
					haterm_usage(progname);

				port = ip = *argv;
				if (*ip == '[') {
					/* IPv6 address */
					ip++;
					port = strchr(port, ']');
					if (!port)
						haterm_usage(progname);
					*port++ = '\0';
					ipv6 = 1;
				}

				while ((port = strchr(port, ':'))) {
					*port++ = '\0';
					if (!port1)
						port1 = port;
					else {
						if (port2)
							haterm_usage(progname);

						port2 = port;
					}
				}

				if (!port1)
					haterm_usage(progname);

				if (hbuf_is_null(&fbuf)) {
					if (hbuf_alloc(&fbuf) == NULL) {
						ha_alert("failed to allocate a buffer.\n");
						goto leave;
					}

					hbuf_appendf(&fbuf, "frontend " HATERM_FRONTEND_NAME "\n");
					hbuf_appendf(&fbuf, "\toption accept-unsafe-violations-in-http-request\n");
				}

				/* clear HTTP */
				hbuf_appendf(&fbuf, "\tbind %s:%s shards by-thread\n", ip, port1);
				has_bind = 1;
				if (port2) {
					has_ssl = 1;

					/* SSL/TCP binding */
					hbuf_appendf(&fbuf, "\tbind %s:%s shards by-thread ssl "
					             "alpn h2,http1.1,http1.0"
					             " crt " HATERM_RSA_CERT_NAME
					             " crt " HATERM_ECDSA_CERT_NAME "\n",
					             ip, port2);

					/* QUIC binding */
					hbuf_appendf(&fbuf, "\tbind %s@%s:%s shards by-thread ssl"
					             " crt " HATERM_RSA_CERT_NAME
					             " crt " HATERM_ECDSA_CERT_NAME "\n",
					             ipv6 ? "quic6" : "quic4", ip, port2);
				}
			}
			else
				haterm_usage(progname);
		}
		else
			haterm_usage(progname);
		argv++; argc--;
	}

	if (!has_bind) {
		ha_alert("No binding! Exiting...\n");
		haterm_usage(progname);
	}

	if (hbuf_is_null(&gbuf)) {
		/* use 3MB of local cache per thread mainly for QUIC */
		if (hbuf_alloc(&gbuf) == NULL) {
			ha_alert("failed to allocate a buffer.\n");
			goto leave;
		}
		hbuf_appendf(&gbuf, "global\n");
		hbuf_appendf(&gbuf, "\ttune.memory.hot-size 3145728\n");
	}

	/* "global" section */
	if (!hbuf_is_null(&gbuf))
		hbuf_appendf(&mbuf, "%.*s\n", (int)gbuf.data, gbuf.area);
	/* "traces" section */
	if (haterm_debug) {
		hbuf_appendf(&mbuf, "%s", haterm_cfg_traces_str);
		if (!hbuf_is_null(&tbuf))
			hbuf_appendf(&mbuf, "%.*s\n", (int)tbuf.data, tbuf.area);
	}
	/* "defaults" section */
	hbuf_appendf(&mbuf, "%s\n", haterm_cfg_dflt_str);

	/* "crt-store" section */
	if (has_ssl)
		hbuf_appendf(&mbuf, "%s\n", haterm_cfg_crt_store_str);

	/* "frontend" section */
	hbuf_appendf(&mbuf, "%.*s\n", (int)fbuf.data, fbuf.area);

	fileless_cfg.filename = strdup("haterm cfgfile");
	fileless_cfg.content = strdup(mbuf.area);
	if (!fileless_cfg.filename || !fileless_cfg.content) {
		ha_alert("cfgfile strdup() failed.\n");
		goto leave;
	}

	fileless_cfg.size = mbuf.data;
	if (dump) {
		fprintf(stdout, "%.*s", (int)fileless_cfg.size, fileless_cfg.content);
		exit(0);
	}

	/* no pool debugging */
	pool_debugging = 0;

	err = 0;
 leave:
	free_hbuf(&mbuf);
	free_hbuf(&gbuf);
	free_hbuf(&fbuf);
	free_hbuf(&tbuf);
	if (err)
		exit(1);
}

/* Dummy arg copier function */
char **copy_argv(int argc, char **argv)
{
	char **ret = calloc(1, sizeof(*ret));
	*ret = strdup("");
	return ret;
}
