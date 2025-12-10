#include <stdlib.h>
#include <string.h>

#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/protocol-t.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>
#include <haproxy/version.h>

/* global options */
struct global global = {
	.uid = -1, // not set
	.gid = -1, // not set
	.hard_stop_after = TICK_ETERNITY,
	.close_spread_time = TICK_ETERNITY,
	.close_spread_end = TICK_ETERNITY,
	.numa_cpu_mapping = 1,
	.nbthread = 0,
	.req_count = 0,
	.loggers = LIST_HEAD_INIT(global.loggers),
	.maxzlibmem = DEFAULT_MAXZLIBMEM * 1024U * 1024U,
	.comp_rate_lim = 0,
	.ssl_server_verify = SSL_SERVER_VERIFY_REQUIRED,
	.unix_bind = {
		 .ux = {
			 .uid = -1,
			 .gid = -1,
			 .mode = 0,
		 }
	},
	.tune = {
		.options = GTUNE_LISTENER_MQ_OPT,
		.bufsize = (BUFSIZE + 2*sizeof(void *) - 1) & -(2*sizeof(void *)),
		.bufsize_small = BUFSIZE_SMALL,
		.maxrewrite = MAXREWRITE,
		.reserved_bufs = RESERVED_BUFS,
		.pattern_cache = DEFAULT_PAT_LRU_SIZE,
		.pool_low_ratio  = 20,
		.pool_high_ratio = 25,
		.max_http_hdr = MAX_HTTP_HDR,
#ifdef USE_OPENSSL
		.sslcachesize = SSLCACHESIZE,
#endif
		.comp_maxlevel = 1,
		.glitch_kill_maxidle = 100,
#ifdef DEFAULT_IDLE_TIMER
		.idle_timer = DEFAULT_IDLE_TIMER,
#else
		.idle_timer = 1000, /* 1 second */
#endif
		.nb_stk_ctr = MAX_SESS_STKCTR,
		.default_shards = -2, /* by-group */
	},
#ifdef USE_OPENSSL
#ifdef DEFAULT_MAXSSLCONN
	.maxsslconn = DEFAULT_MAXSSLCONN,
#endif
#endif
	/* by default allow clients which use a privileged port for TCP only */
	.clt_privileged_ports = HA_PROTO_TCP,
	/* others NULL OK */
};

int stopping;	/* non zero means stopping in progress */

/* These are strings to be reported in the output of "haproxy -vv". They may
 * either be constants (in which case must_free must be zero) or dynamically
 * allocated strings to pass to free() on exit, and in this case must_free
 * must be non-zero.
 */
struct list build_opts_list = LIST_HEAD_INIT(build_opts_list);
struct build_opts_str {
	struct list list;
	const char *str;
	int must_free;
};

/*********************************************************************/
/*  general purpose functions  ***************************************/
/*********************************************************************/

/* used to register some build option strings at boot. Set must_free to
 * non-zero if the string must be freed upon exit.
 */
void hap_register_build_opts(const char *str, int must_free)
{
	struct build_opts_str *b;

	b = calloc(1, sizeof(*b));
	if (!b) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	b->str = str;
	b->must_free = must_free;
	LIST_APPEND(&build_opts_list, &b->list);
}

/* returns the first build option when <curr> is NULL, or the next one when
 * <curr> is passed the last returned value. NULL when there is no more entries
 * in the list. Otherwise the returned pointer is &opt->str so the caller can
 * print it as *ret.
 */
const char **hap_get_next_build_opt(const char **curr)
{
	struct build_opts_str *head, *start;

	head = container_of(&build_opts_list, struct build_opts_str, list);

	if (curr)
		start = container_of(curr, struct build_opts_str, str);
	else
		start = head;

	start = container_of(start->list.n, struct build_opts_str, list);

	if (start == head)
		return NULL;

	return &start->str;
}

/* used to make a new feature appear in the build_features list at boot time.
 * The feature must be in the format "XXX" without the leading "+" which will
 * be automatically appended.
 */
void hap_register_feature(const char *name)
{
	static int must_free = 0;
	int new_len = strlen(build_features) + 2 + strlen(name);
	char *new_features;
	char *startp, *endp;
	int found = 0;

	new_features = malloc(new_len + 1);
	if (!new_features)
		return;

	strlcpy2(new_features, build_features, new_len);

	startp = new_features;

	/* look if the string already exists */
	while (startp) {
		char *sign = startp;

		/* tokenize for simpler strcmp */
		endp = strchr(startp, ' ');
		if (endp)
			*endp = '\0';

		startp++; /* skip sign */

		if (strcmp(startp, name) == 0) {
			*sign = '+';
			found = 1;
		}

		/* couldn't find a space, that's the end of the string */
		if (!endp)
			break;

		*endp = ' ';
		startp = endp + 1;

		if (found)
			break;
	}

	/* if we didn't find the feature add it to the string */
	if (!found)
		snprintf(new_features, new_len + 1, "%s +%s", build_features, name);

	if (must_free)
		ha_free(&build_features);

	build_features = new_features;
	must_free = 1;
}

void ha_free_build_opts_list(void)
{
	struct build_opts_str *bol, *bolb;

	list_for_each_entry_safe(bol, bolb, &build_opts_list, list) {
		if (bol->must_free)
			free((void *)bol->str);
		LIST_DELETE(&bol->list);
		free(bol);
	}
}
