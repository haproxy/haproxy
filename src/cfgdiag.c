#include <stdarg.h>
#include <stdlib.h>

#include <import/ebistree.h>

#include <haproxy/cfgdiag.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>

struct cookie_entry {
	struct ebpt_node node;
};

/* Use this function to emit diagnostic.
 * This can be used as a shortcut to set value pointed by <ret> to 1 at the
 * same time.
 */
static inline void diag_warning(int *ret, char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	*ret = 1;
	_ha_vdiag_warning(fmt, argp);
	va_end(argp);
}

/* Use this for dynamic allocation in diagnostics.
 * In case of allocation failure, this will immediately terminates haproxy.
 */
static inline void *diag_alloc(size_t size)
{
	void *out = NULL;

	if (!(out = malloc(size))) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

	return out;
}

/* Checks that two servers from the same backend does not share the same cookie
 * value. Backup servers are not taken into account as it can be quite common to
 * share cookie values in this case.
 */
static void srv_diag_cookies(int *ret, struct server *srv, struct eb_root *cookies_tree)
{
	struct ebpt_node *cookie_node;

	/* do not take into account backup servers */
	if (!srv->cookie || (srv->flags & SRV_F_BACKUP))
		return;

	cookie_node = ebis_lookup(cookies_tree, srv->cookie);
	if (cookie_node) {
		diag_warning(ret, "parsing [%s:%d] : 'server %s' : same cookie value is set for a previous non-backup server in the same backend, it may break connection persistence\n",
		             srv->conf.file, srv->conf.line, srv->id);
	}
	else {
		cookie_node = diag_alloc(sizeof(*cookie_node));
		cookie_node->key = srv->cookie;
		ebis_insert(cookies_tree, cookie_node);
	}
}

/* Reports a diag if check-reuse-pool is active while backend check ruleset is
 * non HTTP.
 */
static void srv_diag_check_reuse(int *ret, struct server *srv, struct proxy *px)
{
	if (srv->do_check && srv->check.reuse_pool) {
		if ((px->tcpcheck_rules.flags & TCPCHK_RULES_PROTO_CHK) != TCPCHK_RULES_HTTP_CHK) {
			diag_warning(ret, "parsing [%s:%d] : 'server %s': check-reuse-pool is ineffective for non http-check rulesets.\n",
			             srv->conf.file, srv->conf.line, srv->id);
		}
	}
}

/* Perform a series of diagnostics on every servers from the configuration. */
static void run_servers_diag(int *ret)
{
	struct eb_root cookies_tree = EB_ROOT_UNIQUE;
	struct ebpt_node *cookie_node;
	struct proxy  *px;
	struct server *srv;

	for (px = proxies_list; px; px = px->next) {
		for (srv = px->srv; srv; srv = srv->next) {
			srv_diag_cookies(ret, srv, &cookies_tree);
			srv_diag_check_reuse(ret, srv, px);
		}

		/* clear the cookies tree before passing to the next proxy */
		while ((cookie_node = ebpt_first(&cookies_tree))) {
			ebpt_delete(cookie_node);
			free(cookie_node);
		}
	}
}

/* Placeholder to execute various diagnostic checks after the configuration file
 * has been fully parsed. It will output a warning for each diagnostic found.
 *
 * Returns 0 if no diagnostic message has been found else 1.
 */
int cfg_run_diagnostics()
{
	int ret = 0;

	run_servers_diag(&ret);

	return ret;
}
