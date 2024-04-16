#ifndef _HAPROXY_STATS_HTML_T_H
#define _HAPROXY_STATS_HTML_T_H

/* HTTP stats : applet.st0 */
enum {
	STAT_HTTP_INIT = 0,  /* Initial state */
	STAT_HTTP_HEAD,      /* send headers before dump */
	STAT_HTTP_DUMP,      /* dumping stats */
	STAT_HTTP_POST,      /* waiting post data */
	STAT_HTTP_LAST,      /* sending last chunk of response */
	STAT_HTTP_DONE,      /* dump is finished */
	STAT_HTTP_END,       /* finished */
};

/* HTML form to limit output scope */
#define STAT_SCOPE_TXT_MAXLEN 20      /* max len for scope substring */
#define STAT_SCOPE_INPUT_NAME "scope" /* pattern form scope name <input> in html form */
#define STAT_SCOPE_PATTERN    "?" STAT_SCOPE_INPUT_NAME "="


#endif /* _HAPROXY_STATS_HTML_T_H */
