/*
 * include/haproxy/tcpcheck-t.h
 * TCP check definitions, enums, macros and bitfields.
 *
 * Copyright 2000-2009,2020 Willy Tarreau <w@1wt.eu>
 * Copyright 2007-2010 Krzysztof Piotr Oledzki <ole@ans.pl>
 * Copyright 2013 Baptiste Assmann <bedis9@gmail.com>
 * Copyright 2020 Gaetan Rivet <grive@u256.net>
 * Copyright 2020 Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _HAPROXY_TCPCHECK_T_H
#define _HAPROXY_TCPCHECK_T_H

#include <import/ebtree-t.h>
#include <import/ist.h>
#include <haproxy/api-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/check-t.h>
#include <haproxy/connection-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/vars-t.h>

/* options for tcp-check connect */
#define TCPCHK_OPT_NONE            0x0000  /* no options specified, default */
#define TCPCHK_OPT_SEND_PROXY      0x0001  /* send proxy-protocol string */
#define TCPCHK_OPT_SSL             0x0002  /* SSL connection */
#define TCPCHK_OPT_LINGER          0x0004  /* Do not RST connection, let it linger */
#define TCPCHK_OPT_DEFAULT_CONNECT 0x0008  /* Do a connect using server params */
#define TCPCHK_OPT_IMPLICIT        0x0010  /* Implicit connect */
#define TCPCHK_OPT_SOCKS4          0x0020  /* check the connection via socks4 proxy */
#define TCPCHK_OPT_HAS_DATA        0x0040  /* data should be sent after connection */

enum tcpcheck_send_type {
	TCPCHK_SEND_UNDEF = 0,  /* Send is not parsed. */
	TCPCHK_SEND_STRING,     /* Send an ASCII string. */
	TCPCHK_SEND_BINARY,     /* Send a binary sequence. */
	TCPCHK_SEND_STRING_LF,  /* Send an ASCII log-format string. */
	TCPCHK_SEND_BINARY_LF,  /* Send a binary log-format sequence. */
	TCPCHK_SEND_HTTP,       /* Send an HTTP request */
};

/* flags for tcp-check send */
#define TCPCHK_SND_HTTP_FL_URI_FMT    0x0001 /* Use a log-format string for the uri */
#define TCPCHK_SND_HTTP_FL_BODY_FMT   0x0002 /* Use a log-format string for the body */
#define TCPCHK_SND_HTTP_FROM_OPT      0x0004 /* Send rule coming from "option httpck" directive */

enum tcpcheck_eval_ret {
	TCPCHK_EVAL_WAIT = 0,
	TCPCHK_EVAL_STOP,
	TCPCHK_EVAL_CONTINUE,
};

enum tcpcheck_expect_type {
	TCPCHK_EXPECT_UNDEF = 0,         /* Match is not used. */
	TCPCHK_EXPECT_STRING,            /* Matches a string. */
	TCPCHK_EXPECT_STRING_REGEX,      /* Matches a regular pattern. */
	TCPCHK_EXPECT_STRING_LF,         /* Matches a log-format string. */
	TCPCHK_EXPECT_BINARY,            /* Matches a binary sequence on a hex-encoded text. */
	TCPCHK_EXPECT_BINARY_REGEX,      /* Matches a regular pattern on a hex-encoded text. */
	TCPCHK_EXPECT_BINARY_LF,         /* Matches a log-format binary sequence on a hex-encoded text. */
	TCPCHK_EXPECT_CUSTOM,            /* Execute a custom function. */
	TCPCHK_EXPECT_HTTP_STATUS,       /* Matches a list of codes on the HTTP status */
	TCPCHK_EXPECT_HTTP_STATUS_REGEX, /* Matches a regular pattern on the HTTP status */
	TCPCHK_EXPECT_HTTP_HEADER,       /* Matches on HTTP headers */
	TCPCHK_EXPECT_HTTP_BODY,         /* Matches a string oa the HTTP payload */
	TCPCHK_EXPECT_HTTP_BODY_REGEX,   /* Matches a regular pattern on a HTTP payload */
	TCPCHK_EXPECT_HTTP_BODY_LF,      /* Matches a log-format string on the HTTP payload */
};

/* tcp-check expect flags */
#define TCPCHK_EXPT_FL_INV             0x0001 /* Matching is inversed */
#define TCPCHK_EXPT_FL_HTTP_HNAME_STR  0x0002 /* Exact match on the HTTP header name */
#define TCPCHK_EXPT_FL_HTTP_HNAME_BEG  0x0004 /* Prefix match on the HTTP header name */
#define TCPCHK_EXPT_FL_HTTP_HNAME_END  0x0008 /* Suffix match on the HTTP header name */
#define TCPCHK_EXPT_FL_HTTP_HNAME_SUB  0x0010 /* Substring match on the HTTP header name */
#define TCPCHK_EXPT_FL_HTTP_HNAME_REG  0x0020 /* Regex match on the HTTP header name */
#define TCPCHK_EXPT_FL_HTTP_HNAME_FMT  0x0040 /* The HTTP header name is a log-format string */
#define TCPCHK_EXPT_FL_HTTP_HVAL_NONE  0x0080 /* No match on the HTTP header value */
#define TCPCHK_EXPT_FL_HTTP_HVAL_STR   0x0100 /* Exact match on the HTTP header value */
#define TCPCHK_EXPT_FL_HTTP_HVAL_BEG   0x0200 /* Prefix match on the HTTP header value */
#define TCPCHK_EXPT_FL_HTTP_HVAL_END   0x0400 /* Suffix match on the HTTP header value */
#define TCPCHK_EXPT_FL_HTTP_HVAL_SUB   0x0800 /* Substring match on the HTTP header value */
#define TCPCHK_EXPT_FL_HTTP_HVAL_REG   0x1000 /* Regex match on the HTTP header value*/
#define TCPCHK_EXPT_FL_HTTP_HVAL_FMT   0x2000 /* The HTTP header value is a log-format string */
#define TCPCHK_EXPT_FL_HTTP_HVAL_FULL  0x4000 /* Match the full header value ( no stop on commas ) */

#define TCPCHK_EXPT_FL_HTTP_HNAME_TYPE 0x003E /* Mask to get matching method on header name */
#define TCPCHK_EXPT_FL_HTTP_HVAL_TYPE  0x1F00 /* Mask to get matching method on header value */

/* possible actions for tcpcheck_rule->action */
enum tcpcheck_rule_type {
	TCPCHK_ACT_SEND = 0, /* send action, regular string format */
	TCPCHK_ACT_EXPECT, /* expect action, either regular or binary string */
	TCPCHK_ACT_CONNECT, /* connect action, to probe a new port */
	TCPCHK_ACT_COMMENT, /* no action, simply a comment used for logs */
	TCPCHK_ACT_ACTION_KW, /* custom registered action_kw rule. */
};

#define TCPCHK_RULES_NONE           0x00000000
#define TCPCHK_RULES_UNUSED_TCP_RS  0x00000001 /* An unused tcp-check ruleset exists */
#define TCPCHK_RULES_UNUSED_HTTP_RS 0x00000002 /* An unused http-check ruleset exists */
#define TCPCHK_RULES_UNUSED_RS      0x00000003 /* Mask for unused ruleset */

#define TCPCHK_RULES_PGSQL_CHK   0x00000010
#define TCPCHK_RULES_REDIS_CHK   0x00000020
#define TCPCHK_RULES_SMTP_CHK    0x00000030
#define TCPCHK_RULES_HTTP_CHK    0x00000040
#define TCPCHK_RULES_MYSQL_CHK   0x00000050
#define TCPCHK_RULES_LDAP_CHK    0x00000060
#define TCPCHK_RULES_SSL3_CHK    0x00000070
#define TCPCHK_RULES_AGENT_CHK   0x00000080
#define TCPCHK_RULES_SPOP_CHK    0x00000090
/* Unused 0x000000A0..0x00000FF0 (reserved for future proto) */
#define TCPCHK_RULES_TCP_CHK     0x00000FF0
#define TCPCHK_RULES_PROTO_CHK   0x00000FF0 /* Mask to cover protocol check */

struct check;
struct tcpcheck_connect {
	char *sni;                     /* server name to use for SSL connections */
	char *alpn;                    /* ALPN to use for the SSL connection */
	int alpn_len;                  /* ALPN string length */
	const struct mux_proto_list *mux_proto; /* the mux to use for all outgoing connections (specified by the "proto" keyword) */
	uint16_t options;              /* options when setting up a new connection */
	uint16_t port;                 /* port to connect to */
	struct sample_expr *port_expr; /* sample expr to determine the port, may be NULL */
	struct sockaddr_storage addr;  /* the address to the connect */
};

struct tcpcheck_http_hdr {
	struct ist  name;     /* the header name */
	struct lf_expr value; /* the log-format string value */
	struct list list;     /* header linked list */
};

struct tcpcheck_codes {
	unsigned int (*codes)[2]; /* an array of roange of codes: [0]=min [1]=max */
	size_t num;               /* number of entry in the array */
};

struct tcpcheck_send {
	enum tcpcheck_send_type type;
	union {
		struct ist  data;   /* an ASCII string or a binary sequence */
		struct lf_expr fmt; /* an ASCII or hexa log-format string */
		struct {
			unsigned int flags;             /* TCPCHK_SND_HTTP_FL_* */
			struct http_meth meth;          /* the HTTP request method */
			union {
				struct ist  uri;        /* the HTTP request uri is a string  */
				struct lf_expr uri_fmt; /* or a log-format string */
			};
			struct ist vsn;                 /* the HTTP request version string */
			struct list hdrs;               /* the HTTP request header list */
			union {
				struct ist   body;      /* the HTTP request payload is a string */
				struct lf_expr body_fmt;/* or a log-format string */
			};
		} http;           /* Info about the HTTP request to send */
	};
};

struct tcpcheck_expect {
	enum tcpcheck_expect_type type;   /* Type of pattern used for matching. */
	unsigned int flags;               /* TCPCHK_EXPT_FL_* */
	union {
		struct ist data;             /* Matching a literal string / binary anywhere in the response. */
		struct my_regex *regex;      /* Matching a regex pattern. */
		struct tcpcheck_codes codes; /* Matching a list of codes */
		struct lf_expr fmt;          /* Matching a log-format string / binary */
		struct {
			union {
				struct ist name;
				struct lf_expr name_fmt;
				struct my_regex *name_re;
			};
			union {
				struct ist value;
				struct lf_expr value_fmt;
				struct my_regex *value_re;
			};
		} hdr;                       /* Matching a header pattern */


		/* custom function to eval expect rule */
		enum tcpcheck_eval_ret (*custom)(struct check *, struct tcpcheck_rule *, int);
	};
	struct tcpcheck_rule *head;     /* first expect of a chain. */
	int min_recv;                   /* Minimum amount of data before an expect can be applied. (default: -1, ignored) */
	enum healthcheck_status ok_status;   /* The healthcheck status to use on success (default: L7OKD) */
	enum healthcheck_status err_status;  /* The healthcheck status to use on error (default: L7RSP) */
	enum healthcheck_status tout_status; /* The healthcheck status to use on timeout (default: L7TOUT) */
	struct lf_expr onerror_fmt;          /* log-format string to use as comment on error */
	struct lf_expr onsuccess_fmt;        /* log-format string to use as comment on success (if last rule) */
	struct sample_expr *status_expr;     /* sample expr to determine the check status code */
};

struct tcpcheck_action_kw {
	struct act_rule *rule;
};

struct tcpcheck_rule {
	struct list list;                       /* list linked to from the proxy */
	enum tcpcheck_rule_type action;         /* type of the rule. */
	int index;                              /* Index within the list. Starts at 0. */
	char *comment;				/* comment to be used in the logs and on the stats socket */
	union {
		struct tcpcheck_connect connect; /* Connect rule. */
		struct tcpcheck_send send;      /* Send rule. */
		struct tcpcheck_expect expect;  /* Expected pattern. */
		struct tcpcheck_action_kw action_kw;  /* Custom action. */
	};
};

/* A list of tcp-check vars, to be registered before executing a ruleset */
struct tcpcheck_var {
	struct ist name;         /* the variable name with the scope */
	struct sample_data data; /* the data associated to the variable */
	struct list list;        /* element to chain tcp-check vars */
};

/* a list of tcp-check rules */
struct tcpcheck_rules {
	unsigned int flags;       /* flags applied to the rules */
	struct list *list;        /* the list of tcpcheck_rules */
	struct list  preset_vars; /* The list of variable to preset before executing the ruleset */
};

/* A list of tcp-check rules with a name */
struct tcpcheck_ruleset {
	struct list rules;     /* the list of tcpcheck_rule */
	struct ebpt_node node; /* node in the shared tree */
};


#endif /* _HAPROXY_CHECKS_T_H */
