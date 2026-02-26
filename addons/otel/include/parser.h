/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_PARSER_H_
#define _OTEL_PARSER_H_

#define FLT_OTEL_SCOPE                        "OTEL"

/*
 * filter FLT_OTEL_OPT_NAME FLT_OTEL_OPT_FILTER_ID <FLT_OTEL_OPT_FILTER_ID_DEFAULT> FLT_OTEL_OPT_CONFIG <file>
 */
#define FLT_OTEL_OPT_NAME                     "opentelemetry"
#define FLT_OTEL_OPT_FILTER_ID                "id"
#define FLT_OTEL_OPT_FILTER_ID_DEFAULT        "otel-filter"
#define FLT_OTEL_OPT_CONFIG                   "config"

#define FLT_OTEL_PARSE_SECTION_INSTR_ID       "otel-instrumentation"
#define FLT_OTEL_PARSE_SECTION_GROUP_ID       "otel-group"
#define FLT_OTEL_PARSE_SECTION_SCOPE_ID       "otel-scope"

#define FLT_OTEL_PARSE_SPAN_ROOT              "root"
#define FLT_OTEL_PARSE_SPAN_PARENT            "parent"
#define FLT_OTEL_PARSE_SPAN_LINK              "link"
#define FLT_OTEL_PARSE_CTX_AUTONAME           "-"
#define FLT_OTEL_PARSE_CTX_IGNORE_NAME        '-'
#define FLT_OTEL_PARSE_CTX_USE_HEADERS        "use-headers"
#define FLT_OTEL_PARSE_CTX_USE_VARS           "use-vars"
#define FLT_OTEL_PARSE_OPTION_HARDERR         "hard-errors"
#define FLT_OTEL_PARSE_OPTION_DISABLED        "disabled"
#define FLT_OTEL_PARSE_OPTION_NOLOGNORM       "dontlog-normal"

/*
 * A description of the macro arguments can be found in the structure
 * flt_otel_parse_data definition
 */
#define FLT_OTEL_PARSE_INSTR_DEFINES                                                                                                                                      \
	FLT_OTEL_PARSE_INSTR_DEF(         ID, 0, CHAR, 2, 2, "otel-instrumentation", " <name>")                                                                           \
	FLT_OTEL_PARSE_INSTR_DEF(        ACL, 0, CHAR, 3, 0, "acl",                  " <name> <criterion> [flags] [operator] <value> ...")                                \
	FLT_OTEL_PARSE_INSTR_DEF(        LOG, 0, CHAR, 2, 0, "log",                  " { global | <addr> [len <len>] [format <fmt>] <facility> [<level> [<minlevel>]] }") \
	FLT_OTEL_PARSE_INSTR_DEF(     CONFIG, 0, NONE, 2, 2, "config",               " <file>")                                                                           \
	FLT_OTEL_PARSE_INSTR_DEF(     GROUPS, 0, NONE, 2, 0, "groups",               " <name> ...")                                                                       \
	FLT_OTEL_PARSE_INSTR_DEF(     SCOPES, 0, NONE, 2, 0, "scopes",               " <name> ...")                                                                       \
	FLT_OTEL_PARSE_INSTR_DEF( RATE_LIMIT, 0, NONE, 2, 2, "rate-limit",           " <value>")                                                                          \
	FLT_OTEL_PARSE_INSTR_DEF(     OPTION, 0, NONE, 2, 2, "option",               " { disabled | dontlog-normal | hard-errors }")                                      \
	FLT_OTEL_PARSE_INSTR_DEF(DEBUG_LEVEL, 0, NONE, 2, 2, "debug-level",          " <value>")

#define FLT_OTEL_PARSE_GROUP_DEFINES                                             \
	FLT_OTEL_PARSE_GROUP_DEF(    ID, 0, CHAR, 2, 2, "otel-group", " <name>") \
	FLT_OTEL_PARSE_GROUP_DEF(SCOPES, 0, NONE, 2, 0, "scopes",   " <name> ...")

#ifdef USE_OTEL_VARS
#  define FLT_OTEL_PARSE_SCOPE_INJECT_HELP    " <name-prefix> [use-vars] [use-headers]"
#  define FLT_OTEL_PARSE_SCOPE_EXTRACT_HELP   " <name-prefix> [use-vars | use-headers]"
#else
#  define FLT_OTEL_PARSE_SCOPE_INJECT_HELP    " <name-prefix> [use-headers]"
#  define FLT_OTEL_PARSE_SCOPE_EXTRACT_HELP   " <name-prefix> [use-headers]"
#endif

/*
 * The first argument of the FLT_OTEL_PARSE_SCOPE_STATUS_DEF() macro is defined
 * as otelc_span_status_t in <opentelemetry-c-wrapper/span.h> .
 */
#define FLT_OTEL_PARSE_SCOPE_STATUS_DEFINES               \
	FLT_OTEL_PARSE_SCOPE_STATUS_DEF(IGNORE, "ignore") \
	FLT_OTEL_PARSE_SCOPE_STATUS_DEF( UNSET, "unset" ) \
	FLT_OTEL_PARSE_SCOPE_STATUS_DEF(    OK, "ok"    ) \
	FLT_OTEL_PARSE_SCOPE_STATUS_DEF( ERROR, "error" )

/*
 * In case the possibility of working with OpenTelemetry context via HAProxy
 * variables is not used, args_max member of the structure flt_otel_parse_data
 * should be reduced for 'inject' keyword.  However, this is not critical
 * because in this case the 'use-vars' argument cannot be entered anyway,
 * so I will not complicate it here with additional definitions.
 */
#define FLT_OTEL_PARSE_SCOPE_DEFINES                                                                                                \
	FLT_OTEL_PARSE_SCOPE_DEF(          ID, 0, CHAR, 2, 2, "otel-scope",   " <name>")                                            \
	FLT_OTEL_PARSE_SCOPE_DEF(        SPAN, 0, NONE, 2, 7, "span",         " <name> [<reference>] [<link>] [root]")              \
	FLT_OTEL_PARSE_SCOPE_DEF(        LINK, 1, NONE, 2, 0,   "link",       " <span> ...")                                        \
	FLT_OTEL_PARSE_SCOPE_DEF(   ATTRIBUTE, 1, NONE, 3, 0,   "attribute",  " <key> <sample> ...")                                \
	FLT_OTEL_PARSE_SCOPE_DEF(       EVENT, 1, NONE, 4, 0,   "event",      " <name> <key> <sample> ...")                         \
	FLT_OTEL_PARSE_SCOPE_DEF(     BAGGAGE, 1,  VAR, 3, 0,   "baggage",    " <key> <sample> ...")                                \
	FLT_OTEL_PARSE_SCOPE_DEF(      INJECT, 1,  CTX, 2, 4,   "inject",     FLT_OTEL_PARSE_SCOPE_INJECT_HELP)                     \
	FLT_OTEL_PARSE_SCOPE_DEF(     EXTRACT, 0,  CTX, 2, 3,   "extract",    FLT_OTEL_PARSE_SCOPE_EXTRACT_HELP)                    \
	FLT_OTEL_PARSE_SCOPE_DEF(      STATUS, 1, NONE, 2, 0,   "status",     " <code> [<sample> ...]")                             \
	FLT_OTEL_PARSE_SCOPE_DEF(      FINISH, 0, NONE, 2, 0,   "finish",     " <name> ...")                                        \
	FLT_OTEL_PARSE_SCOPE_DEF(IDLE_TIMEOUT, 0, NONE, 2, 2, "idle-timeout", " <time>")                                            \
	FLT_OTEL_PARSE_SCOPE_DEF(         ACL, 0, CHAR, 3, 0, "acl",          " <name> <criterion> [flags] [operator] <value> ...") \
	FLT_OTEL_PARSE_SCOPE_DEF(    ON_EVENT, 0, NONE, 2, 0, "otel-event",   " <name> [{ if | unless } <condition>]")

/* Invalid character check modes for identifier validation. */
enum FLT_OTEL_PARSE_INVCHAR_enum {
	FLT_OTEL_PARSE_INVALID_NONE,
	FLT_OTEL_PARSE_INVALID_CHAR,
	FLT_OTEL_PARSE_INVALID_DOM,
	FLT_OTEL_PARSE_INVALID_CTX,
	FLT_OTEL_PARSE_INVALID_VAR,
};

enum FLT_OTEL_PARSE_INSTR_enum {
#define FLT_OTEL_PARSE_INSTR_DEF(a,b,c,d,e,f,g)   FLT_OTEL_PARSE_INSTR_##a,
	FLT_OTEL_PARSE_INSTR_DEFINES
#undef FLT_OTEL_PARSE_INSTR_DEF
};

enum FLT_OTEL_PARSE_GROUP_enum {
#define FLT_OTEL_PARSE_GROUP_DEF(a,b,c,d,e,f,g)   FLT_OTEL_PARSE_GROUP_##a,
	FLT_OTEL_PARSE_GROUP_DEFINES
#undef FLT_OTEL_PARSE_GROUP_DEF
};

enum FLT_OTEL_PARSE_SCOPE_enum {
#define FLT_OTEL_PARSE_SCOPE_DEF(a,b,c,d,e,f,g)   FLT_OTEL_PARSE_SCOPE_##a,
	FLT_OTEL_PARSE_SCOPE_DEFINES
#undef FLT_OTEL_PARSE_SCOPE_DEF
};

/* Context storage type flags for inject/extract operations. */
enum FLT_OTEL_CTX_USE_enum {
	FLT_OTEL_CTX_USE_VARS    = 1 << 0,
	FLT_OTEL_CTX_USE_HEADERS = 1 << 1,
};

/* Logging state flags for the OTel filter. */
enum FLT_OTEL_LOGGING_enum {
	FLT_OTEL_LOGGING_OFF       = 0,
	FLT_OTEL_LOGGING_ON        = 1 << 0,
	FLT_OTEL_LOGGING_NOLOGNORM = 1 << 1,
};

/* Keyword metadata used by the configuration section parsers. */
struct flt_otel_parse_data {
	int         keyword;       /* Keyword index. */
	bool        flag_check_id; /* Whether the group ID must be defined for the keyword. */
	int         check_name;    /* Checking allowed characters in the name. */
	int         args_min;      /* The minimum number of arguments required. */
	int         args_max;      /* The maximum number of arguments allowed. */
	const char *name;          /* Keyword name. */
	const char *usage;         /* Usage text to be printed in case of an error. */
};

#define FLT_OTEL_PARSE_KEYWORD(n,s)           (strcmp(args[n], (s)) == 0)

#define FLT_OTEL_PARSE_WARNING(f, ...) \
	ha_warning("parsing [%s:%d] : " FLT_OTEL_FMT_TYPE FLT_OTEL_FMT_NAME "'" f "'\n", ##__VA_ARGS__);

#define FLT_OTEL_PARSE_ALERT(f, ...)                                                                           \
	do {                                                                                                   \
		ha_alert("parsing [%s:%d] : " FLT_OTEL_FMT_TYPE FLT_OTEL_FMT_NAME "'" f "'\n", ##__VA_ARGS__); \
		                                                                                               \
		retval |= ERR_ABORT | ERR_ALERT;                                                               \
	} while (0)

#define FLT_OTEL_POST_PARSE_ALERT(f, ...) \
	FLT_OTEL_PARSE_ALERT(f, flt_otel_current_config->cfg_file, ##__VA_ARGS__)

#define FLT_OTEL_PARSE_ERR(e,f, ...)                            \
	do {                                                    \
		if (*(e) == NULL)                               \
			(void)memprintf((e), f, ##__VA_ARGS__); \
		                                                \
		retval |= ERR_ABORT | ERR_ALERT;                \
	} while (0)

#define FLT_OTEL_PARSE_IFERR_ALERT()                         \
	do {                                                 \
		if (err == NULL)                             \
			break;                               \
		                                             \
		FLT_OTEL_PARSE_ALERT("%s", file, line, err); \
		FLT_OTEL_ERR_FREE(err);                      \
	} while (0)

#endif /* _OTEL_PARSER_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
