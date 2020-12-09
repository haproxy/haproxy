/***
 * Copyright 2020 HAProxy Technologies
 *
 * This file is part of the HAProxy OpenTracing filter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef _OPENTRACING_PARSER_H_
#define _OPENTRACING_PARSER_H_

#define FLT_OT_SCOPE                        "OT"

/*
 * filter FLT_OT_OPT_NAME FLT_OT_OPT_FILTER_ID <FLT_OT_OPT_FILTER_ID_DEFAULT> FLT_OT_OPT_CONFIG <file>
 */
#define FLT_OT_OPT_NAME                     "opentracing"
#define FLT_OT_OPT_FILTER_ID                "id"
#define FLT_OT_OPT_FILTER_ID_DEFAULT        "ot-filter"
#define FLT_OT_OPT_CONFIG                   "config"

#define FLT_OT_PARSE_SECTION_TRACER_ID      "ot-tracer"
#define FLT_OT_PARSE_SECTION_GROUP_ID       "ot-group"
#define FLT_OT_PARSE_SECTION_SCOPE_ID       "ot-scope"

#define FLT_OT_PARSE_SPAN_ROOT              "root"
#define FLT_OT_PARSE_SPAN_REF_CHILD         "child-of"
#define FLT_OT_PARSE_SPAN_REF_FOLLOWS       "follows-from"
#define FLT_OT_PARSE_CTX_AUTONAME           "-"
#define FLT_OT_PARSE_CTX_USE_HEADERS        "use-headers"
#define FLT_OT_PARSE_CTX_USE_VARS           "use-vars"
#define FLT_OT_PARSE_OPTION_HARDERR         "hard-errors"
#define FLT_OT_PARSE_OPTION_DISABLED        "disabled"
#define FLT_OT_PARSE_OPTION_NOLOGNORM       "dontlog-normal"

/*
 * A description of the macro arguments can be found in the structure
 * flt_ot_parse_data definition
 */
#define FLT_OT_PARSE_TRACER_DEFINES                                                                                                                          \
	FLT_OT_PARSE_TRACER_DEF(         ID, 0, 1, 2, 2, "ot-tracer",   " <name>")                                                                           \
	FLT_OT_PARSE_TRACER_DEF(        ACL, 0, 1, 3, 0, "acl",         " <name> <criterion> [flags] [operator] <value> ...")                                \
	FLT_OT_PARSE_TRACER_DEF(        LOG, 0, 1, 2, 0, "log",         " { global | <addr> [len <len>] [format <fmt>] <facility> [<level> [<minlevel>]] }") \
	FLT_OT_PARSE_TRACER_DEF(     CONFIG, 0, 0, 2, 2, "config",      " <file>")                                                                           \
	FLT_OT_PARSE_TRACER_DEF(     PLUGIN, 0, 0, 2, 2, "plugin",      " <file>")                                                                           \
	FLT_OT_PARSE_TRACER_DEF(     GROUPS, 0, 0, 2, 0, "groups",      " <name> ...")                                                                       \
	FLT_OT_PARSE_TRACER_DEF(     SCOPES, 0, 0, 2, 0, "scopes",      " <name> ...")                                                                       \
	FLT_OT_PARSE_TRACER_DEF( RATE_LIMIT, 0, 0, 2, 2, "rate-limit",  " <value>")                                                                          \
	FLT_OT_PARSE_TRACER_DEF(     OPTION, 0, 0, 2, 2, "option",      " { disabled | dontlog-normal | hard-errors }")                                      \
	FLT_OT_PARSE_TRACER_DEF(DEBUG_LEVEL, 0, 0, 2, 2, "debug-level", " <value>")

#define FLT_OT_PARSE_GROUP_DEFINES                                        \
	FLT_OT_PARSE_GROUP_DEF(    ID, 0, 1, 2, 2, "ot-group", " <name>") \
	FLT_OT_PARSE_GROUP_DEF(SCOPES, 0, 0, 2, 0, "scopes",   " <name> ...")

#define FLT_OT_PARSE_SCOPE_DEFINES                                                                                    \
	FLT_OT_PARSE_SCOPE_DEF(     ID, 0, 1, 2, 2, "ot-scope", " <name>")                                            \
	FLT_OT_PARSE_SCOPE_DEF(   SPAN, 0, 0, 2, 5, "span",     " <name> [<reference>] [root]")                       \
	FLT_OT_PARSE_SCOPE_DEF(    TAG, 1, 0, 3, 0, "tag",      " <name> <sample> ...")                               \
	FLT_OT_PARSE_SCOPE_DEF(    LOG, 1, 0, 3, 0, "log",      " <name> <sample> ...")                               \
	FLT_OT_PARSE_SCOPE_DEF(BAGGAGE, 1, 4, 3, 0, "baggage",  " <name> <sample> ...")                               \
	FLT_OT_PARSE_SCOPE_DEF( INJECT, 1, 3, 2, 4, "inject",   " <name-prefix> [use-vars] [use-headers]")            \
	FLT_OT_PARSE_SCOPE_DEF(EXTRACT, 0, 3, 2, 3, "extract",  " <name-prefix> [use-vars | use-headers]")            \
	FLT_OT_PARSE_SCOPE_DEF( FINISH, 0, 0, 2, 0, "finish",   " <name> ...")                                        \
	FLT_OT_PARSE_SCOPE_DEF(    ACL, 0, 1, 3, 0, "acl",      " <name> <criterion> [flags] [operator] <value> ...") \
	FLT_OT_PARSE_SCOPE_DEF(  EVENT, 0, 0, 2, 0, "event",    " <name> [{ if | unless } <condition>]")

enum FLT_OT_PARSE_TRACER_enum {
#define FLT_OT_PARSE_TRACER_DEF(a,b,c,d,e,f,g)   FLT_OT_PARSE_TRACER_##a,
	FLT_OT_PARSE_TRACER_DEFINES
#undef FLT_OT_PARSE_TRACER_DEF
};

enum FLT_OT_PARSE_GROUP_enum {
#define FLT_OT_PARSE_GROUP_DEF(a,b,c,d,e,f,g)   FLT_OT_PARSE_GROUP_##a,
	FLT_OT_PARSE_GROUP_DEFINES
#undef FLT_OT_PARSE_GROUP_DEF
};

enum FLT_OT_PARSE_SCOPE_enum {
#define FLT_OT_PARSE_SCOPE_DEF(a,b,c,d,e,f,g)   FLT_OT_PARSE_SCOPE_##a,
	FLT_OT_PARSE_SCOPE_DEFINES
#undef FLT_OT_PARSE_SCOPE_DEF
};

enum FLT_OT_CTX_USE_enum {
	FLT_OT_CTX_USE_VARS    = 1 << 0,
	FLT_OT_CTX_USE_HEADERS = 1 << 1,
};

struct flt_ot_parse_data {
	int         keyword;       /* Keyword index. */
	bool        flag_check_id; /* Whether the group ID must be defined for the keyword. */
	int         check_name;    /* Checking allowed characters in the name. */
	int         args_min;      /* The minimum number of arguments required. */
	int         args_max;      /* The maximum number of arguments allowed. */
	const char *name;          /* Keyword name. */
	const char *usage;         /* Usage text to be printed in case of an error. */
};

#define FLT_OT_PARSE_WARNING(f, ...) \
	ha_warning("parsing [%s:%d] : " FLT_OT_FMT_TYPE FLT_OT_FMT_NAME "'" f "'\n", ##__VA_ARGS__);
#define FLT_OT_PARSE_ALERT(f, ...)                                                                         \
	do {                                                                                               \
		ha_alert("parsing [%s:%d] : " FLT_OT_FMT_TYPE FLT_OT_FMT_NAME "'" f "'\n", ##__VA_ARGS__); \
                                                                                                           \
		retval |= ERR_ABORT | ERR_ALERT;                                                           \
	} while (0)
#define FLT_OT_POST_PARSE_ALERT(f, ...) \
	FLT_OT_PARSE_ALERT(f, flt_ot_current_config->cfg_file, ##__VA_ARGS__)

#define FLT_OT_PARSE_ERR(e,f, ...)                              \
	do {                                                    \
		if (*(e) == NULL)                               \
			(void)memprintf((e), f, ##__VA_ARGS__); \
                                                                \
		retval |= ERR_ABORT | ERR_ALERT;                \
	} while (0)
#define FLT_OT_PARSE_IFERR_ALERT()                            \
	do {                                                  \
		if (err == NULL)                              \
			break;                                \
                                                              \
		FLT_OT_PARSE_ALERT("%s", file, linenum, err); \
		FLT_OT_ERR_FREE(err);                         \
	} while (0)

#endif /* _OPENTRACING_PARSER_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
