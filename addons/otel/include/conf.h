/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_CONF_H_
#define _OTEL_CONF_H_

/* Extract the OTel filter configuration from a filter instance. */
#define FLT_OTEL_CONF(f)              ((struct flt_otel_conf *)FLT_CONF(f))

/* Expand to a string pointer and its length for a named member. */
#define FLT_OTEL_STR_HDR_ARGS(p,m)    (p)->m, (p)->m##_len
/***
 * It should be noted that the macro FLT_OTEL_CONF_HDR_ARGS() does not have
 * all the parameters defined that would correspond to the format found in
 * the FLT_OTEL_CONF_HDR_FMT macro (first pointer is missing).
 *
 * This is because during the expansion of the OTELC_DBG_STRUCT() macro, an
 * incorrect conversion is performed and instead of the first correct code,
 * a second incorrect code is generated:
 *
 * do {
 *    if ((p) == NULL)
 *    ..
 * } while (0)
 *
 * do {
 *    if ((p), (int) (p)->id_len, (p)->id, (p)->id_len, (p)->cfg_line == NULL)
 *    ..
 * } while (0)
 *
 */
#define FLT_OTEL_CONF_HDR_FMT         "%p:{ { '%.*s' %zu %d } "
#define FLT_OTEL_CONF_HDR_ARGS(p,m)   (int)(p)->m##_len, (p)->m, (p)->m##_len, (p)->cfg_line

#define FLT_OTEL_CONF_STR_CMP(s,S)    ((s##_len == S##_len) && (memcmp(s, S, S##_len) == 0))

#define FLT_OTEL_DBG_CONF_SAMPLE_EXPR(h,p) \
	OTELC_DBG(DEBUG, h "%p:{ '%s' %p }", (p), (p)->fmt_expr, (p)->expr)

#define FLT_OTEL_DBG_CONF_SAMPLE(h,p)                                             \
	OTELC_DBG(DEBUG, h "%p:{ '%s' '%s' %s %s %d }", (p),                      \
	          (p)->key, (p)->fmt_string, otelc_value_dump(&((p)->extra), ""), \
	          flt_otel_list_dump(&((p)->exprs)), (p)->num_exprs)

#define FLT_OTEL_DBG_CONF_HDR(h,p,i) \
	OTELC_DBG_STRUCT(DEBUG, h, h FLT_OTEL_CONF_HDR_FMT "}", (p), FLT_OTEL_CONF_HDR_ARGS(p, i))

#define FLT_OTEL_DBG_CONF_CONTEXT(h,p) \
	OTELC_DBG_STRUCT(DEBUG, h, h FLT_OTEL_CONF_HDR_FMT "0x%02hhx }", (p), FLT_OTEL_CONF_HDR_ARGS(p, id), (p)->flags)

#define FLT_OTEL_DBG_CONF_SPAN(h,p)                                                                        \
	OTELC_DBG_STRUCT(DEBUG, h, h FLT_OTEL_CONF_HDR_FMT "'%s' %zu %s' %zu %hhu 0x%02hhx %s %s %s %s }", \
	                 (p), FLT_OTEL_CONF_HDR_ARGS(p, id), FLT_OTEL_STR_HDR_ARGS(p, ref_id),             \
	                 FLT_OTEL_STR_HDR_ARGS(p, ctx_id), (p)->flag_root, (p)->ctx_flags,                 \
	                 flt_otel_list_dump(&((p)->attributes)), flt_otel_list_dump(&((p)->events)),       \
	                 flt_otel_list_dump(&((p)->baggages)), flt_otel_list_dump(&((p)->statuses)))

#define FLT_OTEL_DBG_CONF_SCOPE(h,p)                                                                        \
	OTELC_DBG_STRUCT(DEBUG, h, h FLT_OTEL_CONF_HDR_FMT "%hhu %d %u %s %p %s %s %s }", (p),              \
	                 FLT_OTEL_CONF_HDR_ARGS(p, id), (p)->flag_used, (p)->event, (p)->idle_timeout,      \
	                 flt_otel_list_dump(&((p)->acls)), (p)->cond, flt_otel_list_dump(&((p)->contexts)), \
	                 flt_otel_list_dump(&((p)->spans)), flt_otel_list_dump(&((p)->spans_to_finish)))

#define FLT_OTEL_DBG_CONF_GROUP(h,p)                                         \
	OTELC_DBG_STRUCT(DEBUG, h, h FLT_OTEL_CONF_HDR_FMT "%hhu %s }", (p), \
	                 FLT_OTEL_CONF_HDR_ARGS(p, id), (p)->flag_used, flt_otel_list_dump(&((p)->ph_scopes)))

#define FLT_OTEL_DBG_CONF_PH(h,p) \
	OTELC_DBG_STRUCT(DEBUG, h, h FLT_OTEL_CONF_HDR_FMT "%p }", (p), FLT_OTEL_CONF_HDR_ARGS(p, id), (p)->ptr)

#define FLT_OTEL_DBG_CONF_INSTR(h,p)                                                                                                 \
	OTELC_DBG_STRUCT(DEBUG, h, h FLT_OTEL_CONF_HDR_FMT "'%s' %p %u %hhu %hhu 0x%02hhx %p:%s 0x%08x %u %s %s %s }", (p),          \
	                 FLT_OTEL_CONF_HDR_ARGS(p, id), (p)->config, (p)->tracer, (p)->rate_limit, (p)->flag_harderr,                \
	                 (p)->flag_disabled, (p)->logging, &((p)->proxy_log), flt_otel_list_dump(&((p)->proxy_log.loggers)),         \
	                 (p)->analyzers, (p)->idle_timeout, flt_otel_list_dump(&((p)->acls)), flt_otel_list_dump(&((p)->ph_groups)), \
	                 flt_otel_list_dump(&((p)->ph_scopes)))

#define FLT_OTEL_DBG_CONF(h,p)                                    \
	OTELC_DBG(DEBUG, h "%p:{ %p '%s' '%s' %p %s %s }", (p),   \
	          (p)->proxy, (p)->id, (p)->cfg_file, (p)->instr, \
	          flt_otel_list_dump(&((p)->groups)), flt_otel_list_dump(&((p)->scopes)))

/* Anonymous struct containing a string pointer and its length. */
#define FLT_OTEL_CONF_STR(p)     \
	struct {                 \
		char   *p;       \
		size_t  p##_len; \
	}

/* Common header embedded in all configuration structures. */
#define FLT_OTEL_CONF_HDR(p)          \
	struct {                      \
		FLT_OTEL_CONF_STR(p); \
		int         cfg_line; \
		struct list list;     \
	}


/* Generic configuration header used for simple named list entries. */
struct flt_otel_conf_hdr {
	FLT_OTEL_CONF_HDR(id); /* A list containing header names. */
};

/* flt_otel_conf_sample->exprs */
struct flt_otel_conf_sample_expr {
	FLT_OTEL_CONF_HDR(fmt_expr); /* The original sample expression format string. */
	struct sample_expr *expr;    /* The sample expression. */
};

/*
 * flt_otel_conf_span->attributes
 * flt_otel_conf_span->events (event_name -> OTELC_VALUE_STR(&extra))
 * flt_otel_conf_span->baggages
 * flt_otel_conf_span->statuses (status_code -> extra.u.value_int32)
 */
struct flt_otel_conf_sample {
	FLT_OTEL_CONF_HDR(key);         /* The list containing sample names. */
	char               *fmt_string; /* All sample-expression arguments are combined into a single string. */
	struct otelc_value  extra;      /* Optional supplementary data. */
	struct list         exprs;      /* Used to chain sample expressions. */
	int                 num_exprs;  /* Number of defined expressions. */
};

/*
 * flt_otel_conf_scope->spans_to_finish
 *
 * It can be seen that this structure is actually identical to the structure
 * flt_otel_conf_hdr.
 */
struct flt_otel_conf_str {
	FLT_OTEL_CONF_HDR(str); /* A list containing character strings. */
};

/* flt_otel_conf_scope->contexts */
struct flt_otel_conf_context {
	FLT_OTEL_CONF_HDR(id); /* The name of the context. */
	uint8_t flags;         /* The type of storage from which the span context is extracted.  */
};

/*
 * Span configuration within a scope.
 *   flt_otel_conf_scope->spans
 */
struct flt_otel_conf_span {
	FLT_OTEL_CONF_HDR(id);     /* The name of the span. */
	FLT_OTEL_CONF_STR(ref_id); /* The reference name, if used. */
	FLT_OTEL_CONF_STR(ctx_id); /* The span context name, if used. */
	uint8_t     ctx_flags;     /* The type of storage used for the span context. */
	bool        flag_root;     /* Whether this is a root span. */
	struct list attributes;    /* The set of key:value attributes. */
	struct list events;        /* The set of events with key-value attributes. */
	struct list baggages;      /* The set of key:value baggage items. */
	struct list statuses;      /* Span status code and description (only one per list). */
};

/* Configuration for a single event scope. */
struct flt_otel_conf_scope {
	FLT_OTEL_CONF_HDR(id);            /* The scope name. */
	bool             flag_used;       /* The indication that the scope is being used. */
	int              event;           /* FLT_OTEL_EVENT_* */
	uint             idle_timeout;    /* Idle timeout interval in milliseconds (0 = off). */
	struct list      acls;            /* ACLs declared on this scope. */
	struct acl_cond *cond;            /* ACL condition to meet. */
	struct list      contexts;        /* Declared contexts. */
	struct list      spans;           /* Declared spans. */
	struct list      spans_to_finish; /* The list of spans scheduled for finishing. */
};

/* Configuration for a named group of scopes. */
struct flt_otel_conf_group {
	FLT_OTEL_CONF_HDR(id); /* The group name. */
	bool        flag_used; /* The indication that the group is being used. */
	struct list ph_scopes; /* List of all used scopes. */
};

/* Placeholder referencing a scope or group by name. */
struct flt_otel_conf_ph {
	FLT_OTEL_CONF_HDR(id); /* The scope/group name. */
	void *ptr;             /* Pointer to real placeholder structure. */
};
#define flt_otel_conf_ph_group        flt_otel_conf_ph
#define flt_otel_conf_ph_scope        flt_otel_conf_ph

/* Top-level OTel instrumentation settings (tracer, options). */
struct flt_otel_conf_instr {
	FLT_OTEL_CONF_HDR(id);              /* The OpenTelemetry instrumentation name. */
	char                *config;        /* The OpenTelemetry configuration file name. */
	struct otelc_tracer *tracer;        /* The OpenTelemetry tracer handle. */
	uint32_t             rate_limit;    /* [0 2^32-1] <-> [0.0 100.0] */
	bool                 flag_harderr;  /* [0 1] */
	bool                 flag_disabled; /* [0 1] */
	uint8_t              logging;       /* [0 1 3] */
	struct proxy         proxy_log;     /* The log server list. */
	uint                 analyzers;     /* Defined channel analyzers. */
	uint                 idle_timeout;  /* Minimum idle timeout across scopes (ms, 0 = off). */
	struct list          acls;          /* ACLs declared on this tracer. */
	struct list          ph_groups;     /* List of all used groups. */
	struct list          ph_scopes;     /* List of all used scopes. */
};

/* Runtime counters for filter diagnostics. */
struct flt_otel_counters {
#ifdef DEBUG_OTEL
	struct {
		bool     flag_used; /* Whether this event is used. */
		uint64_t htx[2];    /* htx_is_empty() function result counter. */
	} event[FLT_OTEL_EVENT_MAX];
#endif

#ifdef FLT_OTEL_USE_COUNTERS
	uint64_t attached[4];       /* [run rate-limit disabled error] */
	uint64_t disabled[2];       /* How many times stream processing is disabled. */
#endif
};

/* The OpenTelemetry filter configuration. */
struct flt_otel_conf {
	struct proxy               *proxy;    /* Proxy owning the filter. */
	char                       *id;       /* The OpenTelemetry filter id. */
	char                       *cfg_file; /* The OpenTelemetry filter configuration file name. */
	struct flt_otel_conf_instr *instr;    /* The OpenTelemetry instrumentation settings. */
	struct list                 groups;   /* List of all available groups. */
	struct list                 scopes;   /* List of all available scopes. */
	struct flt_otel_counters    cnt;      /* Various counters related to filter operation. */
	struct list                 smp_args; /* Deferred OTEL sample fetch args to resolve. */
};


/* Allocate and initialize a sample from parsed arguments. */
struct flt_otel_conf_sample *flt_otel_conf_sample_init_ex(const char **args, int idx, int n, const struct otelc_value *extra, int line, struct list *head, char **err);

/* Allocate and initialize the top-level OTel filter configuration. */
struct flt_otel_conf        *flt_otel_conf_init(struct proxy *px);

/* Free the top-level OTel filter configuration. */
void                         flt_otel_conf_free(struct flt_otel_conf **ptr);

#endif /* _OTEL_CONF_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
