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
#ifndef _OPENTRACING_CONF_H_
#define _OPENTRACING_CONF_H_

#define FLT_OT_CONF(f)              ((struct flt_ot_conf *)FLT_CONF(f))
#define FLT_OT_CONF_HDR_FMT         "%p:{ { '%.*s' %zu %d } "
#define FLT_OT_CONF_HDR_ARGS(a,b)   (a), (int)(a)->b##_len, (a)->b, (a)->b##_len, (a)->cfg_line
#define FLT_OT_STR_HDR_ARGS(a,b)    (a)->b, (a)->b##_len

#define FLT_OT_DBG_CONF_SAMPLE_EXPR(f,a) \
	FLT_OT_DBG(3, "%s%p:{ '%s' %p }", (f), (a), (a)->value, (a)->expr)

#define FLT_OT_DBG_CONF_SAMPLE(f,a)               \
	FLT_OT_DBG(3, "%s%p:{ '%s' '%s' %s %d }", \
	           (f), (a), (a)->key, (a)->value, flt_ot_list_debug(&((a)->exprs)), (a)->num_exprs)

#define FLT_OT_DBG_CONF_STR(f,a) \
	FLT_OT_DBG(3, f FLT_OT_CONF_HDR_FMT "}", FLT_OT_CONF_HDR_ARGS(a, str))

#define FLT_OT_DBG_CONF_CONTEXT(f,a) \
	FLT_OT_DBG(3, f FLT_OT_CONF_HDR_FMT "0x%02hhx }", FLT_OT_CONF_HDR_ARGS(a, id), (a)->flags)

#define FLT_OT_DBG_CONF_SPAN(f,a)                                                                                   \
	FLT_OT_DBG(3, f FLT_OT_CONF_HDR_FMT "'%s' %zu %d '%s' %zu %hhu 0x%02hhx %s %s %s }",                        \
	           FLT_OT_CONF_HDR_ARGS(a, id), FLT_OT_STR_HDR_ARGS(a, ref_id), (a)->ref_type,                      \
	           FLT_OT_STR_HDR_ARGS(a, ctx_id), (a)->flag_root, (a)->ctx_flags, flt_ot_list_debug(&((a)->tags)), \
	           flt_ot_list_debug(&((a)->logs)), flt_ot_list_debug(&((a)->baggages)))

#define FLT_OT_DBG_CONF_SCOPE(f,a)                                                                           \
	FLT_OT_DBG(3, f FLT_OT_CONF_HDR_FMT "%hhu %d %s %p %s %s %s }",                                      \
	           FLT_OT_CONF_HDR_ARGS(a, id), (a)->flag_used, (a)->event, flt_ot_list_debug(&((a)->acls)), \
	           (a)->cond, flt_ot_list_debug(&((a)->contexts)), flt_ot_list_debug(&((a)->spans)),         \
	           flt_ot_list_debug(&((a)->finish)))

#define FLT_OT_DBG_CONF_GROUP(f,a)                       \
	FLT_OT_DBG(3, f FLT_OT_CONF_HDR_FMT "%hhu %s }", \
	           FLT_OT_CONF_HDR_ARGS(a, id), (a)->flag_used, flt_ot_list_debug(&((a)->ph_scopes)))

#define FLT_OT_DBG_CONF_PH(f,a) \
	FLT_OT_DBG(3, f FLT_OT_CONF_HDR_FMT "%p }", FLT_OT_CONF_HDR_ARGS(a, id), (a)->ptr)

#define FLT_OT_DBG_CONF_TRACER(f,a)                                                                                                   \
	FLT_OT_DBG(3, f FLT_OT_CONF_HDR_FMT "'%s' '%s' %p %u %hhu %hhu 0x%02hhx %p:%s 0x%08x %s %s %s }",                             \
	           FLT_OT_CONF_HDR_ARGS(a, id), (a)->config, (a)->plugin, (a)->tracer, (a)->rate_limit, (a)->flag_harderr,            \
	           (a)->flag_disabled, (a)->logging, &((a)->proxy_log), flt_ot_list_debug(&((a)->proxy_log.logsrvs)), (a)->analyzers, \
	           flt_ot_list_debug(&((a)->acls)), flt_ot_list_debug(&((a)->ph_groups)), flt_ot_list_debug(&((a)->ph_scopes)))

#define FLT_OT_DBG_CONF(f,a)                                                  \
	FLT_OT_DBG(3, "%s%p:{ %p '%s' '%s' %p %s %s }",                       \
	           (f), (a), (a)->proxy, (a)->id, (a)->cfg_file, (a)->tracer, \
	           flt_ot_list_debug(&((a)->groups)), flt_ot_list_debug(&((a)->scopes)))

#define FLT_OT_STR_HDR(a)        \
	struct {                 \
		char   *a;       \
		size_t  a##_len; \
	}

#define FLT_OT_CONF_HDR(a)            \
	struct {                      \
		FLT_OT_STR_HDR(a);    \
		int         cfg_line; \
		struct list list;     \
	}


struct flt_ot_conf_hdr {
	FLT_OT_CONF_HDR(id);
};

/* flt_ot_conf_sample->exprs */
struct flt_ot_conf_sample_expr {
	FLT_OT_CONF_HDR(value);   /* The sample value. */
	struct sample_expr *expr; /* The sample expression. */
};

/*
 * flt_ot_conf_span->tags
 * flt_ot_conf_span->logs
 * flt_ot_conf_span->baggages
 */
struct flt_ot_conf_sample {
	FLT_OT_CONF_HDR(key);   /* The sample name. */
	char        *value;     /* The sample content. */
	struct list  exprs;     /* Used to chain sample expressions. */
	int          num_exprs; /* Number of defined expressions. */
};

/* flt_ot_conf_scope->finish */
struct flt_ot_conf_str {
	FLT_OT_CONF_HDR(str); /* String content/length. */
};

/* flt_ot_conf_scope->contexts */
struct flt_ot_conf_context {
	FLT_OT_CONF_HDR(id); /* The name of the context. */
	uint8_t flags;       /* The type of storage from which the span context is extracted.  */
};

/* flt_ot_conf_scope->spans */
struct flt_ot_conf_span {
	FLT_OT_CONF_HDR(id);    /* The name of the span. */
	FLT_OT_STR_HDR(ref_id); /* The reference name, if used. */
	int         ref_type;   /* The reference type. */
	FLT_OT_STR_HDR(ctx_id); /* The span context name, if used. */
	uint8_t     ctx_flags;  /* The type of storage used for the span context. */
	bool        flag_root;  /* Whether this is a root span. */
	struct list tags;       /* The set of key:value tags. */
	struct list logs;       /* The set of key:value logs. */
	struct list baggages;   /* The set of key:value baggage items. */
};

struct flt_ot_conf_scope {
	FLT_OT_CONF_HDR(id);        /* The scope name. */
	bool             flag_used; /* The indication that the scope is being used. */
	int              event;     /* FLT_OT_EVENT_* */
	struct list      acls;      /* ACLs declared on this scope. */
	struct acl_cond *cond;      /* ACL condition to meet. */
	struct list      contexts;  /* Declared contexts. */
	struct list      spans;     /* Declared spans. */
	struct list      finish;    /* The list of spans to be finished. */
};

struct flt_ot_conf_group {
	FLT_OT_CONF_HDR(id);   /* The group name. */
	bool        flag_used; /* The indication that the group is being used. */
	struct list ph_scopes; /* List of all used scopes. */
};

struct flt_ot_conf_ph {
	FLT_OT_CONF_HDR(id); /* The scope/group name. */
	void *ptr;           /* Pointer to real placeholder structure. */
};
#define flt_ot_conf_ph_group      flt_ot_conf_ph
#define flt_ot_conf_ph_scope      flt_ot_conf_ph

struct flt_ot_conf_tracer {
	FLT_OT_CONF_HDR(id);              /* The tracer name. */
	char              *config;        /* The OpenTracing configuration file name. */
	char              *plugin;        /* The OpenTracing plugin library file name. */
	struct otc_tracer *tracer;        /* The OpenTracing tracer handle. */
	uint32_t           rate_limit;    /* [0 2^32-1] <-> [0.0 100.0] */
	bool               flag_harderr;  /* [0 1] */
	bool               flag_disabled; /* [0 1] */
	uint8_t            logging;       /* [0 1 3] */
	struct proxy       proxy_log;     /* The log server list. */
	uint               analyzers;     /* Defined channel analyzers. */
	struct list        acls;          /* ACLs declared on this tracer. */
	struct list        ph_groups;     /* List of all used groups. */
	struct list        ph_scopes;     /* List of all used scopes. */
};

struct flt_ot_counters {
#ifdef DEBUG_OT
	struct {
		bool     flag_used; /* Whether this event is used. */
		uint64_t htx[2];    /* htx_is_empty() function result counter. */
	} event[FLT_OT_EVENT_MAX];
#endif

	uint64_t disabled[2];       /* How many times stream processing is disabled. */
};

/* The OpenTracing filter configuration. */
struct flt_ot_conf {
	struct proxy              *proxy;    /* Proxy owning the filter. */
	char                      *id;       /* The OpenTracing filter id. */
	char                      *cfg_file; /* The OpenTracing filter configuration file name. */
	struct flt_ot_conf_tracer *tracer;   /* There can only be one tracer. */
	struct list                groups;   /* List of all available groups. */
	struct list                scopes;   /* List of all available scopes. */
	struct flt_ot_counters     cnt;      /* Various counters related to filter operation. */
};


#define flt_ot_conf_ph_group_free   flt_ot_conf_ph_free
#define flt_ot_conf_ph_scope_free   flt_ot_conf_ph_free

struct flt_ot_conf_ph          *flt_ot_conf_ph_init(const char *id, int linenum, struct list *head, char **err);
void                            flt_ot_conf_ph_free(struct flt_ot_conf_ph **ptr);
struct flt_ot_conf_sample_expr *flt_ot_conf_sample_expr_init(const char *id, int linenum, struct list *head, char **err);
void                            flt_ot_conf_sample_expr_free(struct flt_ot_conf_sample_expr **ptr);
struct flt_ot_conf_sample      *flt_ot_conf_sample_init(char **args, int linenum, struct list *head, char **err);
void                            flt_ot_conf_sample_free(struct flt_ot_conf_sample **ptr);
struct flt_ot_conf_str         *flt_ot_conf_str_init(const char *id, int linenum, struct list *head, char **err);
void                            flt_ot_conf_str_free(struct flt_ot_conf_str **ptr);
struct flt_ot_conf_context     *flt_ot_conf_context_init(const char *id, int linenum, struct list *head, char **err);
void                            flt_ot_conf_context_free(struct flt_ot_conf_context **ptr);
struct flt_ot_conf_span        *flt_ot_conf_span_init(const char *id, int linenum, struct list *head, char **err);
void                            flt_ot_conf_span_free(struct flt_ot_conf_span **ptr);
struct flt_ot_conf_scope       *flt_ot_conf_scope_init(const char *id, int linenum, struct list *head, char **err);
void                            flt_ot_conf_scope_free(struct flt_ot_conf_scope **ptr);
struct flt_ot_conf_group       *flt_ot_conf_group_init(const char *id, int linenum, struct list *head, char **err);
void                            flt_ot_conf_group_free(struct flt_ot_conf_group **ptr);
struct flt_ot_conf_tracer      *flt_ot_conf_tracer_init(const char *id, int linenum, char **err);
void                            flt_ot_conf_tracer_free(struct flt_ot_conf_tracer **ptr);
struct flt_ot_conf             *flt_ot_conf_init(struct proxy *px);
void                            flt_ot_conf_free(struct flt_ot_conf **ptr);

#endif /* _OPENTRACING_CONF_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
