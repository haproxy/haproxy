/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _OTEL_SCOPE_H_
#define _OTEL_SCOPE_H_

#define FLT_OTEL_SCOPE_SPAN_FINISH_REQ       "*req*"
#define FLT_OTEL_SCOPE_SPAN_FINISH_RES       "*res*"
#define FLT_OTEL_SCOPE_SPAN_FINISH_ALL       "*"

#define FLT_OTEL_RT_CTX(p)                   ((struct flt_otel_runtime_context *)(p))

#define FLT_OTEL_DBG_SCOPE_SPAN(h,p)                                \
	OTELC_DBG(DEBUG, h "%p:{ '%s' %zu %u %hhu %p %p %p }", (p), \
	          FLT_OTEL_STR_HDR_ARGS(p, id), (p)->smp_opt_dir,   \
	          (p)->flag_finish, (p)->span, (p)->ref_span, (p)->ref_ctx)

#define FLT_OTEL_DBG_SCOPE_CONTEXT(h,p)                           \
	OTELC_DBG(DEBUG, h "%p:{ '%s' %zu %u %hhu %p }", (p),     \
	          FLT_OTEL_STR_HDR_ARGS(p, id), (p)->smp_opt_dir, \
	          (p)->flag_finish, (p)->context)

#define FLT_OTEL_DBG_SCOPE_DATA_EVENT(h,p)                    \
	OTELC_DBG(DEBUG, h "%p:{ '%s' %p %zu %zu %s }", &(p), \
	          (p).name, (p).attr, (p).cnt, (p).size,      \
	          flt_otel_list_dump(&((p).list)))

#define FLT_OTEL_DBG_SCOPE_DATA_STATUS(h,p) \
	OTELC_DBG(DEBUG, h "%p:{ %d '%s' }", (p), (p)->code, OTELC_STR_ARG((p)->description))

#define FLT_OTEL_DBG_SCOPE_DATA_KV_FMT       "%p:{ %p %zu %zu }"
#define FLT_OTEL_DBG_SCOPE_DATA_KV_ARGS(p)   &(p), (p).attr, (p).cnt, (p).size
#define FLT_OTEL_DBG_SCOPE_DATA(h,p)                                                                               \
	OTELC_DBG(DEBUG, h "%p:{ " FLT_OTEL_DBG_SCOPE_DATA_KV_FMT " " FLT_OTEL_DBG_SCOPE_DATA_KV_FMT " %s }", (p), \
	          FLT_OTEL_DBG_SCOPE_DATA_KV_ARGS((p)->baggage), FLT_OTEL_DBG_SCOPE_DATA_KV_ARGS((p)->attributes), \
	          flt_otel_list_dump(&((p)->events)))

#define FLT_OTEL_DBG_RUNTIME_CONTEXT(h,p)                                                     \
	OTELC_DBG(DEBUG, h "%p:{ %p %p '%s' %hhu %hhu 0x%02hhx 0x%08x %u %d %s %s }", (p),    \
	          (p)->stream, (p)->filter, (p)->uuid, (p)->flag_harderr, (p)->flag_disabled, \
	          (p)->logging, (p)->analyzers, (p)->idle_timeout, (p)->idle_exp,             \
	          flt_otel_list_dump(&((p)->spans)), flt_otel_list_dump(&((p)->contexts)))

/* Anonymous struct containing a const string pointer and its length. */
#define FLT_OTEL_CONST_STR_HDR(p)    \
	struct {                     \
		const char *p;       \
		size_t      p##_len; \
	}


/* Growable key-value array for span attributes or baggage. */
struct flt_otel_scope_data_kv {
	struct otelc_kv *attr; /* Key-value array for storing attributes. */
	size_t           cnt;  /* Number of currently used array elements. */
	size_t           size; /* Total number of array elements. */
};

/* Named event with its own key-value attribute array. */
struct flt_otel_scope_data_event {
	char            *name; /* Event name, not used for other data types. */
	struct otelc_kv *attr; /* Key-value array for storing attributes. */
	size_t           cnt;  /* Number of currently used array elements. */
	size_t           size; /* Total number of array elements. */
	struct list      list; /* Used to chain this structure. */
};

struct flt_otel_scope_data_status {
	int   code;        /* OTELC_SPAN_STATUS_* value. */
	char *description; /* Span status description string. */
};

struct flt_otel_scope_data {
	struct flt_otel_scope_data_kv     baggage;    /* Defined scope baggage. */
	struct flt_otel_scope_data_kv     attributes; /* Defined scope attributes. */
	struct list                       events;     /* Defined scope events. */
	struct flt_otel_scope_data_status status;     /* Defined scope status. */
};

/* flt_otel_runtime_context->spans */
struct flt_otel_scope_span {
	FLT_OTEL_CONST_STR_HDR(id);             /* The span operation name/len. */
	uint                       smp_opt_dir; /* SMP_OPT_DIR_RE(Q|S) */
	bool                       flag_finish; /* Whether the span is marked for completion. */
	struct otelc_span         *span;        /* The current span. */
	struct otelc_span         *ref_span;    /* Span to which the current span refers. */
	struct otelc_span_context *ref_ctx;     /* Span context to which the current span refers. */
	struct list                list;        /* Used to chain this structure. */
};

/* flt_otel_runtime_context->contexts */
struct flt_otel_scope_context {
	FLT_OTEL_CONST_STR_HDR(id);             /* The span context name/len. */
	uint                       smp_opt_dir; /* SMP_OPT_DIR_RE(Q|S) */
	bool                       flag_finish; /* Whether the span context is marked for completion. */
	struct otelc_span_context *context;     /* The current span context. */
	struct list                list;        /* Used to chain this structure. */
};

/* The runtime filter context attached to a stream. */
struct flt_otel_runtime_context {
	struct stream *stream;        /* The stream to which the filter is attached. */
	struct filter *filter;        /* The OpenTelemetry filter. */
	char           uuid[40];      /* Randomly generated UUID. */
	bool           flag_harderr;  /* [0 1] */
	bool           flag_disabled; /* [0 1] */
	uint8_t        logging;       /* [0 1 3] */
	uint           analyzers;     /* Executed channel analyzers. */
	uint           idle_timeout;  /* Idle timeout interval in milliseconds (0 = off). */
	int            idle_exp;      /* Tick at which the next idle timeout fires. */
	struct list    spans;         /* The scope spans. */
	struct list    contexts;      /* The scope contexts. */
};


#ifndef DEBUG_OTEL
#  define flt_otel_scope_data_dump(...)   while (0)
#else
/* Dump scope data contents for debugging. */
void                             flt_otel_scope_data_dump(const struct flt_otel_scope_data *data);
#endif

/* Allocate and initialize a runtime context for a stream. */
struct flt_otel_runtime_context *flt_otel_runtime_context_init(struct stream *s, struct filter *f, char **err);

/* Free the runtime context attached to a filter. */
void                             flt_otel_runtime_context_free(struct filter *f);

/* Allocate and initialize a scope span in the runtime context. */
struct flt_otel_scope_span      *flt_otel_scope_span_init(struct flt_otel_runtime_context *rt_ctx, const char *id, size_t id_len, const char *ref_id, size_t ref_id_len, uint dir, char **err);

/* Free a scope span and remove it from the runtime context. */
void                             flt_otel_scope_span_free(struct flt_otel_scope_span **ptr);

/* Allocate and initialize a scope context in the runtime context. */
struct flt_otel_scope_context   *flt_otel_scope_context_init(struct flt_otel_runtime_context *rt_ctx, struct otelc_tracer *tracer, const char *id, size_t id_len, const struct otelc_text_map *text_map, uint dir, char **err);

/* Free a scope context and remove it from the runtime context. */
void                             flt_otel_scope_context_free(struct flt_otel_scope_context **ptr);

/* Initialize scope data arrays and lists. */
void                             flt_otel_scope_data_init(struct flt_otel_scope_data *ptr);

/* Free all scope data contents. */
void                             flt_otel_scope_data_free(struct flt_otel_scope_data *ptr);

/* Mark a span for finishing by name in the runtime context. */
int                              flt_otel_scope_finish_mark(const struct flt_otel_runtime_context *rt_ctx, const char *id, size_t id_len);

/* End all spans that have been marked for finishing. */
void                             flt_otel_scope_finish_marked(const struct flt_otel_runtime_context *rt_ctx, const struct timespec *ts_finish);

/* Free scope spans and contexts no longer needed by a channel. */
void                             flt_otel_scope_free_unused(struct flt_otel_runtime_context *rt_ctx, struct channel *chn);

#endif /* _OTEL_SCOPE_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
