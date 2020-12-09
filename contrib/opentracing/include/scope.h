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
#ifndef _OPENTRACING_SCOPE_H_
#define _OPENTRACING_SCOPE_H_

#define FLT_OT_SCOPE_SPAN_FINISH_REQ   "*req*"
#define FLT_OT_SCOPE_SPAN_FINISH_RES   "*res*"
#define FLT_OT_SCOPE_SPAN_FINISH_ALL   "*"

#define FLT_OT_RT_CTX(a)               ((struct flt_ot_runtime_context *)(a))

#define FLT_OT_DBG_SCOPE_SPAN(f,a)                                         \
	FLT_OT_DBG(3, "%s%p:{ '%s' %zu %u %hhu %p %d %p %p }",             \
	           (f), (a), FLT_OT_STR_HDR_ARGS(a, id), (a)->smp_opt_dir, \
	           (a)->flag_finish, (a)->span, (a)->ref_type, (a)->ref_span, (a)->ref_ctx)

#define FLT_OT_DBG_SCOPE_CONTEXT(f,a)                                      \
	FLT_OT_DBG(3, "%s%p:{ '%s' %zu %u %hhu %p }",                      \
	           (f), (a), FLT_OT_STR_HDR_ARGS(a, id), (a)->smp_opt_dir, \
	           (a)->flag_finish, (a)->context)

#define FLT_OT_DBG_SCOPE_DATA(f,a)               \
	FLT_OT_DBG(3, "%s%p:{ %p %d %p %p %d }", \
	           (f), (a), (a)->tags, (a)->num_tags, (a)->baggage, (a)->log_fields, (a)->num_log_fields)

#define FLT_OT_DBG_RUNTIME_CONTEXT(f,a)                                                                                    \
	FLT_OT_DBG(3, "%s%p:{ %p %p { %016" PRIx64 " %016" PRIx64 " '%s' } %hhu %hhu 0x%02hhx 0x%08x %s %s }",             \
	           (f), (a), (a)->stream, (a)->filter, (a)->uuid.u64[0], (a)->uuid.u64[1], (a)->uuid.s, (a)->flag_harderr, \
	           (a)->flag_disabled, (a)->logging, (a)->analyzers, flt_ot_list_debug(&((a)->spans)),                     \
	           flt_ot_list_debug(&((a)->contexts)))

#define FLT_OT_CONST_STR_HDR(a)      \
	struct {                     \
		const char *a;       \
		size_t      a##_len; \
	}


struct flt_ot_scope_data {
	struct otc_tag        tags[FLT_OT_MAXTAGS];         /* Defined tags. */
	int                   num_tags;                     /* The number of tags used. */
	struct otc_text_map  *baggage;                      /* Defined baggage. */
	struct otc_log_field  log_fields[OTC_MAXLOGFIELDS]; /* Defined logs. */
	int                   num_log_fields;               /* The number of log fields used. */
};

/* flt_ot_runtime_context->spans */
struct flt_ot_scope_span {
	FLT_OT_CONST_STR_HDR(id);               /* The span operation name/len. */
	uint                       smp_opt_dir; /* SMP_OPT_DIR_RE(Q|S) */
	bool                       flag_finish; /* Whether the span is marked for completion. */
	struct otc_span           *span;        /* The current span. */
	otc_span_reference_type_t  ref_type;    /* Span reference type. */
	struct otc_span           *ref_span;    /* Span to which the current span refers. */
	struct otc_span_context   *ref_ctx;     /* Span context to which the current span refers. */
	struct list                list;        /* Used to chain this structure. */
};

/* flt_ot_runtime_context->contexts */
struct flt_ot_scope_context {
	FLT_OT_CONST_STR_HDR(id);             /* The span context name/len. */
	uint                     smp_opt_dir; /* SMP_OPT_DIR_RE(Q|S) */
	bool                     flag_finish; /* Whether the span context is marked for completion. */
	struct otc_span_context *context;     /* The current span context. */
	struct list              list;        /* Used to chain this structure. */
};

struct flt_ot_uuid {
	union {
		uint64_t u64[2];
		uint8_t  u8[16];
		struct {
			uint32_t time_low;
			uint16_t time_mid;
			uint16_t time_hi_and_version;
			uint16_t clock_seq;
			uint64_t node : 48;
		} __attribute__((packed));
	};
	char s[40];
};

/* The runtime filter context attached to a stream. */
struct flt_ot_runtime_context {
	struct stream      *stream;        /* The stream to which the filter is attached. */
	struct filter      *filter;        /* The OpenTracing filter. */
	struct flt_ot_uuid  uuid;          /* Randomly generated UUID. */
	bool                flag_harderr;  /* [0 1] */
	bool                flag_disabled; /* [0 1] */
	uint8_t             logging;       /* [0 1 3] */
	uint                analyzers;     /* Executed channel analyzers. */
	struct list         spans;         /* The scope spans. */
	struct list         contexts;      /* The scope contexts. */
};


#ifndef DEBUG_OT
#  define flt_ot_pools_info()   while (0)
#else
void                           flt_ot_pools_info(void);
#endif
struct flt_ot_runtime_context *flt_ot_runtime_context_init(struct stream *s, struct filter *f, char **err);
void                           flt_ot_runtime_context_free(struct filter *f);

struct flt_ot_scope_span      *flt_ot_scope_span_init(struct flt_ot_runtime_context *rt_ctx, const char *id, size_t id_len, otc_span_reference_type_t ref_type, const char *ref_id, size_t ref_id_len, uint dir, char **err);
void                           flt_ot_scope_span_free(struct flt_ot_scope_span **ptr);
struct flt_ot_scope_context   *flt_ot_scope_context_init(struct flt_ot_runtime_context *rt_ctx, struct otc_tracer *tracer, const char *id, size_t id_len, const struct otc_text_map *text_map, uint dir, char **err);
void                           flt_ot_scope_context_free(struct flt_ot_scope_context **ptr);
void                           flt_ot_scope_data_free(struct flt_ot_scope_data *ptr);

int                            flt_ot_scope_finish_mark(const struct flt_ot_runtime_context *rt_ctx, const char *id, size_t id_len);
void                           flt_ot_scope_finish_marked(const struct flt_ot_runtime_context *rt_ctx, const struct timespec *ts_finish);
void                           flt_ot_scope_free_unused(struct flt_ot_runtime_context *rt_ctx, struct channel *chn);

#endif /* _OPENTRACING_SCOPE_H_ */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 *
 * vi: noexpandtab shiftwidth=8 tabstop=8
 */
