/*
 * MAP management functions.
 *
 * Copyright 2000-2013 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <syslog.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/arg.h>
#include <haproxy/cli.h>
#include <haproxy/map.h>
#include <haproxy/pattern.h>
#include <haproxy/regex.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stats-t.h>
#include <haproxy/stconn.h>
#include <haproxy/tools.h>


/* Parse an IPv4 or IPv6 address and store it into the sample.
 * The output type is IPv4 or IPv6.
 */
int map_parse_ip(const char *text, struct sample_data *data)
{
	int len = strlen(text);

	if (buf2ip(text, len, &data->u.ipv4)) {
		data->type = SMP_T_IPV4;
		return 1;
	}
	if (buf2ip6(text, len, &data->u.ipv6)) {
		data->type = SMP_T_IPV6;
		return 1;
	}
	return 0;
}

/* Parse a string and store a pointer to it into the sample. The original
 * string must be left in memory because we return a direct memory reference.
 * The output type is SMP_T_STR. There is no risk that the data will be
 * overwritten because sample_conv_map() makes a const sample with this
 * output.
 */
int map_parse_str(const char *text, struct sample_data *data)
{
	data->u.str.area = (char *)text;
	data->u.str.data = strlen(text);
	data->u.str.size = data->u.str.data + 1;
	data->type = SMP_T_STR;
	return 1;
}

/* Parse an integer and convert it to a sample. The output type is SINT if the
 * number is negative, or UINT if it is positive or null. The function returns
 * zero (error) if the number is too large.
 */
int map_parse_int(const char *text, struct sample_data *data)
{
	data->type = SMP_T_SINT;
	data->u.sint = read_int64(&text, text + strlen(text));
	if (*text != '\0')
		return 0;
	return 1;
}

/* This crete and initialize map descriptor.
 * Return NULL if out of memory error
 */
static struct map_descriptor *map_create_descriptor(struct sample_conv *conv)
{
	struct map_descriptor *desc;

	desc = calloc(1, sizeof(*desc));
	if (!desc)
		return NULL;

	desc->conv = conv;

	return desc;
}

/* This function load the map file according with data type declared into
 * the "struct sample_conv".
 *
 * This function choose the indexation type (ebtree or list) according with
 * the type of match needed.
 */
int sample_load_map(struct arg *arg, struct sample_conv *conv,
                    const char *file, int line, char **err)
{
	struct map_descriptor *desc;

	if (!(global.mode & MODE_STARTING)) {
		memprintf(err, "map: cannot load map at runtime");
		return 0;
	}

	/* create new map descriptor */
	desc = map_create_descriptor(conv);
	if (!desc) {
		memprintf(err, "out of memory");
		return 0;
	}

	/* Initialize pattern */
	pattern_init_head(&desc->pat);

	/* This is original pattern, must free */
	desc->do_free = 1;

	/* Set the match method. */
	desc->pat.match = pat_match_fcts[(long)conv->private];
	desc->pat.parse = pat_parse_fcts[(long)conv->private];
	desc->pat.index = pat_index_fcts[(long)conv->private];
	desc->pat.prune = pat_prune_fcts[(long)conv->private];
	desc->pat.expect_type = pat_match_types[(long)conv->private];

	/* Set the output parse method. */
	switch (desc->conv->out_type) {
	case SMP_T_STR:  desc->pat.parse_smp = map_parse_str;  break;
	case SMP_T_SINT: desc->pat.parse_smp = map_parse_int;  break;
	case SMP_T_ADDR: desc->pat.parse_smp = map_parse_ip;   break;
	default:
		memprintf(err, "map: internal haproxy error: no default parse case for the input type <%d>.",
		          conv->out_type);
		free(desc);
		return 0;
	}

	/* Load map. */
	if (!pattern_read_from_file(&desc->pat, PAT_REF_MAP, arg[0].data.str.area, PAT_MF_NO_DNS,
	                            1, err, file, line))
		return 0;

	/* the maps of type IP support a string as default value. This
	 * string can be an ipv4 or an ipv6, we must convert it.
	 */
	if (arg[1].type != ARGT_STOP && desc->conv->out_type == SMP_T_ADDR) {
		struct sample_data data;
		if (!map_parse_ip(arg[1].data.str.area, &data)) {
			memprintf(err, "map: cannot parse default ip <%s>.",
				  arg[1].data.str.area);
			return 0;
		}
		chunk_destroy(&arg[1].data.str);
		if (data.type == SMP_T_IPV4) {
			arg[1].type = ARGT_IPV4;
			arg[1].data.ipv4 = data.u.ipv4;
		} else {
			arg[1].type = ARGT_IPV6;
			arg[1].data.ipv6 = data.u.ipv6;
		}
	}

	/* replace the first argument by this definition */
	chunk_destroy(&arg[0].data.str);
	arg[0].type = ARGT_MAP;
	arg[0].data.map = desc;

	return 1;
}

/* try to match input sample against map entries, returns matched entry's key
 * on success
 */
static int sample_conv_map_key(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct map_descriptor *desc;
	struct pattern *pat;

	/* get config */
	desc = arg_p[0].data.map;

	/* Execute the match function. */
	pat = pattern_exec_match(&desc->pat, smp, 1);

	/* Match case. */
	if (pat) {
		smp->data.type = SMP_T_STR;
		smp->flags |= SMP_F_CONST;
		smp->data.u.str.area = (char *)pat->ref->pattern;
		smp->data.u.str.data = strlen(pat->ref->pattern);
		return 1;
	}
	return 0;
}

/* try to match input sample against map entries, returns matched entry's value
 * on success
 */
static int sample_conv_map(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct map_descriptor *desc;
	struct pattern *pat;
	struct buffer *str;

	/* get config */
	desc = arg_p[0].data.map;

	/* Execute the match function. */
	pat = pattern_exec_match(&desc->pat, smp, 1);

	/* Match case. */
	if (pat) {
		if (pat->data) {
			/* In the regm case, merge the sample with the input. */
			if ((long)private == PAT_MATCH_REGM) {
				struct buffer *tmptrash;
				int len;

				/* Copy the content of the sample because it could
				   be scratched by incoming get_trash_chunk */
				tmptrash = alloc_trash_chunk();
				if (!tmptrash)
					return 0;

				tmptrash->data = smp->data.u.str.data;
				if (tmptrash->data > (tmptrash->size-1))
					tmptrash->data = tmptrash->size-1;

				memcpy(tmptrash->area, smp->data.u.str.area, tmptrash->data);
				tmptrash->area[tmptrash->data] = 0;

				str = get_trash_chunk();
				len = exp_replace(str->area, str->size,
				                  tmptrash->area,
				                  pat->data->u.str.area,
				                  (regmatch_t *)smp->ctx.a[0]);
				free_trash_chunk(tmptrash);

				if (len == -1)
					return 0;

				str->data = len;
				smp->data.u.str = *str;
				return 1;
			}
			/* Copy sample. */
			smp->data = *pat->data;
			smp->flags |= SMP_F_CONST;
			return 1;
		}

		/* Return just int sample containing 1. */
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = 1;
		return 1;
	}

	/* If no default value available, the converter fails. */
	if (arg_p[1].type == ARGT_STOP)
		return 0;

	/* Return the default value. */
	switch (desc->conv->out_type) {

	case SMP_T_STR:
		smp->data.type = SMP_T_STR;
		smp->flags |= SMP_F_CONST;
		smp->data.u.str = arg_p[1].data.str;
		break;

	case SMP_T_SINT:
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = arg_p[1].data.sint;
		break;

	case SMP_T_ADDR:
		if (arg_p[1].type == ARGT_IPV4) {
			smp->data.type = SMP_T_IPV4;
			smp->data.u.ipv4 = arg_p[1].data.ipv4;
		} else {
			smp->data.type = SMP_T_IPV6;
			smp->data.u.ipv6 = arg_p[1].data.ipv6;
		}
		break;
	}

	return 1;
}

/* This function is used with map and acl management. It permits to browse
 * each reference. The variable <getnext> must contain the current node,
 * <end> point to the root node and the <flags> permit to filter required
 * nodes.
 */
static inline
struct pat_ref *pat_list_get_next(struct pat_ref *getnext, struct list *end,
                                  unsigned int flags)
{
	struct pat_ref *ref = getnext;

	while (1) {

		/* Get next list entry. */
		ref = LIST_NEXT(&ref->list, struct pat_ref *, list);

		/* If the entry is the last of the list, return NULL. */
		if (&ref->list == end)
			return NULL;

		/* If the entry match the flag, return it. */
		if (ref->flags & flags)
			return ref;
	}
}

static inline
struct pat_ref *pat_ref_lookup_ref(const char *reference)
{
	int id;
	char *error;

	/* If the reference starts by a '#', this is numeric id. */
	if (reference[0] == '#') {
		/* Try to convert the numeric id. If the conversion fails, the lookup fails. */
		id = strtol(reference + 1, &error, 10);
		if (*error != '\0')
			return NULL;

		/* Perform the unique id lookup. */
		return pat_ref_lookupid(id);
	}

	/* Perform the string lookup. */
	return pat_ref_lookup(reference);
}

/* This function is used with map and acl management. It permits to browse
 * each reference.
 */
static inline
struct pattern_expr *pat_expr_get_next(struct pattern_expr *getnext, struct list *end)
{
	struct pattern_expr *expr;
	expr = LIST_NEXT(&getnext->list, struct pattern_expr *, list);
	if (&expr->list == end)
		return NULL;
	return expr;
}

/* appctx context for the "{show|get|add|del|*} {map|acl}" commands. This is
 * used even by commands that only have a parser and no I/O handler because
 * it provides a unified way to manipulate some fields and will allow to
 * expand some of them more easily later if needed.
 */
struct show_map_ctx {
	struct pat_ref *ref;
	struct bref bref;	/* back-reference from the pat_ref_elt being dumped */
	struct pattern_expr *expr;
	struct buffer chunk;
	unsigned int display_flags;
	unsigned int curr_gen;  /* current/latest generation, for show/clear */
	unsigned int prev_gen;  /* prev generation, for clear */
	enum {
		STATE_INIT = 0, /* initialize list and backrefs */
		STATE_LIST,     /* list entries */
		STATE_DONE,     /* finished */
	} state;                /* state of the dump */
};

/* expects the current generation ID in ctx->curr_gen */
static int cli_io_handler_pat_list(struct appctx *appctx)
{
	struct show_map_ctx *ctx = appctx->svcctx;
	struct pat_ref_elt *elt;

	switch (ctx->state) {
	case STATE_INIT:
		ctx->state = STATE_LIST;
		__fallthrough;

	case STATE_LIST:
		HA_RWLOCK_WRLOCK(PATREF_LOCK, &ctx->ref->lock);

		if (!LIST_ISEMPTY(&ctx->bref.users)) {
			LIST_DELETE(&ctx->bref.users);
			LIST_INIT(&ctx->bref.users);
		} else {
			ctx->bref.ref = ctx->ref->head.n;
		}

		while (ctx->bref.ref != &ctx->ref->head) {
			chunk_reset(&trash);

			elt = LIST_ELEM(ctx->bref.ref, struct pat_ref_elt *, list);

			if (elt->gen_id != ctx->curr_gen)
				goto skip;

			/* build messages */
			if (elt->sample)
				chunk_appendf(&trash, "%p %s %s\n",
				              elt, elt->pattern,
				              elt->sample);
			else
				chunk_appendf(&trash, "%p %s\n",
				              elt, elt->pattern);

			if (applet_putchk(appctx, &trash) == -1) {
				/* let's try again later from this stream. We add ourselves into
				 * this stream's users so that it can remove us upon termination.
				 */
				LIST_APPEND(&elt->back_refs, &ctx->bref.users);
				HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
				return 0;
			}
		skip:
			/* get next list entry and check the end of the list */
			ctx->bref.ref = elt->list.n;
		}
		HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
		__fallthrough;

	default:
		ctx->state = STATE_DONE;
		return 1;
	}
}

static int cli_io_handler_pats_list(struct appctx *appctx)
{
	struct show_map_ctx *ctx = appctx->svcctx;

	switch (ctx->state) {
	case STATE_INIT:
		/* Display the column headers. If the message cannot be sent,
		 * quit the function with returning 0. The function is called
		 * later and restarted at the state "STATE_INIT".
		 */
		chunk_reset(&trash);
		chunk_appendf(&trash, "# id (file) description\n");
		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		/* Now, we start the browsing of the references lists.
		 * Note that the following call to LIST_ELEM returns a bad pointer. The only
		 * available field of this pointer is <list>. It is used with the function
		 * pat_list_get_next() for returning the first available entry
		 */
		ctx->ref = LIST_ELEM(&pattern_reference, struct pat_ref *, list);
		ctx->ref = pat_list_get_next(ctx->ref, &pattern_reference,
		                                        ctx->display_flags);
		ctx->state = STATE_LIST;
		__fallthrough;

	case STATE_LIST:
		while (ctx->ref) {
			chunk_reset(&trash);

			/* Build messages. If the reference is used by another category than
			 * the listed categories, display the information in the message.
			 */
			chunk_appendf(&trash, "%d (%s) %s. curr_ver=%u next_ver=%u entry_cnt=%llu\n", ctx->ref->unique_id,
			              ctx->ref->reference ? ctx->ref->reference : "",
			              ctx->ref->display, ctx->ref->curr_gen, ctx->ref->next_gen,
			              ctx->ref->entry_cnt);

			if (applet_putchk(appctx, &trash) == -1) {
				/* let's try again later from this stream. We add ourselves into
				 * this stream's users so that it can remove us upon termination.
				 */
				return 0;
			}

			/* get next list entry and check the end of the list */
			ctx->ref = pat_list_get_next(ctx->ref, &pattern_reference,
			                                        ctx->display_flags);
		}

		__fallthrough;

	default:
		ctx->state = STATE_DONE;
		return 1;
	}
	return 0;
}

static int cli_io_handler_map_lookup(struct appctx *appctx)
{
	struct show_map_ctx *ctx = appctx->svcctx;
	struct sample sample;
	struct pattern *pat;
	int match_method;

	switch (ctx->state) {
	case STATE_INIT:
		/* Init to the first entry. The list cannot be change */
		ctx->expr = LIST_ELEM(&ctx->ref->pat, struct pattern_expr *, list);
		ctx->expr = pat_expr_get_next(ctx->expr, &ctx->ref->pat);
		ctx->state = STATE_LIST;
		__fallthrough;

	case STATE_LIST:
		HA_RWLOCK_RDLOCK(PATREF_LOCK, &ctx->ref->lock);
		/* for each lookup type */
		while (ctx->expr) {
			/* initialise chunk to build new message */
			chunk_reset(&trash);

			/* execute pattern matching */
			sample.data.type = SMP_T_STR;
			sample.flags = SMP_F_CONST;
			sample.data.u.str.data = ctx->chunk.data;
			sample.data.u.str.area = ctx->chunk.area;

			if (ctx->expr->pat_head->match &&
			    sample_convert(&sample, ctx->expr->pat_head->expect_type))
				pat = ctx->expr->pat_head->match(&sample, ctx->expr, 1);
			else
				pat = NULL;

			/* build return message: set type of match */
			for (match_method=0; match_method<PAT_MATCH_NUM; match_method++)
				if (ctx->expr->pat_head->match == pat_match_fcts[match_method])
					break;
			if (match_method >= PAT_MATCH_NUM)
				chunk_appendf(&trash, "type=unknown(%p)", ctx->expr->pat_head->match);
			else
				chunk_appendf(&trash, "type=%s", pat_match_names[match_method]);

			/* case sensitive */
			if (ctx->expr->mflags & PAT_MF_IGNORE_CASE)
				chunk_appendf(&trash, ", case=insensitive");
			else
				chunk_appendf(&trash, ", case=sensitive");

			/* Display no match, and set default value */
			if (!pat) {
				if (ctx->display_flags == PAT_REF_MAP)
					chunk_appendf(&trash, ", found=no");
				else
					chunk_appendf(&trash, ", match=no");
			}

			/* Display match and match info */
			else {
				/* display match */
				if (ctx->display_flags == PAT_REF_MAP)
					chunk_appendf(&trash, ", found=yes");
				else
					chunk_appendf(&trash, ", match=yes");

				/* display index mode */
				if (pat->sflags & PAT_SF_TREE)
					chunk_appendf(&trash, ", idx=tree");
				else
					chunk_appendf(&trash, ", idx=list");

				/* display pattern */
				if (ctx->display_flags == PAT_REF_MAP) {
					if (pat->ref)
						chunk_appendf(&trash, ", key=\"%s\"", pat->ref->pattern);
					else
						chunk_appendf(&trash, ", key=unknown");
				}
				else {
					if (pat->ref)
						chunk_appendf(&trash, ", pattern=\"%s\"", pat->ref->pattern);
					else
						chunk_appendf(&trash, ", pattern=unknown");
				}

				/* display return value */
				if (ctx->display_flags == PAT_REF_MAP) {
					if (pat->data && pat->ref && pat->ref->sample)
						chunk_appendf(&trash, ", value=\"%s\", type=\"%s\"", pat->ref->sample,
						              smp_to_type[pat->data->type]);
					else
						chunk_appendf(&trash, ", value=none");
				}
			}

			chunk_appendf(&trash, "\n");

			/* display response */
			if (applet_putchk(appctx, &trash) == -1) {
				/* let's try again later from this stream. We add ourselves into
				 * this stream's users so that it can remove us upon termination.
				 */
				HA_RWLOCK_RDUNLOCK(PATREF_LOCK, &ctx->ref->lock);
				return 0;
			}

			/* get next entry */
			ctx->expr = pat_expr_get_next(ctx->expr,
			                                         &ctx->ref->pat);
		}
		HA_RWLOCK_RDUNLOCK(PATREF_LOCK, &ctx->ref->lock);
		__fallthrough;

	default:
		ctx->state = STATE_DONE;
		return 1;
	}
}

static void cli_release_mlook(struct appctx *appctx)
{
	struct show_map_ctx *ctx = appctx->svcctx;

	ha_free(&ctx->chunk.area);
}


static int cli_parse_get_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_map_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (strcmp(args[1], "map") == 0 || strcmp(args[1], "acl") == 0) {
		/* Set flags. */
		if (args[1][0] == 'm')
			ctx->display_flags = PAT_REF_MAP;
		else
			ctx->display_flags = PAT_REF_ACL;

		/* No parameter. */
		if (!*args[2] || !*args[3]) {
			if (ctx->display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Missing map identifier and/or key.\n");
			else
				return cli_err(appctx, "Missing ACL identifier and/or key.\n");
		}

		/* lookup into the maps */
		ctx->ref = pat_ref_lookup_ref(args[2]);
		if (!ctx->ref) {
			if (ctx->display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}

		/* copy input string. The string must be allocated because
		 * it may be used over multiple iterations. It's released
		 * at the end and upon abort anyway.
		 */
		ctx->chunk.data = strlen(args[3]);
		ctx->chunk.size = ctx->chunk.data + 1;
		ctx->chunk.area = strdup(args[3]);
		if (!ctx->chunk.area)
			return cli_err(appctx,  "Out of memory error.\n");

		return 0;
	}
	return 1;
}

static int cli_parse_prepare_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_map_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (strcmp(args[1], "map") == 0 ||
	    strcmp(args[1], "acl") == 0) {
		uint next_gen;
		char *msg = NULL;

		/* Set ACL or MAP flags. */
		if (args[1][0] == 'm')
			ctx->display_flags = PAT_REF_MAP;
		else
			ctx->display_flags = PAT_REF_ACL;

		/* lookup into the refs and check the map flag */
		ctx->ref = pat_ref_lookup_ref(args[2]);
		if (!ctx->ref ||
		    !(ctx->ref->flags & ctx->display_flags)) {
			if (ctx->display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}
		next_gen = pat_ref_newgen(ctx->ref);
		return cli_dynmsg(appctx, LOG_INFO, memprintf(&msg, "New version created: %u\n", next_gen));
	}

	return 0;
}

static void cli_release_show_map(struct appctx *appctx)
{
	struct show_map_ctx *ctx = appctx->svcctx;

	if (!LIST_ISEMPTY(&ctx->bref.users)) {
		HA_RWLOCK_WRLOCK(PATREF_LOCK, &ctx->ref->lock);
		LIST_DEL_INIT(&ctx->bref.users);
		HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
	}
}

static int cli_parse_show_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_map_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (strcmp(args[1], "map") == 0 ||
	    strcmp(args[1], "acl") == 0) {
		const char *gen = NULL;

		/* Set ACL or MAP flags. */
		if (args[1][0] == 'm')
			ctx->display_flags = PAT_REF_MAP;
		else
			ctx->display_flags = PAT_REF_ACL;

		/* no parameter: display all map available */
		if (!*args[2]) {
			appctx->io_handler = cli_io_handler_pats_list;
			return 0;
		}

		/* For both "map" and "acl" we may have an optional generation
		 * number specified using a "@" character before the pattern
		 * file name.
		 */
		if (*args[2] == '@') {
			gen = args[2] + 1;
			args++;
		}

		/* lookup into the refs and check the map flag */
		ctx->ref = pat_ref_lookup_ref(args[2]);
		if (!ctx->ref ||
		    !(ctx->ref->flags & ctx->display_flags)) {
			if (ctx->display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}

		/* set the desired generation id in curr_gen */
		if (gen)
			ctx->curr_gen = str2uic(gen);
		else
			ctx->curr_gen = ctx->ref->curr_gen;

		LIST_INIT(&ctx->bref.users);
		appctx->io_handler = cli_io_handler_pat_list;
		appctx->io_release = cli_release_show_map;
		return 0;
	}

	return 0;
}

static int cli_parse_set_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_map_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (strcmp(args[1], "map") == 0) {
		char *err;

		/* Set flags. */
		ctx->display_flags = PAT_REF_MAP;

		/* Expect three parameters: map name, key and new value. */
		if (!*args[2] || !*args[3] || !*args[4])
			return cli_err(appctx, "'set map' expects three parameters: map identifier, key and value.\n");

		/* Lookup the reference in the maps. */
		ctx->ref = pat_ref_lookup_ref(args[2]);
		if (!ctx->ref)
			return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");

		/* If the entry identifier start with a '#', it is considered as
		 * pointer id
		 */
		if (args[3][0] == '#' && args[3][1] == '0' && args[3][2] == 'x') {
			struct pat_ref_elt *ref;
			long long int conv;
			char *error;

			/* Convert argument to integer value. */
			conv = strtoll(&args[3][1], &error, 16);
			if (*error != '\0')
				return cli_err(appctx, "Malformed identifier. Please use #<id> or <file>.\n");

			/* Convert and check integer to pointer. */
			ref = (struct pat_ref_elt *)(long)conv;
			if ((long long int)(long)ref != conv)
				return cli_err(appctx, "Malformed identifier. Please use #<id> or <file>.\n");

			/* Try to modify the entry. */
			err = NULL;
			HA_RWLOCK_WRLOCK(PATREF_LOCK, &ctx->ref->lock);
			if (!pat_ref_set_by_id(ctx->ref, ref, args[4], &err)) {
				HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
				if (err)
					return cli_dynerr(appctx, memprintf(&err, "%s.\n", err));
				else
					return cli_err(appctx, "Failed to update an entry.\n");
			}
			HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
		}
		else {
			/* Else, use the entry identifier as pattern
			 * string, and update the value.
			 */
			err = NULL;
			HA_RWLOCK_WRLOCK(PATREF_LOCK, &ctx->ref->lock);
			if (!pat_ref_set(ctx->ref, args[3], args[4], &err)) {
				HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
				if (err)
					return cli_dynerr(appctx, memprintf(&err, "%s.\n", err));
				else
					return cli_err(appctx, "Failed to update an entry.\n");
			}
			HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
		}

		/* The set is done, send message. */
		appctx->st0 = CLI_ST_PROMPT;
		return 0;
	}
	return 1;
}

static int cli_parse_add_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_map_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (strcmp(args[1], "map") == 0 ||
	    strcmp(args[1], "acl") == 0) {
		const char *gen = NULL;
		uint genid = 0;
		int ret;
		char *err;

		/* Set flags. */
		if (args[1][0] == 'm')
			ctx->display_flags = PAT_REF_MAP;
		else
			ctx->display_flags = PAT_REF_ACL;

		/* For both "map" and "acl" we may have an optional generation
		 * number specified using a "@" character before the pattern
		 * file name.
		 */
		if (*args[2] == '@') {
			gen = args[2] + 1;
			args++;
		}

		/* If the keyword is "map", we expect:
		 *   - three parameters if there is no payload
		 *   - one parameter if there is a payload
		 * If it is "acl", we expect only two parameters
		 */
		if (ctx->display_flags == PAT_REF_MAP) {
			if ((!payload && (!*args[2] || !*args[3] || !*args[4])) ||
			    (payload && !*args[2]))
				return cli_err(appctx,
					       "'add map' expects three parameters (map identifier, key and value)"
					       " or one parameter (map identifier) and a payload\n");
		}
		else if (!*args[2] || !*args[3])
			return cli_err(appctx, "'add acl' expects two parameters: ACL identifier and pattern.\n");

		/* Lookup for the reference. */
		ctx->ref = pat_ref_lookup_ref(args[2]);
		if (!ctx->ref) {
			if (ctx->display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}

		if (gen) {
			genid = str2uic(gen);
			if ((int)(genid - ctx->ref->next_gen) > 0) {
				if (ctx->display_flags == PAT_REF_MAP)
					return cli_err(appctx, "Version number in the future, please use 'prepare map' before.\n");
				else
					return cli_err(appctx, "Version number in the future, please use 'prepare acl' before.\n");
			}
		}

		/* The command "add acl" is prohibited if the reference
		 * use samples.
		 */
		if ((ctx->display_flags & PAT_REF_ACL) &&
		    (ctx->ref->flags & PAT_REF_SMP)) {
			return cli_err(appctx,
				       "This ACL is shared with a map containing samples. "
				       "You must use the command 'add map' to add values.\n");
		}

		/* Add value(s). If no payload is used, key and value are read
		 * from the command line and only one key is set. If a payload
		 * is passed, one key/value pair is read per line till the end
		 * of the payload is reached.
		 */
		err = NULL;

		do {
			char *key   = args[3];
			char *value = args[4];
			size_t l;

			if (payload) {
				/* key and value passed as payload, one pair per line */
				if (!*payload)
					break;

				key = payload;
				l = strcspn(key, " \t");
				payload += l;

				if (!*payload && ctx->display_flags == PAT_REF_MAP)
					return cli_dynerr(appctx, memprintf(&err, "Missing value for key '%s'.\n", key));

				key[l] = 0;
				payload++;

				/* value */
				payload += strspn(payload, " \t");
				value = payload;
				l = strcspn(value, "\n");
				payload += l;
				if (*payload)
					payload++;
				value[l] = 0;
			}

			if (ctx->display_flags != PAT_REF_MAP)
				value = NULL;

			HA_RWLOCK_WRLOCK(PATREF_LOCK, &ctx->ref->lock);
			ret = !!pat_ref_load(ctx->ref, gen ? genid : ctx->ref->curr_gen, key, value, -1, &err);
			HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);

			if (!ret) {
				if (err)
					return cli_dynerr(appctx, memprintf(&err, "%s.\n", err));
				else
					return cli_err(appctx, "Failed to add a key.\n");
			}
		} while (payload && *payload);

		/* The add is done, send message. */
		appctx->st0 = CLI_ST_PROMPT;
		return 1;
	}

	return 0;
}

static int cli_parse_del_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_map_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (args[1][0] == 'm')
		ctx->display_flags = PAT_REF_MAP;
	else
		ctx->display_flags = PAT_REF_ACL;

	/* Expect two parameters: map name and key. */
	if (!*args[2] || !*args[3]) {
		if (ctx->display_flags == PAT_REF_MAP)
			return cli_err(appctx, "This command expects two parameters: map identifier and key.\n");
		else
			return cli_err(appctx, "This command expects two parameters: ACL identifier and key.\n");
	}

	/* Lookup the reference in the maps. */
	ctx->ref = pat_ref_lookup_ref(args[2]);
	if (!ctx->ref ||
	    !(ctx->ref->flags & ctx->display_flags))
		return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");

	/* If the entry identifier start with a '#', it is considered as
	 * pointer id
	 */
	if (args[3][0] == '#' && args[3][1] == '0' && args[3][2] == 'x') {
		struct pat_ref_elt *ref;
		long long int conv;
		char *error;

		/* Convert argument to integer value. */
		conv = strtoll(&args[3][1], &error, 16);
		if (*error != '\0')
			return cli_err(appctx, "Malformed identifier. Please use #<id> or <file>.\n");

		/* Convert and check integer to pointer. */
		ref = (struct pat_ref_elt *)(long)conv;
		if ((long long int)(long)ref != conv)
			return cli_err(appctx, "Malformed identifier. Please use #<id> or <file>.\n");

		/* Try to delete the entry. */
		HA_RWLOCK_WRLOCK(PATREF_LOCK, &ctx->ref->lock);
		if (!pat_ref_delete_by_id(ctx->ref, ref)) {
			HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
			/* The entry is not found, send message. */
			return cli_err(appctx, "Key not found.\n");
		}
		HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
	}
	else {
		/* Else, use the entry identifier as pattern
		 * string and try to delete the entry.
		 */
		HA_RWLOCK_WRLOCK(PATREF_LOCK, &ctx->ref->lock);
		if (!pat_ref_delete(ctx->ref, args[3])) {
			HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
			/* The entry is not found, send message. */
			return cli_err(appctx, "Key not found.\n");
		}
		HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);
	}

	/* The deletion is done, send message. */
	appctx->st0 = CLI_ST_PROMPT;
	return 1;
}

/* continue to clear a map which was started in the parser. The range of
 * generations this applies to is taken from ctx->curr_gen for the oldest
 * and ctx->prev_gen for the latest.
 */
static int cli_io_handler_clear_map(struct appctx *appctx)
{
	struct show_map_ctx *ctx = appctx->svcctx;
	int finished;

	HA_RWLOCK_WRLOCK(PATREF_LOCK, &ctx->ref->lock);
	finished = pat_ref_purge_range(ctx->ref, ctx->curr_gen, ctx->prev_gen, 100);
	HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);

	if (!finished) {
		/* let's come back later */
		applet_have_more_data(appctx);
		return 0;
	}

	trim_all_pools();
	return 1;
}

/* note: sets ctx->curr_gen and ctx->prev_gen to the oldest and
 * latest generations to clear, respectively, and will call the clear_map
 * handler.
 */
static int cli_parse_clear_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_map_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (strcmp(args[1], "map") == 0 || strcmp(args[1], "acl") == 0) {
		const char *gen = NULL;

		/* Set ACL or MAP flags. */
		if (args[1][0] == 'm')
			ctx->display_flags = PAT_REF_MAP;
		else
			ctx->display_flags = PAT_REF_ACL;

		/* For both "map" and "acl" we may have an optional generation
		 * number specified using a "@" character before the pattern
		 * file name.
		 */
		if (*args[2] == '@') {
			gen = args[2] + 1;
			args++;
		}

		/* no parameter */
		if (!*args[2]) {
			if (ctx->display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Missing map identifier.\n");
			else
				return cli_err(appctx, "Missing ACL identifier.\n");
		}

		/* lookup into the refs and check the map flag */
		ctx->ref = pat_ref_lookup_ref(args[2]);
		if (!ctx->ref ||
		    !(ctx->ref->flags & ctx->display_flags)) {
			if (ctx->display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}

		/* set the desired generation id in curr_gen/prev_gen */
		if (gen)
			ctx->prev_gen = ctx->curr_gen = str2uic(gen);
		else
			ctx->prev_gen = ctx->curr_gen = ctx->ref->curr_gen;

		/* delegate the clearing to the I/O handler which can yield */
		return 0;
	}
	return 1;
}

/* note: sets ctx->curr_gen and ctx->prev_gen to the oldest and
 * latest generations to clear, respectively, and will call the clear_map
 * handler.
 */
static int cli_parse_commit_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_map_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (strcmp(args[1], "map") == 0 || strcmp(args[1], "acl") == 0) {
		const char *gen = NULL;
		uint genid;
		uint ret;

		/* Set ACL or MAP flags. */
		if (args[1][0] == 'm')
			ctx->display_flags = PAT_REF_MAP;
		else
			ctx->display_flags = PAT_REF_ACL;

		if (*args[2] != '@')
			return cli_err(appctx, "Missing version number.\n");

		/* The generation number is mandatory for a commit. The range
		 * of generations that get trashed by a commit starts from the
		 * opposite of the current one and ends at the previous one.
		 */
		gen = args[2] + 1;
		genid = str2uic(gen);
		ctx->prev_gen = genid - 1;
		ctx->curr_gen = ctx->prev_gen - ((~0U) >> 1);

		/* no parameter */
		if (!*args[3]) {
			if (ctx->display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Missing map identifier.\n");
			else
				return cli_err(appctx, "Missing ACL identifier.\n");
		}

		/* lookup into the refs and check the map flag */
		ctx->ref = pat_ref_lookup_ref(args[3]);
		if (!ctx->ref ||
		    !(ctx->ref->flags & ctx->display_flags)) {
			if (ctx->display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}

		HA_RWLOCK_WRLOCK(PATREF_LOCK, &ctx->ref->lock);
		if (genid - (ctx->ref->curr_gen + 1) <
		    ctx->ref->next_gen - ctx->ref->curr_gen)
			ret = pat_ref_commit(ctx->ref, genid);
		else
			ret = 1;
		HA_RWLOCK_WRUNLOCK(PATREF_LOCK, &ctx->ref->lock);

		if (ret != 0)
			return cli_err(appctx, "Version number out of range.\n");

		/* delegate the clearing to the I/O handler which can yield */
		return 0;
	}
	return 1;
}

/* register cli keywords */

static struct cli_kw_list cli_kws = {{ },{
	{ { "add",   "acl", NULL }, "add acl [@<ver>] <acl> <pattern>        : add an acl entry",                                       cli_parse_add_map, NULL },
	{ { "clear", "acl", NULL }, "clear acl [@<ver>] <acl>                : clear the contents of this acl",                         cli_parse_clear_map, cli_io_handler_clear_map, NULL },
	{ { "commit","acl", NULL }, "commit acl @<ver> <acl>                 : commit the ACL at this version",                         cli_parse_commit_map, cli_io_handler_clear_map, NULL },
	{ { "del",   "acl", NULL }, "del acl <acl> [<key>|#<ref>]            : delete acl entries matching <key>",                      cli_parse_del_map, NULL },
	{ { "get",   "acl", NULL }, "get acl <acl> <value>                   : report the patterns matching a sample for an ACL",       cli_parse_get_map, cli_io_handler_map_lookup, cli_release_mlook },
	{ { "prepare","acl",NULL }, "prepare acl <acl>                       : prepare a new version for atomic ACL replacement",       cli_parse_prepare_map, NULL },
	{ { "show",  "acl", NULL }, "show acl [@<ver>] <acl>]                : report available acls or dump an acl's contents",        cli_parse_show_map, NULL },
	{ { "add",   "map", NULL }, "add map [@<ver>] <map> <key> <val>      : add a map entry (payload supported instead of key/val)", cli_parse_add_map, NULL },
	{ { "clear", "map", NULL }, "clear map [@<ver>] <map>                : clear the contents of this map",                         cli_parse_clear_map, cli_io_handler_clear_map, NULL },
	{ { "commit","map", NULL }, "commit map @<ver> <map>                 : commit the map at this version",                         cli_parse_commit_map, cli_io_handler_clear_map, NULL },
	{ { "del",   "map", NULL }, "del map <map> [<key>|#<ref>]            : delete map entries matching <key>",                      cli_parse_del_map, NULL },
	{ { "get",   "map", NULL }, "get map <acl> <value>                   : report the keys and values matching a sample for a map", cli_parse_get_map, cli_io_handler_map_lookup, cli_release_mlook },
	{ { "prepare","map",NULL }, "prepare map <acl>                       : prepare a new version for atomic map replacement",       cli_parse_prepare_map, NULL },
	{ { "set",   "map", NULL }, "set map <map> [<key>|#<ref>] <value>    : modify a map entry",                                     cli_parse_set_map, NULL },
	{ { "show",  "map", NULL }, "show map [@ver] [map]                   : report available maps or dump a map's contents",         cli_parse_show_map, NULL },
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/* Note: must not be declared <const> as its list will be overwritten
 *
 * For the map_*_int keywords, the output is declared as SMP_T_UINT, but the converter function
 * can provide SMP_T_UINT, SMP_T_SINT or SMP_T_BOOL depending on how the patterns found in the
 * file can be parsed.
 *
 * For the map_*_ip keyword, the output is declared as SMP_T_IPV4, but the converter function
 * can provide SMP_T_IPV4 or SMP_T_IPV6 depending on the patterns found in the file.
 *
 * The map_* keywords only emit strings.
 *
 * The output type is only used during the configuration parsing. It is used for detecting
 * compatibility problems.
 *
 * The arguments are: <file>[,<default value>]
 */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "map",         sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  (void *)PAT_MATCH_STR },
	{ "map_str",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  (void *)PAT_MATCH_STR },
	{ "map_beg",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  (void *)PAT_MATCH_BEG },
	{ "map_sub",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  (void *)PAT_MATCH_SUB },
	{ "map_dir",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  (void *)PAT_MATCH_DIR },
	{ "map_dom",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  (void *)PAT_MATCH_DOM },
	{ "map_end",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  (void *)PAT_MATCH_END },
	{ "map_reg",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  (void *)PAT_MATCH_REG },
	{ "map_regm",    sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  (void *)PAT_MATCH_REGM},
	{ "map_int",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_SINT, SMP_T_STR,  (void *)PAT_MATCH_INT },
	{ "map_ip",      sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_ADDR, SMP_T_STR,  (void *)PAT_MATCH_IP  },

	{ "map_str_int", sample_conv_map, ARG2(1,STR,SINT), sample_load_map, SMP_T_STR,  SMP_T_SINT, (void *)PAT_MATCH_STR },
	{ "map_beg_int", sample_conv_map, ARG2(1,STR,SINT), sample_load_map, SMP_T_STR,  SMP_T_SINT, (void *)PAT_MATCH_BEG },
	{ "map_sub_int", sample_conv_map, ARG2(1,STR,SINT), sample_load_map, SMP_T_STR,  SMP_T_SINT, (void *)PAT_MATCH_SUB },
	{ "map_dir_int", sample_conv_map, ARG2(1,STR,SINT), sample_load_map, SMP_T_STR,  SMP_T_SINT, (void *)PAT_MATCH_DIR },
	{ "map_dom_int", sample_conv_map, ARG2(1,STR,SINT), sample_load_map, SMP_T_STR,  SMP_T_SINT, (void *)PAT_MATCH_DOM },
	{ "map_end_int", sample_conv_map, ARG2(1,STR,SINT), sample_load_map, SMP_T_STR,  SMP_T_SINT, (void *)PAT_MATCH_END },
	{ "map_reg_int", sample_conv_map, ARG2(1,STR,SINT), sample_load_map, SMP_T_STR,  SMP_T_SINT, (void *)PAT_MATCH_REG },
	{ "map_int_int", sample_conv_map, ARG2(1,STR,SINT), sample_load_map, SMP_T_SINT, SMP_T_SINT, (void *)PAT_MATCH_INT },
	{ "map_ip_int",  sample_conv_map, ARG2(1,STR,SINT), sample_load_map, SMP_T_ADDR, SMP_T_SINT, (void *)PAT_MATCH_IP  },

	{ "map_str_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_ADDR, (void *)PAT_MATCH_STR },
	{ "map_beg_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_ADDR, (void *)PAT_MATCH_BEG },
	{ "map_sub_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_ADDR, (void *)PAT_MATCH_SUB },
	{ "map_dir_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_ADDR, (void *)PAT_MATCH_DIR },
	{ "map_dom_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_ADDR, (void *)PAT_MATCH_DOM },
	{ "map_end_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_ADDR, (void *)PAT_MATCH_END },
	{ "map_reg_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_ADDR, (void *)PAT_MATCH_REG },
	{ "map_int_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_SINT, SMP_T_ADDR, (void *)PAT_MATCH_INT },
	{ "map_ip_ip",   sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_ADDR, SMP_T_ADDR, (void *)PAT_MATCH_IP  },

	{ "map_str_key",  sample_conv_map_key, ARG1(1,STR), sample_load_map, SMP_T_STR,  SMP_T_STR, (void *)PAT_MATCH_STR },
	{ "map_beg_key",  sample_conv_map_key, ARG1(1,STR), sample_load_map, SMP_T_STR,  SMP_T_STR, (void *)PAT_MATCH_BEG },
	{ "map_sub_key",  sample_conv_map_key, ARG1(1,STR), sample_load_map, SMP_T_STR,  SMP_T_STR, (void *)PAT_MATCH_SUB },
	{ "map_dir_key",  sample_conv_map_key, ARG1(1,STR), sample_load_map, SMP_T_STR,  SMP_T_STR, (void *)PAT_MATCH_DIR },
	{ "map_dom_key",  sample_conv_map_key, ARG1(1,STR), sample_load_map, SMP_T_STR,  SMP_T_STR, (void *)PAT_MATCH_DOM },
	{ "map_end_key",  sample_conv_map_key, ARG1(1,STR), sample_load_map, SMP_T_STR,  SMP_T_STR, (void *)PAT_MATCH_END },
	{ "map_reg_key",  sample_conv_map_key, ARG1(1,STR), sample_load_map, SMP_T_STR,  SMP_T_STR, (void *)PAT_MATCH_REG },
	{ "map_int_key",  sample_conv_map_key, ARG1(1,STR), sample_load_map, SMP_T_SINT, SMP_T_STR, (void *)PAT_MATCH_INT },
	{ "map_ip_key",   sample_conv_map_key, ARG1(1,STR), sample_load_map, SMP_T_ADDR, SMP_T_STR, (void *)PAT_MATCH_IP  },

	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);
