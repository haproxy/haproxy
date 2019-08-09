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

#include <limits.h>
#include <stdio.h>

#include <common/initcall.h>
#include <common/standard.h>

#include <types/applet.h>
#include <types/cli.h>
#include <types/global.h>
#include <types/map.h>
#include <types/pattern.h>
#include <types/stats.h>

#include <proto/applet.h>
#include <proto/arg.h>
#include <proto/cli.h>
#include <proto/log.h>
#include <proto/map.h>
#include <proto/pattern.h>
#include <proto/stream_interface.h>
#include <proto/sample.h>

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
	desc->pat.delete = pat_delete_fcts[(long)conv->private];
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
		if (data.type == SMP_T_IPV4) {
			arg[1].type = ARGT_IPV4;
			arg[1].data.ipv4 = data.u.ipv4;
		} else {
			arg[1].type = ARGT_IPV6;
			arg[1].data.ipv6 = data.u.ipv6;
		}
	}

	/* replace the first argument by this definition */
	arg[0].type = ARGT_MAP;
	arg[0].data.map = desc;

	return 1;
}

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

static int cli_io_handler_pat_list(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct pat_ref_elt *elt;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW))) {
		/* If we're forced to shut down, we might have to remove our
		 * reference to the last ref_elt being dumped.
		 */
		if (appctx->st2 == STAT_ST_LIST) {
			if (!LIST_ISEMPTY(&appctx->ctx.map.bref.users)) {
				LIST_DEL(&appctx->ctx.map.bref.users);
				LIST_INIT(&appctx->ctx.map.bref.users);
			}
		}
		return 1;
	}

	switch (appctx->st2) {

	case STAT_ST_INIT:
		/* the function had not been called yet, let's prepare the
		 * buffer for a response. We initialize the current stream
		 * pointer to the first in the global list. When a target
		 * stream is being destroyed, it is responsible for updating
		 * this pointer. We know we have reached the end when this
		 * pointer points back to the head of the streams list.
		 */
		HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		LIST_INIT(&appctx->ctx.map.bref.users);
		appctx->ctx.map.bref.ref = appctx->ctx.map.ref->head.n;
		HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		appctx->st2 = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:

		HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);

		if (!LIST_ISEMPTY(&appctx->ctx.map.bref.users)) {
			LIST_DEL(&appctx->ctx.map.bref.users);
			LIST_INIT(&appctx->ctx.map.bref.users);
		}

		while (appctx->ctx.map.bref.ref != &appctx->ctx.map.ref->head) {
			chunk_reset(&trash);

			elt = LIST_ELEM(appctx->ctx.map.bref.ref, struct pat_ref_elt *, list);

			/* build messages */
			if (elt->sample)
				chunk_appendf(&trash, "%p %s %s\n",
				              elt, elt->pattern,
				              elt->sample);
			else
				chunk_appendf(&trash, "%p %s\n",
				              elt, elt->pattern);

			if (ci_putchk(si_ic(si), &trash) == -1) {
				/* let's try again later from this stream. We add ourselves into
				 * this stream's users so that it can remove us upon termination.
				 */
				LIST_ADDQ(&elt->back_refs, &appctx->ctx.map.bref.users);
				HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
				si_rx_room_blk(si);
				return 0;
			}

			/* get next list entry and check the end of the list */
			appctx->ctx.map.bref.ref = elt->list.n;
		}
		HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		/* fall through */

	default:
		appctx->st2 = STAT_ST_FIN;
		return 1;
	}
}

static int cli_io_handler_pats_list(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;

	switch (appctx->st2) {
	case STAT_ST_INIT:
		/* Display the column headers. If the message cannot be sent,
		 * quit the function with returning 0. The function is called
		 * later and restarted at the state "STAT_ST_INIT".
		 */
		chunk_reset(&trash);
		chunk_appendf(&trash, "# id (file) description\n");
		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			return 0;
		}

		/* Now, we start the browsing of the references lists.
		 * Note that the following call to LIST_ELEM returns a bad pointer. The only
		 * available field of this pointer is <list>. It is used with the function
		 * pat_list_get_next() for returning the first available entry
		 */
		appctx->ctx.map.ref = LIST_ELEM(&pattern_reference, struct pat_ref *, list);
		appctx->ctx.map.ref = pat_list_get_next(appctx->ctx.map.ref, &pattern_reference,
		                                        appctx->ctx.map.display_flags);
		appctx->st2 = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		while (appctx->ctx.map.ref) {
			chunk_reset(&trash);

			/* Build messages. If the reference is used by another category than
			 * the listed categories, display the information in the message.
			 */
			chunk_appendf(&trash, "%d (%s) %s\n", appctx->ctx.map.ref->unique_id,
			              appctx->ctx.map.ref->reference ? appctx->ctx.map.ref->reference : "",
			              appctx->ctx.map.ref->display);

			if (ci_putchk(si_ic(si), &trash) == -1) {
				/* let's try again later from this stream. We add ourselves into
				 * this stream's users so that it can remove us upon termination.
				 */
				si_rx_room_blk(si);
				return 0;
			}

			/* get next list entry and check the end of the list */
			appctx->ctx.map.ref = pat_list_get_next(appctx->ctx.map.ref, &pattern_reference,
			                                        appctx->ctx.map.display_flags);
		}

		/* fall through */

	default:
		appctx->st2 = STAT_ST_FIN;
		return 1;
	}
	return 0;
}

static int cli_io_handler_map_lookup(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct sample sample;
	struct pattern *pat;
	int match_method;

	switch (appctx->st2) {
	case STAT_ST_INIT:
		/* Init to the first entry. The list cannot be change */
		appctx->ctx.map.expr = LIST_ELEM(&appctx->ctx.map.ref->pat, struct pattern_expr *, list);
		appctx->ctx.map.expr = pat_expr_get_next(appctx->ctx.map.expr, &appctx->ctx.map.ref->pat);
		appctx->st2 = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		/* for each lookup type */
		while (appctx->ctx.map.expr) {
			/* initialise chunk to build new message */
			chunk_reset(&trash);

			/* execute pattern matching */
			sample.data.type = SMP_T_STR;
			sample.flags = SMP_F_CONST;
			sample.data.u.str.data = appctx->ctx.map.chunk.data;
			sample.data.u.str.area = appctx->ctx.map.chunk.area;

			if (appctx->ctx.map.expr->pat_head->match &&
			    sample_convert(&sample, appctx->ctx.map.expr->pat_head->expect_type))
				pat = appctx->ctx.map.expr->pat_head->match(&sample, appctx->ctx.map.expr, 1);
			else
				pat = NULL;

			/* build return message: set type of match */
			for (match_method=0; match_method<PAT_MATCH_NUM; match_method++)
				if (appctx->ctx.map.expr->pat_head->match == pat_match_fcts[match_method])
					break;
			if (match_method >= PAT_MATCH_NUM)
				chunk_appendf(&trash, "type=unknown(%p)", appctx->ctx.map.expr->pat_head->match);
			else
				chunk_appendf(&trash, "type=%s", pat_match_names[match_method]);

			/* case sensitive */
			if (appctx->ctx.map.expr->mflags & PAT_MF_IGNORE_CASE)
				chunk_appendf(&trash, ", case=insensitive");
			else
				chunk_appendf(&trash, ", case=sensitive");

			/* Display no match, and set default value */
			if (!pat) {
				if (appctx->ctx.map.display_flags == PAT_REF_MAP)
					chunk_appendf(&trash, ", found=no");
				else
					chunk_appendf(&trash, ", match=no");
			}

			/* Display match and match info */
			else {
				/* display match */
				if (appctx->ctx.map.display_flags == PAT_REF_MAP)
					chunk_appendf(&trash, ", found=yes");
				else
					chunk_appendf(&trash, ", match=yes");

				/* display index mode */
				if (pat->sflags & PAT_SF_TREE)
					chunk_appendf(&trash, ", idx=tree");
				else
					chunk_appendf(&trash, ", idx=list");

				/* display pattern */
				if (appctx->ctx.map.display_flags == PAT_REF_MAP) {
					if (pat->ref && pat->ref->pattern)
						chunk_appendf(&trash, ", key=\"%s\"", pat->ref->pattern);
					else
						chunk_appendf(&trash, ", key=unknown");
				}
				else {
					if (pat->ref && pat->ref->pattern)
						chunk_appendf(&trash, ", pattern=\"%s\"", pat->ref->pattern);
					else
						chunk_appendf(&trash, ", pattern=unknown");
				}

				/* display return value */
				if (appctx->ctx.map.display_flags == PAT_REF_MAP) {
					if (pat->data && pat->ref && pat->ref->sample)
						chunk_appendf(&trash, ", value=\"%s\", type=\"%s\"", pat->ref->sample,
						              smp_to_type[pat->data->type]);
					else
						chunk_appendf(&trash, ", value=none");
				}
			}

			chunk_appendf(&trash, "\n");

			/* display response */
			if (ci_putchk(si_ic(si), &trash) == -1) {
				/* let's try again later from this stream. We add ourselves into
				 * this stream's users so that it can remove us upon termination.
				 */
				HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
				si_rx_room_blk(si);
				return 0;
			}

			/* get next entry */
			appctx->ctx.map.expr = pat_expr_get_next(appctx->ctx.map.expr,
			                                         &appctx->ctx.map.ref->pat);
		}
		HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		/* fall through */

	default:
		appctx->st2 = STAT_ST_FIN;
		return 1;
	}
}

static void cli_release_mlook(struct appctx *appctx)
{
	free(appctx->ctx.map.chunk.area);
	appctx->ctx.map.chunk.area = NULL;
}


static int cli_parse_get_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (strcmp(args[1], "map") == 0 || strcmp(args[1], "acl") == 0) {
		/* Set flags. */
		if (args[1][0] == 'm')
			appctx->ctx.map.display_flags = PAT_REF_MAP;
		else
			appctx->ctx.map.display_flags = PAT_REF_ACL;

		/* No parameter. */
		if (!*args[2] || !*args[3]) {
			if (appctx->ctx.map.display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Missing map identifier and/or key.\n");
			else
				return cli_err(appctx, "Missing ACL identifier and/or key.\n");
		}

		/* lookup into the maps */
		appctx->ctx.map.ref = pat_ref_lookup_ref(args[2]);
		if (!appctx->ctx.map.ref) {
			if (appctx->ctx.map.display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}

		/* copy input string. The string must be allocated because
		 * it may be used over multiple iterations. It's released
		 * at the end and upon abort anyway.
		 */
		appctx->ctx.map.chunk.data = strlen(args[3]);
		appctx->ctx.map.chunk.size = appctx->ctx.map.chunk.data + 1;
		appctx->ctx.map.chunk.area = strdup(args[3]);
		if (!appctx->ctx.map.chunk.area)
			return cli_err(appctx,  "Out of memory error.\n");

		return 0;
	}
	return 1;
}

static void cli_release_show_map(struct appctx *appctx)
{
	if (appctx->st2 == STAT_ST_LIST) {
		HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		if (!LIST_ISEMPTY(&appctx->ctx.map.bref.users))
			LIST_DEL(&appctx->ctx.map.bref.users);
		HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
	}
}

static int cli_parse_show_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (strcmp(args[1], "map") == 0 ||
	    strcmp(args[1], "acl") == 0) {

		/* Set ACL or MAP flags. */
		if (args[1][0] == 'm')
			appctx->ctx.map.display_flags = PAT_REF_MAP;
		else
			appctx->ctx.map.display_flags = PAT_REF_ACL;

		/* no parameter: display all map available */
		if (!*args[2]) {
			appctx->io_handler = cli_io_handler_pats_list;
			return 0;
		}

		/* lookup into the refs and check the map flag */
		appctx->ctx.map.ref = pat_ref_lookup_ref(args[2]);
		if (!appctx->ctx.map.ref ||
		    !(appctx->ctx.map.ref->flags & appctx->ctx.map.display_flags)) {
			if (appctx->ctx.map.display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}
		appctx->io_handler = cli_io_handler_pat_list;
		appctx->io_release = cli_release_show_map;
		return 0;
	}

	return 0;
}

static int cli_parse_set_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (strcmp(args[1], "map") == 0) {
		char *err;

		/* Set flags. */
		appctx->ctx.map.display_flags = PAT_REF_MAP;

		/* Expect three parameters: map name, key and new value. */
		if (!*args[2] || !*args[3] || !*args[4])
			return cli_err(appctx, "'set map' expects three parameters: map identifier, key and value.\n");

		/* Lookup the reference in the maps. */
		appctx->ctx.map.ref = pat_ref_lookup_ref(args[2]);
		if (!appctx->ctx.map.ref)
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
			HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
			if (!pat_ref_set_by_id(appctx->ctx.map.ref, ref, args[4], &err)) {
				HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
				if (err)
					return cli_dynerr(appctx, memprintf(&err, "%s.\n", err));
				else
					return cli_err(appctx, "Failed to update an entry.\n");
			}
			HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		}
		else {
			/* Else, use the entry identifier as pattern
			 * string, and update the value.
			 */
			err = NULL;
			HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
			if (!pat_ref_set(appctx->ctx.map.ref, args[3], args[4], &err)) {
				HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
				if (err)
					return cli_dynerr(appctx, memprintf(&err, "%s.\n", err));
				else
					return cli_err(appctx, "Failed to update an entry.\n");
			}
			HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		}

		/* The set is done, send message. */
		appctx->st0 = CLI_ST_PROMPT;
		return 0;
	}
	return 1;
}

static int map_add_key_value(struct appctx *appctx, const char *key, const char *value, char **err)
{
	int ret;

	HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
	if (appctx->ctx.map.display_flags == PAT_REF_MAP)
		ret = pat_ref_add(appctx->ctx.map.ref, key, value, err);
	else
		ret = pat_ref_add(appctx->ctx.map.ref, key, NULL, err);
	HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);

	return ret;
}

static int cli_parse_add_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (strcmp(args[1], "map") == 0 ||
	    strcmp(args[1], "acl") == 0) {
		int ret;
		char *err;

		/* Set flags. */
		if (args[1][0] == 'm')
			appctx->ctx.map.display_flags = PAT_REF_MAP;
		else
			appctx->ctx.map.display_flags = PAT_REF_ACL;

		/* If the keyword is "map", we expect:
		 *   - three parameters if there is no payload
		 *   - one parameter if there is a payload
		 * If it is "acl", we expect only two parameters
		 */
		if (appctx->ctx.map.display_flags == PAT_REF_MAP) {
			if ((!payload && (!*args[2] || !*args[3] || !*args[4])) ||
			    (payload && !*args[2]))
				return cli_err(appctx,
					       "'add map' expects three parameters (map identifier, key and value)"
					       " or one parameter (map identifier) and a payload\n");
		}
		else if (!*args[2] || !*args[3])
			return cli_err(appctx, "'add acl' expects two parameters: ACL identifier and pattern.\n");

		/* Lookup for the reference. */
		appctx->ctx.map.ref = pat_ref_lookup_ref(args[2]);
		if (!appctx->ctx.map.ref) {
			if (appctx->ctx.map.display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}

		/* The command "add acl" is prohibited if the reference
		 * use samples.
		 */
		if ((appctx->ctx.map.display_flags & PAT_REF_ACL) &&
		    (appctx->ctx.map.ref->flags & PAT_REF_SMP)) {
			return cli_err(appctx,
				       "This ACL is shared with a map containing samples. "
				       "You must use the command 'add map' to add values.\n");
		}
		/* Add value(s). */
		err = NULL;
		if (!payload) {
			ret = map_add_key_value(appctx, args[3], args[4], &err);
			if (!ret) {
				if (err)
					return cli_dynerr(appctx, memprintf(&err, "%s.\n", err));
				else
					return cli_err(appctx, "Failed to add an entry.\n");
			}
		}
		else {
			const char *end = payload + strlen(payload);

			while (payload < end) {
				char *key, *value;
				size_t l;

				/* key */
				key = payload;
				l = strcspn(key, " \t");
				payload += l;

				if (!*payload && appctx->ctx.map.display_flags == PAT_REF_MAP)
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

				ret = map_add_key_value(appctx, key, value, &err);
				if (!ret) {
					if (err)
						return cli_dynerr(appctx, memprintf(&err, "%s.\n", err));
					else
						return cli_err(appctx, "Failed to add a key.\n");
				}
			}
		}

		/* The add is done, send message. */
		appctx->st0 = CLI_ST_PROMPT;
		return 1;
	}

	return 0;
}

static int cli_parse_del_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (args[1][0] == 'm')
		appctx->ctx.map.display_flags = PAT_REF_MAP;
	else
		appctx->ctx.map.display_flags = PAT_REF_ACL;

	/* Expect two parameters: map name and key. */
	if (!*args[2] || !*args[3]) {
		if (appctx->ctx.map.display_flags == PAT_REF_MAP)
			return cli_err(appctx, "This command expects two parameters: map identifier and key.\n");
		else
			return cli_err(appctx, "This command expects two parameters: ACL identifier and key.\n");
	}

	/* Lookup the reference in the maps. */
	appctx->ctx.map.ref = pat_ref_lookup_ref(args[2]);
	if (!appctx->ctx.map.ref ||
	    !(appctx->ctx.map.ref->flags & appctx->ctx.map.display_flags))
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
		HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		if (!pat_ref_delete_by_id(appctx->ctx.map.ref, ref)) {
			HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
			/* The entry is not found, send message. */
			return cli_err(appctx, "Key not found.\n");
		}
		HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
	}
	else {
		/* Else, use the entry identifier as pattern
		 * string and try to delete the entry.
		 */
		HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		if (!pat_ref_delete(appctx->ctx.map.ref, args[3])) {
			HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
			/* The entry is not found, send message. */
			return cli_err(appctx, "Key not found.\n");
		}
		HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
	}

	/* The deletion is done, send message. */
	appctx->st0 = CLI_ST_PROMPT;
	return 1;
}


static int cli_parse_clear_map(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (strcmp(args[1], "map") == 0 || strcmp(args[1], "acl") == 0) {
		/* Set ACL or MAP flags. */
		if (args[1][0] == 'm')
			appctx->ctx.map.display_flags = PAT_REF_MAP;
		else
			appctx->ctx.map.display_flags = PAT_REF_ACL;

		/* no parameter */
		if (!*args[2]) {
			if (appctx->ctx.map.display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Missing map identifier.\n");
			else
				return cli_err(appctx, "Missing ACL identifier.\n");
		}

		/* lookup into the refs and check the map flag */
		appctx->ctx.map.ref = pat_ref_lookup_ref(args[2]);
		if (!appctx->ctx.map.ref ||
		    !(appctx->ctx.map.ref->flags & appctx->ctx.map.display_flags)) {
			if (appctx->ctx.map.display_flags == PAT_REF_MAP)
				return cli_err(appctx, "Unknown map identifier. Please use #<id> or <file>.\n");
			else
				return cli_err(appctx, "Unknown ACL identifier. Please use #<id> or <file>.\n");
		}

		/* Clear all. */
		HA_SPIN_LOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);
		pat_ref_prune(appctx->ctx.map.ref);
		HA_SPIN_UNLOCK(PATREF_LOCK, &appctx->ctx.map.ref->lock);

		/* return response */
		appctx->st0 = CLI_ST_PROMPT;
		return 1;
	}
	return 0;
}

/* register cli keywords */

static struct cli_kw_list cli_kws = {{ },{
	{ { "add",   "acl", NULL }, "add acl        : add acl entry", cli_parse_add_map, NULL },
	{ { "clear", "acl", NULL }, "clear acl <id> : clear the content of this acl", cli_parse_clear_map, NULL },
	{ { "del",   "acl", NULL }, "del acl        : delete acl entry", cli_parse_del_map, NULL },
	{ { "get",   "acl", NULL }, "get acl        : report the patterns matching a sample for an ACL", cli_parse_get_map, cli_io_handler_map_lookup, cli_release_mlook },
	{ { "show",  "acl", NULL }, "show acl [id]  : report available acls or dump an acl's contents", cli_parse_show_map, NULL },
	{ { "add",   "map", NULL }, "add map        : add map entry", cli_parse_add_map, NULL },
	{ { "clear", "map", NULL }, "clear map <id> : clear the content of this map", cli_parse_clear_map, NULL },
	{ { "del",   "map", NULL }, "del map        : delete map entry", cli_parse_del_map, NULL },
	{ { "get",   "map", NULL }, "get map        : report the keys and values matching a sample for a map", cli_parse_get_map, cli_io_handler_map_lookup, cli_release_mlook },
	{ { "set",   "map", NULL }, "set map        : modify map entry", cli_parse_set_map, NULL },
	{ { "show",  "map", NULL }, "show map [id]  : report available maps or dump a map's contents", cli_parse_show_map, NULL },
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

	{ /* END */ },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);
