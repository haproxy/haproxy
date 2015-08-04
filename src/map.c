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

#include <common/standard.h>

#include <types/global.h>
#include <types/map.h>
#include <types/pattern.h>

#include <proto/arg.h>
#include <proto/map.h>
#include <proto/pattern.h>
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
	data->u.str.str = (char *)text;
	data->u.str.len = strlen(text);
	data->u.str.size = data->u.str.len + 1;
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
		return 0;
	}

	/* Load map. */
	if (!pattern_read_from_file(&desc->pat, PAT_REF_MAP, arg[0].data.str.str, PAT_MF_NO_DNS,
	                            1, err, file, line))
		return 0;

	/* the maps of type IP have a string as defaultvalue. This
	 * string canbe anipv4 or an ipv6, we must convert it.
	 */
	if (desc->conv->out_type == SMP_T_ADDR) {
		struct sample_data data;
		if (!map_parse_ip(arg[1].data.str.str, &data)) {
			memprintf(err, "map: cannot parse default ip <%s>.", arg[1].data.str.str);
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

	/* get config */
	desc = arg_p[0].data.map;

	/* Execute the match function. */
	pat = pattern_exec_match(&desc->pat, smp, 1);

	/* Match case. */
	if (pat) {
		/* Copy sample. */
		if (pat->data) {
			smp->data = *pat->data;
			smp->flags |= SMP_F_CONST;
			return 1;
		}

		/* Return just int sample containing 1. */
		smp->data.type = SMP_T_SINT;
		smp->data.u.sint = 1;
		return 1;
	}

	/* If no default value avalaible, the converter fails. */
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

__attribute__((constructor))
static void __map_init(void)
{
	/* register format conversion keywords */
	sample_register_convs(&sample_conv_kws);
}
