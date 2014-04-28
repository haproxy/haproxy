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

/* Parse an IPv4 address and store it into the sample.
 * The output type is IPV4.
 */
int map_parse_ip(const char *text, struct sample_storage *smp)
{
	if (!buf2ip(text, strlen(text), &smp->data.ipv4))
		return 0;
	smp->type = SMP_T_IPV4;
	return 1;
}

/* Parse an IPv6 address and store it into the sample.
 * The output type is IPV6.
 */
int map_parse_ip6(const char *text, struct sample_storage *smp)
{
	if (!buf2ip6(text, strlen(text), &smp->data.ipv6))
		return 0;
	smp->type = SMP_T_IPV6;
	return 1;
}

/* Parse a string and store a pointer to it into the sample. The original
 * string must be left in memory because we return a direct memory reference.
 * The output type is SMP_T_STR. There is no risk that the data will be
 * overwritten because sample_conv_map() makes a const sample with this
 * output.
 */
int map_parse_str(const char *text, struct sample_storage *smp)
{
	smp->data.str.str = (char *)text;
	smp->data.str.len = strlen(text);
	smp->data.str.size = smp->data.str.len + 1;
	smp->type = SMP_T_STR;
	return 1;
}

/* Parse an integer and convert it to a sample. The output type is SINT if the
 * number is negative, or UINT if it is positive or null. The function returns
 * zero (error) if the number is too large.
 */
int map_parse_int(const char *text, struct sample_storage *smp)
{
	long long int value;
	char *error;

	/* parse interger and convert it. Return the value in 64 format. */
	value = strtoll(text, &error, 10);
	if (*error != '\0')
		return 0;

	/* check sign iand limits */
	if (value < 0) {
		if (value < INT_MIN)
			return 0;
		smp->type = SMP_T_SINT;
		smp->data.sint = value;
	}
	else {
		if (value > UINT_MAX)
			return 0;
		smp->type = SMP_T_UINT;
		smp->data.uint = value;
	}

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
static int sample_load_map(struct arg *arg, struct sample_conv *conv,
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
	desc->pat.match = pat_match_fcts[conv->private];
	desc->pat.parse = pat_parse_fcts[conv->private];
	desc->pat.index = pat_index_fcts[conv->private];
	desc->pat.delete = pat_delete_fcts[conv->private];
	desc->pat.prune = pat_prune_fcts[conv->private];
	desc->pat.expect_type = pat_match_types[conv->private];

	/* Set the output parse method. */
	switch (desc->conv->out_type) {
	case SMP_T_STR:  desc->pat.parse_smp = map_parse_str;  break;
	case SMP_T_UINT: desc->pat.parse_smp = map_parse_int;  break;
	case SMP_T_IPV4: desc->pat.parse_smp = map_parse_ip;   break;
	case SMP_T_IPV6: desc->pat.parse_smp = map_parse_ip6;  break;
	default:
		memprintf(err, "map: internal haproxy error: no default parse case for the input type <%d>.",
		          conv->out_type);
		return 0;
	}

	/* Load map. */
	if (!pattern_read_from_file(&desc->pat, PAT_REF_MAP, arg[0].data.str.str, PAT_MF_NO_DNS,
	                            1, err, file, line))
		return 0;

	/* The second argument is the default value */
	if (arg[1].type == ARGT_STR) {
		desc->default_value = strdup(arg[1].data.str.str);
		if (!desc->default_value) {
			memprintf(err, "out of memory");
			return 0;
		}
		desc->def = calloc(1, sizeof(*desc->def));
		if (!desc->def) {
			memprintf(err, "out of memory");
			return 0;
		}
		if (!desc->pat.parse_smp(desc->default_value, desc->def)) {
			memprintf(err, "Cannot parse default value");
			return 0;
		}
	}
	else
		desc->def = NULL;

	/* replace the first argument by this definition */
	arg[0].type = ARGT_MAP;
	arg[0].data.map = desc;

	return 1;
}

static int sample_conv_map(const struct arg *arg_p, struct sample *smp)
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
		if (pat->smp) {
			smp->type = pat->smp->type;
			smp->flags |= SMP_F_CONST;
			memcpy(&smp->data, &pat->smp->data, sizeof(smp->data));
			return 1;
		}

		/* Return just int sample containing 1. */
		smp->type = SMP_T_UINT;
		smp->data.uint= 1;
		return 1;
	}

	/* If no default value avalaible, the converter fails. */
	if (!desc->def)
		return 0;

	/* Return the default value. */
	smp->type = desc->def->type;
	smp->flags |= SMP_F_CONST;
	memcpy(&smp->data, &desc->def->data, sizeof(smp->data));
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
	{ "map",         sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  PAT_MATCH_STR },
	{ "map_str",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  PAT_MATCH_STR },
	{ "map_beg",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  PAT_MATCH_BEG },
	{ "map_sub",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  PAT_MATCH_SUB },
	{ "map_dir",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  PAT_MATCH_DIR },
	{ "map_dom",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  PAT_MATCH_DOM },
	{ "map_end",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  PAT_MATCH_END },
	{ "map_reg",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_STR,  PAT_MATCH_REG },
	{ "map_int",     sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_UINT, SMP_T_STR,  PAT_MATCH_INT },
	{ "map_ip",      sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_ADDR, SMP_T_STR,  PAT_MATCH_IP  },

	{ "map_str_int", sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_UINT, PAT_MATCH_STR },
	{ "map_beg_int", sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_UINT, PAT_MATCH_BEG },
	{ "map_sub_int", sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_UINT, PAT_MATCH_SUB },
	{ "map_dir_int", sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_UINT, PAT_MATCH_DIR },
	{ "map_dom_int", sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_UINT, PAT_MATCH_DOM },
	{ "map_end_int", sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_UINT, PAT_MATCH_END },
	{ "map_reg_int", sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_UINT, PAT_MATCH_REG },
	{ "map_int_int", sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_UINT, SMP_T_UINT, PAT_MATCH_INT },
	{ "map_ip_int",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_ADDR, SMP_T_UINT, PAT_MATCH_IP  },

	{ "map_str_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_IPV4, PAT_MATCH_STR },
	{ "map_beg_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_IPV4, PAT_MATCH_BEG },
	{ "map_sub_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_IPV4, PAT_MATCH_SUB },
	{ "map_dir_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_IPV4, PAT_MATCH_DIR },
	{ "map_dom_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_IPV4, PAT_MATCH_DOM },
	{ "map_end_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_IPV4, PAT_MATCH_END },
	{ "map_reg_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR,  SMP_T_IPV4, PAT_MATCH_REG },
	{ "map_int_ip",  sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_UINT, SMP_T_IPV4, PAT_MATCH_INT },
	{ "map_ip_ip",   sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_ADDR, SMP_T_IPV4, PAT_MATCH_IP  },

	{ /* END */ },
}};

__attribute__((constructor))
static void __map_init(void)
{
	/* register format conversion keywords */
	sample_register_convs(&sample_conv_kws);
}
