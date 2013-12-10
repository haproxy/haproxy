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

#include <proto/arg.h>
#include <proto/map.h>
#include <proto/pattern.h>
#include <proto/sample.h>

struct list maps = LIST_HEAD_INIT(maps); /* list of struct map_reference */

/* This function return existing map reference or return NULL. */
struct map_reference *map_get_reference(const char *reference)
{
	struct map_reference *ref;

	/* process the lookup */
	list_for_each_entry(ref, &maps, list)
		if (strcmp(ref->reference, reference) == 0)
			return ref;
	return NULL;
}

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
 * The output type is CSTR.
 */
int map_parse_str(const char *text, struct sample_storage *smp)
{
	/* The loose of the "const" is balanced by the SMP_T_CSTR type */
	smp->data.str.str = (char *)text;
	smp->data.str.len = strlen(text);
	smp->data.str.size = smp->data.str.len + 1;
	smp->type = SMP_T_CSTR;
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

/* This function creates and initializes a new map_reference entry. This
 * function only fails in case of a memory allocation issue, in which case
 * it returns NULL. <reference> here is a unique identifier for the map's
 * contents, typically the name of the file used to build the map.
 */
static struct map_reference *map_create_reference(const char *reference)
{
	struct map_reference *ref;

	/* create new entry */
	ref = calloc(1, sizeof(*ref));
	if (!ref)
		return NULL;

	ref->reference = strdup(reference);
	if (!ref->reference)
		return NULL;

	LIST_INIT(&ref->entries);
	LIST_INIT(&ref->maps);
	LIST_ADDQ(&maps, &ref->list);

	return ref;
}

/* This function just create new entry */
static struct map_entry *map_create_entry(int line, char *key, char *value)
{
	struct map_entry *ent;

	ent = calloc(1, sizeof(*ent));
	if (!ent)
		return NULL;

	ent->line = line;

	ent->key = strdup(key);
	if (!ent->key) {
		free(ent);
		return NULL;
	}

	ent->value = strdup(value);
	if (!ent->value) {
		free(ent->key);
		free(ent);
		return NULL;
	}

	return ent;
}

/* This crete and initialize map descriptor.
 * Return NULL if out of memory error
 */
static struct map_descriptor *map_create_descriptor(struct map_reference *ref,
                                                    struct sample_conv *conv)
{
	struct map_descriptor *desc;

	desc = calloc(1, sizeof(*desc));
	if (!desc)
		return NULL;

	desc->conv = conv;
	desc->ref = ref;

	LIST_ADDQ(&ref->maps, &desc->list);

	return desc;
}

/* This function just add entry into the list of pattern.
 * It can return false only in memory problem case
 */
static int map_add_entry(struct map_reference *map, int line, char *key, char *value)
{
	struct map_entry *ent;

	ent = map_create_entry(line, key, value);
	if (!ent)
		return 0;
	LIST_ADDQ(&map->entries, &ent->list);
	return 1;
}

/* Reads patterns from a file. If <err_msg> is non-NULL, an error message will
 * be returned there on errors and the caller will have to free it.
 *
 * The file contains one key + value per line. Lines which start with '#' are
 * ignored, just like empty lines. Leading tabs/spaces are stripped. The key is
 * then the first "word" (series of non-space/tabs characters), and the value is
 * what follows this series of space/tab till the end of the line excluding
 * trailing spaces/tabs.
 *
 * Example :
 *
 *     # this is a comment and is ignored
 *        62.212.114.60     1wt.eu      \n
 *     <-><-----------><---><----><---->
 *      |       |        |     |     `--- trailing spaces ignored
 *      |       |        |      `-------- value
 *      |       |        `--------------- middle spaces ignored
 *      |       `------------------------ key
 *      `-------------------------------- leading spaces ignored
 *
 * Return non-zero in case of succes, otherwise 0.
 */
static int map_read_entries_from_file(const char *filename,
                                      struct map_reference *ref,
                                      char **err)
{
	FILE *file;
	char *c;
	int ret = 0;
	int line = 0;
	char *key_beg;
	char *key_end;
	char *value_beg;
	char *value_end;

	file = fopen(filename, "r");
	if (!file) {
		memprintf(err, "failed to open pattern file <%s>", filename);
		return 0;
	}

	/* now parse all patterns. The file may contain only one pattern
	 * followed by one value per line. The start spaces, separator spaces
	 * and and spaces are stripped. Each can contain comment started by '#'
	 */
	while (fgets(trash.str, trash.size, file) != NULL) {
		line++;
		c = trash.str;

		/* ignore lines beginning with a dash */
		if (*c == '#')
			continue;

		/* strip leading spaces and tabs */
		while (*c == ' ' || *c == '\t')
			c++;

		/* empty lines are ignored too */
		if (*c == '\0')
			continue;

		/* look for the end of the key */
		key_beg = c;
		while (*c && *c != ' ' && *c != '\t' && *c != '\n' && *c != '\r')
			c++;

		key_end = c;

		/* strip middle spaces and tabs */
		while (*c == ' ' || *c == '\t')
			c++;

		/* look for the end of the value, it is the end of the line */
		value_beg = c;
		while (*c && *c != '\n' && *c != '\r')
			c++;
		value_end = c;

		/* trim possibly trailing spaces and tabs */
		while (value_end > value_beg && (value_end[-1] == ' ' || value_end[-1] == '\t'))
			value_end--;

		/* set final \0 and check entries */
		*key_end = '\0';
		*value_end = '\0';

		/* insert values */
		if (!map_add_entry(ref, line, key_beg, value_beg)) {
			memprintf(err, "out of memory");
			goto out_close;
		}
	}

	/* succes */
	ret = 1;

 out_close:
	fclose(file);
	return ret;
}

/* This function read the string entries of <ent>, parse it with
 * the <desc> methods, and strore the result into <desc> dummy ACL.
 * return 1 in succes case, else return 0 and <err> is filled.
 *
 * The acm parser use <pattern> for creating new pattern (list
 * of values case) or using the same pattern (tree index case).
 *
 * <patflags> must be PAT_F_*.
 */
static int map_parse_and_index(struct map_descriptor *desc,
                               struct pattern **pattern,
                               struct map_entry *ent,
                               int patflags,
                               char **err)
{
	struct sample_storage *smp;
	const char *args[2];

	/* use new smp for storing value */
	smp = calloc(1, sizeof(*smp));
	if (!smp)
		return 0;

	/* first read and convert value */
	if (!desc->parse(ent->value, smp)) {
		memprintf(err, "parse value failed at line %d of file <%s>",
		          ent->line, desc->ref->reference);
		return 0;
	}

	/* register key */
	args[0] = ent->key;
	args[1] = "";
	if (!pattern_register(desc->pat, args, smp, pattern, patflags, err))
		return 0;

	return 1;
}

/* This function load the map file according with data type declared into
 * the "struct sample_conv".
 *
 * This function choose the indexation type (ebtree or list) according with
 * the type of match needed.
 */
static int sample_load_map(struct arg *arg, struct sample_conv *conv, char **err)
{
	struct map_reference *ref;
	struct map_descriptor *desc;
	struct pattern *pattern;
	struct map_entry *ent;
	struct pattern_expr *pat = NULL;

	/* look for existing map reference. The reference is the
	 * file encountered in the first argument. arg[0] with string
	 * type is guaranteed by the parser.
	 */
	ref = map_get_reference(arg[0].data.str.str);

	/* The reference doesn't exist */
	if (!ref) {

		/* create new reference entry */
		ref = map_create_reference(arg[0].data.str.str);
		if (!ref) {
			memprintf(err, "out of memory");
			return 0;
		}

		/* load the file */
		if (!map_read_entries_from_file(arg[0].data.str.str, ref, err))
			return 0;
	}

	/* look for identical existing map. Two maps are identical if
	 * their in_type and out_type are the same. If is not found, pat
	 * is NULL.
	 */
	else {
		list_for_each_entry(desc, &ref->maps, list)
			if (desc->conv->in_type == conv->in_type &&
			    desc->conv->out_type == conv->out_type &&
			    desc->conv->private == conv->private)
				break;
		if (&desc->list !=  &ref->maps)
			pat = desc->pat;
	}

	/* create new map descriptor */
	desc = map_create_descriptor(ref, conv);
	if (!desc) {
		memprintf(err, "out of memory");
		return 0;
	}

	/* check the output parse method */
	switch (desc->conv->out_type) {
	case SMP_T_STR:  desc->parse = map_parse_str;  break;
	case SMP_T_UINT: desc->parse = map_parse_int;  break;
	case SMP_T_IPV4: desc->parse = map_parse_ip;   break;
	case SMP_T_IPV6: desc->parse = map_parse_ip6;  break;
	default:
		memprintf(err, "map: internal haproxy error: no default parse case for the input type <%d>.",
		          conv->out_type);
		return 0;
	}

	/* If identical pattern is not found, initialize his own pattern */
	if (!pat) {

		desc->pat = calloc(1, sizeof(*desc->pat));
		if (!desc->pat) {
			memprintf(err, "out of memory");
			return 0;
		}

		pattern_init_expr(desc->pat);

		/* This is original pattern, must free */
		desc->do_free = 1;

		/* set the match method */
		desc->pat->match = pat_match_fcts[conv->private];
		desc->pat->parse = pat_parse_fcts[conv->private];

		/* parse each line of the file */
		pattern = NULL;
		list_for_each_entry(ent, &ref->entries, list)
			if (!map_parse_and_index(desc, &pattern, ent, 0, err))
				return 0;
	}

	/* identical pattern found. Use reference to this pattern, and mark
	 * the map_descriptor pattern as non freeable
	 */
	else {
		desc->pat = pat;
		desc->do_free = 0;
	}

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
		if (!desc->parse(desc->default_value, desc->def)) {
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
	struct sample_storage *sample;
	enum pat_match_res ret;

	/* get config */
	desc = arg_p[0].data.map;

	/* Execute the match function. */
	ret = pattern_exec_match(desc->pat, smp, &sample, NULL, NULL);
	if (ret != PAT_MATCH) {
		if (!desc->def)
			return 0;
		sample = desc->def;
	}

	/* copy new data */
	smp->type = sample->type;
	memcpy(&smp->data, &sample->data, sizeof(smp->data));
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
