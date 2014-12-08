/*
 * Functions used to parse typed argument lists
 *
 * Copyright 2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <common/standard.h>
#include <proto/arg.h>

const char *arg_type_names[ARGT_NBTYPES] = {
	[ARGT_STOP] = "end of arguments",
	[ARGT_UINT] = "unsigned integer",
	[ARGT_SINT] = "signed integer",
	[ARGT_STR]  = "string",
	[ARGT_IPV4] = "IPv4 address",
	[ARGT_MSK4] = "IPv4 mask",
	[ARGT_IPV6] = "IPv6 address",
	[ARGT_MSK6] = "IPv6 mask",
	[ARGT_TIME] = "delay",
	[ARGT_SIZE] = "size",
	[ARGT_FE]   = "frontend",
	[ARGT_BE]   = "backend",
	[ARGT_TAB]  = "table",
	[ARGT_SRV]  = "server",
	[ARGT_USR]  = "user list",
	[ARGT_MAP]  = "map",
	[ARGT_REG]  = "regex",
	/* Unassigned types must never happen. Better crash during parsing if they do. */
};

/* This dummy arg list may be used by default when no arg is found, it helps
 * parsers by removing pointer checks.
 */
struct arg empty_arg_list[ARGM_NBARGS] = { };

/* This function clones a struct arg_list template into a new one which is
 * returned.
 */
struct arg_list *arg_list_clone(const struct arg_list *orig)
{
	struct arg_list *new;

	if ((new = calloc(1, sizeof(*new))) != NULL) {
		/* ->list will be set by the caller when inserting the element.
		 * ->arg and ->arg_pos will be set by the caller.
		 */
		new->ctx = orig->ctx;
		new->kw = orig->kw;
		new->conv = orig->conv;
		new->file = orig->file;
		new->line = orig->line;
	}
	return new;
}

/* This function clones a struct <arg_list> template into a new one which is
 * set to point to arg <arg> at pos <pos>, and which is returned if the caller
 * wants to apply further changes.
 */
struct arg_list *arg_list_add(struct arg_list *orig, struct arg *arg, int pos)
{
	struct arg_list *new;

	new = arg_list_clone(orig);
	new->arg = arg;
	new->arg_pos = pos;
	LIST_ADDQ(&orig->list, &new->list);
	return new;
}

/* This function builds an argument list from a config line. It returns the
 * number of arguments found, or <0 in case of any error. Everything needed
 * it automatically allocated. A pointer to an error message might be returned
 * in err_msg if not NULL, in which case it would be allocated and the caller
 * will have to check it and free it. The output arg list is returned in argp
 * which must be valid. The returned array is always terminated by an arg of
 * type ARGT_STOP (0), unless the mask indicates that no argument is supported.
 * Unresolved arguments are appended to arg list <al>, which also serves as a
 * template to create new entries. The mask is composed of a number of
 * mandatory arguments in its lower ARGM_BITS bits, and a concatenation of each
 * argument type in each subsequent ARGT_BITS-bit sblock. If <err_msg> is not
 * NULL, it must point to a freeable or NULL pointer.
 */
int make_arg_list(const char *in, int len, unsigned int mask, struct arg **argp,
                  char **err_msg, const char **err_ptr, int *err_arg,
                  struct arg_list *al)
{
	int nbarg;
	int pos;
	struct arg *arg;
	const char *beg;
	char *word = NULL;
	const char *ptr_err = NULL;
	int min_arg;

	*argp = NULL;

	min_arg = mask & ARGM_MASK;
	mask >>= ARGM_BITS;

	pos = 0;
	/* find between 0 and NBARGS the max number of args supported by the mask */
	for (nbarg = 0; nbarg < ARGM_NBARGS && ((mask >> (nbarg * ARGT_BITS)) & ARGT_MASK); nbarg++);

	if (!nbarg)
		goto end_parse;

	/* Note: an empty input string contains an empty argument if this argument
	 * is marked mandatory. Otherwise we can ignore it.
	 */
	if (!len && !min_arg)
		goto end_parse;

	arg = *argp = calloc(nbarg + 1, sizeof(*arg));

	/* Note: empty arguments after a comma always exist. */
	while (pos < nbarg) {
		beg = in;
		while (len && *in != ',') {
			in++;
			len--;
		}

		/* we have a new argument between <beg> and <in> (not included).
		 * For ease of handling, we copy it into a zero-terminated word.
		 * By default, the output argument will be the same type of the
		 * expected one.
		 */
		free(word);
		word = my_strndup(beg, in - beg);

		arg->type = (mask >> (pos * ARGT_BITS)) & ARGT_MASK;

		switch (arg->type) {
		case ARGT_SINT:
			if (in == beg)	  // empty number
				goto empty_err;
			else if (*beg < '0' || *beg > '9') {
				beg++;
				arg->data.sint = read_uint(&beg, in);
				if (beg < in)
					goto parse_err;
				if (*word == '-')
					arg->data.sint = -arg->data.sint;
				else if (*word != '+')    // invalid first character
					goto parse_err;
				break;
			}

			arg->type = ARGT_UINT;
			/* fall through ARGT_UINT if no sign is present */

		case ARGT_UINT:
			if (in == beg)    // empty number
				goto empty_err;

			arg->data.uint = read_uint(&beg, in);
			if (beg < in)
				goto parse_err;
			break;

		case ARGT_FE:
		case ARGT_BE:
		case ARGT_TAB:
		case ARGT_SRV:
		case ARGT_USR:
		case ARGT_REG:
			/* These argument types need to be stored as strings during
			 * parsing then resolved later.
			 */
			arg->unresolved = 1;
			arg_list_add(al, arg, pos);

			/* fall through */
		case ARGT_STR:
			/* all types that must be resolved are stored as strings
			 * during the parsing. The caller must at one point resolve
			 * them and free the string.
			 */
			arg->data.str.str = word;
			arg->data.str.len = in - beg;
			arg->data.str.size = arg->data.str.len + 1;
			word = NULL;
			break;

		case ARGT_IPV4:
			if (in == beg)    // empty address
				goto empty_err;

			if (inet_pton(AF_INET, word, &arg->data.ipv4) <= 0)
				goto parse_err;
			break;

		case ARGT_MSK4:
			if (in == beg)    // empty mask
				goto empty_err;

			if (!str2mask(word, &arg->data.ipv4))
				goto parse_err;

			arg->type = ARGT_IPV4;
			break;

		case ARGT_IPV6:
			if (in == beg)    // empty address
				goto empty_err;

			if (inet_pton(AF_INET6, word, &arg->data.ipv6) <= 0)
				goto parse_err;
			break;

		case ARGT_MSK6: /* not yet implemented */
			goto not_impl;

		case ARGT_TIME:
			if (in == beg)    // empty time
				goto empty_err;

			ptr_err = parse_time_err(word, &arg->data.uint, TIME_UNIT_MS);
			if (ptr_err)
				goto parse_err;

			arg->type = ARGT_UINT;
			break;

		case ARGT_SIZE:
			if (in == beg)    // empty size
				goto empty_err;

			ptr_err = parse_size_err(word, &arg->data.uint);
			if (ptr_err)
				goto parse_err;

			arg->type = ARGT_UINT;
			break;

			/* FIXME: other types need to be implemented here */
		default:
			goto not_impl;
		}

		pos++;
		arg++;

		/* don't go back to parsing if we reached end */
		if (!len || pos >= nbarg)
			break;

		/* skip comma */
		in++; len--;
	}

 end_parse:
	free(word); word = NULL;

	if (pos < min_arg) {
		/* not enough arguments */
		memprintf(err_msg,
		          "missing arguments (got %d/%d), type '%s' expected",
		          pos, min_arg, arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK]);
		goto err;
	}

	if (len) {
		/* too many arguments, starting at <in> */
		/* the caller is responsible for freeing this message */
		word = my_strndup(in, len);
		if (nbarg)
			memprintf(err_msg, "end of arguments expected at position %d, but got '%s'",
			          pos + 1, word);
		else
			memprintf(err_msg, "no argument supported, but got '%s'", word);
		free(word); word = NULL;
		goto err;
	}

	/* note that pos might be < nbarg and this is not an error, it's up to the
	 * caller to decide what to do with optional args.
	 */
	if (err_arg)
		*err_arg = pos;
	if (err_ptr)
		*err_ptr = in;
	return pos;

 err:
	free(word);
	free(*argp);
	*argp = NULL;
	if (err_arg)
		*err_arg = pos;
	if (err_ptr)
		*err_ptr = in;
	return -1;

 empty_err:
	memprintf(err_msg, "expected type '%s' at position %d, but got nothing",
	          arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK], pos + 1);
	goto err;

 parse_err:
	memprintf(err_msg, "failed to parse '%s' as type '%s' at position %d",
	          word, arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK], pos + 1);
	goto err;

 not_impl:
	memprintf(err_msg, "parsing for type '%s' was not implemented, please report this bug",
	          arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK]);
	goto err;
}
