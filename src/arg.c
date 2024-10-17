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

#include <haproxy/arg.h>
#include <haproxy/chunk.h>
#include <haproxy/global.h>
#include <haproxy/regex.h>
#include <haproxy/tools.h>

const char *arg_type_names[ARGT_NBTYPES] = {
	[ARGT_STOP] = "end of arguments",
	[ARGT_SINT] = "integer",
	[ARGT_STR]  = "string",
	[ARGT_ID]   = "identifier",
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
	[ARGT_VAR]  = "variable",
	[ARGT_PBUF_FNUM] = "Protocol buffers field number",
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
	if (new) {
		new->arg = arg;
		new->arg_pos = pos;
		LIST_APPEND(&orig->list, &new->list);
	}
	return new;
}

/* This function builds an argument list from a config line, and stops at the
 * first non-matching character, which is pointed to in <end_ptr>. A valid arg
 * list starts with an opening parenthesis '(', contains a number of comma-
 * delimited words, and ends with the closing parenthesis ')'. An empty list
 * (with or without the parenthesis) will lead to a valid empty argument if the
 * keyword has a mandatory one. The function returns the number of arguments
 * emitted, or <0 in case of any error. Everything needed it automatically
 * allocated. A pointer to an error message might be returned in err_msg if not
 * NULL, in which case it would be allocated and the caller will have to check
 * it and free it. The output arg list is returned in argp which must be valid.
 * The returned array is always terminated by an arg of type ARGT_STOP (0),
 * unless the mask indicates that no argument is supported. Unresolved arguments
 * are appended to arg list <al>, which also serves as a template to create new
 * entries. <al> may be NULL if unresolved arguments are not allowed. The mask
 * is composed of a number of mandatory arguments in its lower ARGM_BITS bits,
 * and a concatenation of each argument type in each subsequent ARGT_BITS-bit
 * sblock. If <err_msg> is not NULL, it must point to a freeable or NULL
 * pointer. The caller is expected to restart the parsing from the new pointer
 * set in <end_ptr>, which is the first character considered as not being part
 * of the arg list. The input string ends on the first between <len> characters
 * (when len is positive) or the first NUL character. Placing -1 in <len> will
 * make it virtually unbounded (~2GB long strings).
 */
int make_arg_list(const char *in, int len, uint64_t mask, struct arg **argp,
                  char **err_msg, const char **end_ptr, int *err_arg,
                  struct arg_list *al)
{
	int nbarg;
	int pos;
	struct arg *arg;
	const char *beg;
	const char *ptr_err = NULL;
	int min_arg;
	int empty;
	struct arg_list *new_al = al;

	*argp = NULL;

	empty = 0;
	if (!len || *in != '(') {
		/* it's already not for us, stop here */
		empty = 1;
		len = 0;
	} else {
		/* skip opening parenthesis */
		len--;
		in++;
	}

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
	if (empty && !min_arg)
		goto end_parse;

	arg = *argp = calloc(nbarg + 1, sizeof(**argp));

	if (!arg)
		goto alloc_err;

	/* Note: empty arguments after a comma always exist. */
	while (pos < nbarg) {
		unsigned int uint;
		int squote = 0, dquote = 0;
		char *out;

		chunk_reset(&trash);
		out = trash.area;

		while (len && *in && trash.data < trash.size - 1) {
			if (*in == '"' && !squote) {  /* double quote outside single quotes */
				if (dquote)
					dquote = 0;
				else
					dquote = 1;
				in++; len--;
				continue;
			}
			else if (*in == '\'' && !dquote) { /* single quote outside double quotes */
				if (squote)
					squote = 0;
				else
					squote = 1;
				in++; len--;
				continue;
			}
			else if (*in == '\\' && !squote && len != 1) {
				/* '\', ', ' ', '"' support being escaped by '\' */
				if (in[1] == 0)
					goto unquote_err;

				if (in[1] == '\\' || in[1] == ' ' || in[1] == '"' || in[1] == '\'') {
					in++; len--;
					*out++ = *in;
				}
				else if (in[1] == 'r') {
					in++; len--;
					*out++ = '\r';
				}
				else if (in[1] == 'n') {
					in++; len--;
					*out++ = '\n';
				}
				else if (in[1] == 't') {
					in++; len--;
					*out++ = '\t';
				}
				else {
					/* just a lone '\' */
					*out++ = *in;
				}
				in++; len--;
			}
			else {
				if (!squote && !dquote && (*in == ',' || *in == ')')) {
					/* end of argument */
					break;
				}
				/* verbatim copy */
				*out++ = *in++;
				len--;
			}
			trash.data = out - trash.area;
		}

		if (len && *in && *in != ',' && *in != ')')
			goto buffer_err;

		trash.area[trash.data] = 0;

		arg->type = (mask >> (pos * ARGT_BITS)) & ARGT_MASK;

		switch (arg->type) {
		case ARGT_SINT:
			if (!trash.data)	  // empty number
				goto empty_err;
			beg = trash.area;
			arg->data.sint = read_int64(&beg, trash.area + trash.data);
			if (beg < trash.area + trash.data)
				goto parse_err;
			arg->type = ARGT_SINT;
			break;

		case ARGT_ID:
		case ARGT_FE:
		case ARGT_BE:
		case ARGT_TAB:
		case ARGT_SRV:
		case ARGT_USR:
		case ARGT_REG:
			/* These argument types need to be stored as strings during
			 * parsing then resolved later.
			 */
			if (!al)
				goto resolve_err;
			arg->unresolved = 1;
			new_al = arg_list_add(al, arg, pos);
			__fallthrough;

		case ARGT_STR:
			/* all types that must be resolved are stored as strings
			 * during the parsing. The caller must at one point resolve
			 * them and free the string.
			 */
			arg->data.str.area = my_strndup(trash.area, trash.data);
			arg->data.str.data = trash.data;
			arg->data.str.size = trash.data + 1;
			break;

		case ARGT_IPV4:
			if (!trash.data)    // empty address
				goto empty_err;

			if (inet_pton(AF_INET, trash.area, &arg->data.ipv4) <= 0)
				goto parse_err;
			break;

		case ARGT_MSK4:
			if (!trash.data)    // empty mask
				goto empty_err;

			if (!str2mask(trash.area, &arg->data.ipv4))
				goto parse_err;

			arg->type = ARGT_IPV4;
			break;

		case ARGT_IPV6:
			if (!trash.data)    // empty address
				goto empty_err;

			if (inet_pton(AF_INET6, trash.area, &arg->data.ipv6) <= 0)
				goto parse_err;
			break;

		case ARGT_MSK6:
			if (!trash.data)    // empty mask
				goto empty_err;

			if (!str2mask6(trash.area, &arg->data.ipv6))
				goto parse_err;

			arg->type = ARGT_IPV6;
			break;

		case ARGT_TIME:
			if (!trash.data)    // empty time
				goto empty_err;

			ptr_err = parse_time_err(trash.area, &uint, TIME_UNIT_MS);
			if (ptr_err) {
				if (ptr_err == PARSE_TIME_OVER || ptr_err == PARSE_TIME_UNDER)
					ptr_err = trash.area;
				goto parse_err;
			}
			arg->data.sint = uint;
			arg->type = ARGT_SINT;
			break;

		case ARGT_SIZE:
			if (!trash.data)    // empty size
				goto empty_err;

			ptr_err = parse_size_err(trash.area, &uint);
			if (ptr_err)
				goto parse_err;

			arg->data.sint = uint;
			arg->type = ARGT_SINT;
			break;

		case ARGT_PBUF_FNUM:
			if (!trash.data)
				goto empty_err;

			if (!parse_dotted_uints(trash.area, &arg->data.fid.ids, &arg->data.fid.sz))
				goto parse_err;

			break;

			/* FIXME: other types need to be implemented here */
		default:
			goto not_impl;
		}

		pos++;
		arg++;

		/* don't go back to parsing if we reached end */
		if (!len || !*in || *in == ')' || pos >= nbarg)
			break;

		/* skip comma */
		in++; len--;
	}

 end_parse:
	if (pos < min_arg) {
		/* not enough arguments */
		memprintf(err_msg,
		          "missing arguments (got %d/%d), type '%s' expected",
		          pos, min_arg, arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK]);
		goto err;
	}

	if (empty) {
		/* nothing to do */
	} else if (*in == ')') {
		/* skip the expected closing parenthesis */
		in++;
	} else {
		/* the caller is responsible for freeing this message */
		char *word = (len > 0) ? my_strndup(in, len) : (char *)in;

		if (*word)
			memprintf(err_msg, "expected ')' before '%s'", word);
		else
			memprintf(err_msg, "expected ')'");

		if (len > 0)
			free(word);
		/* when we're missing a right paren, the empty part preceding
		 * already created an empty arg, adding one to the position, so
		 * let's fix the reporting to avoid being confusing.
		 */
		if (pos > 1)
			pos--;
		goto err;
	}

	/* note that pos might be < nbarg and this is not an error, it's up to the
	 * caller to decide what to do with optional args.
	 */
	if (err_arg)
		*err_arg = pos;
	if (end_ptr)
		*end_ptr = in;
	return pos;

 err:
	if (new_al == al) {
		/* only free the arg area if we have not queued unresolved args
		 * still pointing to it.
		 */
		free_args(*argp);
		free(*argp);
	}
	*argp = NULL;
	if (err_arg)
		*err_arg = pos;
	if (end_ptr)
		*end_ptr = in;
	return -1;

 empty_err:
	/* If we've only got an empty set of parenthesis with nothing
	 * in between, there is no arg at all.
	 */
	if (!pos) {
		ha_free(argp);
	}

	if (pos >= min_arg)
		goto end_parse;

	memprintf(err_msg, "expected type '%s' at position %d, but got nothing",
	          arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK], pos + 1);
	goto err;

 parse_err:
	/* come here with the word attempted to parse in trash */
	memprintf(err_msg, "failed to parse '%s' as type '%s' at position %d",
	          trash.area, arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK], pos + 1);
	goto err;

 not_impl:
	memprintf(err_msg, "parsing for type '%s' was not implemented, please report this bug",
	          arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK]);
	goto err;

 buffer_err:
	memprintf(err_msg, "too small buffer size to store decoded argument %d, increase bufsize ?",
	          pos + 1);
	goto err;

 unquote_err:
	/* come here with the parsed part in <trash.area>:<trash.data> and the
	 * unparsable part in <in>.
	 */
	trash.area[trash.data] = 0;
	memprintf(err_msg, "failed to parse '%s' after '%s' as type '%s' at position %d",
	          in, trash.area, arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK], pos + 1);
	goto err;

alloc_err:
	memprintf(err_msg, "out of memory");
	goto err;

 resolve_err:
	memprintf(err_msg, "unresolved argument of type '%s' at position %d not allowed",
	          arg_type_names[(mask >> (pos * ARGT_BITS)) & ARGT_MASK], pos + 1);
	goto err;
}

/* Free all args of an args array, taking care of unresolved arguments as well.
 * It stops at the ARGT_STOP, which must be present. The array itself is not
 * freed, it's up to the caller to do it. However it is returned, allowing to
 * call free(free_args(argptr)). It is valid to call it with a NULL args, and
 * nothing will be done).
 */
struct arg *free_args(struct arg *args)
{
	struct arg *arg;

	for (arg = args; arg && arg->type != ARGT_STOP; arg++) {
		if (arg->type == ARGT_STR || arg->unresolved)
			chunk_destroy(&arg->data.str);
		else if (arg->type == ARGT_REG)
			regex_free(arg->data.reg);
		else if (arg->type == ARGT_PBUF_FNUM)
			ha_free(&arg->data.fid.ids);
	}
	return args;
}
