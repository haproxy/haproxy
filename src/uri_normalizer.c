/*
 * HTTP request URI normalization.
 *
 * Copyright 2021 Tim Duesterhus <tim@bastelstu.be>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <import/ist.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/tools.h>
#include <haproxy/uri_normalizer.h>

/* Encodes '#' as '%23'. */
enum uri_normalizer_err uri_normalizer_fragment_encode(const struct ist input, struct ist *dst)
{
	enum uri_normalizer_err err;

	const size_t size = istclear(dst);
	struct ist output = *dst;

	struct ist scanner = input;

	while (istlen(scanner)) {
		const struct ist before_hash = istsplit(&scanner, '#');

		if (istcat(&output, before_hash, size) < 0) {
			err = URI_NORMALIZER_ERR_ALLOC;
			goto fail;
		}

		if (istend(before_hash) != istend(scanner)) {
			if (istcat(&output, ist("%23"), size) < 0) {
				err = URI_NORMALIZER_ERR_ALLOC;
				goto fail;
			}
		}
	}

	*dst = output;

	return URI_NORMALIZER_ERR_NONE;

  fail:

	return err;
}

/* Returns 1 if the given character is part of the 'unreserved' set in the
 * RFC 3986 ABNF.
 * Returns 0 if not.
 */
static int is_unreserved_character(unsigned char c)
{
	switch (c) {
	case 'A'...'Z': /* ALPHA */
	case 'a'...'z': /* ALPHA */
	case '0'...'9': /* DIGIT */
	case '-':
	case '.':
	case '_':
	case '~':
		return 1;
	default:
		return 0;
	}
}

/* Decodes percent encoded characters that are part of the 'unreserved' set.
 *
 * RFC 3986, section 2.3:
 * >  URIs that differ in the replacement of an unreserved character with
 * >  its corresponding percent-encoded US-ASCII octet are equivalent [...]
 * >  when found in a URI, should be decoded to their corresponding unreserved
 * >  characters by URI normalizers.
 *
 * If `strict` is set to 0 then percent characters that are not followed by a
 * hexadecimal digit are returned as-is without performing any decoding.
 * If `strict` is set to 1 then `URI_NORMALIZER_ERR_INVALID_INPUT` is returned
 * for invalid sequences.
 */
enum uri_normalizer_err uri_normalizer_percent_decode_unreserved(const struct ist input, int strict, struct ist *dst)
{
	enum uri_normalizer_err err;

	const size_t size = istclear(dst);
	struct ist output = *dst;

	struct ist scanner = input;

	/* The output will either be shortened or have the same length. */
	if (size < istlen(input)) {
		err = URI_NORMALIZER_ERR_ALLOC;
		goto fail;
	}

	while (istlen(scanner)) {
		const char current = istshift(&scanner);

		if (current == '%') {
			if (istlen(scanner) >= 2) {
				if (ishex(istptr(scanner)[0]) && ishex(istptr(scanner)[1])) {
					char hex1, hex2, c;

					hex1 = istshift(&scanner);
					hex2 = istshift(&scanner);
					c = (hex2i(hex1) << 4) + hex2i(hex2);

					if (is_unreserved_character(c)) {
						output = __istappend(output, c);
					}
					else {
						output = __istappend(output, current);
						output = __istappend(output, hex1);
						output = __istappend(output, hex2);
					}

					continue;
				}
			}

			if (strict) {
				err = URI_NORMALIZER_ERR_INVALID_INPUT;
				goto fail;
			}
			else {
				output = __istappend(output, current);
			}
		}
		else {
			output = __istappend(output, current);
		}
	}

	*dst = output;

	return URI_NORMALIZER_ERR_NONE;

  fail:

	return err;
}

/* Uppercases letters used in percent encoding.
 *
 * If `strict` is set to 0 then percent characters that are not followed by a
 * hexadecimal digit are returned as-is without modifying the following letters.
 * If `strict` is set to 1 then `URI_NORMALIZER_ERR_INVALID_INPUT` is returned
 * for invalid sequences.
 */
enum uri_normalizer_err uri_normalizer_percent_upper(const struct ist input, int strict, struct ist *dst)
{
	enum uri_normalizer_err err;

	const size_t size = istclear(dst);
	struct ist output = *dst;

	struct ist scanner = input;

	/* The output will have the same length. */
	if (size < istlen(input)) {
		err = URI_NORMALIZER_ERR_ALLOC;
		goto fail;
	}

	while (istlen(scanner)) {
		const char current = istshift(&scanner);

		if (current == '%') {
			if (istlen(scanner) >= 2) {
				if (ishex(istptr(scanner)[0]) && ishex(istptr(scanner)[1])) {
					output = __istappend(output, current);
					output = __istappend(output, toupper(istshift(&scanner)));
					output = __istappend(output, toupper(istshift(&scanner)));
					continue;
				}
			}

			if (strict) {
				err = URI_NORMALIZER_ERR_INVALID_INPUT;
				goto fail;
			}
			else {
				output = __istappend(output, current);
			}
		}
		else {
			output = __istappend(output, current);
		}
	}

	*dst = output;

	return URI_NORMALIZER_ERR_NONE;

  fail:

	return err;
}

/* Removes `/./` from the given path. */
enum uri_normalizer_err uri_normalizer_path_dot(const struct ist path, struct ist *dst)
{
	enum uri_normalizer_err err;

	const size_t size = istclear(dst);
	struct ist newpath = *dst;

	struct ist scanner = path;

	/* The path will either be shortened or have the same length. */
	if (size < istlen(path)) {
		err = URI_NORMALIZER_ERR_ALLOC;
		goto fail;
	}

	while (istlen(scanner) > 0) {
		const struct ist segment = istsplit(&scanner, '/');

		if (!isteq(segment, ist("."))) {
			if (istcat(&newpath, segment, size) < 0) {
				/* This is impossible, because we checked the size of the destination buffer. */
				my_unreachable();
				err = URI_NORMALIZER_ERR_INTERNAL_ERROR;
				goto fail;
			}

			if (istend(segment) != istend(scanner))
				newpath = __istappend(newpath, '/');
		}
	}

	*dst = newpath;

	return URI_NORMALIZER_ERR_NONE;

  fail:

	return err;
}

/* Merges `/../` with preceding path segments.
 *
 * If `full` is set to `0` then `/../` will be printed at the start of the resulting
 * path if the number of `/../` exceeds the number of other segments. If `full` is
 * set to `1` these will not be printed.
 */
enum uri_normalizer_err uri_normalizer_path_dotdot(const struct ist path, int full, struct ist *dst)
{
	enum uri_normalizer_err err;

	const size_t size = istclear(dst);
	char * const tail = istptr(*dst) + size;
	char *head = tail;

	ssize_t offset = istlen(path) - 1;

	int up = 0;

	/* The path will either be shortened or have the same length. */
	if (size < istlen(path)) {
		err = URI_NORMALIZER_ERR_ALLOC;
		goto fail;
	}

	/* Handle `/..` at the end of the path without a trailing slash. */
	if (offset >= 2 && istmatch(istadv(path, offset - 2), ist("/.."))) {
		up++;
		offset -= 2;
	}

	while (offset >= 0) {
		if (offset >= 3 && istmatch(istadv(path, offset - 3), ist("/../"))) {
			up++;
			offset -= 3;
			continue;
		}

		if (up > 0) {
			/* Skip the slash. */
			offset--;

			/* First check whether we already reached the start of the path,
			 * before popping the current `/../`.
			 */
			if (offset >= 0) {
				up--;

				/* Skip the current path segment. */
				while (offset >= 0 && istptr(path)[offset] != '/')
					offset--;
			}
		}
		else {
			/* Prepend the slash. */
			*(--head) = istptr(path)[offset];
			offset--;

			/* Prepend the current path segment. */
			while (offset >= 0 && istptr(path)[offset] != '/') {
				*(--head) = istptr(path)[offset];
				offset--;
			}
		}
	}

	if (up > 0) {
		/* Prepend a trailing slash. */
		*(--head) = '/';

		if (!full) {
			/* Prepend unconsumed `/..`. */
			do {
				*(--head) = '.';
				*(--head) = '.';
				*(--head) = '/';
				up--;
			} while (up > 0);
		}
	}

	*dst = ist2(head, tail - head);

	return URI_NORMALIZER_ERR_NONE;

  fail:

	return err;
}

/* Merges adjacent slashes in the given path. */
enum uri_normalizer_err uri_normalizer_path_merge_slashes(const struct ist path, struct ist *dst)
{
	enum uri_normalizer_err err;

	const size_t size = istclear(dst);
	struct ist newpath = *dst;

	struct ist scanner = path;

	/* The path will either be shortened or have the same length. */
	if (size < istlen(path)) {
		err = URI_NORMALIZER_ERR_ALLOC;
		goto fail;
	}

	while (istlen(scanner) > 0) {
		const char current = istshift(&scanner);

		if (current == '/') {
			while (istlen(scanner) > 0 && *istptr(scanner) == '/')
				scanner = istnext(scanner);
		}

		newpath = __istappend(newpath, current);
	}

	*dst = newpath;

	return URI_NORMALIZER_ERR_NONE;

  fail:

	return err;
}

/* Compares two query parameters by name. Query parameters are ordered
 * as with memcmp. Shorter parameter names are ordered lower. Identical
 * parameter names are compared by their pointer to maintain a stable
 * sort.
 */
static int query_param_cmp(const void *a, const void *b)
{
	const struct ist param_a = *(struct ist*)a;
	const struct ist param_b = *(struct ist*)b;
	const struct ist param_a_name = iststop(param_a, '=');
	const struct ist param_b_name = iststop(param_b, '=');

	int cmp = istdiff(param_a_name, param_b_name);

	if (cmp != 0)
		return cmp;

	/* The contents are identical: Compare the pointer. */
	if (istptr(param_a) < istptr(param_b))
		return -1;

	if (istptr(param_a) > istptr(param_b))
		return 1;

	return 0;
}

/* Sorts the parameters within the given query string. */
enum uri_normalizer_err uri_normalizer_query_sort(const struct ist query, const char delim, struct ist *dst)
{
	enum uri_normalizer_err err;

	const size_t size = istclear(dst);
	struct ist newquery = *dst;

	struct ist scanner = query;

	const struct buffer *trash = get_trash_chunk();
	struct ist *params = (struct ist *)b_orig(trash);
	const size_t max_param = b_size(trash) / sizeof(*params);
	size_t param_count = 0;

	size_t i;

	/* The query will have the same length. */
	if (size < istlen(query)) {
		err = URI_NORMALIZER_ERR_ALLOC;
		goto fail;
	}

	/* Handle the leading '?'. */
	newquery = __istappend(newquery, istshift(&scanner));

	while (istlen(scanner) > 0) {
		const struct ist param = istsplit(&scanner, delim);

		if (param_count + 1 > max_param) {
			err = URI_NORMALIZER_ERR_ALLOC;
			goto fail;
		}

		params[param_count] = param;
		param_count++;
	}

	qsort(params, param_count, sizeof(*params), query_param_cmp);

	for (i = 0; i < param_count; i++) {
		if (i > 0)
			newquery = __istappend(newquery, delim);

		if (istcat(&newquery, params[i], size) < 0) {
			/* This is impossible, because we checked the size of the destination buffer. */
			my_unreachable();
			err = URI_NORMALIZER_ERR_INTERNAL_ERROR;
			goto fail;
		}
	}

	*dst = newquery;

	return URI_NORMALIZER_ERR_NONE;

  fail:

	return err;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
