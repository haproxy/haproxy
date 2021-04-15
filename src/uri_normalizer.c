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
#include <haproxy/uri_normalizer.h>

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


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
