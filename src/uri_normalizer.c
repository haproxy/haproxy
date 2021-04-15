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
