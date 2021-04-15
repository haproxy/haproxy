/*
 * include/haproxy/uri_normalizer.h
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

#ifndef _HAPROXY_URI_NORMALIZER_T_H
#define _HAPROXY_URI_NORMALIZER_T_H

enum uri_normalizer_err {
	URI_NORMALIZER_ERR_NONE = 0,
	URI_NORMALIZER_ERR_ALLOC,
	URI_NORMALIZER_ERR_INVALID_INPUT,
	URI_NORMALIZER_ERR_INTERNAL_ERROR = 0xdead,
};

#endif /* _HAPROXY_URI_NORMALIZER_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
