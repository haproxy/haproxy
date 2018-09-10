/*
 * HTTP semantics
 *
 * Copyright 2000-2018 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <common/config.h>
#include <common/http.h>

/* It is about twice as fast on recent architectures to lookup a byte in a
 * table than to perform a boolean AND or OR between two tests. Refer to
 * RFC2616/RFC5234/RFC7230 for those chars. A token is any ASCII char that is
 * neither a separator nor a CTL char. An http ver_token is any ASCII which can
 * be found in an HTTP version, which includes 'H', 'T', 'P', '/', '.' and any
 * digit. Note: please do not overwrite values in assignment since gcc-2.95
 * will not handle them correctly. It's worth noting that chars 128..255 are
 * nothing, not even control chars.
 */
const unsigned char http_char_classes[256] = {
	[  0] = HTTP_FLG_CTL,
	[  1] = HTTP_FLG_CTL,
	[  2] = HTTP_FLG_CTL,
	[  3] = HTTP_FLG_CTL,
	[  4] = HTTP_FLG_CTL,
	[  5] = HTTP_FLG_CTL,
	[  6] = HTTP_FLG_CTL,
	[  7] = HTTP_FLG_CTL,
	[  8] = HTTP_FLG_CTL,
	[  9] = HTTP_FLG_SPHT | HTTP_FLG_LWS | HTTP_FLG_SEP | HTTP_FLG_CTL,
	[ 10] = HTTP_FLG_CRLF | HTTP_FLG_LWS | HTTP_FLG_CTL,
	[ 11] = HTTP_FLG_CTL,
	[ 12] = HTTP_FLG_CTL,
	[ 13] = HTTP_FLG_CRLF | HTTP_FLG_LWS | HTTP_FLG_CTL,
	[ 14] = HTTP_FLG_CTL,
	[ 15] = HTTP_FLG_CTL,
	[ 16] = HTTP_FLG_CTL,
	[ 17] = HTTP_FLG_CTL,
	[ 18] = HTTP_FLG_CTL,
	[ 19] = HTTP_FLG_CTL,
	[ 20] = HTTP_FLG_CTL,
	[ 21] = HTTP_FLG_CTL,
	[ 22] = HTTP_FLG_CTL,
	[ 23] = HTTP_FLG_CTL,
	[ 24] = HTTP_FLG_CTL,
	[ 25] = HTTP_FLG_CTL,
	[ 26] = HTTP_FLG_CTL,
	[ 27] = HTTP_FLG_CTL,
	[ 28] = HTTP_FLG_CTL,
	[ 29] = HTTP_FLG_CTL,
	[ 30] = HTTP_FLG_CTL,
	[ 31] = HTTP_FLG_CTL,
	[' '] = HTTP_FLG_SPHT | HTTP_FLG_LWS | HTTP_FLG_SEP,
	['!'] = HTTP_FLG_TOK,
	['"'] = HTTP_FLG_SEP,
	['#'] = HTTP_FLG_TOK,
	['$'] = HTTP_FLG_TOK,
	['%'] = HTTP_FLG_TOK,
	['&'] = HTTP_FLG_TOK,
	[ 39] = HTTP_FLG_TOK,
	['('] = HTTP_FLG_SEP,
	[')'] = HTTP_FLG_SEP,
	['*'] = HTTP_FLG_TOK,
	['+'] = HTTP_FLG_TOK,
	[','] = HTTP_FLG_SEP,
	['-'] = HTTP_FLG_TOK,
	['.'] = HTTP_FLG_TOK | HTTP_FLG_VER,
	['/'] = HTTP_FLG_SEP | HTTP_FLG_VER,
	['0'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	['1'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	['2'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	['3'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	['4'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	['5'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	['6'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	['7'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	['8'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	['9'] = HTTP_FLG_TOK | HTTP_FLG_VER | HTTP_FLG_DIG,
	[':'] = HTTP_FLG_SEP,
	[';'] = HTTP_FLG_SEP,
	['<'] = HTTP_FLG_SEP,
	['='] = HTTP_FLG_SEP,
	['>'] = HTTP_FLG_SEP,
	['?'] = HTTP_FLG_SEP,
	['@'] = HTTP_FLG_SEP,
	['A'] = HTTP_FLG_TOK,
	['B'] = HTTP_FLG_TOK,
	['C'] = HTTP_FLG_TOK,
	['D'] = HTTP_FLG_TOK,
	['E'] = HTTP_FLG_TOK,
	['F'] = HTTP_FLG_TOK,
	['G'] = HTTP_FLG_TOK,
	['H'] = HTTP_FLG_TOK | HTTP_FLG_VER,
	['I'] = HTTP_FLG_TOK,
	['J'] = HTTP_FLG_TOK,
	['K'] = HTTP_FLG_TOK,
	['L'] = HTTP_FLG_TOK,
	['M'] = HTTP_FLG_TOK,
	['N'] = HTTP_FLG_TOK,
	['O'] = HTTP_FLG_TOK,
	['P'] = HTTP_FLG_TOK | HTTP_FLG_VER,
	['Q'] = HTTP_FLG_TOK,
	['R'] = HTTP_FLG_TOK | HTTP_FLG_VER,
	['S'] = HTTP_FLG_TOK | HTTP_FLG_VER,
	['T'] = HTTP_FLG_TOK | HTTP_FLG_VER,
	['U'] = HTTP_FLG_TOK,
	['V'] = HTTP_FLG_TOK,
	['W'] = HTTP_FLG_TOK,
	['X'] = HTTP_FLG_TOK,
	['Y'] = HTTP_FLG_TOK,
	['Z'] = HTTP_FLG_TOK,
	['['] = HTTP_FLG_SEP,
	[ 92] = HTTP_FLG_SEP,
	[']'] = HTTP_FLG_SEP,
	['^'] = HTTP_FLG_TOK,
	['_'] = HTTP_FLG_TOK,
	['`'] = HTTP_FLG_TOK,
	['a'] = HTTP_FLG_TOK,
	['b'] = HTTP_FLG_TOK,
	['c'] = HTTP_FLG_TOK,
	['d'] = HTTP_FLG_TOK,
	['e'] = HTTP_FLG_TOK,
	['f'] = HTTP_FLG_TOK,
	['g'] = HTTP_FLG_TOK,
	['h'] = HTTP_FLG_TOK,
	['i'] = HTTP_FLG_TOK,
	['j'] = HTTP_FLG_TOK,
	['k'] = HTTP_FLG_TOK,
	['l'] = HTTP_FLG_TOK,
	['m'] = HTTP_FLG_TOK,
	['n'] = HTTP_FLG_TOK,
	['o'] = HTTP_FLG_TOK,
	['p'] = HTTP_FLG_TOK,
	['q'] = HTTP_FLG_TOK,
	['r'] = HTTP_FLG_TOK,
	['s'] = HTTP_FLG_TOK,
	['t'] = HTTP_FLG_TOK,
	['u'] = HTTP_FLG_TOK,
	['v'] = HTTP_FLG_TOK,
	['w'] = HTTP_FLG_TOK,
	['x'] = HTTP_FLG_TOK,
	['y'] = HTTP_FLG_TOK,
	['z'] = HTTP_FLG_TOK,
	['{'] = HTTP_FLG_SEP,
	['|'] = HTTP_FLG_TOK,
	['}'] = HTTP_FLG_SEP,
	['~'] = HTTP_FLG_TOK,
	[127] = HTTP_FLG_CTL,
};

const struct ist http_known_methods[HTTP_METH_OTHER] = {
	[HTTP_METH_OPTIONS] = IST("OPTIONS"),
	[HTTP_METH_GET]     = IST("GET"),
	[HTTP_METH_HEAD]    = IST("HEAD"),
	[HTTP_METH_POST]    = IST("POST"),
	[HTTP_METH_PUT]     = IST("PUT"),
	[HTTP_METH_DELETE]  = IST("DELETE"),
	[HTTP_METH_TRACE]   = IST("TRACE"),
	[HTTP_METH_CONNECT] = IST("CONNECT"),
};

/*
 * returns a known method among HTTP_METH_* or HTTP_METH_OTHER for all unknown
 * ones.
 */
enum http_meth_t find_http_meth(const char *str, const int len)
{
	const struct ist m = ist2(str, len);

	if      (isteq(m, ist("GET")))     return HTTP_METH_GET;
	else if (isteq(m, ist("HEAD")))    return HTTP_METH_HEAD;
	else if (isteq(m, ist("POST")))    return HTTP_METH_POST;
	else if (isteq(m, ist("CONNECT"))) return HTTP_METH_CONNECT;
	else if (isteq(m, ist("PUT")))     return HTTP_METH_PUT;
	else if (isteq(m, ist("OPTIONS"))) return HTTP_METH_OPTIONS;
	else if (isteq(m, ist("DELETE")))  return HTTP_METH_DELETE;
	else if (isteq(m, ist("TRACE")))   return HTTP_METH_TRACE;
	else                               return HTTP_METH_OTHER;
}
