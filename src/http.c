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
#include <haproxy/api.h>
#include <haproxy/http.h>
#include <haproxy/tools.h>

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

const int http_err_codes[HTTP_ERR_SIZE] = {
	[HTTP_ERR_200] = 200,  /* used by "monitor-uri" */
	[HTTP_ERR_400] = 400,
	[HTTP_ERR_401] = 401,
	[HTTP_ERR_403] = 403,
	[HTTP_ERR_404] = 404,
	[HTTP_ERR_405] = 405,
	[HTTP_ERR_407] = 407,
	[HTTP_ERR_408] = 408,
	[HTTP_ERR_410] = 410,
	[HTTP_ERR_413] = 413,
	[HTTP_ERR_421] = 421,
	[HTTP_ERR_425] = 425,
	[HTTP_ERR_429] = 429,
	[HTTP_ERR_500] = 500,
	[HTTP_ERR_502] = 502,
	[HTTP_ERR_503] = 503,
	[HTTP_ERR_504] = 504,
};

const char *http_err_msgs[HTTP_ERR_SIZE] = {
	[HTTP_ERR_200] =
	"HTTP/1.1 200 OK\r\n"
	"Content-length: 58\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n",

	[HTTP_ERR_400] =
	"HTTP/1.1 400 Bad request\r\n"
	"Content-length: 90\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request.\n</body></html>\n",

	[HTTP_ERR_401] =
	"HTTP/1.1 401 Unauthorized\r\n"
	"Content-length: 112\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n",

	[HTTP_ERR_403] =
	"HTTP/1.1 403 Forbidden\r\n"
	"Content-length: 93\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>\n",

	[HTTP_ERR_404] =
	"HTTP/1.1 404 Not Found\r\n"
	"Content-length: 83\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>404 Not Found</h1>\nThe resource could not be found.\n</body></html>\n",

	[HTTP_ERR_405] =
	"HTTP/1.1 405 Method Not Allowed\r\n"
	"Content-length: 146\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>405 Method Not Allowed</h1>\nA request was made of a resource using a request method not supported by that resource\n</body></html>\n",

	[HTTP_ERR_407] =
	"HTTP/1.1 407 Unauthorized\r\n"
	"Content-length: 112\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>407 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n",

	[HTTP_ERR_408] =
	"HTTP/1.1 408 Request Time-out\r\n"
	"Content-length: 110\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time.\n</body></html>\n",

	[HTTP_ERR_410] =
	"HTTP/1.1 410 Gone\r\n"
	"Content-length: 114\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>410 Gone</h1>\nThe resource is no longer available and will not be available again.\n</body></html>\n",

	[HTTP_ERR_413] =
	"HTTP/1.1 413 Payload Too Large\r\n"
	"Content-length: 106\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>413 Payload Too Large</h1>\nThe request entity exceeds the maximum allowed.\n</body></html>\n",

	[HTTP_ERR_421] =
	"HTTP/1.1 421 Misdirected Request\r\n"
	"Content-length: 104\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>421 Misdirected Request</h1>\nRequest sent to a non-authoritative server.\n</body></html>\n",

	[HTTP_ERR_425] =
	"HTTP/1.1 425 Too Early\r\n"
	"Content-length: 80\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>425 Too Early</h1>\nYour browser sent early data.\n</body></html>\n",

	[HTTP_ERR_429] =
	"HTTP/1.1 429 Too Many Requests\r\n"
	"Content-length: 117\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>429 Too Many Requests</h1>\nYou have sent too many requests in a given amount of time.\n</body></html>\n",

	[HTTP_ERR_500] =
	"HTTP/1.1 500 Internal Server Error\r\n"
	"Content-length: 97\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>500 Internal Server Error</h1>\nAn internal server error occurred.\n</body></html>\n",

	[HTTP_ERR_502] =
	"HTTP/1.1 502 Bad Gateway\r\n"
	"Content-length: 107\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response.\n</body></html>\n",

	[HTTP_ERR_503] =
	"HTTP/1.1 503 Service Unavailable\r\n"
	"Content-length: 107\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n",

	[HTTP_ERR_504] =
	"HTTP/1.1 504 Gateway Time-out\r\n"
	"Content-length: 92\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>504 Gateway Time-out</h1>\nThe server didn't respond in time.\n</body></html>\n",
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

/* This function returns HTTP_ERR_<num> (enum) matching http status code.
 * Returned value should match codes from http_err_codes.
 */
int http_get_status_idx(unsigned int status)
{
	switch (status) {
	case 200: return HTTP_ERR_200;
	case 400: return HTTP_ERR_400;
	case 401: return HTTP_ERR_401;
	case 403: return HTTP_ERR_403;
	case 404: return HTTP_ERR_404;
	case 405: return HTTP_ERR_405;
	case 407: return HTTP_ERR_407;
	case 408: return HTTP_ERR_408;
	case 410: return HTTP_ERR_410;
	case 413: return HTTP_ERR_413;
	case 421: return HTTP_ERR_421;
	case 425: return HTTP_ERR_425;
	case 429: return HTTP_ERR_429;
	case 500: return HTTP_ERR_500;
	case 502: return HTTP_ERR_502;
	case 503: return HTTP_ERR_503;
	case 504: return HTTP_ERR_504;
	default: return HTTP_ERR_500;
	}
}

/* This function returns a reason associated with the HTTP status.
 * This function never fails, a message is always returned.
 */
const char *http_get_reason(unsigned int status)
{
	switch (status) {
	case 100: return "Continue";
	case 101: return "Switching Protocols";
	case 102: return "Processing";
	case 200: return "OK";
	case 201: return "Created";
	case 202: return "Accepted";
	case 203: return "Non-Authoritative Information";
	case 204: return "No Content";
	case 205: return "Reset Content";
	case 206: return "Partial Content";
	case 207: return "Multi-Status";
	case 210: return "Content Different";
	case 226: return "IM Used";
	case 300: return "Multiple Choices";
	case 301: return "Moved Permanently";
	case 302: return "Moved Temporarily";
	case 303: return "See Other";
	case 304: return "Not Modified";
	case 305: return "Use Proxy";
	case 307: return "Temporary Redirect";
	case 308: return "Permanent Redirect";
	case 310: return "Too many Redirects";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 402: return "Payment Required";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 406: return "Not Acceptable";
	case 407: return "Proxy Authentication Required";
	case 408: return "Request Time-out";
	case 409: return "Conflict";
	case 410: return "Gone";
	case 411: return "Length Required";
	case 412: return "Precondition Failed";
	case 413: return "Request Entity Too Large";
	case 414: return "Request-URI Too Long";
	case 415: return "Unsupported Media Type";
	case 416: return "Requested range unsatisfiable";
	case 417: return "Expectation failed";
	case 418: return "I'm a teapot";
	case 421: return "Misdirected Request";
	case 422: return "Unprocessable entity";
	case 423: return "Locked";
	case 424: return "Method failure";
	case 425: return "Too Early";
	case 426: return "Upgrade Required";
	case 428: return "Precondition Required";
	case 429: return "Too Many Requests";
	case 431: return "Request Header Fields Too Large";
	case 449: return "Retry With";
	case 450: return "Blocked by Windows Parental Controls";
	case 451: return "Unavailable For Legal Reasons";
	case 456: return "Unrecoverable Error";
	case 499: return "client has closed connection";
	case 500: return "Internal Server Error";
	case 501: return "Not Implemented";
	case 502: return "Bad Gateway or Proxy Error";
	case 503: return "Service Unavailable";
	case 504: return "Gateway Time-out";
	case 505: return "HTTP Version not supported";
	case 506: return "Variant also negotiate";
	case 507: return "Insufficient storage";
	case 508: return "Loop detected";
	case 509: return "Bandwidth Limit Exceeded";
	case 510: return "Not extended";
	case 511: return "Network authentication required";
	case 520: return "Web server is returning an unknown error";
	default:
		switch (status) {
		case 100 ... 199: return "Informational";
		case 200 ... 299: return "Success";
		case 300 ... 399: return "Redirection";
		case 400 ... 499: return "Client Error";
		case 500 ... 599: return "Server Error";
		default:          return "Other";
		}
	}
}

/* Parse the uri and looks for the authority, between the scheme and the
 * path. if no_userinfo is not zero, the part before the '@' (including it) is
 * skipped. If not found, an empty ist is returned. Otherwise, the ist pointing
 * on the authority is returned.
 */
struct ist http_get_authority(const struct ist uri, int no_userinfo)
{
	const char *ptr, *start, *end;

	if (!uri.len)
		goto not_found;

	ptr = uri.ptr;
	start = ptr;
	end = ptr + uri.len;

	/* RFC7230, par. 2.7 :
	 * Request-URI = "*" | absuri | abspath | authority
	 */

	if (*ptr == '*' || *ptr == '/')
		goto not_found;

	if (isalpha((unsigned char)*ptr)) {
		/* this is a scheme as described by RFC3986, par. 3.1, or only
		 * an authority (in case of a CONNECT method).
		 */
		ptr++;
		while (ptr < end &&
		       (isalnum((unsigned char)*ptr) || *ptr == '+' || *ptr == '-' || *ptr == '.'))
			ptr++;
		/* skip '://' or take the whole as authority if not found */
		if (ptr == end || *ptr++ != ':')
			goto authority;
		if (ptr == end || *ptr++ != '/')
			goto authority;
		if (ptr == end || *ptr++ != '/')
			goto authority;
	}

	start = ptr;
	while (ptr < end && *ptr != '/') {
		if (*ptr++ == '@' && no_userinfo)
			start = ptr;
	}

	/* OK, ptr point on the '/' or the end */
	end = ptr;

  authority:
	return ist2(start, end - start);

  not_found:
	return IST_NULL;
}

/* Parse the URI from the given transaction (which is assumed to be in request
 * phase) and look for the "/" beginning the PATH. If not found, ist2(0,0) is
 * returned. Otherwise the pointer and length are returned.
 */
struct ist http_get_path(const struct ist uri)
{
	const char *ptr, *end;

	if (!uri.len)
		goto not_found;

	ptr = uri.ptr;
	end = ptr + uri.len;

	/* RFC7230, par. 2.7 :
	 * Request-URI = "*" | absuri | abspath | authority
	 */

	if (*ptr == '*')
		goto not_found;

	if (isalpha((unsigned char)*ptr)) {
		/* this is a scheme as described by RFC3986, par. 3.1 */
		ptr++;
		while (ptr < end &&
		       (isalnum((unsigned char)*ptr) || *ptr == '+' || *ptr == '-' || *ptr == '.'))
			ptr++;
		/* skip '://' */
		if (ptr == end || *ptr++ != ':')
			goto not_found;
		if (ptr == end || *ptr++ != '/')
			goto not_found;
		if (ptr == end || *ptr++ != '/')
			goto not_found;
	}
	/* skip [user[:passwd]@]host[:[port]] */

	while (ptr < end && *ptr != '/')
		ptr++;

	if (ptr == end)
		goto not_found;

	/* OK, we got the '/' ! */
	return ist2(ptr, end - ptr);

 not_found:
	return IST_NULL;
}

/*
 * Checks if <hdr> is exactly <name> for <len> chars, and ends with a colon.
 * If so, returns the position of the first non-space character relative to
 * <hdr>, or <end>-<hdr> if not found before. If no value is found, it tries
 * to return a pointer to the place after the first space. Returns 0 if the
 * header name does not match. Checks are case-insensitive.
 */
int http_header_match2(const char *hdr, const char *end,
		       const char *name, int len)
{
	const char *val;

	if (hdr + len >= end)
		return 0;
	if (hdr[len] != ':')
		return 0;
	if (strncasecmp(hdr, name, len) != 0)
		return 0;
	val = hdr + len + 1;
	while (val < end && HTTP_IS_SPHT(*val))
		val++;
	if ((val >= end) && (len + 2 <= end - hdr))
		return len + 2; /* we may replace starting from second space */
	return val - hdr;
}

/* Find the end of the header value contained between <s> and <e>. See RFC7230,
 * par 3.2 for more information. Note that it requires a valid header to return
 * a valid result. This works for headers defined as comma-separated lists.
 */
char *http_find_hdr_value_end(char *s, const char *e)
{
	int quoted, qdpair;

	quoted = qdpair = 0;

#ifdef HA_UNALIGNED_LE
	/* speedup: skip everything not a comma nor a double quote */
	for (; s <= e - sizeof(int); s += sizeof(int)) {
		unsigned int c = *(int *)s; // comma
		unsigned int q = c;         // quote

		c ^= 0x2c2c2c2c; // contains one zero on a comma
		q ^= 0x22222222; // contains one zero on a quote

		c = (c - 0x01010101) & ~c; // contains 0x80 below a comma
		q = (q - 0x01010101) & ~q; // contains 0x80 below a quote

		if ((c | q) & 0x80808080)
			break; // found a comma or a quote
	}
#endif
	for (; s < e; s++) {
		if (qdpair)                    qdpair = 0;
		else if (quoted) {
			if (*s == '\\')        qdpair = 1;
			else if (*s == '"')    quoted = 0;
		}
		else if (*s == '"')            quoted = 1;
		else if (*s == ',')            return s;
	}
	return s;
}

/* Find the end of a cookie value contained between <s> and <e>. It works the
 * same way as with headers above except that the semi-colon also ends a token.
 * See RFC2965 for more information. Note that it requires a valid header to
 * return a valid result.
 */
char *http_find_cookie_value_end(char *s, const char *e)
{
	int quoted, qdpair;

	quoted = qdpair = 0;
	for (; s < e; s++) {
		if (qdpair)                    qdpair = 0;
		else if (quoted) {
			if (*s == '\\')        qdpair = 1;
			else if (*s == '"')    quoted = 0;
		}
		else if (*s == '"')            quoted = 1;
		else if (*s == ',' || *s == ';') return s;
	}
	return s;
}

/* Try to find the next occurrence of a cookie name in a cookie header value.
 * To match on any cookie name, <cookie_name_l> must be set to 0.
 * The lookup begins at <hdr>. The pointer and size of the next occurrence of
 * the cookie value is returned into *value and *value_l, and the function
 * returns a pointer to the next pointer to search from if the value was found.
 * Otherwise if the cookie was not found, NULL is returned and neither value
 * nor value_l are touched. The input <hdr> string should first point to the
 * header's value, and the <hdr_end> pointer must point to the first character
 * not part of the value. <list> must be non-zero if value may represent a list
 * of values (cookie headers). This makes it faster to abort parsing when no
 * list is expected.
 */
char *http_extract_cookie_value(char *hdr, const char *hdr_end,
                                char *cookie_name, size_t cookie_name_l,
                                int list, char **value, size_t *value_l)
{
	char *equal, *att_end, *att_beg, *val_beg, *val_end;
	char *next;

	/* we search at least a cookie name followed by an equal, and more
	 * generally something like this :
	 * Cookie:    NAME1  =  VALUE 1  ; NAME2 = VALUE2 ; NAME3 = VALUE3\r\n
	 */
	for (att_beg = hdr; att_beg + cookie_name_l + 1 < hdr_end; att_beg = next + 1) {
		/* Iterate through all cookies on this line */

		while (att_beg < hdr_end && HTTP_IS_SPHT(*att_beg))
			att_beg++;

		/* find att_end : this is the first character after the last non
		 * space before the equal. It may be equal to hdr_end.
		 */
		equal = att_end = att_beg;

		while (equal < hdr_end) {
			if (*equal == '=' || *equal == ';' || (list && *equal == ','))
				break;
			if (HTTP_IS_SPHT(*equal++))
				continue;
			att_end = equal;
		}

		/* here, <equal> points to '=', a delimiter or the end. <att_end>
		 * is between <att_beg> and <equal>, both may be identical.
		 */

		/* look for end of cookie if there is an equal sign */
		if (equal < hdr_end && *equal == '=') {
			/* look for the beginning of the value */
			val_beg = equal + 1;
			while (val_beg < hdr_end && HTTP_IS_SPHT(*val_beg))
				val_beg++;

			/* find the end of the value, respecting quotes */
			next = http_find_cookie_value_end(val_beg, hdr_end);

			/* make val_end point to the first white space or delimiter after the value */
			val_end = next;
			while (val_end > val_beg && HTTP_IS_SPHT(*(val_end - 1)))
				val_end--;
		} else {
			val_beg = val_end = next = equal;
		}

		/* We have nothing to do with attributes beginning with '$'. However,
		 * they will automatically be removed if a header before them is removed,
		 * since they're supposed to be linked together.
		 */
		if (*att_beg == '$')
			continue;

		/* Ignore cookies with no equal sign */
		if (equal == next)
			continue;

		/* Now we have the cookie name between att_beg and att_end, and
		 * its value between val_beg and val_end.
		 */

		if (cookie_name_l == 0 || (att_end - att_beg == cookie_name_l &&
		    memcmp(att_beg, cookie_name, cookie_name_l) == 0)) {
			/* let's return this value and indicate where to go on from */
			*value = val_beg;
			*value_l = val_end - val_beg;
			return next + 1;
		}

		/* Set-Cookie headers only have the name in the first attr=value part */
		if (!list)
			break;
	}

	return NULL;
}

/* Parses a qvalue and returns it multiplied by 1000, from 0 to 1000. If the
 * value is larger than 1000, it is bound to 1000. The parser consumes up to
 * 1 digit, one dot and 3 digits and stops on the first invalid character.
 * Unparsable qvalues return 1000 as "q=1.000".
 */
int http_parse_qvalue(const char *qvalue, const char **end)
{
	int q = 1000;

	if (!isdigit((unsigned char)*qvalue))
		goto out;
	q = (*qvalue++ - '0') * 1000;

	if (*qvalue++ != '.')
		goto out;

	if (!isdigit((unsigned char)*qvalue))
		goto out;
	q += (*qvalue++ - '0') * 100;

	if (!isdigit((unsigned char)*qvalue))
		goto out;
	q += (*qvalue++ - '0') * 10;

	if (!isdigit((unsigned char)*qvalue))
		goto out;
	q += (*qvalue++ - '0') * 1;
 out:
	if (q > 1000)
		q = 1000;
	if (end)
		*end = qvalue;
	return q;
}

/*
 * Given a url parameter, find the starting position of the first occurrence,
 * or NULL if the parameter is not found.
 *
 * Example: if query_string is "yo=mama;ye=daddy" and url_param_name is "ye",
 * the function will return query_string+8.
 *
 * Warning: this function returns a pointer that can point to the first chunk
 * or the second chunk. The caller must be check the position before using the
 * result.
 */
const char *http_find_url_param_pos(const char **chunks,
                                    const char* url_param_name, size_t url_param_name_l,
                                    char delim)
{
	const char *pos, *last, *equal;
	const char **bufs = chunks;
	int l1, l2;


	pos  = bufs[0];
	last = bufs[1];
	while (pos < last) {
		/* Check the equal. */
		equal = pos + url_param_name_l;
		if (fix_pointer_if_wrap(chunks, &equal)) {
			if (equal >= chunks[3])
				return NULL;
		} else {
			if (equal >= chunks[1])
				return NULL;
		}
		if (*equal == '=') {
			if (pos + url_param_name_l > last) {
				/* process wrap case, we detect a wrap. In this case, the
				 * comparison is performed in two parts.
				 */

				/* This is the end, we dont have any other chunk. */
				if (bufs != chunks || !bufs[2])
					return NULL;

				/* Compute the length of each part of the comparison. */
				l1 = last - pos;
				l2 = url_param_name_l - l1;

				/* The second buffer is too short to contain the compared string. */
				if (bufs[2] + l2 > bufs[3])
					return NULL;

				if (memcmp(pos,     url_param_name,    l1) == 0 &&
				    memcmp(bufs[2], url_param_name+l1, l2) == 0)
					return pos;

				/* Perform wrapping and jump the string who fail the comparison. */
				bufs += 2;
				pos = bufs[0] + l2;
				last = bufs[1];

			} else {
				/* process a simple comparison. */
				if (memcmp(pos, url_param_name, url_param_name_l) == 0)
					return pos;
				pos += url_param_name_l + 1;
				if (fix_pointer_if_wrap(chunks, &pos))
					last = bufs[2];
			}
		}

		while (1) {
			/* Look for the next delimiter. */
			while (pos < last && !http_is_param_delimiter(*pos, delim))
				pos++;
			if (pos < last)
				break;
			/* process buffer wrapping. */
			if (bufs != chunks || !bufs[2])
				return NULL;
			bufs += 2;
			pos = bufs[0];
			last = bufs[1];
		}
		pos++;
	}
	return NULL;
}

/*
 * Given a url parameter name and a query string, find the next value.
 * An empty url_param_name matches the first available parameter.
 * If the parameter is found, 1 is returned and *vstart / *vend are updated to
 * respectively provide a pointer to the value and its end.
 * Otherwise, 0 is returned and vstart/vend are not modified.
 */
int http_find_next_url_param(const char **chunks,
                             const char* url_param_name, size_t url_param_name_l,
                             const char **vstart, const char **vend, char delim)
{
	const char *arg_start, *qs_end;
	const char *value_start, *value_end;

	arg_start = chunks[0];
	qs_end = chunks[1];
	if (url_param_name_l) {
		/* Looks for an argument name. */
		arg_start = http_find_url_param_pos(chunks,
		                                    url_param_name, url_param_name_l,
		                                    delim);
		/* Check for wrapping. */
		if (arg_start >= qs_end)
			qs_end = chunks[3];
	}
	if (!arg_start)
		return 0;

	if (!url_param_name_l) {
		while (1) {
			/* looks for the first argument. */
			value_start = memchr(arg_start, '=', qs_end - arg_start);
			if (!value_start) {
				/* Check for wrapping. */
				if (arg_start >= chunks[0] &&
				    arg_start < chunks[1] &&
				    chunks[2]) {
					arg_start = chunks[2];
					qs_end = chunks[3];
					continue;
				}
				return 0;
			}
			break;
		}
		value_start++;
	}
	else {
		/* Jump the argument length. */
		value_start = arg_start + url_param_name_l + 1;

		/* Check for pointer wrapping. */
		if (fix_pointer_if_wrap(chunks, &value_start)) {
			/* Update the end pointer. */
			qs_end = chunks[3];

			/* Check for overflow. */
			if (value_start >= qs_end)
				return 0;
		}
	}

	value_end = value_start;

	while (1) {
		while ((value_end < qs_end) && !http_is_param_delimiter(*value_end, delim))
			value_end++;
		if (value_end < qs_end)
			break;
		/* process buffer wrapping. */
		if (value_end >= chunks[0] &&
		    value_end < chunks[1] &&
		    chunks[2]) {
			value_end = chunks[2];
			qs_end = chunks[3];
			continue;
		}
		break;
	}

	*vstart = value_start;
	*vend = value_end;
	return 1;
}

/* Parses a single header line (without the CRLF) and splits it into its name
 * and its value. The parsing is pretty naive and just skip spaces.
 */
int http_parse_header(const struct ist hdr, struct ist *name, struct ist *value)
{
        char *p   = hdr.ptr;
        char *end = p + hdr.len;

        name->len = value->len = 0;

        /* Skip leading spaces */
        for (; p < end && HTTP_IS_SPHT(*p); p++);

        /* Set the header name */
        name->ptr = p;
        for (; p < end && HTTP_IS_TOKEN(*p); p++);
        name->len = p - name->ptr;

        /* Skip the ':' and spaces before and after it */
        for (; p < end && HTTP_IS_SPHT(*p); p++);
        if (p < end && *p == ':') p++;
        for (; p < end && HTTP_IS_SPHT(*p); p++);

        /* Set the header value */
        value->ptr = p;
        value->len = end - p;

        return 1;
}

/* Parses a single start line (without the CRLF) and splits it into 3 parts. The
 * parsing is pretty naive and just skip spaces.
 */
int http_parse_stline(const struct ist line, struct ist *p1, struct ist *p2, struct ist *p3)
{
        char *p   = line.ptr;
        char *end = p + line.len;

        p1->len = p2->len = p3->len = 0;

        /* Skip leading spaces */
        for (; p < end && HTTP_IS_SPHT(*p); p++);

        /* Set the first part */
        p1->ptr = p;
        for (; p < end && HTTP_IS_TOKEN(*p); p++);
        p1->len = p - p1->ptr;

        /* Skip spaces between p1 and p2 */
        for (; p < end && HTTP_IS_SPHT(*p); p++);

        /* Set the second part */
        p2->ptr = p;
        for (; p < end && !HTTP_IS_SPHT(*p); p++);
        p2->len = p - p2->ptr;

        /* Skip spaces between p2 and p3 */
        for (; p < end && HTTP_IS_SPHT(*p); p++);

        /* The remaining is the third value */
        p3->ptr = p;
        p3->len = end - p;

        return 1;
}

/* Parses value of a Status header with the following format: "Status: Code[
 * Reason]".  The parsing is pretty naive and just skip spaces. It return the
 * numeric value of the status code.
 */
int http_parse_status_val(const struct ist value, struct ist *status, struct ist *reason)
{
	char *p   = value.ptr;
        char *end = p + value.len;
	uint16_t code;

	status->len = reason->len = 0;

	/* Skip leading spaces */
        for (; p < end && HTTP_IS_SPHT(*p); p++);

        /* Set the status part */
        status->ptr = p;
        for (; p < end && HTTP_IS_TOKEN(*p); p++);
        status->len = p - status->ptr;

	/* Skip spaces between status and reason */
        for (; p < end && HTTP_IS_SPHT(*p); p++);

	/* the remaining is the reason */
        reason->ptr = p;
        reason->len = end - p;

	code = strl2ui(status->ptr, status->len);
	return code;
}


/* Returns non-zero if the two ETags are comparable (see RFC 7232#2.3.2).
 * If any of them is a weak ETag, we discard the weakness prefix and perform
 * a strict string comparison.
 * Returns 0 otherwise.
 */
int http_compare_etags(struct ist etag1, struct ist etag2)
{
	enum http_etag_type etag_type1;
	enum http_etag_type etag_type2;

	etag_type1 = http_get_etag_type(etag1);
	etag_type2 = http_get_etag_type(etag2);

	if (etag_type1 == ETAG_INVALID || etag_type2 == ETAG_INVALID)
		return 0;

	/* Discard the 'W/' prefix an ETag is a weak one. */
	if (etag_type1 == ETAG_WEAK)
		etag1 = istadv(etag1, 2);
	if (etag_type2 == ETAG_WEAK)
		etag2 = istadv(etag2, 2);

	return isteq(etag1, etag2);
}


/*
 * Trim leading space or horizontal tab characters from <value> string.
 * Returns the trimmed string.
 */
struct ist http_trim_leading_spht(struct ist value)
{
	struct ist ret = value;

	while (ret.len && HTTP_IS_SPHT(ret.ptr[0])) {
		++ret.ptr;
		--ret.len;
	}

	return ret;
}

/*
 * Trim trailing space or horizontal tab characters from <value> string.
 * Returns the trimmed string.
 */
struct ist http_trim_trailing_spht(struct ist value)
{
	struct ist ret = value;

	while (ret.len && HTTP_IS_SPHT(ret.ptr[-1]))
		--ret.len;

	return ret;
}
