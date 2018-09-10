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
#include <common/standard.h>

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

/* We must put the messages here since GCC cannot initialize consts depending
 * on strlen().
 */
struct buffer http_err_chunks[HTTP_ERR_SIZE];

const struct ist HTTP_100 = IST("HTTP/1.1 100 Continue\r\n\r\n");

/* Warning: no "connection" header is provided with the 3xx messages below */
const char *HTTP_301 =
	"HTTP/1.1 301 Moved Permanently\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

const char *HTTP_302 =
	"HTTP/1.1 302 Found\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* same as 302 except that the browser MUST retry with the GET method */
const char *HTTP_303 =
	"HTTP/1.1 303 See Other\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* same as 302 except that the browser MUST retry with the same method */
const char *HTTP_307 =
	"HTTP/1.1 307 Temporary Redirect\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* same as 301 except that the browser MUST retry with the same method */
const char *HTTP_308 =
	"HTTP/1.1 308 Permanent Redirect\r\n"
	"Content-length: 0\r\n"
	"Location: "; /* not terminated since it will be concatenated with the URL */

/* Warning: this one is an sprintf() fmt string, with <realm> as its only argument */
const char *HTTP_401_fmt =
	"HTTP/1.0 401 Unauthorized\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"WWW-Authenticate: Basic realm=\"%s\"\r\n"
	"\r\n"
	"<html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n";

const char *HTTP_407_fmt =
	"HTTP/1.0 407 Unauthorized\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"Proxy-Authenticate: Basic realm=\"%s\"\r\n"
	"\r\n"
	"<html><body><h1>407 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n";

const int http_err_codes[HTTP_ERR_SIZE] = {
	[HTTP_ERR_200] = 200,  /* used by "monitor-uri" */
	[HTTP_ERR_400] = 400,
	[HTTP_ERR_403] = 403,
	[HTTP_ERR_405] = 405,
	[HTTP_ERR_408] = 408,
	[HTTP_ERR_421] = 421,
	[HTTP_ERR_425] = 425,
	[HTTP_ERR_429] = 429,
	[HTTP_ERR_500] = 500,
	[HTTP_ERR_502] = 502,
	[HTTP_ERR_503] = 503,
	[HTTP_ERR_504] = 504,
};

static const char *http_err_msgs[HTTP_ERR_SIZE] = {
	[HTTP_ERR_200] =
	"HTTP/1.0 200 OK\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n",

	[HTTP_ERR_400] =
	"HTTP/1.0 400 Bad request\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request.\n</body></html>\n",

	[HTTP_ERR_403] =
	"HTTP/1.0 403 Forbidden\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>\n",

	[HTTP_ERR_405] =
	"HTTP/1.0 405 Method Not Allowed\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>405 Method Not Allowed</h1>\nA request was made of a resource using a request method not supported by that resource\n</body></html>\n",

	[HTTP_ERR_408] =
	"HTTP/1.0 408 Request Time-out\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time.\n</body></html>\n",

	[HTTP_ERR_421] =
	"HTTP/1.0 421 Misdirected Request\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>421 Misdirected Request</h1>\nRequest sent to a non-authoritative server.\n</body></html>\n",

	[HTTP_ERR_425] =
	"HTTP/1.0 425 Too Early\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>425 Too Early</h1>\nYour browser sent early data.\n</body></html>\n",

	[HTTP_ERR_429] =
	"HTTP/1.0 429 Too Many Requests\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>429 Too Many Requests</h1>\nYou have sent too many requests in a given amount of time.\n</body></html>\n",

	[HTTP_ERR_500] =
	"HTTP/1.0 500 Internal Server Error\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>500 Internal Server Error</h1>\nAn internal server error occured.\n</body></html>\n",

	[HTTP_ERR_502] =
	"HTTP/1.0 502 Bad Gateway\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response.\n</body></html>\n",

	[HTTP_ERR_503] =
	"HTTP/1.0 503 Service Unavailable\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n",

	[HTTP_ERR_504] =
	"HTTP/1.0 504 Gateway Time-out\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
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
const int http_get_status_idx(unsigned int status)
{
	switch (status) {
	case 200: return HTTP_ERR_200;
	case 400: return HTTP_ERR_400;
	case 403: return HTTP_ERR_403;
	case 405: return HTTP_ERR_405;
	case 408: return HTTP_ERR_408;
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
	case 506: return "Variant also negociate";
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
	return ist2(NULL, 0);
}

/* post-initializes the HTTP parts. Returns non-zero on error, with <err>
 * pointing to the error message.
 */
int init_http(char **err)
{
	int msg;

	for (msg = 0; msg < HTTP_ERR_SIZE; msg++) {
		if (!http_err_msgs[msg]) {
			memprintf(err, "Internal error: no message defined for HTTP return code %d", msg);
			return 0;
		}

		http_err_chunks[msg].area = (char *)http_err_msgs[msg];
		http_err_chunks[msg].data = strlen(http_err_msgs[msg]);
	}
	return 1;
}
