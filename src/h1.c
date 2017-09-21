/*
 * HTTP/1 protocol analyzer
 *
 * Copyright 2000-2017 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>

#include <proto/h1.h>

/* It is about twice as fast on recent architectures to lookup a byte in a
 * table than to perform a boolean AND or OR between two tests. Refer to
 * RFC2616/RFC5234/RFC7230 for those chars. A token is any ASCII char that is
 * neither a separator nor a CTL char. An http ver_token is any ASCII which can
 * be found in an HTTP version, which includes 'H', 'T', 'P', '/', '.' and any
 * digit. Note: please do not overwrite values in assignment since gcc-2.95
 * will not handle them correctly. It's worth noting that chars 128..255 are
 * nothing, not even control chars.
 */
const unsigned char h1_char_classes[256] = {
	[  0] = H1_FLG_CTL,
	[  1] = H1_FLG_CTL,
	[  2] = H1_FLG_CTL,
	[  3] = H1_FLG_CTL,
	[  4] = H1_FLG_CTL,
	[  5] = H1_FLG_CTL,
	[  6] = H1_FLG_CTL,
	[  7] = H1_FLG_CTL,
	[  8] = H1_FLG_CTL,
	[  9] = H1_FLG_SPHT | H1_FLG_LWS | H1_FLG_SEP | H1_FLG_CTL,
	[ 10] = H1_FLG_CRLF | H1_FLG_LWS | H1_FLG_CTL,
	[ 11] = H1_FLG_CTL,
	[ 12] = H1_FLG_CTL,
	[ 13] = H1_FLG_CRLF | H1_FLG_LWS | H1_FLG_CTL,
	[ 14] = H1_FLG_CTL,
	[ 15] = H1_FLG_CTL,
	[ 16] = H1_FLG_CTL,
	[ 17] = H1_FLG_CTL,
	[ 18] = H1_FLG_CTL,
	[ 19] = H1_FLG_CTL,
	[ 20] = H1_FLG_CTL,
	[ 21] = H1_FLG_CTL,
	[ 22] = H1_FLG_CTL,
	[ 23] = H1_FLG_CTL,
	[ 24] = H1_FLG_CTL,
	[ 25] = H1_FLG_CTL,
	[ 26] = H1_FLG_CTL,
	[ 27] = H1_FLG_CTL,
	[ 28] = H1_FLG_CTL,
	[ 29] = H1_FLG_CTL,
	[ 30] = H1_FLG_CTL,
	[ 31] = H1_FLG_CTL,
	[' '] = H1_FLG_SPHT | H1_FLG_LWS | H1_FLG_SEP,
	['!'] = H1_FLG_TOK,
	['"'] = H1_FLG_SEP,
	['#'] = H1_FLG_TOK,
	['$'] = H1_FLG_TOK,
	['%'] = H1_FLG_TOK,
	['&'] = H1_FLG_TOK,
	[ 39] = H1_FLG_TOK,
	['('] = H1_FLG_SEP,
	[')'] = H1_FLG_SEP,
	['*'] = H1_FLG_TOK,
	['+'] = H1_FLG_TOK,
	[','] = H1_FLG_SEP,
	['-'] = H1_FLG_TOK,
	['.'] = H1_FLG_TOK | H1_FLG_VER,
	['/'] = H1_FLG_SEP | H1_FLG_VER,
	['0'] = H1_FLG_TOK | H1_FLG_VER,
	['1'] = H1_FLG_TOK | H1_FLG_VER,
	['2'] = H1_FLG_TOK | H1_FLG_VER,
	['3'] = H1_FLG_TOK | H1_FLG_VER,
	['4'] = H1_FLG_TOK | H1_FLG_VER,
	['5'] = H1_FLG_TOK | H1_FLG_VER,
	['6'] = H1_FLG_TOK | H1_FLG_VER,
	['7'] = H1_FLG_TOK | H1_FLG_VER,
	['8'] = H1_FLG_TOK | H1_FLG_VER,
	['9'] = H1_FLG_TOK | H1_FLG_VER,
	[':'] = H1_FLG_SEP,
	[';'] = H1_FLG_SEP,
	['<'] = H1_FLG_SEP,
	['='] = H1_FLG_SEP,
	['>'] = H1_FLG_SEP,
	['?'] = H1_FLG_SEP,
	['@'] = H1_FLG_SEP,
	['A'] = H1_FLG_TOK,
	['B'] = H1_FLG_TOK,
	['C'] = H1_FLG_TOK,
	['D'] = H1_FLG_TOK,
	['E'] = H1_FLG_TOK,
	['F'] = H1_FLG_TOK,
	['G'] = H1_FLG_TOK,
	['H'] = H1_FLG_TOK | H1_FLG_VER,
	['I'] = H1_FLG_TOK,
	['J'] = H1_FLG_TOK,
	['K'] = H1_FLG_TOK,
	['L'] = H1_FLG_TOK,
	['M'] = H1_FLG_TOK,
	['N'] = H1_FLG_TOK,
	['O'] = H1_FLG_TOK,
	['P'] = H1_FLG_TOK | H1_FLG_VER,
	['Q'] = H1_FLG_TOK,
	['R'] = H1_FLG_TOK | H1_FLG_VER,
	['S'] = H1_FLG_TOK | H1_FLG_VER,
	['T'] = H1_FLG_TOK | H1_FLG_VER,
	['U'] = H1_FLG_TOK,
	['V'] = H1_FLG_TOK,
	['W'] = H1_FLG_TOK,
	['X'] = H1_FLG_TOK,
	['Y'] = H1_FLG_TOK,
	['Z'] = H1_FLG_TOK,
	['['] = H1_FLG_SEP,
	[ 92] = H1_FLG_SEP,
	[']'] = H1_FLG_SEP,
	['^'] = H1_FLG_TOK,
	['_'] = H1_FLG_TOK,
	['`'] = H1_FLG_TOK,
	['a'] = H1_FLG_TOK,
	['b'] = H1_FLG_TOK,
	['c'] = H1_FLG_TOK,
	['d'] = H1_FLG_TOK,
	['e'] = H1_FLG_TOK,
	['f'] = H1_FLG_TOK,
	['g'] = H1_FLG_TOK,
	['h'] = H1_FLG_TOK,
	['i'] = H1_FLG_TOK,
	['j'] = H1_FLG_TOK,
	['k'] = H1_FLG_TOK,
	['l'] = H1_FLG_TOK,
	['m'] = H1_FLG_TOK,
	['n'] = H1_FLG_TOK,
	['o'] = H1_FLG_TOK,
	['p'] = H1_FLG_TOK,
	['q'] = H1_FLG_TOK,
	['r'] = H1_FLG_TOK,
	['s'] = H1_FLG_TOK,
	['t'] = H1_FLG_TOK,
	['u'] = H1_FLG_TOK,
	['v'] = H1_FLG_TOK,
	['w'] = H1_FLG_TOK,
	['x'] = H1_FLG_TOK,
	['y'] = H1_FLG_TOK,
	['z'] = H1_FLG_TOK,
	['{'] = H1_FLG_SEP,
	['|'] = H1_FLG_TOK,
	['}'] = H1_FLG_SEP,
	['~'] = H1_FLG_TOK,
	[127] = H1_FLG_CTL,
};


/* This function skips trailers in the buffer associated with HTTP message
 * <msg>. The first visited position is msg->next. If the end of the trailers is
 * found, the function returns >0. So, the caller can automatically schedul it
 * to be forwarded, and switch msg->msg_state to HTTP_MSG_DONE. If not enough
 * data are available, the function does not change anything except maybe
 * msg->sol if it could parse some lines, and returns zero.  If a parse error
 * is encountered, the function returns < 0 and does not change anything except
 * maybe msg->sol. Note that the message must already be in HTTP_MSG_TRAILERS
 * state before calling this function, which implies that all non-trailers data
 * have already been scheduled for forwarding, and that msg->next exactly
 * matches the length of trailers already parsed and not forwarded. It is also
 * important to note that this function is designed to be able to parse wrapped
 * headers at end of buffer.
 */
int http_forward_trailers(struct http_msg *msg)
{
	const struct buffer *buf = msg->chn->buf;

	/* we have msg->next which points to next line. Look for CRLF. But
	 * first, we reset msg->sol */
	msg->sol = 0;
	while (1) {
		const char *p1 = NULL, *p2 = NULL;
		const char *start = b_ptr(buf, msg->next + msg->sol);
		const char *stop  = bi_end(buf);
		const char *ptr   = start;
		int bytes = 0;

		/* scan current line and stop at LF or CRLF */
		while (1) {
			if (ptr == stop)
				return 0;

			if (*ptr == '\n') {
				if (!p1)
					p1 = ptr;
				p2 = ptr;
				break;
			}

			if (*ptr == '\r') {
				if (p1) {
					msg->err_pos = buffer_count(buf, buf->p, ptr);
					return -1;
				}
				p1 = ptr;
			}

			ptr++;
			if (ptr >= buf->data + buf->size)
				ptr = buf->data;
		}

		/* after LF; point to beginning of next line */
		p2++;
		if (p2 >= buf->data + buf->size)
			p2 = buf->data;

		bytes = p2 - start;
		if (bytes < 0)
			bytes += buf->size;
		msg->sol += bytes;

		/* LF/CRLF at beginning of line => end of trailers at p2.
		 * Everything was scheduled for forwarding, there's nothing left
		 * from this message. */
		if (p1 == start)
			return 1;

		/* OK, next line then */
	}
}
