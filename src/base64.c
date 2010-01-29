/*
 * ASCII <-> Base64 conversion as described in RFC1421.
 *
 * Copyright 2006-2008 Willy Tarreau <w@1wt.eu>
 * Copyright 2009-2010 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>
#include <string.h>

#include <common/base64.h>
#include <common/config.h>

#define B64BASE	'#'		/* arbitrary chosen base value */
#define B64CMIN	'+'
#define B64CMAX	'z'
#define B64PADV	64		/* Base64 chosen special pad value */

const char base64tab[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char base64rev[]="b###cXYZ[\\]^_`a###d###$%&'()*+,-./0123456789:;<=######>?@ABCDEFGHIJKLMNOPQRSTUVW";

/* Encodes <ilen> bytes from <in> to <out> for at most <olen> chars (including
 * the trailing zero). Returns the number of bytes written. No check is made
 * for <in> or <out> to be NULL. Returns negative value if <olen> is too short
 * to accept <ilen>. 4 output bytes are produced for 1 to 3 input bytes.
 */
int a2base64(char *in, int ilen, char *out, int olen)
{
	int convlen;

	convlen = ((ilen + 2) / 3) * 4;

	if (convlen >= olen)
		return -1;

	/* we don't need to check olen anymore */
	while (ilen >= 3) {
		out[0] = base64tab[(((unsigned char)in[0]) >> 2)];
		out[1] = base64tab[(((unsigned char)in[0] & 0x03) << 4) | (((unsigned char)in[1]) >> 4)];
		out[2] = base64tab[(((unsigned char)in[1] & 0x0F) << 2) | (((unsigned char)in[2]) >> 6)];
		out[3] = base64tab[(((unsigned char)in[2] & 0x3F))];
		out += 4;
		in += 3; ilen -= 3;
	}
	
	if (!ilen) {
		out[0] = '\0';
	} else {
		out[0] = base64tab[((unsigned char)in[0]) >> 2];
		if (ilen == 1) {
			out[1] = base64tab[((unsigned char)in[0] & 0x03) << 4];
			out[2] = '=';
		} else {
			out[1] = base64tab[(((unsigned char)in[0] & 0x03) << 4) |
					(((unsigned char)in[1]) >> 4)];
			out[2] = base64tab[((unsigned char)in[1] & 0x0F) << 2];
		}
		out[3] = '=';
		out[4] = '\0';
	}

	return convlen;
}

/* Decodes <ilen> bytes from <in> to <out> for at most <olen> chars.
 * Returns the number of bytes converted. No check is made for
 * <in> or <out> to be NULL. Returns -1 if <in> is invalid or ilen
 * has wrong size, -2 if <olen> is too short.
 * 1 to 3 output bytes are produced for 4 input bytes.
 */
int base64dec(const char *in, size_t ilen, char *out, size_t olen) {

	unsigned char t[4];
	signed char b;
	int convlen = 0, i = 0, pad = 0;

	if (ilen % 4)
		return -1;

	if (olen < ilen / 4 * 3)
		return -2;

	while (ilen) {

		/* if (*p < B64CMIN || *p > B64CMAX) */
		b = (signed char)*in - B64CMIN;
		if ((unsigned char)b > (B64CMAX-B64CMIN))
			return -1;

		b = base64rev[b] - B64BASE - 1;

		/* b == -1: invalid character */
		if (b < 0)
			return -1;

		/* padding has to be continous */
		if (pad && b != B64PADV)
			return -1;

		/* valid padding: "XX==" or "XXX=", but never "X===" or "====" */
		if (pad && i < 2)
			return -1;

		if (b == B64PADV)
			pad++;

		t[i++] = b;

		if (i == 4) {
			/*
			 * WARNING: we allow to write little more data than we
			 * should, but the checks from the beginning of the
			 * functions guarantee that we can safely do that.
			 */

			/* xx000000 xx001111 xx111122 xx222222 */
			out[convlen]   = ((t[0] << 2) + (t[1] >> 4));
			out[convlen+1] = ((t[1] << 4) + (t[2] >> 2));
			out[convlen+2] = ((t[2] << 6) + (t[3] >> 0));

			convlen += 3-pad;

			pad = i = 0;
		}

		in++;
		ilen--;
	}

	return convlen;
}
