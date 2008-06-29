/*
 * Ascii to Base64 conversion as described in RFC1421.
 *
 * Copyright 2006-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/base64.h>
#include <common/config.h>

const char base64tab[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
