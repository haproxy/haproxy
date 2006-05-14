/*
 * Ascii to Base64 conversion as described in RFC1421.
 * Copyright 2006 Willy Tarreau <willy@w.ods.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef BASE64_H
#define BASE64_H

int a2base64(char *in, int ilen, char *out, int olen);

#endif /* BASE64_H */
