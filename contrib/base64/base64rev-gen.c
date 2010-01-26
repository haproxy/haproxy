/*
 * base64rev generator
 *
 * Copyright 2009-2010 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>

const char base64tab[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char base64rev[128];

#define base '#'	/* arbitrary chosen base value */
#define B64MAX	64
#define B64PADV B64MAX

int main() {
	char *p, c;
	int i, min = 255, max = 0;

	for (i = 0; i < sizeof(base64rev); i++)
		base64rev[i] = base;

	for (i = 0;  i < B64MAX; i++) {
		c = base64tab[i];

		if (min > c)
			min = c;

		if (max < c)
			max = c;
	}

	for (i = 0;  i < B64MAX; i++) {
		c = base64tab[i];

		if (base+i+1 > 127) {
			printf("Wrong base value @%d\n", i);
			return 1;
		}

		base64rev[c - min] = base+i+1;
	}

	base64rev['=' - min] = base + B64PADV;

	base64rev[max - min + 1] = '\0';

	printf("#define B64BASE '%c'\n", base);
	printf("#define B64CMIN '%c'\n", min);
	printf("#define B64CMAX '%c'\n", max);
	printf("#define B64PADV %u\n", B64PADV);

	p = base64rev;
	printf("const char base64rev[]=\"");
	for (p = base64rev; *p; p++) {
		if (*p == '\\')
			printf("\\%c", *p);
		else
			printf("%c", *p);
	}
	printf("\"\n");

	return 0;
}
