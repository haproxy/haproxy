/*
 * fast fgets() replacement for log parsing
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This function manages its own buffer and returns a pointer to that buffer
 * in order to avoid expensive memory copies. It also checks for line breaks
 * 32 bits at a time. It could be improved a lot using mmap() but we would
 * not be allowed to replace trailing \n with zeroes and we would be limited
 * to small log files on 32-bit machines.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

// return 1 if the integer contains at least one zero byte
static inline unsigned int has_zero(unsigned int x)
{
	if (!(x & 0xFF000000U) ||
	    !(x & 0xFF0000U) ||
	    !(x & 0xFF00U) ||
	    !(x & 0xFFU))
		return 1;
	return 0;
}

static inline unsigned int has_zero64(unsigned long long x)
{
	unsigned long long x2;

	x2 = x & (x >> 8);
	/* no need to split it further */
	if ((x2 & 0x00FF) && (x2 & 0x00FF0000) && (x2 & 0x00FF00000000ULL) && (x2 & 0x00FF000000000000ULL))
			return 0; // approx 11/12 return here

	if (!(x & 0xff00000000000000ULL) ||
	    !(x & 0xff000000000000ULL) ||
	    !(x & 0xff0000000000ULL) ||
	    !(x & 0xff00000000ULL) ||
	    !(x & 0xff000000UL) ||
	    !(x & 0xff0000UL) ||
	    !(x & 0xff00UL) ||
	    !(x & 0xffUL))
		return 1; // approx 1/3 of the remaining return here

	return 0;
}

#define FGETS2_BUFSIZE		(256*1024)
const char *fgets2(FILE *stream)
{
	static char buffer[FGETS2_BUFSIZE + 5];
	static char *end = buffer;
	static char *line = buffer;

	char *next;
	int ret;

	next = line;

	while (1) {
		/* this is a speed-up, we read 32 bits at once and check for an
		 * LF character there. We stop if found then continue one at a
		 * time.
		 */
		while (next < end && (((unsigned long)next) & 7) && *next != '\n')
			next++;

		/* now next is multiple of 4 or equal to end */
		while (next <= (end-32)) {
			if (has_zero64(*(unsigned long long *)next ^ 0x0A0A0A0A0A0A0A0AULL))
				break;
			next += 8;
			if (has_zero64(*(unsigned long long *)next ^ 0x0A0A0A0A0A0A0A0AULL))
				break;
			next += 8;
			if (has_zero64(*(unsigned long long *)next ^ 0x0A0A0A0A0A0A0A0AULL))
				break;
			next += 8;
			if (has_zero64(*(unsigned long long *)next ^ 0x0A0A0A0A0A0A0A0AULL))
				break;
			next += 8;
		}

		/* we finish if needed. Note that next might be slightly higher
		 * than end here because we might have gone past it above.
		 */
		while (next < end) {
			if (*next == '\n') {
				const char *start = line;

				*next = '\0';
				line = next + 1;
				return start;
			}
			next++;
		}

		/* we found an incomplete line. First, let's move the
		 * remaining part of the buffer to the beginning, then
		 * try to complete the buffer with a new read.
		 */
		if (line > buffer) {
			if (end != line)
				memmove(buffer, line, end - line);
			end = buffer + (end - line);
			next = end;
			line = buffer;
		} else {
			if (end == buffer + FGETS2_BUFSIZE)
				return NULL;
		}

		ret = read(fileno(stream), end, buffer + FGETS2_BUFSIZE - end);

		if (ret <= 0) {
			if (end == line)
				return NULL;

			*end = '\0';
			return line;
		}

		end += ret;
		/* search for '\n' again */
	}
}

#ifdef BENCHMARK
int main() {
	const char *p;
	unsigned int lines = 0;

	while ((p=fgets2(stdin)))
		lines++;
	printf("lines=%d\n", lines);
	return 0;
}
#endif
