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

// return non-zero if the integer contains at least one zero byte
static inline unsigned int has_zero(unsigned int x)
{
	unsigned int y;

	/* Principle: we want to perform 4 tests on one 32-bit int at once. For
	 * this, we have to simulate an SIMD instruction which we don't have by
	 * default. The principle is that a zero byte is the only one which
	 * will cause a 1 to appear on the upper bit of a byte/word/etc... when
	 * we subtract 1. So we can detect a zero byte if a one appears at any
	 * of the bits 7, 15, 23 or 31 where it was not. It takes only one
	 * instruction to test for the presence of any of these bits, but it is
	 * still complex to check for their initial absence. Thus, we'll
	 * proceed differently : we first save and clear only those bits, then
	 * we check in the final result if one of them is present and was not.
	 */
	y = x;
        y -= 0x01010101;    /* generate a carry */
        y &= ~x;             /* clear the bits that were already set */
        return y & 0x80808080;
}


// return non-zero if the argument contains at least one zero byte. See principle above.
static inline unsigned long long has_zero64(unsigned long long x)
{
	unsigned long long y;

	y = x;
	y -= 0x0101010101010101ULL;     /* generate a carry */
	y &= ~x;                        /* clear the bits that were already set */
	return y & 0x8080808080808080ULL;
}

#define FGETS2_BUFSIZE		(256*1024)
const char *fgets2(FILE *stream)
{
	static char buffer[FGETS2_BUFSIZE + 68];
	static char *end = buffer;
	static char *line = buffer;

	char *next;
	int ret;

	next = line;

	while (1) {
		/* this is a speed-up, we read 64 bits at once and check for an
		 * LF character there. We stop if found then continue one at a
		 * time.
		 */

		if (next <= end) {
			/* max 3 bytes tested here */
			while ((((unsigned long)next) & 3) && *next != '\n')
				next++;

			/* maybe we have can skip 4 more bytes */
			if ((((unsigned long)next) & 4) && !has_zero(*(unsigned int *)next ^ 0x0A0A0A0AU))
				next += 4;
		}

		/* now next is multiple of 8 or equal to end */
		while (next <= (end-68)) {
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

		/* maybe we can skip 4 more bytes */
		if (!has_zero(*(unsigned int *)next ^ 0x0A0A0A0AU))
			next += 4;

		/* We finish if needed : if <next> is below <end>, it means we
		 * found an LF in one of the 4 following bytes.
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
		 * try to complete the buffer with a new read. We can't
		 * rely on <next> anymore because it went past <end>.
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
			end = line; /* ensure we stop next time */
			return line;
		}

		end += ret;
		*end = '\n'; /* make parser stop ASAP */
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
