/*
 * fast fgets() replacement for log parsing
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * This function manages its own buffer and returns a pointer to that buffer
 * in order to avoid expensive memory copies. It also checks for line breaks
 * 32 or 64 bits at a time. It could be improved a lot using mmap() but we
 * would not be allowed to replace trailing \n with zeroes and we would be
 * limited to small log files on 32-bit machines.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#ifndef FGETS2_BUFSIZE
#define FGETS2_BUFSIZE		(256*1024)
#endif

/* return non-zero if the integer contains at least one zero byte */
static inline __attribute__((unused)) unsigned int has_zero32(unsigned int x)
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
	 * The order of operations below is important to save registers and
	 * tests. The result is used as a boolean, so the last test must apply
	 * on the constant so that it can efficiently be inlined.
	 */
#if defined(__i386__)
	/* gcc on x86 loves copying registers over and over even on code that
	 * simple, so let's do it by hand to prevent it from doing so :-(
	 */
	asm("lea -0x01010101(%0),%1\n"
	    "not %0\n"
	    "and %1,%0\n"
	    : "=a" (x), "=r"(y)
	    : "0" (x)
	    );
	return x & 0x80808080;
#else
	y = x - 0x01010101;  /* generate a carry */
	x = ~x & y;          /* clear the bits that were already set */
	return x & 0x80808080;
#endif
}

/* return non-zero if the argument contains at least one zero byte. See principle above. */
static inline __attribute__((unused)) unsigned long long has_zero64(unsigned long long x)
{
	unsigned long long y;

	y = x - 0x0101010101010101ULL; /* generate a carry */
	y &= ~x;                       /* clear the bits that were already set */
	return y & 0x8080808080808080ULL;
}

static inline __attribute__((unused)) unsigned long has_zero(unsigned long x)
{
	return (sizeof(x) == 8) ? has_zero64(x) : has_zero32(x);
}

/* find a '\n' between <next> and <end>. Warning: may read slightly past <end>.
 * If no '\n' is found, <end> is returned.
 */
static char *find_lf(char *next, char *end)
{
#if defined USE_MEMCHR
	/* some recent libc use platform-specific optimizations to provide more
	 * efficient byte search than below (eg: glibc 2.11 on x86_64).
	 */
	next = memchr(next, '\n', end - next);
	if (!next)
		next = end;
#else
	if (sizeof(long) == 4) {  /* 32-bit system */
		/* this is a speed-up, we read 32 bits at once and check for an
		 * LF character there. We stop if found then continue one at a
		 * time.
		 */
		while (next < end && (((unsigned long)next) & 3) && *next != '\n')
			next++;

		/* Now next is multiple of 4 or equal to end. We know we can safely
		 * read up to 32 bytes past end if needed because they're allocated.
		 */
		while (next < end) {
			if (has_zero32(*(unsigned int *)next ^ 0x0A0A0A0A))
				break;
			next += 4;
			if (has_zero32(*(unsigned int *)next ^ 0x0A0A0A0A))
				break;
			next += 4;
			if (has_zero32(*(unsigned int *)next ^ 0x0A0A0A0A))
				break;
			next += 4;
			if (has_zero32(*(unsigned int *)next ^ 0x0A0A0A0A))
				break;
			next += 4;
			if (has_zero32(*(unsigned int *)next ^ 0x0A0A0A0A))
				break;
			next += 4;
			if (has_zero32(*(unsigned int *)next ^ 0x0A0A0A0A))
				break;
			next += 4;
			if (has_zero32(*(unsigned int *)next ^ 0x0A0A0A0A))
				break;
			next += 4;
			if (has_zero32(*(unsigned int *)next ^ 0x0A0A0A0A))
				break;
			next += 4;
		}
	}
	else {  /* 64-bit system */
		/* this is a speed-up, we read 64 bits at once and check for an
		 * LF character there. We stop if found then continue one at a
		 * time.
		 */
		if (next <= end) {
			/* max 3 bytes tested here */
			while ((((unsigned long)next) & 3) && *next != '\n')
				next++;

			/* maybe we have can skip 4 more bytes */
			if ((((unsigned long)next) & 4) && !has_zero32(*(unsigned int *)next ^ 0x0A0A0A0AU))
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
		if (!has_zero32(*(unsigned int *)next ^ 0x0A0A0A0AU))
			next += 4;
	}

	/* We finish if needed : if <next> is below <end>, it means we
	 * found an LF in one of the 4 following bytes.
	 */
	while (next < end) {
		if (*next == '\n')
			break;
		next++;
	}
#endif
	return next;
}

const char *fgets2(FILE *stream)
{
	static char buffer[FGETS2_BUFSIZE + 68]; /* Note: +32 is enough on 32-bit systems */
	static char *end = buffer;
	static char *line = buffer;
	char *next;
	int ret;

	next = line;

	while (1) {
		next = find_lf(next, end);
		if (next < end) {
			const char *start = line;
			*next = '\0';
			line = next + 1;
			return start;
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
		*end = '\n';  /* make parser stop ASAP */
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
