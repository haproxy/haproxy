/*
 * Function call tracing for gcc >= 2.95
 * WARNING! THIS CODE IS NOT THREAD-SAFE!
 *
 * Copyright 2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * gcc is able to call a specific function when entering and leaving any
 * function when compiled with -finstrument-functions. This code must not
 * be built with this argument. The performance impact is huge, so this
 * feature should only be used when debugging.
 *
 * The entry and exits of all functions will be dumped into a file designated
 * by the HAPROXY_TRACE environment variable, or by default "trace.out". If the
 * trace file name is empty or "/dev/null", then traces are disabled. If
 * opening the trace file fails, then stderr is used. If HAPROXY_TRACE_FAST is
 * used, then the time is taken from the global <now> variable. Last, if
 * HAPROXY_TRACE_TSC is used, then the machine's TSC is used instead of the
 * real time (almost twice as fast).
 *
 * The output format is :
 *
 *   <sec.usec> <level> <caller_ptr> <dir> <callee_ptr>
 *  or :
 *   <tsc> <level> <caller_ptr> <dir> <callee_ptr>
 *
 * where <dir> is '>' when entering a function and '<' when leaving.
 *
 * It is also possible to emit comments using the calltrace() function which uses
 * the printf() format. Such comments are then inserted by replacing the caller
 * pointer with a sharp ('#') like this :
 *
 *   <sec.usec> <level> # <comment>
 *  or :
 *   <tsc> <level> # <comment>
 *
 * The article below is a nice explanation of how this works :
 *   http://balau82.wordpress.com/2010/10/06/trace-and-profile-function-calls-with-gcc/
 */

#include <sys/time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <common/compiler.h>
#include <common/time.h>

static FILE *log;
static int level;
static int disabled;
static int fast_time;
static int use_tsc;
static struct timeval trace_now;
static struct timeval *now_ptr;
static char line[128]; /* more than enough for a message (9+1+6+1+3+1+18+1+1+18+1+1) */

static int open_trace()
{
	const char *output = getenv("HAPROXY_TRACE");

	if (!output)
		output = "trace.out";

	if (!*output || strcmp(output, "/dev/null") == 0) {
		disabled = 1;
		return 0;
	}

	log = fopen(output, "w");
	if (!log)
		log = stderr;

	now_ptr = &now;
	if (getenv("HAPROXY_TRACE_FAST") != NULL) {
		fast_time = 1;
		now_ptr = &trace_now;
	}
	if (getenv("HAPROXY_TRACE_TSC") != NULL) {
		fast_time = 1;
		use_tsc = 1;
	}
	return 1;
}

/* This function first divides the number by 100M then iteratively multiplies it
 * by 100 (using adds and shifts). The trick is that dividing by 100M is equivalent
 * to multiplying by 1/100M, which approximates to 1441151881/2^57. All local
 * variables fit in registers on x86. This version outputs two digits per round.
 * <min_pairs> indicates the minimum number of pairs of digits that have to be
 * emitted, which might be left-padded with zeroes.
 * It returns the pointer to the ending '\0'.
 */
static char *ultoad2(unsigned int x, char *out, int min_pairs)
{
	unsigned int q;
	char *p = out;
	int pos = 4;
	unsigned long long y;

	static const unsigned short bcd[100] = {
		0x3030, 0x3130, 0x3230, 0x3330, 0x3430, 0x3530, 0x3630, 0x3730, 0x3830, 0x3930,
		0x3031, 0x3131, 0x3231, 0x3331, 0x3431, 0x3531, 0x3631, 0x3731, 0x3831, 0x3931,
		0x3032, 0x3132, 0x3232, 0x3332, 0x3432, 0x3532, 0x3632, 0x3732, 0x3832, 0x3932,
		0x3033, 0x3133, 0x3233, 0x3333, 0x3433, 0x3533, 0x3633, 0x3733, 0x3833, 0x3933,
		0x3034, 0x3134, 0x3234, 0x3334, 0x3434, 0x3534, 0x3634, 0x3734, 0x3834, 0x3934,
		0x3035, 0x3135, 0x3235, 0x3335, 0x3435, 0x3535, 0x3635, 0x3735, 0x3835, 0x3935,
		0x3036, 0x3136, 0x3236, 0x3336, 0x3436, 0x3536, 0x3636, 0x3736, 0x3836, 0x3936,
		0x3037, 0x3137, 0x3237, 0x3337, 0x3437, 0x3537, 0x3637, 0x3737, 0x3837, 0x3937,
		0x3038, 0x3138, 0x3238, 0x3338, 0x3438, 0x3538, 0x3638, 0x3738, 0x3838, 0x3938,
		0x3039, 0x3139, 0x3239, 0x3339, 0x3439, 0x3539, 0x3639, 0x3739, 0x3839, 0x3939 };

	y = x * 1441151881ULL;  /* y>>57 will be the integer part of x/100M */
	while (1) {
		q = y >> 57;
		/* Q is composed of the first digit in the lower byte and the second
		 * digit in the higher byte.
		 */
		if (p != out || q > 9 || pos < min_pairs) {
#if defined(__i386__) || defined(__x86_64__)
			/* unaligned accesses are fast on x86 */
			*(unsigned short *)p = bcd[q];
			p += 2;
#else
			*(p++) = bcd[q];
			*(p++) = bcd[q] >> 8;
#endif
		}
		else if (q || !pos) {
			/* only at most one digit */
			*(p++) = bcd[q] >> 8;
		}
		if (--pos < 0)
			break;

		y &= 0x1FFFFFFFFFFFFFFULL;  // remainder

		if (sizeof(long) >= sizeof(long long)) {
			/* shifting is preferred on 64-bit archs, while mult is faster on 32-bit.
			 * We multiply by 100 by doing *5, *5 and *4, all of which are trivial.
			 */
			y += (y << 2);
			y += (y << 2);
			y <<= 2;
		}
		else
			y *= 100;
	}

	*p = '\0';
	return p;
}

/* Send <h> as hex into <out>. Returns the pointer to the ending '\0'. */
static char *emit_hex(unsigned long h, char *out)
{
	static unsigned char hextab[16] = "0123456789abcdef";
	int shift = sizeof(h) * 8 - 4;
	unsigned int idx;

	do {
		idx = (h >> shift);
		if (idx || !shift)
			*out++ = hextab[idx & 15];
		shift -= 4;
	} while (shift >= 0);
	*out = '\0';
	return out;
}

static void make_line(void *from, void *to, int level, char dir, long ret)
{
	char *p = line;

	if (unlikely(!log) && !open_trace())
		return;

	if (unlikely(!fast_time))
		gettimeofday(now_ptr, NULL);

#ifdef USE_SLOW_FPRINTF
	if (!use_tsc)
		fprintf(log, "%u.%06u %d %p %c %p\n",
			(unsigned int)now_ptr->tv_sec,
			(unsigned int)now_ptr->tv_usec,
			level, from, dir, to);
	else
		fprintf(log, "%llx %d %p %c %p\n",
			rdtsc(), level, from, dir, to);
	return;
#endif

	if (unlikely(!use_tsc)) {
		/* "%u.06u", tv_sec, tv_usec */
		p = ultoad2(now_ptr->tv_sec, p, 0);
		*p++ = '.';
		p = ultoad2(now_ptr->tv_usec, p, 3);
	} else {
		/* "%08x%08x", high, low */
		unsigned long long t = rdtsc();
		if (sizeof(long) < sizeof(long long))
			p = emit_hex((unsigned long)(t >> 32U), p);
		p = emit_hex((unsigned long)(t), p);
	}

	/* " %u", level */
	*p++ = ' ';
	p = ultoad2(level, p, 0);

	/* " %p", from */
	*p++ = ' '; *p++ = '0'; *p++ = 'x';
	p = emit_hex((unsigned long)from, p);

	/* " %c", dir */
	*p++ = ' '; *p++ = dir;

	/* " %p", to */
	*p++ = ' '; *p++ = '0'; *p++ = 'x';
	p = emit_hex((unsigned long)to, p);

	if (dir == '<') {
		/* " %x", ret */
		*p++ = ' '; *p++ = '0'; *p++ = 'x';
		p = emit_hex(ret, p);
	}

	*p++ = '\n';

	fwrite(line, p - line, 1, log);
}

/* These are the functions GCC calls */
void __cyg_profile_func_enter(void *to,  void *from)
{
	if (!disabled)
		return make_line(from, to, ++level, '>', 0);
}

void __cyg_profile_func_exit(void *to,  void *from)
{
	long ret = 0;

#if defined(__x86_64__)
	/* on x86_64, the return value (eax) is temporarily stored in ebx
	 * during the call to __cyg_profile_func_exit() so we can snoop it.
	 */
	asm volatile("mov %%rbx, %0" : "=r"(ret));
#endif
	if (!disabled)
		return make_line(from, to, level--, '<', ret);
}

/* the one adds comments in the trace above. The output format is :
 * <timestamp> <level> # <string>
 */
__attribute__((format(printf, 1, 2)))
void calltrace(char *fmt, ...)
{
	va_list ap;

	if (unlikely(!log) && !open_trace())
		return;

	if (unlikely(!fast_time))
		gettimeofday(now_ptr, NULL);

	if (!use_tsc)
		fprintf(log, "%u.%06u %d # ",
			(unsigned int)now_ptr->tv_sec,
			(unsigned int)now_ptr->tv_usec,
			level + 1);
	else
		fprintf(log, "%llx %d # ",
			rdtsc(), level + 1);

	va_start(ap, fmt);
	vfprintf(log, fmt, ap);
	va_end(ap);
	fputc('\n', log);
	fflush(log);
}
