/*
 * include/haproxy/show_flags.h
 * These are helper macros used to decode flags for debugging
 *
 * Copyright (C) 2022 Willy Tarreau - w@1wt.eu
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_SHOW_FLAGS_H
#define _HAPROXY_SHOW_FLAGS_H

/* Only define the macro below if the caller requests it using HA_EXPOSE_FLAGS.
 * It will be used by many low-level includes and we don't want to
 * include the huge stdio here by default. The macro is used to make a string
 * of a set of flags (and handles one flag at a time). It will append into
 * <_buf>:<_len> the state of flag <_val> in <_flg>, appending string <_del> as
 * delimiters till the last flag is dumped, then updating <_buf> and <_len>
 * accordingly. <_nam> is used as the name for value <_val>. <_flg> loses all
 * dumped flags. If <_flg> is zero and <_val> is 0, a "0" is reported, this can
 * be used as a prologue to the dump. If <_val> contains more than one bit set,
 * <_flg>'s hexadecimal output is reported instead of a name.
 *
 * It is possible to use it to enumerate all flags from right to left so that
 * they are easier to check in the code. It will start by executing the optional
 * code block in the extra flags (if any) before proceeding with the dump using
 * the arguments. It is suggested to locally rename it to a single-char macro
 * locally for readability, e.g:
 *
 *    #define _(n, ...) __APPEND_FLAG(buf, len, del, flg, n, #n, __VA_ARGS__)
 *       _(0);
 *       _(X_FLAG1, _(X_FLAG2, _(X_FLAG3)));
 *       _(~0);
 *    #undef _
 *
 * __APPEND_ENUM() works a bit differently in that it takes an additional mask
 * to isolate bits to compare to the enum's value, and will remove the mask's
 * bits at once in case of match.
 */
#ifdef HA_EXPOSE_FLAGS

#define __APPEND_FLAG(_buf, _len, _del, _flg, _val, _nam, ...)			\
	do {									\
		size_t _ret = 0;						\
		unsigned int _flg0 = (_flg);					\
		do { __VA_ARGS__; } while (0);					\
		(_flg) &= ~(unsigned int)(_val);				\
		if (!((unsigned int)_val) && !(_flg))				\
			_ret = snprintf(_buf, _len, "0%s",			\
					(_flg) ? (_del) : "");			\
		else if ((_flg0) & (_val)) {					\
			if ((_val) & ((_val) - 1))				\
				_ret = snprintf(_buf, _len, "%#x%s",		\
						(_flg0), (_flg) ? (_del) : "");	\
			else							\
				_ret = snprintf(_buf, _len, _nam "%s",		\
						(_flg) ? (_del) : "");		\
		}								\
		if (_ret < _len) {						\
			_len -= _ret;						\
			_buf += _ret;						\
		}								\
	} while (0)

#define __APPEND_ENUM(_buf, _len, _del, _flg, _msk, _val, _nam, ...)	\
	do {								\
		size_t _ret = 0;					\
		do { __VA_ARGS__; } while (0);				\
		if (((_flg) & (_msk)) == (_val)) {			\
			(_flg) &= ~(_msk);				\
			_ret = snprintf(_buf, _len, _nam "%s",		\
					(_flg) ? (_del) : "");		\
		}							\
		if (_ret < _len) {					\
			_len -= _ret;					\
			_buf += _ret;					\
		}							\
	} while (0)

#else /* EOF not defined => no stdio, do nothing */

#define __APPEND_FLAG(_buf, _len, _del, _flg, _val, _nam, ...)         do { } while (0)
#define __APPEND_ENUM(_buf, _len, _del, _flg, _msk, _val, _nam, ...)   do { } while (0)

#endif /* EOF */

#endif /* _HAPROXY_SHOW_FLAGS_H */
