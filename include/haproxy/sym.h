/*
 * include/haproxy/sym.h
 * In-process symbol table used by backtraces.
 *
 * Copyright (C) 2026 HAProxy Technologies
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

#ifndef _HAPROXY_SYM_H
#define _HAPROXY_SYM_H

#ifdef USE_BACKTRACE
// for backtrace() on Linux
#define _GNU_SOURCE
#endif

#include <haproxy/buf-t.h>
#include <haproxy/compat.h>
#include <haproxy/compiler.h>
#include <haproxy/sym-t.h>
#include <haproxy/tools.h>

#if defined(USE_BACKTRACE) && defined(HA_HAVE_WORKING_BACKTRACE)
#include <execinfo.h>
#endif

/* set to true if this is a static build */
extern int build_is_static;

/* appends to buffer <buf> the name of the symbol at address <addr>, in the
 * form "[obj:]sym[+off[/size]]", or an offset relative to main(). Returns the
 * symbol's base address, or NULL when unresolved, in order to allow the
 * caller to match it against known ones.
 */
const void *resolve_sym_name(struct buffer *buf, const char *pfx, const void *addr);

/* appends to buffer <buf> the name of the object containing the symbol at
 * address <addr>, between the last '/' and the first following '.', or
 * "*unknown*" when it is not found.
 */
const void *resolve_dso_name(struct buffer *buf, const char *pfx, const void *addr);

/* tries to retrieve the address of the first (curr) or next (next)
 * occurrence of symbol <name>, or NULL; the address is also NULL in
 * special situations, so it is not always an error.
 */
void *get_sym_curr_addr(const char *name);
void *get_sym_next_addr(const char *name);

/* reports the executable path name on platforms supporting this,
 * or NULL when not found.
 */
const char *get_exec_path(void);

/* builds the table (post-check) */
int sym_load_all(void);

/* adds a directory to search for separate debug files (config time) */
int sym_add_debug_dir(const char *dir);

/* Note that this may result in opening libgcc() on first call, so it may need
 * to have been called once before chrooting.
 */
static forceinline int my_backtrace(void **buffer, int max)
{
#if !defined(USE_BACKTRACE)
	return 0;
#elif defined(HA_HAVE_WORKING_BACKTRACE)
	return backtrace(buffer, max);
#else
	const struct frame {
		const struct frame *next;
		void *ra;
	} *frame;
	int count;

	frame = __builtin_frame_address(0);
	for (count = 0; count < max && may_access(frame) && may_access(frame->ra);) {
		buffer[count++] = frame->ra;
		frame = frame->next;
	}
	return count;
#endif
}

#endif /* _HAPROXY_SYM_H */
