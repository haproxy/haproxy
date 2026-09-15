/*
 * include/haproxy/sym-t.h
 * Types for the in-process symbol table used by backtraces.
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

#ifndef _HAPROXY_SYM_T_H
#define _HAPROXY_SYM_T_H

/* a function that must always be resolvable, even from a stripped or
 * unreadable executable (see sym_known_fcts[] in sym.c).
 */
struct sym_known {
	const void *func;
	const char *name;
};

/* One loaded object (the executable or a shared library). */
struct sym_obj {
	const char *file;       /* object path (strdup'd), NULL if unknown */
	unsigned long base;     /* load bias */
	unsigned long low;      /* lowest runtime address covered by the object */
	unsigned long high;     /* one past the highest runtime address covered */
	int is_exe;             /* non-zero for the main executable */
};

/* One function symbol, with runtime addresses already relocated. */
struct sym_entry {
	unsigned long addr;          /* runtime start address of the symbol */
	unsigned long size;          /* symbol size in bytes, 0 if unknown */
	const char *name;            /* symbol name (into sym_table->names) */
	const struct sym_obj *obj;   /* owning object */
};

/* A published, immutable snapshot of all symbols. */
struct sym_table {
	struct sym_entry *syms; /* array sorted by addr ascending */
	unsigned int nsyms;     /* number of entries in <syms> */
	struct sym_obj **objs;  /* objects referenced by <syms> */
	unsigned int nobjs;     /* number of entries in <objs> */
	char *names;            /* name pool backing all syms[].name */
};

/* Result of a lookup. */
struct sym_lookup {
	const char *file;       /* owning object path, NULL for the executable */
	const char *name;       /* symbol name, or NULL if only the object is known */
	const void *addr;       /* symbol's runtime base address (for caller matching) */
	unsigned long size;     /* symbol size, 0 if unknown */
	unsigned long obj_base; /* owning object's load base */
	int is_exe;             /* non-zero if the owning object is the executable */
	int inside;             /* non-zero if addr lies within the symbol's extent (dladdr() rule) */
};

#endif /* _HAPROXY_SYM_T_H */
