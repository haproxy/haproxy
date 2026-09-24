/*
 * Symbol resolution helpers.
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 * Copyright (C) 2026 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE

#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
#include <dlfcn.h>
#include <link.h>
#endif

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(__linux__) && defined(__GLIBC__) && (__GLIBC__ > 2 || __GLIBC__ == 2 && __GLIBC_MINOR__ >= 16)
#include <sys/auxv.h>
#endif

#if defined(__FreeBSD__)
#include <sys/param.h>
#if __FreeBSD_version < 1300058
#include <elf.h>
#include <dlfcn.h>
extern void *__elf_aux_vector;
#else
#include <sys/auxv.h>
#endif
#endif

#if defined(__NetBSD__)
#include <sys/exec_elf.h>
#include <dlfcn.h>
#endif

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/atomic.h>
#include <haproxy/bug.h>
#include <haproxy/chunk.h>
#include <haproxy/dgram.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/hlua.h>
#include <haproxy/init.h>
#include <haproxy/listener.h>
#include <haproxy/quic_sock.h>
#include <haproxy/sc_strm.h>
#include <haproxy/session.h>
#include <haproxy/signal-t.h>
#include <haproxy/sock.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>

/* set to true if this is a static build */
int build_is_static = 0;

/* Tries to report the executable path name on platforms supporting this. If
 * not found or not possible, returns NULL.
 */
const char *get_exec_path()
{
	const char *ret = NULL;

#if defined(__linux__) && defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 16))
	long execfn = getauxval(AT_EXECFN);

	if (execfn && execfn != ENOENT)
		ret = (const char *)execfn;
#elif defined(__FreeBSD__)
#if __FreeBSD_version < 1300058
	Elf_Auxinfo *auxv;
	for (auxv = __elf_aux_vector; auxv->a_type != AT_NULL; ++auxv) {
		if (auxv->a_type == AT_EXECPATH) {
			ret = (const char *)auxv->a_un.a_ptr;
			break;
		}
	}
#else
	static char execpath[MAXPATHLEN];

	if (execpath[0] == '\0')
		elf_aux_info(AT_EXECPATH, execpath, MAXPATHLEN);
	if (execpath[0] != '\0')
		ret = execpath;
#endif
#elif defined(__NetBSD__)
	AuxInfo *auxv;
	for (auxv = _dlauxinfo(); auxv->a_type != AT_NULL; ++auxv) {
		if (auxv->a_type == AT_SUN_EXECNAME) {
			ret = (const char *)auxv->a_v;
			break;
		}
	}
#elif defined(__sun)
	ret = getexecname();
#endif
	return ret;
}

#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
/* calls dladdr() or dladdr1() on <addr> and <dli>. If dladdr1 is available,
 * also returns the symbol size in <size>, otherwise returns 0 there.
 */
static int dladdr_and_size(const void *addr, Dl_info *dli, size_t *size)
{
	int ret;
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 3)) // most detailed one
	const ElfW(Sym) *sym __attribute__((may_alias));

	ret = dladdr1(addr, dli, (void **)&sym, RTLD_DL_SYMENT);
	if (ret)
		*size = sym ? sym->st_size : 0;
#else
#if defined(__sun)
	ret = dladdr((void *)addr, dli);
#else
	ret = dladdr(addr, dli);
#endif
	*size = 0;
#endif
	return ret;
}

/* Sets build_is_static to true if we detect a static build. Some older glibcs
 * tend to crash inside dlsym() in static builds, but tests show that at least
 * dladdr() still works (and will fail to resolve anything of course). Thus we
 * try to determine if we're on a static build to avoid calling dlsym() in this
 * case.
 */
void check_if_static_build()
{
	Dl_info dli = { };
	size_t size = 0;

	/* Now let's try to be smarter */
	if (!dladdr_and_size(&main, &dli, &size))
		build_is_static = 1;
	else
		build_is_static = 0;
}

INITCALL0(STG_PREPARE, check_if_static_build);

/* Tries to retrieve the address of the first occurrence symbol <name>.
 * Note that NULL in return is not always an error as a symbol may have that
 * address in special situations.
 */
void *get_sym_curr_addr(const char *name)
{
	void *ptr = NULL;

#ifdef RTLD_DEFAULT
	if (!build_is_static)
		ptr = dlsym(RTLD_DEFAULT, name);
#endif
	return ptr;
}


/* Tries to retrieve the address of the next occurrence of symbol <name>
 * Note that NULL in return is not always an error as a symbol may have that
 * address in special situations.
 */
void *get_sym_next_addr(const char *name)
{
	void *ptr = NULL;

#ifdef RTLD_NEXT
	if (!build_is_static)
		ptr = dlsym(RTLD_NEXT, name);
#endif
	return ptr;
}

#else /* elf & linux & dl */

/* no possible resolving on other platforms at the moment */
void *get_sym_curr_addr(const char *name)
{
	return NULL;
}

void *get_sym_next_addr(const char *name)
{
	return NULL;
}

#endif /* elf & linux & dl */

/* Tries to append to buffer <buf> some indications about the symbol at address
 * <addr> using the following form:
 *   lib:+0xoffset              (unresolvable address from lib's base)
 *   main+0xoffset              (unresolvable address from main (+/-))
 *   lib:main+0xoffset          (unresolvable lib address from main (+/-))
 *   name                       (resolved exact exec address)
 *   lib:name                   (resolved exact lib address)
 *   name+0xoffset/0xsize       (resolved address within exec symbol)
 *   lib:name+0xoffset/0xsize   (resolved address within lib symbol)
 *
 * The file name (lib or executable) is limited to what lies between the last
 * '/' and the first following '.'. An optional prefix <pfx> is prepended before
 * the output if not null. The file is not dumped when it's the same as the one
 * that contains the "main" symbol, or when __ELF__ && USE_DL are not set.
 *
 * The symbol's base address is returned, or NULL when unresolved, in order to
 * allow the caller to match it against known ones.
 */
const void *resolve_sym_name(struct buffer *buf, const char *pfx, const void *addr)
{
	const struct {
		const void *func;
		const char *name;
	} fcts[] = {
#define DEF_SYM(sym, ...) { .func = ({ __VA_ARGS__; sym; }), .name = #sym }
		DEF_SYM(process_stream),
		DEF_SYM(task_run_applet),
		DEF_SYM(run_poll_loop),
		DEF_SYM(run_tasks_from_lists),
		DEF_SYM(process_runnable_tasks),
		DEF_SYM(sc_conn_io_cb),
		DEF_SYM(sock_conn_iocb),
		DEF_SYM(dgram_fd_handler),
		DEF_SYM(listener_accept),
		DEF_SYM(manage_global_listener_queue),
		DEF_SYM(poller_pipe_io_handler),
		DEF_SYM(mworker_accept_wrapper),
		DEF_SYM(session_expire_embryonic),
		DEF_SYM(ha_dump_backtrace, extern void ha_dump_backtrace(struct buffer *, const char *, int)),
		DEF_SYM(cli_io_handler, extern void cli_io_handler(struct appctx*)),
#ifdef USE_THREAD
		DEF_SYM(accept_queue_process),
#endif
#ifdef USE_LUA
		DEF_SYM(hlua_process_task),
#endif
#ifdef SSL_MODE_ASYNC
		DEF_SYM(ssl_async_fd_free),
		DEF_SYM(ssl_async_fd_handler),
#endif
#ifdef USE_QUIC
		DEF_SYM(quic_conn_sock_fd_iocb),
#endif
#undef DEF_SYM
	};

#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
	static Dl_info dli_main;
	static int dli_main_done; // 0 = not resolved, 1 = resolve in progress, 2 = done
	__decl_thread_var(static HA_SPINLOCK_T dladdr_lock);
	sigset_t new_mask, old_mask;
	int isolated;
	Dl_info dli;
	size_t size = 0;
	const char *fname, *p;
#endif
	size_t dist, best_dist;
	int i, best_idx;

	if (pfx)
		chunk_appendf(buf, "%s", pfx);

	best_idx = -1; best_dist = ~0;
	for (i = 0; i < sizeof(fcts) / sizeof(fcts[0]); i++) {
		if (addr < (void*)fcts[i].func)
			continue;
		dist = addr - (void*)fcts[i].func;
		if (dist < (1<<18) && dist < best_dist) {
			best_dist = dist;
			best_idx = i;
			if (!dist)
				break;
		}
	}

	/* if that's an exact match, no need to call dl_addr. This happens
	 * when showing callback pointers for example, but not in backtraces.
	 */
	if (!best_dist)
		goto use_array;

#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
	/* Now let's try to be smarter */

	/* dladdr_and_size() can be super expensive and will often rely on a
	 * mutex inside the library to deal with concurrent accesses. We don't
	 * want to inflict this to parallel callers who could wait much too
	 * long (e.g. during a wdt warning). Thus, we'll do the following:
	 *   - if we're isolated or in a panic, we're safe and don't need to
	 *     lock so we don't wait.
	 *   - otherwise we use a trylock and we fail on conflict so that
	 *     no one waits when there is contention.
	 */
	isolated = thread_isolated() || (get_tainted() & TAINTED_PANIC);

	if (!isolated &&
	    HA_SPIN_TRYLOCK(OTHER_LOCK, &dladdr_lock) != 0)
		goto use_array;

	/* make sure we don't re-enter from wdt nor debug coming from other
	 * threads as dladdr() is not re-entrant. We'll block these sensitive
	 * signals while possibly dumping a backtrace.
	 */
	sigemptyset(&new_mask);
#ifdef WDTSIG
	sigaddset(&new_mask, WDTSIG);
#endif
#ifdef DEBUGSIG
	sigaddset(&new_mask, DEBUGSIG);
#endif
	ha_sigmask(SIG_BLOCK, &new_mask, &old_mask);

	/* now resolve the symbol */
	i = dladdr_and_size(addr, &dli, &size);

	if (!i) {
		/* unblock temporarily blocked signals */
		ha_sigmask(SIG_SETMASK, &old_mask, NULL);

		if (!isolated)
			HA_SPIN_UNLOCK(OTHER_LOCK, &dladdr_lock);
		goto use_array;
	}

	/* 1. prefix the library name if it's not the same object as the one
	 * that contains the main function. The name is picked between last '/'
	 * and first following '.'.
	 */

	/* let's check main only once, no need to do it all the time */

	i = HA_ATOMIC_LOAD(&dli_main_done);
	while (i < 2) {
		i = 0;
		if (HA_ATOMIC_CAS(&dli_main_done, &i, 1)) {
			/* we're the first ones, resolve it */
			if (!dladdr(main, &dli_main))
				dli_main.dli_fbase = NULL;
			HA_ATOMIC_STORE(&dli_main_done, 2); // done
			break;
		}
		ha_thread_relax();
	}

	/* unblock temporarily blocked signals */
	ha_sigmask(SIG_SETMASK, &old_mask, NULL);

	if (!isolated)
		HA_SPIN_UNLOCK(OTHER_LOCK, &dladdr_lock);

	if (dli_main.dli_fbase != dli.dli_fbase) {
		fname = dli.dli_fname;
		p = strrchr(fname, '/');
		if (p++)
			fname = p;
		p = strchr(fname, '.');
		if (!p)
			p = fname + strlen(fname);

		chunk_appendf(buf, "%.*s:", (int)(long)(p - fname), fname);
	}

	/* 2. symbol name */
	if (dli.dli_sname) {
		/* known, dump it and return symbol's address (exact or relative) */
		chunk_appendf(buf, "%s", dli.dli_sname);
		if (addr != dli.dli_saddr) {
			chunk_appendf(buf, "+%#lx", (long)(addr - dli.dli_saddr));
			if (size)
				chunk_appendf(buf, "/%#lx", (long)size);
		}
		return dli.dli_saddr;
	}
	else if (dli_main.dli_fbase != dli.dli_fbase) {
		/* unresolved symbol from a known library, report relative offset */
		chunk_appendf(buf, "+%#lx", (long)(addr - dli.dli_fbase));
		return NULL;
	}
#endif /* __ELF__ && !__linux__ || USE_DL */
 use_array:
	/* either exact match from the array, or unresolved symbol for which we
	 * may have a close match. Otherwise we report an offset relative to main.
	 */
	if (best_idx >= 0) {
		chunk_appendf(buf, "%s", fcts[best_idx].name);
		if (best_dist)
			chunk_appendf(buf, "+%#lx", (long)best_dist);
		return best_dist == 0 ? addr : NULL;
	}
	else if ((void*)addr < (void*)main)
		chunk_appendf(buf, "main-%#lx", (long)((void*)main - addr));
	else
		chunk_appendf(buf, "main+%#lx", (long)(addr - (void*)main));
	return NULL;
}

/* Tries to append to buffer <buf> the DSO name containing the symbol at address
 * <addr>. The name (lib or executable) is limited to what lies between the last
 * '/' and the first following '.'. An optional prefix <pfx> is prepended before
 * the output if not null. It returns "*unknown*" when the symbol is not found.
 *
 * The symbol's address is returned, or NULL when unresolved, in order to allow
 * the caller to match it against known ones.
 */
const void *resolve_dso_name(struct buffer *buf, const char *pfx, const void *addr)
{
#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
	Dl_info dli;
	size_t size;
	const char *fname, *p;

	/* Now let's try to be smarter */
	if (!dladdr_and_size(addr, &dli, &size))
		goto unknown;

	if (pfx) {
		chunk_appendf(buf, "%s", pfx);
		pfx = NULL;
	}

	/* keep the part between '/' and '.' */
	fname = dli.dli_fname;
	p = strrchr(fname, '/');
	if (p++)
		fname = p;
	p = strchr(fname, '.');
	if (!p)
		p = fname + strlen(fname);
	chunk_appendf(buf, "%.*s", (int)(long)(p - fname), fname);
	return addr;
 unknown:
#endif /* __ELF__ && !__linux__ || USE_DL */

	/* unknown symbol */
	chunk_appendf(buf, "%s*unknown*", pfx ? pfx : "");
	return NULL;
}

/* the RTLD_* macros alone do not mean that dlfcn.h was included: on glibc
 * <link.h>, which the ELF parsing also includes, defines them without
 * bringing the loader functions, so the dynamic-loader helpers'
 * condition is checked as well.
 */
#if (defined(__ELF__) && !defined(__linux__)) || defined(USE_DL)
#if defined(RTLD_DEFAULT) || defined(RTLD_NEXT)
/* redefine dlopen() so that we can detect unexpected replacement of some
 * critical symbols, typically init/alloc/free functions coming from alternate
 * libraries. When called, a tainted flag is set (TAINTED_SHARED_LIBS).
 * It's important to understand that the dynamic linker will present the
 * first loaded of each symbol to all libs, so that if haproxy is linked
 * with a new lib that uses a static inline or a #define to replace an old
 * function, and a dependency was linked against an older version of that
 * lib that had a function there, that lib would use all of the newer
 * versions of the functions that are already loaded in haproxy, except
 * for that unique function which would continue to be the old one. This
 * creates all sort of problems when init code allocates smaller structs
 * than required for example but uses new functions on them, etc. Thus what
 * we do here is to try to detect API consistency: we take a fingerprint of
 * a number of known functions, and verify that if they change in a loaded
 * library, either there all appeared or all disappeared, but not partially.
 * We can check up to 64 symbols that belong to individual groups that are
 * checked together.
 */
void *dlopen(const char *filename, int flags)
{
	static void *(*_dlopen)(const char *filename, int flags);
	struct {
		const char *name;
		uint64_t bit, grp;
		void *curr, *next;
	} check_syms[] = {
		/* openssl's libcrypto checks: group bits 0x1f */
		{ .name="OPENSSL_init",                  .bit = 0x0000000000000001, .grp = 0x000000000000001f, }, // openssl 1.0 / 1.1 / 3.0
		{ .name="OPENSSL_init_crypto",           .bit = 0x0000000000000002, .grp = 0x000000000000001f, }, // openssl 1.1 / 3.0
		{ .name="ENGINE_init",                   .bit = 0x0000000000000004, .grp = 0x000000000000001f, }, // openssl 1.x / 3.x with engine
		{ .name="EVP_CIPHER_CTX_init",           .bit = 0x0000000000000008, .grp = 0x000000000000001f, }, // openssl 1.0
		{ .name="HMAC_Init",                     .bit = 0x0000000000000010, .grp = 0x000000000000001f, }, // openssl 1.x

		/* openssl's libssl checks: group bits 0x3e0 */
		{ .name="OPENSSL_init_ssl",              .bit = 0x0000000000000020, .grp = 0x00000000000003e0, }, // openssl 1.1 / 3.0
		{ .name="SSL_library_init",              .bit = 0x0000000000000040, .grp = 0x00000000000003e0, }, // openssl 1.x
		{ .name="SSL_is_quic",                   .bit = 0x0000000000000080, .grp = 0x00000000000003e0, }, // quictls
		{ .name="SSL_CTX_new_ex",                .bit = 0x0000000000000100, .grp = 0x00000000000003e0, }, // openssl 3.x
		{ .name="SSL_CTX_get0_security_ex_data", .bit = 0x0000000000000200, .grp = 0x00000000000003e0, }, // openssl 1.x / 3.x

		/* insert only above, 0 must be the last one */
		{ 0 },
	};
	const char *trace;
	uint64_t own_fp, lib_fp; // symbols fingerprints
	void *addr;
	void *ret;
	int sym = 0;

	if (!_dlopen) {
		_dlopen = get_sym_next_addr("dlopen");
		if (!_dlopen || _dlopen == dlopen) {
			_dlopen = NULL;
			return NULL;
		}
	}

	/* save a few pointers to critical symbols. We keep a copy of both the
	 * current and the next value, because we might already have replaced
	 * some of them in an inconsistent way (i.e. not all), and we're only
	 * interested in verifying that a loaded library doesn't come with a
	 * completely different definition that would be incompatible. We'll
	 * keep a fingerprint of our own symbols.
	 */
	own_fp = 0;
	for (sym = 0; check_syms[sym].name; sym++) {
		check_syms[sym].curr = get_sym_curr_addr(check_syms[sym].name);
		check_syms[sym].next = get_sym_next_addr(check_syms[sym].name);
		if (check_syms[sym].curr || check_syms[sym].next)
			own_fp |= check_syms[sym].bit;
	}

	/* now open the requested lib */
	ret = _dlopen(filename, flags);
	if (!ret)
		return ret;

	mark_tainted(TAINTED_SHARED_LIBS);

	/* and check that critical symbols didn't change */
	lib_fp = 0;
	for (sym = 0; check_syms[sym].name; sym++) {
		addr = dlsym(ret, check_syms[sym].name);
		if (addr)
			lib_fp |= check_syms[sym].bit;
	}

	if (lib_fp != own_fp) {
		/* let's check what changed:  */
		uint64_t mask = 0;

		for (sym = 0; check_syms[sym].name; sym++) {
			mask = check_syms[sym].grp;

			/* new group of symbols. If they all appeared together
			 * their use will be consistent. If none appears, it's
			 * just that the lib doesn't use them. If some appear
			 * or disappear, it means the lib relies on a different
			 * dependency and will end up with a mix.
			 */
			if (!(own_fp & mask) || !(lib_fp & mask) ||
			    (own_fp & mask) == (lib_fp & mask))
				continue;

			/* let's report a symbol that really changes */
			if (!((own_fp ^ lib_fp) & check_syms[sym].bit))
				continue;

			/* OK it's clear that this symbol was redefined */
			mark_tainted(TAINTED_REDEFINITION);

			trace = hlua_show_current_location("\n    ");
			ha_warning("dlopen(): shared library '%s' brings a different and inconsistent definition of symbol '%s'. The process cannot be trusted anymore!%s%s\n",
				   filename, check_syms[sym].name,
				   trace ? " Suspected call location: \n    " : "",
				   trace ? trace : "");
		}
	}

	return ret;
}
#endif
#endif
