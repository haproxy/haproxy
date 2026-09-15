/*
 * In-process symbol table for backtraces.
 *
 * Copyright 2000-2010 Willy Tarreau <w@1wt.eu>
 * Copyright (C) 2026 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This maintains a table of function symbols (address, size, name, owning
 * object) sorted by address, so that backtraces and pointer dumps can name
 * the functions they hit. It is built at boot time
 * from the well-known entry points of sym_known_fcts[] and, where the dynamic
 * linker exposes dl_iterate_phdr(), from the exported symbols of the
 * executable and of every loaded shared library, read straight from their
 * memory image (what dladdr() sees, but lock-free and usable in a chroot).
 * When the ELF files are readable, their .symtab (which includes local/static
 * functions) is parsed too, and for stripped objects separate debug info is
 * looked up via the GNU build-id and .gnu_debuglink mechanisms. Finally, the
 * compressed symbol tables that objects may embed in a loadable
 * .gnu_debugdata section (the MiniDebugInfo format gdb also reads) are
 * decompressed and parsed, which works even on a stripped or unreadable file.
 *
 * Lookups (sym_resolve()) are lock-free and async-signal-safe: they only read
 * an immutable snapshot, replaced only while no thread is running and
 * released at deinit.
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

#include <sys/mman.h>
#include <sys/stat.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/atomic.h>
#include <haproxy/bug.h>
#include <haproxy/chunk.h>
#include <haproxy/dgram.h>
#include <haproxy/errors.h>
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
#include <haproxy/sym.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/tools.h>

/* set to true if this is a static build */
int build_is_static = 0;

/* well-known entry points that must always resolve, even from a stripped or
 * unreadable executable. Also fed to the in-process symbol table.
 */
extern void ha_dump_backtrace(struct buffer *, const char *, int);
extern void cli_io_handler(struct appctx *);

static const struct sym_known sym_known_fcts[] = {
#define DEF_SYM(sym) { .func = (const void *)sym, .name = #sym }
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
		DEF_SYM(ha_dump_backtrace),
		DEF_SYM(cli_io_handler),
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
static const unsigned int sym_known_nb = sizeof(sym_known_fcts) / sizeof(sym_known_fcts[0]);

/* the currently published, immutable snapshot (atomic) */
static struct sym_table * volatile cur_symtab;

/* A file mapping kept alive until the end of a build: collected symbol names
 * point into these mappings and are copied into the table's name pool just
 * before the mappings are released.
 */
struct mapref {
	void *addr;
	size_t size;
};

/* Transient state while a snapshot is being built. */
struct sym_build {
	struct sym_entry *syms;    /* growing array of collected symbols */
	unsigned int n, alloc;
	struct mapref *maps;       /* file mappings to release at the end of the build */
	unsigned int nmaps, mapalloc;
	void **bufs;               /* memory blocks to release at the end of the build */
	unsigned int nbufs, balloc;
	const unsigned char *debugdata; /* compressed table of the object being collected */
	size_t debugdata_size;
	struct sym_obj **objs;     /* objects created this build, handed to the snapshot */
	unsigned int nobjs, oalloc;
	int oom;                   /* set on any allocation failure */
};

/* records an object created this build; returns 0 on success, -1 on OOM */
static int build_keep_obj(struct sym_build *b, struct sym_obj *obj)
{
	if (b->nobjs >= b->oalloc) {
		unsigned int na = b->oalloc ? b->oalloc * 2 : 16;
		struct sym_obj **no = realloc(b->objs, na * sizeof(*no));

		if (!no) {
			b->oom = 1;
			return -1;
		}
		b->objs = no;
		b->oalloc = na;
	}
	b->objs[b->nobjs++] = obj;
	return 0;
}

/* appends one symbol; <name> must stay valid until the names are copied into
 * the pool at the end of the build. Sets b->oom on allocation failure.
 */
static void build_add_sym(struct sym_build *b, unsigned long addr,
			  unsigned long size, const char *name,
			  const struct sym_obj *obj)
{
	if (b->n >= b->alloc) {
		unsigned int na = b->alloc ? b->alloc * 2 : 4096;
		struct sym_entry *ns = realloc(b->syms, na * sizeof(*ns));

		if (!ns) {
			b->oom = 1;
			return;
		}
		b->syms = ns;
		b->alloc = na;
	}
	b->syms[b->n].addr = addr;
	b->syms[b->n].size = size;
	b->syms[b->n].name = name;
	b->syms[b->n].obj  = obj;
	b->n++;
}

/* LSD radix sort of <n> entries by their .addr field, 8 bits per pass. It is
 * stable, so among equal addresses the entry collected first (see collect
 * order) stays ahead of its aliases. <scratch> is an
 * n-element scratch buffer. sizeof(long) (4 or 8) passes is even on every
 * supported platform, so the result ends back in <a>.
 */
static void radix_sort_syms(struct sym_entry *a, struct sym_entry *scratch, unsigned int n)
{
	unsigned int pass, i;

	for (pass = 0; pass < sizeof(unsigned long); pass++) {
		size_t count[256] = { 0 };
		unsigned int shift = pass * 8;
		struct sym_entry *src = (pass & 1) ? scratch : a;
		struct sym_entry *dst = (pass & 1) ? a : scratch;
		size_t acc = 0, c;

		for (i = 0; i < n; i++)
			count[(src[i].addr >> shift) & 0xff]++;
		for (i = 0; i < 256; i++) {
			c = count[i];
			count[i] = acc;
			acc += c;
		}
		for (i = 0; i < n; i++) {
			unsigned int k = (src[i].addr >> shift) & 0xff;

			dst[count[k]++] = src[i];
		}
	}
}

static void add_known(struct sym_build *b, const struct sym_obj *obj)
{
	unsigned int i;

	for (i = 0; i < sym_known_nb && !b->oom; i++)
		build_add_sym(b, (unsigned long)sym_known_fcts[i].func, 0,
			      sym_known_fcts[i].name, obj);
}

/* The list of directories searched for separate debug files. The built-in
 * default "/usr/lib/debug" is always searched first.
 */
static const char **dbg_dirs;
static unsigned int nb_dbg_dirs;

int sym_add_debug_dir(const char *dir)
{
	const char **n;
	char *dup;

	dup = strdup(dir);
	if (!dup)
		return -1;
	n = realloc(dbg_dirs, (nb_dbg_dirs + 1) * sizeof(*dbg_dirs));
	if (!n) {
		free(dup);
		return -1;
	}
	dbg_dirs = n;
	dbg_dirs[nb_dbg_dirs++] = dup;
	return 0;
}

#if defined(__ELF__)

#include <elf.h>
#include <link.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>

#include <haproxy/hash.h>
#include <haproxy/net_helper.h>
#include <import/xz.h>

/* Largest decompressed symbol table we accept, and largest LZMA2 dictionary we
 * let the decoder allocate for it.
 */
#define SYM_DEBUGDATA_MAX      (64 * 1024 * 1024)
#define SYM_DEBUGDATA_DICT_MAX (64 * 1024 * 1024)

#ifdef USE_MINIDEBUG
/* Placeholders for this program's own table, filled in by scripts/minidbg.sh
 * after the link: the section gives it the name gdb looks for, and the note,
 * whose alignment makes linkers give it a segment of its own, gives it the
 * segment entry that is turned into a loadable one.
 */
__attribute__((section(".gnu_debugdata"), aligned(16), used))
static const unsigned char sym_debugdata_room[16];

__attribute__((section(".note.hapdbg"), aligned(16), used))
static const struct {
	uint32_t namesz, descsz, type;
	char name[8];
	uint32_t desc;
} sym_debugdata_note = { 7, 4, 1, "HAPDBG", 0 };
#endif

/* native ELF class / endianness / symbol-type accessor, derived from the
 * toolchain since glibc doesn't provide *_NATIVE convenience macros.
 */
#if __WORDSIZE == 64
# define SYM_ELFCLASS    ELFCLASS64
# define SYM_ST_TYPE(i)  ELF64_ST_TYPE(i)
#else
# define SYM_ELFCLASS    ELFCLASS32
# define SYM_ST_TYPE(i)  ELF32_ST_TYPE(i)
#endif

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
# define SYM_ELFDATA     ELFDATA2MSB
#else
# define SYM_ELFDATA     ELFDATA2LSB
#endif


/* returns true if the [ptr, ptr+len) range lies entirely within the mapping
 * [map, map+sz). Also guards against length overflow.
 */
static inline int in_map(const void *ptr, size_t len, const void *map, size_t sz)
{
	const char *p = ptr, *m = map;

	if (p < m)
		return 0;
	if (len > sz)
		return 0;
	return (size_t)(p - m) <= sz - len;
}

/* validates an ELF header for the native class/endianness and a sane section
 * header table that fits in the <sz>-byte mapping. Returns 1 if usable.
 */
static int elf_hdr_ok(const ElfW(Ehdr) *eh, size_t sz)
{
	if (!in_map(eh, sizeof(*eh), eh, sz))
		return 0;
	if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
		return 0;
	if (eh->e_ident[EI_CLASS] != SYM_ELFCLASS)
		return 0;
	if (eh->e_ident[EI_DATA] != SYM_ELFDATA)
		return 0;
	if (eh->e_shentsize != sizeof(ElfW(Shdr)))
		return 0;
	if (!eh->e_shoff || !eh->e_shnum)
		return 0;
	if (!in_map((const char *)eh + eh->e_shoff,
		    (size_t)eh->e_shnum * sizeof(ElfW(Shdr)), eh, sz))
		return 0;
	return 1;
}

/* returns the section header string table pointer and stores its size, or NULL
 * on any inconsistency. Handles the SHN_XINDEX extension for e_shstrndx.
 */
static const char *elf_shstrtab(const ElfW(Ehdr) *eh, size_t sz, size_t *pstrsz)
{
	const ElfW(Shdr) *sh = (const ElfW(Shdr) *)((const char *)eh + eh->e_shoff);
	unsigned int idx = eh->e_shstrndx;
	const char *str;

	if (idx == SHN_XINDEX)
		idx = sh[0].sh_link;
	if (idx >= eh->e_shnum)
		return NULL;

	str = (const char *)eh + sh[idx].sh_offset;
	if (!in_map(str, sh[idx].sh_size, eh, sz) || !sh[idx].sh_size)
		return NULL;
	*pstrsz = sh[idx].sh_size;
	return str;
}

static void *map_file_ro(const char *path, size_t *psz)
{
	struct stat st;
	void *map;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
	    (size_t)st.st_size < sizeof(ElfW(Ehdr))) {
		close(fd);
		return NULL;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return NULL;

	*psz = st.st_size;
	return map;
}

/* records a mapping to release when the build finishes; the mapping is
 * released right away when it cannot be recorded, so the caller must not use
 * it afterwards.
 */
static void build_keep_map(struct sym_build *b, void *addr, size_t size)
{
	if (b->nmaps >= b->mapalloc) {
		unsigned int na = b->mapalloc ? b->mapalloc * 2 : 16;
		struct mapref *nm = realloc(b->maps, na * sizeof(*nm));

		if (!nm) {
			munmap(addr, size);
			b->oom = 1;
			return;
		}
		b->maps = nm;
		b->mapalloc = na;
	}
	b->maps[b->nmaps].addr = addr;
	b->maps[b->nmaps].size = size;
	b->nmaps++;
}

/* records a memory block to release when the build finishes */
static int build_keep_buf(struct sym_build *b, void *buf)
{
	if (b->nbufs >= b->balloc) {
		unsigned int na = b->balloc ? b->balloc * 2 : 8;
		void **nb = realloc(b->bufs, na * sizeof(*nb));

		if (!nb) {
			b->oom = 1;
			return -1;
		}
		b->bufs = nb;
		b->balloc = na;
	}
	b->bufs[b->nbufs++] = buf;
	return 0;
}

static void collect_syms(struct sym_build *b, const void *map, size_t sz,
			 const ElfW(Shdr) *symsh, const ElfW(Shdr) *strsh,
			 unsigned long base, const struct sym_obj *obj)
{
	const ElfW(Sym) *sym;
	const char *str;
	size_t strsz, n, i;

	if (!symsh || !strsh || symsh->sh_entsize != sizeof(ElfW(Sym)))
		return;

	sym = (const ElfW(Sym) *)((const char *)map + symsh->sh_offset);
	if (!in_map(sym, symsh->sh_size, map, sz))
		return;

	str = (const char *)map + strsh->sh_offset;
	strsz = strsh->sh_size;
	if (!in_map(str, strsz, map, sz) || !strsz)
		return;

	n = symsh->sh_size / sizeof(ElfW(Sym));
	for (i = 0; i < n && !b->oom; i++) {
		unsigned char type = SYM_ST_TYPE(sym[i].st_info);
		const char *name;

		if (type != STT_FUNC && type != STT_GNU_IFUNC)
			continue;
		/* must be defined in a regular section and have a real value */
		if (sym[i].st_shndx == SHN_UNDEF || sym[i].st_shndx >= SHN_LORESERVE)
			continue;
		if (!sym[i].st_value || sym[i].st_name >= strsz)
			continue;
		name = str + sym[i].st_name;
		if (!*name)
			continue;

		build_add_sym(b, base + sym[i].st_value, sym[i].st_size, name, obj);
	}
}

static const char *dbg_dir(unsigned int idx)
{
	if (idx == 0)
		return "/usr/lib/debug";
	if (idx - 1 < nb_dbg_dirs)
		return dbg_dirs[idx - 1];
	return NULL;
}

/* Extracts the GNU build-id (raw bytes) and/or the .gnu_debuglink name from the
 * section headers of the mapping.
 */
static void elf_debug_refs(const void *map, size_t sz, const ElfW(Ehdr) *eh,
			   const char *shstr, size_t shstrsz,
			   const unsigned char **bid, size_t *bidlen,
			   const char **link, size_t *linklen, size_t *linksz)
{
	const ElfW(Shdr) *sh = (const ElfW(Shdr) *)((const char *)map + eh->e_shoff);
	unsigned int i;

	*bid = NULL; *bidlen = 0;
	*link = NULL; *linklen = 0; *linksz = 0;

	for (i = 0; i < eh->e_shnum; i++) {
		if (sh[i].sh_name >= shstrsz)
			continue;

		if (!*bid && sh[i].sh_type == SHT_NOTE &&
		    strcmp(shstr + sh[i].sh_name, ".note.gnu.build-id") == 0) {
			const ElfW(Nhdr) *nh = (const ElfW(Nhdr) *)((const char *)map + sh[i].sh_offset);
			size_t off, namesz, descsz;

			if (!in_map(nh, sh[i].sh_size, map, sz) || sh[i].sh_size < sizeof(*nh))
				continue;
			namesz = (nh->n_namesz + 3) & ~3U;
			descsz = nh->n_descsz;
			off = sizeof(*nh) + namesz;
			if (nh->n_type != NT_GNU_BUILD_ID || off + descsz > sh[i].sh_size)
				continue;
			if (nh->n_namesz < 4 || memcmp((const char *)(nh + 1), "GNU", 4) != 0)
				continue;
			if (descsz >= 2 && descsz <= 64) {
				*bid = (const unsigned char *)nh + off;
				*bidlen = descsz;
			}
		}
		else if (!*link && sh[i].sh_type == SHT_PROGBITS &&
			 strcmp(shstr + sh[i].sh_name, ".gnu_debuglink") == 0) {
			const char *l = (const char *)map + sh[i].sh_offset;
			size_t ll;

			if (!in_map(l, sh[i].sh_size, map, sz) || !sh[i].sh_size)
				continue;
			ll = strnlen(l, sh[i].sh_size);
			if (ll && ll < sh[i].sh_size) { /* must be NUL-terminated */
				*link = l;
				*linklen = ll;
				*linksz = sh[i].sh_size;
			}
		}
	}
}

/* Checks that the separate debug file mapped at [<dmap>,<dmap>+<dsz>) (header
 * <deh>) really belongs to the object it was found for: same GNU build-id when
 * the object has one, otherwise a matching .gnu_debuglink CRC32 (as gdb does).
 * Returns 1 if usable.
 */
static int debug_file_ok(const void *dmap, size_t dsz, const ElfW(Ehdr) *deh,
			 const unsigned char *bid, size_t bidlen,
			 const char *link, size_t linklen, size_t linksz)
{
	const unsigned char *dbid;
	const char *dlink, *dshstr;
	size_t dbidlen, dlinklen, dlinksz, dshstrsz = 0, off;

	if (bid) {
		dshstr = elf_shstrtab(deh, dsz, &dshstrsz);
		if (!dshstr)
			return 0;
		elf_debug_refs(dmap, dsz, deh, dshstr, dshstrsz,
			       &dbid, &dbidlen, &dlink, &dlinklen, &dlinksz);
		return dbid && dbidlen == bidlen && memcmp(dbid, bid, bidlen) == 0;
	}
	if (link) {
		/* the CRC32 follows the NUL-terminated name, 4-byte aligned */
		off = (linklen + 4) & ~(size_t)3;
		if (off + 4 > linksz || dsz > INT_MAX)
			return 0;
		return read_u32(link + off) == hash_crc32(dmap, (int)dsz);
	}
	return 0;
}

static void *try_debug_file(const char *path, size_t *dsz,
			    const unsigned char *bid, size_t bidlen,
			    const char *link, size_t linklen, size_t linksz)
{
	void *m = map_file_ro(path, dsz);

	if (!m)
		return NULL;
	if (elf_hdr_ok(m, *dsz) && debug_file_ok(m, *dsz, m, bid, bidlen, link, linklen, linksz))
		return m;
	munmap(m, *dsz);
	return NULL;
}

/* Looks for the separate debug file of the executable/library, and returns
 * the mapping, if any were found.
 */
static void *map_debug_file(const char *obj_path, size_t *dsz,
			    const unsigned char *bid, size_t bidlen,
			    const char *link, size_t linklen, size_t linksz)
{
	const char *slash;
	size_t dirlen, j;
	const char *root;
	char buf[PATH_MAX];
	void *res;
	unsigned int d;
	int n;

	/* directory of the object, including the trailing slash (may be empty) */
	slash = strrchr(obj_path, '/');
	dirlen = slash ? (size_t)(slash - obj_path) + 1 : 0;

	/* 1. for each debug directory, <root>/.build-id/<xx>/<rest>.debug */
	for (d = 0; bid && (root = dbg_dir(d)); d++) {
		n = snprintf(buf, sizeof(buf), "%s/.build-id/%02x/", root, bid[0]);
		for (j = 1; j < bidlen && n > 0 && n + 2 < (int)sizeof(buf); j++)
			n += snprintf(buf + n, sizeof(buf) - n, "%02x", bid[j]);
		if (n > 0 && n + 6 < (int)sizeof(buf)) {
			memcpy(buf + n, ".debug", 7);
			if ((res = try_debug_file(buf, dsz, bid, bidlen, link, linklen, linksz)))
				return res;
		}
	}

	if (!link)
		return NULL;

	/* 2. .gnu_debuglink, in locations relative to the object itself:
	 *    <objdir>/<name> and <objdir>/.debug/<name>
	 */
	n = snprintf(buf, sizeof(buf), "%.*s%.*s",
		     (int)dirlen, obj_path, (int)linklen, link);
	if (n > 0 && n < (int)sizeof(buf) && (res = try_debug_file(buf, dsz, bid, bidlen, link, linklen, linksz)))
		return res;

	n = snprintf(buf, sizeof(buf), "%.*s.debug/%.*s",
		     (int)dirlen, obj_path, (int)linklen, link);
	if (n > 0 && n < (int)sizeof(buf) && (res = try_debug_file(buf, dsz, bid, bidlen, link, linklen, linksz)))
		return res;

	/* 3. for each debug directory, <root>/<objdir>/<name> */
	for (d = 0; (root = dbg_dir(d)); d++) {
		n = snprintf(buf, sizeof(buf), "%s%.*s%.*s",
			     root, (int)dirlen, obj_path, (int)linklen, link);
		if (n > 0 && n < (int)sizeof(buf) && (res = try_debug_file(buf, dsz, bid, bidlen, link, linklen, linksz)))
			return res;
	}
	return NULL;
}

static const void *elf_find_section(const void *map, size_t sz, const ElfW(Ehdr) *eh,
				    const char *shstr, size_t shstrsz,
				    const char *name, size_t *psize)
{
	const ElfW(Shdr) *sh = (const ElfW(Shdr) *)((const char *)map + eh->e_shoff);
	const void *data;
	unsigned int i;

	for (i = 0; i < eh->e_shnum; i++) {
		if (sh[i].sh_type == SHT_NOBITS || sh[i].sh_name >= shstrsz)
			continue;
		if (strcmp(shstr + sh[i].sh_name, name) != 0)
			continue;

		data = (const char *)map + sh[i].sh_offset;
		if (!in_map(data, sh[i].sh_size, map, sz) || !sh[i].sh_size)
			return NULL;
		*psize = sh[i].sh_size;
		return data;
	}
	return NULL;
}

static void elf_find_symtab(const ElfW(Ehdr) *eh,
			    const ElfW(Shdr) **symtab, const ElfW(Shdr) **strtab)
{
	const ElfW(Shdr) *sh = (const ElfW(Shdr) *)((const char *)eh + eh->e_shoff);
	unsigned int i;

	*symtab = *strtab = NULL;
	for (i = 0; i < eh->e_shnum; i++) {
		if (sh[i].sh_type == SHT_SYMTAB && sh[i].sh_link < eh->e_shnum) {
			*symtab = &sh[i];
			*strtab = &sh[sh[i].sh_link];
			return;
		}
	}
}

/* Decompresses the xz-compressed ELF image
 */
static void collect_debugdata(struct sym_build *b, const struct sym_obj *obj,
			      const unsigned char *blob, size_t size)
{
	static const unsigned char magic[6] = { 0xfd, '7', 'z', 'X', 'Z', 0x00 };
	static int crc_done;
	const ElfW(Shdr) *symtab, *strtab;
	const ElfW(Ehdr) *eh;
	struct xz_dec *dec;
	struct xz_buf xb;
	unsigned char *out, *new;
	size_t outsz = 1024 * 1024;
	enum xz_ret ret;

	/* room left empty by a build without the required tools, or not a
	 * compressed table at all.
	 */
	if (size < sizeof(magic) || memcmp(blob, magic, sizeof(magic)) != 0)
		return;

	if (!crc_done) {
		xz_crc32_init();
		xz_crc64_init();
		crc_done = 1;
	}

	dec = xz_dec_init(XZ_DYNALLOC, SYM_DEBUGDATA_DICT_MAX);
	if (!dec)
		return;

	out = malloc(outsz);
	if (!out)
		goto end;

	memset(&xb, 0, sizeof(xb));
	xb.in = blob;
	xb.in_size = size;
	xb.out = out;
	xb.out_size = outsz;

	while ((ret = xz_dec_run(dec, &xb)) == XZ_OK) {
		/* only a full output buffer is worth retrying, anything else
		 * means the stream is truncated.
		 */
		if (xb.out_pos < xb.out_size || outsz >= SYM_DEBUGDATA_MAX)
			goto end;
		new = realloc(out, outsz * 2);
		if (!new)
			goto end;
		out = new;
		outsz *= 2;
		xb.out = out;
		xb.out_size = outsz;
	}

	if (ret != XZ_STREAM_END)
		goto end;

	eh = (const ElfW(Ehdr) *)out;
	if (!elf_hdr_ok(eh, xb.out_pos))
		goto end;

	elf_find_symtab(eh, &symtab, &strtab);
	if (!symtab || build_keep_buf(b, out) != 0)
		goto end;

	collect_syms(b, out, xb.out_pos, symtab, strtab, obj->base, obj);
	out = NULL; /* now owned by the builder */
 end:
	free(out);
	xz_dec_end(dec);
}

/* Returns the build-id, if available */
static const unsigned char *mem_build_id(const ElfW(Phdr) *phdr, unsigned int phnum,
					 unsigned long base, size_t *len)
{
	unsigned int i, j;

	for (i = 0; i < phnum; i++) {
		const unsigned char *p, *name, *desc;
		size_t rem, off, align, namesz, descsz;

		if (phdr[i].p_type != PT_NOTE || !phdr[i].p_filesz)
			continue;

		for (j = 0; j < phnum; j++) {
			if (phdr[j].p_type == PT_LOAD && (phdr[j].p_flags & PF_R) &&
			    phdr[i].p_vaddr >= phdr[j].p_vaddr &&
			    phdr[i].p_vaddr + phdr[i].p_filesz <= phdr[j].p_vaddr + phdr[j].p_filesz)
				break;
		}
		if (j == phnum)
			continue;

		/* entries are padded to the segment's alignment, 4 or 8 */
		align = phdr[i].p_align == 8 ? 8 : 4;
		p = (const unsigned char *)(base + phdr[i].p_vaddr);
		rem = phdr[i].p_filesz;
		off = 0;
		while (rem - off >= sizeof(ElfW(Nhdr))) {
			const ElfW(Nhdr) *nh = (const ElfW(Nhdr) *)(p + off);

			off += sizeof(*nh);
			namesz = ((size_t)nh->n_namesz + align - 1) & ~(align - 1);
			descsz = ((size_t)nh->n_descsz + align - 1) & ~(align - 1);
			if (namesz > rem - off)
				break;
			name = p + off;
			off += namesz;
			if (descsz > rem - off)
				break;
			desc = p + off;
			off += descsz;

			if (nh->n_type == NT_GNU_BUILD_ID && nh->n_namesz == 4 &&
			    memcmp(name, "GNU", 4) == 0 &&
			    nh->n_descsz >= 2 && nh->n_descsz <= 64) {
				*len = nh->n_descsz;
				return desc;
			}
		}
	}
	*len = 0;
	return NULL;
}

/*
 * Collect the local symbols from the symtab.
 */
#if !defined(HA_HAVE_DL_ITERATE_PHDR)
/* the loader callback is the only enumerator of the loaded objects, so the
 * file parsing stays unreferenced where that API is missing; reading a file
 * needs no loader help.
 */
__maybe_unused
#endif
static int parse_object(struct sym_build *b, const char *path, const struct sym_obj *obj,
			const ElfW(Phdr) *phdr, unsigned int phnum)
{
	const ElfW(Shdr) *symtab, *strtab;
	const ElfW(Ehdr) *eh, *deh = NULL;
	void *map, *dmap = NULL;
	size_t mapsz = 0, dmapsz = 0;
	const void *blob = NULL;
	size_t blobsz = 0;
	const unsigned char *bid = NULL, *mbid;
	const char *link = NULL, *shstr;
	size_t bidlen = 0, mbidlen, linklen = 0, linksz = 0, shstrsz = 0;
	unsigned int before;

	if (!path)
		return 0;

	map = map_file_ro(path, &mapsz);
	if (!map)
		return 0;

	eh = map;
	if (!elf_hdr_ok(eh, mapsz) ||
	    eh->e_phentsize != sizeof(ElfW(Phdr)) || eh->e_phnum != phnum ||
	    !in_map((const char *)eh + eh->e_phoff, (size_t)phnum * sizeof(ElfW(Phdr)), eh, mapsz) ||
	    memcmp((const char *)eh + eh->e_phoff, phdr, (size_t)phnum * sizeof(ElfW(Phdr))) != 0) {
		munmap(map, mapsz);
		return 0;
	}

	shstr = elf_shstrtab(eh, mapsz, &shstrsz);
	if (shstr)
		elf_debug_refs(map, mapsz, eh, shstr, shstrsz,
			       &bid, &bidlen, &link, &linklen, &linksz);

	/* Same program headers do not make it the same build: a rebuilt library
	 * often keeps its layout. So when the loaded image carries a build-id,
	 * the file must carry the same one.
	 */
	mbid = mem_build_id(phdr, phnum, obj->base, &mbidlen);
	if (mbid && (!bid || bidlen != mbidlen || memcmp(bid, mbid, bidlen) != 0)) {
		munmap(map, mapsz);
		return 0;
	}

	elf_find_symtab(eh, &symtab, &strtab);

	/* if the object is stripped (no symtab), try separate debug info, then
	 * the compressed table it may carry.
	 */
	if (!symtab) {
		if (shstr)
			blob = elf_find_section(map, mapsz, eh, shstr, shstrsz,
					        ".gnu_debugdata", &blobsz);
		dmap = map_debug_file(path, &dmapsz, bid, bidlen, link, linklen, linksz);
		if (dmap) {
			/* the debug file's symtab matches the object's vaddrs */
			deh = dmap;
			elf_find_symtab(deh, &symtab, &strtab);
		}
	}

	before = b->n;

	if (symtab) {
		collect_syms(b, deh ? dmap : map, deh ? dmapsz : mapsz,
			     symtab, strtab, obj->base, obj);
	}
	else if (blob) {
		/* not loaded in memory by this object, but readable here. The
		 * collected names point into the decompressed image, which the
		 * builder owns, so the file mappings are not needed afterwards.
		 */
		collect_debugdata(b, obj, blob, blobsz);
		munmap(map, mapsz);
		if (dmap)
			munmap(dmap, dmapsz);
		return b->oom ? -1 : (b->n != before);
	}
	else {
		munmap(map, mapsz);
		if (dmap)
			munmap(dmap, dmapsz);
		return 0;
	}

	if (b->n == before) {
		munmap(map, mapsz);
		if (dmap)
			munmap(dmap, dmapsz);
		return b->oom ? -1 : 0;
	}

	/* keep the mappings alive: names point into them, they are copied out
	 * at the end of the build. On OOM a mapping may already be released
	 * while symbols still point into it; this is safe only because b->oom
	 * aborts the build before any name is read.
	 */
	build_keep_map(b, map, mapsz);
	if (dmap)
		build_keep_map(b, dmap, dmapsz);

	return b->oom ? -1 : 1;
}

#if defined(HA_HAVE_DL_ITERATE_PHDR)

/* A compressed symbol table stored into an object by the build sits alone in a
 * segment of its own (see scripts/minidbg.sh), which is how it is recognised
 * below: nothing has to be exported for it, and the same applies to any other
 * object carrying one. Being in a segment is what makes it readable from memory
 * alone once the file is stripped, replaced or unreachable.
 */
static const unsigned char sym_xz_magic[6] = { 0xfd, '7', 'z', 'X', 'Z', 0x00 };

/*
 * Collects the exported symbols of the object as provided by the dynamic
 * linker.
 */
static void collect_dynsym_mem(struct sym_build *b, const struct dl_phdr_info *info,
			       const struct sym_obj *obj)
{
	const ElfW(Dyn) *dyn = NULL;
	const ElfW(Sym) *sym = NULL;
	const char *str = NULL;
	const ElfW(Word) *hash = NULL;
	const uint32_t *gnu = NULL;
	unsigned long base = info->dlpi_addr;
	size_t strsz = 0, nsyms = 0, i;

	b->debugdata = NULL;
	b->debugdata_size = 0;

	for (i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
			dyn = (const ElfW(Dyn) *)(base + info->dlpi_phdr[i].p_vaddr);
			break;
		}
	}
	if (!dyn)
		return;

	for (; dyn->d_tag != DT_NULL; dyn++) {
		unsigned long ptr = dyn->d_un.d_ptr;

		/* glibc relocates these pointers in place, other loaders leave
		 * the link-time vaddr which is then below the load address.
		 */
		if (ptr < base)
			ptr += base;

		switch (dyn->d_tag) {
		case DT_SYMTAB:   sym  = (const ElfW(Sym) *)ptr; break;
		case DT_STRTAB:   str  = (const char *)ptr; break;
		case DT_STRSZ:    strsz = dyn->d_un.d_val; break;
		case DT_HASH:     hash = (const ElfW(Word) *)ptr; break;
		case DT_GNU_HASH: gnu  = (const uint32_t *)ptr; break;
		}
	}
	if (!sym || !str || !strsz)
		return;

	if (hash) {
		nsyms = hash[1]; /* nchain */
	}
	else if (gnu) {
		uint32_t nbuckets = gnu[0], symoff = gnu[1], bloomsz = gnu[2];
		const uint32_t *buckets = (const uint32_t *)((const ElfW(Addr) *)(gnu + 4) + bloomsz);
		const uint32_t *chains = buckets + nbuckets;
		uint32_t last = 0;

		for (i = 0; i < nbuckets; i++)
			if (buckets[i] > last)
				last = buckets[i];
		if (last >= symoff) {
			/* walk the last chain to its terminator */
			while (!(chains[last - symoff] & 1))
				last++;
			nsyms = last + 1;
		}
	}
	else if ((const char *)sym < str) {
		nsyms = (size_t)(str - (const char *)sym) / sizeof(*sym);
	}

	for (i = 0; i < nsyms && !b->oom; i++) {
		unsigned char type = SYM_ST_TYPE(sym[i].st_info);

		if (sym[i].st_shndx == SHN_UNDEF || sym[i].st_shndx >= SHN_LORESERVE)
			continue;
		if (!sym[i].st_value || sym[i].st_name >= strsz || !str[sym[i].st_name])
			continue;

		if (type != STT_FUNC && type != STT_GNU_IFUNC)
			continue;

		build_add_sym(b, base + sym[i].st_value, sym[i].st_size, str + sym[i].st_name, obj);
	}
}


/* Returns the end address of the loaded segment covering <addr> in the object
 * described by <info>, or 0 when it is covered by none.
 */
static unsigned long seg_end(const struct dl_phdr_info *info, unsigned long addr)
{
	unsigned long beg;
	int idx;

	for (idx = 0; idx < info->dlpi_phnum; idx++) {
		if (info->dlpi_phdr[idx].p_type != PT_LOAD)
			continue;
		beg = info->dlpi_addr + info->dlpi_phdr[idx].p_vaddr;
		if (addr >= beg && addr < beg + info->dlpi_phdr[idx].p_memsz)
			return beg + info->dlpi_phdr[idx].p_memsz;
	}
	return 0;
}

/* dl_iterate_phdr() callback: collects each loaded object into the builder.
 * Local symbols come from the file's .symtab (or separate debug file) when
 * readable, exported ones always from the memory image, and the well-known
 * entry points of sym_known_fcts[] are always added for the executable.
 * Returns non-zero (stopping the iteration) on OOM.
 */
static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct sym_build *b = data;
	unsigned long beg = ~0UL, end = 0;
	const char *path = NULL, *name = info->dlpi_name;
	struct sym_obj *obj;
	unsigned int before;
	int is_exe = 0;
	int idx, seen = 0, ret = 0;

	if (!name || !*name) {
		/* the main executable has an empty name */
		path = name = get_exec_path();
		is_exe = 1;
	}
	else if (strchr(name, '/')) {
		path = name;
	}
	/* else vDSO or similar: no backing file, memory image only */

	/* compute the runtime address range from the PT_LOAD segments */
	for (idx = 0; idx < info->dlpi_phnum; idx++) {
		unsigned long p1, p2;

		if (info->dlpi_phdr[idx].p_type != PT_LOAD ||
		    !info->dlpi_phdr[idx].p_memsz)
			continue;
		seen = 1;
		p1 = info->dlpi_phdr[idx].p_vaddr;
		p2 = p1 + info->dlpi_phdr[idx].p_memsz;
		if (p1 < beg)
			beg = p1;
		if (p2 > end)
			end = p2;
	}
	if (!seen)
		return 0;

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		b->oom = 1;
		return 1;
	}
	obj->base = info->dlpi_addr;
	obj->low = info->dlpi_addr + beg;
	obj->high = info->dlpi_addr + end;
	obj->is_exe = is_exe;
	obj->file = name ? strdup(name) : NULL; /* NULL tolerated; only used for the lib: prefix */

	before = b->n;

	/* .symtab first so it wins dedup over an alias at the same address
	 * (radix sort is stable), then the memory image, then the well-known
	 * functions (sizeless) as a last resort.
	 */
#ifdef __linux__
	/* always the running image, even if the file was moved or replaced,
	 * or if the exec path is relative and the process changed directory.
	 */
	if (is_exe)
		ret = parse_object(b, "/proc/self/exe", obj, info->dlpi_phdr, info->dlpi_phnum);
#endif
	if (ret == 0)
		ret = parse_object(b, path, obj, info->dlpi_phdr, info->dlpi_phnum);
	if (ret < 0)
		goto fail;

	collect_dynsym_mem(b, info, obj);

	/* a table stored by the build is covered by a segment of its own, whose
	 * contents identify it.
	 */
	for (idx = 0; !b->debugdata && idx < info->dlpi_phnum; idx++) {
		const unsigned char *p;

		if (info->dlpi_phdr[idx].p_type != PT_LOAD ||
		    !(info->dlpi_phdr[idx].p_flags & PF_R) ||
		    info->dlpi_phdr[idx].p_filesz < sizeof(sym_xz_magic))
			continue;
		p = (const unsigned char *)(info->dlpi_addr + info->dlpi_phdr[idx].p_vaddr);
		if (memcmp(p, sym_xz_magic, sizeof(sym_xz_magic)) == 0) {
			b->debugdata = p;
			b->debugdata_size = info->dlpi_phdr[idx].p_filesz;
		}
	}
	/* stay within the mapping no matter what the segment advertises */
	if (b->debugdata) {
		unsigned long end = seg_end(info, (unsigned long)b->debugdata);

		if (!end)
			b->debugdata_size = 0;
		else if (end - (unsigned long)b->debugdata < b->debugdata_size)
			b->debugdata_size = end - (unsigned long)b->debugdata;
	}

	/* the file's symbol table, when we could read it, is a superset of the
	 * embedded one, so only pay for the decompression when we have nothing.
	 */
	if (b->debugdata && b->debugdata_size && ret <= 0)
		collect_debugdata(b, obj, b->debugdata, b->debugdata_size);

	if (is_exe)
		add_known(b, obj);

	if (b->oom)
		goto fail;

	if (b->n == before) {
		/* no symbol at all: drop this object */
		free((void *)obj->file);
		free(obj);
		return 0;
	}

	if (build_keep_obj(b, obj) != 0)
		goto fail;
	return 0;

 fail:
	free((void *)obj->file);
	free(obj);
	return 1;
}

#endif /* HA_HAVE_DL_ITERATE_PHDR */
#endif /* __ELF__ */

/* collects everything known about the loaded objects */
static void collect_all(struct sym_build *b)
{
#if defined(HA_HAVE_DL_ITERATE_PHDR) && defined(__ELF__)
	dl_iterate_phdr(phdr_cb, b);
#else
	/* without the dynamic linker's help, only the well-known functions,
	 * into an object describing the executable whose extent is unknown,
	 * so any address may be attributed to it.
	 */
	struct sym_obj *obj;

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		b->oom = 1;
		return;
	}
	obj->high = ~0UL;
	obj->is_exe = 1;
	if (build_keep_obj(b, obj) != 0) {
		free(obj);
		return;
	}
	add_known(b, obj);
#endif
}

/* release a snapshot and every object it references; <t> may be NULL. Must
 * not run while a thread may still be resolving: a build replaces the
 * previous snapshot before the threads are started, and the deinit runs
 * once they are gone.
 */
static void sym_free_table(struct sym_table *t)
{
	unsigned int i;

	if (!t)
		return;

	for (i = 0; i < t->nobjs; i++) {
		free((void *)t->objs[i]->file);
		free(t->objs[i]);
	}
	free(t->objs);
	free(t->syms);
	free(t->names);
	free(t);
}

/* build and publish the snapshot */
static void sym_build(void)
{
	struct sym_build b = { 0 };
	struct sym_entry *scratch = NULL;
	struct sym_table *t = NULL, *prev = NULL;
	char *pool = NULL, *p;
	size_t namebytes = 0;
	unsigned int i, out = 0;
	int published = 0;

	if (global.tune.debug & GDBG_NO_ELF_SYMS)
		return;

	/* the table is built at boot, while the process is still starting and
	 * no thread is running yet, so the build needs no locking. An init
	 * phase may load more objects with dlopen() and build again to
	 * cover them, releasing the previous snapshot; once threads are
	 * running, later builds are ignored.
	 */
	if (!(global.mode & MODE_STARTING))
		return;

	collect_all(&b);
	if (b.oom || !b.n)
		goto leave;

	/* sort all symbols of all objects by address */
	scratch = malloc(b.n * sizeof(*scratch));
	if (!scratch)
		goto leave;
	radix_sort_syms(b.syms, scratch, b.n);

	/* drop duplicate addresses (keep the first collected), and size the name
	 * pool from the survivors.
	 */
	for (i = 0; i < b.n; i++) {
		if (out && b.syms[out - 1].addr == b.syms[i].addr)
			continue;
		b.syms[out] = b.syms[i];
		namebytes += strlen(b.syms[i].name) + 1;
		out++;
	}

	/* copy the surviving names out of the (still-mapped) files into a single
	 * pool so the mappings can then be released.
	 */
	pool = malloc(namebytes);
	t = malloc(sizeof(*t));
	if (!pool || !t)
		goto leave;

	p = pool;
	for (i = 0; i < out; i++) {
		size_t l = strlen(b.syms[i].name) + 1;

		memcpy(p, b.syms[i].name, l);
		b.syms[i].name = p;
		p += l;
	}

	t->syms = b.syms;   /* hand the sorted, deduped array to the snapshot */
	t->nsyms = out;
	t->names = pool;
	t->objs = b.objs;   /* the objects are referenced by the published symbols */
	t->nobjs = b.nobjs;
	b.syms = NULL;      /* ownership transferred */
	b.objs = NULL;
	pool = NULL;

	/* publish; the previous snapshot, if any, can be released: the build
	 * runs before the threads are started, so nothing can be walking it.
	 * The last published snapshot is released at deinit.
	 */
	prev = HA_ATOMIC_LOAD(&cur_symtab);
	HA_ATOMIC_STORE(&cur_symtab, t);
	published = 1;

 leave:
	/* release all file mappings; collected names have been copied out (or
	 * are being discarded along with b.syms).
	 */
	for (i = 0; i < b.nmaps; i++)
		munmap(b.maps[i].addr, b.maps[i].size);
	free(b.maps);

	for (i = 0; i < b.nbufs; i++)
		free(b.bufs[i]);
	free(b.bufs);

	/* on success the objects are referenced by the published symbols and
	 * survive with the snapshot; on failure free them.
	 */
	if (!published) {
		for (i = 0; i < b.nobjs; i++) {
			free((void *)b.objs[i]->file);
			free(b.objs[i]);
		}
		free(t);
		free(pool);
	}
	free(b.objs);       /* NULL on success */
	free(b.syms);       /* NULL on success */
	free(scratch);

	sym_free_table(prev);
}

/* release the last published snapshot; lookups fall back to dladdr() once
 * the table pointer is NULL.
 */
static void sym_free_all(void)
{
	unsigned int i;

	sym_free_table(HA_ATOMIC_XCHG(&cur_symtab, NULL));

	for (i = 0; i < nb_dbg_dirs; i++)
		free((void *)dbg_dirs[i]);
	free(dbg_dirs);
	dbg_dirs = NULL;
	nb_dbg_dirs = 0;
}

REGISTER_POST_DEINIT(sym_free_all);

int sym_load_all(void)
{
	sym_build();
	return ERR_NONE;
}

static int sym_resolve(const void *addr, struct sym_lookup *out)
{
	const struct sym_table *t = HA_ATOMIC_LOAD(&cur_symtab);
	unsigned long a = (unsigned long)addr;
	const struct sym_entry *e;
	const struct sym_obj *obj;
	int lo, hi, mid, found;

	if (!t || !t->nsyms)
		return 0;

	/* binary search the greatest symbol whose addr <= a, across all objects */
	lo = 0;
	hi = (int)t->nsyms - 1;
	found = -1;
	while (lo <= hi) {
		mid = lo + (hi - lo) / 2;
		if (t->syms[mid].addr <= a) {
			found = mid;
			lo = mid + 1;
		}
		else
			hi = mid - 1;
	}
	if (found < 0)
		return 0;

	e = &t->syms[found];
	obj = e->obj;

	/* reject addresses beyond the owning object (e.g. in a gap between two
	 * objects): they are not actually covered by this symbol. Let the caller
	 * fall back to dladdr() in that case. Within the object, the nearest
	 * lower symbol is reported even past its size: "sym+off/size" remains
	 * usable as an address expression in gdb, unlike a raw object offset.
	 * <inside> tells whether the symbol really covers the address (same
	 * rule as dladdr(): a sizeless symbol only matches exactly).
	 */
	if (a >= obj->high)
		return 0;

	out->file = obj->file;
	out->is_exe = obj->is_exe;
	out->obj_base = obj->base;
	out->name = e->name;
	out->addr = (const void *)e->addr;
	out->size = e->size;
	out->inside = e->size ? a < e->addr + e->size : a == e->addr;
	return 1;
}

REGISTER_POST_CHECK(sym_load_all);

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

/* appends "[obj:]sym[+off[/size]]" for the symbol <sl> found for <addr>; the
 * object prefix (between last '/' and first following '.') is omitted for the
 * executable or when <with_obj> is zero.
 */
static void dump_sym_lookup(struct buffer *buf, const struct sym_lookup *sl,
			    const void *addr, int with_obj)
{
	if (with_obj && !sl->is_exe && sl->file) {
		const char *fn = sl->file, *q;

		q = strrchr(fn, '/');
		if (q)
			fn = q + 1;
		q = strchr(fn, '.');
		if (!q)
			q = fn + strlen(fn);
		chunk_appendf(buf, "%.*s:", (int)(long)(q - fn), fn);
	}

	chunk_appendf(buf, "%s", sl->name);
	if (addr != sl->addr) {
		chunk_appendf(buf, "+%#lx", (long)(addr - sl->addr));
		if (sl->size)
			chunk_appendf(buf, "/%#lx", (long)sl->size);
	}
}

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
	struct sym_lookup sl;
	int have_near = 0;
	size_t dist, best_dist;
	int i, best_idx;

	if (pfx)
		chunk_appendf(buf, "%s", pfx);

	best_idx = -1; best_dist = ~0;
	for (i = 0; i < sym_known_nb; i++) {
		if (addr < sym_known_fcts[i].func)
			continue;
		dist = addr - sym_known_fcts[i].func;
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

	/* First try our own ELF symbol tables. Unlike dladdr(), these also
	 * contain local/static functions (from .symtab) and work on static
	 * builds. They're lock-free and async-signal-safe. Like dladdr(), a
	 * symbol is only considered resolved (non-NULL return) when the
	 * address is really within it: callers use this to tell code pointers
	 * from arbitrary values. When only the nearest lower symbol is known,
	 * the dladdr() path below gets the priority (it may know a data symbol
	 * or the object), and the nearest symbol is only used where the old
	 * output would have been a bare offset.
	 */
	if (sym_resolve(addr, &sl) && sl.name) {
		if (sl.inside) {
			dump_sym_lookup(buf, &sl, addr, 1);
			return sl.addr;
		}
		have_near = 1;
	}

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
		/* unresolved symbol from a known library, report the nearest
		 * symbol if known, otherwise the relative offset.
		 */
		if (have_near)
			dump_sym_lookup(buf, &sl, addr, 0);
		else
			chunk_appendf(buf, "+%#lx", (long)(addr - dli.dli_fbase));
		return NULL;
	}
#endif /* __ELF__ && !__linux__ || USE_DL */
 use_array:
	/* either exact match from the array, or unresolved symbol for which we
	 * may have a close match, in the array or in the ELF tables. Otherwise
	 * we report an offset relative to main.
	 */
	if (have_near && (best_idx < 0 || (size_t)(addr - sl.addr) < best_dist)) {
		dump_sym_lookup(buf, &sl, addr, 1);
		return NULL;
	}

	if (best_idx >= 0) {
		chunk_appendf(buf, "%s", sym_known_fcts[best_idx].name);
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
