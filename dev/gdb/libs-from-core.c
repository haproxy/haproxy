/*
 * Extracts the libs archives from a core dump
 *
 * Copyright (C) 2026 Willy Tarreau <w@1wt.eu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/* Note: builds with no option under glibc, and can be built as a minimal
 * uploadable static executable using nolibc as well:
    gcc -o libs-from-core -nostdinc -nostdlib -s -Os -static -fno-ident \
        -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables \
        -Wl,--gc-sections,--orphan-handling=discard,-znoseparate-code \
        -I /path/to/nolibc-sysroot/include libs-from-core.c
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void usage(const char *progname)
{
	const char *slash = strrchr(progname, '/');

	if (slash)
		progname = slash + 1;

	fprintf(stderr,
	        "Usage: %s [-q] <core_file>\n"
	        "Locate a libs archive from an haproxy core dump and dump it to stdout.\n"
	        "Arguments:\n"
	        "    -q            Query mode: only report offset and length, do not dump\n"
	        "    core_file     Core dump produced by haproxy\n",
	        progname);
}

int main(int argc, char **argv)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	struct stat st;
	uint8_t *mem;
	int i, fd;
	const char *fname;
	int quiet = 0;
	int arg;

	for (arg = 1; arg < argc; arg++) {
		if (*argv[arg] != '-')
			break;

		if (strcmp(argv[arg], "-q") == 0)
			quiet = 1;
		else if (strcmp(argv[arg], "--") == 0) {
			arg++;
			break;
		}
	}

	if (arg < argc) {
		fname = argv[arg];
	} else {
		usage(argv[0]);
		exit(1);
	}

	fd = open(fname, O_RDONLY);

	/* Let's just map the core dump as an ELF header */
	fstat(fd, &st);
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap()");
		exit(1);
	}

	/* get the program headers */
	ehdr = (Elf64_Ehdr *)mem;

	/* check that it's really a core. Should be "\x7fELF" */
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "ELF magic not found.\n");
		exit(1);
	}

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Only 64-bit ELF supported.\n");
		exit(1);
	}

	if (ehdr->e_type != ET_CORE) {
		fprintf(stderr, "ELF type %d, not a core dump.\n", ehdr->e_type);
		exit(1);
	}

	/* OK we can safely go with program headers */
	phdr = (Elf64_Phdr *)(mem + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++) {
		uint64_t size   = phdr[i].p_filesz;
		uint64_t offset = phdr[i].p_offset;
		int ret = 0;

		if (phdr[i].p_type != PT_LOAD)
			continue;

		//fprintf(stderr, "Scanning segment %d...\n", ehdr->e_phnum);
		//fprintf(stderr, "\r%-5d: off=%lx va=%lx sz=%lx     ", i, (long)offset, (long)phdr[i].p_vaddr, (long)size);
		if (!size)
			continue;

		if (size < 512) // minimum for a tar header
			continue;

		/* tar magic */
		if (memcmp(mem + offset + 257, "ustar\0""00", 8) != 0)
			continue;

		/* uid, gid */
		if (memcmp(mem + offset + 108, "0000000\0""0000000\0", 16) != 0)
			continue;

		/* link name */
		if (memcmp(mem + offset + 157, "haproxy-libs-dump\0", 18) != 0)
			continue;

		/* OK that's really it */

		if (quiet)
			printf("offset=%#lx size=%#lx\n", offset, size);
		else
			ret = (write(1, mem + offset, size) == size) ? 0 : 1;
		return ret;
	}
	//fprintf(stderr, "\r%75s\n", "\r");
	fprintf(stderr, "libs archive not found. Was 'set-dumpable' set to 'libs' ?\n");
	return 1;
}
