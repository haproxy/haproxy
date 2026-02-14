/*
 * Find the post-mortem offset from a core dump
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
    gcc -o pm-from-core -nostdinc -nostdlib -s -Os -static -fno-ident \
        -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables \
        -Wl,--gc-sections,--orphan-handling=discard,-znoseparate-code \
        -I /path/to/nolibc-sysroot/include pm-from-core.c
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

#if defined(__GLIBC__)
#  define my_memmem memmem
#else
void *my_memmem(const void *haystack, size_t haystacklen,
                const void *needle, size_t needlelen)
{
	while (haystacklen >= needlelen) {
		if (!memcmp(haystack, needle, needlelen))
			return (void*)haystack;
		haystack++;
		haystacklen--;
	}
	return NULL;
}
#endif

#define MAGIC "POST-MORTEM STARTS HERE+7654321\0"

int main(int argc, char **argv)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	struct stat st;
	uint8_t *mem;
	int i, fd;

	if (argc < 2) {
		printf("Usage: %s <core_file>\n", argv[0]);
		exit(1);
	}

	fd = open(argv[1], O_RDONLY);

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
		uint64_t vaddr  = phdr[i].p_vaddr;
		uint64_t found_ofs;
		uint8_t *found;

		if (phdr[i].p_type != PT_LOAD)
			continue;

		//printf("Scanning segment %d...\n", ehdr->e_phnum);
		//printf("\r%-5d: off=%lx va=%lx sz=%lx     ", i, (long)offset, (long)vaddr, (long)size);
		if (!size)
			continue;

		if (size >= 1048576) // don't scan large segments
			continue;

		found = my_memmem(mem + offset, size, MAGIC, sizeof(MAGIC) - 1);
		if (!found)
			continue;

		found_ofs = found - (mem + offset);

		printf("Found post-mortem magic in segment %d:\n", i);
		printf("  Core File Offset: 0x%lx (0x%lx + 0x%lx)\n", offset + found_ofs, offset, found_ofs);
		printf("  Runtime VAddr:    0x%lx (0x%lx + 0x%lx)\n", vaddr + found_ofs, vaddr, found_ofs);
		printf("  Segment Size:     0x%lx\n", size);
		printf("\nIn gdb, copy-paste this line:\n\n   pm_init 0x%lx\n\n", vaddr + found_ofs);
		return 0;
	}
	//printf("\r%75s\n", "\r");
	printf("post-mortem magic not found\n");
	return 1;
}
