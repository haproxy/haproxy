/*
 * post-mortem ring reader for haproxy
 *
 * Copyright (C) 2022 Willy Tarreau <w@1wt.eu>
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
/* we do not implement BUG_ON() */
#undef DEBUG_STRICT

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/ring-t.h>
#include <haproxy/thread.h>

int force = 0; // force access to a different layout
int lfremap = 0; // remap LF in traces
int repair = 0; // repair file

struct ring_v1 {
	struct buffer buf;   // storage area
};

// ring v2 format (not aligned)
struct ring_v2 {
	size_t size;         // storage size
	size_t rsvd;         // header length (used for file-backed maps)
	size_t tail;         // storage tail
	size_t head;         // storage head
	char area[0];        // storage area begins immediately here
};

// ring v2 format (thread aligned)
struct ring_v2a {
	size_t size;         // storage size
	size_t rsvd;         // header length (used for file-backed maps)
	size_t tail __attribute__((aligned(64)));         // storage tail
	size_t head __attribute__((aligned(64)));         // storage head
	char area[0] __attribute__((aligned(64)));        // storage area begins immediately here
};

/* display the message and exit with the code */
__attribute__((noreturn)) void die(int code, const char *format, ...)
{
	va_list args;

	if (format) {
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
	}
	exit(code);
}

/* display the usage message and exit with the code */
__attribute__((noreturn)) void usage(int code, const char *arg0)
{
	die(code,
	    "Usage: %s [options]* <file>\n"
	    "\n"
	    "options :\n"
	    "  -f           : force accessing a non-matching layout for 'ring struct'\n"
	    "  -l           : replace LF in contents with CR VT\n"
	    "  -r           : \"repair\" corrupted file (actively search for message boundaries)\n"
	    "\n"
	    "", arg0);
}

/* dump a ring represented in a pre-initialized buffer, starting from offset
 * <ofs> and with flags <flags>
 */
int dump_ring_as_buf(struct buffer buf, size_t ofs, int flags)
{
	uint64_t msg_len = 0;
	size_t len, cnt;
	const char *blk1 = NULL, *blk2 = NULL, *p;
	size_t len1 = 0, len2 = 0, bl;

	while (1) {
		if (ofs >= buf.size) {
			fprintf(stderr, "FATAL error at %d\n", __LINE__);
			return 1;
		}

		/* in this loop, ofs always points to the counter byte that precedes
		 * the message so that we can take our reference there if we have to
		 * stop before the end.
		 */
		while (ofs + 1 < b_data(&buf)) {
			if (unlikely(repair && *b_peek(&buf, ofs))) {
				/* in repair mode we consider that we could have landed
				 * in the middle of a message so we skip all bytes till
				 * the next zero.
				 */
				ofs++;
				continue;
			}
			cnt = 1;
			len = b_peek_varint(&buf, ofs + cnt, &msg_len);
			if (!len)
				break;
			cnt += len;

			if (msg_len + ofs + cnt + 1 > buf.data) {
				fprintf(stderr, "FATAL error at %d\n", __LINE__);
				return 1;
			}

			len = b_getblk_nc(&buf, &blk1, &len1, &blk2, &len2, ofs + cnt, msg_len);
			if (!lfremap) {
				if (len > 0 && len1)
					fwrite(blk1, len1, 1, stdout);
				if (len > 1 && len2)
					fwrite(blk2, len2, 1, stdout);
			} else {
				while (len > 0) {
					for (; len1; p++) {
						p = memchr(blk1, '\n', len1);
						if (!p || p > blk1) {
							bl = p ? p - blk1 : len1;
							fwrite(blk1, bl, 1, stdout);
							blk1 += bl;
							len1 -= bl;
						}

						if (p) {
							putchar('\r');
							putchar('\v');
							blk1++;
							len1--;
						}
					}
					len--;
					blk1 = blk2;
					len1 = len2;
				}
			}

			putchar('\n');

			ofs += cnt + msg_len;
		}

		if (!(flags & RING_WF_WAIT_MODE))
			break;

		/* pause 10ms before checking for new stuff */
		usleep(10000);
	}
	return 0;
}

/* This function dumps all events from the ring <ring> from offset <ofs> and
 * with flags <flags>.
 */
int dump_ring_v1(struct ring_v1 *ring, size_t ofs, int flags)
{
	struct buffer buf;

	/* Explanation: the storage area in the writing process starts after
	 * the end of the structure. Since the whole area is mmapped(), we know
	 * it starts at 0 mod 4096, hence the buf->area pointer's 12 LSB point
	 * to the relative offset of the storage area. As there will always be
	 * users using the wrong version of the tool with a dump, we need to
	 * run a few checks first. After that we'll create our own buffer
	 * descriptor matching that area.
	 */

	/* Now make our own buffer pointing to that area */
	buf = b_make(((void *)ring + (((long)ring->buf.area) & 4095)),
		     ring->buf.size, ring->buf.head, ring->buf.data);

	return dump_ring_as_buf(buf, ofs, flags);
}

/* This function dumps all events from the ring <ring> from offset <ofs> and
 * with flags <flags>.
 */
int dump_ring_v2(struct ring_v2 *ring, size_t ofs, int flags)
{
	size_t size, head, tail, data;
	struct buffer buf;

	/* In ring v2 format, we have in this order:
	 *    - size
	 *    - hdr len (reserved bytes)
	 *    - tail
	 *    - head
	 * We can rebuild an equivalent buffer from these info for the function
	 * to dump.
	 */

	/* Now make our own buffer pointing to that area */
	size = ring->size;
	head = ring->head;
	tail = ring->tail & ~RING_TAIL_LOCK;
	data = (head <= tail ? 0 : size) + tail - head;
	buf = b_make((void *)ring + ring->rsvd, size, head, data);
	return dump_ring_as_buf(buf, ofs, flags);
}

/* This function dumps all events from the ring <ring> from offset <ofs> and
 * with flags <flags>.
 */
int dump_ring_v2a(struct ring_v2a *ring, size_t ofs, int flags)
{
	size_t size, head, tail, data;
	struct buffer buf;

	/* In ring v2 format, we have in this order:
	 *    - size
	 *    - hdr len (reserved bytes)
	 *    - tail
	 *    - head
	 * We can rebuild an equivalent buffer from these info for the function
	 * to dump.
	 */

	/* Now make our own buffer pointing to that area */
	size = ring->size;
	head = ring->head;
	tail = ring->tail & ~RING_TAIL_LOCK;
	data = (head <= tail ? 0 : size) + tail - head;
	buf = b_make((void *)ring + ring->rsvd, size, head, data);
	return dump_ring_as_buf(buf, ofs, flags);
}

int main(int argc, char **argv)
{
	void *ring;
	struct stat statbuf;
	const char *arg0;
	int fd;

	arg0 = argv[0];
	while (argc > 1 && argv[1][0] == '-') {
		argc--; argv++;
		if (strcmp(argv[0], "-f") == 0)
			force = 1;
		else if (strcmp(argv[0], "-l") == 0)
			lfremap = 1;
		else if (strcmp(argv[0], "-r") == 0)
			repair = 1;
		else if (strcmp(argv[0], "--") == 0)
			break;
		else
			usage(1, arg0);
	}

	if (argc < 2)
		usage(1, arg0);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open()");
		return 1;
	}

	if (fstat(fd, &statbuf) < 0) {
		perror("fstat()");
		return 1;
	}

	ring = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	if (ring == MAP_FAILED) {
		perror("mmap()");
		return 1;
	}

	if (((struct ring_v2 *)ring)->rsvd < 4096 && // not a pointer (v1), must be ringv2's rsvd
	    ((struct ring_v2 *)ring)->rsvd + ((struct ring_v2 *)ring)->size == statbuf.st_size) {
		if (((struct ring_v2 *)ring)->rsvd < 192)
			return dump_ring_v2(ring, 0, 0);
		else
			return dump_ring_v2a(ring, 0, 0); // thread-aligned version
	}
	else
		return dump_ring_v1(ring, 0, 0);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
