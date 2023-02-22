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

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/ring.h>

int force = 0; // force access to a different layout
int lfremap = 0; // remap LF in traces
int repair = 0; // repair file


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

/* This function dumps all events from the ring whose pointer is in <p0> into
 * the appctx's output buffer, and takes from <o0> the seek offset into the
 * buffer's history (0 for oldest known event). It looks at <i0> for boolean
 * options: bit0 means it must wait for new data or any key to be pressed. Bit1
 * means it must seek directly to the end to wait for new contents. It returns
 * 0 if the output buffer or events are missing is full and it needs to be
 * called again, otherwise non-zero. It is meant to be used with
 * cli_release_show_ring() to clean up.
 */
int dump_ring(struct ring *ring, size_t ofs, int flags)
{
	struct buffer buf;
	uint64_t msg_len = 0;
	size_t len, cnt;
	const char *blk1 = NULL, *blk2 = NULL, *p;
	size_t len1 = 0, len2 = 0, bl;

	/* Explanation: the storage area in the writing process starts after
	 * the end of the structure. Since the whole area is mmapped(), we know
	 * it starts at 0 mod 4096, hence the buf->area pointer's 12 LSB point
	 * to the relative offset of the storage area. As there will always be
	 * users using the wrong version of the tool with a dump, we need to
	 * run a few checks first. After that we'll create our own buffer
	 * descriptor matching that area.
	 */
	if ((((long)ring->buf.area) & 4095) != sizeof(*ring)) {
		if (!force) {
			fprintf(stderr, "FATAL: header in file is %ld bytes long vs %ld expected!\n",
				(((long)ring->buf.area) & 4095),
				(long)sizeof(*ring));
			exit(1);
		}
		else {
			fprintf(stderr, "WARNING: header in file is %ld bytes long vs %ld expected!\n",
				(((long)ring->buf.area) & 4095),
				(long)sizeof(*ring));
		}
		/* maybe we could emit a warning at least ? */
	}

	/* Now make our own buffer pointing to that area */
	buf = b_make(((void *)ring + (((long)ring->buf.area) & 4095)),
		     ring->buf.size, ring->buf.head, ring->buf.data);

	/* explanation for the initialization below: it would be better to do
	 * this in the parsing function but this would occasionally result in
	 * dropped events because we'd take a reference on the oldest message
	 * and keep it while being scheduled. Thus instead let's take it the
	 * first time we enter here so that we have a chance to pass many
	 * existing messages before grabbing a reference to a location. This
	 * value cannot be produced after initialization.
	 */
	if (unlikely(ofs == ~0)) {
		ofs = 0;

		/* going to the end means looking at tail-1 */
		ofs = (flags & RING_WF_SEEK_NEW) ? buf.data - 1 : 0;

		//HA_ATOMIC_INC(b_peek(&buf, ofs));
	}

	while (1) {
		//HA_RWLOCK_RDLOCK(LOGSRV_LOCK, &ring->lock);

		if (ofs >= buf.size) {
			fprintf(stderr, "FATAL error at %d\n", __LINE__);
			return 1;
		}
		//HA_ATOMIC_DEC(b_peek(&buf, ofs));

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

		//HA_ATOMIC_INC(b_peek(&buf, ofs));
		//HA_RWLOCK_RDUNLOCK(LOGSRV_LOCK, &ring->lock);

		if (!(flags & RING_WF_WAIT_MODE))
			break;

		/* pause 10ms before checking for new stuff */
		usleep(10000);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ring *ring;
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

	return dump_ring(ring, ~0, 0);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
