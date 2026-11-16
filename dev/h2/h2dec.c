/*
 * HTTP/2 frame decoder. Reads a raw HTTP/2 byte stream on stdin (e.g. as
 * produced by mkhdr) and prints one line per frame on stdout, showing the 9
 * bytes of the frame header in hex followed by their decoded meaning. For
 * HEADERS, PUSH_PROMISE and CONTINUATION frames, the header block is
 * reassembled and once complete (END_HEADERS), decoded using haproxy's HPACK
 * decoder, and each header field is printed on its own indented line, in
 * HTTP/1 form ("name: value"). An optional connection preface at the
 * beginning of the stream is detected and reported. A single HPACK dynamic
 * table is maintained for the whole stream, so the input is expected to be
 * one direction of a single connection.
 *
 * Usage: h2dec [-s <dht_size>] < input.bin
 *
 * Build like this from the top directory :
 *    make dev/h2/h2dec
 */

#define HPACK_STANDALONE

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <haproxy/chunk.h>
#include <haproxy/hpack-dec.h>

#include "../src/hpack-huff.c"
#include "../src/hpack-tbl.c"
#include "../src/hpack-dec.c"

#define MAX_FRAME_LEN  (1 << 24)   /* 24-bit length field */
#define MAX_HDR_NUM    1000
#define TMP_SIZE       (1 << 20)   /* decoded strings storage */

static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/* trash is needed by the HPACK decoder in debug mode */
static char trash_buf[TMP_SIZE];
static char tmp_buf[TMP_SIZE];
THREAD_LOCAL struct buffer trash = { .area = trash_buf, .data = 0, .size = sizeof(trash_buf) };
static struct buffer tmp = { .area = tmp_buf, .data = 0, .size = sizeof(tmp_buf) };

/* current frame's payload */
static uint8_t payload[MAX_FRAME_LEN];

/* header block being reassembled across HEADERS/PUSH_PROMISE/CONTINUATION */
static uint8_t *hblk;
static size_t hblk_len, hblk_size;
static int hblk_open;      /* 1 if a header block is waiting for CONTINUATION */
static uint32_t hblk_sid;  /* stream ID of the pending header block */

static const char *frame_types[] = {
	"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
	"PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION",
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

/* reads exactly <len> bytes from stdin into <buf>. Returns the number of bytes
 * read, which is lower than <len> only on EOF or error.
 */
static size_t read_full(void *buf, size_t len)
{
	return fread(buf, 1, len, stdin);
}

/* appends <len> bytes from <data> to the pending header block */
static void hblk_append(const uint8_t *data, size_t len)
{
	if (hblk_len + len > hblk_size) {
		size_t new_size = hblk_size ? hblk_size : 16384;

		while (new_size < hblk_len + len)
			new_size *= 2;
		hblk = realloc(hblk, new_size);
		if (!hblk)
			die(1, "out of memory\n");
		hblk_size = new_size;
	}
	memcpy(hblk + hblk_len, data, len);
	hblk_len += len;
}

/* prints <str> of length <len>, escaping non-printable characters */
static void print_escaped(const char *str, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		unsigned char c = str[i];

		if (c == '\\')
			fputs("\\\\", stdout);
		else if (isprint(c))
			putchar(c);
		else
			printf("\\x%02x", c);
	}
}

/* decodes the pending header block and prints the headers, indented */
static void hblk_decode(struct hpack_dht *dht)
{
	static struct http_hdr list[MAX_HDR_NUM];
	int outlen, idx;

	outlen = hpack_decode_frame(dht, hblk, hblk_len, list,
	                            sizeof(list) / sizeof(list[0]), &tmp);
	if (outlen <= 0) {
		printf("    HPACK decoding error %d\n", outlen);
		return;
	}

	/* the last entry is the end marker */
	for (idx = 0; idx < outlen - 1; idx++) {
		fputs("    ", stdout);
		if (isttest(list[idx].n))
			print_escaped(list[idx].n.ptr, list[idx].n.len);
		else
			fputs(h2_phdr_to_str(list[idx].n.len), stdout);
		fputs(": ", stdout);
		print_escaped(list[idx].v.ptr, list[idx].v.len);
		putchar('\n');
	}
}

/* prints the decoded flags for frame type <type> */
static void print_flags(uint8_t type, uint8_t flags)
{
	static const struct { uint8_t type, flag; const char *name; } names[] = {
		{ 0x0, 0x01, "ES" },  { 0x0, 0x08, "PAD" },
		{ 0x1, 0x01, "ES" },  { 0x1, 0x04, "EH" },
		{ 0x1, 0x08, "PAD" }, { 0x1, 0x20, "PRIO" },
		{ 0x4, 0x01, "ACK" },
		{ 0x5, 0x04, "EH" },  { 0x5, 0x08, "PAD" },
		{ 0x6, 0x01, "ACK" },
		{ 0x9, 0x04, "EH" },
	};
	const char *sep = "";
	uint8_t left = flags;
	int i;

	printf(" flags=0x%02x", flags);
	if (!flags)
		return;

	putchar('(');
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (names[i].type == type && (flags & names[i].flag)) {
			printf("%s%s", sep, names[i].name);
			left &= ~names[i].flag;
			sep = ",";
		}
	}
	if (left)
		printf("%s0x%02x", sep, left);
	putchar(')');
}

int main(int argc, char **argv)
{
	struct hpack_dht *dht;
	struct pool_head pool;
	uint8_t hdr[9];
	int dht_size = 4096;
	size_t ret;

	while (argc > 1 && *argv[1] == '-') {
		if (strcmp(argv[1], "-s") == 0 && argc > 2) {
			dht_size = atoi(argv[2]);
			argv += 2; argc -= 2;
		}
		else
			die(strcmp(argv[1], "-h") == 0 ? 0 : 1,
			    "Usage: %s [-s <dht_size>] < input.bin\n"
			    "Decodes a raw HTTP/2 frame stream read from stdin. <dht_size> is\n"
			    "the HPACK dynamic table size (default 4096).\n", argv[0]);
	}

	if (argc > 1)
		die(1, "Usage: %s [-s <dht_size>] < input.bin\n", argv[0]);

	pool.size = dht_size;
	pool_head_hpack_tbl = &pool;
	dht = hpack_dht_alloc();
	if (!dht)
		die(1, "cannot initialize dht\n");

	/* the optional preface is 24 bytes, it starts like a 9-byte frame header */
	ret = read_full(hdr, sizeof(hdr));
	if (ret == sizeof(hdr) && memcmp(hdr, preface, sizeof(hdr)) == 0) {
		char rest[sizeof(preface) - 1 - sizeof(hdr)];

		ret = read_full(rest, sizeof(rest));
		if (ret != sizeof(rest) || memcmp(rest, preface + sizeof(hdr), sizeof(rest)) != 0) {
			printf("invalid or truncated connection preface\n");
			return 1;
		}
		printf("PREFACE\n");
		ret = read_full(hdr, sizeof(hdr));
	}

	printf("-LENGTH- TY FL -STREAM_ID-\n");
	while (ret) {
		uint32_t len, sid;
		uint8_t type, flags;
		const char *err = NULL;
		uint32_t padlen = 0;
		uint32_t ofs = 0;
		size_t got;
		int i;

		for (i = 0; i < ret; i++)
			printf("%02x ", hdr[i]);

		if (ret < sizeof(hdr)) {
			printf(" truncated frame header (%u/9 bytes)\n", (uint)ret);
			return 1;
		}

		len   = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2];
		type  = hdr[3];
		flags = hdr[4];
		sid   = ((hdr[5] & 0x7f) << 24) | (hdr[6] << 16) | (hdr[7] << 8) | hdr[8];

		if (type < sizeof(frame_types) / sizeof(frame_types[0]))
			printf(" type=%s", frame_types[type]);
		else
			printf(" type=UNKNOWN(0x%02x)", type);

		printf(" sid=%u", sid);
		if (hdr[5] & 0x80)
			printf("(R)");
		printf(" len=%u", len);
		print_flags(type, flags);

		got = read_full(payload, len);

		/* padding is present for DATA, HEADERS and PUSH_PROMISE */
		if ((type == 0x0 || type == 0x1 || type == 0x5) && (flags & 0x08)) {
			if (got < 1)
				err = "missing pad length";
			else {
				padlen = payload[0];
				ofs = 1;
				printf(" padlen=%u", padlen);
				if (padlen + 1 > len)
					err = "padding exceeds frame length";
			}
		}
		putchar('\n');

		if (got < len) {
			printf("    truncated payload (%u/%u bytes)\n", (uint)got, len);
			return 1;
		}

		if (err) {
			printf("    %s\n", err);
			hblk_open = 0;
			goto next;
		}

		if (type == 0x1 || type == 0x5) {
			/* HEADERS or PUSH_PROMISE: skip the priority or promised
			 * stream ID fields, then start a new header block.
			 */
			uint32_t skip = (type == 0x5) ? 4 : (flags & 0x20) ? 5 : 0;

			if (ofs + skip + padlen > len) {
				printf("    frame too short for its fields\n");
				hblk_open = 0;
				goto next;
			}
			if (hblk_open)
				printf("    (previous header block was never completed)\n");
			hblk_len = 0;
			hblk_append(payload + ofs + skip, len - ofs - skip - padlen);
			hblk_open = 1;
			hblk_sid = sid;
		}
		else if (type == 0x9) {
			if (!hblk_open) {
				printf("    (unexpected CONTINUATION, no header block in progress)\n");
				goto next;
			}
			if (sid != hblk_sid)
				printf("    (CONTINUATION on stream %u, header block started on stream %u)\n",
				       sid, hblk_sid);
			hblk_append(payload, len);
		}
		else {
			if (hblk_open)
				printf("    (header block on stream %u interrupted without END_HEADERS)\n",
				       hblk_sid);
			hblk_open = 0;
			goto next;
		}

		if (flags & 0x04) {
			hblk_decode(dht);
			hblk_open = 0;
		}
	next:
		ret = read_full(hdr, sizeof(hdr));
	}

	if (hblk_open)
		printf("(header block on stream %u never completed)\n", hblk_sid);

	return 0;
}
