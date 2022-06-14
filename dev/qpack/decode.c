/*
 * QPACK stream decoder. Decode a series of hex codes on stdin using one line
 * per H3 HEADERS frame. Silently skip spaces, tabs, CR, '-' and ','.
 *
 * Compilation via Makefile
 *
 * Example run:
 *   echo 0000d1d7508b089d5c0b8170dc101a699fc15f5085ed6989397f | ./dev/qpack/decode
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_RQ_SIZE 65536
#define MAX_HDR_NUM 1000

#define QPACK_STANDALONE

#define USE_OPENSSL
#define USE_QUIC

#include <haproxy/buf-t.h>
#include <haproxy/http-hdr-t.h>
#include <haproxy/qpack-dec.h>
#include <haproxy/qpack-tbl.h>

char line[MAX_RQ_SIZE * 3 + 3];
uint8_t bin[MAX_RQ_SIZE];

char tmp_buf[MAX_RQ_SIZE];
struct buffer buf   = { .area = tmp_buf,   .data = 0, .size = sizeof(tmp_buf)   };

#define DEBUG_QPACK
#include "../src/hpack-huff.c"
#include "../src/qpack-dec.c"
#include "../src/qpack-tbl.c"

/* define to compile with BUG_ON/ABORT_NOW statements */
void ha_backtrace_to_stderr(void)
{
}

/* taken from dev/hpack/decode.c */
int hex2bin(const char *hex, uint8_t *bin, int size)
{
	int a, b, c;
	uint8_t code;
	int len = 0;

	a = b = -1;

	for (; *hex; hex++) {
		c = *hex;
		if (c == ' ' || c == '\t' || c == '\r' ||
		    c == '-' || c == ',')
			continue;

		if (c == '\n' || c == '#')
			break;

		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'a' && c <= 'f')
			c -= 'a' - 10;
		else if (c >= 'A' && c <= 'F')
			c -= 'A' - 10;
		else
			return -1;

		if (a == -1)
			a = c;
		else
			b = c;

		if (b == -1)
			continue;

		code = (a << 4) | b;
		a = b = -1;
		if (len >= size)
			return -2;

		bin[len] = code;
		len++;
	}
	if (a >= 0 || b >= 0)
		return -3;
	return len;
}

/* taken from src/tools.c */
void debug_hexdump(FILE *out, const char *pfx, const char *buf,
                   unsigned int baseaddr, int len)
{
	unsigned int i;
	int b, j;

	for (i = 0; i < (len + (baseaddr & 15)); i += 16) {
		b = i - (baseaddr & 15);
		fprintf(out, "%s%08x: ", pfx ? pfx : "", i + (baseaddr & ~15));
		for (j = 0; j < 8; j++) {
			if (b + j >= 0 && b + j < len)
				fprintf(out, "%02x ", (unsigned char)buf[b + j]);
			else
				fprintf(out, "   ");
		}

		if (b + j >= 0 && b + j < len)
			fputc('-', out);
		else
			fputc(' ', out);

		for (j = 8; j < 16; j++) {
			if (b + j >= 0 && b + j < len)
				fprintf(out, " %02x", (unsigned char)buf[b + j]);
			else
				fprintf(out, "   ");
		}

		fprintf(out, "   ");
		for (j = 0; j < 16; j++) {
			if (b + j >= 0 && b + j < len) {
				if (isprint((unsigned char)buf[b + j]))
					fputc((unsigned char)buf[b + j], out);
				else
					fputc('.', out);
			}
			else
				fputc(' ', out);
		}
		fputc('\n', out);
	}
}

int main(int argc, char **argv)
{
	struct http_hdr hdrs[MAX_HDR_NUM];
	int len, outlen, hdr_idx;

	do {
		if (!fgets(line, sizeof(line), stdin))
			break;

		if ((len = hex2bin(line, bin, MAX_RQ_SIZE)) < 0)
			break;

		outlen = qpack_decode_fs(bin, len, &buf, hdrs,
		                         sizeof(hdrs) / sizeof(hdrs[0]));
		if (outlen < 0) {
			fprintf(stderr, "QPACK decoding failed: %d\n", outlen);
			continue;
		}

		hdr_idx = 0;
		fprintf(stderr, "<<< Found %d headers:\n", outlen);
		while (1) {
			if (isteq(hdrs[hdr_idx].n, ist("")))
				break;

			fprintf(stderr, "%.*s: %.*s\n",
			        (int)hdrs[hdr_idx].n.len, hdrs[hdr_idx].n.ptr,
			        (int)hdrs[hdr_idx].v.len, hdrs[hdr_idx].v.ptr);

			++hdr_idx;
		}
	} while (1);

	return EXIT_SUCCESS;
}
