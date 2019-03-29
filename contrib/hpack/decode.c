/*
 * HPACK stream decoder. Takes a series of hex codes on stdin using one line
 * per HEADERS frame. Spaces, tabs, CR, '-' and ',' are silently skipped.
 * e.g. :
 *   echo 82864188f439ce75c875fa5784 | contrib/hpack/decode
 *
 * The DHT size may optionally be changed in argv[1].
 *
 * Build like this :
 *    gcc -I../../include -I../../ebtree -O0 -g -fno-strict-aliasing -fwrapv \
 *        -o decode decode.c
 */
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <common/chunk.h>
#include <common/hpack-dec.h>
#include <common/mini-clist.h>

#define MAX_RQ_SIZE 65536
#define MAX_HDR_NUM 1000

char hex[MAX_RQ_SIZE*3+3]; // enough for "[ XX]* <CR> <LF> \0"
uint8_t buf[MAX_RQ_SIZE];

char trash_buf[MAX_RQ_SIZE];
char tmp_buf[MAX_RQ_SIZE];

struct buffer trash = { .area = trash_buf, .data = 0, .size = sizeof(trash_buf) };
struct buffer tmp   = { .area = tmp_buf,   .data = 0, .size = sizeof(tmp_buf)   };

/* displays a <len> long memory block at <buf>, assuming first byte of <buf>
 * has address <baseaddr>. String <pfx> may be placed as a prefix in front of
 * each line. It may be NULL if unused. The output is emitted to file <out>.
 */
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

/* enable DEBUG_HPACK to show each individual hpack code */
#define DEBUG_HPACK
#include "../src/hpack-huff.c"
#include "../src/hpack-tbl.c"
#include "../src/hpack-dec.c"

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

/* reads <hex> and stops at the first LF, '#' or \0. Converts from hex to
 * binary, ignoring spaces, tabs, CR, "-" and ','. The output is sent into
 * <bin> for no more than <size> bytes. The number of bytes placed there is
 * returned, or a negative value in case of parsing error.
 */
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

int main(int argc, char **argv)
{
	struct hpack_dht *dht;
	struct http_hdr list[MAX_HDR_NUM];
	int outlen;
	int dht_size = 4096;
	int len, idx;
	int line;

	/* first arg: dht size */
	if (argc > 1) {
		dht_size = atoi(argv[1]);
		argv++;	argc--;
	}

	dht = hpack_dht_alloc(dht_size);
	if (!dht) {
		die(1, "cannot initialize dht\n");
		return 1;
	}

	for (line = 1; fgets(hex, sizeof(hex), stdin); line++) {
		len = hex2bin(hex, buf, sizeof(buf));
		if (len <= 0)
			continue;
		printf("###### line %d : frame len=%d #######\n", line, len);
		debug_hexdump(stdout, "   ", (const char *)buf, 0, len);

		outlen = hpack_decode_frame(dht, buf, len, list,
					    sizeof(list)/sizeof(list[0]), &tmp);
		if (outlen <= 0) {
			printf("   HPACK decoding failed: %d\n", outlen);
			continue;
		}

		printf("<<< Found %d headers :\n", outlen);
		for (idx = 0; idx < outlen - 1; idx++) {
			//printf("      \e[1;34m%s\e[0m: ",
			//       list[idx].n.ptr ? istpad(trash.str, list[idx].n).ptr : h2_phdr_to_str(list[idx].n.len));

			//printf("\e[1;35m%s\e[0m\n", istpad(trash.str, list[idx].v).ptr);

			printf("      %s: ", list[idx].n.ptr ?
			       istpad(trash.area, list[idx].n).ptr :
			       h2_phdr_to_str(list[idx].n.len));

			printf("%s [n=(%p,%d) v=(%p,%d)]\n",
			       istpad(trash.area, list[idx].v).ptr,
			       list[idx].n.ptr, (int)list[idx].n.len, list[idx].v.ptr, (int)list[idx].v.len);
		}
		puts(">>>");
#ifdef DEBUG_HPACK
		printf("<<=== DHT dump [ptr=%p]:\n", dht);
		hpack_dht_dump(stdout, dht);
		puts("===>>");
#endif
	}
	return 0;
}
