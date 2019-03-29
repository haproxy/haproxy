/*
 * HPACK encoding table generator. It produces a stream of
 * <len><idx><name> and a table pointing to the first <len> of each series.
 * The end of the stream is marked by <len>=0. In parallel, a length-indexed
 * table is built to access the first entry of each length.
 *
 * Build like this :
 *    gcc -I../../include -I../../ebtree -o gen-enc gen-enc.c
 */
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <common/ist.h>
#include <common/hpack-tbl.h>
#include "../../src/hpack-tbl.c"

struct idxhdr {
	const char *ptr;
	int len;
	int idx;
};

struct idxhdr idxhdr[HPACK_SHT_SIZE];
static int positions[32];
static char known_hdr[1024];

/* preferred ordering of headers of similar size. Those not mentioned will be
 * less prioritized.
 */
const struct {
	const char *name;
	const int rank;
} ranks[] = {
	{ .name = "age", .rank = 1 },
	{ .name = "via", .rank = 2 },

	{ .name = "date", .rank = 1 },
	{ .name = "host", .rank = 2 },

	{ .name = "accept", .rank = 1 },
	{ .name = "server", .rank = 2 },
	{ .name = "cookie", .rank = 3 },

	{ .name = "referer", .rank = 1 },
	{ .name = "expires", .rank = 2 },

	{ .name = "location", .rank = 1 },

	{ .name = "user-agent", .rank = 1 },
	{ .name = "set-cookie", .rank = 2 },

	{ .name = "content-type", .rank = 1 },

	{ .name = "cache-control", .rank = 1 },
	{ .name = "last-modified", .rank = 2 },
	{ .name = "accept-ranges", .rank = 3 },
	{ .name = "if-none-match", .rank = 4 },

	{ .name = "content-length", .rank = 1 },

	{ .name = "accept-encoding", .rank = 1 },
	{ .name = "accept-language", .rank = 2 },

	{ .name = "content-encoding", .rank = 1 },

	{ .name = "transfer-encoding", .rank = 1 },
	{ .name = "if-modified-since", .rank = 2 },

	{ .name = "content-disposition", .rank = 1 },
};

/* returns the rank of header <name> or 255 if not found */
int get_hdr_rank(const char *name)
{
	int i;

	for (i = 0; i < sizeof(ranks) / sizeof(ranks[0]); i++) {
		if (strcmp(ranks[i].name, name) == 0)
			return ranks[i].rank;
	}
	return 255;
}

/* sorts first on the length, second on the name, and third on the idx, so that
 * headers which appear with multiple occurrences are always met first.
 */
int cmp_idx(const void *l, const void *r)
{
	const struct idxhdr *a = l, *b = r;
	int ranka, rankb;
	int ret;

	if (a->len < b->len)
		return -1;
	else if (a->len > b->len)
		return 1;

	ranka = get_hdr_rank(a->ptr);
	rankb = get_hdr_rank(b->ptr);

	if (ranka < rankb)
		return -1;
	else if (ranka > rankb)
		return 1;

	/* same rank, check for duplicates and use index */
	ret = strcmp(a->ptr, b->ptr);
	if (ret != 0)
		return ret;

	if (a->idx < b->idx)
		return -1;
	else if (a->idx > b->idx)
		return 1;
	else
		return 0;
}

int main(int argc, char **argv)
{
	int pos;
	int prev;
	int len;
	int i;

	for (len = 0; len < 32; len++)
		positions[len] = -1;

	for (i = 0; i < HPACK_SHT_SIZE; i++) {
		idxhdr[i].ptr = hpack_sht[i].n.ptr;
		idxhdr[i].len = hpack_sht[i].n.len;
		idxhdr[i].idx = i;
	}

	/* sorts all header names by length first, then by name, and finally by
	 * idx so that we meet smaller headers first, that within a length they
	 * appear in frequency order, and that multiple occurrences appear with
	 * the smallest index first.
	 */
	qsort(&idxhdr[1], HPACK_SHT_SIZE - 1, sizeof(idxhdr[0]), cmp_idx);

	pos = 0;
	prev = -1;
	for (i = 1; i < HPACK_SHT_SIZE; i++) {
		len = idxhdr[i].len;
		if (len > 31) {
			//printf("skipping %s (len=%d)\n", idxhdr[i].ptr, idxhdr[i].len);
			continue;
		}

		/* first occurrence of this length? */
		if (positions[len] == -1)
			positions[len] = pos;
		else if (prev >= 0 &&
			 memcmp(&known_hdr[prev] + 2, idxhdr[i].ptr, len) == 0) {
			/* duplicate header field */
			continue;
		}

		/* store <len> <idx> <name> in the output array */

		if (pos + 1 + len + 2 >= sizeof(known_hdr))
			abort();

		prev = pos;
		known_hdr[pos++] = len;
		known_hdr[pos++] = idxhdr[i].idx;
		memcpy(&known_hdr[pos], idxhdr[i].ptr, len);
		pos += len;
		//printf("%d %d %s\n", len, idxhdr[i].idx, idxhdr[i].ptr);
	}

	if (pos + 1 >= sizeof(known_hdr))
		abort();
	known_hdr[pos++] = 0; // size zero ends the stream

	printf("const char hpack_enc_stream[%d] = {\n", pos);
	for (i = 0; i < pos; i++) {
		if ((i & 7) == 0)
			printf("\t /* % 4d: */", i);

		printf(" 0x%02x,", known_hdr[i]);

		if ((i & 7) == 7 || (i == pos - 1))
			putchar('\n');
	}
	printf("};\n\n");

	printf("const signed short hpack_pos_len[32] = {\n");
	for (i = 0; i < 32; i++) {
		if ((i & 7) == 0)
			printf("\t /* % 4d: */", i);

		printf(" % 4d,", positions[i]);

		if ((i & 7) == 7 || (i == pos - 1))
			putchar('\n');
	}
	printf("};\n\n");
	return 0;
}
