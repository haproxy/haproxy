#include <haproxy/qpack-enc.h>

#include <haproxy/buf.h>
#include <haproxy/intops.h>

/* Returns the byte size required to encode <i> as a <prefix_size>-prefix
 * integer.
 */
static size_t qpack_get_prefix_int_size(int i, int prefix_size)
{
	int n = (1 << prefix_size) - 1;
	if (i < n) {
		return 1;
	}
	else {
		size_t result = 0;
		while (i) {
			++result;
			i >>= 7;
		}
		return 1 + result;
	}
}

/* Encode the integer <i> in the buffer <out> in a <prefix_size>-bit prefix
 * integer. The caller must ensure there is enough size in the buffer. The
 * prefix is OR-ed with <before_prefix> byte.
 *
 * Returns 0 if success else non-zero.
 */
static int qpack_encode_prefix_integer(struct buffer *out, int i,
                                       int prefix_size,
                                       unsigned char before_prefix)
{
	const int mod = (1 << prefix_size) - 1;
	BUG_ON_HOT(!prefix_size);

	if (i < mod) {
		if (b_room(out) < 1)
			return 1;

		b_putchr(out, before_prefix | i);
	}
	else {
		int to_encode = i - mod;
		const size_t sz = to_encode / mod;

		if (b_room(out) < sz)
			return 1;

		b_putchr(out, before_prefix | mod);
		while (1) {
			if (to_encode > 0x7f) {
				b_putchr(out, 0x80 | (to_encode & 0x7f));
				to_encode >>= 7;
			}
			else {
				b_putchr(out, to_encode & 0x7f);
				break;
			}
		}
	}

	return 0;
}

/* Returns 0 on success else non-zero. */
int qpack_encode_int_status(struct buffer *out, unsigned int status)
{
	int status_size, idx = 0;

	if (status < 100 || status > 999)
		return 1;

	switch (status) {
	case 103: idx = 24; break;
	case 200: idx = 25; break;
	case 304: idx = 26; break;
	case 404: idx = 27; break;
	case 503: idx = 28; break;
	case 100: idx = 63; break;
	case 204: idx = 64; break;
	case 206: idx = 65; break;
	case 302: idx = 66; break;
	case 400: idx = 67; break;
	case 403: idx = 68; break;
	case 421: idx = 69; break;
	case 425: idx = 70; break;
	case 500: idx = 71; break;

	/* status code not in QPACK static table, idx is null. */
	default: break;
	}

	if (idx) {
		/* status code present in QPACK static table
		 * -> indexed field line
		 */
		status_size = qpack_get_prefix_int_size(idx, 6);
		if (b_room(out) < status_size)
			return 1;

		qpack_encode_prefix_integer(out, idx, 6, 0xc0);
	}
	else {
		/* status code not present in QPACK static table
		 * -> literal field line with name reference
		 */
		char a, b, c;
		a = '0' + status / 100;
		status -= (status / 100 * 100);
		b = '0' + status / 10;
		status -= (status / 10 * 10);
		c = '0' + status;

		/* field name */
		if (qpack_encode_prefix_integer(out, 24, 4, 0x50))
			return 1;

		/* field value length */
		if (qpack_encode_prefix_integer(out, 3, 7, 0x00))
			return 1;

		if (b_room(out) < 3)
			return 1;

		b_putchr(out, a);
		b_putchr(out, b);
		b_putchr(out, c);
	}

	return 0;
}

/* Returns 0 on success else non-zero. */
int qpack_encode_field_section_line(struct buffer *out)
{
	char qpack_field_section[] = {
	  '\x00',   /* required insert count */
	  '\x00',   /* S + delta base */
	};

	if (b_room(out) < 2)
		return 1;

	b_putblk(out, qpack_field_section, 2);

	return 0;
}

#define QPACK_LFL_WLN_BIT  0x20 // Literal field line with literal name

/* Encode a header in literal field line with literal name.
 * Returns 0 on success else non-zero.
 */
int qpack_encode_header(struct buffer *out, const struct ist n, const struct ist v)
{
	int i;
	size_t sz = qpack_get_prefix_int_size(n.len, 3) + n.len +
	            qpack_get_prefix_int_size(v.len, 7) + v.len;

	if (sz > b_room(out))
		return 1;

	/* literal field line with literal name
	 * | 0 | 0 | 1 | N | H | . | . | . |
	 * N :(allow an intermediary to add the header in a dynamic table)
	 * H: huffman encoded
	 * name len
	 */
	qpack_encode_prefix_integer(out, n.len, 3, QPACK_LFL_WLN_BIT);
	/* name */
	for (i = 0; i < n.len; ++i)
		b_putchr(out, n.ptr[i]);

	/* | 0 | . | . | . | . | . | . | . |
	 * value len
	 */
	qpack_encode_prefix_integer(out, v.len, 7, 0x00);
	/* value */
	for (i = 0; i < v.len; ++i)
		b_putchr(out, v.ptr[i]);

	return 0;
}
