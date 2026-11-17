/*
 * Copyright (C) 2013-2015 Willy Tarreau <w@1wt.eu>
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

#include <stdio.h>
#include <string.h>
#include "slz.h"
#include "slz-prv.h"
#include "tables.h"

/* if PRECOMPUTE_TABLES not set, then tables.h does not provide fh_dist_table
 * nor text_dist_table as we need to recompute them.
 */
#ifndef PRECOMPUTE_TABLES
static uint32_t fh_dist_table[32768];
static uint32_t text_dist_table[32768];
#endif // ifndef PRECOMPUTE_TABLES

/* The enqueue functions have two possible implementations. The default one
 * only writes to the output buffer once it holds a whole store's worth of
 * bits, which costs a test but never writes a byte it does not advance over.
 * The "direct" one, selected by these macros, stores unconditionally and then
 * advances by however many whole bytes the queue turned out to hold, leaving
 * fewer than 8 bits behind. That saves a branch, and requires the caller to
 * leave room past the output pointer for the widest store used (3 bytes for
 * enqueue24() and enqueue8(), 7 for enqueue56()), since the bytes beyond the
 * advance are rewritten by the next call. They're only usable for unaligned
 * little endian archs and generally work better on modern x86_64. Tests show
 * that x86_64 and arm64 benefit greatly from this.
 *
 * SLZ_DIRECT_ENQUEUE56 goes further by writing a whole length+distance pair in
 * a single operation instead of two.
 */

/* directly write 32 bits at a time to output for up to 24 bits */
#ifndef SLZ_DIRECT_ENQUEUE24
# if defined(UNALIGNED_LE_OK)
#  define SLZ_DIRECT_ENQUEUE24 1
# else
#  define SLZ_DIRECT_ENQUEUE24 0
# endif
#endif

/* directly write 8 bits at a time to the output */
#ifndef SLZ_DIRECT_ENQUEUE8
# define SLZ_DIRECT_ENQUEUE8 SLZ_DIRECT_ENQUEUE24
#endif

/* directly write 64 bits at a tome to output for up to 56 bits */
#ifndef SLZ_DIRECT_ENQUEUE56
# if defined(__SIZEOF_LONG__) && (__SIZEOF_LONG__ - 0 > 4) && defined(UNALIGNED_LE_OK)
#  define SLZ_DIRECT_ENQUEUE56 1
# else
#  define SLZ_DIRECT_ENQUEUE56 0
# endif
#endif

/* The direct enqueue8() writes a single byte, which is only enough because it
 * assumes fewer than 8 bits were already queued. That holds for every enqueue
 * variant except the conditional 64-bit enqueue24(), which deliberately lets
 * up to 31 bits accumulate before storing. Combining the two would advance the
 * output pointer over bytes that were never written.
 */
#if SLZ_DIRECT_ENQUEUE8 && !SLZ_DIRECT_ENQUEUE24 && \
    defined(__SIZEOF_LONG__) && (__SIZEOF_LONG__ - 0 > 4) && defined(UNALIGNED_LE_OK)
# error "SLZ_DIRECT_ENQUEUE8 requires SLZ_DIRECT_ENQUEUE24 on this platform"
#endif

/* enqueue56() needs a 64-bit queue and unaligned little-endian stores. */
#if SLZ_DIRECT_ENQUEUE56 && !(defined(__SIZEOF_LONG__) && (__SIZEOF_LONG__ - 0 > 4) && defined(UNALIGNED_LE_OK))
# undef SLZ_DIRECT_ENQUEUE56
# define SLZ_DIRECT_ENQUEUE56 0
#endif

/* Also indexes the positions covered by the beginning of a match. This is quite
 * important for example on HTML or other streams with lots of varying prefixes,
 * especially when combined with the backwards match, because otherwise a likely
 * repeating element will not be indexed, and when the window advances, its ref
 * is likely to disappear, causing the next one to experience a miss.
 */
#ifndef SLZ_INSERT_SKIPPED
# define SLZ_INSERT_SKIPPED 1
#endif

/* Skip large non-compressible areas and send them as literals to avoid wasting
 * CPU trying to compress them. It's faster on incompressible data, at the cost
 * of a slightly reduced compression ratio.
 */
#ifndef SLZ_LITERAL_SKIP
# define SLZ_LITERAL_SKIP 1
#endif

/* Log2 of the size of the hash table used for the references table. */
#ifndef SLZ_HASH_BITS
# define SLZ_HASH_BITS 13
#endif

/* First, RFC1951-specific declarations and extracts from the RFC.
 *
 * RFC1951 - deflate stream format


             * Data elements are packed into bytes in order of
               increasing bit number within the byte, i.e., starting
               with the least-significant bit of the byte.
             * Data elements other than Huffman codes are packed
               starting with the least-significant bit of the data
               element.
             * Huffman codes are packed starting with the most-
               significant bit of the code.

      3.2.3. Details of block format

         Each block of compressed data begins with 3 header bits
         containing the following data:

            first bit       BFINAL
            next 2 bits     BTYPE

         Note that the header bits do not necessarily begin on a byte
         boundary, since a block does not necessarily occupy an integral
         number of bytes.

         BFINAL is set if and only if this is the last block of the data
         set.

         BTYPE specifies how the data are compressed, as follows:

            00 - no compression
            01 - compressed with fixed Huffman codes
            10 - compressed with dynamic Huffman codes
            11 - reserved (error)

      3.2.4. Non-compressed blocks (BTYPE=00)

         Any bits of input up to the next byte boundary are ignored.
         The rest of the block consists of the following information:

              0   1   2   3   4...
            +---+---+---+---+================================+
            |  LEN  | NLEN  |... LEN bytes of literal data...|
            +---+---+---+---+================================+

         LEN is the number of data bytes in the block.  NLEN is the
         one's complement of LEN.

      3.2.5. Compressed blocks (length and distance codes)

         As noted above, encoded data blocks in the "deflate" format
         consist of sequences of symbols drawn from three conceptually
         distinct alphabets: either literal bytes, from the alphabet of
         byte values (0..255), or <length, backward distance> pairs,
         where the length is drawn from (3..258) and the distance is
         drawn from (1..32,768).  In fact, the literal and length
         alphabets are merged into a single alphabet (0..285), where
         values 0..255 represent literal bytes, the value 256 indicates
         end-of-block, and values 257..285 represent length codes
         (possibly in conjunction with extra bits following the symbol
         code) as follows:

Length encoding :
                Extra               Extra               Extra
            Code Bits Length(s) Code Bits Lengths   Code Bits Length(s)
            ---- ---- ------     ---- ---- -------   ---- ---- -------
             257   0     3       267   1   15,16     277   4   67-82
             258   0     4       268   1   17,18     278   4   83-98
             259   0     5       269   2   19-22     279   4   99-114
             260   0     6       270   2   23-26     280   4  115-130
             261   0     7       271   2   27-30     281   5  131-162
             262   0     8       272   2   31-34     282   5  163-194
             263   0     9       273   3   35-42     283   5  195-226
             264   0    10       274   3   43-50     284   5  227-257
             265   1  11,12      275   3   51-58     285   0    258
             266   1  13,14      276   3   59-66

Distance encoding :
                  Extra           Extra               Extra
             Code Bits Dist  Code Bits   Dist     Code Bits Distance
             ---- ---- ----  ---- ----  ------    ---- ---- --------
               0   0    1     10   4     33-48    20    9   1025-1536
               1   0    2     11   4     49-64    21    9   1537-2048
               2   0    3     12   5     65-96    22   10   2049-3072
               3   0    4     13   5     97-128   23   10   3073-4096
               4   1   5,6    14   6    129-192   24   11   4097-6144
               5   1   7,8    15   6    193-256   25   11   6145-8192
               6   2   9-12   16   7    257-384   26   12  8193-12288
               7   2  13-16   17   7    385-512   27   12 12289-16384
               8   3  17-24   18   8    513-768   28   13 16385-24576
               9   3  25-32   19   8   769-1024   29   13 24577-32768

      3.2.6. Compression with fixed Huffman codes (BTYPE=01)

         The Huffman codes for the two alphabets are fixed, and are not
         represented explicitly in the data.  The Huffman code lengths
         for the literal/length alphabet are:

                   Lit Value    Bits        Codes
                   ---------    ----        -----
                     0 - 143     8          00110000 through
                                            10111111
                   144 - 255     9          110010000 through
                                            111111111
                   256 - 279     7          0000000 through
                                            0010111
                   280 - 287     8          11000000 through
                                            11000111

         The code lengths are sufficient to generate the actual codes,
         as described above; we show the codes in the table for added
         clarity.  Literal/length values 286-287 will never actually
         occur in the compressed data, but participate in the code
         construction.

         Distance codes 0-31 are represented by (fixed-length) 5-bit
         codes, with possible additional bits as shown in the table
         shown in Paragraph 3.2.5, above.  Note that distance codes 30-
         31 will never actually occur in the compressed data.

*/

/* for use to temporarily disable a builtin_expect */
#define __no_builtin_expect(cond, exp) (cond)

/* back references, built in a way that is optimal for 32/64 bits */
/* format:
 * bit0..31  = word
 * bit32..63 = last position in buffer of similar content
 */
union ref {
	struct {
		uint32_t pos;
		uint32_t word;
	} by32;
	uint64_t by64;
};

/* This hash provides good average results on HTML contents, and is among the
 * few which provide almost optimal results on various different pages. It
 * returns <bits> bits, which must be a constant.
 */
static inline __attribute__((always_inline))
uint32_t slz_hash_bits(uint32_t a, const int bits)
{
#if defined(__ARM_FEATURE_CRC32)
#  if defined(__ARM_ARCH_ISA_A64)
	// 64 bit mode
	__asm__ volatile("crc32w %w0,%w0,%w1" : "+r"(a) : "r"(0));
#  else
	// 32 bit mode (e.g. armv7 compiler building for armv8
	__asm__ volatile("crc32w %0,%0,%1" : "+r"(a) : "r"(0));
#  endif
#elif defined(__SSE4_2__) && defined(USE_CRC32C_HASH)
	// SSE 4.2 offers CRC32C which is a bit slower than the multiply
	// but provides a slightly smoother hash
	__asm__ volatile("crc32l %1,%0" : "+r"(a) : "r"(0));
#elif defined(HAVE_FAST_MULT)
	// optimal factor for SLZ_HASH_BITS=12 and SLZ_HASH_BITS=13 among 48k tested: 0x1af42f
	a = (a * 0x1af42f); // 12: 44.12, 13: 43.35
	//return (a * 0x1aaee3) >> (32 - SLZ_HASH_BITS); // 12: 44.14, 13: 43.34
	//return (a * 0x1aae0b) >> (32 - SLZ_HASH_BITS); // 12: 44.15, 13: 43.35, -30k
	//return (a * 0x17e7bd) >> (32 - SLZ_HASH_BITS); // 12: 44.15, 13: 43.36
	//return (a * 0xaae7b) >> (32 - SLZ_HASH_BITS); // 12: 44.22, 13:43.35, -1k
	//return (a * 0xaaec3) >> (32 - SLZ_HASH_BITS); // 12: 44.20, 13: 43.35, -10k // 275659647
#else
	a = ((a << 19) + (a << 6) - a);
#endif
	return a >> (32 - bits);
}

/* the hash of the main encoder's reference table, on SLZ_HASH_BITS bits */
static inline uint32_t slz_hash(uint32_t a)
{
	return slz_hash_bits(a, SLZ_HASH_BITS);
}

/* This function compares buffers <a> and <b> and reads 32 or 64 bits at a time
 * during the approach. It makes us of unaligned little endian memory accesses
 * on capable architectures. <max> is the maximum number of bytes that can be
 * read, so both <a> and <b> must have at least <max> bytes ahead. <max> may
 * safely be null or negative if that simplifies computations in the caller.
 */
static inline long memmatch(const unsigned char *a, const unsigned char *b, long max)
{
	long len = 0;

#ifdef UNALIGNED_LE_OK

	while (len + 2 * (long)sizeof(long) - 1 < max) {
		unsigned long xor;

		xor = *(unsigned long *)&a[len] ^ *(unsigned long *)&b[len];
		if (xor)
			return len + (__builtin_ctzl(xor) >> 3);
		len += (long)sizeof(long);

		xor = *(unsigned long *)&a[len] ^ *(unsigned long *)&b[len];
		if (xor)
			return len + (__builtin_ctzl(xor) >> 3);
		len += (long)sizeof(long);
	}

	while (len + (long)sizeof(long) - 1 < max) {
		unsigned long xor;

		xor = *(unsigned long *)&a[len] ^ *(unsigned long *)&b[len];
		if (xor)
			return len + (__builtin_ctzl(xor) >> 3);
		len += (long)sizeof(long);
	}

	if (sizeof(long) > 4 && len + 3 < max) {
		uint32_t xor;

		xor = *(uint32_t *)&a[len] ^ *(uint32_t *)&b[len];
		if (xor)
			return len + (__builtin_ctz(xor) >> 3);
		len += 4;
	}

	if (len + 1 < max) {
		uint16_t xor;

		xor = *(uint16_t *)&a[len] ^ *(uint16_t *)&b[len];
		if (xor)
			return len + !(uint8_t)xor;
		len += 2;
	}

	if (len < max && a[len] == b[len])
		len++;
	return len;

#else // UNALIGNED_LE_OK
	/* This is the generic version for big endian or unaligned-incompatible
	 * architectures.
	 */
	while (len < max) {
		if (a[len] != b[len])
			break;
		len++;
	}
	return len;

#endif
}

#if defined(__SIZEOF_LONG__) && (__SIZEOF_LONG__ - 0 > 4)

/* enqueue code x of <xbits> bits (LSB aligned, at most 24) and copy complete
 * 32-bit words into output buffer. X must not contain non-zero bits above
 * xbits. Note that the function may write up to 3 extra bytes since it may
 * write 32 bits even if only 8 are needed.
 */
static inline void enqueue24(struct slz_stream *__restrict strm, uint64_t x, uint32_t xbits)
{
	uint64_t queue = strm->queue + (x << strm->qbits);
	uint32_t qbits = strm->qbits + xbits;

#if SLZ_DIRECT_ENQUEUE24
	write_le32(strm->outbuf, queue);
	queue >>= qbits & ~7U;

	strm->queue = queue;
	strm->outbuf += qbits >> 3;
	strm->qbits = qbits & 7;
#else
	if (__builtin_expect(qbits >= 32, 1)) {
		write_le32(strm->outbuf, queue);
		queue >>= 32;
		qbits -= 32;
		strm->outbuf += 4;
	}

	strm->queue = queue;
	strm->qbits = qbits;
#endif
}

/* enqueue code x of <xbits> bits (at most 8) and copy complete bytes into out
 * buf. X must not contain non-zero bits above xbits.
 */
#if SLZ_DIRECT_ENQUEUE8
static inline void enqueue8(struct slz_stream *__restrict strm, uint32_t x, uint32_t xbits)
{
	uint64_t queue = strm->queue + ((uint64_t)x << strm->qbits);
	uint32_t qbits = strm->qbits + xbits;

	*strm->outbuf = queue;
	strm->outbuf += qbits >= 8;
	queue >>= qbits & 8;
	strm->queue = queue;
	strm->qbits = qbits & 7;
}
#else
#define enqueue8 enqueue24
#endif

#if SLZ_DIRECT_ENQUEUE56
/* Enqueues code <x> of <xbits> bits (LSB aligned) and stores the low 8 bytes
 * of the queue, then advances over the whole bytes it holds. <xbits> plus
 * whatever was already queued must stay below 64, and the caller must leave 8
 * bytes of room past strm->outbuf rather than the 4 the other enqueues need.
 * It exists to send a length code and the distance code that follows it in one
 * go, which is at most 31 bits: 7 or 8 for the length code plus up to 5 extra,
 * then 5 for the distance code plus up to 13 extra.
 */
static inline void enqueue56(struct slz_stream *__restrict strm, uint64_t x, uint32_t xbits)
{
	uint64_t queue = strm->queue + (x << strm->qbits);
	uint32_t qbits = strm->qbits + xbits;

	*(uint64_t *)strm->outbuf = queue;
	queue >>= qbits & ~7U;

	strm->queue = queue;
	strm->outbuf += qbits >> 3;
	strm->qbits = qbits & 7;
}
#endif

/* flush the queue and align to next byte */
static inline void flush_bits(struct slz_stream *__restrict strm)
{
	if (!strm->qbits)
		return;

	*strm->outbuf++ = strm->queue;

#if !SLZ_DIRECT_ENQUEUE24
	/* Only the conditional enqueue24() can leave more than 7 bits in the
	 * queue, and only it needs the three extra stores. The direct one
	 * masks the count with 7 on every path, as do enqueue8() and
	 * enqueue56(), so a single byte covers every case there.
	 *
	 * This is not free to get wrong: flush_bits() is inlined into
	 * copy_lit() and into all six flush/finish entry points, so the three
	 * dead stores cost 585 bytes of text and 3% of throughput on silesia
	 * once SLZ_LITERAL_SKIP starts calling copy_lit() for every skipped
	 * chunk.
	 */
	if (strm->qbits > 8)
		*strm->outbuf++ = strm->queue >> 8;

#if !SLZ_DIRECT_ENQUEUE8
	if (strm->qbits > 16)
		*strm->outbuf++ = strm->queue >> 16;

	if (strm->qbits > 24)
		*strm->outbuf++ = strm->queue >> 24;
#endif
#endif

	strm->queue = 0;
	strm->qbits = 0;
}

#else /* non-64 bit */

/* enqueue code x of <xbits> bits (LSB aligned, at most 24) and copy complete
 * bytes into out buf. X must not contain non-zero bits above xbits. Prefer
 * enqueue8() when xbits is known for being 8 or less. Note that the function
 * may write up to 3 extra bytes since it may write 32 bits even if only 8 are
 * needed.
 */
static void enqueue24(struct slz_stream *__restrict strm, uint32_t x, uint32_t xbits)
{
	uint32_t queue = strm->queue + (x << strm->qbits);
	uint32_t qbits = strm->qbits + xbits;

#if SLZ_DIRECT_ENQUEUE24
	write_le32(strm->outbuf, queue);
	queue >>= qbits & ~7U;
	strm->outbuf += qbits >> 3;
	strm->qbits = qbits & 7;
	strm->queue = queue;
	return;
#endif
	if (qbits >= 16) {
		write_le16(strm->outbuf, queue);
		strm->outbuf += 2;
		queue >>= 16;
		qbits -= 16;
	}

	if (qbits >= 8) {
		qbits -= 8;
		*strm->outbuf++ = queue;
		queue >>= 8;
	}
	strm->qbits = qbits;
	strm->queue = queue;
	return;
}

/* enqueue code x of <xbits> bits (at most 8) and copy complete bytes into
 * out buf. X must not contain non-zero bits above xbits.
 */
static inline void enqueue8(struct slz_stream *__restrict strm, uint32_t x, uint32_t xbits)
{
	uint32_t queue = strm->queue + (x << strm->qbits);
	uint32_t qbits = strm->qbits + xbits;

#if SLZ_DIRECT_ENQUEUE8
	*strm->outbuf = queue;
	strm->outbuf += qbits >= 8;
	queue >>= qbits & 8;
	strm->queue = queue;
	strm->qbits = qbits & 7;
	return;
#endif
	if (__builtin_expect((signed)(qbits - 8) >= 0, 1)) {
		qbits -= 8;
		*strm->outbuf++ = queue;
		queue >>= 8;
	}

	strm->qbits = qbits;
	strm->queue = queue;
}

/* align to next byte */
static inline void flush_bits(struct slz_stream *__restrict strm)
{
	if (!strm->qbits)
		return;

	*strm->outbuf++ = strm->queue;

#if !SLZ_DIRECT_ENQUEUE8
	if (strm->qbits > 8)
		*strm->outbuf++ = strm->queue >> 8;
#endif

	strm->queue = 0;
	strm->qbits = 0;
}
#endif


/* only valid if buffer is already aligned */
static inline void copy_8b(struct slz_stream *__restrict strm, uint32_t x)
{
	*strm->outbuf++ = x;
}

/* only valid if buffer is already aligned */
static inline void copy_16b(struct slz_stream *__restrict strm, uint32_t x)
{
	write_le16(strm->outbuf, x);
	strm->outbuf += 2;
}

/* only valid if buffer is already aligned */
static inline void copy_32b(struct slz_stream *__restrict strm, uint32_t x)
{
	write_le32(strm->outbuf, x);
	strm->outbuf += 4;
}

/* From level 2 on, the huffman tree is chosen on the fly, within a call,
 * between the fixed one and the text one. The encoder then switches between
 * them as it goes, with the same reference table, and the stream's <cur_tree>
 * tells which one is in use. The literals sent with a tree are compared to
 * what the other tree would have cost them, and the difference is accumulated
 * in <tree_save> (a cumulated sum, never below zero):
 *   - the fixed tree's literals sent in a huffman block add what the text
 *     tree would have saved on them, computed by the out-of-line function
 *     that sends them, and its stored blocks reset it (binary data);
 *   - from level 3, the fixed tree's references add what the text tree
 *     would have saved on their length and distance codes (len_tsave[] and
 *     dist_tsave[]). On text with few literals, such as C headers made of
 *     #defines, that's where nearly all of its savings are, which the
 *     literals alone take too long to notice, if ever. It costs 0.2 to 1%
 *     of speed for 0.02 to 0.8% of output, hence not at level 2;
 *   - the text tree's literals add their <lit_excess>, known when they are
 *     sent, i.e. as if the fixed tree took 8 bits for each of them, whether
 *     they are sent in a huffman block or in a stored one.
 * Above SLZ_AUTO_IN bits (fixed -> text) or SLZ_AUTO_OUT bits (text ->
 * fixed), <tree_switch> is set and the encoder switches after the next match,
 * closing its block, and continues from there with the other tree. In
 * addition, with the text tree, 64 pending literals that take 9 bits or more
 * on average switch at once: this is binary data, which the fixed tree can
 * skip, so the encoder processes them again from the first of them.
 *
 * Streams start with the text tree (see the init functions): on text, it
 * saves the 160 to 290 bytes the fixed tree took to switch, i.e. 8% of a
 * 4 kB object, while the start of a binary object costs about 80 bytes
 * until the text tree gives up.
 */
#define SLZ_AUTO_IN   1280
#define SLZ_AUTO_OUT   256

/* accounts <d> more bits that the other tree would have saved on literals
 * sent with <ctype>, and requests a switch past the threshold.
 */
static inline void auto_account(struct slz_stream *__restrict strm, int32_t d, int ctype)
{
	int32_t s = strm->tree_save + d;

	if (s < 0)
		s = 0;
	if (s > (ctype == SLZ_CT_TEXT ? SLZ_AUTO_OUT : SLZ_AUTO_IN)) {
		strm->tree_switch = 1;
		s = 0;
	}
	strm->tree_save = s;
}

/* Everything below that depends on the huffman tree takes a <ctype> argument
 * (SLZ_CT_*), that must be a constant in the encoder, so that each of its
 * specialisations only contains the code for its own tree and names the
 * tables directly. Passing the tables by pointer instead was measured to cost
 * 5.7% on the fixed tree since gcc doesn't propagate the constant pointer's
 * contents into the loop. Out of the encoder (flush, finish), it may vary.
 */

/* Using long because faster on 64-bit (can save one shift) */
static inline void send_huff(struct slz_stream *__restrict strm, unsigned long code, int ctype)
{
	uint32_t bits;

	if (ctype == SLZ_CT_TEXT)
		code = text_huff[code];
	else
		code = fixed_huff[code];
	bits = code & 15;
	code >>= 4;
	enqueue24(strm, code, bits);
}

static inline void send_eob(struct slz_stream *__restrict strm, int ctype)
{
	if (ctype == SLZ_CT_TEXT)
		enqueue24(strm, text_huff[256] >> 4, TEXT_EOB_BITS);
	else
		enqueue8(strm, 0, 7); // direct encoding of 256 = EOB (cf RFC1951)
}

/* Opens a dynamic block (BTYPE=10) with BFINAL set to <bfinal>, and sends the
 * definition of the text tree. The whole round trip is charged to the debt
 * (SLZ_TEXT_SWITCH_COST, see SLZ_TEXT_MAX_DEBT): the block type and the
 * header, and the EOB and stored block header needed to leave it later. It's
 * rare enough not to deserve being inlined.
 */
static void send_text_hdr(struct slz_stream *__restrict strm, int bfinal)
{
	uint32_t i;

	enqueue8(strm, 4 + bfinal, 3); // BFINAL = bfinal ; BTYPE = 10
	for (i = 0; i < TEXT_HDR_BITS / 8; i++)
		enqueue8(strm, text_hdr[i], 8);
	if (TEXT_HDR_BITS & 7)
		enqueue8(strm, text_hdr[i], TEXT_HDR_BITS & 7);
	strm->text_debt += TEXT_EOB_BITS + 42 + 3 + TEXT_HDR_BITS;
}

/* Opens a huffman block for <ctype> with BFINAL set to <bfinal> */
static inline void open_huff_block(struct slz_stream *__restrict strm, int bfinal, int ctype)
{
	if (ctype == SLZ_CT_TEXT)
		send_text_hdr(strm, bfinal);
	else
		enqueue8(strm, 2 + bfinal, 3); // BFINAL = bfinal ; BTYPE = 01
}

/* returns the length code for match length <mlen> in the tree for <ctype>, in
 * the len_fh[] format.
 */
static inline uint32_t len_code(long mlen, int ctype)
{
	if (ctype == SLZ_CT_TEXT)
		return text_len[mlen];
	else
		return len_fh[mlen];
}

/* copies <len> litterals from <buf>. at once. <len> must not be null and must
 * be lower than or equal to 65535, which can be guaranteed when using
 * SLZ_LITERAL_SKIP with limited literal lengths. <more> indicates that there
 * are data past buf + <len>. Use copy_lit_small() instead. In this function
 * and the other copy_lit*() ones, a non-zero <track_save> (a constant) adds
 * what the text tree would have saved on the fixed tree's literals to the
 * stream's <tree_save>, or resets it for those sent in a stored block, see
 * SLZ_AUTO_IN. It is ignored with the text tree, whose encoder does it.
 */
static inline __attribute__((always_inline))
void _copy_lit_small(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more, int ctype, int track_save)
{
	/* stored literals with the fixed tree: binary data. With the text
	 * tree, the encoder accounts them itself.
	 */
	if (track_save && ctype == SLZ_CT_GENERIC)
		strm->tree_save = 0;

	if (ctype == SLZ_CT_TEXT) {
		/* same as below with the text tree's EOB, which is not
		 * zero: 3 to 21 bits.
		 */
		uint32_t eob_bits = (strm->state == SLZ_ST_EOB) ? 0 : TEXT_EOB_BITS;
		uint32_t eob_code = eob_bits ? text_huff[256] >> 4 : 0;

		enqueue24(strm, eob_code + ((!more) << eob_bits), 3 + eob_bits + (7 & -(3 + eob_bits + strm->qbits)));
	} else {
		int eob_shift = (strm->state == SLZ_ST_EOB) ? 0 : 7;

		/* explanation: if there is no EOB yet, we have to send one.
		 * It's 0 encoded over 7 bits. Then we have to copy !more into BFINAL
		 * (one bit), and 00 in btype (two bits). Finally we pad to the next
		 * byte. So we add 0 or 7 bits for EOB, followed by 3 then by 0 to 7
		 * bits for alignment. That's 3 to 17 bits.
		 */
		enqueue24(strm, (!more) << eob_shift, 3 + eob_shift + (7 & -(3 + eob_shift + strm->qbits))); // EOB + BFINAL + BTYPE
	}
	strm->state = more ? SLZ_ST_EOB : SLZ_ST_DONE;

#if !SLZ_DIRECT_ENQUEUE24
	/* the queue is byte-aligned now, but the conditional 64-bit enqueue24()
	 * may still hold up to 4 bytes of it that must be written first.
	 */
	flush_bits(strm);
#endif
	copy_16b(strm, len);
	copy_16b(strm, ~len);
	memcpy(strm->outbuf, buf, len);
	strm->outbuf += len;
}

/* out-of-line versions of _copy_lit_small() for each tree. They must
 * not be inlined in the encoder, which is sensitive to register pressure.
 */
static __attribute__((noinline))
void copy_lit_small_generic(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more)
{
	_copy_lit_small(strm, buf, len, more, SLZ_CT_GENERIC, 0);
}

static __attribute__((noinline))
void copy_lit_small_generic_auto(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more)
{
	_copy_lit_small(strm, buf, len, more, SLZ_CT_GENERIC, 1);
}

static __attribute__((noinline))
void copy_lit_small_text(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more)
{
	_copy_lit_small(strm, buf, len, more, SLZ_CT_TEXT, 0);
}

/* calls the version of _copy_lit_small() for <ctype> */
static inline __attribute__((always_inline))
void copy_lit_small(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more, int ctype, int track_save)
{
	if (ctype == SLZ_CT_TEXT)
		copy_lit_small_text(strm, buf, len, more);
	else if (track_save)
		copy_lit_small_generic_auto(strm, buf, len, more);
	else
		copy_lit_small_generic(strm, buf, len, more);
}

/* copies <len> litterals from <buf>. <more> indicates that there are data past
 * buf + <len>. <len> must not be null. Use copy_lit() instead. It's only used
 * with the fixed tree, the text tree's literals leave through copy_lit_small()
 * since they never accumulate past 0xffc0 bytes.
 */
static inline __attribute__((always_inline))
void _copy_lit(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more, int track_save)
{
	uint32_t len2;

	if (len <= 65535)
		return copy_lit_small(strm, buf, len, more, SLZ_CT_GENERIC, track_save);

	if (track_save)
		strm->tree_save = 0;

	if (strm->state != SLZ_ST_EOB)
		send_eob(strm, SLZ_CT_GENERIC);

	len2 = 65535;
	len -= len2;

	do {
		/* wire BFINAL (!more), BTYPE (00) and round to the next byte boundary */
		enqueue24(strm, !(more || len), 3 + ((5 - strm->qbits) & 7));
#if !SLZ_DIRECT_ENQUEUE24
		flush_bits(strm); // see copy_lit_small()
#endif
		copy_32b(strm, (~len2 << 16) + len2);
		memcpy(strm->outbuf, buf, len2);
		buf += len2;
		strm->outbuf += len2;
		len2 = len;
		if (__builtin_expect(len2 > 65535, 0))
			len2 = 65535;

		len -= len2;
	} while (__builtin_expect(len2, 0));

	strm->state = more ? SLZ_ST_EOB : SLZ_ST_DONE;
}

/* out-of-line versions of _copy_lit() with and without <track_save> */
static __attribute__((noinline,unused))
void copy_lit_generic(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more)
{
	_copy_lit(strm, buf, len, more, 0);
}

static __attribute__((noinline))
void copy_lit_generic_auto(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more)
{
	_copy_lit(strm, buf, len, more, 1);
}

/* calls the version of _copy_lit() for <track_save> */
static inline __attribute__((always_inline))
void copy_lit(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more, int track_save)
{
	if (track_save)
		copy_lit_generic_auto(strm, buf, len, more);
	else
		copy_lit_generic(strm, buf, len, more);
}

/* copies <len> litterals from <buf>. <more> indicates that there are data past
 * buf + <len>. <len> must not be null. Use copy_lit_huff() instead.
 */
static inline __attribute__((always_inline))
void _copy_lit_huff(struct slz_stream *__restrict strm, const unsigned char *buf, uint32_t len, int more, int ctype, int track_save)
{
	uint32_t pos;

	/* This ugly construct limits the mount of tests and optimizes for the
	 * most common case (more > 0).
	 */
	if (strm->state == SLZ_ST_EOB) {
	eob:
		strm->state = more ? SLZ_ST_FIXED : SLZ_ST_LAST;
		open_huff_block(strm, !more, ctype);
	}
	else if (!more) {
		send_eob(strm, ctype);
		goto eob;
	}

	pos = 0;
	if (track_save && ctype == SLZ_CT_GENERIC) {
		/* what the text tree would have saved on these literals, from
		 * lit_tsave[], next to their fixed codes from fixed_huff[].
		 * A 64-bit table holding both, summed at once, was 1.9% slower
		 * on a Cortex-A720 and within 1% elsewhere.
		 */
		int32_t sum = 0;

		do {
			uint32_t c = buf[pos++];
			uint32_t code = fixed_huff[c];

			sum += lit_tsave[c];
			enqueue24(strm, code >> 4, code & 15);
		} while (pos < len);
		auto_account(strm, sum, ctype);
		return;
	}

	do {
		send_huff(strm, buf[pos++], ctype);
	} while (pos < len);
}

/* out-of-line versions of _copy_lit_huff() for each tree */
static __attribute__((noinline))
void copy_lit_huff_generic(struct slz_stream *__restrict strm, const unsigned char *buf, uint32_t len, int more)
{
	_copy_lit_huff(strm, buf, len, more, SLZ_CT_GENERIC, 0);
}

static __attribute__((noinline))
void copy_lit_huff_generic_auto(struct slz_stream *__restrict strm, const unsigned char *buf, uint32_t len, int more)
{
	_copy_lit_huff(strm, buf, len, more, SLZ_CT_GENERIC, 1);
}

static __attribute__((noinline))
void copy_lit_huff_text(struct slz_stream *__restrict strm, const unsigned char *buf, uint32_t len, int more)
{
	_copy_lit_huff(strm, buf, len, more, SLZ_CT_TEXT, 0);
}

/* calls the version of _copy_lit_huff() for <ctype> */
static inline __attribute__((always_inline))
void copy_lit_huff(struct slz_stream *__restrict strm, const unsigned char *buf, uint32_t len, int more, int ctype, int track_save)
{
	if (ctype == SLZ_CT_TEXT)
		copy_lit_huff_text(strm, buf, len, more);
	else if (track_save)
		copy_lit_huff_generic_auto(strm, buf, len, more);
	else
		copy_lit_huff_generic(strm, buf, len, more);
}

/* Marks all <count> bytes worth of entries in <refs> as unusable, so that any
 * entry not written since is rejected by the (pos - last - 1 >= 32768) test in
 * slz_rfc1951_encode(). <count> is in bytes and <refs> must be at least that
 * large.
 *
 * The byte value is not arbitrary. It has to leave a <pos> field that reads as
 * "far in the past" for every possible <pos>, on 32-bit as well, where that
 * subtraction is done on 32 bits. 0xFF wouldn't work. 0xFE gives 0xFEFEFEFE,
 * hence pos + 0x01010101, which is above 32768 and does not wrap for any
 * realistic input length. Note that the use of memset() here is intentional
 * as it was measured to be faster on modern libcs than an unrolled loop.
 */
static void reset_refs(union ref *refs, long count)
{
	memset(refs, 0xFE, count);
}

/* Inserts position <p> of input buffer <in> into the reference table <refs>.
 * Reads the 4 bytes at in[p], so the caller must guarantee that in[p + 3] is
 * within the input buffer.
 */
static inline void insert_ref(union ref *refs, const unsigned char *in, unsigned long p)
{
#ifdef UNALIGNED_LE_OK
	uint32_t w = *(uint32_t *)&in[p];
#else
	uint32_t w = ((uint32_t)in[p]) | ((uint32_t)in[p + 1] << 8) |
	             ((uint32_t)in[p + 2] << 16) | ((uint32_t)in[p + 3] << 24);
#endif
	uint32_t h = slz_hash(w);

	if (sizeof(long) >= 8)
		refs[h].by64 = ((uint64_t)p) + ((uint64_t)w << 32);
	else {
		refs[h].by32.pos = p;
		refs[h].by32.word = w;
	}
}

/* Number of bits wasted by the 9-bit literals above which it becomes
 * preferable to send the pending literals as a stored block. It corresponds to
 * the cost of leaving the fixed huffman encoding and coming back to it: EOB
 * (7 bits) + block type (3 bits) + alignment (up to 7 bits) + LEN and NLEN
 * (32 bits) + block type of the next block (3 bits), that is 52 bits. Two
 * cheaper variants are needed for the last literals of a block: nothing
 * follows the stored block while the huffman encoding still has to send an EOB
 * (10 bits less), and if the stream is still in EOB state, no EOB has to be
 * sent and the block type is needed in both cases (10 more bits less). Using a
 * larger value than these would leave the output larger than the same data
 * sent as stored blocks, in violation of the promise made above.
 */
#define SLZ_SWITCH_COST      52
#define SLZ_LAST_COST        42
#define SLZ_LAST_COST_EOB    32

/* The same for the text tree, whose EOB is longer, and whose blocks start with
 * the tree's definition, which makes leaving such a block for a stored one a
 * much bigger decision: EOB + block type + alignment + LEN and NLEN (42 bits)
 * + block type and header of the next block. On the other hand, a stored block
 * started in EOB state only costs 42 bits more than the literals it contains,
 * and opening a text block costs the block type and the header. The literals
 * are not compared by number of 9-bit ones but by their exact cost relative
 * to 8 bits, which is negative for text (see <lit_excess>), so that these
 * costs can be negative as well when it takes saving bits to pay for opening
 * a block.
 */
#define SLZ_TEXT_STORED_COST  42
#define SLZ_TEXT_OPEN_COST    (3 + TEXT_HDR_BITS)
#define SLZ_TEXT_SWITCH_COST  (TEXT_EOB_BITS + SLZ_TEXT_STORED_COST + SLZ_TEXT_OPEN_COST)

/* The encoder keeps a running balance <bal> of how many bits the output is
 * above the same data sent as stored blocks (5 bytes per 65535), offset by
 * SLZ_CREDIT so that it remains unsigned. Literals sent in fixed huffman mode
 * add one bit per byte >= 144, entering fixed huffman mode adds the
 * SLZ_SWITCH_COST needed to leave it later, and references subtract the bits
 * they save compared to the same bytes sent as literals. Pending literals are
 * sent as a stored block once the balance reaches SLZ_SWITCH_COST above the
 * credit, and they are then removed from it. The balance is not allowed to
 * drop below zero, i.e. to accumulate more than SLZ_CREDIT bits of savings:
 * these allow a few groups of literals to remain in fixed huffman instead of
 * paying for a return to it, which improves the compression ratio at level 3
 * (and at the former level 4; from 32 to 300 it only grows, but costs more CPU past 64, since
 * more literals are huffman-encoded). The balance is carried between calls in
 * <strm->debt>, and a stream starts with no savings at all.
 *
 * SLZ_MAX_DEBT is the number of bits above the credit past which a reference
 * met in fixed huffman mode must also pay for the return to it, as if it were
 * met in stored mode, because the pending literals will leave as a stored
 * block. Below it, such references are accepted for what they save by
 * themselves, which is better for the ratio. Thus the balance never exceeds
 * SLZ_CREDIT + SLZ_MAX_DEBT + SLZ_SWITCH_COST, which is what bounds the excess
 * of a stream over the same data sent as stored blocks to 252 bits. In
 * practice it reaches 154 bits on crafted data and 149 on silesia.tar, where
 * values 100 to 1000 trade a little ratio between levels 3 and the former 4.
 *
 * The same threshold also marks the stored mode inside a call: whenever the
 * encoder leaves fixed huffman mode (literal skip, full stored block), the
 * balance is raised to at least SLZ_CREDIT + SLZ_MAX_DEBT, so that the test
 * on references does not need to load the state for each candidate, and so
 * that the pending literals leave as a stored block. Entering fixed huffman
 * mode restarts from the balance saved in <strm->debt>, which drops the mark.
 * A call starting in stored mode is not marked, as this would force its first
 * literals into a stored block. Its first reference is then accepted for what
 * it saves by itself, and the switch to fixed huffman is charged when it is
 * performed by that reference, but not when the first literals perform it.
 *
 * At encoder levels 1 and 2 (compression levels 1 to 3, see the <level>
 * argument of _slz_rfc1951_encode()), literals are not counted one at a time,
 * which costs too much in the main loop. Instead, a group of literals sent in
 * fixed huffman mode before a reference is charged one bit per byte as if all
 * of them took 9 bits, once the decision to send it in fixed huffman mode is
 * taken. The balance is thus still an upper bound of the excess, and the group
 * itself, whose decision did not include it, is shorter than 64 bytes there
 * (longer ones are skipped and leave as a stored block), so it adds less than
 * 64 bits to the bound, which is thus 315 bits, published in bytes as
 * SLZ_MAX_DEBT_BYTES in slz.h. On real data, the reference that follows almost
 * always saves more than the charge, so this rarely changes a decision. This
 * relies on the literal skip: without it (SLZ_LITERAL_SKIP=0), a group may be
 * up to 65472 bytes long and would add as many bits to the bound, so all
 * levels count literals one at a time then.
 */
#define SLZ_MAX_DEBT        200
#define SLZ_CREDIT           64

/* fails to build if SLZ_MAX_DEBT_BYTES doesn't cover the bound above */
typedef char slz_max_debt_bytes_check[(SLZ_MAX_DEBT_BYTES * 8 >= SLZ_MAX_DEBT + SLZ_SWITCH_COST + 63) ? 1 : -1];

/* With the text tree, opening a block charges the whole round trip to the
 * debt (SLZ_TEXT_SWITCH_COST: the header, and the EOB and stored block header
 * needed to leave it). The header is part of the encoding, not of the
 * overhead: a block is only opened if the bits already known to be saved, by
 * the pending literals that will join it and by the reference that opens it,
 * repay it enough for the debt to remain below SLZ_TEXT_MAX_DEBT, which is
 * the same as SLZ_MAX_DEBT. Similarly, the pending literals and the reference
 * that follows them are only sent in an open block if the debt remains below
 * it, or if together they save bits, so that the debt never exceeds it once
 * they are sent. The literals sent at the end of a call follow the same rule.
 * Thus, as with the fixed tree, the excess over the same data sent as stored
 * blocks is bounded to SLZ_MAX_DEBT bits, whatever the tree's header.
 *
 * The debt is offset by SLZ_TEXT_CREDIT, which allows it to keep up to that
 * many bits of savings, so that a block closed for incompressible data can be
 * reopened with what the previous ones saved instead of waiting for a single
 * reference to repay the whole round trip, which kept mixed contents such as
 * silesia.tar in stored blocks. Since the output of each call must also stay
 * within SLZ_MAX_OVERHEAD(), only the savings of the current call may be used,
 * and those carried from previous calls are dropped when a call starts (see
 * _slz_rfc1951_encode()). Past 2000 bits, little is gained. This needs a
 * larger counter, <text_debt>, which is only used with the text tree so that
 * the code for the fixed one doesn't have to deal with 16-bit values.
 */
#define SLZ_TEXT_CREDIT     4096
#define SLZ_TEXT_MAX_DEBT   (SLZ_MAX_DEBT + SLZ_TEXT_CREDIT)

/* Each tree's part only maintains its own counter, <debt> or <text_debt>, so
 * the excess must be carried from one to the other when the tree changes, or
 * a call or a stream alternating between them could reach the sum of their
 * bounds. Both counters remain within the larger bound, since none of the
 * parts adds to its counter past its own threshold. Only the fixed tree takes
 * the savings, as the text tree may only use those of the current call.
 */
static inline void debt_to_text(struct slz_stream *__restrict strm)
{
	strm->text_debt = SLZ_TEXT_CREDIT + (strm->debt > SLZ_CREDIT ? strm->debt - SLZ_CREDIT : 0);
}

static inline void debt_to_fixed(struct slz_stream *__restrict strm)
{
	strm->debt = (strm->text_debt > SLZ_TEXT_CREDIT - SLZ_CREDIT) ? strm->text_debt - (SLZ_TEXT_CREDIT - SLZ_CREDIT) : 0;
}

/* Makes the fixed tree the current one for the encoders that only know it,
 * closing a block opened with the text tree. <cur_tree> may be the text tree
 * when they are entered: the init functions start with it from level 2, and
 * the level may be changed between calls (e.g. lowered under load).
 */
static inline void leave_text_tree(struct slz_stream *__restrict strm)
{
	if (strm->cur_tree != SLZ_CT_GENERIC) {
		if (strm->state == SLZ_ST_FIXED) {
			send_eob(strm, strm->cur_tree);
			strm->state = SLZ_ST_EOB;
		}
		strm->cur_tree = SLZ_CT_GENERIC;
		debt_to_fixed(strm);
	}
}

/* fails to build if send_text_hdr() doesn't charge SLZ_TEXT_SWITCH_COST */
typedef char slz_text_switch_cost_check[(SLZ_TEXT_SWITCH_COST == TEXT_EOB_BITS + 42 + 3 + TEXT_HDR_BITS) ? 1 : -1];

/* fails to build if SLZ_MAX_DEBT_BYTES doesn't cover the text bound above */
typedef char slz_max_text_debt_bytes_check[(SLZ_MAX_DEBT_BYTES * 8 >= SLZ_TEXT_MAX_DEBT - SLZ_TEXT_CREDIT) ? 1 : -1];

/* With the text tree, while no block is open, the references that cannot
 * repay the opening yet are not turned into literals but recorded, up to
 * SLZ_TEXT_VREFS of them, and their exact cost relative to 8 bits per byte is
 * added to <lit_excess> with the pending literals, which also cover their
 * bytes. If the pending bytes are sent as a stored block, the references are
 * simply dropped. If a block is opened for them, they're replayed by
 * text_replay() between their literals. Thus the decision to open a block
 * still only depends on bits known to be saved, but these include those of
 * the first references, which otherwise were lost until the literals alone
 * could repay the opening.
 */
#define SLZ_TEXT_VREFS 32

struct text_vref {
	uint32_t code;   /* length code, as returned by len_code() */
	uint32_t dist;   /* distance code, as in text_dist_table */
	uint16_t lits;   /* literals before this reference */
	uint16_t mlen;   /* match length */
};

/* sends the <len> pending bytes at <buf> in a text block, as literals except
 * for the <n> references recorded in <vref>, opening the block if needed with
 * BFINAL set if <more> is null.
 */
static __attribute__((noinline))
void text_replay(struct slz_stream *__restrict strm, const unsigned char *buf, uint32_t len,
                 const struct text_vref *vref, uint32_t n, int more)
{
	const unsigned char *end = buf + len;
	uint32_t i, l;

	if (strm->state == SLZ_ST_EOB) {
		strm->state = more ? SLZ_ST_FIXED : SLZ_ST_LAST;
		open_huff_block(strm, !more, SLZ_CT_TEXT);
	}

	for (i = 0; i < n; i++) {
		for (l = vref[i].lits; l; l--)
			send_huff(strm, *buf++, SLZ_CT_TEXT);
		enqueue24(strm, vref[i].code & 0xFFFF, vref[i].code >> 16);
		enqueue24(strm, vref[i].dist >> 5, vref[i].dist & 0x1f);
		buf += vref[i].mlen;
	}

	while (buf < end)
		send_huff(strm, *buf++, SLZ_CT_TEXT);
}

/* returns non-zero if the pending literals of text stream <strm>, which cost
 * <excess> bits more than 8 bits each, must be sent as a stored block, either
 * because it's cheaper, or because keeping them in the open huffman block
 * would bring the debt to SLZ_TEXT_MAX_DEBT. They are compared to the lowest
 * cost first, which text literals never reach, so that the common case is a
 * single test against a constant: making the test depend on the state let gcc
 * test the match length first in the encoder, which is a mispredicted branch.
 */
static inline int text_lit_stored(const struct slz_stream *strm, int32_t excess)
{
	return __builtin_expect(excess >= SLZ_TEXT_STORED_COST, 0) &&
	       (strm->state == SLZ_ST_EOB || excess >= SLZ_TEXT_SWITCH_COST ||
	        (int32_t)strm->text_debt + excess >= SLZ_TEXT_MAX_DEBT);
}

/* returns how many of the up to <bmax> bytes before <in>[<pos>] are equal to
 * those before <lastp>, comparing at most <len> of them, which must be a
 * constant. See the backward match in _slz_rfc1951_encode().
 */
static inline __attribute__((always_inline))
long backward_match(const unsigned char *in, unsigned long pos, const unsigned char *lastp, long bmax, int len)
{
	long back = 0;

#if defined(UNALIGNED_LE_OK)
	if (len == 2) { // 43.32%, best speed vs savings
		uint16_t x = *(uint16_t *)&in[pos - 2] ^ *(uint16_t *)(lastp - 2);
		back = x & 0xff00 ? 0 : x ? 1 : 2;
		if (back > bmax)
			back = bmax;
	} else if (len == 3 || len == 4) { // 32 bits: 43.31% or 43.30%
		uint32_t x = *(uint32_t *)&in[pos - 4] ^ *(uint32_t *)(lastp - 4);
		back = x & 0xffff0000u ?
			x & 0xff000000u ? 0 : 1 :
			x & 0xffffff00u ? 2 :
			x ? 3 : len; // 3 or 4, test eliminated at 3
		if (back > bmax)
			back = bmax;
	} else if (len == 8) { // 64 bits: 43.30%
		uint64_t x = *(uint64_t *)&in[pos - 8] ^ *(uint64_t *)(lastp - 8);
		back = x ? (__builtin_clzll(x) >> 3) : 8;
		if (back > bmax)
			back = bmax;
	} else
#endif
	if (len == 1) { // single-byte match: 43.39%
		if (in[pos - 1] == lastp[-1])
			back++;
		if (back > bmax)
			back = bmax;
	}
	else { /* unaligned not supported or match != 1/2/3/4/8 */
		while (back < bmax && in[pos - back - 1] == lastp[-back - 1])
			back++;
	}

	return back;
}

/* Compresses <ilen> bytes from <in> into <out> according to RFC1951. The
 * output result may be up to 5 bytes larger than the input for each 65535
 * nput bytes, to which 2 extra bytes may be added to send the last chunk due
 * to BFINAL+EOB encoding (10 bits) when <more> is not set. This is a property
 * of the whole stream, not of each call: since up to 31 bits are retained in
 * the queue from one call to the next, a single call may emit up to 5 bytes
 * more than its own share, which the following ones will not emit. In
 * addition, the fixed huffman encoding may be behind the same data sent as
 * stored blocks by up to SLZ_MAX_DEBT_BYTES, which may all be reached within a
 * single call, so each call must also have that much room. SLZ_MAX_OVERHEAD()
 * in slz.h sums all of this, including the text tree's header and debt (see
 * SLZ_TEXT_MAX_DEBT). The caller is responsible
 * for ensuring there is enough room in the output buffer for this. The amount
 * of output bytes is returned, and no CRC is computed.
 *
 * Note: this function uses a lot of registers due to local variables that
 * hold pre-computed values that need to be kept very long. Be extremely
 * careful when changing anything there, and test again on multiple compiler
 * versions. For example, when building with avx512f (e.g. -march=native on
 * Skylake-X and Zen-4+), gcc 13 and 14 tend to move some variables to %xmm0
 * and to read it back using vmovq multiple times, affecting performance, which
 * can be recovered using -mno-avx512f (~1-2%). On gcc-15, the performance is
 * better and that option degrades it by 2% again. gcc-16 is even slightly
 * better (+0.5%). As a general rule, nothing vectorizes well here, and the
 * unaligned, short memcpy() calls must not be translated to AVX512 code.
 *
 * <level> is the encoder's level, not the compression level, see
 * _slz_rfc1951_encode_lev1(), and <bmatch> the fixed tree's backward match
 * length. <auto_tree> is zero to only use the fixed tree, or non-zero to
 * choose between the fixed and the text trees on the fly (see SLZ_AUTO_IN).
 * All three must be constants. Each tree has its own part below.
 */
static inline __attribute__((always_inline))
long _slz_rfc1951_encode(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more, int level, int bmatch, int auto_tree)
{
	long rem = ilen;
	unsigned long pos = 0;
	unsigned long last;
	const unsigned char *lastp;
	uint32_t word = 0;
	long mlen;
	uint32_t h;
	uint64_t ent;

	uint32_t plit = 0;
	uint32_t dist, code;
	union ref refs[1 << SLZ_HASH_BITS];

	if (__builtin_expect(!strm->level, 0)) {
		/* force to send as literals (eg to preserve CPU) */
		strm->outbuf = out;
		if (ilen)
			copy_lit(strm, in, ilen, more, auto_tree);
		goto leave;
	}

	reset_refs(refs, sizeof(refs));
	strm->outbuf = out;

	if (auto_tree) {
		/* only the savings of this call may pay for its text blocks,
		 * see SLZ_TEXT_CREDIT.
		 */
		if (strm->text_debt < SLZ_TEXT_CREDIT)
			strm->text_debt = SLZ_TEXT_CREDIT;

		if (strm->tree_switch) {
			/* requested by the last literals of the previous call */
			if (strm->state == SLZ_ST_FIXED) {
				send_eob(strm, strm->cur_tree);
				strm->state = SLZ_ST_EOB;
			}
			if (strm->state == SLZ_ST_EOB) {
				strm->cur_tree = !strm->cur_tree;
				if (strm->cur_tree == SLZ_CT_TEXT)
					debt_to_text(strm);
				else
					debt_to_fixed(strm);
			}
			strm->tree_switch = 0;
			strm->tree_save = 0;
		}
		if (strm->cur_tree == SLZ_CT_TEXT)
			goto text_start;
	}

	/* The fixed tree's part, with its own loop. */
	{
		uint32_t bal; /* see SLZ_MAX_DEBT */

 fixed_start:
		rem = ilen - pos;
		plit = 0;
		bal = strm->debt;

#ifndef UNALIGNED_FASTER
 reload_word:
		if (rem >= 4)  // <word> is only used inside the loop below, hence the test for >= 4
			word = ((uint32_t)(unsigned char)in[pos] << 8) + ((uint32_t)(unsigned char)in[pos + 1] << 16) + ((uint32_t)(unsigned char)in[pos + 2] << 24);
#endif
		while (rem >= 4) {
#ifndef UNALIGNED_FASTER
			word = ((uint32_t)(unsigned char)in[pos + 3] << 24) + (word >> 8);
#else
			word = *(uint32_t *)&in[pos];
#endif
			h = slz_hash(word);
			asm volatile ("" ::); // prevent gcc from trying to be smart with the prefetch

			if (sizeof(long) >= 8) {
				ent = refs[h].by64;
				last = (uint32_t)ent;
				ent >>= 32;
				refs[h].by64 = ((uint64_t)pos) + ((uint64_t)word << 32);
			} else {
				ent  = refs[h].by32.word;
				last = refs[h].by32.pos;
				refs[h].by32.pos = pos;
				refs[h].by32.word = word;
			}

			if ((uint32_t)ent != word) {
			send_as_lit:
				rem--;
				plit++;
				if (level >= 3 || !SLZ_LITERAL_SKIP) // see SLZ_MAX_DEBT
					bal += ((unsigned char)word >= 144);
				pos++;

				/* Incompressible data: once enough literals have accumulated
				 * without a single match, stop looking for a while and just
				 * add what follows to the pending literals, doubling the
				 * amount skipped each time so that a long incompressible block
				 * costs less and less to walk over. A match resets it. The
				 * skipped bytes are not emitted here, as closing a stored
				 * block at each step would cost 5 bytes every few kB and
				 * break the promise of 5 bytes per 65535. Since they were not
				 * inspected, <bal> is raised so that they may only leave as
				 * a stored block, and so that a reference is only accepted if
				 * it pays for the return to FIXED (see SLZ_MAX_DEBT). The EOB
				 * is sent by copy_lit() along with them. <plit> may thus
				 * exceed 65535, the pending literals are always sent with
				 * copy_lit() which splits them into full stored blocks.
				 */
#if SLZ_LITERAL_SKIP
				if (level <= 2 && !(plit & 63)) {
					/* The step is derived from the literals pending since
					 * the last match: 0, 64, 192, 448, ... up to 8128, i.e.
					 * the capped exponential ramp, which keeps <plit>
					 * aligned on 64. Keeping it in a separate variable reset
					 * at each match cost 2% at level 1 even on data that
					 * never skips, through register pressure in the match
					 * path.
					 */
					long skip = plit - 64 > 8128 ? 8128 : plit - 64;

					skip = rem >= skip ? skip : rem;
					/* Level 2 still looks up and indexes the last word of
					 * each whole 64-byte chunk it skips, and stops skipping
					 * on the first one already present within the window,
					 * so that the main loop resumes at the start of that
					 * chunk. The skipped words remain indexed for the data
					 * that follows. The last word rather than the first one
					 * gives shorter distances to what follows the skip and a
					 * smaller output. Only the remainder of a skip limited by
					 * the end of the input is skipped unchecked. Since the
					 * skip steps are 64 bytes apart, <plit> remains aligned
					 * on them.
					 */
					if (level == 2 && skip >= 64) {
						long chunks = skip >> 6;

						skip &= 63;
						do {
							uint32_t w = read_le32(in + pos + 60);
							uint32_t hw = slz_hash(w);

							if (sizeof(long) >= 8) {
								uint64_t old = refs[hw].by64;

								if ((uint32_t)(old >> 32) == w && (unsigned long)(pos + 59 - (uint32_t)old) < 32768) {
									skip = 0;
									break;
								}
								refs[hw].by64 = ((uint64_t)(pos + 60)) + ((uint64_t)w << 32);
							} else {
								if (refs[hw].by32.word == w && (unsigned long)(pos + 59 - refs[hw].by32.pos) < 32768) {
									skip = 0;
									break;
								}
								refs[hw].by32.pos = pos + 60;
								refs[hw].by32.word = w;
							}
							pos += 64;
							rem -= 64;
							plit += 64;
						} while (--chunks);
					}
					pos += skip;
					rem -= skip;
					plit += skip;
					/* skipped bytes may only leave as a stored block */
					bal += SLZ_MAX_DEBT + SLZ_CREDIT;
# ifndef UNALIGNED_FASTER
					/* we'll need to update the current word since we skipped some bytes */
					goto reload_word;
# else
					continue;
# endif
				}
				else if (__builtin_expect(level == 3 && !(plit & 2047), 0)) {
					/* derived from <plit> as well: 0, 4096, 16384, then
					 * 28672 (the former ramp gave 0, 4096, 12288, 28672).
					 * <plit> is not always a multiple of 2048 here (see
					 * below), hence the rounding.
					 */
					long skip = 2 * (long)(plit & ~2047U) - 4096;

					skip = skip > 28672 ? 28672 : skip;
					skip = rem >= skip ? skip : rem;

					/* Note: by checking intervals smaller than the mask above, a hit resumes
					 * at the start of the 64-byte chunk containing it, so <plit> is then no
					 * longer a multiple of 2048 and the next check comes after 64 to 1984
					 * literals if no match is found in between. This shortens the scan after
					 * a false hit. Rewinding to the 2048 boundary instead showed almost no
					 * size gains but was 0.3-0.8% slower. Checking every 64 bytes instead
					 * of 256 makes level 4 0.05% smaller on silesia and 0.64% on a tar of
					 * /usr/share/doc for 0.4-1.2% of speed.
					 */
					if (skip >= 64) {
						long chunks = skip >> 6;

						skip &= 63;
						do {
							uint32_t w = read_le32(in + pos + 60);
							uint32_t hw = slz_hash(w);

							if (sizeof(long) >= 8) {
								uint64_t old = refs[hw].by64;

								if ((uint32_t)(old >> 32) == w && (unsigned long)(pos + 59 - (uint32_t)old) < 32768) {
									skip = 0;
									break;
								}
								refs[hw].by64 = ((uint64_t)(pos + 60)) + ((uint64_t)w << 32);
							} else {
								if (refs[hw].by32.word == w && (unsigned long)(pos + 59 - refs[hw].by32.pos) < 32768) {
									skip = 0;
									break;
								}
								refs[hw].by32.pos = pos + 60;
								refs[hw].by32.word = w;
							}
							pos += 64;
							rem -= 64;
							plit += 64;
						} while (--chunks);
					}
					pos += skip;
					rem -= skip;
					plit += skip;
					/* skipped bytes may only leave as a stored block. Also done
					 * on the first test, where <skip> is 0, like the stored
					 * block sent there before: it keeps the same matches.
					 */
					bal += SLZ_MAX_DEBT + SLZ_CREDIT;
# ifndef UNALIGNED_FASTER
					/* we'll need to update the current word since we skipped some bytes */
					goto reload_word;
# else
					continue;
# endif
				}
#else
				/* no literal skip at build time: the stored blocks are as
				 * large as possible.
				 */
				if (__builtin_expect(plit == 0xffc0, 0)) {
					copy_lit_small(strm, in + pos - plit, plit, 1, SLZ_CT_GENERIC, auto_tree);
					plit = 0;
					bal = strm->debt + SLZ_MAX_DEBT + SLZ_CREDIT;
				}
#endif
				continue;
			}

			/* We reject pos = last and pos > last+32768 */
			if ((unsigned long)(pos - last - 1) >= 32768)
				goto send_as_lit;

			/* faster to keep a copy of this with gcc 13-16 */
			lastp = in + last;

			/* Note: cannot encode a length larger than 258 bytes */
			mlen = memmatch(in + pos + 4, lastp + 4, (rem > 258 ? 258 : rem) - 4) + 4;

			/* found a matching entry */

			/* if the pending literals are going to be sent as a stored
			 * block, a short match is not worth splitting it.
			 */
			if (bal >= SLZ_SWITCH_COST + SLZ_CREDIT && mlen < 6)
				goto send_as_lit;

			/* compute the output code, its size and the length's size in
			 * bits to know if the reference is cheaper than literals.
			 */
			code = len_code(mlen, SLZ_CT_GENERIC);

			/* direct mapping of dist->huffman code */
			dist = fh_dist_table[pos - last - 1];

			/* If encoding the dist+length is more expensive than sending
			 * the equivalent as bytes, lets keep the literals. This is
			 * important for the compression ratio and also for standing by
			 * our promise that the output is no longer than input + 5 bytes
			 * every 65535. The explanation is that a valid stream starts in
			 * EOB and ends in EOB, which is the state where we can grow by
			 * up to 5 bytes (1 byte for BT, 2 for LEN, 2 for NLEN, then
			 * literal data). Sending compressed Huffman data (reference or
			 * fixed encoding) may only be accepted if it is guaranteed that
			 * it will not represent more bytes in the worst case. Switching
			 * from EOB to FIXED requires 3 bits of BT. Then either fixed
			 * data (8 or 9 bits) or references (15-33 bits). Switching back
			 * to EOB requires EOB (7 bits), and in order to get back to the
			 * situation where bytes can be added with no overhead, the BT,
			 * align, LEN and NLEN have to be sent as well:
			 *
			 * Before switching:
			 *          [BT] [ALIGN] [LEN] [NLEN] [PLIT]
			 *   bits:    3     7     16     16   8*plit
			 *
			 * In case of sending mlen bytes as literals:
			 *          [BT] [ALIGN] [LEN] [NLEN] [PLIT] [MLEN]
			 *   bits:    3     7     16     16   8*plit 8*mlen
			 *
			 * In case of sending mlen bytes as literals, we add:
			 *       [MLEN]
			 * bits: 8*mlen
			 *
			 * In case of sending reference, we add in the worst case:
			 *       [BT] [CODE] [DIST] [EOB] [BT] [ALIGN] [LEN] [NLEN]
			 * bits:  3    clen   dlen    7    3      7      16    16
			 *
			 * Thus for literals we add 8*mlen bits, and for reference we
			 * add clen+dlen+52 bits. If the reference encoding + 52 bits
			 * is shorter. Of course there are plenty of opportunities to
			 * be much shorter once we switch to FIXED, and a stricter
			 * tracking could allow to send references more often. But here
			 * we at least guarantee that if data fit as literals, they also
			 * fit using a temporary switch to FIXED.
			 *
			 * Regarding encoding size, clen is 7 for mlen 3..10, to 12 for
			 * mlen 131..257. dlen is 8 for distances 1..4, to 21 for
			 * distances 16385..32768. Thus mlen <= 130 produces clen+dlen
			 * <= 32 bits. This means that for mlen 4 or above, the encoded
			 * reference is always smaller than the data it references. This
			 * is what guarantees that once switched to FIXED we can stay
			 * in it for as long as needed.
			 */
			/* Note: <bal> is at least SLZ_MAX_DEBT + SLZ_CREDIT in stored
			 * mode, except at the beginning of a call (see SLZ_MAX_DEBT).
			 */
			if (bal >= SLZ_MAX_DEBT + SLZ_CREDIT &&
			    (dist & 0x1f) + (code >> 16) + SLZ_SWITCH_COST > 8 * mlen)
				goto send_as_lit;

			/* Compare queued literals in case the previous ones were not
			 * found due to hash collisions but still match. We don't go
			 * further than 8 bytes so that we can find them in a single
			 * 64-bit comparison. On aligned-only machines we read one byte
			 * at a time, as it is expected to be cheaper than composing an
			 * unaligned int and manually doing a ctzll() on it. Tests have
			 * shown that there's little to gain past 8 bytes, and anyway
			 * the total match length will be bounded by 258. BTW we only
			 * consider cases where last >= 8 because this guarantees that
			 * we can access both the searched sequence and the match found
			 * on a wole word at once. It may miss some rare matches on the
			 * edge of the buffer that we don't care about.
			 *
			 * It's worth noting that we *do not* fixup <bal> if a match
			 * is found, as this would be too complicated and counter-
			 * productive. This means that literals that were finally
			 * encoded might still count towards the budget limit, but this
			 * is not dramatic and keeps us on the safe side.
			 *
			 * The result of the search is to only touch <back> that will be
			 * used all along in all operations. Multiple attempts have shown
			 * that it's both easier and faster this way than changing then
			 * rolling back offsets when we finally give up and send_as_lit.
			 * It is disabled when <bmatch> is zero.
			 */
			if (bmatch &&
			    __builtin_expect(plit != 0, 1) &&
			    (last >= MAX_C(sizeof(long), bmatch))) {
				long bmax = MIN(plit, 8); // keep it at 8, always faster
				long back;

				if (bmax > 258 - mlen)
					bmax = 258 - mlen;

				back = backward_match(in, pos, lastp, bmax, bmatch);

				if (back) {
					/* OK now we're certain to use the match, we must rewind the
					 * literals that are part of the match.
					 */
					pos  -= back;
					plit -= back;
					rem  += back;
					mlen += back;
					/* <code> was computed from the un-extended
					 * length above and must follow, or we would
					 * consume <back> more bytes than the length
					 * code tells the decoder to copy. <dist> does
					 * not move. The cost test above keeps using
					 * the un-extended length, which is safe: the
					 * extension only makes the match cheaper per
					 * byte, never more expensive.
					 */
					code = len_code(mlen, SLZ_CT_GENERIC);
				}
			}

			/* first, copy pending literals */
			if (plit) {
				/* Huffman encoding requires 9 bits for octets 144..255, so this
				 * is a waste of space for binary data. Switching between Huffman
				 * and no-comp then huffman consumes 52 bits (7 for EOB + 3 for
				 * block type + 7 for alignment + 32 for LEN+NLEN + 3 for next
				 * block). The balance already counts these literals, so once
				 * it is SLZ_SWITCH_COST above the credit, the literals leave
				 * as a stored block and are removed from it by restoring the
				 * value it had after the last reference. Literals sent in a
				 * stored block do not cost anything extra.
				 */
				if (bal >= SLZ_SWITCH_COST + SLZ_CREDIT) {
					copy_lit(strm, in + pos - plit, plit, 1, auto_tree);
					bal = strm->debt;
				}
				else {
					if (level <= 2 && SLZ_LITERAL_SKIP)
						bal += plit; // worst case: all of them take 9 bits
					copy_lit_huff(strm, in + pos - plit, plit, 1, SLZ_CT_GENERIC, auto_tree);
				}

				plit = 0;
			}

			/* use mode 01 - fixed huffman */
			if (strm->state == SLZ_ST_EOB) {
				strm->state = SLZ_ST_FIXED;
				open_huff_block(strm, 0, SLZ_CT_GENERIC);
				/* restart from the saved balance (drops the stored mode mark)
				 * plus what leaving fixed huffman will cost
				 */
				bal = strm->debt + SLZ_SWITCH_COST;
			}

			/* copy the length first */
#if SLZ_DIRECT_ENQUEUE56
			/* the length code and the distance code that follows it total
			 * 31 bits at most, which one enqueue can take in a single
			 * shift-or-store instead of two
			 */
			enqueue56(strm, (uint64_t)(code & 0xFFFF) |
			                ((uint64_t)(dist >> 5) << (code >> 16)),
			          (code >> 16) + (dist & 0x1f));
#else
			enqueue24(strm, code & 0xFFFF, code >> 16);

			/* in fixed huffman mode, dist is fixed 5 bits */
			enqueue24(strm, dist >> 5, dist & 0x1f);
#endif

			/* from level 3, what the text tree would save on this
			 * reference, see SLZ_AUTO_IN.
			 */
			if (auto_tree && level >= 2) {
				int32_t save = strm->tree_save + len_tsave[mlen] + dist_tsave[(dist >> 5) & 31];

				save = save < 0 ? 0 : save;
				if (__builtin_expect(save > SLZ_AUTO_IN, 0)) {
					strm->tree_switch = 1;
					save = 0;
				}
				strm->tree_save = save;
			}

			/* The reference just used (code>>16)+(dist&0x1f) bits in place
			 * of the 8*mlen bits these bytes would have taken as literals,
			 * so it saves that much on the balance, which is saturated at
			 * zero (no more than SLZ_CREDIT bits of savings) and saved
			 * there for the next group of literals and the next calls. The
			 * update is unconditional because a test on a value that is
			 * often null but not always turns into a mispredicted branch
			 * on binary data.
			 */
			code = bal + (code >> 16) + (dist & 0x1f);
			bal = (code > 8 * (uint32_t)mlen) ? code - 8 * (uint32_t)mlen : 0;
			strm->debt = bal;

			/* switch to the other tree after this match if the literals
			 * sent before it requested it, see SLZ_AUTO_IN.
			 */
			if (auto_tree) {
				if (__builtin_expect(strm->tree_switch, 0)) {
					pos += mlen;
					goto switch_to_text;
				}
			}
			rem -= mlen;
			pos += mlen;

#if SLZ_INSERT_SKIPPED
			if (rem < 4)
				break;
			/* try to index the matched entry to improve the likelyhood
			 * that a similar sequence will be a hit next time. We only
			 * need 4 remaining bytes starting from the current one.
			 */
			insert_ref(refs, in, pos - mlen + 3);
			insert_ref(refs, in, pos - mlen + 2);
			insert_ref(refs, in, pos - mlen + 1);
#endif // SLZ_INSERT_SKIPPED

#ifndef UNALIGNED_FASTER
			/* same as before the loop, this is only used when continuing
			 * in the loop, so let's use the same condition (rem>=4).
			 */
			if (rem >= 4) {
#ifdef UNALIGNED_LE_OK
				word = *(uint32_t *)&in[pos - 1];
#else
				word = ((uint32_t)(unsigned char)in[pos] << 8) + ((uint32_t)(unsigned char)in[pos + 1] << 16) + ((uint32_t)(unsigned char)in[pos + 2] << 24);
#endif
			}
#endif
		}

		if (__builtin_expect(rem, 0)) {
			/* we're reading the 1..3 last bytes */
			plit += rem;
			do {
				bal += ((unsigned char)in[pos++] >= 144);
			} while (--rem);
		}

		/* Now copy remaining literals or mark the end. The cost of switching to
		 * a stored block depends on the current state and on the presence of
		 * data after these literals, see the SLZ_*_COST definitions above.
		 */
		if (plit) {
			uint32_t cost;

			if (more)
				cost = SLZ_SWITCH_COST;
			else
				cost = (strm->state == SLZ_ST_EOB) ? SLZ_LAST_COST_EOB : SLZ_LAST_COST;

			if (bal >= cost + SLZ_CREDIT)
				copy_lit(strm, in + pos - plit, plit, more, auto_tree);
			else {
				copy_lit_huff(strm, in + pos - plit, plit, more, SLZ_CT_GENERIC, auto_tree);
				strm->debt = bal;
			}

			plit = 0;
		}
		goto leave;
	}

	/* The text tree's part, with its own loop, used when it's chosen with
	 * the automatic tree. It is the same at all levels: no literal skip,
	 * debt charged per literal (<lit_excess>) and 2-byte backward match.
	 */
	if (auto_tree) {
		uint32_t lit_excess; /* see SLZ_TEXT_STORED_COST */
		int lit_stored;      /* pending literals go to a stored block */
		uint32_t nvref;      /* recorded references, see SLZ_TEXT_VREFS */
		uint32_t vplit;      /* <plit> after the last recorded reference */
		struct text_vref vref[SLZ_TEXT_VREFS];

 text_start:
		rem = ilen - pos;
		plit = 0;
		lit_excess = 0;
		lit_stored = 0;
		nvref = 0;
		vplit = 0;

#ifndef UNALIGNED_FASTER
		if (rem >= 4)  // <word> is only used inside the loop below, hence the test for >= 4
			word = ((uint32_t)(unsigned char)in[pos] << 8) + ((uint32_t)(unsigned char)in[pos + 1] << 16) + ((uint32_t)(unsigned char)in[pos + 2] << 24);
#endif
		while (rem >= 4) {
			int32_t cost;

#ifndef UNALIGNED_FASTER
			word = ((uint32_t)(unsigned char)in[pos + 3] << 24) + (word >> 8);
#else
			word = *(uint32_t *)&in[pos];
#endif
			h = slz_hash(word);
			asm volatile ("" ::); // prevent gcc from trying to be smart with the prefetch

			if (sizeof(long) >= 8) {
				ent = refs[h].by64;
				last = (uint32_t)ent;
				ent >>= 32;
				refs[h].by64 = ((uint64_t)pos) + ((uint64_t)word << 32);
			} else {
				ent  = refs[h].by32.word;
				last = refs[h].by32.pos;
				refs[h].by32.pos = pos;
				refs[h].by32.word = word;
			}

			if ((uint32_t)ent != word) {
			text_send_as_lit:
				rem--;
				plit++;
				/* for the text tree, <lit_excess> is the exact number of
				 * bits the pending literals cost over 8 bits each, as a
				 * signed value.
				 */
				lit_excess += (text_huff[(unsigned char)word] & 15) - 8;
				pos++;

				/* no literal skip with the text tree, where it would be too
				 * expensive to leave the huffman block for so few literals.
				 * The stored blocks are as large as possible since each split
				 * costs 5 bytes on top of the debt. When choosing the tree,
				 * the text tree checks every 64 literals instead, which costs
				 * the same test, and leaves for the fixed tree if they're
				 * binary data, see SLZ_AUTO_IN.
				 */
				if (__builtin_expect(auto_tree ? !(plit & 63) : plit == 0xffc0, 0)) {
					if (auto_tree) {
						if (plit != 0xffc0) {
							if ((int32_t)lit_excess >= (int32_t)plit) {
								pos -= plit;
								goto switch_to_fixed;
							}
							continue;
						}
					}
					copy_lit_small(strm, in + pos - plit, plit, 1, SLZ_CT_TEXT, auto_tree);
					plit = 0;
					/* the text tree's <lit_excess> may be negative */
					lit_excess = 0;
					nvref = vplit = 0;
				}
				continue;
			}

			/* We reject pos = last and pos > last+32768 */
			if ((unsigned long)(pos - last - 1) >= 32768)
				goto text_send_as_lit;

			/* faster to keep a copy of this with gcc 13-16 */
			lastp = in + last;

			/* Note: cannot encode a length larger than 258 bytes */
			mlen = memmatch(in + pos + 4, lastp + 4, (rem > 258 ? 258 : rem) - 4) + 4;

			/* found a matching entry */

			/* if the pending literals are going to be sent as a stored
			 * block, a short match is not worth splitting it.
			 */
			if (text_lit_stored(strm, lit_excess) && mlen < 6)
				goto text_send_as_lit;

			/* compute the output code, its size and the length's size in
			 * bits to know if the reference is cheaper than literals.
			 */
			code = len_code(mlen, SLZ_CT_TEXT);

			/* direct mapping of dist->huffman code. Computing the text
			 * tree's one from the fixed one instead was measured 3 to 5%
			 * slower than a second table.
			 */
			dist = text_dist_table[pos - last - 1];

			/* With the text tree, the decision is taken here for
			 * the pending literals and the reference together, and
			 * <lit_stored> keeps it for when the literals are sent,
			 * since extending the match backwards may change their
			 * cost. The literals that don't leave as a stored block
			 * join the reference's block, and if it has to be
			 * (re)opened, its round trip is charged. The reference
			 * is accepted if the debt remains below the limit (see
			 * SLZ_TEXT_MAX_DEBT), or if it doesn't open a block and
			 * saves bits together with the literals.
			 */
			cost = (int32_t)((dist & 0x1f) + (code >> 16) + lit_excess) - 8 * (int32_t)mlen;

			/* <lit_excess> is null when there are no literals */
			lit_stored = text_lit_stored(strm, lit_excess);
			if (__builtin_expect(strm->state != SLZ_ST_EOB && !lit_stored, 1)) {
				/* literals and reference in the open block */
				if (cost > 0 && (int32_t)strm->text_debt + cost >= SLZ_TEXT_MAX_DEBT)
					goto text_send_as_lit;
			}
			else {
				/* the reference (re)opens the block */
				if (lit_stored)
					cost -= (int32_t)lit_excess;
				if ((int32_t)strm->text_debt + cost + SLZ_TEXT_SWITCH_COST >= SLZ_TEXT_MAX_DEBT) {
					if (strm->state != SLZ_ST_EOB || lit_stored ||
					    nvref >= SLZ_TEXT_VREFS || plit + mlen >= 0xffc0 ||
					    plit - vplit > 0xffff)
						goto text_send_as_lit;

					/* record it, see SLZ_TEXT_VREFS */
					vref[nvref].code = code;
					vref[nvref].dist = dist;
					vref[nvref].lits = plit - vplit;
					vref[nvref].mlen = mlen;
					nvref++;
					lit_excess += (dist & 0x1f) + (code >> 16) - 8 * (uint32_t)mlen;
					plit += mlen;
					vplit = plit;
					goto text_skip_ref;
				}
			}

			/* Compare queued literals, see the fixed tree's loop. Only
			 * those after the last recorded reference may be used.
			 */
			if (__builtin_expect(plit != vplit, 1) &&
			    (last >= MAX_C(sizeof(long), 2))) {
				long bmax = MIN(plit - vplit, 8); // keep it at 8, always faster
				long back, i;

				if (bmax > 258 - mlen)
					bmax = 258 - mlen;

				/* 2 bytes, which proved best for the text tree */
				back = backward_match(in, pos, lastp, bmax, 2);

				if (back) {
					/* rewind the literals that are part of the match, see
					 * the fixed tree's loop.
					 */
					pos  -= back;
					plit -= back;
					rem  += back;
					mlen += back;
					code = len_code(mlen, SLZ_CT_TEXT);

					/* Not fixing <lit_excess> above is only safe when it
					 * overestimates the cost of the literals. With
					 * the text tree, these ones most likely saved
					 * bits, which would be counted twice since the
					 * match is credited 8 bits per byte as well.
					 */
					for (i = 0; i < back; i++)
						lit_excess -= (text_huff[in[pos + i]] & 15) - 8;
				}
			}

			/* first, copy pending literals */
			if (plit) {
				if (lit_stored)
					copy_lit_small(strm, in + pos - plit, plit, 1, SLZ_CT_TEXT, auto_tree);
				else {
					int32_t debt;

					if (__builtin_expect(nvref != 0, 0))
						text_replay(strm, in + pos - plit, plit, vref, nvref, 1);
					else
						copy_lit_huff(strm, in + pos - plit, plit, 1, SLZ_CT_TEXT, auto_tree);
					debt = strm->text_debt + (int32_t)lit_excess;
					strm->text_debt = debt > 0 ? debt : 0;
				}
				if (auto_tree)
					auto_account(strm, (int32_t)lit_excess, SLZ_CT_TEXT);
				nvref = vplit = 0;

				plit = 0;
			}

			/* open a text block (state "FIXED" means a huffman block) */
			if (strm->state == SLZ_ST_EOB) {
				strm->state = SLZ_ST_FIXED;
				open_huff_block(strm, 0, SLZ_CT_TEXT);
			}

			/* copy the length first */
#if SLZ_DIRECT_ENQUEUE56
			/* the length code and the distance code that follows it total
			 * 31 bits at most, which one enqueue can take in a single
			 * shift-or-store instead of two
			 */
			enqueue56(strm, (uint64_t)(code & 0xFFFF) |
			                ((uint64_t)(dist >> 5) << (code >> 16)),
			          (code >> 16) + (dist & 0x1f));
#else
			enqueue24(strm, code & 0xFFFF, code >> 16);

			/* the distance's code and size */
			enqueue24(strm, dist >> 5, dist & 0x1f);
#endif

			/* the reference's savings repay the debt, see SLZ_TEXT_MAX_DEBT */
			code = strm->text_debt + (code >> 16) + (dist & 0x1f);
			strm->text_debt = (code > 8 * (uint32_t)mlen) ? code - 8 * (uint32_t)mlen : 0;
			lit_excess = 0;

			/* switch to the other tree after this match if the literals
			 * sent before it requested it, see SLZ_AUTO_IN.
			 */
			if (auto_tree) {
				if (__builtin_expect(strm->tree_switch, 0)) {
					pos += mlen;
					goto switch_to_fixed;
				}
			}
	text_skip_ref:
			rem -= mlen;
			pos += mlen;

#if SLZ_INSERT_SKIPPED
			if (rem < 4)
				break;
			insert_ref(refs, in, pos - mlen + 3);
			insert_ref(refs, in, pos - mlen + 2);
			insert_ref(refs, in, pos - mlen + 1);
#endif // SLZ_INSERT_SKIPPED

#ifndef UNALIGNED_FASTER
			if (rem >= 4) {
#ifdef UNALIGNED_LE_OK
				word = *(uint32_t *)&in[pos - 1];
#else
				word = ((uint32_t)(unsigned char)in[pos] << 8) + ((uint32_t)(unsigned char)in[pos + 1] << 16) + ((uint32_t)(unsigned char)in[pos + 2] << 24);
#endif
			}
#endif
		}

		if (__builtin_expect(rem, 0)) {
			/* we're reading the 1..3 last bytes */
			plit += rem;
			do {
				lit_excess += (text_huff[in[pos++]] & 15) - 8;
			} while (--rem);
		}

		/* Now copy remaining literals or mark the end. The cost of switching to
		 * a stored block depends on the current state and on the presence of
		 * data after these literals, see the SLZ_*_COST definitions above.
		 */
		if (plit) {
			int32_t lit_cost;

			/* same with the text tree, in EOB state the huffman encoding
			 * has to pay for the block type and the header, and the EOB
			 * when nothing follows. When nothing follows and a text block
			 * is already open, the literals stay in it, as reopening one
			 * only to set BFINAL would cost a second header. The stream
			 * is then terminated by slz_finish() with an EOB and an empty
			 * final fixed block (10 bits), while leaving the block for a
			 * final stored one costs the EOB and SLZ_TEXT_STORED_COST.
			 */
			if (more)
				lit_cost = (strm->state == SLZ_ST_EOB) ?
					SLZ_TEXT_STORED_COST - SLZ_TEXT_OPEN_COST : SLZ_TEXT_SWITCH_COST;
			else
				lit_cost = (strm->state == SLZ_ST_EOB) ?
					SLZ_TEXT_STORED_COST - SLZ_TEXT_OPEN_COST - TEXT_EOB_BITS : SLZ_TEXT_STORED_COST - 10;

			if ((int32_t)lit_excess >= lit_cost ||
			    (int32_t)strm->text_debt + (int32_t)lit_excess +
			    (strm->state == SLZ_ST_EOB ? SLZ_TEXT_SWITCH_COST : 0) >= SLZ_TEXT_MAX_DEBT)
				copy_lit_small(strm, in + pos - plit, plit, more, SLZ_CT_TEXT, auto_tree);
			else {
				int32_t debt;

				/* the header, if any, is charged when opening the block */
				if (nvref)
					text_replay(strm, in + pos - plit, plit, vref, nvref, more);
				else
					copy_lit_huff(strm, in + pos - plit, plit, more || strm->state != SLZ_ST_EOB, SLZ_CT_TEXT, auto_tree);
				debt = strm->text_debt + (int32_t)lit_excess;
				strm->text_debt = debt > 0 ? debt : 0;
			}

			plit = 0;
		}
		goto leave;
	}

	/* Switching trees with the automatic tree (see SLZ_AUTO_IN): close the
	 * block and continue from <pos> with the other tree's part.
	 */
	if (auto_tree) {
 switch_to_text:
		if (strm->state == SLZ_ST_FIXED) {
			send_eob(strm, SLZ_CT_GENERIC);
			strm->state = SLZ_ST_EOB;
		}
		strm->tree_switch = 0;
		strm->tree_save = 0;
		strm->cur_tree = SLZ_CT_TEXT;
		debt_to_text(strm);
		goto text_start;

 switch_to_fixed:
		if (strm->state == SLZ_ST_FIXED) {
			send_eob(strm, SLZ_CT_TEXT);
			strm->state = SLZ_ST_EOB;
		}
		strm->tree_switch = 0;
		strm->tree_save = 0;
		strm->cur_tree = SLZ_CT_GENERIC;
		debt_to_fixed(strm);
		goto fixed_start;
	}
 leave:
	strm->ilen += ilen;
	return strm->outbuf - out;
}

/* The <level> argument of the encoder is not the compression level, it sets
 * the fixed tree's literal skip and debt accounting (see SLZ_MAX_DEBT and the
 * literal skip in _slz_rfc1951_encode()):
 *   1: blind skip ramp from 64 to 8128 bytes, debt charged per group of
 *      literals (per literal without SLZ_LITERAL_SKIP);
 *   2: same, with a probe every 64 skipped bytes;
 *   3: skip in 2048-byte steps up to 28 kB, with a probe every 64 skipped
 *      bytes, debt charged per literal.
 * Its <bmatch> argument is the number of bytes a match may be grown
 * backwards over the pending literals with the fixed tree (0 to disable it).
 * It costs a little CPU on every match and gains about 1% of output. Tests
 * show that matching up to 2 bytes brings almost optimal results at minimal
 * extra cost, and that compression gains at 1 byte are higher than the CPU
 * increase they cause, and tend to result in higher compression speed due to
 * the savings on encoding. At compression level 4, 8 bytes save 0.03% over 2
 * on silesia for 0.5% of speed.
 * The compression levels are made of:
 *   level 1: encoder level 1, 1-byte backward match, fixed tree only;
 *   level 2: encoder level 1, 1-byte backward match, automatic tree (see
 *            SLZ_AUTO_IN);
 *   level 3: encoder level 2, 1-byte backward match, automatic tree;
 *   level 4: encoder level 3, 8-byte backward match, automatic tree.
 * The text tree's part is the same at all levels (2-byte backward match).
 */
static __attribute__((noinline))
long _slz_rfc1951_encode_lev1(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	return _slz_rfc1951_encode(strm, out, in, ilen, more, 1, 1, 0);
}

static __attribute__((noinline))
long _slz_rfc1951_encode_lev2(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	return _slz_rfc1951_encode(strm, out, in, ilen, more, 1, 1, 1);
}

static __attribute__((noinline))
long _slz_rfc1951_encode_lev3(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	return _slz_rfc1951_encode(strm, out, in, ilen, more, 2, 1, 1);
}

static __attribute__((noinline))
long _slz_rfc1951_encode_lev4(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	return _slz_rfc1951_encode(strm, out, in, ilen, more, 3, 8, 1);
}

/* Event encoder, used with SLZ_CT_EVENT: streams made of small events flushed
 * one at a time (SSE, syslog...), where slz_rfc1951_encode() cannot find much
 * since it forgets everything at each call. The ring, allocated by the caller
 * (slz_ring_size bytes, zeroed) and referenced by strm->ring, keeps the last
 * SLZ_EV_HIST bytes passed to the stream and a reference table between calls.
 * 2 kB of history and a 9-bit table of 4-byte entries were found to be a good
 * trade-off between SSE and logs, and between ratio and cost with many
 * concurrent streams whose ring is out of the caches at each call, see
 * experiments/events.
 */
#define SLZ_EV_HIST      2048 /* history size, a power of 2 */
#define SLZ_EV_HASH_BITS 9    /* size of the reference table */
#define SLZ_EV_STEP      8    /* step between the matched positions indexed */

struct slz_ring {
	/* entries: 16 low bits of the position, and a 16-bit tag of the word */
	uint32_t refs[1 << SLZ_EV_HASH_BITS];
	unsigned char hist[SLZ_EV_HIST]; /* ring of the last bytes */
	uint32_t hoff;   /* next write position in <hist> */
	uint32_t hlen;   /* bytes of history in <hist>, at most SLZ_EV_HIST */
	uint32_t hend;   /* stream position (strm->ilen) at the history's end */
};

/* size of the ring to allocate per stream for SLZ_CT_EVENT */
const int slz_ring_size = sizeof(struct slz_ring);

/* the hash of the event encoder's reference table, on SLZ_EV_HASH_BITS bits */
static inline uint32_t slz_ev_hash(uint32_t a)
{
	return slz_hash_bits(a, SLZ_EV_HASH_BITS);
}

/* 16-bit tag of word <w>, from bits the hash mostly ignores */
static inline uint32_t slz_ev_tag(uint32_t w)
{
	return (uint16_t)(w ^ (w >> 16));
}

/* inserts absolute position <p> whose 4 first bytes are <w> */
static inline void slz_ev_insert(struct slz_ring *ring, uint32_t p, uint32_t w)
{
	ring->refs[slz_ev_hash(w)] = (uint16_t)p + (slz_ev_tag(w) << 16);
}

/* compares up to <max> bytes at <a> with the source at <b>, of which only
 * <bavail> are contiguous, the source then continuing at <in>.
 */
static inline long slz_ev_match(const unsigned char *a, const unsigned char *b, long bavail, const unsigned char *in, long max)
{
	long l;

	if (max <= bavail)
		return memmatch(a, b, max);
	l = memmatch(a, b, bavail);
	if (l < bavail)
		return l;
	return l + memmatch(a + l, in, max - l);
}

/* Encodes <ilen> bytes from <in> into <out> for stream <strm> using the ring
 * at strm->ring, see above. It is a copy of the fixed tree's part of
 * _slz_rfc1951_encode(), whose comments apply here, adapted to the ring and
 * simplified. The references may point into the history kept
 * in the ring, which is matched in place: from the oldest byte to the ring's
 * end, then from the ring's start, then into the input. Positions are counted
 * from the start of the stream (strm->ilen), so that the entries from the
 * previous calls remain valid, and every hit is verified by reading the
 * source bytes, which also rejects the entries aliased by the 16-bit
 * positions or by the 32-bit wrapping. The level is ignored (except 0, which
 * never comes here), it always uses the fixed tree, never skips literals, and
 * grows matches up to 8 bytes backwards. One matched position in SLZ_EV_STEP
 * is indexed: with a step of 8, the first indexed position after the point
 * where the data diverge is at most 8 bytes away, and the backward match
 * recovers these bytes. The input is appended to the ring on exit.
 */
static __attribute__((noinline))
long _slz_rfc1951_ev_encode(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	struct slz_ring *ring = strm->ring;
	const unsigned char *hist = ring->hist;
	/* the history is lost if some data were passed without the ring */
	uint32_t hlen = (ring->hend == strm->ilen) ? ring->hlen : 0;
	uint32_t hstart = (ring->hoff - hlen) & (SLZ_EV_HIST - 1); /* oldest byte */
	uint32_t base = strm->ilen;        /* absolute position of in[0] */
	uint32_t hbase = base - hlen;      /* absolute position of the oldest byte */
	long pos = 0, rem = ilen;
	uint32_t plit = 0;
	uint32_t bal;
	const char *p;
	int k;

	strm->outbuf = out;

	/* on busy proxies, nothing of the ring is left in the caches since
	 * the previous event, and the table is accessed randomly.
	 */
	for (p = (const char *)ring->refs; p < (const char *)ring->refs + sizeof(ring->refs); p += 64)
		__builtin_prefetch(p, 1);

	/* only the fixed tree here, see SLZ_AUTO_IN */
	leave_text_tree(strm);
	strm->tree_switch = 0;

	/* the last 3 positions of the history could not be indexed before
	 * their 4th byte was known.
	 */
	for (k = 3; k >= 1; k--) {
		unsigned char tmp[4];
		int j;

		if (hlen < (uint32_t)k || ilen < 4 - k)
			continue;
		for (j = 0; j < k; j++)
			tmp[j] = hist[(hstart + hlen - k + j) & (SLZ_EV_HIST - 1)];
		for (; j < 4; j++)
			tmp[j] = in[j - k];
		slz_ev_insert(ring, base - k, read_le32(tmp));
	}

	bal = strm->debt;

	while (rem >= 4) {
		uint32_t word = read_le32(in + pos);
		uint32_t h = slz_ev_hash(word);
		uint32_t cur = base + pos;
		uint32_t ent = ring->refs[h];
		uint32_t last, off, dist, code, d;
		const unsigned char *src;
		long savail, mlen, max, sback;

		ring->refs[h] = (uint16_t)cur + (slz_ev_tag(word) << 16);
		if ((ent >> 16) != slz_ev_tag(word))
			goto send_as_lit;

		/* the most recent position with these 16 low bits, at most
		 * 65536 bytes back: older entries alias to it and are rejected
		 * by the range check or the comparison below.
		 */
		last = cur - (uint16_t)(cur - ent);

		/* must be within the history or the input before <pos> */
		off = last - hbase;
		if (off >= hlen + (uint32_t)pos)
			goto send_as_lit;
		dist = hlen + pos - off;
		if (dist > 32768)
			goto send_as_lit;

		max = rem > 258 ? 258 : rem;
		if (off < hlen) {
			/* in the history: the source may run to the ring's
			 * end, then continue at its start, then into the
			 * input. <sback> is what can be read before it in
			 * the same segment.
			 */
			uint32_t ph = (hstart + off) & (SLZ_EV_HIST - 1);
			long wrap = SLZ_EV_HIST - ph;

			src = hist + ph;
			savail = hlen - off;
			sback = off < ph ? off : ph;
			if (savail > wrap) {
				long l = memmatch(in + pos, src, wrap < max ? wrap : max);

				mlen = l;
				if (l == wrap && l < max)
					mlen += slz_ev_match(in + pos + l, hist, savail - wrap, in, max - l);
			}
			else
				mlen = slz_ev_match(in + pos, src, savail, in, max);
		}
		else {
			src = in + (off - hlen);
			sback = off - hlen;
			mlen = memmatch(in + pos, src, max);
		}

		/* this also verifies the word */
		if (mlen < 4)
			goto send_as_lit;

		if (bal >= SLZ_SWITCH_COST + SLZ_CREDIT && mlen < 6)
			goto send_as_lit;

		code = len_code(mlen, SLZ_CT_GENERIC);
		d = fh_dist_table[dist - 1];

		/* see _slz_rfc1951_encode() */
		if (bal >= SLZ_MAX_DEBT + SLZ_CREDIT &&
		    (d & 0x1f) + (code >> 16) + SLZ_SWITCH_COST > 8 * mlen)
			goto send_as_lit;

		/* grow the match backwards over up to 8 pending literals,
		 * within the source's segment, see the backward match in
		 * _slz_rfc1951_encode(). 8 bytes are compared at once when
		 * available before both sides, otherwise one at a time.
		 */
		if (plit) {
			long bmax = MIN(plit, 8);
			long back;

			if (bmax > 258 - mlen)
				bmax = 258 - mlen;
			if (bmax > sback)
				bmax = sback;
			if (MIN((long)pos, sback) >= 8)
				back = backward_match(in, pos, src, bmax, 8);
			else
				back = backward_match(in, pos, src, bmax, 0);
			if (back) {
				pos  -= back;
				plit -= back;
				rem  += back;
				mlen += back;
				code = len_code(mlen, SLZ_CT_GENERIC);
			}
		}

		if (plit) {
			if (bal >= SLZ_SWITCH_COST + SLZ_CREDIT) {
				copy_lit(strm, in + pos - plit, plit, 1, 0);
				bal = strm->debt;
			}
			else
				copy_lit_huff(strm, in + pos - plit, plit, 1, SLZ_CT_GENERIC, 0);
			plit = 0;
		}

		if (strm->state == SLZ_ST_EOB) {
			strm->state = SLZ_ST_FIXED;
			open_huff_block(strm, 0, SLZ_CT_GENERIC);
			bal = strm->debt + SLZ_SWITCH_COST;
		}

#if SLZ_DIRECT_ENQUEUE56
		/* see _slz_rfc1951_encode() */
		enqueue56(strm, (uint64_t)(code & 0xFFFF) |
		                ((uint64_t)(d >> 5) << (code >> 16)),
		          (code >> 16) + (d & 0x1f));
#else
		enqueue24(strm, code & 0xFFFF, code >> 16);
		enqueue24(strm, d >> 5, d & 0x1f);
#endif

		code = bal + (code >> 16) + (d & 0x1f);
		bal = (code > 8 * (uint32_t)mlen) ? code - 8 * (uint32_t)mlen : 0;
		strm->debt = bal;

		rem -= mlen;
		pos += mlen;

		/* Index the matched positions, also when the match reaches the
		 * end of the input since the next calls need them. Those whose
		 * 4 bytes are not all there yet are indexed by the next call.
		 */
		{
			long i = pos - mlen + 1;
			long e = pos;

			if (e > ilen - 3)
				e = ilen - 3;
			for (; i < e; i += SLZ_EV_STEP)
				slz_ev_insert(ring, base + i, read_le32(in + i));
		}
		continue;

	send_as_lit:
		bal += ((unsigned char)word >= 144);
		plit++;
		pos++;
		rem--;
		if (__builtin_expect(plit == 0xffc0, 0)) {
			copy_lit_small(strm, in + pos - plit, plit, 1, SLZ_CT_GENERIC, 0);
			plit = 0;
			bal = strm->debt + SLZ_MAX_DEBT + SLZ_CREDIT;
		}
	}

	if (rem) {
		plit += rem;
		do {
			bal += (in[pos++] >= 144);
		} while (--rem);
	}

	if (plit) {
		uint32_t cost;

		if (more)
			cost = SLZ_SWITCH_COST;
		else
			cost = (strm->state == SLZ_ST_EOB) ? SLZ_LAST_COST_EOB : SLZ_LAST_COST;

		if (bal >= cost + SLZ_CREDIT)
			copy_lit(strm, in + pos - plit, plit, more, 0);
		else {
			copy_lit_huff(strm, in + pos - plit, plit, more, SLZ_CT_GENERIC, 0);
			strm->debt = bal;
		}
	}

	/* append the input to the ring */
	if (ilen >= SLZ_EV_HIST) {
		memcpy(ring->hist, in + ilen - SLZ_EV_HIST, SLZ_EV_HIST);
		ring->hoff = 0;
		ring->hlen = SLZ_EV_HIST;
	}
	else {
		uint32_t hoff = ring->hoff;
		uint32_t n1 = SLZ_EV_HIST - hoff;

		if (n1 > ilen)
			n1 = ilen;
		memcpy(ring->hist + hoff, in, n1);
		memcpy(ring->hist, in + n1, ilen - n1);
		ring->hoff = (hoff + ilen) & (SLZ_EV_HIST - 1);
		ring->hlen = hlen + ilen > SLZ_EV_HIST ? SLZ_EV_HIST : hlen + ilen;
	}
	ring->hend = base + ilen;

	strm->ilen += ilen;
	return strm->outbuf - out;
}

long slz_rfc1951_encode(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	int level = strm->level;

	/* events: needs a ring, otherwise the same as no hint */
	if (__builtin_expect(strm->content_type == SLZ_CT_EVENT, 0) && strm->ring && level)
		return _slz_rfc1951_ev_encode(strm, out, in, ilen, more);

	/* mostly text: levels 1 and 2 work as level 3, see
	 * slz_set_content_type().
	 */
	if (strm->content_type == SLZ_CT_TEXT && level && level < 3)
		level = 3;

	if (level <= 1) {
		/* level 1 (and 0) only use the fixed tree */
		if (__builtin_expect(strm->cur_tree != SLZ_CT_GENERIC, 0)) {
			long n;

			strm->outbuf = out;
			leave_text_tree(strm);
			n = strm->outbuf - out;
			return n + _slz_rfc1951_encode_lev1(strm, out + n, in, ilen, more);
		}
		return _slz_rfc1951_encode_lev1(strm, out, in, ilen, more);
	}
	else if (level <= 2)
		return _slz_rfc1951_encode_lev2(strm, out, in, ilen, more);
	else if (level <= 3)
		return _slz_rfc1951_encode_lev3(strm, out, in, ilen, more);
	else
		return _slz_rfc1951_encode_lev4(strm, out, in, ilen, more);
}

/* Initializes stream <strm> for use with raw deflate (rfc1951). The CRC is
 * unused but set to zero. The compression level passed in <level> is set. This
 * value will be capped between 0 (no compression) and 15 (max compression).
 * The function always returns 0.
 */
int slz_rfc1951_init(struct slz_stream *strm, int level)
{
	strm->state = SLZ_ST_EOB; // no header
	strm->level = MIN(MAX(level, 0), 15);
	strm->format = SLZ_FMT_DEFLATE;
	strm->ring = NULL;
	strm->crc32 = 0;
	strm->ilen  = 0;
	strm->qbits = 0;
	strm->queue = 0;
	strm->debt  = SLZ_CREDIT;
	strm->text_debt = SLZ_TEXT_CREDIT;
	strm->content_type = SLZ_CT_GENERIC;
	strm->cur_tree = (strm->level >= 2) ? SLZ_CT_TEXT : SLZ_CT_GENERIC; // see SLZ_AUTO_IN
	strm->tree_save = 0;
	strm->tree_switch = 0;
	return 0;
}

/* Emits into buffer <buf> all the bits pending in stream <strm> at the time of
 * the call, so that everything passed so far is decodable from the emitted
 * bytes, and returns their number. Pending bits ending on a byte boundary are
 * simply emitted. Otherwise, the least is added to cross the boundary,
 * depending on the state:
 *   - inside a block: its EOB, which is at least 7 bits long. The next encode
 *     call opens a new block.
 *   - inside the last block: its EOB, then padding to the next byte since
 *     nothing may follow it. The stream is then complete.
 *   - after the last block: padding, for the same reason.
 *   - between blocks: an empty fixed block (10 bits).
 * Only the complete bytes are emitted, so that the bits added beyond the
 * boundary may stay queued, the next call emitting them. The output is then
 * not aligned on return. It costs 7 bits plus the next block's 3 header bits
 * where older versions emitted an empty stored block to byte-align the
 * output, or about 48 bits. This requires that the output buffer still has
 * the size of the queue (up to 31 bits when using the 64-bit queue) plus up
 * to 11 bits, rounded up to the next byte, or 6 bytes in the worst case.
 */
int slz_rfc1951_flush(struct slz_stream *strm, unsigned char *buf)
{
	strm->outbuf = buf;

	if (strm->qbits & 7) {
		switch (strm->state) {
		case SLZ_ST_FIXED:
			send_eob(strm, strm->cur_tree);
			strm->state = SLZ_ST_EOB;
			break;
		case SLZ_ST_LAST:
			send_eob(strm, strm->cur_tree);
			strm->state = SLZ_ST_DONE;
			__fallthrough;
		case SLZ_ST_DONE:
		case SLZ_ST_END:
			flush_bits(strm);
			return strm->outbuf - buf;
		default:
			/* an empty fixed block, whatever the tree
			 * since it's the cheapest one, as in finish().
			 */
			enqueue8(strm, 2, 3); // BFINAL = 0 ; BTYPE = 01
			send_eob(strm, SLZ_CT_GENERIC);
			break;
		}
	}

	/* emit the complete bytes only */
	while (strm->qbits >= 8) {
		*strm->outbuf++ = strm->queue;
		strm->queue >>= 8;
		strm->qbits -= 8;
	}
	return strm->outbuf - buf;
}

/* the EOB must cross the byte boundary in slz_rfc1951_flush() */
typedef char slz_text_eob_bits_check[(TEXT_EOB_BITS >= 7) ? 1 : -1];

/* Flushes any pending for stream <strm> into buffer <buf>, then sends BTYPE=1
 * and BFINAL=1 if needed. The stream ends in SLZ_ST_DONE. It returns the number
 * of bytes emitted. The trailer consists in flushing the possibly pending bits
 * from the queue (up to 31 bits when the queue is not stored after each
 * enqueue, see SLZ_DIRECT_ENQUEUE24), then possibly the EOB (7 bits with the
 * fixed tree, 11 with the text one), then 3 bits, EOB, a rounding to the next
 * byte, which amounts to a total of 7 bytes max, that the caller must ensure
 * are available before calling the function.
 */
int slz_rfc1951_finish(struct slz_stream *strm, unsigned char *buf)
{
	strm->outbuf = buf;

	if (strm->state == SLZ_ST_FIXED || strm->state == SLZ_ST_LAST) {
		strm->state = (strm->state == SLZ_ST_LAST) ? SLZ_ST_DONE : SLZ_ST_EOB;
		send_eob(strm, strm->cur_tree);
	}

	if (strm->state != SLZ_ST_DONE) {
		/* send BTYPE=1, BFINAL=1. This is an empty fixed block whatever
		 * the tree since it's the cheapest one.
		 */
		enqueue8(strm, 3, 3);
		send_eob(strm, SLZ_CT_GENERIC);
		strm->state = SLZ_ST_DONE;
	}

	flush_bits(strm);
	return strm->outbuf - buf;
}

/* Now RFC1952-specific declarations and extracts from RFC.
 * From RFC1952 about the GZIP file format :

A gzip file consists of a series of "members" ...

2.3. Member format

      Each member has the following structure:

         +---+---+---+---+---+---+---+---+---+---+
         |ID1|ID2|CM |FLG|     MTIME     |XFL|OS | (more-->)
         +---+---+---+---+---+---+---+---+---+---+

      (if FLG.FEXTRA set)

         +---+---+=================================+
         | XLEN  |...XLEN bytes of "extra field"...| (more-->)
         +---+---+=================================+

      (if FLG.FNAME set)

         +=========================================+
         |...original file name, zero-terminated...| (more-->)
         +=========================================+

      (if FLG.FCOMMENT set)

         +===================================+
         |...file comment, zero-terminated...| (more-->)
         +===================================+

      (if FLG.FHCRC set)

         +---+---+
         | CRC16 |
         +---+---+

         +=======================+
         |...compressed blocks...| (more-->)
         +=======================+

           0   1   2   3   4   5   6   7
         +---+---+---+---+---+---+---+---+
         |     CRC32     |     ISIZE     |
         +---+---+---+---+---+---+---+---+


2.3.1. Member header and trailer

         ID1 (IDentification 1)
         ID2 (IDentification 2)
            These have the fixed values ID1 = 31 (0x1f, \037), ID2 = 139
            (0x8b, \213), to identify the file as being in gzip format.

         CM (Compression Method)
            This identifies the compression method used in the file.  CM
            = 0-7 are reserved.  CM = 8 denotes the "deflate"
            compression method, which is the one customarily used by
            gzip and which is documented elsewhere.

         FLG (FLaGs)
            This flag byte is divided into individual bits as follows:

               bit 0   FTEXT
               bit 1   FHCRC
               bit 2   FEXTRA
               bit 3   FNAME
               bit 4   FCOMMENT
               bit 5   reserved
               bit 6   reserved
               bit 7   reserved

            Reserved FLG bits must be zero.

         MTIME (Modification TIME)
            This gives the most recent modification time of the original
            file being compressed.  The time is in Unix format, i.e.,
            seconds since 00:00:00 GMT, Jan.  1, 1970.  (Note that this
            may cause problems for MS-DOS and other systems that use
            local rather than Universal time.)  If the compressed data
            did not come from a file, MTIME is set to the time at which
            compression started.  MTIME = 0 means no time stamp is
            available.

         XFL (eXtra FLags)
            These flags are available for use by specific compression
            methods.  The "deflate" method (CM = 8) sets these flags as
            follows:

               XFL = 2 - compressor used maximum compression,
                         slowest algorithm
               XFL = 4 - compressor used fastest algorithm

         OS (Operating System)
            This identifies the type of file system on which compression
            took place.  This may be useful in determining end-of-line
            convention for text files.  The currently defined values are
            as follows:

                 0 - FAT filesystem (MS-DOS, OS/2, NT/Win32)
                 1 - Amiga
                 2 - VMS (or OpenVMS)
                 3 - Unix
                 4 - VM/CMS
                 5 - Atari TOS
                 6 - HPFS filesystem (OS/2, NT)
                 7 - Macintosh
                 8 - Z-System
                 9 - CP/M
                10 - TOPS-20
                11 - NTFS filesystem (NT)
                12 - QDOS
                13 - Acorn RISCOS
               255 - unknown

 ==> A file compressed using "gzip -1" on Unix-like systems can be :

        1F 8B 08 00  00 00 00 00  04 03
        <deflate-compressed stream>
        crc32 size32
*/

static const unsigned char gzip_hdr[] = { 0x1F, 0x8B,   // ID1, ID2
                                          0x08, 0x00,   // Deflate, flags (none)
                                          0x00, 0x00, 0x00, 0x00, // mtime: none
                                          0x04, 0x03 }; // fastest comp, OS=Unix

/* Sends the gzip header for stream <strm> into buffer <buf>. When it's done,
 * the stream state is updated to SLZ_ST_EOB. It returns the number of bytes
 * emitted which is always 10. The caller is responsible for ensuring there's
 * always enough room in the buffer.
 */
int slz_rfc1952_send_header(struct slz_stream *strm, unsigned char *buf)
{
	memcpy(buf, gzip_hdr, sizeof(gzip_hdr));
	strm->state = SLZ_ST_EOB;
	return sizeof(gzip_hdr);
}

/* Encodes the block according to rfc1952. This means that the CRC of the input
 * block is computed according to the CRC32 algorithm. If the header was never
 * sent, it may be sent first. The number of output bytes is returned.
 */
long slz_rfc1952_encode(struct slz_stream *strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	long ret = 0;

	if (__builtin_expect(strm->state == SLZ_ST_INIT, 0))
		ret += slz_rfc1952_send_header(strm, out);

	strm->crc32 = update_crc(strm->crc32, in, ilen);
	ret += slz_rfc1951_encode(strm, out + ret, in, ilen, more);
	return ret;
}

/* Initializes stream <strm> for use with the gzip format (rfc1952). The
 * compression level passed in <level> is set. This value will be capped
 * between 0 (no compression) and 15 (max compression). The function always
 * returns 0.
 */
int slz_rfc1952_init(struct slz_stream *strm, int level)
{
	strm->state  = SLZ_ST_INIT;
	strm->level  = MIN(MAX(level, 0), 15);
	strm->format = SLZ_FMT_GZIP;
	strm->ring = NULL;
	strm->crc32  = 0;
	strm->ilen   = 0;
	strm->qbits  = 0;
	strm->queue  = 0;
	strm->debt   = SLZ_CREDIT;
	strm->text_debt = SLZ_TEXT_CREDIT;
	strm->content_type = SLZ_CT_GENERIC;
	strm->cur_tree = (strm->level >= 2) ? SLZ_CT_TEXT : SLZ_CT_GENERIC; // see SLZ_AUTO_IN
	strm->tree_save = 0;
	strm->tree_switch = 0;
	return 0;
}

/* Makes everything passed to stream <strm> so far decodable from the bytes
 * emitted into buffer <buf>, see slz_rfc1951_flush(). Note that if the initial
 * header was never sent, it will be sent first as well (10 extra bytes). This
 * requires that the output buffer still has this plus the 6 bytes needed to
 * emit the queue and a possible EOB, or a total of 16 bytes in the worst case.
 * The number of bytes emitted is returned.
 */
int slz_rfc1952_flush(struct slz_stream *strm, unsigned char *buf)
{
	int sent = 0;

	if (__builtin_expect(strm->state == SLZ_ST_INIT, 0))
		sent = slz_rfc1952_send_header(strm, buf);

	sent += slz_rfc1951_flush(strm, buf + sent);
	return sent;
}

/* Flushes pending bits and sends the gzip trailer for stream <strm> into
 * buffer <buf>. When it's done, the stream state is updated to SLZ_ST_END. It
 * returns the number of bytes emitted. The trailer consists in flushing the
 * possibly pending bits from the queue, the possible EOB and the final empty
 * block, rounding to the next byte, then 4 bytes for the CRC and another 4
 * bytes for the input length. That may amount to 7+4+4 = 15 bytes, that the
 * caller must ensure are available before calling the function. Note that if
 * the initial header was never sent, it will be sent first as well (10 extra
 * bytes).
 */
int slz_rfc1952_finish(struct slz_stream *strm, unsigned char *buf)
{
	strm->outbuf = buf;

	if (__builtin_expect(strm->state == SLZ_ST_INIT, 0))
		strm->outbuf += slz_rfc1952_send_header(strm, strm->outbuf);

	slz_rfc1951_finish(strm, strm->outbuf);
	copy_32b(strm, strm->crc32);
	copy_32b(strm, strm->ilen);
	strm->state = SLZ_ST_END;

	return strm->outbuf - buf;
}


/* RFC1950-specific stuff. This is for the Zlib stream format.
 * From RFC1950 (zlib) :
 *

   2.2. Data format

      A zlib stream has the following structure:

           0   1
         +---+---+
         |CMF|FLG|   (more-->)
         +---+---+


      (if FLG.FDICT set)

           0   1   2   3
         +---+---+---+---+
         |     DICTID    |   (more-->)
         +---+---+---+---+

         +=====================+---+---+---+---+
         |...compressed data...|    ADLER32    |
         +=====================+---+---+---+---+

      Any data which may appear after ADLER32 are not part of the zlib
      stream.

      CMF (Compression Method and flags)
         This byte is divided into a 4-bit compression method and a 4-
         bit information field depending on the compression method.

            bits 0 to 3  CM     Compression method
            bits 4 to 7  CINFO  Compression info

      CM (Compression method)
         This identifies the compression method used in the file. CM = 8
         denotes the "deflate" compression method with a window size up
         to 32K.  This is the method used by gzip and PNG (see
         references [1] and [2] in Chapter 3, below, for the reference
         documents).  CM = 15 is reserved.  It might be used in a future
         version of this specification to indicate the presence of an
         extra field before the compressed data.

      CINFO (Compression info)
         For CM = 8, CINFO is the base-2 logarithm of the LZ77 window
         size, minus eight (CINFO=7 indicates a 32K window size). Values
         of CINFO above 7 are not allowed in this version of the
         specification.  CINFO is not defined in this specification for
         CM not equal to 8.

      FLG (FLaGs)
         This flag byte is divided as follows:

            bits 0 to 4  FCHECK  (check bits for CMF and FLG)
            bit  5       FDICT   (preset dictionary)
            bits 6 to 7  FLEVEL  (compression level)

         The FCHECK value must be such that CMF and FLG, when viewed as
         a 16-bit unsigned integer stored in MSB order (CMF*256 + FLG),
         is a multiple of 31.


      FDICT (Preset dictionary)
         If FDICT is set, a DICT dictionary identifier is present
         immediately after the FLG byte. The dictionary is a sequence of
         bytes which are initially fed to the compressor without
         producing any compressed output. DICT is the Adler-32 checksum
         of this sequence of bytes (see the definition of ADLER32
         below).  The decompressor can use this identifier to determine
         which dictionary has been used by the compressor.

      FLEVEL (Compression level)
         These flags are available for use by specific compression
         methods.  The "deflate" method (CM = 8) sets these flags as
         follows:

            0 - compressor used fastest algorithm
            1 - compressor used fast algorithm
            2 - compressor used default algorithm
            3 - compressor used maximum compression, slowest algorithm

         The information in FLEVEL is not needed for decompression; it
         is there to indicate if recompression might be worthwhile.

      compressed data
         For compression method 8, the compressed data is stored in the
         deflate compressed data format as described in the document
         "DEFLATE Compressed Data Format Specification" by L. Peter
         Deutsch. (See reference [3] in Chapter 3, below)

         Other compressed data formats are not specified in this version
         of the zlib specification.

      ADLER32 (Adler-32 checksum)
         This contains a checksum value of the uncompressed data
         (excluding any dictionary data) computed according to Adler-32
         algorithm. This algorithm is a 32-bit extension and improvement
         of the Fletcher algorithm, used in the ITU-T X.224 / ISO 8073
         standard. See references [4] and [5] in Chapter 3, below)

         Adler-32 is composed of two sums accumulated per byte: s1 is
         the sum of all bytes, s2 is the sum of all s1 values. Both sums
         are done modulo 65521. s1 is initialized to 1, s2 to zero.  The
         Adler-32 checksum is stored as s2*65536 + s1 in most-
         significant-byte first (network) order.

  ==> The stream can start with only 2 bytes :
        - CM  = 0x78 : CMINFO=7 (32kB window),  CM=8 (deflate)
        - FLG = 0x01 : FLEVEL = 0 (fastest), FDICT=0 (no dict), FCHECK=1 so
          that 0x7801 is a multiple of 31 (30721 = 991 * 31).

  ==> and it ends with only 4 bytes, the Adler-32 checksum in big-endian format.

 */

static const unsigned char zlib_hdr[] = { 0x78, 0x01 };   // 32k win, deflate, chk=1

/* Sends the zlib header for stream <strm> into buffer <buf>. When it's done,
 * the stream state is updated to SLZ_ST_EOB. It returns the number of bytes
 * emitted which is always 2. The caller is responsible for ensuring there's
 * always enough room in the buffer.
 */
int slz_rfc1950_send_header(struct slz_stream *strm, unsigned char *buf)
{
	memcpy(buf, zlib_hdr, sizeof(zlib_hdr));
	strm->state = SLZ_ST_EOB;
	return sizeof(zlib_hdr);
}

/* Encodes the block according to rfc1950. This means that the CRC of the input
 * block is computed according to the ADLER32 algorithm. If the header was never
 * sent, it may be sent first. The number of output bytes is returned.
 */
long slz_rfc1950_encode(struct slz_stream *strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	long ret = 0;

	if (__builtin_expect(strm->state == SLZ_ST_INIT, 0))
		ret += slz_rfc1950_send_header(strm, out);

	strm->crc32 = slz_adler32_block(strm->crc32, in, ilen);
	ret += slz_rfc1951_encode(strm, out + ret, in, ilen, more);
	return ret;
}

/* Initializes stream <strm> for use with the zlib format (rfc1950). The
 * compression level passed in <level> is set. This value will be capped
 * between 0 (no compression) and 15 (max compression). The function always
 * returns 0.
 */
int slz_rfc1950_init(struct slz_stream *strm, int level)
{
	strm->state  = SLZ_ST_INIT;
	strm->level  = MIN(MAX(level, 0), 15);
	strm->format = SLZ_FMT_ZLIB;
	strm->ring = NULL;
	strm->crc32  = 1; // rfc1950/zlib starts with initial crc=1
	strm->ilen   = 0;
	strm->qbits  = 0;
	strm->queue  = 0;
	strm->debt   = SLZ_CREDIT;
	strm->text_debt = SLZ_TEXT_CREDIT;
	strm->content_type = SLZ_CT_GENERIC;
	strm->cur_tree = (strm->level >= 2) ? SLZ_CT_TEXT : SLZ_CT_GENERIC; // see SLZ_AUTO_IN
	strm->tree_save = 0;
	strm->tree_switch = 0;
	return 0;
}

/* Makes everything passed to stream <strm> so far decodable from the bytes
 * emitted into buffer <buf>, see slz_rfc1951_flush(). Note that if the initial
 * header was never sent, it will be sent first as well (2 extra bytes). This
 * requires that the output buffer still has this plus the 6 bytes needed to
 * emit the queue and a possible EOB, or a total of 8 bytes in the worst case.
 * The number of bytes emitted is returned.
 */
int slz_rfc1950_flush(struct slz_stream *strm, unsigned char *buf)
{
	int sent = 0;

	if (__builtin_expect(strm->state == SLZ_ST_INIT, 0))
		sent = slz_rfc1950_send_header(strm, buf);

	sent += slz_rfc1951_flush(strm, buf + sent);
	return sent;
}

/* Flushes pending bits and sends the zlib trailer for stream <strm> into
 * buffer <buf>. When it's done, the stream state is updated to SLZ_ST_END. It
 * returns the number of bytes emitted. The trailer consists in flushing the
 * possibly pending bits from the queue, the possible EOB and the final empty
 * block, rounding to the next byte, then 4 bytes for the Adler-32. That may
 * amount to 7+4 = 11 bytes, that the caller must ensure are available before
 * calling the function. Note that if the initial header was never sent, it
 * will be sent first as well (2 extra bytes).
 */
int slz_rfc1950_finish(struct slz_stream *strm, unsigned char *buf)
{
	strm->outbuf = buf;

	if (__builtin_expect(strm->state == SLZ_ST_INIT, 0))
		strm->outbuf += slz_rfc1950_send_header(strm, strm->outbuf);

	slz_rfc1951_finish(strm, strm->outbuf);
	copy_8b(strm, (strm->crc32 >> 24) & 0xff);
	copy_8b(strm, (strm->crc32 >> 16) & 0xff);
	copy_8b(strm, (strm->crc32 >>  8) & 0xff);
	copy_8b(strm, (strm->crc32 >>  0) & 0xff);
	strm->state = SLZ_ST_END;
	return strm->outbuf - buf;
}

#ifndef PRECOMPUTE_TABLES
/* Converts <dist>, an entry of fh_dist_table[], to the same for the text tree.
 * The two only differ by the huffman code and its length, the extra bits are
 * the same, so the code is looked up from the 5-bit fixed one in bits 5..9.
 */
static inline uint32_t text_dist(uint32_t dist)
{
	uint32_t c = (dist >> 5) & 31;

	return ((dist >> 10) << text_dist_shift[c]) + text_dist_add[c] + (dist & 31);
}

/* Returns code for lengths 1 to 32768. The bit size for the next value can be
 * found this way :
 *
 *	bits = code >> 1;
 *	if (bits)
 *		bits--;
 *
 */
static inline uint32_t dist_to_code(uint32_t l)
{
	uint32_t code;

	code = 0;
	switch (l) {
	case 24577 ... 32768: code++; __fallthrough;
	case 16385 ... 24576: code++; __fallthrough;
	case 12289 ... 16384: code++; __fallthrough;
	case  8193 ... 12288: code++; __fallthrough;
	case  6145 ...  8192: code++; __fallthrough;
	case  4097 ...  6144: code++; __fallthrough;
	case  3073 ...  4096: code++; __fallthrough;
	case  2049 ...  3072: code++; __fallthrough;
	case  1537 ...  2048: code++; __fallthrough;
	case  1025 ...  1536: code++; __fallthrough;
	case   769 ...  1024: code++; __fallthrough;
	case   513 ...   768: code++; __fallthrough;
	case   385 ...   512: code++; __fallthrough;
	case   257 ...   384: code++; __fallthrough;
	case   193 ...   256: code++; __fallthrough;
	case   129 ...   192: code++; __fallthrough;
	case    97 ...   128: code++; __fallthrough;
	case    65 ...    96: code++; __fallthrough;
	case    49 ...    64: code++; __fallthrough;
	case    33 ...    48: code++; __fallthrough;
	case    25 ...    32: code++; __fallthrough;
	case    17 ...    24: code++; __fallthrough;
	case    13 ...    16: code++; __fallthrough;
	case     9 ...    12: code++; __fallthrough;
	case     7 ...     8: code++; __fallthrough;
	case     5 ...     6: code++; __fallthrough;
	case     4          : code++; __fallthrough;
	case     3          : code++; __fallthrough;
	case     2          : code++;
	}

	return code;
}
#endif

/* not thread-safe, must be called exactly once */
static inline void __slz_prepare_dist_table()
{
#ifndef PRECOMPUTE_TABLES
	uint32_t dist;
	uint32_t code;
	uint32_t bits;

	for (dist = 0; dist < sizeof(fh_dist_table) / sizeof(*fh_dist_table); dist++) {
		code = dist_to_code(dist + 1);
		bits = code >> 1;
		if (bits)
			bits--;

		/* Distance codes are stored on 5 bits reversed. The RFC
		 * doesn't state that they are reversed, but it's the only
		 * way it works.
		 */
		code = ((code & 0x01) << 4) | ((code & 0x02) << 2) |
		       (code & 0x04) |
		       ((code & 0x08) >> 2) | ((code & 0x10) >> 4);

		code += (dist & ((1 << bits) - 1)) << 5;
		fh_dist_table[dist] = (code << 5) + bits + 5;
		text_dist_table[dist] = text_dist(fh_dist_table[dist]);
	}
#endif
}

__attribute__((constructor))
static void __slz_initialize(void)
{
	__slz_prepare_dist_table(); // used by slz_rfc1951_encode()
}
