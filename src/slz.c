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
 * table as we need to recompute it.
 */
#ifndef PRECOMPUTE_TABLES
static uint32_t fh_dist_table[32768];
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

/* Enables growing a match backwards over the literals that are still pending,
 * see slz_rfc1951_encode(). Costs a little CPU on every match and gains about
 * 1% of output. Tests show that matching up to 2 bytes brings almost optimal
 * results at minimal extra cost, and that compression gains at 1 byte are
 * higher than the CPU increase they cause, and tend to result in higher
 * compression speed due to the savings on encoding. The only way to disable
 * this optimization is to comment out this line.
 */
#define SLZ_BACKWARD_MATCH ((const int[]){ 0, 1, 2, 8 })

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
 * few which provide almost optimal results on various different pages.
 */
static inline uint32_t slz_hash(uint32_t a)
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
	return a >> (32 - SLZ_HASH_BITS);
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

/* Using long because faster on 64-bit (can save one shift) */
static inline void send_huff(struct slz_stream *__restrict strm, unsigned long code)
{
	uint32_t bits;

	code = fixed_huff[code];
	bits = code & 15;
	code >>= 4;
	enqueue24(strm, code, bits);
}

static inline void send_eob(struct slz_stream *__restrict strm)
{
	enqueue8(strm, 0, 7); // direct encoding of 256 = EOB (cf RFC1951)
}

/* copies <len> litterals from <buf>. at once. <len> must not be null and must
 * be lower than or equal to 65535, which can be guaranteed when using
 * SLZ_LITERAL_SKIP with limited literal lengths. <more> indicates that there
 * are data past buf + <len>. Only supports fixed encoding.
 */
__attribute__((unused))
static void copy_lit_small(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more)
{
	int eob_shift = (strm->state == SLZ_ST_EOB) ? 0 : 7;

	/* explanation: if there is no EOB yet, we have to send one.
	 * It's 0 encoded over 7 bits. Then we have to copy !more into BFINAL
	 * (one bit), and 00 in btype (two bits). Finally we pad to the next
	 * byte. So we add 0 or 7 bits for EOB, followed by 3 then by 0 to 7
	 * bits for alignment. That's 3 to 17 bits.
	 */
	enqueue24(strm, (!more) << eob_shift, 3 + eob_shift + (7 & -(3 + eob_shift + strm->qbits))); // EOB + BFINAL + BTYPE
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

/* copies <len> litterals from <buf>. <more> indicates that there are data past
 * buf + <len>. <len> must not be null.
 */
__attribute__((unused))
static void copy_lit(struct slz_stream *__restrict strm, const void *buf, uint32_t len, int more)
{
	uint32_t len2;

	if (len <= 65535)
		return copy_lit_small(strm, buf, len, more);

	if (strm->state != SLZ_ST_EOB)
		send_eob(strm);

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

/* copies <len> litterals from <buf>. <more> indicates that there are data past
 * buf + <len>. <len> must not be null.
 */
static void copy_lit_huff(struct slz_stream *__restrict strm, const unsigned char *buf, uint32_t len, int more)
{
	uint32_t pos;

	/* This ugly construct limits the mount of tests and optimizes for the
	 * most common case (more > 0).
	 */
	if (strm->state == SLZ_ST_EOB) {
	eob:
		strm->state = more ? SLZ_ST_FIXED : SLZ_ST_LAST;
		enqueue8(strm, 2 + !more, 3); // BFINAL = !more ; BTYPE = 01
	}
	else if (!more) {
		send_eob(strm);
		goto eob;
	}

	pos = 0;
	do {
		send_huff(strm, buf[pos++]);
	} while (pos < len);
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

/* Maximum number of bits the fixed huffman encoding is allowed to be behind
 * the equivalent stored blocks before the encoder stops trusting the local
 * decisions above and falls back to stored blocks only (see <debt> in
 * slz_rfc1951_encode_blk()). This bounds by 25 bytes the amount by which a
 * stream may exceed the size of the same data sent as stored blocks. It must
 * be large enough not to trigger on regular data, where the debt oscillates
 * around zero: measured on the 212 MB silesia.tar, no value from 196 up
 * changes the output by a single byte, while 52 costs 2331 bytes and 192
 * costs 615. It must also leave room for one last group of literals in the
 * 8-bit counter that holds the debt, which is why it may not exceed
 * 255 - (SLZ_SWITCH_COST - 1) = 204.
 */
#define SLZ_MAX_DEBT        200

/* Compresses <ilen> bytes from <in> into <out> according to RFC1951. The
 * output result may be up to 5 bytes larger than the input for each 65535
 * nput bytes, to which 2 extra bytes may be added to send the last chunk due
 * to BFINAL+EOB encoding (10 bits) when <more> is not set. This is a property
 * of the whole stream, not of each call: since up to 31 bits are retained in
 * the queue from one call to the next, a single call may emit up to 5 bytes
 * more than its own share, which the following ones will not emit. The caller
 * is responsible for ensuring there is enough room in the output buffer for
 * this. The amount of output bytes is returned, and no CRC is computed.
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
 */
static inline __attribute__((always_inline))
long _slz_rfc1951_encode(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more, int level)
{
	long rem = ilen;
	unsigned long pos = 0;
	unsigned long last;
	const unsigned char *lastp;
	uint32_t word = 0;
	long mlen;
	uint32_t h;
	uint64_t ent;

#if SLZ_LITERAL_SKIP
	long skip_ratio = 0;
#endif
	uint32_t plit = 0;
	uint32_t bit9 = 0;
	uint32_t dist, code;
	union ref refs[1 << SLZ_HASH_BITS];

	if (__builtin_expect(!strm->level, 0)) {
		/* force to send as literals (eg to preserve CPU) */
		strm->outbuf = out;
		if (ilen)
			copy_lit(strm, in, ilen, more);
		goto leave;
	}

	reset_refs(refs, sizeof(refs));

	strm->outbuf = out;

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

#ifdef FIND_OPTIMAL_MATCH
		/* Experimental code to see what could be saved with an ideal
		 * longest match lookup algorithm. This one is very slow but
		 * scans the whole window. In short, here are the savings :
		 *   file        orig     fast(ratio)  optimal(ratio)
		 *  README       5185    3419 (65.9%)    3165 (61.0%)  -7.5%
		 *  index.html  76799   35662 (46.4%)   29875 (38.9%) -16.3%
		 *  rfc1952.c   29383   13442 (45.7%)   11793 (40.1%) -12.3%
		 *
		 * Thus the savings to expect for large files is at best 16%.
		 *
		 * A non-colliding hash gives 33025 instead of 35662 (-7.4%),
		 * and keeping the last two entries gives 31724 (-11.0%).
		 */
		unsigned long scan;
		int saved = 0;
		int bestpos = 0;
		int bestlen = 0;
		int firstlen = 0;
		int max_lookup = 2; // 0 = no limit

		for (scan = pos - 1; scan < pos && (unsigned long)(pos - scan - 1) < 32768; scan--) {
			int len;

			if (*(uint32_t *)(in + scan) != word)
				continue;

			len = memmatch(in + pos, in + scan, rem);
			if (!bestlen)
				firstlen = len;

			if (len > bestlen) {
				bestlen = len;
				bestpos = scan;
			}
			if (!--max_lookup)
				break;
		}
		if (bestlen) {
			//printf("pos=%d last=%d bestpos=%d word=%08x ent=%08x len=%d\n",
			//       (int)pos, (int)last, (int)bestpos, (int)word, (int)ent, bestlen);
			last = bestpos;
			ent  = word;
			saved += bestlen - firstlen;
		}
		//fprintf(stderr, "first=%d best=%d saved_total=%d\n", firstlen, bestlen, saved);
#endif

		if ((uint32_t)ent != word) {
		send_as_lit:
			rem--;
			plit++;
			bit9 += ((unsigned char)word >= 144);
			pos++;

			/* Incompressible data: once enough literals have accumulated
			 * without a single match, stop looking for a while and just
			 * dump what follows as literal blocks, doubling the amount
			 * skipped each time so that a long incompressible block
			 * costs less and less to walk over. A match resets it.
			 */
#if SLZ_LITERAL_SKIP
			if (level <= 1 && !(plit & 63)) {
				/* be careful: plit+skip must never be >= 65535 */
				long skip;
				skip_ratio = (skip_ratio * 2 + 1) & 255; // capped exponential: 0,1,3,7,... and stays at 255
				skip = rem >= skip_ratio * 32 ? skip_ratio * 32 : rem;
				copy_lit_small(strm, in + pos - plit, plit + skip, more || skip < rem);
				pos += skip;
				rem -= skip;
				plit = 0;
# ifndef UNALIGNED_FASTER
				/* we'll need to update the current word since we skipped some bytes */
				goto reload_word;
# else
				continue;
# endif
			}
			else if (level == 2 && !(plit & 2047)) {
				/* be careful: plit+skip must never be >= 65535 */
				long skip = rem >= skip_ratio * 4096 ? skip_ratio * 4096 : rem;
				skip_ratio = (skip_ratio * 2 + 1) & 7; // capped exponential: 0,1,3,7 and stays at 7
				copy_lit_small(strm, in + pos - plit, plit + skip, more || skip < rem);
				pos += skip;
				rem -= skip;
				plit = 0;
# ifndef UNALIGNED_FASTER
				/* we'll need to update the current word since we skipped some bytes */
				goto reload_word;
# else
				continue;
# endif
			}
			else if (level >= 3) // no literal skip at levels >= 3
#endif
			{
				/* either no literal_skip at build time, or high enough level */
				if (__builtin_expect(plit == 0xffc0, 0)) {
					copy_lit_small(strm, in + pos - plit, plit, 1);
					plit = 0;
				}
			}
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

		if (bit9 >= 52 && mlen < 6)
			goto send_as_lit;

		/* compute the output code, its size and the length's size in
		 * bits to know if the reference is cheaper than literals.
		 */
		code = len_fh[mlen];

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
		if ((strm->state == SLZ_ST_EOB || strm->debt >= SLZ_MAX_DEBT) &&
		    (dist & 0x1f) + (code >> 16) + SLZ_SWITCH_COST > 8 * mlen)
			goto send_as_lit;

#if defined(SLZ_BACKWARD_MATCH)
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
		 * It's worth noting that we *do not* fixup <bit9> if a match
		 * is found, as this would be too complicated and counter-
		 * productive. This means that literals that were finally
		 * encoded might still count towards the budget limit, but this
		 * is not dramatic and keeps us on the safe side.
		 *
		 * The result of the search is to only touch <back> that will be
		 * used all along in all operations. Multiple attempts have shown
		 * that it's both easier and faster this way than changing then
		 * rolling back offsets when we finally give up and send_as_lit.
		 */
		if (__builtin_expect(plit != 0, 1) &&
		    (last >= MAX_C(sizeof(long), SLZ_BACKWARD_MATCH[level]))) {
			long bmax = MIN(plit, 8); // keep it at 8, always faster
			long back = 0;

			if (bmax > 258 - mlen)
				bmax = 258 - mlen;

#if defined(UNALIGNED_LE_OK)
			if (SLZ_BACKWARD_MATCH[level] == 2) { // 43.32%, best speed vs savings
				uint16_t x = *(uint16_t *)&in[pos - 2] ^ *(uint16_t *)(lastp - 2);
				back = x & 0xff00 ? 0 : x ? 1 : 2;
				if (back > bmax)
					back = bmax;
			} else if (SLZ_BACKWARD_MATCH[level] == 3 || SLZ_BACKWARD_MATCH[level] == 4) { // 32 bits: 43.31% or 43.30%
				uint32_t x = *(uint32_t *)&in[pos - 4] ^ *(uint32_t *)(lastp - 4);
				back = x & 0xffff0000u ?
					x & 0xff000000u ? 0 : 1 :
					x & 0xffffff00u ? 2 :
					x ? 3 : SLZ_BACKWARD_MATCH[level]; // 3 or 4, test eliminated at 3
				if (back > bmax)
					back = bmax;
			} else if (SLZ_BACKWARD_MATCH[level] == 8) { // 64 bits: 43.30%
				uint64_t x = *(uint64_t *)&in[pos - 8] ^ *(uint64_t *)(lastp - 8);
				back = x ? (__builtin_clzll(x) >> 3) : 8;
				if (back > bmax)
					back = bmax;
			} else
#endif
			if (SLZ_BACKWARD_MATCH[level] == 1) { // single-byte match: 43.39%
				if (in[pos - 1] == lastp[-1])
					back++;
				if (back > bmax)
					back = bmax;
			}
			else { /* unaligned not supported or match != 1/2/3/4/8 */
				while (back < bmax && in[pos - back - 1] == lastp[-back - 1])
					back++;
			}

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
				code = len_fh[mlen];
			}
		}
#endif // SLZ_BACKWARD_MATCH // otherwise 43.83%

		/* first, copy pending literals */
		if (plit) {
			/* Huffman encoding requires 9 bits for octets 144..255, so this
			 * is a waste of space for binary data. Switching between Huffman
			 * and no-comp then huffman consumes 52 bits (7 for EOB + 3 for
			 * block type + 7 for alignment + 32 for LEN+NLEN + 3 for next
			 * block. Only use plain literals if there are more than 52 bits
			 * to save then, or if we're already too much in debt, in which
			 * case only stored blocks may be emitted, see <debt> below.
			 * Literals sent in a stored block do not cost anything extra,
			 * only those sent in huffman mode add to the debt.
			 */
			if (bit9 >= SLZ_SWITCH_COST || strm->debt >= SLZ_MAX_DEBT)
				copy_lit_small(strm, in + pos - plit, plit, 1);
			else {
				copy_lit_huff(strm, in + pos - plit, plit, 1);
				strm->debt += bit9;
			}

			plit = 0;
		}

#if SLZ_LITERAL_SKIP
		skip_ratio = 0;
#endif
		/* use mode 01 - fixed huffman */
		if (strm->state == SLZ_ST_EOB) {
			strm->state = SLZ_ST_FIXED;
			enqueue8(strm, 0x02, 3); // BTYPE = 01, BFINAL = 0
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

		/* <bit9> only measures the current group of literals, which is
		 * what the decisions above compare against, and it restarts
		 * from zero after each reference. <debt> accumulates how much
		 * the literals already emitted in fixed huffman mode are still
		 * costing us compared to the same bytes sent as stored blocks,
		 * and is what bounds the growth of the output: the reference
		 * just used (code>>16)+(dist&0x1f) bits in place of the 8*mlen
		 * bits these bytes would have taken as literals, so it repays
		 * that much of the debt. Without this, a stream made of series
		 * of 9-bit literals interleaved with cheap references would
		 * never reach the threshold above and would keep inflating. The
		 * debt is saturated at zero since we're not interested in
		 * accumulating credits. The update is unconditional because a
		 * test on a debt that is often null but not always turns into
		 * a mispredicted branch on binary data.
		 */
		code = strm->debt + (code >> 16) + (dist & 0x1f);
		strm->debt = (code > 8 * (uint32_t)mlen) ? code - 8 * (uint32_t)mlen : 0;

		bit9 = 0;
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
			bit9 += ((unsigned char)in[pos++] >= 144);
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

		if (bit9 >= cost || strm->debt >= SLZ_MAX_DEBT)
			copy_lit_small(strm, in + pos - plit, plit, more);
		else
			copy_lit_huff(strm, in + pos - plit, plit, more);

		plit = 0;
	}
 leave:
	strm->ilen += ilen;
	return strm->outbuf - out;
}

static __attribute__((noinline))
long _slz_rfc1951_encode_lev1(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	return _slz_rfc1951_encode(strm, out, in, ilen, more, 1);
}

static __attribute__((noinline))
long _slz_rfc1951_encode_lev2(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	return _slz_rfc1951_encode(strm, out, in, ilen, more, 2);
}

static __attribute__((noinline))
long _slz_rfc1951_encode_lev3(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	return _slz_rfc1951_encode(strm, out, in, ilen, more, 3);
}

long slz_rfc1951_encode(struct slz_stream *__restrict strm, unsigned char *out, const unsigned char *in, long ilen, int more)
{
	if (strm->level <= 1)
		return _slz_rfc1951_encode_lev1(strm, out, in, ilen, more);
	else if (strm->level <= 2)
		return _slz_rfc1951_encode_lev2(strm, out, in, ilen, more);
	else
		return _slz_rfc1951_encode_lev3(strm, out, in, ilen, more);
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
	strm->crc32 = 0;
	strm->ilen  = 0;
	strm->qbits = 0;
	strm->queue = 0;
	strm->debt  = 0;
	return 0;
}

/* Flushes any pending data for stream <strm> into buffer <buf>, then emits an
 * empty literal block to byte-align the output, allowing to completely flush
 * the queue. This requires that the output buffer still has the size of the
 * queue (up to 31 bits when using the 64-bit queue), plus a possible EOB (7
 * bits), plus (BFINAL,BTYPE) (3 bits), which once rounded up to the next byte
 * make 6 bytes, plus 4 bytes for LEN+NLEN, or a total of 10 bytes in the worst
 * case. If the stream was already completed by a previous call to encode()
 * with <more> cleared, the last block is simply terminated and the output
 * aligned, since nothing may be appended to a finished stream. The number of
 * bytes emitted is returned. It is guaranteed that the queue is empty on
 * return. This may cause some overhead by adding needless 5-byte blocks if
 * called to often.
 */
int slz_rfc1951_flush(struct slz_stream *strm, unsigned char *buf)
{
	strm->outbuf = buf;

	/* The queue is always empty on INIT, DONE, and END */
	if (!strm->qbits)
		return 0;

	/* we may need to terminate a huffman output. Lit is always in EOB state */
	if (strm->state != SLZ_ST_EOB) {
		strm->state = (strm->state == SLZ_ST_LAST) ? SLZ_ST_DONE : SLZ_ST_EOB;
		send_eob(strm);
	}

	if (strm->state == SLZ_ST_DONE) {
		/* The block we've just terminated was already marked final, so
		 * the deflate stream is complete and nothing may be appended to
		 * it: an extra block here would be located past the end of the
		 * stream and would shift the gzip or zlib trailer that the
		 * caller is about to emit. Aligning the output is all we have
		 * to do, and it's all that's left to do for finish() as well.
		 */
		flush_bits(strm);
		return strm->outbuf - buf;
	}

	/* send BFINAL=0 and BTYPE=00 (lit) */
	enqueue8(strm, 0, 3);
	flush_bits(strm);             // emit pending bits
	copy_32b(strm, 0xFFFF0000U);  // len=0, nlen=~0

	/* Now the queue is empty, EOB was sent, and a zero-byte block was sent
	 * to byte-align the output. The last state reflects all this. Let's
	 * just return the number of bytes added to the output buffer.
	 */
	return strm->outbuf - buf;
}

/* Flushes any pending for stream <strm> into buffer <buf>, then sends BTYPE=1
 * and BFINAL=1 if needed. The stream ends in SLZ_ST_DONE. It returns the number
 * of bytes emitted. The trailer consists in flushing the possibly pending bits
 * from the queue (up to 31 bits when using the 64-bit queue), then possibly
 * EOB (7 bits), then 3 bits, EOB, a rounding to the next byte, which amounts
 * to a total of 6 bytes max, that the caller must ensure are available before
 * calling the function.
 */
int slz_rfc1951_finish(struct slz_stream *strm, unsigned char *buf)
{
	strm->outbuf = buf;

	if (strm->state == SLZ_ST_FIXED || strm->state == SLZ_ST_LAST) {
		strm->state = (strm->state == SLZ_ST_LAST) ? SLZ_ST_DONE : SLZ_ST_EOB;
		send_eob(strm);
	}

	if (strm->state != SLZ_ST_DONE) {
		/* send BTYPE=1, BFINAL=1 */
		enqueue8(strm, 3, 3);
		send_eob(strm);
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
	strm->crc32  = 0;
	strm->ilen   = 0;
	strm->qbits  = 0;
	strm->queue  = 0;
	strm->debt   = 0;
	return 0;
}

/* Flushes any pending data for stream <strm> into buffer <buf>, then emits an
 * empty literal block to byte-align the output, allowing to completely flush
 * the queue. Note that if the initial header was never sent, it will be sent
 * first as well (10 extra bytes). This requires that the output buffer still
 * has this plus the 6 bytes needed to flush the queue, the possible EOB and
 * the (BFINAL,BTYPE) bits, plus 4 bytes for LEN+NLEN, or a total of 20 bytes
 * in the worst case. The number of bytes emitted is returned. It is guaranteed
 * that the queue is empty on return. This may cause some overhead by adding
 * needless 5-byte blocks if called to often.
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
 * bytes for the input length. That may amount to 6+4+4 = 14 bytes, that the
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
	strm->crc32  = 1; // rfc1950/zlib starts with initial crc=1
	strm->ilen   = 0;
	strm->qbits  = 0;
	strm->queue  = 0;
	strm->debt   = 0;
	return 0;
}

/* Flushes any pending data for stream <strm> into buffer <buf>, then emits an
 * empty literal block to byte-align the output, allowing to completely flush
 * the queue. Note that if the initial header was never sent, it will be sent
 * first as well (2 extra bytes). This requires that the output buffer still
 * has this plus the 6 bytes needed to flush the queue, the possible EOB and
 * the (BFINAL,BTYPE) bits, plus 4 bytes for LEN+NLEN, or a total of 12 bytes
 * in the worst case. The number of bytes emitted is returned. It is guaranteed
 * that the queue is empty on return. This may cause some overhead by adding
 * needless 5-byte blocks if called to often.
 */
int slz_rfc1950_flush(struct slz_stream *strm, unsigned char *buf)
{
	int sent = 0;

	if (__builtin_expect(strm->state == SLZ_ST_INIT, 0))
		sent = slz_rfc1950_send_header(strm, buf);

	sent += slz_rfc1951_flush(strm, buf + sent);
	return sent;
}

/* Flushes pending bits and sends the gzip trailer for stream <strm> into
 * buffer <buf>. When it's done, the stream state is updated to SLZ_ST_END. It
 * returns the number of bytes emitted. The trailer consists in flushing the
 * possibly pending bits from the queue, the possible EOB and the final empty
 * block, rounding to the next byte, then 4 bytes for the CRC. That may amount
 * to 6+4 = 10 bytes, that the caller must ensure are available before calling
 * the function. Note that if the initial header was never sent, it will be
 * sent first as well (2 extra bytes).
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
	}
#endif
}

__attribute__((constructor))
static void __slz_initialize(void)
{
	__slz_prepare_dist_table(); // used by slz_rfc1951_encode()
}
