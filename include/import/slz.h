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

#ifndef _SLZ_H
#define _SLZ_H

#include <inttypes.h>
#include <stddef.h>

/*
 * =============================================================================
 *                                Common API
 *                     shared by slz and uslz APIs
 * =============================================================================
 */
void slz_make_crc_table(void); /* obsolete, not needed anymore */
uint32_t slz_crc32_by1(uint32_t crc, const unsigned char *buf, int len);
uint32_t slz_crc32_by4(uint32_t crc, const unsigned char *buf, int len);
uint32_t slz_adler32_by1(uint32_t crc, const unsigned char *buf, int len);
uint32_t slz_adler32_block(uint32_t crc, const unsigned char *buf, long len);

/*
 * =============================================================================
 *                                slz API (compression)
 * =============================================================================
 */

enum slz_state {
	SLZ_ST_INIT,  /* stream initialized */
	SLZ_ST_EOB,   /* header or end of block already sent */
	SLZ_ST_FIXED, /* inside a fixed huffman sequence */
	SLZ_ST_LAST,  /* last block, BFINAL sent */
	SLZ_ST_DONE,  /* BFINAL+EOB sent BFINAL */
	SLZ_ST_END    /* end sent (BFINAL, EOB, CRC + len) */
};

enum {
	SLZ_FMT_NONE = 0,/* default value, this way this ensure library users storing the
			  * the fmt value in a structure that is zero-initialized have no
	                  * FMT by default, plus they have a way to know if a fmt was
	                  * selected or not by comparing it with this value
			  */
	SLZ_FMT_GZIP,    /* RFC1952: gzip envelope and crc32 for CRC */
	SLZ_FMT_ZLIB,    /* RFC1950: zlib envelope and adler-32 for CRC */
	SLZ_FMT_DEFLATE, /* RFC1951: raw deflate, and no crc */
};

struct slz_stream {
#if defined(__SIZEOF_LONG__) && (__SIZEOF_LONG__ - 0 > 4)
	/* Note below: the queue never contains more than 32 bits for the
	 * 64-bit one, or 8 bits for the 32-bit one since contents are dumped
	 * as soon as they're large enough (32b for the 64-bit one, 8b-24b for
	 * the 32-bit one).
	 */
	uint64_t queue; /* last pending bits, LSB first, faster on 64-bit archs */
#else
	uint32_t queue; /* last pending bits, LSB first, faster on 32-bit archs */
#endif
	unsigned char *outbuf; /* set by encode() */
	uint32_t qbits; /* number of bits in queue, < 8 on 32-bit, < 32 on 64-bit */
	uint32_t state;   /* one of slz_state */
	uint8_t unused:2; /* free for future use */
	uint8_t format:2; /* SLZ_FMT_* */
	uint8_t level:4;  /* 0 = no compression, 1..15 = compression */
	uint8_t debt;    /* number of bits by which the fixed huffman encoding is
	                  * currently behind the equivalent stored blocks, see
	                  * SLZ_MAX_DEBT in slz.c
	                  */
	uint32_t crc32;
	uint32_t ilen;
};

/* Note about output buffer sizing: encode functions below do not take an
 * output len, instead the caller must provide a "large enough" output buffer.
 * When enabling direct queuing via SLZ_DIRECT_ENQUEUE24, the 3 bytes following
 * the end of the buffer may be written to, and the caller must take that into
 * account by allocating a buffer that is at least 3 bytes larger than needed.
 * And when using SLZ_DIRECT_ENQUEUE56, it's up to 7 extra bytes that may be
 * needed.
 */

/* Functions specific to rfc1951 (deflate) */
void slz_prepare_dist_table(); /* obsolete, not needed anymore */
long slz_rfc1951_encode(struct slz_stream *strm, unsigned char *out, const unsigned char *in, long ilen, int more);
int slz_rfc1951_init(struct slz_stream *strm, int level);
int slz_rfc1951_flush(struct slz_stream *strm, unsigned char *buf);
int slz_rfc1951_finish(struct slz_stream *strm, unsigned char *buf);

/* Functions specific to rfc1952 (gzip) */
long slz_rfc1952_encode(struct slz_stream *strm, unsigned char *out, const unsigned char *in, long ilen, int more);
int slz_rfc1952_send_header(struct slz_stream *strm, unsigned char *buf);
int slz_rfc1952_init(struct slz_stream *strm, int level);
int slz_rfc1952_flush(struct slz_stream *strm, unsigned char *buf);
int slz_rfc1952_finish(struct slz_stream *strm, unsigned char *buf);

/* Functions specific to rfc1950 (zlib) */
long slz_rfc1950_encode(struct slz_stream *strm, unsigned char *out, const unsigned char *in, long ilen, int more);
int slz_rfc1950_send_header(struct slz_stream *strm, unsigned char *buf);
int slz_rfc1950_init(struct slz_stream *strm, int level);
int slz_rfc1950_flush(struct slz_stream *strm, unsigned char *buf);
int slz_rfc1950_finish(struct slz_stream *strm, unsigned char *buf);

/* generic functions */

/* Initializes stream <strm>. It will configure the stream to use format
 * <format> for the data, which must be one of SLZ_FMT_*. The compression level
 * passed in <level> is set. This value can only be 0 (no compression) or 1
 * (compression) and other values will lead to unpredictable behaviour. The
 * function should always return 0.
 */
static inline int slz_init(struct slz_stream *strm, int level, int format)
{
	int ret;

	if (format == SLZ_FMT_GZIP)
		ret = slz_rfc1952_init(strm, level);
	else if (format == SLZ_FMT_ZLIB)
		ret = slz_rfc1950_init(strm, level);
	else { /* deflate for anything else */
		ret = slz_rfc1951_init(strm, level);
		strm->format = format;
	}
	return ret;
}

/* Encodes the block according to the format used by the stream. This means
 * that the CRC of the input block may be computed according to the CRC32 or
 * adler-32 algorithms. The number of output bytes is returned.
 */
static inline long slz_encode(struct slz_stream *strm, void *out,
                              const void *in, long ilen, int more)
{
	long ret;

	if (strm->format == SLZ_FMT_GZIP)
		ret = slz_rfc1952_encode(strm, (unsigned char *) out, (const unsigned char *) in, ilen, more);
	else if (strm->format == SLZ_FMT_ZLIB)
		ret = slz_rfc1950_encode(strm, (unsigned char *) out, (const unsigned char *) in, ilen, more);
	else /* deflate for other ones */
		ret = slz_rfc1951_encode(strm, (unsigned char *) out, (const unsigned char *) in, ilen, more);

	return ret;
}

/* Flushes pending bits and sends the trailer for stream <strm> into buffer
 * <buf> if needed. When it's done, the stream state is updated to SLZ_ST_END.
 * It returns the number of bytes emitted. The trailer consists in flushing the
 * possibly pending bits from the queue, the possible EOB and the final empty
 * block, rounding to the next byte, then 4 bytes for the CRC when doing
 * zlib/gzip, then another 4 bytes for the input length for gzip. That may
 * amount to 6+4+4 = 14 bytes, that the caller must ensure are available before
 * calling the function. Note that if the initial header was never sent, it
 * will be sent first as well (up to 10 extra bytes).
 */
static inline int slz_finish(struct slz_stream *strm, void *buf)
{
	int ret;

	if (strm->format == SLZ_FMT_GZIP)
		ret = slz_rfc1952_finish(strm, (unsigned char *) buf);
	else if (strm->format == SLZ_FMT_ZLIB)
		ret = slz_rfc1950_finish(strm, (unsigned char *) buf);
	else /* deflate for other ones */
		ret = slz_rfc1951_finish(strm, (unsigned char *) buf);

	return ret;
}

/* Flushes any pending data for stream <strm> into buffer <buf>, then emits an
 * empty literal block to byte-align the output, allowing to completely flush
 * the queue. Note that if the initial header was never sent, it will be sent
 * first as well (0, 2 or 10 extra bytes). This requires that the output buffer
 * still has this plus the 6 bytes needed to flush the queue, the possible EOB
 * and the (BFINAL,BTYPE) bits, plus 4 bytes for LEN+NLEN, or a total of 20
 * bytes in the worst case. The number of bytes emitted is returned. It is
 * guaranteed that the queue is empty on return. This may cause some overhead
 * by adding needless 5-byte blocks if called to often.
 */
static inline int slz_flush(struct slz_stream *strm, void *buf)
{
	int ret;

	if (strm->format == SLZ_FMT_GZIP)
		ret = slz_rfc1952_flush(strm, (unsigned char *) buf);
	else if (strm->format == SLZ_FMT_ZLIB)
		ret = slz_rfc1950_flush(strm, (unsigned char *) buf);
	else /* deflate for other ones */
		ret = slz_rfc1951_flush(strm, (unsigned char *) buf);

	return ret;
}

/*
 * =============================================================================
 *                                uslz API
 *                      (u stands for uncompress)
 * =============================================================================
 */

#define USLZ_FL_NONE        0x0000
#define USLZ_FL_GZIP        0x0001
#define USLZ_FL_ZLIB        0x0002
#define USLZ_FL_FINAL       0x0004   /* current block is the last one. */
#define USLZ_FL_COMPLETE    0x0008   /* last block is completely treated, marks end of the decompressed stream */
#define USLZ_FL_EXP_GZIP    0x0010   /* caller explicitly imposed the gzip envelope */
#define USLZ_FL_EXP_ZLIB    0x0020   /* caller explicitly imposed the zlib envelope */


enum uslz_stream_state {
	USLZ_ST_INITIAL = 0,  /* Initial state of a new state block (must be zero). */
	USLZ_ST_PARTIAL_HEADER,  /* Waiting for a second data byte. */
	USLZ_ST_HEADER,
	USLZ_ST_UNCOMPRESSED_LEN,
	USLZ_ST_UNCOMPRESSED_ILEN,
	USLZ_ST_UNCOMPRESSED_DATA,
	USLZ_ST_LITERAL_COUNT,
	USLZ_ST_DISTANCE_COUNT,
	USLZ_ST_CODELEN_COUNT,
	USLZ_ST_READ_CODE_LENGTHS,
	USLZ_ST_READ_LENGTHS,
	USLZ_ST_READ_LENGTHS_16,
	USLZ_ST_READ_LENGTHS_17,
	USLZ_ST_READ_LENGTHS_18,
	USLZ_ST_READ_SYMBOL,
	USLZ_ST_READ_LENGTH,
	USLZ_ST_READ_DISTANCE,
	USLZ_ST_READ_DISTANCE_RET,
	USLZ_ST_READ_DISTANCE_EXTRA,
	USLZ_ST_CHECK_CKSUM,
};

/* Width, in bits, of the direct lookup tables used to decode dynamic huffman
 * codes: one for the literal/length alphabet, one for the distance alphabet.
 * A code no longer than the table is decoded in a single load, a longer one
 * falls back to walking the tree, which costs one dependent load per bit.
 * Each table costs (1 << bits) * 2 bytes in *every* stream state, so this is
 * a direct trade between memory and decoding speed. Setting a width to zero
 * removes the corresponding table from the state along with the code that
 * uses it, which is the right thing for an application holding many
 * mostly-idle streams.
 *
 * These are deliberately not build options. They set the size and the layout
 * of struct uslz_stream, which is exported and instantiated by the calling
 * application, so a -D reaching only one of the two sides would leave the
 * library and the application disagreeing on the offset of every field past
 * fast_lit[]: the application would allocate 1568 bytes where the library
 * writes 2848, and nothing would detect it. Defining them unconditionally is
 * what prevents this, the definition below wins in every translation unit
 * that includes this file and a -D trying to change them only earns a
 * redefinition warning. The values can still be changed, but only here, and
 * doing so requires rebuilding the library *and* everything that instantiates
 * a stream.
 *
 * The performance below was measured on 8 different machines decoding a
 * silesia.tar compressed by gzip, with various combinations of literal length
 * bits and distance bits. The tests were lacking several optimizations that
 * were later added, so the numbers are off compared to current code, but their
 * ratios are still correct. The rates are expressed in MB/s of output stream
 * after decompression:
 *
 *   lit/dist  state    arl  spr sklx 7800 7v13 5105 atom   n1
 *     0/0     1728 B   237  186  178  232  174  124   50  124
 *     0/7     1984 B   285  223  199  282  206  144   56  143
 *     9/0     2752 B   379  286  313  329  239  175   66  182
 *     8/6     2368 B   433  342  323  378  273  190   69  198
 *     9/7     3008 B   508  402  381  419  303  222   76  229
 *    10/7     4032 B   547  437  403  445  324  238   78  245  <= current
 *    11/7     6080 B   556  446  409  451  325  245   79  250
 *
 * It's important not to forget that decompressing gzip requires to keep a
 * 32 kB sliding window, so the real sizes are those obtained by adding
 * 32768 to the values above. Once taken into account, and measures reported
 * as extra percentages compared to 0/0, the best choices appear more clearly:
 *
 *   lit/dist   memory    arl   spr  sklx  7800  7v13  5105  atom    n1
 *   0/0      34496 B    237   186   178   232   174   124    50   124  MB/s
 *   0/7        +0.7%   +20%  +20%  +12%  +21%  +18%  +17%  +11%  +15%
 *   9/0        +3.0%   +60%  +54%  +76%  +42%  +37%  +41%  +32%  +46%
 *   8/6        +1.9%   +83%  +84%  +82%  +63%  +57%  +54%  +37%  +59%
 *   9/7        +3.7%  +114% +117% +115%  +80%  +74%  +80%  +52%  +84%
 *   10/7       +6.7%  +131% +135% +127%  +92%  +86%  +93%  +56%  +97%  <= current
 *   11/7      +12.6%  +135% +140% +130%  +94%  +87%  +98%  +58% +101%
 *
 * Each step then costs a few percent of the per-stream footprint and buys
 * tens of points on that scale, until it stops:
 *
 *     8/6 -> 9/7     memory +1.8%    speed +14 to +33 points
 *     9/7 -> 10/7    memory +2.9%    speed  +5 to +18 points
 *    10/7 -> 11/7    memory +5.6%    speed  +1 to  +5 points
 *
 * 10/7 is where the curve bends, and that is what is set below: against no
 * table at all it buys between 56% (the Atom) and 135% (the Sapphire Rapids)
 * on a dynamic stream for 6.7% more memory per stream, while the step past it
 * costs twice as much memory for a tenth of the speed.
 *
 * An embedded application that decodes nothing but slz output is the
 * exception: those streams never look these tables up, so it can set both
 * widths to zero and get the 2304 bytes back.
 */
#define USLZ_FAST_BITS 10
#define USLZ_FAST_DBITS 7

#if USLZ_FAST_BITS > 15 || USLZ_FAST_DBITS > 15
#error "USLZ_FAST_BITS and USLZ_FAST_DBITS must not exceed 15, the longest deflate code"
#endif

/* decompression state */
struct uslz_stream {
	enum uslz_stream_state state;         /* parsing state, USLZ_ST_* */

	uint32_t crc;                         /* current crc value for the stream */
	uint16_t flags;                       /* USLZ_FL_* flags */
	unsigned int counter;                 /* generic counter */
	const unsigned char *in_ptr;          /* pointer to the next byte to read from
	                                       * input buffer
	                                       */
	const unsigned char *in_top;          /* pointer to one byte past the last byte
	                                       * of the input buffer
	                                       */
	unsigned int distance;
	unsigned char *out_base;              /* pointer to the beginning of the output
	                                       * buffer
	                                       */
	unsigned long out_max;                /* max number of bytes in ouput buffer */
	unsigned long dec_total;              /* total number of decoded bytes from stream */
	unsigned long dec_bofs;               /* offset used to read the current decoded block */
	unsigned long dec_bsize;              /* size of the current decoded block */

	unsigned char num_bits;               /* number of bits in the accumulator */

	unsigned char block_type;             /* compressed block type */
	unsigned int huff_index;              /* current index for pending huffman decoding
	                                       * attempt
	                                       */
	unsigned long bit_accum;              /* bit accumulator (used by GETBITS() macro) */
	unsigned int symbol;                  /* symbol code currently being processed */
	unsigned int last_value;              /* last value read for length / distance table
	                                       * construction
	                                       */
	unsigned int repeat_length;           /* repeated string length */

	unsigned int len;                     /* uncompressed block length */
	unsigned int ilen;                    /* uncompressed block inverted length */
	unsigned int nread;                   /* number of bytes copied from uncompressed block */

	/* literal_table: Code-to-symbol conversion table for the alphabet used
	 * for literals and length values.  Elements 0 and 1 correspond to a
	 * one-bit code of 0 or 1, respectively; other elements are linked
	 * (directly or indirectly) from these to represent the Huffman tree.
	 * The value of each element is:
	 *    - for terminal codes, the symbol corresponding to the code (a
	 *      nonnegative value);
	 *    - for nonterminal codes, the one's complement of the array index
	 *      corresponding to the code with a zero appended (the following
	 *      array element corresponds to the code with a one appended).
	 * For an alphabet of N symbols, a Huffman tree will have N-1 non-leaf
	 * nodes (including the root node, which is not represented in the
	 * array).  In the case of the literal/length alphabet, there are
	 * normally 286 symbols; however, the default (static) Huffman table
	 * uses a 288-symbol alphabet with two unused symbols, so we reserve
	 * enough space for that alphabet.
	 */
	short literal_table[288*2-2];
	/* Direct lookup table for the literal/length alphabet, indexed by the
	 * next USLZ_FAST_BITS bits of the stream. Same layout as
	 * fixed_huff_dec_table: the symbol in the upper bits and the code
	 * length in the low 4 bits, a length of zero meaning the code is
	 * longer than the table and literal_table[] has to be walked.
	 */
	uint16_t fast_lit[1 << USLZ_FAST_BITS];

	/* same for the distance alphabet */
	uint16_t fast_dist[1 << USLZ_FAST_DBITS];

	union {
		/* Code-to-symbol conversion table for the alphabet used for
		 * distances.  This alphabet consists of 32 symbols, 2 of
		 * which are unused.
		 */
		short distance_table[32*2-2];
		/* we may need to hold up to 10 bytes to detect the format
		 * (zlib/gzip/raw) before starting to decode the stream, thus
		 * we use the distance table memory which is only used when we
		 * start decoding.
		 */
		struct {
			unsigned char buf[10];
			unsigned char gzip_flags;
			int buf_len;
		} hdr_detect;
	};
	short codelen_table[19*2-2];          /* Code-to-symbol conversion table for the alphabet
	                                       * used for code lengths.
	                                       */
	unsigned int literal_count;           /* number of literal codes in the Huffman table
	                                       * (HLIT in RFC 1951)
	                                       */
	unsigned int distance_count;          /* number of distance codes in the Huffman table
	                                       * (HDIST in RFC 1951)
	                                       */
	unsigned int codelen_count;           /* number of codelen codes in the Huffman table
	                                       * used for decompressing the main Huffman tables
	                                       * (HCLEN in RFC 1951)
	                                       */
	unsigned char literal_len[288];       /* code length for the symbol in literal_table */
	unsigned char distance_len[32];       /* code length for the symbol in distance table */
	unsigned char codelen_len[19];        /* code length for the symbol in codelen table */
};

/* list of possible return values for uslz_decode() */
enum uslz_decode_ret {
	USLZ_DECODE_SUCCESS,
	USLZ_DECODE_OUT_OF_SPACE,
	USLZ_DECODE_OUT_OF_DATA,
	USLZ_DECODE_E_INVALID_ARGUMENT,
	USLZ_DECODE_E_BAD_COMP_METHOD,
	USLZ_DECODE_E_BAD_CRC,
	USLZ_DECODE_E_DICT,
	USLZ_DECODE_E_OUT_BUFFER,
	USLZ_DECODE_E_GEN_HUFF,
	USLZ_DECODE_E_DISTANCE,
	USLZ_DECODE_E_INVALID_SYMBOL,
	USLZ_DECODE_E_INVALID_STATE,
	USLZ_DECODE_E_INVALID_BLOCK_CODE,
	USLZ_DECODE_E_INVALID_DATA,
	USLZ_DECODE_E_CORRUPT,
	USLZ_DECODE_E_UNEXPECTED,
};

int uslz_init(struct uslz_stream *strm, unsigned char *output_buffer, long output_size);
int uslz_init_fmt(struct uslz_stream *strm, unsigned char *output_buffer, long output_size,
                  int format);
enum uslz_decode_ret uslz_decode(struct uslz_stream *state,
                                 const unsigned char *compressed_data, long compressed_size,
                                 unsigned char **decoded_data, long *decoded_size,
                                 long *consumed_bytes, uint32_t *crc_ret);

#endif
