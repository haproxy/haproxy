/*
 * Copyright (C) 2026 HAProxy Technologies
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
 *
 * Credits to Andrew Church <achurch@achurch.org> for providing
 * https://achurch.org/tinflate.c -- tiny inflate library as public domain.
 * uslz (slz decompression) implementation was greatly inspired from tinflate
 * library by Andrew Church.
 */

#include <stdio.h>
#include <string.h>
#include "import/slz.h"
#include "import/slz-prv.h"
#include "import/slz-tables.h"

/* if PRECOMPUTE_TABLES not set, then tables.h does not provide
 * fixed_huff_dec_table table as we need to recompute it.
 */
#ifndef PRECOMPUTE_TABLES
static uint16_t fixed_huff_dec_table[512];
#endif // ifndef PRECOMPUTE_TABLES

/* size of a single CRC block to perform CRC computation
 * in bursts of CRC_BLOCK bytes, must be < output buffer size
 * to have effect.
 */
#ifndef CRC_BLOCK
  #define CRC_BLOCK 4096
#endif /* CRC_BLOCK */

/*
 * gen_huffman_table:  Generate a Huffman table from a set of code lengths,
 * using the algorithm described in RFC 1951.  The table format is as
 * described for the literal_table[] array in uslz_decode_block().
 *
 * Parameters:
 *              symbols: Number of symbols in the alphabet.
 *              lengths: Bit lengths of the codes for each symbol
 *                          (0 = symbol not used).
 *     allow_no_symbols: True (nonzero) if a table with no symbols (i.e.,
 *                          no nonzero code lengths) should be allowed.
 *                table: Array into which the Huffman table will be stored.
 * Return value:
 *     Nonzero on success, zero on failure (erroneous data).
 * Preconditions:
 *     symbols > 0 && symbols <= 288
 *     lengths != NULL
 *     table != NULL
 * Notes:
 *     lengths[] must contain the number of elements specified by
 *     "symbols"; table[] must have enough room for symbols*2-2 elements,
 *     or for 2 elements if "symbols" is 1; and all code lengths must be
 *     no greater than 15.
 */
static int gen_huffman_table(unsigned int symbols,
                             const unsigned char *lengths,
                             int allow_no_symbols,
                             short *table)
{
	unsigned short length_count[16];
	unsigned short total_count;
	unsigned short first_code[16];
	unsigned int index;

	unsigned int i;

	/* Count the number of symbols that have each code length.  If an
	 * invalid code length is found, abort.
	 */
	for (i = 0; i < 16; i++)
		length_count[i] = 0;

	for (i = 0; i < symbols; i++) {
		/* We don't count codes of length 0 since they don't participate
		 * in forming the tree.  (It's also convenient to have
		 * length_count[0] == 0 for the code range calculation below.)
		 */
		if (lengths[i] > 0) {
			length_count[lengths[i]]++;
		}
	}

	/* Check for a degenerate table of zero or one symbol.
	 * total_count is count of all symbols with non-zero lengths.
	 */
	total_count = 0;
	for (i = 1; i < 16; i++)
		total_count += length_count[i];

	if (total_count == 0)
		return allow_no_symbols;
	else if (total_count == 1) {
		for (i = 0; i < symbols; i++) {
			if (lengths[i] != 0) {
				table[0] = i;
				table[1] = i;
			}
		}
		return 1;
	}

	/* Determine the first code value for each code length, and make sure
	 * the code space is completely filled as required.  Note that we rely
	 * on length_count[0] being left at 0 above.
	 */
	first_code[0] = 0;
	for (i = 1; i < 16; i++) {
		first_code[i] = (first_code[i-1] + length_count[i-1]) << 1;
		if (first_code[i] + length_count[i] > (unsigned short)1<<i) {
			/* Too many symbols of this code length -- we can't form a
			 * valid Huffman tree.
			 */
			return 0;
		}
	}

	if (first_code[15] + length_count[15] != (unsigned short)1<<15) {
		/* The Huffman tree is incomplete and thus invalid. */
		return 0;
	}

	/* Create the Huffman table, assigning codes to symbols sequentially
	 * within each code length.  If the code value or table overflows
	 * (presumably due to invalid data), abort.
	 *
	 * index is current table index.  This is guaranteed (modulo hardware
	 * errors or memory corruption while this routine is running) to never
	 * exceed symbols*2-2 entries, so its value is not bound-checked below.
	 * This can be seen by simple induction:  Given a code alphabet of N
	 * symbols (N >= 2), adding a new symbol N+1 involves taking a
	 * previously terminal code and splitting it into two codes, one with
	 * a 0 appended and the other with a 1 appended.  This is equivalent
	 * to converting the corresponding leaf node of the Huffman tree to
	 * an internal node and adding two new leaf nodes as children, thus
	 * increasing the total node count by 2.  Since the table[] array
	 * corresponds exactly to the Huffman tree, and index is incremented
	 * exactly once for each node, index can never exceed the total number
	 * of nodes in the tree (2N-2 for N symbols), which is also the
	 * required length of the array.
	 */
	index = 0;

	for (i = 1; i < 16; i++) {
		unsigned int code_limit;
		unsigned int next_code;
		unsigned int next_index;
		unsigned int j;

		/* Maximum code value for this code length, plus one. */
		code_limit = 1U << i;

		/* First free code after all symbols with this code length
		 * have been assigned.
		 */
		next_code = first_code[i] + length_count[i];

		/* First array index for the next higher code length. */
		next_index = index + (code_limit - first_code[i]);

		/* Fill in any symbols of this code length. */
		for (j = 0; j < symbols; j++) {
			if (lengths[j] == i) {
				table[index] = j;
				index += 1;
			}
		}

		/* Fill in remaining (internal) nodes for this length. */
		for (j = next_code; j < code_limit; j++) {
			table[index] = ~next_index;
			index += 1;
			next_index += 2;
		}
	}  /* for each code length */

	/* Return success. */
	return 1;
}

/* updates crc for the current <state> inflate stream, chooses the proper
 * crc computation function according to the format used in the stream.
 */
static inline void uslz_update_crc(struct uslz_stream *state, const unsigned char *buf, long len)
{
	if ((state->flags & USLZ_FL_GZIP))
		state->crc = update_crc(state->crc, buf, len);
	else if ((state->flags & USLZ_FL_ZLIB))
		state->crc = slz_adler32_block(state->crc, buf, len);
	// else: raw format doesn't require crc
}

/* accumulate 8 bits (a full byte) from <in_ptr> in <bit_accum> and update
 * <bit_accum> accordingly.
 *
 * Returns 1 on success and 0 if more data is needed.
 */
static inline int bit_accumulate(const unsigned char **in_ptr, const unsigned char *in_top, unsigned char *num_bits, uint64_t *bit_accum)
{
	if (*in_ptr >= in_top)
		return 0;
	*bit_accum |= (uint64_t)(*in_ptr)[0] << *num_bits;
	*num_bits += 8;
	(*in_ptr)++;
	return 1;
}

/* classic way of decoding symbol using huffman tree traversal.
 * huffman tree is represented by <table>, where even indexes represent
 * left branch, while odd indexes right branch.
 *
 * Cannot fail, returns 0 if it needs more data and 1 when decoding is
 * complete. (In case of error a wrong symbol will be returned, that's it)
 *
 * The decoded symbol is stored in <var>.
 */
static inline int gethuff(unsigned int *huff_index,
                                             const unsigned char **in_ptr, const unsigned char *in_top,
                                             unsigned char *num_bits, uint64_t *bit_accum,
                                             unsigned int *var, short *table)
{
	unsigned int index;
	unsigned int bits;
	unsigned long bit_follow;

	index = *huff_index;
	bits = *num_bits;
	bit_follow = *bit_accum;

	for (;;) {
		if (bits == 0) {
			if (*in_ptr >= in_top) {
				*num_bits = bits;
				*bit_accum = bit_follow;
				*huff_index = index;
				return 0;
			}
			bit_follow |= (unsigned long) (*in_ptr)[0] << bits;
			bits += 8;
			(*in_ptr)++;
		}

		index += (bit_follow & 1);
		bit_follow >>= 1;
		bits--;
		if (table[index] >= 0) {
			break;
		}
		index = ~(table[index]);
	}

	*num_bits = bits;
	*bit_accum = bit_follow;
	*var = table[index];
	*huff_index = 0;

	return 1;
}

/* when decoding static/fixed huffman (we must be sure of that before
 * using this func), we can leverage the fixed huff decoding table to
 * perform direct up to 9 bits lookups (possibly less if no more data
 * available).
 *
 * As with gethuff(), returns 1 when decoding is complete and 0 if it
 * needs more input data.
 */
static inline int gethuff_fixed(const unsigned char **in_ptr, const unsigned char *in_top,
                                                   unsigned char *num_bits, uint64_t *bit_accum,
                                                   unsigned int *var)
{
	unsigned long bit_follow;
	unsigned int bits;
	char bits_needed = 7;
	short idx = 0;

	bits = *num_bits;
	bit_follow = *bit_accum;

	/* static huffman codes are minimum 7bits long and max 9bits long */
	while (1) {
		if (bits < bits_needed) {
			if (*in_ptr >= in_top) {
				*num_bits = bits;
				*bit_accum = bit_follow;
				return 0;
			}
			bit_follow |= (unsigned long) (*in_ptr)[0] << bits;
			bits += 8;
			(*in_ptr)++;
		}
		if (bits < 9) {
			/* we don't have enough bits to perform 9bits lookup, but
			 * maybe there is no more data available, so we must first
			 * check if we could match an entry with currently available
			 * bits. Hopefully fixed_huff_dec_table is padded, so it is
			 * supported to perform lookup with less bits. However we
			 * ensure that we match with a code of the same or smaller
			 * length to prevent mismatch.
			 */
			idx = (bit_follow & ((1 << bits) - 1));
			if ((fixed_huff_dec_table[idx] & 0xF) > bits) {
				/* no match found with <bits>, so there must be
				 * data available for reading (errors appart)
				 * Since we already have 7 bits and a refill is
				 * 8 bits (one byte), we know we will never get back
				 * here and 9bits lookup should be performed next.
				 */
				bits_needed = 9;
				continue;
			}
		}
		else {
			/* we will eventually end there (bits can only increase) */
			idx = (bit_follow & ((1 << 9) - 1));
		}
		break;
	}
	*num_bits = bits - (fixed_huff_dec_table[idx] & 0xF);
	*bit_accum = bit_follow >> (fixed_huff_dec_table[idx] & 0xF);
	*var = fixed_huff_dec_table[idx] >> 7;

	return 1;
}

/* reverses bits in 5bits len <v> input and returns the new value.
 * ie: 01100 becomes 00110. Bits 5-7 are ignored.
 */
static inline uint8_t rbit5(uint8_t v)
{
	v = ((0xf7b3d591e6a2c480ULL >> ((v & 0x1e) * 2)) & 0xf) + ((v & 1) << 4);
	return v;
}


/* The set of macros below is relevant for uslz_decode_block() function */

/* The GETBITS macro retrieves the specified number of bits (n) from
 * the block, returning from the function if no more data is available,
 * and stores the value in the given variable (var).  The number of
 * bits to retrieve (n) must be no greater than 32.
 */
#define GETBITS(n,var)                                                              \
	do {                                                                        \
		while (num_bits < n) {                                              \
			if (!bit_accumulate(&in_ptr, in_top, &num_bits, &bit_accum))\
				goto out_of_data;                                   \
		}                                                                   \
		var = bit_accum & ((1ULL << n) - 1);                                \
		bit_accum >>= n;                                                    \
		num_bits -= n;                                                      \
	} while (0)

/* The GETHUFF macro retrieves enough bits from the block to form a
 * Huffman code according to the given Huffman table (table), storing
 * the corresponding symbol into the given variable (var).
 */
#define GETHUFF(var,table)                                        \
	do {                                                      \
		if (!gethuff(&state->huff_index, &in_ptr, in_top, \
		             &num_bits, &bit_accum, &var, table)) \
			goto out_of_data;                         \
	} while (0)


/* Output is emitted through the <out> pointer, which walks the output ring
 * from <out_base> to <out_end>. Rather than updating one counter per emitted
 * byte, all the bookkeeping is deferred to a single "checkpoint", only
 * reached when <out> meets <out_lim>. <out_lim> is the closest of the three
 * points where something actually has to be done:
 *   - the end of the ring, where <out> must wrap back to <out_base> ;
 *   - the end of the current checksum batch (<crc_ptr> + CRC_BLOCK) ;
 *   - the point where the decoded block fills the caller's buffer.
 * As a result, emitting a byte costs a store and a pointer increment, and
 * the emitting loops only have to compare <out> against <out_lim>, which
 * they have to do anyway to know when to stop. The counters are then only
 * updated once every CRC_BLOCK bytes at most.
 *
 * <crc_ptr> points to the first byte not checksummed yet and doubles as the
 * position of the last checkpoint, so <out> - <crc_ptr> is the number of
 * bytes emitted since then.
 */

/* recomputes <out_lim> for the current position. Valid at any time, not just
 * right after a checkpoint, since it accounts for the bytes still pending in
 * the current checksum batch.
 */
#define SET_OUT_LIM() do {                                          \
		unsigned long __room = out_max - 1 - dec_bsize;      \
		                                                    \
		out_lim = out_end;                                  \
		if ((unsigned long)(out_end - crc_ptr) > CRC_BLOCK)  \
			out_lim = crc_ptr + CRC_BLOCK;              \
		if ((unsigned long)(out_lim - out) > __room)         \
			out_lim = out + __room;                     \
	} while (0)

/* Propagates the bytes emitted since the last checkpoint to the stream
 * counters and to the checksum. Used by all the return paths, so that on the
 * next call the ring position is exactly dec_total % out_max with nothing
 * left pending.
 */
#define SYNC_OUT() do {                                             \
		len = out - crc_ptr;                                \
		uslz_update_crc(state, crc_ptr, len);               \
		state->dec_bsize = dec_bsize + len;                 \
		state->dec_total = dec_total + len;                 \
	} while (0)

/* where to resume after a checkpoint */
#define R_SYMBOL 0
#define R_MATCH  1
#define R_UNCOMP 2

#define CASE_STATE(s)  case USLZ_ST_##s: goto state_##s

/* main decoding function for inflate API, takes <state> stream as parameter
 * and decode as much data as possible from input data (as long as output
 * buffer allows it), it automatically detects uncompressed, fixed or dynamic
 * huffman encoding.
 */
static enum uslz_decode_ret uslz_decode_block(struct uslz_stream *state)
{
	/* Local copies of state variables, to aid compiler optimization.
	 */
	const unsigned char *in_ptr = state->in_ptr;
	const unsigned char *in_top = state->in_top;
	unsigned char *out_base  = state->out_base;
	unsigned long out_max = state->out_max;
	unsigned char *out_end = out_base + out_max;
	/* dec_total and dec_bsize are only up to date as of the last
	 * checkpoint; the bytes emitted since then are counted by
	 * <out> - <crc_ptr>.
	 */
	unsigned long dec_total = state->dec_total;
	unsigned long dec_bsize = state->dec_bsize;
	unsigned char *out = out_base + dec_total % out_max;
	unsigned char *crc_ptr = out;
	unsigned char *out_lim;
	uint64_t bit_accum = state->bit_accum;
	unsigned char num_bits = state->num_bits;
	/* whether the ring already wrapped once, i.e. whether the whole
	 * buffer is valid history for the distances.
	 */
	int wrapped = dec_total >= out_max;
	int resume = R_SYMBOL;
	unsigned int remain;
	unsigned int len;
	unsigned int get_bits;
	enum uslz_decode_ret err_code;

	SET_OUT_LIM();

	/* If continuing processing from an interrupted block, jump to
	 * the appropriate location.
	 */
	switch (state->state) {
		CASE_STATE(HEADER);
		CASE_STATE(UNCOMPRESSED_LEN);
		CASE_STATE(UNCOMPRESSED_ILEN);
		CASE_STATE(UNCOMPRESSED_DATA);
		CASE_STATE(LITERAL_COUNT);
		CASE_STATE(DISTANCE_COUNT);
		CASE_STATE(CODELEN_COUNT);
		CASE_STATE(READ_CODE_LENGTHS);
		CASE_STATE(READ_LENGTHS);
		CASE_STATE(READ_LENGTHS_16);
		CASE_STATE(READ_LENGTHS_17);
		CASE_STATE(READ_LENGTHS_18);
		CASE_STATE(READ_SYMBOL);
		CASE_STATE(READ_LENGTH);
		CASE_STATE(READ_DISTANCE);
		CASE_STATE(READ_DISTANCE_RET);
		CASE_STATE(READ_DISTANCE_EXTRA);
		CASE_STATE(CHECK_CKSUM);
		case USLZ_ST_INITIAL:
		case USLZ_ST_PARTIAL_HEADER:
			/* Both of these are impossible, since uslz_stream()
			 * handles them on its own.  We include them here to avoid
			 * triggering a compiler warning due to missing enumeration
			 * cases.
			 */
		; // empty statement to avoid syntax errors.
	}
	/* The state value is invalid, so return an error. */
	return -1;

	/* Process the block header.  If the block is not a compressed
	 * block, process it and return from the function.
	 */

	/* Retrieve the block header. */
 state_HEADER:
	GETBITS(3, state->block_type);
	if (state->block_type & 1)
		state->flags |= USLZ_FL_FINAL;

	state->block_type >>= 1;

	/* Check for blocks with an invalid block code. */
	if (state->block_type == 3) {
		err_code = USLZ_DECODE_E_INVALID_BLOCK_CODE;
		goto error_return;
	}

	/* Check for uncompressed blocks, and just copy them to the output
	 * buffer.
	 */
	if (state->block_type == 0) {
		num_bits = 0;  /* Skip remaining bits in the previous byte. */
		state->state = USLZ_ST_UNCOMPRESSED_LEN;

 state_UNCOMPRESSED_LEN:
		GETBITS(16, state->len);
		state->state = USLZ_ST_UNCOMPRESSED_ILEN;

 state_UNCOMPRESSED_ILEN:
		GETBITS(16, state->ilen);
		if (state->ilen != (~state->len & 0xFFFF)) {
			/* Length values don't match, so the stream must be corrupted. */
			err_code = USLZ_DECODE_E_CORRUPT;
			goto error_return;
		}
		/* Copy bytes to the output buffer. */
		state->nread = 0;
		state->state = USLZ_ST_UNCOMPRESSED_DATA;

 state_UNCOMPRESSED_DATA:
		remain = state->len - state->nread;

		while (remain) {
			if (out == out_lim) {
				resume = R_UNCOMP;
				goto checkpoint;
			}

			if (in_ptr >= in_top)
				goto out_of_data;

			/* copy at most what the input holds and what fits
			 * before the next checkpoint.
			 */
			len = remain;

			if (len > (unsigned long)(out_lim - out))
				len = out_lim - out;

			if (len > (unsigned long)(in_top - in_ptr))
				len = in_top - in_ptr;

			memcpy(out, in_ptr, len);
			out += len;
			in_ptr += len;
			state->nread += len;
			remain -= len;
		}

		goto decomp_end;
	}  /* if (state->block_type == 0) */

	if (state->block_type == 2) {  /* Dynamic tables. */
		/* codelen_order: Order of code lengths in the block header for the
		 * code length alphabet.
		 */
		static const unsigned char codelen_order[19] = {
			16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
		};

		/* Retrieve the three code counts from the block header. */
		state->state = USLZ_ST_LITERAL_COUNT;

 state_LITERAL_COUNT:
		GETBITS(5, state->literal_count);
		state->literal_count += 257;
		state->state = USLZ_ST_DISTANCE_COUNT;

 state_DISTANCE_COUNT:
		GETBITS(5, state->distance_count);
		state->distance_count += 1;
		state->state = USLZ_ST_CODELEN_COUNT;

 state_CODELEN_COUNT:
		GETBITS(4, state->codelen_count);
		state->codelen_count += 4;

		/* Retrieve the specified number of code lengths for the code
		 * length alphabet, clearing the rest to zero.
		 */
		state->counter = 0;
		state->state = USLZ_ST_READ_CODE_LENGTHS;

 state_READ_CODE_LENGTHS:
		while (state->counter < state->codelen_count) {
			GETBITS(3, state->codelen_len[codelen_order[state->counter]]);
			state->counter++;
		}
		for (; state->counter < 19; state->counter++)
			state->codelen_len[codelen_order[state->counter]] = 0;

		/* Generate the code length Huffman table. */
		if (!gen_huffman_table(19, state->codelen_len, 0,
		                       state->codelen_table)) {
			err_code = USLZ_DECODE_E_GEN_HUFF;
			goto error_return;
		}

		/* Read code lengths for the literal/length and distance alphabets. */

		state->last_value = 0;
		state->counter = 0;
		state->state = USLZ_ST_READ_LENGTHS;

 state_READ_LENGTHS:
		/* remain acts as repeat counter: Number of times remaining
		 * to repeat value. (We cannot run out of data while repeating
		 * values, so there is no need to store this counter in the
		 * state buffer).
		 */
		remain = 0;
		while (state->counter < state->literal_count + state->distance_count) {
			if (remain == 0) {
				/* Get the next value and/or repeat count from the
				 * bitstream.
				 */
				GETHUFF(state->symbol, state->codelen_table);
				if (state->symbol < 16) {
					/* Literal bit length. */
					state->last_value = state->symbol;
					remain = 1;
				}
				else if (state->symbol == 16) {
					/* Repeat last bit length 3-6 times. */
					state->state = USLZ_ST_READ_LENGTHS_16;

 state_READ_LENGTHS_16:
					GETBITS(2, remain);
					remain += 3;
				}
				else if (state->symbol == 17) {
					/* Repeat "0" 3-10 times. */
					state->last_value = 0;
					state->state = USLZ_ST_READ_LENGTHS_17;

 state_READ_LENGTHS_17:
					GETBITS(3, remain);
					remain += 3;
				}
				else {  /* symbol == 18 */
					/* Repeat "0" 11-138 times. */
					state->last_value = 0;
					state->state = USLZ_ST_READ_LENGTHS_18;

 state_READ_LENGTHS_18:
					GETBITS(7, remain);
					remain += 11;
				}
			}  /* if (remain == 0) */
			if (state->counter < state->literal_count)
				state->literal_len[state->counter] = state->last_value;
			else
				state->distance_len[state->counter - state->literal_count] = state->last_value;
			state->counter++;
			remain--;
			state->state = USLZ_ST_READ_LENGTHS;
		}  /* while (counter < literal_count + distance_count) */

		/* Generate the literal/length and distance Huffman tables.  The
		 * distance table is allowed to have no symbols (as may happen if
		 * the data is all literals).
		 */
		if (!gen_huffman_table(state->literal_count, state->literal_len, 0,
		                       state->literal_table) ||
		    !gen_huffman_table(state->distance_count, state->distance_len, 1,
	                       state->distance_table)) {
			err_code = USLZ_DECODE_E_GEN_HUFF;
			goto error_return;
		}
	}
	/* else Static tables: we don't need to generate literal / distance table
	 * because we directly use gethuff_fixed().
	 */

	while (1) {
		state->state = USLZ_ST_READ_SYMBOL;
		state->huff_index = 0;

 state_READ_SYMBOL:

		/* the output buffer is either full, at the end of the ring or
		 * at the end of a checksum batch: sort this out and come back.
		 */
		if (__builtin_expect(out == out_lim, 0)) {
			resume = R_SYMBOL;
			goto checkpoint;
		}

		/* Read a compressed symbol from the block. */
		if (state->block_type != 2) {
			/* fixed huffman */
			if (!gethuff_fixed(&in_ptr, in_top, &num_bits, &bit_accum, &state->symbol))
				goto out_of_data;
		}
		else
			GETHUFF(state->symbol, state->literal_table);

		/* If the symbol is a literal, add it to the buffer and continue
		 * with the next code.
		 */
		if (state->symbol < 256) {
			*out++ = state->symbol;
			continue;
		}

		/* If the symbol indicates end-of-block, exit the decompression
		 * loop.
		 */
		if (state->symbol == 256)
			break;

		/* The symbol must indicate a repeated string length, so determine
		 * the length, reading extra bits from the stream as necessary.
		 */
		if (state->symbol <= 264)
			state->repeat_length = (state->symbol - 257) + 3;
		else if (state->symbol <= 284) {
			state->state = USLZ_ST_READ_LENGTH;

 state_READ_LENGTH:
			get_bits = (state->symbol - 261) / 4;

			GETBITS(get_bits, state->repeat_length);
			state->repeat_length += 3 + ((4 + ((state->symbol - 265) & 3)) << get_bits);
		}
		else if (state->symbol == 285)
			state->repeat_length = 258;
		else {
			/* Invalid symbol. */
			err_code = USLZ_DECODE_E_INVALID_SYMBOL;
			goto error_return;
		}

		/* Read the distance symbol from the bitstream and determine the
		 * backward distance to the string.
		 */
		state->state = USLZ_ST_READ_DISTANCE;

 state_READ_DISTANCE:
		if (state->block_type != 2) {
			/* static huffman opti, read the distance directly in the the bit accum */
			if (num_bits < 5 && !bit_accumulate(&in_ptr, in_top, &num_bits, &bit_accum))
				goto out_of_data;
			state->symbol = rbit5(bit_accum);
			bit_accum >>= 5;
			num_bits -= 5;
		}
		else
			GETHUFF(state->symbol, state->distance_table);

		if (state->symbol <= 3)
			state->distance = state->symbol + 1;
		else if (state->symbol <= 29) {
			state->state = USLZ_ST_READ_DISTANCE_EXTRA;

 state_READ_DISTANCE_EXTRA:
			get_bits = (state->symbol - 2) / 2;

			GETBITS(get_bits, state->distance);
			state->distance += 1 + ((2 + (state->symbol & 1)) << get_bits);
		}
		else {
			/* Invalid symbol. */
			err_code = USLZ_DECODE_E_INVALID_SYMBOL;
			goto error_return;
		}

 state_READ_DISTANCE_RET:
		/* Copy bytes from the history to the output buffer. Since the
		 * output pointer advances with each byte written, we can simply
		 * use a constant offset (the value of "distance") from the
		 * output pointer to retrieve the byte to copy.
		 */
		remain = state->repeat_length;

		while (1) {
			const unsigned char *src;

			if (out == out_lim) {
				/* the match is emitted in as many chunks as
				 * needed, so only what remains has to be
				 * remembered across the checkpoint.
				 */
				state->repeat_length = remain;
				state->state = USLZ_ST_READ_DISTANCE_RET;
				resume = R_MATCH;
				goto checkpoint;
			}

			len = remain;

			if (len > (unsigned long)(out_lim - out))
				len = out_lim - out;

			if (state->distance > (unsigned long)(out - out_base)) {
				/* The match starts in the upper part of the
				 * ring, which is only valid history once the
				 * ring has wrapped at least once. This test
				 * replaces the former distance_avail counter:
				 * a distance never exceeds 32K and the ring is
				 * at least that large, so "have we produced at
				 * least <distance> bytes" is exactly "has the
				 * ring wrapped, or is the distance within the
				 * current position".
				 */
				if (!wrapped) {
					err_code = USLZ_DECODE_E_DISTANCE;
					goto error_return;
				}

				src = out + (out_max - state->distance);

				/* stop where the match wraps back to out_base */
				if (len > (unsigned long)(out_end - src))
					len = out_end - src;

				/* <src> is at or above <out> here, so copying
				 * forward always reads the bytes before they
				 * get overwritten.
				 */
				memmove(out, src, len);
			}
			else {
				src = out - state->distance;

				if (state->distance >= len) {
					/* source and destination don't overlap */
					memcpy(out, src, len);
				}
				else {
					/* overlapping match: the bytes being
					 * written are part of the source, they
					 * have to be replicated one at a time.
					 */
					unsigned char *dst = out;
					unsigned int cnt = len;

					do {
						*dst++ = *src++;
					} while (--cnt);
				}
			}

			out += len;
			remain -= len;
			if (!remain)
				break;
		}

	}  /* End of decompression loop. */

	goto decomp_end;

 checkpoint:
	/* <out> reached <out_lim>: account for the bytes emitted since the
	 * last checkpoint, checksum them while they are still hot in the
	 * cache, wrap the ring if we are at its end, then either report that
	 * the caller's buffer is full or resume where we left off.
	 */
	len = out - crc_ptr;
	dec_bsize += len;
	dec_total += len;
	uslz_update_crc(state, crc_ptr, len);

	if (out == out_end) {
		out = out_base;
		wrapped = 1;
	}
	crc_ptr = out;

	/* Ensure that the total output has not rolled over to a negative
	 * value; if it has, return an error.  (The "dec_total" state field
	 * is unsigned, so a rollover will not cause any improper memory
	 * accesses, but this check ensures that (1) a caller who treats
	 * the value as signed will not suffer negative rollover, and (2)
	 * processing the next symbol will not cause the unsigned offset
	 * value to roll over to zero.  The interface routines also treat
	 * a potential negative rollover as an error, so this check will
	 * not generate any spurious errors).
	 */
	if ((long)dec_total < 0) {
		err_code = USLZ_DECODE_E_UNEXPECTED;
		goto error_return;
	}

	/* no more room in the decoded block, ask for a drain. The state to
	 * resume from was set by whoever jumped here.
	 */
	if (dec_bsize + 1 >= out_max)
		goto out_of_space;

	SET_OUT_LIM();

	if (resume == R_MATCH)
		goto state_READ_DISTANCE_RET;
	if (resume == R_UNCOMP)
		goto state_UNCOMPRESSED_DATA;
	goto state_READ_SYMBOL;

 decomp_end:

	/* success: flush the pending checksum and update stream state with our
	 * local state variables before returning.
	 */
	len = out - crc_ptr;
	uslz_update_crc(state, crc_ptr, len);
	crc_ptr = out;
	dec_total += len;
	dec_bsize += len;
	state->dec_total = dec_total;
	state->dec_bsize = dec_bsize;

	/* only on the very last return */
	if ((state->flags & USLZ_FL_FINAL)) {
		/* checksum checks for relevant formats: we use the bit
		 * accumulator for that purpose since it is not used for
		 * decoding anymore.
		 */
		bit_accum = 0;
		num_bits = 0;
		/* the trailer may well not be available yet, in which case we
		 * have to be able to come back here on the next call.
		 */
		state->state = USLZ_ST_CHECK_CKSUM;

 state_CHECK_CKSUM:
		if ((state->flags & USLZ_FL_ZLIB)) {
			/* check computed zlib adler checksum against 4 last bytes
			 * (stored in Big endian).
			 */
			while (num_bits < 32) {
				if (in_ptr >= in_top)
					goto out_of_data;
				/* the cast matters: in_ptr[0] is promoted to a
				 * signed int, so for the first byte, whose
				 * shift is 24, any value >= 0x80 would become
				 * negative and be sign-extended over the upper
				 * half of the 64-bit accumulator.
				 */
				bit_accum |= (uint32_t)in_ptr[0] << (24 - num_bits);
				in_ptr++;
				num_bits += 8;
			}
			if (state->crc != bit_accum) {
				err_code = USLZ_DECODE_E_BAD_CRC;
				goto error_return;
			}
		}
		else if ((state->flags & USLZ_FL_GZIP)) {
			/* The gzip trailer is 8 bytes: crc32 then isize, both
			 * little endian. Accumulate all 64 bits before looking
			 * at anything, so that an interrupted read just resumes
			 * filling the accumulator and does not have to remember
			 * how far into the trailer it got. Consuming isize as
			 * well is what allows a following member to be found.
			 */
			while (num_bits < 64) {
				if (in_ptr >= in_top)
					goto out_of_data;
				bit_accum |= (uint64_t)in_ptr[0] << num_bits;
				in_ptr++;
				num_bits += 8;
			}

			if (state->crc != (uint32_t)bit_accum) {
				err_code = USLZ_DECODE_E_BAD_CRC;
				goto error_return;
			}

			/* the upper half is isize, the decoded size of this
			 * member modulo 2^32; it is consumed but not checked.
			 */
			bit_accum = 0;
			num_bits = 0;
		}

		/* The trailer has been verified, and only now may the stream
		 * be reported as complete. Doing it before the check meant
		 * that if the trailer was not available yet, the out of data
		 * return above would make uslz_decode() see a complete stream
		 * and return success from its drain path without ever coming
		 * back here, so the checksum was silently never verified.
		 */
		state->flags |= USLZ_FL_COMPLETE;
	}

	state->in_ptr    = in_ptr;
	state->bit_accum = bit_accum;
	state->num_bits  = num_bits;
	state->state     = USLZ_ST_HEADER;

	return USLZ_DECODE_SUCCESS;

	/* handle cases of non successful return */
 out_of_data:
	SYNC_OUT();
	state->in_ptr = in_ptr;
	state->bit_accum = bit_accum;
	state->num_bits = num_bits;
	return USLZ_DECODE_OUT_OF_DATA;

 out_of_space:
	SYNC_OUT();
	state->in_ptr = in_ptr;
	state->bit_accum = bit_accum;
	state->num_bits = num_bits;
	return USLZ_DECODE_OUT_OF_SPACE;

 error_return:
	SYNC_OUT();
	state->in_ptr = in_ptr;
	state->bit_accum = bit_accum;
	state->num_bits  = num_bits;
	return err_code;
}

/* A gzip file is a series of members (rfc1952), which is what "gzip -c a b"
 * and "cat a.gz b.gz" produce. If <state> just completed a gzip member and
 * the input continues with another gzip magic, this resets the per-member
 * state so that decoding can go on, and returns 1. The output ring, the
 * total decoded size and the drain offset are all preserved, so the members'
 * contents are simply concatenated as the caller expects. Returns 0 when no
 * new member starts here, in which case anything left is trailing garbage
 * and is ignored, as gzip(1) does.
 */
static int uslz_next_member(struct uslz_stream *state)
{
	if (!(state->flags & USLZ_FL_GZIP))
		return 0;

	/* Gather the two magic bytes of a possible next member. They may be
	 * split across calls, and the header buffer cannot be used to hold
	 * them in the meantime because it shares its storage with the distance
	 * table, which the member we just finished has overwritten. The bit
	 * accumulator is free at this point and does survive across calls, so
	 * it serves as the lookahead.
	 */
	while (state->num_bits < 16) {
		if (state->in_ptr >= state->in_top) {
			/* Undecided: we cannot tell whether another member
			 * follows without more data. The stream is reported
			 * complete, which is what a caller with nothing left to
			 * send needs, and this is retried on the next call for
			 * a caller which has more.
			 */
			return 0;
		}
		state->bit_accum |= (uint64_t)state->in_ptr[0] << state->num_bits;
		state->in_ptr += 1;
		state->num_bits += 8;
	}

	if ((state->bit_accum & 0xFFFF) != 0x8B1F)
		return 0; // trailing garbage, the stream really ended

	/* Hand the magic over to the format detection, which knows how to
	 * accumulate the rest of the header across calls from there.
	 */
	state->hdr_detect.buf[0] = 0x1F;
	state->hdr_detect.buf[1] = 0x8B;
	state->hdr_detect.buf_len = 2;
	state->hdr_detect.gzip_flags = 0;

	state->flags &= ~(USLZ_FL_GZIP | USLZ_FL_FINAL | USLZ_FL_COMPLETE);
	state->crc = 0;
	state->bit_accum = 0;
	state->num_bits = 0;
	state->state = USLZ_ST_INITIAL;
	return 1;
}

/**
 * decompress stream of data encoded using rfc1950 (zlib), rfc1952(gzip) or
 * rfc1951 (raw) format with "deflate" algorithm.
 *
 * It is supported to call the function one byte at a time (or more).
 *
 * Parameters:
 *       state:           Pointer to a uslz_stream struct to hold decompression
 *                        information, must be initialized using uslz_init().
 *       compressed_data: Pointer to the portion of the compressed data to
 *                        process.
 *       compressed_size: Number of bytes in compressed data.
 *       decoded_data:    Pointer to pointer that will be updated to the start
 *                        of the decoded data.
 *       decoded_size:    Pointer to variable to receive the size of the
 *                        decoded data for the current call.
 *       consumed_bytes   Pointer to variable to receive the number of compressed
 *                        bytes that were actually consumed upon return. It is
 *                        relevant when return value is USLZ_DECODE_OUT_OF_SPACE
 *                        as the caller is able to drop consumed bytes and only provide
 *                        remaining (unconsumed) ones on the next call. When
 *                        USLZ_DECODE_OUT_OF_DATA or USLZ_DECODE_SUCCESS is
 *                        returned, consumed_bytes == compressed_size.
 *               crc_ret: Pointer to variable to receive the CRC or adler32
 *                        checksum (depending on format used) of the uncompressed
 *                        data, or NULL if the CRC is not needed. It is not relevant
 *                        with raw format (rfc1951).
 * Notes:
 *     decoded_data and decoded_size are only set for USLZ_DECODE_OUT_OF_DATA
 *     and USLZ_DECODE_SUCCESS, thus data should not be attempt to be read
 *     by caller with other return codes.
 *
 *     The returned CRC value is only valid after the entire stream of data
 *     has been decompressed with success.
 *
 *     USLZ_DECODE_SUCCESS means the stream is complete as far as the data
 *     provided so far goes. Since a gzip file is a series of members
 *     (rfc1952), a caller which still has input left must keep calling: the
 *     next member will be picked up and its output appended, and success
 *     will be reported again at its end. Only a caller which knows it has
 *     nothing left to send may treat the first success as the end of the
 *     stream. Anything after the last member which is not a gzip magic is
 *     ignored as trailing garbage, as gzip(1) does.
 *
 * caller must check return value to check if the call succeeded
 * (USLZ_DECODE_SUCCESS), needs more space (USLZ_DECODE_OUT_OF_SPACE)
 * more input data (USLZ_DECODE_OUT_OF_DATA) or met an error (any other
 * return codes USLZ_DECODE_E_*).
 */
enum uslz_decode_ret uslz_decode(struct uslz_stream *state,
                                 const unsigned char *compressed_data, long compressed_size,
                                 unsigned char **decoded_data, long *decoded_size,
                                 long *consumed_bytes, uint32_t *crc_ret)
{
	enum uslz_decode_ret res;

	/* ensure input consistency */
	if (compressed_data == NULL || compressed_size < 0 ||
	    consumed_bytes == NULL || decoded_data == NULL || decoded_size == NULL)
		return USLZ_DECODE_E_INVALID_ARGUMENT;

	/* set up initial values */
	*decoded_data = NULL;
	*decoded_size = 0;

	*consumed_bytes = compressed_size;

	state->in_ptr   = (const unsigned char *)compressed_data;
	state->in_top   = state->in_ptr + compressed_size;

	/* A previous call may have completed a gzip member while more members
	 * were still to come; pick the next one up as soon as its magic shows
	 * up, so that a caller which keeps feeding data gets the whole series.
	 */
	if ((state->flags & USLZ_FL_COMPLETE) && !state->dec_bsize)
		uslz_next_member(state);

	/* pending unconsumed data that must be consumed by the caller before
	 * handling a new block.
	 */
	if (state->dec_bsize) {
		res = USLZ_DECODE_OUT_OF_SPACE;
 drain:
		if (state->dec_bofs + state->dec_bsize > state->out_max)
			*decoded_size = state->out_max - state->dec_bofs;
		else
			*decoded_size = state->dec_bsize;

		if (*decoded_size == 0 && state->dec_bsize) {
			/* the pending block starts at the beginning of the
			 * ring because the previous drain stopped on its end.
			 * Note the test on dec_bsize: reaching this point with
			 * nothing pending (e.g. out of data before a single
			 * byte could be decoded) must not move dec_bofs, or
			 * the next drain would report the wrong location.
			 */
			state->dec_bofs = 0;
			*decoded_size = state->dec_bsize;
		}

		*decoded_data = state->out_base + state->dec_bofs;
		state->dec_bsize -= *decoded_size;
		state->dec_bofs += *decoded_size;

		*consumed_bytes = state->in_ptr - compressed_data;

		if (state->flags & USLZ_FL_COMPLETE) {
			/* finished decompressing, but not necessarily
			 * draining our decompression buffer.
			 */
			if (state->dec_bsize)
				return USLZ_DECODE_OUT_OF_SPACE;
			goto end; // decompressed + drained OK
		}

		return res;
	}

	/* first call: auto detect header to known which format is used, then
	 * init the decompressing state.
	 */
 new_member:
	if (state->state == USLZ_ST_INITIAL) {
		const unsigned char *input;
		unsigned int zlib_header;
		/* First byte of the header in the caller's buffer. The fast
		 * paths below consume bytes from it before they know whether
		 * they will be able to complete the header, so they need to be
		 * able to give them back. Only meaningful while buf_len is 0,
		 * that is, as long as nothing has been accumulated yet.
		 */
		const unsigned char *hdr_start = state->in_ptr;

		input = state->in_ptr;

		if ((state->flags & USLZ_FL_GZIP))
			goto gzip_flags; // we already know it is gzip, keep parsing

		if (state->in_top - state->in_ptr > 2 && !state->hdr_detect.buf_len) {
			/* enough data available in the header on first
			 * attempt, let's try with the input buffer directly.
			 */
			state->in_ptr += 2;
			goto detect;
		}

		/* there was not enough data on first try, try to accumulate
		 * at least 2 bytes to detect gzip/zlib format in the persistent
		 * hdr buffer.
		 */
		while (state->hdr_detect.buf_len < 2) {
			if (state->in_ptr >= state->in_top)
				return USLZ_DECODE_OUT_OF_DATA;
			state->hdr_detect.buf[state->hdr_detect.buf_len] = state->in_ptr[0];
			state->in_ptr += 1;
			state->hdr_detect.buf_len += 1;
		}

		/* let's exclusively use the persistent buffer now */
		input = state->hdr_detect.buf;
 detect:
		if (input[0] == 0x1F && input[1] == 0x8B) {
			/* gzip! */
			if (!state->hdr_detect.buf_len) {
				/* go to gzip header parsing directly if there
				 * is enough data to parse it the first time.
				 */
				if (state->in_top - state->in_ptr >= 8) {
					state->in_ptr += 8;
					goto enough_gzip_header;
				}
				/* Not enough data for the 10-byte header. Give
				 * the two magic bytes consumed above back, so
				 * that need_more_header accumulates the header
				 * from its very first byte; otherwise they
				 * would be dropped and the next call would
				 * parse the header two bytes too far.
				 */
				state->in_ptr = hdr_start;
				goto need_more_header; // gzip header is 10 bytes min
			}

			/* < 10 bytes on the first try, accumlate 10 bytes in the
			 * persistent buffer before going any further.
			 */
			while (state->hdr_detect.buf_len < 10) {
				if (state->in_ptr >= state->in_top)
					return USLZ_DECODE_OUT_OF_DATA;
				state->hdr_detect.buf[state->hdr_detect.buf_len] = state->in_ptr[0];
				state->in_ptr += 1;
				state->hdr_detect.buf_len += 1;
			}

			/* let's exclusively use the persistent buffer now */
			input = state->hdr_detect.buf;

 enough_gzip_header:
			/* third byte is compression method */
			if (input[2] != 0x08)
				return USLZ_DECODE_E_BAD_COMP_METHOD;

			/* fourth byte is gzip flags */
			state->hdr_detect.gzip_flags = input[3];

			/* we have all we needed from the gzip header, the
			 * header buffer (10 bytes) may now be reused to accumulate
			 * more data.
			 */
			state->hdr_detect.buf_len = 0;
			state->flags |= USLZ_FL_GZIP;

 gzip_flags:
			if (state->hdr_detect.gzip_flags & 0x4) {
				/* gzip FEXTRA set: a 2-byte little endian length
				 * followed by that many bytes to skip. Both the
				 * length and the payload may be split across any
				 * number of calls, so XLEN is stashed in the
				 * header buffer and buf_len counts how many bytes
				 * of the whole field were consumed so far. That
				 * way resuming never has to guess: below 2, we
				 * are still reading XLEN itself, above, we are
				 * skipping the payload.
				 *
				 * Note that XLEN must not be re-read from the
				 * input on resume; that used to happen when the
				 * length had been consumed but the payload was
				 * not fully available, and the first two payload
				 * bytes were then taken as the length.
				 */
				int xlen;

				while (state->hdr_detect.buf_len < 2) {
					if (state->in_ptr >= state->in_top)
						return USLZ_DECODE_OUT_OF_DATA;
					state->hdr_detect.buf[state->hdr_detect.buf_len] = state->in_ptr[0];
					state->in_ptr += 1;
					state->hdr_detect.buf_len += 1;
				}

				/* xlen is little endian */
				xlen = state->hdr_detect.buf[1] << 8 | state->hdr_detect.buf[0];

				/* skip the payload, counting it in buf_len but
				 * without storing it.
				 */
				while (state->hdr_detect.buf_len < 2 + xlen) {
					if (state->in_ptr >= state->in_top)
						return USLZ_DECODE_OUT_OF_DATA;
					state->in_ptr += 1;
					state->hdr_detect.buf_len += 1;
				}

				/* all FEXTRA bytes skipped, remove FEXTRA bit */
				state->hdr_detect.gzip_flags &= ~0x4;
				state->hdr_detect.buf_len = 0;
			}
			if (state->hdr_detect.gzip_flags & 0x8) {
				/* gzip FNAME set, search for NULL byte which
				 * indicates the end of the string.
				 */
				while (1) {
					if (state->in_ptr >= state->in_top)
						return USLZ_DECODE_OUT_OF_DATA;
					if (state->in_ptr[0] == 0)
						break;
					state->in_ptr += 1;
				}

				state->in_ptr += 1; // also skip NULL byte

				/* all FNAME bytes skipped, remove FNAME bit */
				state->hdr_detect.gzip_flags &= ~0x8;

			}
			if (state->hdr_detect.gzip_flags & 0x10) {
				/* gzip COMMENT set, search for NULL byte which
				 * indicates the end of the string.
				 */

				while (1) {
					if (state->in_ptr >= state->in_top)
						return USLZ_DECODE_OUT_OF_DATA;
					if (state->in_ptr[0] == 0)
						break;
					state->in_ptr += 1;
				}

				state->in_ptr += 1; // also skip NULL byte

				/* all FCOMMENT bytes skipped, remove FNAME bit */
				state->hdr_detect.gzip_flags &= ~0x10;
			}
			if (state->hdr_detect.gzip_flags & 0x2) {
				/* gzip FHCRC set, skip exactly 2 bytes:
				 * use buf_len to count skipped bytes but don't store bytes in the
				 * buffer.
				 */
				while (state->hdr_detect.buf_len < 2) {
					if (state->in_ptr >= state->in_top)
						return USLZ_DECODE_OUT_OF_DATA;
					state->in_ptr += 1;
					state->hdr_detect.buf_len += 1;
				}
			}

		}
	        else if (((zlib_header = (input[0] << 8 | input[1])) & 0x8F00) == 0x0800 && zlib_header % 31 == 0) {
			/*
			 * A zlib header is a big-endian 16-bit integer, composed of the
			 * following fields:
			 *     0xF000: Window size (log2(maximum_distance), 8..15) minus 8
			 *     0x0F00: Compression method (always 8)
			 *     0x00C0: Compression level
			 *     0x0020: Custom dictionary flag
			 *     0x001F: Check bits (set so the header is a multiple of 31)
			 */

			/* zlib format */
			if (zlib_header & 0x0020) {
				/* This library does not support custom dictionaries. */
				return USLZ_DECODE_E_DICT;
			}
			/* rfc1950/zlib starts with initial crc=1 */
			state->crc = 1;
			state->flags |= USLZ_FL_ZLIB;
		} else if (!state->hdr_detect.buf_len) {
			/* Raw format detected on the fast path: the two bytes
			 * consumed above are not a header at all, they are the
			 * first two bytes of the deflate stream. Give them back
			 * and let uslz_decode_block() read them normally.
			 */
			state->in_ptr = hdr_start;
		} else {
			/* raw format, feed back the pending bytes to the stream,
			 * (should be 2 bytes at most) if stream is invalid it
			 * will be detected by tinflate_block().
			 */
			unsigned char bytes[2];
			int it = 0;

			if (state->hdr_detect.buf_len > 2)
				return USLZ_DECODE_E_UNEXPECTED;
			state->state = USLZ_ST_HEADER;

			/* copy pending bytes from hdr_detect to bytes because
			 * hdr_detect buf shares memory with decoding state
			 * and is only valid during INITIAL state.
			 */
			while (it < state->hdr_detect.buf_len) {
				bytes[it] = state->hdr_detect.buf[it];
				it += 1;
			}
			state->in_ptr = bytes;
			state->in_top = bytes + state->hdr_detect.buf_len;
			res = uslz_decode_block(state);

			/* restore original state */
			state->in_ptr   = (const unsigned char *)compressed_data;
			state->in_top   = state->in_ptr + compressed_size;

			goto next_block;
		}// else raw format without pending bytes

		/* The caller may have imposed an envelope. Refuse a stream
		 * that does not carry it rather than silently decoding it as
		 * something else, which for a raw deflate fallback would
		 * produce garbage instead of an error.
		 */
		if (((state->flags & USLZ_FL_EXP_GZIP) && !(state->flags & USLZ_FL_GZIP)) ||
		    ((state->flags & USLZ_FL_EXP_ZLIB) && !(state->flags & USLZ_FL_ZLIB)))
			return USLZ_DECODE_E_CORRUPT;

		state->state = USLZ_ST_HEADER;
	}

	/* format auto-detection is over, let's proceed with decompressing
	 * the blocks and inflating the output buffer until either no more
	 * input data, output is full or error.
	 */
	while (!(state->flags & USLZ_FL_COMPLETE)) {
		res = uslz_decode_block(state);
 next_block:

		switch (res) {
			case USLZ_DECODE_SUCCESS:
				break;
			case USLZ_DECODE_OUT_OF_SPACE:
			case USLZ_DECODE_OUT_OF_DATA:
				goto drain;
			default:
				return res;
		}

		/* Ensure that the total output size has not rolled over to a
		 * negative value; if it has, return an error.
		 */
		if ((long)state->dec_total < 0)
			return USLZ_DECODE_E_UNEXPECTED;

	}

	/* this member is done; if another one follows in the same input, keep
	 * going rather than reporting a complete stream too early.
	 */
	if (uslz_next_member(state))
		goto new_member;

	if (state->dec_bsize)
		goto drain;
 end:
	/* update decompressed size and CRC if requested */
	if (crc_ret)
		*crc_ret = state->crc;

	return USLZ_DECODE_SUCCESS;

 need_more_header:
	/* copy input bytes in header buf so we consume input in order to
	 * ask for more bytes.
	 */
	while (state->in_ptr < state->in_top) {
		state->hdr_detect.buf[state->hdr_detect.buf_len] = state->in_ptr[0];
		state->in_ptr += 1;
		state->hdr_detect.buf_len += 1;
	}

	return USLZ_DECODE_OUT_OF_DATA;
}

/* prepares <state> stream context before it is used with uslz_decode()
 *
 * <output_buffer> is a pointer to the buffer to receive uncompressed data.
 * and associated <output_size> the size of the output buffer, in bytes.
 *
 * It will be used by slz_inflate as a rotating buffer to decode the stream
 * and allow the caller to read decoded data. As such it is exclusively managed
 * by slz_inflate and must not be modified by the caller, only read from during
 * the whole decoding process. Minimum size should be 32K, because zlib algo
 * specifies that up to 32K bytes distance can be used, thus the inflate API
 * should always be able to go 32K bytes in the past at any time with such a
 * buffer.
 *
 * Returns 1 on success and 0 on failure.
 */
int uslz_init(struct uslz_stream *state,
              unsigned char *output_buffer, long output_size)
{
	struct uslz_stream zero = { 0 };

	if (state == NULL || output_size < 32768 || output_buffer == NULL)
		return 0;

	/* zero out <state> */
	*state = zero;

	state->out_base = output_buffer;
	state->out_max = output_size;

	return 1;
}

/* Same as uslz_init() but tells the decoder which envelope to expect, instead
 * of detecting it from the first bytes of the stream. <format> is one of the
 * SLZ_FMT_* values:
 *
 *   SLZ_FMT_DEFLATE  raw deflate (rfc1951). This one cannot be detected: it
 *                    has no header at all, so it is only ever reached as the
 *                    fallback when the stream looks like neither gzip nor
 *                    zlib. A raw stream whose first two bytes happen to form
 *                    a valid zlib header would be mis-detected, so a caller
 *                    that knows it is decoding raw deflate should say so.
 *   SLZ_FMT_GZIP     gzip (rfc1952)
 *   SLZ_FMT_ZLIB     zlib (rfc1950)
 *
 * For the latter two the envelope is still parsed as usual, and the stream is
 * now rejected with USLZ_DECODE_E_CORRUPT if it does not carry the announced
 * one. That matters when the format comes from an outside source, for instance
 * an HTTP Content-Encoding, where accepting a different envelope is wrong.
 *
 * Returns 1 on success and 0 on failure, including for an unknown format.
 */
int uslz_init_fmt(struct uslz_stream *state, unsigned char *output_buffer,
                  long output_size, int format)
{
	if (!uslz_init(state, output_buffer, output_size))
		return 0;

	switch (format) {
	case SLZ_FMT_NONE:
		/* nothing to do */
		break;
	case SLZ_FMT_DEFLATE:
		/* nothing to detect nor to skip, the first bits are already
		 * the first block header.
		 */
		state->state = USLZ_ST_HEADER;
		break;
	case SLZ_FMT_GZIP:
		state->flags |= USLZ_FL_EXP_GZIP;
		break;
	case SLZ_FMT_ZLIB:
		state->flags |= USLZ_FL_EXP_ZLIB;
		break;
	default:
		return 0;
	}
	return 1;
}

/* prepare the static huffman decoding table, which is a 9bits direct
 * lookup array to enable fast static huffman decoding in
 * gethuff_fixed().
 */
static inline void __uslz_prepare_fixed_huff_dec_table(void)
{
#ifndef PRECOMPUTE_TABLES
	int it = 0;

	/* in the fixed huffman tree there are 288 symbols (286 + 2 unused symbols).
	 *
	 * symbols and len are stored on 16bits unsigned integers. We use exactly 512 indexes
	 * (from 0 to 511 which is 9 bits maximal value) as static encoding is performed using
	 * at most 9 bits:
	 *
	 * Each value in the array is stored this way:
	 *
	 *    9 bits for the symbol (A)
	 *    3 unused bits
	 *    4 bits for the len (B)
	 *
	 * ie:
	 *      AAAAAAAA AXXXBBBB
	 */

	// we revese the codes in order to directly compare them as they appear
	// in the bit accumulator in huffman decoding func using rev_short(), the
	// RFC doesn't specify bit order is inverted but this is the only way this
	// works in practise.
	while (it <= 143) {
		// 00110000X through 10111111X
		fixed_huff_dec_table[rev_short((0x30 + it), 8) | 0x100] = it << 7;      // symbol
		fixed_huff_dec_table[rev_short((0x30 + it), 8) | 0x100] |= 8;           // len
		fixed_huff_dec_table[rev_short((0x30 + it), 8)] = it << 7;              // symbol
		fixed_huff_dec_table[rev_short((0x30 + it), 8)] |= 8;                   // len
		it += 1;
	}
	while (it <= 255) {
		// 110010000 through 111111111
		fixed_huff_dec_table[rev_short(0x190 + it - 144, 9)] = it << 7;         // symbol
		fixed_huff_dec_table[rev_short(0x190 + it - 144, 9)] |= 9;              // len
		it += 1;
	}
	while (it <= 279) {
		// 0000000XX through 0010111XX
		fixed_huff_dec_table[rev_short((0x0 + it - 256), 7)] = it << 7;         // symbol
		fixed_huff_dec_table[rev_short((0x0 + it - 256), 7)] |= 7;              // len
		fixed_huff_dec_table[rev_short((0x0 + it - 256), 7) | 0x80] = it << 7;  // symbol
		fixed_huff_dec_table[rev_short((0x0 + it - 256), 7) | 0x80] |= 7;       // len
		fixed_huff_dec_table[rev_short((0x0 + it - 256), 7) | 0x100] = it << 7; // symbol
		fixed_huff_dec_table[rev_short((0x0 + it - 256), 7) | 0x100] |= 7;      // len
		fixed_huff_dec_table[rev_short((0x0 + it - 256), 7) | 0x180] = it << 7; // symbol
		fixed_huff_dec_table[rev_short((0x0 + it - 256), 7) | 0x180] |= 7;      // len
		it += 1;
	}
	while (it <= 287) {
		// 11000000X through 11000111X
		fixed_huff_dec_table[rev_short((0xC0 + it - 280), 8)] = it << 7;         // symbol
		fixed_huff_dec_table[rev_short((0xC0 + it - 280), 8)] |= 8;              // len
		fixed_huff_dec_table[rev_short((0xC0 + it - 280), 8) | 0x100] = it << 7; // symbol
		fixed_huff_dec_table[rev_short((0xC0 + it - 280), 8) | 0x100] |= 8;      // len
		it += 1;
	}
#endif
	/* uncomment the code below to regenerate and dump the fixed_huff_dec_table
	 * (provided by tables.h) on stdout on startup. Never use in production!
	 */
//	int idx = 0;
//	while (idx < 512) {
//		fprintf(stderr, " 0x%06x, ", fixed_huff_dec_table[idx]);
//		if ((idx & 3) == 3 || idx == 511)
//			fprintf(stderr, "  /* %d-%d */\n", idx - 3, idx);
//		idx += 1;
//	}
}

__attribute__((constructor))
static void __uslz_initialize(void)
{
	__uslz_prepare_fixed_huff_dec_table();
}
