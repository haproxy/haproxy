#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* generic function for 32-bit, 4-bytes at a time */
static inline __attribute__((always_inline))
uint32_t is_char4_outside(uint32_t x, uint8_t min8, uint8_t max8)
{
	uint32_t min32 = min8 * 0x01010101U;
	uint32_t max32 = max8 * 0x01010101U;
	return (((x - min32) | (max32 - x)) & 0x80808080U);
}

/* generic function for 64-bit, 4-bytes at a time */
static inline __attribute__((always_inline))
uint64_t is_char8_outside_by4(uint64_t x, uint8_t min8, uint8_t max8)
{
	return is_char4_outside(x, min8, max8) | is_char4_outside(x >> 32, min8, max8);
}

/* generic function for 64-bit, 8-bytes at a time */
static inline __attribute__((always_inline))
uint64_t is_char8_outside_by8(uint64_t x, uint8_t min8, uint8_t max8)
{
	uint64_t min64 = min8 * 0x0101010101010101ULL;
	uint64_t max64 = max8 * 0x0101010101010101ULL;
	return (((x - min64) | (max64 - x)) & 0x8080808080808080ULL);
}

/* generic function for 64-bit, 4- or 8-bytes at a time */
static inline __attribute__((always_inline))
uint64_t is_char8_outside(uint64_t x, uint8_t min8, uint8_t max8)
{
	if (sizeof(long) >= 8)
		return is_char8_outside_by8(x, min8, max8);
	else
		return is_char8_outside_by4(x, min8, max8);
}

/* reference function for 32-bit, one byte at a time */
static inline int slow32_ref(uint32_t x)
{
	uint8_t a, b, c, d;

	a = x >>  0; b = x >>  8; c = x >> 16; d = x >> 24;

	return a < 0x24 || a > 0x7e || b < 0x24 || b > 0x7e ||
	       c < 0x24 || c > 0x7e || d < 0x24 || d > 0x7e;
}

/* reference function for 64-bit, one byte at a time */
static inline int slow64_ref(uint64_t x)
{
	uint8_t a, b, c, d, e, f, g, h;

	a = x >>  0; b = x >>  8; c = x >> 16; d = x >> 24;
	e = x >> 32; f = x >> 40; g = x >> 48; h = x >> 56;

	return a < 0x24 || a > 0x7e || b < 0x24 || b > 0x7e ||
	       c < 0x24 || c > 0x7e || d < 0x24 || d > 0x7e ||
	       e < 0x24 || e > 0x7e || f < 0x24 || f > 0x7e ||
	       g < 0x24 || g > 0x7e || h < 0x24 || h > 0x7e;
}

/* optimal function for 32-bit, 4-bytes at a time */
static inline int fast32_gen(uint32_t x)
{
	return !!is_char4_outside(x, 0x24, 0x7e);
}

/* optimal function for 64-bit, 4-bytes at a time */
static inline int fast64_gen4(uint64_t x)
{
	return !!is_char8_outside_by4(x, 0x24, 0x7e);
}

/* optimal function for 64-bit, 8-bytes at a time */
static inline int fast64_gen8(uint64_t x)
{
	return !!is_char8_outside_by8(x, 0x24, 0x7e);
}

/* optimal function for 64-bit, 4- or 8-bytes at a time */
static inline int fast64_gen(uint64_t x)
{
	return !!is_char8_outside(x, 0x24, 0x7e);
}

/* specific function for 32-bit, 4- or 8-bytes at a time */
static inline int fast32_spec(uint32_t x)
{
	return !!(((x - 0x24242424) | (0x7e7e7e7e - x)) & 0x80808080U);
}

/* specific function for 32-bit, 4- or 8-bytes at a time */
static inline int fast64_spec(uint64_t x)
{
	return !!(((x - 0x2424242424242424ULL) | (0x7e7e7e7e7e7e7e7eULL - x)) & 0x8080808080808080ULL);
}

/* xorshift 64-bit PRNG */
#define RND64SEED 0x9876543210abcdefull
static uint64_t rnd64seed = RND64SEED;
static inline uint64_t rnd64()
{
        rnd64seed ^= rnd64seed << 13;
        rnd64seed ^= rnd64seed >>  7;
        rnd64seed ^= rnd64seed << 17;
        return rnd64seed;
}

int main(int argc, char **argv)
{
	uint32_t base = 0;
	uint32_t step = 1;
	uint32_t loops = 0;
	int size = 32;
	int ref;

	/* usage: cmd [<bits> [<base> [<step>]]] */

	if (argc > 1)
		size = atoi(argv[1]);

	if (argc > 2)
		base = atol(argv[2]);

	if (argc > 3)
		step = atol(argv[3]);

	if (size == 32) {
		do {
			ref = slow32_ref(base);

			if (fast32_gen(base) != ref) {
				printf("fast32_gen() fails at 0x%08x: %d / ref=%d\n", base, !ref, ref);
				return 1;
			}

			if (fast32_spec(base) != ref) {
				printf("fast32_spec() fails at 0x%08x: %d / ref=%d\n", base, !ref, ref);
				return 1;
			}

			base += step;
			loops++;
			if (!(loops & 0x7ffff))
				printf("0x%08x: 0x%08x\r", loops, base);
		} while (base >= step);
	}
	else if (size == 64) { /* 64-bit on randoms but no more than 2^32 tests */
		uint32_t ctr;
		uint64_t rnd;

		/* offset the RNG if using multiple workers */
		for (ctr = 0; ctr < base; ctr++)
			rnd64();

		do {
			rnd = rnd64();
			ref = slow64_ref(rnd);

			if (fast64_gen(rnd) != ref) {
				printf("fast64_gen() fails at 0x%08x: fct(0x%16llx)=%d / ref=%d\n", base, (long long)rnd, !ref, ref);
				return 1;
			}

			if (fast64_gen4(rnd) != ref) {
				printf("fast64_gen4() fails at 0x%08x: fct(0x%16llx)=%d / ref=%d\n", base, (long long)rnd, !ref, ref);
				return 1;
			}

			if (fast64_gen8(rnd) != ref) {
				printf("fast64_gen8() fails at 0x%08x: fct(0x%16llx)=%d / ref=%d\n", base, (long long)rnd, !ref, ref);
				return 1;
			}

			if (fast64_spec(rnd) != ref) {
				printf("fast64_spec() fails at 0x%08x: fct(0x%16llx)=%d / ref=%d\n", base, (long long)rnd, !ref, ref);
				return 1;
			}

			base += step;
			loops++;
			if (!(loops & 0x7ffff))
				printf("0x%08x: 0x%08x -> 0x%16llx\r", loops, base, (long long)rnd);
		} while (base >= step);
	}
	else {
		printf("unknown size, usage: %s [<bits> [<base> [<step>]]]\n", argv[0]);
		return 1;
	}

	printf("%llu checks passed.                                 \n",
	       (unsigned long long)((uint32_t)(base - step) / step) + 1);
	return 0;
}
