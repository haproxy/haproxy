#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static inline unsigned long statistical_prng()
{
	static unsigned long statistical_prng_state = 2463534242U;
	unsigned long x = statistical_prng_state;

	if (sizeof(long) <= 4) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
	} else {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	return statistical_prng_state = x;
}

/* returns the position of one bit set in <v>, starting at position <bit>, and
 * searching in other halves if not found. This is intended to be used to
 * report the position of one bit set among several based on a counter or a
 * random generator while preserving a relatively good distribution so that
 * values made of holes in the middle do not see one of the bits around the
 * hole being returned much more often than the other one. It can be seen as a
 * disturbed ffsl() where the initial search starts at bit <bit>. The look up
 * is performed in O(logN) time for N bit words, yielding a bit among 64 in
 * about 16 cycles. Passing value 0 for <v> makes no sense and -1 is returned
 * in this case.
 */
int one_among(unsigned long v, int bit)
{
	/* note, these masks may be produced by ~0UL/((1UL<<scale)+1) but
	 * that's more expensive.
	 */
	static const unsigned long halves[] = {
		(unsigned long)0x5555555555555555ULL,
		(unsigned long)0x3333333333333333ULL,
		(unsigned long)0x0F0F0F0F0F0F0F0FULL,
		(unsigned long)0x00FF00FF00FF00FFULL,
		(unsigned long)0x0000FFFF0000FFFFULL,
		(unsigned long)0x00000000FFFFFFFFULL
	};
	unsigned long halfword = ~0UL;
	int scope = 0;
	int mirror;
	int scale;

	if (!v)
		return -1;

	/* we check if the exact bit is set or if it's present in a mirror
	 * position based on the current scale we're checking, in which case
	 * it's returned with its current (or mirrored) value. Otherwise we'll
	 * make sure there's at least one bit in the half we're in, and will
	 * scale down to a smaller scope and try again, until we find the
	 * closest bit.
	 */
	for (scale = (sizeof(long) > 4) ? 5 : 4; scale >= 0; scale--) {
		halfword >>= (1UL << scale);
		scope |= (1UL << scale);
		mirror = bit ^ (1UL << scale);
		if (v & ((1UL << bit) | (1UL << mirror)))
			return (v & (1UL << bit)) ? bit : mirror;

		if (!((v >> (bit & scope)) & halves[scale] & halfword))
			bit = mirror;
	}
	return bit;
}

int main(int argc, char **argv)
{
	unsigned long mask;
	int bit;

	if (argc < 2) {
		unsigned long long tests = 0;
		int ret;

		while (1) {
			mask = statistical_prng(); // note: cannot be zero
			bit = statistical_prng() % (sizeof(long) * 8);
			ret = one_among(mask, bit);
			if (ret < 0 || !((mask >> ret) & 1))
				printf("###ERR### mask=%#lx bit=%d ret=%d\n", mask, bit, ret);
			if (!(tests & 0xffffff))
				printf("count=%Ld mask=%lx bit=%d ret=%d\n", tests, mask, bit, ret);
			tests++;
		}
	}

	mask = atol(argv[1]);

	if (argc < 3) {
		for (bit = 0; bit < 8*sizeof(long); bit++)
			printf("v %#x bit %d best %d\n", mask, bit, one_among(mask, bit));
	} else {
		bit = atoi(argv[2]);
		printf("v %#x bit %d best %d\n", mask, bit, one_among(mask, bit));
	}
	return 0;
}
