/* Brute-force based perfect hash generator for small sets of integers. Just
 * fill the table below with the integer values, try to pad a little bit to
 * avoid too complicated divides, experiment with a few operations in the
 * hash function and reuse the output as-is to make your table. You may also
 * want to experiment with the random generator to use either one or two
 * distinct values for mul and key.
 */

#include <stdio.h>
#include <stdlib.h>

/* warning no more than 32 distinct values! */

//#define CODES 21
//#define CODES 20
//#define CODES 19
//const int codes[CODES] = { 200,400,401,403,404,405,407,408,410,413,421,422,425,429,500,501,502,503,504};

#define CODES 32
const int codes[CODES] = { 200,400,401,403,404,405,407,408,410,413,414,421,422,425,429,431,500,501,502,503,504,
	/* padding entries below, which will fall back to the default code */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

unsigned mul, xor;
unsigned bmul = 0, bxor = 0;

static unsigned rnd32seed = 0x11111111U;
static unsigned rnd32()
{
        rnd32seed ^= rnd32seed << 13;
        rnd32seed ^= rnd32seed >> 17;
        rnd32seed ^= rnd32seed << 5;
        return rnd32seed;
}

/* the hash function to use in the target code. Try various combinations of
 * multiplies and xor, always folded with a modulo, and try to spot the
 * simplest operations if possible. Sometimes it may be worth adding a few
 * dummy codes to get a better modulo code. In this case, just add dummy
 * values at the end, but always distinct from the original ones. If the
 * number of codes is even, it might be needed to rotate left the result
 * before the modulo to compensate for lost LSBs.
 */
unsigned hash(unsigned i)
{
	//return ((i * mul) - (i ^ xor)) % CODES; // more solutions
	//return ((i * mul) + (i ^ xor)) % CODES; // alternate
	//return ((i ^ xor) * mul) % CODES; // less solutions but still OK for sequences up to 19 long
	//return ((i * mul) ^ xor) % CODES; // less solutions but still OK for sequences up to 19 long

	i = i * mul;
	i >>= 5;
	//i = i ^ xor;
	//i = (i << 30) | (i >> 2); // rotate 2 right
	//i = (i << 2) | (i >> 30); // rotate 2 left
	//i |= i >> 20;
	//i += i >> 30;
	//i |= i >> 16;
	return i % CODES;
	//return ((i * mul) ^ xor) % CODES; // less solutions but still OK for sequences up to 19 long
}

int main(int argc, char **argv)
{
	unsigned h, i, flag, best, tests;

	if (argc > 2) {
		mul = atol(argv[1]);
		xor = atol(argv[2]);
		for (i = 0; i < CODES && codes[i] >= 0; i++)
			printf("hash(%4u) = %4u   //   [%4u] = %4u\n", codes[i], hash(codes[i]), hash(codes[i]), codes[i]);
		return 0;
	}

	tests = 0;
	best = 0;
	while (/*best < CODES &&*/ ++tests) {
		mul = rnd32();
		xor = mul;  // works for some sequences up to 21 long
		//xor = rnd32(); // more solutions

		flag = 0;
		for (i = 0; i < CODES && codes[i] >= 0; i++) {
			h = hash(codes[i]);
			if (flag & (1 << h))
				break;
			flag |= 1 << h;
		}

		if (i > best ||
		    (i == best && mul <= bmul && xor <= bxor)) {
			/* find the best code and try to find the smallest
			 * parameters among the best ones (need to disable
			 * best<CODES in the loop for this). Small values are
			 * interesting for some multipliers, and for some RISC
			 * architectures where literals can be loaded in less
			 * instructions.
			 */
			best = i;
			bmul = mul;
			bxor = xor;
			printf("%u: mul=%u xor=%u\n", best, bmul, bxor);
		}

		if ((tests & 0x7ffff) == 0)
			printf("%u tests...\r", tests);
	}
	printf("%u tests, %u vals with mul=%u xor=%u:\n", tests, best, bmul, bxor);

	mul = bmul; xor = bxor;
	for (i = 0; i < CODES && codes[i] >= 0; i++)
		printf("hash(%4u) = %2u   //   [%2u] = %4u\n", codes[i], hash(codes[i]), hash(codes[i]), codes[i]);
}
