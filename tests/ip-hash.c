/*
 * Integer hashing tests. These functions work with 32-bit integers, so are
 * perfectly suited for IPv4 addresses. A few tests show that they may also
 * be chained for larger keys (eg: IPv6), this way :
 *   f(x[0-3]) = f(f(f(f(x[0])^x[1])^x[2])^x[3])
 *
 * See also bob jenkin's site for more info on hashing, and check perfect
 * hashing for constants (eg: header names).
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>

#define NSERV   8
#define MAXLINE 1000


int counts_id[NSERV][NSERV];
uint32_t hash_id( uint32_t a)
{
	return a;
}

/* Full-avalanche integer hashing function from Thomas Wang, suitable for use
 * with a modulo. See below, worth a read !
 * http://www.concentric.net/~Ttwang/tech/inthash.htm
 *
 * See also tests performed by Bob Jenkins (says it's faster than his) :
 * http://burtleburtle.net/bob/hash/integer.html
 *
 * This function is small and fast. It does not seem as smooth as bj6 though.
 * About 0x40 bytes, 6 shifts.
 */
int counts_tw1[NSERV][NSERV];
uint32_t hash_tw1(uint32_t a)
{
	a += ~(a<<15);
	a ^=  (a>>10);
	a +=  (a<<3);
	a ^=  (a>>6);
	a += ~(a<<11);
	a ^=  (a>>16);
	return a;
}

/* Thomas Wang's mix function. The multiply is optimized away by the compiler
 * on most platforms.
 * It is about equivalent to the one above.
 */
int counts_tw2[NSERV][NSERV];
uint32_t hash_tw2(uint32_t a)
{
	a = ~a + (a << 15);
	a = a ^ (a >> 12);
	a = a + (a << 2);
	a = a ^ (a >> 4);
	a = a * 2057;
	a = a ^ (a >> 16);
	return a;
}

/* Thomas Wang's multiplicative hash function. About 0x30 bytes, and it is
 * extremely fast on recent processors with a fast multiply. However, it
 * must not be used on low bits only, as multiples of 0x00100010 only return
 * even values !
 */
int counts_tw3[NSERV][NSERV];
uint32_t hash_tw3(uint32_t a)
{
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
	return a;
}


/* Full-avalanche integer hashing function from Bob Jenkins, suitable for use
 * with a modulo. It has a very smooth distribution.
 * http://burtleburtle.net/bob/hash/integer.html
 * About 0x50 bytes, 6 shifts.
 */
int counts_bj6[NSERV][NSERV];
int counts_bj6x[NSERV][NSERV];
uint32_t hash_bj6(uint32_t a)
{
	a = (a+0x7ed55d16) + (a<<12);
	a = (a^0xc761c23c) ^ (a>>19);
	a = (a+0x165667b1) + (a<<5);
	a = (a+0xd3a2646c) ^ (a<<9);
	a = (a+0xfd7046c5) + (a<<3);
	a = (a^0xb55a4f09) ^ (a>>16);
	return a;
}

/* Similar function with one more shift and no magic number. It is slightly
 * slower but provides the overall smoothest distribution.
 * About 0x40 bytes, 7 shifts.
 */
int counts_bj7[NSERV][NSERV];
int counts_bj7x[NSERV][NSERV];
uint32_t hash_bj7(uint32_t a)
{
	a -= (a<<6);
	a ^= (a>>17);
	a -= (a<<9);
	a ^= (a<<4);
	a -= (a<<3);
	a ^= (a<<10);
	a ^= (a>>15);
	return a;
}


void count_hash_results(unsigned long hash, int counts[NSERV][NSERV]) {
	int srv, nsrv;
    
	for (nsrv = 0; nsrv < NSERV; nsrv++) {
		srv = hash % (nsrv + 1);
		counts[nsrv][srv]++;
	}
}

void dump_hash_results(char *name, int counts[NSERV][NSERV]) {
	int srv, nsrv;
	double err, total_err, max_err;

	printf("%s:\n", name);
	for (nsrv = 0; nsrv < NSERV; nsrv++) {
		total_err = 0.0;
		max_err = 0.0;
		printf("%02d srv: ", nsrv+1);
		for (srv = 0; srv <= nsrv; srv++) {
			err = 100.0*(counts[nsrv][srv] - (double)counts[0][0]/(nsrv+1)) / (double)counts[0][0];
			//printf("%6d ", counts[nsrv][srv]);
			printf("% 3.1f%%%c ", err,
			       counts[nsrv][srv]?' ':'*');  /* display '*' when a server is never selected */
			err = fabs(err);
			total_err += err;
			if (err > max_err)
				max_err = err;
		}
		total_err /= (double)(nsrv+1);
		for (srv = nsrv+1; srv < NSERV; srv++)
			printf("       ");
		printf("  avg_err=%3.1f, max_err=%3.1f\n", total_err, max_err);
	}
	printf("\n");
}

int main() {
	int nr;
	unsigned int address = 0;
	unsigned int mask = ~0;

	memset(counts_id, 0, sizeof(counts_id));
	memset(counts_tw1, 0, sizeof(counts_tw1));
	memset(counts_tw2, 0, sizeof(counts_tw2));
	memset(counts_tw3, 0, sizeof(counts_tw3));
	memset(counts_bj6, 0, sizeof(counts_bj6));
	memset(counts_bj7, 0, sizeof(counts_bj7));

	address = 0x10000000;
	mask = 0xffffff00;  // user mask to apply to addresses
	for (nr = 0; nr < 0x10; nr++) {
		//address += ~nr;  // semi-random addresses.
		//address += 1;
		address += 0x00000100;
		//address += 0x11111111;
		//address += 7;
		//address += 8;
		//address += 256;
		//address += 65536;
		//address += 131072;
		//address += 0x00100010;   // this increment kills tw3 !
		count_hash_results(hash_id (address & mask), counts_id);   // 0.69s / 100M
		count_hash_results(hash_tw1(address & mask), counts_tw1);  // 1.04s / 100M
		count_hash_results(hash_tw2(address & mask), counts_tw2);  // 1.13s / 100M
		count_hash_results(hash_tw3(address & mask), counts_tw3);  // 1.01s / 100M
		count_hash_results(hash_bj6(address & mask), counts_bj6);  // 1.07s / 100M
		count_hash_results(hash_bj7(address & mask), counts_bj7);  // 1.20s / 100M
		/* adding the original address after the hash reduces the error
		 * rate in in presence of very small data sets (eg: 16 source
		 * addresses for 8 servers). In this case, bj7 is very good.
		 */
		count_hash_results(hash_bj6(address & mask)+(address&mask), counts_bj6x); // 1.07s / 100M
		count_hash_results(hash_bj7(address & mask)+(address&mask), counts_bj7x); // 1.20s / 100M
	}

	dump_hash_results("hash_id", counts_id);
	dump_hash_results("hash_tw1", counts_tw1);
	dump_hash_results("hash_tw2", counts_tw2);
	dump_hash_results("hash_tw3", counts_tw3);
	dump_hash_results("hash_bj6", counts_bj6);
	dump_hash_results("hash_bj6x", counts_bj6x);
	dump_hash_results("hash_bj7", counts_bj7);
	dump_hash_results("hash_bj7x", counts_bj7x);
	return 0;
}
