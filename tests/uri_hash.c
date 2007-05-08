#include <stdio.h>

#define NSERV   10
#define MAXLINE 1000

char line[MAXLINE];

int counts_gd1[NSERV][NSERV];
static unsigned long hash_gd1(char *uri)
{
    unsigned long hash = 0;
    int c;

    while (c = *uri++)
        hash = c + (hash << 6) + (hash << 16) - hash;

    return hash;
}

int counts_gd2[NSERV][NSERV];
static unsigned long hash_gd2(char *uri)
{
    unsigned long hash = 0;
    int c;

    while (c = *uri++) {
	if (c == '?' || c == '\n')
	    break;
        hash = c + (hash << 6) + (hash << 16) - hash;
    }

    return hash;
}


int counts_gd3[NSERV][NSERV];
static unsigned long hash_gd3(char *uri)
{
    unsigned long hash = 0;
    int c;

    while (c = *uri++) {
	if (c == '?' || c == '\n')
	    break;
        hash = c - (hash << 3) + (hash << 15) - hash;
    }

    return hash;
}


int counts_gd4[NSERV][NSERV];
static unsigned long hash_gd4(char *uri)
{
    unsigned long hash = 0;
    int c;

    while (c = *uri++) {
	if (c == '?' || c == '\n')
	    break;
        hash = hash + (hash << 6) - (hash << 15) - c;
    }

    return hash;
}


int counts_gd5[NSERV][NSERV];
static unsigned long hash_gd5(char *uri)
{
    unsigned long hash = 0;
    int c;

    while (c = *uri++) {
	if (c == '?' || c == '\n')
	    break;
        hash = hash + (hash << 2) - (hash << 19) - c;
    }

    return hash;
}


int counts_gd6[NSERV][NSERV];
static unsigned long hash_gd6(char *uri)
{
    unsigned long hash = 0;
    int c;

    while (c = *uri++) {
	if (c == '?' || c == '\n')
	    break;
        hash = hash + (hash << 2) - (hash << 22) - c;
    }

    return hash;
}


int counts_wt1[NSERV][NSERV];
static unsigned long hash_wt1(int hsize, char *string) {
    int bits;
    unsigned long data, val;

    bits = val = data = 0;
    while (*string) {
	if (*string == '?' || *string == '\n')
	    break;
        data |= ((unsigned long)(unsigned char)*string) << bits;
        bits += 8;
        while (bits >= hsize) {
            val ^= data - (val >> hsize);
            bits -= hsize;
            data >>= hsize;
        }
        string++;
    }
    val ^= data;
    while (val > ((1 << hsize) - 1)) {
        val = (val & ((1 << hsize) - 1)) ^ (val >> hsize);
    }
    return val;
}

/*
 * efficient hash : no duplicate on the first 65536 values of 2 bytes.
 * less than 0.1% duplicates for the first 1.6 M values of 3 bytes.
 */
int counts_wt2[NSERV][NSERV];
typedef unsigned int u_int32_t;

static inline u_int32_t shl32(u_int32_t i, int count) {
	if (count == 32)
		return 0;
	return i << count;
}

static inline u_int32_t shr32(u_int32_t i, int count) {
	if (count == 32)
		return 0;
	return i >> count;
}

static unsigned int rev32(unsigned int c) {
	c = ((c & 0x0000FFFF) << 16)| ((c & 0xFFFF0000) >> 16);
	c = ((c & 0x00FF00FF) << 8) | ((c & 0xFF00FF00) >> 8);
	c = ((c & 0x0F0F0F0F) << 4) | ((c & 0xF0F0F0F0) >> 4);
	c = ((c & 0x33333333) << 2) | ((c & 0xCCCCCCCC) >> 2);
	c = ((c & 0x55555555) << 1) | ((c & 0xAAAAAAAA) >> 1);
	return c;
}

int hash_wt2(const char *src, int len) {
	unsigned int i = 0x3C964BA5; /* as many ones as zeroes */
	unsigned int j, k;
	unsigned int ih, il;
	int bit;

	while (len--) {
		j = (unsigned char)*src++;
		if (j == '?' || j == '\n')
		    break;
		bit = rev32(j - i);
		bit = bit - (bit >> 3) + (bit >> 16) - j;

		bit &= 0x1f;
		ih = shr32(i, bit);
		il = i & (shl32(1, bit) - 1);
		i = shl32(il, 32-bit) - ih - ~j;
	}
	return i;
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

    printf("%s:\n", name);
    for (nsrv = 0; nsrv < NSERV; nsrv++) {
	printf("%02d srv: ", nsrv+1);
	for (srv = 0; srv <= nsrv; srv++) {
	    //printf("%6d ", counts[nsrv][srv]);
	    //printf("%3.1f ", (100.0*counts[nsrv][srv]) / (double)counts[0][0]);
	    printf("%3.1f ", 100.0*(counts[nsrv][srv] - (double)counts[0][0]/(nsrv+1)) / (double)counts[0][0]);
	}
	printf("\n");
    }
    printf("\n");
}

main() {
    memset(counts_gd1, 0, sizeof(counts_gd1));
    memset(counts_gd2, 0, sizeof(counts_gd2));
    memset(counts_gd3, 0, sizeof(counts_gd3));
    memset(counts_gd4, 0, sizeof(counts_gd4));
    memset(counts_gd5, 0, sizeof(counts_gd5));
    memset(counts_gd6, 0, sizeof(counts_gd6));
    memset(counts_wt1, 0, sizeof(counts_wt1));
    memset(counts_wt2, 0, sizeof(counts_wt2));

    while (fgets(line, MAXLINE, stdin) != NULL) {
	count_hash_results(hash_gd1(line), counts_gd1);
	count_hash_results(hash_gd2(line), counts_gd2);
	count_hash_results(hash_gd3(line), counts_gd3);
	count_hash_results(hash_gd4(line), counts_gd4);
	count_hash_results(hash_gd5(line), counts_gd5);
	count_hash_results(hash_gd6(line), counts_gd6);
	count_hash_results(hash_wt1(31, line), counts_wt1);
	count_hash_results(hash_wt2(line, strlen(line)), counts_wt2);
    }

    dump_hash_results("hash_gd1", counts_gd1);
    dump_hash_results("hash_gd2", counts_gd2);
    dump_hash_results("hash_gd3", counts_gd3);
    dump_hash_results("hash_gd4", counts_gd4);
    dump_hash_results("hash_gd5", counts_gd5);
    dump_hash_results("hash_gd6", counts_gd6);
    dump_hash_results("hash_wt1", counts_wt1);
    dump_hash_results("hash_wt2", counts_wt2);
}
