#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define NSERV   10
#define MAXLINE 1000

char line[MAXLINE];

int counts_gd1[NSERV][NSERV];
static unsigned long hash_gd1(char *uri)
{
    unsigned long hash = 0;
    int c;

    while ((c = *uri++))
        hash = c + (hash << 6) + (hash << 16) - hash;

    return hash;
}

int counts_gd2[NSERV][NSERV];
static unsigned long hash_gd2(char *uri)
{
    unsigned long hash = 0;
    int c;

    while ((c = *uri++)) {
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

    while ((c = *uri++)) {
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

    while ((c = *uri++)) {
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

    while ((c = *uri++)) {
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

    while ((c = *uri++)) {
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
	unsigned int j;
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


//typedef unsigned int uint32_t;
//typedef unsigned short uint8_t;
//typedef unsigned char uint16_t;

/*
 * http://www.azillionmonkeys.com/qed/hash.html
 */
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

/*
 * This function has a hole of 11 unused bits in bytes 2 and 3 of each block of
 * 32 bits.
 */
int counts_SuperFastHash[NSERV][NSERV];

uint32_t SuperFastHash (const char * data, int len) {
uint32_t hash = len, tmp;
int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= data[sizeof (uint16_t)] << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += *data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

/*
 * This variant uses all bits from the input block, and is about 15% faster.
 */
int counts_SuperFastHash2[NSERV][NSERV];
uint32_t SuperFastHash2 (const char * data, int len) {
uint32_t hash = len, tmp;
int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
	register uint32_t next;
	next   = get16bits(data+2);
        hash  += get16bits(data);
        tmp    = ((next << 11) | (next >> 21)) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= data[sizeof (uint16_t)] << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += *data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

/* len 4 for ipv4 and 16 for ipv6 */
int counts_srv[NSERV][NSERV];
unsigned int haproxy_server_hash(const char *addr, int len){
  unsigned int h, l;
  l = h = 0;

  while ((l + sizeof (int)) <= len) {
    h ^= ntohl(*(unsigned int *)(&addr[l]));
    l += sizeof (int);
  }
  return h;
}/* end haproxy_server_hash() */



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

int main() {
    memset(counts_gd1, 0, sizeof(counts_gd1));
    memset(counts_gd2, 0, sizeof(counts_gd2));
    memset(counts_gd3, 0, sizeof(counts_gd3));
    memset(counts_gd4, 0, sizeof(counts_gd4));
    memset(counts_gd5, 0, sizeof(counts_gd5));
    memset(counts_gd6, 0, sizeof(counts_gd6));
    memset(counts_wt1, 0, sizeof(counts_wt1));
    memset(counts_wt2, 0, sizeof(counts_wt2));
    memset(counts_srv, 0, sizeof(counts_srv));
    memset(counts_SuperFastHash, 0, sizeof(counts_SuperFastHash));
    memset(counts_SuperFastHash2, 0, sizeof(counts_SuperFastHash2));

    while (fgets(line, MAXLINE, stdin) != NULL) {
	count_hash_results(hash_gd1(line), counts_gd1);
	count_hash_results(hash_gd2(line), counts_gd2);
	count_hash_results(hash_gd3(line), counts_gd3);
	count_hash_results(hash_gd4(line), counts_gd4);
	count_hash_results(hash_gd5(line), counts_gd5);
	count_hash_results(hash_gd6(line), counts_gd6);
	count_hash_results(hash_wt1(31, line), counts_wt1);
	count_hash_results(hash_wt2(line, strlen(line)), counts_wt2);
	count_hash_results(haproxy_server_hash(line, strlen(line)), counts_srv);
	count_hash_results(SuperFastHash(line, strlen(line)), counts_SuperFastHash);
	count_hash_results(SuperFastHash2(line, strlen(line)), counts_SuperFastHash2);
    }

    dump_hash_results("hash_gd1", counts_gd1);
    dump_hash_results("hash_gd2", counts_gd2);
    dump_hash_results("hash_gd3", counts_gd3);
    dump_hash_results("hash_gd4", counts_gd4);
    dump_hash_results("hash_gd5", counts_gd5);
    dump_hash_results("hash_gd6", counts_gd6);
    dump_hash_results("hash_wt1", counts_wt1);
    dump_hash_results("hash_wt2", counts_wt2);
    dump_hash_results("haproxy_server_hash", counts_srv);
    dump_hash_results("SuperFastHash", counts_SuperFastHash);
    dump_hash_results("SuperFastHash2", counts_SuperFastHash2);

    return 0;
}
