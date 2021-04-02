/* Reverse Huffman table generator for HPACK decoder - 2017-05-19 Willy Tarreau
 *
 * rht_bit31_24[256]   is indexed on bits 31..24 when < 0xfe
 * rht_bit24_17[256]   is indexed on bits 24..17 when 31..24 >= 0xfe
 * rht_bit15_11_fe[32] is indexed on bits 15..11 when 24..17 == 0xfe
 * rht_bit15_8[256]    is indexed on bits 15..8 when 24..17 == 0xff
 * rht_bit11_4[256]    is indexed on bits 11..4 when 15..8 == 0xff
 * when 11..4 == 0xff, 3..2 provide the following mapping :
 *   00 => 0x0a, 01 => 0x0d, 10 => 0x16, 11 => EOS
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* from RFC7541 Appendix B */
static const struct huff {
	uint32_t c; /* code point */
	int b;      /* bits */
} ht[257] = {
	[0] = { .c = 0x00001ff8, .b = 13 },
	[1] = { .c = 0x007fffd8, .b = 23 },
	[2] = { .c = 0x0fffffe2, .b = 28 },
	[3] = { .c = 0x0fffffe3, .b = 28 },
	[4] = { .c = 0x0fffffe4, .b = 28 },
	[5] = { .c = 0x0fffffe5, .b = 28 },
	[6] = { .c = 0x0fffffe6, .b = 28 },
	[7] = { .c = 0x0fffffe7, .b = 28 },
	[8] = { .c = 0x0fffffe8, .b = 28 },
	[9] = { .c = 0x00ffffea, .b = 24 },
	[10] = { .c = 0x3ffffffc, .b = 30 },
	[11] = { .c = 0x0fffffe9, .b = 28 },
	[12] = { .c = 0x0fffffea, .b = 28 },
	[13] = { .c = 0x3ffffffd, .b = 30 },
	[14] = { .c = 0x0fffffeb, .b = 28 },
	[15] = { .c = 0x0fffffec, .b = 28 },
	[16] = { .c = 0x0fffffed, .b = 28 },
	[17] = { .c = 0x0fffffee, .b = 28 },
	[18] = { .c = 0x0fffffef, .b = 28 },
	[19] = { .c = 0x0ffffff0, .b = 28 },
	[20] = { .c = 0x0ffffff1, .b = 28 },
	[21] = { .c = 0x0ffffff2, .b = 28 },
	[22] = { .c = 0x3ffffffe, .b = 30 },
	[23] = { .c = 0x0ffffff3, .b = 28 },
	[24] = { .c = 0x0ffffff4, .b = 28 },
	[25] = { .c = 0x0ffffff5, .b = 28 },
	[26] = { .c = 0x0ffffff6, .b = 28 },
	[27] = { .c = 0x0ffffff7, .b = 28 },
	[28] = { .c = 0x0ffffff8, .b = 28 },
	[29] = { .c = 0x0ffffff9, .b = 28 },
	[30] = { .c = 0x0ffffffa, .b = 28 },
	[31] = { .c = 0x0ffffffb, .b = 28 },
	[32] = { .c = 0x00000014, .b =  6 },
	[33] = { .c = 0x000003f8, .b = 10 },
	[34] = { .c = 0x000003f9, .b = 10 },
	[35] = { .c = 0x00000ffa, .b = 12 },
	[36] = { .c = 0x00001ff9, .b = 13 },
	[37] = { .c = 0x00000015, .b =  6 },
	[38] = { .c = 0x000000f8, .b =  8 },
	[39] = { .c = 0x000007fa, .b = 11 },
	[40] = { .c = 0x000003fa, .b = 10 },
	[41] = { .c = 0x000003fb, .b = 10 },
	[42] = { .c = 0x000000f9, .b =  8 },
	[43] = { .c = 0x000007fb, .b = 11 },
	[44] = { .c = 0x000000fa, .b =  8 },
	[45] = { .c = 0x00000016, .b =  6 },
	[46] = { .c = 0x00000017, .b =  6 },
	[47] = { .c = 0x00000018, .b =  6 },
	[48] = { .c = 0x00000000, .b =  5 },
	[49] = { .c = 0x00000001, .b =  5 },
	[50] = { .c = 0x00000002, .b =  5 },
	[51] = { .c = 0x00000019, .b =  6 },
	[52] = { .c = 0x0000001a, .b =  6 },
	[53] = { .c = 0x0000001b, .b =  6 },
	[54] = { .c = 0x0000001c, .b =  6 },
	[55] = { .c = 0x0000001d, .b =  6 },
	[56] = { .c = 0x0000001e, .b =  6 },
	[57] = { .c = 0x0000001f, .b =  6 },
	[58] = { .c = 0x0000005c, .b =  7 },
	[59] = { .c = 0x000000fb, .b =  8 },
	[60] = { .c = 0x00007ffc, .b = 15 },
	[61] = { .c = 0x00000020, .b =  6 },
	[62] = { .c = 0x00000ffb, .b = 12 },
	[63] = { .c = 0x000003fc, .b = 10 },
	[64] = { .c = 0x00001ffa, .b = 13 },
	[65] = { .c = 0x00000021, .b =  6 },
	[66] = { .c = 0x0000005d, .b =  7 },
	[67] = { .c = 0x0000005e, .b =  7 },
	[68] = { .c = 0x0000005f, .b =  7 },
	[69] = { .c = 0x00000060, .b =  7 },
	[70] = { .c = 0x00000061, .b =  7 },
	[71] = { .c = 0x00000062, .b =  7 },
	[72] = { .c = 0x00000063, .b =  7 },
	[73] = { .c = 0x00000064, .b =  7 },
	[74] = { .c = 0x00000065, .b =  7 },
	[75] = { .c = 0x00000066, .b =  7 },
	[76] = { .c = 0x00000067, .b =  7 },
	[77] = { .c = 0x00000068, .b =  7 },
	[78] = { .c = 0x00000069, .b =  7 },
	[79] = { .c = 0x0000006a, .b =  7 },
	[80] = { .c = 0x0000006b, .b =  7 },
	[81] = { .c = 0x0000006c, .b =  7 },
	[82] = { .c = 0x0000006d, .b =  7 },
	[83] = { .c = 0x0000006e, .b =  7 },
	[84] = { .c = 0x0000006f, .b =  7 },
	[85] = { .c = 0x00000070, .b =  7 },
	[86] = { .c = 0x00000071, .b =  7 },
	[87] = { .c = 0x00000072, .b =  7 },
	[88] = { .c = 0x000000fc, .b =  8 },
	[89] = { .c = 0x00000073, .b =  7 },
	[90] = { .c = 0x000000fd, .b =  8 },
	[91] = { .c = 0x00001ffb, .b = 13 },
	[92] = { .c = 0x0007fff0, .b = 19 },
	[93] = { .c = 0x00001ffc, .b = 13 },
	[94] = { .c = 0x00003ffc, .b = 14 },
	[95] = { .c = 0x00000022, .b =  6 },
	[96] = { .c = 0x00007ffd, .b = 15 },
	[97] = { .c = 0x00000003, .b =  5 },
	[98] = { .c = 0x00000023, .b =  6 },
	[99] = { .c = 0x00000004, .b =  5 },
	[100] = { .c = 0x00000024, .b =  6 },
	[101] = { .c = 0x00000005, .b =  5 },
	[102] = { .c = 0x00000025, .b =  6 },
	[103] = { .c = 0x00000026, .b =  6 },
	[104] = { .c = 0x00000027, .b =  6 },
	[105] = { .c = 0x00000006, .b =  5 },
	[106] = { .c = 0x00000074, .b =  7 },
	[107] = { .c = 0x00000075, .b =  7 },
	[108] = { .c = 0x00000028, .b =  6 },
	[109] = { .c = 0x00000029, .b =  6 },
	[110] = { .c = 0x0000002a, .b =  6 },
	[111] = { .c = 0x00000007, .b =  5 },
	[112] = { .c = 0x0000002b, .b =  6 },
	[113] = { .c = 0x00000076, .b =  7 },
	[114] = { .c = 0x0000002c, .b =  6 },
	[115] = { .c = 0x00000008, .b =  5 },
	[116] = { .c = 0x00000009, .b =  5 },
	[117] = { .c = 0x0000002d, .b =  6 },
	[118] = { .c = 0x00000077, .b =  7 },
	[119] = { .c = 0x00000078, .b =  7 },
	[120] = { .c = 0x00000079, .b =  7 },
	[121] = { .c = 0x0000007a, .b =  7 },
	[122] = { .c = 0x0000007b, .b =  7 },
	[123] = { .c = 0x00007ffe, .b = 15 },
	[124] = { .c = 0x000007fc, .b = 11 },
	[125] = { .c = 0x00003ffd, .b = 14 },
	[126] = { .c = 0x00001ffd, .b = 13 },
	[127] = { .c = 0x0ffffffc, .b = 28 },
	[128] = { .c = 0x000fffe6, .b = 20 },
	[129] = { .c = 0x003fffd2, .b = 22 },
	[130] = { .c = 0x000fffe7, .b = 20 },
	[131] = { .c = 0x000fffe8, .b = 20 },
	[132] = { .c = 0x003fffd3, .b = 22 },
	[133] = { .c = 0x003fffd4, .b = 22 },
	[134] = { .c = 0x003fffd5, .b = 22 },
	[135] = { .c = 0x007fffd9, .b = 23 },
	[136] = { .c = 0x003fffd6, .b = 22 },
	[137] = { .c = 0x007fffda, .b = 23 },
	[138] = { .c = 0x007fffdb, .b = 23 },
	[139] = { .c = 0x007fffdc, .b = 23 },
	[140] = { .c = 0x007fffdd, .b = 23 },
	[141] = { .c = 0x007fffde, .b = 23 },
	[142] = { .c = 0x00ffffeb, .b = 24 },
	[143] = { .c = 0x007fffdf, .b = 23 },
	[144] = { .c = 0x00ffffec, .b = 24 },
	[145] = { .c = 0x00ffffed, .b = 24 },
	[146] = { .c = 0x003fffd7, .b = 22 },
	[147] = { .c = 0x007fffe0, .b = 23 },
	[148] = { .c = 0x00ffffee, .b = 24 },
	[149] = { .c = 0x007fffe1, .b = 23 },
	[150] = { .c = 0x007fffe2, .b = 23 },
	[151] = { .c = 0x007fffe3, .b = 23 },
	[152] = { .c = 0x007fffe4, .b = 23 },
	[153] = { .c = 0x001fffdc, .b = 21 },
	[154] = { .c = 0x003fffd8, .b = 22 },
	[155] = { .c = 0x007fffe5, .b = 23 },
	[156] = { .c = 0x003fffd9, .b = 22 },
	[157] = { .c = 0x007fffe6, .b = 23 },
	[158] = { .c = 0x007fffe7, .b = 23 },
	[159] = { .c = 0x00ffffef, .b = 24 },
	[160] = { .c = 0x003fffda, .b = 22 },
	[161] = { .c = 0x001fffdd, .b = 21 },
	[162] = { .c = 0x000fffe9, .b = 20 },
	[163] = { .c = 0x003fffdb, .b = 22 },
	[164] = { .c = 0x003fffdc, .b = 22 },
	[165] = { .c = 0x007fffe8, .b = 23 },
	[166] = { .c = 0x007fffe9, .b = 23 },
	[167] = { .c = 0x001fffde, .b = 21 },
	[168] = { .c = 0x007fffea, .b = 23 },
	[169] = { .c = 0x003fffdd, .b = 22 },
	[170] = { .c = 0x003fffde, .b = 22 },
	[171] = { .c = 0x00fffff0, .b = 24 },
	[172] = { .c = 0x001fffdf, .b = 21 },
	[173] = { .c = 0x003fffdf, .b = 22 },
	[174] = { .c = 0x007fffeb, .b = 23 },
	[175] = { .c = 0x007fffec, .b = 23 },
	[176] = { .c = 0x001fffe0, .b = 21 },
	[177] = { .c = 0x001fffe1, .b = 21 },
	[178] = { .c = 0x003fffe0, .b = 22 },
	[179] = { .c = 0x001fffe2, .b = 21 },
	[180] = { .c = 0x007fffed, .b = 23 },
	[181] = { .c = 0x003fffe1, .b = 22 },
	[182] = { .c = 0x007fffee, .b = 23 },
	[183] = { .c = 0x007fffef, .b = 23 },
	[184] = { .c = 0x000fffea, .b = 20 },
	[185] = { .c = 0x003fffe2, .b = 22 },
	[186] = { .c = 0x003fffe3, .b = 22 },
	[187] = { .c = 0x003fffe4, .b = 22 },
	[188] = { .c = 0x007ffff0, .b = 23 },
	[189] = { .c = 0x003fffe5, .b = 22 },
	[190] = { .c = 0x003fffe6, .b = 22 },
	[191] = { .c = 0x007ffff1, .b = 23 },
	[192] = { .c = 0x03ffffe0, .b = 26 },
	[193] = { .c = 0x03ffffe1, .b = 26 },
	[194] = { .c = 0x000fffeb, .b = 20 },
	[195] = { .c = 0x0007fff1, .b = 19 },
	[196] = { .c = 0x003fffe7, .b = 22 },
	[197] = { .c = 0x007ffff2, .b = 23 },
	[198] = { .c = 0x003fffe8, .b = 22 },
	[199] = { .c = 0x01ffffec, .b = 25 },
	[200] = { .c = 0x03ffffe2, .b = 26 },
	[201] = { .c = 0x03ffffe3, .b = 26 },
	[202] = { .c = 0x03ffffe4, .b = 26 },
	[203] = { .c = 0x07ffffde, .b = 27 },
	[204] = { .c = 0x07ffffdf, .b = 27 },
	[205] = { .c = 0x03ffffe5, .b = 26 },
	[206] = { .c = 0x00fffff1, .b = 24 },
	[207] = { .c = 0x01ffffed, .b = 25 },
	[208] = { .c = 0x0007fff2, .b = 19 },
	[209] = { .c = 0x001fffe3, .b = 21 },
	[210] = { .c = 0x03ffffe6, .b = 26 },
	[211] = { .c = 0x07ffffe0, .b = 27 },
	[212] = { .c = 0x07ffffe1, .b = 27 },
	[213] = { .c = 0x03ffffe7, .b = 26 },
	[214] = { .c = 0x07ffffe2, .b = 27 },
	[215] = { .c = 0x00fffff2, .b = 24 },
	[216] = { .c = 0x001fffe4, .b = 21 },
	[217] = { .c = 0x001fffe5, .b = 21 },
	[218] = { .c = 0x03ffffe8, .b = 26 },
	[219] = { .c = 0x03ffffe9, .b = 26 },
	[220] = { .c = 0x0ffffffd, .b = 28 },
	[221] = { .c = 0x07ffffe3, .b = 27 },
	[222] = { .c = 0x07ffffe4, .b = 27 },
	[223] = { .c = 0x07ffffe5, .b = 27 },
	[224] = { .c = 0x000fffec, .b = 20 },
	[225] = { .c = 0x00fffff3, .b = 24 },
	[226] = { .c = 0x000fffed, .b = 20 },
	[227] = { .c = 0x001fffe6, .b = 21 },
	[228] = { .c = 0x003fffe9, .b = 22 },
	[229] = { .c = 0x001fffe7, .b = 21 },
	[230] = { .c = 0x001fffe8, .b = 21 },
	[231] = { .c = 0x007ffff3, .b = 23 },
	[232] = { .c = 0x003fffea, .b = 22 },
	[233] = { .c = 0x003fffeb, .b = 22 },
	[234] = { .c = 0x01ffffee, .b = 25 },
	[235] = { .c = 0x01ffffef, .b = 25 },
	[236] = { .c = 0x00fffff4, .b = 24 },
	[237] = { .c = 0x00fffff5, .b = 24 },
	[238] = { .c = 0x03ffffea, .b = 26 },
	[239] = { .c = 0x007ffff4, .b = 23 },
	[240] = { .c = 0x03ffffeb, .b = 26 },
	[241] = { .c = 0x07ffffe6, .b = 27 },
	[242] = { .c = 0x03ffffec, .b = 26 },
	[243] = { .c = 0x03ffffed, .b = 26 },
	[244] = { .c = 0x07ffffe7, .b = 27 },
	[245] = { .c = 0x07ffffe8, .b = 27 },
	[246] = { .c = 0x07ffffe9, .b = 27 },
	[247] = { .c = 0x07ffffea, .b = 27 },
	[248] = { .c = 0x07ffffeb, .b = 27 },
	[249] = { .c = 0x0ffffffe, .b = 28 },
	[250] = { .c = 0x07ffffec, .b = 27 },
	[251] = { .c = 0x07ffffed, .b = 27 },
	[252] = { .c = 0x07ffffee, .b = 27 },
	[253] = { .c = 0x07ffffef, .b = 27 },
	[254] = { .c = 0x07fffff0, .b = 27 },
	[255] = { .c = 0x03ffffee, .b = 26 },
	[256] = { .c = 0x3fffffff, .b = 30 }, /* EOS */
};


int main(int argc, char **argv)
{
	uint32_t c, i, j;

	/* fill first byte */
	printf("struct rht rht_bit31_24[256] = {\n");
	for (j = 0; j < 256; j++) {
		for (i = 0; i < sizeof(ht)/sizeof(ht[0]); i++) {
			if (ht[i].b > 8)
				continue;
			c = ht[i].c << (32 - ht[i].b);

			if (((c ^ (j << 24)) & -(1 << (32 - ht[i].b)) & 0xff000000) == 0) {
				printf("\t[0x%02x] = { .c = 0x%02x, .l = %d },\n", j, i, ht[i].b);
				break;
			}
		}
	}
	printf("};\n\n");

	printf("struct rht rht_bit24_17[256] = {\n");
	for (j = 0; j < 256; j++) {
		for (i = 0; i < sizeof(ht)/sizeof(ht[0]); i++) {
			if (ht[i].b <= 8 || ht[i].b > 16)
				continue;
			c = ht[i].c << (32 - ht[i].b);

			if (((c ^ (j << 17)) & -(1 << (32 - ht[i].b)) & 0x01fe0000) == 0) {
				printf("\t[0x%02x] = { .c = 0x%02x, .l = %d },\n", j, i, ht[i].b);
				break;
			}
		}
	}
	printf("};\n\n");

	printf("struct rht rht_bit15_11_fe[32] = {\n");
	for (j = 0; j < 32; j++) {
		for (i = 0; i < sizeof(ht)/sizeof(ht[0]); i++) {
			if (ht[i].b <= 16 || ht[i].b > 21)
				continue;
			c = ht[i].c << (32 - ht[i].b);
			if ((c & 0x00ff0000) != 0x00fe0000)
				continue;

			if (((c ^ (j << 11)) & -(1 << (32 - ht[i].b)) & 0x0000f800) == 0) {
				printf("\t[0x%02x] = { .c = 0x%02x, .l = %d },\n", j, i, ht[i].b);
				break;
			}
		}
	}
	printf("};\n\n");

	printf("struct rht rht_bit15_8[256] = {\n");
	for (j = 0; j < 256; j++) {
		for (i = 0; i < sizeof(ht)/sizeof(ht[0]); i++) {
			if (ht[i].b <= 16 || ht[i].b > 24)
				continue;
			c = ht[i].c << (32 - ht[i].b);
			if ((c & 0x00ff0000) != 0x00ff0000)
				continue;

			if (((c ^ (j << 8)) & -(1 << (32 - ht[i].b)) & 0x0000ff00) == 0) {
				printf("\t[0x%02x] = { .c = 0x%02x, .l = %d },\n", j, i, ht[i].b);
				break;
			}
		}
	}
	printf("};\n\n");

	printf("struct rht rht_bit11_4[256] = {\n");
	/* fill fourth byte after 0xff 0xff 0xf6-0xff. Only 0xfffffffx are not distinguished */
	for (j = 0; j < 256; j++) {
		for (i = 0; i < sizeof(ht)/sizeof(ht[0]); i++) {
			if (ht[i].b <= 24)
				continue;
			c = ht[i].c << (32 - ht[i].b);

			if (((c ^ (j << 4)) & -(1 << (32 - ht[i].b)) & 0x00000ff0) == 0) {
				//printf("\tj=%02x i=%02x c=%08x l=%d c/l=%08x j/l=%08x xor=%08x\n", j, i, c, ht[i].b, c & -(1 << (32 - ht[i].b)), ((j << 4) & -(1 << (32 - ht[i].b))), (c ^ (j << 4)) & -(1 << (32 - ht[i].b)));
				printf("\t[0x%02x] = { .c = 0x%02x, .l = %d },\n", j, i, ht[i].b);
				break;
			}
		}
	}
	printf("\t/* Note, when l==30, bits 3..2 give 00:0x0a, 01:0x0d, 10:0x16, 11:EOS */\n");
	printf("};\n\n");
	return 0;
}
