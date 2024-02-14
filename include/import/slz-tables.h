#include <inttypes.h>

/* Fixed Huffman table as per RFC1951.
 *
 *       Lit Value    Bits        Codes
 *       ---------    ----        -----
 *         0 - 143     8          00110000 through  10111111
 *       144 - 255     9         110010000 through 111111111
 *       256 - 279     7           0000000 through   0010111
 *       280 - 287     8          11000000 through  11000111
 *
 * The codes are encoded in reverse, the high bit of the code appears encoded
 * as bit 0. The table is built by mkhuff.sh. The 16 bits are encoded this way :
 *  - bits 0..3  : bits
 *  - bits 4..12 : code
 */
static const uint16_t fixed_huff[288] = {
	0x00c8, 0x08c8, 0x04c8, 0x0cc8, 0x02c8, 0x0ac8, 0x06c8, 0x0ec8, //   0
	0x01c8, 0x09c8, 0x05c8, 0x0dc8, 0x03c8, 0x0bc8, 0x07c8, 0x0fc8, //   8
	0x0028, 0x0828, 0x0428, 0x0c28, 0x0228, 0x0a28, 0x0628, 0x0e28, //  16
	0x0128, 0x0928, 0x0528, 0x0d28, 0x0328, 0x0b28, 0x0728, 0x0f28, //  24
	0x00a8, 0x08a8, 0x04a8, 0x0ca8, 0x02a8, 0x0aa8, 0x06a8, 0x0ea8, //  32
	0x01a8, 0x09a8, 0x05a8, 0x0da8, 0x03a8, 0x0ba8, 0x07a8, 0x0fa8, //  40
	0x0068, 0x0868, 0x0468, 0x0c68, 0x0268, 0x0a68, 0x0668, 0x0e68, //  48
	0x0168, 0x0968, 0x0568, 0x0d68, 0x0368, 0x0b68, 0x0768, 0x0f68, //  56
	0x00e8, 0x08e8, 0x04e8, 0x0ce8, 0x02e8, 0x0ae8, 0x06e8, 0x0ee8, //  64
	0x01e8, 0x09e8, 0x05e8, 0x0de8, 0x03e8, 0x0be8, 0x07e8, 0x0fe8, //  72
	0x0018, 0x0818, 0x0418, 0x0c18, 0x0218, 0x0a18, 0x0618, 0x0e18, //  80
	0x0118, 0x0918, 0x0518, 0x0d18, 0x0318, 0x0b18, 0x0718, 0x0f18, //  88
	0x0098, 0x0898, 0x0498, 0x0c98, 0x0298, 0x0a98, 0x0698, 0x0e98, //  96
	0x0198, 0x0998, 0x0598, 0x0d98, 0x0398, 0x0b98, 0x0798, 0x0f98, // 104
	0x0058, 0x0858, 0x0458, 0x0c58, 0x0258, 0x0a58, 0x0658, 0x0e58, // 112
	0x0158, 0x0958, 0x0558, 0x0d58, 0x0358, 0x0b58, 0x0758, 0x0f58, // 120
	0x00d8, 0x08d8, 0x04d8, 0x0cd8, 0x02d8, 0x0ad8, 0x06d8, 0x0ed8, // 128
	0x01d8, 0x09d8, 0x05d8, 0x0dd8, 0x03d8, 0x0bd8, 0x07d8, 0x0fd8, // 136
	0x0139, 0x1139, 0x0939, 0x1939, 0x0539, 0x1539, 0x0d39, 0x1d39, // 144
	0x0339, 0x1339, 0x0b39, 0x1b39, 0x0739, 0x1739, 0x0f39, 0x1f39, // 152
	0x00b9, 0x10b9, 0x08b9, 0x18b9, 0x04b9, 0x14b9, 0x0cb9, 0x1cb9, // 160
	0x02b9, 0x12b9, 0x0ab9, 0x1ab9, 0x06b9, 0x16b9, 0x0eb9, 0x1eb9, // 168
	0x01b9, 0x11b9, 0x09b9, 0x19b9, 0x05b9, 0x15b9, 0x0db9, 0x1db9, // 176
	0x03b9, 0x13b9, 0x0bb9, 0x1bb9, 0x07b9, 0x17b9, 0x0fb9, 0x1fb9, // 184
	0x0079, 0x1079, 0x0879, 0x1879, 0x0479, 0x1479, 0x0c79, 0x1c79, // 192
	0x0279, 0x1279, 0x0a79, 0x1a79, 0x0679, 0x1679, 0x0e79, 0x1e79, // 200
	0x0179, 0x1179, 0x0979, 0x1979, 0x0579, 0x1579, 0x0d79, 0x1d79, // 208
	0x0379, 0x1379, 0x0b79, 0x1b79, 0x0779, 0x1779, 0x0f79, 0x1f79, // 216
	0x00f9, 0x10f9, 0x08f9, 0x18f9, 0x04f9, 0x14f9, 0x0cf9, 0x1cf9, // 224
	0x02f9, 0x12f9, 0x0af9, 0x1af9, 0x06f9, 0x16f9, 0x0ef9, 0x1ef9, // 232
	0x01f9, 0x11f9, 0x09f9, 0x19f9, 0x05f9, 0x15f9, 0x0df9, 0x1df9, // 240
	0x03f9, 0x13f9, 0x0bf9, 0x1bf9, 0x07f9, 0x17f9, 0x0ff9, 0x1ff9, // 248
	0x0007, 0x0407, 0x0207, 0x0607, 0x0107, 0x0507, 0x0307, 0x0707, // 256
	0x0087, 0x0487, 0x0287, 0x0687, 0x0187, 0x0587, 0x0387, 0x0787, // 264
	0x0047, 0x0447, 0x0247, 0x0647, 0x0147, 0x0547, 0x0347, 0x0747, // 272
	0x0038, 0x0838, 0x0438, 0x0c38, 0x0238, 0x0a38, 0x0638, 0x0e38  // 280
};

/* length from 3 to 258 converted to bit strings for use with fixed huffman
 * coding. It was built by tools/dump_len.c. The format is the following :
 *   - bits 0..15  = code
 *   - bits 16..19 = #bits
 */
static const uint32_t len_fh[259] = {
	0x000000,  0x000000,  0x000000,  0x070040,   /* 0-3 */
	0x070020,  0x070060,  0x070010,  0x070050,   /* 4-7 */
	0x070030,  0x070070,  0x070008,  0x080048,   /* 8-11 */
	0x0800c8,  0x080028,  0x0800a8,  0x080068,   /* 12-15 */
	0x0800e8,  0x080018,  0x080098,  0x090058,   /* 16-19 */
	0x0900d8,  0x090158,  0x0901d8,  0x090038,   /* 20-23 */
	0x0900b8,  0x090138,  0x0901b8,  0x090078,   /* 24-27 */
	0x0900f8,  0x090178,  0x0901f8,  0x090004,   /* 28-31 */
	0x090084,  0x090104,  0x090184,  0x0a0044,   /* 32-35 */
	0x0a00c4,  0x0a0144,  0x0a01c4,  0x0a0244,   /* 36-39 */
	0x0a02c4,  0x0a0344,  0x0a03c4,  0x0a0024,   /* 40-43 */
	0x0a00a4,  0x0a0124,  0x0a01a4,  0x0a0224,   /* 44-47 */
	0x0a02a4,  0x0a0324,  0x0a03a4,  0x0a0064,   /* 48-51 */
	0x0a00e4,  0x0a0164,  0x0a01e4,  0x0a0264,   /* 52-55 */
	0x0a02e4,  0x0a0364,  0x0a03e4,  0x0a0014,   /* 56-59 */
	0x0a0094,  0x0a0114,  0x0a0194,  0x0a0214,   /* 60-63 */
	0x0a0294,  0x0a0314,  0x0a0394,  0x0b0054,   /* 64-67 */
	0x0b00d4,  0x0b0154,  0x0b01d4,  0x0b0254,   /* 68-71 */
	0x0b02d4,  0x0b0354,  0x0b03d4,  0x0b0454,   /* 72-75 */
	0x0b04d4,  0x0b0554,  0x0b05d4,  0x0b0654,   /* 76-79 */
	0x0b06d4,  0x0b0754,  0x0b07d4,  0x0b0034,   /* 80-83 */
	0x0b00b4,  0x0b0134,  0x0b01b4,  0x0b0234,   /* 84-87 */
	0x0b02b4,  0x0b0334,  0x0b03b4,  0x0b0434,   /* 88-91 */
	0x0b04b4,  0x0b0534,  0x0b05b4,  0x0b0634,   /* 92-95 */
	0x0b06b4,  0x0b0734,  0x0b07b4,  0x0b0074,   /* 96-99 */
	0x0b00f4,  0x0b0174,  0x0b01f4,  0x0b0274,   /* 100-103 */
	0x0b02f4,  0x0b0374,  0x0b03f4,  0x0b0474,   /* 104-107 */
	0x0b04f4,  0x0b0574,  0x0b05f4,  0x0b0674,   /* 108-111 */
	0x0b06f4,  0x0b0774,  0x0b07f4,  0x0c0003,   /* 112-115 */
	0x0c0103,  0x0c0203,  0x0c0303,  0x0c0403,   /* 116-119 */
	0x0c0503,  0x0c0603,  0x0c0703,  0x0c0803,   /* 120-123 */
	0x0c0903,  0x0c0a03,  0x0c0b03,  0x0c0c03,   /* 124-127 */
	0x0c0d03,  0x0c0e03,  0x0c0f03,  0x0d0083,   /* 128-131 */
	0x0d0183,  0x0d0283,  0x0d0383,  0x0d0483,   /* 132-135 */
	0x0d0583,  0x0d0683,  0x0d0783,  0x0d0883,   /* 136-139 */
	0x0d0983,  0x0d0a83,  0x0d0b83,  0x0d0c83,   /* 140-143 */
	0x0d0d83,  0x0d0e83,  0x0d0f83,  0x0d1083,   /* 144-147 */
	0x0d1183,  0x0d1283,  0x0d1383,  0x0d1483,   /* 148-151 */
	0x0d1583,  0x0d1683,  0x0d1783,  0x0d1883,   /* 152-155 */
	0x0d1983,  0x0d1a83,  0x0d1b83,  0x0d1c83,   /* 156-159 */
	0x0d1d83,  0x0d1e83,  0x0d1f83,  0x0d0043,   /* 160-163 */
	0x0d0143,  0x0d0243,  0x0d0343,  0x0d0443,   /* 164-167 */
	0x0d0543,  0x0d0643,  0x0d0743,  0x0d0843,   /* 168-171 */
	0x0d0943,  0x0d0a43,  0x0d0b43,  0x0d0c43,   /* 172-175 */
	0x0d0d43,  0x0d0e43,  0x0d0f43,  0x0d1043,   /* 176-179 */
	0x0d1143,  0x0d1243,  0x0d1343,  0x0d1443,   /* 180-183 */
	0x0d1543,  0x0d1643,  0x0d1743,  0x0d1843,   /* 184-187 */
	0x0d1943,  0x0d1a43,  0x0d1b43,  0x0d1c43,   /* 188-191 */
	0x0d1d43,  0x0d1e43,  0x0d1f43,  0x0d00c3,   /* 192-195 */
	0x0d01c3,  0x0d02c3,  0x0d03c3,  0x0d04c3,   /* 196-199 */
	0x0d05c3,  0x0d06c3,  0x0d07c3,  0x0d08c3,   /* 200-203 */
	0x0d09c3,  0x0d0ac3,  0x0d0bc3,  0x0d0cc3,   /* 204-207 */
	0x0d0dc3,  0x0d0ec3,  0x0d0fc3,  0x0d10c3,   /* 208-211 */
	0x0d11c3,  0x0d12c3,  0x0d13c3,  0x0d14c3,   /* 212-215 */
	0x0d15c3,  0x0d16c3,  0x0d17c3,  0x0d18c3,   /* 216-219 */
	0x0d19c3,  0x0d1ac3,  0x0d1bc3,  0x0d1cc3,   /* 220-223 */
	0x0d1dc3,  0x0d1ec3,  0x0d1fc3,  0x0d0023,   /* 224-227 */
	0x0d0123,  0x0d0223,  0x0d0323,  0x0d0423,   /* 228-231 */
	0x0d0523,  0x0d0623,  0x0d0723,  0x0d0823,   /* 232-235 */
	0x0d0923,  0x0d0a23,  0x0d0b23,  0x0d0c23,   /* 236-239 */
	0x0d0d23,  0x0d0e23,  0x0d0f23,  0x0d1023,   /* 240-243 */
	0x0d1123,  0x0d1223,  0x0d1323,  0x0d1423,   /* 244-247 */
	0x0d1523,  0x0d1623,  0x0d1723,  0x0d1823,   /* 248-251 */
	0x0d1923,  0x0d1a23,  0x0d1b23,  0x0d1c23,   /* 252-255 */
	0x0d1d23,  0x0d1e23,  0x0800a3               /* 256-258 */
};

/* This horrible mess is needed to shut up the fallthrough warning since the
 * stupid comment approach doesn't resist to separate preprocessing (e.g. as
 * used in distcc). Note that compilers which support the fallthrough attribute
 * also support __has_attribute.
 */
#ifndef __fallthrough
#  ifdef __has_attribute
#    if __has_attribute(fallthrough)
#      define __fallthrough __attribute__((fallthrough))
#    else
#      define __fallthrough do { } while (0)
#    endif
#  else
#    define __fallthrough do { } while (0)
#  endif
#endif

#if !defined(__ARM_FEATURE_CRC32)
static uint32_t crc32_fast[4][256];
#endif

static uint32_t fh_dist_table[32768];

#if !defined(__ARM_FEATURE_CRC32)
/* Make the table for a fast CRC.
 * Not thread-safe, must be called exactly once.
 */
static inline void __slz_make_crc_table(void)
{
	uint32_t c;
	int n, k;

	for (n = 0; n < 256; n++) {
		c = (uint32_t) n ^ 255;
		for (k = 0; k < 8; k++) {
			if (c & 1) {
				c = 0xedb88320 ^ (c >> 1);
			} else {
				c = c >> 1;
			}
		}
		crc32_fast[0][n] = c ^ 0xff000000;
	}

	/* Note: here we *do not* have to invert the bits corresponding to the
	 * byte position, because [0] already has the 8 highest bits inverted,
	 * and these bits are shifted by 8 at the end of the operation, which
	 * results in having the next 8 bits shifted in turn. That's why we
	 * have the xor in the index used just after a computation.
	 */
	for (n = 0; n < 256; n++) {
		crc32_fast[1][n] = 0xff000000 ^ crc32_fast[0][(0xff000000 ^ crc32_fast[0][n] ^ 0xff) & 0xff] ^ (crc32_fast[0][n] >> 8);
		crc32_fast[2][n] = 0xff000000 ^ crc32_fast[0][(0x00ff0000 ^ crc32_fast[1][n] ^ 0xff) & 0xff] ^ (crc32_fast[1][n] >> 8);
		crc32_fast[3][n] = 0xff000000 ^ crc32_fast[0][(0x0000ff00 ^ crc32_fast[2][n] ^ 0xff) & 0xff] ^ (crc32_fast[2][n] >> 8);
	}
}
#endif

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

/* not thread-safe, must be called exactly once */
static inline void __slz_prepare_dist_table()
{
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
}
