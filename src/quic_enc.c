#include <haproxy/quic_enc.h>

#include <haproxy/api.h>

int quic_enc_unittest(int argc, char **argv)
{
	const uint8_t init = 4;

	uint64_t val = 0;
	struct buffer b;
	char area[12];

	int ret = 1;

	b = b_make(area, sizeof(area), sizeof(area) - 2, 0);
	/* encode an 8-bit integer as a 4 bytes long varint */
	b_putblk(&b, (char[]){0x80, 0x00, 0x00, init}, 4);
	/* ensure encoded data is wrapping inside buffer */
	BUG_ON(b_data(&b) != b_contig_data(&b, b_head_ofs(&b)));

	/* test that b_quic_dec_int() can decode a wrapping value */
	b_quic_dec_int(&val, &b, NULL);
	if (val != init)
		goto out;

	ret = 0;

 out:
	return ret;
}
REGISTER_UNITTEST("quic_enc", quic_enc_unittest);
