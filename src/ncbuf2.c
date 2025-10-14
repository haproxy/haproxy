#include <haproxy/ncbuf2.h>

#include <string.h>

struct ncbuf2 ncb2_make(char *area, ncb2_sz_t size, ncb2_sz_t head)
{
	struct ncbuf2 buf;
	ncb2_sz_t bitmap_sz;

	bitmap_sz = (size + 8) / 9;

	buf.area = area;
	buf.bitmap = area + size - bitmap_sz;
	buf.size = size - bitmap_sz;
	buf.head = head;

	memset(area, 0, size);

	return buf;
}

ncb2_sz_t ncb2_total_data(const struct ncbuf2 *buf)
{
	/* TODO */
	return 0;
}

int ncb2_is_empty(const struct ncbuf2 *buf)
{
	/* TODO */
	return 0;
}

int ncb2_is_full(const struct ncbuf2 *buf)
{
	/* TODO */
	return 0;
}

int ncb2_is_fragmented(const struct ncbuf2 *buf)
{
	/* TODO */
	return 0;
}

ncb2_sz_t ncb2_data(const struct ncbuf2 *buf, ncb2_sz_t off)
{
	/* TODO */
	return 0;
}

enum ncb_ret ncb2_add(struct ncbuf2 *buf, ncb2_sz_t off,
                       const char *data, ncb2_sz_t len, enum ncb_add_mode mode)
{
	/* TODO */
	return NCB_RET_OK;
}

enum ncb_ret ncb2_advance(struct ncbuf2 *buf, ncb2_sz_t adv)
{
	/* TODO */
	return NCB_RET_OK;
}
