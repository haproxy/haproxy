#include <haproxy/ncbmbuf.h>

#include <string.h>

/* Construct a ncbmbuf with all its parameters. */
struct ncbmbuf ncbmb_make(char *area, ncb_sz_t size, ncb_sz_t head)
{
	struct ncbmbuf buf;
	ncb_sz_t bitmap_sz;

	bitmap_sz = (size + 8) / 9;

	buf.area = area;
	buf.bitmap = area + size - bitmap_sz;
	buf.size = size - bitmap_sz;
	buf.head = head;

	memset(area, 0, size);

	return buf;
}

ncb_sz_t ncbmb_total_data(const struct ncbmbuf *buf)
{
	/* TODO */
	return 0;
}

int ncbmb_is_empty(const struct ncbmbuf *buf)
{
	/* TODO */
	return 0;
}

int ncbmb_is_full(const struct ncbmbuf *buf)
{
	/* TODO */
	return 0;
}

int ncbmb_is_fragmented(const struct ncbmbuf *buf)
{
	/* TODO */
	return 0;
}

ncb_sz_t ncbmb_data(const struct ncbmbuf *buf, ncb_sz_t off)
{
	/* TODO */
	return 0;
}

enum ncb_ret ncbmb_add(struct ncbmbuf *buf, ncb_sz_t off,
                       const char *data, ncb_sz_t len, enum ncb_add_mode mode)
{
	/* TODO */
	return NCB_RET_OK;
}

enum ncb_ret ncbmb_advance(struct ncbmbuf *buf, ncb_sz_t adv)
{
	/* TODO */
	return NCB_RET_OK;
}
