#include <haproxy/ncbuf.h>

#ifdef DEBUG_DEV
# include <haproxy/bug.h>
#else
# include <stdio.h>
# include <stdlib.h>

# undef  BUG_ON
# define BUG_ON(x)     if (x) { fprintf(stderr, "CRASH ON %s:%d\n", __func__, __LINE__); abort(); }

# undef  BUG_ON_HOT
# define BUG_ON_HOT(x) if (x) { fprintf(stderr, "CRASH ON %s:%d\n", __func__, __LINE__); abort(); }
#endif /* DEBUG_DEV */

/* ******** internal API ******** */

/* Return pointer to <off> relative to <buf> head. Support buffer wrapping. */
static char *ncb_peek(const struct ncbuf *buf, ncb_sz_t off)
{
	char *ptr = ncb_head(buf) + off;
	if (ptr >= buf->area + buf->size)
		ptr -= buf->size;
	return ptr;
}

/* Returns the reserved space of <buf> which contains the size of the first
 * data block.
 */
static char *ncb_reserved(const struct ncbuf *buf)
{
	return ncb_peek(buf, buf->size - NCB_RESERVED_SZ);
}

/* Encode <off> at <st> position in <buf>. Support wrapping. */
static void ncb_write_off(const struct ncbuf *buf, char *st, ncb_sz_t off)
{
	int i;

	BUG_ON_HOT(st >= buf->area + buf->size);

	for (i = 0; i < sizeof(ncb_sz_t); ++i) {
		(*st) = off >> (8 * i) & 0xff;

		if ((++st) == ncb_wrap(buf))
			st = ncb_orig(buf);
	}
}

/* Decode offset stored at <st> position in <buf>. Support wrapping. */
static ncb_sz_t ncb_read_off(const struct ncbuf *buf, char *st)
{
	int i;
	ncb_sz_t off = 0;

	BUG_ON_HOT(st >= buf->area + buf->size);

	for (i = 0; i < sizeof(ncb_sz_t); ++i) {
		off |= (unsigned char )(*st) << (8 * i);

		if ((++st) == ncb_wrap(buf))
			st = ncb_orig(buf);
	}

	return off;
}

/* ******** public API ******** */

int ncb_is_null(const struct ncbuf *buf)
{
	return buf->size == 0;
}

/* Initialize or reset <buf> by clearing all data. Its size is untouched.
 * Buffer is positioned to <head> offset. Use 0 to realign it.
 */
void ncb_init(struct ncbuf *buf, ncb_sz_t head)
{
	BUG_ON_HOT(head >= buf->size);
	buf->head = head;

	ncb_write_off(buf, ncb_reserved(buf), 0);
	ncb_write_off(buf, ncb_head(buf), ncb_size(buf));
	ncb_write_off(buf, ncb_peek(buf, sizeof(ncb_sz_t)), 0);
}

/* Construct a ncbuf with all its parameters. */
struct ncbuf ncb_make(char *area, ncb_sz_t size, ncb_sz_t head)
{
	struct ncbuf buf;

	/* Ensure that there is enough space for the reserved space and data.
	 * This is the minimal value to not crash later.
	 */
	BUG_ON_HOT(size <= NCB_RESERVED_SZ);

	buf.area = area;
	buf.size = size;
	buf.head = head;

	return buf;
}

/* Returns start of allocated buffer area. */
char *ncb_orig(const struct ncbuf *buf)
{
	return buf->area;
}

/* Returns current head pointer into buffer area. */
char *ncb_head(const struct ncbuf *buf)
{
	return buf->area + buf->head;
}

/* Returns the first byte after the allocated buffer area. */
char *ncb_wrap(const struct ncbuf *buf)
{
	return buf->area + buf->size;
}

/* Returns the usable size of <buf> for data storage. This is the size of the
 * allocated buffer without the reserved header space.
 */
ncb_sz_t ncb_size(const struct ncbuf *buf)
{
	return buf->size - NCB_RESERVED_SZ;
}

/* Returns true if there is no data anywhere in <buf>. */
int ncb_is_empty(const struct ncbuf *buf)
{
	BUG_ON_HOT(*ncb_reserved(buf) + *ncb_head(buf) > ncb_size(buf));
	return *ncb_reserved(buf) == 0 && *ncb_head(buf) == ncb_size(buf);
}

/* Returns true if no more data can be inserted in <buf>. */
int ncb_is_full(const struct ncbuf *buf)
{
	BUG_ON_HOT(ncb_read_off(buf, ncb_reserved(buf)) > ncb_size(buf));
	return ncb_read_off(buf, ncb_reserved(buf)) == ncb_size(buf);
}
