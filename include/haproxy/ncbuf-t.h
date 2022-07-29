#ifndef _HAPROXY_NCBUF_T_H
#define _HAPROXY_NCBUF_T_H

/* **** public documentation ****
 *
 * <ncbuf> stands for non-contiguous circular buffer. This type can be used to
 * store data in a non-linear way with gaps between them. The buffer is
 * circular and so data may wrapped.
 *
 * The API of <ncbuf> is split in two parts. Please refer to the public API
 * declared in this header file which should cover all the needs.
 *
 * To minimize the memory footprint, size of data and gaps are inserted in the
 * gaps themselves. This way <ncbuf> does not need to maintain a separate list
 * of data offsets in a dedicated structure. However, this put some limitations
 * on the buffer usage that the user need to know.
 *
 * First, a space will always be reserved in the allocated buffer area to store
 * the size of the first data block. Use ncb_size(buf) to retrieve the usable
 * size of the allocated buffer excluding the reserved space.
 *
 * Second, add and deletion operations are constraint and may be impossible if
 * a minimal gap size between data is not respected. A caller must always
 * inspect the return values of these functions. To limit these errors and
 * improve the buffer performance, <ncbuf> should be reserved for use-cases
 * where the number of formed gaps is kept minimal and evenly spread.
 */

/* **** internal documentation ****
 *
 * This section is useful to users who need to understand how ncbuf are
 * implemented.
 *
 * Public and internal functions all shared a common abstraction of the buffer.
 * The buffer content is represented as a list of blocks, alternating between
 * DATA and GAP blocks. This simplifies the buffer examination loop and
 * insertion/deletion. Note that this list of blocks is not stored in the
 * buffer structure.
 *
 * The buffer is considered to always start with a DATA block. The size of this
 * block is stored just before <head> which is the pointer for offset 0. This
 * space will always be reserved for this usage. It can be accessed through
 * ncb_int_head(buf). If the buffer has no data at head, the reserved space
 * will simply contains the value 0, and will be follow by a gap.
 *
 * A gap always contains the size of the gap itself and the size of the next
 * data block. Here is a small representation of a gap stored at offset <x>
 * before a data block at offset <y>.
 *
 *        x                                  y
 * ------------------------------------------------------------
 *  xxxxxx| GAP-SZ | DATA-SZ |               | xxxxxxxxxxxxx...
 * ------------------------------------------------------------
 *        | -------- GAP-SZ -------------- > | --- DATA-SZ --->
 *
 * This means that a gap must be at least big enough to store two sizes.
 * However, there is an optimization when the last block of the buffer is a
 * gap. In this case, there is no minimal size for this block. If the gap is
 * too small, the two sizes won't be stored in it. This block is considered
 * to be a reduced gap. The block API will detect such a gap if stored at an
 * offset near the end of the buffer.
 *
 */

#include <inttypes.h>

/* ncb_sz_t is the basic type used in ncbuf to represent data and gap sizes.
 * Use a bigger type to extend the maximum data size supported in the buffer.
 * On the other hand, this also increases the minimal gap size which can
 * cause more rejection for add/delete operations.
 */
typedef uint32_t        ncb_sz_t;

/* reserved size before head used to store first data block size */
#define NCB_RESERVED_SZ (sizeof(ncb_sz_t))

/* A gap contains its size and the size of the data following it. */
#define NCB_GAP_MIN_SZ  (sizeof(ncb_sz_t) * 2)
#define NCB_GAP_SZ_OFF      0
#define NCB_GAP_SZ_DATA_OFF (sizeof(ncb_sz_t))

#define NCBUF_NULL ((struct ncbuf){ })

struct ncbuf {
	char *area;
	ncb_sz_t size;
	ncb_sz_t head;
};

enum ncb_ret {
	NCB_RET_OK = 0,   /* no error */

	NCB_RET_GAP_SIZE, /* operation would create a too small gap */
	NCB_RET_DATA_REJ, /* operation would overwrite data with different one */
};

/* Define how insert is conducted in regards with already stored data. */
enum ncb_add_mode {
	NCB_ADD_PRESERVE, /* keep the already stored data and only insert in gaps */
	NCB_ADD_OVERWRT,  /* overwrite old data with new ones */
	NCB_ADD_COMPARE,  /* compare before insert : if new data are different do not proceed */
};

#endif /* _HAPROXY_NCBUF_T_H */
