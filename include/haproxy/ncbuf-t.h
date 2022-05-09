#ifndef _HAPROXY_NCBUF_T_H
#define _HAPROXY_NCBUF_T_H

/* **** public documentation ****
 *
 * <ncbuf> stands for non-contiguous circular buffer. This type can be used to
 * store data in a non-linear way with gaps between them. The buffer is
 * circular and so data may wrapped.
 *
 * The API of <ncbuf> is splitted in two parts. Please refer to the public API
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

#include <stdint.h>

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

#endif /* _HAPROXY_NCBUF_T_H */
