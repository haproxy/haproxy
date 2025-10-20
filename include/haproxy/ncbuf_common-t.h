#ifndef _HAPROXY_NCBUF_COMMON_T_H
#define _HAPROXY_NCBUF_COMMON_T_H

#include <inttypes.h>

typedef uint32_t        ncb_sz_t;

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

#endif /* _HAPROXY_NCBUF_COMMON_T_H */
