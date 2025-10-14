#ifndef _HAPROXY_NCBUF2_H
#define _HAPROXY_NCBUF2_H

#include <haproxy/ncbuf2-t.h>
#include <haproxy/ncbuf_common-t.h>

struct ncbuf2 ncb2_make(char *area, ncb2_sz_t size, ncb2_sz_t head);


enum ncb_ret ncb2_add(struct ncbuf2 *buf, ncb2_sz_t off,
                      const char *data, ncb2_sz_t len, enum ncb_add_mode mode);

#endif /* _HAPROXY_NCBUF2_H */
