#ifndef _HAPROXY_NCBUF_H
#define _HAPROXY_NCBUF_H

#include <haproxy/ncbuf-t.h>

int ncb_is_null(const struct ncbuf *buf);
void ncb_init(struct ncbuf *buf, ncb_sz_t head);
struct ncbuf ncb_make(char *area, ncb_sz_t size, ncb_sz_t head);

char *ncb_orig(const struct ncbuf *buf);
char *ncb_head(const struct ncbuf *buf);
char *ncb_wrap(const struct ncbuf *buf);

ncb_sz_t ncb_size(const struct ncbuf *buf);
ncb_sz_t ncb_total_data(const struct ncbuf *buf);
int ncb_is_empty(const struct ncbuf *buf);
int ncb_is_full(const struct ncbuf *buf);

ncb_sz_t ncb_data(const struct ncbuf *buf, ncb_sz_t offset);

enum ncb_ret ncb_add(struct ncbuf *buf, ncb_sz_t off,
                     const char *data, ncb_sz_t len, enum ncb_add_mode mode);

#endif /* _HAPROXY_NCBUF_H */
