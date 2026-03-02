#ifndef _HAPROXY_HBUF_H
#define _HAPROXY_HBUF_H

#include <stdlib.h>

/* Very small API similar to buffer API to carefully bufferize some strings */
#define HBUF_NULL ((struct hbuf) { })
#define HBUF_SIZE (16 << 10) /* bytes */

struct hbuf {
	char *area;
	size_t data;
	size_t size;
};

static inline struct hbuf *hbuf_alloc(struct hbuf *h)
{
	h->area = malloc(HBUF_SIZE);
	if (!h->area)
		return NULL;

	h->size = HBUF_SIZE;
	h->data = 0;
	return h;
}

static inline void free_hbuf(struct hbuf *h)
{
	free(h->area);
	h->area = NULL;
}

static inline size_t hbuf_is_null(const struct hbuf *h)
{
	return h->size == 0;
}

__attribute__ ((format(printf, 2, 3)))
void hbuf_appendf(struct hbuf *h, char *fmt, ...);
void hbuf_str_append(struct hbuf *h, const char *line);

#endif /* _HAPROXY_HBUF_H */
