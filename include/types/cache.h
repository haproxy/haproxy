#ifndef _TYPES_CACHE_H
#define _TYPES_CACHE_H

struct cache_obj {
	int exp;   /* expire time */
	int etag;  /* e-tag entry */
	int last;  /* last entry */
	void *buf;  /* ptr to buffer */
}

#endif /*_TYPES_CACHE_H */


