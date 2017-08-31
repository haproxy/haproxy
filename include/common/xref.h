#ifndef __XREF_H__
#define __XREF_H__

/* xref is used to create relation between two elements.
 * Once an element is released, it breaks the relation. If the
 * relation is already broken, it frees the xref struct.
 * The pointer between two elements is sort of a refcount with
 * max value 1. The relation is only between two elements.
 * The pointer and the type of elements a and b are conventional.
 */

struct xref {
	struct xref *peer;
};

static inline void xref_create(struct xref *xref_a, struct xref *xref_b)
{
	xref_a->peer = xref_b;
	xref_b->peer = xref_a;
}

static inline struct xref *xref_get_peer(struct xref *xref)
{
	if (!xref->peer)
		return NULL;
	return xref->peer;
}

static inline void xref_disconnect(struct xref *xref)
{
	if (!xref->peer)
		return;

	xref->peer->peer = NULL;
	xref->peer = NULL;
}

#endif /* __XREF_H__ */
