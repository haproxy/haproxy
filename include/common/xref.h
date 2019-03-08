#ifndef __XREF_H__
#define __XREF_H__

#include <common/hathreads.h>

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

#define XREF_BUSY ((struct xref *)1)

static inline void xref_create(struct xref *xref_a, struct xref *xref_b)
{
	xref_a->peer = xref_b;
	xref_b->peer = xref_a;
}

static inline struct xref *xref_get_peer_and_lock(struct xref *xref)
{
	struct xref *local;
	struct xref *remote;

	while (1) {

		/* Get the local pointer to the peer. */
		local = _HA_ATOMIC_XCHG(&xref->peer, XREF_BUSY);
		__ha_barrier_atomic_store();

		/* If the local pointer is NULL, the peer no longer exists. */
		if (local == NULL) {
			xref->peer = NULL;
			return NULL;
		}

		/* If the local pointeru is BUSY, the peer try to acquire the
		 * lock. We retry the process.
		 */
		if (local == XREF_BUSY)
			continue;

		/* We are locked, the peer cant disapear, try to acquire
		 * the pper's lock. Note that remote can't be NULL.
		 */
		remote = _HA_ATOMIC_XCHG(&local->peer, XREF_BUSY);

		/* The remote lock is BUSY, We retry the process. */
		if (remote == XREF_BUSY) {
			xref->peer = local;
			__ha_barrier_store();
			continue;
		}

		/* We have the lock, we return the value of the xref. */
		return local;
	}
}

static inline void xref_unlock(struct xref *xref, struct xref *peer)
{
	/* Release the peer. */
	peer->peer = xref;

	__ha_barrier_store();

	/* Release myself. */
	xref->peer = peer;
}

static inline void xref_disconnect(struct xref *xref, struct xref *peer)
{
	peer->peer = NULL;
	__ha_barrier_store();
	xref->peer = NULL;
}

#endif /* __XREF_H__ */
