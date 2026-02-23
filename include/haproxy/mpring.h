/*
 * MPSC byte ring buffer with variable sized entries.
 */

#ifndef _MPRING_H
#define _MPRING_H

#include <sys/types.h>

#include <haproxy/compiler.h>

struct mpring {
	size_t capacity;
	size_t mask;
	uint8_t *buffer;
	uint64_t head THREAD_ALIGNED();
	uint64_t tail THREAD_ALIGNED();
};

/* Initialize the ring buffer. The size MUST be a power of 2, and bigger than
 * the value of the MPRING_PAYLOAD_ALIGN macro in mpring.c (currently set to 8).
 */
void mpring_init(struct mpring *ring, void *buffer, size_t size);

/* Reserve bytes in the buffer. Returns NULL in case of failure, and otherwise
 * a pointer to the buffer with enough space to write <len> bytes.
 */
void *mpring_write_reserve(struct mpring *ring, size_t len);

/* Commit data to the buffer after it was written to the pointer given by
 * mpring_write_reserve(). The <ptr> and <len> parameters MUST be identical to
 * the ones returned by and passed to mpring_write_reserve(), respectively.
 */
void mpring_write_commit(struct mpring *ring, void *ptr, size_t len);

/* Convenience shorthand for when we only need to write one contiguous set of
 * bytes to the buffer. Returns 0 in case of failure, and a non-zero value
 * otherwise.
 */
int mpring_write(struct mpring *ring, const void *data, size_t len);

/* Get the next entry to be read. Returns NULL if there is no data to be read,
 * otherwise returns a pointer to that data and set the size of the entry in the
 * <len> pointer.
 */
void *mpring_read_begin(struct mpring *ring, size_t *len);

/* Indicate that we are done reading an entry, and that the space can be reused
 * for new entries. This MUST be called after we are done reading an entry. The
 * <len> parameter MUST be equal to the length given by mpring_read_begin().
 */
void mpring_read_end(struct mpring *ring, size_t len);

#endif /* _MPRING_H */
