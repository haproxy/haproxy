#include <haproxy/atomic.h>
#include <haproxy/mpring.h>
#include <haproxy/bug.h>
#include <haproxy/compiler.h>

#include <stdint.h>
#include <string.h>

/* 16 bytes would be more wasteful but would allow 128-bit SIMD/NEON memcpy() */
#define MPRING_PAYLOAD_ALIGN	8

#define MPRING_HDR_PADDING	(-1)	/* Denotes padding space at the end of the buffer */
#define MPRING_HDR_BUSY		0	/* No data or it is still being written */

struct mpring_record {
	/* The length or one of the two magic values above */
	int64_t header;
} ALIGNED(MPRING_PAYLOAD_ALIGN);

/* What we call the stride is the total amount of bytes we need to store an
 * entry, including the record header, and the padding bytes necessary to
 * maintain proper alignment.
 */
#define MPRING_STRIDE_LEN(len)	\
	(sizeof(struct mpring_record) + ((len + MPRING_PAYLOAD_ALIGN - 1) & ~(MPRING_PAYLOAD_ALIGN - 1)))

void mpring_init(struct mpring *ring, void *buffer, size_t size)
{
	/* The size of the buffer must be a power of 2 */
	BUG_ON((size & (size - 1)) != 0);

	/* And must also be bigger than the payload alignment */
	BUG_ON(size < MPRING_PAYLOAD_ALIGN);

	ring->buffer = buffer;
	/* We have to zero the buffer to ensure that all records are marked
	 * as BUSY even if we have not written there yet.
	 */
	memset(ring->buffer, 0, size);

	ring->capacity = size;
	ring->mask = size - 1;

	ring->head = ring->tail = 0;
}

void *mpring_write_reserve(struct mpring *ring, size_t len)
{
	struct mpring_record *record;
	uint64_t head, tail;
	size_t stride, offset, padding, need;

	/* Align writes to the buffer. This is both useful in order to guarantee
	 * that SIMD/NEON optimized memcpy() implementations can be used, but
	 * also required to ensure we always have space at the end of the buffer
	 * for a header to mark padding.
	 */
	stride = MPRING_STRIDE_LEN(len);

	head = _HA_ATOMIC_LOAD(&ring->head);
	do {
		offset = head & ring->mask;

		/* Check if we have enough contiguous space */
		padding = 0;
		if (offset + stride > ring->capacity) {
			padding = ring->capacity - offset;
		}

		need = stride + padding;

		tail = HA_ATOMIC_LOAD(&ring->tail);
		if (ring->capacity < head - tail + need) {
			/* Not enough room */
			return NULL;
		}
	} while (!_HA_ATOMIC_CAS(&ring->head, &head, head + need));

	/* Burn the rest of the buffer */
	if (padding > 0) {
		record = (struct mpring_record *)(ring->buffer + offset);
		HA_ATOMIC_STORE(&record->header, MPRING_HDR_PADDING);

		offset = 0;
	}

	record = (struct mpring_record *)(ring->buffer + offset);
	_HA_ATOMIC_STORE(&record->header, MPRING_HDR_BUSY);

	return record + 1;
}

void mpring_write_commit(struct mpring *ring, void *ptr, size_t len)
{
	struct mpring_record *record;

	record = (struct mpring_record *)ptr - 1;
	HA_ATOMIC_STORE(&record->header, len);
}

int mpring_write(struct mpring *ring, const void *data, size_t len)
{
	void *ptr;

	ptr = mpring_write_reserve(ring, len);
	if (!ptr)
		return 0;

	memcpy(ptr, data, len);

	mpring_write_commit(ring, ptr, len);
	return 1;
}

void *mpring_read_begin(struct mpring *ring, size_t *len)
{
	struct mpring_record *record;
	uint64_t tail;
	int64_t size;
	size_t offset, skip;

	tail = ring->tail;

again:
	offset = tail & ring->mask;
	record = (struct mpring_record *)(ring->buffer + offset);
	size = HA_ATOMIC_LOAD(&record->header);

	if (size == MPRING_HDR_BUSY)
		return NULL;	/* No more data to read */

	if (size == MPRING_HDR_PADDING) {
		/* Reset to 0 for next wrap-around */
		_HA_ATOMIC_STORE(&record->header, MPRING_HDR_BUSY);

		/* Skip over the padding */
		skip = ring->capacity - offset;
		tail += skip;
		_HA_ATOMIC_STORE(&ring->tail, tail);
		/* Try again with new tail */
		goto again;
	}

	*len = size;
	return record + 1;
}

void mpring_read_end(struct mpring *ring, size_t len)
{
	struct mpring_record *record;
	uint64_t tail;
	size_t offset, stride;

	tail = _HA_ATOMIC_LOAD(&ring->tail);
	offset = tail & ring->mask;
	record = (struct mpring_record *)(ring->buffer + offset);

	stride = MPRING_STRIDE_LEN(len);

	/* Reset to 0 so all records are set to mpring_HDR_BUSY when
	 * producers wrap around and reuse this memory later.
	 */
	memset(record, 0, stride);

	HA_ATOMIC_STORE(&ring->tail, tail + stride);
}
