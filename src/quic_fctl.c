#include <haproxy/quic_fctl.h>

#include <haproxy/api.h>

void qfctl_init(struct quic_fctl *fctl, uint64_t limit)
{
	fctl->limit = limit;
	fctl->off_real = 0;
	fctl->off_soft = 0;
}

/* Returns true if real limit is blocked for <fctl> flow control instance.
 * This happens if it is equal than current max value.
 */
int qfctl_rblocked(const struct quic_fctl *fctl)
{
	/* Real limit must never be exceeded. */
	BUG_ON(fctl->off_real > fctl->limit);
	return fctl->off_real == fctl->limit;
}

/* Returns true if soft limit is blocked for <fctl> flow control instance.
 * This happens if it is equal or greater than current max value.
 */
int qfctl_sblocked(const struct quic_fctl *fctl)
{
	return fctl->off_soft >= fctl->limit;
}

/* Set a new <val> maximum value for <fctl> flow control instance. If current
 * offset is already equal or more, the new value is ignored. Additionally,
 * <unblocked_soft> and <unblocked_real> can be used as output parameters to
 * detect if the current update result in one or both of these offsets to be
 * unblocked.
 *
 * Returns true if max is incremented else false.
 */
int qfctl_set_max(struct quic_fctl *fctl, uint64_t val,
                  int *out_unblock_soft, int *out_unblock_real)
{
	int unblock_soft = 0, unblock_real = 0;
	int ret = 0;

	if (fctl->limit < val) {
		if (fctl->off_soft >= fctl->limit && fctl->off_soft < val)
			unblock_soft = 1;
		if (fctl->off_real == fctl->limit && fctl->off_real < val)
			unblock_real = 1;

		fctl->limit = val;
		ret = 1;
	}

	if (out_unblock_soft)
		*out_unblock_soft = unblock_soft;
	if (out_unblock_real)
		*out_unblock_real = unblock_real;

	return ret;
}

/* Increment real offset of <fctl> flow control instance by <diff>. This cannot
 * exceed <fctl> limit.
 *
 * Returns true if limit is reached after increment.
 */
int qfctl_rinc(struct quic_fctl *fctl, uint64_t diff)
{
	/* Real limit must never be exceeded. */
	BUG_ON(fctl->off_real + diff > fctl->limit);
	fctl->off_real += diff;

	return fctl->off_real == fctl->limit;
}

/* Increment soft offset of <fctl> flow control instance by <diff>. This cannot
 * be done if <fctl> limit was already reached.
 *
 * Returns true if limit is reached after increment.
 */
int qfctl_sinc(struct quic_fctl *fctl, uint64_t diff)
{
	/* Soft limit must not be incremented if already in excess. */
	BUG_ON(qfctl_sblocked(fctl));
	fctl->off_soft += diff;

	return fctl->off_soft >= fctl->limit;
}

/* Return the remaining offset before reaching <fctl> limit. */
uint64_t qfctl_rcap(const struct quic_fctl *fctl)
{
	/* Real limit must never be exceeded. */
	BUG_ON(fctl->off_real > fctl->limit);
	return fctl->limit - fctl->off_real;
}
