/*
 * File descriptors management functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This code implements "speculative I/O". The principle is to try to perform
 * expected I/O before registering the events in the poller. Each time this
 * succeeds, it saves a possibly expensive system call to set the event. It
 * generally succeeds for all reads after an accept(), and for writes after a
 * connect(). It also improves performance for streaming connections because
 * even if only one side is polled, the other one may react accordingly
 * depending on the fill level of the buffer. This behaviour is also the only
 * one compatible with event-based pollers (eg: EPOLL_ET).
 *
 * More importantly, it enables I/O operations that are backed by invisible
 * buffers. For example, SSL is able to read a whole socket buffer and not
 * deliver it to the application buffer because it's full. Unfortunately, it
 * won't be reported by a poller anymore until some new activity happens. The
 * only way to call it again thus is to perform speculative I/O as soon as
 * reading on the FD is enabled again.
 *
 * The speculative I/O uses a list of expected events and a list of updates.
 * Expected events are events that are expected to come and that we must report
 * to the application until it asks to stop or to poll. Updates are new requests
 * for changing an FD state. Updates are the only way to create new events. This
 * is important because it means that the number of speculative events cannot
 * increase between updates and will only grow one at a time while processing
 * updates. All updates must always be processed, though events might be
 * processed by small batches if required.
 *
 * There is no direct link between the FD and the updates list. There is only a
 * bit in the fdtab[] to indicate than a file descriptor is already present in
 * the updates list. Once an fd is present in the updates list, it will have to
 * be considered even if its changes are reverted in the middle or if the fd is
 * replaced.
 *
 * It is important to understand that as long as all expected events are
 * processed, they might starve the polled events, especially because polled
 * I/O starvation quickly induces more speculative I/O. One solution to this
 * consists in only processing a part of the events at once, but one drawback
 * is that unhandled events will still wake the poller up. Using an event-driven
 * poller such as EPOLL_ET will solve this issue though.
 *
 * A file descriptor has a distinct state for each direction. This state is a
 * combination of two bits :
 *  bit 0 = active Y/N : is set if the FD is active, which means that its
 *          handler will be called without prior polling ;
 *  bit 1 = polled Y/N : is set if the FD was subscribed to polling
 *
 * It is perfectly valid to have both bits set at a time, which generally means
 * that the FD was reported by polling, was marked active and not yet unpolled.
 * Such a state must not last long to avoid unneeded wakeups.
 *
 * The state of the FD as of last change is preserved in two other bits. These
 * ones are useful to save a significant amount of system calls during state
 * changes, because there is no need to update the FD status in the system until
 * we're about to call the poller.
 *
 * Since we do not want to scan all the FD list to find speculative I/O events,
 * we store them in a list consisting in a linear array holding only the FD
 * indexes right now. Note that a closed FD cannot exist in the spec list,
 * because it is closed by fd_delete() which in turn calls __fd_clo() which
 * always removes it from the list.
 *
 * For efficiency reasons, we will store the Read and Write bits interlaced to
 * form a 4-bit field, so that we can simply shift the value right by 0/1 and
 * get what we want :
 *    3  2  1  0
 *   Wp Rp Wa Ra
 *
 * The FD array has to hold a back reference to the speculative list. This
 * reference is always valid unless the FD if currently being polled and not
 * updated (in which case the reference points to index 0).
 *
 * We store the FD state in the 4 lower bits of fdtab[fd].spec_e, and save the
 * previous state upon changes in the 4 higher bits, so that changes are easy
 * to spot.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>

#include <types/global.h>

#include <proto/fd.h>
#include <proto/port_range.h>

struct fdtab *fdtab = NULL;     /* array of all the file descriptors */
struct fdinfo *fdinfo = NULL;   /* less-often used infos for file descriptors */
int maxfd;                      /* # of the highest fd + 1 */
int totalconn;                  /* total # of terminated sessions */
int actconn;                    /* # of active sessions */

struct poller pollers[MAX_POLLERS];
struct poller cur_poller;
int nbpollers = 0;

/* FD status is defined by the poller's status and by the speculative I/O list */
int fd_nbspec = 0;             // number of speculative events in the list
int fd_nbupdt = 0;             // number of updates in the list
unsigned int *fd_spec = NULL;  // speculative I/O list
unsigned int *fd_updt = NULL;  // FD updates list

/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
void fd_delete(int fd)
{
	if (cur_poller.clo)
		cur_poller.clo(fd);

	release_spec_entry(fd);
	fdtab[fd].spec_e &= ~(FD_EV_CURR_MASK | FD_EV_PREV_MASK);

	port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
	fdinfo[fd].port_range = NULL;
	close(fd);
	fdtab[fd].owner = NULL;
	fdtab[fd].new = 0;

	while ((maxfd-1 >= 0) && !fdtab[maxfd-1].owner)
		maxfd--;
}

/* Scan and process the speculative events. This should be called right after
 * the poller.
 */
void fd_process_spec_events()
{
	int fd, spec_idx, e;

	/* now process speculative events if any */

	for (spec_idx = 0; spec_idx < fd_nbspec; ) {
		fd = fd_spec[spec_idx];
		e = fdtab[fd].spec_e;

		/*
		 * Process the speculative events.
		 *
		 * Principle: events which are marked FD_EV_ACTIVE are processed
		 * with their usual I/O callback. The callback may remove the
		 * events from the list or tag them for polling. Changes will be
		 * applied on next round.
		 */

		fdtab[fd].ev &= FD_POLL_STICKY;

		if (e & FD_EV_ACTIVE_R)
			fdtab[fd].ev |= FD_POLL_IN;

		if (e & FD_EV_ACTIVE_W)
			fdtab[fd].ev |= FD_POLL_OUT;

		if (fdtab[fd].iocb && fdtab[fd].owner && fdtab[fd].ev)
			fdtab[fd].iocb(fd);

		/* if the fd was removed from the spec list, it has been
		 * replaced by the next one that we don't want to skip !
		 */
		if (spec_idx < fd_nbspec && fd_spec[spec_idx] != fd)
			continue;

		spec_idx++;
	}
}

/* disable the specified poller */
void disable_poller(const char *poller_name)
{
	int p;

	for (p = 0; p < nbpollers; p++)
		if (strcmp(pollers[p].name, poller_name) == 0)
			pollers[p].pref = 0;
}

/*
 * Initialize the pollers till the best one is found.
 * If none works, returns 0, otherwise 1.
 */
int init_pollers()
{
	int p;
	struct poller *bp;

	if ((fd_spec = (uint32_t *)calloc(1, sizeof(uint32_t) * global.maxsock)) == NULL)
		goto fail_spec;

	if ((fd_updt = (uint32_t *)calloc(1, sizeof(uint32_t) * global.maxsock)) == NULL)
		goto fail_updt;

	do {
		bp = NULL;
		for (p = 0; p < nbpollers; p++)
			if (!bp || (pollers[p].pref > bp->pref))
				bp = &pollers[p];

		if (!bp || bp->pref == 0)
			break;

		if (bp->init(bp)) {
			memcpy(&cur_poller, bp, sizeof(*bp));
			return 1;
		}
	} while (!bp || bp->pref == 0);
	return 0;

 fail_updt:
	free(fd_spec);
 fail_spec:
	return 0;
}

/*
 * Deinitialize the pollers.
 */
void deinit_pollers() {

	struct poller *bp;
	int p;

	for (p = 0; p < nbpollers; p++) {
		bp = &pollers[p];

		if (bp && bp->pref)
			bp->term(bp);
	}

	free(fd_updt);
	free(fd_spec);
	fd_updt = NULL;
	fd_spec = NULL;
}

/*
 * Lists the known pollers on <out>.
 * Should be performed only before initialization.
 */
int list_pollers(FILE *out)
{
	int p;
	int last, next;
	int usable;
	struct poller *bp;

	fprintf(out, "Available polling systems :\n");

	usable = 0;
	bp = NULL;
	last = next = -1;
	while (1) {
		for (p = 0; p < nbpollers; p++) {
			if ((next < 0 || pollers[p].pref > next)
			    && (last < 0 || pollers[p].pref < last)) {
				next = pollers[p].pref;
				if (!bp || (pollers[p].pref > bp->pref))
					bp = &pollers[p];
			}
		}

		if (next == -1)
			break;

		for (p = 0; p < nbpollers; p++) {
			if (pollers[p].pref == next) {
				fprintf(out, " %10s : ", pollers[p].name);
				if (pollers[p].pref == 0)
					fprintf(out, "disabled, ");
				else
					fprintf(out, "pref=%3d, ", pollers[p].pref);
				if (pollers[p].test(&pollers[p])) {
					fprintf(out, " test result OK");
					if (next > 0)
						usable++;
				} else {
					fprintf(out, " test result FAILED");
					if (bp == &pollers[p])
						bp = NULL;
				}
				fprintf(out, "\n");
			}
		}
		last = next;
		next = -1;
	};
	fprintf(out, "Total: %d (%d usable), will use %s.\n", nbpollers, usable, bp ? bp->name : "none");
	return 0;
}

/*
 * Some pollers may lose their connection after a fork(). It may be necessary
 * to create initialize part of them again. Returns 0 in case of failure,
 * otherwise 1. The fork() function may be NULL if unused. In case of error,
 * the the current poller is destroyed and the caller is responsible for trying
 * another one by calling init_pollers() again.
 */
int fork_poller()
{
	if (cur_poller.fork) {
		if (cur_poller.fork(&cur_poller))
			return 1;
		cur_poller.term(&cur_poller);
		return 0;
	}
	return 1;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
