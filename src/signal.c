/*
 * Asynchronous signal delivery functions.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <signal.h>
#include <string.h>

#include <proto/signal.h>
#include <proto/log.h>

/* Principle : we keep an in-order list of the first occurrence of all received
 * signals. All occurrences of a same signal are grouped though. The signal
 * queue does not need to be deeper than the number of signals we can handle.
 * The handlers will be called asynchronously with the signal number. They can
 * check themselves the number of calls by checking the descriptor this signal.
 */

int signal_queue_len; /* length of signal queue, <= MAX_SIGNAL (1 entry per signal max) */
int signal_queue[MAX_SIGNAL];                     /* in-order queue of received signals */
struct signal_descriptor signal_state[MAX_SIGNAL];
sigset_t blocked_sig;

void signal_init()
{
	signal_queue_len = 0;
	memset(signal_queue, 0, sizeof(signal_queue));
	memset(signal_state, 0, sizeof(signal_state));
	sigfillset(&blocked_sig);
}

void signal_handler(int sig)
{
	if (sig < 0 || sig > MAX_SIGNAL || !signal_state[sig].handler) {
		/* unhandled signal */
		qfprintf(stderr, "Received unhandled signal %d. Signal has been disabled.\n", sig);
		signal(sig, SIG_IGN);
		return;
	}

	if (!signal_state[sig].count) {
		/* signal was not queued yet */
		if (signal_queue_len < MAX_SIGNAL)
			signal_queue[signal_queue_len++] = sig;
		else
			qfprintf(stderr, "Signal %d : signal queue is unexpectedly full.\n", sig);
	}
	signal_state[sig].count++;
	signal(sig, signal_handler); /* re-arm signal */
}

/* Register a handler for signal <sig>. Set it to NULL, SIG_DFL or SIG_IGN to
 * remove the handler. The signal's queue is flushed and the signal is really
 * registered (or unregistered) for the process. The interface is the same as
 * for standard signal delivery, except that the handler does not need to rearm
 * the signal itself (it can disable it however).
 */
void signal_register(int sig, void (*handler)(int))
{
	if (sig < 0 || sig > MAX_SIGNAL) {
		qfprintf(stderr, "Failed to register signal %d : out of range [0..%d].\n", sig, MAX_SIGNAL);
		return;
	}

	signal_state[sig].count = 0;
	if (handler == NULL)
		handler = SIG_IGN;

	if (handler != SIG_IGN && handler != SIG_DFL) {
		signal_state[sig].handler = handler;
		signal(sig, signal_handler);
	}
	else {
		signal_state[sig].handler = NULL;
		signal(sig, handler);
	}
}

/* Call handlers of all pending signals and clear counts and queue length. The
 * handlers may unregister themselves by calling signal_register() while they
 * are called, just like it is done with normal signal handlers.
 * Note that it is more efficient to call the inline version which checks the
 * queue length before getting here.
 */
void __signal_process_queue()
{
	int sig, cur_pos = 0;
	struct signal_descriptor *desc;
	sigset_t old_sig;

	/* block signal delivery during processing */
	sigprocmask(SIG_SETMASK, &blocked_sig, &old_sig);

	for (cur_pos = 0; cur_pos < signal_queue_len; cur_pos++) {
		sig  = signal_queue[cur_pos];
		desc = &signal_state[sig];
		if (desc->count) {
			if (desc->handler)
				desc->handler(sig);
			desc->count = 0;
		}
	}
	signal_queue_len = 0;

	/* restore signal delivery */
	sigprocmask(SIG_SETMASK, &old_sig, NULL);
}
