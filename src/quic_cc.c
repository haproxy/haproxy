/*
 * Congestion controller handling.
 *
 * This file contains definitions for QUIC congestion control.
 *
 * Copyright 2019 HAProxy Technologies, Frederic Lecaille <flecaille@haproxy.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <haproxy/quic_cc.h>
#include <haproxy/quic_pacing.h>

struct quic_cc_algo *default_quic_cc_algo = &quic_cc_algo_cubic;

/*
 * Initialize <cc> congestion control with <algo> as algorithm depending on <ipv4>
 * a boolean which is true for an IPv4 path.
 */
void quic_cc_init(struct quic_cc *cc,
                  struct quic_cc_algo *algo, struct quic_conn *qc)
{
	cc->qc = qc;
	cc->algo = algo;
	if (cc->algo->init)
		(cc->algo->init(cc));
}

/* Send <ev> event to <cc> congestion controller. */
void quic_cc_event(struct quic_cc *cc, struct quic_cc_event *ev)
{
	if (cc->algo->event)
		cc->algo->event(cc, ev);
}

void quic_cc_state_trace(struct buffer *buf, const struct quic_cc *cc)
{
	cc->algo->state_trace(buf, cc);
}

/* Return interval in nanoseconds between each datagram emission for a smooth pacing. */
uint quic_cc_default_pacing_inter(const struct quic_cc *cc)
{
	struct quic_cc_path *path = container_of(cc, struct quic_cc_path, cc);
	return path->loss.srtt * 1000000 / (path->cwnd / path->mtu + 1) + 1;
}

/* Returns true if congestion window on path ought to be increased. */
int quic_cwnd_may_increase(const struct quic_cc_path *path)
{
	/* RFC 9002 7.8. Underutilizing the Congestion Window
	 *
	 * When bytes in flight is smaller than the congestion window and
	 * sending is not pacing limited, the congestion window is
	 * underutilized. This can happen due to insufficient application data
	 * or flow control limits. When this occurs, the congestion window
	 * SHOULD NOT be increased in either slow start or congestion avoidance.
	 */

	/* Consider that congestion window can be increased if it is at least
	 * half full or window size is less than 16k. These conditions should
	 * not be restricted too much to prevent slow window growing.
	 */
	return 2 * path->in_flight >= path->cwnd  || path->cwnd < 16384;
}
