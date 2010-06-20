/*
 * include/proto/session.h
 * This file defines everything related to sessions.
 *
 * Copyright (C) 2000-2010 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_SESSION_H
#define _PROTO_SESSION_H

#include <common/config.h>
#include <common/memory.h>
#include <types/session.h>
#include <proto/freq_ctr.h>
#include <proto/stick_table.h>

extern struct pool_head *pool2_session;
extern struct list sessions;

int session_accept(struct listener *l, int cfd, struct sockaddr_storage *addr);
void session_free(struct session *s);

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_session();

void session_process_counters(struct session *s);
void sess_change_server(struct session *sess, struct server *newsrv);
struct task *process_session(struct task *t);
void sess_set_term_flags(struct session *s);
void default_srv_error(struct session *s, struct stream_interface *si);
int parse_track_counters(char **args, int *arg,
			 int section_type, struct proxy *curpx,
			 struct track_ctr_prm *prm,
			 struct proxy *defpx, char *err, int errlen);

/* Remove the refcount from the session to the tracked counters, and clear the
 * pointer to ensure this is only performed once. The caller is responsible for
 * ensuring that the pointer is valid first.
 */
static inline void session_store_counters(struct session *s)
{
	if (s->tracked_counters) {
		void *ptr = stktable_data_ptr(s->tracked_table, s->tracked_counters, STKTABLE_DT_CONN_CUR);
		if (ptr)
			stktable_data_cast(ptr, conn_cur)--;
	}
	s->tracked_counters->ref_cnt--;
	s->tracked_counters = NULL;
}

/* Enable tracking of session counters on stksess <ts>. The caller is
 * responsible for ensuring that <t> and <ts> are valid pointers and that no
 * previous tracked_counters was assigned to the session.
 */
static inline void session_track_counters(struct session *s, struct stktable *t, struct stksess *ts)
{
	ts->ref_cnt++;
	s->tracked_table = t;
	s->tracked_counters = ts;
	if (ts) {
		void *ptr;

		ptr = stktable_data_ptr(t, ts, STKTABLE_DT_CONN_CUR);
		if (ptr)
			stktable_data_cast(ptr, conn_cur)++;

		ptr = stktable_data_ptr(t, ts, STKTABLE_DT_CONN_CNT);
		if (ptr)
			stktable_data_cast(ptr, conn_cnt)++;

		ptr = stktable_data_ptr(t, ts, STKTABLE_DT_CONN_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, conn_rate),
					       t->data_arg[STKTABLE_DT_CONN_RATE].u, 1);

		if (tick_isset(t->expire))
			ts->expire = tick_add(now_ms, MS_TO_TICKS(t->expire));
	}
}

static void inline trace_term(struct session *s, unsigned int code)
{
	s->term_trace <<= TT_BIT_SHIFT;
	s->term_trace |= code;
}

#endif /* _PROTO_SESSION_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
