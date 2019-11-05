/*
 * include/proto/stream.h
 * This file defines everything related to streams.
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

#ifndef _PROTO_STREAM_H
#define _PROTO_STREAM_H

#include <common/config.h>
#include <common/memory.h>
#include <types/action.h>
#include <types/stream.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/obj_type.h>
#include <proto/queue.h>
#include <proto/stick_table.h>
#include <proto/task.h>
#include <proto/trace.h>

extern struct trace_source trace_strm;

/* Details about these events are defined in <src/stream.c> */
#define  STRM_EV_STRM_NEW     (1ULL <<  0)
#define  STRM_EV_STRM_FREE    (1ULL <<  1)
#define  STRM_EV_STRM_ERR     (1ULL <<  2)
#define  STRM_EV_STRM_ANA     (1ULL <<  3)
#define  STRM_EV_STRM_PROC    (1ULL <<  4)
#define  STRM_EV_SI_ST        (1ULL <<  5)
#define  STRM_EV_HTTP_ANA     (1ULL <<  6)
#define  STRM_EV_HTTP_ERR     (1ULL <<  7)
#define  STRM_EV_TCP_ANA      (1ULL <<  8)
#define  STRM_EV_TCP_ERR      (1ULL <<  9)
#define  STRM_EV_FLT_ANA      (1ULL << 10)
#define  STRM_EV_FLT_ERR      (1ULL << 11)

#define IS_HTX_STRM(strm) ((strm)->flags & SF_HTX)

extern struct pool_head *pool_head_stream;
extern struct list streams;

extern struct data_cb sess_conn_cb;

struct stream *stream_new(struct session *sess, enum obj_type *origin);
int stream_create_from_cs(struct conn_stream *cs);

/* kill a stream and set the termination flags to <why> (one of SF_ERR_*) */
void stream_shutdown(struct stream *stream, int why);
void stream_dump(struct buffer *buf, const struct stream *s, const char *pfx, char eol);
void stream_dump_and_crash(enum obj_type *obj, int rate);

void stream_process_counters(struct stream *s);
void sess_change_server(struct stream *sess, struct server *newsrv);
struct task *process_stream(struct task *t, void *context, unsigned short state);
void default_srv_error(struct stream *s, struct stream_interface *si);
int parse_track_counters(char **args, int *arg,
			 int section_type, struct proxy *curpx,
			 struct track_ctr_prm *prm,
			 struct proxy *defpx, char **err);

/* Update the stream's backend and server time stats */
void stream_update_time_stats(struct stream *s);
void stream_release_buffers(struct stream *s);
int stream_buf_available(void *arg);

/* returns the session this stream belongs to */
static inline struct session *strm_sess(const struct stream *strm)
{
	return strm->sess;
}

/* returns the frontend this stream was initiated from */
static inline struct proxy *strm_fe(const struct stream *strm)
{
	return strm->sess->fe;
}

/* returns the listener this stream was initiated from */
static inline struct listener *strm_li(const struct stream *strm)
{
	return strm->sess->listener;
}

/* returns a pointer to the origin of the session which created this stream */
static inline enum obj_type *strm_orig(const struct stream *strm)
{
	return strm->sess->origin;
}

/* Remove the refcount from the stream to the tracked counters, and clear the
 * pointer to ensure this is only performed once. The caller is responsible for
 * ensuring that the pointer is valid first. We must be extremely careful not
 * to touch the entries we inherited from the session.
 */
static inline void stream_store_counters(struct stream *s)
{
	void *ptr;
	int i;
	struct stksess *ts;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		ts = stkctr_entry(&s->stkctr[i]);
		if (!ts)
			continue;

		if (stkctr_entry(&s->sess->stkctr[i]))
			continue;

		ptr = stktable_data_ptr(s->stkctr[i].table, ts, STKTABLE_DT_CONN_CUR);
		if (ptr) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

			if (stktable_data_cast(ptr, conn_cur) > 0)
				stktable_data_cast(ptr, conn_cur)--;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(s->stkctr[i].table, ts, 0);
		}
		stkctr_set_entry(&s->stkctr[i], NULL);
		stksess_kill_if_expired(s->stkctr[i].table, ts, 1);
	}
}

/* Remove the refcount from the stream counters tracked at the content level if
 * any, and clear the pointer to ensure this is only performed once. The caller
 * is responsible for ensuring that the pointer is valid first. We must be
 * extremely careful not to touch the entries we inherited from the session.
 */
static inline void stream_stop_content_counters(struct stream *s)
{
	struct stksess *ts;
	void *ptr;
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		ts = stkctr_entry(&s->stkctr[i]);
		if (!ts)
			continue;

		if (stkctr_entry(&s->sess->stkctr[i]))
			continue;

		if (!(stkctr_flags(&s->stkctr[i]) & STKCTR_TRACK_CONTENT))
			continue;

		ptr = stktable_data_ptr(s->stkctr[i].table, ts, STKTABLE_DT_CONN_CUR);
		if (ptr) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

			if (stktable_data_cast(ptr, conn_cur) > 0)
				stktable_data_cast(ptr, conn_cur)--;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(s->stkctr[i].table, ts, 0);
		}
		stkctr_set_entry(&s->stkctr[i], NULL);
		stksess_kill_if_expired(s->stkctr[i].table, ts, 1);
	}
}

/* Increase total and concurrent connection count for stick entry <ts> of table
 * <t>. The caller is responsible for ensuring that <t> and <ts> are valid
 * pointers, and for calling this only once per connection.
 */
static inline void stream_start_counters(struct stktable *t, struct stksess *ts)
{
	void *ptr;

	HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

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

	HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

	/* If data was modified, we need to touch to re-schedule sync */
	stktable_touch_local(t, ts, 0);
}

/* Enable tracking of stream counters as <stkctr> on stksess <ts>. The caller is
 * responsible for ensuring that <t> and <ts> are valid pointers. Some controls
 * are performed to ensure the state can still change.
 */
static inline void stream_track_stkctr(struct stkctr *ctr, struct stktable *t, struct stksess *ts)
{
	/* Why this test ???? */
	if (stkctr_entry(ctr))
		return;

	ctr->table = t;
	stkctr_set_entry(ctr, ts);
	stream_start_counters(t, ts);
}

/* Increase the number of cumulated HTTP requests in the tracked counters */
static inline void stream_inc_http_req_ctr(struct stream *s)
{
	struct stksess *ts;
	void *ptr;
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		struct stkctr *stkctr = &s->stkctr[i];

		ts = stkctr_entry(stkctr);
		if (!ts) {
			stkctr = &s->sess->stkctr[i];
			ts = stkctr_entry(stkctr);
			if (!ts)
				continue;
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

		ptr = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_REQ_CNT);
		if (ptr)
			stktable_data_cast(ptr, http_req_cnt)++;

		ptr = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_REQ_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u, 1);

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

		/* If data was modified, we need to touch to re-schedule sync */
		stktable_touch_local(stkctr->table, ts, 0);
	}
}

/* Increase the number of cumulated HTTP requests in the backend's tracked
 * counters. We don't look up the session since it cannot happen in the bakcend.
 */
static inline void stream_inc_be_http_req_ctr(struct stream *s)
{
	struct stksess *ts;
	void *ptr;
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		struct stkctr *stkctr = &s->stkctr[i];

		ts = stkctr_entry(stkctr);
		if (!ts)
			continue;

		if (!(stkctr_flags(&s->stkctr[i]) & STKCTR_TRACK_BACKEND))
			continue;

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

		ptr = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_REQ_CNT);
		if (ptr)
			stktable_data_cast(ptr, http_req_cnt)++;

		ptr = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_REQ_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
			                       stkctr->table->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u, 1);

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

		/* If data was modified, we need to touch to re-schedule sync */
		stktable_touch_local(stkctr->table, ts, 0);
	}
}

/* Increase the number of cumulated failed HTTP requests in the tracked
 * counters. Only 4xx requests should be counted here so that we can
 * distinguish between errors caused by client behaviour and other ones.
 * Note that even 404 are interesting because they're generally caused by
 * vulnerability scans.
 */
static inline void stream_inc_http_err_ctr(struct stream *s)
{
	struct stksess *ts;
	void *ptr;
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		struct stkctr *stkctr = &s->stkctr[i];

		ts = stkctr_entry(stkctr);
		if (!ts) {
			stkctr = &s->sess->stkctr[i];
			ts = stkctr_entry(stkctr);
			if (!ts)
				continue;
		}

		HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

		ptr = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_ERR_CNT);
		if (ptr)
			stktable_data_cast(ptr, http_err_cnt)++;

		ptr = stktable_data_ptr(stkctr->table, ts, STKTABLE_DT_HTTP_ERR_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, http_err_rate),
			                       stkctr->table->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u, 1);

		HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

		/* If data was modified, we need to touch to re-schedule sync */
		stktable_touch_local(stkctr->table, ts, 0);
	}
}

static inline void __stream_add_srv_conn(struct stream *sess, struct server *srv)
{
	sess->srv_conn = srv;
	LIST_ADD(&srv->actconns, &sess->by_srv);
}

static inline void stream_add_srv_conn(struct stream *sess, struct server *srv)
{
	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	__stream_add_srv_conn(sess, srv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
}

static inline void stream_del_srv_conn(struct stream *sess)
{
	struct server *srv = sess->srv_conn;

	if (!srv)
		return;

	HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	sess->srv_conn = NULL;
	LIST_DEL(&sess->by_srv);
	HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);
}

static inline void stream_init_srv_conn(struct stream *sess)
{
	sess->srv_conn = NULL;
	LIST_INIT(&sess->by_srv);
}

static inline void stream_choose_redispatch(struct stream *s)
{
	struct stream_interface *si = &s->si[1];

	/* If the "redispatch" option is set on the backend, we are allowed to
	 * retry on another server. By default this redispatch occurs on the
	 * last retry, but if configured we allow redispatches to occur on
	 * configurable intervals, e.g. on every retry. In order to achieve this,
	 * we must mark the stream unassigned, and eventually clear the DIRECT
	 * bit to ignore any persistence cookie. We won't count a retry nor a
	 * redispatch yet, because this will depend on what server is selected.
	 * If the connection is not persistent, the balancing algorithm is not
	 * determinist (round robin) and there is more than one active server,
	 * we accept to perform an immediate redispatch without waiting since
	 * we don't care about this particular server.
	 */
	if (objt_server(s->target) &&
	    (s->be->options & PR_O_REDISP) && !(s->flags & SF_FORCE_PRST) &&
	    ((__objt_server(s->target)->cur_state < SRV_ST_RUNNING) ||
	     (((s->be->redispatch_after > 0) &&
	       ((s->be->conn_retries - si->conn_retries) %
	        s->be->redispatch_after == 0)) ||
	      ((s->be->redispatch_after < 0) &&
	       ((s->be->conn_retries - si->conn_retries) %
	        (s->be->conn_retries + 1 + s->be->redispatch_after) == 0))) ||
	     (!(s->flags & SF_DIRECT) && s->be->srv_act > 1 &&
	      ((s->be->lbprm.algo & BE_LB_KIND) == BE_LB_KIND_RR)))) {
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));

		s->flags &= ~(SF_DIRECT | SF_ASSIGNED | SF_ADDR_SET);
		si->state = SI_ST_REQ;
	} else {
		if (objt_server(s->target))
			_HA_ATOMIC_ADD(&__objt_server(s->target)->counters.retries, 1);
		_HA_ATOMIC_ADD(&s->be->be_counters.retries, 1);
		si->state = SI_ST_ASS;
	}

}

void service_keywords_register(struct action_kw_list *kw_list);
void list_services(FILE *out);

#endif /* _PROTO_STREAM_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
