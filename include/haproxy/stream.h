/*
 * include/haproxy/stream.h
 * This file defines everything related to streams.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_STREAM_H
#define _HAPROXY_STREAM_H

#include <haproxy/action-t.h>
#include <haproxy/api.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/obj_type.h>
#include <haproxy/pool-t.h>
#include <haproxy/queue.h>
#include <haproxy/session.h>
#include <haproxy/stconn.h>
#include <haproxy/stick_table.h>
#include <haproxy/stream-t.h>
#include <haproxy/task-t.h>
#include <haproxy/trace-t.h>

extern struct trace_source trace_strm;

/* Details about these events are defined in <src/stream.c> */
#define  STRM_EV_STRM_NEW     (1ULL <<  0)
#define  STRM_EV_STRM_FREE    (1ULL <<  1)
#define  STRM_EV_STRM_ERR     (1ULL <<  2)
#define  STRM_EV_STRM_ANA     (1ULL <<  3)
#define  STRM_EV_STRM_PROC    (1ULL <<  4)
#define  STRM_EV_CS_ST        (1ULL <<  5)
#define  STRM_EV_HTTP_ANA     (1ULL <<  6)
#define  STRM_EV_HTTP_ERR     (1ULL <<  7)
#define  STRM_EV_TCP_ANA      (1ULL <<  8)
#define  STRM_EV_TCP_ERR      (1ULL <<  9)
#define  STRM_EV_FLT_ANA      (1ULL << 10)
#define  STRM_EV_FLT_ERR      (1ULL << 11)

#define IS_HTX_STRM(strm) ((strm)->flags & SF_HTX)

extern struct pool_head *pool_head_stream;
extern struct pool_head *pool_head_uniqueid;

extern struct data_cb sess_conn_cb;

struct stream *stream_new(struct session *sess, struct stconn *sc, struct buffer *input);
void stream_free(struct stream *s);
int stream_upgrade_from_sc(struct stconn *sc, struct buffer *input);
int stream_set_http_mode(struct stream *s, const struct mux_proto_list *mux_proto);

/* shutdown the stream from itself */
void stream_shutdown_self(struct stream *stream, int why);
void stream_dump_and_crash(enum obj_type *obj, int rate);
void strm_dump_to_buffer(struct buffer *buf, const struct stream *strm, const char *pfx, uint32_t anon_key);

struct ist stream_generate_unique_id(struct stream *strm, struct lf_expr *format);

void stream_process_counters(struct stream *s);
void sess_change_server(struct stream *strm, struct server *newsrv);
struct task *process_stream(struct task *t, void *context, unsigned int state);
void default_srv_error(struct stream *s, struct stconn *sc);

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

	if (unlikely(!s->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++) {
		ts = stkctr_entry(&s->stkctr[i]);
		if (!ts)
			continue;

		if (stkctr_entry(&s->sess->stkctr[i]))
			continue;

		ptr = stktable_data_ptr(s->stkctr[i].table, ts, STKTABLE_DT_CONN_CUR);
		if (ptr) {
			HA_RWLOCK_WRLOCK(STK_SESS_LOCK, &ts->lock);

			if (stktable_data_cast(ptr, std_t_uint) > 0)
				stktable_data_cast(ptr, std_t_uint)--;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(s->stkctr[i].table, ts, 0);
		}
		stkctr_set_entry(&s->stkctr[i], NULL);
		stksess_kill_if_expired(s->stkctr[i].table, ts);
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

	if (unlikely(!s->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++) {
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

			if (stktable_data_cast(ptr, std_t_uint) > 0)
				stktable_data_cast(ptr, std_t_uint)--;

			HA_RWLOCK_WRUNLOCK(STK_SESS_LOCK, &ts->lock);

			/* If data was modified, we need to touch to re-schedule sync */
			stktable_touch_local(s->stkctr[i].table, ts, 0);
		}
		stkctr_set_entry(&s->stkctr[i], NULL);
		stksess_kill_if_expired(s->stkctr[i].table, ts);
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
		stktable_data_cast(ptr, std_t_uint)++;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_CONN_CNT);
	if (ptr)
		stktable_data_cast(ptr, std_t_uint)++;

	ptr = stktable_data_ptr(t, ts, STKTABLE_DT_CONN_RATE);
	if (ptr)
		update_freq_ctr_period(&stktable_data_cast(ptr, std_t_frqp),
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
	int i;

	if (unlikely(!s->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++) {
		if (!stkctr_inc_http_req_ctr(&s->stkctr[i]))
			stkctr_inc_http_req_ctr(&s->sess->stkctr[i]);
	}
}

/* Increase the number of cumulated HTTP requests in the backend's tracked
 * counters. We don't look up the session since it cannot happen in the backend.
 */
static inline void stream_inc_be_http_req_ctr(struct stream *s)
{
	int i;

	if (unlikely(!s->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++) {
		if (!stkctr_entry(&s->stkctr[i]) || !(stkctr_flags(&s->stkctr[i]) & STKCTR_TRACK_BACKEND))
			continue;

		stkctr_inc_http_req_ctr(&s->stkctr[i]);
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
	int i;

	if (unlikely(!s->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++) {
		if (!stkctr_inc_http_err_ctr(&s->stkctr[i]))
			stkctr_inc_http_err_ctr(&s->sess->stkctr[i]);
	}
}

/* Increase the number of cumulated failed HTTP responses in the tracked
 * counters. Only some 5xx responses should be counted here so that we can
 * distinguish between server failures and errors triggered by the client
 * (i.e. 501 and 505 may be triggered and must be ignored).
 */
static inline void stream_inc_http_fail_ctr(struct stream *s)
{
	int i;

	if (unlikely(!s->stkctr)) // pool not allocated yet
		return;

	for (i = 0; i < global.tune.nb_stk_ctr; i++) {
		if (!stkctr_inc_http_fail_ctr(&s->stkctr[i]))
			stkctr_inc_http_fail_ctr(&s->sess->stkctr[i]);
	}
}

static inline void stream_add_srv_conn(struct stream *strm, struct server *srv)
{
	/* note: this inserts in reverse order but we do not care, it's only
	 * used for massive kills (i.e. almost never). MT_LIST_INSERT() is a bit
	 * faster than MT_LIST_APPEND under contention due to a faster recovery
	 * from a conflict with an adjacent MT_LIST_DELETE, and using it improves
	 * the performance by about 3% on 32-cores.
	 */
	MT_LIST_INSERT(&srv->per_thr[tid].streams, &strm->by_srv);
	HA_ATOMIC_STORE(&strm->srv_conn, srv);
}

static inline void stream_del_srv_conn(struct stream *strm)
{
	struct server *srv = strm->srv_conn;

	if (!srv)
		return;

	MT_LIST_DELETE(&strm->by_srv);
	HA_ATOMIC_STORE(&strm->srv_conn, NULL);
}

static inline void stream_init_srv_conn(struct stream *strm)
{
	strm->srv_conn = NULL;
	MT_LIST_INIT(&strm->by_srv);
}

static inline void stream_choose_redispatch(struct stream *s)
{
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
	       (s->conn_retries % s->be->redispatch_after == 0)) ||
	      ((s->be->redispatch_after < 0) &&
	       (s->conn_retries % (s->max_retries + 1 + s->be->redispatch_after) == 0))) ||
	     (!(s->flags & SF_DIRECT) && s->be->srv_act > 1 &&
	      ((s->be->lbprm.algo & BE_LB_KIND) != BE_LB_KIND_HI)))) {
		sess_change_server(s, NULL);
		if (may_dequeue_tasks(objt_server(s->target), s->be))
			process_srv_queue(objt_server(s->target));

		sockaddr_free(&s->scb->dst);
		s->flags &= ~(SF_DIRECT | SF_ASSIGNED);
		s->scb->state = SC_ST_REQ;
	} else {
		if (objt_server(s->target))
			_HA_ATOMIC_INC(&__objt_server(s->target)->counters.retries);
		_HA_ATOMIC_INC(&s->be->be_counters.retries);
		s->scb->state = SC_ST_ASS;
	}

}

/*
 * This function only has to be called once after a wakeup event in case of
 * suspected timeout. It controls the stream connection timeout and sets
 * si->flags accordingly. It does NOT close anything, as this timeout may
 * be used for any purpose. It returns 1 if the timeout fired, otherwise
 * zero.
 */
static inline int stream_check_conn_timeout(struct stream *s)
{
	if (tick_is_expired(s->conn_exp, now_ms)) {
		s->flags |= SF_CONN_EXP;
		return 1;
	}
	return 0;
}

/* Wake a stream up for shutdown by sending it an event. The stream must be
 * locked one way or another so that it cannot leave (i.e. when inspecting a
 * locked list or under thread isolation). Process_stream() will recognize the
 * message and complete the job. <why> only supports SF_ERR_DOWN (mapped to
 * STRM_EVT_SHUT_SRV_DOWN), SF_ERR_KILLED (mapped to STRM_EVT_KILLED) and
 * SF_ERR_UP (mapped to STRM_EVT_SHUT_SRV_UP). Other values will just be
 * ignored. The stream is woken up with TASK_WOKEN_OTHER reason. The stream
 * handler will first call function stream_shutdown_self() on wakeup to complete
 * the notification.
 */
static inline void stream_shutdown(struct stream *s, int why)
{
	HA_ATOMIC_OR(&s->new_events, ((why == SF_ERR_DOWN) ? STRM_EVT_SHUT_SRV_DOWN :
				      (why == SF_ERR_KILLED) ? STRM_EVT_KILLED :
				      (why == SF_ERR_UP) ? STRM_EVT_SHUT_SRV_UP :
				      0));
	task_wakeup(s->task, TASK_WOKEN_OTHER);
}

/* Map task states to stream events. TASK_WOKEN_* are mapped on
 * STRM_EVT_*. Not all states/flags are mapped, only those explicitly used by
 * the stream.
 */
static inline unsigned int stream_map_task_state(unsigned int state)
{
	return ((state & TASK_WOKEN_TIMER) ? STRM_EVT_TIMER : 0)         |
		((state & TASK_WOKEN_MSG)  ? STRM_EVT_MSG : 0)           |
		((state & TASK_F_UEVT1)    ? STRM_EVT_SHUT_SRV_DOWN : 0) |
		((state & TASK_F_UEVT3)    ? STRM_EVT_SHUT_SRV_UP : 0)   |
		((state & TASK_F_UEVT2)    ? STRM_EVT_KILLED : 0)        |
		0;
}

static inline void stream_report_term_evt(struct stconn *sc, enum strm_term_event_type type)
{
	struct stream *s = sc_strm(sc);
	enum term_event_loc loc = tevt_loc_strm;

	if (!s)
		return;

	if (sc->flags & SC_FL_ISBACK)
		loc += 8;
	s->term_evts_log = tevt_report_event(s->term_evts_log, loc, type);
	sc->term_evts_log = tevt_report_event(sc->term_evts_log, loc, type);
}


int stream_set_timeout(struct stream *s, enum act_timeout_name name, int timeout);
void stream_retnclose(struct stream *s, const struct buffer *msg);
void sess_set_term_flags(struct stream *s);
void stream_abort(struct stream *s);

void service_keywords_register(struct action_kw_list *kw_list);
struct action_kw *service_find(const char *kw);
void list_services(FILE *out);

#endif /* _HAPROXY_STREAM_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
