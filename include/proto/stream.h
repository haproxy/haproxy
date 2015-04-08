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
#include <types/stream.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/stick_table.h>
#include <proto/task.h>

extern struct pool_head *pool2_stream;
extern struct list streams;
extern struct list buffer_wq;

extern struct data_cb sess_conn_cb;

struct stream *stream_new(struct session *sess, struct task *t, enum obj_type *origin);

/* perform minimal intializations, report 0 in case of error, 1 if OK. */
int init_stream();

/* kill a stream and set the termination flags to <why> (one of SF_ERR_*) */
void stream_shutdown(struct stream *stream, int why);

void stream_process_counters(struct stream *s);
void sess_change_server(struct stream *sess, struct server *newsrv);
struct task *process_stream(struct task *t);
void default_srv_error(struct stream *s, struct stream_interface *si);
struct stkctr *smp_fetch_sc_stkctr(struct session *sess, struct stream *strm, const struct arg *args, const char *kw);
int parse_track_counters(char **args, int *arg,
			 int section_type, struct proxy *curpx,
			 struct track_ctr_prm *prm,
			 struct proxy *defpx, char **err);

/* Update the stream's backend and server time stats */
void stream_update_time_stats(struct stream *s);
void __stream_offer_buffers(int rqlimit);
static inline void stream_offer_buffers();
int stream_alloc_work_buffer(struct stream *s);
void stream_release_buffers(struct stream *s);
int stream_alloc_recv_buffer(struct channel *chn);

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
 * ensuring that the pointer is valid first.
 */
static inline void stream_store_counters(struct stream *s)
{
	void *ptr;
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		if (!stkctr_entry(&s->stkctr[i]))
			continue;
		ptr = stktable_data_ptr(s->stkctr[i].table, stkctr_entry(&s->stkctr[i]), STKTABLE_DT_CONN_CUR);
		if (ptr)
			stktable_data_cast(ptr, conn_cur)--;
		stkctr_entry(&s->stkctr[i])->ref_cnt--;
		stksess_kill_if_expired(s->stkctr[i].table, stkctr_entry(&s->stkctr[i]));
		stkctr_set_entry(&s->stkctr[i], NULL);
	}
}

/* Remove the refcount from the stream counters tracked at the content level if
 * any, and clear the pointer to ensure this is only performed once. The caller
 * is responsible for ensuring that the pointer is valid first.
 */
static inline void stream_stop_content_counters(struct stream *s)
{
	void *ptr;
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		if (!stkctr_entry(&s->stkctr[i]))
			continue;

		if (!(stkctr_flags(&s->stkctr[i]) & STKCTR_TRACK_CONTENT))
			continue;

		ptr = stktable_data_ptr(s->stkctr[i].table, stkctr_entry(&s->stkctr[i]), STKTABLE_DT_CONN_CUR);
		if (ptr)
			stktable_data_cast(ptr, conn_cur)--;
		stkctr_entry(&s->stkctr[i])->ref_cnt--;
		stksess_kill_if_expired(s->stkctr[i].table, stkctr_entry(&s->stkctr[i]));
		stkctr_set_entry(&s->stkctr[i], NULL);
	}
}

/* Increase total and concurrent connection count for stick entry <ts> of table
 * <t>. The caller is responsible for ensuring that <t> and <ts> are valid
 * pointers, and for calling this only once per connection.
 */
static inline void stream_start_counters(struct stktable *t, struct stksess *ts)
{
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

/* Enable tracking of stream counters as <stkctr> on stksess <ts>. The caller is
 * responsible for ensuring that <t> and <ts> are valid pointers. Some controls
 * are performed to ensure the state can still change.
 */
static inline void stream_track_stkctr(struct stkctr *ctr, struct stktable *t, struct stksess *ts)
{
	if (stkctr_entry(ctr))
		return;

	ts->ref_cnt++;
	ctr->table = t;
	stkctr_set_entry(ctr, ts);
	stream_start_counters(t, ts);
}

/* Increase the number of cumulated HTTP requests in the tracked counters */
static void inline stream_inc_http_req_ctr(struct stream *s)
{
	void *ptr;
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		struct stkctr *stkctr = &s->stkctr[i];

		if (!stkctr_entry(stkctr)) {
			stkctr = &s->sess->stkctr[i];
			if (!stkctr_entry(stkctr))
				continue;
		}

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_CNT);
		if (ptr)
			stktable_data_cast(ptr, http_req_cnt)++;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
					       stkctr->table->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u, 1);
	}
}

/* Increase the number of cumulated HTTP requests in the backend's tracked
 * counters. We don't look up the session since it cannot happen in the bakcend.
 */
static void inline stream_inc_be_http_req_ctr(struct stream *s)
{
	void *ptr;
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		struct stkctr *stkctr = &s->stkctr[i];

		if (!stkctr_entry(stkctr))
			continue;

		if (!(stkctr_flags(&s->stkctr[i]) & STKCTR_TRACK_BACKEND))
			continue;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_CNT);
		if (ptr)
			stktable_data_cast(ptr, http_req_cnt)++;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_REQ_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, http_req_rate),
			                       stkctr->table->data_arg[STKTABLE_DT_HTTP_REQ_RATE].u, 1);
	}
}

/* Increase the number of cumulated failed HTTP requests in the tracked
 * counters. Only 4xx requests should be counted here so that we can
 * distinguish between errors caused by client behaviour and other ones.
 * Note that even 404 are interesting because they're generally caused by
 * vulnerability scans.
 */
static void inline stream_inc_http_err_ctr(struct stream *s)
{
	void *ptr;
	int i;

	for (i = 0; i < MAX_SESS_STKCTR; i++) {
		struct stkctr *stkctr = &s->stkctr[i];

		if (!stkctr_entry(stkctr)) {
			stkctr = &s->sess->stkctr[i];
			if (!stkctr_entry(stkctr))
				continue;
		}

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_ERR_CNT);
		if (ptr)
			stktable_data_cast(ptr, http_err_cnt)++;

		ptr = stktable_data_ptr(stkctr->table, stkctr_entry(stkctr), STKTABLE_DT_HTTP_ERR_RATE);
		if (ptr)
			update_freq_ctr_period(&stktable_data_cast(ptr, http_err_rate),
			                       stkctr->table->data_arg[STKTABLE_DT_HTTP_ERR_RATE].u, 1);
	}
}

static void inline stream_add_srv_conn(struct stream *sess, struct server *srv)
{
	sess->srv_conn = srv;
	LIST_ADD(&srv->actconns, &sess->by_srv);
}

static void inline stream_del_srv_conn(struct stream *sess)
{
	if (!sess->srv_conn)
		return;

	sess->srv_conn = NULL;
	LIST_DEL(&sess->by_srv);
}

static void inline stream_init_srv_conn(struct stream *sess)
{
	sess->srv_conn = NULL;
	LIST_INIT(&sess->by_srv);
}

static inline void stream_offer_buffers()
{
	int avail;

	if (LIST_ISEMPTY(&buffer_wq))
		return;

	/* all streams will need 1 buffer, so we can stop waking up streams
	 * once we have enough of them to eat all the buffers. Note that we
	 * don't really know if they are streams or just other tasks, but
	 * that's a rough estimate. Similarly, for each cached event we'll need
	 * 1 buffer. If no buffer is currently used, always wake up the number
	 * of tasks we can offer a buffer based on what is allocated, and in
	 * any case at least one task per two reserved buffers.
	 */
	avail = pool2_buffer->allocated - pool2_buffer->used - global.tune.reserved_bufs / 2;

	if (avail > (int)run_queue)
		__stream_offer_buffers(avail);
}

#endif /* _PROTO_STREAM_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
