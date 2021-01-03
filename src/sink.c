/*
 * Event sink management
 *
 * Copyright (C) 2000-2019 Willy Tarreau - w@1wt.eu
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

#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/ring.h>
#include <haproxy/signal.h>
#include <haproxy/sink.h>
#include <haproxy/stream_interface.h>
#include <haproxy/time.h>

struct list sink_list = LIST_HEAD_INIT(sink_list);

struct sink *cfg_sink;

struct sink *sink_find(const char *name)
{
	struct sink *sink;

	list_for_each_entry(sink, &sink_list, sink_list)
		if (strcmp(sink->name, name) == 0)
			return sink;
	return NULL;
}

/* creates a new sink and adds it to the list, it's still generic and not fully
 * initialized. Returns NULL on allocation failure. If another one already
 * exists with the same name, it will be returned. The caller can detect it as
 * a newly created one has type SINK_TYPE_NEW.
 */
static struct sink *__sink_new(const char *name, const char *desc, int fmt)
{
	struct sink *sink;

	sink = sink_find(name);
	if (sink)
		goto end;

	sink = calloc(1, sizeof(*sink));
	if (!sink)
		goto end;

	sink->name = strdup(name);
	if (!sink->name)
		goto err;

	sink->desc = strdup(desc);
	if (!sink->desc)
		goto err;

	sink->fmt  = fmt;
	sink->type = SINK_TYPE_NEW;
	sink->maxlen = BUFSIZE;
	/* address will be filled by the caller if needed */
	sink->ctx.fd = -1;
	sink->ctx.dropped = 0;
	HA_RWLOCK_INIT(&sink->ctx.lock);
	LIST_ADDQ(&sink_list, &sink->sink_list);
 end:
	return sink;

 err:
	free(sink->name); sink->name = NULL;
	free(sink->desc); sink->desc = NULL;
	free(sink); sink = NULL;

	return NULL;
}

/* creates a sink called <name> of type FD associated to fd <fd>, format <fmt>,
 * and description <desc>. Returns NULL on allocation failure or conflict.
 * Perfect duplicates are merged (same type, fd, and name).
 */
struct sink *sink_new_fd(const char *name, const char *desc, enum log_fmt fmt, int fd)
{
	struct sink *sink;

	sink = __sink_new(name, desc, fmt);
	if (!sink || (sink->type == SINK_TYPE_FD && sink->ctx.fd == fd))
		goto end;

	if (sink->type != SINK_TYPE_NEW) {
		sink = NULL;
		goto end;
	}

	sink->type = SINK_TYPE_FD;
	sink->ctx.fd = fd;
 end:
	return sink;
}

/* creates a sink called <name> of type BUF of size <size>, format <fmt>,
 * and description <desc>. Returns NULL on allocation failure or conflict.
 * Perfect duplicates are merged (same type and name). If sizes differ, the
 * largest one is kept.
 */
struct sink *sink_new_buf(const char *name, const char *desc, enum log_fmt fmt, size_t size)
{
	struct sink *sink;

	sink = __sink_new(name, desc, fmt);
	if (!sink)
		goto fail;

	if (sink->type == SINK_TYPE_BUFFER) {
		/* such a buffer already exists, we may have to resize it */
		if (!ring_resize(sink->ctx.ring, size))
			goto fail;
		goto end;
	}

	if (sink->type != SINK_TYPE_NEW) {
		/* already exists of another type */
		goto fail;
	}

	sink->ctx.ring = ring_new(size);
	if (!sink->ctx.ring) {
		LIST_DEL(&sink->sink_list);
		free(sink->name);
		free(sink->desc);
		free(sink);
		goto fail;
	}

	sink->type = SINK_TYPE_BUFFER;
 end:
	return sink;
 fail:
	return NULL;
}

/* tries to send <nmsg> message parts (up to 8, ignored above) from message
 * array <msg> to sink <sink>. Formatting according to the sink's preference is
 * done here. Lost messages are NOT accounted for. It is preferable to call
 * sink_write() instead which will also try to emit the number of dropped
 * messages when there are any. It returns >0 if it could write anything,
 * <=0 otherwise.
 */
 ssize_t __sink_write(struct sink *sink, const struct ist msg[], size_t nmsg,
	             int level, int facility, struct ist *metadata)
 {
	struct ist *pfx = NULL;
	size_t npfx = 0;

	if (sink->fmt == LOG_FORMAT_RAW)
		goto send;

	pfx = build_log_header(sink->fmt, level, facility, metadata, &npfx);

send:
	if (sink->type == SINK_TYPE_FD) {
		return fd_write_frag_line(sink->ctx.fd, sink->maxlen, pfx, npfx, msg, nmsg, 1);
	}
	else if (sink->type == SINK_TYPE_BUFFER) {
		return ring_write(sink->ctx.ring, sink->maxlen, pfx, npfx, msg, nmsg);
	}
	return 0;
}

/* Tries to emit a message indicating the number of dropped events. In case of
 * success, the amount of drops is reduced by as much. It's supposed to be
 * called under an exclusive lock on the sink to avoid multiple produces doing
 * the same. On success, >0 is returned, otherwise <=0 on failure.
 */
int sink_announce_dropped(struct sink *sink, int facility)
{
	static THREAD_LOCAL struct ist metadata[LOG_META_FIELDS];
	static THREAD_LOCAL pid_t curr_pid;
	static THREAD_LOCAL char pidstr[16];
	unsigned int dropped;
	struct buffer msg;
	struct ist msgvec[1];
	char logbuf[64];

	while (unlikely((dropped = sink->ctx.dropped) > 0)) {
		chunk_init(&msg, logbuf, sizeof(logbuf));
		chunk_printf(&msg, "%u event%s dropped", dropped, dropped > 1 ? "s" : "");
		msgvec[0] = ist2(msg.area, msg.data);

		if (!metadata[LOG_META_HOST].len) {
			if (global.log_send_hostname)
				metadata[LOG_META_HOST] = ist2(global.log_send_hostname, strlen(global.log_send_hostname));
		}

		if (!metadata[LOG_META_TAG].len)
			metadata[LOG_META_TAG] = ist2(global.log_tag.area, global.log_tag.data);

		if (unlikely(curr_pid != getpid()))
			 metadata[LOG_META_PID].len = 0;

		if (!metadata[LOG_META_PID].len) {
			curr_pid = getpid();
			ltoa_o(curr_pid, pidstr, sizeof(pidstr));
			metadata[LOG_META_PID] = ist2(pidstr, strlen(pidstr));
		}

		if (__sink_write(sink, msgvec, 1, LOG_NOTICE, facility, metadata) <= 0)
			return 0;
		/* success! */
		HA_ATOMIC_SUB(&sink->ctx.dropped, dropped);
	}
	return 1;
}

/* parse the "show events" command, returns 1 if a message is returned, otherwise zero */
static int cli_parse_show_events(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct sink *sink;
	int arg;

	args++; // make args[1] the 1st arg

	if (!*args[1]) {
		/* no arg => report the list of supported sink */
		chunk_printf(&trash, "Supported events sinks are listed below. Add -w(wait), -n(new). Any key to stop\n");
		list_for_each_entry(sink, &sink_list, sink_list) {
			chunk_appendf(&trash, "    %-10s : type=%s, %u dropped, %s\n",
				      sink->name,
				      sink->type == SINK_TYPE_NEW ? "init" :
				      sink->type == SINK_TYPE_FD ? "fd" :
				      sink->type == SINK_TYPE_BUFFER ? "buffer" : "?",
				      sink->ctx.dropped, sink->desc);
		}

		trash.area[trash.data] = 0;
		return cli_msg(appctx, LOG_WARNING, trash.area);
	}

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	sink = sink_find(args[1]);
	if (!sink)
		return cli_err(appctx, "No such event sink");

	if (sink->type != SINK_TYPE_BUFFER)
		return cli_msg(appctx, LOG_NOTICE, "Nothing to report for this sink");

	for (arg = 2; *args[arg]; arg++) {
		if (strcmp(args[arg], "-w") == 0)
			appctx->ctx.cli.i0 |= 1; // wait mode
		else if (strcmp(args[arg], "-n") == 0)
			appctx->ctx.cli.i0 |= 2; // seek to new
		else if (strcmp(args[arg], "-nw") == 0 || strcmp(args[arg], "-wn") == 0)
			appctx->ctx.cli.i0 |= 3; // seek to new + wait
		else
			return cli_err(appctx, "unknown option");
	}
	return ring_attach_cli(sink->ctx.ring, appctx);
}

/* Pre-configures a ring proxy to emit connections */
void sink_setup_proxy(struct proxy *px)
{
	px->last_change = now.tv_sec;
	px->cap = PR_CAP_FE | PR_CAP_BE;
	px->maxconn = 0;
	px->conn_retries = 1;
	px->timeout.server = TICK_ETERNITY;
	px->timeout.client = TICK_ETERNITY;
	px->timeout.connect = TICK_ETERNITY;
	px->accept = NULL;
	px->options2 |= PR_O2_INDEPSTR | PR_O2_SMARTCON | PR_O2_SMARTACC;
	px->bind_proc = 0; /* will be filled by users */
}

/*
 * IO Handler to handle message push to syslog tcp server
 */
static void sink_forward_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct sink *sink = strm_fe(s)->parent;
	struct sink_forward_target *sft = appctx->ctx.sft.ptr;
	struct ring *ring = sink->ctx.ring;
	struct buffer *buf = &ring->buf;
	uint64_t msg_len;
	size_t len, cnt, ofs;
	int ret = 0;

	/* if stopping was requested, close immediately */
	if (unlikely(stopping))
		goto close;

	/* for rex because it seems reset to timeout
	 * and we don't want expire on this case
	 * with a syslog server
	 */
	si_oc(si)->rex = TICK_ETERNITY;
	/* rto should not change but it seems the case */
	si_oc(si)->rto = TICK_ETERNITY;

	/* an error was detected */
	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		goto close;

	/* con closed by server side */
	if ((si_oc(si)->flags & CF_SHUTW))
		goto close;

	/* if the connection is not established, inform the stream that we want
	 * to be notified whenever the connection completes.
	 */
	if (si_opposite(si)->state < SI_ST_EST) {
		si_cant_get(si);
		si_rx_conn_blk(si);
		si_rx_endp_more(si);
		return;
	}

	HA_SPIN_LOCK(SFT_LOCK, &sft->lock);
	if (appctx != sft->appctx) {
		HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);
		goto close;
	}
	ofs = sft->ofs;

	HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &ring->lock);
	LIST_DEL_INIT(&appctx->wait_entry);
	HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);

	HA_RWLOCK_RDLOCK(LOGSRV_LOCK, &ring->lock);

	/* explanation for the initialization below: it would be better to do
	 * this in the parsing function but this would occasionally result in
	 * dropped events because we'd take a reference on the oldest message
	 * and keep it while being scheduled. Thus instead let's take it the
	 * first time we enter here so that we have a chance to pass many
	 * existing messages before grabbing a reference to a location. This
	 * value cannot be produced after initialization.
	 */
	if (unlikely(ofs == ~0)) {
		ofs = 0;

		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
	}

	/* in this loop, ofs always points to the counter byte that precedes
	 * the message so that we can take our reference there if we have to
	 * stop before the end (ret=0).
	 */
	if (si_opposite(si)->state == SI_ST_EST) {
		/* we were already there, adjust the offset to be relative to
		 * the buffer's head and remove us from the counter.
		 */
		ofs -= ring->ofs;
		BUG_ON(ofs >= buf->size);
		HA_ATOMIC_SUB(b_peek(buf, ofs), 1);

		ret = 1;
		while (ofs + 1 < b_data(buf)) {
			cnt = 1;
			len = b_peek_varint(buf, ofs + cnt, &msg_len);
			if (!len)
				break;
			cnt += len;
			BUG_ON(msg_len + ofs + cnt + 1 > b_data(buf));

			if (unlikely(msg_len + 1 > b_size(&trash))) {
				/* too large a message to ever fit, let's skip it */
				ofs += cnt + msg_len;
				continue;
			}

			chunk_reset(&trash);
			len = b_getblk(buf, trash.area, msg_len, ofs + cnt);
			trash.data += len;
			trash.area[trash.data++] = '\n';

			if (ci_putchk(si_ic(si), &trash) == -1) {
				si_rx_room_blk(si);
				ret = 0;
				break;
			}
			ofs += cnt + msg_len;
		}

		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
		sft->ofs = ofs;
	}
	HA_RWLOCK_RDUNLOCK(LOGSRV_LOCK, &ring->lock);

	if (ret) {
		/* let's be woken up once new data arrive */
		HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &ring->lock);
		LIST_ADDQ(&ring->waiters, &appctx->wait_entry);
		HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);
		si_rx_endp_done(si);
	}
	HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);

	/* always drain data from server */
	co_skip(si_oc(si), si_oc(si)->output);
	return;

close:
	si_shutw(si);
	si_shutr(si);
	si_ic(si)->flags |= CF_READ_NULL;
}

/*
 * IO Handler to handle message push to syslog tcp server
 * using octet counting frames
 */
static void sink_forward_oc_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct stream *s = si_strm(si);
	struct sink *sink = strm_fe(s)->parent;
	struct sink_forward_target *sft = appctx->ctx.sft.ptr;
	struct ring *ring = sink->ctx.ring;
	struct buffer *buf = &ring->buf;
	uint64_t msg_len;
	size_t len, cnt, ofs;
	int ret = 0;
	char *p;

	/* if stopping was requested, close immediately */
	if (unlikely(stopping))
		goto close;

	/* for rex because it seems reset to timeout
	 * and we don't want expire on this case
	 * with a syslog server
	 */
	si_oc(si)->rex = TICK_ETERNITY;
	/* rto should not change but it seems the case */
	si_oc(si)->rto = TICK_ETERNITY;

	/* an error was detected */
	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		goto close;

	/* con closed by server side */
	if ((si_oc(si)->flags & CF_SHUTW))
		goto close;

	/* if the connection is not established, inform the stream that we want
	 * to be notified whenever the connection completes.
	 */
	if (si_opposite(si)->state < SI_ST_EST) {
		si_cant_get(si);
		si_rx_conn_blk(si);
		si_rx_endp_more(si);
		return;
	}

	HA_SPIN_LOCK(SFT_LOCK, &sft->lock);
	if (appctx != sft->appctx) {
		HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);
		goto close;
	}
	ofs = sft->ofs;

	HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &ring->lock);
	LIST_DEL_INIT(&appctx->wait_entry);
	HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);

	HA_RWLOCK_RDLOCK(LOGSRV_LOCK, &ring->lock);

	/* explanation for the initialization below: it would be better to do
	 * this in the parsing function but this would occasionally result in
	 * dropped events because we'd take a reference on the oldest message
	 * and keep it while being scheduled. Thus instead let's take it the
	 * first time we enter here so that we have a chance to pass many
	 * existing messages before grabbing a reference to a location. This
	 * value cannot be produced after initialization.
	 */
	if (unlikely(ofs == ~0)) {
		ofs = 0;

		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
	}

	/* in this loop, ofs always points to the counter byte that precedes
	 * the message so that we can take our reference there if we have to
	 * stop before the end (ret=0).
	 */
	if (si_opposite(si)->state == SI_ST_EST) {
		/* we were already there, adjust the offset to be relative to
		 * the buffer's head and remove us from the counter.
		 */
		ofs -= ring->ofs;
		BUG_ON(ofs >= buf->size);
		HA_ATOMIC_SUB(b_peek(buf, ofs), 1);

		ret = 1;
		while (ofs + 1 < b_data(buf)) {
			cnt = 1;
			len = b_peek_varint(buf, ofs + cnt, &msg_len);
			if (!len)
				break;
			cnt += len;
			BUG_ON(msg_len + ofs + cnt + 1 > b_data(buf));

			chunk_reset(&trash);
			p = ulltoa(msg_len, trash.area, b_size(&trash));
			if (p) {
				trash.data = (p - trash.area) + 1;
				*p = ' ';
			}

			if (!p || (trash.data + msg_len > b_size(&trash))) {
				/* too large a message to ever fit, let's skip it */
				ofs += cnt + msg_len;
				continue;
			}

			trash.data += b_getblk(buf, p + 1, msg_len, ofs + cnt);

			if (ci_putchk(si_ic(si), &trash) == -1) {
				si_rx_room_blk(si);
				ret = 0;
				break;
			}
			ofs += cnt + msg_len;
		}

		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
		sft->ofs = ofs;
	}
	HA_RWLOCK_RDUNLOCK(LOGSRV_LOCK, &ring->lock);

	if (ret) {
		/* let's be woken up once new data arrive */
		HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &ring->lock);
		LIST_ADDQ(&ring->waiters, &appctx->wait_entry);
		HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);
		si_rx_endp_done(si);
	}
	HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);

	/* always drain data from server */
	co_skip(si_oc(si), si_oc(si)->output);
	return;

close:
	si_shutw(si);
	si_shutr(si);
	si_ic(si)->flags |= CF_READ_NULL;
}

void __sink_forward_session_deinit(struct sink_forward_target *sft)
{
	struct stream_interface *si;
	struct stream *s;
	struct sink *sink;

	if (!sft->appctx)
		return;

	si = sft->appctx->owner;
	if (!si)
		return;

	s = si_strm(si);
	if (!s)
		return;

	sink = strm_fe(s)->parent;
	if (!sink)
		return;

	HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &sink->ctx.ring->lock);
	LIST_DEL_INIT(&sft->appctx->wait_entry);
	HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &sink->ctx.ring->lock);

	sft->appctx = NULL;
	task_wakeup(sink->forward_task, TASK_WOKEN_MSG);
}


static void sink_forward_session_release(struct appctx *appctx)
{
	struct sink_forward_target *sft = appctx->ctx.peers.ptr;

	if (!sft)
		return;

	HA_SPIN_LOCK(SFT_LOCK, &sft->lock);
	if (sft->appctx == appctx)
		__sink_forward_session_deinit(sft);
	HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);
}

static struct applet sink_forward_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<SINKFWD>", /* used for logging */
	.fct = sink_forward_io_handler,
	.release = sink_forward_session_release,
};

static struct applet sink_forward_oc_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<SINKFWDOC>", /* used for logging */
	.fct = sink_forward_oc_io_handler,
	.release = sink_forward_session_release,
};

/*
 * Create a new peer session in assigned state (connect will start automatically)
 */
static struct appctx *sink_forward_session_create(struct sink *sink, struct sink_forward_target *sft)
{
	struct proxy *p = sink->forward_px;
	struct appctx *appctx;
	struct session *sess;
	struct stream *s;
	struct applet *applet = &sink_forward_applet;

	if (sft->srv->log_proto == SRV_LOG_PROTO_OCTET_COUNTING)
		applet = &sink_forward_oc_applet;

	appctx = appctx_new(applet, tid_bit);
	if (!appctx)
		goto out_close;

	appctx->ctx.sft.ptr = (void *)sft;

	sess = session_new(p, NULL, &appctx->obj_type);
	if (!sess) {
		ha_alert("out of memory in peer_session_create().\n");
		goto out_free_appctx;
	}

	if ((s = stream_new(sess, &appctx->obj_type, &BUF_NULL)) == NULL) {
		ha_alert("Failed to initialize stream in peer_session_create().\n");
		goto out_free_sess;
	}


	s->target = &sft->srv->obj_type;
	if (!sockaddr_alloc(&s->target_addr, &sft->srv->addr, sizeof(sft->srv->addr)))
		goto out_free_strm;
	s->flags = SF_ASSIGNED|SF_ADDR_SET;
	s->si[1].flags |= SI_FL_NOLINGER;

	s->do_log = NULL;
	s->uniq_id = 0;

	s->res.flags |= CF_READ_DONTWAIT;
	/* for rto and rex to eternity to not expire on idle recv:
	 * We are using a syslog server.
	 */
	s->res.rto = TICK_ETERNITY;
	s->res.rex = TICK_ETERNITY;
	sft->appctx = appctx;
	task_wakeup(s->task, TASK_WOKEN_INIT);
	return appctx;

	/* Error unrolling */
 out_free_strm:
	LIST_DEL(&s->list);
	pool_free(pool_head_stream, s);
 out_free_sess:
	session_free(sess);
 out_free_appctx:
	appctx_free(appctx);
 out_close:
	return NULL;
}

/*
 * Task to handle connctions to forward servers
 */
static struct task *process_sink_forward(struct task * task, void *context, unsigned short state)
{
	struct sink *sink = (struct sink *)context;
	struct sink_forward_target *sft = sink->sft;

	task->expire = TICK_ETERNITY;

	if (!stopping) {
		while (sft) {
			HA_SPIN_LOCK(SFT_LOCK, &sft->lock);
			/* if appctx is NULL, start a new session */
			if (!sft->appctx)
				sft->appctx = sink_forward_session_create(sink, sft);
			HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);
			sft = sft->next;
		}
	}
	else {
		while (sft) {
			HA_SPIN_LOCK(SFT_LOCK, &sft->lock);
			/* awake applet to perform a clean close */
			if (sft->appctx)
				appctx_wakeup(sft->appctx);
			HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);
			sft = sft->next;
		}
	}

	return task;
}
/*
 * Init task to manage connctions to forward servers
 *
 * returns 0 in case of error.
 */
int sink_init_forward(struct sink *sink)
{
	sink->forward_task = task_new(MAX_THREADS_MASK);
	if (!sink->forward_task)
		return 0;

	sink->forward_task->process = process_sink_forward;
	sink->forward_task->context = (void *)sink;
	sink->forward_sighandler = signal_register_task(0, sink->forward_task, 0);
	task_wakeup(sink->forward_task, TASK_WOKEN_INIT);
	return 1;
}
/*
 * Parse "ring" section and create corresponding sink buffer.
 *
 * The function returns 0 in success case, otherwise, it returns error
 * flags.
 */
int cfg_parse_ring(const char *file, int linenum, char **args, int kwm)
{
	int err_code = 0;
	const char *inv;
	size_t size = BUFSIZE;
	struct proxy *p;

	if (strcmp(args[0], "ring") == 0) { /* new peers section */
		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing ring name.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		inv = invalid_char(args[1]);
		if (inv) {
			ha_alert("parsing [%s:%d] : invalid ring name '%s' (character '%c' is not permitted).\n", file, linenum, args[1], *inv);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		if (sink_find(args[1])) {
			ha_alert("parsing [%s:%d] : sink named '%s' already exists.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		cfg_sink = sink_new_buf(args[1], args[1], LOG_FORMAT_RAW, size);
		if (!cfg_sink || cfg_sink->type != SINK_TYPE_BUFFER) {
			ha_alert("parsing [%s:%d] : unable to create a new sink buffer for ring '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		/* allocate new proxy to handle forwards */
		p = calloc(1, sizeof *p);
		if (!p) {
			ha_alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		init_new_proxy(p);
		sink_setup_proxy(p);
		p->parent = cfg_sink;
		p->id = strdup(args[1]);
		p->conf.args.file = p->conf.file = strdup(file);
		p->conf.args.line = p->conf.line = linenum;
		cfg_sink->forward_px = p;
	}
	else if (strcmp(args[0], "size") == 0) {
		size = atol(args[1]);
		if (!size) {
			ha_alert("parsing [%s:%d] : invalid size '%s' for new sink buffer.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		if (!cfg_sink || (cfg_sink->type != SINK_TYPE_BUFFER)
		              || !ring_resize(cfg_sink->ctx.ring, size)) {
			ha_alert("parsing [%s:%d] : fail to set sink buffer size '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}
	}
	else if (strcmp(args[0],"server") == 0) {
		err_code |= parse_server(file, linenum, args, cfg_sink->forward_px, NULL, 1, 0, 1);
	}
	else if (strcmp(args[0],"timeout") == 0) {
		if (!cfg_sink || !cfg_sink->forward_px) {
			ha_alert("parsing [%s:%d] : unable to set timeout '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

                if (strcmp(args[1], "connect") == 0 ||
		    strcmp(args[1], "server") == 0) {
			const char *res;
			unsigned int tout;

			if (!*args[2]) {
				ha_alert("parsing [%s:%d] : '%s %s' expects <time> as argument.\n",
					 file, linenum, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto err;
			}
			res = parse_time_err(args[2], &tout, TIME_UNIT_MS);
			if (res == PARSE_TIME_OVER) {
				ha_alert("parsing [%s:%d]: timer overflow in argument <%s> to <%s %s>, maximum value is 2147483647 ms (~24.8 days).\n",
					 file, linenum, args[2], args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto err;
			}
			else if (res == PARSE_TIME_UNDER) {
				ha_alert("parsing [%s:%d]: timer underflow in argument <%s> to <%s %s>, minimum non-null value is 1 ms.\n",
					 file, linenum, args[2], args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto err;
			}
			else if (res) {
				ha_alert("parsing [%s:%d]: unexpected character '%c' in argument to <%s %s>.\n",
					 file, linenum, *res, args[0], args[1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto err;
			}
                        if (args[1][2] == 'c')
                                cfg_sink->forward_px->timeout.connect = tout;
                        else
                                cfg_sink->forward_px->timeout.server = tout;
		}
	}
	else if (strcmp(args[0],"format") == 0) {
		if (!cfg_sink) {
			ha_alert("parsing [%s:%d] : unable to set format '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		cfg_sink->fmt = get_log_format(args[1]);
		if (cfg_sink->fmt == LOG_FORMAT_UNSPEC) {
			ha_alert("parsing [%s:%d] : unknown format '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}
	}
	else if (strcmp(args[0],"maxlen") == 0) {
		if (!cfg_sink) {
			ha_alert("parsing [%s:%d] : unable to set event max length '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		cfg_sink->maxlen = atol(args[1]);
		if (!cfg_sink->maxlen) {
			ha_alert("parsing [%s:%d] : invalid size '%s' for new sink buffer.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}
	}
	else if (strcmp(args[0],"description") == 0) {
		if (!cfg_sink) {
			ha_alert("parsing [%s:%d] : unable to set description '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		if (!*args[1]) {
			ha_alert("parsing [%s:%d] : missing ring description text.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		free(cfg_sink->desc);

		cfg_sink->desc = strdup(args[1]);
		if (!cfg_sink->desc) {
			ha_alert("parsing [%s:%d] : fail to set description '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}
	}
	else {
		ha_alert("parsing [%s:%d] : unknown statement '%s'.\n", file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto err;
	}

err:
	return err_code;
}

/*
 * Post parsing "ring" section.
 *
 * The function returns 0 in success case, otherwise, it returns error
 * flags.
 */
int cfg_post_parse_ring()
{
	int err_code = 0;
	struct server *srv;

	if (cfg_sink && (cfg_sink->type == SINK_TYPE_BUFFER)) {
		if (cfg_sink->maxlen > b_size(&cfg_sink->ctx.ring->buf)) {
			ha_warning("ring '%s' event max length '%u' exceeds size, forced to size '%lu'.\n",
			           cfg_sink->name, cfg_sink->maxlen, (unsigned long)b_size(&cfg_sink->ctx.ring->buf));
			cfg_sink->maxlen = b_size(&cfg_sink->ctx.ring->buf);
			err_code |= ERR_ALERT;
		}

		/* prepare forward server descriptors */
		if (cfg_sink->forward_px) {
			srv = cfg_sink->forward_px->srv;
			while (srv) {
				struct sink_forward_target *sft;
				/* init ssl if needed */
				if (srv->use_ssl == 1 && xprt_get(XPRT_SSL) && xprt_get(XPRT_SSL)->prepare_srv) {
					if (xprt_get(XPRT_SSL)->prepare_srv(srv)) {
						ha_alert("unable to prepare SSL for server '%s' in ring '%s'.\n", srv->id, cfg_sink->name);
						err_code |= ERR_ALERT | ERR_FATAL;
					}
				}

				/* allocate sink_forward_target descriptor */
				sft = calloc(1, sizeof(*sft));
				if (!sft) {
					ha_alert("memory allocation error initializing server '%s' in ring '%s'.\n",srv->id, cfg_sink->name);
					err_code |= ERR_ALERT | ERR_FATAL;
					break;
				}
				sft->srv = srv;
				sft->appctx = NULL;
				sft->ofs = ~0; /* init ring offset */
				sft->next = cfg_sink->sft;
				HA_SPIN_INIT(&sft->lock);

				/* mark server attached to the ring */
				if (!ring_attach(cfg_sink->ctx.ring)) {
					ha_alert("server '%s' sets too many watchers > 255 on ring '%s'.\n", srv->id, cfg_sink->name);
					err_code |= ERR_ALERT | ERR_FATAL;
				}
				cfg_sink->sft = sft;
				srv = srv->next;
			}
			sink_init_forward(cfg_sink);
		}
	}
	cfg_sink = NULL;

	return err_code;
}

/* resolve sink names at end of config. Returns 0 on success otherwise error
 * flags.
*/
int post_sink_resolve()
{
	int err_code = ERR_NONE;
	struct logsrv *logsrv, *logb;
	struct sink *sink;
	struct proxy *px;

	list_for_each_entry_safe(logsrv, logb, &global.logsrvs, list) {
		if (logsrv->type == LOG_TARGET_BUFFER) {
			sink = sink_find(logsrv->ring_name);
			if (!sink || sink->type != SINK_TYPE_BUFFER) {
				ha_alert("global log server uses unknown ring named '%s'.\n", logsrv->ring_name);
				err_code |= ERR_ALERT | ERR_FATAL;
			}
			logsrv->sink = sink;
		}
	}

	for (px = proxies_list; px; px = px->next) {
		list_for_each_entry_safe(logsrv, logb, &px->logsrvs, list) {
			if (logsrv->type == LOG_TARGET_BUFFER) {
				sink = sink_find(logsrv->ring_name);
				if (!sink || sink->type != SINK_TYPE_BUFFER) {
					ha_alert("proxy '%s' log server uses unknown ring named '%s'.\n", px->id, logsrv->ring_name);
					err_code |= ERR_ALERT | ERR_FATAL;
				}
				logsrv->sink = sink;
			}
		}
	}

	for (px = cfg_log_forward; px; px = px->next) {
		list_for_each_entry_safe(logsrv, logb, &px->logsrvs, list) {
			if (logsrv->type == LOG_TARGET_BUFFER) {
				sink = sink_find(logsrv->ring_name);
				if (!sink || sink->type != SINK_TYPE_BUFFER) {
					ha_alert("log-forward '%s' log server uses unknown ring named '%s'.\n", px->id, logsrv->ring_name);
					err_code |= ERR_ALERT | ERR_FATAL;
				}
				logsrv->sink = sink;
			}
		}
	}
	return err_code;
}


static void sink_init()
{
	sink_new_fd("stdout", "standard output (fd#1)", LOG_FORMAT_RAW, 1);
	sink_new_fd("stderr", "standard output (fd#2)", LOG_FORMAT_RAW, 2);
	sink_new_buf("buf0",  "in-memory ring buffer", LOG_FORMAT_TIMED, 1048576);
}

static void sink_deinit()
{
	struct sink *sink, *sb;

	list_for_each_entry_safe(sink, sb, &sink_list, sink_list) {
		if (sink->type == SINK_TYPE_BUFFER)
			ring_free(sink->ctx.ring);
		LIST_DEL(&sink->sink_list);
		free(sink->name);
		free(sink->desc);
		free(sink);
	}
}

INITCALL0(STG_REGISTER, sink_init);
REGISTER_POST_DEINIT(sink_deinit);

static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "events", NULL }, "show events [<sink>] : show event sink state", cli_parse_show_events, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/* config parsers for this section */
REGISTER_CONFIG_SECTION("ring", cfg_parse_ring, cfg_post_parse_ring);
REGISTER_POST_CHECK(post_sink_resolve);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
