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

#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>

#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/cfgparse.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/ring.h>
#include <haproxy/sc_strm.h>
#include <haproxy/signal.h>
#include <haproxy/sink.h>
#include <haproxy/stconn.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

struct list sink_list = LIST_HEAD_INIT(sink_list);

/* sink proxies list */
struct proxy *sink_proxies_list;

struct sink *cfg_sink;

static struct sink *_sink_find(const char *name)
{
	struct sink *sink;

	list_for_each_entry(sink, &sink_list, sink_list)
		if (strcmp(sink->name, name) == 0)
			return sink;
	return NULL;
}

/* returns sink if it really exists */
struct sink *sink_find(const char *name)
{
	struct sink *sink;

	sink = _sink_find(name);
	if (sink && sink->type != SINK_TYPE_FORWARD_DECLARED)
		return sink;
	return NULL;
}

/* Similar to sink_find(), but intended to be used during config parsing:
 * tries to resolve sink name, if it fails, creates the sink and marks
 * it as forward-declared and hope that it will be defined later.
 *
 * The caller has to identify itself using <from>, <file> and <line> in
 * order to report precise error messages in the event that the sink is
 * never defined later (only the first misuse will be considered).
 *
 * It returns the sink on success and NULL on failure (memory error)
 */
struct sink *sink_find_early(const char *name, const char *from, const char *file, int line)
{
	struct sink *sink;

	/* not expected to be used during runtime */
	BUG_ON(!(global.mode & MODE_STARTING));

	sink = _sink_find(name);
	if (sink)
		return sink;

	/* not found, try to forward-declare it */
	sink = calloc(1, sizeof(*sink));
	if (!sink)
		return NULL;

	sink->name = strdup(name);
	if (!sink->name)
		goto err;

	memprintf(&sink->desc, "parsing [%s:%d] : %s", file, line, from);
	if (!sink->desc)
		goto err;

	sink->type = SINK_TYPE_FORWARD_DECLARED;
	LIST_APPEND(&sink_list, &sink->sink_list);

	return sink;

 err:
	ha_free(&sink->name);
	ha_free(&sink->desc);
	ha_free(&sink);
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
	uint8_t _new = 0;

	sink = _sink_find(name);
	if (sink) {
		if (sink->type == SINK_TYPE_FORWARD_DECLARED) {
			ha_free(&sink->desc); // free previous desc
			goto forward_declared;
		}
		goto end;
	}

	sink = calloc(1, sizeof(*sink));
	_new = 1;
	if (!sink)
		goto end;

	sink->name = strdup(name);
	if (!sink->name)
		goto err;

 forward_declared:
	sink->desc = strdup(desc);
	if (!sink->desc)
		goto err;

	sink->fmt  = fmt;
	sink->type = SINK_TYPE_NEW;
	sink->maxlen = BUFSIZE;
	/* address will be filled by the caller if needed */
	sink->ctx.fd = -1;
	sink->ctx.dropped = 0;
	if (_new)
		LIST_APPEND(&sink_list, &sink->sink_list);
 end:
	return sink;

 err:
	ha_free(&sink->name);
	ha_free(&sink->desc);
	ha_free(&sink);

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
		LIST_DELETE(&sink->sink_list);
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

/* tries to send <nmsg> message parts from message array <msg> to sink <sink>.
 * Formatting according to the sink's preference is done here, unless sink->fmt
 * is unspecified, in which case the caller formatting will be used instead.
 * Lost messages are NOT accounted for. It is preferable to call sink_write()
 * instead which will also try to emit the number of dropped messages when there
 * are any.
 *
 * It will stop writing at <maxlen> instead of sink->maxlen if <maxlen> is
 * positive and inferior to sink->maxlen.
 *
 * It returns >0 if it could write anything, <=0 otherwise.
 */
 ssize_t __sink_write(struct sink *sink, struct log_header hdr,
                      size_t maxlen, const struct ist msg[], size_t nmsg)
 {
	struct ist *pfx = NULL;
	size_t npfx = 0;

	if (sink->fmt == LOG_FORMAT_RAW)
		goto send;

	if (sink->fmt != LOG_FORMAT_UNSPEC)
		hdr.format = sink->fmt; /* sink format prevails over log one */
	pfx = build_log_header(hdr, &npfx);

send:
	if (!maxlen)
		maxlen = ~0;
	if (sink->type == SINK_TYPE_FD) {
		return fd_write_frag_line(sink->ctx.fd, MIN(maxlen, sink->maxlen), pfx, npfx, msg, nmsg, 1);
	}
	else if (sink->type == SINK_TYPE_BUFFER) {
		return ring_write(sink->ctx.ring, MIN(maxlen, sink->maxlen), pfx, npfx, msg, nmsg);
	}
	return 0;
}

/* Tries to emit a message indicating the number of dropped events.
 * The log header of the original message that we tried to emit is reused
 * here with the only difference that we override the log level. This is
 * possible since the announce message will be sent from the same context.
 *
 * In case of success, the amount of drops is reduced by as much.
 * The function ensures that a single thread will do that work at once, other
 * ones will only report a failure if a thread is dumping, so that no thread
 * waits. A pair od atomic OR and AND is performed around the code so the
 * caller would be advised to only call this function AFTER having verified
 * that sink->ctx.dropped is not zero in order to avoid a memory write. On
 * success, >0 is returned, otherwise <=0 on failure, indicating that it could
 * not eliminate the pending drop counter. It may loop up to 10 times trying
 * to catch up with failing competing threads.
 */
int sink_announce_dropped(struct sink *sink, struct log_header hdr)
{
	static THREAD_LOCAL char msg_dropped1[] = "1 event dropped";
	static THREAD_LOCAL char msg_dropped2[] = "0000000000 events dropped";
	uint dropped, last_dropped;
	struct ist msgvec[1];
	uint retries = 10;
	int ret = 0;

	/* Explanation. ctx.dropped is made of:
	 *     bit0     = 1 if dropped dump in progress
	 *     bit1..31 = dropped counter
	 * If non-zero there have been some drops. If not &1, it means
	 * nobody's taking care of them and we'll have to, otherwise
	 * another thread is already on them and we can just pass and
	 * count another drop (hence add 2).
	 */
	dropped = HA_ATOMIC_FETCH_OR(&sink->ctx.dropped, 1);
	if (dropped & 1) {
		/* another thread was already on it */
		goto leave;
	}

	last_dropped = 0;
	dropped >>= 1;
	while (1) {
		while (unlikely(dropped > last_dropped) && retries-- > 0) {
			/* try to aggregate multiple messages if other threads arrive while
			 * we're producing the dropped message.
			 */
			uint msglen = sizeof(msg_dropped1);
			const char *msg = msg_dropped1;

			last_dropped = dropped;
			if (dropped > 1) {
				msg = ultoa_r(dropped, msg_dropped2, 11);
				msg_dropped2[10] = ' ';
				msglen = msg_dropped2 + sizeof(msg_dropped2) - msg;
			}
			msgvec[0] = ist2(msg, msglen);
			dropped = HA_ATOMIC_LOAD(&sink->ctx.dropped) >> 1;
		}

		if (!dropped)
			break;

		last_dropped = 0;
		hdr.level = LOG_NOTICE; /* override level but keep original log header data */

		if (__sink_write(sink, hdr, 0, msgvec, 1) <= 0)
			goto done;

		/* success! */
		HA_ATOMIC_SUB(&sink->ctx.dropped, dropped << 1);
	}

	/* done! */
	ret = 1;
done:
	/* unlock the counter */
	HA_ATOMIC_AND(&sink->ctx.dropped, ~1);
leave:
	return ret;
}

/* parse the "show events" command, returns 1 if a message is returned, otherwise zero */
static int cli_parse_show_events(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct sink *sink;
	uint ring_flags;
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

	ring_flags = 0;
	for (arg = 2; *args[arg]; arg++) {
		if (strcmp(args[arg], "-w") == 0)
			ring_flags |= RING_WF_WAIT_MODE;
		else if (strcmp(args[arg], "-n") == 0)
			ring_flags |= RING_WF_SEEK_NEW;
		else if (strcmp(args[arg], "-nw") == 0 || strcmp(args[arg], "-wn") == 0)
			ring_flags |= RING_WF_WAIT_MODE | RING_WF_SEEK_NEW;
		else
			return cli_err(appctx, "unknown option");
	}
	return ring_attach_cli(sink->ctx.ring, appctx, ring_flags);
}

/* Pre-configures a ring proxy to emit connections */
void sink_setup_proxy(struct proxy *px)
{
	px->be_counters.last_change = ns_to_sec(now_ns);
	px->cap = PR_CAP_BE;
	px->maxconn = 0;
	px->conn_retries = 1;
	px->timeout.server = TICK_ETERNITY;
	px->timeout.client = TICK_ETERNITY;
	px->timeout.connect = TICK_ETERNITY;
	px->accept = NULL;
	px->options2 |= PR_O2_INDEPSTR | PR_O2_SMARTCON | PR_O2_SMARTACC;
	px->next = sink_proxies_list;
	sink_proxies_list = px;
}

static void _sink_forward_io_handler(struct appctx *appctx,
                                     ssize_t (*msg_handler)(void *ctx, struct ist v1, struct ist v2, size_t ofs, size_t len))
{
	struct stconn *sc = appctx_sc(appctx);
	struct sink_forward_target *sft = appctx->svcctx;
	struct sink *sink = sft->sink;
	struct ring *ring = sink->ctx.ring;
	size_t ofs, last_ofs;
	size_t processed;
	int ret = 0;

	if (unlikely(se_fl_test(appctx->sedesc, (SE_FL_EOS|SE_FL_ERROR)))) {
		goto out;
	}

	/* if stopping was requested, close immediately */
	if (unlikely(stopping))
		goto soft_close;

	/* if the connection is not established, inform the stream that we want
	 * to be notified whenever the connection completes.
	 */
	if (sc_opposite(sc)->state < SC_ST_EST) {
		applet_need_more_data(appctx);
		se_need_remote_conn(appctx->sedesc);
		applet_have_more_data(appctx);
		goto out;
	}

	HA_SPIN_LOCK(SFT_LOCK, &sft->lock);
	BUG_ON(appctx != sft->appctx);

	MT_LIST_DELETE(&appctx->wait_entry);

	ret = ring_dispatch_messages(ring, appctx, &sft->ofs, &last_ofs, 0,
	                             msg_handler, &processed);
	sft->e_processed += processed;

	/* if server's max-reuse is set (>= 0), destroy the applet once the
	 * connection has been reused at least 'max-reuse' times, which means
	 * it has processed at least 'max-reuse + 1' events (applet will
	 * perform a new connection attempt)
	 */
	if (sft->srv->max_reuse >= 0) {
		uint max_reuse = sft->srv->max_reuse + 1;

		if (max_reuse < sft->srv->max_reuse)
			max_reuse = sft->srv->max_reuse; // overflow, cap to max value

		if (sft->e_processed / max_reuse !=
		    (sft->e_processed - processed) / max_reuse) {
			HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);
			goto soft_close;
		}
	}

	if (ret) {
		/* let's be woken up once new data arrive */
		MT_LIST_APPEND(&ring->waiters, &appctx->wait_entry);
		ofs = ring_tail(ring);
		if (ofs != last_ofs) {
			/* more data was added into the ring between the
			 * unlock and the lock, and the writer might not
			 * have seen us. We need to reschedule a read.
			 */
			applet_have_more_data(appctx);
		} else
			applet_have_no_more_data(appctx);
	}
	HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);

out:
	/* always drain data from server */
	co_skip(sc_oc(sc), sc_oc(sc)->output);
	return;

soft_close:
	/* be careful: since the socket lacks the NOLINGER flag (on purpose)
	 * soft_close will result in the port staying in TIME_WAIT state:
	 * don't abuse from soft_close!
	 */
	se_fl_set(appctx->sedesc, SE_FL_EOS|SE_FL_EOI);
	/* if required, hard_close could be achieve by using SE_FL_EOS|SE_FL_ERROR
	 * flag combination: RST will be sent, TIME_WAIT will be avoided as if
	 * we performed a normal close with NOLINGER flag set
	 */
}

/*
 * IO Handler to handle message push to syslog tcp server.
 * It takes its context from appctx->svcctx.
 */
static inline void sink_forward_io_handler(struct appctx *appctx)
{
	_sink_forward_io_handler(appctx, applet_append_line);
}

/*
 * IO Handler to handle message push to syslog tcp server
 * using octet counting frames
 * It takes its context from appctx->svcctx.
 */
static inline void sink_forward_oc_io_handler(struct appctx *appctx)
{
	_sink_forward_io_handler(appctx, syslog_applet_append_event);
}

void __sink_forward_session_deinit(struct sink_forward_target *sft)
{
	struct sink *sink;

	sink = sft->sink;
	if (!sink)
		return;

	MT_LIST_DELETE(&sft->appctx->wait_entry);

	sft->appctx = NULL;
	task_wakeup(sink->forward_task, TASK_WOKEN_MSG);
}

static int sink_forward_session_init(struct appctx *appctx)
{
	struct sink_forward_target *sft = appctx->svcctx;
	struct stream *s;
	struct sockaddr_storage *addr = NULL;

	/* sft init is performed asynchronously so <sft> must be manipulated
	 * under the lock
	 */
	HA_SPIN_LOCK(SFT_LOCK, &sft->lock);

	BUG_ON(sft->appctx != appctx);

	if (!sockaddr_alloc(&addr, &sft->srv->addr, sizeof(sft->srv->addr)))
		goto out_error;
	/* srv port should be learned from srv->svc_port not from srv->addr */
	set_host_port(addr, sft->srv->svc_port);

	if (appctx_finalize_startup(appctx, sft->srv->proxy, &BUF_NULL) == -1)
		goto out_free_addr;

	s = appctx_strm(appctx);
	s->scb->dst = addr;
	s->scb->flags |= (SC_FL_RCV_ONCE);

	s->target = &sft->srv->obj_type;
	s->flags = SF_ASSIGNED;

	s->do_log = NULL;
	s->uniq_id = 0;

	applet_expect_no_data(appctx);

	HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);

	return 0;

 out_free_addr:
	sockaddr_free(&addr);
 out_error:
	HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);
	return -1;
}

static void sink_forward_session_release(struct appctx *appctx)
{
	struct sink_forward_target *sft = appctx->svcctx;

	if (!sft)
		return;

	HA_SPIN_LOCK(SFT_LOCK, &sft->lock);
	BUG_ON(sft->appctx != appctx);
	__sink_forward_session_deinit(sft);
	HA_SPIN_UNLOCK(SFT_LOCK, &sft->lock);
}

static struct applet sink_forward_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<SINKFWD>", /* used for logging */
	.fct = sink_forward_io_handler,
	.init = sink_forward_session_init,
	.release = sink_forward_session_release,
};

static struct applet sink_forward_oc_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<SINKFWDOC>", /* used for logging */
	.fct = sink_forward_oc_io_handler,
	.init = sink_forward_session_init,
	.release = sink_forward_session_release,
};

/*
 * Create a new peer session in assigned state (connect will start automatically)
 * It sets its context into appctx->svcctx.
 */
static struct appctx *sink_forward_session_create(struct sink *sink, struct sink_forward_target *sft)
{
	struct appctx *appctx;
	struct applet *applet = &sink_forward_applet;
	uint best_tid, best_load;
	int attempts, first;

	if (sft->srv->log_proto == SRV_LOG_PROTO_OCTET_COUNTING)
		applet = &sink_forward_oc_applet;

	BUG_ON(!global.nbthread);
	attempts = MIN(global.nbthread, 3);
	first = 1;

	/* to shut gcc warning */
	best_tid = best_load = 0;

	/* to help spread the load over multiple threads, try to find a
	 * non-overloaded thread by picking a random thread and checking
	 * its load. If we fail to find a non-overloaded thread after 3
	 * attempts, let's pick the least overloaded one.
	 */
	while (attempts-- > 0) {
		uint cur_tid;
		uint cur_load;

		cur_tid = statistical_prng_range(global.nbthread);
		cur_load = HA_ATOMIC_LOAD(&ha_thread_ctx[cur_tid].rq_total);

		if (first || cur_load < best_load) {
			best_tid = cur_tid;
			best_load = cur_load;
		}
		first = 0;

		/* if we already found a non-overloaded thread, stop now */
		if (HA_ATOMIC_LOAD(&ha_thread_ctx[best_tid].rq_total) < 3)
			break;
	}

	appctx = appctx_new_on(applet, NULL, best_tid);
	if (!appctx)
		goto out_close;
	appctx->svcctx = (void *)sft;
	appctx_wakeup(appctx);
	return appctx;

	/* Error unrolling */
 out_close:
	return NULL;
}

/*
 * Task to handle connections to forward servers
 */
static struct task *process_sink_forward(struct task * task, void *context, unsigned int state)
{
	struct sink *sink = (struct sink *)context;
	struct sink_forward_target *sft = sink->sft;

	task->expire = TICK_ETERNITY;

	if (!stopping) {
		while (sft) {
			HA_SPIN_LOCK(SFT_LOCK, &sft->lock);
			/* If appctx is NULL, start a new session and perform the appctx
			 * assigment right away since the applet is not supposed to change
			 * during the session lifetime. By doing the assignment now we
			 * make sure to start the session exactly once.
			 */
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
 * Init task to manage connections to forward servers
 *
 * returns 0 in case of error.
 */
int sink_init_forward(struct sink *sink)
{
	sink->forward_task = task_new_anywhere();
	if (!sink->forward_task)
		return 0;

	sink->forward_task->process = process_sink_forward;
	sink->forward_task->context = (void *)sink;
	sink->forward_sighandler = signal_register_task(0, sink->forward_task, 0);
	task_wakeup(sink->forward_task, TASK_WOKEN_INIT);
	return 1;
}

/* This tries to rotate a file-backed ring, but only if it contains contents.
 * This way empty rings will not cause backups to be overwritten and it's safe
 * to reload multiple times. That's only best effort, failures are silently
 * ignored.
 */
void sink_rotate_file_backed_ring(const char *name)
{
	struct ring_storage storage;
	char *oldback;
	int ret;
	int fd;

	fd = open(name, O_RDONLY);
	if (fd < 0)
		return;

	/* check for contents validity */
	ret = read(fd, &storage, sizeof(storage));
	close(fd);

	if (ret != sizeof(storage))
		goto rotate;

	/* check that it's the expected format before touching it */
	if (storage.rsvd != sizeof(storage))
		return;

	/* contents are present, we want to keep them => rotate. Note that
	 * an empty ring buffer has one byte (the marker).
	 */
	if (storage.head != 0 || storage.tail != 1)
		goto rotate;

	/* nothing to keep, let's scratch the file and preserve the backup */
	return;

 rotate:
	oldback = NULL;
	memprintf(&oldback, "%s.bak", name);
	if (oldback) {
		/* try to rename any possibly existing ring file to
		 * ".bak" and delete remains of older ones. This will
		 * ensure we don't wipe useful debug info upon restart.
		 */
		unlink(oldback);
		if (rename(name, oldback) < 0)
			unlink(oldback);
		ha_free(&oldback);
	}
}


/* helper function to completely deallocate a sink struct
 */
static void sink_free(struct sink *sink)
{
	struct sink_forward_target *sft_next;

	if (!sink)
		return;
	if (sink->type == SINK_TYPE_BUFFER) {
		if (sink->store) {
			size_t size = (ring_allocated_size(sink->ctx.ring) + 4095UL) & -4096UL;
			void *area = ring_allocated_area(sink->ctx.ring);

			msync(area, size, MS_SYNC);
			munmap(area, size);
			ha_free(&sink->store);
		}
		ring_free(sink->ctx.ring);
	}
	LIST_DEL_INIT(&sink->sink_list); // remove from parent list
	task_destroy(sink->forward_task);
	free_proxy(sink->forward_px);
	ha_free(&sink->name);
	ha_free(&sink->desc);
	while (sink->sft) {
		sft_next = sink->sft->next;
		ha_free(&sink->sft);
		sink->sft = sft_next;
	}
	ha_free(&sink);
}

/* Helper function to create new high-level ring buffer (as in ring section from
 * the config): will create a new sink of buf type, and a new forward proxy,
 * which will be stored in forward_px to know that the sink is responsible for
 * it.
 *
 * Returns NULL on failure
 */
static struct sink *sink_new_ringbuf(const char *id, const char *description,
                                     const char *file, int linenum, char **err_msg)
{
	struct sink *sink;
	struct proxy *p = NULL; // forward_px

	/* allocate new proxy to handle forwards */
	p = calloc(1, sizeof(*p));
	if (!p) {
		memprintf(err_msg, "out of memory");
		goto err;
	}

	init_new_proxy(p);
	sink_setup_proxy(p);
	p->id = strdup(id);
	p->conf.args.file = p->conf.file = copy_file_name(file);
	p->conf.args.line = p->conf.line = linenum;

	sink = sink_new_buf(id, description, LOG_FORMAT_RAW, BUFSIZE);
	if (!sink) {
		memprintf(err_msg, "unable to create a new sink buffer for ring '%s'", id);
		goto err;
	}

	/* link sink to proxy */
	sink->forward_px = p;

	return sink;

 err:
	free_proxy(p);
	return NULL;
}

/* helper function: add a new server to an existing sink
 *
 * Returns 1 on success and 0 on failure
 */
static int sink_add_srv(struct sink *sink, struct server *srv)
{
	struct sink_forward_target *sft;

	/* allocate new sink_forward_target descriptor */
	sft = calloc(1, sizeof(*sft));
	if (!sft) {
		ha_alert("memory allocation error initializing server '%s' in ring '%s'.\n", srv->id, sink->name);
		return 0;
	}
	sft->srv = srv;
	sft->appctx = NULL;
	sft->ofs = ~0; /* init ring offset */
	sft->sink = sink;
	sft->next = sink->sft;
	HA_SPIN_INIT(&sft->lock);

	/* mark server attached to the ring */
	if (!ring_attach(sink->ctx.ring)) {
		ha_alert("server '%s' sets too many watchers > 255 on ring '%s'.\n", srv->id, sink->name);
		ha_free(&sft);
		return 0;
	}
	sink->sft = sft;
	return 1;
}

/* Finalize sink struct to ensure configuration consistency and
 * allocate final struct members
 *
 * Returns ERR_NONE on success, ERR_WARN on warning
 * Returns a composition of ERR_ALERT, ERR_ABORT, ERR_FATAL on failure
 */
static int sink_finalize(struct sink *sink)
{
	int err_code = ERR_NONE;
	struct server *srv;

	if (sink && (sink->type == SINK_TYPE_BUFFER)) {
		if (!sink->maxlen)
			sink->maxlen = ~0; // maxlen not set: no implicit truncation
		else if (sink->maxlen > ring_max_payload(sink->ctx.ring)) {
			/* maxlen set by user however it doesn't fit: set to max value */
			ha_warning("ring '%s' event max length '%u' exceeds max payload size, forced to '%lu'.\n",
			           sink->name, sink->maxlen, (unsigned long)ring_max_payload(sink->ctx.ring));
			sink->maxlen = ring_max_payload(sink->ctx.ring);
			err_code |= ERR_WARN;
		}

		/* prepare forward server descriptors */
		if (sink->forward_px) {
			/* sink proxy is set: register all servers from the proxy */
			srv = sink->forward_px->srv;
			while (srv) {
				if (!sink_add_srv(sink, srv)) {
					err_code |= ERR_ALERT | ERR_FATAL;
					break;
				}
				srv = srv->next;
			}
		}
		/* init forwarding if at least one sft is registered */
		if (sink->sft && sink_init_forward(sink) == 0) {
			ha_alert("error when trying to initialize sink buffer forwarding.\n");
			err_code |= ERR_ALERT | ERR_FATAL;
		}
		if (!sink->store) {
			/* virtual memory backed sink */
			vma_set_name(ring_allocated_area(sink->ctx.ring),
			             ring_allocated_size(sink->ctx.ring),
			             "ring", sink->name);
		}
	}
	return err_code;
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
	char *err_msg = NULL;
	const char *inv;

	if (strcmp(args[0], "ring") == 0) { /* new ring section */
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

		cfg_sink = sink_new_ringbuf(args[1], args[1], file, linenum, &err_msg);
		if (!cfg_sink) {
			ha_alert("parsing [%s:%d] : %s.\n", file, linenum, err_msg);
			ha_free(&err_msg);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		/* set maxlen value to 0 for now, we rely on this in postparsing
		 * to know if it was explicitly set using the "maxlen" parameter
		 */
		cfg_sink->maxlen = 0;
	}
	else if (strcmp(args[0], "size") == 0) {
		size_t size;

		if (!cfg_sink || (cfg_sink->type != SINK_TYPE_BUFFER)) {
			ha_alert("parsing [%s:%d] : 'size' directive not usable with this type of sink.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		if (parse_size_err(args[1], &size) != NULL || !size) {
			ha_alert("parsing [%s:%d] : invalid size '%s' for new sink buffer.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		if (size > RING_TAIL_LOCK) {
			ha_alert("parsing [%s:%d] : too large size '%llu' for new sink buffer, the limit on this platform is %llu bytes.\n", file, linenum, (ullong)size, (ullong)RING_TAIL_LOCK);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		if (cfg_sink->store) {
			ha_alert("parsing [%s:%d] : cannot resize an already mapped file, please specify 'size' before 'backing-file'.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		if (size < ring_data(cfg_sink->ctx.ring)) {
			ha_warning("parsing [%s:%d] : ignoring new size '%llu' that is smaller than contents '%llu' for ring '%s'.\n",
				   file, linenum, (ullong)size, (ullong)ring_data(cfg_sink->ctx.ring), cfg_sink->name);
			err_code |= ERR_WARN;
			goto err;
		}

		if (!ring_resize(cfg_sink->ctx.ring, size)) {
			ha_alert("parsing [%s:%d] : fail to set sink buffer size '%llu' for ring '%s'.\n", file, linenum,
				 (ullong)ring_size(cfg_sink->ctx.ring), cfg_sink->name);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}
	}
	else if (strcmp(args[0], "backing-file") == 0) {
		/* This tries to mmap file <file> for size <size> and to use it as a backing store
		 * for ring <ring>. Existing data are delete. NULL is returned on error.
		 */
		const char *backing = args[1];
		size_t size;
		void *area;
		int fd;

		if (!cfg_sink || (cfg_sink->type != SINK_TYPE_BUFFER)) {
			ha_alert("parsing [%s:%d] : 'backing-file' only usable with existing rings.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		if (cfg_sink->store) {
			ha_alert("parsing [%s:%d] : 'backing-file' already specified for ring '%s' (was '%s').\n", file, linenum, cfg_sink->name, cfg_sink->store);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		/* let's check if the file exists and is not empty. That's the
		 * only condition under which we'll trigger a rotate, so that
		 * config checks, reloads, or restarts that don't emit anything
		 * do not rotate it again.
		 */
		sink_rotate_file_backed_ring(backing);

		fd = open(backing, O_RDWR | O_CREAT, 0600);
		if (fd < 0) {
			ha_alert("parsing [%s:%d] : cannot open backing-file '%s' for ring '%s': %s.\n", file, linenum, backing, cfg_sink->name, strerror(errno));
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		size = (ring_size(cfg_sink->ctx.ring) + 4095UL) & -4096UL;
		if (ftruncate(fd, size) != 0) {
			close(fd);
			ha_alert("parsing [%s:%d] : could not adjust size of backing-file for ring '%s': %s.\n", file, linenum, cfg_sink->name, strerror(errno));
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		area = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (area == MAP_FAILED) {
			close(fd);
			ha_alert("parsing [%s:%d] : failed to use '%s' as a backing file for ring '%s': %s.\n", file, linenum, backing, cfg_sink->name, strerror(errno));
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		/* we don't need the file anymore */
		close(fd);
		cfg_sink->store = strdup(backing);

		/* never fails */
		ring_free(cfg_sink->ctx.ring);
		cfg_sink->ctx.ring = ring_make_from_area(area, size, 1);
	}
	else if (strcmp(args[0],"server") == 0) {
		if (!cfg_sink || (cfg_sink->type != SINK_TYPE_BUFFER)) {
			ha_alert("parsing [%s:%d] : unable to create server '%s'.\n", file, linenum, args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto err;
		}

		err_code |= parse_server(file, linenum, args, cfg_sink->forward_px, NULL,
		                         SRV_PARSE_PARSE_ADDR|SRV_PARSE_INITIAL_RESOLVE);
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
                        if (args[1][0] == 'c')
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

/* Creates a new sink buffer from a logger.
 *
 * It uses the logger's address to declare a forward
 * server for this buffer. And it initializes the
 * forwarding.
 *
 * The function returns a pointer on the
 * allocated struct sink if allocate
 * and initialize succeed, else if it fails
 * it returns NULL.
 *
 * Note: the sink is created using the name
 *       specified into logger->target.ring_name
 */
struct sink *sink_new_from_logger(struct logger *logger)
{
	struct sink *sink = NULL;
	struct server *srv = NULL;
	char *err_msg = NULL;

	/* prepare description for the sink */
	chunk_reset(&trash);
	chunk_printf(&trash, "created from log directive declared into '%s' at line %d", logger->conf.file, logger->conf.line);

	/* allocate a new sink buffer */
	sink = sink_new_ringbuf(logger->target.ring_name, trash.area, logger->conf.file, logger->conf.line, &err_msg);
	if (!sink) {
		ha_alert("%s.\n", err_msg);
		ha_free(&err_msg);
		goto error;
	}

	/* ring format normally defaults to RAW, but here we set ring format
	 * to UNSPEC to inherit from caller format in sink_write() since we
	 * cannot customize implicit ring settings
	 */
	sink->fmt = LOG_FORMAT_UNSPEC;

	/* for the same reason, we disable sink->maxlen to inherit from caller
	 * maxlen in sink_write()
	 */
	sink->maxlen = 0;

	/* Set default connect and server timeout for sink forward proxy */
	sink->forward_px->timeout.connect = MS_TO_TICKS(1000);
	sink->forward_px->timeout.server = MS_TO_TICKS(5000);

	/* allocate a new server to forward messages
	 * from ring buffer
	 */
	srv = new_server(sink->forward_px);
	if (!srv)
		goto error;

	/* init server */
	srv->id = strdup(logger->target.ring_name);
	srv->conf.file = strdup(logger->conf.file);
	srv->conf.line = logger->conf.line;
	srv->addr = *logger->target.addr;
	srv->svc_port = get_host_port(logger->target.addr);
	HA_SPIN_INIT(&srv->lock);

	/* process per thread init */
	if (srv_init_per_thr(srv) == -1)
		goto error;

	/* link srv with sink forward proxy: the servers are linked
	 * backwards first into proxy
	 */
	srv->next = sink->forward_px->srv;
	sink->forward_px->srv = srv;

	if (sink_finalize(sink) & ERR_CODE)
		goto error_final;

	return sink;
 error:
	srv_drop(srv);

 error_final:
	sink_free(sink);

	return NULL;
}

/* This function is pretty similar to sink_from_logger():
 * But instead of creating a forward proxy and server from a logger struct
 * it uses already existing srv to create the forwarding sink, so most of
 * the initialization is bypassed.
 *
 * The function returns a pointer on the
 * allocated struct sink if allocate
 * and initialize succeed, else if it fails
 * it returns NULL.
 *
 * <from> allows to specify a string that will be inserted into the sink
 * description to describe where it was created from.

 * Note: the sink is created using the name
 *       specified into srv->id
 */
struct sink *sink_new_from_srv(struct server *srv, const char *from)
{
	struct sink *sink = NULL;
	int bufsize = (srv->log_bufsize) ? srv->log_bufsize : BUFSIZE;
	char *sink_name = NULL;

	/* prepare description for the sink */
	chunk_reset(&trash);
	chunk_printf(&trash, "created from %s declared into '%s' at line %d", from, srv->conf.file, srv->conf.line);

	memprintf(&sink_name, "%s/%s", srv->proxy->id, srv->id);
	if (!sink_name) {
		ha_alert("memory error while creating ring buffer for server '%s/%s'.\n", srv->proxy->id, srv->id);
		goto error;
	}

	/* directly create a sink of BUF type, and use UNSPEC log format to
	 * inherit from caller fmt in sink_write()
	 *
	 * sink_name must be unique to prevent existing sink from being re-used
	 */
	sink = sink_new_buf(sink_name, trash.area, LOG_FORMAT_UNSPEC, bufsize);
	ha_free(&sink_name); // no longer needed

	if (!sink) {
		ha_alert("unable to create a new sink buffer for server '%s/%s'.\n", srv->proxy->id, srv->id);
		goto error;
	}

	/* we disable sink->maxlen to inherit from caller
	 * maxlen in sink_write()
	 */
	sink->maxlen = 0;

	/* add server to sink */
	if (!sink_add_srv(sink, srv))
		goto error;

	if (sink_finalize(sink) & ERR_CODE)
		goto error;

	return sink;

 error:
	sink_free(sink);

	return NULL;
}

/*
 * Post parsing "ring" section.
 *
 * The function returns 0 in success case, otherwise, it returns error
 * flags.
 */
int cfg_post_parse_ring()
{
	int err_code;

	err_code = sink_finalize(cfg_sink);
	cfg_sink = NULL;

	return err_code;
}

/* function: resolve a single logger target of BUFFER type
 *
 * Returns err_code which defaults to ERR_NONE and can be set to a combination
 * of ERR_WARN, ERR_ALERT, ERR_FATAL and ERR_ABORT in case of errors.
 * <msg> could be set at any time (it will usually be set on error, but
 * could also be set when no error occurred to report a diag warning), thus is
 * up to the caller to check it and to free it.
 */
int sink_resolve_logger_buffer(struct logger *logger, char **msg)
{
	struct log_target *target = &logger->target;
	int err_code = ERR_NONE;
	struct sink *sink;

	BUG_ON(target->type != LOG_TARGET_BUFFER || (target->flags & LOG_TARGET_FL_RESOLVED));
	if (target->addr) {
		sink = sink_new_from_logger(logger);
		if (!sink) {
			memprintf(msg, "cannot be initialized (failed to create implicit ring)");
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		ha_free(&target->addr); /* we no longer need this */
	}
	else {
		sink = sink_find(target->ring_name);
		if (!sink) {
			memprintf(msg, "uses unknown ring named '%s'", target->ring_name);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		else if (sink->type != SINK_TYPE_BUFFER) {
			memprintf(msg, "uses incompatible ring '%s'", target->ring_name);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
	}
	/* consistency checks */
	if (sink && logger->maxlen > ring_max_payload(sink->ctx.ring)) {
		memprintf(msg, "uses a max length which exceeds ring capacity ('%s' supports %lu bytes at most)",
		          target->ring_name, (unsigned long)ring_max_payload(sink->ctx.ring));
	}
	else if (sink && logger->maxlen > sink->maxlen) {
		memprintf(msg, "uses a ring with a smaller maxlen than the one specified on the log directive ('%s' has maxlen = %d), logs will be truncated according to the lowest maxlen between the two",
		          target->ring_name, sink->maxlen);
	}
 end:
	ha_free(&target->ring_name); /* sink is resolved and will replace ring_name hint */
	target->sink = sink;
	return err_code;
}

static void sink_init()
{
	sink_new_fd("stdout", "standard output (fd#1)", LOG_FORMAT_RAW, 1);
	sink_new_fd("stderr", "standard output (fd#2)", LOG_FORMAT_RAW, 2);
	sink_new_buf("buf0",  "in-memory ring buffer", LOG_FORMAT_TIMED, 1048576);
}

static int sink_postcheck()
{
	struct sink *sink;

	list_for_each_entry(sink, &sink_list, sink_list) {
		if (sink->type == SINK_TYPE_FORWARD_DECLARED) {
			/* sink wasn't upgraded to actual sink despite being
			 * forward-declared: it is an error (the sink doesn't
			 * really exist)
			 */
			ha_alert("%s: sink '%s' doesn't exist.\n", sink->desc, sink->name);
			return ERR_ALERT | ERR_FATAL;
		}
	}
	return ERR_NONE;
}

static void sink_deinit()
{
	struct sink *sink, *sb;

	list_for_each_entry_safe(sink, sb, &sink_list, sink_list)
		sink_free(sink);
}

INITCALL0(STG_REGISTER, sink_init);
REGISTER_POST_CHECK(sink_postcheck);
REGISTER_POST_DEINIT(sink_deinit);

static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "events", NULL }, "show events [<sink>] [-w] [-n]          : show event sink state", cli_parse_show_events, NULL, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/* config parsers for this section */
REGISTER_CONFIG_SECTION("ring", cfg_parse_ring, cfg_post_parse_ring);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
