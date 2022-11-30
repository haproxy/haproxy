/*
 * Process debugging functions.
 *
 * Copyright 2000-2019 Willy Tarreau <willy@haproxy.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */


#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/buf.h>
#include <haproxy/cli.h>
#include <haproxy/clock.h>
#include <haproxy/debug.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/hlua.h>
#include <haproxy/http_ana.h>
#include <haproxy/log.h>
#include <haproxy/net_helper.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stconn.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <import/ist.h>


/* The dump state is made of:
 *   - num_thread on the lowest 15 bits
 *   - a SYNC flag on bit 15 (waiting for sync start)
 *   - number of participating threads on bits 16-30
 * Initiating a dump consists in setting it to SYNC and incrementing the
 * num_thread part when entering the function. The first thread periodically
 * recounts active threads and compares it to the ready ones, and clears SYNC
 * and sets the number of participants to the value found, which serves as a
 * start signal. A thread finished dumping looks up the TID of the next active
 * thread after it and writes it in the lowest part. If there's none, it sets
 * the thread counter to the number of participants and resets that part,
 * which serves as an end-of-dump signal. All threads decrement the num_thread
 * part. Then all threads wait for the value to reach zero. Only used when
 * USE_THREAD_DUMP is set.
 */
#define THREAD_DUMP_TMASK     0x00007FFFU
#define THREAD_DUMP_FSYNC     0x00008000U
#define THREAD_DUMP_PMASK     0x7FFF0000U

volatile unsigned int thread_dump_state = 0;
unsigned int panic_started = 0;
unsigned int debug_commands_issued = 0;

/* dumps a backtrace of the current thread that is appended to buffer <buf>.
 * Lines are prefixed with the string <prefix> which may be empty (used for
 * indenting). It is recommended to use this at a function's tail so that
 * the function does not appear in the call stack. The <dump> argument
 * indicates what dump state to start from, and should usually be zero. It
 * may be among the following values:
 *   - 0: search usual callers before step 1, or directly jump to 2
 *   - 1: skip usual callers before step 2
 *   - 2: dump until polling loop, scheduler, or main() (excluded)
 *   - 3: end
 *   - 4-7: like 0 but stops *after* main.
 */
void ha_dump_backtrace(struct buffer *buf, const char *prefix, int dump)
{
	struct buffer bak;
	char pfx2[100];
	void *callers[100];
	int j, nptrs;
	const void *addr;

	nptrs = my_backtrace(callers, sizeof(callers)/sizeof(*callers));
	if (!nptrs)
		return;

	if (snprintf(pfx2, sizeof(pfx2), "%s| ", prefix) > sizeof(pfx2))
		pfx2[0] = 0;

	/* The call backtrace_symbols_fd(callers, nptrs, STDOUT_FILENO would
	 * produce similar output to the following:
	 */
	chunk_appendf(buf, "%scall trace(%d):\n", prefix, nptrs);
	for (j = 0; (j < nptrs || (dump & 3) < 2); j++) {
		if (j == nptrs && !(dump & 3)) {
			/* we failed to spot the starting point of the
			 * dump, let's start over dumping everything we
			 * have.
			 */
			dump += 2;
			j = 0;
		}
		bak = *buf;
		dump_addr_and_bytes(buf, pfx2, callers[j], 8);
		addr = resolve_sym_name(buf, ": ", callers[j]);
		if ((dump & 3) == 0) {
			/* dump not started, will start *after*
			 * ha_thread_dump_all_to_trash, ha_panic and ha_backtrace_to_stderr
			 */
			if (addr == ha_thread_dump_all_to_trash || addr == ha_panic ||
			    addr == ha_backtrace_to_stderr)
				dump++;
			*buf = bak;
			continue;
		}

		if ((dump & 3) == 1) {
			/* starting */
			if (addr == ha_thread_dump_all_to_trash || addr == ha_panic ||
			    addr == ha_backtrace_to_stderr) {
				*buf = bak;
				continue;
			}
			dump++;
		}

		if ((dump & 3) == 2) {
			/* still dumping */
			if (dump == 6) {
				/* we only stop *after* main and we must send the LF */
				if (addr == main) {
					j = nptrs;
					dump++;
				}
			}
			else if (addr == run_poll_loop || addr == main || addr == run_tasks_from_lists) {
				dump++;
				*buf = bak;
				break;
			}
		}
		/* OK, line dumped */
		chunk_appendf(buf, "\n");
	}
}

/* dump a backtrace of current thread's stack to stderr. */
void ha_backtrace_to_stderr(void)
{
	char area[2048];
	struct buffer b = b_make(area, sizeof(area), 0, 0);

	ha_dump_backtrace(&b, "  ", 4);
	if (b.data)
		DISGUISE(write(2, b.area, b.data));
}

/* Dumps to the buffer some known information for the desired thread, and
 * optionally extra info for the current thread. The dump will be appended to
 * the buffer, so the caller is responsible for preliminary initializing it.
 * The calling thread ID needs to be passed in <calling_tid> to display a star
 * in front of the calling thread's line (usually it's tid). Any stuck thread
 * is also prefixed with a '>'.
 * It must be called under thread isolation.
 */
void ha_thread_dump(struct buffer *buf, int thr, int calling_tid)
{
	unsigned long thr_bit = ha_thread_info[thr].ltid_bit;
	unsigned long long p = ha_thread_ctx[thr].prev_cpu_time;
	unsigned long long n = now_cpu_time_thread(thr);
	int stuck = !!(ha_thread_ctx[thr].flags & TH_FL_STUCK);
	int tgrp  = ha_thread_info[thr].tgid;

	chunk_appendf(buf,
	              "%c%cThread %-2u: id=0x%llx act=%d glob=%d wq=%d rq=%d tl=%d tlsz=%d rqsz=%d\n"
	              "     %2u/%-2u   stuck=%d prof=%d",
	              (thr == calling_tid) ? '*' : ' ', stuck ? '>' : ' ', thr + 1,
		      ha_get_pthread_id(thr),
		      thread_has_tasks(),
	              !eb_is_empty(&ha_thread_ctx[thr].rqueue_shared),
	              !eb_is_empty(&ha_thread_ctx[thr].timers),
	              !eb_is_empty(&ha_thread_ctx[thr].rqueue),
	              !(LIST_ISEMPTY(&ha_thread_ctx[thr].tasklets[TL_URGENT]) &&
			LIST_ISEMPTY(&ha_thread_ctx[thr].tasklets[TL_NORMAL]) &&
			LIST_ISEMPTY(&ha_thread_ctx[thr].tasklets[TL_BULK]) &&
			MT_LIST_ISEMPTY(&ha_thread_ctx[thr].shared_tasklet_list)),
	              ha_thread_ctx[thr].tasks_in_list,
	              ha_thread_ctx[thr].rq_total,
		      ha_thread_info[thr].tgid, ha_thread_info[thr].ltid + 1,
	              stuck,
	              !!(th_ctx->flags & TH_FL_TASK_PROFILING));

	chunk_appendf(buf,
	              " harmless=%d wantrdv=%d",
	              !!(_HA_ATOMIC_LOAD(&ha_tgroup_ctx[tgrp-1].threads_harmless) & thr_bit),
	              !!(th_ctx->flags & TH_FL_TASK_PROFILING));

	chunk_appendf(buf, "\n");
	chunk_appendf(buf, "             cpu_ns: poll=%llu now=%llu diff=%llu\n", p, n, n-p);

	/* this is the end of what we can dump from outside the current thread */

	if (thr != tid)
		return;

	chunk_appendf(buf, "             curr_task=");
	ha_task_dump(buf, th_ctx->current, "             ");

	if (stuck) {
		/* We only emit the backtrace for stuck threads in order not to
		 * waste precious output buffer space with non-interesting data.
		 * Please leave this as the last instruction in this function
		 * so that the compiler uses tail merging and the current
		 * function does not appear in the stack.
		 */
		ha_dump_backtrace(buf, "             ", 0);
	}
}


/* dumps into the buffer some information related to task <task> (which may
 * either be a task or a tasklet, and prepend each line except the first one
 * with <pfx>. The buffer is only appended and the first output starts by the
 * pointer itself. The caller is responsible for making sure the task is not
 * going to vanish during the dump.
 */
void ha_task_dump(struct buffer *buf, const struct task *task, const char *pfx)
{
	const struct stream *s = NULL;
	const struct appctx __maybe_unused *appctx = NULL;
	struct hlua __maybe_unused *hlua = NULL;
	const struct stconn *sc;

	if (!task) {
		chunk_appendf(buf, "0\n");
		return;
	}

	if (TASK_IS_TASKLET(task))
		chunk_appendf(buf,
		              "%p (tasklet) calls=%u\n",
		              task,
		              task->calls);
	else
		chunk_appendf(buf,
		              "%p (task) calls=%u last=%llu%s\n",
		              task,
		              task->calls,
		              task->wake_date ? (unsigned long long)(now_mono_time() - task->wake_date) : 0,
		              task->wake_date ? " ns ago" : "");

	chunk_appendf(buf, "%s  fct=%p(", pfx, task->process);
	resolve_sym_name(buf, NULL, task->process);
	chunk_appendf(buf,") ctx=%p", task->context);

	if (task->process == task_run_applet && (appctx = task->context))
		chunk_appendf(buf, "(%s)\n", appctx->applet->name);
	else
		chunk_appendf(buf, "\n");

	if (task->process == process_stream && task->context)
		s = (struct stream *)task->context;
	else if (task->process == task_run_applet && task->context && (sc = appctx_sc((struct appctx *)task->context)))
		s = sc_strm(sc);
	else if (task->process == sc_conn_io_cb && task->context)
		s = sc_strm(((struct stconn *)task->context));

	if (s)
		stream_dump(buf, s, pfx, '\n');

#ifdef USE_LUA
	hlua = NULL;
	if (s && (hlua = s->hlua)) {
		chunk_appendf(buf, "%sCurrent executing Lua from a stream analyser -- ", pfx);
	}
	else if (task->process == hlua_process_task && (hlua = task->context)) {
		chunk_appendf(buf, "%sCurrent executing a Lua task -- ", pfx);
	}
	else if (task->process == task_run_applet && (appctx = task->context) &&
		 (appctx->applet->fct == hlua_applet_tcp_fct)) {
		chunk_appendf(buf, "%sCurrent executing a Lua TCP service -- ", pfx);
	}
	else if (task->process == task_run_applet && (appctx = task->context) &&
		 (appctx->applet->fct == hlua_applet_http_fct)) {
		chunk_appendf(buf, "%sCurrent executing a Lua HTTP service -- ", pfx);
	}

	if (hlua && hlua->T) {
		chunk_appendf(buf, "stack traceback:\n    ");
		append_prefixed_str(buf, hlua_traceback(hlua->T, "\n    "), pfx, '\n', 0);
		b_putchr(buf, '\n');
	}
	else
		b_putchr(buf, '\n');
#endif
}

/* This function dumps all profiling settings. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero.
 */
static int cli_io_handler_show_threads(struct appctx *appctx)
{
	struct stconn *sc = appctx_sc(appctx);
	int thr;

	if (unlikely(sc_ic(sc)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	if (appctx->st0)
		thr = appctx->st1;
	else
		thr = 0;

	chunk_reset(&trash);
	ha_thread_dump_all_to_trash();

	if (applet_putchk(appctx, &trash) == -1) {
		/* failed, try again */
		appctx->st1 = thr;
		return 0;
	}
	return 1;
}

#if defined(HA_HAVE_DUMP_LIBS)
/* parse a "show libs" command. It returns 1 if it emits anything otherwise zero. */
static int debug_parse_cli_show_libs(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	chunk_reset(&trash);
	if (dump_libs(&trash, 1))
		return cli_msg(appctx, LOG_INFO, trash.area);
	else
		return 0;
}
#endif

/* dumps a state of all threads into the trash and on fd #2, then aborts. */
void ha_panic()
{
	if (HA_ATOMIC_FETCH_ADD(&panic_started, 1) != 0) {
		/* a panic dump is already in progress, let's not disturb it,
		 * we'll be called via signal DEBUGSIG. By returning we may be
		 * able to leave a current signal handler (e.g. WDT) so that
		 * this will ensure more reliable signal delivery.
		 */
		return;
	}
	chunk_reset(&trash);
	chunk_appendf(&trash, "Thread %u is about to kill the process.\n", tid + 1);
	ha_thread_dump_all_to_trash();
	DISGUISE(write(2, trash.area, trash.data));
	for (;;)
		abort();
}

/* Complain with message <msg> on stderr. If <counter> is not NULL, it is
 * atomically incremented, and the message is only printed when the counter
 * was zero, so that the message is only printed once. <taint> is only checked
 * on bit 1, and will taint the process either for a bug (2) or warn (0).
 */
void complain(int *counter, const char *msg, int taint)
{
	if (counter && _HA_ATOMIC_FETCH_ADD(counter, 1))
		return;
	DISGUISE(write(2, msg, strlen(msg)));
	if (taint & 2)
		mark_tainted(TAINTED_BUG);
	else
		mark_tainted(TAINTED_WARN);
}

/* parse a "debug dev exit" command. It always returns 1, though it should never return. */
static int debug_parse_cli_exit(char **args, char *payload, struct appctx *appctx, void *private)
{
	int code = atoi(args[3]);

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	exit(code);
	return 1;
}

/* parse a "debug dev bug" command. It always returns 1, though it should never return.
 * Note: we make sure not to make the function static so that it appears in the trace.
 */
int debug_parse_cli_bug(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	BUG_ON(one > zero);
	return 1;
}

/* parse a "debug dev warn" command. It always returns 1.
 * Note: we make sure not to make the function static so that it appears in the trace.
 */
int debug_parse_cli_warn(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	WARN_ON(one > zero);
	return 1;
}

/* parse a "debug dev check" command. It always returns 1.
 * Note: we make sure not to make the function static so that it appears in the trace.
 */
int debug_parse_cli_check(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	CHECK_IF(one > zero);
	return 1;
}

/* parse a "debug dev close" command. It always returns 1. */
static int debug_parse_cli_close(char **args, char *payload, struct appctx *appctx, void *private)
{
	int fd;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "Missing file descriptor number.\n");

	fd = atoi(args[3]);
	if (fd < 0 || fd >= global.maxsock)
		return cli_err(appctx, "File descriptor out of range.\n");

	if (!fdtab[fd].owner)
		return cli_msg(appctx, LOG_INFO, "File descriptor was already closed.\n");

	_HA_ATOMIC_INC(&debug_commands_issued);
	fd_delete(fd);
	return 1;
}

/* this is meant to cause a deadlock when more than one task is running it or when run twice */
static struct task *debug_run_cli_deadlock(struct task *task, void *ctx, unsigned int state)
{
	static HA_SPINLOCK_T lock __maybe_unused;

	HA_SPIN_LOCK(OTHER_LOCK, &lock);
	return NULL;
}

/* parse a "debug dev deadlock" command. It always returns 1. */
static int debug_parse_cli_deadlock(char **args, char *payload, struct appctx *appctx, void *private)
{
	int tasks;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	for (tasks = atoi(args[3]); tasks > 0; tasks--) {
		struct task *t = task_new_on(tasks % global.nbthread);
		if (!t)
			continue;
		t->process = debug_run_cli_deadlock;
		t->context = NULL;
		task_wakeup(t, TASK_WOKEN_INIT);
	}

	return 1;
}

/* parse a "debug dev delay" command. It always returns 1. */
static int debug_parse_cli_delay(char **args, char *payload, struct appctx *appctx, void *private)
{
	int delay = atoi(args[3]);

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	usleep((long)delay * 1000);
	return 1;
}

/* parse a "debug dev log" command. It always returns 1. */
static int debug_parse_cli_log(char **args, char *payload, struct appctx *appctx, void *private)
{
	int arg;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	chunk_reset(&trash);
	for (arg = 3; *args[arg]; arg++) {
		if (arg > 3)
			chunk_strcat(&trash, " ");
		chunk_strcat(&trash, args[arg]);
	}

	send_log(NULL, LOG_INFO, "%s\n", trash.area);
	return 1;
}

/* parse a "debug dev loop" command. It always returns 1. */
static int debug_parse_cli_loop(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct timeval deadline, curr;
	int loop = atoi(args[3]);

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	gettimeofday(&curr, NULL);
	tv_ms_add(&deadline, &curr, loop);

	while (tv_ms_cmp(&curr, &deadline) < 0)
		gettimeofday(&curr, NULL);

	return 1;
}

/* parse a "debug dev panic" command. It always returns 1, though it should never return. */
static int debug_parse_cli_panic(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	ha_panic();
	return 1;
}

/* parse a "debug dev exec" command. It always returns 1. */
#if defined(DEBUG_DEV)
static int debug_parse_cli_exec(char **args, char *payload, struct appctx *appctx, void *private)
{
	int pipefd[2];
	int arg;
	int pid;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);
	chunk_reset(&trash);
	for (arg = 3; *args[arg]; arg++) {
		if (arg > 3)
			chunk_strcat(&trash, " ");
		chunk_strcat(&trash, args[arg]);
	}

	thread_isolate();
	if (pipe(pipefd) < 0)
		goto fail_pipe;

	if (fd_set_cloexec(pipefd[0]) == -1)
		goto fail_fcntl;

	if (fd_set_cloexec(pipefd[1]) == -1)
		goto fail_fcntl;

	pid = fork();

	if (pid < 0)
		goto fail_fork;
	else if (pid == 0) {
		/* child */
		char *cmd[4] = { "/bin/sh", "-c", 0, 0 };

		close(0);
		dup2(pipefd[1], 1);
		dup2(pipefd[1], 2);

		cmd[2] = trash.area;
		execvp(cmd[0], cmd);
		printf("execvp() failed\n");
		exit(1);
	}

	/* parent */
	thread_release();
	close(pipefd[1]);
	chunk_reset(&trash);
	while (1) {
		size_t ret = read(pipefd[0], trash.area + trash.data, trash.size - 20 - trash.data);
		if (ret <= 0)
			break;
		trash.data += ret;
		if (trash.data + 20 == trash.size) {
			chunk_strcat(&trash, "\n[[[TRUNCATED]]]\n");
			break;
		}
	}
	close(pipefd[0]);
	waitpid(pid, NULL, WNOHANG);
	trash.area[trash.data] = 0;
	return cli_msg(appctx, LOG_INFO, trash.area);

 fail_fork:
 fail_fcntl:
	close(pipefd[0]);
	close(pipefd[1]);
 fail_pipe:
	thread_release();
	return cli_err(appctx, "Failed to execute command.\n");
}
#endif

/* parse a "debug dev hex" command. It always returns 1. */
static int debug_parse_cli_hex(char **args, char *payload, struct appctx *appctx, void *private)
{
	unsigned long start, len;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "Missing memory address to dump from.\n");

	start = strtoul(args[3], NULL, 0);
	if (!start)
		return cli_err(appctx, "Will not dump from NULL address.\n");

	_HA_ATOMIC_INC(&debug_commands_issued);

	/* by default, dump ~128 till next block of 16 */
	len = strtoul(args[4], NULL, 0);
	if (!len)
		len = ((start + 128) & -16) - start;

	chunk_reset(&trash);
	dump_hex(&trash, "  ", (const void *)start, len, 1);
	trash.area[trash.data] = 0;
	return cli_msg(appctx, LOG_INFO, trash.area);
}

/* parse a "debug dev sym <addr>" command. It always returns 1. */
static int debug_parse_cli_sym(char **args, char *payload, struct appctx *appctx, void *private)
{
	unsigned long addr;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "Missing memory address to be resolved.\n");

	_HA_ATOMIC_INC(&debug_commands_issued);

	addr = strtoul(args[3], NULL, 0);
	chunk_printf(&trash, "%#lx resolves to ", addr);
	resolve_sym_name(&trash, NULL, (const void *)addr);
	chunk_appendf(&trash, "\n");

	return cli_msg(appctx, LOG_INFO, trash.area);
}

/* parse a "debug dev tkill" command. It always returns 1. */
static int debug_parse_cli_tkill(char **args, char *payload, struct appctx *appctx, void *private)
{
	int thr = 0;
	int sig = SIGABRT;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (*args[3])
		thr = atoi(args[3]);

	if (thr < 0 || thr > global.nbthread)
		return cli_err(appctx, "Thread number out of range (use 0 for current).\n");

	if (*args[4])
		sig = atoi(args[4]);

	_HA_ATOMIC_INC(&debug_commands_issued);
	if (thr)
		ha_tkill(thr - 1, sig);
	else
		raise(sig);
	return 1;
}

/* hashes 'word' in "debug dev hash 'word' ". */
static int debug_parse_cli_hash(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *msg = NULL;

	cli_dynmsg(appctx, LOG_INFO, memprintf(&msg, "%s\n", HA_ANON_CLI(args[3])));
	return 1;
}

/* parse a "debug dev write" command. It always returns 1. */
static int debug_parse_cli_write(char **args, char *payload, struct appctx *appctx, void *private)
{
	unsigned long len;

	if (!*args[3])
		return cli_err(appctx, "Missing output size.\n");

	len = strtoul(args[3], NULL, 0);
	if (len >= trash.size)
		return cli_err(appctx, "Output too large, must be <tune.bufsize.\n");

	_HA_ATOMIC_INC(&debug_commands_issued);

	chunk_reset(&trash);
	trash.data = len;
	memset(trash.area, '.', trash.data);
	trash.area[trash.data] = 0;
	for (len = 64; len < trash.data; len += 64)
		trash.area[len] = '\n';
	return cli_msg(appctx, LOG_INFO, trash.area);
}

/* parse a "debug dev stream" command */
/*
 *  debug dev stream [strm=<ptr>] [strm.f[{+-=}<flags>]] [txn.f[{+-=}<flags>]] \
 *                   [req.f[{+-=}<flags>]] [res.f[{+-=}<flags>]]               \
 *                   [sif.f[{+-=<flags>]] [sib.f[{+-=<flags>]]                 \
 *                   [sif.s[=<state>]] [sib.s[=<state>]]
 */
static int debug_parse_cli_stream(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct stream *s = appctx_strm(appctx);
	int arg;
	void *ptr;
	int size;
	const char *word, *end;
	struct ist name;
	char *msg = NULL;
	char *endarg;
	unsigned long long old, new;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	ptr = NULL; size = 0;

	if (!*args[3]) {
		return cli_err(appctx,
			       "Usage: debug dev stream { <obj> <op> <value> | wake }*\n"
			       "     <obj>   = {strm | strm.f | strm.x | scf.s | scb.s |\n"
			       "                txn.f | req.f | req.r | req.w | res.f | res.r | res.w}\n"
			       "     <op>    = {'' (show) | '=' (assign) | '^' (xor) | '+' (or) | '-' (andnot)}\n"
			       "     <value> = 'now' | 64-bit dec/hex integer (0x prefix supported)\n"
			       "     'wake' wakes the stream asssigned to 'strm' (default: current)\n"
			       );
	}

	_HA_ATOMIC_INC(&debug_commands_issued);
	for (arg = 3; *args[arg]; arg++) {
		old = 0;
		end = word = args[arg];
		while (*end && *end != '=' && *end != '^' && *end != '+' && *end != '-')
			end++;
		name = ist2(word, end - word);
		if (isteq(name, ist("strm"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s; size = sizeof(s);
		} else if (isteq(name, ist("strm.f"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->flags; size = sizeof(s->flags);
		} else if (isteq(name, ist("strm.x"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->conn_exp; size = sizeof(s->conn_exp);
		} else if (isteq(name, ist("txn.f"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->txn->flags; size = sizeof(s->txn->flags);
		} else if (isteq(name, ist("req.f"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->req.flags; size = sizeof(s->req.flags);
		} else if (isteq(name, ist("res.f"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->res.flags; size = sizeof(s->res.flags);
		} else if (isteq(name, ist("req.r"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->req.rex; size = sizeof(s->req.rex);
		} else if (isteq(name, ist("res.r"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->res.rex; size = sizeof(s->res.rex);
		} else if (isteq(name, ist("req.w"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->req.wex; size = sizeof(s->req.wex);
		} else if (isteq(name, ist("res.w"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->res.wex; size = sizeof(s->res.wex);
		} else if (isteq(name, ist("scf.s"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->scf->state; size = sizeof(s->scf->state);
		} else if (isteq(name, ist("scb.s"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->scf->state; size = sizeof(s->scb->state);
		} else if (isteq(name, ist("wake"))) {
			if (s && may_access(s) && may_access((void *)s + sizeof(*s) - 1))
				task_wakeup(s->task, TASK_WOKEN_TIMER|TASK_WOKEN_IO|TASK_WOKEN_MSG);
			continue;
		} else
			return cli_dynerr(appctx, memprintf(&msg, "Unsupported field name: '%s'.\n", word));

		/* read previous value */
		if ((s || ptr == &s) && ptr && may_access(ptr) && may_access(ptr + size - 1)) {
			if (size == 8)
				old = read_u64(ptr);
			else if (size == 4)
				old = read_u32(ptr);
			else if (size == 2)
				old = read_u16(ptr);
			else
				old = *(const uint8_t *)ptr;
		} else {
			memprintf(&msg,
				  "%sSkipping inaccessible pointer %p for field '%.*s'.\n",
				  msg ? msg : "", ptr, (int)(end - word), word);
			continue;
		}

		/* parse the new value . */
		new = strtoll(end + 1, &endarg, 0);
		if (end[1] && *endarg) {
			if (strcmp(end + 1, "now") == 0)
				new = now_ms;
			else {
				memprintf(&msg,
					  "%sIgnoring unparsable value '%s' for field '%.*s'.\n",
					  msg ? msg : "", end + 1, (int)(end - word), word);
				continue;
			}
		}

		switch (*end) {
		case '\0': /* show */
			memprintf(&msg, "%s%.*s=%#llx ", msg ? msg : "", (int)(end - word), word, old);
			new = old; // do not change the value
			break;

		case '=': /* set */
			break;

		case '^': /* XOR */
			new = old ^ new;
			break;

		case '+': /* OR */
			new = old | new;
			break;

		case '-': /* AND NOT */
			new = old & ~new;
			break;

		default:
			break;
		}

		/* write the new value */
		if (new != old) {
			if (size == 8)
				write_u64(ptr, new);
			else if (size == 4)
				write_u32(ptr, new);
			else if (size == 2)
				write_u16(ptr, new);
			else
				*(uint8_t *)ptr = new;
		}
	}

	if (msg && *msg)
		return cli_dynmsg(appctx, LOG_INFO, msg);
	return 1;
}

static struct task *debug_task_handler(struct task *t, void *ctx, unsigned int state)
{
	unsigned long *tctx = ctx; // [0] = #tasks, [1] = inter, [2+] = { tl | (tsk+1) }
	unsigned long inter = tctx[1];
	unsigned long rnd;

	t->expire = tick_add(now_ms, inter);

	/* half of the calls will wake up another entry */
	rnd = statistical_prng();
	if (rnd & 1) {
		rnd >>= 1;
		rnd %= tctx[0];
		rnd = tctx[rnd + 2];

		if (rnd & 1)
			task_wakeup((struct task *)(rnd - 1), TASK_WOKEN_MSG);
		else
			tasklet_wakeup((struct tasklet *)rnd);
	}
	return t;
}

static struct task *debug_tasklet_handler(struct task *t, void *ctx, unsigned int state)
{
	unsigned long *tctx = ctx; // [0] = #tasks, [1] = inter, [2+] = { tl | (tsk+1) }
	unsigned long rnd;
	int i;

	/* wake up two random entries */
	for (i = 0; i < 2; i++) {
		rnd = statistical_prng() % tctx[0];
		rnd = tctx[rnd + 2];

		if (rnd & 1)
			task_wakeup((struct task *)(rnd - 1), TASK_WOKEN_MSG);
		else
			tasklet_wakeup((struct tasklet *)rnd);
	}
	return t;
}

/* parse a "debug dev sched" command
 * debug dev sched {task|tasklet} [count=<count>] [mask=<mask>] [single=<single>] [inter=<inter>]
 */
static int debug_parse_cli_sched(char **args, char *payload, struct appctx *appctx, void *private)
{
	int arg;
	void *ptr;
	int size;
	const char *word, *end;
	struct ist name;
	char *msg = NULL;
	char *endarg;
	unsigned long long new;
	unsigned long count = 0;
	unsigned long thrid = tid;
	unsigned int inter = 0;
	unsigned long i;
	int mode = 0; // 0 = tasklet; 1 = task
	unsigned long *tctx; // [0] = #tasks, [1] = inter, [2+] = { tl | (tsk+1) }

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	ptr = NULL; size = 0;

	if (strcmp(args[3], "task") != 0 && strcmp(args[3], "tasklet") != 0) {
		return cli_err(appctx,
			       "Usage: debug dev sched {task|tasklet} { <obj> = <value> }*\n"
			       "     <obj>   = {count | tid | inter }\n"
			       "     <value> = 64-bit dec/hex integer (0x prefix supported)\n"
			       );
	}

	mode = strcmp(args[3], "task") == 0;

	_HA_ATOMIC_INC(&debug_commands_issued);
	for (arg = 4; *args[arg]; arg++) {
		end = word = args[arg];
		while (*end && *end != '=' && *end != '^' && *end != '+' && *end != '-')
			end++;
		name = ist2(word, end - word);
		if (isteq(name, ist("count"))) {
			ptr = &count; size = sizeof(count);
		} else if (isteq(name, ist("tid"))) {
			ptr = &thrid; size = sizeof(thrid);
		} else if (isteq(name, ist("inter"))) {
			ptr = &inter; size = sizeof(inter);
		} else
			return cli_dynerr(appctx, memprintf(&msg, "Unsupported setting: '%s'.\n", word));

		/* parse the new value . */
		new = strtoll(end + 1, &endarg, 0);
		if (end[1] && *endarg) {
			memprintf(&msg,
			          "%sIgnoring unparsable value '%s' for field '%.*s'.\n",
			          msg ? msg : "", end + 1, (int)(end - word), word);
			continue;
		}

		/* write the new value */
		if (size == 8)
			write_u64(ptr, new);
		else if (size == 4)
			write_u32(ptr, new);
		else if (size == 2)
			write_u16(ptr, new);
		else
			*(uint8_t *)ptr = new;
	}

	tctx = calloc(sizeof(*tctx), count + 2);
	if (!tctx)
		goto fail;

	tctx[0] = (unsigned long)count;
	tctx[1] = (unsigned long)inter;

	if (thrid >= global.nbthread)
		thrid = tid;

	for (i = 0; i < count; i++) {
		/* now, if poly or mask was set, tmask corresponds to the
		 * valid thread mask to use, otherwise it remains zero.
		 */
		//printf("%lu: mode=%d mask=%#lx\n", i, mode, tmask);
		if (mode == 0) {
			struct tasklet *tl = tasklet_new();

			if (!tl)
				goto fail;

			tl->tid = thrid;
			tl->process = debug_tasklet_handler;
			tl->context = tctx;
			tctx[i + 2] = (unsigned long)tl;
		} else {
			struct task *task = task_new_on(thrid);

			if (!task)
				goto fail;

			task->process = debug_task_handler;
			task->context = tctx;
			tctx[i + 2] = (unsigned long)task + 1;
		}
	}

	/* start the tasks and tasklets */
	for (i = 0; i < count; i++) {
		unsigned long ctx = tctx[i + 2];

		if (ctx & 1)
			task_wakeup((struct task *)(ctx - 1), TASK_WOKEN_INIT);
		else
			tasklet_wakeup((struct tasklet *)ctx);
	}

	if (msg && *msg)
		return cli_dynmsg(appctx, LOG_INFO, msg);
	return 1;

 fail:
	/* free partially allocated entries */
	for (i = 0; tctx && i < count; i++) {
		unsigned long ctx = tctx[i + 2];

		if (!ctx)
			break;

		if (ctx & 1)
			task_destroy((struct task *)(ctx - 1));
		else
			tasklet_free((struct tasklet *)ctx);
	}

	free(tctx);
	return cli_err(appctx, "Not enough memory");
}

/* CLI state for "debug dev fd" */
struct dev_fd_ctx {
	int start_fd;
};

/* CLI parser for the "debug dev fd" command. The current FD to restart from is
 * stored in a struct dev_fd_ctx pointed to by svcctx.
 */
static int debug_parse_cli_fd(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct dev_fd_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	/* start at fd #0 */
	ctx->start_fd = 0;
	return 0;
}

/* CLI I/O handler for the "debug dev fd" command. Dumps all FDs that are
 * accessible from the process but not known from fdtab. The FD number to
 * restart from is stored in a struct dev_fd_ctx pointed to by svcctx.
 */
static int debug_iohandler_fd(struct appctx *appctx)
{
	struct dev_fd_ctx *ctx = appctx->svcctx;
	struct stconn *sc = appctx_sc(appctx);
	struct sockaddr_storage sa;
	struct stat statbuf;
	socklen_t salen, vlen;
	int ret1, ret2, port;
	char *addrstr;
	int ret = 1;
	int i, fd;

	if (unlikely(sc_ic(sc)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		goto end;

	chunk_reset(&trash);

	thread_isolate();

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	for (fd = ctx->start_fd; fd < global.maxsock; fd++) {
		/* check for FD's existence */
		ret1 = fcntl(fd, F_GETFD, 0);
		if (ret1 == -1)
			continue; // not known to the process
		if (fdtab[fd].owner)
			continue; // well-known

		/* OK we're seeing an orphan let's try to retrieve as much
		 * information as possible about it.
		 */
		chunk_printf(&trash, "%5d", fd);

		if (fstat(fd, &statbuf) != -1) {
			chunk_appendf(&trash, " type=%s mod=%04o dev=%#llx siz=%#llx uid=%lld gid=%lld fs=%#llx ino=%#llx",
				      isatty(fd)                ? "tty.":
				      S_ISREG(statbuf.st_mode)  ? "file":
				      S_ISDIR(statbuf.st_mode)  ? "dir.":
				      S_ISCHR(statbuf.st_mode)  ? "chr.":
				      S_ISBLK(statbuf.st_mode)  ? "blk.":
				      S_ISFIFO(statbuf.st_mode) ? "pipe":
				      S_ISLNK(statbuf.st_mode)  ? "link":
				      S_ISSOCK(statbuf.st_mode) ? "sock":
#ifdef USE_EPOLL
				      epoll_wait(fd, NULL, 0, 0) != -1 || errno != EBADF ? "epol":
#endif
				      "????",
				      (uint)statbuf.st_mode & 07777,

				      (ullong)statbuf.st_rdev,
				      (ullong)statbuf.st_size,
				      (ullong)statbuf.st_uid,
				      (ullong)statbuf.st_gid,

				      (ullong)statbuf.st_dev,
				      (ullong)statbuf.st_ino);
		}

		chunk_appendf(&trash, " getfd=%s+%#x",
			     (ret1 & FD_CLOEXEC) ? "cloex" : "",
			     ret1 &~ FD_CLOEXEC);

		/* FD options */
		ret2 = fcntl(fd, F_GETFL, 0);
		if (ret2) {
			chunk_appendf(&trash, " getfl=%s",
				      (ret1 & 3) >= 2 ? "O_RDWR" :
				      (ret1 & 1) ? "O_WRONLY" : "O_RDONLY");

			for (i = 2; i < 32; i++) {
				if (!(ret2 & (1UL << i)))
					continue;
				switch (1UL << i) {
				case O_CREAT:   chunk_appendf(&trash, ",O_CREAT");   break;
				case O_EXCL:    chunk_appendf(&trash, ",O_EXCL");    break;
				case O_NOCTTY:  chunk_appendf(&trash, ",O_NOCTTY");  break;
				case O_TRUNC:   chunk_appendf(&trash, ",O_TRUNC");   break;
				case O_APPEND:  chunk_appendf(&trash, ",O_APPEND");  break;
#ifdef O_ASYNC
				case O_ASYNC:   chunk_appendf(&trash, ",O_ASYNC");   break;
#endif
#ifdef O_DIRECT
				case O_DIRECT:  chunk_appendf(&trash, ",O_DIRECT");  break;
#endif
#ifdef O_NOATIME
				case O_NOATIME: chunk_appendf(&trash, ",O_NOATIME"); break;
#endif
				}
			}
		}

		vlen = sizeof(ret2);
		ret1 = getsockopt(fd, SOL_SOCKET, SO_TYPE, &ret2, &vlen);
		if (ret1 != -1)
			chunk_appendf(&trash, " so_type=%d", ret2);

		vlen = sizeof(ret2);
		ret1 = getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &ret2, &vlen);
		if (ret1 != -1)
			chunk_appendf(&trash, " so_accept=%d", ret2);

		vlen = sizeof(ret2);
		ret1 = getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret2, &vlen);
		if (ret1 != -1)
			chunk_appendf(&trash, " so_error=%d", ret2);

		salen = sizeof(sa);
		if (getsockname(fd, (struct sockaddr *)&sa, &salen) != -1) {
			if (sa.ss_family == AF_INET)
				port = ntohs(((const struct sockaddr_in *)&sa)->sin_port);
			else if (sa.ss_family == AF_INET6)
				port = ntohs(((const struct sockaddr_in6 *)&sa)->sin6_port);
			else
				port = 0;
			addrstr = sa2str(&sa, port, 0);
			chunk_appendf(&trash, " laddr=%s", addrstr);
			free(addrstr);
		}

		salen = sizeof(sa);
		if (getpeername(fd, (struct sockaddr *)&sa, &salen) != -1) {
			if (sa.ss_family == AF_INET)
				port = ntohs(((const struct sockaddr_in *)&sa)->sin_port);
			else if (sa.ss_family == AF_INET6)
				port = ntohs(((const struct sockaddr_in6 *)&sa)->sin6_port);
			else
				port = 0;
			addrstr = sa2str(&sa, port, 0);
			chunk_appendf(&trash, " raddr=%s", addrstr);
			free(addrstr);
		}

		chunk_appendf(&trash, "\n");

		if (applet_putchk(appctx, &trash) == -1) {
			ctx->start_fd = fd;
			ret = 0;
			break;
		}
	}

	thread_release();
 end:
	return ret;
}

#if defined(DEBUG_MEM_STATS)

/* CLI state for "debug dev memstats" */
struct dev_mem_ctx {
	struct mem_stats *start, *stop; /* begin/end of dump */
	int show_all;                   /* show all entries if non-null */
	int width;
};

/* CLI parser for the "debug dev memstats" command. Sets a dev_mem_ctx shown above. */
static int debug_parse_cli_memstats(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct dev_mem_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int arg;

	extern __attribute__((__weak__)) struct mem_stats __start_mem_stats;
	extern __attribute__((__weak__)) struct mem_stats __stop_mem_stats;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	for (arg = 3; *args[arg]; arg++) {
		if (strcmp(args[arg], "reset") == 0) {
			struct mem_stats *ptr;

			if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
				return 1;

			for (ptr = &__start_mem_stats; ptr < &__stop_mem_stats; ptr++) {
				_HA_ATOMIC_STORE(&ptr->calls, 0);
				_HA_ATOMIC_STORE(&ptr->size, 0);
			}
			return 1;
		}
		else if (strcmp(args[arg], "all") == 0) {
			ctx->show_all = 1;
			continue;
		}
		else
			return cli_err(appctx, "Expects either 'reset' or 'all'.\n");
	}

	/* otherwise proceed with the dump from p0 to p1 */
	ctx->start = &__start_mem_stats;
	ctx->stop  = &__stop_mem_stats;
	ctx->width = 0;
	return 0;
}

/* CLI I/O handler for the "debug dev memstats" command using a dev_mem_ctx
 * found in appctx->svcctx. Dumps all mem_stats structs referenced by pointers
 * located between ->start and ->stop. Dumps all entries if ->show_all != 0,
 * otherwise only non-zero calls.
 */
static int debug_iohandler_memstats(struct appctx *appctx)
{
	struct dev_mem_ctx *ctx = appctx->svcctx;
	struct stconn *sc = appctx_sc(appctx);
	struct mem_stats *ptr;
	int ret = 1;

	if (unlikely(sc_ic(sc)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		goto end;

	if (!ctx->width) {
		/* we don't know the first column's width, let's compute it
		 * now based on a first pass on printable entries and their
		 * expected width (approximated).
		 */
		for (ptr = ctx->start; ptr != ctx->stop; ptr++) {
			const char *p, *name;
			int w = 0;
			char tmp;

			if (!ptr->size && !ptr->calls && !ctx->show_all)
				continue;

			for (p = name = ptr->caller.file; *p; p++) {
				if (*p == '/')
					name = p + 1;
			}

			if (ctx->show_all)
				w = snprintf(&tmp, 0, "%s(%s:%d) ", ptr->caller.func, name, ptr->caller.line);
			else
				w = snprintf(&tmp, 0, "%s:%d ", name, ptr->caller.line);

			if (w > ctx->width)
				ctx->width = w;
		}
	}

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	for (ptr = ctx->start; ptr != ctx->stop; ptr++) {
		const char *type;
		const char *name;
		const char *p;
		const char *info = NULL;
		const char *func = NULL;

		if (!ptr->size && !ptr->calls && !ctx->show_all)
			continue;

		/* basename only */
		for (p = name = ptr->caller.file; *p; p++) {
			if (*p == '/')
				name = p + 1;
		}

		func = ptr->caller.func;

		switch (ptr->caller.what) {
		case MEM_STATS_TYPE_CALLOC:  type = "CALLOC";  break;
		case MEM_STATS_TYPE_FREE:    type = "FREE";    break;
		case MEM_STATS_TYPE_MALLOC:  type = "MALLOC";  break;
		case MEM_STATS_TYPE_REALLOC: type = "REALLOC"; break;
		case MEM_STATS_TYPE_STRDUP:  type = "STRDUP";  break;
		case MEM_STATS_TYPE_P_ALLOC: type = "P_ALLOC"; if (ptr->extra) info = ((const struct pool_head *)ptr->extra)->name; break;
		case MEM_STATS_TYPE_P_FREE:  type = "P_FREE";  if (ptr->extra) info = ((const struct pool_head *)ptr->extra)->name; break;
		default:                     type = "UNSET";   break;
		}

		//chunk_printf(&trash,
		//	     "%20s:%-5d %7s size: %12lu calls: %9lu size/call: %6lu\n",
		//	     name, ptr->line, type,
		//	     (unsigned long)ptr->size, (unsigned long)ptr->calls,
		//	     (unsigned long)(ptr->calls ? (ptr->size / ptr->calls) : 0));

		chunk_reset(&trash);
		if (ctx->show_all)
			chunk_appendf(&trash, "%s(", func);

		chunk_appendf(&trash, "%s:%d", name, ptr->caller.line);

		if (ctx->show_all)
			chunk_appendf(&trash, ")");

		while (trash.data < ctx->width)
			trash.area[trash.data++] = ' ';

		chunk_appendf(&trash, "%7s  size: %12lu  calls: %9lu  size/call: %6lu %s\n",
			     type,
			     (unsigned long)ptr->size, (unsigned long)ptr->calls,
		             (unsigned long)(ptr->calls ? (ptr->size / ptr->calls) : 0),
			     info ? info : "");

		if (applet_putchk(appctx, &trash) == -1) {
			ctx->start = ptr;
			ret = 0;
			break;
		}
	}

 end:
	return ret;
}

#endif

#ifndef USE_THREAD_DUMP

/* This function dumps all threads' state to the trash. This version is the
 * most basic one, which doesn't inspect other threads.
 */
void ha_thread_dump_all_to_trash()
{
	unsigned int thr;

	for (thr = 0; thr < global.nbthread; thr++)
		ha_thread_dump(&trash, thr, tid);
}

#else /* below USE_THREAD_DUMP is set */

/* ID of the thread requesting the dump */
static unsigned int thread_dump_tid;

/* points to the buffer where the dump functions should write. It must
 * have already been initialized by the requester. Nothing is done if
 * it's NULL.
 */
struct buffer *thread_dump_buffer = NULL;

/* initiates a thread dump */
void ha_thread_dump_all_to_trash()
{
	unsigned int old;

	/* initiate a dump starting from first thread. Use a CAS so that we do
	 * not wait if we're not the first one, but we wait for a previous dump
	 * to finish.
	 */
	while (1) {
		old = 0;
		if (HA_ATOMIC_CAS(&thread_dump_state, &old, THREAD_DUMP_FSYNC))
			break;
		ha_thread_relax();
	}
	thread_dump_buffer = &trash;
	thread_dump_tid = tid;
	ha_tkillall(DEBUGSIG);

	/* the call above contains a raise() so we're certain to return after
	 * returning from the sighandler, hence when the dump is complete.
	 */
}

/* handles DEBUGSIG to dump the state of the thread it's working on. This is
 * appended at the end of thread_dump_buffer which must be protected against
 * reentrance from different threads (a thread-local buffer works fine).
 */
void debug_handler(int sig, siginfo_t *si, void *arg)
{
	int harmless = is_thread_harmless();
	int running = 0;
	uint prev;
	uint next;

	/* first, let's check it's really for us and that we didn't just get
	 * a spurious DEBUGSIG.
	 */
	if (!_HA_ATOMIC_LOAD(&thread_dump_state))
		return;

	/* There are 5 phases in the dump process:
	 *   1- wait for all threads to sync or the first one to start
	 *   2- wait for our turn, i.e. when tid appears in lower bits.
	 *   3- perform the action if our tid is there
	 *   4- pass tid to the number of the next thread to dump or
	 *      reset running counter if we're last one.
	 *   5- wait for running to be zero and decrement the count
	 */

	/* wait for all previous threads to finish first */
	if (!harmless)
		thread_harmless_now();

	if (HA_ATOMIC_FETCH_ADD(&thread_dump_state, 1) == THREAD_DUMP_FSYNC) {
		/* the first one which lands here is responsible for constantly
		 * recounting the number of active theads and switching from
		 * SYNC to DUMP.
		 */
		while (1) {
			int first = -1; // first tid to dump
			int thr;

			running = 0;
			for (thr = 0; thr < global.nbthread; thr++) {
				if (ha_thread_info[thr].tg->threads_enabled & ha_thread_info[thr].ltid_bit) {
					running++;
					if (first < 0)
						first = thr;
				}
			}

			if ((HA_ATOMIC_LOAD(&thread_dump_state) & THREAD_DUMP_TMASK) == running) {
				/* all threads are there, let's try to start */
				prev = THREAD_DUMP_FSYNC | running;
				next = (running << 16) | first;
				if (HA_ATOMIC_CAS(&thread_dump_state, &prev, next))
					break;
				/* it failed! maybe a thread appeared late (e.g. during boot), let's
				 * recount.
				 */
			}
			ha_thread_relax();
		}
	}

	/* all threads: let's wait for the SYNC flag to disappear; tid is reset at
	 * the same time to the first valid tid to dump and pmask will reflect the
	 * number of participants.
	 */
	while (HA_ATOMIC_LOAD(&thread_dump_state) & THREAD_DUMP_FSYNC)
		ha_thread_relax();

	/* wait for our turn */
	while ((HA_ATOMIC_LOAD(&thread_dump_state) & THREAD_DUMP_TMASK) != tid)
		ha_thread_relax();

	/* make sure we don't count all that wait time against us */
	HA_ATOMIC_AND(&th_ctx->flags, ~TH_FL_STUCK);

	if (!harmless)
		thread_harmless_end();

	/* dump if needed */
	if (thread_dump_buffer)
		ha_thread_dump(thread_dump_buffer, tid, thread_dump_tid);

	/* figure which is the next thread ID to dump among enabled ones. Note
	 * that this relies on the fact that we're not creating new threads in
	 * the middle of a dump, which is normally granted by the harmless bits
	 * anyway.
	 */
	for (next = tid + 1; next < global.nbthread; next++) {
		if (unlikely(next >= MAX_THREADS)) {
			/* just to please gcc 6.5 who guesses the ranges wrong. */
			continue;
		}

		if (ha_thread_info[next].tg &&
		    ha_thread_info[next].tg->threads_enabled & ha_thread_info[next].ltid_bit)
			break;
	}

	/* if there are threads left to dump, we atomically set the next one,
	 * otherwise we'll clear dump and set the thread part to the number of
	 * threads that need to disappear.
	 */
	if (next < global.nbthread) {
		next = (HA_ATOMIC_LOAD(&thread_dump_state) & THREAD_DUMP_PMASK) | next;
		HA_ATOMIC_STORE(&thread_dump_state, next);
	} else {
		thread_dump_buffer = NULL; // was the last one
		running = (HA_ATOMIC_LOAD(&thread_dump_state) & THREAD_DUMP_PMASK) >> 16;
		HA_ATOMIC_STORE(&thread_dump_state, running);
	}

	/* now wait for all others to finish dumping: the lowest part will turn
	 * to zero. Then all others decrement the done part.
	 */
	if (!harmless)
		thread_harmless_now();

	/* wait for everyone to finish*/
	while (HA_ATOMIC_LOAD(&thread_dump_state) & THREAD_DUMP_PMASK)
		ha_thread_relax();

	/* make sure we don't count all that wait time against us */
	HA_ATOMIC_AND(&th_ctx->flags, ~TH_FL_STUCK);

	if (!harmless)
		thread_harmless_end();

	/* we're gone. Past this point anything can happen including another
	 * thread trying to re-trigger a dump, so thread_dump_buffer and
	 * thread_dump_tid may become invalid immediately after this call.
	 */
	HA_ATOMIC_SUB(&thread_dump_state, 1);

	/* mark the current thread as stuck to detect it upon next invocation
	 * if it didn't move.
	 */
	if (!harmless &&
	    !(_HA_ATOMIC_LOAD(&th_ctx->flags) & TH_FL_SLEEPING))
		_HA_ATOMIC_OR(&th_ctx->flags, TH_FL_STUCK);
}

static int init_debug_per_thread()
{
	sigset_t set;

	/* unblock the DEBUGSIG signal we intend to use */
	sigemptyset(&set);
	sigaddset(&set, DEBUGSIG);
	ha_sigmask(SIG_UNBLOCK, &set, NULL);
	return 1;
}

static int init_debug()
{
	struct sigaction sa;
	void *callers[1];

	/* calling backtrace() will access libgcc at runtime. We don't want to
	 * do it after the chroot, so let's perform a first call to have it
	 * ready in memory for later use.
	 */
	my_backtrace(callers, sizeof(callers)/sizeof(*callers));
	sa.sa_handler = NULL;
	sa.sa_sigaction = debug_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(DEBUGSIG, &sa, NULL);
	return ERR_NONE;
}

REGISTER_POST_CHECK(init_debug);
REGISTER_PER_THREAD_INIT(init_debug_per_thread);

#endif /* USE_THREAD_DUMP */

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{{ "debug", "dev", "bug", NULL },      "debug dev bug                           : call BUG_ON() and crash",                 debug_parse_cli_bug,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "check", NULL },    "debug dev check                         : call CHECK_IF() and possibly crash",      debug_parse_cli_check, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "close", NULL },    "debug dev close  <fd>                   : close this file descriptor",              debug_parse_cli_close, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "deadlock", NULL }, "debug dev deadlock [nbtask]             : deadlock between this number of tasks",   debug_parse_cli_deadlock, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "delay", NULL },    "debug dev delay  [ms]                   : sleep this long",                         debug_parse_cli_delay, NULL, NULL, NULL, ACCESS_EXPERT },
#if defined(DEBUG_DEV)
	{{ "debug", "dev", "exec",  NULL },    "debug dev exec   [cmd] ...              : show this command's output",              debug_parse_cli_exec,  NULL, NULL, NULL, ACCESS_EXPERT },
#endif
	{{ "debug", "dev", "fd", NULL },       "debug dev fd                            : scan for rogue/unhandled FDs",            debug_parse_cli_fd,    debug_iohandler_fd, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "exit",  NULL },    "debug dev exit   [code]                 : immediately exit the process",            debug_parse_cli_exit,  NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "hex",   NULL },    "debug dev hex    <addr> [len]           : dump a memory area",                      debug_parse_cli_hex,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "log",   NULL },    "debug dev log    [msg] ...              : send this msg to global logs",            debug_parse_cli_log,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "loop",  NULL },    "debug dev loop   [ms]                   : loop this long",                          debug_parse_cli_loop,  NULL, NULL, NULL, ACCESS_EXPERT },
#if defined(DEBUG_MEM_STATS)
	{{ "debug", "dev", "memstats", NULL }, "debug dev memstats [reset|all]          : dump/reset memory statistics",            debug_parse_cli_memstats, debug_iohandler_memstats, NULL, NULL, ACCESS_EXPERT },
#endif
	{{ "debug", "dev", "panic", NULL },    "debug dev panic                         : immediately trigger a panic",             debug_parse_cli_panic, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "sched", NULL },    "debug dev sched  {task|tasklet} [k=v]*  : stress the scheduler",                    debug_parse_cli_sched, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "stream",NULL },    "debug dev stream [k=v]*                 : show/manipulate stream flags",            debug_parse_cli_stream,NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "sym",   NULL },    "debug dev sym    <addr>                 : resolve symbol address",                  debug_parse_cli_sym,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "tkill", NULL },    "debug dev tkill  [thr] [sig]            : send signal to thread",                   debug_parse_cli_tkill, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "warn",  NULL },    "debug dev warn                          : call WARN_ON() and possibly crash",       debug_parse_cli_warn,  NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "write", NULL },    "debug dev write  [size]                 : write that many bytes in return",         debug_parse_cli_write, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "hash", NULL },     "debug dev hash  [msg]                   : return msg hashed",                       debug_parse_cli_hash, NULL, NULL, NULL, ACCESS_EXPERT },

#if defined(HA_HAVE_DUMP_LIBS)
	{{ "show", "libs", NULL, NULL },       "show libs                               : show loaded object files and libraries", debug_parse_cli_show_libs, NULL, NULL },
#endif
	{{ "show", "threads", NULL, NULL },    "show threads                            : show some threads debugging information", NULL, cli_io_handler_show_threads, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
