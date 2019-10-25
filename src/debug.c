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

#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <common/buf.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/hathreads.h>
#include <common/initcall.h>
#include <common/ist.h>
#include <common/net_helper.h>
#include <common/standard.h>

#include <types/global.h>

#include <proto/cli.h>
#include <proto/fd.h>
#include <proto/hlua.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

/* mask of threads still having to dump, used to respect ordering. Only used
 * when USE_THREAD_DUMP is set.
 */
volatile unsigned long threads_to_dump = 0;
unsigned int debug_commands_issued = 0;

/* Dumps to the buffer some known information for the desired thread, and
 * optionally extra info for the current thread. The dump will be appended to
 * the buffer, so the caller is responsible for preliminary initializing it.
 * The calling thread ID needs to be passed in <calling_tid> to display a star
 * in front of the calling thread's line (usually it's tid). Any stuck thread
 * is also prefixed with a '>'.
 */
void ha_thread_dump(struct buffer *buf, int thr, int calling_tid)
{
	unsigned long thr_bit = 1UL << thr;
	unsigned long long p = ha_thread_info[thr].prev_cpu_time;
	unsigned long long n = now_cpu_time_thread(&ha_thread_info[thr]);
	int stuck = !!(ha_thread_info[thr].flags & TI_FL_STUCK);

	chunk_appendf(buf,
	              "%c%cThread %-2u: act=%d glob=%d wq=%d rq=%d tl=%d tlsz=%d rqsz=%d\n"
	              "             stuck=%d prof=%d",
	              (thr == calling_tid) ? '*' : ' ', stuck ? '>' : ' ', thr + 1,
		      thread_has_tasks(),
	              !!(global_tasks_mask & thr_bit),
	              !eb_is_empty(&task_per_thread[thr].timers),
	              !eb_is_empty(&task_per_thread[thr].rqueue),
	              !(LIST_ISEMPTY(&task_per_thread[thr].task_list) |
		        MT_LIST_ISEMPTY(&task_per_thread[thr].shared_tasklet_list)),
	              task_per_thread[thr].task_list_size,
	              task_per_thread[thr].rqueue_size,
	              stuck,
	              !!(task_profiling_mask & thr_bit));

	chunk_appendf(buf,
	              " harmless=%d wantrdv=%d",
	              !!(threads_harmless_mask & thr_bit),
	              !!(threads_want_rdv_mask & thr_bit));

	chunk_appendf(buf, "\n");
	chunk_appendf(buf, "             cpu_ns: poll=%llu now=%llu diff=%llu\n", p, n, n-p);

	/* this is the end of what we can dump from outside the thread */

	if (thr != tid)
		return;

	chunk_appendf(buf, "             curr_task=");
	ha_task_dump(buf, sched->current, "             ");
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
		              task->call_date ? (unsigned long long)(now_mono_time() - task->call_date) : 0,
		              task->call_date ? " ns ago" : "");

	chunk_appendf(buf, "%s"
	              "  fct=%p (%s) ctx=%p",
	              pfx,
	              task->process,
	              task->process == process_stream ? "process_stream" :
	              task->process == task_run_applet ? "task_run_applet" :
	              task->process == si_cs_io_cb ? "si_cs_io_cb" :
#ifdef USE_LUA
		      task->process == hlua_process_task ? "hlua_process_task" :
#endif
		      "?",
	              task->context);

	if (task->process == task_run_applet && (appctx = task->context))
		chunk_appendf(buf, "(%s)\n", appctx->applet->name);
	else
		chunk_appendf(buf, "\n");

	if (task->process == process_stream && task->context)
		s = (struct stream *)task->context;
	else if (task->process == task_run_applet && task->context)
		s = si_strm(((struct appctx *)task->context)->owner);
	else if (task->process == si_cs_io_cb && task->context)
		s = si_strm((struct stream_interface *)task->context);

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
		 (appctx->applet->fct == hlua_applet_tcp_fct && (hlua = appctx->ctx.hlua_apptcp.hlua))) {
		chunk_appendf(buf, "%sCurrent executing a Lua TCP service -- ", pfx);
	}
	else if (task->process == task_run_applet && (appctx = task->context) &&
		 (appctx->applet->fct == hlua_applet_http_fct && (hlua = appctx->ctx.hlua_apphttp.hlua))) {
		chunk_appendf(buf, "%sCurrent executing a Lua HTTP service -- ", pfx);
	}

	if (hlua) {
		luaL_traceback(hlua->T, hlua->T, NULL, 0);
		if (!append_prefixed_str(buf, lua_tostring(hlua->T, -1), pfx, '\n', 1))
			b_putchr(buf, '\n');
	}
#endif
}

/* This function dumps all profiling settings. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero.
 */
static int cli_io_handler_show_threads(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	int thr;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	if (appctx->st0)
		thr = appctx->st1;
	else
		thr = 0;

	chunk_reset(&trash);
	ha_thread_dump_all_to_trash();

	if (ci_putchk(si_ic(si), &trash) == -1) {
		/* failed, try again */
		si_rx_room_blk(si);
		appctx->st1 = thr;
		return 0;
	}
	return 1;
}

/* dumps a state of all threads into the trash and on fd #2, then aborts. */
void ha_panic()
{
	chunk_reset(&trash);
	chunk_appendf(&trash, "Thread %u is about to kill the process.\n", tid + 1);
	ha_thread_dump_all_to_trash();
	shut_your_big_mouth_gcc(write(2, trash.area, trash.data));
	for (;;)
		abort();
}

/* parse a "debug dev exit" command. It always returns 1, though it should never return. */
static int debug_parse_cli_exit(char **args, char *payload, struct appctx *appctx, void *private)
{
	int code = atoi(args[3]);

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);
	exit(code);
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

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);
	fd_delete(fd);
	return 1;
}

/* parse a "debug dev delay" command. It always returns 1. */
static int debug_parse_cli_delay(char **args, char *payload, struct appctx *appctx, void *private)
{
	int delay = atoi(args[3]);

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);
	usleep((long)delay * 1000);
	return 1;
}

/* parse a "debug dev log" command. It always returns 1. */
static int debug_parse_cli_log(char **args, char *payload, struct appctx *appctx, void *private)
{
	int arg;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);
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

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);
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

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);
	ha_panic();
	return 1;
}

/* parse a "debug dev exec" command. It always returns 1. */
#if defined(DEBUG_DEV)
static int debug_parse_cli_exec(char **args, char *payload, struct appctx *appctx, void *private)
{
	FILE *f;
	int arg;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);
	chunk_reset(&trash);
	for (arg = 3; *args[arg]; arg++) {
		if (arg > 3)
			chunk_strcat(&trash, " ");
		chunk_strcat(&trash, args[arg]);
	}

	f = popen(trash.area, "re");
	if (!f)
		return cli_err(appctx, "Failed to execute command.\n");

	chunk_reset(&trash);
	while (1) {
		size_t ret = fread(trash.area + trash.data, 1, trash.size - 20 - trash.data, f);
		if (!ret)
			break;
		trash.data += ret;
		if (trash.data + 20 == trash.size) {
			chunk_strcat(&trash, "\n[[[TRUNCATED]]]\n");
			break;
		}
	}

	fclose(f);
	trash.area[trash.data] = 0;
	return cli_msg(appctx, LOG_INFO, trash.area);
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

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);

	/* by default, dump ~128 till next block of 16 */
	len = strtoul(args[4], NULL, 0);
	if (!len)
		len = ((start + 128) & -16) - start;

	chunk_reset(&trash);
	dump_hex(&trash, "  ", (const void *)start, len, 1);
	trash.area[trash.data] = 0;
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

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);
	if (thr)
		ha_tkill(thr - 1, sig);
	else
		raise(sig);
	return 1;
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
	struct stream *s = si_strm(appctx->owner);
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
			       "     <obj>   = {strm | strm.f | sif.f | sif.s | sif.x | sib.f | sib.s | sib.x |\n"
			       "                txn.f | req.f | req.r | req.w | res.f | res.r | res.w}\n"
			       "     <op>    = {'' (show) | '=' (assign) | '^' (xor) | '+' (or) | '-' (andnot)}\n"
			       "     <value> = 'now' | 64-bit dec/hex integer (0x prefix supported)\n"
			       "     'wake' wakes the stream asssigned to 'strm' (default: current)\n"
			       );
	}

	_HA_ATOMIC_ADD(&debug_commands_issued, 1);
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
		} else if (isteq(name, ist("sif.f"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->si[0].flags; size = sizeof(s->si[0].flags);
		} else if (isteq(name, ist("sib.f"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->si[1].flags; size = sizeof(s->si[1].flags);
		} else if (isteq(name, ist("sif.x"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->si[0].exp; size = sizeof(s->si[0].exp);
		} else if (isteq(name, ist("sib.x"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->si[1].exp; size = sizeof(s->si[1].exp);
		} else if (isteq(name, ist("sif.s"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->si[0].state; size = sizeof(s->si[0].state);
		} else if (isteq(name, ist("sib.s"))) {
			ptr = (!s || !may_access(s)) ? NULL : &s->si[1].state; size = sizeof(s->si[1].state);
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

/* The signal to trigger a debug dump on a thread is SIGURG. It has the benefit
 * of not stopping gdb by default, so that issuing "show threads" in a process
 * being debugged has no adverse effect.
 */
#define DEBUGSIG SIGURG

/* ID of the thread requesting the dump */
static unsigned int thread_dump_tid;

/* points to the buffer where the dump functions should write. It must
 * have already been initialized by the requester. Nothing is done if
 * it's NULL.
 */
struct buffer *thread_dump_buffer = NULL;

void ha_thread_dump_all_to_trash()
{
	unsigned long old;

	while (1) {
		old = 0;
		if (HA_ATOMIC_CAS(&threads_to_dump, &old, all_threads_mask))
			break;
		ha_thread_relax();
	}

	thread_dump_buffer = &trash;
	thread_dump_tid = tid;
	ha_tkillall(DEBUGSIG);
}

/* handles DEBUGSIG to dump the state of the thread it's working on */
void debug_handler(int sig, siginfo_t *si, void *arg)
{
	/* There are 4 phases in the dump process:
	 *   1- wait for our turn, i.e. when all lower bits are gone.
	 *   2- perform the action if our bit is set
	 *   3- remove our bit to let the next one go, unless we're
	 *      the last one and have to put them all as a signal
	 *   4- wait out bit to re-appear, then clear it and quit.
	 */

	/* wait for all previous threads to finish first */
	while (threads_to_dump & (tid_bit - 1))
		ha_thread_relax();

	/* dump if needed */
	if (threads_to_dump & tid_bit) {
		if (thread_dump_buffer)
			ha_thread_dump(thread_dump_buffer, tid, thread_dump_tid);
		if ((threads_to_dump & all_threads_mask) == tid_bit) {
			/* last one */
			HA_ATOMIC_STORE(&threads_to_dump, all_threads_mask);
			thread_dump_buffer = NULL;
		}
		else
			HA_ATOMIC_AND(&threads_to_dump, ~tid_bit);
	}

	/* now wait for all others to finish dumping. The last one will set all
	 * bits again to broadcast the leaving condition so we'll see ourselves
	 * present again. This way the threads_to_dump variable never passes to
	 * zero until all visitors have stopped waiting.
	 */
	while (!(threads_to_dump & tid_bit))
		ha_thread_relax();
	HA_ATOMIC_AND(&threads_to_dump, ~tid_bit);

	/* mark the current thread as stuck to detect it upon next invocation
	 * if it didn't move.
	 */
	if (!((threads_harmless_mask|sleeping_thread_mask) & tid_bit))
		ti->flags |= TI_FL_STUCK;
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

	sa.sa_handler = NULL;
	sa.sa_sigaction = debug_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(DEBUGSIG, &sa, NULL);
	return 0;
}

REGISTER_POST_CHECK(init_debug);
REGISTER_PER_THREAD_INIT(init_debug_per_thread);

#endif /* USE_THREAD_DUMP */

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{{ "debug", "dev", "close", NULL }, "debug dev close <fd>        : close this file descriptor",      debug_parse_cli_close, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "delay", NULL }, "debug dev delay [ms]        : sleep this long",                 debug_parse_cli_delay, NULL, NULL, NULL, ACCESS_EXPERT },
#if defined(DEBUG_DEV)
	{{ "debug", "dev", "exec",  NULL }, "debug dev exec  [cmd] ...   : show this command's output",      debug_parse_cli_exec,  NULL, NULL, NULL, ACCESS_EXPERT },
#endif
	{{ "debug", "dev", "exit",  NULL }, "debug dev exit  [code]      : immediately exit the process",    debug_parse_cli_exit,  NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "hex",   NULL }, "debug dev hex   <addr> [len]: dump a memory area",              debug_parse_cli_hex,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "log",   NULL }, "debug dev log   [msg] ...   : send this msg to global logs",    debug_parse_cli_log,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "loop",  NULL }, "debug dev loop  [ms]        : loop this long",                  debug_parse_cli_loop,  NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "panic", NULL }, "debug dev panic             : immediately trigger a panic",     debug_parse_cli_panic, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "stream",NULL }, "debug dev stream ...        : show/manipulate stream flags",    debug_parse_cli_stream,NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "tkill", NULL }, "debug dev tkill [thr] [sig] : send signal to thread",           debug_parse_cli_tkill, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "show", "threads", NULL, NULL }, "show threads   : show some threads debugging information",  NULL, cli_io_handler_show_threads, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
