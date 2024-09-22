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
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
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
#include <haproxy/limits.h>
#if defined(USE_LINUX_CAP)
#include <haproxy/linuxcap.h>
#endif
#include <haproxy/log.h>
#include <haproxy/net_helper.h>
#include <haproxy/sc_strm.h>
#include <haproxy/proxy.h>
#include <haproxy/stconn.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/trace.h>
#include <haproxy/version.h>
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

/* Description of a component with name, version, path, build options etc. E.g.
 * one of them is haproxy. Others might be some clearly identified shared libs.
 * They're intentionally self-contained and to be placed into an array to make
 * it easier to find them in a core. The important fields (name and version)
 * are locally allocated, other ones are dynamic.
 */
struct post_mortem_component {
	char name[32];           // symbolic short name
	char version[32];        // exact version
	char *toolchain;         // compiler and version (e.g. gcc-11.4.0)
	char *toolchain_opts;    // optims, arch-specific options (e.g. CFLAGS)
	char *build_settings;    // build options (e.g. USE_*, TARGET, etc)
	char *path;              // path if known.
};

/* This is a collection of information that are centralized to help with core
 * dump analysis. It must be used with a public variable and gather elements
 * as much as possible without dereferences so that even when identified in a
 * core dump it's possible to get the most out of it even if the core file is
 * not much exploitable. It's aligned to 256 so that it's easy to spot, given
 * that being that large it will not change its size much.
 */
struct post_mortem {
	/* platform-specific information */
	char post_mortem_magic[32];     // "POST-MORTEM STARTS HERE+7654321\0"
	struct {
		struct utsname utsname; // OS name+ver+arch+hostname
		char hw_vendor[64];     // hardware/hypervisor vendor when known
		char hw_family[64];     // hardware/hypervisor product family when known
		char hw_model[64];      // hardware/hypervisor product/model when known
		char brd_vendor[64];    // mainboard vendor when known
		char brd_model[64];     // mainboard model when known
		char soc_vendor[64];    // SoC/CPU vendor from cpuinfo
		char soc_model[64];     // SoC model when known and relevant
		char cpu_model[64];     // CPU model when different from SoC
		char virt_techno[16];   // when provided by cpuid
		char cont_techno[16];   // empty, "no", "yes", "docker" or others
	} platform;

	/* process-specific information */
	struct {
		pid_t pid;
		uid_t boot_uid;
		gid_t boot_gid;
		uid_t run_uid;
		gid_t run_gid;
#if defined(USE_LINUX_CAP)
		struct {
			// initial process capabilities
			struct __user_cap_data_struct boot[_LINUX_CAPABILITY_U32S_3];
			int err_boot; // errno, if capget() syscall fails at boot
			// runtime process capabilities
			struct __user_cap_data_struct run[_LINUX_CAPABILITY_U32S_3];
			int err_run; // errno, if capget() syscall fails at runtime
		} caps;
#endif
		struct rlimit boot_lim_fd;  // RLIMIT_NOFILE at startup
		struct rlimit boot_lim_ram; // RLIMIT_DATA at startup
		struct rlimit run_lim_fd;  // RLIMIT_NOFILE just before enter in polling loop
		struct rlimit run_lim_ram; // RLIMIT_DATA just before enter in polling loop
		char **argv;
		unsigned char argc;
	} process;

#if defined(HA_HAVE_DUMP_LIBS)
	/* information about dynamic shared libraries involved */
	char *libs;                      // dump of one addr / path per line, or NULL
#endif
	struct tgroup_info *tgroup_info; // pointer to ha_tgroup_info
	struct thread_info *thread_info; // pointer to ha_thread_info
	struct tgroup_ctx  *tgroup_ctx;  // pointer to ha_tgroup_ctx
	struct thread_ctx  *thread_ctx;  // pointer to ha_thread_ctx
	struct list *pools;              // pointer to the head of the pools list
	struct proxy **proxies;          // pointer to the head of the proxies list
	struct global *global;           // pointer to the struct global
	struct fdtab **fdtab;            // pointer to the fdtab array
	struct activity *activity;       // pointer to the activity[] per-thread array

	/* info about identified distinct components (executable, shared libs, etc).
	 * These can be all listed at once in gdb using:
	 *    p *post_mortem.components@post_mortem.nb_components
	 */
	uint nb_components;              // # of components below
	struct post_mortem_component *components; // NULL or array
} post_mortem ALIGNED(256) HA_SECTION("_post_mortem") = { };

unsigned int debug_commands_issued = 0;
unsigned int warn_blocked_issued = 0;

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
			/* dump not started, will start *after* ha_thread_dump_one(),
			 * ha_panic and ha_backtrace_to_stderr
			 */
			if (addr == ha_panic ||
			    addr == ha_backtrace_to_stderr || addr == ha_thread_dump_one)
				dump++;
			*buf = bak;
			continue;
		}

		if ((dump & 3) == 1) {
			/* starting */
			if (addr == ha_panic ||
			    addr == ha_backtrace_to_stderr || addr == ha_thread_dump_one) {
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

/* Dumps to the thread's buffer some known information for the desired thread,
 * and optionally extra info when it's safe to do so (current thread or
 * isolated). The dump will be appended to the buffer, so the caller is
 * responsible for preliminary initializing it. The <from_signal> argument will
 * indicate if the function is called from the debug signal handler, indicating
 * the thread was dumped upon request from another one, otherwise if the thread
 * it the current one, a star ('*') will be displayed in front of the thread to
 * indicate the requesting one. Any stuck thread is also prefixed with a '>'.
 * The caller is responsible for atomically setting up the thread's dump buffer
 * to point to a valid buffer with enough room. Output will be truncated if it
 * does not fit. When the dump is complete, the dump buffer will have bit 0 set
 * to 1 to tell the caller it's done, and the caller will then change that value
 * to indicate it's done once the contents are collected.
 */
void ha_thread_dump_one(int thr, int from_signal)
{
	struct buffer *buf = HA_ATOMIC_LOAD(&ha_thread_ctx[thr].thread_dump_buffer);
	unsigned long __maybe_unused thr_bit = ha_thread_info[thr].ltid_bit;
	int __maybe_unused tgrp  = ha_thread_info[thr].tgid;
	unsigned long long p = ha_thread_ctx[thr].prev_cpu_time;
	unsigned long long n = now_cpu_time_thread(thr);
	int stuck = !!(ha_thread_ctx[thr].flags & TH_FL_STUCK);

	chunk_appendf(buf,
	              "%c%cThread %-2u: id=0x%llx act=%d glob=%d wq=%d rq=%d tl=%d tlsz=%d rqsz=%d\n"
	              "     %2u/%-2u   stuck=%d prof=%d",
	              (thr == tid && !from_signal) ? '*' : ' ', stuck ? '>' : ' ', thr + 1,
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
	              !!(ha_thread_ctx[thr].flags & TH_FL_TASK_PROFILING));

#if defined(USE_THREAD)
	chunk_appendf(buf,
	              " harmless=%d isolated=%d",
	              !!(_HA_ATOMIC_LOAD(&ha_tgroup_ctx[tgrp-1].threads_harmless) & thr_bit),
		      isolated_thread == thr);
#endif

	chunk_appendf(buf, "\n");
	chunk_appendf(buf, "             cpu_ns: poll=%llu now=%llu diff=%llu\n", p, n, n-p);

	/* this is the end of what we can dump from outside the current thread */

	if (thr != tid && !thread_isolated())
		goto leave;

	chunk_appendf(buf, "             curr_task=");
	ha_task_dump(buf, th_ctx->current, "             ");

	if (thr == tid && !(HA_ATOMIC_LOAD(&tg_ctx->threads_idle) & ti->ltid_bit)) {
		/* only dump the stack of active threads */
#ifdef USE_LUA
		if (th_ctx->current &&
		    th_ctx->current->process == process_stream && th_ctx->current->context) {
			const struct stream *s = (const struct stream *)th_ctx->current->context;
			struct hlua *hlua = NULL;

			if (s) {
				if (s->hlua[0] && HLUA_IS_BUSY(s->hlua[0]))
					hlua = s->hlua[0];
				else if (s->hlua[1] && HLUA_IS_BUSY(s->hlua[1]))
					hlua = s->hlua[1];
			}
			if (hlua) {
				mark_tainted(TAINTED_LUA_STUCK);
				if (hlua->state_id == 0)
					mark_tainted(TAINTED_LUA_STUCK_SHARED);
			}
		}
#endif

		if (HA_ATOMIC_LOAD(&pool_trim_in_progress))
			mark_tainted(TAINTED_MEM_TRIMMING_STUCK);

		ha_dump_backtrace(buf, "             ", 0);
	}
 leave:
	/* end of dump, setting the buffer to 0x1 will tell the caller we're done */
	HA_ATOMIC_OR((ulong*)DISGUISE(&ha_thread_ctx[thr].thread_dump_buffer), 0x1UL);
}

/* Triggers a thread dump from thread <thr>, either directly if it's the
 * current thread or if thread dump signals are not implemented, or by sending
 * a signal if it's a remote one and the feature is supported. The buffer <buf>
 * will get the dump appended, and the caller is responsible for making sure
 * there is enough room otherwise some contents will be truncated. The function
 * waits for the called thread to fill the buffer before returning (or cancelling
 * by reporting NULL). It does not release the called thread yet. It returns a
 * pointer to the buffer used if the dump was done, otherwise NULL.
 */
struct buffer *ha_thread_dump_fill(struct buffer *buf, int thr)
{
	struct buffer *old = NULL;

	/* try to impose our dump buffer and to reserve the target thread's
	 * next dump for us.
	 */
	do {
		if (old)
			ha_thread_relax();
		old = NULL;
	} while (!HA_ATOMIC_CAS(&ha_thread_ctx[thr].thread_dump_buffer, &old, buf));

#ifdef USE_THREAD_DUMP
	/* asking the remote thread to dump itself allows to get more details
	 * including a backtrace.
	 */
	if (thr != tid)
		ha_tkill(thr, DEBUGSIG);
	else
#endif
		ha_thread_dump_one(thr, thr != tid);

	/* now wait for the dump to be done (or cancelled) */
	while (1) {
		old = HA_ATOMIC_LOAD(&ha_thread_ctx[thr].thread_dump_buffer);
		if ((ulong)old & 0x1)
			break;
		if (!old)
			return old;
		ha_thread_relax();
	}
	return (struct buffer *)((ulong)old & ~0x1UL);
}

/* Indicates to the called thread that the dumped data are collected by writing
 * <buf> into the designated thread's dump buffer (usually buf is NULL). It
 * waits for the dump to be completed if it was not the case, and can also
 * leave if the pointer is NULL (e.g. if a thread has aborted).
 */
void ha_thread_dump_done(struct buffer *buf, int thr)
{
	struct buffer *old;

	/* now wait for the dump to be done or cancelled, and release it */
	do {
		old = HA_ATOMIC_LOAD(&ha_thread_ctx[thr].thread_dump_buffer);
		if (!((ulong)old & 0x1)) {
			if (!old)
				return;
			ha_thread_relax();
			continue;
		}
	} while (!HA_ATOMIC_CAS(&ha_thread_ctx[thr].thread_dump_buffer, &old, buf));
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

	if (s) {
		chunk_appendf(buf, "%sstream=", pfx);
		strm_dump_to_buffer(buf, s, pfx, HA_ATOMIC_LOAD(&global.anon_key));
	}

#ifdef USE_LUA
	hlua = NULL;
	if (s && ((s->hlua[0] && HLUA_IS_BUSY(s->hlua[0])) ||
	    (s->hlua[1] && HLUA_IS_BUSY(s->hlua[1])))) {
		hlua = (s->hlua[0] && HLUA_IS_BUSY(s->hlua[0])) ? s->hlua[0] : s->hlua[1];
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
	}

	/* we may need to terminate the current line */
	if (*b_peek(buf, b_data(buf)-1) != '\n')
		b_putchr(buf, '\n');
#endif
}

/* This function dumps all profiling settings. It returns 0 if the output
 * buffer is full and it needs to be called again, otherwise non-zero.
 */
static int cli_io_handler_show_threads(struct appctx *appctx)
{
	int *thr = appctx->svcctx;

	if (!thr)
		thr = applet_reserve_svcctx(appctx, sizeof(*thr));

	do {
		chunk_reset(&trash);
		if (ha_thread_dump_fill(&trash, *thr)) {
			ha_thread_dump_done(NULL, *thr);
			if (applet_putchk(appctx, &trash) == -1) {
				/* failed, try again */
				return 0;
			}
		}
		(*thr)++;
	} while (*thr < global.nbthread);

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

/* parse a "show dev" command. It returns 1 if it emits anything otherwise zero. */
static int debug_parse_cli_show_dev(char **args, char *payload, struct appctx *appctx, void *private)
{
	const char **build_opt;
	char *err = NULL;
	int i;

	if (*args[2])
		return cli_err(appctx, "This command takes no argument.\n");

	chunk_reset(&trash);

	chunk_appendf(&trash, "HAProxy version %s\n", haproxy_version);
	chunk_appendf(&trash, "Features\n  %s\n", build_features);

	chunk_appendf(&trash, "Build options\n");
	for (build_opt = NULL; (build_opt = hap_get_next_build_opt(build_opt)); )
		if (append_prefixed_str(&trash, *build_opt, "  ", '\n', 0) == 0)
			chunk_strcat(&trash, "\n");

	chunk_appendf(&trash, "Platform info\n");
	if (*post_mortem.platform.hw_vendor)
		chunk_appendf(&trash, "  machine vendor: %s\n", post_mortem.platform.hw_vendor);
	if (*post_mortem.platform.hw_family)
		chunk_appendf(&trash, "  machine family: %s\n", post_mortem.platform.hw_family);
	if (*post_mortem.platform.hw_model)
		chunk_appendf(&trash, "  machine model: %s\n", post_mortem.platform.hw_model);
	if (*post_mortem.platform.brd_vendor)
		chunk_appendf(&trash, "  board vendor: %s\n", post_mortem.platform.brd_vendor);
	if (*post_mortem.platform.brd_model)
		chunk_appendf(&trash, "  board model: %s\n", post_mortem.platform.brd_model);
	if (*post_mortem.platform.soc_vendor)
		chunk_appendf(&trash, "  soc vendor: %s\n", post_mortem.platform.soc_vendor);
	if (*post_mortem.platform.soc_model)
		chunk_appendf(&trash, "  soc model: %s\n", post_mortem.platform.soc_model);
	if (*post_mortem.platform.cpu_model)
		chunk_appendf(&trash, "  cpu model: %s\n", post_mortem.platform.cpu_model);
	if (*post_mortem.platform.virt_techno)
		chunk_appendf(&trash, "  virtual machine: %s\n", post_mortem.platform.virt_techno);
	if (*post_mortem.platform.cont_techno)
		chunk_appendf(&trash, "  container: %s\n", post_mortem.platform.cont_techno);
	if (*post_mortem.platform.utsname.sysname)
		chunk_appendf(&trash, "  OS name: %s\n", post_mortem.platform.utsname.sysname);
	if (*post_mortem.platform.utsname.release)
		chunk_appendf(&trash, "  OS release: %s\n", post_mortem.platform.utsname.release);
	if (*post_mortem.platform.utsname.version)
		chunk_appendf(&trash, "  OS version: %s\n", post_mortem.platform.utsname.version);
	if (*post_mortem.platform.utsname.machine)
		chunk_appendf(&trash, "  OS architecture: %s\n", post_mortem.platform.utsname.machine);
	if (*post_mortem.platform.utsname.nodename)
		chunk_appendf(&trash, "  node name: %s\n", HA_ANON_CLI(post_mortem.platform.utsname.nodename));

	chunk_appendf(&trash, "Process info\n");
	chunk_appendf(&trash, "  pid: %d\n", post_mortem.process.pid);
	chunk_appendf(&trash, "  cmdline: ");
	for (i = 0; i < post_mortem.process.argc; i++)
		chunk_appendf(&trash, "%s ", post_mortem.process.argv[i]);
	chunk_appendf(&trash, "\n");
#if defined(USE_LINUX_CAP)
	/* let's dump saved in feed_post_mortem() initial capabilities sets */
	if(!post_mortem.process.caps.err_boot) {
		chunk_appendf(&trash, "  boot capabilities:\n");
		chunk_appendf(&trash, "  \tCapEff: 0x%016llx\n",
			      CAPS_TO_ULLONG(post_mortem.process.caps.boot[0].effective,
					     post_mortem.process.caps.boot[1].effective));
		chunk_appendf(&trash, "  \tCapPrm: 0x%016llx\n",
			      CAPS_TO_ULLONG(post_mortem.process.caps.boot[0].permitted,
					     post_mortem.process.caps.boot[1].permitted));
		chunk_appendf(&trash, "  \tCapInh: 0x%016llx\n",
			      CAPS_TO_ULLONG(post_mortem.process.caps.boot[0].inheritable,
					     post_mortem.process.caps.boot[1].inheritable));
	} else
		chunk_appendf(&trash, "  capget() failed at boot with: %s.\n",
			      errname(post_mortem.process.caps.err_boot, &err));

	/* let's print actual capabilities sets, could be useful in order to compare */
	if (!post_mortem.process.caps.err_run) {
		chunk_appendf(&trash, "  runtime capabilities:\n");
		chunk_appendf(&trash, "  \tCapEff: 0x%016llx\n",
			      CAPS_TO_ULLONG(post_mortem.process.caps.run[0].effective,
					     post_mortem.process.caps.run[1].effective));
		chunk_appendf(&trash, "  \tCapPrm: 0x%016llx\n",
			      CAPS_TO_ULLONG(post_mortem.process.caps.run[0].permitted,
					     post_mortem.process.caps.run[1].permitted));
		chunk_appendf(&trash, "  \tCapInh: 0x%016llx\n",
			      CAPS_TO_ULLONG(post_mortem.process.caps.run[0].inheritable,
					     post_mortem.process.caps.run[1].inheritable));
	} else
		chunk_appendf(&trash, "  capget() failed at runtime with: %s.\n",
			      errname(post_mortem.process.caps.err_run, &err));
#endif

	chunk_appendf(&trash, "  %-22s  %-11s  %-11s \n", "identity:", "-boot-", "-runtime-");
	chunk_appendf(&trash, "  %-22s  %-11d  %-11d \n", "    uid:", post_mortem.process.boot_uid,
		                                                      post_mortem.process.run_uid);
	chunk_appendf(&trash, "  %-22s  %-11d  %-11d \n", "    gid:", post_mortem.process.boot_gid,
		                                                      post_mortem.process.run_gid);
	chunk_appendf(&trash, "  %-22s  %-11s  %-11s \n", "limits:", "-boot-", "-runtime-");
	chunk_appendf(&trash, "  %-22s  %-11s  %-11s \n", "    fd limit (soft):",
		LIM2A(normalize_rlim((ulong)post_mortem.process.boot_lim_fd.rlim_cur), "unlimited"),
		LIM2A(normalize_rlim((ulong)post_mortem.process.run_lim_fd.rlim_cur), "unlimited"));
	chunk_appendf(&trash, "  %-22s  %-11s  %-11s \n", "    fd limit (hard):",
		LIM2A(normalize_rlim((ulong)post_mortem.process.boot_lim_fd.rlim_max), "unlimited"),
		LIM2A(normalize_rlim((ulong)post_mortem.process.run_lim_fd.rlim_max), "unlimited"));
	chunk_appendf(&trash, "  %-22s  %-11s  %-11s \n", "    ram limit (soft):",
		LIM2A(normalize_rlim((ulong)post_mortem.process.boot_lim_ram.rlim_cur), "unlimited"),
		LIM2A(normalize_rlim((ulong)post_mortem.process.run_lim_ram.rlim_cur), "unlimited"));
	chunk_appendf(&trash, "  %-22s  %-11s  %-11s \n", "    ram limit (hard):",
		LIM2A(normalize_rlim((ulong)post_mortem.process.boot_lim_ram.rlim_max), "unlimited"),
		LIM2A(normalize_rlim((ulong)post_mortem.process.run_lim_ram.rlim_max), "unlimited"));

	ha_free(&err);

	return cli_msg(appctx, LOG_INFO, trash.area);
}

/* Dumps a state of all threads into the trash and on fd #2, then aborts. */
void ha_panic()
{
	struct buffer *buf;
	unsigned int thr;

	if (mark_tainted(TAINTED_PANIC) & TAINTED_PANIC) {
		/* a panic dump is already in progress, let's not disturb it,
		 * we'll be called via signal DEBUGSIG. By returning we may be
		 * able to leave a current signal handler (e.g. WDT) so that
		 * this will ensure more reliable signal delivery.
		 */
		return;
	}

	chunk_printf(&trash, "Thread %u is about to kill the process.\n", tid + 1);
	DISGUISE(write(2, trash.area, trash.data));

	for (thr = 0; thr < global.nbthread; thr++) {
		if (thr == tid)
			buf = get_trash_chunk();
		else
			buf = (void *)0x2UL; // let the target thread allocate it

		buf = ha_thread_dump_fill(buf, thr);
		if (!buf)
			continue;

		DISGUISE(write(2, buf->area, buf->data));
		/* restore the thread's dump pointer for easier post-mortem analysis */
		ha_thread_dump_done(buf, thr);
	}

#ifdef USE_LUA
	if (get_tainted() & TAINTED_LUA_STUCK_SHARED && global.nbthread > 1) {
		chunk_printf(&trash,
			     "### Note: at least one thread was stuck in a Lua context loaded using the\n"
			     "          'lua-load' directive, which is known for causing heavy contention\n"
			     "          when used with threads. Please consider using 'lua-load-per-thread'\n"
			     "          instead if your code is safe to run in parallel on multiple threads.\n");
		DISGUISE(write(2, trash.area, trash.data));
	}
	else if (get_tainted() & TAINTED_LUA_STUCK) {
		chunk_printf(&trash,
			     "### Note: at least one thread was stuck in a Lua context in a way that suggests\n"
			     "          heavy processing inside a dependency or a long loop that can't yield.\n"
			     "          Please make sure any external code you may rely on is safe for use in\n"
			     "          an event-driven engine.\n");
		DISGUISE(write(2, trash.area, trash.data));
	}
#endif
	if (get_tainted() & TAINTED_MEM_TRIMMING_STUCK) {
		chunk_printf(&trash,
			     "### Note: one thread was found stuck under malloc_trim(), which can run for a\n"
			     "          very long time on large memory systems. You way want to disable this\n"
			     "          memory reclaiming feature by setting 'no-memory-trimming' in the\n"
			     "          'global' section of your configuration to avoid this in the future.\n");
		DISGUISE(write(2, trash.area, trash.data));
	}

	chunk_printf(&trash,
	             "\n"
	             "Hint: when reporting this bug to developers, please check if a core file was\n"
	             "      produced, open it with 'gdb', issue 't a a bt full', check that the\n"
	             "      output does not contain sensitive data, then join it with the bug report.\n"
	             "      For more info, please see https://github.com/haproxy/haproxy/issues/2374\n");

	DISGUISE(write(2, trash.area, trash.data));

	for (;;)
		abort();
}

/* Dumps a state of the current thread on fd #2 and returns. It takes a great
 * care about not using any global state variable so as to gracefully recover.
 */
void ha_stuck_warning(int thr)
{
	char msg_buf[4096];
	struct buffer buf;
	ullong n, p;

	if (mark_tainted(TAINTED_WARN_BLOCKED_TRAFFIC) & TAINTED_PANIC) {
		/* a panic dump is already in progress, let's not disturb it,
		 * we'll be called via signal DEBUGSIG. By returning we may be
		 * able to leave a current signal handler (e.g. WDT) so that
		 * this will ensure more reliable signal delivery.
		 */
		return;
	}

	HA_ATOMIC_INC(&warn_blocked_issued);

	buf = b_make(msg_buf, sizeof(msg_buf), 0, 0);

	p = HA_ATOMIC_LOAD(&ha_thread_ctx[thr].prev_cpu_time);
	n = now_cpu_time_thread(thr);

	chunk_printf(&buf,
		     "\nWARNING! thread %u has stopped processing traffic for %llu milliseconds\n"
		     "    with %d streams currently blocked, prevented from making any progress.\n"
		     "    While this may occasionally happen with inefficient configurations\n"
		     "    involving excess of regular expressions, map_reg, or heavy Lua processing,\n"
		     "    this must remain exceptional because the system's stability is now at risk.\n"
		     "    Timers in logs may be reported incorrectly, spurious timeouts may happen,\n"
		     "    some incoming connections may silently be dropped, health checks may\n"
		     "    randomly fail, and accesses to the CLI may block the whole process. The\n"
		     "    blocking delay before emitting this warning may be adjusted via the global\n"
		     "    'warn-blocked-traffic-after' directive. Please check the trace below for\n"
		     "    any clues about configuration elements that need to be corrected:\n\n",
		     thr + 1, (n - p) / 1000000ULL,
		     HA_ATOMIC_LOAD(&ha_thread_ctx[thr].stream_cnt));

	DISGUISE(write(2, buf.area, buf.data));

	/* Note below: the target thread will dump itself */
	chunk_reset(&buf);
	if (ha_thread_dump_fill(&buf, thr)) {
		DISGUISE(write(2, buf.area, buf.data));
		/* restore the thread's dump pointer for easier post-mortem analysis */
		ha_thread_dump_done(NULL, thr);
	}

#ifdef USE_LUA
	if (get_tainted() & TAINTED_LUA_STUCK_SHARED && global.nbthread > 1) {
		chunk_printf(&buf,
			     "### Note: at least one thread was stuck in a Lua context loaded using the\n"
			     "          'lua-load' directive, which is known for causing heavy contention\n"
			     "          when used with threads. Please consider using 'lua-load-per-thread'\n"
			     "          instead if your code is safe to run in parallel on multiple threads.\n");
		DISGUISE(write(2, buf.area, buf.data));
	}
	else if (get_tainted() & TAINTED_LUA_STUCK) {
		chunk_printf(&buf,
			     "### Note: at least one thread was stuck in a Lua context in a way that suggests\n"
			     "          heavy processing inside a dependency or a long loop that can't yield.\n"
			     "          Please make sure any external code you may rely on is safe for use in\n"
			     "          an event-driven engine.\n");
		DISGUISE(write(2, buf.area, buf.data));
	}
#endif
	if (get_tainted() & TAINTED_MEM_TRIMMING_STUCK) {
		chunk_printf(&buf,
			     "### Note: one thread was found stuck under malloc_trim(), which can run for a\n"
			     "          very long time on large memory systems. You way want to disable this\n"
			     "          memory reclaiming feature by setting 'no-memory-trimming' in the\n"
			     "          'global' section of your configuration to avoid this in the future.\n");
		DISGUISE(write(2, buf.area, buf.data));
	}

	chunk_printf(&buf, " => Trying to gracefully recover now.\n");
	DISGUISE(write(2, buf.area, buf.data));
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
	BUG_ON(one > zero, "This was triggered on purpose from the CLI 'debug dev bug' command.");
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
	WARN_ON(one > zero, "This was triggered on purpose from the CLI 'debug dev warn' command.");
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
	CHECK_IF(one > zero, "This was triggered on purpose from the CLI 'debug dev check' command.");
	return 1;
}

/* parse a "debug dev close" command. It always returns 1. */
static int debug_parse_cli_close(char **args, char *payload, struct appctx *appctx, void *private)
{
	int fd;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "Missing file descriptor number (optionally followed by 'hard').\n");

	fd = atoi(args[3]);
	if (fd < 0 || fd >= global.maxsock)
		return cli_err(appctx, "File descriptor out of range.\n");

	if (strcmp(args[4], "hard") == 0) {
		/* hard silent close, even for unknown FDs */
		close(fd);
		goto done;
	}
	if (!fdtab[fd].owner)
		return cli_msg(appctx, LOG_INFO, "File descriptor was already closed.\n");

	fd_delete(fd);
 done:
	_HA_ATOMIC_INC(&debug_commands_issued);
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
	int isolate;
	int warn;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	isolate = strcmp(args[4], "isolated") == 0;
	warn    = strcmp(args[4], "warn") == 0;

	_HA_ATOMIC_INC(&debug_commands_issued);
	gettimeofday(&curr, NULL);
	tv_ms_add(&deadline, &curr, loop);

	if (isolate)
		thread_isolate();

	while (tv_ms_cmp(&curr, &deadline) < 0) {
		if (warn)
			_HA_ATOMIC_AND(&th_ctx->flags, ~TH_FL_STUCK);
		gettimeofday(&curr, NULL);
	}

	if (isolate)
		thread_release();

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

/* handles SIGRTMAX to inject random delays on the receiving thread in order
 * to try to increase the likelihood to reproduce inter-thread races. The
 * signal is periodically sent by a task initiated by "debug dev delay-inj".
 */
void debug_delay_inj_sighandler(int sig, siginfo_t *si, void *arg)
{
	volatile int i = statistical_prng_range(10000);

	while (i--)
		__ha_cpu_relax();
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
			       "Usage: debug dev stream [ strm=<ptr> ] { <obj> <op> <value> | wake }*\n"
			       "     <obj>   = { strm.f | strm.x | scf.s | scb.s | txn.f | req.f | res.f }\n"
			       "     <op>    = {'' (show) | '=' (assign) | '^' (xor) | '+' (or) | '-' (andnot)}\n"
			       "     <value> = 'now' | 64-bit dec/hex integer (0x prefix supported)\n"
			       "     'wake' wakes the stream assigned to 'strm' (default: current)\n"
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

/* parse a "debug dev stream" command */
/*
 *  debug dev task <ptr> [ "wake" | "expire" | "kill" ]
 *  Show/change status of a task/tasklet
 */
static int debug_parse_cli_task(char **args, char *payload, struct appctx *appctx, void *private)
{
	const struct ha_caller *caller;
	struct task *t;
	char *endarg;
	char *msg;
	void *ptr;
	int ret = 1;
	int task_ok;
	int arg;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	/* parse the pointer value */
	ptr = (void *)strtoul(args[3], &endarg, 0);
	if (!*args[3] || *endarg)
		goto usage;

	_HA_ATOMIC_INC(&debug_commands_issued);

	/* everything below must run under thread isolation till reaching label "leave" */
	thread_isolate();

	/* struct tasklet is smaller than struct task and is sufficient to check
	 * the TASK_COMMON part.
	 */
	if (!may_access(ptr) || !may_access(ptr + sizeof(struct tasklet) - 1) ||
	    ((const struct tasklet *)ptr)->tid  < -1 ||
	    ((const struct tasklet *)ptr)->tid  >= (int)MAX_THREADS) {
		ret = cli_err(appctx, "The designated memory area doesn't look like a valid task/tasklet\n");
		goto leave;
	}

	t = ptr;
	caller = t->caller;
	msg = NULL;
	task_ok = may_access(ptr + sizeof(*t) - 1);

	chunk_reset(&trash);
	resolve_sym_name(&trash, NULL, (const void *)t->process);

	/* we need to be careful here because we may dump a freed task that's
	 * still in the pool cache, containing garbage in pointers.
	 */
	if (!*args[4]) {
		memprintf(&msg, "%s%p: %s state=%#x tid=%d process=%s ctx=%p calls=%d last=%s:%d intl=%d",
			  msg ? msg : "", t, (t->state & TASK_F_TASKLET) ? "tasklet" : "task",
			  t->state, t->tid, trash.area, t->context, t->calls,
			  caller && may_access(caller) && may_access(caller->func) && isalnum((uchar)*caller->func) ? caller->func : "0",
			  caller ? t->caller->line : 0,
			  (t->state & TASK_F_TASKLET) ? LIST_INLIST(&((const struct tasklet *)t)->list) : 0);

		if (task_ok && !(t->state & TASK_F_TASKLET))
			memprintf(&msg, "%s inrq=%d inwq=%d exp=%d nice=%d",
				  msg ? msg : "", task_in_rq(t), task_in_wq(t), t->expire, t->nice);

		memprintf(&msg, "%s\n", msg ? msg : "");
	}

	for (arg = 4; *args[arg]; arg++) {
		if (strcmp(args[arg], "expire") == 0) {
			if (t->state & TASK_F_TASKLET) {
				/* do nothing for tasklets */
			}
			else if (task_ok) {
				/* unlink task and wake with timer flag */
				__task_unlink_wq(t);
				t->expire = tick_add(now_ms, 0);
				task_wakeup(t, TASK_WOKEN_TIMER);
			}
		} else if (strcmp(args[arg], "wake") == 0) {
			/* wake with all flags but init / timer */
			if (t->state & TASK_F_TASKLET)
				tasklet_wakeup((struct tasklet *)t);
			else if (task_ok)
				task_wakeup(t, TASK_WOKEN_ANY & ~(TASK_WOKEN_INIT|TASK_WOKEN_TIMER));
		} else if (strcmp(args[arg], "kill") == 0) {
			/* Kill the task. This is not idempotent! */
			if (!(t->state & TASK_KILLED)) {
				if (t->state & TASK_F_TASKLET)
					tasklet_kill((struct tasklet *)t);
				else if (task_ok)
					task_kill(t);
			}
		} else {
			thread_release();
			goto usage;
		}
	}

	if (msg && *msg)
		ret = cli_dynmsg(appctx, LOG_INFO, msg);
 leave:
	thread_release();
	return ret;
 usage:
	return cli_err(appctx,
		       "Usage: debug dev task <ptr> [ wake | expire | kill ]\n"
		       "  By default, dumps some info on task/tasklet <ptr>. 'wake' will wake it up\n"
		       "  with all conditions flags but init/exp. 'expire' will expire the entry, and\n"
		       "  'kill' will kill it (warning: may crash since later not idempotent!). All\n"
		       "  changes may crash the process if performed on a wrong object!\n"
		       );
}

#if defined(DEBUG_DEV)
static struct task *debug_delay_inj_task(struct task *t, void *ctx, unsigned int state)
{
	unsigned long *tctx = ctx; // [0] = interval, [1] = nbwakeups
	unsigned long inter = tctx[0];
	unsigned long count = tctx[1];
	unsigned long rnd;

	if (inter)
		t->expire = tick_add(now_ms, inter);
	else
		task_wakeup(t, TASK_WOKEN_MSG);

	/* wake a random thread */
	while (count--) {
		rnd = statistical_prng_range(global.nbthread);
		ha_tkill(rnd, SIGRTMAX);
	}
	return t;
}

/* parse a "debug dev delay-inj" command
 * debug dev delay-inj <inter> <count>
 */
static int debug_parse_delay_inj(char **args, char *payload, struct appctx *appctx, void *private)
{
	unsigned long *tctx; // [0] = inter, [2] = count
	struct task *task;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[4])
		return cli_err(appctx,  "Usage: debug dev delay-inj <inter_ms> <count>*\n");

	_HA_ATOMIC_INC(&debug_commands_issued);

	tctx = calloc(2, sizeof(*tctx));
	if (!tctx)
		goto fail;

	tctx[0] = atoi(args[3]);
	tctx[1] = atoi(args[4]);

	task = task_new_here/*anywhere*/();
	if (!task)
		goto fail;

	task->process = debug_delay_inj_task;
	task->context = tctx;
	task_wakeup(task, TASK_WOKEN_INIT);
	return 1;

 fail:
	free(tctx);
	return cli_err(appctx, "Not enough memory");
}
#endif // DEBUG_DEV

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

	tctx = calloc(count + 2, sizeof(*tctx));
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

#if defined(DEBUG_DEV)
/* All of this is for "trace dbg" */

static struct trace_source trace_dbg __read_mostly = {
	.name = IST("dbg"),
	.desc = "trace debugger",
	.report_events = ~0,  // report everything by default
};

#define TRACE_SOURCE &trace_dbg
INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

/* This is the task handler used to send traces in loops. Note that the task's
 * context contains the number of remaining calls to be done. The task sends 20
 * messages per wakeup.
 */
static struct task *debug_trace_task(struct task *t, void *ctx, unsigned int state)
{
	ulong count;

	/* send 2 traces enter/leave +18 devel = 20 traces total */
	TRACE_ENTER(1);
	TRACE_DEVEL("msg01 has 20 bytes .", 1);
	TRACE_DEVEL("msg02 has 20 bytes .", 1);
	TRACE_DEVEL("msg03 has 20 bytes .", 1);
	TRACE_DEVEL("msg04 has 70 bytes payload: 0123456789 0123456789 0123456789 012345678", 1);
	TRACE_DEVEL("msg05 has 70 bytes payload: 0123456789 0123456789 0123456789 012345678", 1);
	TRACE_DEVEL("msg06 has 70 bytes payload: 0123456789 0123456789 0123456789 012345678", 1);
	TRACE_DEVEL("msg07 has 120 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 012", 1);
	TRACE_DEVEL("msg08 has 120 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 012", 1);
	TRACE_DEVEL("msg09 has 120 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 012", 1);
	TRACE_DEVEL("msg10 has 170 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 012345678", 1);
	TRACE_DEVEL("msg11 has 170 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 012345678", 1);
	TRACE_DEVEL("msg12 has 170 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 012345678", 1);
	TRACE_DEVEL("msg13 has 220 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123", 1);
	TRACE_DEVEL("msg14 has 220 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123", 1);
	TRACE_DEVEL("msg15 has 220 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123", 1);
	TRACE_DEVEL("msg16 has 270 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789", 1);
	TRACE_DEVEL("msg17 has 270 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789", 1);
	TRACE_DEVEL("msg18 has 270 bytes payload: 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789 0123456789", 1);
	TRACE_LEAVE(1);

	count = (ulong)t->context;
	t->context = (void*)count - 1;

	if (count)
		task_wakeup(t, TASK_WOKEN_MSG);
	else {
		task_destroy(t);
		t = NULL;
	}
	return t;
}

/* parse a "debug dev trace" command
 * debug dev trace <nbthr>.
 * It will create as many tasks (one per thread), starting from lowest threads.
 * The traces will stop after 1M wakeups or 20M messages ~= 4GB of data.
 */
static int debug_parse_cli_trace(char **args, char *payload, struct appctx *appctx, void *private)
{
	unsigned long count = 1;
	unsigned long i;
	char *msg = NULL;
	char *endarg;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	_HA_ATOMIC_INC(&debug_commands_issued);

	if (!args[3][0]) {
		memprintf(&msg, "Need a thread count. Note that 20M msg will be sent per thread.\n");
		goto fail;
	}

	/* parse the new value . */
	count = strtoll(args[3], &endarg, 0);
	if (args[3][1] && *endarg) {
		memprintf(&msg, "Ignoring unparsable thread number '%s'.\n", args[3]);
		goto fail;
	}

	if (count >= global.nbthread)
		count = global.nbthread;

	for (i = 0; i < count; i++) {
		struct task *task = task_new_on(i);

		if (!task)
			goto fail;

		task->process = debug_trace_task;
		task->context = (void*)(ulong)1000000; // 1M wakeups = 20M messages
		task_wakeup(task, TASK_WOKEN_INIT);
	}

	if (msg && *msg)
		return cli_dynmsg(appctx, LOG_INFO, msg);
	return 1;

 fail:
	return cli_dynmsg(appctx, LOG_ERR, msg);
}
#endif /* DEBUG_DEV */

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
	struct sockaddr_storage sa;
	struct stat statbuf;
	socklen_t salen, vlen;
	int ret1, ret2, port;
	char *addrstr;
	int ret = 1;
	int i, fd;

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
				      /* trick: epoll_ctl() will return -ENOENT when trying
				       * to remove from a valid epoll FD an FD that was not
				       * registered against it. But we don't want to risk
				       * disabling a random FD. Instead we'll create a new
				       * one by duplicating 0 (it should be valid since
				       * pointing to a terminal or /dev/null), and try to
				       * remove it.
				       */
				      ({
					      int fd2 = dup(0);
					      int ret = fd2;
					      if (ret >= 0) {
						      ret = epoll_ctl(fd, EPOLL_CTL_DEL, fd2, NULL);
						      if (ret == -1 && errno == ENOENT)
							      ret = 0; // that's a real epoll
						      else
							      ret = -1; // it's something else
						      close(fd2);
					      }
					      ret;
				      }) == 0 ? "epol" :
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
			int i;

			if (sa.ss_family == AF_INET)
				port = ntohs(((const struct sockaddr_in *)&sa)->sin_port);
			else if (sa.ss_family == AF_INET6)
				port = ntohs(((const struct sockaddr_in6 *)&sa)->sin6_port);
			else
				port = 0;
			addrstr = sa2str(&sa, port, 0);
			/* cleanup the output */
			for  (i = 0; i < strlen(addrstr); i++) {
				if (iscntrl((unsigned char)addrstr[i]) || !isprint((unsigned char)addrstr[i]))
					addrstr[i] = '.';
			}

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
			/* cleanup the output */
			for  (i = 0; i < strlen(addrstr); i++) {
				if ((iscntrl((unsigned char)addrstr[i])) || !isprint((unsigned char)addrstr[i]))
					addrstr[i] = '.';
			}
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
	return ret;
}

#if defined(DEBUG_MEM_STATS)

/* CLI state for "debug dev memstats" */
struct dev_mem_ctx {
	struct mem_stats *start, *stop; /* begin/end of dump */
	char *match;                    /* non-null if a name prefix is specified */
	int show_all;                   /* show all entries if non-null */
	int width;                      /* 1st column width */
	long tot_size;                  /* sum of alloc-free */
	ulong tot_calls;                /* sum of calls */
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
		else if (strcmp(args[arg], "match") == 0 && *args[arg + 1]) {
			ha_free(&ctx->match);
			ctx->match = strdup(args[arg + 1]);
			if (!ctx->match)
				return cli_err(appctx, "Out of memory.\n");
			arg++;
			continue;
		}
		else
			return cli_err(appctx, "Expects either 'reset', 'all', or 'match <pfx>'.\n");
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
	struct mem_stats *ptr;
	const char *pfx = ctx->match;
	int ret = 1;

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
		int direction = 0; // neither alloc nor free (e.g. realloc)

		if (!ptr->size && !ptr->calls && !ctx->show_all)
			continue;

		/* basename only */
		for (p = name = ptr->caller.file; *p; p++) {
			if (*p == '/')
				name = p + 1;
		}

		func = ptr->caller.func;

		switch (ptr->caller.what) {
		case MEM_STATS_TYPE_CALLOC:  type = "CALLOC";  direction =  1; break;
		case MEM_STATS_TYPE_FREE:    type = "FREE";    direction = -1; break;
		case MEM_STATS_TYPE_MALLOC:  type = "MALLOC";  direction =  1; break;
		case MEM_STATS_TYPE_REALLOC: type = "REALLOC"; break;
		case MEM_STATS_TYPE_STRDUP:  type = "STRDUP";  direction =  1; break;
		case MEM_STATS_TYPE_P_ALLOC: type = "P_ALLOC"; direction =  1; if (ptr->extra) info = ((const struct pool_head *)ptr->extra)->name; break;
		case MEM_STATS_TYPE_P_FREE:  type = "P_FREE";  direction = -1; if (ptr->extra) info = ((const struct pool_head *)ptr->extra)->name; break;
		default:                     type = "UNSET";   break;
		}

		//chunk_printf(&trash,
		//	     "%20s:%-5d %7s size: %12lu calls: %9lu size/call: %6lu\n",
		//	     name, ptr->line, type,
		//	     (unsigned long)ptr->size, (unsigned long)ptr->calls,
		//	     (unsigned long)(ptr->calls ? (ptr->size / ptr->calls) : 0));

		/* only match requested prefixes */
		if (pfx && (!info || strncmp(info, pfx, strlen(pfx)) != 0))
			continue;

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
			goto end;
		}
		if (direction > 0) {
			ctx->tot_size  += (ulong)ptr->size;
			ctx->tot_calls += (ulong)ptr->calls;
		}
		else if (direction < 0) {
			ctx->tot_size  -= (ulong)ptr->size;
			ctx->tot_calls += (ulong)ptr->calls;
		}
	}

	/* now dump a summary */
	chunk_reset(&trash);
	chunk_appendf(&trash, "Total");
	while (trash.data < ctx->width)
		trash.area[trash.data++] = ' ';

	chunk_appendf(&trash, "%7s  size: %12ld  calls: %9lu  size/call: %6ld %s\n",
		      "BALANCE",
		      ctx->tot_size, ctx->tot_calls,
		      (long)(ctx->tot_calls ? (ctx->tot_size / ctx->tot_calls) : 0),
		      "(excl. realloc)");

	if (applet_putchk(appctx, &trash) == -1) {
		ctx->start = ptr;
		ret = 0;
		goto end;
	}
 end:
	return ret;
}

/* release the "show pools" context */
static void debug_release_memstats(struct appctx *appctx)
{
	struct dev_mem_ctx *ctx = appctx->svcctx;

	ha_free(&ctx->match);
}
#endif

#if !defined(USE_OBSOLETE_LINKER)

/* CLI state for "debug counters" */
struct deb_cnt_ctx {
	struct debug_count *start, *stop; /* begin/end of dump */
	int types;                        /* OR mask of 1<<type */
	int show_all;                     /* show all entries if non-null */
};

/* CLI parser for the "debug counters" command. Sets a deb_cnt_ctx shown above. */
static int debug_parse_cli_counters(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct deb_cnt_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int action;
	int arg;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	action = 0; // 0=show, 1=reset
	for (arg = 2; *args[arg]; arg++) {
		if (strcmp(args[arg], "reset") == 0) {
			action = 1;
			continue;
		}
		else if (strcmp(args[arg], "all") == 0) {
			ctx->show_all = 1;
			continue;
		}
		else if (strcmp(args[arg], "show") == 0) {
			action = 0;
			continue;
		}
		else if (strcmp(args[arg], "bug") == 0) {
			ctx->types |= 1 << DBG_BUG;
			continue;
		}
		else if (strcmp(args[arg], "chk") == 0) {
			ctx->types |= 1 << DBG_BUG_ONCE;
			continue;
		}
		else if (strcmp(args[arg], "cnt") == 0) {
			ctx->types |= 1 << DBG_COUNT_IF;
			continue;
		}
		else if (strcmp(args[arg], "glt") == 0) {
			ctx->types |= 1 << DBG_GLITCH;
			continue;
		}
		else
			return cli_err(appctx, "Expects an optional action ('reset','show'), optional types ('bug','chk','cnt','glt') and optionally 'all' to even dump null counters.\n");
	}

#if DEBUG_STRICT > 0 || defined(DEBUG_GLITCHES)
	ctx->start = &__start_dbg_cnt;
	ctx->stop  = &__stop_dbg_cnt;
#endif
	if (action == 1) { // reset
		struct debug_count *ptr;

		if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
			return 1;

		for (ptr = ctx->start; ptr < ctx->stop; ptr++) {
			if (ctx->types && !(ctx->types & (1 << ptr->type)))
				continue;
			_HA_ATOMIC_STORE(&ptr->count, 0);
		}
		return 1;
	}

	/* OK it's a show, let's dump relevant counters */
	return 0;
}

/* CLI I/O handler for the "debug counters" command using a deb_cnt_ctx
 * found in appctx->svcctx. Dumps all mem_stats structs referenced by pointers
 * located between ->start and ->stop. Dumps all entries if ->show_all != 0,
 * otherwise only non-zero calls.
 */
static int debug_iohandler_counters(struct appctx *appctx)
{
	const char *bug_type[DBG_COUNTER_TYPES] = {
		[DBG_BUG]      = "BUG",
		[DBG_BUG_ONCE] = "CHK",
		[DBG_COUNT_IF] = "CNT",
		[DBG_GLITCH]   = "GLT",
	};
	struct deb_cnt_ctx *ctx = appctx->svcctx;
	struct debug_count *ptr;
	int ret = 1;

	/* we have two inner loops here, one for the proxy, the other one for
	 * the buffer.
	 */
	chunk_printf(&trash, "Count     Type Location function(): \"condition\" [comment]\n");
	for (ptr = ctx->start; ptr != ctx->stop; ptr++) {
		const char *p, *name;

		if (ctx->types && !(ctx->types & (1 << ptr->type)))
			continue;

		if (!ptr->count && !ctx->show_all)
			continue;

		for (p = name = ptr->file; *p; p++) {
			if (*p == '/')
				name = p + 1;
		}

		if (ptr->type < DBG_COUNTER_TYPES)
			chunk_appendf(&trash, "%-10u %3s %s:%d %s()%s%s\n",
				      ptr->count, bug_type[ptr->type],
				      name, ptr->line, ptr->func,
				      *ptr->desc ? ": " : "", ptr->desc);

		if (applet_putchk(appctx, &trash) == -1) {
			ctx->start = ptr;
			ret = 0;
			goto end;
		}
	}

	/* we could even dump a summary here if needed, returning ret=0 */
 end:
	return ret;
}
#endif /* USE_OBSOLETE_LINKER */

#ifdef USE_THREAD_DUMP

/* handles DEBUGSIG to dump the state of the thread it's working on. This is
 * appended at the end of thread_dump_buffer which must be protected against
 * reentrance from different threads (a thread-local buffer works fine). If
 * the buffer pointer is equal to 0x2, then it's a panic. The thread allocates
 * the buffer from its own trash chunks so that the contents remain visible in
 * the core, and it never returns.
 */
void debug_handler(int sig, siginfo_t *si, void *arg)
{
	struct buffer *buf = HA_ATOMIC_LOAD(&th_ctx->thread_dump_buffer);
	int no_return = 0;

	/* first, let's check it's really for us and that we didn't just get
	 * a spurious DEBUGSIG.
	 */
	if (!buf || (ulong)buf & 0x1UL)
		return;

	/* Special value 0x2 is used during panics and requires that the thread
	 * allocates its own dump buffer among its own trash buffers. The goal
	 * is that all threads keep a copy of their own dump.
	 */
	if ((ulong)buf == 0x2UL) {
		no_return = 1;
		buf = get_trash_chunk();
		HA_ATOMIC_STORE(&th_ctx->thread_dump_buffer, buf);
	}

	/* now dump the current state into the designated buffer, and indicate
	 * we come from a sig handler.
	 */
	ha_thread_dump_one(tid, 1);

	/* in case of panic, no return is planned so that we don't destroy
	 * the buffer's contents and we make sure not to trigger in loops.
	 */
	while (no_return)
		wait(NULL);
}

static int init_debug_per_thread()
{
	sigset_t set;

	/* unblock the DEBUGSIG signal we intend to use */
	sigemptyset(&set);
	sigaddset(&set, DEBUGSIG);
#if defined(DEBUG_DEV)
	sigaddset(&set, SIGRTMAX);
#endif
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

#if defined(DEBUG_DEV)
	sa.sa_handler = NULL;
	sa.sa_sigaction = debug_delay_inj_sighandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGRTMAX, &sa, NULL);
#endif
	return ERR_NONE;
}

REGISTER_POST_CHECK(init_debug);
REGISTER_PER_THREAD_INIT(init_debug_per_thread);

#endif /* USE_THREAD_DUMP */


static void feed_post_mortem_linux()
{
#if defined(__linux__)
	struct stat statbuf;
	FILE *file;

	/* DMI reports either HW or hypervisor, this allows to detect most VMs.
	 * On ARM the device-tree is often more precise for the model. Since many
	 * boards present "to be filled by OEM" or so in many fields, we dedup
	 * them as much as possible.
	 */
	if (read_line_to_trash("/sys/class/dmi/id/sys_vendor") > 0)
		strlcpy2(post_mortem.platform.hw_vendor, trash.area, sizeof(post_mortem.platform.hw_vendor));

	if (read_line_to_trash("/sys/class/dmi/id/product_family") > 0 &&
	    strcmp(trash.area, post_mortem.platform.hw_vendor) != 0)
		strlcpy2(post_mortem.platform.hw_family, trash.area, sizeof(post_mortem.platform.hw_family));

	if ((read_line_to_trash("/sys/class/dmi/id/product_name") > 0 &&
	     strcmp(trash.area, post_mortem.platform.hw_vendor) != 0 &&
	     strcmp(trash.area, post_mortem.platform.hw_family) != 0))
		strlcpy2(post_mortem.platform.hw_model, trash.area, sizeof(post_mortem.platform.hw_model));

	if ((read_line_to_trash("/sys/class/dmi/id/board_vendor") > 0 &&
	     strcmp(trash.area, post_mortem.platform.hw_vendor) != 0))
		strlcpy2(post_mortem.platform.brd_vendor, trash.area, sizeof(post_mortem.platform.brd_vendor));

	if ((read_line_to_trash("/sys/firmware/devicetree/base/model") > 0 &&
	     strcmp(trash.area, post_mortem.platform.brd_vendor) != 0 &&
	     strcmp(trash.area, post_mortem.platform.hw_vendor) != 0 &&
	     strcmp(trash.area, post_mortem.platform.hw_family) != 0 &&
	     strcmp(trash.area, post_mortem.platform.hw_model) != 0) ||
	    (read_line_to_trash("/sys/class/dmi/id/board_name") > 0 &&
	     strcmp(trash.area, post_mortem.platform.brd_vendor) != 0 &&
	     strcmp(trash.area, post_mortem.platform.hw_vendor) != 0 &&
	     strcmp(trash.area, post_mortem.platform.hw_family) != 0 &&
	     strcmp(trash.area, post_mortem.platform.hw_model) != 0))
		strlcpy2(post_mortem.platform.brd_model, trash.area, sizeof(post_mortem.platform.brd_model));

	/* Check for containers. In a container on linux we don't see keventd (2.4) kthreadd (2.6+) on pid 2 */
	if (read_line_to_trash("/proc/2/status") <= 0 ||
	    (strcmp(trash.area, "Name:\tkthreadd") != 0 &&
	     strcmp(trash.area, "Name:\tkeventd") != 0)) {
		/* OK we're in a container. Docker often has /.dockerenv */
		const char *tech = "yes";

		if (stat("/.dockerenv", &statbuf) == 0)
			tech = "docker";
		strlcpy2(post_mortem.platform.cont_techno, tech, sizeof(post_mortem.platform.cont_techno));
	}
	else {
		strlcpy2(post_mortem.platform.cont_techno, "no", sizeof(post_mortem.platform.cont_techno));
	}

	file = fopen("/proc/cpuinfo", "r");
	if (file) {
		uint cpu_implem = 0, cpu_arch = 0, cpu_variant = 0, cpu_part = 0, cpu_rev = 0; // arm
		uint cpu_family = 0, model = 0, stepping = 0;                                  // x86
		char vendor_id[64] = "", model_name[64] = "";                                  // x86
		char machine[64] = "", system_type[64] = "", cpu_model[64] = "";               // mips
		const char *virt = "no";
		char *p, *e, *v, *lf;

		/* let's figure what CPU we're working with */
		while ((p = fgets(trash.area, trash.size, file)) != NULL) {
			lf = strchr(p, '\n');
			if (lf)
				*lf = 0;

			/* stop at first line break */
			if (!*p)
				break;

			/* skip colon and spaces and trim spaces after name */
			v = e = strchr(p, ':');
			if (!e)
				continue;

			do { *e-- = 0; } while (e >= p && (*e == ' ' || *e == '\t'));

			/* locate value after colon */
			do { v++; } while (*v == ' ' || *v == '\t');

			/* ARM */
			if (strcmp(p, "CPU implementer") == 0)
				cpu_implem = strtoul(v, NULL, 0);
			else if (strcmp(p, "CPU architecture") == 0)
				cpu_arch = strtoul(v, NULL, 0);
			else if (strcmp(p, "CPU variant") == 0)
				cpu_variant = strtoul(v, NULL, 0);
			else if (strcmp(p, "CPU part") == 0)
				cpu_part = strtoul(v, NULL, 0);
			else if (strcmp(p, "CPU revision") == 0)
				cpu_rev = strtoul(v, NULL, 0);

			/* x86 */
			else if (strcmp(p, "cpu family") == 0)
				cpu_family = strtoul(v, NULL, 0);
			else if (strcmp(p, "model") == 0)
				model = strtoul(v, NULL, 0);
			else if (strcmp(p, "stepping") == 0)
				stepping = strtoul(v, NULL, 0);
			else if (strcmp(p, "vendor_id") == 0)
				strlcpy2(vendor_id, v, sizeof(vendor_id));
			else if (strcmp(p, "model name") == 0)
				strlcpy2(model_name, v, sizeof(model_name));
			else if (strcmp(p, "flags") == 0) {
				if (strstr(v, "hypervisor")) {
					if (strncmp(post_mortem.platform.hw_vendor, "QEMU", 4) == 0)
						virt = "qemu";
					else if (strncmp(post_mortem.platform.hw_vendor, "VMware", 6) == 0)
						virt = "vmware";
					else
						virt = "yes";
				}
			}

			/* MIPS */
			else if (strcmp(p, "system type") == 0)
				strlcpy2(system_type, v, sizeof(system_type));
			else if (strcmp(p, "machine") == 0)
				strlcpy2(machine, v, sizeof(machine));
			else if (strcmp(p, "cpu model") == 0)
				strlcpy2(cpu_model, v, sizeof(cpu_model));
		}
		fclose(file);

		/* Machine may replace hw_product on MIPS */
		if (!*post_mortem.platform.hw_model)
			strlcpy2(post_mortem.platform.hw_model, machine, sizeof(post_mortem.platform.hw_model));

		/* SoC vendor */
		strlcpy2(post_mortem.platform.soc_vendor, vendor_id, sizeof(post_mortem.platform.soc_vendor));

		/* SoC model */
		if (*system_type) {
			/* MIPS */
			strlcpy2(post_mortem.platform.soc_model, system_type, sizeof(post_mortem.platform.soc_model));
			*system_type = 0;
		} else if (*model_name) {
			/* x86 */
			strlcpy2(post_mortem.platform.soc_model, model_name, sizeof(post_mortem.platform.soc_model));
			*model_name = 0;
		}

		/* Create a CPU model name based on available IDs */
		if (cpu_implem) // arm
			snprintf(cpu_model + strlen(cpu_model),
				 sizeof(cpu_model) - strlen(cpu_model),
				 "%sImpl %#02x", *cpu_model ? " " : "", cpu_implem);

		if (cpu_family) // x86
			snprintf(cpu_model + strlen(cpu_model),
				 sizeof(cpu_model) - strlen(cpu_model),
				 "%sFam %u", *cpu_model ? " " : "", cpu_family);

		if (model) // x86
			snprintf(cpu_model + strlen(cpu_model),
				 sizeof(cpu_model) - strlen(cpu_model),
				 "%sModel %u", *cpu_model ? " " : "", model);

		if (stepping) // x86
			snprintf(cpu_model + strlen(cpu_model),
				 sizeof(cpu_model) - strlen(cpu_model),
				 "%sStep %u", *cpu_model ? " " : "", stepping);

		if (cpu_arch) // arm
			snprintf(cpu_model + strlen(cpu_model),
				 sizeof(cpu_model) - strlen(cpu_model),
				 "%sArch %u", *cpu_model ? " " : "", cpu_arch);

		if (cpu_part) // arm
			snprintf(cpu_model + strlen(cpu_model),
				 sizeof(cpu_model) - strlen(cpu_model),
				 "%sPart %#03x", *cpu_model ? " " : "", cpu_part);

		if (cpu_variant || cpu_rev) // arm
			snprintf(cpu_model + strlen(cpu_model),
				 sizeof(cpu_model) - strlen(cpu_model),
				 "%sr%up%u", *cpu_model ? " " : "", cpu_variant, cpu_rev);

		strlcpy2(post_mortem.platform.cpu_model, cpu_model, sizeof(post_mortem.platform.cpu_model));

		if (*virt)
			strlcpy2(post_mortem.platform.virt_techno, virt, sizeof(post_mortem.platform.virt_techno));
	}
#endif // __linux__
}

static int feed_post_mortem()
{
	/* write an easily identifiable magic at the beginning of the struct */
	strncpy(post_mortem.post_mortem_magic,
		"POST-MORTEM STARTS HERE+7654321\0",
		sizeof(post_mortem.post_mortem_magic));
	/* kernel type, version and arch */
	uname(&post_mortem.platform.utsname);

	/* some boot-time info related to the process */
	post_mortem.process.pid = getpid();
	post_mortem.process.boot_uid = geteuid();
	post_mortem.process.boot_gid = getegid();
	post_mortem.process.argc = global.argc;
	post_mortem.process.argv = global.argv;

#if defined(USE_LINUX_CAP)
	if (capget(&cap_hdr_haproxy, post_mortem.process.caps.boot) == -1)
		post_mortem.process.caps.err_boot = errno;
#endif
	post_mortem.process.boot_lim_fd.rlim_cur = rlim_fd_cur_at_boot;
	post_mortem.process.boot_lim_fd.rlim_max = rlim_fd_max_at_boot;
	getrlimit(RLIMIT_DATA, &post_mortem.process.boot_lim_ram);

	if (strcmp(post_mortem.platform.utsname.sysname, "Linux") == 0)
		feed_post_mortem_linux();

#if defined(HA_HAVE_DUMP_LIBS)
	chunk_reset(&trash);
	if (dump_libs(&trash, 1))
		post_mortem.libs = strdup(trash.area);
#endif

	post_mortem.tgroup_info = ha_tgroup_info;
	post_mortem.thread_info = ha_thread_info;
	post_mortem.tgroup_ctx  = ha_tgroup_ctx;
	post_mortem.thread_ctx  = ha_thread_ctx;
	post_mortem.pools = &pools;
	post_mortem.proxies = &proxies_list;
	post_mortem.global = &global;
	post_mortem.fdtab = &fdtab;
	post_mortem.activity = activity;

	return ERR_NONE;
}

REGISTER_POST_CHECK(feed_post_mortem);

static void deinit_post_mortem(void)
{
	int comp;

#if defined(HA_HAVE_DUMP_LIBS)
	ha_free(&post_mortem.libs);
#endif
	for (comp = 0; comp < post_mortem.nb_components; comp++) {
		free(post_mortem.components[comp].toolchain);
		free(post_mortem.components[comp].toolchain_opts);
		free(post_mortem.components[comp].build_settings);
		free(post_mortem.components[comp].path);
	}
	ha_free(&post_mortem.components);
}

REGISTER_POST_DEINIT(deinit_post_mortem);

/* Appends a component to the list of post_portem info. May silently fail
 * on allocation errors but we don't care since the goal is to provide info
 * we have in case it helps.
 */
void post_mortem_add_component(const char *name, const char *version,
			       const char *toolchain, const char *toolchain_opts,
			       const char *build_settings, const char *path)
{
	struct post_mortem_component *comp;
	int nbcomp = post_mortem.nb_components;

	comp = realloc(post_mortem.components, (nbcomp + 1) * sizeof(*comp));
	if (!comp)
		return;

	memset(&comp[nbcomp], 0, sizeof(*comp));
	strlcpy2(comp[nbcomp].name, name, sizeof(comp[nbcomp].name));
	strlcpy2(comp[nbcomp].version, version, sizeof(comp[nbcomp].version));
	comp[nbcomp].toolchain      = strdup(toolchain);
	comp[nbcomp].toolchain_opts = strdup(toolchain_opts);
	comp[nbcomp].build_settings = strdup(build_settings);
	comp[nbcomp].path = strdup(path);

	post_mortem.nb_components++;
	post_mortem.components = comp;
}

#ifdef USE_THREAD
/* init code is called one at a time so let's collect all per-thread info on
 * the last starting thread. These info are not critical anyway and there's no
 * problem if we get them slightly late.
 */
static int feed_post_mortem_late()
{
	static int per_thread_info_collected;

	if (HA_ATOMIC_ADD_FETCH(&per_thread_info_collected, 1) != global.nbthread)
		return 1;

	/* also set runtime process settings. At this stage we are sure, that all
	 * config options and limits adjustments are successfully applied.
	 */
	post_mortem.process.run_uid = geteuid();
	post_mortem.process.run_gid = getegid();
#if defined(USE_LINUX_CAP)
	if (capget(&cap_hdr_haproxy, post_mortem.process.caps.run) == -1) {
		post_mortem.process.caps.err_run = errno;
	}
#endif
	getrlimit(RLIMIT_NOFILE, &post_mortem.process.run_lim_fd);
	getrlimit(RLIMIT_DATA, &post_mortem.process.run_lim_ram);

	return 1;
}

REGISTER_PER_THREAD_INIT(feed_post_mortem_late);
#endif

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
#if !defined(USE_OBSOLETE_LINKER)
	{{ "debug", "counters", NULL },        "debug counters [?|all|bug|cnt|chk|glt]* : dump/reset rare event counters",          debug_parse_cli_counters, debug_iohandler_counters, NULL, NULL, 0 },
#endif
	{{ "debug", "dev", "bug", NULL },      "debug dev bug                           : call BUG_ON() and crash",                 debug_parse_cli_bug,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "check", NULL },    "debug dev check                         : call CHECK_IF() and possibly crash",      debug_parse_cli_check, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "close", NULL },    "debug dev close  <fd> [hard]            : close this file descriptor",              debug_parse_cli_close, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "deadlock", NULL }, "debug dev deadlock [nbtask]             : deadlock between this number of tasks",   debug_parse_cli_deadlock, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "delay", NULL },    "debug dev delay  [ms]                   : sleep this long",                         debug_parse_cli_delay, NULL, NULL, NULL, ACCESS_EXPERT },
#if defined(DEBUG_DEV)
	{{ "debug", "dev", "delay-inj", NULL },"debug dev delay-inj <inter> <count>     : inject random delays into threads",       debug_parse_delay_inj, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "exec",  NULL },    "debug dev exec   [cmd] ...              : show this command's output",              debug_parse_cli_exec,  NULL, NULL, NULL, ACCESS_EXPERT },
#endif
	{{ "debug", "dev", "fd", NULL },       "debug dev fd                            : scan for rogue/unhandled FDs",            debug_parse_cli_fd,    debug_iohandler_fd, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "exit",  NULL },    "debug dev exit   [code]                 : immediately exit the process",            debug_parse_cli_exit,  NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "hash", NULL },     "debug dev hash   [msg]                  : return msg hashed if anon is set",        debug_parse_cli_hash,  NULL, NULL, NULL, 0 },
	{{ "debug", "dev", "hex",   NULL },    "debug dev hex    <addr> [len]           : dump a memory area",                      debug_parse_cli_hex,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "log",   NULL },    "debug dev log    [msg] ...              : send this msg to global logs",            debug_parse_cli_log,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "loop",  NULL },    "debug dev loop   <ms> [isolated|warn]   : loop this long, possibly isolated",       debug_parse_cli_loop,  NULL, NULL, NULL, ACCESS_EXPERT },
#if defined(DEBUG_MEM_STATS)
	{{ "debug", "dev", "memstats", NULL }, "debug dev memstats [reset|all|match ...]: dump/reset memory statistics",            debug_parse_cli_memstats, debug_iohandler_memstats, debug_release_memstats, NULL, 0 },
#endif
	{{ "debug", "dev", "panic", NULL },    "debug dev panic                         : immediately trigger a panic",             debug_parse_cli_panic, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "sched", NULL },    "debug dev sched  {task|tasklet} [k=v]*  : stress the scheduler",                    debug_parse_cli_sched, NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "stream",NULL },    "debug dev stream [k=v]*                 : show/manipulate stream flags",            debug_parse_cli_stream,NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "sym",   NULL },    "debug dev sym    <addr>                 : resolve symbol address",                  debug_parse_cli_sym,   NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "task",  NULL },    "debug dev task <ptr> [wake|expire|kill] : show/wake/expire/kill task/tasklet",      debug_parse_cli_task,  NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "tkill", NULL },    "debug dev tkill  [thr] [sig]            : send signal to thread",                   debug_parse_cli_tkill, NULL, NULL, NULL, ACCESS_EXPERT },
#if defined(DEBUG_DEV)
	{{ "debug", "dev", "trace", NULL },    "debug dev trace [nbthr]                 : flood traces from that many threads",     debug_parse_cli_trace,  NULL, NULL, NULL, ACCESS_EXPERT },
#endif
	{{ "debug", "dev", "warn",  NULL },    "debug dev warn                          : call WARN_ON() and possibly crash",       debug_parse_cli_warn,  NULL, NULL, NULL, ACCESS_EXPERT },
	{{ "debug", "dev", "write", NULL },    "debug dev write  [size]                 : write that many bytes in return",         debug_parse_cli_write, NULL, NULL, NULL, ACCESS_EXPERT },

	{{ "show", "dev", NULL, NULL },        "show dev                                : show debug info for developers",          debug_parse_cli_show_dev, NULL, NULL },
#if defined(HA_HAVE_DUMP_LIBS)
	{{ "show", "libs", NULL, NULL },       "show libs                               : show loaded object files and libraries", debug_parse_cli_show_libs, NULL, NULL },
#endif
	{{ "show", "threads", NULL, NULL },    "show threads                            : show some threads debugging information", NULL, cli_io_handler_show_threads, NULL },
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
