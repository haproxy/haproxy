#include <openssl/ssl.h>

#include <haproxy/api.h>
#include <haproxy/chunk.h>
#include <haproxy/dynbuf.h>
#include <haproxy/errors.h>
#include <haproxy/fcgi-app.h>
#include <haproxy/fcgi-app-t.h>
#include <haproxy/filters.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/haload.h>
#include <haproxy/proxy.h>
#include <haproxy/task.h>
#include <haproxy/trace.h>
#include <haproxy/protocol.h>
#include <haproxy/quic_tp.h>
#include <haproxy/server.h>
#include <haproxy/session.h>
#include <haproxy/stats.h>
#include <haproxy/stconn.h>
#include <haproxy/stream.h>
#include <haproxy/tools.h>

/* haload stream state flags */
#define HLD_STRM_ST_IN_ALLOC     0x0001
#define HLD_STRM_ST_OUT_ALLOC    0x0002
#define HLD_STRM_ST_CONN_ERR     0x0004
#define HLD_STRM_ST_HDRS_SENT    0x0008
#define HLD_STRM_ST_REQ_TO_BUILD 0x0010
#define HLD_STRM_ST_MUST_RECV    0x0020
#define HLD_STRM_ST_GOT_RESP_SL  0x0040

static inline struct hld_usr *hld_new_usr(int nreqs, int tid);
static void hld_report_percentiles(void);
static void hld_dealloc_thrs_info(void);

/* not declared in any header */
extern struct flt_ops fcgi_flt_ops;

struct hld_mtask {
	struct task *t;
	unsigned int show_time;
} mtask;

struct hld_freq_ctr {
	uint32_t curr_sec; /* start date of current period (seconds from now.tv_sec) */
	uint32_t curr_ctr; /* cumulated value for current period */
	uint32_t prev_ctr; /* value for last period */

};

struct hld_thr_info {
	struct timeval now;          // current time
	struct hld_freq_ctr req_rate;    // thread's measured request rate
	struct hld_freq_ctr conn_rate;   // thread's measured connection rate
	int err_ramp_gen;            // last -ee generation seen by this thread
	uint32_t cur_req;            // number of active requests
	uint32_t curconn;            // number of active connections
	uint32_t curusrs;            // number of active users
	uint32_t maxusrs;            // max number of users
	uint64_t tot_conn;           // total conns attempted on this thread
	uint64_t tot_done;           // total successful requests finished
	uint64_t tot_probe_done;     // successes from users created during the current -ee ramp
	uint64_t tot_rcvd;           // total bytes received on this thread
	uint64_t tot_perr;           // total protocol errors on this thread
	uint64_t tot_fbs;            // total number of ttfb samples
	uint64_t tot_ttfb;           // total time-to-first-byte (us)
	uint64_t tot_lbs;            // total number of ttlb samples
	uint64_t tot_ttlb;           // total time-to-last-byte (us)
	uint64_t *ttfb_pct;          // counts per ttfb value for percentile
	uint64_t *ttlb_pct;          // counts per ttlb value for percentile
	uint64_t tot_sc[5];          // total status codes on this thread: 1xx,2xx,3xx,4xx,5xx
	uint64_t vtot_sc[HLD_PROTO_MAX][5]; // by protocol total status codes
	                                       // on this thread: 1xx,2xx,3xx,4xx,5xx
	struct task *rate_task;      // task used when <arg_rate> is set
	__attribute__((aligned(64))) union { } __pad;
};

/* User flags */
#define HLD_USR_FL_STOP  0x00000001 // this user must stop sending requests

/* one cookie held by a user, name and value are owned copies (see
 * istdup()): the HTX buffer they were read from is reused right after.
 */
struct hld_cookie {
	struct ist name;
	struct ist value;
	struct list list;
};

struct hld_usr {
	struct task *task;
	struct session *sess;
	struct list strms;
	struct list cookies;   // cookies set by the server so far, struct hld_cookie
	struct hld_url *urls;
	struct hld_url *cur_url;
	int nreqs;
	int flags;
	int ramp_gen;          // err_ramp_gen at creation time, see hldstream_htx_buf_rcv()
};

struct hld_thr_info *thrs_info;

struct list hld_hdrs = LIST_HEAD_INIT(hld_hdrs);
struct proxy hld_proxy;

const char *arg_host;
const char *arg_conn_hdr;
const char *arg_uri;
const char *arg_path;

int arg_accu;          // more accurate req/time measurements in keep-alive
int arg_dura;          // test duration in sec if non-nul
int arg_fast;          // merge send with connect's ACK
int arg_hscd;          // HTTP status code distribution
int arg_long;          // long output format; 2=raw values
int arg_mreqs = 1;     // max concurrent streams by connection
int arg_pctl;          // report ttfb/ttlb percentiles at the end
int arg_post_sz;       // number of bytes to POST
int arg_rate;          // connection & request rate limit
int arg_rcon = -1;     // max requests per conn
int arg_reqs = -1;     // max total requests
int arg_serr;          // 1 = stop on first error (-e), 2 = probe and ramp (-ee)
int arg_slow;          // slow start: delay in milliseconds
int arg_thnk;          // think time after a reponse (ms)
int arg_thrd;          // number of threads
int arg_usr = 1;       // number of users
int arg_wait = 10000;  // I/O time out (ms)

int all_usr_stop_asap; // all users must stop as soon as possible
int usr_tid;
int usr_cnt;           // user counter incremented by <mtask> main task
int running_tasks;     // tasks counter for the users and for the conn rate
unsigned int hld_proto_flags; // flags to identify the protocols used

char *hld_args[MAX_LINE_ARGS + 1];

#define HLD_POST_DATA_SZ       16384 // bytes
#define HLD_POST_DATA_LINE_SZ     50 // bytes
static char hld_post_data[HLD_POST_DATA_SZ];

volatile unsigned long global_req; // global (started) req counter to sync user tasks.

/************ time manipulation functions ***************/

struct timeval hld_start_date, hld_stop_date, hld_now;
volatile uint32_t throttle = 0;  // pass to mul32hi() if not null.

/* -ee (probe-and-ramp on error) state */
#define HLD_EE_SUCCESS_PER_URL 100      // successes needed per URL before going back to normal load
static struct timeval hld_err_date;     // when the -ee probe/ramp last started
static int err_ramp_pending;            // guard: only one ramp can run at a time
static int err_ramp_active;             // 1 while the ramp is running
static int err_ramp_gen;                // goes up each time -ee triggers again
static int err_ramp_step;               // current step, moves up only after a real success
static uint64_t err_ramp_ok_base;       // success count as of the last step
static int err_rate_floor;              // 1 conn/req per sec, per URL
static int err_rate_target;             // 0 = no limit before, >0 = the old -R value
static uint64_t err_success_target;     // successes needed before going back to normal load
static int hld_reset_summary_baseline;  // tells hld_summary() to reset its own counters
static int hld_nb_url_cfg;              // number of target URLs, set once in hld_init()

/* unsigned 16-bit float, used as a compact histogram bucket for -P:
 *    b15..b11 = 5-bit exponent
 *    b10..b0  = 11-bit mantissa
 * Values 0..2047 are all distinct (no rounding below 2048). Values up
 * to about 2^42 keep some precision. Above that, everything maps to
 * the same, highest bucket.
 */
typedef uint16_t uf16_t;

/* timeval is not set */
#define TV_UNSET ((struct timeval){ .tv_sec = 0, .tv_usec = ~0 })

/* make a timeval from <sec>, <usec> */
static inline struct timeval tv_set(time_t sec, suseconds_t usec)
{
	struct timeval ret = { .tv_sec = sec, .tv_usec = usec };
	return ret;
}

/* used to unset a timeout */
static inline struct timeval tv_unset(void)
{
	return tv_set(0, ~0);
}

/* returns the interval in microseconds, which must be set */
static inline uint64_t tv_us(const struct timeval tv)
{
	return tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
}

/* returns the delay between <past> and <now> or zero if <past> is after <now> */
static inline struct timeval tv_diff(const struct timeval *past, const struct timeval *now)
{
	struct timeval ret = { .tv_sec = 0, .tv_usec = 0 };

	if (tv_isbefore(past, now)) {
		ret.tv_sec  = now->tv_sec  - past->tv_sec;
		ret.tv_usec = now->tv_usec - past->tv_usec;

		if ((signed)ret.tv_usec < 0) { // overflow
			ret.tv_usec += 1000000;
			ret.tv_sec  -= 1;
		}
	}
	return ret;
}

/* builds a uf16 from an exponent and a mantissa */
static inline uf16_t uf16(uint8_t e, uint16_t m)
{
	return ((uf16_t)e << 11) + m;
}

/* converts any value between 0 and 2^42 to a uf16 bucket */
static inline uf16_t to_uf16(uint64_t v)
{
	uint64_t max = (uint64_t)0x7FF << 31;
	int8_t e;

	v = (v <= max) ? v : max;
	e = __builtin_clzl(v) ^ 63;
	e -= 10;
	if (e < 0)
		e = 0;
	v >>= e;
	return uf16(e, v);
}

/* converts a uf16 bucket back to the value it represents */
static inline uint64_t from_uf16(uf16_t u)
{
	return (uint64_t)(u & 0x7FF) << (u >> 11);
}

/* read a freq counter over a 1-second period and return the event rate/s */
uint32_t hdl_read_freq_ctr(struct hld_freq_ctr *ctr, const struct timeval now)
{
	uint32_t curr, past;
	uint32_t age;

	age = now.tv_sec - ctr->curr_sec;
	if (age > 1)
		return 0;

	curr = 0;
	past = ctr->curr_ctr;
	if (!age) {
		curr = past;
		past = ctr->prev_ctr;
	}

	if (past <= 1 && !curr)
		return past; /* very low rate, avoid flapping */

	return curr + mul32hi(past, (unsigned)(999999 - now.tv_usec) * 4294U);
}

/* returns the number of remaining events that can occur on this freq counter
 * while respecting <freq> and taking into account that <pend> events are
 * already known to be pending. Returns 0 if limit was reached.
 */
uint32_t hld_freq_ctr_remain(struct hld_freq_ctr *ctr, uint32_t freq,
                             uint32_t pend, const struct timeval now)
{
	uint32_t curr, past;
	uint32_t age;

	curr = 0;
	age = now.tv_sec - ctr->curr_sec;

	if (age <= 1) {
		past = ctr->curr_ctr;
		if (!age) {
			curr = past;
			past = ctr->prev_ctr;
		}
		curr += mul32hi(past, (unsigned)(999999 - now.tv_usec) * 4294U);
	}
	curr += pend;

	if (curr >= freq)
		return 0;
	return freq - curr;
}

/* return the expected wait time in ms before the next event may occur,
 * respecting frequency <freq>, and assuming there may already be some pending
 * events. It returns zero if we can proceed immediately, otherwise the wait
 * time, which will be rounded down 1ms for better accuracy, with a minimum
 * of one ms.
 */
uint32_t hld_next_event_delay(struct hld_freq_ctr *ctr, uint32_t freq,
                              uint32_t pend, const struct timeval now)
{
	uint32_t curr, past;
	uint32_t wait, age;

	past = 0;
	curr = 0;
	age = now.tv_sec - ctr->curr_sec;

	if (age <= 1) {
		past = ctr->curr_ctr;
		if (!age) {
			curr = past;
			past = ctr->prev_ctr;
		}
		curr += mul32hi(past, (unsigned)(999999 - now.tv_usec) * 4294U);
	}
	curr += pend;

	if (curr < freq)
		return 0;

	/* too many events already, let's count how long to wait before they're
	 * processed.
	 */
	curr = curr - freq; // number of events left after current period

	/* each events takes 1/freq second or 1000/freq ms */

	wait = curr * 1000 / freq;
	if (!wait)
		wait = 1;
	return wait;
}

/* Rotate a frequency counter when current period is over. Must not be called
 * during a valid period. It is important that it correctly initializes a null
 * area.
 */
static inline void hld_rotate_freq_ctr(struct hld_freq_ctr *ctr,
                                       const struct timeval now)
{
	ctr->prev_ctr = ctr->curr_ctr;
	if (now.tv_sec - ctr->curr_sec != 1) {
		/* we missed more than one second */
		ctr->prev_ctr = 0;
	}
	ctr->curr_sec = now.tv_sec;
	ctr->curr_ctr = 0; /* leave it at the end to help gcc optimize it away */
}

/* Update a frequency counter by <inc> incremental units. It is automatically
 * rotated if the period is over. It is important that it correctly initializes
 * a null area.
 */
static inline void hld_update_freq_ctr(struct hld_freq_ctr *ctr, uint32_t inc,
                                       const struct timeval now)
{
	if (ctr->curr_sec == now.tv_sec) {
		ctr->curr_ctr += inc;
		return;
	}
	hld_rotate_freq_ctr(ctr, now);
	ctr->curr_ctr = inc;
}

#define TRACE_SOURCE &trace_haload
struct trace_source trace_haload;
static void hld_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                         const struct ist where, const struct ist func,
                         const void *a1, const void *a2, const void *a3, const void *a4);
static inline void hldstream_free(struct hldstream **hs);

static const struct name_desc hld_trace_logon_args[4] = {
	/* arg1 */ { /* already used by the haload stream */ },
	/* arg2 */ {
		.name = "hld",
		.desc = "haload",
	},
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct trace_event hld_trace_events[] = {
#define HLD_EV_MAIN_TASK  (1ULL << 0)
	{ .mask = HLD_EV_MAIN_TASK, .name = "mtask",      .desc = "haload main task" },
#define HLD_EV_USR_TASK  (1ULL << 0)
	{ .mask = HLD_EV_USR_TASK,  .name = "usr_task",   .desc = "haload user task" },
#define HLD_STRM_EV_TX     (1ULL << 1)
	{ .mask = HLD_STRM_EV_TX,     .name = "tx",        .desc = "haload stream sending" },
#define HLD_STRM_EV_TX_BLK (1ULL << 2)
	{ .mask = HLD_STRM_EV_TX_BLK, .name = "tx_blk",    .desc = "haload stream sending blocked" },
#define HLD_STRM_EV_RX     (1ULL << 3)
	{ .mask = HLD_STRM_EV_RX,     .name = "rx",        .desc = "haload stream receiving" },
#define HLD_STRM_EV_RX_BLK (1ULL << 4)
	{ .mask = HLD_STRM_EV_RX_BLK, .name = "rx_blk",    .desc = "haload stream receiving blocked" },
#define HLD_STRM_EV_TASK   (1ULL << 5)
	{ .mask = HLD_STRM_EV_TASK,   .name = "strm_task", .desc = "haload stream task" },
#define HLD_STRM_EV_IO_CB  (1ULL << 6)
	{ .mask = HLD_STRM_EV_IO_CB,  .name = "io_cb",     .desc = "stconn i/o callback call" },
};

static const struct name_desc hld_trace_decoding[] = {
#define HALOAD_VERB_CLEAN 1
	{ .name = "clean", .desc = "only user-friendly stuff, generally suitable for level \"user\"" },
};

struct trace_source trace_haload = {
	.name = IST("haload"),
	.desc = "haload benchmark tool",
	/* TRACE()'s first argument is always a haload stream */
	.arg_def = TRC_ARG1_HLDSTRM,
	.default_cb = hld_trace,
	.known_events = hld_trace_events,
	.lockon_args = hld_trace_logon_args,
	.decoding = hld_trace_decoding,
	.report_events = ~0, /* report everything by default */
};

INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

static void hld_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                         const struct ist where, const struct ist func,
                         const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct hldstream *hs = a1;

	if (!hs || src->verbosity < HALOAD_VERB_CLEAN)
		return;

	chunk_appendf(&trace_buf, " hs@%p conn@%p se@%p to_send=%llu tot_req=%lu",
	              hs, __sc_conn(hs->sc), __sc_endp(hs->sc),
	              hs->to_send, hs->url->tot_req);
	if (hs->sc) {
		struct connection *conn = sc_conn(hs->sc);
		chunk_appendf(&trace_buf, " - conn=%p(0x%08x)", conn, conn ? conn->flags : 0);
		chunk_appendf(&trace_buf, " sc=%p(0x%08x)", hs->sc, hs->sc->flags);
	}
}

/* Tries to grab a buffer and to re-enables processing on haload stream <target>.
 * The flags are used to figure what buffer was requested. It returns 1 if the
 * allocation succeeds, in which case the haload stream is woken up, or 0 if it's
 * impossible to wake up and we prefer to be woken up later.
 */
int hldstream_buf_available(void *target)
{
	struct hldstream *hs = target;

	if ((hs->flags & HLD_STRM_ST_IN_ALLOC) && b_alloc(&hs->bi, DB_CHANNEL)) {
		hs->flags &= ~HLD_STRM_ST_IN_ALLOC;
		TRACE_STATE("unblocking stream, input buffer allocated",
		            HLD_STRM_EV_RX|HLD_STRM_EV_RX_BLK, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
		return 1;
	}

	if ((hs->flags & HLD_STRM_ST_OUT_ALLOC) && b_alloc(&hs->bo, DB_CHANNEL)) {
		hs->flags &= ~HLD_STRM_ST_OUT_ALLOC;
		TRACE_STATE("unblocking stream, ouput buffer allocated",
		            HLD_STRM_EV_TX|HLD_STRM_EV_TX_BLK, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
		return 1;
	}

	return 0;
}

/* Allocate a buffer. If it fails, it adds the stream in buffer wait queue */
struct buffer *hldstream_get_buf(struct hldstream *hs, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(!LIST_INLIST(&hs->buf_wait.list)) &&
	    unlikely((buf = b_alloc(bptr, DB_CHANNEL)) == NULL)) {
		b_queue(DB_CHANNEL, &hs->buf_wait, hs, hldstream_buf_available);
	}

	return buf;
}

/* Allocate the output buffer attached to <hs> haload stream and returns
 * it if succeded, NULL if not.
 */
static inline struct buffer *hldstream_get_obuf(struct hldstream *hs)
{
	return hldstream_get_buf(hs, &hs->bo);
}

/* Allocate the input buffer attached to <hs> haload stream and returns
 * it if succeded, NULL if not.
 */
static inline struct buffer *hldstream_get_ibuf(struct hldstream *hs)
{
	return hldstream_get_buf(hs, &hs->bi);
}

/* Release a buffer, if any, and try to wake up entities waiting in the buffer
 * wait queue.
 */
void hldstream_release_buf(struct hldstream *hs, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(hs->buf_wait.target, 1);
	}
}

/* Release the input buffer attached to <hs> haload stream */
static inline void hldstream_release_ibuf(struct hldstream *hs)
{
	hldstream_release_buf(hs, &hs->bi);
}

/* Release the output buffer attached to <hs> haload stream */
static inline void hldstream_release_obuf(struct hldstream *hs)
{
	hldstream_release_buf(hs, &hs->bo);
}

/* Free <*hs> haload stream and reset its address to NULL */
static inline void hldstream_free(struct hldstream **hs)
{
	struct hldstream *h = *hs;

	TRACE_PRINTF(TRACE_LEVEL_PROTO, HLD_STRM_EV_TASK, hs, 0, 0, 0,
	             "freeing %p stream", h);
	se_shutdown(h->sc->sedesc, SE_SHW_SILENT);
	hldstream_release_ibuf(h);
	hldstream_release_obuf(h);
	task_destroy(h->task);
	sc_destroy(h->sc);
	ha_free(hs);
	TRACE_LEAVE(HLD_STRM_EV_TASK);
}


/* Creates a new stream connector from a haload connection. There is no endpoint
 * here, thus it will be created by sc_new(). So the SE_FL_DETACHED flag is set.
 * It returns NULL on error. On success, the new stream connector is returned.
 */
static inline struct stconn *sc_new_from_hldstream(struct hldstream *hs, unsigned int flags)
{
	struct stconn *sc;

	sc = sc_new(NULL);
	if (unlikely(!sc))
		return NULL;

	sc->flags |= flags;
	sc_ep_set(sc, SE_FL_DETACHED);
	sc->app = &hs->obj_type;
	return sc;
}

/* reports a locally allocated string to represent a human-readable positive
 * number on 4 characters (3 digits and a unit, which may be "." for ones) :
 *   XXXu
 *   XXuX
 *   XuXX
 */
static const char *human_number(double x)
{
	static char str[8];
	char unit = '.';

	if (x < 0)
		x = -x;

	do {
		if (x == 0.0 || x >= 1.0) break;
		x *= 1000.0; unit = 'm';
		if (x >= 1.0) break;
		x *= 1000.0; unit = 'u';
		if (x >= 1.0) break;
		x *= 1000.0; unit = 'n';
		if (x >= 1.0) break;
		x *= 1000.0; unit = 'p';
		if (x >= 1.0) break;
		x *= 1000.0; unit = 'f';
	} while (0);

	do {
		if (x < 1000.0) break;
		x /= 1000.0; unit = 'k';
		if (x < 1000.0) break;
		x /= 1000.0; unit = 'M';
		if (x < 1000.0) break;
		x /= 1000.0; unit = 'G';
		if (x < 1000.0) break;
		x /= 1000.0; unit = 'T';
		if (x < 1000.0) break;
		x /= 1000.0; unit = 'P';
		if (x < 1000.0) break;
		x /= 1000.0; unit = 'E';
	} while (0);

	if (x < 10.0)
		snprintf(str, sizeof(str), "%d%c%02d", (int)x, unit, (int)((x - (int)x)*100));
	else if (x < 100.0)
		snprintf(str, sizeof(str), "%d%c%d",   (int)x, unit, (int)((x - (int)x)*10));
	else
		snprintf(str, sizeof(str), "%d%c",     (int)x, unit);
	return str;
}

/* Builds a string from the time interval <us> (in microsecond), made of a 5
 * digit value followed by a unit among 'n', 'u', 'm', 's' for "nanoseconds",
 * "microseconds", "milliseconds", "seconds" respectively. Large values will
 * stick to the seconds unit and will enlarge the output, though this is not
 * expected to be a common case. This way the output can be converted back
 * into integer values without too much hassle (e.g. for graphs). The string
 * is locally allocated so this must not be used by multiple threads. Negative
 * values are reported as "  -  ".
 */
static const char *short_delay_str(double us)
{
	static char str[20];
	char unit;

	if (us <= 0.0) {
		return "   -  ";
	}
	else if (us < 1.0) {
		us *= 1000.0;
		unit = 'n';
	}
	else if (us < 1000.0) {
		unit = 'u';
	}
	else if (us < 1000000.0) {
		us /= 1000.0;
		unit = 'm';
	}
	else {
		us /= 1000000.0;
		unit = 's';
	}

	if (us < 10.0)
		snprintf(str, sizeof(str), "%1.3f%c", us, unit);
	else if (us < 100.0)
		snprintf(str, sizeof(str), "%2.2f%c", us, unit);
	else if (us < 1000.0)
		snprintf(str, sizeof(str), "%3.1f%c", us, unit);
	else
		snprintf(str, sizeof(str), "%5f%c", us, unit);
	return str;
}

/* Reset all cumulative per-thread counters, for -ee after an error. */
static void hld_reset_counters(void)
{
	int th;

	for (th = 0; th < arg_thrd; th++) {
		HA_ATOMIC_STORE(&thrs_info[th].tot_conn, 0);
		HA_ATOMIC_STORE(&thrs_info[th].tot_done, 0);
		HA_ATOMIC_STORE(&thrs_info[th].tot_probe_done, 0);
		HA_ATOMIC_STORE(&thrs_info[th].tot_rcvd, 0);
		HA_ATOMIC_STORE(&thrs_info[th].tot_perr, 0);
		HA_ATOMIC_STORE(&thrs_info[th].tot_fbs, 0);
		HA_ATOMIC_STORE(&thrs_info[th].tot_ttfb, 0);
		HA_ATOMIC_STORE(&thrs_info[th].tot_lbs, 0);
		HA_ATOMIC_STORE(&thrs_info[th].tot_ttlb, 0);
		if (arg_hscd) {
			int i;

			for (i = 0; i < 5; i++)
				HA_ATOMIC_STORE(&thrs_info[th].tot_sc[i], 0);
		}
		if (arg_hscd == 2) {
			int v, i;

			for (v = HLD_PROTO_H0; v < HLD_PROTO_MAX; v++)
				for (i = 0; i < 5; i++)
					HA_ATOMIC_STORE(&thrs_info[th].vtot_sc[v][i], 0);
		}
	}
	hld_reset_summary_baseline = 1;
}

/* reports current date (now) and aggragated stats */
void hld_summary(void)
{
	int th;
	uint64_t cur_conn, tot_conn, tot_req, tot_err, tot_rcvd, bytes;
	uint64_t tot_ttfb, tot_ttlb, tot_fbs, tot_lbs, tot_sc[5], vtot_sc[HLD_PROTO_MAX][5];
	static uint64_t prev_totc, prev_totr, prev_totb;
	static uint64_t prev_ttfb, prev_ttlb, prev_fbs, prev_lbs, prev_sc[5],
	                prev_vsc[HLD_PROTO_MAX][5];
	static struct timeval prev_date = TV_UNSET;
	double interval;

	if (hld_reset_summary_baseline) {
		prev_totc = prev_totr = prev_totb = 0;
		prev_ttfb = prev_ttlb = prev_fbs = prev_lbs = 0;
		if (arg_hscd)
			prev_sc[0] = prev_sc[1] = prev_sc[2] = prev_sc[3] = prev_sc[4] = 0;
		if (arg_hscd == 2) {
			int v;

			for (v = HLD_PROTO_H0; v < HLD_PROTO_MAX; v++)
				prev_vsc[v][0] = prev_vsc[v][1] = prev_vsc[v][2] = prev_vsc[v][3] = prev_vsc[v][4] = 0;
		}
		prev_date = TV_UNSET;
		hld_reset_summary_baseline = 0;
	}

	cur_conn = tot_conn = tot_req = tot_err = tot_rcvd = 0;
	tot_ttfb = tot_ttlb = tot_fbs = tot_lbs = 0;
	if (arg_hscd)
		tot_sc[0] = tot_sc[1] = tot_sc[2] = tot_sc[3] = tot_sc[4] = 0;
	if (arg_hscd == 2) {
		int v;

		for (v = HLD_PROTO_H0; v < HLD_PROTO_MAX; v++)
			vtot_sc[v][0] = vtot_sc[v][1] = vtot_sc[v][2] = vtot_sc[v][3] = vtot_sc[v][4] = 0;
	}

	for (th = 0; th < arg_thrd; th++) {
		cur_conn += HA_ATOMIC_LOAD(&thrs_info[th].curconn);
		tot_conn += HA_ATOMIC_LOAD(&thrs_info[th].tot_conn);
		tot_req  += HA_ATOMIC_LOAD(&thrs_info[th].tot_done);
		tot_err  += HA_ATOMIC_LOAD(&thrs_info[th].tot_perr);
		tot_rcvd += HA_ATOMIC_LOAD(&thrs_info[th].tot_rcvd);
		tot_ttfb += HA_ATOMIC_LOAD(&thrs_info[th].tot_ttfb);
		tot_ttlb += HA_ATOMIC_LOAD(&thrs_info[th].tot_ttlb);
		tot_fbs  += HA_ATOMIC_LOAD(&thrs_info[th].tot_fbs);
		tot_lbs  += HA_ATOMIC_LOAD(&thrs_info[th].tot_lbs);
		if (arg_hscd) {
			tot_sc[0]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[0]);
			tot_sc[1]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[1]);
			tot_sc[2]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[2]);
			tot_sc[3]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[3]);
			tot_sc[4]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[4]);
		}
		if (arg_hscd == 2) {
			int v;

			for (v = HLD_PROTO_H0; v < HLD_PROTO_MAX; v++) {
				if (!(hld_proto_flags & (1U << v)))
				    continue;

				vtot_sc[v][0]+= HA_ATOMIC_LOAD(&thrs_info[th].vtot_sc[v][0]);
				vtot_sc[v][1]+= HA_ATOMIC_LOAD(&thrs_info[th].vtot_sc[v][1]);
				vtot_sc[v][2]+= HA_ATOMIC_LOAD(&thrs_info[th].vtot_sc[v][2]);
				vtot_sc[v][3]+= HA_ATOMIC_LOAD(&thrs_info[th].vtot_sc[v][3]);
				vtot_sc[v][4]+= HA_ATOMIC_LOAD(&thrs_info[th].vtot_sc[v][4]);
			}
		}


	}

	if (tv_isset(&prev_date))
		interval = tv_ms_remain(&prev_date, &hld_now) / 1000.0;
	else
		interval = 1.0;

	printf("%10lu %5lu %8llu %8llu %14llu %6lu ",
	       arg_long ? (unsigned long)hld_now.tv_sec :
	       (unsigned long)(hld_now.tv_sec - hld_start_date.tv_sec),
	       (unsigned long)cur_conn,
	       (unsigned long long)tot_conn,
	       (unsigned long long)tot_req,
	       (unsigned long long)tot_rcvd,
	       (unsigned long)tot_err);

	bytes = tot_rcvd - prev_totb;

	if (arg_long >= 2)
		printf("%3u ", throttle ? mul32hi(100, throttle) : 100);

	if (arg_long >= 2)
		printf("%.1f ", (tot_conn - prev_totc) / interval);
	else
		printf("%s ", human_number((tot_conn - prev_totc) / interval));

	if (arg_long >= 2)
		printf("%.1f ", (tot_req  - prev_totr) / interval);
	else
		printf("%s ", human_number((tot_req  - prev_totr) / interval));

	if (arg_long >= 2)
		printf("%.1f ", bytes / interval);
	else if (arg_long)
		printf("%s ", human_number(bytes / interval));

	if (arg_long >= 2)
		printf("%.1f ", bytes * 8 / interval);
	else
		printf("%s ", human_number(bytes * 8 / interval));

	if (arg_long >= 2) {
		if (tot_fbs - prev_fbs)
			printf("%.1f ", (tot_ttfb - prev_ttfb) / (double)(tot_fbs - prev_fbs));
		else
			printf("- ");
	}
	else
		printf("%s ", tot_fbs == prev_fbs ? "   -  " :
		       short_delay_str((tot_ttfb - prev_ttfb) / (double)(tot_fbs - prev_fbs)));

	if (arg_long >= 2) {
		if (tot_lbs - prev_lbs)
			printf("%.1f ", (tot_ttlb - prev_ttlb) / (double)(tot_lbs - prev_lbs));
		else
			printf("- ");
	}
	else if (arg_long)
		printf("%s ", tot_lbs == prev_lbs ? "   -  " :
		       short_delay_str((tot_ttlb - prev_ttlb) / (double)(tot_lbs - prev_lbs)));

	/* status codes distribution */
	if (arg_hscd)
		printf("%3llu %3llu %3llu %3llu %3llu",
		       (unsigned long long)(tot_sc[0] - prev_sc[0]),
		       (unsigned long long)(tot_sc[1] - prev_sc[1]),
		       (unsigned long long)(tot_sc[2] - prev_sc[2]),
		       (unsigned long long)(tot_sc[3] - prev_sc[3]),
		       (unsigned long long)(tot_sc[4] - prev_sc[4]));
	if (arg_hscd == 2) {
		int v;

		for (v = HLD_PROTO_H0; v < HLD_PROTO_MAX; v++) {
			if (!(hld_proto_flags & (1U << v)))
				continue;

			printf("     %3llu %3llu %3llu %3llu %3llu",
			       (unsigned long long)(vtot_sc[v][0] - prev_vsc[v][0]),
			       (unsigned long long)(vtot_sc[v][1] - prev_vsc[v][1]),
			       (unsigned long long)(vtot_sc[v][2] - prev_vsc[v][2]),
			       (unsigned long long)(vtot_sc[v][3] - prev_vsc[v][3]),
			       (unsigned long long)(vtot_sc[v][4] - prev_vsc[v][4]));
		}

	}

	putchar('\n');
	fflush(stdout);

	prev_totc = tot_conn;
	prev_totr = tot_req;
	prev_totb = tot_rcvd;
	prev_fbs  = tot_fbs;
	prev_lbs  = tot_lbs;
	prev_ttfb = tot_ttfb;
	prev_ttlb = tot_ttlb;
	if (arg_hscd) {
		prev_sc[0]= tot_sc[0];
		prev_sc[1]= tot_sc[1];
		prev_sc[2]= tot_sc[2];
		prev_sc[3]= tot_sc[3];
		prev_sc[4]= tot_sc[4];
	}
	if (arg_hscd == 2) {
		int v;

		for (v = HLD_PROTO_H0; v < HLD_PROTO_MAX; v++) {
			prev_vsc[v][0] = vtot_sc[v][0];
			prev_vsc[v][1] = vtot_sc[v][1];
			prev_vsc[v][2] = vtot_sc[v][2];
			prev_vsc[v][3] = vtot_sc[v][3];
			prev_vsc[v][4] = vtot_sc[v][4];
		}
	}
	prev_date = hld_now;
}

/* Same throttle handling as for h1load */
void update_throttle()
{
	int duration;
	uint32_t ratio = 0;
	uint32_t step, steps = 10, pos, base;

	if (!arg_slow)
		goto end;

	duration = tv_ms_remain(&hld_start_date, &hld_now);
	if (duration >= arg_slow)
		goto end;

	/* The ramp-up duration is cut into <steps> steps.
	 * Each step shows a ramp-up during the first quarter of its
	 * duration, and a stabilisation period during the last 3/4.
	 * For instance, with 4 steps, we have this:
	 *
	 *      ramp up
	 * |<-------------->|
	 * |             __________
	 * |         ___/:  :
	 * |     ___/   ::  :
	 * | ___/       ::  :
	 * |/           ::  :
	 * +------------++------------>
	 *
	 * Thus we have to determine the current step and the position within
	 * this step. In order to simplify this, we'll pretend there are 4
	 * times more steps and that only steps 0 mod 4 ramp up the load.
	 * The throttle is stable along the last 3 quarters of a step, at the
	 * base value of the next step.
	 */

	step = (steps * 4) * duration / arg_slow;
	if (step & 3) {
		ratio = (uint64_t)0xffffffffU * (step / 4 + 1) / steps + 1;
		goto end;
	}

	/* position in ms within the current step */
	pos = duration - step * arg_slow / (steps * 4);

	/* get a ratio out of it. We divide 4* the position by the step width
	 * (arg_slow/steps), and multiply this by 1/steps to get the relative
	 * height vs 100%. steps cancel each other.
	 */
	pos = (uint64_t)0xffffffffU * pos * 4 / arg_slow;
	base = (uint64_t)0xffffffffU * (step / 4) / steps;
	ratio = base + pos;

	//printf("base=%#x (%u)  pos=%#x (%u) tot=%#x (%u)\n",
	//       base, mul32hi(100,base),
	//       pos, mul32hi(100,pos),
	//       ratio, mul32hi(100,ratio));

	if (ratio < 1)
		ratio = 1;
 end:
	throttle = ratio;
}

/* Runs once, on the first error while -ee is set: resets counters and
 * drops to 1 conn/req per second per target.
 */
static void hld_err_trigger(void)
{
	int expected = 0;

	/* only one ramp at a time. update_err_ramp() sets this back to 0
	 * once a ramp is done, so a later, new outage can trigger again.
	 */
	if (!HA_ATOMIC_CAS(&err_ramp_pending, &expected, 1))
		return; /* a ramp is already running */

	hld_reset_counters();
	err_rate_target = HA_ATOMIC_LOAD(&arg_rate); /* 0 = no limit before, >0 = old -R value */
	hld_err_date = hld_now;
	err_ramp_step = 0;
	err_ramp_ok_base = 0;
	HA_ATOMIC_INC(&err_ramp_gen); /* tell every thread to reset its own rate history */
	HA_ATOMIC_STORE(&arg_rate, err_rate_floor);
	HA_ATOMIC_STORE(&err_ramp_active, 1); /* set this last, so other threads see the rest first */
	ha_alert("haload: error detected, probing at %d req/s, doubling every second"
	         " until %llu successes are seen\n",
	         err_rate_floor, (unsigned long long)err_success_target);
}

/* -ee ramp-up: doubles the rate every second, from <err_rate_floor>, as long
 * as new requests keep succeeding. Once <err_success_target> successes have
 * been seen (since the trigger), stop probing and go back to the load the
 * command line asked for (<err_rate_target>: 0 = no limit, >0 = old -R
 * value). The doubling is not capped at <err_rate_target> on the way up:
 * only reaching <err_success_target> ends the ramp.
 */
static void update_err_ramp(void)
{
	uint64_t ok = 0;
	int th, step;

	if (!HA_ATOMIC_LOAD(&err_ramp_active))
		return;

	/* add up successes on all threads, counting only users created
	 * during this ramp (tot_probe_done): a pre-existing, unaffected
	 * user succeeding does not mean the probe itself is working.
	 */
	for (th = 0; th < arg_thrd; th++)
		ok += HA_ATOMIC_LOAD(&thrs_info[th].tot_probe_done);

	/* enough confirmed successes: stop probing, resume the normal load */
	if (ok >= err_success_target) {
		HA_ATOMIC_STORE(&arg_rate, err_rate_target);
		HA_ATOMIC_STORE(&err_ramp_active, 0);
		HA_ATOMIC_STORE(&err_ramp_pending, 0); /* a later outage may trigger again */
		return;
	}

	/* step 0 checks every time this runs, to catch the first success
	 * fast. every step after that waits 1s before doubling again.
	 */
	if (err_ramp_step > 0 && tv_ms_remain(&hld_err_date, &hld_now) < 1000)
		return;

	if (ok <= err_ramp_ok_base) {
		/* nothing new succeeded: target is still down, do not speed up */
		if (err_ramp_step > 0)
			hld_err_date = hld_now;
		return;
	}

	err_ramp_ok_base = ok;
	hld_err_date = hld_now;
	step = ++err_ramp_step;
	if (step > 40)
		step = 40; /* keep this small so the math below stays safe */

	HA_ATOMIC_STORE(&arg_rate, (uint64_t)err_rate_floor << step);
}

static const char *hld_proto_names[HLD_PROTO_MAX] = { "h0", "h1", "h2", "h3", "fcgi" };

/* main task */
static struct task *mtask_cb(struct task *t, void *context, unsigned int state)
{
	static int header_printed;

	TRACE_ENTER(HLD_EV_MAIN_TASK);

	gettimeofday(&hld_now, NULL);

	if (!header_printed) {
		header_printed = 1;
		if (arg_long >= 2)
			printf("#_____time conns tot_conn  tot_req      tot_bytes"
				   "    err thr cps rps Bps bps ttfb(us) ttlb(us)");
		else if (arg_long)
			printf("#     time conns tot_conn  tot_req      tot_bytes"
				   "    err  cps  rps  Bps  bps   ttfb   ttlb");
		else
			printf("#     time conns tot_conn  tot_req      tot_bytes"
				   "    err  cps  rps  bps   ttfb");
		if (arg_hscd)
			printf(" 1xx 2xx 3xx 4xx 5xx");
		if (arg_hscd == 2) {
			int i;

			for (i = 0 ; i < HLD_PROTO_MAX; i++) {
				if (!(hld_proto_flags & (1 << i)))
					continue;
				printf("   (%s)1xx 2xx 3xx 4xx 5xx", hld_proto_names[i]);
			}
		}


		putchar('\n');
	}

	update_throttle();
	update_err_ramp();
	if (tick_is_expired(mtask.show_time, now_ms)) {
		hld_summary();
		if (!HA_ATOMIC_LOAD(&running_tasks)) {
			task_destroy(t);
			t = NULL;
			if (arg_pctl)
				hld_report_percentiles();
			hld_dealloc_thrs_info();
			/* The process will exit after this call */
			soft_stop();
			goto leave;
		}

		if (arg_dura && !tv_isbefore(&hld_now, &hld_stop_date))
			HA_ATOMIC_STORE(&all_usr_stop_asap, 1);

		mtask.show_time = tick_add(now_ms, MS_TO_TICKS(1000));
	}

	/* users initializations */
	if (!HA_ATOMIC_LOAD(&arg_rate) && usr_cnt < arg_usr) {
		if (throttle) {
			int i, nb_usr;

			for (i = 0; i < arg_thrd; i++) {
				nb_usr = mul32hi(thrs_info[i].maxusrs, throttle);
				nb_usr = nb_usr ? nb_usr : 1;

				while (thrs_info[i].curusrs < nb_usr) {
					struct hld_usr *hu;
					int req = arg_reqs == -1 ? -1 : (arg_reqs + usr_cnt) / arg_usr;

					hu = hld_new_usr(req, i);
					if (!hu) {
						ha_alert("could not allocate a new haload user\n");
						break;
					}

					HA_ATOMIC_INC(&running_tasks);
					usr_cnt++;
				}
			}

			t->expire = tick_add(now_ms, MS_TO_TICKS(20));
		}
		else {
			int i, nb_usr;

			nb_usr = MIN(arg_usr, arg_usr - usr_cnt);
			nb_usr = MIN(80, nb_usr);
			for (i = 0; i < nb_usr; i++, usr_cnt++) {
				struct hld_usr *hu;
				int req = arg_reqs == -1 ? -1 : (arg_reqs + usr_cnt) / arg_usr;

				hu = hld_new_usr(req, usr_tid++ % arg_thrd);
				if (!hu) {
					ha_alert("could not allocate a new haload user\n");
					break;
				}
			}

			HA_ATOMIC_ADD(&running_tasks, nb_usr);
			task_wakeup(t, TASK_WOKEN_IO);
		}

	}
	else if (HA_ATOMIC_LOAD(&arg_rate) && HA_ATOMIC_LOAD(&running_tasks) <= arg_usr) {
		t->expire = tick_first(tick_add(now_ms, MS_TO_TICKS(100)), mtask.show_time);
	}
	else
		t->expire = tick_add(now_ms, MS_TO_TICKS(1000));

leave:
	TRACE_LEAVE(HLD_EV_MAIN_TASK);
	return t;
}

/* Add up to <to_send> bytes of the POST body to <htx>, shifting the starting
 * offset in hld_post_data by up to one line's width based on how many bytes
 * were already sent, so consecutive chunks don't start with the exact same
 * bytes. Mirrors hstream_add_htx_data() in haterm.c. Returns the number of
 * bytes actually added.
 */
static size_t hldstream_add_htx_data(struct hldstream *hs, struct htx *htx,
                                     unsigned long long to_send)
{
	size_t offset = (hs->post_sz - to_send) % HLD_POST_DATA_LINE_SZ;
	size_t len = MIN(to_send, (unsigned long long)(sizeof(hld_post_data) - offset));

	return htx_add_data(htx, ist2(hld_post_data + offset, len));
}

static int hldstream_build_http_req(struct hldstream *hs, struct ist path)
{
	int ret = 0;
	struct buffer *buf;
	struct htx *htx;
	struct htx_sl *sl;
	struct hld_hdr *hdr;
	struct ist meth_ist = hs->meth_ist;
	unsigned int flags = HTX_SL_F_VER_11 | HTX_SL_F_XFER_LEN |
		(!hs->to_send ? HTX_SL_F_BODYLESS : HTX_SL_F_CLEN);

	TRACE_ENTER(HLD_STRM_EV_TX, hs);
	buf = hldstream_get_obuf(hs);
	if (!buf) {
		TRACE_STATE("waiting for ouput buffer", HLD_STRM_EV_TX|HLD_STRM_EV_TX_BLK, hs);
		hs->flags |= HLD_STRM_ST_OUT_ALLOC;
		goto leave;
	}

	htx = htx_from_buf(buf);
	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, meth_ist, path, ist("HTTP/1.1"));
	if (!sl)
		goto err;

	sl->info.req.meth = hs->http_meth;
	list_for_each_entry(hdr, &hld_hdrs, list)
		if (!htx_add_header(htx, hdr->name, hdr->value)) {
			TRACE_ERROR("could not add a header", HLD_STRM_EV_TX, hs);
			goto err;
		}

	if (!arg_host &&
	    !http_add_header(htx, ist("host"), ist(hs->url->cfg->raw_addr), 1)) {
		TRACE_ERROR("could not add host header", HLD_STRM_EV_TX, hs);
		goto err;
	}

	if (arg_conn_hdr && !http_add_header(htx, ist("Connection"), ist("close"), 0)) {
		TRACE_ERROR("could not add connection header", HLD_STRM_EV_TX, hs);
		goto err;
	}

	if (hs->to_send > 0) {
		char *end = ultoa_o(hs->to_send, trash.area, trash.size);

		if (!end || !htx_add_header(htx, ist("Content-Length"), ist2(trash.area, end - trash.area))) {
			TRACE_ERROR("could not add content-length header", HLD_STRM_EV_TX, hs);
			goto err;
		}
	}

	if (!LIST_ISEMPTY(&hs->usr->cookies)) {
		struct hld_cookie *ck;

		chunk_reset(&trash);
		list_for_each_entry(ck, &hs->usr->cookies, list) {
			if (trash.data)
				chunk_appendf(&trash, "; ");

			chunk_appendf(&trash, "%.*s=%.*s", (int)ck->name.len, ck->name.ptr,
			              (int)ck->value.len, ck->value.ptr);
		}

		if (!htx_add_header(htx, ist("Cookie"), ist2(trash.area, trash.data))) {
			TRACE_ERROR("could not add cookie header", HLD_STRM_EV_TX, hs);
			goto err;
		}
	}

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto err;

	if (hs->to_send > 0)
		hs->to_send -= hldstream_add_htx_data(hs, htx, hs->to_send);

	if (!hs->to_send)
		htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, &hs->bo);
 leave:
	ret = 1;
	TRACE_LEAVE(HLD_STRM_EV_TX, hs);
	return ret;
 err:
	hs->flags |= HLD_STRM_ST_CONN_ERR;
	TRACE_DEVEL("leaving on error", HLD_STRM_EV_TX, hs);
	goto leave;
}

/* Continue sending the POST body once the previous output buffer was fully
 * drained but hs->to_send is still > 0. Sets HTX_FL_EOM once it reaches 0.
 * Return 1 if succeeded, 0 if not.
 */
static int hldstream_build_http_body(struct hldstream *hs)
{
	int ret = 0;
	struct buffer *buf;
	struct htx *htx;

	TRACE_ENTER(HLD_STRM_EV_TX, hs);
	buf = hldstream_get_obuf(hs);
	if (!buf) {
		TRACE_STATE("waiting for ouput buffer", HLD_STRM_EV_TX|HLD_STRM_EV_TX_BLK, hs);
		hs->flags |= HLD_STRM_ST_OUT_ALLOC;
		goto leave;
	}

	htx = htx_from_buf(buf);
	hs->to_send -= hldstream_add_htx_data(hs, htx, hs->to_send);
	if (!hs->to_send)
		htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, &hs->bo);
 leave:
	ret = 1;
	TRACE_LEAVE(HLD_STRM_EV_TX, hs);
	return ret;
}

/* Send HTX data prepared for <hs> haload stream from <conn> connection */
static int hldstream_htx_buf_snd(struct connection *conn, struct hldstream *hs)
{
	struct stconn *sc = hs->sc;
	int ret = 0;
	int nret;

	TRACE_ENTER(HLD_STRM_EV_TX, hs);

	if (!htxbuf(&hs->bo)->data) {
		/* This is possible after having drained the body, so after
		 * having sent the response here when req_after_res=1.
		 */
		ret = 1;
		goto out;
	}

	nret = CALL_MUX_WITH_RET(conn->mux, snd_buf(hs->sc, &hs->bo, (htxbuf(&hs->bo))->data, 0));
	if (nret <= 0) {
		if (hs->flags & HLD_STRM_ST_CONN_ERR ||
		    conn->flags & CO_FL_ERROR || sc_ep_test(sc, SE_FL_ERROR)) {
			TRACE_DEVEL("connection error during send", HLD_STRM_EV_TX, hs);
			goto out;
		}
	}

	hs->req_date = date;
	/* The HTX data are not fully sent if the last HTX data
	 * were not fully transfered or if there are remaining data
	 * to send (->to_send > 0).
	 */
	if (!htx_is_empty(htxbuf(&hs->bo))) {
		TRACE_DEVEL("data not fully sent, wait", HLD_STRM_EV_TX, hs);
		conn->mux->subscribe(sc, SUB_RETRY_SEND, &sc->wait_event);
	}
	else if (hs->to_send) {
		TRACE_STATE("waking up task", HLD_STRM_EV_TX, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
	}

	ret = 1;
 out:
	if (htx_is_empty(htxbuf(&hs->bo)) || ret == 0) {
		TRACE_DEVEL("releasing underlying buffer", HLD_STRM_EV_TX, hs);
		hldstream_release_obuf(hs);
	}

	TRACE_LEAVE(HLD_STRM_EV_TX, hs);
	return ret;
}

/* Split name=value out of a Set-Cookie value, using
 * http_extract_cookie_value() for a properly parsed value. The name
 * is found by hand since that function needs it to already be known.
 * Return 1 if succeeded, 0 if not.
 */
static inline int hld_split_cookie(struct ist v, struct ist *name, struct ist *value)
{
	char *eq, *end = istend(v);
	char *val_ptr;
	size_t val_len;

	for (eq = istptr(v); eq < end && *eq != '=' && *eq != ';'; eq++)
		;

	if (eq == end || *eq != '=')
		return 0;

	*name = ist2(istptr(v), eq - istptr(v));
	if (!http_extract_cookie_value(istptr(v), end, istptr(v), eq - istptr(v), 0, &val_ptr, &val_len))
		return 0;

	*value = ist2(val_ptr, val_len);
	return 1;
}

/* Add or update a cookie for <usr>, copying <name> and <value>. */
static inline void hld_usr_set_cookie(struct hld_usr *usr, struct ist name, struct ist value)
{
	struct hld_cookie *ck;
	struct ist new_value;

	list_for_each_entry(ck, &usr->cookies, list) {
		if (!isteq(ck->name, name))
			continue;

		new_value = istdup(value);
		if (!isttest(new_value))
			return;

		istfree(&ck->value);
		ck->value = new_value;
		return;
	}

	ck = malloc(sizeof(*ck));
	if (!ck)
		return;

	ck->name = istdup(name);
	ck->value = istdup(value);
	if (!isttest(ck->name) || !isttest(ck->value)) {
		istfree(&ck->name);
		istfree(&ck->value);
		free(ck);
		return;
	}

	LIST_APPEND(&usr->cookies, &ck->list);
}

/* Handle HTX data to be received by <h> haload stream. Also set
 * <*fin> to 1 if the end of stream is reached.
 */
static void hldstream_htx_buf_rcv(struct connection *conn,
                                  struct hldstream *hs, int *fin)
{
	struct buffer *buf;
	size_t max, read = 0, cur_read = 0;
	int is_empty = 0;
	struct htx_sl *sl = NULL;
	uint64_t ttfb, ttlb;     // time-to-first-byte, time-to-last-byte (in us)

	TRACE_ENTER(HLD_STRM_EV_RX, hs);

	*fin = 0;
	if (hs->sc->wait_event.events & SUB_RETRY_RECV) {
		TRACE_DEVEL("subscribed for RECV, waiting for data", HLD_STRM_EV_RX, hs);
		goto leave;
	}

	if (hs->flags & HLD_STRM_ST_IN_ALLOC) {
		TRACE_STATE("waiting for input buffer", HLD_STRM_EV_RX, hs);
		goto leave;
	}

	buf = hldstream_get_ibuf(hs);
	if (!buf) {
		TRACE_STATE("waiting for input buffer", HLD_STRM_EV_RX, hs);
		hs->flags |= HLD_STRM_ST_IN_ALLOC;
		goto leave;
	}

	while (sc_ep_test(hs->sc, SE_FL_RCV_MORE) ||
	       (!(conn->flags & CO_FL_ERROR) &&
	        !sc_ep_test(hs->sc, SE_FL_ERROR | SE_FL_EOS))) {
		htx_reset(htxbuf(&hs->bi));
		max = (IS_HTX_SC(hs->sc) ?
		       htx_free_space(htxbuf(&hs->bi)) : b_room(&hs->bi));
		sc_ep_clr(hs->sc, SE_FL_WANT_ROOM);
		read = CALL_MUX_WITH_RET(conn->mux, rcv_buf(hs->sc, &hs->bi, max, 0));
		if (!(hs->flags & HLD_STRM_ST_GOT_RESP_SL) && read && !sl) {
			struct http_hdr_ctx ctx;
			int status;

			sl = http_get_stline(htx_from_buf(&hs->bi));
			if (!sl) {
				TRACE_ERROR("start line not found", HLD_STRM_EV_RX, hs);
				hs->flags |= HLD_STRM_ST_CONN_ERR;
				goto leave;
			}

			status = sl->info.res.status;
			hs->flags |= HLD_STRM_ST_GOT_RESP_SL;
			TRACE_PRINTF(TRACE_LEVEL_PROTO, HLD_STRM_EV_RX, hs, 0, 0, 0,
			             "HTTP status: %d cur_read=%d",
			             status, (int)cur_read);

			ctx.blk = NULL;
			while (http_find_header(htx_from_buf(&hs->bi), ist("Set-Cookie"), &ctx, 1)) {
				struct ist name, value;

				if (hld_split_cookie(ctx.value, &name, &value))
					hld_usr_set_cookie(hs->usr, name, value);
			}

			if (arg_hscd)
				thrs_info[tid].tot_sc[status * 41 / 4096 - 1]++;
			if (arg_hscd == 2) {
				thrs_info[tid].vtot_sc[hs->url->cfg->proto][status * 41 / 4096 - 1]++;
			}
			if (hs->url->tot_req > 1 || !arg_accu) {
				ttfb = tv_us(tv_diff(&hs->req_date, &date));
				thrs_info[tid].tot_fbs++;
				thrs_info[tid].tot_ttfb += ttfb;
				if (arg_pctl)
					thrs_info[tid].ttfb_pct[to_uf16(ttfb)]++;
			}
		}

		cur_read += read;
		if (!htx_expect_more(htxbuf(&hs->bi)) || sc_ep_test(hs->sc, SE_FL_EOS)) {
		    *fin = 1;
			thrs_info[tid].tot_done++;
			/* only count this success towards the current -ee ramp
			 * if this user was itself created during that ramp:
			 * a pre-existing, never-affected user succeeding does
			 * not tell us the probe itself is working.
			 */
			if (hs->usr->ramp_gen == HA_ATOMIC_LOAD(&err_ramp_gen))
				thrs_info[tid].tot_probe_done++;
			if (hs->url->tot_req > 1 || !arg_accu) {
				ttlb = tv_us(tv_diff(&hs->req_date, &date));
				thrs_info[tid].tot_lbs++;
				thrs_info[tid].tot_ttlb += ttlb;
				if (arg_pctl)
					thrs_info[tid].ttlb_pct[to_uf16(ttlb)]++;
			}
		    break;
		}

		if (!read)
			break;
	}

	is_empty = (IS_HTX_SC(hs->sc) ?
	            htx_is_empty(htxbuf(&hs->bi)) : !b_data(&hs->bi));
	if (is_empty &&
	    ((conn->flags & CO_FL_ERROR) || sc_ep_test(hs->sc, SE_FL_ERROR))) {
		/* Report network errors only if we got no other data. Otherwise
		 * we'll let the upper layers decide whether the response is OK
		 * or not. It is very common that an RST sent by the server is
		 * reported as an error just after the last data chunk.
		 */
		TRACE_ERROR("connection error during recv", HLD_STRM_EV_RX, hs);
		hs->flags |= HLD_STRM_ST_CONN_ERR;
	}
	else if (!*fin && !sc_ep_test(hs->sc, SE_FL_ERROR | SE_FL_EOS)) {
		TRACE_DEVEL("subscribing for read data", HLD_STRM_EV_RX, hs);
		conn->mux->subscribe(hs->sc, SUB_RETRY_RECV, &hs->sc->wait_event);
	}

	thrs_info[tid].tot_rcvd += cur_read;
 leave:
	if (!is_empty)
		hldstream_release_ibuf(hs);
	TRACE_PRINTF(TRACE_LEVEL_PROTO, HLD_STRM_EV_RX, hs, 0, 0, 0,
	             "data received (%llu) read=%d *fin=%d",
	             (unsigned long long)cur_read, (int)read, *fin);
	TRACE_LEAVE(HLD_STRM_EV_RX, hs);
}

static void hld_conn_destroy(struct connection *conn)
{
	TRACE_ENTER(HLD_STRM_EV_TASK);
	BUG_ON(!thrs_info[tid].curconn);
	thrs_info[tid].curconn--;
	TRACE_LEAVE(HLD_STRM_EV_TASK);
}

/* Try to reuse a connection from server <srv>, session <sess>, and
 * stream connector <sc>.
 * Always set the connection's <hash> to be reused, and return it
 * at the <conn> address if found.
 * Returns 1 if successful (no error, even if no connection was
 * available to reuse), or 0 otherwise.
 */
static int hld_be_reuse_conn(struct connection **conn, int64_t *hash,
                             struct stconn *sc, struct session *sess,
                             struct server *srv)
{
	int ret;
	struct sockaddr_storage dst;

	/* Reset to ensure <conn> is always initialized */
	*conn = NULL;
	dst = srv->addr;
	set_host_port(&dst, srv->svc_port);
	*hash = be_calculate_conn_hash(srv, NULL, sess, NULL, &dst, IST_NULL);
	ret = be_reuse_connection(*hash, sess, &hld_proxy, srv, sc, &srv->obj_type, 0);
	if (ret == SF_ERR_INTERNAL) {
		TRACE_ERROR("error during connection reuse", HLD_STRM_EV_TASK);
		ret = 0;
		goto leave;
	}

	if (ret == SF_ERR_NONE) {
		TRACE_STATE("performed connection reuse", HLD_STRM_EV_TASK);
		*conn = __sc_conn(sc);
		conn_set_owner(*conn, sess, hld_conn_destroy);
	}

	ret = 1;
 leave:
	return ret;
}

/* This thread's exact share of <rate>, split evenly across arg_thrd
 * threads. Thread <tid> gets (rate + tid) / arg_thrd. The shares
 * always add up to exactly <rate>, with nothing extra from rounding.
 */
static inline uint32_t hld_thr_rate_share(int rate)
{
	if (throttle)
		return (mul32hi(rate, throttle) + tid) / arg_thrd;
	return (rate + tid) / arg_thrd;
}

/* If a new -ee ramp just started, reset this thread's own rate
 * history: it must not carry over data from before the ramp.
 */
static inline void hld_thr_sync_ramp_gen(struct hld_thr_info *ti)
{
	if (HA_ATOMIC_LOAD(&err_ramp_active) && ti->err_ramp_gen != HA_ATOMIC_LOAD(&err_ramp_gen)) {
		memset(&ti->req_rate, 0, sizeof(ti->req_rate));
		memset(&ti->conn_rate, 0, sizeof(ti->conn_rate));
		ti->err_ramp_gen = HA_ATOMIC_LOAD(&err_ramp_gen);
	}
}

/* This thread's send budget for <rate> right now: 0 while <ti> is
 * still ramping up its user count under -s, otherwise its exact
 * share of <rate> (see hld_thr_rate_share()).
 */
static inline uint32_t hld_thr_rate_max(struct hld_thr_info *ti, int rate)
{
	uint32_t maxusrs = ti->maxusrs;

	if (throttle) {
		maxusrs = mul32hi(maxusrs, throttle);
		maxusrs = maxusrs ? maxusrs : 1;
	}

	if (ti->curusrs < maxusrs && throttle)
		return 0;
	return hld_thr_rate_share(rate);
}

/* Schedule <usr> user, depending on <rate> conn/req rate value and on
 * <think>, an already-computed think time in ms (0 if none). The wait
 * used is the larger of the two, same as h1load's -T.
 */
static inline void hld_usr_schedule(struct hld_usr *usr, int rate, uint32_t think)
{
	uint32_t max, wait;
	struct hld_thr_info *ti = &thrs_info[tid];

	hld_thr_sync_ramp_gen(ti);
	max = hld_thr_rate_max(ti, rate);

	if (!max)
		/* this thread has no budget right now (its exact share of
		 * <rate> is 0, or it's still ramping up under -s): nothing
		 * to send from here, just check back shortly.
		 */
		wait = 1000;
	else
		wait = hld_next_event_delay(&ti->req_rate, max,
		                            ti->curusrs - ti->cur_req, date);

	if (think > wait)
		wait = think;

	task_schedule(usr->task, tick_add(now_ms, MS_TO_TICKS(wait)));
}

/* haload stream task handler */
struct task *hld_strm_task(struct task *t, void *context, unsigned int state)
{
	struct hldstream *hs = context, *first_hs;
	struct hld_usr *usr = hs->usr;
	struct hld_url *url = hs->url;
	struct connection *conn = sc_conn(hs->sc);
	struct session *sess = usr->sess;
	struct server *srv = url->cfg->srv;
	int fin = 0;

	TRACE_ENTER(HLD_STRM_EV_TASK, hs);

	if (sc_ep_test(hs->sc, SE_FL_ERROR) || (conn && (conn->flags & CO_FL_ERROR))) {
		TRACE_ERROR("connection error", HLD_STRM_EV_IO_CB, hs);
		hs->flags |= HLD_STRM_ST_CONN_ERR;
		goto err;
	}

	if (tick_is_expired(t->expire, now_ms)) {
		TRACE_STATE("expired task", HLD_STRM_EV_TASK, hs);
		t = NULL;
		goto err;
	}

	if (conn && conn->mux && conn->flags & CO_FL_WAIT_XPRT) {
		TRACE_STATE("waiting for xprt, subscribing to send", HLD_STRM_EV_TASK, hs);
		if (conn->mux->subscribe(hs->sc, SUB_RETRY_SEND, &hs->sc->wait_event) < 0) {
			TRACE_ERROR("send subscribing error", HLD_STRM_EV_TASK, hs);
			goto out;
		}
	}

	if (!hs->conn) {
		struct protocol *proto;
		int flags = arg_fast ? (CONNECT_HAS_DATA|CONNECT_DELACK_ALWAYS) : 0;
		int status;

		BUG_ON(conn);

		hldstream_release_ibuf(hs);
		hldstream_release_obuf(hs);

		conn = conn_new(&srv->obj_type);
		if (!conn) {
			TRACE_ERROR("stconn allocation error", HLD_STRM_EV_TASK, hs);
			goto err;
		}

		conn->hash_node.key = hs->hash;
		// VOIR la CB ici :
		conn_set_owner(conn, sess, hld_conn_destroy);
		BUG_ON(hs->sc->sedesc->sc != hs->sc);
		if (sc_attach_mux(hs->sc, hs->sc->sedesc, conn) < 0) {
			TRACE_ERROR("mux attach error", HLD_STRM_EV_TASK, hs);
			goto err;
		}

		if (!sockaddr_alloc(&conn->dst, NULL, 0)) {
			TRACE_ERROR("sockaddr allocation error", HLD_STRM_EV_TASK, hs);
			goto err;
		}

		*conn->dst = srv->addr;
		proto = protocol_lookup(conn->dst->ss_family,
								srv->addr_type.proto_type, srv->alt_proto);
		set_host_port(conn->dst, srv->svc_port);

		if (conn_prepare(conn, proto, srv->xprt) < 0) {
			TRACE_ERROR("xprt allocation error", HLD_STRM_EV_TASK, hs);
			goto err;
		}

		/* Note that in case of connect() failure, the callback
		 * set by conn_set_owner() is called. Its role is to decrement
		 * the <currconn> counter. So, it must incremented here.
		 */
		thrs_info[tid].curconn++;
		thrs_info[tid].tot_conn++;

		BUG_ON(!proto || !proto->connect);
		status = proto->connect(conn, flags);
		if (status != SF_ERR_NONE) {
			TRACE_ERROR("proto connect error", HLD_STRM_EV_TASK, hs);
			goto err;
		}

		if (HA_ATOMIC_LOAD(&arg_rate))
			hld_update_freq_ctr(&thrs_info[tid].conn_rate, 1, date);

		conn_set_private(conn);
		session_add_conn(sess, conn);
		conn->ctx = hs->sc;

		if (conn_xprt_start(conn) < 0) {
			TRACE_ERROR("could not start xprt", HLD_STRM_EV_TASK, hs);
			goto err;
		}

		if (!conn_is_ssl(conn) || !srv->ssl_ctx.alpn_str) {
			const struct mux_ops *mux_ops;

			if (srv->mux_proto)
				mux_ops = srv->mux_proto->mux;
			else
				mux_ops = conn_get_best_mux(conn, IST_NULL, IST_NULL, PROTO_SIDE_BE, PROTO_MODE_HTTP);
			if (!mux_ops || conn_install_mux(conn, mux_ops, hs->sc, &hld_proxy, sess) < 0) {
				TRACE_ERROR("mux installation failed", HLD_STRM_EV_TASK, hs);
				goto err;
			}
		}

		hs->conn = conn;
		if (conn->flags & CO_FL_WAIT_XPRT) {
			TRACE_STATE("waiting for xprt", HLD_STRM_EV_TASK, hs);
			if (conn->mux) {
				TRACE_STATE("subscribing to send", HLD_STRM_EV_TASK, hs);
				conn->mux->subscribe(hs->sc, SUB_RETRY_SEND, &hs->sc->wait_event);
			}
		}

		goto out;
	}

	if (hs->flags & HLD_STRM_ST_REQ_TO_BUILD) {
		if (!hldstream_build_http_req(hs, ist(hs->path)))
			goto out;

		hs->flags &= ~HLD_STRM_ST_REQ_TO_BUILD;
	}
	else if (hs->to_send && htx_is_empty(htxbuf(&hs->bo))) {
		/* The request headers were already sent but the whole POST body
		 * did not fit in the first buffer. Continue feeding it.
		 */
		if (!hldstream_build_http_body(hs))
			goto out;
	}

	if (!hldstream_htx_buf_snd(conn, hs))
		goto out;

	hldstream_htx_buf_rcv(conn, hs, &fin);

 out:
	if (hs->flags & HLD_STRM_ST_CONN_ERR) {
		TRACE_ERROR("haload stream error", HLD_STRM_EV_TASK, hs);
		goto err;
	}

	if (fin) {
		TRACE_STATE("end of stream", HLD_STRM_EV_TASK, hs);
		goto done;
	}

	/* Update this stream expiration */
	hs->expire = tick_add(now_ms, MS_TO_TICKS(arg_wait));
	/* Requeue it at the end of the usr streams list */
	LIST_DELETE(&hs->list);
	LIST_APPEND(&usr->strms, &hs->list);
	/* Update the user task expiration from the first stream which
	 * is also the stream with the oldest expiration time.
	 */
	first_hs = LIST_ELEM(usr->strms.n, struct hldstream *, list);
	hs->usr->task->expire = first_hs->expire;
	task_queue(hs->usr->task);
 leave:
	TRACE_LEAVE(HLD_STRM_EV_TASK, hs);
	return t;
 done:
	url->tot_rconn_done++;
	thrs_info[tid].cur_req--;
	BUG_ON(arg_rcon > 0 && url->tot_rconn_done > arg_rcon);
	url->mreqs++;
	if (arg_rcon > 0 && url->tot_rconn_done == arg_rcon) {
		/* All the streams attached to this connection will be release */
		TRACE_STATE("releasing connection", HLD_EV_USR_TASK, hs);
		sc_ep_set(hs->sc, SE_FL_KILL_CONN);
		/* Reset these counters here. Cannot be done elsewhere */
		url->tot_rconn_done = 0;
		url->tot_rconn_sent = 0;
		url->mreqs = arg_mreqs;
	}

	LIST_DELETE(&hs->list);
	hldstream_free(&hs);
	t = NULL;

	/* Note that the user task will release all the expired streams
	 * attached to it.
	 */
	if (!HA_ATOMIC_LOAD(&arg_rate) && !url->cfg->thnk_time) {
		task_wakeup(usr->task, TASK_WOKEN_IO);
		if (LIST_ISEMPTY(&usr->strms))
			usr->task->expire = TICK_ETERNITY;
		else {
			/* Update the user task expiration from the first stream which
			 * is also the stream with the oldest expiration time.
			 */
			first_hs = LIST_ELEM(usr->strms.n, struct hldstream *, list);
			usr->task->expire = first_hs->expire;
			task_queue(usr->task);
		}
	}
	else {
		int rate = HA_ATOMIC_LOAD(&arg_rate);
		uint32_t think = 0;

		/* -ee takes over as soon as an error is detected: ignore -T
		 * while it is still probing. -R and -T only apply again once
		 * probing is done and the normal load resumes.
		 */
		if (!HA_ATOMIC_LOAD(&err_ramp_active) && url->cfg->thnk_time)
			think = url->cfg->thnk_time * (4096 - 128 + statistical_prng_range(256)) / 4096;

		if (rate)
			hld_usr_schedule(usr, rate, think);
		else
			task_schedule(usr->task, tick_add(now_ms, MS_TO_TICKS(think)));
	}

	goto leave;
 err:
	TRACE_DEVEL("leaving on error", HLD_STRM_EV_TASK, hs);
	thrs_info[tid].tot_perr++;
	thrs_info[tid].cur_req--;
	url->mreqs++;
	if (arg_rcon > 0) {
		BUG_ON(!url->tot_rconn_sent);
		url->tot_rconn_sent--;
	}
	BUG_ON(arg_rcon > 0 && url->tot_rconn_done > arg_rcon);
	LIST_DELETE(&hs->list);
	hldstream_free(&hs);
	t = NULL;

	if (arg_serr == 2) {
		/* -ee: this user lost its connection. Kill it instead
		 * of retrying it here; hld_rate_task() creates a
		 * replacement at the current ramp rate.
		 */
		usr->flags |= HLD_USR_FL_STOP;
		task_wakeup(usr->task, TASK_WOKEN_IO);
		hld_err_trigger();
	}
	else {
		/* Note that the user task will release all the expired
		 * streams attached to it.
		 */
		if (!HA_ATOMIC_LOAD(&arg_rate))
			task_wakeup(usr->task, TASK_WOKEN_IO);
		else
			hld_usr_schedule(usr, HA_ATOMIC_LOAD(&arg_rate), 0);

		if (arg_serr == 1) {
			usr->flags |= HLD_USR_FL_STOP;
			HA_ATOMIC_STORE(&all_usr_stop_asap, 1);
		}
	}

	goto leave;
}

/* Allocate a new haload stream.
 * Return 1 if succeeded, 0 if not.
 */
static struct hldstream *hld_new_strm(struct hld_usr *usr,
                                      struct hld_url *url,
                                      struct hld_path *path)
{
	struct hldstream *hs;
	struct stconn *sc;
	struct task *t;
	int64_t hash;
	struct connection *conn;

	TRACE_ENTER(HLD_STRM_EV_TASK);
	hs = malloc(sizeof(*hs));
	sc = sc_new_from_hldstream(hs, SC_FL_NONE);
	t = task_new_here();
	if (unlikely(!hs || !sc || !t)) {
		TRACE_ERROR("could not allocate a new stconn", HLD_STRM_EV_TASK);
		goto err;
	}

	/* Mandatory to make sc_attach_mux() identify this stream type */
	hs->obj_type = OBJ_TYPE_HALOAD;
	if (!hld_be_reuse_conn(&conn, &hash, sc, usr->sess, url->cfg->srv)) {
		TRACE_ERROR("internal error during a connection reuse attempt",
		            HLD_STRM_EV_TASK);
		goto err;
	}

	t->context = hs;
	t->process = hld_strm_task;
	t->expire = TICK_ETERNITY;

	hs->conn = conn;
	hs->expire = tick_add(now_ms, MS_TO_TICKS(arg_wait));
	hs->hash = hash;
	hs->usr = usr;
	hs->url = url;
	hs->path = path->path;
	hs->http_meth = path->http_meth;
	hs->meth_ist = path->meth_ist;
	hs->sc = sc;
	hs->bi = hs->bo = BUF_NULL;
	LIST_INIT(&hs->buf_wait.list);
	hs->task = t;
	hs->flags = conn ? HLD_STRM_ST_REQ_TO_BUILD : HLD_STRM_ST_REQ_TO_BUILD;
	hs->state = 0;
	hs->to_send = path->post_sz;
	hs->post_sz = path->post_sz;
	hs->req_date = tv_unset();
	LIST_APPEND(&usr->strms, &hs->list);
	task_wakeup(t, TASK_WOKEN_INIT);

	TRACE_LEAVE(HLD_STRM_EV_TASK, hs);
	return hs;
 err:
	TRACE_DEVEL("leaving on error", HLD_STRM_EV_TASK, hs);
	task_destroy(t);
	sc_destroy(sc);
	free(hs);
	return NULL;
}

static inline struct hld_url *hld_next_url(struct hld_url *list,
                                           struct hld_url *cur)
{
	return cur->next ? cur->next : list;
}

static inline struct hld_path *hld_next_path(struct hld_path *list,
                                             struct hld_path *cur)
{
	return cur->next ? cur->next : list;
}

/* Release the memory allocated for <*usr> user.
 * Also free the session attached to it.
 */
static inline void hld_usr_release(struct hld_usr **usr)
{
	struct hld_url *url;
	struct hld_cookie *ck, *ck_back;

	url = (*usr)->urls;
	while (url) {
		struct hld_url *url_next = url->next;
		ha_free(&url);
		url = url_next;
	}

	list_for_each_entry_safe(ck, ck_back, &(*usr)->cookies, list) {
		LIST_DELETE(&ck->list);
		istfree(&ck->name);
		istfree(&ck->value);
		ha_free(&ck);
	}

	task_destroy((*usr)->task);
	session_free((*usr)->sess);
	ha_free(usr);

	if (arg_serr == 2) {
		/* -ee: update the user count and wake the rate task
		 * so it can create a replacement for this killed user.
		 */
		HA_ATOMIC_DEC(&thrs_info[tid].curusrs);
		if (thrs_info[tid].rate_task)
			task_wakeup(thrs_info[tid].rate_task, TASK_WOKEN_OTHER);
	}

	TRACE_LEAVE(HLD_EV_USR_TASK);
}

static struct task *hld_usr_task(struct task *t, void *context, unsigned int state)
{
	struct hld_usr *usr = context;
	struct hld_url *url, *urls = usr->cur_url, *first_url = urls;
	struct hldstream *hs, *hsbak;
	int nreqs;
	int remain = -1;

	TRACE_ENTER(HLD_EV_USR_TASK);

	if (tick_is_expired(t->expire, now_ms))
		t->expire = TICK_ETERNITY;

	list_for_each_entry_safe(hs, hsbak, &usr->strms, list) {
		if (!tick_is_expired(hs->expire, now_ms))
			break;

		TRACE_STATE("expired task", HLD_EV_USR_TASK, hs);
		/* this stream never got a full response within <arg_wait>:
		 * count it as a failure, not a success
		 */
		thrs_info[tid].tot_perr++;
		hs->url->mreqs++;
		usr->nreqs = usr->nreqs == -1 ? -1 : usr->nreqs + 1;
		LIST_DELETE(&hs->list);
		hldstream_free(&hs);

		if (arg_serr == 1) {
			usr->flags |= HLD_USR_FL_STOP;
			HA_ATOMIC_STORE(&all_usr_stop_asap, 1);
		}
		else if (arg_serr == 2) {
			hld_err_trigger();
		}
	}

	if ((usr->flags & HLD_USR_FL_STOP) || HA_ATOMIC_LOAD(&all_usr_stop_asap)) {
		usr->flags |= HLD_USR_FL_STOP;
		goto skip_new_strms;
	}

	if (HA_ATOMIC_LOAD(&err_ramp_active) && usr->ramp_gen != HA_ATOMIC_LOAD(&err_ramp_gen)) {
		/* This user was scheduled before the current -ee ramp,
		 * under the old rate. Check for room now before it sends.
		 *
		 * Retry with a short, fixed delay if there is none, and
		 * check again next time. hld_usr_schedule()'s wait would
		 * grow with the idle user count instead, which can be huge
		 * right after a mass failure, giving some users a
		 * multi-minute wait with no way back.
		 *
		 * A user created during this ramp already has the right
		 * ramp_gen, so replacements are not affected.
		 */
		struct hld_thr_info *ti = &thrs_info[tid];
		uint32_t rate = HA_ATOMIC_LOAD(&arg_rate);
		uint32_t max = hld_thr_rate_max(ti, rate);

		if (!max || !hld_freq_ctr_remain(&ti->req_rate, max, 0, date)) {
			task_schedule(usr->task, tick_add(now_ms, MS_TO_TICKS(1000)));
			goto skip_new_strms;
		}

		usr->ramp_gen = HA_ATOMIC_LOAD(&err_ramp_gen);
	}

	for (url = urls; url; url = hld_next_url(urls, url)) {
		struct hld_path *path, *paths = url->cfg->cur_path;

		nreqs = usr->nreqs >= 0 ? MIN(usr->nreqs, url->mreqs) : url->mreqs;
		BUG_ON(arg_rcon > 0 && url->tot_rconn_sent > arg_rcon);
		nreqs = arg_rcon > 0 ? MIN(arg_rcon - url->tot_rconn_sent, nreqs) : nreqs;

		for (path = paths; path && nreqs; path = hld_next_path(url->cfg->paths, path)) {
			struct hldstream *hs;

			if ((hs = hld_new_strm(usr, url, path)) == NULL) {
				TRACE_ERROR("could start a new stream task", HLD_EV_USR_TASK);
				goto out;
			}

			if (HA_ATOMIC_LOAD(&arg_rate))
				hld_update_freq_ctr(&thrs_info[tid].req_rate, 1, date);

			thrs_info[tid].cur_req++;
			url->cfg->cur_path = hld_next_path(url->cfg->paths, path);
			BUG_ON(!url->mreqs || !usr->nreqs || !nreqs);

			if (arg_rcon > 0)
				url->tot_rconn_sent++;
			url->mreqs--;
			nreqs--;
			usr->nreqs = usr->nreqs == -1 ? -1 : usr->nreqs - 1;

			if (hs->conn) {
				url->tot_req++;
				remain = hs->conn->mux->avail_streams(hs->conn);
				TRACE_PRINTF(TRACE_LEVEL_PROTO, HLD_STRM_EV_TASK, hs, 0, 0, 0,
				             "remain %d avail. strms", remain);
				if (!remain)
					break;
			}
			else {
				/* Connecting */
				url->tot_req = 1;
				remain = 0;
				break;
			}

			if (!usr->nreqs)
				break;
		}

		if (!usr->nreqs || hld_next_url(urls, url) == first_url)
			break;
	}

 skip_new_strms:
	/* From here, some new streams may have been instantiated or
	 * release upon expiration. This is where this user task
	 * expiration must be updated.
	 */
	if (!LIST_ISEMPTY(&usr->strms)) {
		struct hldstream *first_hs =
			LIST_ELEM(usr->strms.n, struct hldstream *, list);
		BUG_ON(tick_is_expired(first_hs->expire, now_ms));
		usr->task->expire = first_hs->expire;
	}

	if (((usr->flags & HLD_USR_FL_STOP) || !usr->nreqs) && LIST_ISEMPTY(&usr->strms)) {
		HA_ATOMIC_DEC(&running_tasks);
		hld_usr_release(&usr);
		t = NULL;
		goto out;
	}

 out:
	TRACE_LEAVE(HLD_EV_USR_TASK);
	return t;
}

/* Instantiate a haload user and wake up its underlying task */
static inline struct hld_usr *hld_new_usr(int nreqs, int tid)
{
	struct hld_usr *usr;
	struct hld_url_cfg *cfg;
	struct hld_url *url, *urls = NULL, *next_url;
	struct task *t;
	struct session *sess;

	BUG_ON(!nreqs);
	t = task_new_on(tid);
	sess = session_new(&hld_proxy, NULL, NULL);
	if (!t || !sess) {
		ha_alert("could not allocate a new user\n");
		goto err_deps;
	}

	usr = malloc(sizeof(*usr));
	if (!usr) {
		ha_alert("could not allocate a new user\n");
		goto err_deps;
	}

	t->process = hld_usr_task;
	t->context = usr;
	t->expire = TICK_ETERNITY;

	usr->task = t;
	usr->sess = sess;
	usr->flags = 0;
	usr->urls = NULL;
	usr->nreqs = nreqs;
	usr->ramp_gen = HA_ATOMIC_LOAD(&err_ramp_gen);
	LIST_INIT(&usr->strms);
	LIST_INIT(&usr->cookies);

	for (cfg = hld_url_cfgs; cfg; cfg = cfg->next) {
		struct hld_url *url;

		url = malloc(sizeof(*url));
		if (!url)
			goto err;

		url->tot_req = 0;
		url->tot_rconn_done = 0;
		url->tot_rconn_sent = 0;
		url->mreqs = arg_mreqs;
		url->cfg = cfg;
		url->next = usr->urls;
		usr->urls = url;
	}

	HA_ATOMIC_INC(&thrs_info[tid].curusrs);
	/* inverse the URLs order */
	url = usr->urls;
	while (url) {
		next_url = url->next;
		url->next = urls;
		urls = url;
		url = next_url;
	}
	usr->urls = urls;

	usr->cur_url = usr->urls;
	task_wakeup(t, TASK_WOKEN_INIT);
	return usr;

 err:
	url = usr->urls;
	while (url) {
		next_url = url->next;
		free(url);
		url = next_url;
	}
	free(usr);

 err_deps:
	if (sess)
		session_free(sess);
	task_destroy(t);
	return NULL;
}

/* Parse <opt> options for <s> server */
static int hld_srv_parse_opts(char *opts, struct server *s)
{
	int ret = 0;
	size_t outlen = 256;
	int cur_arg = 0;
	char *outline;
	uint32_t err;
	int err_code;
	int arg = sizeof(hld_args) / sizeof(*hld_args);
	const char *errptr = NULL;

	outline = malloc(256);
	if (!outline)
		return 0;

	err = parse_line(opts, outline, &outlen, hld_args, &arg,
					 PARSE_OPT_ENV    | PARSE_OPT_DQUOTE  |
					 PARSE_OPT_SQUOTE | PARSE_OPT_BKSLASH |
					 PARSE_OPT_SHARP  | PARSE_OPT_WORD_EXPAND, &errptr);
	if (err) {
		ha_alert("ssl opts parsing error\n");
		goto err;
	}

	while (*hld_args[cur_arg]) {
		err_code = _srv_parse_kw(s, hld_args, &cur_arg, &hld_proxy, 0);
		if (err_code)
			goto err;
	}

	ret = 1;
 leave:
	free(outline);
	return ret;
 err:
	goto leave;
}

static int hld_cfg_finalize(void)
{
	int ret = 0;
	int fcgi_used = 0;
	struct hld_url_cfg *cfg;

	for (cfg = hld_url_cfgs; cfg; cfg = cfg->next) {
		struct server *srv;
		struct sockaddr_storage *sk;
		int alt_proto, port;
		char *errmsg = NULL;

		/* Same as _srv_parse_init() from here */
		srv = new_server(&hld_proxy);
		if (!srv) {
			ha_alert("could not allocate a new server\n");
			goto leave;
		}

		sk = str2sa_range(cfg->addr, &port, NULL, NULL, NULL, NULL,
						  &srv->addr_type, &errmsg, NULL, NULL, &alt_proto,
						  PA_O_PORT_OK | PA_O_STREAM | PA_O_DGRAM | PA_O_XPRT);
		if (!sk) {
			ha_alert("%s\n", errmsg);
			ha_free(&errmsg);
			goto leave;
		}

		srv->id = strdup("haload");
		srv->addr = *sk;
		srv->svc_port = port;
		srv->alt_proto = alt_proto;
		srv->use_ssl = cfg->ssl;
		srv->xprt = srv_is_quic(srv) ? xprt_get(XPRT_QUIC) :
			srv->use_ssl ? xprt_get(XPRT_SSL) : xprt_get(XPRT_RAW);

#ifdef USE_QUIC
		if (srv_is_quic(srv))
			quic_transport_params_init(&srv->quic_params, 0);
#endif

		/* XXX Must this be done? XXX */
		//srv_set_addr_desc(srv, 0);
		srv_settings_init(srv);

		if (cfg->srv_opts && !hld_srv_parse_opts(cfg->srv_opts, srv))
			goto leave;

		if (cfg->tls_opts && !hld_srv_parse_opts(cfg->tls_opts, srv))
			goto leave;

		/* Same as _srv_parse_finalize() from here */
		if (srv_is_quic(srv)) {
			if (!srv->use_ssl)
				srv->use_ssl = 1;

			if (!srv->ssl_ctx.alpn_str) {
				srv->ssl_ctx.alpn_str = strdup("\002h3");
				if (!srv->ssl_ctx.alpn_str) {
					ha_alert("could not allocate a default alpn.\n");
					goto leave;
				}

				srv->ssl_ctx.alpn_len = strlen(srv->ssl_ctx.alpn_str);
			}
		}

		if (!srv->mux_proto) {
			if (srv_is_quic(srv))
				srv->mux_proto = get_mux_proto(ist("quic"));
			else if (cfg->h2c)
				srv->mux_proto = get_mux_proto(ist("h2"));
			else if (cfg->fcgi)
				srv->mux_proto = get_mux_proto(ist("fcgi"));
		}

		if (srv->mux_proto) {
			int proto_mode = conn_pr_mode_to_proto_mode(hld_proxy.mode);
			const struct mux_proto_list *mux_ent;

			mux_ent = conn_get_best_mux_entry(srv->mux_proto->mux_proto, IST_NULL,
			                                  PROTO_SIDE_BE,
			                                  srv_is_quic(srv), proto_mode);

			if (!mux_ent || !isteq(mux_ent->mux_proto, srv->mux_proto->mux_proto)) {
				ha_alert("MUX protocol is not usable for server.\n");
				goto leave;
			}
			else {
				if ((mux_ent->mux->flags & MX_FL_FRAMED) && !srv_is_quic(srv)) {
					ha_alert("MUX protocol is incompatible with stream"
					         " transport used by server.\n");
					goto leave;
				}
				else if (!(mux_ent->mux->flags & MX_FL_FRAMED) && srv_is_quic(srv)) {
					ha_alert("MUX protocol is incompatible with framed"
					         " transport used by server.\n");
					goto leave;
				}
			}
		}

		/* ensure minconn/maxconn consistency */
		srv_minmax_conn_apply(srv);

		if (srv->use_ssl) {
			if (xprt_get(XPRT_SSL) && xprt_get(XPRT_SSL)->prepare_srv) {
				if (xprt_get(XPRT_SSL)->prepare_srv(srv))
					goto leave;
			}
			/* XXX TO CHECK XXX: in fact XPRT_SSL and XPRT_QUIC have the same
			 * ->prepare_srv() callback.
			 */
			else if (xprt_get(XPRT_QUIC) && xprt_get(XPRT_QUIC)->prepare_srv) {
				if (xprt_get(XPRT_QUIC)->prepare_srv(srv))
					goto leave;
			}
		}

		if (srv_preinit(srv))
			goto leave;
#if 0
		/* XXX Must this be done? XXX */
		if (!srv_alloc_lb(srv, &hld_proxy)) {
			ha_alert("Failed to initialize load-balancing data.\n");
			goto leave;
		}
#endif

		if (!stats_allocate_proxy_counters_internal(&srv->extra_counters,
		                                            COUNTERS_SV, STATS_PX_CAP_SRV,
		                                            &srv->per_tgrp->extra_counters_storage,
		                                            &srv->per_tgrp[1].extra_counters_storage -
		                                            &srv->per_tgrp[0].extra_counters_storage)) {
			ha_alert("failed to allocate extra counters for server.\n");
			goto leave;
		}

		if (srv_postinit(srv))
			goto leave;

		/* Attach the server to the URL */
		cfg->srv = srv;
		if (cfg->fcgi)
			fcgi_used = 1;
	}

	if (fcgi_used) {
		/* same as "use-fcgi-app haload" at config parsing time */
		struct fcgi_flt_conf *fcgi_conf;
		struct flt_conf *fconf;

		fcgi_conf = calloc(1, sizeof(*fcgi_conf));
		fconf = calloc(1, sizeof(*fconf));
		if (!fcgi_conf || !fconf) {
			ha_alert("could not allocate the FCGI filter config\n");
			goto leave;
		}

		fcgi_conf->name = strdup("haload");
		if (!fcgi_conf->name) {
			ha_alert("could not allocate the FCGI app name\n");
			goto leave;
		}

		LIST_INIT(&fcgi_conf->param_rules);
		LIST_INIT(&fcgi_conf->hdr_rules);

		/* same as fcgi_flt_check() does at post-parsing time */
		fcgi_conf->app = fcgi_app_find_by_name(fcgi_conf->name);
		if (!fcgi_conf->app) {
			ha_alert("fcgi-app 'haload' not found. Did you pass --fcgi-app with a \"docroot\"?\n");
			goto leave;
		}

		fconf->id = fcgi_flt_id;
		fconf->conf = fcgi_conf;
		fconf->ops = &fcgi_flt_ops;
		LIST_APPEND(&hld_proxy.filter_configs, &fconf->list);
	}

	ret = 1;
leave:
	return ret;
}

/* this is in order to cleanly stop on Ctrl-C */
void sigint_handler(int sig)
{
	/* make sure a second Ctrl-C really stops */
	HA_ATOMIC_STORE(&all_usr_stop_asap, 1);
	signal(SIGINT, SIG_DFL);
}

/* Report ttfb/ttlb percentiles collected under -P, merging every
 * thread's counters into thread 0's first.
 */
static void hld_report_percentiles(void)
{
	uint64_t tot_ttfb, tot_ttlb;
	uint64_t cur_ttfb, cur_ttlb;
	int ttfb_idx, ttlb_idx;
	double points[100];
	double pct;
	int nbpts;
	int i, t;

	/* build percentile points from 10% up to 100% */
	nbpts = 0; pct = 0.1;
	for (; (points[nbpts] = pct) < 0.500000; nbpts++, pct += 0.1);
	for (; (points[nbpts] = pct) < 0.800000; nbpts++, pct += 0.05);
	for (; (points[nbpts] = pct) < 0.900000; nbpts++, pct += 0.02);
	for (; (points[nbpts] = pct) < 0.950000; nbpts++, pct += 0.01);
	for (; (points[nbpts] = pct) < 0.990000; nbpts++, pct += 0.005);
	for (; (points[nbpts] = pct) < 0.995000; nbpts++, pct += 0.001);
	for (; (points[nbpts] = pct) < 0.999000; nbpts++, pct += 0.0005);
	for (; (points[nbpts] = pct) < 0.999500; nbpts++, pct += 0.0001);
	for (; (points[nbpts] = pct) < 0.999900; nbpts++, pct += 0.00005);
	for (; (points[nbpts] = pct) < 0.999950; nbpts++, pct += 0.00001);
	for (; (points[nbpts] = pct) < 0.999990; nbpts++, pct += 0.000005);
	for (; (points[nbpts] = pct) < 0.999995; nbpts++, pct += 0.000005);
	for (; (points[nbpts] = pct) < 0.999999; nbpts++, pct += 0.000004);
	for (; (points[nbpts] = pct) < 1.000000; nbpts++, pct += 0.000001);

	/* merge every thread's counters into thread 0's */
	for (t = 1; t < arg_thrd; t++) {
		for (i = 0; i < 65536; i++) {
			thrs_info[0].ttfb_pct[i] += thrs_info[t].ttfb_pct[i];
			thrs_info[0].ttlb_pct[i] += thrs_info[t].ttlb_pct[i];
		}
	}

	tot_ttfb = tot_ttlb = 0;
	for (i = 0; i < 65536; i++) {
		tot_ttfb += thrs_info[0].ttfb_pct[i];
		tot_ttlb += thrs_info[0].ttlb_pct[i];
	}

	printf("#======= Percentiles for time-to-first-byte and time-to-last-byte =======\n");
	printf("# use $3:$5 $3:$7 with logscale X\n");
	printf("# $1     $2      $3         $4       $5         $6       $7\n");
	printf("#pctl   tail   invtail   ttfbcnt ttfb(ms)   ttlbcnt ttlb(ms)\n");

	cur_ttfb = cur_ttlb = 0;
	ttfb_idx = ttlb_idx = 0;
	for (i = 0; i < nbpts; i++) {
		while (ttfb_idx < 65536 && cur_ttfb + thrs_info[0].ttfb_pct[ttfb_idx] < points[i] * tot_ttfb)
			cur_ttfb += thrs_info[0].ttfb_pct[ttfb_idx++];

		while (ttlb_idx < 65536 && cur_ttlb + thrs_info[0].ttlb_pct[ttlb_idx] < points[i] * tot_ttlb)
			cur_ttlb += thrs_info[0].ttlb_pct[ttlb_idx++];

		printf("%-7g %-6g %-7.f %9llu %8g %9llu %8g\n",
		       points[i]*100.0, 100.0*(1.0-points[i]),
		       points[i] == 1.0 ? 250000 : 1.0/(1.0-points[i]),
		       (unsigned long long)cur_ttfb, (double)from_uf16(ttfb_idx) / 1000.0,
		       (unsigned long long)cur_ttlb, (double)from_uf16(ttlb_idx) / 1000.0);
	}
}

/* Deallocate the thread information structs */
static void hld_dealloc_thrs_info(void)
{
	int i;

	if (!thrs_info)
		return;

	for (i = 0; i < arg_thrd; i++) {
		task_destroy(thrs_info[i].rate_task);
		thrs_info[i].rate_task = NULL;
		free(thrs_info[i].ttfb_pct);
		free(thrs_info[i].ttlb_pct);
	}

	free(thrs_info);
	thrs_info = NULL;
}

/* Thread task launched to handle the connection and request rate */
static struct task *hld_rate_task(struct task *t, void *context, unsigned int state)
{
	if (HA_ATOMIC_LOAD(&all_usr_stop_asap)) {
		/* the test is ending: destroy this task for good, even
		 * under -ee where it would otherwise stay alive and idle.
		 */
		HA_ATOMIC_DEC(&running_tasks);
		task_destroy(t);
		thrs_info[tid].rate_task = NULL;
		return NULL;
	}

	if (thrs_info[tid].curusrs < thrs_info[tid].maxusrs) {
		int budget = -1;
		uint32_t max;
		uint32_t b1, b2;
		int nb_usr = thrs_info[tid].maxusrs;

		hld_thr_sync_ramp_gen(&thrs_info[tid]);

		if (throttle) {
			nb_usr = mul32hi(thrs_info[tid].maxusrs, throttle);
			nb_usr = nb_usr ? nb_usr : 1;
		}

		if (!HA_ATOMIC_LOAD(&arg_rate) && !HA_ATOMIC_LOAD(&err_ramp_pending) &&
		    HA_ATOMIC_LOAD(&usr_cnt) >= arg_usr) {
			/* 0 means no rate limit here too. Only do this after
			 * the main task's initial ramp-up (usr_cnt >= arg_usr):
			 * fill up to nb_usr directly, no per-thread budget, so
			 * a kill under -ee can still be refilled without -R.
			 *
			 * err_ramp_pending is checked too. It is set first by
			 * hld_err_trigger(). Seeing it at 0 means no other
			 * thread just started a trigger.
			 */
			budget = nb_usr;
		}
		else {
			max = hld_thr_rate_share(HA_ATOMIC_LOAD(&arg_rate));

			/* max may be 0 here: this thread's exact share of the rate is
			 * 0 right now (either a real rate cap, or the initial
			 * ramp-up is still the main task's job). hld_freq_ctr_remain()
			 * below handles freq=0 fine (just returns no budget), no
			 * need to force max to 1.
			 */
			b1 = hld_freq_ctr_remain(&thrs_info[tid].conn_rate, max, 0, date);
			b2 = hld_freq_ctr_remain(&thrs_info[tid].req_rate, max,
			                         thrs_info[tid].curusrs - thrs_info[tid].cur_req, date);
			budget = (!b2 || b1 <= b2) ? b1 : b2;
		}

		while (thrs_info[tid].curusrs < nb_usr && budget--) {
			struct hld_usr *hu;
			int req = arg_reqs == -1 ? -1 : (arg_reqs + tid) / arg_usr;

			hu = hld_new_usr(req, tid);
			if (!hu) {
				ha_alert("could not allocate a new haload user\n");
				break;
			}

			/* count this new user right now, not later when it
			 * really connects. Without this, a fast re-wakeup of
			 * this task (many kills in a row) would still see an
			 * empty counter and create too many replacements.
			 */
			hld_update_freq_ctr(&thrs_info[tid].conn_rate, 1, date);
			HA_ATOMIC_INC(&running_tasks);
		}

		task_schedule(t, tick_add(now_ms, MS_TO_TICKS(100)));
	}
	else {
		if (arg_serr != 2) {
			HA_ATOMIC_DEC(&running_tasks);
			t->expire = TICK_ETERNITY;
			task_destroy(t);
			thrs_info[tid].rate_task = NULL;
			t = NULL;
		}
		else {
			/* -ee: recheck later instead of staying idle
			 * forever. This is how we notice the test is
			 * ending (see the all_usr_stop_asap check above)
			 * even if no user gets killed in the meantime.
			 */
			task_schedule(t, tick_add(now_ms, MS_TO_TICKS(1000)));
		}
	}

	return t;
}

/* Allocate all thread information structs */
static int hld_alloc_thrs_info(void)
{
	int i, ret = 0;

	thrs_info = calloc(arg_thrd, sizeof(*thrs_info));
	if (!thrs_info) {
		ha_alert("failed to alloct threads information array.\n");
		goto out;
	}

	for (i = 0; i < arg_thrd; i++) {
		thrs_info[i].maxusrs = (arg_usr + i) / arg_thrd;
		if (arg_pctl) {
			thrs_info[i].ttfb_pct = calloc(1 << 16, sizeof(*thrs_info[i].ttfb_pct));
			thrs_info[i].ttlb_pct = calloc(1 << 16, sizeof(*thrs_info[i].ttlb_pct));
			if (!thrs_info[i].ttfb_pct || !thrs_info[i].ttlb_pct) {
				ha_alert("could not allocate percentile counters\n");
				goto out;
			}
		}

		if (HA_ATOMIC_LOAD(&arg_rate) || arg_serr == 2) {
			struct task *t;

			t = task_new_on(i);
			if (!t) {
				ha_alert("could not allocate a new task for req rate\n");
				goto out;
			}

			t->process = hld_rate_task;
			t->expire = TICK_ETERNITY;
			task_wakeup(t, TASK_WOKEN_INIT);
			thrs_info[i].rate_task = t;
			HA_ATOMIC_INC(&running_tasks);
		}
	}

	ret = 1;
 out:
	return ret;
}

static int hld_init(void)
{
	int ret = ERR_ALERT | ERR_FATAL;
	char *errmsg = NULL;

	if (arg_slow)
		throttle = 1;

	if (!hld_cfg_finalize())
		goto err;

	/* used by -ee to compute its per-target rate floor; count once here
	 * since hld_url_cfgs never changes once the config is finalized.
	 */
	hld_nb_url_cfg = 0;
	{
		struct hld_url_cfg *cfg;

		for (cfg = hld_url_cfgs; cfg; cfg = cfg->next)
			hld_nb_url_cfg++;
	}
	if (!hld_nb_url_cfg)
		hld_nb_url_cfg = 1;

	/* This is the location to initialize the default value for <arg_thrd>.
	 * Indeed, global.nthread is initialized late(after the parsing step).
	 */
	if (arg_thrd == 0)
		arg_thrd = global.nbthread;

	/* -ee's rate floor: 1 conn/req per sec, per URL. Threads don't come
	 * into this on purpose: a floor that grows with the thread count
	 * would make -ee's probing far from gentle on big machines.
	 * hld_nb_url_cfg is fixed by now, so compute this once instead of
	 * on every -ee trigger.
	 */
	err_rate_floor = hld_nb_url_cfg;
	err_success_target = (uint64_t)HLD_EE_SUCCESS_PER_URL * hld_nb_url_cfg;

	if (HA_ATOMIC_LOAD(&arg_rate) && arg_thrd > arg_usr) {
		ha_alert("Thread count (%d) must not exceed connection count (%d)\n",
		         arg_thrd, arg_usr);
		goto err;
	}

	BUG_ON(arg_thrd != global.nbthread);

	/* Consider the case where <arg_reqs> < <arg_usr> */
	if (arg_reqs != -1 && arg_reqs < arg_usr)
		arg_usr = arg_reqs;

	if (!hld_alloc_thrs_info())
		goto err;

	mtask.t = task_new_here();
	if (mtask.t == NULL) {
		ha_alert("could start main task\n");
		goto err;
	}

	mtask.t->process = mtask_cb;
	mtask.t->state |= TASK_RT;
	mtask.t->expire = TICK_ETERNITY;
	mtask.show_time = tick_add(now_ms, MS_TO_TICKS(1000));

	task_wakeup(mtask.t, TASK_WOKEN_INIT);

	gettimeofday(&hld_start_date, NULL);
	if (arg_dura)
		tv_ms_add(&hld_stop_date, &hld_start_date, arg_dura * 1000);
	else
		hld_stop_date = tv_unset();

	signal(SIGINT, sigint_handler);

	ret = ERR_NONE;
 leave:
	ha_free(&errmsg);
	return ret;
 err:
	hld_dealloc_thrs_info();
	goto leave;
}
REGISTER_POST_CHECK(hld_init);

/* Build the POST data buffer.
 * Always succeeds.
 */
static int hldstream_build_post_data(void)
{
	int i;

	for (i = 0; i < sizeof(hld_post_data); i++) {
		if (i % HLD_POST_DATA_LINE_SZ == HLD_POST_DATA_LINE_SZ - 1)
			hld_post_data[i] = '\n';
		else if (i % 10 == 0)
			hld_post_data[i] = '.';
		else
			hld_post_data[i] = '0' + i % 10;
	}

	return 1;
}
REGISTER_POST_CHECK(hldstream_build_post_data);
