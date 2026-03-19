#include <openssl/ssl.h>

#include <haproxy/api.h>
#include <haproxy/dynbuf.h>
#include <haproxy/errors.h>
#include <haproxy/http.h>
#include <haproxy/http_htx.h>
#include <haproxy/htx.h>
#include <haproxy/hldstream.h>
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

#if 1
#define DDPRINTF(x...) fprintf(x)
#else
#define DDPRINTF(x...) do {} while(0)
#endif

/* haload stream state flags */
#define HLD_STRM_ST_IN_ALLOC     0x0001
#define HLD_STRM_ST_OUT_ALLOC    0x0002
#define HLD_STRM_ST_CONN_ERR     0x0004
#define HLD_STRM_ST_HDRS_SENT    0x0008
#define HLD_STRM_ST_REQ_TO_BUILD 0x0010
#define HLD_STRM_ST_MUST_RECV    0x0020
#define HLD_STRM_ST_GOT_RESP_SL  0x0040

#define HLD_URL_ST_NEED_CONNECT  0x0001

struct hld_freq_ctr {
	uint32_t curr_sec; /* start date of current period (seconds from now.tv_sec) */
	uint32_t curr_ctr; /* cumulated value for current period */
	uint32_t prev_ctr; /* value for last period */

};

struct hld_thr_info {
	struct timeval now;          // current time
	struct hld_freq_ctr req_rate;    // thread's measured request rate
	struct hld_freq_ctr conn_rate;   // thread's measured connection rate
	uint32_t cur_req;            // number of active requests
	uint32_t curconn;            // number of active connections
	uint32_t maxconn;            // max number of active connections
	uint32_t is_ssl;             // non-zero if SSL is used
	uint64_t tot_conn;           // total conns attempted on this thread
	//uint64_t tot_req;            // total requests started on this thread
	uint64_t tot_done;           // total requests finished (successes+failures)
	uint64_t tot_sent;           // total bytes sent on this thread
	uint64_t tot_rcvd;           // total bytes received on this thread
	uint64_t tot_serr;           // total socket errors on this thread
	uint64_t tot_cerr;           // total connection errors on this thread
	uint64_t tot_xerr;           // total xfer errors on this thread
	uint64_t tot_perr;           // total protocol errors on this thread
	uint64_t tot_cto;            // total connection timeouts on this thread
	uint64_t tot_xto;            // total xfer timeouts on this thread
	uint64_t tot_fbs;            // total number of ttfb samples
	uint64_t tot_ttfb;           // total time-to-first-byte (us)
	uint64_t tot_lbs;            // total number of ttlb samples
	uint64_t tot_ttlb;           // total time-to-last-byte (us)
	uint64_t *ttfb_pct;          // counts per ttfb value for percentile
	uint64_t *ttlb_pct;          // counts per ttlb value for percentile
	uint64_t tot_sc[5];          // total status codes on this thread: 1xx,2xx,3xx,4xx,5xx
	//int epollfd;                 // poller's FD
	int start_len;               // request's start line's length
	char *start_line;            // copy of the request's start line to be sent
	char *hdr_block;             // copy of the request's header block to be sent
	int hdr_len;                 // request's header block's length
	int ka_req_len;              // keep-alive request length
	char *ka_req;                // fully assembled keep-alive request
	char *cl_req;                // fully assembled close request
	int cl_req_len;              // close request length
	__attribute__((aligned(64))) union { } __pad;
};

struct hld_usr {
	struct task *task;
	struct session *sess;
	struct list strms;
	struct hld_url *urls;
	struct hld_url *cur_url;
	int flags;
};

struct hld_thr_info *thrs_info;

struct list hld_hdrs = LIST_HEAD_INIT(hld_hdrs);
struct proxy hld_proxy;
struct task *mtask; // main task (stats listing every 1s)

const char *arg_host;
const char *arg_conn_hdr;
const char *arg_uri;
const char *arg_path;

int arg_accu;          // more accurate req/time measurements in keep-alive
int arg_dura;          // test duration in sec if non-nul
int arg_long;          // long output format; 2=raw values
int arg_mreqs = 1;     // max concurrent streams by connection
int arg_rcon;          // max requests per conn
int arg_reqs = -1;     // max total requests
int arg_usr = 1;       // number of users
int arg_wait = 10000;  // I/O time out (ms)
int arg_head;          // use HEAD
int arg_hscd;          // HTTP status code distribution

int conn_tid;

char *hld_args[MAX_LINE_ARGS + 1];

/************ time manipulation functions ***************/

struct timeval hld_start_date, hld_stop_date, hld_now;
volatile uint32_t throttle = 0;  // pass to mul32hi() if not null.

/* timeval is not set */
#define TV_UNSET ((struct timeval){ .tv_sec = 0, .tv_usec = ~0 })

/* make a timeval from <sec>, <usec> */
__attribute__((unused))
static inline struct timeval tv_set(time_t sec, suseconds_t usec)
{
	struct timeval ret = { .tv_sec = sec, .tv_usec = usec };
	return ret;
}

/* used to unset a timeout */
__attribute__((unused))
static inline struct timeval tv_unset(void)
{
	return tv_set(0, ~0);
}

/* returns the interval in microseconds, which must be set */
static inline uint64_t tv_us(const struct timeval tv)
{
	return tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
}

#if 0
/* used to zero a timeval */
static inline struct timeval tv_zero(void)
{
	return tv_set(0, 0);
}

/* returns true if the timeval is set */
static inline int tv_isset(struct timeval tv)
{
	return tv.tv_usec != ~0;
}

/* returns true if <a> is before <b>, taking account unsets */
static inline int tv_isbefore(const struct timeval a, const struct timeval b)
{
	return !tv_isset(b) ? 1 :
	       !tv_isset(a) ? 0 :
	       ( a.tv_sec < b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_usec < b.tv_usec));
}

/* returns the lowest of the two timers, for use in delay computation */
static inline struct timeval tv_min(const struct timeval a, const struct timeval b)
{
	if (tv_isbefore(a, b))
		return a;
	else
		return b;
}

/* returns the normalized sum of the <from> plus <off> */
static inline struct timeval tv_add(const struct timeval from, const struct timeval off)
{
	struct timeval ret;

	ret.tv_sec  = from.tv_sec  + off.tv_sec;
	ret.tv_usec = from.tv_usec + off.tv_usec;

	if (ret.tv_usec >= 1000000) {
		ret.tv_usec -= 1000000;
		ret.tv_sec  += 1;
	}
	return ret;
}

/* returns the normalized sum of <from> plus <ms> milliseconds */
static inline struct timeval tv_ms_add(const struct timeval from, unsigned int ms)
{
	struct timeval tv;

	tv.tv_usec = from.tv_usec + (ms % 1000) * 1000;
	tv.tv_sec  = from.tv_sec  + (ms / 1000);
	if (tv.tv_usec >= 1000000) {
		tv.tv_usec -= 1000000;
		tv.tv_sec++;
	}
	return tv;
}
#endif

/* returns the delay between <past> and <now> or zero if <past> is after <now> */
__attribute__((unused))
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

#if 0
/* returns the time remaining between <tv1> and <tv2>, or zero if passed */
static inline struct timeval tv_remain(const struct timeval tv1, const struct timeval tv2)
{
	struct timeval tv;

	tv.tv_usec = tv2.tv_usec - tv1.tv_usec;
	tv.tv_sec  = tv2.tv_sec  - tv1.tv_sec;
	if ((signed)tv.tv_sec > 0) {
		if ((signed)tv.tv_usec < 0) {
			tv.tv_usec += 1000000;
			tv.tv_sec--;
		}
	} else if (tv.tv_sec == 0) {
		if ((signed)tv.tv_usec < 0)
			tv.tv_usec = 0;
	} else {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
	}
	return tv;
}

/* returns the time remaining between <tv1> and <tv2> in milliseconds rounded
 * up to the next millisecond, or zero if passed.
 */
static inline unsigned long tv_ms_remain(const struct timeval tv1, const struct timeval tv2)
{
	struct timeval tv;

	tv = tv_remain(tv1, tv2);
	return tv.tv_sec * 1000 + (tv.tv_usec + 999) / 1000;
}


/* Multiply the two 32-bit operands and shift the 64-bit result right 32 bits.
 * This is used to compute fixed ratios by setting one of the operands to
 * (2^32*ratio).
 */
static inline uint32_t mul32hi(uint32_t a, uint32_t b)
{
	return ((uint64_t)a * b + a - 1) >> 32;
}
#endif

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
__attribute__((unused))
static inline void hdl_update_freq_ctr(struct hld_freq_ctr *ctr, uint32_t inc,
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

	chunk_appendf(&trace_buf, " hs@%p conn@%p se@%p to_send=%u",
	              hs, __sc_conn(hs->sc), __sc_endp(hs->sc), htxbuf(&hs->bo)->data);
	if (hs->sc) {
		struct connection *conn = sc_conn(hs->sc);
		chunk_appendf(&trace_buf, " - conn=%p(0x%08x)", conn, conn ? conn->flags : 0);
		chunk_appendf(&trace_buf, " sc=%p(0x%08x)", hs->sc, hs->sc->flags);
	}
}

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

static inline struct buffer *hldstream_get_obuf(struct hldstream *hs)
{
	return hldstream_get_buf(hs, &hs->bo);
}

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

static inline void hldstream_release_ibuf(struct hldstream *hs)
{
	hldstream_release_buf(hs, &hs->bi);
}

static inline void hldstream_release_obuf(struct hldstream *hs)
{
	hldstream_release_buf(hs, &hs->bo);
}

static inline void hldstream_free(struct hldstream **hs)
{
	struct hldstream *h = *hs;

	//fprintf(stderr, "%s sc_destroy(%p)\n", __func__, h->sc);
	sc_destroy(h->sc);
	TRACE_PRINTF(TRACE_LEVEL_PROTO, HLD_STRM_EV_TASK, hs, 0, 0, 0,
	             "freeing %p stream", h);
	hldstream_release_ibuf(h);
	hldstream_release_obuf(h);
	ha_free(hs);
	TRACE_LEAVE(HLD_STRM_EV_TASK);
}


/* Creates a new stream connector from a haload connection. There is no endpoint
 * here, thus it will be created by sc_new(). So the SE_FL_DETACHED flag is set.
 * It returns NULL on error. On success, the new stream connector is returned.
 */
struct stconn *sc_new_from_hldstream(struct hldstream *hs, unsigned int flags)
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
	static char str[5];
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

/* reports current date (now) and aggragated stats */
void hld_summary(void)
{
	int th;
	uint64_t cur_conn, tot_conn, tot_req, tot_err, tot_rcvd, bytes;
	uint64_t tot_ttfb, tot_ttlb, tot_fbs, tot_lbs, tot_sc[5];
	static uint64_t prev_totc, prev_totr, prev_totb;
	static uint64_t prev_ttfb, prev_ttlb, prev_fbs, prev_lbs, prev_sc[5];
	static struct timeval prev_date = TV_UNSET;
	double interval;

	cur_conn = tot_conn = tot_req = tot_err = tot_rcvd = 0;
	tot_ttfb = tot_ttlb = tot_fbs = tot_lbs = 0;
	tot_sc[0] = tot_sc[1] = tot_sc[2] = tot_sc[3] = tot_sc[4] = 0;

	for (th = 0; th < global.nbthread; th++) {
		cur_conn += HA_ATOMIC_LOAD(&thrs_info[th].curconn);
		tot_conn += HA_ATOMIC_LOAD(&thrs_info[th].tot_conn);
		tot_req  += HA_ATOMIC_LOAD(&thrs_info[th].tot_done);
		tot_err  += HA_ATOMIC_LOAD(&thrs_info[th].tot_serr) +
		            HA_ATOMIC_LOAD(&thrs_info[th].tot_cerr) +
		            HA_ATOMIC_LOAD(&thrs_info[th].tot_xerr) +
		            HA_ATOMIC_LOAD(&thrs_info[th].tot_perr);
		tot_rcvd += HA_ATOMIC_LOAD(&thrs_info[th].tot_rcvd);
		tot_ttfb += HA_ATOMIC_LOAD(&thrs_info[th].tot_ttfb);
		tot_ttlb += HA_ATOMIC_LOAD(&thrs_info[th].tot_ttlb);
		tot_fbs  += HA_ATOMIC_LOAD(&thrs_info[th].tot_fbs);
		tot_lbs  += HA_ATOMIC_LOAD(&thrs_info[th].tot_lbs);
		tot_sc[0]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[0]);
		tot_sc[1]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[1]);
		tot_sc[2]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[2]);
		tot_sc[3]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[3]);
		tot_sc[4]+= HA_ATOMIC_LOAD(&thrs_info[th].tot_sc[4]);
	}

#if 0
	/* when called after having stopped, check if we need to dump a final
	 * line or not, to cover for the rare cases of the last thread
	 * finishing just after the last summary line
	 */
	if (!(running & THR_COUNT) && (prev_date.tv_sec == now.tv_sec) &&
	     (prev_totc == tot_conn) && (prev_totr == tot_req) && (prev_totb == tot_rcvd))
		return;
#endif

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
#if 0
	if (arg_ovrp) {
		long small_pkt = (bytes + (arg_ovrp - 1)) / arg_ovrp;
		/* we need to account for overhead also on small packets and
		 * at minima once per response.
		 */
		if (small_pkt < tot_req  - prev_totr)
			small_pkt = tot_req  - prev_totr;
		bytes += small_pkt * arg_ovre;
	}
#endif

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
		printf("%3llu %3llu %3llu %3llu %3llu ",
		       (unsigned long long)(tot_sc[0] - prev_sc[0]),
		       (unsigned long long)(tot_sc[1] - prev_sc[1]),
		       (unsigned long long)(tot_sc[2] - prev_sc[2]),
		       (unsigned long long)(tot_sc[3] - prev_sc[3]),
		       (unsigned long long)(tot_sc[4] - prev_sc[4]));

	putchar('\n');

	prev_totc = tot_conn;
	prev_totr = tot_req;
	prev_totb = tot_rcvd;
	prev_fbs  = tot_fbs;
	prev_lbs  = tot_lbs;
	prev_ttfb = tot_ttfb;
	prev_ttlb = tot_ttlb;
	prev_sc[0]= tot_sc[0];
	prev_sc[1]= tot_sc[1];
	prev_sc[2]= tot_sc[2];
	prev_sc[3]= tot_sc[3];
	prev_sc[4]= tot_sc[4];
	prev_date = hld_now;
}
/* main task */
static struct task *mtask_cb(struct task *t, void *context, unsigned int state)
{

	TRACE_ENTER(HLD_EV_MAIN_TASK);

	gettimeofday(&hld_now, NULL);
	hld_summary();
	mtask->expire = tick_add(now_ms, MS_TO_TICKS(1000));
leave:
	TRACE_LEAVE(HLD_EV_MAIN_TASK);
	return t;
}

static int hldstream_build_http_req(struct hldstream *hs, struct ist path, int eom)
{
	int ret = 0;
	struct buffer *buf;
	struct htx *htx;
	struct htx_sl *sl;
	struct ist meth_ist;
	struct hld_hdr *hdr;
	unsigned int flags = HTX_SL_F_VER_11 | HTX_SL_F_XFER_LEN |
		(!hs->to_send ? HTX_SL_F_BODYLESS : 0);

	TRACE_ENTER(HLD_STRM_EV_TX, hs);
	buf = hldstream_get_obuf(hs);
	if (!buf) {
		TRACE_STATE("waiting for ouput buffer", HLD_STRM_EV_TX|HLD_STRM_EV_TX_BLK, hs);
		hs->flags |= HLD_STRM_ST_OUT_ALLOC;
		goto leave;
	}

	htx = htx_from_buf(buf);
	meth_ist = !arg_head ? ist("GET") : ist("HEAD");
	sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, meth_ist, path, ist("HTTP/1.1"));
	if (!sl)
		goto err;

	sl->info.req.meth = !arg_head ? HTTP_METH_GET : HTTP_METH_HEAD;
	list_for_each_entry(hdr, &hld_hdrs, list)
		if (!htx_add_header(htx, hdr->name, hdr->value)) {
			TRACE_ERROR("could not add a header", HLD_STRM_EV_TX, hs);
			goto err;
		}

	if (!arg_host &&
	    !http_add_header(htx, ist("host"), ist(hs->url->cfg->raw_addr))) {
		TRACE_ERROR("could not add host header", HLD_STRM_EV_TX, hs);
		goto err;
	}

	if (arg_conn_hdr && !http_add_header(htx, ist("Connection"), ist("close"))) {
		TRACE_ERROR("could not add connection header", HLD_STRM_EV_TX, hs);
		goto err;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOH))
		goto err;

	if (eom)
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

	//BUG_ON(!conn->mux || !conn->mux->snd_buf);
	nret = conn->mux->snd_buf(hs->sc, &hs->bo, htxbuf(&hs->bo)->data, 0);
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

__attribute__((unused))
static void hldstream_htx_buf_rcv(struct connection *conn,
                                 struct hldstream *hs, int *fin)
{
	struct buffer *buf;
	size_t max, read = 0, cur_read = 0;
	int is_empty;
	struct htx_sl *sl = NULL;
	__attribute__((unused))
	uint64_t ttfb, ttlb;     // time-to-first-byte, time-to-last-byte (in us)

	TRACE_ENTER(HLD_STRM_EV_RX, hs);

	*fin = 0;
	if (hs->sc->wait_event.events & SUB_RETRY_RECV) {
		TRACE_DEVEL("subscribed for RECV, waiting for data", HLD_STRM_EV_RX, hs);
		goto leave;
	}

	if (sc_ep_test(hs->sc, SE_FL_EOS)) {
		TRACE_STATE("end of stream", HLD_STRM_EV_RX, hs);
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
		read = conn->mux->rcv_buf(hs->sc, &hs->bi, max, 0);
		if (!(hs->flags & HLD_STRM_ST_GOT_RESP_SL) && read && !sl) {
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
			thrs_info[tid].tot_sc[status * 41 / 4096 - 1]++;
			ttfb = tv_us(tv_diff(&hs->req_date, &date));
			thrs_info[tid].tot_fbs++;
			thrs_info[tid].tot_ttfb += ttfb;
		}

		cur_read += read;
		if (!htx_expect_more(htxbuf(&hs->bi))) {
		    *fin = 1;
		    ttlb = tv_us(tv_diff(&hs->req_date, &date));
		    thrs_info[tid].tot_lbs++;
		    thrs_info[tid].tot_ttlb += ttlb;
		    thrs_info[tid].tot_done++;
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
	else if (!read && !*fin && !sc_ep_test(hs->sc, SE_FL_ERROR | SE_FL_EOS)) {
		TRACE_DEVEL("subscribing for read data", HLD_STRM_EV_RX, hs);
		conn->mux->subscribe(hs->sc, SUB_RETRY_RECV, &hs->sc->wait_event);
	}

	thrs_info[tid].tot_rcvd += cur_read;
 leave:
	hldstream_release_ibuf(hs);
	TRACE_PRINTF(TRACE_LEVEL_PROTO, HLD_STRM_EV_RX, hs, 0, 0, 0,
	             "data received (%llu) read=%d *fin=%d",
	             (unsigned long long)cur_read, (int)read, *fin);
	TRACE_LEAVE(HLD_STRM_EV_RX, hs);
}

/* I/O handler wakeup from MUX */
struct task *hld_io_cb(struct task *t, void *context, unsigned int state)
{
	struct stconn *sc = context;
	struct connection *conn;
	struct hldstream *hs = __sc_hldstream(sc);

	sc = hs->sc;
	conn = sc_conn(sc);

	if (sc_ep_test(sc, SE_FL_ERROR) || (conn && (conn->flags & CO_FL_ERROR))) {
		TRACE_ERROR("connection error", HLD_STRM_EV_IO_CB, hs);
		hs->flags |= HLD_STRM_ST_CONN_ERR;
		task_wakeup(hs->task, TASK_WOKEN_IO);
		goto err;
	}

	task_wakeup(hs->task, TASK_WOKEN_IO);
 err:
	return t;
}

static void hld_conn_destroy(struct connection *conn)
{
	thrs_info[tid].curconn--;
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

static struct task *hld_strm_task(struct task *t, void *context, unsigned int state)
{
	struct hldstream *hs = context;
	struct hld_url *url = hs->url;
	struct connection *conn = sc_conn(hs->sc);
	struct session *sess = hs->usr->sess;
	struct server *srv = url->cfg->srv;
	__attribute__((unused))
	int ret, fin = 0;
	__attribute__((unused))
	int64_t hash;
	__attribute__((unused))
	struct sockaddr_storage dst;

	TRACE_ENTER(HLD_STRM_EV_TASK, hs);

	if (sc_ep_test(hs->sc, SE_FL_ERROR) || (conn && (conn->flags & CO_FL_ERROR))) {
		fprintf(stderr, " ->%d %d", sc_ep_test(hs->sc, SE_FL_ERROR), conn ? !!(conn->flags & CO_FL_ERROR) : -1);
		TRACE_ERROR("connection error", HLD_STRM_EV_IO_CB, hs);
		hs->flags |= HLD_STRM_ST_CONN_ERR;
		task_wakeup(hs->usr->task, TASK_WOKEN_IO);
		goto err;
	}

	if (tick_is_expired(t->expire, now_ms)) {
		TRACE_STATE("expired task", HLD_STRM_EV_TASK, hs);
		t = NULL;
		DDPRINTF(stderr, "@");
		task_wakeup(hs->usr->task, TASK_WOKEN_IO);
		goto leave;
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
		const struct mux_ops *mux_ops;
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
		if (sc_attach_mux(hs->sc, hs->sc->sedesc, conn) < 0) {
			TRACE_ERROR("mux attach error", HLD_STRM_EV_TASK, hs);
			goto err;
		}

		conn->flags |= CO_FL_SSL_NO_CACHED_INFO;

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

		BUG_ON(!proto || !proto->connect);
		/* XXX check the flags XXX */
		status = proto->connect(conn, 0);
		if (status != SF_ERR_NONE) {
			TRACE_ERROR("proto connect error", HLD_STRM_EV_TASK, hs);
			goto err;
		}

		conn_set_private(conn);
		session_add_conn(sess, conn);
		conn->ctx = hs->sc;

		if (conn_xprt_start(conn) < 0) {
			TRACE_ERROR("could not start xprt", HLD_STRM_EV_TASK, hs);
			goto err;
		}

		if (!conn_is_ssl(conn) || !srv->ssl_ctx.alpn_str) {
			mux_ops = conn_get_best_mux(conn, IST_NULL, PROTO_SIDE_BE, PROTO_MODE_HTTP);
			if (!mux_ops || conn_install_mux(conn, mux_ops, hs->sc, &hld_proxy, sess) < 0) {
				TRACE_ERROR("mux installation failed", HLD_STRM_EV_TASK, hs);
				goto err;
			}

			TRACE_PRINTF(TRACE_LEVEL_PROTO, HLD_STRM_EV_TASK, hs, 0, 0, 0,
			             "mux: %s", mux_ops->name);
		}

		hs->conn = conn;
		if (conn->flags & CO_FL_WAIT_XPRT) {
			TRACE_STATE("waiting for xprt", HLD_STRM_EV_TASK, hs);
			if (conn->mux) {
				TRACE_STATE("subscribing to send", HLD_STRM_EV_TASK, hs);
				conn->mux->subscribe(hs->sc, SUB_RETRY_SEND, &hs->sc->wait_event);
			}
		}

		thrs_info[tid].curconn++;
		thrs_info[tid].tot_conn++;
		goto out;
	}

	if (url->flags & HLD_URL_ST_NEED_CONNECT) {
		url->conns++;
		url->flags &= ~HLD_URL_ST_NEED_CONNECT;
	}

	if (hs->flags & HLD_STRM_ST_REQ_TO_BUILD) {
		if (!hldstream_build_http_req(hs, ist(hs->path), 1))
			goto out;

		hs->flags &= ~HLD_STRM_ST_REQ_TO_BUILD;
	}

	if (!hldstream_htx_buf_snd(conn, hs))
		goto out;

	hldstream_htx_buf_rcv(conn, hs, &fin);

 out:
	if (hs->flags & HLD_STRM_ST_CONN_ERR) {
		TRACE_ERROR("haload stream error", HLD_STRM_EV_TASK, hs);
		//task_wakeup(hs->usr->task, TASK_WOKEN_IO);
		goto err;
	}

	if (fin) {
		TRACE_STATE("end of stream", HLD_STRM_EV_TASK, hs);
		goto done;
	}

	t->expire = tick_add(now_ms, MS_TO_TICKS(arg_wait));
 leave:
	TRACE_LEAVE(HLD_STRM_EV_TASK, hs);
	return t;
 done:
	DDPRINTF(stderr, ".");
	task_wakeup(hs->usr->task, TASK_WOKEN_IO);
	hs->url->mreqs++;
	LIST_DELETE(&hs->list);
	hldstream_free(&hs);
	t = NULL;
	goto leave;
 err:
	thrs_info[tid].tot_perr++;
	DDPRINTF(stderr, "e");
	TRACE_DEVEL("leaving on error", HLD_STRM_EV_TASK, hs);
	task_wakeup(hs->usr->task, TASK_WOKEN_IO);
	LIST_DELETE(&hs->list);
	hldstream_free(&hs);
	t = NULL;
	url->mreqs++;
	url->nreqs = url->nreqs == -1 ? -1 : url->nreqs + 1;
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
	t->expire = tick_add(now_ms, MS_TO_TICKS(arg_wait));

	hs->conn = conn;
	hs->hash = hash;
	hs->usr = usr;
	hs->url = url;
	hs->path = path->path;
	hs->sc = sc;
	hs->bi = hs->bo = BUF_NULL;
	LIST_INIT(&hs->buf_wait.list);
	hs->task = t;
	if (!conn)
		DDPRINTF(stderr, "n");
	else
		DDPRINTF(stderr, "y");
	hs->flags = conn ? HLD_STRM_ST_REQ_TO_BUILD : HLD_STRM_ST_REQ_TO_BUILD;
	hs->state = 0;
	hs->to_send = 0;
	hs->req_date = tv_unset();
	LIST_APPEND(&usr->strms, &hs->list);
	task_wakeup(t, TASK_WOKEN_INIT);

	return hs;
 err:
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

static struct task *hld_usr_task(struct task *t, void *context, unsigned int state)
{
	struct hld_usr *usr = context;
	struct hld_url *url, *urls = usr->cur_url, *first_url = urls;
	struct hldstream *hs, *hsbak;
	__attribute__((unused))
	int nreqs, max_reqs = 20;
	int remain = -1;

	TRACE_ENTER(HLD_EV_USR_TASK);

	urls = first_url = usr->cur_url;
	list_for_each_entry_safe(hs, hsbak, &usr->strms, list) {
		/* This task is wake up upon connection error */
		if (hs->flags & HLD_STRM_ST_CONN_ERR) {
			TRACE_STATE("conn error", HLD_EV_USR_TASK, hs);
			thrs_info[tid].tot_cerr++;
			hs->url->nreqs = hs->url->nreqs == -1 ? -1 : hs->url->nreqs + 1;
		}
		else if (tick_is_expired(hs->task->expire, now_ms)) {
			TRACE_STATE("expired task", HLD_EV_USR_TASK, hs);
		}
		else
			break;

		hs->url->mreqs++;
		LIST_DELETE(&hs->list);
		task_destroy(hs->task);
		hs->task = NULL;
		hldstream_free(&hs);
	}

	for (url = urls; url; usr->cur_url = url = hld_next_url(urls, url)) {
		struct hld_path *path, *paths = url->cfg->paths;

		nreqs = url->flags & HLD_URL_ST_NEED_CONNECT ? 1 :
			url->nreqs >= 0 ? MIN(url->nreqs, url->mreqs) : url->mreqs;

		if (!nreqs || !remain) {
			if (url == first_url)
				break;
			else
				continue;
		}

		for (path = paths; path; path = hld_next_path(paths, path)) {
			struct hldstream *hs;

			if ((hs = hld_new_strm(usr, url, path)) == NULL) {
				TRACE_ERROR("could start a new stream task", HLD_EV_USR_TASK);
				goto out;
			}

			url->mreqs--;
			url->nreqs = url->nreqs == -1 ? -1 : url->nreqs - 1;
			BUG_ON(url->nreqs < -1 || url->mreqs < 0);
			if (--nreqs <= 0)// || --max_reqs <= 0)
				goto out;

			if (hs->conn) {
				remain = hs->conn->mux->avail_streams(hs->conn);
				//if (remain <= 2)
					DDPRINTF(stderr, "-%d", remain);
				if (!remain)
					break;
			}
			else {
				/* Connecting */
				break;
			}
		}
	}

 out:
	DDPRINTF(stderr, "L");
	TRACE_LEAVE(HLD_EV_USR_TASK);
	return t;
}

/* Instantiate a haload user and wake up its underlying task */
static inline struct hld_usr *hld_new_usr(int nreqs)
{
	struct hld_usr *usr;
	struct hld_url_cfg *cfg;
	struct hld_url *url, *urls = NULL, *next_url;
	struct task *t;
	struct session *sess;

	usr = malloc(sizeof(*usr));
	/* XXX check this: always thead 0 when calling task_new_anywhere() */
	t = task_new_on(conn_tid++ % global.nbthread);
	sess = session_new(&hld_proxy, NULL, NULL);
	if (!usr || !t || !sess) {
		ha_alert("could not allocate a new user\n");
		goto err;
	}

	t->process = hld_usr_task;
	t->context = usr;
	t->expire = TICK_ETERNITY;
	task_wakeup(t, TASK_WOKEN_INIT);

	usr->task = t;
	usr->sess = sess;
	usr->flags = 0;
	usr->urls = NULL;
	LIST_INIT(&usr->strms);
	for (cfg = hld_url_cfgs; cfg; cfg = cfg->next) {
		struct hld_url *url;

		url = malloc(sizeof(*url));
		if (!url)
			goto err;

		url->nreqs = nreqs;
		url->mreqs = arg_mreqs;
		url->flags = HLD_URL_ST_NEED_CONNECT;
		url->conns = 0;
		url->cfg = cfg;
		url->next = usr->urls;
		usr->urls = url;
	}

	/* inverse the URLs order */
	url = usr->urls;
	while (url) {
		next_url = url->next;
		url->next = urls;
		urls = url;
		url = next_url;
	}

	usr->cur_url = usr->urls;

	return usr;

 err:
	url = usr->urls;
	while (url) {
		next_url = url->next;
		free(url);
		url = next_url;
	}
	task_destroy(t);
	free(usr);
	return NULL;
}

static int hld_cfg_finalize(void)
{
	int ret = 0;
	struct hld_url_cfg *cfg;
	const char *errptr = NULL;

	for (cfg = hld_url_cfgs; cfg; cfg = cfg->next) {
		struct server *srv;
		struct sockaddr_storage *sk;
		int alt_proto, port;
		char *errmsg = NULL;
		int arg = sizeof(hld_args) / sizeof(*hld_args);

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

		if (srv_is_quic(srv))
			quic_transport_params_init(&srv->quic_params, 0);

		/* XXX Must this be done? XXX */
		//srv_set_addr_desc(srv, 0);
		srv_settings_init(srv);

		if (cfg->ssl_opts) {
			size_t outlen = 256;
			int cur_arg = 0;
			char *outline = malloc(256);
			uint32_t err;
			int err_code;

			err = parse_line(cfg->ssl_opts, outline, &outlen, hld_args, &arg,
			                 PARSE_OPT_ENV    | PARSE_OPT_DQUOTE  |
			                 PARSE_OPT_SQUOTE | PARSE_OPT_BKSLASH |
			                 PARSE_OPT_SHARP  | PARSE_OPT_WORD_EXPAND, &errptr);
			if (err) {
				ha_alert("ssl opts parsing error\n");
				goto leave;
			}

			err_code = _srv_parse_kw(srv, hld_args, &cur_arg, &hld_proxy, 0);
			if (err_code)
				goto leave;

			free(outline);
		}
		/* Should parse server keywords here with _srv_parse_kw() */

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

		if (!srv->mux_proto && srv_is_quic(srv))
			srv->mux_proto = get_mux_proto(ist("quic"));

		if (srv->mux_proto) {
			int proto_mode = conn_pr_mode_to_proto_mode(hld_proxy.mode);
			const struct mux_proto_list *mux_ent;

			mux_ent = conn_get_best_mux_entry(srv->mux_proto->token,
			                                  PROTO_SIDE_BE,
			                                  srv_is_quic(srv), proto_mode);

			if (!mux_ent || !isteq(mux_ent->token, srv->mux_proto->token)) {
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
	}
	ret = 1;
leave:
	return ret;
}

static int hld_init(void)
{
	int i, ret = ERR_ALERT | ERR_FATAL;
	char *errmsg = NULL;
	int usr_reqs, min_reqs, mod_req;

	if (!hld_cfg_finalize())
		goto leave;

	usr_reqs = arg_reqs;
	min_reqs = usr_reqs > 0 ? usr_reqs / arg_usr : -1;
	mod_req = usr_reqs > 0 ? usr_reqs % arg_usr : -1;

	mtask = task_new_anywhere();
	if (!mtask) {
		ha_alert("could start main task\n");
		goto leave;
	}

	if (arg_long >= 2)
		printf("#_____time conns tot_conn  tot_req      tot_bytes"
		       "    err thr cps rps Bps bps ttfb(us) ttlb(us)");
	else if (arg_long)
		printf("#     time conns tot_conn  tot_req      tot_bytes"
		       "    err  cps  rps  Bps  bps   ttfb   ttlb");
	else
		printf("#     time conns tot_conn  tot_req      tot_bytes"
		       "    err  cps  rps  bps   ttfb");
	putchar('\n');

	mtask->process = mtask_cb;
	mtask->expire = tick_add(now_ms, MS_TO_TICKS(1000));
	task_queue(mtask);

	/* users initializations */
	DDPRINTF(stderr, "### arg_usr=%d usr_reqs=%d min_reqs=%d mod_req=%d\n",
	        arg_usr, usr_reqs, min_reqs, mod_req);
	for (i = 0; i < arg_usr; i++) {
		struct hld_usr *hu;
		int req = min_reqs == -1 ? -1 :
			i < mod_req ? min_reqs + 1 : min_reqs;

		hu = hld_new_usr(req);
		if (!hu) {
			ha_alert("could not allocate a new haload user\n");
			goto leave;
		}
	}

	gettimeofday(&hld_start_date, NULL);
	ret = ERR_NONE;
 leave:
	ha_free(&errmsg);
	return ret;
}
REGISTER_POST_CHECK(hld_init);

static int hld_alloc_thrs_info(void)
{
	thrs_info = calloc(global.nbthread, sizeof(*thrs_info));
	if (!thrs_info) {
		ha_alert("failed to alloct threads information array.\n");
		return -1;
	}

	return 1;
}
REGISTER_POST_CHECK(hld_alloc_thrs_info);
