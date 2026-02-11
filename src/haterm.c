#include <haproxy/buf.h>
#include <haproxy/cfgparse.h>
#include <haproxy/chunk.h>
#include <haproxy/global.h>
#include <haproxy/hstream-t.h>
#include <haproxy/http_htx.h>
#include <haproxy/http.h>
#include <haproxy/pool.h>
#include <haproxy/proxy-t.h>
#include <haproxy/sc_strm.h>
#include <haproxy/stconn-t.h>
#include <haproxy/stream.h>
#include <haproxy/task-t.h>
#include <haproxy/trace.h>
#include <haproxy/version.h>

DECLARE_TYPED_POOL(pool_head_hstream, "hstream", struct hstream);

/* haterm stream state flags */
#define HS_ST_IN_ALLOC          0x0001
#define HS_ST_OUT_ALLOC         0x0002
#define HS_ST_CONN_ERROR        0x0004
#define HS_ST_HTTP_GOT_HDRS     0x0008
#define HS_ST_HTTP_HELP         0x0010
#define HS_ST_HTTP_EXPECT       0x0020
#define HS_ST_HTTP_RESP_SL_SENT 0x0040

const char *HTTP_HELP =
	"HAProxy's dummy HTTP server for benchmarks - version " HAPROXY_VERSION ".\n"
        "All integer argument values are in the form [digits]*[kmgr] (r=random(0..1)).\n"
        "The following arguments are supported to override the default objects :\n"
        " - /?s=<size>        return <size> bytes.\n"
        "                     E.g. /?s=20k\n"
        " - /?r=<retcode>     present <retcode> as the HTTP return code.\n"
        "                     E.g. /?r=404\n"
        " - /?c=<cache>       set the return as not cacheable if <1.\n"
        "                     E.g. /?c=0\n"
        " - /?A=<req-after>   drain the request body after sending the response.\n"
        "                     E.g. /?A=1\n"
        " - /?C=<close>       force the response to use close if >0.\n"
        "                     E.g. /?C=1\n"
        " - /?K=<keep-alive>  force the response to use keep-alive if >0.\n"
        "                     E.g. /?K=1\n"
        " - /?t=<time>        wait <time> milliseconds before responding.\n"
        "                     E.g. /?t=500\n"
        " - /?k=<enable>      Enable transfer encoding chunked with only one chunk if >0.\n"
        " - /?R=<enable>      Enable sending random data if >0.\n"
        "\n"
        "Note that those arguments may be cumulated on one line separated by a set of\n"
        "delimitors among [&?,;/] :\n"
        " -  GET /?s=20k&c=1&t=700&K=30r HTTP/1.0\n"
        " -  GET /?r=500?s=0?c=0?t=1000 HTTP/1.0\n"
        "\n";

/* Size in bytes of the prebuilts response buffers */
#define RESPSIZE 16384
/* Number of bytes by body response line */
#define HS_COMMON_RESPONSE_LINE_SZ 50
static char common_response[RESPSIZE];
static char common_chunk_resp[RESPSIZE];
static char *random_resp;
static int random_resp_len = RESPSIZE;

#define TRACE_SOURCE &trace_haterm
struct trace_source trace_haterm;
static void hterm_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                        const struct ist where, const struct ist func,
                        const void *a1, const void *a2, const void *a3, const void *a4);

static const struct  name_desc hterm_trace_logon_args[4] = {
	/* arg1 */ { /* already used by the haterm stream */ },
	/* arg2 */ {
		.name="haterm",
		.desc="haterm server",
	},
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct trace_event hterm_trace_events[] = {
#define HS_EV_HSTRM_NEW      (1ULL << 0)
	{ .mask = HS_EV_HSTRM_NEW,      .name = "hstrm_new",      .desc = "new haterm stream" },
#define HS_EV_PROCESS_HSTRM  (1ULL << 1)
	{ .mask = HS_EV_PROCESS_HSTRM,  .name = "process_hstrm",  .desc = "haterm stream processing" },
#define HS_EV_HSTRM_SEND     (1ULL << 2)
	{ .mask = HS_EV_HSTRM_SEND,     .name = "hstrm_send",     .desc = "haterm stream sending" },
#define HS_EV_HSTRM_RECV     (1ULL << 3)
	{ .mask = HS_EV_HSTRM_RECV,     .name = "hstrm_recv",     .desc = "haterm stream receiving" },
#define HS_EV_HSTRM_IO_CB    (1ULL << 4)
	{ .mask = HS_EV_HSTRM_IO_CB,    .name = "hstrm_io_cb",    .desc = "haterm stream I/O callback call" },
#define HS_EV_HSTRM_RESP     (1ULL << 5)
	{ .mask = HS_EV_HSTRM_RESP,     .name = "hstrm_resp",     .desc = "build a HTTP response" },
#define HS_EV_HSTRM_ADD_DATA (1ULL << 6)
	{ .mask = HS_EV_HSTRM_ADD_DATA, .name = "hstrm_add_data", .desc = "add data to HTX haterm stream" },
};

static const struct name_desc hterm_trace_decoding[] = {
#define HATERM_VERB_CLEAN 1
	{ .name = "clean", .desc = "only user-friendly stuff, generally suitable for level \"user\"" },
};

struct trace_source trace_haterm = {
	.name = IST("haterm"),
	.desc = "haterm",
	/* TRACE()'s first argument is always a haterm stream */
	.arg_def = TRC_ARG1_HSTRM,
	.default_cb = hterm_trace,
	.known_events = hterm_trace_events,
	.lockon_args = hterm_trace_logon_args,
	.decoding = hterm_trace_decoding,
	.report_events = ~0, /* report everything by default */
};

INITCALL1(STG_REGISTER, trace_register_source, TRACE_SOURCE);

static void hterm_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                        const struct ist where, const struct ist func,
                        const void *a1, const void *a2, const void *a3, const void *a4)
{
	const struct hstream *hs = a1;

	chunk_appendf(&trace_buf, " hs@%p ", hs);
	if (hs) {
		chunk_appendf(&trace_buf, " res=%u req=%u req_size=%llu to_write=%llu req_body=%llu",
		              (unsigned int)b_data(&hs->res), (unsigned int)b_data(&hs->res),
		              hs->req_size, hs->to_write, hs->req_body);
	}

}

int hstream_buf_available(void *target)
{
	struct hstream *hs = target;

	BUG_ON(!hs->sc);

	if ((hs->flags & HS_ST_IN_ALLOC) && b_alloc(&hs->req, DB_CHANNEL)) {
		hs->flags &= ~HS_ST_IN_ALLOC;
		TRACE_STATE("waking up task", HS_EV_HSTRM_IO_CB, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
		return 1;
	}

	if ((hs->flags & HS_ST_OUT_ALLOC) && b_alloc(&hs->res, DB_CHANNEL)) {
		hs->flags &= ~HS_ST_OUT_ALLOC;
		TRACE_STATE("waking up task", HS_EV_HSTRM_IO_CB, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
		return 1;
	}

	return 0;
}

/* Allocate a buffer. If it fails, it adds the stream in buffer wait queue */
struct buffer *hstream_get_buf(struct hstream *hs, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(!LIST_INLIST(&hs->buf_wait.list)) &&
	    unlikely((buf = b_alloc(bptr, DB_CHANNEL)) == NULL)) {
		b_queue(DB_CHANNEL, &hs->buf_wait, hs, hstream_buf_available);
	}

	return buf;
}

/* Release a buffer, if any, and try to wake up entities waiting in the buffer
 * wait queue.
 */
void hstream_release_buf(struct hstream *hs, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(hs->buf_wait.target, 1);
	}
}

/* Release <hs> haterm stream */
void hstream_free(struct hstream *hs)
{
	sc_destroy(hs->sc);
	hstream_release_buf(hs, &hs->res);
	hstream_release_buf(hs, &hs->req);
	pool_free(pool_head_hstream, hs);
}

struct task *sc_hstream_io_cb(struct task *t, void *ctx, unsigned int state)
{
	struct stconn *sc = ctx;
	struct connection *conn;
	struct hstream *hs = __sc_hstream(sc);

	TRACE_ENTER(HS_EV_HSTRM_IO_CB, hs);

	conn = sc_conn(sc);
	if (unlikely(!conn || conn->flags & CO_FL_ERROR || sc_ep_test(sc, SE_FL_ERROR))) {
		TRACE_ERROR("connection error", HS_EV_HSTRM_IO_CB, hs);
		hs->flags |= HS_ST_CONN_ERROR;
		task_wakeup(hs->task, TASK_WOKEN_IO);
	}

	if (((!hs->req_after_res || !hs->to_write) && hs->req_body) ||
	    !htx_is_empty(htxbuf(&hs->req))) {
		TRACE_STATE("waking up task", HS_EV_HSTRM_IO_CB, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
	}
	else if (hs->to_write || !htx_is_empty(htxbuf(&hs->res))) {
		TRACE_STATE("waking up task", HS_EV_HSTRM_IO_CB, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
	}

	TRACE_LEAVE(HS_EV_HSTRM_IO_CB, hs);
	return t;
}

static int hstream_htx_buf_rcv(struct connection *conn, struct hstream *hs)
{
	int ret = 0;
	struct buffer *buf;
	size_t max, read = 0, cur_read = 0;
	int is_empty;
	int fin = 0;

	TRACE_ENTER(HS_EV_HSTRM_RECV, hs);

	if (hs->sc->wait_event.events & SUB_RETRY_RECV) {
		TRACE_DEVEL("subscribed for RECV, waiting for data", HS_EV_HSTRM_RECV, hs);
		goto wait_more_data;
	}

	if (sc_ep_test(hs->sc, SE_FL_EOS)) {
		TRACE_STATE("end of stream", HS_EV_HSTRM_RECV, hs);
		goto end_recv;
	}

	if (hs->flags & HS_ST_IN_ALLOC) {
		TRACE_STATE("waiting for input buffer", HS_EV_HSTRM_RECV, hs);
		goto wait_more_data;
	}

	buf = hstream_get_buf(hs, &hs->req);
	if (!buf) {
		TRACE_STATE("waiting for input buffer", HS_EV_HSTRM_RECV, hs);
		hs->flags |= HS_ST_IN_ALLOC;
		goto wait_more_data;
	}

	while (sc_ep_test(hs->sc, SE_FL_RCV_MORE) ||
	       (!(conn->flags & CO_FL_ERROR) && !sc_ep_test(hs->sc, SE_FL_ERROR | SE_FL_EOS))) {
		htx_reset(htxbuf(&hs->req));
		max = (IS_HTX_SC(hs->sc) ?  htx_free_space(htxbuf(&hs->req)) : b_room(&hs->req));
		sc_ep_clr(hs->sc, SE_FL_WANT_ROOM);
		read = conn->mux->rcv_buf(hs->sc, &hs->req, max, 0);
		cur_read += read;
		if (!htx_expect_more(htxbuf(&hs->req))) {
		    fin = 1;
		    break;
		}

		if (!read)
			break;
	}

 end_recv:
	is_empty = (IS_HTX_SC(hs->sc) ? htx_is_empty(htxbuf(&hs->req)) : !b_data(&hs->req));
	hs->req_body -= cur_read;

	if (is_empty && ((conn->flags & CO_FL_ERROR) || sc_ep_test(hs->sc, SE_FL_ERROR))) {
		/* Report network errors only if we got no other data. Otherwise
		 * we'll let the upper layers decide whether the response is OK
		 * or not. It is very common that an RST sent by the server is
		 * reported as an error just after the last data chunk.
		 */
		TRACE_ERROR("connection error during recv", HS_EV_HSTRM_RECV, hs);
		goto stop;
	}
	else if (!read && !fin && !sc_ep_test(hs->sc, SE_FL_ERROR | SE_FL_EOS)) {
		TRACE_DEVEL("subscribing for read data", HS_EV_HSTRM_RECV, hs);
		conn->mux->subscribe(hs->sc, SUB_RETRY_RECV, &hs->sc->wait_event);
		goto wait_more_data;
	}

	ret = 1;
 leave:
	hstream_release_buf(hs, &hs->req);
	TRACE_PRINTF(TRACE_LEVEL_PROTO, HS_EV_HSTRM_RECV, hs, 0, 0, 0,
	             "data received (%llu) ret=%d read=%d fin=%d",
	             (unsigned long long)cur_read, ret, (int)read, fin);
	TRACE_LEAVE(HS_EV_HSTRM_RECV, hs);
	return ret;
 stop:
	ret = 2;
	goto leave;
 wait_more_data:
	ret = 3;
	goto leave;
}

/* Send HTX data prepared for <hs> haterm stream from <conn> connection */
static int hstream_htx_buf_snd(struct connection *conn, struct hstream *hs)
{
	struct stconn *sc = hs->sc;
	int ret = 0;
	int nret;

	TRACE_ENTER(HS_EV_HSTRM_SEND, hs);

	if (!htxbuf(&hs->res)->data) {
		/* This is possible after having drained the body, so after
		 * having sent the response here when req_after_res=1.
		 */
		ret = 1;
		goto out;
	}

	nret = conn->mux->snd_buf(hs->sc, &hs->res, htxbuf(&hs->res)->data, 0);
	if (nret <= 0) {
		if (hs->flags & HS_ST_CONN_ERROR ||
		    conn->flags & CO_FL_ERROR || sc_ep_test(sc, SE_FL_ERROR)) {
			TRACE_DEVEL("connection error during send", HS_EV_HSTRM_SEND, hs);
			goto out;
		}
	}

	/* The HTX data are not fully sent if the last HTX data
	 * were not fully transfered or if there are remaining data
	 * to send (->to_write > 0).
	 */
	if (!htx_is_empty(htxbuf(&hs->res))) {
		TRACE_DEVEL("data not fully sent, wait", HS_EV_HSTRM_SEND, hs);
		conn->mux->subscribe(sc, SUB_RETRY_SEND, &sc->wait_event);
	}
	else if (hs->to_write) {
		TRACE_STATE("waking up task", HS_EV_HSTRM_IO_CB, hs);
		task_wakeup(hs->task, TASK_WOKEN_IO);
	}

	ret = 1;
 out:
	if (htx_is_empty(htxbuf(&hs->res)) || ret == 0) {
		TRACE_DEVEL("releasing underlying buffer", HS_EV_HSTRM_SEND, hs);
		hstream_release_buf(hs, &hs->res);
	}

	TRACE_LEAVE(HS_EV_HSTRM_SEND, hs);
	return ret;
}

/* Build the help response for <hs> haterm stream.
 * Return 1 if succeed, 0 if not.
 */
static int hstream_build_http_help_resp(struct hstream *hs)
{
	int ret = 0;
	struct buffer *buf;
	struct htx *htx;
	unsigned int flags = HTX_SL_F_IS_RESP | HTX_SL_F_XFER_LEN;
	struct htx_sl *sl;

	TRACE_ENTER(HS_EV_HSTRM_SEND, hs);

	buf = hstream_get_buf(hs, &hs->res);
	if (!buf) {
		TRACE_ERROR("waiting for output buffer", HS_EV_HSTRM_SEND, hs);
		hs->flags |= HS_ST_OUT_ALLOC;
		goto err;
	}

	htx = htx_from_buf(buf);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.0"),
	                    ist("200"), IST_NULL);
	if (!sl)
		goto err;

	if (!htx_add_header(htx, ist("Cache-Control"), ist("no-cache")) ||
		!htx_add_header(htx, ist("Connection"), ist("close")) ||
		!htx_add_header(htx, ist("Content-type"), ist("text/plain"))) {
		TRACE_ERROR("could not add connection HTX header", HS_EV_HSTRM_SEND, hs);
		goto err;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOH)) {
		TRACE_ERROR("could not add EOH HTX", HS_EV_HSTRM_SEND, hs);
		goto err;
	}

	if (!htx_add_data_atonce(htx, ist2(HTTP_HELP, strlen(HTTP_HELP)))) {
		TRACE_ERROR("unable to add payload to HTX message", HS_EV_HSTRM_SEND, hs);
		goto err;
	}

	htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, buf);
	sl->info.res.status = 200;
	ret = 1;
leave:
	TRACE_LEAVE(HS_EV_HSTRM_SEND, hs);
	return ret;
err:
	hs->flags |= HS_ST_CONN_ERROR;
	TRACE_DEVEL("leaving on error", HS_EV_HSTRM_SEND, hs);
	goto leave;
}

/* Build 100-continue HTX message.
 * Return 1 if succeeded, 0 if not.
 */
static int hstream_build_http_100_continue_resp(struct hstream *hs)
{
	int ret = 0;
	struct buffer *buf;
	struct htx *htx;
	unsigned int flags = HTX_SL_F_IS_RESP | HTX_SL_F_XFER_LEN;
	struct htx_sl *sl;

	TRACE_ENTER(HS_EV_HSTRM_SEND, hs);

	buf = hstream_get_buf(hs, &hs->res);
	if (!buf) {
		TRACE_STATE("waiting for output buffer", HS_EV_HSTRM_SEND, hs);
		hs->flags |= HS_ST_OUT_ALLOC;
		goto err;
	}

	htx = htx_from_buf(buf);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags, ist("HTTP/1.1"),
						ist("100-continue"), IST_NULL);
	if (!sl) {
		TRACE_ERROR("could not add HTX start line", HS_EV_HSTRM_SEND, hs);
		goto err;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOH)) {
		TRACE_ERROR("could not add EOH HTX", HS_EV_HSTRM_RESP, hs);
		goto err;
	}

	htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, buf);
	sl->info.res.status = 100;
	ret = 1;
leave:
	TRACE_LEAVE(HS_EV_HSTRM_SEND, hs);
	return ret;
err:
	TRACE_DEVEL("leaving on error", HS_EV_HSTRM_SEND, hs);
	goto leave;
}

int hstream_wake(struct stconn *sc)
{
	struct hstream *hs = __sc_hstream(sc);

	TRACE_STATE("waking up task", HS_EV_HSTRM_IO_CB, hs);
	task_wakeup(hs->task, TASK_WOKEN_IO);
	return 0;
}

/* Add data to HTX response buffer from pre-built responses */
static void hstream_add_data(struct htx *htx, struct hstream *hs)
{
	int ret;
	char *data_ptr;
	unsigned long long max;
	unsigned int offset;
	char *buffer;
	size_t buffer_len;
	int modulo;

	TRACE_ENTER(HS_EV_HSTRM_ADD_DATA, hs);

	if (hs->req_chunked) {
		buffer = common_chunk_resp;
		buffer_len = sizeof(common_chunk_resp);
		modulo = sizeof(common_chunk_resp);
	}
	else if (hs->req_random) {
		buffer = random_resp;
		buffer_len = random_resp_len;
		modulo = random_resp_len;
	}
	else {
		buffer = common_response;
		buffer_len = sizeof(common_response);
		modulo = HS_COMMON_RESPONSE_LINE_SZ;
	}

	offset = (hs->req_size - hs->to_write) % modulo;
	data_ptr = buffer + offset;
	max = hs->to_write;
	if (max > (unsigned long long)(buffer_len - offset))
		max = (unsigned long long)(buffer_len - offset);

	ret = htx_add_data(htx, ist2(data_ptr, max));
	if (!ret)
		TRACE_STATE("unable to add payload to HTX message", HS_EV_HSTRM_ADD_DATA, hs);

	hs->to_write -= ret;
leave:
	TRACE_LEAVE(HS_EV_HSTRM_ADD_DATA, hs);
	return;
err:
	TRACE_DEVEL("leaving on error", HS_EV_HSTRM_ADD_DATA);
	goto leave;
}

/* Build the HTTP response with eventually some BODY data depending on ->to_write
 * value. Return 1 if succeeded, 0 if not.
 */
static int hstream_build_http_resp(struct hstream *hs)
{
	int ret = 0;
	struct buffer *buf;
	struct htx *htx;
	unsigned int flags = HTX_SL_F_IS_RESP | HTX_SL_F_XFER_LEN | (!hs->req_chunked ?  HTX_SL_F_CLEN : 0);
	struct htx_sl *sl;
	char hdrbuf[128];

	TRACE_ENTER(HS_EV_HSTRM_RESP, hs);

	snprintf(hdrbuf, sizeof(hdrbuf), "%d", hs->req_code);
	buf = hstream_get_buf(hs, &hs->res);
	if (!buf) {
		TRACE_ERROR("could not allocate response buffer", HS_EV_HSTRM_RESP, hs);
		goto err;
	}

	htx = htx_from_buf(buf);
	sl = htx_add_stline(htx, HTX_BLK_RES_SL, flags,
	                    !(hs->ka & 4) ? ist("HTTP/1.0") : ist("HTTP/1.1"),
	                    ist(hdrbuf), IST_NULL);
	if (!sl) {
		TRACE_ERROR("could not add HTX start line", HS_EV_HSTRM_RESP, hs);
		goto err;
	}

	if ((hs->ka & 5) == 1) {
		// HTTP/1.0 + KA
		if (!htx_add_header(htx, ist("Connection"), ist("keep-alive"))) {
			TRACE_ERROR("could not add connection HTX header", HS_EV_HSTRM_RESP, hs);
			goto err;
		}
	}
	else if ((hs->ka & 5) == 4) {
		// HTTP/1.1 + close
		if (!htx_add_header(htx, ist("Connection"), ist("close"))) {
			TRACE_ERROR("could not add connection HTX header", HS_EV_HSTRM_RESP, hs);
			goto err;
		}
	}

	if (!hs->req_chunked && (hs->ka & 1)) {
		char *end = ultoa_o(hs->req_size, trash.area, trash.size);
		if (!htx_add_header(htx, ist("Content-Length"), ist2(trash.area, end - trash.area))) {
			TRACE_ERROR("could not add content-length HTX header", HS_EV_HSTRM_RESP, hs);
			goto err;
		}
	}

	if (!hs->req_cache && !htx_add_header(htx, ist("Cache-control"), ist("no-cache"))) {
		TRACE_ERROR("could not add cache-control HTX header", HS_EV_HSTRM_RESP, hs);
		goto err;
	}

	/* XXX TODO time?  XXX */
	snprintf(hdrbuf, sizeof(hdrbuf), "time=%ld ms", 0L);
	if (!htx_add_header(htx, ist("X-req"), ist(hdrbuf))) {
		TRACE_ERROR("could not add x-req HTX header", HS_EV_HSTRM_RESP, hs);
	    goto err;
	}

	/* XXX TODO time? XXX */
	snprintf(hdrbuf, sizeof(hdrbuf), "id=%s, code=%d, cache=%d,%s size=%lld, time=%d ms (%ld real)",
	         "dummy", hs->req_code, hs->req_cache,
			 hs->req_chunked ? " chunked," : "",
			 hs->req_size, 0, 0L);
	if (!htx_add_header(htx, ist("X-rsp"), ist(hdrbuf))) {
		TRACE_ERROR("could not add x-rsp HTX header", HS_EV_HSTRM_RESP, hs);
	    goto err;
	}

	if (!htx_add_endof(htx, HTX_BLK_EOH)) {
		TRACE_ERROR("could not add EOH HTX", HS_EV_HSTRM_RESP, hs);
		goto err;
	}

	if (hs->to_write > 0)
		hstream_add_data(htx, hs);
	if (hs->to_write <= 0)
		htx->flags |= HTX_FL_EOM;
	htx_to_buf(htx, buf);

	sl->info.res.status = hs->req_code;
	ret = 1;
 leave:
	TRACE_LEAVE(HS_EV_HSTRM_RESP, hs);
	return ret;
 err:
	TRACE_DEVEL("leaving on error", HS_EV_HSTRM_RESP, hs);
	goto leave;
}


/* Parse <hs> haterm stream <uri> URI. This has as side effect to initialize
 * some <hs> members.
 */
static void hstream_parse_uri(struct ist uri, struct hstream *hs)
{
	char *next = NULL, *arg;
	char *p = istptr(uri);
	char *end = p + istlen(uri);
	long result, mult;
	int use_rand;

	/* we'll check for the following URIs :
	 * /?{s=<size>|r=<resp>|t=<time>|c=<cache>}[&{...}]
	 * /? to get the help page.
	 */
	while (p < end)
		if (*p++ == '?')
			next = p;

	if (next) {
		arg = next;
		if (next == end || *next == ' ') {
			/* request for help */
			hs->flags |= HS_ST_HTTP_HELP;
			return;
		}

		while (arg + 2 <= end && arg[1] == '=') {
			use_rand = 0;
			next = NULL;
			result = strtol(arg + 2, &next, 0);
			if (next > arg + 2) {
				mult = 0;
				do {
					if (*next == 'k' || *next == 'K')
						mult += 10;
					else if (*next == 'm' || *next == 'M')
						mult += 20;
					else if (*next == 'g' || *next == 'G')
						mult += 30;
					else if (*next == 'r' || *next == 'R')
						use_rand=1;
					else
						break;
					next++;
				} while (*next);

				if (use_rand)
					result = ((long long)random() * result) / ((long long)RAND_MAX + 1);

				switch (*arg) {
				case 's':
					if (hs->req_meth != HTTP_METH_HEAD)
						hs->req_size = (long long)result << mult;
					break;
				case 'r':
					hs->req_code = result << mult;
					break;
				case 't':
					hs->res_wait = MS_TO_TICKS(result << mult);
					break;
				case 'c':
					hs->req_cache = result << mult;
					break;
				case 'A':
					hs->req_after_res = result;
					break;
				case 'C':
					hs->ka = (hs->ka & 4) | 2 | !result;  // forced OFF
					break;
				case 'K':
					hs->ka = (hs->ka & 4) | 2 | !!result; // forced ON
					break;
				case 'k':
					hs->req_chunked = result;
					break;
				case 'R':
					hs->req_random = result;
					break;
				}
				arg = next;
			}

			if (*arg == '&' || *arg == ';' || *arg == '/' || *arg == '?' || *arg == ',')
				arg++;
			else
				break;
		}
	}

	hs->to_write = hs->req_size;
}

/* Prepare start line and headers response and push them to HTX.
 * Return 1 if succeeded, 0 if not.
 */
static inline int hstream_sl_hdrs_htx_buf_snd(struct hstream *hs,
                                              struct connection *conn)
{
	int ret = 0;

	if ((hs->flags & HS_ST_HTTP_RESP_SL_SENT))
		return 1;

	if (hs->flags & HS_ST_HTTP_HELP) {
		if (!hstream_build_http_help_resp(hs))
			goto out;
	}
	else {
		if (!hstream_build_http_resp(hs))
			goto out;
	}

	hstream_htx_buf_snd(conn, hs);
	hs->flags |= HS_ST_HTTP_RESP_SL_SENT;
	ret = 1;
 out:
	return ret;
}

/* Must be called before sending to determine if the body request must be
 * drained asap before sending. Return 1 if this is the case, 0 if not.
 * This is the case by default before sending the response except if
 * the contrary has been asked with ->req_after_res=0.
 * Return true if the body request has not been fully drained (->hs->req_body>0)
 * and if the response has been sent (hs->to_write=0 &&
 * htx_is_empty(htxbuf(&hs->res) or if it must not be drained after having
 * sent the response (->req_after_res=0) or
 */
static inline int hstream_must_drain(struct hstream *hs)
{
	int ret;

	TRACE_ENTER(HS_EV_PROCESS_HSTRM, hs);
	ret = !(hs->flags & HS_ST_CONN_ERROR) && hs->req_body > 0 &&
		((!hs->to_write && htx_is_empty(htxbuf(&hs->res))) || !hs->req_after_res);
	TRACE_LEAVE(HS_EV_PROCESS_HSTRM, hs);

	return ret;
}

/* haterm stream processing task */
static struct task *process_hstream(struct task *t, void *context, unsigned int state)
{
	struct hstream *hs = context;
	struct ist uri;
	struct connection *conn = __sc_conn(hs->sc);
	int rcvd;

	TRACE_ENTER(HS_EV_PROCESS_HSTRM, hs);

	if (unlikely(hs->flags & HS_ST_CONN_ERROR ||
	             !conn || conn->flags & CO_FL_ERROR || sc_ep_test(hs->sc, SE_FL_ERROR))) {
		TRACE_ERROR("connection error", HS_EV_PROCESS_HSTRM, hs);
		hs->flags |= HS_ST_CONN_ERROR;
		goto out;
	}

	if (tick_isset(hs->res_time) && !tick_is_expired(hs->res_time, now_ms)) {
		TRACE_STATE("waiting before responding", HS_EV_HSTRM_IO_CB, hs);
		goto leave;
	}

	if (!(hs->flags & HS_ST_HTTP_GOT_HDRS)) {
		struct htx *htx = htx_from_buf(&hs->req);
		struct htx_sl *sl = http_get_stline(htx);
		struct http_hdr_ctx expect, clength;

		if (sl->flags & HTX_SL_F_VER_11)
			hs->ka = 5;

		hs->req_meth = sl->info.req.meth;
		hs->flags |= HS_ST_HTTP_GOT_HDRS;
		uri = htx_sl_req_uri(http_get_stline(htx));
		hstream_parse_uri(uri, hs);

		clength.blk = NULL;
		if (http_find_header(htx, ist("content-length"), &clength, 0)) {
			if (isttest(clength.value)) {
				if (strl2llrc(istptr(clength.value), istlen(clength.value),
				              (long long *)&hs->req_body) != 0) {
					TRACE_ERROR("could not parse the content length",
					            HS_EV_PROCESS_HSTRM, hs);
					goto err;
				}
			}
		}

		expect.blk = NULL;
		if (http_find_header(htx, ist("expect"), &expect, 0)) {
			hs->flags |= HS_ST_HTTP_EXPECT;
			if (hstream_build_http_100_continue_resp(hs))
				hstream_htx_buf_snd(conn, hs);
		}

		if (!htx_expect_more(htxbuf(&hs->req))) {
			/* The request body has always been fully received */
			TRACE_STATE("no more expected data", HS_EV_HSTRM_RESP, hs);
			hs->req_body = 0;
		}

		if (hstream_must_drain(hs)) {
			/* The request must be drained before sending the response (hs->req_after_res=0).
			 * The body will be drained upon next wakeup.
			 */
			TRACE_STATE("waking up task", HS_EV_HSTRM_IO_CB, hs);
			task_wakeup(hs->task, TASK_WOKEN_IO);
			goto out;
		}

		if (tick_isset(hs->res_wait)) {
			TRACE_STATE("task scheduled", HS_EV_HSTRM_IO_CB, hs);
			hs->res_time = tick_add(now_ms, hs->res_wait);
			task_schedule(t, hs->res_time);
			goto leave;
		}

		/* HTX send the start line and headers if not already sent */
		if (!hstream_sl_hdrs_htx_buf_snd(hs, conn))
			goto err;

		if (hstream_must_drain(hs)) {
			/* The request must be drained before sending the response (hs->req_after_res=0).
			 * The body will be drained upon next wakeup.
			 */
			TRACE_STATE("waking up task", HS_EV_HSTRM_IO_CB, hs);
			task_wakeup(hs->task, TASK_WOKEN_IO);
			goto out;
		}
	}
	else {
		struct buffer *buf;
		struct htx *htx;

		/* HTX RX part */
		if (hstream_must_drain(hs)) {
			rcvd = hstream_htx_buf_rcv(conn, hs);
			if (rcvd == 3) {
				TRACE_STATE("waiting for more data", HS_EV_HSTRM_RESP, hs);
				goto out;
			}
		}

		if (tick_isset(hs->res_wait) && !tick_isset(hs->res_time)) {
			TRACE_STATE("task scheduled", HS_EV_HSTRM_IO_CB, hs);
			hs->res_time = tick_add(now_ms, hs->res_wait);
			task_schedule(t, hs->res_time);
			goto leave;
		}

		/* HTX send the start line and headers if not already sent */
		if (!hstream_sl_hdrs_htx_buf_snd(hs, conn))
			goto err;

		/* HTX TX part */
		if (!hs->to_write && htx_is_empty(htxbuf(&hs->res)))
			goto out;

		buf = hstream_get_buf(hs, &hs->res);
		if (!buf) {
			TRACE_ERROR("could not allocate response buffer", HS_EV_HSTRM_RESP, hs);
			goto err;
		}

		htx = htx_from_buf(buf);
		if (hs->to_write > 0)
			hstream_add_data(htx, hs);
		if (hs->to_write <= 0)
			htx->flags |= HTX_FL_EOM;
		htx_to_buf(htx, &hs->res);
		hstream_htx_buf_snd(conn, hs);

		if (hs->req_body && hs->req_after_res && !hs->to_write) {
			/* Response sending has just complete. The body will be drained upon
			 * next wakeup.
			 */
			TRACE_STATE("waking up task", HS_EV_HSTRM_IO_CB, hs);
			task_wakeup(hs->task, TASK_WOKEN_IO);
			goto out;
		}
	}

 out:
	if (!hs->to_write && !hs->req_body && htx_is_empty(htxbuf(&hs->res))) {
		TRACE_DEVEL("shutting down stream", HS_EV_HSTRM_SEND, hs);
		conn->mux->shut(hs->sc, SE_SHW_SILENT|SE_SHW_NORMAL, NULL);
	}

	if (hs->flags & HS_ST_CONN_ERROR ||
	    (!hs->to_write && !hs->req_body && htx_is_empty(htxbuf(&hs->res)))) {
		TRACE_STATE("releasing hstream", HS_EV_PROCESS_HSTRM, hs);
		hstream_free(hs);
		hs = NULL;
		task_destroy(t);
		t = NULL;
	}

 leave:
	TRACE_LEAVE(HS_EV_PROCESS_HSTRM, hs);
	return t;
 err:
	TRACE_DEVEL("leaving on error", HS_EV_PROCESS_HSTRM);
	goto leave;
}

/* Allocate a httpter stream as this is done for classical haproxy streams.
 * This function is called as proxy callback from muxes.
 * Return the haterm stream object if succeede, NUL if not.
 */
void *hstream_new(struct session *sess, struct stconn *sc, struct buffer *input)
{
	struct hstream *hs = NULL;
	struct task *t = NULL;

	TRACE_ENTER(HS_EV_HSTRM_NEW);

	if (unlikely((hs = pool_alloc(pool_head_hstream)) == NULL)) {
		TRACE_ERROR("stream allocation failure", HS_EV_HSTRM_NEW);
		goto err;
	}

	if ((t = task_new_here()) == NULL) {
		TRACE_ERROR("task allocation failure", HS_EV_HSTRM_NEW, hs);
		goto err;
	}

	hs->obj_type = OBJ_TYPE_HATERM;
	hs->sess = sess;
	hs->sc = sc;
	hs->task = t;
	hs->req = BUF_NULL;
	hs->res = BUF_NULL;
	hs->to_write = 0;

	LIST_INIT(&hs->buf_wait.list);
	hs->flags = 0;

	hs->ka = 0;
	hs->req_cache = 1;
	hs->req_size = 0;
	hs->req_body = 0;
	hs->req_code = 200;
	hs->res_wait = TICK_ETERNITY;
	hs->res_time = TICK_ETERNITY;
	hs->req_chunked = 0;
	hs->req_random = 0;
	hs->req_after_res = 0;
	hs->req_meth = HTTP_METH_OTHER;

	if (sc_conn(sc)) {
		const struct mux_ops *mux = sc_mux_ops(sc);
		if (mux && !(mux->flags & MX_FL_HTX)) {
			TRACE_ERROR("mux without HTX not supported",
			            HS_EV_HSTRM_NEW, hs);
			goto err;
		}
	}

	if (sc_attach_hstream(hs->sc, hs) < 0) {
		TRACE_ERROR("could not attach to stream connector",
		            HS_EV_HSTRM_NEW, hs);
		goto err;
	}

	TRACE_PRINTF(TRACE_LEVEL_PROTO, HS_EV_HSTRM_NEW, hs, 0, 0, 0,
	             "stream initialized @%p", hs);
	hs->res = BUF_NULL;
	/* Xfer the input buffer */
	if (!b_is_null(input)) {
		hs->req = *input;
		*input = BUF_NULL;
	}

	t->process = process_hstream;
	t->context = hs;
	t->expire = TICK_ETERNITY;
	task_wakeup(hs->task, TASK_WOKEN_INIT);

	TRACE_LEAVE(HS_EV_HSTRM_NEW, hs);
	return hs;

 err:
	task_destroy(t);
	pool_free(pool_head_hstream, hs);
	TRACE_DEVEL("leaving on error", HS_EV_HSTRM_NEW);
	return NULL;
}

/* Build the response buffers.
 * Return 1 if succeeded, -1 if failed.
 */
static int hstream_build_responses(void)
{
	int i;

	for (i = 0; i < sizeof(common_response); i++) {
		if (i % HS_COMMON_RESPONSE_LINE_SZ == HS_COMMON_RESPONSE_LINE_SZ - 1)
			common_response[i] = '\n';
		else if (i % 10 == 0)
			common_response[i] = '.';
		else
			common_response[i] = '0' + i % 10;
	}

	/* original haterm chunk mode responses are made of 1-byte chunks
	 * but the haproxy muxes do not support this. At this time
	 * these reponses are handled the same way as for common
	 * responses with a pre-built buffer.
	 */
	for (i = 0; i < sizeof(common_chunk_resp); i++)
		common_chunk_resp[i] = '1';

	random_resp = malloc(random_resp_len);
	if (!random_resp) {
		ha_alert("not enough memore...\n");
		return -1;
	}

	for (i = 0; i < random_resp_len; i++)
		random_resp[i] = rand() >> 16;

	return 1;
}

REGISTER_POST_CHECK(hstream_build_responses);
