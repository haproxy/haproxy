#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/hstream-t.h>
#include <haproxy/http_htx.h>
#include <haproxy/http.h>
#include <haproxy/pool.h>
#include <haproxy/stconn-t.h>
#include <haproxy/stream.h>
#include <haproxy/task-t.h>
#include <haproxy/trace.h>

#include <haproxy/sc_strm.h>

DECLARE_TYPED_POOL(pool_head_hstream, "hstream", struct hstream);

#define HTTPTERM_VERSION "1.7.9"
#define HTTPTERM_DATE   "2020/06/28"

#define HS_ST_IN_ALLOC          0x0001
#define HS_ST_OUT_ALLOC         0x0002
#define HS_ST_CONN_ERROR        0x0004
#define HS_ST_HTTP_GOT_HDRS     0x0008
#define HS_ST_HTTP_HELP         0x0010
#define HS_ST_HTTP_EXPECT       0x0020
#define HS_ST_HTTP_RESP_SL_SENT 0x0040

const char *HTTP_HELP =
        "HTTPTerm-" HTTPTERM_VERSION " - " HTTPTERM_DATE "\n"
        "All integer argument values are in the form [digits]*[kmgr] (r=random(0..1)).\n"
        "The following arguments are supported to override the default objects :\n"
        " - /?s=<size>        return <size> bytes.\n"
        "                     E.g. /?s=20k\n"
        " - /?r=<retcode>     present <retcode> as the HTTP return code.\n"
        "                     E.g. /?r=404\n"
        " - /?c=<cache>       set the return as not cacheable if <1.\n"
        "                     E.g. /?c=0\n"
        " - /?A=<req-before>  drain the request body before sending the response.\n"
        "                     E.g. /?A=1\n"
        " - /?C=<close>       force the response to use close if >0.\n"
        "                     E.g. /?C=1\n"
        " - /?K=<keep-alive>  force the response to use keep-alive if >0.\n"
        "                     E.g. /?K=1\n"
        " - /?b=<bodylen>     advertise the body length in content-length if >0.\n"
        "                     E.g. /?b=0\n"
        " - /?B=<maxbody>     read no more than this amount of body before responding.\n"
        "                     E.g. /?B=10000\n"
        " - /?t=<time>        wait <time> milliseconds before responding.\n"
        "                     E.g. /?t=500\n"
        " - /?k=<enable>      Enable transfer encoding chunked with 1 byte chunks if >0.\n"
        " - /?S=<enable>      Disable use of splice() to send data if <1.\n"
        " - /?R=<enable>      Enable sending random data if >0 (disables splicing).\n"
        //" - /?p=<size>        Make pieces no larger than this if >0 (disables splicing).\n"
        "\n"
        "Note that those arguments may be cumulated on one line separated by a set of\n"
        "delimitors among [&?,;/] :\n"
        " -  GET /?s=20k&c=1&t=700&K=30r HTTP/1.0\n"
        " -  GET /?r=500?s=0?c=0?t=1000 HTTP/1.0\n"
        "\n";

#define RESPSIZE 16384 //65536

static char common_response[RESPSIZE];
static char common_chunk_resp[RESPSIZE];
static char *random_resp;
static int random_resp_len = RESPSIZE;

#define TRACE_SOURCE &trace_httpterm

struct trace_source trace_httpterm;

static void hterm_trace(enum trace_level level, uint64_t mask, const struct trace_source *src,
                        const struct ist where, const struct ist func,
                        const void *a1, const void *a2, const void *a3, const void *a4);

static const struct  name_desc hterm_trace_logon_args[4] = {
	/* arg1 */ { /* already used by the httpterm stream */ },
	/* arg2 */ {
		.name="httpterm",
		.desc="httpterm server",
	},
	/* arg3 */ { },
	/* arg4 */ { }
};

static const struct trace_event hterm_trace_events[] = {
#define HS_EV_HSTRM_NEW      (1ULL << 0)
	{ .mask = HS_EV_HSTRM_NEW,      .name = "hstrm_new",      .desc = "new httpterm stream" },
#define HS_EV_PROCESS_HSTRM  (1ULL << 1)
	{ .mask = HS_EV_PROCESS_HSTRM,  .name = "process_hstrm",  .desc = "httpterm stream processing" },
#define HS_EV_HSTRM_SEND     (1ULL << 2)
	{ .mask = HS_EV_HSTRM_SEND,     .name = "hstrm_send",     .desc = "httpterm stream sending" },
#define HS_EV_HSTRM_RECV     (1ULL << 3)
	{ .mask = HS_EV_HSTRM_RECV,     .name = "hstrm_recv",     .desc = "httpterm stream receiving" },
#define HS_EV_HSTRM_IO_CB    (1ULL << 4)
	{ .mask = HS_EV_HSTRM_IO_CB,    .name = "hstrm_io_cb",    .desc = "httpterm stream I/O callback call" },
#define HS_EV_HSTRM_RESP     (1ULL << 5)
	{ .mask = HS_EV_HSTRM_RESP,     .name = "hstrm_resp",     .desc = "build a HTTP response" },
#define HS_EV_HSTRM_ADD_DATA (1ULL << 6)
	{ .mask = HS_EV_HSTRM_ADD_DATA, .name = "hstrm_add_data", .desc = "add data to HTX httpterm stream" },
};

static const struct name_desc hterm_trace_decoding[] = {
#define HTERM_VERB_CLEAN 1
	{ .name = "clean", .desc = "only user-friendly stuff, generally suitable for level \"user\"" },
};

struct trace_source trace_httpterm = {
	.name = IST("httpterm"),
	.desc = "httpterm",
	/* TRACE()'s first argument is always a httpterm stream */
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
		chunk_appendf(&trace_buf, " res=%u req_size=%llu to_write=%llu req_body=%llu",
		              (unsigned int)b_data(&hs->res), hs->req_size, hs->to_write, hs->req_body);
	}

}

int hstream_buf_available(void *target)
{
	struct hstream *hs = target;

	BUG_ON(!hs->sc);

	if ((hs->flags & HS_ST_IN_ALLOC) && b_alloc(&hs->req, DB_CHANNEL)) {
		hs->flags &= ~HS_ST_IN_ALLOC;
		tasklet_wakeup(hs->sc->wait_event.tasklet);
		return 1;
	}

	if ((hs->flags & HS_ST_OUT_ALLOC) && b_alloc(&hs->res, DB_CHANNEL)) {
		hs->flags &= ~HS_ST_OUT_ALLOC;
		tasklet_wakeup(hs->sc->wait_event.tasklet);
		return 1;
	}

	return 0;
}

/*
 * Allocate a buffer. If it fails, it adds the stream in buffer wait queue.
 */
struct buffer *hstream_get_buf(struct hstream *hs, struct buffer *bptr)
{
	struct buffer *buf = NULL;

	if (likely(!LIST_INLIST(&hs->buf_wait.list)) &&
	    unlikely((buf = b_alloc(bptr, DB_CHANNEL)) == NULL)) {
		b_queue(DB_CHANNEL, &hs->buf_wait, hs, hstream_buf_available);
	}

	return buf;
}

/*
 * Release a buffer, if any, and try to wake up entities waiting in the buffer
 * wait queue.
 */
void hstream_release_buf(struct hstream *hs, struct buffer *bptr)
{
	if (bptr->size) {
		b_free(bptr);
		offer_buffers(hs->buf_wait.target, 1);
	}
}

/* Release <hs> httpterm stream */
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

	if ((!hs->res_before_req && hs->req_body) || !htx_is_empty(htxbuf(&hs->req)))
		task_wakeup(hs->task, TASK_WOKEN_IO);

	if (hs->to_write || !htx_is_empty(htxbuf(&hs->res)))
		task_wakeup(hs->task, TASK_WOKEN_IO);

	TRACE_LEAVE(HS_EV_HSTRM_IO_CB, hs);
	return t;
}

static int hstream_recv(struct connection *conn, struct hstream *hs)
{
	int ret = 0;
	struct buffer *buf;
	size_t max, read, cur_read = 0;
	int is_empty, read_poll = MAX_READ_POLL_LOOPS;

	TRACE_ENTER(HS_EV_HSTRM_RECV, hs);

	if (hs->sc->wait_event.events & SUB_RETRY_RECV) {
		TRACE_DEVEL("waiting for data", HS_EV_HSTRM_RECV, hs);
		goto wait_more_data;
	}

	if (sc_ep_test(hs->sc, SE_FL_EOS))
		goto end_recv;

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

	/* prepare to detect if the mux needs more room */
	sc_ep_clr(hs->sc, SE_FL_WANT_ROOM);

	while (sc_ep_test(hs->sc, SE_FL_RCV_MORE) ||
	       (!(conn->flags & CO_FL_ERROR) && !sc_ep_test(hs->sc, SE_FL_ERROR | SE_FL_EOS))) {
		max = (IS_HTX_SC(hs->sc) ?  htx_free_space(htxbuf(&hs->req)) : b_room(&hs->req));
		read = conn->mux->rcv_buf(hs->sc, &hs->req, max, 0);
		cur_read += read;
		if (!read ||
		    sc_ep_test(hs->sc, SE_FL_WANT_ROOM) ||
		    (--read_poll <= 0) ||
		    (read < max && read >= global.tune.recv_enough))
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
	else if ((hs->req_body || !cur_read) && !sc_ep_test(hs->sc, SE_FL_ERROR | SE_FL_EOS)) {
		TRACE_DEVEL("subscribing for read data", HS_EV_HSTRM_RECV, hs);
		conn->mux->subscribe(hs->sc, SUB_RETRY_RECV, &hs->sc->wait_event);
		goto wait_more_data;
	}

	ret = 1;
 leave:
	hstream_release_buf(hs, &hs->req);
	TRACE_PRINTF(TRACE_LEVEL_PROTO, HS_EV_HSTRM_RECV, hs, 0, 0, 0,
	             "data received (%llu) ret=%d", (unsigned long long)cur_read, ret);
	TRACE_LEAVE(HS_EV_HSTRM_RECV, hs);
	return ret;
 stop:
	ret = 2;
 wait_more_data:
	ret = 3;
	goto leave;
}

/* Send HTX data prepared for <hs> httpterm stream from <conn> connection */
static int hstream_send(struct connection *conn, struct hstream *hs)
{
	struct stconn *sc = hs->sc;
	int ret = 0;
	int nret;

	TRACE_ENTER(HS_EV_HSTRM_SEND, hs);

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
	if (!htx_is_empty(htxbuf(&hs->res)) || hs->to_write > 0) {
		TRACE_DEVEL("data not fully sent, wait", HS_EV_HSTRM_SEND, hs);
		conn->mux->subscribe(sc, SUB_RETRY_SEND, &sc->wait_event);
	}

	ret = 1;
 out:
	if (htx_is_empty(htxbuf(&hs->res)) || ret == 0) {
		TRACE_DEVEL("releasing underlying buffer", HS_EV_HSTRM_SEND, hs);
		hstream_release_buf(hs, &hs->res);
	}

	/* XXX TODO check the condition to shut this sc */
	if (!hs->to_write && !hs->req_body && !b_data(&hs->res)) {
		TRACE_DEVEL("shutting down stream", HS_EV_HSTRM_SEND, hs);
		conn->mux->shut(sc, SE_SHW_SILENT|SE_SHW_NORMAL, NULL);
	}

	TRACE_LEAVE(HS_EV_HSTRM_SEND, hs);
	return ret;
}

/* Build the help response for <hs> httpterm stream.
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

	/* XXX TODO: "Connection" header is not set (perhaps because HTTP/1.0 is used) XXX */
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

	tasklet_wakeup(hs->sc->wait_event.tasklet);
	return 0;
}

static int hstream_add_data(struct htx *htx, struct hstream *hs)
{
	int ret = 0;
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
		modulo = 50;
	}

	offset = (hs->req_size - hs->to_write) % modulo;
	data_ptr = buffer + offset;
	max = hs->to_write;
	if (max > (unsigned long long)(buffer_len - offset))
		max = (unsigned long long)buffer_len - offset;

	ret = htx_add_data(htx, ist2(data_ptr, max));
	if (!ret) {
		TRACE_ERROR("unable to add payload to HTX message", HS_EV_HSTRM_ADD_DATA, hs);
		goto err;
	}

	hs->to_write -= ret;
leave:
	TRACE_LEAVE(HS_EV_HSTRM_ADD_DATA, hs);
	return ret;
err:
	TRACE_DEVEL("leaving on error", HS_EV_HSTRM_ADD_DATA);
	goto leave;
}

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

	/* XXX TODO time? total? XXX */
	snprintf(hdrbuf, sizeof(hdrbuf), "size=%ld, time=%ld ms", (long)hs->total, 0L);
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

    if (hs->to_write > 0 && !hstream_add_data(htx, hs)) {
		TRACE_ERROR("could not add data", HS_EV_HSTRM_RESP, hs);
        goto err;
	}

    if (!hs->to_write)
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


static void hstream_parse_uri(struct ist uri, struct hstream *hs, struct connection *conn)
{
	char *next;
	char *end = istptr(uri) + istlen(uri);
	char *arg;
	long result, mult;
	int use_rand;

	/* we'll check for the following URIs :
	 * /?{s=<size>|r=<resp>|t=<time>|c=<cache>}[&{...}]
	 * /? to get the help page.
	 */
	if ((next = strchr(istptr(uri), '?'))) {
		next += 1;
		arg = next;
		if (next == end || *next == ' ') {
			hs->flags |= HS_ST_HTTP_HELP;
			return;
		}

		while (arg + 2 <= end && arg[1] == '=') {
			use_rand = 0;
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
					hs->req_time = result << mult;
					break;
				case 'w':
					hs->ka_time = result << mult;
					break;
				case 'c':
					hs->req_cache = result << mult;
					break;
				case 'A':
					hs->res_before_req = result;
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
		goto out;
	}

    if (!(hs->flags & HS_ST_HTTP_GOT_HDRS)) {
		struct htx *htx = htx_from_buf(&hs->req);
		struct htx_sl *sl = http_get_stline(htx);
		struct http_hdr_ctx expect, clength;

		if (sl->flags & HTX_SL_F_VER_11)
			hs->ka = 5;

		hs->flags |= HS_ST_HTTP_GOT_HDRS;
		uri = htx_sl_req_uri(http_get_stline(htx));
		hstream_parse_uri(uri, hs, conn);

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
				hstream_send(conn, hs);
		}

		hstream_release_buf(hs, &hs->req);
		if (!hs->res_before_req && hs->req_body) {
			rcvd = hstream_recv(conn, hs);
			if (rcvd == 3) {
				TRACE_STATE("waiting for more data", HS_EV_HSTRM_RESP, hs);
				goto leave;
			}
		}

		if (!(hs->flags & HS_ST_HTTP_RESP_SL_SENT)) {
			if (hs->flags & HS_ST_HTTP_HELP) {
				if (hstream_build_http_help_resp(hs))
					hstream_send(conn, hs);
			}
			else {
				if (hstream_build_http_resp(hs))
					hstream_send(conn, hs);
			}

			hs->flags |= HS_ST_HTTP_RESP_SL_SENT;
		}
	}
	else {
		struct buffer *buf;
		struct htx *htx;

		if (!hs->res_before_req && hs->req_body) {
			rcvd = hstream_recv(conn, hs);
			if (rcvd == 3) {
				TRACE_STATE("waiting for more data", HS_EV_HSTRM_RESP, hs);
				goto leave;
			}
		}

		if (!(hs->flags & HS_ST_HTTP_RESP_SL_SENT)) {
			if (hs->flags & HS_ST_HTTP_HELP) {
				if (hstream_build_http_help_resp(hs))
					hstream_send(conn, hs);
			}
			else {
				if (hstream_build_http_resp(hs))
					hstream_send(conn, hs);
			}

			hs->flags |= HS_ST_HTTP_RESP_SL_SENT;
		}

		buf = hstream_get_buf(hs, &hs->res);
		if (!buf) {
			TRACE_ERROR("could not allocate response buffer", HS_EV_HSTRM_RESP, hs);
			goto err;
		}

		htx = htx_from_buf(buf);
		if (hs->to_write && !hstream_add_data(htx, hs))
			goto err;

		if (!hs->to_write)
			htx->flags |= HTX_FL_EOM;
		htx_to_buf(htx, &hs->res);
		hstream_send(conn, hs);
	}

 out:
	if (hs->flags & HS_ST_CONN_ERROR ||
	    (!hs->to_write && htx_is_empty(htxbuf(&hs->res)))) {
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

	hs->obj_type = OBJ_TYPE_HTTPTERM;
	hs->sess = sess;
	hs->sc = sc;
	hs->task = t;
	hs->to_write = 0;

	LIST_INIT(&hs->buf_wait.list);
	hs->flags = 0;

	hs->req_cache = 1;
	hs->req_size = 0;
	hs->req_body = 0;
	hs->req_code = 200;
	hs->req_time = 0;
	hs->req_chunked = 0;
	hs->req_random = 0;
	hs->res_before_req = 0;
	hs->ka = 0;
	hs->total = 0;

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
		if (i % 50 == 49)
			common_response[i] = '\n';
		else if (i % 10 == 0)
			common_response[i] = '.';
		else
			common_response[i] = '0' + i % 10;
	}

	/* httpterm chunk mode responses are made of 1-byte chunks
	 * but the mux does not support this. At this time
	 * these reponses are handled the same way as for common
	 * responses with a pre-built buffer.
	 */
	for (i = 0; i < sizeof(common_chunk_resp); i++)
		common_chunk_resp[i] = '1';

    random_resp = malloc(random_resp_len);
    if (!random_resp)
	    return -1;

    for (i = 0; i < random_resp_len; i++)
		random_resp[i] = rand() >> 16;

	return 1;
}

REGISTER_POST_CHECK(hstream_build_responses);
