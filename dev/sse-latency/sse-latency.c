/*
 * sse-latency.c - SSE benchmark tool for AI gateways, both client and server.
 *
 * Copyright (C) 2026 Willy Tarreau <w@1wt.eu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * A single process plays both roles at once, sharing one process-local clock:
 *
 * SERVER side: listens on -L and exposes an OpenAI-like
 * POST /v1/chat/completions endpoint that streams chat.completion.chunk SSE
 * events over HTTP/1.1 chunked encoding. Each token is a 4-letter word. The
 * number of tokens, the pre-first-token ("thinking") delay and the
 * inter-token delay are configurable and overridable per-request via the
 * JSON body ("pi_tokens", "pi_think_ms", "pi_delay_ms"). Each chunk carries
 * an extra "pi_ts" field with the emission time in nanoseconds since the
 * epoch (CLOCK_REALTIME), taken at the moment the chunk is appended to the
 * socket, so that the client can measure the one-way delay through the
 * gateway using the same clock.
 *
 * CLIENT side: connects to -t (the gateway), sends an OpenAI-like streaming
 * chat completion request, then reads the SSE stream (transparently handling
 * chunked encoding if the gateway uses it) and records:
 *   - TTFT: time from request fully written to first content token received
 *   - inter-token gaps: arrival time deltas between consecutive tokens
 *   - emission delay: arrival_time - pi_ts of each chunk
 *
 * By default a loopback calibration batch is run first (client connects
 * directly to the listening address), then the gateway batch, and the
 * difference between both is reported as the estimated gateway overhead.
 */

#define _GNU_SOURCE     /* for POLLRDHUP, memmem, strcasestr */
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

/* growable array of doubles, values in milliseconds */
struct dlist {
	double *v;
	size_t  n;
	size_t  cap;
};

struct batch_stats {
	struct dlist ttft;      /* per request, ms */
	struct dlist emit_ttft; /* per request, ms */
	struct dlist gaps;      /* per token, ms */
	struct dlist emits;     /* per token, ms */
	int nb_req;             /* number of requests in this batch */
	long ok_req, fail_req, tok_count;
};

enum {
	ROLE_SERVER,
	ROLE_CLIENT,
};

/* server states */
enum {
	CS_READ_REQ,      /* reading the HTTP request */
	CS_EMIT,          /* emitting tokens on schedule */
	CS_FLUSH_CLOSE,   /* draining then close */
};

/* client chunked-decoding states */
enum {
	CC_HEAD,       /* reading response headers */
	CC_RAW,        /* no chunked encoding: raw stream till close */
	CC_CHUNK_LINE, /* chunked: reading the chunk size line */
	CC_CHUNK_DATA, /* chunked: reading chunk payload */
	CC_CHUNK_CRLF, /* chunked: reading the CRLF after payload */
	CC_LAST_CHUNK, /* chunked: after the last (0) chunk, discard */
};

struct batch_ctx {
	struct sockaddr_storage target;
	char    host[64];      /* target address as a string, for Host: */
	int     total, started, done, failed;
	long    tokens_hint;   /* per-request pi_tokens override, 0 = none */
};

struct conn {
	int      fd;
	int      role;
	int      state;

	char    *rbuf;         size_t rlen, rcap;   /* raw receive buffer */
	char    *wbuf;         size_t wlen, wpos, wcap;
	char    *sbuf;         size_t slen, scap;   /* SSE line reassembly */

	/* server */
	long     tokens_left;
	long     delay_us;     /* inter-token delay */
	uint64_t next_wake_us; /* monotonic deadline of next emission */
	long     chunk_index;
	char     id[48];

	/* client */
	int      idx;          /* request index within the batch */
	int      connecting;
	int      cstate;       /* CC_* */
	int      chunked;
	int      status_ok;
	int      head_ok;
	uint64_t csize, cpos;  /* current chunked chunk being decoded */
	uint64_t deadline_us;  /* monotonic overall timeout */
	uint64_t t0_us;        /* monotonic start, for wall time */
	uint64_t sent_ns;      /* realtime ns when request fully written */
	uint64_t last_arrival_ns;
	double   ttft_ms;
	double   emit_ttft_ms;
	long     tok_recv;
	int      ok;
	char     err[128];
};

/* ------------------------------------------------------------------ */
/* Options and globals                                                 */
/* ------------------------------------------------------------------ */

static const char *listen_str = ":8090";
static const char *target_str = NULL;   /* NULL = server only */
static int    nb_requests  = 1;
static int    concurrency  = 1;
static long   nb_tokens    = 1000;
static double think_ms     = 0.0;
static double delay_ms     = 5.0;
static long   timeout_ms   = 300000;
static int    use_loopback = 1;
static int    quiet;
static int    verbose;

static int listener_fd = -1;

static struct batch_ctx   *cur_batch;
static struct batch_stats *cur_stats;
static const char         *ctx_tag;       /* "loop" or "gw", for per-req lines */
static uint64_t             prog_tokens;  /* tokens received in current batch */
static uint64_t             batch_t0_us;
static int                  progress_shown;/* a progress line is on stderr */

static struct conn **conns;
static int nbconns, conncap;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

/* display the message and exit with the code */
__attribute__((noreturn)) void die(int code, const char *format, ...)
{
	va_list args;

	if (format) {
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
	}
	exit(code);
}

/* display the usage message and exit with the code */
__attribute__((noreturn)) void usage(int code, const char *arg0)
{
	die(code,
	    "Usage : %s [options]*\n"
	    "\n"
	    "SSE benchmark for AI gateways: runs an OpenAI-like SSE server\n"
	    "and an SSE client in the same process, sharing one clock.\n"
	    "\n"
	    "options :\n"
	    "  -L <[ip:]port> : address to bind the dummy OpenAI-like SSE server to\n"
	    "                   (default :8090)\n"
	    "  -t <[ip:]port> : gateway address to send requests to (default: none,\n"
	    "                   server only)\n"
	    "  -r <n>         : number of client requests to send (default 1)\n"
	    "  -c <n>         : number of parallel client requests (default 1)\n"
	    "  -n <n>         : tokens per response (default 1000)\n"
	    "  -T <ms>        : delay before the first token, aka thinking (default 0)\n"
	    "  -d <ms>        : delay between tokens (default 5, float ok)\n"
	    "  -w <ms>        : per-request timeout (default 300000)\n"
	    "  -l             : disable the loopback calibration batch\n"
	    "  -q             : quiet, don't print per-request lines\n"
	    "  -v             : verbose\n"
	    "  -h             : this help\n"
	    "\n"
	    "Example against a gateway on 127.0.0.1:8080 forwarding to this tool's\n"
	    "server listening on :8090 :\n"
	    "  %s -L :8090 -t 127.0.0.1:8080 -r 20 -c 5\n"
	    "\n"
	    "Metrics reported :\n"
	    "  TTFT (client)          request fully sent -> first token received\n"
	    "  TTFT emit->recv(1st)   one-way delay of the first token\n"
	    "  inter-token (client)   gaps between consecutive token arrivals\n"
	    "  emit->recv (tokens)    one-way delay of every token\n"
	    "  gateway overhead       gateway batch minus loopback batch\n"
	    "", arg0, arg0);
}

/* erases the progress line if one is currently displayed, so that real
 * output doesn't get glued to it.
 */
static void progress_clear(void)
{
	if (progress_shown) {
		fprintf(stderr, "\r\33[K");
		progress_shown = 0;
	}
}

/* current time in nanoseconds since the epoch, for the pi_ts fields */
static inline uint64_t now_ns_real(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* current monotonic time in microseconds, for scheduling */
static inline uint64_t now_us_mono(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

/* case-insensitive search of a NUL-terminated needle within at most
 * <haylen> bytes of <hay> (which is NOT necessarily NUL-terminated).
 */
static const char *ci_find(const char *hay, size_t haylen, const char *needle)
{
	size_t nlen = strlen(needle);
	size_t i, j;

	if (nlen > haylen)
		return NULL;

	for (i = 0; i + nlen <= haylen; i++) {
		for (j = 0; j < nlen; j++)
			if (tolower((unsigned char)hay[i + j]) != tolower((unsigned char)needle[j]))
				break;
		if (j == nlen)
			return hay + i;
	}
	return NULL;
}

/* converts str in the form [[<ipv4>|<ipv6>|<hostname>]:]port to struct
 * sockaddr_storage. Returns < 0 in case of error.
 */
static int addr_to_ss(const char *str, struct sockaddr_storage *ss)
{
	char *str_copy, *port_str;
	int port;

	memset(ss, 0, sizeof(*ss));

	str_copy = strdup(str);
	if (!str_copy)
		die(1, "out of memory\n");

	/* look for the addr/port delimiter, it's the last colon. If there's no
	 * colon, it's 0:<port>.
	 */
	if ((port_str = strrchr(str_copy, ':')) == NULL) {
		port = atoi(str_copy);
		if (port < 0 || port > 65535) {
			fprintf(stderr, "Missing/invalid port number: '%s'\n", str);
			goto fail;
		}

		ss->ss_family = AF_INET;
		((struct sockaddr_in *)ss)->sin_port = htons(port);
		((struct sockaddr_in *)ss)->sin_addr.s_addr = INADDR_ANY;
		goto done;
	}

	*port_str++ = 0;

	if (strrchr(str_copy, ':') != NULL) {
		/* IPv6 address contains ':' */
		ss->ss_family = AF_INET6;
		((struct sockaddr_in6 *)ss)->sin6_port = htons(atoi(port_str));

		if (!inet_pton(ss->ss_family, str_copy, &((struct sockaddr_in6 *)ss)->sin6_addr)) {
			fprintf(stderr, "Invalid server address: '%s'\n", str);
			goto fail;
		}
	}
	else {
		ss->ss_family = AF_INET;
		((struct sockaddr_in *)ss)->sin_port = htons(atoi(port_str));

		if (*str_copy == '*' || *str_copy == '\0') { /* INADDR_ANY */
			((struct sockaddr_in *)ss)->sin_addr.s_addr = INADDR_ANY;
			goto done;
		}

		if (!inet_pton(ss->ss_family, str_copy, &((struct sockaddr_in *)ss)->sin_addr)) {
			struct hostent *he = gethostbyname(str_copy);

			if (he == NULL) {
				fprintf(stderr, "Invalid server name: '%s'\n", str);
				goto fail;
			}
			((struct sockaddr_in *)ss)->sin_addr = *(struct in_addr *)*he->h_addr_list;
		}
	}
 done:
	free(str_copy);
	return 0;
 fail:
	free(str_copy);
	return -1;
}

static int addr_eq(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return 0;

	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *x = (const struct sockaddr_in *)a;
		const struct sockaddr_in *y = (const struct sockaddr_in *)b;

		return x->sin_port == y->sin_port &&
		       x->sin_addr.s_addr == y->sin_addr.s_addr;
	}

	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)b;

		return x->sin6_port == y->sin6_port &&
		       !memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr));
	}

	return 0;
}

/* replaces the wildcard address with loopback, for addresses used as
 * connection destinations (a bare ":port" or "port" argument).
 */
static void addr_force_loopback(struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;

		if (sin->sin_addr.s_addr == INADDR_ANY)
			sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	else if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

		if (!memcmp(&sin6->sin6_addr, &in6addr_any, sizeof(sin6->sin6_addr)))
			sin6->sin6_addr = in6addr_loopback;
	}
}

static const char *addr_to_str(const struct sockaddr_storage *ss)
{
	static char buf[INET6_ADDRSTRLEN + 8];

	if (ss->ss_family == AF_INET) {
		const struct sockaddr_in *s = (const struct sockaddr_in *)ss;
		char tmp[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &s->sin_addr, tmp, sizeof(tmp));
		snprintf(buf, sizeof(buf), "%s:%d", tmp, ntohs(s->sin_port));
	}
	else {
		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)ss;
		char tmp[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, &s->sin6_addr, tmp, sizeof(tmp));
		snprintf(buf, sizeof(buf), "%s:%d", tmp, ntohs(s->sin6_port));
	}
	return buf;
}

/* ------------------------------------------------------------------ */
/* Statistics                                                          */
/* ------------------------------------------------------------------ */

static void dl_push(struct dlist *l, double x)
{
	if (l->n == l->cap) {
		l->cap = l->cap ? l->cap * 2 : 256;
		l->v = realloc(l->v, l->cap * sizeof(*l->v));
		if (!l->v)
			die(1, "out of memory\n");
	}
	l->v[l->n++] = x;
}

static int dbl_cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	if (x < y)
		return -1;
	if (x > y)
		return 1;
	return 0;
}

/* returns a sorted copy of the list, or NULL if empty */
static double *dl_sorted(const struct dlist *l)
{
	double *v;

	if (!l->n)
		return NULL;

	v = malloc(l->n * sizeof(*v));
	if (!v)
		die(1, "out of memory\n");
	memcpy(v, l->v, l->n * sizeof(*v));
	qsort(v, l->n, sizeof(*v), dbl_cmp);
	return v;
}

static void stats_line(const char *name, const struct dlist *l)
{
	double *v, sum = 0, mean;
	size_t i;

	if (!l->n) {
		printf("%-24s n=0\n", name);
		return;
	}

	v = dl_sorted(l);
	for (i = 0; i < l->n; i++)
		sum += v[i];
	mean = sum / l->n;

	printf("%-24s n=%zu  mean=%.2fms  min=%.2fms  p50=%.2fms  p95=%.2fms  p99=%.2fms  max=%.2fms\n",
	       name, l->n, mean, v[0],
	       v[(size_t)((l->n - 1) * 0.50)],
	       v[(size_t)((l->n - 1) * 0.95)],
	       v[(size_t)((l->n - 1) * 0.99)],
	       v[l->n - 1]);
	free(v);
}

/* prints the difference of <gw> relative to <loop> (gw minus loop).
 * Negative values just mean the loopback run happened to be noisier.
 */
static void delta_line(const char *name, const struct dlist *gw, const struct dlist *lo)
{
	double *vg, *vl, sg = 0, sl = 0;
	size_t i;

	if (!gw->n || !lo->n) {
		printf("%-24s n/a (no samples)\n", name);
		return;
	}

	vg = dl_sorted(gw);
	vl = dl_sorted(lo);
	for (i = 0; i < gw->n; i++)
		sg += vg[i];
	for (i = 0; i < lo->n; i++)
		sl += vl[i];

	printf("%-24s mean %+.3fms  p50 %+.3fms  p95 %+.3fms  p99 %+.3fms\n",
	       name,
	       sg / gw->n - sl / lo->n,
	       vg[(size_t)((gw->n - 1) * 0.50)] - vl[(size_t)((lo->n - 1) * 0.50)],
	       vg[(size_t)((gw->n - 1) * 0.95)] - vl[(size_t)((lo->n - 1) * 0.95)],
	       vg[(size_t)((gw->n - 1) * 0.99)] - vl[(size_t)((lo->n - 1) * 0.99)]);
	free(vg);
	free(vl);
}

static void print_batch(const char *title, struct batch_stats *st)
{
	printf("\n=== %s: %d requests, %ld ok, %ld failed, %ld tokens ===\n",
	       title, st->nb_req, st->ok_req, st->fail_req, st->tok_count);
	stats_line("TTFT (client)",        &st->ttft);
	stats_line("TTFT emit->recv(1st)", &st->emit_ttft);
	stats_line("inter-token (client)", &st->gaps);
	stats_line("emit->recv (tokens)",  &st->emits);
}

/* ------------------------------------------------------------------ */
/* Connection basics                                                    */
/* ------------------------------------------------------------------ */

static void conn_append(struct conn *c, const char *data, size_t len)
{
	if (c->wlen + len > c->wcap) {
		size_t cap = c->wcap;

		while (c->wlen + len > cap)
			cap = cap ? cap * 2 : 8192;
		c->wbuf = realloc(c->wbuf, cap);
		if (!c->wbuf)
			die(1, "out of memory\n");
		c->wcap = cap;
	}
	memcpy(c->wbuf + c->wlen, data, len);
	c->wlen += len;
}

/* tries to write pending data. Returns -1 on write error (caller closes). */
static int conn_flush(struct conn *c)
{
	while (c->wpos < c->wlen) {
		ssize_t ret = send(c->fd, c->wbuf + c->wpos, c->wlen - c->wpos, MSG_NOSIGNAL);

		if (ret > 0) {
			c->wpos += ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			break;
		return -1;
	}

	if (c->wpos == c->wlen) {
		c->wpos = c->wlen = 0;

		/* for clients, this is the "request fully sent" instant */
		if (c->role == ROLE_CLIENT && !c->sent_ns)
			c->sent_ns = now_ns_real();
	}
	else if (c->wpos > 65536) {
		/* compact the pending data */
		memmove(c->wbuf, c->wbuf + c->wpos, c->wlen - c->wpos);
		c->wlen -= c->wpos;
		c->wpos = 0;
	}
	return 0;
}

/* close and release the connection. <err> marks a client-side failure. */
static void conn_close(struct conn *c, const char *err)
{
	int i;

	if (err && c->role == ROLE_CLIENT && !c->err[0])
		snprintf(c->err, sizeof(c->err), "%s", err);

	if (c->role == ROLE_CLIENT && cur_batch) {
		struct batch_ctx *ctx = cur_batch;
		uint64_t wall_us = now_us_mono() - c->t0_us;

		ctx->done++;
		if (c->ok) {
			cur_stats->ok_req++;
			cur_stats->tok_count += c->tok_recv;
		} else {
			ctx->failed++;
			cur_stats->fail_req++;
		}

		if (!quiet) {
			progress_clear();
			if (c->ok)
				printf("%s %3d: ok  ttft=%9.2fms  emit-delay(first)=%9.2fms  tokens=%ld  wall=%.3fs\n",
				       ctx_tag, c->idx, c->ttft_ms, c->emit_ttft_ms,
				       c->tok_recv, wall_us / 1000000.0);
			else
				printf("%s %3d: FAILED: %s\n", ctx_tag, c->idx, c->err);
		}
	}

	close(c->fd);
	free(c->rbuf);
	free(c->wbuf);
	free(c->sbuf);

	/* remove from the list */
	for (i = 0; i < nbconns; i++) {
		if (conns[i] == c) {
			conns[i] = conns[--nbconns];
			break;
		}
	}
	free(c);
}

static struct conn *conn_new(int fd, int role)
{
	struct conn *c;

	c = calloc(1, sizeof(*c));
	if (!c)
		die(1, "out of memory\n");

	c->fd = fd;
	c->role = role;
	c->state = role == ROLE_SERVER ? CS_READ_REQ : CS_EMIT;
	c->cstate = CC_HEAD;

	if (nbconns == conncap) {
		conncap = conncap ? conncap * 2 : 16;
		conns = realloc(conns, conncap * sizeof(*conns));
		if (!conns)
			die(1, "out of memory\n");
	}
	conns[nbconns++] = c;
	return c;
}

/* flush pending output, close the connection if it failed or if a server
 * connection reached the end of its response. Returns -1 if closed.
 */
static int conn_output(struct conn *c)
{
	if (conn_flush(c) < 0) {
		conn_close(c, NULL);
		return -1;
	}
	if (c->role == ROLE_SERVER && c->state == CS_FLUSH_CLOSE &&
	    c->wpos == c->wlen) {
		conn_close(c, NULL);
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Server side: SSE emission                                            */
/* ------------------------------------------------------------------ */

/* appends one SSE event wrapped in its own HTTP chunk */
static void sse_append(struct conn *c, const char *payload, size_t plen)
{
	char hdr[16];
	int hlen;

	hlen = snprintf(hdr, sizeof(hdr), "%zx\r\n", plen + 6 + 2);
	conn_append(c, hdr, hlen);
	conn_append(c, "data: ", 6);
	conn_append(c, payload, plen);
	conn_append(c, "\n\n\r\n", 4);
}

/* 4-letter pseudo-word for token index <i> */
static void token_text(long i, char out[4])
{
	const char letters[] = "abcdefghijklmnopqrstuvwxyz";
	int j;

	for (j = 0; j < 4; j++)
		out[j] = letters[(i * 7 + j * 13) % 26];
}

/* builds and queues one content chunk; timestamped at append time */
static void server_queue_token(struct conn *c)
{
	char json[512];
	char tok[4];
	uint64_t pi_ts = now_ns_real();
	int jl;

	token_text(c->chunk_index++, tok);

	jl = snprintf(json, sizeof(json),
		      "{\"id\":\"%s\",\"object\":\"chat.completion.chunk\","
		      "\"created\":%llu,\"pi_ts\":%llu,\"model\":\"sse-latency-1\","
		      "\"choices\":[{\"index\":0,"
		      "\"delta\":{\"content\":\"%c%c%c%c\"},"
		      "\"finish_reason\":null}]}",
		      c->id, (unsigned long long)(pi_ts / 1000000000ULL),
		      (unsigned long long)pi_ts,
		      tok[0], tok[1], tok[2], tok[3]);

	sse_append(c, json, jl);
}

/* queues the final chunk, [DONE] and the terminating empty HTTP chunk */
static void server_queue_finish(struct conn *c)
{
	char json[512];
	uint64_t pi_ts = now_ns_real();
	int jl;

	jl = snprintf(json, sizeof(json),
		      "{\"id\":\"%s\",\"object\":\"chat.completion.chunk\","
		      "\"created\":%llu,\"pi_ts\":%llu,\"model\":\"sse-latency-1\","
		      "\"choices\":[{\"index\":0,\"delta\":{},"
		      "\"finish_reason\":\"stop\"}]}",
		      c->id, (unsigned long long)(pi_ts / 1000000000ULL),
		      (unsigned long long)pi_ts);

	sse_append(c, json, jl);
	sse_append(c, "[DONE]", 6);
	conn_append(c, "0\r\n\r\n", 5);
	c->state = CS_FLUSH_CLOSE;
}

/* processes a complete HTTP request: extracts the hints, queues the
 * response head + role chunk, and schedules the first token.
 * Returns -1 if the connection was closed.
 */
static int server_process_request(struct conn *c)
{
	char head[512], json[512];
	const char *body, *p;
	size_t head_end, body_len = 0;
	long tokens = nb_tokens;
	double think = think_ms, delay = delay_ms;
	uint64_t pi_ts;
	int hl, jl;

	/* find end of headers */
	p = memmem(c->rbuf, c->rlen, "\r\n\r\n", 4);
	if (!p)
		return 0; /* not yet */
	head_end = p - c->rbuf + 4;

	/* only POST is supported */
	if (c->rlen < 4 || strncmp(c->rbuf, "POST", 4)) {
		static const char notfound[] =
			"HTTP/1.1 404 Not Found\r\n"
			"Content-Length: 0\r\n"
			"Connection: close\r\n"
			"\r\n";

		conn_append(c, notfound, sizeof(notfound) - 1);
		c->state = CS_FLUSH_CLOSE;
		return conn_output(c);
	}

	/* find Content-Length within the headers */
	if ((p = ci_find(c->rbuf, head_end, "\nContent-Length:")))
		body_len = strtoul(p + 15, NULL, 10);

	/* wait for the whole body */
	if (c->rlen < head_end + body_len)
		return 0;

	body = c->rbuf + head_end;

	/* make sure the body is NUL-terminated for the hint parsers below */
	if (c->rcap < c->rlen + 1) {
		c->rcap = c->rlen + 1;
		c->rbuf = realloc(c->rbuf, c->rcap);
		if (!c->rbuf)
			die(1, "out of memory\n");
	}
	c->rbuf[c->rlen] = 0;

	/* per-request overrides, ignored by real gateways */
	if ((p = strstr(body, "\"pi_tokens\":")))
		tokens = strtoul(p + 12, NULL, 10);
	if ((p = strstr(body, "\"pi_think_ms\":")))
		think = strtod(p + 14, NULL);
	if ((p = strstr(body, "\"pi_delay_ms\":")))
		delay = strtod(p + 14, NULL);

	if (tokens < 0)
		tokens = 0;

	/* response id, shared by all chunks of this response */
	snprintf(c->id, sizeof(c->id), "chatcmpl-sse-latency-%llu",
		 (unsigned long long)(now_ns_real() % 100000000000ULL));

	/* response head + role chunk */
	hl = snprintf(head, sizeof(head),
		      "HTTP/1.1 200 OK\r\n"
		      "Content-Type: text/event-stream\r\n"
		      "Cache-Control: no-cache\r\n"
		      "Connection: close\r\n"
		      "X-Accel-Buffering: no\r\n"
		      "Transfer-Encoding: chunked\r\n"
		      "\r\n");
	conn_append(c, head, hl);

	pi_ts = now_ns_real();
	jl = snprintf(json, sizeof(json),
		      "{\"id\":\"%s\",\"object\":\"chat.completion.chunk\","
		      "\"created\":%llu,\"pi_ts\":%llu,\"model\":\"sse-latency-1\","
		      "\"choices\":[{\"index\":0,"
		      "\"delta\":{\"role\":\"assistant\"},"
		      "\"finish_reason\":null}]}",
		      c->id, (unsigned long long)(pi_ts / 1000000000ULL),
		      (unsigned long long)pi_ts);
	sse_append(c, json, jl);

	c->tokens_left = tokens;
	c->delay_us = (long)(delay * 1000.0);
	c->next_wake_us = now_us_mono() + (long)(think * 1000.0);
	c->state = CS_EMIT;

	/* we don't expect anything more from the client; drop the request */
	free(c->rbuf);
	c->rbuf = NULL;
	c->rlen = c->rcap = 0;

	if (verbose)
		fprintf(stderr, "srv %d: %ld tokens, think %.0fms, delay %.0fms\n",
			c->fd, tokens, think, delay);

	return conn_output(c);
}

/* ------------------------------------------------------------------ */
/* Client side                                                          */
/* ------------------------------------------------------------------ */

static void client_spawn(struct batch_ctx *ctx)
{
	struct sockaddr_storage *ss = &ctx->target;
	struct conn *c;
	char req[1024];
	char body[256];
	socklen_t sslen;
	int fd, ret, rl, bl;

	/* the calibration batch shortens its responses via the pi_tokens hint,
	 * which our own server honors and real gateways silently ignore.
	 */
	if (ctx->tokens_hint > 0)
		bl = snprintf(body, sizeof(body),
			      "{\"model\":\"sse-latency-1\",\"stream\":true,"
			      "\"messages\":[{\"role\":\"user\",\"content\":\"Say 4-letter words\"}],"
			      "\"pi_tokens\":%ld}", ctx->tokens_hint);
	else
		bl = snprintf(body, sizeof(body),
			      "{\"model\":\"sse-latency-1\",\"stream\":true,"
			      "\"messages\":[{\"role\":\"user\",\"content\":\"Say 4-letter words\"}]}");

	fd = socket(ss->ss_family, SOCK_STREAM, 0);
	if (fd < 0)
		die(1, "socket(): %s\n", strerror(errno));

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	{
		int one = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	}

	rl = snprintf(req, sizeof(req),
		      "POST /v1/chat/completions HTTP/1.1\r\n"
		      "Host: %s\r\n"
		      "Content-Type: application/json\r\n"
		      "Accept: text/event-stream\r\n"
		      "Content-Length: %d\r\n"
		      "Connection: close\r\n"
		      "\r\n"
		      "%s",
		      ctx->host, bl, body);

	c = conn_new(fd, ROLE_CLIENT);
	c->idx = ctx->started++;
	c->connecting = 1;
	c->t0_us = now_us_mono();
	c->deadline_us = c->t0_us + (uint64_t)timeout_ms * 1000;
	conn_append(c, req, rl);

	sslen = ss->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6)
	                                  : sizeof(struct sockaddr_in);
	ret = connect(fd, (const struct sockaddr *)ss, sslen);
	if (ret < 0 && errno != EINPROGRESS) {
		snprintf(c->err, sizeof(c->err), "connect(): %s", strerror(errno));
		conn_close(c, NULL);
		return;
	}

	if (verbose)
		fprintf(stderr, "cl %d: connecting (req %d)\n", fd, c->idx);
}

/* processes one complete SSE line (NUL-terminated in c->sbuf).
 * Returns -1 if the connection was closed.
 */
static int client_line(struct conn *c, char *line)
{
	char *data, *p;

	/* strip trailing CR */
	p = line + strlen(line);
	if (p > line && p[-1] == '\r')
		p[-1] = 0;

	if (strncmp(line, "data:", 5))
		return 0; /* not a data line */

	data = line + 5;
	while (*data == ' ' || *data == '\t')
		data++;

	if (!strcmp(data, "[DONE]")) {
		c->ok = c->tok_recv > 0;
		if (!c->ok && !c->err[0])
			snprintf(c->err, sizeof(c->err), "no content tokens received");
		conn_close(c, NULL);
		return -1;
	}

	/* extract pi_ts */
	p = strstr(data, "\"pi_ts\":");
	if (!p)
		return 0; /* unknown frame, ignore */
	{
		uint64_t pi_ts = strtoull(p + 8, NULL, 10);
		uint64_t arrival = now_ns_real();
		double delta_ms = (double)(arrival - pi_ts) / 1e6;

		/* a content token? */
		p = strstr(data, "\"content\":\"");
		if (!p || p[11] == '"')
			return 0; /* role or finish chunk */

		c->tok_recv++;
		prog_tokens++;

		if (c->tok_recv == 1) {
			c->ttft_ms = c->sent_ns ?
				(double)(arrival - c->sent_ns) / 1e6 : -1.0;
			c->emit_ttft_ms = delta_ms;
			if (cur_stats) {
				dl_push(&cur_stats->ttft, c->ttft_ms);
				dl_push(&cur_stats->emit_ttft, delta_ms);
			}
		} else {
			if (cur_stats) {
				dl_push(&cur_stats->gaps,
					(double)(arrival - c->last_arrival_ns) / 1e6);
				dl_push(&cur_stats->emits, delta_ms);
			}
		}
		c->last_arrival_ns = arrival;
	}
	return 0;
}

/* feeds decoded payload bytes to the SSE line reassembly buffer.
 * Returns -1 if the connection was closed.
 */
static int client_sse_feed(struct conn *c, const char *data, size_t len)
{
	while (len) {
		char *nl = memchr(data, '\n', len);
		size_t got;
		int ret;

		if (!nl) {
			/* no complete line, keep the remainder */
			if (c->slen + len > c->scap) {
				c->scap = c->slen + len + 256;
				c->sbuf = realloc(c->sbuf, c->scap);
				if (!c->sbuf)
					die(1, "out of memory\n");
			}
			memcpy(c->sbuf + c->slen, data, len);
			c->slen += len;
			break;
		}

		got = nl - data; /* length without the \n */

		if (c->slen + got + 1 > c->scap) {
			c->scap = c->slen + got + 1;
			c->sbuf = realloc(c->sbuf, c->scap);
			if (!c->sbuf)
				die(1, "out of memory\n");
		}
		memcpy(c->sbuf + c->slen, data, got);
		c->sbuf[c->slen + got] = 0;

		ret = client_line(c, c->sbuf);
		c->slen = 0;
		if (ret < 0)
			return -1;

		data += got + 1;
		len -= got + 1;
	}
	return 0;
}

/* consumes bytes from c->rbuf according to the transfer encoding.
 * Returns -1 if the connection was closed.
 */
static int client_feed(struct conn *c)
{
	size_t pos = 0;

	while (pos < c->rlen) {
		size_t avail = c->rlen - pos;
		size_t take;
		char *nl;

		switch (c->cstate) {
		case CC_RAW:
			if (client_sse_feed(c, c->rbuf + pos, avail) < 0)
				return -1;
			pos = c->rlen;
			break;

		case CC_CHUNK_LINE:
			nl = memchr(c->rbuf + pos, '\n', avail);
			if (!nl)
				return 0; /* wait for more */
			{
				uint64_t v = 0;
				char *q;

				for (q = c->rbuf + pos; q < nl; q++) {
					int h;

					if (*q == '\r' || *q == ' ' || *q == '\t')
						continue;
					if (*q >= '0' && *q <= '9')
						h = *q - '0';
					else if (*q >= 'a' && *q <= 'f')
						h = *q - 'a' + 10;
					else if (*q >= 'A' && *q <= 'F')
						h = *q - 'A' + 10;
					else
						break; /* chunk extension, ignore */
					v = v * 16 + h;
				}
				c->csize = v;
				c->cpos = 0;
				c->cstate = v ? CC_CHUNK_DATA : CC_LAST_CHUNK;
			}
			pos = nl - c->rbuf + 1;
			break;

		case CC_CHUNK_DATA:
			take = avail < c->csize - c->cpos ? avail : c->csize - c->cpos;
			if (take) {
				if (client_sse_feed(c, c->rbuf + pos, take) < 0)
					return -1;
				pos += take;
				c->cpos += take;
			}
			if (c->cpos == c->csize)
				c->cstate = CC_CHUNK_CRLF;
			break;

		case CC_CHUNK_CRLF:
			if (avail < 2)
				return 0; /* wait for more */
			pos += 2; /* swallow "\r\n" */
			c->cstate = CC_CHUNK_LINE;
			break;

		case CC_LAST_CHUNK:
			/* discard trailers till EOF; we're done */
			pos = c->rlen;
			if (c->ok) {
				conn_close(c, NULL);
				return -1;
			}
			break;

		default:
			return 0;
		}
	}

	/* everything consumed */
	c->rlen = 0;
	return 0;
}

/* processes bytes accumulated in c->rbuf on a client connection.
 * Returns -1 if the connection was closed.
 */
static int client_process(struct conn *c)
{
	const char *p;

	if (!c->head_ok) {
		size_t head_end;

		p = memmem(c->rbuf, c->rlen, "\r\n\r\n", 4);
		if (!p) {
			if (c->rlen > 65536) {
				conn_close(c, "response headers too large");
				return -1;
			}
			return 0; /* wait for more */
		}
		head_end = p - c->rbuf + 4;

		/* validate the status line directly from the head: at this point
		 * the whole head is present, so the first line is complete.
		 */
		if (c->rlen < 12 || strncmp(c->rbuf, "HTTP/", 5) != 0 ||
		    !isdigit((unsigned char)c->rbuf[5]) || c->rbuf[9] != '2') {
			if (c->rlen >= 12)
				snprintf(c->err, sizeof(c->err), "status %.32s", c->rbuf);
			else
				snprintf(c->err, sizeof(c->err), "short response");
			conn_close(c, NULL);
			return -1;
		}
		c->status_ok = 1;

		/* detect chunked encoding within the head */
		c->chunked = ci_find(c->rbuf, head_end, "chunked") != NULL;
		c->head_ok = 1;
		c->cstate = c->chunked ? CC_CHUNK_LINE : CC_RAW;

		/* move the payload bytes to the front */
		c->rlen -= head_end;
		memmove(c->rbuf, c->rbuf + head_end, c->rlen);
	}

	return client_feed(c);
}

/* ------------------------------------------------------------------ */
/* Socket readiness handling                                            */
/* ------------------------------------------------------------------ */

/* returns -1 if the connection was closed */
static int conn_read(struct conn *c)
{
	ssize_t ret;

	if (c->rlen == c->rcap) {
		c->rcap = c->rcap ? c->rcap * 2 : 16384;
		c->rbuf = realloc(c->rbuf, c->rcap);
		if (!c->rbuf)
			die(1, "out of memory\n");
	}

	ret = recv(c->fd, c->rbuf + c->rlen, c->rcap - c->rlen, 0);
	if (ret > 0) {
		c->rlen += ret;

		if (c->role == ROLE_CLIENT)
			return client_process(c);

		if (c->state == CS_READ_REQ)
			return server_process_request(c);

		/* unexpected data after the request, discard */
		c->rlen = 0;
		return 0;
	}
	if (ret == 0) {
		/* EOF */
		if (c->role == ROLE_CLIENT && !c->ok) {
			conn_close(c, "connection closed before [DONE]");
			return -1;
		}
		conn_close(c, NULL);
		return -1;
	}
	if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		return 0;

	conn_close(c, c->role == ROLE_CLIENT ? "recv error" : NULL);
	return -1;
}

static void do_accept(void)
{
	while (1) {
		int fd = accept(listener_fd, NULL, NULL);
		struct conn *c;
		int one = 1;

		if (fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				return;
			die(1, "accept(): %s\n", strerror(errno));
		}

		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

		c = conn_new(fd, ROLE_SERVER);
		snprintf(c->id, sizeof(c->id), "chatcmpl-sse-latency-%llu",
			 (unsigned long long)(now_ns_real() % 100000000000ULL));

		if (verbose)
			fprintf(stderr, "srv %d: accepted\n", fd);
	}
}

/* ------------------------------------------------------------------ */
/* Event loop                                                           */
/* ------------------------------------------------------------------ */

/* the main poll loop. If <ctx> is NULL, runs forever (server-only mode),
 * otherwise runs until the batch is complete.
 */
static void event_loop(struct batch_ctx *ctx)
{
	struct pollfd *pfds = NULL;
	struct conn **pmap = NULL;
	int cap = 0;
	uint64_t last_prog = 0;

	while (1) {
		uint64_t now = now_us_mono();
		int timeout = 1000;
		int n, i, nb, nb_active;

		if (ctx && ctx->done >= ctx->total)
			return;

		/* spawn clients to fill the concurrency */
		if (ctx) {
			nb_active = 0;
			for (i = 0; i < nbconns; i++)
				if (conns[i]->role == ROLE_CLIENT)
					nb_active++;
			while (ctx->started < ctx->total && nb_active < concurrency) {
				client_spawn(ctx);
				nb_active++;
			}
		}

		/* build the pollfd map */
		nb = nbconns;
		if (cap < nb + 1) {
			cap = nb + 16;
			pfds = realloc(pfds, cap * sizeof(*pfds));
			pmap = realloc(pmap, cap * sizeof(*pmap));
			if (!pfds || !pmap)
				die(1, "out of memory\n");
		}

		n = 0;
		pfds[n].fd = listener_fd;
		pfds[n].events = POLLIN;
		pfds[n].revents = 0;
		pmap[n] = NULL;
		n++;

		for (i = 0; i < nb; i++) {
			struct conn *c = conns[i];
			short ev = POLLIN;

			if (c->connecting)
				ev = POLLOUT; /* connect() completion */
			else if (c->wpos < c->wlen)
				ev |= POLLOUT;

			pfds[n].fd = c->fd;
			pfds[n].events = ev;
			pfds[n].revents = 0;
			pmap[n] = c;
			n++;

			/* compute the timeout from server wakeups and client deadlines */
			if (c->role == ROLE_SERVER && c->state == CS_EMIT) {
				uint64_t left = c->next_wake_us > now ? c->next_wake_us - now : 0;
				int ms = (int)((left + 999) / 1000);

				if (ms < timeout)
					timeout = ms;
			}
			if (c->role == ROLE_CLIENT) {
				uint64_t left = c->deadline_us > now ? c->deadline_us - now : 0;
				int ms = (int)((left + 999) / 1000);

				if (ms < timeout)
					timeout = ms;
			}
		}

		n = poll(pfds, n, timeout);
		if (n < 0) {
			if (errno == EINTR)
				n = 0;
			else
				die(1, "poll(): %s\n", strerror(errno));
		}

		now = now_us_mono();

		/* process poll results; the listener is entry 0. Note that the
		 * conn list may have changed in between, so we iterate over the
		 * snapshot only.
		 */
		if (n > 0 && (pfds[0].revents & POLLIN))
			do_accept();

		for (i = 1; i <= nb; i++) {
			struct conn *c = pmap[i];
			short re = pfds[i].revents;

			if (!re || !c)
				continue;

			if (c->connecting && (re & POLLOUT)) {
				int err = 0;
				socklen_t len = sizeof(err);

				getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len);
				if (err) {
					snprintf(c->err, sizeof(c->err), "connect(): %s", strerror(err));
					conn_close(c, NULL);
					continue;
				}
				c->connecting = 0;
				if (conn_output(c) < 0)
					continue;
			}

			if (re & POLLOUT) {
				if (conn_output(c) < 0)
					continue;
			}

			if (re & (POLLIN | POLLERR | POLLHUP | POLLRDHUP)) {
				if (conn_read(c) < 0)
					continue;
			}
		}

		/* now emit scheduled tokens for all server conns */
		for (i = 0; i < nbconns; i++) {
			struct conn *c = conns[i];

			if (c->role != ROLE_SERVER || c->state != CS_EMIT)
				continue;

			while (c->next_wake_us <= now) {
				if (c->wcap - c->wlen < 1024) {
					/* out of room, retry once drained */
					c->next_wake_us = now + 1000;
					break;
				}
				if (c->tokens_left > 0) {
					c->tokens_left--;
					server_queue_token(c);
					c->next_wake_us += c->delay_us;
				} else {
					server_queue_finish(c);
				}
				if (conn_output(c) < 0)
					break;
			}
		}

		/* enforce client deadlines */
		for (i = 0; i < nbconns; i++) {
			struct conn *c = conns[i];

			if (c->role != ROLE_CLIENT)
				continue;
			if (now > c->deadline_us) {
				snprintf(c->err, sizeof(c->err), "timeout after %ldms", timeout_ms);
				conn_close(c, NULL);
				i--; /* list shrank */
			}
		}

		/* progress line, once per second */
		if (ctx && isatty(2) && now - last_prog >= 1000000) {
			int in_flight = 0;

			for (i = 0; i < nbconns; i++)
				if (conns[i]->role == ROLE_CLIENT)
					in_flight++;

			fprintf(stderr, "\r  streaming: %llus elapsed, %d/%d done, %d in flight, %llu tokens received",
				(unsigned long long)((now - batch_t0_us) / 1000000),
				ctx->done, ctx->total, in_flight,
				(unsigned long long)prog_tokens);
			progress_shown = 1;
			last_prog = now;
		}
	}
}

/* ------------------------------------------------------------------ */
/* Batch runner                                                         */
/* ------------------------------------------------------------------ */

static struct batch_stats *run_batch(struct sockaddr_storage *target, const char *tag,
				     int nb_req, long tokens_hint)
{
	struct batch_ctx ctx;
	struct batch_stats *st;
	uint64_t per_req_ms, total_ms;
	long eff_tokens;

	memset(&ctx, 0, sizeof(ctx));
	ctx.target = *target;
	ctx.total = nb_req;
	ctx.tokens_hint = tokens_hint;
	snprintf(ctx.host, sizeof(ctx.host), "%s", addr_to_str(target));

	st = calloc(1, sizeof(*st));
	if (!st)
		die(1, "out of memory\n");
	st->nb_req = nb_req;

	cur_batch = &ctx;
	cur_stats = st;
	ctx_tag = tag;
	prog_tokens = 0;
	batch_t0_us = now_us_mono();

	if (tokens_hint > 0)
		fprintf(stderr, "%s: calibrating the noise floor with %d request(s) of %ld tokens to %s (concurrency=%d, think=%.0fms, delay=%.0fms) ...\n",
			tag, nb_req, tokens_hint, ctx.host, concurrency, think_ms, delay_ms);
	else
		fprintf(stderr, "%s: sending %d request(s) to %s (concurrency=%d, tokens=%ld, think=%.0fms, delay=%.0fms) ...\n",
			tag, nb_req, ctx.host, concurrency, nb_tokens, think_ms, delay_ms);

	/* announce the expected duration of long batches, so that they don't
	 * look stuck or surprising.
	 */
	eff_tokens = tokens_hint > 0 ? tokens_hint : nb_tokens;
	per_req_ms = (uint64_t)(think_ms + delay_ms * (long long)(eff_tokens > 0 ? eff_tokens - 1 : 0));
	total_ms = per_req_ms * ((nb_req + concurrency - 1) / concurrency);
	if (total_ms > 30000)
		fprintf(stderr, "  (expect ~%llumin%02llus for this batch)\n",
			(unsigned long long)(total_ms / 60000),
			(unsigned long long)((total_ms % 60000) / 1000));

	event_loop(&ctx);

	cur_batch = NULL;
	cur_stats = NULL;
	ctx_tag = NULL;

	progress_clear();

	return st;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	struct sockaddr_storage listen_ss, target_ss, loop_ss;
	struct batch_stats *loop_stats = NULL, *gw_stats;
	const char *arg0 = argv[0];
	int has_loop, calib_req;
	long calib_tokens;

	signal(SIGPIPE, SIG_IGN);

	/* keep the per-request lines visible even when stdout is redirected */
	setvbuf(stdout, NULL, _IOLBF, 0);

	while (argc > 1) {
		const char *arg;

		argc--; argv++;
		arg = *argv;

		if (*arg != '-')
			usage(1, arg0);

		switch (arg[1]) {
		case 'L': if (argc < 2) usage(1, arg0); listen_str = *++argv; argc--; break;
		case 't': if (argc < 2) usage(1, arg0); target_str = *++argv; argc--; break;
		case 'r': if (argc < 2) usage(1, arg0); nb_requests = atoi(*++argv); argc--; break;
		case 'c': if (argc < 2) usage(1, arg0); concurrency = atoi(*++argv); argc--; break;
		case 'n': if (argc < 2) usage(1, arg0); nb_tokens = atol(*++argv); argc--; break;
		case 'T': if (argc < 2) usage(1, arg0); think_ms = atof(*++argv); argc--; break;
		case 'd': if (argc < 2) usage(1, arg0); delay_ms = atof(*++argv); argc--; break;
		case 'w': if (argc < 2) usage(1, arg0); timeout_ms = atol(*++argv); argc--; break;
		case 'l': use_loopback = 0; break;
		case 'q': quiet = 1; break;
		case 'v': verbose++; break;
		case 'h': usage(0, arg0); break;
		default : usage(1, arg0); break;
		}
	}

	if (nb_requests < 1)
		nb_requests = 1;
	if (concurrency < 1)
		concurrency = 1;
	if (concurrency > nb_requests)
		concurrency = nb_requests;

	if (addr_to_ss(listen_str, &listen_ss) < 0)
		usage(1, arg0);

	listener_fd = socket(listen_ss.ss_family, SOCK_STREAM, 0);
	if (listener_fd < 0)
		die(1, "socket(): %s\n", strerror(errno));
	{
		int one = 1;
		setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}
	fcntl(listener_fd, F_SETFL, fcntl(listener_fd, F_GETFL, 0) | O_NONBLOCK);

	if (bind(listener_fd, (struct sockaddr *)&listen_ss, sizeof(listen_ss)) < 0)
		die(1, "bind(%s): %s\n", listen_str, strerror(errno));

	if (listen(listener_fd, 1024) < 0)
		die(1, "listen(): %s\n", strerror(errno));

	fprintf(stderr, "dummy OpenAI-like SSE server listening on %s (POST /v1/chat/completions)\n",
		addr_to_str(&listen_ss));

	if (!target_str) {
		fprintf(stderr, "no -t given: running as server only. Ctrl-C to stop.\n");
		event_loop(NULL);
		return 0;
	}

	if (addr_to_ss(target_str, &target_ss) < 0)
		usage(1, arg0);

	/* a bare port or a wildcard address means loopback for a destination */
	addr_force_loopback(&target_ss);

	/* the loopback calibration always connects to a local address */
	loop_ss = listen_ss;
	addr_force_loopback(&loop_ss);

	has_loop = use_loopback && !addr_eq(&loop_ss, &target_ss);
	if (!has_loop && use_loopback)
		fprintf(stderr, "note: -t equals -L, skipping loopback calibration\n");

	if (has_loop) {
		/* The calibration only establishes the noise floor, it doesn't
		 * need the full load: a few requests with shorter responses are
		 * enough. At least one full concurrency wave is used so that
		 * the measurements are made in comparable conditions.
		 */
		calib_req = concurrency > 3 ? concurrency : 3;
		if (calib_req > nb_requests)
			calib_req = nb_requests;
		calib_tokens = nb_tokens < 200 ? nb_tokens : 200;

		loop_stats = run_batch(&loop_ss, "loop", calib_req, calib_tokens);
	}

	gw_stats = run_batch(&target_ss, "gw", nb_requests, 0);

	if (has_loop)
		print_batch("loopback (direct to listen address)", loop_stats);
	print_batch("gateway", gw_stats);

	if (has_loop) {
		printf("\n=== gateway overhead (gateway minus loopback; negative = loopback noise) ===\n");
		delta_line("emit->recv (1st token)", &gw_stats->emit_ttft, &loop_stats->emit_ttft);
		delta_line("emit->recv (tokens)",    &gw_stats->emits,     &loop_stats->emits);
		delta_line("TTFT (client)",          &gw_stats->ttft,      &loop_stats->ttft);
		delta_line("inter-token (client)",   &gw_stats->gaps,      &loop_stats->gaps);
	}

	return gw_stats->fail_req > 0 ? 1 : 0;
}
