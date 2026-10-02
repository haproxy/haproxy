sse-latency - SSE latency measurement for AI gateways
=====================================================

sse-latency is a single process that acts as BOTH sides of an OpenAI-like
SSE conversation, sharing one process-local clock so that it can measure the
exact delay each token suffers when going through a gateway (haproxy or any
other OpenAI-like proxy):

  SERVER side: listens on -L and exposes POST /v1/chat/completions (plus
  /v1/models). It streams standard chat.completion.chunk SSE events over
  HTTP/1.1 chunked encoding. Tokens are 4-letter words; defaults: 1000 tokens
  per response, no delay before the first token (aka thinking), 5 ms between
  tokens. The number of tokens and both delays are overridable per-request
  via the JSON body ("pi_tokens", "pi_think_ms", "pi_delay_ms"), which real
  gateways silently ignore.

  CLIENT side: sends standard streaming chat completion requests to -t (the
  gateway under test), reads the SSE stream (handling chunked encoding when
  the gateway uses it) and records:
    - TTFT: time from request fully written to first content token received
    - inter-token gaps: arrival time deltas between consecutive tokens
    - emission delay: arrival_time - pi_ts of each chunk

Since both sides share the same clock, every SSE chunk carries an extra
"pi_ts" field with the emission time in nanoseconds since the epoch
(CLOCK_REALTIME), taken at the moment the chunk is appended to the socket.
This makes it possible to measure the true one-way delay through the gateway
instead of just end-to-end timing.

By default a loopback calibration batch runs first (client connects directly
to the listening address), then the gateway batch; the difference between
both is reported as the estimated gateway overhead. Negative values are
normal, they just mean the loopback run happened to be noisier. The
calibration is deliberately kept short (at most max(3, concurrency)
requests of at most 200 tokens each): it only measures the noise floor, it
doesn't need the full load. Long batches announce their expected duration
before starting, and a progress line is displayed once per second while a
batch is running (on terminals only).

Usage
-----

The default listening port is :8090, so that the gateway under test can
conveniently listen on the usual port 8080 and forward to this tool:

    ./sse-latency -L :8090 \                 # where our dummy backend listens
                -t 127.0.0.1:8080 \        # the gateway (haproxy frontend)
                -r 20 -c 5                # 20 requests, 5 in parallel
                -n 1000                    # tokens (no think delay, 5ms/token by default)

Options:
    -L <[ip:]port>  listen address of the dummy OpenAI-like server (def :8090)
    -t <[ip:]port>  gateway address; empty = server only
    -r <n>          number of requests (def 1)
    -c <n>          concurrency (def 1)
    -n <n>          tokens per response (def 1000)
    -T <ms>         think delay before first token (def 0)
    -d <ms>         inter-token delay (def 5, float ok)
    -w <ms>         per-request timeout (def 300000)
    -l              disable the loopback calibration batch
    -q              quiet, no per-request lines
    -v              verbose
    -h              help

Reported metrics
----------------
    TTFT (client)          request fully sent -> first token received
    TTFT emit->recv(1st)   one-way delay of the first token
    inter-token (client)   gaps between consecutive token arrivals
    emit->recv (tokens)    one-way delay of every token
    gateway overhead       gateway batch minus loopback batch

Interpretation notes:
---------------------
  - emit->recv constant and small (loopback: ~0.02 ms) -> the gateway
    flushes SSE immediately.
  - Bursts in inter-token (many 0 ms gaps + one large gap) -> the gateway
    buffers chunks before flushing.
  - TTFT (client) ~= think + emit->recv(1st) sanity-checks the run.

haproxy results (3.5-dev8, loopback, 5x5 concurrency)
-----------------------------------------------------
Without any tuning, SSE responses are buffered in the kernel buffers (bursts of
~20 tokens every ~200 ms, ~100 ms mean per-token delay, first token up to +105
ms):

    global
        daemon
    defaults
        mode http
        option http-no-delay
        timeout client 5m
        timeout server 5m
        timeout connect 5s
    frontend fe
        bind 127.0.0.1:8080
        default_backend be
    backend be
        server sse-latency 127.0.0.1:8090

Adding "option http-no-delay" to the defaults section disables the payload
corking in the kernel and produces the lowest latency, as can be seen below
where this tool shows that haproxy adds roughly 0.04ms:

  === gateway overhead (gateway minus loopback; negative = loopback noise) ===
  emit->recv (1st token)   mean +0.026ms  p50 +0.026ms  p99 +0.026ms
  emit->recv (tokens)      mean +0.034ms  p50 +0.036ms  p99 +0.029ms
  TTFT (client)            mean +0.135ms  p50 +0.135ms  p99 +0.135ms
  inter-token (client)     mean -0.002ms  p50 +0.042ms  p99 +0.035ms
