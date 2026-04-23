#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/mux_quic.h>
#include <haproxy/mux_quic_qstrm.h>
#include <haproxy/pool.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_tp-t.h>

struct xprt_qstrm_ctx {
	struct connection *conn;
	struct wait_event wait_event;

	const struct xprt_ops *ops_lower;
	void *ctx_lower;

	struct quic_transport_params lparams;
	struct quic_transport_params rparams;

	struct buffer txbuf;
	struct buffer rxbuf;
	size_t rxrlen;
};

DECLARE_STATIC_TYPED_POOL(xprt_qstrm_ctx_pool, "xprt_qstrm_ctx", struct xprt_qstrm_ctx);

const struct quic_transport_params *xprt_qstrm_lparams(const void *context)
{
	const struct xprt_qstrm_ctx *ctx = context;
	return &ctx->lparams;
}

const struct quic_transport_params *xprt_qstrm_rparams(const void *context)
{
	const struct xprt_qstrm_ctx *ctx = context;
	return &ctx->rparams;
}

/* Transfer Rx buffer into <out>. */
size_t xprt_qstrm_xfer_rxbuf(void *context, struct buffer *out)
{
	struct xprt_qstrm_ctx *ctx = context;

	if (b_data(&ctx->rxbuf)) {
		*out = ctx->rxbuf;
		ctx->rxbuf = BUF_NULL;
	}

	return ctx->rxrlen;
}

int conn_recv_qstrm(struct connection *conn, struct xprt_qstrm_ctx *ctx, int flag)
{
	struct quic_frame frm;
	struct buffer *buf = &ctx->rxbuf;
	const unsigned char *pos, *old, *end;
	uint64_t rlen;
	size_t ret, rlen_sz = 0;

	if (!conn_ctrl_ready(conn))
		goto fail;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (!fd_recv_ready(conn->handle.fd))
		goto not_ready;

	if (!b_size(buf) && !b_alloc(buf, DB_MUX_RX))
		goto fail;

	do {
		ret = ctx->ops_lower->rcv_buf(conn, ctx->ctx_lower, buf, b_room(buf), NULL, 0, 0);
		if (conn->flags & CO_FL_ERROR)
			goto fail;
	} while (ret);

	if (!b_data(buf))
		goto not_ready;

	/* Read record length. */
	if (!ctx->rxrlen) {
		if (!b_quic_dec_int(&rlen, buf, &rlen_sz))
			goto not_ready;

		/* Reject too small or too big records. */
		if (!rlen || rlen > b_size(buf) - rlen_sz)
			goto fail;

		ctx->rxrlen = rlen;
	}

	if (ctx->rxrlen > b_data(buf))
		goto not_ready;

	old = pos = (unsigned char *)b_head(buf);
	end = pos + ctx->rxrlen;
	if (!qc_parse_frm_type(&frm, &pos, end, NULL))
		goto fail;

	/* TODO close connection with TRANSPORT_PARAMETER_ERROR if frame not present. */
	BUG_ON(frm.type != QUIC_FT_QX_TRANSPORT_PARAMETERS);

	if (!qc_parse_frm_payload(&frm, &pos, end, NULL))
		goto fail;

	ctx->rparams = frm.qmux_transport_params.params;
	b_del(buf, pos - old);
	/* <end> delimiter should guarantee than frame length does not go beyong the record end */
	BUG_ON(ctx->rxrlen < pos - old);
	ctx->rxrlen -= (pos - old);

	conn->flags &= ~flag;
	return 1;

 not_ready:
	return 0;

 fail:
	conn->err_code = CO_ER_QSTRM;
	conn->flags |= CO_FL_ERROR;
	return 0;
}

int conn_send_qstrm(struct connection *conn, struct xprt_qstrm_ctx *ctx, int flag)
{
	struct quic_frame frm;
	struct buffer *buf = &ctx->txbuf;
	unsigned char *pos, *old, *end;
	size_t sent;
	int ret, lensz;

	if (!conn_ctrl_ready(conn))
		goto fail;

	frm.type = QUIC_FT_QX_TRANSPORT_PARAMETERS;
	frm.qmux_transport_params.params = ctx->lparams;

	/* Small buf is sufficient for our transport parameters. */
	if (!b_size(buf) && !b_alloc_small(buf))
		goto fail;
	/* Record size field length */
	lensz = quic_int_getsize(quic_int_cap_length(b_size(buf)));

	if (!b_data(buf)) {
		old = pos = (unsigned char *)b_orig(buf) + lensz;
		end = (unsigned char *)b_wrap(buf);
		ret = qc_build_frm(&frm, &pos, end, NULL);
		BUG_ON(!ret); /* should never fail */

		ret = b_quic_enc_int(buf, pos - old, lensz);
		BUG_ON(!ret); /* should never fail */
		b_add(buf, pos - old);
	}

	sent = ctx->ops_lower->snd_buf(conn, ctx->ctx_lower, buf, b_data(buf),
	                               NULL, 0, 0);
	if (conn->flags & CO_FL_ERROR)
		goto fail;

	b_del(buf, sent);
	if (b_data(buf))
		goto retry;

	conn->flags &= ~flag;

	return 1;

 retry:
	return 0;

 fail:
	conn->err_code = CO_ER_QSTRM;
	conn->flags |= CO_FL_ERROR;
	return 0;
}

struct task *xprt_qstrm_io_cb(struct task *t, void *context, unsigned int state)
{
	struct xprt_qstrm_ctx *ctx = context;
	struct connection *conn = ctx->conn;
	int free = 0, ret;

	if (conn->flags & CO_FL_QSTRM_SEND) {
		if (!conn_send_qstrm(conn, ctx, CO_FL_QSTRM_SEND)) {
			if (!(conn->flags & CO_FL_ERROR)) {
				ctx->ops_lower->subscribe(conn, ctx->ctx_lower,
				                          SUB_RETRY_SEND, &ctx->wait_event);
			}
			goto out;
		}
	}

	if (conn->flags & CO_FL_QSTRM_RECV) {
		if (!conn_recv_qstrm(conn, ctx, CO_FL_QSTRM_RECV)) {
			if (!(conn->flags & CO_FL_ERROR)) {
				ctx->ops_lower->subscribe(conn, ctx->ctx_lower,
				                          SUB_RETRY_RECV, &ctx->wait_event);
			}
			goto out;
		}
	}

 out:
	if ((conn->flags & CO_FL_ERROR) ||
	    !(conn->flags & (CO_FL_QSTRM_RECV|CO_FL_QSTRM_SEND))) {
		/* XPRT should be unsubscribed when transfer done or on error. */
		BUG_ON(ctx->wait_event.events);

		/* MUX will access members from xprt_ctx on init, so create
		 * operation should be called before any members are resetted.
		 */
		ret = conn_create_mux(conn, &free);
		if (free) {
			/* Conn and current XPRT layer including this tasklet already destroyed. */
			return NULL;
		}

		conn->xprt_ctx = ctx->ctx_lower;
		conn->xprt = ctx->ops_lower;

		/* MUX layer is responsible to retrieve any remaining data in
		 * the Rx buffer prior to reset it.
		 */
		BUG_ON(b_data(&ctx->rxbuf));
		b_free(&ctx->rxbuf);
		b_free(&ctx->txbuf);

		tasklet_free(ctx->wait_event.tasklet);
		pool_free(xprt_qstrm_ctx_pool, ctx);
		t = NULL;

		if (ret == 0) {
			/* Wake up MUX layer. This operation may also free the
			 * connection and its XPRT, so it is safest to run it
			 * after the current xprt layer release.
			 */
			conn->mux->wake(conn);
		}
	}

	return t;
}

static int xprt_qstrm_add_xprt(struct connection *conn, void *xprt_ctx,
                              void *ctx_lower, const struct xprt_ops *ops_lower,
                              void **ctx_older, const struct xprt_ops **ops_older)
{
	struct xprt_qstrm_ctx *ctx = xprt_ctx;
	BUG_ON(ctx_older || ops_older);

	ctx->ctx_lower = ctx_lower;
	ctx->ops_lower = ops_lower;

	return 0;
}

static int xprt_qstrm_init(struct connection *conn, void **xprt_ctx)
{
	struct xprt_qstrm_ctx *ctx;
	BUG_ON(*xprt_ctx);

	ctx = pool_alloc(xprt_qstrm_ctx_pool);
	if (!ctx) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		return -1;
	}

	ctx->conn = conn;
	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		pool_free(xprt_qstrm_ctx_pool, ctx);
		return -1;
	}
	ctx->wait_event.tasklet->process = xprt_qstrm_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.events = 0;

	ctx->ctx_lower = NULL;
	ctx->ops_lower = NULL;

	ctx->rxbuf = BUF_NULL;
	ctx->rxrlen = 0;
	ctx->txbuf = BUF_NULL;

	memset(&ctx->rparams, 0, sizeof(struct quic_transport_params));
	memset(&ctx->lparams, 0, sizeof(struct quic_transport_params));

	/* TP configuration advertised by us */
	ctx->lparams.max_idle_timeout = 30;
	ctx->lparams.initial_max_data = 1638400;
	ctx->lparams.initial_max_streams_bidi = 100;
	ctx->lparams.initial_max_streams_uni = 3;
	ctx->lparams.initial_max_stream_data_bidi_local = qmux_stream_rx_bufsz();
	ctx->lparams.initial_max_stream_data_bidi_remote = qmux_stream_rx_bufsz();
	ctx->lparams.initial_max_stream_data_uni = qmux_stream_rx_bufsz();

	*xprt_ctx = ctx;

	return 0;
}

static int xprt_qstrm_start(struct connection *conn, void *xprt_ctx)
{
	struct xprt_qstrm_ctx *ctx = xprt_ctx;
	tasklet_wakeup(ctx->wait_event.tasklet);
	return 0;
}

static void xprt_qstrm_close(struct connection *conn, void *xprt_ctx)
{
	struct xprt_qstrm_ctx *ctx = xprt_ctx;
	if (!ctx)
		return;

	if (ctx->wait_event.events != 0) {
		ctx->ops_lower->unsubscribe(ctx->conn, ctx->ctx_lower,
		                            ctx->wait_event.events,
		                            &ctx->wait_event);
	}

	if (ctx->ops_lower && ctx->ops_lower->close)
		ctx->ops_lower->close(conn, ctx->ctx_lower);

	conn->flags &= ~(CO_FL_QSTRM_RECV|CO_FL_QSTRM_SEND);

	BUG_ON(conn->xprt_ctx != ctx);
	conn->xprt_ctx = ctx->ctx_lower;
	conn->xprt = ctx->ops_lower;

	tasklet_free(ctx->wait_event.tasklet);
	pool_free(xprt_qstrm_ctx_pool, ctx);
}

static int xprt_qstrm_get_alpn(const struct connection *conn, void *xprt_ctx,
                               const char **str, int *len)
{
	struct xprt_qstrm_ctx *ctx = xprt_ctx;
	return ctx->ops_lower->get_alpn(conn, ctx->ctx_lower, str, len);
}

struct xprt_ops xprt_qstrm = {
	.add_xprt  = xprt_qstrm_add_xprt,
	.init      = xprt_qstrm_init,
	.start     = xprt_qstrm_start,
	.close     = xprt_qstrm_close,
	.get_alpn  = xprt_qstrm_get_alpn,
	.name      = "qstrm",
};

static void __xprt_qstrm_init(void)
{
	xprt_register(XPRT_QSTRM, &xprt_qstrm);
}
INITCALL0(STG_REGISTER, __xprt_qstrm_init);
