#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/mux_quic.h>
#include <haproxy/pool.h>
#include <haproxy/quic_frame.h>
#include <haproxy/quic_tp-t.h>

struct xprt_qstrm_ctx {
	struct connection *conn;
	struct wait_event *subs;
	struct wait_event wait_event;

	const struct xprt_ops *ops_lower;
	void *ctx_lower;

	struct quic_transport_params lparams;
	struct quic_transport_params rparams;

	struct buffer rxbuf;
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

int conn_recv_qstrm(struct connection *conn, struct xprt_qstrm_ctx *ctx, int flag)
{
	struct quic_frame frm;
	struct buffer *buf = &ctx->rxbuf;
	const unsigned char *pos, *end;
	size_t ret;

	if (!conn_ctrl_ready(conn))
		goto fail;

	BUG_ON(conn->flags & CO_FL_FDLESS);

	if (!fd_recv_ready(conn->handle.fd))
		goto not_ready;

	if (!b_size(buf) && !b_alloc(buf, DB_MUX_RX))
		goto fail;

	do {
		ret = ctx->ops_lower->rcv_buf(conn, ctx->ctx_lower, buf, b_room(buf), NULL, 0, 0);
		BUG_ON(conn->flags & CO_FL_ERROR);
	} while (ret);

	if (!b_data(buf))
		goto not_ready;

	pos = (unsigned char *)b_orig(buf);
	end = (unsigned char *)(b_orig(buf) + b_data(buf));
	if (!qc_parse_frm_type(&frm, &pos, end, NULL))
		goto not_ready;

	/* TODO close connection with TRANSPORT_PARAMETER_ERROR if frame not present. */
	BUG_ON(frm.type != QUIC_FT_QX_TRANSPORT_PARAMETERS);

	if (!qc_parse_frm_payload(&frm, &pos, end, NULL))
		goto not_ready;

	ctx->rparams = frm.qmux_transport_params.params;

	conn->flags &= ~flag;
	return 1;

 not_ready:
	return 0;

 fail:
	conn->flags |= CO_FL_ERROR;
	return 0;
}

int conn_send_qstrm(struct connection *conn, struct xprt_qstrm_ctx *ctx, int flag)
{
	struct quic_frame frm;
	unsigned char *pos, *old, *end;
	int ret;

	if (!conn_ctrl_ready(conn))
		goto fail;

	frm.type = QUIC_FT_QX_TRANSPORT_PARAMETERS;
	frm.qmux_transport_params.params = ctx->lparams;

	b_reset(&trash);
	old = pos = (unsigned char *)b_head(&trash);
	end = (unsigned char *)b_wrap(&trash);
	ret = qc_build_frm(&frm, &pos, end, NULL);
	BUG_ON(!ret);
	b_add(&trash, pos - old);

	ret = ctx->ops_lower->snd_buf(conn, ctx->ctx_lower, &trash, b_data(&trash),
	                              NULL, 0, 0);
	BUG_ON(!ret || ret != b_data(&trash));

	conn->flags &= ~flag;

	return 1;

 fail:
	conn->flags |= CO_FL_ERROR;
	return 0;
}

struct task *xprt_qstrm_io_cb(struct task *t, void *context, unsigned int state)
{
	struct xprt_qstrm_ctx *ctx = context;
	struct connection *conn = ctx->conn;
	int ret;

	if (conn->flags & CO_FL_QSTRM_SEND) {
		if (!conn_send_qstrm(conn, ctx, CO_FL_QSTRM_SEND)) {
			ctx->ops_lower->subscribe(conn, ctx->ctx_lower,
			                          SUB_RETRY_SEND, &ctx->wait_event);
			goto out;
		}
	}

	if (conn->flags & CO_FL_QSTRM_RECV) {
		if (!conn_recv_qstrm(conn, ctx, CO_FL_QSTRM_RECV)) {
			ctx->ops_lower->subscribe(conn, ctx->ctx_lower,
			                          SUB_RETRY_RECV, &ctx->wait_event);
			goto out;
		}
	}

 out:
	if ((conn->flags & CO_FL_ERROR) ||
	    !(conn->flags & (CO_FL_QSTRM_RECV|CO_FL_QSTRM_SEND))) {
		/* MUX will access members from xprt_ctx on init, so create
		 * operation should be called before any members are resetted.
		 */
		ret = conn_create_mux(conn, NULL);
		BUG_ON(ret);

		conn->xprt_ctx = ctx->ctx_lower;
		conn->xprt = ctx->ops_lower;
		conn->mux->wake(conn);

		b_free(&ctx->rxbuf);

		tasklet_free(ctx->wait_event.tasklet);
		pool_free(xprt_qstrm_ctx_pool, ctx);
		t = NULL;
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

	memset(&ctx->rparams, 0, sizeof(struct quic_transport_params));

	/* TP configuration advertised by us */
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
	/* TODO not implemented */
	ABORT_NOW();
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
