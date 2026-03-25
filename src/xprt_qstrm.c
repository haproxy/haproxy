#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
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
};

DECLARE_STATIC_TYPED_POOL(xprt_qstrm_ctx_pool, "xprt_qstrm_ctx", struct xprt_qstrm_ctx);

struct task *xprt_qstrm_io_cb(struct task *t, void *context, unsigned int state)
{
	struct xprt_qstrm_ctx *ctx = context;
	struct connection *conn = ctx->conn;
	int ret;

 out:
	if (conn->flags & CO_FL_ERROR) {
		/* MUX will access members from xprt_ctx on init, so create
		 * operation should be called before any members are resetted.
		 */
		ret = conn_create_mux(conn, NULL);
		BUG_ON(ret);

		conn->xprt_ctx = ctx->ctx_lower;
		conn->xprt = ctx->ops_lower;
		conn->mux->wake(conn);

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
