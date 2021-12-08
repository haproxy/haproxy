/*
 * HTTP/3 protocol processing
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <haproxy/buf.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/h3.h>
#include <haproxy/http.h>
#include <haproxy/htx.h>
#include <haproxy/istbuf.h>
#include <haproxy/mux_quic-t.h>
#include <haproxy/pool.h>
#include <haproxy/qpack-dec.h>
#include <haproxy/qpack-enc.h>
#include <haproxy/quic_enc.h>
#include <haproxy/stream.h>
#include <haproxy/tools.h>
#include <haproxy/xprt_quic.h>

#define DEBUG_H3

#if defined(DEBUG_H3)
#define h3_debug_printf fprintf
#define h3_debug_hexdump debug_hexdump
#else
#define h3_debug_printf(...) do { } while (0)
#define h3_debug_hexdump(...) do { } while (0)
#endif

#define H3_CF_SETTINGS_SENT  0x00000001

/* Default settings */
static uint64_t h3_settings_qpack_max_table_capacity = 0;
static uint64_t h3_settings_qpack_blocked_streams = 4096;
static uint64_t h3_settings_max_field_section_size = QUIC_VARINT_8_BYTE_MAX; /* Unlimited */

struct h3 {
	struct qcc *qcc;
	enum h3_err err;
	uint32_t flags;
	/* Locally initiated uni-streams */
	struct h3_uqs lqpack_enc;
	struct h3_uqs lqpack_dec;
	struct h3_uqs lctrl;
	/* Remotely initiated uni-streams */
	struct h3_uqs rqpack_enc;
	struct h3_uqs rqpack_dec;
	struct h3_uqs rctrl;
	/* Settings */
	uint64_t qpack_max_table_capacity;
	uint64_t qpack_blocked_streams;
	uint64_t max_field_section_size;
	struct buffer_wait buf_wait; /* wait list for buffer allocations */
};

DECLARE_STATIC_POOL(pool_head_h3, "h3", sizeof(struct h3));

/* Simple function to duplicate a buffer */
static inline struct buffer h3_b_dup(struct buffer *b)
{
	return b_make(b->area, b->size, b->head, b->data);
}

/* Decode a h3 frame header made of two QUIC varints from <b> buffer.
 * Returns the number of bytes consumed if there was enough data in <b>, 0 if not.
 * Note that this function update <b> buffer to reflect the number of bytes consumed
 * to decode the h3 frame header.
 */
static inline size_t h3_decode_frm_header(uint64_t *ftype, uint64_t *flen,
                                          struct buffer *b)
{
	size_t hlen;

	hlen = 0;
	if (!b_quic_dec_int(ftype, b, &hlen) || !b_quic_dec_int(flen, b, &hlen))
		return 0;

	return hlen;
}

/* Decode <qcs> remotely initiated bidi-stream.
 * Returns <0 on error else 0.
 */
static int h3_decode_qcs(struct qcs *qcs, int fin, void *ctx)
{
	struct buffer *rxbuf = &qcs->rx.buf;
	struct h3 *h3 = ctx;
	struct htx *htx = NULL;
	struct htx_sl *sl;
	struct conn_stream *cs;
	struct http_hdr list[global.tune.max_http_hdr];
	unsigned int flags = HTX_SL_F_NONE;
	int hdr_idx;

	h3_debug_printf(stderr, "%s: STREAM ID: %llu\n", __func__, qcs->by_id.key);
	if (!b_data(rxbuf))
		return 0;

	while (b_data(rxbuf)) {
		size_t hlen;
		uint64_t ftype, flen;
		struct buffer b;

		/* Work on a copy of <rxbuf> */
		b = h3_b_dup(rxbuf);
		hlen = h3_decode_frm_header(&ftype, &flen, &b);
		if (!hlen)
			break;

		h3_debug_printf(stderr, "%s: ftype: %llu, flen: %llu\n", __func__,
		        (unsigned long long)ftype, (unsigned long long)flen);
		if (flen > b_data(&b))
			break;

		b_del(rxbuf, hlen);
		switch (ftype) {
		case H3_FT_DATA:
			break;
		case H3_FT_HEADERS:
		{
			const unsigned char *buf = (const unsigned char *)b_head(rxbuf);
			size_t len = b_data(rxbuf);
			struct buffer htx_buf = BUF_NULL;
			struct buffer *tmp = get_trash_chunk();
			struct ist meth = IST_NULL, path = IST_NULL;
			//struct ist scheme = IST_NULL, authority = IST_NULL;
			struct ist authority = IST_NULL;

			if (qpack_decode_fs(buf, len, tmp, list) < 0) {
				h3->err = QPACK_DECOMPRESSION_FAILED;
				return -1;
			}

			b_alloc(&htx_buf);
			htx = htx_from_buf(&htx_buf);

			/* first treat pseudo-header to build the start line */
			hdr_idx = 0;
			while (1) {
				if (isteq(list[hdr_idx].n, ist("")))
					break;

				if (istmatch(list[hdr_idx].n, ist(":"))) {
					/* pseudo-header */
					if (isteq(list[hdr_idx].n, ist(":method")))
						meth = list[hdr_idx].v;
					else if (isteq(list[hdr_idx].n, ist(":path")))
						path = list[hdr_idx].v;
					//else if (isteq(list[hdr_idx].n, ist(":scheme")))
					//	scheme = list[hdr_idx].v;
					else if (isteq(list[hdr_idx].n, ist(":authority")))
						authority = list[hdr_idx].v;
				}

				++hdr_idx;
			}

			flags |= HTX_SL_F_VER_11;

			sl = htx_add_stline(htx, HTX_BLK_REQ_SL, flags, meth, path, ist("HTTP/3.0"));
			if (!sl)
				goto fail;
			sl->flags |= HTX_SL_F_BODYLESS;
			sl->info.req.meth = find_http_meth(meth.ptr, meth.len);
			BUG_ON(sl->info.req.meth == HTTP_METH_OTHER);

			if (isttest(authority))
				htx_add_header(htx, ist("host"), authority);

			/* now treat standard headers */
			hdr_idx = 0;
			while (1) {
				if (isteq(list[hdr_idx].n, ist("")))
					break;

				if (!istmatch(list[hdr_idx].n, ist(":")))
					htx_add_header(htx, list[hdr_idx].n, list[hdr_idx].v);

				++hdr_idx;
			}

			htx_add_endof(htx, HTX_BLK_EOH);
			htx_to_buf(htx, &htx_buf);

			cs = cs_new(qcs->qcc->conn, qcs->qcc->conn->target);
			cs->ctx = qcs;
			stream_create_from_cs(cs, &htx_buf);

			/* buffer is transferred to conn_stream and set to NULL
			 * except on stream creation error.
			 */
			b_free(&htx_buf);

			break;
		}
		case H3_FT_PUSH_PROMISE:
			/* Not supported */
			break;
		default:
			/* draft-ietf-quic-http34 9. Extensions to HTTP/3
			 * unknown frame types MUST be ignored
			 */
			h3_debug_printf(stderr, "ignore unknown frame type 0x%lx\n", ftype);
		}
		b_del(rxbuf, flen);
	}

	if (htx) {
		if (fin && !b_data(rxbuf))
			htx->flags |= HTX_FL_EOM;
	}

	return 0;

 fail:
	return -1;
}

/* Parse a SETTINGS frame which must not be truncated with <flen> as length from
 * <rxbuf> buffer. This function does not update this buffer.
 * Returns 0 if something wrong happened, 1 if not.
 */
static int h3_parse_settings_frm(struct h3 *h3, const struct buffer *rxbuf, size_t flen)
{
	uint64_t id, value;
	const unsigned char *buf, *end;

	buf = (const unsigned char *)b_head(rxbuf);
	end = buf + flen;

	while (buf <= end) {
		if (!quic_dec_int(&id, &buf, end) || !quic_dec_int(&value, &buf, end))
			return 0;

		h3_debug_printf(stderr, "%s id: %llu value: %llu\n",
		                __func__, (unsigned long long)id, (unsigned long long)value);
		switch (id) {
		case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
			h3->qpack_max_table_capacity = value;
			break;
		case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
			h3->max_field_section_size = value;
			break;
		case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
			h3->qpack_blocked_streams = value;
			break;
		case H3_SETTINGS_RESERVED_2 ... H3_SETTINGS_RESERVED_5:
			h3->err = H3_SETTINGS_ERROR;
			return 0;
		default:
			/* MUST be ignored */
			break;
		}
	}

	return 1;
}

/* Decode <qcs> remotely initiated uni-stream. We stop parsing a frame as soon as
 * there is not enough received data.
 * Returns 0 if something wrong happened, 1 if not.
 */
static int h3_control_recv(struct h3_uqs *h3_uqs, void *ctx)
{
	struct buffer *rxbuf = &h3_uqs->qcs->rx.buf;
	struct h3 *h3 = ctx;

	h3_debug_printf(stderr, "%s STREAM ID: %llu\n", __func__,  h3_uqs->qcs->by_id.key);
	if (!b_data(rxbuf))
		return 1;

	while (b_data(rxbuf)) {
		size_t hlen;
		uint64_t ftype, flen;
		struct buffer b;

		/* Work on a copy of <rxbuf> */
		b = h3_b_dup(rxbuf);
		hlen = h3_decode_frm_header(&ftype, &flen, &b);
		if (!hlen)
			break;

		h3_debug_printf(stderr, "%s: ftype: %llu, flen: %llu\n", __func__,
		        (unsigned long long)ftype, (unsigned long long)flen);
		if (flen > b_data(&b))
			break;

		b_del(rxbuf, hlen);
		/* From here, a frame must not be truncated */
		switch (ftype) {
		case H3_FT_CANCEL_PUSH:
			/* XXX TODO XXX */
			ABORT_NOW();
			break;
		case H3_FT_SETTINGS:
			if (!h3_parse_settings_frm(h3, rxbuf, flen))
				return 0;
			break;
		case H3_FT_GOAWAY:
			/* XXX TODO XXX */
			ABORT_NOW();
			break;
		case H3_FT_MAX_PUSH_ID:
			/* XXX TODO XXX */
			ABORT_NOW();
			break;
		default:
			/* Error */
			h3->err = H3_FRAME_UNEXPECTED;
			return 0;
		}
		b_del(rxbuf, flen);
	}

	/* Handle the case where remaining data are present in the buffer. This
	 * can happen if there is an incomplete frame. In this case, subscribe
	 * on the lower layer to restart receive operation.
	 */
	if (b_data(rxbuf))
		qcs_subscribe(h3_uqs->qcs, SUB_RETRY_RECV, &h3_uqs->wait_event);

	return 1;
}

/* Returns buffer for data sending.
 * May be NULL if the allocation failed.
 */
static struct buffer *mux_get_buf(struct qcs *qcs)
{
	if (!b_size(&qcs->tx.buf))
		b_alloc(&qcs->tx.buf);

	return &qcs->tx.buf;
}

/* Function used to emit stream data from <h3_uqs> control uni-stream */
static int h3_control_send(struct h3_uqs *h3_uqs, void *ctx)
{
	int ret;
	struct h3 *h3 = ctx;
	unsigned char data[(2 + 3) * 2 * QUIC_VARINT_MAX_SIZE]; /* enough for 3 settings */
	struct buffer pos, *res;

	ret = 0;
	pos = b_make((char *)data, sizeof(data), 0, 0);
	if (!(h3->flags & H3_CF_SETTINGS_SENT)) {
		struct qcs *qcs = h3_uqs->qcs;
		size_t frm_len;

		frm_len = quic_int_getsize(H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY) +
			quic_int_getsize(h3_settings_qpack_max_table_capacity) +
			quic_int_getsize(H3_SETTINGS_QPACK_BLOCKED_STREAMS) +
			quic_int_getsize(h3_settings_qpack_blocked_streams);
		if (h3_settings_max_field_section_size) {
			frm_len += quic_int_getsize(H3_SETTINGS_MAX_FIELD_SECTION_SIZE) +
			quic_int_getsize(h3_settings_max_field_section_size);
		}

		b_quic_enc_int(&pos, H3_UNI_STRM_TP_CONTROL_STREAM);
		/* Build a SETTINGS frame */
		b_quic_enc_int(&pos, H3_FT_SETTINGS);
		b_quic_enc_int(&pos, frm_len);
		b_quic_enc_int(&pos, H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY);
		b_quic_enc_int(&pos, h3_settings_qpack_max_table_capacity);
		b_quic_enc_int(&pos, H3_SETTINGS_QPACK_BLOCKED_STREAMS);
		b_quic_enc_int(&pos, h3_settings_qpack_blocked_streams);
		if (h3_settings_max_field_section_size) {
			b_quic_enc_int(&pos, H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
			b_quic_enc_int(&pos, h3_settings_max_field_section_size);
		}

		res = mux_get_buf(qcs);
		if (b_room(res) < b_data(&pos)) {
			// TODO the mux should be put in blocked state, with
			// the stream in state waiting for settings to be sent
			ABORT_NOW();
		}

		ret = b_force_xfer(res, &pos, b_data(&pos));
		if (ret > 0) {
			h3->flags |= H3_CF_SETTINGS_SENT;
			if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
				tasklet_wakeup(qcs->qcc->wait_event.tasklet);
		}
	}

	return ret;
}

static int h3_resp_headers_send(struct qcs *qcs, struct htx *htx)
{
	struct buffer outbuf;
	struct buffer headers_buf = BUF_NULL;
	struct buffer *res;
	struct http_hdr list[global.tune.max_http_hdr];
	struct htx_sl *sl;
	struct htx_blk *blk;
	enum htx_blk_type type;
	int frame_length_size;  /* size in bytes of frame length varint field */
	int ret = 0;
	int hdr;
	int status = 0;

	sl = NULL;
	hdr = 0;
	for (blk = htx_get_head_blk(htx); blk; blk = htx_get_next_blk(htx, blk)) {
		type = htx_get_blk_type(blk);

		if (type == HTX_BLK_UNUSED)
			continue;

		if (type == HTX_BLK_EOH)
			break;

		if (type == HTX_BLK_RES_SL) {
			/* start-line -> HEADERS h3 frame */
			BUG_ON(sl);
			sl = htx_get_blk_ptr(htx, blk);
			/* TODO should be on h3 layer */
			status = sl->info.res.status;
		}
		else if (type == HTX_BLK_HDR) {
			list[hdr].n = htx_get_blk_name(htx, blk);
			list[hdr].v = htx_get_blk_value(htx, blk);
			hdr++;
		}
		else {
			ABORT_NOW();
			goto err;
		}
	}

	BUG_ON(!sl);

	list[hdr].n = ist("");

	res = mux_get_buf(qcs);

	/* At least 5 bytes to store frame type + length as a varint max size */
	if (b_room(res) < 5)
		ABORT_NOW();

	b_reset(&outbuf);
	outbuf = b_make(b_tail(res), b_contig_space(res), 0, 0);
	/* Start the headers after frame type + length */
	headers_buf = b_make(b_head(res) + 5, b_size(res) - 5, 0, 0);

	if (qpack_encode_field_section_line(&headers_buf))
		ABORT_NOW();
	if (qpack_encode_int_status(&headers_buf, status))
		ABORT_NOW();

	for (hdr = 0; hdr < sizeof(list) / sizeof(list[0]); ++hdr) {
		if (isteq(list[hdr].n, ist("")))
			break;

		if (qpack_encode_header(&headers_buf, list[hdr].n, list[hdr].v))
			ABORT_NOW();
	}

	/* Now that all headers are encoded, we are certain that res buffer is
	 * big enough
	 */
	frame_length_size = quic_int_getsize(b_data(&headers_buf));
	res->head += 4 - frame_length_size;
	b_putchr(res, 0x01); /* h3 HEADERS frame type */
	if (!b_quic_enc_int(res, b_data(&headers_buf)))
		ABORT_NOW();
	b_add(res, b_data(&headers_buf));

	ret = 0;
	blk = htx_get_head_blk(htx);
	while (blk) {
		type = htx_get_blk_type(blk);
		ret += htx_get_blksz(blk);
		blk = htx_remove_blk(htx, blk);
		if (type == HTX_BLK_EOH)
			break;
	}

	return ret;

 err:
	return 0;
}

/* Returns the total of bytes sent. */
static int h3_resp_data_send(struct qcs *qcs, struct buffer *buf, size_t count)
{
	struct buffer outbuf;
	struct buffer *res;
	size_t total = 0;
	struct htx *htx;
	int bsize, fsize, hsize;
	struct htx_blk *blk;
	enum htx_blk_type type;

	htx = htx_from_buf(buf);

 new_frame:
	if (!count || htx_is_empty(htx))
		goto end;

	blk = htx_get_head_blk(htx);
	type = htx_get_blk_type(blk);
	fsize = bsize = htx_get_blksz(blk);

	if (type != HTX_BLK_DATA)
		goto end;

	res = mux_get_buf(qcs);

	if (fsize > count)
		fsize = count;

	/* h3 DATA headers : 1-byte frame type + varint frame length */
	hsize = 1 + QUIC_VARINT_MAX_SIZE;

	while (1) {
		b_reset(&outbuf);
		outbuf = b_make(b_tail(res), b_contig_space(res), 0, 0);
		if (b_size(&outbuf) > hsize || !b_space_wraps(res))
			break;
		b_slow_realign(res, trash.area, b_data(res));
	}

	/* Not enough room for headers and at least one data byte, block the
	 * stream. It is expected that the conn-stream layer will subscribe on
	 * SEND.
	 */
	if (b_size(&outbuf) <= hsize) {
		qcs->flags |= QC_SF_BLK_MROOM;
		goto end;
	}

	if (b_size(&outbuf) < hsize + fsize)
		fsize = b_size(&outbuf) - hsize;
	BUG_ON(fsize <= 0);

	b_putchr(&outbuf, 0x00);        /* h3 frame type = DATA */
	b_quic_enc_int(&outbuf, fsize); /* h3 frame length */

	b_putblk(&outbuf, htx_get_blk_ptr(htx, blk), fsize);
	total += fsize;
	count -= fsize;

	if (fsize == bsize)
		htx_remove_blk(htx, blk);
	else
		htx_cut_data_blk(htx, blk, fsize);

	/* commit the buffer */
	b_add(res, b_data(&outbuf));
	goto new_frame;

 end:
	return total;
}

size_t h3_snd_buf(struct conn_stream *cs, struct buffer *buf, size_t count, int flags)
{
	size_t total = 0;
	struct qcs *qcs = cs->ctx;
	struct htx *htx;
	enum htx_blk_type btype;
	struct htx_blk *blk;
	uint32_t bsize;
	int32_t idx;
	int ret;

	fprintf(stderr, "%s\n", __func__);

	htx = htx_from_buf(buf);

	while (count && !htx_is_empty(htx) && !(qcs->flags & QC_SF_BLK_MROOM)) {
		idx = htx_get_head(htx);
		blk = htx_get_blk(htx, idx);
		btype = htx_get_blk_type(blk);
		bsize = htx_get_blksz(blk);

		/* Not implemented : QUIC on backend side */
		BUG_ON(btype == HTX_BLK_REQ_SL);

		switch (btype) {
		case HTX_BLK_RES_SL:
			/* start-line -> HEADERS h3 frame */
			ret = h3_resp_headers_send(qcs, htx);
			if (ret > 0) {
				total += ret;
				count -= ret;
				if (ret < bsize)
					goto out;
			}
			break;

		case HTX_BLK_DATA:
			ret = h3_resp_data_send(qcs, buf, count);
			if (ret > 0) {
				htx = htx_from_buf(buf);
				total += ret;
				count -= ret;
				if (ret < bsize)
					goto out;
			}
			break;

		case HTX_BLK_TLR:
		case HTX_BLK_EOT:
			/* TODO trailers */

		default:
			htx_remove_blk(htx, blk);
			total += bsize;
			count -= bsize;
			break;
		}
	}

	if ((htx->flags & HTX_FL_EOM) && htx_is_empty(htx))
		qcs->flags |= QC_SF_FIN_STREAM;

 out:
	if (total) {
		if (!(qcs->qcc->wait_event.events & SUB_RETRY_SEND))
			tasklet_wakeup(qcs->qcc->wait_event.tasklet);
	}

	return total;
}

/* Finalize the initialization of remotely initiated uni-stream <qcs>.
 * Return 1 if succeeded, 0 if not. In this latter case, set the ->err h3 error
 * to inform the QUIC mux layer of the encountered error.
 */
static int h3_attach_ruqs(struct qcs *qcs, void *ctx)
{
	uint64_t strm_type;
	struct h3 *h3 = ctx;
	struct buffer *rxbuf = &qcs->rx.buf;

	/* First octets: the uni-stream type */
	if (!b_quic_dec_int(&strm_type, rxbuf, NULL) || strm_type > H3_UNI_STRM_TP_MAX)
		return 0;

	/* Note that for all the uni-streams below, this is an error to receive two times the
	 * same type of uni-stream (even for Push stream which is not supported at this time.
	 */
	switch (strm_type) {
	case H3_UNI_STRM_TP_CONTROL_STREAM:
		if (h3->rctrl.qcs) {
			h3->err = H3_STREAM_CREATION_ERROR;
			return 0;
		}

		h3->rctrl.qcs = qcs;
		h3->rctrl.cb = h3_control_recv;
		qcs_subscribe(qcs, SUB_RETRY_RECV, &h3->rctrl.wait_event);
		break;
	case H3_UNI_STRM_TP_PUSH_STREAM:
		/* NOT SUPPORTED */
		break;
	case H3_UNI_STRM_TP_QPACK_ENCODER:
		if (h3->rqpack_enc.qcs) {
			h3->err = H3_STREAM_CREATION_ERROR;
			return 0;
		}

		h3->rqpack_enc.qcs = qcs;
		h3->rqpack_enc.cb = qpack_decode_enc;
		qcs_subscribe(qcs, SUB_RETRY_RECV, &h3->rqpack_enc.wait_event);
		break;
	case H3_UNI_STRM_TP_QPACK_DECODER:
		if (h3->rqpack_dec.qcs) {
			h3->err = H3_STREAM_CREATION_ERROR;
			return 0;
		}

		h3->rqpack_dec.qcs = qcs;
		h3->rqpack_dec.cb = qpack_decode_dec;
		qcs_subscribe(qcs, SUB_RETRY_RECV, &h3->rqpack_dec.wait_event);
		break;
	default:
		/* Error */
		h3->err = H3_STREAM_CREATION_ERROR;
		return 0;
	}

	return 1;
}

static int h3_finalize(void *ctx)
{
	struct h3 *h3 = ctx;
	int lctrl_id;

	lctrl_id = qcs_get_next_id(h3->qcc, QCS_SRV_UNI);
	h3->lctrl.qcs = qcs_new(h3->qcc, lctrl_id, QCS_SRV_UNI);
	if (!h3->lctrl.qcs)
		return 0;

	/* Wakeup ->lctrl uni-stream */
	h3_control_send(&h3->lctrl, h3);

	return 1;
}

/* Tasklet dedicated to h3 incoming uni-streams */
static struct task *h3_uqs_task(struct task *t, void *ctx, unsigned int state)
{
	struct h3_uqs *h3_uqs = ctx;
	struct h3 *h3 = h3_uqs->qcs->qcc->ctx;

	h3_uqs->cb(h3_uqs, h3);
	return NULL;
}

/* Release all the tasklet attached to <h3_uqs> uni-stream */
static inline void h3_uqs_tasklet_release(struct h3_uqs *h3_uqs)
{
	struct tasklet *t = h3_uqs->wait_event.tasklet;

	if (t)
		tasklet_free(t);
}

/* Release all the tasklet attached to <h3> uni-streams */
static void h3_uqs_tasklets_release(struct h3 *h3)
{
	h3_uqs_tasklet_release(&h3->rqpack_enc);
	h3_uqs_tasklet_release(&h3->rqpack_dec);
	h3_uqs_tasklet_release(&h3->rctrl);
}

/* Tasklet dedicated to h3 outgoing uni-streams */
__maybe_unused
static struct task *h3_uqs_send_task(struct task *t, void *ctx, unsigned int state)
{
	struct h3_uqs *h3_uqs = ctx;
	struct h3 *h3 = h3_uqs->qcs->qcc->ctx;

	h3_uqs->cb(h3_uqs, h3);
	return NULL;
}

/* Initialize <h3_uqs> uni-stream with <t> as tasklet */
static int h3_uqs_init(struct h3_uqs *h3_uqs, struct h3 *h3,
                       int (*cb)(struct h3_uqs *h3_uqs, void *ctx),
                       struct task *(*t)(struct task *, void *, unsigned int))
{
	h3_uqs->qcs = NULL;
	h3_uqs->cb = cb;
	h3_uqs->wait_event.tasklet = tasklet_new();
	if (!h3_uqs->wait_event.tasklet)
		return 0;

	h3_uqs->wait_event.tasklet->process = t;
	h3_uqs->wait_event.tasklet->context = h3_uqs;
	return 1;

 err:
	tasklet_free(h3_uqs->wait_event.tasklet);
	return 0;
}

static inline void h3_uqs_release(struct h3_uqs *h3_uqs)
{
	if (h3_uqs->qcs)
		uni_qcs_free(h3_uqs->qcs);
}

static inline void h3_uqs_release_all(struct h3 *h3)
{
	h3_uqs_tasklet_release(&h3->lctrl);
	h3_uqs_release(&h3->lctrl);
	h3_uqs_tasklet_release(&h3->lqpack_enc);
	h3_uqs_release(&h3->lqpack_enc);
	h3_uqs_tasklet_release(&h3->lqpack_dec);
	h3_uqs_release(&h3->lqpack_dec);
}

/* Initialize the HTTP/3 context for <qcc> mux.
 * Return 1 if succeeded, 0 if not.
 */
static int h3_init(struct qcc *qcc)
{
	struct h3 *h3;

	h3 = pool_alloc(pool_head_h3);
	if (!h3)
		goto fail_no_h3;

	h3->qcc = qcc;
	h3->err = H3_NO_ERROR;
	h3->flags = 0;

	if (!h3_uqs_init(&h3->rqpack_enc, h3, NULL, h3_uqs_task) ||
	    !h3_uqs_init(&h3->rqpack_dec, h3, NULL, h3_uqs_task) ||
	    !h3_uqs_init(&h3->rctrl, h3, h3_control_recv, h3_uqs_task))
		goto fail_no_h3_ruqs;

	if (!h3_uqs_init(&h3->lctrl, h3, h3_control_send, h3_uqs_task) ||
	    !h3_uqs_init(&h3->lqpack_enc, h3, NULL, h3_uqs_task) ||
	    !h3_uqs_init(&h3->lqpack_dec, h3, NULL, h3_uqs_task))
		goto fail_no_h3_luqs;

	qcc->ctx = h3;
	LIST_INIT(&h3->buf_wait.list);

	return 1;

 fail_no_h3_ruqs:
	h3_uqs_release_all(h3);
 fail_no_h3_luqs:
	h3_uqs_tasklets_release(h3);
	pool_free(pool_head_h3, h3);
 fail_no_h3:
	return 0;
}

/* HTTP/3 application layer operations */
const struct qcc_app_ops h3_ops = {
	.init        = h3_init,
	.attach_ruqs = h3_attach_ruqs,
	.decode_qcs  = h3_decode_qcs,
	.snd_buf     = h3_snd_buf,
	.finalize    = h3_finalize,
};
