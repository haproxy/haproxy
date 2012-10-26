/*
 * HTTP compression.
 *
 * Copyright 2012 Exceliance, David Du Colombier <dducolombier@exceliance.fr>
 *                            William Lallemand <wlallemand@exceliance.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>

/* Note: the crappy zlib and openssl libs both define the "free_func" type.
 * That's a very clever idea to use such a generic name in general purpose
 * libraries, really... The zlib one is easier to redefine than openssl's,
 * so let's only fix this one.
 */
#define free_func zlib_free_func
#include <zlib.h>
#undef free_func

#include <common/compat.h>

#include <types/global.h>
#include <types/compression.h>

#include <proto/compression.h>
#include <proto/proto_http.h>

static const struct comp_algo comp_algos[] =
{
	{ "identity", 8, identity_init, identity_add_data, identity_flush, identity_reset, identity_end },
#ifdef USE_ZLIB
	{ "deflate",  7, deflate_init,  deflate_add_data,  deflate_flush,  deflate_reset,  deflate_end },
	{ "gzip",     4, gzip_init,     deflate_add_data,  deflate_flush,  deflate_reset,  deflate_end },
#endif /* USE_ZLIB */
	{ NULL,       0, NULL ,         NULL,              NULL,           NULL,           NULL }
};

/*
 * Add a content-type in the configuration
 */
int comp_append_type(struct comp *comp, const char *type)
{
	struct comp_type *comp_type;

	comp_type = calloc(1, sizeof(struct comp_type));
	comp_type->name_len = strlen(type);
	comp_type->name = strdup(type);
	comp_type->next = comp->types;
	comp->types = comp_type;
	return 0;
}

/*
 * Add an algorithm in the configuration
 */
int comp_append_algo(struct comp *comp, const char *algo)
{
	struct comp_algo *comp_algo;
	int i;

	for (i = 0; comp_algos[i].name; i++) {
		if (!strcmp(algo, comp_algos[i].name)) {
			comp_algo = calloc(1, sizeof(struct comp_algo));
			memmove(comp_algo, &comp_algos[i], sizeof(struct comp_algo));
			comp_algo->next = comp->algos;
			comp->algos = comp_algo;
			return 0;
		}
	}
	return -1;
}

/* emit the chunksize followed by a CRLF on the output and return the number of
 * bytes written. Appends <add_crlf> additional CRLF after the first one. Chunk
 * sizes are truncated to 6 hex digits (16 MB) and padded left. The caller is
 * responsible for ensuring there is enough room left in the output buffer for
 * the string (8 bytes * add_crlf*2).
 */
int http_emit_chunk_size(char *out, unsigned int chksz, int add_crlf)
{
	int shift;
	int pos = 0;

	for (shift = 20; shift >= 0; shift -= 4)
		out[pos++] = hextab[(chksz >> shift) & 0xF];

	do {
		out[pos++] = '\r';
		out[pos++] = '\n';
	} while (--add_crlf >= 0);

	return pos;
}

/*
 * Init HTTP compression
 */
int http_compression_buffer_init(struct session *s, struct buffer *in, struct buffer *out)
{
	struct http_msg *msg = &s->txn.rsp;
	int left;

	/* not enough space */
	if (in->size - buffer_len(in) < 40)
	    return -1;

	/*
	 * Skip data, we don't need them in the new buffer. They are results
	 * of CHUNK_CRLF and CHUNK_SIZE parsing.
	 */
	b_adv(in, msg->next);
	msg->next = 0;
	msg->sov = 0;
	msg->sol = 0;

	out->size = global.tune.bufsize;
	out->i = 0;
	out->o = 0;
	out->p = out->data;
	/* copy output data */
	if (in->o > 0) {
		left = in->o - bo_contig_data(in);
		memcpy(out->data, bo_ptr(in), bo_contig_data(in));
		out->p += bo_contig_data(in);
		if (left > 0) { /* second part of the buffer */
			memcpy(out->p, in->data, left);
			out->p += left;
		}
		out->o = in->o;
	}
	out->i += http_emit_chunk_size(out->p, 0, 0);

	return 0;
}

/*
 * Add data to compress
 */
int http_compression_buffer_add_data(struct session *s, struct buffer *in, struct buffer *out)
{
	struct http_msg *msg = &s->txn.rsp;
	int data_process_len;
	int left;
	int ret;

	/*
	 * Skip data, we don't need them in the new buffer. They are results
	 * of CHUNK_CRLF and CHUNK_SIZE parsing.
	 */
	b_adv(in, msg->next);
	msg->next = 0;
	msg->sov = 0;
	msg->sol = 0;

	/*
	 * select the smallest size between the announced chunk size, the input
	 * data, and the available output buffer size
	 */
	data_process_len = MIN(in->i, msg->chunk_len);
	data_process_len = MIN(out->size - buffer_len(out), data_process_len);

	left = data_process_len - bi_contig_data(in);
	if (left <= 0) {
		ret = s->comp_algo->add_data(&s->comp_ctx.strm, bi_ptr(in),
					     data_process_len, bi_end(out),
					     out->size - buffer_len(out));
		if (ret < 0)
			return -1;
		out->i += ret;

	} else {
		ret = s->comp_algo->add_data(&s->comp_ctx.strm, bi_ptr(in), bi_contig_data(in), bi_end(out), out->size - buffer_len(out));
		if (ret < 0)
			return -1;
		out->i += ret;
		ret = s->comp_algo->add_data(&s->comp_ctx.strm, in->data, left, bi_end(out), out->size - buffer_len(out));
		if (ret < 0)
			return -1;
		out->i += ret;
	}

	b_adv(in, data_process_len);
	msg->chunk_len -= data_process_len;

	return 0;
}

/*
 * Flush data in process, and write the header and footer of the chunk. Upon
 * success, in and out buffers are swapped to avoid a copy.
 */
int http_compression_buffer_end(struct session *s, struct buffer **in, struct buffer **out, int end)
{
	int to_forward;
	int left;
	struct http_msg *msg = &s->txn.rsp;
	struct buffer *ib = *in, *ob = *out;
	int ret;

	/* flush data here */

	if (end)
		ret = s->comp_algo->flush(&s->comp_ctx, ob, Z_FINISH); /* end of data */
	else
		ret = s->comp_algo->flush(&s->comp_ctx, ob, Z_SYNC_FLUSH); /* end of buffer */

	if (ret < 0)
		return -1; /* flush failed */

	if (ob->i > 8) {
		/* more than a chunk size => some data were emitted */
		char *tail = ob->p + ob->i;

		/* write real size at the begining of the chunk, no need of wrapping */
		http_emit_chunk_size(ob->p, ob->i - 8, 0);

		/* chunked encoding requires CRLF after data */
		*tail++ = '\r';
		*tail++ = '\n';

		if (!(msg->flags & HTTP_MSGF_TE_CHNK) && msg->chunk_len == 0) {
			/* End of data, 0<CRLF><CRLF> is needed but we're not
			 * in chunked mode on input so we must add it ourselves.
			 */
			memcpy(tail, "0\r\n\r\n", 5);
			tail += 5;
		}
		ob->i = tail - ob->p;
	} else {
		/* no data were sent, cancel the chunk size */
		ob->i = 0;
	}

	to_forward = ob->i;

	/* copy the remaining data in the tmp buffer. */
	if (ib->i > 0) {
		left = ib->i - bi_contig_data(ib);
		memcpy(bi_end(ob), bi_ptr(ib), bi_contig_data(ib));
		ob->i += bi_contig_data(ib);
		if (left > 0) {
			memcpy(bi_end(ob), ib->data, left);
			ob->i += left;
		}
	}

	/* swap the buffers */
	*in = ob;
	*out = ib;

	/* forward the new chunk without remaining data */
	b_adv(ob, to_forward);

	/* if there are data between p and next, there are trailers, must forward them */
	b_adv(ob, msg->next);
	msg->next = 0;

	return to_forward;
}


/****************************
 **** Identity algorithm ****
 ****************************/

/*
 * Init the identity algorithm
 */
int identity_init(void *v, int level)
{
	return 0;
}

/*
 * Process data
 *   Return size of processed data or -1 on error
 */
int identity_add_data(void *comp_ctx, const char *in_data, int in_len, char *out_data, int out_len)
{
	if (out_len < in_len)
		return -1;

	memcpy(out_data, in_data, in_len);

	return in_len;
}

int identity_flush(void *comp_ctx, struct buffer *out, int flag)
{
	return 0;
}


int identity_reset(void *comp_ctx)
{
	return 0;
}

/*
 * Deinit the algorithm
 */
int identity_end(void *comp_ctx)
{
	return 0;
}


#ifdef USE_ZLIB

/**************************
****  gzip algorithm   ****
***************************/
int gzip_init(void *v, int level)
{
	z_stream *strm;

	strm = v;

	strm->zalloc = Z_NULL;
	strm->zfree = Z_NULL;
	strm->opaque = Z_NULL;

	if (deflateInit2(strm, level, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
		return -1;

	return 0;
}
/**************************
**** Deflate algorithm ****
***************************/

int deflate_init(void *comp_ctx, int level)
{
	z_stream *strm;

	strm = comp_ctx;

	strm->zalloc = Z_NULL;
	strm->zfree = Z_NULL;
	strm->opaque = Z_NULL;

	if (deflateInit(strm, level) != Z_OK)
		return -1;

	return 0;
}

int deflate_add_data(void *comp_ctx, const char *in_data, int in_len, char *out_data, int out_len)
{
	z_stream *strm;
	int ret;

	if (in_len <= 0)
		return 0;


	if (out_len <= 0)
		return -1;

	strm = comp_ctx;

	strm->next_in = (unsigned char *)in_data;
	strm->avail_in = in_len;
	strm->next_out = (unsigned char *)out_data;
	strm->avail_out = out_len;

	ret = deflate(strm, Z_NO_FLUSH);
	if (ret != Z_OK)
		return -1;

	/* deflate update the available data out */

	return out_len - strm->avail_out;
}

int deflate_flush(void *comp_ctx, struct buffer *out, int flag)
{
	int ret;
	z_stream *strm;
	int out_len = 0;

	strm = comp_ctx;
	strm->next_out = (unsigned char *)bi_end(out);
	strm->avail_out = out->size - buffer_len(out);

	ret = deflate(strm, flag);
	if (ret != Z_OK && ret != Z_STREAM_END)
		return -1;

	out_len = (out->size - buffer_len(out)) - strm->avail_out;
	out->i += out_len;

	return out_len;
}

int deflate_reset(void *comp_ctx)
{
	z_stream *strm;

	strm = comp_ctx;
	if (deflateReset(strm) == Z_OK)
		return 0;
	return -1;
}

int deflate_end(void *comp_ctx)
{
	z_stream *strm;

	strm = comp_ctx;
	if (deflateEnd(strm) == Z_OK)
		return 0;

	return -1;
}

#endif /* USE_ZLIB */

