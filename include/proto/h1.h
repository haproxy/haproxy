/*
 * include/proto/h1.h
 * This file contains HTTP/1 protocol definitions.
 *
 * Copyright (C) 2000-2017 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_H1_H
#define _PROTO_H1_H

#include <common/buffer.h>
#include <common/compiler.h>
#include <common/config.h>
#include <common/standard.h>
#include <types/h1.h>
#include <types/proto_http.h>

extern const uint8_t h1_char_classes[256];
int http_forward_trailers(struct http_msg *msg);

#define H1_FLG_CTL  0x01
#define H1_FLG_SEP  0x02
#define H1_FLG_LWS  0x04
#define H1_FLG_SPHT 0x08
#define H1_FLG_CRLF 0x10
#define H1_FLG_TOK  0x20
#define H1_FLG_VER  0x40

#define HTTP_IS_CTL(x)       (h1_char_classes[(uint8_t)(x)] & H1_FLG_CTL)
#define HTTP_IS_SEP(x)       (h1_char_classes[(uint8_t)(x)] & H1_FLG_SEP)
#define HTTP_IS_LWS(x)       (h1_char_classes[(uint8_t)(x)] & H1_FLG_LWS)
#define HTTP_IS_SPHT(x)      (h1_char_classes[(uint8_t)(x)] & H1_FLG_SPHT)
#define HTTP_IS_CRLF(x)      (h1_char_classes[(uint8_t)(x)] & H1_FLG_CRLF)
#define HTTP_IS_TOKEN(x)     (h1_char_classes[(uint8_t)(x)] & H1_FLG_TOK)
#define HTTP_IS_VER_TOKEN(x) (h1_char_classes[(uint8_t)(x)] & H1_FLG_VER)


/* Macros used in the HTTP/1 parser, to check for the expected presence of
 * certain bytes (ef: LF) or to skip to next byte and yield in case of failure.
 */


/* Expects to find an LF at <ptr>. If not, set <state> to <where> and jump to
 * <bad>.
 */
#define EXPECT_LF_HERE(ptr, bad, state, where)                  \
	do {                                                    \
		if (unlikely(*(ptr) != '\n')) {                 \
			state = (where);                        \
			goto bad;                               \
		}                                               \
	} while (0)

/* Increments pointer <ptr>, continues to label <more> if it's still below
 * pointer <end>, or goes to <stop> and sets <state> to <where> if the end
 * of buffer was reached.
 */
#define EAT_AND_JUMP_OR_RETURN(ptr, end, more, stop, state, where)        \
	do {                                                              \
		if (likely(++(ptr) < (end)))                              \
			goto more;                                        \
		else {                                                    \
			state = (where);                                  \
			goto stop;                                        \
		}                                                         \
	} while (0)

/* for debugging, reports the HTTP/1 message state name */
static inline const char *h1_msg_state_str(enum h1_state msg_state)
{
	switch (msg_state) {
	case HTTP_MSG_RQBEFORE:    return "MSG_RQBEFORE";
	case HTTP_MSG_RQBEFORE_CR: return "MSG_RQBEFORE_CR";
	case HTTP_MSG_RQMETH:      return "MSG_RQMETH";
	case HTTP_MSG_RQMETH_SP:   return "MSG_RQMETH_SP";
	case HTTP_MSG_RQURI:       return "MSG_RQURI";
	case HTTP_MSG_RQURI_SP:    return "MSG_RQURI_SP";
	case HTTP_MSG_RQVER:       return "MSG_RQVER";
	case HTTP_MSG_RQLINE_END:  return "MSG_RQLINE_END";
	case HTTP_MSG_RPBEFORE:    return "MSG_RPBEFORE";
	case HTTP_MSG_RPBEFORE_CR: return "MSG_RPBEFORE_CR";
	case HTTP_MSG_RPVER:       return "MSG_RPVER";
	case HTTP_MSG_RPVER_SP:    return "MSG_RPVER_SP";
	case HTTP_MSG_RPCODE:      return "MSG_RPCODE";
	case HTTP_MSG_RPCODE_SP:   return "MSG_RPCODE_SP";
	case HTTP_MSG_RPREASON:    return "MSG_RPREASON";
	case HTTP_MSG_RPLINE_END:  return "MSG_RPLINE_END";
	case HTTP_MSG_HDR_FIRST:   return "MSG_HDR_FIRST";
	case HTTP_MSG_HDR_NAME:    return "MSG_HDR_NAME";
	case HTTP_MSG_HDR_COL:     return "MSG_HDR_COL";
	case HTTP_MSG_HDR_L1_SP:   return "MSG_HDR_L1_SP";
	case HTTP_MSG_HDR_L1_LF:   return "MSG_HDR_L1_LF";
	case HTTP_MSG_HDR_L1_LWS:  return "MSG_HDR_L1_LWS";
	case HTTP_MSG_HDR_VAL:     return "MSG_HDR_VAL";
	case HTTP_MSG_HDR_L2_LF:   return "MSG_HDR_L2_LF";
	case HTTP_MSG_HDR_L2_LWS:  return "MSG_HDR_L2_LWS";
	case HTTP_MSG_LAST_LF:     return "MSG_LAST_LF";
	case HTTP_MSG_ERROR:       return "MSG_ERROR";
	case HTTP_MSG_BODY:        return "MSG_BODY";
	case HTTP_MSG_100_SENT:    return "MSG_100_SENT";
	case HTTP_MSG_CHUNK_SIZE:  return "MSG_CHUNK_SIZE";
	case HTTP_MSG_DATA:        return "MSG_DATA";
	case HTTP_MSG_CHUNK_CRLF:  return "MSG_CHUNK_CRLF";
	case HTTP_MSG_TRAILERS:    return "MSG_TRAILERS";
	case HTTP_MSG_ENDING:      return "MSG_ENDING";
	case HTTP_MSG_DONE:        return "MSG_DONE";
	case HTTP_MSG_CLOSING:     return "MSG_CLOSING";
	case HTTP_MSG_CLOSED:      return "MSG_CLOSED";
	case HTTP_MSG_TUNNEL:      return "MSG_TUNNEL";
	default:                   return "MSG_??????";
	}
}

/* This function may be called only in HTTP_MSG_CHUNK_CRLF. It reads the CRLF or
 * a possible LF alone at the end of a chunk. The caller should adjust msg->next
 * in order to include this part into the next forwarding phase.  Note that the
 * caller must ensure that ->p points to the first byte to parse.  It returns
 * the number of bytes parsed on success, so the caller can set msg_state to
 * HTTP_MSG_CHUNK_SIZE. If not enough data are available, the function does not
 * change anything and returns zero. If a parse error is encountered, the
 * function returns < 0. Note: this function is designed to parse wrapped CRLF
 * at the end of the buffer.
 */
static inline int http_skip_chunk_crlf(struct http_msg *msg)
{
	const struct buffer *buf = msg->chn->buf;
	const char *ptr;
	int bytes;

	/* NB: we'll check data availabilty at the end. It's not a
	 * problem because whatever we match first will be checked
	 * against the correct length.
	 */
	bytes = 1;
	ptr = b_ptr(buf, msg->next);
	if (*ptr == '\r') {
		bytes++;
		ptr++;
		if (ptr >= buf->data + buf->size)
			ptr = buf->data;
	}

	if (msg->next + bytes > buf->i)
		return 0;

	if (*ptr != '\n') {
		msg->err_pos = buffer_count(buf, buf->p, ptr);
		return -1;
	}
	return bytes;
}

/* Parse the chunk size at msg->next. Once done, caller should adjust ->next to
 * point to the first byte of data after the chunk size, so that we know we can
 * forward exactly msg->next bytes. msg->sol contains the exact number of bytes
 * forming the chunk size. That way it is always possible to differentiate
 * between the start of the body and the start of the data.  Return the number
 * of byte parsed on success, 0 when some data is missing, <0 on error.  Note:
 * this function is designed to parse wrapped CRLF at the end of the buffer.
 */
static inline int http_parse_chunk_size(struct http_msg *msg)
{
	const struct buffer *buf = msg->chn->buf;
	const char *ptr = b_ptr(buf, msg->next);
	const char *ptr_old = ptr;
	const char *end = buf->data + buf->size;
	const char *stop = bi_end(buf);
	unsigned int chunk = 0;

	/* The chunk size is in the following form, though we are only
	 * interested in the size and CRLF :
	 *    1*HEXDIGIT *WSP *[ ';' extensions ] CRLF
	 */
	while (1) {
		int c;
		if (ptr == stop)
			return 0;
		c = hex2i(*ptr);
		if (c < 0) /* not a hex digit anymore */
			break;
		if (unlikely(++ptr >= end))
			ptr = buf->data;
		if (unlikely(chunk & 0xF8000000)) /* integer overflow will occur if result >= 2GB */
			goto error;
		chunk = (chunk << 4) + c;
	}

	/* empty size not allowed */
	if (unlikely(ptr == ptr_old))
		goto error;

	while (HTTP_IS_SPHT(*ptr)) {
		if (++ptr >= end)
			ptr = buf->data;
		if (unlikely(ptr == stop))
			return 0;
	}

	/* Up to there, we know that at least one byte is present at *ptr. Check
	 * for the end of chunk size.
	 */
	while (1) {
		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* we now have a CR or an LF at ptr */
			if (likely(*ptr == '\r')) {
				if (++ptr >= end)
					ptr = buf->data;
				if (ptr == stop)
					return 0;
			}

			if (unlikely(*ptr != '\n'))
				goto error;
			if (++ptr >= end)
				ptr = buf->data;
			/* done */
			break;
		}
		else if (likely(*ptr == ';')) {
			/* chunk extension, ends at next CRLF */
			if (++ptr >= end)
				ptr = buf->data;
			if (ptr == stop)
				return 0;

			while (!HTTP_IS_CRLF(*ptr)) {
				if (++ptr >= end)
					ptr = buf->data;
				if (ptr == stop)
					return 0;
			}
			/* we have a CRLF now, loop above */
			continue;
		}
		else
			goto error;
	}

	/* OK we found our CRLF and now <ptr> points to the next byte, which may
	 * or may not be present. We save the number of bytes parsed into
	 * msg->sol.
	 */
	msg->sol = ptr - ptr_old;
	if (unlikely(ptr < ptr_old))
		msg->sol += buf->size;
	msg->chunk_len = chunk;
	msg->body_len += chunk;
	return msg->sol;
 error:
	msg->err_pos = buffer_count(buf, buf->p, ptr);
	return -1;
}


#endif /* _PROTO_H1_H */
