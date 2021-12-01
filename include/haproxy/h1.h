/*
 * include/haproxy/h1.h
 * This file contains HTTP/1 protocol definitions.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_H1_H
#define _HAPROXY_H1_H

#include <import/ist.h>
#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/http.h>
#include <haproxy/http-hdr-t.h>
#include <haproxy/intops.h>


/* Possible states while parsing HTTP/1 messages (request|response) */
enum h1m_state {
	H1_MSG_RQBEFORE     =  0, // request: leading LF, before start line
	H1_MSG_RQBEFORE_CR  =  1, // request: leading CRLF, before start line
	/* these ones define a request start line */
	H1_MSG_RQMETH       =  2, // parsing the Method
	H1_MSG_RQMETH_SP    =  3, // space(s) after the Method
	H1_MSG_RQURI        =  4, // parsing the Request URI
	H1_MSG_RQURI_SP     =  5, // space(s) after the Request URI
	H1_MSG_RQVER        =  6, // parsing the Request Version
	H1_MSG_RQLINE_END   =  7, // end of request line (CR or LF)

	H1_MSG_RPBEFORE     =  8, // response: leading LF, before start line
	H1_MSG_RPBEFORE_CR  =  9, // response: leading CRLF, before start line

	/* these ones define a response start line */
	H1_MSG_RPVER        = 10, // parsing the Response Version
	H1_MSG_RPVER_SP     = 11, // space(s) after the Response Version
	H1_MSG_RPCODE       = 12, // response code
	H1_MSG_RPCODE_SP    = 13, // space(s) after the response code
	H1_MSG_RPREASON     = 14, // response reason
	H1_MSG_RPLINE_END   = 15, // end of response line (CR or LF)

	/* common header processing */
	H1_MSG_HDR_FIRST    = 16, // waiting for first header or last CRLF (no LWS possible)
	H1_MSG_HDR_NAME     = 17, // parsing header name
	H1_MSG_HDR_COL      = 18, // parsing header colon
	H1_MSG_HDR_L1_SP    = 19, // parsing header LWS (SP|HT) before value
	H1_MSG_HDR_L1_LF    = 20, // parsing header LWS (LF) before value
	H1_MSG_HDR_L1_LWS   = 21, // checking whether it's a new header or an LWS
	H1_MSG_HDR_VAL      = 22, // parsing header value
	H1_MSG_HDR_L2_LF    = 23, // parsing header LWS (LF) inside/after value
	H1_MSG_HDR_L2_LWS   = 24, // checking whether it's a new header or an LWS

	H1_MSG_LAST_LF      = 25, // parsing last LF, last state for headers

	/* Body processing. */

	H1_MSG_CHUNK_SIZE   = 26, // parsing the chunk size (RFC7230 #4.1)
	H1_MSG_DATA         = 27, // skipping data chunk / content-length data
	H1_MSG_CHUNK_CRLF   = 28, // skipping CRLF after data chunk
	H1_MSG_TRAILERS     = 29, // trailers (post-data entity headers)
	/* we enter this state when we've received the end of the current message */
	H1_MSG_DONE         = 30, // message end received, waiting for resync or close
	H1_MSG_TUNNEL       = 31, // tunneled data after DONE
} __attribute__((packed));


/* HTTP/1 message flags (32 bit), for use in h1m->flags only */
#define H1_MF_NONE              0x00000000
#define H1_MF_CLEN              0x00000001 // content-length present
#define H1_MF_CHNK              0x00000002 // chunk present (as last encoding), exclusive with c-l
#define H1_MF_RESP              0x00000004 // this message is the response message
#define H1_MF_TOLOWER           0x00000008 // turn the header names to lower case
#define H1_MF_VER_11            0x00000010 // message indicates version 1.1 or above
#define H1_MF_CONN_CLO          0x00000020 // message contains "connection: close"
#define H1_MF_CONN_KAL          0x00000040 // message contains "connection: keep-alive"
#define H1_MF_CONN_UPG          0x00000080 // message contains "connection: upgrade"
#define H1_MF_XFER_LEN          0x00000100 // message xfer size can be determined
#define H1_MF_XFER_ENC          0x00000200 // transfer-encoding is present
#define H1_MF_NO_PHDR           0x00000400 // don't add pseudo-headers in the header list
#define H1_MF_HDRS_ONLY         0x00000800 // parse headers only
#define H1_MF_CLEAN_CONN_HDR    0x00001000 // skip close/keep-alive values of connection headers during parsing
#define H1_MF_METH_CONNECT      0x00002000 // Set for a response to a CONNECT request
#define H1_MF_METH_HEAD         0x00004000 // Set for a response to a HEAD request
#define H1_MF_UPG_WEBSOCKET     0x00008000 // Set for a Websocket upgrade handshake
#define H1_MF_TE_CHUNKED        0x00010000 // T-E "chunked"
#define H1_MF_TE_OTHER          0x00020000 // T-E other than supported ones found (only "chunked" is supported for now)

/* Mask to use to reset H1M flags when we restart headers parsing.
 *
 * WARNING: Don't forget to update it if a new flag must be preserved when
 *          headers parsing is restarted.
 */
#define H1_MF_RESTART_MASK    (H1_MF_RESP|H1_MF_TOLOWER|H1_MF_NO_PHDR|H1_MF_HDRS_ONLY| \
			       H1_MF_CLEAN_CONN_HDR|H1_MF_METH_CONNECT|H1_MF_METH_HEAD)

/* Note: for a connection to be persistent, we need this for the request :
 *   - one of CLEN or CHNK
 *   - version 1.0 and KAL and not CLO
 *   - or version 1.1 and not CLO
 * For the response it's the same except that UPG must not appear either.
 * So in short, for a request it's (CLEN|CHNK) > 0 && !CLO && (VER_11 || KAL)
 * and for a response it's (CLEN|CHNK) > 0 && !(CLO|UPG) && (VER_11 || KAL)
 */


/* basic HTTP/1 message state for use in parsers. The err_pos field is special,
 * it is pre-set to a negative value (-1 or -2), and once non-negative it contains
 * the relative position in the message of the first parse error. -2 is used to tell
 * the parser that we want to block the invalid message. -1 is used to only perform
 * a silent capture.
 */
struct h1m {
	enum h1m_state state;       // H1 message state (H1_MSG_*)
	/* 24 bits available here */
	uint32_t flags;             // H1 message flags (H1_MF_*)
	uint64_t curr_len;          // content-length or last chunk length
	uint64_t body_len;          // total known size of the body length
	uint32_t next;              // next byte to parse, relative to buffer's head
	int err_pos;                // position in the byte stream of the first error (H1 or H2)
	int err_state;              // state where the first error was met (H1 or H2)
};

/* basic H1 start line, describes either the request and the response */
union h1_sl {                          /* useful start line pointers, relative to ->sol */
	struct {
		struct ist m;          /* METHOD */
		struct ist u;          /* URI */
		struct ist v;          /* VERSION */
		enum http_meth_t meth; /* method */
	} rq;                          /* request line : field, length */
	struct {
		struct ist v;          /* VERSION */
		struct ist c;          /* CODE */
		struct ist r;          /* REASON */
		uint16_t status;       /* status code */
	} st;                          /* status line : field, length */
};

int h1_headers_to_hdr_list(char *start, const char *stop,
                           struct http_hdr *hdr, unsigned int hdr_num,
                           struct h1m *h1m, union h1_sl *slp);
int h1_measure_trailers(const struct buffer *buf, unsigned int ofs, unsigned int max);

int h1_parse_cont_len_header(struct h1m *h1m, struct ist *value);
int h1_parse_xfer_enc_header(struct h1m *h1m, struct ist value);
void h1_parse_connection_header(struct h1m *h1m, struct ist *value);
void h1_parse_upgrade_header(struct h1m *h1m, struct ist value);

void h1_generate_random_ws_input_key(char key_out[25]);
void h1_calculate_ws_output_key(const char *key, char *result);

/* for debugging, reports the HTTP/1 message state name */
static inline const char *h1m_state_str(enum h1m_state msg_state)
{
	switch (msg_state) {
	case H1_MSG_RQBEFORE:    return "MSG_RQBEFORE";
	case H1_MSG_RQBEFORE_CR: return "MSG_RQBEFORE_CR";
	case H1_MSG_RQMETH:      return "MSG_RQMETH";
	case H1_MSG_RQMETH_SP:   return "MSG_RQMETH_SP";
	case H1_MSG_RQURI:       return "MSG_RQURI";
	case H1_MSG_RQURI_SP:    return "MSG_RQURI_SP";
	case H1_MSG_RQVER:       return "MSG_RQVER";
	case H1_MSG_RQLINE_END:  return "MSG_RQLINE_END";
	case H1_MSG_RPBEFORE:    return "MSG_RPBEFORE";
	case H1_MSG_RPBEFORE_CR: return "MSG_RPBEFORE_CR";
	case H1_MSG_RPVER:       return "MSG_RPVER";
	case H1_MSG_RPVER_SP:    return "MSG_RPVER_SP";
	case H1_MSG_RPCODE:      return "MSG_RPCODE";
	case H1_MSG_RPCODE_SP:   return "MSG_RPCODE_SP";
	case H1_MSG_RPREASON:    return "MSG_RPREASON";
	case H1_MSG_RPLINE_END:  return "MSG_RPLINE_END";
	case H1_MSG_HDR_FIRST:   return "MSG_HDR_FIRST";
	case H1_MSG_HDR_NAME:    return "MSG_HDR_NAME";
	case H1_MSG_HDR_COL:     return "MSG_HDR_COL";
	case H1_MSG_HDR_L1_SP:   return "MSG_HDR_L1_SP";
	case H1_MSG_HDR_L1_LF:   return "MSG_HDR_L1_LF";
	case H1_MSG_HDR_L1_LWS:  return "MSG_HDR_L1_LWS";
	case H1_MSG_HDR_VAL:     return "MSG_HDR_VAL";
	case H1_MSG_HDR_L2_LF:   return "MSG_HDR_L2_LF";
	case H1_MSG_HDR_L2_LWS:  return "MSG_HDR_L2_LWS";
	case H1_MSG_LAST_LF:     return "MSG_LAST_LF";
	case H1_MSG_CHUNK_SIZE:  return "MSG_CHUNK_SIZE";
	case H1_MSG_DATA:        return "MSG_DATA";
	case H1_MSG_CHUNK_CRLF:  return "MSG_CHUNK_CRLF";
	case H1_MSG_TRAILERS:    return "MSG_TRAILERS";
	case H1_MSG_DONE:        return "MSG_DONE";
	case H1_MSG_TUNNEL:      return "MSG_TUNNEL";
	default:                 return "MSG_??????";
	}
}

/* This function may be called only in HTTP_MSG_CHUNK_CRLF. It reads the CRLF or
 * a possible LF alone at the end of a chunk. The caller should adjust msg->next
 * in order to include this part into the next forwarding phase.  Note that the
 * caller must ensure that head+start points to the first byte to parse.  It
 * returns the number of bytes parsed on success, so the caller can set msg_state
 * to HTTP_MSG_CHUNK_SIZE. If not enough data are available, the function does not
 * change anything and returns zero. Otherwise it returns a negative value
 * indicating the error position relative to <stop>. Note: this function is
 * designed to parse wrapped CRLF at the end of the buffer.
 */
static inline int h1_skip_chunk_crlf(const struct buffer *buf, int start, int stop)
{
	const char *ptr = b_peek(buf, start);
	int bytes = 1;

	if (stop <= start)
		return 0;

	/* NB: we'll check data availability at the end. It's not a
	 * problem because whatever we match first will be checked
	 * against the correct length.
	 */
	if (*ptr == '\r') {
		bytes++;
		ptr++;
		if (ptr >= b_wrap(buf))
			ptr = b_orig(buf);
	}

	if (bytes > stop - start)
		return 0;

	if (*ptr != '\n') // negative position to stop
		return ptr - __b_peek(buf, stop);

	return bytes;
}

/* Parse the chunk size start at buf + start and stops before buf + stop. The
 * positions are relative to the buffer's head.
 * It returns the chunk size in <res> and the amount of bytes read this way :
 *   < 0 : error at this position relative to <stop>
 *   = 0 : not enough bytes to read a complete chunk size
 *   > 0 : number of bytes successfully read that the caller can skip
 * On success, the caller should adjust its msg->next to point to the first
 * byte of data after the chunk size, so that we know we can forward exactly
 * msg->next bytes, and msg->sol to contain the exact number of bytes forming
 * the chunk size. That way it is always possible to differentiate between the
 * start of the body and the start of the data. Note: this function is designed
 * to parse wrapped CRLF at the end of the buffer.
 */
static inline int h1_parse_chunk_size(const struct buffer *buf, int start, int stop, uint64_t *res)
{
	const char *ptr = b_peek(buf, start);
	const char *ptr_old = ptr;
	const char *end = b_wrap(buf);
	uint64_t chunk = 0;

	stop -= start; // bytes left
	start = stop;  // bytes to transfer

	/* The chunk size is in the following form, though we are only
	 * interested in the size and CRLF :
	 *    1*HEXDIGIT *WSP *[ ';' extensions ] CRLF
	 */
	while (1) {
		int c;
		if (!stop)
			return 0;
		c = hex2i(*ptr);
		if (c < 0) /* not a hex digit anymore */
			break;
		if (unlikely(++ptr >= end))
			ptr = b_orig(buf);
		chunk = (chunk << 4) + c;
		if (unlikely(chunk & 0xF0000000000000)) {
			/* Don't get more than 13 hexa-digit (2^52 - 1) to never fed possibly
			 * bogus values from languages that use floats for their integers
			 */
			goto error;
		}
		stop--;
	}

	/* empty size not allowed */
	if (unlikely(ptr == ptr_old))
		goto error;

	while (HTTP_IS_SPHT(*ptr)) {
		if (++ptr >= end)
			ptr = b_orig(buf);
		if (--stop == 0)
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
					ptr = b_orig(buf);
				if (--stop == 0)
					return 0;
			}

			if (*ptr != '\n')
				goto error;
			if (++ptr >= end)
				ptr = b_orig(buf);
			--stop;
			/* done */
			break;
		}
		else if (likely(*ptr == ';')) {
			/* chunk extension, ends at next CRLF */
			if (++ptr >= end)
				ptr = b_orig(buf);
			if (--stop == 0)
				return 0;

			while (!HTTP_IS_CRLF(*ptr)) {
				if (++ptr >= end)
					ptr = b_orig(buf);
				if (--stop == 0)
					return 0;
			}
			/* we have a CRLF now, loop above */
			continue;
		}
		else
			goto error;
	}

	/* OK we found our CRLF and now <ptr> points to the next byte, which may
	 * or may not be present. Let's return the number of bytes parsed.
	 */
	*res = chunk;
	return start - stop;
 error:
	*res = 0; // just to stop gcc's -Wuninitialized warning :-(
	return -stop;
}

/* initializes an H1 message for a request */
static inline struct h1m *h1m_init_req(struct h1m *h1m)
{
	h1m->state = H1_MSG_RQBEFORE;
	h1m->next = 0;
	h1m->flags = H1_MF_NONE;
	h1m->curr_len = 0;
	h1m->body_len = 0;
	h1m->err_pos = -2;
	h1m->err_state = 0;
	return h1m;
}

/* initializes an H1 message for a response */
static inline struct h1m *h1m_init_res(struct h1m *h1m)
{
	h1m->state = H1_MSG_RPBEFORE;
	h1m->next = 0;
	h1m->flags = H1_MF_RESP;
	h1m->curr_len = 0;
	h1m->body_len = 0;
	h1m->err_pos = -2;
	h1m->err_state = 0;
	return h1m;
}

#endif /* _HAPROXY_H1_H */
