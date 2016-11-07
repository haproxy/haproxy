/*
 * A Random IP reputation service acting as a Stream Processing Offload Agent
 *
 * This is a very simple service that implement a "random" ip reputation
 * service. It will return random scores for all checked IP addresses. It only
 * shows you how to implement a ip reputation service or such kind of services
 * using the SPOE.
 *
 * Copyright 2016 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define DEFAULT_PORT      12345
#define NUM_WORKERS       5
#define MAX_FRAME_SIZE    16384
#define SPOP_VERSION      "1.0"
#define SPOA_CAPABILITIES ""

#define SLEN(str) (sizeof(str)-1)

#define LOG(fmt, args...)                                           \
	do {							    \
		struct timeval now;				    \
		int wid = *((int*)pthread_getspecific(worker_id));  \
								    \
		gettimeofday(&now, NULL);			    \
		fprintf(stderr, "%ld.%06ld [%02d] " fmt "\n",	    \
			now.tv_sec, now.tv_usec, wid, ##args);	    \
	} while (0)

#define DEBUG(x...)                             \
	do {					\
		if (debug)			\
			LOG(x);			\
	} while (0)

/* Frame Types sent by HAProxy and by agents */
enum spoe_frame_type {
	/* Frames sent by HAProxy */
	SPOE_FRM_T_HAPROXY_HELLO = 1,
	SPOE_FRM_T_HAPROXY_DISCON,
	SPOE_FRM_T_HAPROXY_NOTIFY,

	/* Frames sent by the agents */
	SPOE_FRM_T_AGENT_HELLO = 101,
	SPOE_FRM_T_AGENT_DISCON,
	SPOE_FRM_T_AGENT_ACK
};

/* All supported data types */
enum spoe_data_type {
	SPOE_DATA_T_NULL = 0,
	SPOE_DATA_T_BOOL,
	SPOE_DATA_T_INT32,
	SPOE_DATA_T_UINT32,
	SPOE_DATA_T_INT64,
	SPOE_DATA_T_UINT64,
	SPOE_DATA_T_IPV4,
	SPOE_DATA_T_IPV6,
	SPOE_DATA_T_STR,
	SPOE_DATA_T_BIN,
	SPOE_DATA_TYPES
};

/* Errors triggerd by SPOE applet */
enum spoe_frame_error {
	SPOE_FRM_ERR_NONE = 0,
	SPOE_FRM_ERR_IO,
	SPOE_FRM_ERR_TOUT,
	SPOE_FRM_ERR_TOO_BIG,
	SPOE_FRM_ERR_INVALID,
	SPOE_FRM_ERR_NO_VSN,
	SPOE_FRM_ERR_NO_FRAME_SIZE,
	SPOE_FRM_ERR_NO_CAP,
	SPOE_FRM_ERR_BAD_VSN,
	SPOE_FRM_ERR_BAD_FRAME_SIZE,
	SPOE_FRM_ERR_UNKNOWN = 99,
	SPOE_FRM_ERRS,
};

/* All supported SPOE actions */
enum spoe_action_type {
	SPOE_ACT_T_SET_VAR = 1,
	SPOE_ACT_T_UNSET_VAR,
	SPOE_ACT_TYPES,
};

/* Scopes used for variables set by agents. It is a way to be agnotic to vars
 * scope. */
enum spoe_vars_scope {
	SPOE_SCOPE_PROC = 0, /* <=> SCOPE_PROC  */
	SPOE_SCOPE_SESS,     /* <=> SCOPE_SESS */
	SPOE_SCOPE_TXN,      /* <=> SCOPE_TXN  */
	SPOE_SCOPE_REQ,      /* <=> SCOPE_REQ  */
	SPOE_SCOPE_RES,      /* <=> SCOPE_RES  */
};


/* Masks to get data type or flags value */
#define SPOE_DATA_T_MASK  0x0F
#define SPOE_DATA_FL_MASK 0xF0

/* Flags to set Boolean values */
#define SPOE_DATA_FL_FALSE 0x00
#define SPOE_DATA_FL_TRUE  0x10
static const char *spoe_frm_err_reasons[SPOE_FRM_ERRS] = {
	[SPOE_FRM_ERR_NONE]           = "normal",
	[SPOE_FRM_ERR_IO]             = "I/O error",
	[SPOE_FRM_ERR_TOUT]           = "a timeout occurred",
	[SPOE_FRM_ERR_TOO_BIG]        = "frame is too big",
	[SPOE_FRM_ERR_INVALID]        = "invalid frame received",
	[SPOE_FRM_ERR_NO_VSN]         = "version value not found",
	[SPOE_FRM_ERR_NO_FRAME_SIZE]  = "max-frame-size value not found",
	[SPOE_FRM_ERR_NO_CAP]         = "capabilities value not found",
	[SPOE_FRM_ERR_BAD_VSN]        = "unsupported version",
	[SPOE_FRM_ERR_BAD_FRAME_SIZE] = "max-frame-size too big or too small",
	[SPOE_FRM_ERR_UNKNOWN]        = "an unknown error occurred",
};

struct worker {
	unsigned int id;
	char         buf[MAX_FRAME_SIZE];
	unsigned int len;
	unsigned int size;
	int          status_code;
	unsigned int stream_id;
	unsigned int frame_id;
	bool         healthcheck;
	int          ip_score; /* -1 if unset, else between 0 and 100 */
};

struct chunk {
	char *str;	/* beginning of the string itself. Might not be 0-terminated */
	int len;	/* current size of the string from first to last char */
};

union spoe_value {
	bool            boolean; /* use for boolean */
	int32_t         sint32;  /* used for signed 32bits integers */
	uint32_t        uint32;  /* used for signed 32bits integers */
	int32_t         sint64;  /* used for signed 64bits integers */
	uint32_t        uint64;  /* used for signed 64bits integers */
	struct in_addr  ipv4;    /* used for ipv4 addresses */
	struct in6_addr ipv6;    /* used for ipv6 addresses */
	struct chunk    buffer;  /* used for char strings or buffers */
};

/* Used to store sample constant */
struct spoe_data {
	enum spoe_data_type type;  /* SPOE_DATA_T_* */
	union spoe_value    u;     /* spoe data value */
};

static bool debug = false;
static pthread_key_t worker_id;

static void
check_ipv4_reputation(struct worker *w, struct in_addr *ipv4)
{
	char str[INET_ADDRSTRLEN];

	if (inet_ntop(AF_INET, ipv4, str, INET_ADDRSTRLEN) == NULL)
		return;

	w->ip_score = random() % 100;

	DEBUG("  IP score for %.*s is: %d", INET_ADDRSTRLEN, str, w->ip_score);
}

static void
check_ipv6_reputation(struct worker *w, struct in6_addr *ipv6)
{
	char str[INET6_ADDRSTRLEN];

	if (inet_ntop(AF_INET6, ipv6, str, INET6_ADDRSTRLEN) == NULL)
		return;

	w->ip_score = random() % 100;

	DEBUG("  IP score for %.*s is: %d", INET6_ADDRSTRLEN, str, w->ip_score);
}

static int
do_read(int sock, void *buf, int read_len)
{
	fd_set readfds;
	int    n = 0, total = 0, bytesleft = read_len;

	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);

	while (total < read_len) {
		if (select(FD_SETSIZE, &readfds, NULL, NULL, NULL) == -1)
			return -1;
		if (!FD_ISSET(sock, &readfds))
			return -1;

		n = read(sock, buf + total, bytesleft);
		if (n <= 0)
			break;

		total += n;
		bytesleft -= n;
	}

	return (n == -1) ? -1 : total;
}

static int
do_write(int sock, void *buf, int write_len)
{
	fd_set writefds;
	int    n = 0, total = 0, bytesleft = write_len;

	FD_ZERO(&writefds);
	FD_SET(sock, &writefds);

	while (total < write_len) {
		if (select(FD_SETSIZE, NULL, &writefds, NULL, NULL) == -1)
			return -1;
		if (!FD_ISSET(sock, &writefds))
			return -1;

		n = write(sock, buf + total, bytesleft);
		if (n <= 0)
			break;

		total += n;
		bytesleft -= n;
	}

	return (n == -1) ? -1 : total;
}

/* Receive a frame sent by HAProxy. It returns -1 if an error occurred,
 * otherwise the number of read bytes.*/
static int
read_frame(int sock, struct worker *w)
{
	uint32_t     netint;
	unsigned int framesz;

	/* Read the frame size, on 4 bytes */
	if (do_read(sock, &netint, sizeof(netint)) != 4) {
		w->status_code = SPOE_FRM_ERR_IO;
		return -1;
	}

	/* Check it against the max size */
	framesz = ntohl(netint);
	if (framesz > w->size) {
		w->status_code = SPOE_FRM_ERR_TOO_BIG;
		return -1;
	}

	/* Read the frame */
	if (do_read(sock, w->buf, framesz) != framesz) {
		w->status_code = SPOE_FRM_ERR_IO;
		return -1;
	}

	w->len = framesz;
	return framesz;
}

/* Send a frame to HAProxy. It returns -1 if an error occurred, otherwise the
 * number of written bytes. */
static int
write_frame(int sock, struct worker *w)
{
	uint32_t netint;

	/* Write the frame size, on 4 bytes */
	netint = htonl(w->len);
	if (do_write(sock, &netint, sizeof(netint)) != 4) {
		w->status_code = SPOE_FRM_ERR_IO;
		return -1;
	}

	/* Write the frame */
	if (do_write(sock, w->buf, w->len) != w->len) {
		w->status_code = SPOE_FRM_ERR_IO;
		return -1;
	}
	return w->len;
}

/* Encode a variable-length integer. This function never fails and returns the
 * number of written bytes. */
static int
encode_spoe_varint(uint64_t i, char *buf)
{
	int idx;

	if (i < 240) {
		buf[0] = (unsigned char)i;
		return 1;
	}

	buf[0] = (unsigned char)i | 240;
	i = (i - 240) >> 4;
	for (idx = 1; i >= 128; ++idx) {
		buf[idx] = (unsigned char)i | 128;
		i = (i - 128) >> 7;
	}
	buf[idx++] = (unsigned char)i;
	return idx;
}

/* Decode a varable-length integer. If the decoding fails, -1 is returned. This
 * happens when the buffer's end in reached. On success, the number of read
 * bytes is returned. */
static int
decode_spoe_varint(char *buf, char *end, uint64_t *i)
{
	unsigned char *msg = (unsigned char *)buf;
	int            idx = 0;

	if (msg > (unsigned char *)end)
		return -1;

	if (msg[0] < 240) {
		*i = msg[0];
		return 1;
	}
	*i = msg[0];
	do {
		++idx;
		if (msg+idx > (unsigned char *)end)
			return -1;
		*i += (uint64_t)msg[idx] <<  (4 + 7 * (idx-1));
	} while (msg[idx] >= 128);
	return (idx + 1);
}

/* Encode a string. The string will be prefix by its length, encoded as a
 * variable-length integer. This function never fails and returns the number of
 * written bytes. */
static int
encode_spoe_string(const char *str, size_t len, char *dst)
{
	int idx = 0;

	if (!len) {
		dst[0] = 0;
		return 1;
	}

	idx += encode_spoe_varint(len, dst);
	memcpy(dst+idx, str, len);
	return (idx + len);
}

/* Decode a string. Its length is decoded first as a variable-length integer. If
 * it succeeds, and if the string length is valid, the begin of the string is
 * saved in <*str>, its length is saved in <*len> and the total numbre of bytes
 * read is returned. If an error occurred, -1 is returned and <*str> remains
 * NULL. */
static int
decode_spoe_string(char *buf, char *end, char **str, uint64_t *len)
{
	int r, idx = 0;

	*str = NULL;
	*len = 0;

	if ((r = decode_spoe_varint(buf, end, len)) == -1)
		goto error;
	idx += r;
	if (buf + idx + *len > end)
		goto error;

	*str = buf+idx;
	return (idx + *len);

error:
	return -1;
}

/* Skip a typed data. If an error occurred, -1 is returned, otherwise the number
 * of bytes read is returned. A types data is composed of a type (1 byte) and
 * corresponding data:
 *  - boolean: non additional data (0 bytes)
 *  - integers: a variable-length integer (see decode_spoe_varint)
 *  - ipv4: 4 bytes
 *  - ipv6: 16 bytes
 *  - binary and string: a buffer prefixed by its size, a variable-length
 *    integer (see decode_spoe_string) */
static int
skip_spoe_data(char *frame, char *end)
{
	uint64_t sz = 0;
	int      r, idx = 0;

	if (frame > end)
		return -1;

	switch (frame[idx++] & SPOE_DATA_T_MASK) {
		case SPOE_DATA_T_BOOL:
			idx++;
			break;
		case SPOE_DATA_T_INT32:
		case SPOE_DATA_T_INT64:
		case SPOE_DATA_T_UINT32:
		case SPOE_DATA_T_UINT64:
			if ((r = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			idx += r;
			break;
		case SPOE_DATA_T_IPV4:
			idx += 4;
			break;
		case SPOE_DATA_T_IPV6:
			idx += 16;
			break;
		case SPOE_DATA_T_STR:
		case SPOE_DATA_T_BIN:
			if ((r = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			idx += r + sz;
			break;
	}

	if (frame+idx > end)
		return -1;
	return idx;
}

/* Decode a typed data. If an error occurred, -1 is returned, otherwise the
 * number of read bytes is returned. See skip_spoe_data for details. */
static int
decode_spoe_data(char *frame, char *end, struct spoe_data *data)
{
	uint64_t sz  = 0;
	int      type, r, idx = 0;

	if (frame > end)
		return -1;

	type = frame[idx++];
	data->type = (type & SPOE_DATA_T_MASK);
	switch (data->type) {
		case SPOE_DATA_T_BOOL:
			data->u.boolean = ((type & SPOE_DATA_FL_TRUE) == SPOE_DATA_FL_TRUE);
			break;
		case SPOE_DATA_T_INT32:
			if ((r = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			data->u.sint32 = sz;
			idx += r;
			break;
		case SPOE_DATA_T_INT64:
			if ((r = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			data->u.uint32 = sz;
			idx += r;
			break;
		case SPOE_DATA_T_UINT32:
			if ((r = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			data->u.sint64 = sz;
			idx += r;
			break;
		case SPOE_DATA_T_UINT64:
			if ((r = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			data->u.uint64 = sz;
			idx += r;
			break;
		case SPOE_DATA_T_IPV4:
			if (frame+idx+4 > end)
				return -1;
			memcpy(&data->u.ipv4, frame+idx, 4);
			idx += 4;
			break;
		case SPOE_DATA_T_IPV6:
			if (frame+idx+16 > end)
				return -1;
			memcpy(&data->u.ipv6, frame+idx, 16);
			idx += 16;
			break;
		case SPOE_DATA_T_STR:
			if ((r = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			idx += r;
			if (frame+idx+sz > end)
				return -1;
			data->u.buffer.str = frame+idx;
			data->u.buffer.len = sz;
			idx += sz;
			break;
		case SPOE_DATA_T_BIN:
			if ((r = decode_spoe_varint(frame+idx, end, &sz)) == -1)
				return -1;
			idx += r;
			if (frame+idx+sz > end)
				return -1;
			data->u.buffer.str = frame+idx;
			data->u.buffer.len = sz;
			idx += sz;
			break;
		default:
			break;
	}

	if (frame+idx > end)
		return -1;
	return idx;
}


/* Check the protocol version. It returns -1 if an error occurred, the number of
 * read bytes otherwise. */
static int
check_proto_version(struct worker *w, int idx)
{
	char    *str;
	uint64_t sz;

	/* Get the list of all supported versions by HAProxy */
	if ((w->buf[idx++] & SPOE_DATA_T_MASK) != SPOE_DATA_T_STR) {
		w->status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}
	idx += decode_spoe_string(w->buf+idx, w->buf+w->len, &str, &sz);
	if (str == NULL) {
		w->status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}

	/* TODO: Find the right verion in supported ones */

	return idx;
}

/* Check max frame size value. It returns -1 if an error occurred, the number of
 * read bytes otherwise. */
static int
check_max_frame_size(struct worker *w, int idx)
{
	uint64_t sz;
	int      type, i;

	/* Get the max-frame-size value of HAProxy */
	type =  w->buf[idx++];
	if ((type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT32  &&
	    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT64  &&
	    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT32 &&
	    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT64) {
		w->status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}
	if ((i = decode_spoe_varint(w->buf+idx, w->buf+w->len, &sz)) == -1) {
		w->status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}
	idx += i;

	/* Keep the lower value */
	if (sz < w->size)
		w->size = sz;

	return idx;
}

/* Check healthcheck value. It returns -1 if an error occurred, the number of
 * read bytes otherwise. */
static int
check_healthcheck(struct worker *w, int idx)
{
	int type;

	/* Get the "healthcheck" value of HAProxy */
	type = w->buf[idx++];
	if ((type & SPOE_DATA_T_MASK) != SPOE_DATA_T_BOOL) {
		w->status_code = SPOE_FRM_ERR_INVALID;
		return -1;
	}
	w->healthcheck = ((type & SPOE_DATA_FL_TRUE) == SPOE_DATA_FL_TRUE);
	return idx;
}


/* Decode a HELLO frame received from HAProxy. It returns -1 if an error
 * occurred, 0 if the frame must be skipped, otherwise the number of read
 * bytes. */
static int
handle_hahello(struct worker *w)
{
	char        *end = w->buf+w->len;
	int          i, idx = 0;

	/* Check frame type */
	if (w->buf[idx++] != SPOE_FRM_T_HAPROXY_HELLO)
		goto skip;

	/* Skip flags */
	idx += 4;

	/* stream-id and frame-id must be cleared */
	if (w->buf[idx] != 0 || w->buf[idx+1] != 0) {
		w->status_code = SPOE_FRM_ERR_INVALID;
		goto error;
	}
	idx += 2;

	/* Loop on K/V items */
	while (idx < w->len) {
		char     *str;
		uint64_t  sz;

		/* Decode the item name */
		idx += decode_spoe_string(w->buf+idx, end, &str, &sz);
		if (str == NULL) {
			w->status_code = SPOE_FRM_ERR_INVALID;
			goto error;
		}

		/* Check "supported-versions" K/V item */
		if (!memcmp(str, "supported-versions", sz)) {
			if ((i = check_proto_version(w, idx)) == -1)
				goto error;
			idx = i;
		}
		/* Check "max-frame-size" K/V item "*/
		else if (!memcmp(str, "max-frame-size", sz)) {
			if ((i = check_max_frame_size(w, idx)) == -1)
				goto error;
			idx = i;
		}
		/* Check "healthcheck" K/V item "*/
		else if (!memcmp(str, "healthcheck", sz)) {
			if ((i = check_healthcheck(w, idx)) == -1)
				goto error;
			idx = i;
		}
		/* Skip "capabilities" K/V item for now */
		else {
			/* Silently ignore unknown item */
			if ((i = skip_spoe_data(w->buf+idx, end)) == -1) {
				w->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
			idx += i;
		}
	}

	return idx;
skip:
	return 0;
error:
	return -1;
}

/* Decode a DISCONNECT frame received from HAProxy. It returns -1 if an error
 * occurred, 0 if the frame must be skipped, otherwise the number of read
 * bytes. */
static int
handle_hadiscon(struct worker *w)
{
	char        *end = w->buf+w->len;
	int          i, idx = 0;

	/* Check frame type */
	if (w->buf[idx++] != SPOE_FRM_T_HAPROXY_DISCON)
		goto skip;

	/* Skip flags */
	idx += 4;

	/* stream-id and frame-id must be cleared */
	if (w->buf[idx] != 0 || w->buf[idx+1] != 0) {
		w->status_code = SPOE_FRM_ERR_INVALID;
		goto error;
	}
	idx += 2;

	/* Loop on K/V items */
	while (idx < w->len) {
		char     *str;
		uint64_t  sz;

		/* Decode item key */
		idx += decode_spoe_string(w->buf+idx, end, &str, &sz);
		if (str == NULL) {
			w->status_code = SPOE_FRM_ERR_INVALID;
			goto error;
		}
		/* Silently ignore unknown item */
		if ((i = skip_spoe_data(w->buf+idx, end)) == -1) {
			w->status_code = SPOE_FRM_ERR_INVALID;
			goto error;
		}
		idx += i;
	}

	w->status_code = SPOE_FRM_ERR_NONE;
	return idx;
skip:
	return 0;
error:
	return -1;
}

/* Decode a NOTIFY frame received from HAProxy. It returns -1 if an error
 * occurred, 0 if the frame must be skipped, otherwise the number of read
 * bytes. */
static int
handle_hanotify(struct worker *w)
{
	char    *end = w->buf+w->len;
	uint64_t stream_id, frame_id;
	int      nbargs, i, idx = 0;

	/* Check frame type */
	if (w->buf[idx++] != SPOE_FRM_T_HAPROXY_NOTIFY)
		goto skip;

	/* Skip flags */
	idx += 4;

	/* Read the stream-id */
	if ((i = decode_spoe_varint(w->buf+idx, end, &stream_id)) == -1) {
		w->status_code = SPOE_FRM_ERR_INVALID;
		goto error;
	}
	idx += i;

	/* Read the frame-id */
	if ((i = decode_spoe_varint(w->buf+idx, end, &frame_id)) == -1) {
		w->status_code = SPOE_FRM_ERR_INVALID;
		goto error;
	}
	idx += i;

	w->stream_id = (unsigned int)stream_id;
	w->frame_id  = (unsigned int)frame_id;

	DEBUG("Notify frame received: stream-id=%u - frame-id=%u",
	      w->stream_id, w->frame_id);

	/* Loop on messages */
	while (idx < w->len) {
		char    *str;
		uint64_t sz;

		/* Decode the message name */
		idx += decode_spoe_string(w->buf+idx, end, &str, &sz);
		if (str == NULL) {
			w->status_code = SPOE_FRM_ERR_INVALID;
			goto error;
		}
		DEBUG("  Message '%.*s' received", (int)sz, str);

		nbargs = w->buf[idx++];
		if (!memcmp(str, "check-client-ip", sz)) {
			struct spoe_data data;

			memset(&data, 0, sizeof(data));

			if (nbargs != 1) {
				w->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
			if ((i = decode_spoe_string(w->buf+idx, end, &str, &sz)) == -1) {
				w->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
			idx += i;
			if ((i = decode_spoe_data(w->buf+idx, end, &data)) == -1) {
				w->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
			idx += i;
			if ((data.type & SPOE_DATA_T_MASK) == SPOE_DATA_T_IPV4)
				check_ipv4_reputation(w, &data.u.ipv4);
			else if ((data.type & SPOE_DATA_T_MASK) == SPOE_DATA_T_IPV6)
				check_ipv6_reputation(w, &data.u.ipv6);
			else {
				w->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
		else {
			while (nbargs-- > 0) {
				/* Silently ignore argument: its name and its value */
				if ((i = decode_spoe_string(w->buf+idx, end, &str, &sz)) == -1) {
					w->status_code = SPOE_FRM_ERR_INVALID;
					goto error;
				}
				idx += i;
				if ((i = skip_spoe_data(w->buf+idx, end)) == -1) {
					w->status_code = SPOE_FRM_ERR_INVALID;
					goto error;
				}
				idx += i;
			}
		}
	}

	return idx;
skip:
	return 0;
error:
	return -1;
}

/* Encode a HELLO frame to send it to HAProxy. It returns -1 if an error
 * occurred, the number of written bytes otherwise. */
static int
prepare_agenthello(struct worker *w)
{
	int idx = 0;

	/* Frame Type */
	w->buf[idx++] = SPOE_FRM_T_AGENT_HELLO;

	/* No flags for now */
	memset(w->buf+idx, 0, 4); /* No flags */
	idx += 4;

	/* No stream-id and frame-id for HELLO frames */
	w->buf[idx++] = 0;
	w->buf[idx++] = 0;

	/* "version" K/V item */
	idx += encode_spoe_string("version", 7, w->buf+idx);
	w->buf[idx++] = SPOE_DATA_T_STR;
	idx += encode_spoe_string(SPOP_VERSION, SLEN(SPOP_VERSION), w->buf+idx);

	/* "max-frame-size" K/V item */
	idx += encode_spoe_string("max-frame-size", 14, w->buf+idx);
	w->buf[idx++] = SPOE_DATA_T_UINT32;
	idx += encode_spoe_varint(w->size, w->buf+idx);

	/* "capabilities" K/V item */
	idx += encode_spoe_string("capabilities", 12, w->buf+idx);
	w->buf[idx++] = SPOE_DATA_T_STR;
	idx += encode_spoe_string(SPOA_CAPABILITIES, SLEN(SPOA_CAPABILITIES), w->buf+idx);

	w->len = idx;
	return idx;
}

/* Encode a ACK frame to send it to HAProxy. It returns -1 if an error occurred,
 * the number of written bytes otherwise. */
static int
prepare_agentack(struct worker *w)
{
	int idx = 0;

	/* Frame type */
	w->buf[idx++] = SPOE_FRM_T_AGENT_ACK;

	/* No flags for now */
	memset(w->buf+idx, 0, 4); /* No flags */
	idx += 4;

	/* Set stream-id and frame-id for ACK frames */
	idx += encode_spoe_varint(w->stream_id, w->buf+idx);
	idx += encode_spoe_varint(w->frame_id, w->buf+idx);

	/* Data */
	if (w->ip_score == -1)
		goto out;

	w->buf[idx++] = SPOE_ACT_T_SET_VAR;                   /* Action type */
	w->buf[idx++] = 3;                                    /* Number of args */
	w->buf[idx++] = SPOE_SCOPE_SESS;                      /* Arg 1: the scope */
	idx += encode_spoe_string("ip_score", 8, w->buf+idx); /* Arg 2: variable name */
	w->buf[idx++] = SPOE_DATA_T_UINT32;
	idx += encode_spoe_varint(w->ip_score, w->buf+idx);   /* Arg 3: variable value */
out:
	w->len = idx;
	return idx;
}

/* Encode a DISCONNECT frame to send it to HAProxy. It returns -1 if an error
 * occurred, the number of written bytes otherwise. */
static int
prepare_agentdicon(struct worker *w)
{
	const char *reason;
	int         rlen, idx = 0;

	if (w->status_code >= SPOE_FRM_ERRS)
		w->status_code = SPOE_FRM_ERR_UNKNOWN;
	reason = spoe_frm_err_reasons[w->status_code];
	rlen   = strlen(reason);

	/* Frame type */
	w->buf[idx++] = SPOE_FRM_T_AGENT_DISCON;

	/* No flags for now */
	memset(w->buf+idx, 0, 4);
	idx += 4;

	/* No stream-id and frame-id for DISCONNECT frames */
	w->buf[idx++] = 0;
	w->buf[idx++] = 0;

	/* There are 2 mandatory items: "status-code" and "message" */

	/* "status-code" K/V item */
	idx += encode_spoe_string("status-code", 11, w->buf+idx);
	w->buf[idx++] = SPOE_DATA_T_UINT32;
	idx += encode_spoe_varint(w->status_code, w->buf+idx);

	/* "message" K/V item */
	idx += encode_spoe_string("message", 7, w->buf+idx);
	w->buf[idx++] = SPOE_DATA_T_STR;
	idx += encode_spoe_string(reason, rlen, w->buf+idx);

	w->len = idx;
	return idx;
}

static int
hello_handshake(int sock, struct worker *w)
{
	if (read_frame(sock, w) < 0) {
		LOG("Failed to read Haproxy HELLO frame");
		goto error;
	}
	if (handle_hahello(w) < 0) {
		LOG("Failed to handle Haproxy HELLO frame");
		goto error;
	}
	if (prepare_agenthello(w) < 0) {
		LOG("Failed to prepare Agent HELLO frame");
		goto error;
	}
	if (write_frame(sock, w) < 0) {
		LOG("Failed to write Agent frame");
		goto error;
	}
	DEBUG("Hello handshake done: version=%s - max-frame-size=%u - healthcheck=%s",
	      SPOP_VERSION, w->size, (w->healthcheck ? "true" : "false"));
	return 0;
error:
	return -1;
}

static int
notify_ack_roundtip(int sock, struct worker *w)
{
	if (read_frame(sock, w) < 0) {
		LOG("Failed to read Haproxy NOTIFY frame");
		goto error_or_quit;
	}
	if (handle_hadiscon(w) != 0) {
		if (w->status_code != SPOE_FRM_ERR_NONE)
			LOG("Failed to handle Haproxy DISCONNECT frame");
		DEBUG("Disconnect frame received: reason=%s",
		      spoe_frm_err_reasons[w->status_code]);
		goto error_or_quit;
	}
	if (handle_hanotify(w) < 0) {
		LOG("Failed to handle Haproxy NOTIFY frame");
		goto error_or_quit;
	}
	if (prepare_agentack(w) < 0) {
		LOG("Failed to prepare Agent ACK frame");
		goto error_or_quit;
	}
	if (write_frame(sock, w) < 0) {
		LOG("Failed to write Agent ACK frame");
		goto error_or_quit;
	}
	DEBUG("Ack frame sent: stream-id=%u - frame-id=%u",
	      w->stream_id, w->frame_id);
	return 0;
error_or_quit:
	return -1;
}

static void *
worker(void *data)
{
	struct worker w;
	struct sockaddr_in client;
	int *info = (int *)data;
	int csock, lsock = info[0];

	signal(SIGPIPE, SIG_IGN);
	pthread_setspecific(worker_id, &info[1]);

	while (1) {
		socklen_t sz = sizeof(client);

		if ((csock = accept(lsock, (struct sockaddr *)&client, &sz)) < 0) {
			LOG("Failed to accept client connection: %m");
			goto out;
		}
		memset(&w, 0, sizeof(w));
		w.id       = info[1];
		w.size     = MAX_FRAME_SIZE;

		DEBUG("New connection from HAProxy accepted");

		if (hello_handshake(csock, &w) < 0)
			goto disconnect;
		if (w.healthcheck == true)
			goto close;
		while (1) {
			w.ip_score = -1;
			if (notify_ack_roundtip(csock, &w) < 0)
				break;
		}

	disconnect:
		if (w.status_code == SPOE_FRM_ERR_IO) {
			LOG("Close the client socket because of I/O errors");
			goto close;
		}
		if (prepare_agentdicon(&w) < 0) {
			LOG("Failed to prepare Agent DISCONNECT frame");
			goto close;
		}
		if (write_frame(csock, &w) < 0) {
			LOG("Failed to write Agent DISCONNECT frame");
			goto close;
		}
		DEBUG("Disconnect frame sent: reason=%s",
		      spoe_frm_err_reasons[w.status_code]);

	close:
		close(csock);
	}

out:
	free(info);
	pthread_exit(NULL);
}

static void
usage(char *prog)
{
	fprintf(stderr, "Usage: %s [-h] [-d] [-p <port>] [-n <num-workers>]\n", prog);
	fprintf(stderr, "    -h                  Print this message\n");
	fprintf(stderr, "    -d                  Enable the debug mode\n");
	fprintf(stderr, "    -p <port>           Specify the port to listen on (default: 12345)\n");
	fprintf(stderr, "    -n <num-workers>    Specify the number of workers (default: 5)\n");
}

int
main(int argc, char **argv)
{
	pthread_t *ts = NULL;
	struct sockaddr_in server;
	int i, sock, opt, nbworkers, port;

	nbworkers = NUM_WORKERS;
	port      = DEFAULT_PORT;
	while ((opt = getopt(argc, argv, "hdn:p:")) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0]);
				return EXIT_SUCCESS;
			case 'd':
				debug = true;
				break;
			case 'n':
				nbworkers = atoi(optarg);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			default:
				usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	if (nbworkers <= 0) {
		fprintf(stderr, "%s: Invalid number of workers '%d'\n",
			argv[0], nbworkers);
		goto error;
	}
	if (port <= 0) {
		fprintf(stderr, "%s: Invalid port '%d'\n", argv[0], port);
		goto error;
	}

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Failed creating socket: %m\n");
		goto error;
	}

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (int []){1}, sizeof(int));
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (int []){1}, sizeof(int));

	memset(&server, 0, sizeof(server));
	server.sin_family      = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port        = htons(port);

	if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		fprintf(stderr, "Failed to bind the socket: %m\n");
		goto error;
	}

	if (listen(sock , 10) < 0) {
		fprintf(stderr, "Failed to listen on the socket: %m\n");
		goto error;
	}
	fprintf(stderr, "SPOA is listening on port %d\n", port);

	ts = calloc(nbworkers, sizeof(*ts));
	pthread_key_create(&worker_id, NULL);
	for (i = 0; i < nbworkers; i++) {
		int *info = calloc(2, sizeof(*info));

		info[0] = sock;
		info[1] = i+1;
		if (pthread_create(&ts[i], NULL,  worker, info) < 0) {
			fprintf(stderr, "Failed to create thread %d: %m\n", i+1);
			goto error;
		}
		fprintf(stderr, "SPOA worker %02d started\n", i+1);
	}

	for (i = 0; i < nbworkers; i++) {
		pthread_join(ts[i], NULL);
		fprintf(stderr, "SPOA worker %02d stopped\n", i+1);
	}
	pthread_key_delete(worker_id);
	free(ts);
	close(sock);
	return EXIT_SUCCESS;
error:
	free(ts);
	return EXIT_FAILURE;
}
