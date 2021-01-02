/*
 * Modsecurity wrapper for haproxy
 *
 * This file contains the bootstrap for launching and scheduling modsecurity
 * for working with HAProxy SPOE protocol.
 *
 * Copyright 2016 OZON, Thierry Fournier <thierry.fournier@ozon.io>
 *
 * This file is inherited from "A Random IP reputation service acting as a Stream
 * Processing Offload Agent"
 *
 * Copyright 2016 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <err.h>
#include <ctype.h>

#include <pthread.h>

#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/thread.h>

#include <haproxy/chunk.h>
#include <haproxy/list.h>
#include <haproxy/spoe.h>

#include "spoa.h"
#include "modsec_wrapper.h"

#define DEFAULT_PORT       12345
#define CONNECTION_BACKLOG 10
#define NUM_WORKERS        10
#define MAX_FRAME_SIZE     16384
#define SPOP_VERSION       "2.0"

#define SLEN(str) (sizeof(str)-1)

#define DEBUG(x...)				\
	do {					\
		if (debug)			\
			LOG(x);			\
	} while (0)


enum spoa_state {
	SPOA_ST_CONNECTING = 0,
	SPOA_ST_PROCESSING,
	SPOA_ST_DISCONNECTING,
};

enum spoa_frame_type {
	SPOA_FRM_T_UNKNOWN = 0,
	SPOA_FRM_T_HAPROXY,
	SPOA_FRM_T_AGENT,
};

struct spoe_engine {
	char       *id;

	struct list processing_frames;
	struct list outgoing_frames;

	struct list clients;
	struct list list;
};

struct spoe_frame {
	enum spoa_frame_type type;
	char                *buf;
	unsigned int         offset;
	unsigned int         len;

	unsigned int         stream_id;
	unsigned int         frame_id;
	unsigned int         flags;
	bool                 hcheck;     /* true is the CONNECT frame is a healthcheck */
	bool                 fragmented; /* true if the frame is fragmented */
	int                  modsec_code;  /* modsecurity return code. -1 if unset, 0 if none, other it returns http code. */

	struct event         process_frame_event;
	struct worker       *worker;
	struct spoe_engine  *engine;
	struct client       *client;
	struct list          list;

	char                *frag_buf; /* used to accumulate payload of a fragmented frame */
	unsigned int         frag_len;

	char                 data[0];
};

struct client {
	int                 fd;
	unsigned long       id;
	enum spoa_state     state;

	struct event        read_frame_event;
	struct event        write_frame_event;

	struct spoe_frame  *incoming_frame;
	struct spoe_frame  *outgoing_frame;

	struct list         processing_frames;
	struct list         outgoing_frames;

	unsigned int        max_frame_size;
	int                 status_code;

	char               *engine_id;
	struct spoe_engine *engine;
	bool                pipelining;
	bool                async;
	bool                fragmentation;

	struct worker      *worker;
	struct list         by_worker;
	struct list         by_engine;
};

/* Globals */
static struct worker *workers          = NULL;
 struct worker  null_worker            = { .id = 0 };
static unsigned long  clicount         = 0;
static int            server_port      = DEFAULT_PORT;
static int            num_workers      = NUM_WORKERS;
static unsigned int   max_frame_size   = MAX_FRAME_SIZE;
struct timeval        processing_delay = {0, 0};
static bool           debug            = false;
static bool           pipelining       = false;
static bool           async            = false;
static bool           fragmentation    = false;


static const char *spoe_frm_err_reasons[SPOE_FRM_ERRS] = {
	[SPOE_FRM_ERR_NONE]               = "normal",
	[SPOE_FRM_ERR_IO]                 = "I/O error",
	[SPOE_FRM_ERR_TOUT]               = "a timeout occurred",
	[SPOE_FRM_ERR_TOO_BIG]            = "frame is too big",
	[SPOE_FRM_ERR_INVALID]            = "invalid frame received",
	[SPOE_FRM_ERR_NO_VSN]             = "version value not found",
	[SPOE_FRM_ERR_NO_FRAME_SIZE]      = "max-frame-size value not found",
	[SPOE_FRM_ERR_NO_CAP]             = "capabilities value not found",
	[SPOE_FRM_ERR_BAD_VSN]            = "unsupported version",
	[SPOE_FRM_ERR_BAD_FRAME_SIZE]     = "max-frame-size too big or too small",
	[SPOE_FRM_ERR_FRAG_NOT_SUPPORTED] = "fragmentation not supported",
	[SPOE_FRM_ERR_INTERLACED_FRAMES]  = "invalid interlaced frames",
	[SPOE_FRM_ERR_FRAMEID_NOTFOUND]   = "frame-id not found",
	[SPOE_FRM_ERR_RES]                = "resource allocation error",
	[SPOE_FRM_ERR_UNKNOWN]            = "an unknown error occurred",
};

static void signal_cb(evutil_socket_t, short, void *);
static void accept_cb(evutil_socket_t, short, void *);
static void worker_monitor_cb(evutil_socket_t, short, void *);
static void process_frame_cb(evutil_socket_t, short, void *);
static void read_frame_cb(evutil_socket_t, short, void *);
static void write_frame_cb(evutil_socket_t, short, void *);

static void use_spoe_engine(struct client *);
static void unuse_spoe_engine(struct client *);
static void release_frame(struct spoe_frame *);
static void release_client(struct client *);

/* Check the protocol version. It returns -1 if an error occurred, the number of
 * read bytes otherwise. */
static int
check_proto_version(struct spoe_frame *frame, char **buf, char *end)
{
	char      *str, *p = *buf;
	uint64_t   sz;
	int        ret;

	/* Get the list of all supported versions by HAProxy */
	if ((*p++ & SPOE_DATA_T_MASK) != SPOE_DATA_T_STR)
		return -1;
	ret = spoe_decode_buffer(&p, end, &str, &sz);
	if (ret == -1 || !str)
		return -1;

	DEBUG(frame->worker, "<%lu> Supported versions : %.*s",
	      frame->client->id, (int)sz, str);

	/* TODO: Find the right version in supported ones */

	ret  = (p - *buf);
	*buf = p;
	return ret;
}

/* Check max frame size value. It returns -1 if an error occurred, the number of
 * read bytes otherwise. */
static int
check_max_frame_size(struct spoe_frame *frame, char **buf, char *end)
{
	char    *p = *buf;
	uint64_t sz;
	int      type, ret;

	/* Get the max-frame-size value of HAProxy */
	type =  *p++;
	if ((type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT32  &&
	    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT64  &&
	    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT32 &&
	    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT64)
		return -1;
	if (decode_varint(&p, end, &sz) == -1)
		return -1;

	/* Keep the lower value */
	if (sz < frame->client->max_frame_size)
		frame->client->max_frame_size = sz;

	DEBUG(frame->worker, "<%lu> HAProxy maximum frame size : %u",
	      frame->client->id, (unsigned int)sz);

	ret  = (p - *buf);
	*buf = p;
	return ret;
}

/* Check healthcheck value. It returns -1 if an error occurred, the number of
 * read bytes otherwise. */
static int
check_healthcheck(struct spoe_frame *frame, char **buf, char *end)
{
	char *p = *buf;
	int   type, ret;

	/* Get the "healthcheck" value */
	type = *p++;
	if ((type & SPOE_DATA_T_MASK) != SPOE_DATA_T_BOOL)
		return -1;
	frame->hcheck = ((type & SPOE_DATA_FL_TRUE) == SPOE_DATA_FL_TRUE);

	DEBUG(frame->worker, "<%lu> HELLO healthcheck : %s",
	      frame->client->id, (frame->hcheck ? "true" : "false"));

	ret  = (p - *buf);
	*buf = p;
	return ret;
}

/* Check capabilities value. It returns -1 if an error occurred, the number of
 * read bytes otherwise. */
static int
check_capabilities(struct spoe_frame *frame, char **buf, char *end)
{
	struct client *client = frame->client;
	char          *str, *p = *buf;
	uint64_t       sz;
	int            ret;

	if ((*p++ & SPOE_DATA_T_MASK) != SPOE_DATA_T_STR)
		return -1;
	if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
		return -1;
	if (str == NULL) /* this is not an error */
		goto end;

	DEBUG(frame->worker, "<%lu> HAProxy capabilities : %.*s",
	      client->id, (int)sz, str);

	while (sz) {
		char *delim;

		/* Skip leading spaces */
		for (; isspace(*str) && sz; sz--);

		if (sz >= 10 && !strncmp(str, "pipelining", 10)) {
			str += 10; sz -= 10;
			if (!sz || isspace(*str) || *str == ',') {
				DEBUG(frame->worker,
				      "<%lu> HAProxy supports frame pipelining",
				      client->id);
				client->pipelining = true;
			}
		}
		else if (sz >= 5 && !strncmp(str, "async", 5)) {
			str += 5; sz -= 5;
			if (!sz || isspace(*str) || *str == ',') {
				DEBUG(frame->worker,
				      "<%lu> HAProxy supports asynchronous frame",
				      client->id);
				client->async = true;
			}
		}
		else if (sz >= 13 && !strncmp(str, "fragmentation", 13)) {
			str += 13; sz -= 13;
			if (!sz || isspace(*str) || *str == ',') {
				DEBUG(frame->worker,
				      "<%lu> HAProxy supports fragmented frame",
				      client->id);
				client->fragmentation = true;
			}
		}

		if (!sz || (delim = memchr(str, ',', sz)) == NULL)
			break;
		delim++;
		sz -= (delim - str);
		str = delim;
	}
  end:
	ret  = (p - *buf);
	*buf = p;
	return ret;
}

/* Check engine-id value. It returns -1 if an error occurred, the number of
 * read bytes otherwise. */
static int
check_engine_id(struct spoe_frame *frame, char **buf, char *end)
{
	struct client *client = frame->client;
	char          *str, *p = *buf;
	uint64_t       sz;
	int            ret;

	if ((*p++ & SPOE_DATA_T_MASK) != SPOE_DATA_T_STR)
		return -1;

	if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
		return -1;
	if (str == NULL) /* this is not an error */
		goto end;

	if (client->engine != NULL)
		goto end;

	DEBUG(frame->worker, "<%lu> HAProxy engine id : %.*s",
	      client->id, (int)sz, str);

	client->engine_id = strndup(str, (int)sz);
  end:
	ret  = (p - *buf);
	*buf = p;
	return ret;
}

static int
acc_payload(struct spoe_frame *frame)
{
	struct client *client = frame->client;
	char          *buf;
	size_t         len = frame->len - frame->offset;
	int            ret = frame->offset;

	/* No need to accumulation payload */
	if (frame->fragmented == false)
		return ret;

	buf = realloc(frame->frag_buf, frame->frag_len + len);
	if (buf == NULL) {
		client->status_code = SPOE_FRM_ERR_RES;
		return -1;
	}
	memcpy(buf + frame->frag_len, frame->buf + frame->offset, len);
	frame->frag_buf  = buf;
	frame->frag_len += len;

	if (!(frame->flags & SPOE_FRM_FL_FIN)) {
		/* Wait for next parts */
		frame->buf    = (char *)(frame->data);
		frame->offset = 0;
		frame->len    = 0;
		frame->flags  = 0;
		return 1;
	}

	frame->buf    = frame->frag_buf;
	frame->len    = frame->frag_len;
	frame->offset = 0;
	return ret;
}

/* Check disconnect status code. It returns -1 if an error occurred, the number
 * of read bytes otherwise. */
static int
check_discon_status_code(struct spoe_frame *frame, char **buf, char *end)
{
	char    *p = *buf;
	uint64_t sz;
	int      type, ret;

	/* Get the "status-code" value */
	type =  *p++;
	if ((type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT32 &&
	    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_INT64 &&
	    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT32 &&
	    (type & SPOE_DATA_T_MASK) != SPOE_DATA_T_UINT64)
		return -1;
	if (decode_varint(&p, end, &sz) == -1)
		return -1;

	frame->client->status_code = (unsigned int)sz;

	DEBUG(frame->worker, "<%lu> Disconnect status code : %u",
	      frame->client->id, frame->client->status_code);

	ret  = (p - *buf);
	*buf = p;
	return ret;
}

/* Check the disconnect message. It returns -1 if an error occurred, the number
 * of read bytes otherwise. */
static int
check_discon_message(struct spoe_frame *frame, char **buf, char *end)
{
	char    *str, *p = *buf;
	uint64_t sz;
	int      ret;

	/* Get the "message" value */
	if ((*p++ & SPOE_DATA_T_MASK) != SPOE_DATA_T_STR)
		return -1;
	ret = spoe_decode_buffer(&p, end, &str, &sz);
	if (ret == -1 || !str)
		return -1;

	DEBUG(frame->worker, "<%lu> Disconnect message : %.*s",
	      frame->client->id, (int)sz, str);

	ret  = (p - *buf);
	*buf = p;
	return ret;
}



/* Decode a HELLO frame received from HAProxy. It returns -1 if an error
 * occurred, otherwise the number of read bytes. HELLO frame cannot be
 * ignored and having another frame than a HELLO frame is an error. */
static int
handle_hahello(struct spoe_frame *frame)
{
	struct client *client = frame->client;
	char          *p, *end;

	p = frame->buf;
	end = frame->buf + frame->len;

	/* Check frame type: we really want a HELLO frame */
	if (*p++ != SPOE_FRM_T_HAPROXY_HELLO)
		goto error;

	DEBUG(frame->worker, "<%lu> Decode HAProxy HELLO frame", client->id);

	/* Retrieve flags */
	memcpy((char *)&(frame->flags), p, 4);
	frame->flags = ntohl(frame->flags);
	p += 4;

	/* Fragmentation is not supported for HELLO frame */
	if (!(frame->flags & SPOE_FRM_FL_FIN)) {
		client->status_code = SPOE_FRM_ERR_FRAG_NOT_SUPPORTED;
		goto error;
	}

	/* stream-id and frame-id must be cleared */
	if (*p != 0 || *(p+1) != 0) {
		client->status_code = SPOE_FRM_ERR_INVALID;
		goto error;
	}
	p += 2;

	/* Loop on K/V items */
	while (p < end) {
		char     *str;
		uint64_t  sz;

		/* Decode the item name */
		spoe_decode_buffer(&p, end, &str, &sz);
		if (!str) {
			client->status_code = SPOE_FRM_ERR_INVALID;
			goto error;
		}

		/* Check "supported-versions" K/V item */
		if (!memcmp(str, "supported-versions", sz)) {
			if (check_proto_version(frame, &p, end)  == -1) {
				client->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
		/* Check "max-frame-size" K/V item */
		else if (!memcmp(str, "max-frame-size", sz)) {
			if (check_max_frame_size(frame, &p, end) == -1) {
				client->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
		/* Check "healthcheck" K/V item */
		else if (!memcmp(str, "healthcheck", sz)) {
			if (check_healthcheck(frame, &p, end) == -1) {
				client->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
		/* Check "capabilities" K/V item */
		else if (!memcmp(str, "capabilities", sz)) {
			if (check_capabilities(frame, &p, end) == -1) {
				client->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
		/* Check "engine-id" K/V item */
		else if (!memcmp(str, "engine-id", sz)) {
			if (check_engine_id(frame, &p, end) == -1) {
				client->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
		else {
			DEBUG(frame->worker, "<%lu> Skip K/V item : key=%.*s",
			      client->id, (int)sz, str);

			/* Silently ignore unknown item */
			if (spoe_skip_data(&p, end) == -1) {
				client->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
	}

	if (async == false || client->engine_id == NULL)
		client->async = false;
	if (pipelining == false)
		client->pipelining = false;

	if (client->async == true)
		use_spoe_engine(client);

	return (p - frame->buf);
  error:
	return -1;
}

/* Decode a DISCONNECT frame received from HAProxy. It returns -1 if an error
 * occurred, otherwise the number of read bytes. DISCONNECT frame cannot be
 * ignored and having another frame than a DISCONNECT frame is an error.*/
static int
handle_hadiscon(struct spoe_frame *frame)
{
	struct client *client = frame->client;
	char          *p, *end;

	p = frame->buf;
	end = frame->buf + frame->len;

	/* Check frame type: we really want a DISCONNECT frame */
	if (*p++ != SPOE_FRM_T_HAPROXY_DISCON)
		goto error;

	DEBUG(frame->worker, "<%lu> Decode HAProxy DISCONNECT frame", client->id);

	/* Retrieve flags */
	memcpy((char *)&(frame->flags), p, 4);
	frame->flags = ntohl(frame->flags);
	p += 4;

	/* Fragmentation is not supported for DISCONNECT frame */
	if (!(frame->flags & SPOE_FRM_FL_FIN)) {
		client->status_code = SPOE_FRM_ERR_FRAG_NOT_SUPPORTED;
		goto error;
	}

	/* stream-id and frame-id must be cleared */
	if (*p != 0 || *(p+1) != 0) {
		client->status_code = SPOE_FRM_ERR_INVALID;
		goto error;
	}
	p += 2;

	client->status_code = SPOE_FRM_ERR_NONE;

	/* Loop on K/V items */
	while (p < end) {
		char     *str;
		uint64_t  sz;

		/* Decode item key */
		spoe_decode_buffer(&p, end, &str, &sz);
		if (!str) {
			client->status_code = SPOE_FRM_ERR_INVALID;
			goto error;
		}

		/* Check "status-code" K/V item */
		if (!memcmp(str, "status-code", sz)) {
			if (check_discon_status_code(frame, &p, end) == -1) {
				client->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
		/* Check "message" K/V item */
		else if (!memcmp(str, "message", sz)) {
			if (check_discon_message(frame, &p, end) == -1) {
				client->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
		else {
			DEBUG(frame->worker, "<%lu> Skip K/V item : key=%.*s",
			      client->id, (int)sz, str);

			/* Silently ignore unknown item */
			if (spoe_skip_data(&p, end) == -1) {
				client->status_code = SPOE_FRM_ERR_INVALID;
				goto error;
			}
		}
	}

	return (p - frame->buf);
  error:
	return -1;
}

/* Decode a NOTIFY frame received from HAProxy. It returns -1 if an error
 * occurred, 0 if it must be must be ignored, otherwise the number of read
 * bytes. */
static int
handle_hanotify(struct spoe_frame *frame)
{
	struct client *client = frame->client;
	char          *p, *end;
	uint64_t       stream_id, frame_id;

	p = frame->buf;
	end = frame->buf + frame->len;

	/* Check frame type */
	if (*p++ != SPOE_FRM_T_HAPROXY_NOTIFY)
		goto ignore;

	DEBUG(frame->worker, "<%lu> Decode HAProxy NOTIFY frame", client->id);

	/* Retrieve flags */
	memcpy((char *)&(frame->flags), p, 4);
	frame->flags = ntohl(frame->flags);
	p += 4;

	/* Fragmentation is not supported */
	if (!(frame->flags & SPOE_FRM_FL_FIN) && fragmentation == false) {
		client->status_code = SPOE_FRM_ERR_FRAG_NOT_SUPPORTED;
		goto error;
	}

	/* Read the stream-id and frame-id */
	if (decode_varint(&p, end, &stream_id) == -1)
		goto ignore;
	if (decode_varint(&p, end, &frame_id) == -1)
		goto ignore;

	frame->stream_id = (unsigned int)stream_id;
	frame->frame_id  = (unsigned int)frame_id;

	DEBUG(frame->worker, "<%lu> STREAM-ID=%u - FRAME-ID=%u"
	      " - %s frame received"
	      " - frag_len=%u - len=%u - offset=%ld",
	      client->id, frame->stream_id, frame->frame_id,
	      (frame->flags & SPOE_FRM_FL_FIN) ? "unfragmented" : "fragmented",
	      frame->frag_len, frame->len, p - frame->buf);

	frame->fragmented = !(frame->flags & SPOE_FRM_FL_FIN);
	frame->offset = (p - frame->buf);
	return acc_payload(frame);

  ignore:
	return 0;

  error:
	return -1;
}

/* Decode next part of a fragmented frame received from HAProxy. It returns -1
 * if an error occurred, 0 if it must be must be ignored, otherwise the number
 * of read bytes. */
static int
handle_hafrag(struct spoe_frame *frame)
{
	struct client *client = frame->client;
	char          *p, *end;
	uint64_t       stream_id, frame_id;

	p = frame->buf;
	end = frame->buf + frame->len;

	/* Check frame type */
	if (*p++ != SPOE_FRM_T_UNSET)
		goto ignore;

	DEBUG(frame->worker, "<%lu> Decode Next part of a fragmented frame", client->id);

	/* Fragmentation is not supported */
	if (fragmentation == false) {
		client->status_code = SPOE_FRM_ERR_FRAG_NOT_SUPPORTED;
		goto error;
	}

	/* Retrieve flags */
	memcpy((char *)&(frame->flags), p, 4);
	frame->flags = ntohl(frame->flags);
	p+= 4;

	/* Read the stream-id and frame-id */
	if (decode_varint(&p, end, &stream_id) == -1)
		goto ignore;
	if (decode_varint(&p, end, &frame_id) == -1)
		goto ignore;

	if (frame->fragmented == false                  ||
	    frame->stream_id != (unsigned int)stream_id ||
	    frame->frame_id  != (unsigned int)frame_id) {
		client->status_code = SPOE_FRM_ERR_INTERLACED_FRAMES;
		goto error;
	}

	if (frame->flags & SPOE_FRM_FL_ABRT) {
		DEBUG(frame->worker, "<%lu> STREAM-ID=%u - FRAME-ID=%u"
		      " - Abort processing of a fragmented frame"
		      " - frag_len=%u - len=%u - offset=%ld",
		      client->id, frame->stream_id, frame->frame_id,
		      frame->frag_len, frame->len, p - frame->buf);
		goto ignore;
	}

	DEBUG(frame->worker, "<%lu> STREAM-ID=%u - FRAME-ID=%u"
	      " - %s fragment of a fragmented frame received"
	      " - frag_len=%u - len=%u - offset=%ld",
	      client->id, frame->stream_id, frame->frame_id,
	      (frame->flags & SPOE_FRM_FL_FIN) ? "last" : "next",
	      frame->frag_len, frame->len, p - frame->buf);

	frame->offset = (p - frame->buf);
	return acc_payload(frame);

  ignore:
	return 0;

  error:
	return -1;
}

/* Encode a HELLO frame to send it to HAProxy. It returns the number of written
 * bytes. */
static int
prepare_agenthello(struct spoe_frame *frame)
{
	struct client *client = frame->client;
	char          *p, *end;
	char           capabilities[64];
	int            n;
	unsigned int   flags  = SPOE_FRM_FL_FIN;

	DEBUG(frame->worker, "<%lu> Encode Agent HELLO frame", client->id);
	frame->type = SPOA_FRM_T_AGENT;

	p   = frame->buf;
	end = frame->buf+max_frame_size;

	/* Frame Type */
	*p++ = SPOE_FRM_T_AGENT_HELLO;

	/* Set flags */
	flags = htonl(flags);
	memcpy(p, (char *)&flags, 4);
	p += 4;

	/* No stream-id and frame-id for HELLO frames */
	*p++ = 0;
	*p++ = 0;

	/* "version" K/V item */
	spoe_encode_buffer("version", 7, &p, end);
	*p++ = SPOE_DATA_T_STR;
	spoe_encode_buffer(SPOP_VERSION, SLEN(SPOP_VERSION), &p, end);
	DEBUG(frame->worker, "<%lu> Agent version : %s",
	      client->id, SPOP_VERSION);


	/* "max-frame-size" K/V item */
	spoe_encode_buffer("max-frame-size", 14, &p ,end);
	*p++ = SPOE_DATA_T_UINT32;
	encode_varint(client->max_frame_size, &p, end);
	DEBUG(frame->worker, "<%lu> Agent maximum frame size : %u",
	      client->id, client->max_frame_size);

	/* "capabilities" K/V item */
	spoe_encode_buffer("capabilities", 12, &p, end);
	*p++ = SPOE_DATA_T_STR;

	memset(capabilities, 0, sizeof(capabilities));
	n = 0;

	/*     1. Fragmentation capability ? */
	if (fragmentation == true) {
		memcpy(capabilities, "fragmentation", 13);
		n += 13;
	}
	/*     2. Pipelining capability ? */
	if (client->pipelining == true) {
		if (n) capabilities[n++] = ',';
		memcpy(capabilities + n, "pipelining", 10);
		n += 10;
	}
	/*     3. Async capability ? */
	if (client->async == true) {
		if (n) capabilities[n++] = ',';
		memcpy(capabilities + n, "async", 5);
		n += 5;
	}
	spoe_encode_buffer(capabilities, n, &p, end);

	DEBUG(frame->worker, "<%lu> Agent capabilities : %.*s",
	      client->id, n, capabilities);

	frame->len = (p - frame->buf);
	return frame->len;
}

/* Encode a DISCONNECT frame to send it to HAProxy. It returns the number of
 * written bytes. */
static int
prepare_agentdicon(struct spoe_frame *frame)
{
	struct client *client = frame->client;
	char           *p, *end;
	const char     *reason;
	int             rlen;
	unsigned int    flags  = SPOE_FRM_FL_FIN;

	DEBUG(frame->worker, "<%lu> Encode Agent DISCONNECT frame", client->id);
	frame->type = SPOA_FRM_T_AGENT;

	p   = frame->buf;
	end = frame->buf+max_frame_size;

	if (client->status_code >= SPOE_FRM_ERRS)
		client->status_code = SPOE_FRM_ERR_UNKNOWN;
	reason = spoe_frm_err_reasons[client->status_code];
	rlen   = strlen(reason);

	/* Frame type */
	*p++ = SPOE_FRM_T_AGENT_DISCON;

	/* Set flags */
	flags = htonl(flags);
	memcpy(p, (char *)&flags, 4);
	p += 4;

	/* No stream-id and frame-id for DISCONNECT frames */
	*p++ = 0;
	*p++ = 0;

	/* There are 2 mandatory items: "status-code" and "message" */

	/* "status-code" K/V item */
	spoe_encode_buffer("status-code", 11, &p, end);
	*p++ = SPOE_DATA_T_UINT32;
	encode_varint(client->status_code, &p, end);
	DEBUG(frame->worker, "<%lu> Disconnect status code : %u",
	      client->id, client->status_code);

	/* "message" K/V item */
	spoe_encode_buffer("message", 7, &p, end);
	*p++ = SPOE_DATA_T_STR;
	spoe_encode_buffer(reason, rlen, &p, end);
	DEBUG(frame->worker, "<%lu> Disconnect message : %s",
	      client->id, reason);

	frame->len = (p - frame->buf);
	return frame->len;
}

/* Encode a ACK frame to send it to HAProxy. It returns the number of written
 * bytes. */
static int
prepare_agentack(struct spoe_frame *frame)
{
	char        *p, *end;
	unsigned int flags  = SPOE_FRM_FL_FIN;

	/* Be careful here, in async mode, frame->client can be NULL */

	DEBUG(frame->worker, "Encode Agent ACK frame");
	frame->type = SPOA_FRM_T_AGENT;

	p   = frame->buf;
	end = frame->buf+max_frame_size;

	/* Frame type */
	*p++ = SPOE_FRM_T_AGENT_ACK;

	/* Set flags */
	flags = htonl(flags);
	memcpy(p, (char *)&flags, 4);
	p += 4;

	/* Set stream-id and frame-id for ACK frames */
	encode_varint(frame->stream_id, &p, end);
	encode_varint(frame->frame_id, &p, end);

	DEBUG(frame->worker, "STREAM-ID=%u - FRAME-ID=%u",
	      frame->stream_id, frame->frame_id);

	frame->len = (p - frame->buf);
	return frame->len;
}

static int
create_server_socket(void)
{
	struct sockaddr_in listen_addr;
	int                fd, yes = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		LOG(&null_worker, "Failed to create service socket : %m");
		return -1;
	}

	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = INADDR_ANY;
	listen_addr.sin_port = htons(server_port);

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0 ||
	    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) < 0) {
		LOG(&null_worker, "Failed to set option on server socket : %m");
		return -1;
	}

	if (bind(fd, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
		LOG(&null_worker, "Failed to bind server socket : %m");
		return -1;
	}

	if (listen(fd, CONNECTION_BACKLOG) < 0) {
		LOG(&null_worker, "Failed to listen on server socket : %m");
		return -1;
	}

	return fd;
}

static void
release_frame(struct spoe_frame *frame)
{
	struct worker *worker;

	if (frame == NULL)
		return;

	if (event_pending(&frame->process_frame_event, EV_TIMEOUT, NULL))
		event_del(&frame->process_frame_event);

	worker = frame->worker;
	LIST_DEL(&frame->list);
	if (frame->frag_buf)
		free(frame->frag_buf);
	memset(frame, 0, sizeof(*frame)+max_frame_size+4);
	LIST_ADDQ(&worker->frames, &frame->list);
}

static void
release_client(struct client *c)
{
	struct spoe_frame *frame, *back;

	if (c == NULL)
		return;

	DEBUG(c->worker, "<%lu> Release client", c->id);

	LIST_DEL(&c->by_worker);
	c->worker->nbclients--;

	unuse_spoe_engine(c);
	free(c->engine_id);

	if (event_pending(&c->read_frame_event, EV_READ, NULL))
		event_del(&c->read_frame_event);
	if (event_pending(&c->write_frame_event, EV_WRITE, NULL))
		event_del(&c->write_frame_event);

	release_frame(c->incoming_frame);
	release_frame(c->outgoing_frame);
	list_for_each_entry_safe(frame, back, &c->processing_frames, list) {
		release_frame(frame);
	}
	list_for_each_entry_safe(frame, back, &c->outgoing_frames, list) {
		release_frame(frame);
	}

	if (c->fd >= 0)
		close(c->fd);

	free(c);
}

static void
reset_frame(struct spoe_frame *frame)
{
	if (frame == NULL)
		return;

	if (frame->frag_buf)
		free(frame->frag_buf);

	frame->type        = SPOA_FRM_T_UNKNOWN;
	frame->buf         = (char *)(frame->data);
	frame->offset      = 0;
	frame->len         = 0;
	frame->stream_id   = 0;
	frame->frame_id    = 0;
	frame->flags       = 0;
	frame->hcheck      = false;
	frame->fragmented  = false;
	frame->modsec_code = -1;
	frame->frag_buf    = NULL;
	frame->frag_len    = 0;
	LIST_INIT(&frame->list);
}

static void
use_spoe_engine(struct client *client)
{
	struct spoe_engine *eng;

	if (client->engine_id == NULL)
		return;

	list_for_each_entry(eng, &client->worker->engines, list) {
		if (strcmp(eng->id, client->engine_id) == 0)
			goto end;
	}

	if ((eng = malloc(sizeof(*eng))) == NULL) {
		client->async = false;
		return;
	}

	eng->id = strdup(client->engine_id);
	LIST_INIT(&eng->clients);
	LIST_INIT(&eng->processing_frames);
	LIST_INIT(&eng->outgoing_frames);
	LIST_ADDQ(&client->worker->engines, &eng->list);
	LOG(client->worker, "Add new SPOE engine '%s'", eng->id);

  end:
	client->engine = eng;
	LIST_ADDQ(&eng->clients, &client->by_engine);
}

static void
unuse_spoe_engine(struct client *client)
{
	struct spoe_engine *eng;
	struct spoe_frame  *frame, *back;

	if (client == NULL || client->engine == NULL)
		return;

	eng = client->engine;
	client->engine = NULL;
	LIST_DEL(&client->by_engine);
	if (!LIST_ISEMPTY(&eng->clients))
		return;

	LOG(client->worker, "Remove SPOE engine '%s'", eng->id);
	LIST_DEL(&eng->list);

	list_for_each_entry_safe(frame, back, &eng->processing_frames, list) {
		release_frame(frame);
	}
	list_for_each_entry_safe(frame, back, &eng->outgoing_frames, list) {
		release_frame(frame);
	}
	free(eng->id);
	free(eng);
}


static struct spoe_frame *
acquire_incoming_frame(struct client *client)
{
	struct spoe_frame *frame;

	frame = client->incoming_frame;
	if (frame != NULL)
		return frame;

	if (LIST_ISEMPTY(&client->worker->frames)) {
		if ((frame = calloc(1, sizeof(*frame)+max_frame_size+4)) == NULL) {
			LOG(client->worker, "Failed to allocate new frame : %m");
			return NULL;
		}
	}
	else {
		frame = LIST_NEXT(&client->worker->frames, typeof(frame), list);
		LIST_DEL(&frame->list);
	}

	reset_frame(frame);
	frame->worker = client->worker;
	frame->engine = client->engine;
	frame->client = client;

	if (event_assign(&frame->process_frame_event, client->worker->base, -1,
			 EV_TIMEOUT|EV_PERSIST, process_frame_cb, frame) < 0) {
		LOG(client->worker, "Failed to create frame event");
		return NULL;
	}

	client->incoming_frame = frame;
	return frame;
}

static struct spoe_frame *
acquire_outgoing_frame(struct client *client)
{
	struct spoe_engine *engine = client->engine;
	struct spoe_frame  *frame = NULL;

	if (client->outgoing_frame != NULL)
		frame = client->outgoing_frame;
	else if (!LIST_ISEMPTY(&client->outgoing_frames)) {
		frame = LIST_NEXT(&client->outgoing_frames, typeof(frame), list);
		LIST_DEL(&frame->list);
		client->outgoing_frame = frame;
	}
	else if (engine!= NULL && !LIST_ISEMPTY(&engine->outgoing_frames)) {
		frame = LIST_NEXT(&engine->outgoing_frames, typeof(frame), list);
		LIST_DEL(&frame->list);
		client->outgoing_frame = frame;
	}
	return frame;
}

static void
write_frame(struct client *client, struct spoe_frame *frame)
{
	uint32_t netint;

	LIST_DEL(&frame->list);

	frame->buf    = (char *)(frame->data);
	frame->offset = 0;
	netint        = htonl(frame->len);
	memcpy(frame->buf, &netint, 4);

	if (client != NULL) { /* HELLO or DISCONNECT frames */
		event_add(&client->write_frame_event, NULL);

		/* Try to process the frame as soon as possible, and always
		 * attach it to the client */
		if (client->async || client->pipelining) {
			if (client->outgoing_frame == NULL)
				client->outgoing_frame = frame;
			else
				LIST_ADD(&client->outgoing_frames, &frame->list);
		}
		else {
			client->outgoing_frame = frame;
			event_del(&client->read_frame_event);
		}
	}
	else { /* for all other frames */
		if (frame->client == NULL) { /* async mode ! */
			LIST_ADDQ(&frame->engine->outgoing_frames, &frame->list);
			list_for_each_entry(client, &frame->engine->clients, by_engine)
				event_add(&client->write_frame_event, NULL);
		}
		else if (frame->client->pipelining) {
			LIST_ADDQ(&frame->client->outgoing_frames, &frame->list);
			event_add(&frame->client->write_frame_event, NULL);
		}
		else {
			frame->client->outgoing_frame = frame;
			event_add(&frame->client->write_frame_event, NULL);
			event_del(&frame->client->read_frame_event);
		}
	}
}

static void
process_incoming_frame(struct spoe_frame *frame)
{
	struct client *client = frame->client;

	if (event_add(&frame->process_frame_event, &processing_delay) < 0) {
		LOG(client->worker, "Failed to process incoming frame");
		release_frame(frame);
		return;
	}

	if (client->async) {
		frame->client = NULL;
		LIST_ADDQ(&frame->engine->processing_frames, &frame->list);
	}
	else if (client->pipelining)
		LIST_ADDQ(&client->processing_frames, &frame->list);
	else
		event_del(&client->read_frame_event);
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data)
{
	struct event_base *base = user_data;
	int                i;

	DEBUG(&null_worker, "Stopping the server");

	event_base_loopbreak(base);
	DEBUG(&null_worker, "Main event loop stopped");

	for (i = 0; i < num_workers; i++) {
		event_base_loopbreak(workers[i].base);
		DEBUG(&null_worker, "Event loop stopped for worker %02d",
		      workers[i].id);
	}
}

static void
worker_monitor_cb(evutil_socket_t fd, short events, void *arg)
{
	struct worker *worker = arg;

	LOG(worker, "%u clients connected", worker->nbclients);
}

static void
process_frame_cb(evutil_socket_t fd, short events, void *arg)
{
	struct spoe_frame *frame  = arg;
	char              *p, *end;
	int                ret;

	DEBUG(frame->worker,
	      "Process frame messages : STREAM-ID=%u - FRAME-ID=%u - length=%u bytes",
	      frame->stream_id, frame->frame_id, frame->len - frame->offset);

	p   = frame->buf + frame->offset;
	end = frame->buf + frame->len;

	/* Loop on messages */
	while (p < end) {
		char    *str;
		uint64_t sz;
		int      nbargs;

		/* Decode the message name */
		spoe_decode_buffer(&p, end, &str, &sz);
		if (!str)
			goto stop_processing;

		DEBUG(frame->worker, "Process SPOE Message '%.*s'", (int)sz, str);

		nbargs = *p++;                     /* Get the number of arguments */
		frame->offset = (p - frame->buf);  /* Save index to handle errors and skip args */
		if (!memcmp(str, "check-request", sz)) {
			struct modsecurity_parameters params;

			memset(&params, 0, sizeof(params));

			if (nbargs != 8)
				goto skip_message;

			/* Decode parameter name. */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				goto stop_processing;

			/* Decode unique id. */
			if (spoe_decode_data(&p, end, &params.uniqueid) == -1)
				goto skip_message;

			/* Decode parameter name. */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				goto stop_processing;

			/* Decode method. */
			if (spoe_decode_data(&p, end, &params.method) == -1)
				goto skip_message;

			/* Decode parameter name. */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				goto stop_processing;

			/* Decode path. */
			if (spoe_decode_data(&p, end, &params.path) == -1)
				goto skip_message;

			/* Decode parameter name. */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				goto stop_processing;

			/* Decode query. */
			if (spoe_decode_data(&p, end, &params.query) == -1)
				goto skip_message;

			/* Decode parameter name. */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				goto stop_processing;

			/* Decode protocol version. */
			if (spoe_decode_data(&p, end, &params.vers) == -1)
				goto skip_message;

			/* Decode parameter name. */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				goto stop_processing;

			/* Decode hdrs. */
			if (spoe_decode_data(&p, end, &params.hdrs_bin) == -1)
				goto skip_message;

			/* Decode parameter name. */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				goto stop_processing;

			/* Decode body length. */
			if (spoe_decode_data(&p, end, &params.body_length) == -1)
				goto skip_message;

			/* Decode parameter name. */
			if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
				goto stop_processing;

			/* Decode body. */
			if (spoe_decode_data(&p, end, &params.body) == -1)
				goto skip_message;

			frame->modsec_code = modsecurity_process(frame->worker, &params);
		}
		else {
		  skip_message:
			p = frame->buf + frame->offset; /* Restore index */

			while (nbargs-- > 0) {
				/* Silently ignore argument: its name and its value */
				if (spoe_decode_buffer(&p, end, &str, &sz) == -1)
					goto stop_processing;
				if (spoe_skip_data(&p, end) == -1)
					goto stop_processing;
			}
		}
	}

  stop_processing:
	/* Prepare agent ACK frame */
	frame->buf    = (char *)(frame->data) + 4;
	frame->offset = 0;
	frame->len    = 0;
	frame->flags  = 0;

	ret = prepare_agentack(frame);
	p   = frame->buf + ret;
	end = frame->buf+max_frame_size;

	if (frame->modsec_code != -1) {
		DEBUG(frame->worker, "Add action : set variable code=%u",
		      frame->modsec_code);

		*p++ = SPOE_ACT_T_SET_VAR;                     /* Action type */
		*p++ = 3;                                      /* Number of args */
		*p++ = SPOE_SCOPE_TXN;                         /* Arg 1: the scope */
		spoe_encode_buffer("code", 8, &p, end);        /* Arg 2: variable name */
		*p++ = SPOE_DATA_T_UINT32;
		encode_varint(frame->modsec_code, &p, end); /* Arg 3: variable value */
		frame->len = (p - frame->buf);
	}
	write_frame(NULL, frame);
}

static void
read_frame_cb(evutil_socket_t fd, short events, void *arg)
{
	struct client     *client = arg;
	struct spoe_frame *frame;
	uint32_t           netint;
	int                n;

	DEBUG(client->worker, "<%lu> %s", client->id, __FUNCTION__);
	if ((frame = acquire_incoming_frame(client)) == NULL)
		goto close;

	frame->type = SPOA_FRM_T_HAPROXY;
	if (frame->buf == (char *)(frame->data)) {
		/* Read the frame length: frame->buf points on length part (frame->data) */
		n = read(client->fd, frame->buf+frame->offset, 4-frame->offset);
		if (n <= 0) {
			if (n < 0)
				LOG(client->worker, "Failed to read frame length : %m");
			goto close;
		}
		frame->offset += n;
		if (frame->offset != 4)
			return;
		memcpy(&netint, frame->buf, 4);
		frame->buf   += 4;
		frame->offset = 0;
		frame->len    = ntohl(netint);
	}

	/* Read the frame: frame->buf points on frame part (frame->data+4)*/
	n = read(client->fd, frame->buf + frame->offset,
		 frame->len - frame->offset);
	if (n <= 0) {
		if (n < 0) {
			LOG(client->worker, "Frame to read frame : %m");
			goto close;
		}
		return;
	}
	frame->offset += n;
	if (frame->offset != frame->len)
		return;
	frame->offset = 0;

	DEBUG(client->worker, "<%lu> New Frame of %u bytes received",
	      client->id, frame->len);

	switch (client->state) {
		case SPOA_ST_CONNECTING:
			if (handle_hahello(frame) < 0) {
				LOG(client->worker, "Failed to decode HELLO frame");
				goto disconnect;
			}
			prepare_agenthello(frame);
			goto write_frame;

		case SPOA_ST_PROCESSING:
			if (frame->buf[0] == SPOE_FRM_T_HAPROXY_DISCON) {
				client->state = SPOA_ST_DISCONNECTING;
				goto disconnecting;
			}
			if (frame->buf[0] == SPOE_FRM_T_UNSET)
				n = handle_hafrag(frame);
			else
				n = handle_hanotify(frame);

			if (n < 0) {
				LOG(client->worker, "Failed to decode frame: %s",
				    spoe_frm_err_reasons[client->status_code]);
				goto disconnect;
			}
			else if (n == 0) {
				LOG(client->worker, "Ignore invalid/unknown/aborted frame");
				goto ignore_frame;
			}
			else if (n == 1)
				goto noop;
			else
				goto process_frame;

		case SPOA_ST_DISCONNECTING:
		  disconnecting:
			if (handle_hadiscon(frame) < 0) {
				LOG(client->worker, "Failed to decode DISCONNECT frame");
				goto disconnect;
			}
			if (client->status_code != SPOE_FRM_ERR_NONE)
				LOG(client->worker, "<%lu> Peer closed connection: %s",
				    client->id, spoe_frm_err_reasons[client->status_code]);
			goto disconnect;
	}

  noop:
	return;

  ignore_frame:
	reset_frame(frame);
	return;

  process_frame:
	process_incoming_frame(frame);
	client->incoming_frame = NULL;
	return;

  write_frame:
	write_frame(client, frame);
	client->incoming_frame = NULL;
	return;

  disconnect:
	client->state = SPOA_ST_DISCONNECTING;
	if (prepare_agentdicon(frame) < 0) {
		LOG(client->worker, "Failed to encode DISCONNECT frame");
		goto close;
	}
	goto write_frame;

  close:
	release_client(client);
}

static void
write_frame_cb(evutil_socket_t fd, short events, void *arg)
{
	struct client     *client = arg;
	struct spoe_frame *frame;
	int                n;

	DEBUG(client->worker, "<%lu> %s", client->id, __FUNCTION__);
	if ((frame = acquire_outgoing_frame(client)) == NULL) {
		event_del(&client->write_frame_event);
		return;
	}

	if (frame->buf == (char *)(frame->data)) {
		/* Write the frame length: frame->buf points on length part (frame->data) */
		n = write(client->fd, frame->buf+frame->offset, 4-frame->offset);
		if (n <= 0) {
			if (n < 0)
				LOG(client->worker, "Failed to write frame length : %m");
			goto close;
		}
		frame->offset += n;
		if (frame->offset != 4)
			return;
		frame->buf   += 4;
		frame->offset = 0;
	}

	/* Write the frame: frame->buf points on frame part (frame->data+4)*/
	n = write(client->fd, frame->buf + frame->offset,
		  frame->len - frame->offset);
	if (n <= 0) {
		if (n < 0) {
			LOG(client->worker, "Failed to write frame : %m");
			goto close;
		}
		return;
	}
	frame->offset += n;
	if (frame->offset != frame->len)
		return;

	DEBUG(client->worker, "<%lu> Frame of %u bytes send",
	      client->id, frame->len);

	switch (client->state) {
		case SPOA_ST_CONNECTING:
			if (frame->hcheck == true) {
				DEBUG(client->worker,
				      "<%lu> Close client after healthcheck",
				      client->id);
				goto close;
			}
			client->state = SPOA_ST_PROCESSING;
			break;

		case SPOA_ST_PROCESSING:
			break;

		case SPOA_ST_DISCONNECTING:
			goto close;
	}

	release_frame(frame);
	client->outgoing_frame = NULL;
	if (!client->async && !client->pipelining) {
		event_del(&client->write_frame_event);
		event_add(&client->read_frame_event, NULL);
	}
	return;

  close:
	release_client(client);
}

static void
accept_cb(int listener, short event, void *arg)
{
	struct worker     *worker;
	struct client     *client;
	int                fd;

	worker = &workers[clicount++ % num_workers];

	if ((fd = accept(listener, NULL, NULL)) < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			LOG(worker, "Failed to accept client connection : %m");
		return;
	}

	DEBUG(&null_worker,
	      "<%lu> New Client connection accepted and assigned to worker %02d",
	      clicount, worker->id);

	if (evutil_make_socket_nonblocking(fd) < 0) {
		LOG(&null_worker, "Failed to set client socket to non-blocking : %m");
		close(fd);
		return;
	}

	if ((client = calloc(1, sizeof(*client))) == NULL) {
		LOG(&null_worker, "Failed to allocate memory for client state : %m");
		close(fd);
		return;
	}

	client->id             = clicount;
	client->fd             = fd;
	client->worker         = worker;
	client->state          = SPOA_ST_CONNECTING;
	client->status_code    = SPOE_FRM_ERR_NONE;
	client->max_frame_size = max_frame_size;
	client->engine         = NULL;
	client->pipelining     = false;
	client->async          = false;
	client->incoming_frame = NULL;
	client->outgoing_frame = NULL;
	LIST_INIT(&client->processing_frames);
	LIST_INIT(&client->outgoing_frames);

	LIST_ADDQ(&worker->clients, &client->by_worker);

	worker->nbclients++;

	if (event_assign(&client->read_frame_event, worker->base, fd,
			 EV_READ|EV_PERSIST, read_frame_cb, client) < 0     ||
	    event_assign(&client->write_frame_event, worker->base, fd,
			 EV_WRITE|EV_PERSIST, write_frame_cb, client) < 0) {
		LOG(&null_worker, "Failed to create client events");
		release_client(client);
		return;
	}
	event_add(&client->read_frame_event,  NULL);
}

static void *
worker_function(void *data)
{
	struct client     *client, *cback;
	struct spoe_frame *frame, *fback;
	struct worker     *worker = data;

	DEBUG(worker, "Worker ready to process client messages");
	event_base_dispatch(worker->base);

	list_for_each_entry_safe(client, cback, &worker->clients, by_worker) {
		release_client(client);
	}

	list_for_each_entry_safe(frame, fback, &worker->frames, list) {
		LIST_DEL(&frame->list);
		free(frame);
	}

	event_free(worker->monitor_event);
	event_base_free(worker->base);
	DEBUG(worker, "Worker is stopped");
	pthread_exit(&null_worker);
}


static int
parse_processing_delay(const char *str)
{
        unsigned long value;

        value = 0;
        while (1) {
                unsigned int j;

                j = *str - '0';
                if (j > 9)
                        break;
                str++;
                value *= 10;
                value += j;
        }

        switch (*str) {
		case '\0': /* no unit = millisecond */
			value *= 1000;
			break;
		case 's': /* second */
			value *= 1000000;
			str++;
			break;
		case 'm': /* millisecond : "ms" */
			if (str[1] != 's')
				return -1;
			value *= 1000;
			str += 2;
			break;
		case 'u': /* microsecond : "us" */
			if (str[1] != 's')
				return -1;
			str += 2;
			break;
		default:
			return -1;
        }
	if (*str)
		return -1;

	processing_delay.tv_sec = (time_t)(value / 1000000);
	processing_delay.tv_usec = (suseconds_t)(value % 1000000);
        return 0;
}


static void
usage(char *prog)
{
	fprintf(stderr,
		"Usage : %s [OPTION]...\n"
		"    -h                   Print this message\n"
		"    -d                   Enable the debug mode\n"
		"    -f <config-file>     ModSecurity configuration file\n"
		"    -m <max-frame-size>  Specify the maximum frame size (default : %u)\n"
		"    -p <port>            Specify the port to listen on (default : %d)\n"
		"    -n <num-workers>     Specify the number of workers (default : %d)\n"
		"    -c <capability>      Enable the support of the specified capability\n"
		"    -t <time>            Set a delay to process a message (default: 0)\n"
		"                           The value is specified in milliseconds by default,\n"
		"                           but can be in any other unit if the number is suffixed\n"
		"                           by a unit (us, ms, s)\n"
		"\n"
		"    Supported capabilities: fragmentation, pipelining, async\n",
		prog, MAX_FRAME_SIZE, DEFAULT_PORT, NUM_WORKERS);
}

int
main(int argc, char **argv)
{
	struct event_base *base = NULL;
	struct event      *signal_event = NULL, *accept_event = NULL;
	int                opt, i, fd = -1;
	const char        *configuration_file = NULL;

	// TODO: add '-t <processing-time>' option
	while ((opt = getopt(argc, argv, "hdm:n:p:c:t:f:")) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0]);
				return EXIT_SUCCESS;
			case 'd':
				debug = true;
				break;
			case 'm':
				max_frame_size = atoi(optarg);
				break;
			case 'n':
				num_workers = atoi(optarg);
				break;
			case 'p':
				server_port = atoi(optarg);
				break;
			case 'f':
				configuration_file = optarg;
				break;
			case 'c':
				if (strcmp(optarg, "pipelining") == 0)
					pipelining = true;
				else if (strcmp(optarg, "async") == 0)
					async = true;
				else if (strcmp(optarg, "fragmentation") == 0)
					fragmentation = true;
				else
					fprintf(stderr, "WARNING: unsupported capability '%s'\n", optarg);
				break;
			case 't':
				if (!parse_processing_delay(optarg))
					break;
				fprintf(stderr, "%s: failed to parse time '%s'.\n", argv[0], optarg);
				fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
				return EXIT_FAILURE;
			default:
				usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	if (!configuration_file) {
		LOG(&null_worker, "ModSecurity configuration is required.\n");
		goto error;
	}

	if (modsecurity_load(configuration_file) == -1)
		goto error;

	if (num_workers <= 0) {
		LOG(&null_worker, "%s : Invalid number of workers '%d'\n",
		    argv[0], num_workers);
		goto error;
	}

	if (server_port <= 0) {
		LOG(&null_worker, "%s : Invalid port '%d'\n",
		    argv[0], server_port);
		goto error;
	}


	if (evthread_use_pthreads() < 0) {
		LOG(&null_worker, "No pthreads support for libevent");
		goto error;
	}

	if ((base = event_base_new()) == NULL) {
		LOG(&null_worker, "Failed to initialize libevent : %m");
		goto error;
	}

	signal(SIGPIPE, SIG_IGN);

	if ((fd = create_server_socket()) < 0) {
		LOG(&null_worker, "Failed to create server socket");
		goto error;
	}
	if (evutil_make_socket_nonblocking(fd) < 0) {
		LOG(&null_worker, "Failed to set server socket to non-blocking");
		goto error;
	}

	if ((workers = calloc(num_workers, sizeof(*workers))) == NULL) {
		LOG(&null_worker, "Failed to set allocate memory for workers");
		goto error;
	}

	for (i = 0; i < num_workers; ++i) {
		struct worker *w = &workers[i];

		w->id        = i+1;
		w->nbclients = 0;
		LIST_INIT(&w->engines);
		LIST_INIT(&w->clients);
		LIST_INIT(&w->frames);

		if ((w->base = event_base_new()) == NULL) {
			LOG(&null_worker,
			    "Failed to initialize libevent for worker %02d : %m",
			    w->id);
			goto error;
		}

		w->monitor_event = event_new(w->base, fd, EV_PERSIST,
					     worker_monitor_cb, (void *)w);
		if (w->monitor_event == NULL ||
		    event_add(w->monitor_event, (struct timeval[]){{5,0}}) < 0) {
			LOG(&null_worker,
			    "Failed to create monitor event for worker %02d",
			    w->id);
			goto error;
		}

		if (pthread_create(&w->thread, NULL, worker_function, (void *)w)) {
			LOG(&null_worker,
			    "Failed to start thread for worker %02d : %m",
			    w->id);
		}
		DEBUG(&null_worker, "Worker %02d initialized", w->id);
	}

	accept_event = event_new(base, fd, EV_READ|EV_PERSIST, accept_cb,
				 (void *)base);
	if (accept_event == NULL || event_add(accept_event, NULL) < 0) {
		LOG(&null_worker, "Failed to create accept event : %m");
	}

	signal_event = evsignal_new(base, SIGINT, signal_cb, (void *)base);
	if (signal_event == NULL || event_add(signal_event, NULL) < 0) {
		LOG(&null_worker, "Failed to create signal event : %m");
	}

	DEBUG(&null_worker,
	      "Server is ready"
	      " [fragmentation=%s - pipelining=%s - async=%s - debug=%s - max-frame-size=%u]",
	      (fragmentation?"true":"false"), (pipelining?"true":"false"), (async?"true":"false"),
	      (debug?"true":"false"), max_frame_size);
	event_base_dispatch(base);

	for (i = 0; i < num_workers; i++) {
		struct worker *w = &workers[i];

		pthread_join(w->thread, NULL);
		DEBUG(&null_worker, "Worker %02d terminated", w->id);
	}

	free(workers);
	event_free(signal_event);
	event_free(accept_event);
	event_base_free(base);
	close(fd);
	return EXIT_SUCCESS;

  error:
	if (workers != NULL)
		free(workers);
	if (signal_event != NULL)
		event_free(signal_event);
	if (accept_event != NULL)
		event_free(accept_event);
	if (base != NULL)
		event_base_free(base);
	if (fd != -1)
		close(fd);
	return EXIT_FAILURE;
}
