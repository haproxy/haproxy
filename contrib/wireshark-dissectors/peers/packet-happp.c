/* packet-happp.c
 * Routines for HAProxy Peers Protocol (HAPPP) dissection
 * Copyright 2016, Frédéric Lécaille <flecaille@haproxy.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <inttypes.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <config.h>
#include <epan/to_str.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include "strutil.h"
#include "packet-tcp.h"

#define HAPPP_PROTOCOL                   "HAProxyS"
#define HAPPP_MSG_MIN_LEN                2

/* Status messages are the shortest ones (3 digits followed by a LF character) */
#define STATUS_HANDSHAKE_SUCCEEDED       "200"
#define STATUS_TRY_AGAIN_LATER           "300"
#define STATUS_PROTOCOL_ERROR            "501"
#define STATUS_BAD_VERSION               "502"
#define STATUS_LOCAL_PEER_NAME_MISMATCH  "503"
#define STATUS_REMOTE_PEER_NAME_MISMATCH "504"

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>

#include "tvbuff.h"

#ifdef DEBUG
static unsigned char dbg_buf[16 << 10];

__attribute__((format (printf, 3, 4)))
void hexdump(const unsigned char *buf, size_t buflen, const char *title_fmt, ...)
{
	size_t i;
	va_list ap;
	const unsigned char *p;
	char str_buf[2 + 1 + 16 + 1 + 1];

	va_start(ap, title_fmt);
	vfprintf(stderr, title_fmt, ap);
	va_end(ap);

	p = buf;
	str_buf[0] = str_buf[1] = ' ';
	str_buf[2] = '|';

	for (i = 0; i < buflen; i++) {
		if (!(i & 0xf))
			fprintf(stderr, "%08X: ", i);
		fprintf(stderr, " %02x", *p);
		if (isalnum(*p))
			str_buf[(i & 0xf) + 3] = *p;
		else
			str_buf[(i & 0xf) + 3] = '.';
		if ((i & 0xf) == 0xf || i == buflen -1) {
			size_t k;

			for (k = 0; k < (0x10 - (i & 0xf) - 1); k++)
				fprintf(stderr, "   ");
			str_buf[(i & 0xf) + 4] = '|';
			str_buf[(i & 0xf) + 5 ] = '\0';
			fprintf(stderr, "%s\n", str_buf);
		}
		p++;
	}
}

void hexdump_tvb(tvbuff_t *tvb, const gint offset, size_t len)
{
	len = len > sizeof dbg_buf ? sizeof dbg_buf : len;
	if (tvb_memcpy(tvb, dbg_buf, offset, len)) {
		hexdump(dbg_buf, len, "tvb buff (%zu bytes):\n", len);
	} else
		fprintf(stderr, "tvb buff COPY FAILED\n");
}
#endif

/* HAPPP message classes */
enum {
	PEER_MSG_CLASS_CONTROL    = 0,
	PEER_MSG_CLASS_ERROR,
	PEER_MSG_CLASS_STICKTABLE = 0x0a,
	PEER_MSG_CLASS_RESERVED   = 0xff,
};

enum {
	CONTROL_CLASS_INDEX,
	ERROR_CLASS_INDEX,
	STICK_TABLE_CLASS_INDEX,
	RESERVED_CLASS_INDEX,
};

/* Control messages */
enum {
	PEER_MSG_CTRL_RESYNCREQ = 0,
	PEER_MSG_CTRL_RESYNCFINISHED,
	PEER_MSG_CTRL_RESYNCPARTIAL,
	PEER_MSG_CTRL_RESYNCCONFIRM,
};

/* Error messages */
enum {
	PEER_MSG_ERR_PROTOCOL = 0,
	PEER_MSG_ERR_SIZELIMIT,
};

/* Stick table messages */
enum {
	PEER_MSG_STKT_UPDATE = 0x80,
	PEER_MSG_STKT_INCUPDATE,
	PEER_MSG_STKT_DEFINE,
	PEER_MSG_STKT_SWITCH,
	PEER_MSG_STKT_ACK,
	PEER_MSG_STKT_UPDATE_TIMED,
	PEER_MSG_STKT_INCUPDATE_TIMED,
};

/* This is the different key types of the stick tables.
 * Same definitions as in HAProxy sources.
 */
enum {
	SMP_T_ANY,       /* any type */
	SMP_T_BOOL,      /* boolean */
	SMP_T_SINT,      /* signed 64bits integer type */
	SMP_T_ADDR,      /* ipv4 or ipv6, only used for input type compatibility */
	SMP_T_IPV4,      /* ipv4 type */
	SMP_T_IPV6,      /* ipv6 type */
	SMP_T_STR,       /* char string type */
	SMP_T_BIN,       /* buffer type */
	SMP_T_METH,      /* contain method */
	SMP_TYPES        /* number of types, must always be last */
};

/* The types of data we can store in a stick table.
 * Same defintions as in HAProxy sources.
 */
enum {
	STKT_DT_SERVER_ID,      /* the server ID to use with this stream if > 0 */
	STKT_DT_GPT0,           /* General Purpose Flag 0. */
	STKT_DT_GPC0,           /* General Purpose Counter 0 (unsigned 32-bit integer) */
	STKT_DT_GPC0_RATE,      /* General Purpose Counter 0's event rate */
	STKT_DT_CONN_CNT,       /* cumulated number of connections */
	STKT_DT_CONN_RATE,      /* incoming connection rate */
	STKT_DT_CONN_CUR,       /* concurrent number of connections */
	STKT_DT_SESS_CNT,       /* cumulated number of sessions (accepted connections) */
	STKT_DT_SESS_RATE,      /* accepted sessions rate */
	STKT_DT_HTTP_REQ_CNT,   /* cumulated number of incoming HTTP requests */
	STKT_DT_HTTP_REQ_RATE,  /* incoming HTTP request rate */
	STKT_DT_HTTP_ERR_CNT,   /* cumulated number of HTTP requests errors (4xx) */
	STKT_DT_HTTP_ERR_RATE,  /* HTTP request error rate */
	STKT_DT_BYTES_IN_CNT,   /* cumulated bytes count from client to servers */
	STKT_DT_BYTES_IN_RATE,  /* bytes rate from client to servers */
	STKT_DT_BYTES_OUT_CNT,  /* cumulated bytes count from servers to client */
	STKT_DT_BYTES_OUT_RATE, /* bytes rate from servers to client */
	STKT_STATIC_DATA_TYPES, /* number of types above */
};

/* The types of data in stick stored in stick tables.
 * Same definitions as in HAProxy sources.
 */
enum {
	STD_T_SINT = 0, /* signed int */
	STD_T_UINT,     /* unsigned int */
	STD_T_ULL,      /* unsigned long long */
	STD_T_FRQP,     /* freq_ctr_period structure made of three unsigned int */
};

/* Prototypes */
void proto_reg_handoff_happp(void);
void proto_register_happp(void);

/* Initialize the protocol and registered fields */
static int proto_happp = -1;
static int hf_happp_fake = -1;
static int hf_happp_version = -1;
static int hf_happp_remotepeerid = -1;
static int hf_happp_localpeerid = -1;
static int hf_happp_processpid = -1;
static int hf_happp_relativepid = -1;
static int hf_happp_status = -1;
static int hf_happp_msg = -1;
static int hf_happp_msg_class = -1;
static int hf_happp_msg_type = -1;
static int hf_happp_msg_len = -1;
static int hf_happp_stkt_def_id = -1;
static int hf_happp_stkt_def_name_len = -1;
static int hf_happp_stkt_def_name_value = -1;
static int hf_happp_stkt_def_key_type = -1;
static int hf_happp_stkt_def_key_len = -1;
static int hf_happp_stkt_def_data_types = -1;
static int hf_happp_stkt_updt_update_id = -1;
static int hf_happp_stkt_updt_expire = -1;
static int hf_happp_stkt_updt_key_len = -1;
static int hf_happp_stkt_updt_key_ipv4_value = -1;
static int hf_happp_stkt_updt_key_str_value = -1;
static int hf_happp_stkt_updt_key_int_value = -1;
static int hf_happp_stkt_updt_key_bytes_value = -1;
static int hf_happp_stkt_updt_data_server_id = -1;
static int hf_happp_stkt_updt_data_gpt0 = -1;
static int hf_happp_stkt_updt_data_gpc0 = -1;
static int hf_happp_stkt_updt_data_gpc0_rate_curr_tick = -1;
static int hf_happp_stkt_updt_data_gpc0_rate_curr_ctr = -1;
static int hf_happp_stkt_updt_data_gpc0_rate_prev_ctr = -1;
static int hf_happp_stkt_updt_data_conn_cnt = -1;
static int hf_happp_stkt_updt_data_conn_rate_curr_tick = -1;
static int hf_happp_stkt_updt_data_conn_rate_curr_ctr = -1;
static int hf_happp_stkt_updt_data_conn_rate_prev_ctr = -1;
static int hf_happp_stkt_updt_data_conn_cur = -1;
static int hf_happp_stkt_updt_data_sess_cnt = -1;
static int hf_happp_stkt_updt_data_sess_rate_curr_tick = -1;
static int hf_happp_stkt_updt_data_sess_rate_curr_ctr  = -1;
static int hf_happp_stkt_updt_data_sess_rate_prev_ctr = -1;
static int hf_happp_stkt_updt_data_http_req_cnt = -1;
static int hf_happp_stkt_updt_data_http_req_rate_curr_tick = -1;
static int hf_happp_stkt_updt_data_http_req_rate_curr_ctr = -1;
static int hf_happp_stkt_updt_data_http_req_rate_prev_ctr= -1;
static int hf_happp_stkt_updt_data_http_err_cnt = -1;
static int hf_happp_stkt_updt_data_http_err_rate_curr_tick = -1;
static int hf_happp_stkt_updt_data_http_err_rate_curr_ctr = -1;
static int hf_happp_stkt_updt_data_http_err_rate_prev_ctr = -1;
static int hf_happp_stkt_updt_data_bytes_in_cnt = -1;
static int hf_happp_stkt_updt_data_bytes_in_rate_curr_tick = -1;
static int hf_happp_stkt_updt_data_bytes_in_rate_curr_ctr = -1;
static int hf_happp_stkt_updt_data_bytes_in_rate_prev_ctr = -1;
static int hf_happp_stkt_updt_data_bytes_out_cnt = -1;
static int hf_happp_stkt_updt_data_bytes_out_rate_curr_tick = -1;
static int hf_happp_stkt_updt_data_bytes_out_rate_curr_ctr = -1;
static int hf_happp_stkt_updt_data_bytes_out_rate_prev_ctr = -1;
static int hf_happp_stkt_updt_ack_table_id = -1;
static int hf_happp_stkt_updt_ack_update_id = -1;

struct happp_cv_data_t {
	/* Same thing for the type of the the stick table keys */
	uint64_t stkt_key_type;

	/* Same thing for the length of the stick table keys.
	 * Note that this is true only for key types different of SMT_T_STR (strings)
	 * and SMT_T_SINT (signed ints).
	 */
	uint64_t stkt_key_len;

	/* Same thing for the types of the stick table data */
	uint64_t stkt_data_types;
	void *data;
};

struct hf_stkt_data_type {
	const char *name;
	unsigned int type;
	int *hf_ids[3];
	size_t hf_ids_len;
};

struct hf_stkt_data_type hf_stkt_data_types[] = {
	[STKT_DT_SERVER_ID] = {
		.name = "server_id",
		.type = STD_T_SINT,
		.hf_ids = {
			&hf_happp_stkt_updt_data_server_id,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_GPT0] = {
		.name = "gpt0",
		.type = STD_T_UINT,
		.hf_ids = {
			&hf_happp_stkt_updt_data_gpt0,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_GPC0] = {
		.name = "gpc0",
		.type = STD_T_UINT,
		.hf_ids = {
			&hf_happp_stkt_updt_data_gpc0,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_GPC0_RATE] = {
		.name = "gpc0_rate",
		.type = STD_T_FRQP,
		.hf_ids = {
			&hf_happp_stkt_updt_data_gpc0_rate_curr_tick,
			&hf_happp_stkt_updt_data_gpc0_rate_curr_ctr,
			&hf_happp_stkt_updt_data_gpc0_rate_prev_ctr,
		},
		.hf_ids_len = 3,
	},
	[STKT_DT_CONN_CNT] = {
		.name = "conn_cnt",
		.type = STD_T_UINT,
		.hf_ids = {
			&hf_happp_stkt_updt_data_conn_cnt,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_CONN_RATE] = {
		.name = "conn_rate",
		.type = STD_T_FRQP,
		.hf_ids = {
			&hf_happp_stkt_updt_data_conn_rate_curr_tick,
			&hf_happp_stkt_updt_data_conn_rate_curr_ctr,
			&hf_happp_stkt_updt_data_conn_rate_prev_ctr,
		},
		.hf_ids_len = 3,
	},
	[STKT_DT_CONN_CUR] = {
		.name = "conn_cur",
		.type = STD_T_UINT,
		.hf_ids = {
			&hf_happp_stkt_updt_data_conn_cur,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_SESS_CNT] = {
		.name = "sess_cnt",
		.type = STD_T_UINT,
		.hf_ids = {
			&hf_happp_stkt_updt_data_sess_cnt,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_SESS_RATE] = {
		.name = "sess_rate",
		.type = STD_T_FRQP,
		.hf_ids = {
			&hf_happp_stkt_updt_data_sess_rate_curr_tick,
			&hf_happp_stkt_updt_data_sess_rate_curr_ctr,
			&hf_happp_stkt_updt_data_sess_rate_prev_ctr,
		},
		.hf_ids_len = 3,
	},
	[STKT_DT_HTTP_REQ_CNT] = {
		.name = "http_req_cnt",
		.type = STD_T_UINT,
		.hf_ids = {
			&hf_happp_stkt_updt_data_http_req_cnt,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_HTTP_REQ_RATE] = {
		.name = "http_req_rate",
		.type = STD_T_FRQP,
		.hf_ids = {
			&hf_happp_stkt_updt_data_http_req_rate_curr_tick,
			&hf_happp_stkt_updt_data_http_req_rate_curr_ctr,
			&hf_happp_stkt_updt_data_http_req_rate_prev_ctr,
		},
		.hf_ids_len = 3,
	},
	[STKT_DT_HTTP_ERR_CNT] = {
		.name = "http_err_cnt",
		.type = STD_T_UINT,
		.hf_ids = {
			&hf_happp_stkt_updt_data_http_err_cnt,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_HTTP_ERR_RATE] = {
		.name = "http_err_rate",
		.type = STD_T_FRQP,
		.hf_ids = {
			&hf_happp_stkt_updt_data_http_err_rate_curr_tick,
			&hf_happp_stkt_updt_data_http_err_rate_curr_ctr,
			&hf_happp_stkt_updt_data_http_err_rate_prev_ctr,
		},
		.hf_ids_len = 3,
	},
	[STKT_DT_BYTES_IN_CNT] = {
		.name = "bytes_in_cnt",
		.type = STD_T_ULL,
		.hf_ids = {
			&hf_happp_stkt_updt_data_bytes_in_cnt,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_BYTES_IN_RATE] = {
		.name = "bytes_in_rate",
		.type = STD_T_FRQP,
		.hf_ids = {
			&hf_happp_stkt_updt_data_bytes_in_rate_curr_tick,
			&hf_happp_stkt_updt_data_bytes_in_rate_curr_ctr,
			&hf_happp_stkt_updt_data_bytes_in_rate_prev_ctr,
		},
		.hf_ids_len = 3,
	},
	[STKT_DT_BYTES_OUT_CNT] = {
		.name = "bytes_out_cnt",
		.type = STD_T_ULL,
		.hf_ids = {
			&hf_happp_stkt_updt_data_bytes_out_cnt,
		},
		.hf_ids_len = 1,
	},
	[STKT_DT_BYTES_OUT_RATE] = {
		.name = "bytes_out_rate",
		.type = STD_T_FRQP,
		.hf_ids = {
			&hf_happp_stkt_updt_data_bytes_out_rate_curr_tick,
			&hf_happp_stkt_updt_data_bytes_out_rate_curr_ctr,
			&hf_happp_stkt_updt_data_bytes_out_rate_prev_ctr,
		},
		.hf_ids_len = 3,
	},
};


/* Initialize the subtree pointers */
static gint ett_happp = -1;
static gint ett_happp_msg = -1;

static dissector_handle_t happp_tcp_handle;

static const char *control_msg_type_str_from_byte(guint8 c);
static const char *error_msg_type_str_from_byte(guint8 c);
static const char *stkt_msg_type_str_from_byte(guint8 c);

struct class_def_t {
	const char *class_str;
	const char *col_info_str;
	const char *(*msg_type_str_func)(guint8 c);
	unsigned int count;
};

static struct class_def_t class_def_tab[] = {
	[CONTROL_CLASS_INDEX] = {
		.class_str = "Control Class Message",
		.col_info_str = "Ctl",
		.msg_type_str_func = control_msg_type_str_from_byte,
	},
	[ERROR_CLASS_INDEX] = {
		.class_str = "Error Class Message",
		.col_info_str = "Err",
		.msg_type_str_func = error_msg_type_str_from_byte,
	},
	[STICK_TABLE_CLASS_INDEX] = {
		.class_str = "Stick Table Class Message",
		.col_info_str = "Stkt",
		.msg_type_str_func = stkt_msg_type_str_from_byte,
	},
	[RESERVED_CLASS_INDEX] = {
		.class_str = "Reserved Class Message",
		.col_info_str = "Res",
	}
};

static int control_class_index_from_byte(guint8 c)
{
	switch (c) {
	case PEER_MSG_CLASS_CONTROL:
		return CONTROL_CLASS_INDEX;
	case PEER_MSG_CLASS_ERROR:
		return ERROR_CLASS_INDEX;
	case PEER_MSG_CLASS_STICKTABLE:
		return STICK_TABLE_CLASS_INDEX;
	case PEER_MSG_CLASS_RESERVED:
		return RESERVED_CLASS_INDEX;
	default:
		return -1;
	};
}

static const char *class_str_from_byte(guint8 c)
{
	int class_idx;

	class_idx = control_class_index_from_byte(c);
	if (class_idx == -1)
		return "N/A";

	return class_def_tab[class_idx].class_str;
}

static const char *control_msg_type_str_from_byte(guint8 c)
{
	switch (c) {
	case PEER_MSG_CTRL_RESYNCREQ:
		return "resync. request";
	case PEER_MSG_CTRL_RESYNCFINISHED:
		return "resync. finished";
	case PEER_MSG_CTRL_RESYNCPARTIAL:
		return "resync. partial";
	case PEER_MSG_CTRL_RESYNCCONFIRM:
		return "resync. confirm";
	default:
		return "Unknown";
	}
}

static const char *stkt_msg_type_str_from_byte(guint8 c)
{
	switch (c) {
	case PEER_MSG_STKT_UPDATE:
		return "update";
	case PEER_MSG_STKT_INCUPDATE:
		return "inc. update";
	case PEER_MSG_STKT_DEFINE:
		return "definition";
	case PEER_MSG_STKT_SWITCH:
		return "switch";
	case PEER_MSG_STKT_ACK:
		return "ack";
	case PEER_MSG_STKT_UPDATE_TIMED:
		return "update (with expiration)";
	case PEER_MSG_STKT_INCUPDATE_TIMED:
		return "inc. update (with expiration)";
	default:
		return "Unknown";
	}
}

static const char *error_msg_type_str_from_byte(guint8 c)
{
	switch (c) {
	case PEER_MSG_ERR_PROTOCOL:
		return "protocol error";
	case PEER_MSG_ERR_SIZELIMIT:
		return "limit size error";
	default:
		return "Unknown";
	}
}

#define MAX_ENC_LEN 10
static uint64_t intdecode(unsigned char **str, size_t len) {
	int i = 0;
	uint64_t ret;

	if (len < 1 || len > MAX_ENC_LEN) {
		*str = NULL;
		return 0;
	}

	ret = *(*str)++;
	len--;
	if ((ret & 0xf0) != 0xf0 || !len)
		return ret;

	do {
		/* As shifting value may be greater than 8 (size of **str in bits),
		 * uint64_t cast is required.
		 */
		ret += (uint64_t)**str << (4 + 7 * i++);
	} while (len-- && (*(*str)++ & 0x80) == 0x80);

	return ret;
}

static int dissect_happp_handshake_pdu(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *happp_tree)
{
	int line_len, token_len;
	gint offset = 0, next_offset;
	const guchar *line, *line_end, *next_token;
	size_t protocol_strlen;

	line_len = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE);
	/* XXX TO DO */
	if (line_len == -1)
		return -1;

	protocol_strlen = strlen(HAPPP_PROTOCOL);

	line = tvb_get_ptr(tvb, offset, line_len);
	line_end = line + (next_offset - offset);
	/* The line must contain at least HAPPP_PROTOCOL string followed by a space,
	 * then version string (at least one character) and a '\n' character.
	 */
	if (line_len >= (int)protocol_strlen + 3 &&
	    !tvb_strncaseeql(tvb, 0, HAPPP_PROTOCOL, protocol_strlen)) {
		/* This is an Hello message */
		col_set_str(pinfo->cinfo, COL_INFO, "Hello message");

		token_len = get_token_len(line + protocol_strlen + 1, line_end, &next_token);
		proto_tree_add_item(happp_tree, hf_happp_version, tvb,
		                    offset + protocol_strlen + 1, token_len,
		                    ENC_ASCII | ENC_NA);

		offset = next_offset;
		line_len = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE);
		/* XXX TO DO */
		if (line_len == -1)
			return -1;

		line = tvb_get_ptr(tvb, offset, line_len);
		line_end = line + (next_offset - offset);
		/* Get next token: remotepeerid */
		token_len = get_token_len(line, line_end, &next_token);
		if (!token_len)
			return -1;

		proto_tree_add_item(happp_tree, hf_happp_remotepeerid, tvb, offset,
		                    token_len, ENC_ASCII | ENC_NA);

		/* Retrieve next line */
		offset = next_offset;
		line_len = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE);
		/* XXX TO DO */
		if (line_len == -1)
			return -1;

		line = tvb_get_ptr(tvb, offset, line_len);
		line_end = line + (next_offset - offset);
		/* Get next token: localpeerid */
		token_len = get_token_len(line, line_end, &next_token);
		if (!token_len)
			return -1;

		proto_tree_add_item(happp_tree, hf_happp_localpeerid, tvb, offset,
		                    token_len, ENC_ASCII | ENC_NA);
		offset += next_token - line;
		line = next_token;

		/* Get next token: processpid */
		token_len = get_token_len(line, line_end, &next_token);
		if (!token_len)
			return -1;

		proto_tree_add_item(happp_tree, hf_happp_processpid, tvb, offset,
		                    token_len, ENC_ASCII | ENC_NA);
		offset += next_token - line;
		line = next_token;

		/* Get next token: relativepid */
		token_len = get_token_len(line, line_end, &next_token);
		if (!token_len)
			return -1;

		proto_tree_add_item(happp_tree, hf_happp_relativepid, tvb, offset,
		                    token_len, ENC_ASCII | ENC_NA);
		offset += next_token - line;
		line = next_token;

	}
	else if (line_len == 3) {
		col_set_str(pinfo->cinfo, COL_INFO, "Status message");
		token_len = get_token_len(line, line_end, &next_token);
		if (!token_len)
			return -1;

		proto_tree_add_item(happp_tree, hf_happp_status, tvb, offset,
		                    token_len, ENC_ASCII | ENC_NA);
	}

	return tvb_captured_length(tvb);
}

/* Reset to zero all statistics counters of class_def_array */
static void init_class_def_tab(struct class_def_t *class_def_array, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		class_def_array[i].count = 0;
}

/* Add statistics counting information about HAPPP message classes to
 * info column (numbers of messages found in an HAPPP PDU by class).
 */
static inline void col_info_append_class(packet_info *pinfo, int class_index,
                                         int *first_class)
{
	if (!class_def_tab[class_index].count)
		return;

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s=%u",
	                *first_class ? "" : " ",
	                class_def_tab[class_index].col_info_str,
	                class_def_tab[class_index].count);
	class_def_tab[class_index].count = 0;
	*first_class = 0;
}


static int intdecode_from_tvbuff(tvbuff_t *tvb, uint64_t *dec_val,
                                 guint *offset, guint total)
{
	unsigned char *p, enc_buf[MAX_ENC_LEN];
	size_t max_enc_buf_len, left;

	left = total - *offset;
	max_enc_buf_len = left < sizeof enc_buf ? left : sizeof enc_buf;
	if (!tvb_memcpy(tvb, enc_buf, *offset, max_enc_buf_len))
		return -1;

	p = enc_buf;
	*dec_val = intdecode(&p, max_enc_buf_len);
	if (!p)
		return -1;

	*offset += p - enc_buf;

	return 0;
}

static int add_enc_field_to_happp_tree(int field_id, proto_tree *tree, tvbuff_t *tvb,
                                       guint *offset, guint total, uint64_t *val)
{
	uint64_t dec_val;
	size_t dec_val_len;
	guint saved_offset;

	saved_offset = *offset;
	if (intdecode_from_tvbuff(tvb, &dec_val, offset, total) < 0)
		return -1;

	dec_val_len = *offset - saved_offset;
	proto_tree_add_uint64_format_value(tree, field_id, tvb, saved_offset,
	                                   dec_val_len, dec_val, "%" PRIu64, dec_val);

	if (val)
		*val = dec_val;

	return 0;
}

static int add_int_field_to_happp_tree(int field_id,
                                       tvbuff_t *tvb, proto_tree *tree,
                                       guint *offset, guint total _U_)
{
	uint32_t val;

	if (!tvb_memcpy(tvb, &val, *offset, sizeof val))
		return -1;

	val = ntohl(val);
	proto_tree_add_int_format_value(tree, field_id, tvb, *offset,
	                                sizeof val, val, "%" PRId32, val);
	*offset += sizeof val;

	return 0;
}

static void dissect_happp_stkt_define_msg(tvbuff_t *tvb, packet_info *pinfo _U_,
                                          proto_tree *tree, guint offset, guint total)
{
	uint64_t dec_val;
	uint64_t stkt_key_type;
	uint64_t stkt_key_len;
	uint64_t stkt_data_types;
	struct happp_cv_data_t *happp_cv_data;
	conversation_t *cv;

	if (add_enc_field_to_happp_tree(hf_happp_stkt_def_id, tree,
	                                tvb, &offset, total, NULL) < 0 ||
	    add_enc_field_to_happp_tree(hf_happp_stkt_def_name_len, tree,
	                                tvb, &offset, total, &dec_val) < 0)
		return;

	/* Add the stick table name to HAPPP proto tree */
	proto_tree_add_item(tree, hf_happp_stkt_def_name_value, tvb, offset, dec_val,
	                    ENC_ASCII | ENC_NA);
	offset += dec_val;

	if (add_enc_field_to_happp_tree(hf_happp_stkt_def_key_type, tree,
	                                tvb, &offset, total, &stkt_key_type) < 0 ||
	    add_enc_field_to_happp_tree(hf_happp_stkt_def_key_len, tree,
	                                tvb, &offset, total, &stkt_key_len) < 0 ||
	    add_enc_field_to_happp_tree(hf_happp_stkt_def_data_types, tree,
	                                tvb, &offset, total, &stkt_data_types) < 0)
		return;

	cv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
	                       pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	if (!cv)
		return;

	/*
	 * According to the documentation, it is not our responsibility
	 * to free this allocated memory.
	 */
	happp_cv_data = (struct happp_cv_data_t *)wmem_alloc(wmem_file_scope(),
													     sizeof *happp_cv_data);
	if (!happp_cv_data)
		return;

	happp_cv_data->stkt_key_type = stkt_key_type;
	happp_cv_data->stkt_key_len = stkt_key_len;
	happp_cv_data->stkt_data_types = stkt_data_types;

	conversation_add_proto_data(cv, proto_happp, happp_cv_data);
}

static void dissect_happp_stkt_update_msg(tvbuff_t *tvb, packet_info *pinfo _U_,
                                          proto_tree *tree, guint offset, guint total,
                                          unsigned  char msg_type_byte)
{
	unsigned int data_type;
	uint64_t *stkt_key_type;
	uint64_t *stkt_key_len;
	struct happp_cv_data_t *happp_cv_data;
	int has_update_id, has_exp;
	conversation_t *cv;

	cv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
	                       pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	if (!cv)
		return;

	happp_cv_data = (struct happp_cv_data_t *)conversation_get_proto_data(cv, proto_happp);
	if (!happp_cv_data)
		return;

	has_update_id = msg_type_byte == PEER_MSG_STKT_UPDATE       ||
	                msg_type_byte == PEER_MSG_STKT_UPDATE_TIMED;
	has_exp       = msg_type_byte == PEER_MSG_STKT_UPDATE_TIMED ||
	                msg_type_byte == PEER_MSG_STKT_INCUPDATE_TIMED;
	/* Add the stick table update ID to HAPPP tree */
	if (has_update_id &&
	    add_int_field_to_happp_tree(hf_happp_stkt_updt_update_id, tvb, tree,
	                                &offset, total) < 0)
		return;

	if (has_exp &&
	    add_int_field_to_happp_tree(hf_happp_stkt_updt_expire, tvb, tree,
	                                &offset, total) < 0)
		return;


	stkt_key_type = &happp_cv_data->stkt_key_type;
	stkt_key_len = &happp_cv_data->stkt_key_len;

	switch(*stkt_key_type) {
	case SMP_T_STR:
		if (add_enc_field_to_happp_tree(hf_happp_stkt_updt_key_len, tree, tvb,
		                                &offset, total, stkt_key_len) < 0)
			return;

		proto_tree_add_item(tree, hf_happp_stkt_updt_key_str_value, tvb,
		                    offset, *stkt_key_len, ENC_ASCII | ENC_NA);
		offset += *stkt_key_len;
		break;
	case SMP_T_SINT:
	    if (add_int_field_to_happp_tree(hf_happp_stkt_updt_key_int_value, tvb, tree,
	                                    &offset, total) < 0)
		    return;

		break;
	case SMP_T_IPV4:
		proto_tree_add_ipv4(tree, hf_happp_stkt_updt_key_ipv4_value,
		                    tvb, offset, 4, tvb_get_ipv4(tvb, offset));
		offset += 4;
		break;
	default:
		proto_tree_add_item(tree, hf_happp_stkt_updt_key_bytes_value,
		                    tvb, offset, *stkt_key_len, ENC_NA);
		offset += *stkt_key_len;
		break;
	}

	/* Data dissection */
	for (data_type = 0;
	     data_type < sizeof hf_stkt_data_types / sizeof *hf_stkt_data_types;
	     data_type++) {
		struct hf_stkt_data_type *hf_stkt_dtype;
		size_t i;

		if (!(happp_cv_data->stkt_data_types & (1 << data_type)))
			continue;

		hf_stkt_dtype = &hf_stkt_data_types[data_type];

		for (i = 0; i < hf_stkt_dtype->hf_ids_len; i++)
			if (add_enc_field_to_happp_tree(*hf_stkt_dtype->hf_ids[i], tree, tvb,
			                                &offset, total, NULL) < 0)
				return;
	}
}

static void dissect_happp_stkt_ack_msg(tvbuff_t *tvb, packet_info *pinfo _U_,
                                          proto_tree *tree, guint offset, guint total)
{
	if (add_enc_field_to_happp_tree(hf_happp_stkt_updt_ack_table_id, tree, tvb,
	                                &offset, total, NULL) < 0)
		return;

	if (add_int_field_to_happp_tree(hf_happp_stkt_updt_ack_update_id, tvb, tree,
	                                &offset, total) < 0)
		return;
}

static void dissect_happp_stk_msg(tvbuff_t *tvb, packet_info *pinfo _U_,
                                  proto_tree *tree, guint8 msg_type_byte,
                                  guint offset, guint total)
{
	switch (msg_type_byte) {
	case PEER_MSG_STKT_DEFINE:
		dissect_happp_stkt_define_msg(tvb, pinfo, tree, offset, total);
		break;
	case PEER_MSG_STKT_UPDATE:
	case PEER_MSG_STKT_INCUPDATE:
	case PEER_MSG_STKT_UPDATE_TIMED:
	case PEER_MSG_STKT_INCUPDATE_TIMED:
		dissect_happp_stkt_update_msg(tvb, pinfo, tree, offset, total, msg_type_byte);
		break;
	case PEER_MSG_STKT_ACK:
		dissect_happp_stkt_ack_msg(tvb, pinfo, tree, offset, total);
		break;
	};

}

static void
dissect_happp_msg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                  guint8 msg_class_byte, guint8 msg_type_byte,
                  guint *offset, guint total)
{
	unsigned char *p, enc_buf[MAX_ENC_LEN];
	uint64_t dec_msg_len;
	size_t max_enc_buf_len, left, dec_val_len;

	left = total - *offset;
	max_enc_buf_len = left < sizeof enc_buf ? left : sizeof enc_buf;
	if (!tvb_memcpy(tvb, enc_buf, *offset, max_enc_buf_len))
		return;

	p = enc_buf;
	dec_msg_len = intdecode(&p, max_enc_buf_len);
	if (!p)
		return;

	dec_val_len = p - enc_buf;
	proto_tree_add_uint64_format_value(tree, hf_happp_msg_len,
	                                   tvb, *offset, dec_val_len, dec_msg_len,
	                                   "%" PRIu64, dec_msg_len);
	*offset += dec_val_len;

	switch (msg_class_byte) {
	case PEER_MSG_CLASS_STICKTABLE:
		dissect_happp_stk_msg(tvb, pinfo, tree, msg_type_byte, *offset, total);
		break;
	}

	*offset += dec_msg_len;
}

/* Code to actually dissect the packets */
static int
dissect_happp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
	proto_item *item;
	proto_tree *happp_tree;
	/* Other misc. local variables. */
	guint total, offset;
	int first_message, first_class, curr_class, prev_class;
	guint8 first_byte;
	size_t sizeof_class_def_tab;

	offset = 0;
	first_message = first_class = 1;
	total = tvb_reported_length(tvb);

	/* create display subtree for the protocol */
	item = proto_tree_add_item(tree, proto_happp, tvb, offset, -1, ENC_NA);
	happp_tree = proto_item_add_subtree(item, ett_happp);

	/* Set the protocol column value */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "happp");

	first_byte = (gchar)tvb_get_guint8(tvb, offset);
	if (first_byte != PEER_MSG_CLASS_CONTROL    &&
	    first_byte != PEER_MSG_CLASS_ERROR      &&
	    first_byte != PEER_MSG_CLASS_STICKTABLE &&
	    first_byte != PEER_MSG_CLASS_RESERVED)
		return dissect_happp_handshake_pdu(tvb, pinfo, happp_tree);

	/* Reset class_def_tab message class counters */
	sizeof_class_def_tab = sizeof class_def_tab / sizeof *class_def_tab;
	init_class_def_tab(class_def_tab, sizeof_class_def_tab);

	prev_class = curr_class = -1;
	col_set_str(pinfo->cinfo, COL_INFO, "[");
	while (offset < total) {
		guint8 msg_class_byte, msg_type_byte;
		const char *(*msg_type_str_func)(guint8 c);
		struct class_def_t *class_def;

		if (first_message) {
			msg_class_byte = first_byte;
		}
		else {
			msg_class_byte = tvb_get_guint8(tvb, offset);
		}
		curr_class = control_class_index_from_byte(msg_class_byte);
		if (curr_class == -1)
			return -1;

		if (first_message) {
			prev_class = curr_class;
			first_message = 0;
		}

		class_def = &class_def_tab[curr_class];
		class_def->count++;
		msg_type_str_func = class_def->msg_type_str_func;

		/* Insert a line separator */
		proto_tree_add_item(happp_tree, hf_happp_fake, tvb,
		                    offset, 0,
		                    ENC_ASCII | ENC_NA);
		proto_tree_add_uint_format_value(happp_tree, hf_happp_msg_class,
		                                 tvb, offset++, 1, msg_class_byte,
		                                 "%u    (%s)", msg_class_byte,
		                                 class_str_from_byte(msg_class_byte));
		msg_type_byte = tvb_get_guint8(tvb, offset);

		/* First byte: message class */
		switch (msg_class_byte) {
		case PEER_MSG_CLASS_CONTROL:
		case PEER_MSG_CLASS_ERROR:
		case PEER_MSG_CLASS_STICKTABLE:
			/* Second byte: message type in the class */
			proto_tree_add_uint_format_value(happp_tree, hf_happp_msg_type,
			                                 tvb, offset++, 1, msg_type_byte,
			                                 "%u    (%s)", msg_type_byte,
			                                 msg_type_str_func(msg_type_byte));
			break;
		case PEER_MSG_CLASS_RESERVED:
			col_append_str(pinfo->cinfo, COL_INFO, "NON IMPLEMENTED");
			break;
		}
		if (msg_class_byte >= PEER_MSG_CLASS_STICKTABLE)
			dissect_happp_msg(tvb, pinfo, happp_tree,
			                  msg_class_byte, msg_type_byte, &offset, total);

		/* Sequentially add counting information to info column about
		 * number of messages found by class in an HAPPP PDU.
		 * For instance if an HAPPP PDU contains this sequence of messages:
		 * 1 Control message - 2 Stick Table messages - 3 Control messages
		 * column information displays: [Ctl=1 Stkt=2 Ctl=3].
		 */
		if (curr_class != prev_class) {
			col_info_append_class(pinfo, prev_class, &first_class);
			col_info_append_class(pinfo, curr_class, &first_class);
			prev_class = curr_class;
		}
		else if (offset >= total) {
			/* Last message */
			col_info_append_class(pinfo, curr_class, &first_class);
		}
	}
	col_append_str(pinfo->cinfo, COL_INFO, "]");

	return tvb_captured_length(tvb);
}

static guint
get_happp_msg_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	guint ret, len, left;
	gint next_offset, line_len;
	guint8 first_byte;
	uint64_t dec_len;
	int saved_offset;

	/* 0 means there is not enough data to get length. */
	ret = 0;

	len = tvb_reported_length(tvb);
	left = len - offset;
	if (left < HAPPP_MSG_MIN_LEN)
		goto out;

	saved_offset = offset;
	first_byte = (gchar)tvb_get_guint8(tvb, offset);
	if (first_byte == PEER_MSG_CLASS_CONTROL ||
	    first_byte == PEER_MSG_CLASS_ERROR   ||
	    first_byte == PEER_MSG_CLASS_RESERVED) {
		ret = HAPPP_MSG_MIN_LEN;
	} else if (first_byte == PEER_MSG_CLASS_STICKTABLE) {
		int soff;

		left -= HAPPP_MSG_MIN_LEN;
		offset += HAPPP_MSG_MIN_LEN;
		soff = offset;
		if (intdecode_from_tvbuff(tvb, &dec_len, &offset, len) < 0)
			goto out;

		left -= offset - soff;
		if (left < dec_len)
			goto out;

		ret = dec_len + offset - saved_offset;
	} else {
		/* hello message: add line lengths to compute this message length. */
		for (;;) {
			line_len = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE);
			if (line_len == -1)
				break;

			ret += line_len + 1;
			offset += line_len + 1;
		}
	}

 out:
	return ret;
 }

static int
dissect_happp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE,
	                 HAPPP_MSG_MIN_LEN, get_happp_msg_len, dissect_happp_pdu, data);

	return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_happp(void)
{
	/* Setup list of header fields  See Section 1.5 of README.dissector for
	 * details. */
	static hf_register_info hf[] = {
		{
			/* This one is used as separator between HAPPP messages */
			&hf_happp_fake,
			{
				":-----------------------------------------------", "happp.fake",
				FT_STRING, STR_ASCII, NULL, 0, "FAKE", HFILL
			}
		},
		{
			&hf_happp_version,
			{
				"version", "happp.version",
				FT_STRING, STR_ASCII, NULL, 0, "version", HFILL
			}
		},
		{
			&hf_happp_remotepeerid,
			{
				"remotepeerid", "happp.remotepeerid",
				FT_STRING, STR_ASCII, NULL, 0, "remote peer id", HFILL
			}
		},
		{
			&hf_happp_localpeerid,
			{
				"localpeerid", "happp.localpeerid",
				FT_STRING, STR_ASCII, NULL, 0, "local peer id", HFILL
			}
		},
		{
			&hf_happp_processpid,
			{
				"processpid", "happp.processpid",
				FT_STRING, STR_ASCII, NULL, 0, "process pid", HFILL
			}
		},
		{
			&hf_happp_relativepid,
			{
				"relativepid", "happp.relativepid",
				FT_STRING, STR_ASCII, NULL, 0, "relative pid", HFILL
			}
		},
		{
			&hf_happp_status,
			{
				"status", "happp.status",
				FT_STRING, STR_ASCII, NULL, 0, "status message", HFILL
			}
		},
		{
			&hf_happp_msg,
			{
				"message", "happp.msg",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_msg_class,
			{
				"message class", "happp.msg.class",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_msg_type,
			{
				"message type", "happp.msg.type",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_msg_len,
			{
				"message length", "happp.msg.len",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_def_id,
			{
				"    ID", "happp.msg.stkt.def.id",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_def_name_len,
			{
				"    name length", "happp.msg.stkt.def.name.length",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_def_name_value,
			{
				"    name", "happp.msg.stkt.def.name.value",
				FT_STRING, STR_ASCII, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_def_key_type,
			{
				"    key type", "happp.msg.stkt.def.key.type",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_def_key_len,
			{
				"    key length", "happp.msg.stkt.def.key.len",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_def_data_types,
			{
				"    data types", "happp.msg.stkt.def.data_types",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_update_id,
			{
				"    update ID", "happp.msg.stkt.updt.update_id",
				FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_expire,
			{
				"    expiration", "happp.msg.stkt.updt.expiration",
				FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_key_len,
			{
				"    key length", "happp.msg.stkt.updt.key.len",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_key_str_value,
			{
				"    key value", "happp.msg.stkt.updt.key.str.value",
				FT_STRING, STR_ASCII, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_key_int_value,
			{
				"    key value", "happp.msg.stkt.updt.key.int.value",
				FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_key_ipv4_value,
			{
				"    key IPv4 value", "happp.msg.stkt.updt.key.ipv4.value",
				FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_key_bytes_value,
			{
				"    key value", "happp.msg.stkt.updt.key.bytes.value",
				FT_BYTES, 0, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_server_id,
			{
				"    server_id", "happp.msg.stkt.updt.data.server_id",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_gpt0,
			{
				"    gpt0", "happp.msg.stkt.updt.data.gpt0",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_gpc0,
			{
				"    gpc0", "happp.msg.stkt.updt.data.gpc0",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_gpc0_rate_curr_tick,
			{
				"    gpc0 curr. tick",
				"happp.msg.stkt.updt.data.gpc0_rate.curr_tick",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_gpc0_rate_curr_ctr,
			{
				"    gpc0 curr. ctr.",
				"happp.msg.stkt.updt.data.gpc0_rate.curr_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_gpc0_rate_prev_ctr,
			{
				"    gpc0 prev. ctr.",
				"happp.msg.stkt.updt.data.gpc0_rate.prev_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_conn_cnt,
			{
				"    conn_cnt",
				"happp.msg.stkt.updt.data.conn_cnt",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_conn_rate_curr_tick,
			{
				"    conn_rate curr. tick",
				"happp.msg.stkt.updt.data.conn_rate.curr_tick",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_conn_rate_curr_ctr,
			{
				"    conn_rate curr. ctr.",
				"happp.msg.stkt.updt.data.conn_rate.curr_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_conn_rate_prev_ctr,
			{
				"    conn_rate prev. ctr.",
				"happp.msg.stkt.updt.data.conn_rate.prev_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_conn_cur,
			{
				"    conn_curr curr. tick",
				"happp.msg.stkt.updt.data.conn_cur",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_sess_cnt,
			{
				"    sess_cnt", "happp.msg.stkt.updt.data.sess_cnt",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_sess_rate_curr_tick,
			{
				"    sess_rate curr. tick",
				"happp.msg.stkt.updt.data.sess_rate.curr_tick",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_sess_rate_curr_ctr,
			{
				"    sess_rate curr. ctr.",
				"happp.msg.stkt.updt.data.sess_rate.curr_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_sess_rate_prev_ctr,
			{
				"    sess_rate prev. ctr.",
				"happp.msg.stkt.updt.data.sess_rate.prev_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_http_req_cnt,
			{
				"    http_req_cnt",
				"happp.msg.stkt.updt.data.http_req_cnt",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_http_req_rate_curr_tick,
			{
				"    http_req_rate curr. tick",
				"happp.msg.stkt.updt.data.http_req_rate.curr_tick",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_http_req_rate_curr_ctr,
			{
				"    http_req_rate curr. ctr.",
				"happp.msg.stkt.updt.data.http_req_rate.curr_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_http_req_rate_prev_ctr,
			{
				"    http_req_rate prev. ctr.",
				"happp.msg.stkt.updt.data.http_req_rate.prev_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_http_err_cnt,
			{
				"    http_err_cnt",
				"happp.msg.stkt.updt.data.http_err_cnt",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_http_err_rate_curr_tick,
			{
				"    http_err_rate curr. tick",
				"happp.msg.stkt.updt.data.http_err_rate.curr_tick",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_http_err_rate_curr_ctr,
			{
				"    http_err_rate curr. ctr.",
				"happp.msg.stkt.updt.data.http_err_rate.curr_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_http_err_rate_prev_ctr,
			{
				"    http_err_rate prev. ctr.",
				"happp.msg.stkt.updt.data.http_err_rate.prev_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_bytes_in_cnt,
			{
				"    bytes_in_cnt",
				"happp.msg.stkt.updt.data.bytes_in_cnt",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_bytes_in_rate_curr_tick,
			{
				"    bytes_in_rate curr. tick",
				"happp.msg.stkt.updt.data.bytes_in_rate.curr_tick",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_bytes_in_rate_curr_ctr,
			{
				"    bytes_in_rate curr. ctr.",
				"happp.msg.stkt.updt.data.bytes_in_rate.curr_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_bytes_in_rate_prev_ctr,
			{
				"    bytes_in_rate prev. ctr.",
				"happp.msg.stkt.updt.data.bytes_in_rate.prev_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_bytes_out_cnt,
			{
				"    bytes_out_cnt",
				"happp.msg.stkt.updt.data.bytes_out_cnt",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_bytes_out_rate_curr_tick,
			{
				"    bytes_out_rate curr. tick",
				"happp.msg.stkt.updt.data.bytes_out_rate.curr_tick",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_bytes_out_rate_curr_ctr,
			{
				"    bytes_out_rate curr. ctr.",
				"happp.msg.stkt.updt.data.bytes_out_rate.curr_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_data_bytes_out_rate_prev_ctr,
			{
				"    bytes_out_rate prev. ctr.",
				"happp.msg.stkt.updt.data.bytes_out_rate.prev_ctr",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_ack_table_id,
			{
				"    remote table Id",
				"happp.msg.stkt.updt.ack.table_id",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_happp_stkt_updt_ack_update_id,
			{
				"    update Id", "happp.msg.stkt.updt.ack.update_id",
				FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_happp,
		&ett_happp_msg
	};

	/* Register the protocol name and description */
	proto_happp = proto_register_protocol("HAProxy Peers Protocol", "HAPPP", "happp");

	/* Required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_happp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

static gboolean
dissect_happp_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	size_t proto_strlen;
	conversation_t *conversation;

	proto_strlen = strlen(HAPPP_PROTOCOL);

	if (tvb_captured_length(tvb) < proto_strlen + 1)
		return FALSE;

	/* Check that we received a line beginning with HAPPP_PROTOCOL
	 * followed by a space character.
	 */
	if (tvb_strneql(tvb, 0, HAPPP_PROTOCOL, proto_strlen) ||
	    tvb_get_guint8(tvb, proto_strlen) != ' ')
		return FALSE;

	conversation = find_or_create_conversation(pinfo);
	if (!conversation)
		return FALSE;

	conversation_set_dissector(conversation, happp_tcp_handle);
	dissect_happp_tcp(tvb, pinfo, tree, data);

	return TRUE;
}

/* Simpler form of proto_reg_handoff_happp which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_happp(void)
{
	/* Use create_dissector_handle() to indicate that dissect_happp_tcp()
	 * returns the number of bytes it dissected (or 0 if it thinks the packet
	 * does not belong to HAProxy Peers Protocol).
	 */
	happp_tcp_handle = create_dissector_handle(dissect_happp_tcp, proto_happp);
	heur_dissector_add("tcp", dissect_happp_heur_tcp, "HAPPP over TCP", "happp_tcp",
	                   proto_happp, HEURISTIC_ENABLE);
}

