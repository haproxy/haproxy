/*
 * MQTT Protocol
 *
 * Copyright 2020 Baptiste Assmann <bedis9@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/chunk.h>
#include <haproxy/mqtt.h>

uint8_t mqtt_cpt_flags[MQTT_CPT_ENTRIES] = {
	[MQTT_CPT_INVALID]     = 0x00,
	[MQTT_CPT_CONNECT]     = 0x00,
	[MQTT_CPT_CONNACK]     = 0x00,

	/* MQTT_CPT_PUBLISH flags can have different values (DUP, QoS, RETAIN), must be
	 * check more carefully
	 */
	[MQTT_CPT_PUBLISH]     = 0x0F,

	[MQTT_CPT_PUBACK]      = 0x00,
	[MQTT_CPT_PUBREC]      = 0x00,
	[MQTT_CPT_PUBREL]      = 0x02,
	[MQTT_CPT_PUBCOMP]     = 0x00,
	[MQTT_CPT_SUBSCRIBE]   = 0x02,
	[MQTT_CPT_SUBACK]      = 0x00,
	[MQTT_CPT_UNSUBSCRIBE] = 0x02,
	[MQTT_CPT_UNSUBACK]    = 0x00,
	[MQTT_CPT_PINGREQ]     = 0x00,
	[MQTT_CPT_PINGRESP]    = 0x00,
	[MQTT_CPT_DISCONNECT]  = 0x00,
	[MQTT_CPT_AUTH]        = 0x00,
};

const struct ist mqtt_fields_string[MQTT_FN_ENTRIES] = {
	[MQTT_FN_INVALID]                            = IST(""),

	/* it's MQTT 3.1.1 and 5.0, those fields have no unique id, so we use strings */
	[MQTT_FN_FLAGS]                              = IST("flags"),
	[MQTT_FN_REASON_CODE]                        = IST("reason_code"),       /* MQTT 3.1.1: return_code */
	[MQTT_FN_PROTOCOL_NAME]                      = IST("protocol_name"),
	[MQTT_FN_PROTOCOL_VERSION]                   = IST("protocol_version"),  /* MQTT 3.1.1: protocol_level */
	[MQTT_FN_CLIENT_IDENTIFIER]                  = IST("client_identifier"),
	[MQTT_FN_WILL_TOPIC]                         = IST("will_topic"),
	[MQTT_FN_WILL_PAYLOAD]                       = IST("will_payload"),      /* MQTT 3.1.1: will_message */
	[MQTT_FN_USERNAME]                           = IST("username"),
	[MQTT_FN_PASSWORD]                           = IST("password"),
	[MQTT_FN_KEEPALIVE]                          = IST("keepalive"),
	/* from here, it's MQTT 5.0 only */
	[MQTT_FN_PAYLOAD_FORMAT_INDICATOR]           = IST("1"),
	[MQTT_FN_MESSAGE_EXPIRY_INTERVAL]            = IST("2"),
	[MQTT_FN_CONTENT_TYPE]                       = IST("3"),
	[MQTT_FN_RESPONSE_TOPIC]                     = IST("8"),
	[MQTT_FN_CORRELATION_DATA]                   = IST("9"),
	[MQTT_FN_SUBSCRIPTION_IDENTIFIER]            = IST("11"),
	[MQTT_FN_SESSION_EXPIRY_INTERVAL]            = IST("17"),
	[MQTT_FN_ASSIGNED_CLIENT_IDENTIFIER]         = IST("18"),
	[MQTT_FN_SERVER_KEEPALIVE]                   = IST("19"),
	[MQTT_FN_AUTHENTICATION_METHOD]              = IST("21"),
	[MQTT_FN_AUTHENTICATION_DATA]                = IST("22"),
	[MQTT_FN_REQUEST_PROBLEM_INFORMATION]        = IST("23"),
	[MQTT_FN_DELAY_INTERVAL]                     = IST("24"),
	[MQTT_FN_REQUEST_RESPONSE_INFORMATION]       = IST("25"),
	[MQTT_FN_RESPONSE_INFORMATION]               = IST("26"),
	[MQTT_FN_SERVER_REFERENCE]                   = IST("28"),
	[MQTT_FN_REASON_STRING]                      = IST("31"),
	[MQTT_FN_RECEIVE_MAXIMUM]                    = IST("33"),
	[MQTT_FN_TOPIC_ALIAS_MAXIMUM]                = IST("34"),
	[MQTT_FN_TOPIC_ALIAS]                        = IST("35"),
	[MQTT_FN_MAXIMUM_QOS]                        = IST("36"),
	[MQTT_FN_RETAIN_AVAILABLE]                   = IST("37"),
	[MQTT_FN_USER_PROPERTY]                      = IST("38"),
	[MQTT_FN_MAXIMUM_PACKET_SIZE]                = IST("39"),
	[MQTT_FN_WILDCARD_SUBSCRIPTION_AVAILABLE]    = IST("40"),
	[MQTT_FN_SUBSCRIPTION_IDENTIFIERS_AVAILABLE] = IST("41"),
	[MQTT_FN_SHARED_SUBSCRIPTION_AVAILABLE]      = IST("42"),
};

/* list of supported capturable field names for each MQTT control packet type */
const uint64_t mqtt_fields_per_packet[MQTT_CPT_ENTRIES] = {
	[MQTT_CPT_INVALID]     = 0,

	[MQTT_CPT_CONNECT]     = MQTT_FN_BIT_PROTOCOL_NAME                     | MQTT_FN_BIT_PROTOCOL_VERSION                   |
	                         MQTT_FN_BIT_FLAGS                             | MQTT_FN_BIT_KEEPALIVE                          |
	                         MQTT_FN_BIT_SESSION_EXPIRY_INTERVAL           | MQTT_FN_BIT_RECEIVE_MAXIMUM                    |
	                         MQTT_FN_BIT_MAXIMUM_PACKET_SIZE               | MQTT_FN_BIT_TOPIC_ALIAS_MAXIMUM                |
	                         MQTT_FN_BIT_REQUEST_RESPONSE_INFORMATION      | MQTT_FN_BIT_REQUEST_PROBLEM_INFORMATION        |
	                         MQTT_FN_BIT_USER_PROPERTY                     | MQTT_FN_BIT_AUTHENTICATION_METHOD              |
	                         MQTT_FN_BIT_AUTHENTICATION_DATA               | MQTT_FN_BIT_CLIENT_IDENTIFIER                  |
	                         MQTT_FN_BIT_DELAY_INTERVAL                    | MQTT_FN_BIT_PAYLOAD_FORMAT_INDICATOR           |
	                         MQTT_FN_BIT_MESSAGE_EXPIRY_INTERVAL           | MQTT_FN_BIT_CONTENT_TYPE                       |
	                         MQTT_FN_BIT_RESPONSE_TOPIC                    | MQTT_FN_BIT_CORRELATION_DATA                   |
	                         MQTT_FN_BIT_USER_PROPERTY                     | MQTT_FN_BIT_WILL_TOPIC                         |
	                         MQTT_FN_BIT_WILL_PAYLOAD                      | MQTT_FN_BIT_USERNAME                           |
	                         MQTT_FN_BIT_PASSWORD,

	[MQTT_CPT_CONNACK]     = MQTT_FN_BIT_FLAGS                             | MQTT_FN_BIT_PROTOCOL_VERSION                   |
	                         MQTT_FN_BIT_REASON_CODE                       | MQTT_FN_BIT_SESSION_EXPIRY_INTERVAL            |
	                         MQTT_FN_BIT_RECEIVE_MAXIMUM                   | MQTT_FN_BIT_MAXIMUM_QOS                        |
	                         MQTT_FN_BIT_RETAIN_AVAILABLE                  | MQTT_FN_BIT_MAXIMUM_PACKET_SIZE                |
	                         MQTT_FN_BIT_ASSIGNED_CLIENT_IDENTIFIER        | MQTT_FN_BIT_TOPIC_ALIAS_MAXIMUM                |
	                         MQTT_FN_BIT_REASON_STRING                     | MQTT_FN_BIT_WILDCARD_SUBSCRIPTION_AVAILABLE    |
	                         MQTT_FN_BIT_SUBSCRIPTION_IDENTIFIERS_AVAILABLE| MQTT_FN_BIT_SHARED_SUBSCRIPTION_AVAILABLE      |
	                         MQTT_FN_BIT_SERVER_KEEPALIVE                  | MQTT_FN_BIT_RESPONSE_INFORMATION               |
	                         MQTT_FN_BIT_SERVER_REFERENCE                  | MQTT_FN_BIT_USER_PROPERTY                      |
	                         MQTT_FN_BIT_AUTHENTICATION_METHOD             | MQTT_FN_BIT_AUTHENTICATION_DATA,

	[MQTT_CPT_PUBLISH]     = MQTT_FN_BIT_PAYLOAD_FORMAT_INDICATOR          | MQTT_FN_BIT_MESSAGE_EXPIRY_INTERVAL            |
	                         MQTT_FN_BIT_CONTENT_TYPE                      | MQTT_FN_BIT_RESPONSE_TOPIC                     |
	                         MQTT_FN_BIT_CORRELATION_DATA                  | MQTT_FN_BIT_SUBSCRIPTION_IDENTIFIER            |
	                         MQTT_FN_BIT_TOPIC_ALIAS                       | MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_PUBACK]      = MQTT_FN_BIT_REASON_CODE | MQTT_FN_BIT_REASON_STRING | MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_PUBREC]      = MQTT_FN_BIT_REASON_CODE | MQTT_FN_BIT_REASON_STRING | MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_PUBREL]      = MQTT_FN_BIT_REASON_CODE | MQTT_FN_BIT_REASON_STRING | MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_PUBCOMP]     = MQTT_FN_BIT_REASON_CODE | MQTT_FN_BIT_REASON_STRING | MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_SUBSCRIBE]   = MQTT_FN_BIT_SUBSCRIPTION_IDENTIFIER | MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_SUBACK]      = MQTT_FN_BIT_REASON_STRING | MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_UNSUBSCRIBE] = MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_UNSUBACK]    = MQTT_FN_BIT_REASON_STRING | MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_PINGREQ]     = 0,

	[MQTT_CPT_PINGRESP]    = 0,

	[MQTT_CPT_DISCONNECT]  = MQTT_FN_BIT_REASON_CODE                       | MQTT_FN_BIT_SESSION_EXPIRY_INTERVAL            |
	                         MQTT_FN_BIT_SERVER_REFERENCE                  | MQTT_FN_BIT_REASON_STRING                      |
	                         MQTT_FN_BIT_USER_PROPERTY,

	[MQTT_CPT_AUTH]        = MQTT_FN_BIT_AUTHENTICATION_METHOD             | MQTT_FN_BIT_AUTHENTICATION_DATA                |
	                         MQTT_FN_BIT_REASON_STRING                     | MQTT_FN_BIT_USER_PROPERTY,
};

/* Checks the first byte of a message to read the fixed header and extract the
 * packet type and flags. <parser> is supposed to point to the fix header byte.
 *
 * Fix header looks like:
 * +-------+-----------+-----------+-----------+---------+----------+----------+---------+------------+
 * |  bit  |    7      |     6     |    5      |    4    |     3    |     2    |     1   |     0      |
 * +-------+-----------+-----------+-----------+---------+----------+----------+---------+------------+
 * | field |          MQTT Control Packet Type           | Flags specific to each Control Packet type |
 * +-------+---------------------------------------------+--------------------------------------------+
 *
 * On success, <ptk> is updated with the packet type and flags and the new parser
 * state is returned. On error, IST_NULL is returned.
 */
static inline struct ist mqtt_read_fixed_hdr(struct ist parser, struct mqtt_pkt *pkt)
{
	uint8_t type  = (uint8_t)*istptr(parser);
	uint8_t ptype = (type & 0xF0) >> 4;
	uint8_t flags = type & 0x0F;

	if (ptype == MQTT_CPT_INVALID || ptype >= MQTT_CPT_ENTRIES || flags != mqtt_cpt_flags[ptype])
		return IST_NULL;

	pkt->fixed_hdr.type = ptype;
	pkt->fixed_hdr.flags = flags;
	return istnext(parser);
}

/* Reads a one byte integer. more information here :
 *     https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901007
 *
 * <parser> is supposed to point to the first byte of the integer. On success
 * the integer is stored in <*i>, if provided, and the new parser state is returned. On
 * error, IST_NULL is returned.
*/
static inline struct ist mqtt_read_1byte_int(struct ist parser, uint8_t *i)
{
	if (istlen(parser) < 1)
		return IST_NULL;
	if (i)
		*i = (uint8_t)*istptr(parser);
	parser = istadv(parser, 1);
	return parser;
}

/* Reads a two byte integer. more information here :
 *     https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901008
 *
 * <parser> is supposed to point to the first byte of the integer. On success
 * the integer is stored in <*i>, if provided, and the new parser state is returned. On
 * error, IST_NULL is returned.
*/
static inline struct ist mqtt_read_2byte_int(struct ist parser, uint16_t *i)
{
	if (istlen(parser) < 2)
		return IST_NULL;
	if (i) {
		*i  = (uint8_t)*istptr(parser) << 8;
		*i += (uint8_t)*(istptr(parser) + 1);
	}
	parser = istadv(parser, 2);
	return parser;
}

/* Reads a four byte integer. more information here :
 *     https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901009
 *
 * <parser> is supposed to point to the first byte of the integer. On success
 * the integer is stored in <*i>, if provided, and the new parser state is returned. On
 * error, IST_NULL is returned.
*/
static inline struct ist mqtt_read_4byte_int(struct ist parser, uint32_t *i)
{
	if (istlen(parser) < 4)
		return IST_NULL;
	if (i) {
		*i  = (uint8_t)*istptr(parser) << 24;
		*i += (uint8_t)*(istptr(parser) + 1) << 16;
		*i += (uint8_t)*(istptr(parser) + 2) << 8;
		*i += (uint8_t)*(istptr(parser) + 3);
	}
	parser = istadv(parser, 4);
	return parser;
}

/* Reads a variable byte integer. more information here :
 *   https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718023
 *   https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901011
 *
 * It is encoded using a variable length encoding scheme which uses a single
 * byte for values up to 127.  Larger values are handled as follows. The least
 * significant seven bits of each byte encode the data, and the most significant
 * bit is used to indicate that there are following bytes in the representation.
 * Thus each byte encodes 128 values and a "continuation bit".
 *
 * The maximum number of bytes in the Remaining Length field is four
 * (MQTT_REMAINING_LENGHT_MAX_SIZE).
 *
 * <parser> is supposed to point to the first byte of the integer. On success
 * the integer is stored in <*i> and the new parser state is returned. On
 * error, IST_NULL is returned.
 */
static inline struct ist mqtt_read_varint(struct ist parser, uint32_t *i)
{
	int off, m;

	off = m = 0;
	if (i)
		*i = 0;
	for (off = 0; off < MQTT_REMAINING_LENGHT_MAX_SIZE && istlen(parser); off++) {
		uint8_t byte = (uint8_t)*istptr(parser);

		if (i) {
			*i += (byte & 127) << m;
			m += 7; /* preparing <m> for next byte */
		}
		parser = istnext(parser);

		/* we read the latest byte for the remaining length field */
		if (byte <= 127)
			break;
	}

	if (off == MQTT_REMAINING_LENGHT_MAX_SIZE)
		return IST_NULL;
	return parser;
}

/* Reads a MQTT string. more information here :
 *   http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718016
 *   https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901010
 *
 * In MQTT, strings are prefixed by their size, encoded over 2 bytes:
 *   byte 1:  length MSB
 *   byte 2:  length LSB
 *   byte 3:  string
 *   ...
 *
 *   string size is MSB * 256 + LSB
 *
 * <parser> is supposed to point to the first byte of the string. On success the
 * string is stored in <*str>, if provided, and the new parser state is
 * returned. On error, IST_NULL is returned.
 */
static inline struct ist mqtt_read_string(struct ist parser, struct ist *str)
{
	uint16_t len;

	/* read and compute the string length */
	if (istlen(parser) <= 2)
		goto error;

	len = ((uint16_t)*istptr(parser) << 8) + (uint16_t)*(istptr(parser) + 1);
	parser = istadv(parser, 2);
	if (istlen(parser) < len)
		goto error;

	if (str) {
		str->ptr = istptr(parser);
		str->len = len;
	}

	return istadv(parser, len);

  error:
	return IST_NULL;
}

/* Helper function to convert a unsigned integer to a string. The result is
 * written in <buf>. On success, the written size is returned, otherwise, on
 * error, 0 is returned.
 */
static inline size_t mqtt_uint2str(struct buffer *buf, uint32_t i)
{
	char *end;

	end = ultoa_o(i, buf->area, buf->size);
	if (!end)
		return 0;
	buf->data = end - buf->area;
	return buf->data;
}

/* Extracts the value of a <fieldname_id> of type <type> from a given MQTT
 * message <msg>.  IST_NULL is returned if an error occurred while parsing or if
 * the field could not be found. If more data are required, the message with a
 * length set to 0 is returned. If the field is found, the response is returned
 * as a struct ist.
 */
struct ist mqtt_field_value(struct ist msg, int type, int fieldname_id)
{
	struct buffer *trash = get_trash_chunk();
	struct mqtt_pkt mpkt;
	struct ist res;

	switch (mqtt_validate_message(msg, &mpkt)) {
	case MQTT_VALID_MESSAGE:
		if (mpkt.fixed_hdr.type != type)
			goto not_found_or_invalid;
		break;
	case MQTT_NEED_MORE_DATA:
	     goto need_more;
	case MQTT_INVALID_MESSAGE:
		goto not_found_or_invalid;
	}

	switch (type) {
	case MQTT_CPT_CONNECT:
		switch (fieldname_id) {
		case MQTT_FN_FLAGS:
			if (!mqtt_uint2str(trash, mpkt.data.connect.var_hdr.flags))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_PROTOCOL_NAME:
			if (!istlen(mpkt.data.connect.var_hdr.protocol_name))
				goto not_found_or_invalid;
			res = mpkt.data.connect.var_hdr.protocol_name;
			goto end;

		case MQTT_FN_PROTOCOL_VERSION:
			if (!mqtt_uint2str(trash, mpkt.data.connect.var_hdr.protocol_version))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_CLIENT_IDENTIFIER:
			if (!istlen(mpkt.data.connect.payload.client_identifier))
				goto not_found_or_invalid;
			res = mpkt.data.connect.payload.client_identifier;
			goto end;

		case MQTT_FN_WILL_TOPIC:
			if (!istlen(mpkt.data.connect.payload.will_topic))
				goto not_found_or_invalid;
			res = mpkt.data.connect.payload.will_topic;
			goto end;

		case MQTT_FN_WILL_PAYLOAD:
			if (!istlen(mpkt.data.connect.payload.will_payload))
				goto not_found_or_invalid;
			res = mpkt.data.connect.payload.will_payload;
			goto end;

		case MQTT_FN_USERNAME:
			if (!istlen(mpkt.data.connect.payload.username))
				goto not_found_or_invalid;
			res = mpkt.data.connect.payload.username;
			goto end;

		case MQTT_FN_PASSWORD:
			if (!istlen(mpkt.data.connect.payload.password))
				goto not_found_or_invalid;
			res = mpkt.data.connect.payload.password;
			goto end;

		case MQTT_FN_KEEPALIVE:
			    if (!mqtt_uint2str(trash, mpkt.data.connect.var_hdr.keepalive))
				    goto not_found_or_invalid;
			    res = ist2(trash->area, trash->data);
			    goto end;

		case MQTT_FN_PAYLOAD_FORMAT_INDICATOR:
			if ((mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0) ||
			    !(mpkt.data.connect.var_hdr.flags & MQTT_CONNECT_FL_WILL))
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connect.payload.will_props.payload_format_indicator))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_MESSAGE_EXPIRY_INTERVAL:
			if ((mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0) ||
			    !(mpkt.data.connect.var_hdr.flags & MQTT_CONNECT_FL_WILL))
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connect.payload.will_props.message_expiry_interval))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_CONTENT_TYPE:
			if ((mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0) ||
			    !(mpkt.data.connect.var_hdr.flags & MQTT_CONNECT_FL_WILL))
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connect.payload.will_props.content_type))
				goto not_found_or_invalid;
			res = mpkt.data.connect.payload.will_props.content_type;
			goto end;

		case MQTT_FN_RESPONSE_TOPIC:
			if ((mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0) ||
			    !(mpkt.data.connect.var_hdr.flags & MQTT_CONNECT_FL_WILL))
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connect.payload.will_props.response_topic))
				goto not_found_or_invalid;
			res = mpkt.data.connect.payload.will_props.response_topic;
			goto end;

		case MQTT_FN_CORRELATION_DATA:
			if ((mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0) ||
			    !(mpkt.data.connect.var_hdr.flags & MQTT_CONNECT_FL_WILL))
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connect.payload.will_props.correlation_data))
				goto not_found_or_invalid;
			res = mpkt.data.connect.payload.will_props.correlation_data;
			goto end;

		case MQTT_FN_SESSION_EXPIRY_INTERVAL:
			if (mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connect.var_hdr.props.session_expiry_interval))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_AUTHENTICATION_METHOD:
			if (mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connect.var_hdr.props.authentication_method))
				goto not_found_or_invalid;
			res = mpkt.data.connect.var_hdr.props.authentication_method;
			goto end;

		case MQTT_FN_AUTHENTICATION_DATA:
			if (mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connect.var_hdr.props.authentication_data))
				goto not_found_or_invalid;
			res = mpkt.data.connect.var_hdr.props.authentication_data;
			goto end;

		case MQTT_FN_REQUEST_PROBLEM_INFORMATION:
			if (mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connect.var_hdr.props.request_problem_information))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_DELAY_INTERVAL:
			if ((mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0) ||
			    !(mpkt.data.connect.var_hdr.flags & MQTT_CONNECT_FL_WILL))
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connect.payload.will_props.delay_interval))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_REQUEST_RESPONSE_INFORMATION:
			if (mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connect.var_hdr.props.request_response_information))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_RECEIVE_MAXIMUM:
			if (mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connect.var_hdr.props.receive_maximum))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_TOPIC_ALIAS_MAXIMUM:
			if (mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connect.var_hdr.props.topic_alias_maximum))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_MAXIMUM_PACKET_SIZE:
			if (mpkt.data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connect.var_hdr.props.maximum_packet_size))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		default:
			goto not_found_or_invalid;
		}
		break;

	case MQTT_CPT_CONNACK:
		switch (fieldname_id) {
		case MQTT_FN_FLAGS:
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.flags))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_REASON_CODE:
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.reason_code))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_PROTOCOL_VERSION:
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.protocol_version))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_SESSION_EXPIRY_INTERVAL:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.session_expiry_interval))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_ASSIGNED_CLIENT_IDENTIFIER:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connack.var_hdr.props.assigned_client_identifier))
				goto not_found_or_invalid;
			res = mpkt.data.connack.var_hdr.props.assigned_client_identifier;
			goto end;

		case MQTT_FN_SERVER_KEEPALIVE:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.server_keepalive))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_AUTHENTICATION_METHOD:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connack.var_hdr.props.authentication_method))
				goto not_found_or_invalid;
			res = mpkt.data.connack.var_hdr.props.authentication_method;
			goto end;

		case MQTT_FN_AUTHENTICATION_DATA:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connack.var_hdr.props.authentication_data))
				goto not_found_or_invalid;
			res = mpkt.data.connack.var_hdr.props.authentication_data;
			goto end;

		case MQTT_FN_RESPONSE_INFORMATION:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connack.var_hdr.props.response_information))
				goto not_found_or_invalid;
			res = mpkt.data.connack.var_hdr.props.response_information;
			goto end;

		case MQTT_FN_SERVER_REFERENCE:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connack.var_hdr.props.server_reference))
				goto not_found_or_invalid;
			res = mpkt.data.connack.var_hdr.props.server_reference;
			goto end;

		case MQTT_FN_REASON_STRING:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!istlen(mpkt.data.connack.var_hdr.props.reason_string))
				goto not_found_or_invalid;
			res = mpkt.data.connack.var_hdr.props.reason_string;
			goto end;

		case MQTT_FN_RECEIVE_MAXIMUM:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.receive_maximum))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_TOPIC_ALIAS_MAXIMUM:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.topic_alias_maximum))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_MAXIMUM_QOS:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.maximum_qos))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_RETAIN_AVAILABLE:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.retain_available))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_MAXIMUM_PACKET_SIZE:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.maximum_packet_size))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_WILDCARD_SUBSCRIPTION_AVAILABLE:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.wildcard_subscription_available))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_SUBSCRIPTION_IDENTIFIERS_AVAILABLE:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.subscription_identifiers_available))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		case MQTT_FN_SHARED_SUBSCRIPTION_AVAILABLE:
			if (mpkt.data.connack.var_hdr.protocol_version != MQTT_VERSION_5_0)
				goto not_found_or_invalid;
			if (!mqtt_uint2str(trash, mpkt.data.connack.var_hdr.props.shared_subsription_available))
				goto not_found_or_invalid;
			res = ist2(trash->area, trash->data);
			goto end;

		default:
			goto not_found_or_invalid;
		}
		break;

	default:
		goto not_found_or_invalid;
	}

  end:
	return res;

  need_more:
	return ist2(istptr(msg), 0);

  not_found_or_invalid:
	return IST_NULL;
}

/* Parses a CONNECT packet :
 *   https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718028
 *   https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901033
 *
 * <parser> should point right after the MQTT fixed header. The remaining length
 * was already checked, thus missing data is an error. On success, the result of
 * the parsing is stored in <mpkt>.
 *
 * Returns:
 *  MQTT_INVALID_MESSAGE if the CONNECT message is invalid
 *  MQTT_VALID_MESSAGE   if the CONNECT message looks valid
 */
static int mqtt_parse_connect(struct ist parser, struct mqtt_pkt *mpkt)
{
	/* The parser length is stored to be sure exactly consumed the announced
	 * remaining length. */
	size_t orig_len = istlen(parser);
	int ret = MQTT_INVALID_MESSAGE;

	/*
	 * parsing variable header
	 */
	/* read protocol_name */
	parser = mqtt_read_string(parser, &mpkt->data.connect.var_hdr.protocol_name);
	if (!isttest(parser) || !isteqi(mpkt->data.connect.var_hdr.protocol_name, ist("MQTT")))
		goto end;

	/* read protocol_version */
	parser = mqtt_read_1byte_int(parser, &mpkt->data.connect.var_hdr.protocol_version);
	if (!isttest(parser))
		goto end;
	if (mpkt->data.connect.var_hdr.protocol_version != MQTT_VERSION_3_1_1 &&
	    mpkt->data.connect.var_hdr.protocol_version != MQTT_VERSION_5_0)
		goto end;

	/* read flags */
	/* bit 1 is 'reserved' and must be set to 0 in CONNECT message flags */
	parser = mqtt_read_1byte_int(parser, &mpkt->data.connect.var_hdr.flags);
	if (!isttest(parser) || (mpkt->data.connect.var_hdr.flags & MQTT_CONNECT_FL_RESERVED))
		goto end;

	/* if WILL flag must be set to have WILL_QOS flag or WILL_RETAIN set */
	if ((mpkt->data.connect.var_hdr.flags & (MQTT_CONNECT_FL_WILL|MQTT_CONNECT_FL_WILL_QOS|MQTT_CONNECT_FL_WILL_RETAIN)) == MQTT_CONNECT_FL_WILL_QOS)
	    goto end;

	/* read keepalive */
	parser = mqtt_read_2byte_int(parser, &mpkt->data.connect.var_hdr.keepalive);
	if (!isttest(parser))
		goto end;

	/* read properties, only available in MQTT_VERSION_5_0 */
	if (mpkt->data.connect.var_hdr.protocol_version == MQTT_VERSION_5_0) {
		struct ist props;
		unsigned int user_prop_idx = 0;
		uint64_t fields = 0;
		uint32_t plen = 0;

		parser = mqtt_read_varint(parser, &plen);
		if (!isttest(parser) || istlen(parser) < plen)
			goto end;
		props  = ist2(istptr(parser), plen);
		parser = istadv(parser, props.len);

		while (istlen(props) > 0) {
			switch (*istptr(props)) {
			case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
				if (fields & MQTT_FN_BIT_SESSION_EXPIRY_INTERVAL)
					goto end;
				props = mqtt_read_4byte_int(istnext(props), &mpkt->data.connect.var_hdr.props.session_expiry_interval);
				fields |= MQTT_FN_BIT_SESSION_EXPIRY_INTERVAL;
				break;

			case MQTT_PROP_RECEIVE_MAXIMUM:
				if (fields & MQTT_FN_BIT_RECEIVE_MAXIMUM)
					goto end;
				props = mqtt_read_2byte_int(istnext(props), &mpkt->data.connect.var_hdr.props.receive_maximum);
				/* cannot be 0 */
				if (!mpkt->data.connect.var_hdr.props.receive_maximum)
					goto end;
				fields |= MQTT_FN_BIT_RECEIVE_MAXIMUM;
				break;

			case MQTT_PROP_MAXIMUM_PACKET_SIZE:
				if (fields & MQTT_FN_BIT_MAXIMUM_PACKET_SIZE)
					goto end;
				props = mqtt_read_4byte_int(istnext(props), &mpkt->data.connect.var_hdr.props.maximum_packet_size);
				/* cannot be 0 */
				if (!mpkt->data.connect.var_hdr.props.maximum_packet_size)
					goto end;
				fields |= MQTT_FN_BIT_MAXIMUM_PACKET_SIZE;
				break;

			case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
				if (fields & MQTT_FN_BIT_TOPIC_ALIAS)
					goto end;
				props = mqtt_read_2byte_int(istnext(props), &mpkt->data.connect.var_hdr.props.topic_alias_maximum);
				fields |= MQTT_FN_BIT_TOPIC_ALIAS;
				break;

			case MQTT_PROP_REQUEST_RESPONSE_INFORMATION:
				if (fields & MQTT_FN_BIT_REQUEST_RESPONSE_INFORMATION)
					goto end;
				props = mqtt_read_1byte_int(istnext(props), &mpkt->data.connect.var_hdr.props.request_response_information);
				/* can have only 2 values: 0 or 1 */
				if (mpkt->data.connect.var_hdr.props.request_response_information > 1)
					goto end;
				fields |= MQTT_FN_BIT_REQUEST_RESPONSE_INFORMATION;
				break;

			case MQTT_PROP_REQUEST_PROBLEM_INFORMATION:
				if (fields & MQTT_FN_BIT_REQUEST_PROBLEM_INFORMATION)
					goto end;
				props = mqtt_read_1byte_int(istnext(props), &mpkt->data.connect.var_hdr.props.request_problem_information);
				/* can have only 2 values: 0 or 1 */
				if (mpkt->data.connect.var_hdr.props.request_problem_information > 1)
					goto end;
				fields |= MQTT_FN_BIT_REQUEST_PROBLEM_INFORMATION;
				break;

			case MQTT_PROP_USER_PROPERTIES:
				/* if we reached MQTT_PROP_USER_PROPERTY_ENTRIES already, then
				 * we start writing over the first property */
				if (user_prop_idx >= MQTT_PROP_USER_PROPERTY_ENTRIES)
					user_prop_idx = 0;

				/* read user property name and value */
				props = mqtt_read_string(istnext(props), &mpkt->data.connect.var_hdr.props.user_props[user_prop_idx].name);
				if (!isttest(props))
					goto end;
				props = mqtt_read_string(props, &mpkt->data.connect.var_hdr.props.user_props[user_prop_idx].value);
				++user_prop_idx;
				break;

			case MQTT_PROP_AUTHENTICATION_METHOD:
				if (fields & MQTT_FN_BIT_AUTHENTICATION_METHOD)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connect.var_hdr.props.authentication_method);
				fields |= MQTT_FN_BIT_AUTHENTICATION_METHOD;
				break;

			case MQTT_PROP_AUTHENTICATION_DATA:
				if (fields & MQTT_FN_BIT_AUTHENTICATION_DATA)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connect.var_hdr.props.authentication_data);
				fields |= MQTT_FN_BIT_AUTHENTICATION_DATA;
				break;

			default:
				goto end;
			}

			if (!isttest(props))
				goto end;
		}
	}

	/* cannot have auth data without auth method */
	if (!istlen(mpkt->data.connect.var_hdr.props.authentication_method) &&
	    istlen(mpkt->data.connect.var_hdr.props.authentication_data))
	    goto end;

	/* parsing payload
	 *
	 * Content of payload is related to flags parsed above and the field order is pre-defined:
	 *   Client Identifier, Will Topic, Will Message, User Name, Password
	 */
	/* read client identifier */
	parser = mqtt_read_string(parser, &mpkt->data.connect.payload.client_identifier);
	if (!isttest(parser) || !istlen(mpkt->data.connect.payload.client_identifier))
		goto end;

	/* read Will Properties, for MQTT v5 only
	 * https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901060
	 */
	if ((mpkt->data.connect.var_hdr.protocol_version == MQTT_VERSION_5_0) &&
	    (mpkt->data.connect.var_hdr.flags & MQTT_CONNECT_FL_WILL)) {
		struct ist props;
		unsigned int user_prop_idx = 0;
		uint64_t fields = 0;
		uint32_t plen = 0;

		parser = mqtt_read_varint(parser, &plen);
		if (!isttest(parser) || istlen(parser) < plen)
			goto end;
		props  = ist2(istptr(parser), plen);
		parser = istadv(parser, props.len);

		while (istlen(props) > 0) {
			switch (*istptr(props)) {
			case MQTT_PROP_WILL_DELAY_INTERVAL:
				if (fields & MQTT_FN_BIT_DELAY_INTERVAL)
					goto end;
				props = mqtt_read_4byte_int(istnext(props), &mpkt->data.connect.payload.will_props.delay_interval);
				fields |= MQTT_FN_BIT_DELAY_INTERVAL;
				break;

			case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
				if (fields & MQTT_FN_BIT_PAYLOAD_FORMAT_INDICATOR)
					goto end;
				props = mqtt_read_1byte_int(istnext(props), &mpkt->data.connect.payload.will_props.payload_format_indicator);
				/* can have only 2 values: 0 or 1 */
				if (mpkt->data.connect.payload.will_props.payload_format_indicator > 1)
					goto end;
				fields |= MQTT_FN_BIT_PAYLOAD_FORMAT_INDICATOR;
				break;

			case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
				if (fields & MQTT_FN_BIT_MESSAGE_EXPIRY_INTERVAL)
					goto end;
				props = mqtt_read_4byte_int(istnext(props), &mpkt->data.connect.payload.will_props.message_expiry_interval);
				fields |= MQTT_FN_BIT_MESSAGE_EXPIRY_INTERVAL;
				break;

			case MQTT_PROP_CONTENT_TYPE:
				if (fields & MQTT_FN_BIT_CONTENT_TYPE)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connect.payload.will_props.content_type);
				fields |= MQTT_FN_BIT_CONTENT_TYPE;
				break;

			case MQTT_PROP_RESPONSE_TOPIC:
				if (fields & MQTT_FN_BIT_RESPONSE_TOPIC)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connect.payload.will_props.response_topic);
				fields |= MQTT_FN_BIT_RESPONSE_TOPIC;
				break;

			case MQTT_PROP_CORRELATION_DATA:
				if (fields & MQTT_FN_BIT_CORRELATION_DATA)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connect.payload.will_props.correlation_data);
				fields |= MQTT_FN_BIT_CORRELATION_DATA;
				break;

			case MQTT_PROP_USER_PROPERTIES:
				/* if we reached MQTT_PROP_USER_PROPERTY_ENTRIES already, then
				 * we start writing over the first property */
				if (user_prop_idx >= MQTT_PROP_USER_PROPERTY_ENTRIES)
					user_prop_idx = 0;

				/* read user property name and value */
				props = mqtt_read_string(istnext(props), &mpkt->data.connect.payload.will_props.user_props[user_prop_idx].name);
				if (!isttest(props))
					goto end;
				props = mqtt_read_string(props, &mpkt->data.connect.payload.will_props.user_props[user_prop_idx].value);
				++user_prop_idx;
				break;

			default:
				goto end;
			}

			if (!isttest(props))
				goto end;
		}
	}

	/* read Will Topic and Will Message (MQTT 3.1.1) or Payload (MQTT 5.0) */
	if (mpkt->data.connect.var_hdr.flags & MQTT_CONNECT_FL_WILL) {
		parser = mqtt_read_string(parser, &mpkt->data.connect.payload.will_topic);
		if (!isttest(parser))
			goto end;
		parser = mqtt_read_string(parser, &mpkt->data.connect.payload.will_payload);
		if (!isttest(parser))
			goto end;
	}

	/* read User Name */
	if (mpkt->data.connect.var_hdr.flags & MQTT_CONNECT_FL_USERNAME) {
		parser = mqtt_read_string(parser, &mpkt->data.connect.payload.username);
		if (!isttest(parser))
			goto end;
	}

	/* read Password */
	if (mpkt->data.connect.var_hdr.flags & MQTT_CONNECT_FL_PASSWORD) {
		parser = mqtt_read_string(parser, &mpkt->data.connect.payload.password);
		if (!isttest(parser))
			goto end;
	}

	if ((orig_len - istlen(parser)) == mpkt->fixed_hdr.remaining_length)
		ret = MQTT_VALID_MESSAGE;

  end:
	return ret;
}

/* Parses a CONNACK packet :
 *   https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718033
 *   https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901074
 *
 * <parser> should point right after the MQTT fixed header. The remaining length
 * was already checked, thus missing data is an error. On success, the result of
 * the parsing is stored in <mpkt>.
 *
 * Returns:
 *  MQTT_INVALID_MESSAGE if the CONNECT message is invalid
 *  MQTT_VALID_MESSAGE   if the CONNECT message looks valid
 */
static int mqtt_parse_connack(struct ist parser, struct mqtt_pkt *mpkt)
{
	/* The parser length is stored to be sure exactly consumed the announced
	 * remaining length. */
	size_t orig_len = istlen(parser);
	int ret = MQTT_INVALID_MESSAGE;

	if (istlen(parser) < 2)
		goto end;
	else if (istlen(parser) == 2)
		mpkt->data.connack.var_hdr.protocol_version = MQTT_VERSION_3_1_1;
	else
		mpkt->data.connack.var_hdr.protocol_version = MQTT_VERSION_5_0;

	/*
	 * parsing variable header
	 */
	/* read flags */
	/* bits 7 to 1 on flags are reserved and must be 0 */
	parser = mqtt_read_1byte_int(parser, &mpkt->data.connack.var_hdr.flags);
	if (!isttest(parser) || (mpkt->data.connack.var_hdr.flags & 0xFE))
		goto end;

	/* read reason_code */
	parser = mqtt_read_1byte_int(parser, &mpkt->data.connack.var_hdr.reason_code);
	if (!isttest(parser))
		goto end;

	/* we can leave here for MQTT 3.1.1 */
	if (mpkt->data.connack.var_hdr.protocol_version == MQTT_VERSION_3_1_1) {
		if ((orig_len - istlen(parser)) == mpkt->fixed_hdr.remaining_length)
			ret = MQTT_VALID_MESSAGE;
		goto end;
	}

	/* read properties, only available in MQTT_VERSION_5_0 */
	if (mpkt->data.connack.var_hdr.protocol_version == MQTT_VERSION_5_0) {
		struct ist props;
		unsigned int user_prop_idx = 0;
		uint64_t fields = 0;
		uint32_t plen = 0;

		parser = mqtt_read_varint(parser, &plen);
		if (!isttest(parser) || istlen(parser) < plen)
			goto end;
		props  = ist2(istptr(parser), plen);
		parser = istadv(parser, props.len);

		while (istlen(props) > 0) {
			switch (*istptr(props)) {
			case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
				if (fields & MQTT_FN_BIT_SESSION_EXPIRY_INTERVAL)
					goto end;
				props = mqtt_read_4byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.session_expiry_interval);
				fields |= MQTT_FN_BIT_SESSION_EXPIRY_INTERVAL;
				break;

			case MQTT_PROP_RECEIVE_MAXIMUM:
				if (fields & MQTT_FN_BIT_RECEIVE_MAXIMUM)
					goto end;
				props = mqtt_read_2byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.receive_maximum);
				/* cannot be 0 */
				if (!mpkt->data.connack.var_hdr.props.receive_maximum)
					goto end;
				fields |= MQTT_FN_BIT_RECEIVE_MAXIMUM;
				break;

			case MQTT_PROP_MAXIMUM_QOS:
				if (fields & MQTT_FN_BIT_MAXIMUM_QOS)
					goto end;
				props = mqtt_read_1byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.maximum_qos);
				/* can have only 2 values: 0 or 1 */
				if (mpkt->data.connack.var_hdr.props.maximum_qos > 1)
					goto end;
				fields |= MQTT_FN_BIT_MAXIMUM_QOS;
				break;

			case MQTT_PROP_RETAIN_AVAILABLE:
				if (fields & MQTT_FN_BIT_RETAIN_AVAILABLE)
					goto end;
				props = mqtt_read_1byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.retain_available);
				/* can have only 2 values: 0 or 1 */
				if (mpkt->data.connack.var_hdr.props.retain_available > 1)
					goto end;
				fields |= MQTT_FN_BIT_RETAIN_AVAILABLE;
				break;

			case MQTT_PROP_MAXIMUM_PACKET_SIZE:
				if (fields & MQTT_FN_BIT_MAXIMUM_PACKET_SIZE)
					goto end;
				props = mqtt_read_4byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.maximum_packet_size);
				/* cannot be 0 */
				if (!mpkt->data.connack.var_hdr.props.maximum_packet_size)
					goto end;
				fields |= MQTT_FN_BIT_MAXIMUM_PACKET_SIZE;
				break;

			case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
				if (fields & MQTT_FN_BIT_ASSIGNED_CLIENT_IDENTIFIER)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connack.var_hdr.props.assigned_client_identifier);
				if (!istlen(mpkt->data.connack.var_hdr.props.assigned_client_identifier))
					goto end;
				fields |= MQTT_FN_BIT_ASSIGNED_CLIENT_IDENTIFIER;
				break;

			case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
				if (fields & MQTT_FN_BIT_TOPIC_ALIAS_MAXIMUM)
					goto end;
				props = mqtt_read_2byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.topic_alias_maximum);
				fields |= MQTT_FN_BIT_TOPIC_ALIAS_MAXIMUM;
				break;

			case MQTT_PROP_REASON_STRING:
				if (fields & MQTT_FN_BIT_REASON_STRING)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connack.var_hdr.props.reason_string);
				fields |= MQTT_FN_BIT_REASON_STRING;
				break;

			case MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
				if (fields & MQTT_FN_BIT_WILDCARD_SUBSCRIPTION_AVAILABLE)
					goto end;
				props = mqtt_read_1byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.wildcard_subscription_available);
				/* can have only 2 values: 0 or 1 */
				if (mpkt->data.connack.var_hdr.props.wildcard_subscription_available > 1)
					goto end;
				fields |= MQTT_FN_BIT_WILDCARD_SUBSCRIPTION_AVAILABLE;
				break;

			case MQTT_PROP_SUBSCRIPTION_IDENTIFIERS_AVAILABLE:
				if (fields & MQTT_FN_BIT_SUBSCRIPTION_IDENTIFIER)
					goto end;
				props = mqtt_read_1byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.subscription_identifiers_available);
				/* can have only 2 values: 0 or 1 */
				if (mpkt->data.connack.var_hdr.props.subscription_identifiers_available > 1)
					goto end;
				fields |= MQTT_FN_BIT_SUBSCRIPTION_IDENTIFIER;
				break;

			case MQTT_PROP_SHARED_SUBSRIPTION_AVAILABLE:
				if (fields & MQTT_FN_BIT_SHARED_SUBSCRIPTION_AVAILABLE)
					goto end;
				props = mqtt_read_1byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.shared_subsription_available);
				/* can have only 2 values: 0 or 1 */
				if (mpkt->data.connack.var_hdr.props.shared_subsription_available > 1)
					goto end;
				fields |= MQTT_FN_BIT_SHARED_SUBSCRIPTION_AVAILABLE;
				break;

			case MQTT_PROP_SERVER_KEEPALIVE:
				if (fields & MQTT_FN_BIT_SERVER_KEEPALIVE)
					goto end;
				props = mqtt_read_2byte_int(istnext(props), &mpkt->data.connack.var_hdr.props.server_keepalive);
				fields |= MQTT_FN_BIT_SERVER_KEEPALIVE;
				break;

			case MQTT_PROP_RESPONSE_INFORMATION:
				if (fields & MQTT_FN_BIT_RESPONSE_INFORMATION)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connack.var_hdr.props.response_information);
				fields |= MQTT_FN_BIT_RESPONSE_INFORMATION;
				break;

			case MQTT_PROP_SERVER_REFERENCE:
				if (fields & MQTT_FN_BIT_SERVER_REFERENCE)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connack.var_hdr.props.server_reference);
				fields |= MQTT_FN_BIT_SERVER_REFERENCE;
				break;

			case MQTT_PROP_USER_PROPERTIES:
				/* if we reached MQTT_PROP_USER_PROPERTY_ENTRIES already, then
				 * we start writing over the first property */
				if (user_prop_idx >= MQTT_PROP_USER_PROPERTY_ENTRIES)
					user_prop_idx = 0;

				/* read user property name and value */
				props = mqtt_read_string(istnext(props), &mpkt->data.connack.var_hdr.props.user_props[user_prop_idx].name);
				if (!isttest(props))
					goto end;
				props = mqtt_read_string(props, &mpkt->data.connack.var_hdr.props.user_props[user_prop_idx].value);
				++user_prop_idx;
				break;

			case MQTT_PROP_AUTHENTICATION_METHOD:
				if (fields & MQTT_FN_BIT_AUTHENTICATION_METHOD)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connack.var_hdr.props.authentication_method);
				fields |= MQTT_FN_BIT_AUTHENTICATION_METHOD;
				break;

			case MQTT_PROP_AUTHENTICATION_DATA:
				if (fields & MQTT_FN_BIT_AUTHENTICATION_DATA)
					goto end;
				props = mqtt_read_string(istnext(props), &mpkt->data.connack.var_hdr.props.authentication_data);
				fields |= MQTT_FN_BIT_AUTHENTICATION_DATA;
				break;

			default:
				return 0;
			}

			if (!isttest(props))
				goto end;
		}
	}

	if ((orig_len - istlen(parser)) == mpkt->fixed_hdr.remaining_length)
		ret = MQTT_VALID_MESSAGE;
  end:
	return ret;
}


/* Parses and validates a MQTT packet
 *   https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718028
 *
 * For now, due to HAProxy limitation, only validation of CONNECT and CONNACK packets
 * are supported.
 *
 *   - check FIXED_HDR
 *   - check remaining length
 *   - check variable headers and payload
 *
 * if <mpkt> is not NULL, then this structure will be filled up as well. An
 * unsupported packet type is considered as invalid. It is not a problem for now
 * because only the first packet on each side can be parsed (CONNECT for the
 * client and CONNACK for the server).
 *
 * Returns:
 *  MQTT_INVALID_MESSAGE if the message is invalid
 *  MQTT_NEED_MORE_DATA  if we need more data to fully validate the message
 *  MQTT_VALID_MESSAGE   if the message looks valid
 */
int mqtt_validate_message(const struct ist msg, struct mqtt_pkt *mpkt)
{
	struct ist parser;
	struct mqtt_pkt tmp_mpkt;
	int ret = MQTT_INVALID_MESSAGE;

	if (!mpkt)
		mpkt = &tmp_mpkt;
	memset(mpkt, 0, sizeof(*mpkt));

	parser = msg;
	if (istlen(msg) < MQTT_MIN_PKT_SIZE) {
		ret = MQTT_NEED_MORE_DATA;
		goto end;
	}

	/* parse the MQTT fixed header */
	parser = mqtt_read_fixed_hdr(parser, mpkt);
	if (!isttest(parser)) {
		ret = MQTT_INVALID_MESSAGE;
		goto end;
	}

	/* Now parsing "remaining length" field */
	parser = mqtt_read_varint(parser, &mpkt->fixed_hdr.remaining_length);
	if (!isttest(parser)) {
		ret = MQTT_INVALID_MESSAGE;
		goto end;
	}

	if (istlen(parser) < mpkt->fixed_hdr.remaining_length)
		return MQTT_NEED_MORE_DATA;

	/* Now parsing the variable header and payload, which is based on the packet type */
	switch (mpkt->fixed_hdr.type) {
	case MQTT_CPT_CONNECT:
		ret = mqtt_parse_connect(parser, mpkt);
		break;
	case MQTT_CPT_CONNACK:
		ret = mqtt_parse_connack(parser, mpkt);
		break;
	default:
		break;
	}

  end:
	return ret;
}
