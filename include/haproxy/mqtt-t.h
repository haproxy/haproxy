/*
 * include/haproxy/mqtt.h
 * This file contains structure declarations for MQTT protocol.
 *
 * Copyright 2020 Baptiste Assmann <bedis9@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _HAPROXY_MQTT_T_H
#define _HAPROXY_MQTT_T_H

#include <inttypes.h>
#include <import/ist.h>

/* MQTT protocol version
 * In MQTT 3.1.1, version is called "level"
 */
#define MQTT_VERSION_3_1      3
#define MQTT_VERSION_3_1_1    4
#define MQTT_VERSION_5_0      5

/*
 * return code when parsing / validating MQTT messages
 */
#define MQTT_INVALID_MESSAGE   -1
#define MQTT_NEED_MORE_DATA     0
#define MQTT_VALID_MESSAGE      1


/*
 * MQTT Control Packet Type: MQTT_CPT_*
 *
 * Part of the fixed headers, encoded on the first packet byte :
 *
 * +-------+-----------+-----------+-----------+---------+----------+----------+---------+------------+
 * | bit   |    7      |     6     |    5      |    4    |     3    |     2    |     1   |     0      |
 * +-------+-----------+-----------+-----------+---------+----------+----------+---------+------------+
 * | field |          MQTT Control Packet Type           | Flags specific to each Control Packet type |
 * +-------+---------------------------------------------+--------------------------------------------+
 *
 * Don't forget to "left offset by 4 bits (<< 4)" the values below when matching against the fixed
 * header collected in a MQTT packet.
 *
 * value 0x0 is reserved and forbidden
 */
enum {
	MQTT_CPT_INVALID = 0,

	MQTT_CPT_CONNECT,
	MQTT_CPT_CONNACK,
	MQTT_CPT_PUBLISH,
	MQTT_CPT_PUBACK,
	MQTT_CPT_PUBREC,
	MQTT_CPT_PUBREL,
	MQTT_CPT_PUBCOMP,
	MQTT_CPT_SUBSCRIBE,
	MQTT_CPT_SUBACK,
	MQTT_CPT_UNSUBSCRIBE,
	MQTT_CPT_UNSUBACK,
	MQTT_CPT_PINGREQ,
	MQTT_CPT_PINGRESP,
	MQTT_CPT_DISCONNECT,
	MQTT_CPT_AUTH,
	MQTT_CPT_ENTRIES  /* used to mark the end/size of our MQTT_CPT_* list */
};

/* MQTT CONNECT packet flags */
#define MQTT_CONNECT_FL_RESERVED        0x01
#define MQTT_CONNECT_FL_CLEAN_SESSION   0x02
#define MQTT_CONNECT_FL_WILL            0x04
#define MQTT_CONNECT_FL_WILL_QOS        0x18  /* covers 2 bits 00011000 */
#define MQTT_CONNECT_FL_WILL_RETAIN     0x20
#define MQTT_CONNECT_FL_PASSWORD        0x40
#define MQTT_CONNECT_FL_USERNAME        0x80

/* MQTT packet properties identifiers
 * https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901029
 */
#define MQTT_PROP_PAYLOAD_FORMAT_INDICATOR           0x01
#define MQTT_PROP_MESSAGE_EXPIRY_INTERVAL            0x02
#define MQTT_PROP_CONTENT_TYPE                       0x03
#define MQTT_PROP_RESPONSE_TOPIC                     0x08
#define MQTT_PROP_CORRELATION_DATA                   0x09
#define MQTT_PROP_SESSION_EXPIRY_INTERVAL            0x11
#define MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER         0x12
#define MQTT_PROP_SERVER_KEEPALIVE                   0x13
#define MQTT_PROP_AUTHENTICATION_METHOD              0x15
#define MQTT_PROP_AUTHENTICATION_DATA                0x16
#define MQTT_PROP_REQUEST_PROBLEM_INFORMATION        0x17
#define MQTT_PROP_WILL_DELAY_INTERVAL                0x18
#define MQTT_PROP_REQUEST_RESPONSE_INFORMATION       0x19
#define MQTT_PROP_RESPONSE_INFORMATION               0x1A
#define MQTT_PROP_SERVER_REFERENCE                   0x1C
#define MQTT_PROP_RECEIVE_MAXIMUM                    0x21
#define MQTT_PROP_TOPIC_ALIAS_MAXIMUM                0x22
#define MQTT_PROP_MAXIMUM_QOS                        0x24
#define MQTT_PROP_RETAIN_AVAILABLE                   0x25
#define MQTT_PROP_USER_PROPERTIES                    0x26
#define MQTT_PROP_MAXIMUM_PACKET_SIZE                0x27
#define MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE    0x28
#define MQTT_PROP_SUBSCRIPTION_IDENTIFIERS_AVAILABLE 0x29
#define MQTT_PROP_SHARED_SUBSRIPTION_AVAILABLE       0x2A
#define MQTT_PROP_REASON_STRING                      0x1F
#define MQTT_PROP_LAST                               0xFF

/* MQTT minimal packet size */
#define MQTT_MIN_PKT_SIZE              2
#define MQTT_REMAINING_LENGTH_MAX_SIZE 4

/* list of supported capturable Field Names and configuration file string */
enum {
	MQTT_FN_INVALID = 0,

	MQTT_FN_FLAGS,
	MQTT_FN_REASON_CODE,
	MQTT_FN_PROTOCOL_NAME,
	MQTT_FN_PROTOCOL_VERSION,
	MQTT_FN_CLIENT_IDENTIFIER,
	MQTT_FN_WILL_TOPIC,
	MQTT_FN_WILL_PAYLOAD,
	MQTT_FN_USERNAME,
	MQTT_FN_PASSWORD,
	MQTT_FN_KEEPALIVE,

	/* MQTT 5.0 properties
	 * https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901029
	 */
	MQTT_FN_PAYLOAD_FORMAT_INDICATOR,
	MQTT_FN_MESSAGE_EXPIRY_INTERVAL,
	MQTT_FN_CONTENT_TYPE,
	MQTT_FN_RESPONSE_TOPIC,
	MQTT_FN_CORRELATION_DATA,
	MQTT_FN_SUBSCRIPTION_IDENTIFIER,
	MQTT_FN_SESSION_EXPIRY_INTERVAL,
	MQTT_FN_ASSIGNED_CLIENT_IDENTIFIER,
	MQTT_FN_SERVER_KEEPALIVE,
	MQTT_FN_AUTHENTICATION_METHOD,
	MQTT_FN_AUTHENTICATION_DATA,
	MQTT_FN_REQUEST_PROBLEM_INFORMATION,
	MQTT_FN_DELAY_INTERVAL,
	MQTT_FN_REQUEST_RESPONSE_INFORMATION,
	MQTT_FN_RESPONSE_INFORMATION,
	MQTT_FN_SERVER_REFERENCE,
	MQTT_FN_REASON_STRING,
	MQTT_FN_RECEIVE_MAXIMUM,
	MQTT_FN_TOPIC_ALIAS_MAXIMUM,
	MQTT_FN_TOPIC_ALIAS,
	MQTT_FN_MAXIMUM_QOS,
	MQTT_FN_RETAIN_AVAILABLE,
	MQTT_FN_USER_PROPERTY,
	MQTT_FN_MAXIMUM_PACKET_SIZE,
	MQTT_FN_WILDCARD_SUBSCRIPTION_AVAILABLE,
	MQTT_FN_SUBSCRIPTION_IDENTIFIERS_AVAILABLE,
	MQTT_FN_SHARED_SUBSCRIPTION_AVAILABLE,

	MQTT_FN_ENTRIES           /* this one must always be the latest one */
};

/* MQTT field string bit, for easy match using bitmasks
 * ATTENTION: "user-properties" are not supported for now
 */
enum {
	MQTT_FN_BIT_FLAGS                             = (1ULL << MQTT_FN_FLAGS),
	MQTT_FN_BIT_REASON_CODE                       = (1ULL << MQTT_FN_REASON_CODE),
	MQTT_FN_BIT_PROTOCOL_NAME                     = (1ULL << MQTT_FN_PROTOCOL_NAME),
	MQTT_FN_BIT_PROTOCOL_VERSION                  = (1ULL << MQTT_FN_PROTOCOL_VERSION),
	MQTT_FN_BIT_CLIENT_IDENTIFIER                 = (1ULL << MQTT_FN_CLIENT_IDENTIFIER),
	MQTT_FN_BIT_WILL_TOPIC                        = (1ULL << MQTT_FN_WILL_TOPIC),
	MQTT_FN_BIT_WILL_PAYLOAD                      = (1ULL << MQTT_FN_WILL_PAYLOAD),
	MQTT_FN_BIT_USERNAME                          = (1ULL << MQTT_FN_USERNAME),
	MQTT_FN_BIT_PASSWORD                          = (1ULL << MQTT_FN_PASSWORD),
	MQTT_FN_BIT_KEEPALIVE                         = (1ULL << MQTT_FN_KEEPALIVE),
	MQTT_FN_BIT_PAYLOAD_FORMAT_INDICATOR          = (1ULL << MQTT_FN_PAYLOAD_FORMAT_INDICATOR),
	MQTT_FN_BIT_MESSAGE_EXPIRY_INTERVAL           = (1ULL << MQTT_FN_MESSAGE_EXPIRY_INTERVAL),
	MQTT_FN_BIT_CONTENT_TYPE                      = (1ULL << MQTT_FN_CONTENT_TYPE),
	MQTT_FN_BIT_RESPONSE_TOPIC                    = (1ULL << MQTT_FN_RESPONSE_TOPIC),
	MQTT_FN_BIT_CORRELATION_DATA                  = (1ULL << MQTT_FN_CORRELATION_DATA),
	MQTT_FN_BIT_SUBSCRIPTION_IDENTIFIER           = (1ULL << MQTT_FN_SUBSCRIPTION_IDENTIFIER),
	MQTT_FN_BIT_SESSION_EXPIRY_INTERVAL           = (1ULL << MQTT_FN_SESSION_EXPIRY_INTERVAL),
	MQTT_FN_BIT_ASSIGNED_CLIENT_IDENTIFIER        = (1ULL << MQTT_FN_ASSIGNED_CLIENT_IDENTIFIER),
	MQTT_FN_BIT_SERVER_KEEPALIVE                  = (1ULL << MQTT_FN_SERVER_KEEPALIVE),
	MQTT_FN_BIT_AUTHENTICATION_METHOD             = (1ULL << MQTT_FN_AUTHENTICATION_METHOD),
	MQTT_FN_BIT_AUTHENTICATION_DATA               = (1ULL << MQTT_FN_AUTHENTICATION_DATA),
	MQTT_FN_BIT_REQUEST_PROBLEM_INFORMATION       = (1ULL << MQTT_FN_REQUEST_PROBLEM_INFORMATION),
	MQTT_FN_BIT_DELAY_INTERVAL                    = (1ULL << MQTT_FN_DELAY_INTERVAL),
	MQTT_FN_BIT_REQUEST_RESPONSE_INFORMATION      = (1ULL << MQTT_FN_REQUEST_RESPONSE_INFORMATION),
	MQTT_FN_BIT_RESPONSE_INFORMATION              = (1ULL << MQTT_FN_RESPONSE_INFORMATION),
	MQTT_FN_BIT_SERVER_REFERENCE                  = (1ULL << MQTT_FN_SERVER_REFERENCE),
	MQTT_FN_BIT_REASON_STRING                     = (1ULL << MQTT_FN_REASON_STRING),
	MQTT_FN_BIT_RECEIVE_MAXIMUM                   = (1ULL << MQTT_FN_RECEIVE_MAXIMUM),
	MQTT_FN_BIT_TOPIC_ALIAS_MAXIMUM               = (1ULL << MQTT_FN_TOPIC_ALIAS_MAXIMUM),
	MQTT_FN_BIT_TOPIC_ALIAS                       = (1ULL << MQTT_FN_TOPIC_ALIAS),
	MQTT_FN_BIT_MAXIMUM_QOS                       = (1ULL << MQTT_FN_MAXIMUM_QOS),
	MQTT_FN_BIT_RETAIN_AVAILABLE                  = (1ULL << MQTT_FN_RETAIN_AVAILABLE),
	MQTT_FN_BIT_USER_PROPERTY                     = (1ULL << MQTT_FN_USER_PROPERTY),
	MQTT_FN_BIT_MAXIMUM_PACKET_SIZE               = (1ULL << MQTT_FN_MAXIMUM_PACKET_SIZE),
	MQTT_FN_BIT_WILDCARD_SUBSCRIPTION_AVAILABLE   = (1ULL << MQTT_FN_WILDCARD_SUBSCRIPTION_AVAILABLE),
	MQTT_FN_BIT_SUBSCRIPTION_IDENTIFIERS_AVAILABLE= (1ULL << MQTT_FN_SUBSCRIPTION_IDENTIFIERS_AVAILABLE),
	MQTT_FN_BIT_SHARED_SUBSCRIPTION_AVAILABLE     = (1ULL << MQTT_FN_SHARED_SUBSCRIPTION_AVAILABLE),
};

/* structure to host fields for a MQTT CONNECT packet */
#define MQTT_PROP_USER_PROPERTY_ENTRIES 5
struct connect {
	struct {
		struct ist protocol_name;
		uint8_t protocol_version;
		uint8_t flags;
		uint16_t keepalive;

		struct {
			uint32_t session_expiry_interval;
			uint16_t receive_maximum;
			uint32_t maximum_packet_size;
			uint16_t topic_alias_maximum;
			uint8_t  request_response_information;
			uint8_t  request_problem_information;
			struct {
				struct ist name;
				struct ist value;
			} user_props[MQTT_PROP_USER_PROPERTY_ENTRIES];
			struct ist authentication_method;
			struct ist authentication_data;
		} props;
	} var_hdr;
	struct {
		struct ist client_identifier;
		struct {
			uint32_t delay_interval;
			uint8_t  payload_format_indicator;
			uint32_t message_expiry_interval;
			struct ist content_type;
			struct ist response_topic;
			struct ist correlation_data;
			struct {
				struct ist name;
				struct ist value;
			} user_props[MQTT_PROP_USER_PROPERTY_ENTRIES];
		} will_props;
		struct ist will_topic;
		struct ist will_payload;
		struct ist username;
		struct ist password;
	} payload;
};

/* structure to host fields for a MQTT CONNACK packet */
struct connack {
	struct {
		uint8_t protocol_version;
		uint8_t flags;
		uint8_t reason_code;
		struct {
			uint32_t session_expiry_interval;
			uint16_t receive_maximum;
			uint8_t  maximum_qos;
			uint8_t  retain_available;
			uint32_t maximum_packet_size;
			struct ist assigned_client_identifier;
			uint16_t topic_alias_maximum;
			struct ist reason_string;
			struct {
				struct ist name;
				struct ist value;
			} user_props[MQTT_PROP_USER_PROPERTY_ENTRIES];
			uint8_t  wildcard_subscription_available;
			uint8_t  subscription_identifiers_available;
			uint8_t  shared_subsription_available;
			uint16_t server_keepalive;
			struct ist response_information;
			struct ist server_reference;
			struct ist authentication_method;
			struct ist authentication_data;
		} props;
	} var_hdr;
};

/* structure to host a MQTT packet */
struct mqtt_pkt {
	struct {
		uint8_t type;              /* MQTT_CPT_* */
		uint8_t flags;             /* MQTT_CPT_FL* */
		uint32_t remaining_length;
	} fixed_hdr;
	union {
		struct connect connect;
		struct connack connack;
	} data;
};

#endif /* _HAPROXY_MQTT_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
