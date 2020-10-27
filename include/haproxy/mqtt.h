/*
 * include/haproxt/mqtt.h
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

#ifndef _HAPROXY_MQTT_H
#define _HAPROXY_MQTT_H

#include <import/ist.h>

#include <haproxy/mqtt-t.h>
#include <haproxy/tools.h>

/* expected flags for control packets */
extern uint8_t mqtt_cpt_flags[MQTT_CPT_ENTRIES];

/* MQTT field string names */
extern const struct ist mqtt_fields_string[MQTT_FN_ENTRIES];

/* list of supported capturable field names for each MQTT control packet type */
extern const uint64_t mqtt_fields_per_packet[MQTT_CPT_ENTRIES];

int mqtt_validate_message(const struct ist msg, struct mqtt_pkt *mpkt);
struct ist mqtt_field_value(const struct ist msg, int type, int fieldname_id);

/*
 * Return a MQTT packet type ID based found in <str>.
 * <str> can be a number or a string and returned value will always be the numeric value.
 *
 * If <str> can't be translated into an ID, then MQTT_CPT_INVALID (0) is returned.
 */
static inline int mqtt_typeid(struct ist str)
{
	int id;

	id = strl2ui(str.ptr, istlen(str));
	if ((id >= MQTT_CPT_CONNECT) && (id < MQTT_CPT_ENTRIES))
		return id;

	else if (isteqi(str, ist("CONNECT")) != 0)
		return MQTT_CPT_CONNECT;
	else if (isteqi(str, ist("CONNACK")) != 0)
		return MQTT_CPT_CONNACK;
	else if (isteqi(str, ist("PUBLISH")) != 0)
		return MQTT_CPT_PUBLISH;
	else if (isteqi(str, ist("PUBACK")) != 0)
		return MQTT_CPT_PUBACK;
	else if (isteqi(str, ist("PUBREC")) != 0)
		return MQTT_CPT_PUBREC;
	else if (isteqi(str, ist("PUBREL")) != 0)
		return MQTT_CPT_PUBREL;
	else if (isteqi(str, ist("PUBCOMP")) != 0)
		return MQTT_CPT_PUBCOMP;
	else if (isteqi(str, ist("SUBSCRIBE")) != 0)
		return MQTT_CPT_SUBSCRIBE;
	else if (isteqi(str, ist("SUBACK")) != 0)
		return MQTT_CPT_SUBACK;
	else if (isteqi(str, ist("UNSUBSCRIBE")) != 0)
		return MQTT_CPT_UNSUBSCRIBE;
	else if (isteqi(str, ist("UNSUBACK")) != 0)
		return MQTT_CPT_UNSUBACK;
	else if (isteqi(str, ist("PINGREQ")) != 0)
		return MQTT_CPT_PINGREQ;
	else if (isteqi(str, ist("PINGRESP")) != 0)
		return MQTT_CPT_PINGRESP;
	else if (isteqi(str, ist("DISCONNECT")) != 0)
		return MQTT_CPT_DISCONNECT;
	else if (isteqi(str, ist("AUTH")) != 0)
		return MQTT_CPT_AUTH;

	return MQTT_CPT_INVALID;
}

/*
 * validate that <str> is a field that can be extracted from a <type> MQTT packet
 *
 * return the field name ID (MQTT_FN_*) if a match is found, MQTT_FN_INVALID (0) otherwise.
 */
static inline int mqtt_check_type_fieldname(int type, struct ist str)
{
	int i, id = MQTT_FN_INVALID;

	for (i = 0; i < MQTT_FN_ENTRIES; i++) {
		if (isteqi(str, mqtt_fields_string[i])) {
			if (mqtt_fields_per_packet[type] & (1ULL << i))
				id = i;
			break;
		}
	}

	return id;

}

#endif /* _HAPROXY_MQTT_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
