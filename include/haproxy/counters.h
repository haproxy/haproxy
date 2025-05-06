/*
 * include/haproxy/counters.h
 * objects counters management
 *
 * Copyright 2025 HAProxy Technologies
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

#ifndef _HAPROXY_COUNTERS_H
# define _HAPROXY_COUNTERS_H

#include <haproxy/counters-t.h>
#include <haproxy/guid-t.h>

struct fe_counters_shared *counters_fe_shared_get(const struct guid_node *guid);
struct be_counters_shared *counters_be_shared_get(const struct guid_node *guid);

void counters_fe_shared_drop(struct fe_counters_shared *counters);
void counters_be_shared_drop(struct be_counters_shared *counters);

#endif /* _HAPROXY_COUNTERS_H */
