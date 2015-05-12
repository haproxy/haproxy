/*
 * include/proto/peers.h
 * This file defines function prototypes for peers management.
 *
 * Copyright 2010 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#ifndef _PROTO_PEERS_H
#define _PROTO_PEERS_H

#include <common/config.h>
#include <common/ticks.h>
#include <common/time.h>
#include <types/stream.h>
#include <types/peers.h>

void peers_init_sync(struct peers *peers);
void peers_register_table(struct peers *, struct stktable *table);
void peers_setup_frontend(struct proxy *fe);

#endif /* _PROTO_PEERS_H */

