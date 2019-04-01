/*
 * Master Worker
 *
 * Copyright HAProxy Technologies 2019 - William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef PROTO_MWORKER_H_
#define PROTO_MWORKER_H_

void mworker_proc_list_to_env();
void mworker_env_to_proc_list();

#endif /* PROTO_MWORKER_H_ */
