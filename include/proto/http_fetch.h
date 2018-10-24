/*
 * include/proto/http_fetch.h
 * This file contains the minimally required http sample fetch declarations.
 *
 * Copyright (C) 2000-2018 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_HTTP_FETCH_H
#define _PROTO_HTTP_FETCH_H

#include <common/config.h>
#include <common/mini-clist.h>
#include <types/action.h>
#include <types/proxy.h>

/* Note: these functions *do* modify the sample. Even in case of success, at
 * least the type and uint value are modified.
 */
#define CHECK_HTTP_MESSAGE_FIRST() \
	do { int r = smp_prefetch_http(smp->px, smp->strm, smp->opt, args, smp, 1); if (r <= 0) return r; } while (0)

#define CHECK_HTTP_MESSAGE_FIRST_PERM() \
	do { int r = smp_prefetch_http(smp->px, smp->strm, smp->opt, args, smp, 0); if (r <= 0) return r; } while (0)

int smp_prefetch_http(struct proxy *px, struct stream *s, unsigned int opt,
                  const struct arg *args, struct sample *smp, int req_vol);

struct htx;
struct htx *smp_prefetch_htx(struct sample *smp, const struct arg *args);

int val_hdr(struct arg *arg, char **err_msg);


#endif /* _PROTO_HTTP_FETCH_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
