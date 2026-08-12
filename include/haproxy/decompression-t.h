/*
 * include/haproxy/decompression-t.h
 * This file defines everything related to decompression.
 *
 * Copyright 2026 HAProxy Technologies
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

#ifndef _HAPROXY_DECOMP_T_H
#define _HAPROXY_DECOMP_T_H

#if defined(USE_SLZ)
#ifdef USE_ZLIB
#error "Cannot build with both USE_SLZ and USE_ZLIB at the same time."
#endif
#include <import/slz.h>
#elif defined(USE_ZLIB)
#include <zlib.h>
#endif

#include <haproxy/buf-t.h>

/* Decompression flags */

#define DECOMP_FL_NONE	        0x00000000
#define DECOMP_FL_DIR_REQ	0x00000001 /* decompress requests */
#define DECOMP_FL_DIR_RES	0x00000002 /* decompress responses */

/* Per direction decompression flags */

/* DECOMP_DIR_FL_MODE modes are mutually exclusive */
#define DECOMP_DIR_FL_MODE_MASK     0x0007
#define DECOMP_DIR_FL_MODE_NONE     0x0001 /* default: do nothing */
#define DECOMP_DIR_FL_MODE_AUTO     0x0002 /* best effort */
#define DECOMP_DIR_FL_MODE_ALWAYS   0x0004 /* guarantees the output stream will be decompressed */

/* Decompression ctx flags */

#define DECOMP_CTX_FL_DONE      0x0001     /* decompression done */

/* for either request or response decompression */
struct decomp_dir {
	struct decomp_algo *algos;    /* algos available for decompression */
	uint16_t flags;               /* DECOMP_DIR_FL_* flags */
};
struct decomp {
	struct decomp_dir req;
	struct decomp_dir res;
	unsigned int flags;            /* DECOMP_FL_* flags */
};

struct decomp_ctx {
	uint16_t flags;                /* DECOMP_CTX_FL_* flags */
	char *drain;                   /* pointer to pending (unconsumed) data in decompression buffer */
	uint32_t drain_len;            /* pending bytes in decompression buffer */
#if defined(USE_SLZ)
	struct uslz_stream state;
	int fmt;                       /* SLZ_FMT_* value, if != SLZ_FMT_NONE library will be initialized
	                                * with uslz_init_fmt() and format will be enforced (this disables
	                                * auto-detection)
	                                */
	char out_buf[32768];           /* decompression buffer */
#endif
};

struct decomp_algo {
	char *cfg_name;  /* config name */
	int cfg_name_len;

	char *ua_name;  /* name for the user-agent */
	int ua_name_len;

	int (*init)(struct decomp_ctx **decomp_ctx);
	int (*stream_new)(struct decomp_ctx *decomp_ctx);
	int (*add_data)(struct decomp_ctx *decomp_ctx, const char *in_data, int in_len);
	int (*finish)(struct decomp_ctx *decomp_ctx);
	int (*end)(struct decomp_ctx **decomp_ctx);
	struct decomp_algo *next;
};

#endif /* _HAPROXY_DECOMP_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */

