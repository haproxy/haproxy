/*
 * include/haproxy/backend-t.h
 * This file assembles definitions for backends
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_BACKEND_T_H
#define _HAPROXY_BACKEND_T_H

#include <haproxy/api-t.h>
#include <haproxy/lb_chash-t.h>
#include <haproxy/lb_fas-t.h>
#include <haproxy/lb_fwlc-t.h>
#include <haproxy/lb_fwrr-t.h>
#include <haproxy/lb_map-t.h>
#include <haproxy/lb_ss-t.h>
#include <haproxy/server-t.h>
#include <haproxy/thread-t.h>

/* Parameters for lbprm.algo */

/* Lower bits define the kind of load balancing method, which means the type of
 * algorithm, and which criterion it is based on. For this reason, those bits
 * also include information about dependencies, so that the config parser can
 * detect incompatibilities.
 */

/* LB parameters are on the lower 8 bits. Depends on the LB kind. */

/* BE_LB_HASH_* is used with BE_LB_KIND_HI */
#define BE_LB_HASH_SRC  0x00000000  /* hash source IP */
#define BE_LB_HASH_URI  0x00000001  /* hash HTTP URI */
#define BE_LB_HASH_PRM  0x00000002  /* hash HTTP URL parameter */
#define BE_LB_HASH_HDR  0x00000003  /* hash HTTP header value */
#define BE_LB_HASH_RDP  0x00000004  /* hash RDP cookie value */
#define BE_LB_HASH_SMP  0x00000005  /* hash a sample expression */

/* BE_LB_RR_* is used with BE_LB_KIND_RR */
#define BE_LB_RR_DYN    0x00000000  /* dynamic round robin (default) */
#define BE_LB_RR_STATIC 0x00000001  /* static round robin */
#define BE_LB_RR_RANDOM 0x00000002  /* random round robin */

/* BE_LB_CB_* is used with BE_LB_KIND_CB */
#define BE_LB_CB_LC     0x00000000  /* least-connections */
#define BE_LB_CB_FAS    0x00000001  /* first available server (opposite of leastconn) */

/* BE_LB_SA_* is used with BE_LB_KIND_SA */
#define BE_LB_SA_SS     0x00000000  /* stick to server as long as it is available */

#define BE_LB_PARM      0x000000FF  /* mask to get/clear the LB param */

/* Required input(s) */
#define BE_LB_NEED_NONE 0x00000000  /* no input needed            */
#define BE_LB_NEED_ADDR 0x00000100  /* only source address needed */
#define BE_LB_NEED_DATA 0x00000200  /* some payload is needed     */
#define BE_LB_NEED_HTTP 0x00000400  /* an HTTP request is needed  */
#define BE_LB_NEED_LOG  0x00000800  /* LOG backend required  */
#define BE_LB_NEED      0x0000FF00  /* mask to get/clear dependencies */

/* Algorithm */
#define BE_LB_KIND_NONE 0x00000000  /* algorithm not set */
#define BE_LB_KIND_RR   0x00010000  /* round-robin */
#define BE_LB_KIND_CB   0x00020000  /* connection-based */
#define BE_LB_KIND_HI   0x00030000  /* hash of input (see hash inputs above) */
#define BE_LB_KIND_SA   0x00040000  /* standalone (specific algorithms, cannot be grouped) */
#define BE_LB_KIND      0x00070000  /* mask to get/clear LB algorithm */

/* All known variants of load balancing algorithms. These can be cleared using
 * the BE_LB_ALGO mask. For a check, using BE_LB_KIND is preferred.
 */
#define BE_LB_ALGO_NONE (BE_LB_KIND_NONE | BE_LB_NEED_NONE)    /* not defined */
#define BE_LB_ALGO_RR   (BE_LB_KIND_RR | BE_LB_NEED_NONE)      /* round robin */
#define BE_LB_ALGO_RND  (BE_LB_KIND_RR | BE_LB_NEED_NONE | BE_LB_RR_RANDOM) /* random value */
#define BE_LB_ALGO_LC   (BE_LB_KIND_CB | BE_LB_NEED_NONE | BE_LB_CB_LC)    /* least connections */
#define BE_LB_ALGO_FAS  (BE_LB_KIND_CB | BE_LB_NEED_NONE | BE_LB_CB_FAS)   /* first available server */
#define BE_LB_ALGO_SS   (BE_LB_KIND_SA | BE_LB_NEED_NONE | BE_LB_SA_SS)    /* sticky */
#define BE_LB_ALGO_SRR  (BE_LB_KIND_RR | BE_LB_NEED_NONE | BE_LB_RR_STATIC) /* static round robin */
#define BE_LB_ALGO_SH	(BE_LB_KIND_HI | BE_LB_NEED_ADDR | BE_LB_HASH_SRC) /* hash: source IP */
#define BE_LB_ALGO_UH	(BE_LB_KIND_HI | BE_LB_NEED_HTTP | BE_LB_HASH_URI) /* hash: HTTP URI  */
#define BE_LB_ALGO_PH	(BE_LB_KIND_HI | BE_LB_NEED_HTTP | BE_LB_HASH_PRM) /* hash: HTTP URL parameter */
#define BE_LB_ALGO_HH	(BE_LB_KIND_HI | BE_LB_NEED_HTTP | BE_LB_HASH_HDR) /* hash: HTTP header value  */
#define BE_LB_ALGO_RCH	(BE_LB_KIND_HI | BE_LB_NEED_DATA | BE_LB_HASH_RDP) /* hash: RDP cookie value   */
#define BE_LB_ALGO_SMP	(BE_LB_KIND_HI | BE_LB_NEED_DATA | BE_LB_HASH_SMP) /* hash: sample expression  */
#define BE_LB_ALGO_LH	(BE_LB_KIND_HI | BE_LB_NEED_LOG  | BE_LB_HASH_SMP) /* log hash: sample expression  */
#define BE_LB_ALGO      (BE_LB_KIND    | BE_LB_NEED      | BE_LB_PARM    ) /* mask to clear algo */

/* Higher bits define how a given criterion is mapped to a server. In fact it
 * designates the LB function by itself. The dynamic algorithms will also have
 * the DYN bit set. These flags are automatically set at the end of the parsing.
 */
#define BE_LB_LKUP_NONE   0x00000000  /* not defined */
#define BE_LB_LKUP_MAP    0x00100000  /* static map based lookup */
#define BE_LB_LKUP_RRTREE 0x00200000  /* FWRR tree lookup */
#define BE_LB_LKUP_LCTREE 0x00300000  /* FWLC tree lookup */
#define BE_LB_LKUP_CHTREE 0x00400000  /* consistent hash  */
#define BE_LB_LKUP_FSTREE 0x00500000  /* FAS tree lookup */
#define BE_LB_LKUP        0x00700000  /* mask to get just the LKUP value */

/* additional properties */
#define BE_LB_PROP_DYN    0x00800000 /* bit to indicate a dynamic algorithm */

/* hash types */
#define BE_LB_HASH_MAP    0x00000000 /* map-based hash (default) */
#define BE_LB_HASH_CONS   0x01000000 /* consistent hashbit to indicate a dynamic algorithm */
#define BE_LB_HASH_TYPE   0x01000000 /* get/clear hash types */

/* additional modifier on top of the hash function (only avalanche right now) */
#define BE_LB_HMOD_AVAL   0x02000000  /* avalanche modifier */
#define BE_LB_HASH_MOD    0x02000000  /* get/clear hash modifier */

/* BE_LB_HFCN_* is the hash function, to be used with BE_LB_HASH_FUNC */
#define BE_LB_HFCN_SDBM   0x00000000  /* sdbm hash */
#define BE_LB_HFCN_DJB2   0x04000000  /* djb2 hash */
#define BE_LB_HFCN_WT6    0x08000000  /* wt6 hash */
#define BE_LB_HFCN_CRC32  0x0C000000  /* crc32 hash */
#define BE_LB_HFCN_NONE   0x10000000 /* none - no hash */
#define BE_LB_HASH_FUNC   0x1C000000 /* get/clear hash function */


/* various constants */

/* The scale factor between user weight and effective weight allows smooth
 * weight modulation even with small weights (eg: 1). It should not be too high
 * though because it limits the number of servers in FWRR mode in order to
 * prevent any integer overflow. The max number of servers per backend is
 * limited to about (2^32-1)/256^2/scale ~= 65535.9999/scale. A scale of 16
 * looks like a good value, as it allows 4095 servers per backend while leaving
 * modulation steps of about 6% for servers with the lowest weight (1).
 */
#define BE_WEIGHT_SCALE 16

/* LB parameters for all algorithms */
struct lbprm {
	union { /* LB parameters depending on the algo type */
		struct lb_map map;
		struct lb_fwrr fwrr;
		struct lb_fwlc fwlc;
		struct lb_chash chash;
		struct lb_fas fas;
		struct lb_ss ss;
	};
	uint32_t algo;			/* load balancing algorithm and variants: BE_LB_* */
	int tot_wact, tot_wbck;		/* total effective weights of active and backup servers */
	int tot_weight;			/* total effective weight of servers participating to LB */
	int tot_uweight;		/* total user weight of servers participating to LB (for reporting) */
	int tot_used;			/* total number of servers used for LB */
	int wmult;			/* ratio between user weight and effective weight */
	int wdiv;			/* ratio between effective weight and user weight */
	int hash_balance_factor;	/* load balancing factor * 100, 0 if disabled */
	struct sample_expr *expr;       /* sample expression for "balance (log-)hash" */
	char *arg_str;			/* name of the URL parameter/header/cookie used for hashing */
	int   arg_len;			/* strlen(arg_str), computed only once */
	int   arg_opt1;			/* extra option 1 for the LB algo (algo-specific) */
	int   arg_opt2;			/* extra option 2 for the LB algo (algo-specific) */
	int   arg_opt3;			/* extra option 3 for the LB algo (algo-specific) */
	__decl_thread(HA_RWLOCK_T lock);
	struct server *fbck;		/* first backup server when !PR_O_USE_ALL_BK, or NULL */

	/* Call backs for some actions. Any of them may be NULL (thus should be ignored).
	 * Those marked "srvlock" will need to be called with the server lock held.
	 * The other ones might take it themselves if needed.
	 */
	void (*update_server_eweight)(struct server *);  /* to be called after eweight change // srvlock */
	void (*set_server_status_up)(struct server *);   /* to be called after status changes to UP // srvlock */
	void (*set_server_status_down)(struct server *); /* to be called after status changes to DOWN // srvlock */
	void (*server_take_conn)(struct server *);       /* to be called when connection is assigned */
	void (*server_drop_conn)(struct server *);       /* to be called when connection is dropped */
};

#endif /* _HAPROXY_BACKEND_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
