/*
 * include/haproxy/check.h
 * Functions prototypes for the checks.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_CHECKS_H
#define _HAPROXY_CHECKS_H

#include <haproxy/check-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>
#include <haproxy/trace-t.h>

extern struct trace_source trace_check;

/* Details about these events are defined in <src/check.c> */
#define CHK_EV_TASK_WAKE       (1ULL <<  0)
#define CHK_EV_HCHK_START      (1ULL <<  1)
#define CHK_EV_HCHK_WAKE       (1ULL <<  2)
#define CHK_EV_HCHK_RUN        (1ULL <<  3)
#define CHK_EV_HCHK_END        (1ULL <<  4)
#define CHK_EV_HCHK_SUCC       (1ULL <<  5)
#define CHK_EV_HCHK_ERR        (1ULL <<  6)
#define CHK_EV_HCHK            (CHK_EV_HCHK_START|CHK_EV_HCHK_WAKE|CHK_EV_HCHK_RUN|\
				CHK_EV_HCHK_END|CHK_EV_HCHK_SUCC|CHK_EV_HCHK_ERR)

#define CHK_EV_TCPCHK_EVAL     (1ULL <<  7)
#define CHK_EV_TCPCHK_ERR      (1ULL <<  8)
#define CHK_EV_TCPCHK_CONN     (1ULL <<  9)
#define CHK_EV_TCPCHK_SND      (1ULL << 10)
#define CHK_EV_TCPCHK_EXP      (1ULL << 11)
#define CHK_EV_TCPCHK_ACT      (1ULL << 12)
#define CHK_EV_TCPCHK          (CHK_EV_TCPCHK_EVAL|CHK_EV_TCPCHK_ERR|CHK_EV_TCPCHK_CONN|\
				CHK_EV_TCPCHK_SND|CHK_EV_TCPCHK_EXP|CHK_EV_TCPCHK_ACT)

#define CHK_EV_RX_DATA         (1ULL << 13)
#define CHK_EV_RX_BLK          (1ULL << 14)
#define CHK_EV_RX_ERR          (1ULL << 15)
#define CHK_EV_RX              (CHK_EV_RX_DATA|CHK_EV_RX_BLK|CHK_EV_RX_ERR)

#define CHK_EV_TX_DATA         (1ULL << 16)
#define CHK_EV_TX_BLK          (1ULL << 17)
#define CHK_EV_TX_ERR          (1ULL << 18)
#define CHK_EV_TX              (CHK_EV_TX_DATA|CHK_EV_TX_BLK|CHK_EV_TX_ERR)

extern struct data_cb check_conn_cb;
extern struct proxy checks_fe;

short get_check_status_result(short check_status);
const char *get_check_status_description(short check_status);
const char *get_check_status_info(short check_status);
int httpchk_build_status_header(struct server *s, struct buffer *buf);
void __health_adjust(struct server *s, short status);
void check_append_info(struct buffer *msg, struct check *check);
void set_server_check_status(struct check *check, short status, const char *desc);
void chk_report_conn_err(struct check *check, int errno_bck, int expired);
void check_notify_failure(struct check *check);
void check_notify_stopping(struct check *check);
void check_notify_success(struct check *check);
struct task *process_chk(struct task *t, void *context, unsigned int state);

struct task *srv_chk_io_cb(struct task *t, void *ctx, unsigned int state);

int check_buf_available(void *target);
struct buffer *check_get_buf(struct check *check, struct buffer *bptr);
void check_release_buf(struct check *check, struct buffer *bptr);
const char *init_check(struct check *check, int type);
void free_check(struct check *check);
void check_purge(struct check *check);
int wake_srv_chk(struct stconn *sc);

int init_srv_check(struct server *srv);
int init_srv_agent_check(struct server *srv);
int start_check_task(struct check *check, int mininter, int nbcheck, int srvpos);

int set_srv_agent_send(struct server *srv, const char *send);

/* set agent addr and appropriate flag */
static inline void set_srv_agent_addr(struct server *srv, struct sockaddr_storage *sk)
{
	srv->agent.addr = *sk;
	srv->flags |= SRV_F_AGENTADDR;
}

/* set agent port and appropriate flag */
static inline void set_srv_agent_port(struct server *srv, int port)
{
	srv->agent.port = port;
	srv->flags |= SRV_F_AGENTPORT;
}

/* Use this one only. This inline version only ensures that we don't
 * call the function when the observe mode is disabled.
 */
static inline void health_adjust(struct server *s, short status)
{
	/* return now if observing nor health check is not enabled */
	if (!s->observe || !s->check.task)
		return;

	__health_adjust(s, status);
}

#endif /* _HAPROXY_CHECKS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
