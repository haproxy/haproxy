#ifndef _HAPROXY_QUIC_SOCK_T_H
#define _HAPROXY_QUIC_SOCK_T_H
#ifdef USE_QUIC

#include <haproxy/buf-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/mpring.h>

/* QUIC socket allocation strategy. */
enum quic_sock_mode {
	QUIC_SOCK_MODE_CONN,  /* Use a dedicated socket per connection. */
	QUIC_SOCK_MODE_LSTNR, /* Multiplex connections over listener socket. */
};

/* QUIC connection accept queue. One per thread. */
struct quic_accept_queue {
	struct mt_list listeners; /* QUIC listeners with at least one connection ready to be accepted on this queue */
	struct tasklet *tasklet;  /* task responsible to call listener_accept */
};

#define QUIC_DGRAM_FL_REJECT			0x00000001
#define QUIC_DGRAM_FL_SEND_RETRY		0x00000002

union sockaddr_in46 {
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
};

/* QUIC datagram */
struct quic_dgram {
	enum obj_type obj_type;
	void *owner;
	unsigned char *buf;
	size_t len;
	size_t dcid_off;
	size_t dcid_len;
	union sockaddr_in46 saddr;
	union sockaddr_in46 daddr;
	struct quic_conn *qc;

	int flags; /* QUIC_DGRAM_FL_* values */
};

/* QUIC datagram handler */
struct quic_dghdlr {
	struct mpring buf;      /* MPSC ring buffer for datagrams. */
	struct tasklet *task;
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_SOCK_T_H */
