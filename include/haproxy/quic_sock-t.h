#ifndef _HAPROXY_QUIC_SOCK_T_H
#define _HAPROXY_QUIC_SOCK_T_H
#ifdef USE_QUIC

#include <haproxy/buf-t.h>
#include <haproxy/obj_type-t.h>

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

/* Buffer used to receive QUIC datagrams on random thread and redispatch them
 * to the connection thread.
 */
struct quic_receiver_buf {
	struct buffer buf; /* storage for datagrams received. */
	struct list dgram_list; /* datagrams received with this rxbuf. */
	struct mt_list rxbuf_el; /* list element into receiver.rxbuf_list. */
};

#define QUIC_DGRAM_FL_REJECT			0x00000001
#define QUIC_DGRAM_FL_SEND_RETRY		0x00000002

/* QUIC datagram */
struct quic_dgram {
	enum obj_type obj_type;
	void *owner;
	unsigned char *buf;
	size_t len;
	unsigned char *dcid;
	size_t dcid_len;
	struct sockaddr_storage saddr;
	struct sockaddr_storage daddr;
	struct quic_conn *qc;

	struct list recv_list; /* element pointing to quic_receiver_buf <dgram_list>. */
	struct mt_list handler_list; /* element pointing to quic_dghdlr <dgrams>. */

	int flags; /* QUIC_DGRAM_FL_* values */
};

/* QUIC datagram handler */
struct quic_dghdlr {
	struct mt_list dgrams;
	struct tasklet *task;
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_SOCK_T_H */
