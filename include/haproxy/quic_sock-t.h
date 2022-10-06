#ifndef _HAPROXY_QUIC_SOCK_T_H
#define _HAPROXY_QUIC_SOCK_T_H
#ifdef USE_QUIC

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

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_SOCK_T_H */
