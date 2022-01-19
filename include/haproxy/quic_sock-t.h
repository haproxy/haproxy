#ifndef _HAPROXY_QUIC_SOCK_T_H
#define _HAPROXY_QUIC_SOCK_T_H
#ifdef USE_QUIC

/* QUIC connection accept queue. One per thread. */
struct quic_accept_queue {
	struct mt_list listeners; /* QUIC listeners with at least one connection ready to be accepted on this queue */
	struct tasklet *tasklet;  /* task responsible to call listener_accept */
};

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_SOCK_T_H */
