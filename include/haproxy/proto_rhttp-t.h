#ifndef _HAPROXY_PROTO_RHTTP_H_T
#define _HAPROXY_PROTO_RHTTP_H_T

/* State for reverse preconnect listener state machine.
 * Used to limit log reporting only on state changes.
 */
enum li_preconn_state {
	LI_PRECONN_ST_STOP, /* pre-connect task inactive */
	LI_PRECONN_ST_INIT, /* pre-connect task bootstrapped */
	LI_PRECONN_ST_ERR,  /* last pre-connect attempt failed */
	LI_PRECONN_ST_FULL, /* pre-connect maxconn reached */
};

#endif /* _HAPROXY_PROTO_RHTTP_H_T */
