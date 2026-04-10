#ifndef _HAPROXY_XPRT_QSTRM_H
#define _HAPROXY_XPRT_QSTRM_H

const struct quic_transport_params *xprt_qstrm_lparams(const void *context);
const struct quic_transport_params *xprt_qstrm_rparams(const void *context);

struct buffer *xprt_qstrm_rxbuf(const void *context);

#endif /* _HAPROXY_XPRT_QSTRM_H */
