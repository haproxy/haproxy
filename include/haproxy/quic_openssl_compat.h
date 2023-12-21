#ifndef _HAPROXY_QUIC_OPENSSL_COMPAT_H_
#define _HAPROXY_QUIC_OPENSSL_COMPAT_H_

#ifdef USE_QUIC_OPENSSL_COMPAT

/* Highly inspired from nginx QUIC TLS compatibility code */
#include <haproxy/listener-t.h>
#include <haproxy/quic_openssl_compat-t.h>

#define QUIC_OPENSSL_COMPAT_SSL_TP_EXT           0x39

/* Used by keylog */
#define QUIC_OPENSSL_COMPAT_CLIENT_HANDSHAKE     "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
#define QUIC_OPENSSL_COMPAT_SERVER_HANDSHAKE     "SERVER_HANDSHAKE_TRAFFIC_SECRET"
#define QUIC_OPENSSL_COMPAT_CLIENT_APPLICATION   "CLIENT_TRAFFIC_SECRET_0"
#define QUIC_OPENSSL_COMPAT_SERVER_APPLICATION   "SERVER_TRAFFIC_SECRET_0"

void quic_tls_compat_msg_callback(struct connection *conn,
                                  int write_p, int version, int content_type,
                                  const void *buf, size_t len, SSL *ssl);
int quic_tls_compat_init(struct bind_conf *bind_conf, SSL_CTX *ctx);
void quic_tls_compat_keylog_callback(const SSL *ssl, const char *line);

int SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *quic_method);
enum ssl_encryption_level_t SSL_quic_read_level(const SSL *ssl);
enum ssl_encryption_level_t SSL_quic_write_level(const SSL *ssl);
int SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params, size_t params_len);
int SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level,
                          const uint8_t *data, size_t len);
int SSL_process_quic_post_handshake(SSL *ssl);

#endif /* USE_QUIC_OPENSSL_COMPAT */
#endif /* _HAPROXY_QUIC_OPENSSL_COMPAT_H_ */
