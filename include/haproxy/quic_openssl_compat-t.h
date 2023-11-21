#ifndef _HAPROXY_QUIC_OPENSSL_COMPAT_T_H_
#define _HAPROXY_QUIC_OPENSSL_COMPAT_T_H_

#ifdef USE_QUIC_OPENSSL_COMPAT
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#define QUIC_OPENSSL_COMPAT_TLS_SECRET_LEN 48
#define QUIC_OPENSSL_COMPAT_TLS_IV_LEN     12

/* Highly inspired from nginx QUIC TLS compatibility code */

enum ssl_encryption_level_t {
	ssl_encryption_initial = 0,
	ssl_encryption_early_data,
	ssl_encryption_handshake,
	ssl_encryption_application
};

typedef struct ssl_quic_method_st {
	int (*set_encryption_secrets)(SSL *ssl, enum ssl_encryption_level_t level,
	                              const uint8_t *rsecret, const uint8_t *wsecret,
	                              size_t secret_len);
	int (*add_handshake_data)(SSL *ssl, enum ssl_encryption_level_t level,
	                          const uint8_t *data, size_t len);
	int (*flush_flight)(SSL *ssl);
	int (*send_alert)(SSL *ssl, enum ssl_encryption_level_t level,
	                  uint8_t alert);
} SSL_QUIC_METHOD;

struct quic_tls_md {
	unsigned char data[QUIC_OPENSSL_COMPAT_TLS_SECRET_LEN];
	size_t len;
};

struct quic_tls_iv {
	unsigned char data[QUIC_OPENSSL_COMPAT_TLS_IV_LEN];
	size_t len;
};

struct quic_tls_secret {
	struct quic_tls_md secret;
	struct quic_tls_md key;
	struct quic_tls_iv iv;
};

struct quic_tls_compat_keys {
	struct quic_tls_secret secret;
	const EVP_CIPHER *cipher;
};

struct quic_openssl_compat {
	BIO *rbio;
	BIO *wbio;
	const SSL_QUIC_METHOD *method;
	enum ssl_encryption_level_t write_level;
	enum ssl_encryption_level_t read_level;
	uint64_t read_record;
	struct quic_tls_compat_keys keys;
};

#endif /* USE_QUIC_OPENSSL_COMPAT */
#endif /* _HAPROXY_QUIC_OPENSSL_COMPAT_T_H_ */
