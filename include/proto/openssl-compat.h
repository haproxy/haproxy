#ifndef _PROTO_OPENSSL_COMPAT_H
#define _PROTO_OPENSSL_COMPAT_H
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
#include <openssl/ocsp.h>
#endif
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif

#if (OPENSSL_VERSION_NUMBER < 0x0090800fL)
/* Functions present in OpenSSL 0.9.8, older not tested */
static inline const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *sess, unsigned int *sid_length)
{
	*sid_length = sess->session_id_length;
	return sess->session_id;
}

static inline X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *name, int loc)
{
	return sk_X509_NAME_ENTRY_value(name->entries, loc);
}

static inline ASN1_OBJECT *X509_NAME_ENTRY_get_object(const X509_NAME_ENTRY *ne)
{
	return ne->object;
}

static inline ASN1_STRING *X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne)
{
	return ne->value;
}

static inline int ASN1_STRING_length(const ASN1_STRING *x)
{
	return x->length;
}

static inline int X509_NAME_entry_count(X509_NAME *name)
{
	return sk_X509_NAME_ENTRY_num(name->entries)
}

static inline void X509_ALGOR_get0(ASN1_OBJECT **paobj, int *pptype, const void **ppval, const X509_ALGOR *algor)
{
	*paobj = algor->algorithm;
}

#endif // OpenSSL < 0.9.8


#if (OPENSSL_VERSION_NUMBER < 0x1000000fL)
/* Functions introduced in OpenSSL 1.0.0 */
static inline int EVP_PKEY_base_id(const EVP_PKEY *pkey)
{
	return EVP_PKEY_type(pkey->type);
}

/* minimal implementation based on the fact that the only known call place
 * doesn't make use of other arguments.
 */
static inline int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen, X509_ALGOR **pa, X509_PUBKEY *pub)
{
	*ppkalg = pub->algor->algorithm;
	return 1;
}

#ifndef X509_get_X509_PUBKEY
#define X509_get_X509_PUBKEY(x) ((x)->cert_info->key
#endif

#endif

#if (OPENSSL_VERSION_NUMBER < 0x1000100fL)
/*
 * Functions introduced in OpenSSL 1.0.1
 */
static inline int SSL_SESSION_set1_id_context(SSL_SESSION *s, const unsigned char *sid_ctx, unsigned int sid_ctx_len)
{
	s->sid_ctx_length = sid_ctx_len;
	memcpy(s->sid_ctx, sid_ctx, sid_ctx_len);
	return 1;
}
#endif

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL) || defined(LIBRESSL_VERSION_NUMBER) || defined(OPENSSL_IS_BORINGSSL)
/*
 * Functions introduced in OpenSSL 1.1.0 and not yet present in LibreSSL / BoringSSL
 */

static inline const unsigned char *SSL_SESSION_get0_id_context(const SSL_SESSION *sess, unsigned int *sid_ctx_length)
{
	*sid_ctx_length = sess->sid_ctx_length;
	return sess->sid_ctx;
}

static inline int SSL_SESSION_set1_id(SSL_SESSION *s, const unsigned char *sid, unsigned int sid_len)
{
	s->session_id_length = sid_len;
	memcpy(s->session_id, sid, sid_len);
	return 1;
}

static inline X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x)
{
	return x->cert_info->signature;
}

#if (!defined OPENSSL_NO_OCSP)
static inline const OCSP_CERTID *OCSP_SINGLERESP_get0_id(const OCSP_SINGLERESP *single)
{
	return single->certId;
}
#endif

#endif

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL) || defined(LIBRESSL_VERSION_NUMBER)
/*
 * Functions introduced in OpenSSL 1.1.0 and not yet present in LibreSSL
 */

static inline pem_password_cb *SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx)
{
	return ctx->default_passwd_callback;
}

static inline void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx)
{
	return ctx->default_passwd_callback_userdata;
}

#ifndef OPENSSL_NO_DH
static inline int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	/* Implements only the bare necessities for HAProxy */
	dh->p = p;
	dh->g = g;
	return 1;
}
#endif

static inline const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x)
{
	return x->data;
}

#endif

#if (OPENSSL_VERSION_NUMBER >= 0x1010000fL)
#define __OPENSSL_110_CONST__ const
#else
#define __OPENSSL_110_CONST__
#endif

#ifdef OPENSSL_IS_BORINGSSL
#define SSL_NO_GENERATE_CERTIFICATES

static inline int EVP_PKEY_base_id(EVP_PKEY *pkey)
{
	return EVP_PKEY_type(pkey->type);
}
#endif

/* ERR_remove_state() was deprecated in 1.0.0 in favor of
 * ERR_remove_thread_state(), which was in turn deprecated in
 * 1.1.0 and does nothing anymore. Let's simply silently kill
 * it.
 */
#if (OPENSSL_VERSION_NUMBER >= 0x1010000fL)
#undef  ERR_remove_state
#define ERR_remove_state(x)
#endif


/* RAND_pseudo_bytes() is deprecated in 1.1.0 in favor of RAND_bytes(). Note
 * that the return codes differ, but it happens that the only use case (ticket
 * key update) was already wrong, considering a non-cryptographic random as a
 * failure.
 */
#if (OPENSSL_VERSION_NUMBER >= 0x1010000fL)
#undef  RAND_pseudo_bytes
#define RAND_pseudo_bytes(x,y) RAND_bytes(x,y)
#endif


/* Signature from RFC 5246, missing in openssl < 1.0.1 */
#ifndef TLSEXT_signature_anonymous
#define TLSEXT_signature_anonymous  0
#define TLSEXT_signature_rsa        1
#define TLSEXT_signature_dsa        2
#define TLSEXT_signature_ecdsa      3
#endif

#endif /* _PROTO_OPENSSL_COMPAT_H */
