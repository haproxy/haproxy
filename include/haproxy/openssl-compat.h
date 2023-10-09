#ifndef _HAPROXY_OPENSSL_COMPAT_H
#define _HAPROXY_OPENSSL_COMPAT_H
#ifdef USE_OPENSSL

#ifdef USE_OPENSSL_WOLFSSL
#define TLSEXT_MAXLEN_host_name 255
#include <wolfssl/options.h>
#endif

#ifdef USE_OPENSSL_AWSLC
#include <openssl/base.h>
#if !defined(OPENSSL_IS_AWSLC)
#error "USE_OPENSSL_AWSLC is set but OPENSSL_IS_AWSLC is not defined, wrong header files detected"
#endif
#endif

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
#include <openssl/ocsp.h>
#endif
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#if defined(USE_ENGINE) && !defined(OPENSSL_NO_ENGINE)
#include <openssl/engine.h>
#endif

#ifdef SSL_MODE_ASYNC
#include <openssl/async.h>
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x3000000fL)
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#endif

#ifdef USE_QUIC_OPENSSL_COMPAT
#include <haproxy/quic_openssl_compat.h>
#endif

#if defined(LIBRESSL_VERSION_NUMBER)
/* LibreSSL is a fork of OpenSSL 1.0.1g but pretends to be 2.0.0, thus
 * systematically breaking when some code is written for a specific version
 * of OpenSSL. Let's make it appear like what it really is and deal with
 * extra features with ORs and not with AND NOT.
 */
#define HA_OPENSSL_VERSION_NUMBER 0x1000107fL
#else /* this is for a real OpenSSL or a truly compatible derivative */
#define HA_OPENSSL_VERSION_NUMBER OPENSSL_VERSION_NUMBER
#endif

#ifndef OPENSSL_VERSION
#define OPENSSL_VERSION         SSLEAY_VERSION
#define OpenSSL_version(x)      SSLeay_version(x)
#define OpenSSL_version_num     SSLeay
#endif

#if (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x2070100fL) || defined(OPENSSL_IS_BORINGSSL) || (!defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L))
#define HAVE_SSL_EXTRACT_RANDOM
#endif

#if ((OPENSSL_VERSION_NUMBER >= 0x10101000L) && !defined(OPENSSL_IS_BORINGSSL) && !defined(LIBRESSL_VERSION_NUMBER))
#define HAVE_SSL_RAND_KEEP_RANDOM_DEVICES_OPEN
#endif

#if ((OPENSSL_VERSION_NUMBER >= 0x10101000L) && !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL)) || defined(USE_OPENSSL_WOLFSSL)
#define HAVE_SSL_CTX_SET_CIPHERSUITES
#define HAVE_ASN1_TIME_TO_TM
#endif

#if (defined(SSL_CLIENT_HELLO_CB) || defined(OPENSSL_IS_BORINGSSL))
#define HAVE_SSL_CLIENT_HELLO_CB
#endif

#if ((OPENSSL_VERSION_NUMBER >= 0x1000200fL) && !defined(OPENSSL_NO_TLSEXT) && !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL))
#define HAVE_SSL_CTX_ADD_SERVER_CUSTOM_EXT
#endif

#if ((OPENSSL_VERSION_NUMBER >= 0x10002000L) && !defined(LIBRESSL_VERSION_NUMBER))
#define HAVE_SSL_CTX_get0_privatekey
#endif

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000104fL || defined(USE_OPENSSL_WOLFSSL) || defined(USE_OPENSSL_AWSLC)
/* CRYPTO_memcmp() is present since openssl 1.0.1d */
#define HAVE_CRYPTO_memcmp
#endif

#if (defined(SN_ct_cert_scts) && !defined(OPENSSL_NO_TLSEXT))
#define HAVE_SSL_SCTL
#endif

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L) || defined(USE_OPENSSL_AWSLC) || (defined(USE_OPENSSL_WOLFSSL) && defined(HAVE_SECRET_CALLBACK))
#define HAVE_SSL_KEYLOG
#endif

/* minimum OpenSSL 1.1.1 & libreSSL 3.3.6 */
#if (defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER >= 0x3030600L)) || (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L) || defined(USE_OPENSSL_WOLFSSL)
#define HAVE_SSL_get0_verified_chain
#endif


#if (HA_OPENSSL_VERSION_NUMBER >= 0x3000000fL)
#define HAVE_OSSL_PARAM
#define MAC_CTX EVP_MAC_CTX
#define HASSL_DH EVP_PKEY
#define HASSL_DH_free EVP_PKEY_free
#define HASSL_DH_up_ref EVP_PKEY_up_ref

#define HAVE_SSL_PROVIDERS

#else /* HA_OPENSSL_VERSION_NUMBER >= 0x3000000fL */
#define MAC_CTX HMAC_CTX
#define HASSL_DH DH
#define HASSL_DH_free DH_free
#define HASSL_DH_up_ref DH_up_ref
#endif

#if ((HA_OPENSSL_VERSION_NUMBER < 0x1000000fL) && !defined(X509_get_X509_PUBKEY))
#define X509_get_X509_PUBKEY(x) ((x)->cert_info->key)
#endif


#if (HA_OPENSSL_VERSION_NUMBER < 0x1000100fL)
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


#if (HA_OPENSSL_VERSION_NUMBER < 0x1000200fL) && (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2070500fL)
/* introduced in openssl 1.0.2 */

static inline STACK_OF(X509) *X509_chain_up_ref(STACK_OF(X509) *chain)
{
	STACK_OF(X509) *ret;
	int i;

	if ((ret = sk_X509_dup(chain)) == NULL)
		return NULL;
	for (i = 0; i < sk_X509_num(ret); i++) {
		X509 *x = sk_X509_value(ret, i);
		CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
	}
	return ret;
}

#endif

#ifdef OPENSSL_IS_BORINGSSL
/*
 * Functions missing in BoringSSL
 */

static inline X509_CRL *X509_OBJECT_get0_X509_CRL(const X509_OBJECT *a)
{
    if (a == NULL || a->type != X509_LU_CRL) {
        return NULL;
    }
    return a->data.crl;
}
#endif

#if (HA_OPENSSL_VERSION_NUMBER < 0x1010000fL) && (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2070000fL)
/*
 * Functions introduced in OpenSSL 1.1.0 and in LibreSSL 2.7.0
 */

static inline STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(X509_STORE *st)
{
    return st->objs;
}

static inline int X509_OBJECT_get_type(const X509_OBJECT *a)
{
    return a->type;
}

static inline X509 *X509_OBJECT_get0_X509(const X509_OBJECT *a)
{
    if (a == NULL || a->type != X509_LU_X509) {
        return NULL;
    }
    return a->data.x509;
}

static inline X509_CRL *X509_OBJECT_get0_X509_CRL(const X509_OBJECT *a)
{
    if (a == NULL || a->type != X509_LU_CRL) {
        return NULL;
    }
    return a->data.crl;
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

static inline void X509_up_ref(X509 *x)
{
	CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
}

static inline void EVP_PKEY_up_ref(EVP_PKEY *pkey)
{
	CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
}

static inline void SSL_CTX_up_ref(SSL_CTX *ctx)
{
    CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
}

static inline int X509_CRL_get_signature_nid(const X509_CRL *crl)
{
	return OBJ_obj2nid(crl->sig_alg->algorithm);
}

static inline const ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *crl)
{
	return X509_CRL_get_lastUpdate(crl);
}

static inline const ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *crl)
{
	return X509_CRL_get_nextUpdate(crl);
}

static inline const ASN1_INTEGER *X509_REVOKED_get0_serialNumber(const X509_REVOKED *x)
{
    return x->serialNumber;
}

static inline const ASN1_TIME *X509_REVOKED_get0_revocationDate(const X509_REVOKED *x)
{
    return x->revocationDate;
}

static inline X509 *X509_STORE_CTX_get0_cert(X509_STORE_CTX *ctx)
{
    return ctx->cert;
}

static inline int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	if (r == NULL || s == NULL)
		return 0;
	BN_clear_free(sig->r);
	BN_clear_free(sig->s);

	sig->r = r;
	sig->s = s;
	return 1;
}

#endif

#if (HA_OPENSSL_VERSION_NUMBER < 0x3000000fL)
#if defined(SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB)
#define SSL_CTX_set_tlsext_ticket_key_evp_cb SSL_CTX_set_tlsext_ticket_key_cb
#endif

/*
 * Functions introduced in OpenSSL 3.0.0
 */
static inline unsigned long ERR_peek_error_func(const char **func)
{
	unsigned long ret = ERR_peek_error();
	if (ret == 0)
		return ret;

	if (func)
		*func = ERR_func_error_string(ret);

	return ret;
}

#endif

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x2070200fL)
#define __OPENSSL_110_CONST__ const
#else
#define __OPENSSL_110_CONST__
#endif

/* ERR_remove_state() was deprecated in 1.0.0 in favor of
 * ERR_remove_thread_state(), which was in turn deprecated in
 * 1.1.0 and does nothing anymore. Let's simply silently kill
 * it.
 */
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL)
#undef  ERR_remove_state
#define ERR_remove_state(x)
#endif


/* RAND_pseudo_bytes() is deprecated in 1.1.0 in favor of RAND_bytes(). Note
 * that the return codes differ, but it happens that the only use case (ticket
 * key update) was already wrong, considering a non-cryptographic random as a
 * failure.
 */
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL)
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

#if ((HA_OPENSSL_VERSION_NUMBER < 0x1010000fL) && (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2070000fL)) ||\
	defined(OPENSSL_IS_BORINGSSL)
#define X509_getm_notBefore     X509_get_notBefore
#define X509_getm_notAfter      X509_get_notAfter
#endif

#if !defined(EVP_CTRL_AEAD_SET_IVLEN)
#define EVP_CTRL_AEAD_SET_IVLEN EVP_CTRL_GCM_SET_IVLEN
#endif

#if !defined(EVP_CTRL_AEAD_SET_TAG)
#define EVP_CTRL_AEAD_SET_TAG   EVP_CTRL_GCM_SET_TAG
#endif

/* Supported hash function for TLS tickets */
#ifdef OPENSSL_NO_SHA256
#define TLS_TICKET_HASH_FUNCT EVP_sha1
#else
#define TLS_TICKET_HASH_FUNCT EVP_sha256
#endif /* OPENSSL_NO_SHA256 */

#ifndef SSL_OP_CIPHER_SERVER_PREFERENCE                 /* needs OpenSSL >= 0.9.7 */
#define SSL_OP_CIPHER_SERVER_PREFERENCE 0
#endif

#ifndef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   /* needs OpenSSL >= 0.9.7 */
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION 0
#define SSL_renegotiate_pending(arg) 0
#endif

#ifndef SSL_OP_SINGLE_ECDH_USE                          /* needs OpenSSL >= 0.9.8 */
#define SSL_OP_SINGLE_ECDH_USE 0
#endif

#ifndef SSL_OP_NO_TICKET                                /* needs OpenSSL >= 0.9.8 */
#define SSL_OP_NO_TICKET 0
#endif

#ifndef SSL_OP_NO_COMPRESSION                           /* needs OpenSSL >= 0.9.9 */
#define SSL_OP_NO_COMPRESSION 0
#endif

#ifdef OPENSSL_NO_SSL3                                  /* SSLv3 support removed */
#undef  SSL_OP_NO_SSLv3
#define SSL_OP_NO_SSLv3 0
#endif

#ifndef SSL_OP_NO_TLSv1_1                               /* needs OpenSSL >= 1.0.1 */
#define SSL_OP_NO_TLSv1_1 0
#endif

#ifndef SSL_OP_NO_TLSv1_2                               /* needs OpenSSL >= 1.0.1 */
#define SSL_OP_NO_TLSv1_2 0
#endif

#ifndef SSL_OP_NO_TLSv1_3                               /* needs OpenSSL >= 1.1.1 */
#define SSL_OP_NO_TLSv1_3 0
#endif

#ifndef SSL_OP_SINGLE_DH_USE                            /* needs OpenSSL >= 0.9.6 */
#define SSL_OP_SINGLE_DH_USE 0
#endif

#ifndef SSL_OP_SINGLE_ECDH_USE                            /* needs OpenSSL >= 1.0.0 */
#define SSL_OP_SINGLE_ECDH_USE 0
#endif

#ifndef SSL_MODE_RELEASE_BUFFERS                        /* needs OpenSSL >= 1.0.0 */
#define SSL_MODE_RELEASE_BUFFERS 0
#endif

#ifndef SSL_MODE_SMALL_BUFFERS                          /* needs small_records.patch */
#define SSL_MODE_SMALL_BUFFERS 0
#endif

#ifndef SSL_OP_PRIORITIZE_CHACHA                        /* needs OpenSSL >= 1.1.1 */
#define SSL_OP_PRIORITIZE_CHACHA 0
#endif

#ifndef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
#define SSL_CTX_get_extra_chain_certs(ctx, chain) do { *(chain) = (ctx)->extra_certs; } while (0)
#endif

#if HA_OPENSSL_VERSION_NUMBER < 0x10100000L && (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2070000fL)
#define BIO_get_data(b)            (b)->ptr
#define BIO_set_data(b, v)         do { (b)->ptr  = (v); } while (0)
#define BIO_set_init(b, v)         do { (b)->init = (v); } while (0)

#define BIO_meth_free(m)           free(m)
#define BIO_meth_new(type, name)   calloc(1, sizeof(BIO_METHOD))
#define BIO_meth_set_gets(m, f)    do { (m)->bgets   = (f); } while (0)
#define BIO_meth_set_puts(m, f)    do { (m)->bputs   = (f); } while (0)
#define BIO_meth_set_read(m, f)    do { (m)->bread   = (f); } while (0)
#define BIO_meth_set_write(m, f)   do { (m)->bwrite  = (f); } while (0)
#define BIO_meth_set_create(m, f)  do { (m)->create  = (f); } while (0)
#define BIO_meth_set_ctrl(m, f)    do { (m)->ctrl    = (f); } while (0)
#define BIO_meth_set_destroy(m, f) do { (m)->destroy = (f); } while (0)
#endif

#ifndef SSL_CTX_set_ecdh_auto
#define SSL_CTX_set_ecdh_auto(dummy, onoff)      ((onoff) != 0)
#endif

/* The EVP_MD_CTX_create() and EVP_MD_CTX_destroy() functions were renamed to
 * EVP_MD_CTX_new() and EVP_MD_CTX_free() in OpenSSL 1.1.0, respectively.
 */
#if (HA_OPENSSL_VERSION_NUMBER < 0x1010000fL)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

/* OpenSSL 1.0.2 and onwards define SSL_CTX_set1_curves_list which is both a
 * function and a macro. OpenSSL 1.0.2 to 1.1.0 define SSL_CTRL_SET_CURVES_LIST
 * as a macro, which disappeared from 1.1.1. BoringSSL only has that one and
 * not the former macro but it does have the function. Let's keep the test on
 * the macro matching the function name.
 */
#if !defined(SSL_CTX_set1_curves_list) && defined(SSL_CTRL_SET_CURVES_LIST)
#define SSL_CTX_set1_curves_list SSL_CTX_set1_curves_list
#endif

#if !defined(SSL_CTX_set1_sigalgs_list) && defined(SSL_CTRL_SET_SIGALGS_LIST)
#define SSL_CTX_set1_sigalgs_list SSL_CTX_set1_sigalgs_list
#endif

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_OPENSSL_COMPAT_H */
