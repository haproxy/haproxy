/*
 * SSL 'generate-certificate' option logic.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <import/lru.h>

#include <haproxy/errors.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/xxhash.h>

#if (defined SSL_CTRL_SET_TLSEXT_HOSTNAME && !defined SSL_NO_GENERATE_CERTIFICATES)
/* X509V3 Extensions that will be added on generated certificates */
#define X509V3_EXT_SIZE 5
static char *x509v3_ext_names[X509V3_EXT_SIZE] = {
	"basicConstraints",
	"nsComment",
	"subjectKeyIdentifier",
	"authorityKeyIdentifier",
	"keyUsage",
};
static char *x509v3_ext_values[X509V3_EXT_SIZE] = {
	"CA:FALSE",
	"\"OpenSSL Generated Certificate\"",
	"hash",
	"keyid,issuer:always",
	"nonRepudiation,digitalSignature,keyEncipherment"
};
/* LRU cache to store generated certificate */
static struct lru64_head *ssl_ctx_lru_tree = NULL;
static unsigned int       ssl_ctx_lru_seed = 0;
static unsigned int	  ssl_ctx_serial;
__decl_rwlock(ssl_ctx_lru_rwlock);

#endif // SSL_CTRL_SET_TLSEXT_HOSTNAME

#ifndef SSL_NO_GENERATE_CERTIFICATES

/* Configure a DNS SAN extension on a certificate. */
int ssl_sock_add_san_ext(X509V3_CTX* ctx, X509* cert, const char *servername) {
	int failure = 0;
	X509_EXTENSION *san_ext = NULL;
	CONF *conf = NULL;
	struct buffer *san_name = get_trash_chunk();

	conf = NCONF_new(NULL);
	if (!conf) {
		failure = 1;
		goto cleanup;
	}

	/* Build an extension based on the DNS entry above */
	chunk_appendf(san_name, "DNS:%s", servername);
	san_ext = X509V3_EXT_nconf_nid(conf, ctx, NID_subject_alt_name, san_name->area);
	if (!san_ext) {
		failure = 1;
		goto cleanup;
	}

	/* Add the extension */
	if (!X509_add_ext(cert, san_ext, -1 /* Add to end */)) {
		failure = 1;
		goto cleanup;
	}

	/* Success */
	failure = 0;

cleanup:
	if (NULL != san_ext) X509_EXTENSION_free(san_ext);
	if (NULL != conf) NCONF_free(conf);

	return failure;
}

/* Create a X509 certificate with the specified servername and serial. This
 * function returns a SSL_CTX object or NULL if an error occurs. */
static SSL_CTX *ssl_sock_do_create_cert(const char *servername, struct bind_conf *bind_conf, SSL *ssl)
{
	X509         *cacert  = bind_conf->ca_sign_ckch->cert;
	EVP_PKEY     *capkey  = bind_conf->ca_sign_ckch->key;
	SSL_CTX      *ssl_ctx = NULL;
	X509         *newcrt  = NULL;
	EVP_PKEY     *pkey    = NULL;
	SSL          *tmp_ssl = NULL;
	CONF         *ctmp    = NULL;
	X509_NAME    *name;
	const EVP_MD *digest;
	X509V3_CTX    ctx;
	unsigned int  i;
	int 	      key_type;
	struct sni_ctx *sni_ctx;

	sni_ctx = ssl_sock_chose_sni_ctx(bind_conf, "", 1, 1);
	if (!sni_ctx)
		goto mkcert_error;

	/* Get the private key of the default certificate and use it */
#ifdef HAVE_SSL_CTX_get0_privatekey
	pkey = SSL_CTX_get0_privatekey(sni_ctx->ctx);
#else
	tmp_ssl = SSL_new(sni_ctx->ctx);
	if (tmp_ssl)
		pkey = SSL_get_privatekey(tmp_ssl);
#endif
	if (!pkey)
		goto mkcert_error;

	/* Create the certificate */
	if (!(newcrt = X509_new()))
		goto mkcert_error;

	/* Set version number for the certificate (X509v3) and the serial
	 * number */
	if (X509_set_version(newcrt, 2L) != 1)
		goto mkcert_error;
	ASN1_INTEGER_set(X509_get_serialNumber(newcrt), _HA_ATOMIC_ADD_FETCH(&ssl_ctx_serial, 1));

	/* Set duration for the certificate */
	if (!X509_gmtime_adj(X509_getm_notBefore(newcrt), (long)-60*60*24) ||
	    !X509_gmtime_adj(X509_getm_notAfter(newcrt),(long)60*60*24*365))
		goto mkcert_error;

	/* set public key in the certificate */
	if (X509_set_pubkey(newcrt, pkey) != 1)
		goto mkcert_error;

	/* Set issuer name from the CA */
	if (!(name = X509_get_subject_name(cacert)))
		goto mkcert_error;
	if (X509_set_issuer_name(newcrt, name) != 1)
		goto mkcert_error;

	/* Set the subject name using the same, but the CN */
	name = X509_NAME_dup(name);
	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				       (const unsigned char *)servername,
				       -1, -1, 0) != 1) {
		X509_NAME_free(name);
		goto mkcert_error;
	}
	if (X509_set_subject_name(newcrt, name) != 1) {
		X509_NAME_free(name);
		goto mkcert_error;
	}
	X509_NAME_free(name);

	/* Add x509v3 extensions as specified */
	ctmp = NCONF_new(NULL);
	X509V3_set_ctx(&ctx, cacert, newcrt, NULL, NULL, 0);
	for (i = 0; i < X509V3_EXT_SIZE; i++) {
		X509_EXTENSION *ext;

		if (!(ext = X509V3_EXT_nconf(ctmp, &ctx, x509v3_ext_names[i], x509v3_ext_values[i])))
			goto mkcert_error;
		if (!X509_add_ext(newcrt, ext, -1)) {
			X509_EXTENSION_free(ext);
			goto mkcert_error;
		}
		X509_EXTENSION_free(ext);
	}

	/* Add SAN extension */
	if (ssl_sock_add_san_ext(&ctx, newcrt, servername)) {
		goto mkcert_error;
	}

	/* Sign the certificate with the CA private key */

	key_type = EVP_PKEY_base_id(capkey);

	if (key_type == EVP_PKEY_DSA)
		digest = EVP_sha1();
	else if (key_type == EVP_PKEY_RSA)
		digest = EVP_sha256();
	else if (key_type == EVP_PKEY_EC)
		digest = EVP_sha256();
	else {
#ifdef ASN1_PKEY_CTRL_DEFAULT_MD_NID
		int nid;

		if (EVP_PKEY_get_default_digest_nid(capkey, &nid) <= 0)
			goto mkcert_error;
		if (!(digest = EVP_get_digestbynid(nid)))
			goto mkcert_error;
#else
		goto mkcert_error;
#endif
	}

	if (!(X509_sign(newcrt, capkey, digest)))
		goto mkcert_error;

	/* Create and set the new SSL_CTX */
	if (!(ssl_ctx = SSL_CTX_new(SSLv23_server_method())))
		goto mkcert_error;

	if (global_ssl.security_level > -1)
		SSL_CTX_set_security_level(ssl_ctx, global_ssl.security_level);

	if (!SSL_CTX_use_PrivateKey(ssl_ctx, pkey))
		goto mkcert_error;
	if (!SSL_CTX_use_certificate(ssl_ctx, newcrt))
		goto mkcert_error;
	if (!SSL_CTX_check_private_key(ssl_ctx))
		goto mkcert_error;

	/* Build chaining the CA cert and the rest of the chain, keep these order */
#if defined(SSL_CTX_add1_chain_cert)
	if (!SSL_CTX_add1_chain_cert(ssl_ctx, bind_conf->ca_sign_ckch->cert)) {
		goto mkcert_error;
	}

	if (bind_conf->ca_sign_ckch->chain) {
		for (i = 0; i < sk_X509_num(bind_conf->ca_sign_ckch->chain); i++) {
			X509 *chain_cert = sk_X509_value(bind_conf->ca_sign_ckch->chain, i);
			if (!SSL_CTX_add1_chain_cert(ssl_ctx, chain_cert)) {
				goto mkcert_error;
			}
		}
	}
#endif

	if (newcrt) X509_free(newcrt);

#ifndef OPENSSL_NO_DH
#if (HA_OPENSSL_VERSION_NUMBER < 0x3000000fL)
	SSL_CTX_set_tmp_dh_callback(ssl_ctx, ssl_get_tmp_dh_cbk);
#else
	ssl_sock_set_tmp_dh_from_pkey(ssl_ctx, pkey);
#endif
#endif

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
#if defined(SSL_CTX_set1_curves_list)
	{
		const char *ecdhe = (bind_conf->ssl_conf.ecdhe ? bind_conf->ssl_conf.ecdhe : ECDHE_DEFAULT_CURVE);
		if (!SSL_CTX_set1_curves_list(ssl_ctx, ecdhe))
			goto end;
	}
#endif
#else
#if defined(SSL_CTX_set_tmp_ecdh) && !defined(OPENSSL_NO_ECDH)
	{
		const char *ecdhe = (bind_conf->ssl_conf.ecdhe ? bind_conf->ssl_conf.ecdhe : ECDHE_DEFAULT_CURVE);
		EC_KEY     *ecc;
		int         nid;

		if ((nid = OBJ_sn2nid(ecdhe)) == NID_undef)
			goto end;
		if (!(ecc = EC_KEY_new_by_curve_name(nid)))
			goto end;
		SSL_CTX_set_tmp_ecdh(ssl_ctx, ecc);
		EC_KEY_free(ecc);
	}
#endif /* defined(SSL_CTX_set_tmp_ecdh) && !defined(OPENSSL_NO_ECDH) */
#endif /* HA_OPENSSL_VERSION_NUMBER >= 0x10101000L */
 end:
	return ssl_ctx;

 mkcert_error:
	if (ctmp) NCONF_free(ctmp);
	if (tmp_ssl) SSL_free(tmp_ssl);
	if (ssl_ctx) SSL_CTX_free(ssl_ctx);
	if (newcrt)  X509_free(newcrt);
	return NULL;
}


/* Do a lookup for a certificate in the LRU cache used to store generated
 * certificates and immediately assign it to the SSL session if not null. */
SSL_CTX *ssl_sock_assign_generated_cert(unsigned int key, struct bind_conf *bind_conf, SSL *ssl)
{
	struct lru64 *lru = NULL;

	if (ssl_ctx_lru_tree) {
		HA_RWLOCK_WRLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		lru = lru64_lookup(key, ssl_ctx_lru_tree, bind_conf->ca_sign_ckch->cert, 0);
		if (lru && lru->domain) {
			if (ssl)
				SSL_set_SSL_CTX(ssl, (SSL_CTX *)lru->data);
			HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
			return (SSL_CTX *)lru->data;
		}
		HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
	}
	return NULL;
}

/* Same as <ssl_sock_assign_generated_cert> but without SSL session. This
 * function is not thread-safe, it should only be used to check if a certificate
 * exists in the lru cache (with no warranty it will not be removed by another
 * thread). It is kept for backward compatibility. */
SSL_CTX *
ssl_sock_get_generated_cert(unsigned int key, struct bind_conf *bind_conf)
{
	return ssl_sock_assign_generated_cert(key, bind_conf, NULL);
}

/* Set a certificate int the LRU cache used to store generated
 * certificate. Return 0 on success, otherwise -1 */
int ssl_sock_set_generated_cert(SSL_CTX *ssl_ctx, unsigned int key, struct bind_conf *bind_conf)
{
	struct lru64 *lru = NULL;

	if (ssl_ctx_lru_tree) {
		HA_RWLOCK_WRLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		lru = lru64_get(key, ssl_ctx_lru_tree, bind_conf->ca_sign_ckch->cert, 0);
		if (!lru) {
			HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
			return -1;
		}
		if (lru->domain && lru->data)
			lru->free((SSL_CTX *)lru->data);
		lru64_commit(lru, ssl_ctx, bind_conf->ca_sign_ckch->cert, 0, (void (*)(void *))SSL_CTX_free);
		HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		return 0;
	}
	return -1;
}

/* Compute the key of the certificate. */
unsigned int
ssl_sock_generated_cert_key(const void *data, size_t len)
{
	return XXH32(data, len, ssl_ctx_lru_seed);
}

/* Generate a cert and immediately assign it to the SSL session so that the cert's
 * refcount is maintained regardless of the cert's presence in the LRU cache.
 */
int ssl_sock_generate_certificate(const char *servername, struct bind_conf *bind_conf, SSL *ssl)
{
	X509         *cacert  = bind_conf->ca_sign_ckch->cert;
	SSL_CTX      *ssl_ctx = NULL;
	struct lru64 *lru     = NULL;
	unsigned int  key;

	key = ssl_sock_generated_cert_key(servername, strlen(servername));
	if (ssl_ctx_lru_tree) {
		HA_RWLOCK_WRLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		lru = lru64_get(key, ssl_ctx_lru_tree, cacert, 0);
		if (lru && lru->domain)
			ssl_ctx = (SSL_CTX *)lru->data;
		if (!ssl_ctx && lru) {
			ssl_ctx = ssl_sock_do_create_cert(servername, bind_conf, ssl);
			lru64_commit(lru, ssl_ctx, cacert, 0, (void (*)(void *))SSL_CTX_free);
		}
		SSL_set_SSL_CTX(ssl, ssl_ctx);
		HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		return 1;
	}
	else {
		ssl_ctx = ssl_sock_do_create_cert(servername, bind_conf, ssl);
		SSL_set_SSL_CTX(ssl, ssl_ctx);
		/* No LRU cache, this CTX will be released as soon as the session dies */
		SSL_CTX_free(ssl_ctx);
		return 1;
	}
	return 0;
}
int ssl_sock_generate_certificate_from_conn(struct bind_conf *bind_conf, SSL *ssl)
{
	unsigned int key;
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);

	if (conn_get_dst(conn)) {
		key = ssl_sock_generated_cert_key(conn->dst, get_addr_len(conn->dst));
		if (ssl_sock_assign_generated_cert(key, bind_conf, ssl))
			return 1;
	}
	return 0;
}

/* Load CA cert file and private key used to generate certificates */
int
ssl_sock_gencert_load_ca(struct bind_conf *bind_conf)
{
	struct proxy *px = bind_conf->frontend;
	struct ckch_data *data = NULL;
	int ret = 0;
	char *err = NULL;

	if (!(bind_conf->options & BC_O_GENERATE_CERTS))
		return ret;

#if (defined SSL_CTRL_SET_TLSEXT_HOSTNAME && !defined SSL_NO_GENERATE_CERTIFICATES)
	if (global_ssl.ctx_cache) {
		ssl_ctx_lru_tree = lru64_new(global_ssl.ctx_cache);
	}
	ssl_ctx_lru_seed = (unsigned int)time(NULL);
	ssl_ctx_serial   = now_ms;
#endif

	if (!bind_conf->ca_sign_file) {
		ha_alert("Proxy '%s': cannot enable certificate generation, "
			 "no CA certificate File configured at [%s:%d].\n",
			 px->id, bind_conf->file, bind_conf->line);
		goto failed;
	}

	/* Allocate cert structure */
	data = calloc(1, sizeof(*data));
	if (!data) {
		ha_alert("Proxy '%s': Failed to read CA certificate file '%s' at [%s:%d]. Chain allocation failure\n",
			px->id, bind_conf->ca_sign_file, bind_conf->file, bind_conf->line);
		goto failed;
	}

	/* Try to parse file */
	if (ssl_sock_load_files_into_ckch(bind_conf->ca_sign_file, data, &err)) {
		ha_alert("Proxy '%s': Failed to read CA certificate file '%s' at [%s:%d]. Chain loading failed: %s\n",
			px->id, bind_conf->ca_sign_file, bind_conf->file, bind_conf->line, err);
		free(err);
		goto failed;
	}

	/* Fail if missing cert or pkey */
	if ((!data->cert) || (!data->key)) {
		ha_alert("Proxy '%s': Failed to read CA certificate file '%s' at [%s:%d]. Chain missing certificate or private key\n",
			px->id, bind_conf->ca_sign_file, bind_conf->file, bind_conf->line);
		goto failed;
	}

	/* Final assignment to bind */
	bind_conf->ca_sign_ckch = data;
	return ret;

 failed:
	if (data) {
		ssl_sock_free_cert_key_and_chain_contents(data);
		free(data);
	}

	bind_conf->options &= ~BC_O_GENERATE_CERTS;
	ret++;
	return ret;
}

/* Release CA cert and private key used to generate certificated */
void
ssl_sock_gencert_free_ca(struct bind_conf *bind_conf)
{
	if (bind_conf->ca_sign_ckch) {
		ssl_sock_free_cert_key_and_chain_contents(bind_conf->ca_sign_ckch);
		ha_free(&bind_conf->ca_sign_ckch);
	}
}

#endif /* !defined SSL_NO_GENERATE_CERTIFICATES */


static void __ssl_gencert_deinit(void)
{
#if (defined SSL_CTRL_SET_TLSEXT_HOSTNAME && !defined SSL_NO_GENERATE_CERTIFICATES)
	if (ssl_ctx_lru_tree) {
		lru64_destroy(ssl_ctx_lru_tree);
		HA_RWLOCK_DESTROY(&ssl_ctx_lru_rwlock);
	}
#endif
}
REGISTER_POST_DEINIT(__ssl_gencert_deinit);

