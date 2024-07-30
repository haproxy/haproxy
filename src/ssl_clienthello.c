/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Note: do NOT include openssl/xxx.h here, do it in openssl-compat.h */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <import/ebpttree.h>
#include <import/ebsttree.h>

#include <haproxy/openssl-compat.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_openssl_compat.h>
#include <haproxy/quic_tp.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_gencert.h>
#include <haproxy/ssl_sock.h>

static void ssl_sock_switchctx_set(SSL *ssl, SSL_CTX *ctx)
{
	SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ctx), ssl_sock_bind_verifycbk);
	SSL_set_client_CA_list(ssl, SSL_dup_CA_list(SSL_CTX_get_client_CA_list(ctx)));
	SSL_set_SSL_CTX(ssl, ctx);
}

/*
 * Return the right sni_ctx for a <bind_conf> and a chosen <servername> (must be in lowercase)
 * RSA <have_rsa_sig> and ECDSA <have_ecdsa_sig> capabilities of the client can also be used.
 *
 * This function does a lookup in the bind_conf sni tree so the caller should lock its tree.
 */
struct sni_ctx *ssl_sock_chose_sni_ctx(struct bind_conf *s, const char *servername,
                                                             int have_rsa_sig, int have_ecdsa_sig)
{
	struct ebmb_node *node, *n, *node_ecdsa = NULL, *node_rsa = NULL, *node_anonymous = NULL;
	const char *wildp = NULL;
	int i;

	/* look for the first dot for wildcard search */
	for (i = 0; servername[i] != '\0'; i++) {
		if (servername[i] == '.') {
			wildp = &servername[i];
			break;
		}
	}
	/* if the servername is empty look for the default in the wildcard list */
	if (!*servername)
		wildp = servername;

	/* Look for an ECDSA, RSA and DSA certificate, first in the single
	 * name and if not found in the wildcard  */
	for (i = 0; i < 2; i++) {
		if (i == 0) 	/* lookup in full qualified names */
			node = ebst_lookup(&s->sni_ctx, trash.area);
		else if (i == 1 && wildp)  /* lookup in wildcards names */
			node = ebst_lookup(&s->sni_w_ctx, wildp);
		else
			break;

		for (n = node; n; n = ebmb_next_dup(n)) {

			/* lookup a not neg filter */
			if (!container_of(n, struct sni_ctx, name)->neg) {
				struct sni_ctx *sni, *sni_tmp;
				int skip = 0;

				if (i == 1 && wildp) { /* wildcard */
					/* If this is a wildcard, look for an exclusion on the same crt-list line */
					sni = container_of(n, struct sni_ctx, name);
					list_for_each_entry(sni_tmp, &sni->ckch_inst->sni_ctx, by_ckch_inst) {
						if (sni_tmp->neg && (strcmp((const char *)sni_tmp->name.key, trash.area) == 0)) {
							skip = 1;
							break;
						}
					}
					if (skip)
						continue;
				}

				switch(container_of(n, struct sni_ctx, name)->kinfo.sig) {
				case TLSEXT_signature_ecdsa:
					if (!node_ecdsa)
						node_ecdsa = n;
					break;
				case TLSEXT_signature_rsa:
					if (!node_rsa)
						node_rsa = n;
					break;
				default: /* TLSEXT_signature_anonymous|dsa */
					if (!node_anonymous)
						node_anonymous = n;
					break;
				}
			}
		}
	}
	/* Once the certificates are found, select them depending on what is
	 * supported in the client and by key_signature priority order: EDSA >
	 * RSA > DSA */
	if (have_ecdsa_sig && node_ecdsa)
		node = node_ecdsa;
	else if (have_rsa_sig && node_rsa)
		node = node_rsa;
	else if (node_anonymous)
		node = node_anonymous;
	else if (node_ecdsa)
		node = node_ecdsa;      /* no ecdsa signature case (< TLSv1.2) */
	else
		node = node_rsa;        /* no rsa signature case (far far away) */

	if (node)
		return container_of(node, struct sni_ctx, name);

	return NULL;
}

#ifdef HAVE_SSL_CLIENT_HELLO_CB

int ssl_sock_switchctx_err_cbk(SSL *ssl, int *al, void *priv)
{
	struct bind_conf *s = priv;
	(void)al; /* shut gcc stupid warning */

	if (SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) || (s->options & BC_O_GENERATE_CERTS))
		return SSL_TLSEXT_ERR_OK;
	return SSL_TLSEXT_ERR_NOACK;
}

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
int ssl_sock_switchctx_cbk(const struct ssl_early_callback_ctx *ctx)
{
	SSL *ssl = ctx->ssl;
#else
int ssl_sock_switchctx_cbk(SSL *ssl, int *al, void *arg)
{
#endif
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
#ifdef USE_QUIC
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
#endif /* USE_QUIC */
	struct bind_conf *s = NULL;
	const uint8_t *extension_data;
	size_t extension_len;
	int has_rsa_sig = 0, has_ecdsa_sig = 0;
	struct sni_ctx *sni_ctx;
	const char *servername;
	size_t servername_len = 0;
	int default_lookup = 0; /* did we lookup for a default yet? */
	int allow_early = 0;
	int i;

	if (conn)
		s = __objt_listener(conn->target)->bind_conf;
#ifdef USE_QUIC
	else if (qc)
		s = qc->li->bind_conf;
#endif /* USE_QUIC */

	if (!s) {
		/* must never happen */
		ABORT_NOW();
		return 0;
	}

#ifdef USE_QUIC
	if (qc) {
		/* Look for the QUIC transport parameters. */
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
		if (!SSL_early_callback_ctx_extension_get(ctx, qc->tps_tls_ext,
		                                          &extension_data, &extension_len))
#else
		if (!SSL_client_hello_get0_ext(ssl, qc->tps_tls_ext,
		                               &extension_data, &extension_len))
#endif
		{
			/* This is not redundant. It we only return 0 without setting
			 * <*al>, this has as side effect to generate another TLS alert
			 * which would be set after calling quic_set_tls_alert().
			 */
#if !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_IS_AWSLC)
			*al = SSL_AD_MISSING_EXTENSION;
#endif
			quic_set_tls_alert(qc, SSL_AD_MISSING_EXTENSION);
			return 0;
		}

		if (!quic_transport_params_store(qc, 0, extension_data,
		                                 extension_data + extension_len))
			goto abort;

		qc->flags |= QUIC_FL_CONN_TX_TP_RECEIVED;
	}
#endif /* USE_QUIC */

	if (s->ssl_conf.early_data)
		allow_early = 1;
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
	if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_server_name,
						 &extension_data, &extension_len)) {
#else
	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &extension_data, &extension_len)) {
#endif
		/*
		 * The server_name extension was given too much extensibility when it
		 * was written, so parsing the normal case is a bit complex.
		 */
		size_t len;
		if (extension_len <= 2)
			goto abort;
		/* Extract the length of the supplied list of names. */
		len = (*extension_data++) << 8;
		len |= *extension_data++;
		if (len + 2 != extension_len)
			goto abort;
		/*
		 * The list in practice only has a single element, so we only consider
		 * the first one.
		 */
		if (len == 0 || *extension_data++ != TLSEXT_NAMETYPE_host_name)
			goto abort;
		extension_len = len - 1;
		/* Now we can finally pull out the byte array with the actual hostname. */
		if (extension_len <= 2)
			goto abort;
		len = (*extension_data++) << 8;
		len |= *extension_data++;
		if (len == 0 || len + 2 > extension_len || len > TLSEXT_MAXLEN_host_name
		    || memchr(extension_data, 0, len) != NULL)
			goto abort;
		servername = (char *)extension_data;
		servername_len = len;
	} else {
#if (!defined SSL_NO_GENERATE_CERTIFICATES)
		if (s->options & BC_O_GENERATE_CERTS && ssl_sock_generate_certificate_from_conn(s, ssl)) {
			goto allow_early;
		}
#endif

		/* no servername field is not compatible with strict-sni */
		if (s->strict_sni)
			goto abort;

		/* without servername extension, look for the defaults which is
		 * defined by an empty servername string */
		servername = "";
		servername_len = 0;
		default_lookup = 1;
	}

	/* extract/check clientHello information */
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
	if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_signature_algorithms, &extension_data, &extension_len)) {
#else
	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_signature_algorithms, &extension_data, &extension_len)) {
#endif
		uint8_t sign;
		size_t len;
		if (extension_len < 2)
			goto abort;
		len = (*extension_data++) << 8;
		len |= *extension_data++;
		if (len + 2 != extension_len)
			goto abort;
		if (len % 2 != 0)
			goto abort;
		for (; len > 0; len -= 2) {
			extension_data++; /* hash */
			sign = *extension_data++;
			switch (sign) {
			case TLSEXT_signature_rsa:
				has_rsa_sig = 1;
				break;
			case TLSEXT_signature_ecdsa:
				has_ecdsa_sig = 1;
				break;
			default:
				continue;
			}
			if (has_ecdsa_sig && has_rsa_sig)
				break;
		}
	} else {
		/* without TLSEXT_TYPE_signature_algorithms extension (< TLSv1.2) */
		has_rsa_sig = 1;
	}
	if (has_ecdsa_sig) {  /* in very rare case: has ecdsa sign but not a ECDSA cipher */
		const SSL_CIPHER *cipher;
		STACK_OF(SSL_CIPHER) *ha_ciphers; /* haproxy side ciphers */
		uint32_t cipher_id;
		size_t len;
		const uint8_t *cipher_suites;

		ha_ciphers = SSL_get_ciphers(ssl);
		has_ecdsa_sig = 0;

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
		len = ctx->cipher_suites_len;
		cipher_suites = ctx->cipher_suites;
#else
		len = SSL_client_hello_get0_ciphers(ssl, &cipher_suites);
#endif
		if (len % 2 != 0)
			goto abort;
		for (; len != 0; len -= 2, cipher_suites += 2) {
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
			uint16_t cipher_suite = (cipher_suites[0] << 8) | cipher_suites[1];
			cipher = SSL_get_cipher_by_value(cipher_suite);
#else
			cipher = SSL_CIPHER_find(ssl, cipher_suites);
#endif
			if (!cipher)
				continue;

			/* check if this cipher is available in haproxy configuration */
#if defined(OPENSSL_IS_AWSLC)
                        /* because AWS-LC does not provide the TLSv1.3 ciphersuites (which are NID_auth_any) in ha_ciphers,
                         * does not check if it's available when it's an NID_auth_any
                         */
                        if (sk_SSL_CIPHER_find(ha_ciphers, cipher) == -1 && SSL_CIPHER_get_auth_nid(cipher) != NID_auth_any)
				continue;
#else

			if (sk_SSL_CIPHER_find(ha_ciphers, cipher) == -1)
				continue;
#endif

			cipher_id = SSL_CIPHER_get_id(cipher);
			/* skip the SCSV "fake" signaling ciphersuites because they are NID_auth_any (RFC 7507) */
			if (cipher_id == SSL3_CK_SCSV || cipher_id == SSL3_CK_FALLBACK_SCSV)
				continue;

			if (SSL_CIPHER_get_auth_nid(cipher) == NID_auth_ecdsa
			    || SSL_CIPHER_get_auth_nid(cipher) == NID_auth_any) {
				has_ecdsa_sig = 1;
				break;
			}
		}
	}

sni_lookup:
	/* we need to transform this a NULL-ended string in lowecase */
	for (i = 0; i < trash.size && i < servername_len; i++)
		trash.area[i] = tolower((unsigned char)servername[i]);
	trash.area[i] = 0;

	HA_RWLOCK_RDLOCK(SNI_LOCK, &s->sni_lock);
	sni_ctx = ssl_sock_chose_sni_ctx(s, trash.area, has_rsa_sig, has_ecdsa_sig);
	if (sni_ctx) {
		/* switch ctx */
		struct ssl_bind_conf *conf = sni_ctx->conf;
		ssl_sock_switchctx_set(ssl, sni_ctx->ctx);
		if (conf) {
			methodVersions[conf->ssl_methods.min].ssl_set_version(ssl, SET_MIN);
			methodVersions[conf->ssl_methods.max].ssl_set_version(ssl, SET_MAX);
			if (conf->early_data)
				allow_early = 1;
		}
		HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
		goto allow_early;
	}

	HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
#if (!defined SSL_NO_GENERATE_CERTIFICATES)
	if (s->options & BC_O_GENERATE_CERTS && ssl_sock_generate_certificate(trash.area, s, ssl)) {
		/* switch ctx done in ssl_sock_generate_certificate */
		goto allow_early;
	}
#endif

	if (!s->strict_sni && !default_lookup) {
		/* we didn't find a SNI, and we didn't look for a default
		 * look again to find a matching default cert */
		servername = "";
		servername_len = 0;
		default_lookup = 1;

		goto sni_lookup;
	}

	/* We are about to raise an handshake error so the servername extension
	 * callback will never be called and the SNI will never be stored in the
	 * SSL context. In order for the ssl_fc_sni sample fetch to still work
	 * in such a case, we store the SNI ourselves as an ex_data information
	 * in the SSL context.
	 */
	{
		char *client_sni = pool_alloc(ssl_sock_client_sni_pool);
		if (client_sni) {
			strncpy(client_sni, servername, TLSEXT_MAXLEN_host_name);
			client_sni[TLSEXT_MAXLEN_host_name] = '\0';
			SSL_set_ex_data(ssl, ssl_client_sni_index, client_sni);
		}
	}

	/* other cases fallback on abort, if strict-sni is set but no node was found */

 abort:
	/* abort handshake (was SSL_TLSEXT_ERR_ALERT_FATAL) */
	if (conn)
		conn->err_code = CO_ER_SSL_HANDSHAKE;
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
	return ssl_select_cert_error;
#else
	*al = SSL_AD_UNRECOGNIZED_NAME;
	return 0;
#endif

allow_early:
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
	if (allow_early)
		SSL_set_early_data_enabled(ssl, 1);
#else
	if (!allow_early)
		SSL_set_max_early_data(ssl, 0);
#endif
	return 1;
}

#else /* ! HAVE_SSL_CLIENT_HELLO_CB  */

/* Sets the SSL ctx of <ssl> to match the advertised server name. Returns a
 * warning when no match is found, which implies the default (first) cert
 * will keep being used.
 */
int ssl_sock_switchctx_cbk(SSL *ssl, int *al, void *priv)
{
	const char *servername;
	const char *wildp = NULL;
	struct ebmb_node *node, *n;
	struct bind_conf *s = priv;
	int default_lookup = 0; /* did we lookup for a default yet? */
#ifdef USE_QUIC
	const uint8_t *extension_data;
	size_t extension_len;
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
#endif /* USE_QUIC */
	int i;
	(void)al; /* shut gcc stupid warning */

#ifdef USE_QUIC
	if (qc) {

		/* Look for the QUIC transport parameters. */
		SSL_get_peer_quic_transport_params(ssl, &extension_data, &extension_len);
		if (extension_len == 0) {
			/* This is not redundant. It we only return 0 without setting
			 * <*al>, this has as side effect to generate another TLS alert
			 * which would be set after calling quic_set_tls_alert().
			 */
			*al = SSL_AD_MISSING_EXTENSION;
			quic_set_tls_alert(qc, SSL_AD_MISSING_EXTENSION);
			return SSL_TLSEXT_ERR_NOACK;
		}

		if (!quic_transport_params_store(qc, 0, extension_data,
		                                 extension_data + extension_len))
			return SSL_TLSEXT_ERR_NOACK;

		qc->flags |= QUIC_FL_CONN_TX_TP_RECEIVED;
	}
#endif /* USE_QUIC */

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername) {
#if (!defined SSL_NO_GENERATE_CERTIFICATES)
		if (s->options & BC_O_GENERATE_CERTS && ssl_sock_generate_certificate_from_conn(s, ssl))
			return SSL_TLSEXT_ERR_OK;
#endif
		if (s->strict_sni)
			return SSL_TLSEXT_ERR_ALERT_FATAL;

		/* without servername extension, look for the defaults which is
		 * defined by an empty servername string */
		servername = "";
		default_lookup = 1;
	}

sni_lookup:

	for (i = 0; i < trash.size; i++) {
		if (!servername[i])
			break;
		trash.area[i] = tolower((unsigned char)servername[i]);
		if (!wildp && (trash.area[i] == '.'))
			wildp = &trash.area[i];
	}
	trash.area[i] = 0;
	if(!*trash.area) /* handle the default which in wildcard tree */
		wildp = trash.area;

	HA_RWLOCK_RDLOCK(SNI_LOCK, &s->sni_lock);
	node = NULL;
	/* lookup in full qualified names */
	for (n = ebst_lookup(&s->sni_ctx, trash.area); n; n = ebmb_next_dup(n)) {
		/* lookup a not neg filter */
		if (!container_of(n, struct sni_ctx, name)->neg) {
			node = n;
			break;
		}
	}
	if (!node && wildp) {
		/* lookup in wildcards names */
		for (n = ebst_lookup(&s->sni_w_ctx, wildp); n; n = ebmb_next_dup(n)) {
			/* lookup a not neg filter */
			if (!container_of(n, struct sni_ctx, name)->neg) {
				node = n;
				break;
			}
		}
	}
	if (!node) {
#if (!defined SSL_NO_GENERATE_CERTIFICATES)
		if (s->options & BC_O_GENERATE_CERTS && ssl_sock_generate_certificate(servername, s, ssl)) {
			/* switch ctx done in ssl_sock_generate_certificate */
			HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
			return SSL_TLSEXT_ERR_OK;
		}
#endif
		HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);

		if (!s->strict_sni && !default_lookup) {
			/* we didn't find a SNI, and we didn't look for a default
			 * look again to find a matching default cert */
			servername = "";
			default_lookup = 1;

			goto sni_lookup;
		}
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	/* switch ctx */
	ssl_sock_switchctx_set(ssl, container_of(node, struct sni_ctx, name)->ctx);
	HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
	return SSL_TLSEXT_ERR_OK;
}
#endif /* (!) OPENSSL_IS_BORINGSSL */

#if defined(USE_OPENSSL_WOLFSSL)
/* This implement the equivalent of the clientHello Callback but using the cert_cb.
 * WolfSSL is able to extract the sigalgs and ciphers of the client byt using the API
 * provided in https://github.com/wolfSSL/wolfssl/pull/6963
 *
 * Not activated for now since the PR is not merged.
 */
int ssl_sock_switchctx_wolfSSL_cbk(WOLFSSL* ssl, void* arg)
{
	struct bind_conf *s = arg;
	int has_rsa_sig = 0, has_ecdsa_sig = 0;
	const char *servername;
	int default_lookup = 0;
	struct sni_ctx *sni_ctx;
	int i;

	if (!s) {
		/* must never happen */
		ABORT_NOW();
		return 0;
	}

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername) {
		if (s->strict_sni)
			goto abort;

		/* without servername extension, look for the defaults which is
		 * defined by an empty servername string */
		servername = "";
		default_lookup = 1;
	}

	/* extract sigalgs and ciphers */
	{
		const byte* suites = NULL;
		word16 suiteSz = 0;
		const byte* hashSigAlgo = NULL;
		word16 hashSigAlgoSz = 0;
		word16 idx = 0;

		wolfSSL_get_client_suites_sigalgs(ssl, &suites, &suiteSz, &hashSigAlgo, &hashSigAlgoSz);
		if (suites == NULL || suiteSz == 0 || hashSigAlgo == NULL || hashSigAlgoSz == 0)
			return 0;

		if (SSL_version(ssl) != TLS1_3_VERSION) {

			/* with TLS <= 1.2, we must use the auth which is provided by the cipher, but we don't need to
			 * consider the auth provided by the signature algorithms */

			for (idx = 0; idx < suiteSz; idx += 2) {
				WOLFSSL_CIPHERSUITE_INFO info;
				info = wolfSSL_get_ciphersuite_info(suites[idx], suites[idx+1]);
				if (info.rsaAuth)
					has_rsa_sig = 1;
				else if (info.eccAuth)
					has_ecdsa_sig = 1;
			}
		} else {
			/* with TLS >= 1.3, we must use the auth which is provided by the signature algorithms because
			 * the ciphers does not provide the auth */

			for (idx = 0; idx < hashSigAlgoSz; idx += 2) {
				int hashAlgo;
				int sigAlgo;

				wolfSSL_get_sigalg_info(hashSigAlgo[idx+0], hashSigAlgo[idx+1], &hashAlgo, &sigAlgo);

				if (sigAlgo == RSAk || sigAlgo == RSAPSSk)
					has_rsa_sig = 1;
				else if (sigAlgo == ECDSAk)
					has_ecdsa_sig = 1;

			}
		}
	}

sni_lookup:

	/* we need to transform this into a NULL-ended string in lowecase */
	for (i = 0; i < trash.size && servername[i] != '\0'; i++)
		trash.area[i] = tolower((unsigned char)servername[i]);
	trash.area[i] = 0;
	servername = trash.area;

	HA_RWLOCK_RDLOCK(SNI_LOCK, &s->sni_lock);
	sni_ctx = ssl_sock_chose_sni_ctx(s, servername, has_rsa_sig, has_ecdsa_sig);
	if (sni_ctx) {
		/* switch ctx */
		struct ssl_bind_conf *conf = sni_ctx->conf;
		ssl_sock_switchctx_set(ssl, sni_ctx->ctx);
		if (conf) {
			methodVersions[conf->ssl_methods.min].ssl_set_version(ssl, SET_MIN);
			methodVersions[conf->ssl_methods.max].ssl_set_version(ssl, SET_MAX);
		}
		HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
		goto allow_early;
	}

	HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
	if (!s->strict_sni && !default_lookup) {
		/* we didn't find a SNI, and we didn't look for a default
		 * look again to find a matching default cert */
		servername = "";
		default_lookup = 1;

		goto sni_lookup;
	}

	/* We are about to raise an handshake error so the servername extension
	 * callback will never be called and the SNI will never be stored in the
	 * SSL context. In order for the ssl_fc_sni sample fetch to still work
	 * in such a case, we store the SNI ourselves as an ex_data information
	 * in the SSL context.
	 */
	{
		char *client_sni = pool_alloc(ssl_sock_client_sni_pool);
		if (client_sni) {
			strncpy(client_sni, servername, TLSEXT_MAXLEN_host_name);
			client_sni[TLSEXT_MAXLEN_host_name] = '\0';
			SSL_set_ex_data(ssl, ssl_client_sni_index, client_sni);
		}
	}

	/* other cases fallback on abort, if strict-sni is set but no node was found */

 abort:
	/* abort handshake (was SSL_TLSEXT_ERR_ALERT_FATAL) */
	return 0;

allow_early:
	return 1;
}
#endif

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
