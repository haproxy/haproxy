/*
 * This file contains the sample fetches related to the SSL
 *
 * Copyright (C) 2012 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 * Copyright (C) 2020 HAProxy Technologies, William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <haproxy/acl.h>
#include <haproxy/api.h>
#include <haproxy/arg.h>
#include <haproxy/buf-t.h>
#include <haproxy/obj_type.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/sample.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/ssl_utils.h>
#include <haproxy/tools.h>


/***** Below are some sample fetching functions for ACL/patterns *****/

static int
smp_fetch_ssl_fc_has_early(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	SSL *ssl;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	smp->flags = 0;
	smp->data.type = SMP_T_BOOL;
#ifdef OPENSSL_IS_BORINGSSL
	{
		smp->data.u.sint = (SSL_in_early_data(ssl) &&
				    SSL_early_data_accepted(ssl));
	}
#else
	smp->data.u.sint = ((conn->flags & CO_FL_EARLY_DATA)  &&
	    (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_SSL_WAIT_HS))) ? 1 : 0;
#endif
	return 1;
}

/* boolean, returns true if client cert was present */
static int
smp_fetch_ssl_fc_has_crt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	ctx = conn->xprt_ctx;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->flags = SMP_F_VOL_SESS;
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = SSL_SOCK_ST_FL_VERIFY_DONE & ctx->xprt_st ? 1 : 0;

	return 1;
}

/* binary, returns a certificate in a binary chunk (der/raw).
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_der(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;

	X509 *crt = NULL;
	int ret = 0;
	struct buffer *smp_trash;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);

	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_crt2der(crt, smp_trash) <= 0)
		goto out;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_BIN;
	ret = 1;
out:
	/* SSL_get_peer_certificate, it increase X509 * ref count */
	if (cert_peer && crt)
		X509_free(crt);
	return ret;
}

/* binary, returns a chain certificate in a binary chunk (der/raw).
 * The 5th keyword char is used to support only peer cert
 */
static int
smp_fetch_ssl_x_chain_der(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;
	struct buffer *smp_trash;
	struct buffer *tmp_trash = NULL;
	struct connection *conn;
	STACK_OF(X509) *certs = NULL;
	X509 *crt = NULL;
	SSL *ssl;
	int ret = 0;
	int num_certs;
	int i;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);

	if (!conn)
		return 0;

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (!cert_peer)
		return 0;

	certs = SSL_get_peer_cert_chain(ssl);
	if (!certs)
		return 0;

	num_certs = sk_X509_num(certs);
	if (!num_certs)
		goto out;
	smp_trash = get_trash_chunk();
	tmp_trash = alloc_trash_chunk();
	if (!tmp_trash)
		goto out;
	for (i = 0; i < num_certs; i++) {
		crt = sk_X509_value(certs, i);
		if (ssl_sock_crt2der(crt, tmp_trash) <= 0)
			goto out;
		chunk_cat(smp_trash, tmp_trash);
	}

	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_BIN;
	ret = 1;
out:
	if (tmp_trash)
		free_trash_chunk(tmp_trash);
	return ret;
}

/* binary, returns serial of certificate in a binary chunk.
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_serial(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;
	X509 *crt = NULL;
	int ret = 0;
	struct buffer *smp_trash;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);

	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_get_serial(crt, smp_trash) <= 0)
		goto out;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_BIN;
	ret = 1;
out:
	/* SSL_get_peer_certificate, it increase X509 * ref count */
	if (cert_peer && crt)
		X509_free(crt);
	return ret;
}

/* binary, returns the client certificate's SHA-1 fingerprint (SHA-1 hash of DER-encoded certificate) in a binary chunk.
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_sha1(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;
	X509 *crt = NULL;
	const EVP_MD *digest;
	int ret = 0;
	unsigned int len = 0;
	struct buffer *smp_trash;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);
	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	digest = EVP_sha1();
	X509_digest(crt, digest, (unsigned char *) smp_trash->area, &len);
	smp_trash->data = len;
	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_BIN;
	ret = 1;
out:
	/* SSL_get_peer_certificate, it increase X509 * ref count */
	if (cert_peer && crt)
		X509_free(crt);
	return ret;
}

/* string, returns certificate's notafter date in ASN1_UTCTIME format.
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_notafter(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;
	X509 *crt = NULL;
	int ret = 0;
	struct buffer *smp_trash;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);
	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_get_time(X509_getm_notAfter(crt), smp_trash) <= 0)
		goto out;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_STR;
	ret = 1;
out:
	/* SSL_get_peer_certificate, it increase X509 * ref count */
	if (cert_peer && crt)
		X509_free(crt);
	return ret;
}

/* string, returns a string of a formatted full dn \C=..\O=..\OU=.. \CN=.. of certificate's issuer
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_i_dn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;
	X509 *crt = NULL;
	X509_NAME *name;
	int ret = 0;
	struct buffer *smp_trash;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);
	if (!crt)
		goto out;

	name = X509_get_issuer_name(crt);
	if (!name)
		goto out;

	smp_trash = get_trash_chunk();
	if (args[0].type == ARGT_STR && args[0].data.str.data > 0) {
		int pos = 1;

		if (args[1].type == ARGT_SINT)
			pos = args[1].data.sint;

		if (ssl_sock_get_dn_entry(name, &args[0].data.str, pos, smp_trash) <= 0)
			goto out;
	}
	else if (args[2].type == ARGT_STR && args[2].data.str.data > 0) {
		if (ssl_sock_get_dn_formatted(name, &args[2].data.str, smp_trash) <= 0)
			goto out;
	}
	else if (ssl_sock_get_dn_oneline(name, smp_trash) <= 0)
		goto out;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.type = SMP_T_STR;
	smp->data.u.str = *smp_trash;
	ret = 1;
out:
	/* SSL_get_peer_certificate, it increase X509 * ref count */
	if (cert_peer && crt)
		X509_free(crt);
	return ret;
}

/* string, returns notbefore date in ASN1_UTCTIME format.
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_notbefore(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;
	X509 *crt = NULL;
	int ret = 0;
	struct buffer *smp_trash;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);
	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_get_time(X509_getm_notBefore(crt), smp_trash) <= 0)
		goto out;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_STR;
	ret = 1;
out:
	/* SSL_get_peer_certificate, it increase X509 * ref count */
	if (cert_peer && crt)
		X509_free(crt);
	return ret;
}

/* string, returns a string of a formatted full dn \C=..\O=..\OU=.. \CN=.. of certificate's subject
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_s_dn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;
	X509 *crt = NULL;
	X509_NAME *name;
	int ret = 0;
	struct buffer *smp_trash;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);
	if (!crt)
		goto out;

	name = X509_get_subject_name(crt);
	if (!name)
		goto out;

	smp_trash = get_trash_chunk();
	if (args[0].type == ARGT_STR && args[0].data.str.data > 0) {
		int pos = 1;

		if (args[1].type == ARGT_SINT)
			pos = args[1].data.sint;

		if (ssl_sock_get_dn_entry(name, &args[0].data.str, pos, smp_trash) <= 0)
			goto out;
	}
	else if (args[2].type == ARGT_STR && args[2].data.str.data > 0) {
		if (ssl_sock_get_dn_formatted(name, &args[2].data.str, smp_trash) <= 0)
			goto out;
	}
	else if (ssl_sock_get_dn_oneline(name, smp_trash) <= 0)
		goto out;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.type = SMP_T_STR;
	smp->data.u.str = *smp_trash;
	ret = 1;
out:
	/* SSL_get_peer_certificate, it increase X509 * ref count */
	if (cert_peer && crt)
		X509_free(crt);
	return ret;
}

/* integer, returns true if current session use a client certificate */
static int
smp_fetch_ssl_c_used(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	X509 *crt;
	struct connection *conn;
	SSL *ssl;

	conn = objt_conn(smp->sess->origin);
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	/* SSL_get_peer_certificate returns a ptr on allocated X509 struct */
	crt = SSL_get_peer_certificate(ssl);
	if (crt) {
		X509_free(crt);
	}

	smp->flags = SMP_F_VOL_SESS;
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (crt != NULL);
	return 1;
}

/* integer, returns the certificate version
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_version(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;

	X509 *crt;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);
	if (!crt)
		return 0;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.sint = (unsigned int)(1 + X509_get_version(crt));
	/* SSL_get_peer_certificate increase X509 * ref count  */
	if (cert_peer)
		X509_free(crt);
	smp->data.type = SMP_T_SINT;

	return 1;
}

/* string, returns the certificate's signature algorithm.
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_sig_alg(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;
	X509 *crt;
	__OPENSSL_110_CONST__ ASN1_OBJECT *algorithm;
	int nid;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);
	if (!crt)
		return 0;

	X509_ALGOR_get0(&algorithm, NULL, NULL, X509_get0_tbs_sigalg(crt));
	nid = OBJ_obj2nid(algorithm);

	smp->data.u.str.area = (char *)OBJ_nid2sn(nid);
	if (!smp->data.u.str.area) {
		/* SSL_get_peer_certificate increase X509 * ref count  */
		if (cert_peer)
			X509_free(crt);
		return 0;
	}

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_VOL_SESS | SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);
	/* SSL_get_peer_certificate increase X509 * ref count  */
	if (cert_peer)
		X509_free(crt);

	return 1;
}

/* string, returns the certificate's key algorithm.
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_key_alg(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c' || kw[4] == 's') ? 1 : 0;
	int conn_server = (kw[4] == 's') ? 1 : 0;
	X509 *crt;
	ASN1_OBJECT *algorithm;
	int nid;
	struct connection *conn;
	SSL *ssl;

	if (conn_server)
		conn = cs_conn(objt_cs(smp->strm->si[1].end));
	else
		conn = objt_conn(smp->sess->origin);
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ssl);
	else
		crt = SSL_get_certificate(ssl);
	if (!crt)
		return 0;

	X509_PUBKEY_get0_param(&algorithm, NULL, NULL, NULL, X509_get_X509_PUBKEY(crt));
	nid = OBJ_obj2nid(algorithm);

	smp->data.u.str.area = (char *)OBJ_nid2sn(nid);
	if (!smp->data.u.str.area) {
		/* SSL_get_peer_certificate increase X509 * ref count  */
		if (cert_peer)
			X509_free(crt);
		return 0;
	}

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_VOL_SESS | SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);
	if (cert_peer)
		X509_free(crt);

	return 1;
}

/* boolean, returns true if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (conn && conn->xprt == &ssl_sock);
	return 1;
}

/* boolean, returns true if client present a SNI */
static int
smp_fetch_ssl_fc_has_sni(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	struct connection *conn = objt_conn(smp->sess->origin);
	SSL *ssl = ssl_sock_get_ssl_object(conn);

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = ssl && SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) != NULL;
	return 1;
#else
	return 0;
#endif
}

/* boolean, returns true if client session has been resumed.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_is_resumed(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL *ssl;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	ssl = ssl_sock_get_ssl_object(conn);

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = ssl && SSL_session_reused(ssl);
	return 1;
}

/* string, returns the used cipher if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_cipher(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL *ssl;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	smp->flags = 0;
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	smp->data.u.str.area = (char *)SSL_get_cipher_name(ssl);
	if (!smp->data.u.str.area)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_VOL_SESS | SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);

	return 1;
}

/* integer, returns the algoritm's keysize if front conn. transport layer
 * is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_alg_keysize(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL *ssl;
	int sint;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	smp->flags = 0;
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (!SSL_get_cipher_bits(ssl, &sint))
		return 0;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.sint = sint;
	smp->data.type = SMP_T_SINT;

	return 1;
}

/* integer, returns the used keysize if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_use_keysize(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL *ssl;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	smp->flags = 0;
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	smp->data.u.sint = (unsigned int)SSL_get_cipher_bits(ssl, NULL);
	if (!smp->data.u.sint)
		return 0;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.type = SMP_T_SINT;

	return 1;
}

#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
static int
smp_fetch_ssl_fc_npn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL *ssl;
	unsigned int len = 0;

	smp->flags = SMP_F_CONST;
	smp->data.type = SMP_T_STR;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.str.area = NULL;
	SSL_get0_next_proto_negotiated(ssl,
	                               (const unsigned char **)&smp->data.u.str.area,
	                               &len);

	if (!smp->data.u.str.area)
		return 0;

	smp->data.u.str.data = len;
	return 1;
}
#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int
smp_fetch_ssl_fc_alpn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL *ssl;
	unsigned int len = 0;

	smp->flags = SMP_F_VOL_SESS | SMP_F_CONST;
	smp->data.type = SMP_T_STR;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	smp->data.u.str.area = NULL;
	SSL_get0_alpn_selected(ssl,
	                       (const unsigned char **)&smp->data.u.str.area,
	                       &len);

	if (!smp->data.u.str.area)
		return 0;

	smp->data.u.str.data = len;
	return 1;
}
#endif

/* string, returns the used protocol if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_protocol(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL *ssl;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	smp->flags = 0;
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	smp->data.u.str.area = (char *)SSL_get_version(ssl);
	if (!smp->data.u.str.area)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_VOL_SESS | SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);

	return 1;
}

/* binary, returns the SSL stream id if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
static int
smp_fetch_ssl_fc_session_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL_SESSION *ssl_sess;
	SSL *ssl;
	unsigned int len = 0;

	smp->flags = SMP_F_VOL_SESS | SMP_F_CONST;
	smp->data.type = SMP_T_BIN;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	ssl_sess = SSL_get_session(ssl);
	if (!ssl_sess)
		return 0;

	smp->data.u.str.area = (char *)SSL_SESSION_get_id(ssl_sess, &len);
	if (!smp->data.u.str.area || !len)
		return 0;

	smp->data.u.str.data = len;
	return 1;
}
#endif


#ifdef HAVE_SSL_EXTRACT_RANDOM
static int
smp_fetch_ssl_fc_random(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct buffer *data;
	SSL *ssl;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	data = get_trash_chunk();
	if (kw[7] == 'c')
		data->data = SSL_get_client_random(ssl,
		                                   (unsigned char *) data->area,
		                                   data->size);
	else
		data->data = SSL_get_server_random(ssl,
		                                   (unsigned char *) data->area,
		                                   data->size);
	if (!data->data)
		return 0;

	smp->flags = SMP_F_VOL_TEST;
	smp->data.type = SMP_T_BIN;
	smp->data.u.str = *data;

	return 1;
}

static int
smp_fetch_ssl_fc_session_key(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL_SESSION *ssl_sess;
	struct buffer *data;
	SSL *ssl;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	ssl_sess = SSL_get_session(ssl);
	if (!ssl_sess)
		return 0;

	data = get_trash_chunk();
	data->data = SSL_SESSION_get_master_key(ssl_sess,
					       (unsigned char *) data->area,
					       data->size);
	if (!data->data)
		return 0;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.type = SMP_T_BIN;
	smp->data.u.str = *data;

	return 1;
}
#endif

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static int
smp_fetch_ssl_fc_sni(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL *ssl;

	smp->flags = SMP_F_VOL_SESS | SMP_F_CONST;
	smp->data.type = SMP_T_STR;

	conn = objt_conn(smp->sess->origin);
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	smp->data.u.str.area = (char *)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!smp->data.u.str.area)
		return 0;

	smp->data.u.str.data = strlen(smp->data.u.str.area);
	return 1;
}
#endif

static int
smp_fetch_ssl_fc_cl_bin(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_capture *capture;
	SSL *ssl;

	conn = objt_conn(smp->sess->origin);
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	capture = SSL_get_ex_data(ssl, ssl_capture_ptr_index);
	if (!capture)
		return 0;

	smp->flags = SMP_F_VOL_TEST | SMP_F_CONST;
	smp->data.type = SMP_T_BIN;
	smp->data.u.str.area = capture->ciphersuite;
	smp->data.u.str.data = capture->ciphersuite_len;
	return 1;
}

static int
smp_fetch_ssl_fc_cl_hex(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct buffer *data;

	if (!smp_fetch_ssl_fc_cl_bin(args, smp, kw, private))
		return 0;

	data = get_trash_chunk();
	dump_binary(data, smp->data.u.str.area, smp->data.u.str.data);
	smp->flags = SMP_F_VOL_SESS;
	smp->data.type = SMP_T_BIN;
	smp->data.u.str = *data;
	return 1;
}

static int
smp_fetch_ssl_fc_cl_xxh64(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_capture *capture;
	SSL *ssl;

	conn = objt_conn(smp->sess->origin);
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	capture = SSL_get_ex_data(ssl, ssl_capture_ptr_index);
	if (!capture)
		return 0;

	smp->flags = SMP_F_VOL_SESS;
	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = capture->xxh64;
	return 1;
}

/* Dump the SSL keylog, it only works with "tune.ssl.keylog 1" */
#ifdef HAVE_OPENSSL_KEYLOG
static int smp_fetch_ssl_x_keylog(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_keylog *keylog;
	SSL *ssl;
	char *src = NULL;
	const char *sfx;

	conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	       smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	if (!conn)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	keylog = SSL_get_ex_data(ssl, ssl_keylog_index);
	if (!keylog)
		return 0;

	sfx = kw + strlen("ssl_xx_");

	if (strcmp(sfx, "client_early_traffic_secret") == 0) {
		src = keylog->client_early_traffic_secret;
	} else if (strcmp(sfx, "client_handshake_traffic_secret") == 0) {
		src = keylog->client_handshake_traffic_secret;
	} else if (strcmp(sfx, "server_handshake_traffic_secret") == 0) {
		src = keylog->server_handshake_traffic_secret;
	} else if (strcmp(sfx, "client_traffic_secret_0") == 0) {
		src = keylog->client_traffic_secret_0;
	} else if (strcmp(sfx, "server_traffic_secret_0") == 0) {
		src = keylog->server_traffic_secret_0;
	} else if (strcmp(sfx, "exporter_secret") == 0) {
		src = keylog->exporter_secret;
	} else if (strcmp(sfx, "early_exporter_secret") == 0) {
		src = keylog->early_exporter_secret;
	}

	if (!src || !*src)
		return 0;

	smp->data.u.str.area = src;
	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_VOL_TEST | SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);
	return 1;
}
#endif

static int
smp_fetch_ssl_fc_cl_str(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
#if defined(OPENSSL_IS_BORINGSSL) || defined(SSL_CTRL_GET_RAW_CIPHERLIST)
	struct buffer *data;
	int i;

	if (!smp_fetch_ssl_fc_cl_bin(args, smp, kw, private))
		return 0;

	data = get_trash_chunk();
	for (i = 0; i + 1 < smp->data.u.str.data; i += 2) {
		const char *str;
		const SSL_CIPHER *cipher;
		const unsigned char *bin = (const unsigned char *) smp->data.u.str.area + i;
		uint16_t id = (bin[0] << 8) | bin[1];
#if defined(OPENSSL_IS_BORINGSSL)
		cipher = SSL_get_cipher_by_value(id);
#else
		struct connection *conn = __objt_conn(smp->sess->origin);
		SSL *ssl = ssl_sock_get_ssl_object(conn);
		cipher = SSL_CIPHER_find(ssl, bin);
#endif
		str = SSL_CIPHER_get_name(cipher);
		if (!str || strcmp(str, "(NONE)") == 0)
			chunk_appendf(data, "%sUNKNOWN(%04x)", i == 0 ? "" : ",", id);
		else
			chunk_appendf(data, "%s%s", i == 0 ? "" : ",", str);
	}
	smp->data.type = SMP_T_STR;
	smp->data.u.str = *data;
	return 1;
#else
	return smp_fetch_ssl_fc_cl_xxh64(args, smp, kw, private);
#endif
}

#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
static int
smp_fetch_ssl_fc_unique_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	int finished_len;
	struct buffer *finished_trash;
	SSL *ssl;

	if (obj_type(smp->sess->origin) == OBJ_TYPE_CHECK)
		conn = (kw[4] == 'b') ? cs_conn(__objt_check(smp->sess->origin)->cs) : NULL;
	else
		conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
			smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	smp->flags = 0;
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	finished_trash = get_trash_chunk();
	if (!SSL_session_reused(ssl))
		finished_len = SSL_get_peer_finished(ssl,
						     finished_trash->area,
						     finished_trash->size);
	else
		finished_len = SSL_get_finished(ssl,
						finished_trash->area,
						finished_trash->size);

	if (!finished_len)
		return 0;

	finished_trash->data = finished_len;
	smp->flags = SMP_F_VOL_SESS;
	smp->data.u.str = *finished_trash;
	smp->data.type = SMP_T_BIN;

	return 1;
}
#endif

/* integer, returns the first verify error in CA chain of client certificate chain. */
static int
smp_fetch_ssl_c_ca_err(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (unsigned long long int)SSL_SOCK_ST_TO_CA_ERROR(ctx->xprt_st);
	smp->flags = SMP_F_VOL_SESS;

	return 1;
}

/* integer, returns the depth of the first verify error in CA chain of client certificate chain. */
static int
smp_fetch_ssl_c_ca_err_depth(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}
	ctx = conn->xprt_ctx;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (long long int)SSL_SOCK_ST_TO_CAEDEPTH(ctx->xprt_st);
	smp->flags = SMP_F_VOL_SESS;

	return 1;
}

/* integer, returns the first verify error on client certificate */
static int
smp_fetch_ssl_c_err(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	ctx = conn->xprt_ctx;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (long long int)SSL_SOCK_ST_TO_CRTERROR(ctx->xprt_st);
	smp->flags = SMP_F_VOL_SESS;

	return 1;
}

/* integer, returns the verify result on client cert */
static int
smp_fetch_ssl_c_verify(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	SSL *ssl;

	conn = objt_conn(smp->sess->origin);
	ssl = ssl_sock_get_ssl_object(conn);
	if (!ssl)
		return 0;

	if (conn->flags & CO_FL_WAIT_XPRT) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (long long int)SSL_get_verify_result(ssl);
	smp->flags = SMP_F_VOL_SESS;

	return 1;
}

/* Argument validation functions */

/* This function is used to validate the arguments passed to any "x_dn" ssl
 * keywords. These keywords support specifying a third parameter that must be
 * either empty or the value "rfc2253". Returns 0 on error, non-zero if OK.
 */
int val_dnfmt(struct arg *arg, char **err_msg)
{
	if (arg && arg[2].type == ARGT_STR && arg[2].data.str.data > 0 && (strcmp(arg[2].data.str.area, "rfc2253") != 0)) {
		memprintf(err_msg, "only rfc2253 or a blank value are currently supported as the format argument.");
		return 0;
	}
	return 1;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "ssl_bc",                 smp_fetch_ssl_fc,             0,                   NULL,    SMP_T_BOOL, SMP_USE_L5SRV },
	{ "ssl_bc_alg_keysize",     smp_fetch_ssl_fc_alg_keysize, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5SRV },
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	{ "ssl_bc_alpn",            smp_fetch_ssl_fc_alpn,        0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
#endif
	{ "ssl_bc_cipher",          smp_fetch_ssl_fc_cipher,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	{ "ssl_bc_npn",             smp_fetch_ssl_fc_npn,         0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
#endif
	{ "ssl_bc_is_resumed",      smp_fetch_ssl_fc_is_resumed,  0,                   NULL,    SMP_T_BOOL, SMP_USE_L5SRV },
	{ "ssl_bc_protocol",        smp_fetch_ssl_fc_protocol,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
	{ "ssl_bc_unique_id",       smp_fetch_ssl_fc_unique_id,   0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
	{ "ssl_bc_use_keysize",     smp_fetch_ssl_fc_use_keysize, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5SRV },
#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
	{ "ssl_bc_session_id",      smp_fetch_ssl_fc_session_id,  0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
#endif
#ifdef HAVE_SSL_EXTRACT_RANDOM
	{ "ssl_bc_client_random",   smp_fetch_ssl_fc_random,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
	{ "ssl_bc_server_random",   smp_fetch_ssl_fc_random,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
	{ "ssl_bc_session_key",     smp_fetch_ssl_fc_session_key, 0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
#endif
	{ "ssl_c_ca_err",           smp_fetch_ssl_c_ca_err,       0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_c_ca_err_depth",     smp_fetch_ssl_c_ca_err_depth, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_c_der",              smp_fetch_ssl_x_der,          0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_chain_der",        smp_fetch_ssl_x_chain_der,    0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_err",              smp_fetch_ssl_c_err,          0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_c_i_dn",             smp_fetch_ssl_x_i_dn,         ARG3(0,STR,SINT,STR),val_dnfmt,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_key_alg",          smp_fetch_ssl_x_key_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_notafter",         smp_fetch_ssl_x_notafter,     0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_notbefore",        smp_fetch_ssl_x_notbefore,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_sig_alg",          smp_fetch_ssl_x_sig_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_s_dn",             smp_fetch_ssl_x_s_dn,         ARG3(0,STR,SINT,STR),val_dnfmt,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_serial",           smp_fetch_ssl_x_serial,       0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_sha1",             smp_fetch_ssl_x_sha1,         0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_used",             smp_fetch_ssl_c_used,         0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_c_verify",           smp_fetch_ssl_c_verify,       0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_c_version",          smp_fetch_ssl_x_version,      0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_f_der",              smp_fetch_ssl_x_der,          0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_f_i_dn",             smp_fetch_ssl_x_i_dn,         ARG3(0,STR,SINT,STR),val_dnfmt,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_key_alg",          smp_fetch_ssl_x_key_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_notafter",         smp_fetch_ssl_x_notafter,     0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_notbefore",        smp_fetch_ssl_x_notbefore,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_sig_alg",          smp_fetch_ssl_x_sig_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_s_dn",             smp_fetch_ssl_x_s_dn,         ARG3(0,STR,SINT,STR),val_dnfmt,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_serial",           smp_fetch_ssl_x_serial,       0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_f_sha1",             smp_fetch_ssl_x_sha1,         0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_f_version",          smp_fetch_ssl_x_version,      0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_fc",                 smp_fetch_ssl_fc,             0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_alg_keysize",     smp_fetch_ssl_fc_alg_keysize, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_fc_cipher",          smp_fetch_ssl_fc_cipher,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_has_crt",         smp_fetch_ssl_fc_has_crt,     0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_has_early",       smp_fetch_ssl_fc_has_early,   0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_has_sni",         smp_fetch_ssl_fc_has_sni,     0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_is_resumed",      smp_fetch_ssl_fc_is_resumed,  0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	{ "ssl_fc_npn",             smp_fetch_ssl_fc_npn,         0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	{ "ssl_fc_alpn",            smp_fetch_ssl_fc_alpn,        0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#endif
	{ "ssl_fc_protocol",        smp_fetch_ssl_fc_protocol,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
	{ "ssl_fc_unique_id",       smp_fetch_ssl_fc_unique_id,   0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
#endif
	{ "ssl_fc_use_keysize",     smp_fetch_ssl_fc_use_keysize, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
	{ "ssl_fc_session_id",      smp_fetch_ssl_fc_session_id,  0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
#endif
#ifdef HAVE_SSL_EXTRACT_RANDOM
	{ "ssl_fc_client_random",   smp_fetch_ssl_fc_random,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_fc_server_random",   smp_fetch_ssl_fc_random,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_fc_session_key",     smp_fetch_ssl_fc_session_key, 0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
#endif

#ifdef HAVE_OPENSSL_KEYLOG
	{ "ssl_fc_client_early_traffic_secret",     smp_fetch_ssl_x_keylog,       0,   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_client_handshake_traffic_secret", smp_fetch_ssl_x_keylog,       0,   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_server_handshake_traffic_secret", smp_fetch_ssl_x_keylog,       0,   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_client_traffic_secret_0",         smp_fetch_ssl_x_keylog,       0,   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_server_traffic_secret_0",         smp_fetch_ssl_x_keylog,       0,   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_exporter_secret",                 smp_fetch_ssl_x_keylog,       0,   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_early_exporter_secret",           smp_fetch_ssl_x_keylog,       0,   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#endif

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	{ "ssl_fc_sni",             smp_fetch_ssl_fc_sni,         0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#endif
	{ "ssl_fc_cipherlist_bin",  smp_fetch_ssl_fc_cl_bin,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_cipherlist_hex",  smp_fetch_ssl_fc_cl_hex,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_fc_cipherlist_str",  smp_fetch_ssl_fc_cl_str,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_cipherlist_xxh",  smp_fetch_ssl_fc_cl_xxh64,    0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },

/* SSL server certificate fetches */
	{ "ssl_s_der",              smp_fetch_ssl_x_der,          0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_s_chain_der",        smp_fetch_ssl_x_chain_der,    0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_s_key_alg",          smp_fetch_ssl_x_key_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_s_notafter",         smp_fetch_ssl_x_notafter,     0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_s_notbefore",        smp_fetch_ssl_x_notbefore,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_s_sig_alg",          smp_fetch_ssl_x_sig_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_s_s_dn",             smp_fetch_ssl_x_s_dn,         ARG3(0,STR,SINT,STR),val_dnfmt,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_s_i_dn",             smp_fetch_ssl_x_i_dn,         ARG3(0,STR,SINT,STR),val_dnfmt,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_s_serial",           smp_fetch_ssl_x_serial,       0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_s_sha1",             smp_fetch_ssl_x_sha1,         0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_s_version",          smp_fetch_ssl_x_version,      0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ "ssl_fc_sni_end",         "ssl_fc_sni", PAT_MATCH_END },
	{ "ssl_fc_sni_reg",         "ssl_fc_sni", PAT_MATCH_REG },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, acl_register_keywords, &acl_kws);
