
/*
 * SSL/TLS OCSP-related functions
 *
 * Copyright (C) 2022 HAProxy Technologies, Remi Tricot-Le Breton <rlebreton@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Acknowledgement:
 *   We'd like to specially thank the Stud project authors for a very clean
 *   and well documented code which helped us understand how the OpenSSL API
 *   ought to be used in non-blocking mode. This is one difficult part which
 *   is not easy to get from the OpenSSL doc, and reading the Stud code made
 *   it much more obvious than the examples in the OpenSSL package. Keep up
 *   the good works, guys !
 *
 *   Stud is an extremely efficient and scalable SSL/TLS proxy which combines
 *   particularly well with haproxy. For more info about this project, visit :
 *       https://github.com/bumptech/stud
 *
 */

/* Note: do NOT include openssl/xxx.h here, do it in openssl-compat.h */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include <import/ebpttree.h>
#include <import/ebsttree.h>
#include <import/lru.h>

#include <haproxy/api.h>
#include <haproxy/applet.h>
#include <haproxy/arg.h>
#include <haproxy/base64.h>
#include <haproxy/channel.h>
#include <haproxy/chunk.h>
#include <haproxy/cli.h>
#include <haproxy/connection.h>
#include <haproxy/dynbuf.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/freq_ctr.h>
#include <haproxy/frontend.h>
#include <haproxy/global.h>
#include <haproxy/http_rules.h>
#include <haproxy/log.h>
#include <haproxy/openssl-compat.h>
#include <haproxy/pattern-t.h>
#include <haproxy/proto_tcp.h>
#include <haproxy/proxy.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_tp.h>
#include <haproxy/server.h>
#include <haproxy/shctx.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_crtlist.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/ssl_utils.h>
#include <haproxy/stats.h>
#include <haproxy/stconn.h>
#include <haproxy/stream-t.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>
#include <haproxy/xxhash.h>
#include <haproxy/istbuf.h>
#include <haproxy/ssl_ocsp-t.h>
#include <haproxy/http_client.h>


/* ***** READ THIS before adding code here! *****
 *
 * Due to API incompatibilities between multiple OpenSSL versions and their
 * derivatives, it's often tempting to add macros to (re-)define certain
 * symbols. Please do not do this here, and do it in common/openssl-compat.h
 * exclusively so that the whole code consistently uses the same macros.
 *
 * Whenever possible if a macro is missing in certain versions, it's better
 * to conditionally define it in openssl-compat.h than using lots of ifdefs.
 */

#ifndef OPENSSL_NO_OCSP
int ocsp_ex_index = -1;

int ssl_sock_get_ocsp_arg_kt_index(int evp_keytype)
{
	switch (evp_keytype) {
	case EVP_PKEY_RSA:
		return 2;
	case EVP_PKEY_DSA:
		return 0;
	case EVP_PKEY_EC:
		return 1;
	}

	return -1;
}

/*
 * Callback used to set OCSP status extension content in server hello.
 */
int ssl_sock_ocsp_stapling_cbk(SSL *ssl, void *arg)
{
	struct certificate_ocsp *ocsp;
	struct ocsp_cbk_arg *ocsp_arg;
	char *ssl_buf;
	SSL_CTX *ctx;
	EVP_PKEY *ssl_pkey;
	int key_type;
	int index;

	ctx = SSL_get_SSL_CTX(ssl);
	if (!ctx)
		return SSL_TLSEXT_ERR_NOACK;

	ocsp_arg = SSL_CTX_get_ex_data(ctx, ocsp_ex_index);
	if (!ocsp_arg)
		return SSL_TLSEXT_ERR_NOACK;

	ssl_pkey = SSL_get_privatekey(ssl);
	if (!ssl_pkey)
		return SSL_TLSEXT_ERR_NOACK;

	key_type = EVP_PKEY_base_id(ssl_pkey);

	if (ocsp_arg->is_single && ocsp_arg->single_kt == key_type)
		ocsp = ocsp_arg->s_ocsp;
	else {
		/* For multiple certs per context, we have to find the correct OCSP response based on
		 * the certificate type
		 */
		index = ssl_sock_get_ocsp_arg_kt_index(key_type);

		if (index < 0)
			return SSL_TLSEXT_ERR_NOACK;

		ocsp = ocsp_arg->m_ocsp[index];

	}

	if (!ocsp ||
	    !ocsp->response.area ||
	    !ocsp->response.data ||
	    (ocsp->expire < now.tv_sec))
		return SSL_TLSEXT_ERR_NOACK;

	ssl_buf = OPENSSL_malloc(ocsp->response.data);
	if (!ssl_buf)
		return SSL_TLSEXT_ERR_NOACK;

	memcpy(ssl_buf, ocsp->response.area, ocsp->response.data);
	SSL_set_tlsext_status_ocsp_resp(ssl, (unsigned char*)ssl_buf, ocsp->response.data);

	return SSL_TLSEXT_ERR_OK;
}

#endif /* !defined(OPENSSL_NO_OCSP) */


#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)

struct eb_root cert_ocsp_tree = EB_ROOT_UNIQUE;

__decl_thread(HA_SPINLOCK_T ocsp_tree_lock);

struct eb_root ocsp_update_tree = EB_ROOT; /* updatable ocsp responses sorted by next_update in absolute time */
#define SSL_OCSP_UPDATE_DELAY_MAX 60*60 /* 1H */
#define SSL_OCSP_UPDATE_DELAY_MIN 5*60  /* 5 minutes */
#define SSL_OCSP_UPDATE_MARGIN 60   /* 1 minute */

/* This function starts to check if the OCSP response (in DER format) contained
 * in chunk 'ocsp_response' is valid (else exits on error).
 * If 'cid' is not NULL, it will be compared to the OCSP certificate ID
 * contained in the OCSP Response and exits on error if no match.
 * If it's a valid OCSP Response:
 *  If 'ocsp' is not NULL, the chunk is copied in the OCSP response's container
 * pointed by 'ocsp'.
 *  If 'ocsp' is NULL, the function looks up into the OCSP response's
 * containers tree (using as index the ASN1 form of the OCSP Certificate ID extracted
 * from the response) and exits on error if not found. Finally, If an OCSP response is
 * already present in the container, it will be overwritten.
 *
 * Note: OCSP response containing more than one OCSP Single response is not
 * considered valid.
 *
 * Returns 0 on success, 1 in error case.
 */
int ssl_sock_load_ocsp_response(struct buffer *ocsp_response,
                                struct certificate_ocsp *ocsp,
                                OCSP_CERTID *cid, char **err)
{
	OCSP_RESPONSE *resp;
	OCSP_BASICRESP *bs = NULL;
	OCSP_SINGLERESP *sr;
	OCSP_CERTID *id;
	unsigned char *p = (unsigned char *) ocsp_response->area;
	int rc , count_sr;
	ASN1_GENERALIZEDTIME *revtime, *thisupd, *nextupd = NULL;
	int reason;
	int ret = 1;
#ifdef HAVE_ASN1_TIME_TO_TM
	struct tm nextupd_tm = {0};
#endif

	resp = d2i_OCSP_RESPONSE(NULL, (const unsigned char **)&p,
				 ocsp_response->data);
	if (!resp) {
		memprintf(err, "Unable to parse OCSP response");
		goto out;
	}

	rc = OCSP_response_status(resp);
	if (rc != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		memprintf(err, "OCSP response status not successful");
		goto out;
	}

	bs = OCSP_response_get1_basic(resp);
	if (!bs) {
		memprintf(err, "Failed to get basic response from OCSP Response");
		goto out;
	}

	count_sr = OCSP_resp_count(bs);
	if (count_sr > 1) {
		memprintf(err, "OCSP response ignored because contains multiple single responses (%d)", count_sr);
		goto out;
	}

	sr = OCSP_resp_get0(bs, 0);
	if (!sr) {
		memprintf(err, "Failed to get OCSP single response");
		goto out;
	}

	id = (OCSP_CERTID*)OCSP_SINGLERESP_get0_id(sr);

	rc = OCSP_single_get0_status(sr, &reason, &revtime, &thisupd, &nextupd);
	if (rc != V_OCSP_CERTSTATUS_GOOD && rc != V_OCSP_CERTSTATUS_REVOKED) {
		memprintf(err, "OCSP single response: certificate status is unknown");
		goto out;
	}

	if (!nextupd) {
		memprintf(err, "OCSP single response: missing nextupdate");
		goto out;
	}

	rc = OCSP_check_validity(thisupd, nextupd, OCSP_MAX_RESPONSE_TIME_SKEW, -1);
	if (!rc) {
		memprintf(err, "OCSP single response: no longer valid.");
		goto out;
	}

	if (cid) {
		if (OCSP_id_cmp(id, cid)) {
			memprintf(err, "OCSP single response: Certificate ID does not match certificate and issuer");
			goto out;
		}
	}

	if (!ocsp) {
		unsigned char key[OCSP_MAX_CERTID_ASN1_LENGTH];
		unsigned char *p;

		rc = i2d_OCSP_CERTID(id, NULL);
		if (!rc) {
			memprintf(err, "OCSP single response: Unable to encode Certificate ID");
			goto out;
		}

		if (rc > OCSP_MAX_CERTID_ASN1_LENGTH) {
			memprintf(err, "OCSP single response: Certificate ID too long");
			goto out;
		}

		p = key;
		memset(key, 0, OCSP_MAX_CERTID_ASN1_LENGTH);
		i2d_OCSP_CERTID(id, &p);
		HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);
		ocsp = (struct certificate_ocsp *)ebmb_lookup(&cert_ocsp_tree, key, OCSP_MAX_CERTID_ASN1_LENGTH);
		if (!ocsp) {
			HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
			memprintf(err, "OCSP single response: Certificate ID does not match any certificate or issuer");
			goto out;
		}
		HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
	}

	/* According to comments on "chunk_dup", the
	   previous chunk buffer will be freed */
	if (!chunk_dup(&ocsp->response, ocsp_response)) {
		memprintf(err, "OCSP response: Memory allocation error");
		goto out;
	}

#ifdef HAVE_ASN1_TIME_TO_TM
	if (ASN1_TIME_to_tm(nextupd, &nextupd_tm) == 0) {
		memprintf(err, "OCSP single response: Invalid \"Next Update\" time");
		goto out;
	}
	ocsp->expire = my_timegm(&nextupd_tm) - OCSP_MAX_RESPONSE_TIME_SKEW;
#else
	ocsp->expire = asn1_generalizedtime_to_epoch(nextupd) - OCSP_MAX_RESPONSE_TIME_SKEW;
	if (ocsp->expire < 0) {
		memprintf(err, "OCSP single response: Invalid \"Next Update\" time");
		goto out;
	}
#endif

	ret = 0;
out:
	ERR_clear_error();

	if (bs)
		 OCSP_BASICRESP_free(bs);

	if (resp)
		OCSP_RESPONSE_free(resp);

	return ret;
}
/*
 * External function use to update the OCSP response in the OCSP response's
 * containers tree. The chunk 'ocsp_response' must contain the OCSP response
 * to update in DER format.
 *
 * Returns 0 on success, 1 in error case.
 */
int ssl_sock_update_ocsp_response(struct buffer *ocsp_response, char **err)
{
	return ssl_sock_load_ocsp_response(ocsp_response, NULL, NULL, err);
}



#if !defined OPENSSL_IS_BORINGSSL
/*
 * Decrease the refcount of the struct ocsp_response and frees it if it's not
 * used anymore. Also removes it from the tree if free'd.
 */
void ssl_sock_free_ocsp(struct certificate_ocsp *ocsp)
{
	if (!ocsp)
		return;

	HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);
	ocsp->refcount--;
	if (ocsp->refcount <= 0) {
		ebmb_delete(&ocsp->key);
		eb64_delete(&ocsp->next_update);
		X509_free(ocsp->issuer);
		ocsp->issuer = NULL;
		sk_X509_pop_free(ocsp->chain, X509_free);
		ocsp->chain = NULL;
		chunk_destroy(&ocsp->response);
		free_trash_chunk(ocsp->uri);
		ocsp->uri = NULL;

		free(ocsp);
	}
	HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
}


/*
 * This function dumps the details of an OCSP_CERTID. It is based on
 * ocsp_certid_print in OpenSSL.
 */
static inline int ocsp_certid_print(BIO *bp, OCSP_CERTID *certid, int indent)
{
	ASN1_OCTET_STRING *piNameHash = NULL;
	ASN1_OCTET_STRING *piKeyHash = NULL;
	ASN1_INTEGER *pSerial = NULL;

	if (OCSP_id_get0_info(&piNameHash, NULL, &piKeyHash, &pSerial, certid)) {

		BIO_printf(bp, "%*sCertificate ID:\n", indent, "");
		indent += 2;
		BIO_printf(bp, "%*sIssuer Name Hash: ", indent, "");
#ifndef USE_OPENSSL_WOLFSSL
		i2a_ASN1_STRING(bp, piNameHash, 0);
#else
        wolfSSL_ASN1_STRING_print(bp, piNameHash);
#endif
		BIO_printf(bp, "\n%*sIssuer Key Hash: ", indent, "");
#ifndef USE_OPENSSL_WOLFSSL
		i2a_ASN1_STRING(bp, piKeyHash, 0);
#else
		wolfSSL_ASN1_STRING_print(bp, piNameHash);
#endif
		BIO_printf(bp, "\n%*sSerial Number: ", indent, "");
		i2a_ASN1_INTEGER(bp, pSerial);
	}
	return 1;
}

/*
 * Dump the details about an OCSP response in DER format stored in
 * <ocsp_response> into buffer <out>.
 * Returns 0 in case of success.
 */
int ssl_ocsp_response_print(struct buffer *ocsp_response, struct buffer *out)
{
	BIO *bio = NULL;
	int write = -1;
	OCSP_RESPONSE *resp;
	const unsigned char *p;
	int retval = -1;

	if (!ocsp_response)
		return -1;

	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		return -1;

	p = (const unsigned char*)ocsp_response->area;

	resp = d2i_OCSP_RESPONSE(NULL, &p, ocsp_response->data);
	if (!resp) {
		chunk_appendf(out, "Unable to parse OCSP response");
		goto end;
	}

#ifndef USE_OPENSSL_WOLFSSL
   if (OCSP_RESPONSE_print(bio, resp, 0) != 0) {
#else
   if (wolfSSL_d2i_OCSP_RESPONSE_bio(bio, &resp) != 0) {
#endif
		struct buffer *trash = get_trash_chunk();
		struct ist ist_block = IST_NULL;
		struct ist ist_double_lf = IST_NULL;
		static struct ist double_lf = IST("\n\n");

		write = BIO_read(bio, trash->area, trash->size - 1);
		if (write <= 0)
			goto end;
		trash->data = write;

		/* Look for empty lines in the 'trash' buffer and add a space to
		 * the beginning to avoid having empty lines in the output
		 * (without changing the appearance of the information
		 * displayed).
		 */
		ist_block = ist2(b_orig(trash), b_data(trash));

		ist_double_lf = istist(ist_block, double_lf);

		while (istlen(ist_double_lf)) {
			/* istptr(ist_double_lf) points to the first \n of a
			 * \n\n pattern.
			 */
			uint empty_line_offset = istptr(ist_double_lf) + 1 - istptr(ist_block);

			/* Write up to the first '\n' of the "\n\n" pattern into
			 * the output buffer.
			 */
			b_putblk(out, istptr(ist_block), empty_line_offset);
			/* Add an extra space. */
			b_putchr(out, ' ');

			/* Keep looking for empty lines in the rest of the data. */
			ist_block = istadv(ist_block, empty_line_offset);

			ist_double_lf = istist(ist_block, double_lf);
		}

		retval = (b_istput(out, ist_block) <= 0);
	}

end:
	if (bio)
		BIO_free(bio);

	OCSP_RESPONSE_free(resp);

	return retval;
}

/*
 * Dump the details of the OCSP response of ID <ocsp_certid> into buffer <out>.
 * Returns 0 in case of success.
 */
int ssl_get_ocspresponse_detail(unsigned char *ocsp_certid, struct buffer *out)
{
	struct certificate_ocsp *ocsp;
	int ret = 0;

	HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);
	ocsp = (struct certificate_ocsp *)ebmb_lookup(&cert_ocsp_tree, ocsp_certid, OCSP_MAX_CERTID_ASN1_LENGTH);
	if (!ocsp) {
		HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
		return -1;
	}

	ret = ssl_ocsp_response_print(&ocsp->response, out);

	HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);

	return ret;
}


/* IO handler of details "show ssl ocsp-response <id>".
 * The current entry is taken from appctx->svcctx.
 */
static int cli_io_handler_show_ocspresponse_detail(struct appctx *appctx)
{
	struct buffer *trash = alloc_trash_chunk();
	struct certificate_ocsp *ocsp = appctx->svcctx;

	if (trash == NULL)
		return 1;

	if (ssl_ocsp_response_print(&ocsp->response, trash)) {
		free_trash_chunk(trash);
		return 1;
	}

	if (applet_putchk(appctx, trash) == -1)
		goto yield;

	appctx->svcctx = NULL;
	if (trash)
		free_trash_chunk(trash);
	return 1;

yield:
	if (trash)
		free_trash_chunk(trash);

	return 0;
}

void ssl_sock_ocsp_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	struct ocsp_cbk_arg *ocsp_arg;

	if (ptr) {
		ocsp_arg = ptr;

		if (ocsp_arg->is_single) {
			ssl_sock_free_ocsp(ocsp_arg->s_ocsp);
			ocsp_arg->s_ocsp = NULL;
		} else {
			int i;

			for (i = 0; i < SSL_SOCK_NUM_KEYTYPES; i++) {
				ssl_sock_free_ocsp(ocsp_arg->m_ocsp[i]);
				ocsp_arg->m_ocsp[i] = NULL;
			}
		}
		free(ocsp_arg);
	}
}

/*
 * Extract the first OCSP URI (if any) contained in <cert> and write it into
 * <out>.
 * Returns 0 in case of success, 1 otherwise.
 */
int ssl_ocsp_get_uri_from_cert(X509 *cert, struct buffer *out, char **err)
{
	STACK_OF(OPENSSL_STRING) *ocsp_uri_stk = NULL;
	int ret = 1;

	if (!cert || !out)
		goto end;

	ocsp_uri_stk = X509_get1_ocsp(cert);
	if (ocsp_uri_stk == NULL) {
		memprintf(err, "%sNo OCSP URL stack!\n", *err ? *err : "");
		goto end;
	}

	if (!chunk_strcpy(out, sk_OPENSSL_STRING_value(ocsp_uri_stk, 0))) {
		memprintf(err, "%sOCSP URI too long!\n", *err ? *err : "");
		goto end;
	}
	if (b_data(out) == 0) {
		memprintf(err, "%sNo OCSP URL!\n", *err ? *err : "");
		goto end;
	}

	ret = 0;

end:
	X509_email_free(ocsp_uri_stk);
	return ret;
}

/*
 * Create the url and request body that make a proper OCSP request for the
 * <certid>. The <req_url> parameter should already hold the OCSP URI that was
 * extracted from the corresponding certificate. Depending on the size of the
 * certid we will either append data to the <req_url> to create a proper URL
 * that will be sent with a GET command, or the <req_body> will be constructed
 * in case of a POST.
 * Returns 0 in case of success.
 */
int ssl_ocsp_create_request_details(const OCSP_CERTID *certid, struct buffer *req_url,
                                    struct buffer *req_body, char **err)
{
	int errcode = -1;
	OCSP_REQUEST *ocsp;
	struct buffer *bin_request = get_trash_chunk();
	unsigned char *outbuf = (unsigned char*)b_orig(bin_request);

	ocsp = OCSP_REQUEST_new();
	if (ocsp == NULL) {
		memprintf(err, "%sCan't create OCSP_REQUEST\n", *err ? *err : "");
		goto end;
	}

	if (OCSP_request_add0_id(ocsp, (OCSP_CERTID*)certid) == NULL) {
		memprintf(err, "%sOCSP_request_add0_id() error\n", *err ? *err : "");
		goto end;
	}

	bin_request->data = i2d_OCSP_REQUEST(ocsp, &outbuf);
	if (b_data(bin_request) <= 0) {
		memprintf(err, "%si2d_OCSP_REQUEST() error\n", *err ? *err : "");
		goto end;
	}

	/* HTTP based OCSP requests can use either the GET or the POST method to
	 * submit their requests. To enable HTTP caching, small requests (that
	 * after encoding are less than 255 bytes), MAY be submitted using GET.
	 * If HTTP caching is not important, or the request is greater than 255
	 * bytes, the request SHOULD be submitted using POST.
	 */
	if (b_data(bin_request) + b_data(req_url) < 0xff) {
		struct buffer *b64buf = get_trash_chunk();
		char *ret = NULL;
		int base64_ret = 0;

		chunk_strcat(req_url, "/");

		base64_ret = a2base64(b_orig(bin_request), b_data(bin_request),
		                      b_orig(b64buf), b_size(b64buf));

		if (base64_ret < 0) {
			memprintf(err, "%sa2base64() error\n", *err ? *err : "");
			goto end;
		}

		b64buf->data = base64_ret;

		ret = encode_chunk((char*)b_stop(req_url), b_orig(req_url) + b_size(req_url), '%',
		                   query_encode_map, b64buf);
		if (ret && *ret == '\0') {
			req_url->data = ret - b_orig(req_url);
			errcode = 0;
		}
	}
	else {
		chunk_cpy(req_body, bin_request);
		errcode = 0;
	}


end:
	OCSP_REQUEST_free(ocsp);

	return errcode;
}

/*
 * Parse an OCSP_RESPONSE contained in <respbuf> and check its validity in
 * regard to the contents of <ckch> or the <issuer> certificate.
 * Certificate_ocsp structure does not keep a reference to the corresponding
 * ckch_store so outside of a CLI context (see "send ssl ocsp-response"
 * command), we only have an easy access to the issuer's certificate whose
 * reference is held in the structure.
 * Return 0 in case of success, 1 otherwise.
 */
int ssl_ocsp_check_response(STACK_OF(X509) *chain, X509 *issuer,
                            struct buffer *respbuf, char **err)
{
	int ret = 1;
	int n;
	OCSP_RESPONSE *response = NULL;
	OCSP_BASICRESP *basic = NULL;
	X509_STORE *store = NULL;
	const unsigned char *start = (const unsigned char*)b_orig(respbuf);

	if (!chain && !issuer) {
		memprintf(err, "check_ocsp_response needs a certificate validation chain or an issuer certificate");
		goto end;
	}

	response = d2i_OCSP_RESPONSE(NULL, &start, b_data(respbuf));
	if (!response) {
		memprintf(err, "d2i_OCSP_RESPONSE() failed");
		goto end;
	}

	n = OCSP_response_status(response);

	if (n != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		memprintf(err, "OCSP response not successful (%d: %s)",
		        n, OCSP_response_status_str(n));
		goto end;
	}

	basic = OCSP_response_get1_basic(response);
	if (basic == NULL) {
		memprintf(err, "OCSP_response_get1_basic() failed");
		goto end;
	}

	/* Create a temporary store in which we add the certificate's chain
	 * certificates. We assume that all those certificates can be trusted
	 * because they were provided by the user.
	 * The only ssl item that needs to be verified here is the OCSP
	 * response.
	 */
	store = X509_STORE_new();
	if (!store) {
		memprintf(err, "X509_STORE_new() failed");
		goto end;
	}

	if (chain) {
		int i = 0;
		for (i = 0; i < sk_X509_num(chain); i++) {
			X509 *cert = sk_X509_value(chain, i);
			X509_STORE_add_cert(store, cert);
		}
	}

	if (issuer)
		X509_STORE_add_cert(store, issuer);

	if (OCSP_basic_verify(basic, chain, store, OCSP_TRUSTOTHER) != 1) {
		memprintf(err, "OCSP_basic_verify() failed");
		goto end;
	}

	ret = 0;

end:
	X509_STORE_free(store);
	OCSP_RESPONSE_free(response);
	OCSP_BASICRESP_free(basic);
	return ret;
}


/*
 * OCSP-UPDATE RELATED FUNCTIONS AND STRUCTURES
 */

struct task *ocsp_update_task __read_mostly = NULL;

static struct ssl_ocsp_task_ctx {
	struct certificate_ocsp *cur_ocsp;
	struct httpclient *hc;
	int flags;
} ssl_ocsp_task_ctx;

const struct http_hdr ocsp_request_hdrs[] = {
	{ IST("Content-Type"), IST("application/ocsp-request") },
	{ IST_NULL, IST_NULL }
};

static struct task *ssl_ocsp_update_responses(struct task *task, void *context, unsigned int state);

/*
 * Create the main OCSP update task that will iterate over the OCSP responses
 * stored in ocsp_update_tree and send an OCSP request via the http_client
 * applet to the corresponding OCSP responder. The task will then be in charge
 * of processing the response, verifying it and resinserting it in the actual
 * ocsp response tree if the response is valid.
 * Returns 0 in case of success.
 */
int ssl_create_ocsp_update_task(char **err)
{
	if (ocsp_update_task)
		return 0; /* Already created */

	ocsp_update_task = task_new_anywhere();
	if (!ocsp_update_task) {
		memprintf(err, "parsing : failed to allocate global ocsp update task.");
		return -1;
	}

	ocsp_update_task->process = ssl_ocsp_update_responses;
	ocsp_update_task->context = NULL;

	return 0;
}

static int ssl_ocsp_task_schedule()
{
	if (ocsp_update_task)
		task_schedule(ocsp_update_task, now_ms);

	return 0;
}
REGISTER_POST_CHECK(ssl_ocsp_task_schedule);

void ssl_sock_free_ocsp(struct certificate_ocsp *ocsp);

void ssl_destroy_ocsp_update_task(void)
{
	struct eb64_node *node, *next;
	if (!ocsp_update_task)
		return;

	HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);

	node = eb64_first(&ocsp_update_tree);
	while (node) {
		next = eb64_next(node);
		eb64_delete(node);
		node = next;
	}

	HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);

	task_destroy(ocsp_update_task);
	ocsp_update_task = NULL;
}

/*
 * Insert a certificate_ocsp structure into the ocsp_update_tree tree, in which
 * entries are sorted by absolute date of the next update. The next_update key
 * will be the smallest out of the actual expire value of the response and
 * now+1H. This arbitrary 1H value ensures that ocsp responses are updated
 * periodically even when they have a long expire time, while not overloading
 * the system too much (in theory). Likewise, a minimum 5 minutes interval is
 * defined in order to avoid updating too often responses that have a really
 * short expire time or even no 'Next Update' at all.
 */
int ssl_ocsp_update_insert(struct certificate_ocsp *ocsp)
{
	int update_margin = (ocsp->expire >= SSL_OCSP_UPDATE_MARGIN) ? SSL_OCSP_UPDATE_MARGIN : 0;

	ocsp->next_update.key = MIN(now.tv_sec + SSL_OCSP_UPDATE_DELAY_MAX,
	                            ocsp->expire - update_margin);

	/* An already existing valid OCSP response that expires within less than
	 * SSL_OCSP_UPDATE_DELAY_MIN or has no 'Next Update' field should not be
	 * updated more than once every 5 minutes in order to avoid continuous
	 * update of the same response. */
	if (b_data(&ocsp->response))
		ocsp->next_update.key = MAX(ocsp->next_update.key, SSL_OCSP_UPDATE_DELAY_MIN);

	HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);
	eb64_insert(&ocsp_update_tree, &ocsp->next_update);
	HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);

	return 0;
}

void ocsp_update_response_stline_cb(struct httpclient *hc)
{
	struct task *task = hc->caller;

	if (!task)
		return;

	ssl_ocsp_task_ctx.flags |= HC_F_RES_STLINE;
	task_wakeup(task, TASK_WOKEN_MSG);
}

void ocsp_update_response_headers_cb(struct httpclient *hc)
{
	struct task *task = hc->caller;

	if (!task)
		return;

	ssl_ocsp_task_ctx.flags |= HC_F_RES_HDR;
	task_wakeup(task, TASK_WOKEN_MSG);
}

void ocsp_update_response_body_cb(struct httpclient *hc)
{
	struct task *task = hc->caller;

	if (!task)
		return;

	ssl_ocsp_task_ctx.flags |= HC_F_RES_BODY;
	task_wakeup(task, TASK_WOKEN_MSG);
}

void ocsp_update_response_end_cb(struct httpclient *hc)
{
	struct task *task = hc->caller;

	if (!task)
		return;

	ssl_ocsp_task_ctx.flags |= HC_F_RES_END;
	task_wakeup(task, TASK_WOKEN_MSG);
}

/*
 * This is the main function of the ocsp auto update mechanism. It has two
 * distinct parts and the branching to one or the other is completely based on
 * the fact that the cur_ocsp pointer of the ssl_ocsp_task_ctx member is set.
 *
 * If the pointer is not set, we need to look at the first item of the update
 * tree and see if it needs to be updated. If it does not we simply wait until
 * the time is right and let the task asleep. If it does need to be updated, we
 * simply build and send the corresponding ocsp request thanks to the
 * http_client. The task is then sent to sleep with an expire time set to
 * infinity. The http_client will wake it back up once the response is received
 * (or a timeout occurs). Just note that during this whole process the
 * cetificate_ocsp object corresponding to the entry being updated is taken out
 * of the update tree and only stored in the ssl_ocsp_task_ctx context.
 *
 * Once the task is waken up by the http_client, it branches on the response
 * processing part of the function which basically checks that the response is
 * valid and inserts it into the ocsp_response tree. The task then goes back to
 * sleep until another entry needs to be updated.
 */
static struct task *ssl_ocsp_update_responses(struct task *task, void *context, unsigned int state)
{
	unsigned int next_wakeup;
	struct eb64_node *eb;
	struct certificate_ocsp *ocsp;
	struct httpclient *hc = NULL;
	struct buffer *req_url = NULL;
	struct buffer *req_body = NULL;
	OCSP_CERTID *certid = NULL;
	struct ssl_ocsp_task_ctx *ctx = &ssl_ocsp_task_ctx;

	/* This arbitrary 10s time should only be used when an error occurred
	 * during an ocsp response processing. */
	next_wakeup = 10000;

	if (ctx->cur_ocsp) {
		/* An update is in process */
		ocsp = ctx->cur_ocsp;
		hc = ctx->hc;
		if (ctx->flags & HC_F_RES_STLINE) {
			if (hc->res.status != 200) {
				goto http_error;
			}
			ctx->flags &= ~HC_F_RES_STLINE;
		}

		if (ctx->flags & HC_F_RES_HDR) {
			struct http_hdr *hdr;
			int found = 0;
			/* Look for "Content-Type" header which should have
			 * "application/ocsp-response" value. */
			for (hdr = hc->res.hdrs; isttest(hdr->v); hdr++) {
				if (isteqi(hdr->n, ist("Content-Type")) &&
				    isteqi(hdr->v, ist("application/ocsp-response"))) {
					found = 1;
					break;
				}
			}
			if (!found) {
				goto http_error;
			}
			ctx->flags &= ~HC_F_RES_HDR;
		}

		/* If the HC_F_RES_BODY is set, we still need for the
		 * HC_F_RES_END flag to be set as well in order to be sure that
		 * the body is complete. */

		/* we must close only if F_RES_END is the last flag */
		if (ctx->flags & HC_F_RES_END) {

			/* Process the body that must be complete since
			 * HC_F_RES_END is set. */
			if (ctx->flags & HC_F_RES_BODY) {
				if (ssl_ocsp_check_response(ocsp->chain, ocsp->issuer, &hc->res.buf, NULL))
					goto http_error;

				if (ssl_sock_update_ocsp_response(&hc->res.buf, NULL) != 0) {
					goto http_error;
				}

				ctx->flags &= ~HC_F_RES_BODY;
			}

			ctx->flags &= ~HC_F_RES_END;

			/* Reinsert the entry into the update list so that it can be updated later */
			ssl_ocsp_update_insert(ocsp);
			/* Release the reference kept on the updated ocsp response. */
			ssl_sock_free_ocsp(ctx->cur_ocsp);
			ctx->cur_ocsp = NULL;

			HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);
			/* Set next_wakeup to the new first entry of the tree */
			eb = eb64_first(&ocsp_update_tree);
			if (eb) {
				if (eb->key > now.tv_sec)
					next_wakeup = (eb->key - now.tv_sec)*1000;
				else
					next_wakeup = 0;
			}
			HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
			goto leave;
		}

		/* We did not receive the HC_F_RES_END flag yet, wait for it
		 * before trying to update a new ocsp response. */
		goto wait;
	} else {
		/* Look for next entry that needs to be updated. */
		const unsigned char *p = NULL;

		HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);

		eb = eb64_first(&ocsp_update_tree);
		if (!eb) {
			HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
			goto leave;
		}

		if (eb->key > now.tv_sec) {
			next_wakeup = (eb->key - now.tv_sec)*1000;
			HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
			goto leave;
		}

		ocsp = eb64_entry(eb, struct certificate_ocsp, next_update);

		/* Take the current entry out of the update tree, it will be
		 * reinserted after the response is processed. */
		eb64_delete(&ocsp->next_update);

		++ocsp->refcount;
		ctx->cur_ocsp = ocsp;

		HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);

		req_url = alloc_trash_chunk();
		if (!req_url) {
			goto leave;
		}
		req_body = alloc_trash_chunk();
		if (!req_body) {
			goto leave;
		}

		p = ocsp->key_data;

		d2i_OCSP_CERTID(&certid, &p, ocsp->key_length);
		if (!certid)
			goto leave;

		/* Copy OCSP URI stored in ocsp structure into req_url */
		chunk_cpy(req_url, ocsp->uri);

		/* Create ocsp request */
		if (ssl_ocsp_create_request_details(certid, req_url, req_body, NULL) != 0) {
			goto leave;
		}

		/* Depending on the processing that occurred in
		 * ssl_ocsp_create_request_details we could either have to send
		 * a GET or a POST request. */
		hc = httpclient_new(task, b_data(req_body) ? HTTP_METH_POST : HTTP_METH_GET, ist2(b_orig(req_url), b_data(req_url)));
		if (!hc) {
			goto leave;
		}

		if (httpclient_req_gen(hc, hc->req.url, hc->req.meth,
		                       b_data(req_body) ? ocsp_request_hdrs : NULL,
		                       b_data(req_body) ? ist2(b_orig(req_body), b_data(req_body)) : IST_NULL) != ERR_NONE) {
			goto leave;
		}

		hc->ops.res_stline = ocsp_update_response_stline_cb;
		hc->ops.res_headers = ocsp_update_response_headers_cb;
		hc->ops.res_payload = ocsp_update_response_body_cb;
		hc->ops.res_end = ocsp_update_response_end_cb;

		if (!httpclient_start(hc)) {
			goto leave;
		}

		ctx->flags = 0;
		ctx->hc = hc;

		/* We keep the lock, this indicates that an update is in process. */
		goto wait;
	}

leave:
	if (ctx->cur_ocsp) {
		/* Something went wrong, reinsert the entry in the tree. */
		ssl_ocsp_update_insert(ctx->cur_ocsp);
		/* Release the reference kept on the updated ocsp response. */
		ssl_sock_free_ocsp(ctx->cur_ocsp);
		ctx->cur_ocsp = NULL;
	}
	if (hc)
		httpclient_stop_and_destroy(hc);
	free_trash_chunk(req_url);
	free_trash_chunk(req_body);
	task->expire = tick_add(now_ms, next_wakeup);
	return task;

wait:
	free_trash_chunk(req_url);
	free_trash_chunk(req_body);
	task->expire = TICK_ETERNITY;
	return task;

http_error:
	/* Reinsert certificate into update list so that it can be updated later */
	if (ocsp)
		ssl_ocsp_update_insert(ocsp);

	if (hc)
		httpclient_stop_and_destroy(hc);
	/* Release the reference kept on the updated ocsp response. */
	ssl_sock_free_ocsp(ctx->cur_ocsp);
	ctx->cur_ocsp = NULL;
	ctx->hc = NULL;
	ctx->flags = 0;
	task->expire = tick_add(now_ms, next_wakeup);
	return task;
}




struct ocsp_cli_ctx {
	struct httpclient *hc;
	struct ckch_data *ckch_data;
	X509 *ocsp_issuer;
	uint flags;
	uint do_update;
};


void cli_ocsp_res_stline_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;
	struct ocsp_cli_ctx *ctx;

	if (!appctx)
		return;

	ctx = appctx->svcctx;
	ctx->flags |= HC_F_RES_STLINE;
	appctx_wakeup(appctx);
}

void cli_ocsp_res_headers_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;
	struct ocsp_cli_ctx *ctx;

	if (!appctx)
		return;

	ctx = appctx->svcctx;
	ctx->flags |= HC_F_RES_HDR;
	appctx_wakeup(appctx);
}

void cli_ocsp_res_body_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;
	struct ocsp_cli_ctx *ctx;

	if (!appctx)
		return;

	ctx = appctx->svcctx;
	ctx->flags |= HC_F_RES_BODY;
	appctx_wakeup(appctx);
}

void cli_ocsp_res_end_cb(struct httpclient *hc)
{
	struct appctx *appctx = hc->caller;
	struct ocsp_cli_ctx *ctx;

	if (!appctx)
		return;

	ctx = appctx->svcctx;
	ctx->flags |= HC_F_RES_END;
	appctx_wakeup(appctx);
}

static int cli_parse_update_ocsp_response(char **args, char *payload, struct appctx *appctx, void *private)
{
	int errcode = 0;
	char *err = NULL;
	struct ckch_store *ckch_store = NULL;
	X509 *cert = NULL;
	struct ocsp_cli_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct httpclient *hc = NULL;
	struct buffer *req_url = NULL;
	struct buffer *req_body = NULL;
	OCSP_CERTID *certid = NULL;

	if (!*args[3]) {
		memprintf(&err, "'update ssl ocsp-response' expects a filename\n");
		return cli_dynerr(appctx, err);
	}

	req_url = alloc_trash_chunk();
	if (!req_url) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	req_body = alloc_trash_chunk();
	if (!req_body) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock)) {
		memprintf(&err, "%sCan't update the certificate!\nOperations on certificates are currently locked!\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	ckch_store = ckchs_lookup(args[3]);

	if (!ckch_store) {
		memprintf(&err, "%sCkch_store not found!\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		goto end;
	}

	ctx->ckch_data = ckch_store->data;

	cert = ckch_store->data->cert;

	if (ssl_ocsp_get_uri_from_cert(cert, req_url, &err)) {
		errcode |= ERR_ALERT | ERR_FATAL;
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		goto end;
	}

	/* Look for the ocsp issuer in the ckch_data or in the certificate
	 * chain, the same way it is done in ssl_sock_load_ocsp. */
	ctx->ocsp_issuer = ctx->ckch_data->ocsp_issuer;

	/* take issuer from chain over ocsp_issuer, is what is done historicaly */
	if (ctx->ckch_data->chain) {
		int i = 0;
		/* check if one of the certificate of the chain is the issuer */
		for (i = 0; i < sk_X509_num(ctx->ckch_data->chain); i++) {
			X509 *ti = sk_X509_value(ctx->ckch_data->chain, i);
			if (X509_check_issued(ti, cert) == X509_V_OK) {
				ctx->ocsp_issuer = ti;
				break;
			}
		}
	}

	if (!ctx->ocsp_issuer) {
		memprintf(&err, "%sOCSP issuer not found\n", err ? err : "");
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		goto end;
	}

	X509_up_ref(ctx->ocsp_issuer);

	certid = OCSP_cert_to_id(NULL, cert, ctx->ocsp_issuer);
	if (certid == NULL) {
		memprintf(&err, "%sOCSP_cert_to_id() error\n", err ? err : "");
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		goto end;
	}

	/* From here on the lock is not needed anymore. */
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	/* Create ocsp request */
	if (ssl_ocsp_create_request_details(certid, req_url, req_body, &err) != 0) {
		memprintf(&err, "%sCreate ocsp request error\n", err ? err : "");
		goto end;
	}

	hc = httpclient_new(appctx, b_data(req_body) ? HTTP_METH_POST : HTTP_METH_GET, ist2(b_orig(req_url), b_data(req_url)));
	if (!hc) {
		memprintf(&err, "%sCan't allocate httpclient\n", err ? err : "");
		goto end;
	}

	if (httpclient_req_gen(hc, hc->req.url, hc->req.meth, b_data(req_body) ? ocsp_request_hdrs : NULL,
	                       ist2(b_orig(req_body), b_data(req_body))) != ERR_NONE) {
		memprintf(&err, "%shttpclient_req_gen() error\n", err ? err : "");
		goto end;
	}

	hc->ops.res_stline = cli_ocsp_res_stline_cb;
	hc->ops.res_headers = cli_ocsp_res_headers_cb;
	hc->ops.res_payload = cli_ocsp_res_body_cb;
	hc->ops.res_end = cli_ocsp_res_end_cb;

	ctx->hc = hc; /* store the httpclient ptr in the applet */
	ctx->flags = 0;

	if (!httpclient_start(hc)) {
		memprintf(&err, "%shttpclient_start() error\n", err ? err : "");
		goto end;
	}

	free_trash_chunk(req_url);

	return 0;

end:
	free_trash_chunk(req_url);

	if (errcode & ERR_CODE) {
		return cli_dynerr(appctx, memprintf(&err, "%sCan't send ocsp request for %s!\n", err ? err : "", args[3]));
	}
	return cli_dynmsg(appctx, LOG_NOTICE, err);
}

static int cli_io_handler_update_ocsp_response(struct appctx *appctx)
{
	struct ocsp_cli_ctx *ctx = appctx->svcctx;
	struct httpclient *hc = ctx->hc;

	if (ctx->flags & HC_F_RES_STLINE) {
		if (hc->res.status != 200) {
			chunk_printf(&trash, "OCSP response error (status %d)\n", hc->res.status);
			if (applet_putchk(appctx, &trash) == -1)
				goto more;
			goto end;
		}
		ctx->flags &= ~HC_F_RES_STLINE;
	}

	if (ctx->flags & HC_F_RES_HDR) {
		struct http_hdr *hdr;
		int found = 0;
		/* Look for "Content-Type" header which should have
		 * "application/ocsp-response" value. */
		for (hdr = hc->res.hdrs; isttest(hdr->v); hdr++) {
			if (isteqi(hdr->n, ist("Content-Type")) &&
			    isteqi(hdr->v, ist("application/ocsp-response"))) {
				found = 1;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "Missing 'Content-Type: application/ocsp-response' header\n");
			goto end;
		}
		ctx->flags &= ~HC_F_RES_HDR;
	}

	if (ctx->flags & HC_F_RES_BODY) {
		/* Wait until the full body is received and HC_F_RES_END flag is
		 * set. */
	}

	/* we must close only if F_END is the last flag */
	if (ctx->flags & HC_F_RES_END) {
		char *err = NULL;

		if (ssl_ocsp_check_response(ctx->ckch_data->chain, ctx->ocsp_issuer, &hc->res.buf, &err)) {
			chunk_printf(&trash, "%s", err);
			if (applet_putchk(appctx, &trash) == -1)
				goto more;
			goto end;
		}

		if (ssl_sock_update_ocsp_response(&hc->res.buf, &err) != 0) {
			chunk_printf(&trash, "%s", err);
			if (applet_putchk(appctx, &trash) == -1)
				goto more;
			goto end;
		}

		chunk_reset(&trash);

		if (ssl_ocsp_response_print(&hc->res.buf, &trash))
			goto end;

		if (applet_putchk(appctx, &trash) == -1)
			goto more;
		ctx->flags &= ~HC_F_RES_BODY;
		ctx->flags &= ~HC_F_RES_END;
		goto end;
	}

more:
	if (!ctx->flags)
		applet_have_no_more_data(appctx);
	return 0;
end:
	return 1;
}

static void cli_release_update_ocsp_response(struct appctx *appctx)
{
	struct ocsp_cli_ctx *ctx = appctx->svcctx;
	struct httpclient *hc = ctx->hc;

	if (ctx)
		X509_free(ctx->ocsp_issuer);

	/* Everything possible was printed on the CLI, we can destroy the client */
	httpclient_stop_and_destroy(hc);

	return;
}


#endif  /* !defined OPENSSL_IS_BORINGSSL */


#endif /* (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) */


static int cli_parse_set_ocspresponse(char **args, char *payload, struct appctx *appctx, void *private)
{
#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
	char *err = NULL;
	int i, j, ret;

	if (!payload)
		payload = args[3];

	/* Expect one parameter: the new response in base64 encoding */
	if (!*payload)
		return cli_err(appctx, "'set ssl ocsp-response' expects response in base64 encoding.\n");

	/* remove \r and \n from the payload */
	for (i = 0, j = 0; payload[i]; i++) {
		if (payload[i] == '\r' || payload[i] == '\n')
			continue;
		payload[j++] = payload[i];
	}
	payload[j] = 0;

	ret = base64dec(payload, j, trash.area, trash.size);
	if (ret < 0)
		return cli_err(appctx, "'set ssl ocsp-response' received invalid base64 encoded response.\n");

	trash.data = ret;
	if (ssl_sock_update_ocsp_response(&trash, &err)) {
		if (err)
			return cli_dynerr(appctx, memprintf(&err, "%s.\n", err));
		else
			return cli_err(appctx, "Failed to update OCSP response.\n");
	}

	return cli_msg(appctx, LOG_INFO, "OCSP Response updated!\n");
#else
	return cli_err(appctx, "HAProxy was compiled against a version of OpenSSL that doesn't support OCSP stapling.\n");
#endif

}

/* parsing function for 'show ssl ocsp-response [id]'. If an entry is forced,
 * it's set into appctx->svcctx.
 */
static int cli_parse_show_ocspresponse(char **args, char *payload, struct appctx *appctx, void *private)
{
#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) && !defined OPENSSL_IS_BORINGSSL)
	if (*args[3]) {
		struct certificate_ocsp *ocsp = NULL;
		char key[OCSP_MAX_CERTID_ASN1_LENGTH] = {};
		int key_length = OCSP_MAX_CERTID_ASN1_LENGTH;
		char *key_ptr = key;

		if (strlen(args[3]) > OCSP_MAX_CERTID_ASN1_LENGTH*2) {
			return cli_err(appctx, "'show ssl ocsp-response' received a too big key.\n");
		}

		if (!parse_binary(args[3], &key_ptr, &key_length, NULL)) {
			return cli_err(appctx, "'show ssl ocsp-response' received an invalid key.\n");
		}

		HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);
		ocsp = (struct certificate_ocsp *)ebmb_lookup(&cert_ocsp_tree, key, OCSP_MAX_CERTID_ASN1_LENGTH);

		if (!ocsp) {
			HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
			return cli_err(appctx, "Certificate ID does not match any certificate.\n");
		}
		++ocsp->refcount;
		HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);

		appctx->svcctx = ocsp;
		appctx->io_handler = cli_io_handler_show_ocspresponse_detail;
	}

	return 0;

#else
	return cli_err(appctx, "HAProxy was compiled against a version of OpenSSL that doesn't support OCSP stapling.\n");
#endif
}

/*
 * IO handler of "show ssl ocsp-response". The command taking a specific ID
 * is managed in cli_io_handler_show_ocspresponse_detail.
 * The current entry is taken from appctx->svcctx.
 */
static int cli_io_handler_show_ocspresponse(struct appctx *appctx)
{
#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) && !defined OPENSSL_IS_BORINGSSL)
	struct buffer *trash = alloc_trash_chunk();
	struct buffer *tmp = NULL;
	struct ebmb_node *node;
	struct certificate_ocsp *ocsp = NULL;
	BIO *bio = NULL;
	int write = -1;

	if (trash == NULL)
		return 1;

	HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);

	tmp = alloc_trash_chunk();
	if (!tmp)
		goto end;

	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		goto end;

	if (!appctx->svcctx) {
		chunk_appendf(trash, "# Certificate IDs\n");
		node = ebmb_first(&cert_ocsp_tree);
	} else {
		node = &((struct certificate_ocsp *)appctx->svcctx)->key;
	}

	while (node) {
		OCSP_CERTID *certid = NULL;
		const unsigned char *p = NULL;
		int i;

		ocsp = ebmb_entry(node, struct certificate_ocsp, key);

		/* Dump the key in hexadecimal */
		chunk_appendf(trash, "Certificate ID key : ");
		for (i = 0; i < ocsp->key_length; ++i) {
			chunk_appendf(trash, "%02x", ocsp->key_data[i]);
		}
		chunk_appendf(trash, "\n");

		p = ocsp->key_data;

		/* Decode the certificate ID (serialized into the key). */
		d2i_OCSP_CERTID(&certid, &p, ocsp->key_length);
		if (!certid)
			goto end;

		/* Dump the CERTID info */
		ocsp_certid_print(bio, certid, 1);
		OCSP_CERTID_free(certid);
		write = BIO_read(bio, tmp->area, tmp->size-1);
		/* strip trailing LFs */
		while (write > 0 && tmp->area[write-1] == '\n')
			write--;
		tmp->area[write] = '\0';

		chunk_appendf(trash, "%s\n", tmp->area);

		node = ebmb_next(node);
		if (applet_putchk(appctx, trash) == -1)
			goto yield;
	}

end:
	HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
	appctx->svcctx = NULL;
	free_trash_chunk(trash);
	free_trash_chunk(tmp);
	BIO_free(bio);
	return 1;

yield:
	free_trash_chunk(trash);
	free_trash_chunk(tmp);
	BIO_free(bio);

	++ocsp->refcount;
	appctx->svcctx = ocsp;
	HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
	return 0;
#else
	return cli_err(appctx, "HAProxy was compiled against a version of OpenSSL that doesn't support OCSP stapling.\n");
#endif
}


static struct cli_kw_list cli_kws = {{ },{
	{ { "set", "ssl", "ocsp-response", NULL }, "set ssl ocsp-response <resp|payload>    : update a certificate's OCSP Response from a base64-encode DER",      cli_parse_set_ocspresponse, NULL },

	{ { "show", "ssl", "ocsp-response", NULL },"show ssl ocsp-response [id]             : display the IDs of the OCSP responses used in memory, or the details of a single OCSP response", cli_parse_show_ocspresponse, cli_io_handler_show_ocspresponse, NULL },
#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) && !defined OPENSSL_IS_BORINGSSL)
	{ { "update", "ssl", "ocsp-response", NULL }, "update ssl ocsp-response <certfile>  : send ocsp request and update stored ocsp response",                  cli_parse_update_ocsp_response, cli_io_handler_update_ocsp_response, cli_release_update_ocsp_response },
#endif
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
