/*
 * SSL/TLS transport layer over SOCK_STREAM sockets
 *
 * Copyright (C) 2012 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
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

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/tcp.h>

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

#include <import/lru.h>
#include <import/xxhash.h>

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/errors.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/cfgparse.h>
#include <common/base64.h>

#include <ebsttree.h>

#include <types/global.h>
#include <types/ssl_sock.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/frontend.h>
#include <proto/listener.h>
#include <proto/pattern.h>
#include <proto/proto_tcp.h>
#include <proto/server.h>
#include <proto/log.h>
#include <proto/proxy.h>
#include <proto/shctx.h>
#include <proto/ssl_sock.h>
#include <proto/stream.h>
#include <proto/task.h>

/* Warning, these are bits, not integers! */
#define SSL_SOCK_ST_FL_VERIFY_DONE  0x00000001
#define SSL_SOCK_ST_FL_16K_WBFSIZE  0x00000002
#define SSL_SOCK_SEND_UNLIMITED     0x00000004
#define SSL_SOCK_RECV_HEARTBEAT     0x00000008

/* bits 0xFFFF0000 are reserved to store verify errors */

/* Verify errors macros */
#define SSL_SOCK_CA_ERROR_TO_ST(e) (((e > 63) ? 63 : e) << (16))
#define SSL_SOCK_CAEDEPTH_TO_ST(d) (((d > 15) ? 15 : d) << (6+16))
#define SSL_SOCK_CRTERROR_TO_ST(e) (((e > 63) ? 63 : e) << (4+6+16))

#define SSL_SOCK_ST_TO_CA_ERROR(s) ((s >> (16)) & 63)
#define SSL_SOCK_ST_TO_CAEDEPTH(s) ((s >> (6+16)) & 15)
#define SSL_SOCK_ST_TO_CRTERROR(s) ((s >> (4+6+16)) & 63)

/* Supported hash function for TLS tickets */
#ifdef OPENSSL_NO_SHA256
#define HASH_FUNCT EVP_sha1
#else
#define HASH_FUNCT EVP_sha256
#endif /* OPENSSL_NO_SHA256 */

/* server and bind verify method, it uses a global value as default */
enum {
	SSL_SOCK_VERIFY_DEFAULT  = 0,
	SSL_SOCK_VERIFY_REQUIRED = 1,
	SSL_SOCK_VERIFY_OPTIONAL = 2,
	SSL_SOCK_VERIFY_NONE     = 3,
};

int sslconns = 0;
int totalsslconns = 0;

#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
struct list tlskeys_reference = LIST_HEAD_INIT(tlskeys_reference);
#endif

#ifndef OPENSSL_NO_DH
static int ssl_dh_ptr_index = -1;
static DH *global_dh = NULL;
static DH *local_dh_1024 = NULL;
static DH *local_dh_2048 = NULL;
static DH *local_dh_4096 = NULL;
#endif /* OPENSSL_NO_DH */

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
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
#endif // SSL_CTRL_SET_TLSEXT_HOSTNAME

#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
struct certificate_ocsp {
	struct ebmb_node key;
	unsigned char key_data[OCSP_MAX_CERTID_ASN1_LENGTH];
	struct chunk response;
	long expire;
};

/*
 *  This function returns the number of seconds  elapsed
 *  since the Epoch, 1970-01-01 00:00:00 +0000 (UTC) and the
 *  date presented un ASN1_GENERALIZEDTIME.
 *
 *  In parsing error case, it returns -1.
 */
static long asn1_generalizedtime_to_epoch(ASN1_GENERALIZEDTIME *d)
{
	long epoch;
	char *p, *end;
	const unsigned short month_offset[12] = {
		0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
	};
	int year, month;

	if (!d || (d->type != V_ASN1_GENERALIZEDTIME)) return -1;

	p = (char *)d->data;
	end = p + d->length;

	if (end - p < 4) return -1;
	year = 1000 * (p[0] - '0') + 100 * (p[1] - '0') + 10 * (p[2] - '0') + p[3] - '0';
	p += 4;
	if (end - p < 2) return -1;
	month = 10 * (p[0] - '0') + p[1] - '0';
	if (month < 1 || month > 12) return -1;
	/* Compute the number of seconds since 1 jan 1970 and the beginning of current month
	   We consider leap years and the current month (<marsh or not) */
	epoch = (  ((year - 1970) * 365)
		 + ((year - (month < 3)) / 4 - (year - (month < 3)) / 100 + (year - (month < 3)) / 400)
		 - ((1970 - 1) / 4 - (1970 - 1) / 100 + (1970 - 1) / 400)
		 + month_offset[month-1]
		) * 24 * 60 * 60;
	p += 2;
	if (end - p < 2) return -1;
	/* Add the number of seconds of completed days of current month */
	epoch += (10 * (p[0] - '0') + p[1] - '0' - 1) * 24 * 60 * 60;
	p += 2;
	if (end - p < 2) return -1;
	/* Add the completed hours of the current day */
	epoch += (10 * (p[0] - '0') + p[1] - '0') * 60 * 60;
	p += 2;
	if (end - p < 2) return -1;
	/* Add the completed minutes of the current hour */
	epoch += (10 * (p[0] - '0') + p[1] - '0') * 60;
	p += 2;
	if (p == end) return -1;
	/* Test if there is available seconds */
	if (p[0] < '0' || p[0] > '9')
		goto nosec;
	if (end - p < 2) return -1;
	/* Add the seconds of the current minute */
	epoch += 10 * (p[0] - '0') + p[1] - '0';
	p += 2;
	if (p == end) return -1;
	/* Ignore seconds float part if present */
	if (p[0] == '.') {
		do {
			if (++p == end) return -1;
		} while (p[0] >= '0' && p[0] <= '9');
	}

nosec:
	if (p[0] == 'Z') {
		if (end - p != 1) return -1;
		return epoch;
	}
	else if (p[0] == '+') {
		if (end - p != 5) return -1;
		/* Apply timezone offset */
		return epoch - ((10 * (p[1] - '0') + p[2] - '0') * 60 + (10 * (p[3] - '0') + p[4] - '0')) * 60;
	}
	else if (p[0] == '-') {
		if (end - p != 5) return -1;
		/* Apply timezone offset */
		return epoch + ((10 * (p[1] - '0') + p[2] - '0') * 60 + (10 * (p[3] - '0') + p[4] - '0')) * 60;
	}

	return -1;
}

static struct eb_root cert_ocsp_tree = EB_ROOT_UNIQUE;

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
static int ssl_sock_load_ocsp_response(struct chunk *ocsp_response, struct certificate_ocsp *ocsp, OCSP_CERTID *cid, char **err)
{
	OCSP_RESPONSE *resp;
	OCSP_BASICRESP *bs = NULL;
	OCSP_SINGLERESP *sr;
	unsigned char *p = (unsigned char *)ocsp_response->str;
	int rc , count_sr;
	ASN1_GENERALIZEDTIME *revtime, *thisupd, *nextupd = NULL;
	int reason;
	int ret = 1;

	resp = d2i_OCSP_RESPONSE(NULL, (const unsigned char **)&p, ocsp_response->len);
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

	rc = OCSP_single_get0_status(sr, &reason, &revtime, &thisupd, &nextupd);
	if (rc != V_OCSP_CERTSTATUS_GOOD) {
		memprintf(err, "OCSP single response: certificate status not good");
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
		if (OCSP_id_cmp(sr->certId, cid)) {
			memprintf(err, "OCSP single response: Certificate ID does not match certificate and issuer");
			goto out;
		}
	}

	if (!ocsp) {
		unsigned char key[OCSP_MAX_CERTID_ASN1_LENGTH];
		unsigned char *p;

		rc = i2d_OCSP_CERTID(sr->certId, NULL);
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
		i2d_OCSP_CERTID(sr->certId, &p);
		ocsp = (struct certificate_ocsp *)ebmb_lookup(&cert_ocsp_tree, key, OCSP_MAX_CERTID_ASN1_LENGTH);
		if (!ocsp) {
			memprintf(err, "OCSP single response: Certificate ID does not match any certificate or issuer");
			goto out;
		}
	}

	/* According to comments on "chunk_dup", the
	   previous chunk buffer will be freed */
	if (!chunk_dup(&ocsp->response, ocsp_response)) {
		memprintf(err, "OCSP response: Memory allocation error");
		goto out;
	}

	ocsp->expire = asn1_generalizedtime_to_epoch(nextupd) - OCSP_MAX_RESPONSE_TIME_SKEW;

	ret = 0;
out:
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
int ssl_sock_update_ocsp_response(struct chunk *ocsp_response, char **err)
{
	return ssl_sock_load_ocsp_response(ocsp_response, NULL, NULL, err);
}

/*
 * This function load the OCSP Resonse in DER format contained in file at
 * path 'ocsp_path' and call 'ssl_sock_load_ocsp_response'
 *
 * Returns 0 on success, 1 in error case.
 */
static int ssl_sock_load_ocsp_response_from_file(const char *ocsp_path, struct certificate_ocsp *ocsp, OCSP_CERTID *cid, char **err)
{
	int fd = -1;
	int r = 0;
	int ret = 1;

	fd = open(ocsp_path, O_RDONLY);
	if (fd == -1) {
		memprintf(err, "Error opening OCSP response file");
		goto end;
	}

	trash.len = 0;
	while (trash.len < trash.size) {
		r = read(fd, trash.str + trash.len, trash.size - trash.len);
		if (r < 0) {
			if (errno == EINTR)
				continue;

			memprintf(err, "Error reading OCSP response from file");
			goto end;
		}
		else if (r == 0) {
			break;
		}
		trash.len += r;
	}

	close(fd);
	fd = -1;

	ret = ssl_sock_load_ocsp_response(&trash, ocsp, cid, err);
end:
	if (fd != -1)
		close(fd);

	return ret;
}

#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
static int ssl_tlsext_ticket_key_cb(SSL *s, unsigned char key_name[16], unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
{
	struct tls_sess_key *keys;
	struct connection *conn;
	int head;
	int i;

	conn = (struct connection *)SSL_get_app_data(s);
	keys = objt_listener(conn->target)->bind_conf->keys_ref->tlskeys;
	head = objt_listener(conn->target)->bind_conf->keys_ref->tls_ticket_enc_index;

	if (enc) {
		memcpy(key_name, keys[head].name, 16);

		if(!RAND_pseudo_bytes(iv, EVP_MAX_IV_LENGTH))
			return -1;

		if(!EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, keys[head].aes_key, iv))
			return -1;

		HMAC_Init_ex(hctx, keys[head].hmac_key, 16, HASH_FUNCT(), NULL);

		return 1;
	} else {
		for (i = 0; i < TLS_TICKETS_NO; i++) {
			if (!memcmp(key_name, keys[(head + i) % TLS_TICKETS_NO].name, 16))
				goto found;
		}
		return 0;

		found:
		HMAC_Init_ex(hctx, keys[(head + i) % TLS_TICKETS_NO].hmac_key, 16, HASH_FUNCT(), NULL);
		if(!EVP_DecryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, keys[(head + i) % TLS_TICKETS_NO].aes_key, iv))
			return -1;
		/* 2 for key renewal, 1 if current key is still valid */
		return i ? 2 : 1;
	}
}

struct tls_keys_ref *tlskeys_ref_lookup(const char *filename)
{
        struct tls_keys_ref *ref;

        list_for_each_entry(ref, &tlskeys_reference, list)
                if (ref->filename && strcmp(filename, ref->filename) == 0)
                        return ref;
        return NULL;
}

struct tls_keys_ref *tlskeys_ref_lookupid(int unique_id)
{
        struct tls_keys_ref *ref;

        list_for_each_entry(ref, &tlskeys_reference, list)
                if (ref->unique_id == unique_id)
                        return ref;
        return NULL;
}

int ssl_sock_update_tlskey(char *filename, struct chunk *tlskey, char **err) {
	struct tls_keys_ref *ref = tlskeys_ref_lookup(filename);

	if(!ref) {
		memprintf(err, "Unable to locate the referenced filename: %s", filename);
		return 1;
	}

	memcpy((char *) (ref->tlskeys + 2 % TLS_TICKETS_NO), tlskey->str, tlskey->len);
	ref->tls_ticket_enc_index = ref->tls_ticket_enc_index + 1 % TLS_TICKETS_NO;

	return 0;
}

/* This function finalize the configuration parsing. Its set all the
 * automatic ids
 */
void tlskeys_finalize_config(void)
{
	int i = 0;
	struct tls_keys_ref *ref, *ref2, *ref3;
	struct list tkr = LIST_HEAD_INIT(tkr);

	list_for_each_entry(ref, &tlskeys_reference, list) {
		if (ref->unique_id == -1) {
			/* Look for the first free id. */
			while (1) {
				list_for_each_entry(ref2, &tlskeys_reference, list) {
					if (ref2->unique_id == i) {
						i++;
						break;
					}
				}
				if (&ref2->list == &tlskeys_reference)
					break;
			}

			/* Uses the unique id and increment it for the next entry. */
			ref->unique_id = i;
			i++;
		}
	}

	/* This sort the reference list by id. */
	list_for_each_entry_safe(ref, ref2, &tlskeys_reference, list) {
		LIST_DEL(&ref->list);
		list_for_each_entry(ref3, &tkr, list) {
			if (ref->unique_id < ref3->unique_id) {
				LIST_ADDQ(&ref3->list, &ref->list);
				break;
			}
		}
		if (&ref3->list == &tkr)
			LIST_ADDQ(&tkr, &ref->list);
	}

	/* swap root */
	LIST_ADD(&tkr, &tlskeys_reference);
	LIST_DEL(&tkr);
}

#endif /* SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB */

/*
 * Callback used to set OCSP status extension content in server hello.
 */
int ssl_sock_ocsp_stapling_cbk(SSL *ssl, void *arg)
{
	struct certificate_ocsp *ocsp = (struct certificate_ocsp *)arg;
	char* ssl_buf;

	if (!ocsp ||
	    !ocsp->response.str ||
	    !ocsp->response.len ||
	    (ocsp->expire < now.tv_sec))
		return SSL_TLSEXT_ERR_NOACK;

	ssl_buf = OPENSSL_malloc(ocsp->response.len);
	if (!ssl_buf)
		return SSL_TLSEXT_ERR_NOACK;

	memcpy(ssl_buf, ocsp->response.str, ocsp->response.len);
	SSL_set_tlsext_status_ocsp_resp(ssl, ssl_buf, ocsp->response.len);

	return SSL_TLSEXT_ERR_OK;
}

/*
 * This function enables the handling of OCSP status extension on 'ctx' if a
 * file name 'cert_path' suffixed using ".ocsp" is present.
 * To enable OCSP status extension, the issuer's certificate is mandatory.
 * It should be present in the certificate's extra chain builded from file
 * 'cert_path'. If not found, the issuer certificate is loaded from a file
 * named 'cert_path' suffixed using '.issuer'.
 *
 * In addition, ".ocsp" file content is loaded as a DER format of an OCSP
 * response. If file is empty or content is not a valid OCSP response,
 * OCSP status extension is enabled but OCSP response is ignored (a warning
 * is displayed).
 *
 * Returns 1 if no ".ocsp" file found, 0 if OCSP status extension is
 * succesfully enabled, or -1 in other error case.
 */
static int ssl_sock_load_ocsp(SSL_CTX *ctx, const char *cert_path)
{

	BIO *in = NULL;
	X509 *x, *xi = NULL, *issuer = NULL;
	STACK_OF(X509) *chain = NULL;
	OCSP_CERTID *cid = NULL;
	SSL *ssl;
	char ocsp_path[MAXPATHLEN+1];
	int i, ret = -1;
	struct stat st;
	struct certificate_ocsp *ocsp = NULL, *iocsp;
	char *warn = NULL;
	unsigned char *p;

	snprintf(ocsp_path, MAXPATHLEN+1, "%s.ocsp", cert_path);

	if (stat(ocsp_path, &st))
		return 1;

	ssl = SSL_new(ctx);
	if (!ssl)
		goto out;

	x = SSL_get_certificate(ssl);
	if (!x)
		goto out;

	/* Try to lookup for issuer in certificate extra chain */
#ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
	SSL_CTX_get_extra_chain_certs(ctx, &chain);
#else
	chain = ctx->extra_certs;
#endif
	for (i = 0; i < sk_X509_num(chain); i++) {
		issuer = sk_X509_value(chain, i);
		if (X509_check_issued(issuer, x) == X509_V_OK)
			break;
		else
			issuer = NULL;
	}

	/* If not found try to load issuer from a suffixed file */
	if (!issuer) {
		char issuer_path[MAXPATHLEN+1];

		in = BIO_new(BIO_s_file());
		if (!in)
			goto out;

		snprintf(issuer_path, MAXPATHLEN+1, "%s.issuer", cert_path);
		if (BIO_read_filename(in, issuer_path) <= 0)
			goto out;

		xi = PEM_read_bio_X509_AUX(in, NULL, ctx->default_passwd_callback, ctx->default_passwd_callback_userdata);
		if (!xi)
			goto out;

		if (X509_check_issued(xi, x) != X509_V_OK)
			goto out;

		issuer = xi;
	}

	cid = OCSP_cert_to_id(0, x, issuer);
	if (!cid)
		goto out;

	i = i2d_OCSP_CERTID(cid, NULL);
	if (!i || (i > OCSP_MAX_CERTID_ASN1_LENGTH))
		goto out;

	ocsp = calloc(1, sizeof(struct certificate_ocsp));
	if (!ocsp)
		goto out;

	p = ocsp->key_data;
	i2d_OCSP_CERTID(cid, &p);

	iocsp = (struct certificate_ocsp *)ebmb_insert(&cert_ocsp_tree, &ocsp->key, OCSP_MAX_CERTID_ASN1_LENGTH);
	if (iocsp == ocsp)
		ocsp = NULL;

	SSL_CTX_set_tlsext_status_cb(ctx, ssl_sock_ocsp_stapling_cbk);
	SSL_CTX_set_tlsext_status_arg(ctx, iocsp);

	ret = 0;

	warn = NULL;
	if (ssl_sock_load_ocsp_response_from_file(ocsp_path, iocsp, cid, &warn)) {
		memprintf(&warn, "Loading '%s': %s. Content will be ignored", ocsp_path, warn ? warn : "failure");
		Warning("%s.\n", warn);
	}

out:
	if (ssl)
		SSL_free(ssl);

	if (in)
		BIO_free(in);

	if (xi)
		X509_free(xi);

	if (cid)
		OCSP_CERTID_free(cid);

	if (ocsp)
		free(ocsp);

	if (warn)
		free(warn);


	return ret;
}

#endif

#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)

#define CT_EXTENSION_TYPE 18

static int sctl_ex_index = -1;

/*
 * Try to parse Signed Certificate Timestamp List structure. This function
 * makes only basic test if the data seems like SCTL. No signature validation
 * is performed.
 */
static int ssl_sock_parse_sctl(struct chunk *sctl)
{
	int ret = 1;
	int len, pos, sct_len;
	unsigned char *data;

	if (sctl->len < 2)
		goto out;

	data = (unsigned char *)sctl->str;
	len = (data[0] << 8) | data[1];

	if (len + 2 != sctl->len)
		goto out;

	data = data + 2;
	pos = 0;
	while (pos < len) {
		if (len - pos < 2)
			goto out;

		sct_len = (data[pos] << 8) | data[pos + 1];
		if (pos + sct_len + 2 > len)
			goto out;

		pos += sct_len + 2;
	}

	ret = 0;

out:
	return ret;
}

static int ssl_sock_load_sctl_from_file(const char *sctl_path, struct chunk **sctl)
{
	int fd = -1;
	int r = 0;
	int ret = 1;

	*sctl = NULL;

	fd = open(sctl_path, O_RDONLY);
	if (fd == -1)
		goto end;

	trash.len = 0;
	while (trash.len < trash.size) {
		r = read(fd, trash.str + trash.len, trash.size - trash.len);
		if (r < 0) {
			if (errno == EINTR)
				continue;

			goto end;
		}
		else if (r == 0) {
			break;
		}
		trash.len += r;
	}

	ret = ssl_sock_parse_sctl(&trash);
	if (ret)
		goto end;

	*sctl = calloc(1, sizeof(struct chunk));
	if (!chunk_dup(*sctl, &trash)) {
		free(*sctl);
		*sctl = NULL;
		goto end;
	}

end:
	if (fd != -1)
		close(fd);

	return ret;
}

int ssl_sock_sctl_add_cbk(SSL *ssl, unsigned ext_type, const unsigned char **out, size_t *outlen, int *al, void *add_arg)
{
	struct chunk *sctl = (struct chunk *)add_arg;

	*out = (unsigned char *)sctl->str;
	*outlen = sctl->len;

	return 1;
}

int ssl_sock_sctl_parse_cbk(SSL *s, unsigned int ext_type, const unsigned char *in, size_t inlen, int *al, void *parse_arg)
{
	return 1;
}

static int ssl_sock_load_sctl(SSL_CTX *ctx, const char *cert_path)
{
	char sctl_path[MAXPATHLEN+1];
	int ret = -1;
	struct stat st;
	struct chunk *sctl = NULL;

	snprintf(sctl_path, MAXPATHLEN+1, "%s.sctl", cert_path);

	if (stat(sctl_path, &st))
		return 1;

	if (ssl_sock_load_sctl_from_file(sctl_path, &sctl))
		goto out;

	if (!SSL_CTX_add_server_custom_ext(ctx, CT_EXTENSION_TYPE, ssl_sock_sctl_add_cbk, NULL, sctl, ssl_sock_sctl_parse_cbk, NULL)) {
		free(sctl);
		goto out;
	}

	SSL_CTX_set_ex_data(ctx, sctl_ex_index, sctl);

	ret = 0;

out:
	return ret;
}

#endif

void ssl_sock_infocbk(const SSL *ssl, int where, int ret)
{
	struct connection *conn = (struct connection *)SSL_get_app_data(ssl);
	BIO *write_bio;
	(void)ret; /* shut gcc stupid warning */

	if (where & SSL_CB_HANDSHAKE_START) {
		/* Disable renegotiation (CVE-2009-3555) */
		if (conn->flags & CO_FL_CONNECTED) {
			conn->flags |= CO_FL_ERROR;
			conn->err_code = CO_ER_SSL_RENEG;
		}
	}

	if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
		if (!(conn->xprt_st & SSL_SOCK_ST_FL_16K_WBFSIZE)) {
			/* Long certificate chains optimz
			   If write and read bios are differents, we
			   consider that the buffering was activated,
                           so we rise the output buffer size from 4k
			   to 16k */
			write_bio = SSL_get_wbio(ssl);
			if (write_bio != SSL_get_rbio(ssl)) {
				BIO_set_write_buffer_size(write_bio, 16384);
				conn->xprt_st |= SSL_SOCK_ST_FL_16K_WBFSIZE;
			}
		}
	}
}

/* Callback is called for each certificate of the chain during a verify
   ok is set to 1 if preverify detect no error on current certificate.
   Returns 0 to break the handshake, 1 otherwise. */
int ssl_sock_bind_verifycbk(int ok, X509_STORE_CTX *x_store)
{
	SSL *ssl;
	struct connection *conn;
	int err, depth;

	ssl = X509_STORE_CTX_get_ex_data(x_store, SSL_get_ex_data_X509_STORE_CTX_idx());
	conn = (struct connection *)SSL_get_app_data(ssl);

	conn->xprt_st |= SSL_SOCK_ST_FL_VERIFY_DONE;

	if (ok) /* no errors */
		return ok;

	depth = X509_STORE_CTX_get_error_depth(x_store);
	err = X509_STORE_CTX_get_error(x_store);

	/* check if CA error needs to be ignored */
	if (depth > 0) {
		if (!SSL_SOCK_ST_TO_CA_ERROR(conn->xprt_st)) {
			conn->xprt_st |= SSL_SOCK_CA_ERROR_TO_ST(err);
			conn->xprt_st |= SSL_SOCK_CAEDEPTH_TO_ST(depth);
		}

		if (objt_listener(conn->target)->bind_conf->ca_ignerr & (1ULL << err)) {
			ERR_clear_error();
			return 1;
		}

		conn->err_code = CO_ER_SSL_CA_FAIL;
		return 0;
	}

	if (!SSL_SOCK_ST_TO_CRTERROR(conn->xprt_st))
		conn->xprt_st |= SSL_SOCK_CRTERROR_TO_ST(err);

	/* check if certificate error needs to be ignored */
	if (objt_listener(conn->target)->bind_conf->crt_ignerr & (1ULL << err)) {
		ERR_clear_error();
		return 1;
	}

	conn->err_code = CO_ER_SSL_CRT_FAIL;
	return 0;
}

/* Callback is called for ssl protocol analyse */
void ssl_sock_msgcbk(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
#ifdef TLS1_RT_HEARTBEAT
	/* test heartbeat received (write_p is set to 0
	   for a received record) */
	if ((content_type == TLS1_RT_HEARTBEAT) && (write_p == 0)) {
		struct connection *conn = (struct connection *)SSL_get_app_data(ssl);
		const unsigned char *p = buf;
		unsigned int payload;

		conn->xprt_st |= SSL_SOCK_RECV_HEARTBEAT;

		/* Check if this is a CVE-2014-0160 exploitation attempt. */
		if (*p != TLS1_HB_REQUEST)
			return;

		if (len < 1 + 2 + 16) /* 1 type + 2 size + 0 payload + 16 padding */
			goto kill_it;

		payload = (p[1] * 256) + p[2];
		if (3 + payload + 16 <= len)
			return; /* OK no problem */
	kill_it:
		/* We have a clear heartbleed attack (CVE-2014-0160), the
		 * advertised payload is larger than the advertised packet
		 * length, so we have garbage in the buffer between the
		 * payload and the end of the buffer (p+len). We can't know
		 * if the SSL stack is patched, and we don't know if we can
		 * safely wipe out the area between p+3+len and payload.
		 * So instead, we prevent the response from being sent by
		 * setting the max_send_fragment to 0 and we report an SSL
		 * error, which will kill this connection. It will be reported
		 * above as SSL_ERROR_SSL while an other handshake failure with
		 * a heartbeat message will be reported as SSL_ERROR_SYSCALL.
		 */
		ssl->max_send_fragment = 0;
		SSLerr(SSL_F_TLS1_HEARTBEAT, SSL_R_SSL_HANDSHAKE_FAILURE);
		return;
	}
#endif
}

#ifdef OPENSSL_NPN_NEGOTIATED
/* This callback is used so that the server advertises the list of
 * negociable protocols for NPN.
 */
static int ssl_sock_advertise_npn_protos(SSL *s, const unsigned char **data,
                                         unsigned int *len, void *arg)
{
	struct bind_conf *conf = arg;

	*data = (const unsigned char *)conf->npn_str;
	*len = conf->npn_len;
	return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
/* This callback is used so that the server advertises the list of
 * negociable protocols for ALPN.
 */
static int ssl_sock_advertise_alpn_protos(SSL *s, const unsigned char **out,
                                          unsigned char *outlen,
                                          const unsigned char *server,
                                          unsigned int server_len, void *arg)
{
	struct bind_conf *conf = arg;

	if (SSL_select_next_proto((unsigned char**) out, outlen, (const unsigned char *)conf->alpn_str,
	                          conf->alpn_len, server, server_len) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
/* Create a X509 certificate with the specified servername and serial. This
 * function returns a SSL_CTX object or NULL if an error occurs. */
SSL_CTX *
ssl_sock_create_cert(const char *servername, unsigned int serial, X509 *cacert, EVP_PKEY *capkey)
{
	SSL_CTX      *ssl_ctx = NULL;
	X509         *newcrt  = NULL;
	EVP_PKEY     *pkey    = NULL;
	RSA          *rsa;
	X509_NAME    *name;
	const EVP_MD *digest;
	X509V3_CTX    ctx;
	unsigned int  i;

	/* Generate the public key */
	if (!(rsa = RSA_generate_key(2048, 3, NULL, NULL)))
		goto mkcert_error;
	if (!(pkey = EVP_PKEY_new()))
		goto mkcert_error;
	if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
		goto mkcert_error;

	/* Create the certificate */
	if (!(newcrt = X509_new()))
		goto mkcert_error;

	/* Set version number for the certificate (X509v3) and the serial
	 * number */
	if (X509_set_version(newcrt, 2L) != 1)
		goto mkcert_error;
	ASN1_INTEGER_set(X509_get_serialNumber(newcrt), serial);

	/* Set duration for the certificate */
	if (!X509_gmtime_adj(X509_get_notBefore(newcrt), (long)-60*60*24) ||
	    !X509_gmtime_adj(X509_get_notAfter(newcrt),(long)60*60*24*365))
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
	X509V3_set_ctx(&ctx, cacert, newcrt, NULL, NULL, 0);
	for (i = 0; i < X509V3_EXT_SIZE; i++) {
		X509_EXTENSION *ext;

		if (!(ext = X509V3_EXT_conf(NULL, &ctx, x509v3_ext_names[i], x509v3_ext_values[i])))
			goto mkcert_error;
		if (!X509_add_ext(newcrt, ext, -1)) {
			X509_EXTENSION_free(ext);
			goto mkcert_error;
		}
		X509_EXTENSION_free(ext);
	}

	/* Sign the certificate with the CA private key */
	if (EVP_PKEY_type(capkey->type) == EVP_PKEY_DSA)
		digest = EVP_dss1();
	else if (EVP_PKEY_type (capkey->type) == EVP_PKEY_RSA)
		digest = EVP_sha256();
	else
		goto mkcert_error;
	if (!(X509_sign(newcrt, capkey, digest)))
		goto mkcert_error;

	/* Create and set the new SSL_CTX */
	if (!(ssl_ctx = SSL_CTX_new(SSLv23_server_method())))
		goto mkcert_error;
	if (!SSL_CTX_use_PrivateKey(ssl_ctx, pkey))
		goto mkcert_error;
	if (!SSL_CTX_use_certificate(ssl_ctx, newcrt))
		goto mkcert_error;
	if (!SSL_CTX_check_private_key(ssl_ctx))
		goto mkcert_error;

	if (newcrt) X509_free(newcrt);
	if (pkey)   EVP_PKEY_free(pkey);
	return ssl_ctx;

 mkcert_error:
	if (ssl_ctx) SSL_CTX_free(ssl_ctx);
	if (newcrt)  X509_free(newcrt);
	if (pkey)    EVP_PKEY_free(pkey);
	return NULL;
}

/* Do a lookup for a certificate in the LRU cache used to store generated
 * certificates. */
SSL_CTX *
ssl_sock_get_generated_cert(unsigned int serial, X509 *cacert)
{
	struct lru64 *lru = NULL;

	if (ssl_ctx_lru_tree) {
		lru = lru64_lookup(serial, ssl_ctx_lru_tree, cacert, 0);
		if (lru && lru->domain)
			return (SSL_CTX *)lru->data;
	}
	return NULL;
}

/* Set a certificate int the LRU cache used to store generated certificate. */
void
ssl_sock_set_generated_cert(SSL_CTX *ssl_ctx, unsigned int serial, X509 *cacert)
{
	struct lru64 *lru = NULL;

	if (ssl_ctx_lru_tree) {
		lru = lru64_get(serial, ssl_ctx_lru_tree, cacert, 0);
		if (!lru)
			return;
		if (lru->domain && lru->data)
			lru->free((SSL_CTX *)lru->data);
		lru64_commit(lru, ssl_ctx, cacert, 0, (void (*)(void *))SSL_CTX_free);
	}
}

/* Compute the serial that will be used to create/set/get a certificate. */
unsigned int
ssl_sock_generated_cert_serial(const void *data, size_t len)
{
	return XXH32(data, len, ssl_ctx_lru_seed);
}

static SSL_CTX *
ssl_sock_generate_certificate(const char *servername, struct bind_conf *bind_conf)
{
	X509         *cacert  = bind_conf->ca_sign_cert;
	EVP_PKEY     *capkey  = bind_conf->ca_sign_pkey;
	SSL_CTX      *ssl_ctx = NULL;
	struct lru64 *lru     = NULL;
	unsigned int  serial;

	serial = ssl_sock_generated_cert_serial(servername, strlen(servername));
	if (ssl_ctx_lru_tree) {
		lru = lru64_get(serial, ssl_ctx_lru_tree, cacert, 0);
		if (lru && lru->domain)
			ssl_ctx = (SSL_CTX *)lru->data;
	}

	if (!ssl_ctx) {
		ssl_ctx = ssl_sock_create_cert(servername, serial, cacert, capkey);
		if (lru)
			lru64_commit(lru, ssl_ctx, cacert, 0, (void (*)(void *))SSL_CTX_free);
	}
	return ssl_ctx;
}

/* Sets the SSL ctx of <ssl> to match the advertised server name. Returns a
 * warning when no match is found, which implies the default (first) cert
 * will keep being used.
 */
static int ssl_sock_switchctx_cbk(SSL *ssl, int *al, struct bind_conf *s)
{
	const char *servername;
	const char *wildp = NULL;
	struct ebmb_node *node, *n;
	int i;
	(void)al; /* shut gcc stupid warning */

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername) {
		if (s->generate_certs) {
			struct connection *conn = (struct connection *)SSL_get_app_data(ssl);
			unsigned int serial;
			SSL_CTX *ctx;

			conn_get_to_addr(conn);
			if (conn->flags & CO_FL_ADDR_TO_SET) {
				serial = ssl_sock_generated_cert_serial(&conn->addr.to, get_addr_len(&conn->addr.to));
				ctx = ssl_sock_get_generated_cert(serial, s->ca_sign_cert);
				if (ctx) {
					/* switch ctx */
					SSL_set_SSL_CTX(ssl, ctx);
					return SSL_TLSEXT_ERR_OK;
				}
			}
		}

		return (s->strict_sni ?
			SSL_TLSEXT_ERR_ALERT_FATAL :
			SSL_TLSEXT_ERR_NOACK);
	}

	for (i = 0; i < trash.size; i++) {
		if (!servername[i])
			break;
		trash.str[i] = tolower(servername[i]);
		if (!wildp && (trash.str[i] == '.'))
			wildp = &trash.str[i];
	}
	trash.str[i] = 0;

	/* lookup in full qualified names */
	node = ebst_lookup(&s->sni_ctx, trash.str);

	/* lookup a not neg filter */
	for (n = node; n; n = ebmb_next_dup(n)) {
		if (!container_of(n, struct sni_ctx, name)->neg) {
			node = n;
			break;
		}
	}
	if (!node && wildp) {
		/* lookup in wildcards names */
		node = ebst_lookup(&s->sni_w_ctx, wildp);
	}
	if (!node || container_of(node, struct sni_ctx, name)->neg) {
		SSL_CTX *ctx;

		if (s->generate_certs &&
		    (ctx = ssl_sock_generate_certificate(servername, s))) {
			/* switch ctx */
			SSL_set_SSL_CTX(ssl, ctx);
			return SSL_TLSEXT_ERR_OK;
		}
		return (s->strict_sni ?
			SSL_TLSEXT_ERR_ALERT_FATAL :
			SSL_TLSEXT_ERR_ALERT_WARNING);
	}

	/* switch ctx */
	SSL_set_SSL_CTX(ssl, container_of(node, struct sni_ctx, name)->ctx);
	return SSL_TLSEXT_ERR_OK;
}
#endif /* SSL_CTRL_SET_TLSEXT_HOSTNAME */

#ifndef OPENSSL_NO_DH

static DH * ssl_get_dh_1024(void)
{
	static unsigned char dh1024_p[]={
		0xFA,0xF9,0x2A,0x22,0x2A,0xA7,0x7F,0xE1,0x67,0x4E,0x53,0xF7,
		0x56,0x13,0xC3,0xB1,0xE3,0x29,0x6B,0x66,0x31,0x6A,0x7F,0xB3,
		0xC2,0x68,0x6B,0xCB,0x1D,0x57,0x39,0x1D,0x1F,0xFF,0x1C,0xC9,
		0xA6,0xA4,0x98,0x82,0x31,0x5D,0x25,0xFF,0x8A,0xE0,0x73,0x96,
		0x81,0xC8,0x83,0x79,0xC1,0x5A,0x04,0xF8,0x37,0x0D,0xA8,0x3D,
		0xAE,0x74,0xBC,0xDB,0xB6,0xA4,0x75,0xD9,0x71,0x8A,0xA0,0x17,
		0x9E,0x2D,0xC8,0xA8,0xDF,0x2C,0x5F,0x82,0x95,0xF8,0x92,0x9B,
		0xA7,0x33,0x5F,0x89,0x71,0xC8,0x2D,0x6B,0x18,0x86,0xC4,0x94,
		0x22,0xA5,0x52,0x8D,0xF6,0xF6,0xD2,0x37,0x92,0x0F,0xA5,0xCC,
		0xDB,0x7B,0x1D,0x3D,0xA1,0x31,0xB7,0x80,0x8F,0x0B,0x67,0x5E,
		0x36,0xA5,0x60,0x0C,0xF1,0x95,0x33,0x8B,
		};
	static unsigned char dh1024_g[]={
		0x02,
		};

	DH *dh = DH_new();
	if (dh) {
		dh->p = BN_bin2bn(dh1024_p, sizeof dh1024_p, NULL);
		dh->g = BN_bin2bn(dh1024_g, sizeof dh1024_g, NULL);

		if (!dh->p || !dh->g) {
			DH_free(dh);
			dh = NULL;
		}
	}
	return dh;
}

static DH *ssl_get_dh_2048(void)
{
	static unsigned char dh2048_p[]={
		0xEC,0x86,0xF8,0x70,0xA0,0x33,0x16,0xEC,0x05,0x1A,0x73,0x59,
		0xCD,0x1F,0x8B,0xF8,0x29,0xE4,0xD2,0xCF,0x52,0xDD,0xC2,0x24,
		0x8D,0xB5,0x38,0x9A,0xFB,0x5C,0xA4,0xE4,0xB2,0xDA,0xCE,0x66,
		0x50,0x74,0xA6,0x85,0x4D,0x4B,0x1D,0x30,0xB8,0x2B,0xF3,0x10,
		0xE9,0xA7,0x2D,0x05,0x71,0xE7,0x81,0xDF,0x8B,0x59,0x52,0x3B,
		0x5F,0x43,0x0B,0x68,0xF1,0xDB,0x07,0xBE,0x08,0x6B,0x1B,0x23,
		0xEE,0x4D,0xCC,0x9E,0x0E,0x43,0xA0,0x1E,0xDF,0x43,0x8C,0xEC,
		0xBE,0xBE,0x90,0xB4,0x51,0x54,0xB9,0x2F,0x7B,0x64,0x76,0x4E,
		0x5D,0xD4,0x2E,0xAE,0xC2,0x9E,0xAE,0x51,0x43,0x59,0xC7,0x77,
		0x9C,0x50,0x3C,0x0E,0xED,0x73,0x04,0x5F,0xF1,0x4C,0x76,0x2A,
		0xD8,0xF8,0xCF,0xFC,0x34,0x40,0xD1,0xB4,0x42,0x61,0x84,0x66,
		0x42,0x39,0x04,0xF8,0x68,0xB2,0x62,0xD7,0x55,0xED,0x1B,0x74,
		0x75,0x91,0xE0,0xC5,0x69,0xC1,0x31,0x5C,0xDB,0x7B,0x44,0x2E,
		0xCE,0x84,0x58,0x0D,0x1E,0x66,0x0C,0xC8,0x44,0x9E,0xFD,0x40,
		0x08,0x67,0x5D,0xFB,0xA7,0x76,0x8F,0x00,0x11,0x87,0xE9,0x93,
		0xF9,0x7D,0xC4,0xBC,0x74,0x55,0x20,0xD4,0x4A,0x41,0x2F,0x43,
		0x42,0x1A,0xC1,0xF2,0x97,0x17,0x49,0x27,0x37,0x6B,0x2F,0x88,
		0x7E,0x1C,0xA0,0xA1,0x89,0x92,0x27,0xD9,0x56,0x5A,0x71,0xC1,
		0x56,0x37,0x7E,0x3A,0x9D,0x05,0xE7,0xEE,0x5D,0x8F,0x82,0x17,
		0xBC,0xE9,0xC2,0x93,0x30,0x82,0xF9,0xF4,0xC9,0xAE,0x49,0xDB,
		0xD0,0x54,0xB4,0xD9,0x75,0x4D,0xFA,0x06,0xB8,0xD6,0x38,0x41,
		0xB7,0x1F,0x77,0xF3,
		};
	static unsigned char dh2048_g[]={
		0x02,
		};

	DH *dh = DH_new();
	if (dh) {
		dh->p = BN_bin2bn(dh2048_p, sizeof dh2048_p, NULL);
		dh->g = BN_bin2bn(dh2048_g, sizeof dh2048_g, NULL);

		if (!dh->p || !dh->g) {
			DH_free(dh);
			dh = NULL;
		}
	}
	return dh;
}

static DH *ssl_get_dh_4096(void)
{
	static unsigned char dh4096_p[]={
		0xDE,0x16,0x94,0xCD,0x99,0x58,0x07,0xF1,0xF7,0x32,0x96,0x11,
		0x04,0x82,0xD4,0x84,0x72,0x80,0x99,0x06,0xCA,0xF0,0xA3,0x68,
		0x07,0xCE,0x64,0x50,0xE7,0x74,0x45,0x20,0x80,0x5E,0x4D,0xAD,
		0xA5,0xB6,0xED,0xFA,0x80,0x6C,0x3B,0x35,0xC4,0x9A,0x14,0x6B,
		0x32,0xBB,0xFD,0x1F,0x17,0x8E,0xB7,0x1F,0xD6,0xFA,0x3F,0x7B,
		0xEE,0x16,0xA5,0x62,0x33,0x0D,0xED,0xBC,0x4E,0x58,0xE5,0x47,
		0x4D,0xE9,0xAB,0x8E,0x38,0xD3,0x6E,0x90,0x57,0xE3,0x22,0x15,
		0x33,0xBD,0xF6,0x43,0x45,0xB5,0x10,0x0A,0xBE,0x2C,0xB4,0x35,
		0xB8,0x53,0x8D,0xAD,0xFB,0xA7,0x1F,0x85,0x58,0x41,0x7A,0x79,
		0x20,0x68,0xB3,0xE1,0x3D,0x08,0x76,0xBF,0x86,0x0D,0x49,0xE3,
		0x82,0x71,0x8C,0xB4,0x8D,0x81,0x84,0xD4,0xE7,0xBE,0x91,0xDC,
		0x26,0x39,0x48,0x0F,0x35,0xC4,0xCA,0x65,0xE3,0x40,0x93,0x52,
		0x76,0x58,0x7D,0xDD,0x51,0x75,0xDC,0x69,0x61,0xBF,0x47,0x2C,
		0x16,0x68,0x2D,0xC9,0x29,0xD3,0xE6,0xC0,0x99,0x48,0xA0,0x9A,
		0xC8,0x78,0xC0,0x6D,0x81,0x67,0x12,0x61,0x3F,0x71,0xBA,0x41,
		0x1F,0x6C,0x89,0x44,0x03,0xBA,0x3B,0x39,0x60,0xAA,0x28,0x55,
		0x59,0xAE,0xB8,0xFA,0xCB,0x6F,0xA5,0x1A,0xF7,0x2B,0xDD,0x52,
		0x8A,0x8B,0xE2,0x71,0xA6,0x5E,0x7E,0xD8,0x2E,0x18,0xE0,0x66,
		0xDF,0xDD,0x22,0x21,0x99,0x52,0x73,0xA6,0x33,0x20,0x65,0x0E,
		0x53,0xE7,0x6B,0x9B,0xC5,0xA3,0x2F,0x97,0x65,0x76,0xD3,0x47,
		0x23,0x77,0x12,0xB6,0x11,0x7B,0x24,0xED,0xF1,0xEF,0xC0,0xE2,
		0xA3,0x7E,0x67,0x05,0x3E,0x96,0x4D,0x45,0xC2,0x18,0xD1,0x73,
		0x9E,0x07,0xF3,0x81,0x6E,0x52,0x63,0xF6,0x20,0x76,0xB9,0x13,
		0xD2,0x65,0x30,0x18,0x16,0x09,0x16,0x9E,0x8F,0xF1,0xD2,0x10,
		0x5A,0xD3,0xD4,0xAF,0x16,0x61,0xDA,0x55,0x2E,0x18,0x5E,0x14,
		0x08,0x54,0x2E,0x2A,0x25,0xA2,0x1A,0x9B,0x8B,0x32,0xA9,0xFD,
		0xC2,0x48,0x96,0xE1,0x80,0xCA,0xE9,0x22,0x17,0xBB,0xCE,0x3E,
		0x9E,0xED,0xC7,0xF1,0x1F,0xEC,0x17,0x21,0xDC,0x7B,0x82,0x48,
		0x8E,0xBB,0x4B,0x9D,0x5B,0x04,0x04,0xDA,0xDB,0x39,0xDF,0x01,
		0x40,0xC3,0xAA,0x26,0x23,0x89,0x75,0xC6,0x0B,0xD0,0xA2,0x60,
		0x6A,0xF1,0xCC,0x65,0x18,0x98,0x1B,0x52,0xD2,0x74,0x61,0xCC,
		0xBD,0x60,0xAE,0xA3,0xA0,0x66,0x6A,0x16,0x34,0x92,0x3F,0x41,
		0x40,0x31,0x29,0xC0,0x2C,0x63,0xB2,0x07,0x8D,0xEB,0x94,0xB8,
		0xE8,0x47,0x92,0x52,0x93,0x6A,0x1B,0x7E,0x1A,0x61,0xB3,0x1B,
		0xF0,0xD6,0x72,0x9B,0xF1,0xB0,0xAF,0xBF,0x3E,0x65,0xEF,0x23,
		0x1D,0x6F,0xFF,0x70,0xCD,0x8A,0x4C,0x8A,0xA0,0x72,0x9D,0xBE,
		0xD4,0xBB,0x24,0x47,0x4A,0x68,0xB5,0xF5,0xC6,0xD5,0x7A,0xCD,
		0xCA,0x06,0x41,0x07,0xAD,0xC2,0x1E,0xE6,0x54,0xA7,0xAD,0x03,
		0xD9,0x12,0xC1,0x9C,0x13,0xB1,0xC9,0x0A,0x43,0x8E,0x1E,0x08,
		0xCE,0x50,0x82,0x73,0x5F,0xA7,0x55,0x1D,0xD9,0x59,0xAC,0xB5,
		0xEA,0x02,0x7F,0x6C,0x5B,0x74,0x96,0x98,0x67,0x24,0xA3,0x0F,
		0x15,0xFC,0xA9,0x7D,0x3E,0x67,0xD1,0x70,0xF8,0x97,0xF3,0x67,
		0xC5,0x8C,0x88,0x44,0x08,0x02,0xC7,0x2B,
	};
	static unsigned char dh4096_g[]={
		0x02,
		};

	DH *dh = DH_new();
	if (dh) {
		dh->p = BN_bin2bn(dh4096_p, sizeof dh4096_p, NULL);
		dh->g = BN_bin2bn(dh4096_g, sizeof dh4096_g, NULL);

		if (!dh->p || !dh->g) {
			DH_free(dh);
			dh = NULL;
		}
	}
	return dh;
}

/* Returns Diffie-Hellman parameters matching the private key length
   but not exceeding global.tune.ssl_default_dh_param */
static DH *ssl_get_tmp_dh(SSL *ssl, int export, int keylen)
{
	DH *dh = NULL;
	EVP_PKEY *pkey = SSL_get_privatekey(ssl);
	int type = pkey ? EVP_PKEY_type(pkey->type) : EVP_PKEY_NONE;

	/* The keylen supplied by OpenSSL can only be 512 or 1024.
	   See ssl3_send_server_key_exchange() in ssl/s3_srvr.c
	 */
	if (type == EVP_PKEY_RSA || type == EVP_PKEY_DSA) {
		keylen = EVP_PKEY_bits(pkey);
	}

	if (keylen > global.tune.ssl_default_dh_param) {
		keylen = global.tune.ssl_default_dh_param;
	}

	if (keylen >= 4096) {
		dh = local_dh_4096;
	}
	else if (keylen >= 2048) {
		dh = local_dh_2048;
	}
	else {
		dh = local_dh_1024;
	}

	return dh;
}

static DH * ssl_sock_get_dh_from_file(const char *filename)
{
	DH *dh = NULL;
	BIO *in = BIO_new(BIO_s_file());

	if (in == NULL)
		goto end;

	if (BIO_read_filename(in, filename) <= 0)
		goto end;

	dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);

end:
        if (in)
                BIO_free(in);

	return dh;
}

int ssl_sock_load_global_dh_param_from_file(const char *filename)
{
	global_dh = ssl_sock_get_dh_from_file(filename);

	if (global_dh) {
		return 0;
	}

	return -1;
}

/* Loads Diffie-Hellman parameter from a file. Returns 1 if loaded, else -1
   if an error occured, and 0 if parameter not found. */
int ssl_sock_load_dh_params(SSL_CTX *ctx, const char *file)
{
	int ret = -1;
	DH *dh = ssl_sock_get_dh_from_file(file);

	if (dh) {
		ret = 1;
		SSL_CTX_set_tmp_dh(ctx, dh);

		if (ssl_dh_ptr_index >= 0) {
			/* store a pointer to the DH params to avoid complaining about
			   ssl-default-dh-param not being set for this SSL_CTX */
			SSL_CTX_set_ex_data(ctx, ssl_dh_ptr_index, dh);
		}
	}
	else if (global_dh) {
		SSL_CTX_set_tmp_dh(ctx, global_dh);
		ret = 0; /* DH params not found */
	}
	else {
		/* Clear openssl global errors stack */
		ERR_clear_error();

		if (global.tune.ssl_default_dh_param <= 1024) {
			/* we are limited to DH parameter of 1024 bits anyway */
			local_dh_1024 = ssl_get_dh_1024();
			if (local_dh_1024 == NULL)
				goto end;

			SSL_CTX_set_tmp_dh(ctx, local_dh_1024);
		}
		else {
			SSL_CTX_set_tmp_dh_callback(ctx, ssl_get_tmp_dh);
		}

		ret = 0; /* DH params not found */
	}

end:
	if (dh)
		DH_free(dh);

	return ret;
}
#endif

static int ssl_sock_add_cert_sni(SSL_CTX *ctx, struct bind_conf *s, char *name, int order)
{
	struct sni_ctx *sc;
	int wild = 0, neg = 0;

	if (*name == '!') {
		neg = 1;
		name++;
	}
	if (*name == '*') {
		wild = 1;
		name++;
	}
	/* !* filter is a nop */
	if (neg && wild)
		return order;
	if (*name) {
		int j, len;
		len = strlen(name);
		sc = malloc(sizeof(struct sni_ctx) + len + 1);
		for (j = 0; j < len; j++)
			sc->name.key[j] = tolower(name[j]);
		sc->name.key[len] = 0;
		sc->ctx = ctx;
		sc->order = order++;
		sc->neg = neg;
		if (wild)
			ebst_insert(&s->sni_w_ctx, &sc->name);
		else
			ebst_insert(&s->sni_ctx, &sc->name);
	}
	return order;
}

/* Loads a certificate key and CA chain from a file. Returns 0 on error, -1 if
 * an early error happens and the caller must call SSL_CTX_free() by itelf.
 */
static int ssl_sock_load_cert_chain_file(SSL_CTX *ctx, const char *file, struct bind_conf *s, char **sni_filter, int fcount)
{
	BIO *in;
	X509 *x = NULL, *ca;
	int i, err;
	int ret = -1;
	int order = 0;
	X509_NAME *xname;
	char *str;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	STACK_OF(GENERAL_NAME) *names;
#endif

	in = BIO_new(BIO_s_file());
	if (in == NULL)
		goto end;

	if (BIO_read_filename(in, file) <= 0)
		goto end;

	x = PEM_read_bio_X509_AUX(in, NULL, ctx->default_passwd_callback, ctx->default_passwd_callback_userdata);
	if (x == NULL)
		goto end;

	if (fcount) {
		while (fcount--)
			order = ssl_sock_add_cert_sni(ctx, s, sni_filter[fcount], order);
	}
	else {
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
		names = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
		if (names) {
			for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
				GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
				if (name->type == GEN_DNS) {
					if (ASN1_STRING_to_UTF8((unsigned char **)&str, name->d.dNSName) >= 0) {
						order = ssl_sock_add_cert_sni(ctx, s, str, order);
						OPENSSL_free(str);
					}
				}
			}
			sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
		}
#endif /* SSL_CTRL_SET_TLSEXT_HOSTNAME */
		xname = X509_get_subject_name(x);
		i = -1;
		while ((i = X509_NAME_get_index_by_NID(xname, NID_commonName, i)) != -1) {
			X509_NAME_ENTRY *entry = X509_NAME_get_entry(xname, i);
			if (ASN1_STRING_to_UTF8((unsigned char **)&str, entry->value) >= 0) {
				order = ssl_sock_add_cert_sni(ctx, s, str, order);
				OPENSSL_free(str);
			}
		}
	}

	ret = 0; /* the caller must not free the SSL_CTX argument anymore */
	if (!SSL_CTX_use_certificate(ctx, x))
		goto end;

	if (ctx->extra_certs != NULL) {
		sk_X509_pop_free(ctx->extra_certs, X509_free);
		ctx->extra_certs = NULL;
	}

	while ((ca = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback, ctx->default_passwd_callback_userdata))) {
		if (!SSL_CTX_add_extra_chain_cert(ctx, ca)) {
			X509_free(ca);
			goto end;
		}
	}

	err = ERR_get_error();
	if (!err || (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
		/* we successfully reached the last cert in the file */
		ret = 1;
	}
	ERR_clear_error();

end:
	if (x)
		X509_free(x);

	if (in)
		BIO_free(in);

	return ret;
}

static int ssl_sock_load_cert_file(const char *path, struct bind_conf *bind_conf, struct proxy *curproxy, char **sni_filter, int fcount, char **err)
{
	int ret;
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		memprintf(err, "%sunable to allocate SSL context for cert '%s'.\n",
		          err && *err ? *err : "", path);
		return 1;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM) <= 0) {
		memprintf(err, "%sunable to load SSL private key from PEM file '%s'.\n",
		          err && *err ? *err : "", path);
		SSL_CTX_free(ctx);
		return 1;
	}

	ret = ssl_sock_load_cert_chain_file(ctx, path, bind_conf, sni_filter, fcount);
	if (ret <= 0) {
		memprintf(err, "%sunable to load SSL certificate from PEM file '%s'.\n",
		          err && *err ? *err : "", path);
		if (ret < 0) /* serious error, must do that ourselves */
			SSL_CTX_free(ctx);
		return 1;
	}

	if (SSL_CTX_check_private_key(ctx) <= 0) {
		memprintf(err, "%sinconsistencies between private key and certificate loaded from PEM file '%s'.\n",
		          err && *err ? *err : "", path);
		return 1;
	}

	/* we must not free the SSL_CTX anymore below, since it's already in
	 * the tree, so it will be discovered and cleaned in time.
	 */
#ifndef OPENSSL_NO_DH
	/* store a NULL pointer to indicate we have not yet loaded
	   a custom DH param file */
	if (ssl_dh_ptr_index >= 0) {
		SSL_CTX_set_ex_data(ctx, ssl_dh_ptr_index, NULL);
	}

	ret = ssl_sock_load_dh_params(ctx, path);
	if (ret < 0) {
		if (err)
			memprintf(err, "%sunable to load DH parameters from file '%s'.\n",
				  *err ? *err : "", path);
		return 1;
	}
#endif

#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
	ret = ssl_sock_load_ocsp(ctx, path);
	if (ret < 0) {
		if (err)
			memprintf(err, "%s '%s.ocsp' is present and activates OCSP but it is impossible to compute the OCSP certificate ID (maybe the issuer could not be found)'.\n",
				  *err ? *err : "", path);
		return 1;
	}
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
	if (sctl_ex_index >= 0) {
		ret = ssl_sock_load_sctl(ctx, path);
		if (ret < 0) {
			if (err)
				memprintf(err, "%s '%s.sctl' is present but cannot be read or parsed'.\n",
					  *err ? *err : "", path);
			return 1;
		}
	}
#endif

#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
	if (bind_conf->default_ctx) {
		memprintf(err, "%sthis version of openssl cannot load multiple SSL certificates.\n",
		          err && *err ? *err : "");
		return 1;
	}
#endif
	if (!bind_conf->default_ctx)
		bind_conf->default_ctx = ctx;

	return 0;
}

int ssl_sock_load_cert(char *path, struct bind_conf *bind_conf, struct proxy *curproxy, char **err)
{
	struct dirent **de_list;
	int i, n;
	DIR *dir;
	struct stat buf;
	char *end;
	char fp[MAXPATHLEN+1];
	int cfgerr = 0;

	if (!(dir = opendir(path)))
		return ssl_sock_load_cert_file(path, bind_conf, curproxy, NULL, 0, err);

	/* strip trailing slashes, including first one */
	for (end = path + strlen(path) - 1; end >= path && *end == '/'; end--)
		*end = 0;

	n = scandir(path, &de_list, 0, alphasort);
	if (n < 0) {
		memprintf(err, "%sunable to scan directory '%s' : %s.\n",
			  err && *err ? *err : "", path, strerror(errno));
		cfgerr++;
	}
	else {
		for (i = 0; i < n; i++) {
			struct dirent *de = de_list[i];

			end = strrchr(de->d_name, '.');
			if (end && (!strcmp(end, ".issuer") || !strcmp(end, ".ocsp") || !strcmp(end, ".sctl")))
				goto ignore_entry;

			snprintf(fp, sizeof(fp), "%s/%s", path, de->d_name);
			if (stat(fp, &buf) != 0) {
				memprintf(err, "%sunable to stat SSL certificate from file '%s' : %s.\n",
					  err && *err ? *err : "", fp, strerror(errno));
				cfgerr++;
				goto ignore_entry;
			}
			if (!S_ISREG(buf.st_mode))
				goto ignore_entry;
			cfgerr += ssl_sock_load_cert_file(fp, bind_conf, curproxy, NULL, 0, err);
	ignore_entry:
			free(de);
		}
		free(de_list);
	}
	closedir(dir);
	return cfgerr;
}

/* Make sure openssl opens /dev/urandom before the chroot. The work is only
 * done once. Zero is returned if the operation fails. No error is returned
 * if the random is said as not implemented, because we expect that openssl
 * will use another method once needed.
 */
static int ssl_initialize_random()
{
	unsigned char random;
	static int random_initialized = 0;

	if (!random_initialized && RAND_bytes(&random, 1) != 0)
		random_initialized = 1;

	return random_initialized;
}

int ssl_sock_load_cert_list_file(char *file, struct bind_conf *bind_conf, struct proxy *curproxy, char **err)
{
	char thisline[LINESIZE];
	FILE *f;
	int linenum = 0;
	int cfgerr = 0;

	if ((f = fopen(file, "r")) == NULL) {
		memprintf(err, "cannot open file '%s' : %s", file, strerror(errno));
		return 1;
	}

	while (fgets(thisline, sizeof(thisline), f) != NULL) {
		int arg;
		int newarg;
		char *end;
		char *args[MAX_LINE_ARGS + 1];
		char *line = thisline;

		linenum++;
		end = line + strlen(line);
		if (end-line == sizeof(thisline)-1 && *(end-1) != '\n') {
			/* Check if we reached the limit and the last char is not \n.
			 * Watch out for the last line without the terminating '\n'!
			 */
			memprintf(err, "line %d too long in file '%s', limit is %d characters",
				  linenum, file, (int)sizeof(thisline)-1);
			cfgerr = 1;
			break;
		}

		arg = 0;
		newarg = 1;
		while (*line) {
			if (*line == '#' || *line == '\n' || *line == '\r') {
				/* end of string, end of loop */
				*line = 0;
				break;
			}
			else if (isspace(*line)) {
				newarg = 1;
				*line = 0;
			}
			else if (newarg) {
				if (arg == MAX_LINE_ARGS) {
					memprintf(err, "too many args on line %d in file '%s'.",
						  linenum, file);
					cfgerr = 1;
					break;
				}
				newarg = 0;
				args[arg++] = line;
			}
			line++;
		}
		if (cfgerr)
			break;

		/* empty line */
		if (!arg)
			continue;

		cfgerr = ssl_sock_load_cert_file(args[0], bind_conf, curproxy, &args[1], arg-1, err);
		if (cfgerr) {
			memprintf(err, "error processing line %d in file '%s' : %s", linenum, file, *err);
			break;
		}
	}
	fclose(f);
	return cfgerr;
}

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
#ifndef SSL_OP_NO_TLSv1_1                               /* needs OpenSSL >= 1.0.1 */
#define SSL_OP_NO_TLSv1_1 0
#endif
#ifndef SSL_OP_NO_TLSv1_2                               /* needs OpenSSL >= 1.0.1 */
#define SSL_OP_NO_TLSv1_2 0
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

int ssl_sock_prepare_ctx(struct bind_conf *bind_conf, SSL_CTX *ctx, struct proxy *curproxy)
{
	int cfgerr = 0;
	int verify = SSL_VERIFY_NONE;
	long ssloptions =
		SSL_OP_ALL | /* all known workarounds for bugs */
		SSL_OP_NO_SSLv2 |
		SSL_OP_NO_COMPRESSION |
		SSL_OP_SINGLE_DH_USE |
		SSL_OP_SINGLE_ECDH_USE |
		SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
		SSL_OP_CIPHER_SERVER_PREFERENCE;
	long sslmode =
		SSL_MODE_ENABLE_PARTIAL_WRITE |
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
		SSL_MODE_RELEASE_BUFFERS |
		SSL_MODE_SMALL_BUFFERS;
	STACK_OF(SSL_CIPHER) * ciphers = NULL;
	SSL_CIPHER * cipher = NULL;
	char cipher_description[128];
	/* The description of ciphers using an Ephemeral Diffie Hellman key exchange
	   contains " Kx=DH " or " Kx=DH(". Beware of " Kx=DH/",
	   which is not ephemeral DH. */
	const char dhe_description[] = " Kx=DH ";
	const char dhe_export_description[] = " Kx=DH(";
	int idx = 0;
	int dhe_found = 0;
	SSL *ssl = NULL;

	/* Make sure openssl opens /dev/urandom before the chroot */
	if (!ssl_initialize_random()) {
		Alert("OpenSSL random data generator initialization failed.\n");
		cfgerr++;
	}

	if (bind_conf->ssl_options & BC_SSL_O_NO_SSLV3)
		ssloptions |= SSL_OP_NO_SSLv3;
	if (bind_conf->ssl_options & BC_SSL_O_NO_TLSV10)
		ssloptions |= SSL_OP_NO_TLSv1;
	if (bind_conf->ssl_options & BC_SSL_O_NO_TLSV11)
		ssloptions |= SSL_OP_NO_TLSv1_1;
	if (bind_conf->ssl_options & BC_SSL_O_NO_TLSV12)
		ssloptions |= SSL_OP_NO_TLSv1_2;
	if (bind_conf->ssl_options & BC_SSL_O_NO_TLS_TICKETS)
		ssloptions |= SSL_OP_NO_TICKET;
	if (bind_conf->ssl_options & BC_SSL_O_USE_SSLV3)
		SSL_CTX_set_ssl_version(ctx, SSLv3_server_method());
	if (bind_conf->ssl_options & BC_SSL_O_USE_TLSV10)
		SSL_CTX_set_ssl_version(ctx, TLSv1_server_method());
#if SSL_OP_NO_TLSv1_1
	if (bind_conf->ssl_options & BC_SSL_O_USE_TLSV11)
		SSL_CTX_set_ssl_version(ctx, TLSv1_1_server_method());
#endif
#if SSL_OP_NO_TLSv1_2
	if (bind_conf->ssl_options & BC_SSL_O_USE_TLSV12)
		SSL_CTX_set_ssl_version(ctx, TLSv1_2_server_method());
#endif

	SSL_CTX_set_options(ctx, ssloptions);
	SSL_CTX_set_mode(ctx, sslmode);
	switch (bind_conf->verify) {
		case SSL_SOCK_VERIFY_NONE:
			verify = SSL_VERIFY_NONE;
			break;
		case SSL_SOCK_VERIFY_OPTIONAL:
			verify = SSL_VERIFY_PEER;
			break;
		case SSL_SOCK_VERIFY_REQUIRED:
			verify = SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			break;
	}
	SSL_CTX_set_verify(ctx, verify, ssl_sock_bind_verifycbk);
	if (verify & SSL_VERIFY_PEER) {
		if (bind_conf->ca_file) {
			/* load CAfile to verify */
			if (!SSL_CTX_load_verify_locations(ctx, bind_conf->ca_file, NULL)) {
				Alert("Proxy '%s': unable to load CA file '%s' for bind '%s' at [%s:%d].\n",
				      curproxy->id, bind_conf->ca_file, bind_conf->arg, bind_conf->file, bind_conf->line);
				cfgerr++;
			}
			/* set CA names fo client cert request, function returns void */
			SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(bind_conf->ca_file));
		}
		else {
			Alert("Proxy '%s': verify is enabled but no CA file specified for bind '%s' at [%s:%d].\n",
			      curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr++;
		}
#ifdef X509_V_FLAG_CRL_CHECK
		if (bind_conf->crl_file) {
			X509_STORE *store = SSL_CTX_get_cert_store(ctx);

			if (!store || !X509_STORE_load_locations(store, bind_conf->crl_file, NULL)) {
				Alert("Proxy '%s': unable to configure CRL file '%s' for bind '%s' at [%s:%d].\n",
				      curproxy->id, bind_conf->crl_file, bind_conf->arg, bind_conf->file, bind_conf->line);
				cfgerr++;
			}
			else {
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
			}
		}
#endif
		ERR_clear_error();
	}

#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
	if(bind_conf->keys_ref) {
		if (!SSL_CTX_set_tlsext_ticket_key_cb(ctx, ssl_tlsext_ticket_key_cb)) {
			Alert("Proxy '%s': unable to set callback for TLS ticket validation for bind '%s' at [%s:%d].\n",
				curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr++;
		}
	}
#endif

	if (global.tune.ssllifetime)
		SSL_CTX_set_timeout(ctx, global.tune.ssllifetime);

	shared_context_set_cache(ctx);
	if (bind_conf->ciphers &&
	    !SSL_CTX_set_cipher_list(ctx, bind_conf->ciphers)) {
		Alert("Proxy '%s': unable to set SSL cipher list to '%s' for bind '%s' at [%s:%d].\n",
		curproxy->id, bind_conf->ciphers, bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}

	/* If tune.ssl.default-dh-param has not been set,
	   neither has ssl-default-dh-file and no static DH
	   params were in the certificate file. */
	if (global.tune.ssl_default_dh_param == 0 &&
	    global_dh == NULL &&
	    (ssl_dh_ptr_index == -1 ||
	     SSL_CTX_get_ex_data(ctx, ssl_dh_ptr_index) == NULL)) {

		ssl = SSL_new(ctx);

		if (ssl) {
			ciphers = SSL_get_ciphers(ssl);

			if (ciphers) {
				for (idx = 0; idx < sk_SSL_CIPHER_num(ciphers); idx++) {
					cipher = sk_SSL_CIPHER_value(ciphers, idx);
					if (SSL_CIPHER_description(cipher, cipher_description, sizeof (cipher_description)) == cipher_description) {
						if (strstr(cipher_description, dhe_description) != NULL ||
						    strstr(cipher_description, dhe_export_description) != NULL) {
							dhe_found = 1;
							break;
						}
					}
				}
			}
			SSL_free(ssl);
			ssl = NULL;
		}

		if (dhe_found) {
			Warning("Setting tune.ssl.default-dh-param to 1024 by default, if your workload permits it you should set it to at least 2048. Please set a value >= 1024 to make this warning disappear.\n");
		}

		global.tune.ssl_default_dh_param = 1024;
	}

#ifndef OPENSSL_NO_DH
	if (global.tune.ssl_default_dh_param >= 1024) {
		if (local_dh_1024 == NULL) {
			local_dh_1024 = ssl_get_dh_1024();
		}
		if (global.tune.ssl_default_dh_param >= 2048) {
			if (local_dh_2048 == NULL) {
				local_dh_2048 = ssl_get_dh_2048();
			}
			if (global.tune.ssl_default_dh_param >= 4096) {
				if (local_dh_4096 == NULL) {
					local_dh_4096 = ssl_get_dh_4096();
				}
			}
		}
	}
#endif /* OPENSSL_NO_DH */

	SSL_CTX_set_info_callback(ctx, ssl_sock_infocbk);
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	SSL_CTX_set_msg_callback(ctx, ssl_sock_msgcbk);
#endif

#ifdef OPENSSL_NPN_NEGOTIATED
	if (bind_conf->npn_str)
		SSL_CTX_set_next_protos_advertised_cb(ctx, ssl_sock_advertise_npn_protos, bind_conf);
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	if (bind_conf->alpn_str)
		SSL_CTX_set_alpn_select_cb(ctx, ssl_sock_advertise_alpn_protos, bind_conf);
#endif

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
	SSL_CTX_set_tlsext_servername_arg(ctx, bind_conf);
#endif
#if defined(SSL_CTX_set_tmp_ecdh) && !defined(OPENSSL_NO_ECDH)
	{
		int i;
		EC_KEY  *ecdh;

		i = OBJ_sn2nid(bind_conf->ecdhe ? bind_conf->ecdhe : ECDHE_DEFAULT_CURVE);
		if (!i || ((ecdh = EC_KEY_new_by_curve_name(i)) == NULL)) {
			Alert("Proxy '%s': unable to set elliptic named curve to '%s' for bind '%s' at [%s:%d].\n",
			      curproxy->id, bind_conf->ecdhe ? bind_conf->ecdhe : ECDHE_DEFAULT_CURVE,
			      bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr++;
		}
		else {
			SSL_CTX_set_tmp_ecdh(ctx, ecdh);
			EC_KEY_free(ecdh);
		}
	}
#endif

	return cfgerr;
}

static int ssl_sock_srv_hostcheck(const char *pattern, const char *hostname)
{
	const char *pattern_wildcard, *pattern_left_label_end, *hostname_left_label_end;
	size_t prefixlen, suffixlen;

	/* Trivial case */
	if (strcmp(pattern, hostname) == 0)
		return 1;

	/* The rest of this logic is based on RFC 6125, section 6.4.3
	 * (http://tools.ietf.org/html/rfc6125#section-6.4.3) */

	pattern_wildcard = NULL;
	pattern_left_label_end = pattern;
	while (*pattern_left_label_end != '.') {
		switch (*pattern_left_label_end) {
			case 0:
				/* End of label not found */
				return 0;
			case '*':
				/* If there is more than one wildcards */
                                if (pattern_wildcard)
                                        return 0;
				pattern_wildcard = pattern_left_label_end;
				break;
		}
		pattern_left_label_end++;
	}

	/* If it's not trivial and there is no wildcard, it can't
	 * match */
	if (!pattern_wildcard)
		return 0;

	/* Make sure all labels match except the leftmost */
	hostname_left_label_end = strchr(hostname, '.');
	if (!hostname_left_label_end
	    || strcmp(pattern_left_label_end, hostname_left_label_end) != 0)
		return 0;

	/* Make sure the leftmost label of the hostname is long enough
	 * that the wildcard can match */
	if (hostname_left_label_end - hostname < (pattern_left_label_end - pattern) - 1)
		return 0;

	/* Finally compare the string on either side of the
	 * wildcard */
	prefixlen = pattern_wildcard - pattern;
	suffixlen = pattern_left_label_end - (pattern_wildcard + 1);
	if ((prefixlen && (memcmp(pattern, hostname, prefixlen) != 0))
	    || (suffixlen && (memcmp(pattern_wildcard + 1, hostname_left_label_end - suffixlen, suffixlen) != 0)))
		return 0;

	return 1;
}

static int ssl_sock_srv_verifycbk(int ok, X509_STORE_CTX *ctx)
{
	SSL *ssl;
	struct connection *conn;
	char *servername;

	int depth;
	X509 *cert;
	STACK_OF(GENERAL_NAME) *alt_names;
	int i;
	X509_NAME *cert_subject;
	char *str;

	if (ok == 0)
		return ok;

	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	conn = (struct connection *)SSL_get_app_data(ssl);

	servername = objt_server(conn->target)->ssl_ctx.verify_host;

	/* We only need to verify the CN on the actual server cert,
	 * not the indirect CAs */
	depth = X509_STORE_CTX_get_error_depth(ctx);
	if (depth != 0)
		return ok;

	/* At this point, the cert is *not* OK unless we can find a
	 * hostname match */
	ok = 0;

	cert = X509_STORE_CTX_get_current_cert(ctx);
	/* It seems like this might happen if verify peer isn't set */
	if (!cert)
		return ok;

	alt_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (alt_names) {
		for (i = 0; !ok && i < sk_GENERAL_NAME_num(alt_names); i++) {
			GENERAL_NAME *name = sk_GENERAL_NAME_value(alt_names, i);
			if (name->type == GEN_DNS) {
#if OPENSSL_VERSION_NUMBER < 0x00907000L
				if (ASN1_STRING_to_UTF8((unsigned char **)&str, name->d.ia5) >= 0) {
#else
				if (ASN1_STRING_to_UTF8((unsigned char **)&str, name->d.dNSName) >= 0) {
#endif
					ok = ssl_sock_srv_hostcheck(str, servername);
					OPENSSL_free(str);
				}
			}
		}
		sk_GENERAL_NAME_pop_free(alt_names, GENERAL_NAME_free);
	}

	cert_subject = X509_get_subject_name(cert);
	i = -1;
	while (!ok && (i = X509_NAME_get_index_by_NID(cert_subject, NID_commonName, i)) != -1) {
		X509_NAME_ENTRY *entry = X509_NAME_get_entry(cert_subject, i);
		if (ASN1_STRING_to_UTF8((unsigned char **)&str, entry->value) >= 0) {
			ok = ssl_sock_srv_hostcheck(str, servername);
			OPENSSL_free(str);
		}
	}

	return ok;
}

/* prepare ssl context from servers options. Returns an error count */
int ssl_sock_prepare_srv_ctx(struct server *srv, struct proxy *curproxy)
{
	int cfgerr = 0;
	long options =
		SSL_OP_ALL | /* all known workarounds for bugs */
		SSL_OP_NO_SSLv2 |
		SSL_OP_NO_COMPRESSION;
	long mode =
		SSL_MODE_ENABLE_PARTIAL_WRITE |
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
		SSL_MODE_RELEASE_BUFFERS |
		SSL_MODE_SMALL_BUFFERS;
	int verify = SSL_VERIFY_NONE;

	/* Make sure openssl opens /dev/urandom before the chroot */
	if (!ssl_initialize_random()) {
		Alert("OpenSSL random data generator initialization failed.\n");
		cfgerr++;
	}

	/* Automatic memory computations need to know we use SSL there */
	global.ssl_used_backend = 1;

	/* Initiate SSL context for current server */
	srv->ssl_ctx.reused_sess = NULL;
	if (srv->use_ssl)
		srv->xprt = &ssl_sock;
	if (srv->check.use_ssl)
		srv->check.xprt = &ssl_sock;

	srv->ssl_ctx.ctx = SSL_CTX_new(SSLv23_client_method());
	if (!srv->ssl_ctx.ctx) {
		Alert("config : %s '%s', server '%s': unable to allocate ssl context.\n",
		      proxy_type_str(curproxy), curproxy->id,
		      srv->id);
		cfgerr++;
		return cfgerr;
	}
	if (srv->ssl_ctx.client_crt) {
		if (SSL_CTX_use_PrivateKey_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt, SSL_FILETYPE_PEM) <= 0) {
			Alert("config : %s '%s', server '%s': unable to load SSL private key from PEM file '%s'.\n",
			      proxy_type_str(curproxy), curproxy->id,
			      srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
		else if (SSL_CTX_use_certificate_chain_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt) <= 0) {
			Alert("config : %s '%s', server '%s': unable to load ssl certificate from PEM file '%s'.\n",
			      proxy_type_str(curproxy), curproxy->id,
			      srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
		else if (SSL_CTX_check_private_key(srv->ssl_ctx.ctx) <= 0) {
			Alert("config : %s '%s', server '%s': inconsistencies between private key and certificate loaded from PEM file '%s'.\n",
			      proxy_type_str(curproxy), curproxy->id,
			      srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
	}

	if (srv->ssl_ctx.options & SRV_SSL_O_NO_SSLV3)
		options |= SSL_OP_NO_SSLv3;
	if (srv->ssl_ctx.options & SRV_SSL_O_NO_TLSV10)
		options |= SSL_OP_NO_TLSv1;
	if (srv->ssl_ctx.options & SRV_SSL_O_NO_TLSV11)
		options |= SSL_OP_NO_TLSv1_1;
	if (srv->ssl_ctx.options & SRV_SSL_O_NO_TLSV12)
		options |= SSL_OP_NO_TLSv1_2;
	if (srv->ssl_ctx.options & SRV_SSL_O_NO_TLS_TICKETS)
		options |= SSL_OP_NO_TICKET;
	if (srv->ssl_ctx.options & SRV_SSL_O_USE_SSLV3)
		SSL_CTX_set_ssl_version(srv->ssl_ctx.ctx, SSLv3_client_method());
	if (srv->ssl_ctx.options & SRV_SSL_O_USE_TLSV10)
		SSL_CTX_set_ssl_version(srv->ssl_ctx.ctx, TLSv1_client_method());
#if SSL_OP_NO_TLSv1_1
	if (srv->ssl_ctx.options & SRV_SSL_O_USE_TLSV11)
		SSL_CTX_set_ssl_version(srv->ssl_ctx.ctx, TLSv1_1_client_method());
#endif
#if SSL_OP_NO_TLSv1_2
	if (srv->ssl_ctx.options & SRV_SSL_O_USE_TLSV12)
		SSL_CTX_set_ssl_version(srv->ssl_ctx.ctx, TLSv1_2_client_method());
#endif

	SSL_CTX_set_options(srv->ssl_ctx.ctx, options);
	SSL_CTX_set_mode(srv->ssl_ctx.ctx, mode);

	if (global.ssl_server_verify == SSL_SERVER_VERIFY_REQUIRED)
		verify = SSL_VERIFY_PEER;

	switch (srv->ssl_ctx.verify) {
		case SSL_SOCK_VERIFY_NONE:
			verify = SSL_VERIFY_NONE;
			break;
		case SSL_SOCK_VERIFY_REQUIRED:
			verify = SSL_VERIFY_PEER;
			break;
	}
	SSL_CTX_set_verify(srv->ssl_ctx.ctx,
	                   verify,
	                   srv->ssl_ctx.verify_host ? ssl_sock_srv_verifycbk : NULL);
	if (verify & SSL_VERIFY_PEER) {
		if (srv->ssl_ctx.ca_file) {
			/* load CAfile to verify */
			if (!SSL_CTX_load_verify_locations(srv->ssl_ctx.ctx, srv->ssl_ctx.ca_file, NULL)) {
				Alert("Proxy '%s', server '%s' [%s:%d] unable to load CA file '%s'.\n",
				      curproxy->id, srv->id,
				      srv->conf.file, srv->conf.line, srv->ssl_ctx.ca_file);
				cfgerr++;
			}
		}
		else {
			if (global.ssl_server_verify == SSL_SERVER_VERIFY_REQUIRED)
				Alert("Proxy '%s', server '%s' [%s:%d] verify is enabled by default but no CA file specified. If you're running on a LAN where you're certain to trust the server's certificate, please set an explicit 'verify none' statement on the 'server' line, or use 'ssl-server-verify none' in the global section to disable server-side verifications by default.\n",
				      curproxy->id, srv->id,
				      srv->conf.file, srv->conf.line);
			else
				Alert("Proxy '%s', server '%s' [%s:%d] verify is enabled but no CA file specified.\n",
				      curproxy->id, srv->id,
				      srv->conf.file, srv->conf.line);
			cfgerr++;
		}
#ifdef X509_V_FLAG_CRL_CHECK
		if (srv->ssl_ctx.crl_file) {
			X509_STORE *store = SSL_CTX_get_cert_store(srv->ssl_ctx.ctx);

			if (!store || !X509_STORE_load_locations(store, srv->ssl_ctx.crl_file, NULL)) {
				Alert("Proxy '%s', server '%s' [%s:%d] unable to configure CRL file '%s'.\n",
				      curproxy->id, srv->id,
				      srv->conf.file, srv->conf.line, srv->ssl_ctx.crl_file);
				cfgerr++;
			}
			else {
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
			}
		}
#endif
	}

	if (global.tune.ssllifetime)
		SSL_CTX_set_timeout(srv->ssl_ctx.ctx, global.tune.ssllifetime);

	SSL_CTX_set_session_cache_mode(srv->ssl_ctx.ctx, SSL_SESS_CACHE_OFF);
	if (srv->ssl_ctx.ciphers &&
		!SSL_CTX_set_cipher_list(srv->ssl_ctx.ctx, srv->ssl_ctx.ciphers)) {
		Alert("Proxy '%s', server '%s' [%s:%d] : unable to set SSL cipher list to '%s'.\n",
		      curproxy->id, srv->id,
		      srv->conf.file, srv->conf.line, srv->ssl_ctx.ciphers);
		cfgerr++;
	}

	return cfgerr;
}

/* Walks down the two trees in bind_conf and prepares all certs. The pointer may
 * be NULL, in which case nothing is done. Returns the number of errors
 * encountered.
 */
int ssl_sock_prepare_all_ctx(struct bind_conf *bind_conf, struct proxy *px)
{
	struct ebmb_node *node;
	struct sni_ctx *sni;
	int err = 0;

	if (!bind_conf || !bind_conf->is_ssl)
		return 0;

	/* Automatic memory computations need to know we use SSL there */
	global.ssl_used_frontend = 1;

	if (bind_conf->default_ctx)
		err += ssl_sock_prepare_ctx(bind_conf, bind_conf->default_ctx, px);

	node = ebmb_first(&bind_conf->sni_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		if (!sni->order && sni->ctx != bind_conf->default_ctx)
			/* only initialize the CTX on its first occurrence and
			   if it is not the default_ctx */
			err += ssl_sock_prepare_ctx(bind_conf, sni->ctx, px);
		node = ebmb_next(node);
	}

	node = ebmb_first(&bind_conf->sni_w_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		if (!sni->order && sni->ctx != bind_conf->default_ctx)
			/* only initialize the CTX on its first occurrence and
			   if it is not the default_ctx */
			err += ssl_sock_prepare_ctx(bind_conf, sni->ctx, px);
		node = ebmb_next(node);
	}
	return err;
}

/* Walks down the two trees in bind_conf and frees all the certs. The pointer may
 * be NULL, in which case nothing is done. The default_ctx is nullified too.
 */
void ssl_sock_free_all_ctx(struct bind_conf *bind_conf)
{
	struct ebmb_node *node, *back;
	struct sni_ctx *sni;

	if (!bind_conf || !bind_conf->is_ssl)
		return;

	node = ebmb_first(&bind_conf->sni_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		back = ebmb_next(node);
		ebmb_delete(node);
		if (!sni->order) /* only free the CTX on its first occurrence */
			SSL_CTX_free(sni->ctx);
		free(sni);
		node = back;
	}

	node = ebmb_first(&bind_conf->sni_w_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		back = ebmb_next(node);
		ebmb_delete(node);
		if (!sni->order) /* only free the CTX on its first occurrence */
			SSL_CTX_free(sni->ctx);
		free(sni);
		node = back;
	}

	bind_conf->default_ctx = NULL;
}

/* Load CA cert file and private key used to generate certificates */
int
ssl_sock_load_ca(struct bind_conf *bind_conf, struct proxy *px)
{
	FILE     *fp;
	X509     *cacert = NULL;
	EVP_PKEY *capkey = NULL;
	int       err    = 0;

	if (!bind_conf || !bind_conf->generate_certs)
		return err;

	if (!bind_conf->ca_sign_file) {
		Alert("Proxy '%s': cannot enable certificate generation, "
		      "no CA certificate File configured at [%s:%d].\n",
		      px->id, bind_conf->file, bind_conf->line);
		err++;
	}

	if (err)
		goto load_error;

	/* read in the CA certificate */
	if (!(fp = fopen(bind_conf->ca_sign_file, "r"))) {
		Alert("Proxy '%s': Failed to read CA certificate file '%s' at [%s:%d].\n",
		      px->id, bind_conf->ca_sign_file, bind_conf->file, bind_conf->line);
		err++;
		goto load_error;
	}
	if (!(cacert = PEM_read_X509(fp, NULL, NULL, NULL))) {
		Alert("Proxy '%s': Failed to read CA certificate file '%s' at [%s:%d].\n",
		      px->id, bind_conf->ca_sign_file, bind_conf->file, bind_conf->line);
		fclose (fp);
		err++;
		goto load_error;
	}
	if (!(capkey = PEM_read_PrivateKey(fp, NULL, NULL, bind_conf->ca_sign_pass))) {
		Alert("Proxy '%s': Failed to read CA private key file '%s' at [%s:%d].\n",
		      px->id, bind_conf->ca_sign_file, bind_conf->file, bind_conf->line);
		fclose (fp);
		err++;
		goto load_error;
	}
	fclose (fp);

	bind_conf->ca_sign_cert = cacert;
	bind_conf->ca_sign_pkey = capkey;
	return err;

 load_error:
	bind_conf->generate_certs = 0;
	if (capkey) EVP_PKEY_free(capkey);
	if (cacert) X509_free(cacert);
	return err;
}

/* Release CA cert and private key used to generate certificated */
void
ssl_sock_free_ca(struct bind_conf *bind_conf)
{
	if (!bind_conf)
		return;

	if (bind_conf->ca_sign_pkey)
		EVP_PKEY_free(bind_conf->ca_sign_pkey);
	if (bind_conf->ca_sign_cert)
		X509_free(bind_conf->ca_sign_cert);
}

/*
 * This function is called if SSL * context is not yet allocated. The function
 * is designed to be called before any other data-layer operation and sets the
 * handshake flag on the connection. It is safe to call it multiple times.
 * It returns 0 on success and -1 in error case.
 */
static int ssl_sock_init(struct connection *conn)
{
	/* already initialized */
	if (conn->xprt_ctx)
		return 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (global.maxsslconn && sslconns >= global.maxsslconn) {
		conn->err_code = CO_ER_SSL_TOO_MANY;
		return -1;
	}

	/* If it is in client mode initiate SSL session
	   in connect state otherwise accept state */
	if (objt_server(conn->target)) {
		int may_retry = 1;

	retry_connect:
		/* Alloc a new SSL session ctx */
		conn->xprt_ctx = SSL_new(objt_server(conn->target)->ssl_ctx.ctx);
		if (!conn->xprt_ctx) {
			if (may_retry--) {
				pool_gc2();
				goto retry_connect;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			return -1;
		}

		/* set fd on SSL session context */
		if (!SSL_set_fd(conn->xprt_ctx, conn->t.sock.fd)) {
			SSL_free(conn->xprt_ctx);
			conn->xprt_ctx = NULL;
			if (may_retry--) {
				pool_gc2();
				goto retry_connect;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			return -1;
		}

		/* set connection pointer */
		if (!SSL_set_app_data(conn->xprt_ctx, conn)) {
			SSL_free(conn->xprt_ctx);
			conn->xprt_ctx = NULL;
			if (may_retry--) {
				pool_gc2();
				goto retry_connect;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			return -1;
		}

		SSL_set_connect_state(conn->xprt_ctx);
		if (objt_server(conn->target)->ssl_ctx.reused_sess) {
			if(!SSL_set_session(conn->xprt_ctx, objt_server(conn->target)->ssl_ctx.reused_sess)) {
				SSL_SESSION_free(objt_server(conn->target)->ssl_ctx.reused_sess);
				objt_server(conn->target)->ssl_ctx.reused_sess = NULL;
			}
		}

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;

		sslconns++;
		totalsslconns++;
		return 0;
	}
	else if (objt_listener(conn->target)) {
		int may_retry = 1;

	retry_accept:
		/* Alloc a new SSL session ctx */
		conn->xprt_ctx = SSL_new(objt_listener(conn->target)->bind_conf->default_ctx);
		if (!conn->xprt_ctx) {
			if (may_retry--) {
				pool_gc2();
				goto retry_accept;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			return -1;
		}

		/* set fd on SSL session context */
		if (!SSL_set_fd(conn->xprt_ctx, conn->t.sock.fd)) {
			SSL_free(conn->xprt_ctx);
			conn->xprt_ctx = NULL;
			if (may_retry--) {
				pool_gc2();
				goto retry_accept;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			return -1;
		}

		/* set connection pointer */
		if (!SSL_set_app_data(conn->xprt_ctx, conn)) {
			SSL_free(conn->xprt_ctx);
			conn->xprt_ctx = NULL;
			if (may_retry--) {
				pool_gc2();
				goto retry_accept;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			return -1;
		}

		SSL_set_accept_state(conn->xprt_ctx);

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;

		sslconns++;
		totalsslconns++;
		return 0;
	}
	/* don't know how to handle such a target */
	conn->err_code = CO_ER_SSL_NO_TARGET;
	return -1;
}


/* This is the callback which is used when an SSL handshake is pending. It
 * updates the FD status if it wants some polling before being called again.
 * It returns 0 if it fails in a fatal way or needs to poll to go further,
 * otherwise it returns non-zero and removes itself from the connection's
 * flags (the bit is provided in <flag> by the caller).
 */
int ssl_sock_handshake(struct connection *conn, unsigned int flag)
{
	int ret;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!conn->xprt_ctx)
		goto out_error;

	/* If we use SSL_do_handshake to process a reneg initiated by
	 * the remote peer, it sometimes returns SSL_ERROR_SSL.
	 * Usually SSL_write and SSL_read are used and process implicitly
	 * the reneg handshake.
	 * Here we use SSL_peek as a workaround for reneg.
	 */
	if ((conn->flags & CO_FL_CONNECTED) && SSL_renegotiate_pending(conn->xprt_ctx)) {
		char c;

		ret = SSL_peek(conn->xprt_ctx, &c, 1);
		if (ret <= 0) {
			/* handshake may have not been completed, let's find why */
			ret = SSL_get_error(conn->xprt_ctx, ret);
			if (ret == SSL_ERROR_WANT_WRITE) {
				/* SSL handshake needs to write, L4 connection may not be ready */
				__conn_sock_stop_recv(conn);
				__conn_sock_want_send(conn);
				fd_cant_send(conn->t.sock.fd);
				return 0;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				/* handshake may have been completed but we have
				 * no more data to read.
                                 */
				if (!SSL_renegotiate_pending(conn->xprt_ctx)) {
					ret = 1;
					goto reneg_ok;
				}
				/* SSL handshake needs to read, L4 connection is ready */
				if (conn->flags & CO_FL_WAIT_L4_CONN)
					conn->flags &= ~CO_FL_WAIT_L4_CONN;
				__conn_sock_stop_send(conn);
				__conn_sock_want_recv(conn);
				fd_cant_recv(conn->t.sock.fd);
				return 0;
			}
			else if (ret == SSL_ERROR_SYSCALL) {
				/* if errno is null, then connection was successfully established */
				if (!errno && conn->flags & CO_FL_WAIT_L4_CONN)
					conn->flags &= ~CO_FL_WAIT_L4_CONN;
				if (!conn->err_code) {
					if (!((SSL *)conn->xprt_ctx)->packet_length) {
						if (!errno) {
							if (conn->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
								conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
							else
								conn->err_code = CO_ER_SSL_EMPTY;
						}
						else {
							if (conn->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
								conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
							else
								conn->err_code = CO_ER_SSL_ABORT;
						}
					}
					else {
						if (conn->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
							conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
						else
							conn->err_code = CO_ER_SSL_HANDSHAKE;
					}
				}
				goto out_error;
			}
			else {
				/* Fail on all other handshake errors */
				/* Note: OpenSSL may leave unread bytes in the socket's
				 * buffer, causing an RST to be emitted upon close() on
				 * TCP sockets. We first try to drain possibly pending
				 * data to avoid this as much as possible.
				 */
				conn_sock_drain(conn);
				if (!conn->err_code)
					conn->err_code = (conn->xprt_st & SSL_SOCK_RECV_HEARTBEAT) ?
						CO_ER_SSL_KILLED_HB : CO_ER_SSL_HANDSHAKE;
				goto out_error;
			}
		}
		/* read some data: consider handshake completed */
		goto reneg_ok;
	}

	ret = SSL_do_handshake(conn->xprt_ctx);
	if (ret != 1) {
		/* handshake did not complete, let's find why */
		ret = SSL_get_error(conn->xprt_ctx, ret);

		if (ret == SSL_ERROR_WANT_WRITE) {
			/* SSL handshake needs to write, L4 connection may not be ready */
			__conn_sock_stop_recv(conn);
			__conn_sock_want_send(conn);
			fd_cant_send(conn->t.sock.fd);
			return 0;
		}
		else if (ret == SSL_ERROR_WANT_READ) {
			/* SSL handshake needs to read, L4 connection is ready */
			if (conn->flags & CO_FL_WAIT_L4_CONN)
				conn->flags &= ~CO_FL_WAIT_L4_CONN;
			__conn_sock_stop_send(conn);
			__conn_sock_want_recv(conn);
			fd_cant_recv(conn->t.sock.fd);
			return 0;
		}
		else if (ret == SSL_ERROR_SYSCALL) {
			/* if errno is null, then connection was successfully established */
			if (!errno && conn->flags & CO_FL_WAIT_L4_CONN)
				conn->flags &= ~CO_FL_WAIT_L4_CONN;

			if (!((SSL *)conn->xprt_ctx)->packet_length) {
				if (!errno) {
					if (conn->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
						conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
					else
						conn->err_code = CO_ER_SSL_EMPTY;
				}
				else {
					if (conn->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
						conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
					else
						conn->err_code = CO_ER_SSL_ABORT;
				}
			}
			else {
				if (conn->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
					conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
				else
					conn->err_code = CO_ER_SSL_HANDSHAKE;
			}
			goto out_error;
		}
		else {
			/* Fail on all other handshake errors */
			/* Note: OpenSSL may leave unread bytes in the socket's
			 * buffer, causing an RST to be emitted upon close() on
			 * TCP sockets. We first try to drain possibly pending
			 * data to avoid this as much as possible.
			 */
			conn_sock_drain(conn);
			if (!conn->err_code)
				conn->err_code = (conn->xprt_st & SSL_SOCK_RECV_HEARTBEAT) ?
					CO_ER_SSL_KILLED_HB : CO_ER_SSL_HANDSHAKE;
			goto out_error;
		}
	}

reneg_ok:

	/* Handshake succeeded */
	if (!SSL_session_reused(conn->xprt_ctx)) {
		if (objt_server(conn->target)) {
			update_freq_ctr(&global.ssl_be_keys_per_sec, 1);
			if (global.ssl_be_keys_per_sec.curr_ctr > global.ssl_be_keys_max)
				global.ssl_be_keys_max = global.ssl_be_keys_per_sec.curr_ctr;

			/* check if session was reused, if not store current session on server for reuse */
			if (objt_server(conn->target)->ssl_ctx.reused_sess)
				SSL_SESSION_free(objt_server(conn->target)->ssl_ctx.reused_sess);

			if (!(objt_server(conn->target)->ssl_ctx.options & SRV_SSL_O_NO_REUSE))
				objt_server(conn->target)->ssl_ctx.reused_sess = SSL_get1_session(conn->xprt_ctx);
		}
		else {
			update_freq_ctr(&global.ssl_fe_keys_per_sec, 1);
			if (global.ssl_fe_keys_per_sec.curr_ctr > global.ssl_fe_keys_max)
				global.ssl_fe_keys_max = global.ssl_fe_keys_per_sec.curr_ctr;
		}
	}

	/* The connection is now established at both layers, it's time to leave */
	conn->flags &= ~(flag | CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN);
	return 1;

 out_error:
	/* Clear openssl global errors stack */
	ERR_clear_error();

	/* free resumed session if exists */
	if (objt_server(conn->target) && objt_server(conn->target)->ssl_ctx.reused_sess) {
		SSL_SESSION_free(objt_server(conn->target)->ssl_ctx.reused_sess);
		objt_server(conn->target)->ssl_ctx.reused_sess = NULL;
	}

	/* Fail on all other handshake errors */
	conn->flags |= CO_FL_ERROR;
	if (!conn->err_code)
		conn->err_code = CO_ER_SSL_HANDSHAKE;
	return 0;
}

/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 */
static int ssl_sock_to_buf(struct connection *conn, struct buffer *buf, int count)
{
	int ret, done = 0;
	int try;

	if (!conn->xprt_ctx)
		goto out_error;

	if (conn->flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return 0;

	/* let's realign the buffer to optimize I/O */
	if (buffer_empty(buf))
		buf->p = buf->data;

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {
		/* first check if we have some room after p+i */
		try = buf->data + buf->size - (buf->p + buf->i);
		/* otherwise continue between data and p-o */
		if (try <= 0) {
			try = buf->p - (buf->data + buf->o);
			if (try <= 0)
				break;
		}
		if (try > count)
			try = count;

		ret = SSL_read(conn->xprt_ctx, bi_end(buf), try);
		if (conn->flags & CO_FL_ERROR) {
			/* CO_FL_ERROR may be set by ssl_sock_infocbk */
			goto out_error;
		}
		if (ret > 0) {
			buf->i += ret;
			done += ret;
			if (ret < try)
				break;
			count -= ret;
		}
		else if (ret == 0) {
			ret =  SSL_get_error(conn->xprt_ctx, ret);
			if (ret != SSL_ERROR_ZERO_RETURN) {
				/* error on protocol or underlying transport */
				if ((ret != SSL_ERROR_SYSCALL)
				     || (errno && (errno != EAGAIN)))
					conn->flags |= CO_FL_ERROR;

				/* Clear openssl global errors stack */
				ERR_clear_error();
			}
			goto read0;
		}
		else {
			ret =  SSL_get_error(conn->xprt_ctx, ret);
			if (ret == SSL_ERROR_WANT_WRITE) {
				/* handshake is running, and it needs to enable write */
				conn->flags |= CO_FL_SSL_WAIT_HS;
				__conn_sock_want_send(conn);
				break;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				if (SSL_renegotiate_pending(conn->xprt_ctx)) {
					/* handshake is running, and it may need to re-enable read */
					conn->flags |= CO_FL_SSL_WAIT_HS;
					__conn_sock_want_recv(conn);
					break;
				}
				/* we need to poll for retry a read later */
				fd_cant_recv(conn->t.sock.fd);
				break;
			}
			/* otherwise it's a real error */
			goto out_error;
		}
	}
	return done;

 read0:
	conn_sock_read0(conn);
	return done;
 out_error:
	/* Clear openssl global errors stack */
	ERR_clear_error();

	conn->flags |= CO_FL_ERROR;
	return done;
}


/* Send all pending bytes from buffer <buf> to connection <conn>'s socket.
 * <flags> may contain some CO_SFL_* flags to hint the system about other
 * pending data for example, but this flag is ignored at the moment.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this.
 */
static int ssl_sock_from_buf(struct connection *conn, struct buffer *buf, int flags)
{
	int ret, try, done;

	done = 0;

	if (!conn->xprt_ctx)
		goto out_error;

	if (conn->flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return 0;

	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (buf->o) {
		try = bo_contig_data(buf);

		if (!(flags & CO_SFL_STREAMER) &&
		    !(conn->xprt_st & SSL_SOCK_SEND_UNLIMITED) &&
		    global.tune.ssl_max_record && try > global.tune.ssl_max_record) {
			try = global.tune.ssl_max_record;
		}
		else {
			/* we need to keep the information about the fact that
			 * we're not limiting the upcoming send(), because if it
			 * fails, we'll have to retry with at least as many data.
			 */
			conn->xprt_st |= SSL_SOCK_SEND_UNLIMITED;
		}

		ret = SSL_write(conn->xprt_ctx, bo_ptr(buf), try);

		if (conn->flags & CO_FL_ERROR) {
			/* CO_FL_ERROR may be set by ssl_sock_infocbk */
			goto out_error;
		}
		if (ret > 0) {
			conn->xprt_st &= ~SSL_SOCK_SEND_UNLIMITED;

			buf->o -= ret;
			done += ret;

			if (likely(buffer_empty(buf)))
				/* optimize data alignment in the buffer */
				buf->p = buf->data;

			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else {
			ret = SSL_get_error(conn->xprt_ctx, ret);
			if (ret == SSL_ERROR_WANT_WRITE) {
				if (SSL_renegotiate_pending(conn->xprt_ctx)) {
					/* handshake is running, and it may need to re-enable write */
					conn->flags |= CO_FL_SSL_WAIT_HS;
					__conn_sock_want_send(conn);
					break;
				}
				/* we need to poll to retry a write later */
				fd_cant_send(conn->t.sock.fd);
				break;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				/* handshake is running, and it needs to enable read */
				conn->flags |= CO_FL_SSL_WAIT_HS;
				__conn_sock_want_recv(conn);
				break;
			}
			goto out_error;
		}
	}
	return done;

 out_error:
	/* Clear openssl global errors stack */
	ERR_clear_error();

	conn->flags |= CO_FL_ERROR;
	return done;
}

static void ssl_sock_close(struct connection *conn) {

	if (conn->xprt_ctx) {
		SSL_free(conn->xprt_ctx);
		conn->xprt_ctx = NULL;
		sslconns--;
	}
}

/* This function tries to perform a clean shutdown on an SSL connection, and in
 * any case, flags the connection as reusable if no handshake was in progress.
 */
static void ssl_sock_shutw(struct connection *conn, int clean)
{
	if (conn->flags & CO_FL_HANDSHAKE)
		return;
	/* no handshake was in progress, try a clean ssl shutdown */
	if (clean && (SSL_shutdown(conn->xprt_ctx) <= 0)) {
		/* Clear openssl global errors stack */
		ERR_clear_error();
	}

	/* force flag on ssl to keep session in cache regardless shutdown result */
	SSL_set_shutdown(conn->xprt_ctx, SSL_SENT_SHUTDOWN);
}

/* used for logging, may be changed for a sample fetch later */
const char *ssl_sock_get_cipher_name(struct connection *conn)
{
	if (!conn->xprt && !conn->xprt_ctx)
		return NULL;
	return SSL_get_cipher_name(conn->xprt_ctx);
}

/* used for logging, may be changed for a sample fetch later */
const char *ssl_sock_get_proto_version(struct connection *conn)
{
	if (!conn->xprt && !conn->xprt_ctx)
		return NULL;
	return SSL_get_version(conn->xprt_ctx);
}

/* Extract a serial from a cert, and copy it to a chunk.
 * Returns 1 if serial is found and copied, 0 if no serial found and
 * -1 if output is not large enough.
 */
static int
ssl_sock_get_serial(X509 *crt, struct chunk *out)
{
	ASN1_INTEGER *serial;

	serial = X509_get_serialNumber(crt);
	if (!serial)
		return 0;

	if (out->size < serial->length)
		return -1;

	memcpy(out->str, serial->data, serial->length);
	out->len = serial->length;
	return 1;
}

/* Extract a cert to der, and copy it to a chunk.
 * Returns 1 if cert is found and copied, 0 on der convertion failure and
 * -1 if output is not large enough.
 */
static int
ssl_sock_crt2der(X509 *crt, struct chunk *out)
{
	int len;
	unsigned char *p = (unsigned char *)out->str;;

	len =i2d_X509(crt, NULL);
	if (len <= 0)
		return 1;

	if (out->size < len)
		return -1;

	i2d_X509(crt,&p);
	out->len = len;
	return 1;
}


/* Copy Date in ASN1_UTCTIME format in struct chunk out.
 * Returns 1 if serial is found and copied, 0 if no valid time found
 * and -1 if output is not large enough.
 */
static int
ssl_sock_get_time(ASN1_TIME *tm, struct chunk *out)
{
	if (tm->type == V_ASN1_GENERALIZEDTIME) {
		ASN1_GENERALIZEDTIME *gentm = (ASN1_GENERALIZEDTIME *)tm;

		if (gentm->length < 12)
			return 0;
		if (gentm->data[0] != 0x32 || gentm->data[1] != 0x30)
			return 0;
		if (out->size < gentm->length-2)
			return -1;

		memcpy(out->str, gentm->data+2, gentm->length-2);
		out->len = gentm->length-2;
		return 1;
	}
	else if (tm->type == V_ASN1_UTCTIME) {
		ASN1_UTCTIME *utctm = (ASN1_UTCTIME *)tm;

		if (utctm->length < 10)
			return 0;
		if (utctm->data[0] >= 0x35)
			return 0;
		if (out->size < utctm->length)
			return -1;

		memcpy(out->str, utctm->data, utctm->length);
		out->len = utctm->length;
		return 1;
	}

	return 0;
}

/* Extract an entry from a X509_NAME and copy its value to an output chunk.
 * Returns 1 if entry found, 0 if entry not found, or -1 if output not large enough.
 */
static int
ssl_sock_get_dn_entry(X509_NAME *a, const struct chunk *entry, int pos, struct chunk *out)
{
	X509_NAME_ENTRY *ne;
	int i, j, n;
	int cur = 0;
	const char *s;
	char tmp[128];

	out->len = 0;
	for (i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++) {
		if (pos < 0)
			j = (sk_X509_NAME_ENTRY_num(a->entries)-1) - i;
		else
			j = i;

		ne = sk_X509_NAME_ENTRY_value(a->entries, j);
		n = OBJ_obj2nid(ne->object);
		if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL)) {
			i2t_ASN1_OBJECT(tmp, sizeof(tmp), ne->object);
			s = tmp;
		}

		if (chunk_strcasecmp(entry, s) != 0)
			continue;

		if (pos < 0)
			cur--;
		else
			cur++;

		if (cur != pos)
			continue;

		if (ne->value->length > out->size)
			return -1;

		memcpy(out->str, ne->value->data, ne->value->length);
		out->len = ne->value->length;
		return 1;
	}

	return 0;

}

/* Extract and format full DN from a X509_NAME and copy result into a chunk
 * Returns 1 if dn entries exits, 0 if no dn entry found or -1 if output is not large enough.
 */
static int
ssl_sock_get_dn_oneline(X509_NAME *a, struct chunk *out)
{
	X509_NAME_ENTRY *ne;
	int i, n, ln;
	int l = 0;
	const char *s;
	char *p;
	char tmp[128];

	out->len = 0;
	p = out->str;
	for (i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++) {
		ne = sk_X509_NAME_ENTRY_value(a->entries, i);
		n = OBJ_obj2nid(ne->object);
		if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL)) {
			i2t_ASN1_OBJECT(tmp, sizeof(tmp), ne->object);
			s = tmp;
		}
		ln = strlen(s);

		l += 1 + ln + 1 + ne->value->length;
		if (l > out->size)
			return -1;
		out->len = l;

		*(p++)='/';
		memcpy(p, s, ln);
		p += ln;
		*(p++)='=';
		memcpy(p, ne->value->data, ne->value->length);
		p += ne->value->length;
	}

	if (!out->len)
		return 0;

	return 1;
}

char *ssl_sock_get_version(struct connection *conn)
{
	if (!ssl_sock_is_ssl(conn))
		return NULL;

	return (char *)SSL_get_version(conn->xprt_ctx);
}

void ssl_sock_set_servername(struct connection *conn, const char *hostname)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	if (!ssl_sock_is_ssl(conn))
		return;

	SSL_set_tlsext_host_name(conn->xprt_ctx, hostname);
#endif
}

/* Extract peer certificate's common name into the chunk dest
 * Returns
 *  the len of the extracted common name
 *  or 0 if no CN found in DN
 *  or -1 on error case (i.e. no peer certificate)
 */
int ssl_sock_get_remote_common_name(struct connection *conn, struct chunk *dest)
{
	X509 *crt = NULL;
	X509_NAME *name;
	const char find_cn[] = "CN";
	const struct chunk find_cn_chunk = {
		.str = (char *)&find_cn,
		.len = sizeof(find_cn)-1
	};
	int result = -1;

	if (!ssl_sock_is_ssl(conn))
		goto out;

	/* SSL_get_peer_certificate, it increase X509 * ref count */
	crt = SSL_get_peer_certificate(conn->xprt_ctx);
	if (!crt)
		goto out;

	name = X509_get_subject_name(crt);
	if (!name)
		goto out;

	result = ssl_sock_get_dn_entry(name, &find_cn_chunk, 1, dest);
out:
	if (crt)
		X509_free(crt);

	return result;
}

/* returns 1 if client passed a certificate for this session, 0 if not */
int ssl_sock_get_cert_used_sess(struct connection *conn)
{
	X509 *crt = NULL;

	if (!ssl_sock_is_ssl(conn))
		return 0;

	/* SSL_get_peer_certificate, it increase X509 * ref count */
	crt = SSL_get_peer_certificate(conn->xprt_ctx);
	if (!crt)
		return 0;

	X509_free(crt);
	return 1;
}

/* returns 1 if client passed a certificate for this connection, 0 if not */
int ssl_sock_get_cert_used_conn(struct connection *conn)
{
	if (!ssl_sock_is_ssl(conn))
		return 0;

	return SSL_SOCK_ST_FL_VERIFY_DONE & conn->xprt_st ? 1 : 0;
}

/* returns result from SSL verify */
unsigned int ssl_sock_get_verify_result(struct connection *conn)
{
	if (!ssl_sock_is_ssl(conn))
		return (unsigned int)X509_V_ERR_APPLICATION_VERIFICATION;

	return (unsigned int)SSL_get_verify_result(conn->xprt_ctx);
}

/***** Below are some sample fetching functions for ACL/patterns *****/

/* boolean, returns true if client cert was present */
static int
smp_fetch_ssl_fc_has_crt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->flags = 0;
	smp->type = SMP_T_BOOL;
	smp->data.uint = SSL_SOCK_ST_FL_VERIFY_DONE & conn->xprt_st ? 1 : 0;

	return 1;
}

/* binary, returns a certificate in a binary chunk (der/raw).
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_der(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt = NULL;
	int ret = 0;
	struct chunk *smp_trash;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);

	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_crt2der(crt, smp_trash) <= 0)
		goto out;

	smp->data.str = *smp_trash;
	smp->type = SMP_T_BIN;
	ret = 1;
out:
	/* SSL_get_peer_certificate, it increase X509 * ref count */
	if (cert_peer && crt)
		X509_free(crt);
	return ret;
}

/* binary, returns serial of certificate in a binary chunk.
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_serial(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt = NULL;
	int ret = 0;
	struct chunk *smp_trash;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);

	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_get_serial(crt, smp_trash) <= 0)
		goto out;

	smp->data.str = *smp_trash;
	smp->type = SMP_T_BIN;
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
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt = NULL;
	const EVP_MD *digest;
	int ret = 0;
	struct chunk *smp_trash;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);
	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	digest = EVP_sha1();
	X509_digest(crt, digest, (unsigned char *)smp_trash->str, (unsigned int *)&smp_trash->len);

	smp->data.str = *smp_trash;
	smp->type = SMP_T_BIN;
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
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt = NULL;
	int ret = 0;
	struct chunk *smp_trash;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);
	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_get_time(X509_get_notAfter(crt), smp_trash) <= 0)
		goto out;

	smp->data.str = *smp_trash;
	smp->type = SMP_T_STR;
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
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt = NULL;
	X509_NAME *name;
	int ret = 0;
	struct chunk *smp_trash;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);
	if (!crt)
		goto out;

	name = X509_get_issuer_name(crt);
	if (!name)
		goto out;

	smp_trash = get_trash_chunk();
	if (args && args[0].type == ARGT_STR) {
		int pos = 1;

		if (args[1].type == ARGT_SINT)
			pos = args[1].data.sint;
		else if (args[1].type == ARGT_UINT)
			pos =(int)args[1].data.uint;

		if (ssl_sock_get_dn_entry(name, &args[0].data.str, pos, smp_trash) <= 0)
			goto out;
	}
	else if (ssl_sock_get_dn_oneline(name, smp_trash) <= 0)
		goto out;

	smp->type = SMP_T_STR;
	smp->data.str = *smp_trash;
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
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt = NULL;
	int ret = 0;
	struct chunk *smp_trash;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);
	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_get_time(X509_get_notBefore(crt), smp_trash) <= 0)
		goto out;

	smp->data.str = *smp_trash;
	smp->type = SMP_T_STR;
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
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt = NULL;
	X509_NAME *name;
	int ret = 0;
	struct chunk *smp_trash;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);
	if (!crt)
		goto out;

	name = X509_get_subject_name(crt);
	if (!name)
		goto out;

	smp_trash = get_trash_chunk();
	if (args && args[0].type == ARGT_STR) {
		int pos = 1;

		if (args[1].type == ARGT_SINT)
			pos = args[1].data.sint;
		else if (args[1].type == ARGT_UINT)
			pos =(int)args[1].data.uint;

		if (ssl_sock_get_dn_entry(name, &args[0].data.str, pos, smp_trash) <= 0)
			goto out;
	}
	else if (ssl_sock_get_dn_oneline(name, smp_trash) <= 0)
		goto out;

	smp->type = SMP_T_STR;
	smp->data.str = *smp_trash;
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

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	/* SSL_get_peer_certificate returns a ptr on allocated X509 struct */
	crt = SSL_get_peer_certificate(conn->xprt_ctx);
	if (crt) {
		X509_free(crt);
	}

	smp->type = SMP_T_BOOL;
	smp->data.uint = (crt != NULL);
	return 1;
}

/* integer, returns the certificate version
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_version(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);
	if (!crt)
		return 0;

	smp->data.uint = (unsigned int)(1 + X509_get_version(crt));
	/* SSL_get_peer_certificate increase X509 * ref count  */
	if (cert_peer)
		X509_free(crt);
	smp->type = SMP_T_UINT;

	return 1;
}

/* string, returns the certificate's signature algorithm.
 * The 5th keyword char is used to know if SSL_get_certificate or SSL_get_peer_certificate
 * should be use.
 */
static int
smp_fetch_ssl_x_sig_alg(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt;
	int nid;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);
	if (!crt)
		return 0;

	nid = OBJ_obj2nid((ASN1_OBJECT *)(crt->cert_info->signature->algorithm));

	smp->data.str.str = (char *)OBJ_nid2sn(nid);
	if (!smp->data.str.str) {
		/* SSL_get_peer_certificate increase X509 * ref count  */
		if (cert_peer)
			X509_free(crt);
		return 0;
	}

	smp->type = SMP_T_STR;
	smp->flags |= SMP_F_CONST;
	smp->data.str.len = strlen(smp->data.str.str);
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
	int cert_peer = (kw[4] == 'c') ? 1 : 0;
	X509 *crt;
	int nid;
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(conn->xprt_ctx);
	else
		crt = SSL_get_certificate(conn->xprt_ctx);
	if (!crt)
		return 0;

	nid = OBJ_obj2nid((ASN1_OBJECT *)(crt->cert_info->key->algor->algorithm));

	smp->data.str.str = (char *)OBJ_nid2sn(nid);
	if (!smp->data.str.str) {
		/* SSL_get_peer_certificate increase X509 * ref count  */
		if (cert_peer)
			X509_free(crt);
		return 0;
	}

	smp->type = SMP_T_STR;
	smp->flags |= SMP_F_CONST;
	smp->data.str.len = strlen(smp->data.str.str);
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
	int back_conn = (kw[4] == 'b') ? 1 : 0;
	struct connection *conn = objt_conn(smp->strm->si[back_conn].end);

	smp->type = SMP_T_BOOL;
	smp->data.uint = (conn && conn->xprt == &ssl_sock);
	return 1;
}

/* boolean, returns true if client present a SNI */
static int
smp_fetch_ssl_fc_has_sni(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	struct connection *conn = objt_conn(smp->sess->origin);

	smp->type = SMP_T_BOOL;
	smp->data.uint = (conn && conn->xprt == &ssl_sock) &&
		conn->xprt_ctx &&
		SSL_get_servername(conn->xprt_ctx, TLSEXT_NAMETYPE_host_name) != NULL;
	return 1;
#else
	return 0;
#endif
}

/* boolean, returns true if client session has been resumed */
static int
smp_fetch_ssl_fc_is_resumed(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = objt_conn(smp->sess->origin);

	smp->type = SMP_T_BOOL;
	smp->data.uint = (conn && conn->xprt == &ssl_sock) &&
		conn->xprt_ctx &&
		SSL_session_reused(conn->xprt_ctx);
	return 1;
}

/* string, returns the used cipher if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_cipher(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int back_conn = (kw[4] == 'b') ? 1 : 0;
	struct connection *conn;

	smp->flags = 0;

	conn = objt_conn(smp->strm->si[back_conn].end);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;

	smp->data.str.str = (char *)SSL_get_cipher_name(conn->xprt_ctx);
	if (!smp->data.str.str)
		return 0;

	smp->type = SMP_T_STR;
	smp->flags |= SMP_F_CONST;
	smp->data.str.len = strlen(smp->data.str.str);

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
	int back_conn = (kw[4] == 'b') ? 1 : 0;
	struct connection *conn;

	smp->flags = 0;

	conn = objt_conn(smp->strm->si[back_conn].end);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;

	if (!SSL_get_cipher_bits(conn->xprt_ctx, (int *)&smp->data.uint))
		return 0;

	smp->type = SMP_T_UINT;

	return 1;
}

/* integer, returns the used keysize if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_use_keysize(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	int back_conn = (kw[4] == 'b') ? 1 : 0;
	struct connection *conn;

	smp->flags = 0;

	conn = objt_conn(smp->strm->si[back_conn].end);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;

	smp->data.uint = (unsigned int)SSL_get_cipher_bits(conn->xprt_ctx, NULL);
	if (!smp->data.uint)
		return 0;

	smp->type = SMP_T_UINT;

	return 1;
}

#ifdef OPENSSL_NPN_NEGOTIATED
static int
smp_fetch_ssl_fc_npn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	smp->flags = SMP_F_CONST;
	smp->type = SMP_T_STR;

	conn = objt_conn(smp->sess->origin);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;

	smp->data.str.str = NULL;
	SSL_get0_next_proto_negotiated(conn->xprt_ctx,
	                                (const unsigned char **)&smp->data.str.str, (unsigned *)&smp->data.str.len);

	if (!smp->data.str.str)
		return 0;

	return 1;
}
#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int
smp_fetch_ssl_fc_alpn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	smp->flags = SMP_F_CONST;
	smp->type = SMP_T_STR;

	conn = objt_conn(smp->sess->origin);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;

	smp->data.str.str = NULL;
	SSL_get0_alpn_selected(conn->xprt_ctx,
	                         (const unsigned char **)&smp->data.str.str, (unsigned *)&smp->data.str.len);

	if (!smp->data.str.str)
		return 0;

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
	int back_conn = (kw[4] == 'b') ? 1 : 0;
	struct connection *conn;

	smp->flags = 0;

	conn = objt_conn(smp->strm->si[back_conn].end);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;

	smp->data.str.str = (char *)SSL_get_version(conn->xprt_ctx);
	if (!smp->data.str.str)
		return 0;

	smp->type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.str.len = strlen(smp->data.str.str);

	return 1;
}

/* binary, returns the SSL stream id if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_session_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
#if OPENSSL_VERSION_NUMBER > 0x0090800fL
	int back_conn = (kw[4] == 'b') ? 1 : 0;
	SSL_SESSION *ssl_sess;
	struct connection *conn;

	smp->flags = SMP_F_CONST;
	smp->type = SMP_T_BIN;

	conn = objt_conn(smp->strm->si[back_conn].end);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;

	ssl_sess = SSL_get_session(conn->xprt_ctx);
	if (!ssl_sess)
		return 0;

	smp->data.str.str = (char *)SSL_SESSION_get_id(ssl_sess, (unsigned int *)&smp->data.str.len);
	if (!smp->data.str.str || !smp->data.str.len)
		return 0;

	return 1;
#else
	return 0;
#endif
}

static int
smp_fetch_ssl_fc_sni(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	struct connection *conn;

	smp->flags = SMP_F_CONST;
	smp->type = SMP_T_STR;

	conn = objt_conn(smp->sess->origin);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;

	smp->data.str.str = (char *)SSL_get_servername(conn->xprt_ctx, TLSEXT_NAMETYPE_host_name);
	if (!smp->data.str.str)
		return 0;

	smp->data.str.len = strlen(smp->data.str.str);
	return 1;
#else
	return 0;
#endif
}

static int
smp_fetch_ssl_fc_unique_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
#if OPENSSL_VERSION_NUMBER > 0x0090800fL
	int back_conn = (kw[4] == 'b') ? 1 : 0;
	struct connection *conn;
	int finished_len;
	struct chunk *finished_trash;

	smp->flags = 0;

	conn = objt_conn(smp->strm->si[back_conn].end);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	finished_trash = get_trash_chunk();
	if (!SSL_session_reused(conn->xprt_ctx))
		finished_len = SSL_get_peer_finished(conn->xprt_ctx, finished_trash->str, finished_trash->size);
	else
		finished_len = SSL_get_finished(conn->xprt_ctx, finished_trash->str, finished_trash->size);

	if (!finished_len)
		return 0;

	finished_trash->len = finished_len;
	smp->data.str = *finished_trash;
	smp->type = SMP_T_BIN;

	return 1;
#else
	return 0;
#endif
}

/* integer, returns the first verify error in CA chain of client certificate chain. */
static int
smp_fetch_ssl_c_ca_err(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->type = SMP_T_UINT;
	smp->data.uint = (unsigned int)SSL_SOCK_ST_TO_CA_ERROR(conn->xprt_st);
	smp->flags = 0;

	return 1;
}

/* integer, returns the depth of the first verify error in CA chain of client certificate chain. */
static int
smp_fetch_ssl_c_ca_err_depth(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->type = SMP_T_UINT;
	smp->data.uint = (unsigned int)SSL_SOCK_ST_TO_CAEDEPTH(conn->xprt_st);
	smp->flags = 0;

	return 1;
}

/* integer, returns the first verify error on client certificate */
static int
smp_fetch_ssl_c_err(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->type = SMP_T_UINT;
	smp->data.uint = (unsigned int)SSL_SOCK_ST_TO_CRTERROR(conn->xprt_st);
	smp->flags = 0;

	return 1;
}

/* integer, returns the verify result on client cert */
static int
smp_fetch_ssl_c_verify(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	if (!conn->xprt_ctx)
		return 0;

	smp->type = SMP_T_UINT;
	smp->data.uint = (unsigned int)SSL_get_verify_result(conn->xprt_ctx);
	smp->flags = 0;

	return 1;
}

/* parse the "ca-file" bind keyword */
static int bind_parse_ca_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CAfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && global.ca_base)
		memprintf(&conf->ca_file, "%s/%s", global.ca_base, args[cur_arg + 1]);
	else
		memprintf(&conf->ca_file, "%s", args[cur_arg + 1]);

	return 0;
}

/* parse the "ca-sign-file" bind keyword */
static int bind_parse_ca_sign_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CAfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && global.ca_base)
		memprintf(&conf->ca_sign_file, "%s/%s", global.ca_base, args[cur_arg + 1]);
	else
		memprintf(&conf->ca_sign_file, "%s", args[cur_arg + 1]);

	return 0;
}

/* parse the ca-sign-pass bind keyword */

static int bind_parse_ca_sign_pass(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CAkey password", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	memprintf(&conf->ca_sign_pass, "%s", args[cur_arg + 1]);
	return 0;
}

/* parse the "ciphers" bind keyword */
static int bind_parse_ciphers(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->ciphers);
	conf->ciphers = strdup(args[cur_arg + 1]);
	return 0;
}

/* parse the "crt" bind keyword */
static int bind_parse_crt(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char path[MAXPATHLEN];

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate location", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/' ) && global.crt_base) {
		if ((strlen(global.crt_base) + 1 + strlen(args[cur_arg + 1]) + 1) > MAXPATHLEN) {
			memprintf(err, "'%s' : path too long", args[cur_arg]);
			return ERR_ALERT | ERR_FATAL;
		}
		snprintf(path, sizeof(path), "%s/%s",  global.crt_base, args[cur_arg + 1]);
		if (ssl_sock_load_cert(path, conf, px, err) > 0)
			return ERR_ALERT | ERR_FATAL;

		return 0;
	}

	if (ssl_sock_load_cert(args[cur_arg + 1], conf, px, err) > 0)
		return ERR_ALERT | ERR_FATAL;

	return 0;
}

/* parse the "crt-list" bind keyword */
static int bind_parse_crt_list(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate location", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (ssl_sock_load_cert_list_file(args[cur_arg + 1], conf, px, err) > 0) {
		memprintf(err, "'%s' : %s", args[cur_arg], *err);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "crl-file" bind keyword */
static int bind_parse_crl_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#ifndef X509_V_FLAG_CRL_CHECK
	if (err)
		memprintf(err, "'%s' : library does not support CRL verify", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CRLfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && global.ca_base)
		memprintf(&conf->crl_file, "%s/%s", global.ca_base, args[cur_arg + 1]);
	else
		memprintf(&conf->crl_file, "%s", args[cur_arg + 1]);

	return 0;
#endif
}

/* parse the "ecdhe" bind keyword keywords */
static int bind_parse_ecdhe(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	if (err)
		memprintf(err, "'%s' : library does not support elliptic curve Diffie-Hellman (too old)", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#elif defined(OPENSSL_NO_ECDH)
	if (err)
		memprintf(err, "'%s' : library does not support elliptic curve Diffie-Hellman (disabled via OPENSSL_NO_ECDH)", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing named curve", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	conf->ecdhe = strdup(args[cur_arg + 1]);

	return 0;
#endif
}

/* parse the "crt_ignerr" and "ca_ignerr" bind keywords */
static int bind_parse_ignore_err(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int code;
	char *p = args[cur_arg + 1];
	unsigned long long *ignerr = &conf->crt_ignerr;

	if (!*p) {
		if (err)
			memprintf(err, "'%s' : missing error IDs list", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg], "ca-ignore-err") == 0)
		ignerr = &conf->ca_ignerr;

	if (strcmp(p, "all") == 0) {
		*ignerr = ~0ULL;
		return 0;
	}

	while (p) {
		code = atoi(p);
		if ((code <= 0) || (code > 63)) {
			if (err)
				memprintf(err, "'%s' : ID '%d' out of range (1..63) in error IDs list '%s'",
				          args[cur_arg], code, args[cur_arg + 1]);
			return ERR_ALERT | ERR_FATAL;
		}
		*ignerr |= 1ULL << code;
		p = strchr(p, ',');
		if (p)
			p++;
	}

	return 0;
}

/* parse the "force-sslv3" bind keyword */
static int bind_parse_force_sslv3(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_USE_SSLV3;
	return 0;
}

/* parse the "force-tlsv10" bind keyword */
static int bind_parse_force_tlsv10(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_USE_TLSV10;
	return 0;
}

/* parse the "force-tlsv11" bind keyword */
static int bind_parse_force_tlsv11(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#if SSL_OP_NO_TLSv1_1
	conf->ssl_options |= BC_SSL_O_USE_TLSV11;
	return 0;
#else
	if (err)
		memprintf(err, "'%s' : library does not support protocol TLSv1.1", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* parse the "force-tlsv12" bind keyword */
static int bind_parse_force_tlsv12(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#if SSL_OP_NO_TLSv1_2
	conf->ssl_options |= BC_SSL_O_USE_TLSV12;
	return 0;
#else
	if (err)
		memprintf(err, "'%s' : library does not support protocol TLSv1.2", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}


/* parse the "no-tls-tickets" bind keyword */
static int bind_parse_no_tls_tickets(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_NO_TLS_TICKETS;
	return 0;
}


/* parse the "no-sslv3" bind keyword */
static int bind_parse_no_sslv3(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_NO_SSLV3;
	return 0;
}

/* parse the "no-tlsv10" bind keyword */
static int bind_parse_no_tlsv10(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_NO_TLSV10;
	return 0;
}

/* parse the "no-tlsv11" bind keyword */
static int bind_parse_no_tlsv11(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_NO_TLSV11;
	return 0;
}

/* parse the "no-tlsv12" bind keyword */
static int bind_parse_no_tlsv12(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_NO_TLSV12;
	return 0;
}

/* parse the "npn" bind keyword */
static int bind_parse_npn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#ifdef OPENSSL_NPN_NEGOTIATED
	char *p1, *p2;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing the comma-delimited NPN protocol suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->npn_str);

	/* the NPN string is built as a suite of (<len> <name>)* */
	conf->npn_len = strlen(args[cur_arg + 1]) + 1;
	conf->npn_str = calloc(1, conf->npn_len);
	memcpy(conf->npn_str + 1, args[cur_arg + 1], conf->npn_len);

	/* replace commas with the name length */
	p1 = conf->npn_str;
	p2 = p1 + 1;
	while (1) {
		p2 = memchr(p1 + 1, ',', conf->npn_str + conf->npn_len - (p1 + 1));
		if (!p2)
			p2 = p1 + 1 + strlen(p1 + 1);

		if (p2 - (p1 + 1) > 255) {
			*p2 = '\0';
			memprintf(err, "'%s' : NPN protocol name too long : '%s'", args[cur_arg], p1 + 1);
			return ERR_ALERT | ERR_FATAL;
		}

		*p1 = p2 - (p1 + 1);
		p1 = p2;

		if (!*p2)
			break;

		*(p2++) = '\0';
	}
	return 0;
#else
	if (err)
		memprintf(err, "'%s' : library does not support TLS NPN extension", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* parse the "alpn" bind keyword */
static int bind_parse_alpn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	char *p1, *p2;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing the comma-delimited ALPN protocol suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->alpn_str);

	/* the ALPN string is built as a suite of (<len> <name>)* */
	conf->alpn_len = strlen(args[cur_arg + 1]) + 1;
	conf->alpn_str = calloc(1, conf->alpn_len);
	memcpy(conf->alpn_str + 1, args[cur_arg + 1], conf->alpn_len);

	/* replace commas with the name length */
	p1 = conf->alpn_str;
	p2 = p1 + 1;
	while (1) {
		p2 = memchr(p1 + 1, ',', conf->alpn_str + conf->alpn_len - (p1 + 1));
		if (!p2)
			p2 = p1 + 1 + strlen(p1 + 1);

		if (p2 - (p1 + 1) > 255) {
			*p2 = '\0';
			memprintf(err, "'%s' : ALPN protocol name too long : '%s'", args[cur_arg], p1 + 1);
			return ERR_ALERT | ERR_FATAL;
		}

		*p1 = p2 - (p1 + 1);
		p1 = p2;

		if (!*p2)
			break;

		*(p2++) = '\0';
	}
	return 0;
#else
	if (err)
		memprintf(err, "'%s' : library does not support TLS ALPN extension", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* parse the "ssl" bind keyword */
static int bind_parse_ssl(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	struct listener *l;

	conf->is_ssl = 1;

	if (global.listen_default_ciphers && !conf->ciphers)
		conf->ciphers = strdup(global.listen_default_ciphers);
	conf->ssl_options |= global.listen_default_ssloptions;

	list_for_each_entry(l, &conf->listeners, by_bind)
		l->xprt = &ssl_sock;

	return 0;
}

/* parse the "generate-certificates" bind keyword */
static int bind_parse_generate_certs(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	conf->generate_certs = 1;
#else
	memprintf(err, "%sthis version of openssl cannot generate SSL certificates.\n",
		  err && *err ? *err : "");
#endif
	return 0;
}

/* parse the "strict-sni" bind keyword */
static int bind_parse_strict_sni(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->strict_sni = 1;
	return 0;
}

/* parse the "tls-ticket-keys" bind keyword */
static int bind_parse_tls_ticket_keys(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
	FILE *f;
	int i = 0;
	char thisline[LINESIZE];
	struct tls_keys_ref *keys_ref;

	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing TLS ticket keys file path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	keys_ref = tlskeys_ref_lookup(args[cur_arg + 1]);
	if(keys_ref) {
		conf->keys_ref = keys_ref;
		return 0;
	}

	keys_ref = malloc(sizeof(struct tls_keys_ref));
	keys_ref->tlskeys = malloc(TLS_TICKETS_NO * sizeof(struct tls_sess_key));

	if ((f = fopen(args[cur_arg + 1], "r")) == NULL) {
		if (err)
			memprintf(err, "'%s' : unable to load ssl tickets keys file", args[cur_arg+1]);
		return ERR_ALERT | ERR_FATAL;
	}

	keys_ref->filename = strdup(args[cur_arg + 1]);

	while (fgets(thisline, sizeof(thisline), f) != NULL) {
		int len = strlen(thisline);
		/* Strip newline characters from the end */
		if(thisline[len - 1] == '\n')
			thisline[--len] = 0;

		if(thisline[len - 1] == '\r')
			thisline[--len] = 0;

		if (base64dec(thisline, len, (char *) (keys_ref->tlskeys + i % TLS_TICKETS_NO), sizeof(struct tls_sess_key)) != sizeof(struct tls_sess_key)) {
			if (err)
				memprintf(err, "'%s' : unable to decode base64 key on line %d", args[cur_arg+1], i + 1);
			return ERR_ALERT | ERR_FATAL;
		}
		i++;
	}

	if (i < TLS_TICKETS_NO) {
		if (err)
			memprintf(err, "'%s' : please supply at least %d keys in the tls-tickets-file", args[cur_arg+1], TLS_TICKETS_NO);
		return ERR_ALERT | ERR_FATAL;
	}

	fclose(f);

	/* Use penultimate key for encryption, handle when TLS_TICKETS_NO = 1 */
	i-=2;
	keys_ref->tls_ticket_enc_index = i < 0 ? 0 : i;
	keys_ref->unique_id = -1;
	conf->keys_ref = keys_ref;

	LIST_ADD(&tlskeys_reference, &keys_ref->list);

	return 0;
#else
	if (err)
		memprintf(err, "'%s' : TLS ticket callback extension not supported", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif /* SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB */
}

/* parse the "verify" bind keyword */
static int bind_parse_verify(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing verify method", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[cur_arg + 1], "none") == 0)
		conf->verify = SSL_SOCK_VERIFY_NONE;
	else if (strcmp(args[cur_arg + 1], "optional") == 0)
		conf->verify = SSL_SOCK_VERIFY_OPTIONAL;
	else if (strcmp(args[cur_arg + 1], "required") == 0)
		conf->verify = SSL_SOCK_VERIFY_REQUIRED;
	else {
		if (err)
			memprintf(err, "'%s' : unknown verify method '%s', only 'none', 'optional', and 'required' are supported\n",
			          args[cur_arg], args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/************** "server" keywords ****************/

/* parse the "ca-file" server keyword */
static int srv_parse_ca_file(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CAfile path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '/') && global.ca_base)
		memprintf(&newsrv->ssl_ctx.ca_file, "%s/%s", global.ca_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.ca_file, "%s", args[*cur_arg + 1]);

	return 0;
}

/* parse the "check-ssl" server keyword */
static int srv_parse_check_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->check.use_ssl = 1;
	if (global.connect_default_ciphers && !newsrv->ssl_ctx.ciphers)
		newsrv->ssl_ctx.ciphers = strdup(global.connect_default_ciphers);
	newsrv->ssl_ctx.options |= global.connect_default_ssloptions;
	return 0;
}

/* parse the "ciphers" server keyword */
static int srv_parse_ciphers(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->ssl_ctx.ciphers);
	newsrv->ssl_ctx.ciphers = strdup(args[*cur_arg + 1]);
	return 0;
}

/* parse the "crl-file" server keyword */
static int srv_parse_crl_file(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifndef X509_V_FLAG_CRL_CHECK
	if (err)
		memprintf(err, "'%s' : library does not support CRL verify", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CRLfile path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '/') && global.ca_base)
		memprintf(&newsrv->ssl_ctx.crl_file, "%s/%s", global.ca_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.crl_file, "%s", args[*cur_arg + 1]);

	return 0;
#endif
}

/* parse the "crt" server keyword */
static int srv_parse_crt(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing certificate file path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '/') && global.crt_base)
		memprintf(&newsrv->ssl_ctx.client_crt, "%s/%s", global.ca_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.client_crt, "%s", args[*cur_arg + 1]);

	return 0;
}

/* parse the "force-sslv3" server keyword */
static int srv_parse_force_sslv3(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_USE_SSLV3;
	return 0;
}

/* parse the "force-tlsv10" server keyword */
static int srv_parse_force_tlsv10(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_USE_TLSV10;
	return 0;
}

/* parse the "force-tlsv11" server keyword */
static int srv_parse_force_tlsv11(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#if SSL_OP_NO_TLSv1_1
	newsrv->ssl_ctx.options |= SRV_SSL_O_USE_TLSV11;
	return 0;
#else
	if (err)
		memprintf(err, "'%s' : library does not support protocol TLSv1.1", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* parse the "force-tlsv12" server keyword */
static int srv_parse_force_tlsv12(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#if SSL_OP_NO_TLSv1_2
	newsrv->ssl_ctx.options |= SRV_SSL_O_USE_TLSV12;
	return 0;
#else
	if (err)
		memprintf(err, "'%s' : library does not support protocol TLSv1.2", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* parse the "no-ssl-reuse" server keyword */
static int srv_parse_no_ssl_reuse(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_REUSE;
	return 0;
}

/* parse the "no-sslv3" server keyword */
static int srv_parse_no_sslv3(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_SSLV3;
	return 0;
}

/* parse the "no-tlsv10" server keyword */
static int srv_parse_no_tlsv10(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_TLSV10;
	return 0;
}

/* parse the "no-tlsv11" server keyword */
static int srv_parse_no_tlsv11(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_TLSV11;
	return 0;
}

/* parse the "no-tlsv12" server keyword */
static int srv_parse_no_tlsv12(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_TLSV12;
	return 0;
}

/* parse the "no-tls-tickets" server keyword */
static int srv_parse_no_tls_tickets(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_TLS_TICKETS;
	return 0;
}
/* parse the "send-proxy-v2-ssl" server keyword */
static int srv_parse_send_proxy_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->pp_opts |= SRV_PP_V2;
	newsrv->pp_opts |= SRV_PP_V2_SSL;
	return 0;
}

/* parse the "send-proxy-v2-ssl-cn" server keyword */
static int srv_parse_send_proxy_cn(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->pp_opts |= SRV_PP_V2;
	newsrv->pp_opts |= SRV_PP_V2_SSL;
	newsrv->pp_opts |= SRV_PP_V2_SSL_CN;
	return 0;
}

/* parse the "sni" server keyword */
static int srv_parse_sni(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
	memprintf(err, "'%s' : the current SSL library doesn't support the SNI TLS extension", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#else
	struct sample_expr *expr;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing sni expression", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	(*cur_arg)++;
	proxy->conf.args.ctx = ARGC_SRV;

	expr = sample_parse_expr((char **)args, cur_arg, px->conf.file, px->conf.line, err, &proxy->conf.args);
	if (!expr) {
		memprintf(err, "error detected while parsing sni expression : %s", *err);
		return ERR_ALERT | ERR_FATAL;
	}

	if (!(expr->fetch->val & SMP_VAL_BE_SRV_CON)) {
		memprintf(err, "error detected while parsing sni expression : "
		          " fetch method '%s' extracts information from '%s', none of which is available here.\n",
		          args[*cur_arg-1], sample_src_names(expr->fetch->use));
		return ERR_ALERT | ERR_FATAL;
	}

	px->http_needed |= !!(expr->fetch->use & SMP_USE_HTTP_ANY);
	newsrv->ssl_ctx.sni = expr;
	return 0;
#endif
}

/* parse the "ssl" server keyword */
static int srv_parse_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->use_ssl = 1;
	if (global.connect_default_ciphers && !newsrv->ssl_ctx.ciphers)
		newsrv->ssl_ctx.ciphers = strdup(global.connect_default_ciphers);
	return 0;
}

/* parse the "verify" server keyword */
static int srv_parse_verify(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing verify method", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if (strcmp(args[*cur_arg + 1], "none") == 0)
		newsrv->ssl_ctx.verify = SSL_SOCK_VERIFY_NONE;
	else if (strcmp(args[*cur_arg + 1], "required") == 0)
		newsrv->ssl_ctx.verify = SSL_SOCK_VERIFY_REQUIRED;
	else {
		if (err)
			memprintf(err, "'%s' : unknown verify method '%s', only 'none' and 'required' are supported\n",
			          args[*cur_arg], args[*cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}

	return 0;
}

/* parse the "verifyhost" server keyword */
static int srv_parse_verifyhost(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing hostname to verify against", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	newsrv->ssl_ctx.verify_host = strdup(args[*cur_arg + 1]);

	return 0;
}

/* parse the "ssl-default-bind-options" keyword in global section */
static int ssl_parse_default_bind_options(char **args, int section_type, struct proxy *curpx,
                                          struct proxy *defpx, const char *file, int line,
                                          char **err) {
	int i = 1;

	if (*(args[i]) == 0) {
		memprintf(err, "global statement '%s' expects an option as an argument.", args[0]);
		return -1;
	}
	while (*(args[i])) {
		if (!strcmp(args[i], "no-sslv3"))
			global.listen_default_ssloptions |= BC_SSL_O_NO_SSLV3;
		else if (!strcmp(args[i], "no-tlsv10"))
			global.listen_default_ssloptions |= BC_SSL_O_NO_TLSV10;
		else if (!strcmp(args[i], "no-tlsv11"))
			global.listen_default_ssloptions |= BC_SSL_O_NO_TLSV11;
		else if (!strcmp(args[i], "no-tlsv12"))
			global.listen_default_ssloptions |= BC_SSL_O_NO_TLSV12;
		else if (!strcmp(args[i], "force-sslv3"))
			global.listen_default_ssloptions |= BC_SSL_O_USE_SSLV3;
		else if (!strcmp(args[i], "force-tlsv10"))
			global.listen_default_ssloptions |= BC_SSL_O_USE_TLSV10;
		else if (!strcmp(args[i], "force-tlsv11")) {
#if SSL_OP_NO_TLSv1_1
			global.listen_default_ssloptions |= BC_SSL_O_USE_TLSV11;
#else
			memprintf(err, "'%s' '%s': library does not support protocol TLSv1.1", args[0], args[i]);
			return -1;
#endif
		}
		else if (!strcmp(args[i], "force-tlsv12")) {
#if SSL_OP_NO_TLSv1_2
			global.listen_default_ssloptions |= BC_SSL_O_USE_TLSV12;
#else
			memprintf(err, "'%s' '%s': library does not support protocol TLSv1.2", args[0], args[i]);
			return -1;
#endif
		}
		else if (!strcmp(args[i], "no-tls-tickets"))
			global.listen_default_ssloptions |= BC_SSL_O_NO_TLS_TICKETS;
		else {
			memprintf(err, "unknown option '%s' on global statement '%s'.", args[i], args[0]);
			return -1;
		}
		i++;
	}
	return 0;
}

/* parse the "ssl-default-server-options" keyword in global section */
static int ssl_parse_default_server_options(char **args, int section_type, struct proxy *curpx,
                                            struct proxy *defpx, const char *file, int line,
                                            char **err) {
	int i = 1;

	if (*(args[i]) == 0) {
		memprintf(err, "global statement '%s' expects an option as an argument.", args[0]);
		return -1;
	}
	while (*(args[i])) {
		if (!strcmp(args[i], "no-sslv3"))
			global.connect_default_ssloptions |= SRV_SSL_O_NO_SSLV3;
		else if (!strcmp(args[i], "no-tlsv10"))
			global.connect_default_ssloptions |= SRV_SSL_O_NO_TLSV10;
		else if (!strcmp(args[i], "no-tlsv11"))
			global.connect_default_ssloptions |= SRV_SSL_O_NO_TLSV11;
		else if (!strcmp(args[i], "no-tlsv12"))
			global.connect_default_ssloptions |= SRV_SSL_O_NO_TLSV12;
		else if (!strcmp(args[i], "force-sslv3"))
			global.connect_default_ssloptions |= SRV_SSL_O_USE_SSLV3;
		else if (!strcmp(args[i], "force-tlsv10"))
			global.connect_default_ssloptions |= SRV_SSL_O_USE_TLSV10;
		else if (!strcmp(args[i], "force-tlsv11")) {
#if SSL_OP_NO_TLSv1_1
			global.connect_default_ssloptions |= SRV_SSL_O_USE_TLSV11;
#else
			memprintf(err, "'%s' '%s': library does not support protocol TLSv1.1", args[0], args[i]);
			return -1;
#endif
		}
		else if (!strcmp(args[i], "force-tlsv12")) {
#if SSL_OP_NO_TLSv1_2
			global.connect_default_ssloptions |= SRV_SSL_O_USE_TLSV12;
#else
			memprintf(err, "'%s' '%s': library does not support protocol TLSv1.2", args[0], args[i]);
			return -1;
#endif
		}
		else if (!strcmp(args[i], "no-tls-tickets"))
			global.connect_default_ssloptions |= SRV_SSL_O_NO_TLS_TICKETS;
		else {
			memprintf(err, "unknown option '%s' on global statement '%s'.", args[i], args[0]);
			return -1;
		}
		i++;
	}
	return 0;
}

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "ssl_bc",                 smp_fetch_ssl_fc,             0,                   NULL,    SMP_T_BOOL, SMP_USE_L5SRV },
	{ "ssl_bc_alg_keysize",     smp_fetch_ssl_fc_alg_keysize, 0,                   NULL,    SMP_T_UINT, SMP_USE_L5SRV },
	{ "ssl_bc_cipher",          smp_fetch_ssl_fc_cipher,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
	{ "ssl_bc_protocol",        smp_fetch_ssl_fc_protocol,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
	{ "ssl_bc_unique_id",       smp_fetch_ssl_fc_unique_id,   0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
	{ "ssl_bc_use_keysize",     smp_fetch_ssl_fc_use_keysize, 0,                   NULL,    SMP_T_UINT, SMP_USE_L5SRV },
	{ "ssl_bc_session_id",      smp_fetch_ssl_fc_session_id,  0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
	{ "ssl_c_ca_err",           smp_fetch_ssl_c_ca_err,       0,                   NULL,    SMP_T_UINT, SMP_USE_L5CLI },
	{ "ssl_c_ca_err_depth",     smp_fetch_ssl_c_ca_err_depth, 0,                   NULL,    SMP_T_UINT, SMP_USE_L5CLI },
	{ "ssl_c_der",              smp_fetch_ssl_x_der,          0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_err",              smp_fetch_ssl_c_err,          0,                   NULL,    SMP_T_UINT, SMP_USE_L5CLI },
	{ "ssl_c_i_dn",             smp_fetch_ssl_x_i_dn,         ARG2(0,STR,SINT),    NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_key_alg",          smp_fetch_ssl_x_key_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_notafter",         smp_fetch_ssl_x_notafter,     0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_notbefore",        smp_fetch_ssl_x_notbefore,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_sig_alg",          smp_fetch_ssl_x_sig_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_s_dn",             smp_fetch_ssl_x_s_dn,         ARG2(0,STR,SINT),    NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_serial",           smp_fetch_ssl_x_serial,       0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_sha1",             smp_fetch_ssl_x_sha1,         0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_used",             smp_fetch_ssl_c_used,         0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_c_verify",           smp_fetch_ssl_c_verify,       0,                   NULL,    SMP_T_UINT, SMP_USE_L5CLI },
	{ "ssl_c_version",          smp_fetch_ssl_x_version,      0,                   NULL,    SMP_T_UINT, SMP_USE_L5CLI },
	{ "ssl_f_der",              smp_fetch_ssl_x_der,          0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_f_i_dn",             smp_fetch_ssl_x_i_dn,         ARG2(0,STR,SINT),    NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_key_alg",          smp_fetch_ssl_x_key_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_notafter",         smp_fetch_ssl_x_notafter,     0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_notbefore",        smp_fetch_ssl_x_notbefore,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_sig_alg",          smp_fetch_ssl_x_sig_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_s_dn",             smp_fetch_ssl_x_s_dn,         ARG2(0,STR,SINT),    NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_serial",           smp_fetch_ssl_x_serial,       0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_f_sha1",             smp_fetch_ssl_x_sha1,         0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_f_version",          smp_fetch_ssl_x_version,      0,                   NULL,    SMP_T_UINT, SMP_USE_L5CLI },
	{ "ssl_fc",                 smp_fetch_ssl_fc,             0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_alg_keysize",     smp_fetch_ssl_fc_alg_keysize, 0,                   NULL,    SMP_T_UINT, SMP_USE_L5CLI },
	{ "ssl_fc_cipher",          smp_fetch_ssl_fc_cipher,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_has_crt",         smp_fetch_ssl_fc_has_crt,     0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_has_sni",         smp_fetch_ssl_fc_has_sni,     0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_is_resumed",      smp_fetch_ssl_fc_is_resumed,  0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
#ifdef OPENSSL_NPN_NEGOTIATED
	{ "ssl_fc_npn",             smp_fetch_ssl_fc_npn,         0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	{ "ssl_fc_alpn",            smp_fetch_ssl_fc_alpn,        0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#endif
	{ "ssl_fc_protocol",        smp_fetch_ssl_fc_protocol,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_unique_id",       smp_fetch_ssl_fc_unique_id,   0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_fc_use_keysize",     smp_fetch_ssl_fc_use_keysize, 0,                   NULL,    SMP_T_UINT, SMP_USE_L5CLI },
	{ "ssl_fc_session_id",      smp_fetch_ssl_fc_session_id,  0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_fc_sni",             smp_fetch_ssl_fc_sni,         0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ NULL, NULL, 0, 0, 0 },
}};

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ "ssl_fc_sni_end",         "ssl_fc_sni", PAT_MATCH_END },
	{ "ssl_fc_sni_reg",         "ssl_fc_sni", PAT_MATCH_REG },
	{ /* END */ },
}};

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct bind_kw_list bind_kws = { "SSL", { }, {
	{ "alpn",                  bind_parse_alpn,            1 }, /* set ALPN supported protocols */
	{ "ca-file",               bind_parse_ca_file,         1 }, /* set CAfile to process verify on client cert */
	{ "ca-ignore-err",         bind_parse_ignore_err,      1 }, /* set error IDs to ignore on verify depth > 0 */
	{ "ca-sign-file",          bind_parse_ca_sign_file,    1 }, /* set CAFile used to generate and sign server certs */
	{ "ca-sign-pass",          bind_parse_ca_sign_pass,    1 }, /* set CAKey passphrase */
	{ "ciphers",               bind_parse_ciphers,         1 }, /* set SSL cipher suite */
	{ "crl-file",              bind_parse_crl_file,        1 }, /* set certificat revocation list file use on client cert verify */
	{ "crt",                   bind_parse_crt,             1 }, /* load SSL certificates from this location */
	{ "crt-ignore-err",        bind_parse_ignore_err,      1 }, /* set error IDs to ingore on verify depth == 0 */
	{ "crt-list",              bind_parse_crt_list,        1 }, /* load a list of crt from this location */
	{ "ecdhe",                 bind_parse_ecdhe,           1 }, /* defines named curve for elliptic curve Diffie-Hellman */
	{ "force-sslv3",           bind_parse_force_sslv3,     0 }, /* force SSLv3 */
	{ "force-tlsv10",          bind_parse_force_tlsv10,    0 }, /* force TLSv10 */
	{ "force-tlsv11",          bind_parse_force_tlsv11,    0 }, /* force TLSv11 */
	{ "force-tlsv12",          bind_parse_force_tlsv12,    0 }, /* force TLSv12 */
	{ "generate-certificates", bind_parse_generate_certs,  0 }, /* enable the server certificates generation */
	{ "no-sslv3",              bind_parse_no_sslv3,        0 }, /* disable SSLv3 */
	{ "no-tlsv10",             bind_parse_no_tlsv10,       0 }, /* disable TLSv10 */
	{ "no-tlsv11",             bind_parse_no_tlsv11,       0 }, /* disable TLSv11 */
	{ "no-tlsv12",             bind_parse_no_tlsv12,       0 }, /* disable TLSv12 */
	{ "no-tls-tickets",        bind_parse_no_tls_tickets,  0 }, /* disable session resumption tickets */
	{ "ssl",                   bind_parse_ssl,             0 }, /* enable SSL processing */
	{ "strict-sni",            bind_parse_strict_sni,      0 }, /* refuse negotiation if sni doesn't match a certificate */
	{ "tls-ticket-keys",       bind_parse_tls_ticket_keys, 1 }, /* set file to load TLS ticket keys from */
	{ "verify",                bind_parse_verify,          1 }, /* set SSL verify method */
	{ "npn",                   bind_parse_npn,             1 }, /* set NPN supported protocols */
	{ NULL, NULL, 0 },
}};

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct srv_kw_list srv_kws = { "SSL", { }, {
	{ "ca-file",               srv_parse_ca_file,        1, 0 }, /* set CAfile to process verify server cert */
	{ "check-ssl",             srv_parse_check_ssl,      0, 0 }, /* enable SSL for health checks */
	{ "ciphers",               srv_parse_ciphers,        1, 0 }, /* select the cipher suite */
	{ "crl-file",              srv_parse_crl_file,       1, 0 }, /* set certificate revocation list file use on server cert verify */
	{ "crt",                   srv_parse_crt,            1, 0 }, /* set client certificate */
	{ "force-sslv3",           srv_parse_force_sslv3,    0, 0 }, /* force SSLv3 */
	{ "force-tlsv10",          srv_parse_force_tlsv10,   0, 0 }, /* force TLSv10 */
	{ "force-tlsv11",          srv_parse_force_tlsv11,   0, 0 }, /* force TLSv11 */
	{ "force-tlsv12",          srv_parse_force_tlsv12,   0, 0 }, /* force TLSv12 */
	{ "no-ssl-reuse",          srv_parse_no_ssl_reuse,   0, 0 }, /* disable session reuse */
	{ "no-sslv3",              srv_parse_no_sslv3,       0, 0 }, /* disable SSLv3 */
	{ "no-tlsv10",             srv_parse_no_tlsv10,      0, 0 }, /* disable TLSv10 */
	{ "no-tlsv11",             srv_parse_no_tlsv11,      0, 0 }, /* disable TLSv11 */
	{ "no-tlsv12",             srv_parse_no_tlsv12,      0, 0 }, /* disable TLSv12 */
	{ "no-tls-tickets",        srv_parse_no_tls_tickets, 0, 0 }, /* disable session resumption tickets */
	{ "send-proxy-v2-ssl",     srv_parse_send_proxy_ssl, 0, 0 }, /* send PROXY protocol header v2 with SSL info */
	{ "send-proxy-v2-ssl-cn",  srv_parse_send_proxy_cn,  0, 0 }, /* send PROXY protocol header v2 with CN */
	{ "sni",                   srv_parse_sni,            1, 0 }, /* send SNI extension */
	{ "ssl",                   srv_parse_ssl,            0, 0 }, /* enable SSL processing */
	{ "verify",                srv_parse_verify,         1, 0 }, /* set SSL verify method */
	{ "verifyhost",            srv_parse_verifyhost,     1, 0 }, /* require that SSL cert verifies for hostname */
	{ NULL, NULL, 0, 0 },
}};

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "ssl-default-bind-options", ssl_parse_default_bind_options },
	{ CFG_GLOBAL, "ssl-default-server-options", ssl_parse_default_server_options },
	{ 0, NULL, NULL },
}};

/* transport-layer operations for SSL sockets */
struct xprt_ops ssl_sock = {
	.snd_buf  = ssl_sock_from_buf,
	.rcv_buf  = ssl_sock_to_buf,
	.rcv_pipe = NULL,
	.snd_pipe = NULL,
	.shutr    = NULL,
	.shutw    = ssl_sock_shutw,
	.close    = ssl_sock_close,
	.init     = ssl_sock_init,
};

#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)

static void ssl_sock_sctl_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	if (ptr) {
		chunk_destroy(ptr);
		free(ptr);
	}
}

#endif

__attribute__((constructor))
static void __ssl_sock_init(void)
{
	STACK_OF(SSL_COMP)* cm;

#ifdef LISTEN_DEFAULT_CIPHERS
	global.listen_default_ciphers = LISTEN_DEFAULT_CIPHERS;
#endif
#ifdef CONNECT_DEFAULT_CIPHERS
	global.connect_default_ciphers = CONNECT_DEFAULT_CIPHERS;
#endif
	if (global.listen_default_ciphers)
		global.listen_default_ciphers = strdup(global.listen_default_ciphers);
	if (global.connect_default_ciphers)
		global.connect_default_ciphers = strdup(global.connect_default_ciphers);
	global.listen_default_ssloptions = BC_SSL_O_NONE;
	global.connect_default_ssloptions = SRV_SSL_O_NONE;

	SSL_library_init();
	cm = SSL_COMP_get_compression_methods();
	sk_SSL_COMP_zero(cm);
#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
	sctl_ex_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, ssl_sock_sctl_free_func);
#endif
	sample_register_fetches(&sample_fetch_keywords);
	acl_register_keywords(&acl_kws);
	bind_register_keywords(&bind_kws);
	srv_register_keywords(&srv_kws);
	cfg_register_keywords(&cfg_kws);

	global.ssl_session_max_cost   = SSL_SESSION_MAX_COST;
	global.ssl_handshake_max_cost = SSL_HANDSHAKE_MAX_COST;

#ifndef OPENSSL_NO_DH
	ssl_dh_ptr_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
#endif

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	/* Add a global parameter for the LRU cache size */
	if (global.tune.ssl_ctx_cache)
		ssl_ctx_lru_tree = lru64_new(global.tune.ssl_ctx_cache);
	ssl_ctx_lru_seed = (unsigned int)time(NULL);
#endif
}

__attribute__((destructor))
static void __ssl_sock_deinit(void)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	lru64_destroy(ssl_ctx_lru_tree);
#endif

#ifndef OPENSSL_NO_DH
        if (local_dh_1024) {
                DH_free(local_dh_1024);
                local_dh_1024 = NULL;
        }

        if (local_dh_2048) {
                DH_free(local_dh_2048);
                local_dh_2048 = NULL;
        }

        if (local_dh_4096) {
                DH_free(local_dh_4096);
                local_dh_4096 = NULL;
        }

	if (global_dh) {
		DH_free(global_dh);
		global_dh = NULL;
	}
#endif

        ERR_remove_state(0);
        ERR_free_strings();

        EVP_cleanup();

#if OPENSSL_VERSION_NUMBER >= 0x00907000L
        CRYPTO_cleanup_all_ex_data();
#endif
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
