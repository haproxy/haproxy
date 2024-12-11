/*
 *
 * Copyright (C) 2020 HAProxy Technologies, William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
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
#include <syslog.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <import/ebpttree.h>
#include <import/ebsttree.h>

#include <haproxy/applet.h>
#include <haproxy/base64.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/proxy.h>
#include <haproxy/sc_strm.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/ssl_ocsp.h>
#include <haproxy/ssl_utils.h>
#include <haproxy/stconn.h>
#include <haproxy/tools.h>

/* Uncommitted CKCH transaction */

static struct {
	struct ckch_store *new_ckchs;
	struct ckch_store *old_ckchs;
	char *path;
} ckchs_transaction;

/* Uncommitted CA file transaction */

static struct {
	struct cafile_entry *old_cafile_entry;
	struct cafile_entry *new_cafile_entry;
	char *path;
} cafile_transaction;

/* Uncommitted CRL file transaction */

static struct {
	struct cafile_entry *old_crlfile_entry;
	struct cafile_entry *new_crlfile_entry;
	char *path;
} crlfile_transaction;

/* CLI context used by "show cafile" */
struct show_cafile_ctx {
	struct cafile_entry *cur_cafile_entry;
	struct cafile_entry *old_cafile_entry;
	int ca_index;
	int show_all;
};

/* CLI context used by "show crlfile" */
struct show_crlfile_ctx {
	struct cafile_entry *cafile_entry;
	struct cafile_entry *old_crlfile_entry;
	int index;
};

/* CLI context used by "show cert" */
struct show_cert_ctx {
	struct ckch_store *old_ckchs;
	struct ckch_store *cur_ckchs;
	int transaction;
};

#define SHOW_SNI_OPT_1FRONTEND  (1 << 0) /* show only the selected frontend */
#define SHOW_SNI_OPT_NOTAFTER   (1 << 1) /* show certificates that are [A]fter the notAfter date */

/* CLI context used by "show ssl sni" */
struct show_sni_ctx {
	struct proxy *px;
	struct bind_conf *bind;
	struct ebmb_node *n;
	int nodetype;
	int options;
};

/* CLI context used by "dump ssl cert" */
struct dump_cert_ctx {
	struct ckch_store *ckchs;
	int index;
};

/* CLI context used by "commit cert" */
struct commit_cert_ctx {
	struct ckch_store *old_ckchs;
	struct ckch_store *new_ckchs;
	struct ckch_inst *next_ckchi;
	char *err;
	enum {
		CERT_ST_INIT = 0,
		CERT_ST_GEN,
		CERT_ST_INSERT,
		CERT_ST_SUCCESS,
		CERT_ST_FIN,
		CERT_ST_ERROR,
	} state;
};

/* CLI context used by "commit cafile" and "commit crlfile" */
struct commit_cacrlfile_ctx {
	struct cafile_entry *old_entry;
	struct cafile_entry *new_entry;
	struct ckch_inst_link *next_ckchi_link;
	enum cafile_type cafile_type; /* either CA or CRL, depending on the current command */
	char *err;
	enum {
		CACRL_ST_INIT = 0,
		CACRL_ST_GEN,
		CACRL_ST_CRLCB,
		CACRL_ST_INSERT,
		CACRL_ST_SUCCESS,
		CACRL_ST_FIN,
		CACRL_ST_ERROR,
	} state;
};


/*
 * Callback function, which is called if defined after loading CRLs from disk
 * when starting HAProxy (function __ssl_store_load_locations_file()), and after
 * committing new CRLs via CLI (function cli_io_handler_commit_cafile_crlfile()).
 *
 * The input parameters of the function are the path for the CRL data and
 * a structure containing information about X.509 certificates and CRLs.
 * In case of error, returns -1 with an error message in err; or the number
 * of revoked certificates (>= 0) otherwise.
 */
int (*ssl_commit_crlfile_cb)(const char *path, X509_STORE *ctx, char **err) = NULL;

/********************  cert_key_and_chain functions *************************
 * These are the functions that fills a cert_key_and_chain structure. For the
 * functions filling a SSL_CTX from a cert_key_and_chain, see ssl_sock.c
 */

/*
 * Try to parse Signed Certificate Timestamp List structure. This function
 * makes only basic test if the data seems like SCTL. No signature validation
 * is performed.
 */
static int ssl_sock_parse_sctl(struct buffer *sctl)
{
	int ret = 1;
	int len, pos, sct_len;
	unsigned char *data;

	if (sctl->data < 2)
		goto out;

	data = (unsigned char *) sctl->area;
	len = (data[0] << 8) | data[1];

	if (len + 2 != sctl->data)
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

/* Try to load a sctl from a buffer <buf> if not NULL, or read the file <sctl_path>
 * It fills the ckch->sctl buffer
 * return 0 on success or != 0 on failure */
int ssl_sock_load_sctl_from_file(const char *sctl_path, char *buf, struct ckch_data *data, char **err)
{
	int fd = -1;
	int r = 0;
	int ret = 1;
	struct buffer tmp;
	struct buffer *src;
	struct buffer *sctl;

	if (buf) {
		chunk_initstr(&tmp, buf);
		src = &tmp;
	} else {
		fd = open(sctl_path, O_RDONLY);
		if (fd == -1)
			goto end;

		trash.data = 0;
		while (trash.data < trash.size) {
			r = read(fd, trash.area + trash.data, trash.size - trash.data);
			if (r < 0) {
				if (errno == EINTR)
					continue;
				goto end;
			}
			else if (r == 0) {
				break;
			}
			trash.data += r;
		}
		src = &trash;
	}

	ret = ssl_sock_parse_sctl(src);
	if (ret)
		goto end;

	sctl = calloc(1, sizeof(*sctl));
	if (!chunk_dup(sctl, src)) {
		ha_free(&sctl);
		goto end;
	}
	/* no error, fill ckch with new context, old context must be free */
	if (data->sctl) {
		ha_free(&data->sctl->area);
		free(data->sctl);
	}
	data->sctl = sctl;
	ret = 0;
end:
	if (fd != -1)
		close(fd);

	return ret;
}

#if defined(HAVE_SSL_OCSP)
/*
 * This function load the OCSP Response in DER format contained in file at
 * path 'ocsp_path' or base64 in a buffer <buf>
 *
 * Returns 0 on success, 1 in error case.
 */
int ssl_sock_load_ocsp_response_from_file(const char *ocsp_path, char *buf, struct ckch_data *data, char **err)
{
	int fd = -1;
	int r = 0;
	int ret = 1;
	struct buffer *ocsp_response;
	struct buffer *src = NULL;

	if (buf) {
		int i, j;
		/* if it's from a buffer it will be base64 */

		/* remove \r and \n from the payload */
		for (i = 0, j = 0; buf[i]; i++) {
			if (buf[i] == '\r' || buf[i] == '\n')
				continue;
			buf[j++] = buf[i];
		}
		buf[j] = 0;

		ret = base64dec(buf, j, trash.area, trash.size);
		if (ret < 0) {
			memprintf(err, "Error reading OCSP response in base64 format");
			goto end;
		}
		trash.data = ret;
		src = &trash;
	} else {
		fd = open(ocsp_path, O_RDONLY);
		if (fd == -1) {
			memprintf(err, "Error opening OCSP response file");
			goto end;
		}

		trash.data = 0;
		while (trash.data < trash.size) {
			r = read(fd, trash.area + trash.data, trash.size - trash.data);
			if (r < 0) {
				if (errno == EINTR)
					continue;

				memprintf(err, "Error reading OCSP response from file");
				goto end;
			}
			else if (r == 0) {
				break;
			}
			trash.data += r;
		}
		close(fd);
		fd = -1;
		src = &trash;
	}

	ocsp_response = calloc(1, sizeof(*ocsp_response));
	if (!chunk_dup(ocsp_response, src)) {
		ha_free(&ocsp_response);
		goto end;
	}
	/* no error, fill data with new context, old context must be free */
	if (data->ocsp_response) {
		ha_free(&data->ocsp_response->area);
		free(data->ocsp_response);
	}
	data->ocsp_response = ocsp_response;
	ret = 0;
end:
	if (fd != -1)
		close(fd);

	return ret;
}
#endif

/*
 * Try to load in a ckch every files related to a ckch.
 * (PEM, sctl, ocsp, issuer etc.)
 *
 * This function is only used to load files during the configuration parsing,
 * it is not used with the CLI.
 *
 * This allows us to carry the contents of the file without having to read the
 * file multiple times.  The caller must call
 * ssl_sock_free_cert_key_and_chain_contents.
 *
 * returns:
 *      0 on Success
 *      1 on SSL Failure
 */
int ssl_sock_load_files_into_ckch(const char *path, struct ckch_data *data, char **err)
{
	struct buffer *fp = NULL;
	int ret = 1;
	struct stat st;

	/* try to load the PEM */
	if (ssl_sock_load_pem_into_ckch(path, NULL, data , err) != 0) {
		goto end;
	}

	fp = alloc_trash_chunk();
	if (!fp) {
		memprintf(err, "%sCan't allocate memory\n", err && *err ? *err : "");
		goto end;
	}

	if (!chunk_strcpy(fp, path) || (b_data(fp) > MAXPATHLEN)) {
		memprintf(err, "%s '%s' filename too long'.\n",
			  err && *err ? *err : "", fp->area);
		ret = 1;
		goto end;
	}

	/* remove the ".crt" extension */
	if (global_ssl.extra_files_noext) {
		char *ext;

		/* look for the extension */
		if ((ext = strrchr(fp->area, '.'))) {

			if (strcmp(ext, ".crt") == 0) {
				*ext = '\0';
				fp->data = strlen(fp->area);
			}
		}

	}

	if (data->key == NULL) {
		/* If no private key was found yet and we cannot look for it in extra
		 * files, raise an error.
		 */
		if (!(global_ssl.extra_files & SSL_GF_KEY)) {
			memprintf(err, "%sNo Private Key found in '%s'.\n", err && *err ? *err : "", fp->area);
			goto end;
		}

		/* try to load an external private key if it wasn't in the PEM */
		if (!chunk_strcat(fp, ".key") || (b_data(fp) > MAXPATHLEN)) {
			memprintf(err, "%s '%s' filename too long'.\n",
				  err && *err ? *err : "", fp->area);
			ret = 1;
			goto end;
		}

		if (stat(fp->area, &st) == 0) {
			if (ssl_sock_load_key_into_ckch(fp->area, NULL, data, err)) {
				memprintf(err, "%s '%s' is present but cannot be read or parsed'.\n",
					  err && *err ? *err : "", fp->area);
				goto end;
			}
		}

		if (data->key == NULL) {
			memprintf(err, "%sNo Private Key found in '%s'.\n", err && *err ? *err : "", fp->area);
			goto end;
		}
		/* remove the added extension */
		*(fp->area + fp->data - strlen(".key")) = '\0';
		b_sub(fp, strlen(".key"));
	}


	if (!X509_check_private_key(data->cert, data->key)) {
		memprintf(err, "%sinconsistencies between private key and certificate loaded '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

#ifdef HAVE_SSL_SCTL
	/* try to load the sctl file */
	if (global_ssl.extra_files & SSL_GF_SCTL) {
		struct stat st;

		if (!chunk_strcat(fp, ".sctl") || b_data(fp) > MAXPATHLEN) {
			memprintf(err, "%s '%s' filename too long'.\n",
			          err && *err ? *err : "", fp->area);
			ret = 1;
			goto end;
		}

		if (stat(fp->area, &st) == 0) {
			if (ssl_sock_load_sctl_from_file(fp->area, NULL, data, err)) {
				memprintf(err, "%s '%s.sctl' is present but cannot be read or parsed'.\n",
					  err && *err ? *err : "", fp->area);
				ret = 1;
				goto end;
			}
		}
		/* remove the added extension */
		*(fp->area + fp->data - strlen(".sctl")) = '\0';
		b_sub(fp, strlen(".sctl"));
	}
#endif

#ifdef HAVE_SSL_OCSP
	/* try to load an ocsp response file */
	if (global_ssl.extra_files & SSL_GF_OCSP) {
		struct stat st;

		if (!chunk_strcat(fp, ".ocsp") || b_data(fp) > MAXPATHLEN) {
			memprintf(err, "%s '%s' filename too long'.\n",
			          err && *err ? *err : "", fp->area);
			ret = 1;
			goto end;
		}

		if (stat(fp->area, &st) == 0) {
			if (ssl_sock_load_ocsp_response_from_file(fp->area, NULL, data, err)) {
				ret = 1;
				goto end;
			}
		}
		/* remove the added extension */
		*(fp->area + fp->data - strlen(".ocsp")) = '\0';
		b_sub(fp, strlen(".ocsp"));
	}
#ifndef OPENSSL_IS_BORINGSSL /* Useless for BoringSSL */
	if (data->ocsp_response && (global_ssl.extra_files & SSL_GF_OCSP_ISSUER)) {
		/* if no issuer was found, try to load an issuer from the .issuer */
		if (!data->ocsp_issuer) {
			struct stat st;

			if (!chunk_strcat(fp, ".issuer") || b_data(fp) > MAXPATHLEN) {
				memprintf(err, "%s '%s' filename too long'.\n",
					  err && *err ? *err : "", fp->area);
				ret = 1;
				goto end;
			}

			if (stat(fp->area, &st) == 0) {
				if (ssl_sock_load_issuer_file_into_ckch(fp->area, NULL, data, err)) {
					ret = 1;
					goto end;
				}

				if (X509_check_issued(data->ocsp_issuer, data->cert) != X509_V_OK) {
					memprintf(err, "%s '%s' is not an issuer'.\n",
						  err && *err ? *err : "", fp->area);
					ret = 1;
					goto end;
				}
			}
			/* remove the added extension */
			*(fp->area + fp->data - strlen(".issuer")) = '\0';
			b_sub(fp, strlen(".issuer"));
		}
	}
#endif
#endif

	ret = 0;

end:

	ERR_clear_error();

	/* Something went wrong in one of the reads */
	if (ret != 0)
		ssl_sock_free_cert_key_and_chain_contents(data);

	free_trash_chunk(fp);

	return ret;
}

/*
 *  Try to load a private key file from a <path> or a buffer <buf>
 *
 *  If it failed you should not attempt to use the ckch but free it.
 *
 *  Return 0 on success or != 0 on failure
 */
int ssl_sock_load_key_into_ckch(const char *path, char *buf, struct ckch_data *data , char **err)
{
	BIO *in = NULL;
	int ret = 1;
	EVP_PKEY *key = NULL;

	if (buf) {
		/* reading from a buffer */
		in = BIO_new_mem_buf(buf, -1);
		if (in == NULL) {
			memprintf(err, "%sCan't allocate memory\n", err && *err ? *err : "");
			goto end;
		}

	} else {
		/* reading from a file */
		in = BIO_new(BIO_s_file());
		if (in == NULL)
			goto end;

		if (BIO_read_filename(in, path) <= 0)
			goto end;
	}

	/* Read Private Key */
	key = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
	if (key == NULL) {
		memprintf(err, "%sunable to load private key from file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

	ret = 0;

	SWAP(data->key, key);

end:

	ERR_clear_error();
	if (in)
		BIO_free(in);
	if (key)
		EVP_PKEY_free(key);

	return ret;
}

/*
 *  Try to load a PEM file from a <path> or a buffer <buf>
 *  The PEM must contain at least a Certificate,
 *  It could contain a DH, a certificate chain and a PrivateKey.
 *
 *  If it failed you should not attempt to use the ckch but free it.
 *
 *  Return 0 on success or != 0 on failure
 */
int ssl_sock_load_pem_into_ckch(const char *path, char *buf, struct ckch_data *data , char **err)
{
	BIO *in = NULL;
	int ret = 1;
	X509 *ca;
	X509 *cert = NULL;
	EVP_PKEY *key = NULL;
	HASSL_DH *dh = NULL;
	STACK_OF(X509) *chain = NULL;
	struct issuer_chain *issuer_chain = NULL;

	if (buf) {
		/* reading from a buffer */
		in = BIO_new_mem_buf(buf, -1);
		if (in == NULL) {
			memprintf(err, "%sCan't allocate memory\n", err && *err ? *err : "");
			goto end;
		}

	} else {
		/* reading from a file */
		in = BIO_new(BIO_s_file());
		if (in == NULL) {
			memprintf(err, "%sCan't allocate memory\n", err && *err ? *err : "");
			goto end;
		}

		if (BIO_read_filename(in, path) <= 0) {
			memprintf(err, "%scannot open the file '%s'.\n",
			          err && *err ? *err : "", path);
			goto end;
		}
	}

	/* Read Private Key */
	key = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
	/* no need to check for errors here, because the private key could be loaded later */

#ifndef OPENSSL_NO_DH
	/* Seek back to beginning of file */
	if (BIO_reset(in) == -1) {
		memprintf(err, "%san error occurred while reading the file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

	dh = ssl_sock_get_dh_from_bio(in);
	ERR_clear_error();
	/* no need to return an error there, dh is not mandatory */
#endif

	/* Seek back to beginning of file */
	if (BIO_reset(in) == -1) {
		memprintf(err, "%san error occurred while reading the file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

	/* Read Certificate */
	cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
	if (cert == NULL) {
		ret = ERR_get_error();
		memprintf(err, "%sunable to load certificate from file '%s': %s.\n",
		          err && *err ? *err : "", path, ERR_reason_error_string(ret));
		goto end;
	}

	/* Look for a Certificate Chain */
	while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
		if (chain == NULL)
			chain = sk_X509_new_null();
		if (!sk_X509_push(chain, ca)) {
			X509_free(ca);
			break;
		}
	}

	/* If we couldn't find a chain, we should try to look for a corresponding chain in 'issuers-chain-path' */
	if (chain == NULL) {
		issuer_chain = ssl_get0_issuer_chain(cert);
		if (issuer_chain)
			chain = X509_chain_up_ref(issuer_chain->chain);
	}

	ret = ERR_get_error();
	if (ret && !(ERR_GET_LIB(ret) == ERR_LIB_PEM && ERR_GET_REASON(ret) == PEM_R_NO_START_LINE)) {
		memprintf(err, "%sunable to load certificate chain from file '%s': %s\n",
		          err && *err ? *err : "", path, ERR_reason_error_string(ret));
		goto end;
	}

	/* once it loaded the PEM, it should remove everything else in the data */
	if (data->ocsp_response) {
		ha_free(&data->ocsp_response->area);
		ha_free(&data->ocsp_response);
	}

	if (data->sctl) {
		ha_free(&data->sctl->area);
		ha_free(&data->sctl);
	}

	if (data->ocsp_issuer) {
		X509_free(data->ocsp_issuer);
		data->ocsp_issuer = NULL;
	}

	/* no error, fill data with new context, old context will be free at end: */
	SWAP(data->key, key);
	SWAP(data->dh, dh);
	SWAP(data->cert, cert);
	SWAP(data->chain, chain);
	SWAP(data->extra_chain, issuer_chain);

	ret = 0;

end:

	ERR_clear_error();
	if (in)
		BIO_free(in);
	if (key)
		EVP_PKEY_free(key);
	if (dh)
		HASSL_DH_free(dh);
	if (cert)
		X509_free(cert);
	if (chain)
		sk_X509_pop_free(chain, X509_free);

	return ret;
}

/* Frees the contents of a cert_key_and_chain
 */
void ssl_sock_free_cert_key_and_chain_contents(struct ckch_data *data)
{
	if (!data)
		return;

	/* Free the certificate and set pointer to NULL */
	if (data->cert)
		X509_free(data->cert);
	data->cert = NULL;

	/* Free the key and set pointer to NULL */
	if (data->key)
		EVP_PKEY_free(data->key);
	data->key = NULL;

	/* Free each certificate in the chain */
	if (data->chain)
		sk_X509_pop_free(data->chain, X509_free);
	data->chain = NULL;

	if (data->dh)
		HASSL_DH_free(data->dh);
	data->dh = NULL;

	if (data->sctl) {
		ha_free(&data->sctl->area);
		ha_free(&data->sctl);
	}

	if (data->ocsp_response) {
		ha_free(&data->ocsp_response->area);
		ha_free(&data->ocsp_response);
	}

	if (data->ocsp_issuer)
		X509_free(data->ocsp_issuer);
	data->ocsp_issuer = NULL;


	/* We need to properly remove the reference to the corresponding
	 * certificate_ocsp structure if it exists (which it should).
	 */
#if (defined(HAVE_SSL_OCSP) && !defined OPENSSL_IS_BORINGSSL)
	if (data->ocsp_cid) {
		struct certificate_ocsp *ocsp = NULL;
		unsigned char certid[OCSP_MAX_CERTID_ASN1_LENGTH] = {};
		unsigned int certid_length = 0;

		if (ssl_ocsp_build_response_key(data->ocsp_cid, (unsigned char*)certid, &certid_length) >= 0) {
			HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);
			ocsp = (struct certificate_ocsp *)ebmb_lookup(&cert_ocsp_tree, certid, OCSP_MAX_CERTID_ASN1_LENGTH);
			HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
			ssl_sock_free_ocsp(ocsp);
		}

		OCSP_CERTID_free(data->ocsp_cid);
		data->ocsp_cid = NULL;
	}
#endif
}

/*
 *
 * This function copy a cert_key_and_chain in memory
 *
 * It's used to try to apply changes on a ckch before committing them, because
 * most of the time it's not possible to revert those changes
 *
 * Return a the dst or NULL
 */
struct ckch_data *ssl_sock_copy_cert_key_and_chain(struct ckch_data *src,
                                                                   struct ckch_data *dst)
{
	if (!src || !dst)
		return NULL;

	if (src->cert) {
		dst->cert = src->cert;
		X509_up_ref(src->cert);
	}

	if (src->key) {
		dst->key = src->key;
		EVP_PKEY_up_ref(src->key);
	}

	if (src->chain) {
		dst->chain = X509_chain_up_ref(src->chain);
	}

	if (src->dh) {
#ifndef USE_OPENSSL_WOLFSSL
		HASSL_DH_up_ref(src->dh);
		dst->dh = src->dh;
#else
       dst->dh = wolfSSL_DH_dup(src->dh);
       if (!dst->dh)
           goto error;
#endif
	}

	if (src->sctl) {
		struct buffer *sctl;

		sctl = calloc(1, sizeof(*sctl));
		if (!chunk_dup(sctl, src->sctl)) {
			ha_free(&sctl);
			goto error;
		}
		dst->sctl = sctl;
	}

#ifdef HAVE_SSL_OCSP
	if (src->ocsp_response) {
		struct buffer *ocsp_response;

		ocsp_response = calloc(1, sizeof(*ocsp_response));
		if (!chunk_dup(ocsp_response, src->ocsp_response)) {
			ha_free(&ocsp_response);
			goto error;
		}
		dst->ocsp_response = ocsp_response;
	}

	if (src->ocsp_issuer) {
		X509_up_ref(src->ocsp_issuer);
		dst->ocsp_issuer = src->ocsp_issuer;
	}
	dst->ocsp_cid = OCSP_CERTID_dup(src->ocsp_cid);
#endif
	return dst;

error:

	/* free everything */
	ssl_sock_free_cert_key_and_chain_contents(dst);

	return NULL;
}

/*
 * return 0 on success or != 0 on failure
 */
int ssl_sock_load_issuer_file_into_ckch(const char *path, char *buf, struct ckch_data *data, char **err)
{
	int ret = 1;
	BIO *in = NULL;
	X509 *issuer;

	if (buf) {
		/* reading from a buffer */
		in = BIO_new_mem_buf(buf, -1);
		if (in == NULL) {
			memprintf(err, "%sCan't allocate memory\n", err && *err ? *err : "");
			goto end;
		}

	} else {
		/* reading from a file */
		in = BIO_new(BIO_s_file());
		if (in == NULL)
			goto end;

		if (BIO_read_filename(in, path) <= 0)
			goto end;
	}

	issuer = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
	if (!issuer) {
		memprintf(err, "%s'%s' cannot be read or parsed'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}
	/* no error, fill data with new context, old context must be free */
	if (data->ocsp_issuer)
		X509_free(data->ocsp_issuer);
	data->ocsp_issuer = issuer;
	ret = 0;

end:

	ERR_clear_error();
	if (in)
		BIO_free(in);

	return ret;
}

/********************  ckch_store functions ***********************************
 * The ckch_store is a structure used to cache and index the SSL files used in
 * configuration
 */

/*
 * Free a ckch_store, its ckch, its instances and remove it from the ebtree
 */
void ckch_store_free(struct ckch_store *store)
{
	struct ckch_inst *inst, *inst_s;

	if (!store)
		return;

	list_for_each_entry_safe(inst, inst_s, &store->ckch_inst, by_ckchs) {
		ckch_inst_free(inst);
	}
	ebmb_delete(&store->node);

	ssl_sock_free_cert_key_and_chain_contents(store->data);
	ha_free(&store->data);

	/* free the ckch_conf content */
	ckch_conf_clean(&store->conf);

	free(store);
}

/*
 * create and initialize a ckch_store
 * <path> is the key name
 * <nmemb> is the number of store->ckch objects to allocate
 *
 * Return a ckch_store or NULL upon failure.
 */
struct ckch_store *ckch_store_new(const char *filename)
{
	struct ckch_store *store;
	int pathlen;

	pathlen = strlen(filename);
	store = calloc(1, sizeof(*store) + pathlen + 1);
	if (!store)
		return NULL;

	memcpy(store->path, filename, pathlen + 1);

	LIST_INIT(&store->ckch_inst);
	LIST_INIT(&store->crtlist_entry);

	store->data = calloc(1, sizeof(*store->data));
	if (!store->data)
		goto error;

	return store;
error:
	ckch_store_free(store);
	return NULL;
}

/* allocate and duplicate a ckch_store
 * Return a new ckch_store or NULL */
struct ckch_store *ckchs_dup(const struct ckch_store *src)
{
	struct ckch_store *dst;

	if (!src)
		return NULL;

	dst = ckch_store_new(src->path);
	if (!dst)
		return NULL;

	if (!ssl_sock_copy_cert_key_and_chain(src->data, dst->data))
		goto error;


	dst->conf.ocsp_update_mode = src->conf.ocsp_update_mode;

	return dst;

error:
	ckch_store_free(dst);

	return NULL;
}

/*
 * lookup a path into the ckchs tree.
 */
struct ckch_store *ckchs_lookup(char *path)
{
	struct ebmb_node *eb;

	eb = ebst_lookup(&ckchs_tree, path);
	if (!eb)
		return NULL;

	return ebmb_entry(eb, struct ckch_store, node);
}

/*
 * This function allocate a ckch_store and populate it with certificates from files.
 */
struct ckch_store *ckch_store_new_load_files_path(char *path, char **err)
{
	struct ckch_store *ckchs;

	ckchs = ckch_store_new(path);
	if (!ckchs) {
		memprintf(err, "%sunable to allocate memory.\n", err && *err ? *err : "");
		goto end;
	}

	if (ssl_sock_load_files_into_ckch(path, ckchs->data, err) == 1)
		goto end;

	ckchs->conf.used = CKCH_CONF_SET_EMPTY;

	/* insert into the ckchs tree */
	memcpy(ckchs->path, path, strlen(path) + 1);
	ebst_insert(&ckchs_tree, &ckchs->node);
	return ckchs;

end:
	ckch_store_free(ckchs);

	return NULL;
}

/*
 * This function allocate a ckch_store and populate it with certificates using
 * the ckch_conf structure.
 */
struct ckch_store *ckch_store_new_load_files_conf(char *name, struct ckch_conf *conf, char **err)
{
	struct ckch_store *ckchs;
	int cfgerr = ERR_NONE;
	char *tmpcrt = conf->crt;

	ckchs = ckch_store_new(name);
	if (!ckchs) {
		memprintf(err, "%sunable to allocate memory.\n", err && *err ? *err : "");
		goto end;
	}

	/* this is done for retro-compatibility. When no "filename" crt-store
	 * options were configured in a crt-list, try to load the files by
	 * auto-detecting them. */
	if ((conf->used == CKCH_CONF_SET_EMPTY || conf->used == CKCH_CONF_SET_CRTLIST) &&
		(!conf->key && !conf->ocsp && !conf->issuer && !conf->sctl)) {
		cfgerr = ssl_sock_load_files_into_ckch(conf->crt, ckchs->data, err);
		if (cfgerr & ERR_FATAL)
			goto end;
		/* set conf->crt to NULL so it's not erased */
		conf->crt = NULL;
	}

	/* load files using the ckch_conf */
	cfgerr = ckch_store_load_files(conf, ckchs, 0, err);
	if (cfgerr & ERR_FATAL)
		goto end;

	conf->crt = tmpcrt;

	/* insert into the ckchs tree */
	memcpy(ckchs->path, name, strlen(name) + 1);
	ebst_insert(&ckchs_tree, &ckchs->node);
	return ckchs;

end:
	ckch_store_free(ckchs);

	return NULL;
}

/********************  ckch_inst functions ******************************/

/* unlink a ckch_inst, free all SNIs, free the ckch_inst */
/* The caller must use the lock of the bind_conf if used with inserted SNIs */
void ckch_inst_free(struct ckch_inst *inst)
{
	struct sni_ctx *sni, *sni_s;
	struct ckch_inst_link_ref *link_ref, *link_ref_s;

	if (inst == NULL)
		return;

	list_for_each_entry_safe(sni, sni_s, &inst->sni_ctx, by_ckch_inst) {
		SSL_CTX_free(sni->ctx);
		LIST_DELETE(&sni->by_ckch_inst);
		ebmb_delete(&sni->name);
		free(sni);
	}
	SSL_CTX_free(inst->ctx);
	inst->ctx = NULL;
	LIST_DELETE(&inst->by_ckchs);
	LIST_DELETE(&inst->by_crtlist_entry);

	/* Free the cafile_link_refs list */
	list_for_each_entry_safe(link_ref, link_ref_s, &inst->cafile_link_refs, list) {
		if (link_ref->link && LIST_INLIST(&link_ref->link->list)) {
			/* Try to detach and free the ckch_inst_link only if it
			 * was attached, this way it can be used to loop from
			 * the caller */
			LIST_DEL_INIT(&link_ref->link->list);
			ha_free(&link_ref->link);
		}
		LIST_DELETE(&link_ref->list);
		free(link_ref);
	}

	free(inst);
}

/* Alloc and init a ckch_inst */
struct ckch_inst *ckch_inst_new()
{
	struct ckch_inst *ckch_inst;

	ckch_inst = calloc(1, sizeof *ckch_inst);
	if (!ckch_inst)
		return NULL;

	LIST_INIT(&ckch_inst->sni_ctx);
	LIST_INIT(&ckch_inst->by_ckchs);
	LIST_INIT(&ckch_inst->by_crtlist_entry);
	LIST_INIT(&ckch_inst->cafile_link_refs);

	return ckch_inst;
}


/********************  ssl_store functions ******************************/
struct eb_root cafile_tree = EB_ROOT;

/*
 * Returns the cafile_entry found in the cafile_tree indexed by the path 'path'.
 * If 'oldest_entry' is 1, returns the "original" cafile_entry (since
 * during a set cafile/commit cafile cycle there might be two entries for any
 * given path, the original one and the new one set via the CLI but not
 * committed yet).
 */
struct cafile_entry *ssl_store_get_cafile_entry(char *path, int oldest_entry)
{
	struct cafile_entry *ca_e = NULL;
	struct ebmb_node *eb;

	eb = ebst_lookup(&cafile_tree, path);
	while (eb) {
		ca_e = ebmb_entry(eb, struct cafile_entry, node);
		/* The ebst_lookup in a tree that has duplicates returns the
		 * oldest entry first. If we want the latest entry, we need to
		 * iterate over all the duplicates until we find the last one
		 * (in our case there should never be more than two entries for
		 * any given path). */
		if (oldest_entry)
			return ca_e;
		eb = ebmb_next_dup(eb);
	}
	return ca_e;
}

int ssl_store_add_uncommitted_cafile_entry(struct cafile_entry *entry)
{
	return (ebst_insert(&cafile_tree, &entry->node) != &entry->node);
}

X509_STORE* ssl_store_get0_locations_file(char *path)
{
	struct cafile_entry *ca_e = ssl_store_get_cafile_entry(path, 0);

	if (ca_e)
		return ca_e->ca_store;

	return NULL;
}

/* Create a cafile_entry object, without adding it to the cafile_tree. */
struct cafile_entry *ssl_store_create_cafile_entry(char *path, X509_STORE *store, enum cafile_type type)
{
	struct cafile_entry *ca_e;
	int pathlen;

	pathlen = strlen(path);

	ca_e = calloc(1, sizeof(*ca_e) + pathlen + 1);
	if (ca_e) {
		memcpy(ca_e->path, path, pathlen + 1);
		ca_e->ca_store = store;
		ca_e->type = type;
		LIST_INIT(&ca_e->ckch_inst_link);
	}
	return ca_e;
}


/* Duplicate a cafile_entry
 * Allocate the X509_STORE and copy the X509 and CRL inside.
 *
 * Return the newly allocated cafile_entry or NULL.
 *
 */
struct cafile_entry *ssl_store_dup_cafile_entry(struct cafile_entry *src)
{
	struct cafile_entry *dst = NULL;
	X509_STORE *store = NULL;
	STACK_OF(X509_OBJECT) *objs;
	int i;

	if (!src)
		return NULL;

	if (src->ca_store) {
		/* if there was a store in the src, copy it */
		store = X509_STORE_new();
		if (!store)
			goto err;

		objs = X509_STORE_get0_objects(src->ca_store);
		for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
			X509 *cert;
			X509_CRL *crl;

			cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
			if (cert) {
				if (X509_STORE_add_cert(store, cert) == 0) {
					/* only exits on error if the error is not about duplicate certificates */
					if (!(ERR_GET_REASON(ERR_get_error()) == X509_R_CERT_ALREADY_IN_HASH_TABLE)) {
						goto err;
					}
				}

			}
			crl = X509_OBJECT_get0_X509_CRL(sk_X509_OBJECT_value(objs, i));
			if (crl) {
				if (X509_STORE_add_crl(store, crl) == 0) {
					/* only exits on error if the error is not about duplicate certificates */
					if (!(ERR_GET_REASON(ERR_get_error()) == X509_R_CERT_ALREADY_IN_HASH_TABLE)) {
						goto err;
					}
				}

			}
		}
	}
	dst = ssl_store_create_cafile_entry(src->path, store, src->type);

	return dst;

err:
	X509_STORE_free(store);
	ha_free(&dst);

	return NULL;
}

/* Delete a cafile_entry. The caller is responsible from removing this entry
 * from the cafile_tree first if is was previously added into it. */
void ssl_store_delete_cafile_entry(struct cafile_entry *ca_e)
{
	struct ckch_inst_link *link, *link_s;
	if (!ca_e)
		return;

	X509_STORE_free(ca_e->ca_store);

	list_for_each_entry_safe(link, link_s, &ca_e->ckch_inst_link, list) {
		struct ckch_inst *inst = link->ckch_inst;
		struct ckch_inst_link_ref *link_ref, *link_ref_s;
		list_for_each_entry_safe(link_ref, link_ref_s, &inst->cafile_link_refs, list) {
			if (link_ref->link == link) {
				LIST_DELETE(&link_ref->list);
				free(link_ref);
				break;
			}
		}
		LIST_DELETE(&link->list);
		free(link);
	}

	free(ca_e);
}

/*
 * Fill a cafile_entry <ca_e> X509_STORE ca_e->store out of a buffer <cert_buf>
 * instead of out of a file. The <append> field should be set to 1 if you want
 * to keep the existing X509_STORE and append data to it.
 *
 * This function is used when the "set ssl ca-file" cli command is used.
 * It can parse CERTIFICATE sections as well as CRL ones.
 * Returns 0 in case of success, 1 otherwise.
 *
 * /!\ Warning: If there was an error the X509_STORE could have been modified so it's
 * better to not use it after a return 1.
 */
int ssl_store_load_ca_from_buf(struct cafile_entry *ca_e, char *cert_buf, int append)
{
	BIO *bio = NULL;
	STACK_OF(X509_INFO) *infos;
	X509_INFO *info;
	int i;
	int retval = 1;
	int retcert = 0;

	if (!ca_e)
		return 1;

	if (!append) {
		X509_STORE_free(ca_e->ca_store);
		ca_e->ca_store = NULL;
	}

	if (!ca_e->ca_store)
		ca_e->ca_store = X509_STORE_new();

	if (!ca_e->ca_store)
		goto end;

	bio = BIO_new_mem_buf(cert_buf, strlen(cert_buf));
	if (!bio)
		goto end;

	infos = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
	if (!infos)
		goto end;

	for (i = 0; i < sk_X509_INFO_num(infos) && !retcert; i++) {
		info = sk_X509_INFO_value(infos, i);

		/* X509_STORE_add_cert and X509_STORE_add_crl return 1 on success */
		if (info->x509)
			retcert = !X509_STORE_add_cert(ca_e->ca_store, info->x509);
		if (!retcert && info->crl)
			retcert = !X509_STORE_add_crl(ca_e->ca_store, info->crl);
	}

	/* return an error if we didn't compute all the X509_INFO or if there was none
	 * set to 0 if everything was right */
	if (!(retcert || (i != sk_X509_INFO_num(infos)) || (sk_X509_INFO_num(infos) == 0)))
		retval = 0;

	/* Cleanup */
	sk_X509_INFO_pop_free(infos, X509_INFO_free);

end:
	BIO_free(bio);

	return retval;
}

/*
 * Try to load a ca-file from disk into the ca-file cache.
 *  <shuterror> allows you to to stop emitting the errors.
 *  Return 0 upon error
 */
int __ssl_store_load_locations_file(char *path, int create_if_none, enum cafile_type type, int shuterror)
{
	X509_STORE *store = ssl_store_get0_locations_file(path);

	/* If this function is called by the CLI, we should not call the
	 * X509_STORE_load_locations function because it performs forbidden disk
	 * accesses. */
	if (!store && create_if_none) {
		STACK_OF(X509_OBJECT) *objs;
		int cert_count = 0;
		struct stat buf;
		struct cafile_entry *ca_e;
		const char *file = NULL;
		const char *dir = NULL;
		unsigned long e;

		store = X509_STORE_new();
		if (!store) {
			if (!shuterror)
				ha_alert("Cannot allocate memory!\n");
			goto err;
		}

		if (strcmp(path, "@system-ca") == 0) {
			dir = X509_get_default_cert_dir();
			if (!dir) {
				if (!shuterror)
					ha_alert("Couldn't get the system CA directory from X509_get_default_cert_dir().\n");
				goto err;
			}

		} else {

			if (stat(path, &buf) == -1) {
				if (!shuterror)
					ha_alert("Couldn't open the ca-file '%s' (%s).\n", path, strerror(errno));
				goto err;
			}

			if (S_ISDIR(buf.st_mode))
				dir = path;
			else
				file = path;
		}

		if (file) {
			if (!X509_STORE_load_locations(store, file, NULL)) {
				e = ERR_get_error();
				if (!shuterror)
					ha_alert("Couldn't open the ca-file '%s' (%s).\n", path, ERR_reason_error_string(e));
				goto err;
			}
		} else if (dir) {
			int n, i;
			struct dirent **de_list;

			n = scandir(dir, &de_list, 0, alphasort);
			if (n < 0)
				goto err;

			for (i= 0; i < n; i++) {
				char *end;
				struct dirent *de = de_list[i];
				BIO *in = NULL;
				X509 *ca = NULL;;

				ERR_clear_error();

				/* we try to load the files that would have
				 * been loaded in an hashed directory loaded by
				 * X509_LOOKUP_hash_dir, so according to "man 1
				 * c_rehash", we should load  ".pem", ".crt",
				 * ".cer", or ".crl". Files starting with a dot
				 * are ignored.
				 */
				end = strrchr(de->d_name, '.');
				if (!end || de->d_name[0] == '.' ||
				    (strcmp(end, ".pem") != 0 &&
				     strcmp(end, ".crt") != 0 &&
				     strcmp(end, ".cer") != 0 &&
				     strcmp(end, ".crl") != 0)) {
					free(de);
					continue;
				}
				in = BIO_new(BIO_s_file());
				if (in == NULL)
					goto scandir_err;

				chunk_printf(&trash, "%s/%s", dir, de->d_name);

				if (BIO_read_filename(in, trash.area) == 0)
					goto scandir_err;

				if (PEM_read_bio_X509_AUX(in, &ca, NULL, NULL) == NULL)
					goto scandir_err;

				if (X509_STORE_add_cert(store, ca) == 0) {
					/* only exits on error if the error is not about duplicate certificates */
					 if (!(ERR_GET_REASON(ERR_get_error()) == X509_R_CERT_ALREADY_IN_HASH_TABLE)) {
						 goto scandir_err;
					 }
				}

				X509_free(ca);
				BIO_free(in);
				free(de);
				continue;

scandir_err:
				e = ERR_get_error();
				X509_free(ca);
				BIO_free(in);
				free(de);
				/* warn if it can load one of the files, but don't abort */
				if (!shuterror)
					ha_warning("ca-file: '%s' couldn't load '%s' (%s)\n", path, trash.area, ERR_reason_error_string(e));

			}
			free(de_list);
		} else {
			if (!shuterror)
				ha_alert("ca-file: couldn't load '%s'\n", path);
			goto err;
		}

		if (ssl_commit_crlfile_cb != NULL) {
			if (ssl_commit_crlfile_cb(path, store, NULL) == -1) {
				if (!shuterror)
					ha_alert("crl-file: couldn't load '%s'\n", path);
				goto err;
			}
		}

		objs = X509_STORE_get0_objects(store);
		cert_count = sk_X509_OBJECT_num(objs);
		if (cert_count == 0) {
			if (!shuterror)
				ha_warning("ca-file: 0 CA were loaded from '%s'\n", path);
		}
		ca_e = ssl_store_create_cafile_entry(path, store, type);
		if (!ca_e) {
			if (!shuterror)
				ha_alert("Cannot allocate memory!\n");
			goto err;
		}
		ebst_insert(&cafile_tree, &ca_e->node);
	}
	return (store != NULL);

err:
	X509_STORE_free(store);
	store = NULL;
	return 0;

}

int ssl_store_load_locations_file(char *path, int create_if_none, enum cafile_type type)
{
	return __ssl_store_load_locations_file(path, create_if_none, type, 0);
}

/*************************** CLI commands ***********************/

/* Type of SSL payloads that can be updated over the CLI */

struct cert_exts cert_exts[] = {
	{ "",        CERT_TYPE_PEM,      &ssl_sock_load_pem_into_ckch }, /* default mode, no extensions */
	{ "key",     CERT_TYPE_KEY,      &ssl_sock_load_key_into_ckch },
#if defined(HAVE_SSL_OCSP)
	{ "ocsp",    CERT_TYPE_OCSP,     &ssl_sock_load_ocsp_response_from_file },
#endif
#ifdef HAVE_SSL_SCTL
	{ "sctl",    CERT_TYPE_SCTL,     &ssl_sock_load_sctl_from_file },
#endif
	{ "issuer",  CERT_TYPE_ISSUER,   &ssl_sock_load_issuer_file_into_ckch },
	{ NULL,      CERT_TYPE_MAX,      NULL },
};

/* release function of the  `show ssl sni' command */
static void cli_release_show_sni(struct appctx *appctx)
{
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
}

/* IO handler of "show ssl sni [<frontend>]".
 * It makes use of a show_sni_ctx context
 *
 * The fonction does loop over the frontend, the bind_conf and the sni_ctx.
 */
static int cli_io_handler_show_sni(struct appctx *appctx)
{
	struct show_sni_ctx *ctx = appctx->svcctx;
	struct buffer *trash = alloc_trash_chunk();
	struct ebmb_node *n = NULL;
	int type = 0;
	struct bind_conf *bind = NULL;
	struct proxy *px = NULL;

	if (trash == NULL)
		return 1;

	/* ctx->bind is NULL only once we finished dumping a frontend or when starting
	 * so let's dump the header in these cases*/
	if (ctx->bind == NULL && (ctx->options & SHOW_SNI_OPT_1FRONTEND ||
	    (!(ctx->options & SHOW_SNI_OPT_1FRONTEND) && ctx->px == proxies_list)))
		chunk_appendf(trash, "# Frontend/Bind\tSNI\tNegative Filter\tType\tFilename\tNotAfter\tNotBefore\n");
	if (applet_putchk(appctx, trash) == -1)
		goto yield;

	for (px = ctx->px; px; px = px->next) {

		/* only check the frontends which are not internal proxies */
		if (!(px->cap & PR_CAP_FE) || (px->cap & PR_CAP_INT))
			continue;

		bind = ctx->bind;
		/* if we didn't get a bind from the previous yield */
		if (!bind)
			bind = LIST_ELEM(px->conf.bind.n, typeof(bind), by_fe);

		list_for_each_entry_from(bind, &px->conf.bind, by_fe) {

			HA_RWLOCK_RDLOCK(SNI_LOCK, &bind->sni_lock);

			/* do this twice: once for the standard SNI and once for wildcards */
			for (type = ctx->nodetype; type < 2; type++) {

				n = ctx->n; /* get the node from previous yield */

				if (!n) {
					if (type == 0)
						n = ebmb_first(&bind->sni_ctx);
					else
						n = ebmb_first(&bind->sni_w_ctx);
				}
				/* emty SNI tree, skip */
				if (!n)
					continue;

				for (; n; n = ebmb_next(n)) {
					struct sni_ctx *sni;
					const char *name;
					const char *certalg;
					int isneg = 0; /* is there any negative filters associated to this node */

					sni = ebmb_entry(n, struct sni_ctx, name);

					if (sni->neg)
						continue;
#ifdef HAVE_ASN1_TIME_TO_TM
					if (ctx->options & SHOW_SNI_OPT_NOTAFTER) {
						time_t notAfter = x509_get_notafter_time_t(sni->ckch_inst->ckch_store->data->cert);
						if (!(date.tv_sec > notAfter))
							continue;
					}
#endif

					chunk_appendf(trash, "%s/%s:%d\t", bind->frontend->id, bind->file, bind->line);

					name = (char *)sni->name.key;

					chunk_appendf(trash, "%s%s%s\t", sni->neg ? "!" : "", type ? "*" : "",  name);

					/* we are looking at wildcards, let's check the negative filters */
					if (type == 1) {
						struct sni_ctx *sni_tmp;
						list_for_each_entry(sni_tmp, &sni->ckch_inst->sni_ctx, by_ckch_inst) {
							if (sni_tmp->neg) {
								chunk_appendf(trash, "%s%s ", sni_tmp->neg ? "!" : "",  (char *)sni_tmp->name.key);
								isneg = 1;
							}
						}
					}
					chunk_appendf(trash, "%s\t", isneg ? "" : "-");

					switch (sni->kinfo.sig) {
						case TLSEXT_signature_ecdsa:
							certalg = "ecdsa";
							break;
						case TLSEXT_signature_rsa:
							certalg = "rsa";
							break;
						default: /* TLSEXT_signature_anonymous|dsa */
							certalg = "dsa";
							break;
					}

					chunk_appendf(trash, "%s\t", certalg);

					/* we need to lock so the certificates in the ckch are not modified during the listing */
					chunk_appendf(trash, "%s\t", sni->ckch_inst->ckch_store->path);
					chunk_appendf(trash, "%s\t", x509_get_notafter(sni->ckch_inst->ckch_store->data->cert));
					chunk_appendf(trash, "%s\n", x509_get_notbefore(sni->ckch_inst->ckch_store->data->cert));

					if (applet_putchk(appctx, trash) == -1) {
						HA_RWLOCK_RDUNLOCK(SNI_LOCK, &bind->sni_lock);
						goto yield;
					}

				}
				ctx->n = NULL;
			}
			ctx->nodetype = 0;
			HA_RWLOCK_RDUNLOCK(SNI_LOCK, &bind->sni_lock);

		}
		ctx->bind = NULL;
		/* only want to display the specified frontend */
		if (ctx->options & SHOW_SNI_OPT_1FRONTEND)
			break;
	}
	ctx->px = NULL;

	free_trash_chunk(trash);
	return 1;
yield:

	ctx->px = px;
	ctx->bind = bind;
	ctx->n = n;
	ctx->nodetype = type;

	free_trash_chunk(trash);
	return 0; /* should come back */
}


/* parsing function for 'show ssl sni [-f <frontend>] [-A]' */
static int cli_parse_show_sni(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_sni_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	int cur_arg = 3;

	ctx->px = proxies_list;

	/* look for the right <frontend> to display */

	while (*args[cur_arg]) {
		struct proxy *px;

		if (strcmp(args[cur_arg], "-f") == 0) {

			if (*args[cur_arg+1] == '\0')
				return cli_err(appctx, "'-f' requires a frontend name!\n");

			for (px = proxies_list; px; px = px->next) {

				/* only check the frontends */
				if (!(px->cap & PR_CAP_FE))
					continue;

				/* skip the internal proxies */
				if (px->cap & PR_CAP_INT)
					continue;

				if (strcmp(px->id, args[cur_arg+1]) == 0) {
					ctx->px = px;
					ctx->options |= SHOW_SNI_OPT_1FRONTEND;
				}
			}
			cur_arg++; /* skip the argument */
			if (ctx->px == NULL)
				return cli_err(appctx, "Couldn't find the specified frontend!\n");

		} else if (strcmp(args[cur_arg], "-A") == 0) {
			/* when current date > notAfter */
			ctx->options |= SHOW_SNI_OPT_NOTAFTER;
#ifndef HAVE_ASN1_TIME_TO_TM
			return cli_err(appctx, "'-A' option is only supported with OpenSSL >= 1.1.1!\n");
#endif

		} else {

			return cli_err(appctx, "Invalid parameters, 'show ssl sni' only supports '-f', or '-A' options!\n");
		}
		cur_arg++;
	}

	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't list SNIs\nOperations on certificates are currently locked!\n");

	return 0;
}

/* release function of the  `show ssl cert' command */
static void cli_release_show_cert(struct appctx *appctx)
{
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
}

/* IO handler of "show ssl cert <filename>".
 * It makes use of a show_cert_ctx context, and ckchs_transaction in read-only.
 */
static int cli_io_handler_show_cert(struct appctx *appctx)
{
	struct show_cert_ctx *ctx = appctx->svcctx;
	struct buffer *trash = alloc_trash_chunk();
	struct ebmb_node *node;
	struct ckch_store *ckchs = NULL;

	if (trash == NULL)
		return 1;

	if (!ctx->old_ckchs && ckchs_transaction.old_ckchs) {
		ckchs = ckchs_transaction.old_ckchs;
		chunk_appendf(trash, "# transaction\n");
		chunk_appendf(trash, "*%s\n", ckchs->path);
		if (applet_putchk(appctx, trash) == -1)
			goto yield;
		ctx->old_ckchs = ckchs_transaction.old_ckchs;
	}

	if (!ctx->cur_ckchs) {
		chunk_appendf(trash, "# filename\n");
		node = ebmb_first(&ckchs_tree);
	} else {
		node = &ctx->cur_ckchs->node;
	}
	while (node) {
		ckchs = ebmb_entry(node, struct ckch_store, node);
		chunk_appendf(trash, "%s\n", ckchs->path);

		node = ebmb_next(node);
		if (applet_putchk(appctx, trash) == -1)
			goto yield;
	}

	ctx->cur_ckchs = NULL;
	free_trash_chunk(trash);
	return 1;
yield:

	free_trash_chunk(trash);
	ctx->cur_ckchs = ckchs;
	return 0; /* should come back */
}

/*
 * Extract and format the DNS SAN extensions and copy result into a chuink
 * Return 0;
 */
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static int ssl_sock_get_san_oneline(X509 *cert, struct buffer *out)
{
	int i;
	char *str;
	STACK_OF(GENERAL_NAME) *names = NULL;

	names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (names) {
		for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
			GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
			if (i > 0)
				chunk_appendf(out, ", ");
			if (name->type == GEN_DNS) {
				if (ASN1_STRING_to_UTF8((unsigned char **)&str, name->d.dNSName) >= 0) {
					chunk_appendf(out, "DNS:%s", str);
					OPENSSL_free(str);
				}
			}
		}
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
	}
	return 0;
}
#endif

/*
 * Build the ckch_inst_link that will be chained in the CA file entry and the
 * corresponding ckch_inst_link_ref that will be chained in the ckch instance.
 * Return 0 in case of success.
 */
static int do_chain_inst_and_cafile(struct cafile_entry *cafile_entry, struct ckch_inst *ckch_inst)
{
	struct ckch_inst_link *new_link;
	if (!LIST_ISEMPTY(&cafile_entry->ckch_inst_link)) {
		struct ckch_inst_link *link = LIST_ELEM(cafile_entry->ckch_inst_link.n,
							typeof(link), list);
		/* Do not add multiple references to the same
		 * instance in a cafile_entry */
		if (link->ckch_inst == ckch_inst) {
			return 1;
		}
	}

	new_link = calloc(1, sizeof(*new_link));
	if (new_link) {
		struct ckch_inst_link_ref *new_link_ref = calloc(1, sizeof(*new_link_ref));
		if (!new_link_ref) {
			free(new_link);
			return 1;
		}

		new_link->ckch_inst = ckch_inst;
		new_link_ref->link = new_link;
		LIST_INIT(&new_link->list);
		LIST_INIT(&new_link_ref->list);

		LIST_APPEND(&cafile_entry->ckch_inst_link, &new_link->list);
		LIST_APPEND(&ckch_inst->cafile_link_refs, &new_link_ref->list);
	}

	return 0;
}


/*
 * Link a CA file tree entry to the ckch instance that uses it.
 * To determine if and which CA file tree entries need to be linked to the
 * instance, we follow the same logic performed in ssl_sock_prepare_ctx when
 * processing the verify option.
 * This function works for a frontend as well as for a backend, depending on the
 * configuration parameters given (bind_conf or server).
 */
void ckch_inst_add_cafile_link(struct ckch_inst *ckch_inst, struct bind_conf *bind_conf,
			       struct ssl_bind_conf *ssl_conf, const struct server *srv)
{
	int verify = SSL_VERIFY_NONE;

	if (srv) {

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
	}
	else {
		switch ((ssl_conf && ssl_conf->verify) ? ssl_conf->verify : bind_conf->ssl_conf.verify) {
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
	}

	if (verify & SSL_VERIFY_PEER) {
		struct cafile_entry *ca_file_entry = NULL;
		struct cafile_entry *ca_verify_file_entry = NULL;
		struct cafile_entry *crl_file_entry = NULL;
		if (srv) {
			if (srv->ssl_ctx.ca_file) {
				ca_file_entry = ssl_store_get_cafile_entry(srv->ssl_ctx.ca_file, 0);

			}
			if (srv->ssl_ctx.crl_file) {
				crl_file_entry = ssl_store_get_cafile_entry(srv->ssl_ctx.crl_file, 0);
			}
		}
		else {
			char *ca_file = (ssl_conf && ssl_conf->ca_file) ? ssl_conf->ca_file : bind_conf->ssl_conf.ca_file;
			char *ca_verify_file = (ssl_conf && ssl_conf->ca_verify_file) ? ssl_conf->ca_verify_file : bind_conf->ssl_conf.ca_verify_file;
			char *crl_file = (ssl_conf && ssl_conf->crl_file) ? ssl_conf->crl_file : bind_conf->ssl_conf.crl_file;

			if (ca_file)
				ca_file_entry = ssl_store_get_cafile_entry(ca_file, 0);
			if (ca_verify_file)
				ca_verify_file_entry = ssl_store_get_cafile_entry(ca_verify_file, 0);
			if (crl_file)
				crl_file_entry = ssl_store_get_cafile_entry(crl_file, 0);
		}

		if (ca_file_entry) {
			/* If we have a ckch instance that is not already in the
			 * cafile_entry's list, add it to it. */
			if (do_chain_inst_and_cafile(ca_file_entry, ckch_inst))
				return;

		}
		if (ca_verify_file_entry && (ca_file_entry != ca_verify_file_entry)) {
			/* If we have a ckch instance that is not already in the
			 * cafile_entry's list, add it to it. */
			if (do_chain_inst_and_cafile(ca_verify_file_entry, ckch_inst))
				return;
		}
		if (crl_file_entry) {
			/* If we have a ckch instance that is not already in the
			 * cafile_entry's list, add it to it. */
			if (do_chain_inst_and_cafile(crl_file_entry, ckch_inst))
				return;
		}
	}
}



static int show_cert_detail(X509 *cert, STACK_OF(X509) *chain, struct issuer_chain *extra_chain, struct buffer *out)
{
	BIO *bio = NULL;
	struct buffer *tmp = alloc_trash_chunk();
	int i;
	int write = -1;
	unsigned int len = 0;
	X509_NAME *name = NULL;

	if (!tmp)
		return -1;

	if (!cert)
		goto end;

	if (extra_chain) {
		chunk_appendf(out, "Chain Filename: ");
		chunk_appendf(out, "%s\n", extra_chain->path);
	}

	chunk_appendf(out, "Serial: ");
	if (ssl_sock_get_serial(cert, tmp) == -1)
		goto end;
	dump_binary(out, tmp->area, tmp->data);
	chunk_appendf(out, "\n");

	chunk_appendf(out, "notBefore: ");
	chunk_reset(tmp);
	if ((bio = BIO_new(BIO_s_mem())) ==  NULL)
		goto end;
	if (ASN1_TIME_print(bio, X509_getm_notBefore(cert)) == 0)
		goto end;
	write = BIO_read(bio, tmp->area, tmp->size-1);
	tmp->area[write] = '\0';
	BIO_free(bio);
	bio = NULL;
	chunk_appendf(out, "%s\n", tmp->area);

	chunk_appendf(out, "notAfter: ");
	chunk_reset(tmp);
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		goto end;
	if (ASN1_TIME_print(bio, X509_getm_notAfter(cert)) == 0)
		goto end;
	if ((write = BIO_read(bio, tmp->area, tmp->size-1)) <= 0)
		goto end;
	tmp->area[write] = '\0';
	BIO_free(bio);
	bio = NULL;
	chunk_appendf(out, "%s\n", tmp->area);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	chunk_appendf(out, "Subject Alternative Name: ");
	if (ssl_sock_get_san_oneline(cert, out) == -1)
		goto end;
	*(out->area + out->data) = '\0';
	chunk_appendf(out, "\n");
#endif
	chunk_reset(tmp);
	chunk_appendf(out, "Algorithm: ");
	if (cert_get_pkey_algo(cert, tmp) == 0)
		goto end;
	chunk_appendf(out, "%s\n", tmp->area);

	chunk_reset(tmp);
	chunk_appendf(out, "SHA1 FingerPrint: ");
	if (X509_digest(cert, EVP_sha1(), (unsigned char *) tmp->area, &len) == 0)
		goto end;
	tmp->data = len;
	dump_binary(out, tmp->area, tmp->data);
	chunk_appendf(out, "\n");

	chunk_appendf(out, "Subject: ");
	if ((name = X509_get_subject_name(cert)) == NULL)
		goto end;
	if ((ssl_sock_get_dn_oneline(name, tmp)) == -1)
		goto end;
	*(tmp->area + tmp->data) = '\0';
	chunk_appendf(out, "%s\n", tmp->area);

	chunk_appendf(out, "Issuer: ");
	if ((name = X509_get_issuer_name(cert)) == NULL)
		goto end;
	if ((ssl_sock_get_dn_oneline(name, tmp)) == -1)
		goto end;
	*(tmp->area + tmp->data) = '\0';
	chunk_appendf(out, "%s\n", tmp->area);

	/* Displays subject of each certificate in the chain */
	for (i = 0; i < sk_X509_num(chain); i++) {
		X509 *ca = sk_X509_value(chain, i);

		chunk_appendf(out, "Chain Subject: ");
		if ((name = X509_get_subject_name(ca)) == NULL)
			goto end;
		if ((ssl_sock_get_dn_oneline(name, tmp)) == -1)
			goto end;
		*(tmp->area + tmp->data) = '\0';
		chunk_appendf(out, "%s\n", tmp->area);

		chunk_appendf(out, "Chain Issuer: ");
		if ((name = X509_get_issuer_name(ca)) == NULL)
			goto end;
		if ((ssl_sock_get_dn_oneline(name, tmp)) == -1)
			goto end;
		*(tmp->area + tmp->data) = '\0';
		chunk_appendf(out, "%s\n", tmp->area);
	}

end:
	if (bio)
		BIO_free(bio);
	free_trash_chunk(tmp);

	return 0;
}

/*
 * Dump the OCSP certificate key (if it exists) of certificate <ckch> into
 * buffer <out>.
 * Returns 0 in case of success.
 */
static int ckch_store_show_ocsp_certid(struct ckch_store *ckch_store, struct buffer *out)
{
#if (defined(HAVE_SSL_OCSP) && !defined OPENSSL_IS_BORINGSSL)
	unsigned char key[OCSP_MAX_CERTID_ASN1_LENGTH] = {};
	unsigned int key_length = 0;
	int i;

	if (ssl_ocsp_build_response_key(ckch_store->data->ocsp_cid, (unsigned char*)key, &key_length) >= 0) {
		/* Dump the CERTID info */
		chunk_appendf(out, "OCSP Response Key: ");
		for (i = 0; i < key_length; ++i) {
			chunk_appendf(out, "%02x", key[i]);
		}
		chunk_appendf(out, "\n");
	}
#endif

	return 0;
}


/* IO handler of the details "show ssl cert <filename>".
 * It uses a struct show_cert_ctx and ckchs_transaction in read-only.
 */
static int cli_io_handler_show_cert_detail(struct appctx *appctx)
{
	struct show_cert_ctx *ctx = appctx->svcctx;
	struct ckch_store *ckchs = ctx->cur_ckchs;
	struct buffer *out = alloc_trash_chunk();
	int retval = 0;

	if (!out)
		goto end_no_putchk;

	chunk_appendf(out, "Filename: ");
	if (ckchs == ckchs_transaction.new_ckchs)
		chunk_appendf(out, "*");
	chunk_appendf(out, "%s\n", ckchs->path);

	chunk_appendf(out, "Status: ");
	if (ckchs->data->cert == NULL)
		chunk_appendf(out, "Empty\n");
	else if (ckchs == ckchs_transaction.new_ckchs)
		chunk_appendf(out, "Uncommitted\n");
	else if (LIST_ISEMPTY(&ckchs->ckch_inst))
		chunk_appendf(out, "Unused\n");
	else
		chunk_appendf(out, "Used\n");

	retval = show_cert_detail(ckchs->data->cert, ckchs->data->chain, ckchs->data->extra_chain, out);
	if (retval < 0)
		goto end_no_putchk;
	else if (retval)
		goto end;

	ckch_store_show_ocsp_certid(ckchs, out);

end:
	if (applet_putchk(appctx, out) == -1)
		goto yield;

end_no_putchk:
	free_trash_chunk(out);
	return 1;
yield:
	free_trash_chunk(out);
	return 0; /* should come back */
}


/* IO handler of the details "show ssl cert <filename.ocsp>".
 * It uses a show_cert_ctx.
 */
static int cli_io_handler_show_cert_ocsp_detail(struct appctx *appctx)
{
#if (defined(HAVE_SSL_OCSP) && !defined OPENSSL_IS_BORINGSSL)
	struct show_cert_ctx *ctx = appctx->svcctx;
	struct ckch_store *ckchs = ctx->cur_ckchs;
	struct buffer *out = alloc_trash_chunk();
	int from_transaction = ctx->transaction;

	if (!out)
		goto end_no_putchk;

	/* If we try to display an ongoing transaction's OCSP response, we
	 * need to dump the ckch's ocsp_response buffer directly.
	 * Otherwise, we must rebuild the certificate's certid in order to
	 * look for the current OCSP response in the tree. */
	if (from_transaction && ckchs->data->ocsp_response) {
		if (ssl_ocsp_response_print(ckchs->data->ocsp_response, out))
			goto end_no_putchk;
	}
	else {
		unsigned char key[OCSP_MAX_CERTID_ASN1_LENGTH] = {};
		unsigned int key_length = 0;

		if (ssl_ocsp_build_response_key(ckchs->data->ocsp_cid, (unsigned char*)key, &key_length) < 0)
			goto end_no_putchk;

		if (ssl_get_ocspresponse_detail(key, out))
			goto end_no_putchk;
	}

	if (applet_putchk(appctx, out) == -1)
		goto yield;

end_no_putchk:
	free_trash_chunk(out);
	return 1;
yield:
	free_trash_chunk(out);
	return 0; /* should come back */
#else
	return cli_err(appctx, "HAProxy was compiled against a version of OpenSSL that doesn't support OCSP stapling.\n");
#endif
}

/* parsing function for 'show ssl cert [[*][\]<certfile>]' */
static int cli_parse_show_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_cert_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct ckch_store *ckchs;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return cli_err(appctx, "Can't allocate memory!\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't show!\nOperations on certificates are currently locked!\n");

	/* check if there is a certificate to lookup */
	if (*args[3]) {
		int show_ocsp_detail = 0;
		int from_transaction = 0;
		char *end;

		/* We manage the special case "certname.ocsp" through which we
		 * can show the details of an OCSP response. */
		end = strrchr(args[3], '.');
		if (end && strcmp(end+1, "ocsp") == 0) {
			*end = '\0';
			show_ocsp_detail = 1;
		}

		if (*args[3] == '*') {
			char *filename = args[3]+1;

			from_transaction = 1;
			if (!ckchs_transaction.new_ckchs)
				goto error;

			ckchs = ckchs_transaction.new_ckchs;

			if (filename[0] == '\\')
				filename++;

			if (strcmp(filename, ckchs->path) != 0)
				goto error;

		} else {
			char *filename = args[3];

			if (filename[0] == '\\')
				filename++;

			if ((ckchs = ckchs_lookup(filename)) == NULL)
				goto error;

		}

		ctx->cur_ckchs = ckchs;
		/* use the IO handler that shows details */
		if (show_ocsp_detail) {
			ctx->transaction = from_transaction;
			appctx->io_handler = cli_io_handler_show_cert_ocsp_detail;
		}
		else
			appctx->io_handler = cli_io_handler_show_cert_detail;
	}

	return 0;

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_err(appctx, "Can't display the certificate: Not found or the certificate is a bundle!\n");
}

/* parsing function for 'dump ssl cert <certfile>' */
static int cli_parse_dump_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct dump_cert_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct ckch_store *ckchs;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return cli_err(appctx, "Can't allocate memory!\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't show!\nOperations on certificates are currently locked!\n");

	/* check if there is a certificate to lookup */
	if (*args[3]) {

		if (*args[3] == '*') {
			if (!ckchs_transaction.new_ckchs)
				goto error;

			ckchs = ckchs_transaction.new_ckchs;

			if (strcmp(args[3] + 1, ckchs->path) != 0)
				goto error;

		} else {
			if ((ckchs = ckchs_lookup(args[3])) == NULL)
				goto error;

		}

		ctx->ckchs = ckchs;
		ctx->index = -2; /* -2 for pkey, -1 for cert, >= 0 for chain */

		return 0;

	}
error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_err(appctx, "Can't display the certificate: Not found or the certificate is a bundle!\n");
}


/*
 * Dump a CKCH in PEM format over the CLI
 * - dump the PKEY
 * - dump the cert
 * - dump the chain element by element
 *
 *   Store an index to know what we need to dump at next yield
 */
static int cli_io_handler_dump_cert(struct appctx *appctx)
{
	struct dump_cert_ctx *ctx = appctx->svcctx;
	struct ckch_store *ckchs = ctx->ckchs;
	struct buffer *out = alloc_trash_chunk();
	size_t write = 0;
	BIO *bio = NULL;
	int index = ctx->index;

	if (!out)
		goto end_no_putchk;


	if ((bio = BIO_new(BIO_s_mem())) ==  NULL)
		goto end_no_putchk;

	if (index == -2) {

		if (BIO_reset(bio) == -1)
			goto end_no_putchk;

		if (!PEM_write_bio_PrivateKey(bio, ckchs->data->key, NULL, NULL, 0, 0, NULL))
			goto end_no_putchk;

		write = BIO_read(bio, out->area, out->size-1);
		if (write == 0)
			goto end_no_putchk;
		out->area[write] = '\0';
		out->data = write;

		if (applet_putchk(appctx, out) == -1)
			goto end_no_putchk;

		index++;

	}

	if (index == -1) {

		if (BIO_reset(bio) == -1)
			goto end_no_putchk;

		if (!PEM_write_bio_X509(bio, ckchs->data->cert))
			goto end_no_putchk;

		write = BIO_read(bio, out->area, out->size-1);
		if (write == 0)
			goto end_no_putchk;
		out->area[write] = '\0';
		out->data = write;

		if (applet_putchk(appctx, out) == -1)
			goto yield;

		index++;
	}


	for (; index < sk_X509_num(ckchs->data->chain); index++) {
		X509 *cert = sk_X509_value(ckchs->data->chain, index);

		if (BIO_reset(bio) == -1)
			goto end_no_putchk;

		if (!PEM_write_bio_X509(bio, cert))
			goto end_no_putchk;

		write = BIO_read(bio, out->area, out->size-1);
		if (write == 0)
			goto end_no_putchk;
		out->area[write] = '\0';
		out->data = write;

		if (applet_putchk(appctx, out) == -1)
			goto yield;
	}

end:
	free_trash_chunk(out);
	BIO_free(bio);
	return 1; /* end, don't come back */

end_no_putchk:
	free_trash_chunk(out);
	BIO_free(bio);
	return 1;
yield:
	/* save the current state */
	ctx->index = index;
	free_trash_chunk(out);
	BIO_free(bio);
	return 0; /* should come back */

}


/* release function of the 'show ssl ca-file' command */
static void cli_release_dump_cert(struct appctx *appctx)
{
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
}

/* release function of the  `set ssl cert' command, free things and unlock the spinlock */
static void cli_release_commit_cert(struct appctx *appctx)
{
	struct commit_cert_ctx *ctx = appctx->svcctx;

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	/* free every new sni_ctx and the new store, which are not in the trees so no spinlock there */
	if (ctx->new_ckchs)
		ckch_store_free(ctx->new_ckchs);
	ha_free(&ctx->err);
}


/*
 * Rebuild a new instance 'new_inst' based on an old instance 'ckchi' and a
 * specific ckch_store.
 * Returns 0 in case of success, 1 otherwise.
 */
int ckch_inst_rebuild(struct ckch_store *ckch_store, struct ckch_inst *ckchi,
                      struct ckch_inst **new_inst, char **err)
{
	int retval = 0;
	int errcode = 0;
	struct sni_ctx *sc0, *sc0s;
	char **sni_filter = NULL;
	int fcount = 0;

	if (ckchi->crtlist_entry) {
		sni_filter = ckchi->crtlist_entry->filters;
		fcount = ckchi->crtlist_entry->fcount;
	}

	if (ckchi->is_server_instance)
		errcode |= ckch_inst_new_load_srv_store(ckch_store->path, ckch_store, new_inst, err);
	else
		errcode |= ckch_inst_new_load_store(ckch_store->path, ckch_store, ckchi->bind_conf, ckchi->ssl_conf, sni_filter, fcount, ckchi->is_default, new_inst, err);

	if (errcode & ERR_CODE)
		return 1;

	/* if the previous ckchi was used as the default */
	if (ckchi->is_default)
		(*new_inst)->is_default = 1;

	(*new_inst)->is_server_instance = ckchi->is_server_instance;
	(*new_inst)->server = ckchi->server;
	/* Create a new SSL_CTX and link it to the new instance. */
	if ((*new_inst)->is_server_instance) {
		retval = ssl_sock_prep_srv_ctx_and_inst(ckchi->server, (*new_inst)->ctx, (*new_inst));
		if (retval)
			return 1;
	}

	/* create the link to the crtlist_entry */
	(*new_inst)->crtlist_entry = ckchi->crtlist_entry;

	/* we need to initialize the SSL_CTX generated */
	/* this iterate on the newly generated SNIs in the new instance to prepare their SSL_CTX */
	list_for_each_entry_safe(sc0, sc0s, &(*new_inst)->sni_ctx, by_ckch_inst) {
		if (!sc0->order) { /* we initialized only the first SSL_CTX because it's the same in the other sni_ctx's */
			errcode |= ssl_sock_prep_ctx_and_inst(ckchi->bind_conf, ckchi->ssl_conf, sc0->ctx, *new_inst, err);
			if (errcode & ERR_CODE)
				return 1;
		}
	}

	return 0;
}

/*
 * Load all the new SNIs of a newly built ckch instance in the trees, or replace
 * a server's main ckch instance.
 */
static void __ssl_sock_load_new_ckch_instance(struct ckch_inst *ckchi)
{
	/* The bind_conf will be null on server ckch_instances. */
	if (ckchi->is_server_instance) {
		int i;
		/* a lock is needed here since we have to free the SSL cache */
		HA_RWLOCK_WRLOCK(SSL_SERVER_LOCK, &ckchi->server->ssl_ctx.lock);
		/* free the server current SSL_CTX */
		SSL_CTX_free(ckchi->server->ssl_ctx.ctx);
		/* Actual ssl context update */
		SSL_CTX_up_ref(ckchi->ctx);
		ckchi->server->ssl_ctx.ctx = ckchi->ctx;
		ckchi->server->ssl_ctx.inst = ckchi;

		/* flush the session cache of the server */
		for (i = 0; i < global.nbthread; i++) {
			ha_free(&ckchi->server->ssl_ctx.reused_sess[i].sni);
			ha_free(&ckchi->server->ssl_ctx.reused_sess[i].ptr);
		}
		HA_RWLOCK_WRUNLOCK(SSL_SERVER_LOCK, &ckchi->server->ssl_ctx.lock);

	} else {
		HA_RWLOCK_WRLOCK(SNI_LOCK, &ckchi->bind_conf->sni_lock);
		ssl_sock_load_cert_sni(ckchi, ckchi->bind_conf);
		HA_RWLOCK_WRUNLOCK(SNI_LOCK, &ckchi->bind_conf->sni_lock);
	}
}

/*
 * Delete a ckch instance that was replaced after a CLI command.
 */
static void __ckch_inst_free_locked(struct ckch_inst *ckchi)
{
	if (ckchi->is_server_instance) {
		/* no lock for servers */
		ckch_inst_free(ckchi);
	} else {
		struct bind_conf __maybe_unused *bind_conf = ckchi->bind_conf;

		HA_RWLOCK_WRLOCK(SNI_LOCK, &bind_conf->sni_lock);
		ckch_inst_free(ckchi);
		HA_RWLOCK_WRUNLOCK(SNI_LOCK, &bind_conf->sni_lock);
	}
}

/* Replace a ckch_store in the ckch tree and insert the whole dependencies,
* then free the previous dependencies and store.
* Used in the case of a certificate update.
*
* Every dependencies must allocated before using this function.
*
* This function can't fail as it only update pointers, and does not alloc anything.
*
* /!\ This function must be used under the ckch lock. /!\
*
* - Insert every dependencies (SNI, crtlist_entry, ckch_inst, etc)
* - Delete the old ckch_store from the tree
* - Insert the new ckch_store
* - Free the old dependencies and the old ckch_store
*/
void ckch_store_replace(struct ckch_store *old_ckchs, struct ckch_store *new_ckchs)
{
	struct crtlist_entry *entry;
	struct ckch_inst *ckchi, *ckchis;

	LIST_SPLICE(&new_ckchs->crtlist_entry, &old_ckchs->crtlist_entry);
	list_for_each_entry(entry, &new_ckchs->crtlist_entry, by_ckch_store) {
		ebpt_delete(&entry->node);
		/* change the ptr and reinsert the node */
		entry->node.key = new_ckchs;
		ebpt_insert(&entry->crtlist->entries, &entry->node);
	}
	/* insert the new ckch_insts in the crtlist_entry */
	list_for_each_entry(ckchi, &new_ckchs->ckch_inst, by_ckchs) {
		if (ckchi->crtlist_entry)
			LIST_INSERT(&ckchi->crtlist_entry->ckch_inst, &ckchi->by_crtlist_entry);
	}
	/* First, we insert every new SNIs in the trees, also replace the default_ctx */
	list_for_each_entry_safe(ckchi, ckchis, &new_ckchs->ckch_inst, by_ckchs) {
		__ssl_sock_load_new_ckch_instance(ckchi);
	}
	/* delete the old sni_ctx, the old ckch_insts and the ckch_store */
	list_for_each_entry_safe(ckchi, ckchis, &old_ckchs->ckch_inst, by_ckchs) {
		__ckch_inst_free_locked(ckchi);
	}

	ckch_store_free(old_ckchs);
	ebst_insert(&ckchs_tree, &new_ckchs->node);
}


/*
 * This function tries to create the new ckch_inst and their SNIs
 *
 * /!\ don't forget to update __hlua_ckch_commit() if you changes things there. /!\
 */
static int cli_io_handler_commit_cert(struct appctx *appctx)
{
	struct commit_cert_ctx *ctx = appctx->svcctx;
	int y = 0;
	struct ckch_store *old_ckchs, *new_ckchs = NULL;
	struct ckch_inst *ckchi;

	usermsgs_clr("CLI");
	while (1) {
		switch (ctx->state) {
			case CERT_ST_INIT:
				/* This state just print the update message */
				chunk_printf(&trash, "Committing %s", ckchs_transaction.path);
				if (applet_putchk(appctx, &trash) == -1)
					goto yield;

				ctx->state = CERT_ST_GEN;
				__fallthrough;
			case CERT_ST_GEN:
				/*
				 * This state generates the ckch instances with their
				 * sni_ctxs and SSL_CTX.
				 *
				 * Since the SSL_CTX generation can be CPU consumer, we
				 * yield every 10 instances.
				 */

				old_ckchs = ctx->old_ckchs;
				new_ckchs = ctx->new_ckchs;

				/* get the next ckchi to regenerate */
				ckchi = ctx->next_ckchi;
				/* we didn't start yet, set it to the first elem */
				if (ckchi == NULL)
					ckchi = LIST_ELEM(old_ckchs->ckch_inst.n, typeof(ckchi), by_ckchs);

				/* walk through the old ckch_inst and creates new ckch_inst using the updated ckchs */
				list_for_each_entry_from(ckchi, &old_ckchs->ckch_inst, by_ckchs) {
					struct ckch_inst *new_inst;

					/* save the next ckchi to compute in case of yield */
					ctx->next_ckchi = ckchi;

					/* it takes a lot of CPU to creates SSL_CTXs, so we yield every 10 CKCH instances */
					if (y >= 10) {
						applet_have_more_data(appctx); /* let's come back later */
						goto yield;
					}

					/* display one dot per new instance */
					if (applet_putstr(appctx, ".") == -1)
						goto yield;

					ctx->err = NULL;
					if (ckch_inst_rebuild(new_ckchs, ckchi, &new_inst, &ctx->err)) {
						ctx->state = CERT_ST_ERROR;
						goto error;
					}

					/* link the new ckch_inst to the duplicate */
					LIST_APPEND(&new_ckchs->ckch_inst, &new_inst->by_ckchs);
					y++;
				}
				ctx->state = CERT_ST_INSERT;
				__fallthrough;
			case CERT_ST_INSERT:
				/* The generation is finished, we can insert everything */

				old_ckchs = ctx->old_ckchs;
				new_ckchs = ctx->new_ckchs;

				/* insert everything and remove the previous objects */
				ckch_store_replace(old_ckchs, new_ckchs);
				ctx->new_ckchs = ctx->old_ckchs = NULL;
				ctx->state = CERT_ST_SUCCESS;
				__fallthrough;
			case CERT_ST_SUCCESS:
				chunk_printf(&trash, "\n%sSuccess!\n", usermsgs_str());
				if (applet_putchk(appctx, &trash) == -1)
					goto yield;
				ctx->state = CERT_ST_FIN;
				__fallthrough;
			case CERT_ST_FIN:
				/* we achieved the transaction, we can set everything to NULL */
				ckchs_transaction.new_ckchs = NULL;
				ckchs_transaction.old_ckchs = NULL;
				ckchs_transaction.path = NULL;
				goto end;

			case CERT_ST_ERROR:
			  error:
				chunk_printf(&trash, "\n%s%sFailed!\n", usermsgs_str(), ctx->err);
				if (applet_putchk(appctx, &trash) == -1)
					goto yield;
				ctx->state = CERT_ST_FIN;
				break;
		}
	}
end:
	usermsgs_clr(NULL);
	/* success: call the release function and don't come back */
	return 1;

yield:
	usermsgs_clr(NULL);
	return 0; /* should come back */
}

/*
 * Parsing function of 'commit ssl cert'
 */
static int cli_parse_commit_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct commit_cert_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'commit ssl cert' expects a filename\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't commit the certificate!\nOperations on certificates are currently locked!\n");

	if (!ckchs_transaction.path) {
		memprintf(&err, "No ongoing transaction! !\n");
		goto error;
	}

	if (strcmp(ckchs_transaction.path, args[3]) != 0) {
		memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", ckchs_transaction.path, args[3]);
		goto error;
	}

	/* if a certificate is here, a private key must be here too */
	if (ckchs_transaction.new_ckchs->data->cert && !ckchs_transaction.new_ckchs->data->key) {
		memprintf(&err, "The transaction must contain at least a certificate and a private key!\n");
		goto error;
	}

	if (!X509_check_private_key(ckchs_transaction.new_ckchs->data->cert, ckchs_transaction.new_ckchs->data->key)) {
		memprintf(&err, "inconsistencies between private key and certificate loaded '%s'.\n", ckchs_transaction.path);
		goto error;
	}

	/* init the appctx structure */
	ctx->state = CERT_ST_INIT;
	ctx->next_ckchi = NULL;
	ctx->new_ckchs = ckchs_transaction.new_ckchs;
	ctx->old_ckchs = ckchs_transaction.old_ckchs;

	/* we don't unlock there, it will be unlock after the IO handler, in the release handler */
	return 0;

error:

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	err = memprintf(&err, "%sCan't commit %s!\n", err ? err : "", args[3]);

	return cli_dynerr(appctx, err);
}




/*
 * Parsing function of `set ssl cert`, it updates or creates a temporary ckch.
 * It uses a set_cert_ctx context, and ckchs_transaction under a lock.
 */
static int cli_parse_set_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct ckch_store *new_ckchs = NULL;
	struct ckch_store *old_ckchs = NULL;
	char *err = NULL;
	int i;
	int errcode = 0;
	char *end;
	struct cert_exts *cert_ext = &cert_exts[0]; /* default one, PEM */
	struct ckch_data *data;
	struct buffer *buf;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3] || !payload)
		return cli_err(appctx, "'set ssl cert' expects a filename and a certificate as a payload\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't update the certificate!\nOperations on certificates are currently locked!\n");

	if ((buf = alloc_trash_chunk()) == NULL) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	if (!chunk_strcpy(buf, args[3])) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* check which type of file we want to update */
	for (i = 0; cert_exts[i].ext != NULL; i++) {
		end = strrchr(buf->area, '.');
		if (end && *cert_exts[i].ext && (strcmp(end + 1, cert_exts[i].ext) == 0)) {
			*end = '\0';
			buf->data = strlen(buf->area);
			cert_ext = &cert_exts[i];
			break;
		}
	}

	/* if there is an ongoing transaction */
	if (ckchs_transaction.path) {
		/* if there is an ongoing transaction, check if this is the same file */
		if (strcmp(ckchs_transaction.path, buf->area) != 0) {
			/* we didn't find the transaction, must try more cases below */

			/* if the del-ext option is activated we should try to take a look at a ".crt" too. */
			if (cert_ext->type != CERT_TYPE_PEM && global_ssl.extra_files_noext) {
				if (!chunk_strcat(buf, ".crt")) {
					memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
					errcode |= ERR_ALERT | ERR_FATAL;
					goto end;
				}
				/* check again with the right extension */
				if (strcmp(ckchs_transaction.path, buf->area) != 0) {
					/* remove .crt of the error message */
					*(b_orig(buf) + b_data(buf) + strlen(".crt")) = '\0';
					b_sub(buf, strlen(".crt"));

					memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", ckchs_transaction.path, buf->area);
					errcode |= ERR_ALERT | ERR_FATAL;
					goto end;
				}
			} else {
				/* without del-ext the error is definitive */
				memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", ckchs_transaction.path, buf->area);
				errcode |= ERR_ALERT | ERR_FATAL;
				goto end;
			}
		}

		old_ckchs = ckchs_transaction.new_ckchs;

	} else {

		/* lookup for the certificate in the tree */
		old_ckchs = ckchs_lookup(buf->area);

		if (!old_ckchs) {
			/* if the del-ext option is activated we should try to take a look at a ".crt" too. */
			if (cert_ext->type != CERT_TYPE_PEM && global_ssl.extra_files_noext) {
				if (!chunk_strcat(buf, ".crt")) {
					memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
					errcode |= ERR_ALERT | ERR_FATAL;
					goto end;
				}
				old_ckchs = ckchs_lookup(buf->area);
			}
		}
	}

	if (!old_ckchs) {
		memprintf(&err, "%sCan't replace a certificate which is not referenced by the configuration!\n",
		          err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* duplicate the ckch store */
	new_ckchs = ckchs_dup(old_ckchs);
	if (!new_ckchs) {
		memprintf(&err, "%sCannot allocate memory!\n",
			  err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

#if defined(HAVE_SSL_OCSP)
	/* Reset the OCSP CID */
	if (cert_ext->type == CERT_TYPE_PEM || cert_ext->type == CERT_TYPE_KEY ||
	    cert_ext->type == CERT_TYPE_ISSUER) {
		OCSP_CERTID_free(new_ckchs->data->ocsp_cid);
		new_ckchs->data->ocsp_cid = NULL;
	}
#endif
	data = new_ckchs->data;

	/* apply the change on the duplicate */
	if (cert_ext->load(buf->area, payload, data, &err) != 0) {
		memprintf(&err, "%sCan't load the payload\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* we succeed, we can save the ckchs in the transaction */

	/* if there wasn't a transaction, update the old ckchs */
	if (!ckchs_transaction.old_ckchs) {
		ckchs_transaction.old_ckchs = old_ckchs;
		ckchs_transaction.path = old_ckchs->path;
		err = memprintf(&err, "Transaction created for certificate %s!\n", ckchs_transaction.path);
	} else {
		err = memprintf(&err, "Transaction updated for certificate %s!\n", ckchs_transaction.path);

	}

	/* free the previous ckchs if there was a transaction */
	ckch_store_free(ckchs_transaction.new_ckchs);

	ckchs_transaction.new_ckchs = new_ckchs;


	/* creates the SNI ctxs later in the IO handler */

end:
	free_trash_chunk(buf);

	if (errcode & ERR_CODE) {
		ckch_store_free(new_ckchs);
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynerr(appctx, memprintf(&err, "%sCan't update %s!\n", err ? err : "", args[3]));
	} else {
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynmsg(appctx, LOG_NOTICE, err);
	}
	/* TODO: handle the ERR_WARN which are not handled because of the io_handler */
}

/* parsing function of 'abort ssl cert' */
static int cli_parse_abort_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'abort ssl cert' expects a filename\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't abort!\nOperations on certificates are currently locked!\n");

	if (!ckchs_transaction.path) {
		memprintf(&err, "No ongoing transaction!\n");
		goto error;
	}

	if (strcmp(ckchs_transaction.path, args[3]) != 0) {
		memprintf(&err, "The ongoing transaction is about '%s' but you are trying to abort a transaction for '%s'\n", ckchs_transaction.path, args[3]);
		goto error;
	}

	/* Only free the ckchs there, because the SNI and instances were not generated yet */
	ckch_store_free(ckchs_transaction.new_ckchs);
	ckchs_transaction.new_ckchs = NULL;
	ckchs_transaction.old_ckchs = NULL;
	ckchs_transaction.path = NULL;

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	err = memprintf(&err, "Transaction aborted for certificate '%s'!\n", args[3]);
	return cli_dynmsg(appctx, LOG_NOTICE, err);

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	return cli_dynerr(appctx, err);
}

/* parsing function of 'new ssl cert' */
static int cli_parse_new_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct ckch_store *store;
	char *err = NULL;
	char *path;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'new ssl cert' expects a filename\n");

	path = args[3];

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't create a certificate!\nOperations on certificates are currently locked!\n");

	store = ckchs_lookup(path);
	if (store != NULL) {
		memprintf(&err, "Certificate '%s' already exists!\n", path);
		store = NULL; /* we don't want to free it */
		goto error;
	}
	/* we won't support multi-certificate bundle here */
	store = ckch_store_new(path);
	if (!store) {
		memprintf(&err, "unable to allocate memory.\n");
		goto error;
	}

	/* insert into the ckchs tree */
	ebst_insert(&ckchs_tree, &store->node);
	memprintf(&err, "New empty certificate store '%s'!\n", args[3]);

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynmsg(appctx, LOG_NOTICE, err);
error:
	free(store);
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynerr(appctx, err);
}

/* parsing function of 'del ssl cert' */
static int cli_parse_del_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct ckch_store *store;
	char *err = NULL;
	char *filename;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'del ssl cert' expects a certificate name\n");

	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't delete the certificate!\nOperations on certificates are currently locked!\n");

	filename = args[3];

	if (ckchs_transaction.path && strcmp(ckchs_transaction.path, filename) == 0) {
		memprintf(&err, "ongoing transaction for the certificate '%s'", filename);
		goto error;
	}

	store = ckchs_lookup(filename);
	if (store == NULL) {
		memprintf(&err, "certificate '%s' doesn't exist!\n", filename);
		goto error;
	}
	if (!LIST_ISEMPTY(&store->ckch_inst)) {
		memprintf(&err, "certificate '%s' in use, can't be deleted!\n", filename);
		goto error;
	}

	ebmb_delete(&store->node);
	ckch_store_free(store);

	memprintf(&err, "Certificate '%s' deleted!\n", filename);

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynmsg(appctx, LOG_NOTICE, err);

error:
	memprintf(&err, "Can't remove the certificate: %s\n", err ? err : "");
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynerr(appctx, err);
}



/* parsing function of 'new ssl ca-file' */
static int cli_parse_new_cafile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cafile_entry *cafile_entry;
	char *err = NULL;
	char *path;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'new ssl ca-file' expects a filename\n");

	path = args[3];

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't create a CA file!\nOperations on certificates are currently locked!\n");

	cafile_entry = ssl_store_get_cafile_entry(path, 0);
	if (cafile_entry) {
		memprintf(&err, "CA file '%s' already exists!\n", path);
		goto error;
	}

	cafile_entry = ssl_store_create_cafile_entry(path, NULL, CAFILE_CERT);
	if (!cafile_entry) {
		memprintf(&err, "%sCannot allocate memory!\n",
			  err ? err : "");
		goto error;
	}

	/* Add the newly created cafile_entry to the tree so that
	 * any new ckch instance created from now can use it. */
	if (ssl_store_add_uncommitted_cafile_entry(cafile_entry))
		goto error;

	memprintf(&err, "New CA file created '%s'!\n", path);

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynmsg(appctx, LOG_NOTICE, err);
error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynerr(appctx, err);
}

/*
 * Parsing function of `set ssl ca-file`
 */
static int cli_parse_set_cafile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cafile_entry *old_cafile_entry = NULL;
	struct cafile_entry *new_cafile_entry = NULL;
	char *err = NULL;
	int errcode = 0;
	struct buffer *buf;
	int add_cmd = 0;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	/* this is "add ssl ca-file" */
	if (*args[0] == 'a')
		add_cmd = 1;

	if (!*args[3] || !payload)
		return cli_err(appctx, "'set ssl ca-file' expects a filename and CAs as a payload\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't update the CA file!\nOperations on certificates are currently locked!\n");

	if ((buf = alloc_trash_chunk()) == NULL) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	if (!chunk_strcpy(buf, args[3])) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	old_cafile_entry = NULL;
	new_cafile_entry = NULL;

	/* if there is an ongoing transaction */
	if (cafile_transaction.path) {
		/* if there is an ongoing transaction, check if this is the same file */
		if (strcmp(cafile_transaction.path, buf->area) != 0) {
			memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", cafile_transaction.path, buf->area);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		old_cafile_entry = cafile_transaction.old_cafile_entry;
	} else {
		/* lookup for the certificate in the tree */
		old_cafile_entry = ssl_store_get_cafile_entry(buf->area, 0);
	}

	if (!old_cafile_entry) {
		memprintf(&err, "%sCan't replace a CA file which is not referenced by the configuration!\n",
		          err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* if the transaction is new, duplicate the old_ca_file_entry, otherwise duplicate the cafile in the current transaction */
	if (cafile_transaction.new_cafile_entry)
		new_cafile_entry = ssl_store_dup_cafile_entry(cafile_transaction.new_cafile_entry);
	else
		new_cafile_entry = ssl_store_dup_cafile_entry(old_cafile_entry);

	if (!new_cafile_entry) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* Fill the new entry with the new CAs. The add_cmd variable determine
	   if we flush the X509_STORE or not */
	if (ssl_store_load_ca_from_buf(new_cafile_entry, payload, add_cmd)) {
		memprintf(&err, "%sInvalid payload\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* we succeed, we can save the ca in the transaction */

	/* if there wasn't a transaction, update the old CA */
	if (!cafile_transaction.old_cafile_entry) {
		cafile_transaction.old_cafile_entry = old_cafile_entry;
		cafile_transaction.path = old_cafile_entry->path;
		err = memprintf(&err, "transaction created for CA %s!\n", cafile_transaction.path);
	} else {
		err = memprintf(&err, "transaction updated for CA %s!\n", cafile_transaction.path);
	}

	/* free the previous CA if there was a transaction */
	ssl_store_delete_cafile_entry(cafile_transaction.new_cafile_entry);

	cafile_transaction.new_cafile_entry = new_cafile_entry;

	/* creates the SNI ctxs later in the IO handler */

end:
	free_trash_chunk(buf);

	if (errcode & ERR_CODE) {
		ssl_store_delete_cafile_entry(new_cafile_entry);
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynerr(appctx, memprintf(&err, "%sCan't update %s!\n", err ? err : "", args[3]));
	} else {

		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynmsg(appctx, LOG_NOTICE, err);
	}
}


/*
 * Parsing function of 'commit ssl ca-file'.
 * It uses a commit_cacrlfile_ctx that's also shared with "commit ssl crl-file".
 */
static int cli_parse_commit_cafile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct commit_cacrlfile_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'commit ssl ca-file' expects a filename\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't commit the CA file!\nOperations on certificates are currently locked!\n");

	if (!cafile_transaction.path) {
		memprintf(&err, "No ongoing transaction! !\n");
		goto error;
	}

	if (strcmp(cafile_transaction.path, args[3]) != 0) {
		memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", cafile_transaction.path, args[3]);
		goto error;
	}
	/* init the appctx structure */
	ctx->state = CACRL_ST_INIT;
	ctx->next_ckchi_link = NULL;
	ctx->old_entry = cafile_transaction.old_cafile_entry;
	ctx->new_entry = cafile_transaction.new_cafile_entry;
	ctx->cafile_type = CAFILE_CERT;

	return 0;

error:

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	err = memprintf(&err, "%sCan't commit %s!\n", err ? err : "", args[3]);

	return cli_dynerr(appctx, err);
}

/*
 * This function tries to create new ckch instances and their SNIs using a newly
 * set certificate authority (CA file) or a newly set Certificate Revocation
 * List (CRL), depending on the command being called.
 */
static int cli_io_handler_commit_cafile_crlfile(struct appctx *appctx)
{
	struct commit_cacrlfile_ctx *ctx = appctx->svcctx;
	int y = 0;
	struct cafile_entry *old_cafile_entry = ctx->old_entry;
	struct cafile_entry *new_cafile_entry = ctx->new_entry;
	struct ckch_inst_link *ckchi_link;
	char *path;

	/* The ctx was already validated by the ca-file/crl-file parsing
	 * function. Entries can only be NULL in CACRL_ST_SUCCESS or
	 * CACRL_ST_FIN states
	 */
	switch (ctx->cafile_type) {
		case CAFILE_CERT:
			path = cafile_transaction.path;
			break;
		case CAFILE_CRL:
			path = crlfile_transaction.path;
			break;
		default:
			path = NULL;
			goto error;
	}

	while (1) {
		switch (ctx->state) {
			case CACRL_ST_INIT:
				/* This state just print the update message */
				chunk_printf(&trash, "Committing %s", path);
				if (applet_putchk(appctx, &trash) == -1)
					goto yield;

				ctx->state = CACRL_ST_GEN;
				__fallthrough;
			case CACRL_ST_GEN:
				/*
				 * This state generates the ckch instances with their
				 * sni_ctxs and SSL_CTX.
				 *
				 * Since the SSL_CTX generation can be CPU consumer, we
				 * yield every 10 instances.
				 */

				/* get the next ckchi to regenerate */
				ckchi_link = ctx->next_ckchi_link;

				/* we didn't start yet, set it to the first elem */
				if (ckchi_link == NULL) {
					ckchi_link = LIST_ELEM(old_cafile_entry->ckch_inst_link.n, typeof(ckchi_link), list);
					/* Add the newly created cafile_entry to the tree so that
					 * any new ckch instance created from now can use it. */
					if (ssl_store_add_uncommitted_cafile_entry(new_cafile_entry)) {
						ctx->state = CACRL_ST_ERROR;
						goto error;
					}
				}

				list_for_each_entry_from(ckchi_link, &old_cafile_entry->ckch_inst_link, list) {
					struct ckch_inst *new_inst;

					/* save the next ckchi to compute */
					ctx->next_ckchi_link = ckchi_link;

					/* it takes a lot of CPU to creates SSL_CTXs, so we yield every 10 CKCH instances */
					if (y >= 10) {
						applet_have_more_data(appctx); /* let's come back later */
						goto yield;
					}

					/* display one dot per new instance */
					if (applet_putstr(appctx, ".") == -1)
						goto yield;

					/* Rebuild a new ckch instance that uses the same ckch_store
					 * than a reference ckchi instance but will use a new CA file. */
					ctx->err = NULL;
					if (ckch_inst_rebuild(ckchi_link->ckch_inst->ckch_store, ckchi_link->ckch_inst, &new_inst, &ctx->err)) {
						ctx->state = CACRL_ST_ERROR;
						goto error;
					}

					y++;
				}

				ctx->state = CACRL_ST_CRLCB;
				__fallthrough;
			case CACRL_ST_CRLCB:
				if ((ctx->cafile_type == CAFILE_CRL) && (ssl_commit_crlfile_cb != NULL)) {
					if (ssl_commit_crlfile_cb(crlfile_transaction.path, crlfile_transaction.new_crlfile_entry->ca_store, &ctx->err) == -1) {
						ctx->state = CACRL_ST_ERROR;
						goto error;
					}
				}
				ctx->state = CACRL_ST_INSERT;
				__fallthrough;
			case CACRL_ST_INSERT:
				/* The generation is finished, we can insert everything */

				/* insert the new ckch_insts in the crtlist_entry */
				list_for_each_entry(ckchi_link, &new_cafile_entry->ckch_inst_link, list) {
					if (ckchi_link->ckch_inst->crtlist_entry)
						LIST_INSERT(&ckchi_link->ckch_inst->crtlist_entry->ckch_inst,
							    &ckchi_link->ckch_inst->by_crtlist_entry);
				}

				/* First, we insert every new SNIs in the trees, also replace the default_ctx */
				list_for_each_entry(ckchi_link, &new_cafile_entry->ckch_inst_link, list) {
					__ssl_sock_load_new_ckch_instance(ckchi_link->ckch_inst);
				}

				/* delete the old sni_ctx, the old ckch_insts
				 * and the ckch_store. ckch_inst_free() also
				 * manipulates the list so it's cleaner to loop
				 * until it's empty  */
				while (!LIST_ISEMPTY(&old_cafile_entry->ckch_inst_link)) {
					ckchi_link = LIST_ELEM(old_cafile_entry->ckch_inst_link.n, typeof(ckchi_link), list);

					LIST_DEL_INIT(&ckchi_link->list); /* must reinit because ckch_inst checks the list */
					__ckch_inst_free_locked(ckchi_link->ckch_inst);
					free(ckchi_link);
				}

				/* Remove the old cafile entry from the tree */
				ebmb_delete(&old_cafile_entry->node);
				ssl_store_delete_cafile_entry(old_cafile_entry);

				ctx->old_entry = ctx->new_entry = NULL;
				ctx->state = CACRL_ST_SUCCESS;
				__fallthrough;
			case CACRL_ST_SUCCESS:
				if (applet_putstr(appctx, "\nSuccess!\n") == -1)
					goto yield;
				ctx->state = CACRL_ST_FIN;
				__fallthrough;
			case CACRL_ST_FIN:
				/* we achieved the transaction, we can set everything to NULL */
				switch (ctx->cafile_type) {
				case CAFILE_CERT:
					cafile_transaction.old_cafile_entry = NULL;
					cafile_transaction.new_cafile_entry = NULL;
					cafile_transaction.path = NULL;
					break;
				case CAFILE_CRL:
					crlfile_transaction.old_crlfile_entry = NULL;
					crlfile_transaction.new_crlfile_entry = NULL;
					crlfile_transaction.path = NULL;
					break;
				}
				goto end;

			case CACRL_ST_ERROR:
			  error:
				chunk_printf(&trash, "\n%sFailed!\n", ctx->err);
				if (applet_putchk(appctx, &trash) == -1)
					goto yield;
				ctx->state = CACRL_ST_FIN;
				break;
		}
	}
end:
	/* success: call the release function and don't come back */
	return 1;
yield:
	return 0; /* should come back */
}


/* parsing function of 'abort ssl ca-file' */
static int cli_parse_abort_cafile(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'abort ssl ca-file' expects a filename\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't abort!\nOperations on certificates are currently locked!\n");

	if (!cafile_transaction.path) {
		memprintf(&err, "No ongoing transaction!\n");
		goto error;
	}

	if (strcmp(cafile_transaction.path, args[3]) != 0) {
		memprintf(&err, "The ongoing transaction is about '%s' but you are trying to abort a transaction for '%s'\n", cafile_transaction.path, args[3]);
		goto error;
	}

	/* Only free the uncommitted cafile_entry here, because the SNI and instances were not generated yet */
	ssl_store_delete_cafile_entry(cafile_transaction.new_cafile_entry);
	cafile_transaction.new_cafile_entry = NULL;
	cafile_transaction.old_cafile_entry = NULL;
	cafile_transaction.path = NULL;

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	err = memprintf(&err, "Transaction aborted for certificate '%s'!\n", args[3]);
	return cli_dynmsg(appctx, LOG_NOTICE, err);

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	return cli_dynerr(appctx, err);
}

/* release function of the `commit ssl ca-file' command, free things and unlock the spinlock.
 * It uses a commit_cacrlfile_ctx context.
 */
static void cli_release_commit_cafile(struct appctx *appctx)
{
	struct commit_cacrlfile_ctx *ctx = appctx->svcctx;
	struct cafile_entry *new_cafile_entry = ctx->new_entry;

	/* Remove the uncommitted cafile_entry from the tree. */
	if (new_cafile_entry) {
		ebmb_delete(&new_cafile_entry->node);
		ssl_store_delete_cafile_entry(new_cafile_entry);
	}
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	ha_free(&ctx->err);
}


/* IO handler of details "show ssl ca-file <filename[:index]>".
 * It uses a show_cafile_ctx context, and the global
 * cafile_transaction.new_cafile_entry in read-only.
 */
static int cli_io_handler_show_cafile_detail(struct appctx *appctx)
{
	struct show_cafile_ctx *ctx = appctx->svcctx;
	struct cafile_entry *cafile_entry = ctx->cur_cafile_entry;
	struct buffer *out = alloc_trash_chunk();
	int i = 0;
	X509 *cert;
	STACK_OF(X509_OBJECT) *objs;
	int retval = 0;
	int ca_index = ctx->ca_index;
	int show_all = ctx->show_all;

	if (!out)
		goto end_no_putchk;

	chunk_appendf(out, "Filename: ");
	if (cafile_entry == cafile_transaction.new_cafile_entry)
		chunk_appendf(out, "*");
	chunk_appendf(out, "%s\n", cafile_entry->path);

	chunk_appendf(out, "Status: ");
	if (!cafile_entry->ca_store)
		chunk_appendf(out, "Empty\n");
	else if (cafile_entry == cafile_transaction.new_cafile_entry)
		chunk_appendf(out, "Uncommitted\n");
	else if (LIST_ISEMPTY(&cafile_entry->ckch_inst_link))
		chunk_appendf(out, "Unused\n");
	else
		chunk_appendf(out, "Used\n");

	if (!cafile_entry->ca_store)
		goto end;

	objs = X509_STORE_get0_objects(cafile_entry->ca_store);
	for (i = ca_index; i < sk_X509_OBJECT_num(objs); i++) {

		cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
		if (!cert)
			continue;

		/* file starts at line 1 */
		chunk_appendf(out, " \nCertificate #%d:\n", i+1);
		retval = show_cert_detail(cert, NULL, NULL, out);
		if (retval < 0)
			goto end_no_putchk;
		else if (retval)
			goto yield;

		if (applet_putchk(appctx, out) == -1)
			goto yield;

		if (!show_all)   /* only need to dump one certificate */
			goto end;
	}

end:
	free_trash_chunk(out);
	return 1; /* end, don't come back */

end_no_putchk:
	free_trash_chunk(out);
	return 1;
yield:
	/* save the current state */
	ctx->ca_index = i;
	free_trash_chunk(out);
	return 0; /* should come back */
}


/* parsing function for 'show ssl ca-file [[*][\]<cafile>[:index]]'.
 * It prepares a show_cafile_ctx context, and checks the global
 * cafile_transaction under the ckch_lock (read only).
 */
static int cli_parse_show_cafile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_cafile_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct cafile_entry *cafile_entry;
	int ca_index = 0;
	char *colons;
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return cli_err(appctx, "Can't allocate memory!\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't show!\nOperations on certificates are currently locked!\n");

	ctx->show_all = 1; /* show all certificates */
	ctx->ca_index = 0;
	/* check if there is a certificate to lookup */
	if (*args[3]) {

		/* Look for an optional CA index after the CA file name */
		colons = strchr(args[3], ':');
		if (colons) {
			char *endptr;

			ca_index = strtol(colons + 1, &endptr, 10);
			/* Indexes start at 1 */
			if (colons + 1 == endptr || *endptr != '\0' || ca_index <= 0) {
				memprintf(&err, "wrong CA index after colons in '%s'!", args[3]);
				goto error;
			}
			*colons = '\0';
			ctx->ca_index = ca_index - 1; /* we start counting at 0 in the ca_store, but at 1 on the CLI */
			ctx->show_all = 0; /* show only one certificate */
		}

		if (*args[3] == '*') {
			char *filename = args[3]+1;

			if (filename[0] == '\\')
				filename++;

			if (!cafile_transaction.new_cafile_entry)
				goto error;

			cafile_entry = cafile_transaction.new_cafile_entry;

			if (strcmp(filename, cafile_entry->path) != 0)
				goto error;

		} else {
			char *filename = args[3];

			if (filename[0] == '\\')
				filename++;
			/* Get the "original" cafile_entry and not the
			 * uncommitted one if it exists. */
			if ((cafile_entry = ssl_store_get_cafile_entry(filename, 1)) == NULL || cafile_entry->type != CAFILE_CERT)
				goto error;
		}

		ctx->cur_cafile_entry = cafile_entry;
		/* use the IO handler that shows details */
		appctx->io_handler = cli_io_handler_show_cafile_detail;
	}

	return 0;

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	if (err)
		return cli_dynerr(appctx, err);
	return cli_err(appctx, "Can't display the CA file : Not found!\n");
}


/* release function of the 'show ssl ca-file' command */
static void cli_release_show_cafile(struct appctx *appctx)
{
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
}


/* This function returns the number of certificates in a cafile_entry. */
static int get_certificate_count(struct cafile_entry *cafile_entry)
{
	int cert_count = 0;
	STACK_OF(X509_OBJECT) *objs;

	if (cafile_entry && cafile_entry->ca_store) {
		objs = X509_STORE_get0_objects(cafile_entry->ca_store);
		if (objs)
			cert_count = sk_X509_OBJECT_num(objs);
	}
	return cert_count;
}

/* IO handler of "show ssl ca-file". The command taking a specific CA file name
 * is managed in cli_io_handler_show_cafile_detail.
 * It uses a show_cafile_ctx and the global cafile_transaction.new_cafile_entry
 * in read-only.
 */
static int cli_io_handler_show_cafile(struct appctx *appctx)
{
	struct show_cafile_ctx *ctx = appctx->svcctx;
	struct buffer *trash = alloc_trash_chunk();
	struct ebmb_node *node;
	struct cafile_entry *cafile_entry = NULL;

	if (trash == NULL)
		return 1;

	if (!ctx->old_cafile_entry && cafile_transaction.old_cafile_entry) {
		chunk_appendf(trash, "# transaction\n");
		chunk_appendf(trash, "*%s", cafile_transaction.old_cafile_entry->path);
		chunk_appendf(trash, " - %d certificate(s)\n", get_certificate_count(cafile_transaction.new_cafile_entry));
		if (applet_putchk(appctx, trash) == -1)
			goto yield;
		ctx->old_cafile_entry = cafile_transaction.new_cafile_entry;
	}

	/* First time in this io_handler. */
	if (!ctx->cur_cafile_entry) {
		chunk_appendf(trash, "# filename\n");
		node = ebmb_first(&cafile_tree);
	} else {
		/* We yielded during a previous call. */
		node = &ctx->cur_cafile_entry->node;
	}

	while (node) {
		cafile_entry = ebmb_entry(node, struct cafile_entry, node);
		if (cafile_entry->type == CAFILE_CERT) {
			chunk_appendf(trash, "%s", cafile_entry->path);

			chunk_appendf(trash, " - %d certificate(s)\n", get_certificate_count(cafile_entry));
		}

		node = ebmb_next(node);
		if (applet_putchk(appctx, trash) == -1)
			goto yield;
	}

	ctx->cur_cafile_entry = NULL;
	free_trash_chunk(trash);
	return 1;
yield:

	free_trash_chunk(trash);
	ctx->cur_cafile_entry = cafile_entry;
	return 0; /* should come back */
}

/* parsing function of 'del ssl ca-file' */
static int cli_parse_del_cafile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cafile_entry *cafile_entry;
	char *err = NULL;
	char *filename;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'del ssl ca-file' expects a CA file name\n");

	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't delete the CA file!\nOperations on certificates are currently locked!\n");

	filename = args[3];

	if (cafile_transaction.path && strcmp(cafile_transaction.path, filename) == 0) {
		memprintf(&err, "ongoing transaction for the CA file '%s'", filename);
		goto error;
	}

	cafile_entry = ssl_store_get_cafile_entry(filename, 0);
	if (!cafile_entry) {
		memprintf(&err, "CA file '%s' doesn't exist!\n", filename);
		goto error;
	}

	if (!LIST_ISEMPTY(&cafile_entry->ckch_inst_link)) {
		memprintf(&err, "CA file '%s' in use, can't be deleted!\n", filename);
		goto error;
	}

	/* Remove the cafile_entry from the tree */
	ebmb_delete(&cafile_entry->node);
	ssl_store_delete_cafile_entry(cafile_entry);

	memprintf(&err, "CA file '%s' deleted!\n", filename);

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynmsg(appctx, LOG_NOTICE, err);

error:
	memprintf(&err, "Can't remove the CA file: %s\n", err ? err : "");
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynerr(appctx, err);
}

/* parsing function of 'new ssl crl-file' */
static int cli_parse_new_crlfile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cafile_entry *cafile_entry;
	char *err = NULL;
	char *path;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'new ssl crl-file' expects a filename\n");

	path = args[3];

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't create a CRL file!\nOperations on certificates are currently locked!\n");

	cafile_entry = ssl_store_get_cafile_entry(path, 0);
	if (cafile_entry) {
		memprintf(&err, "CRL file '%s' already exists!\n", path);
		goto error;
	}

	cafile_entry = ssl_store_create_cafile_entry(path, NULL, CAFILE_CRL);
	if (!cafile_entry) {
		memprintf(&err, "%sCannot allocate memory!\n", err ? err : "");
		goto error;
	}

	/* Add the newly created cafile_entry to the tree so that
	 * any new ckch instance created from now can use it. */
	if (ssl_store_add_uncommitted_cafile_entry(cafile_entry))
		goto error;

	memprintf(&err, "New CRL file created '%s'!\n", path);

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynmsg(appctx, LOG_NOTICE, err);
error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynerr(appctx, err);
}

/* Parsing function of `set ssl crl-file` */
static int cli_parse_set_crlfile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cafile_entry *old_crlfile_entry = NULL;
	struct cafile_entry *new_crlfile_entry = NULL;
	char *err = NULL;
	int errcode = 0;
	struct buffer *buf;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3] || !payload)
		return cli_err(appctx, "'set ssl crl-file' expects a filename and CRLs as a payload\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't update the CRL file!\nOperations on certificates are currently locked!\n");

	if ((buf = alloc_trash_chunk()) == NULL) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	if (!chunk_strcpy(buf, args[3])) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	old_crlfile_entry = NULL;
	new_crlfile_entry = NULL;

	/* if there is an ongoing transaction */
	if (crlfile_transaction.path) {
		/* if there is an ongoing transaction, check if this is the same file */
		if (strcmp(crlfile_transaction.path, buf->area) != 0) {
			memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", crlfile_transaction.path, buf->area);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		old_crlfile_entry = crlfile_transaction.old_crlfile_entry;
	}
	else {
		/* lookup for the certificate in the tree */
		old_crlfile_entry = ssl_store_get_cafile_entry(buf->area, 0);
	}

	if (!old_crlfile_entry) {
		memprintf(&err, "%sCan't replace a CRL file which is not referenced by the configuration!\n",
		          err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* Create a new cafile_entry without adding it to the cafile tree. */
	new_crlfile_entry = ssl_store_create_cafile_entry(old_crlfile_entry->path, NULL, CAFILE_CRL);
	if (!new_crlfile_entry) {
		memprintf(&err, "%sCannot allocate memory!\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* Fill the new entry with the new CRL. */
	if (ssl_store_load_ca_from_buf(new_crlfile_entry, payload, 0)) {
		memprintf(&err, "%sInvalid payload\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* we succeed, we can save the crl in the transaction */

	/* if there wasn't a transaction, update the old CRL */
	if (!crlfile_transaction.old_crlfile_entry) {
		crlfile_transaction.old_crlfile_entry = old_crlfile_entry;
		crlfile_transaction.path = old_crlfile_entry->path;
		err = memprintf(&err, "transaction created for CRL %s!\n", crlfile_transaction.path);
	} else {
		err = memprintf(&err, "transaction updated for CRL %s!\n", crlfile_transaction.path);
	}

	/* free the previous CRL file if there was a transaction */
	ssl_store_delete_cafile_entry(crlfile_transaction.new_crlfile_entry);

	crlfile_transaction.new_crlfile_entry = new_crlfile_entry;

	/* creates the SNI ctxs later in the IO handler */

end:
	free_trash_chunk(buf);

	if (errcode & ERR_CODE) {
		ssl_store_delete_cafile_entry(new_crlfile_entry);
		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynerr(appctx, memprintf(&err, "%sCan't update %s!\n", err ? err : "", args[3]));
	} else {

		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynmsg(appctx, LOG_NOTICE, err);
	}
}

/* Parsing function of 'commit ssl crl-file'.
 * It uses a commit_cacrlfile_ctx that's also shared with "commit ssl ca-file".
 */
static int cli_parse_commit_crlfile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct commit_cacrlfile_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'commit ssl ca-file' expects a filename\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't commit the CRL file!\nOperations on certificates are currently locked!\n");

	if (!crlfile_transaction.path) {
		memprintf(&err, "No ongoing transaction! !\n");
		goto error;
	}

	if (strcmp(crlfile_transaction.path, args[3]) != 0) {
		memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", crlfile_transaction.path, args[3]);
		goto error;
	}
	/* init the appctx structure */
	ctx->state = CACRL_ST_INIT;
	ctx->next_ckchi_link = NULL;
	ctx->old_entry = crlfile_transaction.old_crlfile_entry;
	ctx->new_entry = crlfile_transaction.new_crlfile_entry;
	ctx->cafile_type = CAFILE_CRL;

	return 0;

error:

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	err = memprintf(&err, "%sCan't commit %s!\n", err ? err : "", args[3]);

	return cli_dynerr(appctx, err);
}


/* release function of the `commit ssl crl-file' command, free things and unlock the spinlock.
 * it uses a commit_cacrlfile_ctx that's the same as for "commit ssl ca-file".
 */
static void cli_release_commit_crlfile(struct appctx *appctx)
{
	struct commit_cacrlfile_ctx *ctx = appctx->svcctx;
	struct cafile_entry *new_crlfile_entry = ctx->new_entry;

	/* Remove the uncommitted cafile_entry from the tree. */
	if (new_crlfile_entry) {
		ebmb_delete(&new_crlfile_entry->node);
		ssl_store_delete_cafile_entry(new_crlfile_entry);
	}
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	ha_free(&ctx->err);
}

/* parsing function of 'del ssl crl-file' */
static int cli_parse_del_crlfile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cafile_entry *cafile_entry;
	char *err = NULL;
	char *filename;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'del ssl crl-file' expects a CRL file name\n");

	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't delete the CRL file!\nOperations on certificates are currently locked!\n");

	filename = args[3];

	if (crlfile_transaction.path && strcmp(crlfile_transaction.path, filename) == 0) {
		memprintf(&err, "ongoing transaction for the CRL file '%s'", filename);
		goto error;
	}

	cafile_entry = ssl_store_get_cafile_entry(filename, 0);
	if (!cafile_entry) {
		memprintf(&err, "CRL file '%s' doesn't exist!\n", filename);
		goto error;
	}
	if (cafile_entry->type != CAFILE_CRL) {
		memprintf(&err, "'del ssl crl-file' does not work on CA files!\n");
		goto error;
	}

	if (!LIST_ISEMPTY(&cafile_entry->ckch_inst_link)) {
		memprintf(&err, "CRL file '%s' in use, can't be deleted!\n", filename);
		goto error;
	}

	/* Remove the cafile_entry from the tree */
	ebmb_delete(&cafile_entry->node);
	ssl_store_delete_cafile_entry(cafile_entry);

	memprintf(&err, "CRL file '%s' deleted!\n", filename);

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynmsg(appctx, LOG_NOTICE, err);

error:
	memprintf(&err, "Can't remove the CRL file: %s\n", err ? err : "");
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_dynerr(appctx, err);
}

/* parsing function of 'abort ssl crl-file' */
static int cli_parse_abort_crlfile(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'abort ssl crl-file' expects a filename\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't abort!\nOperations on certificates are currently locked!\n");

	if (!crlfile_transaction.path) {
		memprintf(&err, "No ongoing transaction!\n");
		goto error;
	}

	if (strcmp(crlfile_transaction.path, args[3]) != 0) {
		memprintf(&err, "The ongoing transaction is about '%s' but you are trying to abort a transaction for '%s'\n", crlfile_transaction.path, args[3]);
		goto error;
	}

	/* Only free the uncommitted cafile_entry here, because the SNI and instances were not generated yet */
	ssl_store_delete_cafile_entry(crlfile_transaction.new_crlfile_entry);
	crlfile_transaction.new_crlfile_entry = NULL;
	crlfile_transaction.old_crlfile_entry = NULL;
	crlfile_transaction.path = NULL;

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	err = memprintf(&err, "Transaction aborted for certificate '%s'!\n", args[3]);
	return cli_dynmsg(appctx, LOG_NOTICE, err);

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	return cli_dynerr(appctx, err);
}


/*
 * Display a Certificate Resignation List's information.
 * The information displayed is inspired by the output of 'openssl crl -in
 * crl.pem -text'.
 * Returns 0 in case of success.
 */
static int show_crl_detail(X509_CRL *crl, struct buffer *out)
{
	BIO *bio = NULL;
	struct buffer *tmp = alloc_trash_chunk();
	long version;
	X509_NAME *issuer;
	int write = -1;
#ifndef USE_OPENSSL_WOLFSSL
	STACK_OF(X509_REVOKED) *rev = NULL;
	X509_REVOKED *rev_entry = NULL;
	int i;
#endif

	if (!tmp)
		return -1;

	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		goto end;

	/* Version (as displayed by 'openssl crl') */
	version = X509_CRL_get_version(crl);
	chunk_appendf(out, "Version %ld\n", version + 1);

	/* Signature Algorithm */
	chunk_appendf(out, "Signature Algorithm: %s\n", OBJ_nid2ln(X509_CRL_get_signature_nid(crl)));

	/* Issuer */
	chunk_appendf(out, "Issuer: ");
	if ((issuer = X509_CRL_get_issuer(crl)) == NULL)
		goto end;
	if ((ssl_sock_get_dn_oneline(issuer, tmp)) == -1)
		goto end;
	*(tmp->area + tmp->data) = '\0';
	chunk_appendf(out, "%s\n", tmp->area);

	/* Last Update */
	chunk_appendf(out, "Last Update: ");
	chunk_reset(tmp);
	if (BIO_reset(bio) == -1)
		goto end;
	if (ASN1_TIME_print(bio, X509_CRL_get0_lastUpdate(crl)) == 0)
		goto end;
	write = BIO_read(bio, tmp->area, tmp->size-1);
	tmp->area[write] = '\0';
	chunk_appendf(out, "%s\n", tmp->area);


	/* Next Update */
	chunk_appendf(out, "Next Update: ");
	chunk_reset(tmp);
	if (BIO_reset(bio) == -1)
		goto end;
	if (ASN1_TIME_print(bio, X509_CRL_get0_nextUpdate(crl)) == 0)
		goto end;
	write = BIO_read(bio, tmp->area, tmp->size-1);
	tmp->area[write] = '\0';
	chunk_appendf(out, "%s\n", tmp->area);

#ifndef USE_OPENSSL_WOLFSSL
	/* Revoked Certificates */
	rev = X509_CRL_get_REVOKED(crl);
	if (sk_X509_REVOKED_num(rev) > 0)
		chunk_appendf(out, "Revoked Certificates:\n");
	else
		chunk_appendf(out, "No Revoked Certificates.\n");

	for (i = 0; i < sk_X509_REVOKED_num(rev); i++) {
		rev_entry = sk_X509_REVOKED_value(rev, i);

		/* Serial Number and Revocation Date */
		if (BIO_reset(bio) == -1)
			goto end;
		BIO_printf(bio , "    Serial Number: ");
		i2a_ASN1_INTEGER(bio, (ASN1_INTEGER*)X509_REVOKED_get0_serialNumber(rev_entry));
		BIO_printf(bio, "\n        Revocation Date: ");
		if (ASN1_TIME_print(bio, X509_REVOKED_get0_revocationDate(rev_entry)) == 0)
			goto end;
		BIO_printf(bio, "\n");

		write = BIO_read(bio, tmp->area, tmp->size-1);
		tmp->area[write] = '\0';
		chunk_appendf(out, "%s", tmp->area);
	}
#endif /* not USE_OPENSSL_WOLFSSL */

end:
	free_trash_chunk(tmp);
	if (bio)
		BIO_free(bio);

	return 0;
}

/* IO handler of details "show ssl crl-file [*][\]<filename[:index]>".
 * It uses show_crlfile_ctx and the global
 * crlfile_transaction.new_cafile_entry in read-only.
 */
static int cli_io_handler_show_crlfile_detail(struct appctx *appctx)
{
	struct show_crlfile_ctx *ctx = appctx->svcctx;
	struct cafile_entry *cafile_entry = ctx->cafile_entry;
	struct buffer *out = alloc_trash_chunk();
	int i;
	X509_CRL *crl;
	STACK_OF(X509_OBJECT) *objs;
	int retval = 0;
	int index = ctx->index;

	if (!out)
		goto end_no_putchk;

	chunk_appendf(out, "Filename: ");
	if (cafile_entry == crlfile_transaction.new_crlfile_entry)
		chunk_appendf(out, "*");
	chunk_appendf(out, "%s\n", cafile_entry->path);

	chunk_appendf(out, "Status: ");
	if (!cafile_entry->ca_store)
		chunk_appendf(out, "Empty\n");
	else if (cafile_entry == crlfile_transaction.new_crlfile_entry)
		chunk_appendf(out, "Uncommitted\n");
	else if (LIST_ISEMPTY(&cafile_entry->ckch_inst_link))
		chunk_appendf(out, "Unused\n");
	else
		chunk_appendf(out, "Used\n");

	if (!cafile_entry->ca_store)
		goto end;

	objs = X509_STORE_get0_objects(cafile_entry->ca_store);
	for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
		crl = X509_OBJECT_get0_X509_CRL(sk_X509_OBJECT_value(objs, i));
		if (!crl)
			continue;

		/* CRL indexes start at 1 on the CLI output. */
		if (index && index-1 != i)
			continue;

		chunk_appendf(out, " \nCertificate Revocation List #%d:\n", i+1);
		retval = show_crl_detail(crl, out);
		if (retval < 0)
			goto end_no_putchk;
		else if (retval || index)
			goto end;
	}

end:
	if (applet_putchk(appctx, out) == -1)
		goto yield;

end_no_putchk:
	free_trash_chunk(out);
	return 1;
yield:
	free_trash_chunk(out);
	return 0; /* should come back */
}

/* parsing function for 'show ssl crl-file [crlfile[:index]]'.
 * It sets the context to a show_crlfile_ctx, and the global
 * cafile_transaction.new_crlfile_entry under the ckch_lock.
 */
static int cli_parse_show_crlfile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_crlfile_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));
	struct cafile_entry *cafile_entry;
	long index = 0;
	char *colons;
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return cli_err(appctx, "Can't allocate memory!\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't show!\nOperations on certificates are currently locked!\n");

	/* check if there is a certificate to lookup */
	if (*args[3]) {

		/* Look for an optional index after the CRL file name */
		colons = strchr(args[3], ':');
		if (colons) {
			char *endptr;

			index = strtol(colons + 1, &endptr, 10);
			/* Indexes start at 1 */
			if (colons + 1 == endptr || *endptr != '\0' || index <= 0) {
				memprintf(&err, "wrong CRL index after colons in '%s'!", args[3]);
				goto error;
			}
			*colons = '\0';
		}

		if (*args[3] == '*') {
			char *filename = args[3]+1;

			if (filename[0] == '\\')
				 filename++;
			if (!crlfile_transaction.new_crlfile_entry)
				goto error;

			cafile_entry = crlfile_transaction.new_crlfile_entry;

			if (strcmp(filename, cafile_entry->path) != 0)
				goto error;

		} else {
			char *filename = args[3];

			if (filename[0] == '\\')
				filename++;
			/* Get the "original" cafile_entry and not the
			 * uncommitted one if it exists. */
			if ((cafile_entry = ssl_store_get_cafile_entry(filename, 1)) == NULL || cafile_entry->type != CAFILE_CRL)
				goto error;
		}

		ctx->cafile_entry = cafile_entry;
		ctx->index = index;
		/* use the IO handler that shows details */
		appctx->io_handler = cli_io_handler_show_crlfile_detail;
	}

	return 0;

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	if (err)
		return cli_dynerr(appctx, err);
	return cli_err(appctx, "Can't display the CRL file : Not found!\n");
}

/* IO handler of "show ssl crl-file". The command taking a specific CRL file name
 * is managed in cli_io_handler_show_crlfile_detail. */
static int cli_io_handler_show_crlfile(struct appctx *appctx)
{
	struct show_crlfile_ctx *ctx = appctx->svcctx;
	struct buffer *trash = alloc_trash_chunk();
	struct ebmb_node *node;
	struct cafile_entry *cafile_entry = NULL;

	if (trash == NULL)
		return 1;

	if (!ctx->old_crlfile_entry && crlfile_transaction.old_crlfile_entry) {
		chunk_appendf(trash, "# transaction\n");
		chunk_appendf(trash, "*%s\n", crlfile_transaction.old_crlfile_entry->path);
		if (applet_putchk(appctx, trash) == -1)
			goto yield;
		ctx->old_crlfile_entry = crlfile_transaction.old_crlfile_entry;
	}

	/* First time in this io_handler. */
	if (!ctx->cafile_entry) {
		chunk_appendf(trash, "# filename\n");
		node = ebmb_first(&cafile_tree);
	} else {
		/* We yielded during a previous call. */
		node = &ctx->cafile_entry->node;
	}

	while (node) {
		cafile_entry = ebmb_entry(node, struct cafile_entry, node);
		if (cafile_entry->type == CAFILE_CRL) {
			chunk_appendf(trash, "%s\n", cafile_entry->path);
		}

		node = ebmb_next(node);
		if (applet_putchk(appctx, trash) == -1)
			goto yield;
	}

	ctx->cafile_entry = NULL;
	free_trash_chunk(trash);
	return 1;
yield:

	free_trash_chunk(trash);
	ctx->cafile_entry = cafile_entry;
	return 0; /* should come back */
}


/* release function of the 'show ssl crl-file' command */
static void cli_release_show_crlfile(struct appctx *appctx)
{
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
}


void ckch_deinit()
{
	struct eb_node *node, *next;
	struct ckch_store *store;
	struct ebmb_node *canode;

	/* deinit the ckch stores */
	node = eb_first(&ckchs_tree);
	while (node) {
		next = eb_next(node);
		store = ebmb_entry(node, struct ckch_store, node);
		ckch_store_free(store);
		node = next;
	}

	/* deinit the ca-file store */
	canode = ebmb_first(&cafile_tree);
	while (canode) {
		struct cafile_entry *entry = NULL;

		entry = ebmb_entry(canode, struct cafile_entry, node);
		canode = ebmb_next(canode);
		ebmb_delete(&entry->node);
		ssl_store_delete_cafile_entry(entry);
	}
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "show", "ssl", "sni", NULL },       "show ssl sni [-f <frontend>] [-A]       : display the list of SNI and their corresponding filename",              cli_parse_show_sni, cli_io_handler_show_sni, cli_release_show_sni },

	{ { "new", "ssl", "cert", NULL },       "new ssl cert <certfile>                 : create a new certificate file to be used in a crt-list or a directory", cli_parse_new_cert, NULL, NULL },
	{ { "set", "ssl", "cert", NULL },       "set ssl cert <certfile> <payload>       : replace a certificate file",                                            cli_parse_set_cert, NULL, NULL },
	{ { "commit", "ssl", "cert", NULL },    "commit ssl cert <certfile>              : commit a certificate file",                                             cli_parse_commit_cert, cli_io_handler_commit_cert, cli_release_commit_cert },
	{ { "abort", "ssl", "cert", NULL },     "abort ssl cert <certfile>               : abort a transaction for a certificate file",                            cli_parse_abort_cert, NULL, NULL },
	{ { "del", "ssl", "cert", NULL },       "del ssl cert <certfile>                 : delete an unused certificate file",                                     cli_parse_del_cert, NULL, NULL },
	{ { "show", "ssl", "cert", NULL },      "show ssl cert [<certfile>]              : display the SSL certificates used in memory, or the details of a file", cli_parse_show_cert, cli_io_handler_show_cert, cli_release_show_cert },
	{ { "dump", "ssl", "cert", NULL },      "dump ssl cert <certfile>                : dump the SSL certificates in PEM format",                               cli_parse_dump_cert, cli_io_handler_dump_cert, cli_release_dump_cert },


	{ { "new", "ssl", "ca-file", NULL },    "new ssl ca-file <cafile>                : create a new CA file to be used in a crt-list",                         cli_parse_new_cafile, NULL, NULL },
	{ { "add", "ssl", "ca-file", NULL },    "add ssl ca-file <cafile> <payload>      : add a certificate into the CA file",                                    cli_parse_set_cafile, NULL, NULL },
	{ { "set", "ssl", "ca-file", NULL },    "set ssl ca-file <cafile> <payload>      : replace a CA file",                                                     cli_parse_set_cafile, NULL, NULL },
	{ { "commit", "ssl", "ca-file", NULL }, "commit ssl ca-file <cafile>             : commit a CA file",                                                      cli_parse_commit_cafile, cli_io_handler_commit_cafile_crlfile, cli_release_commit_cafile },
	{ { "abort", "ssl", "ca-file", NULL },  "abort ssl ca-file <cafile>              : abort a transaction for a CA file",                                     cli_parse_abort_cafile, NULL, NULL },
	{ { "del", "ssl", "ca-file", NULL },    "del ssl ca-file <cafile>                : delete an unused CA file",                                              cli_parse_del_cafile, NULL, NULL },
	{ { "show", "ssl", "ca-file", NULL },   "show ssl ca-file [<cafile>[:<index>]]   : display the SSL CA files used in memory, or the details of a <cafile>, or a single certificate of index <index> of a CA file <cafile>", cli_parse_show_cafile, cli_io_handler_show_cafile, cli_release_show_cafile },

	{ { "new", "ssl", "crl-file", NULL },   "new ssl crl-file <crlfile>               : create a new CRL file to be used in a crt-list",                        cli_parse_new_crlfile, NULL, NULL },
	{ { "set", "ssl", "crl-file", NULL },   "set ssl crl-file <crlfile> <payload>    : replace a CRL file",                                                    cli_parse_set_crlfile, NULL, NULL },
	{ { "commit", "ssl", "crl-file", NULL },"commit ssl crl-file <crlfile>           : commit a CRL file",                                                     cli_parse_commit_crlfile, cli_io_handler_commit_cafile_crlfile, cli_release_commit_crlfile },
	{ { "abort", "ssl", "crl-file", NULL }, "abort ssl crl-file <crlfile>            : abort a transaction for a CRL file",                                    cli_parse_abort_crlfile, NULL, NULL },
	{ { "del", "ssl", "crl-file", NULL },   "del ssl crl-file <crlfile>              : delete an unused CRL file",                                             cli_parse_del_crlfile, NULL, NULL },
	{ { "show", "ssl", "crl-file", NULL },  "show ssl crl-file [<crlfile[:<index>>]] : display the SSL CRL files used in memory, or the details of a <crlfile>, or a single CRL of index <index> of CRL file <crlfile>", cli_parse_show_crlfile, cli_io_handler_show_crlfile, cli_release_show_crlfile },
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

static char *current_crtbase = NULL;
static char *current_keybase = NULL;
static int crtstore_load = 0; /* did we already load in this crt-store */

struct ckch_conf_kws ckch_conf_kws[] = {
	{ "alias",                               -1,                 PARSE_TYPE_NONE, NULL,                                  NULL },
	{ "crt",    offsetof(struct ckch_conf, crt),    PARSE_TYPE_STR, ckch_conf_load_pem,           &current_crtbase },
	{ "key",    offsetof(struct ckch_conf, key),    PARSE_TYPE_STR, ckch_conf_load_key,           &current_keybase },
#ifdef HAVE_SSL_OCSP
	{ "ocsp",   offsetof(struct ckch_conf, ocsp),   PARSE_TYPE_STR, ckch_conf_load_ocsp_response, &current_crtbase },
#endif
	{ "issuer", offsetof(struct ckch_conf, issuer), PARSE_TYPE_STR, ckch_conf_load_ocsp_issuer,   &current_crtbase },
	{ "sctl",   offsetof(struct ckch_conf, sctl),   PARSE_TYPE_STR, ckch_conf_load_sctl,          &current_crtbase },
#if defined(HAVE_SSL_OCSP)
	{ "ocsp-update", offsetof(struct ckch_conf, ocsp_update_mode), PARSE_TYPE_ONOFF, ocsp_update_init, NULL   },
#endif
	{ NULL,     -1,                                  PARSE_TYPE_STR, NULL,                                  NULL            }
};

/* crt-store does not try to find files, but use the stored filename */
int ckch_store_load_files(struct ckch_conf *f, struct ckch_store *c, int cli, char **err)
{
	int i;
	int err_code = 0;
	int rc = 1;
	struct ckch_data *d = c->data;

	for (i = 0; ckch_conf_kws[i].name; i++) {
		void *src = NULL;

		if (ckch_conf_kws[i].offset < 0)
			continue;

		if (!ckch_conf_kws[i].func)
			continue;

		src = (void *)((intptr_t)f + (ptrdiff_t)ckch_conf_kws[i].offset);

		switch (ckch_conf_kws[i].type) {
			case PARSE_TYPE_STR:
			{
				char *v;
				char *path;
				char **base = ckch_conf_kws[i].base;
				char path_base[PATH_MAX];

				v = *(char **)src;
				if (!v)
					goto next;

				path = v;
				if (base && *base && *path != '/') {
					int rv = snprintf(path_base, sizeof(path_base), "%s/%s", *base, path);
					if (rv >= sizeof(path_base)) {
						memprintf(err, "'%s/%s' : path too long", *base, path);
						err_code |= ERR_ALERT | ERR_FATAL;
						goto out;
					}
					path = path_base;
				}
				rc = ckch_conf_kws[i].func(path, NULL, d, cli, err);
				if (rc) {
					err_code |= ERR_ALERT | ERR_FATAL;
					memprintf(err, "%s '%s' cannot be read or parsed.", err && *err ? *err : "", path);
					goto out;
				}
				break;
			}

			case PARSE_TYPE_INT:
			case PARSE_TYPE_ONOFF:
			{
				int v = *(int *)src;
				rc = ckch_conf_kws[i].func(&v, NULL, d, cli, err);
				if (rc) {
					err_code |= ERR_ALERT | ERR_FATAL;
					memprintf(err, "%s '%d' cannot be read or parsed.", err && *err ? *err : "", v);
					goto out;
				}

				break;
			}

			default:
				break;
		}
next:
		;
	}

out:
	if (err_code & ERR_FATAL)
		ssl_sock_free_cert_key_and_chain_contents(d);
	ERR_clear_error();

	return err_code;
}

/* Parse a local crt-base or key-base for a crt-store */
static int crtstore_parse_path_base(char **args, int section_type, struct proxy *curpx, const struct proxy *defpx,
                        const char *file, int linenum, char **err)
{
	int err_code = ERR_NONE;

	if (!*args[1]) {
		memprintf(err, "parsing [%s:%d] : '%s' requires a <path> argument.",
		          file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	if (crtstore_load) {
		memprintf(err, "parsing [%s:%d] : '%s' can't be used after a load line, use it at the beginning of the section.",
		          file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	if (args[0][1] == 'r') {
		/* crt-base */
		free(current_crtbase);
		current_crtbase = strdup(args[1]);
	} else if (args[0][1] == 'e') {
		/* key-base */
		free(current_keybase);
		current_keybase = strdup(args[1]);
	}
out:
	return err_code;
}

/*
 * Check if ckch_conf <prev> and <new> are compatible:
 *
 * new \ prev | EMPTY | CRTLIST  | CRTSTORE
 * ----------------------------------------
 *  EMPTY     |  OK   |  X       |   OK
 * ----------------------------------------
 *  CRTLIST   |  X    | CMP      |  CMP
 * ----------------------------------------
 *
 * Return:
 *  1 when the 2 structures have different variables or are incompatible
 *  0 when the 2 structures have equal variables or are compatibles
 */
int ckch_conf_cmp(struct ckch_conf *prev, struct ckch_conf *new, char **err)
{
	int ret = 0;
	int i;

	if (!prev || !new)
	    return 1;

	/* compatibility check */

	if (prev->used == CKCH_CONF_SET_EMPTY) {
		if (new->used == CKCH_CONF_SET_CRTLIST) {
			memprintf(err, "%sCan't use the certificate previously defined without any keyword with these keywords:\n", *err ? *err : "");
			ret = 1;
		}
		if (new->used == CKCH_CONF_SET_EMPTY)
			return 0;

	} else if (prev->used == CKCH_CONF_SET_CRTLIST) {
		if (new->used == CKCH_CONF_SET_EMPTY) {
			memprintf(err, "%sCan't use the certificate previously defined with keywords without these keywords:\n", *err ? *err : "");
			ret = 1;
		}
	} else if (prev->used == CKCH_CONF_SET_CRTSTORE) {
		if (new->used == CKCH_CONF_SET_EMPTY)
			return 0;
	}


	for (i = 0; ckch_conf_kws[i].name != NULL; i++) {

		if (strcmp(ckch_conf_kws[i].name, "crt") == 0)
			continue;

		switch (ckch_conf_kws[i].type) {
			case PARSE_TYPE_STR: {
				char *avail1, *avail2;
				avail1 = *(char **)((intptr_t)prev + (ptrdiff_t)ckch_conf_kws[i].offset);
				avail2 = *(char **)((intptr_t)new + (ptrdiff_t)ckch_conf_kws[i].offset);

				/* must alert when strcmp is wrong, or when one of the field is NULL */
				if (((avail1 && avail2) && strcmp(avail1, avail2) != 0) || (!!avail1 ^ !!avail2)) {
					memprintf(err, "%s- different parameter '%s' : previously '%s' vs '%s'\n", *err ? *err : "", ckch_conf_kws[i].name, avail1, avail2);
					ret = 1;
				}
			}
			break;

			default:
				break;
		}
#if defined(HAVE_SSL_OCSP)
		/* special case for ocsp-update and default */
		if (strcmp(ckch_conf_kws[i].name, "ocsp-update") == 0) {
			int o1, o2; /* ocsp-update from the configuration */
			int q1, q2; /* final ocsp-update value (from default) */


			o1 = *(int *)((intptr_t)prev + (ptrdiff_t)ckch_conf_kws[i].offset);
			o2 = *(int *)((intptr_t)new + (ptrdiff_t)ckch_conf_kws[i].offset);

			q1 = (o1 == SSL_SOCK_OCSP_UPDATE_DFLT) ? global_ssl.ocsp_update.mode : o1;
			q2 = (o2 == SSL_SOCK_OCSP_UPDATE_DFLT) ? global_ssl.ocsp_update.mode : o2;

			if (q1 != q2) {
				int j = 1;
				int o = o1;
				int q = q1;
				memprintf(err, "%s- different parameter '%s' : previously ", *err ? *err : "", ckch_conf_kws[i].name);

				do {
					switch (o) {
						case SSL_SOCK_OCSP_UPDATE_DFLT:
							memprintf(err, "%s'default' (ocsp-update.mode %s)", *err ? *err : "", (q > 0) ? "on" : "off");
						break;
						case SSL_SOCK_OCSP_UPDATE_ON:
							memprintf(err, "%s'%s'", *err ? *err : "", "on");
						break;
						case SSL_SOCK_OCSP_UPDATE_OFF:
							memprintf(err, "%s'%s'", *err ? *err : "", "off");
						break;
					}
					o = o2;
					q = q2;
					if (j)
						memprintf(err, "%s vs ", *err ? *err : "");
				} while (j--);
				memprintf(err, "%s\n", *err ? *err : "");
				ret = 1;
			}
		}
#endif
	}

out:
	return ret;
}

/*
 *  Compare a previously generated ckch_conf with an empty one, using ckch_conf_cmp().
 */
int ckch_conf_cmp_empty(struct ckch_conf *prev, char **err)
{
	struct ckch_conf new = {};

	return ckch_conf_cmp(prev, &new, err);
}

/* parse ckch_conf keywords for crt-list */
int ckch_conf_parse(char **args, int cur_arg, struct ckch_conf *f, int *found, const char *file, int linenum, char **err)
{
	int i;
	int err_code = 0;

	for (i = 0; ckch_conf_kws[i].name != NULL; i++) {
		if (strcmp(ckch_conf_kws[i].name, args[cur_arg]) == 0) {
			void *target;
			*found = 1;
			target = (char **)((intptr_t)f + (ptrdiff_t)ckch_conf_kws[i].offset);

			if (ckch_conf_kws[i].type == PARSE_TYPE_STR) {
				char **t = target;

				*t = strdup(args[cur_arg + 1]);
				if (!*t) {
					ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
					err_code |= ERR_ALERT | ERR_ABORT;
					goto out;
				}
			} else if (ckch_conf_kws[i].type == PARSE_TYPE_INT) {
				int *t = target;
				char *stop;

				*t = strtol(args[cur_arg + 1], &stop, 10);
				if (*stop != '\0') {
					memprintf(err, "parsing [%s:%d] : cannot parse '%s' value '%s', an integer is expected.\n",
					          file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			} else if (ckch_conf_kws[i].type == PARSE_TYPE_ONOFF) {
				int *t = target;

				if (strcmp(args[cur_arg + 1], "on") == 0) {
					*t = 1;
				} else if (strcmp(args[cur_arg + 1], "off") == 0) {
					*t = -1;
				} else {
					memprintf(err, "parsing [%s:%d] : cannot parse '%s' value '%s', 'on' or 'off' is expected.\n",
					          file, linenum, args[cur_arg], args[cur_arg + 1]);
					err_code |= ERR_ALERT | ERR_FATAL;
					goto out;
				}
			}
			break;
		}
	}
out:
	return err_code;
}

/* freeing the content of a ckch_conf structure */
void ckch_conf_clean(struct ckch_conf *conf)
{
	free(conf->crt);
	free(conf->key);
	free(conf->ocsp);
	free(conf->issuer);
	free(conf->sctl);
}

static char current_crtstore_name[PATH_MAX] = {};

static int crtstore_parse_load(char **args, int section_type, struct proxy *curpx, const struct proxy *defpx,
                        const char *file, int linenum, char **err)
{
	int err_code = 0;
	int cur_arg = 0;
	struct ckch_conf f = {};
	struct ckch_store *c = NULL;
	char store_path[PATH_MAX]; /* complete path with crt_base */
	char alias_name[PATH_MAX]; /* complete alias name with the store prefix '@/' */
	char *final_name = NULL; /* name used as a key in the ckch_store */

	cur_arg++; /* skip "load" */

	while (*(args[cur_arg])) {
		int found = 0;

		if (strcmp("alias", args[cur_arg]) == 0) {
			int rv;

			if (*args[cur_arg + 1] == '/') {
				memprintf(err, "parsing [%s:%d] : cannot parse '%s' value '%s', '/' is forbidden as the first character.\n",
					  file, linenum, args[cur_arg], args[cur_arg + 1]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}

			rv = snprintf(alias_name, sizeof(alias_name), "@%s/%s", current_crtstore_name, args[cur_arg + 1]);
			if (rv >= sizeof(alias_name)) {
				memprintf(err, "parsing [%s:%d] : cannot parse '%s' value '%s', too long, max len is %zd.\n",
					  file, linenum, args[cur_arg], args[cur_arg + 1], sizeof(alias_name));
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			final_name = alias_name;
			found = 1;
		} else {
			err_code |= ckch_conf_parse(args, cur_arg, &f, &found, file, linenum, err);
			if (err_code & ERR_FATAL)
			goto out;
		}

		if (!found) {
			memprintf(err,"parsing [%s:%d] : '%s %s' in section 'crt-store': unknown keyword '%s'.",
			         file, linenum, args[0], args[cur_arg],args[cur_arg]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
		cur_arg += 2;
	}

	if (!f.crt) {
		memprintf(err,"parsing [%s:%d] : '%s' in section 'crt-store': mandatory 'crt' parameter not found.",
		         file, linenum, args[0]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	crtstore_load = 1;

	if (!final_name) {
		final_name = f.crt;

		/* if no alias was used:
		 * - when a crt-store exists, use @store/crt
		 * - or use the absolute file (crt_base + crt)
		 * - or the relative file when no crt_base exists
		 */
		if (current_crtstore_name[0] != '\0') {
			int rv;

			/* add the crt-store name, avoid a double / if the crt starts by it */
			rv = snprintf(alias_name, sizeof(alias_name), "@%s%s%s", current_crtstore_name, f.crt[0] != '/' ? "/" : "", f.crt);
			if (rv >= sizeof(alias_name)) {
				memprintf(err, "parsing [%s:%d] : cannot parse '%s' value '%s', too long, max len is %zd.\n",
				          file, linenum, args[cur_arg], args[cur_arg + 1], sizeof(alias_name));
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			final_name = alias_name;
		} else if (global_ssl.crt_base && *f.crt != '/') {
			int rv;
			/* When no crt_store name, complete the name in the ckch_tree with 'crt-base' */

			rv = snprintf(store_path, sizeof(store_path), "%s/%s", global_ssl.crt_base, f.crt);
			if (rv >= sizeof(store_path)) {
				memprintf(err, "'%s/%s' : path too long", global_ssl.crt_base, f.crt);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			final_name = store_path;
		}
	}
	/* process and insert the ckch_store */
	c = ckch_store_new(final_name);
	if (!c)
		goto alloc_error;

	err_code |= ckch_store_load_files(&f, c,  0, err);
	if (err_code & ERR_FATAL)
		goto out;

	c->conf = f;
	c->conf.used = CKCH_CONF_SET_CRTSTORE;

	if (ebst_insert(&ckchs_tree, &c->node) != &c->node) {
		memprintf(err,"parsing [%s:%d] : '%s' in section 'crt-store': store '%s' was already defined.",
		         file, linenum, args[0], c->path);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

out:
	/* free ckch_conf content */
	if (err_code & ERR_FATAL)
		ckch_store_free(c);
	return err_code;

alloc_error:
	ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
	err_code |= ERR_ALERT | ERR_ABORT;
	goto out;
}

/*
 * Parse "crt-store" section and create corresponding ckch_stores.
 *
 * The function returns 0 in success case, otherwise, it returns error
 * flags.
 */
static int cfg_parse_crtstore(const char *file, int linenum, char **args, int kwm)
{
	struct cfg_kw_list *kwl;
	const char *best;
	int index;
	int rc = 0;
	int err_code = 0;
	char *errmsg = NULL;

	if (strcmp(args[0], "crt-store") == 0) { /* new crt-store section */
		if (!*args[1]) {
			current_crtstore_name[0] = '\0';
		} else {
			rc = snprintf(current_crtstore_name, sizeof(current_crtstore_name), "%s", args[1]);
			if (rc >= sizeof(current_crtstore_name)) {
				ha_alert("parsing [%s:%d] : 'crt-store' <name> argument is too long.\n", file, linenum);
				current_crtstore_name[0] = '\0';
				err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
				goto out;
			}
		}

		if (*args[2]) {
			ha_alert("parsing [%s:%d] : 'crt-store' section only supports a <name> argument.\n", file, linenum);
			err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
			goto out;
		}
		/* copy the crt_base and key_base */
		ha_free(&current_crtbase);
		if (global_ssl.crt_base)
			current_crtbase = strdup(global_ssl.crt_base);
		ha_free(&current_keybase);
		if (global_ssl.key_base)
			current_keybase = strdup(global_ssl.key_base);
		crtstore_load = 0;

		goto out;
	}

	list_for_each_entry(kwl, &cfg_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if (kwl->kw[index].section != CFG_CRTSTORE)
				continue;
			if (strcmp(kwl->kw[index].kw, args[0]) == 0) {
				if (check_kw_experimental(&kwl->kw[index], file, linenum, &errmsg)) {
					ha_alert("%s\n", errmsg);
					err_code |= ERR_ALERT | ERR_FATAL | ERR_ABORT;
					goto out;
				}

				/* prepare error message just in case */
				rc = kwl->kw[index].parse(args, CFG_CRTSTORE, NULL, NULL, file, linenum, &errmsg);
				if (rc & ERR_ALERT) {
					ha_alert("parsing [%s:%d] : %s\n", file, linenum, errmsg);
					err_code |= rc;
					goto out;
				}
				else if (rc & ERR_WARN) {
					ha_warning("parsing [%s:%d] : %s\n", file, linenum, errmsg);
					err_code |= rc;
					goto out;
				}
				goto out;
			}
		}
	}

	best = cfg_find_best_match(args[0], &cfg_keywords.list, CFG_CRTSTORE, NULL);
	if (best)
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section; did you mean '%s' maybe ?\n", file, linenum, args[0], cursection, best);
	else
		ha_alert("parsing [%s:%d] : unknown keyword '%s' in '%s' section\n", file, linenum, args[0], cursection);
	err_code |= ERR_ALERT | ERR_FATAL;
	goto out;

out:
	if (err_code & ERR_FATAL)
		err_code |= ERR_ABORT;
	free(errmsg);
	return err_code;
}

static int cfg_post_parse_crtstore()
{
	current_crtstore_name[0] = '\0';
	ha_free(&current_crtbase);
	ha_free(&current_keybase);

	return ERR_NONE;
}

REGISTER_CONFIG_SECTION("crt-store", cfg_parse_crtstore, cfg_post_parse_crtstore);

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_CRTSTORE, "crt-base", crtstore_parse_path_base },
	{ CFG_CRTSTORE, "key-base", crtstore_parse_path_base },
	{ CFG_CRTSTORE, "load", crtstore_parse_load },
	{ 0, NULL, NULL },
}};
INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
