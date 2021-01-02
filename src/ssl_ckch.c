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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <import/ebsttree.h>

#include <haproxy/base64.h>
#include <haproxy/channel.h>
#include <haproxy/cli.h>
#include <haproxy/errors.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/ssl_utils.h>
#include <haproxy/stream_interface.h>
#include <haproxy/tools.h>

/* Uncommitted CKCH transaction */

static struct {
	struct ckch_store *new_ckchs;
	struct ckch_store *old_ckchs;
	char *path;
} ckchs_transaction;



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
int ssl_sock_load_sctl_from_file(const char *sctl_path, char *buf, struct cert_key_and_chain *ckch, char **err)
{
	int fd = -1;
	int r = 0;
	int ret = 1;
	struct buffer tmp;
	struct buffer *src;
	struct buffer *sctl;

	if (buf) {
		tmp.area = buf;
		tmp.data = strlen(buf);
		tmp.size = tmp.data + 1;
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
		free(sctl);
		sctl = NULL;
		goto end;
	}
	/* no error, fill ckch with new context, old context must be free */
	if (ckch->sctl) {
		free(ckch->sctl->area);
		ckch->sctl->area = NULL;
		free(ckch->sctl);
	}
	ckch->sctl = sctl;
	ret = 0;
end:
	if (fd != -1)
		close(fd);

	return ret;
}

#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) || defined OPENSSL_IS_BORINGSSL)
/*
 * This function load the OCSP Response in DER format contained in file at
 * path 'ocsp_path' or base64 in a buffer <buf>
 *
 * Returns 0 on success, 1 in error case.
 */
int ssl_sock_load_ocsp_response_from_file(const char *ocsp_path, char *buf, struct cert_key_and_chain *ckch, char **err)
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
		free(ocsp_response);
		ocsp_response = NULL;
		goto end;
	}
	/* no error, fill ckch with new context, old context must be free */
	if (ckch->ocsp_response) {
		free(ckch->ocsp_response->area);
		ckch->ocsp_response->area = NULL;
		free(ckch->ocsp_response);
	}
	ckch->ocsp_response = ocsp_response;
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
int ssl_sock_load_files_into_ckch(const char *path, struct cert_key_and_chain *ckch, char **err)
{
	struct buffer *fp = NULL;
	int ret = 1;

	/* try to load the PEM */
	if (ssl_sock_load_pem_into_ckch(path, NULL, ckch , err) != 0) {
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

	/* try to load an external private key if it wasn't in the PEM */
	if ((ckch->key == NULL) && (global_ssl.extra_files & SSL_GF_KEY)) {
		struct stat st;


		if (!chunk_strcat(fp, ".key") || (b_data(fp) > MAXPATHLEN)) {
			memprintf(err, "%s '%s' filename too long'.\n",
			          err && *err ? *err : "", fp->area);
			ret = 1;
			goto end;
		}

		if (stat(fp->area, &st) == 0) {
			if (ssl_sock_load_key_into_ckch(fp->area, NULL, ckch, err)) {
				memprintf(err, "%s '%s' is present but cannot be read or parsed'.\n",
					  err && *err ? *err : "", fp->area);
				goto end;
			}
		}

		if (ckch->key == NULL) {
			memprintf(err, "%sNo Private Key found in '%s'.\n", err && *err ? *err : "", fp->area);
			goto end;
		}
		/* remove the added extension */
		*(fp->area + fp->data - strlen(".key")) = '\0';
		b_sub(fp, strlen(".key"));
	}

	if (!X509_check_private_key(ckch->cert, ckch->key)) {
		memprintf(err, "%sinconsistencies between private key and certificate loaded '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
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
			if (ssl_sock_load_sctl_from_file(fp->area, NULL, ckch, err)) {
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
			if (ssl_sock_load_ocsp_response_from_file(fp->area, NULL, ckch, err)) {
				ret = 1;
				goto end;
			}
		}
		/* remove the added extension */
		*(fp->area + fp->data - strlen(".ocsp")) = '\0';
		b_sub(fp, strlen(".ocsp"));
	}

#ifndef OPENSSL_IS_BORINGSSL /* Useless for BoringSSL */
	if (ckch->ocsp_response && (global_ssl.extra_files & SSL_GF_OCSP_ISSUER)) {
		/* if no issuer was found, try to load an issuer from the .issuer */
		if (!ckch->ocsp_issuer) {
			struct stat st;

			if (!chunk_strcat(fp, ".issuer") || b_data(fp) > MAXPATHLEN) {
				memprintf(err, "%s '%s' filename too long'.\n",
					  err && *err ? *err : "", fp->area);
				ret = 1;
				goto end;
			}

			if (stat(fp->area, &st) == 0) {
				if (ssl_sock_load_issuer_file_into_ckch(fp->area, NULL, ckch, err)) {
					ret = 1;
					goto end;
				}

				if (X509_check_issued(ckch->ocsp_issuer, ckch->cert) != X509_V_OK) {
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

	ret = 0;

end:

	ERR_clear_error();

	/* Something went wrong in one of the reads */
	if (ret != 0)
		ssl_sock_free_cert_key_and_chain_contents(ckch);

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
int ssl_sock_load_key_into_ckch(const char *path, char *buf, struct cert_key_and_chain *ckch , char **err)
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

	SWAP(ckch->key, key);

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
int ssl_sock_load_pem_into_ckch(const char *path, char *buf, struct cert_key_and_chain *ckch , char **err)
{
	BIO *in = NULL;
	int ret = 1;
	X509 *ca;
	X509 *cert = NULL;
	EVP_PKEY *key = NULL;
	DH *dh = NULL;
	STACK_OF(X509) *chain = NULL;

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

	dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
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
		memprintf(err, "%sunable to load certificate from file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

	/* Look for a Certificate Chain */
	while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
		if (chain == NULL)
			chain = sk_X509_new_null();
		if (!sk_X509_push(chain, ca)) {
			X509_free(ca);
			goto end;
		}
	}

	ret = ERR_get_error();
	if (ret && (ERR_GET_LIB(ret) != ERR_LIB_PEM && ERR_GET_REASON(ret) != PEM_R_NO_START_LINE)) {
		memprintf(err, "%sunable to load certificate chain from file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

	/* once it loaded the PEM, it should remove everything else in the ckch */
	if (ckch->ocsp_response) {
		free(ckch->ocsp_response->area);
		ckch->ocsp_response->area = NULL;
		free(ckch->ocsp_response);
		ckch->ocsp_response = NULL;
	}

	if (ckch->sctl) {
		free(ckch->sctl->area);
		ckch->sctl->area = NULL;
		free(ckch->sctl);
		ckch->sctl = NULL;
	}

	if (ckch->ocsp_issuer) {
		X509_free(ckch->ocsp_issuer);
		ckch->ocsp_issuer = NULL;
	}

	/* no error, fill ckch with new context, old context will be free at end: */
	SWAP(ckch->key, key);
	SWAP(ckch->dh, dh);
	SWAP(ckch->cert, cert);
	SWAP(ckch->chain, chain);

	ret = 0;

end:

	ERR_clear_error();
	if (in)
		BIO_free(in);
	if (key)
		EVP_PKEY_free(key);
	if (dh)
		DH_free(dh);
	if (cert)
		X509_free(cert);
	if (chain)
		sk_X509_pop_free(chain, X509_free);

	return ret;
}

/* Frees the contents of a cert_key_and_chain
 */
void ssl_sock_free_cert_key_and_chain_contents(struct cert_key_and_chain *ckch)
{
	if (!ckch)
		return;

	/* Free the certificate and set pointer to NULL */
	if (ckch->cert)
		X509_free(ckch->cert);
	ckch->cert = NULL;

	/* Free the key and set pointer to NULL */
	if (ckch->key)
		EVP_PKEY_free(ckch->key);
	ckch->key = NULL;

	/* Free each certificate in the chain */
	if (ckch->chain)
		sk_X509_pop_free(ckch->chain, X509_free);
	ckch->chain = NULL;

	if (ckch->dh)
		DH_free(ckch->dh);
	ckch->dh = NULL;

	if (ckch->sctl) {
		free(ckch->sctl->area);
		ckch->sctl->area = NULL;
		free(ckch->sctl);
		ckch->sctl = NULL;
	}

	if (ckch->ocsp_response) {
		free(ckch->ocsp_response->area);
		ckch->ocsp_response->area = NULL;
		free(ckch->ocsp_response);
		ckch->ocsp_response = NULL;
	}

	if (ckch->ocsp_issuer)
		X509_free(ckch->ocsp_issuer);
	ckch->ocsp_issuer = NULL;
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
struct cert_key_and_chain *ssl_sock_copy_cert_key_and_chain(struct cert_key_and_chain *src,
                                                                   struct cert_key_and_chain *dst)
{
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
		DH_up_ref(src->dh);
		dst->dh = src->dh;
	}

	if (src->sctl) {
		struct buffer *sctl;

		sctl = calloc(1, sizeof(*sctl));
		if (!chunk_dup(sctl, src->sctl)) {
			free(sctl);
			sctl = NULL;
			goto error;
		}
		dst->sctl = sctl;
	}

	if (src->ocsp_response) {
		struct buffer *ocsp_response;

		ocsp_response = calloc(1, sizeof(*ocsp_response));
		if (!chunk_dup(ocsp_response, src->ocsp_response)) {
			free(ocsp_response);
			ocsp_response = NULL;
			goto error;
		}
		dst->ocsp_response = ocsp_response;
	}

	if (src->ocsp_issuer) {
		X509_up_ref(src->ocsp_issuer);
		dst->ocsp_issuer = src->ocsp_issuer;
	}

	return dst;

error:

	/* free everything */
	ssl_sock_free_cert_key_and_chain_contents(dst);

	return NULL;
}

/*
 * return 0 on success or != 0 on failure
 */
int ssl_sock_load_issuer_file_into_ckch(const char *path, char *buf, struct cert_key_and_chain *ckch, char **err)
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
	/* no error, fill ckch with new context, old context must be free */
	if (ckch->ocsp_issuer)
		X509_free(ckch->ocsp_issuer);
	ckch->ocsp_issuer = issuer;
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

	ssl_sock_free_cert_key_and_chain_contents(store->ckch);

	free(store->ckch);
	store->ckch = NULL;

	list_for_each_entry_safe(inst, inst_s, &store->ckch_inst, by_ckchs) {
		ckch_inst_free(inst);
	}
	ebmb_delete(&store->node);
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

	store->ckch = calloc(1, sizeof(*store->ckch));
	if (!store->ckch)
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

	dst = ckch_store_new(src->path);

	if (!ssl_sock_copy_cert_key_and_chain(src->ckch, dst->ckch))
		goto error;

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
struct ckch_store *ckchs_load_cert_file(char *path, char **err)
{
	struct ckch_store *ckchs;

	ckchs = ckch_store_new(path);
	if (!ckchs) {
		memprintf(err, "%sunable to allocate memory.\n", err && *err ? *err : "");
		goto end;
	}

	if (ssl_sock_load_files_into_ckch(path, ckchs->ckch, err) == 1)
		goto end;

	/* insert into the ckchs tree */
	memcpy(ckchs->path, path, strlen(path) + 1);
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

	if (inst == NULL)
		return;

	list_for_each_entry_safe(sni, sni_s, &inst->sni_ctx, by_ckch_inst) {
		SSL_CTX_free(sni->ctx);
		LIST_DEL(&sni->by_ckch_inst);
		ebmb_delete(&sni->name);
		free(sni);
	}
	LIST_DEL(&inst->by_ckchs);
	LIST_DEL(&inst->by_crtlist_entry);
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

	return ckch_inst;
}

/*************************** CLI commands ***********************/

/* Type of SSL payloads that can be updated over the CLI */

enum {
	CERT_TYPE_PEM = 0,
	CERT_TYPE_KEY,
#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) || defined OPENSSL_IS_BORINGSSL)
	CERT_TYPE_OCSP,
#endif
	CERT_TYPE_ISSUER,
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
	CERT_TYPE_SCTL,
#endif
	CERT_TYPE_MAX,
};

struct {
	const char *ext;
	int type;
	int (*load)(const char *path, char *payload, struct cert_key_and_chain *ckch, char **err);
	/* add a parsing callback */
} cert_exts[CERT_TYPE_MAX+1] = {
	[CERT_TYPE_PEM]    = { "",        CERT_TYPE_PEM,      &ssl_sock_load_pem_into_ckch }, /* default mode, no extensions */
	[CERT_TYPE_KEY]    = { "key",     CERT_TYPE_KEY,      &ssl_sock_load_key_into_ckch },
#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) || defined OPENSSL_IS_BORINGSSL)
	[CERT_TYPE_OCSP]   = { "ocsp",    CERT_TYPE_OCSP,     &ssl_sock_load_ocsp_response_from_file },
#endif
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
	[CERT_TYPE_SCTL]   = { "sctl",    CERT_TYPE_SCTL,     &ssl_sock_load_sctl_from_file },
#endif
	[CERT_TYPE_ISSUER] = { "issuer",  CERT_TYPE_ISSUER,   &ssl_sock_load_issuer_file_into_ckch },
	[CERT_TYPE_MAX]    = { NULL,      CERT_TYPE_MAX,      NULL },
};


/* release function of the  `show ssl cert' command */
static void cli_release_show_cert(struct appctx *appctx)
{
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
}

/* IO handler of "show ssl cert <filename>" */
static int cli_io_handler_show_cert(struct appctx *appctx)
{
	struct buffer *trash = alloc_trash_chunk();
	struct ebmb_node *node;
	struct stream_interface *si = appctx->owner;
	struct ckch_store *ckchs;

	if (trash == NULL)
		return 1;

	if (!appctx->ctx.ssl.old_ckchs) {
		if (ckchs_transaction.old_ckchs) {
			ckchs = ckchs_transaction.old_ckchs;
			chunk_appendf(trash, "# transaction\n");
			chunk_appendf(trash, "*%s\n", ckchs->path);
		}
	}

	if (!appctx->ctx.cli.p0) {
		chunk_appendf(trash, "# filename\n");
		node = ebmb_first(&ckchs_tree);
	} else {
		node = &((struct ckch_store *)appctx->ctx.cli.p0)->node;
	}
	while (node) {
		ckchs = ebmb_entry(node, struct ckch_store, node);
		chunk_appendf(trash, "%s\n", ckchs->path);

		node = ebmb_next(node);
		if (ci_putchk(si_ic(si), trash) == -1) {
			si_rx_room_blk(si);
			goto yield;
		}
	}

	appctx->ctx.cli.p0 = NULL;
	free_trash_chunk(trash);
	return 1;
yield:

	free_trash_chunk(trash);
	appctx->ctx.cli.p0 = ckchs;
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




/* IO handler of the details "show ssl cert <filename>" */
static int cli_io_handler_show_cert_detail(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct ckch_store *ckchs = appctx->ctx.cli.p0;
	struct buffer *out = alloc_trash_chunk();
	struct buffer *tmp = alloc_trash_chunk();
	X509_NAME *name = NULL;
	STACK_OF(X509) *chain;
	unsigned int len = 0;
	int write = -1;
	BIO *bio = NULL;
	int i;

	if (!tmp || !out)
		goto end_no_putchk;

	chunk_appendf(out, "Filename: ");
	if (ckchs == ckchs_transaction.new_ckchs)
		chunk_appendf(out, "*");
	chunk_appendf(out, "%s\n", ckchs->path);

	chunk_appendf(out, "Status: ");
	if (ckchs->ckch->cert == NULL)
		chunk_appendf(out, "Empty\n");
	else if (LIST_ISEMPTY(&ckchs->ckch_inst))
		chunk_appendf(out, "Unused\n");
	else
		chunk_appendf(out, "Used\n");

	if (ckchs->ckch->cert == NULL)
		goto end;

	chain = ckchs->ckch->chain;
	if (chain == NULL) {
		struct issuer_chain *issuer;
		issuer = ssl_get0_issuer_chain(ckchs->ckch->cert);
		if (issuer) {
			chain = issuer->chain;
			chunk_appendf(out, "Chain Filename: ");
			chunk_appendf(out, "%s\n", issuer->path);
		}
	}
	chunk_appendf(out, "Serial: ");
	if (ssl_sock_get_serial(ckchs->ckch->cert, tmp) == -1)
		goto end;
	dump_binary(out, tmp->area, tmp->data);
	chunk_appendf(out, "\n");

	chunk_appendf(out, "notBefore: ");
	chunk_reset(tmp);
	if ((bio = BIO_new(BIO_s_mem())) ==  NULL)
		goto end;
	if (ASN1_TIME_print(bio, X509_getm_notBefore(ckchs->ckch->cert)) == 0)
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
	if (ASN1_TIME_print(bio, X509_getm_notAfter(ckchs->ckch->cert)) == 0)
		goto end;
	if ((write = BIO_read(bio, tmp->area, tmp->size-1)) <= 0)
		goto end;
	tmp->area[write] = '\0';
	BIO_free(bio);
	bio = NULL;
	chunk_appendf(out, "%s\n", tmp->area);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	chunk_appendf(out, "Subject Alternative Name: ");
	if (ssl_sock_get_san_oneline(ckchs->ckch->cert, out) == -1)
		goto end;
	*(out->area + out->data) = '\0';
	chunk_appendf(out, "\n");
#endif
	chunk_reset(tmp);
	chunk_appendf(out, "Algorithm: ");
	if (cert_get_pkey_algo(ckchs->ckch->cert, tmp) == 0)
		goto end;
	chunk_appendf(out, "%s\n", tmp->area);

	chunk_reset(tmp);
	chunk_appendf(out, "SHA1 FingerPrint: ");
	if (X509_digest(ckchs->ckch->cert, EVP_sha1(), (unsigned char *) tmp->area, &len) == 0)
		goto end;
	tmp->data = len;
	dump_binary(out, tmp->area, tmp->data);
	chunk_appendf(out, "\n");

	chunk_appendf(out, "Subject: ");
	if ((name = X509_get_subject_name(ckchs->ckch->cert)) == NULL)
		goto end;
	if ((ssl_sock_get_dn_oneline(name, tmp)) == -1)
		goto end;
	*(tmp->area + tmp->data) = '\0';
	chunk_appendf(out, "%s\n", tmp->area);

	chunk_appendf(out, "Issuer: ");
	if ((name = X509_get_issuer_name(ckchs->ckch->cert)) == NULL)
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
	if (ci_putchk(si_ic(si), out) == -1) {
		si_rx_room_blk(si);
		goto yield;
	}

end_no_putchk:
	if (bio)
		BIO_free(bio);
	free_trash_chunk(tmp);
	free_trash_chunk(out);
	return 1;
yield:
	free_trash_chunk(tmp);
	free_trash_chunk(out);
	return 0; /* should come back */
}

/* parsing function for 'show ssl cert [certfile]' */
static int cli_parse_show_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct ckch_store *ckchs;

	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
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

		appctx->ctx.cli.p0 = ckchs;
		/* use the IO handler that shows details */
		appctx->io_handler = cli_io_handler_show_cert_detail;
	}

	return 0;

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	return cli_err(appctx, "Can't display the certificate: Not found or the certificate is a bundle!\n");
}

/* release function of the  `set ssl cert' command, free things and unlock the spinlock */
static void cli_release_commit_cert(struct appctx *appctx)
{
	struct ckch_store *new_ckchs;

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	if (appctx->st2 != SETCERT_ST_FIN) {
		/* free every new sni_ctx and the new store, which are not in the trees so no spinlock there */
		new_ckchs = appctx->ctx.ssl.new_ckchs;

		/* if the allocation failed, we need to free everything from the temporary list */
		ckch_store_free(new_ckchs);
	}
}

/*
 * This function tries to create the new ckch_inst and their SNIs
 */
static int cli_io_handler_commit_cert(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	int y = 0;
	char *err = NULL;
	int errcode = 0;
	struct ckch_store *old_ckchs, *new_ckchs = NULL;
	struct ckch_inst *ckchi, *ckchis;
	struct buffer *trash = alloc_trash_chunk();
	struct sni_ctx *sc0, *sc0s;
	struct crtlist_entry *entry;

	if (trash == NULL)
		goto error;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		goto error;

	while (1) {
		switch (appctx->st2) {
			case SETCERT_ST_INIT:
				/* This state just print the update message */
				chunk_printf(trash, "Committing %s", ckchs_transaction.path);
				if (ci_putchk(si_ic(si), trash) == -1) {
					si_rx_room_blk(si);
					goto yield;
				}
				appctx->st2 = SETCERT_ST_GEN;
				/* fallthrough */
			case SETCERT_ST_GEN:
				/*
				 * This state generates the ckch instances with their
				 * sni_ctxs and SSL_CTX.
				 *
				 * Since the SSL_CTX generation can be CPU consumer, we
				 * yield every 10 instances.
				 */

				old_ckchs = appctx->ctx.ssl.old_ckchs;
				new_ckchs = appctx->ctx.ssl.new_ckchs;

				if (!new_ckchs)
					continue;

				/* get the next ckchi to regenerate */
				ckchi = appctx->ctx.ssl.next_ckchi;
				/* we didn't start yet, set it to the first elem */
				if (ckchi == NULL)
					ckchi = LIST_ELEM(old_ckchs->ckch_inst.n, typeof(ckchi), by_ckchs);

				/* walk through the old ckch_inst and creates new ckch_inst using the updated ckchs */
				list_for_each_entry_from(ckchi, &old_ckchs->ckch_inst, by_ckchs) {
					struct ckch_inst *new_inst;
					char **sni_filter = NULL;
					int fcount = 0;

					/* it takes a lot of CPU to creates SSL_CTXs, so we yield every 10 CKCH instances */
					if (y >= 10) {
						/* save the next ckchi to compute */
						appctx->ctx.ssl.next_ckchi = ckchi;
						goto yield;
					}

					if (ckchi->crtlist_entry) {
						sni_filter = ckchi->crtlist_entry->filters;
						fcount = ckchi->crtlist_entry->fcount;
					}

					errcode |= ckch_inst_new_load_store(new_ckchs->path, new_ckchs, ckchi->bind_conf, ckchi->ssl_conf, sni_filter, fcount, &new_inst, &err);

					if (errcode & ERR_CODE)
						goto error;

					/* if the previous ckchi was used as the default */
					if (ckchi->is_default)
						new_inst->is_default = 1;

					/* create the link to the crtlist_entry */
					new_inst->crtlist_entry = ckchi->crtlist_entry;

					/* we need to initialize the SSL_CTX generated */
					/* this iterate on the newly generated SNIs in the new instance to prepare their SSL_CTX */
					list_for_each_entry_safe(sc0, sc0s, &new_inst->sni_ctx, by_ckch_inst) {
						if (!sc0->order) { /* we initialized only the first SSL_CTX because it's the same in the other sni_ctx's */
							errcode |= ssl_sock_prepare_ctx(ckchi->bind_conf, ckchi->ssl_conf, sc0->ctx, &err);
							if (errcode & ERR_CODE)
								goto error;
						}
					}


					/* display one dot per new instance */
					chunk_appendf(trash, ".");
					/* link the new ckch_inst to the duplicate */
					LIST_ADDQ(&new_ckchs->ckch_inst, &new_inst->by_ckchs);
					y++;
				}
				appctx->st2 = SETCERT_ST_INSERT;
				/* fallthrough */
			case SETCERT_ST_INSERT:
				/* The generation is finished, we can insert everything */

				old_ckchs = appctx->ctx.ssl.old_ckchs;
				new_ckchs = appctx->ctx.ssl.new_ckchs;

				if (!new_ckchs)
					continue;

				/* get the list of crtlist_entry in the old store, and update the pointers to the store */
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
						LIST_ADD(&ckchi->crtlist_entry->ckch_inst, &ckchi->by_crtlist_entry);
				}

				/* First, we insert every new SNIs in the trees, also replace the default_ctx */
				list_for_each_entry_safe(ckchi, ckchis, &new_ckchs->ckch_inst, by_ckchs) {
					HA_RWLOCK_WRLOCK(SNI_LOCK, &ckchi->bind_conf->sni_lock);
					ssl_sock_load_cert_sni(ckchi, ckchi->bind_conf);
					HA_RWLOCK_WRUNLOCK(SNI_LOCK, &ckchi->bind_conf->sni_lock);
				}

				/* delete the old sni_ctx, the old ckch_insts and the ckch_store */
				list_for_each_entry_safe(ckchi, ckchis, &old_ckchs->ckch_inst, by_ckchs) {
					struct bind_conf __maybe_unused *bind_conf = ckchi->bind_conf;

					HA_RWLOCK_WRLOCK(SNI_LOCK, &bind_conf->sni_lock);
					ckch_inst_free(ckchi);
					HA_RWLOCK_WRUNLOCK(SNI_LOCK, &bind_conf->sni_lock);
				}

				/* Replace the old ckchs by the new one */
				ckch_store_free(old_ckchs);
				ebst_insert(&ckchs_tree, &new_ckchs->node);
				appctx->st2 = SETCERT_ST_FIN;
				/* fallthrough */
			case SETCERT_ST_FIN:
				/* we achieved the transaction, we can set everything to NULL */
				free(ckchs_transaction.path);
				ckchs_transaction.path = NULL;
				ckchs_transaction.new_ckchs = NULL;
				ckchs_transaction.old_ckchs = NULL;
				goto end;
		}
	}
end:

	chunk_appendf(trash, "\n");
	if (errcode & ERR_WARN)
		chunk_appendf(trash, "%s", err);
	chunk_appendf(trash, "Success!\n");
	if (ci_putchk(si_ic(si), trash) == -1)
		si_rx_room_blk(si);
	free_trash_chunk(trash);
	/* success: call the release function and don't come back */
	return 1;
yield:
	/* store the state */
	if (ci_putchk(si_ic(si), trash) == -1)
		si_rx_room_blk(si);
	free_trash_chunk(trash);
	si_rx_endp_more(si); /* let's come back later */
	return 0; /* should come back */

error:
	/* spin unlock and free are done in the release  function */
	if (trash) {
		chunk_appendf(trash, "\n%sFailed!\n", err);
		if (ci_putchk(si_ic(si), trash) == -1)
			si_rx_room_blk(si);
		free_trash_chunk(trash);
	}
	/* error: call the release function and don't come back */
	return 1;
}

/*
 * Parsing function of 'commit ssl cert'
 */
static int cli_parse_commit_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'commit ssl cert expects a filename\n");

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
	if (ckchs_transaction.new_ckchs->ckch->cert && !ckchs_transaction.new_ckchs->ckch->key) {
		memprintf(&err, "The transaction must contain at least a certificate and a private key!\n");
		goto error;
	}

	if (!X509_check_private_key(ckchs_transaction.new_ckchs->ckch->cert, ckchs_transaction.new_ckchs->ckch->key)) {
		memprintf(&err, "inconsistencies between private key and certificate loaded '%s'.\n", ckchs_transaction.path);
		goto error;
	}

	/* init the appctx structure */
	appctx->st2 = SETCERT_ST_INIT;
	appctx->ctx.ssl.next_ckchi = NULL;
	appctx->ctx.ssl.new_ckchs = ckchs_transaction.new_ckchs;
	appctx->ctx.ssl.old_ckchs = ckchs_transaction.old_ckchs;

	/* we don't unlock there, it will be unlock after the IO handler, in the release handler */
	return 0;

error:

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	err = memprintf(&err, "%sCan't commit %s!\n", err ? err : "", args[3]);

	return cli_dynerr(appctx, err);
}




/*
 * Parsing function of `set ssl cert`, it updates or creates a temporary ckch.
 */
static int cli_parse_set_cert(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct ckch_store *new_ckchs = NULL;
	struct ckch_store *old_ckchs = NULL;
	char *err = NULL;
	int i;
	int errcode = 0;
	char *end;
	int type = CERT_TYPE_PEM;
	struct cert_key_and_chain *ckch;
	struct buffer *buf;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3] || !payload)
		return cli_err(appctx, "'set ssl cert expects a filename and a certificate as a payload\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't update the certificate!\nOperations on certificates are currently locked!\n");

	if ((buf = alloc_trash_chunk()) == NULL)
		return cli_err(appctx, "Can't allocate memory\n");

	if (!chunk_strcpy(buf, args[3])) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* check which type of file we want to update */
	for (i = 0; cert_exts[i].type < CERT_TYPE_MAX; i++) {
		end = strrchr(buf->area, '.');
		if (end && *cert_exts[i].ext && (strcmp(end + 1, cert_exts[i].ext) == 0)) {
			*end = '\0';
			buf->data = strlen(buf->area);
			type = cert_exts[i].type;
			break;
		}
	}

	appctx->ctx.ssl.old_ckchs = NULL;
	appctx->ctx.ssl.new_ckchs = NULL;

	/* if there is an ongoing transaction */
	if (ckchs_transaction.path) {
		/* if there is an ongoing transaction, check if this is the same file */
		if (strcmp(ckchs_transaction.path, buf->area) != 0) {
			/* we didn't find the transaction, must try more cases below */

			/* if the del-ext option is activated we should try to take a look at a ".crt" too. */
			if (type != CERT_TYPE_PEM && global_ssl.extra_files_noext) {
				if (!chunk_strcat(buf, ".crt")) {
					memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
					errcode |= ERR_ALERT | ERR_FATAL;
					goto end;
				}

				if (strcmp(ckchs_transaction.path, buf->area) != 0) {
					/* remove .crt of the error message */
					*(b_orig(buf) + b_data(buf) + strlen(".crt")) = '\0';
					b_sub(buf, strlen(".crt"));

					memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", ckchs_transaction.path, buf->area);
					errcode |= ERR_ALERT | ERR_FATAL;
					goto end;
				}
			}
		}

		appctx->ctx.ssl.old_ckchs = ckchs_transaction.new_ckchs;

	} else {

		/* lookup for the certificate in the tree */
		appctx->ctx.ssl.old_ckchs = ckchs_lookup(buf->area);

		if (!appctx->ctx.ssl.old_ckchs) {
			/* if the del-ext option is activated we should try to take a look at a ".crt" too. */
			if (type != CERT_TYPE_PEM && global_ssl.extra_files_noext) {
				if (!chunk_strcat(buf, ".crt")) {
					memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
					errcode |= ERR_ALERT | ERR_FATAL;
					goto end;
				}
				appctx->ctx.ssl.old_ckchs = ckchs_lookup(buf->area);
			}
		}
	}

	if (!appctx->ctx.ssl.old_ckchs) {
		memprintf(&err, "%sCan't replace a certificate which is not referenced by the configuration!\n",
		          err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	if (!appctx->ctx.ssl.path) {
	/* this is a new transaction, set the path of the transaction */
		appctx->ctx.ssl.path = strdup(appctx->ctx.ssl.old_ckchs->path);
		if (!appctx->ctx.ssl.path) {
			memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
	}

	old_ckchs = appctx->ctx.ssl.old_ckchs;

	/* duplicate the ckch store */
	new_ckchs = ckchs_dup(old_ckchs);
	if (!new_ckchs) {
		memprintf(&err, "%sCannot allocate memory!\n",
			  err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	ckch = new_ckchs->ckch;

	/* appply the change on the duplicate */
	if (cert_exts[type].load(buf->area, payload, ckch, &err) != 0) {
		memprintf(&err, "%sCan't load the payload\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	appctx->ctx.ssl.new_ckchs = new_ckchs;

	/* we succeed, we can save the ckchs in the transaction */

	/* if there wasn't a transaction, update the old ckchs */
	if (!ckchs_transaction.old_ckchs) {
		ckchs_transaction.old_ckchs = appctx->ctx.ssl.old_ckchs;
		ckchs_transaction.path = appctx->ctx.ssl.path;
		err = memprintf(&err, "Transaction created for certificate %s!\n", ckchs_transaction.path);
	} else {
		err = memprintf(&err, "Transaction updated for certificate %s!\n", ckchs_transaction.path);

	}

	/* free the previous ckchs if there was a transaction */
	ckch_store_free(ckchs_transaction.new_ckchs);

	ckchs_transaction.new_ckchs = appctx->ctx.ssl.new_ckchs;


	/* creates the SNI ctxs later in the IO handler */

end:
	free_trash_chunk(buf);

	if (errcode & ERR_CODE) {

		ckch_store_free(appctx->ctx.ssl.new_ckchs);
		appctx->ctx.ssl.new_ckchs = NULL;

		appctx->ctx.ssl.old_ckchs = NULL;

		free(appctx->ctx.ssl.path);
		appctx->ctx.ssl.path = NULL;

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
	ckch_store_free(ckchs_transaction.old_ckchs);
	ckchs_transaction.old_ckchs = NULL;
	free(ckchs_transaction.path);
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

void ckch_deinit()
{
	struct eb_node *node, *next;
	struct ckch_store *store;

	node = eb_first(&ckchs_tree);
	while (node) {
		next = eb_next(node);
		store = ebmb_entry(node, struct ckch_store, node);
		ckch_store_free(store);
		node = next;
	}
}

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "new", "ssl", "cert", NULL }, "new ssl cert <certfile> : create a new certificate file to be used in a crt-list or a directory", cli_parse_new_cert, NULL, NULL },
	{ { "set", "ssl", "cert", NULL }, "set ssl cert <certfile> <payload> : replace a certificate file", cli_parse_set_cert, NULL, NULL },
	{ { "commit", "ssl", "cert", NULL }, "commit ssl cert <certfile> : commit a certificate file", cli_parse_commit_cert, cli_io_handler_commit_cert, cli_release_commit_cert },
	{ { "abort", "ssl", "cert", NULL }, "abort ssl cert <certfile> : abort a transaction for a certificate file", cli_parse_abort_cert, NULL, NULL },
	{ { "del", "ssl", "cert", NULL }, "del ssl cert <certfile> : delete an unused certificate file", cli_parse_del_cert, NULL, NULL },
	{ { "show", "ssl", "cert", NULL }, "show ssl cert [<certfile>] : display the SSL certificates used in memory, or the details of a <certfile>", cli_parse_show_cert, cli_io_handler_show_cert, cli_release_show_cert },
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

