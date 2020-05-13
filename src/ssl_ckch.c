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
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <common/base64.h>
#include <common/errors.h>
#include <common/standard.h>

#include <ebsttree.h>

#include <types/ssl_ckch.h>
#include <types/ssl_sock.h>

#include <proto/ssl_ckch.h>
#include <proto/ssl_sock.h>

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
 * This function load the OCSP Resonse in DER format contained in file at
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
	int ret = 1;

	/* try to load the PEM */
	if (ssl_sock_load_pem_into_ckch(path, NULL, ckch , err) != 0) {
		goto end;
	}

	/* try to load an external private key if it wasn't in the PEM */
	if ((ckch->key == NULL) && (global_ssl.extra_files & SSL_GF_KEY)) {
		char fp[MAXPATHLEN+1];
		struct stat st;

		snprintf(fp, MAXPATHLEN+1, "%s.key", path);
		if (stat(fp, &st) == 0) {
			if (ssl_sock_load_key_into_ckch(fp, NULL, ckch, err)) {
				memprintf(err, "%s '%s' is present but cannot be read or parsed'.\n",
					  err && *err ? *err : "", fp);
				goto end;
			}
		}
	}

	if (ckch->key == NULL) {
		memprintf(err, "%sNo Private Key found in '%s' or '%s.key'.\n", err && *err ? *err : "", path, path);
		goto end;
	}

	if (!X509_check_private_key(ckch->cert, ckch->key)) {
		memprintf(err, "%sinconsistencies between private key and certificate loaded '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
	/* try to load the sctl file */
	if (global_ssl.extra_files & SSL_GF_SCTL) {
		char fp[MAXPATHLEN+1];
		struct stat st;

		snprintf(fp, MAXPATHLEN+1, "%s.sctl", path);
		if (stat(fp, &st) == 0) {
			if (ssl_sock_load_sctl_from_file(fp, NULL, ckch, err)) {
				memprintf(err, "%s '%s.sctl' is present but cannot be read or parsed'.\n",
					  err && *err ? *err : "", fp);
				ret = 1;
				goto end;
			}
		}
	}
#endif

	/* try to load an ocsp response file */
	if (global_ssl.extra_files & SSL_GF_OCSP) {
		char fp[MAXPATHLEN+1];
		struct stat st;

		snprintf(fp, MAXPATHLEN+1, "%s.ocsp", path);
		if (stat(fp, &st) == 0) {
			if (ssl_sock_load_ocsp_response_from_file(fp, NULL, ckch, err)) {
				ret = 1;
				goto end;
			}
		}
	}

#ifndef OPENSSL_IS_BORINGSSL /* Useless for BoringSSL */
	if (ckch->ocsp_response && (global_ssl.extra_files & SSL_GF_OCSP_ISSUER)) {
		/* if no issuer was found, try to load an issuer from the .issuer */
		if (!ckch->ocsp_issuer) {
			struct stat st;
			char fp[MAXPATHLEN+1];

			snprintf(fp, MAXPATHLEN+1, "%s.issuer", path);
			if (stat(fp, &st) == 0) {
				if (ssl_sock_load_issuer_file_into_ckch(fp, NULL, ckch, err)) {
					ret = 1;
					goto end;
				}

				if (X509_check_issued(ckch->ocsp_issuer, ckch->cert) != X509_V_OK) {
					memprintf(err, "%s '%s' is not an issuer'.\n",
						  err && *err ? *err : "", fp);
					ret = 1;
					goto end;
				}
			}
		}
	}
#endif

	ret = 0;

end:

	ERR_clear_error();

	/* Something went wrong in one of the reads */
	if (ret != 0)
		ssl_sock_free_cert_key_and_chain_contents(ckch);

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

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200L
	if (store->multi) {
		int n;

		for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++)
			ssl_sock_free_cert_key_and_chain_contents(&store->ckch[n]);
	} else
#endif
	{
		ssl_sock_free_cert_key_and_chain_contents(store->ckch);
	}

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
struct ckch_store *ckch_store_new(const char *filename, int nmemb)
{
	struct ckch_store *store;
	int pathlen;

	pathlen = strlen(filename);
	store = calloc(1, sizeof(*store) + pathlen + 1);
	if (!store)
		return NULL;

	if (nmemb > 1)
		store->multi = 1;
	else
		store->multi = 0;

	memcpy(store->path, filename, pathlen + 1);

	LIST_INIT(&store->ckch_inst);
	LIST_INIT(&store->crtlist_entry);

	store->ckch = calloc(nmemb, sizeof(*store->ckch));
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

	dst = ckch_store_new(src->path, src->multi ? SSL_SOCK_NUM_KEYTYPES : 1);

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
	if (src->multi) {
		int n;

		for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++) {
			if (&src->ckch[n]) {
				if (!ssl_sock_copy_cert_key_and_chain(&src->ckch[n], &dst->ckch[n]))
					goto error;
			}
		}
	} else
#endif
	{
		if (!ssl_sock_copy_cert_key_and_chain(src->ckch, dst->ckch))
			goto error;
	}

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
struct ckch_store *ckchs_load_cert_file(char *path, int multi, char **err)
{
	struct ckch_store *ckchs;

	ckchs = ckch_store_new(path, multi ? SSL_SOCK_NUM_KEYTYPES : 1);
	if (!ckchs) {
		memprintf(err, "%sunable to allocate memory.\n", err && *err ? *err : "");
		goto end;
	}
	if (!multi) {

		if (ssl_sock_load_files_into_ckch(path, ckchs->ckch, err) == 1)
			goto end;

		/* insert into the ckchs tree */
		memcpy(ckchs->path, path, strlen(path) + 1);
		ebst_insert(&ckchs_tree, &ckchs->node);
	} else {
		int found = 0;
#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
		char fp[MAXPATHLEN+1] = {0};
		int n = 0;

		/* Load all possible certs and keys */
		for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++) {
			struct stat buf;
			snprintf(fp, sizeof(fp), "%s.%s", path, SSL_SOCK_KEYTYPE_NAMES[n]);
			if (stat(fp, &buf) == 0) {
				if (ssl_sock_load_files_into_ckch(fp, &ckchs->ckch[n], err) == 1)
					goto end;
				found = 1;
				ckchs->multi = 1;
			}
		}
#endif

		if (!found) {
			memprintf(err, "%sDidn't find any certificate for bundle '%s'.\n", err && *err ? *err : "", path);
			goto end;
		}
		/* insert into the ckchs tree */
		memcpy(ckchs->path, path, strlen(path) + 1);
		ebst_insert(&ckchs_tree, &ckchs->node);
	}
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

