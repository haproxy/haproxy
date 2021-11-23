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

#include <import/ebpttree.h>
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
	if (ckch->sctl) {
		ha_free(&ckch->sctl->area);
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
		ha_free(&ocsp_response);
		goto end;
	}
	/* no error, fill ckch with new context, old context must be free */
	if (ckch->ocsp_response) {
		ha_free(&ckch->ocsp_response->area);
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
		ha_free(&ckch->ocsp_response->area);
		ha_free(&ckch->ocsp_response);
	}

	if (ckch->sctl) {
		ha_free(&ckch->sctl->area);
		ha_free(&ckch->sctl);
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
		ha_free(&ckch->sctl->area);
		ha_free(&ckch->sctl);
	}

	if (ckch->ocsp_response) {
		ha_free(&ckch->ocsp_response->area);
		ha_free(&ckch->ocsp_response);
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
		DH_up_ref(src->dh);
		dst->dh = src->dh;
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

	ha_free(&store->ckch);

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

	if (!src)
		return NULL;

	dst = ckch_store_new(src->path);
	if (!dst)
		return NULL;

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

	list_for_each_entry_safe(link_ref, link_ref_s, &inst->cafile_link_refs, list) {
		LIST_DELETE(&link_ref->link->list);
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
 * Build a cafile_entry out of a buffer instead of out of a file.
 * This function is used when the "commit ssl ca-file" cli command is used.
 * It can parse CERTIFICATE sections as well as CRL ones.
 * Returns 0 in case of success, 1 otherwise.
 */
int ssl_store_load_ca_from_buf(struct cafile_entry *ca_e, char *cert_buf)
{
	int retval = 0;

	if (!ca_e)
		return 1;

	if (!ca_e->ca_store) {
		ca_e->ca_store = X509_STORE_new();
		if (ca_e->ca_store) {
			BIO *bio = BIO_new_mem_buf(cert_buf, strlen(cert_buf));
			if (bio) {
				X509_INFO *info;
				int i;
				STACK_OF(X509_INFO) *infos = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
				if (!infos)
				{
					BIO_free(bio);
					return 1;
				}

				for (i = 0; i < sk_X509_INFO_num(infos) && !retval; i++) {
					info = sk_X509_INFO_value(infos, i);
					/* X509_STORE_add_cert and X509_STORE_add_crl return 1 on success */
					if (info->x509) {
						retval = !X509_STORE_add_cert(ca_e->ca_store, info->x509);
					}
					if (!retval && info->crl) {
						retval = !X509_STORE_add_crl(ca_e->ca_store, info->crl);
					}
				}
				retval = retval || (i != sk_X509_INFO_num(infos));

				/* Cleanup */
				sk_X509_INFO_pop_free(infos, X509_INFO_free);
				BIO_free(bio);
			}
		}
	}

	return retval;
}

int ssl_store_load_locations_file(char *path, int create_if_none, enum cafile_type type)
{
	X509_STORE *store = ssl_store_get0_locations_file(path);

	/* If this function is called by the CLI, we should not call the
	 * X509_STORE_load_locations function because it performs forbidden disk
	 * accesses. */
	if (!store && create_if_none) {
		struct cafile_entry *ca_e;
		store = X509_STORE_new();
		if (X509_STORE_load_locations(store, path, NULL)) {
			ca_e = ssl_store_create_cafile_entry(path, store, type);
			if (ca_e) {
				ebst_insert(&cafile_tree, &ca_e->node);
			}
		} else {
			X509_STORE_free(store);
			store = NULL;
		}
	}
	return (store != NULL);
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
#ifdef HAVE_SSL_SCTL
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
#ifdef HAVE_SSL_SCTL
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



static int show_cert_detail(X509 *cert, STACK_OF(X509) *chain, struct buffer *out)
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

	if (chain == NULL) {
		struct issuer_chain *issuer;
		issuer = ssl_get0_issuer_chain(cert);
		if (issuer) {
			chain = issuer->chain;
			chunk_appendf(out, "Chain Filename: ");
			chunk_appendf(out, "%s\n", issuer->path);
		}
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

#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) && !defined OPENSSL_IS_BORINGSSL)
/*
 * Build the OCSP tree entry's key for a given ckch_store.
 * Returns a negative value in case of error.
 */
static int ckch_store_build_certid(struct ckch_store *ckch_store, unsigned char certid[128], unsigned int *key_length)
{
	OCSP_RESPONSE *resp;
	OCSP_BASICRESP *bs = NULL;
	OCSP_SINGLERESP *sr;
	OCSP_CERTID *id;
	unsigned char *p = NULL;

	if (!key_length)
		return -1;

	*key_length = 0;

	if (!ckch_store->ckch->ocsp_response)
		return 0;

	p = (unsigned char *) ckch_store->ckch->ocsp_response->area;

	resp = d2i_OCSP_RESPONSE(NULL, (const unsigned char **)&p,
				 ckch_store->ckch->ocsp_response->data);
	if (!resp) {
		goto end;
	}

	bs = OCSP_response_get1_basic(resp);
	if (!bs) {
		goto end;
	}

	sr = OCSP_resp_get0(bs, 0);
	if (!sr) {
		goto end;
	}

	id = (OCSP_CERTID*)OCSP_SINGLERESP_get0_id(sr);

	p = certid;
	*key_length = i2d_OCSP_CERTID(id, &p);

end:
	return *key_length > 0;
}
#endif

/*
 * Dump the OCSP certificate key (if it exists) of certificate <ckch> into
 * buffer <out>.
 * Returns 0 in case of success.
 */
static int ckch_store_show_ocsp_certid(struct ckch_store *ckch_store, struct buffer *out)
{
#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) && !defined OPENSSL_IS_BORINGSSL)
	unsigned char key[OCSP_MAX_CERTID_ASN1_LENGTH] = {};
	unsigned int key_length = 0;
	int i;

	if (ckch_store_build_certid(ckch_store, (unsigned char*)key, &key_length) >= 0) {
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


/* IO handler of the details "show ssl cert <filename>" */
static int cli_io_handler_show_cert_detail(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct ckch_store *ckchs = appctx->ctx.cli.p0;
	struct buffer *out = alloc_trash_chunk();
	int retval = 0;

	if (!out)
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

	retval = show_cert_detail(ckchs->ckch->cert, ckchs->ckch->chain, out);
	if (retval < 0)
		goto end_no_putchk;
	else if (retval)
		goto end;

	ckch_store_show_ocsp_certid(ckchs, out);

end:
	if (ci_putchk(si_ic(si), out) == -1) {
		si_rx_room_blk(si);
		goto yield;
	}

end_no_putchk:
	free_trash_chunk(out);
	return 1;
yield:
	free_trash_chunk(out);
	return 0; /* should come back */
}


/* IO handler of the details "show ssl cert <filename.ocsp>" */
static int cli_io_handler_show_cert_ocsp_detail(struct appctx *appctx)
{
#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) && !defined OPENSSL_IS_BORINGSSL)
	struct stream_interface *si = appctx->owner;
	struct ckch_store *ckchs = appctx->ctx.cli.p0;
	struct buffer *out = alloc_trash_chunk();
	int from_transaction = appctx->ctx.cli.i0;

	if (!out)
		goto end_no_putchk;

	/* If we try to display an ongoing transaction's OCSP response, we
	 * need to dump the ckch's ocsp_response buffer directly.
	 * Otherwise, we must rebuild the certificate's certid in order to
	 * look for the current OCSP response in the tree. */
	if (from_transaction && ckchs->ckch->ocsp_response) {
		ssl_ocsp_response_print(ckchs->ckch->ocsp_response, out);
	}
	else {
		unsigned char key[OCSP_MAX_CERTID_ASN1_LENGTH] = {};
		unsigned int key_length = 0;

		if (ckch_store_build_certid(ckchs, (unsigned char*)key, &key_length) < 0)
			goto end_no_putchk;

		ssl_get_ocspresponse_detail(key, out);
	}

	if (ci_putchk(si_ic(si), out) == -1) {
		si_rx_room_blk(si);
		goto yield;
	}

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
			from_transaction = 1;
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
		if (show_ocsp_detail) {
			appctx->ctx.cli.i0 = from_transaction;
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
 * Rebuild a new instance 'new_inst' based on an old instance 'ckchi' and a
 * specific ckch_store.
 * Returns 0 in case of success, 1 otherwise.
 */
static int ckch_inst_rebuild(struct ckch_store *ckch_store, struct ckch_inst *ckchi,
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
		errcode |= ckch_inst_new_load_store(ckch_store->path, ckch_store, ckchi->bind_conf, ckchi->ssl_conf, sni_filter, fcount, new_inst, err);

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


/*
 * This function tries to create the new ckch_inst and their SNIs
 */
static int cli_io_handler_commit_cert(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	int y = 0;
	char *err = NULL;
	struct ckch_store *old_ckchs, *new_ckchs = NULL;
	struct ckch_inst *ckchi, *ckchis;
	struct buffer *trash = alloc_trash_chunk();
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

					/* it takes a lot of CPU to creates SSL_CTXs, so we yield every 10 CKCH instances */
					if (y >= 10) {
						/* save the next ckchi to compute */
						appctx->ctx.ssl.next_ckchi = ckchi;
						goto yield;
					}

					if (ckch_inst_rebuild(new_ckchs, ckchi, &new_inst, &err))
						goto error;

					/* display one dot per new instance */
					chunk_appendf(trash, ".");
					/* link the new ckch_inst to the duplicate */
					LIST_APPEND(&new_ckchs->ckch_inst, &new_inst->by_ckchs);
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

				/* Replace the old ckchs by the new one */
				ckch_store_free(old_ckchs);
				ebst_insert(&ckchs_tree, &new_ckchs->node);
				appctx->st2 = SETCERT_ST_FIN;
				/* fallthrough */
			case SETCERT_ST_FIN:
				/* we achieved the transaction, we can set everything to NULL */
				ha_free(&ckchs_transaction.path);
				ckchs_transaction.new_ckchs = NULL;
				ckchs_transaction.old_ckchs = NULL;
				goto end;
		}
	}
end:

	chunk_appendf(trash, "\n");
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

		ha_free(&appctx->ctx.ssl.path);

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
	ha_free(&ckchs_transaction.path);

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
	char *err = NULL;
	int errcode = 0;
	struct buffer *buf;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3] || !payload)
		return cli_err(appctx, "'set ssl ca-file expects a filename and CAs as a payload\n");

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

	appctx->ctx.ssl.old_cafile_entry = NULL;
	appctx->ctx.ssl.new_cafile_entry = NULL;

	/* if there is an ongoing transaction */
	if (cafile_transaction.path) {
		/* if there is an ongoing transaction, check if this is the same file */
		if (strcmp(cafile_transaction.path, buf->area) != 0) {
			memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", cafile_transaction.path, buf->area);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		appctx->ctx.ssl.old_cafile_entry = cafile_transaction.old_cafile_entry;
	}
	else {
		/* lookup for the certificate in the tree */
		appctx->ctx.ssl.old_cafile_entry = ssl_store_get_cafile_entry(buf->area, 0);
	}

	if (!appctx->ctx.ssl.old_cafile_entry) {
		memprintf(&err, "%sCan't replace a CA file which is not referenced by the configuration!\n",
		          err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	if (!appctx->ctx.ssl.path) {
		/* this is a new transaction, set the path of the transaction */
		appctx->ctx.ssl.path = strdup(appctx->ctx.ssl.old_cafile_entry->path);
		if (!appctx->ctx.ssl.path) {
			memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
	}

	if (appctx->ctx.ssl.new_cafile_entry)
		ssl_store_delete_cafile_entry(appctx->ctx.ssl.new_cafile_entry);

	/* Create a new cafile_entry without adding it to the cafile tree. */
	appctx->ctx.ssl.new_cafile_entry = ssl_store_create_cafile_entry(appctx->ctx.ssl.path, NULL, CAFILE_CERT);
	if (!appctx->ctx.ssl.new_cafile_entry) {
		memprintf(&err, "%sCannot allocate memory!\n",
			  err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* Fill the new entry with the new CAs. */
	if (ssl_store_load_ca_from_buf(appctx->ctx.ssl.new_cafile_entry, payload)) {
		memprintf(&err, "%sInvalid payload\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* we succeed, we can save the ca in the transaction */

	/* if there wasn't a transaction, update the old CA */
	if (!cafile_transaction.old_cafile_entry) {
		cafile_transaction.old_cafile_entry = appctx->ctx.ssl.old_cafile_entry;
		cafile_transaction.path = appctx->ctx.ssl.path;
		err = memprintf(&err, "transaction created for CA %s!\n", cafile_transaction.path);
	} else {
		err = memprintf(&err, "transaction updated for CA %s!\n", cafile_transaction.path);
	}

	/* free the previous CA if there was a transaction */
	ssl_store_delete_cafile_entry(cafile_transaction.new_cafile_entry);

	cafile_transaction.new_cafile_entry = appctx->ctx.ssl.new_cafile_entry;

	/* creates the SNI ctxs later in the IO handler */

end:
	free_trash_chunk(buf);

	if (errcode & ERR_CODE) {
		ssl_store_delete_cafile_entry(appctx->ctx.ssl.new_cafile_entry);
		appctx->ctx.ssl.new_cafile_entry = NULL;
		appctx->ctx.ssl.old_cafile_entry = NULL;

		ha_free(&appctx->ctx.ssl.path);

		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynerr(appctx, memprintf(&err, "%sCan't update %s!\n", err ? err : "", args[3]));
	} else {

		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynmsg(appctx, LOG_NOTICE, err);
	}
}


/*
 * Parsing function of 'commit ssl ca-file'
 */
static int cli_parse_commit_cafile(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'commit ssl ca-file expects a filename\n");

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
	appctx->st2 = SETCERT_ST_INIT;
	appctx->ctx.ssl.next_ckchi_link = NULL;
	appctx->ctx.ssl.old_cafile_entry = cafile_transaction.old_cafile_entry;
	appctx->ctx.ssl.new_cafile_entry = cafile_transaction.new_cafile_entry;
	appctx->ctx.ssl.cafile_type = CAFILE_CERT;

	return 0;

error:

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	err = memprintf(&err, "%sCan't commit %s!\n", err ? err : "", args[3]);

	return cli_dynerr(appctx, err);
}

enum {
	CREATE_NEW_INST_OK = 0,
	CREATE_NEW_INST_YIELD = -1,
	CREATE_NEW_INST_ERR = -2
};

static inline int __create_new_instance(struct appctx *appctx, struct ckch_inst *ckchi, int *count,
					struct buffer *trash, char **err)
{
	struct ckch_inst *new_inst;

	/* it takes a lot of CPU to creates SSL_CTXs, so we yield every 10 CKCH instances */
	if (*count >= 10) {
		/* save the next ckchi to compute */
		appctx->ctx.ssl.next_ckchi = ckchi;
		return CREATE_NEW_INST_YIELD;
	}

	/* Rebuild a new ckch instance that uses the same ckch_store
	 * than a reference ckchi instance but will use a new CA file. */
	if (ckch_inst_rebuild(ckchi->ckch_store, ckchi, &new_inst, err))
		return CREATE_NEW_INST_ERR;

	/* display one dot per new instance */
	chunk_appendf(trash, ".");
	++(*count);

	return CREATE_NEW_INST_OK;
}

/*
 * This function tries to create new ckch instances and their SNIs using a newly
 * set certificate authority (CA file) or a newly set Certificate Revocation
 * List (CRL), depending on the command being called.
 */
static int cli_io_handler_commit_cafile_crlfile(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	int y = 0;
	char *err = NULL;
	struct cafile_entry *old_cafile_entry = NULL, *new_cafile_entry = NULL;
	struct ckch_inst_link *ckchi_link;
	struct buffer *trash = alloc_trash_chunk();

	if (trash == NULL)
		goto error;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		goto error;

	while (1) {
		switch (appctx->st2) {
			case SETCERT_ST_INIT:
				/* This state just print the update message */
				switch (appctx->ctx.ssl.cafile_type) {
				case CAFILE_CERT:
					chunk_printf(trash, "Committing %s", cafile_transaction.path);
					break;
				case CAFILE_CRL:
					chunk_printf(trash, "Committing %s", crlfile_transaction.path);
					break;
				default:
					goto error;
				}
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
				switch (appctx->ctx.ssl.cafile_type) {
				case CAFILE_CERT:
					old_cafile_entry = appctx->ctx.ssl.old_cafile_entry;
					new_cafile_entry = appctx->ctx.ssl.new_cafile_entry;
					break;
				case CAFILE_CRL:
					old_cafile_entry = appctx->ctx.ssl.old_crlfile_entry;
					new_cafile_entry = appctx->ctx.ssl.new_crlfile_entry;
					break;
				}
				if (!new_cafile_entry)
					continue;

				/* get the next ckchi to regenerate */
				ckchi_link = appctx->ctx.ssl.next_ckchi_link;
				/* we didn't start yet, set it to the first elem */
				if (ckchi_link == NULL) {
					ckchi_link = LIST_ELEM(old_cafile_entry->ckch_inst_link.n, typeof(ckchi_link), list);
					/* Add the newly created cafile_entry to the tree so that
					 * any new ckch instance created from now can use it. */
					if (ssl_store_add_uncommitted_cafile_entry(new_cafile_entry))
						goto error;
				}

				list_for_each_entry_from(ckchi_link, &old_cafile_entry->ckch_inst_link, list) {
					switch (__create_new_instance(appctx, ckchi_link->ckch_inst, &y, trash, &err)) {
					case CREATE_NEW_INST_YIELD:
						appctx->ctx.ssl.next_ckchi_link = ckchi_link;
						goto yield;
					case CREATE_NEW_INST_ERR:
						goto error;
					default: break;
					}
				}

				appctx->st2 = SETCERT_ST_INSERT;
				/* fallthrough */
			case SETCERT_ST_INSERT:
				/* The generation is finished, we can insert everything */
				switch (appctx->ctx.ssl.cafile_type) {
				case CAFILE_CERT:
					old_cafile_entry = appctx->ctx.ssl.old_cafile_entry;
					new_cafile_entry = appctx->ctx.ssl.new_cafile_entry;
					break;
				case CAFILE_CRL:
					old_cafile_entry = appctx->ctx.ssl.old_crlfile_entry;
					new_cafile_entry = appctx->ctx.ssl.new_crlfile_entry;
					break;
				}
				if (!new_cafile_entry)
					continue;

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

				/* delete the old sni_ctx, the old ckch_insts and the ckch_store */
				list_for_each_entry(ckchi_link, &old_cafile_entry->ckch_inst_link, list) {
					__ckch_inst_free_locked(ckchi_link->ckch_inst);
				}


				/* Remove the old cafile entry from the tree */
				ebmb_delete(&old_cafile_entry->node);
				ssl_store_delete_cafile_entry(old_cafile_entry);

				appctx->st2 = SETCERT_ST_FIN;
				/* fallthrough */
			case SETCERT_ST_FIN:
				/* we achieved the transaction, we can set everything to NULL */
				switch (appctx->ctx.ssl.cafile_type) {
				case CAFILE_CERT:
					ha_free(&cafile_transaction.path);
					cafile_transaction.old_cafile_entry = NULL;
					cafile_transaction.new_cafile_entry = NULL;
					break;
				case CAFILE_CRL:
					ha_free(&crlfile_transaction.path);
					crlfile_transaction.old_crlfile_entry = NULL;
					crlfile_transaction.new_crlfile_entry = NULL;
					break;
				}
				goto end;
		}
	}
end:

	chunk_appendf(trash, "\n");
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
	/* spin unlock and free are done in the release function */
	if (trash) {
		chunk_appendf(trash, "\n%sFailed!\n", err);
		if (ci_putchk(si_ic(si), trash) == -1)
			si_rx_room_blk(si);
		free_trash_chunk(trash);
	}
	/* error: call the release function and don't come back */
	return 1;
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
	ha_free(&cafile_transaction.path);

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	err = memprintf(&err, "Transaction aborted for certificate '%s'!\n", args[3]);
	return cli_dynmsg(appctx, LOG_NOTICE, err);

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	return cli_dynerr(appctx, err);
}

/* release function of the `commit ssl ca-file' command, free things and unlock the spinlock */
static void cli_release_commit_cafile(struct appctx *appctx)
{
	if (appctx->st2 != SETCERT_ST_FIN) {
		struct cafile_entry *new_cafile_entry = appctx->ctx.ssl.new_cafile_entry;

		/* Remove the uncommitted cafile_entry from the tree. */
		ebmb_delete(&new_cafile_entry->node);
		ssl_store_delete_cafile_entry(new_cafile_entry);
	}
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
}


/* IO handler of details "show ssl ca-file <filename[:index]>" */
static int cli_io_handler_show_cafile_detail(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct cafile_entry *cafile_entry = appctx->ctx.cli.p0;
	struct buffer *out = alloc_trash_chunk();
	int i;
	X509 *cert;
	STACK_OF(X509_OBJECT) *objs;
	int retval = 0;
	long ca_index = (long)appctx->ctx.cli.p1;

	if (!out)
		goto end_no_putchk;

	chunk_appendf(out, "Filename: ");
	if (cafile_entry == cafile_transaction.new_cafile_entry)
		chunk_appendf(out, "*");
	chunk_appendf(out, "%s\n", cafile_entry->path);

	chunk_appendf(out, "Status: ");
	if (!cafile_entry->ca_store)
		chunk_appendf(out, "Empty\n");
	else if (LIST_ISEMPTY(&cafile_entry->ckch_inst_link))
		chunk_appendf(out, "Unused\n");
	else
		chunk_appendf(out, "Used\n");

	if (!cafile_entry->ca_store)
		goto end;

	objs = X509_STORE_get0_objects(cafile_entry->ca_store);
	for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
		cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
		if (!cert)
			continue;

		/* Certificate indexes start at 1 on the CLI output. */
		if (ca_index && ca_index-1 != i)
			continue;

		chunk_appendf(out, "\nCertificate #%d:\n", i+1);
		retval = show_cert_detail(cert, NULL, out);
		if (retval < 0)
			goto end_no_putchk;
		else if (retval || ca_index)
			goto end;
	}

end:
	if (ci_putchk(si_ic(si), out) == -1) {
		si_rx_room_blk(si);
		goto yield;
	}

end_no_putchk:
	free_trash_chunk(out);
	return 1;
yield:
	free_trash_chunk(out);
	return 0; /* should come back */
}


/* parsing function for 'show ssl ca-file [cafile[:index]]' */
static int cli_parse_show_cafile(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct cafile_entry *cafile_entry;
	long ca_index = 0;
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
		}

		if (*args[3] == '*') {
			if (!cafile_transaction.new_cafile_entry)
				goto error;

			cafile_entry = cafile_transaction.new_cafile_entry;

			if (strcmp(args[3] + 1, cafile_entry->path) != 0)
				goto error;

		} else {
			/* Get the "original" cafile_entry and not the
			 * uncommitted one if it exists. */
			if ((cafile_entry = ssl_store_get_cafile_entry(args[3], 1)) == NULL || cafile_entry->type != CAFILE_CERT)
				goto error;
		}

		appctx->ctx.cli.p0 = cafile_entry;
		appctx->ctx.cli.p1 = (void*)ca_index;
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
 * is managed in cli_io_handler_show_cafile_detail. */
static int cli_io_handler_show_cafile(struct appctx *appctx)
{
	struct buffer *trash = alloc_trash_chunk();
	struct ebmb_node *node;
	struct stream_interface *si = appctx->owner;
	struct cafile_entry *cafile_entry;

	if (trash == NULL)
		return 1;

	if (!appctx->ctx.ssl.old_cafile_entry) {
		if (cafile_transaction.old_cafile_entry) {
			chunk_appendf(trash, "# transaction\n");
			chunk_appendf(trash, "*%s", cafile_transaction.old_cafile_entry->path);

			chunk_appendf(trash, " - %d certificate(s)\n", get_certificate_count(cafile_transaction.new_cafile_entry));
		}
	}

	/* First time in this io_handler. */
	if (!appctx->ctx.cli.p0) {
		chunk_appendf(trash, "# filename\n");
		node = ebmb_first(&cafile_tree);
	} else {
		/* We yielded during a previous call. */
		node = &((struct cafile_entry*)appctx->ctx.cli.p0)->node;
	}

	while (node) {
		cafile_entry = ebmb_entry(node, struct cafile_entry, node);
		if (cafile_entry->type == CAFILE_CERT) {
			chunk_appendf(trash, "%s", cafile_entry->path);

			chunk_appendf(trash, " - %d certificate(s)\n", get_certificate_count(cafile_entry));
		}

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
	appctx->ctx.cli.p0 = cafile_entry;
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
		return cli_err(appctx, "Can't create a CA file!\nOperations on certificates are currently locked!\n");

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
	char *err = NULL;
	int errcode = 0;
	struct buffer *buf;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3] || !payload)
		return cli_err(appctx, "'set ssl crl-file expects a filename and CAs as a payload\n");

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

	appctx->ctx.ssl.old_crlfile_entry = NULL;
	appctx->ctx.ssl.new_crlfile_entry = NULL;

	/* if there is an ongoing transaction */
	if (crlfile_transaction.path) {
		/* if there is an ongoing transaction, check if this is the same file */
		if (strcmp(crlfile_transaction.path, buf->area) != 0) {
			memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", crlfile_transaction.path, buf->area);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		appctx->ctx.ssl.old_crlfile_entry = crlfile_transaction.old_crlfile_entry;
	}
	else {
		/* lookup for the certificate in the tree */
		appctx->ctx.ssl.old_crlfile_entry = ssl_store_get_cafile_entry(buf->area, 0);
	}

	if (!appctx->ctx.ssl.old_crlfile_entry) {
		memprintf(&err, "%sCan't replace a CRL file which is not referenced by the configuration!\n",
		          err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	if (!appctx->ctx.ssl.path) {
		/* this is a new transaction, set the path of the transaction */
		appctx->ctx.ssl.path = strdup(appctx->ctx.ssl.old_crlfile_entry->path);
		if (!appctx->ctx.ssl.path) {
			memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
	}

	if (appctx->ctx.ssl.new_crlfile_entry)
		ssl_store_delete_cafile_entry(appctx->ctx.ssl.new_crlfile_entry);

	/* Create a new cafile_entry without adding it to the cafile tree. */
	appctx->ctx.ssl.new_crlfile_entry = ssl_store_create_cafile_entry(appctx->ctx.ssl.path, NULL, CAFILE_CRL);
	if (!appctx->ctx.ssl.new_crlfile_entry) {
		memprintf(&err, "%sCannot allocate memory!\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* Fill the new entry with the new CRL. */
	if (ssl_store_load_ca_from_buf(appctx->ctx.ssl.new_crlfile_entry, payload)) {
		memprintf(&err, "%sInvalid payload\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* we succeed, we can save the crl in the transaction */

	/* if there wasn't a transaction, update the old CA */
	if (!crlfile_transaction.old_crlfile_entry) {
		crlfile_transaction.old_crlfile_entry = appctx->ctx.ssl.old_crlfile_entry;
		crlfile_transaction.path = appctx->ctx.ssl.path;
		err = memprintf(&err, "transaction created for CA %s!\n", crlfile_transaction.path);
	} else {
		err = memprintf(&err, "transaction updated for CA %s!\n", crlfile_transaction.path);
	}

	/* free the previous CRL file if there was a transaction */
	ssl_store_delete_cafile_entry(crlfile_transaction.new_crlfile_entry);

	crlfile_transaction.new_crlfile_entry = appctx->ctx.ssl.new_crlfile_entry;

	/* creates the SNI ctxs later in the IO handler */

end:
	free_trash_chunk(buf);

	if (errcode & ERR_CODE) {
		ssl_store_delete_cafile_entry(appctx->ctx.ssl.new_crlfile_entry);
		appctx->ctx.ssl.new_crlfile_entry = NULL;
		appctx->ctx.ssl.old_crlfile_entry = NULL;

		ha_free(&appctx->ctx.ssl.path);

		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynerr(appctx, memprintf(&err, "%sCan't update %s!\n", err ? err : "", args[3]));
	} else {

		HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
		return cli_dynmsg(appctx, LOG_NOTICE, err);
	}
}

/* Parsing function of 'commit ssl crl-file' */
static int cli_parse_commit_crlfile(char **args, char *payload, struct appctx *appctx, void *private)
{
	char *err = NULL;

	if (!cli_has_level(appctx, ACCESS_LVL_ADMIN))
		return 1;

	if (!*args[3])
		return cli_err(appctx, "'commit ssl ca-file expects a filename\n");

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
	appctx->st2 = SETCERT_ST_INIT;
	appctx->ctx.ssl.next_ckchi = NULL;
	appctx->ctx.ssl.old_crlfile_entry = crlfile_transaction.old_crlfile_entry;
	appctx->ctx.ssl.new_crlfile_entry = crlfile_transaction.new_crlfile_entry;
	appctx->ctx.ssl.cafile_type = CAFILE_CRL;

	return 0;

error:

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	err = memprintf(&err, "%sCan't commit %s!\n", err ? err : "", args[3]);

	return cli_dynerr(appctx, err);
}


/* release function of the `commit ssl crl-file' command, free things and unlock the spinlock */
static void cli_release_commit_crlfile(struct appctx *appctx)
{
	if (appctx->st2 != SETCERT_ST_FIN) {
		struct cafile_entry *new_crlfile_entry = appctx->ctx.ssl.new_crlfile_entry;

		/* Remove the uncommitted cafile_entry from the tree. */
		ebmb_delete(&new_crlfile_entry->node);
		ssl_store_delete_cafile_entry(new_crlfile_entry);
	}
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
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
	ha_free(&crlfile_transaction.path);

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
	STACK_OF(X509_REVOKED) *rev = NULL;
	X509_REVOKED *rev_entry = NULL;
	int i;

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

end:
	free_trash_chunk(tmp);
	if (bio)
		BIO_free(bio);

	return 0;
}

/* IO handler of details "show ssl crl-file <filename[:index]>" */
static int cli_io_handler_show_crlfile_detail(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct cafile_entry *cafile_entry = appctx->ctx.cli.p0;
	struct buffer *out = alloc_trash_chunk();
	int i;
	X509_CRL *crl;
	STACK_OF(X509_OBJECT) *objs;
	int retval = 0;
	long index = (long)appctx->ctx.cli.p1;

	if (!out)
		goto end_no_putchk;

	chunk_appendf(out, "Filename: ");
	if (cafile_entry == crlfile_transaction.new_crlfile_entry)
		chunk_appendf(out, "*");
	chunk_appendf(out, "%s\n", cafile_entry->path);

	chunk_appendf(out, "Status: ");
	if (!cafile_entry->ca_store)
		chunk_appendf(out, "Empty\n");
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

		chunk_appendf(out, "\nCertificate Revocation List #%d:\n", i+1);
		retval = show_crl_detail(crl, out);
		if (retval < 0)
			goto end_no_putchk;
		else if (retval || index)
			goto end;
	}

end:
	if (ci_putchk(si_ic(si), out) == -1) {
		si_rx_room_blk(si);
		goto yield;
	}

end_no_putchk:
	free_trash_chunk(out);
	return 1;
yield:
	free_trash_chunk(out);
	return 0; /* should come back */
}

/* parsing function for 'show ssl crl-file [crlfile[:index]]' */
static int cli_parse_show_crlfile(char **args, char *payload, struct appctx *appctx, void *private)
{
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
			if (!crlfile_transaction.new_crlfile_entry)
				goto error;

			cafile_entry = crlfile_transaction.new_crlfile_entry;

			if (strcmp(args[3] + 1, cafile_entry->path) != 0)
				goto error;

		} else {
			/* Get the "original" cafile_entry and not the
			 * uncommitted one if it exists. */
			if ((cafile_entry = ssl_store_get_cafile_entry(args[3], 1)) == NULL || cafile_entry->type != CAFILE_CRL)
				goto error;
		}

		appctx->ctx.cli.p0 = cafile_entry;
		appctx->ctx.cli.p1 = (void*)index;
		/* use the IO handler that shows details */
		appctx->io_handler = cli_io_handler_show_crlfile_detail;
	}

	return 0;

error:
	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);
	if (err)
		return cli_dynerr(appctx, err);
	return cli_err(appctx, "Can't display the CA file : Not found!\n");
}

/* IO handler of "show ssl crl-file". The command taking a specific CRL file name
 * is managed in cli_io_handler_show_crlfile_detail. */
static int cli_io_handler_show_crlfile(struct appctx *appctx)
{
	struct buffer *trash = alloc_trash_chunk();
	struct ebmb_node *node;
	struct stream_interface *si = appctx->owner;
	struct cafile_entry *cafile_entry;

	if (trash == NULL)
		return 1;

	if (!appctx->ctx.ssl.old_crlfile_entry) {
		if (crlfile_transaction.old_crlfile_entry) {
			chunk_appendf(trash, "# transaction\n");
			chunk_appendf(trash, "*%s\n", crlfile_transaction.old_crlfile_entry->path);
		}
	}

	/* First time in this io_handler. */
	if (!appctx->ctx.cli.p0) {
		chunk_appendf(trash, "# filename\n");
		node = ebmb_first(&cafile_tree);
	} else {
		/* We yielded during a previous call. */
		node = &((struct cafile_entry*)appctx->ctx.cli.p0)->node;
	}

	while (node) {
		cafile_entry = ebmb_entry(node, struct cafile_entry, node);
		if (cafile_entry->type == CAFILE_CRL) {
			chunk_appendf(trash, "%s\n", cafile_entry->path);
		}

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
	appctx->ctx.cli.p0 = cafile_entry;
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
	{ { "new", "ssl", "cert", NULL },       "new ssl cert <certfile>                 : create a new certificate file to be used in a crt-list or a directory", cli_parse_new_cert, NULL, NULL },
	{ { "set", "ssl", "cert", NULL },       "set ssl cert <certfile> <payload>       : replace a certificate file",                                            cli_parse_set_cert, NULL, NULL },
	{ { "commit", "ssl", "cert", NULL },    "commit ssl cert <certfile>              : commit a certificate file",                                             cli_parse_commit_cert, cli_io_handler_commit_cert, cli_release_commit_cert },
	{ { "abort", "ssl", "cert", NULL },     "abort ssl cert <certfile>               : abort a transaction for a certificate file",                            cli_parse_abort_cert, NULL, NULL },
	{ { "del", "ssl", "cert", NULL },       "del ssl cert <certfile>                 : delete an unused certificate file",                                     cli_parse_del_cert, NULL, NULL },
	{ { "show", "ssl", "cert", NULL },      "show ssl cert [<certfile>]              : display the SSL certificates used in memory, or the details of a file", cli_parse_show_cert, cli_io_handler_show_cert, cli_release_show_cert },

	{ { "new", "ssl", "ca-file", NULL },    "new ssl ca-file <cafile>                : create a new CA file to be used in a crt-list",                         cli_parse_new_cafile, NULL, NULL },
	{ { "set", "ssl", "ca-file", NULL },    "set ssl ca-file <cafile> <payload>      : replace a CA file",                                                     cli_parse_set_cafile, NULL, NULL },
	{ { "commit", "ssl", "ca-file", NULL }, "commit ssl ca-file <cafile>             : commit a CA file",                                                      cli_parse_commit_cafile, cli_io_handler_commit_cafile_crlfile, cli_release_commit_cafile },
	{ { "abort", "ssl", "ca-file", NULL },  "abort ssl ca-file <cafile>              : abort a transaction for a CA file",                                     cli_parse_abort_cafile, NULL, NULL },
	{ { "del", "ssl", "ca-file", NULL },    "del ssl ca-file <cafile>                : delete an unused CA file",                                              cli_parse_del_cafile, NULL, NULL },
	{ { "show", "ssl", "ca-file", NULL },   "show ssl ca-file [<cafile>[:<index>]]   : display the SSL CA files used in memory, or the details of a <cafile>, or a single certificate of index <index> of a CA file <cafile>", cli_parse_show_cafile, cli_io_handler_show_cafile, cli_release_show_cafile },

	{ { "new", "ssl", "crl-file", NULL },   "new ssl crlfile <crlfile>               : create a new CRL file to be used in a crt-list",                        cli_parse_new_crlfile, NULL, NULL },
	{ { "set", "ssl", "crl-file", NULL },   "set ssl crl-file <crlfile> <payload>    : replace a CRL file",                                                    cli_parse_set_crlfile, NULL, NULL },
	{ { "commit", "ssl", "crl-file", NULL },"commit ssl crl-file <crlfile>           : commit a CRL file",                                                     cli_parse_commit_crlfile, cli_io_handler_commit_cafile_crlfile, cli_release_commit_crlfile },
	{ { "abort", "ssl", "crl-file", NULL }, "abort ssl crl-file <crlfile>            : abort a transaction for a CRL file",                                    cli_parse_abort_crlfile, NULL, NULL },
	{ { "del", "ssl", "crl-file", NULL },   "del ssl crl-file <crlfile>              : delete an unused CRL file",                                             cli_parse_del_crlfile, NULL, NULL },
	{ { "show", "ssl", "crl-file", NULL },  "show ssl crl-file [<crlfile[:<index>>]] : display the SSL CRL files used in memory, or the details of a <crlfile>, or a single CRL of index <index> of CRL file <crlfile>", cli_parse_show_crlfile, cli_io_handler_show_crlfile, cli_release_show_crlfile },
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

