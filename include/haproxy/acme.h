/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _ACME_H_
#define _ACME_H_

#include <haproxy/ssl_ckch-t.h>

int ckch_conf_acme_init(void *value, char *buf, struct ckch_store *s, int cli, const char *filename, int linenum, char **err);
EVP_PKEY *acme_gen_tmp_pkey();
X509 *acme_gen_tmp_x509();
EVP_PKEY *acme_EVP_PKEY_gen(int keytype, int curves, int bits, char **err);
X509 *acme_gen_x509(EVP_PKEY *pkey);


#endif
