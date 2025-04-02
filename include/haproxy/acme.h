/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _ACME_H_
#define _ACME_H_

#include <haproxy/ssl_ckch-t.h>

int ckch_conf_acme_init(void *value, char *buf, struct ckch_data *d, int cli, const char *filename, int linenum, char **err);

#endif
