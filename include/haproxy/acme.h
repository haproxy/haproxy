/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _ACME_H_
#define _ACME_H_

#include <haproxy/ssl_ckch-t.h>

int ckch_conf_acme_init(void *value, char *buf, struct ckch_store *s, int cli, const char *filename, int linenum, char **err);
int acme_challenge_ready(const char *crt, const char *dns);
EVP_PKEY *acme_gen_tmp_pkey();
X509 *acme_gen_tmp_x509();

#if defined(USE_LUA)
#include <haproxy/hlua-t.h>
#include <haproxy/event_hdl-t.h>
void acme_hlua_event_push_args(struct hlua *hlua, struct event_hdl_sub_type event, void *data);
#endif /* USE_LUA */

#endif
