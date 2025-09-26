/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef _HAPROXY_ECH_H
# define _HAPROXY_ECH_H
#ifdef USE_ECH

#include <openssl/ech.h>

int load_echkeys(SSL_CTX *ctx, char *dirname, int *loaded);
int cli_parse_show_ech(char **args, char *payload,
                       struct appctx *appctx, void *private);
int cli_io_handler_ech_details(struct appctx *appctx);
int cli_parse_add_ech(char **args, char *payload, struct appctx *appctx,
                      void *private);
int cli_parse_set_ech(char **args, char *payload,
                      struct appctx *appctx, void *private);
int cli_parse_del_ech(char **args, char *payload,
                      struct appctx *appctx, void *private);
int conn_get_ech_status(struct connection *conn, struct buffer *buf);
int conn_get_ech_outer_sni(struct connection *conn, struct buffer *buf);

# endif /* USE_ECH */
#endif /* _HAPROXY_ECH_H */
