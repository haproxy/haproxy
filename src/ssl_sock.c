
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
#include <haproxy/quic_conn.h>
#include <haproxy/quic_openssl_compat.h>
#include <haproxy/quic_tp.h>
#include <haproxy/sample.h>
#include <haproxy/sc_strm.h>
#include <haproxy/server.h>
#include <haproxy/shctx.h>
#include <haproxy/ssl_ckch.h>
#include <haproxy/ssl_crtlist.h>
#include <haproxy/ssl_gencert.h>
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
#include <haproxy/ssl_ocsp.h>
#include <haproxy/trace.h>
#include <haproxy/ssl_trace-t.h>


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

int nb_engines = 0;

static struct eb_root cert_issuer_tree = EB_ROOT; /* issuers tree from "issuers-chain-path" */

struct global_ssl global_ssl = {
#ifdef LISTEN_DEFAULT_CIPHERS
	.listen_default_ciphers = LISTEN_DEFAULT_CIPHERS,
#endif
#ifdef CONNECT_DEFAULT_CIPHERS
	.connect_default_ciphers = CONNECT_DEFAULT_CIPHERS,
#endif
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	.listen_default_ciphersuites = LISTEN_DEFAULT_CIPHERSUITES,
	.connect_default_ciphersuites = CONNECT_DEFAULT_CIPHERSUITES,
#endif
	.listen_default_ssloptions = BC_SSL_O_NONE,
	.connect_default_ssloptions = SRV_SSL_O_NONE,

	.listen_default_sslmethods.flags = MC_SSL_O_ALL,
	.listen_default_sslmethods.min = CONF_TLSV_NONE,
	.listen_default_sslmethods.max = CONF_TLSV_NONE,
	.connect_default_sslmethods.flags = MC_SSL_O_ALL,
	.connect_default_sslmethods.min = CONF_TLSV_NONE,
	.connect_default_sslmethods.max = CONF_TLSV_NONE,

#ifdef DEFAULT_SSL_MAX_RECORD
	.max_record = DEFAULT_SSL_MAX_RECORD,
#endif
	.hard_max_record = 0,
	.default_dh_param = SSL_DEFAULT_DH_PARAM,
	.ctx_cache = DEFAULT_SSL_CTX_CACHE,
	.capture_buffer_size = 0,
	.extra_files = SSL_GF_ALL,
	.extra_files_noext = 0,
#ifdef HAVE_SSL_KEYLOG
	.keylog = 0,
#endif
	.security_level = -1,
#ifdef HAVE_SSL_OCSP
	.ocsp_update.delay_max = SSL_OCSP_UPDATE_DELAY_MAX,
	.ocsp_update.delay_min = SSL_OCSP_UPDATE_DELAY_MIN,
	.ocsp_update.mode = SSL_SOCK_OCSP_UPDATE_OFF,
	.ocsp_update.disable = 0,
#endif
#ifdef HAVE_ACME
	.acme_scheduler = 1,
#endif

};

static BIO_METHOD *ha_meth;

DECLARE_STATIC_POOL(ssl_sock_ctx_pool, "ssl_sock_ctx", sizeof(struct ssl_sock_ctx));

DECLARE_POOL(ssl_sock_client_sni_pool, "ssl_sock_client_sni", TLSEXT_MAXLEN_host_name + 1);

/* ssl stats module */
enum {
	SSL_ST_SESS,
	SSL_ST_REUSED_SESS,
	SSL_ST_FAILED_HANDSHAKE,
	SSL_ST_OCSP_STAPLE,
	SSL_ST_FAILED_OCSP_STAPLE,

	SSL_ST_STATS_COUNT /* must be the last member of the enum */
};

static struct stat_col ssl_stats[] = {
	[SSL_ST_SESS]             = { .name = "ssl_sess",
	                              .desc = "Total number of ssl sessions established" },
	[SSL_ST_REUSED_SESS]      = { .name = "ssl_reused_sess",
	                              .desc = "Total number of ssl sessions reused" },
	[SSL_ST_FAILED_HANDSHAKE] = { .name = "ssl_failed_handshake",
	                              .desc = "Total number of failed handshake" },
	[SSL_ST_OCSP_STAPLE]      = { .name = "ssl_ocsp_staple",
	                              .desc = "Total number of stapled OCSP responses" },
	[SSL_ST_FAILED_OCSP_STAPLE] = { .name = "ssl_failed_ocsp_staple",
	                              .desc = "Total number of failed OCSP stapling (expired or error)" },
};

static struct ssl_counters ssl_counters;

static int ssl_fill_stats(void *data, struct field *stats, unsigned int *selected_field)
{
	struct ssl_counters *counters = data;
	unsigned int current_field = (selected_field != NULL ? *selected_field : 0);

	for (; current_field < SSL_ST_STATS_COUNT; current_field++) {
		struct field metric = { 0 };

		switch (current_field) {
		case SSL_ST_SESS:
			metric = mkf_u64(FN_COUNTER, counters->sess);
			break;
		case SSL_ST_REUSED_SESS:
			metric = mkf_u64(FN_COUNTER, counters->reused_sess);
			break;
		case SSL_ST_FAILED_HANDSHAKE:
			metric = mkf_u64(FN_COUNTER, counters->failed_handshake);
			break;
		case SSL_ST_OCSP_STAPLE:
			metric = mkf_u64(FN_COUNTER, counters->ocsp_staple);
			break;
		case SSL_ST_FAILED_OCSP_STAPLE:
			metric = mkf_u64(FN_COUNTER, counters->failed_ocsp_staple);
			break;

		default:
			/* not used for frontends. If a specific metric
			 * is requested, return an error. Otherwise continue.
			 */
			if (selected_field != NULL)
				return 0;
			continue;
		}
		stats[current_field] = metric;
		if (selected_field != NULL)
			break;
	}
	return 1;
}

struct stats_module ssl_stats_module = {
	.name          = "ssl",
	.fill_stats    = ssl_fill_stats,
	.stats         = ssl_stats,
	.stats_count   = SSL_ST_STATS_COUNT,
	.counters      = &ssl_counters,
	.counters_size = sizeof(ssl_counters),
	.domain_flags  = MK_STATS_PROXY_DOMAIN(STATS_PX_CAP_FE|STATS_PX_CAP_LI|STATS_PX_CAP_BE|STATS_PX_CAP_SRV),
	.clearable     = 1,
};

INITCALL1(STG_REGISTER, stats_register_module, &ssl_stats_module);

/* CLI context for "show tls-keys" */
struct show_keys_ctx {
	struct tls_keys_ref *next_ref; /* next reference to be dumped */
	int names_only;                /* non-zero = only show file names */
	int next_index;                /* next index to be dumped */
	int dump_entries;              /* dump entries also */
	enum {
		SHOW_KEYS_INIT = 0,
		SHOW_KEYS_LIST,
		SHOW_KEYS_DONE,
	} state;                       /* phase of the current dump */
};

/* ssl_sock_io_cb is exported to see it resolved in "show fd" */
struct task *ssl_sock_io_cb(struct task *, void *, unsigned int);
static int ssl_sock_handshake(struct connection *conn, unsigned int flag);

/* Methods to implement OpenSSL BIO */
static int ha_ssl_write(BIO *h, const char *buf, int num)
{
	struct buffer tmpbuf;
	struct ssl_sock_ctx *ctx;
	uint flags;
	int ret;

	ctx = BIO_get_data(h);
	tmpbuf.size = num;
	tmpbuf.area = (void *)(uintptr_t)buf;
	tmpbuf.data = num;
	tmpbuf.head = 0;
	flags = (ctx->xprt_st & SSL_SOCK_SEND_MORE) ? CO_SFL_MSG_MORE : 0;
	ret = ctx->xprt->snd_buf(ctx->conn, ctx->xprt_ctx, &tmpbuf, num, flags);
	BIO_clear_retry_flags(h);
	if (ret == 0 && !(ctx->conn->flags & (CO_FL_ERROR | CO_FL_SOCK_WR_SH))) {
		BIO_set_retry_write(h);
		ret = -1;
	}
	return ret;
}

static int ha_ssl_gets(BIO *h, char *buf, int size)
{

	return 0;
}

static int ha_ssl_puts(BIO *h, const char *str)
{

	return ha_ssl_write(h, str, strlen(str));
}

static int ha_ssl_read(BIO *h, char *buf, int size)
{
	struct buffer tmpbuf;
	struct ssl_sock_ctx *ctx;
	int ret;

	ctx = BIO_get_data(h);
	tmpbuf.size = size;
	tmpbuf.area = buf;
	tmpbuf.data = 0;
	tmpbuf.head = 0;
	ret = ctx->xprt->rcv_buf(ctx->conn, ctx->xprt_ctx, &tmpbuf, size, 0);
	BIO_clear_retry_flags(h);
	if (ret == 0 && !(ctx->conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH))) {
		BIO_set_retry_read(h);
		ret = -1;
	}

	return ret;
}

static long ha_ssl_ctrl(BIO *h, int cmd, long arg1, void *arg2)
{
	int ret = 0;
	switch (cmd) {
	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		ret = 1;
		break;
	}
	return ret;
}

static int ha_ssl_new(BIO *h)
{
	BIO_set_init(h, 1);
	BIO_set_data(h, NULL);
	BIO_clear_flags(h, ~0);
	return 1;
}

static int ha_ssl_free(BIO *data)
{

	return 1;
}


#if defined(USE_THREAD) && (HA_OPENSSL_VERSION_NUMBER < 0x10100000L)

static HA_RWLOCK_T *ssl_rwlocks;


unsigned long ssl_id_function(void)
{
	return (unsigned long)tid;
}

void ssl_locking_function(int mode, int n, const char * file, int line)
{
	if (mode & CRYPTO_LOCK) {
		if (mode & CRYPTO_READ)
			HA_RWLOCK_RDLOCK(SSL_LOCK, &ssl_rwlocks[n]);
		else
			HA_RWLOCK_WRLOCK(SSL_LOCK, &ssl_rwlocks[n]);
	}
	else {
		if (mode & CRYPTO_READ)
			HA_RWLOCK_RDUNLOCK(SSL_LOCK, &ssl_rwlocks[n]);
		else
			HA_RWLOCK_WRUNLOCK(SSL_LOCK, &ssl_rwlocks[n]);
	}
}

static int ssl_locking_init(void)
{
	int i;

	ssl_rwlocks = malloc(sizeof(HA_RWLOCK_T)*CRYPTO_num_locks());
	if (!ssl_rwlocks)
		return -1;

	for (i = 0 ; i < CRYPTO_num_locks() ; i++)
		HA_RWLOCK_INIT(&ssl_rwlocks[i]);

	CRYPTO_set_id_callback(ssl_id_function);
	CRYPTO_set_locking_callback(ssl_locking_function);

	return 0;
}

#endif

__decl_thread(HA_SPINLOCK_T ckch_lock);



/* mimic what X509_STORE_load_locations do with store_ctx */
static int ssl_set_cert_crl_file(X509_STORE *store_ctx, char *path)
{
	X509_STORE *store = NULL;
	struct cafile_entry *ca_e = ssl_store_get_cafile_entry(path, 0);
	if (ca_e)
		store = ca_e->ca_store;
	if (store_ctx && store) {
		int i;
		X509_OBJECT *obj;
		STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(store);
		for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
			obj = sk_X509_OBJECT_value(objs, i);
			switch (X509_OBJECT_get_type(obj)) {
			case X509_LU_X509:
				X509_STORE_add_cert(store_ctx, X509_OBJECT_get0_X509(obj));
				break;
			case X509_LU_CRL:
				X509_STORE_add_crl(store_ctx, X509_OBJECT_get0_X509_CRL(obj));
				break;
			default:
				break;
			}
		}
		return 1;
	}
	return 0;
}

/* SSL_CTX_load_verify_locations substitute, internally call X509_STORE_load_locations */
static int ssl_set_verify_locations_file(SSL_CTX *ctx, char *path)
{
	X509_STORE *store_ctx = SSL_CTX_get_cert_store(ctx);
	return ssl_set_cert_crl_file(store_ctx, path);
}

/*
   Extract CA_list from CA_file already in tree.
   Duplicate ca_name is tracking with ebtree. It's simplify openssl compatibility.
   Return a shared ca_list: SSL_dup_CA_list must be used before set it on SSL_CTX.
*/
static STACK_OF(X509_NAME)* ssl_get_client_ca_file(char *path)
{
	struct ebmb_node *eb;
	struct cafile_entry *ca_e;

	eb = ebst_lookup(&cafile_tree, path);
	if (!eb)
		return NULL;
	ca_e = ebmb_entry(eb, struct cafile_entry, node);

	if (ca_e->ca_list == NULL) {
		int i;
		unsigned long key;
		struct eb_root ca_name_tree = EB_ROOT;
		struct eb64_node *node, *back;
		struct {
			struct eb64_node node;
			X509_NAME *xname;
		} *ca_name;
		STACK_OF(X509_OBJECT) *objs;
		STACK_OF(X509_NAME) *skn;
		X509 *x;
		X509_NAME *xn;

		skn = sk_X509_NAME_new_null();
		/* take x509 from cafile_tree */
		objs = X509_STORE_get0_objects(ca_e->ca_store);
		for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
			x = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
			if (!x)
				continue;
			xn = X509_get_subject_name(x);
			if (!xn)
				continue;
			/* Check for duplicates. */
			key = X509_NAME_hash(xn);
			for (node = eb64_lookup(&ca_name_tree, key), ca_name = NULL;
			     node && ca_name == NULL;
			     node = eb64_next(node)) {
				ca_name = container_of(node, typeof(*ca_name), node);
				if (X509_NAME_cmp(xn, ca_name->xname) != 0)
					ca_name = NULL;
			}
			/* find a duplicate */
			if (ca_name)
				continue;
			ca_name = calloc(1, sizeof *ca_name);
			xn = X509_NAME_dup(xn);
			if (!ca_name ||
			    !xn ||
			    !sk_X509_NAME_push(skn, xn)) {
				    free(ca_name);
				    X509_NAME_free(xn);
				    sk_X509_NAME_pop_free(skn, X509_NAME_free);
				    sk_X509_NAME_free(skn);
				    skn = NULL;
				    break;
			}
			ca_name->node.key = key;
			ca_name->xname = xn;
			eb64_insert(&ca_name_tree, &ca_name->node);
		}
		ca_e->ca_list = skn;
		/* remove temporary ca_name tree */
		node = eb64_first(&ca_name_tree);
		while (node) {
			ca_name = container_of(node, typeof(*ca_name), node);
			back = eb64_next(node);
			eb64_delete(node);
			free(ca_name);
			node = back;
		}
	}
	return ca_e->ca_list;
}

struct pool_head *pool_head_ssl_capture __read_mostly = NULL;
int ssl_capture_ptr_index = -1;
int ssl_app_data_index = -1;
#ifdef USE_QUIC
int ssl_qc_app_data_index = -1;
#endif /* USE_QUIC */

#ifdef HAVE_SSL_KEYLOG
int ssl_keylog_index = -1;
struct pool_head *pool_head_ssl_keylog __read_mostly = NULL;
struct pool_head *pool_head_ssl_keylog_str __read_mostly = NULL;
#endif

int ssl_client_crt_ref_index = -1;

/* Used to store the client's SNI in case of ClientHello callback error */
int ssl_client_sni_index = -1;

#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
struct list tlskeys_reference = LIST_HEAD_INIT(tlskeys_reference);
#endif

#if defined(USE_ENGINE) && !defined(OPENSSL_NO_ENGINE)
unsigned int openssl_engines_initialized;
struct list openssl_engines = LIST_HEAD_INIT(openssl_engines);
struct ssl_engine_list {
	struct list list;
	ENGINE *e;
};
#endif

#ifdef HAVE_SSL_PROVIDERS
struct list openssl_providers = LIST_HEAD_INIT(openssl_providers);
struct ssl_provider_list {
	struct list list;
	OSSL_PROVIDER *provider;
};
#endif

#ifndef OPENSSL_NO_DH
static int ssl_dh_ptr_index = -1;
static HASSL_DH *global_dh = NULL;
static HASSL_DH *local_dh_1024 = NULL;
static HASSL_DH *local_dh_2048 = NULL;
static HASSL_DH *local_dh_4096 = NULL;
#endif /* OPENSSL_NO_DH */

/* The order here matters for picking a default context,
 * keep the most common keytype at the bottom of the list
 */
const char *SSL_SOCK_KEYTYPE_NAMES[] = {
	"dsa",
	"ecdsa",
	"rsa"
};

static struct shared_context *ssl_shctx = NULL; /* ssl shared session cache */
static struct eb_root *sh_ssl_sess_tree; /* ssl shared session tree */

/* Dedicated callback functions for heartbeat and clienthello.
 */
#ifdef TLS1_RT_HEARTBEAT
static void ssl_sock_parse_heartbeat(struct connection *conn, int write_p, int version,
                                     int content_type, const void *buf, size_t len,
                                     SSL *ssl);
#endif
static void ssl_sock_parse_clienthello(struct connection *conn, int write_p, int version,
                                       int content_type, const void *buf, size_t len,
                                       SSL *ssl);

#ifdef HAVE_SSL_KEYLOG
static void ssl_init_keylog(struct connection *conn, int write_p, int version,
                            int content_type, const void *buf, size_t len,
                            SSL *ssl);
#endif

/* List head of all registered SSL/TLS protocol message callbacks. */
struct list ssl_sock_msg_callbacks = LIST_HEAD_INIT(ssl_sock_msg_callbacks);

/* Registers the function <func> in order to be called on SSL/TLS protocol
 * message processing. It will return 0 if the function <func> is not set
 * or if it fails to allocate memory.
 */
int ssl_sock_register_msg_callback(ssl_sock_msg_callback_func func)
{
	struct ssl_sock_msg_callback *cbk;

	if (!func)
		return 0;

	cbk = calloc(1, sizeof(*cbk));
	if (!cbk) {
		ha_alert("out of memory in ssl_sock_register_msg_callback().\n");
		return 0;
	}

	cbk->func = func;

	LIST_APPEND(&ssl_sock_msg_callbacks, &cbk->list);

	return 1;
}

/* Used to register dedicated SSL/TLS protocol message callbacks.
 */
static int ssl_sock_register_msg_callbacks(void)
{
#ifdef TLS1_RT_HEARTBEAT
	if (!ssl_sock_register_msg_callback(ssl_sock_parse_heartbeat))
		return ERR_ABORT;
#endif
	if (global_ssl.capture_buffer_size > 0) {
		if (!ssl_sock_register_msg_callback(ssl_sock_parse_clienthello))
			return ERR_ABORT;
	}
#ifdef HAVE_SSL_KEYLOG
	if (global_ssl.keylog > 0) {
		if (!ssl_sock_register_msg_callback(ssl_init_keylog))
			return ERR_ABORT;
	}
#endif
#ifdef USE_QUIC_OPENSSL_COMPAT
	if (!ssl_sock_register_msg_callback(quic_tls_compat_msg_callback))
		return ERR_ABORT;
#endif

	return ERR_NONE;
}

/* Used to free all SSL/TLS protocol message callbacks that were
 * registered by using ssl_sock_register_msg_callback().
 */
static void ssl_sock_unregister_msg_callbacks(void)
{
	struct ssl_sock_msg_callback *cbk, *cbkback;

	list_for_each_entry_safe(cbk, cbkback, &ssl_sock_msg_callbacks, list) {
		LIST_DELETE(&cbk->list);
		free(cbk);
	}
}

static struct ssl_sock_ctx *ssl_sock_get_ctx(struct connection *conn)
{
	if (!conn || conn->xprt != xprt_get(XPRT_SSL) || !conn->xprt_ctx)
		return NULL;

	return (struct ssl_sock_ctx *)conn->xprt_ctx;
}

SSL *ssl_sock_get_ssl_object(struct connection *conn)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);

	return ctx ? ctx->ssl : NULL;
}
/*
 * This function gives the detail of the SSL error. It is used only
 * if the debug mode and the verbose mode are activated. It dump all
 * the SSL error until the stack was empty.
 */
static forceinline void ssl_sock_dump_errors(struct connection *conn,
                                             struct quic_conn *qc)
{
	unsigned long ret;

	if (unlikely(global.mode & MODE_DEBUG)) {
		while(1) {
			const char *func = NULL;
			ERR_peek_error_func(&func);

			ret = ERR_get_error();
			if (ret == 0)
				return;
			if (conn) {
				fprintf(stderr, "fd[%#x] OpenSSL error[0x%lx] %s: %s\n",
				        conn_fd(conn), ret,
				        func, ERR_reason_error_string(ret));
			}
#ifdef USE_QUIC
			else {
				/* TODO: we are not sure <conn> is always initialized for QUIC connections */
				fprintf(stderr, "qc @%p OpenSSL error[0x%lx] %s: %s\n", qc, ret,
				        func, ERR_reason_error_string(ret));
			}
#endif
		}
	}
}


#if defined(USE_ENGINE) && !defined(OPENSSL_NO_ENGINE)
int ssl_init_single_engine(const char *engine_id, const char *def_algorithms)
{
	int err_code = ERR_ABORT;
	ENGINE *engine;
	struct ssl_engine_list *el;

	/* grab the structural reference to the engine */
	engine = ENGINE_by_id(engine_id);
	if (engine  == NULL) {
		ha_alert("ssl-engine %s: failed to get structural reference\n", engine_id);
		goto fail_get;
	}

	if (!ENGINE_init(engine)) {
		/* the engine couldn't initialise, release it */
		ha_alert("ssl-engine %s: failed to initialize\n", engine_id);
		goto fail_init;
	}

	if (ENGINE_set_default_string(engine, def_algorithms) == 0) {
		ha_alert("ssl-engine %s: failed on ENGINE_set_default_string\n", engine_id);
		goto fail_set_method;
	}

	el = calloc(1, sizeof(*el));
	if (!el)
		goto fail_alloc;
	el->e = engine;
	LIST_INSERT(&openssl_engines, &el->list);
	nb_engines++;
	if (global_ssl.async)
		global.ssl_used_async_engines = nb_engines;
	return 0;

fail_alloc:
fail_set_method:
	/* release the functional reference from ENGINE_init() */
	ENGINE_finish(engine);

fail_init:
	/* release the structural reference from ENGINE_by_id() */
	ENGINE_free(engine);

fail_get:
	return err_code;
}
#endif

#ifdef HAVE_SSL_PROVIDERS
int ssl_init_provider(const char *provider_name)
{
	int err_code = ERR_ABORT;
	struct ssl_provider_list *prov = NULL;

	prov = calloc(1, sizeof(*prov));
	if (!prov) {
		ha_alert("ssl-provider %s: memory allocation failure\n", provider_name);
		goto error;
	}

	if ((prov->provider = OSSL_PROVIDER_load(NULL, provider_name)) == NULL) {
		ha_alert("ssl-provider %s: unknown provider\n", provider_name);
		goto error;
	}

	LIST_INSERT(&openssl_providers, &prov->list);

	return 0;

error:
	ha_free(&prov);
	return err_code;
}
#endif /* HAVE_SSL_PROVIDERS */

#ifdef SSL_MODE_ASYNC
/*
 * openssl async fd handler
 */
void ssl_async_fd_handler(int fd)
{
	struct ssl_sock_ctx *ctx = fdtab[fd].owner;

	/* fd is an async enfine fd, we must stop
	 * to poll this fd until it is requested
	 */
        fd_stop_recv(fd);
        fd_cant_recv(fd);

	/* crypto engine is available, let's notify the associated
	 * connection that it can pursue its processing.
	 */
	tasklet_wakeup(ctx->wait_event.tasklet);
}

/*
 * openssl async delayed SSL_free handler
 */
void ssl_async_fd_free(int fd)
{
	SSL *ssl = fdtab[fd].owner;
	OSSL_ASYNC_FD all_fd[32];
	size_t num_all_fds = 0;
	int i;

	/* We suppose that the async job for a same SSL *
	 * are serialized. So if we are awake it is
	 * because the running job has just finished
	 * and we can remove all async fds safely
	 */
	SSL_get_all_async_fds(ssl, NULL, &num_all_fds);
	if (num_all_fds > 32) {
		send_log(NULL, LOG_EMERG, "haproxy: openssl returns too many async fds. It seems a bug. Process may crash\n");
		return;
	}

	SSL_get_all_async_fds(ssl, all_fd, &num_all_fds);
	for (i=0 ; i < num_all_fds ; i++) {
		/* We want to remove the fd from the fdtab
		 * but we flag it to disown because the
		 * close is performed by the engine itself
		 */
		fdtab[all_fd[i]].state |= FD_DISOWN;
		fd_delete(all_fd[i]);
	}

	/* Now we can safely call SSL_free, no more pending job in engines */
	SSL_free(ssl);
	_HA_ATOMIC_DEC(&global.sslconns);
	_HA_ATOMIC_DEC(&jobs);
}
/*
 * function used to manage a returned SSL_ERROR_WANT_ASYNC
 * and enable/disable polling for async fds
 */
static inline void ssl_async_process_fds(struct ssl_sock_ctx *ctx)
{
	OSSL_ASYNC_FD add_fd[32];
	OSSL_ASYNC_FD del_fd[32];
	SSL *ssl = ctx->ssl;
	size_t num_add_fds = 0;
	size_t num_del_fds = 0;
	int i;

	SSL_get_changed_async_fds(ssl, NULL, &num_add_fds, NULL,
			&num_del_fds);
	if (num_add_fds > 32 || num_del_fds > 32) {
		send_log(NULL, LOG_EMERG, "haproxy: openssl returns too many async fds. It seems a bug. Process may crash\n");
		return;
	}

	SSL_get_changed_async_fds(ssl, add_fd, &num_add_fds, del_fd, &num_del_fds);

	/* We remove unused fds from the fdtab */
	for (i=0 ; i < num_del_fds ; i++) {
		/* We want to remove the fd from the fdtab
		 * but we flag it to disown because the
		 * close is performed by the engine itself
		 */
		fdtab[del_fd[i]].state |= FD_DISOWN;
		fd_delete(del_fd[i]);
	}

	/* We add new fds to the fdtab */
	for (i=0 ; i < num_add_fds ; i++) {
		fd_insert(add_fd[i], ctx, ssl_async_fd_handler, tgid, ti->ltid_bit);
	}

	num_add_fds = 0;
	SSL_get_all_async_fds(ssl, NULL, &num_add_fds);
	if (num_add_fds > 32) {
		send_log(NULL, LOG_EMERG, "haproxy: openssl returns too many async fds. It seems a bug. Process may crash\n");
		return;
	}

	/* We activate the polling for all known async fds */
	SSL_get_all_async_fds(ssl, add_fd, &num_add_fds);
	for (i=0 ; i < num_add_fds ; i++) {
		fd_want_recv(add_fd[i]);
		/* To ensure that the fd cache won't be used
		 * We'll prefer to catch a real RD event
		 * because handling an EAGAIN on this fd will
		 * result in a context switch and also
		 * some engines uses a fd in blocking mode.
		 */
		fd_cant_recv(add_fd[i]);
	}

}
#endif


/*
 * Initialize an HMAC context <hctx> using the <key> and <md> parameters.
 * Returns -1 in case of error, 1 otherwise.
 */
static int ssl_hmac_init(MAC_CTX *hctx, unsigned char *key, int key_len, const EVP_MD *md)
{
#ifdef HAVE_OSSL_PARAM
       OSSL_PARAM params[3];

       params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, key_len);
       params[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)EVP_MD_name(md), 0);
       params[2] = OSSL_PARAM_construct_end();
       if (EVP_MAC_CTX_set_params(hctx, params) == 0)
               return -1; /* error in mac initialisation */

#else
       HMAC_Init_ex(hctx, key, key_len, md, NULL);
#endif
       return 1;
}

#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)

static int ssl_tlsext_ticket_key_cb(SSL *s, unsigned char key_name[16], unsigned char *iv, EVP_CIPHER_CTX *ectx, MAC_CTX *hctx, int enc)
{
	struct tls_keys_ref *ref = NULL;
	union tls_sess_key *keys;
	int head;
	int i;
	int ret = -1; /* error by default */
	struct connection *conn = SSL_get_ex_data(s, ssl_app_data_index);
#ifdef USE_QUIC
	struct quic_conn *qc = SSL_get_ex_data(s, ssl_qc_app_data_index);
#endif

	if (conn)
		ref  = __objt_listener(conn->target)->bind_conf->keys_ref;
#ifdef USE_QUIC
	else if (qc)
		ref =  qc->li->bind_conf->keys_ref;
#endif

	if (!ref) {
		/* must never happen */
		ABORT_NOW();
	}

	HA_RWLOCK_RDLOCK(TLSKEYS_REF_LOCK, &ref->lock);

	keys = ref->tlskeys;
	head = ref->tls_ticket_enc_index;

	if (enc) {
		memcpy(key_name, keys[head].name, 16);

		if(!RAND_pseudo_bytes(iv, EVP_MAX_IV_LENGTH))
			goto end;

		if (ref->key_size_bits == 128) {

			if(!EVP_EncryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, keys[head].key_128.aes_key, iv))
				goto end;

			if (ssl_hmac_init(hctx, keys[head].key_128.hmac_key, 16, TLS_TICKET_HASH_FUNCT()) < 0)
				goto end;
			ret = 1;
		}
		else if (ref->key_size_bits == 256 ) {

			if(!EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, keys[head].key_256.aes_key, iv))
				goto end;

			if (ssl_hmac_init(hctx,  keys[head].key_256.hmac_key, 32, TLS_TICKET_HASH_FUNCT()) < 0)
				goto end;
			ret = 1;
		}
	} else {
		for (i = 0; i < TLS_TICKETS_NO; i++) {
			if (!memcmp(key_name, keys[(head + i) % TLS_TICKETS_NO].name, 16))
				goto found;
		}
		ret = 0;
		goto end;

	  found:
		if (ref->key_size_bits == 128) {
			if (ssl_hmac_init(hctx, keys[(head + i) % TLS_TICKETS_NO].key_128.hmac_key, 16, TLS_TICKET_HASH_FUNCT()) < 0)
				goto end;
			if(!EVP_DecryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, keys[(head + i) % TLS_TICKETS_NO].key_128.aes_key, iv))
				goto end;
			/* 2 for key renewal, 1 if current key is still valid */
			ret = i ? 2 : 1;
		}
		else if (ref->key_size_bits == 256) {
			if (ssl_hmac_init(hctx, keys[(head + i) % TLS_TICKETS_NO].key_256.hmac_key, 32, TLS_TICKET_HASH_FUNCT()) < 0)
				goto end;
			if(!EVP_DecryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, keys[(head + i) % TLS_TICKETS_NO].key_256.aes_key, iv))
				goto end;
			/* 2 for key renewal, 1 if current key is still valid */
			ret = i ? 2 : 1;
		}
	}

  end:
	HA_RWLOCK_RDUNLOCK(TLSKEYS_REF_LOCK, &ref->lock);
	return ret;
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

/* Update the key into ref: if keysize doesn't
 * match existing ones, this function returns -1
 * else it returns 0 on success.
 */
int ssl_sock_update_tlskey_ref(struct tls_keys_ref *ref,
				struct buffer *tlskey)
{
	if (ref->key_size_bits == 128) {
		if (tlskey->data != sizeof(struct tls_sess_key_128))
			       return -1;
	}
	else if (ref->key_size_bits == 256) {
		if (tlskey->data != sizeof(struct tls_sess_key_256))
			       return -1;
	}
	else
		return -1;

	HA_RWLOCK_WRLOCK(TLSKEYS_REF_LOCK, &ref->lock);
	memcpy((char *) (ref->tlskeys + ((ref->tls_ticket_enc_index + 2) % TLS_TICKETS_NO)),
	       tlskey->area, tlskey->data);
	ref->tls_ticket_enc_index = (ref->tls_ticket_enc_index + 1) % TLS_TICKETS_NO;
	HA_RWLOCK_WRUNLOCK(TLSKEYS_REF_LOCK, &ref->lock);

	return 0;
}

int ssl_sock_update_tlskey(char *filename, struct buffer *tlskey, char **err)
{
	struct tls_keys_ref *ref = tlskeys_ref_lookup(filename);

	if(!ref) {
		memprintf(err, "Unable to locate the referenced filename: %s", filename);
		return 1;
	}
	if (ssl_sock_update_tlskey_ref(ref, tlskey) < 0) {
		memprintf(err, "Invalid key size");
		return 1;
	}

	return 0;
}

/* This function finalize the configuration parsing. Its set all the
 * automatic ids. It's called just after the basic checks. It returns
 * 0 on success otherwise ERR_*.
 */
static int tlskeys_finalize_config(void)
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
		LIST_DELETE(&ref->list);
		list_for_each_entry(ref3, &tkr, list) {
			if (ref->unique_id < ref3->unique_id) {
				LIST_APPEND(&ref3->list, &ref->list);
				break;
			}
		}
		if (&ref3->list == &tkr)
			LIST_APPEND(&tkr, &ref->list);
	}

	/* swap root */
	LIST_SPLICE(&tlskeys_reference, &tkr);
	return ERR_NONE;
}
#endif /* SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB */


#if (defined(HAVE_SSL_OCSP) && !defined OPENSSL_IS_BORINGSSL)
/*
 * This function enables the handling of OCSP status extension on 'ctx' if a
 * ocsp_response buffer was found in the cert_key_and_chain.  To enable OCSP
 * status extension, the issuer's certificate is mandatory.  It should be
 * present in ckch->ocsp_issuer.
 *
 * In addition, the ckch->ocsp_reponse buffer is loaded as a DER format of an
 * OCSP response. If file is empty or content is not a valid OCSP response,
 * OCSP status extension is enabled but OCSP response is ignored (a warning is
 * displayed).
 *
 * Returns 1 if no ".ocsp" file found, 0 if OCSP status extension is
 * successfully enabled, or -1 in other error case.
 */
static int ssl_sock_load_ocsp(const char *path, SSL_CTX *ctx, struct ckch_store *store, STACK_OF(X509) *chain)
{
	struct ckch_data *data = store->data;
	X509 *x, *issuer;
	int i, ret = -1;
	struct certificate_ocsp *ocsp = NULL, *iocsp;
	char *warn = NULL;
	unsigned char *p;
#ifdef USE_OPENSSL_WOLFSSL
	/* typedef int(*tlsextStatusCb)(WOLFSSL* ssl, void*); */
	tlsextStatusCb callback = NULL;
#elif (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	int (*callback) (SSL *, void *) = NULL;
#else
	void (*callback) (void) = NULL;
#endif
	struct buffer *ocsp_uri = get_trash_chunk();
	char *err = NULL;
	size_t path_len;
	int inc_refcount_store = 0;
	int enable_auto_update = (store->conf.ocsp_update_mode == SSL_SOCK_OCSP_UPDATE_ON) ||
	                         (store->conf.ocsp_update_mode == SSL_SOCK_OCSP_UPDATE_DFLT &&
	                          global_ssl.ocsp_update.mode == SSL_SOCK_OCSP_UPDATE_ON);

	x = data->cert;
	if (!x)
		goto out;

	ssl_ocsp_get_uri_from_cert(x, ocsp_uri, &err);
	if (!data->ocsp_response && !data->ocsp_cid) {
		/* In case of ocsp update mode set to 'on', this function might
		 * be called with no known ocsp response. If no ocsp uri can be
		 * found in the certificate, nothing needs to be done here. */
		if (!enable_auto_update || b_data(ocsp_uri) == 0) {
			ret = 0;
			goto out;
		}
	}

	issuer = data->ocsp_issuer;
	/* take issuer from chain over ocsp_issuer, is what is done historicaly */
	if (chain) {
		/* check if one of the certificate of the chain is the issuer */
		for (i = 0; i < sk_X509_num(chain); i++) {
			X509 *ti = sk_X509_value(chain, i);
			if (X509_check_issued(ti, x) == X509_V_OK) {
				issuer = ti;
				break;
			}
		}
	}
	if (!issuer)
		goto out;

	if (!data->ocsp_cid) {
		data->ocsp_cid = OCSP_cert_to_id(0, x, issuer);
		inc_refcount_store = 1;
	}
	if (!data->ocsp_cid)
		goto out;

	i = i2d_OCSP_CERTID(data->ocsp_cid, NULL);
	if (!i || (i > OCSP_MAX_CERTID_ASN1_LENGTH))
		goto out;

	path_len = strlen(path);
	ocsp = calloc(1, sizeof(*ocsp) + path_len + 1);
	if (!ocsp)
		goto out;

	p = ocsp->key_data;
	ocsp->key_length = i2d_OCSP_CERTID(data->ocsp_cid, &p);

	HA_SPIN_LOCK(OCSP_LOCK, &ocsp_tree_lock);
	iocsp = (struct certificate_ocsp *)ebmb_insert(&cert_ocsp_tree, &ocsp->key, OCSP_MAX_CERTID_ASN1_LENGTH);
	if (iocsp == ocsp)
		ocsp = NULL;

	SSL_CTX_get_tlsext_status_cb(ctx, &callback);

	if (inc_refcount_store)
		iocsp->refcount_store++;

	if (!callback) {
		struct ocsp_cbk_arg *cb_arg;
		EVP_PKEY *pkey;

		cb_arg = calloc(1, sizeof(*cb_arg));
		if (!cb_arg) {
			HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);
			goto out;
		}

		cb_arg->is_single = 1;
		cb_arg->s_ocsp = iocsp;
		iocsp->refcount++;

		pkey = X509_get_pubkey(x);
		cb_arg->single_kt = EVP_PKEY_base_id(pkey);
		EVP_PKEY_free(pkey);

		SSL_CTX_set_tlsext_status_cb(ctx, ssl_sock_ocsp_stapling_cbk);
		SSL_CTX_set_ex_data(ctx, ocsp_ex_index, cb_arg); /* we use the ex_data instead of the cb_arg function here, so we can use the cleanup callback to free */

	} else {
		/*
		 * If the ctx has a status CB, then we have previously set an OCSP staple for this ctx
		 * Update that cb_arg with the new cert's staple
		 */
		struct ocsp_cbk_arg *cb_arg;
		struct certificate_ocsp *tmp_ocsp;
		int index;
		int key_type;
		EVP_PKEY *pkey;

		cb_arg = SSL_CTX_get_ex_data(ctx, ocsp_ex_index);

		/*
		 * The following few lines will convert cb_arg from a single ocsp to multi ocsp
		 * the order of operations below matter, take care when changing it
		 */
		tmp_ocsp = cb_arg->s_ocsp;
		index = ssl_sock_get_ocsp_arg_kt_index(cb_arg->single_kt);
		cb_arg->s_ocsp = NULL;
		cb_arg->m_ocsp[index] = tmp_ocsp;
		cb_arg->is_single = 0;
		cb_arg->single_kt = 0;

		pkey = X509_get_pubkey(x);
		key_type = EVP_PKEY_base_id(pkey);
		EVP_PKEY_free(pkey);

		index = ssl_sock_get_ocsp_arg_kt_index(key_type);
		if (index >= 0 && !cb_arg->m_ocsp[index]) {
			cb_arg->m_ocsp[index] = iocsp;
			iocsp->refcount++;
		}
	}
	HA_SPIN_UNLOCK(OCSP_LOCK, &ocsp_tree_lock);

	ret = 0;

	warn = NULL;
	if (data->ocsp_response && ssl_sock_load_ocsp_response(data->ocsp_response, iocsp, data->ocsp_cid, &warn)) {
		memprintf(&warn, "Loading: %s. Content will be ignored", warn ? warn : "failure");
		ha_warning("%s.\n", warn);
	}


	/* Do not insert the same certificate_ocsp structure in the
	 * update tree more than once. */
	if (!ocsp) {
		/* Issuer certificate is not included in the certificate
		 * chain, it will have to be treated separately during
		 * ocsp response validation. */
		if (issuer == data->ocsp_issuer) {
			iocsp->issuer = issuer;
			X509_up_ref(issuer);
		}
		if (data->chain)
			iocsp->chain = X509_chain_up_ref(data->chain);

		iocsp->uri = calloc(1, sizeof(*iocsp->uri));
		if (!chunk_dup(iocsp->uri, ocsp_uri)) {
			ha_free(&iocsp->uri);
			goto out;
		}

		/* Note: if we arrive here, ocsp==NULL because iocsp==ocsp
		 * after the ebmb_insert(), which indicates that we've
		 * just inserted this new node and that it's the one for
		 * which we previously allocated enough room for path_len+1
		 * chars.
		 */
		memcpy(iocsp->path, path, path_len + 1);

		if (enable_auto_update) {
			ssl_ocsp_update_insert(iocsp);
			/* If we are during init the update task is not
			 * scheduled yet so a wakeup won't do anything.
			 * Otherwise, if the OCSP was added through the CLI, we
			 * wake the task up to manage the case of a new entry
			 * that needs to be updated before the previous first
			 * entry.
			 */
			if (ocsp_update_task)
				task_wakeup(ocsp_update_task, TASK_WOKEN_MSG);
		}
	} else if (iocsp->uri && enable_auto_update) {
		/* This unlikely case can happen if a series of "del ssl
		 * crt-list" / "add ssl crt-list" commands are made on the CLI.
		 * In such a case, the OCSP response tree entry will be created
		 * prior to the activation of the ocsp auto update and in such a
		 * case we must "force" insertion in the auto update tree.
		 */
		if (iocsp->next_update.node.leaf_p == NULL) {
			ssl_ocsp_update_insert(iocsp);
			/* If we are during init the update task is not
			 * scheduled yet so a wakeup won't do anything.
			 * Otherwise, if the OCSP was added through the CLI, we
			 * wake the task up to manage the case of a new entry
			 * that needs to be updated before the previous first
			 * entry.
			 */
			if (ocsp_update_task)
				task_wakeup(ocsp_update_task, TASK_WOKEN_MSG);
		}
	}

out:
	if (ret && data->ocsp_cid) {
		OCSP_CERTID_free(data->ocsp_cid);
		data->ocsp_cid = NULL;
	}

	if (!ret && data->ocsp_response) {
		ha_free(&data->ocsp_response->area);
		ha_free(&data->ocsp_response);
	}

	if (ocsp)
		ssl_sock_free_ocsp(ocsp);

	if (warn)
		free(warn);

	free(err);

	return ret;
}

#endif

#ifdef OPENSSL_IS_BORINGSSL
static int ssl_sock_load_ocsp(const char *path, SSL_CTX *ctx, struct ckch_data *data, STACK_OF(X509) *chain)
{
	return SSL_CTX_set_ocsp_response(ctx, (const uint8_t *)ckch->ocsp_response->area, ckch->ocsp_response->data);
}
#endif


#ifdef HAVE_SSL_CTX_ADD_SERVER_CUSTOM_EXT

#define CT_EXTENSION_TYPE 18

int sctl_ex_index = -1;

int ssl_sock_sctl_add_cbk(SSL *ssl, unsigned ext_type, const unsigned char **out, size_t *outlen, int *al, void *add_arg)
{
	struct buffer *sctl = add_arg;

	*out = (unsigned char *) sctl->area;
	*outlen = sctl->data;

	return 1;
}

int ssl_sock_sctl_parse_cbk(SSL *s, unsigned int ext_type, const unsigned char *in, size_t inlen, int *al, void *parse_arg)
{
	return 1;
}

static int ssl_sock_load_sctl(SSL_CTX *ctx, struct buffer *sctl)
{
	int ret = -1;

	if (!SSL_CTX_add_server_custom_ext(ctx, CT_EXTENSION_TYPE, ssl_sock_sctl_add_cbk, NULL, sctl, ssl_sock_sctl_parse_cbk, NULL))
		goto out;

	SSL_CTX_set_ex_data(ctx, sctl_ex_index, sctl);

	ret = 0;

out:
	return ret;
}

#endif

void ssl_sock_infocbk(const SSL *ssl, int where, int ret)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
#ifdef USE_QUIC
	struct quic_conn *qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
#endif /* USE_QUIC */
	struct ssl_sock_ctx *ctx = NULL;

	BIO *write_bio;
	(void)ret; /* shut gcc stupid warning */

	if (conn)
		ctx = conn_get_ssl_sock_ctx(conn);
#ifdef USE_QUIC
	else if (qc)
		ctx = qc->xprt_ctx;
#endif /* USE_QUIC */

	if (!ctx) {
		/* must never happen */
		ABORT_NOW();
		return;
	}

#ifndef SSL_OP_NO_RENEGOTIATION
	/* Please note that BoringSSL defines this macro to zero so don't
	 * change this to #if and do not assign a default value to this macro!
	 */
	if (where & SSL_CB_HANDSHAKE_START) {
		/* Disable renegotiation (CVE-2009-3555) */
		if (conn && (conn->flags & (CO_FL_WAIT_L6_CONN | CO_FL_EARLY_SSL_HS | CO_FL_EARLY_DATA)) == 0) {
			conn->flags |= CO_FL_ERROR;
			conn->err_code = CO_ER_SSL_RENEG;
		}
	}
#endif

	if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
		if (!(ctx->xprt_st & SSL_SOCK_ST_FL_16K_WBFSIZE)) {
			/* Long certificate chains optimz
			   If write and read bios are different, we
			   consider that the buffering was activated,
                           so we rise the output buffer size from 4k
			   to 16k */
			write_bio = SSL_get_wbio(ssl);
			if (write_bio != SSL_get_rbio(ssl)) {
				BIO_set_write_buffer_size(write_bio, 16384);
				ctx->xprt_st |= SSL_SOCK_ST_FL_16K_WBFSIZE;
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
	struct ssl_sock_ctx *ctx = NULL;
	int err, depth;
	X509 *client_crt;
	STACK_OF(X509) *certs;
	struct bind_conf *bind_conf = NULL;
	struct quic_conn *qc = NULL;

	ssl = X509_STORE_CTX_get_ex_data(x_store, SSL_get_ex_data_X509_STORE_CTX_idx());
	conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	client_crt = SSL_get_ex_data(ssl, ssl_client_crt_ref_index);

	if (conn) {
		bind_conf = __objt_listener(conn->target)->bind_conf;
		ctx = __conn_get_ssl_sock_ctx(conn);
		TRACE_ENTER(SSL_EV_CONN_VFY_CB, conn);
	}
#ifdef USE_QUIC
	else {
		qc = SSL_get_ex_data(ssl, ssl_qc_app_data_index);
		BUG_ON(!qc); /* Must never happen */
		bind_conf = qc->li->bind_conf;
		ctx = qc->xprt_ctx;
	}
#endif

	BUG_ON(!ctx || !bind_conf);

	ctx->xprt_st |= SSL_SOCK_ST_FL_VERIFY_DONE;

	depth = X509_STORE_CTX_get_error_depth(x_store);
	err = X509_STORE_CTX_get_error(x_store);

	if (ok) { /* no errors */
		TRACE_LEAVE(SSL_EV_CONN_VFY_CB, conn);
		return ok;
	}

	/* Keep a reference to the client's certificate in order to be able to
	 * dump some fetches values in a log even when the verification process
	 * fails. */
	if (depth == 0) {
		X509_free(client_crt);
		client_crt = X509_STORE_CTX_get0_cert(x_store);
		if (client_crt) {
			X509_up_ref(client_crt);
			SSL_set_ex_data(ssl, ssl_client_crt_ref_index, client_crt);
		}
	}
	else {
		/* An error occurred on a CA certificate of the certificate
		 * chain, we might never call this verify callback on the client
		 * certificate's depth (which is 0) so we try to store the
		 * reference right now. */
		certs = X509_STORE_CTX_get1_chain(x_store);
		if (certs) {
			client_crt = sk_X509_value(certs, 0);
			if (client_crt) {
				X509_up_ref(client_crt);
				SSL_set_ex_data(ssl, ssl_client_crt_ref_index, client_crt);
			}
			sk_X509_pop_free(certs, X509_free);
		}
	}

	/* check if CA error needs to be ignored */
	if (depth > 0) {
		if (!SSL_SOCK_ST_TO_CA_ERROR(ctx->xprt_st)) {
			ctx->xprt_st |= SSL_SOCK_CA_ERROR_TO_ST(err);
			ctx->xprt_st |= SSL_SOCK_CAEDEPTH_TO_ST(depth);
		}

		if (err <= SSL_MAX_VFY_ERROR_CODE &&
		    cert_ignerr_bitfield_get(bind_conf->ca_ignerr_bitfield, err)) {
			TRACE_STATE("Ignored ca-related error", SSL_EV_CONN_VFY_CB, conn, ssl, NULL, &err);
			goto err_ignored;
		}

		/* TODO: for QUIC connection, this error code is lost */
		if (conn) {
			conn->err_code = CO_ER_SSL_CA_FAIL;
			TRACE_ERROR("Verify callback error (ca)", SSL_EV_CONN_VFY_CB|SSL_EV_CONN_ERR, conn, ssl, &conn->err_code, &err);
		}
		return 0;
	}

	if (!SSL_SOCK_ST_TO_CRTERROR(ctx->xprt_st))
		ctx->xprt_st |= SSL_SOCK_CRTERROR_TO_ST(err);

	/* check if certificate error needs to be ignored */
	if (err <= SSL_MAX_VFY_ERROR_CODE &&
	    cert_ignerr_bitfield_get(bind_conf->crt_ignerr_bitfield, err)) {
		TRACE_STATE("Ignored crt-related error", SSL_EV_CONN_VFY_CB, conn, ssl, NULL, &err);
		goto err_ignored;
	}

	/* TODO: for QUIC connection, this error code is lost */
	if (conn) {
		conn->err_code = CO_ER_SSL_CRT_FAIL;
		TRACE_ERROR("Verify callback error (crt)", SSL_EV_CONN_VFY_CB|SSL_EV_CONN_ERR, conn, ssl, &conn->err_code, &err);
	}
	return 0;

 err_ignored:
	ssl_sock_dump_errors(conn, qc);
	ERR_clear_error();
	TRACE_LEAVE(SSL_EV_CONN_VFY_CB, conn);
	return 1;
}

#ifdef TLS1_RT_HEARTBEAT
static void ssl_sock_parse_heartbeat(struct connection *conn, int write_p, int version,
                                     int content_type, const void *buf, size_t len,
                                     SSL *ssl)
{
	/* test heartbeat received (write_p is set to 0
	   for a received record) */
	if ((content_type == TLS1_RT_HEARTBEAT) && (write_p == 0)) {
		struct ssl_sock_ctx *ctx = __conn_get_ssl_sock_ctx(conn);
		const unsigned char *p = buf;
		unsigned int payload;

		ctx->xprt_st |= SSL_SOCK_RECV_HEARTBEAT;

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
	}
}
#endif

static void ssl_sock_parse_clienthello(struct connection *conn, int write_p, int version,
                                       int content_type, const void *buf, size_t len,
                                       SSL *ssl)
{
	struct ssl_capture *capture;
	uchar *msg;
	uchar *end;
	uchar *extensions_end;
	uchar *ec_start = NULL;
	uchar *ec_formats_start = NULL;
	uchar *supver_start = NULL;      /* supported_versions */
	uchar supver_len = 0;            /* supported_versions len */
	uchar *sigalgs_start = NULL;
	ushort sigalgs_len = 0;
	uchar *list_end;
	ushort protocol_version;
	ushort extension_id;
	ushort ec_len = 0;
	uchar ec_formats_len = 0;
	int offset = 0;
	int rec_len;

	/* This function is called for "from client" and "to server"
	 * connections. The combination of write_p == 0 and content_type == 22
	 * is only available during "from client" connection.
	 */

	/* "write_p" is set to 0 is the bytes are received messages,
	 * otherwise it is set to 1.
	 */
	if (write_p != 0)
		return;

	/* content_type contains the type of message received or sent
	 * according with the SSL/TLS protocol spec. This message is
	 * encoded with one byte. The value 256 (two bytes) is used
	 * for designing the SSL/TLS record layer. According with the
	 * rfc6101, the expected message (other than 256) are:
	 *  - change_cipher_spec(20)
	 *  - alert(21)
	 *  - handshake(22)
	 *  - application_data(23)
	 *  - (255)
	 * We are interessed by the handshake and specially the client
	 * hello.
	 */
	if (content_type != 22)
		return;

	/* The message length is at least 4 bytes, containing the
	 * message type and the message length.
	 */
	if (len < 4)
		return;

	/* First byte of the handshake message id the type of
	 * message. The known types are:
	 *  - hello_request(0)
	 *  - client_hello(1)
	 *  - server_hello(2)
	 *  - certificate(11)
	 *  - server_key_exchange (12)
	 *  - certificate_request(13)
	 *  - server_hello_done(14)
	 * We are interested by the client hello.
	 */
	msg = (unsigned char *)buf;
	if (msg[0] != 1)
		return;

	/* Next three bytes are the length of the message. The total length
	 * must be this decoded length + 4. If the length given as argument
	 * is not the same, we abort the protocol dissector.
	 */
	rec_len = (msg[1] << 16) + (msg[2] << 8) + msg[3];
	if (len < rec_len + 4)
		return;
	msg += 4;
	end = msg + rec_len;
	if (end < msg)
		return;

	/* Expect 2 bytes for protocol version
	 * (1 byte for major and 1 byte for minor)
	 */
	if (msg + 2 > end)
		return;
	protocol_version = (msg[0] << 8) + msg[1];
	msg += 2;

	/* Expect the random, composed by 4 bytes for the unix time and
	 * 28 bytes for unix payload. So we jump 4 + 28.
	 */
	msg += 4 + 28;
	if (msg > end)
		return;

	/* Next, is session id:
	 * if present, we have to jump by length + 1 for the size information
	 * if not present, we have to jump by 1 only
	 */
	if (msg[0] > 0)
		msg += msg[0];
	msg += 1;
	if (msg > end)
		return;

	/* Next two bytes are the ciphersuite length. */
	if (msg + 2 > end)
		return;
	rec_len = (msg[0] << 8) + msg[1];
	msg += 2;
	if (msg + rec_len > end || msg + rec_len < msg)
		return;

	capture = pool_zalloc(pool_head_ssl_capture);
	if (!capture)
		return;
	/* Compute the xxh64 of the ciphersuite. */
	capture->xxh64 = XXH64(msg, rec_len, 0);

	/* Capture the ciphersuite. */
	capture->ciphersuite_len = MIN(global_ssl.capture_buffer_size, rec_len);
	capture->ciphersuite_offset = 0;
	memcpy(capture->data, msg, capture->ciphersuite_len);
	msg += rec_len;
	offset += capture->ciphersuite_len;

	/* Initialize other data */
	capture->protocol_version = protocol_version;

	/* Next, compression methods:
	 * if present, we have to jump by length + 1 for the size information
	 * if not present, we have to jump by 1 only
	 */
	if (msg[0] > 0)
		msg += msg[0];
	msg += 1;
	if (msg > end)
		goto store_capture;

	/* We reached extensions */
	if (msg + 2 > end)
		goto store_capture;
	rec_len = (msg[0] << 8) + msg[1];
	msg += 2;
	if (msg + rec_len > end || msg + rec_len < msg)
		goto store_capture;
	extensions_end = msg + rec_len;
	capture->extensions_offset = offset;

	/* Parse each extension */
	while (msg + 4 < extensions_end) {
		/* Add 2 bytes of extension_id */
		if (global_ssl.capture_buffer_size >= offset + 2) {
			capture->data[offset++] = msg[0];
			capture->data[offset++] = msg[1];
			capture->extensions_len += 2;
		}
		else
			break;
		extension_id = (msg[0] << 8) + msg[1];
		/* Length of the extension */
		rec_len = (msg[2] << 8) + msg[3];

		/* Expect 2 bytes extension id + 2 bytes extension size */
		msg += 2 + 2;
		if (msg + rec_len > extensions_end || msg + rec_len < msg)
			goto store_capture;

		list_end = msg + rec_len; /* end of the current extension */
		/* TLS Extensions
		 * https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */
		switch (extension_id) {
		case 10:
			/* supported_groups(10)
			 * Elliptic Curves:
			 * https://www.rfc-editor.org/rfc/rfc8422.html
			 * https://www.rfc-editor.org/rfc/rfc7919.html */
			if (msg + 2 > list_end)
				goto store_capture;
			rec_len = (msg[0] << 8) + msg[1];
			msg += 2;

			if (msg + rec_len > list_end || msg + rec_len < msg)
				goto store_capture;
			/* Store location/size of the list */
			ec_start = msg;
			ec_len = rec_len;
			break;
		case 11:
			/* ec_point_formats(11)
			 * Elliptic Curves Point Formats:
			 * https://www.rfc-editor.org/rfc/rfc8422.html */
			if (msg + 1 > list_end)
				goto store_capture;
			rec_len = msg[0];
			msg += 1;

			if (msg + rec_len > list_end || msg + rec_len < msg)
				goto store_capture;
			/* Store location/size of the list */
			ec_formats_start = msg;
			ec_formats_len = rec_len;
			break;
		case 13:
			/* signature_algorithms(13)
			 * https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3 */
			if (msg + 2 > list_end)
				goto store_capture;
			rec_len = (msg[0] << 8) + msg[1];
			msg += 2;

			if (msg + rec_len > list_end || msg + rec_len < msg)
				goto store_capture;
			/* Store location/size of the list */
			sigalgs_start = msg;
			sigalgs_len = rec_len;
			break;
		case 43:
			/* supported_versions(43)
			 * https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1 */
			if (msg + 1 > list_end)
				goto store_capture;
			rec_len = msg[0];
			msg += 1;
			if (msg + rec_len > list_end || msg + rec_len < msg)
				goto store_capture;
			/* Store location/size of the list */
			supver_start = msg;
			supver_len = rec_len;
			break;
		default:
			break;
		}
		msg += rec_len;
	}

	if (ec_start) {
		rec_len = ec_len;
		if (offset + rec_len > global_ssl.capture_buffer_size)
			 rec_len = global_ssl.capture_buffer_size - offset;
		memcpy(capture->data + offset, ec_start, rec_len);
		capture->ec_offset = offset;
		capture->ec_len = rec_len;
		offset += rec_len;
	}
	if (ec_formats_start) {
		rec_len = ec_formats_len;
		if (offset + rec_len > global_ssl.capture_buffer_size)
			rec_len = global_ssl.capture_buffer_size - offset;
		memcpy(capture->data + offset, ec_formats_start, rec_len);
		capture->ec_formats_offset = offset;
		capture->ec_formats_len = rec_len;
		offset += rec_len;
	}
	if (supver_start) {
		rec_len = supver_len;
		if (offset + rec_len > global_ssl.capture_buffer_size)
			rec_len = global_ssl.capture_buffer_size - offset;
		memcpy(capture->data + offset, supver_start, rec_len);
		capture->supver_offset = offset;
		capture->supver_len = rec_len;
		offset += rec_len;
	}
	if (sigalgs_start) {
		rec_len = sigalgs_len;
		if (offset + rec_len > global_ssl.capture_buffer_size)
			rec_len = global_ssl.capture_buffer_size - offset;
		memcpy(capture->data + offset, sigalgs_start, rec_len);
		capture->sigalgs_offset = offset;
		capture->sigalgs_len = rec_len;
		offset += rec_len;
	}


 store_capture:
	SSL_set_ex_data(ssl, ssl_capture_ptr_index, capture);
}


#ifdef HAVE_SSL_KEYLOG
static void ssl_init_keylog(struct connection *conn, int write_p, int version,
                            int content_type, const void *buf, size_t len,
                            SSL *ssl)
{
	struct ssl_keylog *keylog;

	if (SSL_get_ex_data(ssl, ssl_keylog_index))
		return;

	keylog = pool_zalloc(pool_head_ssl_keylog);
	if (!keylog)
		return;

	if (!SSL_set_ex_data(ssl, ssl_keylog_index, keylog)) {
		pool_free(pool_head_ssl_keylog, keylog);
		return;
	}
}
#endif

/* Callback is called for ssl protocol analyse */
void ssl_sock_msgcbk(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct ssl_sock_msg_callback *cbk;

	/* Try to call all callback functions that were registered by using
	 * ssl_sock_register_msg_callback().
	 */
	list_for_each_entry(cbk, &ssl_sock_msg_callbacks, list) {
		cbk->func(conn, write_p, version, content_type, buf, len, ssl);
	}
}

#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
static int ssl_sock_srv_select_protos(SSL *s, unsigned char **out, unsigned char *outlen,
                                      const unsigned char *in, unsigned int inlen,
				      void *arg)
{
	struct server *srv = arg;

	if (SSL_select_next_proto(out, outlen, in, inlen, (unsigned char *)srv->ssl_ctx.npn_str,
	    srv->ssl_ctx.npn_len) == OPENSSL_NPN_NEGOTIATED)
		return SSL_TLSEXT_ERR_OK;
	return SSL_TLSEXT_ERR_NOACK;
}
#endif

#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
/* This callback is used so that the server advertises the list of
 * negotiable protocols for NPN.
 */
static int ssl_sock_advertise_npn_protos(SSL *s, const unsigned char **data,
                                         unsigned int *len, void *arg)
{
	struct ssl_bind_conf *conf = arg;

	*data = (const unsigned char *)conf->npn_str;
	*len = conf->npn_len;
	return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
/* This callback is used so that the server advertises the list of
 * negotiable protocols for ALPN.
 */
static int ssl_sock_advertise_alpn_protos(SSL *s, const unsigned char **out,
                                          unsigned char *outlen,
                                          const unsigned char *server,
                                          unsigned int server_len, void *arg)
{
	struct ssl_bind_conf *conf = arg;
#ifdef USE_QUIC
	struct quic_conn *qc = SSL_get_ex_data(s, ssl_qc_app_data_index);
#endif

	if (SSL_select_next_proto((unsigned char**) out, outlen, (const unsigned char *)conf->alpn_str,
	                          conf->alpn_len, server, server_len) != OPENSSL_NPN_NEGOTIATED) {
#ifdef USE_QUIC
		if (qc)
			quic_set_tls_alert(qc, SSL_AD_NO_APPLICATION_PROTOCOL);
#endif
		return SSL_TLSEXT_ERR_NOACK;
	}

#ifdef USE_QUIC
	if (qc && !quic_set_app_ops(qc, *out, *outlen)) {
		quic_set_tls_alert(qc, SSL_AD_NO_APPLICATION_PROTOCOL);
		return SSL_TLSEXT_ERR_NOACK;
	}
#endif

	return SSL_TLSEXT_ERR_OK;
}
#endif

#if (HA_OPENSSL_VERSION_NUMBER < 0x1010000fL)

static void ctx_set_SSLv3_func(SSL_CTX *ctx, set_context_func c)
{
#if SSL_OP_NO_SSLv3
	c == SET_SERVER ? SSL_CTX_set_ssl_version(ctx, SSLv3_server_method())
		: SSL_CTX_set_ssl_version(ctx, SSLv3_client_method());
#endif
}
static void ctx_set_TLSv10_func(SSL_CTX *ctx, set_context_func c) {
	c == SET_SERVER ? SSL_CTX_set_ssl_version(ctx, TLSv1_server_method())
		: SSL_CTX_set_ssl_version(ctx, TLSv1_client_method());
}
static void ctx_set_TLSv11_func(SSL_CTX *ctx, set_context_func c) {
#if SSL_OP_NO_TLSv1_1
	c == SET_SERVER ? SSL_CTX_set_ssl_version(ctx, TLSv1_1_server_method())
		: SSL_CTX_set_ssl_version(ctx, TLSv1_1_client_method());
#endif
}
static void ctx_set_TLSv12_func(SSL_CTX *ctx, set_context_func c) {
#if SSL_OP_NO_TLSv1_2
	c == SET_SERVER ? SSL_CTX_set_ssl_version(ctx, TLSv1_2_server_method())
		: SSL_CTX_set_ssl_version(ctx, TLSv1_2_client_method());
#endif
}
/* TLSv1.2 is the last supported version in this context. */
static void ctx_set_TLSv13_func(SSL_CTX *ctx, set_context_func c) {}
/* Unusable in this context. */
static void ssl_set_SSLv3_func(SSL *ssl, set_context_func c) {}
static void ssl_set_TLSv10_func(SSL *ssl, set_context_func c) {}
static void ssl_set_TLSv11_func(SSL *ssl, set_context_func c) {}
static void ssl_set_TLSv12_func(SSL *ssl, set_context_func c) {}
static void ssl_set_TLSv13_func(SSL *ssl, set_context_func c) {}
#else /* openssl >= 1.1.0 */

static void ctx_set_SSLv3_func(SSL_CTX *ctx, set_context_func c) {
	c == SET_MAX ? SSL_CTX_set_max_proto_version(ctx, SSL3_VERSION)
		: SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
}
static void ssl_set_SSLv3_func(SSL *ssl, set_context_func c) {
	c == SET_MAX ? SSL_set_max_proto_version(ssl, SSL3_VERSION)
		: SSL_set_min_proto_version(ssl, SSL3_VERSION);
}
static void ctx_set_TLSv10_func(SSL_CTX *ctx, set_context_func c) {
	c == SET_MAX ? SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION)
		: SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
}
static void ssl_set_TLSv10_func(SSL *ssl, set_context_func c) {
	c == SET_MAX ? SSL_set_max_proto_version(ssl, TLS1_VERSION)
		: SSL_set_min_proto_version(ssl, TLS1_VERSION);
}
static void ctx_set_TLSv11_func(SSL_CTX *ctx, set_context_func c) {
	c == SET_MAX ? SSL_CTX_set_max_proto_version(ctx, TLS1_1_VERSION)
		: SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
}
static void ssl_set_TLSv11_func(SSL *ssl, set_context_func c) {
	c == SET_MAX ? SSL_set_max_proto_version(ssl, TLS1_1_VERSION)
		: SSL_set_min_proto_version(ssl, TLS1_1_VERSION);
}
static void ctx_set_TLSv12_func(SSL_CTX *ctx, set_context_func c) {
	c == SET_MAX ? SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)
		: SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}
static void ssl_set_TLSv12_func(SSL *ssl, set_context_func c) {
	c == SET_MAX ? SSL_set_max_proto_version(ssl, TLS1_2_VERSION)
		: SSL_set_min_proto_version(ssl, TLS1_2_VERSION);
}
static void ctx_set_TLSv13_func(SSL_CTX *ctx, set_context_func c) {
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	c == SET_MAX ? SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)
		: SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
#endif
}
static void ssl_set_TLSv13_func(SSL *ssl, set_context_func c) {
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	c == SET_MAX ? SSL_set_max_proto_version(ssl, TLS1_3_VERSION)
		: SSL_set_min_proto_version(ssl, TLS1_3_VERSION);
#endif
}
#endif
static void ctx_set_None_func(SSL_CTX *ctx, set_context_func c) { }
static void ssl_set_None_func(SSL *ssl, set_context_func c) { }

struct methodVersions methodVersions[] = {
	{0, 0, ctx_set_None_func, ssl_set_None_func, "NONE"},   /* CONF_TLSV_NONE */
	{SSL_OP_NO_SSLv3,   MC_SSL_O_NO_SSLV3,  ctx_set_SSLv3_func, ssl_set_SSLv3_func, "SSLv3"},    /* CONF_SSLV3 */
	{SSL_OP_NO_TLSv1,   MC_SSL_O_NO_TLSV10, ctx_set_TLSv10_func, ssl_set_TLSv10_func, "TLSv1.0"}, /* CONF_TLSV10 */
	{SSL_OP_NO_TLSv1_1, MC_SSL_O_NO_TLSV11, ctx_set_TLSv11_func, ssl_set_TLSv11_func, "TLSv1.1"}, /* CONF_TLSV11 */
	{SSL_OP_NO_TLSv1_2, MC_SSL_O_NO_TLSV12, ctx_set_TLSv12_func, ssl_set_TLSv12_func, "TLSv1.2"}, /* CONF_TLSV12 */
	{SSL_OP_NO_TLSv1_3, MC_SSL_O_NO_TLSV13, ctx_set_TLSv13_func, ssl_set_TLSv13_func, "TLSv1.3"}, /* CONF_TLSV13 */
};

#ifndef OPENSSL_NO_DH

static inline HASSL_DH *ssl_new_dh_fromdata(BIGNUM *p, BIGNUM *g)
{
#if (HA_OPENSSL_VERSION_NUMBER >= 0x3000000fL)
	OSSL_PARAM_BLD *tmpl = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;

	if ((tmpl = OSSL_PARAM_BLD_new()) == NULL
	    || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, p)
	    || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, g)
	    || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
		goto end;
	}
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (ctx == NULL
	    || !EVP_PKEY_fromdata_init(ctx)
	    || !EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params)) {
		goto end;
	}

end:
	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(tmpl);
	BN_free(p);
	BN_free(g);
	return pkey;
#else

	HASSL_DH *dh = DH_new();

	if (!dh)
		return NULL;

	DH_set0_pqg(dh, p, NULL, g);

	return dh;
#endif
}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
static inline HASSL_DH *ssl_get_dh_by_nid(int nid)
{
#if (HA_OPENSSL_VERSION_NUMBER >= 0x3000000fL)
	OSSL_PARAM params[2];
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	const char *named_group = NULL;

	if (!pctx)
		goto end;

	named_group = OBJ_nid2ln(nid);

	if (!named_group)
		goto end;

	params[0] = OSSL_PARAM_construct_utf8_string("group", (char*)named_group, 0);
	params[1] = OSSL_PARAM_construct_end();

	if (EVP_PKEY_keygen_init(pctx) && EVP_PKEY_CTX_set_params(pctx, params))
		EVP_PKEY_generate(pctx, &pkey);

end:
	EVP_PKEY_CTX_free(pctx);
	return pkey;
#else

	HASSL_DH *dh = NULL;
	dh = DH_new_by_nid(nid);
	return dh;
#endif
}
#endif


static HASSL_DH * ssl_get_dh_1024(void)
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

	BIGNUM *p;
	BIGNUM *g;

	HASSL_DH *dh = NULL;

	p = BN_bin2bn(dh1024_p, sizeof dh1024_p, NULL);
	g = BN_bin2bn(dh1024_g, sizeof dh1024_g, NULL);

	if (p && g)
		dh = ssl_new_dh_fromdata(p, g);

	return dh;
}

static HASSL_DH *ssl_get_dh_2048(void)
{
#if (HA_OPENSSL_VERSION_NUMBER < 0x10101000L)
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

	BIGNUM *p;
	BIGNUM *g;

	HASSL_DH *dh = NULL;

	p = BN_bin2bn(dh2048_p, sizeof dh2048_p, NULL);
	g = BN_bin2bn(dh2048_g, sizeof dh2048_g, NULL);

	if (p && g)
		dh = ssl_new_dh_fromdata(p, g);

	return dh;
#else
	return ssl_get_dh_by_nid(NID_ffdhe2048);
#endif
}

static HASSL_DH *ssl_get_dh_4096(void)
{
#if (HA_OPENSSL_VERSION_NUMBER < 0x10101000L)
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

	BIGNUM *p;
	BIGNUM *g;

	HASSL_DH *dh = NULL;

	p = BN_bin2bn(dh4096_p, sizeof dh4096_p, NULL);
	g = BN_bin2bn(dh4096_g, sizeof dh4096_g, NULL);

	if (p && g)
		dh = ssl_new_dh_fromdata(p, g);

	return dh;
#else
	return ssl_get_dh_by_nid(NID_ffdhe4096);
#endif
}

static HASSL_DH *ssl_get_tmp_dh(EVP_PKEY *pkey)
{
	HASSL_DH *dh = NULL;
	int type;
	int keylen = 0;

	type = pkey ? EVP_PKEY_base_id(pkey) : EVP_PKEY_NONE;

	if (type == EVP_PKEY_EC) {
		keylen = global_ssl.default_dh_param;
	}

	/* The keylen supplied by OpenSSL can only be 512 or 1024.
	   See ssl3_send_server_key_exchange() in ssl/s3_srvr.c
	 */
	if (type == EVP_PKEY_RSA || type == EVP_PKEY_DSA) {
		keylen = EVP_PKEY_bits(pkey);
	}

	if (keylen > global_ssl.default_dh_param) {
		keylen = global_ssl.default_dh_param;
	}

	if (keylen >= 4096) {
		if (!local_dh_4096)
			local_dh_4096 = ssl_get_dh_4096();
		dh = local_dh_4096;
	}
	else if (keylen >= 2048) {
		if (!local_dh_2048)
			local_dh_2048 = ssl_get_dh_2048();
		dh = local_dh_2048;
	}
	else {
		if (!local_dh_1024)
			local_dh_1024 = ssl_get_dh_1024();
		dh = local_dh_1024;
	}

	return dh;
}

#if (HA_OPENSSL_VERSION_NUMBER < 0x3000000fL)
/* Returns Diffie-Hellman parameters matching the private key length
   but not exceeding global_ssl.default_dh_param */
HASSL_DH *ssl_get_tmp_dh_cbk(SSL *ssl, int export, int keylen)
{
	EVP_PKEY *pkey = SSL_get_privatekey(ssl);

	return ssl_get_tmp_dh(pkey);
}
#endif

static int ssl_sock_set_tmp_dh(SSL_CTX *ctx, HASSL_DH *dh)
{
#if (HA_OPENSSL_VERSION_NUMBER < 0x3000000fL)
	return SSL_CTX_set_tmp_dh(ctx, dh);
#else
	int retval = 0;
	HASSL_DH_up_ref(dh);

	retval = SSL_CTX_set0_tmp_dh_pkey(ctx, dh);

	if (!retval)
		HASSL_DH_free(dh);

	return retval;
#endif
}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x3000000fL)
void ssl_sock_set_tmp_dh_from_pkey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
	HASSL_DH *dh = NULL;
	if (pkey && (dh = ssl_get_tmp_dh(pkey))) {
		HASSL_DH_up_ref(dh);
		if (!SSL_CTX_set0_tmp_dh_pkey(ctx, dh))
			HASSL_DH_free(dh);
	}
}
#endif

HASSL_DH *ssl_sock_get_dh_from_bio(BIO *bio)
{
#if (HA_OPENSSL_VERSION_NUMBER >= 0x3000000fL)
	HASSL_DH *dh = NULL;
	OSSL_DECODER_CTX *dctx = NULL;
	const char *format = "PEM";
	const char *keytype = "DH";

	dctx = OSSL_DECODER_CTX_new_for_pkey(&dh, format, NULL, keytype,
					     OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
					     NULL, NULL);

	if (dctx == NULL || OSSL_DECODER_CTX_get_num_decoders(dctx) == 0)
		goto end;

	/* The DH parameters might not be the first section found in the PEM
	 * file so we need to iterate over all of them until we find the right
	 * one.
	 */
	while (!BIO_eof(bio) && !dh)
		OSSL_DECODER_from_bio(dctx, bio);

end:
	OSSL_DECODER_CTX_free(dctx);
	return dh;
#else
	HASSL_DH *dh = NULL;

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);

	return dh;
#endif
}

static HASSL_DH * ssl_sock_get_dh_from_file(const char *filename)
{
	HASSL_DH *dh = NULL;
	BIO *in = BIO_new(BIO_s_file());

	if (in == NULL)
		goto end;

	if (BIO_read_filename(in, filename) <= 0)
		goto end;

	dh = ssl_sock_get_dh_from_bio(in);

end:
        if (in)
                BIO_free(in);

	ERR_clear_error();

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
#endif

/* This function allocates a sni_ctx and adds it to the ckch_inst */
static int ckch_inst_add_cert_sni(SSL_CTX *ctx, struct ckch_inst *ckch_inst,
                                 struct bind_conf *s, struct ssl_bind_conf *conf,
                                 struct pkey_info kinfo, char *name, int order)
{
	struct sni_ctx *sc;
	int wild = 0, neg = 0, default_crt = 0;

	if (*name == '!') {
		neg = 1;
		name++;
	}
	if (*name == '*') {
		wild = 1;
		name++;
		/* if this was only a '*' filter, this is a default cert */
		if (!*name)
			default_crt = 1;
	}
	/* !* filter is a nop */
	if (neg && wild) {
		if (*name)
			ha_warning("parsing [%s:%d]: crt-list: Unsupported exclusion (!) on a wildcard filter \"!*%s\"\n", s->file, s->line, name);
		return order;
	}
	if (*name || default_crt) {
		int j, len;
		len = strlen(name);
		for (j = 0; j < len && j < trash.size; j++)
			trash.area[j] = tolower((unsigned char)name[j]);
		if (j >= trash.size)
			return -1;
		trash.area[j] = 0;

		sc = malloc(sizeof(struct sni_ctx) + len + 1);
		if (!sc)
			return -1;
		memcpy(sc->name.key, trash.area, len + 1);
		SSL_CTX_up_ref(ctx);
		sc->ctx = ctx;
		sc->conf = conf;
		sc->kinfo = kinfo;
		sc->order = order++;
		sc->neg = neg;
		sc->wild = wild;
		sc->name.node.leaf_p = NULL;
		sc->ckch_inst = ckch_inst;
		LIST_APPEND(&ckch_inst->sni_ctx, &sc->by_ckch_inst);
	}
	return order;
}

/*
 * Insert the sni_ctxs that are listed in the ckch_inst, in the bind_conf's sni_ctx tree
 * This function can't return an error.
 *
 * *CAUTION*: The caller must lock the sni tree if called in multithreading mode
 */
void ssl_sock_load_cert_sni(struct ckch_inst *ckch_inst, struct bind_conf *bind_conf)
{

	struct sni_ctx *sc0, *sc0b, *sc1;
	struct ebmb_node *node;
	int nb_neg = 0, nb_wild = 0;

	list_for_each_entry_safe(sc0, sc0b, &ckch_inst->sni_ctx, by_ckch_inst) {

		/* ignore if sc0 was already inserted in a tree */
		if (sc0->name.node.leaf_p)
			continue;

		/* Check for duplicates. */
		if (sc0->wild)
			node = ebst_lookup(&bind_conf->sni_w_ctx, (char *)sc0->name.key);
		else
			node = ebst_lookup(&bind_conf->sni_ctx, (char *)sc0->name.key);

		for (; node; node = ebmb_next_dup(node)) {
			sc1 = ebmb_entry(node, struct sni_ctx, name);
			if (sc1->ctx == sc0->ctx && sc1->conf == sc0->conf
			    && sc1->neg == sc0->neg && sc1->wild == sc0->wild) {
				/* it's a duplicate, we should remove and free it */
				LIST_DELETE(&sc0->by_ckch_inst);
				SSL_CTX_free(sc0->ctx);
				ha_free(&sc0);
				break;
			}
		}

		/* if duplicate, ignore the insertion */
		if (!sc0)
			continue;

		if (sc0->wild && sc0->name.key[0]) /* count wildcard but exclude the default */
			nb_wild++;
		if (sc0->neg)
			nb_neg++;

		if (sc0->wild)
			ebst_insert(&bind_conf->sni_w_ctx, &sc0->name);
		else
			ebst_insert(&bind_conf->sni_ctx, &sc0->name);
	}

	if (nb_neg > 0 && nb_wild == 0) {
		ha_warning("parsing [%s:%d]: crt-list: negative filters on crt-list line \"%s\" without a positive wildcard filter won't do anything!\n", bind_conf->file, bind_conf->line, ckch_inst->ckch_store->node.key);
	}

}

/*
 * tree used to store the ckchs ordered by filename/bundle name
 */
struct eb_root ckchs_tree = EB_ROOT_UNIQUE;

/* tree of crtlist (crt-list/directory) */
struct eb_root crtlists_tree = EB_ROOT_UNIQUE;

/* Loads Diffie-Hellman parameter from a ckchs to an SSL_CTX.
 *  If there is no DH parameter available in the ckchs, the global
 *  DH parameter is loaded into the SSL_CTX and if there is no
 *  DH parameter available in ckchs nor in global, the default
 *  DH parameters are applied on the SSL_CTX.
 * Returns a bitfield containing the flags:
 *     ERR_FATAL in any fatal error case
 *     ERR_ALERT if a reason of the error is availabine in err
 *     ERR_WARN if a warning is available into err
 * The value 0 means there is no error nor warning and
 * the operation succeed.
 */
#ifndef OPENSSL_NO_DH
static int ssl_sock_load_dh_params(SSL_CTX *ctx, const struct ckch_data *data,
                                   const char *path, char **err)
{
	int ret = 0;
	HASSL_DH *dh = NULL;

	if (data && data->dh) {
		dh = data->dh;
		if (!ssl_sock_set_tmp_dh(ctx, dh)) {
			memprintf(err, "%sunable to load the DH parameter specified in '%s'",
				  err && *err ? *err : "", path);
			memprintf(err, "%s, DH ciphers won't be available.\n",
				  err && *err ? *err : "");
			ret |= ERR_WARN;
			goto end;
		}

		if (ssl_dh_ptr_index >= 0) {
			/* store a pointer to the DH params to avoid complaining about
			   ssl-default-dh-param not being set for this SSL_CTX */
			SSL_CTX_set_ex_data(ctx, ssl_dh_ptr_index, dh);
		}
	}
	else if (global_dh) {
		if (!ssl_sock_set_tmp_dh(ctx, global_dh)) {
			memprintf(err, "%sunable to use the global DH parameter for certificate '%s'",
				  err && *err ? *err : "", path);
			memprintf(err, "%s, DH ciphers won't be available.\n",
				  err && *err ? *err : "");
			ret |= ERR_WARN;
			goto end;
		}
	}
	else {
		/* Clear openssl global errors stack */
		ERR_clear_error();

		/* We do not want DHE ciphers to be added to the cipher list
		 * unless there is an explicit global dh option in the conf.
		 */
		if (global_ssl.default_dh_param) {
			if (global_ssl.default_dh_param <= 1024) {
				/* we are limited to DH parameter of 1024 bits anyway */
				if (local_dh_1024 == NULL)
					local_dh_1024 = ssl_get_dh_1024();

				if (local_dh_1024 == NULL) {
					memprintf(err, "%sunable to load default 1024 bits DH parameter for certificate '%s'.\n",
						  err && *err ? *err : "", path);
					ret |= ERR_ALERT | ERR_FATAL;
					goto end;
				}

				if (!ssl_sock_set_tmp_dh(ctx, local_dh_1024)) {
					memprintf(err, "%sunable to load default 1024 bits DH parameter for certificate '%s'.\n",
						  err && *err ? *err : "", path);
					memprintf(err, "%s, DH ciphers won't be available.\n",
						  err && *err ? *err : "");
					ret |= ERR_WARN;
					goto end;
				}
			}
			else {
#ifndef OPENSSL_NO_DH
#if (HA_OPENSSL_VERSION_NUMBER < 0x3000000fL)
				SSL_CTX_set_tmp_dh_callback(ctx, ssl_get_tmp_dh_cbk);
#else
				ssl_sock_set_tmp_dh_from_pkey(ctx, data ? data->key : NULL);
#endif
#endif
			}
		}
	}

end:
	ERR_clear_error();
	return ret;
}
#endif


/* Load a certificate chain into an SSL context.
 * Returns a bitfield containing the flags:
 *     ERR_FATAL in any fatal error case
 *     ERR_ALERT if the reason of the error is available in err
 *     ERR_WARN if a warning is available into err
 * The caller is responsible of freeing the newly built or newly refcounted
 * find_chain element.
 * The value 0 means there is no error nor warning and
 * the operation succeed.
 */
static int ssl_sock_load_cert_chain(const char *path, const struct ckch_data *data,
				    SSL_CTX *ctx, STACK_OF(X509) **find_chain, char **err)
{
	int errcode = 0;
	int ret;

	ERR_clear_error();

	if (find_chain == NULL) {
		errcode |= ERR_FATAL;
		goto end;
	}

	if (!SSL_CTX_use_certificate(ctx, data->cert)) {
		ret = ERR_get_error();
		memprintf(err, "%sunable to load SSL certificate into SSL Context '%s': %s.\n",
				err && *err ? *err : "", path, ERR_reason_error_string(ret));
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	if (data->chain) {
		*find_chain = X509_chain_up_ref(data->chain);
	}

	if (!*find_chain) {
		/* always put a null chain stack in the SSL_CTX so it does not
		 * try to build the chain from the verify store */
		*find_chain = sk_X509_new_null();
	}

	/* Load all certs in the data into the ctx_chain for the ssl_ctx */
#ifdef SSL_CTX_set1_chain
	if (!SSL_CTX_set1_chain(ctx, *find_chain)) {
		ret = ERR_get_error();
		memprintf(err, "%sunable to load chain certificate into SSL Context '%s': %s.\n",
			  err && *err ? *err : "", path,  ERR_reason_error_string(ret));
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}
#else
	{ /* legacy compat (< openssl 1.0.2) */
		X509 *ca;
		while ((ca = sk_X509_shift(*find_chain)))
			if (!SSL_CTX_add_extra_chain_cert(ctx, ca)) {
				memprintf(err, "%sunable to load chain certificate into SSL Context '%s'.\n",
					  err && *err ? *err : "", path);
				X509_free(ca);
				errcode |= ERR_ALERT | ERR_FATAL;
				goto end;
			}
	}
#endif

#ifdef SSL_CTX_build_cert_chain
	/* remove the Root CA from the SSL_CTX if the option is activated */
	if (global_ssl.skip_self_issued_ca) {
		if (!SSL_CTX_build_cert_chain(ctx, SSL_BUILD_CHAIN_FLAG_NO_ROOT|SSL_BUILD_CHAIN_FLAG_UNTRUSTED|SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR)) {
			memprintf(err, "%sunable to load chain certificate into SSL Context '%s'.\n",
				  err && *err ? *err : "", path);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
	}
#endif

end:
	return errcode;
}


/* Loads the info in ckch into ctx
 * Returns a bitfield containing the flags:
 *     ERR_FATAL in any fatal error case
 *     ERR_ALERT if the reason of the error is available in err
 *     ERR_WARN if a warning is available into err
 * The value 0 means there is no error nor warning and
 * the operation succeed.
 */
static int ssl_sock_put_ckch_into_ctx(const char *path, struct ckch_store *store, SSL_CTX *ctx, char **err)
{
	int errcode = 0;
	struct ckch_data *data = store->data;
	STACK_OF(X509) *find_chain = NULL;

	ERR_clear_error();

	if (SSL_CTX_use_PrivateKey(ctx, data->key) <= 0) {
		int ret;

		ret = ERR_get_error();
		memprintf(err, "%sunable to load SSL private key into SSL Context '%s': %s.\n",
				err && *err ? *err : "", path, ERR_reason_error_string(ret));
		errcode |= ERR_ALERT | ERR_FATAL;
		return errcode;
	}

	/* Load certificate chain */
	errcode |= ssl_sock_load_cert_chain(path, data, ctx, &find_chain, err);
	if (errcode & ERR_CODE)
		goto end;

#ifndef OPENSSL_NO_DH
	/* store a NULL pointer to indicate we have not yet loaded
	   a custom DH param file */
	if (ssl_dh_ptr_index >= 0) {
		SSL_CTX_set_ex_data(ctx, ssl_dh_ptr_index, NULL);
	}

	errcode |= ssl_sock_load_dh_params(ctx, data, path, err);
	if (errcode & ERR_CODE) {
		memprintf(err, "%sunable to load DH parameters from file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}
#endif

#ifdef HAVE_SSL_CTX_ADD_SERVER_CUSTOM_EXT
	if (sctl_ex_index >= 0 && data->sctl) {
		if (ssl_sock_load_sctl(ctx, data->sctl) < 0) {
			memprintf(err, "%s '%s.sctl' is present but cannot be read or parsed'.\n",
			          err && *err ? *err : "", path);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
	}
#endif

#if defined(HAVE_SSL_OCSP)
	/* Load OCSP Info into context
	 * If OCSP update mode is set to 'on', an entry will be created in the
	 * ocsp tree even if no ocsp_response was known during init, unless the
	 * frontend's conf disables ocsp update explicitly.
	 */
	if (ssl_sock_load_ocsp(path, ctx, store, find_chain) < 0) {
		if (data->ocsp_response)
			memprintf(err, "%s '%s.ocsp' is present and activates OCSP but it is impossible to compute the OCSP certificate ID (maybe the issuer could not be found)'.\n",
				  err && *err ? *err : "", path);
		else
			memprintf(err, "%s '%s' has an OCSP auto-update set to 'on' but an error occurred (maybe the OCSP URI or the issuer could not be found)'.\n",
				  err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}
#endif

 end:
	sk_X509_pop_free(find_chain, X509_free);
	return errcode;
}


/* Loads the info of a ckch built out of a backend certificate into an SSL ctx
 * Returns a bitfield containing the flags:
 *     ERR_FATAL in any fatal error case
 *     ERR_ALERT if the reason of the error is available in err
 *     ERR_WARN if a warning is available into err
 * The value 0 means there is no error nor warning and
 * the operation succeed.
 */
static int ssl_sock_put_srv_ckch_into_ctx(const char *path, const struct ckch_data *data,
					  SSL_CTX *ctx, char **err)
{
	int errcode = 0;
	STACK_OF(X509) *find_chain = NULL;

	/* Load the private key */
	if (SSL_CTX_use_PrivateKey(ctx, data->key) <= 0) {
		memprintf(err, "%sunable to load SSL private key into SSL Context '%s'.\n",
				err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
	}

	/* Load certificate chain */
	errcode |= ssl_sock_load_cert_chain(path, data, ctx, &find_chain, err);
	if (errcode & ERR_CODE)
		goto end;

	if (SSL_CTX_check_private_key(ctx) <= 0) {
		memprintf(err, "%sinconsistencies between private key and certificate loaded from PEM file '%s'.\n",
			  err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
	}

end:
	sk_X509_pop_free(find_chain, X509_free);
	return errcode;
}


/*
 * This function allocate a ckch_inst and create its snis
 *
 * Returns a bitfield containing the flags:
 *     ERR_FATAL in any fatal error case
 *     ERR_ALERT if the reason of the error is available in err
 *     ERR_WARN if a warning is available into err
 */
int ckch_inst_new_load_store(const char *path, struct ckch_store *ckchs, struct bind_conf *bind_conf,
                                    struct ssl_bind_conf *ssl_conf, char **sni_filter, int fcount, int is_default, struct ckch_inst **ckchi, char **err)
{
	SSL_CTX *ctx;
	int i;
	int order = 0;
	X509_NAME *xname;
	char *str;
	EVP_PKEY *pkey;
	struct pkey_info kinfo = { .sig = TLSEXT_signature_anonymous, .bits = 0 };
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	STACK_OF(GENERAL_NAME) *names;
#endif
	struct ckch_data *data;
	struct ckch_inst *ckch_inst = NULL;
	int errcode = 0;

	*ckchi = NULL;

	if (!ckchs || !ckchs->data)
		return ERR_FATAL;

	data = ckchs->data;

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		memprintf(err, "%sunable to allocate SSL context for cert '%s'.\n",
		          err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto error;
	}

	if (global_ssl.security_level > -1)
		SSL_CTX_set_security_level(ctx, global_ssl.security_level);

	errcode |= ssl_sock_put_ckch_into_ctx(path, ckchs, ctx, err);
	if (errcode & ERR_CODE)
		goto error;

	ckch_inst = ckch_inst_new();
	if (!ckch_inst) {
		memprintf(err, "%sunable to allocate SSL context for cert '%s'.\n",
		          err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto error;
	}

	pkey = X509_get_pubkey(data->cert);
	if (pkey) {
		kinfo.bits = EVP_PKEY_bits(pkey);
		switch(EVP_PKEY_base_id(pkey)) {
		case EVP_PKEY_RSA:
			kinfo.sig = TLSEXT_signature_rsa;
			break;
		case EVP_PKEY_EC:
			kinfo.sig = TLSEXT_signature_ecdsa;
			break;
		case EVP_PKEY_DSA:
			kinfo.sig = TLSEXT_signature_dsa;
			break;
		}
		EVP_PKEY_free(pkey);
	}

	if (fcount) {
		while (fcount--) {
			order = ckch_inst_add_cert_sni(ctx, ckch_inst, bind_conf, ssl_conf, kinfo, sni_filter[fcount], order);
			if (order < 0) {
				memprintf(err, "%sunable to create a sni context.\n", err && *err ? *err : "");
				errcode |= ERR_ALERT | ERR_FATAL;
				goto error;
			}
		}
	}
	else {
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
		names = X509_get_ext_d2i(data->cert, NID_subject_alt_name, NULL, NULL);
		if (names) {
			for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
				GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
				if (name->type == GEN_DNS) {
					if (ASN1_STRING_to_UTF8((unsigned char **)&str, name->d.dNSName) >= 0) {
						order = ckch_inst_add_cert_sni(ctx, ckch_inst, bind_conf, ssl_conf, kinfo, str, order);
						OPENSSL_free(str);
						if (order < 0) {
							memprintf(err, "%sunable to create a sni context.\n", err && *err ? *err : "");
							errcode |= ERR_ALERT | ERR_FATAL;
							goto error;
						}
					}
				}
			}
			sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
		}
#endif /* SSL_CTRL_SET_TLSEXT_HOSTNAME */
		xname = X509_get_subject_name(data->cert);
		i = -1;
		while ((i = X509_NAME_get_index_by_NID(xname, NID_commonName, i)) != -1) {
			X509_NAME_ENTRY *entry = X509_NAME_get_entry(xname, i);
			ASN1_STRING *value;

			value = X509_NAME_ENTRY_get_data(entry);
			if (ASN1_STRING_to_UTF8((unsigned char **)&str, value) >= 0) {
				order = ckch_inst_add_cert_sni(ctx, ckch_inst, bind_conf, ssl_conf, kinfo, str, order);
				OPENSSL_free(str);
				if (order < 0) {
					memprintf(err, "%sunable to create a sni context.\n", err && *err ? *err : "");
					errcode |= ERR_ALERT | ERR_FATAL;
					goto error;
				}
			}
		}
	}
	/* we must not free the SSL_CTX anymore below, since it's already in
	 * the tree, so it will be discovered and cleaned in time.
	 */

	if (is_default) {
		ckch_inst->is_default = 1;

		/* insert an empty SNI which will be used to lookup default certificate */
		order = ckch_inst_add_cert_sni(ctx, ckch_inst, bind_conf, ssl_conf, kinfo, "*", order);
		if (order < 0) {
			memprintf(err, "%sunable to create a sni context.\n", err && *err ? *err : "");
			errcode |= ERR_ALERT | ERR_FATAL;
			goto error;
		}
	}

	/* Always keep a reference to the newly constructed SSL_CTX in the
	 * instance. This way if the instance has no SNIs, the SSL_CTX will
	 * still be linked. */
	SSL_CTX_up_ref(ctx);
	ckch_inst->ctx = ctx;

	/* everything succeed, the ckch instance can be used */
	ckch_inst->bind_conf = bind_conf;
	ckch_inst->ssl_conf = ssl_conf;
	ckch_inst->ckch_store = ckchs;

	SSL_CTX_free(ctx); /* we need to free the ctx since we incremented the refcount where it's used */

	*ckchi = ckch_inst;
	return errcode;

error:
	/* free the allocated sni_ctxs */
	if (ckch_inst) {
		ckch_inst_free(ckch_inst);
		ckch_inst = NULL;
	}
	SSL_CTX_free(ctx);

	return errcode;
}


/*
 * This function allocate a ckch_inst that will be used on the backend side
 * (server line)
 *
 * Returns a bitfield containing the flags:
 *     ERR_FATAL in any fatal error case
 *     ERR_ALERT if the reason of the error is available in err
 *     ERR_WARN if a warning is available into err
 */
int ckch_inst_new_load_srv_store(const char *path, struct ckch_store *ckchs,
				 struct ckch_inst **ckchi, char **err)
{
	SSL_CTX *ctx;
	struct ckch_data *data;
	struct ckch_inst *ckch_inst = NULL;
	int errcode = 0;

	*ckchi = NULL;

	if (!ckchs || !ckchs->data)
		return ERR_FATAL;

	data = ckchs->data;

	ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ctx) {
		memprintf(err, "%sunable to allocate SSL context for cert '%s'.\n",
		          err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto error;
	}

	if (global_ssl.security_level > -1)
		SSL_CTX_set_security_level(ctx, global_ssl.security_level);

	errcode |= ssl_sock_put_srv_ckch_into_ctx(path, data, ctx, err);
	if (errcode & ERR_CODE)
		goto error;

	ckch_inst = ckch_inst_new();
	if (!ckch_inst) {
		memprintf(err, "%sunable to allocate SSL context for cert '%s'.\n",
		          err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto error;
	}

	/* everything succeed, the ckch instance can be used */
	ckch_inst->bind_conf = NULL;
	ckch_inst->ssl_conf = NULL;
	ckch_inst->ckch_store = ckchs;
	ckch_inst->ctx = ctx;
	ckch_inst->is_server_instance = 1;

	*ckchi = ckch_inst;
	return errcode;

error:
	SSL_CTX_free(ctx);

	return errcode;
}

/* Returns a set of ERR_* flags possibly with an error in <err>. */
static int ssl_sock_load_ckchs(const char *path, struct ckch_store *ckchs,
                               struct bind_conf *bind_conf, struct ssl_bind_conf *ssl_conf,
                               char **sni_filter, int fcount,
                               int is_default,
                               struct ckch_inst **ckch_inst, char **err)
{
	int errcode = 0;

	/* we found the ckchs in the tree, we can use it directly */
	errcode |= ckch_inst_new_load_store(path, ckchs, bind_conf, ssl_conf, sni_filter, fcount, is_default, ckch_inst, err);

	if (errcode & ERR_CODE)
		return errcode;

	ssl_sock_load_cert_sni(*ckch_inst, bind_conf);

	/* succeed, add the instance to the ckch_store's list of instance */
	LIST_APPEND(&ckchs->ckch_inst, &((*ckch_inst)->by_ckchs));
	return errcode;
}

/* This function generates a <struct ckch_inst *> for a <struct server *>, and
 * fill the SSL_CTX of the server.
 *
 * Returns a set of ERR_* flags possibly with an error in <err>. */
static int ssl_sock_load_srv_ckchs(const char *path, struct ckch_store *ckchs,
				   struct server *server, struct ckch_inst **ckch_inst, char **err)
{
	int errcode = 0;

	/* we found the ckchs in the tree, we can use it directly */
	errcode |= ckch_inst_new_load_srv_store(path, ckchs, ckch_inst, err);

	if (errcode & ERR_CODE)
		return errcode;

	(*ckch_inst)->server = server;
	/* Keep the reference to the SSL_CTX in the server. */
	SSL_CTX_up_ref((*ckch_inst)->ctx);
	server->ssl_ctx.ctx = (*ckch_inst)->ctx;
	/* succeed, add the instance to the ckch_store's list of instance */
	LIST_APPEND(&ckchs->ckch_inst, &((*ckch_inst)->by_ckchs));
	return errcode;
}




/* Make sure openssl opens /dev/urandom before the chroot. The work is only
 * done once. Zero is returned if the operation fails. No error is returned
 * if the random is said as not implemented, because we expect that openssl
 * will use another method once needed.
 */
int ssl_initialize_random(void)
{
	unsigned char random;
	static int random_initialized = 0;

	if (!random_initialized && RAND_bytes(&random, 1) != 0)
		random_initialized = 1;

	return random_initialized;
}

/*  Load a crt-list file, this is done in 2 parts:
 *  - store the content of the file in a crtlist structure with crtlist_entry structures
 *  - generate the instances by iterating on entries in the crtlist struct
 *
 *  Nothing is locked there, this function is used in the configuration parser.
 *
 *  Returns a set of ERR_* flags possibly with an error in <err>.
 */
int ssl_sock_load_cert_list_file(char *file, int dir, struct bind_conf *bind_conf, struct proxy *curproxy, char **err)
{
	struct crtlist *crtlist = NULL;
	struct ebmb_node *eb;
	struct crtlist_entry *entry = NULL;
	struct bind_conf_list *bind_conf_node = NULL;
	int cfgerr = 0;
	char *end;

	bind_conf_node = malloc(sizeof(*bind_conf_node));
	if (!bind_conf_node) {
		memprintf(err, "%sCan't alloc memory!\n", err && *err ? *err : "");
		cfgerr |= ERR_FATAL | ERR_ALERT;
		goto error;
	}
	bind_conf_node->next = NULL;
	bind_conf_node->bind_conf = bind_conf;

	/* strip trailing slashes, including first one */
	for (end = file + strlen(file) - 1; end >= file && *end == '/'; end--)
		*end = 0;

	/* look for an existing crtlist or create one */
	eb = ebst_lookup(&crtlists_tree, file);
	if (eb) {
		crtlist = ebmb_entry(eb, struct crtlist, node);
	} else {
		/* load a crt-list OR a directory */
		if (dir)
			cfgerr |= crtlist_load_cert_dir(file, bind_conf, &crtlist, err);
		else
			cfgerr |= crtlist_parse_file(file, bind_conf, curproxy, &crtlist, err);

		if (!(cfgerr & ERR_CODE))
			ebst_insert(&crtlists_tree, &crtlist->node);
	}

	if (cfgerr & ERR_CODE) {
		cfgerr |= ERR_FATAL | ERR_ALERT;
		goto error;
	}

	/* generates ckch instance from the crtlist_entry */
	list_for_each_entry(entry, &crtlist->ord_entries, by_crtlist) {
		struct ckch_store *store;
		struct ckch_inst *ckch_inst = NULL;
		int is_default = 0;

		store = entry->node.key;

		/* if the SNI trees were empty the first "crt" become a default certificate,
		 * it can be applied on multiple certificates if it's a bundle */
		if (eb_is_empty(&bind_conf->sni_ctx) && eb_is_empty(&bind_conf->sni_w_ctx))
			is_default = 1;


		cfgerr |= ssl_sock_load_ckchs(store->path, store, bind_conf, entry->ssl_conf, entry->filters, entry->fcount, is_default, &ckch_inst, err);
		if (cfgerr & ERR_CODE) {
			memprintf(err, "error processing line %d in file '%s' : %s", entry->linenum, file, *err);
			goto error;
		}
		LIST_APPEND(&entry->ckch_inst, &ckch_inst->by_crtlist_entry);
		ckch_inst->crtlist_entry = entry;
	}

	/* add the bind_conf to the list */
	bind_conf_node->next = crtlist->bind_conf;
	crtlist->bind_conf = bind_conf_node;

	return cfgerr;
error:
	{
		struct crtlist_entry *lastentry;
		struct ckch_inst *inst, *s_inst;

		lastentry = entry; /* which entry we tried to generate last */
		if (lastentry) {
			list_for_each_entry(entry, &crtlist->ord_entries, by_crtlist) {
				if (entry == lastentry) /* last entry we tried to generate, no need to go further */
					break;

				list_for_each_entry_safe(inst, s_inst, &entry->ckch_inst, by_crtlist_entry) {

					/* this was not generated for this bind_conf, skip */
					if (inst->bind_conf != bind_conf)
						continue;

					/* free the sni_ctx and instance */
					ckch_inst_free(inst);
				}
			}
		}
		free(bind_conf_node);
	}
	return cfgerr;
}

/* Returns a set of ERR_* flags possibly with an error in <err>. */
int ssl_sock_load_cert(char *path, struct bind_conf *bind_conf, int is_default, char **err)
{
	struct stat buf;
	int cfgerr = 0;
	struct ckch_store *ckchs;
	struct ckch_inst *ckch_inst = NULL;
	int found = 0; /* did we found a file to load ? */

	/* if the SNI trees were empty the first "crt" become a default certificate,
	 * it can be applied on multiple certificates if it's a bundle */
	if (is_default == 0) {
		if (eb_is_empty(&bind_conf->sni_ctx) && eb_is_empty(&bind_conf->sni_w_ctx))
			is_default = 1;
	}

	if ((ckchs = ckchs_lookup(path))) {

		cfgerr |= ckch_conf_cmp_empty(&ckchs->conf, err);
		if (cfgerr & ERR_CODE) {
			memprintf(err, "Can't load '%s', is already defined with incompatible parameters:\n %s", path, err ? *err : "");
			return cfgerr;
		}

		/* we found the ckchs in the tree, we can use it directly */
		 cfgerr |= ssl_sock_load_ckchs(path, ckchs, bind_conf, NULL, NULL, 0, is_default, &ckch_inst, err);

		 found++;
	} else if (stat(path, &buf) == 0) {
		found++;
		if (S_ISDIR(buf.st_mode) == 0) {
			ckchs = ckch_store_new_load_files_path(path, err);
			if (!ckchs)
				cfgerr |= ERR_ALERT | ERR_FATAL;
			cfgerr |= ssl_sock_load_ckchs(path, ckchs, bind_conf, NULL, NULL, 0, is_default, &ckch_inst, err);
		} else {
			cfgerr |= ssl_sock_load_cert_list_file(path, 1, bind_conf, bind_conf->frontend, err);
		}
	} else {
		/* stat failed, could be a bundle */
		if (global_ssl.extra_files & SSL_GF_BUNDLE) {
			char fp[MAXPATHLEN+1] = {0};
			int n = 0;

			/* Load all possible certs and keys in separate ckch_store */
			for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++) {
				struct stat buf;
				int ret;

				ret = snprintf(fp, sizeof(fp), "%s.%s", path, SSL_SOCK_KEYTYPE_NAMES[n]);
				if (ret > sizeof(fp))
					continue;

				if ((ckchs = ckchs_lookup(fp))) {
					cfgerr |= ssl_sock_load_ckchs(fp, ckchs, bind_conf, NULL, NULL, 0, is_default, &ckch_inst, err);
					found++;
				} else {
					if (stat(fp, &buf) == 0) {
						found++;
						ckchs =  ckch_store_new_load_files_path(fp, err);
						if (!ckchs)
							cfgerr |= ERR_ALERT | ERR_FATAL;
						cfgerr |= ssl_sock_load_ckchs(fp, ckchs, bind_conf, NULL, NULL, 0, is_default, &ckch_inst, err);
					}
				}
			}
#if HA_OPENSSL_VERSION_NUMBER < 0x10101000L
			if (found) {
				memprintf(err, "%sCan't load '%s'. Loading a multi certificates bundle requires OpenSSL >= 1.1.1\n",
				          err && *err ? *err : "", path);
				cfgerr |= ERR_ALERT | ERR_FATAL;
			}
#endif
		}
	}
	if (!found) {
		memprintf(err, "%sunable to stat SSL certificate from file '%s' : %s.\n",
		          err && *err ? *err : "", path, strerror(errno));
		cfgerr |= ERR_ALERT | ERR_FATAL;
	}

	return cfgerr;
}


/* Create a full ssl context and ckch instance that will be used for a specific
 * backend server (server configuration line).
 * Returns a set of ERR_* flags possibly with an error in <err>.
 */
int ssl_sock_load_srv_cert(char *path, struct server *server, int create_if_none, char **err)
{
	struct stat buf;
	int cfgerr = 0;
	struct ckch_store *ckchs;
	int found = 0; /* did we found a file to load ? */

	if ((ckchs = ckchs_lookup(path))) {
		/* we found the ckchs in the tree, we can use it directly */
		 cfgerr |= ssl_sock_load_srv_ckchs(path, ckchs, server, &server->ssl_ctx.inst, err);
		 found++;
	} else {
		if (!create_if_none) {
			memprintf(err, "%sunable to stat SSL certificate '%s'.\n",
			          err && *err ? *err : "", path);
			cfgerr |= ERR_ALERT | ERR_FATAL;
			goto out;
		}

		if (stat(path, &buf) == 0) {
			/* We do not manage directories on backend side. */
			if (S_ISDIR(buf.st_mode) == 0) {
				++found;
				ckchs = ckch_store_new_load_files_path(path, err);
				if (!ckchs)
					cfgerr |= ERR_ALERT | ERR_FATAL;
				cfgerr |= ssl_sock_load_srv_ckchs(path, ckchs, server, &server->ssl_ctx.inst, err);
			}
		}
	}
	if (!found) {
		memprintf(err, "%sunable to stat SSL certificate from file '%s' : %s.\n",
		          err && *err ? *err : "", path, strerror(errno));
		cfgerr |= ERR_ALERT | ERR_FATAL;
	}

out:
	return cfgerr;
}

/* Create an initial CTX used to start the SSL connection before switchctx */
static int
ssl_sock_initial_ctx(struct bind_conf *bind_conf)
{
	SSL_CTX *ctx = NULL;
	long options =
		SSL_OP_ALL | /* all known workarounds for bugs */
		SSL_OP_NO_SSLv2 |
		SSL_OP_NO_COMPRESSION |
		SSL_OP_SINGLE_DH_USE |
		SSL_OP_SINGLE_ECDH_USE |
		SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
		SSL_OP_PRIORITIZE_CHACHA |
		SSL_OP_CIPHER_SERVER_PREFERENCE;
	long mode =
		SSL_MODE_ENABLE_PARTIAL_WRITE |
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
		SSL_MODE_RELEASE_BUFFERS |
		SSL_MODE_SMALL_BUFFERS;
	struct tls_version_filter *conf_ssl_methods = &bind_conf->ssl_conf.ssl_methods;
	int i, min, max, hole;
	int flags = MC_SSL_O_ALL;
	int cfgerr = 0;
	const int default_min_ver = CONF_TLSV12;

	ctx = SSL_CTX_new(SSLv23_server_method());
	bind_conf->initial_ctx = ctx;

	if (global_ssl.security_level > -1)
		SSL_CTX_set_security_level(ctx, global_ssl.security_level);

	if (conf_ssl_methods->flags && (conf_ssl_methods->min || conf_ssl_methods->max))
		ha_warning("Proxy '%s': no-sslv3/no-tlsv1x are ignored for bind '%s' at [%s:%d]. "
			   "Use only 'ssl-min-ver' and 'ssl-max-ver' to fix.\n",
			   bind_conf->frontend->id, bind_conf->arg, bind_conf->file, bind_conf->line);
	else
		flags = conf_ssl_methods->flags;

	min = conf_ssl_methods->min;
	max = conf_ssl_methods->max;

	/* default minimum is TLSV12,  */
	if (!min) {
		if (!max || (max >= default_min_ver)) {
			min = default_min_ver;
		} else {
			ha_warning("Proxy '%s': Ambiguous configuration for bind '%s' at [%s:%d]: the ssl-min-ver value is not configured and the ssl-max-ver value is lower than the default ssl-min-ver value (%s). "
			           "Setting the ssl-min-ver to %s. Use 'ssl-min-ver' to fix this.\n",
			           bind_conf->frontend->id, bind_conf->arg, bind_conf->file, bind_conf->line, methodVersions[default_min_ver].name, methodVersions[max].name);
			min = max;
		}
	}
	/* Real min and max should be determinate with configuration and openssl's capabilities */
	if (min)
		flags |= (methodVersions[min].flag - 1);
	if (max)
		flags |= ~((methodVersions[max].flag << 1) - 1);
	/* find min, max and holes */
	min = max = CONF_TLSV_NONE;
	hole = 0;
	for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++)
		/*  version is in openssl && version not disable in configuration */
		if (methodVersions[i].option && !(flags & methodVersions[i].flag)) {
			if (min) {
				if (hole) {
					ha_warning("Proxy '%s': SSL/TLS versions range not contiguous for bind '%s' at [%s:%d]. "
						   "Hole find for %s. Use only 'ssl-min-ver' and 'ssl-max-ver' to fix.\n",
						   bind_conf->frontend->id, bind_conf->arg, bind_conf->file, bind_conf->line,
						   methodVersions[hole].name);
					hole = 0;
				}
				max = i;
			}
			else {
				min = max = i;
			}
		}
		else {
			if (min)
				hole = i;
		}
	if (!min) {
		ha_alert("Proxy '%s': all SSL/TLS versions are disabled for bind '%s' at [%s:%d].\n",
			 bind_conf->frontend->id, bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr += 1;
	}
	/* save real min/max in bind_conf */
	conf_ssl_methods->min = min;
	conf_ssl_methods->max = max;

#if (HA_OPENSSL_VERSION_NUMBER < 0x1010000fL)
	/* Keep force-xxx implementation as it is in older haproxy. It's a
	   precautionary measure to avoid any surprise with older openssl version. */
	if (min == max)
		methodVersions[min].ctx_set_version(ctx, SET_SERVER);
	else
		for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++) {
			/* clear every version flags in case SSL_CTX_new()
			 * returns an SSL_CTX with disabled versions */
			SSL_CTX_clear_options(ctx, methodVersions[i].option);

			if (flags & methodVersions[i].flag)
				options |= methodVersions[i].option;

		}
#else   /* openssl >= 1.1.0 */
	/* set the max_version is required to cap TLS version or activate new TLS (v1.3) */
        methodVersions[min].ctx_set_version(ctx, SET_MIN);
        methodVersions[max].ctx_set_version(ctx, SET_MAX);
#endif

	if (bind_conf->ssl_options & BC_SSL_O_NO_TLS_TICKETS)
		options |= SSL_OP_NO_TICKET;
	if (bind_conf->ssl_options & BC_SSL_O_PREF_CLIE_CIPH)
		options &= ~SSL_OP_CIPHER_SERVER_PREFERENCE;

#ifdef SSL_OP_NO_RENEGOTIATION
	options |= SSL_OP_NO_RENEGOTIATION;
#endif

	SSL_CTX_set_options(ctx, options);

#ifdef SSL_MODE_ASYNC
	if (global_ssl.async)
		mode |= SSL_MODE_ASYNC;
#endif
	SSL_CTX_set_mode(ctx, mode);
	if (global_ssl.life_time)
		SSL_CTX_set_timeout(ctx, global_ssl.life_time);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
# if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
	SSL_CTX_set_select_certificate_cb(ctx, ssl_sock_switchctx_cbk);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
	if (bind_conf->ssl_conf.early_data)
		SSL_CTX_set_early_data_enabled(ctx, 1);
# elif defined(HAVE_SSL_CLIENT_HELLO_CB)
#  if defined(SSL_OP_NO_ANTI_REPLAY)
	if (bind_conf->ssl_conf.early_data)
		SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
#  endif /* ! SSL_OP_NO_ANTI_REPLAY */
	SSL_CTX_set_client_hello_cb(ctx, ssl_sock_switchctx_cbk, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
# elif defined(USE_OPENSSL_WOLFSSL)
	SSL_CTX_set_cert_cb(ctx, ssl_sock_switchctx_wolfSSL_cbk, bind_conf);
# else
	/* ! OPENSSL_IS_BORINGSSL && ! HAVE_SSL_CLIENT_HELLO_CB */
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
# endif
	SSL_CTX_set_tlsext_servername_arg(ctx, bind_conf);
#endif /* ! SSL_CTRL_SET_TLSEXT_HOSTNAME */
	return cfgerr;
}


static inline void sh_ssl_sess_free_blocks(struct shared_block *first, void *data)
{
	struct sh_ssl_sess_hdr *sh_ssl_sess = (struct sh_ssl_sess_hdr *)first->data;
	if (first->len > 0)
		sh_ssl_sess_tree_delete(sh_ssl_sess);
}

/* return first block from sh_ssl_sess  */
static inline struct shared_block *sh_ssl_sess_first_block(struct sh_ssl_sess_hdr *sh_ssl_sess)
{
	return (struct shared_block *)((unsigned char *)sh_ssl_sess - offsetof(struct shared_block, data));

}

/* store a session into the cache
 * s_id : session id padded with zero to SSL_MAX_SSL_SESSION_ID_LENGTH
 * data: asn1 encoded session
 * data_len: asn1 encoded session length
 * Returns 1 id session was stored (else 0)
 */
static int sh_ssl_sess_store(unsigned char *s_id, unsigned char *data, int data_len)
{
	struct shared_block *first;
	struct sh_ssl_sess_hdr *sh_ssl_sess, *oldsh_ssl_sess;

	first = shctx_row_reserve_hot(ssl_shctx, NULL, data_len + sizeof(struct sh_ssl_sess_hdr));
	if (!first) {
		/* Could not retrieve enough free blocks to store that session */
		return 0;
	}

	shctx_wrlock(ssl_shctx);

	/* STORE the key in the first elem */
	sh_ssl_sess = (struct sh_ssl_sess_hdr *)first->data;
	memcpy(sh_ssl_sess->key_data, s_id, SSL_MAX_SSL_SESSION_ID_LENGTH);
	first->len = sizeof(struct sh_ssl_sess_hdr);

	/* it returns the already existing node
           or current node if none, never returns null */
	oldsh_ssl_sess = sh_ssl_sess_tree_insert(sh_ssl_sess);
	if (oldsh_ssl_sess != sh_ssl_sess) {
		 /* NOTE: Row couldn't be in use because we lock read & write function */
		/* release the reserved row */
		first->len = 0; /* the len must be liberated in order not to call the release callback on it */
		shctx_row_reattach(ssl_shctx, first);
		/* replace the previous session already in the tree */
		sh_ssl_sess = oldsh_ssl_sess;
		/* ignore the previous session data, only use the header */
		first = sh_ssl_sess_first_block(sh_ssl_sess);
		shctx_row_detach(ssl_shctx, first);
		first->len = sizeof(struct sh_ssl_sess_hdr);
	}

	if (shctx_row_data_append(ssl_shctx, first, data, data_len) < 0) {
		shctx_row_reattach(ssl_shctx, first);
		return 0;
	}

	shctx_row_reattach(ssl_shctx, first);

	shctx_wrunlock(ssl_shctx);

	return 1;
}

/* SSL callback used when a new session is created while connecting to a server */
static int ssl_sess_new_srv_cb(SSL *ssl, SSL_SESSION *sess)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct server *s;
	uint old_tid;

	s = __objt_server(conn->target);

	/* RWLOCK: only read lock the SSL cache even when writing in it because there is
	 * one cache per thread, it only prevents to flush it from the CLI in
	 * another thread. However, we also write-lock our session element while
	 * updating it to make sure no other thread is reading it while we're copying
	 * or releasing it.
	 */

	if (!(s->ssl_ctx.options & SRV_SSL_O_NO_REUSE)) {
		int len;
		unsigned char *ptr;
		const char *sni;

		/* determine the required len to store this new session */
		len = i2d_SSL_SESSION(sess, NULL);
		sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
		HA_RWLOCK_RDLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.lock);

		ptr = s->ssl_ctx.reused_sess[tid].ptr;

		/* we're updating the possibly shared session right now */
		HA_RWLOCK_WRLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.reused_sess[tid].sess_lock);

		if (!ptr || s->ssl_ctx.reused_sess[tid].allocated_size < len) {
			/* insufficient storage, reallocate */
			len = (len + 7) & -8; /* round to the nearest 8 bytes */
			ptr = realloc(ptr, len);
			if (!ptr)
				free(s->ssl_ctx.reused_sess[tid].ptr);
			s->ssl_ctx.reused_sess[tid].ptr = ptr;
			s->ssl_ctx.reused_sess[tid].allocated_size = len;
		}

		if (ptr) {
			/* store the new session into ptr and advance it; save the
			 * resulting size. It's guaranteed to be equal to the returned
			 * len above, and the pointer to be advanced by as much.
			 */
			s->ssl_ctx.reused_sess[tid].size = i2d_SSL_SESSION(sess, &ptr);
		}

		/* done updating the session */

		/* Now we'll try to add or remove this entry as a valid one:
		 *  - if no entry is set and we have one, let's share it
		 *  - if our entry was set and we have no more, let's clear it
		 */
		old_tid = HA_ATOMIC_LOAD(&s->ssl_ctx.last_ssl_sess_tid); // 0=none, >0 = tid + 1
		if (!s->ssl_ctx.reused_sess[tid].ptr && old_tid == tid + 1)
			HA_ATOMIC_CAS(&s->ssl_ctx.last_ssl_sess_tid, &old_tid, 0); // no more valid
		else if (s->ssl_ctx.reused_sess[tid].ptr && !old_tid)
			HA_ATOMIC_CAS(&s->ssl_ctx.last_ssl_sess_tid, &old_tid, tid + 1);

		if (s->ssl_ctx.reused_sess[tid].sni) {
			/* if the new sni is empty or isn' t the same as the old one */
			if ((!sni) || strcmp(s->ssl_ctx.reused_sess[tid].sni, sni) != 0) {
				ha_free(&s->ssl_ctx.reused_sess[tid].sni);
				if (sni)
					s->ssl_ctx.reused_sess[tid].sni = strdup(sni);
			}
		} else if (sni) {
			/* if there wasn't an old sni but there is a new one */
			s->ssl_ctx.reused_sess[tid].sni = strdup(sni);
		}
		HA_RWLOCK_WRUNLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.reused_sess[tid].sess_lock);
		HA_RWLOCK_RDUNLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.lock);
	} else {
		HA_RWLOCK_RDLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.lock);

		if (s->ssl_ctx.reused_sess[tid].ptr) {
			HA_RWLOCK_WRLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.reused_sess[tid].sess_lock);
			ha_free(&s->ssl_ctx.reused_sess[tid].ptr);
			HA_RWLOCK_WRUNLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.reused_sess[tid].sess_lock);
		}

		old_tid = HA_ATOMIC_LOAD(&s->ssl_ctx.last_ssl_sess_tid); // 0=none, >0 = tid + 1
		if (old_tid == tid + 1)
			HA_ATOMIC_CAS(&s->ssl_ctx.last_ssl_sess_tid, &old_tid, 0); // no more valid

		HA_RWLOCK_RDUNLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.lock);
	}

	return 0;
}


/* SSL callback used on new session creation */
int sh_ssl_sess_new_cb(SSL *ssl, SSL_SESSION *sess)
{
	unsigned char encsess[SHSESS_MAX_DATA_LEN];           /* encoded session  */
	unsigned char encid[SSL_MAX_SSL_SESSION_ID_LENGTH];   /* encoded id */
	unsigned char *p;
	int data_len;
	unsigned int sid_length;
	const unsigned char *sid_data;

	/* Session id is already stored in to key and session id is known
	 * so we don't store it to keep size.
	 * note: SSL_SESSION_set1_id is using
	 * a memcpy so we need to use a different pointer
	 * than sid_data or sid_ctx_data to avoid valgrind
	 * complaining.
	 */

	sid_data = SSL_SESSION_get_id(sess, &sid_length);

	/* copy value in an other buffer */
	memcpy(encid, sid_data, sid_length);

	/* pad with 0 */
	if (sid_length < SSL_MAX_SSL_SESSION_ID_LENGTH)
		memset(encid + sid_length, 0, SSL_MAX_SSL_SESSION_ID_LENGTH-sid_length);

	/* force length to zero to avoid ASN1 encoding */
	SSL_SESSION_set1_id(sess, encid, 0);

	/* force length to zero to avoid ASN1 encoding */
	SSL_SESSION_set1_id_context(sess, (const unsigned char *)SHCTX_APPNAME, 0);

	/* check if buffer is large enough for the ASN1 encoded session */
	data_len = i2d_SSL_SESSION(sess, NULL);
	if (data_len > SHSESS_MAX_DATA_LEN)
		goto err;

	p = encsess;

	/* process ASN1 session encoding before the lock */
	i2d_SSL_SESSION(sess, &p);


	/* store to cache */
	sh_ssl_sess_store(encid, encsess, data_len);
err:
	/* reset original length values */
	SSL_SESSION_set1_id(sess, encid, sid_length);
	SSL_SESSION_set1_id_context(sess, (const unsigned char *)SHCTX_APPNAME, strlen(SHCTX_APPNAME));

	return 0; /* do not increment session reference count */
}

/* SSL callback used on lookup an existing session cause none found in internal cache */
SSL_SESSION *sh_ssl_sess_get_cb(SSL *ssl, __OPENSSL_110_CONST__ unsigned char *key, int key_len, int *do_copy)
{
	struct sh_ssl_sess_hdr *sh_ssl_sess;
	unsigned char data[SHSESS_MAX_DATA_LEN], *p;
	unsigned char tmpkey[SSL_MAX_SSL_SESSION_ID_LENGTH];
	SSL_SESSION *sess;
	struct shared_block *first;

	_HA_ATOMIC_INC(&global.shctx_lookups);

	/* allow the session to be freed automatically by openssl */
	*do_copy = 0;

	/* tree key is zeros padded sessionid */
	if (key_len < SSL_MAX_SSL_SESSION_ID_LENGTH) {
		memcpy(tmpkey, key, key_len);
		memset(tmpkey + key_len, 0, SSL_MAX_SSL_SESSION_ID_LENGTH - key_len);
		key = tmpkey;
	}

	/* lock cache */
	shctx_wrlock(ssl_shctx);

	/* lookup for session */
	sh_ssl_sess = sh_ssl_sess_tree_lookup(key);
	if (!sh_ssl_sess) {
		/* no session found: unlock cache and exit */
		shctx_wrunlock(ssl_shctx);
		_HA_ATOMIC_INC(&global.shctx_misses);
		return NULL;
	}

	/* sh_ssl_sess (shared_block->data) is at the end of shared_block */
	first = sh_ssl_sess_first_block(sh_ssl_sess);

	shctx_row_data_get(ssl_shctx, first, data, sizeof(struct sh_ssl_sess_hdr), first->len-sizeof(struct sh_ssl_sess_hdr));

	shctx_wrunlock(ssl_shctx);

	/* decode ASN1 session */
	p = data;
	sess = d2i_SSL_SESSION(NULL, (const unsigned char **)&p, first->len-sizeof(struct sh_ssl_sess_hdr));
	/* Reset session id and session id contenxt */
	if (sess) {
		SSL_SESSION_set1_id(sess, key, key_len);
		SSL_SESSION_set1_id_context(sess, (const unsigned char *)SHCTX_APPNAME, strlen(SHCTX_APPNAME));
	}

	return sess;
}


/* SSL callback used to signal session is no more used in internal cache */
void sh_ssl_sess_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess)
{
	struct sh_ssl_sess_hdr *sh_ssl_sess;
	unsigned char tmpkey[SSL_MAX_SSL_SESSION_ID_LENGTH];
	unsigned int sid_length;
	const unsigned char *sid_data;
	(void)ctx;

	sid_data = SSL_SESSION_get_id(sess, &sid_length);
	/* tree key is zeros padded sessionid */
	if (sid_length < SSL_MAX_SSL_SESSION_ID_LENGTH) {
		memcpy(tmpkey, sid_data, sid_length);
		memset(tmpkey+sid_length, 0, SSL_MAX_SSL_SESSION_ID_LENGTH - sid_length);
		sid_data = tmpkey;
	}

	shctx_wrlock(ssl_shctx);

	/* lookup for session */
	sh_ssl_sess = sh_ssl_sess_tree_lookup(sid_data);
	if (sh_ssl_sess) {
		/* free session */
		sh_ssl_sess_tree_delete(sh_ssl_sess);
	}

	/* unlock cache */
	shctx_wrunlock(ssl_shctx);
}

/* Set session cache mode to server and disable openssl internal cache.
 * Set shared cache callbacks on an ssl context.
 * Shared context MUST be firstly initialized */
void ssl_set_shctx(SSL_CTX *ctx)
{
	SSL_CTX_set_session_id_context(ctx, (const unsigned char *)SHCTX_APPNAME, strlen(SHCTX_APPNAME));

	if (!ssl_shctx) {
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
		return;
	}

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER |
	                                    SSL_SESS_CACHE_NO_INTERNAL |
	                                    SSL_SESS_CACHE_NO_AUTO_CLEAR);

	/* Set callbacks */
	SSL_CTX_sess_set_new_cb(ctx, sh_ssl_sess_new_cb);
	SSL_CTX_sess_set_get_cb(ctx, sh_ssl_sess_get_cb);
	SSL_CTX_sess_set_remove_cb(ctx, sh_ssl_sess_remove_cb);
}

/*
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
 *
 * The format is:
 * * <Label> <space> <ClientRandom> <space> <Secret>
 * We only need to copy the secret as there is a sample fetch for the ClientRandom
 */

#ifdef HAVE_SSL_KEYLOG
void SSL_CTX_keylog(const SSL *ssl, const char *line)
{
	struct ssl_keylog *keylog;
	char *lastarg = NULL;
	char *dst = NULL;

#ifdef USE_QUIC_OPENSSL_COMPAT
	quic_tls_compat_keylog_callback(ssl, line);
#endif
	keylog = SSL_get_ex_data(ssl, ssl_keylog_index);
	if (!keylog)
		return;

	lastarg = strrchr(line, ' ');
	if (lastarg == NULL || ++lastarg == NULL)
		return;

	dst = pool_alloc(pool_head_ssl_keylog_str);
	if (!dst)
		return;

	strncpy(dst, lastarg, SSL_KEYLOG_MAX_SECRET_SIZE-1);
	dst[SSL_KEYLOG_MAX_SECRET_SIZE-1] = '\0';

	if (strncmp(line, "CLIENT_RANDOM ", strlen("CLIENT RANDOM ")) == 0) {
		if (keylog->client_random)
			goto error;
		keylog->client_random = dst;

	} else if (strncmp(line, "CLIENT_EARLY_TRAFFIC_SECRET ", strlen("CLIENT_EARLY_TRAFFIC_SECRET ")) == 0) {
		if (keylog->client_early_traffic_secret)
			goto error;
		keylog->client_early_traffic_secret = dst;

	} else if (strncmp(line, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ", strlen("CLIENT_HANDSHAKE_TRAFFIC_SECRET ")) == 0) {
		if(keylog->client_handshake_traffic_secret)
			goto error;
		keylog->client_handshake_traffic_secret = dst;

	} else if (strncmp(line, "SERVER_HANDSHAKE_TRAFFIC_SECRET ", strlen("SERVER_HANDSHAKE_TRAFFIC_SECRET ")) == 0) {
		if (keylog->server_handshake_traffic_secret)
			goto error;
		keylog->server_handshake_traffic_secret = dst;

	} else if (strncmp(line, "CLIENT_TRAFFIC_SECRET_0 ", strlen("CLIENT_TRAFFIC_SECRET_0 ")) == 0) {
		if (keylog->client_traffic_secret_0)
			goto error;
		keylog->client_traffic_secret_0 = dst;

	} else if (strncmp(line, "SERVER_TRAFFIC_SECRET_0 ", strlen("SERVER_TRAFFIC_SECRET_0 ")) == 0) {
		if (keylog->server_traffic_secret_0)
			goto error;
		keylog->server_traffic_secret_0 = dst;

	} else if (strncmp(line, "EARLY_EXPORTER_SECRET ", strlen("EARLY_EXPORTER_SECRET ")) == 0) {
		if (keylog->early_exporter_secret)
			goto error;
		keylog->early_exporter_secret = dst;

	} else if (strncmp(line, "EXPORTER_SECRET ", strlen("EXPORTER_SECRET ")) == 0) {
		if (keylog->exporter_secret)
			goto error;
		keylog->exporter_secret = dst;
	} else {
		goto error;
	}

	return;

error:
	pool_free(pool_head_ssl_keylog_str, dst);

	return;
}
#endif

/*
 * This function applies the SSL configuration on a SSL_CTX
 * It returns an error code and fills the <err> buffer
 */
static int ssl_sock_prepare_ctx(struct bind_conf *bind_conf, struct ssl_bind_conf *ssl_conf, SSL_CTX *ctx, char **err)
{
	struct proxy *curproxy = bind_conf->frontend;
	int cfgerr = 0;
	int verify = SSL_VERIFY_NONE;
	struct ssl_bind_conf __maybe_unused *ssl_conf_cur;
	const char *conf_ciphers;
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	const char *conf_ciphersuites;
#endif
	const char *conf_curves = NULL;
	X509_STORE *store = SSL_CTX_get_cert_store(ctx);
#if defined(SSL_CTX_set1_sigalgs_list)
	const char *conf_sigalgs = NULL;
#endif
#if defined(SSL_CTX_set1_client_sigalgs_list)
	const char *conf_client_sigalgs = NULL;
#endif

	if (ssl_conf) {
		struct tls_version_filter *conf_ssl_methods = &ssl_conf->ssl_methods;
		int i, min, max;
		int flags = MC_SSL_O_ALL;

		/* Real min and max should be determinate with configuration and openssl's capabilities */
		min = conf_ssl_methods->min ? conf_ssl_methods->min : bind_conf->ssl_conf.ssl_methods.min;
		max = conf_ssl_methods->max ? conf_ssl_methods->max : bind_conf->ssl_conf.ssl_methods.max;
		if (min)
			flags |= (methodVersions[min].flag - 1);
		if (max)
			flags |= ~((methodVersions[max].flag << 1) - 1);
		min = max = CONF_TLSV_NONE;
		for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++)
			if (methodVersions[i].option && !(flags & methodVersions[i].flag)) {
				if (min)
					max = i;
				else
					min = max = i;
			}
		/* save real min/max */
		conf_ssl_methods->min = min;
		conf_ssl_methods->max = max;
		if (!min) {
			memprintf(err, "%sProxy '%s': all SSL/TLS versions are disabled for bind '%s' at [%s:%d].\n",
			          err && *err ? *err : "", bind_conf->frontend->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr |= ERR_ALERT | ERR_FATAL;
		}
	}

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
	SSL_CTX_set_verify(ctx, verify, ssl_sock_bind_verifycbk);
	if (verify & SSL_VERIFY_PEER) {
		char *ca_file = (ssl_conf && ssl_conf->ca_file) ? ssl_conf->ca_file : bind_conf->ssl_conf.ca_file;
		char *ca_verify_file = (ssl_conf && ssl_conf->ca_verify_file) ? ssl_conf->ca_verify_file : bind_conf->ssl_conf.ca_verify_file;
		char *crl_file = (ssl_conf && ssl_conf->crl_file) ? ssl_conf->crl_file : bind_conf->ssl_conf.crl_file;
		if (ca_file || ca_verify_file) {
			/* set CAfile to verify */
			if (ca_file && !ssl_set_verify_locations_file(ctx, ca_file)) {
				memprintf(err, "%sProxy '%s': unable to set CA file '%s' for bind '%s' at [%s:%d].\n",
				          err && *err ? *err : "", curproxy->id, ca_file, bind_conf->arg, bind_conf->file, bind_conf->line);
				cfgerr |= ERR_ALERT | ERR_FATAL;
			}
			if (ca_verify_file && !ssl_set_verify_locations_file(ctx, ca_verify_file)) {
				memprintf(err, "%sProxy '%s': unable to set CA-no-names file '%s' for bind '%s' at [%s:%d].\n",
				          err && *err ? *err : "", curproxy->id, ca_verify_file, bind_conf->arg, bind_conf->file, bind_conf->line);
				cfgerr |= ERR_ALERT | ERR_FATAL;
			}
			if (ca_file && !((ssl_conf && ssl_conf->no_ca_names) || bind_conf->ssl_conf.no_ca_names)) {
				/* set CA names for client cert request, function returns void */
				SSL_CTX_set_client_CA_list(ctx, SSL_dup_CA_list(ssl_get_client_ca_file(ca_file)));
			}
#ifdef USE_OPENSSL_WOLFSSL
			/* WolfSSL activates CRL checks by default so we need to disable it */
			X509_STORE_set_flags(store, 0) ;
#endif
		}
		else {
			memprintf(err, "%sProxy '%s': verify is enabled but no CA file specified for bind '%s' at [%s:%d].\n",
			          err && *err ? *err : "", curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr |= ERR_ALERT | ERR_FATAL;
		}
#ifdef X509_V_FLAG_CRL_CHECK
		if (crl_file) {

			if (!ssl_set_cert_crl_file(store, crl_file)) {
				memprintf(err, "%sProxy '%s': unable to configure CRL file '%s' for bind '%s' at [%s:%d].\n",
				          err && *err ? *err : "", curproxy->id, crl_file, bind_conf->arg, bind_conf->file, bind_conf->line);
				cfgerr |= ERR_ALERT | ERR_FATAL;
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
		if (!SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, ssl_tlsext_ticket_key_cb)) {
			memprintf(err, "%sProxy '%s': unable to set callback for TLS ticket validation for bind '%s' at [%s:%d].\n",
			          err && *err ? *err : "", curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr |= ERR_ALERT | ERR_FATAL;
		}
	}
#endif

	ssl_set_shctx(ctx);
	conf_ciphers = (ssl_conf && ssl_conf->ciphers) ? ssl_conf->ciphers : bind_conf->ssl_conf.ciphers;
	if (conf_ciphers &&
	    !SSL_CTX_set_cipher_list(ctx, conf_ciphers)) {
		memprintf(err, "%sProxy '%s': unable to set SSL cipher list to '%s' for bind '%s' at [%s:%d].\n",
		          err && *err ? *err : "", curproxy->id, conf_ciphers, bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr |= ERR_ALERT | ERR_FATAL;
	}

#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	conf_ciphersuites = (ssl_conf && ssl_conf->ciphersuites) ? ssl_conf->ciphersuites : bind_conf->ssl_conf.ciphersuites;
	if (conf_ciphersuites &&
	    !SSL_CTX_set_ciphersuites(ctx, conf_ciphersuites)) {
		memprintf(err, "%sProxy '%s': unable to set TLS 1.3 cipher suites to '%s' for bind '%s' at [%s:%d].\n",
		          err && *err ? *err : "", curproxy->id, conf_ciphersuites, bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr |= ERR_ALERT | ERR_FATAL;
	}
#endif

#ifndef OPENSSL_NO_DH
	if (!local_dh_1024)
		local_dh_1024 = ssl_get_dh_1024();
	if (!local_dh_2048)
		local_dh_2048 = ssl_get_dh_2048();
	if (!local_dh_4096)
		local_dh_4096 = ssl_get_dh_4096();
#endif /* OPENSSL_NO_DH */

	SSL_CTX_set_info_callback(ctx, ssl_sock_infocbk);
#ifdef SSL_CTRL_SET_MSG_CALLBACK
	SSL_CTX_set_msg_callback(ctx, ssl_sock_msgcbk);
#endif
#ifdef HAVE_SSL_KEYLOG
	/* only activate the keylog callback if it was required to prevent performance loss */
	if (global_ssl.keylog > 0)
		SSL_CTX_set_keylog_callback(ctx, SSL_CTX_keylog);
#endif

#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	ssl_conf_cur = NULL;
	if (ssl_conf && ssl_conf->npn_str)
		ssl_conf_cur = ssl_conf;
	else if (bind_conf->ssl_conf.npn_str)
		ssl_conf_cur = &bind_conf->ssl_conf;
	if (ssl_conf_cur)
		SSL_CTX_set_next_protos_advertised_cb(ctx, ssl_sock_advertise_npn_protos, ssl_conf_cur);
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	ssl_conf_cur = NULL;
	if (ssl_conf && ssl_conf->alpn_str)
		ssl_conf_cur = ssl_conf;
	else if (bind_conf->ssl_conf.alpn_str)
		ssl_conf_cur = &bind_conf->ssl_conf;
	if (ssl_conf_cur && ssl_conf_cur->alpn_len)
		SSL_CTX_set_alpn_select_cb(ctx, ssl_sock_advertise_alpn_protos, ssl_conf_cur);
#endif
#if defined(SSL_CTX_set1_curves_list)
	conf_curves = (ssl_conf && ssl_conf->curves) ? ssl_conf->curves : bind_conf->ssl_conf.curves;
	if (conf_curves) {
		if (!SSL_CTX_set1_curves_list(ctx, conf_curves)) {
			memprintf(err, "%sProxy '%s': unable to set SSL curves list to '%s' for bind '%s' at [%s:%d].\n",
			          err && *err ? *err : "", curproxy->id, conf_curves, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr |= ERR_ALERT | ERR_FATAL;
		}
		(void)SSL_CTX_set_ecdh_auto(ctx, 1);
	}
#endif /* defined(SSL_CTX_set1_curves_list) */

	if (!conf_curves) {
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
#if defined(SSL_CTX_set1_curves_list)
		const char *ecdhe = (ssl_conf && ssl_conf->ecdhe) ? ssl_conf->ecdhe :
			(bind_conf->ssl_conf.ecdhe ? bind_conf->ssl_conf.ecdhe :
			 NULL);

		if (ecdhe && SSL_CTX_set1_curves_list(ctx, ecdhe) == 0) {
			memprintf(err, "%sProxy '%s': unable to set elliptic named curve to '%s' for bind '%s' at [%s:%d].\n",
				  err && *err ? *err : "", curproxy->id, ecdhe, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr |= ERR_ALERT | ERR_FATAL;
		}
#endif /* defined(SSL_CTX_set1_curves_list) */
#else
#if defined(SSL_CTX_set_tmp_ecdh) && !defined(OPENSSL_NO_ECDH)
		int i;
		EC_KEY  *ecdh;

		const char *ecdhe = (ssl_conf && ssl_conf->ecdhe) ? ssl_conf->ecdhe :
			(bind_conf->ssl_conf.ecdhe ? bind_conf->ssl_conf.ecdhe :
			 ECDHE_DEFAULT_CURVE);

		i = OBJ_sn2nid(ecdhe);
		if (!i || ((ecdh = EC_KEY_new_by_curve_name(i)) == NULL)) {
			memprintf(err, "%sProxy '%s': unable to set elliptic named curve to '%s' for bind '%s' at [%s:%d].\n",
				  err && *err ? *err : "", curproxy->id, ecdhe, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr |= ERR_ALERT | ERR_FATAL;
		}
		else {
			SSL_CTX_set_tmp_ecdh(ctx, ecdh);
			EC_KEY_free(ecdh);
		}
#endif /* defined(SSL_CTX_set_tmp_ecdh) && !defined(OPENSSL_NO_ECDH) */
#endif /* HA_OPENSSL_VERSION_NUMBER >= 0x10101000L */
	}

#if defined(SSL_CTX_set1_sigalgs_list)
	conf_sigalgs = (ssl_conf && ssl_conf->sigalgs) ? ssl_conf->sigalgs : bind_conf->ssl_conf.sigalgs;
	if (conf_sigalgs) {
		if (!SSL_CTX_set1_sigalgs_list(ctx, conf_sigalgs)) {
			memprintf(err, "%sProxy '%s': unable to set SSL Signature Algorithm list to '%s' for bind '%s' at [%s:%d].\n",
			          err && *err ? *err : "", curproxy->id, conf_sigalgs, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr |= ERR_ALERT | ERR_FATAL;
		}
	}
#endif

#if defined(SSL_CTX_set1_client_sigalgs_list)
	conf_client_sigalgs = (ssl_conf && ssl_conf->client_sigalgs) ? ssl_conf->client_sigalgs : bind_conf->ssl_conf.client_sigalgs;
	if (conf_client_sigalgs) {
		if (!SSL_CTX_set1_client_sigalgs_list(ctx, conf_client_sigalgs)) {
			memprintf(err, "%sProxy '%s': unable to set SSL Signature Algorithm list to '%s' for bind '%s' at [%s:%d].\n",
			          err && *err ? *err : "", curproxy->id, conf_client_sigalgs, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr |= ERR_ALERT | ERR_FATAL;
		}
	}
#endif

#ifdef USE_QUIC_OPENSSL_COMPAT
	if (!quic_tls_compat_init(bind_conf, ctx))
		cfgerr |= ERR_ALERT | ERR_FATAL;
#endif

	return cfgerr;
}


/*
 * Prepare the SSL_CTX based on the bind line configuration.
 * Since the CA file loading is made depending on the verify option of the bind
 * line, the link between the SSL_CTX and the CA file tree entry is made here.
 * If we want to create a link between the CA file entry and the corresponding
 * ckch instance (for CA file hot update), it needs to be done after
 * ssl_sock_prepare_ctx.
 * Returns 0 in case of success.
 */
int ssl_sock_prep_ctx_and_inst(struct bind_conf *bind_conf, struct ssl_bind_conf *ssl_conf,
			       SSL_CTX *ctx, struct ckch_inst *ckch_inst, char **err)
{
	int errcode = 0;

	errcode |= ssl_sock_prepare_ctx(bind_conf, ssl_conf, ctx, err);
	if (!errcode && ckch_inst)
		ckch_inst_add_cafile_link(ckch_inst, bind_conf, ssl_conf, NULL);

	return errcode;
}

static int ssl_sock_srv_hostcheck(const char *pattern, const char *hostname)
{
	const char *pattern_wildcard, *pattern_left_label_end, *hostname_left_label_end;
	size_t prefixlen, suffixlen;

	/* Trivial case */
	if (strcasecmp(pattern, hostname) == 0)
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
	    || strcasecmp(pattern_left_label_end, hostname_left_label_end) != 0)
		return 0;

	/* Make sure the leftmost label of the hostname is long enough
	 * that the wildcard can match */
	if (hostname_left_label_end - hostname < (pattern_left_label_end - pattern) - 1)
		return 0;

	/* Finally compare the string on either side of the
	 * wildcard */
	prefixlen = pattern_wildcard - pattern;
	suffixlen = pattern_left_label_end - (pattern_wildcard + 1);
	if ((prefixlen && (strncasecmp(pattern, hostname, prefixlen) != 0))
	    || (suffixlen && (strncasecmp(pattern_wildcard + 1, hostname_left_label_end - suffixlen, suffixlen) != 0)))
		return 0;

	return 1;
}

static int ssl_sock_srv_verifycbk(int ok, X509_STORE_CTX *ctx)
{
	SSL *ssl;
	struct connection *conn;
	struct ssl_sock_ctx *ssl_ctx;
	const char *servername;
	const char *sni;

	int depth;
	X509 *cert;
	STACK_OF(GENERAL_NAME) *alt_names;
	int i;
	X509_NAME *cert_subject;
	char *str;

	if (ok == 0)
		return ok;

	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	ssl_ctx = __conn_get_ssl_sock_ctx(conn);

	/* We're checking if the provided hostnames match the desired one. The
	 * desired hostname comes from the SNI we presented if any, or if not
	 * provided then it may have been explicitly stated using a "verifyhost"
	 * directive. If neither is set, we don't care about the name so the
	 * verification is OK.
	 */
	servername = SSL_get_servername(ssl_ctx->ssl, TLSEXT_NAMETYPE_host_name);
	sni = servername;
	if (!servername) {
		servername = __objt_server(conn->target)->ssl_ctx.verify_host;
		if (!servername)
			return ok;
	}

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
#if HA_OPENSSL_VERSION_NUMBER < 0x00907000L
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
		ASN1_STRING *value;
		value = X509_NAME_ENTRY_get_data(entry);
		if (ASN1_STRING_to_UTF8((unsigned char **)&str, value) >= 0) {
			ok = ssl_sock_srv_hostcheck(str, servername);
			OPENSSL_free(str);
		}
	}

	/* report the mismatch and indicate if SNI was used or not */
	if (!ok && !conn->err_code)
		conn->err_code = sni ? CO_ER_SSL_MISMATCH_SNI : CO_ER_SSL_MISMATCH;
	return ok;
}

/* prepare ssl context from servers options. Returns an error count */
int ssl_sock_prepare_srv_ctx(struct server *srv)
{
	int cfgerr = 0;
	SSL_CTX *ctx;
	/* Automatic memory computations need to know we use SSL there
	 * If this is an internal proxy, don't use it for the computation */
	if (!(srv->proxy->cap & PR_CAP_INT))
		global.ssl_used_backend = 1;

	/* Initiate SSL context for current server */
	if (!srv->ssl_ctx.reused_sess) {
		if ((srv->ssl_ctx.reused_sess = calloc(1, global.nbthread*sizeof(*srv->ssl_ctx.reused_sess))) == NULL) {
			ha_alert("out of memory.\n");
			cfgerr++;
			return cfgerr;
		}
	}
	if (srv->use_ssl == 1)
		srv->xprt = &ssl_sock;

	if (srv->ssl_ctx.client_crt) {
		const int create_if_none = srv->flags & SRV_F_DYNAMIC ? 0 : 1;
		char *err = NULL;
		int err_code = 0;

		/* If there is a crt keyword there, the SSL_CTX will be created here. */
		err_code = ssl_sock_load_srv_cert(srv->ssl_ctx.client_crt, srv, create_if_none, &err);
		if (err_code != ERR_NONE) {
			if ((err_code & ERR_WARN) && !(err_code & ERR_ALERT))
				ha_warning("%s", err);
			else
				ha_alert("%s", err);

			if (err_code & (ERR_FATAL|ERR_ABORT))
				cfgerr++;
		}
		ha_free(&err);
	}

	ctx = srv->ssl_ctx.ctx;

	/* The context will be uninitialized if there wasn't any "cert" option
	 * in the server line. */
	if (!ctx) {
		ctx = SSL_CTX_new(SSLv23_client_method());
		if (!ctx) {
			ha_alert("unable to allocate ssl context.\n");
			cfgerr++;
			return cfgerr;
		}
		if (global_ssl.security_level > -1)
			SSL_CTX_set_security_level(ctx, global_ssl.security_level);

		srv->ssl_ctx.ctx = ctx;
	}

	cfgerr += ssl_sock_prep_srv_ctx_and_inst(srv, srv->ssl_ctx.ctx, srv->ssl_ctx.inst);

	return cfgerr;
}

/* Initialize an SSL context that will be used on the backend side.
 * Returns an error count.
 */
static int ssl_sock_prepare_srv_ssl_ctx(const struct server *srv, SSL_CTX *ctx)
{
	struct proxy *curproxy = srv->proxy;
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
	const struct tls_version_filter *conf_ssl_methods = &srv->ssl_ctx.methods;
	int i, min, max, hole;
	int flags = MC_SSL_O_ALL;
#if defined(SSL_CTX_set1_sigalgs_list)
	const char *conf_sigalgs = NULL;
#endif
#if defined(SSL_CTX_set1_client_sigalgs_list)
	const char *conf_client_sigalgs = NULL;
#endif
#if defined(SSL_CTX_set1_curves_list)
	const char *conf_curves = NULL;
#endif
	X509_STORE *store = SSL_CTX_get_cert_store(ctx);

	if (conf_ssl_methods->flags && (conf_ssl_methods->min || conf_ssl_methods->max))
		ha_warning("no-sslv3/no-tlsv1x are ignored for this server. "
			   "Use only 'ssl-min-ver' and 'ssl-max-ver' to fix.\n");
	else
		flags = conf_ssl_methods->flags;

	/* Real min and max should be determinate with configuration and openssl's capabilities */
	if (conf_ssl_methods->min)
		flags |= (methodVersions[conf_ssl_methods->min].flag - 1);
	if (conf_ssl_methods->max)
		flags |= ~((methodVersions[conf_ssl_methods->max].flag << 1) - 1);

	/* find min, max and holes */
	min = max = CONF_TLSV_NONE;
	hole = 0;
	for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++)
		/*  version is in openssl && version not disable in configuration */
		if (methodVersions[i].option && !(flags & methodVersions[i].flag)) {
			if (min) {
				if (hole) {
					ha_warning("%s '%s': SSL/TLS versions range not contiguous for server '%s'. "
						   "Hole find for %s. Use only 'ssl-min-ver' and 'ssl-max-ver' to fix.\n",
						   proxy_type_str(curproxy), curproxy->id, srv->id,
						   methodVersions[hole].name);
					hole = 0;
				}
				max = i;
			}
			else {
				min = max = i;
			}
		}
		else {
			if (min)
				hole = i;
		}
	if (!min) {
		ha_alert("%s '%s': all SSL/TLS versions are disabled for server '%s'.\n",
			 proxy_type_str(curproxy), curproxy->id, srv->id);
		cfgerr += 1;
	}

#if (HA_OPENSSL_VERSION_NUMBER < 0x1010000fL)
	/* Keep force-xxx implementation as it is in older haproxy. It's a
	   precautionary measure to avoid any surprise with older openssl version. */
	if (min == max)
		methodVersions[min].ctx_set_version(ctx, SET_CLIENT);
	else
		for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++)
			if (flags & methodVersions[i].flag)
				options |= methodVersions[i].option;
#else   /* openssl >= 1.1.0 */
	/* set the max_version is required to cap TLS version or activate new TLS (v1.3) */
        methodVersions[min].ctx_set_version(ctx, SET_MIN);
        methodVersions[max].ctx_set_version(ctx, SET_MAX);
#endif

	if (srv->ssl_ctx.options & SRV_SSL_O_NO_TLS_TICKETS)
		options |= SSL_OP_NO_TICKET;
	SSL_CTX_set_options(ctx, options);

#ifdef SSL_MODE_ASYNC
	if (global_ssl.async)
		mode |= SSL_MODE_ASYNC;
#endif
	SSL_CTX_set_mode(ctx, mode);

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
	SSL_CTX_set_verify(ctx, verify,
	                   (srv->ssl_ctx.verify_host || (verify & SSL_VERIFY_PEER)) ? ssl_sock_srv_verifycbk : NULL);
	if (verify & SSL_VERIFY_PEER) {
		if (srv->ssl_ctx.ca_file) {
			/* set CAfile to verify */
			if (!ssl_set_verify_locations_file(ctx, srv->ssl_ctx.ca_file)) {
				ha_alert("unable to set CA file '%s'.\n",
					 srv->ssl_ctx.ca_file);
				cfgerr++;
			}
#ifdef USE_OPENSSL_WOLFSSL
			/* WolfSSL activates CRL checks by default so we need to disable it */
			X509_STORE_set_flags(store, 0) ;
#endif
		}
		else {
			if (global.ssl_server_verify == SSL_SERVER_VERIFY_REQUIRED)
				ha_alert("verify is enabled by default but no CA file specified. If you're running on a LAN where you're certain to trust the server's certificate, please set an explicit 'verify none' statement on the 'server' line, or use 'ssl-server-verify none' in the global section to disable server-side verifications by default.\n");
			else
				ha_alert("verify is enabled but no CA file specified.\n");
			cfgerr++;
		}
#ifdef X509_V_FLAG_CRL_CHECK
		if (srv->ssl_ctx.crl_file) {
			if (!ssl_set_cert_crl_file(store, srv->ssl_ctx.crl_file)) {
				ha_alert("unable to configure CRL file '%s'.\n",
					 srv->ssl_ctx.crl_file);
				cfgerr++;
			}
			else {
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
			}
		}
#endif
	}

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
	SSL_CTX_sess_set_new_cb(ctx, ssl_sess_new_srv_cb);
	if (srv->ssl_ctx.ciphers &&
		!SSL_CTX_set_cipher_list(ctx, srv->ssl_ctx.ciphers)) {
		ha_alert("unable to set SSL cipher list to '%s'.\n",
			 srv->ssl_ctx.ciphers);
		cfgerr++;
	}

#ifdef SSL_CTRL_SET_MSG_CALLBACK
	SSL_CTX_set_msg_callback(ctx, ssl_sock_msgcbk);
#endif

#ifdef HAVE_SSL_KEYLOG
	/* only activate the keylog callback if it was required to prevent performance loss */
	if (global_ssl.keylog > 0)
		SSL_CTX_set_keylog_callback(ctx, SSL_CTX_keylog);
#endif

#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	if (srv->ssl_ctx.ciphersuites &&
		!SSL_CTX_set_ciphersuites(ctx, srv->ssl_ctx.ciphersuites)) {
		ha_alert("unable to set TLS 1.3 cipher suites to '%s'.\n",
			 srv->ssl_ctx.ciphersuites);
		cfgerr++;
	}
#endif
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	if (srv->ssl_ctx.npn_str)
		SSL_CTX_set_next_proto_select_cb(ctx, ssl_sock_srv_select_protos, (struct server*)srv);
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	if (srv->ssl_ctx.alpn_str && srv->ssl_ctx.alpn_len)
		SSL_CTX_set_alpn_protos(ctx, (unsigned char *)srv->ssl_ctx.alpn_str, srv->ssl_ctx.alpn_len);
#endif

#if defined(SSL_CTX_set1_sigalgs_list)
	conf_sigalgs = srv->ssl_ctx.sigalgs;
	if (conf_sigalgs) {
		if (!SSL_CTX_set1_sigalgs_list(ctx, conf_sigalgs)) {
			ha_alert("Proxy '%s': unable to set SSL Signature Algorithm list to '%s' for server '%s'.\n",
			         curproxy->id, conf_sigalgs, srv->id);
			cfgerr++;
		}
	}
#endif
#if defined(SSL_CTX_set1_client_sigalgs_list)
	conf_client_sigalgs = srv->ssl_ctx.client_sigalgs;
	if (conf_client_sigalgs) {
		if (!SSL_CTX_set1_client_sigalgs_list(ctx, conf_client_sigalgs)) {
			ha_alert("Proxy '%s': unable to set SSL Client Signature Algorithm list to '%s' for server '%s'.\n",
			         curproxy->id, conf_client_sigalgs, srv->id);
			cfgerr++;
		}
	}
#endif

#if defined(SSL_CTX_set1_curves_list)
	conf_curves =  srv->ssl_ctx.curves;
	if (conf_curves) {
		if (!SSL_CTX_set1_curves_list(ctx, conf_curves)) {
			ha_alert("Proxy '%s': unable to set SSL curves list to '%s' for server '%s'.\n",
			         curproxy->id, conf_curves, srv->id);
			cfgerr++;
		}
	}
#endif /* defined(SSL_CTX_set1_curves_list) */

	return cfgerr;
}

/*
 * Prepare the frontend's SSL_CTX based on the server line configuration.
 * Since the CA file loading is made depending on the verify option of the
 * server line, the link between the SSL_CTX and the CA file tree entry is
 * made here.
 * If we want to create a link between the CA file entry and the corresponding
 * ckch instance (for CA file hot update), it needs to be done after
 * ssl_sock_prepare_srv_ssl_ctx.
 * Returns an error count.
 */
int ssl_sock_prep_srv_ctx_and_inst(const struct server *srv, SSL_CTX *ctx,
				   struct ckch_inst *ckch_inst)
{
	int cfgerr = 0;

	cfgerr += ssl_sock_prepare_srv_ssl_ctx(srv, ctx);
	if (!cfgerr && ckch_inst)
		ckch_inst_add_cafile_link(ckch_inst, NULL, NULL, srv);

	return cfgerr;
}


/*
 * Create an initial CTX used to start the SSL connections.
 * May be used by QUIC xprt which makes usage of SSL sessions initialized from SSL_CTXs.
 * Returns 0 if succeeded, or something >0 if not.
 */
#ifdef USE_QUIC
static int ssl_initial_ctx(struct bind_conf *bind_conf)
{
	if (bind_conf->xprt == xprt_get(XPRT_QUIC))
		return ssl_quic_initial_ctx(bind_conf);
	else
		return ssl_sock_initial_ctx(bind_conf);
}
#else
static int ssl_initial_ctx(struct bind_conf *bind_conf)
{
	return ssl_sock_initial_ctx(bind_conf);
}
#endif

/* Walks down the two trees in bind_conf and prepares all certs. The pointer may
 * be NULL, in which case nothing is done. Returns the number of errors
 * encountered.
 */
int ssl_sock_prepare_all_ctx(struct bind_conf *bind_conf)
{
	struct ebmb_node *node;
	struct sni_ctx *sni;
	int err = 0;
	int errcode = 0;
	char *errmsg = NULL;

	/* Automatic memory computations need to know we use SSL there */
	global.ssl_used_frontend = 1;

	/* Create initial_ctx used to start the ssl connection before do switchctx */
	if (!bind_conf->initial_ctx) {
		err += ssl_initial_ctx(bind_conf);
		/* It should not be necessary to call this function, but it's
		   necessary first to check and move all initialisation related
		   to initial_ctx in ssl_initial_ctx. */
		errcode |= ssl_sock_prep_ctx_and_inst(bind_conf, NULL, bind_conf->initial_ctx, NULL, &errmsg);
	}

	node = ebmb_first(&bind_conf->sni_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		if (!sni->order) {
			/* only initialize the CTX on its first occurrence */
			errcode |= ssl_sock_prep_ctx_and_inst(bind_conf, sni->conf, sni->ctx, sni->ckch_inst, &errmsg);
		}
		node = ebmb_next(node);
	}

	node = ebmb_first(&bind_conf->sni_w_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		if (!sni->order) {
			/* only initialize the CTX on its first occurrence */
			errcode |= ssl_sock_prep_ctx_and_inst(bind_conf, sni->conf, sni->ctx, sni->ckch_inst, &errmsg);
		}
		node = ebmb_next(node);
	}

	if (errcode & ERR_WARN) {
		ha_warning("%s", errmsg);
	} else if (errcode & ERR_CODE) {
		ha_alert("%s", errmsg);
		err++;
	}

	free(errmsg);
	return err;
}

/* Prepares all the contexts for a bind_conf and allocates the shared SSL
 * context if needed. Returns < 0 on error, 0 on success. The warnings and
 * alerts are directly emitted since the rest of the stack does it below.
 */
int ssl_sock_prepare_bind_conf(struct bind_conf *bind_conf)
{
	struct proxy *px = bind_conf->frontend;
	int alloc_ctx;
	int err;

	/* check if some certificates were loaded but no ssl keyword is used */
	if (!(bind_conf->options & BC_O_USE_SSL)) {
		if (!eb_is_empty(&bind_conf->sni_ctx) || !eb_is_empty(&bind_conf->sni_w_ctx)) {
			ha_warning("Proxy '%s': A certificate was specified but SSL was not enabled on bind '%s' at [%s:%d] (use 'ssl').\n",
				   px->id, bind_conf->arg, bind_conf->file, bind_conf->line);
		}
		return 0;
	}

	/* check if we have certificates */
	if (eb_is_empty(&bind_conf->sni_ctx) && eb_is_empty(&bind_conf->sni_w_ctx)) {
		if ((bind_conf->ssl_options & BC_SSL_O_STRICT_SNI) && !(bind_conf->options & BC_O_GENERATE_CERTS)) {
			ha_warning("Proxy '%s': no SSL certificate specified for bind '%s' at [%s:%d], ssl connections will fail (use 'crt').\n",
				   px->id, bind_conf->arg, bind_conf->file, bind_conf->line);
		}
		else {
			ha_alert("Proxy '%s': no SSL certificate specified for bind '%s' at [%s:%d] (use 'crt').\n",
				 px->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			return -1;
		}
	}

	if ((bind_conf->options & BC_O_GENERATE_CERTS)) {
		struct sni_ctx *sni_ctx;

		/* if we use the generate-certificates option, look for the first default cert available */
		sni_ctx = ssl_sock_chose_sni_ctx(bind_conf, NULL, "", 1, 1);
		if (!sni_ctx) {
			ha_alert("Proxy '%s': no SSL certificate specified for bind '%s' and 'generate-certificates' option at [%s:%d] (use 'crt').\n",
				 px->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			return -1;
		}
	}

	if (!ssl_shctx && global.tune.sslcachesize) {
		alloc_ctx = shctx_init(&ssl_shctx, global.tune.sslcachesize,
		                       sizeof(struct sh_ssl_sess_hdr) + SHSESS_BLOCK_MIN_SIZE, -1,
		                       sizeof(*sh_ssl_sess_tree), "ssl cache");
		if (alloc_ctx <= 0) {
			if (alloc_ctx == SHCTX_E_INIT_LOCK)
				ha_alert("Unable to initialize the lock for the shared SSL session cache. You can retry using the global statement 'tune.ssl.force-private-cache' but it could increase CPU usage due to renegotiations if nbproc > 1.\n");
			else
				ha_alert("Unable to allocate SSL session cache.\n");
			return -1;
		}
		/* free block callback */
		ssl_shctx->free_block = sh_ssl_sess_free_blocks;
		/* init the root tree within the extra space */
		sh_ssl_sess_tree = (void *)ssl_shctx + sizeof(struct shared_context);
		*sh_ssl_sess_tree = EB_ROOT_UNIQUE;
	}
	err = 0;
	/* initialize all certificate contexts */
	err += ssl_sock_prepare_all_ctx(bind_conf);

#ifndef SSL_NO_GENERATE_CERTIFICATES
	/* initialize CA variables if the certificates generation is enabled */
	err += ssl_sock_gencert_load_ca(bind_conf);
#endif

	return -err;
}

/* release ssl context allocated for servers.  Most of the field free here
 * must also be allocated in srv_ssl_settings_cpy() */
void ssl_sock_free_srv_ctx(struct server *srv)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	ha_free(&srv->ssl_ctx.alpn_str);
#endif
#ifdef OPENSSL_NPN_NEGOTIATED
	ha_free(&srv->ssl_ctx.npn_str);
#endif
	if (srv->ssl_ctx.reused_sess) {
		int i;

		for (i = 0; i < global.nbthread; i++) {
			ha_free(&srv->ssl_ctx.reused_sess[i].ptr);
			ha_free(&srv->ssl_ctx.reused_sess[i].sni);
		}
		ha_free(&srv->ssl_ctx.reused_sess);
	}

	if (srv->ssl_ctx.ctx) {
		SSL_CTX_free(srv->ssl_ctx.ctx);
		srv->ssl_ctx.ctx = NULL;
	}

	ha_free(&srv->ssl_ctx.ca_file);
	ha_free(&srv->ssl_ctx.crl_file);
	ha_free(&srv->ssl_ctx.client_crt);
	ha_free(&srv->ssl_ctx.verify_host);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	ha_free(&srv->sni_expr);
	release_sample_expr(srv->ssl_ctx.sni);
	srv->ssl_ctx.sni = NULL;
#endif
	ha_free(&srv->ssl_ctx.ciphers);
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	ha_free(&srv->ssl_ctx.ciphersuites);
#endif
	/* If there is a certificate we must unlink the ckch instance */
	ckch_inst_free(srv->ssl_ctx.inst);
}

/* Walks down the two trees in bind_conf and frees all the certs. The pointer may
 * be NULL, in which case nothing is done. The default_ctx is nullified too.
 */
void ssl_sock_free_all_ctx(struct bind_conf *bind_conf)
{
	struct ebmb_node *node, *back;
	struct sni_ctx *sni;

	node = ebmb_first(&bind_conf->sni_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		back = ebmb_next(node);
		ebmb_delete(node);
		SSL_CTX_free(sni->ctx);
		LIST_DELETE(&sni->by_ckch_inst);
		free(sni);
		node = back;
	}

	node = ebmb_first(&bind_conf->sni_w_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		back = ebmb_next(node);
		ebmb_delete(node);
		SSL_CTX_free(sni->ctx);
		LIST_DELETE(&sni->by_ckch_inst);
		free(sni);
		node = back;
	}

	SSL_CTX_free(bind_conf->initial_ctx);
	bind_conf->initial_ctx = NULL;
}


void ssl_sock_deinit()
{
	crtlist_deinit(); /* must be free'd before the ckchs */
	ckch_deinit();
}
REGISTER_POST_DEINIT(ssl_sock_deinit);

/* Destroys all the contexts for a bind_conf. This is used during deinit(). */
void ssl_sock_destroy_bind_conf(struct bind_conf *bind_conf)
{
#ifndef SSL_NO_GENERATE_CERTIFICATES
	ssl_sock_gencert_free_ca(bind_conf);
#endif
	ssl_sock_free_all_ctx(bind_conf);
	ssl_sock_free_ssl_conf(&bind_conf->ssl_conf);
	free(bind_conf->ca_sign_file);
	free(bind_conf->ca_sign_pass);
	if (bind_conf->keys_ref && !--bind_conf->keys_ref->refcount) {
		free(bind_conf->keys_ref->filename);
		free(bind_conf->keys_ref->tlskeys);
		LIST_DELETE(&bind_conf->keys_ref->list);
		free(bind_conf->keys_ref);
	}
	bind_conf->keys_ref = NULL;
	bind_conf->ca_sign_pass = NULL;
	bind_conf->ca_sign_file = NULL;
}

/*
 * Try to allocate the BIO and SSL session objects of <conn> connection with <bio> and
 * <ssl> as addresses, <bio_meth> as BIO method and <ssl_ctx> as SSL context inherited settings.
 * Connect the allocated BIO to the allocated SSL session. Also set <ctx> as address of custom
 * data for the BIO and store <conn> as user data of the SSL session object.
 * This is the responsibility of the caller to check the validity of all the pointers passed
 * as parameters to this function.
 * Return 0 if succeeded, -1 if not. If failed, sets the ->err_code member of <conn> to
 * CO_ER_SSL_NO_MEM.
 */
int ssl_bio_and_sess_init(struct connection *conn, SSL_CTX *ssl_ctx,
                          SSL **ssl, BIO **bio, BIO_METHOD *bio_meth, void *ctx)
{
	int retry = 1;

 retry:
	/* Alloc a new SSL session. */
	*ssl = SSL_new(ssl_ctx);
	if (!*ssl) {
		if (!retry--)
			goto err;

		pool_gc(NULL);
		goto retry;
	}

	*bio = BIO_new(bio_meth);
	if (!*bio) {
		SSL_free(*ssl);
		*ssl = NULL;
		if (!retry--)
			goto err;

		pool_gc(NULL);
		goto retry;
	}

	BIO_set_data(*bio, ctx);
	SSL_set_bio(*ssl, *bio, *bio);

	/* set connection pointer. */
	if (!SSL_set_ex_data(*ssl, ssl_app_data_index, conn)) {
		SSL_free(*ssl);
		*ssl = NULL;
		if (!retry--)
			goto err;

		pool_gc(NULL);
		goto retry;
	}

	return 0;

 err:
	conn->err_code = CO_ER_SSL_NO_MEM;
	return -1;
}

/* This function is called when all the XPRT have been initialized. We can
 * now attempt to start the SSL handshake.
 */
static int ssl_sock_start(struct connection *conn, void *xprt_ctx)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;

	if (ctx->xprt->start) {
		int ret;

		ret = ctx->xprt->start(conn, ctx->xprt_ctx);
		if (ret < 0)
			return ret;
	}
	tasklet_wakeup(ctx->wait_event.tasklet);

	return 0;
}

/* Similar to increment_actconn() but for SSL connections. */
int increment_sslconn()
{
	unsigned int count, next_sslconn;

	do {
		count = global.sslconns;
		if (global.maxsslconn && count >= global.maxsslconn) {
			/* maxconn reached */
			next_sslconn = 0;
			goto end;
		}

		/* try to increment sslconns */
		next_sslconn = count + 1;
	} while (!_HA_ATOMIC_CAS(&global.sslconns, &count, next_sslconn) && __ha_cpu_relax());

 end:
	return next_sslconn;
}

/*
 * This function is called if SSL * context is not yet allocated. The function
 * is designed to be called before any other data-layer operation and sets the
 * handshake flag on the connection. It is safe to call it multiple times.
 * It returns 0 on success and -1 in error case.
 */
static int ssl_sock_init(struct connection *conn, void **xprt_ctx)
{
	struct ssl_sock_ctx *ctx;
	int next_sslconn = 0;

	TRACE_ENTER(SSL_EV_CONN_NEW, conn);

	/* already initialized */
	if (*xprt_ctx)
		return 0;

	ctx = pool_alloc(ssl_sock_ctx_pool);
	if (!ctx) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		TRACE_ERROR("ssl_sock_ctx allocation failure", SSL_EV_CONN_NEW|SSL_EV_CONN_ERR|SSL_EV_CONN_END, conn);
		return -1;
	}
	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		pool_free(ssl_sock_ctx_pool, ctx);
		TRACE_ERROR("tasklet allocation failure", SSL_EV_CONN_NEW|SSL_EV_CONN_ERR|SSL_EV_CONN_END, conn);
		return -1;
	}
	ctx->wait_event.tasklet->process = ssl_sock_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.tasklet->state  |= TASK_HEAVY; // assign it to the bulk queue during handshake
	ctx->wait_event.events = 0;
	ctx->sent_early_data = 0;
	ctx->early_buf = BUF_NULL;
	ctx->conn = conn;
	ctx->subs = NULL;
	ctx->xprt_st = 0;
	ctx->xprt_ctx = NULL;
	ctx->error_code = 0;

	next_sslconn = increment_sslconn();
	if (!next_sslconn) {
		conn->err_code = CO_ER_SSL_TOO_MANY;
		TRACE_ERROR("Too many SSL connections", SSL_EV_CONN_NEW|SSL_EV_CONN_ERR|SSL_EV_CONN_END, conn);
		goto err;
	}

	/* Only work with sockets for now, this should be adapted when we'll
	 * add QUIC support.
	 */
	ctx->xprt = xprt_get(XPRT_RAW);
	if (ctx->xprt->init) {
		if (ctx->xprt->init(conn, &ctx->xprt_ctx) != 0)
			goto err;
	}

	/* If it is in client mode initiate SSL session
	   in connect state otherwise accept state */
	if (objt_server(conn->target)) {
		struct server *srv = __objt_server(conn->target);

		if (ssl_bio_and_sess_init(conn, srv->ssl_ctx.ctx,
		                          &ctx->ssl, &ctx->bio, ha_meth, ctx) == -1)
			goto err;

		SSL_set_connect_state(ctx->ssl);
		HA_RWLOCK_RDLOCK(SSL_SERVER_LOCK, &srv->ssl_ctx.lock);
		if (srv->ssl_ctx.reused_sess[tid].ptr) {
			/* let's recreate a session from (ptr,size) and assign
			 * it to ctx->ssl. Its refcount will be updated by the
			 * creation and by the assignment, so after assigning
			 * it or failing to, we must always free it to decrement
			 * the refcount.
			 */
			const unsigned char *ptr = srv->ssl_ctx.reused_sess[tid].ptr;
			SSL_SESSION *sess = d2i_SSL_SESSION(NULL, &ptr, srv->ssl_ctx.reused_sess[tid].size);

			if (sess && !SSL_set_session(ctx->ssl, sess)) {
				uint old_tid = HA_ATOMIC_LOAD(&srv->ssl_ctx.last_ssl_sess_tid); // 0=none, >0 = tid + 1
				if (old_tid == tid + 1)
					HA_ATOMIC_CAS(&srv->ssl_ctx.last_ssl_sess_tid, &old_tid, 0); // no more valid
				SSL_SESSION_free(sess);
				HA_RWLOCK_WRLOCK(SSL_SERVER_LOCK, &srv->ssl_ctx.reused_sess[tid].sess_lock);
				ha_free(&srv->ssl_ctx.reused_sess[tid].ptr);
				HA_RWLOCK_WRTORD(SSL_SERVER_LOCK, &srv->ssl_ctx.reused_sess[tid].sess_lock);
				if (srv->ssl_ctx.reused_sess[tid].sni)
					SSL_set_tlsext_host_name(ctx->ssl, srv->ssl_ctx.reused_sess[tid].sni);
				HA_RWLOCK_RDUNLOCK(SSL_SERVER_LOCK, &srv->ssl_ctx.reused_sess[tid].sess_lock);
			} else if (sess) {
				/* already assigned, not needed anymore */
				SSL_SESSION_free(sess);
				HA_RWLOCK_RDLOCK(SSL_SERVER_LOCK, &srv->ssl_ctx.reused_sess[tid].sess_lock);
				if (srv->ssl_ctx.reused_sess[tid].sni)
					SSL_set_tlsext_host_name(ctx->ssl, srv->ssl_ctx.reused_sess[tid].sni);
				HA_RWLOCK_RDUNLOCK(SSL_SERVER_LOCK, &srv->ssl_ctx.reused_sess[tid].sess_lock);
			}
		} else {
			/* No session available yet, let's see if we can pick one
			 * from another thread. If old_tid is non-null, it designates
			 * the index of a recently updated thread that might still have
			 * a usable session. All threads are collectively responsible
			 * for resetting the index if it fails.
			 */
			const unsigned char *ptr;
			SSL_SESSION *sess;
			uint old_tid = HA_ATOMIC_LOAD(&srv->ssl_ctx.last_ssl_sess_tid); // 0=none, >0 = tid + 1

			if (old_tid) {
				HA_RWLOCK_RDLOCK(SSL_SERVER_LOCK, &srv->ssl_ctx.reused_sess[old_tid-1].sess_lock);

				ptr = srv->ssl_ctx.reused_sess[old_tid-1].ptr;
				if (ptr) {
					sess = d2i_SSL_SESSION(NULL, &ptr, srv->ssl_ctx.reused_sess[old_tid-1].size);
					if (sess) {
						if (!SSL_set_session(ctx->ssl, sess))
							HA_ATOMIC_CAS(&srv->ssl_ctx.last_ssl_sess_tid, &old_tid, 0); // no more valid
						SSL_SESSION_free(sess);
					}
				}

				if (srv->ssl_ctx.reused_sess[old_tid-1].sni)
					SSL_set_tlsext_host_name(ctx->ssl, srv->ssl_ctx.reused_sess[old_tid-1].sni);

				HA_RWLOCK_RDUNLOCK(SSL_SERVER_LOCK, &srv->ssl_ctx.reused_sess[old_tid-1].sess_lock);
			}
		}
		HA_RWLOCK_RDUNLOCK(SSL_SERVER_LOCK, &srv->ssl_ctx.lock);

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;

		_HA_ATOMIC_INC(&global.totalsslconns);
		*xprt_ctx = ctx;

		TRACE_LEAVE(SSL_EV_CONN_NEW, conn);
		return 0;
	}
	else if (objt_listener(conn->target)) {
		struct bind_conf *bc = __objt_listener(conn->target)->bind_conf;

		if (ssl_bio_and_sess_init(conn, bc->initial_ctx,
		                           &ctx->ssl, &ctx->bio, ha_meth, ctx) == -1)
			goto err;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
		if (bc->ssl_conf.early_data) {
			b_alloc(&ctx->early_buf, DB_MUX_RX);
			SSL_set_max_early_data(ctx->ssl,
			    /* Only allow early data if we managed to allocate
			     * a buffer.
			     */
			    (!b_is_null(&ctx->early_buf)) ?
			    global.tune.bufsize - global.tune.maxrewrite : 0);
		}
#endif

		SSL_set_accept_state(ctx->ssl);

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;
#ifdef SSL_READ_EARLY_DATA_SUCCESS
		if (bc->ssl_conf.early_data)
			conn->flags |= CO_FL_EARLY_SSL_HS;
#endif

		_HA_ATOMIC_INC(&global.totalsslconns);
		*xprt_ctx = ctx;

		TRACE_LEAVE(SSL_EV_CONN_NEW, conn);
		return 0;
	}
	/* don't know how to handle such a target */
	conn->err_code = CO_ER_SSL_NO_TARGET;
err:
	if (next_sslconn)
		_HA_ATOMIC_DEC(&global.sslconns);
	if (ctx && ctx->wait_event.tasklet)
		tasklet_free(ctx->wait_event.tasklet);
	pool_free(ssl_sock_ctx_pool, ctx);
	TRACE_DEVEL("leaving in error", SSL_EV_CONN_NEW|SSL_EV_CONN_ERR|SSL_EV_CONN_END);
	return -1;
}


/* This is the callback which is used when an SSL handshake is pending. It
 * updates the FD status if it wants some polling before being called again.
 * It returns 0 if it fails in a fatal way or needs to poll to go further,
 * otherwise it returns non-zero and removes itself from the connection's
 * flags (the bit is provided in <flag> by the caller).
 */
static int ssl_sock_handshake(struct connection *conn, unsigned int flag)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);
	int ret;
	struct ssl_counters *counters = NULL;
	struct ssl_counters *counters_px = NULL;
	struct listener *li;
	struct server *srv;
	socklen_t lskerr;
	int skerr;

	TRACE_ENTER(SSL_EV_CONN_HNDSHK, conn);

	if (!conn_ctrl_ready(conn))
		return 0;

	/* get counters */
	switch (obj_type(conn->target)) {
	case OBJ_TYPE_LISTENER:
		li = __objt_listener(conn->target);
		counters = EXTRA_COUNTERS_GET(li->extra_counters, &ssl_stats_module);
		counters_px = EXTRA_COUNTERS_GET(li->bind_conf->frontend->extra_counters_fe,
		                                 &ssl_stats_module);
		break;

	case OBJ_TYPE_SERVER:
		srv = __objt_server(conn->target);
		counters = EXTRA_COUNTERS_GET(srv->extra_counters, &ssl_stats_module);
		counters_px = EXTRA_COUNTERS_GET(srv->proxy->extra_counters_be,
		                                 &ssl_stats_module);
		break;

	default:
		break;
	}

	if (!ctx)
		goto out_error;

	/* don't start calculating a handshake on a dead connection */
	if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH)) {
		TRACE_ERROR("Trying to perform handshake on dead connection", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
		goto out_error;
	}

	/* FIXME/WT: for now we don't have a clear way to inspect the connection
	 * status from the lower layers, so let's check the FD directly. Ideally
	 * the xprt layers should provide some status indicating their knowledge
	 * of shutdowns or error.
	 */
	BUG_ON(conn->flags & CO_FL_FDLESS);

	skerr = 0;
	lskerr = sizeof(skerr);
	if ((getsockopt(conn->handle.fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr) < 0) ||
	    skerr != 0)
		goto out_error;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
	/*
	 * Check if we have early data. If we do, we have to read them
	 * before SSL_do_handshake() is called, And there's no way to
	 * detect early data, except to try to read them
	 */
	if (conn->flags & CO_FL_EARLY_SSL_HS) {
		size_t read_data = 0;

		while (1) {
			ret = SSL_read_early_data(ctx->ssl,
			    b_tail(&ctx->early_buf), b_room(&ctx->early_buf),
			    &read_data);
			if (ret == SSL_READ_EARLY_DATA_ERROR) {
				TRACE_ERROR("Read early data error", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
				goto check_error;
			}
			if (read_data > 0) {
				TRACE_DEVEL("Early data read", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
				conn->flags |= CO_FL_EARLY_DATA;
				b_add(&ctx->early_buf, read_data);
			}
			if (ret == SSL_READ_EARLY_DATA_FINISH) {
				conn->flags &= ~CO_FL_EARLY_SSL_HS;
				if (!b_data(&ctx->early_buf))
					b_free(&ctx->early_buf);
				TRACE_STATE("Read early data finish", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
				break;
			}
		}
	}
#endif
	/* If we use SSL_do_handshake to process a reneg initiated by
	 * the remote peer, it sometimes returns SSL_ERROR_SSL.
	 * Usually SSL_write and SSL_read are used and process implicitly
	 * the reneg handshake.
	 * Here we use SSL_peek as a workaround for reneg.
	 */
	if (!(conn->flags & CO_FL_WAIT_L6_CONN) && SSL_renegotiate_pending(ctx->ssl)) {
		char c;

		TRACE_STATE("Renegotiate pending", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);

		ret = SSL_peek(ctx->ssl, &c, 1);
		if (ret <= 0) {
			/* handshake may have not been completed, let's find why */
			ret = SSL_get_error(ctx->ssl, ret);

			if (ret == SSL_ERROR_WANT_WRITE) {
				/* SSL handshake needs to write, L4 connection may not be ready */
				if (!(ctx->wait_event.events & SUB_RETRY_SEND))
					ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND, &ctx->wait_event);
				TRACE_DEVEL("Renegotiate pending: want write", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
				return 0;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				/* handshake may have been completed but we have
				 * no more data to read.
                                 */
				if (!SSL_renegotiate_pending(ctx->ssl)) {
					ret = 1;
					TRACE_DEVEL("Renegotiate pending: reneg ok", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
					goto reneg_ok;
				}
				/* SSL handshake needs to read, L4 connection is ready */
				if (!(ctx->wait_event.events & SUB_RETRY_RECV))
					ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_RECV, &ctx->wait_event);
				TRACE_DEVEL("Renegotiate pending: want read", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
				return 0;
			}
#ifdef SSL_MODE_ASYNC
			else if (ret == SSL_ERROR_WANT_ASYNC) {
				ssl_async_process_fds(ctx);
				TRACE_ERROR("Renegotiate pending: want async error", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
				return 0;
			}
#endif
			else if (ret == SSL_ERROR_SYSCALL) {
				/* if errno is null, then connection was successfully established */
				if (!errno && conn->flags & CO_FL_WAIT_L4_CONN)
					conn->flags &= ~CO_FL_WAIT_L4_CONN;
				if (!conn->err_code) {
#if defined(OPENSSL_IS_BORINGSSL) || defined(LIBRESSL_VERSION_NUMBER)
					/* do not handle empty handshakes in BoringSSL or LibreSSL */
					conn->err_code = CO_ER_SSL_HANDSHAKE;
#else
					int empty_handshake;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL)
					/* use SSL_get_state() in OpenSSL >= 1.1.0; SSL_state() is broken */
					OSSL_HANDSHAKE_STATE state = SSL_get_state((SSL *)ctx->ssl);
					empty_handshake = state == TLS_ST_BEFORE;
#else
					/* access packet_length directly in OpenSSL <= 1.0.2; SSL_state() is broken */
					empty_handshake = !ctx->ssl->packet_length;
#endif
					if (empty_handshake) {
						if (!errno) {
							if (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
								conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
							else
								conn->err_code = CO_ER_SSL_EMPTY;
						}
						else {
							if (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
								conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
							else
								conn->err_code = CO_ER_SSL_ABORT;
						}
					}
					else {
						if (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
							conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
						else
							conn->err_code = CO_ER_SSL_HANDSHAKE;
					}
#endif /* BoringSSL or LibreSSL */
				}
				TRACE_ERROR("Renegotiate pending: syscall error", SSL_EV_CONN_HNDSHK|SSL_EV_CONN_ERR, conn, ctx->ssl, &conn->err_code);
				goto out_error;
			}
			else {
				/* Fail on all other handshake errors */
				/* Note: OpenSSL may leave unread bytes in the socket's
				 * buffer, causing an RST to be emitted upon close() on
				 * TCP sockets. We first try to drain possibly pending
				 * data to avoid this as much as possible.
				 */
				conn_ctrl_drain(conn);
				if (!conn->err_code)
					conn->err_code = (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT) ?
						CO_ER_SSL_KILLED_HB : CO_ER_SSL_HANDSHAKE;
				TRACE_ERROR("Renegotiate pending: other error", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
				goto out_error;
			}
		}
		TRACE_STATE("Renegotiate pending: reneg ok", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
		/* read some data: consider handshake completed */
		goto reneg_ok;
	}
	ret = SSL_do_handshake(ctx->ssl);
check_error:
	if (ret != 1) {
		/* handshake did not complete, let's find why */
		ret = SSL_get_error(ctx->ssl, ret);

		if (!ctx->error_code)
			ctx->error_code = ERR_peek_error();

		if (ret == SSL_ERROR_WANT_WRITE) {
			/* SSL handshake needs to write, L4 connection may not be ready */
			if (!(ctx->wait_event.events & SUB_RETRY_SEND))
				ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND, &ctx->wait_event);
			TRACE_DEVEL("Want write (post SSL_do_handshake)", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
			return 0;
		}
		else if (ret == SSL_ERROR_WANT_READ) {
			/* SSL handshake needs to read, L4 connection is ready */
			if (!(ctx->wait_event.events & SUB_RETRY_RECV))
				ctx->xprt->subscribe(conn, ctx->xprt_ctx,
				    SUB_RETRY_RECV, &ctx->wait_event);
			TRACE_DEVEL("Want read (post SSL_do_handshake)", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
			return 0;
		}
#ifdef SSL_MODE_ASYNC
		else if (ret == SSL_ERROR_WANT_ASYNC) {
			ssl_async_process_fds(ctx);
			TRACE_ERROR("Want async error", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
			return 0;
		}
#endif
		else if (ret == SSL_ERROR_SYSCALL) {
			/* if errno is null, then connection was successfully established */
			if (!errno && conn->flags & CO_FL_WAIT_L4_CONN)
				conn->flags &= ~CO_FL_WAIT_L4_CONN;
			if (!conn->err_code) {
#if defined(OPENSSL_IS_BORINGSSL) || defined(LIBRESSL_VERSION_NUMBER)
				/* do not handle empty handshakes in BoringSSL or LibreSSL */
				conn->err_code = CO_ER_SSL_HANDSHAKE;
#else
				int empty_handshake;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL)
				/* use SSL_get_state() in OpenSSL >= 1.1.0; SSL_state() is broken */
				OSSL_HANDSHAKE_STATE state = SSL_get_state(ctx->ssl);
				empty_handshake = state == TLS_ST_BEFORE;
#else
				/* access packet_length directly in OpenSSL <= 1.0.2; SSL_state() is broken */
				empty_handshake = !ctx->ssl->packet_length;
#endif
				if (empty_handshake) {
					if (!errno) {
						if (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
							conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
						else
							conn->err_code = CO_ER_SSL_EMPTY;
					}
					else {
						if (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
							conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
						else
							conn->err_code = CO_ER_SSL_ABORT;
					}
				}
				else {
					if (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT)
						conn->err_code = CO_ER_SSL_HANDSHAKE_HB;
					else
						conn->err_code = CO_ER_SSL_HANDSHAKE;
				}
#endif /* BoringSSL or LibreSSL */
			}
			TRACE_ERROR("Syscall error", SSL_EV_CONN_HNDSHK|SSL_EV_CONN_ERR, conn, ctx->ssl, &conn->err_code, &ctx->error_code);
			goto out_error;

		} else if (ret == SSL_ERROR_ZERO_RETURN) {
			/* The peer has closed the SSL session for writing by
			 * sending a close_notify alert */
			conn_ctrl_drain(conn);
			conn->err_code = CO_ER_SSL_EMPTY;
			TRACE_ERROR("Zero return error", SSL_EV_CONN_HNDSHK|SSL_EV_CONN_ERR, conn, ctx->ssl, &conn->err_code, &ctx->error_code);
			goto out_error;

		}
		else {
			/* Fail on all other handshake errors */
			/* Note: OpenSSL may leave unread bytes in the socket's
			 * buffer, causing an RST to be emitted upon close() on
			 * TCP sockets. We first try to drain possibly pending
			 * data to avoid this as much as possible.
			 */
			conn_ctrl_drain(conn);
			if (!conn->err_code)
				conn->err_code = (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT) ?
					CO_ER_SSL_KILLED_HB : CO_ER_SSL_HANDSHAKE;
			TRACE_ERROR("Other error", SSL_EV_CONN_HNDSHK|SSL_EV_CONN_ERR, conn, ctx->ssl, &conn->err_code, &ctx->error_code);
			goto out_error;
		}
	}
	else {
		TRACE_STATE("Successful SSL_do_handshake", SSL_EV_CONN_HNDSHK, conn, ctx->ssl);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
		/*
		 * If the server refused the early data, we have to send a
		 * 425 to the client, as we no longer have the data to sent
		 * them again.
		 */
		if ((conn->flags & CO_FL_EARLY_DATA) && (objt_server(conn->target))) {
			if (SSL_get_early_data_status(ctx->ssl) == SSL_EARLY_DATA_REJECTED) {
				conn->err_code = CO_ER_SSL_EARLY_FAILED;
				TRACE_ERROR("Early data rejected", SSL_EV_CONN_HNDSHK|SSL_EV_CONN_ERR, conn, ctx->ssl, &conn->err_code);
				goto out_error;
			}
		}
#endif
	}


reneg_ok:

#ifdef SSL_MODE_ASYNC
	/* ASYNC engine API doesn't support moving read/write
	 * buffers. So we disable ASYNC mode right after
	 * the handshake to avoid buffer overflow.
	 */
	if (global_ssl.async)
		SSL_clear_mode(ctx->ssl, SSL_MODE_ASYNC);
#endif
	/* Handshake succeeded */
	if (!SSL_session_reused(ctx->ssl)) {
		if (objt_server(conn->target)) {
			update_freq_ctr(&global.ssl_be_keys_per_sec, 1);
			if (global.ssl_be_keys_per_sec.curr_ctr > global.ssl_be_keys_max)
				global.ssl_be_keys_max = global.ssl_be_keys_per_sec.curr_ctr;
		}
		else {
			update_freq_ctr(&global.ssl_fe_keys_per_sec, 1);
			if (global.ssl_fe_keys_per_sec.curr_ctr > global.ssl_fe_keys_max)
				global.ssl_fe_keys_max = global.ssl_fe_keys_per_sec.curr_ctr;
		}

		if (counters) {
			HA_ATOMIC_INC(&counters->sess);
			HA_ATOMIC_INC(&counters_px->sess);
		}
	}
	else if (counters) {
		HA_ATOMIC_INC(&counters->reused_sess);
		HA_ATOMIC_INC(&counters_px->reused_sess);
	}

	TRACE_LEAVE(SSL_EV_CONN_HNDSHK, conn, ctx->ssl);

	/* The connection is now established at both layers, it's time to leave */
	conn->flags &= ~(flag | CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN);
	return 1;

 out_error:
	/* Clear openssl global errors stack */
	ssl_sock_dump_errors(conn, NULL);
	ERR_clear_error();

	/* free resumed session if exists */
	if (objt_server(conn->target)) {
		struct server *s = __objt_server(conn->target);
		/* RWLOCK: only rdlock the SSL cache even when writing in it because there is
		 * one cache per thread, it only prevents to flush it from the CLI in
		 * another thread */

		HA_RWLOCK_RDLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.lock);
		if (s->ssl_ctx.reused_sess[tid].ptr)
			ha_free(&s->ssl_ctx.reused_sess[tid].ptr);
		HA_RWLOCK_RDUNLOCK(SSL_SERVER_LOCK, &s->ssl_ctx.lock);
	}

	if (counters) {
		HA_ATOMIC_INC(&counters->failed_handshake);
		HA_ATOMIC_INC(&counters_px->failed_handshake);
	}

	/* Report an HS error only on SSL error */
	if (!(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH)))
		conn_report_term_evt(conn, tevt_loc_hs, hs_tevt_type_truncated_rcv_err);

	/* Fail on all other handshake errors */
	conn->flags |= CO_FL_ERROR;
	if (!conn->err_code)
		conn->err_code = CO_ER_SSL_HANDSHAKE;

	TRACE_ERROR("handshake error", SSL_EV_CONN_HNDSHK|SSL_EV_CONN_ERR, conn, ctx->ssl, &conn->err_code, &ctx->error_code);
	return 0;
}

/* Called from the upper layer, to subscribe <es> to events <event_type>. The
 * event subscriber <es> is not allowed to change from a previous call as long
 * as at least one event is still subscribed. The <event_type> must only be a
 * combination of SUB_RETRY_RECV and SUB_RETRY_SEND. It always returns 0,
 * unless the transport layer was already released.
 */
static int ssl_subscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;

	if (!ctx)
		return -1;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(ctx->subs && ctx->subs != es);

	ctx->subs = es;
	es->events |= event_type;

	/* we may have to subscribe to lower layers for new events */
	event_type &= ~ctx->wait_event.events;
	if (event_type && !(conn->flags & CO_FL_SSL_WAIT_HS))
		ctx->xprt->subscribe(conn, ctx->xprt_ctx, event_type, &ctx->wait_event);
	return 0;
}

/* Called from the upper layer, to unsubscribe <es> from events <event_type>.
 * The <es> pointer is not allowed to differ from the one passed to the
 * subscribe() call. It always returns zero.
 */
static int ssl_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, struct wait_event *es)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;

	BUG_ON(event_type & ~(SUB_RETRY_SEND|SUB_RETRY_RECV));
	BUG_ON(ctx->subs && ctx->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		ctx->subs = NULL;

	/* If we subscribed, and we're not doing the handshake,
	 * then we subscribed because the upper layer asked for it,
	 * as the upper layer is no longer interested, we can
	 * unsubscribe too.
	 */
	event_type &= ctx->wait_event.events;
	if (event_type && !(ctx->conn->flags & CO_FL_SSL_WAIT_HS))
		conn_unsubscribe(conn, ctx->xprt_ctx, event_type, &ctx->wait_event);

	return 0;
}

/* The connection has been taken over, so destroy the old tasklet and create
 * a new one. The original thread ID must be passed into orig_tid
 * It should be called with the takeover lock for the old thread held.
 * Returns 0 on success, and -1 on failure
 */
static int ssl_takeover(struct connection *conn, void *xprt_ctx, int orig_tid, int release)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;
	struct tasklet *tl = NULL;

	if (!release) {
		tl = tasklet_new();
		if (!tl)
			return -1;
	}

	ctx->wait_event.tasklet->context = NULL;
	tasklet_wakeup_on(ctx->wait_event.tasklet, orig_tid);

	ctx->wait_event.tasklet = tl;
	if (!release) {
		ctx->wait_event.tasklet->process = ssl_sock_io_cb;
		ctx->wait_event.tasklet->context = ctx;
	}

	return 0;
}

/* notify the next xprt that the connection is about to become idle and that it
 * may be stolen at any time after the function returns and that any tasklet in
 * the chain must be careful before dereferencing its context.
 */
static void ssl_set_idle(struct connection *conn, void *xprt_ctx)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;

	if (!ctx || !ctx->wait_event.tasklet)
		return;

	HA_ATOMIC_OR(&ctx->wait_event.tasklet->state, TASK_F_USR1);
	if (ctx->xprt)
		xprt_set_idle(conn, ctx->xprt, ctx->xprt_ctx);
}

/* notify the next xprt that the connection is not idle anymore and that it may
 * not be stolen before the next xprt_set_idle().
 */
static void ssl_set_used(struct connection *conn, void *xprt_ctx)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;

	if (!ctx || !ctx->wait_event.tasklet)
		return;

	HA_ATOMIC_AND(&ctx->wait_event.tasklet->state, ~TASK_F_USR1);
	if (ctx->xprt)
		xprt_set_used(conn, ctx->xprt, ctx->xprt_ctx);
}

/* Use the provided XPRT as an underlying XPRT, and provide the old one.
 * Returns 0 on success, and non-zero on failure.
 */
static int ssl_add_xprt(struct connection *conn, void *xprt_ctx, void *toadd_ctx, const struct xprt_ops *toadd_ops, void **oldxprt_ctx, const struct xprt_ops **oldxprt_ops)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;

	if (oldxprt_ops != NULL)
		*oldxprt_ops = ctx->xprt;
	if (oldxprt_ctx != NULL)
		*oldxprt_ctx = ctx->xprt_ctx;
	ctx->xprt = toadd_ops;
	ctx->xprt_ctx = toadd_ctx;
	return 0;
}

/* Remove the specified xprt. If if it our underlying XPRT, remove it and
 * return 0, otherwise just call the remove_xprt method from the underlying
 * XPRT.
 */
static int ssl_remove_xprt(struct connection *conn, void *xprt_ctx, void *toremove_ctx, const struct xprt_ops *newops, void *newctx)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;

	if (ctx->xprt_ctx == toremove_ctx) {
		ctx->xprt_ctx = newctx;
		ctx->xprt = newops;
		return 0;
	}
	return (ctx->xprt->remove_xprt(conn, ctx->xprt_ctx, toremove_ctx, newops, newctx));
}

struct task *ssl_sock_io_cb(struct task *t, void *context, unsigned int state)
{
	struct tasklet *tl = (struct tasklet *)t;
	struct ssl_sock_ctx *ctx = context;
	struct connection *conn;
	int conn_in_list;
	int ret = 0;

	TRACE_ENTER(SSL_EV_CONN_IO_CB, ctx->conn);

	if (state & TASK_F_USR1) {
		/* the tasklet was idling on an idle connection, it might have
		 * been stolen, let's be careful!
		 */
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		if (tl->context == NULL) {
			HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
			tasklet_free(tl);
			return NULL;
		}
		conn = ctx->conn;
		conn_in_list = conn->flags & CO_FL_LIST_MASK;
		if (conn_in_list)
			conn_delete_from_tree(conn);
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	} else {
		conn = ctx->conn;
		conn_in_list = 0;
	}

	/* First if we're doing an handshake, try that */
	if (ctx->conn->flags & CO_FL_SSL_WAIT_HS) {
		ssl_sock_handshake(ctx->conn, CO_FL_SSL_WAIT_HS);
		if (!(ctx->conn->flags & CO_FL_SSL_WAIT_HS)) {
			/* handshake completed, leave the bulk queue */
			_HA_ATOMIC_AND(&tl->state, ~TASK_HEAVY);
		}
	}
	/* If we had an error, or the handshake is done and I/O is available,
	 * let the upper layer know.
	 * If no mux was set up yet, then call conn_create_mux()
	 * we can't be sure conn_fd_handler() will be called again.
	 */
	if ((ctx->conn->flags & CO_FL_ERROR) ||
	    !(ctx->conn->flags & CO_FL_SSL_WAIT_HS)) {
		int woke = 0;

		/* On error, wake any waiter */
		if (ctx->subs) {
			tasklet_wakeup(ctx->subs->tasklet);
			ctx->subs->events = 0;
			woke = 1;
			ctx->subs = NULL;
		}

		/* If we're the first xprt for the connection, let the
		 * upper layers know. If we have no mux, create it,
		 * and once we have a mux, call its wake method if we didn't
		 * woke a tasklet already.
		 */
		if (ctx->conn->xprt_ctx == ctx) {
			int closed_connection = 0;

			if (!ctx->conn->mux)
				ret = conn_create_mux(ctx->conn, &closed_connection);
			if (ret >= 0 && !woke && ctx->conn->mux && ctx->conn->mux->wake) {
				ret = ctx->conn->mux->wake(ctx->conn);
				if (ret < 0)
					closed_connection = 1;
			}
			if (closed_connection)
				t = NULL;
			goto leave;
		}
	}
#ifdef SSL_READ_EARLY_DATA_SUCCESS
	/* If we have early data and somebody wants to receive, let them */
	else if (b_data(&ctx->early_buf) && ctx->subs &&
		 ctx->subs->events & SUB_RETRY_RECV) {
		tasklet_wakeup(ctx->subs->tasklet);
		ctx->subs->events &= ~SUB_RETRY_RECV;
		if (!ctx->subs->events)
			ctx->subs = NULL;
	}
#endif
leave:
	if (!ret && conn_in_list) {
		struct server *srv = objt_server(conn->target);

		TRACE_DEVEL("adding conn back to idle list", SSL_EV_CONN_IO_CB, conn);
		HA_SPIN_LOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
		_srv_add_idle(srv, conn, conn_in_list == CO_FL_SAFE_LIST);
		HA_SPIN_UNLOCK(IDLE_CONNS_LOCK, &idle_conns[tid].idle_conns_lock);
	}
	TRACE_LEAVE(SSL_EV_CONN_IO_CB, conn);
	return t;
}

/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 */
static size_t ssl_sock_to_buf(struct connection *conn, void *xprt_ctx, struct buffer *buf, size_t count, int flags)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;
	ssize_t ret;
	size_t try, done = 0;

	TRACE_ENTER(SSL_EV_CONN_RECV, conn);

	if (!ctx)
		goto out_error;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
	if (b_data(&ctx->early_buf)) {
		try = b_contig_space(buf);
		if (try > b_data(&ctx->early_buf))
			try = b_data(&ctx->early_buf);
		memcpy(b_tail(buf), b_head(&ctx->early_buf), try);
		b_add(buf, try);
		b_del(&ctx->early_buf, try);
		if (b_data(&ctx->early_buf) == 0)
			b_free(&ctx->early_buf);
		TRACE_STATE("read early data", SSL_EV_CONN_RECV|SSL_EV_CONN_RECV_EARLY, conn, &try);
		return try;
	}
#endif

	if (conn->flags & (CO_FL_WAIT_XPRT | CO_FL_SSL_WAIT_HS)) {
		/* a handshake was requested */
		TRACE_LEAVE(SSL_EV_CONN_RECV, conn);
		return 0;
	}

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {

		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > count)
			try = count;

		ret = SSL_read(ctx->ssl, b_tail(buf), try);

		if (conn->flags & CO_FL_ERROR) {
			/* CO_FL_ERROR may be set by ssl_sock_infocbk */
			goto out_error;
		}
		if (ret > 0) {
			b_add(buf, ret);
			done += ret;
			count -= ret;
			TRACE_DEVEL("Post SSL_read success", SSL_EV_CONN_RECV, conn, &ret);
		}
		else {
			ret =  SSL_get_error(ctx->ssl, ret);
			if (ret == SSL_ERROR_WANT_WRITE) {
				/* handshake is running, and it needs to enable write */
				conn->flags |= CO_FL_SSL_WAIT_HS;
				ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND, &ctx->wait_event);
#ifdef SSL_MODE_ASYNC
				/* Async mode can be re-enabled, because we're leaving data state.*/
				if (global_ssl.async)
					SSL_set_mode(ctx->ssl, SSL_MODE_ASYNC);
#endif
				TRACE_DEVEL("SSL want write", SSL_EV_CONN_RECV, conn);
				break;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				if (SSL_renegotiate_pending(ctx->ssl)) {
					ctx->xprt->subscribe(conn, ctx->xprt_ctx,
					                     SUB_RETRY_RECV,
							     &ctx->wait_event);
					/* handshake is running, and it may need to re-enable read */
					conn->flags |= CO_FL_SSL_WAIT_HS;
#ifdef SSL_MODE_ASYNC
					/* Async mode can be re-enabled, because we're leaving data state.*/
					if (global_ssl.async)
						SSL_set_mode(ctx->ssl, SSL_MODE_ASYNC);
#endif
					break;
				}
				TRACE_DEVEL("SSL want read", SSL_EV_CONN_RECV, conn);
				break;
			} else if (ret == SSL_ERROR_ZERO_RETURN) {
				TRACE_STATE("SSL read error (zero return)", SSL_EV_CONN_RECV, conn);
				goto read0;
			} else if (ret == SSL_ERROR_SSL) {
				struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);
				if (ctx && !ctx->error_code)
					ctx->error_code = ERR_peek_error();
				conn->err_code = CO_ER_SSL_FATAL;
			}
			/* For SSL_ERROR_SYSCALL, make sure to clear the error
			 * stack before shutting down the connection for
			 * reading. */
			if (ret == SSL_ERROR_SYSCALL && (!errno || errno == EAGAIN || errno == EWOULDBLOCK)) {
				TRACE_PROTO("SSL read error (syscall)", SSL_EV_CONN_RECV, conn);
				goto clear_ssl_error;
			}
			/* otherwise it's a real error */
			TRACE_ERROR("rx fatal error", SSL_EV_CONN_RECV|SSL_EV_CONN_ERR, conn, &ret);
			goto out_error;
		}
	}
 leave:
	TRACE_LEAVE(SSL_EV_CONN_RECV, conn);
	return done;

 clear_ssl_error:
	/* Clear openssl global errors stack */
	ssl_sock_dump_errors(conn, NULL);
	ERR_clear_error();
 read0:
	conn_report_term_evt(conn, tevt_loc_xprt, xprt_tevt_type_shutr);
	conn_sock_read0(conn);
	goto leave;

 out_error:
	TRACE_ERROR("rx error", SSL_EV_CONN_RECV, conn);
	conn_report_term_evt(conn, tevt_loc_xprt, xprt_tevt_type_rcv_err);
	conn->flags |= CO_FL_ERROR;
	/* Clear openssl global errors stack */
	ssl_sock_dump_errors(conn, NULL);
	ERR_clear_error();
	goto leave;
}


/* Send up to <count> pending bytes from buffer <buf> to connection <conn>'s
 * socket. <flags> may contain some CO_SFL_* flags to hint the system about
 * other pending data for example, but this flag is ignored at the moment.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this. The buffer's output is not adjusted, it's up to the
 * caller to take care of this. It's up to the caller to update the buffer's
 * contents based on the return value.
 */
static size_t ssl_sock_from_buf(struct connection *conn, void *xprt_ctx, const struct buffer *buf, size_t count, int flags)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;
	ssize_t ret;
	size_t try, done;

	TRACE_ENTER(SSL_EV_CONN_SEND, conn);

	done = 0;

	if (!ctx)
		goto out_error;

	if (conn->flags & (CO_FL_WAIT_XPRT | CO_FL_SSL_WAIT_HS | CO_FL_EARLY_SSL_HS)) {
		/* a handshake was requested */
		TRACE_LEAVE(SSL_EV_CONN_SEND, conn);
		return 0;
	}

	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (count) {
#ifdef SSL_READ_EARLY_DATA_SUCCESS
		size_t written_data;
#endif

		try = b_contig_data(buf, done);
		if (try > count)
			try = count;

		if (global_ssl.hard_max_record && try > global_ssl.hard_max_record)
			try = global_ssl.hard_max_record;

		if (!(flags & CO_SFL_STREAMER) &&
		    !(ctx->xprt_st & SSL_SOCK_SEND_UNLIMITED) &&
		    global_ssl.max_record && try > global_ssl.max_record) {
			try = global_ssl.max_record;
		}
		else {
			/* we need to keep the information about the fact that
			 * we're not limiting the upcoming send(), because if it
			 * fails, we'll have to retry with at least as many data.
			 */
			ctx->xprt_st |= SSL_SOCK_SEND_UNLIMITED;
		}

		if (try < count || flags & CO_SFL_MSG_MORE)
			ctx->xprt_st |= SSL_SOCK_SEND_MORE;
		else
			ctx->xprt_st &= ~SSL_SOCK_SEND_MORE;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
		if (!SSL_is_init_finished(ctx->ssl) && conn_is_back(conn)) {
			unsigned int max_early;

			if (objt_listener(conn->target))
				max_early = SSL_get_max_early_data(ctx->ssl);
			else {
				if (SSL_get0_session(ctx->ssl))
					max_early = SSL_SESSION_get_max_early_data(SSL_get0_session(ctx->ssl));
				else
					max_early = 0;
			}

			if (try + ctx->sent_early_data > max_early) {
				try -= (try + ctx->sent_early_data) - max_early;
				if (try <= 0) {
					conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;
					tasklet_wakeup(ctx->wait_event.tasklet);
					break;
				}
			}
			ret = SSL_write_early_data(ctx->ssl, b_peek(buf, done), try, &written_data);
			if (ret == 1) {
				ret = written_data;
				ctx->sent_early_data += ret;
				if (objt_server(conn->target)) {
					conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN | CO_FL_EARLY_DATA;
					/* Initiate the handshake, now */
					tasklet_wakeup(ctx->wait_event.tasklet);
				}
				TRACE_PROTO("Write early data", SSL_EV_CONN_SEND|SSL_EV_CONN_SEND_EARLY, conn, &ret);
			}

		} else
#endif
			ret = SSL_write(ctx->ssl, b_peek(buf, done), try);

		if (conn->flags & CO_FL_ERROR) {
			/* CO_FL_ERROR may be set by ssl_sock_infocbk */
			goto out_error;
		}
		if (ret > 0) {
			/* A send succeeded, so we can consider ourself connected */
			conn->flags &= ~CO_FL_WAIT_L4L6;
			ctx->xprt_st &= ~SSL_SOCK_SEND_UNLIMITED;
			count -= ret;
			done += ret;
			TRACE_DEVEL("Post SSL_write success", SSL_EV_CONN_SEND, conn, &ret);
		}
		else {
			ret = SSL_get_error(ctx->ssl, ret);

			if (ret == SSL_ERROR_WANT_WRITE) {
				if (SSL_renegotiate_pending(ctx->ssl)) {
					/* handshake is running, and it may need to re-enable write */
					conn->flags |= CO_FL_SSL_WAIT_HS;
					ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND, &ctx->wait_event);
#ifdef SSL_MODE_ASYNC
					/* Async mode can be re-enabled, because we're leaving data state.*/
					if (global_ssl.async)
						SSL_set_mode(ctx->ssl, SSL_MODE_ASYNC);
#endif
					break;
				}
				TRACE_DEVEL("SSL want write", SSL_EV_CONN_SEND, conn);
				break;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				/* handshake is running, and it needs to enable read */
				conn->flags |= CO_FL_SSL_WAIT_HS;
				ctx->xprt->subscribe(conn, ctx->xprt_ctx,
				                     SUB_RETRY_RECV,
						     &ctx->wait_event);
#ifdef SSL_MODE_ASYNC
				/* Async mode can be re-enabled, because we're leaving data state.*/
				if (global_ssl.async)
					SSL_set_mode(ctx->ssl, SSL_MODE_ASYNC);
#endif
				TRACE_DEVEL("SSL want read", SSL_EV_CONN_SEND, conn);
				break;
			}
			else if (ret == SSL_ERROR_SSL || ret == SSL_ERROR_SYSCALL) {
				struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);

				if (ctx && !ctx->error_code)
					ctx->error_code = ERR_peek_error();
				conn->err_code = CO_ER_SSL_FATAL;
				TRACE_ERROR("tx fatal error", SSL_EV_CONN_SEND|SSL_EV_CONN_ERR, conn, &ctx->error_code);
			}
			goto out_error;
		}
	}
 leave:
	TRACE_LEAVE(SSL_EV_CONN_SEND, conn);
	return done;

 out_error:
	TRACE_ERROR("tx error", SSL_EV_CONN_SEND, conn);
	/* Clear openssl global errors stack */
	ssl_sock_dump_errors(conn, NULL);
	ERR_clear_error();
	conn_report_term_evt(conn, tevt_loc_xprt, xprt_tevt_type_snd_err);
	conn->flags |= CO_FL_ERROR;
	goto leave;
}

void ssl_sock_close(struct connection *conn, void *xprt_ctx) {

	struct ssl_sock_ctx *ctx = xprt_ctx;

	TRACE_ENTER(SSL_EV_CONN_CLOSE, conn);

	if (ctx) {
		if (ctx->wait_event.events != 0)
			ctx->xprt->unsubscribe(ctx->conn, ctx->xprt_ctx,
			                       ctx->wait_event.events,
					       &ctx->wait_event);
		if (ctx->subs) {
			ctx->subs->events = 0;
			tasklet_wakeup(ctx->subs->tasklet);
		}

		if (ctx->xprt->close)
			ctx->xprt->close(conn, ctx->xprt_ctx);
#ifdef SSL_MODE_ASYNC
		if (global_ssl.async) {
			OSSL_ASYNC_FD all_fd[32], afd;
			size_t num_all_fds = 0;
			int i;

			SSL_get_all_async_fds(ctx->ssl, NULL, &num_all_fds);
			if (num_all_fds > 32) {
				send_log(NULL, LOG_EMERG, "haproxy: openssl returns too many async fds. It seems a bug. Process may crash\n");
				TRACE_ERROR("Too many async fds", SSL_EV_CONN_CLOSE|SSL_EV_CONN_ERR, conn);
				return;
			}

			SSL_get_all_async_fds(ctx->ssl, all_fd, &num_all_fds);

			/* If an async job is pending, we must try to
			   to catch the end using polling before calling
			   SSL_free */
			if (num_all_fds && SSL_waiting_for_async(ctx->ssl)) {
				for (i=0 ; i < num_all_fds ; i++) {
					/* switch on an handler designed to
					 * handle the SSL_free
					 */
					afd = all_fd[i];
					fdtab[afd].iocb = ssl_async_fd_free;
					fdtab[afd].owner = ctx->ssl;
					fd_want_recv(afd);
					/* To ensure that the fd cache won't be used
					 * and we'll catch a real RD event.
					 */
					fd_cant_recv(afd);
				}
				tasklet_free(ctx->wait_event.tasklet);
				pool_free(ssl_sock_ctx_pool, ctx);
				_HA_ATOMIC_INC(&jobs);
				TRACE_DEVEL("async end", SSL_EV_CONN_CLOSE, conn);
				return;
			}
			/* Else we can remove the fds from the fdtab
			 * and call SSL_free.
			 * note: we do a fd_stop_both and not a delete
			 * because the fd is  owned by the engine.
			 * the engine is responsible to close
			 */
			for (i=0 ; i < num_all_fds ; i++) {
				/* We want to remove the fd from the fdtab
				 * but we flag it to disown because the
				 * close is performed by the engine itself
				 */
				fdtab[all_fd[i]].state |= FD_DISOWN;
				fd_delete(all_fd[i]);
			}
		}
#endif
		SSL_free(ctx->ssl);
		b_free(&ctx->early_buf);
		tasklet_free(ctx->wait_event.tasklet);
		pool_free(ssl_sock_ctx_pool, ctx);
		_HA_ATOMIC_DEC(&global.sslconns);
	}
	TRACE_LEAVE(SSL_EV_CONN_CLOSE, conn);
}

/* This function tries to perform a clean shutdown on an SSL connection, and in
 * any case, flags the connection as reusable if no handshake was in progress.
 */
static void ssl_sock_shutw(struct connection *conn, void *xprt_ctx, int clean)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;

	TRACE_ENTER(SSL_EV_CONN_END, conn);

	if (conn->flags & (CO_FL_WAIT_XPRT | CO_FL_SSL_WAIT_HS))
		return;
	conn_report_term_evt(conn, tevt_loc_xprt, xprt_tevt_type_shutw);
	if (!clean)
		/* don't sent notify on SSL_shutdown */
		SSL_set_quiet_shutdown(ctx->ssl, 1);
	/* no handshake was in progress, try a clean ssl shutdown */
	if (SSL_shutdown(ctx->ssl) <= 0) {
		/* Clear openssl global errors stack */
		ssl_sock_dump_errors(conn, NULL);
		ERR_clear_error();
	}

	TRACE_LEAVE(SSL_EV_CONN_END, conn);
}


/* used for ppv2 pkey algo (can be used for logging) */
int ssl_sock_get_pkey_algo(struct connection *conn, struct buffer *out)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);
	X509 *crt;

	if (!ctx)
		return 0;
	crt = SSL_get_certificate(ctx->ssl);
	if (!crt)
		return 0;

	return cert_get_pkey_algo(crt, out);
}

/* used for ppv2 cert signature (can be used for logging) */
const char *ssl_sock_get_cert_sig(struct connection *conn)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);

	__OPENSSL_110_CONST__ ASN1_OBJECT *algorithm;
	X509 *crt;

	if (!ctx)
		return NULL;
	crt = SSL_get_certificate(ctx->ssl);
	if (!crt)
		return NULL;
	X509_ALGOR_get0(&algorithm, NULL, NULL, X509_get0_tbs_sigalg(crt));
	return OBJ_nid2sn(OBJ_obj2nid(algorithm));
}

/* used for ppv2 authority */
const char *ssl_sock_get_sni(struct connection *conn)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);

	if (!ctx)
		return NULL;
	return SSL_get_servername(ctx->ssl, TLSEXT_NAMETYPE_host_name);
#else
	return NULL;
#endif
}

/* used for logging/ppv2, may be changed for a sample fetch later */
const char *ssl_sock_get_cipher_name(struct connection *conn)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);

	if (!ctx)
		return NULL;
	return SSL_get_cipher_name(ctx->ssl);
}

/* used for logging/ppv2, may be changed for a sample fetch later */
const char *ssl_sock_get_proto_version(struct connection *conn)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);

	if (!ctx)
		return NULL;
	return SSL_get_version(ctx->ssl);
}

void ssl_sock_set_alpn(struct connection *conn, const unsigned char *alpn, int len)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);

	if (!ctx)
		return;
	SSL_set_alpn_protos(ctx->ssl, alpn, len);
#endif
}

/* Sets advertised SNI for outgoing connections. Please set <hostname> to NULL
 * to disable SNI.
 */
void ssl_sock_set_servername(struct connection *conn, const char *hostname)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);
	char *prev_name;

	if (!ctx)
		return;

	BUG_ON(!(conn->flags & CO_FL_WAIT_L6_CONN));
	BUG_ON(!(conn->flags & CO_FL_SSL_WAIT_HS));

	/* if the SNI changes, we must destroy the reusable context so that a
	 * new connection will present a new SNI. compare with the SNI
	 * previously stored in the reused_sess. If the session was reused,
	 * the associated SNI (if any) has already been assigned to the SSL
	 * during ssl_sock_init() so SSL_get_servername() will properly
	 * retrieve the currently known hostname for the SSL.
	 */

	prev_name = (char *)SSL_get_servername(ctx->ssl, TLSEXT_NAMETYPE_host_name);
	if ((!prev_name && hostname) ||
	    !hostname ||
	    strcmp(hostname, prev_name) != 0) {
		SSL_set_session(ctx->ssl, NULL);
		SSL_set_tlsext_host_name(ctx->ssl, hostname);
	}
#endif
}

/* Extract peer certificate's common name into the chunk dest
 * Returns
 *  the len of the extracted common name
 *  or 0 if no CN found in DN
 *  or -1 on error case (i.e. no peer certificate)
 */
int ssl_sock_get_remote_common_name(struct connection *conn,
				    struct buffer *dest)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);
	X509 *crt = NULL;
	X509_NAME *name;
	const char find_cn[] = "CN";
	const struct buffer find_cn_chunk = {
		.area = (char *)&find_cn,
		.data = sizeof(find_cn)-1
	};
	int result = -1;

	if (!ctx)
		goto out;

	/* SSL_get_peer_certificate, it increase X509 * ref count */
	crt = SSL_get_peer_certificate(ctx->ssl);
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
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);
	X509 *crt = NULL;

	if (!ctx)
		return 0;

	/* SSL_get_peer_certificate, it increase X509 * ref count */
	crt = SSL_get_peer_certificate(ctx->ssl);
	if (!crt)
		return 0;

	X509_free(crt);
	return 1;
}

/* returns 1 if client passed a certificate for this connection, 0 if not */
int ssl_sock_get_cert_used_conn(struct connection *conn)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);

	if (!ctx)
		return 0;
	return SSL_SOCK_ST_FL_VERIFY_DONE & ctx->xprt_st ? 1 : 0;
}

/* returns result from SSL verify */
unsigned int ssl_sock_get_verify_result(struct connection *conn)
{
	struct ssl_sock_ctx *ctx = conn_get_ssl_sock_ctx(conn);

	if (!ctx)
		return (unsigned int)X509_V_ERR_APPLICATION_VERIFICATION;
	return (unsigned int)SSL_get_verify_result(ctx->ssl);
}

/* Returns the application layer protocol name in <str> and <len> when known.
 * Zero is returned if the protocol name was not found, otherwise non-zero is
 * returned. The string is allocated in the SSL context and doesn't have to be
 * freed by the caller. NPN is also checked if available since older versions
 * of openssl (1.0.1) which are more common in field only support this one.
 */
int ssl_sock_get_alpn(const struct connection *conn, void *xprt_ctx, const char **str, int *len)
{
#if defined(TLSEXT_TYPE_application_layer_protocol_negotiation) || \
	defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	struct ssl_sock_ctx *ctx = xprt_ctx;
	if (!ctx)
		return 0;

	*str = NULL;

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	SSL_get0_alpn_selected(ctx->ssl, (const unsigned char **)str, (unsigned *)len);
	if (*str)
		return 1;
#endif
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	SSL_get0_next_proto_negotiated(ctx->ssl, (const unsigned char **)str, (unsigned *)len);
	if (*str)
		return 1;
#endif
#endif
	return 0;
}

/* "issuers-chain-path" load chain certificate in global */
int ssl_load_global_issuer_from_BIO(BIO *in, char *fp, char **err)
{
	X509 *ca;
	X509_NAME *name = NULL;
	ASN1_OCTET_STRING *skid = NULL;
	STACK_OF(X509) *chain = NULL;
	struct issuer_chain *issuer;
	struct eb64_node *node;
	char *path;
	u64 key;
	int ret = 0;

	while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
		if (chain == NULL) {
			chain = sk_X509_new_null();
			skid = X509_get_ext_d2i(ca, NID_subject_key_identifier, NULL, NULL);
			name = X509_get_subject_name(ca);
		}
		if (!sk_X509_push(chain, ca)) {
			X509_free(ca);
			goto end;
		}
	}
	if (!chain) {
		memprintf(err, "unable to load issuers-chain %s : pem certificate not found.\n", fp);
		goto end;
	}
	if (!skid) {
		memprintf(err, "unable to load issuers-chain %s : SubjectKeyIdentifier not found.\n", fp);
		goto end;
	}
	if (!name) {
		memprintf(err, "unable to load issuers-chain %s : SubjectName not found.\n", fp);
		goto end;
	}
	key = XXH3(ASN1_STRING_get0_data(skid), ASN1_STRING_length(skid), 0);
	for (node = eb64_lookup(&cert_issuer_tree, key); node; node = eb64_next(node)) {
		issuer = container_of(node, typeof(*issuer), node);
		if (!X509_NAME_cmp(name, X509_get_subject_name(sk_X509_value(issuer->chain, 0)))) {
			memprintf(err, "duplicate issuers-chain %s: %s already in store\n", fp, issuer->path);
			goto end;
		}
	}
	issuer = calloc(1, sizeof *issuer);
	path = strdup(fp);
	if (!issuer || !path) {
		free(issuer);
		free(path);
		goto end;
	}
	issuer->node.key = key;
	issuer->path = path;
	issuer->chain = chain;
	chain = NULL;
	eb64_insert(&cert_issuer_tree, &issuer->node);
	ret = 1;
 end:
	if (skid)
		ASN1_OCTET_STRING_free(skid);
	if (chain)
		sk_X509_pop_free(chain, X509_free);
	return ret;
}

 struct issuer_chain* ssl_get0_issuer_chain(X509 *cert)
{
	AUTHORITY_KEYID *akid;
	struct issuer_chain *issuer = NULL;

	akid = X509_get_ext_d2i(cert, NID_authority_key_identifier, NULL, NULL);
	if (akid && akid->keyid) {
		struct eb64_node *node;
		u64 hk;
		hk = XXH3(ASN1_STRING_get0_data(akid->keyid), ASN1_STRING_length(akid->keyid), 0);
		for (node = eb64_lookup(&cert_issuer_tree, hk); node; node = eb64_next(node)) {
			struct issuer_chain *ti = container_of(node, typeof(*issuer), node);
			if (X509_check_issued(sk_X509_value(ti->chain, 0), cert) == X509_V_OK) {
				issuer = ti;
				break;
			}
		}
	}
	AUTHORITY_KEYID_free(akid);
	return issuer;
}

void ssl_free_global_issuers(void)
{
	struct eb64_node *node, *back;
	struct issuer_chain *issuer;

	node = eb64_first(&cert_issuer_tree);
	while (node) {
		issuer = container_of(node, typeof(*issuer), node);
		back = eb64_next(node);
		eb64_delete(node);
		free(issuer->path);
		sk_X509_pop_free(issuer->chain, X509_free);
		free(issuer);
		node = back;
	}
}

#if defined(USE_ENGINE) && !defined(OPENSSL_NO_ENGINE)
static int ssl_check_async_engine_count(void) {
	int err_code = ERR_NONE;

	if (global_ssl.async && (openssl_engines_initialized > 32)) {
		ha_alert("ssl-mode-async only supports a maximum of 32 engines.\n");
		err_code = ERR_ABORT;
	}
	return err_code;
}
#endif

/* "show fd" helper to dump ssl internals. Warning: the output buffer is often
 * the common trash! It returns non-zero if the connection entry looks suspicious.
 */
static int ssl_sock_show_fd(struct buffer *buf, const struct connection *conn, const void *ctx)
{
	const struct ssl_sock_ctx *sctx = ctx;
	int ret = 0;

	if (!sctx)
		return ret;

	if (sctx->conn != conn) {
		chunk_appendf(&trash, " xctx.conn=%p(BOGUS)", sctx->conn);
		ret = 1;
	}
	chunk_appendf(&trash, " xctx.st=%d .err=%ld", sctx->xprt_st, sctx->error_code);

	if (sctx->xprt) {
		chunk_appendf(&trash, " .xprt=%s", sctx->xprt->name);
		if (sctx->xprt_ctx)
			chunk_appendf(&trash, " .xctx=%p", sctx->xprt_ctx);
	}

	chunk_appendf(&trash, " .wait.ev=%d", sctx->wait_event.events);

	/* as soon as a shutdown is reported the lower layer unregisters its
	 * subscriber, so the situations below are transient and rare enough to
	 * be reported as suspicious. In any case they shouldn't last.
	 */
	if ((sctx->wait_event.events & 1) && (conn->flags & (CO_FL_SOCK_RD_SH|CO_FL_ERROR)))
		ret = 1;
	if ((sctx->wait_event.events & 2) && (conn->flags & (CO_FL_SOCK_WR_SH|CO_FL_ERROR)))
		ret = 1;

	chunk_appendf(&trash, " .subs=%p", sctx->subs);
	if (sctx->subs) {
		chunk_appendf(&trash, "(ev=%d tl=%p", sctx->subs->events, sctx->subs->tasklet);
		if (sctx->subs->tasklet->calls >= 1000000)
			ret = 1;
		chunk_appendf(&trash, " tl.calls=%d tl.ctx=%p tl.fct=",
			      sctx->subs->tasklet->calls,
			      sctx->subs->tasklet->context);
		resolve_sym_name(&trash, NULL, sctx->subs->tasklet->process);
		chunk_appendf(&trash, ")");
	}
	chunk_appendf(&trash, " .sent_early=%d", sctx->sent_early_data);
	chunk_appendf(&trash, " .early_in=%d", (int)sctx->early_buf.data);
	return ret;
}

#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
/* This function is used with TLS ticket keys management. It permits to browse
 * each reference. The variable <ref> must point to the current node's list
 * element (which starts by the root), and <end> must point to the root node.
 */
static inline
struct tls_keys_ref *tlskeys_list_get_next(struct list *ref, struct list *end)
{
	/* Get next list entry. */
	ref = ref->n;

	/* If the entry is the last of the list, return NULL. */
	if (ref == end)
		return NULL;

	return LIST_ELEM(ref, struct tls_keys_ref *, list);
}

static inline
struct tls_keys_ref *tlskeys_ref_lookup_ref(const char *reference)
{
	int id;
	char *error;

	/* If the reference starts by a '#', this is numeric id. */
	if (reference[0] == '#') {
		/* Try to convert the numeric id. If the conversion fails, the lookup fails. */
		id = strtol(reference + 1, &error, 10);
		if (*error != '\0')
			return NULL;

		/* Perform the unique id lookup. */
		return tlskeys_ref_lookupid(id);
	}

	/* Perform the string lookup. */
	return tlskeys_ref_lookup(reference);
}
#endif


#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)

/* dumps all tls keys. Relies on the show_keys_ctx context from the appctx. */
static int cli_io_handler_tlskeys_files(struct appctx *appctx)
{
	struct show_keys_ctx *ctx = appctx->svcctx;

	switch (ctx->state) {
	case SHOW_KEYS_INIT:
		/* Display the column headers. If the message cannot be sent,
		 * quit the function with returning 0. The function is called
		 * later and restart at the state "SHOW_KEYS_INIT".
		 */
		chunk_reset(&trash);

		if (ctx->dump_entries)
			chunk_appendf(&trash, "# id secret\n");
		else
			chunk_appendf(&trash, "# id (file)\n");

		if (applet_putchk(appctx, &trash) == -1)
			return 0;

		/* Now, we start the browsing of the references lists.
		 * Note that the following call to LIST_ELEM return bad pointer. The only
		 * available field of this pointer is <list>. It is used with the function
		 * tlskeys_list_get_next() for returning the first available entry
		 */
		if (ctx->next_ref == NULL)
			ctx->next_ref = tlskeys_list_get_next(&tlskeys_reference, &tlskeys_reference);

		ctx->state = SHOW_KEYS_LIST;
		__fallthrough;

	case SHOW_KEYS_LIST:
		while (ctx->next_ref) {
			struct tls_keys_ref *ref = ctx->next_ref;

			chunk_reset(&trash);
			if (ctx->dump_entries && ctx->next_index == 0)
				chunk_appendf(&trash, "# ");

			if (ctx->next_index == 0)
				chunk_appendf(&trash, "%d (%s)\n", ref->unique_id, ref->filename);

			if (ctx->dump_entries) {
				int head;

				HA_RWLOCK_RDLOCK(TLSKEYS_REF_LOCK, &ref->lock);
				head = ref->tls_ticket_enc_index;
				while (ctx->next_index < TLS_TICKETS_NO) {
					struct buffer *t2 = get_trash_chunk();

					chunk_reset(t2);
					/* should never fail here because we dump only a key in the t2 buffer */
					if (ref->key_size_bits == 128) {
						t2->data = a2base64((char *)(ref->tlskeys + (head + 2 + ctx->next_index) % TLS_TICKETS_NO),
						                   sizeof(struct tls_sess_key_128),
						                   t2->area, t2->size);
						chunk_appendf(&trash, "%d.%d %s\n", ref->unique_id, ctx->next_index,
							      t2->area);
					}
					else if (ref->key_size_bits == 256) {
						t2->data = a2base64((char *)(ref->tlskeys + (head + 2 + ctx->next_index) % TLS_TICKETS_NO),
						                   sizeof(struct tls_sess_key_256),
						                   t2->area, t2->size);
						chunk_appendf(&trash, "%d.%d %s\n", ref->unique_id, ctx->next_index,
							      t2->area);
					}
					else {
						/* This case should never happen */
						chunk_appendf(&trash, "%d.%d <unknown>\n", ref->unique_id, ctx->next_index);
					}

					if (applet_putchk(appctx, &trash) == -1) {
						/* let's try again later from this stream. We add ourselves into
						 * this stream's users so that it can remove us upon termination.
						 */
						HA_RWLOCK_RDUNLOCK(TLSKEYS_REF_LOCK, &ref->lock);
						return 0;
					}
					ctx->next_index++;
				}
				HA_RWLOCK_RDUNLOCK(TLSKEYS_REF_LOCK, &ref->lock);
				ctx->next_index = 0;
			}
			if (applet_putchk(appctx, &trash) == -1) {
				/* let's try again later from this stream. We add ourselves into
				 * this stream's users so that it can remove us upon termination.
				 */
				return 0;
			}

			if (ctx->names_only == 0) /* don't display everything if not necessary */
				break;

			/* get next list entry and check the end of the list */
			ctx->next_ref = tlskeys_list_get_next(&ref->list, &tlskeys_reference);
		}
		ctx->state = SHOW_KEYS_DONE;
		__fallthrough;

	default:
		return 1;
	}
	return 0;
}

/* Prepares a "show_keys_ctx" and sets the appropriate io_handler if needed */
static int cli_parse_show_tlskeys(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct show_keys_ctx *ctx = applet_reserve_svcctx(appctx, sizeof(*ctx));

	/* no parameter, shows only file list */
	if (!*args[2]) {
		ctx->names_only = 1;
		return 0;
	}

	if (args[2][0] == '*') {
		/* list every TLS ticket keys */
		ctx->names_only = 1;
	} else {
		ctx->next_ref = tlskeys_ref_lookup_ref(args[2]);
		if (!ctx->next_ref)
			return cli_err(appctx, "'show tls-keys' unable to locate referenced filename\n");
	}

	ctx->dump_entries = 1;
	return 0;
}

static int cli_parse_set_tlskeys(char **args, char *payload, struct appctx *appctx, void *private)
{
	struct tls_keys_ref *ref;
	int ret;

	/* Expect two parameters: the filename and the new new TLS key in encoding */
	if (!*args[3] || !*args[4])
		return cli_err(appctx, "'set ssl tls-key' expects a filename and the new TLS key in base64 encoding.\n");

	ref = tlskeys_ref_lookup_ref(args[3]);
	if (!ref)
		return cli_err(appctx, "'set ssl tls-key' unable to locate referenced filename\n");

	ret = base64dec(args[4], strlen(args[4]), trash.area, trash.size);
	if (ret < 0)
		return cli_err(appctx, "'set ssl tls-key' received invalid base64 encoded TLS key.\n");

	trash.data = ret;
	if (ssl_sock_update_tlskey_ref(ref, &trash) < 0)
		return cli_err(appctx, "'set ssl tls-key' received a key of wrong size.\n");

	return cli_msg(appctx, LOG_INFO, "TLS ticket key updated!\n");
}
#endif


#ifdef HAVE_SSL_PROVIDERS
struct provider_name {
	const char *name;
	struct list list;
};


static int ssl_provider_get_name_cb(OSSL_PROVIDER *provider, void *cbdata)
{
	struct list *provider_names = cbdata;
	struct provider_name *item = NULL;
	const char *name = OSSL_PROVIDER_get0_name(provider);

	if (!provider_names)
		return 0;

	item = calloc(1, sizeof(*item));

	if (!item)
		return 0;

	item->name = name;
	LIST_APPEND(provider_names, &item->list);

	return 1;
}

static void ssl_provider_get_name_list(struct list *provider_names)
{
	if (!provider_names)
		return;

	OSSL_PROVIDER_do_all(NULL, ssl_provider_get_name_cb, provider_names);
}

static void ssl_provider_clear_name_list(struct list *provider_names)
{
	struct provider_name *item = NULL, *item_s = NULL;

	if (provider_names) {
		list_for_each_entry_safe(item, item_s, provider_names, list) {
			LIST_DELETE(&item->list);
			free(item);
		}
	}
}

static int cli_io_handler_show_providers(struct appctx *appctx)
{
	struct buffer *trash = get_trash_chunk();
	struct list provider_names;
	struct provider_name *name;

	LIST_INIT(&provider_names);

	chunk_appendf(trash, "Loaded providers : \n");

	ssl_provider_get_name_list(&provider_names);

	list_for_each_entry(name, &provider_names, list) {
		chunk_appendf(trash, "\t- %s\n", name->name);
	}

	ssl_provider_clear_name_list(&provider_names);

	if (applet_putchk(appctx, trash) == -1)
		goto yield;

	return 1;

yield:
	return 0;
}
#endif


/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
	{ { "show", "tls-keys", NULL },               "show tls-keys [id|*]                    : show tls keys references or dump tls ticket keys when id specified", cli_parse_show_tlskeys, cli_io_handler_tlskeys_files },
	{ { "set", "ssl", "tls-key", NULL },          "set ssl tls-key [id|file] <key>         : set the next TLS key for the <id> or <file> listener to <key>",      cli_parse_set_tlskeys, NULL },
#endif
#ifdef HAVE_SSL_PROVIDERS
	{ { "show", "ssl", "providers", NULL },    "show ssl providers                      : show loaded SSL providers", NULL, cli_io_handler_show_providers },
#endif
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/* transport-layer operations for SSL sockets */
struct xprt_ops ssl_sock = {
	.snd_buf  = ssl_sock_from_buf,
	.rcv_buf  = ssl_sock_to_buf,
	.subscribe = ssl_subscribe,
	.unsubscribe = ssl_unsubscribe,
	.remove_xprt = ssl_remove_xprt,
	.add_xprt = ssl_add_xprt,
	.rcv_pipe = NULL,
	.snd_pipe = NULL,
	.shutr    = NULL,
	.shutw    = ssl_sock_shutw,
	.close    = ssl_sock_close,
	.init     = ssl_sock_init,
	.start    = ssl_sock_start,
	.prepare_bind_conf = ssl_sock_prepare_bind_conf,
	.destroy_bind_conf = ssl_sock_destroy_bind_conf,
	.prepare_srv = ssl_sock_prepare_srv_ctx,
	.destroy_srv = ssl_sock_free_srv_ctx,
	.get_alpn = ssl_sock_get_alpn,
	.takeover = ssl_takeover,
	.set_idle = ssl_set_idle,
	.set_used = ssl_set_used,
	.get_ssl_sock_ctx = ssl_sock_get_ctx,
	.name     = "SSL",
	.show_fd  = ssl_sock_show_fd,
};

enum act_return ssl_action_wait_for_hs(struct act_rule *rule, struct proxy *px,
                                       struct session *sess, struct stream *s, int flags)
{
	struct connection *conn;

	conn = objt_conn(sess->origin);

	if (conn) {
		if (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_SSL_WAIT_HS)) {
			sc_ep_set(s->scf, SE_FL_WAIT_FOR_HS);
			s->req.flags |= CF_READ_EVENT;
			return ACT_RET_YIELD;
		}
	}
	return (ACT_RET_CONT);
}

static enum act_parse_ret ssl_parse_wait_for_hs(const char **args, int *orig_arg, struct proxy *px, struct act_rule *rule, char **err)
{
	rule->action_ptr = ssl_action_wait_for_hs;

	return ACT_RET_PRS_OK;
}

static struct action_kw_list http_req_actions = {ILH, {
	{ "wait-for-handshake", ssl_parse_wait_for_hs },
	{ /* END */ }
}};

INITCALL1(STG_REGISTER, http_req_keywords_register, &http_req_actions);

#ifdef HAVE_SSL_CTX_ADD_SERVER_CUSTOM_EXT

static void ssl_sock_sctl_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	if (ptr) {
		chunk_destroy(ptr);
		free(ptr);
	}
}

#endif


static void ssl_sock_capture_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	pool_free(pool_head_ssl_capture, ptr);
}

#ifdef HAVE_SSL_KEYLOG
static void ssl_sock_keylog_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	struct ssl_keylog *keylog;

	if (!ptr)
		return;

	keylog = ptr;

	pool_free(pool_head_ssl_keylog_str, keylog->client_random);
	pool_free(pool_head_ssl_keylog_str, keylog->client_early_traffic_secret);
	pool_free(pool_head_ssl_keylog_str, keylog->client_handshake_traffic_secret);
	pool_free(pool_head_ssl_keylog_str, keylog->server_handshake_traffic_secret);
	pool_free(pool_head_ssl_keylog_str, keylog->client_traffic_secret_0);
	pool_free(pool_head_ssl_keylog_str, keylog->server_traffic_secret_0);
	pool_free(pool_head_ssl_keylog_str, keylog->exporter_secret);
	pool_free(pool_head_ssl_keylog_str, keylog->early_exporter_secret);

	pool_free(pool_head_ssl_keylog, ptr);
}
#endif

static void ssl_sock_clt_crt_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	if (!ptr)
		return;

	X509_free((X509*)ptr);
}

static void ssl_sock_clt_sni_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	pool_free(ssl_sock_client_sni_pool, ptr);
}

static void __ssl_sock_init(void)
{
#if (!defined(OPENSSL_NO_COMP) && !defined(SSL_OP_NO_COMPRESSION))
	STACK_OF(SSL_COMP)* cm;
	int n;
#endif

	if (global_ssl.listen_default_ciphers)
		global_ssl.listen_default_ciphers = strdup(global_ssl.listen_default_ciphers);
	if (global_ssl.connect_default_ciphers)
		global_ssl.connect_default_ciphers = strdup(global_ssl.connect_default_ciphers);
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	if (global_ssl.listen_default_ciphersuites)
		global_ssl.listen_default_ciphersuites = strdup(global_ssl.listen_default_ciphersuites);
	if (global_ssl.connect_default_ciphersuites)
		global_ssl.connect_default_ciphersuites = strdup(global_ssl.connect_default_ciphersuites);
#endif

	xprt_register(XPRT_SSL, &ssl_sock);
#if HA_OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
#elif HA_OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_init_ssl(0, NULL);
#endif
#if (!defined(OPENSSL_NO_COMP) && !defined(SSL_OP_NO_COMPRESSION))
	cm = SSL_COMP_get_compression_methods();
	n = sk_SSL_COMP_num(cm);
	while (n--) {
		(void) sk_SSL_COMP_pop(cm);
	}
#endif

#if defined(USE_THREAD) && (HA_OPENSSL_VERSION_NUMBER < 0x10100000L)
	ssl_locking_init();
#endif
#ifdef HAVE_SSL_CTX_ADD_SERVER_CUSTOM_EXT
	sctl_ex_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, ssl_sock_sctl_free_func);
#endif

#if (defined(HAVE_SSL_OCSP) && !defined OPENSSL_IS_BORINGSSL)
	ocsp_ex_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, ssl_sock_ocsp_free_func);
#endif

	ssl_app_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	ssl_capture_ptr_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, ssl_sock_capture_free_func);
#ifdef USE_QUIC
	ssl_qc_app_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
#endif /* USE_QUIC */
#ifdef HAVE_SSL_KEYLOG
	ssl_keylog_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, ssl_sock_keylog_free_func);
#endif
	ssl_client_crt_ref_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, ssl_sock_clt_crt_free_func);
	ssl_client_sni_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, ssl_sock_clt_sni_free_func);
#if defined(USE_ENGINE) && !defined(OPENSSL_NO_ENGINE)
	ENGINE_load_builtin_engines();
	hap_register_post_check(ssl_check_async_engine_count);
#endif
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
	hap_register_post_check(tlskeys_finalize_config);
#endif

	global.ssl_session_max_cost   = SSL_SESSION_MAX_COST;
	global.ssl_handshake_max_cost = SSL_HANDSHAKE_MAX_COST;

	hap_register_post_deinit(ssl_free_global_issuers);

#ifndef OPENSSL_NO_DH
	ssl_dh_ptr_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	hap_register_post_deinit(ssl_free_dh);
#endif
#if defined(USE_ENGINE) && !defined(OPENSSL_NO_ENGINE)
	hap_register_post_deinit(ssl_free_engines);
#endif
#ifdef HAVE_SSL_PROVIDERS
	hap_register_post_deinit(ssl_unload_providers);
#endif
#if (HA_OPENSSL_VERSION_NUMBER < 0x3000000fL) && !defined(OPENSSL_IS_AWSLC)
	/* Load SSL string for the verbose & debug mode. */
	ERR_load_SSL_strings();
#endif
	ha_meth = BIO_meth_new(0x666, "ha methods");
	if (ha_meth != NULL) {
		BIO_meth_set_write(ha_meth, ha_ssl_write);
		BIO_meth_set_read(ha_meth, ha_ssl_read);
		BIO_meth_set_ctrl(ha_meth, ha_ssl_ctrl);
		BIO_meth_set_create(ha_meth, ha_ssl_new);
		BIO_meth_set_destroy(ha_meth, ha_ssl_free);
		BIO_meth_set_puts(ha_meth, ha_ssl_puts);
		BIO_meth_set_gets(ha_meth, ha_ssl_gets);
	}

	HA_SPIN_INIT(&ckch_lock);

#if defined(HAVE_SSL_OCSP)
	HA_SPIN_INIT(&ocsp_tree_lock);
#endif

	/* Try to register dedicated SSL/TLS protocol message callbacks for
	 * heartbleed attack (CVE-2014-0160) and clienthello.
	 */
	hap_register_post_check(ssl_sock_register_msg_callbacks);

	/* Try to free all callbacks that were registered by using
	 * ssl_sock_register_msg_callback().
	 */
	hap_register_post_deinit(ssl_sock_unregister_msg_callbacks);
}
INITCALL0(STG_REGISTER, __ssl_sock_init);

/* Compute and register the version string */
static void ssl_register_build_options()
{
	char *ptr = NULL;
	int i;

	memprintf(&ptr, "Built with SSL library version : "
#ifdef OPENSSL_IS_BORINGSSL
		"BoringSSL");
#else /* OPENSSL_IS_BORINGSSL */
	        OPENSSL_VERSION_TEXT
		"\nRunning on SSL library version : %s%s",
	       OpenSSL_version(OPENSSL_VERSION),
	       ((OPENSSL_VERSION_NUMBER ^ OpenSSL_version_num()) >> 8) ? " (VERSIONS DIFFER!)" : "");
#endif
	memprintf(&ptr, "%s\nSSL library supports TLS extensions : "
#if HA_OPENSSL_VERSION_NUMBER < 0x00907000L
		"no (library version too old)"
#elif defined(OPENSSL_NO_TLSEXT)
		"no (disabled via OPENSSL_NO_TLSEXT)"
#else
		"yes"
#endif
		"", ptr);

	memprintf(&ptr, "%s\nSSL library supports SNI : "
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
		"yes"
#else
#ifdef OPENSSL_NO_TLSEXT
		"no (because of OPENSSL_NO_TLSEXT)"
#else
		"no (version might be too old, 0.9.8f min needed)"
#endif
#endif
	       "", ptr);
#if defined(USE_OPENSSL) && (HA_OPENSSL_VERSION_NUMBER < 0x3000000fL)
	memprintf(&ptr, "%s\nSSL library FIPS mode : %s", ptr, FIPS_mode() ? "yes" : "no");
#endif
	memprintf(&ptr, "%s\nSSL library supports :", ptr);
	for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++)
		if (methodVersions[i].option)
			memprintf(&ptr, "%s %s", ptr, methodVersions[i].name);

#ifdef HAVE_SSL_PROVIDERS
	{
		struct list provider_names;
		struct provider_name *name;
		LIST_INIT(&provider_names);
		ssl_provider_get_name_list(&provider_names);

		memprintf(&ptr, "%s\nOpenSSL providers loaded :", ptr);

		list_for_each_entry(name, &provider_names, list) {
			memprintf(&ptr, "%s %s", ptr, name->name);
		}

		ssl_provider_clear_name_list(&provider_names);
	}
#endif

	hap_register_build_opts(ptr, 1);
}

INITCALL0(STG_REGISTER, ssl_register_build_options);

#if defined(USE_ENGINE) && !defined(OPENSSL_NO_ENGINE)
void ssl_free_engines(void) {
	struct ssl_engine_list *wl, *wlb;
	/* free up engine list */
	list_for_each_entry_safe(wl, wlb, &openssl_engines, list) {
		ENGINE_finish(wl->e);
		ENGINE_free(wl->e);
		LIST_DELETE(&wl->list);
		free(wl);
	}
}
#endif

#ifdef HAVE_SSL_PROVIDERS
void ssl_unload_providers(void) {
	struct ssl_provider_list *prov, *provb;
	list_for_each_entry_safe(prov, provb, &openssl_providers, list) {
		OSSL_PROVIDER_unload(prov->provider);
		LIST_DELETE(&prov->list);
		free(prov);
	}
}
#endif

#ifndef OPENSSL_NO_DH
void ssl_free_dh(void) {
	if (local_dh_1024) {
		HASSL_DH_free(local_dh_1024);
		local_dh_1024 = NULL;
	}
	if (local_dh_2048) {
		HASSL_DH_free(local_dh_2048);
		local_dh_2048 = NULL;
	}
	if (local_dh_4096) {
		HASSL_DH_free(local_dh_4096);
		local_dh_4096 = NULL;
	}
	if (global_dh) {
		HASSL_DH_free(global_dh);
		global_dh = NULL;
	}
}
#endif

static void __ssl_sock_deinit(void)
{

#if (HA_OPENSSL_VERSION_NUMBER < 0x10100000L)
        ERR_remove_state(0);
        ERR_free_strings();

        EVP_cleanup();
#endif

#if (HA_OPENSSL_VERSION_NUMBER >= 0x00907000L) && (HA_OPENSSL_VERSION_NUMBER < 0x10100000L)
        CRYPTO_cleanup_all_ex_data();
#endif
	BIO_meth_free(ha_meth);

#if defined(HAVE_SSL_OCSP)
	ssl_destroy_ocsp_update_task();
#endif
}
REGISTER_POST_DEINIT(__ssl_sock_deinit);


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
