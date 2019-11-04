
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

#include <import/lru.h>
#include <import/xxhash.h>

#include <common/buffer.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/errors.h>
#include <common/initcall.h>
#include <common/openssl-compat.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/cfgparse.h>
#include <common/base64.h>

#include <ebsttree.h>

#include <types/applet.h>
#include <types/cli.h>
#include <types/global.h>
#include <types/ssl_sock.h>
#include <types/stats.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/channel.h>
#include <proto/connection.h>
#include <proto/cli.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/frontend.h>
#include <proto/http_rules.h>
#include <proto/listener.h>
#include <proto/pattern.h>
#include <proto/proto_tcp.h>
#include <proto/http_ana.h>
#include <proto/server.h>
#include <proto/stream_interface.h>
#include <proto/log.h>
#include <proto/proxy.h>
#include <proto/shctx.h>
#include <proto/ssl_sock.h>
#include <proto/stream.h>
#include <proto/task.h>
#include <proto/vars.h>

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

/* ssl_methods flags for ssl options */
#define MC_SSL_O_ALL            0x0000
#define MC_SSL_O_NO_SSLV3       0x0001	/* disable SSLv3 */
#define MC_SSL_O_NO_TLSV10      0x0002	/* disable TLSv10 */
#define MC_SSL_O_NO_TLSV11      0x0004	/* disable TLSv11 */
#define MC_SSL_O_NO_TLSV12      0x0008	/* disable TLSv12 */
#define MC_SSL_O_NO_TLSV13      0x0010	/* disable TLSv13 */

/* ssl_methods versions */
enum {
	CONF_TLSV_NONE = 0,
	CONF_TLSV_MIN  = 1,
	CONF_SSLV3     = 1,
	CONF_TLSV10    = 2,
	CONF_TLSV11    = 3,
	CONF_TLSV12    = 4,
	CONF_TLSV13    = 5,
	CONF_TLSV_MAX  = 5,
};

/* server and bind verify method, it uses a global value as default */
enum {
	SSL_SOCK_VERIFY_DEFAULT  = 0,
	SSL_SOCK_VERIFY_REQUIRED = 1,
	SSL_SOCK_VERIFY_OPTIONAL = 2,
	SSL_SOCK_VERIFY_NONE     = 3,
};


int sslconns = 0;
int totalsslconns = 0;
static struct xprt_ops ssl_sock;
int nb_engines = 0;

static struct {
	char *crt_base;             /* base directory path for certificates */
	char *ca_base;              /* base directory path for CAs and CRLs */
	int  async;                 /* whether we use ssl async mode */

	char *listen_default_ciphers;
	char *connect_default_ciphers;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	char *listen_default_ciphersuites;
	char *connect_default_ciphersuites;
#endif
	int listen_default_ssloptions;
	int connect_default_ssloptions;
	struct tls_version_filter listen_default_sslmethods;
	struct tls_version_filter connect_default_sslmethods;

	int private_cache; /* Force to use a private session cache even if nbproc > 1 */
	unsigned int life_time;   /* SSL session lifetime in seconds */
	unsigned int max_record; /* SSL max record size */
	unsigned int default_dh_param; /* SSL maximum DH parameter size */
	int ctx_cache; /* max number of entries in the ssl_ctx cache. */
	int capture_cipherlist; /* Size of the cipherlist buffer. */
} global_ssl = {
#ifdef LISTEN_DEFAULT_CIPHERS
	.listen_default_ciphers = LISTEN_DEFAULT_CIPHERS,
#endif
#ifdef CONNECT_DEFAULT_CIPHERS
	.connect_default_ciphers = CONNECT_DEFAULT_CIPHERS,
#endif
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
#ifdef LISTEN_DEFAULT_CIPHERSUITES
	.listen_default_ciphersuites = LISTEN_DEFAULT_CIPHERSUITES,
#endif
#ifdef CONNECT_DEFAULT_CIPHERSUITES
	.connect_default_ciphersuites = CONNECT_DEFAULT_CIPHERSUITES,
#endif
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
	.default_dh_param = SSL_DEFAULT_DH_PARAM,
	.ctx_cache = DEFAULT_SSL_CTX_CACHE,
	.capture_cipherlist = 0,
};

static BIO_METHOD *ha_meth;

struct ssl_sock_ctx {
	struct connection *conn;
	SSL *ssl;
	BIO *bio;
	const struct xprt_ops *xprt;
	void *xprt_ctx;
	struct wait_event wait_event;
	struct wait_event *recv_wait;
	struct wait_event *send_wait;
	int xprt_st;                  /* transport layer state, initialized to zero */
	int tmp_early_data;           /* 1st byte of early data, if any */
	int sent_early_data;          /* Amount of early data we sent so far */

};

DECLARE_STATIC_POOL(ssl_sock_ctx_pool, "ssl_sock_ctx_pool", sizeof(struct ssl_sock_ctx));

static struct task *ssl_sock_io_cb(struct task *, void *, unsigned short);
static int ssl_sock_handshake(struct connection *conn, unsigned int flag);

/* Methods to implement OpenSSL BIO */
static int ha_ssl_write(BIO *h, const char *buf, int num)
{
	struct buffer tmpbuf;
	struct ssl_sock_ctx *ctx;
	int ret;

	ctx = BIO_get_data(h);
	tmpbuf.size = num;
	tmpbuf.area = (void *)(uintptr_t)buf;
	tmpbuf.data = num;
	tmpbuf.head = 0;
	ret = ctx->xprt->snd_buf(ctx->conn, ctx->xprt_ctx, &tmpbuf, num, 0);
	if (ret == 0 && !(ctx->conn->flags & (CO_FL_ERROR | CO_FL_SOCK_WR_SH))) {
		BIO_set_retry_write(h);
		ret = -1;
	} else if (ret == 0)
		 BIO_clear_retry_flags(h);
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
	if (ret == 0 && !(ctx->conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH))) {
		BIO_set_retry_read(h);
		ret = -1;
	} else if (ret == 0)
		BIO_clear_retry_flags(h);

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

__decl_hathreads(HA_SPINLOCK_T ckch_lock);

/* Uncommitted CKCH transaction */

static struct {
	struct ckch_store *new_ckchs;
	struct ckch_store *old_ckchs;
	char *path;
} ckchs_transaction;

/* This memory pool is used for capturing clienthello parameters. */
struct ssl_capture {
	unsigned long long int xxh64;
	unsigned char ciphersuite_len;
	char ciphersuite[0];
};
struct pool_head *pool_head_ssl_capture = NULL;
static int ssl_capture_ptr_index = -1;
static int ssl_app_data_index = -1;

static int ssl_pkey_info_index = -1;

#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
struct list tlskeys_reference = LIST_HEAD_INIT(tlskeys_reference);
#endif

#ifndef OPENSSL_NO_ENGINE
static unsigned int openssl_engines_initialized;
struct list openssl_engines = LIST_HEAD_INIT(openssl_engines);
struct ssl_engine_list {
	struct list list;
	ENGINE *e;
};
#endif

#ifndef OPENSSL_NO_DH
static int ssl_dh_ptr_index = -1;
static DH *global_dh = NULL;
static DH *local_dh_1024 = NULL;
static DH *local_dh_2048 = NULL;
static DH *local_dh_4096 = NULL;
static DH *ssl_get_tmp_dh(SSL *ssl, int export, int keylen);
#endif /* OPENSSL_NO_DH */

#if (defined SSL_CTRL_SET_TLSEXT_HOSTNAME && !defined SSL_NO_GENERATE_CERTIFICATES)
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
static unsigned int	  ssl_ctx_serial;
__decl_rwlock(ssl_ctx_lru_rwlock);

#endif // SSL_CTRL_SET_TLSEXT_HOSTNAME

static struct ssl_bind_kw ssl_bind_kws[];

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
/* The order here matters for picking a default context,
 * keep the most common keytype at the bottom of the list
 */
const char *SSL_SOCK_KEYTYPE_NAMES[] = {
	"dsa",
	"ecdsa",
	"rsa"
};
#define SSL_SOCK_NUM_KEYTYPES 3
#else
#define SSL_SOCK_NUM_KEYTYPES 1
#endif

static struct shared_context *ssl_shctx = NULL; /* ssl shared session cache */
static struct eb_root *sh_ssl_sess_tree; /* ssl shared session tree */

#define sh_ssl_sess_tree_delete(s)	ebmb_delete(&(s)->key);

#define sh_ssl_sess_tree_insert(s)	(struct sh_ssl_sess_hdr *)ebmb_insert(sh_ssl_sess_tree, \
								     &(s)->key, SSL_MAX_SSL_SESSION_ID_LENGTH);

#define sh_ssl_sess_tree_lookup(k)	(struct sh_ssl_sess_hdr *)ebmb_lookup(sh_ssl_sess_tree, \
								     (k), SSL_MAX_SSL_SESSION_ID_LENGTH);

/*
 * This function gives the detail of the SSL error. It is used only
 * if the debug mode and the verbose mode are activated. It dump all
 * the SSL error until the stack was empty.
 */
static forceinline void ssl_sock_dump_errors(struct connection *conn)
{
	unsigned long ret;

	if (unlikely(global.mode & MODE_DEBUG)) {
		while(1) {
			ret = ERR_get_error();
			if (ret == 0)
				return;
			fprintf(stderr, "fd[%04x] OpenSSL error[0x%lx] %s: %s\n",
			        (unsigned short)conn->handle.fd, ret,
			        ERR_func_error_string(ret), ERR_reason_error_string(ret));
		}
	}
}


#ifndef OPENSSL_NO_ENGINE
static int ssl_init_single_engine(const char *engine_id, const char *def_algorithms)
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
	el->e = engine;
	LIST_ADD(&openssl_engines, &el->list);
	nb_engines++;
	if (global_ssl.async)
		global.ssl_used_async_engines = nb_engines;
	return 0;

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

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
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
	ssl_sock_io_cb(NULL, ctx, 0);
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
	for (i=0 ; i < num_all_fds ; i++)
		fd_remove(all_fd[i]);

	/* Now we can safely call SSL_free, no more pending job in engines */
	SSL_free(ssl);
	_HA_ATOMIC_SUB(&sslconns, 1);
	_HA_ATOMIC_SUB(&jobs, 1);
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
	for (i=0 ; i < num_del_fds ; i++)
		fd_remove(del_fd[i]);

	/* We add new fds to the fdtab */
	for (i=0 ; i < num_add_fds ; i++) {
		fd_insert(add_fd[i], ctx, ssl_async_fd_handler, tid_bit);
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

#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
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
		return epoch - ((10 * (p[1] - '0') + p[2] - '0') * 60 * 60 + (10 * (p[3] - '0') + p[4] - '0')) * 60;
	}
	else if (p[0] == '-') {
		if (end - p != 5) return -1;
		/* Apply timezone offset */
		return epoch + ((10 * (p[1] - '0') + p[2] - '0') * 60 * 60 + (10 * (p[3] - '0') + p[4] - '0')) * 60;
	}

	return -1;
}

/*
 * struct alignment works here such that the key.key is the same as key_data
 * Do not change the placement of key_data
 */
struct certificate_ocsp {
	struct ebmb_node key;
	unsigned char key_data[OCSP_MAX_CERTID_ASN1_LENGTH];
	struct buffer response;
	long expire;
};

struct ocsp_cbk_arg {
	int is_single;
	int single_kt;
	union {
		struct certificate_ocsp *s_ocsp;
		/*
		 * m_ocsp will have multiple entries dependent on key type
		 * Entry 0 - DSA
		 * Entry 1 - ECDSA
		 * Entry 2 - RSA
		 */
		struct certificate_ocsp *m_ocsp[SSL_SOCK_NUM_KEYTYPES];
	};
};

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
static int ssl_sock_load_ocsp_response(struct buffer *ocsp_response,
				       struct certificate_ocsp *ocsp,
				       OCSP_CERTID *cid, char **err)
{
	OCSP_RESPONSE *resp;
	OCSP_BASICRESP *bs = NULL;
	OCSP_SINGLERESP *sr;
	OCSP_CERTID *id;
	unsigned char *p = (unsigned char *) ocsp_response->area;
	int rc , count_sr;
	ASN1_GENERALIZEDTIME *revtime, *thisupd, *nextupd = NULL;
	int reason;
	int ret = 1;

	resp = d2i_OCSP_RESPONSE(NULL, (const unsigned char **)&p,
				 ocsp_response->data);
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

	id = (OCSP_CERTID*)OCSP_SINGLERESP_get0_id(sr);

	rc = OCSP_single_get0_status(sr, &reason, &revtime, &thisupd, &nextupd);
	if (rc != V_OCSP_CERTSTATUS_GOOD && rc != V_OCSP_CERTSTATUS_REVOKED) {
		memprintf(err, "OCSP single response: certificate status is unknown");
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
		if (OCSP_id_cmp(id, cid)) {
			memprintf(err, "OCSP single response: Certificate ID does not match certificate and issuer");
			goto out;
		}
	}

	if (!ocsp) {
		unsigned char key[OCSP_MAX_CERTID_ASN1_LENGTH];
		unsigned char *p;

		rc = i2d_OCSP_CERTID(id, NULL);
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
		i2d_OCSP_CERTID(id, &p);
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
	ERR_clear_error();

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
int ssl_sock_update_ocsp_response(struct buffer *ocsp_response, char **err)
{
	return ssl_sock_load_ocsp_response(ocsp_response, NULL, NULL, err);
}

#endif

#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) || defined OPENSSL_IS_BORINGSSL)
/*
 * This function load the OCSP Resonse in DER format contained in file at
 * path 'ocsp_path' or base64 in a buffer <buf>
 *
 * Returns 0 on success, 1 in error case.
 */
static int ssl_sock_load_ocsp_response_from_file(const char *ocsp_path, char *buf, struct cert_key_and_chain *ckch, char **err)
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

	ckch->ocsp_response = ocsp_response;
	ret = 0;
end:
	if (fd != -1)
		close(fd);

	return ret;
}
#endif

#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
static int ssl_tlsext_ticket_key_cb(SSL *s, unsigned char key_name[16], unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
{
	struct tls_keys_ref *ref;
	union tls_sess_key *keys;
	struct connection *conn;
	int head;
	int i;
	int ret = -1; /* error by default */

	conn = SSL_get_ex_data(s, ssl_app_data_index);
	ref  = __objt_listener(conn->target)->bind_conf->keys_ref;
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

			HMAC_Init_ex(hctx, keys[head].key_128.hmac_key, 16, TLS_TICKET_HASH_FUNCT(), NULL);
			ret = 1;
		}
		else if (ref->key_size_bits == 256 ) {

			if(!EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, keys[head].key_256.aes_key, iv))
				goto end;

			HMAC_Init_ex(hctx, keys[head].key_256.hmac_key, 32, TLS_TICKET_HASH_FUNCT(), NULL);
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
			HMAC_Init_ex(hctx, keys[(head + i) % TLS_TICKETS_NO].key_128.hmac_key, 16, TLS_TICKET_HASH_FUNCT(), NULL);
			if(!EVP_DecryptInit_ex(ectx, EVP_aes_128_cbc(), NULL, keys[(head + i) % TLS_TICKETS_NO].key_128.aes_key, iv))
				goto end;
			/* 2 for key renewal, 1 if current key is still valid */
			ret = i ? 2 : 1;
		}
		else if (ref->key_size_bits == 256) {
			HMAC_Init_ex(hctx, keys[(head + i) % TLS_TICKETS_NO].key_256.hmac_key, 32, TLS_TICKET_HASH_FUNCT(), NULL);
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

/* Update the key into ref: if keysize doesnt
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
	return 0;
}
#endif /* SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB */

#ifndef OPENSSL_NO_OCSP
int ssl_sock_get_ocsp_arg_kt_index(int evp_keytype)
{
	switch (evp_keytype) {
	case EVP_PKEY_RSA:
		return 2;
	case EVP_PKEY_DSA:
		return 0;
	case EVP_PKEY_EC:
		return 1;
	}

	return -1;
}

/*
 * Callback used to set OCSP status extension content in server hello.
 */
int ssl_sock_ocsp_stapling_cbk(SSL *ssl, void *arg)
{
	struct certificate_ocsp *ocsp;
	struct ocsp_cbk_arg *ocsp_arg;
	char *ssl_buf;
	EVP_PKEY *ssl_pkey;
	int key_type;
	int index;

	ocsp_arg = arg;

	ssl_pkey = SSL_get_privatekey(ssl);
	if (!ssl_pkey)
		return SSL_TLSEXT_ERR_NOACK;

	key_type = EVP_PKEY_base_id(ssl_pkey);

	if (ocsp_arg->is_single && ocsp_arg->single_kt == key_type)
		ocsp = ocsp_arg->s_ocsp;
	else {
		/* For multiple certs per context, we have to find the correct OCSP response based on
		 * the certificate type
		 */
		index = ssl_sock_get_ocsp_arg_kt_index(key_type);

		if (index < 0)
			return SSL_TLSEXT_ERR_NOACK;

		ocsp = ocsp_arg->m_ocsp[index];

	}

	if (!ocsp ||
	    !ocsp->response.area ||
	    !ocsp->response.data ||
	    (ocsp->expire < now.tv_sec))
		return SSL_TLSEXT_ERR_NOACK;

	ssl_buf = OPENSSL_malloc(ocsp->response.data);
	if (!ssl_buf)
		return SSL_TLSEXT_ERR_NOACK;

	memcpy(ssl_buf, ocsp->response.area, ocsp->response.data);
	SSL_set_tlsext_status_ocsp_resp(ssl, ssl_buf, ocsp->response.data);

	return SSL_TLSEXT_ERR_OK;
}

#endif

#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) || defined OPENSSL_IS_BORINGSSL)
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
#ifndef OPENSSL_IS_BORINGSSL
static int ssl_sock_load_ocsp(SSL_CTX *ctx, const struct cert_key_and_chain *ckch)
{
	X509 *x = NULL, *issuer = NULL;
	OCSP_CERTID *cid = NULL;
	int i, ret = -1;
	struct certificate_ocsp *ocsp = NULL, *iocsp;
	char *warn = NULL;
	unsigned char *p;
	void (*callback) (void);


	x = ckch->cert;
	if (!x)
		goto out;

	issuer = ckch->ocsp_issuer;
	if (!issuer)
		goto out;

	cid = OCSP_cert_to_id(0, x, issuer);
	if (!cid)
		goto out;

	i = i2d_OCSP_CERTID(cid, NULL);
	if (!i || (i > OCSP_MAX_CERTID_ASN1_LENGTH))
		goto out;

	ocsp = calloc(1, sizeof(*ocsp));
	if (!ocsp)
		goto out;

	p = ocsp->key_data;
	i2d_OCSP_CERTID(cid, &p);

	iocsp = (struct certificate_ocsp *)ebmb_insert(&cert_ocsp_tree, &ocsp->key, OCSP_MAX_CERTID_ASN1_LENGTH);
	if (iocsp == ocsp)
		ocsp = NULL;

#ifndef SSL_CTX_get_tlsext_status_cb
# define SSL_CTX_get_tlsext_status_cb(ctx, cb) \
	*cb = (void (*) (void))ctx->tlsext_status_cb;
#endif
	SSL_CTX_get_tlsext_status_cb(ctx, &callback);

	if (!callback) {
		struct ocsp_cbk_arg *cb_arg = calloc(1, sizeof(*cb_arg));
		EVP_PKEY *pkey;

		cb_arg->is_single = 1;
		cb_arg->s_ocsp = iocsp;

		pkey = X509_get_pubkey(x);
		cb_arg->single_kt = EVP_PKEY_base_id(pkey);
		EVP_PKEY_free(pkey);

		SSL_CTX_set_tlsext_status_cb(ctx, ssl_sock_ocsp_stapling_cbk);
		SSL_CTX_set_tlsext_status_arg(ctx, cb_arg);
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

#ifdef SSL_CTX_get_tlsext_status_arg
		SSL_CTX_ctrl(ctx, SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG, 0, &cb_arg);
#else
		cb_arg = ctx->tlsext_status_arg;
#endif

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
		if (index >= 0 && !cb_arg->m_ocsp[index])
			cb_arg->m_ocsp[index] = iocsp;

	}

	ret = 0;

	warn = NULL;
	if (ssl_sock_load_ocsp_response(ckch->ocsp_response, ocsp, cid, &warn)) {
		memprintf(&warn, "Loading: %s. Content will be ignored", warn ? warn : "failure");
		ha_warning("%s.\n", warn);
	}

out:
	if (cid)
		OCSP_CERTID_free(cid);

	if (ocsp)
		free(ocsp);

	if (warn)
		free(warn);

	return ret;
}
#else /* OPENSSL_IS_BORINGSSL */
static int ssl_sock_load_ocsp(SSL_CTX *ctx, const struct cert_key_and_chain *ckch)
{
	return SSL_CTX_set_ocsp_response(ctx, (const uint8_t *)ckch->ocsp_response->area, ckch->ocsp_response->data);
}
#endif

#endif


#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)

#define CT_EXTENSION_TYPE 18

static int sctl_ex_index = -1;

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
static int ssl_sock_load_sctl_from_file(const char *sctl_path, char *buf, struct cert_key_and_chain *ckch, char **err)
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
	ret = 0;
	/* TODO: free the previous SCTL in the ckch */
	ckch->sctl = sctl;

end:
	if (fd != -1)
		close(fd);

	return ret;
}

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
	struct ssl_sock_ctx *ctx = conn->xprt_ctx;
	BIO *write_bio;
	(void)ret; /* shut gcc stupid warning */

#ifndef SSL_OP_NO_RENEGOTIATION
	/* Please note that BoringSSL defines this macro to zero so don't
	 * change this to #if and do not assign a default value to this macro!
	 */
	if (where & SSL_CB_HANDSHAKE_START) {
		/* Disable renegotiation (CVE-2009-3555) */
		if ((conn->flags & (CO_FL_CONNECTED | CO_FL_EARLY_SSL_HS | CO_FL_EARLY_DATA)) == CO_FL_CONNECTED) {
			conn->flags |= CO_FL_ERROR;
			conn->err_code = CO_ER_SSL_RENEG;
		}
	}
#endif

	if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
		if (!(ctx->xprt_st & SSL_SOCK_ST_FL_16K_WBFSIZE)) {
			/* Long certificate chains optimz
			   If write and read bios are differents, we
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
	struct ssl_sock_ctx *ctx;
	int err, depth;

	ssl = X509_STORE_CTX_get_ex_data(x_store, SSL_get_ex_data_X509_STORE_CTX_idx());
	conn = SSL_get_ex_data(ssl, ssl_app_data_index);

	ctx = conn->xprt_ctx;

	ctx->xprt_st |= SSL_SOCK_ST_FL_VERIFY_DONE;

	if (ok) /* no errors */
		return ok;

	depth = X509_STORE_CTX_get_error_depth(x_store);
	err = X509_STORE_CTX_get_error(x_store);

	/* check if CA error needs to be ignored */
	if (depth > 0) {
		if (!SSL_SOCK_ST_TO_CA_ERROR(ctx->xprt_st)) {
			ctx->xprt_st |= SSL_SOCK_CA_ERROR_TO_ST(err);
			ctx->xprt_st |= SSL_SOCK_CAEDEPTH_TO_ST(depth);
		}

		if (__objt_listener(conn->target)->bind_conf->ca_ignerr & (1ULL << err)) {
			ssl_sock_dump_errors(conn);
			ERR_clear_error();
			return 1;
		}

		conn->err_code = CO_ER_SSL_CA_FAIL;
		return 0;
	}

	if (!SSL_SOCK_ST_TO_CRTERROR(ctx->xprt_st))
		ctx->xprt_st |= SSL_SOCK_CRTERROR_TO_ST(err);

	/* check if certificate error needs to be ignored */
	if (__objt_listener(conn->target)->bind_conf->crt_ignerr & (1ULL << err)) {
		ssl_sock_dump_errors(conn);
		ERR_clear_error();
		return 1;
	}

	conn->err_code = CO_ER_SSL_CRT_FAIL;
	return 0;
}

static inline
void ssl_sock_parse_clienthello(int write_p, int version, int content_type,
                                const void *buf, size_t len, SSL *ssl)
{
	struct ssl_capture *capture;
	unsigned char *msg;
	unsigned char *end;
	size_t rec_len;

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
	 * message. The konwn types are:
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

	/* Expect 2 bytes for protocol version (1 byte for major and 1 byte
	 * for minor, the random, composed by 4 bytes for the unix time and
	 * 28 bytes for unix payload. So we jump 1 + 1 + 4 + 28.
	 */
	msg += 1 + 1 + 4 + 28;
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

	capture = pool_alloc_dirty(pool_head_ssl_capture);
	if (!capture)
		return;
	/* Compute the xxh64 of the ciphersuite. */
	capture->xxh64 = XXH64(msg, rec_len, 0);

	/* Capture the ciphersuite. */
	capture->ciphersuite_len = (global_ssl.capture_cipherlist < rec_len) ?
		global_ssl.capture_cipherlist : rec_len;
	memcpy(capture->ciphersuite, msg, capture->ciphersuite_len);

	SSL_set_ex_data(ssl, ssl_capture_ptr_index, capture);
}

/* Callback is called for ssl protocol analyse */
void ssl_sock_msgcbk(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
#ifdef TLS1_RT_HEARTBEAT
	/* test heartbeat received (write_p is set to 0
	   for a received record) */
	if ((content_type == TLS1_RT_HEARTBEAT) && (write_p == 0)) {
		struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
		struct ssl_sock_ctx *ctx = conn->xprt_ctx;
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
		return;
	}
#endif
	if (global_ssl.capture_cipherlist > 0)
		ssl_sock_parse_clienthello(write_p, version, content_type, buf, len, ssl);
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
 * negociable protocols for NPN.
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
 * negociable protocols for ALPN.
 */
static int ssl_sock_advertise_alpn_protos(SSL *s, const unsigned char **out,
                                          unsigned char *outlen,
                                          const unsigned char *server,
                                          unsigned int server_len, void *arg)
{
	struct ssl_bind_conf *conf = arg;

	if (SSL_select_next_proto((unsigned char**) out, outlen, (const unsigned char *)conf->alpn_str,
	                          conf->alpn_len, server, server_len) != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
#ifndef SSL_NO_GENERATE_CERTIFICATES

/* Create a X509 certificate with the specified servername and serial. This
 * function returns a SSL_CTX object or NULL if an error occurs. */
static SSL_CTX *
ssl_sock_do_create_cert(const char *servername, struct bind_conf *bind_conf, SSL *ssl)
{
	X509         *cacert  = bind_conf->ca_sign_cert;
	EVP_PKEY     *capkey  = bind_conf->ca_sign_pkey;
	SSL_CTX      *ssl_ctx = NULL;
	X509         *newcrt  = NULL;
	EVP_PKEY     *pkey    = NULL;
	SSL          *tmp_ssl = NULL;
	CONF         *ctmp    = NULL;
	X509_NAME    *name;
	const EVP_MD *digest;
	X509V3_CTX    ctx;
	unsigned int  i;
	int 	      key_type;

	/* Get the private key of the default certificate and use it */
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10002000L)
	pkey = SSL_CTX_get0_privatekey(bind_conf->default_ctx);
#else
	tmp_ssl = SSL_new(bind_conf->default_ctx);
	if (tmp_ssl)
		pkey = SSL_get_privatekey(tmp_ssl);
#endif
	if (!pkey)
		goto mkcert_error;

	/* Create the certificate */
	if (!(newcrt = X509_new()))
		goto mkcert_error;

	/* Set version number for the certificate (X509v3) and the serial
	 * number */
	if (X509_set_version(newcrt, 2L) != 1)
		goto mkcert_error;
	ASN1_INTEGER_set(X509_get_serialNumber(newcrt), _HA_ATOMIC_ADD(&ssl_ctx_serial, 1));

	/* Set duration for the certificate */
	if (!X509_gmtime_adj(X509_getm_notBefore(newcrt), (long)-60*60*24) ||
	    !X509_gmtime_adj(X509_getm_notAfter(newcrt),(long)60*60*24*365))
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
	ctmp = NCONF_new(NULL);
	X509V3_set_ctx(&ctx, cacert, newcrt, NULL, NULL, 0);
	for (i = 0; i < X509V3_EXT_SIZE; i++) {
		X509_EXTENSION *ext;

		if (!(ext = X509V3_EXT_nconf(ctmp, &ctx, x509v3_ext_names[i], x509v3_ext_values[i])))
			goto mkcert_error;
		if (!X509_add_ext(newcrt, ext, -1)) {
			X509_EXTENSION_free(ext);
			goto mkcert_error;
		}
		X509_EXTENSION_free(ext);
	}

	/* Sign the certificate with the CA private key */

	key_type = EVP_PKEY_base_id(capkey);

	if (key_type == EVP_PKEY_DSA)
		digest = EVP_sha1();
	else if (key_type == EVP_PKEY_RSA)
		digest = EVP_sha256();
	else if (key_type == EVP_PKEY_EC)
		digest = EVP_sha256();
	else {
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000000fL) && !defined(OPENSSL_IS_BORINGSSL)
		int nid;

		if (EVP_PKEY_get_default_digest_nid(capkey, &nid) <= 0)
			goto mkcert_error;
		if (!(digest = EVP_get_digestbynid(nid)))
			goto mkcert_error;
#else
		goto mkcert_error;
#endif
	}

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

#ifndef OPENSSL_NO_DH
	SSL_CTX_set_tmp_dh_callback(ssl_ctx, ssl_get_tmp_dh);
#endif
#if defined(SSL_CTX_set_tmp_ecdh) && !defined(OPENSSL_NO_ECDH)
	{
		const char *ecdhe = (bind_conf->ssl_conf.ecdhe ? bind_conf->ssl_conf.ecdhe : ECDHE_DEFAULT_CURVE);
		EC_KEY     *ecc;
		int         nid;

		if ((nid = OBJ_sn2nid(ecdhe)) == NID_undef)
			goto end;
		if (!(ecc = EC_KEY_new_by_curve_name(nid)))
			goto end;
		SSL_CTX_set_tmp_ecdh(ssl_ctx, ecc);
		EC_KEY_free(ecc);
	}
#endif
 end:
	return ssl_ctx;

 mkcert_error:
	if (ctmp) NCONF_free(ctmp);
	if (tmp_ssl) SSL_free(tmp_ssl);
	if (ssl_ctx) SSL_CTX_free(ssl_ctx);
	if (newcrt)  X509_free(newcrt);
	return NULL;
}

SSL_CTX *
ssl_sock_create_cert(struct connection *conn, const char *servername, unsigned int key)
{
	struct bind_conf *bind_conf = __objt_listener(conn->target)->bind_conf;
	struct ssl_sock_ctx *ctx = conn->xprt_ctx;

	return ssl_sock_do_create_cert(servername, bind_conf, ctx->ssl);
}

/* Do a lookup for a certificate in the LRU cache used to store generated
 * certificates and immediately assign it to the SSL session if not null. */
SSL_CTX *
ssl_sock_assign_generated_cert(unsigned int key, struct bind_conf *bind_conf, SSL *ssl)
{
	struct lru64 *lru = NULL;

	if (ssl_ctx_lru_tree) {
		HA_RWLOCK_WRLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		lru = lru64_lookup(key, ssl_ctx_lru_tree, bind_conf->ca_sign_cert, 0);
		if (lru && lru->domain) {
			if (ssl)
				SSL_set_SSL_CTX(ssl, (SSL_CTX *)lru->data);
			HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
			return (SSL_CTX *)lru->data;
		}
		HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
	}
	return NULL;
}

/* Same as <ssl_sock_assign_generated_cert> but without SSL session. This
 * function is not thread-safe, it should only be used to check if a certificate
 * exists in the lru cache (with no warranty it will not be removed by another
 * thread). It is kept for backward compatibility. */
SSL_CTX *
ssl_sock_get_generated_cert(unsigned int key, struct bind_conf *bind_conf)
{
	return ssl_sock_assign_generated_cert(key, bind_conf, NULL);
}

/* Set a certificate int the LRU cache used to store generated
 * certificate. Return 0 on success, otherwise -1 */
int
ssl_sock_set_generated_cert(SSL_CTX *ssl_ctx, unsigned int key, struct bind_conf *bind_conf)
{
	struct lru64 *lru = NULL;

	if (ssl_ctx_lru_tree) {
		HA_RWLOCK_WRLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		lru = lru64_get(key, ssl_ctx_lru_tree, bind_conf->ca_sign_cert, 0);
		if (!lru) {
			HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
			return -1;
		}
		if (lru->domain && lru->data)
			lru->free((SSL_CTX *)lru->data);
		lru64_commit(lru, ssl_ctx, bind_conf->ca_sign_cert, 0, (void (*)(void *))SSL_CTX_free);
		HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		return 0;
	}
	return -1;
}

/* Compute the key of the certificate. */
unsigned int
ssl_sock_generated_cert_key(const void *data, size_t len)
{
	return XXH32(data, len, ssl_ctx_lru_seed);
}

/* Generate a cert and immediately assign it to the SSL session so that the cert's
 * refcount is maintained regardless of the cert's presence in the LRU cache.
 */
static int
ssl_sock_generate_certificate(const char *servername, struct bind_conf *bind_conf, SSL *ssl)
{
	X509         *cacert  = bind_conf->ca_sign_cert;
	SSL_CTX      *ssl_ctx = NULL;
	struct lru64 *lru     = NULL;
	unsigned int  key;

	key = ssl_sock_generated_cert_key(servername, strlen(servername));
	if (ssl_ctx_lru_tree) {
		HA_RWLOCK_WRLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		lru = lru64_get(key, ssl_ctx_lru_tree, cacert, 0);
		if (lru && lru->domain)
			ssl_ctx = (SSL_CTX *)lru->data;
		if (!ssl_ctx && lru) {
			ssl_ctx = ssl_sock_do_create_cert(servername, bind_conf, ssl);
			lru64_commit(lru, ssl_ctx, cacert, 0, (void (*)(void *))SSL_CTX_free);
		}
		SSL_set_SSL_CTX(ssl, ssl_ctx);
		HA_RWLOCK_WRUNLOCK(SSL_GEN_CERTS_LOCK, &ssl_ctx_lru_rwlock);
		return 1;
	}
	else {
		ssl_ctx = ssl_sock_do_create_cert(servername, bind_conf, ssl);
		SSL_set_SSL_CTX(ssl, ssl_ctx);
		/* No LRU cache, this CTX will be released as soon as the session dies */
		SSL_CTX_free(ssl_ctx);
		return 1;
	}
	return 0;
}
static int
ssl_sock_generate_certificate_from_conn(struct bind_conf *bind_conf, SSL *ssl)
{
	unsigned int key;
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);

	if (conn_get_dst(conn)) {
		key = ssl_sock_generated_cert_key(conn->dst, get_addr_len(conn->dst));
		if (ssl_sock_assign_generated_cert(key, bind_conf, ssl))
			return 1;
	}
	return 0;
}
#endif /* !defined SSL_NO_GENERATE_CERTIFICATES */

#if (HA_OPENSSL_VERSION_NUMBER < 0x1010000fL)
typedef enum { SET_CLIENT, SET_SERVER } set_context_func;

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
typedef enum { SET_MIN, SET_MAX } set_context_func;

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
#if SSL_OP_NO_TLSv1_3
	c == SET_MAX ? SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)
		: SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
#endif
}
static void ssl_set_TLSv13_func(SSL *ssl, set_context_func c) {
#if SSL_OP_NO_TLSv1_3
	c == SET_MAX ? SSL_set_max_proto_version(ssl, TLS1_3_VERSION)
		: SSL_set_min_proto_version(ssl, TLS1_3_VERSION);
#endif
}
#endif
static void ctx_set_None_func(SSL_CTX *ctx, set_context_func c) { }
static void ssl_set_None_func(SSL *ssl, set_context_func c) { }

static struct {
	int      option;
	uint16_t flag;
	void   (*ctx_set_version)(SSL_CTX *, set_context_func);
	void   (*ssl_set_version)(SSL *, set_context_func);
	const char *name;
} methodVersions[] = {
	{0, 0, ctx_set_None_func, ssl_set_None_func, "NONE"},   /* CONF_TLSV_NONE */
	{SSL_OP_NO_SSLv3,   MC_SSL_O_NO_SSLV3,  ctx_set_SSLv3_func, ssl_set_SSLv3_func, "SSLv3"},    /* CONF_SSLV3 */
	{SSL_OP_NO_TLSv1,   MC_SSL_O_NO_TLSV10, ctx_set_TLSv10_func, ssl_set_TLSv10_func, "TLSv1.0"}, /* CONF_TLSV10 */
	{SSL_OP_NO_TLSv1_1, MC_SSL_O_NO_TLSV11, ctx_set_TLSv11_func, ssl_set_TLSv11_func, "TLSv1.1"}, /* CONF_TLSV11 */
	{SSL_OP_NO_TLSv1_2, MC_SSL_O_NO_TLSV12, ctx_set_TLSv12_func, ssl_set_TLSv12_func, "TLSv1.2"}, /* CONF_TLSV12 */
	{SSL_OP_NO_TLSv1_3, MC_SSL_O_NO_TLSV13, ctx_set_TLSv13_func, ssl_set_TLSv13_func, "TLSv1.3"}, /* CONF_TLSV13 */
};

static void ssl_sock_switchctx_set(SSL *ssl, SSL_CTX *ctx)
{
	SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ctx), ssl_sock_bind_verifycbk);
	SSL_set_client_CA_list(ssl, SSL_dup_CA_list(SSL_CTX_get_client_CA_list(ctx)));
	SSL_set_SSL_CTX(ssl, ctx);
}

#if ((HA_OPENSSL_VERSION_NUMBER >= 0x10101000L) || defined(OPENSSL_IS_BORINGSSL))

static int ssl_sock_switchctx_err_cbk(SSL *ssl, int *al, void *priv)
{
	struct bind_conf *s = priv;
	(void)al; /* shut gcc stupid warning */

	if (SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) || s->generate_certs)
		return SSL_TLSEXT_ERR_OK;
	return SSL_TLSEXT_ERR_NOACK;
}

#ifdef OPENSSL_IS_BORINGSSL
static int ssl_sock_switchctx_cbk(const struct ssl_early_callback_ctx *ctx)
{
	SSL *ssl = ctx->ssl;
#else
static int ssl_sock_switchctx_cbk(SSL *ssl, int *al, void *arg)
{
#endif
	struct connection *conn;
	struct bind_conf *s;
	const uint8_t *extension_data;
	size_t extension_len;
	int has_rsa_sig = 0, has_ecdsa_sig = 0;

	char *wildp = NULL;
	const uint8_t *servername;
	size_t servername_len;
	struct ebmb_node *node, *n, *node_ecdsa = NULL, *node_rsa = NULL, *node_anonymous = NULL;
	int allow_early = 0;
	int i;

	conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	s = __objt_listener(conn->target)->bind_conf;

	if (s->ssl_conf.early_data)
		allow_early = 1;
#ifdef OPENSSL_IS_BORINGSSL
	if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_server_name,
						 &extension_data, &extension_len)) {
#else
	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &extension_data, &extension_len)) {
#endif
		/*
		 * The server_name extension was given too much extensibility when it
		 * was written, so parsing the normal case is a bit complex.
		 */
		size_t len;
		if (extension_len <= 2)
			goto abort;
		/* Extract the length of the supplied list of names. */
		len = (*extension_data++) << 8;
		len |= *extension_data++;
		if (len + 2 != extension_len)
			goto abort;
		/*
		 * The list in practice only has a single element, so we only consider
		 * the first one.
		 */
		if (len == 0 || *extension_data++ != TLSEXT_NAMETYPE_host_name)
			goto abort;
		extension_len = len - 1;
		/* Now we can finally pull out the byte array with the actual hostname. */
		if (extension_len <= 2)
			goto abort;
		len = (*extension_data++) << 8;
		len |= *extension_data++;
		if (len == 0 || len + 2 > extension_len || len > TLSEXT_MAXLEN_host_name
		    || memchr(extension_data, 0, len) != NULL)
			goto abort;
		servername = extension_data;
		servername_len = len;
	} else {
#if (!defined SSL_NO_GENERATE_CERTIFICATES)
		if (s->generate_certs && ssl_sock_generate_certificate_from_conn(s, ssl)) {
			goto allow_early;
		}
#endif
		/* without SNI extension, is the default_ctx (need SSL_TLSEXT_ERR_NOACK) */
		if (!s->strict_sni) {
			HA_RWLOCK_RDLOCK(SNI_LOCK, &s->sni_lock);
			ssl_sock_switchctx_set(ssl, s->default_ctx);
			HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
			goto allow_early;
		}
		goto abort;
	}

	/* extract/check clientHello informations */
#ifdef OPENSSL_IS_BORINGSSL
	if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_signature_algorithms, &extension_data, &extension_len)) {
#else
	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_signature_algorithms, &extension_data, &extension_len)) {
#endif
		uint8_t sign;
		size_t len;
		if (extension_len < 2)
			goto abort;
		len = (*extension_data++) << 8;
		len |= *extension_data++;
		if (len + 2 != extension_len)
			goto abort;
		if (len % 2 != 0)
			goto abort;
		for (; len > 0; len -= 2) {
			extension_data++; /* hash */
			sign = *extension_data++;
			switch (sign) {
			case TLSEXT_signature_rsa:
				has_rsa_sig = 1;
				break;
			case TLSEXT_signature_ecdsa:
				has_ecdsa_sig = 1;
				break;
			default:
				continue;
			}
			if (has_ecdsa_sig && has_rsa_sig)
				break;
		}
	} else {
		/* without TLSEXT_TYPE_signature_algorithms extension (< TLSv1.2) */
		has_rsa_sig = 1;
	}
	if (has_ecdsa_sig) {  /* in very rare case: has ecdsa sign but not a ECDSA cipher */
		const SSL_CIPHER *cipher;
		size_t len;
		const uint8_t *cipher_suites;
		has_ecdsa_sig = 0;
#ifdef OPENSSL_IS_BORINGSSL
		len = ctx->cipher_suites_len;
		cipher_suites = ctx->cipher_suites;
#else
		len = SSL_client_hello_get0_ciphers(ssl, &cipher_suites);
#endif
		if (len % 2 != 0)
			goto abort;
		for (; len != 0; len -= 2, cipher_suites += 2) {
#ifdef OPENSSL_IS_BORINGSSL
			uint16_t cipher_suite = (cipher_suites[0] << 8) | cipher_suites[1];
			cipher = SSL_get_cipher_by_value(cipher_suite);
#else
			cipher = SSL_CIPHER_find(ssl, cipher_suites);
#endif
			if (cipher && SSL_CIPHER_get_auth_nid(cipher) == NID_auth_ecdsa) {
				has_ecdsa_sig = 1;
				break;
			}
		}
	}

	for (i = 0; i < trash.size && i < servername_len; i++) {
		trash.area[i] = tolower(servername[i]);
		if (!wildp && (trash.area[i] == '.'))
			wildp = &trash.area[i];
	}
	trash.area[i] = 0;

	HA_RWLOCK_RDLOCK(SNI_LOCK, &s->sni_lock);
	/* lookup in full qualified names */
	node = ebst_lookup(&s->sni_ctx, trash.area);

	/* lookup a not neg filter */
	for (n = node; n; n = ebmb_next_dup(n)) {
		if (!container_of(n, struct sni_ctx, name)->neg) {
			switch(container_of(n, struct sni_ctx, name)->kinfo.sig) {
			case TLSEXT_signature_ecdsa:
				if (!node_ecdsa)
					node_ecdsa = n;
				break;
			case TLSEXT_signature_rsa:
				if (!node_rsa)
					node_rsa = n;
				break;
			default: /* TLSEXT_signature_anonymous|dsa */
				if (!node_anonymous)
					node_anonymous = n;
				break;
			}
		}
	}
	if (wildp) {
		/* lookup in wildcards names */
		node = ebst_lookup(&s->sni_w_ctx, wildp);
		for (n = node; n; n = ebmb_next_dup(n)) {
			if (!container_of(n, struct sni_ctx, name)->neg) {
				switch(container_of(n, struct sni_ctx, name)->kinfo.sig) {
				case TLSEXT_signature_ecdsa:
					if (!node_ecdsa)
						node_ecdsa = n;
					break;
				case TLSEXT_signature_rsa:
					if (!node_rsa)
						node_rsa = n;
					break;
				default: /* TLSEXT_signature_anonymous|dsa */
					if (!node_anonymous)
						node_anonymous = n;
					break;
				}
			}
		}
	}
	/* select by key_signature priority order */
	node = (has_ecdsa_sig && node_ecdsa) ? node_ecdsa
		: ((has_rsa_sig && node_rsa) ? node_rsa
		   : (node_anonymous ? node_anonymous
		      : (node_ecdsa ? node_ecdsa      /* no ecdsa signature case (< TLSv1.2) */
			 : node_rsa                   /* no rsa signature case (far far away) */
			 )));
	if (node) {
		/* switch ctx */
		struct ssl_bind_conf *conf = container_of(node, struct sni_ctx, name)->conf;
		ssl_sock_switchctx_set(ssl, container_of(node, struct sni_ctx, name)->ctx);
			if (conf) {
				methodVersions[conf->ssl_methods.min].ssl_set_version(ssl, SET_MIN);
				methodVersions[conf->ssl_methods.max].ssl_set_version(ssl, SET_MAX);
				if (conf->early_data)
					allow_early = 1;
			}
			HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
			goto allow_early;
	}

	HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
#if (!defined SSL_NO_GENERATE_CERTIFICATES)
	if (s->generate_certs && ssl_sock_generate_certificate(trash.area, s, ssl)) {
		/* switch ctx done in ssl_sock_generate_certificate */
		goto allow_early;
	}
#endif
	if (!s->strict_sni) {
		/* no certificate match, is the default_ctx */
		HA_RWLOCK_RDLOCK(SNI_LOCK, &s->sni_lock);
		ssl_sock_switchctx_set(ssl, s->default_ctx);
		HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
	}
allow_early:
#ifdef OPENSSL_IS_BORINGSSL
	if (allow_early)
		SSL_set_early_data_enabled(ssl, 1);
#else
	if (!allow_early)
		SSL_set_max_early_data(ssl, 0);
#endif
	return 1;
 abort:
	/* abort handshake (was SSL_TLSEXT_ERR_ALERT_FATAL) */
	conn->err_code = CO_ER_SSL_HANDSHAKE;
#ifdef OPENSSL_IS_BORINGSSL
	return ssl_select_cert_error;
#else
	*al = SSL_AD_UNRECOGNIZED_NAME;
	return 0;
#endif
}

#else /* OPENSSL_IS_BORINGSSL */

/* Sets the SSL ctx of <ssl> to match the advertised server name. Returns a
 * warning when no match is found, which implies the default (first) cert
 * will keep being used.
 */
static int ssl_sock_switchctx_cbk(SSL *ssl, int *al, void *priv)
{
	const char *servername;
	const char *wildp = NULL;
	struct ebmb_node *node, *n;
	struct bind_conf *s = priv;
	int i;
	(void)al; /* shut gcc stupid warning */

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername) {
#if (!defined SSL_NO_GENERATE_CERTIFICATES)
		if (s->generate_certs && ssl_sock_generate_certificate_from_conn(s, ssl))
			return SSL_TLSEXT_ERR_OK;
#endif
		if (s->strict_sni)
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		HA_RWLOCK_RDLOCK(SNI_LOCK, &s->sni_lock);
		ssl_sock_switchctx_set(ssl, s->default_ctx);
		HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
		return SSL_TLSEXT_ERR_NOACK;
	}

	for (i = 0; i < trash.size; i++) {
		if (!servername[i])
			break;
		trash.area[i] = tolower(servername[i]);
		if (!wildp && (trash.area[i] == '.'))
			wildp = &trash.area[i];
	}
	trash.area[i] = 0;

	HA_RWLOCK_RDLOCK(SNI_LOCK, &s->sni_lock);
	/* lookup in full qualified names */
	node = ebst_lookup(&s->sni_ctx, trash.area);

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
#if (!defined SSL_NO_GENERATE_CERTIFICATES)
		if (s->generate_certs && ssl_sock_generate_certificate(servername, s, ssl)) {
			/* switch ctx done in ssl_sock_generate_certificate */
			HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
			return SSL_TLSEXT_ERR_OK;
		}
#endif
		if (s->strict_sni) {
			HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		}
		ssl_sock_switchctx_set(ssl, s->default_ctx);
		HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
		return SSL_TLSEXT_ERR_OK;
	}

	/* switch ctx */
	ssl_sock_switchctx_set(ssl, container_of(node, struct sni_ctx, name)->ctx);
	HA_RWLOCK_RDUNLOCK(SNI_LOCK, &s->sni_lock);
	return SSL_TLSEXT_ERR_OK;
}
#endif /* (!) OPENSSL_IS_BORINGSSL */
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

	BIGNUM *p;
	BIGNUM *g;
	DH *dh = DH_new();
	if (dh) {
		p = BN_bin2bn(dh1024_p, sizeof dh1024_p, NULL);
		g = BN_bin2bn(dh1024_g, sizeof dh1024_g, NULL);

		if (!p || !g) {
			DH_free(dh);
			dh = NULL;
		} else {
			DH_set0_pqg(dh, p, NULL, g);
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

	BIGNUM *p;
	BIGNUM *g;
	DH *dh = DH_new();
	if (dh) {
		p = BN_bin2bn(dh2048_p, sizeof dh2048_p, NULL);
		g = BN_bin2bn(dh2048_g, sizeof dh2048_g, NULL);

		if (!p || !g) {
			DH_free(dh);
			dh = NULL;
		} else {
			DH_set0_pqg(dh, p, NULL, g);
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

	BIGNUM *p;
	BIGNUM *g;
	DH *dh = DH_new();
	if (dh) {
		p = BN_bin2bn(dh4096_p, sizeof dh4096_p, NULL);
		g = BN_bin2bn(dh4096_g, sizeof dh4096_g, NULL);

		if (!p || !g) {
			DH_free(dh);
			dh = NULL;
		} else {
			DH_set0_pqg(dh, p, NULL, g);
		}
	}
	return dh;
}

/* Returns Diffie-Hellman parameters matching the private key length
   but not exceeding global_ssl.default_dh_param */
static DH *ssl_get_tmp_dh(SSL *ssl, int export, int keylen)
{
	DH *dh = NULL;
	EVP_PKEY *pkey = SSL_get_privatekey(ssl);
	int type;

	type = pkey ? EVP_PKEY_base_id(pkey) : EVP_PKEY_NONE;

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

/* Alloc and init a ckch_inst */
static struct ckch_inst *ckch_inst_new()
{
	struct ckch_inst *ckch_inst;

	ckch_inst = calloc(1, sizeof *ckch_inst);
	if (ckch_inst)
		LIST_INIT(&ckch_inst->sni_ctx);

	return ckch_inst;
}


/* This function allocates a sni_ctx and adds it to the ckch_inst */
static int ckch_inst_add_cert_sni(SSL_CTX *ctx, struct ckch_inst *ckch_inst,
                                 struct bind_conf *s, struct ssl_bind_conf *conf,
                                 struct pkey_info kinfo, char *name, int order)
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
		for (j = 0; j < len && j < trash.size; j++)
			trash.area[j] = tolower(name[j]);
		if (j >= trash.size)
			return -1;
		trash.area[j] = 0;

		sc = malloc(sizeof(struct sni_ctx) + len + 1);
		if (!sc)
			return -1;
		memcpy(sc->name.key, trash.area, len + 1);
		sc->ctx = ctx;
		sc->conf = conf;
		sc->kinfo = kinfo;
		sc->order = order++;
		sc->neg = neg;
		sc->wild = wild;
		sc->name.node.leaf_p = NULL;
		if (kinfo.sig != TLSEXT_signature_anonymous)
			SSL_CTX_set_ex_data(ctx, ssl_pkey_info_index, &sc->kinfo);

		LIST_ADDQ(&ckch_inst->sni_ctx, &sc->by_ckch_inst);
	}
	return order;
}

/*
 * Insert the sni_ctxs that are listed in the ckch_inst, in the bind_conf's sni_ctx tree
 * This function can't return an error.
 *
 * *CAUTION*: The caller must lock the sni tree if called in multithreading mode
 */
static void ssl_sock_load_cert_sni(struct ckch_inst *ckch_inst, struct bind_conf *bind_conf)
{

	struct sni_ctx *sc0, *sc0b, *sc1;
	struct ebmb_node *node;
	int def = 0;

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
				LIST_DEL(&sc0->by_ckch_inst);
				free(sc0);
				sc0 = NULL;
				break;
			}
		}

		/* if duplicate, ignore the insertion */
		if (!sc0)
			continue;

		if (sc0->wild)
			ebst_insert(&bind_conf->sni_w_ctx, &sc0->name);
		else
			ebst_insert(&bind_conf->sni_ctx, &sc0->name);

		/* replace the default_ctx if required with the first ctx */
		if (ckch_inst->is_default && !def) {
			/* we don't need to free the default_ctx because the refcount was not incremented */
			bind_conf->default_ctx = sc0->ctx;
			def = 1;
		}
	}
}

/*
 * tree used to store the ckchs ordered by filename/bundle name
 */
struct eb_root ckchs_tree = EB_ROOT_UNIQUE;


/* Loads Diffie-Hellman parameter from a ckchs to an SSL_CTX.
 *  If there is no DH paramater availaible in the ckchs, the global
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
static int ssl_sock_load_dh_params(SSL_CTX *ctx, const struct cert_key_and_chain *ckch,
                                   const char *path, char **err)
{
	int ret = 0;
	DH *dh = NULL;

	if (ckch && ckch->dh) {
		dh = ckch->dh;
		if (!SSL_CTX_set_tmp_dh(ctx, dh)) {
			memprintf(err, "%sunable to load the DH parameter specified in '%s'",
				  err && *err ? *err : "", path);
#if defined(SSL_CTX_set_dh_auto)
			SSL_CTX_set_dh_auto(ctx, 1);
			memprintf(err, "%s, SSL library will use an automatically generated DH parameter.\n",
				  err && *err ? *err : "");
#else
			memprintf(err, "%s, DH ciphers won't be available.\n",
				  err && *err ? *err : "");
#endif
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
		if (!SSL_CTX_set_tmp_dh(ctx, global_dh)) {
			memprintf(err, "%sunable to use the global DH parameter for certificate '%s'",
				  err && *err ? *err : "", path);
#if defined(SSL_CTX_set_dh_auto)
			SSL_CTX_set_dh_auto(ctx, 1);
			memprintf(err, "%s, SSL library will use an automatically generated DH parameter.\n",
				  err && *err ? *err : "");
#else
			memprintf(err, "%s, DH ciphers won't be available.\n",
				  err && *err ? *err : "");
#endif
			ret |= ERR_WARN;
			goto end;
		}
	}
	else {
		/* Clear openssl global errors stack */
		ERR_clear_error();

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

			if (!SSL_CTX_set_tmp_dh(ctx, local_dh_1024)) {
				memprintf(err, "%sunable to load default 1024 bits DH parameter for certificate '%s'.\n",
					  err && *err ? *err : "", path);
#if defined(SSL_CTX_set_dh_auto)
				SSL_CTX_set_dh_auto(ctx, 1);
				memprintf(err, "%s, SSL library will use an automatically generated DH parameter.\n",
					  err && *err ? *err : "");
#else
				memprintf(err, "%s, DH ciphers won't be available.\n",
					  err && *err ? *err : "");
#endif
				ret |= ERR_WARN;
				goto end;
			}
		}
		else {
			SSL_CTX_set_tmp_dh_callback(ctx, ssl_get_tmp_dh);
		}
	}

end:
	return ret;
}
#endif

/* Frees the contents of a cert_key_and_chain
 */
static void ssl_sock_free_cert_key_and_chain_contents(struct cert_key_and_chain *ckch)
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
static struct cert_key_and_chain *ssl_sock_copy_cert_key_and_chain(struct cert_key_and_chain *src,
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


/* checks if a key and cert exists in the ckch
 */
#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
static int ssl_sock_is_ckch_valid(struct cert_key_and_chain *ckch)
{
	return (ckch->cert != NULL && ckch->key != NULL);
}
#endif

/*
 * return 0 on success or != 0 on failure
 */
static int ssl_sock_load_issuer_file_into_ckch(const char *path, char *buf, struct cert_key_and_chain *ckch, char **err)
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
		          *err ? *err : "", path);
		goto end;
	}
	ret = 0;
	ckch->ocsp_issuer = issuer;

end:

	ERR_clear_error();
	if (in)
		BIO_free(in);

	return ret;
}


/*
 *  Try to load a PEM file from a <path> or a buffer <buf>
 *  The PEM must contain at least a Private Key and a Certificate,
 *  It could contain a DH and a certificate chain.
 *
 *  If it failed you should not attempt to use the ckch but free it.
 *
 *  Return 0 on success or != 0 on failure
 */
static int ssl_sock_load_pem_into_ckch(const char *path, char *buf, struct cert_key_and_chain *ckch , char **err)
{
	BIO *in = NULL;
	int ret = 1;
	X509 *ca;
	X509 *cert = NULL;
	EVP_PKEY *key = NULL;
	DH *dh;

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

#ifndef OPENSSL_NO_DH
	/* Seek back to beginning of file */
	if (BIO_reset(in) == -1) {
		memprintf(err, "%san error occurred while reading the file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

	dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
	/* no need to return an error there, dh is not mandatory */

	if (dh) {
		if (ckch->dh)
			DH_free(ckch->dh);
		ckch->dh = dh;
	}

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

	if (!X509_check_private_key(cert, key)) {
		memprintf(err, "%sinconsistencies between private key and certificate loaded from PEM file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

	/* Key and Cert are good, we can use them in the ckch */
	if (ckch->key) /* free the previous key */
		EVP_PKEY_free(ckch->key);
	ckch->key = key;
	key = NULL;

	if (ckch->cert) /* free the previous cert */
		X509_free(ckch->cert);
	ckch->cert = cert;
	cert = NULL;

	/* Look for a Certificate Chain */
	ca = PEM_read_bio_X509(in, NULL, NULL, NULL);
	if (ca) {
		/* there is a chain a in the PEM, clean the previous one in the CKCH */
		if (ckch->chain) /* free the previous chain */
			sk_X509_pop_free(ckch->chain, X509_free);
		ckch->chain = sk_X509_new_null();
		if (!sk_X509_push(ckch->chain, ca)) {
			X509_free(ca);
			goto end;
		}
	}
	/* look for other crt in the chain */
	while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL)))
		if (!sk_X509_push(ckch->chain, ca)) {
			X509_free(ca);
			goto end;
		}

	/* no chain */
	if (ckch->chain == NULL) {
		ckch->chain = sk_X509_new_null();
	}

	ret = ERR_get_error();
	if (ret && (ERR_GET_LIB(ret) != ERR_LIB_PEM && ERR_GET_REASON(ret) != PEM_R_NO_START_LINE)) {
		memprintf(err, "%sunable to load certificate chain from file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}

	ret = 0;

end:

	ERR_clear_error();
	if (in)
		BIO_free(in);
	if (key)
		EVP_PKEY_free(key);
	if (cert)
		X509_free(cert);

	return ret;
}

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
static int ssl_sock_load_files_into_ckch(const char *path, struct cert_key_and_chain *ckch, char **err)
{
	int ret = 1;

	/* try to load the PEM */
	if (ssl_sock_load_pem_into_ckch(path, NULL, ckch , err) != 0) {
		goto end;
	}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
	/* try to load the sctl file */
	{
		char fp[MAXPATHLEN+1];
		struct stat st;

		snprintf(fp, MAXPATHLEN+1, "%s.sctl", path);
		if (stat(fp, &st) == 0) {
			if (ssl_sock_load_sctl_from_file(fp, NULL, ckch, err)) {
				memprintf(err, "%s '%s.sctl' is present but cannot be read or parsed'.\n",
					  *err ? *err : "", fp);
				ret = 1;
				goto end;
			}
		}
	}
#endif

	/* try to load an ocsp response file */
	{
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
	if (ckch->ocsp_response) {
		X509 *issuer;
		int i;

		/* check if one of the certificate of the chain is the issuer */
		for (i = 0; i < sk_X509_num(ckch->chain); i++) {
			issuer = sk_X509_value(ckch->chain, i);
			if (X509_check_issued(issuer, ckch->cert) == X509_V_OK) {
				ckch->ocsp_issuer = issuer;
				break;
			} else
				issuer = NULL;
		}

		/* if no issuer was found, try to load an issuer from the .issuer */
		if (!issuer) {
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
						  *err ? *err : "", fp);
					ret = 1;
					goto end;
				}
			} else {
				memprintf(err, "%sNo issuer found, cannot use the OCSP response'.\n",
				          *err ? *err : "");
				ret = 1;
				goto end;
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

/* Loads the info in ckch into ctx
 * Returns a bitfield containing the flags:
 *     ERR_FATAL in any fatal error case
 *     ERR_ALERT if the reason of the error is available in err
 *     ERR_WARN if a warning is available into err
 * The value 0 means there is no error nor warning and
 * the operation succeed.
 */
static int ssl_sock_put_ckch_into_ctx(const char *path, const struct cert_key_and_chain *ckch, SSL_CTX *ctx, char **err)
{
	int errcode = 0;

	if (SSL_CTX_use_PrivateKey(ctx, ckch->key) <= 0) {
		memprintf(err, "%sunable to load SSL private key into SSL Context '%s'.\n",
				err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		return errcode;
	}

	if (!SSL_CTX_use_certificate(ctx, ckch->cert)) {
		memprintf(err, "%sunable to load SSL certificate into SSL Context '%s'.\n",
				err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* Load all certs in the ckch into the ctx_chain for the ssl_ctx */
#ifdef SSL_CTX_set1_chain
        if (!SSL_CTX_set1_chain(ctx, ckch->chain)) {
		memprintf(err, "%sunable to load chain certificate into SSL Context '%s'. Make sure you are linking against Openssl >= 1.0.2.\n",
			  err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}
#else
	{ /* legacy compat (< openssl 1.0.2) */
		X509 *ca;
		while ((ca = sk_X509_shift(ckch->chain)))
			if (!SSL_CTX_add_extra_chain_cert(ctx, ca)) {
				memprintf(err, "%sunable to load chain certificate into SSL Context '%s'.\n",
					  err && *err ? *err : "", path);
				X509_free(ca);
				errcode |= ERR_ALERT | ERR_FATAL;
				goto end;
			}
	}
#endif

#ifndef OPENSSL_NO_DH
	/* store a NULL pointer to indicate we have not yet loaded
	   a custom DH param file */
	if (ssl_dh_ptr_index >= 0) {
		SSL_CTX_set_ex_data(ctx, ssl_dh_ptr_index, NULL);
	}

	errcode |= ssl_sock_load_dh_params(ctx, ckch, path, err);
	if (errcode & ERR_CODE) {
		memprintf(err, "%sunable to load DH parameters from file '%s'.\n",
		          err && *err ? *err : "", path);
		goto end;
	}
#endif

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
	if (sctl_ex_index >= 0 && ckch->sctl) {
		if (ssl_sock_load_sctl(ctx, ckch->sctl) < 0) {
			memprintf(err, "%s '%s.sctl' is present but cannot be read or parsed'.\n",
			          *err ? *err : "", path);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
	}
#endif

#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) || defined OPENSSL_IS_BORINGSSL)
	/* Load OCSP Info into context */
	if (ckch->ocsp_response) {
		if (ssl_sock_load_ocsp(ctx, ckch) < 0) {
			if (err)
				memprintf(err, "%s '%s.ocsp' is present and activates OCSP but it is impossible to compute the OCSP certificate ID (maybe the issuer could not be found)'.\n",
				          *err ? *err : "", path);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
	}
#endif

 end:
	return errcode;
}

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL

static int ssl_sock_populate_sni_keytypes_hplr(const char *str, struct eb_root *sni_keytypes, int key_index)
{
	struct sni_keytype *s_kt = NULL;
	struct ebmb_node *node;
	int i;

	for (i = 0; i < trash.size; i++) {
		if (!str[i])
			break;
		trash.area[i] = tolower(str[i]);
	}
	trash.area[i] = 0;
	node = ebst_lookup(sni_keytypes, trash.area);
	if (!node) {
		/* CN not found in tree */
		s_kt = malloc(sizeof(struct sni_keytype) + i + 1);
		/* Using memcpy here instead of strncpy.
		 * strncpy will cause sig_abrt errors under certain versions of gcc with -O2
		 * See: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=60792
		 */
		if (!s_kt)
			return -1;

		memcpy(s_kt->name.key, trash.area, i+1);
		s_kt->keytypes = 0;
		ebst_insert(sni_keytypes, &s_kt->name);
	} else {
		/* CN found in tree */
		s_kt = container_of(node, struct sni_keytype, name);
	}

	/* Mark that this CN has the keytype of key_index via keytypes mask */
	s_kt->keytypes |= 1<<key_index;

	return 0;

}

#endif
/*
 * Free a ckch_store and its ckch(s)
 * The linked ckch_inst are not free'd
 */
void ckchs_free(struct ckch_store *ckchs)
{
	if (!ckchs)
		return;

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
	if (ckchs->multi) {
		int n;

		for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++)
			ssl_sock_free_cert_key_and_chain_contents(&ckchs->ckch[n]);
	} else
#endif
	{
		ssl_sock_free_cert_key_and_chain_contents(ckchs->ckch);
		ckchs->ckch = NULL;
	}

	free(ckchs);
}

/* allocate and duplicate a ckch_store
 * Return a new ckch_store or NULL */
static struct ckch_store *ckchs_dup(const struct ckch_store *src)
{
	struct ckch_store *dst;
	int pathlen;

	pathlen = strlen(src->path);
	dst = calloc(1, sizeof(*dst) + pathlen + 1);
	if (!dst)
		return NULL;
	/* copy previous key */
	memcpy(dst->path, src->path, pathlen + 1);
	dst->multi = src->multi;
	LIST_INIT(&dst->ckch_inst);

	dst->ckch = calloc((src->multi ? SSL_SOCK_NUM_KEYTYPES : 1), sizeof(*dst->ckch));
	if (!dst->ckch)
		goto error;

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
	ckchs_free(dst);

	return NULL;
}

/*
 * lookup a path into the ckchs tree.
 */
static inline struct ckch_store *ckchs_lookup(char *path)
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
static struct ckch_store *ckchs_load_cert_file(char *path, int multi, char **err)
{
	struct ckch_store *ckchs;

	ckchs = calloc(1, sizeof(*ckchs) + strlen(path) + 1);
	if (!ckchs) {
		memprintf(err, "%sunable to allocate memory.\n", err && *err ? *err : "");
		goto end;
	}
	ckchs->ckch = calloc(1, sizeof(*ckchs->ckch) * (multi ? SSL_SOCK_NUM_KEYTYPES : 1));

	if (!ckchs->ckch) {
		memprintf(err, "%sunable to allocate memory.\n", err && *err ? *err : "");
		goto end;
	}

	LIST_INIT(&ckchs->ckch_inst);

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
	if (ckchs) {
		free(ckchs->ckch);
		ebmb_delete(&ckchs->node);
	}

	free(ckchs);

	return NULL;
}

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL

/*
 * Take a ckch_store which contains a multi-certificate bundle.
 * Group these certificates into a set of SSL_CTX*
 * based on shared and unique CN and SAN entries. Add these SSL_CTX* to the SNI tree.
 *
 * This will allow the user to explicitly group multiple cert/keys for a single purpose
 *
 * Returns a bitfield containing the flags:
 *     ERR_FATAL in any fatal error case
 *     ERR_ALERT if the reason of the error is available in err
 *     ERR_WARN if a warning is available into err
 *
 */
static int ckch_inst_new_load_multi_store(const char *path, struct ckch_store *ckchs,
                                          struct bind_conf *bind_conf, struct ssl_bind_conf *ssl_conf,
                                          char **sni_filter, int fcount, struct ckch_inst **ckchi, char **err)
{
	int i = 0, n = 0;
	struct cert_key_and_chain *certs_and_keys;
	struct eb_root sni_keytypes_map = EB_ROOT;
	struct ebmb_node *node;
	struct ebmb_node *next;
	/* Array of SSL_CTX pointers corresponding to each possible combo
	 * of keytypes
	 */
	struct key_combo_ctx key_combos[SSL_SOCK_POSSIBLE_KT_COMBOS] = { {0} };
	int errcode = 0;
	X509_NAME *xname = NULL;
	char *str = NULL;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	STACK_OF(GENERAL_NAME) *names = NULL;
#endif
	struct ckch_inst *ckch_inst;

	*ckchi = NULL;

	if (!ckchs || !ckchs->ckch || !ckchs->multi) {
		memprintf(err, "%sunable to load SSL certificate file '%s' file does not exist.\n",
		          err && *err ? *err : "", path);
		return ERR_ALERT | ERR_FATAL;
	}

	ckch_inst = ckch_inst_new();
	if (!ckch_inst) {
		memprintf(err, "%sunable to allocate SSL context for cert '%s'.\n",
		          err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	certs_and_keys = ckchs->ckch;

	/* at least one of the instances is using filters during the config
	 * parsing, that's ok to inherit this during loading on CLI */
	ckchs->filters = !!fcount;

	/* Process each ckch and update keytypes for each CN/SAN
	 * for example, if CN/SAN www.a.com is associated with
	 * certs with keytype 0 and 2, then at the end of the loop,
	 * www.a.com will have:
	 *     keyindex = 0 | 1 | 4 = 5
	 */
	for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++) {
		int ret;

		if (!ssl_sock_is_ckch_valid(&certs_and_keys[n]))
			continue;

		if (fcount) {
			for (i = 0; i < fcount; i++) {
				ret = ssl_sock_populate_sni_keytypes_hplr(sni_filter[i], &sni_keytypes_map, n);
				if (ret < 0) {
					memprintf(err, "%sunable to allocate SSL context.\n",
					          err && *err ? *err : "");
					errcode |= ERR_ALERT | ERR_FATAL;
					goto end;
				}
			}
		} else {
			/* A lot of the following code is OpenSSL boilerplate for processing CN's and SAN's,
			 * so the line that contains logic is marked via comments
			 */
			xname = X509_get_subject_name(certs_and_keys[n].cert);
			i = -1;
			while ((i = X509_NAME_get_index_by_NID(xname, NID_commonName, i)) != -1) {
				X509_NAME_ENTRY *entry = X509_NAME_get_entry(xname, i);
				ASN1_STRING *value;
				value = X509_NAME_ENTRY_get_data(entry);
				if (ASN1_STRING_to_UTF8((unsigned char **)&str, value) >= 0) {
					/* Important line is here */
					ret = ssl_sock_populate_sni_keytypes_hplr(str, &sni_keytypes_map, n);

					OPENSSL_free(str);
					str = NULL;
					if (ret < 0) {
						memprintf(err, "%sunable to allocate SSL context.\n",
						          err && *err ? *err : "");
						errcode |= ERR_ALERT | ERR_FATAL;
						goto end;
					}
				}
			}

			/* Do the above logic for each SAN */
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
			names = X509_get_ext_d2i(certs_and_keys[n].cert, NID_subject_alt_name, NULL, NULL);
			if (names) {
				for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
					GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

					if (name->type == GEN_DNS) {
						if (ASN1_STRING_to_UTF8((unsigned char **)&str, name->d.dNSName) >= 0) {
							/* Important line is here */
							ret = ssl_sock_populate_sni_keytypes_hplr(str, &sni_keytypes_map, n);

							OPENSSL_free(str);
							str = NULL;
							if (ret < 0) {
								memprintf(err, "%sunable to allocate SSL context.\n",
								          err && *err ? *err : "");
								errcode |= ERR_ALERT | ERR_FATAL;
								goto end;
							}
						}
					}
				}
			}
		}
#endif /* SSL_CTRL_SET_TLSEXT_HOSTNAME */
	}

	/* If no files found, return error */
	if (eb_is_empty(&sni_keytypes_map)) {
		memprintf(err, "%sunable to load SSL certificate file '%s' file does not exist.\n",
		          err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* We now have a map of CN/SAN to keytypes that are loaded in
	 * Iterate through the map to create the SSL_CTX's (if needed)
	 * and add each CTX to the SNI tree
	 *
	 * Some math here:
	 *   There are 2^n - 1 possible combinations, each unique
	 *   combination is denoted by the key in the map. Each key
	 *   has a value between 1 and 2^n - 1. Conveniently, the array
	 *   of SSL_CTX* is sized 2^n. So, we can simply use the i'th
	 *   entry in the array to correspond to the unique combo (key)
	 *   associated with i. This unique key combo (i) will be associated
	 *   with combos[i-1]
	 */

	node = ebmb_first(&sni_keytypes_map);
	while (node) {
		SSL_CTX *cur_ctx;
		char cur_file[MAXPATHLEN+1];
		const struct pkey_info kinfo = { .sig = TLSEXT_signature_anonymous, .bits = 0 };

		str = (char *)container_of(node, struct sni_keytype, name)->name.key;
		i = container_of(node, struct sni_keytype, name)->keytypes;
		cur_ctx = key_combos[i-1].ctx;

		if (cur_ctx == NULL) {
			/* need to create SSL_CTX */
			cur_ctx = SSL_CTX_new(SSLv23_server_method());
			if (cur_ctx == NULL) {
				memprintf(err, "%sunable to allocate SSL context.\n",
				          err && *err ? *err : "");
				errcode |= ERR_ALERT | ERR_FATAL;
				goto end;
			}

			/* Load all required certs/keys/chains/OCSPs info into SSL_CTX */
			for (n = 0; n < SSL_SOCK_NUM_KEYTYPES; n++) {
				if (i & (1<<n)) {
					/* Key combo contains ckch[n] */
					snprintf(cur_file, MAXPATHLEN+1, "%s.%s", path, SSL_SOCK_KEYTYPE_NAMES[n]);
					errcode |= ssl_sock_put_ckch_into_ctx(cur_file, &certs_and_keys[n], cur_ctx, err);
					if (errcode & ERR_CODE)
						goto end;
				}
			}

			/* Update key_combos */
			key_combos[i-1].ctx = cur_ctx;
		}

		/* Update SNI Tree */

		key_combos[i-1].order = ckch_inst_add_cert_sni(cur_ctx, ckch_inst, bind_conf, ssl_conf,
		                                              kinfo, str, key_combos[i-1].order);
		if (key_combos[i-1].order < 0) {
			memprintf(err, "%sunable to create a sni context.\n", err && *err ? *err : "");
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}
		node = ebmb_next(node);
	}


	/* Mark a default context if none exists, using the ctx that has the most shared keys */
	if (!bind_conf->default_ctx) {
		for (i = SSL_SOCK_POSSIBLE_KT_COMBOS - 1; i >= 0; i--) {
			if (key_combos[i].ctx) {
				bind_conf->default_ctx = key_combos[i].ctx;
				bind_conf->default_ssl_conf = ssl_conf;
				ckch_inst->is_default = 1;
				break;
			}
		}
	}

	ckch_inst->bind_conf = bind_conf;
	ckch_inst->ssl_conf = ssl_conf;
end:

	if (names)
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);

	node = ebmb_first(&sni_keytypes_map);
	while (node) {
		next = ebmb_next(node);
		ebmb_delete(node);
		free(ebmb_entry(node, struct sni_keytype, name));
		node = next;
	}

	if (errcode & ERR_CODE && ckch_inst) {
		struct sni_ctx *sc0, *sc0b;

		/* free the SSL_CTX in case of error */
		for (i = 0; i < SSL_SOCK_POSSIBLE_KT_COMBOS; i++) {
			if (key_combos[i].ctx)
				SSL_CTX_free(key_combos[i].ctx);
		}

		/* free the sni_ctx in case of error */
		list_for_each_entry_safe(sc0, sc0b, &ckch_inst->sni_ctx, by_ckch_inst) {

			ebmb_delete(&sc0->name);
			LIST_DEL(&sc0->by_ckch_inst);
			free(sc0);
		}
		free(ckch_inst);
		ckch_inst = NULL;
	}

	*ckchi = ckch_inst;
	return errcode;
}
#else
/* This is a dummy, that just logs an error and returns error */
static int ckch_inst_new_load_multi_store(const char *path, struct ckch_store *ckchs,
                                          struct bind_conf *bind_conf, struct ssl_bind_conf *ssl_conf,
                                          char **sni_filter, int fcount, struct ckch_inst **ckchi, char **err)
{
	memprintf(err, "%sunable to stat SSL certificate from file '%s' : %s.\n",
	          err && *err ? *err : "", path, strerror(errno));
	return ERR_ALERT | ERR_FATAL;
}

#endif /* #if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL: Support for loading multiple certs into a single SSL_CTX */

/*
 * This function allocate a ckch_inst and create its snis
 *
 * Returns a bitfield containing the flags:
 *     ERR_FATAL in any fatal error case
 *     ERR_ALERT if the reason of the error is available in err
 *     ERR_WARN if a warning is available into err
 */
static int ckch_inst_new_load_store(const char *path, struct ckch_store *ckchs, struct bind_conf *bind_conf,
                                    struct ssl_bind_conf *ssl_conf, char **sni_filter, int fcount, struct ckch_inst **ckchi, char **err)
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
	struct cert_key_and_chain *ckch;
	struct ckch_inst *ckch_inst = NULL;
	int errcode = 0;

	*ckchi = NULL;

	if (!ckchs || !ckchs->ckch)
		return ERR_FATAL;

	ckch = ckchs->ckch;

	/* at least one of the instances is using filters during the config
	 * parsing, that's ok to inherit this during loading on CLI */
	ckchs->filters = !!fcount;

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		memprintf(err, "%sunable to allocate SSL context for cert '%s'.\n",
		          err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto error;
	}

	errcode |= ssl_sock_put_ckch_into_ctx(path, ckch, ctx, err);
	if (errcode & ERR_CODE)
		goto error;

	ckch_inst = ckch_inst_new();
	if (!ckch_inst) {
		memprintf(err, "%sunable to allocate SSL context for cert '%s'.\n",
		          err && *err ? *err : "", path);
		errcode |= ERR_ALERT | ERR_FATAL;
		goto error;
	}

	pkey = X509_get_pubkey(ckch->cert);
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
		names = X509_get_ext_d2i(ckch->cert, NID_subject_alt_name, NULL, NULL);
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
		xname = X509_get_subject_name(ckch->cert);
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

#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
	if (bind_conf->default_ctx) {
		memprintf(err, "%sthis version of openssl cannot load multiple SSL certificates.\n",
		          err && *err ? *err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto error;
	}
#endif
	if (!bind_conf->default_ctx) {
		bind_conf->default_ctx = ctx;
		bind_conf->default_ssl_conf = ssl_conf;
		ckch_inst->is_default = 1;
	}

	/* everything succeed, the ckch instance can be used */
	ckch_inst->bind_conf = bind_conf;
	ckch_inst->ssl_conf = ssl_conf;

	*ckchi = ckch_inst;
	return errcode;

error:
	/* free the allocated sni_ctxs */
	if (ckch_inst) {
		struct sni_ctx *sc0, *sc0b;

		list_for_each_entry_safe(sc0, sc0b, &ckch_inst->sni_ctx, by_ckch_inst) {

			ebmb_delete(&sc0->name);
			LIST_DEL(&sc0->by_ckch_inst);
			free(sc0);
		}
		free(ckch_inst);
		ckch_inst = NULL;
	}
	/* We only created 1 SSL_CTX so we can free it there */
	SSL_CTX_free(ctx);

	return errcode;
}

/* Returns a set of ERR_* flags possibly with an error in <err>. */
static int ssl_sock_load_ckchs(const char *path, struct ckch_store *ckchs,
                               struct bind_conf *bind_conf, struct ssl_bind_conf *ssl_conf,
                               char **sni_filter, int fcount, char **err)
{
	struct ckch_inst *ckch_inst = NULL;
	int errcode = 0;

	/* we found the ckchs in the tree, we can use it directly */
	if (ckchs->multi)
		errcode |= ckch_inst_new_load_multi_store(path, ckchs, bind_conf, ssl_conf, sni_filter, fcount, &ckch_inst, err);
	else
		errcode |= ckch_inst_new_load_store(path, ckchs, bind_conf, ssl_conf, sni_filter, fcount, &ckch_inst, err);

	if (errcode & ERR_CODE)
		return errcode;

	ssl_sock_load_cert_sni(ckch_inst, bind_conf);

	/* succeed, add the instance to the ckch_store's list of instance */
	LIST_ADDQ(&ckchs->ckch_inst, &ckch_inst->by_ckchs);
	return errcode;
}


/* Returns a set of ERR_* flags possibly with an error in <err>. */
int ssl_sock_load_cert(char *path, struct bind_conf *bind_conf, char **err)
{
	struct dirent **de_list;
	int i, n;
	DIR *dir;
	struct stat buf;
	char *end;
	char fp[MAXPATHLEN+1];
	int cfgerr = 0;
	struct ckch_store *ckchs;
#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
	int is_bundle;
	int j;
#endif
	if ((ckchs = ckchs_lookup(path))) {
		/* we found the ckchs in the tree, we can use it directly */
		return ssl_sock_load_ckchs(path, ckchs, bind_conf, NULL, NULL, 0, err);
	}

	if (stat(path, &buf) == 0) {
		dir = opendir(path);
		if (!dir) {
			ckchs =  ckchs_load_cert_file(path, 0,  err);
			if (!ckchs)
				return ERR_ALERT | ERR_FATAL;

			return ssl_sock_load_ckchs(path, ckchs, bind_conf, NULL, NULL, 0, err);
		}

		/* strip trailing slashes, including first one */
		for (end = path + strlen(path) - 1; end >= path && *end == '/'; end--)
			*end = 0;

		n = scandir(path, &de_list, 0, alphasort);
		if (n < 0) {
			memprintf(err, "%sunable to scan directory '%s' : %s.\n",
			          err && *err ? *err : "", path, strerror(errno));
			cfgerr |= ERR_ALERT | ERR_FATAL;
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
					cfgerr |= ERR_ALERT | ERR_FATAL;
					goto ignore_entry;
				}
				if (!S_ISREG(buf.st_mode))
					goto ignore_entry;

#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
				is_bundle = 0;
				/* Check if current entry in directory is part of a multi-cert bundle */

				if (end) {
					for (j = 0; j < SSL_SOCK_NUM_KEYTYPES; j++) {
						if (!strcmp(end + 1, SSL_SOCK_KEYTYPE_NAMES[j])) {
							is_bundle = 1;
							break;
						}
					}

					if (is_bundle) {
						int dp_len;

						dp_len = end - de->d_name;

						/* increment i and free de until we get to a non-bundle cert
						 * Note here that we look at de_list[i + 1] before freeing de
						 * this is important since ignore_entry will free de. This also
						 * guarantees that de->d_name continues to hold the same prefix.
						 */
						while (i + 1 < n && !strncmp(de_list[i + 1]->d_name, de->d_name, dp_len)) {
							free(de);
							i++;
							de = de_list[i];
						}

						snprintf(fp, sizeof(fp), "%s/%.*s", path, dp_len, de->d_name);
						if ((ckchs = ckchs_lookup(fp)) == NULL)
							ckchs =  ckchs_load_cert_file(fp, 1,  err);
						if (!ckchs)
							cfgerr |= ERR_ALERT | ERR_FATAL;
						else
							cfgerr |= ssl_sock_load_ckchs(path, ckchs, bind_conf, NULL, NULL, 0, err);
						/* Successfully processed the bundle */
						goto ignore_entry;
					}
				}

#endif
				if ((ckchs = ckchs_lookup(fp)) == NULL)
					ckchs =  ckchs_load_cert_file(fp, 0,  err);
				if (!ckchs)
					cfgerr |= ERR_ALERT | ERR_FATAL;
				else
					cfgerr |= ssl_sock_load_ckchs(path, ckchs, bind_conf, NULL, NULL, 0, err);

ignore_entry:
				free(de);
			}
			free(de_list);
		}
		closedir(dir);
		return cfgerr;
	}

	ckchs =  ckchs_load_cert_file(path, 1,  err);
	if (!ckchs)
		return ERR_ALERT | ERR_FATAL;

	cfgerr |= ssl_sock_load_ckchs(path, ckchs, bind_conf, NULL, NULL, 0, err);

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

/* release ssl bind conf */
void ssl_sock_free_ssl_conf(struct ssl_bind_conf *conf)
{
	if (conf) {
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
		free(conf->npn_str);
		conf->npn_str = NULL;
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
		free(conf->alpn_str);
		conf->alpn_str = NULL;
#endif
		free(conf->ca_file);
		conf->ca_file = NULL;
		free(conf->crl_file);
		conf->crl_file = NULL;
		free(conf->ciphers);
		conf->ciphers = NULL;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
		free(conf->ciphersuites);
		conf->ciphersuites = NULL;
#endif
		free(conf->curves);
		conf->curves = NULL;
		free(conf->ecdhe);
		conf->ecdhe = NULL;
	}
}

/* Returns a set of ERR_* flags possibly with an error in <err>. */
int ssl_sock_load_cert_list_file(char *file, struct bind_conf *bind_conf, struct proxy *curproxy, char **err)
{
	char thisline[CRT_LINESIZE];
	char path[MAXPATHLEN+1];
	FILE *f;
	struct stat buf;
	int linenum = 0;
	int cfgerr = 0;
	struct ckch_store *ckchs;

	if ((f = fopen(file, "r")) == NULL) {
		memprintf(err, "cannot open file '%s' : %s", file, strerror(errno));
		return ERR_ALERT | ERR_FATAL;
	}

	while (fgets(thisline, sizeof(thisline), f) != NULL) {
		int arg, newarg, cur_arg, i, ssl_b = 0, ssl_e = 0;
		char *end;
		char *args[MAX_CRT_ARGS + 1];
		char *line = thisline;
		char *crt_path;
		struct ssl_bind_conf *ssl_conf = NULL;

		linenum++;
		end = line + strlen(line);
		if (end-line == sizeof(thisline)-1 && *(end-1) != '\n') {
			/* Check if we reached the limit and the last char is not \n.
			 * Watch out for the last line without the terminating '\n'!
			 */
			memprintf(err, "line %d too long in file '%s', limit is %d characters",
				  linenum, file, (int)sizeof(thisline)-1);
			cfgerr |= ERR_ALERT | ERR_FATAL;
			break;
		}

		arg = 0;
		newarg = 1;
		while (*line) {
			if (*line == '#' || *line == '\n' || *line == '\r') {
				/* end of string, end of loop */
				*line = 0;
				break;
			} else if (isspace(*line)) {
				newarg = 1;
				*line = 0;
			} else if (*line == '[') {
				if (ssl_b) {
					memprintf(err, "too many '[' on line %d in file '%s'.", linenum, file);
					cfgerr |= ERR_ALERT | ERR_FATAL;
					break;
				}
				if (!arg) {
					memprintf(err, "file must start with a cert on line %d in file '%s'", linenum, file);
					cfgerr |= ERR_ALERT | ERR_FATAL;
					break;
				}
				ssl_b = arg;
				newarg = 1;
				*line = 0;
			} else if (*line == ']') {
				if (ssl_e) {
					memprintf(err, "too many ']' on line %d in file '%s'.", linenum, file);
					cfgerr |= ERR_ALERT | ERR_FATAL;
					break;
				}
				if (!ssl_b) {
					memprintf(err, "missing '[' in line %d in file '%s'.", linenum, file);
					cfgerr |= ERR_ALERT | ERR_FATAL;
					break;
				}
				ssl_e = arg;
				newarg = 1;
				*line = 0;
			} else if (newarg) {
				if (arg == MAX_CRT_ARGS) {
					memprintf(err, "too many args on line %d in file '%s'.", linenum, file);
					cfgerr |= ERR_ALERT | ERR_FATAL;
					break;
				}
				newarg = 0;
				args[arg++] = line;
			}
			line++;
		}
		if (cfgerr)
			break;
		args[arg++] = line;

		/* empty line */
		if (!*args[0])
			continue;

		crt_path = args[0];
		if (*crt_path != '/' && global_ssl.crt_base) {
			if ((strlen(global_ssl.crt_base) + 1 + strlen(crt_path)) > MAXPATHLEN) {
				memprintf(err, "'%s' : path too long on line %d in file '%s'",
					  crt_path, linenum, file);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				break;
			}
			snprintf(path, sizeof(path), "%s/%s",  global_ssl.crt_base, crt_path);
			crt_path = path;
		}

		ssl_conf = calloc(1, sizeof *ssl_conf);
		cur_arg = ssl_b ? ssl_b : 1;
		while (cur_arg < ssl_e) {
			newarg = 0;
			for (i = 0; ssl_bind_kws[i].kw != NULL; i++) {
				if (strcmp(ssl_bind_kws[i].kw, args[cur_arg]) == 0) {
					newarg = 1;
					cfgerr |= ssl_bind_kws[i].parse(args, cur_arg, curproxy, ssl_conf, err);
					if (cur_arg + 1 + ssl_bind_kws[i].skip > ssl_e) {
						memprintf(err, "ssl args out of '[]' for %s on line %d in file '%s'",
							  args[cur_arg], linenum, file);
						cfgerr |= ERR_ALERT | ERR_FATAL;
					}
					cur_arg += 1 + ssl_bind_kws[i].skip;
					break;
				}
			}
			if (!cfgerr && !newarg) {
				memprintf(err, "unknown ssl keyword %s on line %d in file '%s'.",
					  args[cur_arg], linenum, file);
				cfgerr |= ERR_ALERT | ERR_FATAL;
				break;
			}
		}

		if (cfgerr) {
			ssl_sock_free_ssl_conf(ssl_conf);
			free(ssl_conf);
			ssl_conf = NULL;
			break;
		}

		if ((ckchs = ckchs_lookup(crt_path)) == NULL) {
			if (stat(crt_path, &buf) == 0)
				ckchs = ckchs_load_cert_file(crt_path, 0,  err);
			else
				ckchs = ckchs_load_cert_file(crt_path, 1,  err);
		}

		if (!ckchs)
			cfgerr |= ERR_ALERT | ERR_FATAL;
		else
			cfgerr |= ssl_sock_load_ckchs(crt_path, ckchs, bind_conf, ssl_conf, &args[cur_arg], arg - cur_arg - 1, err);

		if (cfgerr) {
			memprintf(err, "error processing line %d in file '%s' : %s", linenum, file, *err);
			break;
		}
	}
	fclose(f);
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

	ctx = SSL_CTX_new(SSLv23_server_method());
	bind_conf->initial_ctx = ctx;

	if (conf_ssl_methods->flags && (conf_ssl_methods->min || conf_ssl_methods->max))
		ha_warning("Proxy '%s': no-sslv3/no-tlsv1x are ignored for bind '%s' at [%s:%d]. "
			   "Use only 'ssl-min-ver' and 'ssl-max-ver' to fix.\n",
			   bind_conf->frontend->id, bind_conf->arg, bind_conf->file, bind_conf->line);
	else
		flags = conf_ssl_methods->flags;

	min = conf_ssl_methods->min;
	max = conf_ssl_methods->max;
	/* start with TLSv10 to remove SSLv3 per default */
	if (!min && (!max || max >= CONF_TLSV10))
		min = CONF_TLSV10;
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
		for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++)
			if (flags & methodVersions[i].flag)
				options |= methodVersions[i].option;
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

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
	if (global_ssl.async)
		mode |= SSL_MODE_ASYNC;
#endif
	SSL_CTX_set_mode(ctx, mode);
	if (global_ssl.life_time)
		SSL_CTX_set_timeout(ctx, global_ssl.life_time);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
#ifdef OPENSSL_IS_BORINGSSL
	SSL_CTX_set_select_certificate_cb(ctx, ssl_sock_switchctx_cbk);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
#elif (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (bind_conf->ssl_conf.early_data) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
		SSL_CTX_set_max_early_data(ctx, global.tune.bufsize - global.tune.maxrewrite);
	}
	SSL_CTX_set_client_hello_cb(ctx, ssl_sock_switchctx_cbk, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_err_cbk);
#else
	SSL_CTX_set_tlsext_servername_callback(ctx, ssl_sock_switchctx_cbk);
#endif
	SSL_CTX_set_tlsext_servername_arg(ctx, bind_conf);
#endif
	return cfgerr;
}


static inline void sh_ssl_sess_free_blocks(struct shared_block *first, struct shared_block *block)
{
	if (first == block) {
		struct sh_ssl_sess_hdr *sh_ssl_sess = (struct sh_ssl_sess_hdr *)first->data;
		if (first->len > 0)
			sh_ssl_sess_tree_delete(sh_ssl_sess);
	}
}

/* return first block from sh_ssl_sess  */
static inline struct shared_block *sh_ssl_sess_first_block(struct sh_ssl_sess_hdr *sh_ssl_sess)
{
	return (struct shared_block *)((unsigned char *)sh_ssl_sess - ((struct shared_block *)NULL)->data);

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
		shctx_row_dec_hot(ssl_shctx, first);
		/* replace the previous session already in the tree */
		sh_ssl_sess = oldsh_ssl_sess;
		/* ignore the previous session data, only use the header */
		first = sh_ssl_sess_first_block(sh_ssl_sess);
		shctx_row_inc_hot(ssl_shctx, first);
		first->len = sizeof(struct sh_ssl_sess_hdr);
	}

	if (shctx_row_data_append(ssl_shctx, first, NULL, data, data_len) < 0) {
		shctx_row_dec_hot(ssl_shctx, first);
		return 0;
	}

	shctx_row_dec_hot(ssl_shctx, first);

	return 1;
}

/* SSL callback used when a new session is created while connecting to a server */
static int ssl_sess_new_srv_cb(SSL *ssl, SSL_SESSION *sess)
{
	struct connection *conn = SSL_get_ex_data(ssl, ssl_app_data_index);
	struct server *s;

	s = __objt_server(conn->target);

	if (!(s->ssl_ctx.options & SRV_SSL_O_NO_REUSE)) {
		int len;
		unsigned char *ptr;

		len = i2d_SSL_SESSION(sess, NULL);
		if (s->ssl_ctx.reused_sess[tid].ptr && s->ssl_ctx.reused_sess[tid].allocated_size >= len) {
			ptr = s->ssl_ctx.reused_sess[tid].ptr;
		} else {
			free(s->ssl_ctx.reused_sess[tid].ptr);
			ptr = s->ssl_ctx.reused_sess[tid].ptr = malloc(len);
			s->ssl_ctx.reused_sess[tid].allocated_size = len;
		}
		if (s->ssl_ctx.reused_sess[tid].ptr) {
			s->ssl_ctx.reused_sess[tid].size = i2d_SSL_SESSION(sess,
			    &ptr);
		}
	} else {
		free(s->ssl_ctx.reused_sess[tid].ptr);
		s->ssl_ctx.reused_sess[tid].ptr = NULL;
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
	 * so we dont store it to keep size.
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


	shctx_lock(ssl_shctx);
	/* store to cache */
	sh_ssl_sess_store(encid, encsess, data_len);
	shctx_unlock(ssl_shctx);
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

	global.shctx_lookups++;

	/* allow the session to be freed automatically by openssl */
	*do_copy = 0;

	/* tree key is zeros padded sessionid */
	if (key_len < SSL_MAX_SSL_SESSION_ID_LENGTH) {
		memcpy(tmpkey, key, key_len);
		memset(tmpkey + key_len, 0, SSL_MAX_SSL_SESSION_ID_LENGTH - key_len);
		key = tmpkey;
	}

	/* lock cache */
	shctx_lock(ssl_shctx);

	/* lookup for session */
	sh_ssl_sess = sh_ssl_sess_tree_lookup(key);
	if (!sh_ssl_sess) {
		/* no session found: unlock cache and exit */
		shctx_unlock(ssl_shctx);
		global.shctx_misses++;
		return NULL;
	}

	/* sh_ssl_sess (shared_block->data) is at the end of shared_block */
	first = sh_ssl_sess_first_block(sh_ssl_sess);

	shctx_row_data_get(ssl_shctx, first, data, sizeof(struct sh_ssl_sess_hdr), first->len-sizeof(struct sh_ssl_sess_hdr));

	shctx_unlock(ssl_shctx);

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

	shctx_lock(ssl_shctx);

	/* lookup for session */
	sh_ssl_sess = sh_ssl_sess_tree_lookup(sid_data);
	if (sh_ssl_sess) {
		/* free session */
		sh_ssl_sess_tree_delete(sh_ssl_sess);
	}

	/* unlock cache */
	shctx_unlock(ssl_shctx);
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

int ssl_sock_prepare_ctx(struct bind_conf *bind_conf, struct ssl_bind_conf *ssl_conf, SSL_CTX *ctx)
{
	struct proxy *curproxy = bind_conf->frontend;
	int cfgerr = 0;
	int verify = SSL_VERIFY_NONE;
	struct ssl_bind_conf __maybe_unused *ssl_conf_cur;
	const char *conf_ciphers;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	const char *conf_ciphersuites;
#endif
	const char *conf_curves = NULL;

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
			ha_alert("Proxy '%s': all SSL/TLS versions are disabled for bind '%s' at [%s:%d].\n",
				 bind_conf->frontend->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr += 1;
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
		char *crl_file = (ssl_conf && ssl_conf->crl_file) ? ssl_conf->crl_file : bind_conf->ssl_conf.crl_file;
		if (ca_file) {
			/* load CAfile to verify */
			if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL)) {
				ha_alert("Proxy '%s': unable to load CA file '%s' for bind '%s' at [%s:%d].\n",
					 curproxy->id, ca_file, bind_conf->arg, bind_conf->file, bind_conf->line);
				cfgerr++;
			}
			if (!((ssl_conf && ssl_conf->no_ca_names) || bind_conf->ssl_conf.no_ca_names)) {
				/* set CA names for client cert request, function returns void */
				SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_file));
			}
		}
		else {
			ha_alert("Proxy '%s': verify is enabled but no CA file specified for bind '%s' at [%s:%d].\n",
				 curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr++;
		}
#ifdef X509_V_FLAG_CRL_CHECK
		if (crl_file) {
			X509_STORE *store = SSL_CTX_get_cert_store(ctx);

			if (!store || !X509_STORE_load_locations(store, crl_file, NULL)) {
				ha_alert("Proxy '%s': unable to configure CRL file '%s' for bind '%s' at [%s:%d].\n",
					 curproxy->id, crl_file, bind_conf->arg, bind_conf->file, bind_conf->line);
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
			ha_alert("Proxy '%s': unable to set callback for TLS ticket validation for bind '%s' at [%s:%d].\n",
				 curproxy->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr++;
		}
	}
#endif

	ssl_set_shctx(ctx);
	conf_ciphers = (ssl_conf && ssl_conf->ciphers) ? ssl_conf->ciphers : bind_conf->ssl_conf.ciphers;
	if (conf_ciphers &&
	    !SSL_CTX_set_cipher_list(ctx, conf_ciphers)) {
		ha_alert("Proxy '%s': unable to set SSL cipher list to '%s' for bind '%s' at [%s:%d].\n",
			 curproxy->id, conf_ciphers, bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	conf_ciphersuites = (ssl_conf && ssl_conf->ciphersuites) ? ssl_conf->ciphersuites : bind_conf->ssl_conf.ciphersuites;
	if (conf_ciphersuites &&
	    !SSL_CTX_set_ciphersuites(ctx, conf_ciphersuites)) {
		ha_alert("Proxy '%s': unable to set TLS 1.3 cipher suites to '%s' for bind '%s' at [%s:%d].\n",
			 curproxy->id, conf_ciphersuites, bind_conf->arg, bind_conf->file, bind_conf->line);
		cfgerr++;
	}
#endif

#ifndef OPENSSL_NO_DH
	/* If tune.ssl.default-dh-param has not been set,
	   neither has ssl-default-dh-file and no static DH
	   params were in the certificate file. */
	if (global_ssl.default_dh_param == 0 &&
	    global_dh == NULL &&
	    (ssl_dh_ptr_index == -1 ||
	     SSL_CTX_get_ex_data(ctx, ssl_dh_ptr_index) == NULL)) {
		STACK_OF(SSL_CIPHER) * ciphers = NULL;
		const SSL_CIPHER * cipher = NULL;
		char cipher_description[128];
		/* The description of ciphers using an Ephemeral Diffie Hellman key exchange
		   contains " Kx=DH " or " Kx=DH(". Beware of " Kx=DH/",
		   which is not ephemeral DH. */
		const char dhe_description[] = " Kx=DH ";
		const char dhe_export_description[] = " Kx=DH(";
		int idx = 0;
		int dhe_found = 0;
		SSL *ssl = NULL;

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
			ha_warning("Setting tune.ssl.default-dh-param to 1024 by default, if your workload permits it you should set it to at least 2048. Please set a value >= 1024 to make this warning disappear.\n");
		}

		global_ssl.default_dh_param = 1024;
	}

	if (global_ssl.default_dh_param >= 1024) {
		if (local_dh_1024 == NULL) {
			local_dh_1024 = ssl_get_dh_1024();
		}
		if (global_ssl.default_dh_param >= 2048) {
			if (local_dh_2048 == NULL) {
				local_dh_2048 = ssl_get_dh_2048();
			}
			if (global_ssl.default_dh_param >= 4096) {
				if (local_dh_4096 == NULL) {
					local_dh_4096 = ssl_get_dh_4096();
				}
			}
		}
	}
#endif /* OPENSSL_NO_DH */

	SSL_CTX_set_info_callback(ctx, ssl_sock_infocbk);
#if HA_OPENSSL_VERSION_NUMBER >= 0x00907000L
	SSL_CTX_set_msg_callback(ctx, ssl_sock_msgcbk);
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
	if (ssl_conf_cur)
		SSL_CTX_set_alpn_select_cb(ctx, ssl_sock_advertise_alpn_protos, ssl_conf_cur);
#endif
#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
	conf_curves = (ssl_conf && ssl_conf->curves) ? ssl_conf->curves : bind_conf->ssl_conf.curves;
	if (conf_curves) {
		if (!SSL_CTX_set1_curves_list(ctx, conf_curves)) {
			ha_alert("Proxy '%s': unable to set SSL curves list to '%s' for bind '%s' at [%s:%d].\n",
				 curproxy->id, conf_curves, bind_conf->arg, bind_conf->file, bind_conf->line);
			cfgerr++;
		}
#if defined(SSL_CTX_set_ecdh_auto)
		(void)SSL_CTX_set_ecdh_auto(ctx, 1);
#endif
	}
#endif
#if defined(SSL_CTX_set_tmp_ecdh) && !defined(OPENSSL_NO_ECDH)
	if (!conf_curves) {
		int i;
		EC_KEY  *ecdh;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
		const char *ecdhe = (ssl_conf && ssl_conf->ecdhe) ? ssl_conf->ecdhe :
			(bind_conf->ssl_conf.ecdhe ? bind_conf->ssl_conf.ecdhe :
			 NULL);

		if (ecdhe == NULL) {
			SSL_CTX_set_ecdh_auto(ctx, 1);
			return cfgerr;
		}
#else
		const char *ecdhe = (ssl_conf && ssl_conf->ecdhe) ? ssl_conf->ecdhe :
			(bind_conf->ssl_conf.ecdhe ? bind_conf->ssl_conf.ecdhe :
			 ECDHE_DEFAULT_CURVE);
#endif

		i = OBJ_sn2nid(ecdhe);
		if (!i || ((ecdh = EC_KEY_new_by_curve_name(i)) == NULL)) {
			ha_alert("Proxy '%s': unable to set elliptic named curve to '%s' for bind '%s' at [%s:%d].\n",
				 curproxy->id, ecdhe, bind_conf->arg, bind_conf->file, bind_conf->line);
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
	ssl_ctx = conn->xprt_ctx;

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
	SSL_CTX *ctx = NULL;
	struct tls_version_filter *conf_ssl_methods = &srv->ssl_ctx.methods;
	int i, min, max, hole;
	int flags = MC_SSL_O_ALL;

	/* Make sure openssl opens /dev/urandom before the chroot */
	if (!ssl_initialize_random()) {
		ha_alert("OpenSSL random data generator initialization failed.\n");
		cfgerr++;
	}

	/* Automatic memory computations need to know we use SSL there */
	global.ssl_used_backend = 1;

	/* Initiate SSL context for current server */
	if (!srv->ssl_ctx.reused_sess) {
		if ((srv->ssl_ctx.reused_sess = calloc(1, global.nbthread*sizeof(*srv->ssl_ctx.reused_sess))) == NULL) {
			ha_alert("Proxy '%s', server '%s' [%s:%d] out of memory.\n",
				 curproxy->id, srv->id,
				 srv->conf.file, srv->conf.line);
			cfgerr++;
			return cfgerr;
		}
	}
	if (srv->use_ssl)
		srv->xprt = &ssl_sock;
	if (srv->check.use_ssl)
		srv->check.xprt = &ssl_sock;

	ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ctx) {
		ha_alert("config : %s '%s', server '%s': unable to allocate ssl context.\n",
			 proxy_type_str(curproxy), curproxy->id,
			 srv->id);
		cfgerr++;
		return cfgerr;
	}

	if (conf_ssl_methods->flags && (conf_ssl_methods->min || conf_ssl_methods->max))
		ha_warning("config : %s '%s': no-sslv3/no-tlsv1x are ignored for server '%s'. "
			   "Use only 'ssl-min-ver' and 'ssl-max-ver' to fix.\n",
			   proxy_type_str(curproxy), curproxy->id, srv->id);
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
					ha_warning("config : %s '%s': SSL/TLS versions range not contiguous for server '%s'. "
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
		ha_alert("config : %s '%s': all SSL/TLS versions are disabled for server '%s'.\n",
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

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
	if (global_ssl.async)
		mode |= SSL_MODE_ASYNC;
#endif
	SSL_CTX_set_mode(ctx, mode);
	srv->ssl_ctx.ctx = ctx;

	if (srv->ssl_ctx.client_crt) {
		if (SSL_CTX_use_PrivateKey_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt, SSL_FILETYPE_PEM) <= 0) {
			ha_alert("config : %s '%s', server '%s': unable to load SSL private key from PEM file '%s'.\n",
				 proxy_type_str(curproxy), curproxy->id,
				 srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
		else if (SSL_CTX_use_certificate_chain_file(srv->ssl_ctx.ctx, srv->ssl_ctx.client_crt) <= 0) {
			ha_alert("config : %s '%s', server '%s': unable to load ssl certificate from PEM file '%s'.\n",
				 proxy_type_str(curproxy), curproxy->id,
				 srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
		else if (SSL_CTX_check_private_key(srv->ssl_ctx.ctx) <= 0) {
			ha_alert("config : %s '%s', server '%s': inconsistencies between private key and certificate loaded from PEM file '%s'.\n",
				 proxy_type_str(curproxy), curproxy->id,
				 srv->id, srv->ssl_ctx.client_crt);
			cfgerr++;
		}
	}

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
	                   (srv->ssl_ctx.verify_host || (verify & SSL_VERIFY_PEER)) ? ssl_sock_srv_verifycbk : NULL);
	if (verify & SSL_VERIFY_PEER) {
		if (srv->ssl_ctx.ca_file) {
			/* load CAfile to verify */
			if (!SSL_CTX_load_verify_locations(srv->ssl_ctx.ctx, srv->ssl_ctx.ca_file, NULL)) {
				ha_alert("Proxy '%s', server '%s' [%s:%d] unable to load CA file '%s'.\n",
					 curproxy->id, srv->id,
					 srv->conf.file, srv->conf.line, srv->ssl_ctx.ca_file);
				cfgerr++;
			}
		}
		else {
			if (global.ssl_server_verify == SSL_SERVER_VERIFY_REQUIRED)
				ha_alert("Proxy '%s', server '%s' [%s:%d] verify is enabled by default but no CA file specified. If you're running on a LAN where you're certain to trust the server's certificate, please set an explicit 'verify none' statement on the 'server' line, or use 'ssl-server-verify none' in the global section to disable server-side verifications by default.\n",
					 curproxy->id, srv->id,
					 srv->conf.file, srv->conf.line);
			else
				ha_alert("Proxy '%s', server '%s' [%s:%d] verify is enabled but no CA file specified.\n",
					 curproxy->id, srv->id,
					 srv->conf.file, srv->conf.line);
			cfgerr++;
		}
#ifdef X509_V_FLAG_CRL_CHECK
		if (srv->ssl_ctx.crl_file) {
			X509_STORE *store = SSL_CTX_get_cert_store(srv->ssl_ctx.ctx);

			if (!store || !X509_STORE_load_locations(store, srv->ssl_ctx.crl_file, NULL)) {
				ha_alert("Proxy '%s', server '%s' [%s:%d] unable to configure CRL file '%s'.\n",
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

	SSL_CTX_set_session_cache_mode(srv->ssl_ctx.ctx, SSL_SESS_CACHE_CLIENT |
	    SSL_SESS_CACHE_NO_INTERNAL_STORE);
	SSL_CTX_sess_set_new_cb(srv->ssl_ctx.ctx, ssl_sess_new_srv_cb);
	if (srv->ssl_ctx.ciphers &&
		!SSL_CTX_set_cipher_list(srv->ssl_ctx.ctx, srv->ssl_ctx.ciphers)) {
		ha_alert("Proxy '%s', server '%s' [%s:%d] : unable to set SSL cipher list to '%s'.\n",
			 curproxy->id, srv->id,
			 srv->conf.file, srv->conf.line, srv->ssl_ctx.ciphers);
		cfgerr++;
	}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (srv->ssl_ctx.ciphersuites &&
		!SSL_CTX_set_ciphersuites(srv->ssl_ctx.ctx, srv->ssl_ctx.ciphersuites)) {
		ha_alert("Proxy '%s', server '%s' [%s:%d] : unable to set TLS 1.3 cipher suites to '%s'.\n",
			 curproxy->id, srv->id,
			 srv->conf.file, srv->conf.line, srv->ssl_ctx.ciphersuites);
		cfgerr++;
	}
#endif
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	if (srv->ssl_ctx.npn_str)
		SSL_CTX_set_next_proto_select_cb(ctx, ssl_sock_srv_select_protos, srv);
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	if (srv->ssl_ctx.alpn_str)
		SSL_CTX_set_alpn_protos(ctx, (unsigned char *)srv->ssl_ctx.alpn_str, srv->ssl_ctx.alpn_len);
#endif


	return cfgerr;
}

/* Walks down the two trees in bind_conf and prepares all certs. The pointer may
 * be NULL, in which case nothing is done. Returns the number of errors
 * encountered.
 */
int ssl_sock_prepare_all_ctx(struct bind_conf *bind_conf)
{
	struct ebmb_node *node;
	struct sni_ctx *sni;
	int err = 0;

	/* Automatic memory computations need to know we use SSL there */
	global.ssl_used_frontend = 1;

	/* Make sure openssl opens /dev/urandom before the chroot */
	if (!ssl_initialize_random()) {
		ha_alert("OpenSSL random data generator initialization failed.\n");
		err++;
	}
	/* Create initial_ctx used to start the ssl connection before do switchctx */
	if (!bind_conf->initial_ctx) {
		err += ssl_sock_initial_ctx(bind_conf);
		/* It should not be necessary to call this function, but it's
		   necessary first to check and move all initialisation related
		   to initial_ctx in ssl_sock_initial_ctx. */
		err += ssl_sock_prepare_ctx(bind_conf, NULL, bind_conf->initial_ctx);
	}
	if (bind_conf->default_ctx)
		err += ssl_sock_prepare_ctx(bind_conf, bind_conf->default_ssl_conf, bind_conf->default_ctx);

	node = ebmb_first(&bind_conf->sni_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		if (!sni->order && sni->ctx != bind_conf->default_ctx)
			/* only initialize the CTX on its first occurrence and
			   if it is not the default_ctx */
			err += ssl_sock_prepare_ctx(bind_conf, sni->conf, sni->ctx);
		node = ebmb_next(node);
	}

	node = ebmb_first(&bind_conf->sni_w_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		if (!sni->order && sni->ctx != bind_conf->default_ctx)
			/* only initialize the CTX on its first occurrence and
			   if it is not the default_ctx */
			err += ssl_sock_prepare_ctx(bind_conf, sni->conf, sni->ctx);
		node = ebmb_next(node);
	}
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

	if (!bind_conf->is_ssl) {
		if (bind_conf->default_ctx) {
			ha_warning("Proxy '%s': A certificate was specified but SSL was not enabled on bind '%s' at [%s:%d] (use 'ssl').\n",
				   px->id, bind_conf->arg, bind_conf->file, bind_conf->line);
		}
		return 0;
	}
	if (!bind_conf->default_ctx) {
		if (bind_conf->strict_sni && !bind_conf->generate_certs) {
			ha_warning("Proxy '%s': no SSL certificate specified for bind '%s' at [%s:%d], ssl connections will fail (use 'crt').\n",
				   px->id, bind_conf->arg, bind_conf->file, bind_conf->line);
		}
		else {
			ha_alert("Proxy '%s': no SSL certificate specified for bind '%s' at [%s:%d] (use 'crt').\n",
				 px->id, bind_conf->arg, bind_conf->file, bind_conf->line);
			return -1;
		}
	}
	if (!ssl_shctx && global.tune.sslcachesize) {
		alloc_ctx = shctx_init(&ssl_shctx, global.tune.sslcachesize,
		                       sizeof(struct sh_ssl_sess_hdr) + SHSESS_BLOCK_MIN_SIZE, -1,
		                       sizeof(*sh_ssl_sess_tree),
		                       ((global.nbthread > 1) || (!global_ssl.private_cache && (global.nbproc > 1))) ? 1 : 0);
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

	/* initialize CA variables if the certificates generation is enabled */
	err += ssl_sock_load_ca(bind_conf);

	return -err;
}

/* release ssl context allocated for servers. */
void ssl_sock_free_srv_ctx(struct server *srv)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	if (srv->ssl_ctx.alpn_str)
		free(srv->ssl_ctx.alpn_str);
#endif
#ifdef OPENSSL_NPN_NEGOTIATED
	if (srv->ssl_ctx.npn_str)
		free(srv->ssl_ctx.npn_str);
#endif
	if (srv->ssl_ctx.ctx)
		SSL_CTX_free(srv->ssl_ctx.ctx);
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
		if (!sni->order) { /* only free the CTX on its first occurrence */
			SSL_CTX_free(sni->ctx);
			ssl_sock_free_ssl_conf(sni->conf);
			free(sni->conf);
			sni->conf = NULL;
		}
		free(sni);
		node = back;
	}

	node = ebmb_first(&bind_conf->sni_w_ctx);
	while (node) {
		sni = ebmb_entry(node, struct sni_ctx, name);
		back = ebmb_next(node);
		ebmb_delete(node);
		if (!sni->order) { /* only free the CTX on its first occurrence */
			SSL_CTX_free(sni->ctx);
			ssl_sock_free_ssl_conf(sni->conf);
			free(sni->conf);
			sni->conf = NULL;
		}
		free(sni);
		node = back;
	}
	SSL_CTX_free(bind_conf->initial_ctx);
	bind_conf->initial_ctx = NULL;
	bind_conf->default_ctx = NULL;
	bind_conf->default_ssl_conf = NULL;
}

/* Destroys all the contexts for a bind_conf. This is used during deinit(). */
void ssl_sock_destroy_bind_conf(struct bind_conf *bind_conf)
{
	ssl_sock_free_ca(bind_conf);
	ssl_sock_free_all_ctx(bind_conf);
	ssl_sock_free_ssl_conf(&bind_conf->ssl_conf);
	free(bind_conf->ca_sign_file);
	free(bind_conf->ca_sign_pass);
	if (bind_conf->keys_ref && !--bind_conf->keys_ref->refcount) {
		free(bind_conf->keys_ref->filename);
		free(bind_conf->keys_ref->tlskeys);
		LIST_DEL(&bind_conf->keys_ref->list);
		free(bind_conf->keys_ref);
	}
	bind_conf->keys_ref = NULL;
	bind_conf->ca_sign_pass = NULL;
	bind_conf->ca_sign_file = NULL;
}

/* Load CA cert file and private key used to generate certificates */
int
ssl_sock_load_ca(struct bind_conf *bind_conf)
{
	struct proxy *px = bind_conf->frontend;
	FILE     *fp;
	X509     *cacert = NULL;
	EVP_PKEY *capkey = NULL;
	int       err    = 0;

	if (!bind_conf->generate_certs)
		return err;

#if (defined SSL_CTRL_SET_TLSEXT_HOSTNAME && !defined SSL_NO_GENERATE_CERTIFICATES)
	if (global_ssl.ctx_cache) {
		ssl_ctx_lru_tree = lru64_new(global_ssl.ctx_cache);
	}
	ssl_ctx_lru_seed = (unsigned int)time(NULL);
	ssl_ctx_serial   = now_ms;
#endif

	if (!bind_conf->ca_sign_file) {
		ha_alert("Proxy '%s': cannot enable certificate generation, "
			 "no CA certificate File configured at [%s:%d].\n",
			 px->id, bind_conf->file, bind_conf->line);
		goto load_error;
	}

	/* read in the CA certificate */
	if (!(fp = fopen(bind_conf->ca_sign_file, "r"))) {
		ha_alert("Proxy '%s': Failed to read CA certificate file '%s' at [%s:%d].\n",
			 px->id, bind_conf->ca_sign_file, bind_conf->file, bind_conf->line);
		goto load_error;
	}
	if (!(cacert = PEM_read_X509(fp, NULL, NULL, NULL))) {
		ha_alert("Proxy '%s': Failed to read CA certificate file '%s' at [%s:%d].\n",
			 px->id, bind_conf->ca_sign_file, bind_conf->file, bind_conf->line);
		goto read_error;
	}
	rewind(fp);
	if (!(capkey = PEM_read_PrivateKey(fp, NULL, NULL, bind_conf->ca_sign_pass))) {
		ha_alert("Proxy '%s': Failed to read CA private key file '%s' at [%s:%d].\n",
			 px->id, bind_conf->ca_sign_file, bind_conf->file, bind_conf->line);
		goto read_error;
	}

	fclose (fp);
	bind_conf->ca_sign_cert = cacert;
	bind_conf->ca_sign_pkey = capkey;
	return err;

 read_error:
	fclose (fp);
	if (capkey) EVP_PKEY_free(capkey);
	if (cacert) X509_free(cacert);
 load_error:
	bind_conf->generate_certs = 0;
	err++;
	return err;
}

/* Release CA cert and private key used to generate certificated */
void
ssl_sock_free_ca(struct bind_conf *bind_conf)
{
	if (bind_conf->ca_sign_pkey)
		EVP_PKEY_free(bind_conf->ca_sign_pkey);
	if (bind_conf->ca_sign_cert)
		X509_free(bind_conf->ca_sign_cert);
	bind_conf->ca_sign_pkey = NULL;
	bind_conf->ca_sign_cert = NULL;
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
	/* already initialized */
	if (*xprt_ctx)
		return 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	ctx = pool_alloc(ssl_sock_ctx_pool);
	if (!ctx) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		return -1;
	}
	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		pool_free(ssl_sock_ctx_pool, ctx);
		return -1;
	}
	ctx->wait_event.tasklet->process = ssl_sock_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.events = 0;
	ctx->sent_early_data = 0;
	ctx->tmp_early_data = -1;
	ctx->conn = conn;
	ctx->send_wait = NULL;
	ctx->recv_wait = NULL;
	ctx->xprt_st = 0;
	ctx->xprt_ctx = NULL;

	/* Only work with sockets for now, this should be adapted when we'll
	 * add QUIC support.
	 */
	ctx->xprt = xprt_get(XPRT_RAW);
	if (ctx->xprt->init) {
		if (ctx->xprt->init(conn, &ctx->xprt_ctx) != 0)
			goto err;
	}

	if (global.maxsslconn && sslconns >= global.maxsslconn) {
		conn->err_code = CO_ER_SSL_TOO_MANY;
		goto err;
	}

	/* If it is in client mode initiate SSL session
	   in connect state otherwise accept state */
	if (objt_server(conn->target)) {
		int may_retry = 1;

	retry_connect:
		/* Alloc a new SSL session ctx */
		ctx->ssl = SSL_new(__objt_server(conn->target)->ssl_ctx.ctx);
		if (!ctx->ssl) {
			if (may_retry--) {
				pool_gc(NULL);
				goto retry_connect;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			goto err;
		}
		ctx->bio = BIO_new(ha_meth);
		if (!ctx->bio) {
			if (may_retry--) {
				pool_gc(NULL);
				goto retry_connect;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			goto err;
		}
		BIO_set_data(ctx->bio, ctx);
		SSL_set_bio(ctx->ssl, ctx->bio, ctx->bio);

		/* set connection pointer */
		if (!SSL_set_ex_data(ctx->ssl, ssl_app_data_index, conn)) {
			SSL_free(ctx->ssl);
			ctx->ssl = NULL;
			conn->xprt_ctx = NULL;
			if (may_retry--) {
				pool_gc(NULL);
				goto retry_connect;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			goto err;
		}

		SSL_set_connect_state(ctx->ssl);
		if (__objt_server(conn->target)->ssl_ctx.reused_sess[tid].ptr) {
			const unsigned char *ptr = __objt_server(conn->target)->ssl_ctx.reused_sess[tid].ptr;
			SSL_SESSION *sess = d2i_SSL_SESSION(NULL, &ptr, __objt_server(conn->target)->ssl_ctx.reused_sess[tid].size);
			if (sess && !SSL_set_session(ctx->ssl, sess)) {
				SSL_SESSION_free(sess);
				free(__objt_server(conn->target)->ssl_ctx.reused_sess[tid].ptr);
				__objt_server(conn->target)->ssl_ctx.reused_sess[tid].ptr = NULL;
			} else if (sess) {
				SSL_SESSION_free(sess);
			}
		}

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;

		_HA_ATOMIC_ADD(&sslconns, 1);
		_HA_ATOMIC_ADD(&totalsslconns, 1);
		*xprt_ctx = ctx;
		/* Start the handshake */
		tasklet_wakeup(ctx->wait_event.tasklet);
		if (conn->flags & CO_FL_ERROR)
			goto err;
		return 0;
	}
	else if (objt_listener(conn->target)) {
		int may_retry = 1;

	retry_accept:
		/* Alloc a new SSL session ctx */
		ctx->ssl = SSL_new(__objt_listener(conn->target)->bind_conf->initial_ctx);
		if (!ctx->ssl) {
			if (may_retry--) {
				pool_gc(NULL);
				goto retry_accept;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			goto err;
		}

		ctx->bio = BIO_new(ha_meth);
		if (!ctx->bio) {
			if (may_retry--) {
				pool_gc(NULL);
				goto retry_accept;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			goto err;
		}
		BIO_set_data(ctx->bio, ctx);
		SSL_set_bio(ctx->ssl, ctx->bio, ctx->bio);

		/* set connection pointer */
		if (!SSL_set_ex_data(ctx->ssl, ssl_app_data_index, conn)) {
			SSL_free(ctx->ssl);
			ctx->ssl = NULL;
			if (may_retry--) {
				pool_gc(NULL);
				goto retry_accept;
			}
			conn->err_code = CO_ER_SSL_NO_MEM;
			goto err;
		}

		SSL_set_accept_state(ctx->ssl);

		/* leave init state and start handshake */
		conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
		conn->flags |= CO_FL_EARLY_SSL_HS;
#endif

		_HA_ATOMIC_ADD(&sslconns, 1);
		_HA_ATOMIC_ADD(&totalsslconns, 1);
		*xprt_ctx = ctx;
		/* Start the handshake */
		tasklet_wakeup(ctx->wait_event.tasklet);
		if (conn->flags & CO_FL_ERROR)
			goto err;
		return 0;
	}
	/* don't know how to handle such a target */
	conn->err_code = CO_ER_SSL_NO_TARGET;
err:
	if (ctx && ctx->wait_event.tasklet)
		tasklet_free(ctx->wait_event.tasklet);
	pool_free(ssl_sock_ctx_pool, ctx);
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
	struct ssl_sock_ctx *ctx = conn->xprt_ctx;
	int ret;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!conn->xprt_ctx)
		goto out_error;

#if HA_OPENSSL_VERSION_NUMBER >= 0x10101000L
	/*
	 * Check if we have early data. If we do, we have to read them
	 * before SSL_do_handshake() is called, And there's no way to
	 * detect early data, except to try to read them
	 */
	if (conn->flags & CO_FL_EARLY_SSL_HS) {
		size_t read_data;

		ret = SSL_read_early_data(ctx->ssl, &ctx->tmp_early_data,
		    1, &read_data);
		if (ret == SSL_READ_EARLY_DATA_ERROR)
			goto check_error;
		if (ret == SSL_READ_EARLY_DATA_SUCCESS) {
			conn->flags &= ~(CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN);
			return 1;
		} else
			conn->flags &= ~CO_FL_EARLY_SSL_HS;
	}
#endif
	/* If we use SSL_do_handshake to process a reneg initiated by
	 * the remote peer, it sometimes returns SSL_ERROR_SSL.
	 * Usually SSL_write and SSL_read are used and process implicitly
	 * the reneg handshake.
	 * Here we use SSL_peek as a workaround for reneg.
	 */
	if ((conn->flags & CO_FL_CONNECTED) && SSL_renegotiate_pending(ctx->ssl)) {
		char c;

		ret = SSL_peek(ctx->ssl, &c, 1);
		if (ret <= 0) {
			/* handshake may have not been completed, let's find why */
			ret = SSL_get_error(ctx->ssl, ret);

			if (ret == SSL_ERROR_WANT_WRITE) {
				/* SSL handshake needs to write, L4 connection may not be ready */
				if (!(ctx->wait_event.events & SUB_RETRY_SEND))
					ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND, &ctx->wait_event);
				return 0;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				/* handshake may have been completed but we have
				 * no more data to read.
                                 */
				if (!SSL_renegotiate_pending(ctx->ssl)) {
					ret = 1;
					goto reneg_ok;
				}
				/* SSL handshake needs to read, L4 connection is ready */
				if (!(ctx->wait_event.events & SUB_RETRY_RECV))
					ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_RECV, &ctx->wait_event);
				return 0;
			}
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
			else if (ret == SSL_ERROR_WANT_ASYNC) {
				ssl_async_process_fds(ctx);
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
					conn->err_code = (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT) ?
						CO_ER_SSL_KILLED_HB : CO_ER_SSL_HANDSHAKE;
				goto out_error;
			}
		}
		/* read some data: consider handshake completed */
		goto reneg_ok;
	}
	ret = SSL_do_handshake(ctx->ssl);
check_error:
	if (ret != 1) {
		/* handshake did not complete, let's find why */
		ret = SSL_get_error(ctx->ssl, ret);

		if (ret == SSL_ERROR_WANT_WRITE) {
			/* SSL handshake needs to write, L4 connection may not be ready */
			if (!(ctx->wait_event.events & SUB_RETRY_SEND))
				ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND, &ctx->wait_event);
			return 0;
		}
		else if (ret == SSL_ERROR_WANT_READ) {
			/* SSL handshake needs to read, L4 connection is ready */
			if (!(ctx->wait_event.events & SUB_RETRY_RECV))
				ctx->xprt->subscribe(conn, ctx->xprt_ctx,
				    SUB_RETRY_RECV, &ctx->wait_event);
			return 0;
		}
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
		else if (ret == SSL_ERROR_WANT_ASYNC) {
			ssl_async_process_fds(ctx);
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
				conn->err_code = (ctx->xprt_st & SSL_SOCK_RECV_HEARTBEAT) ?
					CO_ER_SSL_KILLED_HB : CO_ER_SSL_HANDSHAKE;
			goto out_error;
		}
	}
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	else {
		/*
		 * If the server refused the early data, we have to send a
		 * 425 to the client, as we no longer have the data to sent
		 * them again.
		 */
		if ((conn->flags & CO_FL_EARLY_DATA) && (objt_server(conn->target))) {
			if (SSL_get_early_data_status(ctx->ssl) == SSL_EARLY_DATA_REJECTED) {
				conn->err_code = CO_ER_SSL_EARLY_FAILED;
				goto out_error;
			}
		}
	}
#endif


reneg_ok:

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
	/* ASYNC engine API doesn't support moving read/write
	 * buffers. So we disable ASYNC mode right after
	 * the handshake to avoid buffer oveflows.
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
	}

	/* The connection is now established at both layers, it's time to leave */
	conn->flags &= ~(flag | CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN);
	return 1;

 out_error:
	/* Clear openssl global errors stack */
	ssl_sock_dump_errors(conn);
	ERR_clear_error();

	/* free resumed session if exists */
	if (objt_server(conn->target) && __objt_server(conn->target)->ssl_ctx.reused_sess[tid].ptr) {
		free(__objt_server(conn->target)->ssl_ctx.reused_sess[tid].ptr);
		__objt_server(conn->target)->ssl_ctx.reused_sess[tid].ptr = NULL;
	}

	/* Fail on all other handshake errors */
	conn->flags |= CO_FL_ERROR;
	if (!conn->err_code)
		conn->err_code = CO_ER_SSL_HANDSHAKE;
	return 0;
}

static int ssl_subscribe(struct connection *conn, void *xprt_ctx, int event_type, void *param)
{
	struct wait_event *sw;
	struct ssl_sock_ctx *ctx = xprt_ctx;

	if (!ctx)
		return -1;

	if (event_type & SUB_RETRY_RECV) {
		sw = param;
		BUG_ON(ctx->recv_wait !=  NULL || (sw->events & SUB_RETRY_RECV));
		sw->events |= SUB_RETRY_RECV;
		ctx->recv_wait = sw;
		if (!(conn->flags & CO_FL_SSL_WAIT_HS) &&
		    !(ctx->wait_event.events & SUB_RETRY_RECV))
			ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_RECV, &ctx->wait_event);
		event_type &= ~SUB_RETRY_RECV;
	}
	if (event_type & SUB_RETRY_SEND) {
sw = param;
		BUG_ON(ctx->send_wait !=  NULL || (sw->events & SUB_RETRY_SEND));
		sw->events |= SUB_RETRY_SEND;
		ctx->send_wait = sw;
		if (!(conn->flags & CO_FL_SSL_WAIT_HS) &&
		    !(ctx->wait_event.events & SUB_RETRY_SEND))
			ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND, &ctx->wait_event);
		event_type &= ~SUB_RETRY_SEND;

	}
	if (event_type != 0)
		return -1;
	return 0;
}

static int ssl_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, void *param)
{
	struct wait_event *sw;
	struct ssl_sock_ctx *ctx = xprt_ctx;

	if (event_type & SUB_RETRY_RECV) {
		sw = param;
		BUG_ON(ctx->recv_wait != sw);
		ctx->recv_wait = NULL;
		sw->events &= ~SUB_RETRY_RECV;
		/* If we subscribed, and we're not doing the handshake,
		 * then we subscribed because the upper layer asked for it,
		 * as the upper layer is no longer interested, we can
		 * unsubscribe too.
		 */
		if (!(ctx->conn->flags & CO_FL_SSL_WAIT_HS) &&
		    (ctx->wait_event.events & SUB_RETRY_RECV))
			conn_unsubscribe(conn, ctx->xprt_ctx, SUB_RETRY_RECV,
			                 &ctx->wait_event);
	}
	if (event_type & SUB_RETRY_SEND) {
		sw = param;
		BUG_ON(ctx->send_wait != sw);
		ctx->send_wait = NULL;
		sw->events &= ~SUB_RETRY_SEND;
		if (!(ctx->conn->flags & CO_FL_SSL_WAIT_HS) &&
		    (ctx->wait_event.events & SUB_RETRY_SEND))
			conn_unsubscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND,
			                 &ctx->wait_event);

	}

	return 0;
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

static struct task *ssl_sock_io_cb(struct task *t, void *context, unsigned short state)
{
	struct ssl_sock_ctx *ctx = context;

	/* First if we're doing an handshake, try that */
	if (ctx->conn->flags & CO_FL_SSL_WAIT_HS)
		ssl_sock_handshake(ctx->conn, CO_FL_SSL_WAIT_HS);
	/* If we had an error, or the handshake is done and I/O is available,
	 * let the upper layer know.
	 * If no mux was set up yet, and nobody subscribed, then call
	 * xprt_done_cb() ourself if it's set, or destroy the connection,
	 * we can't be sure conn_fd_handler() will be called again.
	 */
	if ((ctx->conn->flags & CO_FL_ERROR) ||
	    !(ctx->conn->flags & CO_FL_SSL_WAIT_HS)) {
		int ret = 0;
		int woke = 0;

		/* On error, wake any waiter */
		if (ctx->recv_wait) {
			ctx->recv_wait->events &= ~SUB_RETRY_RECV;
			tasklet_wakeup(ctx->recv_wait->tasklet);
			ctx->recv_wait = NULL;
			woke = 1;
		}
		if (ctx->send_wait) {
			ctx->send_wait->events &= ~SUB_RETRY_SEND;
			tasklet_wakeup(ctx->send_wait->tasklet);
			ctx->send_wait = NULL;
			woke = 1;
		}
		/* If we're the first xprt for the connection, let the
		 * upper layers know. If xprt_done_cb() is set, call it,
		 * otherwise, we should have a mux, so call its wake
		 * method if we didn't woke a tasklet already.
		 */
		if (ctx->conn->xprt_ctx == ctx) {
			if (ctx->conn->xprt_done_cb)
				ret = ctx->conn->xprt_done_cb(ctx->conn);
			if (ret >= 0 && !woke && ctx->conn->mux && ctx->conn->mux->wake)
				ctx->conn->mux->wake(ctx->conn);
			return NULL;
		}
	}
	return NULL;
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

	conn_refresh_polling_flags(conn);

	if (!ctx)
		goto out_error;

	if (conn->flags & CO_FL_HANDSHAKE)
		/* a handshake was requested */
		return 0;

	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {
		int need_out = 0;

		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > count)
			try = count;

		if (((conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_EARLY_DATA)) == CO_FL_EARLY_SSL_HS) &&
		    ctx->tmp_early_data != -1) {
			*b_tail(buf) = ctx->tmp_early_data;
			done++;
			try--;
			count--;
			b_add(buf, 1);
			ctx->tmp_early_data = -1;
			continue;
		}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
		if (conn->flags & CO_FL_EARLY_SSL_HS) {
			size_t read_length;

			ret = SSL_read_early_data(ctx->ssl,
			    b_tail(buf), try, &read_length);
			if (ret == SSL_READ_EARLY_DATA_SUCCESS &&
			    read_length > 0)
				conn->flags |= CO_FL_EARLY_DATA;
			if (ret == SSL_READ_EARLY_DATA_SUCCESS ||
			    ret == SSL_READ_EARLY_DATA_FINISH) {
				if (ret == SSL_READ_EARLY_DATA_FINISH) {
					/*
					 * We're done reading the early data,
					 * let's make the handshake
					 */
					conn->flags &= ~CO_FL_EARLY_SSL_HS;
					conn->flags |= CO_FL_SSL_WAIT_HS;
					need_out = 1;
					/* Now initiate the handshake */
					tasklet_wakeup(ctx->wait_event.tasklet);
					if (read_length == 0)
						break;
				}
				ret = read_length;
			}
		} else
#endif
		ret = SSL_read(ctx->ssl, b_tail(buf), try);

		if (conn->flags & CO_FL_ERROR) {
			/* CO_FL_ERROR may be set by ssl_sock_infocbk */
			goto out_error;
		}
		if (ret > 0) {
			b_add(buf, ret);
			done += ret;
			count -= ret;
		}
		else {
			ret =  SSL_get_error(ctx->ssl, ret);
			if (ret == SSL_ERROR_WANT_WRITE) {
				/* handshake is running, and it needs to enable write */
				conn->flags |= CO_FL_SSL_WAIT_HS;
				ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND, &ctx->wait_event);
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
				/* Async mode can be re-enabled, because we're leaving data state.*/
				if (global_ssl.async)
					SSL_set_mode(ctx->ssl, SSL_MODE_ASYNC);
#endif
				break;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				if (SSL_renegotiate_pending(ctx->ssl)) {
					ctx->xprt->subscribe(conn, ctx->xprt_ctx,
					                     SUB_RETRY_RECV,
							     &ctx->wait_event);
					/* handshake is running, and it may need to re-enable read */
					conn->flags |= CO_FL_SSL_WAIT_HS;
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
					/* Async mode can be re-enabled, because we're leaving data state.*/
					if (global_ssl.async)
						SSL_set_mode(ctx->ssl, SSL_MODE_ASYNC);
#endif
					break;
				}
				break;
			} else if (ret == SSL_ERROR_ZERO_RETURN)
				goto read0;
			/* For SSL_ERROR_SYSCALL, make sure to clear the error
			 * stack before shutting down the connection for
			 * reading. */
			if (ret == SSL_ERROR_SYSCALL && (!errno || errno == EAGAIN))
				goto clear_ssl_error;
			/* otherwise it's a real error */
			goto out_error;
		}
		if (need_out)
			break;
	}
 leave:
	return done;

 clear_ssl_error:
	/* Clear openssl global errors stack */
	ssl_sock_dump_errors(conn);
	ERR_clear_error();
 read0:
	conn_sock_read0(conn);
	goto leave;

 out_error:
	conn->flags |= CO_FL_ERROR;
	/* Clear openssl global errors stack */
	ssl_sock_dump_errors(conn);
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

	done = 0;
	conn_refresh_polling_flags(conn);

	if (!ctx)
		goto out_error;

	if (conn->flags & (CO_FL_HANDSHAKE | CO_FL_EARLY_SSL_HS))
		/* a handshake was requested */
		return 0;

	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (count) {
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
		size_t written_data;
#endif

		try = b_contig_data(buf, done);
		if (try > count)
			try = count;

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

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
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

			}

		} else
#endif
			ret = SSL_write(ctx->ssl, b_peek(buf, done), try);

		if (conn->flags & CO_FL_ERROR) {
			/* CO_FL_ERROR may be set by ssl_sock_infocbk */
			goto out_error;
		}
		if (ret > 0) {
			/* A send succeeded, so we can consier ourself connected */
			conn->flags |= CO_FL_CONNECTED;
			ctx->xprt_st &= ~SSL_SOCK_SEND_UNLIMITED;
			count -= ret;
			done += ret;
		}
		else {
			ret = SSL_get_error(ctx->ssl, ret);

			if (ret == SSL_ERROR_WANT_WRITE) {
				if (SSL_renegotiate_pending(ctx->ssl)) {
					/* handshake is running, and it may need to re-enable write */
					conn->flags |= CO_FL_SSL_WAIT_HS;
					ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_SEND, &ctx->wait_event);
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
					/* Async mode can be re-enabled, because we're leaving data state.*/
					if (global_ssl.async)
						SSL_set_mode(ctx->ssl, SSL_MODE_ASYNC);
#endif
					break;
				}

				break;
			}
			else if (ret == SSL_ERROR_WANT_READ) {
				/* handshake is running, and it needs to enable read */
				conn->flags |= CO_FL_SSL_WAIT_HS;
				ctx->xprt->subscribe(conn, ctx->xprt_ctx,
				                     SUB_RETRY_RECV,
						     &ctx->wait_event);
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
				/* Async mode can be re-enabled, because we're leaving data state.*/
				if (global_ssl.async)
					SSL_set_mode(ctx->ssl, SSL_MODE_ASYNC);
#endif
				break;
			}
			goto out_error;
		}
	}
 leave:
	return done;

 out_error:
	/* Clear openssl global errors stack */
	ssl_sock_dump_errors(conn);
	ERR_clear_error();

	conn->flags |= CO_FL_ERROR;
	goto leave;
}

static void ssl_sock_close(struct connection *conn, void *xprt_ctx) {

	struct ssl_sock_ctx *ctx = xprt_ctx;


	if (ctx) {
		if (ctx->wait_event.events != 0)
			ctx->xprt->unsubscribe(ctx->conn, ctx->xprt_ctx,
			                       ctx->wait_event.events,
					       &ctx->wait_event);
		if (ctx->send_wait) {
			ctx->send_wait->events &= ~SUB_RETRY_SEND;
			tasklet_wakeup(ctx->send_wait->tasklet);
		}
		if (ctx->recv_wait) {
			ctx->recv_wait->events &= ~SUB_RETRY_RECV;
			tasklet_wakeup(ctx->recv_wait->tasklet);
		}
		if (ctx->xprt->close)
			ctx->xprt->close(conn, ctx->xprt_ctx);
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
		if (global_ssl.async) {
			OSSL_ASYNC_FD all_fd[32], afd;
			size_t num_all_fds = 0;
			int i;

			SSL_get_all_async_fds(ctx->ssl, NULL, &num_all_fds);
			if (num_all_fds > 32) {
				send_log(NULL, LOG_EMERG, "haproxy: openssl returns too many async fds. It seems a bug. Process may crash\n");
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
				_HA_ATOMIC_ADD(&jobs, 1);
				return;
			}
			/* Else we can remove the fds from the fdtab
			 * and call SSL_free.
			 * note: we do a fd_remove and not a delete
			 * because the fd is  owned by the engine.
			 * the engine is responsible to close
			 */
			for (i=0 ; i < num_all_fds ; i++)
				fd_remove(all_fd[i]);
		}
#endif
		SSL_free(ctx->ssl);
		tasklet_free(ctx->wait_event.tasklet);
		pool_free(ssl_sock_ctx_pool, ctx);
		_HA_ATOMIC_SUB(&sslconns, 1);
	}
}

/* This function tries to perform a clean shutdown on an SSL connection, and in
 * any case, flags the connection as reusable if no handshake was in progress.
 */
static void ssl_sock_shutw(struct connection *conn, void *xprt_ctx, int clean)
{
	struct ssl_sock_ctx *ctx = xprt_ctx;

	if (conn->flags & CO_FL_HANDSHAKE)
		return;
	if (!clean)
		/* don't sent notify on SSL_shutdown */
		SSL_set_quiet_shutdown(ctx->ssl, 1);
	/* no handshake was in progress, try a clean ssl shutdown */
	if (SSL_shutdown(ctx->ssl) <= 0) {
		/* Clear openssl global errors stack */
		ssl_sock_dump_errors(conn);
		ERR_clear_error();
	}
}

/* used for ppv2 pkey alog (can be used for logging) */
int ssl_sock_get_pkey_algo(struct connection *conn, struct buffer *out)
{
	struct ssl_sock_ctx *ctx;
	struct pkey_info *pkinfo;
	int bits = 0;
	int sig = TLSEXT_signature_anonymous;
	int len = -1;

	if (!ssl_sock_is_ssl(conn))
		return 0;
	ctx = conn->xprt_ctx;
	pkinfo = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ctx->ssl), ssl_pkey_info_index);
	if (pkinfo) {
		sig = pkinfo->sig;
		bits = pkinfo->bits;
	} else {
		/* multicert and generated cert have no pkey info */
		X509 *crt;
		EVP_PKEY *pkey;
		crt = SSL_get_certificate(ctx->ssl);
		if (!crt)
			return 0;
		pkey = X509_get_pubkey(crt);
		if (pkey) {
			bits = EVP_PKEY_bits(pkey);
			switch(EVP_PKEY_base_id(pkey)) {
			case EVP_PKEY_RSA:
				sig = TLSEXT_signature_rsa;
				break;
			case EVP_PKEY_EC:
				sig = TLSEXT_signature_ecdsa;
				break;
			case EVP_PKEY_DSA:
				sig = TLSEXT_signature_dsa;
				break;
			}
			EVP_PKEY_free(pkey);
		}
	}

	switch(sig) {
	case TLSEXT_signature_rsa:
		len = chunk_printf(out, "RSA%d", bits);
		break;
	case TLSEXT_signature_ecdsa:
		len = chunk_printf(out, "EC%d", bits);
		break;
	case TLSEXT_signature_dsa:
		len = chunk_printf(out, "DSA%d", bits);
		break;
	default:
		return 0;
	}
	if (len < 0)
		return 0;
	return 1;
}

/* used for ppv2 cert signature (can be used for logging) */
const char *ssl_sock_get_cert_sig(struct connection *conn)
{
	struct ssl_sock_ctx *ctx;

	__OPENSSL_110_CONST__ ASN1_OBJECT *algorithm;
	X509 *crt;

	if (!ssl_sock_is_ssl(conn))
		return NULL;
	ctx = conn->xprt_ctx;
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
	struct ssl_sock_ctx *ctx;

	if (!ssl_sock_is_ssl(conn))
		return NULL;
	ctx = conn->xprt_ctx;
	return SSL_get_servername(ctx->ssl, TLSEXT_NAMETYPE_host_name);
#else
	return NULL;
#endif
}

/* used for logging/ppv2, may be changed for a sample fetch later */
const char *ssl_sock_get_cipher_name(struct connection *conn)
{
	struct ssl_sock_ctx *ctx;

	if (!ssl_sock_is_ssl(conn))
		return NULL;
	ctx = conn->xprt_ctx;
	return SSL_get_cipher_name(ctx->ssl);
}

/* used for logging/ppv2, may be changed for a sample fetch later */
const char *ssl_sock_get_proto_version(struct connection *conn)
{
	struct ssl_sock_ctx *ctx;

	if (!ssl_sock_is_ssl(conn))
		return NULL;
	ctx = conn->xprt_ctx;
	return SSL_get_version(ctx->ssl);
}

/* Extract a serial from a cert, and copy it to a chunk.
 * Returns 1 if serial is found and copied, 0 if no serial found and
 * -1 if output is not large enough.
 */
static int
ssl_sock_get_serial(X509 *crt, struct buffer *out)
{
	ASN1_INTEGER *serial;

	serial = X509_get_serialNumber(crt);
	if (!serial)
		return 0;

	if (out->size < serial->length)
		return -1;

	memcpy(out->area, serial->data, serial->length);
	out->data = serial->length;
	return 1;
}

/* Extract a cert to der, and copy it to a chunk.
 * Returns 1 if the cert is found and copied, 0 on der conversion failure
 * and -1 if the output is not large enough.
 */
static int
ssl_sock_crt2der(X509 *crt, struct buffer *out)
{
	int len;
	unsigned char *p = (unsigned char *) out->area;;

	len =i2d_X509(crt, NULL);
	if (len <= 0)
		return 1;

	if (out->size < len)
		return -1;

	i2d_X509(crt,&p);
	out->data = len;
	return 1;
}


/* Copy Date in ASN1_UTCTIME format in struct buffer out.
 * Returns 1 if serial is found and copied, 0 if no valid time found
 * and -1 if output is not large enough.
 */
static int
ssl_sock_get_time(ASN1_TIME *tm, struct buffer *out)
{
	if (tm->type == V_ASN1_GENERALIZEDTIME) {
		ASN1_GENERALIZEDTIME *gentm = (ASN1_GENERALIZEDTIME *)tm;

		if (gentm->length < 12)
			return 0;
		if (gentm->data[0] != 0x32 || gentm->data[1] != 0x30)
			return 0;
		if (out->size < gentm->length-2)
			return -1;

		memcpy(out->area, gentm->data+2, gentm->length-2);
		out->data = gentm->length-2;
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

		memcpy(out->area, utctm->data, utctm->length);
		out->data = utctm->length;
		return 1;
	}

	return 0;
}

/* Extract an entry from a X509_NAME and copy its value to an output chunk.
 * Returns 1 if entry found, 0 if entry not found, or -1 if output not large enough.
 */
static int
ssl_sock_get_dn_entry(X509_NAME *a, const struct buffer *entry, int pos,
		      struct buffer *out)
{
	X509_NAME_ENTRY *ne;
	ASN1_OBJECT *obj;
	ASN1_STRING *data;
	const unsigned char *data_ptr;
	int data_len;
	int i, j, n;
	int cur = 0;
	const char *s;
	char tmp[128];
	int name_count;

	name_count = X509_NAME_entry_count(a);

	out->data = 0;
	for (i = 0; i < name_count; i++) {
		if (pos < 0)
			j = (name_count-1) - i;
		else
			j = i;

		ne = X509_NAME_get_entry(a, j);
		obj = X509_NAME_ENTRY_get_object(ne);
		data = X509_NAME_ENTRY_get_data(ne);
		data_ptr = ASN1_STRING_get0_data(data);
		data_len = ASN1_STRING_length(data);
		n = OBJ_obj2nid(obj);
		if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL)) {
			i2t_ASN1_OBJECT(tmp, sizeof(tmp), obj);
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

		if (data_len > out->size)
			return -1;

		memcpy(out->area, data_ptr, data_len);
		out->data = data_len;
		return 1;
	}

	return 0;

}

/* Extract and format full DN from a X509_NAME and copy result into a chunk
 * Returns 1 if dn entries exits, 0 if no dn entry found or -1 if output is not large enough.
 */
static int
ssl_sock_get_dn_oneline(X509_NAME *a, struct buffer *out)
{
	X509_NAME_ENTRY *ne;
	ASN1_OBJECT *obj;
	ASN1_STRING *data;
	const unsigned char *data_ptr;
	int data_len;
	int i, n, ln;
	int l = 0;
	const char *s;
	char *p;
	char tmp[128];
	int name_count;


	name_count = X509_NAME_entry_count(a);

	out->data = 0;
	p = out->area;
	for (i = 0; i < name_count; i++) {
		ne = X509_NAME_get_entry(a, i);
		obj = X509_NAME_ENTRY_get_object(ne);
		data = X509_NAME_ENTRY_get_data(ne);
		data_ptr = ASN1_STRING_get0_data(data);
		data_len = ASN1_STRING_length(data);
		n = OBJ_obj2nid(obj);
		if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL)) {
			i2t_ASN1_OBJECT(tmp, sizeof(tmp), obj);
			s = tmp;
		}
		ln = strlen(s);

		l += 1 + ln + 1 + data_len;
		if (l > out->size)
			return -1;
		out->data = l;

		*(p++)='/';
		memcpy(p, s, ln);
		p += ln;
		*(p++)='=';
		memcpy(p, data_ptr, data_len);
		p += data_len;
	}

	if (!out->data)
		return 0;

	return 1;
}

void ssl_sock_set_alpn(struct connection *conn, const unsigned char *alpn, int len)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	struct ssl_sock_ctx *ctx;

	if (!ssl_sock_is_ssl(conn))
		return;
	ctx = conn->xprt_ctx;
	SSL_set_alpn_protos(ctx->ssl, alpn, len);
#endif
}

/* Sets advertised SNI for outgoing connections. Please set <hostname> to NULL
 * to disable SNI.
 */
void ssl_sock_set_servername(struct connection *conn, const char *hostname)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	struct ssl_sock_ctx *ctx;

	char *prev_name;

	if (!ssl_sock_is_ssl(conn))
		return;
	ctx = conn->xprt_ctx;

	/* if the SNI changes, we must destroy the reusable context so that a
	 * new connection will present a new SNI. As an optimization we could
	 * later imagine having a small cache of ssl_ctx to hold a few SNI per
	 * server.
	 */
	prev_name = (char *)SSL_get_servername(ctx->ssl, TLSEXT_NAMETYPE_host_name);
	if ((!prev_name && hostname) ||
	    (prev_name && (!hostname || strcmp(hostname, prev_name) != 0)))
		SSL_set_session(ctx->ssl, NULL);

	SSL_set_tlsext_host_name(ctx->ssl, hostname);
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
	struct ssl_sock_ctx *ctx;
	X509 *crt = NULL;
	X509_NAME *name;
	const char find_cn[] = "CN";
	const struct buffer find_cn_chunk = {
		.area = (char *)&find_cn,
		.data = sizeof(find_cn)-1
	};
	int result = -1;

	if (!ssl_sock_is_ssl(conn))
		goto out;
	ctx = conn->xprt_ctx;

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
	struct ssl_sock_ctx *ctx;
	X509 *crt = NULL;

	if (!ssl_sock_is_ssl(conn))
		return 0;
	ctx = conn->xprt_ctx;

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
	struct ssl_sock_ctx *ctx;

	if (!ssl_sock_is_ssl(conn))
		return 0;
	ctx = conn->xprt_ctx;
	return SSL_SOCK_ST_FL_VERIFY_DONE & ctx->xprt_st ? 1 : 0;
}

/* returns result from SSL verify */
unsigned int ssl_sock_get_verify_result(struct connection *conn)
{
	struct ssl_sock_ctx *ctx;

	if (!ssl_sock_is_ssl(conn))
		return (unsigned int)X509_V_ERR_APPLICATION_VERIFICATION;
	ctx = conn->xprt_ctx;
	return (unsigned int)SSL_get_verify_result(ctx->ssl);
}

/* Returns the application layer protocol name in <str> and <len> when known.
 * Zero is returned if the protocol name was not found, otherwise non-zero is
 * returned. The string is allocated in the SSL context and doesn't have to be
 * freed by the caller. NPN is also checked if available since older versions
 * of openssl (1.0.1) which are more common in field only support this one.
 */
static int ssl_sock_get_alpn(const struct connection *conn, void *xprt_ctx, const char **str, int *len)
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

/***** Below are some sample fetching functions for ACL/patterns *****/

static int
smp_fetch_ssl_fc_has_early(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	smp->flags = 0;
	smp->data.type = SMP_T_BOOL;
#ifdef OPENSSL_IS_BORINGSSL
	{
		struct ssl_sock_ctx *ctx = conn->xprt_ctx;
		smp->data.u.sint = (SSL_in_early_data(ctx->ssl) &&
				    SSL_early_data_accepted(ctx->ssl));
	}
#else
	smp->data.u.sint = ((conn->flags & CO_FL_EARLY_DATA)  &&
	    (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_HANDSHAKE))) ? 1 : 0;
#endif
	return 1;
}

/* boolean, returns true if client cert was present */
static int
smp_fetch_ssl_fc_has_crt(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->flags = 0;
	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = SSL_SOCK_ST_FL_VERIFY_DONE & ctx->xprt_st ? 1 : 0;

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
	struct buffer *smp_trash;
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);

	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_crt2der(crt, smp_trash) <= 0)
		goto out;

	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_BIN;
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
	struct buffer *smp_trash;
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);

	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_get_serial(crt, smp_trash) <= 0)
		goto out;

	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_BIN;
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
	struct buffer *smp_trash;
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);
	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	digest = EVP_sha1();
	X509_digest(crt, digest, (unsigned char *) smp_trash->area,
		    (unsigned int *)&smp_trash->data);

	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_BIN;
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
	struct buffer *smp_trash;
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);
	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_get_time(X509_getm_notAfter(crt), smp_trash) <= 0)
		goto out;

	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_STR;
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
	struct buffer *smp_trash;
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);
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

		if (ssl_sock_get_dn_entry(name, &args[0].data.str, pos, smp_trash) <= 0)
			goto out;
	}
	else if (ssl_sock_get_dn_oneline(name, smp_trash) <= 0)
		goto out;

	smp->data.type = SMP_T_STR;
	smp->data.u.str = *smp_trash;
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
	struct buffer *smp_trash;
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);
	if (!crt)
		goto out;

	smp_trash = get_trash_chunk();
	if (ssl_sock_get_time(X509_getm_notBefore(crt), smp_trash) <= 0)
		goto out;

	smp->data.u.str = *smp_trash;
	smp->data.type = SMP_T_STR;
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
	struct buffer *smp_trash;
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);
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

		if (ssl_sock_get_dn_entry(name, &args[0].data.str, pos, smp_trash) <= 0)
			goto out;
	}
	else if (ssl_sock_get_dn_oneline(name, smp_trash) <= 0)
		goto out;

	smp->data.type = SMP_T_STR;
	smp->data.u.str = *smp_trash;
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
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	/* SSL_get_peer_certificate returns a ptr on allocated X509 struct */
	crt = SSL_get_peer_certificate(ctx->ssl);
	if (crt) {
		X509_free(crt);
	}

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (crt != NULL);
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
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);
	if (!crt)
		return 0;

	smp->data.u.sint = (unsigned int)(1 + X509_get_version(crt));
	/* SSL_get_peer_certificate increase X509 * ref count  */
	if (cert_peer)
		X509_free(crt);
	smp->data.type = SMP_T_SINT;

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
	__OPENSSL_110_CONST__ ASN1_OBJECT *algorithm;
	int nid;
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);
	if (!crt)
		return 0;

	X509_ALGOR_get0(&algorithm, NULL, NULL, X509_get0_tbs_sigalg(crt));
	nid = OBJ_obj2nid(algorithm);

	smp->data.u.str.area = (char *)OBJ_nid2sn(nid);
	if (!smp->data.u.str.area) {
		/* SSL_get_peer_certificate increase X509 * ref count  */
		if (cert_peer)
			X509_free(crt);
		return 0;
	}

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);
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
	ASN1_OBJECT *algorithm;
	int nid;
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	if (cert_peer)
		crt = SSL_get_peer_certificate(ctx->ssl);
	else
		crt = SSL_get_certificate(ctx->ssl);
	if (!crt)
		return 0;

	X509_PUBKEY_get0_param(&algorithm, NULL, NULL, NULL, X509_get_X509_PUBKEY(crt));
	nid = OBJ_obj2nid(algorithm);

	smp->data.u.str.area = (char *)OBJ_nid2sn(nid);
	if (!smp->data.u.str.area) {
		/* SSL_get_peer_certificate increase X509 * ref count  */
		if (cert_peer)
			X509_free(crt);
		return 0;
	}

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);
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
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (conn && conn->xprt == &ssl_sock);
	return 1;
}

/* boolean, returns true if client present a SNI */
static int
smp_fetch_ssl_fc_has_sni(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	struct connection *conn = objt_conn(smp->sess->origin);
	struct ssl_sock_ctx *ctx = conn ? conn->xprt_ctx : NULL;

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (conn && conn->xprt == &ssl_sock) &&
		conn->xprt_ctx &&
		SSL_get_servername(ctx->ssl, TLSEXT_NAMETYPE_host_name) != NULL;
	return 1;
#else
	return 0;
#endif
}

/* boolean, returns true if client session has been resumed.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_is_resumed(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	struct ssl_sock_ctx *ctx = conn ? conn->xprt_ctx : NULL;


	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = (conn && conn->xprt == &ssl_sock) &&
		conn->xprt_ctx &&
		SSL_session_reused(ctx->ssl);
	return 1;
}

/* string, returns the used cipher if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_cipher(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	struct ssl_sock_ctx *ctx;

	smp->flags = 0;
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	smp->data.u.str.area = (char *)SSL_get_cipher_name(ctx->ssl);
	if (!smp->data.u.str.area)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags |= SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);

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
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	struct ssl_sock_ctx *ctx;
	int sint;

	smp->flags = 0;
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!SSL_get_cipher_bits(ctx->ssl, &sint))
		return 0;

	smp->data.u.sint = sint;
	smp->data.type = SMP_T_SINT;

	return 1;
}

/* integer, returns the used keysize if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
static int
smp_fetch_ssl_fc_use_keysize(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	struct ssl_sock_ctx *ctx;

	smp->flags = 0;
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	smp->data.u.sint = (unsigned int)SSL_get_cipher_bits(ctx->ssl, NULL);
	if (!smp->data.u.sint)
		return 0;

	smp->data.type = SMP_T_SINT;

	return 1;
}

#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
static int
smp_fetch_ssl_fc_npn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	smp->flags = SMP_F_CONST;
	smp->data.type = SMP_T_STR;

	conn = (kw[4] != 'b' ) ? objt_conn(smp->sess->origin) :
	    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	smp->data.u.str.area = NULL;
	SSL_get0_next_proto_negotiated(ctx->ssl,
	                                (const unsigned char **)&smp->data.u.str.area,
	                                (unsigned *)&smp->data.u.str.data);

	if (!smp->data.u.str.area)
		return 0;

	return 1;
}
#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int
smp_fetch_ssl_fc_alpn(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	smp->flags = SMP_F_CONST;
	smp->data.type = SMP_T_STR;

	conn = (kw[4] != 'b' ) ? objt_conn(smp->sess->origin) :
	    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;

	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	smp->data.u.str.area = NULL;
	SSL_get0_alpn_selected(ctx->ssl,
	                         (const unsigned char **)&smp->data.u.str.area,
	                         (unsigned *)&smp->data.u.str.data);

	if (!smp->data.u.str.area)
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
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	struct ssl_sock_ctx *ctx;

	smp->flags = 0;
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	smp->data.u.str.area = (char *)SSL_get_version(ctx->ssl);
	if (!smp->data.u.str.area)
		return 0;

	smp->data.type = SMP_T_STR;
	smp->flags = SMP_F_CONST;
	smp->data.u.str.data = strlen(smp->data.u.str.area);

	return 1;
}

/* binary, returns the SSL stream id if front conn. transport layer is SSL.
 * This function is also usable on backend conn if the fetch keyword 5th
 * char is 'b'.
 */
#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
static int
smp_fetch_ssl_fc_session_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	SSL_SESSION *ssl_sess;
	struct ssl_sock_ctx *ctx;

	smp->flags = SMP_F_CONST;
	smp->data.type = SMP_T_BIN;

	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	ssl_sess = SSL_get_session(ctx->ssl);
	if (!ssl_sess)
		return 0;

	smp->data.u.str.area = (char *)SSL_SESSION_get_id(ssl_sess,
							  (unsigned int *)&smp->data.u.str.data);
	if (!smp->data.u.str.area || !smp->data.u.str.data)
		return 0;

	return 1;
}
#endif


#if HA_OPENSSL_VERSION_NUMBER >= 0x10100000L
static int
smp_fetch_ssl_fc_random(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                           smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	struct buffer *data;
	struct ssl_sock_ctx *ctx;

	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	data = get_trash_chunk();
	if (kw[7] == 'c')
		data->data = SSL_get_client_random(ctx->ssl,
		                                   (unsigned char *) data->area,
		                                   data->size);
	else
		data->data = SSL_get_server_random(ctx->ssl,
		                                   (unsigned char *) data->area,
		                                   data->size);
	if (!data->data)
		return 0;

	smp->flags = 0;
	smp->data.type = SMP_T_BIN;
	smp->data.u.str = *data;

	return 1;
}

static int
smp_fetch_ssl_fc_session_key(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	SSL_SESSION *ssl_sess;
	struct buffer *data;
	struct ssl_sock_ctx *ctx;

	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	ssl_sess = SSL_get_session(ctx->ssl);
	if (!ssl_sess)
		return 0;

	data = get_trash_chunk();
	data->data = SSL_SESSION_get_master_key(ssl_sess,
					       (unsigned char *) data->area,
					       data->size);
	if (!data->data)
		return 0;

	smp->flags = 0;
	smp->data.type = SMP_T_BIN;
	smp->data.u.str = *data;

	return 1;
}
#endif

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static int
smp_fetch_ssl_fc_sni(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	smp->flags = SMP_F_CONST;
	smp->data.type = SMP_T_STR;

	conn = objt_conn(smp->sess->origin);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	smp->data.u.str.area = (char *)SSL_get_servername(ctx->ssl, TLSEXT_NAMETYPE_host_name);
	if (!smp->data.u.str.area)
		return 0;

	smp->data.u.str.data = strlen(smp->data.u.str.area);
	return 1;
}
#endif

static int
smp_fetch_ssl_fc_cl_bin(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_capture *capture;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	capture = SSL_get_ex_data(ctx->ssl, ssl_capture_ptr_index);
	if (!capture)
		return 0;

	smp->flags = SMP_F_CONST;
	smp->data.type = SMP_T_BIN;
	smp->data.u.str.area = capture->ciphersuite;
	smp->data.u.str.data = capture->ciphersuite_len;
	return 1;
}

static int
smp_fetch_ssl_fc_cl_hex(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct buffer *data;

	if (!smp_fetch_ssl_fc_cl_bin(args, smp, kw, private))
		return 0;

	data = get_trash_chunk();
	dump_binary(data, smp->data.u.str.area, smp->data.u.str.data);
	smp->data.type = SMP_T_BIN;
	smp->data.u.str = *data;
	return 1;
}

static int
smp_fetch_ssl_fc_cl_xxh64(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_capture *capture;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	capture = SSL_get_ex_data(ctx->ssl, ssl_capture_ptr_index);
	if (!capture)
		return 0;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = capture->xxh64;
	return 1;
}

static int
smp_fetch_ssl_fc_cl_str(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL)
	struct buffer *data;
	int i;

	if (!smp_fetch_ssl_fc_cl_bin(args, smp, kw, private))
		return 0;

	data = get_trash_chunk();
	for (i = 0; i + 1 < smp->data.u.str.data; i += 2) {
		const char *str;
		const SSL_CIPHER *cipher;
		const unsigned char *bin = (const unsigned char *) smp->data.u.str.area + i;
		uint16_t id = (bin[0] << 8) | bin[1];
#if defined(OPENSSL_IS_BORINGSSL)
		cipher = SSL_get_cipher_by_value(id);
#else
		struct connection *conn = __objt_conn(smp->sess->origin);
		struct ssl_sock_ctx *ctx = conn->xprt_ctx;
		cipher = SSL_CIPHER_find(ctx->ssl, bin);
#endif
		str = SSL_CIPHER_get_name(cipher);
		if (!str || strcmp(str, "(NONE)") == 0)
			chunk_appendf(data, "%sUNKNOWN(%04x)", i == 0 ? "" : ",", id);
		else
			chunk_appendf(data, "%s%s", i == 0 ? "" : ",", str);
	}
	smp->data.type = SMP_T_STR;
	smp->data.u.str = *data;
	return 1;
#else
	return smp_fetch_ssl_fc_cl_xxh64(args, smp, kw, private);
#endif
}

#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
static int
smp_fetch_ssl_fc_unique_id(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn = (kw[4] != 'b') ? objt_conn(smp->sess->origin) :
	                                    smp->strm ? cs_conn(objt_cs(smp->strm->si[1].end)) : NULL;
	int finished_len;
	struct buffer *finished_trash;
	struct ssl_sock_ctx *ctx;

	smp->flags = 0;
	if (!conn || !conn->xprt_ctx || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}

	finished_trash = get_trash_chunk();
	if (!SSL_session_reused(ctx->ssl))
		finished_len = SSL_get_peer_finished(ctx->ssl,
						     finished_trash->area,
						     finished_trash->size);
	else
		finished_len = SSL_get_finished(ctx->ssl,
						finished_trash->area,
						finished_trash->size);

	if (!finished_len)
		return 0;

	finished_trash->data = finished_len;
	smp->data.u.str = *finished_trash;
	smp->data.type = SMP_T_BIN;

	return 1;
}
#endif

/* integer, returns the first verify error in CA chain of client certificate chain. */
static int
smp_fetch_ssl_c_ca_err(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;
	ctx = conn->xprt_ctx;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (unsigned long long int)SSL_SOCK_ST_TO_CA_ERROR(ctx->xprt_st);
	smp->flags = 0;

	return 1;
}

/* integer, returns the depth of the first verify error in CA chain of client certificate chain. */
static int
smp_fetch_ssl_c_ca_err_depth(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}
	ctx = conn->xprt_ctx;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (long long int)SSL_SOCK_ST_TO_CAEDEPTH(ctx->xprt_st);
	smp->flags = 0;

	return 1;
}

/* integer, returns the first verify error on client certificate */
static int
smp_fetch_ssl_c_err(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	ctx = conn->xprt_ctx;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (long long int)SSL_SOCK_ST_TO_CRTERROR(ctx->xprt_st);
	smp->flags = 0;

	return 1;
}

/* integer, returns the verify result on client cert */
static int
smp_fetch_ssl_c_verify(const struct arg *args, struct sample *smp, const char *kw, void *private)
{
	struct connection *conn;
	struct ssl_sock_ctx *ctx;

	conn = objt_conn(smp->sess->origin);
	if (!conn || conn->xprt != &ssl_sock)
		return 0;

	if (!(conn->flags & CO_FL_CONNECTED)) {
		smp->flags = SMP_F_MAY_CHANGE;
		return 0;
	}

	if (!conn->xprt_ctx)
		return 0;
	ctx = conn->xprt_ctx;

	smp->data.type = SMP_T_SINT;
	smp->data.u.sint = (long long int)SSL_get_verify_result(ctx->ssl);
	smp->flags = 0;

	return 1;
}

/* parse the "ca-file" bind keyword */
static int ssl_bind_parse_ca_file(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CAfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && global_ssl.ca_base)
		memprintf(&conf->ca_file, "%s/%s", global_ssl.ca_base, args[cur_arg + 1]);
	else
		memprintf(&conf->ca_file, "%s", args[cur_arg + 1]);

	return 0;
}
static int bind_parse_ca_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ca_file(args, cur_arg, px, &conf->ssl_conf, err);
}

/* parse the "ca-sign-file" bind keyword */
static int bind_parse_ca_sign_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CAfile path", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/') && global_ssl.ca_base)
		memprintf(&conf->ca_sign_file, "%s/%s", global_ssl.ca_base, args[cur_arg + 1]);
	else
		memprintf(&conf->ca_sign_file, "%s", args[cur_arg + 1]);

	return 0;
}

/* parse the "ca-sign-pass" bind keyword */
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
static int ssl_bind_parse_ciphers(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->ciphers);
	conf->ciphers = strdup(args[cur_arg + 1]);
	return 0;
}
static int bind_parse_ciphers(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ciphers(args, cur_arg, px, &conf->ssl_conf, err);
}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
/* parse the "ciphersuites" bind keyword */
static int ssl_bind_parse_ciphersuites(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->ciphersuites);
	conf->ciphersuites = strdup(args[cur_arg + 1]);
	return 0;
}
static int bind_parse_ciphersuites(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ciphersuites(args, cur_arg, px, &conf->ssl_conf, err);
}
#endif

/* parse the "crt" bind keyword. Returns a set of ERR_* flags possibly with an error in <err>. */
static int bind_parse_crt(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	char path[MAXPATHLEN];

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate location", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[cur_arg + 1] != '/' ) && global_ssl.crt_base) {
		if ((strlen(global_ssl.crt_base) + 1 + strlen(args[cur_arg + 1]) + 1) > MAXPATHLEN) {
			memprintf(err, "'%s' : path too long", args[cur_arg]);
			return ERR_ALERT | ERR_FATAL;
		}
		snprintf(path, sizeof(path), "%s/%s",  global_ssl.crt_base, args[cur_arg + 1]);
		return ssl_sock_load_cert(path, conf, err);
	}

	return ssl_sock_load_cert(args[cur_arg + 1], conf, err);
}

/* parse the "crt-list" bind keyword. Returns a set of ERR_* flags possibly with an error in <err>. */
static int bind_parse_crt_list(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	int err_code;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing certificate location", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	err_code = ssl_sock_load_cert_list_file(args[cur_arg + 1], conf, px, err);
	if (err_code)
		memprintf(err, "'%s' : %s", args[cur_arg], *err);

	return err_code;
}

/* parse the "crl-file" bind keyword */
static int ssl_bind_parse_crl_file(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
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

	if ((*args[cur_arg + 1] != '/') && global_ssl.ca_base)
		memprintf(&conf->crl_file, "%s/%s", global_ssl.ca_base, args[cur_arg + 1]);
	else
		memprintf(&conf->crl_file, "%s", args[cur_arg + 1]);

	return 0;
#endif
}
static int bind_parse_crl_file(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_crl_file(args, cur_arg, px, &conf->ssl_conf, err);
}

/* parse the "curves" bind keyword keyword */
static int ssl_bind_parse_curves(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing curve suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	conf->curves = strdup(args[cur_arg + 1]);
	return 0;
#else
	if (err)
		memprintf(err, "'%s' : library does not support curve suite", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}
static int bind_parse_curves(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_curves(args, cur_arg, px, &conf->ssl_conf, err);
}

/* parse the "ecdhe" bind keyword keyword */
static int ssl_bind_parse_ecdhe(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
#if HA_OPENSSL_VERSION_NUMBER < 0x0090800fL
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
static int bind_parse_ecdhe(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_ecdhe(args, cur_arg, px, &conf->ssl_conf, err);
}

/* parse the "crt-ignore-err" and "ca-ignore-err" bind keywords */
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

/* parse tls_method_options "no-xxx" and "force-xxx" */
static int parse_tls_method_options(char *arg, struct tls_version_filter *methods, char **err)
{
	uint16_t v;
	char *p;
	p = strchr(arg, '-');
	if (!p)
		goto fail;
	p++;
	if (!strcmp(p, "sslv3"))
		v = CONF_SSLV3;
	else if (!strcmp(p, "tlsv10"))
		v = CONF_TLSV10;
	else if (!strcmp(p, "tlsv11"))
		v = CONF_TLSV11;
	else if (!strcmp(p, "tlsv12"))
		v = CONF_TLSV12;
	else if (!strcmp(p, "tlsv13"))
		v = CONF_TLSV13;
	else
		goto fail;
	if (!strncmp(arg, "no-", 3))
		methods->flags |= methodVersions[v].flag;
	else if (!strncmp(arg, "force-", 6))
		methods->min = methods->max = v;
	else
		goto fail;
	return 0;
 fail:
	if (err)
		memprintf(err, "'%s' : option not implemented", arg);
	return ERR_ALERT | ERR_FATAL;
}

static int bind_parse_tls_method_options(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return parse_tls_method_options(args[cur_arg], &conf->ssl_conf.ssl_methods, err);
}

static int srv_parse_tls_method_options(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	return parse_tls_method_options(args[*cur_arg], &newsrv->ssl_ctx.methods, err);
}

/* parse tls_method min/max: "ssl-min-ver" and "ssl-max-ver" */
static int parse_tls_method_minmax(char **args, int cur_arg, struct tls_version_filter *methods, char **err)
{
	uint16_t i, v = 0;
	char *argv = args[cur_arg + 1];
	if (!*argv) {
		if (err)
			memprintf(err, "'%s' : missing the ssl/tls version", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++)
		if (!strcmp(argv, methodVersions[i].name))
			v = i;
	if (!v) {
		if (err)
			memprintf(err, "'%s' : unknown ssl/tls version", args[cur_arg + 1]);
		return ERR_ALERT | ERR_FATAL;
	}
	if (!strcmp("ssl-min-ver", args[cur_arg]))
		methods->min = v;
	else if (!strcmp("ssl-max-ver", args[cur_arg]))
		methods->max = v;
	else {
		if (err)
			memprintf(err, "'%s' : option not implemented", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;
}

static int ssl_bind_parse_tls_method_minmax(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
#if (HA_OPENSSL_VERSION_NUMBER < 0x10101000L) && !defined(OPENSSL_IS_BORINGSSL)
	ha_warning("crt-list: ssl-min-ver and ssl-max-ver are not supported with this Openssl version (skipped).\n");
#endif
	return parse_tls_method_minmax(args, cur_arg, &conf->ssl_methods, err);
}

static int bind_parse_tls_method_minmax(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return parse_tls_method_minmax(args, cur_arg, &conf->ssl_conf.ssl_methods, err);
}

static int srv_parse_tls_method_minmax(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	return parse_tls_method_minmax(args, *cur_arg, &newsrv->ssl_ctx.methods, err);
}

/* parse the "no-tls-tickets" bind keyword */
static int bind_parse_no_tls_tickets(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_options |= BC_SSL_O_NO_TLS_TICKETS;
	return 0;
}

/* parse the "allow-0rtt" bind keyword */
static int ssl_bind_parse_allow_0rtt(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
	conf->early_data = 1;
	return 0;
}

static int bind_parse_allow_0rtt(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->ssl_conf.early_data = 1;
	return 0;
}

/* parse the "npn" bind keyword */
static int ssl_bind_parse_npn(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	char *p1, *p2;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing the comma-delimited NPN protocol suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->npn_str);

	/* the NPN string is built as a suite of (<len> <name>)*,
	 * so we reuse each comma to store the next <len> and need
	 * one more for the end of the string.
	 */
	conf->npn_len = strlen(args[cur_arg + 1]) + 1;
	conf->npn_str = calloc(1, conf->npn_len + 1);
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

static int bind_parse_npn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_npn(args, cur_arg, px, &conf->ssl_conf, err);
}

/* parse the "alpn" bind keyword */
static int ssl_bind_parse_alpn(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	char *p1, *p2;

	if (!*args[cur_arg + 1]) {
		memprintf(err, "'%s' : missing the comma-delimited ALPN protocol suite", args[cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(conf->alpn_str);

	/* the ALPN string is built as a suite of (<len> <name>)*,
	 * so we reuse each comma to store the next <len> and need
	 * one more for the end of the string.
	 */
	conf->alpn_len = strlen(args[cur_arg + 1]) + 1;
	conf->alpn_str = calloc(1, conf->alpn_len + 1);
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

static int bind_parse_alpn(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_alpn(args, cur_arg, px, &conf->ssl_conf, err);
}

/* parse the "ssl" bind keyword */
static int bind_parse_ssl(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->xprt = &ssl_sock;
	conf->is_ssl = 1;

	if (global_ssl.listen_default_ciphers && !conf->ssl_conf.ciphers)
		conf->ssl_conf.ciphers = strdup(global_ssl.listen_default_ciphers);
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (global_ssl.listen_default_ciphersuites && !conf->ssl_conf.ciphersuites)
		conf->ssl_conf.ciphersuites = strdup(global_ssl.listen_default_ciphersuites);
#endif
	conf->ssl_options |= global_ssl.listen_default_ssloptions;
	conf->ssl_conf.ssl_methods.flags |= global_ssl.listen_default_sslmethods.flags;
	if (!conf->ssl_conf.ssl_methods.min)
		conf->ssl_conf.ssl_methods.min = global_ssl.listen_default_sslmethods.min;
	if (!conf->ssl_conf.ssl_methods.max)
		conf->ssl_conf.ssl_methods.max = global_ssl.listen_default_sslmethods.max;

	return 0;
}

/* parse the "prefer-client-ciphers" bind keyword */
static int bind_parse_pcc(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
        conf->ssl_options |= BC_SSL_O_PREF_CLIE_CIPH;
        return 0;
}

/* parse the "generate-certificates" bind keyword */
static int bind_parse_generate_certs(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
#if (defined SSL_CTRL_SET_TLSEXT_HOSTNAME && !defined SSL_NO_GENERATE_CERTIFICATES)
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
	FILE *f = NULL;
	int i = 0;
	char thisline[LINESIZE];
	struct tls_keys_ref *keys_ref = NULL;

	if (!*args[cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing TLS ticket keys file path", args[cur_arg]);
		goto fail;
	}

	keys_ref = tlskeys_ref_lookup(args[cur_arg + 1]);
	if (keys_ref) {
		keys_ref->refcount++;
		conf->keys_ref = keys_ref;
		return 0;
	}

	keys_ref = calloc(1, sizeof(*keys_ref));
	if (!keys_ref) {
		if (err)
			 memprintf(err, "'%s' : allocation error", args[cur_arg+1]);
		goto fail;
	}

	keys_ref->tlskeys = malloc(TLS_TICKETS_NO * sizeof(union tls_sess_key));
	if (!keys_ref->tlskeys) {
		if (err)
			 memprintf(err, "'%s' : allocation error", args[cur_arg+1]);
		goto fail;
	}

	if ((f = fopen(args[cur_arg + 1], "r")) == NULL) {
		if (err)
			memprintf(err, "'%s' : unable to load ssl tickets keys file", args[cur_arg+1]);
		goto fail;
	}

	keys_ref->filename = strdup(args[cur_arg + 1]);
	if (!keys_ref->filename) {
		if (err)
			 memprintf(err, "'%s' : allocation error", args[cur_arg+1]);
		goto fail;
	}

	keys_ref->key_size_bits = 0;
	while (fgets(thisline, sizeof(thisline), f) != NULL) {
		int len = strlen(thisline);
		int dec_size;

		/* Strip newline characters from the end */
		if(thisline[len - 1] == '\n')
			thisline[--len] = 0;

		if(thisline[len - 1] == '\r')
			thisline[--len] = 0;

		dec_size = base64dec(thisline, len, (char *) (keys_ref->tlskeys + i % TLS_TICKETS_NO), sizeof(union tls_sess_key));
		if (dec_size < 0) {
			if (err)
				memprintf(err, "'%s' : unable to decode base64 key on line %d", args[cur_arg+1], i + 1);
			goto fail;
		}
		else if (!keys_ref->key_size_bits && (dec_size == sizeof(struct tls_sess_key_128))) {
			keys_ref->key_size_bits = 128;
		}
		else if (!keys_ref->key_size_bits && (dec_size == sizeof(struct tls_sess_key_256))) {
			keys_ref->key_size_bits = 256;
		}
		else if (((dec_size != sizeof(struct tls_sess_key_128)) && (dec_size != sizeof(struct tls_sess_key_256)))
			 || ((dec_size == sizeof(struct tls_sess_key_128) && (keys_ref->key_size_bits != 128)))
			 || ((dec_size == sizeof(struct tls_sess_key_256) && (keys_ref->key_size_bits != 256)))) {
			if (err)
				memprintf(err, "'%s' : wrong sized key on line %d", args[cur_arg+1], i + 1);
			goto fail;
		}
		i++;
	}

	if (i < TLS_TICKETS_NO) {
		if (err)
			memprintf(err, "'%s' : please supply at least %d keys in the tls-tickets-file", args[cur_arg+1], TLS_TICKETS_NO);
		goto fail;
	}

	fclose(f);

	/* Use penultimate key for encryption, handle when TLS_TICKETS_NO = 1 */
	i -= 2;
	keys_ref->tls_ticket_enc_index = i < 0 ? 0 : i % TLS_TICKETS_NO;
	keys_ref->unique_id = -1;
	keys_ref->refcount = 1;
	HA_RWLOCK_INIT(&keys_ref->lock);
	conf->keys_ref = keys_ref;

	LIST_ADD(&tlskeys_reference, &keys_ref->list);

	return 0;

  fail:
	if (f)
		fclose(f);
	if (keys_ref) {
		free(keys_ref->filename);
		free(keys_ref->tlskeys);
		free(keys_ref);
	}
	return ERR_ALERT | ERR_FATAL;

#else
	if (err)
		memprintf(err, "'%s' : TLS ticket callback extension not supported", args[cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif /* SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB */
}

/* parse the "verify" bind keyword */
static int ssl_bind_parse_verify(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
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
static int bind_parse_verify(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_verify(args, cur_arg, px, &conf->ssl_conf, err);
}

/* parse the "no-ca-names" bind keyword */
static int ssl_bind_parse_no_ca_names(char **args, int cur_arg, struct proxy *px, struct ssl_bind_conf *conf, char **err)
{
	conf->no_ca_names = 1;
	return 0;
}
static int bind_parse_no_ca_names(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	return ssl_bind_parse_no_ca_names(args, cur_arg, px, &conf->ssl_conf, err);
}

/************** "server" keywords ****************/

/* parse the "npn" bind keyword */
static int srv_parse_npn(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	char *p1, *p2;

	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing the comma-delimited NPN protocol suite", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->ssl_ctx.npn_str);

	/* the NPN string is built as a suite of (<len> <name>)*,
	 * so we reuse each comma to store the next <len> and need
	 * one more for the end of the string.
	 */
	newsrv->ssl_ctx.npn_len = strlen(args[*cur_arg + 1]) + 1;
	newsrv->ssl_ctx.npn_str = calloc(1, newsrv->ssl_ctx.npn_len + 1);
	memcpy(newsrv->ssl_ctx.npn_str + 1, args[*cur_arg + 1],
	    newsrv->ssl_ctx.npn_len);

	/* replace commas with the name length */
	p1 = newsrv->ssl_ctx.npn_str;
	p2 = p1 + 1;
	while (1) {
		p2 = memchr(p1 + 1, ',', newsrv->ssl_ctx.npn_str +
		    newsrv->ssl_ctx.npn_len - (p1 + 1));
		if (!p2)
			p2 = p1 + 1 + strlen(p1 + 1);

		if (p2 - (p1 + 1) > 255) {
			*p2 = '\0';
			memprintf(err, "'%s' : NPN protocol name too long : '%s'", args[*cur_arg], p1 + 1);
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
		memprintf(err, "'%s' : library does not support TLS NPN extension", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* parse the "alpn" or the "check-alpn" server keyword */
static int srv_parse_alpn(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	char *p1, *p2;
	char **alpn_str;
	int *alpn_len;

	if (*args[*cur_arg] == 'c') {
		alpn_str = &newsrv->check.alpn_str;
		alpn_len = &newsrv->check.alpn_len;
	} else {
		alpn_str = &newsrv->ssl_ctx.alpn_str;
		alpn_len = &newsrv->ssl_ctx.alpn_len;

	}
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing the comma-delimited ALPN protocol suite", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(*alpn_str);

	/* the ALPN string is built as a suite of (<len> <name>)*,
	 * so we reuse each comma to store the next <len> and need
	 * one more for the end of the string.
	 */
	*alpn_len = strlen(args[*cur_arg + 1]) + 1;
	*alpn_str = calloc(1, *alpn_len + 1);
	memcpy(*alpn_str + 1, args[*cur_arg + 1], *alpn_len);

	/* replace commas with the name length */
	p1 = *alpn_str;
	p2 = p1 + 1;
	while (1) {
		p2 = memchr(p1 + 1, ',', *alpn_str + *alpn_len - (p1 + 1));
		if (!p2)
			p2 = p1 + 1 + strlen(p1 + 1);

		if (p2 - (p1 + 1) > 255) {
			*p2 = '\0';
			memprintf(err, "'%s' : ALPN protocol name too long : '%s'", args[*cur_arg], p1 + 1);
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
		memprintf(err, "'%s' : library does not support TLS ALPN extension", args[*cur_arg]);
	return ERR_ALERT | ERR_FATAL;
#endif
}

/* parse the "ca-file" server keyword */
static int srv_parse_ca_file(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing CAfile path", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	if ((*args[*cur_arg + 1] != '/') && global_ssl.ca_base)
		memprintf(&newsrv->ssl_ctx.ca_file, "%s/%s", global_ssl.ca_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.ca_file, "%s", args[*cur_arg + 1]);

	return 0;
}

/* parse the "check-sni" server keyword */
static int srv_parse_check_sni(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		if (err)
			memprintf(err, "'%s' : missing SNI", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	newsrv->check.sni = strdup(args[*cur_arg + 1]);
	if (!newsrv->check.sni) {
		memprintf(err, "'%s' : failed to allocate memory", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}
	return 0;

}

/* parse the "check-ssl" server keyword */
static int srv_parse_check_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->check.use_ssl = 1;
	if (global_ssl.connect_default_ciphers && !newsrv->ssl_ctx.ciphers)
		newsrv->ssl_ctx.ciphers = strdup(global_ssl.connect_default_ciphers);
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (global_ssl.connect_default_ciphersuites && !newsrv->ssl_ctx.ciphersuites)
		newsrv->ssl_ctx.ciphersuites = strdup(global_ssl.connect_default_ciphersuites);
#endif
	newsrv->ssl_ctx.options |= global_ssl.connect_default_ssloptions;
	newsrv->ssl_ctx.methods.flags |= global_ssl.connect_default_sslmethods.flags;
	if (!newsrv->ssl_ctx.methods.min)
		newsrv->ssl_ctx.methods.min = global_ssl.connect_default_sslmethods.min;
	if (!newsrv->ssl_ctx.methods.max)
		newsrv->ssl_ctx.methods.max = global_ssl.connect_default_sslmethods.max;

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

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
/* parse the "ciphersuites" server keyword */
static int srv_parse_ciphersuites(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	if (!*args[*cur_arg + 1]) {
		memprintf(err, "'%s' : missing cipher suite", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->ssl_ctx.ciphersuites);
	newsrv->ssl_ctx.ciphersuites = strdup(args[*cur_arg + 1]);
	return 0;
}
#endif

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

	if ((*args[*cur_arg + 1] != '/') && global_ssl.ca_base)
		memprintf(&newsrv->ssl_ctx.crl_file, "%s/%s", global_ssl.ca_base, args[*cur_arg + 1]);
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

	if ((*args[*cur_arg + 1] != '/') && global_ssl.crt_base)
		memprintf(&newsrv->ssl_ctx.client_crt, "%s/%s", global_ssl.crt_base, args[*cur_arg + 1]);
	else
		memprintf(&newsrv->ssl_ctx.client_crt, "%s", args[*cur_arg + 1]);

	return 0;
}

/* parse the "no-check-ssl" server keyword */
static int srv_parse_no_check_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->check.use_ssl = 0;
	free(newsrv->ssl_ctx.ciphers);
	newsrv->ssl_ctx.ciphers = NULL;
	newsrv->ssl_ctx.options &= ~global_ssl.connect_default_ssloptions;
	return 0;
}

/* parse the "no-send-proxy-v2-ssl" server keyword */
static int srv_parse_no_send_proxy_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->pp_opts &= ~SRV_PP_V2;
	newsrv->pp_opts &= ~SRV_PP_V2_SSL;
	return 0;
}

/* parse the "no-send-proxy-v2-ssl-cn" server keyword */
static int srv_parse_no_send_proxy_cn(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->pp_opts &= ~SRV_PP_V2;
	newsrv->pp_opts &= ~SRV_PP_V2_SSL;
	newsrv->pp_opts &= ~SRV_PP_V2_SSL_CN;
	return 0;
}

/* parse the "no-ssl" server keyword */
static int srv_parse_no_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->use_ssl = 0;
	free(newsrv->ssl_ctx.ciphers);
	newsrv->ssl_ctx.ciphers = NULL;
	return 0;
}

/* parse the "allow-0rtt" server keyword */
static int srv_parse_allow_0rtt(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_EARLY_DATA;
	return 0;
}

/* parse the "no-ssl-reuse" server keyword */
static int srv_parse_no_ssl_reuse(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options |= SRV_SSL_O_NO_REUSE;
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
	char *arg;

	arg = args[*cur_arg + 1];
	if (!*arg) {
		memprintf(err, "'%s' : missing sni expression", args[*cur_arg]);
		return ERR_ALERT | ERR_FATAL;
	}

	free(newsrv->sni_expr);
	newsrv->sni_expr = strdup(arg);

	return 0;
#endif
}

/* parse the "ssl" server keyword */
static int srv_parse_ssl(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->use_ssl = 1;
	if (global_ssl.connect_default_ciphers && !newsrv->ssl_ctx.ciphers)
		newsrv->ssl_ctx.ciphers = strdup(global_ssl.connect_default_ciphers);
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (global_ssl.connect_default_ciphersuites && !newsrv->ssl_ctx.ciphersuites)
		newsrv->ssl_ctx.ciphersuites = strdup(global_ssl.connect_default_ciphersuites);
#endif
	return 0;
}

/* parse the "ssl-reuse" server keyword */
static int srv_parse_ssl_reuse(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options &= ~SRV_SSL_O_NO_REUSE;
	return 0;
}

/* parse the "tls-tickets" server keyword */
static int srv_parse_tls_tickets(char **args, int *cur_arg, struct proxy *px, struct server *newsrv, char **err)
{
	newsrv->ssl_ctx.options &= ~SRV_SSL_O_NO_TLS_TICKETS;
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

	free(newsrv->ssl_ctx.verify_host);
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
		if (!strcmp(args[i], "no-tls-tickets"))
			global_ssl.listen_default_ssloptions |= BC_SSL_O_NO_TLS_TICKETS;
		else if (!strcmp(args[i], "prefer-client-ciphers"))
			global_ssl.listen_default_ssloptions |= BC_SSL_O_PREF_CLIE_CIPH;
		else if (!strcmp(args[i], "ssl-min-ver") || !strcmp(args[i], "ssl-max-ver")) {
			if (!parse_tls_method_minmax(args, i, &global_ssl.listen_default_sslmethods, err))
				i++;
			else {
				memprintf(err, "%s on global statement '%s'.", *err, args[0]);
				return -1;
			}
		}
		else if (parse_tls_method_options(args[i], &global_ssl.listen_default_sslmethods, err)) {
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
		if (!strcmp(args[i], "no-tls-tickets"))
			global_ssl.connect_default_ssloptions |= SRV_SSL_O_NO_TLS_TICKETS;
		else if (!strcmp(args[i], "ssl-min-ver") || !strcmp(args[i], "ssl-max-ver")) {
			if (!parse_tls_method_minmax(args, i, &global_ssl.connect_default_sslmethods, err))
				i++;
			else {
				memprintf(err, "%s on global statement '%s'.", *err, args[0]);
				return -1;
			}
		}
		else if (parse_tls_method_options(args[i], &global_ssl.connect_default_sslmethods, err)) {
			memprintf(err, "unknown option '%s' on global statement '%s'.", args[i], args[0]);
			return -1;
		}
		i++;
	}
	return 0;
}

/* parse the "ca-base" / "crt-base" keywords in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ca_crt_base(char **args, int section_type, struct proxy *curpx,
                                        struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	char **target;

	target = (args[0][1] == 'a') ? &global_ssl.ca_base : &global_ssl.crt_base;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*target) {
		memprintf(err, "'%s' already specified.", args[0]);
		return -1;
	}

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a directory path as an argument.", args[0]);
		return -1;
	}
	*target = strdup(args[1]);
	return 0;
}

/* parse the "ssl-mode-async" keyword in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ssl_async(char **args, int section_type, struct proxy *curpx,
                                       struct proxy *defpx, const char *file, int line,
                                       char **err)
{
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1010000fL) && !defined(OPENSSL_NO_ASYNC)
	global_ssl.async = 1;
	global.ssl_used_async_engines = nb_engines;
	return 0;
#else
	memprintf(err, "'%s': openssl library does not support async mode", args[0]);
	return -1;
#endif
}

#ifndef OPENSSL_NO_ENGINE
static int ssl_check_async_engine_count(void) {
	int err_code = 0;

	if (global_ssl.async && (openssl_engines_initialized > 32)) {
		ha_alert("ssl-mode-async only supports a maximum of 32 engines.\n");
		err_code = ERR_ABORT;
	}
	return err_code;
}

/* parse the "ssl-engine" keyword in global section.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ssl_engine(char **args, int section_type, struct proxy *curpx,
                                       struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	char *algo;
	int ret = -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a valid engine name as an argument.", args[0]);
		return ret;
	}

	if (*(args[2]) == 0) {
		/* if no list of algorithms is given, it defaults to ALL */
		algo = strdup("ALL");
		goto add_engine;
	}

	/* otherwise the expected format is ssl-engine <engine_name> algo <list of algo> */
	if (strcmp(args[2], "algo") != 0) {
		memprintf(err, "global statement '%s' expects to have algo keyword.", args[0]);
		return ret;
	}

	if (*(args[3]) == 0) {
		memprintf(err, "global statement '%s' expects algorithm names as an argument.", args[0]);
		return ret;
	}
	algo = strdup(args[3]);

add_engine:
	if (ssl_init_single_engine(args[1], algo)==0) {
		openssl_engines_initialized++;
		ret = 0;
	}
	free(algo);
	return ret;
}
#endif

/* parse the "ssl-default-bind-ciphers" / "ssl-default-server-ciphers" keywords
 * in global section. Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ciphers(char **args, int section_type, struct proxy *curpx,
                                    struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	char **target;

	target = (args[0][12] == 'b') ? &global_ssl.listen_default_ciphers : &global_ssl.connect_default_ciphers;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a cipher suite as an argument.", args[0]);
		return -1;
	}

	free(*target);
	*target = strdup(args[1]);
	return 0;
}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
/* parse the "ssl-default-bind-ciphersuites" / "ssl-default-server-ciphersuites" keywords
 * in global section. Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_ciphersuites(char **args, int section_type, struct proxy *curpx,
                                    struct proxy *defpx, const char *file, int line,
                                    char **err)
{
	char **target;

	target = (args[0][12] == 'b') ? &global_ssl.listen_default_ciphersuites : &global_ssl.connect_default_ciphersuites;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "global statement '%s' expects a cipher suite as an argument.", args[0]);
		return -1;
	}

	free(*target);
	*target = strdup(args[1]);
	return 0;
}
#endif

/* parse various global tune.ssl settings consisting in positive integers.
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_int(char **args, int section_type, struct proxy *curpx,
                                struct proxy *defpx, const char *file, int line,
                                char **err)
{
	int *target;

	if (strcmp(args[0], "tune.ssl.cachesize") == 0)
		target = &global.tune.sslcachesize;
	else if (strcmp(args[0], "tune.ssl.maxrecord") == 0)
		target = (int *)&global_ssl.max_record;
	else if (strcmp(args[0], "tune.ssl.ssl-ctx-cache-size") == 0)
		target = &global_ssl.ctx_cache;
	else if (strcmp(args[0], "maxsslconn") == 0)
		target = &global.maxsslconn;
	else if (strcmp(args[0], "tune.ssl.capture-cipherlist-size") == 0)
		target = &global_ssl.capture_cipherlist;
	else {
		memprintf(err, "'%s' keyword not unhandled (please report this bug).", args[0]);
		return -1;
	}

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an integer argument.", args[0]);
		return -1;
	}

	*target = atoi(args[1]);
	if (*target < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

static int ssl_parse_global_capture_cipherlist(char **args, int section_type, struct proxy *curpx,
                                               struct proxy *defpx, const char *file, int line,
                                               char **err)
{
	int ret;

	ret = ssl_parse_global_int(args, section_type, curpx, defpx, file, line, err);
	if (ret != 0)
		return ret;

	if (pool_head_ssl_capture) {
		memprintf(err, "'%s' is already configured.", args[0]);
		return -1;
	}

	pool_head_ssl_capture = create_pool("ssl-capture", sizeof(struct ssl_capture) + global_ssl.capture_cipherlist, MEM_F_SHARED);
	if (!pool_head_ssl_capture) {
		memprintf(err, "Out of memory error.");
		return -1;
	}
	return 0;
}

/* parse "ssl.force-private-cache".
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_private_cache(char **args, int section_type, struct proxy *curpx,
                                          struct proxy *defpx, const char *file, int line,
                                          char **err)
{
	if (too_many_args(0, args, err, NULL))
		return -1;

	global_ssl.private_cache = 1;
	return 0;
}

/* parse "ssl.lifetime".
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_lifetime(char **args, int section_type, struct proxy *curpx,
                                     struct proxy *defpx, const char *file, int line,
                                     char **err)
{
	const char *res;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects ssl sessions <lifetime> in seconds as argument.", args[0]);
		return -1;
	}

	res = parse_time_err(args[1], &global_ssl.life_time, TIME_UNIT_S);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to <%s> (maximum value is 2147483647 s or ~68 years).",
			  args[1], args[0]);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to <%s> (minimum non-null value is 1 s).",
			  args[1], args[0]);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in argument to <%s>.", *res, args[0]);
		return -1;
	}
	return 0;
}

#ifndef OPENSSL_NO_DH
/* parse "ssl-dh-param-file".
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_dh_param_file(char **args, int section_type, struct proxy *curpx,
                                       struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects a file path as an argument.", args[0]);
		return -1;
	}

	if (ssl_sock_load_global_dh_param_from_file(args[1])) {
		memprintf(err, "'%s': unable to load DH parameters from file <%s>.", args[0], args[1]);
		return -1;
	}
	return 0;
}

/* parse "ssl.default-dh-param".
 * Returns <0 on alert, >0 on warning, 0 on success.
 */
static int ssl_parse_global_default_dh(char **args, int section_type, struct proxy *curpx,
                                       struct proxy *defpx, const char *file, int line,
                                       char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) == 0) {
		memprintf(err, "'%s' expects an integer argument.", args[0]);
		return -1;
	}

	global_ssl.default_dh_param = atoi(args[1]);
	if (global_ssl.default_dh_param < 1024) {
		memprintf(err, "'%s' expects a value >= 1024.", args[0]);
		return -1;
	}
	return 0;
}
#endif


/* This function is used with TLS ticket keys management. It permits to browse
 * each reference. The variable <getnext> must contain the current node,
 * <end> point to the root node.
 */
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
static inline
struct tls_keys_ref *tlskeys_list_get_next(struct tls_keys_ref *getnext, struct list *end)
{
	struct tls_keys_ref *ref = getnext;

	while (1) {

		/* Get next list entry. */
		ref = LIST_NEXT(&ref->list, struct tls_keys_ref *, list);

		/* If the entry is the last of the list, return NULL. */
		if (&ref->list == end)
			return NULL;

		return ref;
	}
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

static int cli_io_handler_tlskeys_files(struct appctx *appctx);

static inline int cli_io_handler_tlskeys_entries(struct appctx *appctx) {
	return cli_io_handler_tlskeys_files(appctx);
}

/* dumps all tls keys. Relies on cli.i0 (non-null = only list file names), cli.i1
 * (next index to be dumped), and cli.p0 (next key reference).
 */
static int cli_io_handler_tlskeys_files(struct appctx *appctx) {

	struct stream_interface *si = appctx->owner;

	switch (appctx->st2) {
	case STAT_ST_INIT:
		/* Display the column headers. If the message cannot be sent,
		 * quit the function with returning 0. The function is called
		 * later and restart at the state "STAT_ST_INIT".
		 */
		chunk_reset(&trash);

		if (appctx->io_handler == cli_io_handler_tlskeys_entries)
			chunk_appendf(&trash, "# id secret\n");
		else
			chunk_appendf(&trash, "# id (file)\n");

		if (ci_putchk(si_ic(si), &trash) == -1) {
			si_rx_room_blk(si);
			return 0;
		}

		/* Now, we start the browsing of the references lists.
		 * Note that the following call to LIST_ELEM return bad pointer. The only
		 * available field of this pointer is <list>. It is used with the function
		 * tlskeys_list_get_next() for retruning the first available entry
		 */
		if (appctx->ctx.cli.p0 == NULL) {
			appctx->ctx.cli.p0 = LIST_ELEM(&tlskeys_reference, struct tls_keys_ref *, list);
			appctx->ctx.cli.p0 = tlskeys_list_get_next(appctx->ctx.cli.p0, &tlskeys_reference);
		}

		appctx->st2 = STAT_ST_LIST;
		/* fall through */

	case STAT_ST_LIST:
		while (appctx->ctx.cli.p0) {
			struct tls_keys_ref *ref = appctx->ctx.cli.p0;

			chunk_reset(&trash);
			if (appctx->io_handler == cli_io_handler_tlskeys_entries && appctx->ctx.cli.i1 == 0)
				chunk_appendf(&trash, "# ");

			if (appctx->ctx.cli.i1 == 0)
				chunk_appendf(&trash, "%d (%s)\n", ref->unique_id, ref->filename);

			if (appctx->io_handler == cli_io_handler_tlskeys_entries) {
				int head;

				HA_RWLOCK_RDLOCK(TLSKEYS_REF_LOCK, &ref->lock);
				head = ref->tls_ticket_enc_index;
				while (appctx->ctx.cli.i1 < TLS_TICKETS_NO) {
					struct buffer *t2 = get_trash_chunk();

					chunk_reset(t2);
					/* should never fail here because we dump only a key in the t2 buffer */
					if (ref->key_size_bits == 128) {
						t2->data = a2base64((char *)(ref->tlskeys + (head + 2 + appctx->ctx.cli.i1) % TLS_TICKETS_NO),
						                   sizeof(struct tls_sess_key_128),
						                   t2->area, t2->size);
						chunk_appendf(&trash, "%d.%d %s\n", ref->unique_id, appctx->ctx.cli.i1,
							      t2->area);
					}
					else if (ref->key_size_bits == 256) {
						t2->data = a2base64((char *)(ref->tlskeys + (head + 2 + appctx->ctx.cli.i1) % TLS_TICKETS_NO),
						                   sizeof(struct tls_sess_key_256),
						                   t2->area, t2->size);
						chunk_appendf(&trash, "%d.%d %s\n", ref->unique_id, appctx->ctx.cli.i1,
							      t2->area);
					}
					else {
						/* This case should never happen */
						chunk_appendf(&trash, "%d.%d <unknown>\n", ref->unique_id, appctx->ctx.cli.i1);
					}

					if (ci_putchk(si_ic(si), &trash) == -1) {
						/* let's try again later from this stream. We add ourselves into
						 * this stream's users so that it can remove us upon termination.
						 */
						HA_RWLOCK_RDUNLOCK(TLSKEYS_REF_LOCK, &ref->lock);
						si_rx_room_blk(si);
						return 0;
					}
					appctx->ctx.cli.i1++;
				}
				HA_RWLOCK_RDUNLOCK(TLSKEYS_REF_LOCK, &ref->lock);
				appctx->ctx.cli.i1 = 0;
			}
			if (ci_putchk(si_ic(si), &trash) == -1) {
				/* let's try again later from this stream. We add ourselves into
				 * this stream's users so that it can remove us upon termination.
				 */
				si_rx_room_blk(si);
				return 0;
			}

			if (appctx->ctx.cli.i0 == 0) /* don't display everything if not necessary */
				break;

			/* get next list entry and check the end of the list */
			appctx->ctx.cli.p0 = tlskeys_list_get_next(appctx->ctx.cli.p0, &tlskeys_reference);
		}

		appctx->st2 = STAT_ST_FIN;
		/* fall through */

	default:
		appctx->st2 = STAT_ST_FIN;
		return 1;
	}
	return 0;
}

/* sets cli.i0 to non-zero if only file lists should be dumped */
static int cli_parse_show_tlskeys(char **args, char *payload, struct appctx *appctx, void *private)
{
	/* no parameter, shows only file list */
	if (!*args[2]) {
		appctx->ctx.cli.i0 = 1;
		appctx->io_handler = cli_io_handler_tlskeys_files;
		return 0;
	}

	if (args[2][0] == '*') {
		/* list every TLS ticket keys */
		appctx->ctx.cli.i0 = 1;
	} else {
		appctx->ctx.cli.p0 = tlskeys_ref_lookup_ref(args[2]);
		if (!appctx->ctx.cli.p0)
			return cli_err(appctx, "'show tls-keys' unable to locate referenced filename\n");
	}
	appctx->io_handler = cli_io_handler_tlskeys_entries;
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


/* Type of SSL payloads that can be updated over the CLI */

enum {
	CERT_TYPE_PEM = 0,
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
#if ((defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP) || defined OPENSSL_IS_BORINGSSL)
	[CERT_TYPE_OCSP]   = { "ocsp",    CERT_TYPE_OCSP,     &ssl_sock_load_ocsp_response_from_file },
#endif
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
	[CERT_TYPE_SCTL]   = { "sctl",    CERT_TYPE_SCTL,     &ssl_sock_load_sctl_from_file },
#endif
	[CERT_TYPE_ISSUER] = { "issuer",  CERT_TYPE_ISSUER,   &ssl_sock_load_issuer_file_into_ckch },
	[CERT_TYPE_MAX]    = { NULL,      CERT_TYPE_MAX,      NULL },
};

/* states of the CLI IO handler for 'set ssl cert' */
enum {
	SETCERT_ST_INIT = 0,
	SETCERT_ST_GEN,
	SETCERT_ST_INSERT,
	SETCERT_ST_FIN,
};

/* release function of the  `set ssl cert' command, free things and unlock the spinlock */
static void cli_release_commit_cert(struct appctx *appctx)
{
	struct ckch_store *new_ckchs;
	struct ckch_inst *ckchi, *ckchis;

	HA_SPIN_UNLOCK(CKCH_LOCK, &ckch_lock);

	if (appctx->st2 != SETCERT_ST_FIN) {
		/* free every new sni_ctx and the new store, which are not in the trees so no spinlock there */
		new_ckchs = appctx->ctx.ssl.new_ckchs;

		if (!new_ckchs)
			return;

		/* if the allocation failed, we need to free everything from the temporary list */
		list_for_each_entry_safe(ckchi, ckchis, &new_ckchs->ckch_inst, by_ckchs) {
			struct sni_ctx *sc0, *sc0s;

			list_for_each_entry_safe(sc0, sc0s, &ckchi->sni_ctx, by_ckch_inst) {
				if (sc0->order == 0) /* we only free if it's the first inserted */
					SSL_CTX_free(sc0->ctx);
				LIST_DEL(&sc0->by_ckch_inst);
				free(sc0);
			}
			LIST_DEL(&ckchi->by_ckchs);
			free(ckchi);
		}
		ckchs_free(new_ckchs);
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

					if (new_ckchs->multi)
						errcode |= ckch_inst_new_load_multi_store(new_ckchs->path, new_ckchs, ckchi->bind_conf, ckchi->ssl_conf, NULL, 0, &new_inst, &err);
					else
						errcode |= ckch_inst_new_load_store(new_ckchs->path, new_ckchs, ckchi->bind_conf, ckchi->ssl_conf, NULL, 0, &new_inst, &err);

					if (errcode & ERR_CODE)
						goto error;

					/* if the previous ckchi was used as the default */
					if (ckchi->is_default)
						new_inst->is_default = 1;

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

				/* First, we insert every new SNIs in the trees, also replace the default_ctx */
				list_for_each_entry_safe(ckchi, ckchis, &new_ckchs->ckch_inst, by_ckchs) {
					HA_RWLOCK_WRLOCK(SNI_LOCK, &ckchi->bind_conf->sni_lock);
					ssl_sock_load_cert_sni(ckchi, ckchi->bind_conf);
					HA_RWLOCK_WRUNLOCK(SNI_LOCK, &ckchi->bind_conf->sni_lock);
				}

				/* delete the old sni_ctx, the old ckch_insts and the ckch_store */
				list_for_each_entry_safe(ckchi, ckchis, &old_ckchs->ckch_inst, by_ckchs) {
					struct sni_ctx *sc0, *sc0s;

					HA_RWLOCK_WRLOCK(SNI_LOCK, &ckchi->bind_conf->sni_lock);
					list_for_each_entry_safe(sc0, sc0s, &ckchi->sni_ctx, by_ckch_inst) {
						ebmb_delete(&sc0->name);
						LIST_DEL(&sc0->by_ckch_inst);
						free(sc0);
					}
					HA_RWLOCK_WRUNLOCK(SNI_LOCK, &ckchi->bind_conf->sni_lock);
					LIST_DEL(&ckchi->by_ckchs);
					free(ckchi);
				}

				/* Replace the old ckchs by the new one */
				ebmb_delete(&old_ckchs->node);
				ckchs_free(old_ckchs);
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

	chunk_appendf(trash, "\nSuccess!\n");
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
	int bundle = -1; /* TRUE if >= 0 (ckch index) */
	int errcode = 0;
	char *end;
	int type = CERT_TYPE_PEM;
	struct cert_key_and_chain *ckch;
	struct buffer *buf;

	if ((buf = alloc_trash_chunk()) == NULL)
		return cli_err(appctx, "Can't allocate memory\n");

	if (!*args[3] || !payload)
		return cli_err(appctx, "'set ssl cert expects a filename and a certificat as a payload\n");

	/* The operations on the CKCH architecture are locked so we can
	 * manipulate ckch_store and ckch_inst */
	if (HA_SPIN_TRYLOCK(CKCH_LOCK, &ckch_lock))
		return cli_err(appctx, "Can't update the certificate!\nOperations on certificates are currently locked!\n");

	if (!chunk_strcpy(buf, args[3])) {
		memprintf(&err, "%sCan't allocate memory\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	/* check which type of file we want to update */
	for (i = 0; cert_exts[i].type < CERT_TYPE_MAX; i++) {
		end = strrchr(buf->area, '.');
		if (end && *cert_exts[i].ext && (!strcmp(end + 1, cert_exts[i].ext))) {
			*end = '\0';
			type = cert_exts[i].type;
			break;
		}
	}

	appctx->ctx.ssl.old_ckchs = NULL;
	appctx->ctx.ssl.new_ckchs = NULL;

	/* if there is an ongoing transaction */
	if (ckchs_transaction.path) {
		/* if the ongoing transaction is a bundle, we need to find which part of the bundle need to be updated */
#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
		if (ckchs_transaction.new_ckchs->multi) {
			char *end;
			int j;

			/* check if it was used in a bundle by removing the
			 *   .dsa/.rsa/.ecdsa at the end of the filename */
			end = strrchr(buf->area, '.');
			for (j = 0; end && j < SSL_SOCK_NUM_KEYTYPES; j++) {
				if (!strcmp(end + 1, SSL_SOCK_KEYTYPE_NAMES[j])) {
					bundle = j; /* keep the type of certificate so we insert it at the right place */
					*end = '\0'; /* it's a bundle let's end the string*/
					break;
				}
			}
			if (bundle < 0) {
				memprintf(&err, "The ongoing transaction is the '%s' bundle. You need to specify which part of the bundle you want to update ('%s.{rsa,ecdsa,dsa}')\n", ckchs_transaction.path, buf->area);
				errcode |= ERR_ALERT | ERR_FATAL;
				goto end;
			}
		}
#endif

		/* if there is an ongoing transaction, check if this is the same file */
		if (strcmp(ckchs_transaction.path, buf->area) != 0) {
			memprintf(&err, "The ongoing transaction is about '%s' but you are trying to set '%s'\n", ckchs_transaction.path, buf->area);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}

		appctx->ctx.ssl.old_ckchs = ckchs_transaction.new_ckchs;

	} else {
		struct ckch_store *find_ckchs[2] = { NULL, NULL };

		/* lookup for the certificate in the tree:
		 * check if this is used as a bundle AND as a unique certificate */
		for (i = 0; i < 2; i++) {

			if ((find_ckchs[i] = ckchs_lookup(buf->area)) != NULL) {
				/* only the bundle name is in the tree and you should
				 * never update a bundle name, only a filename */
				if (bundle < 0 && find_ckchs[i]->multi) {
					/* we tried to look for a non-bundle and we found a bundle */
					memprintf(&err, "%s%s is a multi-cert bundle. Try updating %s.{dsa,rsa,ecdsa}\n",
						  err ? err : "", args[3], args[3]);
					errcode |= ERR_ALERT | ERR_FATAL;
					goto end;
				}
				/* If we want a bundle but this is not a bundle
				 * example: When you try to update <file>.rsa, but
				 * <file> is a regular file */
				if (bundle >= 0 && find_ckchs[i]->multi == 0) {
					find_ckchs[i] = NULL;
					break;
				}
			}
#if HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL
			{
				char *end;
				int j;

				/* check if it was used in a bundle by removing the
				 *   .dsa/.rsa/.ecdsa at the end of the filename */
				end = strrchr(buf->area, '.');
				for (j = 0; end && j < SSL_SOCK_NUM_KEYTYPES; j++) {
					if (!strcmp(end + 1, SSL_SOCK_KEYTYPE_NAMES[j])) {
						bundle = j; /* keep the type of certificate so we insert it at the right place */
						*end = '\0'; /* it's a bundle let's end the string*/
						break;
					}
				}
				if (bundle < 0) /* we didn't find a bundle extension */
					break;
			}
#else
			/* bundles are not supported here, so we don't need to lookup again */
			break;
#endif
		}

		if (find_ckchs[0] && find_ckchs[1]) {
			memprintf(&err, "%sUpdating a certificate which is used in the HAProxy configuration as a bundle and as a unique certificate is not supported. ('%s' and '%s')\n",
			          err ? err : "", find_ckchs[0]->path, find_ckchs[1]->path);
			errcode |= ERR_ALERT | ERR_FATAL;
			goto end;
		}

		appctx->ctx.ssl.old_ckchs = find_ckchs[0] ? find_ckchs[0] : find_ckchs[1];
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

	/* TODO: handle filters */
	if (old_ckchs->filters) {
		memprintf(&err, "%sCertificates used in crt-list with filters are not supported!\n",
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

	if (!new_ckchs->multi)
		ckch = new_ckchs->ckch;
	else
		ckch = &new_ckchs->ckch[bundle];

	/* appply the change on the duplicate */
	if (cert_exts[type].load(buf->area, payload, ckch, &err) != 0) {
		memprintf(&err, "%sCan't load the payload\n", err ? err : "");
		errcode |= ERR_ALERT | ERR_FATAL;
		goto end;
	}

	appctx->ctx.ssl.new_ckchs = new_ckchs;

	/* we succeed, we can save the ckchs in the transaction */

	/* if there wasn't a transaction, update the old ckchs */
	if (!ckchs_transaction.old_ckchs && !ckchs_transaction.old_ckchs) {
		ckchs_transaction.old_ckchs = appctx->ctx.ssl.old_ckchs;
		ckchs_transaction.path = appctx->ctx.ssl.path;
		err = memprintf(&err, "Transaction created for certificate %s!\n", ckchs_transaction.path);
	} else {
		err = memprintf(&err, "Transaction updated for certificate %s!\n", ckchs_transaction.path);

	}

	/* free the previous ckchs if there was a transaction */
	ckchs_free(ckchs_transaction.new_ckchs);

	ckchs_transaction.new_ckchs = appctx->ctx.ssl.new_ckchs;


	/* creates the SNI ctxs later in the IO handler */

end:
	free_trash_chunk(buf);

	if (errcode & ERR_CODE) {

		ckchs_free(appctx->ctx.ssl.new_ckchs);
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

static int cli_parse_set_ocspresponse(char **args, char *payload, struct appctx *appctx, void *private)
{
#if (defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB && !defined OPENSSL_NO_OCSP)
	char *err = NULL;
	int i, j, ret;

	if (!payload)
		payload = args[3];

	/* Expect one parameter: the new response in base64 encoding */
	if (!*payload)
		return cli_err(appctx, "'set ssl ocsp-response' expects response in base64 encoding.\n");

	/* remove \r and \n from the payload */
	for (i = 0, j = 0; payload[i]; i++) {
		if (payload[i] == '\r' || payload[i] == '\n')
			continue;
		payload[j++] = payload[i];
	}
	payload[j] = 0;

	ret = base64dec(payload, j, trash.area, trash.size);
	if (ret < 0)
		return cli_err(appctx, "'set ssl ocsp-response' received invalid base64 encoded response.\n");

	trash.data = ret;
	if (ssl_sock_update_ocsp_response(&trash, &err)) {
		if (err)
			return cli_dynerr(appctx, memprintf(&err, "%s.\n", err));
		else
			return cli_err(appctx, "Failed to update OCSP response.\n");
	}

	return cli_msg(appctx, LOG_INFO, "OCSP Response updated!\n");
#else
	return cli_err(appctx, "HAProxy was compiled against a version of OpenSSL that doesn't support OCSP stapling.\n");
#endif

}

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000100fL)
static inline int sample_conv_var2smp_str(const struct arg *arg, struct sample *smp)
{
	switch (arg->type) {
	case ARGT_STR:
		smp->data.type = SMP_T_STR;
		smp->data.u.str = arg->data.str;
		return 1;
	case ARGT_VAR:
		if (!vars_get_by_desc(&arg->data.var, smp))
				return 0;
		if (!sample_casts[smp->data.type][SMP_T_STR])
				return 0;
		if (!sample_casts[smp->data.type][SMP_T_STR](smp))
				return 0;
		return 1;
	default:
		return 0;
	}
}

static int check_aes_gcm(struct arg *args, struct sample_conv *conv,
						  const char *file, int line, char **err)
{
	switch(args[0].data.sint) {
	case 128:
	case 192:
	case 256:
		break;
	default:
		memprintf(err, "key size must be 128, 192 or 256 (bits).");
		return 0;
	}
	/* Try to decode a variable. */
	vars_check_arg(&args[1], NULL);
	vars_check_arg(&args[2], NULL);
	vars_check_arg(&args[3], NULL);
	return 1;
}

/* Arguements: AES size in bits, nonce, key, tag. The last three arguments are base64 encoded */
static int sample_conv_aes_gcm_dec(const struct arg *arg_p, struct sample *smp, void *private)
{
	struct sample nonce, key, aead_tag;
	struct buffer *smp_trash, *smp_trash_alloc;
	EVP_CIPHER_CTX *ctx;
	int dec_size, ret;

	smp_set_owner(&nonce, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_str(&arg_p[1], &nonce))
		return 0;

	smp_set_owner(&key, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_str(&arg_p[2], &key))
		return 0;

	smp_set_owner(&aead_tag, smp->px, smp->sess, smp->strm, smp->opt);
	if (!sample_conv_var2smp_str(&arg_p[3], &aead_tag))
		return 0;

	smp_trash = get_trash_chunk();
	smp_trash_alloc = alloc_trash_chunk();
	if (!smp_trash_alloc)
		return 0;

	ctx = EVP_CIPHER_CTX_new();

	if (!ctx)
		goto err;

	dec_size = base64dec(nonce.data.u.str.area, nonce.data.u.str.data, smp_trash->area, smp_trash->size);
	if (dec_size < 0)
		goto err;
	smp_trash->data = dec_size;

	/* Set cipher type and mode */
	switch(arg_p[0].data.sint) {
	case 128:
		EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
		break;
	case 192:
		EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
		break;
	case 256:
		EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
		break;
	}

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, smp_trash->data, NULL);

	/* Initialise IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, (unsigned char *) smp_trash->area))
		goto err;

	dec_size = base64dec(key.data.u.str.area, key.data.u.str.data, smp_trash->area, smp_trash->size);
	if (dec_size < 0)
		goto err;
	smp_trash->data = dec_size;

	/* Initialise key */
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char *) smp_trash->area, NULL))
		goto err;

	if (!EVP_DecryptUpdate(ctx, (unsigned char *) smp_trash->area, (int *) &smp_trash->data,
						  (unsigned char *) smp->data.u.str.area, (int) smp->data.u.str.data))
		goto err;

	dec_size = base64dec(aead_tag.data.u.str.area, aead_tag.data.u.str.data, smp_trash_alloc->area, smp_trash_alloc->size);
	if (dec_size < 0)
		goto err;
	smp_trash_alloc->data = dec_size;
	dec_size = smp_trash->data;

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, smp_trash_alloc->data, (void *) smp_trash_alloc->area);
	ret = EVP_DecryptFinal_ex(ctx, (unsigned char *) smp_trash->area + smp_trash->data, (int *) &smp_trash->data);

	if (ret <= 0)
		goto err;

	smp->data.u.str.data = dec_size + smp_trash->data;
	smp->data.u.str.area = smp_trash->area;
	smp->data.type = SMP_T_BIN;
	smp->flags &= ~SMP_F_CONST;
	free_trash_chunk(smp_trash_alloc);
	return 1;

err:
	free_trash_chunk(smp_trash_alloc);
	return 0;
}
# endif

/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
	{ { "show", "tls-keys", NULL }, "show tls-keys [id|*]: show tls keys references or dump tls ticket keys when id specified", cli_parse_show_tlskeys, NULL },
	{ { "set", "ssl", "tls-key", NULL }, "set ssl tls-key [id|keyfile] <tlskey>: set the next TLS key for the <id> or <keyfile> listener to <tlskey>", cli_parse_set_tlskeys, NULL },
#endif
	{ { "set", "ssl", "ocsp-response", NULL }, NULL, cli_parse_set_ocspresponse, NULL },
	{ { "set", "ssl", "cert", NULL }, "set ssl cert <certfile> <payload> : replace a certificate file", cli_parse_set_cert, NULL, NULL },
	{ { "commit", "ssl", "cert", NULL }, "commit ssl cert <certfile> : commit a certificate file", cli_parse_commit_cert, cli_io_handler_commit_cert, cli_release_commit_cert },
	{ { NULL }, NULL, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct sample_fetch_kw_list sample_fetch_keywords = {ILH, {
	{ "ssl_bc",                 smp_fetch_ssl_fc,             0,                   NULL,    SMP_T_BOOL, SMP_USE_L5SRV },
	{ "ssl_bc_alg_keysize",     smp_fetch_ssl_fc_alg_keysize, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5SRV },
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	{ "ssl_bc_alpn",            smp_fetch_ssl_fc_alpn,        0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
#endif
	{ "ssl_bc_cipher",          smp_fetch_ssl_fc_cipher,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	{ "ssl_bc_npn",             smp_fetch_ssl_fc_npn,         0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
#endif
	{ "ssl_bc_is_resumed",      smp_fetch_ssl_fc_is_resumed,  0,                   NULL,    SMP_T_BOOL, SMP_USE_L5SRV },
	{ "ssl_bc_protocol",        smp_fetch_ssl_fc_protocol,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5SRV },
	{ "ssl_bc_unique_id",       smp_fetch_ssl_fc_unique_id,   0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
	{ "ssl_bc_use_keysize",     smp_fetch_ssl_fc_use_keysize, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5SRV },
#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
	{ "ssl_bc_session_id",      smp_fetch_ssl_fc_session_id,  0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
#endif
#if HA_OPENSSL_VERSION_NUMBER >= 0x10100000L
	{ "ssl_bc_client_random",   smp_fetch_ssl_fc_random,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
	{ "ssl_bc_server_random",   smp_fetch_ssl_fc_random,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
	{ "ssl_bc_session_key",     smp_fetch_ssl_fc_session_key, 0,                   NULL,    SMP_T_BIN,  SMP_USE_L5SRV },
#endif
	{ "ssl_c_ca_err",           smp_fetch_ssl_c_ca_err,       0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_c_ca_err_depth",     smp_fetch_ssl_c_ca_err_depth, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_c_der",              smp_fetch_ssl_x_der,          0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_err",              smp_fetch_ssl_c_err,          0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_c_i_dn",             smp_fetch_ssl_x_i_dn,         ARG2(0,STR,SINT),    NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_key_alg",          smp_fetch_ssl_x_key_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_notafter",         smp_fetch_ssl_x_notafter,     0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_notbefore",        smp_fetch_ssl_x_notbefore,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_sig_alg",          smp_fetch_ssl_x_sig_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_s_dn",             smp_fetch_ssl_x_s_dn,         ARG2(0,STR,SINT),    NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_c_serial",           smp_fetch_ssl_x_serial,       0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_sha1",             smp_fetch_ssl_x_sha1,         0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_c_used",             smp_fetch_ssl_c_used,         0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_c_verify",           smp_fetch_ssl_c_verify,       0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_c_version",          smp_fetch_ssl_x_version,      0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_f_der",              smp_fetch_ssl_x_der,          0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_f_i_dn",             smp_fetch_ssl_x_i_dn,         ARG2(0,STR,SINT),    NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_key_alg",          smp_fetch_ssl_x_key_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_notafter",         smp_fetch_ssl_x_notafter,     0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_notbefore",        smp_fetch_ssl_x_notbefore,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_sig_alg",          smp_fetch_ssl_x_sig_alg,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_s_dn",             smp_fetch_ssl_x_s_dn,         ARG2(0,STR,SINT),    NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_f_serial",           smp_fetch_ssl_x_serial,       0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_f_sha1",             smp_fetch_ssl_x_sha1,         0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_f_version",          smp_fetch_ssl_x_version,      0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_fc",                 smp_fetch_ssl_fc,             0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_alg_keysize",     smp_fetch_ssl_fc_alg_keysize, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ "ssl_fc_cipher",          smp_fetch_ssl_fc_cipher,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_has_crt",         smp_fetch_ssl_fc_has_crt,     0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_has_early",       smp_fetch_ssl_fc_has_early,   0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_has_sni",         smp_fetch_ssl_fc_has_sni,     0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
	{ "ssl_fc_is_resumed",      smp_fetch_ssl_fc_is_resumed,  0,                   NULL,    SMP_T_BOOL, SMP_USE_L5CLI },
#if defined(OPENSSL_NPN_NEGOTIATED) && !defined(OPENSSL_NO_NEXTPROTONEG)
	{ "ssl_fc_npn",             smp_fetch_ssl_fc_npn,         0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
	{ "ssl_fc_alpn",            smp_fetch_ssl_fc_alpn,        0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#endif
	{ "ssl_fc_protocol",        smp_fetch_ssl_fc_protocol,    0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
	{ "ssl_fc_unique_id",       smp_fetch_ssl_fc_unique_id,   0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
#endif
	{ "ssl_fc_use_keysize",     smp_fetch_ssl_fc_use_keysize, 0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
#if HA_OPENSSL_VERSION_NUMBER > 0x0090800fL
	{ "ssl_fc_session_id",      smp_fetch_ssl_fc_session_id,  0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
#endif
#if HA_OPENSSL_VERSION_NUMBER >= 0x10100000L
	{ "ssl_fc_client_random",   smp_fetch_ssl_fc_random,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_fc_server_random",   smp_fetch_ssl_fc_random,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_fc_session_key",     smp_fetch_ssl_fc_session_key, 0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
#endif
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	{ "ssl_fc_sni",             smp_fetch_ssl_fc_sni,         0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
#endif
	{ "ssl_fc_cipherlist_bin",  smp_fetch_ssl_fc_cl_bin,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_cipherlist_hex",  smp_fetch_ssl_fc_cl_hex,      0,                   NULL,    SMP_T_BIN,  SMP_USE_L5CLI },
	{ "ssl_fc_cipherlist_str",  smp_fetch_ssl_fc_cl_str,      0,                   NULL,    SMP_T_STR,  SMP_USE_L5CLI },
	{ "ssl_fc_cipherlist_xxh",  smp_fetch_ssl_fc_cl_xxh64,    0,                   NULL,    SMP_T_SINT, SMP_USE_L5CLI },
	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_fetches, &sample_fetch_keywords);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {ILH, {
	{ "ssl_fc_sni_end",         "ssl_fc_sni", PAT_MATCH_END },
	{ "ssl_fc_sni_reg",         "ssl_fc_sni", PAT_MATCH_REG },
	{ /* END */ },
}};

INITCALL1(STG_REGISTER, acl_register_keywords, &acl_kws);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct ssl_bind_kw ssl_bind_kws[] = {
	{ "allow-0rtt",            ssl_bind_parse_allow_0rtt,       0 }, /* allow 0-RTT */
	{ "alpn",                  ssl_bind_parse_alpn,             1 }, /* set ALPN supported protocols */
	{ "ca-file",               ssl_bind_parse_ca_file,          1 }, /* set CAfile to process verify on client cert */
	{ "ciphers",               ssl_bind_parse_ciphers,          1 }, /* set SSL cipher suite */
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	{ "ciphersuites",          ssl_bind_parse_ciphersuites,     1 }, /* set TLS 1.3 cipher suite */
#endif
	{ "crl-file",              ssl_bind_parse_crl_file,         1 }, /* set certificat revocation list file use on client cert verify */
	{ "curves",                ssl_bind_parse_curves,           1 }, /* set SSL curve suite */
	{ "ecdhe",                 ssl_bind_parse_ecdhe,            1 }, /* defines named curve for elliptic curve Diffie-Hellman */
	{ "no-ca-names",           ssl_bind_parse_no_ca_names,      0 }, /* do not send ca names to clients (ca_file related) */
	{ "npn",                   ssl_bind_parse_npn,              1 }, /* set NPN supported protocols */
	{ "ssl-min-ver",           ssl_bind_parse_tls_method_minmax,1 }, /* minimum version */
	{ "ssl-max-ver",           ssl_bind_parse_tls_method_minmax,1 }, /* maximum version */
	{ "verify",                ssl_bind_parse_verify,           1 }, /* set SSL verify method */
	{ NULL, NULL, 0 },
};

/* no initcall for ssl_bind_kws, these ones are parsed in the parser loop */

static struct bind_kw_list bind_kws = { "SSL", { }, {
	{ "allow-0rtt",            bind_parse_allow_0rtt,         0 }, /* Allow 0RTT */
	{ "alpn",                  bind_parse_alpn,               1 }, /* set ALPN supported protocols */
	{ "ca-file",               bind_parse_ca_file,            1 }, /* set CAfile to process verify on client cert */
	{ "ca-ignore-err",         bind_parse_ignore_err,         1 }, /* set error IDs to ignore on verify depth > 0 */
	{ "ca-sign-file",          bind_parse_ca_sign_file,       1 }, /* set CAFile used to generate and sign server certs */
	{ "ca-sign-pass",          bind_parse_ca_sign_pass,       1 }, /* set CAKey passphrase */
	{ "ciphers",               bind_parse_ciphers,            1 }, /* set SSL cipher suite */
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	{ "ciphersuites",          bind_parse_ciphersuites,       1 }, /* set TLS 1.3 cipher suite */
#endif
	{ "crl-file",              bind_parse_crl_file,           1 }, /* set certificat revocation list file use on client cert verify */
	{ "crt",                   bind_parse_crt,                1 }, /* load SSL certificates from this location */
	{ "crt-ignore-err",        bind_parse_ignore_err,         1 }, /* set error IDs to ingore on verify depth == 0 */
	{ "crt-list",              bind_parse_crt_list,           1 }, /* load a list of crt from this location */
	{ "curves",                bind_parse_curves,             1 }, /* set SSL curve suite */
	{ "ecdhe",                 bind_parse_ecdhe,              1 }, /* defines named curve for elliptic curve Diffie-Hellman */
	{ "force-sslv3",           bind_parse_tls_method_options, 0 }, /* force SSLv3 */
	{ "force-tlsv10",          bind_parse_tls_method_options, 0 }, /* force TLSv10 */
	{ "force-tlsv11",          bind_parse_tls_method_options, 0 }, /* force TLSv11 */
	{ "force-tlsv12",          bind_parse_tls_method_options, 0 }, /* force TLSv12 */
	{ "force-tlsv13",          bind_parse_tls_method_options, 0 }, /* force TLSv13 */
	{ "generate-certificates", bind_parse_generate_certs,     0 }, /* enable the server certificates generation */
	{ "no-ca-names",           bind_parse_no_ca_names,        0 }, /* do not send ca names to clients (ca_file related) */
	{ "no-sslv3",              bind_parse_tls_method_options, 0 }, /* disable SSLv3 */
	{ "no-tlsv10",             bind_parse_tls_method_options, 0 }, /* disable TLSv10 */
	{ "no-tlsv11",             bind_parse_tls_method_options, 0 }, /* disable TLSv11 */
	{ "no-tlsv12",             bind_parse_tls_method_options, 0 }, /* disable TLSv12 */
	{ "no-tlsv13",             bind_parse_tls_method_options, 0 }, /* disable TLSv13 */
	{ "no-tls-tickets",        bind_parse_no_tls_tickets,     0 }, /* disable session resumption tickets */
	{ "ssl",                   bind_parse_ssl,                0 }, /* enable SSL processing */
	{ "ssl-min-ver",           bind_parse_tls_method_minmax,  1 }, /* minimum version */
	{ "ssl-max-ver",           bind_parse_tls_method_minmax,  1 }, /* maximum version */
	{ "strict-sni",            bind_parse_strict_sni,         0 }, /* refuse negotiation if sni doesn't match a certificate */
	{ "tls-ticket-keys",       bind_parse_tls_ticket_keys,    1 }, /* set file to load TLS ticket keys from */
	{ "verify",                bind_parse_verify,             1 }, /* set SSL verify method */
	{ "npn",                   bind_parse_npn,                1 }, /* set NPN supported protocols */
	{ "prefer-client-ciphers", bind_parse_pcc,                0 }, /* prefer client ciphers */
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted, doing so helps
 * all code contributors.
 * Optional keywords are also declared with a NULL ->parse() function so that
 * the config parser can report an appropriate error when a known keyword was
 * not enabled.
 */
static struct srv_kw_list srv_kws = { "SSL", { }, {
	{ "allow-0rtt",              srv_parse_allow_0rtt,         0, 1 }, /* Allow using early data on this server */
	{ "alpn",                    srv_parse_alpn,               1, 1 }, /* Set ALPN supported protocols */
	{ "ca-file",                 srv_parse_ca_file,            1, 1 }, /* set CAfile to process verify server cert */
	{ "check-alpn",              srv_parse_alpn,               1, 1 }, /* Set ALPN used for checks */
	{ "check-sni",               srv_parse_check_sni,          1, 1 }, /* set SNI */
	{ "check-ssl",               srv_parse_check_ssl,          0, 1 }, /* enable SSL for health checks */
	{ "ciphers",                 srv_parse_ciphers,            1, 1 }, /* select the cipher suite */
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	{ "ciphersuites",            srv_parse_ciphersuites,       1, 1 }, /* select the cipher suite */
#endif
	{ "crl-file",                srv_parse_crl_file,           1, 1 }, /* set certificate revocation list file use on server cert verify */
	{ "crt",                     srv_parse_crt,                1, 1 }, /* set client certificate */
	{ "force-sslv3",             srv_parse_tls_method_options, 0, 1 }, /* force SSLv3 */
	{ "force-tlsv10",            srv_parse_tls_method_options, 0, 1 }, /* force TLSv10 */
	{ "force-tlsv11",            srv_parse_tls_method_options, 0, 1 }, /* force TLSv11 */
	{ "force-tlsv12",            srv_parse_tls_method_options, 0, 1 }, /* force TLSv12 */
	{ "force-tlsv13",            srv_parse_tls_method_options, 0, 1 }, /* force TLSv13 */
	{ "no-check-ssl",            srv_parse_no_check_ssl,       0, 1 }, /* disable SSL for health checks */
	{ "no-send-proxy-v2-ssl",    srv_parse_no_send_proxy_ssl,  0, 1 }, /* do not send PROXY protocol header v2 with SSL info */
	{ "no-send-proxy-v2-ssl-cn", srv_parse_no_send_proxy_cn,   0, 1 }, /* do not send PROXY protocol header v2 with CN */
	{ "no-ssl",                  srv_parse_no_ssl,             0, 1 }, /* disable SSL processing */
	{ "no-ssl-reuse",            srv_parse_no_ssl_reuse,       0, 1 }, /* disable session reuse */
	{ "no-sslv3",                srv_parse_tls_method_options, 0, 0 }, /* disable SSLv3 */
	{ "no-tlsv10",               srv_parse_tls_method_options, 0, 0 }, /* disable TLSv10 */
	{ "no-tlsv11",               srv_parse_tls_method_options, 0, 0 }, /* disable TLSv11 */
	{ "no-tlsv12",               srv_parse_tls_method_options, 0, 0 }, /* disable TLSv12 */
	{ "no-tlsv13",               srv_parse_tls_method_options, 0, 0 }, /* disable TLSv13 */
	{ "no-tls-tickets",          srv_parse_no_tls_tickets,     0, 1 }, /* disable session resumption tickets */
	{ "npn",                     srv_parse_npn,                1, 1 }, /* Set NPN supported protocols */
	{ "send-proxy-v2-ssl",       srv_parse_send_proxy_ssl,     0, 1 }, /* send PROXY protocol header v2 with SSL info */
	{ "send-proxy-v2-ssl-cn",    srv_parse_send_proxy_cn,      0, 1 }, /* send PROXY protocol header v2 with CN */
	{ "sni",                     srv_parse_sni,                1, 1 }, /* send SNI extension */
	{ "ssl",                     srv_parse_ssl,                0, 1 }, /* enable SSL processing */
	{ "ssl-min-ver",             srv_parse_tls_method_minmax,  1, 1 }, /* minimum version */
	{ "ssl-max-ver",             srv_parse_tls_method_minmax,  1, 1 }, /* maximum version */
	{ "ssl-reuse",               srv_parse_ssl_reuse,          0, 1 }, /* enable session reuse */
	{ "tls-tickets",             srv_parse_tls_tickets,        0, 1 }, /* enable session resumption tickets */
	{ "verify",                  srv_parse_verify,             1, 1 }, /* set SSL verify method */
	{ "verifyhost",              srv_parse_verifyhost,         1, 1 }, /* require that SSL cert verifies for hostname */
	{ NULL, NULL, 0, 0 },
}};

INITCALL1(STG_REGISTER, srv_register_keywords, &srv_kws);

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "ca-base",  ssl_parse_global_ca_crt_base },
	{ CFG_GLOBAL, "crt-base", ssl_parse_global_ca_crt_base },
	{ CFG_GLOBAL, "maxsslconn", ssl_parse_global_int },
	{ CFG_GLOBAL, "ssl-default-bind-options", ssl_parse_default_bind_options },
	{ CFG_GLOBAL, "ssl-default-server-options", ssl_parse_default_server_options },
#ifndef OPENSSL_NO_DH
	{ CFG_GLOBAL, "ssl-dh-param-file", ssl_parse_global_dh_param_file },
#endif
	{ CFG_GLOBAL, "ssl-mode-async",  ssl_parse_global_ssl_async },
#ifndef OPENSSL_NO_ENGINE
	{ CFG_GLOBAL, "ssl-engine",  ssl_parse_global_ssl_engine },
#endif
	{ CFG_GLOBAL, "tune.ssl.cachesize", ssl_parse_global_int },
#ifndef OPENSSL_NO_DH
	{ CFG_GLOBAL, "tune.ssl.default-dh-param", ssl_parse_global_default_dh },
#endif
	{ CFG_GLOBAL, "tune.ssl.force-private-cache",  ssl_parse_global_private_cache },
	{ CFG_GLOBAL, "tune.ssl.lifetime", ssl_parse_global_lifetime },
	{ CFG_GLOBAL, "tune.ssl.maxrecord", ssl_parse_global_int },
	{ CFG_GLOBAL, "tune.ssl.ssl-ctx-cache-size", ssl_parse_global_int },
	{ CFG_GLOBAL, "tune.ssl.capture-cipherlist-size", ssl_parse_global_capture_cipherlist },
	{ CFG_GLOBAL, "ssl-default-bind-ciphers", ssl_parse_global_ciphers },
	{ CFG_GLOBAL, "ssl-default-server-ciphers", ssl_parse_global_ciphers },
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	{ CFG_GLOBAL, "ssl-default-bind-ciphersuites", ssl_parse_global_ciphersuites },
	{ CFG_GLOBAL, "ssl-default-server-ciphersuites", ssl_parse_global_ciphersuites },
#endif
	{ 0, NULL, NULL },
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list conv_kws = {ILH, {
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000100fL)
	{ "aes_gcm_dec", sample_conv_aes_gcm_dec, ARG4(4,SINT,STR,STR,STR), check_aes_gcm, SMP_T_BIN, SMP_T_BIN },
#endif
	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &conv_kws);

/* transport-layer operations for SSL sockets */
static struct xprt_ops ssl_sock = {
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
	.prepare_bind_conf = ssl_sock_prepare_bind_conf,
	.destroy_bind_conf = ssl_sock_destroy_bind_conf,
	.prepare_srv = ssl_sock_prepare_srv_ctx,
	.destroy_srv = ssl_sock_free_srv_ctx,
	.get_alpn = ssl_sock_get_alpn,
	.name     = "SSL",
};

enum act_return ssl_action_wait_for_hs(struct act_rule *rule, struct proxy *px,
                                       struct session *sess, struct stream *s, int flags)
{
	struct connection *conn;
	struct conn_stream *cs;

	conn = objt_conn(sess->origin);
	cs = objt_cs(s->si[0].end);

	if (conn && cs) {
		if (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_SSL_WAIT_HS)) {
			cs->flags |= CS_FL_WAIT_FOR_HS;
			s->req.flags |= CF_READ_NULL;
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

#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)

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

__attribute__((constructor))
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
#if (HA_OPENSSL_VERSION_NUMBER >= 0x10101000L)
	if (global_ssl.listen_default_ciphersuites)
		global_ssl.listen_default_ciphersuites = strdup(global_ssl.listen_default_ciphersuites);
	if (global_ssl.connect_default_ciphersuites)
		global_ssl.connect_default_ciphersuites = strdup(global_ssl.connect_default_ciphersuites);
#endif

	xprt_register(XPRT_SSL, &ssl_sock);
#if HA_OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
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
#if (HA_OPENSSL_VERSION_NUMBER >= 0x1000200fL && !defined OPENSSL_NO_TLSEXT && !defined OPENSSL_IS_BORINGSSL)
	sctl_ex_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, ssl_sock_sctl_free_func);
#endif
	ssl_app_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	ssl_capture_ptr_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, ssl_sock_capture_free_func);
	ssl_pkey_info_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
#ifndef OPENSSL_NO_ENGINE
	ENGINE_load_builtin_engines();
	hap_register_post_check(ssl_check_async_engine_count);
#endif
#if (defined SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB && TLS_TICKETS_NO > 0)
	hap_register_post_check(tlskeys_finalize_config);
#endif

	global.ssl_session_max_cost   = SSL_SESSION_MAX_COST;
	global.ssl_handshake_max_cost = SSL_HANDSHAKE_MAX_COST;

#ifndef OPENSSL_NO_DH
	ssl_dh_ptr_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	hap_register_post_deinit(ssl_free_dh);
#endif
#ifndef OPENSSL_NO_ENGINE
	hap_register_post_deinit(ssl_free_engines);
#endif
	/* Load SSL string for the verbose & debug mode. */
	ERR_load_SSL_strings();
	ha_meth = BIO_meth_new(0x666, "ha methods");
	BIO_meth_set_write(ha_meth, ha_ssl_write);
	BIO_meth_set_read(ha_meth, ha_ssl_read);
	BIO_meth_set_ctrl(ha_meth, ha_ssl_ctrl);
	BIO_meth_set_create(ha_meth, ha_ssl_new);
	BIO_meth_set_destroy(ha_meth, ha_ssl_free);
	BIO_meth_set_puts(ha_meth, ha_ssl_puts);
	BIO_meth_set_gets(ha_meth, ha_ssl_gets);

	HA_SPIN_INIT(&ckch_lock);
}

/* Compute and register the version string */
static void ssl_register_build_options()
{
	char *ptr = NULL;
	int i;

	memprintf(&ptr, "Built with OpenSSL version : "
#ifdef OPENSSL_IS_BORINGSSL
		"BoringSSL");
#else /* OPENSSL_IS_BORINGSSL */
	        OPENSSL_VERSION_TEXT
		"\nRunning on OpenSSL version : %s%s",
	       OpenSSL_version(OPENSSL_VERSION),
	       ((OPENSSL_VERSION_NUMBER ^ OpenSSL_version_num()) >> 8) ? " (VERSIONS DIFFER!)" : "");
#endif
	memprintf(&ptr, "%s\nOpenSSL library supports TLS extensions : "
#if HA_OPENSSL_VERSION_NUMBER < 0x00907000L
		"no (library version too old)"
#elif defined(OPENSSL_NO_TLSEXT)
		"no (disabled via OPENSSL_NO_TLSEXT)"
#else
		"yes"
#endif
		"", ptr);

	memprintf(&ptr, "%s\nOpenSSL library supports SNI : "
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

	memprintf(&ptr, "%s\nOpenSSL library supports :", ptr);
	for (i = CONF_TLSV_MIN; i <= CONF_TLSV_MAX; i++)
		if (methodVersions[i].option)
			memprintf(&ptr, "%s %s", ptr, methodVersions[i].name);

	hap_register_build_opts(ptr, 1);
}

INITCALL0(STG_REGISTER, ssl_register_build_options);


#ifndef OPENSSL_NO_ENGINE
void ssl_free_engines(void) {
	struct ssl_engine_list *wl, *wlb;
	/* free up engine list */
	list_for_each_entry_safe(wl, wlb, &openssl_engines, list) {
		ENGINE_finish(wl->e);
		ENGINE_free(wl->e);
		LIST_DEL(&wl->list);
		free(wl);
	}
}
#endif

#ifndef OPENSSL_NO_DH
void ssl_free_dh(void) {
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
}
#endif

__attribute__((destructor))
static void __ssl_sock_deinit(void)
{
#if (defined SSL_CTRL_SET_TLSEXT_HOSTNAME && !defined SSL_NO_GENERATE_CERTIFICATES)
	if (ssl_ctx_lru_tree) {
		lru64_destroy(ssl_ctx_lru_tree);
		HA_RWLOCK_DESTROY(&ssl_ctx_lru_rwlock);
	}
#endif

#if (HA_OPENSSL_VERSION_NUMBER < 0x10100000L)
        ERR_remove_state(0);
        ERR_free_strings();

        EVP_cleanup();
#endif

#if (HA_OPENSSL_VERSION_NUMBER >= 0x00907000L) && (HA_OPENSSL_VERSION_NUMBER < 0x10100000L)
        CRYPTO_cleanup_all_ex_data();
#endif
	BIO_meth_free(ha_meth);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
