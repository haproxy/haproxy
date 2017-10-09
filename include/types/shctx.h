#ifndef __TYPES_SHCTX
#define __TYPES_SHCTX

#include <openssl/ssl.h> /* shared session depend of openssl */

#ifndef SHSESS_BLOCK_MIN_SIZE
#define SHSESS_BLOCK_MIN_SIZE 128
#endif

#ifndef SHSESS_MAX_DATA_LEN
#define SHSESS_MAX_DATA_LEN 4096
#endif

#ifndef SHCTX_APPNAME
#define SHCTX_APPNAME "haproxy"
#endif

#define SHCTX_E_ALLOC_CACHE -1
#define SHCTX_E_INIT_LOCK   -2

struct shared_session {
	struct ebmb_node key;
	unsigned char key_data[SSL_MAX_SSL_SESSION_ID_LENGTH];
	unsigned char data[SHSESS_BLOCK_MIN_SIZE];
};

struct shared_block {
	union {
		struct shared_session session;
		unsigned char data[sizeof(struct shared_session)];
	} data;
	short int data_len;
	struct shared_block *p;
	struct shared_block *n;
};

struct shared_context {
#ifndef USE_PRIVATE_CACHE
#ifdef USE_PTHREAD_PSHARED
	pthread_mutex_t mutex;
#else
	unsigned int waiters;
#endif
#endif
	struct shared_block active;
	struct shared_block free;
};

extern struct shared_context *shctx;

#endif
