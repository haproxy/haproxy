#ifndef _MINI_SAMPLE_H
#define _MINI_SAMPLE_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

/* input and output sample types */
enum {
	SMP_T_ANY = 0,   /* any type */
	SMP_T_BOOL,      /* boolean */
	SMP_T_SINT,      /* signed 64bits integer type */
	SMP_T_ADDR,      /* ipv4 or ipv6, only used for input type compatibility */
	SMP_T_IPV4,      /* ipv4 type */
	SMP_T_IPV6,      /* ipv6 type */
	SMP_T_STR,       /* char string type */
	SMP_T_BIN,       /* buffer type */
	SMP_T_METH,      /* contain method */
	SMP_TYPES        /* number of types, must always be last */
};

/* describes a chunk of string */
struct chunk {
	char *str;	/* beginning of the string itself. Might not be 0-terminated */
	int size;	/* total size of the buffer, 0 if the *str is read-only */
	int len;	/* current size of the string from first to last char. <0 = uninit. */
};

union sample_value {
	long long int   sint;  /* used for signed 64bits integers */
	struct in_addr  ipv4;  /* used for ipv4 addresses */
	struct in6_addr ipv6;  /* used for ipv6 addresses */
	struct chunk    str;   /* used for char strings or buffers */
	//struct meth     meth;  /* used for http method */
};

/* Used to store sample constant */
struct sample_data {
	int type;                 /* SMP_T_* */
	union sample_value u;     /* sample data */
};

/* a sample is a typed data extracted from a stream. It has a type, contents,
 * validity constraints, a context for use in iterative calls.
 */
struct sample {
	struct sample_data data;
};
#endif

