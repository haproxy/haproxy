/*
 * include/haproxy/dns-t.h
 * This file provides structures and types for DNS.
 *
 * Copyright (C) 2014 Baptiste Assmann <bedis9@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_RESOLVERS_T_H
#define _HAPROXY_RESOLVERS_T_H

#include <import/ebtree-t.h>

#include <haproxy/connection-t.h>
#include <haproxy/dns-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/task-t.h>
#include <haproxy/thread.h>

extern struct pool_head *resolv_requester_pool;

/*DNS maximum values */
/*
 * Maximum issued from RFC:
 *  RFC 1035: https://www.ietf.org/rfc/rfc1035.txt chapter 2.3.4
 *  RFC 2671: http://tools.ietf.org/html/rfc2671
 */
#define DNS_MAX_LABEL_SIZE   63
#define DNS_MAX_NAME_SIZE    255
#define DNS_MAX_UDP_MESSAGE  65535

/* DNS minimum record size: 1 char + 1 NULL + type + class */
#define DNS_MIN_RECORD_SIZE  (1 + 1 + 2 + 2)

/* DNS smallest fqdn 'a.gl' size */
# define DNS_SMALLEST_FQDN_SIZE 4

/* maximum number of query records in a DNS response
 * For now, we allow only one */
#define DNS_MAX_QUERY_RECORDS 1

/* maximum number of answer record in a DNS response */
#define DNS_MAX_ANSWER_RECORDS ((DNS_MAX_UDP_MESSAGE - DNS_HEADER_SIZE) / DNS_MIN_RECORD_SIZE)

/* size of dns_buffer used to store responses from the buffer
 * dns_buffer is used to store data collected from records found in a response.
 * Before using it, caller will always check that there is at least DNS_MAX_NAME_SIZE bytes
 * available */
#define DNS_ANALYZE_BUFFER_SIZE DNS_MAX_UDP_MESSAGE + DNS_MAX_NAME_SIZE

/* DNS error messages */
#define DNS_TOO_LONG_FQDN       "hostname too long"
#define DNS_LABEL_TOO_LONG      "one label too long"
#define DNS_INVALID_CHARACTER   "found an invalid character"

/* dns query class */
#define DNS_RCLASS_IN           1      /* internet class */

/* dns record types (non exhaustive list) */
#define DNS_RTYPE_A             1       /* IPv4 address */
#define DNS_RTYPE_CNAME         5       /* canonical name */
#define DNS_RTYPE_AAAA          28      /* IPv6 address */
#define DNS_RTYPE_SRV           33      /* SRV record */
#define DNS_RTYPE_OPT           41      /* OPT */
#define DNS_RTYPE_ANY           255     /* all records */

/* dns rcode values */
#define DNS_RCODE_NO_ERROR      0       /* no error */
#define DNS_RCODE_NX_DOMAIN     3       /* non existent domain */
#define DNS_RCODE_REFUSED       5       /* query refused */

/* dns flags masks */
#define DNS_FLAG_TRUNCATED      0x0200  /* mask for truncated flag */
#define DNS_FLAG_REPLYCODE      0x000F  /* mask for reply code */

/* max number of network preference entries are available from the
 * configuration file.
 */
#define SRV_MAX_PREF_NET 5

/* NOTE: big endian structure */
struct resolv_query_item {
	char           name[DNS_MAX_NAME_SIZE+1]; /* query name */
	unsigned short type;                      /* question type */
	unsigned short class;                     /* query class */
};

/* NOTE: big endian structure */
struct resolv_answer_item {
	/*For SRV type, name also includes service and protocol value */
	char            name[DNS_MAX_NAME_SIZE+1];   /* answer name */
	int16_t         type;                        /* question type */
	int16_t         class;                       /* query class */
	int32_t         ttl;                         /* response TTL */
	int16_t         priority;                    /* SRV type priority */
	uint16_t        weight;                      /* SRV type weight */
	uint16_t        port;                        /* SRV type port */
	uint16_t        data_len;                    /* number of bytes in the <data> field below */
	struct eb32_node link;                       /* linking node */
	union {
		struct sockaddr_in in4;              /* IPv4 address for RTYPE_A */
		struct sockaddr_in6 in6;             /* IPv6 address for RTYPE_AAAA */
		char target[DNS_MAX_NAME_SIZE+1];    /* Response data: SRV or CNAME type target */
	} data;
	unsigned int    last_seen;                   /* When was the answer was last seen */
	struct resolv_answer_item *ar_item;          /* pointer to a RRset from the additional section, if exists */
	struct list	attached_servers;            /* attached server head */
};

struct resolv_response {
	struct dns_header header;
	struct eb_root    answer_tree;
	/* authority ignored for now */
};

/* Resolvers section and parameters. It is linked to the name servers
 * servers points to it.
 * current resolution are stored in a FIFO list.
 */
struct resolvers {
	__decl_thread(HA_SPINLOCK_T lock);
	unsigned int accepted_payload_size; /* maximum payload size we accept for responses */
	int          nb_nameservers;        /* total number of active nameservers in a resolvers section */
	int          resolve_retries;       /* number of retries before giving up */
	struct {                            /* time to: */
		int resolve;                /*     wait between 2 queries for the same resolution */
		int retry;                  /*     wait for a response before retrying */
	} timeout;
	struct {                            /* time to hold current data when */
		int valid;                  /*     a response is valid */
		int nx;                     /*     a response doesn't exist */
		int timeout;                /*     no answer was delivered */
		int refused;                /*     dns server refused to answer */
		int other;                  /*     other dns response errors */
		int obsolete;               /*     an answer hasn't been seen */
	} hold;
	struct task *t;                     /* timeout management */
	struct {
		struct list wait;           /* resolutions managed to this resolvers section */
		struct list curr;           /* current running resolutions */
	} resolutions;
	struct eb_root query_ids;           /* tree to quickly lookup/retrieve query ids currently in use
                                             * used by each nameserver, but stored in resolvers since there must
                                             * be a unique relation between an eb_root and an eb_node (resolution) */
	struct list list;                   /* resolvers list */
	struct list  nameservers;           /* dns server list */
	struct proxy *px;                   /* px to handle connections to DNS servers */
	char      *id;                      /* resolvers unique identifier */
	struct {
		const char *file;           /* file where the section appears */
		int         line;           /* line where the section appears */
	} conf;                             /* config information */
};

struct resolv_options {
	int family_prio; /* which IP family should the resolver use when both are returned */
	struct {
		int family;
		union {
			struct in_addr  in4;
			struct in6_addr in6;
		} addr;
		union {
			struct in_addr  in4;
			struct in6_addr in6;
		} mask;
	} pref_net[SRV_MAX_PREF_NET];
	int pref_net_nb; /* The number of registered preferred networks. */
	int accept_duplicate_ip; /* flag to indicate whether the associated object can use an IP address
				    already set to an other object of the same group */
	int ignore_weight; /* flag to indicate whether to ignore the weight within the record */
};

/* Resolution structure associated to single server and used to manage name
 * resolution for this server.
 * The only link between the resolution and a nameserver is through the
 * query_id.
 */
struct resolv_resolution {
	struct resolvers     *resolvers;           /* pointer to the resolvers structure owning the resolution */
	struct list           requesters;          /* list of requesters using this resolution */
	int                   uuid;                /* unique id (used for debugging purpose) */
	char                 *hostname_dn;         /* server hostname in domain name label format */
	int                   hostname_dn_len;     /* server domain name label len */
	unsigned int          last_resolution;     /* time of the last resolution */
	unsigned int          last_query;          /* time of the last query sent */
	unsigned int          last_valid;          /* time of the last valid response */
	int                   query_id;            /* DNS query ID dedicated for this resolution */
	struct eb32_node      qid;                 /* ebtree query id */
	int                   prefered_query_type; /* preferred query type */
	int                   query_type;          /* current query type  */
	int                   status;              /* status of the resolution being processed RSLV_STATUS_* */
	int                   step;                /* RSLV_STEP_* */
	int                   try;                 /* current resolution try */
	int                   nb_queries;          /* count number of queries sent */
	int                   nb_responses;        /* count number of responses received */

	struct resolv_response response;           /* structure hosting the DNS response */
	struct resolv_query_item response_query_records[DNS_MAX_QUERY_RECORDS]; /* <response> query records */

	struct list list; /* resolution list */
};

/* Structure used to describe the owner of a DNS resolution. */
struct resolv_requester {
	enum obj_type         *owner;       /* pointer to the owner (server or dns_srvrq) */
	struct resolv_resolution *resolution;  /* pointer to the owned DNS resolution */

	int (*requester_cb)(struct resolv_requester *, struct dns_counters *);   /* requester callback for valid response */
	int (*requester_error_cb)(struct resolv_requester *, int);               /* requester callback, for error management */

	struct list list; /* requester list */
};

/* Last resolution status code */
enum {
	RSLV_STATUS_NONE = 0,  /* no resolution occurred yet */
	RSLV_STATUS_VALID,     /* no error */
	RSLV_STATUS_INVALID,   /* invalid responses */
	RSLV_STATUS_ERROR,     /* error */
	RSLV_STATUS_NX,        /* NXDOMAIN */
	RSLV_STATUS_REFUSED,   /* server refused our query */
	RSLV_STATUS_TIMEOUT,   /* no response from DNS servers */
	RSLV_STATUS_OTHER,     /* other errors */
};

/* Current resolution step */
enum {
	RSLV_STEP_NONE = 0,    /* nothing happening currently */
	RSLV_STEP_RUNNING,     /* resolution is running */
};

/* Return codes after analyzing a DNS response */
enum {
	RSLV_RESP_VALID = 0,          /* valid response */
	RSLV_RESP_INVALID,            /* invalid response (various type of errors can trigger it) */
	RSLV_RESP_ERROR,              /* DNS error code */
	RSLV_RESP_NX_DOMAIN,          /* resolution unsuccessful */
	RSLV_RESP_REFUSED,            /* DNS server refused to answer */
	RSLV_RESP_ANCOUNT_ZERO,       /* no answers in the response */
	RSLV_RESP_WRONG_NAME,         /* response does not match query name */
	RSLV_RESP_CNAME_ERROR,        /* error when resolving a CNAME in an atomic response */
	RSLV_RESP_TIMEOUT,            /* DNS server has not answered in time */
	RSLV_RESP_TRUNCATED,          /* DNS response is truncated */
	RSLV_RESP_NO_EXPECTED_RECORD, /* No expected records were found in the response */
	RSLV_RESP_QUERY_COUNT_ERROR,  /* we did not get the expected number of queries in the response */
	RSLV_RESP_INTERNAL,           /* internal resolver error */
};

/* Return codes after searching an IP in a DNS response buffer, using a family
 * preference
 */
enum {
	RSLV_UPD_NO = 1,           /* provided IP was found and preference is matched
	                            * OR provided IP found and preference is not matched, but no IP
	                            * matching preference was found.
	                            */
	RSLV_UPD_SRVIP_NOT_FOUND,  /* provided IP not found
	                            * OR provided IP found and preference is not match and an IP
	                            * matching preference was found.
	                            */
	RSLV_UPD_CNAME,            /* CNAME without any IP provided in the response */
	RSLV_UPD_NAME_ERROR,       /* name in the response did not match the query */
	RSLV_UPD_NO_IP_FOUND,      /* no IP could be found in the response */
	RSLV_UPD_OBSOLETE_IP,      /* The server IP was obsolete, and no other IP was found */
};

struct proxy;
struct resolv_srvrq {
	enum obj_type         obj_type;         /* object type == OBJ_TYPE_SRVRQ */
	struct resolvers     *resolvers;        /* pointer to the resolvers structure used for this server template */
	struct proxy         *proxy;            /* associated proxy */
	char                 *name;
	char                 *hostname_dn;      /* server hostname in Domain Name format */
	int                   hostname_dn_len;  /* string length of the server hostname in Domain Name format */
	struct resolv_requester *requester;     /* used to link to its DNS resolution */
	struct list attached_servers;           /* List of the servers free to use */
	struct eb_root named_servers;           /* tree of servers indexed by hostnames found in server state file */
	struct list list;                       /* Next SRV RQ for the same proxy */
};

#endif /* _HAPROXY_RESOLVERS_T_H */
