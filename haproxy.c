/*
 * HA-Proxy : High Availability-enabled HTTP/TCP proxy
 * 2000-2002 - Willy Tarreau - willy AT meta-x DOT org.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Pending bugs :
 *   - cookie in insert+indirect mode sometimes segfaults !
 *   - a proxy with an invalid config will prevent the startup even if disabled.
 *
 * ChangeLog :
 *
 * 2002/03/22
 *   - released 1.1.3
 *   - fixed a bug : cr_expire and cw_expire were inverted in CL_STSHUT[WR]
 *     which could lead to loops.
 * 2002/03/21
 *   - released 1.1.2
 *   - fixed a bug in buffer management where we could have a loop
 *     between event_read() and process_{cli|srv} if R==BUFSIZE-MAXREWRITE.
 *     => implemented an adjustable buffer limit.
 *   - fixed a bug : expiration of tasks in wait queue timeout is used again,
 *     and running tasks are skipped.
 *   - added some debug lines for accept events.
 *   - send warnings for servers up/down.
 * 2002/03/12
 *   - released 1.1.1
 *   - fixed a bug in total failure handling
 *   - fixed a bug in timestamp comparison within same second (tv_cmp_ms)
 * 2002/03/10
 *   - released 1.1.0
 *   - fixed a few timeout bugs
 *   - rearranged the task scheduler subsystem to improve performance,
 *     add new tasks, and make it easier to later port to librt ;
 *   - allow multiple accept() for one select() wake up ;
 *   - implemented internal load balancing with basic health-check ;
 *   - cookie insertion and header add/replace/delete, with better strings
 *     support.
 * 2002/03/08
 *   - reworked buffer handling to fix a few rewrite bugs, and
 *     improve overall performance.
 *   - implement the "purge" option to delete server cookies in direct mode.
 * 2002/03/07
 *   - fixed some error cases where the maxfd was not decreased.
 * 2002/02/26
 *   - now supports transparent proxying, at least on linux 2.4.
 * 2002/02/12
 *   - soft stop works again (fixed select timeout computation).
 *   - it seems that TCP proxies sometimes cannot timeout.
 *   - added a "quiet" mode.
 *   - enforce file descriptor limitation on socket() and accept().
 * 2001/12/30 : release of version 1.0.2 : fixed a bug in header processing
 * 2001/12/19 : release of version 1.0.1 : no MSG_NOSIGNAL on solaris
 * 2001/12/16 : release of version 1.0.0.
 * 2001/12/16 : added syslog capability for each accepted connection.
 * 2001/11/19 : corrected premature end of files and occasional SIGPIPE.
 * 2001/10/31 : added health-check type servers (mode health) which replies OK then closes.
 * 2001/10/30 : added the ability to support standard TCP proxies and HTTP proxies
 * 		with or without cookies (use keyword http for this).
 * 2001/09/01 : added client/server header replacing with regexps.
 * 		eg:
 *			cliexp ^(Host:\ [^:]*).* Host:\ \1:80
 *			srvexp ^Server:\ .* Server:\ Apache
 * 2000/11/29 : first fully working release with complete FSMs and timeouts.
 * 2000/11/28 : major rewrite
 * 2000/11/26 : first write
 *
 * TODO:
 *   - handle properly intermediate incomplete server headers. Done ?
 *   - log proxies start/stop
 *   - handle hot-reconfiguration
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <time.h>
#include <regex.h>
#include <syslog.h>
#if defined(TRANSPARENT) && defined(NETFILTER)
#include <linux/netfilter_ipv4.h>
#endif

#define HAPROXY_VERSION "1.1.3"
#define HAPROXY_DATE	"2002/03/22"

/* this is for libc5 for example */
#ifndef TCP_NODELAY
#define TCP_NODELAY	1
#endif

#ifndef SHUT_RD
#define SHUT_RD		0
#endif

#ifndef SHUT_WR
#define SHUT_WR		1
#endif

#define BUFSIZE		4096

// reserved buffer space for header rewriting
#define	MAXREWRITE	256

// max # args on a configuration line
#define MAX_LINE_ARGS	10

// max # of regexps per proxy
#define	MAX_REGEXP	10

// max # of matches per regexp
#define	MAX_MATCH	10

/* FIXME: serverid_len and cookiename_len are no longer checked in configuration file */
#define COOKIENAME_LEN	16
#define SERVERID_LEN	16
#define CONN_RETRIES	3

/* FIXME: this should be user-configurable */
#define	CHK_CONNTIME	2000
#define	CHK_INTERVAL	2000
#define FALLTIME	3
#define RISETIME	2

/* how many bits are needed to code the size of an int (eg: 32bits -> 5) */
#define	INTBITS		5

/* show stats this every millisecond, 0 to disable */
#ifndef STATTIME
#define STATTIME	2000
#endif

/* this reduces the number of calls to select() by choosing appropriate
 * sheduler precision in milliseconds. It should be near the minimum
 * time that is needed by select() to collect all events. All timeouts
 * are rounded up by adding this value prior to pass it to select().
 */
#define SCHEDULER_RESOLUTION	9

#define MINTIME(old, new)	(((new)<0)?(old):(((old)<0||(new)<(old))?(new):(old)))
#define SETNOW(a)		(*a=now)

/****** string-specific macros and functions ******/
/* if a > max, then bound <a> to <max>. The macro returns the new <a> */
#define UBOUND(a, max)	({ typeof(a) b = (max); if ((a) > b) (a) = b; (a); })

/* if a < min, then bound <a> to <min>. The macro returns the new <a> */
#define LBOUND(a, min)	({ typeof(a) b = (min); if ((a) < b) (a) = b; (a); })


#ifndef HAVE_STRLCPY
/*
 * copies at most <size-1> chars from <src> to <dst>. Last char is always
 * set to 0, unless <size> is 0. The number of chars copied is returned
 * (excluding the terminating zero).
 * This code has been optimized for size and speed : on x86, it's 45 bytes
 * long, uses only registers, and consumes only 4 cycles per char.
 */
int strlcpy(char *dst, const char *src, int size) {
    char *orig = dst;
    if (size) {
	while (--size && (*dst = *src)) {
	    src++; dst++;
	}
	*dst = 0;
    }
    return dst - orig;
}
#endif


#define MEM_OPTIM
#ifdef	MEM_OPTIM
/*
 * Returns a pointer to type <type> taken from the
 * pool <pool_type> or dynamically allocated. In the
 * first case, <pool_type> is updated to point to the
 * next element in the list.
 */
#define pool_alloc(type) ({			\
    void *p;					\
    if ((p = pool_##type) == NULL)		\
	p = malloc(sizeof_##type);		\
    else {					\
	pool_##type = *(void **)pool_##type;	\
    }						\
    p;						\
})

/*
 * Puts a memory area back to the corresponding pool.
 * Items are chained directly through a pointer that
 * is written in the beginning of the memory area, so
 * there's no need for any carrier cell. This implies
 * that each memory area is at least as big as one
 * pointer.
 */
#define pool_free(type, ptr) ({				\
    *(void **)ptr = (void *)pool_##type;		\
    pool_##type = (void *)ptr;				\
})

#else
#define pool_alloc(type) (calloc(1,sizeof_##type));
#define pool_free(type, ptr) (free(ptr));
#endif	/* MEM_OPTIM */

#define sizeof_task	sizeof(struct task)
#define sizeof_session	sizeof(struct session)
#define sizeof_buffer	sizeof(struct buffer)
#define sizeof_fdtab	sizeof(struct fdtab)
#define sizeof_str256	256


/* different possible states for the sockets */
#define FD_STCLOSE	0
#define FD_STLISTEN	1
#define FD_STCONN	2
#define FD_STREADY	3
#define FD_STERROR	4

/* values for task->state */
#define TASK_IDLE	0
#define TASK_RUNNING	1

/* values for proxy->state */
#define PR_STNEW	0
#define PR_STIDLE	1
#define PR_STRUN	2
#define PR_STDISABLED	3

/* values for proxy->mode */
#define PR_MODE_TCP	0
#define PR_MODE_HTTP	1
#define PR_MODE_HEALTH	2

/* bits for proxy->options */
#define PR_O_REDISP	1	/* allow reconnection to dispatch in case of errors */
#define PR_O_TRANSP	2	/* transparent mode : use original DEST as dispatch */
#define PR_O_COOK_RW	4	/* rewrite all direct cookies with the right serverid */
#define PR_O_COOK_IND	8	/* keep only indirect cookies */
#define PR_O_COOK_INS	16	/* insert cookies when not accessing a server directly */
#define PR_O_COOK_ANY	(PR_O_COOK_RW | PR_O_COOK_IND | PR_O_COOK_INS)
#define PR_O_BALANCE_RR	32	/* balance in round-robin mode */
#define PR_O_BALANCE	(PR_O_BALANCE_RR)

/* various task flags */
#define TF_DIRECT	1	/* connection made on the server matching the client cookie */

/* different possible states for the client side */
#define CL_STHEADERS	0
#define CL_STDATA	1
#define CL_STSHUTR	2
#define CL_STSHUTW	3
#define CL_STCLOSE	4

/* different possible states for the server side */
#define SV_STIDLE	0
#define SV_STCONN	1
#define SV_STHEADERS	2
#define SV_STDATA	3
#define SV_STSHUTR	4
#define SV_STSHUTW	5
#define SV_STCLOSE	6

/* result of an I/O event */
#define	RES_SILENT	0	/* didn't happen */
#define RES_DATA	1	/* data were sent or received */
#define	RES_NULL	2	/* result is 0 (read == 0), or connect without need for writing */
#define RES_ERROR	3	/* result -1 or error on the socket (eg: connect()) */

/* modes of operation (global variable "mode") */
#define	MODE_DEBUG	1
#define	MODE_STATS	2
#define	MODE_LOG	4
#define	MODE_DAEMON	8
#define	MODE_QUIET	16

/* server flags */
#define SRV_RUNNING	1

/*********************************************************************/

#define LIST_HEAD(a)	((void *)(&(a)))

/*********************************************************************/

struct hdr_exp {
    regex_t *preg;	/* expression to look for */
    char *replace;	/* expression to set instead */
};

struct buffer {
    unsigned int l;			/* data length */
    char *r, *w, *h, *lr;     		/* read ptr, write ptr, last header ptr, last read */
    char *rlim;				/* read limit, used for header rewriting */
    char data[BUFSIZE];
};

struct server {
    struct server *next;
    int state;				/* server state (SRV_*) */
    int  cklen;				/* the len of the cookie, to speed up checks */
    char *cookie;			/* the id set in the cookie */
    char *id;				/* just for identification */
    struct sockaddr_in addr;		/* the address to connect to */
    int health;				/* 0->rise-1 = bad; rise->rise+fall-1 = good */
    int result;				/* 0 = connect OK, -1 = connect KO */
    int curfd;				/* file desc used for current test, or -1 if not in test */
};

/* The base for all tasks */
struct task {
    struct task *next, *prev;		/* chaining ... */
    struct task *rqnext;		/* chaining in run queue ... */
    struct task *wq;			/* the wait queue this task is in */
    int state;				/* task state : IDLE or RUNNING */
    struct timeval expire;		/* next expiration time for this task, use only for fast sorting */
    int (*process)(struct task *t);	/* the function which processes the task */
    void *context;			/* the task's context */
};

/* WARNING: if new fields are added, they must be initialized in event_accept() */
struct session {
    struct task *task;			/* the task associated with this session */
    /* application specific below */
    struct timeval crexpire;		/* expiration date for a client read  */
    struct timeval cwexpire;		/* expiration date for a client write */
    struct timeval srexpire;		/* expiration date for a server read  */
    struct timeval swexpire;		/* expiration date for a server write */
    struct timeval cnexpire;		/* expiration date for a connect */
    char res_cr, res_cw, res_sr, res_sw;/* results of some events */
    struct proxy *proxy;		/* the proxy this socket belongs to */
    int cli_fd;				/* the client side fd */
    int srv_fd;				/* the server side fd */
    int cli_state;			/* state of the client side */
    int srv_state;			/* state of the server side */
    int conn_retries;			/* number of connect retries left */
    int flags;				/* some flags describing the session */
    struct buffer *req;			/* request buffer */
    struct buffer *rep;			/* response buffer */
    struct sockaddr_in cli_addr;	/* the client address */
    struct sockaddr_in srv_addr;	/* the address to connect to */
    struct server *srv;			/* the server being used */
};

struct proxy {
    int listen_fd;			/* the listen socket */
    int state;				/* proxy state */
    struct sockaddr_in listen_addr;	/* the address we listen to */
    struct sockaddr_in dispatch_addr;	/* the default address to connect to */
    struct server *srv, *cursrv;	/* known servers, current server */
    int nbservers;			/* # of servers */
    char *cookie_name;			/* name of the cookie to look for */
    int clitimeout;			/* client I/O timeout (in milliseconds) */
    int srvtimeout;			/* server I/O timeout (in milliseconds) */
    int contimeout;			/* connect timeout (in milliseconds) */
    char *id;				/* proxy id */
    int nbconn;				/* # of active sessions */
    int maxconn;			/* max # of active sessions */
    int conn_retries;			/* maximum number of connect retries */
    int options;			/* PR_O_REDISP, PR_O_TRANSP */
    int mode;				/* mode = PR_MODE_TCP, PR_MODE_HTTP or PR_MODE_HEALTH */
    struct proxy *next;
    struct sockaddr_in logsrv1, logsrv2; /* 2 syslog servers */
    char logfac1, logfac2;		/* log facility for both servers. -1 = disabled */
    struct timeval stop_time;		/* date to stop listening, when stopping != 0 */
    int nb_reqexp, nb_rspexp, nb_reqadd, nb_rspadd;
    struct hdr_exp req_exp[MAX_REGEXP];	/* regular expressions for request headers */
    struct hdr_exp rsp_exp[MAX_REGEXP];	/* regular expressions for response headers */
    char *req_add[MAX_REGEXP], *rsp_add[MAX_REGEXP]; /* headers to be added */
    int grace;				/* grace time after stop request */
};

/* info about one given fd */
struct fdtab {
    int (*read)(int fd);	/* read function */
    int (*write)(int fd);	/* write function */
    struct task *owner;		/* the session (or proxy) associated with this fd */
    int state;			/* the state of this fd */
};

/*********************************************************************/

int cfg_maxconn = 2000;		/* # of simultaneous connections, (-n) */
int cfg_maxpconn = 2000;	/* # of simultaneous connections per proxy (-N) */
int cfg_maxsock = 0;		/* max # of sockets */
char *cfg_cfgfile = NULL;	/* configuration file */
char *progname = NULL;		/* program name */
int  pid;			/* current process id */
/*********************************************************************/

fd_set	*ReadEvent,
	*WriteEvent,
	*StaticReadEvent,
    	*StaticWriteEvent;

void **pool_session = NULL,
    **pool_buffer   = NULL,
    **pool_fdtab    = NULL,
    **pool_str256   = NULL,
    **pool_task	    = NULL;

struct proxy *proxy  = NULL;	/* list of all existing proxies */
struct fdtab *fdtab = NULL;	/* array of all the file descriptors */
struct task *rq = NULL;		/* global run queue */
struct task wait_queue = {	/* global wait queue */
    prev:LIST_HEAD(wait_queue),
    next:LIST_HEAD(wait_queue)
};

static int mode = 0;		/* MODE_DEBUG, ... */
static int totalconn = 0;	/* total # of terminated sessions */
static int actconn = 0;		/* # of active sessions */
static int maxfd = 0;		/* # of the highest fd + 1 */
static int listeners = 0;	/* # of listeners */
static int stopping = 0;	/* non zero means stopping in progress */
static struct timeval now = {0,0};	/* the current date at any moment */

static regmatch_t pmatch[MAX_MATCH];  /* rm_so, rm_eo for regular expressions */
static char trash[BUFSIZE];

/*
 * Syslog facilities and levels
 */

#define MAX_SYSLOG_LEN		1024
#define NB_LOG_FACILITIES	24
const char *log_facilities[NB_LOG_FACILITIES] = {
    "kern", "user", "mail", "daemon",
    "auth", "syslog", "lpr", "news",
    "uucp", "cron", "auth2", "ftp",
    "ntp", "audit", "alert", "cron2",
    "local0", "local1", "local2", "local3",
    "local4", "local5", "local6", "local7"
};


#define NB_LOG_LEVELS	8
const char *log_levels[NB_LOG_LEVELS] = {
    "emerg", "alert", "crit", "err",
    "warning", "notice", "info", "debug"
};

#define SYSLOG_PORT	514

const char *monthname[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
#define MAX_HOSTNAME_LEN	32
static char hostname[MAX_HOSTNAME_LEN] = "";

/*********************************************************************/
/*  statistics  ******************************************************/
/*********************************************************************/

static int stats_tsk_lsrch, stats_tsk_rsrch,
    stats_tsk_good, stats_tsk_right, stats_tsk_left,
    stats_tsk_new, stats_tsk_nsrch;


/*********************************************************************/
/*  function prototypes  *********************************************/
/*********************************************************************/

int event_accept(int fd);
int event_cli_read(int fd);
int event_cli_write(int fd);
int event_srv_read(int fd);
int event_srv_write(int fd);
int process_session(struct task *t);

/*********************************************************************/
/*  general purpose functions  ***************************************/
/*********************************************************************/

void display_version() {
    printf("HA-Proxy version " HAPROXY_VERSION " " HAPROXY_DATE"\n");
    printf("Copyright 2000-2002 Willy Tarreau <willy AT meta-x DOT org>\n\n");
}

/*
 * This function prints the command line usage and exits
 */
void usage(char *name) {
    display_version();
    fprintf(stderr,
	    "Usage : %s -f <cfgfile> [ -vd"
#if STATTIME > 0
	    "sl"
#endif
	    "D ] [ -n <maxconn> ] [ -N <maxpconn> ]\n"
	    "        -v displays version\n"
	    "        -d enters debug mode\n"
#if STATTIME > 0
	    "        -s enables statistics output\n"
	    "        -l enables long statistics format\n"
#endif
	    "        -D goes daemon ; implies -q\n"
	    "        -q quiet mode : don't display messages\n"
	    "        -n sets the maximum total # of connections (%d)\n"
	    "        -N sets the default, per-proxy maximum # of connections (%d)\n\n",
	    name, cfg_maxconn, cfg_maxpconn);
    exit(1);
}


/*
 * Displays the message on stderr with the date and pid.
 */
void Alert(char *fmt, ...) {
    va_list argp;
    struct timeval tv;
    struct tm *tm;

    if (!(mode & MODE_QUIET)) {
	va_start(argp, fmt);

	gettimeofday(&tv, NULL);
	tm=localtime(&tv.tv_sec);
	fprintf(stderr, "[ALERT] %03d/%02d%02d%02d (%d) : ",
		tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec, getpid());
	vfprintf(stderr, fmt, argp);
	fflush(stderr);
	va_end(argp);
    }
}


/*
 * Displays the message on stderr with the date and pid.
 */
void Warning(char *fmt, ...) {
    va_list argp;
    struct timeval tv;
    struct tm *tm;

    if (!(mode & MODE_QUIET)) {
	va_start(argp, fmt);

	gettimeofday(&tv, NULL);
	tm=localtime(&tv.tv_sec);
	fprintf(stderr, "[WARNING] %03d/%02d%02d%02d (%d) : ",
		tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec, getpid());
	vfprintf(stderr, fmt, argp);
	fflush(stderr);
	va_end(argp);
    }
}

/*
 * Displays the message on <out> only if quiet mode is not set.
 */
void qfprintf(FILE *out, char *fmt, ...) {
    va_list argp;

    if (!(mode & MODE_QUIET)) {
	va_start(argp, fmt);
	vfprintf(out, fmt, argp);
	fflush(out);
	va_end(argp);
    }
}


/*
 * converts <str> to a struct sockaddr_in* which is locally allocated.
 * The format is "addr:port", where "addr" can be empty or "*" to indicate
 * INADDR_ANY.
 */
struct sockaddr_in *str2sa(char *str) {
    static struct sockaddr_in sa;
    char *c;
    int port;

    bzero(&sa, sizeof(sa));
    str=strdup(str);

    if ((c=strrchr(str,':')) != NULL) {
	*c++=0;
	port=atol(c);
    }
    else
	port=0;

    if (*str == '*' || *str == '\0') { /* INADDR_ANY */
	sa.sin_addr.s_addr = INADDR_ANY;
    }
    else if (
#ifndef SOLARIS
	!inet_aton(str, &sa.sin_addr)
#else
	!inet_pton(AF_INET, str, &sa.sin_addr)
#endif
	) {
	struct hostent *he;

	if ((he = gethostbyname(str)) == NULL) {
	    Alert("Invalid server name: <%s>\n", str);
	}
	else
	    sa.sin_addr = *(struct in_addr *) *(he->h_addr_list);
    }
    sa.sin_port=htons(port);
    sa.sin_family=AF_INET;

    free(str);
    return &sa;
}

/*
 * This function tries to send a syslog message to the syslog server at
 * address <sa>. It doesn't care about errors nor does it report them.
 * WARNING! no check is made on the prog+hostname+date length, so the
 * local hostname + the prog name must be shorter than MAX_SYSLOG_LEN-19.
 * the message will be truncated to fit the maximum length.
 */
void send_syslog(struct sockaddr_in *sa,
		 int facility, int level, char *message)
{

    static int logfd = -1;	/* syslog UDP socket */
    struct timeval tv;
    struct tm *tm;
    static char logmsg[MAX_SYSLOG_LEN];
    char *p;

    if (logfd < 0) {
	if ((logfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	    return;
    }
    
    if (facility < 0 || level < 0
	|| sa == NULL || progname == NULL || message == NULL)
	return;

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);

    p = logmsg;
    //p += sprintf(p, "<%d>%s %2d %02d:%02d:%02d %s %s[%d]: ",
    //		   facility * 8 + level,
    //		   monthname[tm->tm_mon],
    //		   tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec,
    //		   hostname, progname, pid);
    /* 20011216/WT : other progs don't set the hostname, and syslogd
     * systematically repeats it which is contrary to RFC3164.
     */
    p += sprintf(p, "<%d>%s %2d %02d:%02d:%02d %s[%d]: ",
		 facility * 8 + level,
		 monthname[tm->tm_mon],
		 tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec,
		 progname, pid);

    if (((char *)&logmsg - p + MAX_SYSLOG_LEN) > 0) {
	int len = strlen(message);
	if (len > ((char *)&logmsg + MAX_SYSLOG_LEN - p))
	    len = ((char *)&logmsg + MAX_SYSLOG_LEN - p);
	memcpy(p, message, len);
	p += len;
    }
#ifndef MSG_NOSIGNAL
    sendto(logfd, logmsg, p - logmsg, MSG_DONTWAIT,
	   (struct sockaddr *)sa, sizeof(*sa));
#else
    sendto(logfd, logmsg, p - logmsg, MSG_DONTWAIT | MSG_NOSIGNAL,
	   (struct sockaddr *)sa, sizeof(*sa));
#endif
}


/* sets <tv> to the current time */
static inline struct timeval *tv_now(struct timeval *tv) {
    if (tv)
	gettimeofday(tv, NULL);
    return tv;
}

/*
 * adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv>
 */
static inline struct timeval *tv_delayfrom(struct timeval *tv, struct timeval *from, int ms) {
    if (!tv || !from)
	return NULL;
    tv->tv_usec = from->tv_usec + (ms%1000)*1000;
    tv->tv_sec  = from->tv_sec  + (ms/1000);
    while (tv->tv_usec >= 1000000) {
	tv->tv_usec -= 1000000;
	tv->tv_sec++;
    }
    return tv;
}

/*
 * compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 */
static inline int tv_cmp(struct timeval *tv1, struct timeval *tv2) {
    if (tv1->tv_sec > tv2->tv_sec)
	return 1;
    else if (tv1->tv_sec < tv2->tv_sec)
	return -1;
    else if (tv1->tv_usec > tv2->tv_usec)
	return 1;
    else if (tv1->tv_usec < tv2->tv_usec)
	return -1;
    else
	return 0;
}

/*
 * returns the absolute difference, in ms, between tv1 and tv2
 */
unsigned long tv_delta(struct timeval *tv1, struct timeval *tv2) {
    int cmp;
    unsigned long ret;
  

    cmp = tv_cmp(tv1, tv2);
    if (!cmp)
	return 0; /* same dates, null diff */
    else if (cmp<0) {
	struct timeval *tmp = tv1;
	tv1 = tv2;
	tv2 = tmp;
    }
    ret = (tv1->tv_sec - tv2->tv_sec) * 1000;
    if (tv1->tv_usec > tv2->tv_usec)
	ret += (tv1->tv_usec - tv2->tv_usec) / 1000;
    else
	ret -= (tv2->tv_usec - tv1->tv_usec) / 1000;
    return (unsigned long) ret;
}

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 */
static inline int tv_cmp_ms(struct timeval *tv1, struct timeval *tv2) {
    if (tv1->tv_sec == tv2->tv_sec) {
	if (tv1->tv_usec > tv2->tv_usec + 1000)
	    return 1;
	else if (tv2->tv_usec > tv1->tv_usec + 1000)
	    return -1;
	else
	    return 0;
    }
    else if ((tv1->tv_sec > tv2->tv_sec + 1) ||
	((tv1->tv_sec == tv2->tv_sec + 1) && (tv1->tv_usec + 1000000 > tv2->tv_usec + 1000)))
	return 1;
    else if ((tv2->tv_sec > tv1->tv_sec + 1) ||
	     ((tv2->tv_sec == tv1->tv_sec + 1) && (tv2->tv_usec + 1000000 > tv1->tv_usec + 1000)))
	return -1;
    else
	return 0;
}

/*
 * returns the remaining time between tv1=now and event=tv2
 * if tv2 is passed, 0 is returned.
 */
static inline unsigned long tv_remain(struct timeval *tv1, struct timeval *tv2) {
    unsigned long ret;
  
    if (tv_cmp_ms(tv1, tv2) >= 0)
	return 0; /* event elapsed */

    ret = (tv2->tv_sec - tv1->tv_sec) * 1000;
    if (tv2->tv_usec > tv1->tv_usec)
	ret += (tv2->tv_usec - tv1->tv_usec) / 1000;
    else
	ret -= (tv1->tv_usec - tv2->tv_usec) / 1000;
    return (unsigned long) ret;
}


/*
 * zeroes a struct timeval
 */

static inline struct timeval *tv_eternity(struct timeval *tv) {
    tv->tv_sec = tv->tv_usec = 0;
    return tv;
}

/*
 * returns 1 if tv is null, else 0
 */
static inline int tv_iseternity(struct timeval *tv) {
    if (tv->tv_sec == 0 && tv->tv_usec == 0)
	return 1;
    else
	return 0;
}

/*
 * compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * considering that 0 is the eternity.
 */
static inline int tv_cmp2(struct timeval *tv1, struct timeval *tv2) {
    if (tv_iseternity(tv1))
	if (tv_iseternity(tv2))
	    return 0; /* same */
	else
	    return 1; /* tv1 later than tv2 */
    else if (tv_iseternity(tv2))
	return -1; /* tv2 later than tv1 */
    
    if (tv1->tv_sec > tv2->tv_sec)
	return 1;
    else if (tv1->tv_sec < tv2->tv_sec)
	return -1;
    else if (tv1->tv_usec > tv2->tv_usec)
	return 1;
    else if (tv1->tv_usec < tv2->tv_usec)
	return -1;
    else
	return 0;
}

/*
 * compares <tv1> and <tv2> modulo 1 ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2,
 * considering that 0 is the eternity.
 */
static inline int tv_cmp2_ms(struct timeval *tv1, struct timeval *tv2) {
    if (tv_iseternity(tv1))
	if (tv_iseternity(tv2))
	    return 0; /* same */
	else
	    return 1; /* tv1 later than tv2 */
    else if (tv_iseternity(tv2))
	return -1; /* tv2 later than tv1 */
    
    if (tv1->tv_sec == tv2->tv_sec) {
	if (tv1->tv_usec > tv2->tv_usec + 1000)
	    return 1;
	else if (tv2->tv_usec > tv1->tv_usec + 1000)
	    return -1;
	else
	    return 0;
    }
    else if ((tv1->tv_sec > tv2->tv_sec + 1) ||
	     ((tv1->tv_sec == tv2->tv_sec + 1) && (tv1->tv_usec + 1000000 > tv2->tv_usec + 1000)))
	return 1;
    else if ((tv2->tv_sec > tv1->tv_sec + 1) ||
	     ((tv2->tv_sec == tv1->tv_sec + 1) && (tv2->tv_usec + 1000000 > tv1->tv_usec + 1000)))
	return -1;
    else
	return 0;
}

/*
 * returns the first event between tv1 and tv2 into tvmin.
 * a zero tv is ignored. tvmin is returned.
 */
static inline struct timeval *tv_min(struct timeval *tvmin,
				     struct timeval *tv1, struct timeval *tv2) {

    if (tv_cmp2(tv1, tv2) <= 0)
	*tvmin = *tv1;
    else
	*tvmin = *tv2;

    return tvmin;
}



/***********************************************************/
/*   fd management   ***************************************/
/***********************************************************/



/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
static inline void fd_delete(int fd) {
    FD_CLR(fd, StaticReadEvent);
    FD_CLR(fd, StaticWriteEvent);
    close(fd);
    fdtab[fd].state = FD_STCLOSE;

    while ((maxfd-1 >= 0) && (fdtab[maxfd-1].state == FD_STCLOSE))
	    maxfd--;
}

/* recomputes the maxfd limit from the fd */
static inline void fd_insert(int fd) {
    if (fd+1 > maxfd)
	maxfd = fd+1;
}

/*************************************************************/
/*   task management   ***************************************/
/*************************************************************/

/* puts the task <t> in run queue <q>, and returns <t> */
static inline struct task *task_wakeup(struct task **q, struct task *t) {
    if (t->state == TASK_RUNNING)
	return t;
    else {
	t->rqnext = *q;
	t->state = TASK_RUNNING;
	return *q = t;
    }
}

/* removes the task <t> from the queue <q>
 * <s> MUST be <q>'s first task.
 * set the run queue to point to the next one, and return it
 */
static inline struct task *task_sleep(struct task **q, struct task *t) {
    if (t->state == TASK_RUNNING) {
	*q = t->rqnext;
	t->state = TASK_IDLE; /* tell that s has left the run queue */
    }
    return *q; /* return next running task */
}

/*
 * removes the task <t> from its wait queue. It must have already been removed
 * from the run queue. A pointer to the task itself is returned.
 */
static inline struct task *task_delete(struct task *t) {
    t->prev->next = t->next;
    t->next->prev = t->prev;
    return t;
}

/*
 * frees a task. Its context must have been freed since it will be lost.
 */
static inline void task_free(struct task *t) {
    pool_free(task, t);
}

/* inserts <task> into its assigned wait queue, where it may already be. In this case, it
 * may be only moved or left where it was, depending on its timing requirements.
 * <task> is returned.
 */
struct task *task_queue(struct task *task) {
    struct task *list = task->wq;
    struct task *start_from;

    /* first, test if the task was already in a list */
    if (task->prev == NULL) {
	//	start_from = list;
	start_from = list->prev;
	stats_tsk_new++;

	/* insert the unlinked <task> into the list, searching back from the last entry */
	while (start_from != list && tv_cmp2(&task->expire, &start_from->expire) < 0) {
	    start_from = start_from->prev;
	    stats_tsk_nsrch++;
	}
	
	//	  while (start_from->next != list && tv_cmp2(&task->expire, &start_from->next->expire) > 0) {
	//	      start_from = start_from->next;
	//	      stats_tsk_nsrch++;
	//	  }
    }	
    else if (task->prev == list ||
	     tv_cmp2(&task->expire, &task->prev->expire) >= 0) { /* walk right */
	start_from = task->next;
	if (start_from == list || tv_cmp2(&task->expire, &start_from->expire) <= 0) {
	    stats_tsk_good++;
	    return task; /* it's already in the right place */
	}

	stats_tsk_right++;
	/* insert the unlinked <task> into the list, searching after position <start_from> */
	while (start_from->next != list && tv_cmp2(&task->expire, &start_from->next->expire) > 0) {
	    start_from = start_from->next;
	    stats_tsk_rsrch++;
	}
	/* we need to unlink it now */
	task_delete(task);
    }
    else { /* walk left. */
	stats_tsk_left++;
#ifdef LEFT_TO_TOP	/* not very good */
	start_from = list;
	while (start_from->next != list && tv_cmp2(&task->expire, &start_from->next->expire) > 0) {
	    start_from = start_from->next;
	    stats_tsk_lsrch++;
	}
#else
	start_from = task->prev->prev; /* valid because of the previous test above */
	while (start_from != list && tv_cmp2(&task->expire, &start_from->expire) < 0) {
	    start_from = start_from->prev;
	    stats_tsk_lsrch++;
	}
#endif
	/* we need to unlink it now */
	task_delete(task);
    }
    task->prev = start_from;
    task->next = start_from->next;
    task->next->prev = task;
    start_from->next = task;
    return task;
}


/*********************************************************************/
/*   more specific functions   ***************************************/
/*********************************************************************/

/* some prototypes */
static int maintain_proxies(void);

/* this either returns the sockname or the original destination address. Code
 * inspired from Patrick Schaaf's example of nf_getsockname() implementation.
 */
static int get_original_dst(int fd, struct sockaddr_in *sa, int *salen) {
#if defined(TRANSPARENT) && defined(SO_ORIGINAL_DST)
    return getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, (void *)sa, salen);
#else
#if defined(TRANSPARENT) && defined(USE_GETSOCKNAME)
    return getsockname(fd, (struct sockaddr *)sa, salen);
#else
    return -1;
#endif
#endif
}

/*
 * frees  the context associated to a session. It must have been removed first.
 */
static inline void session_free(struct session *s) {
    if (s->req)
	pool_free(buffer, s->req);
    if (s->rep)
	pool_free(buffer, s->rep);
    pool_free(session, s);
}


/*
 * This function initiates a connection to the current server (s->srv) if (s->direct)
 * is set, or to the dispatch server if (s->direct) is 0. It returns 0 if
 * it's OK, -1 if it's impossible.
 */
int connect_server(struct session *s) {
    int one = 1;
    int fd;

    //    fprintf(stderr,"connect_server : s=%p\n",s);

    if (s->flags & TF_DIRECT) { /* srv cannot be null */
	s->srv_addr = s->srv->addr;
    }
    else if (s->proxy->options & PR_O_BALANCE) {
	if (s->proxy->options & PR_O_BALANCE_RR) {
	    int retry = s->proxy->nbservers;
	    while (retry) {
		if (s->proxy->cursrv == NULL)
		    s->proxy->cursrv = s->proxy->srv;
		if (s->proxy->cursrv->state & SRV_RUNNING)
		    break;
		s->proxy->cursrv = s->proxy->cursrv->next;
		retry--;
	    }

	    if (retry == 0) /* no server left */
		return -1;

	    s->srv = s->proxy->cursrv;
	    s->srv_addr = s->srv->addr;
	    s->proxy->cursrv = s->proxy->cursrv->next;
	}
	else /* unknown balancing algorithm */
	    return -1;
    }
    else if (*(int *)&s->proxy->dispatch_addr) {
	/* connect to the defined dispatch addr */
	s->srv_addr = s->proxy->dispatch_addr;
    }
    else if (s->proxy->options & PR_O_TRANSP) {
	/* in transparent mode, use the original dest addr if no dispatch specified */
	int salen = sizeof(struct sockaddr_in);
	if (get_original_dst(s->cli_fd, &s->srv_addr, &salen) == -1) {
	    qfprintf(stderr, "Cannot get original server address.\n");
	    return -1;
	}
    }

    if ((fd = s->srv_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	qfprintf(stderr, "Cannot get a server socket.\n");
	return -1;
    }
	
    if (fd >= cfg_maxsock) {
	Alert("socket(): not enough free sockets. Raise -n argument. Giving up.\n");
	close(fd);
	return -1;
    }

    if ((fcntl(fd, F_SETFL, O_NONBLOCK)==-1) ||
	(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) == -1)) {
	qfprintf(stderr,"Cannot set client socket to non blocking mode.\n");
	close(fd);
	return -1;
    }

    if ((connect(fd, (struct sockaddr *)&s->srv_addr, sizeof(s->srv_addr)) == -1) && (errno != EINPROGRESS)) {
	if (errno == EAGAIN) { /* no free ports left, try again later */
	    qfprintf(stderr,"Cannot connect, no free ports.\n");
	    close(fd);
	    return -1;
	}
	else if (errno != EALREADY && errno != EISCONN) {
	    close(fd);
	    return -1;
	}
    }

    fdtab[fd].owner = s->task;
    fdtab[fd].read  = &event_srv_read;
    fdtab[fd].write = &event_srv_write;
    fdtab[fd].state = FD_STCONN; /* connection in progress */
    
    FD_SET(fd, StaticWriteEvent);  /* for connect status */
    
    fd_insert(fd);

    if (s->proxy->contimeout)
	tv_delayfrom(&s->cnexpire, &now, s->proxy->contimeout);
    else
	tv_eternity(&s->cnexpire);
    return 0;
}
    
/*
 * this function is called on a read event from a client socket.
 * It returns 0.
 */
int event_cli_read(int fd) {
    struct task *t = fdtab[fd].owner;
    struct session *s = t->context;
    struct buffer *b = s->req;
    int ret, max;

    //    fprintf(stderr,"event_cli_read : fd=%d, s=%p\n", fd, s);

    if (fdtab[fd].state != FD_STERROR) {
	while (1) {
	    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
		b->r = b->w = b->h = b->lr  = b->data;
		max = b->rlim - b->data;
	    }
	    else if (b->r > b->w) {
		max = b->rlim - b->r;
	    }
	    else {
		max = b->w - b->r;
		/* FIXME: theorically, if w>0, we shouldn't have rlim < data+size anymore
		 * since it means that the rewrite protection has been removed. This
		 * implies that the if statement can be removed.
		 */
		if (max > b->rlim - b->data)
		    max = b->rlim - b->data;
	    }
	    
	    if (max == 0) {  /* not anymore room to store data */
		FD_CLR(fd, StaticReadEvent);
		break;
	    }
	    
#ifndef MSG_NOSIGNAL
	    {
		int skerr, lskerr;
		
		lskerr = sizeof(skerr);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
		if (skerr)
		    ret = -1;
		else
		    ret = recv(fd, b->r, max, 0);
	    }
#else
	    ret = recv(fd, b->r, max, MSG_NOSIGNAL);
#endif
	    if (ret > 0) {
		b->r += ret;
		b->l += ret;
		s->res_cr = RES_DATA;
		
		if (b->r == b->data + BUFSIZE) {
		    b->r = b->data; /* wrap around the buffer */
		}
		/* we hope to read more data or to get a close on next round */
		continue;
	    }
	    else if (ret == 0) {
		s->res_cr = RES_NULL;
		break;
	    }
	    else if (errno == EAGAIN) {/* ignore EAGAIN */
		break;
	    }
	    else {
		s->res_cr = RES_ERROR;
		fdtab[fd].state = FD_STERROR;
		break;
	    }
	} /* while(1) */
    }
    else {
	s->res_cr = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }

    if (s->res_cr != RES_SILENT) {
	if (s->proxy->clitimeout)
	    tv_delayfrom(&s->crexpire, &now, s->proxy->clitimeout);
	else
	    tv_eternity(&s->crexpire);
	
	task_wakeup(&rq, t);
    }

    return 0;
}


/*
 * this function is called on a read event from a server socket.
 * It returns 0.
 */
int event_srv_read(int fd) {
    struct task *t = fdtab[fd].owner;
    struct session *s = t->context;
    struct buffer *b = s->rep;
    int ret, max;

    //    fprintf(stderr,"event_srv_read : fd=%d, s=%p\n", fd, s);

    if (fdtab[fd].state != FD_STERROR) {
	while (1) {
	    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
		b->r = b->w = b->h = b->lr  = b->data;
		max = b->rlim - b->data;
	    }
	    else if (b->r > b->w) {
		max = b->rlim - b->r;
	    }
	    else {
		max = b->w - b->r;
		/* FIXME: theorically, if w>0, we shouldn't have rlim < data+size anymore
		 * since it means that the rewrite protection has been removed. This
		 * implies that the if statement can be removed.
		 */
		if (max > b->rlim - b->data)
		    max = b->rlim - b->data;
	    }
	    
	    if (max == 0) {  /* not anymore room to store data */
		FD_CLR(fd, StaticReadEvent);
		break;
	    }

#ifndef MSG_NOSIGNAL
	    {
		int skerr, lskerr;

		lskerr = sizeof(skerr);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
		if (skerr)
		    ret = -1;
		else
		    ret = recv(fd, b->r, max, 0);
	    }
#else
	    ret = recv(fd, b->r, max, MSG_NOSIGNAL);
#endif
	    if (ret > 0) {
		b->r += ret;
		b->l += ret;
		s->res_sr = RES_DATA;
	    
		if (b->r == b->data + BUFSIZE) {
		    b->r = b->data; /* wrap around the buffer */
		}
		/* we hope to read more data or to get a close on next round */
		continue;
	    }
	    else if (ret == 0) {
		s->res_sr = RES_NULL;
		break;
	    }
	    else if (errno == EAGAIN) {/* ignore EAGAIN */
		break;
	    }
	    else {
		s->res_sr = RES_ERROR;
		fdtab[fd].state = FD_STERROR;
		break;
	    }
	} /* while(1) */
    }
    else {
	s->res_sr = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }

    if (s->res_sr != RES_SILENT) {
	if (s->proxy->srvtimeout)
	    tv_delayfrom(&s->srexpire, &now, s->proxy->srvtimeout);
	else
	    tv_eternity(&s->srexpire);
	
	task_wakeup(&rq, t);
    }

    return 0;
}

/*
 * this function is called on a write event from a client socket.
 * It returns 0.
 */
int event_cli_write(int fd) {
    struct task *t = fdtab[fd].owner;
    struct session *s = t->context;
    struct buffer *b = s->rep;
    int ret, max;

    //    fprintf(stderr,"event_cli_write : fd=%d, s=%p\n", fd, s);

    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
	b->r = b->w = b->h = b->lr  = b->data;
	//	max = BUFSIZE;		BUG !!!!
	max = 0;
    }
    else if (b->r > b->w) {
	max = b->r - b->w;
    }
    else
	max = b->data + BUFSIZE - b->w;
    
    if (fdtab[fd].state != FD_STERROR) {
#ifndef MSG_NOSIGNAL
	int skerr, lskerr;
#endif

	if (max == 0) {
	    s->res_cw = RES_NULL;
	    task_wakeup(&rq, t);
	    return 0;
	}

#ifndef MSG_NOSIGNAL
	lskerr=sizeof(skerr);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
	if (skerr)
		ret = -1;
	else
		ret = send(fd, b->w, max, MSG_DONTWAIT);
#else
	ret = send(fd, b->w, max, MSG_DONTWAIT | MSG_NOSIGNAL);
#endif

	if (ret > 0) {
	    b->l -= ret;
	    b->w += ret;
	    
	    s->res_cw = RES_DATA;
	    
	    if (b->w == b->data + BUFSIZE) {
		b->w = b->data; /* wrap around the buffer */
	    }
	}
	else if (ret == 0) {
	    /* nothing written, just make as if we were never called */
//	    s->res_cw = RES_NULL;
	    return 0;
	}
	else if (errno == EAGAIN) /* ignore EAGAIN */
	    return 0;
	else {
	    s->res_cw = RES_ERROR;
	    fdtab[fd].state = FD_STERROR;
	}
    }
    else {
	s->res_cw = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }

    if (s->proxy->clitimeout)
	tv_delayfrom(&s->cwexpire, &now, s->proxy->clitimeout);
    else
	tv_eternity(&s->cwexpire);

    task_wakeup(&rq, t);
    return 0;
}


/*
 * this function is called on a write event from a server socket.
 * It returns 0.
 */
int event_srv_write(int fd) {
    struct task *t = fdtab[fd].owner;
    struct session *s = t->context;
    struct buffer *b = s->req;
    int ret, max;

    //fprintf(stderr,"event_srv_write : fd=%d, s=%p\n", fd, s);

    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
	b->r = b->w = b->h = b->lr = b->data;
	//	max = BUFSIZE;		BUG !!!!
	max = 0;
    }
    else if (b->r > b->w) {
	max = b->r - b->w;
    }
    else
	max = b->data + BUFSIZE - b->w;
    
    if (fdtab[fd].state != FD_STERROR) {
#ifndef MSG_NOSIGNAL
	int skerr, lskerr;
#endif
	if (max == 0) {
	    /* may be we have received a connection acknowledgement in TCP mode without data */
	    s->res_sw = RES_NULL;
	    task_wakeup(&rq, t);
	    fdtab[fd].state = FD_STREADY;
	    return 0;
	}


#ifndef MSG_NOSIGNAL
	lskerr=sizeof(skerr);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
	if (skerr)
		ret = -1;
	else
		ret = send(fd, b->w, max, MSG_DONTWAIT);
#else
	ret = send(fd, b->w, max, MSG_DONTWAIT | MSG_NOSIGNAL);
#endif
	fdtab[fd].state = FD_STREADY;
	if (ret > 0) {
	    b->l -= ret;
	    b->w += ret;
	    
	    s->res_sw = RES_DATA;
	    
	    if (b->w == b->data + BUFSIZE) {
		b->w = b->data; /* wrap around the buffer */
	    }
	}
	else if (ret == 0) {
	    /* nothing written, just make as if we were never called */
	    // s->res_sw = RES_NULL;
	    return 0;
	}
	else if (errno == EAGAIN) /* ignore EAGAIN */
	    return 0;
	else {
	    s->res_sw = RES_ERROR;
	    fdtab[fd].state = FD_STERROR;
	}
    }
    else {
	s->res_sw = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }

    if (s->proxy->srvtimeout)
	tv_delayfrom(&s->swexpire, &now, s->proxy->srvtimeout);
    else
	tv_eternity(&s->swexpire);

    task_wakeup(&rq, t);
    return 0;
}


/*
 * this function is called on a read event from a listen socket, corresponding
 * to an accept. It tries to accept as many connections as possible.
 * It returns 0.
 */
int event_accept(int fd) {
    struct proxy *p = (struct proxy *)fdtab[fd].owner;
    struct session *s;
    struct task *t;
    int cfd;
    int one = 1;

    while (p->nbconn < p->maxconn) {
	struct sockaddr_in addr;
	int laddr = sizeof(addr);
	if ((cfd = accept(fd, (struct sockaddr *)&addr, &laddr)) == -1)
	    return 0;	    /* nothing more to accept */

	if ((s = pool_alloc(session)) == NULL) { /* disable this proxy for a while */
	    Alert("out of memory in event_accept().\n");
	    FD_CLR(fd, StaticReadEvent);
	    p->state = PR_STIDLE;
	    close(cfd);
	    return 0;
	}

	if ((t = pool_alloc(task)) == NULL) { /* disable this proxy for a while */
	    Alert("out of memory in event_accept().\n");
	    FD_CLR(fd, StaticReadEvent);
	    p->state = PR_STIDLE;
	    close(cfd);
	    pool_free(session, s);
	    return 0;
	}

	s->cli_addr = addr;
	if (cfd >= cfg_maxsock) {
	    Alert("accept(): not enough free sockets. Raise -n argument. Giving up.\n");
	    close(cfd);
	    pool_free(task, t);
	    pool_free(session, s);
	    return 0;
	}

	if ((fcntl(cfd, F_SETFL, O_NONBLOCK) == -1) ||
	    (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY,
			(char *) &one, sizeof(one)) == -1)) {
	    Alert("accept(): cannot set the socket in non blocking mode. Giving up\n");
	    close(cfd);
	    pool_free(task, t);
	    pool_free(session, s);
	    return 0;
	}

	if ((p->mode == PR_MODE_TCP || p->mode == PR_MODE_HTTP)
	    && (p->logfac1 >= 0 || p->logfac2 >= 0)) {
	    struct sockaddr_in peername, sockname;
	    unsigned char *pn, *sn;
	    int namelen;
	    char message[256];

	    //namelen = sizeof(peername);
	    //getpeername(cfd, (struct sockaddr *)&peername, &namelen);
	    //pn = (unsigned char *)&peername.sin_addr;
	    pn = (unsigned char *)&s->cli_addr;

	    namelen = sizeof(sockname);
	    if (get_original_dst(cfd, (struct sockaddr_in *)&sockname, &namelen) == -1)
		getsockname(cfd, (struct sockaddr *)&sockname, &namelen);
	    sn = (unsigned char *)&sockname.sin_addr;

	    sprintf(message, "Connect from %d.%d.%d.%d:%d to %d.%d.%d.%d:%d (%s/%s)\n",
		    pn[0], pn[1], pn[2], pn[3], ntohs(peername.sin_port),
		    sn[0], sn[1], sn[2], sn[3], ntohs(sockname.sin_port),
		    p->id, (p->mode == PR_MODE_HTTP) ? "HTTP" : "TCP");

	    if (p->logfac1 >= 0)
		send_syslog(&p->logsrv1, p->logfac1, LOG_INFO, message);
	    if (p->logfac2 >= 0)
		send_syslog(&p->logsrv2, p->logfac2, LOG_INFO, message);
	}

	if ((mode & MODE_DEBUG) && !(mode & MODE_QUIET)) {
	    int len;
	    len = sprintf(trash, "accept(%04x)=%04x\n", (unsigned short)fd, (unsigned short)cfd);
	    write(1, trash, len);
	}

	t->next = t->prev = t->rqnext = NULL; /* task not in run queue yet */
	t->wq = LIST_HEAD(wait_queue); /* but already has a wait queue assigned */
	t->state = TASK_IDLE;
	t->process = process_session;
	t->context = s;

	s->task = t;
	s->proxy = p;
	s->cli_state = (p->mode == PR_MODE_HTTP) ?  CL_STHEADERS : CL_STDATA; /* no HTTP headers for non-HTTP proxies */
	s->srv_state = SV_STIDLE;
	s->req = s->rep = NULL; /* will be allocated later */
	s->flags = 0;
	s->res_cr = s->res_cw = s->res_sr = s->res_sw = RES_SILENT;
	s->cli_fd = cfd;
	s->srv_fd = -1;
	s->conn_retries = p->conn_retries;

	if ((s->req = pool_alloc(buffer)) == NULL) { /* no memory */
	    close(cfd); /* nothing can be done for this fd without memory */
	    pool_free(task, t);
	    pool_free(session, s);
	    return 0;
	}
	s->req->l = 0;
	s->req->h = s->req->r = s->req->lr = s->req->w = s->req->data;	/* r and w will be reset further */
	s->req->rlim = s->req->data + BUFSIZE;
	if (s->cli_state == CL_STHEADERS) /* reserver some space for header rewriting */
	    s->req->rlim -= MAXREWRITE;

	if ((s->rep = pool_alloc(buffer)) == NULL) { /* no memory */
	    pool_free(buffer, s->req);
	    close(cfd); /* nothing can be done for this fd without memory */
	    pool_free(task, t);
	    pool_free(session, s);
	    return 0;
	}
	s->rep->l = 0;
	s->rep->h = s->rep->r = s->rep->lr = s->rep->w = s->rep->rlim = s->rep->data;

	fdtab[cfd].read  = &event_cli_read;
	fdtab[cfd].write = &event_cli_write;
	fdtab[cfd].owner = t;
	fdtab[cfd].state = FD_STREADY;

	if (p->mode == PR_MODE_HEALTH) {  /* health check mode, no client reading */
	    FD_CLR(cfd, StaticReadEvent);
	    FD_SET(cfd, StaticWriteEvent);
	    tv_eternity(&s->crexpire);
	    shutdown(s->cli_fd, SHUT_RD);
	    s->cli_state = CL_STSHUTR;

	    strcpy(s->rep->data, "OK\n"); /* forge an "OK" response */
	    s->rep->l = 3;
	    s->rep->r += 3;
	}
	else {
	    FD_SET(cfd, StaticReadEvent);
	}

	fd_insert(cfd);

	tv_eternity(&s->cnexpire);
	tv_eternity(&s->srexpire);
	tv_eternity(&s->swexpire);
	tv_eternity(&s->cwexpire);

	if (s->proxy->clitimeout)
	    tv_delayfrom(&s->crexpire, &now, s->proxy->clitimeout);
	else
	    tv_eternity(&s->crexpire);

	t->expire = s->crexpire;

	task_queue(t);

	if (p->mode != PR_MODE_HEALTH)
	    task_wakeup(&rq, t);

	p->nbconn++;
	actconn++;
	totalconn++;

	// fprintf(stderr, "accepting from %p => %d conn, %d total\n", p, actconn, totalconn);
    } /* end of while (p->nbconn < p->maxconn) */
    return 0;
}


/*
 * This function is used only for server health-checks. It handles
 * the connection acknowledgement and returns 1 if the socket is OK,
 * or -1 if an error occured.
 */
int event_srv_hck(int fd) {
    struct task *t = fdtab[fd].owner;
    struct server *s = t->context;

    int skerr, lskerr;
    lskerr = sizeof(skerr);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
    if (skerr)
	s->result = -1;
    else
	s->result = 1;

    task_wakeup(&rq, t);
    return 0;
}


/*
 * this function writes the string <str> at position <pos> which must be in buffer <b>,
 * and moves <end> just after the end of <str>.
 * <b>'s parameters (l, r, w, h, lr) are recomputed to be valid after the shift.
 * the shift value (positive or negative) is returned.
 * If there's no space left, the move is not done.
 *
 */
int buffer_replace(struct buffer *b, char *pos, char *end, char *str) {
    int delta;
    int len;

    len = strlen(str);
    delta = len - (end - pos);

    if (delta + b->r >= b->data + BUFSIZE)
	return 0;  /* no space left */

    /* first, protect the end of the buffer */
    memmove(end + delta, end, b->data + b->l - end);

    /* now, copy str over pos */
    memcpy(pos, str,len);

    /* we only move data after the displaced zone */
    if (b->r  > pos) b->r  += delta;
    if (b->w  > pos) b->w  += delta;
    if (b->h  > pos) b->h  += delta;
    if (b->lr > pos) b->lr += delta;
    b->l += delta;

    return delta;
}

/* same except that the string len is given */
int buffer_replace2(struct buffer *b, char *pos, char *end, char *str, int len) {
    int delta;

    delta = len - (end - pos);

    if (delta + b->r >= b->data + BUFSIZE)
	return 0;  /* no space left */

    /* first, protect the end of the buffer */
    memmove(end + delta, end, b->data + b->l - end);

    /* now, copy str over pos */
    memcpy(pos, str,len);

    /* we only move data after the displaced zone */
    if (b->r  > pos) b->r  += delta;
    if (b->w  > pos) b->w  += delta;
    if (b->h  > pos) b->h  += delta;
    if (b->lr > pos) b->lr += delta;
    b->l += delta;

    return delta;
}


int exp_replace(char *dst, char *src, char *str, regmatch_t *matches) {
    char *old_dst = dst;

    while (*str) {
	if (*str == '\\') {
	    str++;
	    if (isdigit(*str)) {
		int len, num;

		num = *str - '0';
		str++;

		if (matches[num].rm_so > -1) {
		    len = matches[num].rm_eo - matches[num].rm_so;
		    memcpy(dst, src + matches[num].rm_so, len);
		    dst += len;
		}
		
	    }
	    else if (*str == 'x') {
		unsigned char hex1, hex2;
		str++;

		hex1=toupper(*str++) - '0'; hex2=toupper(*str++) - '0';

		if (hex1 > 9) hex1 -= 'A' - '9' - 1;
		if (hex2 > 9) hex2 -= 'A' - '9' - 1;
		*dst++ = (hex1<<4) + hex2;
	    }
	    else
		*dst++ = *str++;
	}
	else
	    *dst++ = *str++;
    }
    *dst = 0;
    return dst - old_dst;
}

/*
 * manages the client FSM and its socket. BTW, it also tries to handle the
 * cookie. It returns 1 if a state has changed (and a resync may be needed),
 * 0 else.
 */
int process_cli(struct session *t) {
    int s = t->srv_state;
    int c = t->cli_state;
    struct buffer *req = t->req;
    struct buffer *rep = t->rep;

    //fprintf(stderr,"process_cli: c=%d, s=%d, cr=%d, cw=%d, sr=%d, sw=%d\n", c, s,
    //FD_ISSET(t->cli_fd, StaticReadEvent), FD_ISSET(t->cli_fd, StaticWriteEvent),
    //FD_ISSET(t->srv_fd, StaticReadEvent), FD_ISSET(t->srv_fd, StaticWriteEvent)
    //);
    if (c == CL_STHEADERS) {
	/* now parse the partial (or complete) headers */
	while (req->lr < req->r) { /* this loop only sees one header at each iteration */
	    char *ptr;
	    int delete_header;
	
	    ptr = req->lr;

	    /* look for the end of the current header */
	    while (ptr < req->r && *ptr != '\n' && *ptr != '\r')
		ptr++;
	    
	    if (ptr == req->h) { /* empty line, end of headers */
		char newhdr[MAXREWRITE + 1];
		int line, len;
		/* we can only get here after an end of headers */
		/* we'll have something else to do here : add new headers ... */

		for (line = 0; line < t->proxy->nb_reqadd; line++) {
		    len = sprintf(newhdr, "%s\r\n", t->proxy->req_add[line]);
		    buffer_replace2(req, req->h, req->h, newhdr, len);
		}

		t->cli_state = CL_STDATA;
		req->rlim = req->data + BUFSIZE; /* no more rewrite needed */

		/* FIXME: we'll set the client in a wait state while we try to
		 * connect to the server. Is this really needed ? wouldn't it be
		 * better to release the maximum of system buffers instead ? */
		//FD_CLR(t->cli_fd, StaticReadEvent);
		//tv_eternity(&t->crexpire);
		break;
	    }

	    /* to get a complete header line, we need the ending \r\n, \n\r, \r or \n too */
	    if (ptr > req->r - 2) {
		/* this is a partial header, let's wait for more to come */
		req->lr = ptr;
		break;
	    }

	    /* now we know that *ptr is either \r or \n,
	     * and that there are at least 1 char after it.
	     */
	    if ((ptr[0] == ptr[1]) || (ptr[1] != '\r' && ptr[1] != '\n'))
		req->lr = ptr + 1; /* \r\r, \n\n, \r[^\n], \n[^\r] */
	    else
		req->lr = ptr + 2; /* \r\n or \n\r */

	    /*
	     * now we know that we have a full header ; we can do whatever
	     * we want with these pointers :
	     *   req->h  = beginning of header
	     *   ptr     = end of header (first \r or \n)
	     *   req->lr = beginning of next line (next rep->h)
	     *   req->r  = end of data (not used at this stage)
	     */

	    delete_header = 0;

	    if ((mode & MODE_DEBUG) && !(mode & MODE_QUIET)) {
		int len, max;
		len = sprintf(trash, "clihdr[%04x:%04x]: ", (unsigned  short)t->cli_fd, (unsigned short)t->srv_fd);
		max = ptr - req->h;
		UBOUND(max, sizeof(trash) - len - 1);
		len += strlcpy(trash + len, req->h, max + 1);
		trash[len++] = '\n';
		write(1, trash, len);
	    }

	    /* try headers regexps */
	    if (t->proxy->nb_reqexp) {
		struct proxy *p = t->proxy;
		int exp;
		char term;
		
		term = *ptr;
		*ptr = '\0';
		for (exp=0; exp < p->nb_reqexp; exp++) {
		    if (regexec(p->req_exp[exp].preg, req->h, MAX_MATCH, pmatch, 0) == 0) {
			if (p->req_exp[exp].replace != NULL) {
			    int len = exp_replace(trash, req->h, p->req_exp[exp].replace, pmatch);
			    ptr += buffer_replace2(req, req->h, ptr, trash, len);
			}
			else {
			    delete_header = 1;
			}
			break;
		    }
		}
		*ptr = term; /* restore the string terminator */
	    }
	    
	    /* now look for cookies */
	    if (!delete_header && (req->r >= req->h + 8) && (t->proxy->cookie_name != NULL)
		&& (strncmp(req->h, "Cookie: ", 8) == 0)) {
		char *p1, *p2, *p3, *p4;
		
		p1 = req->h + 8; /* first char after 'Cookie: ' */
		
		while (p1 < ptr) {
		    while (p1 < ptr && (isspace(*p1) || *p1 == ';'))
			p1++;
		    
		    if (p1 == ptr)
			break;
		    else if (*p1 == ';') { /* next cookie */
			++p1;
			continue;
		    }
		    
		    /* p1 is at the beginning of the cookie name */
		    p2 = p1;
		    
		    while (p2 < ptr && *p2 != '=' && *p2 != ';')
			p2++;
		    
		    if (p2 == ptr)
			break;
		    else if (*p2 == ';') { /* next cookie */
			p1=++p2;
			continue;
		    }

		    p3 = p2 + 1; /* skips the '=' sign */
		    if (p3 == ptr)
			break;
		    
		    p4=p3;
		    while (p4 < ptr && !isspace(*p4) && *p4 != ';')
			p4++;
		    
		    /* here, we have the cookie name between p1 and p2,
		     * and its value between p3 and p4.
		     * we can process it.
		     */
		    
		    if ((p2 - p1 == strlen(t->proxy->cookie_name)) &&
			(strncmp(p1, t->proxy->cookie_name, p2 - p1) == 0)) {
			/* Cool... it's the right one */
			struct server *srv = t->proxy->srv;

			while (srv &&
			       ((srv->cklen != p4 - p3) || memcmp(p3, srv->cookie, p4 - p3))) {
			    srv = srv->next;
			}

			if (srv) { /* we found the server */
			    t->flags |= TF_DIRECT;
			    t->srv = srv;
			}

			break;
		    }
		    else {
			// fprintf(stderr,"Ignoring unknown cookie : ");
			// write(2, p1, p2-p1);
			// fprintf(stderr," = ");
			// write(2, p3, p4-p3);
			// fprintf(stderr,"\n");
		    }
		    /* we'll have to look for another cookie ... */
		    p1 = p4;
		} /* while (p1 < ptr) */
	    } /* end of cookie processing */

	    /* let's look if we have to delete this header */
	    if (delete_header) {
		buffer_replace2(req, req->h, req->lr, "", 0);
	    }
	    req->h = req->lr;
	} /* while (req->lr < req->r) */

	/* end of header processing (even if incomplete) */


	if ((req->l < req->rlim - req->data) && ! FD_ISSET(t->cli_fd, StaticReadEvent)) {
	    /* fd in StaticReadEvent was disabled, perhaps because of a previous buffer
	     * full. We cannot loop here since event_cli_read will disable it only if
	     * req->l == rlim-data
	     */
	    FD_SET(t->cli_fd, StaticReadEvent);
	    if (t->proxy->clitimeout)
		tv_delayfrom(&t->crexpire, &now, t->proxy->clitimeout);
	    else
		tv_eternity(&t->crexpire);
	}

	/* read timeout, read error, or last read : give up.
	 * since we are in header mode, if there's no space left for headers, we
	 * won't be able to free more later, so the session will never terminate.
	 */
	if (t->res_cr == RES_ERROR || t->res_cr == RES_NULL
	    || req->l >= req->rlim - req->data || tv_cmp2_ms(&t->crexpire, &now) <= 0) {
	    tv_eternity(&t->crexpire);
	    fd_delete(t->cli_fd);
	    t->cli_state = CL_STCLOSE;
	    return 1;
	}

	return t->cli_state != CL_STHEADERS;
    }
    else if (c == CL_STDATA) {
	/* read or write error */
	if (t->res_cw == RES_ERROR || t->res_cr == RES_ERROR) {
	    tv_eternity(&t->crexpire);
	    tv_eternity(&t->cwexpire);
	    fd_delete(t->cli_fd);
	    t->cli_state = CL_STCLOSE;
	    return 1;
	}
	/* read timeout, last read, or end of server write */
	else if (t->res_cr == RES_NULL || s == SV_STSHUTW || s == SV_STCLOSE
		 || tv_cmp2_ms(&t->crexpire, &now) <= 0) {
	    FD_CLR(t->cli_fd, StaticReadEvent);
	    //	    if (req->l == 0) /* nothing to write on the server side */
	    //		FD_CLR(t->srv_fd, StaticWriteEvent);
	    tv_eternity(&t->crexpire);
	    shutdown(t->cli_fd, SHUT_RD);
	    t->cli_state = CL_STSHUTR;
	    return 1;
	}	
	/* write timeout, or last server read and buffer empty */
	else if (((s == SV_STSHUTR || s == SV_STCLOSE) && (rep->l == 0))
		 ||(tv_cmp2_ms(&t->cwexpire, &now) <= 0)) {
	    FD_CLR(t->cli_fd, StaticWriteEvent);
	    tv_eternity(&t->cwexpire);
	    shutdown(t->cli_fd, SHUT_WR);
	    t->cli_state = CL_STSHUTW;
	    return 1;
	}

	if (req->l >= req->rlim - req->data) {
	    /* no room to read more data */
	    if (FD_ISSET(t->cli_fd, StaticReadEvent)) {
		/* stop reading until we get some space */
		FD_CLR(t->cli_fd, StaticReadEvent);
		tv_eternity(&t->crexpire);
	    }
	}
	else {
	    /* there's still some space in the buffer */
	    if (! FD_ISSET(t->cli_fd, StaticReadEvent)) {
		FD_SET(t->cli_fd, StaticReadEvent);
		if (t->proxy->clitimeout)
		    tv_delayfrom(&t->crexpire, &now, t->proxy->clitimeout);
		else
		    tv_eternity(&t->crexpire);
	    }
	}

	if ((rep->l == 0) ||
	    ((s == SV_STHEADERS) /* FIXME: this may be optimized && (rep->w == rep->h)*/)) {
	    if (FD_ISSET(t->cli_fd, StaticWriteEvent)) {
		FD_CLR(t->cli_fd, StaticWriteEvent); /* stop writing */
		tv_eternity(&t->cwexpire);
	    }
	}
	else { /* buffer not empty */
	    if (! FD_ISSET(t->cli_fd, StaticWriteEvent)) {
		FD_SET(t->cli_fd, StaticWriteEvent); /* restart writing */
		if (t->proxy->clitimeout)
		    tv_delayfrom(&t->cwexpire, &now, t->proxy->clitimeout);
		else
		    tv_eternity(&t->cwexpire);
	    }
	}
	return 0; /* other cases change nothing */
    }
    else if (c == CL_STSHUTR) {
	if ((t->res_cw == RES_ERROR) ||
	    ((s == SV_STSHUTR || s == SV_STCLOSE) && (rep->l == 0))
	    || (tv_cmp2_ms(&t->cwexpire, &now) <= 0)) {
	    tv_eternity(&t->cwexpire);
	    fd_delete(t->cli_fd);
	    t->cli_state = CL_STCLOSE;
	    return 1;
	}
	else if ((rep->l == 0) ||
		 ((s == SV_STHEADERS) /* FIXME: this may be optimized && (rep->w == rep->h)*/)) {
	    if (FD_ISSET(t->cli_fd, StaticWriteEvent)) {
		FD_CLR(t->cli_fd, StaticWriteEvent); /* stop writing */
		tv_eternity(&t->cwexpire);
	    }
	}
	else { /* buffer not empty */
	    if (! FD_ISSET(t->cli_fd, StaticWriteEvent)) {
		FD_SET(t->cli_fd, StaticWriteEvent); /* restart writing */
		if (t->proxy->clitimeout)
		    tv_delayfrom(&t->cwexpire, &now, t->proxy->clitimeout);
		else
		    tv_eternity(&t->cwexpire);
	    }
	}
	return 0;
    }
    else if (c == CL_STSHUTW) {
	if (t->res_cr == RES_ERROR || t->res_cr == RES_NULL || s == SV_STSHUTW ||
	    s == SV_STCLOSE || tv_cmp2_ms(&t->crexpire, &now) <= 0) {
	    tv_eternity(&t->crexpire);
	    fd_delete(t->cli_fd);
	    t->cli_state = CL_STCLOSE;
	    return 1;
	}
	else if (req->l >= req->rlim - req->data) {
	    /* no room to read more data */
	    if (FD_ISSET(t->cli_fd, StaticReadEvent)) {
		/* stop reading until we get some space */
		FD_CLR(t->cli_fd, StaticReadEvent);
		tv_eternity(&t->crexpire);
	    }
	}
	else {
	    /* there's still some space in the buffer */
	    if (! FD_ISSET(t->cli_fd, StaticReadEvent)) {
		FD_SET(t->cli_fd, StaticReadEvent);
		if (t->proxy->clitimeout)
		    tv_delayfrom(&t->crexpire, &now, t->proxy->clitimeout);
		else
		    tv_eternity(&t->crexpire);
	    }
	}
	return 0;
    }
    else { /* CL_STCLOSE: nothing to do */
	if ((mode & MODE_DEBUG) && !(mode & MODE_QUIET)) {
	    int len;
	    len = sprintf(trash, "clicls[%04x:%04x]\n", (unsigned short)t->cli_fd, (unsigned short)t->srv_fd);
	    write(1, trash, len);
	}
	return 0;
    }
    return 0;
}


/*
 * manages the server FSM and its socket. It returns 1 if a state has changed
 * (and a resync may be needed), 0 else.
 */
int process_srv(struct session *t) {
    int s = t->srv_state;
    int c = t->cli_state;
    struct buffer *req = t->req;
    struct buffer *rep = t->rep;

    //fprintf(stderr,"process_srv: c=%d, s=%d\n", c, s);
    //fprintf(stderr,"process_srv: c=%d, s=%d, cr=%d, cw=%d, sr=%d, sw=%d\n", c, s,
    //FD_ISSET(t->cli_fd, StaticReadEvent), FD_ISSET(t->cli_fd, StaticWriteEvent),
    //FD_ISSET(t->srv_fd, StaticReadEvent), FD_ISSET(t->srv_fd, StaticWriteEvent)
    //);
    if (s == SV_STIDLE) {
	if (c == CL_STHEADERS)
	    return 0;	/* stay in idle, waiting for data to reach the client side */
	else if (c == CL_STCLOSE ||
		 c == CL_STSHUTW ||
		 (c == CL_STSHUTR && t->req->l == 0)) { /* give up */
	    tv_eternity(&t->cnexpire);
	    t->srv_state = SV_STCLOSE;
	    return 1;
	}
	else { /* go to SV_STCONN */
	    if (connect_server(t) == 0) { /* initiate a connection to the server */
		//fprintf(stderr,"0: c=%d, s=%d\n", c, s);
		t->srv_state = SV_STCONN;
	    }
	    else { /* try again */
		while (t->conn_retries-- > 0) {
		    if ((t->proxy->options & PR_O_REDISP) && (t->conn_retries == 0)) {
			t->flags &= ~TF_DIRECT; /* ignore cookie and force to use the dispatcher */
			t->srv = NULL; /* it's left to the dispatcher to choose a server */
		    }

		    if (connect_server(t) == 0) {
			t->srv_state = SV_STCONN;
			break;
		    }
		}
		if (t->conn_retries < 0) {
		    /* if conn_retries < 0 or other error, let's abort */
		    tv_eternity(&t->cnexpire);
		    t->srv_state = SV_STCLOSE;
		}
	    }
	    return 1;
	}
    }
    else if (s == SV_STCONN) { /* connection in progress */
	if (t->res_sw == RES_SILENT && tv_cmp2_ms(&t->cnexpire, &now) > 0) {
	    //fprintf(stderr,"1: c=%d, s=%d\n", c, s);
	    return 0; /* nothing changed */
	}
	else if (t->res_sw == RES_SILENT || t->res_sw == RES_ERROR) {
	    //fprintf(stderr,"2: c=%d, s=%d\n", c, s);
	    /* timeout,  connect error or first write error */
	    //FD_CLR(t->srv_fd, StaticWriteEvent);
	    fd_delete(t->srv_fd);
	    //close(t->srv_fd);
	    t->conn_retries--;
	    if (t->conn_retries >= 0) {
		    if ((t->proxy->options & PR_O_REDISP) && (t->conn_retries == 0)) {
			t->flags &= ~TF_DIRECT; /* ignore cookie and force to use the dispatcher */
			t->srv = NULL; /* it's left to the dispatcher to choose a server */
		    }
		    if (connect_server(t) == 0)
			return 0; /* no state changed */
	    }
	    /* if conn_retries < 0 or other error, let's abort */
	    tv_eternity(&t->cnexpire);
	    t->srv_state = SV_STCLOSE;
	    return 1;
	}
	else { /* no error or write 0 */
	    //fprintf(stderr,"3: c=%d, s=%d\n", c, s);
	    if (req->l == 0) /* nothing to write */
		FD_CLR(t->srv_fd, StaticWriteEvent);
	    else  /* need the right to write */
		FD_SET(t->srv_fd, StaticWriteEvent);

	    if (t->proxy->mode == PR_MODE_TCP) { /* let's allow immediate data connection in this case */
		FD_SET(t->srv_fd, StaticReadEvent);
		if (t->proxy->srvtimeout)
		    tv_delayfrom(&t->srexpire, &now, t->proxy->srvtimeout);
		else
		    tv_eternity(&t->srexpire);
		
		t->srv_state = SV_STDATA;
		rep->rlim = rep->data + BUFSIZE; /* no rewrite needed */
	    }
	    else {
		t->srv_state = SV_STHEADERS;
		rep->rlim = rep->data + BUFSIZE - MAXREWRITE; /* rewrite needed */
	    }
	    tv_eternity(&t->cnexpire);
	    return 1;
	}
    }
    else if (s == SV_STHEADERS) { /* receiving server headers */

	/* now parse the partial (or complete) headers */
	while (rep->lr < rep->r) { /* this loop only sees one header at each iteration */
	    char *ptr;
	    int delete_header;

	    ptr = rep->lr;

	    /* look for the end of the current header */
	    while (ptr < rep->r && *ptr != '\n' && *ptr != '\r')
		ptr++;
	    
	    if (ptr == rep->h) {
		char newhdr[MAXREWRITE + 1];
		int line, len;

		/* we can only get here after an end of headers */
		/* we'll have something else to do here : add new headers ... */

		if ((t->srv) && !(t->flags & TF_DIRECT) && (t->proxy->options & PR_O_COOK_INS)) {
		    /* the server is known, it's not the one the client requested, we have to
		     * insert a set-cookie here.
		     */
		    len = sprintf(newhdr, "Set-Cookie: %s=%s; path=/\r\n",
				  t->proxy->cookie_name, t->srv->cookie);
		    buffer_replace2(rep, rep->h, rep->h, newhdr, len);
		}

		/* headers to be added */
		for (line = 0; line < t->proxy->nb_rspadd; line++) {
		    len = sprintf(newhdr, "%s\r\n", t->proxy->rsp_add[line]);
		    buffer_replace2(rep, rep->h, rep->h, newhdr, len);
		}

		t->srv_state = SV_STDATA;
		rep->rlim = rep->data + BUFSIZE; /* no more rewrite needed */
		break;
	    }

	    /* to get a complete header line, we need the ending \r\n, \n\r, \r or \n too */
	    if (ptr > rep->r - 2) {
		/* this is a partial header, let's wait for more to come */
		rep->lr = ptr;
		break;
	    }

	    //	    fprintf(stderr,"h=%p, ptr=%p, lr=%p, r=%p, *h=", rep->h, ptr, rep->lr, rep->r);
	    //	    write(2, rep->h, ptr - rep->h);   fprintf(stderr,"\n");

	    /* now we know that *ptr is either \r or \n,
	     * and that there are at least 1 char after it.
	     */
	    if ((ptr[0] == ptr[1]) || (ptr[1] != '\r' && ptr[1] != '\n'))
		rep->lr = ptr + 1; /* \r\r, \n\n, \r[^\n], \n[^\r] */
	    else
		rep->lr = ptr + 2; /* \r\n or \n\r */

	    /*
	     * now we know that we have a full header ; we can do whatever
	     * we want with these pointers :
	     *   rep->h  = beginning of header
	     *   ptr     = end of header (first \r or \n)
	     *   rep->lr = beginning of next line (next rep->h)
	     *   rep->r  = end of data (not used at this stage)
	     */

	    delete_header = 0;

	    if ((mode & MODE_DEBUG) && !(mode & MODE_QUIET)) {
		int len, max;
		len = sprintf(trash, "srvhdr[%04x:%04x]: ", (unsigned  short)t->cli_fd, (unsigned short)t->srv_fd);
		max = ptr - rep->h;
		UBOUND(max, sizeof(trash) - len - 1);
		len += strlcpy(trash + len, rep->h, max + 1);
		trash[len++] = '\n';
		write(1, trash, len);
	    }

	    /* try headers regexps */
	    if (t->proxy->nb_rspexp) {
		struct proxy *p = t->proxy;
		int exp;
		char term;
		
		term = *ptr;
		*ptr = '\0';
		for (exp=0; exp < p->nb_rspexp; exp++) {
		    if (regexec(p->rsp_exp[exp].preg, rep->h, MAX_MATCH, pmatch, 0) == 0) {
			if (p->rsp_exp[exp].replace != NULL) {
			    int len = exp_replace(trash, rep->h, p->rsp_exp[exp].replace, pmatch);
			    ptr += buffer_replace2(rep, rep->h, ptr, trash, len);
			}
			else {
			    delete_header = 1;
			}
			break;
		    }
		}
		*ptr = term; /* restore the string terminator */
	    }
	    
	    /* check for server cookies */
	    if (!delete_header && (t->proxy->options & PR_O_COOK_ANY) && (rep->r >= rep->h + 12) &&
		(t->proxy->cookie_name != NULL)	&& (strncmp(rep->h, "Set-Cookie: ", 12) == 0)) {
		char *p1, *p2, *p3, *p4;
		
		p1 = rep->h + 12; /* first char after 'Set-Cookie: ' */
		
		while (p1 < ptr) { /* in fact, we'll break after the first cookie */
		    while (p1 < ptr && (isspace(*p1)))
			p1++;
		    
		    if (p1 == ptr || *p1 == ';') /* end of cookie */
			break;
		    
		    /* p1 is at the beginning of the cookie name */
		    p2 = p1;
		    
		    while (p2 < ptr && *p2 != '=' && *p2 != ';')
			p2++;
		    
		    if (p2 == ptr || *p2 == ';') /* next cookie */
			break;
		    
		    p3 = p2 + 1; /* skips the '=' sign */
		    if (p3 == ptr)
			break;
		    
		    p4 = p3;
		    while (p4 < ptr && !isspace(*p4) && *p4 != ';')
			p4++;
		    
		    /* here, we have the cookie name between p1 and p2,
		     * and its value between p3 and p4.
		     * we can process it.
		     */
		    
		    if ((p2 - p1 == strlen(t->proxy->cookie_name)) &&
			(strncmp(p1, t->proxy->cookie_name, p2 - p1) == 0)) {
			/* Cool... it's the right one */
			
			/* If the cookie is in insert mode on a known server, we'll delete
			 * this occurrence because we'll insert another one later.
			 * We'll delete it too if the "indirect" option is set and we're in
			 * a direct access. */
			if (((t->srv) && (t->proxy->options & PR_O_COOK_INS)) ||
			    ((t->flags & TF_DIRECT) && (t->proxy->options & PR_O_COOK_IND))) {
			    /* this header must be deleted */
			    delete_header = 1;
			}
			else if ((t->srv) && (t->proxy->options & PR_O_COOK_RW)) {
			    /* replace bytes p3->p4 with the cookie name associated
			     * with this server since we know it.
			     */
			    buffer_replace2(rep, p3, p4, t->srv->cookie, t->srv->cklen);
			}
			break;
		    }
		    else {
			//	fprintf(stderr,"Ignoring unknown cookie : ");
			//	write(2, p1, p2-p1);
			//	fprintf(stderr," = ");
			//	write(2, p3, p4-p3);
			//	fprintf(stderr,"\n");
		    }
		    break; /* we don't want to loop again since there cannot be another cookie on the same line */
		} /* we're now at the end of the cookie value */
	    } /* end of cookie processing */

	    /* let's look if we have to delete this header */
	    if (delete_header) {
		buffer_replace2(rep, rep->h, rep->lr, "", 0);
	    }
	    rep->h = rep->lr;
	} /* while (rep->lr < rep->r) */

	/* end of header processing (even if incomplete) */

	if ((rep->l < rep->rlim - rep->data) && ! FD_ISSET(t->srv_fd, StaticReadEvent)) {
	    /* fd in StaticReadEvent was disabled, perhaps because of a previous buffer
	     * full. We cannot loop here since event_srv_read will disable it only if
	     * rep->l == rlim-data
	     */
	    FD_SET(t->srv_fd, StaticReadEvent);
	    if (t->proxy->srvtimeout)
		tv_delayfrom(&t->srexpire, &now, t->proxy->srvtimeout);
	    else
		tv_eternity(&t->srexpire);
	}

	/* read or write error */
	if (t->res_sw == RES_ERROR || t->res_sr == RES_ERROR) {
	    tv_eternity(&t->srexpire);
	    tv_eternity(&t->swexpire);
	    fd_delete(t->srv_fd);
	    t->srv_state = SV_STCLOSE;
	    return 1;
	}
	/* read timeout, last read, or end of client write
	 * since we are in header mode, if there's no space left for headers, we
	 * won't be able to free more later, so the session will never terminate.
	 */
	else if (t->res_sr == RES_NULL || c == CL_STSHUTW || c == CL_STCLOSE
		 || rep->l >= rep->rlim - rep->data || tv_cmp2_ms(&t->srexpire, &now) <= 0) {
	    FD_CLR(t->srv_fd, StaticReadEvent);
	    tv_eternity(&t->srexpire);
	    shutdown(t->srv_fd, SHUT_RD);
	    t->srv_state = SV_STSHUTR;
	    return 1;
	    
	}	
	/* write timeout, or last client read and buffer empty */
	else if (((c == CL_STSHUTR || c == CL_STCLOSE) && (req->l == 0)) ||
		 (tv_cmp2_ms(&t->swexpire, &now) <= 0)) {
	    FD_CLR(t->srv_fd, StaticWriteEvent);
	    tv_eternity(&t->swexpire);
	    shutdown(t->srv_fd, SHUT_WR);
	    t->srv_state = SV_STSHUTW;
	    return 1;
	}

	if (req->l == 0) {
	    if (FD_ISSET(t->srv_fd, StaticWriteEvent)) {
		FD_CLR(t->srv_fd, StaticWriteEvent); /* stop writing */
		tv_eternity(&t->swexpire);
	    }
	}
	else { /* client buffer not empty */
	    if (! FD_ISSET(t->srv_fd, StaticWriteEvent)) {
		FD_SET(t->srv_fd, StaticWriteEvent); /* restart writing */
		if (t->proxy->srvtimeout)
		    tv_delayfrom(&t->swexpire, &now, t->proxy->srvtimeout);
		else
		    tv_eternity(&t->swexpire);
	    }
	}

	/* be nice with the client side which would like to send a complete header
	 * FIXME: COMPLETELY BUGGY !!! not all headers may be processed because the client
	 * would read all remaining data at once ! The client should not write past rep->lr
	 * when the server is in header state.
	 */
	//return header_processed;
	return t->srv_state != SV_STHEADERS;
    }
    else if (s == SV_STDATA) {
	/* read or write error */
	if (t->res_sw == RES_ERROR || t->res_sr == RES_ERROR) {
	    tv_eternity(&t->srexpire);
	    tv_eternity(&t->swexpire);
	    fd_delete(t->srv_fd);
	    t->srv_state = SV_STCLOSE;
	    return 1;
	}
	/* read timeout, last read, or end of client write */
	else if (t->res_sr == RES_NULL || c == CL_STSHUTW || c == CL_STCLOSE
		 || tv_cmp2_ms(&t->srexpire, &now) <= 0) {
	    FD_CLR(t->srv_fd, StaticReadEvent);
	    tv_eternity(&t->srexpire);
	    shutdown(t->srv_fd, SHUT_RD);
	    t->srv_state = SV_STSHUTR;
	    return 1;
	    
	}	
	/* write timeout, or last client read and buffer empty */
	else if (((c == CL_STSHUTR || c == CL_STCLOSE) && (req->l == 0))
		 || (tv_cmp2_ms(&t->swexpire, &now) <= 0)) {
	    FD_CLR(t->srv_fd, StaticWriteEvent);
	    tv_eternity(&t->swexpire);
	    shutdown(t->srv_fd, SHUT_WR);
	    t->srv_state = SV_STSHUTW;
	    return 1;
	}
	else if (req->l == 0) {
	    if (FD_ISSET(t->srv_fd, StaticWriteEvent)) {
		FD_CLR(t->srv_fd, StaticWriteEvent); /* stop writing */
		tv_eternity(&t->swexpire);
	    }
	}
	else { /* buffer not empty */
	    if (! FD_ISSET(t->srv_fd, StaticWriteEvent)) {
		FD_SET(t->srv_fd, StaticWriteEvent); /* restart writing */
		if (t->proxy->srvtimeout)
		    tv_delayfrom(&t->swexpire, &now, t->proxy->srvtimeout);
		else
		    tv_eternity(&t->swexpire);
	    }
	}

	if (rep->l == BUFSIZE) { /* no room to read more data */
	    if (FD_ISSET(t->srv_fd, StaticReadEvent)) {
		FD_CLR(t->srv_fd, StaticReadEvent);
		tv_eternity(&t->srexpire);
	    }
	}
	else {
	    if (! FD_ISSET(t->srv_fd, StaticReadEvent)) {
		FD_SET(t->srv_fd, StaticReadEvent);
		if (t->proxy->srvtimeout)
		    tv_delayfrom(&t->srexpire, &now, t->proxy->srvtimeout);
		else
		    tv_eternity(&t->srexpire);
	    }
	}

	return 0; /* other cases change nothing */
    }
    else if (s == SV_STSHUTR) {
	if ((t->res_sw == RES_ERROR) ||
	    ((c == CL_STSHUTR || c == CL_STCLOSE) && (req->l == 0)) ||
	    (tv_cmp2_ms(&t->swexpire, &now) <= 0)) {
	    //FD_CLR(t->srv_fd, StaticWriteEvent);
	    tv_eternity(&t->swexpire);
	    fd_delete(t->srv_fd);
	    //close(t->srv_fd);
	    t->srv_state = SV_STCLOSE;
	    return 1;
	}
	else if (req->l == 0) {
	    if (FD_ISSET(t->srv_fd, StaticWriteEvent)) {
		FD_CLR(t->srv_fd, StaticWriteEvent); /* stop writing */
		tv_eternity(&t->swexpire);
	    }
	}
	else { /* buffer not empty */
	    if (! FD_ISSET(t->srv_fd, StaticWriteEvent)) {
		FD_SET(t->srv_fd, StaticWriteEvent); /* restart writing */
		if (t->proxy->srvtimeout)
		    tv_delayfrom(&t->swexpire, &now, t->proxy->srvtimeout);
		else
		    tv_eternity(&t->swexpire);
	    }
	}
	return 0;
    }
    else if (s == SV_STSHUTW) {
	if (t->res_sr == RES_ERROR || t->res_sr == RES_NULL ||
	    c == CL_STSHUTW || c == CL_STCLOSE ||
	    tv_cmp2_ms(&t->srexpire, &now) <= 0) {
	    //FD_CLR(t->srv_fd, StaticReadEvent);
	    tv_eternity(&t->srexpire);
	    fd_delete(t->srv_fd);
	    //close(t->srv_fd);
	    t->srv_state = SV_STCLOSE;
	    return 1;
	}
	else if (rep->l == BUFSIZE) { /* no room to read more data */
	    if (FD_ISSET(t->srv_fd, StaticReadEvent)) {
		FD_CLR(t->srv_fd, StaticReadEvent);
		tv_eternity(&t->srexpire);
	    }
	}
	else {
	    if (! FD_ISSET(t->srv_fd, StaticReadEvent)) {
		FD_SET(t->srv_fd, StaticReadEvent);
		if (t->proxy->srvtimeout)
		    tv_delayfrom(&t->srexpire, &now, t->proxy->srvtimeout);
		else
		    tv_eternity(&t->srexpire);
	    }
	}
	return 0;
    }
    else { /* SV_STCLOSE : nothing to do */
	if ((mode & MODE_DEBUG) && !(mode & MODE_QUIET)) {
	    int len;
	    len = sprintf(trash, "srvcls[%04x:%04x]\n", (unsigned short)t->cli_fd, (unsigned short)t->srv_fd);
	    write(1, trash, len);
	}
	return 0;
    }
    return 0;
}


/* Processes the client and server jobs of a session task, then
 * puts it back to the wait queue in a clean state, or
 * cleans up its resources if it must be deleted. Returns
 * the time the task accepts to wait, or -1 for infinity
 */
int process_session(struct task *t) {
    struct session *s = t->context;
    int fsm_resync = 0;

    do {
	fsm_resync = 0;
	//fprintf(stderr,"before_cli:cli=%d, srv=%d\n", t->cli_state, t->srv_state);
	fsm_resync |= process_cli(s);
	//fprintf(stderr,"cli/srv:cli=%d, srv=%d\n", t->cli_state, t->srv_state);
	fsm_resync |= process_srv(s);
	//fprintf(stderr,"after_srv:cli=%d, srv=%d\n", t->cli_state, t->srv_state);
    } while (fsm_resync);

    if (s->cli_state != CL_STCLOSE || s->srv_state != SV_STCLOSE) {
	struct timeval min1, min2;
	s->res_cw = s->res_cr = s->res_sw = s->res_sr = RES_SILENT;

	tv_min(&min1, &s->crexpire, &s->cwexpire);
	tv_min(&min2, &s->srexpire, &s->swexpire);
	tv_min(&min1, &min1, &s->cnexpire);
	tv_min(&t->expire, &min1, &min2);

	/* restore t to its place in the task list */
	task_queue(t);

	return tv_remain(&now, &t->expire); /* nothing more to do */
    }

    s->proxy->nbconn--;
    actconn--;
    
    if ((mode & MODE_DEBUG) && !(mode & MODE_QUIET)) {
	int len;
	len = sprintf(trash, "closed[%04x:%04x]\n", (unsigned short)s->cli_fd, (unsigned short)s->srv_fd);
	write(1, trash, len);
    }

    /* the task MUST not be in the run queue anymore */
    task_delete(t);
    session_free(s);
    task_free(t);
    return -1; /* rest in peace for eternity */
}



/*
 * manages a server health-check. Returns
 * the time the task accepts to wait, or -1 for infinity.
 */
int process_chk(struct task *t) {
    struct server *s = t->context;
    int fd = s->curfd;
    int one = 1;

    //fprintf(stderr, "process_chk: task=%p\n", t);

    if (fd < 0) {   /* no check currently running */
	//fprintf(stderr, "process_chk: 2\n");
	if (tv_cmp2_ms(&t->expire, &now) > 0) { /* not good time yet */
	    task_queue(t);	/* restore t to its place in the task list */
	    return tv_remain(&now, &t->expire);
	}
	
	/* we'll initiate a new check */
	s->result = 0; /* no result yet */
	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != -1) {
	    if ((fd < cfg_maxsock) &&
		(fcntl(fd, F_SETFL, O_NONBLOCK) != -1) &&
		(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) != -1)) {
		//fprintf(stderr, "process_chk: 3\n");

		if ((connect(fd, (struct sockaddr *)&s->addr, sizeof(s->addr)) != -1) || (errno == EINPROGRESS)) {
		    /* OK, connection in progress or established */

		    //fprintf(stderr, "process_chk: 4\n");

		    s->curfd = fd; /* that's how we know a test is in progress ;-) */
		    fdtab[fd].owner = t;
		    fdtab[fd].read  = NULL;
		    fdtab[fd].write = &event_srv_hck;
		    fdtab[fd].state = FD_STCONN; /* connection in progress */
		    FD_SET(fd, StaticWriteEvent);  /* for connect status */
		    fd_insert(fd);
		    tv_delayfrom(&t->expire, &now, CHK_CONNTIME);
		    task_queue(t);	/* restore t to its place in the task list */
		    return tv_remain(&now, &t->expire);
		}
		else if (errno != EALREADY && errno != EISCONN && errno != EAGAIN) {
		    s->result = -1;    /* a real error */
		}
	    }
	    //fprintf(stderr, "process_chk: 5\n");
	    close(fd);
	}

	if (!s->result) { /* nothing done */
	    //fprintf(stderr, "process_chk: 6\n");
	    tv_delayfrom(&t->expire, &now, CHK_INTERVAL);
	    task_queue(t);	/* restore t to its place in the task list */
	    return tv_remain(&now, &t->expire);
	}

	/* here, we have seen a failure */
	if (s->health > FALLTIME)
	    s->health--; /* still good */
	else {
	    if (s->health == FALLTIME && !(mode & MODE_QUIET))
		Warning("server %s DOWN.\n", s->id);

	    s->health = 0; /* failure */
	    s->state &= ~SRV_RUNNING;
	}

	//fprintf(stderr, "process_chk: 7\n");
	tv_delayfrom(&t->expire, &now, CHK_CONNTIME);
    }
    else {
	//fprintf(stderr, "process_chk: 8\n");
	/* there was a test running */
	if (s->result > 0) { /* good server detected */
	    //fprintf(stderr, "process_chk: 9\n");
	    s->health++; /* was bad, stays for a while */
	    if (s->health >= FALLTIME) {
		if (s->health == FALLTIME && !(mode & MODE_QUIET))
		    Warning("server %s UP.\n", s->id);

		s->health = FALLTIME + RISETIME -1; /* OK now */
		s->state |= SRV_RUNNING;
	    }
	    s->curfd = -1; /* no check running anymore */
	    //FD_CLR(fd, StaticWriteEvent);
	    fd_delete(fd);
	    tv_delayfrom(&t->expire, &now, CHK_INTERVAL);
	}
	else if (s->result < 0 || tv_cmp2_ms(&t->expire, &now) <= 0) {
	    //fprintf(stderr, "process_chk: 10\n");
	    /* failure or timeout detected */
	    if (s->health > FALLTIME)
		s->health--; /* still good */
	    else {
		if (s->health == FALLTIME && !(mode & MODE_QUIET))
		    Warning("server %s DOWN.\n", s->id);

		s->health = 0; /* failure */
		s->state &= ~SRV_RUNNING;
	    }
	    s->curfd = -1;
	    //FD_CLR(fd, StaticWriteEvent);
	    fd_delete(fd);
	    tv_delayfrom(&t->expire, &now, CHK_INTERVAL);
	}
	/* if result is 0 and there's no timeout, we have to wait again */
    }
    //fprintf(stderr, "process_chk: 11\n");
    s->result = 0;
    task_queue(t);	/* restore t to its place in the task list */
    return tv_remain(&now, &t->expire);
}



#if STATTIME > 0
int stats(void);
#endif

/*
 * Main select() loop.
 */

void select_loop() {
  int next_time;
  int time2;
  int status;
  int fd,i;
  struct timeval delta;
  int readnotnull, writenotnull;
  struct task *t, *tnext;

  tv_now(&now);

  while (1) {
      next_time = -1; /* set the timer to wait eternally first */

      /* look for expired tasks and add them to the run queue.
       */
      tnext = ((struct task *)LIST_HEAD(wait_queue))->next;
      while ((t = tnext) != LIST_HEAD(wait_queue)) { /* we haven't looped ? */
	  tnext = t->next;
	  if (t->state & TASK_RUNNING)
	      continue;

	  /* wakeup expired entries. It doesn't matter if they are
	   * already running because of a previous event
	   */
	  if (tv_cmp2_ms(&t->expire, &now) <= 0) {
	      //fprintf(stderr,"task_wakeup(%p, %p)\n", &rq, t);
	      task_wakeup(&rq, t);
	  }
	  else {
	      /* first non-runnable task. Use its expiration date as an upper bound */
	      int temp_time = tv_remain(&now, &t->expire);
	      if (temp_time)
		  next_time = temp_time;
	      //fprintf(stderr,"no_task_wakeup(%p, %p) : expire in %d ms\n", &rq, t, temp_time);
	      break;
	  }
      }

      /* process each task in the run queue now. Each task may be deleted
       * since we only use tnext.
       */
      tnext = rq;
      while ((t = tnext) != NULL) {
	  int temp_time;
	  
	  tnext = t->rqnext;
	  task_sleep(&rq, t);
	  //fprintf(stderr,"task %p\n",t);	  
	  temp_time = t->process(t);
	  next_time = MINTIME(temp_time, next_time);
	  //fprintf(stderr,"process(%p)=%d -> next_time=%d)\n", t, temp_time, next_time);
      }

      //fprintf(stderr,"---end of run---\n");

      /* maintain all proxies in a consistent state. This should quickly become a task */
      time2 = maintain_proxies();
      next_time = MINTIME(time2, next_time);

      /* stop when there's no connection left and we don't allow them anymore */
      if (!actconn && listeners == 0)
	  break;

	  
#if STATTIME > 0
      time2 = stats();
      //      fprintf(stderr,"                stats = %d\n", time2);
      next_time = MINTIME(time2, next_time);
#endif

      if (next_time > 0) {  /* FIXME */
	  /* Convert to timeval */
	  /* to avoid eventual select loops due to timer precision */
	  next_time += SCHEDULER_RESOLUTION;
	  delta.tv_sec  = next_time / 1000; 
	  delta.tv_usec = (next_time % 1000) * 1000;
      }
      else if (next_time == 0) { /* allow select to return immediately when needed */
	  delta.tv_sec = delta.tv_usec = 0;
      }


      /* let's restore fdset state */

      readnotnull = 0; writenotnull = 0;
      for (i = 0; i < (cfg_maxsock + FD_SETSIZE - 1)/(8*sizeof(int)); i++) {
	  readnotnull |= (*(((int*)ReadEvent)+i) = *(((int*)StaticReadEvent)+i)) != 0;
	  writenotnull |= (*(((int*)WriteEvent)+i) = *(((int*)StaticWriteEvent)+i)) != 0;
      }

//	/* just a verification code, needs to be removed for performance */
//	for (i=0; i<maxfd; i++) {
//	    if (FD_ISSET(i, ReadEvent) != FD_ISSET(i, StaticReadEvent))
//		abort();
//	    if (FD_ISSET(i, WriteEvent) != FD_ISSET(i, StaticWriteEvent))
//		abort();
//	    
//	}

      status=select(maxfd,
		    readnotnull ? ReadEvent : NULL,
		    writenotnull ? WriteEvent : NULL,
		    NULL,
		    (next_time >= 0) ? &delta : NULL);
      
      /* this is an experiment on the separation of the select work */
      // status  = (readnotnull  ? select(maxfd, ReadEvent, NULL, NULL, (next_time >= 0) ? &delta : NULL) : 0);
      // status |= (writenotnull ? select(maxfd, NULL, WriteEvent, NULL, (next_time >= 0) ? &delta : NULL) : 0);
      
      tv_now(&now);

      if (status > 0) { /* must proceed with events */

	  int fds;
	  char count;
	  
	  for (fds = 0; (fds << INTBITS) < maxfd; fds++)
	      if ((((int *)(ReadEvent))[fds] | ((int *)(WriteEvent))[fds]) != 0)
		  for (count = 1<<INTBITS, fd = fds << INTBITS; count && fd < maxfd; count--, fd++) {
		      
		      /* if we specify read first, the accepts and zero reads will be
		       * seen first. Moreover, system buffers will be flushed faster.
		       */
		      if (fdtab[fd].state == FD_STCLOSE)
			  continue;
		      
		      if (FD_ISSET(fd, ReadEvent))
			  fdtab[fd].read(fd);

		      if (FD_ISSET(fd, WriteEvent))
			  fdtab[fd].write(fd);
		  }
      }
      else {
	  //	  fprintf(stderr,"select returned %d, maxfd=%d\n", status, maxfd);
      }
  }
}


#if STATTIME > 0
/*
 * Display proxy statistics regularly. It is designed to be called from the
 * select_loop().
 */
int stats(void) {
    static int lines;
    static struct timeval nextevt;
    static struct timeval lastevt;
    static struct timeval starttime = {0,0};
    unsigned long totaltime, deltatime;
    int ret;

    if (tv_remain(&now, &nextevt) == 0) {
	deltatime = (tv_delta(&now, &lastevt)?:1);
	totaltime = (tv_delta(&now, &starttime)?:1);
	
	if (mode & MODE_STATS) {	
		if ((lines++ % 16 == 0) && !(mode & MODE_LOG))
		    qfprintf(stderr,
			    "\n active   total  tsknew tskgood tskleft tskrght tsknsch tsklsch tskrsch\n");
		if (lines>1) {
			qfprintf(stderr,"%07d %07d %07d %07d %07d %07d %07d %07d %07d\n",
				actconn, totalconn,
				stats_tsk_new, stats_tsk_good,
				stats_tsk_left, stats_tsk_right,
				stats_tsk_nsrch, stats_tsk_lsrch, stats_tsk_rsrch);
		}
	}
	    
	tv_delayfrom(&nextevt, &now, STATTIME);

	lastevt=now;
    }	
    ret = tv_remain(&now, &nextevt);
    return ret;
}
#endif


/*
 * this function enables proxies when there are enough free sessions,
 * or stops them when the table is full. It is designed to be called from the
 * select_loop(). It returns the time left before next expiration event
 * during stop time, -1 otherwise.
 */
static int maintain_proxies(void) {
    struct proxy *p;
    int tleft; /* time left */

    p = proxy;
    tleft = -1; /* infinite time */

    /* if there are enough free sessions, we'll activate proxies */
    if (actconn < cfg_maxconn) {
	while (p) {
	    if (p->nbconn < p->maxconn) {
		if (p->state == PR_STIDLE) {
		    FD_SET(p->listen_fd, StaticReadEvent);
		    p->state = PR_STRUN;
		}
	    }
	    else {
		if (p->state == PR_STRUN) {
		    FD_CLR(p->listen_fd, StaticReadEvent);
		    p->state = PR_STIDLE;
		}
	    }
	    p = p->next;
	}
    }
    else {  /* block all proxies */
	while (p) {
	    if (p->state == PR_STRUN) {
		FD_CLR(p->listen_fd, StaticReadEvent);
		p->state = PR_STIDLE;
	    }
	    p = p->next;
	}
    }

    if (stopping) {
	p = proxy;
	while (p) {
	    if (p->state != PR_STDISABLED) {
		int t;
		t = tv_remain(&now, &p->stop_time);
		if (t == 0) {
		    //FD_CLR(p->listen_fd, StaticReadEvent);
		    //close(p->listen_fd);
		    fd_delete(p->listen_fd);
		    p->state = PR_STDISABLED;
		    listeners--;
		}
		else {
		    tleft = MINTIME(t, tleft);
		}
	    }
	    p = p->next;
	}
    }
    return tleft;
}

/*
 * this function disables health-check servers so that the process will quickly be ignored
 * by load balancers.
 */
static void soft_stop(void) {
    struct proxy *p;

    stopping = 1;
    p = proxy;
    tv_now(&now); /* else, the old time before select will be used */
    while (p) {
	if (p->state != PR_STDISABLED)
	    tv_delayfrom(&p->stop_time, &now, p->grace);
	p = p->next;
    }
}

/*
 * upon SIGUSR1, let's have a soft stop.
 */
void sig_soft_stop(int sig) {
    soft_stop();
    signal(sig, SIG_IGN);
}


void dump(int sig) {
    struct task *t, *tnext;
    struct session *s;

    tnext = ((struct task *)LIST_HEAD(wait_queue))->next;
    while ((t = tnext) != LIST_HEAD(wait_queue)) { /* we haven't looped ? */
	tnext = t->next;
	s = t->context;
	qfprintf(stderr,"[dump] wq: task %p, still %ld ms, "
		 "cli=%d, srv=%d, cr=%d, cw=%d, sr=%d, sw=%d, "
		 "req=%d, rep=%d, clifd=%d\n",
		 s, tv_remain(&now, &t->expire),
		 s->cli_state,
		 s->srv_state,
		 FD_ISSET(s->cli_fd, StaticReadEvent),
		 FD_ISSET(s->cli_fd, StaticWriteEvent),
		 FD_ISSET(s->srv_fd, StaticReadEvent),
		 FD_ISSET(s->srv_fd, StaticWriteEvent),
		 s->req->l, s->rep?s->rep->l:0, s->cli_fd
		 );
    }
}

/*
 * This function reads and parses the configuration file given in the argument.
 * returns 0 if OK, -1 if error.
 */
int readcfgfile(char *file) {
    char thisline[256];
    char *line;
    FILE *f;
    int linenum = 0;
    char *end;
    char *args[MAX_LINE_ARGS];
    int arg;
    int cfgerr = 0;

    struct proxy *curproxy = NULL;
    struct server *newsrv = NULL;

    if ((f=fopen(file,"r")) == NULL)
	return -1;

    while (fgets(line = thisline, sizeof(thisline), f) != NULL) {
	linenum++;

	end = line + strlen(line);

	/* skip leading spaces */
	while (isspace(*line))
	    line++;
	
	arg = 0;
	args[arg] = line;

	while (*line && arg < MAX_LINE_ARGS) {
	    /* first, we'll replace \\, \<space>, \#, \r, \n, \t, \xXX with their
	     * C equivalent value. Other combinations left unchanged (eg: \1).
	     */
	    if (*line == '\\') {
		int skip = 0;
		if (line[1] == ' ' || line[1] == '\\' || line[1] == '#') {
		    *line = line[1];
		    skip = 1;
		}
		else if (line[1] == 'r') {
		    *line = '\r';
		    skip = 1;
		} 
		else if (line[1] == 'n') {
		    *line = '\n';
		    skip = 1;
		}
		else if (line[1] == 't') {
		    *line = '\t';
		    skip = 1;
		}
		else if (line[1] == 'x' && (line + 3 < end )) {
		    unsigned char hex1, hex2;
		    hex1 = toupper(line[2]) - '0'; hex2 = toupper(line[3]) - '0';
		    if (hex1 > 9) hex1 -= 'A' - '9' - 1;
		    if (hex2 > 9) hex2 -= 'A' - '9' - 1;
		    *line = (hex1<<4) + hex2;
		    skip = 3;
		} 
		if (skip) {
		    memmove(line + 1, line + 1 + skip, end - (line + skip + 1));
		    end -= skip;
		}
		line++;
	    }
	    else {
		if (*line == '#' || *line == '\n' || *line == '\r')
		    *line = 0; /* end of string, end of loop */
		else
		    line++;
		
		/* a non-escaped space is an argument separator */
		if (isspace(*line)) {
		    *line++ = 0;
		    while (isspace(*line))
			line++;
		    args[++arg] = line;
		}
	    }
	}

	/* empty line */
	if (!**args)
	    continue;

	/* zero out remaining args */
	while (++arg < MAX_LINE_ARGS) {
	    args[arg] = line;
	}

	if (!strcmp(args[0], "listen")) {  /* new proxy */
	    if (strchr(args[2], ':') == NULL) {
		Alert("parsing [%s:%d] : <listen> expects <id> and <addr:port> as arguments.\n",
		      file, linenum);
		return -1;
	    }

	    if ((curproxy = (struct proxy *)calloc(1, sizeof(struct proxy)))
		== NULL) {
		Alert("parsing [%s:%d] : out of memory\n", file, linenum);
		exit(1);
	    }
	    curproxy->next = proxy;
	    proxy = curproxy;
	    curproxy->id = strdup(args[1]);
	    curproxy->listen_addr = *str2sa(args[2]);
	    curproxy->state = PR_STNEW;
	    /* set default values */
	    curproxy->maxconn = cfg_maxpconn;
	    curproxy->conn_retries = CONN_RETRIES;
	    curproxy->options = 0;
	    curproxy->clitimeout = curproxy->contimeout = curproxy->srvtimeout = 0;
	    curproxy->mode = PR_MODE_TCP;
	    curproxy->logfac1 = curproxy->logfac2 = -1; /* log disabled */
	    continue;
	}
	else if (curproxy == NULL) {
	    Alert("parsing [%s:%d] : <listen> expected.\n",
		  file, linenum);
	    return -1;
	}
    
	if (!strcmp(args[0], "mode")) {  /* sets the proxy mode */
	    if (!strcmp(args[1], "http")) curproxy->mode = PR_MODE_HTTP;
	    else if (!strcmp(args[1], "tcp")) curproxy->mode = PR_MODE_TCP;
	    else if (!strcmp(args[1], "health")) curproxy->mode = PR_MODE_HEALTH;
	    else {
		Alert("parsing [%s:%d] : unknown proxy mode <%s>.\n", file, linenum, args[1]);
		return -1;
	    }
	}
	else if (!strcmp(args[0], "disabled")) {  /* disables this proxy */
	    curproxy->state = PR_STDISABLED;
	}
	else if (!strcmp(args[0], "cookie")) {  /* cookie name */
	    int cur_arg;
	    if (curproxy->cookie_name != NULL) {
		Alert("parsing [%s:%d] : cookie name already specified. Continuing.\n",
		      file, linenum);
		continue;
	    }

	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <cookie> expects <cookie_name> as argument.\n",
		      file, linenum);
		return -1;
	    }
	    curproxy->cookie_name = strdup(args[1]);

	    cur_arg = 2;
	    while (*(args[cur_arg])) {
		if (!strcmp(args[cur_arg], "rewrite")) {
		    curproxy->options |= PR_O_COOK_RW;
		}
		else if (!strcmp(args[cur_arg], "indirect")) {
		    curproxy->options |= PR_O_COOK_IND;
		}
		else if (!strcmp(args[cur_arg], "insert")) {
		    curproxy->options |= PR_O_COOK_INS;
		}
		else {
		    Alert("parsing [%s:%d] : <cookie> supports 'rewrite', 'insert' and 'indirect' options.\n",
			  file, linenum);
		    return -1;
		}
		cur_arg++;
	    }
	    if ((curproxy->options & (PR_O_COOK_RW|PR_O_COOK_IND)) == (PR_O_COOK_RW|PR_O_COOK_IND)) {
		Alert("parsing [%s:%d] : <cookie> 'rewrite' and 'indirect' mode are incompatibles.\n",
		      file, linenum);
		return -1;
	    }
	}
	else if (!strcmp(args[0], "contimeout")) {  /* connect timeout */
	    if (curproxy->contimeout != 0) {
		Alert("parsing [%s:%d] : contimeout already specified. Continuing.\n",
		      file, linenum);
		continue;
	    }
	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <contimeout> expects an integer <time_in_ms> as argument.\n",
		      file, linenum);
		return -1;
	    }
	    curproxy->contimeout = atol(args[1]);
	}
	else if (!strcmp(args[0], "clitimeout")) {  /*  client timeout */
	    if (curproxy->clitimeout != 0) {
		Alert("parsing [%s:%d] : clitimeout already specified. Continuing.\n",
		      file, linenum);
		continue;
	    }
	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <clitimeout> expects an integer <time_in_ms> as argument.\n",
		      file, linenum);
		return -1;
	    }
	    curproxy->clitimeout = atol(args[1]);
	}
	else if (!strcmp(args[0], "srvtimeout")) {  /*  server timeout */
	    if (curproxy->srvtimeout != 0) {
		Alert("parsing [%s:%d] : srvtimeout already specified. Continuing.\n",
		      file, linenum);
		continue;
	    }
	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <srvtimeout> expects an integer <time_in_ms> as argument.\n",
		      file, linenum);
		return -1;
	    }
	    curproxy->srvtimeout = atol(args[1]);
	}
	else if (!strcmp(args[0], "retries")) {  /* connection retries */
	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <retries> expects an integer argument (dispatch counts for one).\n",
		      file, linenum);
		return -1;
	    }
	    curproxy->conn_retries = atol(args[1]);
	}
	else if (!strcmp(args[0], "redispatch") || !strcmp(args[0], "redisp")) {
	    /* enable reconnections to dispatch */
	    curproxy->options |= PR_O_REDISP;
	}
#ifdef TRANSPARENT
	else if (!strcmp(args[0], "transparent")) {
	    /* enable transparent proxy connections */
	    curproxy->options |= PR_O_TRANSP;
	}
#endif
	else if (!strcmp(args[0], "maxconn")) {  /* maxconn */
	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <maxconn> expects an integer argument.\n",
		      file, linenum);
		return -1;
	    }
	    curproxy->maxconn = atol(args[1]);
	}
	else if (!strcmp(args[0], "grace")) {  /* grace time (ms) */
	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <grace> expects a time in milliseconds.\n",
		      file, linenum);
		return -1;
	    }
	    curproxy->grace = atol(args[1]);
	}
	else if (!strcmp(args[0], "dispatch")) {  /* dispatch address */
	    if (strchr(args[1], ':') == NULL) {
		Alert("parsing [%s:%d] : <dispatch> expects <addr:port> as argument.\n",
		      file, linenum);
		return -1;
	    }
	    curproxy->dispatch_addr = *str2sa(args[1]);
	}
	else if (!strcmp(args[0], "balance")) {  /* set balancing with optionnal algorithm */
	    if (*(args[1])) {
		if (!strcmp(args[1], "roundrobin")) {
		    curproxy->options |= PR_O_BALANCE_RR;
		}
		else {
		    Alert("parsing [%s:%d] : <balance> supports 'roundrobin' options.\n",
			  file, linenum);
		    return -1;
		}
	    }
	    else /* if no option is set, use round-robin by default */
		curproxy->options |= PR_O_BALANCE_RR;
	}
	else if (!strcmp(args[0], "server")) {  /* server address */
	    int cur_arg;

	    if (strchr(args[2], ':') == NULL) {
		Alert("parsing [%s:%d] : <server> expects <name> and <addr:port> as arguments.\n",
		      file, linenum);
		return -1;
	    }
	    if ((newsrv = (struct server *)calloc(1, sizeof(struct server))) == NULL) {
		Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
		exit(1);
	    }
	    newsrv->next = curproxy->srv;
	    curproxy->srv = newsrv;
	    newsrv->id = strdup(args[1]);
	    newsrv->addr = *str2sa(args[2]);
	    newsrv->state = SRV_RUNNING; /* early server setup */
	    newsrv->health = FALLTIME; /* up, but will fall down at first failure */
	    newsrv->curfd = -1; /* no health-check in progress */
	    cur_arg = 3;
	    while (*args[cur_arg]) {
		if (!strcmp(args[cur_arg], "cookie")) {
		    newsrv->cookie = strdup(args[cur_arg + 1]);
		    newsrv->cklen = strlen(args[cur_arg + 1]);
		    cur_arg += 2;
		}
		else if (!strcmp(args[cur_arg], "check")) {
		    struct task *t;

		    if ((t = pool_alloc(task)) == NULL) { /* disable this proxy for a while */
			Alert("parsing [%s:%d] : out of memory.\n", file, linenum);
			return -1;
		    }

		    t->next = t->prev = t->rqnext = NULL; /* task not in run queue yet */
		    t->wq = LIST_HEAD(wait_queue); /* but already has a wait queue assigned */
		    t->state = TASK_IDLE;
		    t->process = process_chk;
		    t->context = newsrv;

		    tv_delayfrom(&t->expire, &now, CHK_INTERVAL); /* check this every ms */
		    task_queue(t);
		    task_wakeup(&rq, t);

		    cur_arg += 1;
		}
		else {
		    Alert("parsing [%s:%d] : server %s only supports options 'cookie' and 'check'.\n",
			  file, linenum, newsrv->id);
		    return -1;
		}
	    }
	    curproxy->nbservers++;
	}
	else if (!strcmp(args[0], "log")) {  /* syslog server address */
	    struct sockaddr_in *sa;
	    int facility;

	    if (*(args[1]) == 0 || *(args[2]) == 0) {
		Alert("parsing [%s:%d] : <log> expects <address> and <facility> as arguments.\n",
		      file, linenum);
		return -1;
	    }

	    for (facility = 0; facility < NB_LOG_FACILITIES; facility++)
		if (!strcmp(log_facilities[facility], args[2]))
		    break;

	    if (facility >= NB_LOG_FACILITIES) {
		Alert("parsing [%s:%d] : unknown log facility <%s>\n", file, linenum, args[2]);
		exit(1);
	    }

	    sa = str2sa(args[1]);
	    if (!sa->sin_port)
		sa->sin_port = htons(SYSLOG_PORT);

	    if (curproxy->logfac1 == -1) {
		curproxy->logsrv1 = *sa;
		curproxy->logfac1 = facility;
	    }
	    else if (curproxy->logfac2 == -1) {
		curproxy->logsrv2 = *sa;
		curproxy->logfac2 = facility;
	    }
	    else {
		Alert("parsing [%s:%d] : too many syslog servers\n", file, linenum);
		exit(1);
	    }

	}
	else if (!strcmp(args[0], "cliexp") || !strcmp(args[0], "reqrep")) {  /* replace request header from a regex */
	    regex_t *preg;
	    if (curproxy->nb_reqexp >= MAX_REGEXP) {
		Alert("parsing [%s:%d] : too many request expressions. Continuing.\n",
		      file, linenum);
		continue;
	    }

	    if (*(args[1]) == 0 || *(args[2]) == 0) {
		Alert("parsing [%s:%d] : <reqrep> expects <search> and <replace> as arguments.\n",
		      file, linenum);
		return -1;
	    }

	    preg = calloc(1, sizeof(regex_t));
	    if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
		Alert("parsing [%s:%d] : bad regular expression <%s>.\n", file, linenum, args[1]);
		return -1;
	    }
	    curproxy->req_exp[curproxy->nb_reqexp].preg = preg;
	    curproxy->req_exp[curproxy->nb_reqexp].replace = strdup(args[2]);
	    curproxy->nb_reqexp++;
	}
	else if (!strcmp(args[0], "reqdel")) {  /* delete request header from a regex */
	    regex_t *preg;
	    if (curproxy->nb_reqexp >= MAX_REGEXP) {
		Alert("parsing [%s:%d] : too many request expressions. Continuing.\n",
		      file, linenum);
		continue;
	    }

	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <reqdel> expects <search> as an argument.\n",
		      file, linenum);
		return -1;
	    }

	    preg = calloc(1, sizeof(regex_t));
	    if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
		Alert("parsing [%s:%d] : bad regular expression <%s>.\n", file, linenum, args[1]);
		return -1;
	    }
	    curproxy->req_exp[curproxy->nb_reqexp].preg = preg;
	    curproxy->req_exp[curproxy->nb_reqexp].replace = NULL; /* means it must be deleted */
	    curproxy->nb_reqexp++;
	}
	else if (!strcmp(args[0], "reqadd")) {  /* add request header */
	    if (curproxy->nb_reqadd >= MAX_REGEXP) {
		Alert("parsing [%s:%d] : too many client expressions. Continuing.\n",
		      file, linenum);
		continue;
	    }

	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <reqadd> expects <header> as an argument.\n",
		      file, linenum);
		return -1;
	    }

	    curproxy->req_add[curproxy->nb_reqadd++] = strdup(args[1]);
	}
	else if (!strcmp(args[0], "srvexp") || !strcmp(args[0], "rsprep")) {  /* replace response header from a regex */
	    regex_t *preg;
	    if (curproxy->nb_rspexp >= MAX_REGEXP) {
		Alert("parsing [%s:%d] : too many server expressions. Continuing.\n",
		      file, linenum);
		continue;
	    }

	    if (*(args[1]) == 0 || *(args[2]) == 0) {
		Alert("parsing [%s:%d] : <rsprep> expects <search> and <replace> as arguments.\n",
		      file, linenum);
		return -1;
	    }

	    preg = calloc(1, sizeof(regex_t));
	    if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
		Alert("parsing [%s:%d] : bad regular expression <%s>.\n", file, linenum, args[1]);
		return -1;
	    }
	    //	    fprintf(stderr,"before=<%s> after=<%s>\n", args[1], args[2]);
	    curproxy->rsp_exp[curproxy->nb_rspexp].preg = preg;
	    curproxy->rsp_exp[curproxy->nb_rspexp].replace = strdup(args[2]);
	    curproxy->nb_rspexp++;
	}
	else if (!strcmp(args[0], "rspdel")) {  /* delete response header from a regex */
	    regex_t *preg;
	    if (curproxy->nb_rspexp >= MAX_REGEXP) {
		Alert("parsing [%s:%d] : too many server expressions. Continuing.\n",
		      file, linenum);
		continue;
	    }

	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <rspdel> expects <search> as an argument.\n",
		      file, linenum);
		return -1;
	    }

	    preg = calloc(1, sizeof(regex_t));
	    if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
		Alert("parsing [%s:%d] : bad regular expression <%s>.\n", file, linenum, args[1]);
		return -1;
	    }
	    //	    fprintf(stderr,"before=<%s> after=<%s>\n", args[1], args[2]);
	    curproxy->rsp_exp[curproxy->nb_rspexp].preg = preg;
	    curproxy->rsp_exp[curproxy->nb_rspexp].replace = NULL; /* means it must be deleted */
	    curproxy->nb_rspexp++;
	}
	else if (!strcmp(args[0], "rspadd")) {  /* add response header */
	    if (curproxy->nb_rspadd >= MAX_REGEXP) {
		Alert("parsing [%s:%d] : too many server expressions. Continuing.\n",
		      file, linenum);
		continue;
	    }

	    if (*(args[1]) == 0) {
		Alert("parsing [%s:%d] : <rspadd> expects <header> as an argument.\n",
		      file, linenum);
		return -1;
	    }

	    curproxy->rsp_add[curproxy->nb_rspadd++] = strdup(args[1]);
	}
	else {
	    Alert("parsing [%s:%d] : unknown keyword <%s>\n", file, linenum, args[0]);
	    exit(1);
	}
    }
    fclose(f);

    /*
     * Now, check for the integrity of all that we have collected.
     */

    if ((curproxy = proxy) == NULL) {
	Alert("parsing %s : no <listen> line. Nothing to do !\n",
	      file);
	return -1;
    }

    while (curproxy != NULL) {
	if (curproxy->state == PR_STDISABLED) {
	    curproxy = curproxy->next;
	    continue;
	}
	if ((curproxy->mode != PR_MODE_HEALTH) &&
	    !(curproxy->options & (PR_O_TRANSP | PR_O_BALANCE)) &&
	    (*(int *)&curproxy->dispatch_addr == 0)) {
	    Alert("parsing %s : listener %s has no dispatch address and is not in transparent or balance mode.\n",
		    file, curproxy->id);
	    cfgerr++;
	}
	else if ((curproxy->mode != PR_MODE_HEALTH) && (curproxy->options & PR_O_BALANCE)) {
	    if (curproxy->options & PR_O_TRANSP) {
		Alert("parsing %s : listener %s cannot use both transparent and balance mode.\n",
		      file, curproxy->id);
		cfgerr++;
	    }
	    else if (curproxy->srv == NULL) {
		Alert("parsing %s : listener %s needs at least 1 server in balance mode.\n",
		      file, curproxy->id);
		cfgerr++;
	    }
	    else if (*(int *)&curproxy->dispatch_addr != 0) {
		Warning("parsing %s : dispatch address of listener %s will be ignored in balance mode.\n",
			file, curproxy->id);
	    }
	}
	else if (curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HEALTH) { /* TCP PROXY or HEALTH CHECK */
	    if (curproxy->cookie_name != NULL) {
		Warning("parsing %s : cookie will be ignored for listener %s.\n",
			file, curproxy->id);
	    }
	    if ((newsrv = curproxy->srv) != NULL) {
		Warning("parsing %s : servers will be ignored for listener %s.\n",
			file, curproxy->id);
	    }
	    if (curproxy->nb_rspexp) {
		Warning("parsing %s : server regular expressions will be ignored for listener %s.\n",
			file, curproxy->id);
	    }
	    if (curproxy->nb_reqexp) {
		Warning("parsing %s : client regular expressions will be ignored for listener %s.\n",
			file, curproxy->id);
	    }
	}
	else if (curproxy->mode == PR_MODE_HTTP) { /* HTTP PROXY */
	    if ((curproxy->cookie_name != NULL) && ((newsrv = curproxy->srv) == NULL)) {
		Alert("parsing %s : HTTP proxy %s has a cookie but no server list !\n",
		      file, curproxy->id);
		cfgerr++;
	    }
	    else {
		while (newsrv != NULL) {
		    /* nothing to check for now */
		    newsrv = newsrv->next;
		}
	    }
	}
	curproxy = curproxy->next;
    }
    if (cfgerr > 0) {
	Alert("Errors found in configuration file, aborting.\n");
	return -1;
    }
    else
	return 0;
}


/*
 * This function initializes all the necessary variables. It only returns
 * if everything is OK. If something fails, it exits.
 */
void init(int argc, char **argv) {
    int i;
    char *old_argv = *argv;
    char *tmp;

    if (1<<INTBITS != sizeof(int)*8) {
	qfprintf(stderr,
		"Error: wrong architecture. Recompile so that sizeof(int)=%d\n",
		sizeof(int)*8);
	exit(1);
    }

    pid = getpid();
    progname = *argv;
    while ((tmp = strchr(progname, '/')) != NULL)
	progname = tmp + 1;

    argc--; argv++;
    while (argc > 0) {
	char *flag;

	if (**argv == '-') {
	    flag = *argv+1;

	    /* 1 arg */
	    if (*flag == 'v') {
		display_version();
		exit(0);
	    }
	    else if (*flag == 'd')
		mode |= MODE_DEBUG;
	    else if (*flag == 'D')
		mode |= MODE_DAEMON | MODE_QUIET;
	    else if (*flag == 'q')
		mode |= MODE_QUIET;
#if STATTIME > 0
	    else if (*flag == 's')
		mode |= MODE_STATS;
	    else if (*flag == 'l')
		mode |= MODE_LOG;
#endif
	    else { /* >=2 args */
		argv++; argc--;
		if (argc == 0)
		    usage(old_argv);

		switch (*flag) {
		case 'n' : cfg_maxconn = atol(*argv); break;
		case 'N' : cfg_maxpconn = atol(*argv); break;
		case 'f' : cfg_cfgfile = *argv; break;
		default: usage(old_argv);
		}
	    }
	}
	else
	    usage(old_argv);
	    argv++; argc--;
    }

    cfg_maxsock = cfg_maxconn * 2; /* each connection needs two sockets */

    if (!cfg_cfgfile)
	usage(old_argv);

    gethostname(hostname, MAX_HOSTNAME_LEN);

    if (readcfgfile(cfg_cfgfile) < 0) {
	Alert("Error reading configuration file : %s\n", cfg_cfgfile);
	exit(1);
    }

    ReadEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(cfg_maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
    WriteEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(cfg_maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
    StaticReadEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(cfg_maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
    StaticWriteEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(cfg_maxsock + FD_SETSIZE - 1) / FD_SETSIZE);

    fdtab = (struct fdtab *)calloc(1,
		sizeof(struct fdtab) * (cfg_maxsock));
    for (i = 0; i < cfg_maxsock; i++) {
	fdtab[i].state = FD_STCLOSE;
    }
}

/*
 * this function starts all the proxies. It returns 0 if OK, -1 if not.
 */
int start_proxies() {
    struct proxy *curproxy;
    int one = 1;
    int fd;

    for (curproxy = proxy; curproxy != NULL; curproxy = curproxy->next) {

	if (curproxy->state == PR_STDISABLED)
	    continue;

	if ((fd = curproxy->listen_fd =
	     socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	    Alert("cannot create listening socket for proxy %s. Aborting.\n",
		  curproxy->id);
	    return -1;
	}
	
	if (fd >= cfg_maxsock) {
	    Alert("socket(): not enough free sockets for proxy %s. Raise -n argument. Aborting.\n",
		  curproxy->id);
	    close(fd);
	    return -1;
	}

	if ((fcntl(fd, F_SETFL, O_NONBLOCK) == -1) ||
	    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
			(char *) &one, sizeof(one)) == -1)) {
	    Alert("cannot make socket non-blocking for proxy %s. Aborting.\n",
		  curproxy->id);
	    close(fd);
	    return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) == -1) {
	    Alert("cannot do so_reuseaddr for proxy %s. Continuing.\n",
		  curproxy->id);
	}
	
	if (bind(fd,
		 (struct sockaddr *)&curproxy->listen_addr,
		 sizeof(curproxy->listen_addr)) == -1) {
	    Alert("cannot bind socket for proxy %s. Aborting.\n",
		  curproxy->id);
	    close(fd);
	    return -1;
	}
	
	if (listen(fd, curproxy->maxconn) == -1) {
	    Alert("cannot listen to socket for proxy %s. Aborting.\n",
		  curproxy->id);
	    close(fd);
	    return -1;
	}
	
	/* the function for the accept() event */
	fdtab[fd].read  = &event_accept;
	fdtab[fd].write = NULL; /* never called */
	fdtab[fd].owner = (struct task *)curproxy; /* reference the proxy instead of a task */
	curproxy->state = PR_STRUN;
	fdtab[fd].state = FD_STLISTEN;
	FD_SET(fd, StaticReadEvent);
	fd_insert(fd);
	listeners++;
//	fprintf(stderr,"Proxy %s : socket bound.\n", curproxy->id);
    }
    return 0;
}


int main(int argc, char **argv) {
    init(argc, argv);

    if (mode & MODE_DAEMON) {
	int ret;

	ret = fork();

	if (ret > 0)
	    exit(0); /* parent must leave */
	else if (ret < 0) {
	    Alert("[%s.main()] Cannot fork\n", argv[0]);
	    exit(1); /* there has been an error */
	}
	setpgid(1, 0);
    }

    if (mode & MODE_QUIET) {
	/* detach from the tty */
	fclose(stdin); fclose(stdout); fclose(stderr);
	close(0); close(1); close(2);
    }

    signal(SIGQUIT, dump);
    signal(SIGUSR1, sig_soft_stop);

    /* on very high loads, a sigpipe sometimes happen just between the
     * getsockopt() which tells "it's OK to write", and the following write :-(
     */
#ifndef MSG_NOSIGNAL
    signal(SIGPIPE, SIG_IGN);
#endif

    if (start_proxies() < 0)
	exit(1);

    select_loop();

    exit(0);
}
