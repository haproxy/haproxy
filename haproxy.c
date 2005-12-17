/*
 * HA-Proxy : High Availability-enabled HTTP/TCP proxy - Willy Tarreau
 * willy AT meta-x DOT org.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * ChangeLog :
 *
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
 * TODO: handle properly intermediate incomplete server headers.
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

#define HAPROXY_VERSION "1.0.1"
#define HAPROXY_DATE	"2001/12/19"

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

// max # of regexps per proxy
#define	MAX_REGEXP	10

// max # of matches per regexp
#define	MAX_MATCH	10

#define COOKIENAME_LEN	16
#define SERVERID_LEN	16
#define CONN_RETRIES	3

/* how many bits are needed to code the size of an int (eg: 32bits -> 5) */
#define	INTBITS		5

/* show stats this every millisecond, 0 to disable */
#ifndef STATTIME
#define STATTIME	2000
#endif

#define MINTIME(old, new)	(((new)<0)?(old):(((old)<0||(new)<(old))?(new):(old)))
#define SETNOW(a)		(*a=now)

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
 * there's no need for any carrier cells. This implies
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

#define sizeof_session	sizeof(struct task)
#define sizeof_buffer	sizeof(struct buffer)
#define sizeof_fdtab	sizeof(struct fdtab)
#define sizeof_str256	256


/*
 * different possible states for the sockets
 */
#define FD_STCLOSE	0
#define FD_STLISTEN	1
#define FD_STCONN	2
#define FD_STREADY	3
#define FD_STERROR	4

#define TASK_IDLE	0
#define TASK_RUNNING	1

#define PR_STNEW	0
#define PR_STIDLE	1
#define PR_STRUN	2
#define PR_STDISABLED	3

#define PR_MODE_TCP	0
#define PR_MODE_HTTP	1
#define PR_MODE_HEALTH	2

#define CL_STHEADERS	0
#define CL_STDATA	1
#define CL_STSHUTR	2
#define CL_STSHUTW	3
#define CL_STCLOSE	4

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

/* modes of operation */
#define	MODE_DEBUG	1
#define	MODE_STATS	2
#define	MODE_LOG	4
#define	MODE_DAEMON	8

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
    char data[BUFSIZE];
};

struct server {
    struct server *next;
    char *id;				/* the id found in the cookie */
    struct sockaddr_in addr;		/* the address to connect to */
};

struct task {
    struct task *next, *prev;		/* chaining ... */
    struct task *rqnext;		/* chaining in run queue ... */
    int state;				/* task state : IDLE or RUNNING */
    struct timeval expire;		/* next expiration time for this task, use only for fast sorting */
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
    int conn_redisp;			/* allow reconnection to dispatch in case of errors */
    struct buffer *req;			/* request buffer */
    struct buffer *rep;			/* response buffer */
    struct sockaddr_in cli_addr;	/* the client address */
    struct sockaddr_in srv_addr;	/* the address to connect to */
    char cookie_val[SERVERID_LEN+1];	/* the cookie value, if present */
};

struct proxy {
    int listen_fd;			/* the listen socket */
    int state;				/* proxy state */
    struct sockaddr_in listen_addr;	/* the address we listen to */
    struct sockaddr_in dispatch_addr;	/* the default address to connect to */
    struct server *srv;			/* known servers */
    char *cookie_name;			/* name of the cookie to look for */
    int clitimeout;			/* client I/O timeout (in milliseconds) */
    int srvtimeout;			/* server I/O timeout (in milliseconds) */
    int contimeout;			/* connect timeout (in milliseconds) */
    char *id;				/* proxy id */
    int nbconn;				/* # of active sessions */
    int maxconn;			/* max # of active sessions */
    int conn_retries;			/* number of connect retries left */
    int conn_redisp;			/* allow to reconnect to dispatch in case of errors */
    int mode;				/* mode = PR_MODE_TCP or PR_MODE_HTTP */
    struct task task;			/* active sessions (bi-dir chaining) */
    struct task *rq;			/* sessions in the run queue (unidir chaining) */
    struct proxy *next;
    struct sockaddr_in logsrv1, logsrv2; /* 2 syslog servers */
    char logfac1, logfac2;		/* log facility for both servers. -1 = disabled */
    struct timeval stop_time;		/* date to stop listening, when stopping != 0 */
    int nb_cliexp, nb_srvexp;
    struct hdr_exp cli_exp[MAX_REGEXP];	/* regular expressions for client headers */
    struct hdr_exp srv_exp[MAX_REGEXP];	/* regular expressions for server headers */
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
    **pool_str256   = NULL;

struct proxy *proxy  = NULL;	/* list of all existing proxies */
struct fdtab *fdtab = NULL;	/* array of all the file descriptors */

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

/*********************************************************************/
/*  general purpose functions  ***************************************/
/*********************************************************************/

void display_version() {
    printf("HA-Proxy version " HAPROXY_VERSION " " HAPROXY_DATE"\n");
    printf("Copyright 2000-2001 Willy Tarreau <willy AT meta-x DOT org>\n\n");
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
	    "        -D goes daemon\n"
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

    va_start(argp, fmt);

    gettimeofday(&tv, NULL);
    tm=localtime(&tv.tv_sec);
    fprintf(stderr, "[ALERT] %03d/%02d%02d%02d (%d) : ",
	    tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec, getpid());
    vfprintf(stderr, fmt, argp);
    fflush(stderr);
    va_end(argp);
}


/*
 * Displays the message on stderr with the date and pid.
 */
void Warning(char *fmt, ...) {
    va_list argp;
    struct timeval tv;
    struct tm *tm;

    va_start(argp, fmt);

    gettimeofday(&tv, NULL);
    tm=localtime(&tv.tv_sec);
    fprintf(stderr, "[WARNING] %03d/%02d%02d%02d (%d) : ",
	    tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec, getpid());
    vfprintf(stderr, fmt, argp);
    fflush(stderr);
    va_end(argp);
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
	    Alert("Invalid server name: <%s>\n",str);
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
  

    cmp=tv_cmp(tv1, tv2);
    if (!cmp)
	return 0; /* same dates, null diff */
    else if (cmp<0) {
	struct timeval *tmp=tv1;
	tv1=tv2;
	tv2=tmp;
    }
    ret=(tv1->tv_sec - tv2->tv_sec)*1000;
    if (tv1->tv_usec > tv2->tv_usec)
	ret+=(tv1->tv_usec - tv2->tv_usec)/1000;
    else
	ret-=(tv2->tv_usec - tv1->tv_usec)/1000;
    return (unsigned long) ret;
}

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 */
static inline int tv_cmp_ms(struct timeval *tv1, struct timeval *tv2) {
    if ((tv1->tv_sec > tv2->tv_sec + 1) ||
	((tv1->tv_sec == tv2->tv_sec + 1) && (tv1->tv_usec + 1000000 >= tv2->tv_usec + 1000)))
	return 1;
    else if ((tv2->tv_sec > tv1->tv_sec + 1) ||
	     ((tv2->tv_sec == tv1->tv_sec + 1) && (tv2->tv_usec + 1000000 >= tv1->tv_usec + 1000)))
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

    ret=(tv2->tv_sec - tv1->tv_sec)*1000;
    if (tv2->tv_usec > tv1->tv_usec)
	ret+=(tv2->tv_usec - tv1->tv_usec)/1000;
    else
	ret-=(tv1->tv_usec - tv2->tv_usec)/1000;
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
    
    if ((tv1->tv_sec > tv2->tv_sec + 1) ||
	((tv1->tv_sec == tv2->tv_sec + 1) && (tv1->tv_usec + 1000000 >= tv2->tv_usec + 1000)))
	return 1;
    else if ((tv2->tv_sec > tv1->tv_sec + 1) ||
	     ((tv2->tv_sec == tv1->tv_sec + 1) && (tv2->tv_usec + 1000000 >= tv1->tv_usec + 1000)))
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



/* deletes an FD from the fdsets, and recomputes the maxfd limit */
static inline void fd_delete(int fd) {
    fdtab[fd].state = FD_STCLOSE;
    FD_CLR(fd, StaticReadEvent);
    FD_CLR(fd, StaticWriteEvent);

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

/* puts the task <s> in <p>'s run queue, and returns <s> */
static inline struct task *task_wakeup(struct proxy *p, struct task *s) {
    //    fprintf(stderr,"task_wakeup: proxy %p, task %p\n", p, s);

    if (s->state == TASK_RUNNING)
	return s;
    else {
	s->rqnext = p->rq;
	s->state = TASK_RUNNING;
	return p->rq = s;
    }
}

/* removes the task <s> from <p>'s run queue.
 * <s> MUST be <p>'s first task in the queue.
 * set the run queue to point to the next one, and return it
 */
static inline struct task *task_sleep(struct proxy *p, struct task *s) {
    if (s->state == TASK_RUNNING) {
	p->rq = s->rqnext;
	s->state = TASK_IDLE; /* tell that s has left the run queue */
    }
    return p->rq; /* return next running task */
}

/*
 * removes the task <s> from its wait queue. It must have already been removed
 * from the run queue. A pointer to the task itself is returned.
 */
static inline struct task *task_delete(struct task *s) {
    s->prev->next = s->next;
    s->next->prev = s->prev;
    return s;
}

/*
 * frees  the context associated to a task. It must have been removed first.
 */
static inline void task_free(struct task *t) {
    if (t->req)
	pool_free(buffer, t->req);
    if (t->rep)
	pool_free(buffer, t->rep);
    pool_free(session, t);
}

/* inserts <task> into the list <list>, where it may already be. In this case, it
 * may be only moved or left where it was, depending on its timing requirements.
 * <task> is returned.
 */

struct task *task_queue(struct task *list, struct task *task) {
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


/*
 * This function initiates a connection to the server whose name is in <s->proxy->src->id>,
 * or the dispatch server if <id> not found. It returns 0 if
 * it's OK, -1 if it's impossible.
 */
int connect_server(struct task *s, int usecookie) {
    struct server *srv = s->proxy->srv;
    char *sn = s->cookie_val;
    int one = 1;
    int fd;

    //    fprintf(stderr,"connect_server : s=%p\n",s);

    if (usecookie) {
	while (*sn && srv && strcmp(sn, srv->id)) {
	    srv = srv->next;
	}
	if (!srv || !*sn) { /* server not found, let's use the dispatcher */
	    s->srv_addr = s->proxy->dispatch_addr;
	}
	else {
	    s->srv_addr = srv->addr;
	}
    }
    else
	s->srv_addr = s->proxy->dispatch_addr;

    if ((fd = s->srv_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	fprintf(stderr,"Cannot get a server socket.\n");
	return -1;
    }
	
    if ((fcntl(fd, F_SETFL, O_NONBLOCK)==-1) ||
	(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) == -1)) {
	fprintf(stderr,"Cannot set client socket to non blocking mode.\n");
	close(fd);
	return -1;
    }

    if ((connect(fd, (struct sockaddr *)&s->srv_addr, sizeof(s->srv_addr)) == -1) && (errno != EINPROGRESS)) {
	if (errno == EAGAIN) { /* no free ports left, try again later */
	    fprintf(stderr,"Cannot connect, no free ports.\n");
	    close(fd);
	    return -1;
	}
	else if (errno != EALREADY && errno != EISCONN) {
	    close(fd);
	    return -1;
	}
    }

    fdtab[fd].owner = s;
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
    struct task *s = fdtab[fd].owner;
    struct buffer *b = s->req;
    int ret, max;

    //    fprintf(stderr,"event_cli_read : fd=%d, s=%p\n", fd, s);

    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
	b->r = b->w = b->data;
	max = BUFSIZE - MAXREWRITE;
    }
    else if (b->r > b->w) {
	max = b->data + BUFSIZE - MAXREWRITE - b->r;
    }
    else {
	max = b->w - b->r;
	if (max > BUFSIZE - MAXREWRITE)
	    max = BUFSIZE - MAXREWRITE;
    }

    if (max == 0) {
	FD_CLR(fd, StaticReadEvent);
	//fprintf(stderr, "cli_read(%d) : max=%d, d=%p, r=%p, w=%p, l=%d\n",
	//fd, max, b->data, b->r, b->w, b->l);
	return 0;
    }

    if (fdtab[fd].state != FD_STERROR) {
#ifndef MSG_NOSIGNAL
	int skerr, lskerr;
	lskerr=sizeof(skerr);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
	if (skerr)
		ret = -1;
	else
		ret = recv(fd, b->r, max, 0);
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
	}
	else if (ret == 0)
	    s->res_cr = RES_NULL;
	else if (errno == EAGAIN) /* ignore EAGAIN */
	    return 0;
	else {
	    s->res_cr = RES_ERROR;
	    fdtab[fd].state = FD_STERROR;
	}
    }
    else {
	s->res_cr = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }

    if (s->proxy->clitimeout)
	tv_delayfrom(&s->crexpire, &now, s->proxy->clitimeout);
    else
	tv_eternity(&s->crexpire);

    task_wakeup(s->proxy, s);
    return 0;
}


/*
 * this function is called on a read event from a server socket.
 * It returns 0.
 */
int event_srv_read(int fd) {
    struct task *s = fdtab[fd].owner;
    struct buffer *b = s->rep;
    int ret, max;

    //    fprintf(stderr,"event_srv_read : fd=%d, s=%p\n", fd, s);

    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
	b->r = b->w = b->data;
	max = BUFSIZE - MAXREWRITE;
    }
    else if (b->r > b->w) {
	max = b->data + BUFSIZE - MAXREWRITE - b->r;
    }
    else {
	max = b->w - b->r;
    	if (max > BUFSIZE - MAXREWRITE)
	    max = BUFSIZE - MAXREWRITE;
    }

    if (max == 0) {
	FD_CLR(fd, StaticReadEvent);
	//fprintf(stderr, "srv_read(%d) : max=%d, d=%p, r=%p, w=%p, l=%d\n",
	//fd, max, b->data, b->r, b->w, b->l);
	return 0;
    }

    if (fdtab[fd].state != FD_STERROR) {
#ifndef MSG_NOSIGNAL
	int skerr, lskerr;
	lskerr=sizeof(skerr);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &skerr, &lskerr);
	if (skerr)
		ret = -1;
	else
		ret = recv(fd, b->r, max, 0);
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
	}
	else if (ret == 0)
	    s->res_sr = RES_NULL;
	else if (errno != EAGAIN) /* ignore EAGAIN */
	    return 0;
	else {
	    s->res_sr = RES_ERROR;
	    fdtab[fd].state = FD_STERROR;
	}
    }
    else {
	s->res_sr = RES_ERROR;
	fdtab[fd].state = FD_STERROR;
    }


    if (s->proxy->srvtimeout)
	tv_delayfrom(&s->srexpire, &now, s->proxy->srvtimeout);
    else
	tv_eternity(&s->srexpire);

    task_wakeup(s->proxy, s);
    return 0;
}

/*
 * this function is called on a write event from a client socket.
 * It returns 0.
 */
int event_cli_write(int fd) {
    struct task *s = fdtab[fd].owner;
    struct buffer *b = s->rep;
    int ret, max;

    //    fprintf(stderr,"event_cli_write : fd=%d, s=%p\n", fd, s);

    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
	b->r = b->w = b->data;
	//	max = BUFSIZE;		BUG !!!!
	max = 0;
    }
    else if (b->r > b->w) {
	max = b->r - b->w;
    }
    else
	max = b->data + BUFSIZE - b->w;
    
    if (max == 0) {
	FD_CLR(fd, StaticWriteEvent);
	//fprintf(stderr, "cli_write(%d) : max=%d, d=%p, r=%p, w=%p, l=%d\n",
	//fd, max, b->data, b->r, b->w, b->l);
	s->res_cw = RES_NULL;
	return 0;
    }

    if (fdtab[fd].state != FD_STERROR) {
#ifndef MSG_NOSIGNAL
	int skerr, lskerr;
#endif
	if (max == 0) { /* nothing to write, just make as if we were never called */
		s->res_cw = RES_NULL;
		task_wakeup(s->proxy, s);
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

    task_wakeup(s->proxy, s);
    return 0;
}


/*
 * this function is called on a write event from a server socket.
 * It returns 0.
 */
int event_srv_write(int fd) {
    struct task *s = fdtab[fd].owner;
    struct buffer *b = s->req;
    int ret, max;

    //fprintf(stderr,"event_srv_write : fd=%d, s=%p\n", fd, s);

    if (b->l == 0) { /* let's realign the buffer to optimize I/O */
	b->r = b->w = b->data;
	//	max = BUFSIZE;		BUG !!!!
	max = 0;
    }
    else if (b->r > b->w) {
	max = b->r - b->w;
    }
    else
	max = b->data + BUFSIZE - b->w;
    
    if (max == 0) {
	FD_CLR(fd, StaticWriteEvent);
	//fprintf(stderr, "srv_write(%d) : max=%d, d=%p, r=%p, w=%p, l=%d\n",
	//fd, max, b->data, b->r, b->w, b->l);
	s->res_sw = RES_NULL;
	return 0;
    }

    if (fdtab[fd].state != FD_STERROR) {
#ifndef MSG_NOSIGNAL
	int skerr, lskerr;
#endif
	fdtab[fd].state = FD_STREADY;
	if (max == 0) { /* nothing to write, just make as if we were never called, except to finish a connect() */
	    s->res_sw = RES_NULL;
	    task_wakeup(s->proxy, s);
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

    task_wakeup(s->proxy, s);
    return 0;
}


/*
 * this function is called on a read event from a listen socket, corresponding
 * to an accept. It returns 0.
 */
int event_accept(int fd) {
    struct proxy *p = (struct proxy *)fdtab[fd].owner;
    struct task *s;
    int laddr;
    int cfd;
    int one = 1;

    if ((s = pool_alloc(session)) == NULL) { /* disable this proxy for a while */
	Alert("out of memory in event_accept().\n");
	FD_CLR(fd, StaticReadEvent);
	p->state = PR_STIDLE;
	return 0;
    }

    laddr = sizeof(s->cli_addr);
    if ((cfd = accept(fd, (struct sockaddr *)&s->cli_addr, &laddr)) == -1) {
	pool_free(session, s);
	return 0;
    }

    if ((fcntl(cfd, F_SETFL, O_NONBLOCK) == -1) ||
	(setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY,
		    (char *) &one, sizeof(one)) == -1)) {
	Alert("accept(): cannot set the socket in non blocking mode. Giving up\n");
	close(cfd);
	pool_free(session, s);
	return 0;
    }

    if ((p->mode == PR_MODE_TCP || p->mode == PR_MODE_HTTP)
	&& (p->logfac1 >= 0 || p->logfac2 >= 0)) {
	struct sockaddr_in peername, sockname;
	unsigned char *pn, *sn;
	int namelen;
	char message[256];

	namelen = sizeof(peername);
	getpeername(cfd, (struct sockaddr *)&peername, &namelen);
	pn = (unsigned char *)&peername.sin_addr;

	namelen = sizeof(sockname);
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

    s->proxy = p;
    s->state = TASK_IDLE;
    s->cli_state = (p->mode == PR_MODE_HTTP) ?  CL_STHEADERS : CL_STDATA; /* no HTTP headers for non-HTTP proxies */
    s->srv_state = SV_STIDLE;
    s->req = s->rep = NULL; /* will be allocated later */
    s->cookie_val[0] = 0;
    s->res_cr = s->res_cw = s->res_sr = s->res_sw = RES_SILENT;
    s->rqnext = NULL; /* task not in run queue */
    s->next = s->prev = NULL;
    s->cli_fd = cfd;
    s->conn_retries = p->conn_retries;
    s->conn_redisp  = p->conn_redisp;

    if ((s->req = pool_alloc(buffer)) == NULL) { /* no memory */
	close(cfd); /* nothing can be done for this fd without memory */
	pool_free(session, s);
	return 0;
    }
    s->req->l = 0;
    s->req->h = s->req->r = s->req->lr = s->req->w = s->req->data;		/* r and w will be reset further */

    if ((s->rep = pool_alloc(buffer)) == NULL) { /* no memory */
	pool_free(buffer, s->req);
	close(cfd); /* nothing can be done for this fd without memory */
	pool_free(session, s);
	return 0;
    }
    s->rep->l = 0;
    s->rep->h = s->rep->r = s->rep->lr = s->rep->w = s->rep->data;

    fdtab[cfd].read  = &event_cli_read;
    fdtab[cfd].write = &event_cli_write;
    fdtab[cfd].owner = s;
    fdtab[cfd].state = FD_STREADY;

    if (p->mode == PR_MODE_HEALTH) {  /* health check mode, no client reading */
	FD_CLR(cfd, StaticReadEvent);
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

    s->expire = s->crexpire;

    task_queue(LIST_HEAD(p->task), s);
    task_wakeup(p, s);

    p->nbconn++;
    actconn++;
    totalconn++;

    // fprintf(stderr, "accepting from %p => %d conn, %d total\n", p, actconn, totalconn);

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
int buffer_replace(struct buffer *b, char *pos, char *str, char *end) {
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

    if (b->r >= end) b->r += delta;
    if (b->w >= end) b->w += delta;
    if (b->h >= end) b->h += delta;
    if (b->lr >= end) b->lr += delta;
    b->l += delta;

    return delta;
}

/* same except that the string len is given */
int buffer_replace2(struct buffer *b, char *pos, char *str, int len, char *end) {
    int delta;

    delta = len - (end - pos);

    if (delta + b->r >= b->data + BUFSIZE)
	return 0;  /* no space left */

    /* first, protect the end of the buffer */
    memmove(end + delta, end, b->data + b->l - end);

    /* now, copy str over pos */
    memcpy(pos, str,len);

    if (b->r >= end) b->r += delta;
    if (b->w >= end) b->w += delta;
    if (b->h >= end) b->h += delta;
    if (b->lr >= end) b->lr += delta;
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
int process_cli(struct task *t) {
    int s = t->srv_state;
    int c = t->cli_state;
    struct buffer *req = t->req;
    struct buffer *rep = t->rep;

    //fprintf(stderr,"process_cli: c=%d, s=%d, cr=%d, cw=%d, sr=%d, sw=%d\n", c, s,
    //FD_ISSET(t->cli_fd, StaticReadEvent), FD_ISSET(t->cli_fd, StaticWriteEvent),
    //FD_ISSET(t->srv_fd, StaticReadEvent), FD_ISSET(t->srv_fd, StaticWriteEvent)
    //);
    if (c == CL_STHEADERS) {
	char *ptr;
	
	/* read timeout, read error, or last read : give up */
	if (t->res_cr == RES_ERROR || t->res_cr == RES_NULL ||
	    tv_cmp2_ms(&t->crexpire, &now) <= 0) {
	    FD_CLR(t->cli_fd, StaticReadEvent);
	    FD_CLR(t->cli_fd, StaticWriteEvent);
	    fd_delete(t->cli_fd);
	    close(t->cli_fd);
	    tv_eternity(&t->crexpire);
	    t->cli_state = CL_STCLOSE;
	    return 1;
	}
	else if (t->res_cr == RES_SILENT) {
	    return 0;
	}
	/* now we know that there are headers to process */

	if (req->l >= BUFSIZE - MAXREWRITE) {
	    /* buffer full : stop reading till we free some space */
	    FD_CLR(t->cli_fd, StaticReadEvent);
	    tv_eternity(&t->crexpire);
	}

	ptr = req->lr;
	req->lr = req->r; /* tell that bytes up to <lr> have been read and processes */
	while (ptr < req->r) {
	    /* look for the end of the current header */
	    while (ptr < req->r && *ptr != '\n' && *ptr != '\r')
		ptr++;
	    
	    if (ptr < req->r) {
		/* now we have one complete client header between req->h and ptr */
		if (ptr == req->h) { /* empty line, end of headers */
		    t->cli_state = CL_STDATA;
		    //req->lr = ptr; /* tell that bytes up to <lr> have been read and processes */
		    return 1;
		}
		else {
		    /* we have one standard header */
		    if (mode & MODE_DEBUG) {
			int len, max;
			len = sprintf(trash, "clihdr[%04x:%04x]: ", (unsigned  short)t->cli_fd, (unsigned short)t->srv_fd);
			max = ptr - req->h;
			if (max > sizeof(trash) - len - 2)
			    max = sizeof(trash) - len - 2;
			strncat(trash+len, req->h, max); len += max;
			trash[len++] = '\n';
			trash[len] = '\0';
			//    write(1,"Client Header found: ",21);
		    	//    write(1, req->h, ptr - req->h);
		    	//    write(1, "\n", 1);
			write(1, trash, len);
		    }

		    if ((req->r >= req->h + 8) && (t->proxy->cookie_name != NULL)
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

			    if ((p2-p1 == strlen(t->proxy->cookie_name)) &&
				(strncmp(p1, t->proxy->cookie_name, p2-p1) == 0)) {
				/* Cool... it's the right one */
				int l;
				l = (p4 - p3) < SERVERID_LEN ?
				    (p4 - p3) : SERVERID_LEN;
				strncpy(t->cookie_val, p3, l);
				t->cookie_val[l] = 0;
				break;
			    }
			    else {
//				fprintf(stderr,"Ignoring unknown cookie : ");
//				write(2, p1, p2-p1);
//				fprintf(stderr," = ");
//				write(2, p3, p4-p3);
//				fprintf(stderr,"\n");
			    }
			    /* we'll have to look for another cookie ... */
			    p1 = p4;
			}
			/* FIXME */
//			fprintf(stderr,"Cookie is now: <%s>\n", s->cookie_val);
		    }
		    else if (t->proxy->nb_cliexp) { /* try headers regexps */
			struct proxy *p = t->proxy;
			int exp;
			char term;

			term = *ptr;
			*ptr = '\0';
			for (exp=0; exp < p->nb_cliexp; exp++) {
			    if (regexec(p->cli_exp[exp].preg, req->h, MAX_MATCH, pmatch, 0) == 0) {
				int len = exp_replace(trash, req->h, p->cli_exp[exp].replace, pmatch);
				ptr += buffer_replace2(req, req->h, trash, len, ptr);
				break;
			    }
			}
			*ptr = term; /* restore the string terminator */
		    }
		    
		    /* look for the beginning of the next header */
		    if (ptr < req->r) {
			if (*ptr == '\n') {
			    if ((++ptr < req->r) && (*ptr == '\r'))
				ptr++;
			}
			else if (*ptr == '\r') {
			    if ((++ptr < req->r) && (*ptr == '\n'))
				ptr++;
			}
			req->h = ptr;
		    }
		}
	    }
	    else if (ptr >= req->data + BUFSIZE - MAXREWRITE) { /* no more headers */
		t->cli_state = CL_STDATA;
		FD_CLR(t->cli_fd, StaticReadEvent);
		tv_eternity(&t->crexpire);
		//req->lr = ptr; /* tell that bytes up to <lr> have been read and processes */
		return 1;
	    }
	}
	//req->lr = ptr; /* tell that bytes up to <lr> have been read and processes */
    }
    else if (c == CL_STDATA) {
	/* read or write error */
	if (t->res_cw == RES_ERROR || t->res_cr == RES_ERROR) {
	    FD_CLR(t->cli_fd, StaticReadEvent);
	    FD_CLR(t->cli_fd, StaticWriteEvent);
	    tv_eternity(&t->crexpire);
	    tv_eternity(&t->cwexpire);
	    close(t->cli_fd);
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

	if (req->l >= BUFSIZE - MAXREWRITE) { /* no room to read more data */
	    if (FD_ISSET(t->cli_fd, StaticReadEvent)) {
		FD_CLR(t->cli_fd, StaticReadEvent);
		tv_eternity(&t->crexpire);
	    }
	}
	else {
	    if (! FD_ISSET(t->cli_fd, StaticReadEvent)) {
		FD_SET(t->cli_fd, StaticReadEvent);
		if (t->proxy->clitimeout)
		    tv_delayfrom(&t->crexpire, &now, t->proxy->clitimeout);
		else
		    tv_eternity(&t->crexpire);
	    }
	}

	if ((rep->l == 0) ||
	    ((s == SV_STHEADERS) && (rep->w == rep->h))) {
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
	    || (tv_cmp2_ms(&t->crexpire, &now) <= 0)) {
	    
	    FD_CLR(t->cli_fd, StaticWriteEvent);
	    tv_eternity(&t->cwexpire);
	    fd_delete(t->cli_fd);
	    close(t->cli_fd);
	    t->cli_state = CL_STCLOSE;
	    return 1;
	}
	else if ((rep->l == 0) ||
	    ((s == SV_STHEADERS) && (rep->w == rep->h))) {
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
	    s == SV_STCLOSE || tv_cmp2_ms(&t->cwexpire, &now) <= 0) {
	    FD_CLR(t->cli_fd, StaticReadEvent);
	    tv_eternity(&t->crexpire);
	    fd_delete(t->cli_fd);
	    close(t->cli_fd);
	    t->cli_state = CL_STCLOSE;
	    return 1;
	}
	else if (req->l >= BUFSIZE - MAXREWRITE) { /* no room to read more data */
	    if (FD_ISSET(t->cli_fd, StaticReadEvent)) {
		FD_CLR(t->cli_fd, StaticReadEvent);
		tv_eternity(&t->crexpire);
	    }
	}
	else {
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
	if (mode & MODE_DEBUG) {
	    int len;
	    len = sprintf(trash, "clicls[%04x:%04x]\n", t->cli_fd, t->srv_fd);
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
int process_srv(struct task *t) {
    int s = t->srv_state;
    int c = t->cli_state;
    struct buffer *req = t->req;
    struct buffer *rep = t->rep;

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
	    if (connect_server(t, 1) == 0) { /* initiate a connection to the server */
		//fprintf(stderr,"0: c=%d, s=%d\n", c, s);
		t->srv_state = SV_STCONN;
	    }
	    else { /* try again */
		while (t->conn_retries-- > 0) {
		    if (connect_server(t, !t->conn_redisp || (t->conn_retries > 0)) == 0) {
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
	    FD_CLR(t->srv_fd, StaticWriteEvent);
	    fd_delete(t->srv_fd);
	    close(t->srv_fd);
	    t->conn_retries--;
	    if (t->conn_retries >= 0 &&
		connect_server(t, !t->conn_redisp || (t->conn_retries > 0)) == 0) {
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
	    }
	    else
		t->srv_state = SV_STHEADERS;
	    return 1;
	}
    }
    else if (s == SV_STHEADERS) { /* receiving server headers */
	char *ptr;
	int header_processed = 0;

	/* read or write error */
	if (t->res_sw == RES_ERROR || t->res_sr == RES_ERROR) {
	    FD_CLR(t->srv_fd, StaticReadEvent);
	    FD_CLR(t->srv_fd, StaticWriteEvent);
	    tv_eternity(&t->srexpire);
	    tv_eternity(&t->swexpire);
	    close(t->srv_fd);
	    t->srv_state = SV_STCLOSE;
	    return 1;
	}
	/* read timeout, last read, or end of client write */
	else if (t->res_sr == RES_NULL || c == CL_STSHUTW || c == CL_STCLOSE ||
		 tv_cmp2_ms(&t->srexpire, &now) <= 0) {
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

	if (rep->l >= BUFSIZE - MAXREWRITE) { /* no room to read more data */
	    if (FD_ISSET(t->srv_fd, StaticReadEvent)) {
		FD_CLR(t->srv_fd, StaticReadEvent);
		tv_eternity(&t->srexpire);
	    }
	}

	/* now parse the partial (or complete) headers */

	//fprintf(stderr,"rep->data=%p, rep->lr=%p, rep->r=%p, rep->l=%d\n", rep->data, rep->lr, rep->r, rep->l);
	ptr = rep->lr;
	rep->lr = rep->r;

	//write(1,"rep=",4); write(1, ptr, 4); write(1,"\n",1);
	//write(1,"hdr=",4); write(1, rep->h, 4); write(1,"\n",1);
	while (ptr < rep->r) {
	    /* look for the end of the current header */
	    while (ptr < rep->r && *ptr != '\n' && *ptr != '\r')
		ptr++;
	    
	    if (ptr < rep->r) {
		//write(1,"ptr=",4); write(1, ptr, 4); write(1,"\n",1);
		/* now we have one complete header between rep->h and ptr */
		header_processed = 1;
		if (ptr == rep->h) { /* empty line, end of headers */
		    t->srv_state = SV_STDATA;
		    //rep->lr = ptr; /* tell that bytes up to <lr> have been read and processes */
		    return 1;
		}
		else {
		    /* we have one standard header */
		    if (mode & MODE_DEBUG) {
			int len, max;
			len = sprintf(trash, "srvhdr[%04x:%04x]: ", (unsigned  short)t->cli_fd, (unsigned short)t->srv_fd);
			max = ptr - rep->h;
			if (max > sizeof(trash) - len - 2)
			    max = sizeof(trash) - len - 2;
			strncat(trash+len, rep->h, max); len += max;
			trash[len++] = '\n';
			trash[len] = '\0';
			write(1, trash, len);
			//    write(1,"Server Header found: ",21);
		    	//    write(1, rep->h, ptr-rep->h);
		    	//    write(1, "\n", 1);
		    }

		    if (t->proxy->nb_srvexp) { /* try headers regexps */
			struct proxy *p = t->proxy;
			int exp;
			char term;

			term = *ptr;
			*ptr = '\0';
			for (exp=0; exp < p->nb_srvexp; exp++) {
			    if (regexec(p->srv_exp[exp].preg, rep->h, MAX_MATCH, pmatch, 0) == 0) {
				int len = exp_replace(trash, rep->h, p->srv_exp[exp].replace, pmatch);
				ptr += buffer_replace2(rep, rep->h, trash, len, ptr);
				break;
			    }
			}
			*ptr = term; /* restore the string terminator */
		    }

		    /* look for the beginning of the next header */
		    if (ptr < rep->r) {
			if (*ptr == '\n') {
			    if ((++ptr < rep->r) && (*ptr == '\r'))
				ptr++;
			}
			else if (*ptr == '\r') {
			    if ((++ptr < rep->r) && (*ptr == '\n'))
				ptr++;
			}
			rep->h = ptr;
		    }
		}
		//// rep->lr = ptr;
		//rep->lr = rep->h;
	    }
	}

	if ((rep->l < BUFSIZE - MAXREWRITE) && ! FD_ISSET(t->srv_fd, StaticReadEvent)) {
	    FD_SET(t->srv_fd, StaticReadEvent);
	    if (t->proxy->srvtimeout)
		tv_delayfrom(&t->srexpire, &now, t->proxy->srvtimeout);
	    else
		tv_eternity(&t->srexpire);
	}

	/* be nice with the client side which would like to send a complete header */
	return header_processed;
	//return 0;
    }
    else if (s == SV_STDATA) {
	/* read or write error */
	if (t->res_sw == RES_ERROR || t->res_sr == RES_ERROR) {
	    FD_CLR(t->srv_fd, StaticReadEvent);
	    FD_CLR(t->srv_fd, StaticWriteEvent);
	    tv_eternity(&t->srexpire);
	    tv_eternity(&t->swexpire);
	    close(t->srv_fd);
	    t->srv_state = SV_STCLOSE;
	    return 1;
	}
	/* read timeout, last read, or end of client write */
	else if (t->res_sr == RES_NULL || c == CL_STSHUTW || c == CL_STCLOSE ||
		 tv_cmp2_ms(&t->srexpire, &now) <= 0) {

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

	    FD_CLR(t->srv_fd, StaticWriteEvent);
	    tv_eternity(&t->swexpire);
	    fd_delete(t->srv_fd);
	    close(t->srv_fd);
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

	    FD_CLR(t->srv_fd, StaticReadEvent);
	    tv_eternity(&t->srexpire);
	    fd_delete(t->srv_fd);
	    close(t->srv_fd);
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
	if (mode & MODE_DEBUG) {
	    int len;
	    len = sprintf(trash, "srvcls[%04x:%04x]\n", t->cli_fd, t->srv_fd);
	    write(1, trash, len);
	}
	return 0;
    }
    return 0;
}


/*
 * puts a task back to the wait queue in a clean state, or
 * cleans up its resources if it must be deleted.
 */
void process_task(struct task *t) {

    if (t->cli_state != CL_STCLOSE || t->srv_state != SV_STCLOSE) {
	struct timeval min1, min2;
	t->res_cw = t->res_cr = t->res_sw = t->res_sr = RES_SILENT;

	tv_min(&min1, &t->crexpire, &t->cwexpire);
	tv_min(&min2, &t->srexpire, &t->swexpire);
	tv_min(&min1, &min1, &t->cnexpire);
	tv_min(&t->expire, &min1, &min2);

	/* restore t to its place in the task list */
	task_queue(LIST_HEAD(t->proxy->task), t);

	return; /* nothing more to do */
    }

    t->proxy->nbconn--;
    actconn--;
    
    if (mode & MODE_DEBUG) {
	int len;
	len = sprintf(trash, "closed[%04x:%04x]\n", t->cli_fd, t->srv_fd);
	write(1, trash, len);
    }

    /* the task MUST not be in the run queue anymore */
    task_delete(t);
    task_free(t);
}


#if STATTIME > 0
int stats(void);
#endif

/*
 * Main select() loop.
 */

void select_loop() {
  int next_time;
#if STATTIME > 0
  int time2;
#endif
  int status;
  int fd,i;
  struct timeval delta;
  int readnotnull, writenotnull;
  struct proxy *p;

  /* stop when there's no connection left and we don't allow them anymore */
  while (actconn || listeners > 0) {
      next_time = -1;
      tv_now(&now);

      maintain_proxies();
	  
#if STATTIME > 0
      time2 = stats();
      //      fprintf(stderr,"                stats = %d\n", time2);
      next_time = MINTIME(time2, next_time);
#endif

      if (next_time >= 0) {
	  /* Convert to timeval */
	  delta.tv_sec=next_time/1000; 
	  delta.tv_usec=(next_time%1000)*1000;
      }


      /* let's restore fdset state */

      readnotnull = 0; writenotnull = 0;
      for (i = 0; i < (cfg_maxsock + 3 + FD_SETSIZE - 1)/(8*sizeof(int)); i++) {
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
      
      tv_now(&now);
      if (status > 0) { /* must proceed with events */

	  int fds;
	  char count;
	  
	  for (fds = 0; (fds << INTBITS) < maxfd; fds++)
	      if ((((int *)(ReadEvent))[fds] | ((int *)(WriteEvent))[fds]) != 0)
		  for (count = 1<<INTBITS, fd = fds << INTBITS; count && fd < maxfd; count--, fd++) {
		      
		      if (fdtab[fd].state == FD_STCLOSE)
			  continue;

		      if (FD_ISSET(fd, WriteEvent))
			  fdtab[fd].write(fd);
		      
		      if (FD_ISSET(fd, ReadEvent))
			  fdtab[fd].read(fd);
		  }
      }
      else {
	  //	  fprintf(stderr,"select returned %d, maxfd=%d\n", status, maxfd);
      }

      for (p = proxy; p; p = p->next) {
	  struct task *t, *tnext;
	  tnext = ((struct task *)LIST_HEAD(p->task))->next;
	  while ((t = tnext) != LIST_HEAD(p->task)) { /* we haven't looped ? */
	      tnext = t->next;

	      /* wakeup expired entries. It doesn't matter if they are
	       * already running because of a previous event
	       */
	      if (tv_cmp2_ms(&t->expire, &now) <= 0) {
		  //		  fprintf(stderr,"WQ: expiring task %p : rq=%p\n", t, p->rq);
		  task_wakeup(p, t);
	      }
	      else {
		  //		  fprintf(stderr,"WQ: ignoring task %p : rq=%p\n", t, p->rq);
		  break;
	      }
	  }

	  /* process each task in the run queue now. Each task may be deleted
	   * since we only use tnext.
	   */
	  tnext = p->rq;
	  while ((t = tnext) != NULL) {
	      int fsm_resync = 0;

	      tnext = t->rqnext;
	      task_sleep(p, t);

	      do {
		  fsm_resync = 0;
		  //fprintf(stderr,"before_cli:cli=%d, srv=%d\n", t->cli_state, t->srv_state);
		  fsm_resync |= process_cli(t);
		  //fprintf(stderr,"cli/srv:cli=%d, srv=%d\n", t->cli_state, t->srv_state);
		  fsm_resync |= process_srv(t);
		  //fprintf(stderr,"after_srv:cli=%d, srv=%d\n", t->cli_state, t->srv_state);
	      } while (fsm_resync);

	      // task_queue(LIST_HEAD(p->task), t);  /* restore t to its place in the task list */
	      // it has been moved to process_task which was more logical.
	      process_task(t);
	  }
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
		    fprintf(stderr,
			    "\n active   total  tsknew tskgood tskleft tskrght tsknsch tsklsch tskrsch\n");
		if (lines>1) {
			fprintf(stderr,"%07d %07d %07d %07d %07d %07d %07d %07d %07d\n",
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
 * select_loop().
 */
static int maintain_proxies(void) {
    struct proxy *p;

    p = proxy;

    if (stopping) {
	while (p) {
	    if (p->state != PR_STDISABLED) {
		if (stopping && (tv_remain(&now, &p->stop_time) == 0)) {
		    FD_CLR(p->listen_fd, StaticReadEvent);
		    close(p->listen_fd);
		    p->state = PR_STDISABLED;
		    listeners--;
		}
	    }
	    p = p->next;
	}
	return -1;
    }

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

    return -1;
}

/*
 * this function disables health-check servers so that the process will quickly be ignored
 * by load balancers.
 */
static void soft_stop(void) {
    struct proxy *p;

    stopping = 1;
    p = proxy;
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
    struct proxy *p;

    for (p = proxy; p; p = p->next) {
	struct task *t, *tnext;
	tnext = ((struct task *)LIST_HEAD(p->task))->next;
	while ((t = tnext) != LIST_HEAD(p->task)) { /* we haven't looped ? */
	    tnext = t->next;
	    fprintf(stderr,"[dump] wq: task %p, still %ld ms, "
		    "cli=%d, srv=%d, cr=%d, cw=%d, sr=%d, sw=%d, "
		    "req=%d, rep=%d, clifd=%d\n",
		    t, tv_remain(&now, &t->expire),
		    t->cli_state,
		    t->srv_state,
		    FD_ISSET(t->cli_fd, StaticReadEvent),
		    FD_ISSET(t->cli_fd, StaticWriteEvent),
		    FD_ISSET(t->srv_fd, StaticReadEvent),
		    FD_ISSET(t->srv_fd, StaticWriteEvent),
		    t->req->l, t->rep?t->rep->l:0, t->cli_fd
		    );
	}
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
    char *cmd;
    char *args[10];
    int arg;
    int cfgerr = 0;

    struct proxy *curproxy = NULL;
    struct server *newsrv = NULL;

    if ((f=fopen(file,"r")) == NULL)
	return -1;

    while (fgets(line = thisline, sizeof(thisline), f) != NULL) {
	linenum++;
	/* skips leading spaces */
	while (isspace(*line))
	    line++;

	/* cleans up line contents */
	cmd = line;
	while (*cmd) {
	    if (*cmd == '#' || *cmd == ';' || *cmd == '\n' || *cmd == '\r')
		*cmd = 0; /* end of string, end of loop */
	    else
		cmd++;
	}

	if (*line == 0)
	    continue;
	
	/* fills args[0..9] with the line contents */
	for (arg=0; arg<9; arg++) {
	    int escaped = 0;

	    args[arg] = line;
	    while (*line && (escaped || !isspace(*line))) {
	        if (!escaped) {
		    if (*line == '\\')
			escaped = 1; 
		}
		else
		    escaped = 0;
		line++;
	    }

	    if (*line) {
		*(line++) = 0;
		while (isspace(*line))
		    line++;
	    }
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
	    curproxy->task.prev = curproxy->task.next = LIST_HEAD(curproxy->task);
	    curproxy->rq = NULL;
	    /* set default values */
	    curproxy->maxconn = cfg_maxpconn;
	    curproxy->conn_retries = CONN_RETRIES;
	    curproxy->conn_redisp = 0;
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
	else if (!strcmp(args[0], "redisp")) {  /* enable reconnections to dispatch */
	    curproxy->conn_redisp = 1;
	}
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
	else if (!strcmp(args[0], "server")) {  /* server address */
	    if (strchr(args[2], ':') == NULL) {
		Alert("parsing [%s:%d] : <server> expects <name> and <addr:port> as arguments.\n",
		      file, linenum);
		return -1;
	    }
	    if ((newsrv = (struct server *)calloc(1, sizeof(struct server)))
		== NULL) {
		Alert("parsing [%s:%d] : out of memory\n", file, linenum);
		exit(1);
	    }
	    newsrv->next = curproxy->srv;
	    curproxy->srv = newsrv;
	    newsrv->id = strdup(args[1]);
	    newsrv->addr = *str2sa(args[2]);
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
	else if (!strcmp(args[0], "cliexp")) {  /* client regex */
	    regex_t *preg;
	    if (curproxy->nb_cliexp >= MAX_REGEXP) {
		Alert("parsing [%s:%d] : too many client expressions. Continuing.\n",
		      file, linenum);
		continue;
	    }

	    if (*(args[1]) == 0 || *(args[2]) == 0) {
		Alert("parsing [%s:%d] : <cliexp> expects <search> and <replace> as arguments.\n",
		      file, linenum);
		return -1;
	    }

	    preg = calloc(1, sizeof(regex_t));
	    if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
		Alert("parsing [%s:%d] : bad regular expression <%s>.\n", file, linenum, args[1]);
		return -1;
	    }
	    curproxy->cli_exp[curproxy->nb_cliexp].preg = preg;
	    curproxy->cli_exp[curproxy->nb_cliexp].replace = strdup(args[2]);
	    curproxy->nb_cliexp++;
	}
	else if (!strcmp(args[0], "srvexp")) {  /* server regex */
	    regex_t *preg;
	    if (curproxy->nb_srvexp >= MAX_REGEXP) {
		Alert("parsing [%s:%d] : too many server expressions. Continuing.\n",
		      file, linenum);
		continue;
	    }

	    if (*(args[1]) == 0 || *(args[2]) == 0) {
		Alert("parsing [%s:%d] : <srvexp> expects <search> and <replace> as arguments.\n",
		      file, linenum);
		return -1;
	    }

	    preg = calloc(1, sizeof(regex_t));
	    if (regcomp(preg, args[1], REG_EXTENDED) != 0) {
		Alert("parsing [%s:%d] : bad regular expression <%s>.\n", file, linenum, args[1]);
		return -1;
	    }
	    //	    fprintf(stderr,"before=<%s> after=<%s>\n", args[1], args[2]);
	    curproxy->srv_exp[curproxy->nb_srvexp].preg = preg;
	    curproxy->srv_exp[curproxy->nb_srvexp].replace = strdup(args[2]);
	    curproxy->nb_srvexp++;
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
	if (curproxy->mode == PR_MODE_TCP || curproxy->mode == PR_MODE_HEALTH) { /* TCP PROXY or HEALTH CHECK */
	    if (curproxy->cookie_name != NULL) {
		Warning("parsing %s : cookie will be ignored for listener %s.\n",
			file, curproxy->id);
	    }
	    if ((newsrv = curproxy->srv) != NULL) {
		Warning("parsing %s : servers will be ignored for listener %s.\n",
			file, curproxy->id);
	    }
	    if (curproxy->nb_srvexp) {
		Warning("parsing %s : server regular expressions will be ignored for listener %s.\n",
			file, curproxy->id);
	    }
	    if (curproxy->nb_cliexp) {
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
	fprintf(stderr,
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
		mode |= MODE_DAEMON;
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
		(cfg_maxsock + 3 + FD_SETSIZE - 1) / FD_SETSIZE);
    WriteEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(cfg_maxsock + 3 + FD_SETSIZE - 1) / FD_SETSIZE);
    StaticReadEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(cfg_maxsock + 3 + FD_SETSIZE - 1) / FD_SETSIZE);
    StaticWriteEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(cfg_maxsock + 3 + FD_SETSIZE - 1) / FD_SETSIZE);

    fdtab = (struct fdtab *)calloc(1,
		sizeof(struct fdtab) * (cfg_maxsock + 3));
    for (i = 0; i < cfg_maxsock + 3; i++) {
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
	fdtab[fd].owner = (struct task *)curproxy; /* reference the proxy */
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

	/* detach from the tty */
	close(0); close(1); close(2);
	setpgid(1, 0);
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
