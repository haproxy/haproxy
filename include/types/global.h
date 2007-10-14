/*
  include/types/global.h
  Global variables.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _TYPES_GLOBAL_H
#define _TYPES_GLOBAL_H

#include <netinet/in.h>

#include <common/config.h>
#include <types/task.h>

/* modes of operation (global.mode) */
#define	MODE_DEBUG	1
#define	MODE_STATS	2
#define	MODE_LOG	4
#define	MODE_DAEMON	8
#define	MODE_QUIET	16
#define	MODE_CHECK	32
#define	MODE_VERBOSE	64
#define	MODE_STARTING	128
#define	MODE_FOREGROUND	256

/* list of last checks to perform, depending on config options */
#define LSTCHK_CAP_BIND	0x00000001	/* check that we can bind to any port */
#define LSTCHK_CTTPROXY	0x00000002	/* check that tproxy is enabled */
#define LSTCHK_NETADM	0x00000004	/* check that we have CAP_NET_ADMIN */
#define LSTCHK_TCPSPLICE	0x00000008	/* check that linux tcp_splice is enabled */

/* FIXME : this will have to be redefined correctly */
struct global {
	int uid;
	int gid;
	int nbproc;
	int maxconn;
	int maxsock;		/* max # of sockets */
	int rlimit_nofile;	/* default ulimit-n value : 0=unset */
	int rlimit_memmax;	/* default ulimit-d in megs value : 0=unset */
	int mode;
	int last_checks;
	int spread_checks;
	char *chroot;
	char *pidfile;
	int logfac1, logfac2;
	int loglev1, loglev2;
	struct sockaddr_in logsrv1, logsrv2;
	struct {
		int maxpollevents; /* max number of poll events at once */
	} tune;
};

extern struct global global;
extern char *progname;          /* program name */
extern int  pid;                /* current process id */
extern int  actconn;            /* # of active sessions */
extern int listeners;
extern char trash[BUFSIZE];
extern const int zero;
extern const int one;
extern const struct linger nolinger;
extern int stopping;	/* non zero means stopping in progress */

#endif /* _TYPES_GLOBAL_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
