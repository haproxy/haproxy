/*
 * Copyright (C) 2010-2022 Willy Tarreau <w@1wt.eu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
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
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define MAXCONN 1

const int zero = 0;
const int one = 1;

struct conn {
	struct sockaddr_storage cli_addr;
	int fd_bck;
};

struct errmsg {
	char *msg;
	int size;
	int len;
};

struct sockaddr_storage frt_addr; // listen address
struct sockaddr_storage srv_addr; // server address

#define MAXPKTSIZE 16384
#define MAXREORDER 20
char trash[MAXPKTSIZE];

/* history buffer, to resend random packets */
struct {
	char buf[MAXPKTSIZE];
	size_t len;
} history[MAXREORDER];
int history_idx = 0;
unsigned int rand_rate = 0;
unsigned int corr_rate = 0;
unsigned int corr_span = 1;
unsigned int corr_base = 0;

struct conn conns[MAXCONN];        // sole connection for now
int fd_frt;

int nbfd = 0;
int nbconn = MAXCONN;


/* display the message and exit with the code */
__attribute__((noreturn)) void die(int code, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(code);
}

/* Xorshift RNG */
unsigned int prng_state = ~0U/3; // half bits set, but any seed will fit
static inline unsigned int prng(unsigned int range)
{
	unsigned int x = prng_state;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	prng_state = x;
        return ((unsigned long long)x * (range - 1) + x) >> 32;
}

/* converts str in the form [<ipv4>|<ipv6>|<hostname>]:port to struct sockaddr_storage.
 * Returns < 0 with err set in case of error.
 */
int addr_to_ss(char *str, struct sockaddr_storage *ss, struct errmsg *err)
{
	char *port_str;
	int port;

	/* look for the addr/port delimiter, it's the last colon. */
	if ((port_str = strrchr(str, ':')) == NULL)
		port_str = str;
	else
		*port_str++ = 0;

	port = atoi(port_str);
	if (port <= 0 || port > 65535) {
		err->len = snprintf(err->msg, err->size, "Missing/invalid port number: '%s'\n", port_str);
		return -1;
	}
	*port_str = 0; // present an empty address if none was set

	memset(ss, 0, sizeof(*ss));

	if (strrchr(str, ':') != NULL) {
		/* IPv6 address contains ':' */
		ss->ss_family = AF_INET6;
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);

		if (!inet_pton(ss->ss_family, str, &((struct sockaddr_in6 *)ss)->sin6_addr)) {
			err->len = snprintf(err->msg, err->size, "Invalid IPv6 server address: '%s'", str);
			return -1;
		}
	}
	else {
		ss->ss_family = AF_INET;
		((struct sockaddr_in *)ss)->sin_port = htons(port);

		if (*str == '*' || *str == '\0') { /* INADDR_ANY */
			((struct sockaddr_in *)ss)->sin_addr.s_addr = INADDR_ANY;
			return 0;
		}

		if (!inet_pton(ss->ss_family, str, &((struct sockaddr_in *)ss)->sin_addr)) {
			struct hostent *he = gethostbyname(str);

			if (he == NULL) {
				err->len = snprintf(err->msg, err->size, "Invalid IPv4 server name: '%s'", str);
				return -1;
			}
			((struct sockaddr_in *)ss)->sin_addr = *(struct in_addr *) *(he->h_addr_list);
		}
	}
	return 0;
}

/* returns <0 with err in case of error or the front FD */
int create_udp_listener(struct sockaddr_storage *addr, struct errmsg *err)
{
	int fd;

	if ((fd = socket(addr->ss_family, SOCK_DGRAM, 0)) == -1) {
		err->len = snprintf(err->msg, err->size, "socket(): '%s'", strerror(errno));
		goto fail;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		err->len = snprintf(err->msg, err->size, "fcntl(O_NONBLOCK): '%s'", strerror(errno));
		goto fail;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) == -1) {
		err->len = snprintf(err->msg, err->size, "setsockopt(SO_REUSEADDR): '%s'", strerror(errno));
		goto fail;
	}

#ifdef SO_REUSEPORT
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *) &one, sizeof(one)) == -1) {
		err->len = snprintf(err->msg, err->size, "setsockopt(SO_REUSEPORT): '%s'", strerror(errno));
		goto fail;
	}
#endif
	if (bind(fd, (struct sockaddr *)addr, addr->ss_family == AF_INET6 ?
		 sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)) == -1) {
		err->len = snprintf(err->msg, err->size, "bind(): '%s'", strerror(errno));
		goto fail;
	}

	/* the socket is ready */
	return fd;

 fail:
	if (fd > -1)
		close(fd);
	fd = -1;
	return fd;
}

/* recompute pollfds using frt_fd and scanning nbconn connections.
 * Returns the number of FDs in the set.
 */
int update_pfd(struct pollfd *pfd, int frt_fd, struct conn *conns, int nbconn)
{
	int nbfd = 0;
	int i;

	pfd[nbfd].fd   = frt_fd;
	pfd[nbfd].events = POLLIN;
	nbfd++;

	for (i = 0; i < nbconn; i++) {
		if (conns[i].fd_bck < 0)
			continue;
		pfd[nbfd].fd = conns[i].fd_bck;
		pfd[nbfd].events = POLLIN;
		nbfd++;
	}
	return nbfd;
}

/* searches a connection using fd <fd> as back connection, returns it if found
 * otherwise NULL.
 */
struct conn *conn_bck_lookup(struct conn *conns, int nbconn, int fd)
{
	int i;

	for (i = 0; i < nbconn; i++) {
		if (conns[i].fd_bck < 0)
			continue;
		if (conns[i].fd_bck == fd)
			return &conns[i];
	}
	return NULL;
}

/* Try to establish a connection to <sa>. Return the fd or -1 in case of error */
int add_connection(struct sockaddr_storage *ss)
{
	int fd;

	fd = socket(ss->ss_family, SOCK_DGRAM, 0);
	if (fd < 0)
		goto fail;

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		goto fail;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		goto fail;

	if (connect(fd, (struct sockaddr *)ss, ss->ss_family == AF_INET6 ?
		    sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)) == -1) {
		if (errno != EINPROGRESS)
			goto fail;
	}

	return fd;
 fail:
	if (fd > -1)
		close(fd);
	return -1;
}

/* Corrupt <buf> buffer with <buflen> as length if required */
static void pktbuf_apply_corruption(char *buf, size_t buflen)
{
	if (corr_rate > 0 && prng(100) < corr_rate) {
		unsigned int rnd = prng(corr_span * 256); // pos and value
		unsigned int pos = corr_base + (rnd >> 8);

		if (pos < buflen)
			buf[pos] ^= rnd;
	}
}

/* Handle a read operation on an front FD. Will either reuse the existing
 * connection if the source is found, or will allocate a new one, possibly
 * replacing the oldest one. Returns <0 on error or the number of bytes
 * transmitted.
 */
int handle_frt(int fd, struct pollfd *pfd, struct conn *conns, int nbconn)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	struct conn *conn;
	char *pktbuf = trash;
	int ret;
	int i;

	if (rand_rate > 0) {
		/* keep a copy of this packet */
		history_idx++;
		if (history_idx >= MAXREORDER)
			history_idx = 0;
		pktbuf = history[history_idx].buf;
	}

	addrlen = sizeof(addr);
	ret = recvfrom(fd, pktbuf, MAXPKTSIZE, MSG_DONTWAIT | MSG_NOSIGNAL,
		       (struct sockaddr *)&addr, &addrlen);

	if (rand_rate > 0) {
		history[history_idx].len = ret; // note: we may store -1/EAGAIN
		if (prng(100) < rand_rate) {
			/* return a random buffer or nothing */
			int idx = prng(MAXREORDER + 1) - 1;
			if (idx < 0) {
				/* pretend we didn't receive anything */
				return 0;
			}
			pktbuf = history[idx].buf;
			ret    = history[idx].len;
			if (ret < 0)
				errno = EAGAIN;
		}
	}

	if (ret == 0)
		return 0;

	if (ret < 0)
		return errno == EAGAIN ? 0 : -1;

	pktbuf_apply_corruption(pktbuf, ret);

	conn = NULL;
	for (i = 0; i < nbconn; i++) {
		if (addr.ss_family != conns[i].cli_addr.ss_family)
			continue;
		if (memcmp(&conns[i].cli_addr, &addr,
			   (addr.ss_family == AF_INET6) ?
			   sizeof(struct sockaddr_in6) :
			   sizeof(struct sockaddr_in)) != 0)
			continue;
		conn = &conns[i];
		break;
	}

	if (!conn) {
		/* address not found, create a new conn or replace the oldest
		 * one. For now we support a single one.
		 */
		conn = &conns[0];

		memcpy(&conn->cli_addr, &addr,
		       (addr.ss_family == AF_INET6) ?
		       sizeof(struct sockaddr_in6) :
		       sizeof(struct sockaddr_in));

		if (conn->fd_bck < 0) {
			/* try to create a new connection */
			conn->fd_bck = add_connection(&srv_addr);
			nbfd = update_pfd(pfd, fd, conns, nbconn); // FIXME: MAXCONN instead ?
		}
	}

	if (conn->fd_bck < 0)
		return 0;

	ret = send(conn->fd_bck, pktbuf, ret, MSG_DONTWAIT | MSG_NOSIGNAL);
	return ret;
}

/* Handle a read operation on an FD. Close and return 0 when the read returns zero or an error */
int handle_bck(int fd, struct pollfd *pfd, struct conn *conns, int nbconn)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	struct conn *conn;
	char *pktbuf = trash;
	int ret;

	if (rand_rate > 0) {
		/* keep a copy of this packet */
		history_idx++;
		if (history_idx >= MAXREORDER)
			history_idx = 0;
		pktbuf = history[history_idx].buf;
	}

	ret = recvfrom(fd, pktbuf, MAXPKTSIZE, MSG_DONTWAIT | MSG_NOSIGNAL,
		       (struct sockaddr *)&addr, &addrlen);

	if (rand_rate > 0) {
		history[history_idx].len = ret; // note: we may store -1/EAGAIN
		if (prng(100) < rand_rate) {
			/* return a random buffer or nothing */
			int idx = prng(MAXREORDER + 1) - 1;
			if (idx < 0) {
				/* pretend we didn't receive anything */
				return 0;
			}
			pktbuf = history[idx].buf;
			ret    = history[idx].len;
			if (ret < 0)
				errno = EAGAIN;
		}
	}

	if (ret == 0)
		return 0;

	if (ret < 0)
		return errno == EAGAIN ? 0 : -1;

	pktbuf_apply_corruption(pktbuf, ret);

	conn = conn_bck_lookup(conns, nbconn, fd);
	if (!conn)
		return 0;

	ret = sendto(fd_frt, pktbuf, ret, MSG_DONTWAIT | MSG_NOSIGNAL,
		     (struct sockaddr *)&conn->cli_addr,
		     conn->cli_addr.ss_family == AF_INET6 ?
		     sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
	return ret;
}

/* print the usage message for program named <name> and exit with status <status> */
void usage(int status, const char *name)
{
	if (strchr(name, '/'))
		name = strrchr(name, '/') + 1;
	die(status,
	    "Usage: %s [-h] [options] [<laddr>:]<lport> [<saddr>:]<sport>\n"
	    "Options:\n"
	    "  -h           display this help\n"
	    "  -r rate      reorder/duplicate/lose around <rate>%% of packets\n"
	    "  -s seed      force initial random seed (currently %#x)\n"
	    "  -c rate      corrupt around <rate>%% of packets\n"
	    "  -o ofs       start offset of corrupted area (def: 0)\n"
	    "  -w width     width of the corrupted area (def: 1)\n"
	    "", name, prng_state);
}

int main(int argc, char **argv)
{
	struct errmsg err;
	struct pollfd *pfd;
	int opt;
	int i;

	err.len = 0;
	err.size = 100;
	err.msg = malloc(err.size);

	while ((opt = getopt(argc, argv, "hr:s:c:o:w:")) != -1) {
		switch (opt) {
		case 'r': // rand_rate%
			rand_rate = atoi(optarg);
			break;
		case 's': // seed
			prng_state = atol(optarg);
			break;
		case 'c': // corruption rate
			corr_rate = atol(optarg);
			break;
		case 'o': // corruption offset
			corr_base = atol(optarg);
			break;
		case 'w': // corruption width
			corr_span = atol(optarg);
			break;
		default: // help, anything else
			usage(0, argv[0]);
		}
	}

	if (argc - optind < 2)
		usage(1, argv[0]);

	if (addr_to_ss(argv[optind], &frt_addr, &err) < 0)
		die(1, "parsing listen address: %s\n", err.msg);

	if (addr_to_ss(argv[optind+1], &srv_addr, &err) < 0)
		die(1, "parsing server address: %s\n", err.msg);

	pfd = calloc(MAXCONN + 1, sizeof(struct pollfd));
	if (!pfd)
		die(1, "out of memory\n");

	fd_frt = create_udp_listener(&frt_addr, &err);
	if (fd_frt < 0)
		die(1, "binding listener: %s\n", err.msg);


	for (i = 0; i < MAXCONN; i++)
		conns[i].fd_bck = -1;

	nbfd = update_pfd(pfd, fd_frt, conns, MAXCONN);

	while (1) {
		/* listen for incoming packets */
		int ret, i;

		ret = poll(pfd, nbfd, 1000);
		if (ret <= 0)
			continue;

		for (i = 0; ret; i++) {
			if (!pfd[i].revents)
				continue;
			ret--;

			if (pfd[i].fd == fd_frt) {
				handle_frt(pfd[i].fd, pfd, conns, nbconn);
				continue;
			}

			handle_bck(pfd[i].fd, pfd, conns, nbconn);
		}
	}
}
