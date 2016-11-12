#include <sys/resource.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


struct err_msg {
	int size;
	int len;
	char msg[0];
};

const int zero = 0;
const int one = 1;
const struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };

#define TRASH_SIZE 65536
static char trash[TRASH_SIZE];

volatile int nbproc = 0;

/* display the message and exit with the code */
__attribute__((noreturn)) void die(int code, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(code);
}

/* display the usage message and exit with the code */
__attribute__((noreturn)) void usage(int code, const char *arg0)
{
	die(code, "Usage: %s [<ip>:]port [action*]\n", arg0);
}

struct err_msg *alloc_err_msg(int size)
{
	struct err_msg *err;

	err = malloc(sizeof(*err) + size);
	if (err) {
		err->len = 0;
		err->size = size;
	}
	return err;
}

void sig_handler(int sig)
{
	if (sig == SIGCHLD) {
		while (waitpid(-1, NULL, WNOHANG) > 0)
			__sync_sub_and_fetch(&nbproc, 1);
	}
}

/* converts str in the form [[<ipv4>|<ipv6>|<hostname>]:]port to struct sockaddr_storage.
 * Returns < 0 with err set in case of error.
 */
int addr_to_ss(char *str, struct sockaddr_storage *ss, struct err_msg *err)
{
	char *port_str;
	int port;

	memset(ss, 0, sizeof(*ss));

	/* look for the addr/port delimiter, it's the last colon. If there's no
	 * colon, it's 0:<port>.
	 */
	if ((port_str = strrchr(str, ':')) == NULL) {
		port = atoi(str);
		if (port <= 0 || port > 65535) {
			err->len = snprintf(err->msg, err->size, "Missing/invalid port number: '%s'\n", str);
			return -1;
		}

		ss->ss_family = AF_INET;
		((struct sockaddr_in *)ss)->sin_port = htons(port);
		((struct sockaddr_in *)ss)->sin_addr.s_addr = INADDR_ANY;
		return 0;
	}

	*port_str++ = 0;

	if (strrchr(str, ':') != NULL) {
		/* IPv6 address contains ':' */
		ss->ss_family = AF_INET6;
		((struct sockaddr_in6 *)ss)->sin6_port = htons(atoi(port_str));

		if (!inet_pton(ss->ss_family, str, &((struct sockaddr_in6 *)ss)->sin6_addr)) {
			err->len = snprintf(err->msg, err->size, "Invalid server address: '%s'\n", str);
			return -1;
		}
	}
	else {
		ss->ss_family = AF_INET;
		((struct sockaddr_in *)ss)->sin_port = htons(atoi(port_str));

		if (*str == '*' || *str == '\0') { /* INADDR_ANY */
			((struct sockaddr_in *)ss)->sin_addr.s_addr = INADDR_ANY;
			return 0;
		}

		if (!inet_pton(ss->ss_family, str, &((struct sockaddr_in *)ss)->sin_addr)) {
			struct hostent *he = gethostbyname(str);

			if (he == NULL) {
				err->len = snprintf(err->msg, err->size, "Invalid server name: '%s'\n", str);
				return -1;
			}
			((struct sockaddr_in *)ss)->sin_addr = *(struct in_addr *) *(he->h_addr_list);
		}
	}

	return 0;
}

/* waits up to one second on fd <fd> for events <events> (POLLIN|POLLOUT).
 * returns poll's status.
 */
int wait_on_fd(int fd, int events)
{
	struct pollfd pollfd;
	int ret;

	do {
		pollfd.fd = fd;
		pollfd.events = events;
		ret = poll(&pollfd, 1, 1000);
	} while (ret == -1 && errno == EINTR);

	return ret;
}

int tcp_set_nodelay(int sock, const char *arg)
{
	return setsockopt(sock, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
}

int tcp_set_nolinger(int sock, const char *arg)
{
	return setsockopt(sock, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));
}

int tcp_set_noquickack(int sock, const char *arg)
{
	/* warning: do not use during connect if nothing is to be sent! */
	return setsockopt(sock, SOL_TCP, TCP_QUICKACK, &zero, sizeof(zero));
}

/* Try to listen to address <sa>. Return the fd or -1 in case of error */
int tcp_listen(const struct sockaddr_storage *sa, const char *arg)
{
	int sock;
	int backlog;

	if (arg[1])
		backlog = atoi(arg + 1);
	else
		backlog = 1000;

	if (backlog < 0 || backlog > 65535) {
		fprintf(stderr, "backlog must be between 0 and 65535 inclusive (was %d)\n", backlog);
		return -1;
	}

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket()");
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		perror("setsockopt(SO_REUSEADDR)");
		goto fail;
	}

#ifdef SO_REUSEPORT
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char *) &one, sizeof(one)) == -1) {
		perror("setsockopt(SO_REUSEPORT)");
		goto fail;
	}
#endif
	if (bind(sock, (struct sockaddr *)sa, sa->ss_family == AF_INET6 ?
		 sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)) == -1) {
		perror("bind");
		goto fail;
	}

	if (listen(sock, backlog) == -1) {
		perror("listen");
		goto fail;
	}

	return sock;
 fail:
	close(sock);
	return -1;
}

/* accepts a socket from listening socket <sock>, and returns it (or -1 in case of error) */
int tcp_accept(int sock, const char *arg)
{
	int count;
	int newsock;

	if (arg[1])
		count = atoi(arg + 1);
	else
		count = 1;

	if (count <= 0) {
		fprintf(stderr, "accept count must be > 0 or unset (was %d)\n", count);
		return -1;
	}

	do {
		newsock = accept(sock, NULL, NULL);
		if (newsock < 0) { // TODO: improve error handling
			if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED)
				continue;
			perror("accept()");
			break;
		}

		if (count > 1)
			close(newsock);
		count--;
	} while (count > 0);

	fcntl(newsock, F_SETFL, O_NONBLOCK);
	return newsock;
}

/* Try to establish a new connection to <sa>. Return the fd or -1 in case of error */
int tcp_connect(const struct sockaddr_storage *sa, const char *arg)
{
	int sock;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		return -1;

	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1)
		goto fail;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		goto fail;

	if (connect(sock, (const struct sockaddr *)sa, sizeof(*sa)) < 0) {
		if (errno != EINPROGRESS)
			goto fail;
	}

	return sock;
 fail:
	close(sock);
	return -1;
}

/* receives N bytes from the socket and returns 0 (or -1 in case of error).
 * When no arg is passed, receives anything and stops. Otherwise reads the
 * requested amount of data. 0 means read as much as possible.
 */
int tcp_recv(int sock, const char *arg)
{
	int count = -1; // stop at first read
	int ret;

	if (arg[1]) {
		count = atoi(arg + 1);
		if (count < 0) {
			fprintf(stderr, "recv count must be >= 0 or unset (was %d)\n", count);
			return -1;
		}
	}

	while (1) {
		ret = recv(sock, NULL, (count > 0) ? count : INT_MAX, MSG_NOSIGNAL | MSG_TRUNC);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN)
				return -1;
			while (!wait_on_fd(sock, POLLIN));
			continue;
		}
		if (!ret)
			break;

		if (!count)
			continue;
		else if (count > 0)
			count -= ret;

		if (count <= 0)
			break;
	}

	return 0;
}

/* sends N bytes to the socket and returns 0 (or -1 in case of error). If not
 * set, sends only one block. Sending zero means try to send forever.
 */
int tcp_send(int sock, const char *arg)
{
	int count = -1; // stop after first block
	int ret;

	if (arg[1]) {
		count = atoi(arg + 1);
		if (count <= 0) {
			fprintf(stderr, "send count must be >= 0 or unset (was %d)\n", count);
			return -1;
		}
	}

	while (1) {
		ret = send(sock, trash,
		           (count > 0) && (count < sizeof(trash)) ? count : sizeof(trash),
		           MSG_NOSIGNAL | ((count > sizeof(trash)) ? MSG_MORE : 0));
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN)
				return -1;
			while (!wait_on_fd(sock, POLLOUT));
			continue;
		}
		if (!count)
			continue;
		else if (count > 0)
			count -= ret;

		if (count <= 0)
			break;
	}

	return 0;
}

/* echoes N bytes to the socket and returns 0 (or -1 in case of error). If not
 * set, echoes only the first block. Zero means forward forever.
 */
int tcp_echo(int sock, const char *arg)
{
	int count = -1; // echo forever
	int ret;
	int rcvd;

	if (arg[1]) {
		count = atoi(arg + 1);
		if (count < 0) {
			fprintf(stderr, "send count must be >= 0 or unset (was %d)\n", count);
			return -1;
		}
	}

	rcvd = 0;
	while (1) {
		if (rcvd <= 0) {
			/* no data pending */
			rcvd = recv(sock, trash, (count > 0) && (count < sizeof(trash)) ? count : sizeof(trash), MSG_NOSIGNAL);
			if (rcvd < 0) {
				if (errno == EINTR)
					continue;
				if (errno != EAGAIN)
					return -1;
				while (!wait_on_fd(sock, POLLIN));
				continue;
			}
			if (!rcvd)
				break;
		}
		else {
			/* some data still pending */
			ret = send(sock, trash, rcvd, MSG_NOSIGNAL | ((count > rcvd) ? MSG_MORE : 0));
			if (ret < 0) {
				if (errno == EINTR)
					continue;
				if (errno != EAGAIN)
					return -1;
				while (!wait_on_fd(sock, POLLOUT));
				continue;
			}
			rcvd -= ret;
			if (rcvd)
				continue;

			if (!count)
				continue;
			else if (count > 0)
				count -= ret;

			if (count <= 0)
				break;
		}
	}
	return 0;
}

/* waits for an event on the socket, usually indicates an accept for a
 * listening socket and a connect for an outgoing socket.
 */
int tcp_wait(int sock, const char *arg)
{
	struct pollfd pollfd;
	int delay = -1; // wait forever
	int ret;

	if (arg[1]) {
		delay = atoi(arg + 1);
		if (delay < 0) {
			fprintf(stderr, "wait time must be >= 0 or unset (was %d)\n", delay);
			return -1;
		}
	}

	/* FIXME: this doesn't take into account delivered signals */
	do {
		pollfd.fd = sock;
		pollfd.events = POLLIN | POLLOUT;
		ret = poll(&pollfd, 1, delay);
	} while (ret == -1 && errno == EINTR);

	return 0;
}

/* waits for the input data to be present */
int tcp_wait_in(int sock, const char *arg)
{
	struct pollfd pollfd;
	int ret;

	do {
		pollfd.fd = sock;
		pollfd.events = POLLIN;
		ret = poll(&pollfd, 1, 1000);
	} while (ret == -1 && errno == EINTR);
	return 0;
}

/* waits for the output queue to be empty */
int tcp_wait_out(int sock, const char *arg)
{
	struct pollfd pollfd;
	int ret;

	do {
		pollfd.fd = sock;
		pollfd.events = POLLOUT;
		ret = poll(&pollfd, 1, 1000);
	} while (ret == -1 && errno == EINTR);

	/* Now wait for data to leave the socket */
	do {
		if (ioctl(sock, TIOCOUTQ, &ret) < 0)
			return -1;
	} while (ret > 0);
	return 0;
}

/* delays processing for <time> milliseconds, 100 by default */
int tcp_pause(int sock, const char *arg)
{
	struct pollfd pollfd;
	int delay = 100;
	int ret;

	if (arg[1]) {
		delay = atoi(arg + 1);
		if (delay < 0) {
			fprintf(stderr, "wait time must be >= 0 or unset (was %d)\n", delay);
			return -1;
		}
	}

	usleep(delay * 1000);
	return 0;
}

/* forks another process while respecting the limit imposed in argument (1 by
 * default). Will wait for another process to exit before creating a new one.
 * Returns the value of the fork() syscall, ie 0 for the child, non-zero for
 * the parent, -1 for an error.
 */
int tcp_fork(int sock, const char *arg)
{
	int max = 1;
	int ret;

	if (arg[1]) {
		max = atoi(arg + 1);
		if (max <= 0) {
			fprintf(stderr, "max process must be > 0 or unset (was %d)\n", max);
			return -1;
		}
	}

	while (nbproc >= max)
		poll(NULL, 0, 1000);

	ret = fork();
	if (ret > 0)
		__sync_add_and_fetch(&nbproc, 1);
	return ret;
}

int main(int argc, char **argv)
{
	struct sockaddr_storage ss;
	struct err_msg err;
	const char *arg0;
	int arg;
	int ret;
	int sock;

	arg0 = argv[0];
	if (argc < 2)
		usage(1, arg0);

	signal(SIGCHLD, sig_handler);

	if (addr_to_ss(argv[1], &ss, &err) < 0)
		die(1, "%s\n", err.msg);

	sock = -1;
	for (arg = 2; arg < argc; arg++) {
		switch (argv[arg][0]) {
		case 'L':
			/* silently ignore existing connections */
			if (sock == -1)
				sock = tcp_listen(&ss, argv[arg]);
			if (sock < 0)
				die(1, "Fatal: tcp_listen() failed.\n");
			break;

		case 'C':
			/* silently ignore existing connections */
			if (sock == -1)
				sock = tcp_connect(&ss, argv[arg]);
			if (sock < 0)
				die(1, "Fatal: tcp_connect() failed.\n");
			break;

		case 'A':
			if (sock < 0)
				die(1, "Fatal: tcp_accept() on non-socket.\n");
			sock = tcp_accept(sock, argv[arg]);
			if (sock < 0)
				die(1, "Fatal: tcp_accept() failed.\n");
			break;

		case 'T':
			if (sock < 0)
				die(1, "Fatal: tcp_set_nodelay() on non-socket.\n");
			if (tcp_set_nodelay(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_set_nodelay() failed.\n");
			break;

		case 'G':
			if (sock < 0)
				die(1, "Fatal: tcp_set_nolinger() on non-socket.\n");
			if (tcp_set_nolinger(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_set_nolinger() failed.\n");
			break;

		case 'Q':
			if (sock < 0)
				die(1, "Fatal: tcp_set_noquickack() on non-socket.\n");
			if (tcp_set_noquickack(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_set_noquickack() failed.\n");
			break;

		case 'R':
			if (sock < 0)
				die(1, "Fatal: tcp_recv() on non-socket.\n");
			if (tcp_recv(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_recv() failed.\n");
			break;

		case 'S':
			if (sock < 0)
				die(1, "Fatal: tcp_send() on non-socket.\n");
			if (tcp_send(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_send() failed.\n");
			break;

		case 'E':
			if (sock < 0)
				die(1, "Fatal: tcp_echo() on non-socket.\n");
			if (tcp_echo(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_echo() failed.\n");
			break;

		case 'P':
			if (tcp_pause(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_pause() failed.\n");
			break;

		case 'W':
			if (sock < 0)
				die(1, "Fatal: tcp_wait() on non-socket.\n");
			if (tcp_wait(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_wait() failed.\n");
			break;

		case 'I':
			if (sock < 0)
				die(1, "Fatal: tcp_wait_in() on non-socket.\n");
			if (tcp_wait_in(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_wait_in() failed.\n");
			break;

		case 'O':
			if (sock < 0)
				die(1, "Fatal: tcp_wait_out() on non-socket.\n");
			if (tcp_wait_out(sock, argv[arg]) < 0)
				die(1, "Fatal: tcp_wait_out() failed.\n");
			break;

		case 'K':
			if (sock < 0 || close(sock) < 0)
				die(1, "Fatal: close() on non-socket.\n");
			sock = -1;
			break;

		case 'F':
			/* ignore errors on shutdown() as they are common */
			if (sock >= 0)
				shutdown(sock, SHUT_WR);
			break;

		case 'N':
			ret = tcp_fork(sock, argv[arg]);
			if (ret < 0)
				die(1, "Fatal: fork() failed.\n");
			if (ret > 0) {
				/* loop back to first arg */
				arg = 1;
				continue;
			}
			/* OK we're in the child, let's continue */
			break;
		default:
			usage(1, arg0);
		}
	}
	return 0;
}
