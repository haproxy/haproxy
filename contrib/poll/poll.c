#define _GNU_SOURCE // for POLLRDHUP
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* for OSes which don't have it */
#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef MSG_MORE
#define MSG_MORE 0
#endif

int verbose = 0;
int cmd = 0;
int cmdstep = 0;
int zero = 0;
int one  = 1;
int lfd = -1;
int cfd = -1;
int sfd = -1;
struct sockaddr_in saddr, caddr;
socklen_t salen, calen;

void usage(const char *arg0)
{
	printf("Usage: %s [ arg [<action>[,...]] ] ...\n"
	       "args:\n"
	       "    -h            display this help\n"
	       "    -v            verbose mode (shows ret values)\n"
	       "    -c <actions>  perform <action> on client side socket\n"
	       "    -s <actions>  perform <action> on server side socket\n"
	       "    -l <actions>  perform <action> on listening socket\n"
	       "\n"
	       "actions for -c/-s/-l (multiple may be delimited by commas) :\n"
	       "    acc           accept on listener, implicit before first -s\n"
	       "    snd           send a few bytes of data\n"
	       "    mor           send a few bytes of data with MSG_MORE\n"
	       "    rcv           receive a few bytes of data\n"
	       "    drn           drain: receive till zero\n"
	       "    shr           SHUT_RD : shutdown read side\n"
	       "    shw           SHUT_WR : shutdown write side\n"
	       "    shb           SHUT_RDWR : shutdown both sides\n"
	       "    lin           disable lingering on the socket\n"
	       "    clo           close the file descriptor\n"
	       "    pol           poll() for any event\n"
	       "\n", arg0);
}

void die(const char *msg)
{
	if (msg)
		fprintf(stderr, "%s\n", msg);
	exit(1);
}

const char *get_errno(int ret)
{
	static char errmsg[100];

	if (ret >= 0)
		return "";

	snprintf(errmsg, sizeof(errmsg), " (%s)", strerror(errno));
	return errmsg;
}

void do_acc(int fd)
{
	int ret;

	calen = sizeof(caddr);
	ret = accept(lfd, (struct sockaddr*)&caddr, &calen);
	if (sfd < 0)
		sfd = ret;
	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret));
}

void do_snd(int fd)
{
	int ret;

	ret = send(fd, "foo", 3, MSG_NOSIGNAL|MSG_DONTWAIT);
	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret));
}

void do_mor(int fd)
{
	int ret;

	ret = send(fd, "foo", 3, MSG_NOSIGNAL|MSG_DONTWAIT|MSG_MORE);
	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret));
}

void do_rcv(int fd)
{
	char buf[10];
	int ret;

	ret = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret));
}

void do_drn(int fd)
{
	char buf[16384];
	int total = -1;
	int ret;

	while (1) {
		ret = recv(fd, buf, sizeof(buf), 0);
		if (ret <= 0)
			break;
		if (total < 0)
			total = 0;
		total += ret;
	}

	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, total, get_errno(ret));
}

void do_shr(int fd)
{
	int ret;

	ret = shutdown(fd, SHUT_RD);
	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret));
}

void do_shw(int fd)
{
	int ret;

	ret = shutdown(fd, SHUT_WR);
	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret));
}

void do_shb(int fd)
{
	int ret;

	ret = shutdown(fd, SHUT_RDWR);
	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret));
}

void do_lin(int fd)
{
	struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };
	int ret;

	ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, &nolinger, sizeof(nolinger));
	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret));
}

void do_clo(int fd)
{
	int ret;

	ret = close(fd);
	if (verbose)
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s\n", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret));
}

void do_pol(int fd)
{
	struct pollfd fds = { .fd = fd, .events = POLLIN|POLLOUT|POLLRDHUP, .revents=0 };
	int ret;

	ret = poll(&fds, 1, 0);
	if (verbose) {
		printf("cmd #%d stp #%d: %s(%d): ret=%d%s ev=%#x ", cmd, cmdstep, __FUNCTION__, fd, ret, get_errno(ret), ret > 0 ? fds.revents : 0);
		if (ret > 0 && fds.revents) {
			int flags, flag;
			putchar('(');

			for (flags = fds.revents; flags; flags ^= flag) {
				flag = flags ^ (flags & (flags - 1)); // keep lowest bit only
				switch (flag) {
				case POLLIN: printf("IN"); break;
				case POLLOUT: printf("OUT"); break;
				case POLLPRI: printf("PRI"); break;
				case POLLHUP: printf("HUP"); break;
				case POLLERR: printf("ERR"); break;
				case POLLNVAL: printf("NVAL"); break;
#if POLLRDHUP
				case POLLRDHUP: printf("RDHUP"); break;
#endif
				default: printf("???[%#x]", flag); break;
				}
				if (flags ^ flag)
					putchar(' ');
			}
			putchar(')');
		}
		putchar('\n');
	}
}

int main(int argc, char **argv)
{
	const char *arg0;
	char *word, *next;
	int fd;

	/* listener */
	lfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (lfd < 0)
		die("socket(l)");

	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(0);
	salen = sizeof(saddr);

	if (bind(lfd, (struct sockaddr *)&saddr, salen) < 0)
		die("bind()");

	if (listen(lfd, 1000) < 0)
		die("listen()");

	if (getsockname(lfd, (struct sockaddr *)&saddr, &salen) < 0)
		die("getsockname()");


	/* client */
	cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (cfd < 0)
		die("socket(c)");

        if (connect(cfd, (const struct sockaddr*)&saddr, salen) == -1)
		die("connect()");

	/* connection is pending in accept queue, accept() will either be
	 * explicit with "-l acc" below, or implicit on "-s <cmd>"
	 */

	arg0 = argv[0];
	if (argc < 2) {
		usage(arg0);
		exit(1);
	}

	write(1, "#### BEGIN ####\n", 16); // add a visible delimiter in the traces

	while (argc > 1) {
		argc--; argv++;
		if (**argv != '-') {
			usage(arg0);
			exit(1);
		}

		fd = -1;
		switch (argv[0][1]) {
		case 'h' :
			usage(arg0);
			exit(0);
			break;
		case 'v' :
			verbose++;
			break;
		case 'c' :
			cmd++; cmdstep = 0;
			fd = cfd;
			break;
		case 's' :
			cmd++; cmdstep = 0;
			if (sfd < 0)
				do_acc(lfd);
			if (sfd < 0)
				die("accept()");
			fd = sfd;
			break;
		case 'l' :
			cmd++; cmdstep = 0;
			fd = lfd;
			break;
		default  : usage(arg0); exit(1); break;
		}

		if (fd >= 0) { /* an action is required */
			if (argc < 2) {
				usage(arg0);
				exit(1);
			}

			for (word = argv[1]; word && *word; word = next) {
				next = strchr(word, ',');
				if (next)
					*(next++) = 0;
				cmdstep++;
				if (strcmp(word, "acc") == 0) {
					do_acc(fd);
				}
				else if (strcmp(word, "snd") == 0) {
					do_snd(fd);
				}
				else if (strcmp(word, "mor") == 0) {
					do_mor(fd);
				}
				else if (strcmp(word, "rcv") == 0) {
					do_rcv(fd);
				}
				else if (strcmp(word, "drn") == 0) {
					do_drn(fd);
				}
				else if (strcmp(word, "shb") == 0) {
					do_shb(fd);
				}
				else if (strcmp(word, "shr") == 0) {
					do_shr(fd);
				}
				else if (strcmp(word, "shw") == 0) {
					do_shw(fd);
				}
				else if (strcmp(word, "lin") == 0) {
					do_lin(fd);
				}
				else if (strcmp(word, "clo") == 0) {
					do_clo(fd);
				}
				else if (strcmp(word, "pol") == 0) {
					do_pol(fd);
				}
				else {
					printf("Ignoring unknown action '%s' in step #%d of cmd #%d\n", word, cmdstep, cmd);
				}
			}
			argc--; argv++;
		}
	}

	write(1, "#### END ####\n", 14); // add a visible delimiter in the traces

	if (!cmd) {
		printf("No command was requested!\n");
		usage(arg0);
		exit(1);
	}

	return 0;
}
