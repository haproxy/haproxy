#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>

int main(int argc, char **argv) {
	char *addr;
	int port;
	int sock;
	struct sockaddr_in saddr;
	const struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };

	if (argc < 4) {
		fprintf(stderr,
			"usage : %s <addr> <port> <string>\n"
			"        This will connect to TCP port <addr>:<port> and send string <string>\n"
			"        then immediately reset.\n",
			argv[0]);
		exit(1);
	}

	addr = argv[1];
	port = atoi(argv[2]);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&saddr, sizeof(saddr));
	saddr.sin_addr.s_addr = inet_addr(addr);
	saddr.sin_port = htons(port);
	saddr.sin_family = AF_INET;

	if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("connect");
		exit(1);
	}

	send(sock, argv[3], strlen(argv[3]), MSG_DONTWAIT | MSG_NOSIGNAL);
	setsockopt(sock, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));
	close(sock);
	exit(0);
}
