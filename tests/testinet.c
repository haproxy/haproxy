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


main() {
    printf("sizeof sockaddr=%d\n", sizeof(struct sockaddr));
    printf("sizeof sockaddr_in=%d\n", sizeof(struct sockaddr_in));
    printf("sizeof sockaddr_in6=%d\n", sizeof(struct sockaddr_in6));
}
