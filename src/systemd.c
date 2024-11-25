/* SPDX-License-Identifier: MIT-0 */

/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#include <haproxy/tools.h>

/*
 *  standalone reimplementation of sd_notify from the libsystemd
 *  Return:
 *     -errno in case of error
 *     0 when ignored
 *     >0 when succeeded
 *
 * Will send <message> over the NOTIFY_SOCKET.
 * When unset_environement is set, unsetenv NOTIFY_SOCKET.
 */
int sd_notify(int unset_environment, const char *message)
{
	union sockaddr_union {
		struct sockaddr sa;
		struct sockaddr_un ux;
	} socket_addr = {
		.ux.sun_family = AF_UNIX,
	};
	int ret = 1;
	int fd = -1;
	size_t path_length, message_length;
	const char *socket_path;
	ssize_t written;

	socket_path = getenv("NOTIFY_SOCKET");
	if (!socket_path) {
		ret = 0; /* Not running under systemd? Nothing to do */
		goto end;
	}

	if (unset_environment)
		unsetenv("NOTIFY_SOCKET");

	if (!message) {
		ret = -EINVAL;
		goto end;
	}

	message_length = strlen(message);
	if (message_length == 0) {
		ret = -EINVAL;
		goto end;
	}

	/* Only AF_UNIX is supported, with path or abstract sockets */
	if (socket_path[0] != '/' && socket_path[0] != '@') {
		ret = -EAFNOSUPPORT;
		goto end;
	}

	path_length = strlen(socket_path);
	/* Ensure there is room for NUL byte */
	if (path_length >= sizeof(socket_addr.ux.sun_path)) {
		ret = -E2BIG;
		goto end;
	}

	memcpy(socket_addr.ux.sun_path, socket_path, path_length);

	/* Support for abstract socket */
	if (socket_addr.ux.sun_path[0] == '@')
		socket_addr.ux.sun_path[0] = 0;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		ret = -errno;
		goto end;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
		ret = -errno;
		goto end;
	}

	if (connect(fd, &socket_addr.sa, offsetof(struct sockaddr_un, sun_path) + path_length) != 0) {
		ret = -errno;
		goto end;
	}

	written = write(fd, message, message_length);
	if (written != (ssize_t) message_length) {
		ret = written < 0 ? -errno : -EPROTO;
		goto end;
	}

end:
	if (fd > -1)
		close(fd);
	return ret; /* Notified! */
}

/* va_args variant of sd_notify */
int sd_notifyf(int unset_environment, const char *format, ...)
{
	int r;
	va_list args;
	char *strp = NULL;

	va_start(args, format);
	strp = memvprintf(&strp, format, args);
	va_end(args);

	if (strp == NULL) {
		r = -ENOMEM;
		goto end;
	}

	r = sd_notify(unset_environment, strp);
	free(strp);
end:
	return r;
}

