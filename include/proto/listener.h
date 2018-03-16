/*
 * include/proto/listener.h
 * This file declares listener management primitives.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
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

#ifndef _PROTO_LISTENER_H
#define _PROTO_LISTENER_H

#include <string.h>

#include <types/listener.h>
#include <types/cli.h>

/* This function tries to temporarily disable a listener, depending on the OS
 * capabilities. Linux unbinds the listen socket after a SHUT_RD, and ignores
 * SHUT_WR. Solaris refuses either shutdown(). OpenBSD ignores SHUT_RD but
 * closes upon SHUT_WR and refuses to rebind. So a common validation path
 * involves SHUT_WR && listen && SHUT_RD. In case of success, the FD's polling
 * is disabled. It normally returns non-zero, unless an error is reported.
 */
int pause_listener(struct listener *l);

/* This function tries to resume a temporarily disabled listener.
 * The resulting state will either be LI_READY or LI_FULL. 0 is returned
 * in case of failure to resume (eg: dead socket).
 */
int resume_listener(struct listener *l);

/* This function adds all of the protocol's listener's file descriptors to the
 * polling lists when they are in the LI_LISTEN state. It is intended to be
 * used as a protocol's generic enable_all() primitive, for use after the
 * fork(). It puts the listeners into LI_READY or LI_FULL states depending on
 * their number of connections. It always returns ERR_NONE.
 */
int enable_all_listeners(struct protocol *proto);

/* This function removes all of the protocol's listener's file descriptors from
 * the polling lists when they are in the LI_READY or LI_FULL states. It is
 * intended to be used as a protocol's generic disable_all() primitive. It puts
 * the listeners into LI_LISTEN, and always returns ERR_NONE.
 */
int disable_all_listeners(struct protocol *proto);

/* Dequeues all of the listeners waiting for a resource in wait queue <queue>. */
void dequeue_all_listeners(struct list *list);

/* Must be called with the lock held. Depending on <do_close> value, it does
 * what unbind_listener or unbind_listener_no_close should do.
 */
void do_unbind_listener(struct listener *listener, int do_close);

/* This function closes the listening socket for the specified listener,
 * provided that it's already in a listening state. The listener enters the
 * LI_ASSIGNED state. This function is intended to be used as a generic
 * function for standard protocols.
 */
void unbind_listener(struct listener *listener);

/* This function pretends the listener is dead, but keeps the FD opened, so
 * that we can provide it, for conf reloading.
 */
void unbind_listener_no_close(struct listener *listener);

/* This function closes all listening sockets bound to the protocol <proto>,
 * and the listeners end in LI_ASSIGNED state if they were higher. It does not
 * detach them from the protocol. It always returns ERR_NONE.
 */
int unbind_all_listeners(struct protocol *proto);


/* creates one or multiple listeners for bind_conf <bc> on sockaddr <ss> on port
 * range <portl> to <porth>, and possibly attached to fd <fd> (or -1 for auto
 * allocation). The address family is taken from ss->ss_family. The number of
 * jobs and listeners is automatically increased by the number of listeners
 * created. If the <inherited> argument is set to 1, it specifies that the FD
 * was obtained from a parent process.
 * It returns non-zero on success, zero on error with the error message
 * set in <err>.
 */
int create_listeners(struct bind_conf *bc, const struct sockaddr_storage *ss,
                     int portl, int porth, int fd, int inherited, char **err);

/* Delete a listener from its protocol's list of listeners. The listener's
 * state is automatically updated from LI_ASSIGNED to LI_INIT. The protocol's
 * number of listeners is updated. Note that the listener must have previously
 * been unbound. This is the generic function to use to remove a listener.
 */
void delete_listener(struct listener *listener);

/* This function is called on a read event from a listening socket, corresponding
 * to an accept. It tries to accept as many connections as possible, and for each
 * calls the listener's accept handler (generally the frontend's accept handler).
 */
void listener_accept(int fd);

/* Notify the listener that a connection initiated from it was released. This
 * is used to keep the connection count consistent and to possibly re-open
 * listening when it was limited.
 */
void listener_release(struct listener *l);

/*
 * Registers the bind keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void bind_register_keywords(struct bind_kw_list *kwl);

/* Return a pointer to the bind keyword <kw>, or NULL if not found. */
struct bind_kw *bind_find_kw(const char *kw);

/* Dumps all registered "bind" keywords to the <out> string pointer. */
void bind_dump_kws(char **out);

/* allocate an bind_conf struct for a bind line, and chain it to the frontend <fe>.
 * If <arg> is not NULL, it is duplicated into ->arg to store useful config
 * information for error reporting.
 */
static inline struct bind_conf *bind_conf_alloc(struct proxy *fe, const char *file,
                                 int line, const char *arg, struct xprt_ops *xprt)
{
	struct bind_conf *bind_conf = (void *)calloc(1, sizeof(struct bind_conf));

	bind_conf->file = strdup(file);
	bind_conf->line = line;
	LIST_ADDQ(&fe->conf.bind, &bind_conf->by_fe);
	if (arg)
		bind_conf->arg = strdup(arg);

	bind_conf->ux.uid = -1;
	bind_conf->ux.gid = -1;
	bind_conf->ux.mode = 0;
	bind_conf->xprt = xprt;
	bind_conf->frontend = fe;
	bind_conf->severity_output = CLI_SEVERITY_NONE;

	LIST_INIT(&bind_conf->listeners);
	return bind_conf;
}

static inline const char *listener_state_str(const struct listener *l)
{
	static const char *states[9] = {
		"NEW", "INI", "ASS", "PAU", "ZOM", "LIS", "RDY", "FUL", "LIM",
	};
	unsigned int st = l->state;

	if (st > sizeof(states) / sizeof(*states))
		return "INVALID";
	return states[st];
}

extern struct xfer_sock_list *xfer_sock_list;
#endif /* _PROTO_LISTENER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
