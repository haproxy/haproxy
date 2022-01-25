/*
 * include/haproxy/listener.h
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

#ifndef _HAPROXY_LISTENER_H
#define _HAPROXY_LISTENER_H

#include <stdlib.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/listener-t.h>

struct proxy;
struct task;

int li_init_per_thr(struct listener *li);

/* adjust the listener's state and its proxy's listener counters if needed */
void listener_set_state(struct listener *l, enum li_state st);

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

/*
 * This function completely stops a listener. It will need to operate under the
 * proxy's lock, the protocol's lock, and the listener's lock. The caller is
 * responsible for indicating in lpx, lpr, lli whether the respective locks are
 * already held (non-zero) or not (zero) so that the function picks the missing
 * ones, in this order.
 */
void stop_listener(struct listener *l, int lpx, int lpr, int lli);

/* This function adds the specified listener's file descriptor to the polling
 * lists if it is in the LI_LISTEN state. The listener enters LI_READY or
 * LI_FULL state depending on its number of connections. In daemon mode, we
 * also support binding only the relevant processes to their respective
 * listeners. We don't do that in debug mode however.
 */
void enable_listener(struct listener *listener);

/* Dequeues all listeners waiting for a resource the global wait queue */
void dequeue_all_listeners(void);

/* Dequeues all listeners waiting for a resource in proxy <px>'s queue */
void dequeue_proxy_listeners(struct proxy *px);

/* This function closes the listening socket for the specified listener,
 * provided that it's already in a listening state. The listener enters the
 * LI_ASSIGNED state, except if the FD is not closed, in which case it may
 * remain in LI_LISTEN. Depending on the process's status (master or worker),
 * the listener's bind options and the receiver's origin, it may or may not
 * close the receiver's FD. Must be called with the lock held.
 */
void do_unbind_listener(struct listener *listener);

/* This function closes the listening socket for the specified listener,
 * provided that it's already in a listening state. The listener enters the
 * LI_ASSIGNED state, except if the FD is not closed, in which case it may
 * remain in LI_LISTEN. This function is intended to be used as a generic
 * function for standard protocols.
 */
void unbind_listener(struct listener *listener);

/* creates one or multiple listeners for bind_conf <bc> on sockaddr <ss> on port
 * range <portl> to <porth>, and possibly attached to fd <fd> (or -1 for auto
 * allocation). The address family is taken from ss->ss_family, and the protocol
 * passed in <proto> must be usable on this family. The number of jobs and
 * listeners is automatically increased by the number of listeners created. It
 * returns non-zero on success, zero on error with the error message set in <err>.
 */
int create_listeners(struct bind_conf *bc, const struct sockaddr_storage *ss,
                     int portl, int porth, int fd, struct protocol *proto, char **err);
struct listener *clone_listener(struct listener *src);

/* Delete a listener from its protocol's list of listeners. The listener's
 * state is automatically updated from LI_ASSIGNED to LI_INIT. The protocol's
 * number of listeners is updated. Note that the listener must have previously
 * been unbound. This is the generic function to use to remove a listener.
 */
void delete_listener(struct listener *listener);
void __delete_listener(struct listener *listener);

/* This function is called on a read event from a listening socket, corresponding
 * to an accept. It tries to accept as many connections as possible, and for each
 * calls the listener's accept handler (generally the frontend's accept handler).
 */
void listener_accept(struct listener *l);

/* Returns a suitable value for a listener's backlog. It uses the listener's,
 * otherwise the frontend's backlog, otherwise the listener's maxconn,
 * otherwise the frontend's maxconn, otherwise 1024.
 */
int listener_backlog(const struct listener *l);

/* Notify the listener that a connection initiated from it was released. This
 * is used to keep the connection count consistent and to possibly re-open
 * listening when it was limited.
 */
void listener_release(struct listener *l);

/* This function adds the specified <listener> to the protocol <proto>. It
 * does nothing if the protocol was already added. The listener's state is
 * automatically updated from LI_INIT to LI_ASSIGNED. The number of listeners
 * for the protocol is updated. This must be called with the proto lock held.
 */
void default_add_listener(struct protocol *proto, struct listener *listener);

/* default function used to unbind a listener. This is for use by standard
 * protocols working on top of accepted sockets. The receiver's rx_unbind()
 * will automatically be used after the listener is disabled if the socket is
 * still bound. This must be used under the listener's lock.
 */
void default_unbind_listener(struct listener *listener);

/* default function called to suspend a listener: it simply passes the call to
 * the underlying receiver. This is find for most socket-based protocols. This
 * must be called under the listener's lock. It will return non-zero on success,
 * 0 on failure. If no receiver-level suspend is provided, the operation is
 * assumed to succeed.
 */
int default_suspend_listener(struct listener *l);

/* Tries to resume a suspended listener, and returns non-zero on success or
 * zero on failure. On certain errors, an alert or a warning might be displayed.
 * It must be called with the listener's lock held. Depending on the listener's
 * state and protocol, a listen() call might be used to resume operations, or a
 * call to the receiver's resume() function might be used as well. This is
 * suitable as a default function for TCP and UDP. This must be called with the
 * listener's lock held.
 */
int default_resume_listener(struct listener *l);

/*
 * Registers the bind keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void bind_register_keywords(struct bind_kw_list *kwl);

/* Return a pointer to the bind keyword <kw>, or NULL if not found. */
struct bind_kw *bind_find_kw(const char *kw);

/* Dumps all registered "bind" keywords to the <out> string pointer. */
void bind_dump_kws(char **out);
const char *bind_find_best_kw(const char *word);

void bind_recount_thread_bits(struct bind_conf *conf);
unsigned int bind_map_thread_id(const struct bind_conf *conf, unsigned int r);
struct bind_conf *bind_conf_alloc(struct proxy *fe, const char *file,
                                  int line, const char *arg, struct xprt_ops *xprt);
const char *listener_state_str(const struct listener *l);
struct task *accept_queue_process(struct task *t, void *context, unsigned int state);
struct task *manage_global_listener_queue(struct task *t, void *context, unsigned int state);

extern struct accept_queue_ring accept_queue_rings[MAX_THREADS] __attribute__((aligned(64)));

extern const char* li_status_st[LI_STATE_COUNT];
enum li_status get_li_status(struct listener *l);

#endif /* _HAPROXY_LISTENER_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
