/*
 * Protocol registration functions.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <haproxy/api.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/tools.h>


/* List head of all registered protocols */
static struct list protocols = LIST_HEAD_INIT(protocols);
struct protocol *__protocol_by_family[AF_CUST_MAX][2][2] __read_mostly = { };

/* This is the global spinlock we may need to register/unregister listeners or
 * protocols. Its main purpose is in fact to serialize the rare stop/deinit()
 * phases.
 */
__decl_spinlock(proto_lock);

/* Registers the protocol <proto> */
void protocol_register(struct protocol *proto)
{
	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	LIST_APPEND(&protocols, &proto->list);
	if (proto->fam->sock_domain >= 0 && proto->fam->sock_domain < AF_CUST_MAX)
		__protocol_by_family[proto->fam->sock_domain]
			[proto->sock_type == SOCK_DGRAM]
			[proto->ctrl_type == SOCK_DGRAM] = proto;
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
}

/* Unregisters the protocol <proto>. Note that all listeners must have
 * previously been unbound.
 */
void protocol_unregister(struct protocol *proto)
{
	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	LIST_DELETE(&proto->list);
	LIST_INIT(&proto->list);
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
}

/* binds all listeners of all registered protocols. Returns a composition
 * of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_bind_all(int verbose)
{
	struct protocol *proto;
	struct listener *listener;
	struct receiver *receiver;
	char msg[100];
	char *errmsg;
	int err, lerr;

	err = 0;
	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list) {
		list_for_each_entry(receiver, &proto->receivers, proto_list) {
			listener = LIST_ELEM(receiver, struct listener *, rx);

			lerr = proto->fam->bind(receiver, &errmsg);
			err |= lerr;

			/* errors are reported if <verbose> is set or if they are fatal */
			if (verbose || (lerr & (ERR_FATAL | ERR_ABORT))) {
				struct proxy *px = listener->bind_conf->frontend;

				if (lerr & ERR_ALERT)
					ha_alert("Starting %s %s: %s\n",
						 proxy_type_str(px), px->id, errmsg);
				else if (lerr & ERR_WARN)
					ha_warning("Starting %s %s: %s\n",
						   proxy_type_str(px), px->id, errmsg);
				ha_free(&errmsg);
			}
			if (lerr & ERR_ABORT)
				break;

			if (lerr & ~ERR_WARN)
				continue;

			/* for now there's still always a listening function */
			BUG_ON(!proto->listen);
			lerr = proto->listen(listener, msg, sizeof(msg));
			err |= lerr;

			if (verbose || (lerr & (ERR_FATAL | ERR_ABORT))) {
				struct proxy *px = listener->bind_conf->frontend;

				if (lerr & ERR_ALERT)
					ha_alert("Starting %s %s: %s\n",
						 proxy_type_str(px), px->id, msg);
				else if (lerr & ERR_WARN)
					ha_warning("Starting %s %s: %s\n",
						   proxy_type_str(px), px->id, msg);
			}
			if (lerr & ERR_ABORT)
				break;
		}
		if (err & ERR_ABORT)
			break;
	}
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
	return err;
}

/* unbinds all listeners of all registered protocols. They are also closed.
 * This must be performed before calling exit() in order to get a chance to
 * remove file-system based sockets and pipes.
 * Returns a composition of ERR_NONE, ERR_RETRYABLE, ERR_FATAL, ERR_ABORT.
 */
int protocol_unbind_all(void)
{
	struct protocol *proto;
	struct listener *listener;
	int err;

	err = 0;
	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list) {
		list_for_each_entry(listener, &proto->receivers, rx.proto_list)
			unbind_listener(listener);
	}
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
	return err;
}

/* stops all listeners of all registered protocols, except when the belong to a
 * proxy configured with a grace time. This will normally catch every single
 * listener, all protocols included, and the grace ones will have to be handled
 * by the proxy stopping loop. This is to be used during soft_stop() only. It
 * does not return any error.
 */
void protocol_stop_now(void)
{
	struct protocol *proto;
	struct listener *listener, *lback;

	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list) {
		list_for_each_entry_safe(listener, lback, &proto->receivers, rx.proto_list)
			if (!listener->bind_conf->frontend->grace)
				stop_listener(listener, 0, 1, 0);
	}
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
}

/* pauses all listeners of all registered protocols. This is typically
 * used on SIG_TTOU to release all listening sockets for the time needed to
 * try to bind a new process. The listeners enter LI_PAUSED. It returns
 * ERR_NONE, with ERR_FATAL on failure.
 */
int protocol_pause_all(void)
{
	struct protocol *proto;
	struct listener *listener;
	int err;

	err = 0;
	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list) {
		list_for_each_entry(listener, &proto->receivers, rx.proto_list)
			if (!pause_listener(listener))
				err |= ERR_FATAL;
	}
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
	return err;
}

/* resumes all listeners of all registered protocols. This is typically used on
 * SIG_TTIN to re-enable listening sockets after a new process failed to bind.
 * The listeners switch to LI_READY/LI_FULL. It returns ERR_NONE, with ERR_FATAL
 * on failure.
 */
int protocol_resume_all(void)
{
	struct protocol *proto;
	struct listener *listener;
	int err;

	err = 0;
	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list) {
		list_for_each_entry(listener, &proto->receivers, rx.proto_list)
			if (!resume_listener(listener))
				err |= ERR_FATAL;
	}
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
	return err;
}

/* enables all listeners of all registered protocols. This is intended to be
 * used after a fork() to enable reading on all file descriptors. Returns
 * composition of ERR_NONE.
 */
int protocol_enable_all(void)
{
	struct protocol *proto;
	struct listener *listener;

	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list) {
		list_for_each_entry(listener, &proto->receivers, rx.proto_list)
			enable_listener(listener);
	}
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
	return ERR_NONE;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
