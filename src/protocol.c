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
#include <haproxy/global.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/proto_quic.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/sock.h>
#include <haproxy/tools.h>


/* List head of all registered protocols */
static struct list protocols = LIST_HEAD_INIT(protocols);
struct protocol *__protocol_by_family[AF_CUST_MAX][PROTO_NUM_TYPES][2] __read_mostly = { };
const struct proto_fam *__proto_fam_by_family[AF_CUST_MAX] = { };

/* This is the global spinlock we may need to register/unregister listeners or
 * protocols. Its main purpose is in fact to serialize the rare stop/deinit()
 * phases.
 */
__decl_spinlock(proto_lock);

/* Registers the protocol <proto> */
void protocol_register(struct protocol *proto)
{
	int sock_family = proto->fam->sock_family;

	BUG_ON(sock_family < 0 || sock_family >= AF_CUST_MAX);
	BUG_ON(proto->proto_type >= PROTO_NUM_TYPES);

	LIST_INIT(&proto->receivers);
	proto->nb_receivers = 0;

	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	LIST_APPEND(&protocols, &proto->list);
	__protocol_by_family[sock_family]
	                    [proto->proto_type]
	                    [proto->xprt_type == PROTO_TYPE_DGRAM ||
	                     proto->sock_prot == IPPROTO_MPTCP] = proto;
	__proto_fam_by_family[sock_family] = proto->fam;
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

/* clears flag <flag> on all protocols. */
void protocol_clrf_all(uint flag)
{
	struct protocol *proto;

	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list)
		proto->flags &= ~flag;
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
}

/* sets flag <flag> on all protocols. */
void protocol_setf_all(uint flag)
{
	struct protocol *proto;

	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list)
		proto->flags |= flag;
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
}

/* Checks if protocol <proto> supports PROTO_F flag <flag>. Returns zero if not,
 * non-zero if supported. It may return a cached value from a previous test,
 * and may run live tests then update the proto's flags to cache a result. It's
 * better to call it only if needed so that it doesn't result in modules being
 * loaded in case of a live test. It is only supposed to be used during boot.
 */
int protocol_supports_flag(struct protocol *proto, uint flag)
{
	if (flag == PROTO_F_REUSEPORT_SUPPORTED) {
		int ret = 0;

		/* check if the protocol supports SO_REUSEPORT */
		if (!(_HA_ATOMIC_LOAD(&proto->flags) & PROTO_F_REUSEPORT_SUPPORTED))
			return 0;

		/* at least nobody said it was not supported */
		if (_HA_ATOMIC_LOAD(&proto->flags) & PROTO_F_REUSEPORT_TESTED)
			return 1;

		/* run a live check */
		ret = _sock_supports_reuseport(proto->fam, proto->sock_type, proto->sock_prot);
		if (!ret)
			_HA_ATOMIC_AND(&proto->flags, ~PROTO_F_REUSEPORT_SUPPORTED);

		_HA_ATOMIC_OR(&proto->flags, PROTO_F_REUSEPORT_TESTED);
		return ret;
	}
	return 0;
}

#ifdef USE_QUIC
/* Return 1 if QUIC protocol may be bound, 0 if no, depending on the tuning
 * parameters.
 */
static inline int protocol_may_bind_quic(struct listener *l)
{
	if (global.tune.options & GTUNE_NO_QUIC)
		return 0;
	return 1;
}
#endif

/* binds all listeners of all registered protocols. Returns a composition
 * of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_bind_all(int verbose)
{
	struct protocol *proto;
	struct listener *listener;
	struct receiver *receiver;
	char msg[1000];
	char *errmsg;
	int err, lerr;

	err = 0;
	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list) {
		list_for_each_entry(receiver, &proto->receivers, proto_list) {
			listener = LIST_ELEM(receiver, struct listener *, rx);
#ifdef USE_QUIC
			if ((proto == &proto_quic4 || proto == &proto_quic6) &&
			    !protocol_may_bind_quic(listener))
				continue;
#endif

			lerr = proto->fam->bind(receiver, &errmsg);
			err |= lerr;

			/* errors are reported if <verbose> is set or if they are fatal */
			if (verbose || (lerr & (ERR_FATAL | ERR_ABORT))) {
				struct proxy *px = listener->bind_conf->frontend;

				if (lerr & ERR_ALERT)
					ha_alert("Binding [%s:%d] for %s %s: protocol %s: %s.\n",
					         listener->bind_conf->file, listener->bind_conf->line,
						 proxy_type_str(px), px->id, proto->name, errmsg);
				else if (lerr & ERR_WARN)
					ha_warning("Binding [%s:%d] for %s %s: protocol %s: %s.\n",
					           listener->bind_conf->file, listener->bind_conf->line,
						   proxy_type_str(px), px->id, proto->name, errmsg);
			}
			if (lerr != ERR_NONE)
				ha_free(&errmsg);

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
					ha_alert("Starting [%s:%d] for %s %s: protocol %s: %s.\n",
					         listener->bind_conf->file, listener->bind_conf->line,
						 proxy_type_str(px), px->id, proto->name, msg);
				else if (lerr & ERR_WARN)
					ha_warning("Starting [%s:%d] for %s %s: protocol %s: %s.\n",
					           listener->bind_conf->file, listener->bind_conf->line,
						   proxy_type_str(px), px->id, proto->name, msg);
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

/* stops all listeners of all registered protocols. This will normally catch
 * every single listener, all protocols included. This is to be used during
 * soft_stop() only. It does not return any error.
 */
void protocol_stop_now(void)
{
	struct protocol *proto;
	struct listener *listener, *lback;

	HA_SPIN_LOCK(PROTO_LOCK, &proto_lock);
	list_for_each_entry(proto, &protocols, list) {
		list_for_each_entry_safe(listener, lback, &proto->receivers, rx.proto_list)
			stop_listener(listener, 0, 1, 0);
	}
	HA_SPIN_UNLOCK(PROTO_LOCK, &proto_lock);
}

/* suspends all listeners of all registered protocols. This is typically
 * used on SIG_TTOU to release all listening sockets for the time needed to
 * try to bind a new process. The listeners enter LI_PAUSED or LI_ASSIGNED.
 * It returns ERR_NONE, with ERR_FATAL on failure.
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
			if (!suspend_listener(listener, 0, 0))
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
			if (!resume_listener(listener, 0, 0))
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
