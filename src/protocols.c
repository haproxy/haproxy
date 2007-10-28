/*
 * Protocol registration functions.
 *
 * Copyright 2000-2007 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <common/errors.h>
#include <common/mini-clist.h>
#include <common/standard.h>

#include <types/protocols.h>

#include <proto/fd.h>

/* List head of all registered protocols */
static struct list protocols = LIST_HEAD_INIT(protocols);

/* This function adds the specified listener's file descriptor to the polling
 * lists if it is in the LI_LISTEN state. The listener enters LI_READY or
 * LI_FULL state depending on its number of connections.
 */
void enable_listener(struct listener *listener)
{
	if (listener->state == LI_LISTEN) {
		if (listener->nbconn < listener->maxconn) {
			EV_FD_SET(listener->fd, DIR_RD);
			listener->state = LI_READY;
		} else {
			listener->state = LI_FULL;
		}
	}
}

/* This function removes the specified listener's file descriptor from the
 * polling lists if it is in the LI_READY or in the LI_FULL state. The listener
 * enters LI_LISTEN.
 */
void disable_listener(struct listener *listener)
{
	if (listener->state < LI_READY)
		return;
	if (listener->state == LI_READY)
		EV_FD_CLR(listener->fd, DIR_RD);
	listener->state = LI_LISTEN;
}

/* This function adds all of the protocol's listener's file descriptors to the
 * polling lists when they are in the LI_LISTEN state. It is intended to be
 * used as a protocol's generic enable_all() primitive, for use after the
 * fork(). It puts the listeners into LI_READY or LI_FULL states depending on
 * their number of connections. It always returns ERR_NONE.
 */
int enable_all_listeners(struct protocol *proto)
{
	struct listener *listener;

	list_for_each_entry(listener, &proto->listeners, proto_list)
		enable_listener(listener);
	return ERR_NONE;
}

/* This function removes all of the protocol's listener's file descriptors from
 * the polling lists when they are in the LI_READY or LI_FULL states. It is
 * intended to be used as a protocol's generic disable_all() primitive. It puts
 * the listeners into LI_LISTEN, and always returns ERR_NONE.
 */
int disable_all_listeners(struct protocol *proto)
{
	struct listener *listener;

	list_for_each_entry(listener, &proto->listeners, proto_list)
		disable_listener(listener);
	return ERR_NONE;
}

/* This function closes the listening socket for the specified listener,
 * provided that it's already in a listening state. The listener enters the
 * LI_ASSIGNED state. It always returns ERR_NONE. This function is intended
 * to be used as a generic function for standard protocols.
 */
int unbind_listener(struct listener *listener)
{
	if (listener->state == LI_READY)
		EV_FD_CLR(listener->fd, DIR_RD);

	if (listener->state >= LI_LISTEN) {
		fd_delete(listener->fd);
		listener->state = LI_ASSIGNED;
	}
	return ERR_NONE;
}

/* Registers the protocol <proto> */
void protocol_register(struct protocol *proto)
{
	LIST_ADDQ(&protocols, &proto->list);
}

/* Unregisters the protocol <proto>. Note that all listeners must have
 * previously been unbound.
 */
void protocol_unregister(struct protocol *proto)
{
	LIST_DEL(&proto->list);
	LIST_INIT(&proto->list);
}

/* binds all listeners of all registered protocols. Returns a composition
 * of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_bind_all(void)
{
	struct protocol *proto;
	int err;

	err = 0;
	list_for_each_entry(proto, &protocols, list) {
		if (proto->bind_all)
			err |= proto->bind_all(proto);
	}
	return err;
}

/* unbinds all listeners of all registered protocols. They are also closed.
 * This must be performed before calling exit() in order to get a chance to
 * remove file-system based sockets and pipes.
 * Returns a composition of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_unbind_all(void)
{
	struct protocol *proto;
	int err;

	err = 0;
	list_for_each_entry(proto, &protocols, list) {
		if (proto->unbind_all)
			err |= proto->unbind_all(proto);
	}
	return err;
}

/* enables all listeners of all registered protocols. This is intended to be
 * used after a fork() to enable reading on all file descriptors. Returns a
 * composition of ERR_NONE, ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_enable_all(void)
{
	struct protocol *proto;
	int err;

	err = 0;
	list_for_each_entry(proto, &protocols, list) {
		if (proto->enable_all)
			err |= proto->enable_all(proto);
	}
	return err;
}

/* disables all listeners of all registered protocols. This may be used before
 * a fork() to avoid duplicating poll lists. Returns a composition of ERR_NONE,
 * ERR_RETRYABLE, ERR_FATAL.
 */
int protocol_disable_all(void)
{
	struct protocol *proto;
	int err;

	err = 0;
	list_for_each_entry(proto, &protocols, list) {
		if (proto->disable_all)
			err |= proto->disable_all(proto);
	}
	return err;
}

