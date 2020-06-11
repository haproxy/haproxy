/*
 * include/haproxy/ssl_crtlist-t.h
 * crt-list structures
 *
 * Copyright (C) 2020 HAProxy Technologies, William Lallemand <wlallemand@haproxy.com>
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

#ifndef _HAPROXY_SSL_CRTLIST_T_H
#define _HAPROXY_SSL_CRTLIST_T_H
#ifdef USE_OPENSSL

#include <import/ebmbtree.h>
#include <import/ebpttree.h>


/* forward declarations for structures below */
struct bind_conf;
struct ssl_bind_conf;
struct proxy;

/* list of bind conf used by struct crtlist */
struct bind_conf_list {
	struct bind_conf *bind_conf;
	struct bind_conf_list *next;
};

/* This structure is basically a crt-list or a directory */
struct crtlist {
	struct bind_conf_list *bind_conf; /* list of bind_conf which use this crtlist */
	unsigned int linecount; /* number of lines */
	struct eb_root entries;
	struct list ord_entries; /* list to keep the line order of the crt-list file */
	struct ebmb_node node; /* key is the filename or directory */
};

/* a file in a directory or a line in a crt-list */
struct crtlist_entry {
	struct ssl_bind_conf *ssl_conf; /* SSL conf in crt-list */
	unsigned int linenum;
	unsigned int fcount; /* filters count */
	char **filters;
	struct crtlist *crtlist; /* ptr to the parent crtlist */
	struct list ckch_inst; /* list of instances of this entry, there is 1 ckch_inst per instance of the crt-list */
	struct list by_crtlist; /* ordered entries */
	struct list by_ckch_store; /* linked in ckch_store list of crtlist_entries */
	struct ebpt_node node; /* key is a ptr to a ckch_store */
};

#endif /* USE_OPENSSL */
#endif /* _HAPROXY_SSL_CRTLIST_T_H */
