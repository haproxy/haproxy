/*
 * include/haproxy/version.h
 * This file serves as a template for future include files.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_VERSION_H
#define _HAPROXY_VERSION_H

#include <haproxy/api.h>

#ifdef  CONFIG_PRODUCT_NAME
#define PRODUCT_NAME    CONFIG_PRODUCT_NAME
#else
#define PRODUCT_NAME    "HAProxy"
#endif

#ifdef  CONFIG_PRODUCT_BRANCH
#define PRODUCT_BRANCH    CONFIG_PRODUCT_BRANCH
#else
#define PRODUCT_BRANCH   "2.6"
#endif

#ifdef  CONFIG_PRODUCT_STATUS
#define PRODUCT_STATUS    CONFIG_PRODUCT_STATUS
#else
#define PRODUCT_STATUS   "Status: development branch - not safe for use in production."
#endif

#ifdef CONFIG_PRODUCT_URL_BUGS
#define PRODUCT_URL_BUGS  CONFIG_PRODUCT_URL_BUGS
#else
#define PRODUCT_URL_BUGS "http://www.haproxy.org/bugs/bugs-%s.html"
#endif

#ifdef  CONFIG_PRODUCT_URL
#define PRODUCT_URL    CONFIG_PRODUCT_URL
#else
#define PRODUCT_URL    "http://www.haproxy.org/"
#endif

#ifdef  CONFIG_PRODUCT_URL_UPD
#define PRODUCT_URL_UPD  CONFIG_PRODUCT_URL_UPD
#else
#define PRODUCT_URL_UPD "http://www.haproxy.org/#down"
#endif

#ifdef  CONFIG_PRODUCT_URL_DOC
#define PRODUCT_URL_DOC  CONFIG_PRODUCT_URL_DOC
#else
#define PRODUCT_URL_DOC "http://www.haproxy.org/#docs"
#endif

#ifdef CONFIG_HAPROXY_VERSION
#define HAPROXY_VERSION CONFIG_HAPROXY_VERSION
#else
#error "Must define CONFIG_HAPROXY_VERSION"
#endif

#ifdef CONFIG_HAPROXY_DATE
#define HAPROXY_DATE    CONFIG_HAPROXY_DATE
#else
#error "Must define CONFIG_HAPROXY_DATE"
#endif

extern char haproxy_version[];
extern char haproxy_date[];
extern char stats_version_string[];

#endif /* _HAPROXY_VERSION_H */

