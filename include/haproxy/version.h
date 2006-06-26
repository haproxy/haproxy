/*
  include/haproxy/version.h
  This file serves as a template for future include files.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _HAPROXY_VERSION_H
#define _HAPROXY_VERSION_H

#ifdef  CONFIG_PRODUCT_NAME
#define PRODUCT_NAME CONFIG_PRODUCT_NAME
#else
#define PRODUCT_NAME "HAProxy"
#endif

#ifndef HAPROXY_VERSION
#define HAPROXY_VERSION "1.3.0"
#endif

#ifndef HAPROXY_DATE
#define HAPROXY_DATE    "2006/06/26"
#endif

#endif /* _HAPROXY_VERSION_H */
