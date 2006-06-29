/*
  include/common/config.h
  This files contains most of the user-configurable settings.

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

#ifndef _COMMON_CONFIG_H
#define _COMMON_CONFIG_H

#include <common/defaults.h>

/* this reduces the number of calls to select() by choosing appropriate
 * sheduler precision in milliseconds. It should be near the minimum
 * time that is needed by select() to collect all events. All timeouts
 * are rounded up by adding this value prior to pass it to select().
 */
#define SCHEDULER_RESOLUTION    9

#endif /* _COMMON_CONFIG_H */
