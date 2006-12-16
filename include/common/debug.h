/*
  include/common/debug.h
  This files contains some macros to help debugging.

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

#ifndef _COMMON_DEBUG_H
#define _COMMON_DEBUG_H

#include <common/config.h>

#ifdef DEBUG_FULL
#define DPRINTF(x...) fprintf(x)
#else
#define DPRINTF(x...)
#endif

#ifdef DEBUG_FSM
#define FSM_PRINTF(x...) fprintf(x)
#else
#define FSM_PRINTF(x...)
#endif

#endif /* _COMMON_DEBUG_H */
