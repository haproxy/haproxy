/*
 * include/haproxy/fix-t.h
 * This file contains structure declarations for FIX protocol.
 *
 * Copyright 2020 Baptiste Assmann <bedis9@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _HAPROXY_FIX_T_H
#define _HAPROXY_FIX_T_H

#include <import/ist.h>

/*
 * FIX messages are composed by a list of Tag=Value separated by a 'delimiter'
 */
#define FIX_DELIMITER 0x01

/*
 * know FIX version strings
 */
#define FIX_4_0     (ist("FIX.4.0"))
#define FIX_4_1     (ist("FIX.4.1"))
#define FIX_4_2     (ist("FIX.4.2"))
#define FIX_4_3     (ist("FIX.4.3"))
#define FIX_4_4     (ist("FIX.4.4"))
#define FIX_5_0     (ist("FIXT.1.1"))
/* FIX_5_0SP1 and FIX_5_0SP2 have the same version string than FIX5_0 */

/*
 * Supported FIX tag ID
 */
#define FIX_TAG_BeginString    8
#define FIX_TAG_BodyLength     9
#define FIX_TAG_CheckSum       10
#define FIX_TAG_MsgType        35
#define FIX_TAG_SenderCompID    49
#define FIX_TAG_TargetCompID    56


#define FIX_MSG_MINSIZE        26 /* Minimal length for a FIX Message */
#define FIX_CHKSUM_SIZE        7  /* Length of the CheckSum tag (10=NNN<delim>) */
/*
 * return code when parsing / validating FIX messages
 */
#define FIX_INVALID_MESSAGE   -1
#define FIX_NEED_MORE_DATA     0
#define FIX_VALID_MESSAGE      1

#endif /* _HAPROXY_FIX_T_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
