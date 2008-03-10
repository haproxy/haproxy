/*
  include/types/backend.h
  This file rassembles definitions for backends

  Copyright (C) 2000-2008 Willy Tarreau - w@1wt.eu
  
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

#ifndef _TYPES_BACKEND_H
#define _TYPES_BACKEND_H

#include <common/config.h>

/* Parameters for proxy->lbprm.algo.
 * The low part of the value is unique for each algo so that applying the mask
 * BE_LB_ALGO returns a unique algorithm.
 * The high part indicates specific properties.
 */

/* Masks to extract algorithm properties */
#define BE_LB_ALGO	0x000007FF      /* mask to extract all algorithm flags */
#define BE_LB_PROP_DYN  0x00000100      /* mask to match dynamic algorithms */
#define BE_LB_PROP_L4   0x00000200      /* mask to match layer4-based algorithms */
#define BE_LB_PROP_L7   0x00000400      /* mask to match layer7-based algorithms */

/* the algorithms themselves */
#define BE_LB_ALGO_NONE 0x00000000              /* dispatch or transparent mode */
#define BE_LB_ALGO_RR	(BE_LB_PROP_DYN | 0x01) /* fast weighted round-robin mode (dynamic) */
#define BE_LB_ALGO_SH	(BE_LB_PROP_L4  | 0x02) /* balance on source IP hash */
#define BE_LB_ALGO_UH	(BE_LB_PROP_L7  | 0x03) /* balance on URI hash */
#define BE_LB_ALGO_PH	(BE_LB_PROP_L7  | 0x04) /* balance on URL parameter hash */
#define BE_LB_ALGO_LC	(BE_LB_PROP_DYN | 0x05) /* fast weighted round-robin mode (dynamic) */

/* various constants */

/* The scale factor between user weight an effective weight allows smooth
 * weight modulation even with small weights (eg: 1). It should not be too high
 * though because it limits the number of servers in FWRR mode in order to
 * prevent any integer overflow. The max number of servers per backend is
 * limited to about 2^32/255^2/scale ~= 66051/scale. A scale of 16 looks like
 * a good value, as it allows more than 4000 servers per backend while leaving
 * modulation steps of about 6% for servers with the lowest weight (1).
 */
#define BE_WEIGHT_SCALE 16

#endif /* _TYPES_BACKEND_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
