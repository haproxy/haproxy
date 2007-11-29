/*
  include/types/backend.h
  This file rassembles definitions for backends

  Copyright (C) 2000-2007 Willy Tarreau - w@1wt.eu
  
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

/* Parameters for proxy->lbprm.algo. Those values are exclusive */
#define BE_LB_ALGO_RR	0x00000001      /* balance in round-robin mode */
#define BE_LB_ALGO_SH	0x00000002      /* balance on source IP hash */
#define BE_LB_ALGO_L4	0x00000003      /* mask to match layer4-based algorithms */
#define BE_LB_ALGO_UH	0x00000004      /* balance on URI hash */
#define BE_LB_ALGO_PH	0x00000005      /* balance on URL parameter hash */
#define BE_LB_ALGO_L7	0x00000004      /* mask to match layer7-based algorithms */
#define BE_LB_ALGO	0x00000007      /* mask to extract BALANCE algorithm */

/* various constants */
#define BE_WEIGHT_SCALE 256             /* scale between user weight and effective weight */

#endif /* _TYPES_BACKEND_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
