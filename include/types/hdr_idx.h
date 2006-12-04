/*
  include/types/hdr_idx.h
  This file defines everything related to fast header indexation.

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


/*
 * The type of structure described here is a finite linked list used to
 * reference small number of objects of small size. This is typically used
 * to index HTTP headers within one request or response, in order to be able
 * to add, remove, modify and check them in an efficient way. The overhead is
 * very low : 32 bits are used per list element. This is enough to reference
 * 32k headers of at most 64kB each, with one bit to indicate if the header
 * is terminated by 1 or 2 chars. It may also evolve towards something like
 * 1k headers of at most 64B for the name and 32kB of data + CR/CRLF.
 *
 * A future evolution of this concept may allow for fast header manipulation
 * without data movement through the use of vectors. This is not yet possible
 * in this version, whose goal is only to avoid parsing whole lines for each
 * consultation.
 *
 */


#ifndef _TYPES_HDR_IDX_H
#define _TYPES_HDR_IDX_H

/*
 * This describes one element of the hdr_idx array.
 * It's a tiny linked list of at most 32k 32bit elements. The first one has a
 * special meaning, it's used as the head of the list and cannod be removed.
 * That way, we know that 'next==0' is not possible so we use it to indicate
 * an end of list. Also, [0]->next always designates the head of the list. The
 * first allocatable element is at 1. By convention, [0]->len indicates how
 * many chars should be skipped in the original buffer before finding the first
 * header.
 *
 */

struct hdr_idx_elem {
        unsigned len  :16; /* length of this header not counting CRLF. 0=unused entry. */
        unsigned cr   : 1; /* CR present (1=CRLF, 0=LF). Total line size=len+cr+1. */
        unsigned next :15; /* offset of next header if len>0. 0=end of list. */
};

/*
 * This structure provides necessary information to store, find, remove
 * index entries from a list. This list cannot reference more than 32k
 * elements of 64k each.
 */
struct hdr_idx {
	struct hdr_idx_elem *v;     /* the array itself */
	short size;                 /* size of the array including the head */
	short used;                 /* # of elements really used (1..size) */
	short last;                 /* length of the allocated area (1..size) */
	signed short tail;          /* last used element, 0..size-1 */
};



#endif /* _TYPES_HDR_IDX_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
