/*
  This File is copied from
  
  http://www.oreilly.com/catalog/masteralgoc/index.html
  Mastering Algorithms with C
  By Kyle Loudon
  ISBN: 1-56592-453-3
  Publishd by O'Reilly
  
  Updated O'Reilly's copyright notice follows :

  Copyright (c) 1999 O'Reilly & Associates, Inc.

  Mastering Algorithms with C
  Kyle Loudon

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the "Software"),
  to deal in the Software without restriction, including without limitation
  the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom the
  Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL
  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE, OR ANY OTHER
  DEALINGS IN THE SOFTWARE.

 */

/*****************************************************************************
*                                                                            *
*  ------------------------------- chtbl.h --------------------------------  *
*                                                                            *
*****************************************************************************/

#ifndef _COMMON_CHTBL_H
#define _COMMON_CHTBL_H

#include <stdlib.h>

#include <common/config.h>
#include <common/list.h>

/*****************************************************************************
*                                                                            *
*  Define a structure for chained hash tables.                               *
*                                                                            *
*****************************************************************************/

typedef struct CHTbl_ {

  int                buckets;

  int                (*h)(const void *key);
  int                (*match)(const void *key1, const void *key2);
  void               (*destroy)(void *data);

  int                size;
  List               *table;
} CHTbl;

/*****************************************************************************
 *                                                                            *
 *  --------------------------- Public Interface ---------------------------  *
 *                                                                            *
 *****************************************************************************/

int chtbl_init(CHTbl *htbl, int buckets, int (*h)(const void *key), int
	       (*match)(const void *key1, const void *key2), void (*destroy)(void *data));

void chtbl_destroy(CHTbl *htbl);

int chtbl_insert(CHTbl *htbl, const void *data);

int chtbl_remove(CHTbl *htbl, void **data);

int chtbl_lookup(const CHTbl *htbl, void **data);

#define chtbl_size(htbl) ((htbl)->size)

#endif /* _COMMON_CHTBL_H */

