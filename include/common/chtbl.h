/*
  This File is copied from
  
  http://www.oreilly.com/catalog/masteralgoc/index.html
  Mastering Algorithms with C
  By Kyle Loudon
  ISBN: 1-56592-453-3
  Publishd by O'Reilly
  
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

