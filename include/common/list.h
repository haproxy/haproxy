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
*  -------------------------------- list.h --------------------------------  *
*                                                                            *
*****************************************************************************/

#ifndef _COMMON_LIST_H
#define _COMMON_LIST_H

#include <stdlib.h>
#include <common/config.h>

/*****************************************************************************
 *                                                                            *
 *  Define a structure for linked list elements.                              *
 *                                                                            *
 *****************************************************************************/

typedef struct ListElmt_ {
	void               *data;
	struct ListElmt_   *next;
} ListElmt;

/*****************************************************************************
 *                                                                            *
 *  Define a structure for linked lists.                                      *
 *                                                                            *
 *****************************************************************************/

typedef struct List_ {
	int                size;
	int                (*match)(const void *key1, const void *key2);
	void               (*destroy)(void *data);
  
	ListElmt           *head;
	ListElmt           *tail;
} List;

/*****************************************************************************
 *                                                                            *
 *  --------------------------- Public Interface ---------------------------  *
 *                                                                            *
 *****************************************************************************/

void list_init(List *list, void (*destroy)(void *data));

void list_destroy(List *list);

int list_ins_next(List *list, ListElmt *element, const void *data);

int list_rem_next(List *list, ListElmt *element, void **data);

#define list_size(list) ((list)->size)

#define list_head(list) ((list)->head)

#define list_tail(list) ((list)->tail)

#define list_is_head(list, element) ((element) == (list)->head ? 1 : 0)

#define list_is_tail(element) ((element)->next == NULL ? 1 : 0)

#define list_data(element) ((element)->data)

#define list_next(element) ((element)->next)

#endif /* _COMMON_LIST_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
