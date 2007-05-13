/*
 * AppSession functions.
 *
 * Copyright 2004-2006 Alexander Lazic, Klaus Wagner
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <string.h>

#include <common/appsession.h>
#include <common/chtbl.h>
#include <common/config.h>
#include <common/list.h>
#include <common/time.h>

#include <types/buffers.h>
#include <types/global.h>
#include <types/proxy.h>
#include <types/server.h>

#include <proto/task.h>


void **pool_appsess = NULL;
struct app_pool apools;
int have_appsession;

#if defined(DEBUG_HASH)
void print_table(const CHTbl *htbl)
{
	ListElmt           *element;
	int                i;
	appsess *asession;

	/*********************************************************************
	 *                                                                    *
	 *  Display the chained hash table.                                   *
	 *                                                                    *
	 *********************************************************************/
    
	fprintf(stdout, "Table size is %d\n", chtbl_size(htbl));
    
	for (i = 0; i < TBLSIZ; i++) {
		fprintf(stdout, "Bucket[%03d]\n", i);
	
		for (element = list_head(&htbl->table[i]);
		     element != NULL; element = list_next(element)) {
			//fprintf(stdout, "%c", *(char *)list_data(element));
			asession = (appsess *)list_data(element);
			fprintf(stdout, "ELEM :%s:", asession->sessid);
			fprintf(stdout, " Server :%s: \n", asession->serverid);
			//fprintf(stdout, " Server request_count :%li:\n",asession->request_count);
		}
	
		fprintf(stdout, "\n");
	}
	return;
} /* end print_table */
#endif

int appsession_init(void)
{
	static int          initialized = 0;
	int                 idlen;
	struct server       *s;
	struct proxy        *p = proxy;
    
	if (!initialized) {
		if (!appsession_task_init()) {
			apools.sessid = NULL;
			apools.serverid = NULL;
			apools.ser_waste = 0;
			apools.ser_use = 0;
			apools.ser_msize = sizeof(void *);
			apools.ses_waste = 0;
			apools.ses_use = 0;
			apools.ses_msize = sizeof(void *);
			while (p) {
				s = p->srv;
				if (apools.ses_msize < p->appsession_len)
					apools.ses_msize = p->appsession_len;
				while (s) {
					idlen = strlen(s->id);
					if (apools.ser_msize < idlen)
						apools.ser_msize = idlen;
					s = s->next;
				}
				p = p->next;
			}
			/* we use strings, so reserve space for '\0' */
			apools.ser_msize ++;
			apools.ses_msize ++;
		}
		else {
			fprintf(stderr, "appsession_task_init failed\n");
			return -1;
		}
		initialized ++;
	}
	return 0;
}

int appsession_task_init(void)
{
	static int initialized = 0;
	struct task *t;
	if (!initialized) {
		if ((t = pool_alloc(task)) == NULL)
			return -1;
		t->wq = NULL;
		t->qlist.p = NULL;
		t->state = TASK_IDLE;
		t->context = NULL;
		tv_ms_add(&t->expire, &now, TBLCHKINT);
		task_queue(t);
		t->process = appsession_refresh;
		initialized ++;
	}
	return 0;
}

void appsession_refresh(struct task *t, struct timeval *next)
{
	struct proxy       *p = proxy;
	CHTbl              *htbl;
	ListElmt           *element, *last;
	int                i;
	appsess            *asession;
	void               *data;

	while (p) {
		if (p->appsession_name != NULL) {
			htbl = &p->htbl_proxy;
			/* if we ever give up the use of TBLSIZ, we need to change this */
			for (i = 0; i < TBLSIZ; i++) {
				last = NULL;
				for (element = list_head(&htbl->table[i]);
				     element != NULL; element = list_next(element)) {
					asession = (appsess *)list_data(element);
					if (tv_isle(&asession->expire, &now)) {
						if ((global.mode & MODE_DEBUG) &&
						    (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
							int len;
							/*
							  on Linux NULL pointers are catched by sprintf, on solaris -> segfault 
							*/
							len = sprintf(trash, "appsession_refresh: cleaning up expired Session '%s' on Server %s\n", 
								      asession->sessid,  asession->serverid?asession->serverid:"(null)");
							write(1, trash, len);
						}
						/* delete the expired element from within the hash table */
						if ((list_rem_next(&htbl->table[i], last, (void **)&data) == 0)
						    && (htbl->table[i].destroy != NULL)) {
							htbl->table[i].destroy(data);
						}
						if (last == NULL) {/* patient lost his head, get a new one */
							element = list_head(&htbl->table[i]);
							if (element == NULL) break; /* no heads left, go to next patient */
						}
						else
							element = last;
					}/* end if (tv_isle(&asession->expire, &now)) */
					else
						last = element;
				}/* end  for (element = list_head(&htbl->table[i]); element != NULL; element = list_next(element)) */
			}
		}
		p = p->next;
	}
	tv_ms_add(&t->expire, &now, TBLCHKINT); /* check expiration every 5 seconds */
	*next = t->expire;
} /* end appsession_refresh */

int match_str(const void *key1, const void *key2)
{
    appsess *temp1,*temp2;
    temp1 = (appsess *)key1;
    temp2 = (appsess *)key2;

    //fprintf(stdout,">>>>>>>>>>>>>>temp1->sessid :%s:\n",temp1->sessid);
    //fprintf(stdout,">>>>>>>>>>>>>>temp2->sessid :%s:\n",temp2->sessid);
  
    return (strcmp(temp1->sessid,temp2->sessid) == 0);
}/* end match_str */

void destroy(void *data) {
    appsess *temp1;

    //printf("destroy called\n");
    temp1 = (appsess *)data;

    if (temp1->sessid)
	pool_free_to(apools.sessid, temp1->sessid);

    if (temp1->serverid)
	pool_free_to(apools.serverid, temp1->serverid);

    pool_free(appsess, temp1);
} /* end destroy */

void appsession_cleanup( void )
{
	struct proxy *p = proxy;

	while(p) {
		chtbl_destroy(&(p->htbl_proxy));
		p = p->next;
	}
}/* end appsession_cleanup() */



/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
