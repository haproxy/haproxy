/*
 * AppSession functions.
 *
 * Copyright 2004-2006 Alexander Lazic, Klaus Wagner
 * Copyright 2006-2007 Willy Tarreau
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
#include <common/config.h>
#include <common/memory.h>
#include <common/sessionhash.h>
#include <common/time.h>

#include <types/buffers.h>
#include <types/global.h>
#include <types/proxy.h>
#include <types/server.h>

#include <proto/task.h>


struct pool_head *pool2_appsess;
struct app_pool apools;
int have_appsession;

int appsession_init(void)
{
	static int          initialized = 0;
	int                 idlen;
	struct server       *s;
	struct proxy        *p = proxy;
    
	if (!initialized) {
		pool2_appsess = create_pool("appsess", sizeof(appsess), MEM_F_SHARED);
		if (pool2_appsess == NULL)
			return -1;

		if (!appsession_task_init()) {
			int ser_msize, ses_msize;

			apools.sessid = NULL;
			apools.serverid = NULL;

			ser_msize = sizeof(void *);
			ses_msize = sizeof(void *);
			while (p) {
				s = p->srv;
				if (ses_msize < p->appsession_len)
					ses_msize = p->appsession_len;
				while (s) {
					idlen = strlen(s->id);
					if (ser_msize < idlen)
						ser_msize = idlen;
					s = s->next;
				}
				p = p->next;
			}
			/* we use strings, so reserve space for '\0' */
			ser_msize ++;
			ses_msize ++;

			apools.sessid = create_pool("sessid", ses_msize, MEM_F_SHARED);
			if (!apools.sessid)
				return -1;
			apools.serverid = create_pool("serverid", ser_msize, MEM_F_SHARED);
			if (!apools.serverid)
				return -1;
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
		if ((t = pool_alloc2(pool2_task)) == NULL)
			return -1;
		t->wq = NULL;
		t->qlist.p = NULL;
		t->state = TASK_IDLE;
		t->context = NULL;
		tv_ms_add(&t->expire, &now, TBLCHKINT);
		t->process = appsession_refresh;
		task_queue(t);
		initialized ++;
	}
	return 0;
}

void appsession_refresh(struct task *t, struct timeval *next)
{
	struct proxy           *p = proxy;
	struct appsession_hash *htbl;
	appsess                *element, *back;
	int                    i;

	while (p) {
		if (p->appsession_name != NULL) {
			htbl = &p->htbl_proxy;
			as_hash_for_each_entry_safe(i, element, back, &p->htbl_proxy, hash_list) {
				if (tv_isle(&element->expire, &now)) {
					if ((global.mode & MODE_DEBUG) &&
					    (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
						int len;
						/*
						  on Linux NULL pointers are caught by sprintf, on solaris -> segfault 
						*/
						len = sprintf(trash, "appsession_refresh: cleaning up expired Session '%s' on Server %s\n", 
							      element->sessid, element->serverid?element->serverid:"(null)");
						write(1, trash, len);
					}
					/* delete the expired element from within the hash table */
					LIST_DEL(&element->hash_list);
					htbl->destroy(element);
				}/* end if (tv_isle(&asession->expire, &now)) */
			}
		}
		p = p->next;
	}
	tv_ms_add(&t->expire, &now, TBLCHKINT); /* check expiration every 5 seconds */
	task_queue(t);
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

void destroy(appsess *temp1) {
    if (temp1->sessid)
	pool_free2(apools.sessid, temp1->sessid);

    if (temp1->serverid)
	pool_free2(apools.serverid, temp1->serverid);

    pool_free2(pool2_appsess, temp1);
} /* end destroy */

void appsession_cleanup( void )
{
	struct proxy *p = proxy;

	while(p) {
		appsession_hash_destroy(&(p->htbl_proxy));
		p = p->next;
	}
}/* end appsession_cleanup() */



/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
