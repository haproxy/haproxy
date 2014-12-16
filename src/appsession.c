/*
 * AppSession functions.
 *
 * Copyright 2004-2006 Alexander Lazic, Klaus Wagner
 * Copyright 2006-2009 Willy Tarreau
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <common/appsession.h>
#include <common/config.h>
#include <common/memory.h>
#include <common/sessionhash.h>
#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/proxy.h>
#include <proto/task.h>

static struct task *appsess_refresh = NULL;
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

static struct task *appsession_refresh(struct task *t)
{
	struct proxy           *p = proxy;
	struct appsession_hash *htbl;
	appsess                *element, *back;
	int                    i;

	while (p) {
		if (p->appsession_name != NULL) {
			htbl = &p->htbl_proxy;
			as_hash_for_each_entry_safe(i, element, back, &p->htbl_proxy, hash_list) {
				if (tick_is_expired(element->expire, now_ms)) {
					if ((global.mode & MODE_DEBUG) &&
					    (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))) {
						chunk_printf(&trash, "appsession_refresh: cleaning up expired Session '%s' on Server %s\n", 
						             element->sessid, element->serverid?element->serverid:"(null)");
						shut_your_big_mouth_gcc(write(1, trash.str, trash.len));
					}
					/* delete the expired element from within the hash table */
					LIST_DEL(&element->hash_list);
					htbl->destroy(element);
				}/* end if (tv_isle(&asession->expire, &now)) */
			}
		}
		p = p->next;
	}
	t->expire = tick_add(now_ms, MS_TO_TICKS(TBLCHKINT)); /* check expiration every 5 seconds */
	return t;
} /* end appsession_refresh */

int appsession_task_init(void)
{
	static int initialized = 0;
	if (!initialized) {
		if ((appsess_refresh = task_new()) == NULL)
			return -1;

		appsess_refresh->context = NULL;
		appsess_refresh->expire = tick_add(now_ms, MS_TO_TICKS(TBLCHKINT));
		appsess_refresh->process = appsession_refresh;
		task_queue(appsess_refresh);
		initialized ++;
	}
	return 0;
}

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
	pool_free2(apools.sessid, temp1->sessid);
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

	if (appsess_refresh) {
		task_delete(appsess_refresh);
		task_free(appsess_refresh);
		appsess_refresh = NULL;
	}

}/* end appsession_cleanup() */



/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
