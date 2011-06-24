#ifndef _COMMON_APPSESS_H
#define _COMMON_APPSESS_H

/*
 * The time between two calls of appsession_refresh in ms.
 */
#define TBLCHKINT 5000

#include <sys/time.h>

#include <common/config.h>
#include <common/memory.h>

#include <types/task.h>

typedef struct appsessions {
	char *sessid;
	char *serverid;
	int   expire;		/* next expiration time for this application session (in tick) */
	unsigned long int request_count;
	struct list hash_list;
} appsess;

extern struct pool_head *pool2_appsess;

struct app_pool {
	struct pool_head *sessid;
	struct pool_head *serverid;
};

extern struct app_pool apools;
extern int have_appsession;


/* Callback for hash_lookup */
int match_str(const void *key1, const void *key2);

/* Callback for destroy */
void destroy(appsess *data);

int appsession_task_init(void);
int appsession_init(void);
void appsession_cleanup(void);

#endif /* _COMMON_APPSESS_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
