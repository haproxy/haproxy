#ifndef _APPSESS_H
#define _APPSESS_H

#define TBLSIZ 10
#define TBLCHKINT 5000 /* The time between two calls of appsession_refresh in ms */

/*
  These Parts are copied from
  
  http://www.oreilly.com/catalog/masteralgoc/index.html
  Mastering Algorithms with C
  By Kyle Loudon
  ISBN: 1-56592-453-3
  Publishd by O'Reilly

  We have added our own struct to these function.
 */

#include <include/list.h>
#include <include/chtbl.h>
#include <include/hashpjw.h>
/* end of copied parts */

struct app_pool {
    void **sessid;
    void **serverid;
    int ses_waste, ses_use, ses_msize;
    int ser_waste, ser_use, ser_msize;
};

struct app_pool apools;
int have_appsession;

/* Callback for hash_lookup */
int match_str(const void *key1, const void *key2);

/* Callback for destroy */
void destroy(void *data);

#if defined(DEBUG_HASH)
static void print_table(const CHTbl *htbl);
#endif

#endif
