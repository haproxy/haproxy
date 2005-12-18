/*
  This File is copied from
  
  http://www.oreilly.com/catalog/masteralgoc/index.html
  Mastering Algorithms with C
  By Kyle Loudon
  ISBN: 1-56592-453-3
  Publishd by O'Reilly

  We have added our own struct to these function.
 */

/*****************************************************************************
*                                                                            *
*  ------------------------------- hashpjw.h ------------------------------  *
*                                                                            *
*****************************************************************************/

#ifndef HASHPJW_H
#define HASHPJW_H

#include <sys/time.h>

typedef struct appsessions {
    char *sessid;
    char *serverid;
    struct timeval expire;		/* next expiration time for this application session */
    unsigned long int request_count;
} appsess; /* end struct appsessions */

/*****************************************************************************
*                                                                            *
*  Define a table size for demonstration purposes only.                      *
*                                                                            *
*****************************************************************************/

#define            PRIME_TBLSIZ       1699

/*****************************************************************************
*                                                                            *
*  --------------------------- Public Interface ---------------------------  *
*                                                                            *
*****************************************************************************/

int hashpjw(const void *key);

#endif
