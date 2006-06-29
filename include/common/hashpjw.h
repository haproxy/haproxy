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

#ifndef _COMMON_HASHPJW_H
#define _COMMON_HASHPJW_H

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

#endif /* _COMMON_HASHPJW_H */
