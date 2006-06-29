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
*  ------------------------------- hashpjw.c ------------------------------  *
*                                                                            *
*****************************************************************************/

#include <common/hashpjw.h>
#include <common/appsession.h>

/*****************************************************************************
*                                                                            *
*  -------------------------------- hashpjw -------------------------------  *
*                                                                            *
*****************************************************************************/

int hashpjw(const void *key) {

	const char         *ptr;
	unsigned int        val;
	appsess *appsession_temp;

	/*********************************************************************
	 *                                                                    *
	 *  Hash the key by performing a number of bit operations on it.      *
	 *                                                                    *
	 *********************************************************************/

	val = 0;
	appsession_temp = (appsess *)key;
	ptr = appsession_temp->sessid;

	while (*ptr != '\0') {

		int tmp;

		val = (val << 4) + (*ptr);

		if((tmp = (val & 0xf0000000))) {
			val = val ^ (tmp >> 24);
			val = val ^ tmp;
		}
		ptr++;
	}/* end while */

	/*********************************************************************
	 *                                                                    *
	 *  In practice, replace PRIME_TBLSIZ with the actual table size.     *
	 *                                                                    *
	 *********************************************************************/
	return val % PRIME_TBLSIZ;
}/* end hashpjw */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
