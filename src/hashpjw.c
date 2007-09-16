/*
  This File is copied from
  
  http://www.oreilly.com/catalog/masteralgoc/index.html
  Mastering Algorithms with C
  By Kyle Loudon
  ISBN: 1-56592-453-3
  Publishd by O'Reilly

  We have added our own struct to these function.

  Updated O'Reilly's copyright notice follows :

  Copyright (c) 1999 O'Reilly & Associates, Inc.

  Mastering Algorithms with C
  Kyle Loudon

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the "Software"),
  to deal in the Software without restriction, including without limitation
  the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom the
  Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL
  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE, OR ANY OTHER
  DEALINGS IN THE SOFTWARE.

 */

/*****************************************************************************
*                                                                            *
*  ------------------------------- hashpjw.c ------------------------------  *
*                                                                            *
*****************************************************************************/

#include <common/config.h>
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
