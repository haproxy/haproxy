/*
  include/proto/httperr.h
  This file contains declarations for HTTP responses and errors.

  Copyright (C) 2000-2006 Willy Tarreau - w@1wt.eu
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation, version 2.1
  exclusively.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _PROTO_HTTPERR_H
#define _PROTO_HTTPERR_H

#include <types/httperr.h>

extern const int http_err_codes[HTTP_ERR_SIZE];
extern struct chunk http_err_chunks[HTTP_ERR_SIZE];
extern const char *HTTP_200;
extern const char *HTTP_302;
extern const char *HTTP_303;
extern const char *HTTP_401_fmt;

struct chunk *error_message(struct session *s, int msgnum);

#endif /* _PROTO_HTTPERR_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
