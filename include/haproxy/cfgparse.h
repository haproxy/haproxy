/*
  include/haproxy/cfgparse.h
  Configuration parsing functions.

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

#ifndef _HAPROXY_CFGPARSE_H
#define _HAPROXY_CFGPARSE_H

/* configuration sections */
#define CFG_NONE	0
#define CFG_GLOBAL	1
#define CFG_LISTEN	2

extern int cfg_maxpconn;
extern int cfg_maxconn;

int cfg_parse_global(char *file, int linenum, char **args);
int cfg_parse_listen(char *file, int linenum, char **args);
int readcfgfile(char *file);


#endif /* _HAPROXY_CFGPARSE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
