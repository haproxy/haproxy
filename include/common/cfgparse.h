/*
 * include/common/cfgparse.h
 * Configuration parsing functions.
 *
 * Copyright (C) 2000-2012 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _COMMON_CFGPARSE_H
#define _COMMON_CFGPARSE_H

#include <common/compat.h>
#include <common/config.h>
#include <common/mini-clist.h>

#include <types/proxy.h>

/* configuration sections */
#define CFG_NONE	0
#define CFG_GLOBAL	1
#define CFG_LISTEN	2
#define CFG_USERLIST	3
#define CFG_PEERS	4

struct cfg_keyword {
	int section;                            /* section type for this keyword */
	const char *kw;                         /* the keyword itself */
	int (*parse)(                           /* 0=OK, <0=Alert, >0=Warning */
		     char **args,               /* command line and arguments */
		     int section_type,          /* current section CFG_{GLOBAL|LISTEN} */
		     struct proxy *curpx,       /* current proxy (NULL in GLOBAL) */
		     struct proxy *defpx,       /* default proxy (NULL in GLOBAL) */
		     const char *file,          /* config file name */
		     int line,                  /* config file line number */
		     char **err);               /* error or warning message output pointer */
};

/* A keyword list. It is a NULL-terminated array of keywords. It embeds a
 * struct list in order to be linked to other lists, allowing it to easily
 * be declared where it is needed, and linked without duplicating data nor
 * allocating memory.
 */
struct cfg_kw_list {
	struct list list;
	struct cfg_keyword kw[VAR_ARRAY];
};


extern int cfg_maxpconn;
extern int cfg_maxconn;

int cfg_parse_global(const char *file, int linenum, char **args, int inv);
int cfg_parse_listen(const char *file, int linenum, char **args, int inv);
int readcfgfile(const char *file);
void cfg_register_keywords(struct cfg_kw_list *kwl);
void cfg_unregister_keywords(struct cfg_kw_list *kwl);
void init_default_instance();
int check_config_validity();

#endif /* _COMMON_CFGPARSE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
