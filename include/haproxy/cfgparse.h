/*
 * include/haproxy/cfgparse.h
 * Configuration parsing functions.
 *
 * Copyright (C) 2000-2020 Willy Tarreau - w@1wt.eu
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

#ifndef _HAPROXY_CFGPARSE_H
#define _HAPROXY_CFGPARSE_H

#include <haproxy/api.h>

struct hap_cpuset;
struct proxy;
struct bind_conf;
struct acl_cond;

/* configuration sections */
#define CFG_NONE	0
#define CFG_GLOBAL	1
#define CFG_LISTEN	2
#define CFG_USERLIST	3
#define CFG_PEERS	4

/* various keyword modifiers */
enum kw_mod {
	KWM_STD = 0,  /* normal */
	KWM_NO,       /* "no" prefixed before the keyword */
	KWM_DEF,      /* "default" prefixed before the keyword */
};

enum cfg_keyword_flags {
	KWF_EXPERIMENTAL = 0x1,
	KWF_MATCH_PREFIX = 0x2,
};

struct cfg_keyword {
	int section;                            /* section type for this keyword */
	const char *kw;                         /* the keyword itself */
	int (*parse)(                           /* 0=OK, <0=Alert, >0=Warning */
		     char **args,               /* command line and arguments */
		     int section_type,          /* current section CFG_{GLOBAL|LISTEN} */
		     struct proxy *curpx,       /* current proxy (NULL in GLOBAL) */
		     const struct proxy *defpx, /* default proxy (NULL in GLOBAL) */
		     const char *file,          /* config file name */
		     int line,                  /* config file line number */
		     char **err);               /* error or warning message output pointer */
	int flags;
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

/* permit to store configuration section */
struct cfg_section {
	struct list list;
	char *section_name;
	int (*section_parser)(const char *, int, char **, int);
	int (*post_section_parser)();
};

/* store post configuration parsing */

struct cfg_postparser {
	struct list list;
	char *name;
	int (*func)();
};

extern int cfg_maxpconn;
extern int cfg_maxconn;
extern char *cfg_scope;
extern struct cfg_kw_list cfg_keywords;
extern char *cursection;

int cfg_parse_global(const char *file, int linenum, char **args, int inv);
int cfg_parse_listen(const char *file, int linenum, char **args, int inv);
int cfg_parse_track_sc_num(unsigned int *track_sc_num,
                           const char *arg, const char *end, char **err);
int readcfgfile(const char *file);
void cfg_register_keywords(struct cfg_kw_list *kwl);
void cfg_unregister_keywords(struct cfg_kw_list *kwl);
int check_config_validity();
int str2listener(char *str, struct proxy *curproxy, struct bind_conf *bind_conf, const char *file, int line, char **err);
int str2receiver(char *str, struct proxy *curproxy, struct bind_conf *bind_conf, const char *file, int line, char **err);
int cfg_register_section(char *section_name,
                         int (*section_parser)(const char *, int, char **, int),
                         int (*post_section_parser)());
int cfg_register_postparser(char *name, int (*func)());
void cfg_unregister_sections(void);
void cfg_backup_sections(struct list *backup_sections);
void cfg_restore_sections(struct list *backup_sections);
int warnif_misplaced_tcp_conn(struct proxy *proxy, const char *file, int line, const char *arg);
int warnif_misplaced_tcp_sess(struct proxy *proxy, const char *file, int line, const char *arg);
int warnif_misplaced_tcp_cont(struct proxy *proxy, const char *file, int line, const char *arg);
int warnif_cond_conflicts(const struct acl_cond *cond, unsigned int where, const char *file, int line);
int warnif_tcp_http_cond(const struct proxy *px, const struct acl_cond *cond);
int too_many_args_idx(int maxarg, int index, char **args, char **msg, int *err_code);
int too_many_args(int maxarg, char **args, char **msg, int *err_code);
int alertif_too_many_args_idx(int maxarg, int index, const char *file, int linenum, char **args, int *err_code);
int alertif_too_many_args(int maxarg, const char *file, int linenum, char **args, int *err_code);
int parse_process_number(const char *arg, unsigned long *proc, int max, int *autoinc, char **err);
unsigned long parse_cpu_set(const char **args, struct hap_cpuset *cpu_set, int comma_allowed, char **err);
void free_email_alert(struct proxy *p);
const char *cfg_find_best_match(const char *word, const struct list *list, int section, const char **extra);
int warnifnotcap(struct proxy *proxy, int cap, const char *file, int line, const char *arg, const char *hint);
int failifnotcap(struct proxy *proxy, int cap, const char *file, int line, const char *arg, const char *hint);

/* simplified way to define a section parser */
#define REGISTER_CONFIG_SECTION(name, parse, post)                            \
	INITCALL3(STG_REGISTER, cfg_register_section, (name), (parse), (post))

#define REGISTER_CONFIG_POSTPARSER(name, parser)                              \
	INITCALL2(STG_REGISTER, cfg_register_postparser, (name), (parser))

#endif /* _HAPROXY_CFGPARSE_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
