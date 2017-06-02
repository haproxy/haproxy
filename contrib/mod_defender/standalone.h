/*
 * Mod Defender for HAProxy
 *
 * Support for the Mod Defender code on non-Apache platforms.
 *
 * Copyright 2017 HAProxy Technologies, Dragan Dosen <ddosen@haproxy.com>
 *
 * Parts of code based on Apache HTTP Server source
 * Copyright 2015 The Apache Software Foundation (http://www.apache.org/)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 3 of the License, or (at your option) any later version.
 *
 */
#ifndef __STANDALONE_H__
#define __STANDALONE_H__

#include <http_core.h>
#include <http_main.h>
#include <http_config.h>

#include <apr_pools.h>
#include <apr_hooks.h>

#define INSERT_BEFORE(f, before_this) ((before_this) == NULL                \
                           || (before_this)->frec->ftype > (f)->frec->ftype \
                           || (before_this)->r != (f)->r)

#define DECLARE_EXTERNAL_HOOK(ns,link,ret,name,args)                           \
ns##_HOOK_##name##_t *run_##ns##_hook_##name = NULL;                           \
link##_DECLARE(void) ns##_hook_##name(ns##_HOOK_##name##_t *pf,                \
                                      const char * const *aszPre,              \
                                      const char * const *aszSucc, int nOrder) \
{                                                                              \
	run_##ns##_hook_##name = pf;                                           \
}

#define DECLARE_HOOK(ret,name,args) \
	DECLARE_EXTERNAL_HOOK(ap,AP,ret,name,args)

#define UNKNOWN_METHOD (-1)

extern void (*logger)(int level, char *str);
extern const char *read_module_config(server_rec *s, void *mconfig,
                                      const command_rec *cmds,
                                      apr_pool_t *p, apr_pool_t *ptemp,
                                      const char *filename);
extern int lookup_builtin_method(const char *method, apr_size_t len);

#endif /* __STANDALONE_H__ */
