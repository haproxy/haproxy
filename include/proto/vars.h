#ifndef _PROTO_VARS_H
#define _PROTO_VARS_H

#include <types/vars.h>

void vars_init(struct vars *vars, enum vars_scope scope);
void vars_prune(struct vars *vars, struct stream *strm);
int vars_get_by_name(const char *name, size_t len, struct stream *strm, struct sample *smp);
void vars_set_by_name(const char *name, size_t len, struct stream *strm, struct sample *smp);
int vars_check_arg(struct arg *arg, char **err);

#endif
