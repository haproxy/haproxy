#ifndef _PROTO_VARS_H
#define _PROTO_VARS_H

#include <types/vars.h>

void vars_init(struct vars *vars, enum vars_scope scope);
void vars_prune(struct vars *vars, struct stream *strm);
int vars_check_arg(struct arg *arg, char **err);

#endif
