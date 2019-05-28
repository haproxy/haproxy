#ifndef _PROTO_DICT_H
#define _PROTO_DICT_H

#include <types/dict.h>

struct dict *new_dict(const char *name);
struct dict_entry *dict_insert(struct dict *d, char *str);

#endif  /* _PROTO_DICT_H */
