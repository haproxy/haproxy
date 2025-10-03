// Copyright (c) 2018-2020 Cesanta Software Limited
// All rights reserved
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef MJSON_H
#define MJSON_H

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifndef MJSON_ENABLE_PRINT
#define MJSON_ENABLE_PRINT 1
#endif

#ifndef MJSON_ENABLE_RPC
#define MJSON_ENABLE_RPC 1
#endif

#ifndef MJSON_ENABLE_BASE64
#define MJSON_ENABLE_BASE64 1
#endif

#ifndef MJSON_ENABLE_MERGE
#define MJSON_ENABLE_MERGE 0
#elif MJSON_ENABLE_MERGE
#define MJSON_ENABLE_NEXT 1
#endif

#ifndef MJSON_ENABLE_PRETTY
#define MJSON_ENABLE_PRETTY 0
#elif MJSON_ENABLE_PRETTY
#define MJSON_ENABLE_NEXT 1
#endif

#ifndef MJSON_ENABLE_NEXT
#define MJSON_ENABLE_NEXT 0
#endif

#ifndef MJSON_RPC_LIST_NAME
#define MJSON_RPC_LIST_NAME "rpc.list"
#endif

#ifndef MJSON_DYNBUF_CHUNK
#define MJSON_DYNBUF_CHUNK 256  // Allocation granularity for print_dynamic_buf
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
  MJSON_ERROR_INVALID_INPUT = -1,
  MJSON_ERROR_TOO_DEEP = -2,
};

enum mjson_tok {
  MJSON_TOK_INVALID = 0,
  MJSON_TOK_KEY = 1,
  MJSON_TOK_STRING = 11,
  MJSON_TOK_NUMBER = 12,
  MJSON_TOK_TRUE = 13,
  MJSON_TOK_FALSE = 14,
  MJSON_TOK_NULL = 15,
  MJSON_TOK_ARRAY = 91,
  MJSON_TOK_OBJECT = 123,
};
#define MJSON_TOK_IS_VALUE(t) ((t) > 10 && (t) < 20)

typedef int (*mjson_cb_t)(int ev, const char *s, int off, int len, void *ud);

#ifndef MJSON_MAX_DEPTH
#define MJSON_MAX_DEPTH 20
#endif

int mjson(const char *s, int len, mjson_cb_t cb, void *ud);
enum mjson_tok mjson_find(const char *s, int len, const char *jp,
                          const char **tokptr, int *toklen);
int mjson_get_number(const char *s, int len, const char *path, double *v);
int mjson_get_bool(const char *s, int len, const char *path, int *v);
int mjson_get_string(const char *s, int len, const char *path, char *to, int n);
int mjson_get_hex(const char *s, int len, const char *path, char *to, int n);

#if MJSON_ENABLE_NEXT
int mjson_next(const char *s, int n, int off, int *koff, int *klen, int *voff,
               int *vlen, int *vtype);
#endif

#if MJSON_ENABLE_BASE64
int mjson_get_base64(const char *s, int len, const char *path, char *to, int n);
int mjson_base64_dec(const char *src, int n, char *dst, int dlen);
#endif

#if MJSON_ENABLE_PRINT
typedef int (*mjson_print_fn_t)(const char *buf, int len, void *userdata);
typedef int (*mjson_vprint_fn_t)(mjson_print_fn_t, void *, va_list *);

struct mjson_fixedbuf {
  char *ptr;
  int size, len;
};

int mjson_printf(mjson_print_fn_t, void *, const char *fmt, ...);
int mjson_vprintf(mjson_print_fn_t, void *, const char *fmt, va_list ap);
int mjson_print_str(mjson_print_fn_t, void *, const char *s, int len);
int mjson_print_int(mjson_print_fn_t, void *, int value, int is_signed);
int mjson_print_long(mjson_print_fn_t, void *, long value, int is_signed);
int mjson_print_buf(mjson_print_fn_t fn, void *, const char *buf, int len);

int mjson_print_null(const char *ptr, int len, void *userdata);
int mjson_print_fixed_buf(const char *ptr, int len, void *userdata);
int mjson_print_dynamic_buf(const char *ptr, int len, void *userdata);

#if MJSON_ENABLE_PRETTY
int mjson_pretty(const char *, int, const char *, mjson_print_fn_t, void *);
#endif

#if MJSON_ENABLE_MERGE
int mjson_merge(const char *, int, const char *, int, mjson_print_fn_t, void *);
#endif

#endif  // MJSON_ENABLE_PRINT

#ifdef __cplusplus
}
#endif
#endif  // MJSON_H
