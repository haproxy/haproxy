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

#include <float.h>
#include <math.h>

#include <import/mjson.h>

#if defined(_MSC_VER)
#define alloca(x) _alloca(x)
#endif

#if defined(_MSC_VER) && _MSC_VER < 1700
#define va_copy(x, y) (x) = (y)
#define isinf(x) !_finite(x)
#define isnan(x) _isnan(x)
#endif

static double mystrtod(const char *str, char **end);

static int mjson_esc(int c, int esc) {
  const char *p, *esc1 = "\b\f\n\r\t\\\"", *esc2 = "bfnrt\\\"";
  for (p = esc ? esc1 : esc2; *p != '\0'; p++) {
    if (*p == c) return esc ? esc2[p - esc1] : esc1[p - esc2];
  }
  return 0;
}

static int mjson_escape(int c) {
  return mjson_esc(c, 1);
}

static int mjson_pass_string(const char *s, int len) {
  int i;
  for (i = 0; i < len; i++) {
    if (s[i] == '\\' && i + 1 < len && mjson_escape(s[i + 1])) {
      i++;
    } else if (s[i] == '\0') {
      return MJSON_ERROR_INVALID_INPUT;
    } else if (s[i] == '"') {
      return i;
    }
  }
  return MJSON_ERROR_INVALID_INPUT;
}

int mjson(const char *s, int len, mjson_cb_t cb, void *ud) {
  enum { S_VALUE, S_KEY, S_COLON, S_COMMA_OR_EOO } expecting = S_VALUE;
  unsigned char nesting[MJSON_MAX_DEPTH];
  int i, depth = 0;
#define MJSONCALL(ev) \
  if (cb != NULL && cb(ev, s, start, i - start + 1, ud)) return i + 1;

// In the ascii table, the distance between `[` and `]` is 2.
// Ditto for `{` and `}`. Hence +2 in the code below.
#define MJSONEOO()                                                     \
  do {                                                                 \
    if (c != nesting[depth - 1] + 2) return MJSON_ERROR_INVALID_INPUT; \
    depth--;                                                           \
    if (depth == 0) {                                                  \
      MJSONCALL(tok);                                                  \
      return i + 1;                                                    \
    }                                                                  \
  } while (0)

  for (i = 0; i < len; i++) {
    int start = i;
    unsigned char c = ((unsigned char *) s)[i];
    int tok = c;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
    // printf("- %c [%.*s] %d %d\n", c, i, s, depth, expecting);
    switch (expecting) {
      case S_VALUE:
        if (c == '{') {
          if (depth >= (int) sizeof(nesting)) return MJSON_ERROR_TOO_DEEP;
          nesting[depth++] = c;
          expecting = S_KEY;
          break;
        } else if (c == '[') {
          if (depth >= (int) sizeof(nesting)) return MJSON_ERROR_TOO_DEEP;
          nesting[depth++] = c;
          break;
        } else if (c == ']' && depth > 0) {  // Empty array
          MJSONEOO();
        } else if (c == 't' && i + 3 < len && memcmp(&s[i], "true", 4) == 0) {
          i += 3;
          tok = MJSON_TOK_TRUE;
        } else if (c == 'n' && i + 3 < len && memcmp(&s[i], "null", 4) == 0) {
          i += 3;
          tok = MJSON_TOK_NULL;
        } else if (c == 'f' && i + 4 < len && memcmp(&s[i], "false", 5) == 0) {
          i += 4;
          tok = MJSON_TOK_FALSE;
        } else if (c == '-' || ((c >= '0' && c <= '9'))) {
          char *end = NULL;
          mystrtod(&s[i], &end);
          if (end != NULL) i += (int) (end - &s[i] - 1);
          tok = MJSON_TOK_NUMBER;
        } else if (c == '"') {
          int n = mjson_pass_string(&s[i + 1], len - i - 1);
          if (n < 0) return n;
          i += n + 1;
          tok = MJSON_TOK_STRING;
        } else {
          return MJSON_ERROR_INVALID_INPUT;
        }
        if (depth == 0) {
          MJSONCALL(tok);
          return i + 1;
        }
        expecting = S_COMMA_OR_EOO;
        break;

      case S_KEY:
        if (c == '"') {
          int n = mjson_pass_string(&s[i + 1], len - i - 1);
          if (n < 0) return n;
          i += n + 1;
          tok = MJSON_TOK_KEY;
          expecting = S_COLON;
        } else if (c == '}') {  // Empty object
          MJSONEOO();
          expecting = S_COMMA_OR_EOO;
        } else {
          return MJSON_ERROR_INVALID_INPUT;
        }
        break;

      case S_COLON:
        if (c == ':') {
          expecting = S_VALUE;
        } else {
          return MJSON_ERROR_INVALID_INPUT;
        }
        break;

      case S_COMMA_OR_EOO:
        if (depth <= 0) return MJSON_ERROR_INVALID_INPUT;
        if (c == ',') {
          expecting = (nesting[depth - 1] == '{') ? S_KEY : S_VALUE;
        } else if (c == ']' || c == '}') {
          MJSONEOO();
        } else {
          return MJSON_ERROR_INVALID_INPUT;
        }
        break;
    }
    MJSONCALL(tok);
  }
  return MJSON_ERROR_INVALID_INPUT;
}

struct msjon_get_data {
  const char *path;     // Lookup json path
  int pos;              // Current path index
  int d1;               // Current depth of traversal
  int d2;               // Expected depth of traversal
  int i1;               // Index in an array
  int i2;               // Expected index in an array
  int obj;              // If the value is array/object, offset where it starts
  const char **tokptr;  // Destination
  int *toklen;          // Destination length
  int tok;              // Returned token
};

#include <stdio.h>

static int plen1(const char *s) {
  int i = 0, n = 0;
  while (s[i] != '\0' && s[i] != '.' && s[i] != '[')
    n++, i += s[i] == '\\' ? 2 : 1;
  // printf("PLEN: s: [%s], [%.*s] => %d\n", s, i, s, n);
  return n;
}

static int plen2(const char *s) {
  int i = 0, __attribute__((unused)) n = 0;
  while (s[i] != '\0' && s[i] != '.' && s[i] != '[')
    n++, i += s[i] == '\\' ? 2 : 1;
  // printf("PLEN: s: [%s], [%.*s] => %d\n", s, i, s, n);
  return i;
}

static int kcmp(const char *a, const char *b, int n) {
  int i = 0, j = 0, r = 0;
  for (i = 0, j = 0; j < n; i++, j++) {
    if (b[i] == '\\') i++;
    if ((r = a[j] - b[i]) != 0) return r;
  }
  // printf("KCMP: a: [%.*s], b:[%.*s] ==> %d\n", n, a, i, b, r);
  return r;
}

static int mjson_get_cb(int tok, const char *s, int off, int len, void *ud) {
  struct msjon_get_data *data = (struct msjon_get_data *) ud;
  // printf("--> %2x %2d %2d %2d %2d\t'%s'\t'%.*s'\t\t'%.*s'\n", tok, data->d1,
  // data->d2, data->i1, data->i2, data->path + data->pos, off, s, len,
  // s + off);
  if (data->tok != MJSON_TOK_INVALID) return 1;  // Found

  if (tok == '{') {
    if (!data->path[data->pos] && data->d1 == data->d2) data->obj = off;
    data->d1++;
  } else if (tok == '[') {
    if (data->d1 == data->d2 && data->path[data->pos] == '[') {
      data->i1 = 0;
      data->i2 = (int) mystrtod(&data->path[data->pos + 1], NULL);
      if (data->i1 == data->i2) {
        data->d2++;
        data->pos += 3;
      }
    }
    if (!data->path[data->pos] && data->d1 == data->d2) data->obj = off;
    data->d1++;
  } else if (tok == ',') {
    if (data->d1 == data->d2 + 1) {
      data->i1++;
      if (data->i1 == data->i2) {
        while (data->path[data->pos] != ']') data->pos++;
        data->pos++;
        data->d2++;
      }
    }
  } else if (tok == MJSON_TOK_KEY && data->d1 == data->d2 + 1 &&
             data->path[data->pos] == '.' && s[off] == '"' &&
             s[off + len - 1] == '"' &&
             plen1(&data->path[data->pos + 1]) == len - 2 &&
             kcmp(s + off + 1, &data->path[data->pos + 1], len - 2) == 0) {
    data->d2++;
    data->pos += plen2(&data->path[data->pos + 1]) + 1;
  } else if (tok == MJSON_TOK_KEY && data->d1 == data->d2) {
    return 1;  // Exhausted path, not found
  } else if (tok == '}' || tok == ']') {
    data->d1--;
    // data->d2--;
    if (!data->path[data->pos] && data->d1 == data->d2 && data->obj != -1) {
      data->tok = tok - 2;
      if (data->tokptr) *data->tokptr = s + data->obj;
      if (data->toklen) *data->toklen = off - data->obj + 1;
      return 1;
    }
  } else if (MJSON_TOK_IS_VALUE(tok)) {
    // printf("TOK --> %d\n", tok);
    if (data->d1 == data->d2 && !data->path[data->pos]) {
      data->tok = tok;
      if (data->tokptr) *data->tokptr = s + off;
      if (data->toklen) *data->toklen = len;
      return 1;
    }
  }
  return 0;
}

enum mjson_tok mjson_find(const char *s, int len, const char *jp,
                          const char **tokptr, int *toklen) {
  struct msjon_get_data data = {jp, 1,  0,      0,      0,
                                0,  -1, tokptr, toklen, MJSON_TOK_INVALID};
  if (jp[0] != '$') return MJSON_TOK_INVALID;
  if (mjson(s, len, mjson_get_cb, &data) < 0) return MJSON_TOK_INVALID;
  return (enum mjson_tok) data.tok;
}

int mjson_get_number(const char *s, int len, const char *path, double *v) {
  const char *p;
  int tok, n;
  if ((tok = mjson_find(s, len, path, &p, &n)) == MJSON_TOK_NUMBER) {
    if (v != NULL) *v = mystrtod(p, NULL);
  }
  return tok == MJSON_TOK_NUMBER ? 1 : 0;
}

int mjson_get_bool(const char *s, int len, const char *path, int *v) {
  int tok = mjson_find(s, len, path, NULL, NULL);
  if (tok == MJSON_TOK_TRUE && v != NULL) *v = 1;
  if (tok == MJSON_TOK_FALSE && v != NULL) *v = 0;
  return tok == MJSON_TOK_TRUE || tok == MJSON_TOK_FALSE ? 1 : 0;
}

static unsigned char mjson_unhex_nimble(const char *s) {
  unsigned char i, v = 0;
  for (i = 0; i < 2; i++) {
    int c = s[i];
    if (i > 0) v <<= 4;
    v |= (c >= '0' && c <= '9') ? c - '0'
                                : (c >= 'A' && c <= 'F') ? c - '7' : c - 'W';
  }
  return v;
}

static int mjson_unescape(const char *s, int len, char *to, int n) {
  int i, j;
  for (i = 0, j = 0; i < len && j < n; i++, j++) {
    if (s[i] == '\\' && i + 5 < len && s[i + 1] == 'u') {
      //  \uXXXX escape. We could process a simple one-byte chars
      // \u00xx from the ASCII range. More complex chars would require
      // dragging in a UTF8 library, which is too much for us
      if (s[i + 2] != '0' || s[i + 3] != '0') return -1;  // Too much, give up
      to[j] = mjson_unhex_nimble(s + i + 4);
      i += 5;
    } else if (s[i] == '\\' && i + 1 < len) {
      int c = mjson_esc(s[i + 1], 0);
      if (c == 0) return -1;
      to[j] = c;
      i++;
    } else {
      to[j] = s[i];
    }
  }
  if (j >= n) return -1;
  if (n > 0) to[j] = '\0';
  return j;
}

int mjson_get_string(const char *s, int len, const char *path, char *to,
                     int n) {
  const char *p;
  int sz;
  if (mjson_find(s, len, path, &p, &sz) != MJSON_TOK_STRING) return -1;
  return mjson_unescape(p + 1, sz - 2, to, n);
}

int mjson_get_hex(const char *s, int len, const char *x, char *to, int n) {
  const char *p;
  int i, j, sz;
  if (mjson_find(s, len, x, &p, &sz) != MJSON_TOK_STRING) return -1;
  for (i = j = 0; i < sz - 3 && j < n; i += 2, j++) {
    ((unsigned char *) to)[j] = mjson_unhex_nimble(p + i + 1);
  }
  if (j < n) to[j] = '\0';
  return j;
}

static int is_digit(int c) {
  return c >= '0' && c <= '9';
}

/* NOTE: strtod() implementation by Yasuhiro Matsumoto. */
static double mystrtod(const char *str, char **end) {
  double d = 0.0;
  int sign = 1, __attribute__((unused)) n = 0;
  const char *p = str, *a = str;

  /* decimal part */
  if (*p == '-') {
    sign = -1;
    ++p;
  } else if (*p == '+') {
    ++p;
  }
  if (is_digit(*p)) {
    d = (double) (*p++ - '0');
    while (*p && is_digit(*p)) {
      d = d * 10.0 + (double) (*p - '0');
      ++p;
      ++n;
    }
    a = p;
  } else if (*p != '.') {
    goto done;
  }
  d *= sign;

  /* fraction part */
  if (*p == '.') {
    double f = 0.0;
    double base = 0.1;
    ++p;

    if (is_digit(*p)) {
      while (*p && is_digit(*p)) {
        f += base * (*p - '0');
        base /= 10.0;
        ++p;
        ++n;
      }
    }
    d += f * sign;
    a = p;
  }

  /* exponential part */
  if ((*p == 'E') || (*p == 'e')) {
    double exp, f;
    int i, e = 0, neg = 0;
    p++;
    if (*p == '-') p++, neg++;
    if (*p == '+') p++;
    while (is_digit(*p)) e = e * 10 + *p++ - '0';
    i = e;
    if (neg) e = -e;
#if 0
    if (d == 2.2250738585072011 && e == -308) {
      d = 0.0;
      a = p;
      goto done;
    }
    if (d == 2.2250738585072012 && e <= -308) {
      d *= 1.0e-308;
      a = p;
      goto done;
    }
#endif
    /* calculate f = 10^i */
    exp = 10;
    f = 1;
    while (i > 0) {
      if (i & 1) f *= exp;
      exp *= exp;
      i >>= 1;
    }
    if (e > 0) d *= f;
    else if (e < 0) d /= f;
    a = p;
  } else if (p > str && !is_digit(*(p - 1))) {
    a = str;
    goto done;
  }

done:
  if (end) *end = (char *) a;
  return d;
}


