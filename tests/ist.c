/* ist.c: test code for ist.h
 *
 * Build with :
 *   gcc -Iinclude -Wall -W -fomit-frame-pointer -Os tests/ist.c
 *   gcc -Iinclude -Wall -W -fomit-frame-pointer -O1 tests/ist.c
 *   gcc -Iinclude -Wall -W -fomit-frame-pointer -O2 tests/ist.c
 *   gcc -Iinclude -Wall -W -fomit-frame-pointer -O3 tests/ist.c
 */

#include <stdio.h>
#include <stdlib.h>
#include "common/ist.h"


// pre-extracted from ist.h using the following expression :
// sed -n '/^static inline/s:^\([^ ]\+\) \([^ ]\+\) \(.*[* ]\)\([^* ]\+(\)\(.*\):\3f_\4\5 { return \4); }\nstatic int test_\4)\n{\n\treturn 0;\n}\n:p' include/common/ist.h
// sed -n '/^static inline/s:^\([^ ]\+\) \([^ ]\+\) \(.*[* ]\)\([^* ]\+(\)\(.*\):\tif (test_\4)) printf("\4)\\n");:p' include/common/ist.h
// sed -n '/^static inline/s:^\([^ ]\+\) \([^ ]\+\) \(.*[* ]\)\([^* ]\+(\)\(.*\):\tprintf("%4d \4)\\n", test_\4));:p' include/common/ist.h

struct ist f_ist(const void *str) { return ist(str); }
static int test_ist()
{
	if (ist("foo").ptr == NULL)
		return __LINE__;
	if (ist("foo").len != 3)
		return __LINE__;
	if (strncmp(ist("foo").ptr, "foo", 3) != 0)
		return 3;
	return 0;
}

struct ist f_ist2(const void *ptr, size_t len) { return ist2(ptr, len); }
int test_ist2()
{
	if (ist2("foo", 3).ptr == NULL)
		return __LINE__;
	if (ist2("foo", 3).len != 3)
		return __LINE__;
	if (strncmp(ist2("foo", 3).ptr, "foo", 3) != 0)
		return __LINE__;
	return 0;
}

size_t f_istlen(struct ist ist) { return istlen(ist); }
int test_istlen()
{
	if (istlen(ist("foo")) != 3)
		return __LINE__;
	if (istlen(ist("")) != 0)
		return __LINE__;
	if (istlen(ist(NULL)) != 0)
		return __LINE__;
	return 0;
}

struct ist f_istnext(struct ist ist) { return istnext(ist); }
int test_istnext()
{
	if (istlen(istnext(ist("foo"))) != 2)
		return __LINE__;
	if (strncmp(istnext(ist("foo")).ptr, "oo", 2) != 0)
		return __LINE__;
	if (istnext(istnext(istnext(istnext(ist("foo"))))).len != 0)
		return __LINE__;
	return 0;
}

struct ist f_istpad(void *buf, const struct ist ist) { return istpad(buf, ist); }
int test_istpad()
{
	char buf[5] = "xxxxx";

	if (strncmp(istpad(buf, ist("foo")).ptr, "foo", 3) != 0)
		return __LINE__;
	if (strncmp(buf, "foo", 3) != 0)
		return __LINE__;
	if (buf[3] != 0 || buf[4] != 'x')
		return __LINE__;
	return 0;
}

struct ist f_isttrim(struct ist ist, size_t size) { return isttrim(ist, size); }
int test_isttrim()
{
	if (isttrim(ist("foo"), 5).ptr == NULL)
		return __LINE__;

	if (isttrim(ist("foo"), 5).len != 3)
		return __LINE__;

	if (strncmp(isttrim(ist("foo"), 5).ptr, "foo", 3) != 0)
		return __LINE__;

	if (isttrim(ist("foo"), 2).ptr == NULL)
		return __LINE__;

	if (isttrim(ist("foo"), 2).len != 2)
		return __LINE__;

	if (strncmp(isttrim(ist("foo"), 2).ptr, "fo", 2) != 0)
		return __LINE__;

	return 0;
}

struct ist f_istzero(struct ist ist, size_t size) { return istzero(ist, size); }
int test_istzero()
{
	char buf[5] = "xxxxx";

	if (istzero(ist2(buf, 5), 10).ptr != buf)
		return __LINE__;

	if (istzero(ist2(buf, 5), 10).len != 5)
		return __LINE__;

	if (istzero(ist2(buf, 5), 5).len != 4)
		return __LINE__;

	if (buf[4] != 0)
		return __LINE__;

	if (istzero(ist2(buf, 5), 0).len != 0)
		return __LINE__;

	if (buf[0] == 0)
		return __LINE__;

	return 0;
}

int f_istdiff(const struct ist ist1, const struct ist ist2) { return istdiff(ist1, ist2); }
int test_istdiff()
{
	if (istdiff(ist(""), ist("")) != 0)
		return __LINE__;

	if (istdiff(ist("bar"), ist("bar")) != 0)
		return __LINE__;

	if (istdiff(ist("foo"), ist("")) <= 0)
		return __LINE__;

	if (istdiff(ist(""), ist("bar")) >= 0)
		return __LINE__;

	if (istdiff(ist("foo"), ist("bar")) <= 0)
		return __LINE__;

	if (istdiff(ist("fo"), ist("bar")) <= 0)
		return __LINE__;

	if (istdiff(ist("bar"), ist("foo")) >= 0)
		return __LINE__;

	if (istdiff(ist("bar"), ist("fo")) >= 0)
		return __LINE__;

	return 0;
}

int f_istmatch(const struct ist ist1, const struct ist ist2) { return istmatch(ist1, ist2); }
int test_istmatch()
{
	if (istmatch(ist(""), ist("")) == 0)
		return __LINE__;

	if (istmatch(ist("bar"), ist("bar")) == 0)
		return __LINE__;

	if (istmatch(ist("foo"), ist("")) == 0)
		return __LINE__;

	if (istmatch(ist(""), ist("bar")) != 0)
		return __LINE__;

	if (istmatch(ist("foo"), ist("bar")) != 0)
		return __LINE__;

	if (istmatch(ist("fo"), ist("bar")) != 0)
		return __LINE__;

	if (istmatch(ist("bar"), ist("foo")) != 0)
		return __LINE__;

	if (istmatch(ist("bar"), ist("fo")) != 0)
		return __LINE__;

	if (istmatch(ist("foo"), ist("foobar")) != 0)
		return __LINE__;

	if (istmatch(ist("foobar"), ist("foo")) == 0)
		return __LINE__;

	if (istmatch(ist("foobar"), ist("bar")) != 0)
		return __LINE__;

	return 0;
}

int f_istnmatch(struct ist ist1, struct ist ist2, size_t count) { return istnmatch(ist1, ist2, count); }
int test_istnmatch()
{
	if (istnmatch(ist(""), ist(""), 1) == 0)
		return __LINE__;

	if (istnmatch(ist(""), ist(""), 0) == 0)
		return __LINE__;

	if (istnmatch(ist("bar"), ist("bar"), 4) == 0)
		return __LINE__;

	if (istnmatch(ist("bar"), ist("bar"), 2) == 0)
		return __LINE__;

	if (istnmatch(ist("bar"), ist("baz"), 2) == 0)
		return __LINE__;

	if (istnmatch(ist("foo"), ist(""), 1) == 0)
		return __LINE__;

	if (istnmatch(ist("foo"), ist(""), 0) == 0)
		return __LINE__;

	if (istnmatch(ist(""), ist("bar"), 3) != 0)
		return __LINE__;

	if (istnmatch(ist(""), ist("bar"), 0) == 0)
		return __LINE__;

	if (istnmatch(ist("foo"), ist("bar"), 4) != 0)
		return __LINE__;

	if (istnmatch(ist("foo"), ist("bar"), 0) == 0)
		return __LINE__;

	if (istnmatch(ist("fo"), ist("bar"), 2) != 0)
		return __LINE__;

	if (istnmatch(ist("bar"), ist("foo"), 3) != 0)
		return __LINE__;

	if (istnmatch(ist("bar"), ist("fo"), 2) != 0)
		return __LINE__;

	if (istnmatch(ist("foo"), ist("foobar"), 4) != 0)
		return __LINE__;

	if (istnmatch(ist("foo"), ist("foobar"), 3) == 0)
		return __LINE__;

	if (istnmatch(ist("foobar"), ist("fooz"), 4) != 0)
		return __LINE__;

	if (istnmatch(ist("foobar"), ist("fooz"), 3) == 0)
		return __LINE__;

	if (istnmatch(ist("foobar"), ist("fooz"), 2) == 0)
		return __LINE__;

	if (istnmatch(ist("foobar"), ist("bar"), 3) != 0)
		return __LINE__;

	return 0;
}

int f_isteq(const struct ist ist1, const struct ist ist2) { return isteq(ist1, ist2); }
int test_isteq()
{
	if (isteq(ist(""), ist("")) == 0)
		return __LINE__;

	if (isteq(ist("bar"), ist("bar")) == 0)
		return __LINE__;

	if (isteq(ist("foo"), ist("")) != 0)
		return __LINE__;

	if (isteq(ist(""), ist("bar")) != 0)
		return __LINE__;

	if (isteq(ist("foo"), ist("bar")) != 0)
		return __LINE__;

	if (isteq(ist("fo"), ist("bar")) != 0)
		return __LINE__;

	if (isteq(ist("bar"), ist("foo")) != 0)
		return __LINE__;

	if (isteq(ist("bar"), ist("fo")) != 0)
		return __LINE__;

	if (isteq(ist("foo"), ist("foobar")) != 0)
		return __LINE__;

	if (isteq(ist("foobar"), ist("foo")) != 0)
		return __LINE__;

	if (isteq(ist("foobar"), ist("bar")) != 0)
		return __LINE__;

	return 0;
}

int f_istneq(struct ist ist1, struct ist ist2, size_t count) { return istneq(ist1, ist2, count); }
int test_istneq()
{
	if (istneq(ist(""), ist(""), 1) == 0)
		return __LINE__;

	if (istneq(ist(""), ist(""), 0) == 0)
		return __LINE__;

	if (istneq(ist("bar"), ist("bar"), 4) == 0)
		return __LINE__;

	if (istneq(ist("bar"), ist("bar"), 2) == 0)
		return __LINE__;

	if (istneq(ist("bar"), ist("baz"), 2) == 0)
		return __LINE__;

	if (istneq(ist("foo"), ist(""), 1) != 0)
		return __LINE__;

	if (istneq(ist("foo"), ist(""), 0) == 0)
		return __LINE__;

	if (istneq(ist(""), ist("bar"), 3) != 0)
		return __LINE__;

	if (istneq(ist(""), ist("bar"), 0) == 0)
		return __LINE__;

	if (istneq(ist("foo"), ist("bar"), 4) != 0)
		return __LINE__;

	if (istneq(ist("foo"), ist("bar"), 0) == 0)
		return __LINE__;

	if (istneq(ist("fo"), ist("bar"), 2) != 0)
		return __LINE__;

	if (istneq(ist("bar"), ist("foo"), 3) != 0)
		return __LINE__;

	if (istneq(ist("bar"), ist("fo"), 2) != 0)
		return __LINE__;

	if (istneq(ist("foo"), ist("foobar"), 4) != 0)
		return __LINE__;

	if (istneq(ist("foo"), ist("foobar"), 3) == 0)
		return __LINE__;

	if (istneq(ist("foobar"), ist("fooz"), 4) != 0)
		return __LINE__;

	if (istneq(ist("foobar"), ist("fooz"), 3) == 0)
		return __LINE__;

	if (istneq(ist("foobar"), ist("fooz"), 2) == 0)
		return __LINE__;

	if (istneq(ist("foobar"), ist("bar"), 3) != 0)
		return __LINE__;

	return 0;
}

ssize_t f_istcpy(struct ist *dst, const struct ist src, size_t count) { return istcpy(dst, src, count); }
int test_istcpy()
{
	char buf[100] = "foobar";
	struct ist dst = ist(buf);

	if (istcpy(&dst, ist("FOO"), sizeof(buf)) != 3)
		return __LINE__;

	if (dst.len != 3)
		return __LINE__;

	if (strcmp(buf, "FOObar") != 0)
		return __LINE__;

	if (istcpy(&dst, ist("foo"), 2) != -1)
		return __LINE__;

	if (strcmp(buf, "foObar") != 0)
		return __LINE__;

	if (istcpy(&dst, ist("foo"), 3) != 3)
		return __LINE__;

	if (strcmp(buf, "foobar") != 0)
		return __LINE__;

	return 0;
}

ssize_t f_istscpy(struct ist *dst, const struct ist src, size_t count) { return istscpy(dst, src, count); }
int test_istscpy()
{
	char buf[100] = "foobar";
	struct ist dst = ist(buf);

	if (istscpy(&dst, ist("FOO"), sizeof(buf)) != 3)
		return __LINE__;

	if (dst.len != 3)
		return __LINE__;

	if (memcmp(buf, "FOO\0ar", 6) != 0)
		return __LINE__;

	if (istscpy(&dst, ist("foo"), 3) != -1)
		return __LINE__;

	if (memcmp(buf, "fo\0\0ar", 6) != 0)
		return __LINE__;

	if (istscpy(&dst, ist("foo"), 3) != -1)
		return __LINE__;

	if (istscpy(&dst, ist("foo"), 4) != 3)
		return __LINE__;

	if (memcmp(buf, "foo\0ar", 6) != 0)
		return __LINE__;

	return 0;
}

ssize_t f_istcat(struct ist *dst, const struct ist src, size_t count) { return istcat(dst, src, count); }
int test_istcat()
{
	char buf[11] = "foobar";
	struct ist dst = ist(buf);

	if (istcat(&dst, ist("FOO"), sizeof(buf)) != 9)
		return __LINE__;

	if (strcmp(buf, "foobarFOO") != 0)
		return __LINE__;

	if (istcat(&dst, ist("foo"), 10) != -1)
		return __LINE__;

	if (dst.len != 10)
		return __LINE__;

	if (strncmp(buf, "foobarFOOf", 10) != 0)
		return __LINE__;

	if (istcat(&dst, ist("foo"), 3) != -1)
		return __LINE__;

	if (dst.len != 10)
		return __LINE__;

	if (strncmp(buf, "foobar", 6) != 0)
		return __LINE__;

	return 0;
}

ssize_t f_istscat(struct ist *dst, const struct ist src, size_t count) { return istscat(dst, src, count); }
int test_istscat()
{
	char buf[11] = "foobar";
	struct ist dst = ist(buf);

	if (istscat(&dst, ist("FOO"), sizeof(buf)) != 9)
		return __LINE__;

	if (strcmp(buf, "foobarFOO") != 0)
		return __LINE__;

	if (istscat(&dst, ist("foo"), sizeof(buf)) != -1)
		return __LINE__;

	if (dst.len != 10)
		return __LINE__;

	if (strncmp(buf, "foobarFOOf", 10) != 0)
		return __LINE__;

	if (istscat(&dst, ist("foo"), 3) != -1)
		return __LINE__;

	if (dst.len != 10)
		return __LINE__;

	if (strncmp(buf, "foobar", 6) != 0)
		return __LINE__;

	return 0;
}

char *f_istchr(const struct ist ist, char chr) { return istchr(ist, chr); }
int test_istchr()
{
	struct ist foobar = ist("foobar");

	if (istchr(foobar, 'f') != foobar.ptr)
		return __LINE__;

	if (istchr(foobar, 'o') != foobar.ptr + 1)
		return __LINE__;

	if (istchr(foobar, 'r') != foobar.ptr + 5)
		return __LINE__;

	if (istchr(foobar, 'X') != NULL)
		return __LINE__;

	if (istchr(foobar, 0) != NULL)
		return __LINE__;

	return 0;
}

struct ist f_istfind(struct ist ist, char chr) { return istfind(ist, chr); }
int test_istfind()
{
	struct ist foobar = ist("foobar");

	if (istfind(foobar, 'f').ptr != foobar.ptr)
		return __LINE__;

	if (istfind(foobar, 'f').len != 6)
		return __LINE__;

	if (istfind(foobar, 'o').ptr != foobar.ptr + 1)
		return __LINE__;

	if (istfind(foobar, 'o').len != 5)
		return __LINE__;

	if (istfind(foobar, 'r').ptr != foobar.ptr + 5)
		return __LINE__;

	if (istfind(foobar, 'r').len != 1)
		return __LINE__;

	if (istfind(foobar, 'X').ptr != foobar.ptr + foobar.len)
		return __LINE__;

	if (istfind(foobar, 'X').len != 0)
		return __LINE__;

	if (istfind(foobar, 0).ptr != foobar.ptr + foobar.len)
		return __LINE__;

	if (istfind(foobar, 0).len != 0)
		return __LINE__;

	return 0;
}

struct ist f_istskip(struct ist ist, char chr) { return istskip(ist, chr); }
int test_istskip()
{
	struct ist foobar = ist("foobar");
	struct ist r = ist("r");

	if (istskip(foobar, 'X').ptr != foobar.ptr)
		return __LINE__;

	if (istskip(foobar, 'X').len != foobar.len)
		return __LINE__;

	if (istskip(foobar, 'o').ptr != foobar.ptr)
		return __LINE__;

	if (istskip(foobar, 'o').len != foobar.len)
		return __LINE__;

	if (istskip(foobar, 'f').ptr != foobar.ptr + 1)
		return __LINE__;

	if (istskip(foobar, 'f').len != foobar.len - 1)
		return __LINE__;

	if (istskip(r, 'r').ptr != r.ptr + 1)
		return __LINE__;

	if (istskip(r, 'r').len != r.len - 1)
		return __LINE__;

	if (istskip(foobar, 'X').ptr != foobar.ptr)
		return __LINE__;

	if (istskip(foobar, 'X').len != foobar.len)
		return __LINE__;

	if (istskip(r, 0).ptr != r.ptr)
		return __LINE__;

	if (istskip(r, 0).len != r.len)
		return __LINE__;

	return 0;
}

struct ist f_istist(struct ist ist, const struct ist pat) { return istist(ist, pat); }
int test_istist()
{
	struct ist foobar = ist("foobar");

	if (istist(foobar, ist("f")).ptr != foobar.ptr)
		return __LINE__;

	if (istist(foobar, ist("f")).len != foobar.len)
		return __LINE__;

	if (istist(foobar, ist("foob")).ptr != foobar.ptr)
		return __LINE__;

	if (istist(foobar, ist("foob")).len != foobar.len)
		return __LINE__;

	if (istist(foobar, ist("foobar")).ptr != foobar.ptr)
		return __LINE__;

	if (istist(foobar, ist("foobar")).len != foobar.len)
		return __LINE__;

	if (istist(foobar, ist("o")).ptr != foobar.ptr + 1)
		return __LINE__;

	if (istist(foobar, ist("o")).len != foobar.len - 1)
		return __LINE__;

	if (istist(foobar, ist("ooba")).ptr != foobar.ptr + 1)
		return __LINE__;

	if (istist(foobar, ist("ooba")).len != foobar.len - 1)
		return __LINE__;

	if (istist(foobar, ist("r")).ptr != foobar.ptr + 5)
		return __LINE__;

	if (istist(foobar, ist("r")).len != foobar.len - 5)
		return __LINE__;

	if (istist(foobar, ist("X")).ptr != NULL)
		return __LINE__;

	if (istist(foobar, ist("X")).len != 0)
		return __LINE__;

	if (istist(foobar, ist("oobaX")).ptr != NULL)
		return __LINE__;

	if (istist(foobar, ist("oobaX")).len != 0)
		return __LINE__;

	if (istist(foobar, ist("oobarX")).ptr != NULL)
		return __LINE__;

	if (istist(foobar, ist("oobarX")).len != 0)
		return __LINE__;

	if (istist(foobar, ist("")).ptr != foobar.ptr)
		return __LINE__;

	if (istist(foobar, ist("")).len != foobar.len)
		return __LINE__;

	return 0;
}


int main(void)
{
        printf("%4d ist()\n", test_ist());
        printf("%4d ist2()\n", test_ist2());
        printf("%4d istlen()\n", test_istlen());
        printf("%4d istnext()\n", test_istnext());
        printf("%4d istpad()\n", test_istpad());
        printf("%4d isttrim()\n", test_isttrim());
        printf("%4d istzero()\n", test_istzero());
        printf("%4d istdiff()\n", test_istdiff());
        printf("%4d istmatch()\n", test_istmatch());
        printf("%4d istnmatch()\n", test_istnmatch());
        printf("%4d isteq()\n", test_isteq());
        printf("%4d istneq()\n", test_istneq());
        printf("%4d istcpy()\n", test_istcpy());
        printf("%4d istscpy()\n", test_istscpy());
        printf("%4d istcat()\n", test_istcat());
        printf("%4d istscat()\n", test_istscat());
        printf("%4d istchr()\n", test_istchr());
        printf("%4d istfind()\n", test_istfind());
        printf("%4d istskip()\n", test_istskip());
        printf("%4d istist()\n", test_istist());

	return 0;
}
