@@
struct ist i;
expression p, l;
@@

(
- i.ptr = p;
- i.len = strlen(i.ptr);
+ i = ist(p);
|
- i.ptr = p;
- i.len = l;
+ i = ist2(p, l);
)

@@
@@

- ist2(NULL, 0)
+ IST_NULL

@@
struct ist i;
expression e;
@@

- i.ptr += e;
- i.len -= e;
+ i = istadv(i, e);

@@
struct ist i;
@@

- i = istadv(i, 1);
+ i = istnext(i);

@@
struct ist i;
@@

- i.ptr++;
- i.len--;
+ i = istnext(i);

@@
struct ist i;
@@

- (\(i.ptr\|istptr(i)\) + \(i.len\|istlen(i)\))
+ istend(i)

@@
struct ist i;
expression e;
@@

- if (\(i.len\|istlen(i)\) > e) { i.len = e; }
+ i = isttrim(i, e);

@@
struct ist i;
struct buffer *b;
@@

- chunk_memcat(b, \(i.ptr\|istptr(i)\) , \(i.len\|istlen(i)\));
+ chunk_istcat(b, i);

@@
struct ist i;
@@

- i.ptr != NULL
+ isttest(i)

@@
char *s;
@@

(
- ist2(s, strlen(s))
+ ist(s)
|
- ist2(strdup(s), strlen(s))
+ ist(strdup(s))
)
