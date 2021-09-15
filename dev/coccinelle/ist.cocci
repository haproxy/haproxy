@@
struct ist i;
expression p, l;
@@

- i.ptr = p;
- i.len = l;
+ i = ist2(p, l);

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
