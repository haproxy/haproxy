@@
type T;
expression E;
expression t;
@@

(
  t = calloc(E, sizeof(*t))
|
- t = calloc(E, sizeof(T))
+ t = calloc(E, sizeof(*t))
)

@@
type T;
T *x;
@@

  x = malloc(
- sizeof(T)
+ sizeof(*x)
  )

@@
type T;
T *x;
@@

  x = calloc(1,
- sizeof(T)
+ sizeof(*x)
  )

@@
@@

  calloc(
+ 1,
  ...
- ,1
  )
