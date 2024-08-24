// find calls to malloc
@call@
expression ptr;
position p;
@@

ptr@p = malloc(...);

// find ok calls to malloc
@ok@
expression ptr;
position call.p;
@@

ptr@p = malloc(...);
... when != ptr
(
 (ptr == NULL || ...)
|
 (ptr == 0 || ...)
|
 (ptr != NULL || ...)
|
 (ptr != 0 || ...)
)

// fix bad calls to malloc
@depends on !ok@
expression ptr;
position call.p;
@@

ptr@p = malloc(...);
+ if (ptr == NULL) return;
