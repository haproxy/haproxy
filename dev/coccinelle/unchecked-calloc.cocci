// find calls to calloc
@call@
expression ptr;
position p;
@@

ptr@p = calloc(...);

// find ok calls to calloc
@ok@
expression ptr;
position call.p;
@@

ptr@p = calloc(...);
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

// fix bad calls to calloc
@depends on !ok@
expression ptr;
position call.p;
@@

ptr@p = calloc(...);
+ if (ptr == NULL) return;
