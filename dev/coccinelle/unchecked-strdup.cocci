// find calls to strdup
@call@
expression ptr;
position p;
@@

ptr@p = strdup(...);

// find ok calls to strdup
@ok@
expression ptr;
position call.p;
@@

ptr@p = strdup(...);
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

// fix bad calls to strdup
@depends on !ok@
expression ptr;
position call.p;
@@

ptr@p = strdup(...);
+ if (ptr == NULL) return;
