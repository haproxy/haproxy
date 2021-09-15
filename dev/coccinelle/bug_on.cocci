@@
expression E;
@@

- if (E)
- ABORT_NOW();
+ BUG_ON(E);
