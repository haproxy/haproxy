@ rule @
expression E;
@@
- free(E);
- E = NULL;
+ ha_free(&E);
