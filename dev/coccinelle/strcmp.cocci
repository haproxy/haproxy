@@
statement S;
expression E;
expression F;
@@
    
  if (
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) != 0
  )
(
  S
|
  { ... }
)
    
@@
statement S;
expression E;
expression F;
@@
    
  if (
- !
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) == 0
  )
(
  S
|
  { ... }
)
    
@@
expression E;
expression F;
expression G;
@@
    
(
G &&
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) != 0
)
    
@@
expression E;
expression F;
expression G;
@@
    
(
G ||
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) != 0
)
    
@@
expression E;
expression F;
expression G;
@@
    
(
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) != 0
&& G
)
    
@@
expression E;
expression F;
expression G;
@@
    
(
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) != 0
|| G
)
    
@@
expression E;
expression F;
expression G;
@@
    
(
G &&
- !
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) == 0
)
    
@@
expression E;
expression F;
expression G;
@@
    
(
G ||
- !
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) == 0
)
    
@@
expression E;
expression F;
expression G;
@@
    
(
- !
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) == 0
&& G
)
    
@@
expression E;
expression F;
expression G;
@@
    
(
- !
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) == 0
|| G
)
    
@@
expression E;
expression F;
expression G;
@@
    
(
- !
(
dns_hostname_cmp
|
eb_memcmp
|
memcmp
|
strcasecmp
|
strcmp
|
strncasecmp
|
strncmp
)
-  (E, F)
+  (E, F) == 0
)
