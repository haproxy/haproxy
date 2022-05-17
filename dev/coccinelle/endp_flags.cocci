@@
struct cs_endpoint *endp;
expression e;
@@
(
- (endp->flags & (e))
+ se_fl_test(endp, e)
|
- (endp->flags & e)
+ se_fl_test(endp, e)
|
- endp->flags & (e)
+ se_fl_test(endp, e)
|
- endp->flags & e
+ se_fl_test(endp, e)
)

@@
struct cs_endpoint *endp;
expression e;
@@
(
- endp->flags |= (e)
+ se_fl_set(endp, e)
|
- endp->flags |= e
+ se_fl_set(endp, e)
)

@@
struct cs_endpoint *endp;
expression e;
@@
(
- endp->flags &= ~(e)
+ se_fl_clr(endp, e)
|
- endp->flags &= (e)
+ se_fl_clr(endp, ~e)
|
- endp->flags &= ~e
+ se_fl_clr(endp, e)
|
- endp->flags &= e
+ se_fl_clr(endp, ~e)
)

@@
struct cs_endpoint *endp;
@@
- endp->flags = 0
+ se_fl_zero(endp)

@@
struct cs_endpoint *endp;
expression e;
@@
(
- endp->flags = (e)
+ se_fl_setall(endp, e)
|
- endp->flags = e
+ se_fl_setall(endp, e)
)

@@
struct cs_endpoint *endp;
@@
(
- (endp->flags)
+ se_fl_get(endp)
|
- endp->flags
+ se_fl_get(endp)
)
