@@
struct conn_stream *cs;
expression e;
@@
(
- (cs->endp->flags & (e))
+ sc_ep_test(cs, e)
|
- (cs->endp->flags & e)
+ sc_ep_test(cs, e)
|
- cs->endp->flags & (e)
+ sc_ep_test(cs, e)
|
- cs->endp->flags & e
+ sc_ep_test(cs, e)
)

@@
struct conn_stream *cs;
expression e;
@@
(
- cs->endp->flags |= (e)
+ sc_ep_set(cs, e)
|
- cs->endp->flags |= e
+ sc_ep_set(cs, e)
)

@@
struct conn_stream *cs;
expression e;
@@
(
- cs->endp->flags &= ~(e)
+ sc_ep_clr(cs, e)
|
- cs->endp->flags &= (e)
+ sc_ep_clr(cs, ~e)
|
- cs->endp->flags &= ~e
+ sc_ep_clr(cs, e)
|
- cs->endp->flags &= e
+ sc_ep_clr(cs, ~e)
)

@@
struct conn_stream *cs;
@@
- cs->endp->flags = 0
+ sc_ep_zero(cs)

@@
struct conn_stream *cs;
expression e;
@@
(
- cs->endp->flags = (e)
+ sc_ep_setall(cs, e)
|
- cs->endp->flags = e
+ sc_ep_setall(cs, e)
)

@@
struct conn_stream *cs;
@@
(
- (cs->endp->flags)
+ sc_ep_get(cs)
|
- cs->endp->flags
+ sc_ep_get(cs)
)
