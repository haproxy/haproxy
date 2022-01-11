#include <haproxy/api.h>
#include <haproxy/listener.h>
#include <haproxy/proxy-t.h>

static struct bind_kw_list bind_kws = { "QUIC", { }, {
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);
