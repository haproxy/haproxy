#include <haproxy/api.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/protocol.h>

#include <haproxy/proto_reverse_connect.h>

struct proto_fam proto_fam_reverse_connect = {
	.name = "reverse_connect",
	.sock_domain = AF_CUST_REV_SRV,
	.sock_family = AF_INET,
	.bind = rev_bind_receiver,
};

struct protocol proto_reverse_connect = {
	.name = "rev",

	/* connection layer */
	.listen  = rev_bind_listener,
	.add     = default_add_listener,

	/* address family */
	.fam  = &proto_fam_reverse_connect,

	/* socket layer */
	.proto_type     = PROTO_TYPE_STREAM,
	.sock_type      = SOCK_STREAM,
	.sock_prot      = IPPROTO_TCP,
	.rx_listening   = rev_accepting_conn,
	.receivers      = LIST_HEAD_INIT(proto_reverse_connect.receivers),
};

int rev_bind_receiver(struct receiver *rx, char **errmsg)
{
	return ERR_NONE;
}

int rev_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	return ERR_NONE;
}

int rev_accepting_conn(const struct receiver *rx)
{
	return 1;
}

INITCALL1(STG_REGISTER, protocol_register, &proto_reverse_connect);
