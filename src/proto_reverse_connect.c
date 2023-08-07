#include <stdio.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/errors.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/protocol.h>
#include <haproxy/proxy.h>
#include <haproxy/server.h>

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
	.listen      = rev_bind_listener,
	.unbind      = rev_unbind_receiver,
	.add         = default_add_listener,
	.resume      = default_resume_listener,

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
	rx->flags |= RX_F_BOUND;
	return ERR_NONE;
}

int rev_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	struct proxy *be;
	struct server *srv;
	struct ist be_name, sv_name;
	char *name = NULL;

	name = strdup(listener->bind_conf->reverse_srvname);
	if (!name) {
		snprintf(errmsg, errlen, "Out of memory.");
		goto err;
	}

	sv_name = ist(name);
	be_name = istsplit(&sv_name, '/');
	if (!istlen(sv_name)) {
		snprintf(errmsg, errlen, "Invalid server name: '%s'.", name);
		goto err;
	}

	if (!(be = proxy_be_by_name(ist0(be_name)))) {
		snprintf(errmsg, errlen, "No such backend: '%s'.", name);
		goto err;
	}
	if (!(srv = server_find_by_name(be, ist0(sv_name)))) {
		snprintf(errmsg, errlen, "No such server: '%s/%s'.", ist0(be_name), ist0(sv_name));
		goto err;
	}

	/* TODO check que on utilise pas un serveur @reverse */
	if (srv->flags & SRV_F_REVERSE) {
		snprintf(errmsg, errlen, "Cannot use reverse server '%s/%s' as target to a reverse bind.", ist0(be_name), ist0(sv_name));
		goto err;
	}

	/* Check that server uses HTTP/2 either with proto or ALPN. */
	if ((!srv->mux_proto || !isteqi(srv->mux_proto->token, ist("h2"))) &&
	    (!srv->use_ssl || !isteqi(ist(srv->ssl_ctx.alpn_str), ist("\x02h2")))) {
		snprintf(errmsg, errlen, "Cannot reverse connect with server '%s/%s' unless HTTP/2 is activated on it with either proto or alpn keyword.", name, ist0(sv_name));
		goto err;
	}
	ha_free(&name);

	listener->rx.reverse_connect.srv = srv;

	return ERR_NONE;

 err:
	ha_free(&name);
	return ERR_ALERT | ERR_FATAL;
}

void rev_unbind_receiver(struct listener *l)
{
	l->rx.flags &= ~RX_F_BOUND;
}

int rev_accepting_conn(const struct receiver *rx)
{
	return 1;
}

INITCALL1(STG_REGISTER, protocol_register, &proto_reverse_connect);
