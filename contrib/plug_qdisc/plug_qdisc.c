#include <inttypes.h>
#include <netlink/cache.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/tc.h>
#include <netlink/cli/qdisc.h>
#include <netlink/cli/link.h>
#include <netlink/route/qdisc/plug.h>

/*
 * XXX Please, first note that this code is not safe. XXX
 * It was developed fast so that to reproduce a bug.
 * You will certainly have to adapt it to your application.
 * But at least it gives an idea about how to programatically use plug
 * queueing disciplines.
 */

static struct nl_sock *nl_sock;
static struct nl_cache *link_cache;
static struct rtnl_qdisc *qdisc;
static struct rtnl_tc *tc;

static int qdisc_init(void)
{
	nl_sock = nl_cli_alloc_socket();
	nl_cli_connect(nl_sock, NETLINK_ROUTE);
	link_cache = nl_cli_link_alloc_cache(nl_sock);
	qdisc = nl_cli_qdisc_alloc();
	tc = (struct rtnl_tc *)qdisc;

	return 0;
}

/* Stop buffering and release all buffered and incoming 'qdisc'
 * queueing discipline traffic.
 */
int plug_qdisc_release_indefinite_buffer(void)
{
	rtnl_qdisc_plug_release_indefinite(qdisc);
	return rtnl_qdisc_add(nl_sock, qdisc, 0);
}

/* Start buffering incoming 'qdisc' queueing discipline traffic. */
int plug_qdisc_plug_buffer(void)
{
	rtnl_qdisc_plug_buffer(qdisc);
	return rtnl_qdisc_add(nl_sock, qdisc, 0);
}

/* Create a plug qdisc attached to 'device' network device with 'parent'
 * as parent, with 'id' as ID and 'limit' as buffer size.
 * This is equivalent to use nl-qdisc-add tool like that:
 *  $ nl-qdisc-add --dev=<device> --parent=<parent> --id=<id> plug --limit <limit>
 *  $ nl-qdisc-add --dev=<device> --parent=<parent> --id=<id> --update plug --release-indefinite
 */
int plug_qdisc_attach(char *device, char *parent, char *id, uint32_t limit)
{
	int ret;

	if (!tc && qdisc_init() == -1)
		return -1;

	nl_cli_tc_parse_dev(tc, link_cache, device);
	nl_cli_tc_parse_parent(tc, parent);
	if (!rtnl_tc_get_ifindex(tc))
		return -1;

	if (!rtnl_tc_get_parent(tc))
		return -1;
	if (id)
		nl_cli_tc_parse_handle(tc, id, 1);

	rtnl_tc_set_kind(tc, "plug");
	if (limit)
		rtnl_qdisc_plug_set_limit(qdisc, limit);

	ret = rtnl_qdisc_add(nl_sock, qdisc, NLM_F_CREATE);
	if (ret < 0) {
		fprintf(stderr, "Could add attach qdisc: %s\n", nl_geterror(ret));
		return -1;
	}
	/* Release buffer. */
	plug_qdisc_release_indefinite_buffer();

	return 0;
}

