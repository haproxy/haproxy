/*
 * AF_INET/AF_INET6 SOCK_STREAM protocol layer (tcp)
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/version.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/fd.h>
#include <proto/protocols.h>
#include <proto/proto_tcp.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/session.h>
#include <proto/stream_sock.h>
#include <proto/task.h>

#ifdef CONFIG_HAP_CTTPROXY
#include <import/ip_tproxy.h>
#endif

static int tcp_bind_listeners(struct protocol *proto);

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_tcpv4 = {
	.name = "tcpv4",
	.sock_domain = AF_INET,
	.sock_type = SOCK_STREAM,
	.sock_prot = IPPROTO_TCP,
	.sock_family = AF_INET,
	.sock_addrlen = sizeof(struct sockaddr_in),
	.l3_addrlen = 32/8,
	.read = &stream_sock_read,
	.write = &stream_sock_write,
	.bind_all = tcp_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
	.listeners = LIST_HEAD_INIT(proto_tcpv4.listeners),
	.nb_listeners = 0,
};

/* Note: must not be declared <const> as its list will be overwritten */
static struct protocol proto_tcpv6 = {
	.name = "tcpv6",
	.sock_domain = AF_INET6,
	.sock_type = SOCK_STREAM,
	.sock_prot = IPPROTO_TCP,
	.sock_family = AF_INET6,
	.sock_addrlen = sizeof(struct sockaddr_in6),
	.l3_addrlen = 128/8,
	.read = &stream_sock_read,
	.write = &stream_sock_write,
	.bind_all = tcp_bind_listeners,
	.unbind_all = unbind_all_listeners,
	.enable_all = enable_all_listeners,
	.listeners = LIST_HEAD_INIT(proto_tcpv6.listeners),
	.nb_listeners = 0,
};


/* Binds ipv4 address <local> to socket <fd>, unless <flags> is set, in which
 * case we try to bind <remote>. <flags> is a 2-bit field consisting of :
 *  - 0 : ignore remote address (may even be a NULL pointer)
 *  - 1 : use provided address
 *  - 2 : use provided port
 *  - 3 : use both
 *
 * The function supports multiple foreign binding methods :
 *   - linux_tproxy: we directly bind to the foreign address
 *   - cttproxy: we bind to a local address then nat.
 * The second one can be used as a fallback for the first one.
 * This function returns 0 when everything's OK, 1 if it could not bind, to the
 * local address, 2 if it could not bind to the foreign address.
 */
int tcpv4_bind_socket(int fd, int flags, struct sockaddr_in *local, struct sockaddr_in *remote)
{
	struct sockaddr_in bind_addr;
	int foreign_ok = 0;
	int ret;

#ifdef CONFIG_HAP_LINUX_TPROXY
	static int ip_transp_working = 1;
	if (flags && ip_transp_working) {
		if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, (char *) &one, sizeof(one)) == 0
		    || setsockopt(fd, SOL_IP, IP_FREEBIND, (char *) &one, sizeof(one)) == 0)
			foreign_ok = 1;
		else
			ip_transp_working = 0;
	}
#endif
	if (flags) {
		memset(&bind_addr, 0, sizeof(bind_addr));
		if (flags & 1)
			bind_addr.sin_addr = remote->sin_addr;
		if (flags & 2)
			bind_addr.sin_port = remote->sin_port;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one));
	if (foreign_ok) {
		ret = bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
		if (ret < 0)
			return 2;
	}
	else {
		ret = bind(fd, (struct sockaddr *)local, sizeof(*local));
		if (ret < 0)
			return 1;
	}

	if (!flags)
		return 0;

#ifdef CONFIG_HAP_CTTPROXY
	if (!foreign_ok) {
		struct in_tproxy itp1, itp2;
		memset(&itp1, 0, sizeof(itp1));

		itp1.op = TPROXY_ASSIGN;
		itp1.v.addr.faddr = bind_addr.sin_addr;
		itp1.v.addr.fport = bind_addr.sin_port;

		/* set connect flag on socket */
		itp2.op = TPROXY_FLAGS;
		itp2.v.flags = ITP_CONNECT | ITP_ONCE;

		if (setsockopt(fd, SOL_IP, IP_TPROXY, &itp1, sizeof(itp1)) != -1 &&
		    setsockopt(fd, SOL_IP, IP_TPROXY, &itp2, sizeof(itp2)) != -1) {
			foreign_ok = 1;
		}
	}
#endif
	if (!foreign_ok)
		/* we could not bind to a foreign address */
		return 2;

	return 0;
}

/* This function tries to bind a TCPv4/v6 listener. It may return a warning or
 * an error message in <err> if the message is at most <errlen> bytes long
 * (including '\0'). The return value is composed from ERR_ABORT, ERR_WARN,
 * ERR_ALERT, ERR_RETRYABLE and ERR_FATAL. ERR_NONE indicates that everything
 * was alright and that no message was returned. ERR_RETRYABLE means that an
 * error occurred but that it may vanish after a retry (eg: port in use), and
 * ERR_FATAL indicates a non-fixable error.ERR_WARN and ERR_ALERT do not alter
 * the meaning of the error, but just indicate that a message is present which
 * should be displayed with the respective level. Last, ERR_ABORT indicates
 * that it's pointless to try to start other listeners. No error message is
 * returned if errlen is NULL.
 */
int tcp_bind_listener(struct listener *listener, char *errmsg, int errlen)
{
	__label__ tcp_return, tcp_close_return;
	int fd, err;
	const char *msg = NULL;

	/* ensure we never return garbage */
	if (errmsg && errlen)
		*errmsg = 0;

	if (listener->state != LI_ASSIGNED)
		return ERR_NONE; /* already bound */

	err = ERR_NONE;

	if ((fd = socket(listener->addr.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot create listening socket";
		goto tcp_return;
	}

	if (fd >= global.maxsock) {
		err |= ERR_FATAL | ERR_ABORT | ERR_ALERT;
		msg = "not enough free sockets (raise '-n' parameter)";
		goto tcp_close_return;
	}

	if ((fcntl(fd, F_SETFL, O_NONBLOCK) == -1) ||
	    (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
			(char *) &one, sizeof(one)) == -1)) {
		err |= ERR_FATAL | ERR_ALERT;
		msg = "cannot make socket non-blocking";
		goto tcp_close_return;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) == -1) {
		/* not fatal but should be reported */
		msg = "cannot do so_reuseaddr";
		err |= ERR_ALERT;
	}

	if (listener->options & LI_O_NOLINGER)
		setsockopt(fd, SOL_SOCKET, SO_LINGER, (struct linger *) &nolinger, sizeof(struct linger));

#ifdef SO_REUSEPORT
	/* OpenBSD supports this. As it's present in old libc versions of Linux,
	 * it might return an error that we will silently ignore.
	 */
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *) &one, sizeof(one));
#endif
#ifdef CONFIG_HAP_LINUX_TPROXY
	if ((listener->options & LI_O_FOREIGN)
	    && (setsockopt(fd, SOL_IP, IP_TRANSPARENT, (char *) &one, sizeof(one)) == -1)
	    && (setsockopt(fd, SOL_IP, IP_FREEBIND, (char *) &one, sizeof(one)) == -1)) {
		msg = "cannot make listening socket transparent";
		err |= ERR_ALERT;
	}
#endif
#ifdef SO_BINDTODEVICE
	/* Note: this might fail if not CAP_NET_RAW */
	if (listener->interface) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
			       listener->interface, strlen(listener->interface)) == -1) {
			msg = "cannot bind listener to device";
			err |= ERR_WARN;
		}
	}
#endif
	if (bind(fd, (struct sockaddr *)&listener->addr, listener->proto->sock_addrlen) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot bind socket";
		goto tcp_close_return;
	}

	if (listen(fd, listener->backlog ? listener->backlog : listener->maxconn) == -1) {
		err |= ERR_RETRYABLE | ERR_ALERT;
		msg = "cannot listen to socket";
		goto tcp_close_return;
	}

	/* the socket is ready */
	listener->fd = fd;
	listener->state = LI_LISTEN;

	/* the function for the accept() event */
	fd_insert(fd);
	fdtab[fd].cb[DIR_RD].f = listener->accept;
	fdtab[fd].cb[DIR_WR].f = NULL; /* never called */
	fdtab[fd].cb[DIR_RD].b = fdtab[fd].cb[DIR_WR].b = NULL;
	fdtab[fd].owner = listener; /* reference the listener instead of a task */
	fdtab[fd].state = FD_STLISTEN;
	fdtab[fd].peeraddr = NULL;
	fdtab[fd].peerlen = 0;
 tcp_return:
	if (msg && errlen)
		strlcpy2(errmsg, msg, errlen);
	return err;

 tcp_close_return:
	close(fd);
	goto tcp_return;
}

/* This function creates all TCP sockets bound to the protocol entry <proto>.
 * It is intended to be used as the protocol's bind_all() function.
 * The sockets will be registered but not added to any fd_set, in order not to
 * loose them across the fork(). A call to enable_all_listeners() is needed
 * to complete initialization. The return value is composed from ERR_*.
 */
static int tcp_bind_listeners(struct protocol *proto)
{
	struct listener *listener;
	int err = ERR_NONE;

	list_for_each_entry(listener, &proto->listeners, proto_list) {
		err |= tcp_bind_listener(listener, NULL, 0);
		if ((err & ERR_CODE) == ERR_ABORT)
			break;
	}

	return err;
}

/* Add listener to the list of tcpv4 listeners. The listener's state
 * is automatically updated from LI_INIT to LI_ASSIGNED. The number of
 * listeners is updated. This is the function to use to add a new listener.
 */
void tcpv4_add_listener(struct listener *listener)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_tcpv4;
	LIST_ADDQ(&proto_tcpv4.listeners, &listener->proto_list);
	proto_tcpv4.nb_listeners++;
}

/* Add listener to the list of tcpv4 listeners. The listener's state
 * is automatically updated from LI_INIT to LI_ASSIGNED. The number of
 * listeners is updated. This is the function to use to add a new listener.
 */
void tcpv6_add_listener(struct listener *listener)
{
	if (listener->state != LI_INIT)
		return;
	listener->state = LI_ASSIGNED;
	listener->proto = &proto_tcpv6;
	LIST_ADDQ(&proto_tcpv6.listeners, &listener->proto_list);
	proto_tcpv6.nb_listeners++;
}

/* This function performs the TCP request analysis on the current request. It
 * returns 1 if the processing can continue on next analysers, or zero if it
 * needs more data, encounters an error, or wants to immediately abort the
 * request. It relies on buffers flags, and updates s->req->analysers. Its
 * behaviour is rather simple:
 *  - the analyser must check for errors and timeouts, and react as expected.
 *    It does not have to close anything upon error, the caller will.
 *  - if the analyser does not have enough data, it must return 0without calling
 *    other ones. It should also probably do a buffer_write_dis() to ensure
 *    that unprocessed data will not be forwarded. But that probably depends on
 *    the protocol.
 *  - if an analyser has enough data, it just has to pass on to the next
 *    analyser without using buffer_write_dis() (enabled by default).
 *  - if an analyser thinks it has no added value anymore staying here, it must
 *    reset its bit from the analysers flags in order not to be called anymore.
 *
 * In the future, analysers should be able to indicate that they want to be
 * called after XXX bytes have been received (or transfered), and the min of
 * all's wishes will be used to ring back (unless a special condition occurs).
 */
int tcp_inspect_request(struct session *s, struct buffer *req)
{
	struct tcp_rule *rule;
	int partial;

	DPRINTF(stderr,"[%u] %s: session=%p b=%p, exp(r,w)=%u,%u bf=%08x bl=%d analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		req->l,
		req->analysers);

	/* We will abort if we encounter a read error. In theory, we
	 * should not abort if we get a close, it might be valid,
	 * although very unlikely. FIXME: we'll abort for now, this
	 * will be easier to change later.
	 */
	if (req->flags & BF_READ_ERROR) {
		req->analysers = 0;
		s->fe->failed_req++;
		if (!(s->flags & SN_ERR_MASK))
			s->flags |= SN_ERR_CLICL;
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;
		return 0;
	}

	/* Abort if client read timeout has expired */
	else if (req->flags & BF_READ_TIMEOUT) {
		req->analysers = 0;
		s->fe->failed_req++;
		if (!(s->flags & SN_ERR_MASK))
			s->flags |= SN_ERR_CLITO;
		if (!(s->flags & SN_FINST_MASK))
			s->flags |= SN_FINST_R;
		return 0;
	}

	/* We don't know whether we have enough data, so must proceed
	 * this way :
	 * - iterate through all rules in their declaration order
	 * - if one rule returns MISS, it means the inspect delay is
	 *   not over yet, then return immediately, otherwise consider
	 *   it as a non-match.
	 * - if one rule returns OK, then return OK
	 * - if one rule returns KO, then return KO
	 */

	if (req->flags & BF_SHUTR || tick_is_expired(req->analyse_exp, now_ms))
		partial = 0;
	else
		partial = ACL_PARTIAL;

	list_for_each_entry(rule, &s->fe->tcp_req.inspect_rules, list) {
		int ret = ACL_PAT_PASS;

		if (rule->cond) {
			ret = acl_exec_cond(rule->cond, s->fe, s, NULL, ACL_DIR_REQ | partial);
			if (ret == ACL_PAT_MISS) {
				buffer_write_dis(req);
				/* just set the request timeout once at the beginning of the request */
				if (!tick_isset(req->analyse_exp))
					req->analyse_exp = tick_add_ifset(now_ms, s->fe->tcp_req.inspect_delay);
				return 0;
			}

			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
		}

		if (ret) {
			/* we have a matching rule. */
			if (rule->action == TCP_ACT_REJECT) {
				buffer_abort(req);
				buffer_abort(s->rep);
				req->analysers = 0;
				s->fe->failed_req++;
				if (!(s->flags & SN_ERR_MASK))
					s->flags |= SN_ERR_PRXCOND;
				if (!(s->flags & SN_FINST_MASK))
					s->flags |= SN_FINST_R;
				return 0;
			}
				/* otherwise accept */
			break;
		}
	}

	/* if we get there, it means we have no rule which matches, or
	 * we have an explicit accept, so we apply the default accept.
	 */
	req->analysers &= ~AN_REQ_INSPECT;
	req->analyse_exp = TICK_ETERNITY;
	return 1;
}


/* This function should be called to parse a line starting with the "tcp-request"
 * keyword.
 */
static int tcp_parse_tcp_req(char **args, int section_type, struct proxy *curpx,
			     struct proxy *defpx, char *err, int errlen)
{
	const char *ptr = NULL;
	unsigned int val;
	int retlen;

	if (!*args[1]) {
		snprintf(err, errlen, "missing argument for '%s' in %s '%s'",
			 args[0], proxy_type_str(proxy), curpx->id);
		return -1;
	}

	if (!strcmp(args[1], "inspect-delay")) {
		if (curpx == defpx) {
			snprintf(err, errlen, "%s %s is not allowed in 'defaults' sections",
				 args[0], args[1]);
			return -1;
		}

		if (!(curpx->cap & PR_CAP_FE)) {
			snprintf(err, errlen, "%s %s will be ignored because %s '%s' has no %s capability",
				 args[0], args[1], proxy_type_str(proxy), curpx->id,
				 "frontend");
			return 1;
		}

		if (!*args[2] || (ptr = parse_time_err(args[2], &val, TIME_UNIT_MS))) {
			retlen = snprintf(err, errlen,
					  "'%s %s' expects a positive delay in milliseconds, in %s '%s'",
					  args[0], args[1], proxy_type_str(proxy), curpx->id);
			if (ptr && retlen < errlen)
				retlen += snprintf(err+retlen, errlen - retlen,
						   " (unexpected character '%c')", *ptr);
			return -1;
		}

		if (curpx->tcp_req.inspect_delay) {
			snprintf(err, errlen, "ignoring %s %s (was already defined) in %s '%s'",
				 args[0], args[1], proxy_type_str(proxy), curpx->id);
			return 1;
		}
		curpx->tcp_req.inspect_delay = val;
		return 0;
	}

	if (!strcmp(args[1], "content")) {
		int action;
		int warn = 0;
		int pol = ACL_COND_NONE;
		struct acl_cond *cond;
		struct tcp_rule *rule;

		if (curpx == defpx) {
			snprintf(err, errlen, "%s %s is not allowed in 'defaults' sections",
				 args[0], args[1]);
			return -1;
		}

		if (!strcmp(args[2], "accept"))
			action = TCP_ACT_ACCEPT;
		else if (!strcmp(args[2], "reject"))
			action = TCP_ACT_REJECT;
		else {
			retlen = snprintf(err, errlen,
					  "'%s %s' expects 'accept' or 'reject', in %s '%s' (was '%s')",
					  args[0], args[1], proxy_type_str(curpx), curpx->id, args[2]);
			return -1;
		}

		pol = ACL_COND_NONE;
		cond = NULL;

		if (!strcmp(args[3], "if"))
			pol = ACL_COND_IF;
		else if (!strcmp(args[3], "unless"))
			pol = ACL_COND_UNLESS;

		/* Note: we consider "if TRUE" when there is no condition */
		if (pol != ACL_COND_NONE &&
		    (cond = parse_acl_cond((const char **)args+4, &curpx->acl, pol)) == NULL) {
			retlen = snprintf(err, errlen,
					  "error detected in %s '%s' while parsing '%s' condition",
					  proxy_type_str(curpx), curpx->id, args[3]);
			return -1;
		}

		// FIXME: how to set this ?
		// cond->line = linenum;
		if (cond->requires & (ACL_USE_RTR_ANY | ACL_USE_L7_ANY)) {
			struct acl *acl;
			const char *name;

			acl = cond_find_require(cond, ACL_USE_RTR_ANY|ACL_USE_L7_ANY);
			name = acl ? acl->name : "(unknown)";

			retlen = snprintf(err, errlen,
					  "acl '%s' involves some %s criteria which will be ignored.",
					  name,
					  (acl->requires & ACL_USE_RTR_ANY) ? "response-only" : "layer 7");
			warn++;
		}
		rule = (struct tcp_rule *)calloc(1, sizeof(*rule));
		rule->cond = cond;
		rule->action = action;
		LIST_INIT(&rule->list);
		LIST_ADDQ(&curpx->tcp_req.inspect_rules, &rule->list);
		return warn;
	}

	snprintf(err, errlen, "unknown argument '%s' after '%s' in %s '%s'",
		 args[1], args[0], proxy_type_str(proxy), curpx->id);
	return -1;
}

/* return the number of bytes in the request buffer */
static int
acl_fetch_req_len(struct proxy *px, struct session *l4, void *l7, int dir,
		  struct acl_expr *expr, struct acl_test *test)
{
	if (!l4 || !l4->req)
		return 0;

	test->i = l4->req->l;
	test->flags = ACL_TEST_F_VOLATILE | ACL_TEST_F_MAY_CHANGE;
	return 1;
}

/* Return the version of the SSL protocol in the request. It supports both
 * SSLv3 (TLSv1) header format for any message, and SSLv2 header format for
 * the hello message. The SSLv3 format is described in RFC 2246 p49, and the
 * SSLv2 format is described here, and completed p67 of RFC 2246 :
 *    http://wp.netscape.com/eng/security/SSL_2.html
 *
 * Note: this decoder only works with non-wrapping data.
 */
static int
acl_fetch_req_ssl_ver(struct proxy *px, struct session *l4, void *l7, int dir,
			struct acl_expr *expr, struct acl_test *test)
{
	int version, bleft, msg_len;
	const unsigned char *data;

	if (!l4 || !l4->req)
		return 0;

	msg_len = 0;
	bleft = l4->req->l;
	if (!bleft)
		goto too_short;

	data = (const unsigned char *)l4->req->w;
	if ((*data >= 0x14 && *data <= 0x17) || (*data == 0xFF)) {
		/* SSLv3 header format */
		if (bleft < 5)
			goto too_short;

		version = (data[1] << 16) + data[2]; /* version: major, minor */
		msg_len = (data[3] <<  8) + data[4]; /* record length */

		/* format introduced with SSLv3 */
		if (version < 0x00030000)
			goto not_ssl;

		/* message length between 1 and 2^14 + 2048 */
		if (msg_len < 1 || msg_len > ((1<<14) + 2048))
			goto not_ssl;

		bleft -= 5; data += 5;
	} else {
		/* SSLv2 header format, only supported for hello (msg type 1) */
		int rlen, plen, cilen, silen, chlen;

		if (*data & 0x80) {
			if (bleft < 3)
				goto too_short;
			/* short header format : 15 bits for length */
			rlen = ((data[0] & 0x7F) << 8) | data[1];
			plen = 0;
			bleft -= 2; data += 2;
		} else {
			if (bleft < 4)
				goto too_short;
			/* long header format : 14 bits for length + pad length */
			rlen = ((data[0] & 0x3F) << 8) | data[1];
			plen = data[2];
			bleft -= 3; data += 2;
		}

		if (*data != 0x01)
			goto not_ssl;
		bleft--; data++;

		if (bleft < 8)
			goto too_short;
		version = (data[0] << 16) + data[1]; /* version: major, minor */
		cilen   = (data[2] <<  8) + data[3]; /* cipher len, multiple of 3 */
		silen   = (data[4] <<  8) + data[5]; /* session_id_len: 0 or 16 */
		chlen   = (data[6] <<  8) + data[7]; /* 16<=challenge length<=32 */

		bleft -= 8; data += 8;
		if (cilen % 3 != 0)
			goto not_ssl;
		if (silen && silen != 16)
			goto not_ssl;
		if (chlen < 16 || chlen > 32)
			goto not_ssl;
		if (rlen != 9 + cilen + silen + chlen)
			goto not_ssl;

		/* focus on the remaining data length */
		msg_len = cilen + silen + chlen + plen;
	}
	/* We could recursively check that the buffer ends exactly on an SSL
	 * fragment boundary and that a possible next segment is still SSL,
	 * but that's a bit pointless. However, we could still check that
	 * all the part of the request which fits in a buffer is already
	 * there.
	 */
	if (msg_len > l4->req->max_len + l4->req->data - l4->req->w)
		msg_len = l4->req->max_len + l4->req->data - l4->req->w;

	if (bleft < msg_len)
		goto too_short;

	/* OK that's enough. We have at least the whole message, and we have
	 * the protocol version.
	 */
	test->i = version;
	test->flags = ACL_TEST_F_VOLATILE;
	return 1;

 too_short:
	test->flags = ACL_TEST_F_MAY_CHANGE;
 not_ssl:
	return 0;
}


static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_LISTEN, "tcp-request", tcp_parse_tcp_req },
	{ 0, NULL, NULL },
}};

static struct acl_kw_list acl_kws = {{ },{
	{ "req_len",      acl_parse_int,        acl_fetch_req_len,     acl_match_int, ACL_USE_L4REQ_VOLATILE },
	{ "req_ssl_ver",  acl_parse_dotted_ver, acl_fetch_req_ssl_ver, acl_match_int, ACL_USE_L4REQ_VOLATILE },
	{ NULL, NULL, NULL, NULL },
}};

__attribute__((constructor))
static void __tcp_protocol_init(void)
{
	protocol_register(&proto_tcpv4);
	protocol_register(&proto_tcpv6);
	cfg_register_keywords(&cfg_kws);
	acl_register_keywords(&acl_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
