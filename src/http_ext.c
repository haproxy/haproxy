/*
 * HTTP extensions logic and helpers
 *
 * Copyright 2022 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <haproxy/sample.h>
#include <haproxy/http_htx.h>
#include <haproxy/http_ext.h>
#include <haproxy/chunk.h>
#include <haproxy/stream.h>
#include <haproxy/proxy.h>
#include <haproxy/sc_strm.h>
#include <haproxy/obj_type.h>
#include <haproxy/cfgparse.h>
#include <haproxy/arg.h>
#include <haproxy/initcall.h>
#include <haproxy/tools.h>

/*
 * =========== ANALYZE ===========
 * below are http process/ana helpers
 */

/* checks if <input> contains rfc7239 compliant port
 * Returns 1 for success and 0 for failure
 * if <port> is not NULL, it will be set to the extracted value contained
 * in <input>
 * <input> will be consumed accordingly (parsed/extracted characters are
 * removed from <input>)
 */
static inline int http_7239_extract_port(struct ist *input, uint16_t *port)
{
	char *start = istptr(*input);
	uint32_t port_cast = 0;
	int it = 0;

	/* strtol does not support non-null terminated str,
	 * we extract port ourselves
	 */
	while (it < istlen(*input) &&
	       isdigit((unsigned char)start[it])) {
		port_cast = (port_cast * 10) + (start[it] - '0');
		if (port_cast > 65535)
			return 0; /* invalid port */
		it += 1;
	}
	if (!port_cast)
		return 0; /* invalid port */
	/* ok */
	if (port)
		*port = (uint16_t)port_cast;
	*input = istadv(*input, it);
	return 1;
}

/* check if char is a valid obfuscated identifier char
 * (according to 7239 RFC)
 * Returns non zero value for valid char
 */
static inline int http_7239_valid_obfsc(char c)
{
	return (isalnum((unsigned char)c) ||
                (c == '.' || c == '-' || c == '_'));
}

/* checks if <input> contains rfc7239 compliant obfuscated identifier
 * Returns 1 for success and 0 for failure
 * if <obfs> is not NULL, it will be set to the extracted value contained
 * in <input>
 * <input> will be consumed accordingly (parsed/extracted characters are
 * removed from <input>)
 */
static inline int http_7239_extract_obfs(struct ist *input, struct ist *obfs)
{
	int it = 0;

	if (obfs)
		obfs->ptr = input->ptr;

	while (it < istlen(*input) && istptr(*input)[it] != ';') {
		if (!http_7239_valid_obfsc(istptr(*input)[it]))
			break; /* end of obfs token */
		it += 1;
	}
	if (obfs)
		obfs->len = it;
	*input = istadv(*input, it);
	return !!it;
}

/* checks if <input> contains rfc7239 compliant IPV4 address
 * Returns 1 for success and 0 for failure
 * if <ip> is not NULL, it will be set to the extracted value contained
 * in <input>
 * <input> will be consumed accordingly (parsed/extracted characters are
 * removed from <input>)
 */
static inline int http_7239_extract_ipv4(struct ist *input, struct in_addr *ip)
{
	char ip4[INET_ADDRSTRLEN];
	unsigned char buf[sizeof(struct in_addr)];
	void *dst = buf;
	int it = 0;

	if (ip)
		dst = ip;

	/* extract ipv4 addr */
	while (it < istlen(*input) && it < (sizeof(ip4) - 1)) {
		if (!isdigit((unsigned char)istptr(*input)[it]) &&
		    istptr(*input)[it] != '.')
			break; /* no more ip4 char */
		ip4[it] = istptr(*input)[it];
		it += 1;
	}
	ip4[it] = 0;
	if (inet_pton(AF_INET, ip4, dst) != 1)
		return 0; /* invalid ip4 addr */
	/* ok */
	*input = istadv(*input, it);
	return 1;
}

/* checks if <input> contains rfc7239 compliant IPV6 address
 *    assuming input.len >= 1 and first char is '['
 * Returns 1 for success and 0 for failure
 * if <ip> is not NULL, it will be set to the extracted value contained
 * in <input>
 * <input> will be consumed accordingly (parsed/extracted characters are
 * removed from <input>)
 */
static inline int http_7239_extract_ipv6(struct ist *input, struct in6_addr *ip)
{
	char ip6[INET6_ADDRSTRLEN];
	unsigned char buf[sizeof(struct in6_addr)];
	void *dst = buf;
	int it = 0;

	if (ip)
		dst = ip;

	*input = istnext(*input); /* skip '[' leading char */
	/* extract ipv6 addr */
	while (it < istlen(*input) &&
               it < (sizeof(ip6) - 1)) {
		if (!isalnum((unsigned char)istptr(*input)[it]) &&
		    istptr(*input)[it] != ':')
			break; /* no more ip6 char */
		ip6[it] = istptr(*input)[it];
		it += 1;
	}
	ip6[it] = 0;
	if ((istlen(*input)-it) < 1 || istptr(*input)[it] != ']')
		return 0; /* missing ending "]" char */
	it += 1;
	if (inet_pton(AF_INET6, ip6, dst) != 1)
		return 0; /* invalid ip6 addr */
	/* ok */
	*input = istadv(*input, it);
	return 1;
}

/* checks if <input> contains rfc7239 compliant host
 * <quoted> is used to determine if the current input is being extracted
 * from a quoted (non zero) or unquoted (zero) token, as the parsing rules
 * differ whether the input is quoted or not according to the rfc.
 * Returns 1 for success and 0 for failure
 * if <host> is not NULL, it will be set to the extracted value contained
 * in <input>
 * <input> will be consumed accordingly (parsed/extracted characters are
 * removed from <input>)
 */
static inline int http_7239_extract_host(struct ist *input, struct ist *host, int quoted)
{
	if (istlen(*input) < 1)
		return 0; /* invalid input */

	if (host)
		host->ptr = input->ptr;

	if (quoted && *istptr(*input) == '[') {
		/* raw ipv6 address */
		if (!http_7239_extract_ipv6(input, NULL))
			return 0; /* invalid addr */
	}
	else {
		/* ipv4 or dns */
		while (istlen(*input)) {
			if (!isalnum((unsigned char)*istptr(*input)) &&
			    *istptr(*input) != '.')
				break; /* end of hostname token */
			*input = istnext(*input);
		}
	}
	if (istlen(*input) < 1 || *istptr(*input) != ':') {
		goto out; /* no optional port provided */
	}
	if (!quoted)
		return 0; /* not supported */
	*input = istnext(*input); /* skip ':' */
	/* validate port */
	if (!http_7239_extract_port(input, NULL))
		return 0; /* invalid port */
 out:
	if (host)
		host->len = (input->ptr - host->ptr);
	return 1;
}

/* checks if <input> contains rfc7239 compliant nodename
 * <quoted> is used to determine if the current input is being extracted
 * from a quoted (non zero) or unquoted (zero) token, as the parsing rules
 * differ whether the input is quoted or not according to the rfc.
 * Returns 1 for success and 0 for failure
 * if <nodename> is not NULL, it will be set to the extracted value contained
 * in <input>
 * <input> will be consumed accordingly (parsed/extracted characters are
 * removed from <input>)
 */
static inline int http_7239_extract_nodename(struct ist *input, struct forwarded_header_nodename *nodename, int quoted)
{
	if (istlen(*input) < 1)
		return 0; /* invalid input */
	if (*istptr(*input) == '_') {
		struct ist *obfs = NULL;

		/* obfuscated nodename */
		*input = istnext(*input); /* skip '_' */
		if (nodename) {
			nodename->type = FORWARDED_HEADER_OBFS;
			obfs = &nodename->obfs;
		}
		if (!http_7239_extract_obfs(input, obfs))
			return 0; /* invalid obfs */
	} else if (*istptr(*input) == 'u') {
		/* "unknown" nodename? */
		if (istlen(*input) < 7 ||
		    strncmp("unknown", istptr(*input), 7))
			return 0; /* syntax error */
		*input = istadv(*input, 7); /* skip "unknown" */
		if (nodename)
			nodename->type = FORWARDED_HEADER_UNK;
	} else if (quoted && *istptr(*input) == '[') {
		struct in6_addr *ip6 = NULL;

		/* ipv6 address */
		if (nodename) {
			struct sockaddr_in6 *addr = (void *)&nodename->ip;

			ip6 = &addr->sin6_addr;
			addr->sin6_family = AF_INET6;
			nodename->type = FORWARDED_HEADER_IP;
		}
		if (!http_7239_extract_ipv6(input, ip6))
			return 0; /* invalid ip6 */
	} else if (*istptr(*input)) {
		struct in_addr *ip = NULL;

		/* ipv4 address */
		if (nodename) {
			struct sockaddr_in *addr = (void *)&nodename->ip;

			ip = &addr->sin_addr;
			addr->sin_family = AF_INET;
			nodename->type = FORWARDED_HEADER_IP;
		}
		if (!http_7239_extract_ipv4(input, ip))
			return 0; /* invalid ip */
	} else
		return 0; /* unexpected char */

	/* ok */
	return 1;
}

/* checks if <input> contains rfc7239 compliant nodeport
 * <quoted> is used to determine if the current input is being extracted
 * from a quoted (non zero) or unquoted (zero) token, as the parsing rules
 * differ whether the input is quoted or not according to the rfc.
 * Returns 1 for success and 0 for failure
 * if <nodeport> is not NULL, it will be set to the extracted value contained
 * in <input>
 * <input> will be consumed accordingly (parsed/extracted characters are
 * removed from <input>)
 */
static inline int http_7239_extract_nodeport(struct ist *input, struct forwarded_header_nodeport *nodeport)
{
	if (*istptr(*input) == '_') {
		struct ist *obfs = NULL;

		/* obfuscated nodeport */
		*input = istnext(*input); /* skip '_' */
		if (nodeport) {
			nodeport->type = FORWARDED_HEADER_OBFS;
			obfs = &nodeport->obfs;
		}
		if (!http_7239_extract_obfs(input, obfs))
			return 0; /* invalid obfs */
	} else {
		uint16_t *port = NULL;

		/* normal port */
		if (nodeport) {
			nodeport->type = FORWARDED_HEADER_PORT;
			port = &nodeport->port;
		}
		if (!http_7239_extract_port(input, port))
			return 0; /* invalid port */
	}
	/* ok */
	return 1;
}

/* checks if <input> contains rfc7239 compliant node (nodename:nodeport token)
 * <quoted> is used to determine if the current input is being extracted
 * from a quoted (non zero) or unquoted (zero) token, as the parsing rules
 * differ whether the input is quoted or not according to the rfc.
 * Returns 1 for success and 0 for failure
 * if <node> is not NULL, it will be set to the extracted value contained
 * in <input>
 * <input> will be consumed accordingly (parsed/extracted characters are
 * removed from <input>)
 */
static inline int http_7239_extract_node(struct ist *input, struct forwarded_header_node *node, int quoted)
{
	struct forwarded_header_nodename *nodename = NULL;
	struct forwarded_header_nodeport *nodeport = NULL;

	if (node) {
		nodename = &node->nodename;
		nodeport = &node->nodeport;
		node->raw.ptr = input->ptr;
	}
	if (!http_7239_extract_nodename(input, nodename, quoted))
		return 0; /* invalid nodename */
	if (istlen(*input) < 1 || *istptr(*input) != ':') {
		if (node)
			node->nodeport.type = FORWARDED_HEADER_UNK;
		goto out; /* no optional port provided */
	}
	if (!quoted)
		return 0; /* not supported */
	*input = istnext(*input);
	if (!http_7239_extract_nodeport(input, nodeport))
		return 0; /* invalid nodeport */
 out:
	/* ok */
	if (node)
		node->raw.len = input->ptr - node->raw.ptr;
	return 1;
}

static inline int _forwarded_header_save_ctx(struct forwarded_header_ctx *ctx, int current_step, int required_steps)
{
	return (ctx && (current_step & required_steps));
}

static inline void _forwarded_header_quote_expected(struct ist *hdr, uint8_t *quoted)
{
	if (istlen(*hdr) > 0 && *istptr(*hdr) == '"') {
		*quoted = 1;
		/* node is quoted, we must find corresponding
		 * ending quote at the end of the token
		 */
		*hdr = istnext(*hdr); /* skip quote */
	}
}

/* checks if current header <hdr> is RFC 7239 compliant and can be "trusted".
 * function will stop parsing as soon as every <required_steps> have
 * been validated or error is encountered.
 * Provide FORWARDED_HEADER_ALL for a full header validating spectrum.
 * You may provide limited scope to perform quick searches on specific attributes
 * If <ctx> is provided (not NULL), parsed attributes will be stored according to
 * their types, allowing you to extract some useful information from the header.
 * Returns 0 on failure and <validated_steps> bitfield on success.
 */
int http_validate_7239_header(struct ist hdr, int required_steps, struct forwarded_header_ctx *ctx)
{
	int validated_steps = 0;
	int current_step = 0;
	uint8_t first = 1;
	uint8_t quoted = 0;

	while (istlen(hdr) && (required_steps & ~validated_steps)) {
		if (!first) {
			if (*istptr(hdr) == ';')
				hdr = istnext(hdr); /* skip ';' */
			else
				goto not_ok; /* unexpected char */
		}
		else
			first = 0;

		if (!(validated_steps & FORWARDED_HEADER_FOR) && istlen(hdr) > 4 &&
                    strncmp("for=", istptr(hdr), 4) == 0) {
			struct forwarded_header_node *node = NULL;

			/* for parameter */
			current_step = FORWARDED_HEADER_FOR;
			hdr = istadv(hdr, 4); /* skip "for=" */
			_forwarded_header_quote_expected(&hdr, &quoted);
			if (_forwarded_header_save_ctx(ctx, current_step, required_steps))
				node = &ctx->nfor;
			/* validate node */
			if (!http_7239_extract_node(&hdr, node, quoted))
				goto not_ok; /* invalid node */
		}
		else if (!(validated_steps & FORWARDED_HEADER_BY) && istlen(hdr) > 3 &&
                         strncmp("by=", istptr(hdr), 3) == 0) {
			struct forwarded_header_node *node = NULL;

			/* by parameter */
			current_step = FORWARDED_HEADER_BY;
			hdr = istadv(hdr, 3); /* skip "by=" */
			_forwarded_header_quote_expected(&hdr, &quoted);
			if (_forwarded_header_save_ctx(ctx, current_step, required_steps))
				node = &ctx->nby;
			/* validate node */
			if (!http_7239_extract_node(&hdr, node, quoted))
				goto not_ok; /* invalid node */
		}
		else if (!(validated_steps & FORWARDED_HEADER_HOST) && istlen(hdr) > 5 &&
                         strncmp("host=", istptr(hdr), 5) == 0) {
			struct ist *host = NULL;

			/* host parameter */
			current_step = FORWARDED_HEADER_HOST;
			hdr = istadv(hdr, 5); /* skip "host=" */
			_forwarded_header_quote_expected(&hdr, &quoted);
			if (_forwarded_header_save_ctx(ctx, current_step, required_steps))
				host = &ctx->host;
			/* validate host */
			if (!http_7239_extract_host(&hdr, host, quoted))
				goto not_ok; /* invalid host */
		}
		else if (!(validated_steps & FORWARDED_HEADER_PROTO) && istlen(hdr) > 6 &&
                         strncmp("proto=", istptr(hdr), 6) == 0) {
			/* proto parameter */
			current_step = FORWARDED_HEADER_PROTO;
			hdr = istadv(hdr, 6); /* skip "proto=" */
			/* validate proto (only common used http|https are supported for now) */
			if (istlen(hdr) < 4 || strncmp("http", istptr(hdr), 4))
				goto not_ok;
			hdr = istadv(hdr, 4); /* skip "http" */
			if (istlen(hdr) && *istptr(hdr) == 's') {
				hdr = istnext(hdr);
				if (_forwarded_header_save_ctx(ctx, current_step, required_steps))
					ctx->proto = FORWARDED_HEADER_HTTPS;
			} else if (_forwarded_header_save_ctx(ctx, current_step, required_steps))
				ctx->proto = FORWARDED_HEADER_HTTP;
			/* rfc allows for potential proto quoting, but we don't support
			 * it: it is not common usage
			 */
		}
		else {
			/* not supported
			 * rfc allows for upcoming extensions
			 * but obviously, we can't trust them
			 * as they are not yet standardized
			 */

			goto not_ok;
		}
		/* quote check */
		if (quoted) {
			if (istlen(hdr) < 1 || *istptr(hdr) != '"') {
				/* matching ending quote not found */
				goto not_ok;
			}
			hdr = istnext(hdr); /* skip ending quote */
			quoted = 0; /* reset */
		}
		validated_steps |= current_step;
	}

	return validated_steps;

 not_ok:
	return 0;
}

static inline void _7239_print_ip6(struct buffer *out, struct in6_addr *ip6_addr, int quoted)
{
	char pn[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6,
		  ip6_addr,
		  pn, sizeof(pn));
	if (!quoted)
		chunk_appendf(out, "\""); /* explicit quoting required for ipv6 */
	chunk_appendf(out, "[%s]", pn);
}

static inline void http_build_7239_header_nodename(struct buffer *out,
                                                   struct stream *s, struct proxy *curproxy,
                                                   const struct sockaddr_storage *addr,
                                                   struct http_ext_7239_forby *forby)
{
	struct in6_addr *ip6_addr;
	int quoted = !!forby->np_mode;

	if (forby->nn_mode == HTTP_7239_FORBY_ORIG) {
		if (addr && addr->ss_family == AF_INET) {
			unsigned char *pn = (unsigned char *)&((struct sockaddr_in *)addr)->sin_addr;

			chunk_appendf(out, "%d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);
		}
		else if (addr && addr->ss_family == AF_INET6) {
			ip6_addr = &((struct sockaddr_in6 *)addr)->sin6_addr;
			_7239_print_ip6(out, ip6_addr, quoted);
		}
		/* else: not supported */
	}
	else if (forby->nn_mode == HTTP_7239_FORBY_SMP && forby->nn_expr) {
		struct sample *smp;

		smp = sample_process(curproxy, s->sess, s,
				SMP_OPT_DIR_REQ | SMP_OPT_FINAL, forby->nn_expr, NULL);

		if (smp) {
			if (smp->data.type == SMP_T_IPV6) {
				/* smp is valid IP6, print with RFC compliant output */
				ip6_addr = &smp->data.u.ipv6;
				_7239_print_ip6(out, ip6_addr, quoted);
			}
			else if (sample_casts[smp->data.type][SMP_T_STR] &&
				 sample_casts[smp->data.type][SMP_T_STR](smp)) {
				struct ist validate_n = ist2(smp->data.u.str.area, smp->data.u.str.data);
				struct ist validate_o = ist2(smp->data.u.str.area, smp->data.u.str.data);
				struct forwarded_header_nodename nodename;

				/* validate nodename */
				if (http_7239_extract_nodename(&validate_n, &nodename, 1) &&
				    !istlen(validate_n)) {
					if (nodename.type == FORWARDED_HEADER_IP &&
					    nodename.ip.ss_family == AF_INET6) {
						/* special care needed for valid ip6 nodename (quoting) */
						ip6_addr = &((struct sockaddr_in6 *)&nodename.ip)->sin6_addr;
						_7239_print_ip6(out, ip6_addr, quoted);
					} else {
						/* no special care needed, input is already rfc compliant,
						 * just print as regular non quoted string
						 */
						chunk_cat(out, &smp->data.u.str);
					}
				}
				else if (http_7239_extract_obfs(&validate_o, NULL) &&
					 !istlen(validate_o)) {
					/* raw user input that should be printed as 7239 obfs */
					chunk_appendf(out, "_%.*s", (int)smp->data.u.str.data, smp->data.u.str.area);
				}
				/* else: not compliant */
			}
			/* else: cannot be casted to str */
		}
		/* else: smp error */
	}
}

static inline void http_build_7239_header_nodeport(struct buffer *out,
                                                   struct stream *s, struct proxy *curproxy,
                                                   const struct sockaddr_storage *addr,
                                                   struct http_ext_7239_forby *forby)
{
	if (forby->np_mode == HTTP_7239_FORBY_ORIG) {
		if (addr && addr->ss_family == AF_INET)
			chunk_appendf(out, "%d", ntohs(((struct sockaddr_in *)addr)->sin_port));
		else if (addr && addr->ss_family == AF_INET6)
			chunk_appendf(out, "%d", ntohs(((struct sockaddr_in6 *)addr)->sin6_port));
		/* else: not supported */
	}
	else if (forby->np_mode == HTTP_7239_FORBY_SMP && forby->np_expr) {
		struct sample *smp;

		smp = sample_fetch_as_type(curproxy, s->sess, s,
				SMP_OPT_DIR_REQ | SMP_OPT_FINAL, forby->np_expr, SMP_T_STR);
		if (smp) {
			struct ist validate_n = ist2(smp->data.u.str.area, smp->data.u.str.data);
			struct ist validate_o = ist2(smp->data.u.str.area, smp->data.u.str.data);

			/* validate nodeport */
			if (http_7239_extract_nodeport(&validate_n, NULL) &&
			    !istlen(validate_n)) {
				/* no special care needed, input is already rfc compliant,
				 * just print as regular non quoted string
				 */
				chunk_cat(out, &smp->data.u.str);
			}
			else if (http_7239_extract_obfs(&validate_o, NULL) &&
				 !istlen(validate_o)) {
				/* raw user input that should be printed as 7239 obfs */
				chunk_appendf(out, "_%.*s", (int)smp->data.u.str.data, smp->data.u.str.area);
			}
			/* else: not compliant */
		}
		/* else: smp error */
	}
}

static inline void http_build_7239_header_node(struct buffer *out,
                                               struct stream *s, struct proxy *curproxy,
                                               const struct sockaddr_storage *addr,
                                               struct http_ext_7239_forby *forby)
{
	size_t offset_start;
	size_t offset_save;

	offset_start = out->data;
	if (forby->np_mode)
		chunk_appendf(out, "\"");
	offset_save = out->data;
	http_build_7239_header_nodename(out, s, curproxy, addr, forby);
	if (offset_save == out->data) {
		/* could not build nodename, either because some
		 * data is not available or user is providing bad input
		 */
		chunk_appendf(out, "unknown");
	}
	if (forby->np_mode) {
		chunk_appendf(out, ":");
		offset_save = out->data;
		http_build_7239_header_nodeport(out, s, curproxy, addr, forby);
		if (offset_save == out->data) {
			/* could not build nodeport, either because some data is
			 * not available or user is providing bad input
			 */
			out->data = offset_save - 1;
		}
	}
	if (out->data != offset_start && out->area[offset_start] == '"')
		chunk_appendf(out, "\""); /* add matching end quote */
}

static inline void http_build_7239_header_host(struct buffer *out,
                                               struct stream *s, struct proxy *curproxy,
                                               struct htx *htx, struct http_ext_7239_host *host)
{
	struct http_hdr_ctx ctx = { .blk = NULL };
	char *str = NULL;
	int str_len = 0;

	if (host->mode == HTTP_7239_HOST_ORIG &&
	    http_find_header(htx, ist("host"), &ctx, 0)) {
		str = ctx.value.ptr;
		str_len = ctx.value.len;
 print_host:
		{
			struct ist validate = ist2(str, str_len);
			/* host check, to ensure rfc compliant output
			 * (assuming host is quoted/escaped)
			 */
			if (http_7239_extract_host(&validate, NULL, 1) && !istlen(validate))
				chunk_memcat(out, str, str_len);
			/* else: not compliant or partially compliant */
		}

	}
	else if (host->mode == HTTP_7239_HOST_SMP && host->expr) {
		struct sample *smp;

		smp = sample_fetch_as_type(curproxy, s->sess, s,
				SMP_OPT_DIR_REQ | SMP_OPT_FINAL, host->expr, SMP_T_STR);
		if (smp) {
			str = smp->data.u.str.area;
			str_len = smp->data.u.str.data;
			goto print_host;
		}
		/* else: smp error */
	}
}

/* Tries build 7239 header according to <curproxy> parameters and <s> context
 * It both depends on <curproxy>->http_ext->fwd for config and <s> for request
 * context data.
 * The function will write output to <out> buffer
 * Returns 1 for success and 0 for error (ie: not enough space in buffer)
 */
static int http_build_7239_header(struct buffer *out,
                                  struct stream *s, struct proxy *curproxy, struct htx *htx)
{
	struct connection *cli_conn = objt_conn(strm_sess(s)->origin);

	if (curproxy->http_ext->fwd->p_proto) {
		chunk_appendf(out, "%sproto=%s", ((out->data) ? ";" : ""),
			((conn_is_ssl(cli_conn)) ? "https" : "http"));
	}
	if (curproxy->http_ext->fwd->p_host.mode) {
		/* always add quotes for host parameter to make output compliance checks simpler */
		chunk_appendf(out, "%shost=\"", ((out->data) ? ";" : ""));
		/* ignore return value for now, but could be useful some day */
		http_build_7239_header_host(out, s, curproxy, htx, &curproxy->http_ext->fwd->p_host);
		chunk_appendf(out, "\"");
	}

	if (curproxy->http_ext->fwd->p_by.nn_mode) {
		const struct sockaddr_storage *dst = sc_dst(s->scf);

		chunk_appendf(out, "%sby=", ((out->data) ? ";" : ""));
		http_build_7239_header_node(out, s, curproxy, dst, &curproxy->http_ext->fwd->p_by);
	}

	if (curproxy->http_ext->fwd->p_for.nn_mode) {
		const struct sockaddr_storage *src = sc_src(s->scf);

		chunk_appendf(out, "%sfor=", ((out->data) ? ";" : ""));
		http_build_7239_header_node(out, s, curproxy, src, &curproxy->http_ext->fwd->p_for);
	}
	if (unlikely(out->data == out->size)) {
		/* not enough space in buffer, error */
		return 0;
	}
	return 1;
}

/* This function will try to inject RFC 7239 forwarded header if
 * configured on the backend (ignored for frontends).
 * Will do nothing if the option is not enabled on the proxy.
 * Returns 1 for success and 0 for failure
 */
int http_handle_7239_header(struct stream *s, struct channel *req)
{
	struct proxy *curproxy = s->be; /* ignore frontend */

	if (curproxy->http_ext && curproxy->http_ext->fwd) {
		struct htx *htx = htxbuf(&req->buf);
		int validate = 1;
		struct http_hdr_ctx find = { .blk = NULL };
		struct http_hdr_ctx last = { .blk = NULL};
		struct ist hdr = ist("forwarded");

		/* ok, let's build forwarded header */
		chunk_reset(&trash);
		if (unlikely(!http_build_7239_header(&trash, s, curproxy, htx)))
			return 0; /* error when building header (bad user conf or memory error) */

		/* validate existing forwarded header (including multiple values),
		 * hard stop if error is encountered
		 */
		while (http_find_header(htx, hdr, &find, 0)) {
			/* validate current header chunk */
			if (!http_validate_7239_header(find.value, FORWARDED_HEADER_ALL, NULL)) {
				/* at least one error, existing forwarded header not OK, add our own
				 * forwarded header, so that it can be trusted
				 */
				validate = 0;
				break;
			}
			last = find;
		}
		/* no errors, append our data at the end of existing header */
		if (last.blk && validate) {
			if (unlikely(!http_append_header_value(htx, &last, ist2(trash.area, trash.data))))
				return 0; /* htx error */
		}
		else {
			if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
				return 0; /* htx error */
		}
	}
	return 1;
}

/*
 * add X-Forwarded-For if either the frontend or the backend
 * asks for it.
 * Returns 1 for success and 0 for failure
 */
int http_handle_xff_header(struct stream *s, struct channel *req)
{
	struct session *sess = s->sess;
	struct http_ext_xff *f_xff = NULL;
	struct http_ext_xff *b_xff = NULL;

	if (sess->fe->http_ext && sess->fe->http_ext->xff) {
		/* frontend */
		f_xff = sess->fe->http_ext->xff;
	}
	if (s->be->http_ext && s->be->http_ext->xff) {
		/* backend */
		b_xff = s->be->http_ext->xff;
	}

	if (f_xff || b_xff) {
		struct htx *htx = htxbuf(&req->buf);
		const struct sockaddr_storage *src = sc_src(s->scf);
		struct http_hdr_ctx ctx = { .blk = NULL };
		struct ist hdr = ((b_xff) ? b_xff->hdr_name : f_xff->hdr_name);

		if ((!f_xff || f_xff->mode == HTTP_XFF_IFNONE) &&
		    (!b_xff || b_xff->mode == HTTP_XFF_IFNONE) &&
		    http_find_header(htx, hdr, &ctx, 0)) {
			/* The header is set to be added only if none is present
			 * and we found it, so don't do anything.
			 */
		}
		else if (src && src->ss_family == AF_INET) {
			/* Add an X-Forwarded-For header unless the source IP is
			 * in the 'except' network range.
			 */
			if ((!f_xff || ipcmp2net(src, &f_xff->except_net)) &&
			    (!b_xff || ipcmp2net(src, &b_xff->except_net))) {
				unsigned char *pn = (unsigned char *)&((struct sockaddr_in *)src)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				chunk_printf(&trash, "%d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					return 0;
			}
		}
		else if (src && src->ss_family == AF_INET6) {
			/* Add an X-Forwarded-For header unless the source IP is
			 * in the 'except' network range.
			 */
			if ((!f_xff || ipcmp2net(src, &f_xff->except_net)) &&
			    (!b_xff || ipcmp2net(src, &b_xff->except_net))) {
				char pn[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)(src))->sin6_addr,
					  pn, sizeof(pn));

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				chunk_printf(&trash, "%s", pn);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					return 0;
			}
		}
	}
	return 1;
}

/*
 * add X-Original-To if either the frontend or the backend
 * asks for it.
 * Returns 1 for success and 0 for failure
 */
int http_handle_xot_header(struct stream *s, struct channel *req)
{
	struct session *sess = s->sess;
	struct http_ext_xot *f_xot = NULL;
	struct http_ext_xot *b_xot = NULL;

	if (sess->fe->http_ext && sess->fe->http_ext->xot) {
		/* frontend */
		f_xot = sess->fe->http_ext->xot;
	}
	if (s->be->http_ext && s->be->http_ext->xot) {
		/* backend */
		b_xot = s->be->http_ext->xot;
	}

	if (f_xot || b_xot) {
		struct htx *htx = htxbuf(&req->buf);
		const struct sockaddr_storage *dst = sc_dst(s->scf);
		struct ist hdr = ((b_xot) ? b_xot->hdr_name : f_xot->hdr_name);

		if (dst && dst->ss_family == AF_INET) {
			/* Add an X-Original-To header unless the destination IP is
			 * in the 'except' network range.
			 */
			if ((!f_xot || ipcmp2net(dst, &f_xot->except_net)) &&
			    (!b_xot || ipcmp2net(dst, &b_xot->except_net))) {
				unsigned char *pn = (unsigned char *)&((struct sockaddr_in *)dst)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-original-to, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				chunk_printf(&trash, "%d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					return 0;
			}
		}
		else if (dst && dst->ss_family == AF_INET6) {
			/* Add an X-Original-To header unless the source IP is
			 * in the 'except' network range.
			 */
			if ((!f_xot || ipcmp2net(dst, &f_xot->except_net)) &&
			    (!b_xot || ipcmp2net(dst, &b_xot->except_net))) {
				char pn[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6,
					  (const void *)&((struct sockaddr_in6 *)dst)->sin6_addr,
					  pn, sizeof(pn));

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				chunk_printf(&trash, "%s", pn);
				if (unlikely(!http_add_header(htx, hdr, ist2(trash.area, trash.data))))
					return 0;
			}
		}
	}
	return 1;
}

/*
 * =========== CONFIG ===========
 * below are helpers to parse http ext options from the config
 */
static int proxy_http_parse_oom(const char *file, int linenum)
{
	int err_code = 0;

	ha_alert("parsing [%s:%d]: out of memory.\n", file, linenum);
	err_code |= ERR_ALERT | ERR_ABORT;
	return err_code;
}

static inline int _proxy_http_parse_7239_expr(char **args, int *cur_arg,
                                              const char *file, int linenum,
                                              char **expr_s)
{
	int err_code = 0;

	if (!*args[*cur_arg + 1]) {
		ha_alert("parsing [%s:%d]: '%s' expects <expr> as argument.\n",
			 file, linenum, args[*cur_arg]);
		err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	*cur_arg += 1;
	ha_free(expr_s);
	*expr_s = strdup(args[*cur_arg]);
	if (!*expr_s)
		return proxy_http_parse_oom(file, linenum);
	*cur_arg += 1;
 out:
	return err_code;
}

/* forwarded/7239 RFC: tries to parse "option forwarded" config keyword
 * Returns a composition of ERR_ABORT, ERR_ALERT, ERR_FATAL, ERR_WARN
 */
int proxy_http_parse_7239(char **args, int cur_arg,
                          struct proxy *curproxy, const struct proxy *defpx,
                          const char *file, int linenum)
{
	struct http_ext_7239 *fwd;
	int err_code = 0;

	if (warnifnotcap(curproxy, PR_CAP_BE, file, linenum, "option forwarded", NULL)) {
		/* option is ignored for frontends */
		err_code |= ERR_WARN;
		goto out;
	}

	if (!http_ext_7239_prepare(curproxy))
		return proxy_http_parse_oom(file, linenum);

	fwd = curproxy->http_ext->fwd;

	fwd->p_proto = 0;
	fwd->p_host.mode = 0;
	fwd->p_for.nn_mode = 0;
	fwd->p_for.np_mode = 0;
	fwd->p_by.nn_mode = 0;
	fwd->p_by.np_mode = 0;
	ha_free(&fwd->c_file);
	fwd->c_file = strdup(file);
	fwd->c_line = linenum;

	/* start at 2, since 0+1 = "option" "forwarded" */
	cur_arg = 2;
	if (!*(args[cur_arg])) {
		/* no optional argument provided, use default settings */
		fwd->p_for.nn_mode = HTTP_7239_FORBY_ORIG; /* enable for and mimic xff */
		fwd->p_proto = 1; /* enable proto */
		goto out;
	}
	/* loop to go through optional arguments */
	while (*(args[cur_arg])) {
		if (strcmp(args[cur_arg], "proto") == 0) {
			fwd->p_proto = 1;
			cur_arg += 1;
		} else if (strcmp(args[cur_arg], "host") == 0) {
			fwd->p_host.mode = HTTP_7239_HOST_ORIG;
			cur_arg += 1;
		} else if (strcmp(args[cur_arg], "host-expr") == 0) {
			fwd->p_host.mode = HTTP_7239_HOST_SMP;
			err_code |= _proxy_http_parse_7239_expr(args, &cur_arg, file, linenum,
								&fwd->p_host.expr_s);
			if (err_code & ERR_CODE)
				goto out;
		} else if (strcmp(args[cur_arg], "by") == 0) {
			fwd->p_by.nn_mode = HTTP_7239_FORBY_ORIG;
			cur_arg += 1;
		} else if (strcmp(args[cur_arg], "by-expr") == 0) {
			fwd->p_by.nn_mode = HTTP_7239_FORBY_SMP;
			err_code |= _proxy_http_parse_7239_expr(args, &cur_arg, file, linenum,
								&fwd->p_by.nn_expr_s);
			if (err_code & ERR_CODE)
				goto out;
		} else if (strcmp(args[cur_arg], "for") == 0) {
			fwd->p_for.nn_mode = HTTP_7239_FORBY_ORIG;
			cur_arg += 1;
		} else if (strcmp(args[cur_arg], "for-expr") == 0) {
			fwd->p_for.nn_mode = HTTP_7239_FORBY_SMP;
			err_code |= _proxy_http_parse_7239_expr(args, &cur_arg, file, linenum,
								&fwd->p_for.nn_expr_s);
			if (err_code & ERR_CODE)
				goto out;
		} else if (strcmp(args[cur_arg], "by_port") == 0) {
			fwd->p_by.np_mode = HTTP_7239_FORBY_ORIG;
			cur_arg += 1;
		} else if (strcmp(args[cur_arg], "by_port-expr") == 0) {
			fwd->p_by.np_mode = HTTP_7239_FORBY_SMP;
			err_code |= _proxy_http_parse_7239_expr(args, &cur_arg, file, linenum,
								&fwd->p_by.np_expr_s);
			if (err_code & ERR_CODE)
				goto out;
		} else if (strcmp(args[cur_arg], "for_port") == 0) {
			fwd->p_for.np_mode = HTTP_7239_FORBY_ORIG;
			cur_arg += 1;
		} else if (strcmp(args[cur_arg], "for_port-expr") == 0) {
			fwd->p_for.np_mode = HTTP_7239_FORBY_SMP;
			err_code |= _proxy_http_parse_7239_expr(args, &cur_arg, file, linenum,
								&fwd->p_for.np_expr_s);
			if (err_code & ERR_CODE)
				goto out;
		} else {
			/* unknown suboption - catchall */
			ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'proto', 'host', "
				 "'host-expr', 'by', 'by-expr', 'by_port', 'by_port-expr', "
				 "'for', 'for-expr', 'for_port' and 'for_port-expr'.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	} /* end while loop */

	/* consistency check */
	if (fwd->p_by.np_mode &&
	    !fwd->p_by.nn_mode) {
		fwd->p_by.np_mode = 0;
		ha_free(&fwd->p_by.np_expr_s);
		ha_warning("parsing [%s:%d] : '%s %s' : '%s' will be ignored because both 'by' "
			   "and 'by-expr' are unset\n",
			   file, linenum, args[0], args[1],
			   ((fwd->p_by.np_mode == HTTP_7239_FORBY_ORIG) ? "by_port" : "by_port-expr"));
		err_code |= ERR_WARN;
	}
	if (fwd->p_for.np_mode &&
	    !fwd->p_for.nn_mode) {
		fwd->p_for.np_mode = 0;
		ha_free(&fwd->p_for.np_expr_s);
		ha_warning("parsing [%s:%d] : '%s %s' : '%s' will be ignored because both 'for' "
			   "and 'for-expr' are unset\n",
			   file, linenum, args[0], args[1],
			   ((fwd->p_for.np_mode == HTTP_7239_FORBY_ORIG) ? "for_port" : "for_port-expr"));
		err_code |= ERR_WARN;
	}

 out:
	return err_code;
}

/* rfc7239 forwarded option needs a postparsing step
 * to convert parsing hints into runtime usable sample expressions
 * Returns a composition of ERR_NONE, ERR_FATAL, ERR_ALERT, ERR_WARN
 */
int proxy_http_compile_7239(struct proxy *curproxy)
{
	struct http_ext_7239 *fwd;
	int err = ERR_NONE;
	int loop;

	if (!(curproxy->cap & PR_CAP_BE)) {
		/* no backend cap: not supported (ie: frontend) */
		goto out;
	}

	/* should not happen (test should be performed after BE cap test) */
	BUG_ON(!curproxy->http_ext || !curproxy->http_ext->fwd);

	curproxy->conf.args.ctx = ARGC_OPT; /* option */
	curproxy->conf.args.file = curproxy->http_ext->fwd->c_file;
	curproxy->conf.args.line = curproxy->http_ext->fwd->c_line;
	fwd = curproxy->http_ext->fwd;

	/* it is important that we keep iterating on error to make sure
	 * all fwd config fields are in the same state (post-parsing state)
	 */
	for (loop = 0; loop < 5; loop++) {
		char **expr_str = NULL;
		struct sample_expr **expr = NULL;
		struct sample_expr *cur_expr;
		char *err_str = NULL;
		int smp = 0;
		int idx = 0;

		switch (loop) {
			case 0:
				/* host */
				expr_str = &fwd->p_host.expr_s;
				expr = &fwd->p_host.expr;
				smp = (fwd->p_host.mode == HTTP_7239_HOST_SMP);
				break;
			case 1:
				/* by->node */
				expr_str = &fwd->p_by.nn_expr_s;
				expr = &fwd->p_by.nn_expr;
				smp = (fwd->p_by.nn_mode == HTTP_7239_FORBY_SMP);
				break;
			case 2:
				/* by->nodeport */
				expr_str = &fwd->p_by.np_expr_s;
				expr = &fwd->p_by.np_expr;
				smp = (fwd->p_by.np_mode == HTTP_7239_FORBY_SMP);
				break;
			case 3:
				/* for->node */
				expr_str = &fwd->p_for.nn_expr_s;
				expr = &fwd->p_for.nn_expr;
				smp = (fwd->p_for.nn_mode == HTTP_7239_FORBY_SMP);
				break;
			case 4:
				/* for->nodeport */
				expr_str = &fwd->p_for.np_expr_s;
				expr = &fwd->p_for.np_expr;
				smp = (fwd->p_for.np_mode == HTTP_7239_FORBY_SMP);
				break;
		}
		if (!smp)
			continue; /* no expr */

		/* expr and expr_str cannot be NULL past this point */
		BUG_ON(!expr || !expr_str);

		if (!*expr_str) {
			/* should not happen unless system memory exhaustion */
			ha_alert("%s '%s' [%s:%d]: failed to parse 'option forwarded' expression : %s.\n",
				 proxy_type_str(curproxy), curproxy->id,
				 fwd->c_file, fwd->c_line,
				 "memory error");
			err |= ERR_ALERT | ERR_FATAL;
			continue;
		}

		cur_expr =
			sample_parse_expr((char*[]){*expr_str, NULL}, &idx,
					  fwd->c_file,
					  fwd->c_line,
					  &err_str, &curproxy->conf.args, NULL);

		if (!cur_expr) {
			ha_alert("%s '%s' [%s:%d]: failed to parse 'option forwarded' expression '%s' in : %s.\n",
				 proxy_type_str(curproxy), curproxy->id,
				 fwd->c_file, fwd->c_line,
				 *expr_str, err_str);
			ha_free(&err_str);
			err |= ERR_ALERT | ERR_FATAL;
		}
		else if (!(cur_expr->fetch->val & SMP_VAL_BE_HRQ_HDR)) {
			/* fetch not available in this context: sample expr is resolved
			 * within backend right after headers are processed.
			 * (in http_process_request())
			 * -> we simply warn the user about the misuse
			 */
			ha_warning("%s '%s' [%s:%d]: in 'option forwarded' sample expression '%s' : "
				   "some args extract information from '%s', "
				   "none of which is available here.\n",
				   proxy_type_str(curproxy), curproxy->id,
				   fwd->c_file, fwd->c_line,
				   *expr_str, sample_ckp_names(cur_expr->fetch->use));
			err |= ERR_WARN;
		}
		/* post parsing individual expr cleanup */
		ha_free(expr_str);

		/* expr assignment */
		*expr = cur_expr;
	}
	curproxy->conf.args.file = NULL;
	curproxy->conf.args.line = 0;

	/* post parsing general cleanup */
	ha_free(&fwd->c_file);
	fwd->c_line = 0;

	fwd->c_mode = 1; /* parsing completed */

 out:
	return err;
}

/* x-forwarded-for: tries to parse "option forwardfor" config keyword
 * Returns a composition of ERR_NONE, ERR_FATAL, ERR_ALERT
 */
int proxy_http_parse_xff(char **args, int cur_arg,
                         struct proxy *curproxy, const struct proxy *defpx,
                         const char *file, int linenum)
{
	struct http_ext_xff *xff;
	int err_code = 0;

	if (!http_ext_xff_prepare(curproxy))
		return proxy_http_parse_oom(file, linenum);

	xff = curproxy->http_ext->xff;

	/* insert x-forwarded-for field, but not for the IP address listed as an except.
	 * set default options (ie: bitfield, header name, etc)
	 */

	xff->mode = HTTP_XFF_ALWAYS;

	istfree(&xff->hdr_name);
	xff->hdr_name = istdup(ist(DEF_XFORWARDFOR_HDR));
	if (!isttest(xff->hdr_name))
		return proxy_http_parse_oom(file, linenum);
	xff->except_net.family = AF_UNSPEC;

	/* loop to go through arguments - start at 2, since 0+1 = "option" "forwardfor" */
	cur_arg = 2;
	while (*(args[cur_arg])) {
		if (strcmp(args[cur_arg], "except") == 0) {
			unsigned char mask;
			int i;

			/* suboption except - needs additional argument for it */
			if (*(args[cur_arg+1]) &&
			    str2net(args[cur_arg+1], 1, &xff->except_net.addr.v4.ip, &xff->except_net.addr.v4.mask)) {
				xff->except_net.family = AF_INET;
				xff->except_net.addr.v4.ip.s_addr &= xff->except_net.addr.v4.mask.s_addr;
			}
			else if (*(args[cur_arg+1]) &&
				 str62net(args[cur_arg+1], &xff->except_net.addr.v6.ip, &mask)) {
				xff->except_net.family = AF_INET6;
				len2mask6(mask, &xff->except_net.addr.v6.mask);
				for (i = 0; i < 16; i++)
					xff->except_net.addr.v6.ip.s6_addr[i] &= xff->except_net.addr.v6.mask.s6_addr[i];
			}
			else {
				ha_alert("parsing [%s:%d] : '%s %s %s' expects <address>[/mask] as argument.\n",
					 file, linenum, args[0], args[1], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			/* flush useless bits */
			cur_arg += 2;
		} else if (strcmp(args[cur_arg], "header") == 0) {
			/* suboption header - needs additional argument for it */
			if (*(args[cur_arg+1]) == 0) {
				ha_alert("parsing [%s:%d] : '%s %s %s' expects <header_name> as argument.\n",
					 file, linenum, args[0], args[1], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			istfree(&xff->hdr_name);
			xff->hdr_name = istdup(ist(args[cur_arg+1]));
			if (!isttest(xff->hdr_name))
				return proxy_http_parse_oom(file, linenum);
			cur_arg += 2;
		} else if (strcmp(args[cur_arg], "if-none") == 0) {
			xff->mode = HTTP_XFF_IFNONE;
			cur_arg += 1;
		} else {
			/* unknown suboption - catchall */
			ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'except', 'header' and 'if-none'.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	} /* end while loop */
 out:
	return err_code;
}

/* x-original-to: tries to parse "option originalto" config keyword
 * Returns a composition of ERR_NONE, ERR_FATAL, ERR_ALERT
 */
int proxy_http_parse_xot(char **args, int cur_arg,
                         struct proxy *curproxy, const struct proxy *defpx,
                         const char *file, int linenum)
{
	struct http_ext_xot *xot;
	int err_code = 0;

	if (!http_ext_xot_prepare(curproxy))
		return proxy_http_parse_oom(file, linenum);

	xot = curproxy->http_ext->xot;

	/* insert x-original-to field, but not for the IP address listed as an except.
	 * set default options (ie: bitfield, header name, etc)
	 */

	istfree(&xot->hdr_name);
	xot->hdr_name = istdup(ist(DEF_XORIGINALTO_HDR));
	if (!isttest(xot->hdr_name))
		return proxy_http_parse_oom(file, linenum);
	xot->except_net.family = AF_UNSPEC;

	/* loop to go through arguments - start at 2, since 0+1 = "option" "originalto" */
	cur_arg = 2;
	while (*(args[cur_arg])) {
		if (strcmp(args[cur_arg], "except") == 0) {
			unsigned char mask;
			int i;

			/* suboption except - needs additional argument for it */
			if (*(args[cur_arg+1]) &&
			    str2net(args[cur_arg+1], 1, &xot->except_net.addr.v4.ip, &xot->except_net.addr.v4.mask)) {
				xot->except_net.family = AF_INET;
				xot->except_net.addr.v4.ip.s_addr &= xot->except_net.addr.v4.mask.s_addr;
			}
			else if (*(args[cur_arg+1]) &&
				 str62net(args[cur_arg+1], &xot->except_net.addr.v6.ip, &mask)) {
				xot->except_net.family = AF_INET6;
				len2mask6(mask, &xot->except_net.addr.v6.mask);
				for (i = 0; i < 16; i++)
					xot->except_net.addr.v6.ip.s6_addr[i] &= xot->except_net.addr.v6.mask.s6_addr[i];
			}
			else {
				ha_alert("parsing [%s:%d] : '%s %s %s' expects <address>[/mask] as argument.\n",
					 file, linenum, args[0], args[1], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			cur_arg += 2;
		} else if (strcmp(args[cur_arg], "header") == 0) {
			/* suboption header - needs additional argument for it */
			if (*(args[cur_arg+1]) == 0) {
				ha_alert("parsing [%s:%d] : '%s %s %s' expects <header_name> as argument.\n",
					 file, linenum, args[0], args[1], args[cur_arg]);
				err_code |= ERR_ALERT | ERR_FATAL;
				goto out;
			}
			istfree(&xot->hdr_name);
			xot->hdr_name = istdup(ist(args[cur_arg+1]));
			if (!isttest(xot->hdr_name))
				return proxy_http_parse_oom(file, linenum);
			cur_arg += 2;
		} else {
			/* unknown suboption - catchall */
			ha_alert("parsing [%s:%d] : '%s %s' only supports optional values: 'except' and 'header'.\n",
				 file, linenum, args[0], args[1]);
			err_code |= ERR_ALERT | ERR_FATAL;
			goto out;
		}
	} /* end while loop */

 out:
	return err_code;
}

/*
 * =========== MGMT ===========
 * below are helpers to manage http ext options
 */

/* Ensure http_ext->fwd is properly allocated and
 * initialized for <curproxy>.
 * The function will leverage http_ext_prepare() to make
 * sure http_ext is properly allocated and initialized as well.
 * Returns 1 for success and 0 for failure (memory error)
 */
int http_ext_7239_prepare(struct proxy *curproxy)
{
	struct http_ext_7239 *fwd;

	if (!http_ext_prepare(curproxy))
		return 0;
	if (curproxy->http_ext->fwd)
		return 1; /* nothing to do */

	fwd = malloc(sizeof(*fwd));
	if (!fwd)
		return 0;
	/* initialize fwd mandatory fields */
	fwd->c_mode = 0; /* pre-compile (parse) time */
	fwd->c_file = NULL;
	fwd->p_host.expr_s = NULL;
	fwd->p_by.nn_expr_s = NULL;
	fwd->p_by.np_expr_s = NULL;
	fwd->p_for.nn_expr_s = NULL;
	fwd->p_for.np_expr_s = NULL;
	/* assign */
	curproxy->http_ext->fwd = fwd;
	return 1;
}

/* Ensure http_ext->xff is properly allocated and
 * initialized for <curproxy>.
 * The function will leverage http_ext_prepare() to make
 * sure http_ext is properly allocated and initialized as well.
 * Returns 1 for success and 0 for failure (memory error)
 */
int http_ext_xff_prepare(struct proxy *curproxy)
{
	struct http_ext_xff *xff;

	if (!http_ext_prepare(curproxy))
		return 0;
	if (curproxy->http_ext->xff)
		return 1; /* nothing to do */

	xff = malloc(sizeof(*xff));
	if (!xff)
		return 0;
	/* initialize xff mandatory fields */
	xff->hdr_name = IST_NULL;
	/* assign */
	curproxy->http_ext->xff = xff;
	return 1;
}

/* Ensure http_ext->xot is properly allocated and
 * initialized for <curproxy>.
 * The function will leverage http_ext_prepare() to make
 * sure http_ext is properly allocated and initialized as well.
 * Returns 1 for success and 0 for failure (memory error)
 */
int http_ext_xot_prepare(struct proxy *curproxy)
{
	struct http_ext_xot *xot;

	if (!http_ext_prepare(curproxy))
		return 0;
	if (curproxy->http_ext->xot)
		return 1; /* nothing to do */

	xot = malloc(sizeof(*xot));
	if (!xot)
		return 0;
	/* initialize xot mandatory fields */
	xot->hdr_name = IST_NULL;
	/* assign */
	curproxy->http_ext->xot = xot;
	return 1;
}

/* deep clean http_ext->fwd parameter for <curproxy>
 * http_ext->fwd will be freed
 * clean behavior will differ depending on http_ext->fwd
 * state. If fwd is in 'parsed' state, parsing hints will be
 * cleaned. Else, it means fwd is in 'compiled' state, in this
 * case we're cleaning compiled results.
 * This is because parse and compile memory areas are shared in
 * a single union to optimize struct http_ext_7239 size.
 */
void http_ext_7239_clean(struct proxy *curproxy)
{
	struct http_ext_7239 *clean;

	if (!curproxy->http_ext)
		return;
	clean = curproxy->http_ext->fwd;
	if (!clean)
		return; /* nothing to do */
	if (!clean->c_mode) {
		/* parsed */
		ha_free(&clean->c_file);
		ha_free(&clean->p_host.expr_s);
		ha_free(&clean->p_by.nn_expr_s);
		ha_free(&clean->p_by.np_expr_s);
		ha_free(&clean->p_for.nn_expr_s);
		ha_free(&clean->p_for.np_expr_s);
	}
	else {
		/* compiled */
		release_sample_expr(clean->p_host.expr);
		clean->p_host.expr = NULL;
		release_sample_expr(clean->p_by.nn_expr);
		clean->p_by.nn_expr = NULL;
		release_sample_expr(clean->p_by.np_expr);
		clean->p_by.np_expr = NULL;
		release_sample_expr(clean->p_for.nn_expr);
		clean->p_for.nn_expr = NULL;
		release_sample_expr(clean->p_for.np_expr);
		clean->p_for.np_expr = NULL;
	}
	/* free fwd */
	ha_free(&curproxy->http_ext->fwd);
}

/* deep clean http_ext->xff parameter for <curproxy>
 * http_ext->xff will be freed
 */
void http_ext_xff_clean(struct proxy *curproxy)
{
	struct http_ext_xff *clean;

	if (!curproxy->http_ext)
		return;
	clean = curproxy->http_ext->xff;
	if (!clean)
		return; /* nothing to do */
	istfree(&clean->hdr_name);
	/* free xff */
	ha_free(&curproxy->http_ext->xff);
}

/* deep clean http_ext->xot parameter for <curproxy>
 * http_ext->xot will be freed
 */
void http_ext_xot_clean(struct proxy *curproxy)
{
	struct http_ext_xot *clean;

	if (!curproxy->http_ext)
		return;
	clean = curproxy->http_ext->xot;
	if (!clean)
		return; /* nothing to do */
	istfree(&clean->hdr_name);
	/* free xot */
	ha_free(&curproxy->http_ext->xot);
}

/* duplicate http_ext->fwd parameters from <def> to <cpy>
 * performs the required memory allocation and initialization
 */
void http_ext_7239_dup(const struct proxy *def, struct proxy *cpy)
{
	struct http_ext_7239 *dest = NULL;
	struct http_ext_7239 *orig = NULL;

	/* feature requires backend cap */
	if (!(cpy->cap & PR_CAP_BE))
		return;

	if (def->http_ext == NULL || def->http_ext->fwd == NULL)
		return;

	orig = def->http_ext->fwd;

	if (orig->c_mode)
		return; /* copy not supported once compiled */

	if (!http_ext_7239_prepare(cpy))
		return;

	dest = cpy->http_ext->fwd;

	if (orig->c_file)
		dest->c_file = strdup(orig->c_file);
	dest->c_line = orig->c_line;
	/* proto */
	dest->p_proto = orig->p_proto;
	/* host */
	dest->p_host.mode = orig->p_host.mode;
	if (orig->p_host.expr_s)
		dest->p_host.expr_s = strdup(orig->p_host.expr_s);
	/* by - nodename */
	dest->p_by.nn_mode = orig->p_by.nn_mode;
	if (orig->p_by.nn_expr_s)
		dest->p_by.nn_expr_s = strdup(orig->p_by.nn_expr_s);
	/* by - nodeport */
	dest->p_by.np_mode = orig->p_by.np_mode;
	if (orig->p_by.np_expr_s)
		dest->p_by.np_expr_s = strdup(orig->p_by.np_expr_s);
	/* for - nodename */
	dest->p_for.nn_mode = orig->p_for.nn_mode;
	if (orig->p_for.nn_expr_s)
		dest->p_for.nn_expr_s = strdup(orig->p_for.nn_expr_s);
	/* for - nodeport */
	dest->p_for.np_mode = orig->p_for.np_mode;
	if (orig->p_for.np_expr_s)
		dest->p_for.np_expr_s = strdup(orig->p_for.np_expr_s);
}

/* duplicate http_ext->xff parameters from <def> to <cpy>
 * performs the required memory allocation and initialization
 */
void http_ext_xff_dup(const struct proxy *def, struct proxy *cpy)
{
	struct http_ext_xff *dest = NULL;
	struct http_ext_xff *orig = NULL;

	if (def->http_ext == NULL || def->http_ext->xff == NULL ||
	    !http_ext_xff_prepare(cpy))
		return;

	orig = def->http_ext->xff;
	dest = cpy->http_ext->xff;

	if (isttest(orig->hdr_name))
		dest->hdr_name = istdup(orig->hdr_name);
	dest->mode = orig->mode;
	dest->except_net = orig->except_net;
}

/* duplicate http_ext->xot parameters from <def> to <cpy>
 * performs the required memory allocation and initialization
 */
void http_ext_xot_dup(const struct proxy *def, struct proxy *cpy)
{
	struct http_ext_xot *dest = NULL;
	struct http_ext_xot *orig = NULL;

	if (def->http_ext == NULL || def->http_ext->xot == NULL ||
	    !http_ext_xot_prepare(cpy))
		return;

	orig = def->http_ext->xot;
	dest = cpy->http_ext->xot;

	if (isttest(orig->hdr_name))
		dest->hdr_name = istdup(orig->hdr_name);
	dest->except_net = orig->except_net;
}

/* Allocate new http_ext and initialize it
 * if needed
 * Returns 1 for success and 0 for failure
 */
int http_ext_prepare(struct proxy *curproxy)
{
	if (curproxy->http_ext)
		return 1; /* nothing to do */

	curproxy->http_ext = malloc(sizeof(*curproxy->http_ext));
	if (!curproxy->http_ext)
		return 0; /* failure */
	/* first init, set supported ext to NULL */
	curproxy->http_ext->fwd = NULL;
	curproxy->http_ext->xff = NULL;
	curproxy->http_ext->xot = NULL;
	return 1;
}

/* duplicate existing http_ext from <defproxy> to <curproxy>
 */
void http_ext_dup(const struct proxy *defproxy, struct proxy *curproxy)
{
	/* copy defproxy.http_ext members */
	http_ext_7239_dup(defproxy, curproxy);
	http_ext_xff_dup(defproxy, curproxy);
	http_ext_xot_dup(defproxy, curproxy);
}

/* deep clean http_ext for <curproxy> (if previously allocated)
 */
void http_ext_clean(struct proxy *curproxy)
{
	if (!curproxy->http_ext)
		return; /* nothing to do */
	/* first, free supported ext */
	http_ext_7239_clean(curproxy);
	http_ext_xff_clean(curproxy);
	http_ext_xot_clean(curproxy);

	/* then, free http_ext */
	ha_free(&curproxy->http_ext);
}

/* soft clean (only clean http_ext if no more options are used) */
void http_ext_softclean(struct proxy *curproxy)
{
	if (!curproxy->http_ext)
		return; /* nothing to do */
	if (!curproxy->http_ext->fwd &&
	    !curproxy->http_ext->xff &&
	    !curproxy->http_ext->xot) {
		/* no more use for http_ext, all options are disabled */
		http_ext_clean(curproxy);
	}
}

/* Perform some consistency checks on px.http_ext after parsing
 * is completed.
 * We make sure to perform a softclean in case some options were
 * to be disabled in this check. This way we can release some memory.
 * Returns a composition of ERR_NONE, ERR_ALERT, ERR_FATAL, ERR_WARN
 */
static int check_http_ext_postconf(struct proxy *px) {
	int err = ERR_NONE;

	if (px->http_ext) {
		/* consistency check for http_ext */
		if (px->mode != PR_MODE_HTTP && !(px->options & PR_O_HTTP_UPG)) {
			/* http is disabled on px, yet it is required by http_ext */
			if (px->http_ext->fwd) {
				ha_warning("'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					   "forwarded", proxy_type_str(px), px->id);
				err |= ERR_WARN;
				http_ext_7239_clean(px);
			}
			if (px->http_ext->xff) {
				ha_warning("'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					   "forwardfor", proxy_type_str(px), px->id);
				err |= ERR_WARN;
				http_ext_xff_clean(px);
			}
			if (px->http_ext->xot) {
				ha_warning("'option %s' ignored for %s '%s' as it requires HTTP mode.\n",
					   "originalto", proxy_type_str(px), px->id);
				err |= ERR_WARN;
				http_ext_xot_clean(px);
			}
		} else if (px->http_ext->fwd) {
			/* option "forwarded" may need to compile its expressions */
			err |= proxy_http_compile_7239(px);
		}
		/* http_ext post init early cleanup */
		http_ext_softclean(px);

	}
	return err;
}

REGISTER_POST_PROXY_CHECK(check_http_ext_postconf);
/*
 * =========== CONV ===========
 * related converters
 */

/* input: string representing 7239 forwarded header single value
 * does not take arguments
 * output: 1 if header is RFC compliant, 0 otherwise
 */
static int sample_conv_7239_valid(const struct arg *args, struct sample *smp, void *private)
{
	struct ist input = ist2(smp->data.u.str.area, smp->data.u.str.data);

	smp->data.type = SMP_T_BOOL;
	smp->data.u.sint = !!http_validate_7239_header(input, FORWARDED_HEADER_ALL, NULL);
	return 1;
}

/* input: string representing 7239 forwarded header single value
 * argument: parameter name to look for in the header
 * output: header parameter raw value, as a string
 */
static int sample_conv_7239_field(const struct arg *args, struct sample *smp, void *private)
{
	struct ist input = ist2(smp->data.u.str.area, smp->data.u.str.data);
	struct buffer *output;
	struct forwarded_header_ctx ctx;
	int validate;
	int field = 0;

	if (strcmp(args->data.str.area, "proto") == 0)
		field = FORWARDED_HEADER_PROTO;
	else if (strcmp(args->data.str.area, "host") == 0)
		field = FORWARDED_HEADER_HOST;
	else if (strcmp(args->data.str.area, "for") == 0)
		field = FORWARDED_HEADER_FOR;
	else if (strcmp(args->data.str.area, "by") == 0)
		field = FORWARDED_HEADER_BY;

	validate = http_validate_7239_header(input, FORWARDED_HEADER_ALL, &ctx);
	if (!(validate & field))
		return 0; /* invalid header or header does not contain field */
	output = get_trash_chunk();
	switch (field) {
		case FORWARDED_HEADER_PROTO:
			if (ctx.proto == FORWARDED_HEADER_HTTP)
				chunk_appendf(output, "http");
			else if (ctx.proto == FORWARDED_HEADER_HTTPS)
				chunk_appendf(output, "https");
			break;
		case FORWARDED_HEADER_HOST:
			chunk_istcat(output, ctx.host);
			break;
		case FORWARDED_HEADER_FOR:
			chunk_istcat(output, ctx.nfor.raw);
			break;
		case FORWARDED_HEADER_BY:
			chunk_istcat(output, ctx.nby.raw);
			break;
		default:
			break;
	}
	smp->flags &= ~SMP_F_CONST;
	smp->data.type = SMP_T_STR;
	smp->data.u.str = *output;
	return 1;
}

/* input: substring representing 7239 forwarded header node
 * output: forwarded header nodename translated to either
 * ipv4 address, ipv6 address or str
 * ('_' prefix if obfuscated, or "unknown" if unknown)
 */
static int sample_conv_7239_n2nn(const struct arg *args, struct sample *smp, void *private)
{
	struct ist input = ist2(smp->data.u.str.area, smp->data.u.str.data);
	struct forwarded_header_node ctx;
	struct buffer *output;

	if (http_7239_extract_node(&input, &ctx, 1) == 0)
		return 0; /* could not extract node */
	switch (ctx.nodename.type) {
		case FORWARDED_HEADER_UNK:
			output = get_trash_chunk();
			chunk_appendf(output, "unknown");
			smp->flags &= ~SMP_F_CONST;
			smp->data.type = SMP_T_STR;
			smp->data.u.str = *output;
			break;
		case FORWARDED_HEADER_OBFS:
			output = get_trash_chunk();
			chunk_appendf(output, "_"); /* append obfs prefix */
			chunk_istcat(output, ctx.nodename.obfs);
			smp->flags &= ~SMP_F_CONST;
			smp->data.type = SMP_T_STR;
			smp->data.u.str = *output;
			break;
		case FORWARDED_HEADER_IP:
			if (ctx.nodename.ip.ss_family == AF_INET) {
				smp->data.type = SMP_T_IPV4;
				smp->data.u.ipv4 = ((struct sockaddr_in *)&ctx.nodename.ip)->sin_addr;
			}
			else if (ctx.nodename.ip.ss_family == AF_INET6) {
				smp->data.type = SMP_T_IPV6;
				smp->data.u.ipv6 = ((struct sockaddr_in6 *)&ctx.nodename.ip)->sin6_addr;
			}
			else
				return 0; /* unsupported */
			break;
		default:
			return 0; /* unsupported */
	}
	return 1;
}

/* input: substring representing 7239 forwarded header node
 * output: forwarded header nodeport translated to either
 * integer or str for obfuscated ('_' prefix)
 */
static int sample_conv_7239_n2np(const struct arg *args, struct sample *smp, void *private)
{
	struct ist input = ist2(smp->data.u.str.area, smp->data.u.str.data);
	struct forwarded_header_node ctx;
	struct buffer *output;

	if (http_7239_extract_node(&input, &ctx, 1) == 0)
		return 0; /* could not extract node */

	switch (ctx.nodeport.type) {
		case FORWARDED_HEADER_UNK:
			return 0; /* not provided */
		case FORWARDED_HEADER_OBFS:
			output = get_trash_chunk();
			chunk_appendf(output, "_"); /* append obfs prefix */
			chunk_istcat(output, ctx.nodeport.obfs);
			smp->flags &= ~SMP_F_CONST;
			smp->data.type = SMP_T_STR;
			smp->data.u.str = *output;
			break;
		case FORWARDED_HEADER_PORT:
			smp->data.type = SMP_T_SINT;
			smp->data.u.sint = ctx.nodeport.port;
			break;
		default:
			return 0; /* unsupported */
	}

	return 1;
}

/*
 * input: ipv4 address, ipv6 address or str (empty string will result in
 * "unknown" indentifier, else string will be translated to _obfs
 * indentifier, prefixed by '_'. Must comply with RFC7239 charset)
 *
 * output: rfc7239-compliant forwarded header nodename
 */
static int sample_conv_7239_nn(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();

	switch (smp->data.type) {
		case SMP_T_IPV4:
		{
			unsigned char *pn = (unsigned char *)&(smp->data.u.ipv4);

			chunk_printf(trash, "%d.%d.%d.%d", pn[0], pn[1], pn[2], pn[3]);
			break;
		}
		case SMP_T_IPV6:
			_7239_print_ip6(trash, &smp->data.u.ipv6, 1);
			break;
		case SMP_T_STR:
 case_str:
		{
			struct ist validate_n = ist2(smp->data.u.str.area, smp->data.u.str.data);

			if (!istlen(validate_n)) {
				// empty -> unknown
				chunk_printf(trash, "unknown");
				break;
			}

			if (!(http_7239_extract_obfs(&validate_n, NULL) && !istlen(validate_n)))
				return 0; /* invalid input */
			// output with '_' prefix
			chunk_printf(trash, "_%.*s", (int)smp->data.u.str.data, smp->data.u.str.area);
			break;
		}
		default:
		{
			if (sample_casts[smp->data.type][SMP_T_STR] &&
                            sample_casts[smp->data.type][SMP_T_STR](smp))
				goto case_str;
			return 0; /* unexpected */
		}

	}

	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;

	return 1;
}

/*
 * input: unsigned integer or str (string will be translated to _obfs
 * indentifier, prefixed by '_'. Must comply with RFC7239 charset)
 *
 * output: rfc7239-compliant forwarded header nodeport
 */
static int sample_conv_7239_np(const struct arg *args, struct sample *smp, void *private)
{
	struct buffer *trash = get_trash_chunk();

	switch (smp->data.type) {
		case SMP_T_SINT:
		{
			chunk_printf(trash, "%u", (unsigned int)smp->data.u.sint);
			break;
		}
		case SMP_T_STR:
 case_str:
		{
			struct ist validate_n = ist2(smp->data.u.str.area, smp->data.u.str.data);

			if (!istlen(validate_n))
				return 0;

			if (!(http_7239_extract_obfs(&validate_n, NULL) && !istlen(validate_n)))
				return 0; /* invalid input */
			// output with '_' prefix
			chunk_printf(trash, "_%.*s", (int)smp->data.u.str.data, smp->data.u.str.area);
			break;
		}
		default:
		{
			if (sample_casts[smp->data.type][SMP_T_STR] &&
                            sample_casts[smp->data.type][SMP_T_STR](smp))
				goto case_str;
			return 0; /* unexpected */
		}

	}

	smp->data.u.str = *trash;
	smp->data.type = SMP_T_STR;
	smp->flags &= ~SMP_F_CONST;

	return 1;

}

/* Note: must not be declared <const> as its list will be overwritten */
static struct sample_conv_kw_list sample_conv_kws = {ILH, {
	{ "rfc7239_is_valid",  sample_conv_7239_valid,   0,                NULL,   SMP_T_STR,  SMP_T_BOOL},
	{ "rfc7239_field",     sample_conv_7239_field,   ARG1(1,STR),      NULL,   SMP_T_STR,  SMP_T_STR},
	{ "rfc7239_n2nn",      sample_conv_7239_n2nn,    0,                NULL,   SMP_T_STR,  SMP_T_ANY},
	{ "rfc7239_n2np",      sample_conv_7239_n2np,    0,                NULL,   SMP_T_STR,  SMP_T_ANY},
	{ "rfc7239_nn",        sample_conv_7239_nn,      0,                NULL,   SMP_T_ANY,  SMP_T_STR},
	{ "rfc7239_np",        sample_conv_7239_np,      0,                NULL,   SMP_T_ANY,  SMP_T_STR},
	{ NULL, NULL, 0, 0, 0 },
}};

INITCALL1(STG_REGISTER, sample_register_convs, &sample_conv_kws);
