/*
 * ACL management functions.
 *
 * Copyright 2000-2011 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <common/config.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/uri_auth.h>

#include <types/global.h>

#include <proto/acl.h>
#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/buffers.h>
#include <proto/log.h>
#include <proto/proxy.h>

#include <ebsttree.h>

/* The capabilities of filtering hooks describe the type of information
 * available to each of them.
 */
const unsigned int filt_cap[] = {
	[ACL_HOOK_REQ_FE_TCP]         = ACL_USE_TCP4_ANY|ACL_USE_TCP6_ANY|ACL_USE_TCP_ANY,
	[ACL_HOOK_REQ_FE_TCP_CONTENT] = ACL_USE_TCP4_ANY|ACL_USE_TCP6_ANY|ACL_USE_TCP_ANY|ACL_USE_L6REQ_ANY,
	[ACL_HOOK_REQ_FE_HTTP_IN]     = ACL_USE_TCP4_ANY|ACL_USE_TCP6_ANY|ACL_USE_TCP_ANY|ACL_USE_L6REQ_ANY|ACL_USE_L7REQ_ANY|ACL_USE_HDR_ANY,
	[ACL_HOOK_REQ_FE_SWITCH]      = ACL_USE_TCP4_ANY|ACL_USE_TCP6_ANY|ACL_USE_TCP_ANY|ACL_USE_L6REQ_ANY|ACL_USE_L7REQ_ANY|ACL_USE_HDR_ANY,
	[ACL_HOOK_REQ_BE_TCP_CONTENT] = ACL_USE_TCP4_ANY|ACL_USE_TCP6_ANY|ACL_USE_TCP_ANY|ACL_USE_L6REQ_ANY|ACL_USE_L7REQ_ANY|ACL_USE_HDR_ANY,
	[ACL_HOOK_REQ_BE_HTTP_IN]     = ACL_USE_TCP4_ANY|ACL_USE_TCP6_ANY|ACL_USE_TCP_ANY|ACL_USE_L6REQ_ANY|ACL_USE_L7REQ_ANY|ACL_USE_HDR_ANY,
	[ACL_HOOK_REQ_BE_SWITCH]      = ACL_USE_TCP4_ANY|ACL_USE_TCP6_ANY|ACL_USE_TCP_ANY|ACL_USE_L6REQ_ANY|ACL_USE_L7REQ_ANY|ACL_USE_HDR_ANY,
	[ACL_HOOK_REQ_FE_HTTP_OUT]    = ACL_USE_TCP4_ANY|ACL_USE_TCP6_ANY|ACL_USE_TCP_ANY|ACL_USE_L6REQ_ANY|ACL_USE_L7REQ_ANY|ACL_USE_HDR_ANY,
	[ACL_HOOK_REQ_BE_HTTP_OUT]    = ACL_USE_TCP4_ANY|ACL_USE_TCP6_ANY|ACL_USE_TCP_ANY|ACL_USE_L6REQ_ANY|ACL_USE_L7REQ_ANY|ACL_USE_HDR_ANY,

	[ACL_HOOK_RTR_BE_TCP_CONTENT] = ACL_USE_REQ_PERMANENT|ACL_USE_REQ_CACHEABLE|ACL_USE_L6RTR_ANY,
	[ACL_HOOK_RTR_BE_HTTP_IN]     = ACL_USE_REQ_PERMANENT|ACL_USE_REQ_CACHEABLE|ACL_USE_L6RTR_ANY|ACL_USE_L7RTR_ANY,
	[ACL_HOOK_RTR_FE_TCP_CONTENT] = ACL_USE_REQ_PERMANENT|ACL_USE_REQ_CACHEABLE|ACL_USE_L6RTR_ANY|ACL_USE_L7RTR_ANY,
	[ACL_HOOK_RTR_FE_HTTP_IN]     = ACL_USE_REQ_PERMANENT|ACL_USE_REQ_CACHEABLE|ACL_USE_L6RTR_ANY|ACL_USE_L7RTR_ANY,
	[ACL_HOOK_RTR_BE_HTTP_OUT]    = ACL_USE_REQ_PERMANENT|ACL_USE_REQ_CACHEABLE|ACL_USE_L6RTR_ANY|ACL_USE_L7RTR_ANY,
	[ACL_HOOK_RTR_FE_HTTP_OUT]    = ACL_USE_REQ_PERMANENT|ACL_USE_REQ_CACHEABLE|ACL_USE_L6RTR_ANY|ACL_USE_L7RTR_ANY,
};

/* List head of all known ACL keywords */
static struct acl_kw_list acl_keywords = {
	.list = LIST_HEAD_INIT(acl_keywords.list)
};


/*
 * These functions are only used for debugging complex configurations.
 */

/* force TRUE to be returned at the fetch level */
static int
acl_fetch_true(struct proxy *px, struct session *l4, void *l7, int dir,
	       struct acl_expr *expr, struct acl_test *test)
{
	test->flags |= ACL_TEST_F_SET_RES_PASS;
	return 1;
}

/* wait for more data as long as possible, then return TRUE. This should be
 * used with content inspection.
 */
static int
acl_fetch_wait_end(struct proxy *px, struct session *l4, void *l7, int dir,
		   struct acl_expr *expr, struct acl_test *test)
{
	if (dir & ACL_PARTIAL) {
		test->flags |= ACL_TEST_F_MAY_CHANGE;
		return 0;
	}
	test->flags |= ACL_TEST_F_SET_RES_PASS;
	return 1;
}

/* force FALSE to be returned at the fetch level */
static int
acl_fetch_false(struct proxy *px, struct session *l4, void *l7, int dir,
		struct acl_expr *expr, struct acl_test *test)
{
	test->flags |= ACL_TEST_F_SET_RES_FAIL;
	return 1;
}

/* return the number of bytes in the request buffer */
static int
acl_fetch_req_len(struct proxy *px, struct session *l4, void *l7, int dir,
		  struct acl_expr *expr, struct acl_test *test)
{
	if (!l4 || !l4->req)
		return 0;

	temp_pattern.data.integer = l4->req->i;
	test->flags = ACL_TEST_F_VOLATILE | ACL_TEST_F_MAY_CHANGE;
	return 1;
}


static int
acl_fetch_ssl_hello_type(struct proxy *px, struct session *l4, void *l7, int dir,
			 struct acl_expr *expr, struct acl_test *test)
{
	int hs_len;
	int hs_type, bleft;
	struct buffer *b;
	const unsigned char *data;

	if (!l4)
		goto not_ssl_hello;

	b = ((dir & ACL_DIR_MASK) == ACL_DIR_RTR) ? l4->rep : l4->req;

	bleft = b->i;
	data = (const unsigned char *)b->p;

	if (!bleft)
		goto too_short;

	if ((*data >= 0x14 && *data <= 0x17) || (*data == 0xFF)) {
		/* SSLv3 header format */
		if (bleft < 9)
			goto too_short;

		/* ssl version 3 */
		if ((data[1] << 16) + data[2] < 0x00030000)
			goto not_ssl_hello;

		/* ssl message len must present handshake type and len */
		if ((data[3] << 8) + data[4] < 4)
			goto not_ssl_hello;

		/* format introduced with SSLv3 */

		hs_type = (int)data[5];
		hs_len = ( data[6] << 16 ) + ( data[7] << 8 ) + data[8];

		/* not a full handshake */
		if (bleft < (9 + hs_len))
			goto too_short;

	}
	else {
		goto not_ssl_hello;
	}

	temp_pattern.data.integer = hs_type;
	test->flags = ACL_TEST_F_VOLATILE;

	return 1;

 too_short:
	test->flags = ACL_TEST_F_MAY_CHANGE;

 not_ssl_hello:

	return 0;
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
	bleft = l4->req->i;
	if (!bleft)
		goto too_short;

	data = (const unsigned char *)l4->req->p;
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
	if (msg_len > buffer_max_len(l4->req) + l4->req->data - l4->req->p)
		msg_len = buffer_max_len(l4->req) + l4->req->data - l4->req->p;

	if (bleft < msg_len)
		goto too_short;

	/* OK that's enough. We have at least the whole message, and we have
	 * the protocol version.
	 */
	temp_pattern.data.integer = version;
	test->flags = ACL_TEST_F_VOLATILE;
	return 1;

 too_short:
	test->flags = ACL_TEST_F_MAY_CHANGE;
 not_ssl:
	return 0;
}

/* Try to extract the Server Name Indication that may be presented in a TLS
 * client hello handshake message. The format of the message is the following
 * (cf RFC5246 + RFC6066) :
 * TLS frame :
 *   - uint8  type                            = 0x16   (Handshake)
 *   - uint16 version                        >= 0x0301 (TLSv1)
 *   - uint16 length                                   (frame length)
 *   - TLS handshake :
 *     - uint8  msg_type                      = 0x01   (ClientHello)
 *     - uint24 length                                 (handshake message length)
 *     - ClientHello :
 *       - uint16 client_version             >= 0x0301 (TLSv1)
 *       - uint8 Random[32]                  (4 first ones are timestamp)
 *       - SessionID :
 *         - uint8 session_id_len (0..32)              (SessionID len in bytes)
 *         - uint8 session_id[session_id_len]
 *       - CipherSuite :
 *         - uint16 cipher_len               >= 2      (Cipher length in bytes)
 *         - uint16 ciphers[cipher_len/2]
 *       - CompressionMethod :
 *         - uint8 compression_len           >= 1      (# of supported methods)
 *         - uint8 compression_methods[compression_len]
 *       - optional client_extension_len               (in bytes)
 *       - optional sequence of ClientHelloExtensions  (as many bytes as above):
 *         - uint16 extension_type            = 0 for server_name
 *         - uint16 extension_len
 *         - opaque extension_data[extension_len]
 *           - uint16 server_name_list_len             (# of bytes here)
 *           - opaque server_names[server_name_list_len bytes]
 *             - uint8 name_type              = 0 for host_name
 *             - uint16 name_len
 *             - opaque hostname[name_len bytes]
 */
static int
acl_fetch_ssl_hello_sni(struct proxy *px, struct session *l4, void *l7, int dir,
			struct acl_expr *expr, struct acl_test *test)
{
	int hs_len, ext_len, bleft;
	struct buffer *b;
	unsigned char *data;

	if (!l4)
		goto not_ssl_hello;

	b = ((dir & ACL_DIR_MASK) == ACL_DIR_RTR) ? l4->rep : l4->req;

	bleft = b->i;
	data = (unsigned char *)b->p;

	/* Check for SSL/TLS Handshake */
	if (!bleft)
		goto too_short;
	if (*data != 0x16)
		goto not_ssl_hello;

	/* Check for TLSv1 or later (SSL version >= 3.1) */
	if (bleft < 3)
		goto too_short;
	if (data[1] < 0x03 || data[2] < 0x01)
		goto not_ssl_hello;

	if (bleft < 5)
		goto too_short;
	hs_len = (data[3] << 8) + data[4];
	if (hs_len < 1 + 3 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 2)
		goto not_ssl_hello; /* too short to have an extension */

	data += 5; /* enter TLS handshake */
	bleft -= 5;

	/* Check for a complete client hello starting at <data> */
	if (bleft < 1)
		goto too_short;
	if (data[0] != 0x01) /* msg_type = Client Hello */
		goto not_ssl_hello;

	/* Check the Hello's length */
	if (bleft < 4)
		goto too_short;
	hs_len = (data[1] << 16) + (data[2] << 8) + data[3];
	if (hs_len < 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 2)
		goto not_ssl_hello; /* too short to have an extension */

	/* We want the full handshake here */
	if (bleft < hs_len)
		goto too_short;

	data += 4;
	/* Start of the ClientHello message */
	if (data[0] < 0x03 || data[1] < 0x01) /* TLSv1 minimum */
		goto not_ssl_hello;

	ext_len = data[34]; /* session_id_len */
	if (ext_len > 32 || ext_len > (hs_len - 35)) /* check for correct session_id len */
		goto not_ssl_hello;

	/* Jump to cipher suite */
	hs_len -= 35 + ext_len;
	data   += 35 + ext_len;

	if (hs_len < 4 ||                               /* minimum one cipher */
	    (ext_len = (data[0] << 8) + data[1]) < 2 || /* minimum 2 bytes for a cipher */
	    ext_len > hs_len)
		goto not_ssl_hello;

	/* Jump to the compression methods */
	hs_len -= 2 + ext_len;
	data   += 2 + ext_len;

	if (hs_len < 2 ||                       /* minimum one compression method */
	    data[0] < 1 || data[0] > hs_len)    /* minimum 1 bytes for a method */
		goto not_ssl_hello;

	/* Jump to the extensions */
	hs_len -= 1 + data[0];
	data   += 1 + data[0];

	if (hs_len < 2 ||                       /* minimum one extension list length */
	    (ext_len = (data[0] << 8) + data[1]) > hs_len - 2) /* list too long */
		goto not_ssl_hello;

	hs_len = ext_len; /* limit ourselves to the extension length */
	data += 2;

	while (hs_len >= 4) {
		int ext_type, name_type, srv_len, name_len;

		ext_type = (data[0] << 8) + data[1];
		ext_len  = (data[2] << 8) + data[3];

		if (ext_len > hs_len - 4) /* Extension too long */
			goto not_ssl_hello;

		if (ext_type == 0) { /* Server name */
			if (ext_len < 2) /* need one list length */
				goto not_ssl_hello;

			srv_len = (data[4] << 8) + data[5];
			if (srv_len < 4 || srv_len > hs_len - 6)
				goto not_ssl_hello; /* at least 4 bytes per server name */

			name_type = data[6];
			name_len = (data[7] << 8) + data[8];

			if (name_type == 0) { /* hostname */
				temp_pattern.data.str.str = (char *)data + 9;
				temp_pattern.data.str.len = name_len;
				test->flags = ACL_TEST_F_VOLATILE;
				return 1;
			}
		}

		hs_len -= 4 + ext_len;
		data   += 4 + ext_len;
	}
	/* server name not found */
	goto not_ssl_hello;

 too_short:
	test->flags = ACL_TEST_F_MAY_CHANGE;

 not_ssl_hello:

	return 0;
}

/* Fetch the RDP cookie identified in the expression.
 * Note: this decoder only works with non-wrapping data.
 * Accepts either 0 or 1 argument. Argument is a string (cookie name), other
 * types will lead to undefined behaviour.
 */
int
acl_fetch_rdp_cookie(struct proxy *px, struct session *l4, void *l7, int dir,
                     struct acl_expr *expr, struct acl_test *test)
{
	int bleft;
	const unsigned char *data;

	if (!l4 || !l4->req)
		return 0;

	test->flags = 0;

	bleft = l4->req->i;
	if (bleft <= 11)
		goto too_short;

	data = (const unsigned char *)l4->req->p + 11;
	bleft -= 11;

	if (bleft <= 7)
		goto too_short;

	if (strncasecmp((const char *)data, "Cookie:", 7) != 0)
		goto not_cookie;

	data += 7;
	bleft -= 7;

	while (bleft > 0 && *data == ' ') {
		data++;
		bleft--;
	}

	if (expr->args) {

		if (bleft <= expr->args->data.str.len)
			goto too_short;

		if ((data[expr->args->data.str.len] != '=') ||
		    strncasecmp(expr->args->data.str.str, (const char *)data, expr->args->data.str.len) != 0)
			goto not_cookie;

		data += expr->args->data.str.len + 1;
		bleft -= expr->args->data.str.len + 1;
	} else {
		while (bleft > 0 && *data != '=') {
			if (*data == '\r' || *data == '\n')
				goto not_cookie;
			data++;
			bleft--;
		}

		if (bleft < 1)
			goto too_short;

		if (*data != '=')
			goto not_cookie;

		data++;
		bleft--;
	}

	/* data points to cookie value */
	temp_pattern.data.str.str = (char *)data;
	temp_pattern.data.str.len = 0;

	while (bleft > 0 && *data != '\r') {
		data++;
		bleft--;
	}

	if (bleft < 2)
		goto too_short;

	if (data[0] != '\r' || data[1] != '\n')
		goto not_cookie;

	temp_pattern.data.str.len = (char *)data - temp_pattern.data.str.str;
	test->flags = ACL_TEST_F_VOLATILE;
	return 1;

 too_short:
	test->flags = ACL_TEST_F_MAY_CHANGE;
 not_cookie:
	return 0;
}

static int
acl_fetch_rdp_cookie_cnt(struct proxy *px, struct session *l4, void *l7, int dir,
			struct acl_expr *expr, struct acl_test *test)
{
	int ret;

	ret = acl_fetch_rdp_cookie(px, l4, l7, dir, expr, test);

	temp_pattern.data.str.str = NULL;
	temp_pattern.data.str.len = 0;

	if (test->flags & ACL_TEST_F_MAY_CHANGE)
		return 0;

	test->flags = ACL_TEST_F_VOLATILE;
	temp_pattern.data.integer = ret;

	return 1;
}


/*
 * These functions are exported and may be used by any other component.
 */

/* ignore the current line */
int acl_parse_nothing(const char **text, struct acl_pattern *pattern, int *opaque)
{
	return 1;
}

/* always fake a data retrieval */
int acl_fetch_nothing(struct proxy *px, struct session *l4, void *l7, int dir,
		      struct acl_expr *expr, struct acl_test *test)
{
	return 1;
}

/* always return false */
int acl_match_nothing(struct acl_test *test, struct acl_pattern *pattern)
{
	return ACL_PAT_FAIL;
}


/* NB: For two strings to be identical, it is required that their lengths match */
int acl_match_str(struct acl_test *test, struct acl_pattern *pattern)
{
	int icase;

	if (pattern->len != temp_pattern.data.str.len)
		return ACL_PAT_FAIL;

	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, temp_pattern.data.str.str, temp_pattern.data.str.len) == 0) ||
	    (!icase && strncmp(pattern->ptr.str, temp_pattern.data.str.str, temp_pattern.data.str.len) == 0))
		return ACL_PAT_PASS;
	return ACL_PAT_FAIL;
}

/* Lookup a string in the expression's pattern tree. The node is returned if it
 * exists, otherwise NULL.
 */
void *acl_lookup_str(struct acl_test *test, struct acl_expr *expr)
{
	/* data are stored in a tree */
	struct ebmb_node *node;
	char prev;

	/* we may have to force a trailing zero on the test pattern */
	prev = temp_pattern.data.str.str[temp_pattern.data.str.len];
	if (prev)
		temp_pattern.data.str.str[temp_pattern.data.str.len] = '\0';
	node = ebst_lookup(&expr->pattern_tree, temp_pattern.data.str.str);
	if (prev)
		temp_pattern.data.str.str[temp_pattern.data.str.len] = prev;
	return node;
}

/* Executes a regex. It needs to change the data. If it is marked READ_ONLY
 * then it will be allocated and duplicated in place so that others may use
 * it later on. Note that this is embarrassing because we always try to avoid
 * allocating memory at run time.
 */
int acl_match_reg(struct acl_test *test, struct acl_pattern *pattern)
{
	char old_char;
	int ret;

	if (unlikely(test->flags & ACL_TEST_F_READ_ONLY)) {
		char *new_str;

		new_str = calloc(1, temp_pattern.data.str.len + 1);
		if (!new_str)
			return ACL_PAT_FAIL;

		memcpy(new_str, temp_pattern.data.str.str, temp_pattern.data.str.len);
		new_str[temp_pattern.data.str.len] = 0;
		if (test->flags & ACL_TEST_F_MUST_FREE)
			free(temp_pattern.data.str.str);
		temp_pattern.data.str.str = new_str;
		test->flags |= ACL_TEST_F_MUST_FREE;
		test->flags &= ~ACL_TEST_F_READ_ONLY;
	}

	old_char = temp_pattern.data.str.str[temp_pattern.data.str.len];
	temp_pattern.data.str.str[temp_pattern.data.str.len] = 0;

	if (regexec(pattern->ptr.reg, temp_pattern.data.str.str, 0, NULL, 0) == 0)
		ret = ACL_PAT_PASS;
	else
		ret = ACL_PAT_FAIL;

	temp_pattern.data.str.str[temp_pattern.data.str.len] = old_char;
	return ret;
}

/* Checks that the pattern matches the beginning of the tested string. */
int acl_match_beg(struct acl_test *test, struct acl_pattern *pattern)
{
	int icase;

	if (pattern->len > temp_pattern.data.str.len)
		return ACL_PAT_FAIL;

	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, temp_pattern.data.str.str, pattern->len) != 0) ||
	    (!icase && strncmp(pattern->ptr.str, temp_pattern.data.str.str, pattern->len) != 0))
		return ACL_PAT_FAIL;
	return ACL_PAT_PASS;
}

/* Checks that the pattern matches the end of the tested string. */
int acl_match_end(struct acl_test *test, struct acl_pattern *pattern)
{
	int icase;

	if (pattern->len > temp_pattern.data.str.len)
		return ACL_PAT_FAIL;
	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, temp_pattern.data.str.str + temp_pattern.data.str.len - pattern->len, pattern->len) != 0) ||
	    (!icase && strncmp(pattern->ptr.str, temp_pattern.data.str.str + temp_pattern.data.str.len - pattern->len, pattern->len) != 0))
		return ACL_PAT_FAIL;
	return ACL_PAT_PASS;
}

/* Checks that the pattern is included inside the tested string.
 * NB: Suboptimal, should be rewritten using a Boyer-Moore method.
 */
int acl_match_sub(struct acl_test *test, struct acl_pattern *pattern)
{
	int icase;
	char *end;
	char *c;

	if (pattern->len > temp_pattern.data.str.len)
		return ACL_PAT_FAIL;

	end = temp_pattern.data.str.str + temp_pattern.data.str.len - pattern->len;
	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if (icase) {
		for (c = temp_pattern.data.str.str; c <= end; c++) {
			if (tolower(*c) != tolower(*pattern->ptr.str))
				continue;
			if (strncasecmp(pattern->ptr.str, c, pattern->len) == 0)
				return ACL_PAT_PASS;
		}
	} else {
		for (c = temp_pattern.data.str.str; c <= end; c++) {
			if (*c != *pattern->ptr.str)
				continue;
			if (strncmp(pattern->ptr.str, c, pattern->len) == 0)
				return ACL_PAT_PASS;
		}
	}
	return ACL_PAT_FAIL;
}

/* Background: Fast way to find a zero byte in a word
 * http://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
 * hasZeroByte = (v - 0x01010101UL) & ~v & 0x80808080UL;
 *
 * To look for 4 different byte values, xor the word with those bytes and
 * then check for zero bytes:
 *
 * v = (((unsigned char)c * 0x1010101U) ^ delimiter)
 * where <delimiter> is the 4 byte values to look for (as an uint)
 * and <c> is the character that is being tested
 */
static inline unsigned int is_delimiter(unsigned char c, unsigned int mask)
{
	mask ^= (c * 0x01010101); /* propagate the char to all 4 bytes */
	return (mask - 0x01010101) & ~mask & 0x80808080U;
}

static inline unsigned int make_4delim(unsigned char d1, unsigned char d2, unsigned char d3, unsigned char d4)
{
	return d1 << 24 | d2 << 16 | d3 << 8 | d4;
}

/* This one is used by other real functions. It checks that the pattern is
 * included inside the tested string, but enclosed between the specified
 * delimiters or at the beginning or end of the string. The delimiters are
 * provided as an unsigned int made by make_4delim() and match up to 4 different
 * delimiters. Delimiters are stripped at the beginning and end of the pattern.
 */
static int match_word(struct acl_test *test, struct acl_pattern *pattern, unsigned int delimiters)
{
	int may_match, icase;
	char *c, *end;
	char *ps;
	int pl;

	pl = pattern->len;
	ps = pattern->ptr.str;

	while (pl > 0 && is_delimiter(*ps, delimiters)) {
		pl--;
		ps++;
	}

	while (pl > 0 && is_delimiter(ps[pl - 1], delimiters))
		pl--;

	if (pl > temp_pattern.data.str.len)
		return ACL_PAT_FAIL;

	may_match = 1;
	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	end = temp_pattern.data.str.str + temp_pattern.data.str.len - pl;
	for (c = temp_pattern.data.str.str; c <= end; c++) {
		if (is_delimiter(*c, delimiters)) {
			may_match = 1;
			continue;
		}

		if (!may_match)
			continue;

		if (icase) {
			if ((tolower(*c) == tolower(*ps)) &&
			    (strncasecmp(ps, c, pl) == 0) &&
			    (c == end || is_delimiter(c[pl], delimiters)))
				return ACL_PAT_PASS;
		} else {
			if ((*c == *ps) &&
			    (strncmp(ps, c, pl) == 0) &&
			    (c == end || is_delimiter(c[pl], delimiters)))
				return ACL_PAT_PASS;
		}
		may_match = 0;
	}
	return ACL_PAT_FAIL;
}

/* Checks that the pattern is included inside the tested string, but enclosed
 * between the delimiters '?' or '/' or at the beginning or end of the string.
 * Delimiters at the beginning or end of the pattern are ignored.
 */
int acl_match_dir(struct acl_test *test, struct acl_pattern *pattern)
{
	return match_word(test, pattern, make_4delim('/', '?', '?', '?'));
}

/* Checks that the pattern is included inside the tested string, but enclosed
 * between the delmiters '/', '?', '.' or ":" or at the beginning or end of
 * the string. Delimiters at the beginning or end of the pattern are ignored.
 */
int acl_match_dom(struct acl_test *test, struct acl_pattern *pattern)
{
	return match_word(test, pattern, make_4delim('/', '?', '.', ':'));
}

/* Checks that the integer in <test> is included between min and max */
int acl_match_int(struct acl_test *test, struct acl_pattern *pattern)
{
	if ((!pattern->val.range.min_set || pattern->val.range.min <= temp_pattern.data.integer) &&
	    (!pattern->val.range.max_set || temp_pattern.data.integer <= pattern->val.range.max))
		return ACL_PAT_PASS;
	return ACL_PAT_FAIL;
}

/* Checks that the length of the pattern in <test> is included between min and max */
int acl_match_len(struct acl_test *test, struct acl_pattern *pattern)
{
	if ((!pattern->val.range.min_set || pattern->val.range.min <= temp_pattern.data.str.len) &&
	    (!pattern->val.range.max_set || temp_pattern.data.str.len <= pattern->val.range.max))
		return ACL_PAT_PASS;
	return ACL_PAT_FAIL;
}

int acl_match_ip(struct acl_test *test, struct acl_pattern *pattern)
{
	struct in_addr *s;

	if (temp_pattern.type != PATTERN_TYPE_IP)
		return ACL_PAT_FAIL;

	s = &temp_pattern.data.ip;
	if (((s->s_addr ^ pattern->val.ipv4.addr.s_addr) & pattern->val.ipv4.mask.s_addr) == 0)
		return ACL_PAT_PASS;
	return ACL_PAT_FAIL;
}

/* Lookup an IPv4 address in the expression's pattern tree using the longest
 * match method. The node is returned if it exists, otherwise NULL.
 */
void *acl_lookup_ip(struct acl_test *test, struct acl_expr *expr)
{
	struct in_addr *s;

	if (temp_pattern.type != PATTERN_TYPE_IP)
		return ACL_PAT_FAIL;

	s = &temp_pattern.data.ip;
	return ebmb_lookup_longest(&expr->pattern_tree, &s->s_addr);
}

/* Parse a string. It is allocated and duplicated. */
int acl_parse_str(const char **text, struct acl_pattern *pattern, int *opaque)
{
	int len;

	len  = strlen(*text);

	if (pattern->flags & ACL_PAT_F_TREE_OK) {
		/* we're allowed to put the data in a tree whose root is pointed
		 * to by val.tree.
		 */
		struct ebmb_node *node;

		node = calloc(1, sizeof(*node) + len + 1);
		if (!node)
			return 0;
		memcpy(node->key, *text, len + 1);
		if (ebst_insert(pattern->val.tree, node) != node)
			free(node); /* was a duplicate */
		pattern->flags |= ACL_PAT_F_TREE; /* this pattern now contains a tree */
		return 1;
	}

	pattern->ptr.str = strdup(*text);
	if (!pattern->ptr.str)
		return 0;
	pattern->len = len;
	return 1;
}

/* Parse and concatenate all further strings into one. */
int
acl_parse_strcat(const char **text, struct acl_pattern *pattern, int *opaque)
{

	int len = 0, i;
	char *s;

	for (i = 0; *text[i]; i++)
		len += strlen(text[i])+1;

	pattern->ptr.str = s = calloc(1, len);
	if (!pattern->ptr.str)
		return 0;

	for (i = 0; *text[i]; i++)
		s += sprintf(s, i?" %s":"%s", text[i]);

	pattern->len = len;

	return i;
}

/* Free data allocated by acl_parse_reg */
static void acl_free_reg(void *ptr) {

	regfree((regex_t *)ptr);
}

/* Parse a regex. It is allocated. */
int acl_parse_reg(const char **text, struct acl_pattern *pattern, int *opaque)
{
	regex_t *preg;
	int icase;

	preg = calloc(1, sizeof(regex_t));

	if (!preg)
		return 0;

	icase = (pattern->flags & ACL_PAT_F_IGNORE_CASE) ? REG_ICASE : 0;
	if (regcomp(preg, *text, REG_EXTENDED | REG_NOSUB | icase) != 0) {
		free(preg);
		return 0;
	}

	pattern->ptr.reg = preg;
	pattern->freeptrbuf = &acl_free_reg;
	return 1;
}

/* Parse a range of positive integers delimited by either ':' or '-'. If only
 * one integer is read, it is set as both min and max. An operator may be
 * specified as the prefix, among this list of 5 :
 *
 *    0:eq, 1:gt, 2:ge, 3:lt, 4:le
 *
 * The default operator is "eq". It supports range matching. Ranges are
 * rejected for other operators. The operator may be changed at any time.
 * The operator is stored in the 'opaque' argument.
 *
 */
int acl_parse_int(const char **text, struct acl_pattern *pattern, int *opaque)
{
	signed long long i;
	unsigned int j, last, skip = 0;
	const char *ptr = *text;


	while (!isdigit((unsigned char)*ptr)) {
		switch (get_std_op(ptr)) {
		case STD_OP_EQ: *opaque = 0; break;
		case STD_OP_GT: *opaque = 1; break;
		case STD_OP_GE: *opaque = 2; break;
		case STD_OP_LT: *opaque = 3; break;
		case STD_OP_LE: *opaque = 4; break;
		default:
			return 0;
		}

		skip++;
		ptr = text[skip];
	}

	last = i = 0;
	while (1) {
                j = *ptr++;
		if ((j == '-' || j == ':') && !last) {
			last++;
			pattern->val.range.min = i;
			i = 0;
			continue;
		}
		j -= '0';
                if (j > 9)
			// also catches the terminating zero
                        break;
                i *= 10;
                i += j;
        }

	if (last && *opaque >= 1 && *opaque <= 4)
		/* having a range with a min or a max is absurd */
		return 0;

	if (!last)
		pattern->val.range.min = i;
	pattern->val.range.max = i;

	switch (*opaque) {
	case 0: /* eq */
		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 1;
		break;
	case 1: /* gt */
		pattern->val.range.min++; /* gt = ge + 1 */
	case 2: /* ge */
		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 0;
		break;
	case 3: /* lt */
		pattern->val.range.max--; /* lt = le - 1 */
	case 4: /* le */
		pattern->val.range.min_set = 0;
		pattern->val.range.max_set = 1;
		break;
	}
	return skip + 1;
}

/* Parse a range of positive 2-component versions delimited by either ':' or
 * '-'. The version consists in a major and a minor, both of which must be
 * smaller than 65536, because internally they will be represented as a 32-bit
 * integer.
 * If only one version is read, it is set as both min and max. Just like for
 * pure integers, an operator may be specified as the prefix, among this list
 * of 5 :
 *
 *    0:eq, 1:gt, 2:ge, 3:lt, 4:le
 *
 * The default operator is "eq". It supports range matching. Ranges are
 * rejected for other operators. The operator may be changed at any time.
 * The operator is stored in the 'opaque' argument. This allows constructs
 * such as the following one :
 *
 *    acl obsolete_ssl    ssl_req_proto lt 3
 *    acl unsupported_ssl ssl_req_proto gt 3.1
 *    acl valid_ssl       ssl_req_proto 3.0-3.1
 *
 */
int acl_parse_dotted_ver(const char **text, struct acl_pattern *pattern, int *opaque)
{
	signed long long i;
	unsigned int j, last, skip = 0;
	const char *ptr = *text;


	while (!isdigit((unsigned char)*ptr)) {
		switch (get_std_op(ptr)) {
		case STD_OP_EQ: *opaque = 0; break;
		case STD_OP_GT: *opaque = 1; break;
		case STD_OP_GE: *opaque = 2; break;
		case STD_OP_LT: *opaque = 3; break;
		case STD_OP_LE: *opaque = 4; break;
		default:
			return 0;
		}

		skip++;
		ptr = text[skip];
	}

	last = i = 0;
	while (1) {
                j = *ptr++;
		if (j == '.') {
			/* minor part */
			if (i >= 65536)
				return 0;
			i <<= 16;
			continue;
		}
		if ((j == '-' || j == ':') && !last) {
			last++;
			if (i < 65536)
				i <<= 16;
			pattern->val.range.min = i;
			i = 0;
			continue;
		}
		j -= '0';
                if (j > 9)
			// also catches the terminating zero
                        break;
                i = (i & 0xFFFF0000) + (i & 0xFFFF) * 10;
                i += j;
        }

	/* if we only got a major version, let's shift it now */
	if (i < 65536)
		i <<= 16;

	if (last && *opaque >= 1 && *opaque <= 4)
		/* having a range with a min or a max is absurd */
		return 0;

	if (!last)
		pattern->val.range.min = i;
	pattern->val.range.max = i;

	switch (*opaque) {
	case 0: /* eq */
		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 1;
		break;
	case 1: /* gt */
		pattern->val.range.min++; /* gt = ge + 1 */
	case 2: /* ge */
		pattern->val.range.min_set = 1;
		pattern->val.range.max_set = 0;
		break;
	case 3: /* lt */
		pattern->val.range.max--; /* lt = le - 1 */
	case 4: /* le */
		pattern->val.range.min_set = 0;
		pattern->val.range.max_set = 1;
		break;
	}
	return skip + 1;
}

/* Parse an IP address and an optional mask in the form addr[/mask].
 * The addr may either be an IPv4 address or a hostname. The mask
 * may either be a dotted mask or a number of bits. Returns 1 if OK,
 * otherwise 0.
 */
int acl_parse_ip(const char **text, struct acl_pattern *pattern, int *opaque)
{
	struct eb_root *tree = NULL;
	if (pattern->flags & ACL_PAT_F_TREE_OK)
		tree = pattern->val.tree;

	if (str2net(*text, &pattern->val.ipv4.addr, &pattern->val.ipv4.mask)) {
		unsigned int mask = ntohl(pattern->val.ipv4.mask.s_addr);
		struct ebmb_node *node;
		/* check if the mask is contiguous so that we can insert the
		 * network into the tree. A continuous mask has only ones on
		 * the left. This means that this mask + its lower bit added
		 * once again is null.
		 */
		if (mask + (mask & -mask) == 0 && tree) {
			mask = mask ? 33 - flsnz(mask & -mask) : 0; /* equals cidr value */
			/* FIXME: insert <addr>/<mask> into the tree here */
			node = calloc(1, sizeof(*node) + 4); /* reserve 4 bytes for IPv4 address */
			if (!node)
				return 0;
			memcpy(node->key, &pattern->val.ipv4.addr, 4); /* network byte order */
			node->node.pfx = mask;
			if (ebmb_insert_prefix(tree, node, 4) != node)
				free(node); /* was a duplicate */
			pattern->flags |= ACL_PAT_F_TREE;
			return 1;
		}
		return 1;
	}
	else
		return 0;
}

/*
 * Registers the ACL keyword list <kwl> as a list of valid keywords for next
 * parsing sessions.
 */
void acl_register_keywords(struct acl_kw_list *kwl)
{
	LIST_ADDQ(&acl_keywords.list, &kwl->list);
}

/*
 * Unregisters the ACL keyword list <kwl> from the list of valid keywords.
 */
void acl_unregister_keywords(struct acl_kw_list *kwl)
{
	LIST_DEL(&kwl->list);
	LIST_INIT(&kwl->list);
}

/* Return a pointer to the ACL <name> within the list starting at <head>, or
 * NULL if not found.
 */
struct acl *find_acl_by_name(const char *name, struct list *head)
{
	struct acl *acl;
	list_for_each_entry(acl, head, list) {
		if (strcmp(acl->name, name) == 0)
			return acl;
	}
	return NULL;
}

/* Return a pointer to the ACL keyword <kw>, or NULL if not found. Note that if
 * <kw> contains an opening parenthesis, only the left part of it is checked.
 */
struct acl_keyword *find_acl_kw(const char *kw)
{
	int index;
	const char *kwend;
	struct acl_kw_list *kwl;

	kwend = strchr(kw, '(');
	if (!kwend)
		kwend = kw + strlen(kw);

	list_for_each_entry(kwl, &acl_keywords.list, list) {
		for (index = 0; kwl->kw[index].kw != NULL; index++) {
			if ((strncmp(kwl->kw[index].kw, kw, kwend - kw) == 0) &&
			    kwl->kw[index].kw[kwend-kw] == 0)
				return &kwl->kw[index];
		}
	}
	return NULL;
}

/* NB: does nothing if <pat> is NULL */
static void free_pattern(struct acl_pattern *pat)
{
	if (!pat)
		return;

	if (pat->ptr.ptr) {
		if (pat->freeptrbuf)
			pat->freeptrbuf(pat->ptr.ptr);

		free(pat->ptr.ptr);
	}

	free(pat);
}

static void free_pattern_list(struct list *head)
{
	struct acl_pattern *pat, *tmp;
	list_for_each_entry_safe(pat, tmp, head, list)
		free_pattern(pat);
}

static void free_pattern_tree(struct eb_root *root)
{
	struct eb_node *node, *next;
	node = eb_first(root);
	while (node) {
		next = eb_next(node);
		free(node);
		node = next;
	}
}

static struct acl_expr *prune_acl_expr(struct acl_expr *expr)
{
	struct arg *arg;

	free_pattern_list(&expr->patterns);
	free_pattern_tree(&expr->pattern_tree);
	LIST_INIT(&expr->patterns);

	for (arg = expr->args; arg; arg++) {
		if (arg->type == ARGT_STOP)
			break;
		if (arg->type == ARGT_FE || arg->type == ARGT_BE ||
		    arg->type == ARGT_TAB || arg->type == ARGT_SRV ||
		    arg->type == ARGT_USR || arg->type == ARGT_STR) {
			free(arg->data.str.str);
			arg->data.str.str = NULL;
		}
		arg++;
	}

	free(expr->args);
	expr->kw->use_cnt--;
	return expr;
}

static int acl_read_patterns_from_file(	struct acl_keyword *aclkw,
					struct acl_expr *expr,
					const char *filename, int patflags)
{
	FILE *file;
	char *c;
	const char *args[2];
	struct acl_pattern *pattern;
	int opaque;
	int ret = 0;

	file = fopen(filename, "r");
	if (!file)
		return 0;

	/* now parse all patterns. The file may contain only one pattern per
	 * line. If the line contains spaces, they will be part of the pattern.
	 * The pattern stops at the first CR, LF or EOF encountered.
	 */
	opaque = 0;
	pattern = NULL;
	args[1] = "";
	while (fgets(trash, sizeof(trash), file) != NULL) {

		c = trash;

		/* ignore lines beginning with a dash */
		if (*c == '#')
			continue;

		/* strip leading spaces and tabs */
		while (*c == ' ' || *c == '\t')
			c++;


		args[0] = c;
		while (*c && *c != '\n' && *c != '\r')
			c++;
		*c = 0;

		/* empty lines are ignored too */
		if (c == args[0])
			continue;

		/* we keep the previous pattern along iterations as long as it's not used */
		if (!pattern)
			pattern = (struct acl_pattern *)malloc(sizeof(*pattern));
		if (!pattern)
			goto out_close;

		memset(pattern, 0, sizeof(*pattern));
		pattern->flags = patflags;

		if ((aclkw->requires & ACL_MAY_LOOKUP) && !(pattern->flags & ACL_PAT_F_IGNORE_CASE)) {
			/* we pre-set the data pointer to the tree's head so that functions
			 * which are able to insert in a tree know where to do that.
			 */
			pattern->flags |= ACL_PAT_F_TREE_OK;
			pattern->val.tree = &expr->pattern_tree;
		}

		if (!aclkw->parse(args, pattern, &opaque))
			goto out_free_pattern;

		/* if the parser did not feed the tree, let's chain the pattern to the list */
		if (!(pattern->flags & ACL_PAT_F_TREE)) {
			LIST_ADDQ(&expr->patterns, &pattern->list);
			pattern = NULL; /* get a new one */
		}
	}

	ret = 1; /* success */

 out_free_pattern:
	free_pattern(pattern);
 out_close:
	fclose(file);
	return ret;
}

/* Parse an ACL expression starting at <args>[0], and return it.
 * Right now, the only accepted syntax is :
 * <subject> [<value>...]
 */
struct acl_expr *parse_acl_expr(const char **args)
{
	__label__ out_return, out_free_expr, out_free_pattern;
	struct acl_expr *expr;
	struct acl_keyword *aclkw;
	struct acl_pattern *pattern;
	int opaque, patflags;
	const char *arg;

	aclkw = find_acl_kw(args[0]);
	if (!aclkw || !aclkw->parse)
		goto out_return;

	expr = (struct acl_expr *)calloc(1, sizeof(*expr));
	if (!expr)
		goto out_return;

	expr->kw = aclkw;
	aclkw->use_cnt++;
	LIST_INIT(&expr->patterns);
	expr->pattern_tree = EB_ROOT_UNIQUE;

	arg = strchr(args[0], '(');
	if (aclkw->arg_mask) {
		int nbargs = 0;
		char *end;

		if (arg != NULL) {
			/* there are 0 or more arguments in the form "subject(arg[,arg]*)" */
			arg++;
			end = strchr(arg, ')');
			if (!end)
				goto out_free_expr;

			/* Parse the arguments. Note that currently we have no way to
			 * report parsing errors, hence the NULL in the error pointers.
			 * An error is also reported if some mandatory arguments are
			 * missing.
			 */
			nbargs = make_arg_list(arg, end - arg, aclkw->arg_mask, &expr->args,
					       NULL, NULL, NULL);
			if (nbargs < 0)
				goto out_free_expr;
		}
		else if (ARGM(aclkw->arg_mask)) {
			/* there were some mandatory arguments */
			goto out_free_expr;
		}
	}
	else {
		if (arg) {
			/* no argument expected */
			goto out_free_expr;
		}
	}

	args++;

	/* check for options before patterns. Supported options are :
	 *   -i : ignore case for all patterns by default
	 *   -f : read patterns from those files
	 *   -- : everything after this is not an option
	 */
	patflags = 0;
	while (**args == '-') {
		if ((*args)[1] == 'i')
			patflags |= ACL_PAT_F_IGNORE_CASE;
		else if ((*args)[1] == 'f') {
			if (!acl_read_patterns_from_file(aclkw, expr, args[1], patflags | ACL_PAT_F_FROM_FILE))
				goto out_free_expr;
			args++;
		}
		else if ((*args)[1] == '-') {
			args++;
			break;
		}
		else
			break;
		args++;
	}

	/* now parse all patterns */
	opaque = 0;
	while (**args) {
		int ret;
		pattern = (struct acl_pattern *)calloc(1, sizeof(*pattern));
		if (!pattern)
			goto out_free_expr;
		pattern->flags = patflags;

		ret = aclkw->parse(args, pattern, &opaque);
		if (!ret)
			goto out_free_pattern;
		LIST_ADDQ(&expr->patterns, &pattern->list);
		args += ret;
	}

	return expr;

 out_free_pattern:
	free_pattern(pattern);
 out_free_expr:
	prune_acl_expr(expr);
	free(expr);
 out_return:
	return NULL;
}

/* Purge everything in the acl <acl>, then return <acl>. */
struct acl *prune_acl(struct acl *acl) {

	struct acl_expr *expr, *exprb;

	free(acl->name);

	list_for_each_entry_safe(expr, exprb, &acl->expr, list) {
		LIST_DEL(&expr->list);
		prune_acl_expr(expr);
		free(expr);
	}

	return acl;
}

/* Parse an ACL with the name starting at <args>[0], and with a list of already
 * known ACLs in <acl>. If the ACL was not in the list, it will be added.
 * A pointer to that ACL is returned. If the ACL has an empty name, then it's
 * an anonymous one and it won't be merged with any other one.
 *
 * args syntax: <aclname> <acl_expr>
 */
struct acl *parse_acl(const char **args, struct list *known_acl)
{
	__label__ out_return, out_free_acl_expr, out_free_name;
	struct acl *cur_acl;
	struct acl_expr *acl_expr;
	char *name;

	if (**args && invalid_char(*args))
		goto out_return;

	acl_expr = parse_acl_expr(args + 1);
	if (!acl_expr)
		goto out_return;

	/* Check for args beginning with an opening parenthesis just after the
	 * subject, as this is almost certainly a typo. Right now we can only
	 * emit a warning, so let's do so.
	 */
	if (!strchr(args[1], '(') && *args[2] == '(')
		Warning("parsing acl '%s' :\n"
			"  matching '%s' for pattern '%s' is likely a mistake and probably\n"
			"  not what you want. Maybe you need to remove the extraneous space before '('.\n"
			"  If you are really sure this is not an error, please insert '--' between the\n"
			"  match and the pattern to make this warning message disappear.\n",
			args[0], args[1], args[2]);

	if (*args[0])
		cur_acl = find_acl_by_name(args[0], known_acl);
	else
		cur_acl = NULL;

	if (!cur_acl) {
		name = strdup(args[0]);
		if (!name)
			goto out_free_acl_expr;
		cur_acl = (struct acl *)calloc(1, sizeof(*cur_acl));
		if (cur_acl == NULL)
			goto out_free_name;

		LIST_INIT(&cur_acl->expr);
		LIST_ADDQ(known_acl, &cur_acl->list);
		cur_acl->name = name;
	}

	cur_acl->requires |= acl_expr->kw->requires;
	LIST_ADDQ(&cur_acl->expr, &acl_expr->list);
	return cur_acl;

 out_free_name:
	free(name);
 out_free_acl_expr:
	prune_acl_expr(acl_expr);
	free(acl_expr);
 out_return:
	return NULL;
}

/* Some useful ACLs provided by default. Only those used are allocated. */

const struct {
	const char *name;
	const char *expr[4]; /* put enough for longest expression */
} default_acl_list[] = {
	{ .name = "TRUE",           .expr = {"always_true",""}},
	{ .name = "FALSE",          .expr = {"always_false",""}},
	{ .name = "LOCALHOST",      .expr = {"src","127.0.0.1/8",""}},
	{ .name = "HTTP",           .expr = {"req_proto_http",""}},
	{ .name = "HTTP_1.0",       .expr = {"req_ver","1.0",""}},
	{ .name = "HTTP_1.1",       .expr = {"req_ver","1.1",""}},
	{ .name = "METH_CONNECT",   .expr = {"method","CONNECT",""}},
	{ .name = "METH_GET",       .expr = {"method","GET","HEAD",""}},
	{ .name = "METH_HEAD",      .expr = {"method","HEAD",""}},
	{ .name = "METH_OPTIONS",   .expr = {"method","OPTIONS",""}},
	{ .name = "METH_POST",      .expr = {"method","POST",""}},
	{ .name = "METH_TRACE",     .expr = {"method","TRACE",""}},
	{ .name = "HTTP_URL_ABS",   .expr = {"url_reg","^[^/:]*://",""}},
	{ .name = "HTTP_URL_SLASH", .expr = {"url_beg","/",""}},
	{ .name = "HTTP_URL_STAR",  .expr = {"url","*",""}},
	{ .name = "HTTP_CONTENT",   .expr = {"hdr_val(content-length)","gt","0",""}},
	{ .name = "RDP_COOKIE",     .expr = {"req_rdp_cookie_cnt","gt","0",""}},
	{ .name = "REQ_CONTENT",    .expr = {"req_len","gt","0",""}},
	{ .name = "WAIT_END",       .expr = {"wait_end",""}},
	{ .name = NULL, .expr = {""}}
};

/* Find a default ACL from the default_acl list, compile it and return it.
 * If the ACL is not found, NULL is returned. In theory, it cannot fail,
 * except when default ACLs are broken, in which case it will return NULL.
 * If <known_acl> is not NULL, the ACL will be queued at its tail.
 */
struct acl *find_acl_default(const char *acl_name, struct list *known_acl)
{
	__label__ out_return, out_free_acl_expr, out_free_name;
	struct acl *cur_acl;
	struct acl_expr *acl_expr;
	char *name;
	int index;

	for (index = 0; default_acl_list[index].name != NULL; index++) {
		if (strcmp(acl_name, default_acl_list[index].name) == 0)
			break;
	}

	if (default_acl_list[index].name == NULL)
		return NULL;

	acl_expr = parse_acl_expr((const char **)default_acl_list[index].expr);
	if (!acl_expr)
		goto out_return;

	name = strdup(acl_name);
	if (!name)
		goto out_free_acl_expr;
	cur_acl = (struct acl *)calloc(1, sizeof(*cur_acl));
	if (cur_acl == NULL)
		goto out_free_name;

	cur_acl->name = name;
	cur_acl->requires |= acl_expr->kw->requires;
	LIST_INIT(&cur_acl->expr);
	LIST_ADDQ(&cur_acl->expr, &acl_expr->list);
	if (known_acl)
		LIST_ADDQ(known_acl, &cur_acl->list);

	return cur_acl;

 out_free_name:
	free(name);
 out_free_acl_expr:
	prune_acl_expr(acl_expr);
	free(acl_expr);
 out_return:
	return NULL;
}

/* Purge everything in the acl_cond <cond>, then return <cond>. */
struct acl_cond *prune_acl_cond(struct acl_cond *cond)
{
	struct acl_term_suite *suite, *tmp_suite;
	struct acl_term *term, *tmp_term;

	/* iterate through all term suites and free all terms and all suites */
	list_for_each_entry_safe(suite, tmp_suite, &cond->suites, list) {
		list_for_each_entry_safe(term, tmp_term, &suite->terms, list)
			free(term);
		free(suite);
	}
	return cond;
}

/* Parse an ACL condition starting at <args>[0], relying on a list of already
 * known ACLs passed in <known_acl>. The new condition is returned (or NULL in
 * case of low memory). Supports multiple conditions separated by "or".
 */
struct acl_cond *parse_acl_cond(const char **args, struct list *known_acl, int pol)
{
	__label__ out_return, out_free_suite, out_free_term;
	int arg, neg;
	const char *word;
	struct acl *cur_acl;
	struct acl_term *cur_term;
	struct acl_term_suite *cur_suite;
	struct acl_cond *cond;

	cond = (struct acl_cond *)calloc(1, sizeof(*cond));
	if (cond == NULL)
		goto out_return;

	LIST_INIT(&cond->list);
	LIST_INIT(&cond->suites);
	cond->pol = pol;

	cur_suite = NULL;
	neg = 0;
	for (arg = 0; *args[arg]; arg++) {
		word = args[arg];

		/* remove as many exclamation marks as we can */
		while (*word == '!') {
			neg = !neg;
			word++;
		}

		/* an empty word is allowed because we cannot force the user to
		 * always think about not leaving exclamation marks alone.
		 */
		if (!*word)
			continue;

		if (strcasecmp(word, "or") == 0 || strcmp(word, "||") == 0) {
			/* new term suite */
			cur_suite = NULL;
			neg = 0;
			continue;
		}

		if (strcmp(word, "{") == 0) {
			/* we may have a complete ACL expression between two braces,
			 * find the last one.
			 */
			int arg_end = arg + 1;
			const char **args_new;

			while (*args[arg_end] && strcmp(args[arg_end], "}") != 0)
				arg_end++;

			if (!*args[arg_end])
				goto out_free_suite;

			args_new = calloc(1, (arg_end - arg + 1) * sizeof(*args_new));
			if (!args_new)
				goto out_free_suite;

			args_new[0] = "";
			memcpy(args_new + 1, args + arg + 1, (arg_end - arg) * sizeof(*args_new));
			args_new[arg_end - arg] = "";
			cur_acl = parse_acl(args_new, known_acl);
			free(args_new);

			if (!cur_acl)
				goto out_free_suite;
			arg = arg_end;
		}
		else {
			/* search for <word> in the known ACL names. If we do not find
			 * it, let's look for it in the default ACLs, and if found, add
			 * it to the list of ACLs of this proxy. This makes it possible
			 * to override them.
			 */
			cur_acl = find_acl_by_name(word, known_acl);
			if (cur_acl == NULL) {
				cur_acl = find_acl_default(word, known_acl);
				if (cur_acl == NULL)
					goto out_free_suite;
			}
		}

		cur_term = (struct acl_term *)calloc(1, sizeof(*cur_term));
		if (cur_term == NULL)
			goto out_free_suite;

		cur_term->acl = cur_acl;
		cur_term->neg = neg;
		cond->requires |= cur_acl->requires;

		if (!cur_suite) {
			cur_suite = (struct acl_term_suite *)calloc(1, sizeof(*cur_suite));
			if (cur_term == NULL)
				goto out_free_term;
			LIST_INIT(&cur_suite->terms);
			LIST_ADDQ(&cond->suites, &cur_suite->list);
		}
		LIST_ADDQ(&cur_suite->terms, &cur_term->list);
		neg = 0;
	}

	return cond;

 out_free_term:
	free(cur_term);
 out_free_suite:
	prune_acl_cond(cond);
	free(cond);
 out_return:
	return NULL;
}

/* Builds an ACL condition starting at the if/unless keyword. The complete
 * condition is returned. NULL is returned in case of error or if the first
 * word is neither "if" nor "unless". It automatically sets the file name and
 * the line number in the condition for better error reporting, and adds the
 * ACL requirements to the proxy's acl_requires.
 */
struct acl_cond *build_acl_cond(const char *file, int line, struct proxy *px, const char **args)
{
	int pol = ACL_COND_NONE;
	struct acl_cond *cond = NULL;

	if (!strcmp(*args, "if")) {
		pol = ACL_COND_IF;
		args++;
	}
	else if (!strcmp(*args, "unless")) {
		pol = ACL_COND_UNLESS;
		args++;
	}
	else
		return NULL;

	cond = parse_acl_cond(args, &px->acl, pol);
	if (!cond)
		return NULL;

	cond->file = file;
	cond->line = line;
	px->acl_requires |= cond->requires;

	return cond;
}

/* Execute condition <cond> and return either ACL_PAT_FAIL, ACL_PAT_MISS or
 * ACL_PAT_PASS depending on the test results. ACL_PAT_MISS may only be
 * returned if <dir> contains ACL_PARTIAL, indicating that incomplete data
 * is being examined.
 * This function only computes the condition, it does not apply the polarity
 * required by IF/UNLESS, it's up to the caller to do this using something like
 * this :
 *
 *     res = acl_pass(res);
 *     if (res == ACL_PAT_MISS)
 *         return 0;
 *     if (cond->pol == ACL_COND_UNLESS)
 *         res = !res;
 */
int acl_exec_cond(struct acl_cond *cond, struct proxy *px, struct session *l4, void *l7, int dir)
{
	__label__ fetch_next;
	struct acl_term_suite *suite;
	struct acl_term *term;
	struct acl_expr *expr;
	struct acl *acl;
	struct acl_pattern *pattern;
	struct acl_test test;
	int acl_res, suite_res, cond_res;

	/* We're doing a logical OR between conditions so we initialize to FAIL.
	 * The MISS status is propagated down from the suites.
	 */
	cond_res = ACL_PAT_FAIL;
	list_for_each_entry(suite, &cond->suites, list) {
		/* Evaluate condition suite <suite>. We stop at the first term
		 * which returns ACL_PAT_FAIL. The MISS status is still propagated
		 * in case of uncertainty in the result.
		 */

		/* we're doing a logical AND between terms, so we must set the
		 * initial value to PASS.
		 */
		suite_res = ACL_PAT_PASS;
		list_for_each_entry(term, &suite->terms, list) {
			acl = term->acl;

			/* FIXME: use cache !
			 * check acl->cache_idx for this.
			 */

			/* ACL result not cached. Let's scan all the expressions
			 * and use the first one to match.
			 */
			acl_res = ACL_PAT_FAIL;
			list_for_each_entry(expr, &acl->expr, list) {
				/* we need to reset context and flags */
				memset(&test, 0, sizeof(test));
			fetch_next:
				if (!expr->kw->fetch(px, l4, l7, dir, expr, &test)) {
					/* maybe we could not fetch because of missing data */
					if (test.flags & ACL_TEST_F_MAY_CHANGE && dir & ACL_PARTIAL)
						acl_res |= ACL_PAT_MISS;
					continue;
				}

				if (test.flags & ACL_TEST_F_RES_SET) {
					if (test.flags & ACL_TEST_F_RES_PASS)
						acl_res |= ACL_PAT_PASS;
					else
						acl_res |= ACL_PAT_FAIL;
				}
				else {
					if (!eb_is_empty(&expr->pattern_tree)) {
						/* a tree is present, let's check what type it is */
						if (expr->kw->match == acl_match_str)
							acl_res |= acl_lookup_str(&test, expr) ? ACL_PAT_PASS : ACL_PAT_FAIL;
						else if (expr->kw->match == acl_match_ip)
							acl_res |= acl_lookup_ip(&test, expr) ? ACL_PAT_PASS : ACL_PAT_FAIL;
					}

					/* call the match() function for all tests on this value */
					list_for_each_entry(pattern, &expr->patterns, list) {
						if (acl_res == ACL_PAT_PASS)
							break;
						acl_res |= expr->kw->match(&test, pattern);
					}

					if ((test.flags & ACL_TEST_F_NULL_MATCH) &&
					    LIST_ISEMPTY(&expr->patterns) && eb_is_empty(&expr->pattern_tree))
						acl_res |= expr->kw->match(&test, NULL);
				}
				/*
				 * OK now acl_res holds the result of this expression
				 * as one of ACL_PAT_FAIL, ACL_PAT_MISS or ACL_PAT_PASS.
				 *
				 * Then if (!MISS) we can cache the result, and put
				 * (test.flags & ACL_TEST_F_VOLATILE) in the cache flags.
				 *
				 * FIXME: implement cache.
				 *
				 */

				/* now we may have some cleanup to do */
				if (test.flags & ACL_TEST_F_MUST_FREE) {
					free(temp_pattern.data.str.str);
					temp_pattern.data.str.len = 0;
				}

				/* we're ORing these terms, so a single PASS is enough */
				if (acl_res == ACL_PAT_PASS)
					break;

				if (test.flags & ACL_TEST_F_FETCH_MORE)
					goto fetch_next;

				/* sometimes we know the fetched data is subject to change
				 * later and give another chance for a new match (eg: request
				 * size, time, ...)
				 */
				if (test.flags & ACL_TEST_F_MAY_CHANGE && dir & ACL_PARTIAL)
					acl_res |= ACL_PAT_MISS;
			}
			/*
			 * Here we have the result of an ACL (cached or not).
			 * ACLs are combined, negated or not, to form conditions.
			 */

			if (term->neg)
				acl_res = acl_neg(acl_res);

			suite_res &= acl_res;

			/* we're ANDing these terms, so a single FAIL is enough */
			if (suite_res == ACL_PAT_FAIL)
				break;
		}
		cond_res |= suite_res;

		/* we're ORing these terms, so a single PASS is enough */
		if (cond_res == ACL_PAT_PASS)
			break;
	}
	return cond_res;
}


/* Reports a pointer to the first ACL used in condition <cond> which requires
 * at least one of the USE_FLAGS in <require>. Returns NULL if none matches.
 * The construct is almost the same as for acl_exec_cond() since we're walking
 * down the ACL tree as well. It is important that the tree is really walked
 * through and never cached, because that way, this function can be used as a
 * late check.
 */
struct acl *cond_find_require(const struct acl_cond *cond, unsigned int require)
{
	struct acl_term_suite *suite;
	struct acl_term *term;
	struct acl *acl;

	list_for_each_entry(suite, &cond->suites, list) {
		list_for_each_entry(term, &suite->terms, list) {
			acl = term->acl;
			if (acl->requires & require)
				return acl;
		}
	}
	return NULL;
}

/*
 * Find targets for userlist and groups in acl. Function returns the number
 * of errors or OK if everything is fine.
 */
int
acl_find_targets(struct proxy *p)
{

	struct acl *acl;
	struct acl_expr *expr;
	struct acl_pattern *pattern;
	struct userlist *ul;
	int cfgerr = 0;

	list_for_each_entry(acl, &p->acl, list) {
		list_for_each_entry(expr, &acl->expr, list) {
			if (strcmp(expr->kw->kw, "srv_is_up") == 0 ||
			    strcmp(expr->kw->kw, "srv_conn") == 0) {
				struct proxy *px;
				struct server *srv;
				char *pname, *sname;

				/* FIXME: at the moment we check argument types from the keyword,
				 * but later we'll simlpy inspect argument types.
				 */
				if (!expr->args || !expr->args->data.str.len) {
					Alert("proxy %s: acl %s %s(): missing server name.\n",
						p->id, acl->name, expr->kw->kw);
					cfgerr++;
					continue;
				}

				pname = expr->args->data.str.str;
				sname = strrchr(pname, '/');

				if (sname)
					*sname++ = '\0';
				else {
					sname = pname;
					pname = NULL;
				}

				px = p;
				if (pname) {
					px = findproxy(pname, PR_CAP_BE);
					if (!px) {
						Alert("proxy %s: acl %s %s(): unable to find proxy '%s'.\n",
						      p->id, acl->name, expr->kw->kw, pname);
						cfgerr++;
						continue;
					}
				}

				srv = findserver(px, sname);
				if (!srv) {
					Alert("proxy %s: acl %s %s(): unable to find server '%s'.\n",
					      p->id, acl->name, expr->kw->kw, sname);
					cfgerr++;
					continue;
				}

				free(expr->args->data.str.str);
				expr->args->data.srv = srv;
				continue;
			}

			if (strstr(expr->kw->kw, "http_auth") == expr->kw->kw) {

				/* FIXME: at the moment we check argument types from the keyword,
				 * but later we'll simlpy inspect argument types.
				 */
				if (!expr->args || !expr->args->data.str.len) {
					Alert("proxy %s: acl %s %s(): missing userlist name.\n",
						p->id, acl->name, expr->kw->kw);
					cfgerr++;
					continue;
				}

				if (p->uri_auth && p->uri_auth->userlist &&
				    !strcmp(p->uri_auth->userlist->name, expr->args->data.str.str))
					ul = p->uri_auth->userlist;
				else
					ul = auth_find_userlist(expr->args->data.str.str);

				if (!ul) {
					Alert("proxy %s: acl %s %s(%s): unable to find userlist.\n",
						p->id, acl->name, expr->kw->kw, expr->args->data.str.str);
					cfgerr++;
					continue;
				}

				free(expr->args->data.str.str);
				expr->args->data.usr = ul;
			}


			if (!strcmp(expr->kw->kw, "http_auth_group")) {

				if (LIST_ISEMPTY(&expr->patterns)) {
					Alert("proxy %s: acl %s %s(): no groups specified.\n",
						p->id, acl->name, expr->kw->kw);
					cfgerr++;
					continue;
				}

				list_for_each_entry(pattern, &expr->patterns, list) {
					pattern->val.group_mask = auth_resolve_groups(expr->args->data.usr, pattern->ptr.str);

					free(pattern->ptr.str);
					pattern->ptr.str = NULL;
					pattern->len = 0;

					if (!pattern->val.group_mask) {
						Alert("proxy %s: acl %s %s(): invalid group(s).\n",
							p->id, acl->name, expr->kw->kw);
						cfgerr++;
						continue;
					}
				}
			}
		}
	}

	return cfgerr;
}

/************************************************************************/
/*             All supported keywords must be declared here.            */
/************************************************************************/

/* Note: must not be declared <const> as its list will be overwritten.
 * Please take care of keeping this list alphabetically sorted.
 */
static struct acl_kw_list acl_kws = {{ },{
	{ "always_false",        acl_parse_nothing,    acl_fetch_false,          acl_match_nothing, ACL_USE_NOTHING, 0 },
	{ "always_true",         acl_parse_nothing,    acl_fetch_true,           acl_match_nothing, ACL_USE_NOTHING, 0 },
	{ "rep_ssl_hello_type",  acl_parse_int,        acl_fetch_ssl_hello_type, acl_match_int,     ACL_USE_L6RTR_VOLATILE, 0 },
	{ "req_len",             acl_parse_int,        acl_fetch_req_len,        acl_match_int,     ACL_USE_L6REQ_VOLATILE, 0 },
	{ "req_rdp_cookie",      acl_parse_str,        acl_fetch_rdp_cookie,     acl_match_str,     ACL_USE_L6REQ_VOLATILE|ACL_MAY_LOOKUP, ARG1(0,STR) },
	{ "req_rdp_cookie_cnt",  acl_parse_int,        acl_fetch_rdp_cookie_cnt, acl_match_int,     ACL_USE_L6REQ_VOLATILE, ARG1(0,STR) },
	{ "req_ssl_hello_type",  acl_parse_int,        acl_fetch_ssl_hello_type, acl_match_int,     ACL_USE_L6REQ_VOLATILE, 0 },
	{ "req_ssl_sni",         acl_parse_str,        acl_fetch_ssl_hello_sni,  acl_match_str,     ACL_USE_L6REQ_VOLATILE|ACL_MAY_LOOKUP, 0 },
	{ "req_ssl_ver",         acl_parse_dotted_ver, acl_fetch_req_ssl_ver,    acl_match_int,     ACL_USE_L6REQ_VOLATILE, 0 },
	{ "wait_end",            acl_parse_nothing,    acl_fetch_wait_end,       acl_match_nothing, ACL_USE_NOTHING, 0 },
	{ NULL, NULL, NULL, NULL }
}};


__attribute__((constructor))
static void __acl_init(void)
{
	acl_register_keywords(&acl_kws);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
