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
#include <proto/stick_table.h>

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
acl_fetch_true(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
               const struct arg *args, struct sample *smp)
{
	smp->type = SMP_T_BOOL;
	smp->data.uint = 1;
	return 1;
}

/* wait for more data as long as possible, then return TRUE. This should be
 * used with content inspection.
 */
static int
acl_fetch_wait_end(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                   const struct arg *args, struct sample *smp)
{
	if (!(opt & SMP_OPT_FINAL)) {
		smp->flags |= SMP_F_MAY_CHANGE;
		return 0;
	}
	smp->type = SMP_T_BOOL;
	smp->data.uint = 1;
	return 1;
}

/* force FALSE to be returned at the fetch level */
static int
acl_fetch_false(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                const struct arg *args, struct sample *smp)
{
	smp->type = SMP_T_BOOL;
	smp->data.uint = 0;
	return 1;
}

/* return the number of bytes in the request buffer */
static int
acl_fetch_req_len(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                  const struct arg *args, struct sample *smp)
{
	if (!l4 || !l4->req)
		return 0;

	smp->type = SMP_T_UINT;
	smp->data.uint = l4->req->i;
	smp->flags = SMP_F_VOLATILE | SMP_F_MAY_CHANGE;
	return 1;
}


static int
acl_fetch_ssl_hello_type(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                         const struct arg *args, struct sample *smp)
{
	int hs_len;
	int hs_type, bleft;
	struct buffer *b;
	const unsigned char *data;

	if (!l4)
		goto not_ssl_hello;

	b = ((opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? l4->rep : l4->req;

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

	smp->type = SMP_T_UINT;
	smp->data.uint = hs_type;
	smp->flags = SMP_F_VOLATILE;

	return 1;

 too_short:
	smp->flags = SMP_F_MAY_CHANGE;

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
acl_fetch_req_ssl_ver(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                      const struct arg *args, struct sample *smp)
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
	smp->type = SMP_T_UINT;
	smp->data.uint = version;
	smp->flags = SMP_F_VOLATILE;
	return 1;

 too_short:
	smp->flags = SMP_F_MAY_CHANGE;
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
acl_fetch_ssl_hello_sni(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                        const struct arg *args, struct sample *smp)
{
	int hs_len, ext_len, bleft;
	struct buffer *b;
	unsigned char *data;

	if (!l4)
		goto not_ssl_hello;

	b = ((opt & SMP_OPT_DIR) == SMP_OPT_DIR_RES) ? l4->rep : l4->req;

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
				smp->type = SMP_T_CSTR;
				smp->data.str.str = (char *)data + 9;
				smp->data.str.len = name_len;
				smp->flags = SMP_F_VOLATILE;
				return 1;
			}
		}

		hs_len -= 4 + ext_len;
		data   += 4 + ext_len;
	}
	/* server name not found */
	goto not_ssl_hello;

 too_short:
	smp->flags = SMP_F_MAY_CHANGE;

 not_ssl_hello:

	return 0;
}

/*
 * These functions are exported and may be used by any other component.
 */

/* ignore the current line */
int acl_parse_nothing(const char **text, struct acl_pattern *pattern, int *opaque, char **err)
{
	return 1;
}

/* always fake a data retrieval */
int acl_fetch_nothing(struct proxy *px, struct session *l4, void *l7, unsigned int opt,
                      const struct arg *args, struct sample *smp)
{
	return 1;
}

/* always return false */
int acl_match_nothing(struct sample *smp, struct acl_pattern *pattern)
{
	return ACL_PAT_FAIL;
}


/* NB: For two strings to be identical, it is required that their lengths match */
int acl_match_str(struct sample *smp, struct acl_pattern *pattern)
{
	int icase;

	if (pattern->len != smp->data.str.len)
		return ACL_PAT_FAIL;

	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, smp->data.str.str, smp->data.str.len) == 0) ||
	    (!icase && strncmp(pattern->ptr.str, smp->data.str.str, smp->data.str.len) == 0))
		return ACL_PAT_PASS;
	return ACL_PAT_FAIL;
}

/* Lookup a string in the expression's pattern tree. The node is returned if it
 * exists, otherwise NULL.
 */
static void *acl_lookup_str(struct sample *smp, struct acl_expr *expr)
{
	/* data are stored in a tree */
	struct ebmb_node *node;
	char prev;

	/* we may have to force a trailing zero on the test pattern */
	prev = smp->data.str.str[smp->data.str.len];
	if (prev)
		smp->data.str.str[smp->data.str.len] = '\0';
	node = ebst_lookup(&expr->pattern_tree, smp->data.str.str);
	if (prev)
		smp->data.str.str[smp->data.str.len] = prev;
	return node;
}

/* Executes a regex. It temporarily changes the data to add a trailing zero,
 * and restores the previous character when leaving.
 */
int acl_match_reg(struct sample *smp, struct acl_pattern *pattern)
{
	char old_char;
	int ret;

	old_char = smp->data.str.str[smp->data.str.len];
	smp->data.str.str[smp->data.str.len] = 0;

	if (regexec(pattern->ptr.reg, smp->data.str.str, 0, NULL, 0) == 0)
		ret = ACL_PAT_PASS;
	else
		ret = ACL_PAT_FAIL;

	smp->data.str.str[smp->data.str.len] = old_char;
	return ret;
}

/* Checks that the pattern matches the beginning of the tested string. */
int acl_match_beg(struct sample *smp, struct acl_pattern *pattern)
{
	int icase;

	if (pattern->len > smp->data.str.len)
		return ACL_PAT_FAIL;

	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, smp->data.str.str, pattern->len) != 0) ||
	    (!icase && strncmp(pattern->ptr.str, smp->data.str.str, pattern->len) != 0))
		return ACL_PAT_FAIL;
	return ACL_PAT_PASS;
}

/* Checks that the pattern matches the end of the tested string. */
int acl_match_end(struct sample *smp, struct acl_pattern *pattern)
{
	int icase;

	if (pattern->len > smp->data.str.len)
		return ACL_PAT_FAIL;
	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if ((icase && strncasecmp(pattern->ptr.str, smp->data.str.str + smp->data.str.len - pattern->len, pattern->len) != 0) ||
	    (!icase && strncmp(pattern->ptr.str, smp->data.str.str + smp->data.str.len - pattern->len, pattern->len) != 0))
		return ACL_PAT_FAIL;
	return ACL_PAT_PASS;
}

/* Checks that the pattern is included inside the tested string.
 * NB: Suboptimal, should be rewritten using a Boyer-Moore method.
 */
int acl_match_sub(struct sample *smp, struct acl_pattern *pattern)
{
	int icase;
	char *end;
	char *c;

	if (pattern->len > smp->data.str.len)
		return ACL_PAT_FAIL;

	end = smp->data.str.str + smp->data.str.len - pattern->len;
	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	if (icase) {
		for (c = smp->data.str.str; c <= end; c++) {
			if (tolower(*c) != tolower(*pattern->ptr.str))
				continue;
			if (strncasecmp(pattern->ptr.str, c, pattern->len) == 0)
				return ACL_PAT_PASS;
		}
	} else {
		for (c = smp->data.str.str; c <= end; c++) {
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
static int match_word(struct sample *smp, struct acl_pattern *pattern, unsigned int delimiters)
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

	if (pl > smp->data.str.len)
		return ACL_PAT_FAIL;

	may_match = 1;
	icase = pattern->flags & ACL_PAT_F_IGNORE_CASE;
	end = smp->data.str.str + smp->data.str.len - pl;
	for (c = smp->data.str.str; c <= end; c++) {
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
int acl_match_dir(struct sample *smp, struct acl_pattern *pattern)
{
	return match_word(smp, pattern, make_4delim('/', '?', '?', '?'));
}

/* Checks that the pattern is included inside the tested string, but enclosed
 * between the delmiters '/', '?', '.' or ":" or at the beginning or end of
 * the string. Delimiters at the beginning or end of the pattern are ignored.
 */
int acl_match_dom(struct sample *smp, struct acl_pattern *pattern)
{
	return match_word(smp, pattern, make_4delim('/', '?', '.', ':'));
}

/* Checks that the integer in <test> is included between min and max */
int acl_match_int(struct sample *smp, struct acl_pattern *pattern)
{
	if ((!pattern->val.range.min_set || pattern->val.range.min <= smp->data.uint) &&
	    (!pattern->val.range.max_set || smp->data.uint <= pattern->val.range.max))
		return ACL_PAT_PASS;
	return ACL_PAT_FAIL;
}

/* Checks that the length of the pattern in <test> is included between min and max */
int acl_match_len(struct sample *smp, struct acl_pattern *pattern)
{
	if ((!pattern->val.range.min_set || pattern->val.range.min <= smp->data.str.len) &&
	    (!pattern->val.range.max_set || smp->data.str.len <= pattern->val.range.max))
		return ACL_PAT_PASS;
	return ACL_PAT_FAIL;
}

int acl_match_ip(struct sample *smp, struct acl_pattern *pattern)
{
	unsigned int v4; /* in network byte order */
	struct in6_addr *v6;
	int bits, pos;
	struct in6_addr tmp6;

	if (pattern->type == SMP_T_IPV4) {
		if (smp->type == SMP_T_IPV4) {
			v4 = smp->data.ipv4.s_addr;
		}
		else if (smp->type == SMP_T_IPV6) {
			/* v4 match on a V6 sample. We want to check at least for
			 * the following forms :
			 *   - ::ffff:ip:v4 (ipv4 mapped)
			 *   - ::0000:ip:v4 (old ipv4 mapped)
			 *   - 2002:ip:v4:: (6to4)
			 */
			if (*(uint32_t*)&smp->data.ipv6.s6_addr[0] == 0 &&
			    *(uint32_t*)&smp->data.ipv6.s6_addr[4]  == 0 &&
			    (*(uint32_t*)&smp->data.ipv6.s6_addr[8] == 0 ||
			     *(uint32_t*)&smp->data.ipv6.s6_addr[8] == htonl(0xFFFF))) {
				v4 = *(uint32_t*)&smp->data.ipv6.s6_addr[12];
			}
			else if (*(uint16_t*)&smp->data.ipv6.s6_addr[0] == htons(0x2002)) {
				v4 = htonl((ntohs(*(uint16_t*)&smp->data.ipv6.s6_addr[2]) << 16) +
				            ntohs(*(uint16_t*)&smp->data.ipv6.s6_addr[4]));
			}
			else
				return ACL_PAT_FAIL;
		}
		else
			return ACL_PAT_FAIL;

		if (((v4 ^ pattern->val.ipv4.addr.s_addr) & pattern->val.ipv4.mask.s_addr) == 0)
			return ACL_PAT_PASS;
		else
			return ACL_PAT_FAIL;
	}
	else if (pattern->type == SMP_T_IPV6) {
		if (smp->type == SMP_T_IPV4) {
			/* Convert the IPv4 sample address to IPv4 with the
			 * mapping method using the ::ffff: prefix.
			 */
			memset(&tmp6, 0, 10);
			*(uint16_t*)&tmp6.s6_addr[10] = htons(0xffff);
			*(uint32_t*)&tmp6.s6_addr[12] = smp->data.ipv4.s_addr;
			v6 = &tmp6;
		}
		else if (smp->type == SMP_T_IPV6) {
			v6 = &smp->data.ipv6;
		}
		else {
			return ACL_PAT_FAIL;
		}

		bits = pattern->val.ipv6.mask;
		for (pos = 0; bits > 0; pos += 4, bits -= 32) {
			v4 = *(uint32_t*)&v6->s6_addr[pos] ^ *(uint32_t*)&pattern->val.ipv6.addr.s6_addr[pos];
			if (bits < 32)
				v4 &= (~0U) << (32-bits);
			if (v4)
				return ACL_PAT_FAIL;
		}
		return ACL_PAT_PASS;
	}
	return ACL_PAT_FAIL;
}

/* Lookup an IPv4 address in the expression's pattern tree using the longest
 * match method. The node is returned if it exists, otherwise NULL.
 */
static void *acl_lookup_ip(struct sample *smp, struct acl_expr *expr)
{
	struct in_addr *s;

	if (smp->type != SMP_T_IPV4)
		return ACL_PAT_FAIL;

	s = &smp->data.ipv4;
	return ebmb_lookup_longest(&expr->pattern_tree, &s->s_addr);
}

/* Parse a string. It is allocated and duplicated. */
int acl_parse_str(const char **text, struct acl_pattern *pattern, int *opaque, char **err)
{
	int len;

	len  = strlen(*text);
	pattern->type = SMP_T_CSTR;

	if (pattern->flags & ACL_PAT_F_TREE_OK) {
		/* we're allowed to put the data in a tree whose root is pointed
		 * to by val.tree.
		 */
		struct ebmb_node *node;

		node = calloc(1, sizeof(*node) + len + 1);
		if (!node) {
			if (err)
				memprintf(err, "out of memory while loading string pattern");
			return 0;
		}
		memcpy(node->key, *text, len + 1);
		if (ebst_insert(pattern->val.tree, node) != node)
			free(node); /* was a duplicate */
		pattern->flags |= ACL_PAT_F_TREE; /* this pattern now contains a tree */
		return 1;
	}

	pattern->ptr.str = strdup(*text);
	if (!pattern->ptr.str) {
		if (err)
			memprintf(err, "out of memory while loading string pattern");
		return 0;
	}
	pattern->len = len;
	return 1;
}

/* Parse and concatenate all further strings into one. */
int
acl_parse_strcat(const char **text, struct acl_pattern *pattern, int *opaque, char **err)
{

	int len = 0, i;
	char *s;

	for (i = 0; *text[i]; i++)
		len += strlen(text[i])+1;

	pattern->type = SMP_T_CSTR;
	pattern->ptr.str = s = calloc(1, len);
	if (!pattern->ptr.str) {
		if (err)
			memprintf(err, "out of memory while loading pattern");
		return 0;
	}

	for (i = 0; *text[i]; i++)
		s += sprintf(s, i?" %s":"%s", text[i]);

	pattern->len = len;

	return i;
}

/* Free data allocated by acl_parse_reg */
static void acl_free_reg(void *ptr)
{
	regfree((regex_t *)ptr);
}

/* Parse a regex. It is allocated. */
int acl_parse_reg(const char **text, struct acl_pattern *pattern, int *opaque, char **err)
{
	regex_t *preg;
	int icase;

	preg = calloc(1, sizeof(regex_t));

	if (!preg) {
		if (err)
			memprintf(err, "out of memory while loading pattern");
		return 0;
	}

	icase = (pattern->flags & ACL_PAT_F_IGNORE_CASE) ? REG_ICASE : 0;
	if (regcomp(preg, *text, REG_EXTENDED | REG_NOSUB | icase) != 0) {
		free(preg);
		if (err)
			memprintf(err, "regex '%s' is invalid", *text);
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
 * If err is non-NULL, an error message will be returned there on errors and
 * the caller will have to free it.
 *
 */
int acl_parse_int(const char **text, struct acl_pattern *pattern, int *opaque, char **err)
{
	signed long long i;
	unsigned int j, last, skip = 0;
	const char *ptr = *text;

	pattern->type = SMP_T_UINT;
	while (!isdigit((unsigned char)*ptr)) {
		switch (get_std_op(ptr)) {
		case STD_OP_EQ: *opaque = 0; break;
		case STD_OP_GT: *opaque = 1; break;
		case STD_OP_GE: *opaque = 2; break;
		case STD_OP_LT: *opaque = 3; break;
		case STD_OP_LE: *opaque = 4; break;
		default:
			if (err)
				memprintf(err, "'%s' is neither a number nor a supported operator", ptr);
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

	if (last && *opaque >= 1 && *opaque <= 4) {
		/* having a range with a min or a max is absurd */
		if (err)
			memprintf(err, "integer range '%s' specified with a comparison operator", text[skip]);
		return 0;
	}

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
int acl_parse_dotted_ver(const char **text, struct acl_pattern *pattern, int *opaque, char **err)
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
			if (err)
				memprintf(err, "'%s' is neither a number nor a supported operator", ptr);
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

	if (last && *opaque >= 1 && *opaque <= 4) {
		/* having a range with a min or a max is absurd */
		if (err)
			memprintf(err, "version range '%s' specified with a comparison operator", text[skip]);
		return 0;
	}

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
 * otherwise 0. NOTE: IP address patterns are typed (IPV4/IPV6).
 */
int acl_parse_ip(const char **text, struct acl_pattern *pattern, int *opaque, char **err)
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
		pattern->type = SMP_T_IPV4;
		if (mask + (mask & -mask) == 0 && tree) {
			mask = mask ? 33 - flsnz(mask & -mask) : 0; /* equals cidr value */
			/* FIXME: insert <addr>/<mask> into the tree here */
			node = calloc(1, sizeof(*node) + 4); /* reserve 4 bytes for IPv4 address */
			if (!node) {
				if (err)
					memprintf(err, "out of memory while loading IPv4 pattern");
				return 0;
			}
			memcpy(node->key, &pattern->val.ipv4.addr, 4); /* network byte order */
			node->node.pfx = mask;
			if (ebmb_insert_prefix(tree, node, 4) != node)
				free(node); /* was a duplicate */
			pattern->flags |= ACL_PAT_F_TREE;
			return 1;
		}
		return 1;
	}
	else if (str62net(*text, &pattern->val.ipv6.addr, &pattern->val.ipv6.mask)) {
		/* no tree support right now */
		pattern->type = SMP_T_IPV6;
		return 1;
	}
	else {
		if (err)
			memprintf(err, "'%s' is not a valid IPv4 or IPv6 address", *text);
		return 0;
	}
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
		if (arg->type == ARGT_STR || arg->unresolved) {
			free(arg->data.str.str);
			arg->data.str.str = NULL;
			arg->unresolved = 0;
		}
		arg++;
	}

	free(expr->args);
	expr->kw->use_cnt--;
	return expr;
}


/* Reads patterns from a file. If <err_msg> is non-NULL, an error message will
 * be returned there on errors and the caller will have to free it.
 */
static int acl_read_patterns_from_file(	struct acl_keyword *aclkw,
					struct acl_expr *expr,
					const char *filename, int patflags,
					char **err)
{
	FILE *file;
	char *c;
	const char *args[2];
	struct acl_pattern *pattern;
	int opaque;
	int ret = 0;
	int line = 0;

	file = fopen(filename, "r");
	if (!file) {
		memprintf(err, "failed to open pattern file <%s>", filename);
		return 0;
	}

	/* now parse all patterns. The file may contain only one pattern per
	 * line. If the line contains spaces, they will be part of the pattern.
	 * The pattern stops at the first CR, LF or EOF encountered.
	 */
	opaque = 0;
	pattern = NULL;
	args[1] = "";
	while (fgets(trash, trashlen, file) != NULL) {
		line++;
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
		if (!pattern) {
			memprintf(err, "out of memory when loading patterns from file <%s>", filename);
			goto out_close;
		}

		memset(pattern, 0, sizeof(*pattern));
		pattern->flags = patflags;

		if ((aclkw->requires & ACL_MAY_LOOKUP) && !(pattern->flags & ACL_PAT_F_IGNORE_CASE)) {
			/* we pre-set the data pointer to the tree's head so that functions
			 * which are able to insert in a tree know where to do that.
			 */
			pattern->flags |= ACL_PAT_F_TREE_OK;
			pattern->val.tree = &expr->pattern_tree;
		}

		pattern->type = SMP_TYPES; /* unspecified type by default */
		if (!aclkw->parse(args, pattern, &opaque, err))
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

/* Parse an ACL expression starting at <args>[0], and return it. If <err> is
 * not NULL, it will be filled with a pointer to an error message in case of
 * error. This pointer must be freeable or NULL.
 *
 * Right now, the only accepted syntax is :
 * <subject> [<value>...]
 */
struct acl_expr *parse_acl_expr(const char **args, char **err)
{
	__label__ out_return, out_free_expr, out_free_pattern;
	struct acl_expr *expr;
	struct acl_keyword *aclkw;
	struct acl_pattern *pattern;
	int opaque, patflags;
	const char *arg;

	aclkw = find_acl_kw(args[0]);
	if (!aclkw || !aclkw->parse) {
		if (err)
			memprintf(err, "unknown ACL keyword '%s'", *args);
		goto out_return;
	}

	expr = (struct acl_expr *)calloc(1, sizeof(*expr));
	if (!expr) {
		if (err)
			memprintf(err, "out of memory when parsing ACL expression");
		goto out_return;
	}

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
			if (!end) {
				if (err)
					memprintf(err, "missing closing ')' after arguments to ACL keyword '%s'", aclkw->kw);
				goto out_free_expr;
			}

			/* Parse the arguments. Note that currently we have no way to
			 * report parsing errors, hence the NULL in the error pointers.
			 * An error is also reported if some mandatory arguments are
			 * missing.
			 */
			nbargs = make_arg_list(arg, end - arg, aclkw->arg_mask, &expr->args,
					       err, NULL, NULL);
			if (nbargs < 0) {
				/* note that make_arg_list will have set <err> here */
				if (err)
					memprintf(err, "in argument to '%s', %s", aclkw->kw, *err);
				goto out_free_expr;
			}

			if (aclkw->val_args && !aclkw->val_args(expr->args, err)) {
				/* invalid keyword argument, error must have been
				 * set by val_args().
				 */
				if (err)
					memprintf(err, "in argument to '%s', %s", aclkw->kw, *err);
				goto out_free_expr;
			}
		}
		else if (ARGM(aclkw->arg_mask) == 1) {
			int type = (aclkw->arg_mask >> 4) & 15;

			/* If a proxy is noted as a mandatory argument, we'll fake
			 * an empty one so that acl_find_targets() resolves it as
			 * the current one later.
			 */
			if (type != ARGT_FE && type != ARGT_BE && type != ARGT_TAB) {
				if (err)
					memprintf(err, "ACL keyword '%s' expects %d arguments", aclkw->kw, ARGM(aclkw->arg_mask));
				goto out_free_expr;
			}

			/* Build an arg list containing the type as an empty string
			 * and the usual STOP.
			 */
			expr->args = calloc(2, sizeof(*expr->args));
			expr->args[0].type = type;
			expr->args[0].unresolved = 1;
			expr->args[0].data.str.str = strdup("");
			expr->args[0].data.str.len = 1;
			expr->args[0].data.str.len = 0;
			expr->args[1].type = ARGT_STOP;
		}
		else if (ARGM(aclkw->arg_mask)) {
			/* there were some mandatory arguments */
			if (err)
				memprintf(err, "ACL keyword '%s' expects %d arguments", aclkw->kw, ARGM(aclkw->arg_mask));
			goto out_free_expr;
		}
	}
	else {
		if (arg) {
			/* no argument expected */
			if (err)
				memprintf(err, "ACL keyword '%s' takes no argument", aclkw->kw);
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
			if (!acl_read_patterns_from_file(aclkw, expr, args[1], patflags | ACL_PAT_F_FROM_FILE, err))
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
		if (!pattern) {
			if (err)
				memprintf(err, "out of memory when parsing ACL pattern");
			goto out_free_expr;
		}
		pattern->flags = patflags;

		pattern->type = SMP_TYPES; /* unspecified type */
		ret = aclkw->parse(args, pattern, &opaque, err);
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
 * an anonymous one and it won't be merged with any other one. If <err> is not
 * NULL, it will be filled with an appropriate error. This pointer must be
 * freeable or NULL.
 *
 * args syntax: <aclname> <acl_expr>
 */
struct acl *parse_acl(const char **args, struct list *known_acl, char **err)
{
	__label__ out_return, out_free_acl_expr, out_free_name;
	struct acl *cur_acl;
	struct acl_expr *acl_expr;
	char *name;
	const char *pos;

	if (**args && (pos = invalid_char(*args))) {
		if (err)
			memprintf(err, "invalid character in ACL name : '%c'", *pos);
		goto out_return;
	}

	acl_expr = parse_acl_expr(args + 1, err);
	if (!acl_expr) {
		/* parse_acl_expr will have filled <err> here */
		goto out_return;
	}

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
		if (!name) {
			if (err)
				memprintf(err, "out of memory when parsing ACL");
			goto out_free_acl_expr;
		}
		cur_acl = (struct acl *)calloc(1, sizeof(*cur_acl));
		if (cur_acl == NULL) {
			if (err)
				memprintf(err, "out of memory when parsing ACL");
			goto out_free_name;
		}

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
 * If <known_acl> is not NULL, the ACL will be queued at its tail. If <err> is
 * not NULL, it will be filled with an error message if an error occurs. This
 * pointer must be freeable or NULL.
 */
struct acl *find_acl_default(const char *acl_name, struct list *known_acl, char **err)
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

	if (default_acl_list[index].name == NULL) {
		if (err)
			memprintf(err, "no such ACL : '%s'", acl_name);
		return NULL;
	}

	acl_expr = parse_acl_expr((const char **)default_acl_list[index].expr, err);
	if (!acl_expr) {
		/* parse_acl_expr must have filled err here */
		goto out_return;
	}

	name = strdup(acl_name);
	if (!name) {
		if (err)
			memprintf(err, "out of memory when building default ACL '%s'", acl_name);
		goto out_free_acl_expr;
	}

	cur_acl = (struct acl *)calloc(1, sizeof(*cur_acl));
	if (cur_acl == NULL) {
		if (err)
			memprintf(err, "out of memory when building default ACL '%s'", acl_name);
		goto out_free_name;
	}

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
 * case of low memory). Supports multiple conditions separated by "or". If
 * <err> is not NULL, it will be filled with a pointer to an error message in
 * case of error, that the caller is responsible for freeing. The initial
 * location must either be freeable or NULL.
 */
struct acl_cond *parse_acl_cond(const char **args, struct list *known_acl, int pol, char **err)
{
	__label__ out_return, out_free_suite, out_free_term;
	int arg, neg;
	const char *word;
	struct acl *cur_acl;
	struct acl_term *cur_term;
	struct acl_term_suite *cur_suite;
	struct acl_cond *cond;

	cond = (struct acl_cond *)calloc(1, sizeof(*cond));
	if (cond == NULL) {
		if (err)
			memprintf(err, "out of memory when parsing condition");
		goto out_return;
	}

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

			if (!*args[arg_end]) {
				if (err)
					memprintf(err, "missing closing '}' in condition");
				goto out_free_suite;
			}

			args_new = calloc(1, (arg_end - arg + 1) * sizeof(*args_new));
			if (!args_new) {
				if (err)
					memprintf(err, "out of memory when parsing condition");
				goto out_free_suite;
			}

			args_new[0] = "";
			memcpy(args_new + 1, args + arg + 1, (arg_end - arg) * sizeof(*args_new));
			args_new[arg_end - arg] = "";
			cur_acl = parse_acl(args_new, known_acl, err);
			free(args_new);

			if (!cur_acl) {
				/* note that parse_acl() must have filled <err> here */
				goto out_free_suite;
			}
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
				cur_acl = find_acl_default(word, known_acl, err);
				if (cur_acl == NULL) {
					/* note that find_acl_default() must have filled <err> here */
					goto out_free_suite;
				}
			}
		}

		cur_term = (struct acl_term *)calloc(1, sizeof(*cur_term));
		if (cur_term == NULL) {
			if (err)
				memprintf(err, "out of memory when parsing condition");
			goto out_free_suite;
		}

		cur_term->acl = cur_acl;
		cur_term->neg = neg;
		cond->requires |= cur_acl->requires;

		if (!cur_suite) {
			cur_suite = (struct acl_term_suite *)calloc(1, sizeof(*cur_suite));
			if (cur_term == NULL) {
				if (err)
					memprintf(err, "out of memory when parsing condition");
				goto out_free_term;
			}
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
 * ACL requirements to the proxy's acl_requires. If <err> is not NULL, it will
 * be filled with a pointer to an error message in case of error, that the
 * caller is responsible for freeing. The initial location must either be
 * freeable or NULL.
 */
struct acl_cond *build_acl_cond(const char *file, int line, struct proxy *px, const char **args, char **err)
{
	int pol = ACL_COND_NONE;
	struct acl_cond *cond = NULL;

	if (err)
		*err = NULL;

	if (!strcmp(*args, "if")) {
		pol = ACL_COND_IF;
		args++;
	}
	else if (!strcmp(*args, "unless")) {
		pol = ACL_COND_UNLESS;
		args++;
	}
	else {
		if (err)
			memprintf(err, "conditions must start with either 'if' or 'unless'");
		return NULL;
	}

	cond = parse_acl_cond(args, &px->acl, pol, err);
	if (!cond) {
		/* note that parse_acl_cond must have filled <err> here */
		return NULL;
	}

	cond->file = file;
	cond->line = line;
	px->acl_requires |= cond->requires;

	return cond;
}

/* Execute condition <cond> and return either ACL_PAT_FAIL, ACL_PAT_MISS or
 * ACL_PAT_PASS depending on the test results. ACL_PAT_MISS may only be
 * returned if <opt> does not contain SMP_OPT_FINAL, indicating that incomplete
 * data is being examined. The function automatically sets SMP_OPT_ITERATE.
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
int acl_exec_cond(struct acl_cond *cond, struct proxy *px, struct session *l4, void *l7, unsigned int opt)
{
	__label__ fetch_next;
	struct acl_term_suite *suite;
	struct acl_term *term;
	struct acl_expr *expr;
	struct acl *acl;
	struct acl_pattern *pattern;
	struct sample smp;
	int acl_res, suite_res, cond_res;

	/* ACLs are iterated over all values, so let's always set the flag to
	 * indicate this to the fetch functions.
	 */
	opt |= SMP_OPT_ITERATE;

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
				memset(&smp, 0, sizeof(smp));
			fetch_next:
				if (!expr->kw->fetch(px, l4, l7, opt, expr->args, &smp)) {
					/* maybe we could not fetch because of missing data */
					if (smp.flags & SMP_F_MAY_CHANGE && !(opt & SMP_OPT_FINAL))
						acl_res |= ACL_PAT_MISS;
					continue;
				}

				if (smp.type == SMP_T_BOOL) {
					if (smp.data.uint)
						acl_res |= ACL_PAT_PASS;
					else
						acl_res |= ACL_PAT_FAIL;
				}
				else {
					if (!eb_is_empty(&expr->pattern_tree)) {
						/* a tree is present, let's check what type it is */
						if (expr->kw->match == acl_match_str)
							acl_res |= acl_lookup_str(&smp, expr) ? ACL_PAT_PASS : ACL_PAT_FAIL;
						else if (expr->kw->match == acl_match_ip)
							acl_res |= acl_lookup_ip(&smp, expr) ? ACL_PAT_PASS : ACL_PAT_FAIL;
					}

					/* call the match() function for all tests on this value */
					list_for_each_entry(pattern, &expr->patterns, list) {
						if (acl_res == ACL_PAT_PASS)
							break;
						acl_res |= expr->kw->match(&smp, pattern);
					}
				}
				/*
				 * OK now acl_res holds the result of this expression
				 * as one of ACL_PAT_FAIL, ACL_PAT_MISS or ACL_PAT_PASS.
				 *
				 * Then if (!MISS) we can cache the result, and put
				 * (smp.flags & SMP_F_VOLATILE) in the cache flags.
				 *
				 * FIXME: implement cache.
				 *
				 */

				/* we're ORing these terms, so a single PASS is enough */
				if (acl_res == ACL_PAT_PASS)
					break;

				if (smp.flags & SMP_F_NOT_LAST)
					goto fetch_next;

				/* sometimes we know the fetched data is subject to change
				 * later and give another chance for a new match (eg: request
				 * size, time, ...)
				 */
				if (smp.flags & SMP_F_MAY_CHANGE && !(opt & SMP_OPT_FINAL))
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
	struct arg *arg;
	int cfgerr = 0;

	list_for_each_entry(acl, &p->acl, list) {
		list_for_each_entry(expr, &acl->expr, list) {
			for (arg = expr->args; arg; arg++) {
				if (arg->type == ARGT_STOP)
					break;
				else if (!arg->unresolved)
					continue;
				else if (arg->type == ARGT_SRV) {
					struct proxy *px;
					struct server *srv;
					char *pname, *sname;

					if (!expr->args->data.str.len) {
						Alert("proxy %s: acl '%s' %s(): missing server name.\n",
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
							Alert("proxy %s: acl '%s' %s(): unable to find proxy '%s'.\n",
							      p->id, acl->name, expr->kw->kw, pname);
							cfgerr++;
							continue;
						}
					}

					srv = findserver(px, sname);
					if (!srv) {
						Alert("proxy %s: acl '%s' %s(): unable to find server '%s'.\n",
						      p->id, acl->name, expr->kw->kw, sname);
						cfgerr++;
						continue;
					}

					free(expr->args->data.str.str);
					expr->args->data.str.str = NULL;
					arg->unresolved = 0;
					expr->args->data.srv = srv;
				}
				else if (arg->type == ARGT_FE) {
					struct proxy *prx = p;
					char *pname = p->id;

					if (expr->args->data.str.len) {
						pname = expr->args->data.str.str;
						prx = findproxy(pname, PR_CAP_FE);
					}

					if (!prx) {
						Alert("proxy %s: acl '%s' %s(): unable to find frontend '%s'.\n",
						      p->id, acl->name, expr->kw->kw, pname);
						cfgerr++;
						continue;
					}

					if (!(prx->cap & PR_CAP_FE)) {
						Alert("proxy %s: acl '%s' %s(): proxy '%s' has no frontend capability.\n",
						      p->id, acl->name, expr->kw->kw, pname);
						cfgerr++;
						continue;
					}

					free(expr->args->data.str.str);
					expr->args->data.str.str = NULL;
					arg->unresolved = 0;
					expr->args->data.prx = prx;
				}
				else if (arg->type == ARGT_BE) {
					struct proxy *prx = p;
					char *pname = p->id;

					if (expr->args->data.str.len) {
						pname = expr->args->data.str.str;
						prx = findproxy(pname, PR_CAP_BE);
					}

					if (!prx) {
						Alert("proxy %s: acl '%s' %s(): unable to find backend '%s'.\n",
						      p->id, acl->name, expr->kw->kw, pname);
						cfgerr++;
						continue;
					}

					if (!(prx->cap & PR_CAP_BE)) {
						Alert("proxy %s: acl '%s' %s(): proxy '%s' has no backend capability.\n",
						      p->id, acl->name, expr->kw->kw, pname);
						cfgerr++;
						continue;
					}

					free(expr->args->data.str.str);
					expr->args->data.str.str = NULL;
					arg->unresolved = 0;
					expr->args->data.prx = prx;
				}
				else if (arg->type == ARGT_TAB) {
					struct proxy *prx = p;
					char *pname = p->id;

					if (expr->args->data.str.len) {
						pname = expr->args->data.str.str;
						prx = find_stktable(pname);
					}

					if (!prx) {
						Alert("proxy %s: acl '%s' %s(): unable to find table '%s'.\n",
						      p->id, acl->name, expr->kw->kw, pname);
						cfgerr++;
						continue;
					}


					if (!prx->table.size) {
						Alert("proxy %s: acl '%s' %s(): no table in proxy '%s'.\n",
						      p->id, acl->name, expr->kw->kw, pname);
						cfgerr++;
						continue;
					}

					free(expr->args->data.str.str);
					expr->args->data.str.str = NULL;
					arg->unresolved = 0;
					expr->args->data.prx = prx;
				}
				else if (arg->type == ARGT_USR) {
					if (!expr->args->data.str.len) {
						Alert("proxy %s: acl '%s' %s(): missing userlist name.\n",
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
						Alert("proxy %s: acl '%s' %s(%s): unable to find userlist.\n",
						      p->id, acl->name, expr->kw->kw, expr->args->data.str.str);
						cfgerr++;
						continue;
					}

					free(expr->args->data.str.str);
					expr->args->data.str.str = NULL;
					arg->unresolved = 0;
					expr->args->data.usr = ul;
				}
			} /* end of args processing */

			/* don't try to resolve groups if we're not certain of having
			 * resolved userlists first.
			 */
			if (cfgerr)
				break;

			if (!strcmp(expr->kw->kw, "http_auth_group")) {
				/* note: argument resolved above thanks to ARGT_USR */

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
